"""Propose cross-group finding pairs that compose into an exploit chain.

Spec section 1.3: "Two findings held both halves of an exploit chain and were
never joined, because findings are born inside per-group subagents and
nothing crosses them." The structural cause is in that sentence - no step in
the pipeline ever looked at two groups at once.

So this is a cross-group pass, and it proposes. `dedup` proposes duplicate
pairs and never merges; `bench` proposes candidate matches and never scores
them as matches. Same discipline: a chain is composed by a human or an agent
that read both findings, and `compose` records that decision.

The join is an approximation over English prose - finding A enables finding B
when A's recorded impact names something B's recorded attacker position or
crossed boundary requires - so every edge of it is bounded: generic words are
dropped, one shared word is not enough, same-group pairs are skipped, and the
list is capped.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core import db, text

MAX_CANDIDATES = 100
MIN_SHARED_TOKENS = 2


@dataclass(frozen=True, slots=True)
class ChainCandidate:
    enabler: str
    consumer: str
    shared: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Proposal:
    candidates: tuple[ChainCandidate, ...]
    findings_scanned: int
    without_precondition: int
    truncated: bool


def _significant(value: str) -> frozenset[str]:
    """Four-character-plus tokens, minus the words that say nothing.

    The four-character floor comes from text.location_tokens, where it was
    added because the bare token `tss` matched TssRSASecretKey and
    osal_tss_init and produced two false golden candidates. The same
    reasoning applies harder here: this runs over prose, not paths.
    """
    return frozenset(text.location_tokens(value) - text.NOISE_WORDS)


def propose(con: sqlite3.Connection) -> Proposal:
    """Ordered (enabler, consumer) pairs, across groups only.

    `without_precondition` is the diagnostic, and on a real run it is the
    more useful number: attacker_position and boundary_crossed are optional
    in cba_findings, so a run that never filled them cannot produce a chain,
    and an empty candidate list would otherwise read as "no chains exist".

    Bounded at db.MAX_ROWS findings, stated here rather than left to the
    default: the tplink run produced 45, and a run that produced more than
    200 has a bigger problem than its chain list.
    """
    rows = db.rows(con, "cba_findings",
                   columns=("id", "group_id", "impact", "attacker_position",
                            "boundary_crossed"),
                   limit=db.MAX_ROWS)
    findings = []
    without = 0
    for r in rows:
        precondition = _significant(
            f"{r['attacker_position'] or ''} {r['boundary_crossed'] or ''}")
        if not precondition:
            without += 1
        findings.append((r["id"], r["group_id"] or "",
                         _significant(r["impact"] or ""), precondition))

    out: list[ChainCandidate] = []
    truncated = False
    for eid, egroup, impact, _ in findings:
        if not impact:
            continue
        for cid, cgroup, _, precondition in findings:
            if cid == eid or cgroup == egroup or not precondition:
                continue
            shared = impact & precondition
            if len(shared) < MIN_SHARED_TOKENS:
                continue
            if len(out) >= MAX_CANDIDATES:
                truncated = True
                break
            out.append(ChainCandidate(eid, cid, tuple(sorted(shared))))
        if truncated:
            break

    return Proposal(candidates=tuple(out), findings_scanned=len(findings),
                    without_precondition=without, truncated=truncated)


def compose(con: sqlite3.Connection, *, chain_id: str, finding_ids: str,
            attacker_position: str, completeness: str, pre_auth: str = "",
            blocking_unknowns: str = "", replace: bool = False) -> None:
    """Record a chain somebody decided on. Validates that it names real findings.

    A chain naming a finding that does not exist is a chain nothing can be
    checked against, and the finding ids are typed by hand from a candidate
    list. db.put's validator checks the shape of finding_ids; only a
    connection can check that they resolve.
    """
    ids = [p.strip() for p in finding_ids.split(",") if p.strip()]
    known = {r["id"] for r in db.rows(con, "cba_findings", columns=("id",))}
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise db.DbError(
            f"chain {chain_id} names finding(s) that do not exist: "
            f"{', '.join(unknown)}")
    db.put(con, "cba_chains", {
        "id": chain_id, "finding_ids": ", ".join(ids),
        "attacker_position": attacker_position, "pre_auth": pre_auth or "",
        "completeness": completeness,
        "blocking_unknowns": blocking_unknowns or ""}, replace=replace)


def render(p: Proposal) -> str:
    out = [f"chain candidates: {len(p.candidates)} across "
           f"{p.findings_scanned} finding(s)"]
    for c in p.candidates:
        out.append(f"  {c.enabler} -> {c.consumer}   shared: "
                   f"{', '.join(c.shared)}")
    if p.truncated:
        out.append(f"  capped at {MAX_CANDIDATES}. The impact and "
                   f"attacker-position text is too generic to join on as "
                   f"written - narrow it before reading this list.")
    if p.without_precondition:
        out.append(
            f"  {p.without_precondition} of {p.findings_scanned} finding(s) "
            f"record neither attacker_position nor boundary_crossed, so they "
            f"cannot be the consumer half of any chain. That is a gap in the "
            f"findings, not a statement that no chain exists.")
    if p.candidates:
        out.append("  These are proposals. Read both findings in full, then "
                   "record the decision with `audit.py chain --compose`.")
    return "\n".join(out)
