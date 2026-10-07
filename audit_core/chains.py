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

# Three, not two. Measured on the pinned 45-finding tplink run, the only real
# corpus this project has: at two shared tokens the proposer produced 311
# pairs, hit the 100 cap after 12 of 45 findings, and its top join tokens were
# `lock` (37), `account` (32), `flash` (21) and `cloud` (20) - words that
# appear in nearly every finding on a single-product corpus, so two of them
# together is not evidence of a chain. At three, with the generic set below,
# the same run proposes 24 pairs and never reaches the cap, so every finding
# is examined as an enabler. A list nobody can read is a mechanism nobody
# uses, and the cross-group chain this exists to find is invisible inside 311
# proposals just as surely as inside none.
MIN_SHARED_TOKENS = 3

# Chain-proposal noise, layered on top of `text.NOISE_WORDS`.
#
# `text.NOISE_WORDS` has two callers pulling in opposite directions:
# `db.check_identity_evidence` subtracts it to detect evidence that only
# repeats its own path, so growing it makes that rule reject more legitimate
# evidence; this module subtracts it to suppress generic joins, so growing it
# is how this module gets better. One frozenset cannot serve both, and the
# shared base is the one with the sharper downside - so the base stays as it
# is and the growth happens here, where the only thing at risk is a chain
# proposal.
#
# What belongs here: words that are generic to security-audit prose in any
# target - the vocabulary of impact and attacker position rather than the
# name of a mechanism. What does not: the nouns of whatever product is under
# audit. `lock`, `flash`, `cloud` and `tapo` dominate the tplink corpus
# because the target is a cloud-connected smart lock; on another target they
# would carry real signal, and MIN_SHARED_TOKENS is what handles them.
#
# A compound identifier survives this list intact: `location_tokens` keeps
# underscores, so `session_token` and `nvram_config` are single tokens and are
# not suppressed by `session` or `config` being here.
GENERIC_TOKENS = frozenset({
    # Impact and severity vocabulary.
    "bypass", "corruption", "destructive", "disclose", "disclosure",
    "escalation", "impact", "leak", "leakage", "leaked", "leaks",
    "privilege", "privileges", "persistence", "persistent", "surface",
    # Position, trust and boundary vocabulary.
    "boundary", "credential", "credentials", "identity", "internal",
    "level", "peer", "physical", "secure", "security", "session",
    "sessions", "trust", "trusted", "untrusted", "validation",
    # Software-shape vocabulary: true of nearly every finding ever written.
    "adjacent", "application", "applications", "behaviour", "behavior",
    "bound", "bounded", "chain", "chains", "code", "component",
    "components", "condition", "contents", "context", "feature", "fixed",
    "function", "global", "implementation", "integrity", "interface",
    "invalid", "layer", "logic", "memory", "message", "messages", "module",
    "object", "offset", "operation", "payload", "process", "range",
    "response", "responses", "routine", "size", "state", "store", "stored",
    "string", "strings", "structure", "supplied", "table", "target", "task",
    "version", "versions",
    # English filler that reaches this far. It is not promoted into
    # text.NOISE_WORDS because that set is also the identity rule's, and
    # every word added there is a word an evidence string may no longer
    # count on. Here the blast radius is one chain proposal.
    "between", "drives", "entirely", "every", "fully", "later", "rest",
})


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
    unexamined: int = 0
    """Findings never examined as an enabler, because the cap stopped the scan.

    `sweep.render` and `sweep.record` both apply honest-truncation discipline
    - a truncated sweep is refused outright because it "does not know what it
    did not see" - and this list used to say only "capped at 100". On the
    pinned tplink run that hid the fact that 33 of 45 findings were never
    looked at, which is the number a reader actually needs: a cross-group
    chain is invisible here if its enabler sorts after the cap.
    """


def _significant(value: str) -> frozenset[str]:
    """Four-character-plus tokens, minus the words that say nothing.

    The four-character floor comes from text.location_tokens, where it was
    added because the bare token `tss` matched TssRSASecretKey and
    osal_tss_init and produced two false golden candidates. The same
    reasoning applies harder here: this runs over prose, not paths.

    Two sets are subtracted, not one: the shared English-filler base, and
    this module's own GENERIC_TOKENS. See that constant for why they are
    separate.
    """
    return frozenset(text.location_tokens(value)
                     - text.NOISE_WORDS - GENERIC_TOKENS)


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
    examined = 0
    for eid, egroup, impact, _ in findings:
        for cid, cgroup, _, precondition in findings:
            if not impact:
                break
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
            # This enabler's own list was cut short, so it does not count as
            # examined either. Over-reporting what was looked at is the one
            # direction this number must not fail in.
            break
        examined += 1

    return Proposal(candidates=tuple(out), findings_scanned=len(findings),
                    without_precondition=without, truncated=truncated,
                    unexamined=len(findings) - examined)


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
    # Checked one id at a time, exactly as `pivot.record` checks its finding.
    # Reading the whole id set instead inherits `db.rows`' 200-row clamp -
    # with no ORDER BY, so *which* 200 is arbitrary - and on the 259-finding
    # run that refused F259 with "names finding(s) that do not exist", a
    # false statement about a row the user can see, and no workaround,
    # because the clamp is `min(limit, MAX_ROWS)`.
    unknown = [i for i in ids
               if not db.rows(con, "cba_findings", where={"id": i},
                              columns=("id",))]
    if unknown:
        raise db.DbError(
            f"chain {chain_id} names finding(s) that do not exist: "
            f"{', '.join(unknown)}")
    row = {"id": chain_id, "finding_ids": ", ".join(ids),
           "attacker_position": attacker_position, "completeness": completeness}
    # Optional columns are OMITTED when not given, not written as "": on
    # --replace db.put merges over the stored row, so an absent key keeps its
    # value and a present one overwrites it.
    for key, value in (("pre_auth", pre_auth),
                       ("blocking_unknowns", blocking_unknowns)):
        if value:
            row[key] = value
    db.put(con, "cba_chains", row, replace=replace)


def render(p: Proposal) -> str:
    out = [f"chain candidates: {len(p.candidates)} across "
           f"{p.findings_scanned} finding(s)"]
    for c in p.candidates:
        out.append(f"  {c.enabler} -> {c.consumer}   shared: "
                   f"{', '.join(c.shared)}")
    if p.truncated:
        out.append(f"  capped at {MAX_CANDIDATES}, so the scan STOPPED: "
                   f"{p.unexamined} of {p.findings_scanned} finding(s) were "
                   f"never examined as an enabler. A chain whose enabler is "
                   f"among those is not in this list and nothing below says "
                   f"so. The impact and attacker-position text is too generic "
                   f"to join on as written - narrow it and run this again "
                   f"before treating the list as complete.")
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
