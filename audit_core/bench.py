"""Score an audit run against a golden reference set.

Only human-adjudicated pairs count toward recall. Location overlap produces a
candidate for adjudication, never a match: auto-matching on a shared symbol
inflates recall and would let a regression pass the gate.
"""
from __future__ import annotations

import pathlib
import sqlite3
from dataclasses import dataclass

from audit_core import text
from audit_core.goldens import Reference


@dataclass(frozen=True, slots=True)
class RunFinding:
    id: str
    title: str
    cwe: str | None
    location: str
    severity: str


@dataclass(frozen=True, slots=True)
class Candidate:
    reference_id: str
    finding_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class BenchResult:
    recall: float
    matched: tuple[tuple[str, str], ...]
    unmatched_references: tuple[str, ...]
    candidates: tuple[Candidate, ...]
    reference_count: int
    finding_count: int
    cost_per_match: float | None
    suppressed_candidates: int = 0
    """Pairs that would have been raised as candidates but were rejected.

    Counted inside the candidate loop, so it is the number of adjudications
    this run actually saved - not the number of rows in rejections.json. The
    two differ whenever a rejected pair no longer overlaps at all, which is
    the case for both tplink pairs now that `tss` is under the token floor.
    """


def load_findings_from_db(db_path: str | pathlib.Path) -> list[RunFinding]:
    con = sqlite3.connect(f"file:{pathlib.Path(db_path)}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT id, title, cwe, location, severity FROM cba_findings ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    return [RunFinding(r[0], r[1], r[2], r[3], r[4]) for r in rows]


def score(
    refs: list[Reference],
    findings: list[RunFinding],
    adjudicated: dict[str, str],
    *,
    rejected: frozenset[tuple[str, str]] = frozenset(),
    cost_usd: float | None = None,
) -> BenchResult:
    """Score `findings` against `refs`.

    `rejected` and `cost_usd` are keyword-only: `rejected` was added ahead of
    `cost_usd`, so a positional fourth argument that used to be a cost would
    now be read as a set of rejected pairs and silently drop the cost figure.

    `adjudicated` is the only source of matches. `rejected` holds pairs a
    human already looked at and turned down; they are suppressed from the
    candidate list so a second run does not re-charge the same adjudication.
    A rejection never touches the match path - matches.json wins.
    """
    by_id = {f.id: f for f in findings}

    matched: list[tuple[str, str]] = []
    for ref in refs:
        finding_id = adjudicated.get(ref.id)
        if finding_id and finding_id in by_id:
            matched.append((ref.id, finding_id))

    matched_refs = {r for r, _ in matched}
    matched_findings = {f for _, f in matched}

    candidates: list[Candidate] = []
    suppressed = 0
    for ref in refs:
        if ref.id in matched_refs:
            continue
        ref_tokens: frozenset[str] = frozenset()
        for loc in ref.locations:
            ref_tokens |= text.location_tokens(loc)
        if not ref_tokens:
            continue
        for finding in findings:
            if finding.id in matched_findings:
                continue
            shared = ref_tokens & text.location_tokens(finding.location)
            if not shared:
                continue
            if (ref.id, finding.id) in rejected:
                suppressed += 1
                continue
            candidates.append(Candidate(
                ref.id, finding.id,
                "location overlap: " + ", ".join(sorted(shared))))

    recall = len(matched) / len(refs) if refs else 0.0
    cost_per_match = (cost_usd / len(matched)) if (cost_usd is not None and matched) else None

    return BenchResult(
        recall=recall,
        matched=tuple(matched),
        unmatched_references=tuple(r.id for r in refs if r.id not in matched_refs),
        candidates=tuple(candidates),
        reference_count=len(refs),
        finding_count=len(findings),
        cost_per_match=cost_per_match,
        suppressed_candidates=suppressed,
    )
