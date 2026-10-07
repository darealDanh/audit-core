"""Score an audit run against a golden reference set.

Only human-adjudicated pairs count toward recall. Location overlap produces a
candidate for adjudication, never a match: auto-matching on a shared symbol
inflates recall and would let a regression pass the gate.
"""
from __future__ import annotations

import pathlib
import sqlite3
from dataclasses import dataclass

from audit_core import indicators as indicators_mod
from audit_core import text
from audit_core.db import SEVERITIES
from audit_core.goldens import Reference
from audit_core.readings import Reading


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


UNDER_RATING_PENALTY = 0.25
"""Credit lost per ladder step a match is under-rated.

A quarter per step, so a CRITICAL filed LOW (three steps) keeps a quarter of
its credit and a CRITICAL filed INFORMATIONAL (four) keeps none. The exact
figure is a judgement, not a measurement - it is named here so that changing
it is a visible decision rather than an edit buried in an expression.

Over-rating costs nothing. Calling a medium a high is noise; it is not a
vulnerability anybody failed to find, and recall is a question about finding.
"""


@dataclass(frozen=True, slots=True)
class SeverityDelta:
    reference_id: str
    finding_id: str
    reference_severity: str
    finding_severity: str
    steps: int
    """Ladder steps the finding sits BELOW the reference. Negative means the
    finding was rated higher than the reference."""


@dataclass(frozen=True, slots=True)
class SeverityAgreement:
    """Whether a match that was found was also rated correctly.

    Recall asks whether the audit found the bug. This asks whether it
    understood what it found. The two are independent: an audit can reach
    12/19 while filing an authentication bypass as a low-severity overflow,
    which is what the tplink run did on four of its nine matches.
    """
    agreed: int
    under_rated: int
    over_rated: int
    unrankable: int
    worst_steps: int
    deltas: tuple[SeverityDelta, ...]


def _rank(severity: str) -> int | None:
    """Index on the ladder, or None for a severity outside the vocabulary.

    None rather than an exception: a golden carrying a severity this codebase
    does not know is a reason to report that fact, not to lose the whole
    run's score partway through computing it.
    """
    if not isinstance(severity, str):
        return None
    try:
        return SEVERITIES.index(severity.strip().upper())
    except ValueError:
        return None


def severity_agreement(
    refs: list[Reference],
    findings: list[RunFinding],
    matched: tuple[tuple[str, str], ...],
) -> SeverityAgreement:
    ref_by_id = {r.id: r for r in refs}
    finding_by_id = {f.id: f for f in findings}

    agreed = under = over = unrankable = 0
    worst = 0
    deltas: list[SeverityDelta] = []

    for ref_id, finding_id in matched:
        reference = ref_by_id.get(ref_id)
        found = finding_by_id.get(finding_id)
        if reference is None or found is None:
            continue
        r_rank, f_rank = _rank(reference.severity), _rank(found.severity)
        if r_rank is None or f_rank is None:
            unrankable += 1
            deltas.append(SeverityDelta(
                ref_id, finding_id, reference.severity, found.severity, 0))
            continue
        steps = f_rank - r_rank          # ladder is strongest-first
        if steps == 0:
            agreed += 1
            continue
        if steps > 0:
            under += 1
            worst = max(worst, steps)
        else:
            over += 1
        deltas.append(SeverityDelta(
            ref_id, finding_id, reference.severity, found.severity, steps))

    return SeverityAgreement(agreed=agreed, under_rated=under, over_rated=over,
                             unrankable=unrankable, worst_steps=worst,
                             deltas=tuple(deltas))


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
    precision: Precision | None = None
    severity: SeverityAgreement | None = None
    coverage: Reading | None = None

    @property
    def weighted_recall(self) -> float | None:
        """Recall crediting a match in full only where severity agrees.

        None, not 0.0, when severity was not scored: 0.0 reads as "every
        match was mis-rated". Emitted ALONGSIDE `recall`, never instead -
        the >= 9/19 floor and the >= 12/19 target are written against
        `recall`, and silently restating them is not this figure's job.

        Unrankable pairs (a severity outside the ladder, or not a string)
        KEEP full credit. Crediting them 0 would punish a run for a golden's
        vocabulary problem, and excluding them from the divisor would break
        comparability with `recall`, which shares `reference_count`. The
        consequence: an unrankable pair can mask a real under-rating, which
        is why both the count and the pairs themselves are printed.
        """
        if self.severity is None or not self.reference_count:
            return None
        credit = float(self.severity.agreed + self.severity.over_rated
                       + self.severity.unrankable)
        for d in self.severity.deltas:
            if d.steps > 0:
                credit += max(0.0, 1.0 - UNDER_RATING_PENALTY * d.steps)
        return credit / self.reference_count


@dataclass(frozen=True, slots=True)
class Precision:
    """TRUE_POSITIVE share of the verdicts somebody actually decided.

    DUPLICATE is excluded because a duplicate is not a wrong finding - it is
    the same right finding twice, and counting it against precision punishes
    a run for finding something from two angles. NEEDS_VERIFICATION is
    excluded because it is undecided, and counting it either way asserts a
    verdict nobody reached.

    This measures what THIS RUN'S OWN FP-check kept. A run whose FP-check is
    too lenient scores high and has learned nothing. The number is only
    meaningful comparatively: same golden, same pipeline, one variable
    changed - which is the use spec section 7 puts it to when it gates the
    Sonnet tiering change on "precision measured before and after".
    """
    true_positives: int
    false_positives: int
    duplicates: int
    needs_verification: int

    @property
    def decided(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def fraction(self) -> float | None:
        """None, not 0.0, when nothing was decided: 0.0 reads as "everything
        was a false positive"."""
        return (self.true_positives / self.decided) if self.decided else None


def precision_from_db(db_path: str | pathlib.Path) -> Precision | None:
    """Count verdicts. None when the run predates cba_fp_verdicts.

    Opened read-only without db.connect()'s schema gate, for the same reason
    load_findings_from_db is: bench must keep scoring recall against run
    directories older than the current schema, and that gate rejects exactly
    those.
    """
    path = pathlib.Path(db_path)
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if not con.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'cba_fp_verdicts'").fetchone():
            return None
        counts = dict(con.execute(
            "SELECT verdict, COUNT(*) FROM cba_fp_verdicts GROUP BY verdict"))
    finally:
        con.close()
    return Precision(
        true_positives=counts.get("TRUE_POSITIVE", 0),
        false_positives=counts.get("FALSE_POSITIVE", 0),
        duplicates=counts.get("DUPLICATE", 0),
        needs_verification=counts.get("NEEDS_VERIFICATION", 0))


def coverage_from_db(db_path: str | pathlib.Path) -> Reading:
    """Analyzed over inventoried, or the reason there is no such fraction.

    Reports the whole-run figure (phase=None), not the phase-scoped figure
    that the coverage exit gate answers.

    Opened read-only and ungated, for the same reason `load_findings_from_db`
    is: bench must keep scoring run directories older than the current
    schema, and `db.connect()` rejects exactly those.
    """
    path = pathlib.Path(db_path)
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return indicators_mod.coverage_reading(con)
    finally:
        con.close()


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
    precision: Precision | None = None,
    coverage: Reading | None = None,
) -> BenchResult:
    """Score `findings` against `refs`.

    `rejected`, `cost_usd` and `precision` are keyword-only: `rejected` was
    added ahead of `cost_usd`, so a positional fourth argument that used to
    be a cost would now be read as a set of rejected pairs and silently drop
    the cost figure. `precision` is scored separately by `precision_from_db`
    and passed through unchanged, for the same reason - a positional slot
    would silently swallow whichever keyword-only argument used to sit there.

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

    agreement = severity_agreement(refs, findings, tuple(matched))

    return BenchResult(
        recall=recall,
        matched=tuple(matched),
        unmatched_references=tuple(r.id for r in refs if r.id not in matched_refs),
        candidates=tuple(candidates),
        reference_count=len(refs),
        finding_count=len(findings),
        cost_per_match=cost_per_match,
        suppressed_candidates=suppressed,
        precision=precision,
        severity=agreement,
        coverage=coverage,
    )
