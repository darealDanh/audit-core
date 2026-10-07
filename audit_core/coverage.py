"""Coverage accounting: the denominator, not a feeling.

"Have we audited everything?" was answered by reading the feature-group list,
which records what we chose to look at. The tplink post-mortem found whole
layers never opened - not one finding below the IP layer - with nothing in the
record saying so. An inventory gives the question a denominator, and a
`not_audited` row with a reason turns a silent gap into a visible decision.

Stage 2 recorded and reported. Stage 3 adds the gate: `gate()` decides whether
a phase's coverage is good enough to exit on, and the exit code follows that
decision through `audit.py coverage --gate`.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core import db
from audit_core.db import COVERAGE_STATES, NOT_AUDITED_REASONS

MAX_UNITS_PER_CALL = 5000


@dataclass(frozen=True, slots=True)
class RecordResult:
    units: int
    phase: str
    state: str
    reason: str


def record(con: sqlite3.Connection, *, units, phase: str, state: str,
           reason: str = "", replace: bool = False) -> RecordResult:
    """Record one coverage row per unit, in one call.

    The gate this clears is per-unit, and a real corpus has thousands of
    units. One `audit.py put --table cba_coverage` per unit is thousands of
    process launches and thousands of orchestrator turns to clear one gate -
    which is the economics failure this whole suite exists to remove, so a
    gate that could only be cleared that way would get turned off instead.

    Every row goes through `db.put`, so `_validate_coverage` still applies:
    a `not_audited` row without a legal reason is refused here exactly as it
    is refused one row at a time. The whole call is validated before the
    first write, because a partial clear of a coverage gate is worse than a
    refused one - it looks like progress.
    """
    phase = (phase or "").strip()
    state = (state or "").strip()
    reason = (reason or "").strip()
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in units:
        unit = (raw or "").strip()
        if not unit or unit in seen:
            continue
        seen.add(unit)
        ordered.append(unit)
    if not phase:
        raise db.DbError("recording coverage needs a --phase: the phase whose "
                         "exit this scope is measured at")
    if state not in COVERAGE_STATES:
        raise db.DbError(f"state={state!r} is not one of "
                         + ", ".join(COVERAGE_STATES))
    if not ordered:
        raise db.DbError(
            "no units to record; pass --unit <path> (repeatable) or "
            "--from-file <list>, one unit per line")
    if len(ordered) > MAX_UNITS_PER_CALL:
        raise db.DbError(
            f"{len(ordered)} units in one call is past the "
            f"{MAX_UNITS_PER_CALL} bound; split the list. A single call that "
            f"large is a sign the unit list is a whole tree rather than what "
            f"this phase actually ruled on.")
    # Validated once, on a representative row, before anything is written.
    db.TABLE_SPECS["cba_coverage"].validate(
        {"unit": ordered[0], "phase": phase, "state": state, "reason": reason})
    for unit in ordered:
        row = {"unit": unit, "phase": phase, "state": state}
        if reason:
            row["reason"] = reason
        db.put(con, "cba_coverage", row, replace=replace)
    return RecordResult(units=len(ordered), phase=phase, state=state,
                        reason=reason)


def render_record(r: RecordResult) -> str:
    detail = f" reason={r.reason}" if r.reason else ""
    return (f"coverage: {r.units} unit(s) recorded as {r.state}{detail} "
            f"(phase {r.phase})")


@dataclass(frozen=True, slots=True)
class CoverageReport:
    inventoried: int
    analyzed: int
    not_audited: int
    unrecorded: int
    by_reason: tuple[tuple[str, int], ...]
    budget_skips: int
    phase: str | None

    @property
    def fraction(self) -> float:
        """Analyzed over inventoried. Zero when nothing is inventoried -
        a run with no inventory has no coverage claim to make, in either
        direction.

        `analyzed` counts inventoried units, so this cannot exceed 1.0.
        """
        return (self.analyzed / self.inventoried) if self.inventoried else 0.0


def _states(con: sqlite3.Connection, phase: str | None) -> tuple[int, int, int]:
    """(analyzed, not_audited, recorded), counted in inventoried units.

    Two rules, and both of them were learned the hard way.

    *Join the inventory.* The denominator is `COUNT(*) FROM cba_inventory`, so
    a numerator that counts coverage rows for units nobody inventoried reports
    more than 100% coverage. `unrecorded` already joined; these now do too.

    *One state per unit, and a gap wins.* A unit carries one coverage row per
    phase, so recon can call it analyzed and audit can record a budget skip on
    the same unit. Counted independently it lands in both tallies, and the
    report leads with `100.0% analyzed` on a run whose only unit was skipped -
    the exact scenario R3 exists for. So a unit is `analyzed` only if some
    phase analyzed it and no phase recorded a gap, and the two counts cannot
    double-count a unit. The phase-scoped call is unaffected and still reports
    exactly what that phase did.

    Both tests are explicit rather than complementary, so a state that is
    neither - only reachable by writing the table behind `db.put`, which
    rejects anything outside COVERAGE_STATES - falls out of both counts rather
    than being absorbed into `analyzed`. Overstating coverage is the failure
    this function exists to prevent; understating it is the safe direction.
    """
    sql = ("SELECT SUM(ok AND NOT gap), SUM(gap), COUNT(*) FROM ("
           "SELECT MAX(c.state = 'analyzed') AS ok, "
           "MAX(c.state = 'not_audited') AS gap "
           "FROM cba_coverage c JOIN cba_inventory i ON i.unit = c.unit")
    params: list[str] = []
    if phase is not None:
        sql += " WHERE c.phase = ?"
        params.append(phase)
    sql += " GROUP BY c.unit)"
    analyzed, not_audited, recorded = con.execute(sql, params).fetchone()
    return int(analyzed or 0), int(not_audited or 0), int(recorded or 0)


def report(con: sqlite3.Connection, phase: str | None = None) -> CoverageReport:
    inventoried = con.execute("SELECT COUNT(*) FROM cba_inventory").fetchone()[0]
    analyzed, not_audited, recorded = _states(con, phase)

    # Deliberately NOT joined to the inventory, and counted in distinct units
    # rather than rows. A `not_audited(budget)` row for something nobody
    # remembered to inventory is the loudest version of this failure, and must
    # still raise the warning; a unit skipped in two phases is still one unit.
    # It follows that the reasons can sum past `not_audited` above, which is
    # that breakdown telling you something the top line cannot.
    reason_sql = ("SELECT reason, COUNT(DISTINCT unit) FROM cba_coverage "
                  "WHERE state = 'not_audited' AND reason IS NOT NULL")
    rparams: list[str] = []
    if phase is not None:
        reason_sql += " AND phase = ?"
        rparams.append(phase)
    reason_sql += " GROUP BY reason ORDER BY reason"
    by_reason = tuple((r[0], r[1]) for r in con.execute(reason_sql, rparams))

    return CoverageReport(
        inventoried=inventoried,
        analyzed=analyzed,
        not_audited=not_audited,
        unrecorded=max(0, inventoried - recorded),
        by_reason=by_reason,
        budget_skips=dict(by_reason).get("budget", 0),
        phase=phase,
    )


def render(r: CoverageReport) -> str:
    scope = f" (phase {r.phase})" if r.phase else ""
    if r.inventoried == 0:
        return (f"coverage{scope}: the inventory is empty, so there is no "
                f"denominator to report.\n"
                f"  Populate it with `audit.py put --table cba_inventory "
                f"--set unit=<path> --set kind=file` per analysable unit.")
    out = [f"coverage{scope}: {r.analyzed}/{r.inventoried} analyzed "
           f"({100 * r.fraction:.1f}%)",
           f"  not_audited {r.not_audited}   unrecorded {r.unrecorded}"]
    if r.by_reason:
        out.append("  not_audited by reason:")
        out.extend(f"    {reason:16s} {n}" for reason, n in r.by_reason)
    if r.budget_skips:
        out.append(f"  WARNING: {r.budget_skips} unit(s) skipped for budget. "
                   f"The budget governs where tokens are spent, never whether "
                   f"a surface is opened - checkpoint and restart instead "
                   f"(SKILL.md, R3).")
    if r.unrecorded:
        out.append(f"  {r.unrecorded} inventoried unit(s) have no coverage row "
                   f"in this scope. Record them with `audit.py coverage --db "
                   f"<db> --record --phase {r.phase or '<phase>'} --state "
                   f"analyzed --from-file <list>`; legal not_audited reasons: "
                   f"{', '.join(NOT_AUDITED_REASONS)}.")
    return "\n".join(out)


@dataclass(frozen=True, slots=True)
class GateResult:
    ok: bool
    failures: tuple[str, ...]
    warnings: tuple[str, ...]


def gate(r: CoverageReport) -> GateResult:
    """Decide whether a phase's coverage is good enough to exit on.

    Three failures, and each one is a case where the record cannot support
    the claim "we audited everything":

    - Nothing inventoried. There is no denominator, so there is no claim.
      This is the vacuous pass: a run that never inventoried anything has
      zero budget skips and zero unrecorded units.
    - A unit skipped for budget. Spec R3, verbatim: a group skipped for
      budget "fails the quality gate". The budget governs where tokens are
      spent, never whether a surface is opened.
    - An inventoried unit with no coverage row. The silent case - nobody
      recorded a decision either way. Six of the ten missed tplink CRITICALs
      are on surfaces that were never opened and never written down.

    Everything else recorded as `not_audited` is a warning, not a failure.
    out-of-scope, vendored, generated and the rest are decisions, taken and
    written down, which is exactly what section 3.5 asks for. Failing on them
    would make the gate unclearable on any real target, and an unclearable
    gate gets turned off.
    """
    failures: list[str] = []
    warnings: list[str] = []
    scope = f" (phase {r.phase})" if r.phase else ""

    if r.inventoried == 0:
        failures.append(
            f"the inventory is empty{scope}, so there is no coverage "
            f"denominator. Populate it with `audit.py put --table "
            f"cba_inventory --set unit=<path> --set kind=file` per "
            f"analysable unit.")
    if r.budget_skips:
        failures.append(
            f"{r.budget_skips} unit(s) recorded not_audited(reason='budget'). "
            f"The budget governs where tokens are spent, never whether a "
            f"surface is opened: checkpoint and restart "
            f"(`audit.py checkpoint`), then audit them.")
    if r.unrecorded:
        failures.append(
            f"{r.unrecorded} inventoried unit(s) are unrecorded{scope}: no "
            f"coverage row in this scope. Record them in one call with "
            f"`audit.py coverage --db <db> --record --phase "
            f"{r.phase or '<phase>'} --state analyzed --from-file <list>` "
            f"(one unit per line), and the units nobody opened with "
            f"`--state not_audited --reason <r>`, from: "
            f"{', '.join(NOT_AUDITED_REASONS)}.")

    for reason, n in r.by_reason:
        if reason != "budget":
            warnings.append(f"{n} unit(s) not_audited(reason='{reason}')")

    return GateResult(ok=not failures, failures=tuple(failures),
                      warnings=tuple(warnings))


def render_gate(g: GateResult) -> str:
    out = ["coverage gate: " + ("PASS" if g.ok else "FAIL")]
    out.extend(f"  FAIL  {f}" for f in g.failures)
    out.extend(f"  warn  {w}" for w in g.warnings)
    return "\n".join(out)
