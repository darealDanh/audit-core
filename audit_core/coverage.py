"""Coverage accounting: the denominator, not a feeling.

"Have we audited everything?" was answered by reading the feature-group list,
which records what we chose to look at. The tplink post-mortem found whole
layers never opened - not one finding below the IP layer - with nothing in the
record saying so. An inventory gives the question a denominator, and a
`not_audited` row with a reason turns a silent gap into a visible decision.

Stage 2 records and reports. Nothing here fails a run: gating on coverage is a
Stage 3 quality change that is benchmarked on its own, so that if recall moves
we know which change moved it.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core.db import NOT_AUDITED_REASONS


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
        direction."""
        return (self.analyzed / self.inventoried) if self.inventoried else 0.0


def _distinct_units(con: sqlite3.Connection, state: str,
                    phase: str | None) -> int:
    sql = "SELECT COUNT(DISTINCT unit) FROM cba_coverage WHERE state = ?"
    params: list[str] = [state]
    if phase is not None:
        sql += " AND phase = ?"
        params.append(phase)
    return con.execute(sql, params).fetchone()[0]


def report(con: sqlite3.Connection, phase: str | None = None) -> CoverageReport:
    inventoried = con.execute("SELECT COUNT(*) FROM cba_inventory").fetchone()[0]
    analyzed = _distinct_units(con, "analyzed", phase)
    not_audited = _distinct_units(con, "not_audited", phase)

    recorded_sql = ("SELECT COUNT(DISTINCT c.unit) FROM cba_coverage c "
                    "JOIN cba_inventory i ON i.unit = c.unit")
    params: list[str] = []
    if phase is not None:
        recorded_sql += " WHERE c.phase = ?"
        params.append(phase)
    recorded = con.execute(recorded_sql, params).fetchone()[0]

    reason_sql = ("SELECT reason, COUNT(*) FROM cba_coverage "
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
                   f"in this scope. Legal reasons: {', '.join(NOT_AUDITED_REASONS)}.")
    return "\n".join(out)
