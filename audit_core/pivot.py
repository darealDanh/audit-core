"""Write a FALSE_POSITIVE verdict and the observation it pivots to, together.

Spec section 3.5: a FALSE_POSITIVE verdict is invalid unless it records what
refuted the finding and what that mechanism enables, and the latter is
written back as a rung-1 observation.

The two writes are one act because separating them is how the pivot gets
lost: the verdict is the thing the phase gate counts, so a verdict written
first and an observation "to follow" is an observation nobody writes. The
validator in db.py refuses the verdict without the observation id, and this
module is what produces one.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from audit_core import db


@dataclass(frozen=True, slots=True)
class Pivot:
    finding_id: str
    observation_id: int
    mechanism: str


def record(con: sqlite3.Connection, *, finding_id: str, group_id: str,
           mechanism: str, enables: str, reason: str = "",
           rule_applied: str = "", severity_hint: str = "",
           location: str = "", replace: bool = False) -> Pivot:
    """Record the observation, then the verdict that points at it.

    Everything that can fail is checked before the first write. `db.put`
    commits each row on its own, so a verdict that failed after the
    observation landed would leave an observation referenced by nothing -
    recoverable, but it would make `dangling()` report a problem that is not
    one. Checking first costs two queries and removes the case.
    """
    mechanism = (mechanism or "").strip()
    enables = (enables or "").strip()
    if not mechanism:
        raise db.DbError("a pivot needs --mechanism: what refuted the finding")
    if not enables:
        raise db.DbError(
            "a pivot needs --enables: what the refuting mechanism makes "
            "possible, or what this review ruled out about it. "
            "'no attacker-controlled path identified in this review' is a "
            "legitimate answer; a blank is not.")
    if not db.rows(con, "cba_findings", where={"id": finding_id},
                   columns=("id",)):
        raise db.DbError(f"no finding {finding_id!r} to pivot from")
    if not replace and db.rows(con, "cba_fp_verdicts",
                               where={"finding_id": finding_id},
                               columns=("finding_id",)):
        raise db.DbError(f"{finding_id} already has a verdict; "
                         f"pass --replace to overwrite it")

    db.put(con, "cba_security_observations", {
        "group_id": group_id,
        "observation": f"Pivot from {finding_id}: {mechanism} -- {enables}",
        "severity_hint": severity_hint or "",
        "location": location or ""})
    observation_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])

    db.put(con, "cba_fp_verdicts", {
        "finding_id": finding_id, "verdict": "FALSE_POSITIVE",
        "reason": reason or "", "rule_applied": rule_applied or "",
        "refuting_mechanism": mechanism,
        "enabled_observation": str(observation_id)}, replace=replace)

    return Pivot(finding_id=finding_id, observation_id=observation_id,
                 mechanism=mechanism)


def dangling(con: sqlite3.Connection) -> list[tuple[str, str]]:
    """FALSE_POSITIVE verdicts whose enabled_observation resolves to nothing.

    The validator checks that the field is non-empty; it has no connection,
    so it cannot check that the id exists. This is that check, run on demand
    rather than on every write.
    """
    return [(r[0], str(r[1])) for r in con.execute(
        "SELECT v.finding_id, v.enabled_observation FROM cba_fp_verdicts v "
        "LEFT JOIN cba_security_observations o "
        "  ON CAST(o.id AS TEXT) = CAST(v.enabled_observation AS TEXT) "
        "WHERE v.verdict = 'FALSE_POSITIVE' AND o.id IS NULL "
        "ORDER BY v.finding_id")]


def render(p: Pivot) -> str:
    return (f"pivot {p.finding_id}: FALSE_POSITIVE recorded, "
            f"observation {p.observation_id} written.\n"
            f"  refuting mechanism: {p.mechanism}\n"
            f"  The observation is a lead, not a finding. Read it with "
            f"`audit.py rows --table cba_security_observations "
            f"--where id={p.observation_id}`.")
