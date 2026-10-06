"""Which registered bug patterns have been swept, and which have not.

A confirmed finding is evidence about one call site and a hypothesis about
every other one. The tplink run confirmed `strncpy(dst, src, strlen(src))`
twice, named it as a pattern, and never grepped for it; two reference-set
CRITICALs are that pattern elsewhere.

Stage 2 shipped the sweep. This is the accounting that makes "we swept the
patterns we confirmed" a checkable claim instead of a recollection. The unit
is the pattern, not the finding: whether a given finding's root cause
generalises is a judgment, and a rule that guessed would fire on everything.
Whether a registered pattern has ever been swept is a fact.
"""
from __future__ import annotations

import datetime
import sqlite3
from dataclasses import dataclass

from audit_core import db

# Not 200 by coincidence. `states()` reads through `db.rows`, which clamps
# every read to `db.MAX_ROWS` with `min(limit, MAX_ROWS)` - so raising this
# number alone would change nothing except the claim it makes. The gate below
# reports PASS when it sees no unswept pattern, and a pattern beyond the clamp
# is a pattern it never saw: a gate that stops working without saying so. The
# relationship is written here so that raising the bound means raising
# db.MAX_ROWS, deliberately, in one place.
MAX_PATTERNS = db.MAX_ROWS


@dataclass(frozen=True, slots=True)
class PatternState:
    id: str
    name: str
    origin_finding: str
    swept_at: str
    hit_count: int

    @property
    def swept(self) -> bool:
        """Swept means a sweep ran, not that it found something. Zero hits is
        a result: the pattern was isolated."""
        return bool(self.swept_at)


def states(con: sqlite3.Connection) -> list[PatternState]:
    rows = db.rows(con, "cba_patterns",
                   columns=("id", "name", "origin_finding", "swept_at",
                            "hit_count"),
                   limit=MAX_PATTERNS)
    return [PatternState(id=r["id"], name=r["name"] or "",
                         origin_finding=r["origin_finding"] or "",
                         swept_at=r["swept_at"] or "",
                         hit_count=int(r["hit_count"] or 0))
            for r in rows]


def unswept(con: sqlite3.Connection) -> list[PatternState]:
    return [s for s in states(con) if not s.swept]


def mark_swept(con: sqlite3.Connection, pattern_id: str, *,
               hit_count: int, when: str | None = None) -> None:
    """Record that `pattern_id` was swept, and how many hits it produced.

    A partial UPDATE, which `db.put` cannot express - `put` writes whole
    rows. Writing it here rather than in a workflow is the point of R5: this
    is the only place the statement exists, and the column names are
    literals in this module rather than something an orchestrator retypes.
    """
    if not db.rows(con, "cba_patterns", where={"id": pattern_id},
                   columns=("id",)):
        raise db.DbError(
            f"no pattern {pattern_id!r} to mark swept; register one with "
            f"`audit.py put --table cba_patterns --set id=... --set name=... "
            f"--set regex=...`")
    stamp = when or datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("UPDATE cba_patterns SET swept_at = ?, hit_count = ? "
                "WHERE id = ?", (stamp, int(hit_count), pattern_id))
    con.commit()


def render(items: list[PatternState]) -> str:
    if not items:
        return ("patterns: none registered.\n"
                "  A confirmed finding whose root cause could appear "
                "elsewhere is a pattern. Register it with `audit.py put "
                "--table cba_patterns --set id=P1 --set name=... "
                "--set regex=... --set origin_finding=<finding-id>`.")
    gaps = [s for s in items if not s.swept]
    out = [f"patterns: {len(items)} registered, {len(gaps)} unswept"]
    if len(items) >= MAX_PATTERNS:
        out.append(f"  WARNING: this list is capped at {MAX_PATTERNS} and is "
                   f"full, so there may be registered patterns it has not "
                   f"seen - and `--gate` can only rule on what is here. Treat "
                   f"a PASS as covering these {MAX_PATTERNS} only.")
    for s in items:
        mark = "swept" if s.swept else "NEVER SWEPT"
        origin = f" from {s.origin_finding}" if s.origin_finding else ""
        out.append(f"  {s.id:6s} {s.name:40.40s} {mark:11s} "
                   f"{s.hit_count} hit(s){origin}")
    if gaps:
        out.append("  Sweep each one before the phase exits:")
        out.extend(f"    audit.py sweep --db <db> --pattern {s.id} "
                   f"--root <src> --record" for s in gaps)
        out.append("  A confirmed pattern that was never swept is the tplink "
                   "miss exactly: strncpy(dst, src, strlen(src)) was found "
                   "twice, named, and never grepped for.")
    return "\n".join(out)
