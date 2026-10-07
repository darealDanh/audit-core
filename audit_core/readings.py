"""A measurement, or the reason there isn't one.

Three states, and the distinction between two of them is the whole point.

`absent` means the table does not exist in this database - it predates the
feature. `empty` means the table exists and has no rows, which is a real
measurement whose value may legitimately be zero. Collapsing them renders
both as `0`, and a reader cannot then tell a database written before Stage 2
from a run that analysed nothing. One of those is a non-event; the other is a
catastrophe.

This is not a hypothetical. The only `audit.db` in existence as of 2026-10-07
has no `cba_coverage` table at all.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

ABSENT = "absent"
EMPTY = "empty"
PRESENT = "present"


@dataclass(frozen=True, slots=True)
class Reading:
    state: str
    value: object | None = None
    detail: tuple[tuple[str, int], ...] = ()
    note: str = ""

    @classmethod
    def absent(cls, note: str) -> "Reading":
        return cls(state=ABSENT, value=None, note=note)

    @classmethod
    def of(cls, value: object,
           detail: tuple[tuple[str, int], ...] = ()) -> "Reading":
        """A real measurement. `empty` when the value is a zero count AND no
        detail rows exist - still a number, still rendered as one."""
        state = EMPTY if (value == 0 and not detail) else PRESENT
        return cls(state=state, value=value, detail=tuple(detail))

    @property
    def is_absent(self) -> bool:
        return self.state == ABSENT

    def render(self, unit: str = "") -> str:
        if self.is_absent:
            return f"absent -- {self.note}"
        return f"{self.value}{unit}"

    def as_json(self) -> dict:
        out: dict = {"state": self.state}
        if self.is_absent:
            out["note"] = self.note
        else:
            out["value"] = self.value
            if self.detail:
                out["detail"] = [list(d) for d in self.detail]
        return out


def table_state(con: sqlite3.Connection, *names: str) -> str:
    """ABSENT if ANY named table is missing, else PRESENT.

    Any, not all: an indicator computed from a join across two tables cannot
    be reported when one side does not exist, and reporting it from the half
    that does exist is how a denominator goes missing silently.
    """
    if not names:
        raise ValueError("table_state requires at least one table name")
    placeholders = ", ".join("?" for _ in names)
    found = {r[0] for r in con.execute(
        f"SELECT name FROM sqlite_master WHERE type = 'table' "
        f"AND name IN ({placeholders})", names)}
    return PRESENT if found >= set(names) else ABSENT
