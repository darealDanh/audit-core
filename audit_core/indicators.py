"""The deterministic leading indicators of the design spec, section 6.1.

The parent spec runs the benchmark at milestones only - a full re-run cost
$658.37 - and says that between milestones these four figures are used
instead: coverage percentage, surfaces opened, sweep hit counts, and the
`not_audited` row count. They were never built, which made deferring a gate
blind rather than deferred.

Each figure is a `Reading`, so a database that predates the table reports
`absent` and never `0`. Three of the four have no data in any audit.db that
exists today; they ship verified against fixtures, and their first real
reading comes from a later run.
"""
from __future__ import annotations

import datetime
import json
import pathlib
import re
import sqlite3
from dataclasses import dataclass

from audit_core import coverage as coverage_mod
from audit_core.readings import ABSENT, Reading, table_state

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Indicators:
    target: str
    phase: str | None
    coverage: Reading
    surfaces: Reading
    sweep_hits: Reading
    not_audited: Reading


def coverage_reading(con: sqlite3.Connection, phase: str | None = None) -> Reading:
    """Coverage percentage as a Reading.

    Returns `absent` for two distinct causes: either the coverage or inventory
    table is missing (the database predates Stage 2), or the inventory is empty
    and there is therefore no denominator for a percentage. Either way, a
    fabricated `0%` claim would be wrong.
    """
    if table_state(con, "cba_coverage", "cba_inventory") == ABSENT:
        return Reading.absent(
            "cba_coverage / cba_inventory are not in this database "
            "(it predates Stage 2)")
    r = coverage_mod.report(con, phase)
    if r.inventoried == 0:
        return Reading.absent(
            "the inventory is empty, so there is no denominator")
    return Reading.of(round(100 * r.fraction, 1),
                      detail=(("analyzed", r.analyzed),
                              ("inventoried", r.inventoried)))


def _surfaces(con: sqlite3.Connection) -> Reading:
    if table_state(con, "cba_attack_surface") == ABSENT:
        return Reading.absent("cba_attack_surface is not in this database")
    total = con.execute("SELECT COUNT(*) FROM cba_attack_surface").fetchone()[0]
    detail = tuple((str(g) if g is not None else "(none)", n) for g, n in
                   con.execute("SELECT group_id, COUNT(*) FROM "
                               "cba_attack_surface GROUP BY group_id "
                               "ORDER BY group_id"))
    return Reading.of(total, detail=detail)


def _sweep_hits(con: sqlite3.Connection) -> Reading:
    if table_state(con, "cba_pattern_hits") == ABSENT:
        return Reading.absent("cba_pattern_hits is not in this database")
    total = con.execute("SELECT COUNT(*) FROM cba_pattern_hits").fetchone()[0]
    detail = tuple((str(p), n) for p, n in
                   con.execute("SELECT pattern_id, COUNT(*) FROM "
                               "cba_pattern_hits GROUP BY pattern_id "
                               "ORDER BY pattern_id"))
    return Reading.of(total, detail=detail)


def _not_audited(con: sqlite3.Connection, phase: str | None) -> Reading:
    if table_state(con, "cba_coverage") == ABSENT:
        return Reading.absent("cba_coverage is not in this database")
    # The detail rows enumerate reasons for not_audited, but exclude NULL
    # reasons (units recorded as not_audited without a recorded reason), so
    # detail can sum lower than the headline. Also, in an unscoped read, a unit
    # skipped for multiple reasons appears under each reason, so detail can sum
    # higher than the headline. This breakdown tells you something the top line
    # cannot.
    sql = ("SELECT COUNT(DISTINCT unit) FROM cba_coverage "
           "WHERE state = 'not_audited'")
    rsql = ("SELECT reason, COUNT(DISTINCT unit) FROM cba_coverage "
            "WHERE state = 'not_audited' AND reason IS NOT NULL")
    params: list[str] = []
    if phase is not None:
        sql += " AND phase = ?"
        rsql += " AND phase = ?"
        params.append(phase)
    rsql += " GROUP BY reason ORDER BY reason"
    total = con.execute(sql, params).fetchone()[0]
    detail = tuple((str(r), n) for r, n in con.execute(rsql, params))
    return Reading.of(total, detail=detail)


def collect(con: sqlite3.Connection, *, target: str,
            phase: str | None = None) -> Indicators:
    return Indicators(
        target=target, phase=phase,
        coverage=coverage_reading(con, phase),
        surfaces=_surfaces(con),
        sweep_hits=_sweep_hits(con),
        not_audited=_not_audited(con, phase))


_UNITS = {"coverage": "%", "surfaces": "", "sweep_hits": "", "not_audited": ""}
_LABELS = {"coverage": "coverage", "surfaces": "surfaces opened",
           "sweep_hits": "sweep hits", "not_audited": "not_audited units"}


def render(ind: Indicators) -> str:
    scope = f" (phase {ind.phase})" if ind.phase else ""
    out = [f"indicators for {ind.target}{scope}"]
    for key in ("coverage", "surfaces", "sweep_hits", "not_audited"):
        r: Reading = getattr(ind, key)
        out.append(f"  {_LABELS[key]:<18} {r.render(_UNITS[key])}")
        for name, n in r.detail:
            out.append(f"      {name:<16} {n}")
    if any(getattr(ind, k).is_absent
           for k in ("coverage", "surfaces", "sweep_hits", "not_audited")):
        out.append("")
        out.append("  `absent` means a measurement cannot be made: either the "
                   "table is not in this database, or (for coverage) the "
                   "inventory is empty so there is no denominator. Each entry "
                   "says why.")
    return "\n".join(out)


def to_json(ind: Indicators) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "target": ind.target,
        "phase": ind.phase,
        "indicators": {k: getattr(ind, k).as_json() for k in
                       ("coverage", "surfaces", "sweep_hits", "not_audited")},
    }


SNAPSHOT_DIR = ("docs", "indicators")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class IndicatorError(Exception):
    """A snapshot cannot be written where it was asked for."""


def snapshot_path(root: str | pathlib.Path, target: str,
                  when: datetime.date, label: str | None = None) -> pathlib.Path:
    """`docs/indicators/YYYY-MM-DD-<target>[-<label>].json`.

    The target and label are slugged, because they reach the filesystem: a
    target named from a directory can carry a slash, and a path separator in
    a filename component silently writes somewhere nobody looked.
    """
    stem = _SAFE.sub("-", target).strip("-.") or "unnamed"
    if label:
        stem += "-" + (_SAFE.sub("-", label).strip("-.") or "labelled")
    return pathlib.Path(root).joinpath(*SNAPSHOT_DIR) / f"{when:%Y-%m-%d}-{stem}.json"


def write_snapshot(path: str | pathlib.Path, ind: Indicators) -> pathlib.Path:
    """Write, and refuse to overwrite.

    `docs/indicators/` follows the `docs/baselines/` rule: a measurement is
    never edited in place, so a superseded one stays visible in git history.
    Silently overwriting today's snapshot with this afternoon's would destroy
    the morning's measurement and leave no trace that it existed.
    """
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # "x" is exclusive creation: the existence check and the create are one
        # atomic step, so two writers cannot both pass a check and truncate.
        with open(path, "x") as fh:
            fh.write(json.dumps(to_json(ind), indent=2) + "\n")
    except FileExistsError:
        raise IndicatorError(
            f"{path} already exists. Measurements are never edited in place -- "
            f"pass --label <word> to write a second snapshot of the same "
            f"target on the same day.") from None
    return path


@dataclass(frozen=True, slots=True)
class Delta:
    name: str
    before: str
    after: str
    moved: str


def _fmt(entry: dict) -> str:
    if entry.get("state") == ABSENT:
        return "absent"
    return str(entry.get("value"))


def compare(a: dict, b: dict) -> tuple[Delta, ...]:
    """Diff two snapshots, indicator by indicator.

    An indicator present in one snapshot and not the other is reported as
    `not comparable`, never as a delta against zero: the older snapshot was
    taken before that indicator existed, and inventing a movement from
    nothing to something is a fabricated measurement. The same holds when
    either side is `absent` - a value against a missing table is not a
    difference anyone can interpret.
    """
    names = sorted(set(a.get("indicators", {})) | set(b.get("indicators", {})))
    out: list[Delta] = []
    for name in names:
        ea = a.get("indicators", {}).get(name)
        eb = b.get("indicators", {}).get(name)
        if ea is None or eb is None:
            out.append(Delta(name,
                             _fmt(ea) if ea else "not in snapshot",
                             _fmt(eb) if eb else "not in snapshot",
                             "not comparable"))
            continue
        before, after = _fmt(ea), _fmt(eb)
        if ea.get("state") == ABSENT or eb.get("state") == ABSENT:
            moved = "unchanged" if before == after else "not comparable"
        elif ea.get("value") == eb.get("value"):
            moved = "unchanged"
        else:
            # Only compute delta for numeric values (int or float, not bool)
            ea_val = ea.get("value")
            eb_val = eb.get("value")
            if (isinstance(ea_val, (int, float)) and not isinstance(ea_val, bool) and
                isinstance(eb_val, (int, float)) and not isinstance(eb_val, bool)):
                diff = eb_val - ea_val
                moved = f"{round(diff, 6):+}"
            else:
                moved = "not comparable"
        out.append(Delta(name, before, after, moved))
    return tuple(out)


def render_compare(a_name: str, b_name: str,
                   deltas: tuple[Delta, ...]) -> str:
    out = [f"comparing {a_name} -> {b_name}",
           f"  {'indicator':<18} {'before':>15} {'after':>15}   moved"]
    for d in deltas:
        out.append(f"  {d.name:<18} {d.before:>15} {d.after:>15}   {d.moved}")
    if any(d.moved == "not comparable" for d in deltas):
        out.append("")
        out.append("  `not comparable` means one snapshot has no reading for "
                   "that indicator, not that it did not move.")
    return "\n".join(out)
