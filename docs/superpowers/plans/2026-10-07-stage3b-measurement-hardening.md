# Stage 3b — Measurement Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the project cheap, deterministic signal about an audit's quality — leading indicators, severity agreement, coverage — without changing anything an audit records, and close the four defects Stages 0 and 1 parked.

**Architecture:** One new primitive (`readings.py`) carries the three-state distinction every new reader needs — a value, `empty`, or `absent` — and two new modules (`indicators.py`, `rerate.py`) plus two `bench` extensions are built on it. Two new verbs (`indicators`, `rerate`) read a finished run and print; neither writes to `audit.db`. The four defect fixes are independent one-file changes.

**Tech Stack:** Python 3.10+, stdlib only, no network. SQLite via `sqlite3`. pytest.

**Spec:** [`docs/superpowers/specs/2026-10-07-stage3b-measurement-hardening-design.md`](../specs/2026-10-07-stage3b-measurement-hardening-design.md), which derives from [`2026-10-04-audit-suite-design.md`](../specs/2026-10-04-audit-suite-design.md) §5.3, §6.1 and §7.

## Global Constraints

- **`audit_core` is stdlib-only and reaches no network.** `pyproject.toml` declares `dependencies = []` and `requires-python = ">=3.10"`.
- **Nothing in this stage changes audit output.** No task writes a row to `cba_findings`, alters a stored severity, or adds a step to a phase's execution path. This is what makes the stage mergeable while the benchmark gates are deferred on cost.
- **`recall` keeps its present meaning** — matched on root cause and location. 9/19 stays valid and every citation of it stays correct.
- **`absent` never renders as a number**, in human or JSON output. See Review Focus 1.
- **Never write `tests/goldens/*/matches.json` or `tests/goldens/*/rejections.json`.** Both are human adjudications.
- **Never edit a document under `docs/baselines/` in place.** A correction is an appended, dated note or a new dated file.
- **Never run `install.sh` or `install.ps1` without overriding `HOME`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME`.** Use `make install-smoke`.
- **No audit runs.** Every deliverable reads an existing `audit.db`, changes code, or changes prose.
- **Prose edits follow the anti-absence rule:** write the intended change list to `docs/superpowers/derivations/` *before* editing, reconcile against `git diff -U0` after.
- **A `>` blockquote in a workflow file is presented to the user, not executed.** Never place a command in one and expect it to run.
- **`make all` must pass before any task is considered done.**

## Review Focus

Five input classes the spec implies but no task's happy path exercises. Each has its test pinned to the task that owns the code.

1. **A pre-Stage-2 database, where `cba_coverage` / `cba_inventory` / `cba_patterns` / `cba_pattern_hits` do not exist.** This is not hypothetical — it is the only `audit.db` that exists. Every new reader must report `absent`, never `0%` or `0`. Pinned in Task 1 (Step 5) and Task 2 (Step 9).
2. **A database where those tables exist but hold no rows.** Here `0` is a *legitimate* measurement and must render as a number, not as `absent`. The two cases are indistinguishable from the output unless this is deliberate. Pinned in Task 1 (Step 7) and Task 2 (Step 11).
3. **A golden reference carrying a severity outside `db.SEVERITIES`** — a typo, or a vocabulary that grew. Ranking it against the ladder would raise `ValueError` mid-score and lose the whole run's result. Pinned in Task 5 (Step 9).
4. **`--compare` across two snapshots whose indicator sets differ**, because one was taken before an indicator existed. Reporting a delta against a missing key invents a measurement. Pinned in Task 4 (Step 7).
5. **Two snapshots of the same target on the same day.** `docs/indicators/` follows the never-edit-in-place rule, so the second must not silently overwrite the first. Pinned in Task 3 (Step 11).

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `audit_core/readings.py` | The three-state reading primitive: a value, `empty`, or `absent`. Nothing else. |
| `audit_core/indicators.py` | The four leading indicators of spec §6.1, and snapshot serialisation. |
| `audit_core/rerate.py` | Advisory severity re-rating: compares a finding's severity against its own cited evidence. Stores nothing. |
| `tests/test_readings.py` | Tri-state primitive. |
| `tests/test_indicators.py` | The four indicators, against fixtures. |
| `tests/test_rerate.py` | The advisory report. |
| `tests/test_bench_severity.py` | Severity agreement and weighted recall. |
| `docs/indicators/` | Dated JSON snapshots, tracked, never edited in place. |
| `docs/superpowers/derivations/2026-10-07-stage3b-prose-derivation.md` | Anti-absence derivation for the one prose edit. |

**Modified:**

| File | Change |
|---|---|
| `audit_core/bench.py` | `SeverityAgreement`, `severity_agreement()`, `coverage_from_db()`, two new `BenchResult` fields. |
| `audit_core/preflight.py` | `merge_server()` — `--server` merges over a kept definition. |
| `audit_core/briefs.py` | `render()` reports missing and empty placeholders in one pass. |
| `audit_core/chains.py` | `compose()` stops blanking optional columns. |
| `audit_core/identity.py` | `record()` stops blanking optional columns. |
| `audit.py` | Two verbs (`indicators`, `rerate`), `--server` merge, bench output. 20 → 22 verbs. |
| `workflows/fpcheck.md` | Batch identifiers unified with the reference. |
| `feature_lists.json` | Stage 3b features move `planned` → `shipped`. |
| `tests/test_preflight.py`, `tests/test_briefs.py`, `tests/test_chains.py`, `tests/test_identity.py` | Reproduction tests for the four defects. |

**Why `readings.py` is its own file rather than a few helpers in `db.py`:** `db.py` is already 579 lines and is the validated-write path. The tri-state is a *read* concern used by `indicators.py`, `bench.py` and `rerate.py`, none of which are writers. Putting it in `db.py` would couple three readers to the module whose job is refusing bad writes.

---

## Task 1: The three-state reading primitive

**Files:**
- Create: `audit_core/readings.py`
- Test: `tests/test_readings.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ABSENT`, `EMPTY`, `PRESENT` (str constants); `Reading(state: str, value: object | None, detail: tuple[tuple[str, int], ...])`; `Reading.absent(note: str) -> Reading`; `Reading.of(value, detail=()) -> Reading`; `Reading.render(self, unit: str = "") -> str`; `Reading.as_json(self) -> dict`; `table_state(con: sqlite3.Connection, *names: str) -> str`.

- [ ] **Step 1: Write the failing test for the absent/zero distinction**

```python
# tests/test_readings.py
from audit_core import readings


def test_absent_never_renders_as_a_number():
    """The rule this module exists for. A database from before the feature
    existed and a run that covered nothing both produce `0` otherwise, and a
    reader cannot tell a non-event from a catastrophe."""
    r = readings.Reading.absent("cba_coverage is not in this database")
    rendered = r.render(unit="%")
    assert "0" not in rendered
    assert "absent" in rendered
    assert "cba_coverage is not in this database" in rendered
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_readings.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'audit_core.readings'`

- [ ] **Step 3: Write the module**

```python
# audit_core/readings.py
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
from dataclasses import dataclass, field

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
    placeholders = ", ".join("?" for _ in names)
    found = {r[0] for r in con.execute(
        f"SELECT name FROM sqlite_master WHERE type = 'table' "
        f"AND name IN ({placeholders})", names)}
    return PRESENT if found >= set(names) else ABSENT
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_readings.py -v`
Expected: PASS

- [ ] **Step 5: Pin Review Focus 1 — a pre-Stage-2 database**

```python
# tests/test_readings.py
import sqlite3


def test_table_state_is_absent_when_any_named_table_is_missing():
    """Review Focus 1. A coverage percentage is cba_coverage joined to
    cba_inventory; if either is missing there is no fraction to report, and
    reporting one from the half that exists loses the denominator silently."""
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE cba_inventory (unit TEXT)")
    assert readings.table_state(con, "cba_inventory") == readings.PRESENT
    assert readings.table_state(
        con, "cba_inventory", "cba_coverage") == readings.ABSENT
    con.close()
```

- [ ] **Step 6: Run it**

Run: `python3 -m pytest tests/test_readings.py -v`
Expected: PASS

- [ ] **Step 7: Pin Review Focus 2 — empty is a number, absent is not**

```python
# tests/test_readings.py
def test_empty_is_a_real_zero_and_absent_is_not():
    """Review Focus 2. A table that exists and holds no rows measured zero.
    That is a fact about the run. `absent` is a fact about the schema."""
    empty = readings.Reading.of(0)
    assert empty.state == readings.EMPTY
    assert empty.render() == "0"
    assert empty.as_json() == {"state": "empty", "value": 0}

    gone = readings.Reading.absent("no such table")
    assert gone.as_json() == {"state": "absent", "note": "no such table"}
    assert "value" not in gone.as_json()


def test_a_zero_count_with_detail_rows_is_present_not_empty():
    """A breakdown that lists reasons while the headline is zero is a real
    reading with structure, not an empty one."""
    r = readings.Reading.of(0, detail=(("budget", 0),))
    assert r.state == readings.PRESENT
```

- [ ] **Step 8: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS, test count up by 4

- [ ] **Step 9: Commit**

```bash
git add audit_core/readings.py tests/test_readings.py
git commit -m "feat: a reading is a value, or the reason there isn't one"
```

---

## Task 2: The four leading indicators

**Files:**
- Create: `audit_core/indicators.py`
- Test: `tests/test_indicators.py`

**Interfaces:**
- Consumes: `audit_core.readings.{Reading, ABSENT, EMPTY, PRESENT, table_state}`; `audit_core.coverage.report`.
- Produces: `Indicators(target: str, phase: str | None, coverage: Reading, surfaces: Reading, sweep_hits: Reading, not_audited: Reading)`; `collect(con, *, target: str, phase: str | None = None) -> Indicators`; `render(ind: Indicators) -> str`; `to_json(ind: Indicators) -> dict`; `SCHEMA_VERSION = 1`.

- [ ] **Step 1: Write the failing test for a populated database**

```python
# tests/test_indicators.py
import sqlite3

import pytest

from audit_core import indicators, readings


def _db(tmp_path, *, coverage=True, surfaces=True, patterns=True):
    """A run database with whichever table families the test needs.

    Built table by table rather than from schema.sql, because the point of
    most of these tests is a database that is MISSING a family.
    """
    con = sqlite3.connect(tmp_path / "audit.db")
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, "
                "title TEXT, cwe TEXT, location TEXT, severity TEXT)")
    if surfaces:
        con.execute("CREATE TABLE cba_attack_surface ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, "
                    "endpoint TEXT, method TEXT, auth_required TEXT, "
                    "description TEXT)")
    if coverage:
        con.execute("CREATE TABLE cba_inventory (unit TEXT PRIMARY KEY, "
                    "kind TEXT NOT NULL, group_id TEXT, size INTEGER, "
                    "added_at TEXT)")
        con.execute("CREATE TABLE cba_coverage (unit TEXT NOT NULL, "
                    "phase TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, "
                    "recorded_at TEXT, PRIMARY KEY (unit, phase))")
    if patterns:
        con.execute("CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, "
                    "name TEXT NOT NULL, regex TEXT NOT NULL, "
                    "origin_finding TEXT, language TEXT, notes TEXT, "
                    "swept_at TEXT, hit_count INTEGER, created_at TEXT)")
        con.execute("CREATE TABLE cba_pattern_hits ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "pattern_id TEXT NOT NULL, path TEXT NOT NULL, "
                    "line INTEGER NOT NULL, excerpt TEXT, triaged TEXT, "
                    "swept_at TEXT)")
    con.commit()
    return con


def test_collect_reports_all_four_indicators(tmp_path):
    con = _db(tmp_path)
    con.executemany("INSERT INTO cba_inventory (unit, kind) VALUES (?, 'file')",
                    [("a.c",), ("b.c",), ("c.c",), ("d.c",)])
    con.executemany(
        "INSERT INTO cba_coverage (unit, phase, state, reason) VALUES (?,?,?,?)",
        [("a.c", "audit", "analyzed", None), ("b.c", "audit", "analyzed", None),
         ("c.c", "audit", "not_audited", "budget")])
    con.executemany(
        "INSERT INTO cba_attack_surface (group_id, endpoint) VALUES (?,?)",
        [("G1", "/login"), ("G1", "/admin"), ("G2", "/api")])
    con.execute("INSERT INTO cba_patterns (id, name, regex) "
                "VALUES ('P1', 'strcpy', 'strcpy')")
    con.executemany(
        "INSERT INTO cba_pattern_hits (pattern_id, path, line) VALUES (?,?,?)",
        [("P1", "x.c", 10), ("P1", "y.c", 20)])
    con.commit()

    ind = indicators.collect(con, target="demo")

    assert ind.coverage.state == readings.PRESENT
    assert ind.coverage.value == pytest.approx(50.0)
    assert ind.surfaces.value == 3
    assert dict(ind.surfaces.detail) == {"G1": 2, "G2": 1}
    assert ind.sweep_hits.value == 2
    assert dict(ind.sweep_hits.detail) == {"P1": 2}
    assert ind.not_audited.value == 1
    assert dict(ind.not_audited.detail) == {"budget": 1}
    con.close()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_indicators.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'audit_core.indicators'`

- [ ] **Step 3: Write the module**

```python
# audit_core/indicators.py
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

import sqlite3
from dataclasses import dataclass

from audit_core import coverage as coverage_mod
from audit_core.readings import ABSENT, PRESENT, Reading, table_state

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Indicators:
    target: str
    phase: str | None
    coverage: Reading
    surfaces: Reading
    sweep_hits: Reading
    not_audited: Reading


def _coverage(con: sqlite3.Connection, phase: str | None) -> Reading:
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
        coverage=_coverage(con, phase),
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
        out.append("  `absent` means the table is not in this database, not "
                   "that the value is zero.")
    return "\n".join(out)


def to_json(ind: Indicators) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "target": ind.target,
        "phase": ind.phase,
        "indicators": {k: getattr(ind, k).as_json() for k in
                       ("coverage", "surfaces", "sweep_hits", "not_audited")},
    }
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_indicators.py -v`
Expected: PASS

- [ ] **Step 5: Test the phase scope**

```python
# tests/test_indicators.py
def test_not_audited_is_phase_scoped(tmp_path):
    """The coverage gate's defect, in a different reader: an unscoped count
    answers a question nobody asked. A unit skipped in recon is not a gap in
    audit."""
    con = _db(tmp_path)
    con.execute("INSERT INTO cba_inventory (unit, kind) VALUES ('a.c','file')")
    con.executemany(
        "INSERT INTO cba_coverage (unit, phase, state, reason) VALUES (?,?,?,?)",
        [("a.c", "recon", "not_audited", "budget"),
         ("a.c", "audit", "analyzed", None)])
    con.commit()
    assert indicators.collect(con, target="t", phase="audit").not_audited.value == 0
    assert indicators.collect(con, target="t", phase="recon").not_audited.value == 1
    con.close()
```

- [ ] **Step 6: Run it**

Run: `python3 -m pytest tests/test_indicators.py -v`
Expected: PASS

- [ ] **Step 7: Test the render**

```python
# tests/test_indicators.py
def test_render_names_every_indicator(tmp_path):
    con = _db(tmp_path)
    con.commit()
    out = indicators.render(indicators.collect(con, target="demo"))
    for label in ("coverage", "surfaces opened", "sweep hits",
                  "not_audited units"):
        assert label in out
    assert "demo" in out
    con.close()
```

- [ ] **Step 8: Run it**

Run: `python3 -m pytest tests/test_indicators.py -v`
Expected: PASS

- [ ] **Step 9: Pin Review Focus 1 — the real pre-Stage-2 shape**

```python
# tests/test_indicators.py
def test_a_pre_stage2_database_reports_absent_not_zero(tmp_path):
    """Review Focus 1, and not hypothetical: the only audit.db in existence
    on 2026-10-07 has cba_attack_surface and cba_findings but none of the
    coverage, inventory or pattern tables.

    Reporting `coverage 0.0%` on it would claim the run analysed nothing,
    when the truth is that the feature did not exist when it ran."""
    con = _db(tmp_path, coverage=False, patterns=False)
    con.executemany(
        "INSERT INTO cba_attack_surface (group_id, endpoint) VALUES (?,?)",
        [("G1", "/a")] * 197)
    con.commit()

    ind = indicators.collect(con, target="tplink")
    assert ind.coverage.is_absent
    assert ind.sweep_hits.is_absent
    assert ind.not_audited.is_absent
    assert ind.surfaces.value == 197          # the one that IS readable

    out = indicators.render(ind)
    assert "0.0%" not in out
    assert "absent" in out
    assert "not that the value is zero" in out

    j = indicators.to_json(ind)
    assert j["indicators"]["coverage"] == {
        "state": "absent",
        "note": "cba_coverage / cba_inventory are not in this database "
                "(it predates Stage 2)"}
    con.close()
```

- [ ] **Step 10: Run it**

Run: `python3 -m pytest tests/test_indicators.py -v`
Expected: PASS

- [ ] **Step 11: Pin Review Focus 2 — present but empty**

```python
# tests/test_indicators.py
def test_tables_that_exist_but_are_empty_report_zero_not_absent(tmp_path):
    """Review Focus 2. This run really did open no surfaces and sweep no
    patterns. That is a measurement, and it must read as one."""
    con = _db(tmp_path)
    con.commit()
    ind = indicators.collect(con, target="fresh")
    assert ind.surfaces.state == readings.EMPTY
    assert ind.surfaces.value == 0
    assert ind.sweep_hits.value == 0
    assert ind.not_audited.value == 0
    # Coverage is the exception: an empty inventory is no denominator at all,
    # which is absent rather than 0%.
    assert ind.coverage.is_absent
    assert "no denominator" in ind.coverage.note
    con.close()
```

- [ ] **Step 12: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS

- [ ] **Step 13: Commit**

```bash
git add audit_core/indicators.py tests/test_indicators.py
git commit -m "feat: the four leading indicators spec 6.1 names"
```

---

## Task 3: The `indicators` verb and its snapshots

**Files:**
- Modify: `audit.py` (new `cmd_indicators`, `HANDLERS` entry, subparser)
- Modify: `audit_core/indicators.py` (snapshot path and write)
- Test: `tests/test_indicators.py`, `tests/test_cli_stage3b.py` (create)

**Interfaces:**
- Consumes: `indicators.{collect, render, to_json, Indicators}`.
- Produces: `indicators.snapshot_path(root, target, when, label=None) -> pathlib.Path`; `indicators.write_snapshot(path, ind) -> None`; verb `indicators` with `--db`, `--target`, `--phase`, `--json`, `--snapshot`, `--label`, `--root`.

**CRITICAL — do not use `_open_db`.** `db.connect()` applies a schema gate that rejects a database missing the Stage 3 columns, which is exactly the pre-Stage-2 database this verb exists to read. Open read-only and ungated, the way `bench.load_findings_from_db` already does:
`sqlite3.connect(f"file:{path}?mode=ro", uri=True)`.

- [ ] **Step 1: Write the failing test for snapshot paths**

```python
# tests/test_indicators.py
import datetime
import pathlib


def test_snapshot_path_is_dated_and_named_for_the_target(tmp_path):
    p = indicators.snapshot_path(
        tmp_path, "tplink-dl110v2", datetime.date(2026, 10, 7))
    assert p == tmp_path / "docs" / "indicators" / "2026-10-07-tplink-dl110v2.json"


def test_a_label_distinguishes_two_snapshots_on_one_day(tmp_path):
    p = indicators.snapshot_path(
        tmp_path, "tplink", datetime.date(2026, 10, 7), label="after-r3")
    assert p.name == "2026-10-07-tplink-after-r3.json"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_indicators.py -k snapshot_path -v`
Expected: FAIL with `AttributeError: module 'audit_core.indicators' has no attribute 'snapshot_path'`

- [ ] **Step 3: Add the snapshot functions to `audit_core/indicators.py`**

```python
# audit_core/indicators.py  (append; add `import datetime`, `import json`,
# `import pathlib`, `import re` to the imports)

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
    stem = _SAFE.sub("-", target).strip("-") or "unnamed"
    if label:
        stem += "-" + (_SAFE.sub("-", label).strip("-") or "labelled")
    return pathlib.Path(root).joinpath(*SNAPSHOT_DIR) / f"{when:%Y-%m-%d}-{stem}.json"


def write_snapshot(path: str | pathlib.Path, ind: Indicators) -> pathlib.Path:
    """Write, and refuse to overwrite.

    `docs/indicators/` follows the `docs/baselines/` rule: a measurement is
    never edited in place, so a superseded one stays visible in git history.
    Silently overwriting today's snapshot with this afternoon's would destroy
    the morning's measurement and leave no trace that it existed.
    """
    path = pathlib.Path(path)
    if path.exists():
        raise IndicatorError(
            f"{path} already exists. Measurements are never edited in place -- "
            f"pass --label <word> to write a second snapshot of the same "
            f"target on the same day.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json(ind), indent=2) + "\n")
    return path
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_indicators.py -k snapshot -v`
Expected: PASS

- [ ] **Step 5: Write the failing CLI test**

```python
# tests/test_cli_stage3b.py
import json
import pathlib
import sqlite3
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUDIT = ROOT / "audit.py"


def run(*args, **kw):
    return subprocess.run([sys.executable, str(AUDIT), *args],
                          capture_output=True, text=True, **kw)


def _old_db(path):
    """The shape of the only audit.db that exists: findings and surfaces,
    none of the Stage 2 tables."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
                "cwe TEXT, location TEXT, severity TEXT)")
    con.execute("CREATE TABLE cba_attack_surface (id INTEGER PRIMARY KEY "
                "AUTOINCREMENT, group_id TEXT, endpoint TEXT, method TEXT, "
                "auth_required TEXT, description TEXT)")
    con.execute("INSERT INTO cba_attack_surface (group_id, endpoint) "
                "VALUES ('G1', '/login')")
    con.commit()
    con.close()


def test_indicators_reads_a_database_db_connect_would_reject(tmp_path):
    """The whole point of the verb. db.connect() gates on the Stage 3 schema
    and rejects this database; `indicators` must still read it, because it is
    the only real one in existence."""
    db = tmp_path / "audit.db"
    _old_db(db)
    p = run("indicators", "--db", str(db), "--target", "tplink")
    assert p.returncode == 0, p.stderr
    assert "surfaces opened" in p.stdout
    assert "absent" in p.stdout
    assert "0.0%" not in p.stdout
```

- [ ] **Step 6: Run it to verify it fails**

Run: `python3 -m pytest tests/test_cli_stage3b.py -v`
Expected: FAIL — `invalid choice: 'indicators'`

- [ ] **Step 7: Add the verb to `audit.py`**

Add the import beside the others:

```python
from audit_core import indicators as indicators_mod  # noqa: E402
```

Add the handler (place it after `cmd_bench`):

```python
def cmd_indicators(args: argparse.Namespace) -> int:
    db = pathlib.Path(args.db).expanduser()
    if not db.is_file():
        print(f"not found: {db}", file=sys.stderr)
        return 1
    # Read-only and UNGATED on purpose. db.connect() rejects a database that
    # predates the Stage 3 columns, and that database is precisely what this
    # verb exists to measure.
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        ind = indicators_mod.collect(
            con, target=args.target or db.parent.name, phase=args.phase)
    finally:
        con.close()

    if args.json:
        print(json.dumps(indicators_mod.to_json(ind), indent=2))
    else:
        print(indicators_mod.render(ind))

    if args.snapshot:
        path = indicators_mod.snapshot_path(
            args.root, ind.target, datetime.date.today(), label=args.label)
        try:
            written = indicators_mod.write_snapshot(path, ind)
        except indicators_mod.IndicatorError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"snapshot: {written}")
    return 0
```

Add `import datetime` to `audit.py`'s imports. Add to `HANDLERS`:

```python
    "indicators": cmd_indicators,
```

Add the subparser inside `build_parser()`, after the `bench` block:

```python
    ind = sub.add_parser("indicators",
                         help="deterministic leading indicators for one run")
    ind.add_argument("--db", required=True, metavar="AUDIT_DB")
    ind.add_argument("--target", default=None,
                     help="name for this run in the snapshot; defaults to the "
                          "database's parent directory name")
    ind.add_argument("--phase", default=None,
                     help="scope coverage and not_audited to one phase")
    ind.add_argument("--json", action="store_true")
    ind.add_argument("--snapshot", action="store_true",
                     help="also write docs/indicators/<date>-<target>.json")
    ind.add_argument("--label", default=None,
                     help="distinguish a second snapshot of the same target "
                          "on the same day")
    ind.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent),
                     metavar="DIR")
```

- [ ] **Step 8: Run it to verify it passes**

Run: `python3 -m pytest tests/test_cli_stage3b.py -v`
Expected: PASS

- [ ] **Step 9: Test `--snapshot` writes valid JSON**

```python
# tests/test_cli_stage3b.py
def test_snapshot_writes_tracked_json(tmp_path):
    db = tmp_path / "run" / "audit.db"
    db.parent.mkdir()
    _old_db(db)
    root = tmp_path / "repo"
    p = run("indicators", "--db", str(db), "--target", "demo",
            "--snapshot", "--root", str(root))
    assert p.returncode == 0, p.stderr
    out = root / "docs" / "indicators"
    written = list(out.glob("*.json"))
    assert len(written) == 1
    data = json.loads(written[0].read_text())
    assert data["schema_version"] == 1
    assert data["target"] == "demo"
    assert data["indicators"]["surfaces"]["value"] == 1
    assert data["indicators"]["coverage"]["state"] == "absent"
    assert "value" not in data["indicators"]["coverage"]
```

- [ ] **Step 10: Run it**

Run: `python3 -m pytest tests/test_cli_stage3b.py -v`
Expected: PASS

- [ ] **Step 11: Pin Review Focus 5 — a same-day collision**

```python
# tests/test_cli_stage3b.py
def test_a_second_snapshot_the_same_day_refuses_rather_than_overwrites(tmp_path):
    """Review Focus 5. docs/indicators/ follows the docs/baselines/ rule:
    never edited in place. Overwriting this morning's measurement with this
    afternoon's destroys it and leaves no trace it existed."""
    db = tmp_path / "audit.db"
    _old_db(db)
    root = tmp_path / "repo"
    first = run("indicators", "--db", str(db), "--target", "demo",
                "--snapshot", "--root", str(root))
    assert first.returncode == 0, first.stderr

    second = run("indicators", "--db", str(db), "--target", "demo",
                 "--snapshot", "--root", str(root))
    assert second.returncode == 1
    assert "already exists" in second.stderr
    assert "--label" in second.stderr

    labelled = run("indicators", "--db", str(db), "--target", "demo",
                   "--snapshot", "--label", "afternoon", "--root", str(root))
    assert labelled.returncode == 0, labelled.stderr
    assert len(list((root / "docs" / "indicators").glob("*.json"))) == 2
```

- [ ] **Step 12: Run it**

Run: `python3 -m pytest tests/test_cli_stage3b.py -v`
Expected: PASS

- [ ] **Step 13: Verify `selftest` sees the new verb**

Run: `python3 audit.py selftest`
Expected: `verbs 21 declared, all dispatchable`

- [ ] **Step 14: Commit**

```bash
git add audit.py audit_core/indicators.py tests/test_indicators.py tests/test_cli_stage3b.py
git commit -m "feat: audit.py indicators, with snapshots that are never overwritten"
```

---

## Task 4: `indicators --compare`

**Files:**
- Modify: `audit_core/indicators.py`
- Modify: `audit.py` (`cmd_indicators` gains the compare path, subparser gains `--compare`)
- Test: `tests/test_indicators.py`, `tests/test_cli_stage3b.py`

**Interfaces:**
- Consumes: `indicators.to_json`'s shape.
- Produces: `Delta(name: str, before: str, after: str, moved: str)`; `compare(a: dict, b: dict) -> tuple[Delta, ...]`; `render_compare(a_name, b_name, deltas) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_indicators.py
def test_compare_names_what_moved():
    a = {"schema_version": 1, "target": "t", "phase": None, "indicators": {
        "coverage": {"state": "present", "value": 94.0},
        "surfaces": {"state": "present", "value": 197}}}
    b = {"schema_version": 1, "target": "t", "phase": None, "indicators": {
        "coverage": {"state": "present", "value": 72.0},
        "surfaces": {"state": "present", "value": 197}}}
    deltas = {d.name: d for d in indicators.compare(a, b)}
    assert deltas["coverage"].moved == "-22.0"
    assert deltas["surfaces"].moved == "unchanged"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_indicators.py -k compare -v`
Expected: FAIL with `AttributeError: … has no attribute 'compare'`

- [ ] **Step 3: Implement compare**

```python
# audit_core/indicators.py  (append)

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
            diff = eb["value"] - ea["value"]
            moved = f"{diff:+g}"
        out.append(Delta(name, before, after, moved))
    return tuple(out)


def render_compare(a_name: str, b_name: str,
                   deltas: tuple[Delta, ...]) -> str:
    out = [f"comparing {a_name} -> {b_name}",
           f"  {'indicator':<18} {'before':>12} {'after':>12}   moved"]
    for d in deltas:
        out.append(f"  {d.name:<18} {d.before:>12} {d.after:>12}   {d.moved}")
    if any(d.moved == "not comparable" for d in deltas):
        out.append("")
        out.append("  `not comparable` means one snapshot has no reading for "
                   "that indicator, not that it did not move.")
    return "\n".join(out)
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_indicators.py -k compare -v`
Expected: PASS

- [ ] **Step 5: Wire `--compare` into the verb**

In `cmd_indicators`, before the `--db` handling, add:

```python
    if args.compare:
        a_path, b_path = (pathlib.Path(p).expanduser() for p in args.compare)
        for p in (a_path, b_path):
            if not p.is_file():
                print(f"not found: {p}", file=sys.stderr)
                return 1
        a = json.loads(a_path.read_text())
        b = json.loads(b_path.read_text())
        deltas = indicators_mod.compare(a, b)
        if args.json:
            print(json.dumps([dataclasses.asdict(d) for d in deltas], indent=2))
        else:
            print(indicators_mod.render_compare(a_path.name, b_path.name, deltas))
        return 0
```

Make `--db` conditional rather than `required=True`, and validate the pairing:

```python
    ind.add_argument("--db", metavar="AUDIT_DB")
    ind.add_argument("--compare", nargs=2, metavar=("SNAPSHOT_A", "SNAPSHOT_B"))
```

At the top of `cmd_indicators`:

```python
    if not args.compare and not args.db:
        print("indicators needs --db PATH, or --compare A B", file=sys.stderr)
        return 1
```

- [ ] **Step 6: Test the CLI compare path**

```python
# tests/test_cli_stage3b.py
def test_cli_compare_two_snapshots(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                             "indicators": {"surfaces": {"state": "present",
                                                         "value": 10}}}))
    b.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                             "indicators": {"surfaces": {"state": "present",
                                                         "value": 14}}}))
    p = run("indicators", "--compare", str(a), str(b))
    assert p.returncode == 0, p.stderr
    assert "+4" in p.stdout


def test_indicators_without_db_or_compare_is_an_error():
    p = run("indicators")
    assert p.returncode == 1
    assert "--compare" in p.stderr
```

- [ ] **Step 7: Pin Review Focus 4 — snapshots whose indicator sets differ**

```python
# tests/test_indicators.py
def test_an_indicator_missing_from_one_snapshot_is_not_comparable():
    """Review Focus 4. The older snapshot was taken before this indicator
    existed. Reporting `+2` against a key that was absent invents a
    measurement; so does reporting `-2` the other way."""
    a = {"indicators": {"surfaces": {"state": "present", "value": 5}}}
    b = {"indicators": {"surfaces": {"state": "present", "value": 5},
                        "sweep_hits": {"state": "present", "value": 2}}}
    deltas = {d.name: d for d in indicators.compare(a, b)}
    assert deltas["sweep_hits"].moved == "not comparable"
    assert deltas["sweep_hits"].before == "not in snapshot"
    assert deltas["surfaces"].moved == "unchanged"


def test_a_value_against_an_absent_reading_is_not_comparable():
    """Same rule, different cause: the table did not exist when the first
    snapshot was taken. 72% is not `+72` from absent."""
    a = {"indicators": {"coverage": {"state": "absent", "note": "no table"}}}
    b = {"indicators": {"coverage": {"state": "present", "value": 72.0}}}
    assert indicators.compare(a, b)[0].moved == "not comparable"


def test_absent_on_both_sides_is_unchanged():
    a = {"indicators": {"coverage": {"state": "absent", "note": "no table"}}}
    b = {"indicators": {"coverage": {"state": "absent", "note": "no table"}}}
    assert indicators.compare(a, b)[0].moved == "unchanged"
```

- [ ] **Step 8: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add audit.py audit_core/indicators.py tests/test_indicators.py tests/test_cli_stage3b.py
git commit -m "feat: indicators --compare, which refuses to invent a delta"
```

---

## Task 5: `bench` scores severity agreement

**Files:**
- Modify: `audit_core/bench.py`
- Modify: `audit.py` (`cmd_bench` output)
- Test: `tests/test_bench_severity.py` (create)

**Interfaces:**
- Consumes: `audit_core.db.SEVERITIES` (`("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")`, strongest first); `bench.{Reference, RunFinding, BenchResult}`.
- Produces: `SeverityDelta(reference_id, finding_id, reference_severity, finding_severity, steps)`; `SeverityAgreement(agreed, under_rated, over_rated, unrankable, worst_steps, deltas)`; `severity_agreement(refs, findings, matched) -> SeverityAgreement`; `UNDER_RATING_PENALTY = 0.25`; `BenchResult.severity: SeverityAgreement | None`; `BenchResult.weighted_recall: float | None`.

**Why additive.** `recall` keeps its definition — matched on root cause and location — so 9/19 keeps its meaning, and the ≥ 9/19 floor and ≥ 12/19 target stay written against the same quantity. `weighted_recall` is emitted *alongside*, never instead.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bench_severity.py
from audit_core import bench
from audit_core.goldens import Reference


def ref(rid, severity="CRITICAL"):
    return Reference(id=rid, title=f"ref {rid}", cwe=None,
                     locations=(f"fn_{rid}",), root_cause_key=rid,
                     severity=severity)


def finding(fid, severity):
    return bench.RunFinding(id=fid, title=f"finding {fid}", cwe=None,
                            location=f"fn_{fid}", severity=severity)


def test_severity_agreement_counts_under_rating():
    """The Stage 0 finding, in a test. REF-17 was a pre-authentication auth
    bypass filed LOW against a CRITICAL reference - three steps down the
    ladder - and nothing in the pipeline noticed."""
    refs = [ref("R1"), ref("R2"), ref("R3")]
    findings = [finding("F1", "CRITICAL"), finding("F2", "HIGH"),
                finding("F3", "LOW")]
    matched = (("R1", "F1"), ("R2", "F2"), ("R3", "F3"))

    agreement = bench.severity_agreement(refs, findings, matched)

    assert agreement.agreed == 1
    assert agreement.under_rated == 2
    assert agreement.over_rated == 0
    assert agreement.worst_steps == 3
    by_ref = {d.reference_id: d for d in agreement.deltas}
    assert by_ref["R3"].steps == 3
    assert by_ref["R3"].finding_severity == "LOW"
    assert "R1" not in by_ref          # agreements are not deltas
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_bench_severity.py -v`
Expected: FAIL with `AttributeError: module 'audit_core.bench' has no attribute 'severity_agreement'`

- [ ] **Step 3: Implement it in `audit_core/bench.py`**

Add `from audit_core.db import SEVERITIES` to the imports, then append:

```python
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
    try:
        return SEVERITIES.index((severity or "").strip().upper())
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_bench_severity.py -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for weighted recall**

```python
# tests/test_bench_severity.py
def test_weighted_recall_discounts_under_rated_matches():
    """Five agreed plus four under-rated by 1, 1, 2 and 3 steps is the
    tplink shape: 9/19 unweighted, 7.25/19 weighted."""
    refs = [ref(f"R{i}") for i in range(1, 10)]
    sevs = (["CRITICAL"] * 5) + ["HIGH", "HIGH", "MEDIUM", "LOW"]
    findings = [finding(f"F{i}", s) for i, s in enumerate(sevs, start=1)]
    matched = tuple((f"R{i}", f"F{i}") for i in range(1, 10))
    agreement = bench.severity_agreement(refs, findings, matched)

    result = bench.BenchResult(
        recall=9 / 19, matched=matched, unmatched_references=(),
        candidates=(), reference_count=19, finding_count=45,
        cost_per_match=None, severity=agreement)

    assert result.weighted_recall == pytest.approx(7.25 / 19)
    assert result.recall == pytest.approx(9 / 19)   # unchanged


def test_weighted_recall_is_none_without_a_severity_reading():
    result = bench.BenchResult(
        recall=0.5, matched=(), unmatched_references=(), candidates=(),
        reference_count=2, finding_count=1, cost_per_match=None)
    assert result.weighted_recall is None
```

Add `import pytest` to the test file's imports.

- [ ] **Step 6: Run it to verify it fails**

Run: `python3 -m pytest tests/test_bench_severity.py -k weighted -v`
Expected: FAIL — `BenchResult.__init__() got an unexpected keyword argument 'severity'`

- [ ] **Step 7: Add the field and the property to `BenchResult`**

Add after `precision`:

```python
    severity: SeverityAgreement | None = None
```

and the property on `BenchResult`:

```python
    @property
    def weighted_recall(self) -> float | None:
        """Recall crediting a match in full only where severity agrees.

        None, not 0.0, when severity was not scored: 0.0 reads as "every
        match was mis-rated". Emitted ALONGSIDE `recall`, never instead -
        the >= 9/19 floor and the >= 12/19 target are written against
        `recall`, and silently restating them is not this figure's job.
        """
        if self.severity is None or not self.reference_count:
            return None
        credit = float(self.severity.agreed + self.severity.over_rated
                       + self.severity.unrankable)
        for d in self.severity.deltas:
            if d.steps > 0:
                credit += max(0.0, 1.0 - UNDER_RATING_PENALTY * d.steps)
        return credit / self.reference_count
```

Declare `SeverityAgreement` and `SeverityDelta` *above* `BenchResult` in the file so the annotation resolves.

- [ ] **Step 8: Run it to verify it passes**

Run: `python3 -m pytest tests/test_bench_severity.py -v`
Expected: PASS

- [ ] **Step 9: Pin Review Focus 3 — a severity outside the vocabulary**

```python
# tests/test_bench_severity.py
def test_a_severity_outside_the_ladder_is_reported_not_raised():
    """Review Focus 3. A golden with a typo, or a vocabulary that grew, must
    not take the whole run's score down with it. `SEVERITIES.index` raises
    ValueError, and this is the one place both sides are untrusted strings."""
    refs = [ref("R1", severity="SEV-1"), ref("R2")]
    findings = [finding("F1", "CRITICAL"), finding("F2", "nonsense")]
    matched = (("R1", "F1"), ("R2", "F2"))

    agreement = bench.severity_agreement(refs, findings, matched)

    assert agreement.unrankable == 2
    assert agreement.agreed == 0
    assert agreement.under_rated == 0
    assert agreement.worst_steps == 0
    assert {d.reference_severity for d in agreement.deltas} == {"SEV-1", "CRITICAL"}


def test_severity_comparison_is_case_and_space_insensitive():
    """Severity reaches this from JSON a human typed and from a SQL column a
    subagent wrote. ' critical ' and 'CRITICAL' are the same claim."""
    refs = [ref("R1", severity=" critical ")]
    findings = [finding("F1", "CRITICAL")]
    agreement = bench.severity_agreement(refs, findings, (("R1", "F1"),))
    assert agreement.agreed == 1
    assert agreement.unrankable == 0
```

- [ ] **Step 10: Run it**

Run: `python3 -m pytest tests/test_bench_severity.py -v`
Expected: PASS

- [ ] **Step 11: Wire it into `cmd_bench` and the scorer**

In `bench.score`, after `matched` is built, compute and pass it:

```python
    agreement = severity_agreement(refs, findings, tuple(matched))
```

and add `severity=agreement` to the `BenchResult(...)` construction.

In `audit.py`'s `cmd_bench`, after the precision block:

```python
    if result.severity is not None:
        s = result.severity
        print(f"severity   {s.agreed}/{len(result.matched)} agree  "
              f"[{s.under_rated} under-rated, {s.over_rated} over-rated, "
              f"{s.unrankable} unrankable]")
        if s.under_rated:
            print(f"           worst {s.worst_steps} ladder step(s) low; "
                  f"recall counts these in full, weighted recall does not")
        for d in s.deltas:
            if d.steps > 0:
                print(f"             {d.reference_id} ~ {d.finding_id}: "
                      f"{d.reference_severity} filed as {d.finding_severity}")
    if result.weighted_recall is not None:
        print(f"weighted recall  {result.weighted_recall:.3f} "
              f"(severity-credited; the gate floor is written against "
              f"`recall` above)")
```

- [ ] **Step 12: Verify against the real baseline — the free measurement**

Run:

```bash
python3 audit.py bench \
  --golden tests/goldens/tplink-dl110v2-1.0.11 \
  --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db \
  --cost 658.37
```

Expected, and this is a real check rather than a fixture: `recall 9/19` unchanged, and **`severity 5/9 agree [4 under-rated, 0 over-rated, 0 unrankable]`** with the four named pairs being REF-12, REF-14, REF-16 and REF-17, and `worst 3 ladder step(s) low` from REF-17 (CRITICAL filed LOW).

If the counts differ from four, stop and reconcile against
`docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md` §1
before continuing — that document is the independent record of this number.

- [ ] **Step 13: Append the result to the baseline, dated — never in place**

Add to the END of `docs/baselines/2026-10-05-tplink-baseline.md`:

```markdown

---

## Appended 2026-10-07 — severity agreement (Stage 3b)

Re-scored with `audit.py bench` after Stage 3b added severity agreement. **The
underlying run is unchanged**; this is the same stored `audit.db` read by a
scorer that now compares a dimension it previously loaded and ignored. No
audit was run.

| Metric | Value |
|---|---|
| Recall (unchanged) | 9/19 |
| Severity agreement | 5/9 |
| Under-rated | 4 |
| Worst delta | 3 ladder steps (REF-17, CRITICAL filed LOW) |
| Weighted recall | 7.25/19 |

Recall is unchanged by design: it is matched on root cause and location, and
that is what the ≥ 9/19 floor and the ≥ 12/19 target are written against.
```

- [ ] **Step 14: Run the full suite and the harness**

Run: `python3 -m pytest -q && python3 scripts/harness.py --only bench`
Expected: PASS, and the bench gate still green — `BENCH_EXPECT` pins recall, findings and precision, none of which this task changes.

- [ ] **Step 15: Commit**

```bash
git add audit_core/bench.py audit.py tests/test_bench_severity.py docs/baselines/2026-10-05-tplink-baseline.md
git commit -m "feat: bench scores severity agreement, additively"
```

---

## Task 6: `bench` scores coverage

**Files:**
- Modify: `audit_core/bench.py`
- Modify: `audit.py` (`cmd_bench`)
- Test: `tests/test_bench_severity.py`

**Interfaces:**
- Consumes: `audit_core.readings.{Reading, table_state, ABSENT}`; `audit_core.coverage.report`.
- Produces: `coverage_from_db(db_path) -> Reading`; `BenchResult.coverage: Reading | None`.

Spec §6.1 defines `bench` as scoring recall, precision, **coverage** and cost per finding. It scores three of the four.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bench_severity.py
import sqlite3

from audit_core import readings


def test_coverage_from_a_database_without_the_tables_is_absent(tmp_path):
    """The only audit.db that exists. `0%` would claim the run analysed
    nothing; the truth is the feature did not exist when it ran."""
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
                "cwe TEXT, location TEXT, severity TEXT)")
    con.commit()
    con.close()
    r = bench.coverage_from_db(db)
    assert r.is_absent
    assert "0" not in r.render("%")


def test_coverage_from_a_populated_database(tmp_path):
    db = tmp_path / "new.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_inventory (unit TEXT PRIMARY KEY, "
                "kind TEXT NOT NULL, group_id TEXT, size INTEGER, "
                "added_at TEXT)")
    con.execute("CREATE TABLE cba_coverage (unit TEXT NOT NULL, phase TEXT "
                "NOT NULL, state TEXT NOT NULL, reason TEXT, "
                "recorded_at TEXT, PRIMARY KEY (unit, phase))")
    con.executemany("INSERT INTO cba_inventory (unit, kind) VALUES (?, 'file')",
                    [("a",), ("b",), ("c",), ("d",)])
    con.execute("INSERT INTO cba_coverage (unit, phase, state) "
                "VALUES ('a','audit','analyzed')")
    con.commit()
    con.close()
    r = bench.coverage_from_db(db)
    assert r.state == readings.PRESENT
    assert r.value == 25.0
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_bench_severity.py -k coverage -v`
Expected: FAIL with `AttributeError: … has no attribute 'coverage_from_db'`

- [ ] **Step 3: Implement it in `audit_core/bench.py`**

```python
def coverage_from_db(db_path: str | pathlib.Path) -> Reading:
    """Analyzed over inventoried, or the reason there is no such fraction.

    Opened read-only and ungated, for the same reason `load_findings_from_db`
    is: bench must keep scoring run directories older than the current
    schema, and `db.connect()` rejects exactly those.
    """
    path = pathlib.Path(db_path)
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if table_state(con, "cba_coverage", "cba_inventory") == ABSENT:
            return Reading.absent(
                "cba_coverage / cba_inventory are not in this database "
                "(it predates Stage 2)")
        r = coverage_mod.report(con)
        if r.inventoried == 0:
            return Reading.absent(
                "the inventory is empty, so there is no denominator")
        return Reading.of(round(100 * r.fraction, 1),
                          detail=(("analyzed", r.analyzed),
                                  ("inventoried", r.inventoried)))
    finally:
        con.close()
```

Add to the imports:

```python
from audit_core import coverage as coverage_mod
from audit_core.readings import ABSENT, Reading, table_state
```

Add the field to `BenchResult`, after `severity`:

```python
    coverage: Reading | None = None
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_bench_severity.py -k coverage -v`
Expected: PASS

- [ ] **Step 5: Wire it into `cmd_bench`**

In `audit.py`, after `precision = bench_mod.precision_from_db(db)`:

```python
    coverage_reading = bench_mod.coverage_from_db(db)
```

Pass `coverage=coverage_reading` into `bench_mod.score(...)` (add the keyword-only parameter to `score`, defaulting to `None`, and set it on the returned `BenchResult`). Then print, after the severity block:

```python
    if result.coverage is not None:
        print(f"coverage   {result.coverage.render('%')}")
```

- [ ] **Step 6: Check `--json` still serialises**

`dataclasses.asdict` walks nested dataclasses, and `Reading` is one, so the JSON gains a nested object rather than failing. Verify:

Run:

```bash
python3 audit.py bench --golden tests/goldens/tplink-dl110v2-1.0.11 \
  --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db \
  --json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['coverage']); print(d['severity']['under_rated'])"
```

Expected: the coverage reading prints with `'state': 'absent'`, and `4`.

- [ ] **Step 7: Confirm the harness bench gate still passes**

Run: `python3 scripts/harness.py --only bench`
Expected: PASS. `BENCH_EXPECT` reads `matched`, `reference_count`, `finding_count` and `precision`; none move.

- [ ] **Step 8: Commit**

```bash
git add audit_core/bench.py audit.py tests/test_bench_severity.py
git commit -m "feat: bench scores coverage, the fourth metric 6.1 names"
```

---

## Task 7: `rerate` — advisory severity re-rating that stores nothing

**Files:**
- Create: `audit_core/rerate.py`
- Create: `tests/test_rerate.py`
- Modify: `audit.py` (`cmd_rerate`, `HANDLERS`, subparser)

**Interfaces:**
- Consumes: `audit_core.readings.{table_state, ABSENT}`; `audit_core.db.SEVERITIES`.
- Produces: `Rule(id: str, pattern: re.Pattern, floor: str, why: str)`; `RULES: tuple[Rule, ...]`; `Signal(rule: str, evidence: str)`; `Flag(finding_id, severity, implied_floor, signals)`; `examine(con) -> tuple[Flag, ...]`; `render(flags, *, chains_absent: bool) -> str`.

**It writes nothing.** No `UPDATE`, no `db.put`, no new table. The connection is opened read-only. A reviewer should reject any diff in this task containing `INSERT`, `UPDATE` or `db_mod.put`.

Why its own verb and not part of `bench`: `rerate` needs **no golden set**. It compares a finding against its own cited evidence, so it works on every real client audit. `bench`'s severity agreement needs a reference set, which exists for exactly one target.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_rerate.py
import sqlite3

import pytest

from audit_core import rerate

FINDINGS_DDL = """
CREATE TABLE cba_findings (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL, confidence INTEGER NOT NULL, cwe TEXT,
    location TEXT NOT NULL, root_cause TEXT NOT NULL, impact TEXT NOT NULL,
    attacker_position TEXT, boundary_crossed TEXT, data_flow TEXT,
    verified TEXT, poc TEXT, remediation TEXT, artifact_path TEXT,
    created_at TEXT)
"""

CHAINS_DDL = """
CREATE TABLE cba_chains (
    id TEXT PRIMARY KEY, finding_ids TEXT NOT NULL,
    attacker_position TEXT NOT NULL, pre_auth TEXT,
    completeness TEXT NOT NULL, blocking_unknowns TEXT, created_at TEXT)
"""


def _con(chains=True):
    con = sqlite3.connect(":memory:")
    con.execute(FINDINGS_DDL)
    if chains:
        con.execute(CHAINS_DDL)
    return con


def _add(con, fid, severity, **cols):
    row = {"id": fid, "group_id": "G1", "title": "t", "severity": severity,
           "confidence": 80, "location": "f.c:1", "root_cause": "rc",
           "impact": "i"}
    row.update(cols)
    keys = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    con.execute(f"INSERT INTO cba_findings ({keys}) VALUES ({marks})",
                list(row.values()))


def test_an_unauthenticated_bypass_filed_low_is_flagged():
    """REF-17, in a test. A pre-authentication authentication bypass was
    filed LOW because the overrun was scored on its own and never traced to
    the gate it overwrites - even though the finding's own text names the
    consumer branch."""
    con = _con()
    _add(con, "G1-F7", "LOW",
         title="KLAP handshake-1 overrun",
         root_cause="check-after-copy overrun reached without authentication",
         impact="overwrites the authentication gate in klap_handshake1_handle")
    con.commit()

    flags = {f.finding_id: f for f in rerate.examine(con)}

    assert "G1-F7" in flags
    assert flags["G1-F7"].implied_floor == "HIGH"
    assert any(s.rule == "unauthenticated-reach"
               for s in flags["G1-F7"].signals)
    con.close()


def test_a_finding_already_at_or_above_the_floor_is_not_flagged():
    """The report has to be short enough to read. A CRITICAL that mentions
    authentication is correctly rated and must not appear."""
    con = _con()
    _add(con, "G1-F1", "CRITICAL",
         root_cause="unauthenticated attacker bypasses authentication")
    con.commit()
    assert rerate.examine(con) == ()
    con.close()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_rerate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'audit_core.rerate'`

- [ ] **Step 3: Write the module**

```python
# audit_core/rerate.py
"""Does a finding's severity match the evidence the finding itself cites?

A severity is a claim about reachability and consequence. The pipeline fixes
it at discovery time, before chain composition runs, so a finding scored on
its own mechanism never gets re-read once its reach is understood. On tplink
that cost four of nine matches a correct rating, the worst being a
pre-authentication authentication bypass filed LOW.

This module REPORTS. It opens nothing for writing, stores no row, and changes
no severity. The mutating version stays unbuilt until a benchmark run can
show it helps; this report is the evidence for that decision, gathered at
zero cost and zero risk.

Precedent for the shape: `coverage --gate` reports and does not block.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

from audit_core.db import SEVERITIES
from audit_core.readings import ABSENT, table_state

_TEXT_COLUMNS = ("title", "root_cause", "impact", "attacker_position",
                 "boundary_crossed", "data_flow", "poc")


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    pattern: re.Pattern
    floor: str
    why: str


RULES: tuple[Rule, ...] = (
    Rule("unauthenticated-reach",
         re.compile(r"\b(?:un[- ]?authenticated|pre[- ]?auth(?:entication)?|"
                    r"without\s+(?:any\s+)?authentication|"
                    r"no\s+authentication\s+(?:is\s+)?required)\b", re.I),
         "HIGH",
         "the finding's own text says it is reachable without credentials"),
    Rule("auth-bypass",
         re.compile(r"\b(?:auth(?:entication|orization)?\s+bypass|"
                    r"bypass(?:es|ing)?\s+(?:the\s+)?auth(?:entication|orization)?|"
                    r"access\s+control\s+bypass)\b", re.I),
         "HIGH",
         "the finding's own text describes bypassing an authentication or "
         "authorization check"),
)
"""Deliberately few, and each one quotes the finding back at itself.

A rule that infers severity from something the finding does not say is a
guess wearing a rule's clothes. Every rule here fires on language the audit
itself wrote, so the report can always answer "why is this flagged" with a
quotation.
"""

CHAIN_FLOOR = "CRITICAL"
"""Floor for membership of a chain marked pre-auth.

A bug reachable without credentials, as one step of a chain somebody has
already composed, is the shape of every finding in the reference set.
"""


@dataclass(frozen=True, slots=True)
class Signal:
    rule: str
    evidence: str


@dataclass(frozen=True, slots=True)
class Flag:
    finding_id: str
    severity: str
    implied_floor: str
    signals: tuple[Signal, ...]


def _rank(severity: str) -> int | None:
    try:
        return SEVERITIES.index((severity or "").strip().upper())
    except ValueError:
        return None


def _excerpt(text: str, match: re.Match, width: int = 60) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    return ("..." if start else "") + text[start:end].strip() + (
        "..." if end < len(text) else "")


def _pre_auth_chain_members(con: sqlite3.Connection) -> set[str]:
    """Finding ids belonging to a chain whose `pre_auth` is affirmative.

    `cba_chains.finding_ids` is a comma-separated list, so this splits rather
    than joins. An absent table yields an empty set, and the caller says so
    in the report rather than pretending the rule ran.
    """
    if table_state(con, "cba_chains") == ABSENT:
        return set()
    members: set[str] = set()
    for (ids, pre_auth) in con.execute(
            "SELECT finding_ids, pre_auth FROM cba_chains"):
        if str(pre_auth or "").strip().lower() not in ("1", "true", "yes"):
            continue
        members.update(p.strip() for p in str(ids or "").split(",") if p.strip())
    return members


def examine(con: sqlite3.Connection) -> tuple[Flag, ...]:
    """Every finding rated below the floor its own evidence implies."""
    chain_members = _pre_auth_chain_members(con)
    columns = ", ".join(("id", "severity") + _TEXT_COLUMNS)
    flags: list[Flag] = []

    for row in con.execute(f"SELECT {columns} FROM cba_findings ORDER BY id"):
        finding_id, severity = row[0], row[1]
        blob = "\n".join(str(c) for c in row[2:] if c)

        signals: list[Signal] = []
        floors: list[str] = []
        for rule in RULES:
            match = rule.pattern.search(blob)
            if match:
                signals.append(Signal(rule.id, _excerpt(blob, match)))
                floors.append(rule.floor)
        if finding_id in chain_members:
            signals.append(Signal(
                "pre-auth-chain",
                "member of a composed chain recorded as pre_auth"))
            floors.append(CHAIN_FLOOR)

        if not floors:
            continue
        floor = min(floors, key=lambda s: SEVERITIES.index(s))
        found_rank, floor_rank = _rank(severity), SEVERITIES.index(floor)
        if found_rank is None or found_rank <= floor_rank:
            continue        # correctly rated, or rated higher; say nothing
        flags.append(Flag(finding_id, severity, floor, tuple(signals)))

    return tuple(flags)


def render(flags: tuple[Flag, ...], *, chains_absent: bool = False) -> str:
    if not flags:
        out = ["rerate: no finding is rated below the floor its own evidence "
               "implies."]
    else:
        out = [f"rerate: {len(flags)} finding(s) rated below the floor their "
               f"own evidence implies.", ""]
        for f in flags:
            out.append(f"  {f.finding_id}  filed {f.severity}, "
                       f"evidence implies at least {f.implied_floor}")
            for s in f.signals:
                out.append(f"      [{s.rule}] {s.evidence}")
            out.append("")
    out.append("This is advisory. No severity has been changed and no row "
               "written; re-rating is a judgement for a human, and the "
               "mutating version is unbuilt until a benchmark run can show "
               "it helps.")
    if chains_absent:
        out.append("The pre-auth-chain rule did not run: cba_chains is not "
                   "in this database.")
    return "\n".join(out)
```

- [ ] **Step 4: Run it to verify it passes**

Run: `python3 -m pytest tests/test_rerate.py -v`
Expected: PASS

- [ ] **Step 5: Test the chain rule and the absent-table path**

```python
# tests/test_rerate.py
def test_membership_of_a_pre_auth_chain_implies_critical():
    con = _con()
    _add(con, "G2-F3", "MEDIUM", root_cause="stack overflow in the parser")
    con.execute("INSERT INTO cba_chains (id, finding_ids, attacker_position, "
                "pre_auth, completeness) VALUES "
                "('C1', 'G2-F3, G1-F1', 'LAN', 'true', 'complete')")
    con.commit()
    flags = {f.finding_id: f for f in rerate.examine(con)}
    assert flags["G2-F3"].implied_floor == "CRITICAL"
    assert any(s.rule == "pre-auth-chain" for s in flags["G2-F3"].signals)
    con.close()


def test_a_database_without_cba_chains_still_runs_the_text_rules():
    """The only audit.db that exists has no cba_chains. Raising here would
    make the verb useless on the one corpus available."""
    con = _con(chains=False)
    _add(con, "G1-F7", "LOW", root_cause="reached without authentication")
    con.commit()
    flags = rerate.examine(con)
    assert len(flags) == 1
    assert flags[0].finding_id == "G1-F7"
    con.close()


def test_render_states_that_nothing_was_written():
    """The property that makes this verb safe to ship while the benchmark is
    deferred. If the output ever stops saying so, the reader has no way to
    know whether their severities were rewritten."""
    con = _con()
    _add(con, "G1-F7", "LOW", root_cause="reached without authentication")
    con.commit()
    out = rerate.render(rerate.examine(con))
    assert "No severity has been changed" in out
    assert "advisory" in out
    con.close()


def test_an_unrankable_severity_is_skipped_rather_than_raising():
    con = _con()
    _add(con, "G1-F9", "SEV-2", root_cause="reached without authentication")
    con.commit()
    assert rerate.examine(con) == ()
    con.close()
```

- [ ] **Step 6: Run it**

Run: `python3 -m pytest tests/test_rerate.py -v`
Expected: PASS

- [ ] **Step 7: Add the verb to `audit.py`**

Import:

```python
from audit_core import rerate as rerate_mod  # noqa: E402
```

Handler:

```python
def cmd_rerate(args: argparse.Namespace) -> int:
    db = pathlib.Path(args.db).expanduser()
    if not db.is_file():
        print(f"not found: {db}", file=sys.stderr)
        return 1
    # Read-only, and ungated for the same reason `indicators` is.
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        chains_absent = readings_mod.table_state(
            con, "cba_chains") == readings_mod.ABSENT
        flags = rerate_mod.examine(con)
    finally:
        con.close()
    if args.json:
        print(json.dumps([dataclasses.asdict(f) for f in flags], indent=2))
    else:
        print(rerate_mod.render(flags, chains_absent=chains_absent))
    return 0
```

Add `from audit_core import readings as readings_mod  # noqa: E402`.

`HANDLERS`: `"rerate": cmd_rerate,`

Subparser:

```python
    rr = sub.add_parser("rerate",
                        help="report findings rated below the floor their own "
                             "evidence implies (advisory; stores nothing)")
    rr.add_argument("--db", required=True, metavar="AUDIT_DB")
    rr.add_argument("--json", action="store_true")
```

- [ ] **Step 8: Test the CLI and assert it is read-only**

```python
# tests/test_cli_stage3b.py
def test_rerate_does_not_modify_the_database(tmp_path):
    """The safety property, asserted rather than assumed. If a future change
    makes this verb write, the mtime and the row contents catch it."""
    import os
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, "
                "group_id TEXT NOT NULL, title TEXT NOT NULL, "
                "severity TEXT NOT NULL, confidence INTEGER NOT NULL, "
                "cwe TEXT, location TEXT NOT NULL, root_cause TEXT NOT NULL, "
                "impact TEXT NOT NULL, attacker_position TEXT, "
                "boundary_crossed TEXT, data_flow TEXT, verified TEXT, "
                "poc TEXT, remediation TEXT, artifact_path TEXT, "
                "created_at TEXT)")
    con.execute("INSERT INTO cba_findings (id, group_id, title, severity, "
                "confidence, location, root_cause, impact) VALUES "
                "('F1','G1','t','LOW',80,'f.c:1',"
                "'reached without authentication','i')")
    con.commit()
    con.close()

    before = (db.stat().st_mtime_ns, db.read_bytes())
    p = run("rerate", "--db", str(db))
    assert p.returncode == 0, p.stderr
    assert "F1" in p.stdout
    assert "No severity has been changed" in p.stdout
    assert (db.stat().st_mtime_ns, db.read_bytes()) == before
```

- [ ] **Step 9: Run it**

Run: `python3 -m pytest tests/test_cli_stage3b.py -v`
Expected: PASS

- [ ] **Step 10: Run it against the real baseline**

Run:

```bash
python3 audit.py rerate --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db
```

Expected: a list of flagged findings including `G1-F7` (the REF-17 match, filed LOW), and the line stating `cba_chains is not in this database`. Record the flagged count in the task report — it is the first evidence of whether this report is actionable, which spec §7 names as its own risk.

- [ ] **Step 11: Verify `selftest`**

Run: `python3 audit.py selftest`
Expected: `verbs 22 declared, all dispatchable`

- [ ] **Step 12: Commit**

```bash
git add audit_core/rerate.py audit.py tests/test_rerate.py tests/test_cli_stage3b.py
git commit -m "feat: rerate reports a severity its own evidence contradicts"
```

---

## Task 8: The three code defects

**Files:**
- Modify: `audit_core/preflight.py`, `audit.py` (`cmd_preflight`)
- Modify: `audit_core/briefs.py`
- Modify: `audit_core/chains.py`, `audit_core/identity.py`
- Test: `tests/test_preflight.py`, `tests/test_briefs.py`, `tests/test_chains.py`, `tests/test_identity.py`

These are three independent one-file changes with no shared interface. They are one task because each is too small to be worth its own reviewer gate, and none of them depends on another.

**Interfaces:**
- Produces: `preflight.merge_server(kept: dict | None, command: str) -> dict`.

### 8a — `--server` must merge over `--keep`, not flatten it

- [ ] **Step 1: Write the reproduction test**

```python
# tests/test_preflight.py
def test_server_merges_over_a_kept_definition(tmp_path):
    """Reproduced 2026-10-07: `--keep autorev --server autorev=uvx` wrote
    {"command": "uvx"} and exited 0, discarding args and env.

    That is the exact degradation load_servers' docstring says --keep exists
    to prevent - a config --strict-mcp-config accepts and that then exposes a
    server which cannot start. On a firmware audit it is the IDA server
    arriving broken with no warning."""
    src = tmp_path / "src.json"
    src.write_text(json.dumps({"mcpServers": {"autorev": {
        "command": "uvx", "args": ["autorev-mcp", "--db", "x.i64"],
        "env": {"K": "v"}}}}))
    out = tmp_path / "out.json"
    env = {**os.environ}
    p = subprocess.run(
        [sys.executable, str(AUDIT), "preflight", "--from-config", str(src),
         "--keep", "autorev", "--server", "autorev=uvx-new",
         "--out", str(out)],
        capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stderr
    server = json.loads(out.read_text())["mcpServers"]["autorev"]
    assert server["command"] == "uvx-new"       # the override applies
    assert server["args"] == ["autorev-mcp", "--db", "x.i64"]   # and nothing else is lost
    assert server["env"] == {"K": "v"}
```

Use the file's existing import names and `AUDIT` path constant; if it has none, add `AUDIT = pathlib.Path(__file__).resolve().parent.parent / "audit.py"`.

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_preflight.py -k merges_over -v`
Expected: FAIL — `KeyError: 'args'`

- [ ] **Step 3: Add `merge_server` to `audit_core/preflight.py`**

```python
def merge_server(kept: dict | None, command: str) -> dict:
    """Apply a `--server NAME=COMMAND` override to a kept definition.

    Replacing the whole object discards `args` and `env`, which is exactly
    the degradation `load_servers` exists to prevent: the result is a config
    `--strict-mcp-config` accepts and that then exposes a server unable to
    start. Overriding the command alone keeps the rest.
    """
    if not kept:
        return {"command": command}
    merged = dict(kept)
    merged["command"] = command
    return merged
```

- [ ] **Step 4: Use it in `audit.py`'s `cmd_preflight`**

Replace `servers[name] = {"command": command}` with:

```python
        servers[name] = preflight_mod.merge_server(servers.get(name), command)
```

- [ ] **Step 5: Run it to verify it passes**

Run: `python3 -m pytest tests/test_preflight.py -v`
Expected: PASS

- [ ] **Step 6: Test the other direction — no `--keep`**

```python
# tests/test_preflight.py
def test_server_without_a_kept_definition_is_still_a_bare_command(tmp_path):
    """The untested half. A --server naming something --keep never copied
    must still produce a working single-key definition."""
    assert preflight.merge_server(None, "uvx") == {"command": "uvx"}
    assert preflight.merge_server({}, "uvx") == {"command": "uvx"}


def test_merge_does_not_mutate_the_kept_definition():
    kept = {"command": "old", "args": ["a"]}
    merged = preflight.merge_server(kept, "new")
    assert kept["command"] == "old"
    assert merged["command"] == "new"
```

- [ ] **Step 7: Run and commit 8a**

```bash
python3 -m pytest tests/test_preflight.py -q
git add audit_core/preflight.py audit.py tests/test_preflight.py
git commit -m "fix: --server overrides a kept server's command, not its whole definition"
```

### 8b — `briefs.render` reports both error classes in one pass

- [ ] **Step 8: Write the reproduction test**

```python
# tests/test_briefs.py
def test_missing_and_empty_placeholders_are_reported_together():
    """Reproduced 2026-10-07: render raised on `missing` and returned, so an
    operator fixed the missing placeholder, re-ran, and only then discovered
    the empty one. Two round trips for one template."""
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("a {MISSING} and {EMPTY}", {"EMPTY": "   "})
    message = str(exc.value)
    assert "MISSING" in message
    assert "EMPTY" in message
```

- [ ] **Step 9: Run it to verify it fails**

Run: `python3 -m pytest tests/test_briefs.py -k together -v`
Expected: FAIL — `assert 'EMPTY' in "unsubstituted placeholder(s): MISSING"`

- [ ] **Step 10: Fix `audit_core/briefs.py`**

Replace the two sequential `if missing: raise` / `if empty: raise` blocks with one:

```python
    problems: list[str] = []
    if missing:
        problems.append("unsubstituted placeholder(s): "
                        + ", ".join(sorted(set(missing))))
    if empty:
        problems.append("empty value for placeholder(s): "
                        + ", ".join(sorted(set(empty)))
                        + " (pass --allow-empty if the section is genuinely "
                          "empty)")
    if problems:
        # One raise, both classes. Reporting only the first sends an operator
        # away to fix one thing and back to discover the other.
        raise BriefError("; ".join(problems))
    return out
```

- [ ] **Step 11: Run the briefs tests**

Run: `python3 -m pytest tests/test_briefs.py tests/test_brief_templates.py -q`
Expected: PASS. If an existing test asserts the exact old single-class message, update that assertion to `in` rather than `==` and note it in the task report.

- [ ] **Step 12: Commit 8b**

```bash
git add audit_core/briefs.py tests/test_briefs.py
git commit -m "fix: briefs reports missing and empty placeholders in one pass"
```

### 8c — `--replace` stops blanking optional columns

- [ ] **Step 13: Write the reproduction tests**

```python
# tests/test_chains.py
def test_compose_replace_preserves_columns_the_caller_omitted(tmp_path, ...):
    """db.put already merges on replace; these callers pass a dict that does
    not carry the optional columns, so the merge has nothing to preserve.
    Build the row twice, the second time without the optional fields, and
    assert the first call's values survive."""
```

Write it against the real `chains.compose` signature, using the same fixture style as the file's existing tests. The assertion: compose a chain with `blocking_unknowns` set, re-compose with `--replace` and no `blocking_unknowns`, read the row back, and assert `blocking_unknowns` is unchanged. Write the equivalent in `tests/test_identity.py` for `identity.record` and the `version` column.

- [ ] **Step 14: Run them to verify they fail**

Run: `python3 -m pytest tests/test_chains.py tests/test_identity.py -q`
Expected: FAIL — the omitted column reads back as `None`.

- [ ] **Step 15: Fix both callers**

In `chains.compose` and `identity.record`, build the row dict by **omitting** keys whose value is `None`, rather than including them with a `None` value. `db.put(replace=True)` merges with the stored row, so a key that is absent is preserved and a key present with `None` overwrites.

- [ ] **Step 16: Run and commit 8c**

```bash
python3 -m pytest -q
git add audit_core/chains.py audit_core/identity.py tests/test_chains.py tests/test_identity.py
git commit -m "fix: --replace preserves columns the caller did not pass"
```

---

## Task 9: The one prose defect, with its derivation

**Files:**
- Create: `docs/superpowers/derivations/2026-10-07-stage3b-prose-derivation.md`
- Modify: `workflows/fpcheck.md`
- Test: `tests/test_workflow_prose.py`

`workflows/fpcheck.md` letters batches `A, B, C, D, E, F` and sets `BATCH=A`; `references/phase5-fp-check.md`'s worked example uses `B1`. The artifact path pattern was unified in Stage 1; the identifiers were not.

**Unify on the workflow's form (`A, B, C`)**, because the workflow is what the operator reads first and the reference is the deep-dive.

**`workflows/fpcheck.md` is LF.** `references/phase5-fp-check.md` is CRLF. If you edit the reference, preserve its line endings — `scripts/eol-manifest.txt` and the `eol` gate enforce this.

- [ ] **Step 1: Write the derivation BEFORE editing anything**

Create `docs/superpowers/derivations/2026-10-07-stage3b-prose-derivation.md` listing every intended change as one row: file, line number, exact text before, exact text after, and why. Count the rows and write the total at the top. Rewriting shipped prose lost instructions five times out of five in Stage 1; this list is the control.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_workflow_prose.py
def test_batch_identifiers_agree_between_the_workflow_and_its_reference():
    """Carried forward from Stage 1 and still open on 2026-10-07. An operator
    reading the workflow letters a batch `A`; the reference's worked example
    shows `B1`, so the brief they render and the artifact path they write do
    not match what either document shows."""
    workflow = (ROOT / "workflows" / "fpcheck.md").read_text()
    reference = (ROOT / "references" / "phase5-fp-check.md").read_text()
    assert "--unit B1" not in reference
    assert "batch_id=B1" not in reference
    assert "phase5-B1.md" not in reference
    assert "BATCH=A" in workflow
```

Use the file's existing `ROOT` constant.

- [ ] **Step 3: Run it to verify it fails**

Run: `python3 -m pytest tests/test_workflow_prose.py -k batch_identifiers -v`
Expected: FAIL — `assert '--unit B1' not in reference`

- [ ] **Step 4: Apply exactly the changes the derivation lists**

Edit `references/phase5-fp-check.md` lines 31-33, replacing `B1` with `A` in `--unit`, `--var batch_id=`, and the `artifacts/phase5-<id>.md` path. **Preserve CRLF.** Use a byte-level edit (`python3` with `rb`/`wb`, or `sed -i ''` which preserves the `\r` because it is line content, not the terminator) rather than rewriting the file from a decoded string.

- [ ] **Step 5: Run the test**

Run: `python3 -m pytest tests/test_workflow_prose.py -v`
Expected: PASS

- [ ] **Step 6: Reconcile against the derivation**

Run:

```bash
git diff -U0 references/phase5-fp-check.md | grep -c '^[+-][^+-]'
python3 scripts/harness.py --only eol
```

Expected: the changed-line count matches twice the derivation's row count (one `-` and one `+` per row), and the `eol` gate passes, proving CRLF survived. If the counts disagree, the diff contains a change the derivation did not authorise — find it before continuing.

- [ ] **Step 7: Commit**

```bash
git add references/phase5-fp-check.md tests/test_workflow_prose.py docs/superpowers/derivations/2026-10-07-stage3b-prose-derivation.md
git commit -m "fix: batch identifiers agree between fpcheck and its reference"
```

---

## Task 10: The record — inventory, docs, and the first snapshot

**Files:**
- Modify: `feature_lists.json`, `progress.md`, `SESSION_HANDOFF.md`, `ARCHITECTURE.md`
- Create: `docs/indicators/2026-10-07-tplink-dl110v2-1.0.11.json`
- Modify: `scripts/harness.py` (only if a gate needs it — see Step 6)
- Test: `tests/test_harness.py`

This task exists because the `manifest` gate will be **failing** until it runs: Tasks 3 and 7 add verbs that `feature_lists.json` describes as `planned` under `verbs_planned`. Leaving that inconsistent is how an inventory starts lying.

**Interfaces:**
- Consumes: `indicators` verb from Task 3.
- Produces: nothing other tasks depend on. This is the last task.

- [ ] **Step 1: Write the first real snapshot**

Run:

```bash
python3 audit.py indicators \
  --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db \
  --target tplink-dl110v2-1.0.11 --snapshot
```

Expected: `surfaces opened 197`, and `absent` for coverage, sweep hits and `not_audited`. The file lands at `docs/indicators/2026-10-07-tplink-dl110v2-1.0.11.json`.

**This is the honest first reading, and it is the point of committing it.** Three of four indicators have no data because the database predates the tables. A snapshot showing `absent` in a tracked file is what stops a future reader assuming the indicators were never wired up.

- [ ] **Step 2: Add a README to `docs/indicators/`**

Create `docs/indicators/README.md`:

```markdown
# Indicator snapshots

Deterministic leading indicators, per the design spec §6.1: coverage
percentage, surfaces opened, sweep hit counts, and the `not_audited` row
count. They are the between-milestone substitute for the benchmark, which
runs at milestones only because a full re-run cost $658.37.

Write one with:

    python3 audit.py indicators --db <run>/audit.db --target <name> --snapshot

Compare two with:

    python3 audit.py indicators --compare docs/indicators/<a>.json docs/indicators/<b>.json

**Never edited in place.** A second snapshot of the same target on the same
day needs `--label <word>`; the writer refuses to overwrite. A superseded
measurement stays written so a regression remains visible in git history —
the same rule `docs/baselines/` follows.

**`absent` is not `0`.** It means the table is not in that database, not that
the value was zero. The first snapshot here reads `absent` for three of the
four indicators because the only `audit.db` in existence predates Stage 2.
```

- [ ] **Step 3: Update `feature_lists.json`**

For the five Stage 3b features, set `"status": "shipped"`, rename `verbs_planned` to `verbs`, and add the `modules` and `tests` each one now has. Set `stage3b`'s `"status": "shipped"`. Add `"destination_resolved": "stage3b"` to — and **do not delete** — the five `open_items` this stage closes; mark each `"status": "closed"`. An open item deleted leaves no record that it was ever real.

The `manifest` gate requires every `shipped` feature to name at least one test or doc, every path to exist, and every verb to be dispatchable.

- [ ] **Step 4: Run the manifest gate**

Run: `python3 scripts/harness.py --only manifest`
Expected: PASS, reporting 34 features and the two new verbs resolving.

- [ ] **Step 5: Update the three documents**

- `progress.md`: add Stage 3b to the stage table (status **merged**, gate *none — no audit run*); move items 1–5 out of §8's next steps into §2 as delivered; update the headline counts; state that severity agreement is now scored and what it found (5/9 agree, 4 under-rated, worst 3 steps).
- `SESSION_HANDOFF.md`: replace §4's Options A–C with what remains; keep §3's standing instruction verbatim.
- `ARCHITECTURE.md`: `audit_core` module map gains `readings.py`, `indicators.py`, `rerate.py`; the verb list goes 20 → 22; §8's gate table is unchanged unless Step 6 changes it.

- [ ] **Step 6: Decide whether the harness needs a new gate**

It does not, and this step is here so that the decision is made rather than drifted into. The `eol`, `manifest` and `tests` gates already cover this stage's deliverables. **Do not add an `indicators` gate**: it would need a database to read, the only one available is outside the repo, and a gate that SKIPs on every machine but one is noise.

Record this decision in the task report.

- [ ] **Step 7: Add the harness test for the new verb count**

```python
# tests/test_harness.py
def test_selftest_reports_every_verb_the_parser_declares():
    """The manifest gate checks feature_lists.json against audit.py. This
    checks audit.py against itself, so a verb added to HANDLERS without a
    subparser fails here rather than at a user's first invocation."""
    import subprocess
    import sys
    proc = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "selftest"],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "22 declared, all dispatchable" in proc.stdout
```

- [ ] **Step 8: Run every gate**

Run: `python3 scripts/harness.py --all`
Expected: all 7 PASS. `bench` must still report `recall 9/19, 45 findings, precision 39/40` — this stage changes no audit output, so any movement there is a defect in this stage, not a result.

- [ ] **Step 9: Commit**

```bash
git add feature_lists.json progress.md SESSION_HANDOFF.md ARCHITECTURE.md \
        docs/indicators/ tests/test_harness.py
git commit -m "docs: Stage 3b in the record, and the first indicator snapshot"
```

---

## What this plan deliberately does not do

| Not done | Why | Where it goes |
|---|---|---|
| Mutate any finding's severity | Unmeasurable while the benchmark is deferred; it changes audit output | After a benchmark run, with `rerate`'s report as the evidence |
| Threshold or gate the indicators | No second datapoint exists to calibrate against | Once snapshots accumulate |
| Add an `indicators` harness gate | Its only corpus is outside the repo; a gate that SKIPs everywhere is noise | Task 10, Step 6, as a recorded decision |
| Build the asus or unifi goldens | Stage 4's gate owns them | Stage 4 |
| Apply the Sonnet tiering diff | Needs four audit runs | Held, `docs/baselines/2026-10-05-stage3-tiering-gate.md` |
| Run any gate or audit | Operator decision of 2026-10-07, on cost | Operator's call |
| Execute `install.ps1` | No PowerShell on this machine | Needs a Windows host |
| Wire `indicators` or `rerate` into any workflow phase | Both are post-run inspection; wiring them in would add tokens to every audit and change the pipeline | Only with a measured reason |

---

## Self-Review

**1. Spec coverage.** Every section of the design spec maps to a task:

| Spec § | Requirement | Task |
|---|---|---|
| §4.1 | `indicators` verb, four figures | 2, 3 |
| §4.2 | Snapshots under `docs/indicators/`, `--compare` | 3, 4 |
| §4.3 | `absent` is not `0`, in every new reader | 1 (primitive), 2, 6 (readers) |
| §4.4 | Severity agreement, additive, weighted recall alongside | 5 |
| §4.5 | Coverage in `bench` | 6 |
| §4.6 | `rerate`, advisory, own verb | 7 |
| §4.7 | The four parked defects | 8 (three code), 9 (one prose) |
| §5 | Five verification layers | 1–2 fixtures, 5 real baseline, 10 `make all`, 10 snapshot, 8 reproduction tests |
| §6 | Deliberate omissions | "What this plan deliberately does not do" |

No gaps.

**2. Placeholder scan.** One deliberate exception: **Task 8, Step 13** describes the two `--replace` tests rather than printing them, because their fixture setup depends on `chains.compose` and `identity.record` signatures the implementer must read. Every other code step carries runnable code. The implementer should treat Step 13 as the one place to read neighbouring tests first.

**3. Type consistency.** Checked across tasks:
- `Reading` is constructed only via `Reading.absent(note)` and `Reading.of(value, detail)` — never the bare constructor — in Tasks 2 and 6.
- `table_state(con, *names)` returns `ABSENT`/`PRESENT`, never `EMPTY`; `EMPTY` is a `Reading` state only. This asymmetry is deliberate: a table's existence is binary, a measurement's is not.
- `severity_agreement(refs, findings, matched)` takes `matched` as `tuple[tuple[str, str], ...]`, matching `BenchResult.matched`.
- `SEVERITIES` is strongest-first, so `steps = f_rank - r_rank` is **positive when under-rated**. Used consistently in Task 5's `weighted_recall` and its tests.
- `BenchResult` gains `severity` then `coverage`, both defaulting to `None`, both after `precision` — so no existing positional construction breaks.

**4. Review Focus.** All five pinned, each to the task owning the code: RF1 → Task 1 Step 5 and Task 2 Step 9; RF2 → Task 1 Step 7 and Task 2 Step 11; RF3 → Task 5 Step 9; RF4 → Task 4 Step 7; RF5 → Task 3 Step 11.

**One conflict found and resolved while reviewing.** Task 2's `_coverage` returns `absent` when the inventory is empty, while Task 1's `Reading.of(0)` would call a zero `empty`. These disagree about what zero means, and the disagreement is correct: an empty *inventory* is a missing denominator, not a measured zero, so `0%` would be a fabricated fraction. Task 2 Step 11 asserts this explicitly so a future reader does not "fix" it into consistency.

---

## Execution Notes

**Order matters once.** Task 1 produces the primitive Tasks 2 and 6 consume. Everything after that is independent: 3→4 share the verb, 5→6 share `BenchResult`, and 7, 8, 9, 10 touch nothing the others need. Task 10 must be last — it closes the inventory the other tasks open.

**Model selection.** Tasks 1, 2, 4, 5, 6, 8 carry complete code: transcription plus testing, so the cheapest tier. Tasks 3 and 7 add verbs across two files with wiring to get right: mid tier. Task 9 edits CRLF prose under the anti-absence rule and Task 10 reconciles four documents against the tree: mid tier, and Task 9's reviewer should check the derivation reconciliation specifically.

**The two reproduced defects have known-failing starting points.** Task 8a and 8b both begin with a test that fails against today's code in a specific, documented way. An implementer who cannot reproduce the failure first has a different problem from the one this plan describes — stop and report rather than writing the fix.

**The baseline measurement in Task 5, Step 12 is the stage's only check against reality.** Everything else is fixtures. If it does not report four under-rated matches, the independent record is `docs/superpowers/specs/2026-10-05-stage0-findings-for-later-stages.md` §1 — reconcile against that document, not against the code that just produced the number.
