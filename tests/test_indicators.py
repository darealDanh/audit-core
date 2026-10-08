import json
import datetime
import sqlite3

import pytest

from audit_core import indicators, readings


def _db(tmp_path, *, coverage=True, surfaces=True, patterns=True,
        inventory=None, cba_coverage=None, pattern_hits=None):
    """A run database with whichever table families the test needs.

    Built table by table rather than from schema.sql, because the point of
    most of these tests is a database that is MISSING a family.

    For fine-grained control, inventory, cba_coverage, and pattern_hits can
    override the coverage and patterns flags: if set to True or False, they
    control that specific table independently.
    """
    con = sqlite3.connect(tmp_path / "audit.db")
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, "
                "title TEXT, cwe TEXT, location TEXT, severity TEXT)")
    if surfaces:
        con.execute("CREATE TABLE cba_attack_surface ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, "
                    "endpoint TEXT, method TEXT, auth_required TEXT, "
                    "description TEXT)")
    # Handle fine-grained control for coverage tables
    _inventory = inventory if inventory is not None else coverage
    _cba_coverage = cba_coverage if cba_coverage is not None else coverage
    if _inventory:
        con.execute("CREATE TABLE cba_inventory (unit TEXT PRIMARY KEY, "
                    "kind TEXT NOT NULL, group_id TEXT, size INTEGER, "
                    "added_at TEXT)")
    if _cba_coverage:
        con.execute("CREATE TABLE cba_coverage (unit TEXT NOT NULL, "
                    "phase TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, "
                    "recorded_at TEXT, PRIMARY KEY (unit, phase))")
    # Handle fine-grained control for pattern tables
    _pattern_hits = pattern_hits if pattern_hits is not None else patterns
    if patterns:
        con.execute("CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, "
                    "name TEXT NOT NULL, regex TEXT NOT NULL, "
                    "origin_finding TEXT, language TEXT, notes TEXT, "
                    "swept_at TEXT, hit_count INTEGER, created_at TEXT)")
    if _pattern_hits:
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


def test_render_names_every_indicator(tmp_path):
    con = _db(tmp_path)
    con.commit()
    out = indicators.render(indicators.collect(con, target="demo"))
    for label in ("coverage", "surfaces opened", "sweep hits",
                  "not_audited units"):
        assert label in out
    assert "demo" in out
    con.close()


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
    assert "Each entry says why" in out

    j = indicators.to_json(ind)
    assert j["indicators"]["coverage"] == {
        "state": "absent",
        "note": "cba_coverage / cba_inventory are not in this database "
                "(it predates Stage 2)",
        "unit": "%"}
    con.close()


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


def test_coverage_absent_when_inventory_missing(tmp_path):
    """coverage_reading guards on BOTH tables, so it returns absent if
    cba_inventory is missing even when cba_coverage exists."""
    con = _db(tmp_path, inventory=False, cba_coverage=True)
    con.commit()
    ind = indicators.collect(con, target="partial")
    assert ind.coverage.is_absent
    assert "cba_coverage / cba_inventory" in ind.coverage.note
    con.close()


def test_coverage_absent_when_coverage_table_missing(tmp_path):
    """coverage_reading guards on BOTH tables, so it returns absent if
    cba_coverage is missing even when cba_inventory exists."""
    con = _db(tmp_path, inventory=True, cba_coverage=False)
    con.commit()
    ind = indicators.collect(con, target="partial")
    assert ind.coverage.is_absent
    assert "cba_coverage / cba_inventory" in ind.coverage.note
    con.close()


def test_sweep_hits_absent_when_pattern_hits_missing(tmp_path):
    """_sweep_hits guards on cba_pattern_hits, so it returns absent if
    that table is missing even when cba_patterns exists."""
    con = _db(tmp_path, patterns=True, pattern_hits=False)
    con.commit()
    ind = indicators.collect(con, target="partial")
    assert ind.sweep_hits.is_absent
    assert "cba_pattern_hits" in ind.sweep_hits.note
    con.close()


def test_snapshot_path_is_dated_and_named_for_the_target(tmp_path):
    p = indicators.snapshot_path(
        tmp_path, "tplink-dl110v2", datetime.date(2026, 10, 7))
    assert p == tmp_path / "docs" / "indicators" / "2026-10-07-tplink-dl110v2.json"


def test_a_label_distinguishes_two_snapshots_on_one_day(tmp_path):
    p = indicators.snapshot_path(
        tmp_path, "tplink", datetime.date(2026, 10, 7), label="after-r3")
    assert p.name == "2026-10-07-tplink-after-r3.json"


def test_a_slash_in_the_target_cannot_leave_the_snapshot_directory(tmp_path):
    p = indicators.snapshot_path(tmp_path, "a/b\\c", datetime.date(2026, 10, 7))
    assert p.parent == tmp_path / "docs" / "indicators"
    assert p.name == "2026-10-07-a-b-c.json"


def test_an_empty_or_punctuation_target_is_unnamed(tmp_path):
    for t in ("", "///", "---"):
        p = indicators.snapshot_path(tmp_path, t, datetime.date(2026, 10, 7))
        assert p.name == "2026-10-07-unnamed.json"


def test_dots_cannot_lead_or_trail_a_slug(tmp_path):
    d = datetime.date(2026, 10, 7)
    assert indicators.snapshot_path(tmp_path, "..", d).name == "2026-10-07-unnamed.json"
    assert indicators.snapshot_path(tmp_path, "../x/..", d).name == "2026-10-07-x.json"
    assert indicators.snapshot_path(tmp_path, "t", d, label="..").name == "2026-10-07-t-labelled.json"


def test_a_label_that_slugs_to_nothing_is_labelled(tmp_path):
    p = indicators.snapshot_path(tmp_path, "t", datetime.date(2026, 10, 7), label="//")
    assert p.name == "2026-10-07-t-labelled.json"
    assert p.parent == tmp_path / "docs" / "indicators"


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


def test_float_delta_does_not_render_more_than_six_decimal_places():
    """Floating-point arithmetic produces noise like 0.09999999999999432.
    Rounding to 6 places removes the artefact while preserving precision."""
    a = {"indicators": {"coverage": {"state": "present", "value": 71.9}}}
    b = {"indicators": {"coverage": {"state": "present", "value": 72.0}}}
    delta = indicators.compare(a, b)[0]
    assert delta.moved == "+0.1"
    # Verify no more than 6 decimal places in the moved field
    parts = delta.moved.lstrip("+-").split(".")
    if len(parts) > 1:
        assert len(parts[1]) <= 6


def test_a_string_value_is_not_comparable():
    """Values that are not numeric cannot be compared."""
    a = {"indicators": {"coverage": {"state": "present", "value": "a"}}}
    b = {"indicators": {"coverage": {"state": "present", "value": "b"}}}
    assert indicators.compare(a, b)[0].moved == "not comparable"


def test_a_null_value_is_not_comparable():
    """Null values cannot be numerically compared."""
    a = {"indicators": {"coverage": {"state": "present", "value": None}}}
    b = {"indicators": {"coverage": {"state": "present", "value": 5}}}
    assert indicators.compare(a, b)[0].moved == "not comparable"


def test_an_indicator_missing_from_snapshot_b_is_not_comparable():
    """The reverse case of test_an_indicator_missing_from_one_snapshot_is_not_comparable:
    B was taken before this indicator existed."""
    a = {"indicators": {"surfaces": {"state": "present", "value": 5},
                        "sweep_hits": {"state": "present", "value": 2}}}
    b = {"indicators": {"surfaces": {"state": "present", "value": 5}}}
    deltas = {d.name: d for d in indicators.compare(a, b)}
    assert deltas["sweep_hits"].moved == "not comparable"
    assert deltas["sweep_hits"].after == "not in snapshot"
    assert deltas["surfaces"].moved == "unchanged"


def test_present_to_absent_is_not_comparable():
    """A value that vanishes (becomes absent) is not comparable to its prior value."""
    a = {"indicators": {"coverage": {"state": "present", "value": 72.0}}}
    b = {"indicators": {"coverage": {"state": "absent", "note": "table dropped"}}}
    assert indicators.compare(a, b)[0].moved == "not comparable"


def test_an_empty_state_entry_is_readable():
    """An indicator with state=empty (empty table, not absent) is a real measurement."""
    a = {"indicators": {"surfaces": {"state": "empty", "value": 0}}}
    b = {"indicators": {"surfaces": {"state": "empty", "value": 0}}}
    assert indicators.compare(a, b)[0].moved == "unchanged"


# ---- Stage 3c task 7: the remaining unexecuted statements ----

def test_surfaces_absent_when_attack_surface_table_missing(tmp_path):
    con = _db(tmp_path, surfaces=False)
    ind = indicators.collect(con, target="nosurf")
    assert ind.surfaces.is_absent
    assert ind.surfaces.note == "cba_attack_surface is not in this database"
    con.close()


def _collected(tmp_path):
    con = _db(tmp_path)
    ind = indicators.collect(con, target="demo")
    con.close()
    return ind


def test_write_snapshot_creates_parent_directories(tmp_path):
    ind = _collected(tmp_path)
    target = tmp_path / "out" / "docs" / "indicators" / "2026-10-08-demo.json"
    assert not target.parent.exists()
    written = indicators.write_snapshot(target, ind)
    assert written == target
    assert target.read_text() == (
        json.dumps(indicators.to_json(ind), indent=2) + "\n")


def test_write_snapshot_refuses_to_overwrite_a_measurement(tmp_path):
    """Handoff rule 4 in code: a measurement is never edited in place.

    Overwriting the morning's snapshot with the afternoon's would destroy
    a measurement and leave no trace it existed."""
    ind = _collected(tmp_path)
    target = tmp_path / "2026-10-08-demo.json"
    indicators.write_snapshot(target, ind)
    before = target.read_bytes()

    other = indicators.Indicators(
        target="different", phase="audit", coverage=ind.coverage,
        surfaces=ind.surfaces, sweep_hits=ind.sweep_hits,
        not_audited=ind.not_audited)
    with pytest.raises(indicators.IndicatorError) as excinfo:
        indicators.write_snapshot(target, other)
    msg = str(excinfo.value)
    assert f"{target} already exists." in msg
    assert "Measurements are never edited in place" in msg
    assert "--label" in msg
    assert target.read_bytes() == before, "a refused write must change nothing"
    assert [p.name for p in tmp_path.glob("2026-*")] == [target.name]


def test_compare_appends_unit_to_both_sides():
    a = {"indicators": {"coverage": {"state": "present", "value": 94.0,
                                     "unit": "%"}}}
    b = {"indicators": {"coverage": {"state": "present", "value": 72.0,
                                     "unit": "%"}}}
    d = indicators.compare(a, b)[0]
    assert (d.before, d.after, d.moved) == ("94.0%", "72.0%", "-22.0%")


def test_compare_does_not_append_unit_to_an_absent_side():
    a = {"indicators": {"coverage": {"state": "absent", "note": "n",
                                     "unit": "%"}}}
    b = {"indicators": {"coverage": {"state": "present", "value": 72.0,
                                     "unit": "%"}}}
    d = indicators.compare(a, b)[0]
    assert (d.before, d.after) == ("absent", "72.0%")
    d = indicators.compare(b, a)[0]
    assert (d.before, d.after) == ("72.0%", "absent")


def test_render_compare_header_rows_and_footer():
    deltas = (
        indicators.Delta("coverage", "94.0%", "72.0%", "-22.0%"),
        indicators.Delta("sweep_hits", "not in snapshot", "2",
                         "not comparable"))
    out = indicators.render_compare("old.json", "new.json", deltas).split("\n")
    assert out[0] == "comparing old.json -> new.json"
    assert out[1] == f"  {'indicator':<18} {'before':>15} {'after':>15}   moved"
    assert out[2] == f"  {'coverage':<18} {'94.0%':>15} {'72.0%':>15}   -22.0%"
    assert out[3] == (f"  {'sweep_hits':<18} {'not in snapshot':>15} "
                      f"{'2':>15}   not comparable")
    assert out[4] == ""
    assert out[5] == ("  `not comparable` means one snapshot has no reading "
                      "for that indicator, not that it did not move.")
    assert len(out) == 6


def test_render_compare_omits_footer_when_everything_is_comparable():
    out = indicators.render_compare(
        "a", "b", (indicators.Delta("surfaces", "5", "5", "unchanged"),))
    assert "not comparable" not in out
    assert out.split("\n")[-1].endswith("unchanged")


# --- Stage 3c Task 15: boundaries the first mutation sweep found unpinned ----

def test_one_absent_side_is_enough_to_make_a_pair_not_comparable():
    """indicators.py:232. `a absent OR b absent`: either side alone makes the
    pair uncomparable, even when the absent entry carries a stray value that
    happens to equal (or differ from) the other side's. Under `and`, such a
    snapshot would be diffed as if the reading existed."""
    absent_with_value = {"state": "absent", "value": 7, "note": "no table"}
    present = {"state": "present", "value": 7}
    forward = indicators.compare({"indicators": {"coverage": absent_with_value}},
                                 {"indicators": {"coverage": present}})
    assert forward[0].moved == "not comparable"
    backward = indicators.compare({"indicators": {"coverage": present}},
                                  {"indicators": {"coverage": absent_with_value}})
    assert backward[0].moved == "not comparable"
    shifted = indicators.compare(
        {"indicators": {"coverage": {"state": "absent", "value": 5}}},
        {"indicators": {"coverage": {"state": "present", "value": 7}}})
    assert shifted[0].moved == "not comparable"
