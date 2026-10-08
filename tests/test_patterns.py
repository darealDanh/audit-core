import pytest

from audit_core import db, patterns, workspace


def fresh(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = db.connect(run / "audit.db")
    db.put(con, "cba_patterns", {
        "id": "P1", "name": "strncpy with strlen of source",
        "regex": r"strncpy\s*\([^,]+,\s*([^,]+),\s*strlen\(\s*\1\s*\)",
        "origin_finding": "G1-F1"})
    return con


def test_a_newly_registered_pattern_is_unswept(tmp_path):
    con = fresh(tmp_path)
    states = patterns.states(con)
    assert len(states) == 1
    assert states[0].id == "P1"
    assert states[0].swept is False
    assert states[0].hit_count == 0
    assert [s.id for s in patterns.unswept(con)] == ["P1"]


def test_mark_swept_records_the_time_and_the_count(tmp_path):
    con = fresh(tmp_path)
    patterns.mark_swept(con, "P1", hit_count=7, when="2026-10-05 12:00:00")
    state = patterns.states(con)[0]
    assert state.swept is True
    assert state.swept_at == "2026-10-05 12:00:00"
    assert state.hit_count == 7
    assert patterns.unswept(con) == []


def test_a_sweep_that_found_nothing_still_counts_as_swept(tmp_path):
    """Zero hits is a result. Treating it as unswept would make the gate
    unclearable for exactly the patterns that turned out to be isolated --
    and would push an operator to narrow a pattern until it matched
    something, which is the opposite of what a sweep is for."""
    con = fresh(tmp_path)
    patterns.mark_swept(con, "P1", hit_count=0)
    assert patterns.unswept(con) == []
    assert patterns.states(con)[0].hit_count == 0


def test_mark_swept_on_an_unknown_pattern_is_an_error(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        patterns.mark_swept(con, "P9", hit_count=1)
    assert "P9" in str(exc.value)


def test_render_names_the_sweep_command_for_each_unswept_pattern(tmp_path):
    con = fresh(tmp_path)
    out = patterns.render(patterns.states(con))
    assert "P1" in out
    assert "audit.py sweep" in out
    assert "1 unswept" in out


def test_the_pattern_cap_is_the_read_cap_not_a_coincidence():
    """`MAX_PATTERNS = 200` equalled `db.MAX_ROWS` by accident, and
    `db.rows` clamps with `min(limit, MAX_ROWS)`. Raising MAX_PATTERNS alone
    would change nothing except the claim it makes, and `patterns --gate`
    would report PASS over unswept patterns beyond the clamp: a gate that
    stops working without saying so."""
    assert patterns.MAX_PATTERNS == db.MAX_ROWS


def test_a_full_pattern_list_says_the_gate_can_only_rule_on_what_it_saw():
    items = [patterns.PatternState(id=f"P{i}", name="n", origin_finding="",
                                   swept_at="2026-01-01", hit_count=0)
             for i in range(patterns.MAX_PATTERNS)]
    out = patterns.render(items)
    assert "capped" in out and "PASS" in out


def test_render_with_nothing_registered_says_so_and_says_what_to_do():
    out = patterns.render([])
    assert out.startswith("patterns: none registered.")
    assert "audit.py put --table cba_patterns" in out


# --- Stage 3c Task 15: boundaries the first mutation sweep found unpinned ----

def test_states_carry_the_name_and_origin_the_pattern_was_registered_with(tmp_path):
    """patterns.py:52, 53. `x or ""` is a NULL guard; turned into `x and ""`
    it would erase a set name and origin_finding. A NULL origin_finding must
    still come back as the empty string."""
    con = fresh(tmp_path)
    (state,) = patterns.states(con)
    assert state.name == "strncpy with strlen of source"
    assert state.origin_finding == "G1-F1"

    # name is NOT NULL in the schema; origin_finding is the nullable one.
    db.put(con, "cba_patterns", {"id": "P2", "name": "bare", "regex": "memcpy"})
    bare = next(s for s in patterns.states(con) if s.id == "P2")
    assert bare.name == "bare" and bare.origin_finding == ""
