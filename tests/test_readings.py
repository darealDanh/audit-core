from audit_core import readings
import sqlite3


def test_absent_never_renders_as_a_number():
    """The rule this module exists for. A database from before the feature
    existed and a run that covered nothing both produce `0` otherwise, and a
    reader cannot tell a non-event from a catastrophe."""
    r = readings.Reading.absent("cba_coverage is not in this database")
    rendered = r.render(unit="%")
    assert "0" not in rendered
    assert "absent" in rendered
    assert "cba_coverage is not in this database" in rendered


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
