import pytest

from audit_core import coverage, db, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def inventory(con, *units, kind="file"):
    for u in units:
        db.put(con, "cba_inventory", {"unit": u, "kind": kind})


def test_a_not_audited_row_without_a_reason_is_rejected(con):
    """A gap with no reason is a gap that hides itself - the exact failure
    the tplink post-mortem found below the IP layer."""
    inventory(con, "src/a.c")
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_coverage",
               {"unit": "src/a.c", "phase": "audit", "state": "not_audited"})
    assert "reason" in str(exc.value)


def test_a_not_audited_row_with_an_invented_reason_is_rejected(con):
    inventory(con, "src/a.c")
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                     "state": "not_audited", "reason": "meh"})
    assert "meh" in str(exc.value)
    assert "budget" in str(exc.value)      # names the legal vocabulary


def test_an_analyzed_row_needs_no_reason(con):
    inventory(con, "src/a.c")
    db.put(con, "cba_coverage",
           {"unit": "src/a.c", "phase": "audit", "state": "analyzed"})
    assert coverage.report(con).analyzed == 1


def test_an_invented_state_is_rejected(con):
    inventory(con, "src/a.c")
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_coverage",
               {"unit": "src/a.c", "phase": "audit", "state": "skimmed"})
    assert "skimmed" in str(exc.value)


def test_report_counts_analyzed_not_audited_and_unrecorded(con):
    inventory(con, "a.c", "b.c", "c.c", "d.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "c.c", "phase": "audit",
                                 "state": "not_audited", "reason": "vendored"})
    r = coverage.report(con)
    assert (r.inventoried, r.analyzed, r.not_audited, r.unrecorded) == (4, 2, 1, 1)
    assert r.fraction == 0.5
    assert r.by_reason == (("vendored", 1),)


def test_report_separates_budget_skips_from_every_other_reason(con):
    """Spec R3: a group skipped for budget is a quality-gate failure, not a
    scope decision. Stage 3 gates on this number; Stage 2 surfaces it."""
    inventory(con, "a.c", "b.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit",
                                 "state": "not_audited", "reason": "budget"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit",
                                 "state": "not_audited", "reason": "out-of-scope"})
    r = coverage.report(con)
    assert r.budget_skips == 1
    assert r.not_audited == 2
    assert "budget" in coverage.render(r)


def test_report_on_an_empty_inventory_does_not_divide_by_zero(con):
    """Review Focus 5. Inventory is populated in a later phase than the first
    one that reports, so this is the first real invocation, not an edge case."""
    r = coverage.report(con)
    assert r.inventoried == 0
    assert r.fraction == 0.0
    text = coverage.render(r)
    assert "inventory is empty" in text
    assert "cba_inventory" in text          # says how to populate it
    assert "0.0%" not in text               # does not read as a coverage failure


def test_report_can_be_scoped_to_one_phase(con):
    inventory(con, "a.c", "b.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit", "state": "analyzed"})
    assert coverage.report(con, phase="audit").analyzed == 1
    assert coverage.report(con).analyzed == 2


def test_a_unit_analyzed_in_two_phases_counts_once_overall(con):
    inventory(con, "a.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit", "state": "analyzed"})
    r = coverage.report(con)
    assert r.analyzed == 1
    assert r.unrecorded == 0


def test_an_inventory_row_needs_a_known_kind(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_inventory", {"unit": "a.c", "kind": "thingy"})
    assert "thingy" in str(exc.value)
