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
    inventory(con, "a.c", "b.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit", "state": "analyzed"})
    # b.c is the mixed-state case: recon opened it, audit ran out of budget.
    # Overall it is a gap, not a success - `analyzed` and `not_audited` are a
    # partition of the recorded units, so it cannot be counted in both.
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "b.c", "phase": "audit",
                                 "state": "not_audited", "reason": "budget"})
    r = coverage.report(con)
    assert r.analyzed == 1
    assert r.not_audited == 1
    assert r.unrecorded == 0
    assert r.fraction == 0.5
    rendered = coverage.render(r)
    assert "1/2 analyzed (50.0%)" in rendered
    assert "WARNING" in rendered
    # Per phase, the record still says exactly what each phase did.
    assert coverage.report(con, phase="recon").analyzed == 2
    assert coverage.report(con, phase="audit").not_audited == 1


def test_the_only_inventoried_unit_being_budget_skipped_is_not_full_coverage(con):
    """The R3 scenario, verbatim: one unit, analyzed in recon and skipped for
    budget in audit. Leading with `100.0% analyzed` next to a budget WARNING
    is the number that goes into the Stage 2 gate record."""
    inventory(con, "a.c")
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "recon", "state": "analyzed"})
    db.put(con, "cba_coverage", {"unit": "a.c", "phase": "audit",
                                 "state": "not_audited", "reason": "budget"})
    r = coverage.report(con)
    assert (r.analyzed, r.not_audited, r.unrecorded) == (0, 1, 0)
    assert r.fraction == 0.0
    assert "0/1 analyzed (0.0%)" in coverage.render(r)


def test_analyzed_counts_inventoried_units_so_it_cannot_exceed_the_denominator(con):
    """Three units carry an `analyzed` row; one of them is inventoried. The
    numerator joins the inventory exactly as `unrecorded` already did, so the
    percentage cannot run past 100%."""
    inventory(con, "a.c")
    for unit in ("a.c", "b.c", "c.c"):
        db.put(con, "cba_coverage",
               {"unit": unit, "phase": "audit", "state": "analyzed"})
    r = coverage.report(con)
    assert (r.inventoried, r.analyzed) == (1, 1)
    assert r.fraction == 1.0
    assert "1/1 analyzed (100.0%)" in coverage.render(r)


def test_not_audited_also_counts_only_inventoried_units(con):
    inventory(con, "a.c")
    for unit in ("a.c", "b.c"):
        db.put(con, "cba_coverage", {"unit": unit, "phase": "audit",
                                     "state": "not_audited", "reason": "vendored"})
    r = coverage.report(con)
    assert (r.inventoried, r.analyzed, r.not_audited) == (1, 0, 1)


def test_an_inventory_row_needs_a_known_kind(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_inventory", {"unit": "a.c", "kind": "thingy"})
    assert "thingy" in str(exc.value)


def test_a_fully_analyzed_run_passes(con):
    inventory(con, "src/a.c")
    db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                 "state": "analyzed"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is True
    assert g.failures == ()


def test_an_empty_inventory_fails_the_gate(con):
    """Review Focus 4. fraction is 0.0 with nothing inventoried, and the
    Stage 2 render says there is no denominator. A gate reading `0 budget
    skips, 0 unrecorded` and passing would pass hardest on the run that did
    the least."""
    g = coverage.gate(coverage.report(con))
    assert g.ok is False
    assert any("inventory" in f for f in g.failures)


def test_a_budget_skip_fails_the_gate(con):
    inventory(con, "src/a.c")
    db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                 "state": "not_audited", "reason": "budget"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is False
    assert any("budget" in f for f in g.failures)
    assert any("checkpoint" in f.lower() for f in g.failures), (
        "the failure must name the remedy; R3 answers a budget skip with "
        "checkpoint-and-restart, never with skipping")


def test_an_inventoried_unit_with_no_coverage_row_fails_the_gate(con):
    """The silent case the whole mechanism exists for: a unit nobody ever
    recorded a decision about. Six of ten missed tplink CRITICALs are on
    surfaces that were never opened and never written down."""
    inventory(con, "src/a.c", "src/wifi.c")
    db.put(con, "cba_coverage", {"unit": "src/a.c", "phase": "audit",
                                 "state": "analyzed"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is False
    assert any("unrecorded" in f for f in g.failures)


def test_a_recorded_non_budget_skip_warns_but_passes(con):
    """out-of-scope, vendored and the rest are decisions, recorded with
    reasons -- which is what the mechanism asks for. Failing on them would
    make the gate unclearable on any real target."""
    inventory(con, "vendor/lib.c")
    db.put(con, "cba_coverage", {"unit": "vendor/lib.c", "phase": "audit",
                                 "state": "not_audited", "reason": "vendored"})
    g = coverage.gate(coverage.report(con))
    assert g.ok is True
    assert any("vendored" in w for w in g.warnings)


def test_a_state_outside_the_contract_is_absorbed_into_neither_count(con):
    """`db.put` cannot write this; a hand-edited table can. Overstating
    coverage is the failure this module exists to prevent, so an
    unrecognisable state falls out of both counts rather than into
    `analyzed`."""
    inventory(con, "a.c")
    con.execute("INSERT INTO cba_coverage (unit, phase, state) "
                "VALUES ('a.c', 'audit', 'skimmed')")
    r = coverage.report(con)
    assert (r.analyzed, r.not_audited, r.unrecorded) == (0, 0, 0)
    assert r.fraction == 0.0
