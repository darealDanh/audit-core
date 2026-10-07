"""Behavioral coverage for the two tables Task 1 of Stage 3 declares.

_validate_component checks only vocabulary and confidence range here --
the identity-evidence rule is Task 5's, added to the same function later.
_validate_chain is fully specified by this task, so every rule it enforces
is pinned below.
"""
import pytest

from audit_core import db, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


COMPONENT = {
    "path": "vendor/libfoo.so",
    "kind": "binary",
    "asserted_identity": "libfoo 1.2.3",
    "identity_evidence": "SONAME libfoo.so.1; strings match the upstream "
                         "1.2.3 release tarball",
}


def test_put_accepts_every_declared_component_kind(con):
    for i, kind in enumerate(db.COMPONENT_KINDS):
        db.put(con, "cba_components",
               dict(COMPONENT, path=f"{COMPONENT['path']}.{i}", kind=kind))


def test_put_rejects_a_component_kind_outside_the_vocabulary(con):
    with pytest.raises(db.DbError, match="kind"):
        db.put(con, "cba_components", dict(COMPONENT, kind="operating-system"))


def test_put_accepts_confidence_at_both_boundaries(con):
    db.put(con, "cba_components", dict(COMPONENT, path="a", confidence="1"))
    db.put(con, "cba_components", dict(COMPONENT, path="b", confidence="10"))


@pytest.mark.parametrize("value", ["0", "11", "-1"])
def test_put_rejects_confidence_outside_1_to_10(con, value):
    with pytest.raises(db.DbError, match="confidence"):
        db.put(con, "cba_components", dict(COMPONENT, path="c", confidence=value))


def test_put_rejects_a_non_integer_confidence(con):
    with pytest.raises(db.DbError, match="confidence"):
        db.put(con, "cba_components", dict(COMPONENT, path="d", confidence="high"))


def test_put_accepts_a_component_with_no_confidence_at_all(con):
    """confidence is optional: an absent/empty value is not a validation
    error, only an out-of-range or non-integer one is."""
    db.put(con, "cba_components", dict(COMPONENT, path="e", confidence=""))


CHAIN = {
    "id": "C1",
    "finding_ids": "G1-F1,G1-F2",
    "attacker_position": "unauthenticated network",
    "completeness": "complete",
}


def test_put_accepts_every_declared_chain_completeness(con):
    for i, completeness in enumerate(db.CHAIN_COMPLETENESS):
        db.put(con, "cba_chains",
               dict(CHAIN, id=f"C{i}", completeness=completeness))


def test_put_rejects_a_chain_completeness_outside_the_vocabulary(con):
    with pytest.raises(db.DbError, match="completeness"):
        db.put(con, "cba_chains", dict(CHAIN, completeness="maybe"))


def test_put_rejects_a_chain_with_fewer_than_two_findings(con):
    """A one-finding chain is a finding, not a chain."""
    with pytest.raises(db.DbError, match="finding_ids"):
        db.put(con, "cba_chains", dict(CHAIN, finding_ids="G1-F1"))


def test_put_rejects_a_chain_with_no_finding_ids_at_all(con):
    with pytest.raises(db.DbError, match="finding_ids"):
        db.put(con, "cba_chains", dict(CHAIN, finding_ids=""))


def test_put_rejects_a_chain_that_repeats_a_finding_id(con):
    with pytest.raises(db.DbError, match="repeats"):
        db.put(con, "cba_chains", dict(CHAIN, finding_ids="G1-F1,G1-F1"))


def test_put_accepts_a_three_finding_chain(con):
    db.put(con, "cba_chains",
           dict(CHAIN, id="C9", finding_ids="G1-F1,G1-F2,G1-F3"))
