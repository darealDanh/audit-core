import sqlite3

import pytest

from audit_core import db, pivot, workspace


def fresh(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = db.connect(run / "audit.db")
    db.put(con, "cba_feature_groups", {"id": "G1", "name": "auth"})
    db.put(con, "cba_findings", {
        "id": "G1-F1", "group_id": "G1", "title": "t", "severity": "HIGH",
        "confidence": "9", "location": "src/recv.c:120",
        "root_cause": "unbounded copy", "impact": "overflow"})
    return con


def test_a_false_positive_without_a_refuting_mechanism_is_rejected(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts",
               {"finding_id": "G1-F1", "verdict": "FALSE_POSITIVE",
                "reason": "bounded by the window"})
    message = str(exc.value)
    assert "refuting_mechanism" in message
    assert "audit.py pivot" in message, (
        "the error must name the verb that supplies the fields, or the "
        "operator's next move is to work around the rule")


def test_a_false_positive_without_an_enabled_observation_is_rejected(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts",
               {"finding_id": "G1-F1", "verdict": "FALSE_POSITIVE",
                "refuting_mechanism": "300-byte sliding-window flush"})
    assert "enabled_observation" in str(exc.value)


def test_a_true_positive_needs_neither(tmp_path):
    """The rule is about false positives. A true positive that carried the
    same requirement would make every verdict cost an observation."""
    con = fresh(tmp_path)
    db.put(con, "cba_fp_verdicts",
           {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})


def test_an_unknown_verdict_is_still_rejected(tmp_path):
    """The vocabulary check that one_of() used to do must survive its
    replacement -- this is the regression the swap can silently cause."""
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts",
               {"finding_id": "G1-F1", "verdict": "PROBABLY"})
    assert "PROBABLY" in str(exc.value)


def test_record_writes_the_observation_and_the_verdict_together(tmp_path):
    con = fresh(tmp_path)
    p = pivot.record(
        con, finding_id="G1-F1", group_id="G1",
        mechanism="300-byte sliding-window flush in recv_loop",
        enables="the flush itself takes an attacker-sized length at recv.c:214",
        reason="the copy is bounded by the window", rule_applied="HE-1")
    assert p.finding_id == "G1-F1"
    assert p.observation_id > 0

    verdict = db.rows(con, "cba_fp_verdicts", where={"finding_id": "G1-F1"})[0]
    assert verdict["verdict"] == "FALSE_POSITIVE"
    assert verdict["refuting_mechanism"].startswith("300-byte")
    assert verdict["enabled_observation"] == str(p.observation_id)

    obs = db.rows(con, "cba_security_observations",
                  where={"id": str(p.observation_id)})[0]
    assert "attacker-sized length" in obs["observation"]
    assert obs["group_id"] == "G1"


def test_record_refuses_a_finding_that_already_has_a_verdict(tmp_path):
    """Checked before anything is written. db.put commits, so an observation
    written ahead of a verdict that then fails would be orphaned."""
    con = fresh(tmp_path)
    db.put(con, "cba_fp_verdicts",
           {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})
    before = len(db.rows(con, "cba_security_observations"))
    with pytest.raises(db.DbError) as exc:
        pivot.record(con, finding_id="G1-F1", group_id="G1",
                     mechanism="m", enables="e")
    assert "--replace" in str(exc.value)
    assert len(db.rows(con, "cba_security_observations")) == before


def test_record_rejects_an_empty_mechanism_before_writing_anything(tmp_path):
    con = fresh(tmp_path)
    before = len(db.rows(con, "cba_security_observations"))
    with pytest.raises(db.DbError):
        pivot.record(con, finding_id="G1-F1", group_id="G1",
                     mechanism="   ", enables="e")
    assert len(db.rows(con, "cba_security_observations")) == before


def test_record_rejects_a_finding_that_does_not_exist(tmp_path):
    con = fresh(tmp_path)
    with pytest.raises(db.DbError) as exc:
        pivot.record(con, finding_id="G9-F9", group_id="G1",
                     mechanism="m", enables="e")
    assert "G9-F9" in str(exc.value)


def test_dangling_finds_a_verdict_whose_observation_was_deleted(tmp_path):
    con = fresh(tmp_path)
    p = pivot.record(con, finding_id="G1-F1", group_id="G1",
                     mechanism="m", enables="e")
    assert pivot.dangling(con) == []
    con.execute("DELETE FROM cba_security_observations WHERE id = ?",
                (p.observation_id,))
    con.commit()
    assert pivot.dangling(con) == [("G1-F1", str(p.observation_id))]
