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


def test_dangling_renders_a_null_enabled_observation_as_unset_not_the_word_none(tmp_path):
    """A legacy FALSE_POSITIVE row written by raw SQL can have
    enabled_observation IS NULL. str(None) would print the literal text
    'None', which is ambiguous with a stored string "None" -- render it
    distinguishably instead."""
    con = fresh(tmp_path)
    con.execute(
        "INSERT INTO cba_fp_verdicts (finding_id, verdict, refuting_mechanism) "
        "VALUES (?, 'FALSE_POSITIVE', 'legacy raw-sql row')", ("G1-F1",))
    con.commit()
    assert pivot.dangling(con) == [("G1-F1", "(unset)")]


def test_replace_keeps_the_columns_a_different_step_owns(tmp_path):
    """CRITICAL. `INSERT OR REPLACE` deletes the whole row, and `pivot.record`
    writes 6 of `cba_fp_verdicts`' 10 columns. The other four are written by
    `workflows/fpcheck.md`, which assigns `final_id` by a raw UPDATE *after*
    the verdicts exist -- so `pivot --replace` destroyed the report's finding
    numbering, which exists nowhere else, at exit 0 with no warning and with
    neither `status` nor `pivot --check` noticing.

    The fix is in `db.put`, not here: every `--replace` caller has the hazard.
    """
    con = fresh(tmp_path)
    pivot.record(con, finding_id="G1-F1", group_id="G1",
                 mechanism="300-byte sliding-window flush",
                 enables="the flush is reachable from the parser",
                 reason="bounded by the window")
    # fpcheck's own step, verbatim in shape: a raw UPDATE after the verdict.
    con.execute("UPDATE cba_fp_verdicts SET final_id = 'F-3', "
                "merged_into = 'G2-F9', final_severity = 'HIGH' "
                "WHERE finding_id = 'G1-F1'")
    con.commit()

    pivot.record(con, finding_id="G1-F1", group_id="G1",
                 mechanism="300-byte sliding-window flush, re-reviewed",
                 enables="still reachable from the parser", replace=True)

    row = db.rows(con, "cba_fp_verdicts", where={"finding_id": "G1-F1"})[0]
    assert row["final_id"] == "F-3"
    assert row["merged_into"] == "G2-F9"
    assert row["final_severity"] == "HIGH"
    # The caller's own columns still win.
    assert row["refuting_mechanism"].endswith("re-reviewed")
    # And a column the caller dropped from a row it had previously written
    # keeps its stored value too, rather than silently blanking.
    assert row["reason"] == "bounded by the window"
    con.close()


def test_replace_keeps_the_timestamp_a_full_row_rewrite_would_reset(tmp_path):
    """`cmd_chain` and `cmd_identify` pass every user-facing column, so the
    only thing their `--replace` destroyed was `created_at`/`recorded_at` --
    the record of when the row was first written. The merge fixes those too."""
    con = fresh(tmp_path)
    db.put(con, "cba_components", {
        "path": "images/km0_boot_0C000020.elf", "kind": "binary",
        "asserted_identity": "Realtek RTL8710 Wi-Fi driver image",
        "identity_evidence": "contains 'rtl8710 wlan firmware' at 0x0C00A120"})
    con.execute("UPDATE cba_components SET recorded_at = '2026-01-01 00:00:00'")
    con.commit()
    db.put(con, "cba_components", {
        "path": "images/km0_boot_0C000020.elf", "kind": "binary",
        "asserted_identity": "Realtek RTL8710 Wi-Fi driver image, v2",
        "identity_evidence": "contains 'rtl8710 wlan firmware' at 0x0C00A120"},
        replace=True)
    row = db.rows(con, "cba_components")[0]
    assert row["recorded_at"] == "2026-01-01 00:00:00"
    assert row["asserted_identity"].endswith("v2")
    con.close()


def test_replace_of_a_row_that_is_not_there_is_still_an_insert(tmp_path):
    """The merge must not turn `--replace` into "requires an existing row"."""
    con = fresh(tmp_path)
    db.put(con, "cba_fp_verdicts",
           {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"}, replace=True)
    assert db.rows(con, "cba_fp_verdicts")[0]["verdict"] == "TRUE_POSITIVE"
    con.close()


def test_dangling_states_a_cap_like_every_other_read_path(tmp_path, monkeypatch):
    """R1: the orchestrator reads rows, never raw material. This was the one
    new read path that stated no bound at all."""
    con = fresh(tmp_path)
    for i in range(2, 8):
        db.put(con, "cba_findings", {
            "id": f"G1-F{i}", "group_id": "G1", "title": "t",
            "severity": "HIGH", "confidence": "9", "location": "src/a.c:1",
            "root_cause": "rc", "impact": "im"})
        db.put(con, "cba_fp_verdicts", {
            "finding_id": f"G1-F{i}", "verdict": "FALSE_POSITIVE",
            "refuting_mechanism": "m", "enabled_observation": "9999"})
    monkeypatch.setattr(db, "MAX_ROWS", 4)
    assert len(pivot.dangling(con)) == 4
    con.close()
