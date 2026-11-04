"""Artifact-first atomic import of complete Stage 4i worker decisions."""
import copy
import hashlib
import json
import sqlite3

import pytest

from audit_core import firmware_decide_results as results
from tests.test_firmware_decide_results import (
    bench_id, canonical_json, decision_assignment, save,
)
from tests.test_firmware_dive_prepare import rows
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_hunt_gate import state


def decision_rows(con):
    return rows(con, "cba_firmware_decide_runs")


def test_record_installs_canonical_result_and_moves_exact_pending_row(decision_assignment):
    case, summary, _, body, path = decision_assignment
    con, run = case[:2]
    recorded = results.record(con, run, path)
    raw = canonical_json(body)
    assert recorded.image_id == "target"
    assert recorded.decision_generation == summary.decision_generation
    assert recorded.result_sha256 == hashlib.sha256(raw).hexdigest()
    assert recorded.chain_count == 1 and recorded.bench_test_count == 1
    assert recorded.script_count == 1 and recorded.recorded
    assert (run / recorded.result_path).read_bytes() == raw
    row = decision_rows(con)[0]
    assert row["status"] == "recorded"
    assert (row["result_path"], row["result_sha256"]) == (
        recorded.result_path, recorded.result_sha256)
    assert row["recorded_at"] and row["completed_at"] is None
    assert row["bench_test_count"] == row["script_count"] == row["policy_match_count"] == 0


def test_record_identical_is_zero_write_and_preserves_timestamp(decision_assignment):
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    first = results.record(con, run, path)
    before, changes = state(con), con.total_changes
    second = results.record(con, run, path)
    assert second == first
    assert state(con) == before and con.total_changes == changes and not con.in_transaction


def test_record_refuses_conflicting_result_after_recorded(decision_assignment):
    case, _, _, body, path = decision_assignment
    con, run = case[:2]
    first = results.record(con, run, path)
    body["answer"]["chain_assessments"][0]["rationale"] = "A different bounded worker rationale."
    save(path, body)
    before = state(con)
    with pytest.raises(results.FirmwareDecideResultError, match="conflict"):
        results.record(con, run, path)
    assert state(con) == before
    assert (run / first.result_path).read_bytes() != canonical_json(body)


def test_record_refuses_complete_assignment_even_when_result_is_identical(decision_assignment):
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    results.record(con, run, path)
    row = decision_rows(con)[0]
    con.execute(
        "UPDATE cba_firmware_decide_runs SET status='complete',"
        "package_path='artifacts/package.json',package_sha256=?,"
        "decision='pass',primary_reason='no-policy-match',"
        "reason_codes='[\"no-policy-match\"]',completed_at=recorded_at "
        "WHERE image_id='target'",
        ("b" * 64,))
    con.commit()
    before = state(con)
    with pytest.raises(results.FirmwareDecideResultError, match="pending"):
        results.record(con, run, path)
    assert state(con) == before and decision_rows(con)[0]["status"] == "complete"


@pytest.mark.parametrize("field,value", [
    ("image_id", "foreign"),
    ("decision_generation", "f" * 64),
    ("worklist_sha256", "e" * 64),
])
def test_record_refuses_foreign_assignment_ownership(decision_assignment, field, value):
    case, _, _, body, path = decision_assignment
    body[field] = value
    if field in ("decision_generation", "worklist_sha256"):
        body["decision_generation"] = value
        body["worklist_sha256"] = value
    save(path, body)
    before = state(case[0])
    with pytest.raises(results.FirmwareDecideResultError):
        results.record(case[0], case[1], path)
    assert state(case[0]) == before and not case[0].in_transaction


def test_record_rejects_installed_result_drift(decision_assignment):
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    summary = results.record(con, run, path)
    (run / summary.result_path).write_bytes(b"{}")
    before = state(con)
    with pytest.raises(results.FirmwareDecideResultError):
        results.record(con, run, path)
    assert state(con) == before


def test_record_rejects_symlink_parent_without_writing_outside(decision_assignment, tmp_path):
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    parent = run / "artifacts" / "firmware-decide-results"
    outside = tmp_path / "outside"
    outside.mkdir()
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(results.FirmwareDecideResultError):
        results.record(con, run, path)
    assert list(outside.iterdir()) == []
    assert decision_rows(con)[0]["status"] == "pending"


def test_record_rechecks_source_and_assignment_after_install(decision_assignment, monkeypatch):
    case, _, _, body, path = decision_assignment
    con, run = case[:2]
    original = results.dive._install
    def install_then_change(*args, **kwargs):
        original(*args, **kwargs)
        body["answer"]["chain_assessments"][0]["rationale"] = "Changed during publication."
        save(path, body)
    monkeypatch.setattr(results.dive, "_install", install_then_change)
    before = state(con)
    with pytest.raises(results.FirmwareDecideResultError, match="changed"):
        results.record(con, run, path)
    assert state(con) == before and not con.in_transaction


def test_record_rejects_assignment_worklist_drift(decision_assignment):
    case, summary, _, _, path = decision_assignment
    con, run = case[:2]
    (run / summary.worklist_path).write_bytes(b"{}\n")
    before = state(con)
    with pytest.raises(results.FirmwareDecideResultError):
        results.record(con, run, path)
    assert state(con) == before and decision_rows(con)[0]["status"] == "pending"


def test_record_preserves_sibling_row(decision_assignment):
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    con.execute(
        "INSERT INTO cba_firmware_decide_runs SELECT 'sibling',?,manifest_sha256,"
        "surface_snapshot_sha256,candidate_snapshot_sha256,chain_worklist_sha256,"
        "graph_path,graph_sha256,dive_generation,journal_path,journal_sha256,overlay_sha256,"
        "policy_id,policy_path,policy_sha256,worklist_path,?,status,result_path,result_sha256,"
        "package_path,package_sha256,decision,primary_reason,reason_codes,chain_count,"
        "bench_test_count,script_count,policy_match_count,prepared_at,recorded_at,completed_at "
        "FROM cba_firmware_decide_runs WHERE image_id='target'",
        ("c" * 64, "c" * 64))
    con.commit()
    sibling = dict(con.execute(
        "SELECT * FROM cba_firmware_decide_runs WHERE image_id='sibling'").fetchone())
    results.record(con, run, path)
    assert dict(con.execute(
        "SELECT * FROM cba_firmware_decide_runs WHERE image_id='sibling'").fetchone()) == sibling
    assert con.execute("SELECT count(*) FROM cba_firmware_decide_runs").fetchone()[0] == 2


def test_record_rolls_back_commit_failure(decision_assignment):
    case, _, _, _, path = decision_assignment
    owner, run = case[:2]
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")
    con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    con.row_factory = sqlite3.Row
    before = state(owner)
    try:
        with pytest.raises(results.FirmwareDecideResultError, match="database operation failed"):
            results.record(con, run, path)
        assert state(owner) == before and not con.in_transaction
    finally:
        con.close()


def test_record_write_lock_failure_preserves_sql(decision_assignment):
    case, _, _, _, path = decision_assignment
    owner, run = case[:2]
    reader = sqlite3.connect(run / "audit.db", timeout=0.025)
    reader.row_factory = sqlite3.Row
    before = state(owner)
    owner.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(results.FirmwareDecideResultError, match="database operation failed"):
            results.record(reader, run, path)
        assert state(owner) == before and owner.in_transaction and not reader.in_transaction
    finally:
        owner.rollback()
        reader.close()
