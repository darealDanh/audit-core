"""Artifact-first, immutable Stage 4i decision preparation."""
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import firmware_decide as decide
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_policy import POLICY, RAW, write_policy
from tests.test_firmware_dive_prepare import rows
from tests.test_hunt_gate import state


def test_prepare_freezes_exact_policy_graph_dive_and_open_denominator(decision_case, tmp_path):
    case, _, dive_summary, graph = decision_case
    con, run, root = case[:3]
    policy = write_policy(tmp_path)
    summary = decide.prepare(con, run, root, policy, image_id="target")
    worklist_path = run / summary.worklist_path
    policy_path = run / summary.policy_path
    worklist_raw = worklist_path.read_bytes()
    body = json.loads(worklist_raw)

    assert summary.image_id == "target"
    assert summary.decision_generation == summary.worklist_sha256 == hashlib.sha256(worklist_raw).hexdigest()
    assert summary.graph_sha256 == graph.graph_sha256
    assert summary.dive_generation == dive_summary.dive_generation
    assert summary.overlay_sha256 == dive_summary.overlay_sha256
    assert summary.policy_id == POLICY["policy_id"]
    assert summary.policy_sha256 == hashlib.sha256(RAW).hexdigest()
    assert policy_path.read_bytes() == RAW
    assert summary.chain_count == len(graph.chains) == 1
    assert summary.open_precondition_count == len(body["open_preconditions"]) == 2
    assert body["schema_version"] == 1 and body["image_id"] == "target"
    assert body["technical_provenance"]["graph_sha256"] == graph.graph_sha256
    assert body["dive"]["journal_sha256"] == dive_summary.journal_sha256
    assert body["dive"]["overlay_sha256"] == dive_summary.overlay_sha256
    assert body["policy"] == {
        "path": "policy.json", "policy_id": POLICY["policy_id"],
        "projection": POLICY, "sha256": summary.policy_sha256,
    }
    chain_id = graph.chains[0].chain_id
    blocker = graph.blockers[0]
    assert body["open_preconditions"] == [
        {
            "kind": "blocker",
            "precondition_id": f"blocker:{blocker.blocker_id}",
            "source_id": blocker.blocker_id,
            "question": "Does the script persist?",
            "settling_observation": "Observe persistent startup bytes",
            "method": "static",
            "axes": ["lifecycle"],
            "locations": [{"chain_id": chain_id, "edge_ordinal": None},
                          {"chain_id": chain_id, "edge_ordinal": 0}],
        },
        {
            "kind": "unknown",
            "precondition_id": "unknown:overlap",
            "source_id": "overlap",
            "question": "Which authority?",
            "settling_observation": "Inspect handler authority",
            "method": "static",
            "axes": ["authentication"],
            "locations": [{"chain_id": chain_id, "edge_ordinal": None},
                          {"chain_id": chain_id, "edge_ordinal": 1}],
        },
    ]
    assert worklist_raw == (json.dumps(body, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")) + "\n").encode()

    stored = rows(con, "cba_firmware_decide_runs")
    assert len(stored) == 1
    row = stored[0]
    for key in ("image_id", "decision_generation", "graph_sha256", "dive_generation",
                "overlay_sha256", "policy_id", "policy_path", "policy_sha256",
                "worklist_path", "worklist_sha256", "chain_count"):
        assert row[key] == getattr(summary, key)
    assert row["status"] == "pending" and row["prepared_at"]


def test_prepare_identical_is_zero_write_and_preserves_timestamp(decision_case, tmp_path):
    case = decision_case[0]
    con, run, root = case[:3]
    policy = write_policy(tmp_path)
    first = decide.prepare(con, run, root, policy, image_id="target")
    before, changes = state(con), con.total_changes
    second = decide.prepare(con, run, root, policy, image_id="target")
    assert second == first
    assert state(con) == before and con.total_changes == changes and not con.in_transaction


def test_prepare_preserves_identical_generation_published_during_install(
        decision_case, tmp_path, monkeypatch):
    con, run, root = decision_case[0][:3]
    policy = write_policy(tmp_path)
    original = decide.firmware_dive._install
    winner = {}
    def install_then_publish(*args, **kwargs):
        original(*args, **kwargs)
        monkeypatch.setattr(decide.firmware_dive, "_install", original)
        winner["summary"] = decide.prepare(con, run, root, policy, image_id="target")
        winner["state"], winner["changes"] = state(con), con.total_changes
    monkeypatch.setattr(decide.firmware_dive, "_install", install_then_publish)
    actual = decide.prepare(con, run, root, policy, image_id="target")
    assert actual == winner["summary"]
    assert state(con) == winner["state"] and con.total_changes == winner["changes"]
    assert not con.in_transaction


def test_prepare_refuses_changed_policy_while_generation_is_active(decision_case, tmp_path):
    case = decision_case[0]
    con, run, root = case[:3]
    decide.prepare(con, run, root, write_policy(tmp_path), image_id="target")
    changed = dict(POLICY)
    changed["policy_id"] = "operator-2026-12"
    changed_raw = (json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n").encode()
    changed_path = tmp_path / "changed.json"
    changed_path.write_bytes(changed_raw)
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError, match="active"):
        decide.prepare(con, run, root, changed_path, image_id="target")
    assert state(con) == before and len(rows(con, "cba_firmware_decide_runs")) == 1


def test_prepare_rejects_installed_drift_and_symlink_parent(decision_case, tmp_path):
    case = decision_case[0]
    con, run, root = case[:3]
    policy = write_policy(tmp_path)
    summary = decide.prepare(con, run, root, policy, image_id="target")
    (run / summary.worklist_path).write_bytes(b"{}")
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError):
        decide.prepare(con, run, root, policy, image_id="target")
    assert state(con) == before


def test_prepare_changed_policy_creates_new_generation_after_completed_history(decision_case, tmp_path):
    case = decision_case[0]
    con, run, root = case[:3]
    first = decide.prepare(con, run, root, write_policy(tmp_path), image_id="target")
    row = rows(con, "cba_firmware_decide_runs")[0]
    con.execute(
        "UPDATE cba_firmware_decide_runs SET status='complete',"
        "result_path='artifacts/result.json',result_sha256=?,"
        "package_path='artifacts/package.json',package_sha256=?,"
        "decision='pass',primary_reason='no-policy-match',"
        "reason_codes='[\"no-policy-match\"]',recorded_at=?,completed_at=? "
        "WHERE image_id='target' AND decision_generation=?",
        ("a" * 64, "b" * 64, row["prepared_at"], row["prepared_at"],
         first.decision_generation))
    con.commit()
    changed = dict(POLICY)
    changed["policy_id"] = "operator-2026-12"
    changed_path = tmp_path / "changed-after-complete.json"
    changed_path.write_bytes(
        (json.dumps(changed, sort_keys=True, separators=(",", ":")) + "\n").encode())
    second = decide.prepare(con, run, root, changed_path, image_id="target")
    history = rows(con, "cba_firmware_decide_runs")
    assert second.decision_generation != first.decision_generation
    assert len(history) == 2
    assert {item["status"] for item in history} == {"complete", "pending"}
    assert next(item for item in history if item["status"] == "complete")[
        "decision_generation"] == first.decision_generation




def test_prepare_rejects_symlink_parent_before_writing_outside(decision_case, tmp_path):
    case = decision_case[0]
    con, run, root = case[:3]
    parent = run / "files" / "firmware-decide"
    outside = tmp_path / "outside"
    outside.mkdir()
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(decide.FirmwareDecideError):
        decide.prepare(con, run, root, write_policy(tmp_path), image_id="target")
    assert list(outside.iterdir()) == [] and rows(con, "cba_firmware_decide_runs") == []


def test_prepare_rechecks_policy_after_install(decision_case, tmp_path, monkeypatch):
    case = decision_case[0]
    con, run, root = case[:3]
    policy = write_policy(tmp_path)
    original = decide.firmware_dive._install
    def install_then_change(*args, **kwargs):
        original(*args, **kwargs)
        policy.write_bytes(b"{}\n")
    monkeypatch.setattr(decide.firmware_dive, "_install", install_then_change)
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError):
        decide.prepare(con, run, root, policy, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_rolls_back_commit_failure(decision_case, tmp_path):
    case = decision_case[0]
    source, run, root = case[:3]
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")
    con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    con.row_factory = sqlite3.Row
    before = state(source)
    try:
        with pytest.raises(decide.FirmwareDecideError, match="database operation failed"):
            decide.prepare(con, run, root, write_policy(tmp_path), image_id="target")
        assert state(source) == before and not con.in_transaction
    finally:
        con.close()


def test_prepare_write_lock_failure_preserves_sql(decision_case, tmp_path):
    case = decision_case[0]
    owner, run, root = case[:3]
    reader = sqlite3.connect(run / "audit.db", timeout=0.025)
    reader.row_factory = sqlite3.Row
    before = state(owner)
    owner.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(decide.FirmwareDecideError, match="database operation failed"):
            decide.prepare(reader, run, root, write_policy(tmp_path), image_id="target")
        assert state(owner) == before and owner.in_transaction and not reader.in_transaction
    finally:
        owner.rollback()
        reader.close()
