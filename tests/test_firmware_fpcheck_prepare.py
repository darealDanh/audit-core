"""Stage 4f consumes a complete, immutable and read-only Stage 4e snapshot."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, hunt, hunt_results
from tests.test_hunt_gate import fill, state
from tests.test_hunt_results import candidate, prepared  # noqa: F401


@pytest.fixture
def completed(prepared, tmp_path):
    con, run, payload, _, summary = prepared
    fill(con, run, summary, example=candidate(payload))
    # The same identifier belongs independently to the opposite lane.
    dark = copy.deepcopy(payload)
    dark_lane = summary.lanes[1]
    descriptor = json.loads(pathlib.Path(dark_lane.worklist_path).read_bytes())["batches"][0]
    dark.update(lane="l-dark", worklist_sha256=dark_lane.worklist_sha256,
                batch_sha256=descriptor["sha256"])
    candidate(dark)["dangerous_operation"] = "OTA trust boundary"
    path = run / "dark-result.json"
    path.write_text(json.dumps(dark), encoding="utf-8")
    hunt_results.record(con, run, path, replace=True)
    root = tmp_path / "root"
    for lane in db.HUNT_LANES:
        hunt.check(con, run, root, lane=lane)
    return con, run, root, summary, payload, dark


def test_snapshot_preserves_all_evidence_lane_identity_and_immutable_nested_records(completed):
    # Breaks: dropped candidate fields, mutable nested evidence, cross-lane ID collapse,
    # trusting stored JSON strings, or writing status/timestamps during a read.
    con, run, root, summary, sink, dark = completed
    before, writes = state(con), con.total_changes
    snapshot = hunt.verified_snapshot(con, run, root)
    assert isinstance(snapshot, hunt.VerifiedHuntSnapshot)
    assert (snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256) == (
        "target", summary.manifest_sha256, summary.surface_snapshot_sha256)
    assert snapshot.lanes == tuple(hunt.VerifiedHuntLane(
        lane.lane, lane.worklist_path, lane.worklist_sha256, 4, 2) for lane in summary.lanes)
    assert tuple((row.lane, row.candidate_id) for row in snapshot.candidates) == (
        ("l-sink", "shell-1"), ("l-dark", "shell-1"))
    for row, payload in zip(snapshot.candidates, (sink, dark)):
        receipt = con.execute("SELECT * FROM cba_hunt_receipts WHERE lane=? AND batch_path='batch-0001.json'",
                              (row.lane,)).fetchone()
        artifact = pathlib.Path(receipt["result_path"])
        expected = copy.deepcopy(candidate(payload)) | {
            "lane": row.lane, "surface_ids": ("http-c",),
            "blockers": ({"id": "shell-context", "question": "Which UID runs the daemon?",
                "settling_observation": "Inspect daemon UID after provisioning.", "method": "hardware"},),
            "artifact_path": artifact.relative_to(run).as_posix(),
            "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
        assert isinstance(row, hunt.VerifiedHuntCandidate)
        assert isinstance(row.blockers[0], hunt.VerifiedHuntBlocker)
        assert dataclasses.asdict(row) == expected
    for record in (snapshot, *snapshot.lanes, *snapshot.candidates, snapshot.candidates[0].blockers[0]):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, "changed")
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("completed_lanes", [(), ("l-sink",)])
def test_snapshot_refuses_pending_lanes_without_promoting_them(prepared, tmp_path, completed_lanes):
    con, run, _, _, summary = prepared
    fill(con, run, summary)
    root = tmp_path / "root"
    for lane in completed_lanes:
        hunt.check(con, run, root, lane=lane)
    before, writes = state(con), con.total_changes
    with pytest.raises(hunt.HuntError, match="complete"):
        hunt.verified_snapshot(con, run, root)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("damage", ["pending", "orphan-timestamp", "missing-timestamp", "foreign-image",
    "outside-artifact", "symlink-directory", "symlink-artifact"])
def test_snapshot_rejects_status_ownership_and_escaping_artifacts(completed, tmp_path, damage):
    con, run, root, _, _, _ = completed
    if damage == "pending":
        con.execute("UPDATE cba_hunt_runs SET status='pending',completed_at=NULL WHERE lane='l-dark'")
    elif damage == "orphan-timestamp":
        con.execute("UPDATE cba_hunt_runs SET status='pending' WHERE lane='l-dark'")
    elif damage == "missing-timestamp":
        con.execute("UPDATE cba_hunt_runs SET completed_at=NULL WHERE lane='l-dark'")
    elif damage == "foreign-image":
        con.execute("UPDATE cba_hunt_runs SET image_id='foreign' WHERE lane='l-dark'")
    else:
        receipt = con.execute("SELECT * FROM cba_hunt_receipts WHERE lane='l-sink' AND batch_path='batch-0001.json'").fetchone()
        artifact = pathlib.Path(receipt["result_path"])
        if damage == "outside-artifact":
            outside = tmp_path / "outside.json"
            outside.write_bytes(artifact.read_bytes())
            con.execute("UPDATE cba_hunt_receipts SET result_path=? WHERE result_path=?", (str(outside), str(artifact)))
            con.execute("UPDATE cba_hunt_candidates SET artifact_path=? WHERE artifact_path=?", (str(outside), str(artifact)))
        elif damage == "symlink-directory":
            outside = tmp_path / "outside"
            artifact.parent.rename(outside)
            artifact.parent.symlink_to(outside, target_is_directory=True)
        else:
            outside = tmp_path / "outside.json"
            artifact.rename(outside)
            artifact.symlink_to(outside)
    con.commit()
    before, writes = state(con), con.total_changes
    with pytest.raises(hunt.HuntError):
        hunt.verified_snapshot(con, run, root)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


def test_snapshot_works_on_read_only_sqlite_and_inside_caller_transaction(completed):
    con, run, root, *_ = completed
    with sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert len(hunt.verified_snapshot(readonly, run, root).candidates) == 2
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute("UPDATE cba_hunt_runs SET completed_at='caller-owned'")
    before, writes = state(con), con.total_changes
    assert len(hunt.verified_snapshot(con, run, root).candidates) == 2
    assert con.in_transaction and state(con) == before and con.total_changes == writes
    con.rollback()


def test_snapshot_normalizes_artifacts_with_relative_run_spelling(completed, tmp_path, monkeypatch):
    con, run, root, *_ = completed
    monkeypatch.chdir(tmp_path)
    first = hunt.verified_snapshot(con, run, root)
    assert hunt.verified_snapshot(con, run.relative_to(tmp_path), root) == first
    assert all(row.artifact_path.startswith("artifacts/hunt/") for row in first.candidates)


def test_snapshot_closed_database_is_a_domain_error(completed):
    con, run, root, *_ = completed
    con.close()
    with pytest.raises(hunt.HuntError):
        hunt.verified_snapshot(con, run, root)
