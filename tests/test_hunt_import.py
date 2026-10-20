"""Batch receipts own atomic, image-qualified publication in independent lanes."""
import copy
import dataclasses
import hashlib
import json
import os
import pathlib
import sqlite3

import pytest

from audit_core import db, hunt, hunt_results, surface
from tests.test_hunt_prepare import add_target
from tests.test_hunt_results import candidate, dark_payload, prepared  # noqa: F401


def sql_state(con):
    return {table: sorted([tuple(row) for row in con.execute(f"SELECT * FROM {table}")], key=repr)
            for table in db.TABLE_SPECS}


def record(prepared, payload=None, *, replace=False, connection=None):
    con, run, default, *_ = prepared
    path = run / "hunt-result.json"
    path.write_text(json.dumps(default if payload is None else payload), encoding="utf-8")
    return hunt_results.record(connection or con, run, path, replace=replace)


def rows(con, table):
    return [dict(row) for row in con.execute(f"SELECT * FROM {table}")]


def complete(con):
    con.execute("UPDATE cba_hunt_runs SET status='complete',completed_at='retained'")
    con.commit()


def sibling(prepared):
    payload = copy.deepcopy(prepared[2])
    index = json.loads(pathlib.Path(prepared[4].lanes[0].worklist_path).read_bytes())
    payload.update(batch_path="batch-0002.json", batch_sha256=index["batches"][1]["sha256"],
        decisions=[{"path": "d", "disposition": "analyzed", "reason": None,
                    "candidates": [candidate(payload) | {"candidate_id": "sibling", "component_path": "d",
                        "surface_ids": [], "surface_context": "Unmapped parser at d:10."}]}])
    return payload


def test_first_import_installs_canonical_receipt_coverage_and_exact_candidate(prepared):
    # Breaks: missing receipts, worker-supplied provenance, lost evidence, or shared lane status.
    con, run, _, canonical, preparation = prepared
    complete(con)
    result = record(prepared)
    digest = hashlib.sha256(canonical).hexdigest()
    artifact = run / "artifacts/hunt" / preparation.generation / "l-sink" / digest / "result.json"
    assert result == hunt_results.ImportSummary("target", "l-sink", "batch-0001.json", 3, 1, 1, str(artifact))
    assert artifact.read_bytes() == canonical
    receipt = rows(con, "cba_hunt_receipts")[0]
    assert receipt.pop("recorded_at")
    assert receipt == {"image_id": "target", "lane": "l-sink", "worklist_sha256": preparation.lanes[0].worklist_sha256,
        "batch_path": "batch-0001.json", "batch_sha256": prepared[2]["batch_sha256"],
        "result_path": str(artifact), "result_sha256": digest, "unit_count": 3, "candidate_count": 1}
    coverage = [row for row in rows(con, "cba_coverage") if row["phase"].startswith("hunt")]
    assert {(row["unit"], row["phase"], row["state"], row["reason"]) for row in coverage} == {
        ("/firmware/6:target:a", "hunt-l-sink", "analyzed", "No attacker input reaches an operation."),
        ("/firmware/6:target:b", "hunt-l-sink", "analyzed", "Read-only data contains no executable instructions."),
        ("/firmware/6:target:c", "hunt-l-sink", "analyzed", None)}
    stored = rows(con, "cba_hunt_candidates")[0]
    assert stored.pop("recorded_at")
    expected = copy.deepcopy(candidate(prepared[2]))
    expected["surface_ids"] = '["http-c"]'
    expected["blockers"] = '[{"id":"shell-context","method":"hardware","question":"Which UID runs the daemon?","settling_observation":"Inspect daemon UID after provisioning."}]'
    assert stored == expected | {"image_id": "target", "lane": "l-sink", "artifact_path": str(artifact), "artifact_sha256": digest}
    assert [(row["lane"], row["status"], row["completed_at"]) for row in rows(con, "cba_hunt_runs")] == [
        ("l-sink", "pending", None), ("l-dark", "complete", "retained")]
    assert not con.in_transaction


def test_candidate_free_batch_has_a_durable_receipt(prepared):
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][2].update(candidates=[], reason="No surviving path after guard review.")
    result = record(prepared, payload)
    assert (result.candidate_count, result.blocker_count) == (0, 0)
    assert len(rows(prepared[0], "cba_hunt_receipts")) == 1
    assert rows(prepared[0], "cba_hunt_receipts")[0]["candidate_count"] == 0
    assert not rows(prepared[0], "cba_hunt_candidates")
    assert pathlib.Path(result.artifact_path).is_file()


@pytest.mark.parametrize("candidate_free", [False, True])
def test_duplicate_refuses_without_replacement_even_without_candidates(prepared, candidate_free):
    payload = copy.deepcopy(prepared[2])
    if candidate_free:
        payload["decisions"][2].update(candidates=[], reason="No surviving path.")
    record(prepared, payload)
    before = sql_state(prepared[0])
    with pytest.raises(hunt.HuntError, match="replace"):
        record(prepared, payload)
    assert sql_state(prepared[0]) == before


def test_same_raw_paths_and_candidate_ids_remain_independent_across_images_and_lanes(prepared, tmp_path):
    con, run, payload, *_ = prepared
    record(prepared)
    dark = dark_payload((*prepared[:2], copy.deepcopy(payload), *prepared[3:]))
    candidate(dark).update(dangerous_operation="OTA trust boundary")
    record(prepared, dark)
    image = "other:图像"
    add_target(con, run, tmp_path / "other-root", ["a", "b", "c", "d"], image_id=image)
    preparation = hunt.prepare(con, run, tmp_path / "other-root", image_id=image, sink_batch_size=3, dark_batch_size=3)
    for lane in preparation.lanes:
        other = copy.deepcopy(payload)
        descriptor = json.loads(pathlib.Path(lane.worklist_path).read_bytes())["batches"][0]
        other.update(image_id=image, lane=lane.lane, manifest_sha256=preparation.manifest_sha256,
            surface_snapshot_sha256=preparation.surface_snapshot_sha256,
            worklist_sha256=lane.worklist_sha256, batch_sha256=descriptor["sha256"])
        candidate(other).update(surface_ids=[], surface_context="Unmapped input at c:10.")
        if lane.lane == "l-dark":
            candidate(other)["dangerous_operation"] = "OTA trust boundary"
        record(prepared, other)
    assert {(row["image_id"], row["lane"]) for row in rows(con, "cba_hunt_receipts")} == {
        (image, lane) for image in ("target", "other:图像") for lane in ("l-sink", "l-dark")}
    assert len(rows(con, "cba_hunt_candidates")) == 4
    assert len([row for row in rows(con, "cba_coverage") if row["phase"].startswith("hunt")]) == 12
    complete(con)
    before = sql_state(con)
    candidate(payload)["candidate_id"] = "replacement"
    record(prepared, payload, replace=True)
    after = sql_state(con)
    for table in ("cba_hunt_receipts", "cba_hunt_candidates", "cba_hunt_runs"):
        columns = db.table_columns(con, table)
        image_column, lane_column = columns.index("image_id"), columns.index("lane")
        keep = lambda row: row[image_column] != "target" or row[lane_column] != "l-sink"
        assert list(filter(keep, after[table])) == list(filter(keep, before[table]))


def test_replacement_is_batch_scoped_and_removes_old_candidate_claims(prepared):
    con = prepared[0]
    record(prepared, sibling(prepared))
    original = record(prepared)
    complete(con)
    before = rows(con, "cba_hunt_receipts")
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][2].update(candidates=[], reason="Bounds check blocks the traced path.")
    replaced = record(prepared, payload, replace=True)
    assert replaced.artifact_path != original.artifact_path
    assert pathlib.Path(original.artifact_path).is_file()
    assert [row["candidate_id"] for row in rows(con, "cba_hunt_candidates")] == ["sibling"]
    receipts = rows(con, "cba_hunt_receipts")
    assert len(receipts) == 2
    assert next(row for row in receipts if row["batch_path"] == "batch-0002.json") == before[0]
    assert next(row for row in receipts if row["batch_path"] == "batch-0001.json")["candidate_count"] == 0
    assert len([row for row in rows(con, "cba_coverage") if row["phase"] == "hunt-l-sink"]) == 4


def test_candidate_collision_with_sibling_batch_refuses_and_preserves_prior_sql(prepared):
    record(prepared, sibling(prepared))
    payload = copy.deepcopy(prepared[2])
    candidate(payload)["candidate_id"] = "sibling"
    before = sql_state(prepared[0])
    with pytest.raises(hunt.HuntError):
        record(prepared, payload, replace=True)
    assert sql_state(prepared[0]) == before


@pytest.mark.parametrize("phase", ["hunt", "hunt-l-sink", "hunt-l-dark"])
@pytest.mark.parametrize("replace", [False, True])
def test_ambiguous_legacy_raw_coverage_is_refused_and_preserved(prepared, phase, replace):
    con, run, *_ = prepared
    db.put(con, "cba_coverage", {"unit": "a", "phase": phase, "state": "analyzed"})
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="[Ll]egacy|[Uu]nqualified|[Aa]mbiguous"):
        record(prepared, replace=replace)
    assert sql_state(con) == before
    assert not (run / "artifacts/hunt").exists()


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("failure", ["read", "mkdir", "write", "rename", "receipt", "coverage", "candidate", "commit", "unexpected"])
def test_failed_import_preserves_exact_prior_sql(prepared, monkeypatch, replace, failure):
    # Breaks: artifact-last publication, early commits, or incomplete rollback after any write.
    con, run, payload, *_ = prepared
    record(prepared, sibling(prepared))
    if replace:
        record(prepared)
    complete(con)
    payload = copy.deepcopy(payload)
    candidate(payload)["title"] = "Changed hypothesis"
    path = run / "hunt-result.json"
    path.write_text(json.dumps(payload))
    old_files = {p: p.read_bytes() for p in (run / "artifacts/hunt").rglob("result.json")}
    before = sql_state(con)
    connection = con
    if failure == "read":
        class ReadFailure(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if "FROM cba_hunt_receipts" in sql:
                    raise sqlite3.OperationalError("injected read")
                return super().execute(sql, *args, **kwargs)
        connection = sqlite3.connect(run / "audit.db", factory=ReadFailure)
        connection.row_factory = sqlite3.Row
    elif failure in ("mkdir", "write", "rename"):
        def fail(*args, **kwargs):
            raise OSError("injected install")
        if failure == "rename":
            monkeypatch.setattr(os, "replace", fail)
        else:
            monkeypatch.setattr(pathlib.Path, "mkdir" if failure == "mkdir" else "write_bytes", fail)
    elif failure in ("receipt", "coverage", "candidate"):
        table = {"receipt": "cba_hunt_receipts", "coverage": "cba_coverage", "candidate": "cba_hunt_candidates"}[failure]
        con.execute(f"CREATE TRIGGER refuse_import BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected SQL'); END")
        con.commit()
    elif failure == "commit":
        class CommitFailure(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError("injected commit")
        connection = sqlite3.connect(run / "audit.db", factory=CommitFailure)
        connection.row_factory = sqlite3.Row
    else:
        original = db.put
        def fail_after_write(connection, table, row, **kwargs):
            original(connection, table, row, **kwargs)
            if table == "cba_hunt_candidates":
                raise RuntimeError("injected unexpected")
        monkeypatch.setattr(db, "put", fail_after_write)
    try:
        with pytest.raises(RuntimeError if failure == "unexpected" else hunt.HuntError):
            hunt_results.record(connection, run, path, replace=replace)
        assert sql_state(con) == before
        assert not connection.in_transaction
        current_files = {p: p.read_bytes() for p in (run / "artifacts/hunt").rglob("result.json")}
        assert all(current_files[path] == content for path, content in old_files.items())
        extras = set(current_files) - set(old_files)
        assert len(extras) == (1 if failure in ("receipt", "coverage", "candidate", "commit", "unexpected") else 0)
        for artifact in extras:
            assert artifact.parent.name == hashlib.sha256(current_files[artifact]).hexdigest()
            assert not con.execute("SELECT 1 FROM cba_hunt_receipts WHERE result_path=?", (str(artifact),)).fetchone()
    finally:
        if connection is not con:
            connection.close()


@pytest.mark.parametrize("change", ["worklist", "surface", "batch", "legacy", "duplicate", "artifact"])
def test_concurrent_change_after_install_is_rechecked_under_publication_lock(prepared, monkeypatch, change):
    # Breaks: publication from a snapshot validated before a concurrent writer.
    con, run, payload, *_ = prepared
    original = surface.atomic_install
    concurrent = {}
    def install_and_change(destination, files):
        original(destination, files)
        with db.connect(run / "audit.db") as other:
            if change == "worklist":
                other.execute("UPDATE cba_hunt_runs SET worklist_sha256=? WHERE lane='l-sink'", ("b" * 64,))
            elif change == "surface":
                other.execute("UPDATE cba_surface_runs SET status='pending',completed_at=NULL")
            elif change == "legacy":
                db.put(other, "cba_coverage", {"unit": "a", "phase": "hunt", "state": "analyzed"})
            elif change == "duplicate":
                db.put(other, "cba_hunt_receipts", {"image_id": "target", "lane": "l-sink",
                    "worklist_sha256": payload["worklist_sha256"], "batch_path": payload["batch_path"],
                    "batch_sha256": payload["batch_sha256"], "result_path": str(destination / "result.json"),
                    "result_sha256": destination.name, "unit_count": "3", "candidate_count": "1"})
            elif change == "batch":
                pathlib.Path(prepared[4].lanes[0].worklist_path).with_name("batch-0001.json").write_text("{}")
            else:
                (destination / "result.json").write_text("{}")
            other.commit()
            concurrent.update(sql_state(other))
    monkeypatch.setattr(surface, "atomic_install", install_and_change)
    with pytest.raises(hunt.HuntError):
        record(prepared)
    assert sql_state(con) == concurrent
    assert not con.in_transaction


def test_caller_transaction_is_preserved(prepared):
    con = prepared[0]
    con.execute("UPDATE cba_hunt_runs SET completed_at='caller-owned'")
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="active transaction"):
        record(prepared)
    assert con.in_transaction
    assert sql_state(con) == before
    assert not (prepared[1] / "artifacts/hunt").exists()


def test_invalid_result_is_rejected_before_installation(prepared):
    before = sql_state(prepared[0])
    payload = prepared[2] | {"batch_sha256": "f" * 64}
    with pytest.raises(hunt.HuntError):
        record(prepared, payload)
    assert sql_state(prepared[0]) == before
    assert not (prepared[1] / "artifacts/hunt").exists()


def test_import_rejects_extra_installed_worklist_artifacts_without_publication(prepared):
    con, run, payload, *_ = prepared
    index = pathlib.Path(prepared[4].lanes[0].worklist_path)
    (index.parent / "unexpected.json").write_text("{}")
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="different artifacts"):
        record(prepared)
    assert sql_state(con) == before
    assert not (run / "artifacts/hunt").exists()


def test_replacement_rejects_existing_receipt_with_different_batch_owner(prepared):
    con = prepared[0]
    record(prepared)
    con.execute("UPDATE cba_hunt_receipts SET batch_sha256=? WHERE lane='l-sink'", ("f" * 64,))
    con.commit()
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="different batch ownership"):
        record(prepared, replace=True)
    assert sql_state(con) == before


def test_replacement_refuses_hunt_claims_without_their_batch_receipt(prepared):
    con = prepared[0]
    record(prepared)
    con.execute("DELETE FROM cba_hunt_receipts WHERE lane='l-sink'")
    con.commit()
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="no owning batch receipt"):
        record(prepared, replace=True)
    assert sql_state(con) == before


def test_publication_rolls_back_when_result_changes_inside_sql_transaction(prepared, monkeypatch):
    con, run, *_ = prepared
    original_validate = hunt_results.validate
    calls = 0

    def drift_on_recheck(connection, run_dir, result):
        nonlocal calls
        calls += 1
        validated = original_validate(connection, run_dir, result)
        if calls == 2:
            return dataclasses.replace(validated, assigned_units=validated.assigned_units + ("drift",))
        return validated

    monkeypatch.setattr(hunt_results, "validate", drift_on_recheck)
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="changed before publication"):
        record(prepared)
    assert calls == 2
    assert sql_state(con) == before
    assert not con.in_transaction
    assert list((run / "artifacts/hunt").rglob("result.json"))


@pytest.mark.parametrize("replace", [False, True])
def test_canonical_result_over_limit_is_rejected_before_publication(prepared, replace):
    # Breaks: accepting an 8 MiB input whose canonical trailing newline makes
    # the installed artifact one byte too large for the lane checker.
    con, run, payload, *_ = prepared
    if replace:
        record(prepared)
    before = sql_state(con)
    artifact_root = run / "artifacts/hunt"
    old_files = ({path.relative_to(artifact_root): path.read_bytes()
                  for path in artifact_root.rglob("*") if path.is_file()}
                 if artifact_root.exists() else {})

    oversized = copy.deepcopy(payload)
    oversized["decisions"][0]["reason"] = ""
    base = json.dumps(oversized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    oversized["decisions"][0]["reason"] = "x" * (hunt_results.MAX_RESULT_BYTES - len(base))
    raw = json.dumps(oversized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert len(raw) == hunt_results.MAX_RESULT_BYTES
    path = run / "hunt-result.json"
    path.write_bytes(raw)
    validated = hunt_results.validate(con, run, hunt_results.load(path))
    assert len(hunt_results.canonical_bytes(validated)) == hunt_results.MAX_RESULT_BYTES + 1

    with pytest.raises(hunt.HuntError, match="(?i)canonical.*size|size.*canonical|Result size"):
        hunt_results.record(con, run, path, replace=replace)

    assert sql_state(con) == before
    new_files = ({item.relative_to(artifact_root): item.read_bytes()
                  for item in artifact_root.rglob("*") if item.is_file()}
                 if artifact_root.exists() else {})
    assert new_files == old_files


def test_not_audited_retains_its_permitted_reason(prepared):
    payload = prepared[2]
    payload["decisions"][0].update(disposition="not_audited", reason="budget")
    record(prepared)
    assert dict(prepared[0].execute("SELECT state,reason FROM cba_coverage WHERE unit='/firmware/6:target:a' AND phase='hunt-l-sink'").fetchone()) == {
        "state": "not_audited", "reason": "budget"}


@pytest.mark.parametrize("directory", ["artifacts", "artifacts/hunt", "generation", "lane"])
def test_symlinked_artifact_ancestor_is_refused_before_writing_outside_run(prepared, tmp_path, directory):
    # Breaks: atomic installation follows an attacker-replaced parent directory.
    con, run, _, _, preparation = prepared
    destination = run / "artifacts/hunt" / preparation.generation / "l-sink"
    linked = {"artifacts": run / "artifacts", "artifacts/hunt": run / "artifacts/hunt",
              "generation": destination.parent, "lane": destination}[directory]
    if linked.exists():
        moved = linked.with_name("retained-artifacts")
        linked.rename(moved)
    linked.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    linked.symlink_to(outside, target_is_directory=True)
    before = sql_state(con)
    with pytest.raises(hunt.HuntError):
        record(prepared)
    assert sql_state(con) == before
    assert not list(outside.iterdir())


def test_same_result_replacement_remains_one_receipt_and_one_set_of_claims(prepared):
    original = record(prepared)
    complete(prepared[0])
    replaced = record(prepared, replace=True)
    assert replaced == original
    assert len(rows(prepared[0], "cba_hunt_receipts")) == 1
    assert len(rows(prepared[0], "cba_hunt_candidates")) == 1
    assert len(list((prepared[1] / "artifacts/hunt").rglob("result.json"))) == 1


def test_replacement_preserves_another_generations_receipt_and_candidates(prepared):
    con = prepared[0]
    record(prepared)
    old_receipt = rows(con, "cba_hunt_receipts")[0] | {
        "worklist_sha256": "f" * 64, "result_path": "old-generation/result.json", "result_sha256": "e" * 64}
    old_candidate = rows(con, "cba_hunt_candidates")[0] | {
        "candidate_id": "older-candidate", "artifact_path": "old-generation/result.json", "artifact_sha256": "e" * 64}
    db.put(con, "cba_hunt_receipts", old_receipt)
    db.put(con, "cba_hunt_candidates", old_candidate)
    payload = copy.deepcopy(prepared[2])
    payload["decisions"][2].update(candidates=[], reason="Guard blocks the path.")
    record(prepared, payload, replace=True)
    assert old_receipt in rows(con, "cba_hunt_receipts")
    assert rows(con, "cba_hunt_candidates") == [old_candidate]
