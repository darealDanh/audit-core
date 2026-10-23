"""Atomic, image/snapshot/batch-owned firmware review publication."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, firmware_fpcheck, hunt, surface, workspace
from tests.test_firmware_fpcheck_results import api, review, completed, prepared  # noqa: F401
from tests.test_hunt_gate import fill, state
from tests.test_hunt_prepare import add_target
from tests.test_hunt_results import candidate
from tests.test_firmware_fpcheck_schema import FINDING, PIVOT


def source(review, payload=None):
    path = review[1] / "worker.json"
    path.write_text(json.dumps(review[4] if payload is None else payload), encoding="utf-8")
    return path


def rows(con, table):
    return [dict(row) for row in con.execute(f"SELECT * FROM {table} ORDER BY 1,2,3")]


def test_first_import_owns_provenance_variants_counts_and_canonical_cells(review):
    con, run, _, prepared, _, expected = review
    result = api().record(con, run, source(review))
    digest = hashlib.sha256(expected).hexdigest()
    artifact = run / "artifacts/firmware-fpcheck" / prepared.generation / digest / "result.json"
    assert dataclasses.asdict(result) == dict(image_id="target", batch_path="batch-0001.json",
        assigned_candidates=3, true_positives=1, false_positives=1, duplicates=1, pivots=1,
        artifact_path=str(artifact))
    assert artifact.read_bytes() == expected
    receipt, = rows(con, "cba_firmware_fp_receipts")
    assert (receipt["result_path"], receipt["result_sha256"], receipt["worklist_sha256"],
        receipt["candidate_snapshot_sha256"], receipt["batch_sha256"]) == (
        str(artifact), digest, prepared.worklist_sha256, prepared.candidate_snapshot_sha256,
        review[4]["batch_sha256"])
    assert tuple(receipt[k] for k in ("assigned_count", "verdict_count", "true_positive_count",
        "false_positive_count", "duplicate_count", "pivot_count")) == (3, 3, 1, 1, 1, 1)
    verdicts = rows(con, "cba_firmware_fp_verdicts")
    assert [(v["lane"], v["candidate_id"], v["verdict"]) for v in verdicts] == [
        ("l-dark", "shell-1", "DUPLICATE"), ("l-sink", "pivot-source", "FALSE_POSITIVE"),
        ("l-sink", "shell-1", "TRUE_POSITIVE")]
    for row in verdicts:
        assert (row["artifact_path"], row["artifact_sha256"], row["candidate_snapshot_sha256"],
            row["batch_path"]) == (str(artifact), digest, prepared.candidate_snapshot_sha256, "batch-0001.json")
        assert row["rules_applied"] == '["HE-17"]' and row["reviewed_at"]
        assert (row["reason"], row["attacker_advantage"], row["mitigation_analysis"], row["confidence"]) == (
            "Source reread", "Shell capability", "Trim only", 6)
    duplicate, false_positive, true_positive = verdicts
    assert (duplicate["duplicate_lane"], duplicate["duplicate_candidate_id"], duplicate["dedup_evidence"]) == (
        "l-sink", "shell-1", "Same call")
    assert (false_positive["refuting_mechanism"], false_positive["pivot_id"]) == ("Argument escaping", "pivot-1")
    assert tuple(true_positive[k] for k in ("root_cause_key", "root_cause", "dedup_evidence",
        "reviewed_attacker_position", "reviewed_data_flow", "reviewed_impact_hypothesis",
        "component_paths", "surface_ids")) == ("shell", "Unchecked shell input", "Same call", "lan",
        "POST to system", "Shell execution", '["c"]', '["http-c"]')
    pivot, = rows(con, "cba_firmware_pivots")
    assert pivot == PIVOT | {"image_id": "target", "pivot_id": "pivot-1",
        "candidate_snapshot_sha256": prepared.candidate_snapshot_sha256, "source_candidate_id": "pivot-source",
        "component_path": "c", "refuting_mechanism": "Argument escaping", "enabled_observation": "No shell path",
        "evidence": "Escaper at c:12", "artifact_path": str(artifact), "artifact_sha256": digest,
        "recorded_at": pivot["recorded_at"]}
    assert receipt["recorded_at"] and pivot["recorded_at"]
    run_row, = rows(con, "cba_firmware_fp_runs")
    assert (run_row["status"], run_row["completed_at"]) == ("pending", None)
    assert not con.in_transaction
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.image_id = "other"


def test_duplicate_requires_replace_and_does_not_write(review):
    con, run, *_ = review
    path = source(review)
    api().record(con, run, path)
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError, match="replace"):
        api().record(con, run, path)
    assert state(con) == before and not con.in_transaction


def split_payloads(review):
    con, run, root, _, payload, _ = review
    summary = firmware_fpcheck.prepare(con, run, root, batch_size=1)
    index = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    result = []
    for batch in index["batches"]:
        members = json.loads(pathlib.Path(summary.worklist_path).with_name(batch["path"]).read_bytes())["candidates"]
        identities = {(r["lane"], r["candidate_id"]) for r in members}
        result.append(copy.deepcopy(payload) | {"worklist_sha256": summary.worklist_sha256,
            "batch_path": batch["path"], "batch_sha256": batch["sha256"],
            "decisions": [d for d in payload["decisions"] if (d["lane"], d["candidate_id"]) in identities]})
    return result


def test_replace_preserves_sibling_batch_lane_and_image_and_clears_completed_findings(review):
    con, run, *_ = review
    payloads = split_payloads(review)
    assert len(payloads) > 1
    for payload in payloads:
        api().record(con, run, source(review, payload))
    selected = next(p for p in payloads if any(d["verdict"] == "FALSE_POSITIVE" for d in p["decisions"]))
    # Independent image, overlapping raw candidate ID and pivot ID, and an old
    # snapshot in this image must survive exact replacement predicates.
    for table in ("cba_firmware_fp_receipts", "cba_firmware_fp_verdicts", "cba_firmware_pivots"):
        for row in rows(con, table):
            db.put(con, table, row | {"image_id": "target:%_雪|other"})
    pivot = rows(con, "cba_firmware_pivots")[0]
    db.put(con, "cba_firmware_pivots", pivot | {"pivot_id": "old-snapshot", "candidate_snapshot_sha256": "f" * 64})
    for image in ("target", "target:%_雪|other"):
        db.put(con, "cba_firmware_findings", FINDING | {"image_id": image})
    con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at='done'")
    con.commit()
    before = state(con)
    selected = copy.deepcopy(selected)
    for d in selected["decisions"]:
        if d["false_positive"]:
            d["false_positive"]["pivot_id"] = "replacement-pivot"
            d["reason"] = "Corrected review"
    api().record(con, run, source(review, selected), replace=True)
    after = state(con)
    for table in ("cba_firmware_fp_receipts", "cba_firmware_fp_verdicts", "cba_firmware_pivots", "cba_firmware_findings"):
        assert [r for r in after[table] if r[0] != "target"] == [r for r in before[table] if r[0] != "target"]
    for table in ("cba_firmware_fp_receipts", "cba_firmware_fp_verdicts"):
        column = db.TABLE_SPECS[table].columns.index("batch_path")
        assert [r for r in after[table] if r[column] != selected["batch_path"]] == [
            r for r in before[table] if r[column] != selected["batch_path"]]
    assert {r["pivot_id"] for r in rows(con, "cba_firmware_pivots") if r["image_id"] == "target"} == {
        "replacement-pivot", "old-snapshot"}
    assert not con.execute("SELECT 1 FROM cba_firmware_findings WHERE image_id='target'").fetchone()
    assert tuple(con.execute("SELECT status,completed_at FROM cba_firmware_fp_runs").fetchone()) == ("pending", None)


def test_empty_batches_two_unicode_images_have_independent_receipts(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    with db.connect(run / "audit.db") as con:
        for number, image in enumerate(("a:%_图像", "a:%_图像:other")):
            root = tmp_path / f"root-{number}"
            add_target(con, run, root, ["a", "b"], image_id=image)
            summary = hunt.prepare(con, run, root, image_id=image)
            fill(con, run, summary)
            for lane in db.HUNT_LANES:
                hunt.check(con, run, root, image_id=image, lane=lane)
            summary = firmware_fpcheck.prepare(con, run, root, image_id=image)
            batch = json.loads(pathlib.Path(summary.worklist_path).read_bytes())["batches"][0]
            payload = dict(schema_version=1, image_id=image, candidate_snapshot_sha256=summary.candidate_snapshot_sha256,
                worklist_sha256=summary.worklist_sha256, batch_path=batch["path"], batch_sha256=batch["sha256"], decisions=[])
            path = run / "empty.json"
            path.write_text(json.dumps(payload))
            result = api().record(con, run, path)
            assert (result.assigned_candidates, result.true_positives, result.false_positives,
                result.duplicates, result.pivots) == (0, 0, 0, 0, 0)
            assert pathlib.Path(result.artifact_path).relative_to(run).parts[:2] == ("artifacts", "firmware-fpcheck")
        assert len(rows(con, "cba_firmware_fp_receipts")) == 2
        assert rows(con, "cba_firmware_fp_verdicts") == rows(con, "cba_firmware_pivots") == []


def test_nonempty_images_with_overlapping_paths_and_candidate_ids_are_independent(review, tmp_path):
    con, run, *_ = review
    api().record(con, run, source(review))
    before = state(con)
    image = "target:%_雪|other"
    root = tmp_path / "second-root"
    add_target(con, run, root, ["a", "b", "c"], image_id=image)
    summary = hunt.prepare(con, run, root, image_id=image)
    example = candidate(json.loads((run / "extra-hunt.json").read_bytes()))
    example.update(surface_ids=[], surface_context="Unmapped dispatcher evidence")
    fill(con, run, summary, example=example)
    for lane in db.HUNT_LANES:
        hunt.check(con, run, root, image_id=image, lane=lane)
    prepared = firmware_fpcheck.prepare(con, run, root, image_id=image)
    batch = json.loads(pathlib.Path(prepared.worklist_path).read_bytes())["batches"][0]
    payload = copy.deepcopy(review[4]) | {"image_id": image,
        "candidate_snapshot_sha256": prepared.candidate_snapshot_sha256,
        "worklist_sha256": prepared.worklist_sha256, "batch_path": batch["path"], "batch_sha256": batch["sha256"],
        "decisions": [review[4]["decisions"][2]]}
    payload["decisions"][0]["true_positive"]["surface_ids"] = []
    api().record(con, run, source(review, payload))
    for table in ("cba_firmware_fp_runs", "cba_firmware_fp_receipts", "cba_firmware_fp_verdicts", "cba_firmware_pivots"):
        assert [r for r in state(con)[table] if r[0] == "target"] == before[table]
    assert len(rows(con, "cba_firmware_fp_verdicts")) == 4


def test_replacement_pivots_are_lane_qualified_for_same_raw_candidate_id(review):
    con, run, *_ = review
    payloads = split_payloads(review)
    for payload in payloads:
        for d in payload["decisions"]:
            if d["candidate_id"] == "shell-1":
                d.update(verdict="FALSE_POSITIVE", duplicate=None, true_positive=None,
                    false_positive=copy.deepcopy(review[4]["decisions"][1]["false_positive"]) | {
                        "pivot_id": d["lane"] + "-pivot"})
        api().record(con, run, source(review, payload))
    selected = next(p for p in payloads if any(d["lane"] == "l-dark" for d in p["decisions"]))
    before = next(r for r in rows(con, "cba_firmware_pivots") if r["pivot_id"] == "l-sink-pivot")
    selected = copy.deepcopy(selected)
    next(d for d in selected["decisions"] if d["lane"] == "l-dark")["false_positive"]["pivot_id"] = "new-dark"
    api().record(con, run, source(review, selected), replace=True)
    assert next(r for r in rows(con, "cba_firmware_pivots") if r["pivot_id"] == "l-sink-pivot") == before
    assert {r["pivot_id"] for r in rows(con, "cba_firmware_pivots")} == {"l-sink-pivot", "new-dark", "pivot-1"}


def test_replacement_refuses_unowned_receipt_and_orphan_claims_without_sql_changes(review):
    con, run, *_ = review
    path = source(review)
    api().record(con, run, path)
    con.execute("UPDATE cba_firmware_fp_receipts SET worklist_sha256=?", ("f" * 64,))
    con.commit()
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError, match="ownership"):
        api().record(con, run, path, replace=True)
    assert state(con) == before
    con.execute("UPDATE cba_firmware_fp_receipts SET worklist_sha256=?", (review[3].worklist_sha256,))
    con.execute("DELETE FROM cba_firmware_fp_receipts")
    con.commit()
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().record(con, run, path, replace=True)
    assert state(con) == before and not con.in_transaction


def test_recheck_rejects_changed_validated_identity_under_lock(review, monkeypatch):
    con, run, *_ = review
    path = source(review)
    original = api().validate
    calls = 0
    def validate(*args):
        nonlocal calls
        calls += 1
        result = original(*args)
        return result if calls == 1 else dataclasses.replace(result, index_path="changed")
    monkeypatch.setattr(api(), "validate", validate)
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError, match="changed"):
        api().record(con, run, path)
    assert state(con) == before and not con.in_transaction


def test_concurrent_connection_receipt_is_rechecked_under_publication_lock(review, monkeypatch):
    con, run, *_ = review
    path = source(review)
    original = surface.atomic_install
    before = None
    def install(destination, files):
        original(destination, files)
        with db.connect(run / "audit.db") as other:
            db.put(other, "cba_firmware_fp_receipts", {
                "image_id": "target", "candidate_snapshot_sha256": review[3].candidate_snapshot_sha256,
                "worklist_sha256": review[3].worklist_sha256, "batch_path": "batch-0001.json",
                "batch_sha256": review[4]["batch_sha256"], "result_path": str(destination / "result.json"),
                "result_sha256": hashlib.sha256(review[5]).hexdigest(), "assigned_count": 3,
                "verdict_count": 3, "true_positive_count": 1, "false_positive_count": 1,
                "duplicate_count": 1, "pivot_count": 1})
        nonlocal before
        before = state(con)
    monkeypatch.setattr(surface, "atomic_install", install)
    with pytest.raises(firmware_fpcheck.FpcheckError, match="replace"):
        api().record(con, run, path)
    assert before is not None and state(con) == before and not con.in_transaction


@pytest.mark.parametrize("table,operation", [(t, op) for t in (
    "cba_firmware_fp_receipts", "cba_firmware_fp_verdicts", "cba_firmware_pivots") for op in ("INSERT", "DELETE")]
    + [("cba_firmware_findings", "DELETE"), ("cba_firmware_fp_runs", "UPDATE")])
def test_each_sql_failure_rolls_back_entire_replacement(review, table, operation):
    con, run, *_ = review
    path = source(review)
    api().record(con, run, path)
    db.put(con, "cba_firmware_findings", FINDING | {"image_id": "target"})
    before = state(con)
    con.execute(f"CREATE TRIGGER fail_import BEFORE {operation} ON {table} BEGIN SELECT RAISE(FAIL, 'injected'); END")
    con.commit()
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().record(con, run, path, replace=True)
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("failure", ["source", "install", "artifact-bytes", "artifact-extra", "artifact-symlink",
    "candidate", "worklist", "receipt-race", "snapshot", "run"])
def test_failure_before_publication_keeps_existing_sql(review, monkeypatch, tmp_path, failure):
    con, run, *_ = review
    path = source(review)
    api().record(con, run, path)
    before = state(con)
    original = surface.atomic_install
    def install(destination, files):
        if failure == "install":
            raise OSError("injected install")
        original(destination, files)
        if failure == "artifact-bytes":
            (destination / "result.json").write_bytes(b"{}")
        elif failure == "artifact-extra":
            (destination / "extra.json").write_bytes(b"{}")
        elif failure == "artifact-symlink":
            outside = tmp_path / "result.json"
            (destination / "result.json").rename(outside)
            (destination / "result.json").symlink_to(outside)
        elif failure == "candidate":
            con.execute("UPDATE cba_hunt_candidates SET title='concurrent'")
            con.commit()
        elif failure == "worklist":
            pathlib.Path(review[3].worklist_path).write_bytes(b"{}")
        elif failure == "receipt-race":
            con.execute("UPDATE cba_firmware_fp_receipts SET batch_sha256=?", ("f" * 64,))
            con.commit()
        elif failure == "run":
            con.execute("UPDATE cba_firmware_fp_runs SET worklist_sha256=?", ("f" * 64,))
            con.commit()
        nonlocal before
        before = state(con)
    monkeypatch.setattr(surface, "atomic_install", install)
    if failure == "source":
        path.unlink()
    elif failure == "snapshot":
        original_snapshot = api()._snapshot
        calls = 0
        def snapshot(*args):
            nonlocal calls
            calls += 1
            value = original_snapshot(*args)
            return value if calls == 1 else dataclasses.replace(value, candidates=())
        monkeypatch.setattr(api(), "_snapshot", snapshot)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().record(con, run, path, replace=True)
    assert state(con) == before and not con.in_transaction


def test_commit_failure_leaves_only_unreferenced_canonical_artifact(review):
    con, run, *_ = review
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit")
    connection = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    connection.row_factory = sqlite3.Row
    before = state(con)
    try:
        with pytest.raises(firmware_fpcheck.FpcheckError):
            api().record(connection, run, source(review))
        assert state(con) == before and not connection.in_transaction
        artifact, = (run / "artifacts/firmware-fpcheck").rglob("result.json")
        assert artifact.read_bytes() == review[5]
    finally:
        connection.close()


def test_caller_transaction_is_preserved_and_closed_connection_is_domain_error(review):
    con, run, *_ = review
    path = source(review)
    con.execute("UPDATE cba_firmware_fp_runs SET prepared_at='caller'")
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError, match="transaction"):
        api().record(con, run, path)
    assert con.in_transaction and state(con) == before
    con.rollback()
    con.close()
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().record(con, run, path)


@pytest.mark.parametrize("parent", ["artifacts", "firmware-fpcheck"])
def test_symlink_parent_cannot_install_outside_run(review, tmp_path, parent):
    con, run, *_ = review
    directory = run / "artifacts" if parent == "artifacts" else run / "artifacts/firmware-fpcheck"
    outside = tmp_path / "outside"
    if directory.exists():
        directory.rename(outside)
    else:
        directory.parent.mkdir(exist_ok=True)
        outside.mkdir()
    directory.symlink_to(outside, target_is_directory=True)
    before = state(con)
    files = sorted(str(p.relative_to(outside)) for p in outside.rglob("*"))
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().record(con, run, source(review))
    assert state(con) == before and sorted(str(p.relative_to(outside)) for p in outside.rglob("*")) == files
