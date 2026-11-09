"""Artifact-first, immutable Stage 4j report preparation."""
import json
import os
import sqlite3
import stat

import pytest

from audit_core import db
from audit_core import firmware_decide as decide
from audit_core import firmware_decide_results as decide_results
from audit_core import firmware_report as report
from tests.test_firmware_decide_gate import matching_policy, recorded_pipeline, write_policy
from tests.test_firmware_decide_package import completed_pipeline  # noqa: F401
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_results import build_result, save
from tests.test_firmware_chain_import import rows
from tests.test_hunt_gate import state


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def active_sibling(con, package, *, generation, package_sha256, ordinal,
                   image_id="target", status="pending",
                   prepared_at="2026-11-09 00:00:00", recorded_at=None):
    """One synthetic active report run for the same image."""
    row = {
        "image_id": image_id,
        "report_generation": generation,
        "preparation_ordinal": ordinal,
        "status": status,
        "decision_generation": package.decision_generation,
        "decision_package_sha256": package_sha256,
        "style_contract_sha256": report._style_contract_sha256(),
        "manifest_path": f"files/firmware-report/{generation}/manifest.json",
        "manifest_sha256": "c" * 64,
        "item_count": 0,
        "result_count": 0,
        "prepared_at": prepared_at,
    }
    if status == "recorded":
        row.update(
            results_path=f"artifacts/firmware-report-results/{generation}/"
                         f"{'d' * 64}/results.json",
            results_sha256="d" * 64,
            recorded_at=recorded_at or prepared_at)
    db.put(con, "cba_firmware_report_runs", row)
    return row


def test_prepare_installs_immutable_assignments_then_publishes_pending_run(
        completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    package = decide.verified_package(con, run, root, image_id="target")
    seed, = report._assignment_seeds(package)
    generation = report._generation(package, (seed,))

    summary = report.prepare(con, run, root, image_id="target")

    assert summary.report_generation == generation
    assert summary.image_id == "target"
    assert summary.decision_generation == package.decision_generation
    assert summary.decision_package_sha256 == package.package_sha256
    assert summary.style_contract_sha256 == report._style_contract_sha256()
    assert summary.item_count == 1
    assert summary.status == "pending"
    assert summary.results_path is None and summary.results_sha256 is None
    assert summary.manifest_path == f"files/firmware-report/{generation}/manifest.json"

    manifest_file = run / summary.manifest_path
    manifest_raw = manifest_file.read_bytes()
    chain_id = seed["chain"]["chain_id"]
    assignment_relative = (
        f"files/firmware-report/{generation}/items/1-{chain_id}.json")
    assignment_raw = (run / assignment_relative).read_bytes()
    assignment_sha256 = report._digest(canonical(seed))
    result_relative = (
        f"files/firmware-report-results/{generation}/1-{chain_id}.json")
    assert summary.manifest_sha256 == report._digest(manifest_raw)
    assert json.loads(manifest_raw) == {
        "schema_version": 1, "image_id": "target",
        "report_generation": generation,
        "decision_generation": package.decision_generation,
        "decision_package_sha256": package.package_sha256,
        "style_contract_sha256": report._style_contract_sha256(),
        "item_count": 1,
        "items": [{
            "ordinal": 1, "chain_id": chain_id,
            "assignment_path": assignment_relative,
            "assignment_sha256": assignment_sha256,
            "result_path": result_relative,
        }],
    }
    assert manifest_raw == canonical(json.loads(manifest_raw))
    assert tuple(sorted(json.loads(assignment_raw))) == (
        "assignment_sha256", "report_generation", "result_path", "seed")
    assert assignment_raw == canonical({
        "assignment_sha256": assignment_sha256,
        "report_generation": generation,
        "result_path": result_relative,
        "seed": seed,
    })
    assert canonical(json.loads(assignment_raw)["seed"]) == canonical(seed)
    for path in (manifest_file, run / assignment_relative):
        mode = path.stat().st_mode
        assert stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o600
        assert not os.access(path, os.X_OK)
    assert not (run / result_relative).exists()

    stored, = rows(con, "cba_firmware_report_runs")
    assert stored["preparation_ordinal"] == 1 and stored["status"] == "pending"
    assert stored["item_count"] == 1 and stored["result_count"] == 0
    assert stored["prepared_at"] and stored["recorded_at"] is None
    assert stored["completed_at"] is None and stored["superseded_at"] is None
    assert stored["report_path"] is None and stored["report_sha256"] is None
    assert stored["results_path"] is None and stored["index_path"] is None
    for key in ("image_id", "report_generation", "decision_generation",
                "decision_package_sha256", "style_contract_sha256",
                "manifest_path", "manifest_sha256", "item_count"):
        assert stored[key] == getattr(summary, key if key != "image_id" else "image_id")
    item, = rows(con, "cba_firmware_report_items")
    assert item["report_generation"] == generation and item["ordinal"] == 1
    assert item["chain_id"] == chain_id
    assert item["assignment_path"] == assignment_relative
    assert item["assignment_sha256"] == assignment_sha256
    assert item["result_path"] == result_relative
    assert item["result_sha256"] is None and item["recorded_at"] is None
    assert not con.in_transaction


def test_prepare_identical_is_zero_write_and_preserves_timestamp(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    first = report.prepare(con, run, root, image_id="target")
    before, changes = state(con), con.total_changes
    second = report.prepare(con, run, root, image_id="target")
    assert second == first
    assert state(con) == before and con.total_changes == changes
    assert not con.in_transaction


def test_prepare_re_ranks_identical_generation_and_supersedes_stale_runs(
        completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    package = decide.verified_package(con, run, root, image_id="target")
    first = report.prepare(con, run, root, image_id="target")
    active_sibling(con, package, generation="a" * 64,
                   package_sha256="b" * 64, ordinal=2)

    second = report.prepare(con, run, root, image_id="target")

    assert second == first
    stale = rows(con, "cba_firmware_report_runs")
    current = next(item for item in stale
                   if item["report_generation"] == first.report_generation)
    superseded = next(item for item in stale if item["report_generation"] == "a" * 64)
    assert superseded["status"] == "superseded" and superseded["superseded_at"]
    assert current["status"] == "pending" and current["preparation_ordinal"] == 3
    assert len(rows(con, "cba_firmware_report_items")) == 1


def test_prepare_refuses_a_sibling_active_generation_on_the_same_package(
        completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    package = decide.verified_package(con, run, root, image_id="target")
    active_sibling(con, package, generation="a" * 64,
                   package_sha256=package.package_sha256, ordinal=1)
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="active"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_supersedes_the_run_of_a_superseded_decision_package(
        completed_pipeline, decision_case, tmp_path):
    con, run, root = completed_pipeline[0][0][:3]
    graph = decision_case[3]
    first = report.prepare(con, run, root, image_id="target")

    policy = matching_policy(graph, policy_id="second-policy", cost=101)
    preparation = decide.prepare(
        con, run, root, write_policy(tmp_path, policy, "second-policy.json"),
        image_id="target")
    worklist = json.loads((run / preparation.worklist_path).read_bytes())
    decide_results.record(con, run, save(
        tmp_path / "second-decision.json",
        build_result(worklist, preparation.decision_generation)))
    decide.check(con, run, root, image_id="target")

    second = report.prepare(con, run, root, image_id="target")

    assert second.report_generation != first.report_generation
    assert second.decision_package_sha256 != first.decision_package_sha256
    history = rows(con, "cba_firmware_report_runs")
    assert len(history) == 2
    old = next(item for item in history
               if item["report_generation"] == first.report_generation)
    new = next(item for item in history
               if item["report_generation"] == second.report_generation)
    assert old["status"] == "superseded" and old["superseded_at"]
    assert new["status"] == "pending" and new["preparation_ordinal"] == 2


def test_prepare_refuses_a_superseded_generation(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    first = report.prepare(con, run, root, image_id="target")
    # The row's own prepared_at, not a fixed wall-clock literal: the contract
    # refuses a superseded_at earlier than the preparation it ends, so a
    # hardcoded hour made this test pass or fail by time of day.
    con.execute(
        "UPDATE cba_firmware_report_runs SET status='superseded',"
        "superseded_at=prepared_at "
        "WHERE image_id='target' AND report_generation=?",
        (first.report_generation,))
    con.commit()
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="superseded"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_leaves_sibling_image_rows_untouched(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    package = decide.verified_package(con, run, root, image_id="target")
    active_sibling(con, package, generation="a" * 64, package_sha256="b" * 64,
                   ordinal=7, image_id="sibling")
    before = [item for item in rows(con, "cba_firmware_report_runs", "sibling")]
    summary = report.prepare(con, run, root, image_id="target")
    assert rows(con, "cba_firmware_report_runs", "sibling") == before
    assert [item["report_generation"]
            for item in rows(con, "cba_firmware_report_runs")] == [
        summary.report_generation]


def test_prepare_requires_a_current_completed_decision_package(
        decision_case, tmp_path):
    con, run, root = decision_case[0][:3]
    graph = decision_case[3]
    recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    before = state(con)
    with pytest.raises(report.FirmwareReportError):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_preserves_identical_generation_published_during_install(
        completed_pipeline, monkeypatch):
    con, run, root = completed_pipeline[0][0][:3]
    original = report.firmware_dive._install
    winner = {}

    def install_then_publish(*args, **kwargs):
        original(*args, **kwargs)
        monkeypatch.setattr(report.firmware_dive, "_install", original)
        winner["summary"] = report.prepare(con, run, root, image_id="target")
        winner["state"], winner["changes"] = state(con), con.total_changes

    monkeypatch.setattr(report.firmware_dive, "_install", install_then_publish)
    actual = report.prepare(con, run, root, image_id="target")
    assert actual == winner["summary"]
    assert state(con) == winner["state"] and con.total_changes == winner["changes"]
    assert not con.in_transaction


def test_prepare_rejects_installed_assignment_drift(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    summary = report.prepare(con, run, root, image_id="target")
    (run / summary.manifest_path).write_bytes(b"{}\n")
    before = state(con)
    with pytest.raises(report.FirmwareReportError):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_rolls_back_commit_failure(completed_pipeline):
    source, run, root = completed_pipeline[0][0][:3]

    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    con.row_factory = sqlite3.Row
    before = state(source)
    try:
        with pytest.raises(report.FirmwareReportError, match="database operation failed"):
            report.prepare(con, run, root, image_id="target")
        assert state(source) == before and not con.in_transaction
    finally:
        con.close()


def test_prepare_refuses_an_active_caller_transaction(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    con.execute("BEGIN")
    try:
        with pytest.raises(report.FirmwareReportError, match="transaction"):
            report.prepare(con, run, root, image_id="target")
    finally:
        con.rollback()


def empty_pipeline(graph_case, tmp_path):
    """One complete Stage 4i decision over an image with zero chains."""
    from audit_core import firmware_chain, firmware_dive as dive
    from audit_core import firmware_dive_results
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    from tests.test_firmware_decide_policy import POLICY
    from tests.test_firmware_dive_prepare import canonical as dive_canonical

    con, run = graph_case[:2]
    root = tmp_path / "empty-root"
    empty_review(con, run, root, "empty")
    chain = firmware_chain.prepare(con, run, root, image_id="empty")
    case = (con, run, root, {
        "schema_version": 1, "image_id": "empty",
        "candidate_snapshot_sha256": chain.candidate_snapshot_sha256,
        "worklist_sha256": chain.worklist_sha256,
        "blockers": [], "dispositions": [], "chains": [],
    }, {})
    chain_record(case)
    chain_check(case, image_id="empty")
    prepared_dive = dive.prepare(con, run, root, image_id="empty")
    dive_path = tmp_path / "empty-dive.json"
    dive_path.write_bytes(dive_canonical({
        "schema_version": 1, "image_id": "empty",
        "dive_generation": prepared_dive.dive_generation, "questions": [],
    }))
    firmware_dive_results.record(con, run, dive_path)
    dive.check(con, run, root, image_id="empty")
    preparation = decide.prepare(
        con, run, root, write_policy(tmp_path, POLICY, "empty-policy.json"),
        image_id="empty")
    decide_results.record(con, run, save(tmp_path / "empty-decision.json", {
        "schema_version": 1, "image_id": "empty",
        "decision_generation": preparation.decision_generation,
        "worklist_sha256": preparation.worklist_sha256,
        "answer": {"kind": "empty"},
    }))
    decide.check(con, run, root, image_id="empty")
    return con, run, root


def test_prepare_publishes_a_zero_chain_report_as_recorded(graph_case, tmp_path):
    con, run, root = empty_pipeline(graph_case, tmp_path)
    summary = report.prepare(con, run, root, image_id="empty")
    generation = summary.report_generation
    results_sha256, results_raw = report._results(generation)

    assert summary.item_count == 0 and summary.status == "recorded"
    assert summary.results_sha256 == results_sha256
    assert summary.results_path == (
        f"artifacts/firmware-report-results/{generation}/{results_sha256}/results.json")
    installed = run / summary.results_path
    assert installed.read_bytes() == results_raw
    assert json.loads(results_raw) == {
        "schema_version": 1, "report_generation": generation, "results": []}
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600
    assert json.loads((run / summary.manifest_path).read_bytes())["items"] == []
    assert not (run / "files" / "firmware-report" / generation / "items").exists()

    stored, = rows(con, "cba_firmware_report_runs", "empty")
    assert stored["status"] == "recorded" and stored["item_count"] == 0
    assert stored["result_count"] == 0 and stored["recorded_at"]
    assert stored["results_sha256"] == results_sha256
    assert stored["completed_at"] is None and stored["report_sha256"] is None
    assert rows(con, "cba_firmware_report_items", "empty") == []
    assert report.prepare(con, run, root, image_id="empty") == summary


def test_prepare_refuses_a_stored_run_whose_frozen_identity_drifted(
        completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    first = report.prepare(con, run, root, image_id="target")
    con.execute(
        "UPDATE cba_firmware_report_runs SET manifest_sha256=? "
        "WHERE image_id='target' AND report_generation=?",
        ("e" * 64, first.report_generation))
    con.commit()
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="differs from current authority"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_refuses_a_zero_chain_run_whose_results_identity_drifted(
        graph_case, tmp_path):
    con, run, root = empty_pipeline(graph_case, tmp_path)
    summary = report.prepare(con, run, root, image_id="empty")
    con.execute(
        "UPDATE cba_firmware_report_runs SET results_path=? "
        "WHERE image_id='empty' AND report_generation=?",
        (f"artifacts/firmware-report-results/{summary.report_generation}/"
         f"{'f' * 64}/results.json", summary.report_generation))
    con.commit()
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="differs from current authority"):
        report.prepare(con, run, root, image_id="empty")
    assert state(con) == before and not con.in_transaction


def test_prepare_refuses_stored_items_that_differ_from_current_authority(
        completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    first = report.prepare(con, run, root, image_id="target")
    con.execute(
        "UPDATE cba_firmware_report_items SET result_path='files/elsewhere.json' "
        "WHERE image_id='target' AND report_generation=?",
        (first.report_generation,))
    con.commit()
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="items differ"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before
    con.execute("DELETE FROM cba_firmware_report_items WHERE image_id='target'")
    con.commit()
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="items differ"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("status,prepared_at,recorded_at", [
    ("pending", "2099-01-01 00:00:00", None),
    ("recorded", "2026-11-09 00:00:00", "2099-01-01 00:00:00"),
])
def test_prepare_refuses_superseding_a_run_stamped_after_now(
        completed_pipeline, status, prepared_at, recorded_at):
    con, run, root = completed_pipeline[0][0][:3]
    package = decide.verified_package(con, run, root, image_id="target")
    active_sibling(con, package, generation="a" * 64, package_sha256="b" * 64,
                   ordinal=1, status=status, prepared_at=prepared_at,
                   recorded_at=recorded_at)
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="precedes preparation or recording"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_refuses_inputs_that_change_between_both_passes(
        completed_pipeline, monkeypatch):
    con, run, root = completed_pipeline[0][0][:3]
    original_install = report.firmware_dive._install
    contract = report._style_contract()
    contract["renderer"] = dict(contract["renderer"], version=2)

    def install_then_change_style(*args, **kwargs):
        original_install(*args, **kwargs)
        monkeypatch.setattr(report, "_style_contract", lambda value=contract: value)

    monkeypatch.setattr(report.firmware_dive, "_install", install_then_change_style)
    before = state(con)
    with pytest.raises(report.FirmwareReportError, match="changed before publication"):
        report.prepare(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction
