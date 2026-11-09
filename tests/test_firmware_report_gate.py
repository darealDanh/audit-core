"""Stage 4j completion: pure reconstruction, immutable publication, no repair."""
import json
import os
import sqlite3
import stat

import pytest

from audit_core import db
from audit_core import firmware_chain
from audit_core import firmware_decide as decide
from audit_core import firmware_decide_results as decide_results
from audit_core import firmware_dive as dive
from audit_core import firmware_report as report
from tests.test_firmware_decide_gate import matching_policy, write_policy
from tests.test_firmware_decide_input import graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_results import build_result, save
from tests.test_firmware_report_import import (  # noqa: F401
    artifacts, expected, item_rows, prepared_report, record)
from tests.test_firmware_report_package import mtimes, stored_run
from tests.test_firmware_report_prepare import empty_pipeline
from tests.test_firmware_chain_import import rows
from tests.test_hunt_gate import state


@pytest.fixture
def recorded_report(prepared_report, tmp_path):
    """One two-chain Stage 4j report with every worker result recorded."""
    con, run, root, assignments = prepared_report
    for item in assignments.items:
        record(con, run, tmp_path, assignments, item,
               name=f"result-{item['ordinal']}.json")
    assert stored_run(con, "target", assignments.generation)["status"] == "recorded"
    return con, run, root, assignments


def canonical_report(con, run, root, assignments, image_id="target"):
    """The exact Markdown, index and sections the current authority renders."""
    package = decide.verified_package(con, run, root, image_id=image_id)
    validated = {item["chain_id"]: expected(assignments, item)[0]
                 for item in assignments.items}
    return package, report._render(package, assignments, validated)


def second_decision(con, run, root, tmp_path, *, cost=101):
    """Complete one changed Stage 4i decision package over the same image."""
    graph = firmware_chain.verified_graph_snapshot(con, run, root, image_id="target")
    preparation = decide.prepare(con, run, root, write_policy(
        tmp_path, matching_policy(graph, policy_id="second-policy", cost=cost),
        "second-policy.json"), image_id="target")
    worklist = json.loads((run / preparation.worklist_path).read_bytes())
    decide_results.record(con, run, save(
        tmp_path / "second-decision.json",
        build_result(worklist, preparation.decision_generation)))
    return decide.check(con, run, root, image_id="target")


def failing(run, factory):
    con = sqlite3.connect(run / "audit.db", factory=factory)
    con.row_factory = sqlite3.Row
    return con


def completion(run, generation, report_sha256):
    return (run / "artifacts" / "firmware-report" / generation / report_sha256)


def test_check_completes_a_recorded_run_with_exact_report_and_index_bytes(
        recorded_report):
    con, run, root, assignments = recorded_report
    package, (raw, index_raw, _) = canonical_report(con, run, root, assignments)
    report_sha256, index_sha256 = report._digest(raw), report._digest(index_raw)
    before = stored_run(con, "target", assignments.generation)
    items_before = item_rows(con)
    results_file = run / before["results_path"]
    results_before = results_file.read_bytes()

    summary = report.check(con, run, root, image_id="target")

    assert isinstance(summary, report.ReportSummary)
    assert summary.image_id == "target"
    assert summary.report_generation == assignments.generation
    assert summary.decision_generation == package.decision_generation
    assert summary.decision_package_sha256 == package.package_sha256
    assert summary.style_contract_sha256 == report._style_contract_sha256()
    assert summary.item_count == 2 and summary.status == "complete"
    assert summary.results_path == before["results_path"]
    assert summary.results_sha256 == before["results_sha256"]
    assert summary.report_path == report._report_path(
        assignments.generation, report_sha256)
    assert summary.report_sha256 == report_sha256
    assert summary.index_path == report._index_path(
        assignments.generation, report_sha256)
    assert summary.index_sha256 == index_sha256

    # The completion directory holds exactly the report and its index.
    destination = completion(run, assignments.generation, report_sha256)
    assert sorted(path.name for path in destination.iterdir()) == [
        "report.json", "report.md"]
    for name, content in (("report.md", raw), ("report.json", index_raw)):
        installed = destination / name
        assert installed.read_bytes() == content
        mode = installed.stat().st_mode
        assert stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o600
        assert not os.access(installed, os.X_OK)
    assert raw.startswith(b"Firmware assessment report\n")
    assert raw.count(b"\n# ") == 2
    assert [section["ordinal"] for section in json.loads(index_raw)["sections"]] == [1, 2]

    # The record-time result manifest keeps its own path and bytes.
    assert results_file.read_bytes() == results_before

    row = stored_run(con, "target", assignments.generation)
    assert row["status"] == "complete" and row["report_bytes"] == raw
    assert row["report_path"] == summary.report_path
    assert row["report_sha256"] == report_sha256
    assert row["index_path"] == summary.index_path
    assert row["index_sha256"] == index_sha256
    assert row["completed_at"] >= row["recorded_at"] >= row["prepared_at"]
    assert row["superseded_at"] is None and row["result_count"] == 2
    assert item_rows(con) == items_before and not con.in_transaction


def test_check_refuses_a_pending_run_without_every_recorded_result(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    record(con, run, tmp_path, assignments, assignments.items[0], name="one.json")
    before, stored = state(con), artifacts(run)

    with pytest.raises(report.FirmwareReportError, match="no recorded results"):
        report.check(con, run, root, image_id="target")

    assert not (run / "artifacts" / "firmware-report").exists()
    assert state(con) == before and artifacts(run) == stored
    assert not con.in_transaction


def test_check_is_a_pure_recheck_once_the_report_is_complete(recorded_report):
    con, run, root, _ = recorded_report
    summary = report.check(con, run, root, image_id="target")
    before, changes, stamps = state(con), con.total_changes, mtimes(run)

    assert report.check(con, run, root, image_id="target") == summary

    assert state(con) == before and con.total_changes == changes
    assert mtimes(run) == stamps and not con.in_transaction


def test_check_refuses_a_missing_or_differing_complete_artifact_without_repair(
        recorded_report):
    con, run, root, _ = recorded_report
    summary = report.check(con, run, root, image_id="target")
    installed = run / summary.report_path
    index = run / summary.index_path
    canonical = installed.read_bytes()
    forged = b"Firmware assessment report\n"
    before = state(con)

    # Each sub-case restores mode 0600 so the guard under test is the one that
    # fires, not the umask the recreated file happens to carry.
    installed.unlink()
    with pytest.raises(report.FirmwareReportError,
                       match="Cannot complete firmware report") as missing:
        report.check(con, run, root, image_id="target")
    assert "directory contains different artifacts" in str(missing.value.__cause__)
    assert not installed.exists()

    installed.write_bytes(forged)
    os.chmod(installed, 0o600)
    with pytest.raises(report.FirmwareReportError,
                       match="Cannot complete firmware report") as differing:
        report.check(con, run, root, image_id="target")
    assert "artifact bytes differ" in str(differing.value.__cause__)
    assert installed.read_bytes() == forged
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600

    installed.write_bytes(canonical)
    os.chmod(installed, 0o600)
    index.write_bytes(b"{}\n")
    os.chmod(index, 0o600)
    with pytest.raises(report.FirmwareReportError,
                       match="Cannot complete firmware report") as forged_index:
        report.check(con, run, root, image_id="target")
    assert "artifact bytes differ" in str(forged_index.value.__cause__)
    assert index.read_bytes() == b"{}\n"

    assert state(con) == before and not con.in_transaction


def test_check_requires_the_unique_highest_preparation(recorded_report):
    con, run, root, assignments = recorded_report
    row = stored_run(con, "target", assignments.generation)
    db.put(con, "cba_firmware_report_runs", {
        **row, "report_generation": "a" * 64, "status": "superseded",
        "superseded_at": row["recorded_at"]})
    before, stored = state(con), artifacts(run)

    with pytest.raises(report.FirmwareReportError,
                       match="more than one current report preparation"):
        report.check(con, run, root, image_id="target")

    assert not (run / "artifacts" / "firmware-report").exists()
    assert state(con) == before and artifacts(run) == stored
    assert not con.in_transaction


def test_check_refuses_a_report_whose_decision_package_is_no_longer_current(
        recorded_report, tmp_path):
    con, run, root, _ = recorded_report
    second_decision(con, run, root, tmp_path)
    before, stored = state(con), artifacts(run)

    with pytest.raises(report.FirmwareReportError,
                       match="not the current decision package"):
        report.check(con, run, root, image_id="target")

    assert not (run / "artifacts" / "firmware-report").exists()
    assert state(con) == before and artifacts(run) == stored
    assert not con.in_transaction


def test_check_never_falls_back_to_an_earlier_complete_report(
        recorded_report, tmp_path):
    con, run, root, assignments = recorded_report
    summary = report.check(con, run, root, image_id="target")
    second_decision(con, run, root, tmp_path)
    pending = report.prepare(con, run, root, image_id="target")
    assert pending.report_generation != assignments.generation
    assert pending.status == "pending"
    before, stored = state(con), artifacts(run)

    with pytest.raises(report.FirmwareReportError, match="no recorded results"):
        report.check(con, run, root, image_id="target")
    with pytest.raises(report.FirmwareReportError, match="no recorded results"):
        report.verified_report(con, run, root, image_id="target")

    assert (run / summary.report_path).exists()
    assert stored_run(con, "target", assignments.generation)["status"] == "complete"
    assert state(con) == before and artifacts(run) == stored
    assert not con.in_transaction


def test_check_rolls_back_a_commit_failure_and_keeps_the_recorded_run(
        recorded_report):
    source, run, root, assignments = recorded_report
    _, (raw, index_raw, _) = canonical_report(source, run, root, assignments)
    before = state(source)

    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    con = failing(run, CommitFailure)
    try:
        with pytest.raises(report.FirmwareReportError,
                           match="database operation failed"):
            report.check(con, run, root, image_id="target")
        assert not con.in_transaction
    finally:
        con.close()

    # Artifact-first: the immutable report exists, no SQL row moved.
    destination = completion(run, assignments.generation, report._digest(raw))
    assert (destination / "report.md").read_bytes() == raw
    assert (destination / "report.json").read_bytes() == index_raw
    assert state(source) == before
    assert stored_run(source, "target", assignments.generation)["status"] == "recorded"


def test_check_accepts_a_completion_race_winner_without_rewriting(
        recorded_report, monkeypatch):
    con, run, root, assignments = recorded_report
    original = dive._install
    winner = {}

    def install_then_complete(*args, **kwargs):
        original(*args, **kwargs)
        monkeypatch.setattr(dive, "_install", original)
        winner["summary"] = report.check(con, run, root, image_id="target")
        winner["state"] = state(con)
        winner["artifacts"] = artifacts(run)

    monkeypatch.setattr(dive, "_install", install_then_complete)
    summary = report.check(con, run, root, image_id="target")

    assert summary == winner["summary"] and summary.status == "complete"
    assert state(con) == winner["state"] and artifacts(run) == winner["artifacts"]
    row = stored_run(con, "target", assignments.generation)
    assert row["status"] == "complete" and row["report_sha256"] == summary.report_sha256
    assert not con.in_transaction


def test_check_leaves_sibling_image_rows_untouched(recorded_report):
    con, run, root, assignments = recorded_report
    row = stored_run(con, "target", assignments.generation)
    item = item_rows(con)[0]
    sibling_generation = "e" * 64
    db.put(con, "cba_firmware_report_runs", {
        **row, "image_id": "sibling", "report_generation": sibling_generation,
        "manifest_path": f"files/firmware-report/{sibling_generation}/manifest.json"})
    db.put(con, "cba_firmware_report_items", {
        **item, "image_id": "sibling", "report_generation": sibling_generation})
    before = rows(con, "cba_firmware_report_runs", "sibling")
    before_items = rows(con, "cba_firmware_report_items", "sibling")

    report.check(con, run, root, image_id="target")

    assert rows(con, "cba_firmware_report_runs", "sibling") == before
    assert rows(con, "cba_firmware_report_items", "sibling") == before_items
    assert stored_run(con, "target", assignments.generation)["status"] == "complete"
    assert not con.in_transaction


def test_check_completes_a_zero_chain_report(graph_case, tmp_path):
    con, run, root = empty_pipeline(graph_case, tmp_path)
    prepared_run = report.prepare(con, run, root, image_id="empty")
    assert prepared_run.status == "recorded" and prepared_run.item_count == 0
    results_file = run / prepared_run.results_path
    results_before = results_file.read_bytes()

    summary = report.check(con, run, root, image_id="empty")

    assert summary.item_count == 0 and summary.status == "complete"
    assert summary.results_path == prepared_run.results_path
    assert summary.results_sha256 == prepared_run.results_sha256
    raw = (run / summary.report_path).read_bytes()
    assert b"No technical chain is present" in raw and b"\n# " not in raw
    assert json.loads((run / summary.index_path).read_bytes())["sections"] == []
    assert results_file.read_bytes() == results_before

    value = report.verified_report(con, run, root, image_id="empty")
    assert value.sections == () and value.report_bytes == raw
    assert value.report_path == summary.report_path
    assert value.index_sha256 == summary.index_sha256
    assert not con.in_transaction


def test_check_and_verified_report_publish_the_same_bytes(recorded_report):
    con, run, root, _ = recorded_report

    summary = report.check(con, run, root, image_id="target")
    value = report.verified_report(con, run, root, image_id="target")

    assert value.report_path == summary.report_path
    assert value.report_sha256 == summary.report_sha256
    assert value.index_path == summary.index_path
    assert value.index_sha256 == summary.index_sha256
    assert value.report_generation == summary.report_generation
    assert value.report_bytes == (run / summary.report_path).read_bytes()
    assert [section.ordinal for section in value.sections] == [1, 2]
    assert not con.in_transaction


def test_check_refuses_an_active_caller_transaction(recorded_report):
    con, run, root, _ = recorded_report
    con.execute("BEGIN")
    try:
        with pytest.raises(report.FirmwareReportError, match="transaction"):
            report.check(con, run, root, image_id="target")
    finally:
        con.rollback()
    assert not (run / "artifacts" / "firmware-report").exists()
