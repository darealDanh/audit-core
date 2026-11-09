"""Stage 4j recording races: one transition, safe losers and exact rollback."""
import json
import sqlite3

import pytest

from audit_core import firmware_chain
from audit_core import firmware_decide as decide
from audit_core import firmware_decide_results as decide_results
from audit_core import firmware_dive as dive
from audit_core import firmware_report as report
from audit_core import firmware_report_results as results
from tests.test_firmware_decide_gate import matching_policy, write_policy
from tests.test_firmware_decide_input import graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_results import build_result, save
from tests.test_firmware_report_import import (  # noqa: F401
    expected, item_rows, prepared_report, record)
from tests.test_firmware_report_package import stored_run
from tests.test_firmware_chain_import import rows
from tests.test_hunt_gate import state


def failing(run, factory):
    con = sqlite3.connect(run / "audit.db", factory=factory)
    con.row_factory = sqlite3.Row
    return con


def test_two_final_items_racing_publish_one_recorded_run_and_manifest(
        prepared_report, tmp_path, monkeypatch):
    con, run, root, assignments = prepared_report
    first, second = assignments.items
    one, _, first_digest = expected(assignments, first)
    two, _, second_digest = expected(assignments, second)
    results_sha256, results_raw = report._results(assignments.generation, [
        report._result_entry(assignments.generation, one, first_digest),
        report._result_entry(assignments.generation, two, second_digest)])
    original = dive._install
    winner = {}

    def install_then_record(*args, **kwargs):
        original(*args, **kwargs)
        monkeypatch.setattr(dive, "_install", original)
        winner["summary"] = record(con, run, tmp_path, assignments, second,
                                   name="two.json")

    monkeypatch.setattr(dive, "_install", install_then_record)
    final = record(con, run, tmp_path, assignments, first, name="one.json")

    assert winner["summary"].status == "pending"
    assert winner["summary"].recorded_count == 1
    assert final.status == "recorded" and final.recorded_count == 2
    assert final.chain_id == first["chain_id"]

    row, = rows(con, "cba_firmware_report_runs")
    assert row["status"] == "recorded" and row["result_count"] == 2
    assert row["results_sha256"] == results_sha256
    assert (run / row["results_path"]).read_bytes() == results_raw
    assert sorted(path.name for path in (
        run / "artifacts" / "firmware-report-results"
        / assignments.generation).iterdir()) == sorted(
        {results_sha256, first["chain_id"], second["chain_id"]})
    assert [item["result_sha256"] for item in item_rows(con)] == [
        first_digest, second_digest]
    verified = report._verify_complete_inputs(con, run, root, image_id="target")
    assert verified.results_sha256 == results_sha256
    assert not con.in_transaction


def test_record_racing_a_stale_supersede_loses_without_writing(
        prepared_report, tmp_path, monkeypatch):
    con, run, root, assignments = prepared_report
    graph = firmware_chain.verified_graph_snapshot(con, run, root, image_id="target")
    original = dive._install
    winner = {}

    def install_then_supersede(*args, **kwargs):
        original(*args, **kwargs)
        monkeypatch.setattr(dive, "_install", original)
        preparation = decide.prepare(con, run, root, write_policy(
            tmp_path, matching_policy(graph, policy_id="second-policy", cost=101),
            "second-policy.json"), image_id="target")
        worklist = json.loads((run / preparation.worklist_path).read_bytes())
        decide_results.record(con, run, save(
            tmp_path / "second-decision.json",
            build_result(worklist, preparation.decision_generation)))
        decide.check(con, run, root, image_id="target")
        winner["summary"] = report.prepare(con, run, root, image_id="target")

    monkeypatch.setattr(dive, "_install", install_then_supersede)
    with pytest.raises(results.FirmwareReportResultError,
                       match="not for the current report preparation"):
        record(con, run, tmp_path, assignments, assignments.items[0])

    stale = stored_run(con, "target", assignments.generation)
    current = stored_run(con, "target", winner["summary"].report_generation)
    assert stale["status"] == "superseded" and stale["superseded_at"]
    assert current["status"] == "pending" and current["preparation_ordinal"] == 2
    assert all(item["result_sha256"] is None and item["recorded_at"] is None
               for item in rows(con, "cba_firmware_report_items"))
    assert not con.in_transaction


def test_record_refuses_installed_assignments_that_change_between_passes(
        prepared_report, tmp_path, monkeypatch):
    con, run, root, assignments = prepared_report
    sibling = run / assignments.items[1]["assignment_path"]
    original = dive._checked_install
    before = state(con)

    def check_then_change(*args, **kwargs):
        monkeypatch.setattr(dive, "_checked_install", original)
        original(*args, **kwargs)
        sibling.write_bytes(b"{}\n")

    monkeypatch.setattr(dive, "_checked_install", check_then_change)
    with pytest.raises(results.FirmwareReportResultError,
                       match="changed before publication"):
        record(con, run, tmp_path, assignments, assignments.items[0])

    assert state(con) == before and not con.in_transaction


def test_record_rolls_back_a_commit_failure_and_keeps_prior_results(
        prepared_report, tmp_path):
    source, run, root, assignments = prepared_report
    first, second = assignments.items
    record(source, run, tmp_path, assignments, first, name="one.json")
    before = state(source)

    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")

    con = failing(run, CommitFailure)
    try:
        with pytest.raises(results.FirmwareReportResultError,
                           match="database operation failed"):
            record(con, run, tmp_path, assignments, second, name="two.json")
        assert not con.in_transaction
    finally:
        con.close()

    assert state(source) == before
    assert stored_run(source, "target", assignments.generation)["status"] == "pending"


@pytest.mark.parametrize("table,expected_message", [
    ("cba_firmware_report_items", "item was recorded before this result"),
    ("cba_firmware_report_runs", "run was recorded before this result"),
])
def test_record_rolls_back_a_guarded_update_that_changes_no_row(
        prepared_report, tmp_path, table, expected_message):
    source, run, root, assignments = prepared_report
    first, second = assignments.items
    record(source, run, tmp_path, assignments, first, name="one.json")
    before = state(source)

    class LostUpdate(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith(f"UPDATE {table} SET"):
                return super().execute("SELECT 1 WHERE 0")
            return super().execute(sql, parameters)

    con = failing(run, LostUpdate)
    try:
        with pytest.raises(results.FirmwareReportResultError, match=expected_message):
            record(con, run, tmp_path, assignments, second, name="two.json")
        assert not con.in_transaction
    finally:
        con.close()

    assert state(source) == before
    assert [item["result_sha256"] for item in item_rows(source)][1] is None
