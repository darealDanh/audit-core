"""Atomic Stage 4j per-item recording: one item, exact bytes, one transition."""
import copy
import json
import os
import pathlib
import stat

import pytest

from audit_core import db
from audit_core import firmware_chain
from audit_core import firmware_decide as decide
from audit_core import firmware_dive as dive
from audit_core import firmware_report as report
from audit_core import firmware_report_results as results
from tests.test_firmware_decide_gate import matching_policy, recorded_pipeline
from tests.test_firmware_decide_input import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_gate import complete as chain_complete
from tests.test_firmware_dive_gate import check as dive_check, populate
from tests.test_firmware_dive_prepare import prepare as dive_prepare
from tests.test_firmware_report_package import stored_run, worker_answer
from tests.test_firmware_report_prepare import canonical, empty_pipeline
from tests.test_firmware_chain_import import rows
from tests.test_hunt_gate import state


def two_chain_graph(case):
    """Add one shorter second chain over the same prepared findings."""
    value = case[3]
    second = copy.deepcopy(value["chains"][0])
    second.update(chain_key="b", member_ids=second["member_ids"][:2],
                  edges=second["edges"][:1])
    value["chains"].append(second)
    for disposition in value["dispositions"][:2]:
        disposition["chain_keys"].append("b")


@pytest.fixture
def prepared_report(graph_case, tmp_path):
    """One prepared two-chain Stage 4j report over a current decision package."""
    two_chain_graph(graph_case)
    chain_complete(graph_case)
    dive_prepare(graph_case)
    populate(graph_case, tmp_path, "inconclusive")
    dive_check(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id="target")
    recorded_pipeline((graph_case, None, None, graph), tmp_path,
                      matching_policy(graph))
    con, run, root = graph_case[:3]
    decide.check(con, run, root, image_id="target")
    package = decide.verified_package(con, run, root, image_id="target")
    assignments = report._assignments(package)
    summary = report.prepare(con, run, root, image_id="target")
    assert summary.item_count == len(assignments.items) == 2
    return con, run, root, assignments


def body(assignments, item, **overrides):
    """One worker result for exactly one assigned item."""
    seed = json.loads(assignments.contents[
        f"items/{item['ordinal']}-{item['chain_id']}.json"])["seed"]
    value = {
        "schema_version": 1,
        "image_id": "target",
        "report_generation": assignments.generation,
        "chain_id": item["chain_id"],
        "assignment_sha256": item["assignment_sha256"],
        "answer": worker_answer(seed),
    }
    value.update(overrides)
    return value


def written(tmp_path, value, name="result.json", *, indent=None):
    path = tmp_path / name
    path.write_bytes(canonical(value) if indent is None
                     else json.dumps(value, indent=indent).encode())
    return path


def expected(assignments, item, **overrides):
    """The canonical bytes and digest one accepted worker result installs."""
    raw = assignments.contents[
        f"items/{item['ordinal']}-{item['chain_id']}.json"]
    value = results.validate(
        results._parse(canonical(body(assignments, item, **overrides))), raw)
    content = results._canonical(value)
    return value, content, report._digest(content)


def record(con, run, tmp_path, assignments, item, *, name="result.json", **overrides):
    return results.record(con, run, written(
        tmp_path, body(assignments, item, **overrides), name))


def artifacts(run):
    return {path.relative_to(run).as_posix(): path.read_bytes()
            for path in sorted(run.rglob("*")) if path.is_file()}


def item_rows(con):
    return sorted(rows(con, "cba_firmware_report_items"),
                  key=lambda row: row["ordinal"])


def test_record_installs_the_canonical_result_and_fills_exactly_one_item(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first, second = assignments.items
    value, content, digest = expected(assignments, first)
    relative = report._result_artifact_path(
        assignments.generation, first["chain_id"], digest)

    # A worker may write readable JSON; the core records canonical bytes only.
    summary = results.record(con, run, written(
        tmp_path, body(assignments, first), indent=2))

    assert isinstance(summary, results.ReportRecordSummary)
    assert summary.image_id == "target"
    assert summary.report_generation == assignments.generation
    assert summary.chain_id == first["chain_id"] and summary.ordinal == 1
    assert summary.result_path == relative and summary.result_sha256 == digest
    assert summary.item_count == 2 and summary.recorded_count == 1
    assert summary.status == "pending"

    installed = run / relative
    assert installed.read_bytes() == content != b""
    assert json.loads(content)["chain_id"] == first["chain_id"]
    mode = installed.stat().st_mode
    assert stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o600
    assert not os.access(installed, os.X_OK)

    one, two = item_rows(con)
    assert one["chain_id"] == first["chain_id"]
    assert one["result_sha256"] == digest and one["recorded_at"]
    assert one["result_path"] == first["result_path"]
    assert two["chain_id"] == second["chain_id"]
    assert two["result_sha256"] is None and two["recorded_at"] is None

    row = stored_run(con, "target", assignments.generation)
    assert row["status"] == "pending" and row["result_count"] == 0
    assert row["results_path"] is None and row["results_sha256"] is None
    assert row["recorded_at"] is None and row["item_count"] == 2
    assert not list((run / "artifacts" / "firmware-report-results"
                     / assignments.generation).rglob("results.json"))
    assert value.ordinal == 1 and not con.in_transaction


def test_record_transitions_to_recorded_only_when_every_item_has_a_result(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first, second = assignments.items
    one, first_content, first_digest = expected(assignments, first)
    two, second_content, second_digest = expected(assignments, second)
    entries = [report._result_entry(assignments.generation, one, first_digest),
               report._result_entry(assignments.generation, two, second_digest)]
    results_sha256, results_raw = report._results(assignments.generation, entries)

    partial = record(con, run, tmp_path, assignments, first, name="one.json")
    assert partial.status == "pending"
    final = record(con, run, tmp_path, assignments, second, name="two.json")

    assert final.status == "recorded" and final.recorded_count == 2
    assert final.ordinal == 2 and final.result_sha256 == second_digest
    row = stored_run(con, "target", assignments.generation)
    assert row["status"] == "recorded" and row["result_count"] == 2
    assert row["results_sha256"] == results_sha256
    assert row["results_path"] == report._results_path(
        assignments.generation, results_sha256)
    assert row["recorded_at"] >= row["prepared_at"]
    assert row["completed_at"] is None and row["report_sha256"] is None

    installed = run / row["results_path"]
    assert installed.read_bytes() == results_raw
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600
    assert json.loads(results_raw) == {
        "schema_version": 1,
        "report_generation": assignments.generation,
        "results": [
            {"ordinal": 1, "chain_id": first["chain_id"],
             "result_path": report._result_artifact_path(
                 assignments.generation, first["chain_id"], first_digest),
             "result_sha256": first_digest},
            {"ordinal": 2, "chain_id": second["chain_id"],
             "result_path": report._result_artifact_path(
                 assignments.generation, second["chain_id"], second_digest),
             "result_sha256": second_digest}]}
    assert (run / report._result_artifact_path(
        assignments.generation, first["chain_id"], first_digest)
    ).read_bytes() == first_content
    assert (run / report._result_artifact_path(
        assignments.generation, second["chain_id"], second_digest)
    ).read_bytes() == second_content

    # The pure Task 5 verifier reads exactly these paths and digests.
    verified = report._verify_complete_inputs(con, run, root, image_id="target")
    assert verified.row["status"] == "recorded"
    assert verified.results_sha256 == results_sha256
    assert verified.results == (one, two)
    assert not con.in_transaction


def test_record_is_idempotent_for_an_identical_retry(prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first, second = assignments.items

    partial = record(con, run, tmp_path, assignments, first, name="one.json")
    before, changes, stored = state(con), con.total_changes, artifacts(run)
    assert record(con, run, tmp_path, assignments, first,
                  name="one-again.json") == partial
    assert state(con) == before and con.total_changes == changes
    assert artifacts(run) == stored

    final = record(con, run, tmp_path, assignments, second, name="two.json")
    before, changes, stored = state(con), con.total_changes, artifacts(run)
    assert record(con, run, tmp_path, assignments, second,
                  name="two-again.json") == final
    assert state(con) == before and con.total_changes == changes
    assert artifacts(run) == stored and not con.in_transaction


def test_record_refuses_conflicting_bytes_for_an_already_recorded_item(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first = assignments.items[0]
    record(con, run, tmp_path, assignments, first, name="one.json")
    other = body(assignments, first)
    other["answer"] = {**other["answer"], "severity": "medium"}
    before, stored = state(con), artifacts(run)

    with pytest.raises(results.FirmwareReportResultError, match="already recorded"):
        results.record(con, run, written(tmp_path, other, "conflict.json"))

    assert state(con) == before and artifacts(run) == stored
    assert not con.in_transaction


def test_record_refuses_a_chain_the_current_preparation_never_assigned(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    foreign = body(assignments, assignments.items[0],
                   chain_id="chain:" + "0" * 64)
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="not assigned"):
        results.record(con, run, written(tmp_path, foreign, "foreign.json"))

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_zero_item_preparation(graph_case, tmp_path):
    from tests.test_firmware_report_results import result

    con, run, root = empty_pipeline(graph_case, tmp_path)
    summary = report.prepare(con, run, root, image_id="empty")
    value = result(image_id="empty", report_generation=summary.report_generation)
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="not assigned"):
        results.record(con, run, written(tmp_path, value, "empty-result.json"))

    assert state(con) == before and not con.in_transaction


def test_record_refuses_an_image_without_a_report_preparation(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    foreign = body(assignments, assignments.items[0], image_id="ghost")
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="no report preparation"):
        results.record(con, run, written(tmp_path, foreign, "ghost.json"))

    assert state(con) == before and not con.in_transaction


def test_record_refuses_more_than_one_current_preparation(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    row = stored_run(con, "target", assignments.generation)
    db.put(con, "cba_firmware_report_runs", {
        **row, "report_generation": "a" * 64, "item_count": 0,
        "manifest_path": f"files/firmware-report/{'a' * 64}/manifest.json"})
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="more than one current"):
        record(con, run, tmp_path, assignments, assignments.items[0])

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_generation_that_is_not_the_current_preparation(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    stale = body(assignments, assignments.items[0], report_generation="b" * 64)
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError,
                       match="not for the current report preparation"):
        results.record(con, run, written(tmp_path, stale, "stale.json"))

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_superseded_report_preparation(prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    row = stored_run(con, "target", assignments.generation)
    db.put(con, "cba_firmware_report_runs",
           {**row, "status": "superseded", "superseded_at": row["prepared_at"]},
           replace=True)
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="not active"):
        record(con, run, tmp_path, assignments, assignments.items[0])

    assert state(con) == before and not con.in_transaction


def test_record_refuses_stored_items_that_differ_from_the_preparation(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    con.execute("UPDATE cba_firmware_report_runs SET manifest_sha256=? "
                "WHERE image_id='target' AND report_generation=?",
                ("c" * 64, assignments.generation))
    con.commit()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="stored report items"):
        record(con, run, tmp_path, assignments, assignments.items[0])
    assert state(con) == before

    con.execute("UPDATE cba_firmware_report_runs SET manifest_sha256=? "
                "WHERE image_id='target' AND report_generation=?",
                (assignments.manifest_sha256, assignments.generation))
    con.execute("DELETE FROM cba_firmware_report_items WHERE image_id='target' "
                "AND chain_id=?", (assignments.items[1]["chain_id"],))
    con.commit()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="stored report items"):
        record(con, run, tmp_path, assignments, assignments.items[0])
    assert state(con) == before and not con.in_transaction


def test_record_refuses_an_installed_assignment_that_is_not_the_assigned_one(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    item = assignments.items[0]
    envelope = json.loads(assignments.contents[f"items/1-{item['chain_id']}.json"])
    seed = envelope["seed"]
    seed["chain"] = {**seed["chain"], "title": "An independently revised title"}
    changed = canonical({**envelope, "seed": seed,
                         "assignment_sha256": report._digest(canonical(seed))})
    (run / item["assignment_path"]).write_bytes(changed)
    value = body(assignments, item,
                 assignment_sha256=json.loads(changed)["assignment_sha256"])
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="assigned item"):
        results.record(con, run, written(tmp_path, value, "revised.json"))

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_missing_installed_assignment(prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    (run / assignments.items[1]["assignment_path"]).unlink()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="cannot record"):
        record(con, run, tmp_path, assignments, assignments.items[0])

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_recorded_sibling_result_that_is_not_canonical(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first, second = assignments.items
    record(con, run, tmp_path, assignments, first, name="one.json")
    content = expected(assignments, first)[1]
    readable = json.dumps(json.loads(content), indent=2).encode()
    forged = report._digest(readable)
    dive._install(run / pathlib.PurePosixPath(report._result_artifact_path(
        assignments.generation, first["chain_id"], forged)).parent,
        {"result.json": readable}, run)
    con.execute("UPDATE cba_firmware_report_items SET result_sha256=? "
                "WHERE image_id='target' AND chain_id=?",
                (forged, first["chain_id"]))
    con.commit()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="not canonical"):
        record(con, run, tmp_path, assignments, second, name="two.json")

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_stored_result_manifest_that_differs(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first, second = assignments.items
    record(con, run, tmp_path, assignments, first, name="one.json")
    record(con, run, tmp_path, assignments, second, name="two.json")
    con.execute("UPDATE cba_firmware_report_runs SET results_sha256=? "
                "WHERE image_id='target' AND report_generation=?",
                ("d" * 64, assignments.generation))
    con.commit()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="result manifest"):
        record(con, run, tmp_path, assignments, second, name="two-again.json")

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_recorded_run_whose_items_are_not_all_recorded(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    first, second = assignments.items
    record(con, run, tmp_path, assignments, first, name="one.json")
    record(con, run, tmp_path, assignments, second, name="two.json")
    con.execute("UPDATE cba_firmware_report_items SET result_sha256=NULL,"
                "recorded_at=NULL WHERE image_id='target' AND chain_id=?",
                (first["chain_id"],))
    con.commit()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="result manifest"):
        record(con, run, tmp_path, assignments, second, name="two-again.json")

    assert state(con) == before and not con.in_transaction


def test_record_refuses_a_timestamp_that_precedes_preparation(
        prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    item = assignments.items[0]
    _, content, digest = expected(assignments, item)
    con.execute("UPDATE cba_firmware_report_runs SET prepared_at='2099-01-01 00:00:00' "
                "WHERE image_id='target' AND report_generation=?",
                (assignments.generation,))
    con.commit()
    before = state(con)

    with pytest.raises(results.FirmwareReportResultError, match="precedes preparation"):
        record(con, run, tmp_path, assignments, item)

    # Artifact-first: the immutable bytes exist, no SQL row moved.
    assert (run / report._result_artifact_path(
        assignments.generation, item["chain_id"], digest)).read_bytes() == content
    assert state(con) == before and not con.in_transaction


def test_record_refuses_an_active_caller_transaction(prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    con.execute("BEGIN")
    try:
        with pytest.raises(results.FirmwareReportResultError, match="transaction"):
            record(con, run, tmp_path, assignments, assignments.items[0])
    finally:
        con.rollback()


def test_record_leaves_sibling_image_rows_untouched(prepared_report, tmp_path):
    con, run, root, assignments = prepared_report
    row = stored_run(con, "target", assignments.generation)
    item = item_rows(con)[1]
    sibling_generation = "e" * 64
    db.put(con, "cba_firmware_report_runs", {
        **row, "image_id": "sibling", "report_generation": sibling_generation,
        "item_count": 1,
        "manifest_path": f"files/firmware-report/{sibling_generation}/manifest.json"})
    db.put(con, "cba_firmware_report_items", {
        **item, "image_id": "sibling", "report_generation": sibling_generation,
        "ordinal": 1})
    before = rows(con, "cba_firmware_report_runs", "sibling")
    before_items = rows(con, "cba_firmware_report_items", "sibling")

    record(con, run, tmp_path, assignments, assignments.items[0], name="one.json")
    record(con, run, tmp_path, assignments, assignments.items[1], name="two.json")

    assert rows(con, "cba_firmware_report_runs", "sibling") == before
    assert rows(con, "cba_firmware_report_items", "sibling") == before_items
    assert stored_run(con, "target", assignments.generation)["status"] == "recorded"
