"""Pure Stage 4j report verification: latest preparation, exact bytes, no repair."""
import json
import pathlib
import sqlite3

import pytest

from audit_core import db
from audit_core import firmware_decide as decide
from audit_core import firmware_decide_results as decide_results
from audit_core import firmware_dive as dive
from audit_core import firmware_report as report
from audit_core import firmware_report_results as results
from tests.test_firmware_decide_gate import matching_policy, write_policy
from tests.test_firmware_decide_package import completed_pipeline  # noqa: F401
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_results import build_result, save
from tests.test_firmware_report_prepare import canonical, empty_pipeline
from tests.test_firmware_chain_import import rows
from tests.test_hunt_gate import state


def worker_answer(seed_value):
    """One accepted worker answer for one exact assignment seed."""
    member = seed_value["chain"]["member_ids"][0]
    root_ref = f"finding:{member}#root_cause"
    flow_ref = f"finding:{member}#data_flow"
    return {
        "title_detail": f"Shell command injection in {member}",
        "summary": [{"text": f"The chain member {member} passes request text into "
                             "a shell call without quoting.",
                     "citation_refs": [root_ref]}],
        "root_cause": [{"text": "Unchecked request text reaches the shell argument "
                                f"built by {member}.",
                        "citation_refs": [root_ref]}],
        "reproduction_steps": [{"text": f"Read the recorded data flow of {member} "
                                        "and follow the request text into the shell "
                                        "argument.",
                                "citation_refs": [flow_ref]}],
        "impact": [{"text": f"A caller that reaches {member} gains shell capability "
                            "with the privileges of that component.",
                    "citation_refs": [root_ref]}],
        "severity": "high",
        "severity_justification": {
            "text": f"The injection in {member} is reachable from the recorded "
                    "surface and yields shell capability.",
            "citation_refs": [root_ref]},
        "fix_direction": None,
    }


def stored_run(con, image_id, generation):
    row, = [item for item in rows(con, "cba_firmware_report_runs", image_id)
            if item["report_generation"] == generation]
    return row


def record_items(con, run, package, assignments, stamp):
    """Install and record one validated worker result per assignment item."""
    validated, entries = {}, []
    for item in assignments.items:
        raw = assignments.contents[
            f"items/{item['ordinal']}-{item['chain_id']}.json"]
        parsed = results._parse(canonical({
            "schema_version": 1,
            "image_id": package.image_id,
            "report_generation": assignments.generation,
            "chain_id": item["chain_id"],
            "assignment_sha256": item["assignment_sha256"],
            "answer": worker_answer(json.loads(raw)["seed"])}))
        value = results.validate(parsed, raw)
        result_raw = results._canonical(value)
        result_sha256 = report._digest(result_raw)
        relative = report._result_artifact_path(
            assignments.generation, item["chain_id"], result_sha256)
        dive._install(run / pathlib.PurePosixPath(relative).parent,
                      {"result.json": result_raw}, run)
        row, = [stored for stored in rows(con, "cba_firmware_report_items",
                                          package.image_id)
                if stored["chain_id"] == item["chain_id"]]
        db.put(con, "cba_firmware_report_items",
               {**row, "result_sha256": result_sha256, "recorded_at": stamp},
               replace=True)
        validated[item["chain_id"]] = value
        entries.append(report._result_entry(
            assignments.generation, value, result_sha256))
    return validated, entries


def completed_report(con, run, root, image_id="target"):
    """The recorded-then-complete state Stage 4j records and completes."""
    package = decide.verified_package(con, run, root, image_id=image_id)
    assignments = report._assignments(package)
    stamp = con.execute("SELECT datetime('now')").fetchone()[0]
    validated, entries = record_items(con, run, package, assignments, stamp)
    results_sha256, results_raw = report._results(assignments.generation, entries)
    dive._install(report._results_destination(
        run, assignments.generation, results_sha256),
        {"results.json": results_raw}, run)
    row = stored_run(con, image_id, assignments.generation)
    db.put(con, "cba_firmware_report_runs", {
        **row, "status": "recorded", "result_count": len(entries),
        "results_path": report._results_path(assignments.generation, results_sha256),
        "results_sha256": results_sha256, "recorded_at": stamp}, replace=True)
    raw, index_raw, sections = report._render(package, assignments, validated)
    return package, assignments, validated, raw, index_raw, sections


def complete(con, run, root, image_id="target"):
    """Install the report artifacts and mark the current run complete."""
    package, assignments, validated, raw, index_raw, sections = completed_report(
        con, run, root, image_id)
    report_sha256 = report._digest(raw)
    dive._install(report._report_destination(
        run, assignments.generation, report_sha256),
        {"report.md": raw, "report.json": index_raw}, run)
    stamp = con.execute("SELECT datetime('now')").fetchone()[0]
    row = stored_run(con, image_id, assignments.generation)
    db.put(con, "cba_firmware_report_runs", {
        **row, "status": "complete",
        "report_path": report._report_path(assignments.generation, report_sha256),
        "report_sha256": report_sha256, "report_bytes": raw,
        "index_path": report._index_path(assignments.generation, report_sha256),
        "index_sha256": report._digest(index_raw), "completed_at": stamp},
        replace=True)
    return package, assignments, validated, raw, index_raw, sections


@pytest.fixture
def complete_case(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    report.prepare(con, run, root, image_id="target")
    return (con, run, root) + complete(con, run, root)


def mtimes(run):
    return {path: path.stat().st_mtime_ns
            for path in sorted(run.rglob("*")) if path.is_file()}


def test_verified_report_returns_the_exact_current_complete_report(complete_case):
    con, run, root, package, assignments, _, raw, index_raw, sections = complete_case

    value = report.verified_report(con, run, root, image_id="target")

    assert isinstance(value, report.VerifiedFirmwareReport)
    assert value.image_id == "target"
    assert value.report_generation == assignments.generation
    assert value.decision_generation == package.decision_generation
    assert value.decision_package_sha256 == package.package_sha256
    assert value.report_bytes == raw
    assert value.report_sha256 == report._digest(raw)
    assert value.report_path == (
        f"artifacts/firmware-report/{assignments.generation}/"
        f"{value.report_sha256}/report.md")
    assert value.index_path == (
        f"artifacts/firmware-report/{assignments.generation}/"
        f"{value.report_sha256}/report.json")
    assert value.index_sha256 == report._digest(index_raw)
    assert (run / value.report_path).read_bytes() == raw
    assert (run / value.index_path).read_bytes() == index_raw
    assert value.sections == sections
    assert len(value.sections) == 1
    assert value.sections[0].ordinal == 1
    assert value.sections[0].severity == "high"
    blockers = json.loads(
        assignments.contents[f"items/1-{value.sections[0].chain_id}.json"]
    )["seed"]["open_preconditions"]
    assert value.sections[0].pre_auth == "not established: blocked by " + ", ".join(
        sorted(item["precondition_id"] for item in blockers))
    assert value.sections[0].citation_refs == tuple(
        sorted(set(value.sections[0].citation_refs)))
    assert not con.in_transaction


def test_verified_report_writes_nothing_and_reuses_a_caller_transaction(complete_case):
    con, run, root = complete_case[:3]
    before, changes, stamps = state(con), con.total_changes, mtimes(run)

    value = report.verified_report(con, run, root, image_id="target")

    assert state(con) == before and con.total_changes == changes
    assert mtimes(run) == stamps and not con.in_transaction

    con.execute("BEGIN")
    try:
        assert report.verified_report(con, run, root, image_id="target") == value
        assert con.in_transaction
    finally:
        con.rollback()

    readonly = sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True)
    readonly.row_factory = sqlite3.Row
    try:
        assert report.verified_report(readonly, run, root, image_id="target") == value
    finally:
        readonly.close()
    assert mtimes(run) == stamps


def test_verified_report_returns_a_zero_chain_report(graph_case, tmp_path):
    con, run, root = empty_pipeline(graph_case, tmp_path)
    report.prepare(con, run, root, image_id="empty")
    _, assignments, _, raw, _, _ = complete(con, run, root, image_id="empty")

    value = report.verified_report(con, run, root, image_id="empty")

    assert value.sections == ()
    assert value.report_bytes == raw
    assert b"No technical chain is present" in raw
    assert json.loads((run / value.index_path).read_bytes())["sections"] == []
    assert value.report_generation == assignments.generation


def test_verified_report_refuses_a_recorded_run_and_never_repairs(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    report.prepare(con, run, root, image_id="target")
    _, assignments, _, raw, _, _ = completed_report(con, run, root)
    before, stamps = state(con), mtimes(run)

    with pytest.raises(report.FirmwareReportError, match="complete"):
        report.verified_report(con, run, root, image_id="target")

    assert not (run / "artifacts" / "firmware-report" / assignments.generation).exists()
    assert state(con) == before and mtimes(run) == stamps
    assert not con.in_transaction


def test_verified_report_refuses_a_pending_run_without_results(completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]
    report.prepare(con, run, root, image_id="target")

    with pytest.raises(report.FirmwareReportError, match="recorded"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_refuses_a_missing_or_differing_report_file(complete_case):
    con, run, root = complete_case[:3]
    value = report.verified_report(con, run, root, image_id="target")
    installed = run / value.report_path
    stamps = mtimes(run)

    installed.unlink()
    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")
    assert not installed.exists()

    installed.write_bytes(value.report_bytes + b"appended\n")
    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")
    assert installed.read_bytes() == value.report_bytes + b"appended\n"

    installed.write_bytes(value.report_bytes)
    index = run / value.index_path
    index.write_bytes(b"{}\n")
    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")
    assert index.read_bytes() == b"{}\n"
    assert set(mtimes(run)) == set(stamps)


def test_verified_report_refuses_differing_assignment_or_result_artifacts(
        complete_case):
    con, run, root, _, assignments, _, _, _, _ = complete_case
    item, = assignments.items
    assignment = run / item["assignment_path"]
    original = assignment.read_bytes()

    assignment.write_bytes(original.replace(b'"ordinal":1', b'"ordinal":2'))
    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")

    assignment.write_bytes(original)
    row, = rows(con, "cba_firmware_report_items", "target")
    result = run / report._result_artifact_path(
        assignments.generation, row["chain_id"], row["result_sha256"])
    result.write_bytes(result.read_bytes().replace(b'"high"', b'"low"'))
    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_refuses_a_differing_result_manifest(complete_case):
    con, run, root = complete_case[:3]
    value = report.verified_report(con, run, root, image_id="target")
    row = stored_run(con, "target", value.report_generation)
    installed = run / row["results_path"]

    installed.write_bytes(canonical({"schema_version": 1, "results": []}))
    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")

    con.execute("UPDATE cba_firmware_report_runs SET results_sha256=? "
                "WHERE image_id='target' AND report_generation=?",
                ("e" * 64, value.report_generation))
    con.commit()
    with pytest.raises(report.FirmwareReportError, match="result manifest"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_refuses_an_item_result_that_is_not_recorded(complete_case):
    con, run, root = complete_case[:3]
    con.execute("UPDATE cba_firmware_report_items "
                "SET result_sha256=NULL,recorded_at=NULL WHERE image_id='target'")
    con.commit()

    with pytest.raises(report.FirmwareReportError, match="recorded"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_refuses_stored_rows_that_differ_from_the_current_authority(
        complete_case):
    con, run, root = complete_case[:3]
    value = report.verified_report(con, run, root, image_id="target")

    con.execute("UPDATE cba_firmware_report_runs SET report_sha256=? "
                "WHERE image_id='target' AND report_generation=?",
                ("f" * 64, value.report_generation))
    con.commit()
    with pytest.raises(report.FirmwareReportError, match="complete report row"):
        report.verified_report(con, run, root, image_id="target")

    con.execute("UPDATE cba_firmware_report_runs SET report_sha256=?,"
                "manifest_sha256=? WHERE image_id='target' AND report_generation=?",
                (value.report_sha256, "f" * 64, value.report_generation))
    con.commit()
    with pytest.raises(report.FirmwareReportError, match="current authority"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_refuses_item_rows_that_differ_from_the_current_authority(
        complete_case):
    con, run, root = complete_case[:3]
    con.execute("UPDATE cba_firmware_report_items SET ordinal=2 "
                "WHERE image_id='target'")
    con.commit()

    with pytest.raises(report.FirmwareReportError, match="items differ"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_requires_the_unique_highest_preparation(complete_case):
    con, run, root, _, assignments, _, _, _, _ = complete_case
    row = stored_run(con, "target", assignments.generation)
    db.put(con, "cba_firmware_report_runs", {
        **row, "report_generation": "a" * 64, "status": "superseded",
        "report_path": None, "report_sha256": None, "report_bytes": None,
        "index_path": None, "index_sha256": None, "completed_at": None,
        "superseded_at": row["completed_at"]})

    with pytest.raises(report.FirmwareReportError, match="one current"):
        report.verified_report(con, run, root, image_id="target")

    con.execute("UPDATE cba_firmware_report_runs SET preparation_ordinal=2 "
                "WHERE report_generation=?", ("a" * 64,))
    con.commit()
    with pytest.raises(report.FirmwareReportError, match="current"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_refuses_an_image_without_any_report(
        completed_pipeline):
    con, run, root = completed_pipeline[0][0][:3]

    with pytest.raises(report.FirmwareReportError, match="no report"):
        report.verified_report(con, run, root, image_id="target")


def test_verified_report_never_falls_back_to_a_superseded_decision_package(
        complete_case, decision_case, tmp_path):
    con, run, root = complete_case[:3]
    graph = decision_case[3]
    first = report.verified_report(con, run, root, image_id="target")

    policy = matching_policy(graph, policy_id="second-policy", cost=101)
    preparation = decide.prepare(
        con, run, root, write_policy(tmp_path, policy, "second-policy.json"),
        image_id="target")
    worklist = json.loads((run / preparation.worklist_path).read_bytes())
    decide_results.record(con, run, save(
        tmp_path / "second-decision.json",
        build_result(worklist, preparation.decision_generation)))
    decide.check(con, run, root, image_id="target")

    with pytest.raises(report.FirmwareReportError):
        report.verified_report(con, run, root, image_id="target")
    assert (run / first.report_path).read_bytes() == first.report_bytes


def test_verify_complete_inputs_rebuilds_the_exact_current_report(complete_case):
    con, run, root, package, assignments, validated, raw, index_raw, _ = complete_case

    verified = report._verify_complete_inputs(con, run, root, image_id="target")

    assert verified.package == package
    assert verified.assignments == assignments
    assert verified.results == tuple(
        validated[item["chain_id"]] for item in assignments.items)
    assert verified.report_bytes == raw and verified.index_bytes == index_raw
    assert verified.row["status"] == "complete"
    assert verified.contents == {"report.md": raw, "report.json": index_raw}


def test_validation_accepts_every_rung_a_real_assignment_catalog_copies(
        complete_case):
    con, run, root, package, assignments = complete_case[:5]
    item, = assignments.items
    raw = assignments.contents[f"items/1-{item['chain_id']}.json"]
    envelope = json.loads(raw)
    seed_value = envelope["seed"]
    assert {entry["evidence_rung"] for entry in seed_value["evidence_catalog"]} == {
        "static-reviewed", "static-chained", "unresolved"}

    for entry in seed_value["evidence_catalog"]:
        if entry["kind"] == "edge":
            entry["kind"] = "observation"
            entry["evidence_rung"] = "emulated-observed"
    changed = canonical({**envelope, "seed": seed_value,
                         "assignment_sha256": report._digest(canonical(seed_value))})
    parsed = results._parse(canonical({
        "schema_version": 1,
        "image_id": package.image_id,
        "report_generation": assignments.generation,
        "chain_id": item["chain_id"],
        "assignment_sha256": json.loads(changed)["assignment_sha256"],
        "answer": worker_answer(seed_value)}))

    value = results.validate(parsed, changed)

    assert value.chain_id == item["chain_id"] and value.ordinal == 1
    assert set(db.FIRMWARE_FP_EVIDENCE_RUNGS + db.FIRMWARE_CHAIN_EVIDENCE_RUNGS
               + db.FIRMWARE_DIVE_EVIDENCE_RUNGS) <= set(results._CATALOG_RUNGS)


def test_verified_report_refuses_a_caller_database_failure(complete_case):
    con, run, root = complete_case[:3]
    con.execute("DROP TABLE cba_firmware_report_items")
    con.commit()

    with pytest.raises(report.FirmwareReportError, match="database operation failed"):
        report.verified_report(con, run, root, image_id="target")
