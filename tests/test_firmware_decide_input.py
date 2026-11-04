"""Stage 4i consumes only an exact current graph and completed dive input."""
import dataclasses
import pathlib
import sqlite3

import pytest

from audit_core import firmware_chain, firmware_decide as decide, firmware_dive as dive
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_gate import complete, populate, check as dive_check
from tests.test_firmware_dive_prepare import prepare as dive_prepare, rows
from tests.test_hunt_gate import state


@pytest.fixture
def decision_case(graph_case, tmp_path):
    complete(graph_case)
    prepared = dive_prepare(graph_case)
    populate(graph_case, tmp_path, "inconclusive")
    summary = dive_check(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id="target")
    return graph_case, prepared, summary, graph


def test_verified_decision_input_is_exact_readonly_and_caller_transaction_safe(decision_case):
    case, prepared, summary, graph = decision_case
    con, run, root = case[:3]
    before, changes = state(con), con.total_changes
    value = dive.verified_decision_input(con, run, root, graph)
    assert value.image_id == "target"
    assert value.dive_generation == prepared.dive_generation == summary.dive_generation
    assert value.journal_path == pathlib.Path(summary.journal_path).relative_to(run).as_posix()
    assert value.journal_sha256 == summary.journal_sha256
    assert value.overlay_sha256 == summary.overlay_sha256
    assert value.overlay.observations == ()
    assert state(con) == before and con.total_changes == changes and not con.in_transaction

    readonly = sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True)
    readonly.row_factory = sqlite3.Row
    try:
        readonly.execute("BEGIN")
        assert dive.verified_decision_input(readonly, run, root, graph) == value
        assert readonly.in_transaction
        readonly.rollback()
    finally:
        readonly.close()


def test_firmware_decide_verified_input_wraps_exact_graph_and_dive(decision_case):
    case, _, _, graph = decision_case
    value = decide.verified_input(*case[:3], image_id="target")
    assert value.graph == graph
    assert value.dive.image_id == graph.image_id


def test_decision_input_refuses_absent_or_pending_dive(graph_case, tmp_path):
    complete(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id="target")
    with pytest.raises(dive.FirmwareDiveError):
        dive.verified_decision_input(*graph_case[:3], graph)
    dive_prepare(graph_case)
    with pytest.raises(dive.FirmwareDiveError, match="complete"):
        dive.verified_decision_input(*graph_case[:3], graph)


def test_decision_input_refuses_foreign_graph_and_corrupt_completed_journal(decision_case):
    case, _, summary, graph = decision_case
    con, run, root = case[:3]
    with pytest.raises(dive.FirmwareDiveError):
        dive.verified_decision_input(con, run, root,
            dataclasses.replace(graph, graph_sha256="0" * 64))
    pathlib.Path(summary.journal_path).write_bytes(b"{}")
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError):
        dive.verified_decision_input(con, run, root, graph)
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("damage", ["result", "dependency", "observation"])
def test_decision_input_reconstructs_dive_owned_rows_and_files(decision_case, damage):
    case = decision_case[0]
    con, run, root = case[:3]
    graph = decision_case[3]
    if damage == "result":
        receipt = rows(con, "cba_firmware_dive_receipts")[0]
        (run / receipt["result_path"]).write_bytes(b"{}")
    elif damage == "dependency":
        dependency = rows(con, "cba_firmware_dive_dependencies")[0]
        con.execute(
            "UPDATE cba_firmware_dive_dependencies SET byte_count=? "
            "WHERE image_id=? AND dive_generation=? AND question_id=? AND ordinal=?",
            (dependency["byte_count"] + 1, dependency["image_id"],
             dependency["dive_generation"], dependency["question_id"],
             dependency["ordinal"]))
        con.commit()
    else:
        con.execute(
            "UPDATE cba_firmware_dive_observations SET outcome='supported' "
            "WHERE image_id='target'")
        con.commit()
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError):
        dive.verified_decision_input(con, run, root, graph)
    assert state(con) == before and not con.in_transaction


def test_decision_input_refuses_dive_completed_for_different_graph(graph_case, tmp_path):
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check

    complete(graph_case)
    dive_prepare(graph_case)
    populate(graph_case, tmp_path, "inconclusive")
    dive_check(graph_case)
    firmware_chain.invalidate(graph_case[0], "target", commit=True)
    prepared_chain = firmware_chain.prepare(*graph_case[:3], image_id="target")
    graph_case[3]["worklist_sha256"] = prepared_chain.worklist_sha256
    graph_case[3]["chains"][0]["title"] = "Independently revised chain"
    chain_record(graph_case, root=graph_case[2])
    chain_check(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id="target")
    with pytest.raises(dive.FirmwareDiveError, match="different graph"):
        dive.verified_decision_input(*graph_case[:3], graph)


def test_decision_input_is_selected_image_scoped(graph_case, tmp_path):
    complete(graph_case)
    dive_prepare(graph_case)
    populate(graph_case, tmp_path, "inconclusive")
    dive_check(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id="target")
    with pytest.raises(dive.FirmwareDiveError):
        dive.verified_decision_input(*graph_case[:3], dataclasses.replace(graph, image_id="sibling"))
    assert rows(graph_case[0], "cba_firmware_dive_runs")[0]["image_id"] == "target"


def test_decision_input_accepts_explicit_completed_empty_denominator(graph_case, tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    from tests.test_firmware_dive_prepare import canonical
    from audit_core import firmware_dive_results

    con, run = graph_case[:2]
    root = tmp_path / "empty-root"
    empty_review(con, run, root, "empty")
    chain = firmware_chain.prepare(con, run, root, image_id="empty")
    case = (con, run, root, {
        "schema_version": 1,
        "image_id": "empty",
        "candidate_snapshot_sha256": chain.candidate_snapshot_sha256,
        "worklist_sha256": chain.worklist_sha256,
        "blockers": [],
        "dispositions": [],
        "chains": [],
    }, {})
    chain_record(case)
    chain_check(case, image_id="empty")
    prepared_dive = dive.prepare(con, run, root, image_id="empty")
    result = tmp_path / "empty-dive.json"
    result.write_bytes(canonical({
        "schema_version": 1,
        "image_id": "empty",
        "dive_generation": prepared_dive.dive_generation,
        "questions": [],
    }))
    firmware_dive_results.record(con, run, result)
    dive.check(con, run, root, image_id="empty")
    graph = firmware_chain.verified_graph_snapshot(con, run, root, image_id="empty")
    value = dive.verified_decision_input(con, run, root, graph)
    assert value.image_id == "empty"
    assert value.dive_generation == prepared_dive.dive_generation
    assert value.overlay.observations == ()
