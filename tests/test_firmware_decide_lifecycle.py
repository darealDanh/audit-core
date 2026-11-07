"""Stage 4i generation lifecycle: superseding stale work and latest-prepare selection."""
import json

import pytest

from audit_core import firmware_chain, firmware_decide as decide
from audit_core import firmware_decide_results as results
from tests.test_firmware_decide_gate import matching_policy, write_policy
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_package import completed_pipeline  # noqa: F401
from tests.test_firmware_decide_results import build_result, save
from tests.test_firmware_dive_prepare import rows
from tests.test_hunt_gate import state


def record_generation(con, run, tmp_path, preparation, name):
    worklist = json.loads((run / preparation.worklist_path).read_bytes())
    path = save(tmp_path / name, build_result(worklist, preparation.decision_generation))
    results.record(con, run, path)
    return path


def regenerate_upstream(case, tmp_path):
    """Publish a new current graph and completed dive after a decision was prepared."""
    from tests.test_firmware_chain_gate import check as chain_check
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_dive_gate import check as dive_check, populate
    from tests.test_firmware_dive_prepare import prepare as dive_prepare
    con, run, root = case[:3]
    firmware_chain.invalidate(con, "target", commit=True)
    case[3]["worklist_sha256"] = firmware_chain.prepare(
        con, run, root, image_id="target").worklist_sha256
    case[3]["chains"][0]["title"] = "New current graph after decision preparation"
    chain_record(case, root=root)
    chain_check(case)
    populate(case, tmp_path, "inconclusive", dive_prepare(case).dive_generation)
    dive_check(case)
    return firmware_chain.verified_graph_snapshot(con, run, root, image_id="target")


def by_generation(con):
    return {row["decision_generation"]: row for row in rows(con, "cba_firmware_decide_runs")}


@pytest.mark.parametrize("stage", ["pending", "recorded"])
def test_prepare_supersedes_active_generation_on_stale_technical_input(
        decision_case, tmp_path, stage):
    """Catches a stale pending/recorded generation blocking every later prepare forever."""
    case, _, _, graph = decision_case
    con, run, root = case[:3]
    first = decide.prepare(con, run, root, write_policy(tmp_path, matching_policy(graph)),
                           image_id="target")
    old_result = None
    if stage == "recorded":
        old_result = record_generation(con, run, tmp_path, first, "old-result.json")
    old_row = by_generation(con)[first.decision_generation]
    new_graph = regenerate_upstream(case, tmp_path)

    second = decide.prepare(
        con, run, root, write_policy(tmp_path, matching_policy(new_graph), "new.json"),
        image_id="target")
    assert second.decision_generation != first.decision_generation
    history = by_generation(con)
    old, new = history[first.decision_generation], history[second.decision_generation]
    assert old["status"] == "superseded" and old["superseded_at"] >= old["prepared_at"]
    # Superseding is terminal and keeps the frozen row and its artifacts.
    assert {key: old[key] for key in old if key not in ("status", "superseded_at")} == {
        key: old_row[key] for key in old_row if key not in ("status", "superseded_at")}
    assert (run / first.worklist_path).is_file() and (run / first.policy_path).is_file()
    if stage == "recorded":
        assert old["recorded_at"] and (run / old["result_path"]).is_file()
    assert new["status"] == "pending"
    assert new["preparation_ordinal"] > old["preparation_ordinal"]

    # Superseded work can never be recorded or selected again.
    if old_result is None:
        old_result = save(tmp_path / "old-result.json", build_result(
            json.loads((run / first.worklist_path).read_bytes()), first.decision_generation))
    before = state(con)
    with pytest.raises(results.FirmwareDecideResultError, match="only a pending"):
        results.record(con, run, old_result)
    assert state(con) == before and not con.in_transaction
    with pytest.raises(decide.FirmwareDecideError, match="not recorded"):
        decide.check(con, run, root, image_id="target")

    record_generation(con, run, tmp_path, second, "new-result.json")
    summary = decide.check(con, run, root, image_id="target")
    assert summary.decision_generation == second.decision_generation
    assert decide.verified_package(
        con, run, root, image_id="target").decision_generation == second.decision_generation


def test_superseded_generation_cannot_be_reprepared(decision_case, tmp_path):
    """Catches reviving terminal superseded authority through an identical prepare."""
    case, _, _, graph = decision_case
    con, run, root = case[:3]
    policy = write_policy(tmp_path, matching_policy(graph))
    decide.prepare(con, run, root, policy, image_id="target")
    con.execute("UPDATE cba_firmware_decide_runs SET status='superseded',superseded_at=prepared_at")
    con.commit()
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError, match="was superseded"):
        decide.prepare(con, run, root, policy, image_id="target")
    assert state(con) == before and not con.in_transaction


def complete_generation(con, run, root, tmp_path, policy, name):
    preparation = decide.prepare(con, run, root, policy, image_id="target")
    record_generation(con, run, tmp_path, preparation, f"{name}-result.json")
    return preparation, decide.check(con, run, root, image_id="target")


def test_identical_reprepare_makes_that_policy_latest(decision_case, tmp_path):
    """Catches re-preparing policy A after B returning A but checking/verifying B."""
    case, _, _, graph = decision_case
    con, run, root = case[:3]
    policy_a = write_policy(tmp_path, matching_policy(graph, policy_id="policy-a"), "a.json")
    policy_b = write_policy(tmp_path, matching_policy(
        graph, policy_id="policy-b", support="unknown"), "b.json")
    first, first_check = complete_generation(con, run, root, tmp_path, policy_a, "a")
    second, second_check = complete_generation(con, run, root, tmp_path, policy_b, "b")
    # Same-second completions no longer matter: preparation order decides.
    assert (first_check.decision, second_check.decision) == ("acquire", "defer")

    again = decide.prepare(con, run, root, policy_a, image_id="target")
    assert again == first
    history = by_generation(con)
    assert (history[first.decision_generation]["preparation_ordinal"]
            > history[second.decision_generation]["preparation_ordinal"])
    assert history[first.decision_generation]["status"] == "complete"
    summary = decide.check(con, run, root, image_id="target")
    assert summary == first_check
    package = decide.verified_package(con, run, root, image_id="target")
    assert package.decision_generation == first.decision_generation
    assert package.policy.policy_id == "policy-a"

    assert decide.prepare(con, run, root, policy_b, image_id="target") == second
    assert decide.verified_package(
        con, run, root, image_id="target").policy.policy_id == "policy-b"


def test_unfinished_latest_generation_never_falls_back(decision_case, tmp_path):
    """Catches verifying an older complete package while the latest prepare is unfinished."""
    case, _, _, graph = decision_case
    con, run, root = case[:3]
    complete_generation(con, run, root, tmp_path, write_policy(
        tmp_path, matching_policy(graph, policy_id="policy-a"), "a.json"), "a")
    latest = decide.prepare(con, run, root, write_policy(
        tmp_path, matching_policy(graph, policy_id="policy-b"), "b.json"), image_id="target")
    with pytest.raises(decide.FirmwareDecideError, match="not recorded"):
        decide.verified_package(con, run, root, image_id="target")
    record_generation(con, run, tmp_path, latest, "b-result.json")
    with pytest.raises(decide.FirmwareDecideError, match="differs from canonical package"):
        decide.verified_package(con, run, root, image_id="target")
    assert decide.check(con, run, root, image_id="target").decision_generation == (
        latest.decision_generation)


@pytest.mark.parametrize("column,value", [
    ("completed_at", "not-a-timestamp"),
    ("completed_at", "2026-02-30 00:00:00"),
    ("completed_at", "2000-01-01 00:00:00"),
    ("recorded_at", "9999-12-31 23:59:59"),
    ("prepared_at", "9999-12-31 23:59:59"),
    ("prepared_at", None),
])
def test_complete_rechecks_refuse_invalid_or_unordered_timestamps(
        completed_pipeline, column, value):
    """Catches accepting malformed, impossible or out-of-order lifecycle timestamps."""
    pipeline, _ = completed_pipeline
    con, run, root = pipeline[0][:3]
    con.execute(f"UPDATE cba_firmware_decide_runs SET {column}=?", (value,))
    con.commit()
    before = state(con)
    for operation in (decide.verified_package, decide.check):
        with pytest.raises(decide.FirmwareDecideError, match="database operation failed"):
            operation(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction
