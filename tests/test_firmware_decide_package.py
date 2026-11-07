"""Canonical current Stage 4i packages, inert scripts, and failure atomicity."""
import copy
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import subprocess

import pytest

from audit_core import firmware_decide as decide
from audit_core import firmware_decide_results as results
from tests.test_firmware_decide_gate import matching_policy, recorded_pipeline
from tests.test_firmware_decide_gate import write_policy
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_results import build_result, save
from tests.test_firmware_chain_prepare import files
from tests.test_firmware_dive_prepare import rows
from tests.test_hunt_gate import state


@pytest.fixture
def completed_pipeline(decision_case, tmp_path):
    graph = decision_case[3]
    pipeline = recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    summary = decide.check(*pipeline[0][:3], image_id="target")
    return pipeline, summary


def test_verified_package_matches_canonical_file_and_regular_0600_scripts(completed_pipeline):
    pipeline, summary = completed_pipeline
    case = pipeline[0]
    con, run, root = case[:3]
    package = decide.verified_package(con, run, root, image_id="target")
    assert package.package_path == summary.package_path
    assert package.package_sha256 == summary.package_sha256
    assert (run / package.package_path).read_bytes() == package.package_bytes
    body = json.loads(package.package_bytes)
    assert body["decision"] == package.decision == "acquire"
    assert body["primary_reason"] == package.primary_reason == "eligible-chain"
    assert body["reason_codes"] == list(package.reason_codes)
    assert body["proposed_scripts"][0]["status"] == "proposed_unreviewed"
    script, = package.scripts
    target = run / script.path
    assert target.read_bytes() == script.content
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600 and stat.S_ISREG(target.stat().st_mode)
    assert not os.access(target, os.X_OK)


def test_verified_package_supports_readonly_and_caller_transactions(completed_pipeline):
    pipeline, _ = completed_pipeline
    case = pipeline[0]
    con, run, root = case[:3]
    before, changes = state(con), con.total_changes
    con.execute("BEGIN")
    expected = decide.verified_package(con, run, root, image_id="target")
    assert con.in_transaction
    con.rollback()
    assert state(con) == before and con.total_changes == changes

    readonly = sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True)
    readonly.row_factory = sqlite3.Row
    try:
        actual = decide.verified_package(readonly, run, root, image_id="target")
        assert actual == expected and not readonly.in_transaction
    finally:
        readonly.close()


def test_completed_check_is_readonly_and_does_not_install(completed_pipeline, monkeypatch):
    pipeline, summary = completed_pipeline
    con, run, root = pipeline[0][:3]
    before, changes = state(con), con.total_changes
    def forbidden(*args, **kwargs):
        pytest.fail("completed check attempted artifact installation")
    monkeypatch.setattr(decide.firmware_dive, "_install", forbidden)
    readonly = sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True)
    readonly.row_factory = sqlite3.Row
    statements = []
    readonly.set_trace_callback(statements.append)
    try:
        assert decide.check(readonly, run, root, image_id="target") == summary
        assert not readonly.in_transaction and readonly.total_changes == 0
        assert not any("BEGIN IMMEDIATE" in sql for sql in statements)
    finally:
        readonly.close()
    assert state(con) == before and con.total_changes == changes


@pytest.mark.parametrize("operation", [decide.check, decide.verified_package])
def test_completed_package_missing_directory_is_refused_without_repair(
        completed_pipeline, operation):
    pipeline, summary = completed_pipeline
    con, run, root = pipeline[0][:3]
    destination = (run / summary.package_path).parent
    shutil.rmtree(destination)
    before, changes = state(con), con.total_changes
    with pytest.raises(decide.FirmwareDecideError):
        operation(con, run, root, image_id="target")
    assert not destination.exists()
    assert state(con) == before and con.total_changes == changes
    assert not con.in_transaction


def test_completed_prepare_does_not_recreate_missing_assignment(completed_pipeline, tmp_path):
    pipeline, _ = completed_pipeline
    case, preparation = pipeline[:2]
    con, run, root = case[:3]
    policy_source = tmp_path / "repeat-policy.json"
    policy_source.write_bytes((run / preparation.policy_path).read_bytes())
    destination = (run / preparation.worklist_path).parent
    shutil.rmtree(destination)
    before, changes = state(con), con.total_changes
    with pytest.raises(decide.FirmwareDecideError):
        decide.prepare(con, run, root, policy_source, image_id="target")
    assert not destination.exists()
    assert state(con) == before and con.total_changes == changes


@pytest.mark.parametrize("damage", [
    "package", "script", "extra", "policy", "worklist", "result", "row",
])
def test_verified_package_rejects_any_byte_or_row_drift(completed_pipeline, damage):
    pipeline, summary = completed_pipeline
    case, preparation = pipeline[:2]
    con, run, root = case[:3]
    package = decide.verified_package(con, run, root, image_id="target")
    row = rows(con, "cba_firmware_decide_runs")[0]
    if damage == "package":
        (run / summary.package_path).write_bytes(b"{}\n")
    elif damage == "script":
        (run / package.scripts[0].path).write_bytes(b"changed\n")
    elif damage == "extra":
        pathlib.Path(summary.package_path).parent.joinpath("extra")
        (run / pathlib.PurePosixPath(summary.package_path).parent / "extra").write_bytes(b"x")
    elif damage == "policy":
        (run / row["policy_path"]).write_bytes(b"{}\n")
    elif damage == "worklist":
        (run / row["worklist_path"]).write_bytes(b"{}\n")
    elif damage == "result":
        (run / row["result_path"]).write_bytes(b"{}")
    else:
        con.execute(
            "UPDATE cba_firmware_decide_runs SET package_sha256=? WHERE image_id='target'",
            ("0" * 64,))
        con.commit()
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError):
        decide.verified_package(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_check_never_executes_proposed_scripts(decision_case, tmp_path, monkeypatch):
    graph = decision_case[3]
    pipeline = recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    def forbidden(*args, **kwargs):
        raise AssertionError("script execution is forbidden")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    summary = decide.check(*pipeline[0][:3], image_id="target")
    assert summary.complete
    assert decide.verified_package(*pipeline[0][:3], image_id="target").scripts


def test_check_rejects_symlink_package_parent_without_outside_write(decision_case, tmp_path):
    graph = decision_case[3]
    pipeline = recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    case = pipeline[0]
    run = case[1]
    parent = run / "artifacts" / "firmware-decide"
    outside = tmp_path / "outside"
    outside.mkdir()
    parent.symlink_to(outside, target_is_directory=True)
    before = state(case[0])
    with pytest.raises(decide.FirmwareDecideError):
        decide.check(*case[:3], image_id="target")
    assert list(outside.iterdir()) == [] and state(case[0]) == before


def test_check_revalidates_authority_after_install(decision_case, tmp_path, monkeypatch):
    graph = decision_case[3]
    pipeline = recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    case = pipeline[0]
    con, run, root = case[:3]
    row = rows(con, "cba_firmware_decide_runs")[0]
    original = decide.firmware_dive._install
    def install_then_change(*args, **kwargs):
        original(*args, **kwargs)
        (run / row["policy_path"]).write_bytes(b"{}\n")
    monkeypatch.setattr(decide.firmware_dive, "_install", install_then_change)
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError):
        decide.check(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


def test_check_rolls_back_commit_failure(decision_case, tmp_path):
    graph = decision_case[3]
    pipeline = recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    case = pipeline[0]
    owner, run, root = case[:3]
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")
    con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    con.row_factory = sqlite3.Row
    before = state(owner)
    try:
        with pytest.raises(decide.FirmwareDecideError, match="database operation failed"):
            decide.check(con, run, root, image_id="target")
        assert state(owner) == before and not con.in_transaction
    finally:
        con.close()


def regenerate_graph(case):
    """Replace the current Stage 4g graph after the decision completed."""
    from audit_core import firmware_chain
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check

    con, run, root = case[:3]
    firmware_chain.invalidate(con, "target", commit=True)
    prepared_chain = firmware_chain.prepare(con, run, root, image_id="target")
    case[3]["worklist_sha256"] = prepared_chain.worklist_sha256
    case[3]["chains"][0]["title"] = "New current graph after decision completion"
    chain_record(case, root=root)
    chain_check(case)


def decide_files(run):
    return {path: value for path, value in files(run).items()
            if path.split("/")[1].startswith("firmware-decide")}


def test_verified_package_refuses_newer_current_graph(completed_pipeline):
    """Catches serving a completed package after its graph stopped being current."""
    from audit_core import firmware_dive

    pipeline, _ = completed_pipeline
    case = pipeline[0]
    con, run, root = case[:3]
    regenerate_graph(case)
    with pytest.raises(decide.FirmwareDecideError,
                       match="^Cannot verify firmware decision input$") as refused:
        decide.verified_package(con, run, root, image_id="target")
    assert isinstance(refused.value.__cause__, firmware_dive.FirmwareDiveError)
    assert "different graph" in str(refused.value.__cause__)


def test_completed_history_survives_upstream_graph_change(completed_pipeline):
    """Catches deleting or rewriting a completed decision when upstream evidence changes."""
    pipeline, summary = completed_pipeline
    case = pipeline[0]
    con, run, root = case[:3]
    row_before, = rows(con, "cba_firmware_decide_runs")
    artifacts = decide_files(run)
    assert summary.package_path in artifacts
    assert any(path.startswith("files/firmware-decide/") for path in artifacts)
    assert any(path.startswith("artifacts/firmware-decide-results/") for path in artifacts)
    regenerate_graph(case)
    for operation in (decide.verified_package, decide.check):
        with pytest.raises(decide.FirmwareDecideError):
            operation(con, run, root, image_id="target")
    assert rows(con, "cba_firmware_decide_runs") == [row_before]
    assert row_before["status"] == "complete"
    assert row_before["package_sha256"] == summary.package_sha256
    assert decide_files(run) == artifacts
    assert hashlib.sha256((run / summary.package_path).read_bytes()).hexdigest() == (
        summary.package_sha256)


def test_verified_package_rejects_executable_mode_drift(completed_pipeline):
    pipeline, _ = completed_pipeline
    case = pipeline[0]
    package = decide.verified_package(*case[:3], image_id="target")
    target = case[1] / package.scripts[0].path
    target.chmod(0o700)
    with pytest.raises(decide.FirmwareDecideError):
        decide.verified_package(*case[:3], image_id="target")


def test_completed_identical_prepare_preserves_derived_state(completed_pipeline):
    pipeline, summary = completed_pipeline
    case, preparation = pipeline[:2]
    con, run, root = case[:3]
    policy_source = pathlib.Path(pipeline[4]).parent / "same-policy.json"
    policy_source.write_bytes((run / preparation.policy_path).read_bytes())
    before, changes = state(con), con.total_changes
    repeated = decide.prepare(
        con, run, root, policy_source, image_id="target")
    assert repeated == preparation
    assert state(con) == before and con.total_changes == changes
    row = rows(con, "cba_firmware_decide_runs")[0]
    assert row["status"] == "complete"
    assert row["bench_test_count"] == summary.bench_test_count
    assert row["script_count"] == summary.script_count
    assert row["policy_match_count"] == summary.policy_match_count


def test_verified_script_descriptor_declares_exact_size(completed_pipeline):
    pipeline, _ = completed_pipeline
    package = decide.verified_package(*pipeline[0][:3], image_id="target")
    script = package.scripts[0]
    body = json.loads(package.package_bytes)
    assert script.size == len(script.content)
    assert body["proposed_scripts"][0]["size"] == len(script.content)


def substituted_package(completed_pipeline, tmp_path, source):
    """Forge a self-consistent package whose result belongs to a real other assignment."""
    from audit_core import firmware_chain, firmware_dive, firmware_dive_results
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check

    pipeline, summary = completed_pipeline
    con, run, root = pipeline[0][:3]
    original = json.loads((run / summary.package_path).read_bytes())
    if source == "prior-generation":
        donor = original
        policy = copy.deepcopy(original["policy"])
        policy["notes"].append("A later explicit operator policy snapshot.")
        policy["notes"].sort()
        preparation = decide.prepare(con, run, root,
            write_policy(tmp_path, policy, "later-policy.json"), image_id="target")
        worklist = json.loads((run / preparation.worklist_path).read_bytes())
        results.record(con, run, save(tmp_path / "later-result.json",
            build_result(worklist, preparation.decision_generation)))
        summary = decide.check(con, run, root, image_id="target")
        current = json.loads((run / summary.package_path).read_bytes())
    else:
        sibling_root = tmp_path / "sibling-root"
        empty_review(con, run, sibling_root, "sibling")
        chain = firmware_chain.prepare(con, run, sibling_root, image_id="sibling")
        case = (con, run, sibling_root, {
            "schema_version": 1, "image_id": "sibling",
            "candidate_snapshot_sha256": chain.candidate_snapshot_sha256,
            "worklist_sha256": chain.worklist_sha256,
            "blockers": [], "dispositions": [], "chains": [],
        }, {})
        chain_record(case)
        chain_check(case, image_id="sibling")
        dive = firmware_dive.prepare(con, run, sibling_root, image_id="sibling")
        firmware_dive_results.record(con, run, save(tmp_path / "sibling-dive.json", {
            "schema_version": 1, "image_id": "sibling",
            "dive_generation": dive.dive_generation, "questions": [],
        }))
        firmware_dive.check(con, run, sibling_root, image_id="sibling")
        preparation = decide.prepare(con, run, sibling_root,
            write_policy(tmp_path, original["policy"], "sibling-policy.json"), image_id="sibling")
        results.record(con, run, save(tmp_path / "sibling-result.json", {
            "schema_version": 1, "image_id": "sibling",
            "decision_generation": preparation.decision_generation,
            "worklist_sha256": preparation.worklist_sha256,
            "answer": {"kind": "empty"},
        }))
        sibling = decide.check(con, run, sibling_root, image_id="sibling")
        donor = json.loads((run / sibling.package_path).read_bytes())
        current = original

    # Keep A's current technical input/policy, but replace its result and all
    # resulting projections with B's individually valid historical/sibling result.
    forged = copy.deepcopy(current)
    for field in ("result_path", "result_sha256"):
        forged["provenance"][field] = donor["provenance"][field]
    for field in ("chain_assessments", "open_preconditions", "bench_tests",
                  "proposed_scripts", "policy_matches", "payout_projections",
                  "decision", "primary_reason", "reason_codes", "top_chain_id",
                  "bench_plan_complete"):
        forged[field] = donor[field]
    raw = (json.dumps(forged, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    relative = f"artifacts/firmware-decide/{current['decision_generation']}/{digest}/decision.json"
    destination = run / relative
    destination.parent.mkdir(parents=True)
    destination.write_bytes(raw)
    destination.chmod(0o600)
    donor_row = dict(con.execute(
        "SELECT * FROM cba_firmware_decide_runs WHERE image_id=? AND decision_generation=?",
        (donor["image_id"], donor["decision_generation"])).fetchone())
    for script in donor["proposed_scripts"]:
        target = destination.parent / script["path"]
        target.parent.mkdir(exist_ok=True)
        target.write_bytes((run / donor_row["package_path"]).parent.joinpath(script["path"]).read_bytes())
        target.chmod(0o600)
    con.execute(
        "UPDATE cba_firmware_decide_runs SET result_path=?,result_sha256=?,"
        "package_path=?,package_sha256=?,decision=?,primary_reason=?,reason_codes=?,"
        "chain_count=?,bench_test_count=?,script_count=?,policy_match_count=?,"
        "completed_at='2100-01-01 00:00:00' WHERE image_id='target' AND decision_generation=?",
        (donor_row["result_path"], donor_row["result_sha256"], relative, digest,
         donor["decision"], donor["primary_reason"],
         json.dumps(donor["reason_codes"], separators=(",", ":")),
         donor_row["chain_count"], donor_row["bench_test_count"],
         donor_row["script_count"], donor_row["policy_match_count"],
         current["decision_generation"]))
    con.commit()
    # B remains independently valid; rejection must bind the selected A row.
    results.validate(con, run, results.load(run / donor_row["result_path"]))
    return con, run, root


@pytest.mark.parametrize("source", ["sibling", "prior-generation"])
@pytest.mark.parametrize("operation", [decide.check, decide.verified_package])
def test_selected_package_rejects_valid_other_assignment_result_without_repair(
        completed_pipeline, tmp_path, source, operation):
    con, run, root = substituted_package(completed_pipeline, tmp_path, source)
    before, changes, artifacts = state(con), con.total_changes, files(run)
    with pytest.raises(decide.FirmwareDecideError, match="selected assignment"):
        operation(con, run, root, image_id="target")
    assert state(con) == before and con.total_changes == changes
    assert files(run) == artifacts and not con.in_transaction
