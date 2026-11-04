"""Canonical current Stage 4i packages, inert scripts, and failure atomicity."""
import json
import os
import pathlib
import sqlite3
import stat
import subprocess

import pytest

from audit_core import firmware_decide as decide
from tests.test_firmware_decide_gate import matching_policy, recorded_pipeline
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
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


def test_verified_package_refuses_newer_current_graph(completed_pipeline):
    from audit_core import firmware_chain
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check

    pipeline, _ = completed_pipeline
    case = pipeline[0]
    con, run, root = case[:3]
    firmware_chain.invalidate(con, "target", commit=True)
    prepared_chain = firmware_chain.prepare(con, run, root, image_id="target")
    case[3]["worklist_sha256"] = prepared_chain.worklist_sha256
    case[3]["chains"][0]["title"] = "New current graph after decision completion"
    chain_record(case, root=root)
    chain_check(case)
    with pytest.raises(decide.FirmwareDecideError):
        decide.verified_package(con, run, root, image_id="target")
