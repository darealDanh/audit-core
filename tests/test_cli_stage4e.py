"""Hunt CLI validates before I/O and returns only bounded lane aggregates."""
import json
import pathlib
import sqlite3
import subprocess
import sys

import pytest

import audit
from audit_core import db, hunt, workspace
from tests.test_hunt_prepare import add_target


ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *map(str, args)],
                          capture_output=True, text=True)


def snapshot(run):
    with db.connect(run / "audit.db") as con:
        return tuple(con.iterdump())


@pytest.fixture
def target_run(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    root = tmp_path / "PRIVATE_CARVED_ROOT"
    with db.connect(run / "audit.db") as con:
        add_target(con, run, root, ["a", "b", "c"])
    return run, root


def prepare(run, root, *flags):
    result = run_cli("hunt", "--run", run, "--root", root, "--json", *flags)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    return json.loads(result.stdout)


def worker_result(run, summary, lane):
    """Literal worker decisions; only provenance comes from actual worklists."""
    assignment = next(item for item in summary["lanes"] if item["lane"] == lane)
    index = json.loads(pathlib.Path(assignment["worklist_path"]).read_text())
    batch = index["batches"][0]
    candidate = {
        "candidate_id": "shell-1", "component_path": "c", "title": "PRIVATE_TITLE",
        "bug_class": "command injection", "surface_ids": [],
        "surface_context": "PRIVATE_CONTEXT: no dispatcher mapped; helper reads socket.",
        "attacker_position": "lan", "input_evidence": "PRIVATE_INPUT: attacker socket bytes at c:10.",
        "data_flow": "PRIVATE_FLOW: attacker bytes from socket c:10 reach system at c:20.",
        "dangerous_operation": "system", "operation_evidence": "PRIVATE_OPERATION: c:20 system(cmd).",
        "mitigations_checked": "PRIVATE_GUARDS: c:12 strips whitespace without shell quoting.",
        "lifecycle_required": "provisioned", "posture_required": "sta-lan", "auth_required": "pre-auth",
        "reachability": "evidenced", "state_evidence": "PRIVATE_STATE: socket opens before auth.",
        "confidence": 6, "impact_hypothesis": "PRIVATE_IMPACT: daemon shell execution may follow.",
        "blockers": [{"id": "uid", "question": "PRIVATE_QUESTION: daemon UID?",
            "settling_observation": "PRIVATE_OBSERVATION: inspect daemon UID.", "method": "hardware"}],
    }
    decisions = [
        {"path": "a", "disposition": "analyzed", "reason": "PRIVATE_CLEAR: reviewed all operations.", "candidates": []},
        {"path": "b", "disposition": "not_applicable", "reason": "PRIVATE_DATA: read-only banner text.", "candidates": []},
        {"path": "c", "disposition": "analyzed", "reason": None if lane == "l-sink" else "PRIVATE_DARK: no protocol or heap path.",
         "candidates": [candidate] if lane == "l-sink" else []},
    ]
    payload = {"schema_version": 1, "image_id": "target", "lane": lane,
        "manifest_sha256": summary["manifest_sha256"], "surface_snapshot_sha256": summary["surface_snapshot_sha256"],
        "worklist_sha256": assignment["worklist_sha256"], "batch_path": batch["path"],
        "batch_sha256": batch["sha256"], "decisions": decisions}
    path = run / (lane + "-worker.json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def assert_error(result, text, code=1):
    assert result.returncode == code
    assert result.stdout == ""
    assert text in result.stderr
    assert "Traceback" not in result.stderr


def test_help_exposes_hunt_modes_flags_and_lane_choices():
    result = run_cli("hunt", "--help")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    for flag in ("--run", "--root", "--image-id", "--sink-batch-size", "--dark-batch-size",
                 "--record", "--replace", "--check", "--lane", "--json", "l-sink", "l-dark"):
        assert flag in result.stdout


@pytest.mark.parametrize("flags,cause", [
    ([], "--root is required"),
    (["--check"], "--root is required"),
    (["--replace"], "--replace requires --record"),
    (["--check", "--root", "root", "--replace"], "--replace requires --record"),
    (["--root", "root", "--lane", "l-sink"], "--lane requires --check"),
    *[(["--record", "result.json", flag, value], flag) for flag, value in
      (("--root", "root"), ("--image-id", "target"), ("--lane", "l-dark"),
       ("--sink-batch-size", "50"), ("--dark-batch-size", "50"))],
    *[(["--check", "--root", "root", flag, "50"], flag) for flag in ("--sink-batch-size", "--dark-batch-size")],
    *[(["--root", "root", flag, value], "1 to 1000") for flag in
      ("--sink-batch-size", "--dark-batch-size") for value in ("0", "1001", "-1")],
])
def test_semantic_errors_precede_database_io(tmp_path, monkeypatch, capsys, flags, cause):
    missing = tmp_path / "missing"
    def forbidden_open(*args, **kwargs):
        raise AssertionError("invalid modes must not open a database")
    monkeypatch.setattr(audit, "_open_db", forbidden_open)
    assert audit.main(["hunt", "--run", str(missing), *flags]) == 1
    output = capsys.readouterr()
    assert output.out == "" and cause in output.err
    assert_error(run_cli("hunt", "--run", missing, *flags), cause)
    assert not missing.exists()


@pytest.mark.parametrize("flags,cause", [
    ([], "following arguments are required: --run"),
    (["--run", "unused", "--check", "--record", "result.json"], "not allowed with argument"),
    (["--run", "unused", "--record"], "expected one argument"),
    (["--run", "unused", "--lane", "other"], "invalid choice"),
    *[(["--run", "unused", flag, "many"], "invalid int value") for flag in
      ("--sink-batch-size", "--dark-batch-size")],
])
def test_usage_errors_exit_two(flags, cause):
    assert_error(run_cli("hunt", *flags), cause, 2)


def test_prepare_json_has_only_two_lane_aggregates_and_independent_sizes(target_run):
    run, root = target_run
    summary = prepare(run, root, "--image-id", "target", "--sink-batch-size", "1", "--dark-batch-size", "1000")
    assert set(summary) == {"image_id", "manifest_sha256", "surface_snapshot_sha256", "generation", "lanes"}
    assert summary["image_id"] == "target"
    assert len(summary["generation"]) == 64
    for lane, batches, size in zip(summary["lanes"], (3, 1), (1, 1000)):
        assert set(lane) == {"lane", "worklist_sha256", "unit_count", "batch_count", "worklist_path"}
        assert lane["unit_count"] == 3 and lane["batch_count"] == batches
        assert json.loads(pathlib.Path(lane["worklist_path"]).read_text())["batch_size"] == size
    assert [item["lane"] for item in summary["lanes"]] == ["l-sink", "l-dark"]


def test_prepare_human_output_is_exact_and_aggregate_only(target_run):
    run, root = target_run
    summary = prepare(run, root)
    result = run_cli("hunt", "--run", run, "--root", root)
    assert result.returncode == 0 and result.stderr == ""
    expected = [f"hunt prepared target: generation {summary['generation']}",
        f"manifest sha256 {summary['manifest_sha256']}", f"surface snapshot sha256 {summary['surface_snapshot_sha256']}"]
    for lane in summary["lanes"]:
        expected.extend([f"{lane['lane']}: 3 unit(s), 1 batch(es)",
                         f"worklist sha256 {lane['worklist_sha256']}", lane["worklist_path"]])
    assert result.stdout.splitlines() == expected
    assert str(root) not in result.stdout and "PRIVATE_" not in result.stdout


def lane_counts(lane):
    return {"image_id": "target", "lane": lane, "manifest_units": 3, "analyzed": 2,
        "not_applicable": 1, "not_audited": 0, "receipts": 1,
        "candidates": int(lane == "l-sink"), "blockers": int(lane == "l-sink"), "complete": True}


def lane_line(lane):
    count = int(lane == "l-sink")
    return (f"hunt target {lane}: 3 manifest unit(s), 2 analyzed, 1 not applicable, 0 not audited, "
            f"1 receipt(s), {count} candidate(s), {count} blocker(s), complete")


@pytest.mark.parametrize("json_output", [False, True])
def test_real_prepare_record_independent_lane_checks_and_final_gate(target_run, json_output):
    run, root = target_run
    summary = prepare(run, root)
    flags = ["--json"] if json_output else []
    for lane in ("l-sink", "l-dark"):
        worker = worker_result(run, summary, lane)
        recorded = run_cli("hunt", "--run", run, "--record", worker, *flags)
        assert recorded.returncode == 0 and recorded.stderr == "", recorded.stderr
        with db.connect(run / "audit.db") as con:
            artifact = con.execute("SELECT result_path FROM cba_hunt_receipts WHERE lane=?", (lane,)).fetchone()[0]
        assert pathlib.Path(artifact).is_file()
        count = int(lane == "l-sink")
        if json_output:
            assert json.loads(recorded.stdout) == {"image_id": "target", "lane": lane,
                "batch_path": "batch-0001.json", "unit_count": 3, "candidate_count": count,
                "blocker_count": count, "artifact_path": artifact}
        else:
            assert recorded.stdout.splitlines() == [f"hunt recorded target {lane} batch-0001.json: "
                f"3 unit(s), {count} candidate(s), {count} blocker(s)", artifact]
        before = snapshot(run)
        assert_error(run_cli("hunt", "--run", run, "--record", worker), "--replace")
        assert snapshot(run) == before
        checked = run_cli("hunt", "--run", run, "--check", "--root", root, "--lane", lane, *flags)
        assert checked.returncode == 0 and checked.stderr == "", checked.stderr
        expected = {"image_id": "target", "manifest_sha256": summary["manifest_sha256"],
            "surface_snapshot_sha256": summary["surface_snapshot_sha256"], "lanes": [lane_counts(lane)], "complete": True}
        if json_output:
            assert json.loads(checked.stdout) == expected
        else:
            assert checked.stdout.splitlines() == [lane_line(lane)]
        if lane == "l-sink":
            with db.connect(run / "audit.db") as con:
                assert [tuple(row) for row in con.execute("SELECT lane,status,completed_at IS NOT NULL FROM cba_hunt_runs ORDER BY lane")] == [
                    ("l-dark", "pending", 0), ("l-sink", "complete", 1)]
            before = snapshot(run)
            assert_error(run_cli("hunt", "--run", run, "--check", "--root", root), "already be complete")
            assert snapshot(run) == before
        for output in (recorded.stdout, checked.stdout):
            assert len(output) < 2048
            assert "PRIVATE_" not in output and str(root) not in output
            assert "system(cmd)" not in output and "shell-1" not in output
    final = run_cli("hunt", "--run", run, "--check", "--root", root, "--image-id", "target", *flags)
    assert final.returncode == 0 and final.stderr == "", final.stderr
    if json_output:
        expected["lanes"] = [lane_counts("l-sink"), lane_counts("l-dark")]
        assert json.loads(final.stdout) == expected
    else:
        assert final.stdout.splitlines() == [lane_line("l-sink"), lane_line("l-dark"), "hunt target: both lanes complete"]
    replacement = run_cli("hunt", "--run", run, "--record", worker, "--replace", "--json")
    assert replacement.returncode == 0 and replacement.stderr == ""
    with db.connect(run / "audit.db") as con:
        assert [tuple(row) for row in con.execute("SELECT lane,status,completed_at IS NOT NULL FROM cba_hunt_runs ORDER BY lane")] == [
            ("l-dark", "pending", 0), ("l-sink", "complete", 1)]


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
def test_read_sqlite_failure_is_fixed_diagnostic_and_preserves_state(target_run, monkeypatch, capsys, mode):
    run, root = target_run
    summary = prepare(run, root)
    worker = worker_result(run, summary, "l-sink")
    before = snapshot(run)
    original = audit._open_db
    def denied_read(path, **kwargs):
        con = original(path, **kwargs)
        con.set_authorizer(lambda action, name, *rest: sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and name == "cba_images" else sqlite3.SQLITE_OK)
        return con
    monkeypatch.setattr(audit, "_open_db", denied_read)
    flags = {"prepare": ["--root", str(root)], "record": ["--record", str(worker)],
             "check": ["--check", "--root", str(root)]}[mode]
    assert audit.main(["hunt", "--run", str(run), *flags]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == "hunt: database operation failed\n"
    assert snapshot(run) == before


def test_open_time_sqlite_failure_is_fixed_diagnostic(monkeypatch, capsys, tmp_path):
    failure = sqlite3.OperationalError("PRIVATE_SQL_DETAIL")
    monkeypatch.setattr(db, "connect", lambda *args, **kwargs: (_ for _ in ()).throw(failure))
    args = audit.build_parser().parse_args([
        "hunt", "--run", str(tmp_path / "run"), "--root", str(tmp_path / "root")])

    assert audit.cmd_hunt(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "hunt: database operation failed\n"


def test_unexpected_open_time_error_propagates(monkeypatch, capsys, tmp_path):
    failure = RuntimeError("unexpected connection defect")
    monkeypatch.setattr(db, "connect", lambda *args, **kwargs: (_ for _ in ()).throw(failure))
    args = audit.build_parser().parse_args([
        "hunt", "--run", str(tmp_path / "run"), "--root", str(tmp_path / "root")])

    with pytest.raises(RuntimeError) as caught:
        audit.cmd_hunt(args)
    assert caught.value is failure
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("error_type", [hunt.HuntError, db.DbError, OSError, sqlite3.OperationalError])
@pytest.mark.parametrize("chain", ["none", "cause", "context", "cycle"])
def test_expected_errors_are_escaped_capped_redacted_and_rollback(target_run, monkeypatch, capsys, error_type, chain):
    run, root = target_run
    before = snapshot(run)
    failure = error_type(f"Cannot use {root}: private\n\x1b\u202e" + "x" * 1000)
    if chain != "none":
        middle = RuntimeError("wrapper")
        failure.__cause__ = middle
        driver = sqlite3.OperationalError("PRIVATE_SQL_COLUMN")
        if chain == "cause":
            middle.__cause__ = driver
        else:
            middle.__context__ = driver
            if chain == "cycle":
                middle.__cause__ = failure
    con = db.connect(run / "audit.db")
    monkeypatch.setattr(audit, "_open_db", lambda *args, **kwargs: con)
    def fail_prepare(*args, **kwargs):
        con.execute("UPDATE cba_surface_runs SET status='pending'")
        raise failure
    monkeypatch.setattr(audit.hunt_mod, "prepare", fail_prepare)
    args = audit.build_parser().parse_args(["hunt", "--run", str(run), "--root", str(root)])
    assert audit.cmd_hunt(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    if chain != "none" or issubclass(error_type, sqlite3.Error):
        assert output.err == "hunt: database operation failed\n"
    else:
        prefix = r"Cannot use <root>: private\n\u001b\u202e"
        assert output.err == prefix + "x" * (509 - len(prefix)) + "...\n"
    assert snapshot(run) == before
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        con.execute("SELECT 1")


@pytest.mark.parametrize("error_type", [RuntimeError, AssertionError, ValueError])
def test_unexpected_errors_propagate_from_cmd_hunt_after_rollback(target_run, monkeypatch, capsys, error_type):
    run, root = target_run
    before = snapshot(run)
    con = db.connect(run / "audit.db")
    monkeypatch.setattr(audit, "_open_db", lambda *args, **kwargs: con)
    failure = error_type("unexpected defect")
    failure.__cause__ = sqlite3.OperationalError("driver detail does not make this expected")
    def fail_prepare(*args, **kwargs):
        con.execute("UPDATE cba_surface_runs SET status='pending'")
        raise failure
    monkeypatch.setattr(audit.hunt_mod, "prepare", fail_prepare)
    args = audit.build_parser().parse_args(["hunt", "--run", str(run), "--root", str(root)])
    with pytest.raises(error_type) as caught:
        audit.cmd_hunt(args)
    assert caught.value is failure
    assert capsys.readouterr() == ("", "")
    assert snapshot(run) == before


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
def test_missing_and_corrupt_databases_are_expected_errors(tmp_path, mode):
    run = tmp_path / "missing"
    flags = {"prepare": ["--root", tmp_path], "record": ["--record", "result.json"],
             "check": ["--check", "--root", tmp_path]}[mode]
    assert_error(run_cli("hunt", "--run", run, *flags), "audit.py init")
    assert not run.exists()
    run.mkdir()
    (run / "audit.db").write_bytes(b"not SQLite")
    result = run_cli("hunt", "--run", run, *flags)
    assert_error(result, "hunt: database operation failed")
    assert result.stderr == "hunt: database operation failed\n"


@pytest.mark.parametrize("damage", ["stale-root", "missing-root", "malformed-result", "missing-result"])
def test_domain_refusals_preserve_status_and_timestamps(target_run, damage):
    run, root = target_run
    prepare(run, root)
    before = snapshot(run)
    worker = run / "bad.json"
    if damage == "stale-root":
        (root / "a").write_bytes(b"other\n")
        flags = ["--check", "--root", root, "--lane", "l-sink"]
    elif damage == "missing-root":
        flags = ["--check", "--root", root / "absent", "--lane", "l-sink"]
    else:
        if damage == "malformed-result":
            worker.write_text("{")
        flags = ["--record", worker]
    result = run_cli("hunt", "--run", run, *flags)
    assert_error(result, "")
    assert len(result.stderr) <= 513 and str(root) not in result.stderr
    assert snapshot(run) == before
