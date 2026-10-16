"""Surface CLI keeps semantic evidence on disk and validates modes before I/O."""
import json
import pathlib
import sqlite3
import subprocess
import sys

import pytest

import audit
from audit_core import db, surface, workspace


ROOT = pathlib.Path(__file__).resolve().parent.parent
HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *map(str, args)],
                          capture_output=True, text=True)


def seed_run(tmp_path, paths):
    run = workspace.init_run(tmp_path / "project", timestamp="20261014-000000")
    root = tmp_path / "root"
    root.mkdir()
    con = db.connect(run / "audit.db")
    try:
        db.put(con, "cba_images", {"id": "target", "role": "target", "vendor": "v",
            "model": "m", "version": "1", "path": "firmware.bin", "sha256": "a" * 64})
        for path in paths:
            (root / path).write_bytes(b"hello\n")
            db.put(con, "cba_firmware_files", {"image_id": "target", "path": path,
                "kind": "file", "size": "6", "sha256": HELLO})
            db.put(con, "cba_inventory", {"unit": path, "kind": "file", "size": "6"})
    finally:
        con.close()
    return run, root


@pytest.fixture
def target_run(tmp_path):
    return seed_run(tmp_path, ["banner", "http", "relay"])


def prepare(run, root, *args):
    result = run_cli("surface", "--run", run, "--root", root, "--json", *args)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    return json.loads(result.stdout)


def write_result(run, summary, *, claims=True):
    """Bind literal decisions to real work-list provenance, without core builders."""
    index = json.loads(pathlib.Path(summary["worklist_path"]).read_text())
    descriptor = index["batches"][0]
    batch = json.loads(pathlib.Path(summary["worklist_path"]).with_name(descriptor["path"]).read_text())
    decisions = [{"path": unit["path"], "state": "analyzed",
        "reason": "No dispatcher in this unit.", "surfaces": [], "unknowns": []}
        for unit in batch["units"]]
    if claims:
        for decision in decisions:
            path = decision["path"]
            if path == "banner":
                decision.update(state="not_audited", reason="generated")
                continue
            decision.update(reason=None, surfaces=[{
                "surface_id": path, "component_path": path, "entry_point": "GET /status",
                "protocol": "http", "dispatch_path": "router -> status", "handler": "status",
                "lifecycle_required": "provisioned", "posture_required": "unknown" if path == "relay" else "sta-lan",
                "auth_required": "pre-auth", "reachability": "evidenced",
                "reach_evidence": "PRIVATE_EVIDENCE: router calls status before auth"}],
                unknowns=[{"id": path + "-posture", "component_path": path, "surface_id": path,
                    "field": "posture", "question": "PRIVATE_QUESTION: which interface binds?",
                    "settling_observation": "Observe the interface bound after provisioning.",
                    "method": "hardware", "status": "open" if path == "relay" else "resolved",
                    "resolution": None if path == "relay" else "LAN only",
                    "evidence": None if path == "relay" else "PRIVATE_RESOLUTION: bind selects LAN"}])
    payload = {"schema_version": 1, "image_id": "target",
        "manifest_sha256": summary["manifest_sha256"], "worklist_sha256": summary["worklist_sha256"],
        "batch_path": descriptor["path"], "batch_sha256": descriptor["sha256"], "decisions": decisions}
    result = run / "worker-result.json"
    result.write_text(json.dumps(payload), encoding="utf-8")
    return result


def assert_error(result, cause, *, code=1):
    assert result.returncode == code
    assert result.stdout == ""
    assert cause in result.stderr
    assert "Traceback" not in result.stderr
    assert "sqlite3." not in result.stderr


def test_surface_help_exposes_all_modes_and_flags():
    result = run_cli("surface", "--help")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    for flag in ("--run", "--root", "--image-id", "--batch-size", "--record", "--check", "--replace", "--json"):
        assert flag in result.stdout


@pytest.mark.parametrize("flags,cause,code", [
    ([], "--root is required", 1),
    (["--replace"], "--replace requires --record", 1),
    (["--check", "--replace"], "--replace requires --record", 1),
    (["--check", "--root", "root"], "--root is only valid for prepare", 1),
    (["--check", "--batch-size", "50"], "--batch-size is only valid for prepare", 1),
    (["--record", "result.json", "--root", "root"], "--root is only valid for prepare", 1),
    (["--record", "result.json", "--batch-size", "50"], "--batch-size is only valid for prepare", 1),
    (["--record", "result.json", "--image-id", "target"], "--image-id is not valid with --record", 1),
    (["--root", "root", "--batch-size", "0"], "batch_size must be an integer from 1 to 1000", 1),
    (["--root", "root", "--batch-size", "1001"], "batch_size must be an integer from 1 to 1000", 1),
    (["--check", "--record", "result.json"], "not allowed with argument", 2),
])
def test_invalid_modes_refuse_before_opening_missing_run(tmp_path, flags, cause, code):
    missing = tmp_path / "missing"
    result = run_cli("surface", "--run", missing, *flags)
    assert_error(result, cause, code=code)
    assert "audit.py init" not in result.stderr
    assert not missing.exists()


@pytest.mark.parametrize("args,cause", [
    (["surface"], "following arguments are required: --run"),
    (["surface", "--run", "unused", "--record"], "argument --record: expected one argument"),
    (["surface", "--run", "unused", "--root", "root", "--batch-size", "many"], "invalid int value"),
])
def test_missing_or_malformed_arguments_are_usage_errors(args, cause):
    assert_error(run_cli(*args), cause, code=2)


def test_default_prepare_human_output_has_exact_aggregate_lines(target_run):
    run, root = target_run
    result = run_cli("surface", "--run", run, "--root", root)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    with db.connect(run / "audit.db") as con:
        row = dict(con.execute("SELECT * FROM cba_surface_runs").fetchone())
    assert result.stdout.splitlines() == [
        "surface prepared target: 3 unit(s), 1 batch(es)",
        f"manifest sha256 {row['manifest_sha256']}",
        f"worklist sha256 {row['worklist_sha256']}", row["worklist_path"]]
    assert row["status"] == "pending"
    index = json.loads(pathlib.Path(row["worklist_path"]).read_text())
    assert index["batch_size"] == 50


def test_prepare_json_is_summary_only_and_selects_explicit_target(target_run):
    run, root = target_run
    with db.connect(run / "audit.db") as con:
        db.put(con, "cba_images", {"id": "extra", "role": "target", "vendor": "v",
            "model": "m", "version": "2", "path": "extra.bin", "sha256": "b" * 64})
    summary = prepare(run, root, "--image-id", "target", "--batch-size", "2")
    assert summary == {"image_id": "target", "manifest_sha256": summary["manifest_sha256"],
        "worklist_sha256": summary["worklist_sha256"], "unit_count": 3, "batch_count": 2,
        "worklist_path": summary["worklist_path"]}
    assert len(summary["manifest_sha256"]) == len(summary["worklist_sha256"]) == 64
    assert pathlib.Path(summary["worklist_path"]).is_file()


@pytest.mark.parametrize("json_output", [False, True])
def test_record_and_check_render_only_bounded_aggregates(target_run, json_output):
    run, root = target_run
    summary = prepare(run, root)
    result_path = write_result(run, summary)
    output_flags = ["--json"] if json_output else []
    recorded = run_cli("surface", "--run", run, "--record", result_path, *output_flags)
    assert recorded.returncode == 0, recorded.stderr
    assert recorded.stderr == ""
    with db.connect(run / "audit.db") as con:
        artifact = con.execute("SELECT artifact_path FROM cba_firmware_surfaces LIMIT 1").fetchone()[0]
        assert con.execute("SELECT status FROM cba_surface_runs").fetchone()[0] == "pending"
    assert pathlib.Path(artifact).is_file()
    if json_output:
        assert json.loads(recorded.stdout) == {"image_id": "target", "batch_path": "batch-0001.json",
            "unit_count": 3, "surface_count": 2, "unknown_count": 2, "artifact_path": artifact}
    else:
        assert recorded.stdout.splitlines() == [
            "surface recorded target batch-0001.json: 3 unit(s), 2 surface(s), 2 unknown(s)", artifact]
    checked = run_cli("surface", "--run", run, "--check", "--image-id", "target", *output_flags)
    assert checked.returncode == 0, checked.stderr
    assert checked.stderr == ""
    if json_output:
        assert json.loads(checked.stdout) == {"image_id": "target", "manifest_units": 3,
            "analyzed": 2, "not_audited": 1, "surfaces": 2, "open_unknowns": 1,
            "resolved_unknowns": 1, "complete": True}
    else:
        assert checked.stdout.splitlines() == [
            "surface target: 3 manifest unit(s), 2 analyzed, 1 not audited, 2 surface(s), "
            "1 open unknown(s), 1 resolved unknown(s), complete"]
    for output in (recorded.stdout, checked.stdout):
        assert len(output) < 1024
        assert "PRIVATE_" not in output and "GET /status" not in output
    with db.connect(run / "audit.db") as con:
        assert tuple(con.execute("SELECT status,completed_at IS NOT NULL FROM cba_surface_runs").fetchone()) == ("complete", 1)


def test_duplicate_record_refuses_and_replace_reopens_completed_run(target_run):
    run, root = target_run
    result_path = write_result(run, prepare(run, root))
    args = ("surface", "--run", run, "--record", result_path, "--json")
    first = run_cli(*args)
    assert first.returncode == 0, first.stderr
    assert_error(run_cli(*args), "--replace")
    assert run_cli("surface", "--run", run, "--check").returncode == 0
    replacement = run_cli(*args, "--replace")
    assert replacement.returncode == 0, replacement.stderr
    assert replacement.stderr == ""
    assert json.loads(replacement.stdout) == json.loads(first.stdout)
    with db.connect(run / "audit.db") as con:
        assert tuple(con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()) == ("pending", None)


@pytest.mark.parametrize("case,cause", [
    ("stale-root", "Live root differs"),
    ("no-preparation", "No prepared surface run"),
    ("malformed-result", "Cannot read surface JSON"),
    ("missing-result", "Cannot read"),
    ("partial", "coverage decision"),
])
def test_domain_errors_are_named_without_tracebacks(target_run, case, cause):
    run, root = target_run
    if case == "stale-root":
        (root / "http").write_bytes(b"other\n")
        flags = ["--root", root]
    elif case == "no-preparation":
        flags = ["--check"]
    elif case in ("malformed-result", "missing-result"):
        result = run / "bad.json"
        if case == "malformed-result":
            result.write_text("{")
        flags = ["--record", result]
    else:
        prepare(run, root)
        flags = ["--check"]
    assert_error(run_cli("surface", "--run", run, *flags), cause)


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
def test_missing_or_corrupt_database_is_a_named_db_error(tmp_path, mode):
    run = tmp_path / "missing"
    flags = {"prepare": ["--root", tmp_path], "record": ["--record", "result.json"], "check": ["--check"]}[mode]
    assert_error(run_cli("surface", "--run", run, *flags), "audit.py init")
    run.mkdir()
    (run / "audit.db").write_bytes(b"not a SQLite database")
    result = run_cli("surface", "--run", run, *flags)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "surface: database operation failed\n"


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
def test_read_side_sqlite_failures_are_translated_at_the_module_boundary(target_run, monkeypatch, capsys, mode):
    # A real authorizer produces a read failure after connect's schema checks.
    run, root = target_run
    summary = prepare(run, root)
    result_path = write_result(run, summary)
    original = audit._open_db
    def denied_read(path, **kwargs):
        con = original(path, **kwargs)
        con.set_authorizer(lambda action, name, column, database, source:
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and name == "cba_images" else sqlite3.SQLITE_OK)
        return con
    monkeypatch.setattr(audit, "_open_db", denied_read)
    flags = {"prepare": ["--root", str(root)], "record": ["--record", str(result_path)], "check": ["--check"]}[mode]
    assert audit.main(["surface", "--run", str(run), *flags]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "surface: database operation failed\n"


@pytest.mark.parametrize("error_type", [surface.SurfaceError, db.DbError])
@pytest.mark.parametrize("chain", ["cause", "context", "nested", "both", "cycle"])
def test_sql_causes_are_sanitized_through_every_wrapper_and_connection_closes(
        target_run, monkeypatch, capsys, error_type, chain):
    # A wrapper's driver details must not escape even behind mixed/cyclic links.
    run, root = target_run
    with sqlite3.connect(":memory:") as scratch:
        try:
            scratch.execute("SELECT private_column FROM private_sql_identifier")
        except sqlite3.Error as sql_error:
            driver_error = sql_error
    failure = error_type("Surface wrapper: " + str(driver_error))
    if chain == "cause":
        failure.__cause__ = driver_error
    elif chain == "context":
        failure.__context__ = driver_error
    elif chain == "nested":
        middle = RuntimeError("intermediate: " + str(driver_error))
        middle.__context__ = driver_error
        failure.__cause__ = middle
    elif chain == "both":
        failure.__cause__ = ValueError("unrelated explicit cause")
        failure.__context__ = driver_error
    else:
        middle = RuntimeError("intermediate cyclic wrapper")
        failure.__cause__ = middle
        middle.__cause__ = failure
        middle.__context__ = driver_error
    opened = []
    original = audit._open_db
    def capture_connection(path, **kwargs):
        con = original(path, **kwargs)
        opened.append(con)
        return con
    def fail_prepare(*args, **kwargs):
        raise failure
    monkeypatch.setattr(audit, "_open_db", capture_connection)
    monkeypatch.setattr(audit.surface_mod, "prepare", fail_prepare)
    assert audit.main(["surface", "--run", str(run), "--root", str(root)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "surface: database operation failed\n"
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        opened[0].execute("SELECT 1")


@pytest.mark.parametrize("error_type", [surface.SurfaceError, db.DbError])
@pytest.mark.parametrize("chain", ["none", "nested", "cycle"])
def test_non_sql_domain_errors_retain_their_informative_message(
        target_run, monkeypatch, capsys, error_type, chain):
    run, root = target_run
    message = "Target private_sql_identifier needs an acquired image; no SQLite claim."
    failure = error_type(message)
    if chain != "none":
        middle = ValueError("ordinary validation failure")
        failure.__context__ = middle
        if chain == "cycle":
            middle.__cause__ = failure
    def fail_prepare(*args, **kwargs):
        raise failure
    monkeypatch.setattr(audit.surface_mod, "prepare", fail_prepare)
    assert audit.main(["surface", "--run", str(run), "--root", str(root)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == message + "\n"


@pytest.mark.parametrize("json_output", [False, True])
def test_201_unit_output_never_prints_unit_lists(tmp_path, json_output):
    run, root = seed_run(tmp_path, [f"unit-{n:03}" for n in range(201)])
    summary = prepare(run, root, "--batch-size", "1000")
    assert summary["unit_count"] == 201 and summary["batch_count"] == 1
    result_path = write_result(run, summary, claims=False)
    flags = ["--json"] if json_output else []
    for mode in (["--root", root, "--batch-size", "1000"], ["--record", result_path], ["--check"]):
        result = run_cli("surface", "--run", run, *mode, *flags)
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""
        assert len(result.stdout) < 1024
        assert "unit-000" not in result.stdout and "unit-200" not in result.stdout
        if mode == ["--check"] and json_output:
            assert json.loads(result.stdout) == {"image_id": "target", "manifest_units": 201,
                "analyzed": 201, "not_audited": 0, "surfaces": 0, "open_unknowns": 0,
                "resolved_unknowns": 0, "complete": True}
