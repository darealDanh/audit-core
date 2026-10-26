"""Chain CLI separates routes and keeps firmware evidence behind file boundaries."""
import json
import pathlib
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

import audit
from audit_core import db, firmware_chain, firmware_chain_results, workspace
from tests.test_firmware_chain_prepare import empty_review, prepared  # noqa: F401
from tests.test_firmware_chain_validation import graph_case  # noqa: F401

ROOT = pathlib.Path(__file__).resolve().parent.parent
PREPARE_FIELDS = {"image_id", "manifest_sha256", "surface_snapshot_sha256",
    "candidate_snapshot_sha256", "generation", "worklist_path", "worklist_sha256",
    "finding_count", "surface_count", "unknown_count", "pivot_count"}
RECORD_FIELDS = {"image_id", "finding_count", "disposition_count", "blocker_count",
    "chain_count", "edge_count", "complete_chains", "blocked_chains", "artifact_path"}
CHECK_FIELDS = {"image_id", "finding_count", "disposition_count", "blocker_count",
    "complete_chains", "blocked_chains", "artifact_path", "complete", "chain_count"}


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *map(str, args)],
                          capture_output=True, text=True)


@pytest.mark.parametrize("flags", [
    [], ["--compose", "C"], ["--run", "unused"],
    ["--db", "unused", "--run", "unused", "--prepare", "--root", "root"],
    ["--run", "unused", "--prepare", "--check", "--root", "root"],
    ["--run", "unused", "--prepare", "--record", "result"],
    ["--run", "unused", "--record", "result", "--check"],
    *[["--db", "unused", *flags] for flags in (["--prepare"], ["--record", "r"],
       ["--check"], ["--root", "root"], ["--image-id", "i"])],
    *[["--run", "unused", "--prepare", "--root", "root", flag, value]
      for flag, value in (("--compose", "C"), ("--findings", "a,b"),
       ("--attacker-position", "LAN"), ("--completeness", "complete"),
       ("--pre-auth", "yes"), ("--blocking-unknowns", "unknown"))],
    ["--run", "unused", "--record"], ["--prepare", "--root", "root"],
])
def test_route_syntax_errors_exit_two_before_database_access(tmp_path, monkeypatch, capsys, flags):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    flags = [str(tmp_path / "unused") if f == "unused" else f for f in flags]
    with pytest.raises(SystemExit) as exc:
        audit.main(["chain", *flags])
    assert exc.value.code == 2
    out = capsys.readouterr()
    assert out.out == "" and "error:" in out.err
    result = run_cli("chain", *flags)
    assert result.returncode == 2 and result.stdout == "" and "Traceback" not in result.stderr
    assert not (tmp_path / "unused").exists()


@pytest.mark.parametrize("flags,message", [
    (["--prepare"], "--root is required"), (["--check"], "--root is required"),
    (["--prepare", "--root", "root", "--replace"], "--replace requires --record"),
    (["--check", "--root", "root", "--replace"], "--replace requires --record"),
    (["--record", "result", "--root", "root"], "--root"),
    (["--record", "result", "--image-id", "target"], "--image-id"),
])
def test_semantic_constraints_exit_one_before_database_access(tmp_path, monkeypatch, capsys, flags, message):
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    assert audit.main(["chain", "--run", str(tmp_path / "missing"), *flags]) == 1
    out = capsys.readouterr()
    assert out.out == "" and message in out.err
    assert not (tmp_path / "missing").exists()


def mode_flags(mode, root):
    return ["--record", "~/result.json", "--replace"] if mode == "record" else ["--" + mode, "--root", str(root), "--image-id", "雪:%_|i"]


def summary(mode, root):
    secret = "PRIVATE member edge blocker explanation"
    common = dict(image_id="雪:%_|i\n\x1b" + "x" * 800, finding_count=4,
        chains=(SimpleNamespace(chain_id=secret, member_ids=[secret], edges=[secret]),),
        findings=[secret], blockers=[secret], explanation=secret)
    if mode == "prepare":
        common.update(manifest_sha256="a" * 64, surface_snapshot_sha256="b" * 64,
            candidate_snapshot_sha256="c" * 64, generation="d" * 64,
            worklist_sha256="d" * 64, worklist_path=str(root / "工作\n" / ("x" * 600)),
            surface_count=3, unknown_count=2, pivot_count=1)
    else:
        common.update(disposition_count=4, blocker_count=1, complete_chains=0,
            blocked_chains=1, artifact_path=str(root / "结果\n" / ("x" * 600)))
        if mode == "record":
            common.update(chain_count=1, edge_count=2)
        else:
            common.update(complete=True)
    return SimpleNamespace(**common)


@pytest.mark.parametrize("mode,fields", [("prepare", PREPARE_FIELDS), ("record", RECORD_FIELDS), ("check", CHECK_FIELDS)])
@pytest.mark.parametrize("json_output", [False, True])
def test_exact_delegation_and_lossless_scalar_whitelist(tmp_path, monkeypatch, capsys, mode, fields, json_output):
    root = tmp_path / "PRIVATE_ROOT"
    run = tmp_path / "dữ-liệu"
    con = sqlite3.connect(":memory:")
    def opened(path, **kwargs):
        assert path == str(run / "audit.db")
        assert not kwargs.get("read_only", False)
        assert callable(kwargs["error_message"])
        return con
    monkeypatch.setattr(audit, "_open_db", opened)
    result = summary(mode, root)
    def delegated(connection, run_dir, *args, **kwargs):
        assert connection is con and run_dir == run
        if mode == "record":
            assert args == (pathlib.Path("~/result.json").expanduser(),)
            assert kwargs == {"replace": True}
        else:
            assert args == (root,) and kwargs == {"image_id": "雪:%_|i"}
        return result
    module = firmware_chain_results if mode == "record" else firmware_chain
    monkeypatch.setattr(module, mode, delegated)
    flags = mode_flags(mode, root)
    # Record has no supplied root to redact; use a root-free artifact in that mode.
    if mode == "record":
        result.artifact_path = "结果\n" + "x" * 800
    assert audit.main(["chain", "--run", str(run), *flags, *(["--json"] if json_output else [])]) == 0
    out = capsys.readouterr()
    assert out.err == "" and "PRIVATE member" not in out.out
    if json_output:
        payload = json.loads(out.out)
        assert set(payload) == fields
        assert payload == {f: (1 if f == "chain_count" and mode == "check" else getattr(result, f)) for f in fields}
        assert all(isinstance(value, (str, int, bool)) for value in payload.values())
    else:
        assert out.out.isascii() and str(root) not in out.out
        assert len(out.out) < 4096
        assert all(len(line) <= 512 for line in out.out.splitlines())
    with pytest.raises(sqlite3.ProgrammingError):
        con.execute("SELECT 1")


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("error_type", [firmware_chain.FirmwareChainError, db.DbError, OSError, sqlite3.OperationalError])
@pytest.mark.parametrize("link", [None, "cause", "context", "cycle"])
def test_expected_error_chains_are_fixed_or_bounded_and_transactions_rollback(tmp_path, monkeypatch, capsys, mode, error_type, link):
    path = tmp_path / "audit.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE durable(value)")
    con.commit()
    root = tmp_path / "PRIVATE_ROOT"
    failure = error_type(f"Cannot use {root}: private\n\x1b雪" + "x" * 1000)
    if link:
        wrapper = RuntimeError("PRIVATE_SQL wrapper")
        failure.__cause__ = wrapper
        if link == "cause":
            wrapper.__cause__ = sqlite3.OperationalError("PRIVATE_SQL")
        else:
            wrapper.__context__ = sqlite3.OperationalError("PRIVATE_SQL")
            if link == "cycle":
                wrapper.__cause__ = failure
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    def fail(*args, **kwargs):
        con.execute("INSERT INTO durable VALUES ('partial')")
        raise failure
    monkeypatch.setattr(firmware_chain_results if mode == "record" else firmware_chain, mode, fail)
    assert audit.main(["chain", "--run", str(tmp_path), *mode_flags(mode, root)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    if link or error_type is sqlite3.OperationalError:
        assert out.err == "chain: database operation failed\n"
    else:
        assert len(out.err) <= 513 and out.err.isascii() and out.err.endswith("...\n")
        if mode != "record":
            assert str(root) not in out.err and "<root>" in out.err
    with sqlite3.connect(path) as checked:
        assert checked.execute("SELECT * FROM durable").fetchall() == []
    with pytest.raises(sqlite3.ProgrammingError):
        con.execute("SELECT 1")


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("error_type", [RuntimeError, AssertionError, ValueError])
def test_unexpected_errors_propagate_after_rollback_and_close(tmp_path, monkeypatch, capsys, mode, error_type):
    con = sqlite3.connect(tmp_path / "audit.db")
    con.execute("CREATE TABLE durable(value)")
    con.commit()
    failure = error_type("unexpected defect")
    failure.__cause__ = sqlite3.OperationalError("PRIVATE_SQL")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    def fail(*args, **kwargs):
        con.execute("INSERT INTO durable VALUES ('partial')")
        raise failure
    monkeypatch.setattr(firmware_chain_results if mode == "record" else firmware_chain, mode, fail)
    with pytest.raises(error_type) as caught:
        audit.main(["chain", "--run", str(tmp_path), *mode_flags(mode, tmp_path / "root")])
    assert caught.value is failure and capsys.readouterr() == ("", "")
    with sqlite3.connect(tmp_path / "audit.db") as checked:
        assert checked.execute("SELECT * FROM durable").fetchall() == []
    with pytest.raises(sqlite3.ProgrammingError):
        con.execute("SELECT 1")


@pytest.mark.parametrize("error_type", [db.DbError, OSError, sqlite3.OperationalError, RuntimeError])
def test_database_open_translates_expected_errors_only(tmp_path, monkeypatch, capsys, error_type):
    failure = error_type("open failure\n雪")
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(db, "connect", fail)
    flags = ["chain", "--run", str(tmp_path), "--prepare", "--root", "root"]
    if error_type is RuntimeError:
        with pytest.raises(RuntimeError) as caught:
            audit.main(flags)
        assert caught.value is failure and capsys.readouterr() == ("", "")
    else:
        assert audit.main(flags) == 1
        out = capsys.readouterr()
        assert out.out == ""
        assert out.err == ("chain: database operation failed\n" if error_type is sqlite3.OperationalError else "open failure\\n\\u96ea\n")


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("corrupt", [False, True])
def test_missing_and_corrupt_database_exit_one_without_tracebacks(tmp_path, mode, corrupt):
    run = tmp_path / "missing"
    if corrupt:
        run.mkdir()
        (run / "audit.db").write_text("not sqlite")
    result = run_cli("chain", "--run", run, *mode_flags(mode, tmp_path / "root"))
    assert result.returncode == 1 and result.stdout == "" and "Traceback" not in result.stderr
    assert result.stderr.isascii() and len(result.stderr) <= 513
    if corrupt:
        assert result.stderr == "chain: database operation failed\n"
    else:
        assert not run.exists()


@pytest.mark.parametrize("json_output", [False, True])
def test_real_prepare_record_check_and_replace_preserve_scalar_contract(graph_case, json_output):
    con, run, root, value, _ = graph_case
    flags = ["--json"] if json_output else []
    prepared = run_cli("chain", "--run", run, "--prepare", "--root", root, *flags)
    assert prepared.returncode == 0 and prepared.stderr == ""
    if json_output:
        payload = json.loads(prepared.stdout)
        assert set(payload) == PREPARE_FIELDS
        assert payload["finding_count"] == 4 and pathlib.Path(payload["worklist_path"]).is_file()
    source = run / "worker.json"
    source.write_text(json.dumps(value))
    recorded = run_cli("chain", "--run", run, "--record", source, *flags)
    assert recorded.returncode == 0 and recorded.stderr == ""
    duplicate = run_cli("chain", "--run", run, "--record", source)
    assert duplicate.returncode == 1 and "replace" in duplicate.stderr
    replacement = run_cli("chain", "--run", run, "--record", source, "--replace", *flags)
    assert replacement.returncode == 0 and replacement.stderr == "" and replacement.stdout == recorded.stdout
    checked = run_cli("chain", "--run", run, "--check", "--root", root, *flags)
    assert checked.returncode == 0 and checked.stderr == ""
    if json_output:
        assert set(json.loads(recorded.stdout)) == RECORD_FIELDS
        payload = json.loads(checked.stdout)
        assert set(payload) == CHECK_FIELDS
        assert payload["finding_count"] == payload["disposition_count"] == 4
        assert payload["chain_count"] == payload["complete_chains"] == 1 and payload["complete"]
        assert pathlib.Path(payload["artifact_path"]).is_file()
    for result in (prepared, recorded, checked):
        assert str(root) not in result.stdout and len(result.stdout) < 4096
        assert "Startup control" not in result.stdout and "LAN attacker" not in result.stdout
    before = tuple(con.iterdump())
    repeated = run_cli("chain", "--run", run, "--check", "--root", root, *flags)
    assert repeated.returncode == 0 and repeated.stderr == "" and repeated.stdout == checked.stdout
    assert tuple(con.iterdump()) == before


@pytest.mark.parametrize("layout", ["unicode", "long-path", "root-prefix", "dot-root"])
def test_empty_workflow_roundtrips_unicode_ids_and_reusable_artifact_paths(tmp_path, monkeypatch, layout):
    project = tmp_path / "dữ-liệu"
    root = tmp_path / "carved"
    if layout == "long-path":
        while len(str(project)) < 420:
            project /= "d" * min(180, 420 - len(str(project)))
    elif layout == "root-prefix":
        project = tmp_path / "carved-run" / "dữ-liệu"
    run = workspace.init_run(project)
    image_id = '路由器:%_|雪\n"'
    with db.connect(run / "audit.db") as con:
        empty_review(con, run, root, image_id)
    if layout == "dot-root":
        monkeypatch.chdir(root)
    input_root = "." if layout == "dot-root" else root
    prepared = run_cli("chain", "--run", run, "--prepare", "--root", input_root, "--image-id", image_id, "--json")
    assert prepared.returncode == 0 and prepared.stderr == ""
    prep = json.loads(prepared.stdout)
    assert prep["image_id"] == image_id and prep["finding_count"] == 0
    assert pathlib.Path(prep["worklist_path"]).is_file()
    source = run / "empty.json"
    source.write_text(json.dumps(dict(schema_version=1, image_id=image_id,
        candidate_snapshot_sha256=prep["candidate_snapshot_sha256"], worklist_sha256=prep["worklist_sha256"],
        dispositions=[], chains=[], blockers=[])))
    recorded = run_cli("chain", "--run", run, "--record", source, "--json")
    checked = run_cli("chain", "--run", run, "--check", "--root", input_root, "--image-id", image_id, "--json")
    for result in (recorded, checked):
        assert result.returncode == 0 and result.stderr == ""
        payload = json.loads(result.stdout)
        assert payload["image_id"] == image_id and payload["chain_count"] == 0
        assert pathlib.Path(payload["artifact_path"]).is_file()


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("damage", ["stale-root", "missing-root", "missing-result", "malformed-result"])
def test_real_domain_errors_are_bounded_and_preserve_durable_state(graph_case, mode, damage):
    con, run, root, value, _ = graph_case
    source = run / "worker.json"
    source.write_text(json.dumps(value))
    if mode == "check":
        firmware_chain_results.record(con, run, source)
    before = tuple(con.iterdump())
    if damage in ("missing-result", "malformed-result"):
        flags = ["--record", run / "missing.json"]
        if damage == "malformed-result":
            source.write_text("{}")
            flags = ["--record", source]
    elif damage == "stale-root":
        (root / "a").write_bytes(b"changed")
        flags = ["--prepare" if mode == "record" else "--" + mode, "--root", root]
    else:
        flags = ["--prepare" if mode == "record" else "--" + mode, "--root", root / "missing"]
    result = run_cli("chain", "--run", run, *flags)
    assert result.returncode == 1 and result.stdout == "" and "Traceback" not in result.stderr
    assert result.stderr.isascii() and len(result.stderr) <= 513 and str(root) not in result.stderr
    assert tuple(con.iterdump()) == before


@pytest.mark.parametrize("root_argument", ["PRIVATE_ROOT", "."])
def test_diagnostics_redact_relative_root_without_replacing_unrelated_dots(tmp_path, monkeypatch, capsys, root_argument):
    monkeypatch.chdir(tmp_path)
    root = pathlib.Path(root_argument)
    con = sqlite3.connect(":memory:")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    def fail(*args, **kwargs):
        raise firmware_chain.FirmwareChainError(
            f"Cannot read {root / 'input.bin'} or {root.absolute() / 'other.bin'}.")
    monkeypatch.setattr(firmware_chain, "prepare", fail)
    assert audit.main(["chain", "--run", str(tmp_path), "--prepare", "--root", root_argument]) == 1
    out = capsys.readouterr()
    if root_argument == "PRIVATE_ROOT":
        assert out.err == "Cannot read <root>/input.bin or <root>/other.bin.\n"
    else:
        assert out.err == "Cannot read input.bin or <root>/other.bin.\n"


@pytest.mark.parametrize("stage", ["rollback", "close"])
def test_sqlite_cleanup_failures_have_fixed_diagnostic_and_connection_is_released(tmp_path, monkeypatch, capsys, stage):
    class CleanupFailure(sqlite3.Connection):
        closed = False
        def rollback(self):
            super().rollback()
            if stage == "rollback":
                raise sqlite3.OperationalError("PRIVATE_SQL rollback")
        def close(self):
            super().close()
            self.closed = True
            if stage == "close":
                raise sqlite3.OperationalError("PRIVATE_SQL close")
    con = sqlite3.connect(":memory:", factory=CleanupFailure)
    con.execute("CREATE TABLE durable(value)")
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    def delegated(*args, **kwargs):
        if stage == "rollback":
            con.execute("INSERT INTO durable VALUES ('partial')")
            raise firmware_chain.FirmwareChainError("expected failure")
        return summary("prepare", tmp_path / "root")
    monkeypatch.setattr(firmware_chain, "prepare", delegated)
    assert audit.main(["chain", "--run", str(tmp_path), "--prepare", "--root", str(tmp_path / "root")]) == 1
    assert capsys.readouterr() == ("", "chain: database operation failed\n")
    assert con.closed
