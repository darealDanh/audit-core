"""Firmware review CLI validates before I/O and publishes bounded aggregates."""
import argparse
import json
import pathlib
import sqlite3
import subprocess
import sys

import pytest

import audit
from audit_core import db, firmware_fpcheck, hunt, workspace
from tests.test_firmware_fpcheck_results import review, completed, prepared  # noqa: F401
from tests.test_hunt_gate import fill
from tests.test_hunt_prepare import add_target

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run_cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *map(str, args)],
                          capture_output=True, text=True)


def assert_error(result, message, code=1):
    assert result.returncode == code
    assert result.stdout == ""
    assert message in result.stderr
    assert "Traceback" not in result.stderr


def test_help_exposes_all_explicit_modes_and_flags():
    result = run_cli("fpcheck", "--help")
    assert result.returncode == 0 and result.stderr == ""
    for flag in ("--run", "--prepare", "--record", "--check", "--root", "--image-id",
                 "--batch-size", "--replace", "--json"):
        assert flag in result.stdout


@pytest.mark.parametrize("flags,message", [
    ([], "exactly one of --prepare, --record, or --check is required"),
    (["--prepare", "--check"], "exactly one"),
    (["--prepare", "--record", "result.json"], "exactly one"),
    (["--check", "--record", "result.json"], "exactly one"),
    (["--prepare", "--check", "--record", "result.json"], "exactly one"),
    (["--prepare"], "--root is required"),
    (["--check"], "--root is required"),
    (["--prepare", "--root", "root", "--replace"], "--replace requires --record"),
    (["--check", "--root", "root", "--replace"], "--replace requires --record"),
    *[(["--record", "result.json", flag, value], flag) for flag, value in
      (("--root", "root"), ("--image-id", "target"), ("--batch-size", "20"))],
    (["--check", "--root", "root", "--batch-size", "20"], "--batch-size"),
    *[(["--prepare", "--root", "root", "--batch-size", value], "1 to 200")
      for value in ("0", "201", "-1")],
])
def test_semantic_mode_errors_do_not_open_database_or_create_run(tmp_path, monkeypatch, capsys, flags, message):
    missing = tmp_path / "missing"
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid modes must precede database I/O")
    monkeypatch.setattr(audit, "_open_db", forbidden)
    assert audit.main(["fpcheck", "--run", str(missing), *flags]) == 1
    output = capsys.readouterr()
    assert output.out == "" and message in output.err
    assert_error(run_cli("fpcheck", "--run", missing, *flags), message)
    assert not missing.exists()


@pytest.mark.parametrize("flags,message", [
    ([], "following arguments are required: --run"),
    (["--run", "unused", "--record"], "expected one argument"),
    (["--run", "unused", "--prepare", "--lane", "l-sink"], "unrecognized arguments"),
    *[(["--run", "unused", "--prepare", "--batch-size", value], "invalid int value")
      for value in ("True", "false", "1.0", "many")],
])
def test_syntax_errors_exit_two_without_run_creation(tmp_path, flags, message):
    flags = [str(tmp_path / "unused") if item == "unused" else item for item in flags]
    assert_error(run_cli("fpcheck", *flags), message, 2)
    assert not (tmp_path / "unused").exists()


@pytest.mark.parametrize("size", [True, False, 1.5])
def test_direct_handler_rejects_noninteger_batch_sizes_before_io(tmp_path, monkeypatch, capsys, size):
    args = argparse.Namespace(run=str(tmp_path / "missing"), prepare=True, record=None,
        check=False, root="root", image_id=None, batch_size=size, replace=False, json=False)
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: pytest.fail("database opened"))
    assert audit.cmd_fpcheck(args) == 1
    assert "1 to 200" in capsys.readouterr().err
    assert not pathlib.Path(args.run).exists()


def assert_bounded(result, root):
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert len(result.stdout) < 4096
    for private in (str(root), "PRIVATE_", "shell-1", "pivot-source", "POST to system",
                    "Unchecked shell input", "system(cmd)", "Source reread"):
        assert private not in result.stdout


@pytest.fixture
def empty_review(tmp_path):
    run = workspace.init_run(tmp_path / "project")
    root = tmp_path / "PRIVATE_CARVED_ROOT"
    with db.connect(run / "audit.db") as con:
        add_target(con, run, root, ["a", "b"])
        summary = hunt.prepare(con, run, root)
        fill(con, run, summary)
        for lane in db.HUNT_LANES:
            hunt.check(con, run, root, lane=lane)
    return run, root


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_real_prepare_record_and_check_have_exact_aggregate_contract(request, empty, json_output):
    if empty:
        run, root = request.getfixturevalue("empty_review")
    else:
        _, run, root, _, _, canonical = request.getfixturevalue("review")
    prepared_result = run_cli("fpcheck", "--run", run, "--prepare", "--root", root,
                              "--image-id", "target", "--batch-size", "20", "--json")
    assert_bounded(prepared_result, root)
    prep = json.loads(prepared_result.stdout)
    assert set(prep) == {"image_id", "manifest_sha256", "surface_snapshot_sha256",
        "candidate_snapshot_sha256", "generation", "worklist_path", "worklist_sha256",
        "candidate_count", "batch_count"}
    assert prep["image_id"] == "target" and prep["candidate_count"] == (0 if empty else 3)
    assert prep["batch_count"] == 1 and prep["generation"] == prep["worklist_sha256"]
    assert len(prep["generation"]) == 64
    index = json.loads(pathlib.Path(prep["worklist_path"]).read_text())
    assert index["batch_size"] == 20
    human = run_cli("fpcheck", "--run", run, "--prepare", "--root", root)
    assert_bounded(human, root)
    assert human.stdout == (f"fpcheck prepared target: {prep['candidate_count']} candidate(s), 1 batch(es)\n"
        f"candidate snapshot sha256 {prep['candidate_snapshot_sha256']}\n"
        f"worklist sha256 {prep['worklist_sha256']}\n{prep['worklist_path']}\n")
    result_file = run / "PRIVATE_REVIEW_RESULT.json"
    if empty:
        batch, = index["batches"]
        canonical = ('{"batch_path":"batch-0001.json","batch_sha256":"BATCH",'
            '"candidate_snapshot_sha256":"SNAPSHOT","decisions":[],"image_id":"target",'
            '"schema_version":1,"worklist_sha256":"WORKLIST"}\n').replace(
                "BATCH", batch["sha256"]).replace("SNAPSHOT", prep["candidate_snapshot_sha256"]).replace(
                "WORKLIST", prep["worklist_sha256"]).encode()
    canonical = canonical.replace(b'"reason":"Source reread"', b'"reason":"PRIVATE_REVIEW_REASON"')
    result_file.write_bytes(canonical)
    flags = ["--json"] if json_output else []
    recorded = run_cli("fpcheck", "--run", run, "--record", result_file, *flags)
    assert_bounded(recorded, root)
    with db.connect(run / "audit.db") as con:
        artifact, = con.execute("SELECT result_path FROM cba_firmware_fp_receipts").fetchone()
    counts = dict(candidate_count=0 if empty else 3, true_positives=0 if empty else 1,
        false_positives=0 if empty else 1, duplicates=0 if empty else 1, pivots=0 if empty else 1)
    if json_output:
        assert json.loads(recorded.stdout) == {"image_id": "target", "batch_path": "batch-0001.json",
            "assigned_candidates": counts["candidate_count"], **{k: v for k, v in counts.items() if k != "candidate_count"},
            "artifact_path": artifact}
    else:
        assert recorded.stdout == (f"fpcheck recorded target batch-0001.json: {counts['candidate_count']} candidate(s), "
            f"{counts['true_positives']} true positive(s), {counts['false_positives']} false positive(s), "
            f"{counts['duplicates']} duplicate(s), {counts['pivots']} pivot(s)\n{artifact}\n")
    assert_error(run_cli("fpcheck", "--run", run, "--record", result_file), "replace")
    replaced = run_cli("fpcheck", "--run", run, "--record", result_file, "--replace", *flags)
    assert_bounded(replaced, root)
    assert replaced.stdout == recorded.stdout
    checked = run_cli("fpcheck", "--run", run, "--check", "--root", root, "--image-id", "target", *flags)
    assert_bounded(checked, root)
    with db.connect(run / "audit.db") as con:
        row = con.execute("SELECT status,completed_at FROM cba_firmware_fp_runs").fetchone()
        assert row[0] == "complete" and row[1]
        assert con.execute("SELECT count(*) FROM cba_findings").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM cba_fp_verdicts").fetchone()[0] == 0
        generation = prep["generation"]
        artifact, = map(str, (run / "artifacts/firmware-fpcheck" / generation).glob("*/findings.json"))
    if json_output:
        assert json.loads(checked.stdout) == {"image_id": "target", **counts,
            "finding_count": 0 if empty else 1, "artifact_path": artifact, "complete": True}
    else:
        assert checked.stdout == (f"fpcheck target: {counts['candidate_count']} candidate(s), "
            f"{counts['true_positives']} true positive(s), {counts['false_positives']} false positive(s), "
            f"{counts['duplicates']} duplicate(s), {counts['pivots']} pivot(s), "
            f"{0 if empty else 1} finding(s), complete\n{artifact}\n")
    assert pathlib.Path(artifact).is_file()
    repeated = run_cli("fpcheck", "--run", run, "--check", "--root", root, *flags)
    assert repeated.stdout == checked.stdout and repeated.stderr == "" and repeated.returncode == 0


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
@pytest.mark.parametrize("error_type", [firmware_fpcheck.FpcheckError, db.DbError, OSError, sqlite3.OperationalError])
@pytest.mark.parametrize("chain", ["none", "cause", "context", "cycle"])
def test_expected_errors_are_escaped_capped_and_sql_is_fixed(review, monkeypatch, capsys, mode, error_type, chain):
    _, run, root, *_ = review
    failure = error_type(f"Cannot use {root}: private\n\x1b\u202e" + "x" * 1000)
    if chain != "none":
        middle = RuntimeError("wrapper")
        failure.__cause__ = middle
        if chain == "cause":
            middle.__cause__ = sqlite3.OperationalError("PRIVATE_SQL")
        else:
            middle.__context__ = sqlite3.OperationalError("PRIVATE_SQL")
            if chain == "cycle":
                middle.__cause__ = failure
    con = db.connect(run / "audit.db")
    before = tuple(con.iterdump())
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    def fail(*args, **kwargs):
        con.execute("UPDATE cba_firmware_fp_runs SET candidate_count=99")
        raise failure
    module = audit.firmware_fpcheck_results_mod if mode == "record" else audit.firmware_fpcheck_mod
    monkeypatch.setattr(module, mode, fail)
    flags = ["--record", "unused.json"] if mode == "record" else ["--" + mode, "--root", str(root)]
    args = audit.build_parser().parse_args(["fpcheck", "--run", str(run), *flags])
    assert audit.cmd_fpcheck(args) == 1
    out = capsys.readouterr()
    assert out.out == "" and "Traceback" not in out.err
    if chain != "none" or issubclass(error_type, sqlite3.Error):
        assert out.err == "fpcheck: database operation failed\n"
    else:
        prefix = r"Cannot use <root>: private\n\u001b\u202e" if mode != "record" else f"Cannot use {root}: private\\n\\u001b\\u202e"
        assert out.err == prefix + "x" * (509 - len(prefix)) + "...\n"
    assert len(out.err) <= 513 and out.err.isascii()
    with db.connect(run / "audit.db") as after:
        assert tuple(after.iterdump()) == before
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        con.execute("SELECT 1")


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
def test_missing_and_corrupt_databases_are_expected_and_do_not_create_runs(tmp_path, mode):
    run = tmp_path / "missing"
    flags = ["--record", "unused.json"] if mode == "record" else ["--" + mode, "--root", tmp_path]
    assert_error(run_cli("fpcheck", "--run", run, *flags), "audit.py init")
    assert not run.exists()
    run.mkdir()
    (run / "audit.db").write_bytes(b"not SQLite")
    result = run_cli("fpcheck", "--run", run, *flags)
    assert_error(result, "fpcheck: database operation failed")
    assert result.stderr == "fpcheck: database operation failed\n"


@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, db.DbError, OSError, RuntimeError])
def test_open_errors_translate_only_expected_types(tmp_path, monkeypatch, capsys, error_type):
    failure = error_type("PRIVATE_SQL" if error_type is sqlite3.OperationalError else "open failure\n\u202e")
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(db, "connect", fail)
    args = audit.build_parser().parse_args(["fpcheck", "--run", str(tmp_path), "--prepare", "--root", "root"])
    if error_type is RuntimeError:
        with pytest.raises(RuntimeError) as caught:
            audit.cmd_fpcheck(args)
        assert caught.value is failure and capsys.readouterr() == ("", "")
    else:
        assert audit.cmd_fpcheck(args) == 1
        output = capsys.readouterr()
        assert output.out == ""
        assert output.err == ("fpcheck: database operation failed\n" if error_type is sqlite3.OperationalError
                              else "open failure\\n\\u202e\n")


@pytest.mark.parametrize("error_type", [RuntimeError, AssertionError, ValueError])
def test_unexpected_handler_errors_propagate_and_release_connection(review, monkeypatch, capsys, error_type):
    _, run, root, *_ = review
    con = db.connect(run / "audit.db")
    before = tuple(con.iterdump())
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    failure = error_type("unexpected defect")
    failure.__cause__ = sqlite3.OperationalError("driver detail")
    def fail(*args, **kwargs):
        con.execute("UPDATE cba_firmware_fp_runs SET candidate_count=99")
        raise failure
    monkeypatch.setattr(audit.firmware_fpcheck_mod, "prepare", fail)
    args = audit.build_parser().parse_args(["fpcheck", "--run", str(run), "--prepare", "--root", str(root)])
    with pytest.raises(error_type) as caught:
        audit.cmd_fpcheck(args)
    assert caught.value is failure and capsys.readouterr() == ("", "")
    with db.connect(run / "audit.db") as after:
        assert tuple(after.iterdump()) == before
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        con.execute("SELECT 1")


@pytest.mark.parametrize("damage", ["stale-root", "missing-root", "missing-result", "malformed-result"])
def test_real_domain_refusals_preserve_database(review, damage):
    con, run, root, *_ = review
    before = tuple(con.iterdump())
    source = run / "malformed.json"
    source.write_text("{}")
    if damage == "stale-root":
        (root / "a").write_bytes(b"changed")
        flags = ["--check", "--root", root]
    elif damage == "missing-root":
        flags = ["--prepare", "--root", root / "missing"]
    else:
        flags = ["--record", source if damage == "malformed-result" else run / "missing.json"]
    result = run_cli("fpcheck", "--run", run, *flags)
    assert_error(result, "")
    assert len(result.stderr) <= 513 and result.stderr.isascii()
    assert str(root) not in result.stderr
    assert tuple(con.iterdump()) == before


@pytest.mark.parametrize("json_output", [False, True])
def test_success_preserves_json_identity_and_bounds_human_display(tmp_path, json_output):
    run = workspace.init_run(tmp_path / "project")
    root = tmp_path / "PRIVATE_CARVED_ROOT"
    image_id = "image\n\x1b\u202e" + "x" * 2000
    with db.connect(run / "audit.db") as con:
        add_target(con, run, root, ["a"], image_id=image_id)
        summary = hunt.prepare(con, run, root, image_id=image_id)
        fill(con, run, summary)
        for lane in db.HUNT_LANES:
            hunt.check(con, run, root, image_id=image_id, lane=lane)
    result = run_cli("fpcheck", "--run", run, "--prepare", "--root", root,
                     *(["--json"] if json_output else []))
    assert_bounded(result, root)
    prefix = r"image\n\u001b\u202e"
    public_id = prefix + "x" * (509 - len(prefix)) + "..."
    assert result.stdout.isascii()
    if json_output:
        assert json.loads(result.stdout)["image_id"] == image_id
    else:
        assert result.stdout.splitlines()[0] == f"fpcheck prepared {public_id}: 0 candidate(s), 1 batch(es)"


@pytest.mark.parametrize("layout", ["unicode", "long-path", "root-prefix"])
def test_json_workflow_round_trips_identity_and_usable_artifact_paths(tmp_path, layout):
    # Breaks: display escaping, truncation or root-substring redaction changes
    # machine-readable values before the next workflow command can consume them.
    project = tmp_path / "dữ-liệu"
    root = tmp_path / "PRIVATE_CARVED_ROOT"
    if layout == "long-path":
        # Keep audit.db below SQLite's host path limit while its deeper
        # worklist/result/findings artifact paths exceed the display cap.
        while len(str(project)) < 420:
            project /= "d" * min(180, 420 - len(str(project)))
    elif layout == "root-prefix":
        root = tmp_path / "carved"
        project = tmp_path / "carved-run" / "dữ-liệu"
    run = workspace.init_run(project)
    image_id = "a:%_图像"
    with db.connect(run / "audit.db") as con:
        add_target(con, run, root, ["a"], image_id=image_id)
        summary = hunt.prepare(con, run, root, image_id=image_id)
        fill(con, run, summary)
        for lane in db.HUNT_LANES:
            hunt.check(con, run, root, image_id=image_id, lane=lane)

    prepared_result = run_cli("fpcheck", "--run", run, "--prepare", "--root", root,
                              "--image-id", image_id, "--json")
    assert prepared_result.returncode == 0, prepared_result.stderr
    prep = json.loads(prepared_result.stdout)
    assert prep["image_id"] == image_id
    index_path = pathlib.Path(prep["worklist_path"])
    assert index_path.is_relative_to(run)
    index = json.loads(index_path.read_bytes())
    batch, = index["batches"]
    if layout == "long-path":
        assert len(str(index_path)) > 512
    result_file = run / "review.json"
    result_file.write_text(json.dumps({
        "schema_version": 1, "image_id": prep["image_id"],
        "candidate_snapshot_sha256": prep["candidate_snapshot_sha256"],
        "worklist_sha256": prep["worklist_sha256"], "batch_path": batch["path"],
        "batch_sha256": batch["sha256"], "decisions": [],
    }), encoding="utf-8")
    recorded_result = run_cli("fpcheck", "--run", run, "--record", result_file, "--json")
    assert recorded_result.returncode == 0, recorded_result.stderr
    recorded = json.loads(recorded_result.stdout)
    assert recorded["image_id"] == image_id
    result_path = pathlib.Path(recorded["artifact_path"])
    assert result_path.is_relative_to(run)
    assert json.loads(result_path.read_bytes())["image_id"] == image_id
    # Consume both the returned artifact path and identity through supported CLI steps.
    replaced_result = run_cli("fpcheck", "--run", run, "--record", result_path,
                              "--replace", "--json")
    assert replaced_result.returncode == 0, replaced_result.stderr
    assert json.loads(replaced_result.stdout) == recorded
    checked_result = run_cli("fpcheck", "--run", run, "--check", "--root", root,
                             "--image-id", recorded["image_id"], "--json")
    assert checked_result.returncode == 0, checked_result.stderr
    checked = json.loads(checked_result.stdout)
    assert checked["image_id"] == image_id and checked["complete"] is True
    findings_path = pathlib.Path(checked["artifact_path"])
    assert findings_path.is_relative_to(run)
    assert json.loads(findings_path.read_bytes())["image_id"] == image_id
    for result in (prepared_result, recorded_result, replaced_result, checked_result):
        assert result.stderr == ""
        assert "PRIVATE_" not in result.stdout
        if layout != "root-prefix":
            assert str(root) not in result.stdout


@pytest.mark.parametrize("mode", ["prepare", "record", "check"])
def test_real_sqlite_read_failure_has_fixed_diagnostic_and_preserves_state(review, monkeypatch, capsys, mode):
    _, run, root, _, _, canonical = review
    source = run / "review.json"
    source.write_bytes(canonical)
    con = db.connect(run / "audit.db")
    before = tuple(con.iterdump())
    con.set_authorizer(lambda action, name, *rest: sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_READ and name == "cba_images" else sqlite3.SQLITE_OK)
    monkeypatch.setattr(audit, "_open_db", lambda *a, **k: con)
    flags = ["--record", str(source)] if mode == "record" else ["--" + mode, "--root", str(root)]
    assert audit.main(["fpcheck", "--run", str(run), *flags]) == 1
    assert capsys.readouterr() == ("", "fpcheck: database operation failed\n")
    with db.connect(run / "audit.db") as after:
        assert tuple(after.iterdump()) == before


@pytest.mark.parametrize("size", [1, 200])
def test_prepare_accepts_both_batch_size_boundaries(empty_review, size):
    run, root = empty_review
    result = run_cli("fpcheck", "--run", run, "--prepare", "--root", root,
                     "--batch-size", size, "--json")
    assert_bounded(result, root)
    summary = json.loads(result.stdout)
    assert summary["candidate_count"] == 0 and summary["batch_count"] == 1
    assert json.loads(pathlib.Path(summary["worklist_path"]).read_text())["batch_size"] == size


@pytest.mark.parametrize("json_output", [False, True])
def test_relative_dot_root_preserves_usable_worklist_paths(empty_review, monkeypatch, json_output):
    run, root = empty_review
    monkeypatch.chdir(root)
    result = run_cli("fpcheck", "--run", run, "--prepare", "--root", ".",
                     *(["--json"] if json_output else []))
    assert_bounded(result, root)
    if json_output:
        path = json.loads(result.stdout)["worklist_path"]
    else:
        path = result.stdout.splitlines()[-1]
    assert pathlib.Path(path).name == "index.json"
    assert pathlib.Path(path).is_file()
