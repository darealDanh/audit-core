import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FINDING_ARGS = [
    "--set", "id=G1-F1", "--set", "group_id=G1", "--set", "title=t",
    "--set", "severity=HIGH", "--set", "confidence=9",
    "--set", "location=src/klap.c:120", "--set", "root_cause=rc",
    "--set", "impact=im",
]


def run(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), *args],
        capture_output=True, text=True,
    )


def new_run(tmp_path):
    r = run("init", "--root", str(tmp_path), "--timestamp", "20260105-120000")
    assert r.returncode == 0, r.stderr
    return pathlib.Path(r.stdout.strip().splitlines()[-1])


def test_put_then_status_round_trips(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    assert run("put", "--db", db, "--table", "cba_findings", *FINDING_ARGS).returncode == 0
    r = run("status", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "findings 1" in r.stdout
    assert "unverdicted 1" in r.stdout


def test_put_with_an_unknown_column_exits_one_and_names_it(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("put", "--db", db, "--table", "cba_findings", "--set", "nope=1")
    assert r.returncode == 1
    assert "nope" in r.stderr


def test_rows_prints_the_requested_columns(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    run("put", "--db", db, "--table", "cba_findings", *FINDING_ARGS)
    r = run("rows", "--db", db, "--table", "cba_findings", "--columns", "id,severity")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "G1-F1\tHIGH"


def test_verbs_against_a_missing_db_exit_one_with_the_fix(tmp_path):
    r = run("status", "--db", str(tmp_path / "nope.db"))
    assert r.returncode == 1
    assert "audit.py init" in r.stderr


def test_dedup_on_an_empty_run_says_so_and_exits_zero(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("dedup", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "no cross-group duplicate candidates" in r.stdout
