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


def test_coverage_on_an_empty_inventory_exits_zero_and_explains(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("coverage", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "inventory is empty" in r.stdout


def test_coverage_reports_a_budget_skip_as_a_warning(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    run("put", "--db", db, "--table", "cba_inventory",
        "--set", "unit=src/a.c", "--set", "kind=file")
    run("put", "--db", db, "--table", "cba_coverage", "--set", "unit=src/a.c",
        "--set", "phase=audit", "--set", "state=not_audited", "--set", "reason=budget")
    r = run("coverage", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "WARNING" in r.stdout
    assert "checkpoint and restart" in r.stdout


def test_a_not_audited_row_without_a_reason_is_refused_at_the_cli(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("put", "--db", db, "--table", "cba_coverage", "--set", "unit=a.c",
            "--set", "phase=audit", "--set", "state=not_audited")
    assert r.returncode == 1
    assert "reason" in r.stderr


def test_extract_snapshots_a_source_tree_and_prints_a_bounded_summary(tmp_path):
    run_dir = new_run(tmp_path)
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.c").write_text("alpha")
    (src / "sub" / "b.c").write_text("beta")
    r = run("extract", "--run", str(run_dir), "--root", str(src),
            "--unit", "G1", "--path", "a.c", "--path", "sub/b.c")
    assert r.returncode == 0, r.stderr
    assert "2 snapshot(s), 0 changed, 0 truncated" in r.stdout
    assert (run_dir / "extract" / "G1" / "sub_b.c").read_text() == "beta"
    # The summary is two lines. The detail is in the manifest, which is a file.
    assert len(r.stdout.strip().splitlines()) == 2


def test_extract_refresh_re_reads_what_the_unit_already_holds(tmp_path):
    run_dir = new_run(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("v1")
    run("extract", "--run", str(run_dir), "--root", str(src), "--unit", "G1",
        "--path", "a.c")
    (src / "a.c").write_text("v2")
    r = run("extract", "--run", str(run_dir), "--root", str(src), "--unit", "G1",
            "--refresh")
    assert r.returncode == 0, r.stderr
    assert "1 changed" in r.stdout


def test_extract_with_no_items_exits_one(tmp_path):
    run_dir = new_run(tmp_path)
    (tmp_path / "src").mkdir()
    r = run("extract", "--run", str(run_dir), "--root", str(tmp_path / "src"),
            "--unit", "G1")
    assert r.returncode == 1
    assert "--refresh" in r.stderr


def test_note_appends_then_indexes(tmp_path):
    run_dir = str(new_run(tmp_path))
    assert run("note", "--run", run_dir, "--key", "klap_handshake1_handle",
               "--kind", "semantics",
               "--text", "copies before checking length").returncode == 0
    r = run("note", "--run", run_dir)
    assert r.returncode == 0, r.stderr
    assert "klap_handshake1_handle" in r.stdout
    assert "1 key(s)" in r.stdout


def test_note_text_without_key_exits_one(tmp_path):
    run_dir = str(new_run(tmp_path))
    r = run("note", "--run", run_dir, "--text", "orphan")
    assert r.returncode == 1
    assert "--key" in r.stderr


def test_note_index_warns_about_a_corrupt_line_on_stderr(tmp_path):
    run_dir = new_run(tmp_path)
    run("note", "--run", str(run_dir), "--key", "a", "--text", "one")
    with open(run_dir / "journal.jsonl", "ab") as fh:
        fh.write(b"not json\n")
    r = run("note", "--run", str(run_dir))
    assert r.returncode == 0
    assert "line(s) 2" in r.stderr
