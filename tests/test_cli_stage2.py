import json
import pathlib
import sqlite3
import subprocess
import sys

import pytest

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


def test_checkpoint_records_a_row_and_prints_the_projection(tmp_path):
    run_dir = new_run(tmp_path)
    db = str(run_dir / "audit.db")
    note = tmp_path / "resume.md"
    note.write_text("resume note")
    r = run("checkpoint", "--db", db, "--phase", "audit", "--reason", "ceiling",
            "--turns", "58", "--resume-note", str(note),
            "--prefix", "45000", "--growth", "600")
    assert r.returncode == 0, r.stderr
    assert "turns to checkpoint 58" in r.stdout
    rows = run("rows", "--db", db, "--table", "cba_checkpoints",
               "--columns", "phase,reason,turns")
    assert rows.stdout.strip() == "audit\tceiling\t58"


def test_checkpoint_refuses_a_missing_resume_note(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("checkpoint", "--db", db, "--phase", "audit", "--reason",
            "phase-exit", "--resume-note", str(tmp_path / "nope.md"))
    assert r.returncode == 1
    assert "the note is the restart" in r.stderr


def test_checkpoint_rejects_an_invented_reason(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("checkpoint", "--db", db, "--phase", "audit", "--reason", "tired")
    assert r.returncode != 0


def test_sweep_reports_hits_without_printing_them(tmp_path):
    run_dir = new_run(tmp_path)
    db = str(run_dir / "audit.db")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("strncpy(d, s, strlen(s));\n")
    run("put", "--db", db, "--table", "cba_patterns", "--set", "id=P1",
        "--set", "name=degenerate strncpy",
        "--set", r"regex=strncpy\([^,]+,[^,]+,\s*strlen\(")
    r = run("sweep", "--db", db, "--pattern", "P1", "--root", str(src), "--record")
    assert r.returncode == 0, r.stderr
    assert "1 hit(s)" in r.stdout
    assert "recorded 1 hit(s)" in r.stdout
    assert "strncpy(d, s" not in r.stdout
    assert "candidates for triage, never verdicts" in r.stdout


def test_sweep_against_an_unregistered_pattern_exits_one(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("sweep", "--db", db, "--pattern", "P9", "--root", str(tmp_path))
    assert r.returncode == 1
    assert "cba_patterns" in r.stderr


def test_sweep_refuses_to_record_a_truncated_result(tmp_path):
    run_dir = new_run(tmp_path)
    db = str(run_dir / "audit.db")
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("needle\n" * 50)
    run("put", "--db", db, "--table", "cba_patterns", "--set", "id=P1",
        "--set", "name=broad", "--set", "regex=needle")
    r = run("sweep", "--db", db, "--pattern", "P1", "--root", str(src),
            "--max-hits", "5", "--record")
    assert r.returncode == 1
    assert "truncated" in r.stderr
    assert "P1" in r.stderr


def test_registering_an_uncompilable_pattern_exits_one(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    r = run("put", "--db", db, "--table", "cba_patterns", "--set", "id=P1",
            "--set", "name=bad", "--set", "regex=([a-z")
    assert r.returncode == 1
    assert "compile" in r.stderr


def pre_stage2_run(tmp_path):
    """A run directory as it looked before this branch: Stage 1 tables only."""
    sql, marker, _ = (ROOT / "audit_core" / "schema.sql"
                      ).read_text().partition("-- Stage 2 additions")
    assert marker, "schema.sql no longer carries the Stage 2 marker"
    run = tmp_path / "reports" / "audit-20260105-120000"
    run.mkdir(parents=True)
    con = sqlite3.connect(run / "audit.db")
    try:
        con.executescript(sql)
        con.commit()
    finally:
        con.close()
    return run


PRE_STAGE2_INVOCATIONS = (
    ("coverage",),
    ("status",),
    ("dedup",),
    ("put", "--table", "cba_inventory", "--set", "unit=a.c", "--set", "kind=file"),
    ("rows", "--table", "cba_checkpoints"),
    ("sweep", "--pattern", "P1", "--root", "."),
    ("checkpoint", "--phase", "audit", "--reason", "manual"),
)


@pytest.mark.parametrize("argv", PRE_STAGE2_INVOCATIONS,
                         ids=[a[0] for a in PRE_STAGE2_INVOCATIONS])
def test_verbs_against_a_pre_stage2_db_exit_one_with_the_remedy(tmp_path, argv):
    """The upgrade path: an installed skill moves forward, the next phase of an
    in-flight audit opens an existing run directory. Every one of these used to
    print `sqlite3.OperationalError: no such table: ...` and a traceback.

    `status` and `dedup` are in this list deliberately. They read only Stage 1
    tables, so they *worked* against a pre-Stage-2 database before this gate -
    and that is the trade: a run directory where half the verbs work is worse
    to debug than one clear message naming the one idempotent command that
    fixes all of them. `test_a_repaired_run_directory_keeps_its_rows_and_opens_cleanly`
    pins that the remedy costs nothing.
    """
    db = str(pre_stage2_run(tmp_path) / "audit.db")
    r = run(argv[0], "--db", db, *argv[1:])
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert "cba_inventory" in r.stderr
    assert "audit.py init" in r.stderr and "--timestamp" in r.stderr


def test_bench_still_reads_a_pre_stage2_db(tmp_path):
    """`bench` reads `cba_findings` and nothing else, and must keep working on
    a run directory that predates the Stage 2 tables - the schema gate is on
    `db.connect`, which `bench` does not go through."""
    run_dir = pre_stage2_run(tmp_path)
    con = sqlite3.connect(run_dir / "audit.db")
    con.execute(
        "INSERT INTO cba_findings (id, group_id, title, severity, confidence, "
        "location, root_cause, impact) VALUES "
        "('F-1','G1','overflow','CRITICAL',9,'sub_E0941B4','k','i')")
    con.commit(); con.close()

    golden = tmp_path / "golden"
    golden.mkdir()
    (golden / "reference.json").write_text(json.dumps([{
        "id": "REF-1", "title": "overflow", "cwe": "CWE-787",
        "locations": ["sub_E0941B4"], "root_cause_key": "k",
        "severity": "CRITICAL"}]))
    (golden / "matches.json").write_text(json.dumps({"REF-1": "F-1"}))

    r = run("bench", "--golden", str(golden), "--db", str(run_dir / "audit.db"))
    assert r.returncode == 0, r.stderr
    assert "1/1" in r.stdout


def test_a_repaired_run_directory_keeps_its_rows_and_opens_cleanly(tmp_path):
    """`audit.py init --timestamp <ts>` is what the message tells the operator
    to run; it has to re-apply the schema without destroying a row."""
    run_dir = pre_stage2_run(tmp_path)
    con = sqlite3.connect(run_dir / "audit.db")
    con.execute("INSERT INTO cba_feature_groups (id, name) VALUES ('G1','klap')")
    con.commit(); con.close()

    assert run("init", "--root", str(tmp_path),
               "--timestamp", "20260105-120000").returncode == 0
    r = run("status", "--db", str(run_dir / "audit.db"))
    assert r.returncode == 0, r.stderr
    assert "G1" in r.stdout
    assert run("coverage", "--db", str(run_dir / "audit.db")).returncode == 0


def test_extract_with_a_zero_batch_size_exits_one_rather_than_raising(tmp_path):
    """`range(start, stop, 0)` is a ValueError. Every other bad input on this
    verb gets a message on stderr and exit 1; this one got a traceback."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.c").write_text("alpha")
    r = run("extract", "--run", str(tmp_path / "run"), "--root", str(src),
            "--unit", "G1", "--path", "a.c", "--batch-size", "0")
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert "--batch-size" in r.stderr
    assert not (tmp_path / "run").exists()


def test_extract_refuses_two_paths_that_flatten_to_one_snapshot_name(tmp_path):
    """C1 at the CLI: without this the second file overwrote the first and the
    summary still said `2 snapshot(s)`."""
    src = tmp_path / "src"
    (src / "src" / "osal").mkdir(parents=True)
    (src / "src" / "osal" / "tss.c").write_text("nested")
    (src / "src" / "osal_tss.c").write_text("flat")
    run_dir = tmp_path / "run"
    r = run("extract", "--run", str(run_dir), "--root", str(src), "--unit", "G1",
            "--path", "src/osal/tss.c", "--path", "src/osal_tss.c")
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert "src_osal_tss.c" in r.stderr
    assert not list((run_dir / "extract").rglob("*.c"))


def test_rows_reports_the_cap_on_stderr_for_json_consumers_too(tmp_path):
    """A consumer piping stdout to `jq` got no signal that the result set was
    bounded, because the notice came after the --json return."""
    db = str(new_run(tmp_path) / "audit.db")
    run("put", "--db", db, "--table", "cba_findings", *FINDING_ARGS)
    text = run("rows", "--db", db, "--table", "cba_findings")
    js = run("rows", "--db", db, "--table", "cba_findings", "--json")
    notice = "(1 row(s), capped at 200)"
    assert notice in text.stderr
    assert notice in js.stderr
    assert json.loads(js.stdout)[0]["id"] == "G1-F1"     # stdout stays clean
