import pathlib
import sqlite3
import subprocess
import sys

from audit_core import workspace

ROOT = pathlib.Path(__file__).resolve().parent.parent

EXPECTED_TABLES = [
    "cba_attack_surface", "cba_chains", "cba_checkpoints", "cba_components",
    "cba_coverage", "cba_feature_groups", "cba_findings", "cba_fp_verdicts",
    "cba_inventory", "cba_known_findings", "cba_pattern_hits", "cba_patterns",
    "cba_security_observations", "cba_sources",
]


def test_init_creates_directories_and_db(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    assert run == tmp_path / "reports" / "audit-20260105-120000"
    for sub in ("files", "artifacts", "archived-poc", "briefs"):
        assert (run / sub).is_dir()
    assert (run / "audit.db").is_file()


def test_schema_creates_every_cba_table(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    tables = workspace.apply_schema(run / "audit.db").tables
    for name in EXPECTED_TABLES:
        assert name in tables


def test_init_is_idempotent_and_preserves_rows(tmp_path):
    """Review Focus 5: re-running a phase must not destroy recorded findings."""
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    con.execute(
        "INSERT INTO cba_findings (id, group_id, title, severity, confidence, "
        "location, root_cause, impact) VALUES "
        "('G1-F1','G1','t','HIGH',9,'f.c:1','rc','im')"
    )
    con.commit()
    con.close()

    again = workspace.init_run(tmp_path, timestamp="20260105-120000")
    assert again == run
    con = sqlite3.connect(run / "audit.db")
    assert con.execute("SELECT COUNT(*) FROM cba_findings").fetchone()[0] == 1
    con.close()


def test_timestamp_defaults_to_utc_now(tmp_path):
    run = workspace.init_run(tmp_path)
    assert run.name.startswith("audit-")
    assert len(run.name) == len("audit-20260105-120000")


def test_cli_init_prints_the_run_directory(tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "init",
         "--root", str(tmp_path), "--timestamp", "20260105-120000"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == str(
        tmp_path / "reports" / "audit-20260105-120000")


def test_init_prints_the_run_directory_as_its_last_stdout_line(tmp_path):
    """workflows/recon.md reads `AUDIT_DIR=$(audit.py init | tail -1)`. Any
    line printed after the path silently sets AUDIT_DIR to that line."""
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "init",
         "--root", str(tmp_path), "--timestamp", "20260105-120000"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    last = r.stdout.strip().splitlines()[-1]
    assert pathlib.Path(last) == tmp_path / "reports" / "audit-20260105-120000"


def test_init_against_an_older_database_reports_what_it_migrated(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    con.executescript(
        "DROP TABLE cba_patterns;"
        "CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " regex TEXT NOT NULL, origin_finding TEXT, language TEXT,"
        " notes TEXT, created_at TEXT);")
    con.commit()
    con.close()
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "init",
         "--root", str(tmp_path), "--timestamp", "20260105-120000"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "cba_patterns.swept_at" in r.stdout
    assert pathlib.Path(r.stdout.strip().splitlines()[-1]).name == "audit-20260105-120000"
