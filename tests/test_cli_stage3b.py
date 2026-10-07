import json
import pathlib
import sqlite3
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUDIT = ROOT / "audit.py"


def run(*args, **kw):
    return subprocess.run([sys.executable, str(AUDIT), *args],
                          capture_output=True, text=True, **kw)


def _old_db(path):
    """The shape of the only audit.db that exists: findings and surfaces,
    none of the Stage 2 tables."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
                "cwe TEXT, location TEXT, severity TEXT)")
    con.execute("CREATE TABLE cba_attack_surface (id INTEGER PRIMARY KEY "
                "AUTOINCREMENT, group_id TEXT, endpoint TEXT, method TEXT, "
                "auth_required TEXT, description TEXT)")
    con.execute("INSERT INTO cba_attack_surface (group_id, endpoint) "
                "VALUES ('G1', '/login')")
    con.commit()
    con.close()


def test_indicators_reads_a_database_db_connect_would_reject(tmp_path):
    """The whole point of the verb. db.connect() gates on the Stage 3 schema
    and rejects this database; `indicators` must still read it, because it is
    the only real one in existence."""
    db = tmp_path / "audit.db"
    _old_db(db)
    p = run("indicators", "--db", str(db), "--target", "tplink")
    assert p.returncode == 0, p.stderr
    assert "surfaces opened" in p.stdout
    assert "absent" in p.stdout
    assert "0.0%" not in p.stdout


def test_snapshot_writes_tracked_json(tmp_path):
    db = tmp_path / "run" / "audit.db"
    db.parent.mkdir()
    _old_db(db)
    root = tmp_path / "repo"
    p = run("indicators", "--db", str(db), "--target", "demo",
            "--snapshot", "--root", str(root))
    assert p.returncode == 0, p.stderr
    out = root / "docs" / "indicators"
    written = list(out.glob("*.json"))
    assert len(written) == 1
    data = json.loads(written[0].read_text())
    assert data["schema_version"] == 1
    assert data["target"] == "demo"
    assert data["indicators"]["surfaces"]["value"] == 1
    assert data["indicators"]["coverage"]["state"] == "absent"
    assert "value" not in data["indicators"]["coverage"]


def test_a_second_snapshot_the_same_day_refuses_rather_than_overwrites(tmp_path):
    """Review Focus 5. docs/indicators/ follows the docs/baselines/ rule:
    never edited in place. Overwriting this morning's measurement with this
    afternoon's destroys it and leaves no trace it existed."""
    db = tmp_path / "audit.db"
    _old_db(db)
    root = tmp_path / "repo"
    first = run("indicators", "--db", str(db), "--target", "demo",
                "--snapshot", "--root", str(root))
    assert first.returncode == 0, first.stderr
    (original,) = (root / "docs" / "indicators").glob("*.json")
    before = original.read_text()

    second = run("indicators", "--db", str(db), "--target", "demo",
                 "--snapshot", "--root", str(root))
    assert second.returncode == 1
    assert "already exists" in second.stderr
    assert "--label" in second.stderr
    assert original.read_text() == before

    labelled = run("indicators", "--db", str(db), "--target", "demo",
                   "--snapshot", "--label", "afternoon", "--root", str(root))
    assert labelled.returncode == 0, labelled.stderr
    assert len(list((root / "docs" / "indicators").glob("*.json"))) == 2


def test_a_relative_db_path_still_names_the_target_from_its_directory(tmp_path):
    run_dir = tmp_path / "myrun"
    run_dir.mkdir()
    _old_db(run_dir / "audit.db")
    root = tmp_path / "repo"
    p = run("indicators", "--db", "audit.db", "--snapshot", "--root", str(root),
            cwd=str(run_dir))
    assert p.returncode == 0, p.stderr
    names = [f.name for f in (root / "docs" / "indicators").glob("*.json")]
    assert len(names) == 1 and names[0].endswith("-myrun.json"), names


def test_cli_compare_two_snapshots(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                             "indicators": {"surfaces": {"state": "present",
                                                         "value": 10}}}))
    b.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                             "indicators": {"surfaces": {"state": "present",
                                                         "value": 14}}}))
    p = run("indicators", "--compare", str(a), str(b))
    assert p.returncode == 0, p.stderr
    assert "+4" in p.stdout


def test_indicators_without_db_or_compare_is_an_error():
    p = run("indicators")
    assert p.returncode == 1
    assert "--compare" in p.stderr


def test_compare_rejects_invalid_json(tmp_path):
    valid = tmp_path / "valid.json"
    invalid = tmp_path / "invalid.json"
    valid.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                                  "indicators": {"surfaces": {"state": "present",
                                                              "value": 10}}}))
    invalid.write_text("{ this is not valid json }")
    p = run("indicators", "--compare", str(valid), str(invalid))
    assert p.returncode == 1
    assert "invalid JSON" in p.stderr


def test_compare_rejects_non_dict_top_level(tmp_path):
    valid = tmp_path / "valid.json"
    invalid = tmp_path / "array.json"
    valid.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                                  "indicators": {"surfaces": {"state": "present",
                                                              "value": 10}}}))
    invalid.write_text(json.dumps(["not", "a", "dict"]))
    p = run("indicators", "--compare", str(valid), str(invalid))
    assert p.returncode == 1
    assert "top level must be a dict" in p.stderr


def test_compare_rejects_missing_indicators_key(tmp_path):
    valid = tmp_path / "valid.json"
    missing = tmp_path / "missing.json"
    valid.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None,
                                  "indicators": {"surfaces": {"state": "present",
                                                              "value": 10}}}))
    missing.write_text(json.dumps({"schema_version": 1, "target": "t", "phase": None}))
    p = run("indicators", "--compare", str(valid), str(missing))
    assert p.returncode == 1
    assert "missing 'indicators' key" in p.stderr


def test_rerate_does_not_modify_the_database(tmp_path):
    """The safety property, asserted rather than assumed. If a future change
    makes this verb write, the mtime and the row contents catch it."""
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, "
                "group_id TEXT NOT NULL, title TEXT NOT NULL, "
                "severity TEXT NOT NULL, confidence INTEGER NOT NULL, "
                "cwe TEXT, location TEXT NOT NULL, root_cause TEXT NOT NULL, "
                "impact TEXT NOT NULL, attacker_position TEXT, "
                "boundary_crossed TEXT, data_flow TEXT, verified TEXT, "
                "poc TEXT, remediation TEXT, artifact_path TEXT, "
                "created_at TEXT)")
    con.execute("INSERT INTO cba_findings (id, group_id, title, severity, "
                "confidence, location, root_cause, impact) VALUES "
                "('F1','G1','t','LOW',80,'f.c:1',"
                "'reached without authentication','i')")
    con.commit()
    con.close()

    before = (db.stat().st_mtime_ns, db.read_bytes())
    p = run("rerate", "--db", str(db))
    assert p.returncode == 0, p.stderr
    assert "F1" in p.stdout
    assert "No severity has been changed" in p.stdout
    assert (db.stat().st_mtime_ns, db.read_bytes()) == before
