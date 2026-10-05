import json, pathlib, sqlite3, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *args],
                          capture_output=True, text=True)


def make_golden(tmp_path):
    g = tmp_path / "golden"
    g.mkdir()
    (g / "reference.json").write_text(json.dumps([{
        "id": "REF-1", "title": "overflow", "cwe": "CWE-787",
        "locations": ["sub_E0941B4"], "root_cause_key": "k", "severity": "CRITICAL"}]))
    (g / "matches.json").write_text(json.dumps({"REF-1": "F-1"}))
    return g


def make_db(tmp_path):
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
                "severity TEXT, cwe TEXT, location TEXT)")
    con.execute("INSERT INTO cba_findings VALUES "
                "('F-1','overflow','CRITICAL','CWE-787','sub_E0941B4')")
    con.commit(); con.close()
    return db


def test_bench_reports_recall(tmp_path):
    r = run("bench", "--golden", str(make_golden(tmp_path)),
            "--db", str(make_db(tmp_path)))
    assert r.returncode == 0, r.stderr
    assert "recall" in r.stdout.lower()
    assert "1/1" in r.stdout or "100.0%" in r.stdout


def test_bench_json_output(tmp_path):
    r = run("bench", "--golden", str(make_golden(tmp_path)),
            "--db", str(make_db(tmp_path)), "--json")
    payload = json.loads(r.stdout)
    assert payload["recall"] == 1.0
    assert payload["matched"] == [["REF-1", "F-1"]]


def test_bench_missing_golden_exits_one(tmp_path):
    r = run("bench", "--golden", str(tmp_path / "nope"), "--db", str(make_db(tmp_path)))
    assert r.returncode == 1
