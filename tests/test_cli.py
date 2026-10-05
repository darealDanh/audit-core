import subprocess, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

def run(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), *args],
        capture_output=True, text=True,
    )

def test_selftest_exits_zero_and_reports_version():
    r = run("selftest")
    assert r.returncode == 0, r.stderr
    assert "audit_core" in r.stdout

def test_unknown_verb_exits_nonzero():
    r = run("nosuchverb")
    assert r.returncode != 0
