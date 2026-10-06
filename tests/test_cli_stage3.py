import json
import pathlib
import sqlite3
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FINDING_ARGS = [
    "--set", "id=G1-F1", "--set", "group_id=G1", "--set", "title=t",
    "--set", "severity=HIGH", "--set", "confidence=9",
    "--set", "location=src/recv.c:120", "--set", "root_cause=rc",
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


def seeded(tmp_path):
    db = str(new_run(tmp_path) / "audit.db")
    assert run("put", "--db", db, "--table", "cba_findings",
               *FINDING_ARGS).returncode == 0
    return db


def test_pivot_writes_the_verdict_and_the_observation(tmp_path):
    db = seeded(tmp_path)
    r = run("pivot", "--db", db, "--finding", "G1-F1", "--group", "G1",
            "--mechanism", "300-byte sliding-window flush",
            "--enables", "the flush takes an attacker-sized length")
    assert r.returncode == 0, r.stderr
    assert "FALSE_POSITIVE recorded" in r.stdout

    rows = run("rows", "--db", db, "--table", "cba_fp_verdicts", "--json")
    assert "300-byte sliding-window flush" in rows.stdout
    obs = run("rows", "--db", db, "--table", "cba_security_observations", "--json")
    assert "attacker-sized length" in obs.stdout


def test_put_rejects_a_bare_false_positive_and_points_at_pivot(tmp_path):
    """Review Focus 2: the path references/phase5-fp-check.md documents."""
    db = seeded(tmp_path)
    r = run("put", "--db", db, "--table", "cba_fp_verdicts",
            "--set", "finding_id=G1-F1", "--set", "verdict=FALSE_POSITIVE")
    assert r.returncode == 1
    assert "refuting_mechanism" in r.stderr
    assert "audit.py pivot" in r.stderr


def test_pivot_check_exits_zero_with_no_dangling_observations(tmp_path):
    db = seeded(tmp_path)
    assert run("pivot", "--db", db, "--finding", "G1-F1", "--group", "G1",
               "--mechanism", "m", "--enables", "e").returncode == 0
    r = run("pivot", "--db", db, "--check")
    assert r.returncode == 0, r.stderr
    assert "0 dangling" in r.stdout


def test_pivot_check_exits_one_and_names_the_dangling_reference(tmp_path):
    """A dead test here would pass even if cmd_pivot --check always
    returned 0. This one makes a real dangling reference through the CLI,
    by recording a pivot and then deleting the observation row it wrote,
    and checks that --check both exits 1 and names the finding id and the
    unresolvable observation id."""
    db = seeded(tmp_path)
    assert run("pivot", "--db", db, "--finding", "G1-F1", "--group", "G1",
               "--mechanism", "m", "--enables", "e").returncode == 0

    verdict_rows = run("rows", "--db", db, "--table", "cba_fp_verdicts",
                       "--where", "finding_id=G1-F1", "--json")
    assert verdict_rows.returncode == 0, verdict_rows.stderr
    observation_id = json.loads(verdict_rows.stdout)[0]["enabled_observation"]

    con = sqlite3.connect(db)
    con.execute("DELETE FROM cba_security_observations WHERE id = ?",
                (observation_id,))
    con.commit()
    con.close()

    r = run("pivot", "--db", db, "--check")
    assert r.returncode == 1
    assert "G1-F1" in r.stdout
    assert observation_id in r.stdout
    assert "1 dangling" in r.stdout


def test_pivot_on_an_unknown_finding_exits_one(tmp_path):
    db = seeded(tmp_path)
    r = run("pivot", "--db", db, "--finding", "G9-F9", "--group", "G1",
            "--mechanism", "m", "--enables", "e")
    assert r.returncode == 1
    assert "G9-F9" in r.stderr


PATTERN_ARGS = [
    "--set", "id=P1", "--set", "name=strncpy with strlen of source",
    "--set", "regex=strncpy", "--set", "origin_finding=G1-F1",
]


def test_patterns_gate_fails_on_an_unswept_pattern(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_patterns",
               *PATTERN_ARGS).returncode == 0
    r = run("patterns", "--db", db, "--gate")
    assert r.returncode == 1
    assert "NEVER SWEPT" in r.stdout
    assert "audit.py sweep" in r.stdout


def test_patterns_gate_passes_once_the_pattern_is_swept(tmp_path, tmp_path_factory):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_patterns",
               *PATTERN_ARGS).returncode == 0
    src = tmp_path_factory.mktemp("src")
    (src / "a.c").write_text("strncpy(d, s, strlen(s));\n")
    assert run("sweep", "--db", db, "--pattern", "P1",
               "--root", str(src), "--record").returncode == 0
    r = run("patterns", "--db", db, "--gate")
    assert r.returncode == 0, r.stdout
    assert "0 unswept" in r.stdout


def test_patterns_gate_passes_when_nothing_is_registered(tmp_path):
    """No registered pattern is not a failure. A run that confirmed no
    generalisable pattern has nothing to sweep, and a gate that failed there
    would push an operator to register a junk pattern to clear it."""
    db = seeded(tmp_path)
    r = run("patterns", "--db", db, "--gate")
    assert r.returncode == 0
    assert "none registered" in r.stdout
