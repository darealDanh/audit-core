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


def test_coverage_gate_exits_one_on_a_budget_skip(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_inventory",
               "--set", "unit=src/wifi.c", "--set", "kind=file").returncode == 0
    assert run("put", "--db", db, "--table", "cba_coverage",
               "--set", "unit=src/wifi.c", "--set", "phase=audit",
               "--set", "state=not_audited",
               "--set", "reason=budget").returncode == 0
    r = run("coverage", "--db", db, "--gate")
    assert r.returncode == 1
    assert "coverage gate: FAIL" in r.stdout
    assert "checkpoint" in r.stdout


def test_coverage_gate_exits_zero_on_a_fully_analyzed_run(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_inventory",
               "--set", "unit=src/a.c", "--set", "kind=file").returncode == 0
    assert run("put", "--db", db, "--table", "cba_coverage",
               "--set", "unit=src/a.c", "--set", "phase=audit",
               "--set", "state=analyzed").returncode == 0
    r = run("coverage", "--db", db, "--gate")
    assert r.returncode == 0, r.stdout
    assert "coverage gate: PASS" in r.stdout


def test_coverage_without_gate_still_exits_zero_on_a_gap(tmp_path):
    """Ruling S3: the gate is opt-in. Bare `coverage` reports; it does not
    decide. A verb that started failing would break every existing caller."""
    db = seeded(tmp_path)
    r = run("coverage", "--db", db)
    assert r.returncode == 0


def test_identify_rejects_evidence_that_repeats_the_filename(tmp_path):
    db = seeded(tmp_path)
    r = run("identify", "--db", db, "--path", "images/km0_boot_0C000020.elf",
            "--kind", "binary", "--identity", "bootloader",
            "--evidence", "the file is named km0_boot_0C000020.elf")
    assert r.returncode == 1
    assert "km0_boot" in r.stderr


def test_identify_records_and_lists(tmp_path):
    db = seeded(tmp_path)
    assert run("identify", "--db", db,
               "--path", "images/km0_boot_0C000020.elf", "--kind", "binary",
               "--identity", "Realtek RTL8710 Wi-Fi driver image",
               "--evidence", "contains 'rtl8710 wlan firmware' at 0x0C00A120; "
                             "imports wifi_hal_init",
               "--confidence", "8").returncode == 0
    r = run("identify", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "Realtek RTL8710" in r.stdout
    assert "evidence:" in r.stdout


def test_identify_rejects_a_confidence_outside_the_range(tmp_path):
    db = seeded(tmp_path)
    r = run("identify", "--db", db, "--path", "a.bin", "--kind", "binary",
            "--identity", "x",
            "--evidence", "entropy 7.9 across the file, no ELF header present",
            "--confidence", "99")
    assert r.returncode == 1
    assert "1-10" in r.stderr


def test_chain_proposes_across_groups(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_findings",
               "--set", "id=G2-F1", "--set", "group_id=G2", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/b.c:1", "--set", "root_cause=rc",
               "--set", "impact=im",
               "--set", "attacker_position=needs session_token, nvram_commit "
                        "and nvram_config"
               ).returncode == 0
    assert run("put", "--db", db, "--table", "cba_findings",
               "--set", "id=G3-F1", "--set", "group_id=G3", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/c.c:1", "--set", "root_cause=rc",
               "--set", "impact=leaks session_token through nvram_commit from "
                        "the nvram_config blob"
               ).returncode == 0
    r = run("chain", "--db", db)
    assert r.returncode == 0, r.stderr
    assert "G3-F1 -> G2-F1" in r.stdout
    assert "proposals" in r.stdout


def test_chain_compose_records_and_rejects_an_unknown_finding(tmp_path):
    db = seeded(tmp_path)
    assert run("put", "--db", db, "--table", "cba_findings",
               "--set", "id=G2-F1", "--set", "group_id=G2", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/b.c:1", "--set", "root_cause=rc",
               "--set", "impact=im").returncode == 0
    ok = run("chain", "--db", db, "--compose", "C1",
             "--findings", "G1-F1,G2-F1",
             "--attacker-position", "unauthenticated on the LAN",
             "--completeness", "complete")
    assert ok.returncode == 0, ok.stderr

    bad = run("chain", "--db", db, "--compose", "C2",
              "--findings", "G1-F1,G9-F9",
              "--attacker-position", "LAN", "--completeness", "complete")
    assert bad.returncode == 1
    assert "G9-F9" in bad.stderr


def test_chain_reports_findings_that_cannot_be_a_consumer(tmp_path):
    db = seeded(tmp_path)
    r = run("chain", "--db", db)
    assert r.returncode == 0
    assert "cannot be the consumer half" in r.stdout


# --- coverage --record: the writer side of the coverage gate ------------------


def _inventoried(tmp_path, *units):
    dbp = str(new_run(tmp_path) / "audit.db")
    for u in units:
        assert run("put", "--db", dbp, "--table", "cba_inventory",
                   "--set", f"unit={u}", "--set", "kind=file").returncode == 0
    return dbp


def test_coverage_record_clears_the_phase_gate_from_a_file(tmp_path):
    """Walked end to end: the gate fails, one `--record --from-file` call
    clears it. Before this verb existed, nothing in SKILL.md, workflows/ or
    references/ ever told anyone to write a cba_coverage row, so the gate
    shipped unclearable on every real target."""
    dbp = _inventoried(tmp_path, "src/a.c", "src/b.c", "vendor/z.c")
    before = run("coverage", "--db", dbp, "--gate", "--phase", "audit")
    assert before.returncode == 1
    assert "unrecorded" in before.stdout

    listing = tmp_path / "audited.txt"
    listing.write_text("# the files this phase opened\nsrc/a.c\nsrc/b.c\n")
    r = run("coverage", "--db", dbp, "--record", "--phase", "audit",
            "--state", "analyzed", "--from-file", str(listing))
    assert r.returncode == 0, r.stderr
    assert "2 unit(s) recorded as analyzed" in r.stdout

    r = run("coverage", "--db", dbp, "--record", "--phase", "audit",
            "--state", "not_audited", "--reason", "vendored",
            "--unit", "vendor/z.c")
    assert r.returncode == 0, r.stderr

    after = run("coverage", "--db", dbp, "--gate", "--phase", "audit")
    assert after.returncode == 0, after.stdout + after.stderr
    assert "coverage gate: PASS" in after.stdout


def test_coverage_record_refuses_a_gap_with_no_reason(tmp_path):
    dbp = _inventoried(tmp_path, "src/a.c")
    r = run("coverage", "--db", dbp, "--record", "--phase", "audit",
            "--state", "not_audited", "--unit", "src/a.c")
    assert r.returncode == 1
    assert "reason" in r.stderr
    assert run("coverage", "--db", dbp, "--gate", "--phase",
               "audit").returncode == 1


def test_coverage_record_needs_a_phase(tmp_path):
    dbp = _inventoried(tmp_path, "src/a.c")
    r = run("coverage", "--db", dbp, "--record", "--state", "analyzed",
            "--unit", "src/a.c")
    assert r.returncode == 1
    assert "--phase" in r.stderr


def test_coverage_write_flags_without_record_are_refused(tmp_path):
    """Silently ignoring a write flag on a read-only invocation is how an
    operator believes a gate was cleared when nothing was written."""
    dbp = _inventoried(tmp_path, "src/a.c")
    r = run("coverage", "--db", dbp, "--phase", "audit", "--unit", "src/a.c")
    assert r.returncode == 1
    assert "--record" in r.stderr


def test_coverage_record_names_a_missing_list_file(tmp_path):
    dbp = _inventoried(tmp_path, "src/a.c")
    r = run("coverage", "--db", dbp, "--record", "--phase", "audit",
            "--state", "analyzed", "--from-file", str(tmp_path / "nope.txt"))
    assert r.returncode == 1
    assert "not found" in r.stderr


# --- the minors, each reproduced before it was fixed -------------------------


def test_rows_columns_tolerates_the_space_after_a_comma(tmp_path):
    """`--columns "id, title"` is the natural way to type a list, and it
    answered `has no column(s):  title` -- naming a column that differs from
    a real one only by a space nobody can see."""
    dbp = seeded(tmp_path)
    r = run("rows", "--db", dbp, "--table", "cba_findings",
            "--columns", "id, title")
    assert r.returncode == 0, r.stderr
    assert "G1-F1" in r.stdout


def test_sweep_refuses_a_nonsense_max_hits(tmp_path):
    dbp = seeded(tmp_path)
    assert run("put", "--db", dbp, "--table", "cba_patterns", "--set", "id=P1",
               "--set", "name=n", "--set", r"regex=strcpy\(").returncode == 0
    r = run("sweep", "--db", dbp, "--pattern", "P1", "--root", str(tmp_path),
            "--max-hits", "-1")
    assert r.returncode == 1
    assert "--max-hits must be at least 1" in r.stderr


def test_sweep_says_when_it_clamps_an_oversized_max_hits(tmp_path):
    dbp = seeded(tmp_path)
    assert run("put", "--db", dbp, "--table", "cba_patterns", "--set", "id=P1",
               "--set", "name=n", "--set", r"regex=strcpy\(").returncode == 0
    r = run("sweep", "--db", dbp, "--pattern", "P1", "--root", str(tmp_path),
            "--max-hits", "100000")
    assert r.returncode == 0, r.stderr
    assert "clamped" in r.stderr


def test_sweep_without_record_opens_the_database_read_only(tmp_path):
    """A sweep that only reports has no business holding the run's database
    open for writing."""
    dbp = seeded(tmp_path)
    assert run("put", "--db", dbp, "--table", "cba_patterns", "--set", "id=P1",
               "--set", "name=n", "--set", r"regex=strcpy\(").returncode == 0
    import os
    os.chmod(dbp, 0o444)
    try:
        r = run("sweep", "--db", dbp, "--pattern", "P1", "--root", str(tmp_path))
        assert r.returncode == 0, r.stdout + r.stderr
    finally:
        os.chmod(dbp, 0o644)


def test_chain_compose_refuses_json_instead_of_ignoring_it(tmp_path):
    """Accepted and silently ignored before: a flag that changes nothing is a
    flag whose absence from the output reads as a failed write."""
    dbp = seeded(tmp_path)
    assert run("put", "--db", dbp, "--table", "cba_findings",
               "--set", "id=G2-F1", "--set", "group_id=G2", "--set", "title=t",
               "--set", "severity=HIGH", "--set", "confidence=9",
               "--set", "location=src/b.c:1", "--set", "root_cause=rc",
               "--set", "impact=im").returncode == 0
    r = run("chain", "--db", dbp, "--compose", "C1",
            "--findings", "G1-F1,G2-F1", "--attacker-position", "LAN",
            "--completeness", "complete", "--json")
    assert r.returncode == 1
    assert "--json" in r.stderr
    assert "rows --table cba_chains" in r.stderr
