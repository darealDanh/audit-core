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

def test_selftest_cross_checks_the_table_contract_against_the_real_schema():
    r = run("selftest")
    assert r.returncode == 0, r.stderr
    assert "tables" in r.stdout
    assert "verbs" in r.stdout


def test_selftest_fails_when_a_spec_column_is_not_in_the_schema(tmp_path):
    """Stage 0's finding: a tool's output is only trustworthy if the tool is
    validated against something it did not produce. TABLE_SPECS is
    hand-maintained; schema.sql builds the database. They can drift."""
    import audit
    from audit_core import db
    original = db.TABLE_SPECS["cba_findings"]
    db.TABLE_SPECS["cba_findings"] = db.TableSpec(
        columns=original.columns + ("imaginary_column",),
        required=original.required, validate=original.validate)
    try:
        assert audit.cmd_selftest(None) == 1
    finally:
        db.TABLE_SPECS["cba_findings"] = original


def test_selftest_fails_when_a_handler_has_no_subparser():
    import audit
    audit.HANDLERS["ghost"] = lambda args: 0
    try:
        assert audit.cmd_selftest(None) == 1
    finally:
        del audit.HANDLERS["ghost"]
