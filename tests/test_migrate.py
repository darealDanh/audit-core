import sqlite3

import pytest

from audit_core import db, workspace

# The two Stage 2 tables this stage adds columns to, exactly as Stage 2
# shipped them. Embedded rather than read from git history: this fixture is
# the definition of "the database an upgrading user actually has".
STAGE2_SQL = """
CREATE TABLE IF NOT EXISTS cba_fp_verdicts (
    finding_id TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    reason TEXT,
    final_severity TEXT,
    final_id TEXT,
    merged_into TEXT,
    rule_applied TEXT,
    reviewed_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_patterns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    regex TEXT NOT NULL,
    origin_finding TEXT,
    language TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')));
"""

# A full pre-Stage-3 baseline: every table TABLE_SPECS declares, each in the
# form it had before this stage. It lives in audit_core/ rather than here
# because `audit.py selftest` runs the same check from the installed skill,
# and install.sh copies audit_core/ but not tests/. Read its header before
# editing it: the file is frozen on purpose.
FULL_PRE_STAGE3_SQL = workspace.BASELINE_PATH.read_text()


def columns(con, table):
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def downgrade_cba_patterns(con):
    """Rebuild cba_patterns without the Stage 3 columns, which is what a
    pre-Stage-3 database holds."""
    con.executescript(
        "DROP TABLE cba_patterns;"
        "CREATE TABLE cba_patterns (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " regex TEXT NOT NULL, origin_finding TEXT, language TEXT,"
        " notes TEXT, created_at TEXT);")
    con.commit()


def test_a_stage2_database_migrates_to_the_current_column_set(tmp_path):
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.executescript(STAGE2_SQL)
    con.execute("INSERT INTO cba_fp_verdicts (finding_id, verdict) "
                "VALUES ('G1-F1', 'TRUE_POSITIVE')")
    con.commit()

    applied = db.migrate(con)

    assert "cba_fp_verdicts.refuting_mechanism" in applied
    assert "cba_patterns.hit_count" in applied
    for table in ("cba_fp_verdicts", "cba_patterns"):
        assert columns(con, table) >= set(db.TABLE_SPECS[table].columns)
    # The row an upgrading user already had is still there.
    assert con.execute("SELECT COUNT(*) FROM cba_fp_verdicts").fetchone()[0] == 1
    # Idempotent: a second call against the database it just migrated adds
    # nothing more.
    assert db.migrate(con) == []
    con.close()


def test_migrate_is_idempotent(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    assert db.migrate(con) == []
    con.close()


def test_migrate_skips_a_table_that_is_not_there(tmp_path):
    """An empty database is not an error; it is a database `init` has not
    touched yet. Reporting it as a failed migration would make `init` loud
    on the one path where it has nothing to do."""
    con = sqlite3.connect(tmp_path / "empty.db")
    assert db.migrate(con) == []
    con.close()


def test_every_migration_names_a_column_its_table_spec_declares():
    """The guard that keeps MIGRATIONS and TABLE_SPECS from drifting. A
    migration for a column no spec declares adds a column `put` will reject;
    a spec column with no migration is a column an upgraded database lacks."""
    for table, column, _type in db.MIGRATIONS:
        assert table in db.TABLE_SPECS, table
        assert column in db.TABLE_SPECS[table].columns, f"{table}.{column}"


def test_a_fresh_database_needs_no_migration_for_any_spec_column(tmp_path):
    """schema.sql and TABLE_SPECS agree on a fresh build, so MIGRATIONS only
    ever has work to do on an older database."""
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    for table, spec in db.TABLE_SPECS.items():
        assert columns(con, table) >= set(spec.columns), table
    con.close()


def test_connect_names_a_missing_column_and_gives_the_remedy(tmp_path):
    """Review Focus 1: the normal upgrade path. A run directory created
    before this stage has every table and is missing four columns. Stage 2
    closed this at table granularity; a missing column produced
    `sqlite3.OperationalError: no such column` from six verbs."""
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    downgrade_cba_patterns(con)
    con.close()

    with pytest.raises(db.DbError) as exc:
        db.connect(run / "audit.db")
    message = str(exc.value)
    assert "cba_patterns.swept_at" in message
    assert "audit.py init" in message
    assert "--timestamp" in message


def test_connect_succeeds_once_the_missing_columns_are_migrated(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    downgrade_cba_patterns(con)
    db.migrate(con)
    con.close()
    db.connect(run / "audit.db").close()


def test_migrate_closes_every_column_gap_the_connect_gate_would_reject(tmp_path):
    """Review Focus 2: the gate must never reject a column migrate() cannot
    repair. MIGRATIONS and TABLE_SPECS are built independently, and nothing
    but this test keeps them in lockstep -- add a TABLE_SPECS column with no
    MIGRATIONS entry, and connect() rejects every pre-Stage-3 database with
    a remedy (`audit.py init --timestamp <ts>`) that runs clean, exits 0,
    and repairs nothing; the user's only escape would be hand-editing
    SQLite.

    Every table TABLE_SPECS declares is present in FULL_PRE_STAGE3_SQL, so
    connect()'s table check cannot be what makes this pass or fail -- only
    the column check, and only migrate(), are under test here.
    """
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.executescript(FULL_PRE_STAGE3_SQL)
    con.commit()
    db.migrate(con)
    con.close()

    db.connect(old).close()


def test_selftest_catches_a_spec_column_that_has_no_migration(monkeypatch, capsys):
    """IMPORTANT. `cmd_selftest` compared TABLE_SPECS to schema.sql and
    nothing compared schema.sql to MIGRATIONS. The next stage that adds a
    column inline to an already-shipped table and forgets MIGRATIONS passes
    selftest, passes every test, and permanently bricks every existing run
    directory -- connect() rejects it, `init` cannot repair it, and the
    printed remedy is the thing that cannot help.

    Emptying MIGRATIONS is that defect in its purest form: schema.sql and
    TABLE_SPECS still agree, so checks 1 and 2 pass, and only the baseline
    cross-check can see it.
    """
    import audit

    monkeypatch.setattr(db, "MIGRATIONS", ())
    assert audit.cmd_selftest(None) == 1
    err = capsys.readouterr().err
    assert "pre-Stage-3" in err
    assert "db.MIGRATIONS" in err


def test_selftest_passes_the_migration_cross_check_as_shipped(capsys):
    import audit

    assert audit.cmd_selftest(None) == 0
    assert "migrations" in capsys.readouterr().out


def test_the_frozen_baseline_is_not_a_second_copy_of_the_schema():
    """It must stay behind schema.sql, or it cannot catch anything. The four
    Stage 3 columns are absent from it by construction; if an edit ever
    "fixed" it to match schema.sql, migrate() would have nothing to do and
    the cross-check would pass vacuously."""
    import sqlite3 as _sqlite3
    con = _sqlite3.connect(":memory:")
    con.executescript(workspace.BASELINE_PATH.read_text())
    try:
        for table, column, _type in db.MIGRATIONS:
            assert column not in columns(con, table), (
                f"{table}.{column} is already in the frozen baseline, so the "
                f"selftest cross-check can no longer prove migrate() adds it")
    finally:
        con.close()
