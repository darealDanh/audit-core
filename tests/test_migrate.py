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


@pytest.mark.parametrize("baseline", ["baseline-pre-stage3.sql", "baseline-stage4b.sql"])
def test_firmware_tables_upgrade_frozen_baselines_without_changing_old_rows(tmp_path, baseline):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript((workspace.SCHEMA_PATH.parent / baseline).read_text())
    con.execute("INSERT INTO cba_patterns (id, name, regex, created_at) VALUES "
                "('old-pattern', 'Original', 'test', '2026-01-02 03:04:05')")
    con.execute("INSERT INTO cba_findings (id, group_id, title, severity, confidence, "
                "location, root_cause, impact, created_at) VALUES "
                "('old-finding', 'G1', 'Original', 'HIGH', 8, 'src/a.c:1', "
                "'unchecked length', 'overwrite', '2026-01-03 04:05:06')")
    if baseline == "baseline-stage4b.sql":
        con.execute("INSERT INTO cba_binfacts (path, image_id, machine, bits, endian, elf_type, recorded_at) "
                    "VALUES ('bin/httpd', 'image.1', 'mips', 32, 'big', 'EXEC', '2026-01-04 05:06:07')")
        con.execute("INSERT INTO cba_services (name, image_id, start_source, evidence, recorded_at) "
                    "VALUES ('httpd', 'image.1', 'etc/init.d/S50httpd', "
                    "'init invokes /bin/httpd', '2026-01-04 05:06:07')")
    firmware_tables = ("cba_binfacts", "cba_services") if baseline == "baseline-stage4b.sql" else ()
    preserved_tables = ("cba_patterns", "cba_findings", *firmware_tables)
    con.commit()
    old_rows = {table: con.execute(f"SELECT * FROM {table}").fetchall()
                for table in preserved_tables}
    old_columns = {table: tuple(row[1] for row in con.execute(f"PRAGMA table_info({table})"))
                   for table in old_rows}
    con.close()
    result = workspace.apply_schema(path)
    assert len(result.tables) == 38
    con = db.connect(path)
    try:
        for table in ("cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns",
                      "cba_hunt_runs", "cba_hunt_receipts", "cba_hunt_candidates",
                      "cba_firmware_fp_runs", "cba_firmware_fp_receipts",
                      "cba_firmware_fp_verdicts", "cba_firmware_pivots", "cba_firmware_findings",
                      "cba_firmware_chain_runs", "cba_firmware_chain_receipts",
                      "cba_firmware_chain_dispositions", "cba_firmware_chain_unknowns",
                      "cba_firmware_chains", "cba_firmware_chain_edges"):
            assert db.rows(con, table) == []
        for table in old_rows:
            assert [tuple(row) for row in con.execute(
                f"SELECT {', '.join(old_columns[table])} FROM {table}")] == old_rows[table]
        assert db.migrate(con) == []
    finally:
        con.close()
    second = workspace.apply_schema(path)
    assert second.tables == result.tables
    assert second.migrated == []
    third = workspace.apply_schema(path)
    assert third.tables == result.tables
    assert third.migrated == []
    con = db.connect(path)
    try:
        for table in old_rows:
            assert [tuple(row) for row in con.execute(
                f"SELECT {', '.join(old_columns[table])} FROM {table}")] == old_rows[table]
    finally:
        con.close()


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


def test_apply_schema_closes_every_gap_the_connect_gate_would_reject(tmp_path):
    """The remedy printed by connect() must add both tables and columns.

    New tables come from schema.sql; columns added to previously shipped
    tables come from MIGRATIONS. Applying only either half leaves a real old
    run unusable once both kinds of change exist.
    """
    old = tmp_path / "old.db"
    con = sqlite3.connect(old)
    con.executescript(FULL_PRE_STAGE3_SQL)
    con.commit()
    con.close()

    workspace.apply_schema(old)

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


def stage4b_database(path):
    con = sqlite3.connect(path)
    con.executescript((workspace.SCHEMA_PATH.parent / "baseline-stage4b.sql").read_text())
    con.execute("INSERT INTO cba_binfacts "
                "(path, image_id, machine, bits, endian, elf_type, needed, recorded_at) "
                "VALUES ('bin/httpd', 'acme|r1|1.0', 'mips', 32, 'big', 'EXEC', "
                "'libc.so.0', '2026-10-01 01:02:03')")
    con.execute("INSERT INTO cba_services "
                "(name, image_id, start_source, exec_path, evidence, ports, "
                "ports_evidence, recorded_at) VALUES "
                "('httpd', NULL, 'etc/init.d/S50httpd', '/bin/httpd', "
                "'exec /bin/httpd', '80/tcp', 'httpd.conf:1 listen 80', "
                "'2026-10-02 04:05:06')")
    con.commit()
    return con


def test_connect_rejects_stage4b_keys_with_current_columns(tmp_path):
    path = tmp_path / "stage4b.db"
    con = stage4b_database(path)
    # Add current tables without migrating the stale firmware primary keys.
    con.executescript(workspace.SCHEMA_PATH.read_text())
    con.close()
    with pytest.raises(db.DbError) as exc:
        db.connect(path)
    assert "primary key" in str(exc.value)
    assert "cba_binfacts" in str(exc.value)
    assert "cba_services" in str(exc.value)
    assert "audit.py init" in str(exc.value)
    assert "--timestamp" in str(exc.value)


def test_stage4b_migration_preserves_every_value_and_is_idempotent(tmp_path):
    con = stage4b_database(tmp_path / "stage4b.db")
    try:
        original_binary = con.execute("SELECT * FROM cba_binfacts").fetchone()
        original_service = con.execute("SELECT * FROM cba_services").fetchone()
        binary_columns = db.table_columns(con, "cba_binfacts")
        service_columns = db.table_columns(con, "cba_services")
        assert db.migrate(con) == ["cba_binfacts.primary_key", "cba_services.primary_key"]
        assert db.primary_key(con, "cba_binfacts") == ("image_id", "path")
        assert db.primary_key(con, "cba_services") == ("image_id", "name")
        binary = con.execute("SELECT " + ", ".join(binary_columns) + " FROM cba_binfacts").fetchone()
        service = con.execute("SELECT " + ", ".join(service_columns) + " FROM cba_services").fetchone()
        assert binary == original_binary
        expected_service = list(original_service)
        expected_service[service_columns.index("image_id")] = "legacy-unscoped"
        assert service == tuple(expected_service)
        assert db.migrate(con) == []
    finally:
        con.close()


def test_stage4b_second_rebuild_failure_rolls_back_both_tables(tmp_path, monkeypatch):
    con = stage4b_database(tmp_path / "stage4b.db")
    original = {table: con.execute(f"SELECT * FROM {table}").fetchall()
                for table in ("cba_binfacts", "cba_services")}
    rebuild = getattr(db, "_rebuild_firmware_table", None)

    def fail_services(connection, table):
        if table == "cba_services":
            raise RuntimeError("forced second rebuild failure")
        assert rebuild is not None
        rebuild(connection, table)

    monkeypatch.setattr(db, "_rebuild_firmware_table", fail_services, raising=False)
    try:
        with pytest.raises(RuntimeError, match="forced second rebuild failure"):
            db.migrate(con)
        assert db.primary_key(con, "cba_binfacts") == ("path",)
        assert db.primary_key(con, "cba_services") == ("name",)
        for table, rows in original.items():
            assert con.execute(f"SELECT * FROM {table}").fetchall() == rows
        assert not con.execute("SELECT name FROM sqlite_master "
                               "WHERE name LIKE '%stage4c%'").fetchall()
    finally:
        con.close()


def test_selftest_checks_stage4b_migration_and_primary_key_contract(monkeypatch, capsys):
    import audit
    from dataclasses import replace

    monkeypatch.setitem(db.TABLE_SPECS, "cba_services",
                        replace(db.TABLE_SPECS["cba_services"], primary_key=("name",)))
    assert audit.cmd_selftest(None) == 1
    assert "primary key" in capsys.readouterr().err
