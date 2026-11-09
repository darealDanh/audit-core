"""Stage 4j firmware-report durable lifecycle contracts."""
import sqlite3

import pytest

from audit_core import db, workspace


RUN_TABLE = "cba_firmware_report_runs"
ITEM_TABLE = "cba_firmware_report_items"
RUN_COLUMNS = (
    "image_id", "report_generation", "preparation_ordinal", "status",
    "decision_generation", "decision_package_sha256", "style_contract_sha256",
    "manifest_path", "manifest_sha256", "item_count", "results_path",
    "results_sha256", "result_count", "report_path", "report_sha256",
    "report_bytes", "index_path", "index_sha256", "prepared_at", "recorded_at",
    "completed_at", "superseded_at")
RUN_OPTIONAL = (
    "results_path", "results_sha256", "report_path", "report_sha256",
    "report_bytes", "index_path", "index_sha256", "recorded_at",
    "completed_at", "superseded_at")
ITEM_COLUMNS = (
    "image_id", "report_generation", "chain_id", "ordinal", "assignment_path",
    "assignment_sha256", "result_path", "result_sha256", "recorded_at")
ITEM_OPTIONAL = ("result_sha256", "recorded_at")

PENDING = {
    "image_id": "路由器|r1|target", "report_generation": "a" * 64,
    "preparation_ordinal": 1, "status": "pending", "decision_generation": "b" * 64,
    "decision_package_sha256": "c" * 64, "style_contract_sha256": "d" * 64,
    "manifest_path": "files/firmware-report/manifest.json", "manifest_sha256": "e" * 64,
    "item_count": 2, "result_count": 0, "prepared_at": "2026-11-09 01:02:03"}
RECORDED = PENDING | {
    "status": "recorded", "results_path": "artifacts/firmware-report/results.json",
    "results_sha256": "f" * 64, "result_count": 2,
    "recorded_at": "2026-11-09 02:03:04"}
COMPLETE = RECORDED | {
    "status": "complete", "report_path": "artifacts/firmware-report/report.md",
    "report_sha256": "1" * 64, "report_bytes": b"Firmware assessment report\n",
    "index_path": "artifacts/firmware-report/report.json", "index_sha256": "2" * 64,
    "completed_at": "2026-11-09 03:04:05"}
SUPERSEDED_PENDING = PENDING | {
    "status": "superseded", "superseded_at": "2026-11-09 02:30:00"}
SUPERSEDED_RECORDED = RECORDED | {
    "status": "superseded", "superseded_at": "2026-11-09 03:30:00"}
ITEM = {
    "image_id": PENDING["image_id"], "report_generation": PENDING["report_generation"],
    "chain_id": "CHAIN-1", "ordinal": 1,
    "assignment_path": "files/firmware-report/items/1-CHAIN-1.json",
    "assignment_sha256": "3" * 64,
    "result_path": "artifacts/firmware-report-results/CHAIN-1/result.json"}
RECORDED_ITEM = ITEM | {"result_sha256": "4" * 64, "recorded_at": "2026-11-09 02:03:04"}


@pytest.fixture
def con(tmp_path):
    run = workspace.init_run(tmp_path)
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


def _contract(con, table, columns, optional, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    required = tuple(column for column in columns if column not in optional)
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted((row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert (spec.columns, spec.required, spec.primary_key) == (columns, required, key)


def test_report_exact_sql_and_tablespec_contracts(con):
    _contract(con, RUN_TABLE, RUN_COLUMNS, RUN_OPTIONAL, ("image_id", "report_generation"))
    _contract(con, ITEM_TABLE, ITEM_COLUMNS, ITEM_OPTIONAL,
              ("image_id", "report_generation", "chain_id"))
    assert con.execute(
        f"SELECT type FROM pragma_table_info('{RUN_TABLE}') "
        "WHERE name='report_bytes'").fetchone()[0] == "BLOB"


def test_report_adds_two_ordered_table_migrations(tmp_path):
    run = workspace.init_run(tmp_path)
    assert len(workspace.apply_schema(run / "audit.db").tables) == 47
    assert len(db.TABLE_SPECS) == 46
    assert len(db.MIGRATIONS) == 8
    assert db.MIGRATIONS[-2:] == ((RUN_TABLE, None, None), (ITEM_TABLE, None, None))
    assert db.FIRMWARE_REPORT_STATES == ("pending", "recorded", "complete", "superseded")
    assert db.FIRMWARE_REPORT_SEVERITIES == ("critical", "high", "medium", "low", "informational")


def test_report_upgrade_from_pre_stage4j_creates_empty_tables_and_preserves_rows(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(workspace.SCHEMA_PATH.read_text())
    con.execute(f"DROP TABLE {ITEM_TABLE}")
    con.execute(f"DROP TABLE {RUN_TABLE}")
    con.execute("INSERT INTO cba_patterns (id,name,regex) VALUES ('p','old','x')")
    con.commit()
    assert db.migrate(con) == [RUN_TABLE, ITEM_TABLE]
    assert db.migrate(con) == []
    assert con.execute(f"SELECT COUNT(*) FROM {RUN_TABLE}").fetchone()[0] == 0
    assert con.execute(f"SELECT COUNT(*) FROM {ITEM_TABLE}").fetchone()[0] == 0
    assert con.execute("SELECT name FROM cba_patterns WHERE id='p'").fetchone()[0] == "old"
    con.close()
    result = workspace.apply_schema(path)
    assert {RUN_TABLE, ITEM_TABLE} <= set(result.tables)
    assert result.migrated == []
    db.connect(path).close()


@pytest.mark.parametrize("row", [PENDING, RECORDED, COMPLETE, SUPERSEDED_PENDING, SUPERSEDED_RECORDED])
def test_report_run_lifecycle_variants_roundtrip(con, row):
    db.put(con, RUN_TABLE, row)
    stored = dict(db.rows(con, RUN_TABLE)[0])
    assert all(stored[key] == value for key, value in row.items())


@pytest.mark.parametrize("row,column", [
    (PENDING | {"result_count": 1}, "result_count"),
    (PENDING | {"results_path": "artifacts/results.json"}, "results_path"),
    (RECORDED | {"result_count": 1}, "result_count"),
    (RECORDED | {"results_sha256": None}, "results_sha256"),
    (RECORDED | {"report_path": "artifacts/report.md"}, "report_path"),
    (COMPLETE | {"index_sha256": None}, "index_sha256"),
    (COMPLETE | {"superseded_at": "2026-11-09 04:00:00"}, "superseded_at"),
    (SUPERSEDED_PENDING | {"recorded_at": "2026-11-09 02:00:00"}, "results_path"),
    (SUPERSEDED_RECORDED | {"report_sha256": "5" * 64}, "report_sha256"),
])
def test_report_run_rejects_inconsistent_lifecycle_fields(con, row, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, RUN_TABLE, row)
    assert not con.in_transaction


@pytest.mark.parametrize("row,match", [
    (PENDING | {"status": "ready"}, "status"),
    (PENDING | {"preparation_ordinal": 0}, "preparation_ordinal"),
    (PENDING | {"item_count": -1}, "item_count"),
    (COMPLETE | {"report_bytes": ""}, "report_bytes"),
    (COMPLETE | {"recorded_at": "2026-11-09 00:00:00"}, "recorded_at precedes prepared_at"),
    (COMPLETE | {"completed_at": "2026-11-09 01:00:00"}, "completed_at precedes recorded_at"),
    (SUPERSEDED_PENDING | {"superseded_at": "2026-11-09 00:00:00"}, "superseded_at precedes prepared_at"),
    (PENDING | {"prepared_at": "2026-02-30 00:00:00"}, "prepared_at requires a real"),
])
def test_report_run_rejects_invalid_counts_states_and_timestamps(con, row, match):
    with pytest.raises(db.DbError, match=match):
        db.put(con, RUN_TABLE, row)


@pytest.mark.parametrize("row", [RECORDED, COMPLETE])
def test_report_recorded_variants_require_prepared_at_before_later_timestamps(con, row):
    without_prepared = {key: value for key, value in row.items() if key != "prepared_at"}
    with pytest.raises(db.DbError, match="requires a non-empty value for: prepared_at"):
        db.put(con, RUN_TABLE, without_prepared)
    with pytest.raises(db.DbError, match="prepared_at requires a non-empty string"):
        db.put(con, RUN_TABLE, row | {"prepared_at": None})


@pytest.mark.parametrize("row", [PENDING, RECORDED])
def test_report_superseded_rows_require_their_own_supersede_stamp(con, row):
    with pytest.raises(db.DbError,
                       match="superseded_at is required for a superseded report"):
        db.put(con, RUN_TABLE, row | {"status": "superseded"})


def test_report_item_ordinal_is_unique_within_generation(con):
    db.put(con, ITEM_TABLE, ITEM)
    with pytest.raises(db.DbError, match="UNIQUE constraint failed"):
        db.put(con, ITEM_TABLE, ITEM | {"chain_id": "CHAIN-2"})


@pytest.mark.parametrize("row", [ITEM, RECORDED_ITEM])
def test_report_item_prepared_and_recorded_variants_roundtrip(con, row):
    db.put(con, ITEM_TABLE, row)
    assert all(dict(db.rows(con, ITEM_TABLE)[0])[key] == value for key, value in row.items())


@pytest.mark.parametrize("row,column", [
    (ITEM | {"ordinal": 0}, "ordinal"),
    (ITEM | {"result_sha256": "4" * 64}, "recorded_at"),
    (ITEM | {"recorded_at": "2026-11-09 02:03:04"}, "result_sha256"),
    (RECORDED_ITEM | {"result_sha256": "CRITICAL"}, "result_sha256"),
])
def test_report_item_rejects_invalid_ordinal_or_partial_result(con, row, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, ITEM_TABLE, row)


def test_report_item_storage_is_severity_independent(con):
    assert "severity" not in db.TABLE_SPECS[ITEM_TABLE].columns
    db.put(con, ITEM_TABLE, RECORDED_ITEM)
