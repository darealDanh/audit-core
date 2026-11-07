"""Stage 4i one-row lifecycle contract, exercised through SQLite writes."""
import json
import sqlite3

import pytest

from audit_core import db, firmware_decide as decide, workspace


TABLE = "cba_firmware_decide_runs"
COLUMNS = (
    "image_id", "decision_generation", "manifest_sha256", "surface_snapshot_sha256",
    "candidate_snapshot_sha256", "chain_worklist_sha256", "graph_path", "graph_sha256",
    "dive_generation", "journal_path", "journal_sha256", "overlay_sha256", "policy_id",
    "policy_path", "policy_sha256", "worklist_path", "worklist_sha256", "status",
    "result_path", "result_sha256", "package_path", "package_sha256", "decision",
    "primary_reason", "reason_codes", "chain_count", "bench_test_count", "script_count",
    "policy_match_count", "prepared_at", "recorded_at", "completed_at", "superseded_at",
    "preparation_ordinal")
OPTIONAL = (
    "result_path", "result_sha256", "package_path", "package_sha256", "decision",
    "primary_reason", "reason_codes", "prepared_at", "recorded_at", "completed_at",
    "superseded_at")
BASE = {
    "image_id": "路由器|r1|target", "decision_generation": "a" * 64,
    "manifest_sha256": "b" * 64, "surface_snapshot_sha256": "c" * 64,
    "candidate_snapshot_sha256": "d" * 64, "chain_worklist_sha256": "e" * 64,
    "graph_path": "artifacts/firmware-chain/graph.json", "graph_sha256": "f" * 64,
    "dive_generation": "1" * 64, "journal_path": "artifacts/firmware-dive/journal.json",
    "journal_sha256": "2" * 64, "overlay_sha256": "3" * 64,
    "policy_id": "operator-2026-11", "policy_path": "files/firmware-decide/policy.json",
    "policy_sha256": "4" * 64, "worklist_path": "files/firmware-decide/worklist.json",
    "worklist_sha256": "a" * 64, "status": "pending", "chain_count": 2,
    "bench_test_count": 0, "script_count": 0, "policy_match_count": 0,
    "preparation_ordinal": 1}
RECORDED = BASE | {"status": "recorded", "result_path": "artifacts/firmware-decide-results/result.json",
    "result_sha256": "5" * 64, "recorded_at": "2026-11-04 01:02:03"}
COMPLETE = RECORDED | {"status": "complete", "package_path": "artifacts/firmware-decide/decision.json",
    "package_sha256": "6" * 64, "decision": "acquire", "primary_reason": "eligible-chain",
    "reason_codes": '["eligible-policy-match","bench-plan-complete"]',
    "bench_test_count": 1, "script_count": 1, "policy_match_count": 1,
    "completed_at": "2026-11-04 02:03:04"}
SUPERSEDED = BASE | {"status": "superseded", "superseded_at": "2026-11-04 03:04:05"}
SUPERSEDED_RECORDED = RECORDED | {"status": "superseded", "superseded_at": "2026-11-04 03:04:05"}


@pytest.fixture
def con(tmp_path):
    run = workspace.init_run(tmp_path)
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


def test_decide_exact_sql_and_tablespec_contract(con):
    info = list(con.execute(f"PRAGMA table_info({TABLE})"))
    required = tuple(column for column in COLUMNS if column not in OPTIONAL)
    assert tuple(row[1] for row in info) == COLUMNS
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted((row[5], row[1]) for row in info if row[5])) == (
        "image_id", "decision_generation")
    spec = db.TABLE_SPECS[TABLE]
    assert (spec.columns, spec.required, spec.primary_key) == (
        COLUMNS, required, ("image_id", "decision_generation"))


def test_decide_adds_one_table_and_two_lifecycle_migrations(tmp_path):
    run = workspace.init_run(tmp_path)
    assert len(workspace.apply_schema(run / "audit.db").tables) == 45
    assert len(db.TABLE_SPECS) == 44
    assert len(db.MIGRATIONS) == 6
    assert db.MIGRATIONS[-2:] == (
        (TABLE, "superseded_at", "TEXT"),
        (TABLE, "preparation_ordinal", "INTEGER NOT NULL DEFAULT 0"))


def test_shipped_decide_table_gains_lifecycle_columns_by_migration(tmp_path):
    """Catches adding Stage 4i lifecycle columns inline only, bricking shipped run dirs."""
    run = workspace.init_run(tmp_path)
    path = run / "audit.db"
    raw = sqlite3.connect(path)
    try:
        ddl = raw.execute("SELECT sql FROM sqlite_master WHERE name=?", (TABLE,)).fetchone()[0]
        legacy = ddl.replace("    superseded_at TEXT,\n", "").replace(
            "    preparation_ordinal INTEGER NOT NULL DEFAULT 0,\n", "")
        assert "superseded_at" not in legacy and "preparation_ordinal" not in legacy
        raw.execute(f"DROP TABLE {TABLE}")
        raw.execute(legacy)
        shipped = {key: value for key, value in COMPLETE.items() if key != "preparation_ordinal"}
        shipped["prepared_at"] = "2026-11-04 00:00:00"
        for generation in ("a" * 64, "b" * 64):
            row = shipped | {"decision_generation": generation, "worklist_sha256": generation}
            raw.execute(f"INSERT INTO {TABLE} ({','.join(row)}) VALUES "
                        f"({','.join('?' for _ in row)})", tuple(row.values()))
        raw.commit()
        with pytest.raises(db.DbError, match="preparation_ordinal"):
            db.connect(path).close()
        assert db.migrate(raw) == [f"{TABLE}.superseded_at", f"{TABLE}.preparation_ordinal"]
        assert db.migrate(raw) == []
    finally:
        raw.close()
    con = db.connect(path)
    try:
        stored = db.rows(con, TABLE)
        assert [(row["preparation_ordinal"], row["superseded_at"]) for row in stored] == [
            (0, None), (0, None)]
        for row in stored:
            db.TABLE_SPECS[TABLE].validate(dict(row))
        # Shipped history has no preparation order, so selection refuses to guess.
        with pytest.raises(decide.FirmwareDecideError, match="Latest prepared"):
            decide._select_decision_row(con, COMPLETE["image_id"])
        con.execute(f"DELETE FROM {TABLE} WHERE decision_generation=?", ("b" * 64,))
        con.commit()
        assert decide._select_decision_row(con, COMPLETE["image_id"])[
            "decision_generation"] == "a" * 64
    finally:
        con.close()


@pytest.mark.parametrize("row", [BASE, RECORDED, COMPLETE, SUPERSEDED, SUPERSEDED_RECORDED])
def test_decide_lifecycle_variants_roundtrip(con, row):
    db.put(con, TABLE, row)
    stored = dict(db.rows(con, TABLE)[0])
    assert all(stored[key] == value for key, value in row.items())
    assert isinstance(stored["prepared_at"], str) and len(stored["prepared_at"]) == 19


@pytest.mark.parametrize("column", [column for column in COLUMNS if column not in OPTIONAL])
@pytest.mark.parametrize("value", ["omit", "", " \t", None, True])
def test_decide_required_values_fail_before_sql(con, column, value):
    row = dict(BASE)
    if value == "omit":
        row.pop(column)
    else:
        row[column] = value
    with pytest.raises(db.DbError, match=column):
        db.put(con, TABLE, row)
    assert not con.in_transaction


@pytest.mark.parametrize("column,value", [
    ("status", "ready"), ("decision", "buy"), ("decision_generation", "A" * 64),
    ("graph_sha256", "x" * 64), ("graph_path", "../escape"),
    ("chain_count", -1), ("chain_count", True), ("policy_match_count", 1.5),
    ("primary_reason", "not-a-reason"),
])
def test_decide_invalid_scalars_fail_without_writes(con, column, value):
    row = COMPLETE | {column: value}
    with pytest.raises(db.DbError, match=column):
        db.put(con, TABLE, row)
    assert not con.in_transaction


@pytest.mark.parametrize("value", ['["bench-plan-complete", "eligible-policy-match"]',
    '["eligible-policy-match","eligible-policy-match"]', '{"a":1}', '[1]', '[]\n'])
def test_decide_reason_codes_require_canonical_ordered_known_values(con, value):
    with pytest.raises(db.DbError, match="reason_codes"):
        db.put(con, TABLE, COMPLETE | {"reason_codes": value})


@pytest.mark.parametrize("row,column", [
    (BASE | {"result_path": "artifacts/r.json"}, "result_path"),
    (RECORDED | {"decision": "defer"}, "decision"),
    (COMPLETE | {"recorded_at": None}, "recorded_at"),
    (COMPLETE | {"package_path": None}, "package_path"),
    (SUPERSEDED | {"superseded_at": None}, "superseded_at"),
    (RECORDED | {"superseded_at": "2026-11-04 03:04:05"}, "superseded_at"),
    (COMPLETE | {"superseded_at": "2026-11-04 03:04:05"}, "superseded_at"),
    (SUPERSEDED_RECORDED | {"result_path": None}, "result_path"),
    (SUPERSEDED | {"completed_at": "2026-11-04 03:04:05"}, "completed_at"),
])
def test_decide_lifecycle_rejects_cross_variant_fields(con, row, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, TABLE, row)


@pytest.mark.parametrize("row,match", [
    (COMPLETE | {"completed_at": "2026-11-04T02:03:04"}, "completed_at requires a YYYY"),
    (COMPLETE | {"completed_at": "2026-02-30 02:03:04"}, "completed_at requires a real"),
    (COMPLETE | {"recorded_at": "2026-11-05 00:00:00"}, "completed_at precedes recorded_at"),
    (COMPLETE | {"prepared_at": "2026-11-04 01:02:04"}, "recorded_at precedes prepared_at"),
    (SUPERSEDED_RECORDED | {"superseded_at": "2026-11-04 01:02:02"},
     "superseded_at precedes recorded_at"),
    (BASE | {"prepared_at": None}, "prepared_at is required"),
    (BASE | {"preparation_ordinal": -1}, "preparation_ordinal"),
])
def test_decide_lifecycle_timestamps_are_real_and_ordered(con, row, match):
    """Catches malformed, impossible, NULL or out-of-order lifecycle timestamps."""
    with pytest.raises(db.DbError, match=match):
        db.put(con, TABLE, row)
    assert not db.rows(con, TABLE) and not con.in_transaction


def test_decide_sibling_image_primary_keys_are_isolated(con):
    db.put(con, TABLE, BASE)
    db.put(con, TABLE, BASE | {"image_id": "sibling"})
    assert {row["image_id"] for row in db.rows(con, TABLE)} == {"sibling", BASE["image_id"]}
