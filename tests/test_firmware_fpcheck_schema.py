"""Stage 4f's durable boundary, exercised through real SQLite writes."""
import json

import pytest

from audit_core import db, workspace


CONTRACTS = [
    ("cba_firmware_fp_runs", (
        "image_id", "manifest_sha256", "surface_snapshot_sha256", "sink_worklist_sha256",
        "dark_worklist_sha256", "candidate_snapshot_sha256", "worklist_path", "worklist_sha256",
        "candidate_count", "batch_count", "status", "prepared_at", "completed_at"),
     ("prepared_at", "completed_at"), ("image_id",)),
    ("cba_firmware_fp_receipts", (
        "image_id", "candidate_snapshot_sha256", "worklist_sha256", "batch_path", "batch_sha256",
        "result_path", "result_sha256", "assigned_count", "verdict_count", "true_positive_count",
        "false_positive_count", "duplicate_count", "pivot_count", "recorded_at"),
     ("recorded_at",), ("image_id", "candidate_snapshot_sha256", "batch_path")),
    ("cba_firmware_fp_verdicts", (
        "image_id", "lane", "candidate_id", "candidate_snapshot_sha256", "batch_path", "verdict",
        "reason", "attacker_advantage", "rules_applied", "mitigation_analysis", "confidence",
        "root_cause_key", "root_cause", "dedup_evidence", "duplicate_lane", "duplicate_candidate_id",
        "refuting_mechanism", "pivot_id", "reviewed_attacker_position", "reviewed_data_flow",
        "reviewed_impact_hypothesis", "component_paths", "surface_ids", "artifact_path",
        "artifact_sha256", "reviewed_at"),
     ("root_cause_key", "root_cause", "dedup_evidence", "duplicate_lane", "duplicate_candidate_id",
      "refuting_mechanism", "pivot_id", "reviewed_attacker_position", "reviewed_data_flow",
      "reviewed_impact_hypothesis", "component_paths", "surface_ids", "reviewed_at"),
     ("image_id", "lane", "candidate_id")),
    ("cba_firmware_pivots", (
        "image_id", "pivot_id", "candidate_snapshot_sha256", "source_lane", "source_candidate_id",
        "component_path", "refuting_mechanism", "enabled_observation", "evidence", "artifact_path",
        "artifact_sha256", "recorded_at"), ("recorded_at",), ("image_id", "pivot_id")),
    ("cba_firmware_findings", (
        "image_id", "finding_id", "candidate_snapshot_sha256", "root_cause_key", "canonical_lane",
        "canonical_candidate_id", "contributors", "lanes", "component_paths", "surface_ids", "title",
        "bug_class", "root_cause", "attacker_position", "data_flow", "impact_hypothesis",
        "evidence_summary", "confidence", "evidence_rung", "artifact_path", "artifact_sha256",
        "derived_at"), ("derived_at",), ("image_id", "finding_id")),
]

RUN = {"image_id": "acme|r1|target", "manifest_sha256": "a" * 64,
       "surface_snapshot_sha256": "b" * 64, "sink_worklist_sha256": "c" * 64,
       "dark_worklist_sha256": "d" * 64, "candidate_snapshot_sha256": "e" * 64,
       "worklist_path": "/run/files/firmware-fpcheck/g/index.json", "worklist_sha256": "f" * 64,
       "candidate_count": 3, "batch_count": 1, "status": "pending"}
RECEIPT = {"image_id": RUN["image_id"], "candidate_snapshot_sha256": "e" * 64,
           "worklist_sha256": "f" * 64, "batch_path": "batch-0001.json",
           "batch_sha256": "a" * 64, "result_path": "/run/artifacts/result.json",
           "result_sha256": "b" * 64, "assigned_count": 3, "verdict_count": 3,
           "true_positive_count": 1, "false_positive_count": 1, "duplicate_count": 1,
           "pivot_count": 1}
COMMON = {"image_id": RUN["image_id"], "lane": "l-sink", "candidate_id": "sink.1",
          "candidate_snapshot_sha256": "e" * 64, "batch_path": "batch-0001.json",
          "reason": "Attacker input reaches an unchecked shell argument",
          "attacker_advantage": "LAN client gains commands as daemon user",
          "rules_applied": '["HE-1","CV-2"]', "mitigation_analysis": "Guard bounds length only",
          "confidence": 8, "artifact_path": "/run/artifacts/result.json", "artifact_sha256": "b" * 64}
TP = COMMON | {"verdict": "TRUE_POSITIVE", "root_cause_key": "shell.argument",
               "root_cause": "Unchecked argument reaches system", "dedup_evidence": "Same cfg.c:76 sink",
               "reviewed_attacker_position": "LAN client", "reviewed_data_flow": "field -> system",
               "reviewed_impact_hypothesis": "Commands as daemon user", "component_paths": '["bin/httpd"]',
               "surface_ids": '["http.login:1"]'}
FP = COMMON | {"verdict": "FALSE_POSITIVE", "refuting_mechanism": "Bounded flush resets buffer",
               "pivot_id": "flush.1"}
DUP = COMMON | {"verdict": "DUPLICATE", "duplicate_lane": "l-dark", "duplicate_candidate_id": "dark.1",
                "dedup_evidence": "Both traces reach the same cfg.c:76 sink"}
PIVOT = {"image_id": RUN["image_id"], "pivot_id": "flush.1", "candidate_snapshot_sha256": "e" * 64,
         "source_lane": "l-sink", "source_candidate_id": "sink.1", "component_path": "bin/httpd",
         "refuting_mechanism": "Bounded flush resets buffer", "enabled_observation": "Flush controls framing",
         "evidence": "parser.c:64 discards pending frame", "artifact_path": "/run/artifacts/result.json",
         "artifact_sha256": "b" * 64}
FINDING = {"image_id": RUN["image_id"], "finding_id": "firmware-01", "candidate_snapshot_sha256": "e" * 64,
           "root_cause_key": "shell.argument", "canonical_lane": "l-sink", "canonical_candidate_id": "sink.1",
           "contributors": '[{"candidate_id":"sink.1","lane":"l-sink"}]', "lanes": '["l-sink"]',
           "component_paths": '["bin/httpd"]', "surface_ids": '["http.login:1"]', "title": "Unchecked shell argument",
           "bug_class": "command injection", "root_cause": "Unchecked argument reaches system",
           "attacker_position": "LAN client", "data_flow": "field -> system", "impact_hypothesis": "Commands as daemon user",
           "evidence_summary": "cfg.c:76 interpolates argument", "confidence": 8, "evidence_rung": "static-reviewed",
           "artifact_path": "/run/artifacts/findings.json", "artifact_sha256": "c" * 64}
ROWS = [("cba_firmware_fp_runs", RUN), ("cba_firmware_fp_receipts", RECEIPT),
        ("cba_firmware_fp_verdicts", TP), ("cba_firmware_pivots", PIVOT), ("cba_firmware_findings", FINDING)]


@pytest.fixture
def con(tmp_path):
    run = workspace.init_run(tmp_path)
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


@pytest.mark.parametrize("table,columns,optional,key", CONTRACTS)
def test_fpcheck_exact_durable_contract(con, table, columns, optional, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    required = tuple(column for column in columns if column not in optional)
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted((row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert (spec.columns, spec.required, spec.primary_key) == (columns, required, key)


def test_fpcheck_inventory_and_schema_reapplication(tmp_path):
    run = workspace.init_run(tmp_path)
    assert len(workspace.apply_schema(run / "audit.db").tables) == 44
    assert len(db.TABLE_SPECS) == 43


@pytest.mark.parametrize("table,row", ROWS + [("cba_firmware_fp_verdicts", FP), ("cba_firmware_fp_verdicts", DUP)])
def test_fpcheck_legal_minimal_rows_roundtrip_and_rollback(con, table, row):
    db.put(con, table, row, commit=False)
    assert con.in_transaction
    stored = dict(db.rows(con, table)[0])
    for column, value in row.items():
        assert stored[column] == value
    con.rollback()
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for (table, columns, optional, _), (_, row) in zip(CONTRACTS, ROWS)
    for column in columns if column not in optional
])
@pytest.mark.parametrize("value", ["omit", "", " \t", None, True])
def test_fpcheck_required_values_are_validated_before_write(con, table, row, column, value):
    invalid = row | {column: value}
    if value == "omit":
        invalid.pop(column)
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, invalid)
    assert db.rows(con, table) == []
    assert not con.in_transaction


INVALID = [
    *[(table, row, column, value) for table, row in ROWS for column in row if column.endswith("sha256")
      for value in ("A" * 64, "a" * 63, "g" * 64, 1)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("_count") or column == "confidence"
      for value in (-1, True, False, "1.5", 1.0, "１", 9223372036854775808)],
    ("cba_firmware_fp_runs", RUN, "status", "ready"),
    ("cba_firmware_fp_verdicts", TP, "verdict", "NEEDS_VERIFICATION"),
    ("cba_firmware_fp_verdicts", TP, "lane", "L-sink"),
    ("cba_firmware_pivots", PIVOT, "source_lane", "other"),
    ("cba_firmware_findings", FINDING, "canonical_lane", "other"),
    ("cba_firmware_findings", FINDING, "evidence_rung", "live-verified"),
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column in ("candidate_id", "source_candidate_id", "canonical_candidate_id", "pivot_id", "finding_id", "root_cause_key")
      for value in ("bad/id", "bad id", "x" * 129)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column in ("batch_path", "component_path")
      for value in ("/absolute", "../escape", "a/../b", "a//b", "./a", "C:/a", "a\\b", "a\x00b")],
    *[(table, row, "confidence", 11) for table, row in ROWS if "confidence" in row],
]


@pytest.mark.parametrize("table,row,column,value", INVALID)
def test_fpcheck_rejects_invalid_scalar_contracts(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for table, row in ROWS for column in row
    if column in ("rules_applied", "component_paths", "surface_ids", "contributors", "lanes")
])
@pytest.mark.parametrize("value", ['[', '{}', 'null', '[NaN]', ' []', '[ ]', '[]\n', '[1]', '[""]'])
def test_fpcheck_json_cells_reject_noncanonical_or_wrong_shape(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for table, row in ROWS for column in row
    if column in ("rules_applied", "component_paths", "surface_ids", "contributors", "lanes")
])
def test_fpcheck_json_cells_reject_duplicates(con, table, row, column):
    parsed = json.loads(row[column])
    duplicate = json.dumps(parsed + [parsed[0]], sort_keys=True, separators=(",", ":"))
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: duplicate})


@pytest.mark.parametrize("row,required", [
    (TP, ("root_cause_key", "root_cause", "dedup_evidence", "reviewed_attacker_position",
          "reviewed_data_flow", "reviewed_impact_hypothesis", "component_paths", "surface_ids")),
    (FP, ("refuting_mechanism", "pivot_id")),
    (DUP, ("duplicate_lane", "duplicate_candidate_id", "dedup_evidence")),
])
def test_fpcheck_verdicts_require_their_specific_evidence(con, row, required):
    for column in required:
        with pytest.raises(db.DbError, match=column):
            db.put(con, "cba_firmware_fp_verdicts", {key: value for key, value in row.items() if key != column})
    assert db.rows(con, "cba_firmware_fp_verdicts") == []


@pytest.mark.parametrize("row,forbidden", [
    (TP, ("duplicate_lane", "duplicate_candidate_id", "refuting_mechanism", "pivot_id")),
    (FP, ("root_cause_key", "root_cause", "dedup_evidence", "duplicate_lane", "duplicate_candidate_id",
          "reviewed_attacker_position", "reviewed_data_flow", "reviewed_impact_hypothesis", "component_paths", "surface_ids")),
    (DUP, ("root_cause_key", "root_cause", "refuting_mechanism", "pivot_id", "reviewed_attacker_position",
           "reviewed_data_flow", "reviewed_impact_hypothesis", "component_paths", "surface_ids")),
])
def test_fpcheck_rejects_populated_foreign_verdict_fields(con, row, forbidden):
    for column in forbidden:
        for value in ("foreign", "", " ", 0, False):
            with pytest.raises(db.DbError, match=column):
                db.put(con, "cba_firmware_fp_verdicts", row | {column: value})
    db.put(con, "cba_firmware_fp_verdicts", row | dict.fromkeys(forbidden))


@pytest.mark.parametrize("table,row,column,value", [
    ("cba_firmware_fp_verdicts", DUP, "duplicate_lane", "other"),
    ("cba_firmware_fp_verdicts", DUP, "duplicate_candidate_id", "../bad"),
    ("cba_firmware_fp_verdicts", FP, "pivot_id", "../bad"),
    ("cba_firmware_fp_verdicts", TP, "component_paths", '["../bad"]'),
    ("cba_firmware_fp_verdicts", TP, "component_paths", '[]'),
    ("cba_firmware_fp_verdicts", TP, "surface_ids", '["bad/id"]'),
    ("cba_firmware_fp_verdicts", TP, "rules_applied", '["bad/id"]'),
    ("cba_firmware_findings", FINDING, "contributors", '[{"candidate_id":"x","lane":"other"}]'),
    ("cba_firmware_findings", FINDING, "contributors", '[{"candidate_id":"x","lane":null}]'),
    ("cba_firmware_findings", FINDING, "contributors", '[{"candidate_id":"bad/id","lane":"l-sink"}]'),
    ("cba_firmware_findings", FINDING, "contributors", '[{"candidate_id":"x","extra":"y","lane":"l-sink"}]'),
    ("cba_firmware_findings", FINDING, "contributors", '[]'),
    ("cba_firmware_findings", FINDING, "lanes", '["other"]'),
    ("cba_firmware_findings", FINDING, "lanes", '[]'),
    ("cba_firmware_findings", FINDING, "component_paths", '[]'),
])
def test_fpcheck_nested_and_conditional_values_are_checked(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})


@pytest.mark.parametrize("value", [0, 10])
def test_fpcheck_confidence_boundaries_and_empty_surface_or_rules(con, value):
    db.put(con, "cba_firmware_fp_verdicts", TP | {"confidence": value, "surface_ids": '[]', "rules_applied": '[]'})
    assert db.rows(con, "cba_firmware_fp_verdicts")[0]["confidence"] == value


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for table, row in ROWS for column in row
    if column in ("artifact_path", "worklist_path", "result_path")
])
@pytest.mark.parametrize("value", ["/run/../escape", "//run/file", "run//file", "C:/file", "file\x00name", "file\ud800name"])
def test_fpcheck_stored_paths_allow_absolute_but_reject_noncanonical_spelling(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for table, row in ROWS for column in row if column.endswith("_count")
])
@pytest.mark.parametrize("value", [0, 9223372036854775807])
def test_fpcheck_count_boundaries_persist_as_sqlite_integers(con, table, row, column, value):
    db.put(con, table, row | {column: value})
    assert tuple(con.execute(f"SELECT {column}, typeof({column}) FROM {table}").fetchone()) == (value, "integer")


def test_fpcheck_schema_reapplication_preserves_all_five_tables(tmp_path):
    run = workspace.init_run(tmp_path)
    con = db.connect(run / "audit.db")
    try:
        for table, row in ROWS:
            db.put(con, table, row)
        original = {table: [tuple(row) for row in con.execute(f"SELECT * FROM {table}")] for table, _ in ROWS}
        for _ in range(2):
            assert workspace.apply_schema(run / "audit.db").migrated == []
        for table, _ in ROWS:
            assert [tuple(row) for row in con.execute(f"SELECT * FROM {table}")] == original[table]
    finally:
        con.close()


def test_fpcheck_verdict_replace_rejects_retained_foreign_variant_fields(con):
    db.put(con, "cba_firmware_fp_verdicts", TP)
    with pytest.raises(db.DbError):
        db.put(con, "cba_firmware_fp_verdicts", FP, replace=True)
    assert db.rows(con, "cba_firmware_fp_verdicts")[0]["verdict"] == "TRUE_POSITIVE"
    assert not con.in_transaction


@pytest.mark.parametrize("column", ["root_cause", "reason", "image_id"])
def test_fpcheck_rejects_unencodable_evidence(con, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_firmware_fp_verdicts", TP | {column: "bad\ud800evidence"})
