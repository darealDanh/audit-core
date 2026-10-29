"""Stage 4h local row contracts, exercised through SQLite writes."""
import json

import pytest

from audit_core import db, workspace


CONTRACTS = [
    ("cba_firmware_dive_runs", (
        "image_id", "dive_generation", "manifest_sha256", "surface_snapshot_sha256",
        "candidate_snapshot_sha256", "chain_graph_path", "chain_graph_sha256",
        "analyst_manifest_path", "analyst_manifest_sha256", "journal_input_path",
        "journal_input_sha256", "question_index_path", "question_index_sha256", "question_count",
        "chain_blocker_count", "surface_unknown_count", "analyst_question_count", "retry_count",
        "conflict_count", "status", "journal_path", "journal_sha256", "supported_count",
        "refuted_count", "inconclusive_count", "prepared_at", "completed_at"),
     ("journal_path", "journal_sha256", "prepared_at", "completed_at"), ("image_id", "dive_generation")),
    ("cba_firmware_dive_questions", (
        "image_id", "dive_generation", "question_id", "attempt_ordinal", "origin", "method",
        "question", "settling_observation", "subject_refs", "resolution_contract", "axes",
        "prior_observation_id", "supersedes_observation_ids", "packet_path", "packet_sha256",
        "ordinal", "recorded_at"), ("prior_observation_id", "recorded_at"),
     ("image_id", "dive_generation", "question_id")),
    ("cba_firmware_dive_receipts", (
        "image_id", "dive_generation", "receipt_key", "receipt_kind", "question_id", "attempt_ordinal",
        "packet_sha256", "result_path", "result_sha256", "outcome", "dependency_count", "evidence_count",
        "successor_count", "recorded_at"), ("question_id", "attempt_ordinal", "packet_sha256", "recorded_at"),
     ("image_id", "dive_generation", "receipt_key")),
    ("cba_firmware_dive_observations", (
        "image_id", "dive_generation", "question_id", "attempt_ordinal", "observation_id", "outcome",
        "conclusion", "limitations", "resolution_effect", "evidence_rung", "dependency_refs", "evidence_refs",
        "successor_questions", "artifact_path", "artifact_sha256", "recorded_at"),
     ("resolution_effect", "evidence_rung", "recorded_at"), ("image_id", "dive_generation", "question_id")),
    ("cba_firmware_dive_dependencies", (
        "image_id", "dive_generation", "question_id", "ordinal", "observation_id", "kind", "logical_id",
        "relative_path", "sha256", "byte_count", "source_provenance", "recorded_at"),
     ("recorded_at",), ("image_id", "dive_generation", "question_id", "ordinal")),
    ("cba_firmware_dive_acquisitions", (
        "image_id", "dive_generation", "question_id", "acquisition_id", "kind", "contract_sha256",
        "spec_path", "spec_sha256", "manifest_path", "manifest_sha256", "evidence_paths", "details",
        "recorded_at"), ("recorded_at",), ("image_id", "dive_generation", "question_id", "acquisition_id")),
]
BASE = {"image_id": "路由器|r1|target", "dive_generation": "a" * 64}
QUESTION_BASE = BASE | {"question_id": "b" * 64}
RUN = BASE | {"manifest_sha256": "c" * 64, "surface_snapshot_sha256": "d" * 64,
    "candidate_snapshot_sha256": "e" * 64, "chain_graph_path": "artifacts/chains.json",
    "chain_graph_sha256": "f" * 64, "analyst_manifest_path": "files/analyst.json",
    "analyst_manifest_sha256": "1" * 64, "journal_input_path": "files/journal-input.json",
    "journal_input_sha256": "2" * 64, "question_index_path": "files/index.json",
    "question_index_sha256": "3" * 64, "question_count": 1, "chain_blocker_count": 1,
    "surface_unknown_count": 0, "analyst_question_count": 0, "retry_count": 0, "conflict_count": 0,
    "status": "pending", "supported_count": 0, "refuted_count": 0, "inconclusive_count": 0}
QUESTION = QUESTION_BASE | {"attempt_ordinal": 1, "origin": "chain-blocker", "method": "static",
    "question": "Is the listener reachable?", "settling_observation": "Resolve the listener binding",
    "subject_refs": '["finding:finding.1"]',
    "resolution_contract": '{"mode":"boolean-claim","predicate":"reachability"}',
    "axes": '["reachability"]', "supersedes_observation_ids": '[]',
    "packet_path": "files/question.json", "packet_sha256": "4" * 64, "ordinal": 0}
RECEIPT = QUESTION_BASE | {"receipt_key": "firmware-dive-receipt-" + "5" * 64,
    "receipt_kind": "question", "attempt_ordinal": 1, "packet_sha256": "4" * 64,
    "result_path": "artifacts/result.json", "result_sha256": "6" * 64, "outcome": "supported",
    "dependency_count": 1, "evidence_count": 1, "successor_count": 0}
OBSERVATION = QUESTION_BASE | {"attempt_ordinal": 1, "observation_id": "7" * 64,
    "outcome": "supported", "conclusion": "The listener binds on all interfaces",
    "limitations": "Only the captured binary was read", "resolution_effect": '{"value":true}',
    "evidence_rung": "static-resolved", "dependency_refs": '["dependency.1"]',
    "evidence_refs": '["evidence.1"]', "successor_questions": '[]',
    "artifact_path": "artifacts/result.json", "artifact_sha256": "6" * 64}
DEPENDENCY = QUESTION_BASE | {"ordinal": 0, "observation_id": "7" * 64,
    "kind": "chain-artifact", "logical_id": "chain.1", "relative_path": "artifacts/chains.json",
    "sha256": "f" * 64, "byte_count": 12, "source_provenance": '{}'}
ACQUISITION = QUESTION_BASE | {"acquisition_id": "8" * 64, "kind": "probe", "contract_sha256": "9" * 64,
    "spec_path": "artifacts/probe/spec.json", "spec_sha256": "1" * 64,
    "manifest_path": "artifacts/probe/manifest.json", "manifest_sha256": "2" * 64,
    "evidence_paths": '["artifacts/probe/stdout.bin"]', "details": '{}'}
ROWS = list(zip((item[0] for item in CONTRACTS), (RUN, QUESTION, RECEIPT, OBSERVATION, DEPENDENCY, ACQUISITION)))


@pytest.fixture
def con(tmp_path):
    run = workspace.init_run(tmp_path)
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


@pytest.mark.parametrize("table,columns,optional,key", CONTRACTS)
def test_dive_exact_sql_and_tablespec_contract(con, table, columns, optional, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    required = tuple(column for column in columns if column not in optional)
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted((row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert (spec.columns, spec.required, spec.primary_key) == (columns, required, key)


def test_dive_adds_six_tables_without_column_migrations(tmp_path):
    run = workspace.init_run(tmp_path)
    assert len(workspace.apply_schema(run / "audit.db").tables) == 44
    assert len(db.TABLE_SPECS) == 43
    assert db.MIGRATIONS == (("cba_fp_verdicts", "refuting_mechanism", "TEXT"),
        ("cba_fp_verdicts", "enabled_observation", "TEXT"), ("cba_patterns", "swept_at", "TEXT"),
        ("cba_patterns", "hit_count", "INTEGER"))


@pytest.mark.parametrize("table,row", ROWS)
def test_dive_rows_roundtrip_timestamp_defaults_and_rollback(con, table, row):
    db.put(con, table, row, commit=False)
    stored = dict(db.rows(con, table)[0])
    assert all(stored[column] == value for column, value in row.items())
    timestamp = "prepared_at" if table.endswith("_runs") else "recorded_at"
    assert isinstance(stored[timestamp], str) and len(stored[timestamp]) == 19
    con.rollback()
    assert db.rows(con, table) == []
    stamp = "2026-01-02 03:04:05"
    db.put(con, table, row | {timestamp: stamp})
    assert db.rows(con, table)[0][timestamp] == stamp


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for (table, columns, optional, _), (_, row) in zip(CONTRACTS, ROWS)
    for column in columns if column not in optional])
@pytest.mark.parametrize("value", ["omit", "", " \t", None, True])
def test_dive_required_values_fail_before_sql(con, table, row, column, value):
    invalid = row | {column: value}
    if value == "omit":
        invalid.pop(column)
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, invalid)
    assert not con.in_transaction


INVALID_SCALARS = [
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("sha256") or column in ("dive_generation", "question_id", "observation_id", "acquisition_id")
      for value in ("A" * 64, "a" * 63, "g" * 64, "bad/id", 1)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("_count") or column in ("ordinal", "attempt_ordinal")
      for value in (-1, True, False, "1.5", 1.0, "１", 9223372036854775808)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("_path") for value in ("../escape", "a//b", "a/./b", "C:/file", "a\\b", "a\x00b", "a\ud800b")],
    (ROWS[0][0], RUN, "status", "ready"), (ROWS[1][0], QUESTION, "origin", "manual"),
    (ROWS[1][0], QUESTION, "method", "guess"), (ROWS[1][0], QUESTION, "attempt_ordinal", 0),
    (ROWS[2][0], RECEIPT, "receipt_kind", "answer"), (ROWS[2][0], RECEIPT, "receipt_key", "receipt.1"),
    (ROWS[2][0], RECEIPT, "outcome", "unknown"), (ROWS[3][0], OBSERVATION, "outcome", "empty"),
    (ROWS[3][0], OBSERVATION, "evidence_rung", "static-reviewed"),
    (ROWS[4][0], DEPENDENCY, "kind", "file"), (ROWS[5][0], ACQUISITION, "kind", "hardware"),
]


@pytest.mark.parametrize("table,row,column,value", INVALID_SCALARS)
def test_dive_invalid_scalars_fail_without_writes(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert not con.in_transaction


JSON_COLUMNS = ("subject_refs", "resolution_contract", "axes", "supersedes_observation_ids", "resolution_effect",
                "dependency_refs", "evidence_refs", "successor_questions", "source_provenance", "evidence_paths", "details")
JSON_CELLS = [(table, row, column) for table, row in ROWS for column in row if column in JSON_COLUMNS]


@pytest.mark.parametrize("table,row,column", JSON_CELLS)
@pytest.mark.parametrize("value", ['[1, 2]', '{"a":1,"a":1}', '{"a":NaN}', 'null', '"text"', '[]\n'])
def test_dive_json_cells_require_canonical_container(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert not con.in_transaction


@pytest.mark.parametrize("complete", [False, True])
def test_dive_pending_complete_provenance(con, complete):
    row = RUN | ({"status": "complete", "journal_path": "artifacts/journal.json",
                  "journal_sha256": "8" * 64, "completed_at": "2026-01-02 03:04:05",
                  "supported_count": 1} if complete else {})
    db.put(con, ROWS[0][0], row)
    assert db.rows(con, ROWS[0][0])[0]["status"] == row["status"]


@pytest.mark.parametrize("column,value", [("journal_path", "artifacts/journal.json"),
    ("journal_sha256", "a" * 64), ("completed_at", "2026-01-02 03:04:05"),
    ("supported_count", 1), ("refuted_count", 1), ("inconclusive_count", 1)])
def test_dive_pending_cannot_claim_completion(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[0][0], RUN | {column: value})


@pytest.mark.parametrize("column", ["journal_path", "journal_sha256", "completed_at"])
def test_dive_complete_requires_own_provenance(con, column):
    row = RUN | {"status": "complete", "journal_path": "artifacts/journal.json",
                 "journal_sha256": "a" * 64, "completed_at": "2026-01-02 03:04:05"}
    db.put(con, ROWS[0][0], row)
    row.pop(column)
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[0][0], row, replace=True)


EMPTY = {key: value for key, value in RECEIPT.items()
         if key not in ("question_id", "attempt_ordinal", "packet_sha256")}
EMPTY.update(receipt_kind="empty", outcome="empty", dependency_count=0, evidence_count=0, successor_count=0)


def test_dive_empty_receipt_is_run_level(con):
    db.put(con, ROWS[2][0], EMPTY)
    stored = db.rows(con, ROWS[2][0])[0]
    assert all(stored[column] is None for column in ("question_id", "attempt_ordinal", "packet_sha256"))


@pytest.mark.parametrize("column,value", [("question_id", "b" * 64), ("attempt_ordinal", 1),
    ("packet_sha256", "a" * 64), ("outcome", "supported"), ("dependency_count", 1),
    ("evidence_count", 1), ("successor_count", 1)])
def test_dive_empty_receipt_rejects_question_fields(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[2][0], EMPTY | {column: value})


@pytest.mark.parametrize("column", ["question_id", "attempt_ordinal", "packet_sha256"])
def test_dive_question_receipt_requires_assignment(con, column):
    row = RECEIPT.copy()
    row.pop(column)
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[2][0], row)


@pytest.mark.parametrize("outcome", ["supported", "refuted", "inconclusive"])
def test_dive_observation_outcome_variants(con, outcome):
    row = OBSERVATION | {"outcome": outcome}
    if outcome == "inconclusive":
        row.update(resolution_effect=None, evidence_rung=None, dependency_refs="[]", evidence_refs="[]")
    db.put(con, ROWS[3][0], row)
    assert db.rows(con, ROWS[3][0])[0]["outcome"] == outcome


@pytest.mark.parametrize("column,value", [("resolution_effect", None), ("evidence_rung", None),
                                        ("dependency_refs", "[]"), ("evidence_refs", "[]")])
def test_dive_conclusive_requires_local_evidence_provenance(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[3][0], OBSERVATION | {column: value})


@pytest.mark.parametrize("column,value", [("resolution_effect", '{"value":true}'),
                                        ("evidence_rung", "static-resolved")])
def test_dive_inconclusive_cannot_claim_resolution_rung(con, column, value):
    row = OBSERVATION | {"outcome": "inconclusive", "resolution_effect": None, "evidence_rung": None}
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[3][0], row | {column: value})


@pytest.mark.parametrize("column,value", [("mode", "boolean-claim"), ("mode", "value-discovery"),
    *[("predicate", predicate) for predicate in ("state-value", "reachability", "edge-validity",
                                                  "capability-present", "transition-observed")]])
def test_dive_contract_known_discriminants(con, column, value):
    contract = json.loads(QUESTION["resolution_contract"])
    contract[column] = value
    raw = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    db.put(con, ROWS[1][0], QUESTION | {"resolution_contract": raw})


@pytest.mark.parametrize("column", ["mode", "predicate"])
def test_dive_contract_rejects_unknown_discriminants(con, column):
    contract = json.loads(QUESTION["resolution_contract"])
    contract[column] = "guess"
    with pytest.raises(db.DbError, match="resolution_contract"):
        db.put(con, ROWS[1][0], QUESTION | {"resolution_contract": json.dumps(contract, sort_keys=True, separators=(",", ":"))})


@pytest.mark.parametrize("kind", ["probe", "capture"])
def test_dive_acquisition_detail_variants(con, kind):
    db.put(con, ROWS[5][0], ACQUISITION | {"kind": kind, "details": '{"kind":"' + kind + '"}'})


@pytest.mark.parametrize("kind,details", [("probe", '{"kind":"capture"}'), ("capture", '{"kind":"probe"}')])
def test_dive_acquisition_detail_discriminant_must_agree(con, kind, details):
    with pytest.raises(db.DbError, match="details"):
        db.put(con, ROWS[5][0], ACQUISITION | {"kind": kind, "details": details})


@pytest.mark.parametrize("table,row,column", [cell for cell in JSON_CELLS if cell[2] in (
    "subject_refs", "axes", "supersedes_observation_ids", "dependency_refs", "evidence_refs", "evidence_paths")])
def test_dive_unordered_arrays_reject_duplicates(con, table, row, column):
    values = json.loads(row[column]) or ["a" * 64]
    raw = json.dumps(values + values, sort_keys=True, separators=(",", ":"))
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: raw})


@pytest.mark.parametrize("value", [-1, True, False, 1.0, "1.5", "１", 9223372036854775808])
def test_dive_dependency_byte_count_requires_nonnegative_integer(con, value):
    with pytest.raises(db.DbError, match="byte_count"):
        db.put(con, ROWS[4][0], DEPENDENCY | {"byte_count": value})


@pytest.mark.parametrize("value", [0, 9223372036854775807])
def test_dive_dependency_byte_count_integer_boundaries(con, value):
    db.put(con, ROWS[4][0], DEPENDENCY | {"byte_count": value})
    assert db.rows(con, ROWS[4][0])[0]["byte_count"] == value


@pytest.mark.parametrize("value", ['[1]', '["file:foo"]', '["finding:bad/id"]',
                                 '["edge:short"]', '[]'])
def test_dive_subject_reference_local_shape(con, value):
    with pytest.raises(db.DbError, match="subject_refs"):
        db.put(con, ROWS[1][0], QUESTION | {"subject_refs": value})


@pytest.mark.parametrize("kind", ["edge", "chain", "surface-unknown", "chain-blocker", "finding"])
def test_dive_subject_reference_variants(con, kind):
    identity = "a" * 64 if kind in ("edge", "chain") else "id.1"
    db.put(con, ROWS[1][0], QUESTION | {"subject_refs": '["' + kind + ':' + identity + '"]'})


@pytest.mark.parametrize("column,value", [("prior_observation_id", "bad"),
    ("supersedes_observation_ids", '["bad"]'), ("axes", '["cpu"]'),
    ("axes", '[]'), ("subject_refs", '["finding:z","finding:a"]')])
def test_dive_question_reference_arrays_reject_invalid_entries(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[1][0], QUESTION | {column: value})


@pytest.mark.parametrize("origin", ["chain-blocker", "surface-unknown", "analyst", "conflict"])
@pytest.mark.parametrize("method", ["static", "emulate", "hardware"])
def test_dive_question_origin_and_method_vocabulary(con, origin, method):
    db.put(con, ROWS[1][0], QUESTION | {"origin": origin, "method": method})


@pytest.mark.parametrize("rung", ["static-resolved", "emulated-observed", "hardware-observed"])
def test_dive_conclusive_evidence_rungs(con, rung):
    db.put(con, ROWS[3][0], OBSERVATION | {"evidence_rung": rung})


@pytest.mark.parametrize("kind", ["finding-artifact", "surface-artifact", "chain-artifact",
                                  "extract-record", "probe-manifest", "hardware-capture"])
def test_dive_dependency_kind_variants(con, kind):
    db.put(con, ROWS[4][0], DEPENDENCY | {"kind": kind})


def test_dive_dependency_relative_path_cannot_be_absolute(con):
    with pytest.raises(db.DbError, match="relative_path"):
        db.put(con, ROWS[4][0], DEPENDENCY | {"relative_path": "/run/artifacts/graph.json"})
