"""Stage 4g's local persistence contract, through real SQLite writes."""
import json

import pytest

from audit_core import db, workspace


CONTRACTS = [
    ("cba_firmware_chain_runs", (
        "image_id", "manifest_sha256", "surface_snapshot_sha256", "candidate_snapshot_sha256",
        "fpcheck_artifact_path", "fpcheck_artifact_sha256", "worklist_path", "worklist_sha256",
        "finding_count", "surface_count", "unknown_count", "pivot_count", "status", "graph_path",
        "graph_sha256", "prepared_at", "completed_at"),
     ("graph_path", "graph_sha256", "prepared_at", "completed_at"), ("image_id",)),
    ("cba_firmware_chain_receipts", (
        "image_id", "candidate_snapshot_sha256", "worklist_sha256", "result_path", "result_sha256",
        "disposition_count", "blocker_count", "chain_count", "edge_count", "recorded_at"),
     ("recorded_at",), ("image_id", "candidate_snapshot_sha256")),
    ("cba_firmware_chain_dispositions", (
        "image_id", "finding_id", "candidate_snapshot_sha256", "disposition", "explanation",
        "chain_ids", "existing_unknown_ids", "blocker_ids", "pivot_followup_ids", "artifact_path",
        "artifact_sha256", "recorded_at"), ("recorded_at",), ("image_id", "finding_id")),
    ("cba_firmware_chain_unknowns", (
        "image_id", "blocker_id", "candidate_snapshot_sha256", "question", "settling_observation",
        "method", "axes", "affected_finding_ids", "affected_edges", "status", "artifact_path",
        "artifact_sha256", "recorded_at"), ("recorded_at",), ("image_id", "blocker_id")),
    ("cba_firmware_chains", (
        "image_id", "chain_id", "candidate_snapshot_sha256", "title", "summary", "member_ids",
        "initial_attacker_position", "initial_evidence_refs", "initial_lifecycle", "initial_posture",
        "initial_authentication", "pre_auth", "confidence", "completeness", "existing_unknown_ids",
        "blocker_ids", "evidence_rung", "artifact_path", "artifact_sha256", "derived_at"),
     ("derived_at",), ("image_id", "chain_id")),
    ("cba_firmware_chain_edges", (
        "image_id", "chain_id", "ordinal", "candidate_snapshot_sha256", "producer_finding_id",
        "consumer_finding_id", "capability_kind", "link_key", "produced_capability",
        "required_precondition", "producer_evidence_refs", "consumer_evidence_refs",
        "supplemental_evidence_refs", "required_state", "result_state", "transition_kind",
        "confidence", "existing_unknowns", "blocker_ids", "artifact_path", "artifact_sha256",
        "derived_at"), ("derived_at",), ("image_id", "chain_id", "ordinal")),
]
BASE = {"image_id": "路由器|r1|target", "candidate_snapshot_sha256": "a" * 64}
PROVENANCE = {"artifact_path": "/run/artifacts/chains.json", "artifact_sha256": "b" * 64}
RUN = BASE | {"manifest_sha256": "c" * 64, "surface_snapshot_sha256": "d" * 64,
              "fpcheck_artifact_path": "/run/artifacts/findings.json", "fpcheck_artifact_sha256": "e" * 64,
              "worklist_path": "/run/files/firmware-chain/index.json", "worklist_sha256": "f" * 64,
              "finding_count": 2, "surface_count": 1, "unknown_count": 0, "pivot_count": 0,
              "status": "pending"}
RECEIPT = BASE | {"worklist_sha256": "f" * 64, "result_path": "/run/artifacts/result.json",
                  "result_sha256": "b" * 64, "disposition_count": 2, "blocker_count": 0,
                  "chain_count": 1, "edge_count": 1}
DISPOSITION = BASE | PROVENANCE | {"finding_id": "finding.1", "disposition": "standalone",
    "explanation": "The reviewed primitive needs no second finding", "chain_ids": '[]',
    "existing_unknown_ids": '[]', "blocker_ids": '[]', "pivot_followup_ids": '[]'}
BLOCKER = BASE | PROVENANCE | {"blocker_id": "blocker.1", "question": "Does setup expose this endpoint?",
    "settling_observation": "Capture the setup listener binding", "method": "emulate",
    "axes": '["reachability"]', "affected_finding_ids": '["finding.1"]', "affected_edges": '[]',
    "status": "open"}
CHAIN = BASE | PROVENANCE | {"chain_id": "chain.1", "title": "Session to configuration write",
    "summary": "Stolen setup session authorizes a privileged configuration update",
    "member_ids": '["finding.2","finding.1"]', "initial_attacker_position": "Nearby setup network client",
    "initial_evidence_refs": '["finding:finding.2#attacker_position"]',
    "initial_lifecycle": "factory-fresh", "initial_posture": "SoftAP-setup",
    "initial_authentication": "pre-auth", "pre_auth": "yes", "confidence": 8,
    "completeness": "complete", "existing_unknown_ids": '[]', "blocker_ids": '[]',
    "evidence_rung": "static-chained"}
EDGE = BASE | PROVENANCE | {"chain_id": "chain.1", "ordinal": 0,
    "producer_finding_id": "finding.2", "consumer_finding_id": "finding.1",
    "capability_kind": "session-possession", "link_key": "http:setup-session",
    "produced_capability": "Read the setup session cookie from the status response",
    "required_precondition": "The configuration endpoint accepts that setup session cookie",
    "producer_evidence_refs": '["finding:finding.2#impact_hypothesis"]',
    "consumer_evidence_refs": '["finding:finding.1#attacker_position"]',
    "supplemental_evidence_refs": '[]',
    "required_state": '{"authentication":"any","lifecycle":"any","posture":"any"}',
    "result_state": '{"authentication":"session","lifecycle":"unchanged","posture":"unchanged"}',
    "transition_kind": "direct", "confidence": 8, "existing_unknowns": '[]', "blocker_ids": '[]'}
ROWS = list(zip((item[0] for item in CONTRACTS), (RUN, RECEIPT, DISPOSITION, BLOCKER, CHAIN, EDGE)))
ARRAY_COLUMNS = ("chain_ids", "existing_unknown_ids", "blocker_ids", "pivot_followup_ids", "axes",
                 "affected_finding_ids", "affected_edges", "member_ids", "initial_evidence_refs",
                 "producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs",
                 "existing_unknowns")
ARRAY_CELLS = [(table, row, column) for table, row in ROWS for column in row if column in ARRAY_COLUMNS]


@pytest.fixture
def con(tmp_path):
    run = workspace.init_run(tmp_path)
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


@pytest.mark.parametrize("table,columns,optional,key", CONTRACTS)
def test_chain_exact_durable_contract(con, table, columns, optional, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    required = tuple(column for column in columns if column not in optional)
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted((row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert (spec.columns, spec.required, spec.primary_key) == (columns, required, key)


def test_chain_inventory_and_no_new_column_migrations(tmp_path):
    run = workspace.init_run(tmp_path)
    assert len(workspace.apply_schema(run / "audit.db").tables) == 44
    assert len(db.TABLE_SPECS) == 43
    assert db.MIGRATIONS == (("cba_fp_verdicts", "refuting_mechanism", "TEXT"),
        ("cba_fp_verdicts", "enabled_observation", "TEXT"), ("cba_patterns", "swept_at", "TEXT"),
        ("cba_patterns", "hit_count", "INTEGER"))


@pytest.mark.parametrize("table,row", ROWS)
def test_chain_minimal_rows_roundtrip_and_rollback(con, table, row):
    db.put(con, table, row, commit=False)
    assert con.in_transaction
    stored = dict(db.rows(con, table)[0])
    assert all(stored[column] == value for column, value in row.items())
    con.rollback()
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for (table, columns, optional, _), (_, row) in zip(CONTRACTS, ROWS)
    for column in columns if column not in optional])
@pytest.mark.parametrize("value", ["omit", "", " \t", None, True])
def test_chain_required_values_rejected_before_sql(con, table, row, column, value):
    invalid = row | {column: value}
    if value == "omit":
        invalid.pop(column)
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, invalid)
    assert db.rows(con, table) == []
    assert not con.in_transaction


INVALID_SCALARS = [
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("sha256") for value in ("A" * 64, "a" * 63, "g" * 64, 1)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("_count") or column in ("confidence", "ordinal")
      for value in (-1, True, False, "1.5", 1.0, "１", 9223372036854775808)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column in ("finding_id", "chain_id", "blocker_id", "producer_finding_id", "consumer_finding_id")
      for value in ("bad/id", "bad id", "x" * 129)],
    *[(table, row, column, value) for table, row in ROWS for column in row
      if column.endswith("_path") for value in ("/run/../escape", "//run/file", "run//file", "C:/file",
                                                "file\x00name", "file\ud800name", "a\\b")],
    *[(table, row, "confidence", 11) for table, row in ROWS if "confidence" in row],
    (ROWS[0][0], RUN, "status", "ready"),
    (ROWS[2][0], DISPOSITION, "disposition", "partial"),
    (ROWS[3][0], BLOCKER, "status", "resolved"),
    (ROWS[3][0], BLOCKER, "method", "guess"),
    (ROWS[4][0], CHAIN, "evidence_rung", "live-verified"),
    (ROWS[4][0], CHAIN, "pre_auth", "maybe"),
    (ROWS[4][0], CHAIN, "completeness", "partial"),
    *[(ROWS[4][0], CHAIN, column, "unknown") for column in
      ("initial_lifecycle", "initial_posture", "initial_authentication")],
    (ROWS[4][0], CHAIN, "initial_posture", "softap-setup"),
    (ROWS[4][0], CHAIN, "initial_authentication", "physical-uart"),
    (ROWS[5][0], EDGE, "capability_kind", "access"),
    (ROWS[5][0], EDGE, "transition_kind", "magic"),
]


@pytest.mark.parametrize("table,row,column,value", INVALID_SCALARS)
def test_chain_invalid_scalars_fail_without_writes(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,column", ARRAY_CELLS)
@pytest.mark.parametrize("value", ['[', '{}', 'null', '[NaN]', ' []', '[ ]', '[]\n', '[1]', '[""]'])
def test_chain_rejects_malformed_noncanonical_arrays(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,row,column,value", [
    (ROWS[2][0], DISPOSITION, "existing_unknown_ids", '["z","a"]'),
    (ROWS[2][0], DISPOSITION, "existing_unknown_ids", '["a","a"]'),
    (ROWS[2][0], DISPOSITION, "blocker_ids", '["bad/id"]'),
    (ROWS[3][0], BLOCKER, "axes", '[]'),
    (ROWS[3][0], BLOCKER, "axes", '["auth"]'),
    (ROWS[3][0], BLOCKER, "axes", '["reachability","authentication"]'),
    (ROWS[3][0], BLOCKER, "axes", '["reachability","reachability"]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_key":"x","ordinal":0}]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_id":"x","ordinal":true}]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_id":"x","ordinal":-1}]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_id":"bad/id","ordinal":0}]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_id":"x","extra":1,"ordinal":0}]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_id":"x","chain_id":"y","ordinal":0}]'),
    (ROWS[4][0], CHAIN, "member_ids", '[]'),
    (ROWS[4][0], CHAIN, "member_ids", '["finding.1"]'),
    (ROWS[4][0], CHAIN, "member_ids", '["finding.1","finding.1"]'),
    (ROWS[4][0], CHAIN, "initial_evidence_refs", '[]'),
    (ROWS[4][0], CHAIN, "initial_evidence_refs", '["pivot:pivot.1#evidence"]'),
    (ROWS[5][0], EDGE, "producer_evidence_refs", '[]'),
    (ROWS[5][0], EDGE, "consumer_evidence_refs", '["finding:finding.1#title"]'),
    (ROWS[5][0], EDGE, "supplemental_evidence_refs", '["finding:finding.1#root_cause"]'),
    (ROWS[5][0], EDGE, "existing_unknowns", '[{"axes":[],"unknown_id":"u"}]'),
    (ROWS[5][0], EDGE, "existing_unknowns", '[{"axes":["auth"],"unknown_id":"u"}]'),
    (ROWS[5][0], EDGE, "existing_unknowns", '[{"axes":["authentication"],"id":"u"}]'),
    (ROWS[5][0], EDGE, "existing_unknowns", '[{"axes":["authentication"],"unknown_id":"bad/id"}]'),
    (ROWS[5][0], EDGE, "existing_unknowns", '[{"axes":["authentication"],"unknown_id":"u"},{"axes":["posture"],"unknown_id":"u"}]'),
    (ROWS[5][0], EDGE, "required_state", '{}'),
    (ROWS[5][0], EDGE, "required_state", '{"authentication":"unknown","lifecycle":"any","posture":"any"}'),
    (ROWS[5][0], EDGE, "required_state", '{"authentication":"any","lifecycle":"unchanged","posture":"any"}'),
    (ROWS[5][0], EDGE, "result_state", '{"authentication":"any","lifecycle":"unchanged","posture":"unchanged"}'),
    (ROWS[5][0], EDGE, "result_state", '{"authentication":"session", "lifecycle":"unchanged","posture":"unchanged"}'),
    (ROWS[5][0], EDGE, "result_state", '{"authentication":"session","lifecycle":"unchanged","posture":"unchanged","x":1}'),
])
def test_chain_nested_shapes_and_variants_are_checked(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})


@pytest.mark.parametrize("changes,column", [
    ({"graph_path": "/run/artifacts/chains.json"}, "graph_path"),
    ({"graph_sha256": "b" * 64}, "graph_sha256"),
    ({"completed_at": "2026-10-25 01:02:03"}, "completed_at"),
    ({"status": "complete"}, "graph_path"),
    ({"status": "complete", "graph_path": "/run/artifacts/chains.json"}, "graph_sha256"),
    ({"status": "complete", "graph_path": "/run/artifacts/chains.json", "graph_sha256": "b" * 64}, "completed_at"),
    ({"prepared_at": ""}, "prepared_at"),
    ({"prepared_at": True}, "prepared_at"),
])
def test_chain_run_status_owns_completion_provenance(con, changes, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, ROWS[0][0], RUN | changes)
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,changes,column", [
    (ROWS[2][0], DISPOSITION, {"disposition": "chained"}, "chain_ids"),
    (ROWS[2][0], DISPOSITION, {"chain_ids": '["chain.1"]'}, "chain_ids"),
    (ROWS[2][0], DISPOSITION, {"disposition": "blocked"}, "blocker"),
    (ROWS[2][0], DISPOSITION, {"pivot_followup_ids": '["pivot.1"]'}, "pivot_followup_ids"),
    (ROWS[3][0], BLOCKER, {"affected_finding_ids": '[]'}, "affected"),
    (ROWS[5][0], EDGE, {"capability_kind": "other-specific", "link_key": "access"}, "link_key"),
])
def test_chain_local_variants_require_their_fields(con, table, row, changes, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | changes)


@pytest.mark.parametrize("table,row", [
    (ROWS[0][0], RUN | {"status": "complete", "graph_path": "/run/artifacts/chains.json",
                      "graph_sha256": "b" * 64, "completed_at": "2026-10-25 01:02:03"}),
    (ROWS[2][0], DISPOSITION | {"disposition": "chained", "chain_ids": '["chain.1"]'}),
    (ROWS[2][0], DISPOSITION | {"disposition": "chained", "chain_ids": '["chain.1"]',
                               "existing_unknown_ids": '["unknown.1"]', "blocker_ids": '["blocker.1"]'}),
    (ROWS[2][0], DISPOSITION | {"disposition": "blocked", "blocker_ids": '["blocker.1"]'}),
    (ROWS[2][0], DISPOSITION | {"disposition": "unchainable", "pivot_followup_ids": '["pivot.1"]'}),
    (ROWS[3][0], BLOCKER | {"affected_finding_ids": '[]', "affected_edges": '[{"chain_id":"chain.1","ordinal":0}]'}),
    (ROWS[5][0], EDGE | {"existing_unknowns": '[{"axes":["authentication","reachability"],"unknown_id":"unknown.1"}]',
                       "supplemental_evidence_refs": '["surface:surface.1#reach_evidence","unknown:unknown.1#evidence"]'}),
    (ROWS[5][0], EDGE | {"capability_kind": "other-specific", "link_key": "boot:startup-hook"}),
])
def test_chain_legal_variants_do_not_require_referenced_rows(con, table, row):
    db.put(con, table, row)
    assert len(db.rows(con, table)) == 1


def test_other_specific_row_accepts_concrete_firmware_path_with_spaces(con):
    row = EDGE | {'capability_kind': 'other-specific',
                  'link_key': 'boot-resource:/etc/My Config/startup'}
    db.put(con, 'cba_firmware_chain_edges', row)
    assert db.rows(con, 'cba_firmware_chain_edges')[0]['link_key'] == row['link_key']


@pytest.mark.parametrize('value', [
    1,
    ' boot-resource:/etc/startup',
    'boot-resource:' + '界' * 1365,
    'boot-resource:\ud800',
    'boot-resource:/etc/start\x00up',
])
def test_shared_other_specific_predicate_rejects_noncanonical_hostile_values(value):
    assert not db.firmware_chain_other_specific_link_key(value)


@pytest.mark.parametrize('disposition', ['standalone', 'unchainable'])
@pytest.mark.parametrize('field', ['existing_unknown_ids', 'blocker_ids'])
def test_nonblocked_nonmaterialized_rows_reject_unresolved_references(con, disposition, field):
    row = DISPOSITION | {'disposition': disposition, field: '["unresolved.1"]'}
    with pytest.raises(db.DbError, match='[Uu]nresolved|blocked'):
        db.put(con, 'cba_firmware_chain_dispositions', row)


@pytest.mark.parametrize("table,row,column", [(table, row, column) for table, row in ROWS for column in row
    if column.endswith("_count") or column == "ordinal"])
@pytest.mark.parametrize("value", [0, 9223372036854775807])
def test_chain_integer_boundaries_persist_as_integers(con, table, row, column, value):
    db.put(con, table, row | {column: value})
    assert tuple(con.execute(f"SELECT {column}, typeof({column}) FROM {table}").fetchone()) == (value, "integer")


def test_chain_schema_reapplication_preserves_all_six_tables(tmp_path):
    run = workspace.init_run(tmp_path)
    con = db.connect(run / "audit.db")
    try:
        for table, row in ROWS:
            db.put(con, table, row)
        original = {table: list(map(tuple, con.execute(f"SELECT * FROM {table}"))) for table, _ in ROWS}
        for _ in range(2):
            assert workspace.apply_schema(run / "audit.db").migrated == []
        for table, _ in ROWS:
            assert list(map(tuple, con.execute(f"SELECT * FROM {table}"))) == original[table]
    finally:
        con.close()


@pytest.mark.parametrize("row", [
    CHAIN | {"completeness": "blocked"},
    CHAIN | {"blocker_ids": '["blocker.1"]'},
    CHAIN | {"existing_unknown_ids": '["unknown.1"]'},
])
def test_chain_completeness_variant_agrees_with_local_blocker_lists(con, row):
    with pytest.raises(db.DbError, match="completeness"):
        db.put(con, "cba_firmware_chains", row)
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,column,value", [
    (ROWS[4][0], CHAIN, "initial_lifecycle", value) for value in
    ("factory-fresh", "provisioned", "bound-to-owner", "cloud-registered", "post-reset")
] + [
    (ROWS[4][0], CHAIN, "initial_posture", value) for value in
    ("SoftAP-setup", "STA-LAN", "WAN-exposed", "BLE", "cloud-tunnel-only")
] + [
    (ROWS[4][0], CHAIN, "initial_authentication", value) for value in
    ("pre-auth", "session", "admin", "local-shell", "physical-UART")
] + [
    (ROWS[4][0], CHAIN, "pre_auth", value) for value in ("yes", "no", "unknown")
] + [
    (ROWS[5][0], EDGE, "capability_kind", value) for value in
    ("credential-possession", "session-possession", "file-read", "file-write", "config-read",
     "config-write", "command-execution", "code-execution", "ipc-access", "network-reachability",
     "firmware-update-control", "persistent-execution", "reboot-control", "physical-access")
] + [
    (ROWS[5][0], EDGE, "transition_kind", value) for value in
    ("direct", "reboot", "service-restart", "factory-reset", "reprovision")
] + [(ROWS[3][0], BLOCKER, "method", value) for value in ("static", "emulate", "hardware")])
def test_chain_frozen_vocabulary_accepts_every_legal_value(con, table, row, column, value):
    db.put(con, table, row | {column: value})
    assert db.rows(con, table)[0][column] == value


@pytest.mark.parametrize("table,row,column,value", [
    (ROWS[3][0], BLOCKER, "axes", '["authentication","lifecycle","posture","reachability"]'),
    (ROWS[3][0], BLOCKER, "affected_edges", '[{"chain_id":"chain.1","ordinal":2},{"chain_id":"chain.1","ordinal":10}]'),
    (ROWS[4][0], CHAIN | {"completeness": "blocked"}, "blocker_ids", '["blocker.1"]'),
    (ROWS[4][0], CHAIN | {"completeness": "blocked"}, "existing_unknown_ids", '["unknown.1"]'),
    (ROWS[4][0], CHAIN, "initial_evidence_refs", '["surface:surface.1#reach_evidence"]'),
    *[(table, row, "confidence", value) for table, row in ROWS if "confidence" in row for value in (0, 10)],
])
def test_chain_legal_boundary_and_nested_values(con, table, row, column, value):
    db.put(con, table, row | {column: value})
    assert db.rows(con, table)[0][column] == value


@pytest.mark.parametrize("table,row,column", ARRAY_CELLS)
def test_chain_every_array_rejects_repeated_entries(con, table, row, column):
    values = json.loads(row[column])
    if not values:
        values = ([{"chain_id": "chain.1", "ordinal": 0}] if column == "affected_edges" else
                  [{"axes": ["authentication"], "unknown_id": "unknown.1"}] if column == "existing_unknowns" else
                  ["surface:surface.1#reach_evidence"] if column == "supplemental_evidence_refs" else ["id.1"])
    raw = json.dumps(values + [values[0]], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: raw})


@pytest.mark.parametrize("table,row", ROWS)
def test_chain_unknown_columns_rejected_before_sql(con, table, row):
    with pytest.raises(db.DbError, match="extra"):
        db.put(con, table, row | {"extra": "unrecognized"})
    assert not con.in_transaction


def test_chain_complete_run_cannot_borrow_retained_completion_provenance(con):
    complete = RUN | {"status": "complete", "graph_path": "/run/artifacts/chains.json",
                      "graph_sha256": "b" * 64, "completed_at": "2026-10-25 01:02:03"}
    db.put(con, ROWS[0][0], complete)
    with pytest.raises(db.DbError, match="graph_path"):
        db.put(con, ROWS[0][0], RUN | {"status": "complete"}, replace=True)
    assert db.rows(con, ROWS[0][0])[0]["graph_path"] == complete["graph_path"]
    with pytest.raises(db.DbError):
        db.put(con, ROWS[0][0], RUN, replace=True)
    db.put(con, ROWS[0][0], RUN | {"graph_path": None, "graph_sha256": None, "completed_at": None}, replace=True)
    assert db.rows(con, ROWS[0][0])[0]["status"] == "pending"
