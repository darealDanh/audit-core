import sqlite3
import sys

import pytest

from audit_core import db, workspace


HUNT_CONTRACTS = [
    ("cba_hunt_runs",
     ("image_id", "lane", "manifest_sha256", "surface_snapshot_sha256",
      "worklist_path", "worklist_sha256", "unit_count", "batch_count", "status",
      "prepared_at", "completed_at"),
     ("image_id", "lane", "manifest_sha256", "surface_snapshot_sha256",
      "worklist_path", "worklist_sha256", "unit_count", "batch_count", "status"),
     ("image_id", "lane")),
    ("cba_hunt_receipts",
     ("image_id", "lane", "worklist_sha256", "batch_path", "batch_sha256",
      "result_path", "result_sha256", "unit_count", "candidate_count", "recorded_at"),
     ("image_id", "lane", "worklist_sha256", "batch_path", "batch_sha256",
      "result_path", "result_sha256", "unit_count", "candidate_count"),
     ("image_id", "lane", "worklist_sha256", "batch_path")),
    ("cba_hunt_candidates",
     ("image_id", "lane", "candidate_id", "component_path", "title", "bug_class",
      "surface_ids", "surface_context", "attacker_position", "input_evidence",
      "data_flow", "dangerous_operation", "operation_evidence", "mitigations_checked",
      "lifecycle_required", "posture_required", "auth_required", "reachability",
      "state_evidence", "confidence", "impact_hypothesis", "blockers", "artifact_path",
      "artifact_sha256", "recorded_at"),
     ("image_id", "lane", "candidate_id", "component_path", "title", "bug_class",
      "surface_ids", "surface_context", "attacker_position", "input_evidence",
      "data_flow", "dangerous_operation", "operation_evidence", "mitigations_checked",
      "lifecycle_required", "posture_required", "auth_required", "reachability",
      "state_evidence", "confidence", "impact_hypothesis", "blockers", "artifact_path",
      "artifact_sha256"),
     ("image_id", "lane", "candidate_id")),
]

HUNT_RUN = {
    "image_id": "acme|r1|target", "lane": "l-sink", "manifest_sha256": "a" * 64,
    "surface_snapshot_sha256": "b" * 64, "worklist_path": "files/hunt/l-sink/index.json",
    "worklist_sha256": "c" * 64, "unit_count": 2, "batch_count": 1, "status": "pending",
}
HUNT_RECEIPT = {
    "image_id": "acme|r1|target", "lane": "l-dark", "worklist_sha256": "c" * 64,
    "batch_path": "files/hunt/l-dark/batch-001.json", "batch_sha256": "d" * 64,
    "result_path": "artifacts/hunt/result.json", "result_sha256": "e" * 64,
    "unit_count": 2, "candidate_count": 0,
}
HUNT_CANDIDATE = {
    "image_id": "acme|r1|target", "lane": "l-sink", "candidate_id": "sink.1",
    "component_path": "bin/httpd", "title": "Unchecked command argument",
    "bug_class": "command injection", "surface_ids": '["http.login:1"]',
    "surface_context": "Login route reaches the configuration writer",
    "attacker_position": "LAN client", "input_evidence": "route.c:42 reads user field",
    "data_flow": "user field -> cfg value -> shell argument",
    "dangerous_operation": "system", "operation_evidence": "cfg.c:76 invokes system",
    "mitigations_checked": "length is bounded but shell metacharacters survive",
    "lifecycle_required": "provisioned", "posture_required": "sta-lan",
    "auth_required": "pre-auth", "reachability": "evidenced",
    "state_evidence": "route table orders handler before the authentication guard",
    "confidence": 8, "impact_hypothesis": "Commands may execute as the daemon user",
    "blockers": '[]', "artifact_path": "artifacts/hunt/result.json",
    "artifact_sha256": "e" * 64,
}
HUNT_ROWS = [("cba_hunt_runs", HUNT_RUN), ("cba_hunt_receipts", HUNT_RECEIPT),
             ("cba_hunt_candidates", HUNT_CANDIDATE)]


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for (table, _, required, _), (_, row) in zip(HUNT_CONTRACTS, HUNT_ROWS)
    for column in required
])
@pytest.mark.parametrize("value", ["omit", "", " \t ", None, True])
def test_hunt_contract_requires_every_evidence_and_identity_field(con, table, row, column, value):
    invalid = row | {column: value}
    if value == "omit":
        invalid.pop(column)
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, invalid)
    assert db.rows(con, table) == []
    assert not con.in_transaction


HUNT_ENUMS = [
    *[(table, row, "lane", ("l-sink", "l-dark")) for table, row in HUNT_ROWS],
    ("cba_hunt_runs", HUNT_RUN, "status", ("pending", "complete")),
    ("cba_hunt_candidates", HUNT_CANDIDATE, "lifecycle_required",
     ("factory-fresh", "provisioned", "bound-to-owner", "cloud-registered", "post-reset", "unknown")),
    ("cba_hunt_candidates", HUNT_CANDIDATE, "posture_required",
     ("softap-setup", "sta-lan", "wan-exposed", "ble", "cloud-tunnel-only", "unknown")),
    ("cba_hunt_candidates", HUNT_CANDIDATE, "auth_required",
     ("pre-auth", "session", "admin", "local-shell", "physical-uart", "unknown")),
    ("cba_hunt_candidates", HUNT_CANDIDATE, "reachability", ("evidenced", "refuted", "unknown")),
]


@pytest.mark.parametrize("table,row,column,allowed", HUNT_ENUMS)
@pytest.mark.parametrize("value", ["invalid", "UNKNOWN", " unknown "])
def test_hunt_contract_rejects_foreign_enums(con, table, row, column, allowed, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,column,value", [
    (table, row, column, value) for table, row, column, allowed in HUNT_ENUMS for value in allowed
])
def test_hunt_contract_accepts_all_canonical_enums(con, table, row, column, value):
    db.put(con, table, row | {column: value})
    assert db.rows(con, table)[0][column] == value


HUNT_COUNTS = [("cba_hunt_runs", HUNT_RUN, "unit_count"),
               ("cba_hunt_runs", HUNT_RUN, "batch_count"),
               ("cba_hunt_receipts", HUNT_RECEIPT, "unit_count"),
               ("cba_hunt_receipts", HUNT_RECEIPT, "candidate_count")]


@pytest.mark.parametrize("table,row,column", HUNT_COUNTS + [
    ("cba_hunt_candidates", HUNT_CANDIDATE, "confidence")])
@pytest.mark.parametrize("value", [-1, "-1", 1.0, "1.5", False, True, "１", "1_0",
                                    "\u00a01\u00a0", 9223372036854775808,
                                    "9223372036854775808"])
def test_hunt_contract_rejects_noninteger_or_overflow_numbers(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []
    assert not con.in_transaction


@pytest.mark.parametrize("table,row,column", HUNT_COUNTS)
@pytest.mark.parametrize("value,expected", [(0, 0), ("0", 0), (9223372036854775807, 9223372036854775807)])
def test_hunt_counts_persist_at_sqlite_integer_boundaries(con, table, row, column, value, expected):
    db.put(con, table, row | {column: value})
    assert tuple(con.execute(f"SELECT {column}, typeof({column}) FROM {table}").fetchone()) == (expected, "integer")


@pytest.mark.parametrize("value", [11, "11", 9223372036854775807])
def test_hunt_confidence_cannot_exceed_ten(con, value):
    with pytest.raises(db.DbError, match="confidence"):
        db.put(con, "cba_hunt_candidates", HUNT_CANDIDATE | {"confidence": value})
    assert db.rows(con, "cba_hunt_candidates") == []
    assert not con.in_transaction


@pytest.mark.parametrize("value", [0, "0", 10, "10"])
def test_hunt_confidence_accepts_zero_and_ten(con, value):
    db.put(con, "cba_hunt_candidates", HUNT_CANDIDATE | {"confidence": value})
    assert db.rows(con, "cba_hunt_candidates")[0]["confidence"] == int(value)


@pytest.mark.parametrize("table,row,column", [
    (table, row, column) for table, row in HUNT_ROWS for column in row if column.endswith("sha256")
])
@pytest.mark.parametrize("value", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, 123])
def test_hunt_contract_rejects_invalid_hashes(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []
    assert not con.in_transaction


@pytest.mark.parametrize("column,value", [
    (column, value) for column in ("surface_ids", "blockers")
    for value in ('[', '{}', 'null', '[NaN]', ' []', '[ ]', '[]\n', [])
] + [
    ("surface_ids", '["http.login:1","http.login:1"]'),
    ("surface_ids", '[1]'), ("surface_ids", '[""]'),
    ("surface_ids", '["bad id"]'), ("surface_ids", '["\\u00e9"]'),
    ("blockers", '["pending"]'), ("blockers", '[{}]'),
    ("blockers", '[{"id":"b1","id":"b2"}]'),
])
def test_hunt_candidate_rejects_malformed_or_noncanonical_json(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_hunt_candidates", HUNT_CANDIDATE | {column: value})
    assert db.rows(con, "cba_hunt_candidates") == []
    assert not con.in_transaction


@pytest.mark.parametrize("field", ["id", "question", "settling_observation", "method"])
@pytest.mark.parametrize("value", ["omit", "", "  ", None, True])
def test_hunt_blockers_require_complete_settling_contract(con, field, value):
    import json
    blocker = {"id": "b1", "question": "Is the wrapper enabled?",
               "settling_observation": "Trace dispatch to wrapper", "method": "static"}
    if value == "omit":
        blocker.pop(field)
    else:
        blocker[field] = value
    encoded = json.dumps([blocker], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    with pytest.raises(db.DbError, match="blockers"):
        db.put(con, "cba_hunt_candidates", HUNT_CANDIDATE | {"blockers": encoded})
    assert db.rows(con, "cba_hunt_candidates") == []
    assert not con.in_transaction


@pytest.mark.parametrize("method", ["static", "emulate", "hardware"])
def test_hunt_candidate_retains_canonical_blocker_evidence(con, method):
    encoded = ('[{"id":"b1","method":"' + method + '","question":"Enabled on café model?",'
               '"settling_observation":"Trace dispatch to wrapper"}]')
    db.put(con, "cba_hunt_candidates", HUNT_CANDIDATE | {"blockers": encoded, "surface_ids": '[]'})
    assert db.rows(con, "cba_hunt_candidates")[0]["blockers"] == encoded


@pytest.mark.parametrize("value", [
    '[{"id":"bad/id","method":"static","question":"Enabled?","settling_observation":"Trace"}]',
    '[{"id":"b1","method":"remote","question":"Enabled?","settling_observation":"Trace"}]',
    '[{"extra":"x","id":"b1","method":"static","question":"Enabled?","settling_observation":"Trace"}]',
    '[{"id":"b1","method":"static","question":"Enabled?","settling_observation":"Trace"},'
    '{"id":"b1","method":"static","question":"Other?","settling_observation":"Read"}]',
])
def test_hunt_candidate_rejects_foreign_or_duplicate_blockers(con, value):
    with pytest.raises(db.DbError, match="blockers"):
        db.put(con, "cba_hunt_candidates", HUNT_CANDIDATE | {"blockers": value})
    assert db.rows(con, "cba_hunt_candidates") == []
    assert not con.in_transaction


@pytest.mark.parametrize("table,row", HUNT_ROWS)
def test_hunt_rows_support_caller_owned_transactions(con, table, row):
    db.put(con, table, row, commit=False)
    assert con.in_transaction
    assert len(db.rows(con, table)) == 1
    con.rollback()
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,columns,required,key", HUNT_CONTRACTS)
def test_hunt_tables_have_the_exact_durable_contract(con, table, columns, required, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted(
        (row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert (spec.columns, spec.required, spec.primary_key) == (columns, required, key)


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261009-000000")
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


def test_schema_and_contract_expose_all_firmware_tables(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261009-000000")
    result = workspace.apply_schema(run / "audit.db")
    assert len(result.tables) == 38
    assert len(db.TABLE_SPECS) == 37
    con = sqlite3.connect(run / "audit.db")
    try:
        for table in ("cba_images", "cba_binfacts", "cba_services",
                      "cba_firmware_files", "cba_diffs", "cba_diff_entries",
                      "cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns",
                      "cba_hunt_runs", "cba_hunt_receipts", "cba_hunt_candidates"):
            schema_columns = tuple(
                row[1] for row in con.execute(f"PRAGMA table_info({table})"))
            assert schema_columns == db.TABLE_SPECS[table].columns
    finally:
        con.close()


@pytest.mark.parametrize("table,columns,required,key", [
    ("cba_diffs",
     ("id", "reference_image_id", "target_image_id", "added_count",
      "removed_count", "modified_count", "unchanged_count", "manifest_path",
      "recorded_at"),
     ("id", "reference_image_id", "target_image_id", "added_count",
      "removed_count", "modified_count", "unchanged_count", "manifest_path"),
     ("id",)),
    ("cba_diff_entries",
     ("diff_id", "path", "change", "reference_kind", "target_kind",
      "reference_size", "target_size", "reference_sha256", "target_sha256"),
     ("diff_id", "path", "change"), ("diff_id", "path")),
])
def test_diff_tables_have_the_exact_durable_contract(con, table, columns,
                                                   required, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted(
        (row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert spec.columns == columns
    assert spec.required == required
    assert spec.primary_key == key


DIFF = {"id": "diff-0123456789abcdef", "reference_image_id": "reference",
        "target_image_id": "target", "added_count": "1", "removed_count": "2",
        "modified_count": "3", "unchanged_count": "4",
        "manifest_path": "files/diff-0123456789abcdef-abcd.json"}


@pytest.mark.parametrize("column", tuple(DIFF))
def test_diff_summary_requires_every_identity_and_count_field(con, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_diffs", {k: v for k, v in DIFF.items() if k != column})


@pytest.mark.parametrize("column", ["added_count", "removed_count",
                                    "modified_count", "unchanged_count"])
@pytest.mark.parametrize("value", [-1, "-1", "1.5", 1.0, "nope", None, True,
                                    "1_0", "１"])
def test_diff_summary_rejects_negative_and_noninteger_counts(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_diffs", DIFF | {column: value})
    assert db.rows(con, "cba_diffs") == []


@pytest.mark.parametrize("value", [0, "0", 2, "2", " +2 ", "-0"])
def test_diff_summary_accepts_nonnegative_integer_counts(con, value):
    db.put(con, "cba_diffs", DIFF | {"added_count": value})
    assert db.rows(con, "cba_diffs", columns=("added_count",))[0][0] == int(value)


@pytest.mark.parametrize("column", ["added_count", "removed_count",
                                    "modified_count", "unchanged_count"])
@pytest.mark.parametrize("value", ["\u00a01\u00a0", "\u20031\u2003", "\x1c1\x1c",
                                    "9223372036854775808", 9223372036854775808])
def test_diff_summary_rejects_counts_sqlite_would_store_as_text_or_real(
        con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_diffs", DIFF | {column: value})
    assert con.execute("SELECT COUNT(*) FROM cba_diffs").fetchone()[0] == 0
    assert not con.in_transaction


@pytest.mark.skipif(not hasattr(sys, "set_int_max_str_digits"),
                    reason="Python has no integer conversion digit limit")
def test_diff_summary_wraps_integer_conversion_limit_without_writing(con):
    previous_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        with pytest.raises(db.DbError, match="added_count=.*not a non-negative integer"):
            db.put(con, "cba_diffs", DIFF | {"added_count": "9" * 641})
    finally:
        sys.set_int_max_str_digits(previous_limit)
    assert con.execute("SELECT COUNT(*) FROM cba_diffs").fetchone()[0] == 0
    assert not con.in_transaction


@pytest.mark.parametrize("column", ["added_count", "removed_count",
                                    "modified_count", "unchanged_count"])
@pytest.mark.parametrize("value,expected", [
    (0, 0), ("0", 0),
    (9223372036854775807, 9223372036854775807),
    ("9223372036854775807", 9223372036854775807),
    (" \t+9223372036854775807\r\n", 9223372036854775807),
])
def test_diff_summary_boundary_counts_persist_as_sqlite_integers(
        con, column, value, expected):
    db.put(con, "cba_diffs", DIFF | {column: value})
    got = con.execute(f"SELECT {column}, typeof({column}) FROM cba_diffs").fetchone()
    assert tuple(got) == (expected, "integer")


DIFF_ENTRIES = (
    {"diff_id": "diff-one", "path": "etc/new", "change": "added",
     "target_kind": "config", "target_size": "0", "target_sha256": "aa"},
    {"diff_id": "diff-one", "path": "etc/old", "change": "removed",
     "reference_kind": "config", "reference_size": "2",
     "reference_sha256": "bb"},
    {"diff_id": "diff-one", "path": "bin/httpd", "change": "modified",
     "reference_kind": "binary", "reference_size": "3",
     "reference_sha256": "cc", "target_kind": "binary", "target_size": "4",
     "target_sha256": "dd"},
)


@pytest.mark.parametrize("row", DIFF_ENTRIES)
def test_diff_entry_accepts_each_change_with_its_required_sides(con, row):
    db.put(con, "cba_diff_entries", row)
    got = dict(db.rows(con, "cba_diff_entries")[0])
    assert got["change"] == row["change"]
    for column, value in row.items():
        assert got[column] == (int(value) if column.endswith("_size") else value)


@pytest.mark.parametrize("row,column", [
    (row, column) for row in DIFF_ENTRIES for column in row
])
@pytest.mark.parametrize("missing", ["omit", "", "   ", None])
def test_diff_entry_requires_identity_and_the_change_specific_fields(
        con, row, column, missing):
    incomplete = dict(row)
    if missing == "omit":
        incomplete.pop(column)
    else:
        incomplete[column] = missing
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_diff_entries", incomplete)
    assert db.rows(con, "cba_diff_entries") == []


@pytest.mark.parametrize("change", ["unchanged", "renamed", "ADDED"])
def test_diff_entry_rejects_changes_outside_the_contract(con, change):
    with pytest.raises(db.DbError, match="change"):
        db.put(con, "cba_diff_entries", DIFF_ENTRIES[2] | {"change": change})


def test_diff_entry_keys_scope_the_same_path_to_each_comparison(con):
    db.put(con, "cba_diff_entries", DIFF_ENTRIES[0])
    db.put(con, "cba_diff_entries", DIFF_ENTRIES[0] | {"diff_id": "diff-two"})
    assert len(db.rows(con, "cba_diff_entries")) == 2
    with pytest.raises(db.DbError, match="--replace"):
        db.put(con, "cba_diff_entries", DIFF_ENTRIES[0])


def test_diff_entry_accepts_an_integer_zero_size(con):
    db.put(con, "cba_diff_entries", DIFF_ENTRIES[0] | {"target_size": 0})
    assert db.rows(con, "cba_diff_entries", columns=("target_size",))[0][0] == 0


def test_every_table_primary_key_matches_its_contract(con):
    for table, spec in db.TABLE_SPECS.items():
        keyed = [(row[5], row[1]) for row in con.execute(
            f"PRAGMA table_info({table})") if row[5]]
        assert tuple(name for _, name in sorted(keyed)) == spec.primary_key, table
    assert db.primary_key(con, "cba_binfacts") == ("image_id", "path")
    assert db.primary_key(con, "cba_services") == ("image_id", "name")
    assert db.primary_key(con, "cba_firmware_files") == ("image_id", "path")


def test_manifest_requires_scope_and_file_identity(con):
    row = {"image_id": "target", "path": "etc/config", "kind": "config",
           "size": "3", "sha256": "ba7816bf8f01cfea414140de5dae2223"
           "b00361a396177a9cb410ff61f20015ad"}
    for column in row:
        with pytest.raises(db.DbError, match=column):
            db.put(con, "cba_firmware_files",
                   {key: value for key, value in row.items() if key != column})
    db.put(con, "cba_firmware_files", row)
    db.put(con, "cba_firmware_files", row | {"image_id": "reference"})
    assert len(db.rows(con, "cba_firmware_files")) == 2


def test_image_roles_are_validated(con):
    base = {"id": "acme|r1|target", "vendor": "acme", "model": "r1",
            "version": "1.0", "path": "/images/r1.bin", "sha256": "ab"}
    for role in ("target", "diff-reference"):
        db.put(con, "cba_images", base | {"id": f"acme|r1|{role}", "role": role})
    with pytest.raises(db.DbError, match="snapshot"):
        db.put(con, "cba_images", base | {"role": "snapshot"})


def test_binfact_states_are_validated(con):
    row = {"image_id": "legacy-unscoped", "path": "bin/httpd", "machine": "mips", "bits": "32",
           "endian": "big", "elf_type": "EXEC", "nx": "yes",
           "pie": "no", "relro": "partial", "canary": "unknown",
           "stripped": "yes", "static": "no"}
    db.put(con, "cba_binfacts", row)
    with pytest.raises(db.DbError, match="sometimes"):
        db.put(con, "cba_binfacts", row | {"path": "bin/bad", "nx": "sometimes"})
    with pytest.raises(db.DbError, match="strong"):
        db.put(con, "cba_binfacts", row | {"path": "bin/bad2", "relro": "strong"})


def test_service_ports_need_evidence(con):
    row = {"image_id": "legacy-unscoped", "name": "httpd", "start_source": "etc/init.d/S50httpd",
           "evidence": "/usr/sbin/httpd -f /etc/httpd.conf"}
    db.put(con, "cba_services", row)
    with pytest.raises(db.DbError, match="ports_evidence"):
        db.put(con, "cba_services", row | {"name": "telnetd", "ports": "23/tcp"})


def test_service_replace_validates_the_effective_merged_row(con):
    row = {"image_id": "legacy-unscoped", "name": "httpd", "start_source": "etc/init.d/S50httpd",
           "evidence": "/usr/sbin/httpd", "ports": "80/tcp",
           "ports_evidence": "etc/httpd.conf:1 listen 80"}
    db.put(con, "cba_services", row)

    with pytest.raises(db.DbError, match="ports_evidence"):
        db.put(con, "cba_services", {
            "image_id": "legacy-unscoped", "name": "httpd", "start_source": "etc/init.d/S50httpd",
            "evidence": "/usr/sbin/httpd", "ports_evidence": "",
        }, replace=True)


def test_inventory_accepts_firmware_file_kinds(con):
    db.put(con, "cba_inventory", {"unit": "etc/config", "kind": "config"})
    db.put(con, "cba_inventory", {"unit": "etc/init.d/S01", "kind": "script"})
    assert [r[0] for r in db.rows(con, "cba_inventory", columns=("kind",))] == [
        "config", "script"]


SURFACE_RUN = {
    "image_id": "acme|r1|target", "manifest_sha256": "a" * 64,
    "worklist_path": "files/surface/index.json", "worklist_sha256": "b" * 64,
    "unit_count": 2, "batch_count": 1, "status": "pending",
}
SURFACE = {
    "image_id": "acme|r1|target", "surface_id": "http.login:1",
    "component_path": "bin/httpd", "entry_point": "POST /login",
    "protocol": "http", "dispatch_path": "route table -> dispatch_request",
    "handler": "login_handler", "lifecycle_required": "provisioned",
    "posture_required": "sta-lan", "auth_required": "pre-auth",
    "reachability": "evidenced", "reach_evidence": "dispatch.c:42 route to login",
    "artifact_path": "files/surface/result.json", "artifact_sha256": "c" * 64,
}
UNKNOWN = {
    "id": "unknown.http:1", "image_id": "acme|r1|target",
    "component_path": "bin/httpd", "surface_id": "http.login:1",
    "field": "posture", "question": "Does WAN forward requests to httpd?",
    "settling_observation": "Observe WAN forwarding in a packet trace",
    "method": "emulate", "status": "open",
    "artifact_path": "files/surface/result.json", "artifact_sha256": "c" * 64,
}

SURFACE_CONTRACTS = [
    ("cba_surface_runs",
     ("image_id", "manifest_sha256", "worklist_path", "worklist_sha256",
      "unit_count", "batch_count", "status", "prepared_at", "completed_at"),
     ("image_id", "manifest_sha256", "worklist_path", "worklist_sha256",
      "unit_count", "batch_count", "status"), ("image_id",)),
    ("cba_firmware_surfaces",
     ("image_id", "surface_id", "component_path", "entry_point", "protocol",
      "dispatch_path", "handler", "lifecycle_required", "posture_required",
      "auth_required", "reachability", "reach_evidence", "artifact_path",
      "artifact_sha256", "recorded_at"),
     ("image_id", "surface_id", "component_path", "entry_point", "protocol",
      "dispatch_path", "handler", "lifecycle_required", "posture_required",
      "auth_required", "reachability", "reach_evidence", "artifact_path",
      "artifact_sha256"), ("image_id", "surface_id")),
    ("cba_unknowns",
     ("id", "image_id", "component_path", "surface_id", "field", "question",
      "settling_observation", "method", "status", "resolution", "evidence",
      "artifact_path", "artifact_sha256", "recorded_at"),
     ("id", "image_id", "component_path", "field", "question",
      "settling_observation", "method", "status", "artifact_path",
      "artifact_sha256"), ("id",)),
]


@pytest.mark.parametrize("table,columns,required,key", SURFACE_CONTRACTS)
def test_surface_tables_have_the_exact_durable_contract(con, table, columns,
                                                       required, key):
    info = list(con.execute(f"PRAGMA table_info({table})"))
    assert tuple(row[1] for row in info) == columns
    assert tuple(row[1] for row in info if row[3] or row[5]) == required
    assert tuple(name for _, name in sorted(
        (row[5], row[1]) for row in info if row[5])) == key
    spec = db.TABLE_SPECS[table]
    assert (spec.columns, spec.required, spec.primary_key) == (columns, required, key)


@pytest.mark.parametrize("table,row,column", [
    (table, row, column)
    for (table, _, required, _), row in zip(
        SURFACE_CONTRACTS, (SURFACE_RUN, SURFACE, UNKNOWN))
    for column in required
])
@pytest.mark.parametrize("value", ["omit", "", " \t ", None])
def test_surface_contract_requires_nonempty_fields(con, table, row, column, value):
    invalid = dict(row)
    if value == "omit":
        invalid.pop(column)
    else:
        invalid[column] = value
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, invalid)
    assert db.rows(con, table) == []
    assert not con.in_transaction


SURFACE_ENUMS = [
    ("cba_surface_runs", SURFACE_RUN, "status", ("pending", "complete")),
    ("cba_firmware_surfaces", SURFACE, "lifecycle_required",
     ("factory-fresh", "provisioned", "bound-to-owner", "cloud-registered",
      "post-reset", "unknown")),
    ("cba_firmware_surfaces", SURFACE, "posture_required",
     ("softap-setup", "sta-lan", "wan-exposed", "ble", "cloud-tunnel-only", "unknown")),
    ("cba_firmware_surfaces", SURFACE, "auth_required",
     ("pre-auth", "session", "admin", "local-shell", "physical-uart", "unknown")),
    ("cba_firmware_surfaces", SURFACE, "reachability", ("evidenced", "refuted", "unknown")),
    ("cba_unknowns", UNKNOWN, "field", ("dispatch", "handler", "lifecycle", "posture", "auth", "reachability")),
    ("cba_unknowns", UNKNOWN, "method", ("static", "emulate", "hardware")),
    ("cba_unknowns", UNKNOWN, "status", ("open", "resolved")),
]


@pytest.mark.parametrize("table,row,column,value", [
    (table, row, column, value) for table, row, column, values in SURFACE_ENUMS
    for value in values
])
def test_surface_contract_accepts_every_canonical_enum(con, table, row, column, value):
    valid = row | {column: value}
    if table == "cba_unknowns" and column == "status" and value == "resolved":
        valid |= {"resolution": "WAN forwarding is disabled", "evidence": "config:17 wan=off"}
    db.put(con, table, valid)
    assert db.rows(con, table)[0][column] == value


@pytest.mark.parametrize("table,row,column,values", SURFACE_ENUMS)
@pytest.mark.parametrize("value", ["invalid", "UNKNOWN", " unknown ", True])
def test_surface_contract_rejects_noncanonical_enums(con, table, row, column, values, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []
    assert not con.in_transaction


@pytest.mark.parametrize("column", ["unit_count", "batch_count"])
@pytest.mark.parametrize("value", [-1, "-1", "1.5", 1.0, "nope", None, True,
                                    "1_0", "１", "\u00a01\u00a0",
                                    "9223372036854775808", 9223372036854775808])
def test_surface_run_rejects_counts_outside_sqlite_integer_contract(con, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_surface_runs", SURFACE_RUN | {column: value})
    assert db.rows(con, "cba_surface_runs") == []
    assert not con.in_transaction


@pytest.mark.parametrize("column", ["unit_count", "batch_count"])
@pytest.mark.parametrize("value,expected", [
    (0, 0), ("0", 0), ("-0", 0), (9223372036854775807, 9223372036854775807),
    ("9223372036854775807", 9223372036854775807),
    (" \t+9223372036854775807\r\n", 9223372036854775807),
])
def test_surface_run_boundary_counts_persist_as_sqlite_integers(con, column, value, expected):
    db.put(con, "cba_surface_runs", SURFACE_RUN | {column: value})
    got = con.execute(f"SELECT {column}, typeof({column}) FROM cba_surface_runs").fetchone()
    assert tuple(got) == (expected, "integer")


@pytest.mark.parametrize("table,row,column", [
    ("cba_surface_runs", SURFACE_RUN, "manifest_sha256"),
    ("cba_surface_runs", SURFACE_RUN, "worklist_sha256"),
    ("cba_firmware_surfaces", SURFACE, "artifact_sha256"),
    ("cba_unknowns", UNKNOWN, "artifact_sha256"),
])
@pytest.mark.parametrize("value", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, " a" * 32, 123])
def test_surface_contract_rejects_invalid_sha256(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,row,column", [
    ("cba_firmware_surfaces", SURFACE, "surface_id"),
    ("cba_unknowns", UNKNOWN, "id"), ("cba_unknowns", UNKNOWN, "surface_id"),
])
@pytest.mark.parametrize("value", ["bad id", "bad/id", "-leading", "é", "x" * 129, True, 7])
def test_surface_contract_rejects_unsafe_identifiers(con, table, row, column, value):
    with pytest.raises(db.DbError, match=column):
        db.put(con, table, row | {column: value})
    assert db.rows(con, table) == []


@pytest.mark.parametrize("table,row,column", [
    ("cba_firmware_surfaces", SURFACE, "surface_id"),
    ("cba_unknowns", UNKNOWN, "id"), ("cba_unknowns", UNKNOWN, "surface_id"),
])
@pytest.mark.parametrize("value", ["0", "A._:-z", "x" * 128])
def test_surface_contract_accepts_identifier_boundaries(con, table, row, column, value):
    db.put(con, table, row | {column: value})
    assert db.rows(con, table)[0][column] == value


@pytest.mark.parametrize("surface_id", [None, "", "  "])
def test_unknown_can_omit_surface_when_no_surface_identified(con, surface_id):
    db.put(con, "cba_unknowns", UNKNOWN | {"surface_id": surface_id})
    assert len(db.rows(con, "cba_unknowns")) == 1


@pytest.mark.parametrize("column", ["resolution", "evidence"])
def test_open_unknown_refuses_resolution_or_evidence(con, column):
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_unknowns", UNKNOWN | {column: "unexpected claim"})
    assert db.rows(con, "cba_unknowns") == []


@pytest.mark.parametrize("column", ["resolution", "evidence"])
@pytest.mark.parametrize("value", [None, "", "   "])
def test_resolved_unknown_requires_both_resolution_and_evidence(con, column, value):
    row = UNKNOWN | {"status": "resolved", "resolution": "Forwarding disabled",
                     "evidence": "config:17 wan=off", column: value}
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_unknowns", row)
    assert db.rows(con, "cba_unknowns") == []


@pytest.mark.parametrize("status", ["open", "resolved"])
@pytest.mark.parametrize("column", ["resolution", "evidence"])
@pytest.mark.parametrize("value", [True, 7, {"claim": "not text"}])
def test_unknown_optional_evidence_fields_reject_nontext_values(con, status, column, value):
    row = UNKNOWN | {"status": status}
    if status == "resolved":
        row |= {"resolution": "Forwarding disabled", "evidence": "config:17 wan=off"}
    with pytest.raises(db.DbError, match=column):
        db.put(con, "cba_unknowns", row | {column: value})
    assert db.rows(con, "cba_unknowns") == []
    assert not con.in_transaction


def test_unknown_replacement_validates_retained_resolution(con):
    db.put(con, "cba_unknowns", UNKNOWN | {"status": "resolved",
                                         "resolution": "Forwarding disabled",
                                         "evidence": "config:17 wan=off"})
    with pytest.raises(db.DbError, match="resolution"):
        db.put(con, "cba_unknowns", UNKNOWN, replace=True)
    assert db.rows(con, "cba_unknowns")[0]["status"] == "resolved"


def test_surface_keys_scope_ids_by_image_but_unknown_ids_are_global(con):
    db.put(con, "cba_firmware_surfaces", SURFACE)
    db.put(con, "cba_firmware_surfaces", SURFACE | {"image_id": "other|r1|target"})
    assert len(db.rows(con, "cba_firmware_surfaces")) == 2
    db.put(con, "cba_unknowns", UNKNOWN)
    with pytest.raises(db.DbError, match="--replace"):
        db.put(con, "cba_unknowns", UNKNOWN | {"image_id": "other|r1|target"})
