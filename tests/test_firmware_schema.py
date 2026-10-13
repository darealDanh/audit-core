import sqlite3
import sys

import pytest

from audit_core import db, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261009-000000")
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


def test_schema_and_contract_expose_all_firmware_tables(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261009-000000")
    result = workspace.apply_schema(run / "audit.db")
    assert len(result.tables) == 21
    assert len(db.TABLE_SPECS) == 20
    con = sqlite3.connect(run / "audit.db")
    try:
        for table in ("cba_images", "cba_binfacts", "cba_services",
                      "cba_firmware_files", "cba_diffs", "cba_diff_entries"):
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
