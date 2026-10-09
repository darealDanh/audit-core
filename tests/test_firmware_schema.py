import sqlite3

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
    assert len(result.tables) == 18
    assert len(db.TABLE_SPECS) == 17
    con = sqlite3.connect(run / "audit.db")
    try:
        for table in ("cba_images", "cba_binfacts", "cba_services"):
            schema_columns = tuple(
                row[1] for row in con.execute(f"PRAGMA table_info({table})"))
            assert schema_columns == db.TABLE_SPECS[table].columns
    finally:
        con.close()


def test_image_roles_are_validated(con):
    base = {"id": "acme|r1|target", "vendor": "acme", "model": "r1",
            "version": "1.0", "path": "/images/r1.bin", "sha256": "ab"}
    for role in ("target", "diff-reference"):
        db.put(con, "cba_images", base | {"id": f"acme|r1|{role}", "role": role})
    with pytest.raises(db.DbError, match="snapshot"):
        db.put(con, "cba_images", base | {"role": "snapshot"})


def test_binfact_states_are_validated(con):
    row = {"path": "bin/httpd", "machine": "mips", "bits": "32",
           "endian": "big", "elf_type": "EXEC", "nx": "yes",
           "pie": "no", "relro": "partial", "canary": "unknown",
           "stripped": "yes", "static": "no"}
    db.put(con, "cba_binfacts", row)
    with pytest.raises(db.DbError, match="sometimes"):
        db.put(con, "cba_binfacts", row | {"path": "bin/bad", "nx": "sometimes"})
    with pytest.raises(db.DbError, match="strong"):
        db.put(con, "cba_binfacts", row | {"path": "bin/bad2", "relro": "strong"})


def test_service_ports_need_evidence(con):
    row = {"name": "httpd", "start_source": "etc/init.d/S50httpd",
           "evidence": "/usr/sbin/httpd -f /etc/httpd.conf"}
    db.put(con, "cba_services", row)
    with pytest.raises(db.DbError, match="ports_evidence"):
        db.put(con, "cba_services", row | {"name": "telnetd", "ports": "23/tcp"})


def test_inventory_accepts_firmware_file_kinds(con):
    db.put(con, "cba_inventory", {"unit": "etc/config", "kind": "config"})
    db.put(con, "cba_inventory", {"unit": "etc/init.d/S01", "kind": "script"})
    assert [r[0] for r in db.rows(con, "cba_inventory", columns=("kind",))] == [
        "config", "script"]
