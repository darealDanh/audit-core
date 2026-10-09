import hashlib
import struct

import pytest

from audit_core import db, triage, workspace


def minimal_elf():
    ident = b"\x7fELF" + bytes((2, 1, 1)) + b"\0" * 9
    return struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 0, 0, 0,
                       64, 56, 0, 64, 0, 0)


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261009-020000")
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


def carved_tree(tmp_path):
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    (root / "usr" / "share").mkdir(parents=True)
    (root / "bin" / "httpd").write_bytes(minimal_elf())
    (root / "etc" / "init.d" / "S50httpd").write_text("#!/bin/sh\n/bin/httpd\n")
    (root / "etc" / "httpd.conf").write_text("port=80\n")
    (root / "usr" / "share" / "banner").write_text("hello\n")
    (root / "bin" / "httpd-link").symlink_to("httpd")
    outside = tmp_path / "outside"
    outside.write_text("secret")
    (root / "outside-link").symlink_to(outside)
    return root


def test_run_inventories_regular_files_and_elf_facts(con, tmp_path):
    root = carved_tree(tmp_path)
    summary = triage.run(con, root)
    assert summary == triage.TriageSummary(4, 1, 0)
    rows = [dict(row) for row in db.rows(
        con, "cba_inventory", columns=("unit", "kind", "size"))]
    assert {(r["unit"], r["kind"]) for r in rows} == {
        ("bin/httpd", "binary"),
        ("etc/httpd.conf", "config"),
        ("etc/init.d/S50httpd", "script"),
        ("usr/share/banner", "file"),
    }
    assert all(not r["unit"].startswith("/") for r in rows)
    facts = dict(db.rows(con, "cba_binfacts")[0])
    assert facts["path"] == "bin/httpd"
    assert facts["machine"] == "x86-64"
    assert facts["sha256"] == hashlib.sha256(minimal_elf()).hexdigest()
    assert facts["needed"] == ""


def test_run_is_idempotent(con, tmp_path):
    root = carved_tree(tmp_path)
    assert triage.run(con, root) == triage.run(con, root)
    assert len(db.rows(con, "cba_inventory")) == 4
    assert len(db.rows(con, "cba_binfacts")) == 1


@pytest.mark.parametrize("root_kind", ["missing", "file"])
def test_run_refuses_a_non_directory_root_before_writing(con, tmp_path, root_kind):
    root = tmp_path / root_kind
    if root_kind == "file":
        root.write_text("not a rootfs")
    with pytest.raises(triage.TriageError, match="directory"):
        triage.run(con, root)
    assert db.rows(con, "cba_inventory") == []


def test_run_refuses_unknown_image_id_before_writing(con, tmp_path):
    root = carved_tree(tmp_path)
    with pytest.raises(triage.TriageError, match="not recorded"):
        triage.run(con, root, image_id="acme|r1|target")
    assert db.rows(con, "cba_inventory") == []


def test_run_attaches_valid_image_id_to_binfacts(con, tmp_path):
    root = carved_tree(tmp_path)
    db.put(con, "cba_images", {
        "id": "acme|r1|target", "vendor": "acme", "model": "r1",
        "version": "1", "role": "target", "path": "/fw.bin", "sha256": "ab"})
    triage.run(con, root, image_id="acme|r1|target")
    assert db.rows(con, "cba_binfacts", columns=("image_id",))[0][0] == (
        "acme|r1|target")
