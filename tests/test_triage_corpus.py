import hashlib
import pathlib

import pytest

from audit_core import db, triage, workspace

CORPUS = pathlib.Path(
    "/Users/danhnguyen/Documents/Offsec/Opswat/Devices/gl_inet/extracted/rootfs")


@pytest.mark.skipif(not CORPUS.is_dir(), reason="gl_inet carved rootfs is absent")
def test_gl_inet_triage_is_internally_consistent(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261009-040000")
    con = db.connect(run / "audit.db")
    try:
        summary = triage.run(con, CORPUS)
        assert summary.inventory_count > 0
        assert summary.elf_count > 0
        inventory = {row[0] for row in con.execute("SELECT unit FROM cba_inventory")}
        manifest = {(row[0], row[1]) for row in con.execute(
            "SELECT image_id, path FROM cba_firmware_files")}
        assert len(manifest) == summary.inventory_count
        assert manifest == {(db.FIRMWARE_IMAGE_UNSCOPED, path) for path in inventory}
        binfacts = con.execute(
            "SELECT path, machine, image_id FROM cba_binfacts").fetchall()
        assert len(binfacts) == summary.elf_count
        assert all(row[0] in inventory for row in binfacts)
        assert all((row[2], row[0]) in manifest for row in binfacts)
        machines = {row[1] for row in binfacts if row[1].isdigit() is False}
        assert len(machines) == 1, machines
        bash = con.execute(
            "SELECT needed FROM cba_binfacts WHERE path = 'bin/bash'").fetchone()
        if (CORPUS / "bin/bash").is_file():
            assert bash is not None
            assert {"libncursesw.so.6", "libgcc_s.so.1", "libc.so"} <= set(
                bash[0].split(","))
            stored = con.execute(
                "SELECT kind, size, sha256 FROM cba_firmware_files "
                "WHERE image_id = ? AND path = 'bin/bash'",
                (db.FIRMWARE_IMAGE_UNSCOPED,)).fetchone()
            digest = hashlib.sha256()
            with (CORPUS / "bin/bash").open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            assert tuple(stored) == (
                "binary", (CORPUS / "bin/bash").stat().st_size, digest.hexdigest())
            assert con.execute(
                "SELECT sha256 FROM cba_binfacts WHERE image_id = ? AND path = 'bin/bash'",
                (db.FIRMWARE_IMAGE_UNSCOPED,)).fetchone()[0] == digest.hexdigest()
        service_names = {
            row[0] for row in con.execute("SELECT name FROM cba_services")}
        assert "passwd" not in service_names
        for service in con.execute("SELECT exec_path, image_id FROM cba_services"):
            if service[0]:
                executable = (CORPUS / service[0]).resolve()
                assert executable.is_relative_to(CORPUS.resolve())
                assert executable.is_file()
                assert (service[1], executable.relative_to(CORPUS.resolve()).as_posix()) in manifest
    finally:
        con.close()
