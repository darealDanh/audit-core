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
    assert summary == triage.TriageSummary(4, 1, 1)
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


def assert_triage_tables_empty(con):
    for table in ("cba_inventory", "cba_binfacts", "cba_services"):
        assert db.rows(con, table) == []


@pytest.mark.parametrize("allow_no_elf", [False, True])
def test_run_refuses_empty_tree_before_any_write(con, tmp_path, allow_no_elf):
    root = tmp_path / "empty-root"
    root.mkdir()
    with pytest.raises(triage.TriageError, match="no regular files"):
        triage.run(con, root, allow_no_elf=allow_no_elf)
    assert_triage_tables_empty(con)


def test_run_refuses_zero_elf_tree_without_override_before_any_write(con, tmp_path):
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "config").write_text("setting=yes\n")
    with pytest.raises(triage.TriageError, match="zero ELF"):
        triage.run(con, root)
    assert_triage_tables_empty(con)


def test_allow_no_elf_records_nonempty_tree(con, tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "README").write_text("RTOS image listing\n")
    assert triage.run(con, root, allow_no_elf=True) == triage.TriageSummary(1, 0, 0)
    assert db.rows(con, "cba_inventory", columns=("unit",))[0][0] == "README"


def service_tree(tmp_path):
    root = tmp_path / "service-root"
    for directory in ("bin", "sbin", "usr/bin", "usr/sbin", "etc/init.d", "etc/rc.d"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for executable in ("bin/core", "sbin/getty", "usr/bin/beta", "usr/sbin/alpha"):
        (root / executable).write_bytes(minimal_elf())
    (root / "etc/init.d/S20alpha").write_text(
        "#!/bin/sh\n# /usr/sbin/commented must not count\n/usr/sbin/alpha -d\n")
    (root / "etc/inittab").write_text("ttyS0::respawn:/sbin/getty -L ttyS0 115200\n")
    (root / "etc/rc.d/S30beta").write_text("#!/bin/sh\n/usr/bin/beta --start\n")
    (root / "etc/rc.local").write_text(
        "start guessed-daemon\n/usr/sbin/alpha --duplicate\n/../../outside\n")
    return root


def test_run_records_boot_services_with_exact_evidence(con, tmp_path):
    root = service_tree(tmp_path)
    db.put(con, "cba_images", {
        "id": "acme|r1|target", "vendor": "acme", "model": "r1",
        "version": "1", "role": "target", "path": "/fw.bin", "sha256": "ab"})
    summary = triage.run(con, root, image_id="acme|r1|target")
    assert summary.service_count == 3
    services = {row["name"]: dict(row) for row in db.rows(con, "cba_services")}
    assert set(services) == {"alpha", "beta", "getty"}
    assert services["alpha"]["start_source"] == "etc/init.d/S20alpha"
    assert services["alpha"]["exec_path"] == "usr/sbin/alpha"
    assert services["alpha"]["evidence"] == "/usr/sbin/alpha -d"
    assert services["alpha"]["image_id"] == "acme|r1|target"
    assert services["alpha"]["ports"] is None
    assert services["alpha"]["ports_evidence"] is None
    assert services["getty"]["evidence"] == "ttyS0::respawn:/sbin/getty -L ttyS0 115200"


def test_duplicate_service_keeps_first_sorted_source(con, tmp_path):
    root = service_tree(tmp_path)
    triage.run(con, root)
    alpha = dict(db.rows(con, "cba_services", where={"name": "alpha"})[0])
    assert alpha["start_source"] == "etc/init.d/S20alpha"
    assert alpha["evidence"] == "/usr/sbin/alpha -d"


def test_walk_skips_file_that_vanishes_before_lstat(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    vanished = root / "vanished"
    vanished.write_text("x")
    original = type(vanished).lstat

    def fail_lstat(self):
        if self == vanished:
            raise OSError("vanished")
        return original(self)

    monkeypatch.setattr(type(vanished), "lstat", fail_lstat)
    assert triage._regular_files(root) == []


def test_kind_degrades_when_file_cannot_be_opened(tmp_path, monkeypatch):
    path = tmp_path / "plain"
    path.write_text("x")
    original = type(path).open

    def fail_open(self, *args, **kwargs):
        if self == path:
            raise OSError("vanished")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(path), "open", fail_open)
    assert triage._kind(path, "plain", None) == "file"


def test_service_scan_skips_source_that_cannot_be_read(tmp_path, monkeypatch):
    root = service_tree(tmp_path)
    source = root / "etc/init.d/S20alpha"
    original = type(source).read_text

    def fail_read(self, *args, **kwargs):
        if self == source:
            raise OSError("vanished")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(source), "read_text", fail_read)
    alpha = next(row for row in triage._services(root) if row["name"] == "alpha")
    assert alpha["start_source"] == "etc/rc.local"
