import hashlib
import os
import pathlib
import sqlite3
import struct

import pytest

from audit_core import db, firmware_tree, triage, workspace
from tests.test_hunt_prepare import FP_TABLES, assert_fp_state, seed_fp_state
from tests.test_hunt_prepare import add_target, assert_hunt_cleared_only, seed_hunt_state, sql_state


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
    assert facts["image_id"] == "legacy-unscoped"
    service = dict(db.rows(con, "cba_services")[0])
    assert service["image_id"] == "legacy-unscoped"


def test_run_is_idempotent(con, tmp_path):
    root = carved_tree(tmp_path)
    assert triage.run(con, root) == triage.run(con, root)
    assert len(db.rows(con, "cba_inventory")) == 4
    assert len(db.rows(con, "cba_binfacts")) == 1
    assert len(db.rows(con, "cba_services")) == 1
    assert len(db.rows(con, "cba_firmware_files")) == 4


@pytest.mark.parametrize("scope", ["changed", "same", "reference", "legacy"])
def test_triage_manifest_changes_invalidate_only_target_dependencies(con, tmp_path, scope):
    run = pathlib.Path(con.execute("PRAGMA database_list").fetchone()[2]).parent
    root = tmp_path / "target"
    add_target(con, run, root, ["a", "b"])
    add_target(con, run, tmp_path / "other", ["a", "b"], image_id="other")
    seed_hunt_state(con, "target")
    seed_hunt_state(con, "other")
    if scope == "reference":
        db.put(con, "cba_images", {"id": "ref", "role": "diff-reference", "vendor": "v",
            "model": "m", "version": "1", "path": "ref.bin", "sha256": "b" * 64})
    before = sql_state(con)
    if scope != "same":
        (root / "a").write_bytes(b"world\n")
    image_id = {"reference": "ref", "legacy": None}.get(scope, "target")
    triage.run(con, root, image_id=image_id, allow_no_elf=True)
    if scope == "changed":
        assert_hunt_cleared_only(con, before, "target")
        assert not db.rows(con, "cba_surface_runs", where={"image_id": "target"})
        assert not [r for r in db.rows(con, "cba_coverage") if r[1] == "surface" and r[0].startswith("/firmware/6:target:")]
    else:
        for table in ("cba_surface_runs", "cba_hunt_runs", "cba_hunt_receipts", "cba_hunt_candidates", "cba_coverage"):
            assert sql_state(con)[table] == before[table]


@pytest.mark.parametrize("failure", ["hunt-delete", "manifest-insert", "commit", "ambiguous"])
def test_triage_hunt_failure_rolls_back_manifest_and_dependents(con, tmp_path, failure):
    run = pathlib.Path(con.execute("PRAGMA database_list").fetchone()[2]).parent
    root = tmp_path / "target"
    add_target(con, run, root, ["a", "b"])
    seed_hunt_state(con, "target")
    if failure == "ambiguous":
        db.put(con, "cba_coverage", {"unit": "a", "phase": "hunt-l-sink", "state": "analyzed"})
    elif failure != "commit":
        event, table = ("DELETE", "cba_hunt_runs") if failure == "hunt-delete" else ("INSERT", "cba_firmware_files")
        con.execute(f"CREATE TRIGGER fail_hunt BEFORE {event} ON {table} "
                    "BEGIN SELECT RAISE(FAIL, 'injected publication failure'); END")
        con.commit()
    else:
        class CommitFailure(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError("injected commit failure")
        con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
        con.row_factory = sqlite3.Row
    before = sql_state(con)
    (root / "a").write_bytes(b"world\n")
    try:
        with pytest.raises(triage.TriageError, match="legacy|failure"):
            triage.run(con, root, image_id="target", allow_no_elf=True)
        assert sql_state(con) == before
        assert not con.in_transaction
    finally:
        if failure == "commit":
            con.close()


def test_manifest_records_exact_regular_file_identity(con, tmp_path):
    root = carved_tree(tmp_path)
    (root / "linked-directory").symlink_to(root / "usr", target_is_directory=True)
    triage.run(con, root)
    rows = {row["path"]: (row["image_id"], row["kind"], row["size"], row["sha256"])
            for row in db.rows(con, "cba_firmware_files")}
    assert rows == {
        "bin/httpd": ("legacy-unscoped", "binary", 64,
                      "51224867e5fb13d0c6052397c9f4959c7"
                      "c87bb8bc7d750c91429728a18b507d9"),
        "etc/httpd.conf": ("legacy-unscoped", "config", 8,
                           "8ac56ba2b165fcd437ca405ef420a36cc"
                           "bda0f41ce603a07db42752ff00335a2"),
        "etc/init.d/S50httpd": ("legacy-unscoped", "script", 21,
                                "db21b439bed93b3f035f8cb41ef06cd7"
                                "c68dfe9cfe306b67173199f295993c3f"),
        "usr/share/banner": ("legacy-unscoped", "file", 6,
                             "5891b5b522d5df086d0ff0b110fbd9d21"
                             "bb4fc7163af34d08286a2e846f6be03"),
    }


def test_target_and_reference_keep_facts_without_changing_inventory(con, tmp_path):
    target_parent = tmp_path / "target"
    reference_parent = tmp_path / "reference"
    target_parent.mkdir()
    reference_parent.mkdir()
    target = carved_tree(target_parent)
    reference = carved_tree(reference_parent)
    (reference / "bin/httpd").write_bytes(minimal_elf() + b"reference")
    (reference / "usr/share/reference-only").write_text("reference-only\n")
    for image_id, role in (("target", "target"), ("reference", "diff-reference")):
        db.put(con, "cba_images", {
            "id": image_id, "vendor": "acme", "model": "r1", "version": "1",
            "role": role, "path": f"/{image_id}.bin", "sha256": image_id})
    assert triage.run(con, target, image_id="target") == triage.TriageSummary(4, 1, 1)
    # Include timestamps and every optional field in the byte-for-byte snapshot.
    inventory = tuple(tuple(row) for row in con.execute(
        "SELECT * FROM cba_inventory ORDER BY unit"))
    assert triage.run(con, reference, image_id="reference") == triage.TriageSummary(5, 1, 1)
    assert tuple(tuple(row) for row in con.execute(
        "SELECT * FROM cba_inventory ORDER BY unit")) == inventory
    for table, key, value in (("cba_firmware_files", "path", "bin/httpd"),
                              ("cba_binfacts", "path", "bin/httpd"),
                              ("cba_services", "name", "httpd")):
        rows = db.rows(con, table, where={key: value})
        assert {row["image_id"] for row in rows} == {"target", "reference"}
    assert triage.run(con, reference, image_id="reference") == triage.TriageSummary(5, 1, 1)
    assert len(db.rows(con, "cba_firmware_files")) == 9
    assert len(db.rows(con, "cba_binfacts")) == 2
    assert len(db.rows(con, "cba_services")) == 2


def test_each_regular_file_is_hashed_once_and_elf_digest_is_reused(con, tmp_path, monkeypatch):
    root = carved_tree(tmp_path)
    hashed = []
    original = firmware_tree._sha256

    def record_hash(path):
        hashed.append(path.relative_to(root).as_posix())
        return original(path)

    monkeypatch.setattr(firmware_tree, "_sha256", record_hash)
    triage.run(con, root)
    assert sorted(hashed) == ["bin/httpd", "etc/httpd.conf", "etc/init.d/S50httpd",
                              "usr/share/banner"]
    manifest = db.rows(con, "cba_firmware_files", where={"path": "bin/httpd"})[0]
    assert db.rows(con, "cba_binfacts")[0]["sha256"] == manifest["sha256"]


@pytest.mark.parametrize("prior", [False, True])
def test_scanner_hash_failure_preserves_all_triage_rows_and_timestamps(
        con, tmp_path, monkeypatch, prior):
    root = carved_tree(tmp_path)
    if prior:
        triage.run(con, root)
        (root / "bin/httpd").write_bytes(minimal_elf() + b"changed")
    before = triage_snapshot(con)
    original = firmware_tree._sha256

    def fail_last_hash(path):
        if path.relative_to(root).as_posix() == "usr/share/banner":
            raise OSError("file vanished while hashing")
        return original(path)

    monkeypatch.setattr(firmware_tree, "_sha256", fail_last_hash)
    with pytest.raises(triage.TriageError, match="vanished while hashing"):
        triage.run(con, root)
    assert triage_snapshot(con) == before
    assert not con.in_transaction
    if not prior:
        assert_triage_tables_empty(con)


def test_triage_publishes_identity_from_shared_scan_without_rereading(con, tmp_path, monkeypatch):
    # Breaks: rehashing/reclassifying files after the shared scan returned.
    root = carved_tree(tmp_path)
    facts = firmware_tree.scan(root)
    (root / "usr/share/banner").write_bytes(b"#!/bin/sh\nchanged\n")
    monkeypatch.setattr(firmware_tree, "scan", lambda path: facts)
    assert triage.run(con, root) == triage.TriageSummary(4, 1, 1)
    row = db.rows(con, "cba_firmware_files", where={"path": "usr/share/banner"})[0]
    assert (row["kind"], row["size"], row["sha256"]) == (
        "file", 6, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")


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
    for table in ("cba_inventory", "cba_binfacts", "cba_services",
                  "cba_firmware_files"):
        assert db.rows(con, table) == []


def triage_snapshot(con):
    return tuple(tuple(tuple(row) for row in con.execute(
        f"SELECT * FROM {table} ORDER BY 1, 2")) for table in (
            "cba_firmware_files", "cba_binfacts", "cba_services", "cba_inventory"))


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize("failure_table", [
    "cba_firmware_files", "cba_binfacts", "cba_services", "cba_inventory"])
def test_publication_failure_after_real_write_preserves_all_prior_rows(
        con, tmp_path, monkeypatch, prior, failure_table):
    root = carved_tree(tmp_path)
    if prior:
        triage.run(con, root)
        (root / "bin/httpd").write_bytes(minimal_elf() + b"changed")
        (root / "etc/init.d/S50httpd").write_text("#!/bin/sh\n/bin/httpd --changed\n")
    before = triage_snapshot(con)
    original = db.put

    def fail_after_write(connection, table, row, *, replace=False, commit=True):
        original(connection, table, row, replace=replace, commit=commit)
        if table == failure_table:
            raise sqlite3.OperationalError("injected publication failure")

    monkeypatch.setattr(db, "put", fail_after_write)
    with pytest.raises((triage.TriageError, sqlite3.Error), match="publication failure"):
        triage.run(con, root)
    assert not con.in_transaction
    assert triage_snapshot(con) == before


def test_triage_refuses_active_transaction_and_preserves_caller_work(con, tmp_path):
    root = carved_tree(tmp_path)
    con.execute("INSERT INTO cba_inventory (unit, kind) VALUES ('pending', 'file')")
    with pytest.raises(triage.TriageError, match="transaction"):
        triage.run(con, root)
    assert con.in_transaction
    assert con.execute("SELECT unit FROM cba_inventory").fetchone()[0] == "pending"


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize("failure", ["file-permission", "file-io", "subtree",
                                     "subtree-iteration", "directory-stat"])
def test_traversal_failure_with_readable_siblings_preserves_prior_publication(
        con, tmp_path, monkeypatch, prior, failure):
    root = carved_tree(tmp_path)
    if prior:
        triage.run(con, root)
        (root / "bin/httpd").write_bytes(minimal_elf() + b"changed")
    before = triage_snapshot(con)
    blocked = (root / "usr" if failure in ("subtree", "subtree-iteration", "directory-stat")
               else root / "usr/share/banner")
    if failure in ("subtree", "subtree-iteration"):
        original = os.scandir

        class FailingIterator:
            def __init__(self, path):
                self.iterator = original(path)

            def __enter__(self):
                self.iterator.__enter__()
                return self

            def __exit__(self, *args):
                return self.iterator.__exit__(*args)

            def __iter__(self):
                return self

            def __next__(self):
                next(self.iterator)
                raise OSError("injected subtree iteration failure")

        def fail_scandir(path):
            if str(path) == str(blocked):
                if failure == "subtree-iteration":
                    return FailingIterator(path)
                raise PermissionError("injected subtree permission failure")
            return original(path)

        monkeypatch.setattr(os, "scandir", fail_scandir)
    else:
        original = type(root).lstat

        def fail_lstat(path):
            if path == blocked:
                error = OSError if failure == "file-io" else PermissionError
                raise error("injected stat failure")
            return original(path)

        monkeypatch.setattr(type(root), "lstat", fail_lstat)
    with pytest.raises(triage.TriageError, match="injected"):
        triage.run(con, root)
    assert triage_snapshot(con) == before
    assert not con.in_transaction


@pytest.mark.parametrize("prior", [False, True])
@pytest.mark.parametrize("failure", ["error", "mismatch"])
def test_directory_classification_error_preserves_all_publication_tables(
        con, tmp_path, monkeypatch, prior, failure):
    root = carved_tree(tmp_path)
    (root / "audit_core").mkdir()
    (root / "audit_core/hidden").write_bytes(minimal_elf())
    (root / "audit.py").write_text("readable sibling\n")
    if prior:
        triage.run(con, root)
        (root / "bin/httpd").write_bytes(minimal_elf() + b"changed")
        (root / "audit.py").write_text("changed readable sibling\n")
    before = triage_snapshot(con)
    original = os.scandir

    class EntryProxy:
        def __init__(self, entry):
            self.entry = entry

        def __getattr__(self, name):
            return getattr(self.entry, name)

        def is_dir(self, *, follow_symlinks=True):
            if self.entry.path == str(root / "audit_core"):
                if failure == "mismatch":
                    return False
                raise OSError("injected directory classification failure")
            return self.entry.is_dir(follow_symlinks=follow_symlinks)

    class ScandirProxy:
        def __init__(self, path):
            self.iterator = original(path)

        def __enter__(self):
            self.iterator.__enter__()
            return self

        def __exit__(self, *args):
            return self.iterator.__exit__(*args)

        def __iter__(self):
            return self

        def __next__(self):
            return EntryProxy(next(self.iterator))

    monkeypatch.setattr(os, "scandir", ScandirProxy)
    with pytest.raises(triage.TriageError, match="classif"):
        triage.run(con, root)
    assert triage_snapshot(con) == before
    assert not con.in_transaction


def test_regular_files_are_sorted_and_exclude_links_and_nonregular_entries(tmp_path):
    root = carved_tree(tmp_path)
    (root / "linked-directory").symlink_to(root / "usr", target_is_directory=True)
    (root / "missing-link").symlink_to("missing")
    (root / "z-last").write_text("last\n")
    (root / "a-first").write_text("first\n")
    os.mkfifo(root / "pipe")
    assert [fact.relative for fact in firmware_tree.scan(root)] == [
        "a-first", "bin/httpd", "etc/httpd.conf", "etc/init.d/S50httpd",
        "usr/share/banner", "z-last",
    ]


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


def test_walk_refuses_file_that_vanishes_before_lstat(tmp_path, monkeypatch):
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
    with pytest.raises(firmware_tree.FirmwareTreeError, match="vanished"):
        firmware_tree.scan(root)


def test_triage_refuses_file_that_cannot_be_opened(con, tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    path = root / "plain"
    path.write_text("x")
    original = type(path).open

    def fail_open(self, *args, **kwargs):
        if self == path:
            raise OSError("vanished")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(path), "open", fail_open)
    with pytest.raises(triage.TriageError, match="vanished"):
        triage.run(con, root, allow_no_elf=True)
    assert_triage_tables_empty(con)


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


def test_service_scan_rejects_non_startup_path_references(tmp_path):
    root = tmp_path / "root"
    for directory in ("bin", "etc/init.d"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "bin/core").write_bytes(minimal_elf())
    (root / "etc/passwd").write_text("root:x:0:0\n")
    (root / "etc/service.conf").write_text("enabled=1\n")
    (root / "etc/init.d/S10noise").write_text(
        "CONF=/etc/service.conf\n"
        "procd_add_jail_mount /etc/passwd\n"
        "echo /bin/core\n"
        "cat /etc/service.conf\n"
        "true # /bin/core\n"
        ". /bin/core\n"
        "/bin/core --stop\n")

    assert triage._services(root) == []


def test_service_scan_does_not_follow_symlinked_boot_directory(tmp_path):
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "bin/core").write_bytes(minimal_elf())
    outside = tmp_path / "outside-init"
    outside.mkdir()
    (outside / "S10core").write_text("/bin/core\n")
    (root / "etc/init.d").symlink_to(outside, target_is_directory=True)

    assert triage._services(root) == []


def test_service_scan_handles_start_stop_daemon_conservatively(tmp_path):
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "etc/init.d").mkdir(parents=True)
    (root / "bin/core").write_bytes(minimal_elf())
    (root / "etc/init.d/S10core").write_text(
        "start-stop-daemon --exec /bin/core\n"
        "start-stop-daemon --start\n"
        "start-stop-daemon -S -x /bin/core\n")

    services = triage._services(root)

    assert [service["name"] for service in services] == ["core"]
    assert services[0]["evidence"] == "start-stop-daemon -S -x /bin/core"


@pytest.mark.parametrize("scope", ["changed", "same", "reference"])
def test_triage_invalidates_only_changed_target_review(con, tmp_path, scope):
    run = pathlib.Path(con.execute("PRAGMA database_list").fetchone()[2]).parent
    root = tmp_path / "root"
    add_target(con, run, root, ["a", "b"])
    db.put(con, "cba_images", {"id": "ref", "role": "diff-reference", "vendor": "v",
        "model": "m", "version": "1", "path": "ref.bin", "sha256": "b" * 64})
    seed_fp_state(con, "target")
    seed_fp_state(con, "target:雪%_|")
    before = sql_state(con)
    if scope != "same":
        (root / "a").write_bytes(b"changed")
    triage.run(con, root, image_id="ref" if scope == "reference" else "target", allow_no_elf=True)
    assert_fp_state(con, before, "target", cleared=scope == "changed")


@pytest.mark.parametrize("table", FP_TABLES)
def test_triage_review_delete_failure_rolls_back_manifest_and_dependents(con, tmp_path, table):
    run = pathlib.Path(con.execute("PRAGMA database_list").fetchone()[2]).parent
    root = tmp_path / "root"
    add_target(con, run, root, ["a", "b"])
    seed_fp_state(con, "target")
    before = sql_state(con)
    con.execute(f"CREATE TRIGGER fail_review BEFORE DELETE ON {table} "
                "BEGIN SELECT RAISE(FAIL, 'review delete failure'); END")
    con.commit()
    (root / "a").write_bytes(b"changed")
    with pytest.raises(triage.TriageError, match="review delete failure"):
        triage.run(con, root, image_id="target", allow_no_elf=True)
    assert sql_state(con) == before and not con.in_transaction
