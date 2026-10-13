import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import acquire, db, firmware_diff, triage, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20261009-010000")
    connection = db.connect(run / "audit.db")
    yield connection
    connection.close()


def test_record_hashes_and_stores_local_image(con, tmp_path):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware-v1\0payload")
    result = acquire.record(
        con, vendor="Acme", model="R1", version="1.0", role="target",
        path=image, source="https://vendor.example/r1.bin")
    assert result.id == "acme|r1|target"
    assert result.path == str(image)
    assert result.sha256 == hashlib.sha256(b"firmware-v1\0payload").hexdigest()
    assert result.size == 19
    row = dict(db.rows(con, "cba_images")[0])
    assert (row["vendor"], row["model"], row["version"], row["role"]) == (
        "acme", "r1", "1.0", "target")
    assert row["source"] == "https://vendor.example/r1.bin"


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_record_refuses_non_file_paths(con, tmp_path, kind):
    path = tmp_path / kind
    if kind == "directory":
        path.mkdir()
    with pytest.raises(acquire.AcquireError, match="regular readable file"):
        acquire.record(con, vendor="acme", model="r1", version="1", role="target",
                       path=path, source="local")
    assert db.rows(con, "cba_images") == []


def test_record_refuses_invalid_role(con, tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"x")
    with pytest.raises(db.DbError, match="snapshot"):
        acquire.record(con, vendor="acme", model="r1", version="1",
                       role="snapshot", path=image, source="local")


def test_duplicate_refuses_without_replace(con, tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"v1")
    kwargs = dict(vendor="acme", model="r1", version="1", role="target",
                  path=image, source="vendor.example")
    acquire.record(con, **kwargs)
    with pytest.raises(db.DbError, match="replace"):
        acquire.record(con, **kwargs)


def test_replace_changes_image_but_keeps_omitted_source(con, tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"v1")
    acquire.record(con, vendor="acme", model="r1", version="1", role="target",
                   path=image, source="vendor.example/advisory")
    image.write_bytes(b"version two")
    result = acquire.record(
        con, vendor="acme", model="r1", version="2", role="target",
        path=image, source="", replace=True)
    row = dict(db.rows(con, "cba_images")[0])
    assert row["version"] == "2"
    assert row["sha256"] == result.sha256
    assert row["source"] == "vendor.example/advisory"


def test_record_turns_a_read_race_into_acquire_error(con, tmp_path, monkeypatch):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"x")
    original = type(image).open

    def fail_open(self, *args, **kwargs):
        if self == image:
            raise OSError("vanished")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(image), "open", fail_open)
    with pytest.raises(acquire.AcquireError, match="vanished"):
        acquire.record(con, vendor="v", model="m", version="1", role="target",
                       path=image, source="local")


def acquired_pair(con, tmp_path):
    kwargs = {}
    for role, payload in (("target", b"fixed"), ("diff-reference", b"vulnerable")):
        image = tmp_path / f"{role}.bin"
        image.write_bytes(payload)
        kwargs[role] = dict(vendor="acme", model="r1", version="1", role=role,
                            path=image, source="vendor.example/advisory")
        record = acquire.record(con, **kwargs[role])
        root = tmp_path / role
        root.mkdir()
        (root / "config").write_bytes(payload)
        triage.run(con, root, image_id=record.id, allow_no_elf=True)
    return kwargs


@pytest.mark.parametrize("role", ["target", "diff-reference"])
@pytest.mark.parametrize("change", ["hash", "version"])
def test_provenance_replacement_invalidates_only_its_manifest_until_retriage(
        con, tmp_path, role, change):
    kwargs = acquired_pair(con, tmp_path)
    previous = firmware_diff.run(con, tmp_path / "diff")
    inventory = tuple(tuple(row) for row in con.execute("SELECT * FROM cba_inventory"))
    other_role = "diff-reference" if role == "target" else "target"
    other_id = f"acme|r1|{other_role}"
    other_manifest = tuple(tuple(row) for row in con.execute(
        "SELECT * FROM cba_firmware_files WHERE image_id = ?", (other_id,)))
    if change == "hash":
        kwargs[role]["path"].write_bytes(b"new firmware")
    else:
        kwargs[role]["version"] = "2"
    record = acquire.record(con, **kwargs[role], replace=True)
    assert db.rows(con, "cba_firmware_files", where={"image_id": record.id}) == []
    assert tuple(tuple(row) for row in con.execute(
        "SELECT * FROM cba_firmware_files WHERE image_id = ?", (other_id,))) == other_manifest
    assert tuple(tuple(row) for row in con.execute("SELECT * FROM cba_inventory")) == inventory
    with pytest.raises(firmware_diff.FirmwareDiffError, match="empty triage manifest"):
        firmware_diff.run(con, tmp_path / "diff", replace=True)
    assert db.rows(con, "cba_diffs")[0]["manifest_path"] == previous.manifest_path
    root = tmp_path / role
    (root / "config").write_bytes(b"freshly carved")
    triage.run(con, root, image_id=record.id, allow_no_elf=True)
    result = firmware_diff.run(con, tmp_path / "diff", replace=True)
    artifact = json.loads(pathlib.Path(result.manifest_path).read_bytes())
    metadata_key = "target_image" if role == "target" else "reference_image"
    assert artifact[metadata_key]["sha256"] == record.sha256
    assert artifact[metadata_key]["version"] == kwargs[role]["version"]
    entry = artifact["entries"][0]
    hash_key = "target_sha256" if role == "target" else "reference_sha256"
    assert entry[hash_key] == hashlib.sha256(b"freshly carved").hexdigest()


def test_identical_supplemental_replacement_keeps_manifest_and_diff_usable(con, tmp_path):
    kwargs = acquired_pair(con, tmp_path)
    before = tuple(tuple(row) for row in con.execute("SELECT * FROM cba_firmware_files"))
    same_image = tmp_path / "relocated.bin"
    same_image.write_bytes(b"fixed")
    kwargs["target"].update(path=same_image, source="")
    acquire.record(con, **kwargs["target"], replace=True)
    assert tuple(tuple(row) for row in con.execute("SELECT * FROM cba_firmware_files")) == before
    assert db.rows(con, "cba_images", where={"role": "target"})[0]["source"] == "vendor.example/advisory"
    assert firmware_diff.run(con, tmp_path / "diff").modified_count == 1


@pytest.mark.parametrize("failure", ["image-write", "manifest-delete"])
def test_replacement_failure_rolls_back_provenance_and_manifest(con, tmp_path, monkeypatch, failure):
    kwargs = acquired_pair(con, tmp_path)
    images = tuple(tuple(row) for row in con.execute("SELECT * FROM cba_images"))
    manifests = tuple(tuple(row) for row in con.execute("SELECT * FROM cba_firmware_files"))
    kwargs["target"]["path"].write_bytes(b"new firmware")
    if failure == "image-write":
        original = db.put

        def fail_after_write(connection, table, row, *, replace=False, commit=True):
            original(connection, table, row, replace=replace, commit=commit)
            raise sqlite3.OperationalError("injected replacement failure")

        monkeypatch.setattr(db, "put", fail_after_write)
    else:
        con.execute("CREATE TRIGGER fail_manifest_delete BEFORE DELETE ON cba_firmware_files "
                    "BEGIN SELECT RAISE(FAIL, 'injected replacement failure'); END")
        con.commit()
    with pytest.raises((db.DbError, sqlite3.Error), match="replacement failure"):
        acquire.record(con, **kwargs["target"], replace=True)
    assert not con.in_transaction
    assert tuple(tuple(row) for row in con.execute("SELECT * FROM cba_images")) == images
    assert tuple(tuple(row) for row in con.execute("SELECT * FROM cba_firmware_files")) == manifests


def test_acquire_refuses_active_transaction_and_preserves_caller_work(con, tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"fixed")
    con.execute("INSERT INTO cba_inventory (unit, kind) VALUES ('pending', 'file')")
    with pytest.raises(acquire.AcquireError, match="transaction"):
        acquire.record(con, vendor="acme", model="r1", version="1", role="target",
                       path=image, source="local")
    assert con.in_transaction
    assert con.execute("SELECT unit FROM cba_inventory").fetchone()[0] == "pending"
