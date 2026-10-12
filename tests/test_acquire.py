import hashlib

import pytest

from audit_core import acquire, db, workspace


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
