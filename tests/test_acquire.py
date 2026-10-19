import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import acquire, db, firmware_diff, triage, workspace
from tests.test_hunt_prepare import assert_hunt_cleared_only, seed_hunt_state, sql_state


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
    seed_hunt_state(con, "acme|r1|target")
    before = sql_state(con)
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
    assert sql_state(con) == before


def test_acquire_refuses_active_transaction_and_preserves_caller_work(con, tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"fixed")
    con.execute("INSERT INTO cba_inventory (unit, kind) VALUES ('pending', 'file')")
    with pytest.raises(acquire.AcquireError, match="transaction"):
        acquire.record(con, vendor="acme", model="r1", version="1", role="target",
                       path=image, source="local")
    assert con.in_transaction
    assert con.execute("SELECT unit FROM cba_inventory").fetchone()[0] == "pending"


def completed_surface_pair(con, tmp_path):
    kwargs = acquired_pair(con, tmp_path)
    db.put(con, "cba_firmware_files", {
        "image_id": "acme|r1|target", "path": "bin/httpd", "kind": "binary",
        "size": 4, "sha256": "a" * 64,
    })
    db.put(con, "cba_images", {
        "id": "other|r2|target", "vendor": "other", "model": "r2",
        "version": "1", "role": "target", "path": "/other.bin", "sha256": "b" * 64,
    })
    for image_id, paths, suffix in (
            ("acme|r1|target", ("config", "bin/httpd"), "target"),
            ("other|r2|target", ("other/config",), "other")):
        if suffix == "other":
            db.put(con, "cba_firmware_files", {
                "image_id": image_id, "path": paths[0], "kind": "config",
                "size": 4, "sha256": "a" * 64,
            })
        db.put(con, "cba_surface_runs", {
            "image_id": image_id, "manifest_sha256": "c" * 64,
            "worklist_path": f"files/{suffix}/index.json", "worklist_sha256": "d" * 64,
            "unit_count": len(paths), "batch_count": 1, "status": "complete",
            "prepared_at": "2026-10-01 01:02:03", "completed_at": "2026-10-02 04:05:06",
        })
        for index, path in enumerate(paths):
            surface_id = f"surface-{index}"
            db.put(con, "cba_firmware_surfaces", {
                "image_id": image_id, "surface_id": surface_id, "component_path": path,
                "entry_point": "GET /status", "protocol": "http", "dispatch_path": "route -> handler",
                "handler": "status_handler", "lifecycle_required": "provisioned",
                "posture_required": "unknown", "auth_required": "pre-auth",
                "reachability": "evidenced", "reach_evidence": "dispatch.c:17 route -> handler",
                "artifact_path": f"files/{suffix}/result.json", "artifact_sha256": "e" * 64,
                "recorded_at": "2026-10-02 04:05:06",
            })
            db.put(con, "cba_unknowns", {
                "id": f"unknown-{suffix}-{index}", "image_id": image_id,
                "component_path": path, "surface_id": surface_id, "field": "posture",
                "question": "Does WAN traffic reach the listener?",
                "settling_observation": "Trace WAN forwarding", "method": "emulate",
                "status": "open", "artifact_path": f"files/{suffix}/result.json",
                "artifact_sha256": "e" * 64, "recorded_at": "2026-10-02 04:05:06",
            })
            for phase in ("surface", "audit"):
                unit = db.firmware_unit_key(image_id, path) if phase == "surface" else path
                db.put(con, "cba_coverage", {"unit": unit, "phase": phase, "state": "analyzed"})
    # A surface coverage unit outside either manifest must also survive.
    db.put(con, "cba_coverage", {"unit": "unrelated", "phase": "surface", "state": "analyzed"})
    return kwargs


def surface_snapshot(con):
    return {table: [tuple(row) for row in con.execute(f"SELECT * FROM {table}")]
            for table in ("cba_images", "cba_firmware_files", "cba_surface_runs",
                          "cba_firmware_surfaces", "cba_unknowns", "cba_coverage", "cba_inventory")}


@pytest.mark.parametrize("change", ["hash", "version"])
def test_changed_target_provenance_invalidates_only_its_surface_generation(con, tmp_path, change):
    kwargs = completed_surface_pair(con, tmp_path)
    before = surface_snapshot(con)
    if change == "hash":
        kwargs["target"]["path"].write_bytes(b"changed firmware")
    else:
        kwargs["target"]["version"] = "2"
    acquire.record(con, **kwargs["target"], replace=True)
    for table in ("cba_firmware_files", "cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns"):
        assert db.rows(con, table, where={"image_id": "acme|r1|target"}) == []
        assert [tuple(row) for row in con.execute(f"SELECT * FROM {table} WHERE image_id = ?",
                                                ("other|r2|target",))] == [
            row for row in before[table] if (row[1] if table == "cba_unknowns" else row[0]) == "other|r2|target"]
    assert {(row["unit"], row["phase"]) for row in db.rows(con, "cba_coverage")} == {
        ("config", "audit"), ("bin/httpd", "audit"), ("/firmware/15:other|r2|target:other/config", "surface"),
        ("other/config", "audit"), ("unrelated", "surface"),
    }
    assert surface_snapshot(con)["cba_inventory"] == before["cba_inventory"]
    assert [tuple(row) for row in con.execute("SELECT * FROM cba_firmware_files WHERE image_id = ?",
                                            ("acme|r1|diff-reference",))] == [
        row for row in before["cba_firmware_files"] if row[0] == "acme|r1|diff-reference"]
    assert not con.in_transaction


@pytest.mark.parametrize("role,change", [("target", "same"), ("diff-reference", "hash"),
                                       ("diff-reference", "version")])
def test_same_target_or_changed_reference_preserves_surface_generation(con, tmp_path, role, change):
    kwargs = completed_surface_pair(con, tmp_path)
    before = surface_snapshot(con)
    if change == "hash":
        kwargs[role]["path"].write_bytes(b"changed reference")
    elif change == "version":
        kwargs[role]["version"] = "2"
    else:
        relocated = tmp_path / "relocated.bin"
        relocated.write_bytes(b"fixed")
        kwargs[role].update(path=relocated, source="")
    acquire.record(con, **kwargs[role], replace=True)
    after = surface_snapshot(con)
    for table in ("cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns", "cba_coverage", "cba_inventory"):
        assert after[table] == before[table]
    assert [row for row in after["cba_firmware_files"] if row[0] == "acme|r1|target"] == [
        row for row in before["cba_firmware_files"] if row[0] == "acme|r1|target"]


@pytest.mark.parametrize("table", ["cba_firmware_surfaces", "cba_unknowns", "cba_surface_runs",
                                  "cba_coverage", "cba_firmware_files"])
def test_surface_invalidation_delete_failure_rolls_back_the_whole_generation(con, tmp_path, table):
    kwargs = completed_surface_pair(con, tmp_path)
    before = surface_snapshot(con)
    kwargs["target"]["path"].write_bytes(b"changed firmware")
    con.execute(f"CREATE TRIGGER fail_surface_delete BEFORE DELETE ON {table} "
                "BEGIN SELECT RAISE(FAIL, 'injected surface delete failure'); END")
    con.commit()
    with pytest.raises(sqlite3.Error, match="surface delete failure"):
        acquire.record(con, **kwargs["target"], replace=True)
    assert surface_snapshot(con) == before
    assert not con.in_transaction


def test_acquisition_refuses_ambiguous_raw_hunt_coverage_atomically(con, tmp_path):
    kwargs = completed_surface_pair(con, tmp_path)
    seed_hunt_state(con, "acme|r1|target")
    db.put(con, "cba_coverage", {"unit": "config", "phase": "hunt-l-sink", "state": "analyzed"})
    before = sql_state(con)
    kwargs["target"]["version"] = "2"
    with pytest.raises(acquire.AcquireError, match="legacy|ownership"):
        acquire.record(con, **kwargs["target"], replace=True)
    assert sql_state(con) == before
    assert not con.in_transaction


@pytest.mark.parametrize("change", ["hash", "version", "same", "reference"])
def test_acquisition_invalidates_hunts_only_for_changed_target(con, tmp_path, change):
    kwargs = completed_surface_pair(con, tmp_path)
    seed_hunt_state(con, "acme|r1|target")
    seed_hunt_state(con, "other|r2|target")
    before = sql_state(con)
    role = "diff-reference" if change == "reference" else "target"
    if change in ("hash", "reference"):
        kwargs[role]["path"].write_bytes(b"replacement image")
    elif change == "version":
        kwargs[role]["version"] = "2"
    elif change == "same":
        relocated = tmp_path / "same-provenance.bin"
        relocated.write_bytes(b"fixed")
        kwargs[role].update(path=relocated, source="new source")
    acquire.record(con, **kwargs[role], replace=True)
    if change in ("hash", "version"):
        assert_hunt_cleared_only(con, before, "acme|r1|target")
        assert not db.rows(con, "cba_surface_runs", where={"image_id": "acme|r1|target"})
    else:
        for table in ("cba_hunt_runs", "cba_hunt_receipts", "cba_hunt_candidates", "cba_coverage"):
            assert sql_state(con)[table] == before[table]


@pytest.mark.parametrize("table", ["cba_hunt_runs", "cba_hunt_receipts", "cba_hunt_candidates"])
def test_acquisition_hunt_delete_failure_rolls_back_all_owned_state(con, tmp_path, table):
    kwargs = completed_surface_pair(con, tmp_path)
    seed_hunt_state(con, "acme|r1|target")
    before = sql_state(con)
    con.execute(f"CREATE TRIGGER fail_hunt BEFORE DELETE ON {table} "
                "BEGIN SELECT RAISE(FAIL, 'hunt delete failure'); END")
    con.commit()
    kwargs["target"]["version"] = "2"
    with pytest.raises(sqlite3.Error, match="hunt delete failure"):
        acquire.record(con, **kwargs["target"], replace=True)
    assert sql_state(con) == before
    assert not con.in_transaction
