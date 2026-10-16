"""Preparation binds all assigned units to exact stored and live bytes."""
import hashlib
import json
import os
import pathlib
import sqlite3

import pytest

from audit_core import db, surface, workspace


HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


@pytest.fixture
def setup(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261014-000000")
    con = db.connect(run / "audit.db")
    root = tmp_path / "root"
    root.mkdir()
    (root / "banner").write_bytes(b"hello\n")
    yield con, run, root
    con.close()


def image(con, image_id="target", role="target"):
    db.put(con, "cba_images", {"id": image_id, "role": role, "vendor": "v",
           "model": "m", "version": "1", "path": "firmware.bin", "sha256": "a" * 64})


def manifest(con, path="banner", kind="file", size=6, digest=HELLO, image_id="target"):
    db.put(con, "cba_firmware_files", {"image_id": image_id, "path": path,
           "kind": kind, "size": str(size), "sha256": digest}, replace=True)
    db.put(con, "cba_inventory", {"unit": db.firmware_unit_key(image_id, path), "kind": kind, "size": str(size)}, replace=True)


def seed(setup):
    con, run, root = setup
    image(con)
    manifest(con)
    return con, run, root


def rows(con, table):
    return [tuple(row) for row in con.execute(f"SELECT * FROM {table} ORDER BY 1, 2")]


def artifacts(run):
    return {p.relative_to(run).as_posix(): p.read_bytes()
            for p in (run / "files/surface").rglob("*.json")}


def test_unique_and_explicit_target_resolution(setup):
    # Breaks: implicit selection requiring an ID, or explicit selection rejecting ambiguity.
    con, run, root = seed(setup)
    first = surface.prepare(con, run, root)
    assert first.image_id == "target"
    image(con, "other")
    assert surface.prepare(con, run, root, image_id="target") == first


@pytest.mark.parametrize("refusal, message", [
    ("missing", "exactly one target"), ("ambiguous", "exactly one target"),
    ("unknown", "Unknown"), ("role", "role target"),
    ("legacy", "legacy-unscoped"), ("empty", "empty"),
    ("transaction", "active transaction")])
def test_target_refusals_publish_nothing(setup, refusal, message):
    # Breaks: selecting an unsafe target or publishing before validating prerequisites.
    con, run, root = setup
    selected = None
    if refusal != "missing":
        image(con)
    if refusal == "ambiguous":
        image(con, "other")
    elif refusal == "unknown":
        selected = "absent"
    elif refusal == "role":
        image(con, "reference", "diff-reference")
        selected = "reference"
    elif refusal == "legacy":
        image(con, "legacy-unscoped")
        selected = "legacy-unscoped"
    elif refusal == "transaction":
        con.execute("BEGIN")
    with pytest.raises(surface.SurfaceError, match=message):
        surface.prepare(con, run, root, image_id=selected)
    assert rows(con, "cba_surface_runs") == []
    assert artifacts(run) == {}


def test_implicit_legacy_target_is_refused(setup):
    con, run, root = setup
    image(con, "legacy-unscoped")
    with pytest.raises(surface.SurfaceError, match="legacy-unscoped"):
        surface.prepare(con, run, root)
    assert not artifacts(run)
    assert not rows(con, "cba_surface_runs")


@pytest.mark.parametrize("field,value", [("path", "../banner"), ("kind", "bogus"),
                                        ("size", -1), ("sha256", "bad")])
def test_malformed_stored_manifest_is_refused_before_install(setup, field, value):
    # Breaks: assigning unsafe paths or invalid content identity from a damaged database.
    con, run, root = seed(setup)
    con.execute(f"UPDATE cba_firmware_files SET {field}=?", (value,))
    con.commit()
    with pytest.raises(surface.SurfaceError, match="Invalid manifest"):
        surface.prepare(con, run, root)
    assert not artifacts(run)
    assert not rows(con, "cba_surface_runs")


def test_canonical_manifest_refuses_duplicate_units():
    unit = {"path": "banner", "kind": "file", "size": 6, "sha256": HELLO}
    with pytest.raises(surface.SurfaceError, match="Duplicate manifest path"):
        surface.canonical_manifest([unit, unit])


def test_atomic_install_refuses_filename_escape(tmp_path):
    with pytest.raises(surface.SurfaceError, match="Invalid artifact filename"):
        surface.atomic_install(tmp_path / "generation", {"../escape.json": b"{}"})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("damage", ["directory-file", "directory-link", "missing", "content", "file-link"])
def test_existing_generation_damage_is_never_overwritten(setup, damage):
    # Breaks: idempotent installation trusting or overwriting a damaged generation.
    con, run, root = seed(setup)
    summary = surface.prepare(con, run, root)
    index = pathlib.Path(summary.worklist_path)
    batch = index.with_name("batch-0001.json")
    if damage in ("directory-file", "directory-link"):
        original = index.parent
        original.rename(original.with_name("saved-generation"))
        if damage == "directory-file":
            original.write_bytes(b"not a directory")
        else:
            original.symlink_to(original.with_name("saved-generation"), target_is_directory=True)
    elif damage == "missing":
        batch.unlink()
    elif damage == "content":
        batch.write_bytes(b"changed")
    else:
        saved = batch.with_name("saved.json")
        saved.write_bytes(batch.read_bytes())
        batch.unlink()
        batch.symlink_to(saved.name)
        # Keep the expected filename set: the link target can be outside the generation.
        saved.rename(run / "saved.json")
    before = rows(con, "cba_surface_runs")
    with pytest.raises(surface.SurfaceError, match="existing|Existing"):
        surface.prepare(con, run, root)
    assert rows(con, "cba_surface_runs") == before


@pytest.mark.parametrize("damage", ["missing", "index-digest", "index-provenance", "batch-path",
    "batch-digest", "batch-provenance", "batch-count", "manifest", "json"])
def test_damaged_prior_generation_refuses_replacement_and_preserves_sql(setup, damage):
    # Breaks: clearing claims without proving the exact prior unit set from bound artifacts.
    con, run, root = seed(setup)
    old = surface.prepare(con, run, root)
    claims(con)
    index_path = pathlib.Path(old.worklist_path)
    index = json.loads(index_path.read_bytes())
    batch_path = index_path.with_name("batch-0001.json")
    batch = json.loads(batch_path.read_bytes())
    if damage == "missing":
        index_path.unlink()
    elif damage == "index-digest":
        index_path.write_bytes(b"changed")
    else:
        if damage == "index-provenance":
            index["image_id"] = "other"
        elif damage == "batch-path":
            index["batches"][0]["path"] = "../outside.json"
        elif damage == "batch-digest":
            batch_path.write_bytes(b"changed")
        elif damage in ("batch-provenance", "batch-count", "manifest"):
            if damage == "batch-provenance":
                batch["image_id"] = "other"
            elif damage == "batch-count":
                index["batches"][0]["unit_count"] = 2
            else:
                batch["units"][0]["sha256"] = "b" * 64
            content = json.dumps(batch).encode()
            batch_path.write_bytes(content)
            index["batches"][0]["sha256"] = hashlib.sha256(content).hexdigest()
        content = b"bad json" if damage == "json" else json.dumps(index).encode()
        index_path.write_bytes(content)
        con.execute("UPDATE cba_surface_runs SET worklist_sha256=?", (hashlib.sha256(content).hexdigest(),))
        con.commit()
    before = {table: rows(con, table) for table in ("cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns")}
    before_files = artifacts(run)
    with pytest.raises(surface.SurfaceError, match="prior|Prior"):
        surface.prepare(con, run, root, batch_size=1)
    assert {table: rows(con, table) for table in before} == before
    assert artifacts(run) == before_files


@pytest.mark.parametrize("mutation", ["added", "removed", "content", "kind",
                                     "unreadable", "inventory", "inventory-added", "link"])
def test_root_and_inventory_disagreement_preserves_previous_generation(setup, monkeypatch, mutation):
    # Breaks: checking only paths/sizes, swallowing I/O, or skipping inventory agreement.
    con, run, root = seed(setup)
    surface.prepare(con, run, root)
    before = rows(con, "cba_surface_runs"), artifacts(run)
    if mutation == "added":
        (root / "new").write_bytes(b"x")
    elif mutation == "removed":
        (root / "banner").unlink()
    elif mutation == "content":
        (root / "banner").write_bytes(b"world\n")
    elif mutation == "kind":
        con.execute("UPDATE cba_firmware_files SET kind='config'")
        con.execute("UPDATE cba_inventory SET kind='config'")
        con.commit()
    elif mutation == "unreadable":
        original = pathlib.Path.open
        def fail(path, *args, **kwargs):
            if path == root / "banner":
                raise PermissionError("injected unreadable banner")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(pathlib.Path, "open", fail)
    elif mutation == "inventory":
        con.execute("UPDATE cba_inventory SET size=5")
        con.commit()
    elif mutation == "inventory-added":
        db.put(con, "cba_inventory", {"unit": "/firmware/6:target:extra", "kind": "file", "size": "1"})
    else:
        (root / "banner").unlink()
        (root / "banner").symlink_to(root.parent / "outside")
    with pytest.raises(surface.SurfaceError, match="banner|new|extra|inventory"):
        surface.prepare(con, run, root)
    assert (rows(con, "cba_surface_runs"), artifacts(run)) == before


@pytest.mark.parametrize("size", [0, 1001, True, 1.5])
def test_invalid_batch_size_publishes_nothing(setup, size):
    con, run, root = seed(setup)
    with pytest.raises(surface.SurfaceError, match="batch_size"):
        surface.prepare(con, run, root, batch_size=size)
    assert not artifacts(run)
    assert not rows(con, "cba_surface_runs")


def test_exact_canonical_identity_and_idempotence(setup):
    # Breaks: noncanonical bytes, host paths/timestamps in identity, resetting completed runs.
    con, run, root = seed(setup)
    result = surface.prepare(con, run, root)
    expected_manifest = ('[{"kind":"file","path":"banner","sha256":"' + HELLO +
                         '","size":6}]\n').encode()
    expected_digest = hashlib.sha256(expected_manifest).hexdigest()
    assert result.manifest_sha256 == expected_digest
    expected_batch = ('{"batch_id":"batch-0001","image_id":"target","manifest_sha256":"' +
        expected_digest + '","schema_version":1,"units":[{"kind":"file","path":"banner",' +
        '"sha256":"' + HELLO + '","size":6}]}\n').encode()
    batch_digest = hashlib.sha256(expected_batch).hexdigest()
    expected_index = ('{"batch_size":50,"batches":[{"path":"batch-0001.json","sha256":"' +
        batch_digest + '","unit_count":1}],"image_id":"target","manifest_sha256":"' +
        expected_digest + '","schema_version":1,"unit_count":1}\n').encode()
    assert pathlib.Path(result.worklist_path).read_bytes() == expected_index
    assert pathlib.Path(result.worklist_path).with_name("batch-0001.json").read_bytes() == expected_batch
    assert result.worklist_sha256 == hashlib.sha256(expected_index).hexdigest()
    assert pathlib.Path(result.worklist_path).parent == run / "files/surface" / result.worklist_sha256
    con.execute("UPDATE cba_surface_runs SET status='complete', completed_at='kept'")
    con.commit()
    before = rows(con, "cba_surface_runs"), artifacts(run)
    mtimes = {p: p.stat().st_mtime_ns for p in pathlib.Path(result.worklist_path).parent.iterdir()}
    assert surface.prepare(con, run, root) == result
    assert (rows(con, "cba_surface_runs"), artifacts(run)) == before
    assert {p: p.stat().st_mtime_ns for p in mtimes} == mtimes


def test_complete_ordered_batches_and_bounded_matching_hints(setup, monkeypatch):
    # Breaks: bounded SQL reads, hint filtering, nondeterministic traversal/query ordering.
    con, run, root = setup
    (root / "banner").unlink()
    image(con)
    for i in reversed(range(201)):
        name = f"unit-{i:03}"
        (root / name).write_bytes(b"hello\n")
        manifest(con, path=name)
    db.put(con, "cba_binfacts", {"image_id": "target", "path": "unit-000",
           "machine": "x86-64", "bits": "64", "endian": "little", "elf_type": "EXEC",
           "needed": "x" * 5000})
    db.put(con, "cba_services", {"image_id": "target", "name": "daemon",
           "exec_path": "unit-001", "start_source": "unit-002", "evidence": "x" * 5000})
    db.put(con, "cba_components", {"path": "unit-003", "kind": "binary",
           "asserted_identity": "widget", "identity_evidence": "x" * 5000})
    db.put(con, "cba_binfacts", {"image_id": "other", "path": "unit-004",
           "machine": "ignored", "bits": "64", "endian": "little", "elf_type": "EXEC"})
    result = surface.prepare(con, run, root, batch_size=50)
    index = json.loads(pathlib.Path(result.worklist_path).read_bytes())
    assert [d["unit_count"] for d in index["batches"]] == [50, 50, 50, 50, 1]
    units = []
    for n, desc in enumerate(index["batches"], 1):
        assert desc["path"] == f"batch-{n:04}.json"
        content = pathlib.Path(result.worklist_path).with_name(desc["path"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == desc["sha256"]
        units.extend(json.loads(content)["units"])
    assert [u["path"] for u in units] == [f"unit-{i:03}" for i in range(201)]
    assert units[0]["elf"]["machine"] == "x86-64"
    assert len(units[0]["elf"]["needed"]) <= 1024
    assert units[1]["services"][0]["name"] == "daemon"
    assert units[2]["services"][0]["name"] == "daemon"
    assert len(units[1]["services"][0]["evidence"]) <= 1024
    assert units[3]["component"]["asserted_identity"] == "widget"
    assert len(units[3]["component"]["identity_evidence"]) <= 1024
    assert "elf" not in units[4]
    before = artifacts(run)
    con.execute("PRAGMA reverse_unordered_selects=ON")
    from audit_core import firmware_tree
    original = firmware_tree.scan
    monkeypatch.setattr(firmware_tree, "scan", lambda path: tuple(reversed(original(path))))
    assert surface.prepare(con, run, root) == result
    assert artifacts(run) == before
    assert all(str(root).encode() not in data and b"recorded_at" not in data for data in before.values())


def claims(con, image_id="target", unit="banner"):
    # Deliberately use SQL: generation invalidation must preserve even historic rows.
    con.execute("INSERT INTO cba_firmware_surfaces (image_id,surface_id,component_path,entry_point,"
                "protocol,dispatch_path,handler,lifecycle_required,posture_required,auth_required,"
                "reachability,reach_evidence,artifact_path,artifact_sha256) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (image_id, image_id, unit, "entry", "tcp", "dispatch",
                "handler", "running", "default", "none", "reachable", "proof", "old.json", "a" * 64))
    con.execute("INSERT INTO cba_unknowns (id,image_id,component_path,field,question,settling_observation,"
                "method,status,artifact_path,artifact_sha256) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (image_id, image_id, unit, "posture", "?", "observe", "static", "open", "old.json", "a" * 64))
    con.commit()


def test_changed_generation_invalidates_only_image_and_prior_surface_units(setup):
    # Breaks: clearing other images/phases or forgetting removed old-manifest units.
    con, run, root = seed(setup)
    old = surface.prepare(con, run, root)
    claims(con)
    claims(con, "other", "elsewhere")
    for unit, phase in [("/firmware/6:target:banner", "surface"), ("banner", "audit"), ("elsewhere", "surface")]:
        db.put(con, "cba_coverage", {"unit": unit, "phase": phase, "state": "analyzed"})
    con.execute("DELETE FROM cba_firmware_files WHERE image_id='target'")
    con.execute("DELETE FROM cba_inventory")
    con.commit()
    (root / "banner").rename(root / "replacement")
    manifest(con, path="replacement")
    new = surface.prepare(con, run, root)
    assert new.worklist_sha256 != old.worklist_sha256
    assert pathlib.Path(old.worklist_path).is_file()
    assert [r[0] for r in rows(con, "cba_firmware_surfaces")] == ["other"]
    assert [r[0] for r in rows(con, "cba_unknowns")] == ["other"]
    assert [(r[0], r[1]) for r in rows(con, "cba_coverage")] == [("banner", "audit"), ("elsewhere", "surface")]
    assert con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()[0] == "pending"


def test_same_generation_refuses_inputs_changed_during_install(setup, monkeypatch):
    # Breaks: idempotent early return accepting metadata changed during artifact verification.
    con, run, root = seed(setup)
    surface.prepare(con, run, root)
    before = rows(con, "cba_surface_runs"), artifacts(run)
    original = surface.atomic_install
    def concurrent_update(destination, files):
        original(destination, files)
        with db.connect(run / "audit.db") as other:
            db.put(other, "cba_components", {"path": "banner", "kind": "config",
                   "asserted_identity": "changed", "identity_evidence": "observed concurrent metadata writer"})
    monkeypatch.setattr(surface, "atomic_install", concurrent_update)
    with pytest.raises(surface.SurfaceError, match="changed before publication"):
        surface.prepare(con, run, root)
    assert (rows(con, "cba_surface_runs"), artifacts(run)) == before
    assert not con.in_transaction


@pytest.mark.parametrize("same_generation", [False, True])
@pytest.mark.parametrize("mutation", ["content", "added", "removed", "unreadable"])
def test_root_changed_during_install_preserves_prior_sql(setup, monkeypatch, same_generation, mutation):
    # Breaks: publishing or accepting idempotence after the installed generation's root changes.
    con, run, root = seed(setup)
    old = surface.prepare(con, run, root)
    claims(con)
    db.put(con, "cba_coverage", {"unit": "/firmware/6:target:banner", "phase": "surface", "state": "analyzed"})
    con.execute("UPDATE cba_surface_runs SET status='complete', completed_at='kept'")
    con.commit()
    before = {table: rows(con, table) for table in db.TABLE_SPECS}
    old_files = artifacts(run)
    original = surface.atomic_install
    def change_root(destination, files):
        original(destination, files)
        if mutation == "content":
            (root / "banner").write_bytes(b"world\n")
        elif mutation == "added":
            (root / "new").write_bytes(b"new")
        elif mutation == "removed":
            (root / "banner").unlink()
        else:
            original_open = pathlib.Path.open
            def unreadable(path, *args, **kwargs):
                if path == root / "banner":
                    raise PermissionError("injected root read failure")
                return original_open(path, *args, **kwargs)
            monkeypatch.setattr(pathlib.Path, "open", unreadable)
    monkeypatch.setattr(surface, "atomic_install", change_root)
    with pytest.raises(surface.SurfaceError, match="Live root|injected root read"):
        surface.prepare(con, run, root, batch_size=50 if same_generation else 1)
    assert {table: rows(con, table) for table in before} == before
    assert not con.in_transaction
    assert pathlib.Path(old.worklist_path).is_file()
    assert all(artifacts(run)[path] == content for path, content in old_files.items())


@pytest.mark.parametrize("shape", ["null-unit", "string-unit", "object-units", "null-units",
    "array-index", "object-batches", "null-descriptor", "array-batch"])
def test_hash_consistent_prior_artifact_shapes_raise_surface_error(setup, shape):
    # Breaks: trusting decoded JSON shapes and leaking AttributeError or accepting malformed containers.
    con, run, root = seed(setup)
    old = surface.prepare(con, run, root)
    claims(con)
    index_path = pathlib.Path(old.worklist_path)
    index = json.loads(index_path.read_bytes())
    batch_path = index_path.with_name("batch-0001.json")
    batch = json.loads(batch_path.read_bytes())
    if shape == "array-index":
        index = []
    elif shape == "object-batches":
        index["batches"] = {}
    elif shape == "null-descriptor":
        index["batches"] = [None]
    else:
        if shape == "array-batch":
            batch = []
        else:
            batch["units"] = {"null-unit": [None], "string-unit": ["banner"],
                "object-units": {"banner": None}, "null-units": None}[shape]
        content = json.dumps(batch).encode()
        batch_path.write_bytes(content)
        index["batches"][0]["sha256"] = hashlib.sha256(content).hexdigest()
    content = json.dumps(index).encode()
    index_path.write_bytes(content)
    con.execute("UPDATE cba_surface_runs SET worklist_sha256=?", (hashlib.sha256(content).hexdigest(),))
    con.commit()
    before = {table: rows(con, table) for table in db.TABLE_SPECS}
    before_files = artifacts(run)
    with pytest.raises(surface.SurfaceError, match="prior|Prior"):
        surface.prepare(con, run, root, batch_size=1)
    assert {table: rows(con, table) for table in before} == before
    assert artifacts(run) == before_files


def test_hint_only_generation_change_invalidates_claims(setup):
    # Breaks: invalidation considering only manifest hashes despite changed assignments.
    con, run, root = seed(setup)
    old = surface.prepare(con, run, root)
    claims(con)
    db.put(con, "cba_coverage", {"unit": "/firmware/6:target:banner", "phase": "surface", "state": "analyzed"})
    db.put(con, "cba_components", {"path": "banner", "kind": "config",
           "asserted_identity": "new hint", "identity_evidence": "observed fixture configuration header"})
    new = surface.prepare(con, run, root)
    assert new.manifest_sha256 == old.manifest_sha256
    assert new.worklist_sha256 != old.worklist_sha256
    assert not rows(con, "cba_firmware_surfaces")
    assert not rows(con, "cba_unknowns")
    assert not rows(con, "cba_coverage")


@pytest.mark.parametrize("failure", ["mkdir", "write", "replace", "sql", "commit"])
def test_install_and_publication_failures_preserve_previous_sql_generation(setup, monkeypatch, failure):
    # Breaks: deleting prior claims before complete install, or nontransactional publication.
    con, run, root = seed(setup)
    surface.prepare(con, run, root)
    claims(con)
    db.put(con, "cba_coverage", {"unit": "/firmware/6:target:banner", "phase": "surface", "state": "analyzed"})
    before = {t: rows(con, t) for t in ("cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns", "cba_coverage")}
    old_files = artifacts(run)
    if failure == "mkdir":
        monkeypatch.setattr(pathlib.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("injected mkdir")))
    elif failure == "write":
        monkeypatch.setattr(pathlib.Path, "write_bytes", lambda *a, **k: (_ for _ in ()).throw(OSError("injected write")))
    elif failure == "replace":
        monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("injected replace")))
    elif failure == "sql":
        con.execute("CREATE TRIGGER fail_prepare BEFORE INSERT ON cba_surface_runs BEGIN SELECT RAISE(ABORT,'injected SQL'); END")
        con.commit()
    else:
        class CommitFailure(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError("injected commit")
        con = sqlite3.connect(run / "audit.db", factory=CommitFailure)
        con.row_factory = sqlite3.Row
    with pytest.raises(surface.SurfaceError, match="injected"):
        surface.prepare(con, run, root, batch_size=1)
    assert {t: rows(con, t) for t in before} == before
    assert not con.in_transaction
    assert all(artifacts(run)[path] == content for path, content in old_files.items())
    if failure == "commit":
        con.close()


@pytest.mark.parametrize("error_type", [RuntimeError, AssertionError])
def test_unexpected_preparation_failure_after_writes_propagates_and_rolls_back(
        setup, monkeypatch, error_type):
    # Breaks: translating programming errors or retaining any partial publication.
    con, run, root = seed(setup)
    surface.prepare(con, run, root)
    claims(con)
    db.put(con, "cba_coverage", {"unit": "/firmware/6:target:banner", "phase": "surface", "state": "analyzed"})
    con.execute("UPDATE cba_surface_runs SET status='complete',prepared_at='prepared-kept',"
                "completed_at='completed-kept'")
    con.commit()
    before = {table: rows(con, table) for table in db.TABLE_SPECS}
    failure = error_type("unexpected error after preparation writes")
    original = db.put

    def fail_after_write(connection, table, data, **kwargs):
        result = original(connection, table, data, **kwargs)
        if table == "cba_surface_runs":
            assert connection.in_transaction
            assert connection.execute("SELECT status FROM cba_surface_runs").fetchone()[0] == "pending"
            raise failure
        return result

    monkeypatch.setattr(db, "put", fail_after_write)
    with pytest.raises(error_type) as caught:
        surface.prepare(con, run, root, batch_size=1)
    assert caught.value is failure
    assert {table: rows(con, table) for table in before} == before
    assert not con.in_transaction
    with db.connect(run / "audit.db") as other:
        other.execute("BEGIN IMMEDIATE")
        other.rollback()
