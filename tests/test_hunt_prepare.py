"""Both hunt lanes bind a complete target denominator to verified surface evidence."""
import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, hunt, surface, surface_results, workspace


HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


def add_target(con, run, root, paths, image_id="target", *, complete=True):
    db.put(con, "cba_images", {"id": image_id, "role": "target", "vendor": "v",
        "model": "m", "version": "1", "path": "firmware.bin", "sha256": "a" * 64})
    for path in paths:
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"hello\n")
        db.put(con, "cba_firmware_files", {"image_id": image_id, "path": path,
            "kind": "file", "size": "6", "sha256": HELLO})
        db.put(con, "cba_inventory", {"unit": db.firmware_unit_key(image_id, path),
            "kind": "file", "size": "6"})
    prepared = surface.prepare(con, run, root, image_id=image_id)
    index = json.loads(pathlib.Path(prepared.worklist_path).read_bytes())
    for batch in index["batches"]:
        assigned = json.loads(pathlib.Path(prepared.worklist_path).with_name(batch["path"]).read_bytes())
        result = run / "surface-result.json"
        result.write_text(json.dumps({"schema_version": 1, "image_id": image_id,
            "manifest_sha256": prepared.manifest_sha256, "worklist_sha256": prepared.worklist_sha256,
            "batch_path": batch["path"], "batch_sha256": batch["sha256"], "decisions": [
                {"path": unit["path"], "state": "analyzed", "reason": "No dispatcher in this file.",
                 "surfaces": [], "unknowns": []} for unit in assigned["units"]]}))
        surface_results.record(con, run, result)
    if complete:
        surface.check(con, image_id=image_id)
    return prepared


@pytest.fixture
def ready(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    con = db.connect(run / "audit.db")
    root = tmp_path / "root"
    add_target(con, run, root, ["a", "b"])
    yield con, run, root
    con.close()


def sql_state(con):
    return {table: sorted([tuple(row) for row in con.execute(f"SELECT * FROM {table}")], key=repr)
            for table in db.TABLE_SPECS}


def hunt_files(run):
    return {path.relative_to(run).as_posix(): path.read_bytes()
            for path in (run / "files/hunt").rglob("*.json")}


def seed_claims(con, summary):
    for lane in summary.lanes:
        con.execute("UPDATE cba_hunt_runs SET status='complete',completed_at='retained' WHERE image_id=? AND lane=?",
                    (summary.image_id, lane.lane))
        db.put(con, "cba_hunt_receipts", {"image_id": summary.image_id, "lane": lane.lane,
            "worklist_sha256": lane.worklist_sha256, "batch_path": "batch-0001.json",
            "batch_sha256": "a" * 64, "result_path": "retained/result.json", "result_sha256": "b" * 64,
            "unit_count": "2", "candidate_count": "1"})
        # Clear ownership is the behavior under test; no result importer exists yet.
        values = {key: "retained evidence" for key in db.TABLE_SPECS["cba_hunt_candidates"].required}
        values.update(image_id=summary.image_id, lane=lane.lane, candidate_id="candidate", component_path="a",
            surface_ids="[]", blockers="[]", attacker_position="lan", lifecycle_required="provisioned",
            posture_required="sta-lan", auth_required="pre-auth", reachability="evidenced", confidence="5",
            artifact_sha256="b" * 64)
        db.put(con, "cba_hunt_candidates", values)
        for path in ("a", "b", "removed-from-current-manifest"):
            db.put(con, "cba_coverage", {"unit": db.firmware_unit_key(summary.image_id, path),
                "phase": "hunt-" + lane.lane, "state": "analyzed"})
    con.commit()


def test_unique_and_explicit_target_selection_preserves_completed_generations(ready):
    # Breaks: resetting completion on same inputs or failing explicit multi-target selection.
    con, run, root = ready
    result = hunt.prepare(con, run, root)
    assert isinstance(result, hunt.PreparationSummary)
    assert result.image_id == "target"
    assert result.surface_snapshot_sha256 == surface.verified_snapshot(con, run).snapshot_sha256
    seed_claims(con, result)
    add_target(con, run, root.parent / "other-root", ["a", "b"], image_id="other")
    before, writes = sql_state(con), con.total_changes
    assert hunt.prepare(con, run, root, image_id="target") == result
    assert sql_state(con) == before and con.total_changes == writes
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.generation = "changed"


@pytest.mark.parametrize("damage", ["no-image", "ambiguous", "unknown", "reference", "legacy",
    "no-surface", "pending", "stale", "artifact", "inventory-missing", "inventory-extra", "inventory-size"])
def test_entry_refusals_preserve_sql_and_artifacts(ready, damage):
    # Breaks: trusting completion status or accepting incomplete target/inventory ownership.
    con, run, root = ready
    hunt.prepare(con, run, root)
    image_id = None
    if damage == "no-image":
        con.execute("DELETE FROM cba_images")
    elif damage == "ambiguous":
        db.put(con, "cba_images", {"id": "other", "role": "target", "vendor": "v",
            "model": "m", "version": "1", "path": "other.bin", "sha256": "b" * 64})
    elif damage == "unknown":
        image_id = "missing"
    elif damage == "reference":
        con.execute("UPDATE cba_images SET role='diff-reference'")
        image_id = "target"
    elif damage == "legacy":
        image_id = "legacy-unscoped"
    elif damage == "no-surface":
        con.execute("DELETE FROM cba_surface_runs")
    elif damage == "pending":
        con.execute("UPDATE cba_surface_runs SET status='pending',completed_at=NULL")
    elif damage == "stale":
        con.execute("UPDATE cba_firmware_files SET sha256=? WHERE path='b'", ("b" * 64,))
    elif damage == "artifact":
        next((run / "artifacts/surface").rglob("result.json")).write_bytes(b"{}")
    elif damage == "inventory-missing":
        con.execute("DELETE FROM cba_inventory WHERE unit=?", (db.firmware_unit_key("target", "b"),))
    elif damage == "inventory-extra":
        db.put(con, "cba_inventory", {"unit": db.firmware_unit_key("target", "extra"), "kind": "file", "size": "6"})
    else:
        con.execute("UPDATE cba_inventory SET size=5")
    con.commit()
    before = sql_state(con), hunt_files(run)
    with pytest.raises(hunt.HuntError):
        hunt.prepare(con, run, root, image_id=image_id)
    assert (sql_state(con), hunt_files(run)) == before
    assert not con.in_transaction


def test_active_transaction_refusal_preserves_the_callers_work(ready):
    con, run, root = ready
    con.execute("UPDATE cba_images SET version='caller-owned'")
    before = sql_state(con), hunt_files(run)
    with pytest.raises(hunt.HuntError, match="active transaction"):
        hunt.prepare(con, run, root)
    assert (sql_state(con), hunt_files(run)) == before and con.in_transaction


@pytest.mark.parametrize("damage", ["added", "removed", "same-size", "kind", "unreadable"])
def test_live_root_must_match_before_installation(ready, monkeypatch, damage):
    # Breaks: checking only paths/sizes or publishing work despite an incomplete scan.
    con, run, root = ready
    hunt.prepare(con, run, root)
    before = sql_state(con), hunt_files(run)
    if damage == "added":
        (root / "new").write_bytes(b"x")
    elif damage == "removed":
        (root / "b").unlink()
    elif damage == "same-size":
        (root / "b").write_bytes(b"world\n")
    elif damage == "kind":
        (root / "b").write_bytes(b"#!/sh\n")
    else:
        original = pathlib.Path.open
        def denied(path, *args, **kwargs):
            if path == root / "b":
                raise PermissionError("injected unreadable file")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(pathlib.Path, "open", denied)
    with pytest.raises(hunt.HuntError):
        hunt.prepare(con, run, root)
    assert (sql_state(con), hunt_files(run)) == before


@pytest.mark.parametrize("lane_size", ["sink_batch_size", "dark_batch_size"])
@pytest.mark.parametrize("size", [0, 1001, True, 1.5])
def test_invalid_lane_batch_size_publishes_nothing(ready, lane_size, size):
    con, run, root = ready
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="1 to 1000"):
        hunt.prepare(con, run, root, **{lane_size: size})
    assert sql_state(con) == before and not hunt_files(run)


def test_201_units_get_independent_ordered_complete_deterministic_lanes(tmp_path):
    # Breaks: capped SQL, hint filtering, shared batch sizing, or unstable serialization.
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    with db.connect(run / "audit.db") as con:
        root = tmp_path / "root"
        add_target(con, run, root, [f"unit-{n:03}" for n in reversed(range(201))])
        result = hunt.prepare(con, run, root, sink_batch_size=50, dark_batch_size=73)
        assert len(result.generation) == 64
        assert [(lane.lane, lane.unit_count, lane.batch_count) for lane in result.lanes] == [
            ("l-sink", 201, 5), ("l-dark", 201, 3)]
        assert result.lanes[0].worklist_sha256 != result.lanes[1].worklist_sha256
        for lane in result.lanes:
            index_path = pathlib.Path(lane.worklist_path)
            assert index_path == run / "files/hunt" / result.generation / lane.lane / "index.json"
            index_bytes = index_path.read_bytes()
            assert hashlib.sha256(index_bytes).hexdigest() == lane.worklist_sha256
            index = json.loads(index_bytes)
            identity = {"schema_version": 1, "image_id": "target", "lane": lane.lane,
                "manifest_sha256": result.manifest_sha256,
                "surface_snapshot_sha256": result.surface_snapshot_sha256}
            assert index == identity | {"batch_size": 50 if lane.lane == "l-sink" else 73,
                "unit_count": 201, "batches": index["batches"]}
            paths = []
            for number, descriptor in enumerate(index["batches"], 1):
                data = index_path.with_name(descriptor["path"]).read_bytes()
                assert hashlib.sha256(data).hexdigest() == descriptor["sha256"]
                batch = json.loads(data)
                assert batch == identity | {"batch_id": f"batch-{number:04}", "units": batch["units"]}
                assert len(batch["units"]) == descriptor["unit_count"]
                paths.extend(unit["path"] for unit in batch["units"])
                for unit in batch["units"]:
                    assert unit == {"path": unit["path"], "kind": "file", "size": 6, "sha256": HELLO}
            assert paths == [f"unit-{n:03}" for n in range(201)]
            row = con.execute("SELECT status,completed_at,unit_count,batch_count FROM cba_hunt_runs WHERE lane=?",
                              (lane.lane,)).fetchone()
            assert tuple(row) == ("pending", None, 201, lane.batch_count)
        before, files = sql_state(con), hunt_files(run)
        con.execute("PRAGMA reverse_unordered_selects=ON")
        assert hunt.prepare(con, run, root, sink_batch_size=50, dark_batch_size=73) == result
        assert sql_state(con) == before and hunt_files(run) == files
        assert all(str(root).encode() not in content and b"recorded_at" not in content and b"prepared_at" not in content
                   for content in files.values())


def test_selected_image_hints_are_bounded_and_never_remove_hint_free_units(ready):
    # Breaks: leaking foreign-image hints, unbounded context, or dropping plain files.
    con, run, root = ready
    for image_id, machine in (("target", "MIPS"), ("foreign", "FOREIGN ELF")):
        db.put(con, "cba_binfacts", {"image_id": image_id, "path": "a", "machine": machine,
            "bits": "32", "endian": "little", "elf_type": "EXEC"})
    for n in reversed(range(25)):
        db.put(con, "cba_services", {"image_id": "target", "name": f"svc-{n:02}",
            "start_source": "a", "exec_path": "a", "evidence": "x" * 1100})
    db.put(con, "cba_services", {"image_id": "foreign", "name": "foreign-service",
        "start_source": "a", "exec_path": "a", "evidence": "FOREIGN SERVICE"})
    db.put(con, "cba_components", {"path": "a", "kind": "binary", "asserted_identity": "target component",
        "identity_evidence": "a: measured identity", "confidence": "5"})
    for diff_id, target in (("current", "target"), ("foreign", "foreign"), ("stale", "target")):
        db.put(con, "cba_diffs", {"id": diff_id, "reference_image_id": "reference", "target_image_id": target,
            "added_count": "0", "removed_count": "0", "modified_count": "1", "unchanged_count": "1",
            "manifest_path": "/host/private/diff.json"})
        db.put(con, "cba_diff_entries", {"diff_id": diff_id, "path": "a", "change": "modified",
            "reference_kind": "file", "target_kind": "file", "reference_size": "6", "target_size": "6",
            "reference_sha256": "b" * 64, "target_sha256": HELLO if diff_id != "stale" else "c" * 64})
        db.put(con, "cba_security_observations", {"group_id": "diff-" + diff_id,
            "observation": diff_id + " fix mechanism " + "x" * 1100, "location": "a:0x10"})
    stored = con.execute("SELECT worklist_path,manifest_sha256,worklist_sha256 FROM cba_surface_runs").fetchone()
    index = json.loads(pathlib.Path(stored[0]).read_bytes())
    batch = index["batches"][0]
    result_path = run / "with-surface.json"
    result_path.write_text(json.dumps({"schema_version": 1, "image_id": "target",
        "manifest_sha256": stored[1], "worklist_sha256": stored[2], "batch_path": batch["path"],
        "batch_sha256": batch["sha256"], "decisions": [
            {"path": "a", "state": "analyzed", "reason": None, "surfaces": [{
                "surface_id": "http", "component_path": "a", "entry_point": "GET /status",
                "protocol": "http", "dispatch_path": "route -> status", "handler": "status",
                "lifecycle_required": "provisioned", "posture_required": "unknown", "auth_required": "pre-auth",
                "reachability": "evidenced", "reach_evidence": "a: route before authentication"}],
             "unknowns": [{"id": "posture", "component_path": "a", "surface_id": "http", "field": "posture",
                "question": "Which interface?", "settling_observation": "Observe bind address", "method": "hardware",
                "status": "open", "resolution": None, "evidence": None}]},
            {"path": "b", "state": "analyzed", "reason": "No dispatcher", "surfaces": [], "unknowns": []}]}))
    surface_results.record(con, run, result_path, replace=True)
    surface.check(con)
    prepared = hunt.prepare(con, run, root)
    batch_bytes = pathlib.Path(prepared.lanes[0].worklist_path).with_name("batch-0001.json").read_bytes()
    units = json.loads(batch_bytes)["units"]
    assert [unit["path"] for unit in units] == ["a", "b"]
    assert units[0]["elf"]["machine"] == "MIPS"
    assert len(units[0]["services"]) == 20
    assert units[0]["services"][0]["name"] == "svc-00"
    assert len(units[0]["services"][0]["evidence"]) == 1024
    assert units[0]["component"]["asserted_identity"] == "target component"
    assert [row["surface_id"] for row in units[0]["surfaces"]] == ["http"]
    assert [row["id"] for row in units[0]["unknowns"]] == ["posture"]
    assert [row["diff_id"] for row in units[0]["diffs"]] == ["current"]
    assert len(units[0]["fix_observations"][0]["observation"]) == 1024
    assert units[0]["fix_observations"][0]["group_id"] == "diff-current"
    assert units[1] == {"path": "b", "kind": "file", "size": 6, "sha256": HELLO}
    for forbidden in (b"FOREIGN", b"foreign-service", b"stale fix", b"/host/private", b"recorded_at", str(run).encode()):
        assert forbidden not in batch_bytes
    before = hunt_files(run)
    con.execute("PRAGMA reverse_unordered_selects=ON")
    assert hunt.prepare(con, run, root) == prepared
    assert hunt_files(run) == before


def test_shared_raw_paths_do_not_borrow_globally_keyed_component_hints(ready):
    # Breaks: treating a raw global component key as selected-image provenance.
    con, run, root = ready
    add_target(con, run, root.parent / "other-root", ["a", "b"], image_id="other")
    db.put(con, "cba_components", {"path": "a", "kind": "binary", "asserted_identity": "ambiguous component",
        "identity_evidence": "a: identity has no image ownership"})
    prepared = hunt.prepare(con, run, root, image_id="target")
    for lane in prepared.lanes:
        units = json.loads(pathlib.Path(lane.worklist_path).with_name("batch-0001.json").read_bytes())["units"]
        assert [unit["path"] for unit in units] == ["a", "b"]
        assert "component" not in units[0]


def test_changed_preparation_clears_only_selected_images_hunt_state(ready):
    # Breaks: clearing one lane only, retaining removed-unit coverage, or deleting sibling state.
    con, run, root = ready
    first = hunt.prepare(con, run, root)
    seed_claims(con, first)
    other_root = root.parent / "other-root"
    add_target(con, run, other_root, ["a", "b"], image_id="a%_雪:other")
    sibling = hunt.prepare(con, run, other_root, image_id="a%_雪:other")
    seed_claims(con, sibling)
    before = sql_state(con)
    changed = hunt.prepare(con, run, root, image_id="target", dark_batch_size=1)
    assert changed.generation != first.generation
    assert changed.lanes[0].worklist_sha256 == first.lanes[0].worklist_sha256
    assert changed.lanes[1].worklist_sha256 != first.lanes[1].worklist_sha256
    for table in ("cba_hunt_receipts", "cba_hunt_candidates"):
        assert con.execute(f"SELECT count(*) FROM {table} WHERE image_id='target'").fetchone()[0] == 0
        assert [row for row in sql_state(con)[table] if row[0] == sibling.image_id] == [
            row for row in before[table] if row[0] == sibling.image_id]
    assert con.execute("SELECT count(*) FROM cba_coverage WHERE phase IN ('hunt-l-sink','hunt-l-dark') AND unit LIKE '/firmware/6:target:%'").fetchone()[0] == 0
    assert [row for row in sql_state(con)["cba_coverage"] if sibling.image_id in row[0]] == [
        row for row in before["cba_coverage"] if sibling.image_id in row[0]]
    assert all(row[8] == "pending" and row[10] is None for row in sql_state(con)["cba_hunt_runs"] if row[0] == "target")


def test_ambiguous_legacy_hunt_coverage_is_refused_and_preserved(ready):
    con, run, root = ready
    hunt.prepare(con, run, root)
    db.put(con, "cba_coverage", {"unit": "a", "phase": "hunt-l-dark", "state": "analyzed"})
    before = sql_state(con), hunt_files(run)
    with pytest.raises(hunt.HuntError, match="unqualified|legacy|ownership"):
        hunt.prepare(con, run, root, dark_batch_size=1)
    assert (sql_state(con), hunt_files(run)) == before


@pytest.mark.parametrize("change", ["root", "surface", "inventory", "hint"])
def test_publication_rechecks_inputs_under_lock(ready, monkeypatch, change):
    # Breaks: committing pre-installation inputs after a concurrent change.
    con, run, root = ready
    prior = hunt.prepare(con, run, root)
    before = sql_state(con)
    original = surface.atomic_install
    changed = False
    def install(destination, files):
        nonlocal changed
        original(destination, files)
        if changed:
            return
        changed = True
        if change == "root":
            (root / "b").write_bytes(b"world\n")
        else:
            with db.connect(run / "audit.db") as other:
                if change == "surface":
                    other.execute("UPDATE cba_surface_runs SET status='pending'")
                elif change == "inventory":
                    other.execute("DELETE FROM cba_inventory WHERE unit=?", (db.firmware_unit_key("target", "b"),))
                else:
                    db.put(other, "cba_services", {"image_id": "target", "name": "new",
                        "exec_path": "a", "start_source": "a", "evidence": "a: changed service"})
                other.commit()
    monkeypatch.setattr(surface, "atomic_install", install)
    with pytest.raises(hunt.HuntError):
        hunt.prepare(con, run, root, dark_batch_size=1)
    assert sql_state(con)["cba_hunt_runs"] == before["cba_hunt_runs"]
    assert not con.in_transaction
    assert con.execute("SELECT worklist_sha256 FROM cba_hunt_runs WHERE lane='l-sink'").fetchone()[0] == prior.lanes[0].worklist_sha256


def test_second_lane_sql_failure_rolls_back_both_lanes(ready):
    con, run, root = ready
    prior = hunt.prepare(con, run, root)
    seed_claims(con, prior)
    con.execute("CREATE TRIGGER refuse_dark BEFORE INSERT ON cba_hunt_runs WHEN NEW.lane='l-dark' BEGIN SELECT RAISE(ABORT,'injected hunt publication'); END")
    con.commit()
    before = sql_state(con)
    with pytest.raises(hunt.HuntError, match="injected hunt publication"):
        hunt.prepare(con, run, root, dark_batch_size=1)
    assert sql_state(con) == before and not con.in_transaction


def test_damaged_first_lane_during_second_lane_install_cannot_be_published(ready, monkeypatch):
    # Breaks: binding SQL to precomputed hashes without checking installed lane bytes under lock.
    con, run, root = ready
    original = surface.atomic_install
    def install(destination, files):
        original(destination, files)
        if destination.name == "l-dark":
            (destination.parent / "l-sink/batch-0001.json").write_bytes(b"corrupted during installation")
    monkeypatch.setattr(surface, "atomic_install", install)
    before = sql_state(con)
    with pytest.raises(hunt.HuntError):
        hunt.prepare(con, run, root)
    assert sql_state(con) == before and not con.in_transaction
