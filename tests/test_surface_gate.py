"""The completion claim needs the whole denominator and intact bound evidence."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import shutil
import sqlite3

import pytest

from audit_core import acquire, coverage, db, surface, surface_results, triage, workspace


HELLO = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


def make_run(tmp_path, paths):
    run = workspace.init_run(tmp_path / "project", timestamp="20261014-000000")
    con = db.connect(run / "audit.db")
    root = tmp_path / "root"
    db.put(con, "cba_images", {"id": "target", "role": "target", "vendor": "v",
        "model": "m", "version": "1", "path": "firmware.bin", "sha256": "a" * 64})
    for path in paths:
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"hello\n")
        kind = "file"
        db.put(con, "cba_firmware_files", {"image_id": "target", "path": path,
            "kind": kind, "size": "6", "sha256": HELLO})
        db.put(con, "cba_inventory", {"unit": db.firmware_unit_key("target", path), "kind": kind, "size": "6"})
    return con, run, root


def handler(path, identifier, posture="sta-lan"):
    return {"surface_id": identifier, "component_path": path, "entry_point": "GET /status",
        "protocol": "http", "dispatch_path": "route -> status", "handler": "status",
        "lifecycle_required": "provisioned", "posture_required": posture,
        "auth_required": "pre-auth", "reachability": "evidenced",
        "reach_evidence": path + ": route calls status before authentication"}


def question(path, identifier, surface_id, status="open"):
    return {"id": identifier, "component_path": path, "surface_id": surface_id,
        "field": "posture", "question": "Is the handler available on the LAN?",
        "settling_observation": "Observe the interface bound after provisioning.",
        "method": "hardware", "status": status,
        "resolution": "LAN only" if status == "resolved" else None,
        "evidence": "bind selects LAN interface" if status == "resolved" else None}


def import_batches(con, run, summary, decisions, *, replace=False):
    index = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    artifacts = []
    for descriptor in index["batches"]:
        batch = json.loads(pathlib.Path(summary.worklist_path).with_name(descriptor["path"]).read_bytes())
        payload = {"schema_version": 1, "image_id": "target",
            "manifest_sha256": summary.manifest_sha256, "worklist_sha256": summary.worklist_sha256,
            "batch_path": descriptor["path"], "batch_sha256": descriptor["sha256"],
            "decisions": [decisions[unit["path"]] for unit in batch["units"]]}
        result = run / "result.json"
        result.write_text(json.dumps(payload), encoding="utf-8")
        artifacts.append(pathlib.Path(surface_results.record(con, run, result, replace=replace).artifact_path))
    return artifacts


@pytest.fixture
def complete_run(tmp_path):
    con, run, root = make_run(tmp_path, ["a/config.conf", "b/http", "c/relay", "d/assets"])
    summary = surface.prepare(con, run, root, batch_size=2)
    decisions = {path: {"path": path, "state": "analyzed", "reason": "No dispatch surface in this file.",
                       "surfaces": [], "unknowns": []}
                 for path in ["a/config.conf", "b/http", "c/relay", "d/assets"]}
    decisions["b/http"].update(reason=None, surfaces=[handler("b/http", "http")],
        unknowns=[question("b/http", "http-posture", "http", "resolved")])
    decisions["c/relay"].update(reason=None, surfaces=[handler("c/relay", "relay", "unknown")],
        unknowns=[question("c/relay", "relay-posture", "relay")])
    artifacts = import_batches(con, run, summary, decisions)
    yield con, run, summary, artifacts, decisions
    con.close()


@pytest.fixture
def claim_free_run(tmp_path):
    con, run, root = make_run(tmp_path, ["unit-000", "unit-001"])
    summary = surface.prepare(con, run, root, batch_size=1)
    decisions = {path: {"path": path, "state": "analyzed", "reason": "No dispatcher in this file.",
                       "surfaces": [], "unknowns": []} for path in ["unit-000", "unit-001"]}
    artifacts = import_batches(con, run, summary, decisions)
    yield con, run, summary, artifacts, decisions
    con.close()


def snapshot(con):
    return {table: sorted((tuple(row) for row in con.execute(f"SELECT * FROM {table}")), key=repr)
            for table in db.TABLE_SPECS}


def refuses_unchanged(con, *, match=None, **kwargs):
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError, match=match):
        surface.check(con, **kwargs)
    assert snapshot(con) == before
    assert not con.in_transaction


def test_complete_two_batches_accept_honest_open_unknown_and_are_idempotent(complete_run):
    # Breaks: completing during import, rejecting open questions, or resetting timestamps.
    con = complete_run[0]
    assert tuple(con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()) == ("pending", None)
    result = surface.check(con)
    assert dataclasses.asdict(result) == {"image_id": "target", "manifest_units": 4,
        "analyzed": 4, "not_audited": 0, "surfaces": 2, "open_unknowns": 1,
        "resolved_unknowns": 1, "complete": True}
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.complete = False
    status, timestamp = con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()
    assert status == "complete" and timestamp
    before = snapshot(con)
    writes = con.total_changes
    assert surface.check(con, image_id="target") == result
    assert snapshot(con) == before
    assert con.total_changes == writes


def test_verified_snapshot_is_read_only_order_independent_and_binds_results(complete_run):
    # Breaks: hashing row order, omitting claim-free evidence, or writing completion.
    con, run, summary, artifacts, _ = complete_run
    surface.check(con)
    before, writes = snapshot(con), con.total_changes
    result = surface.verified_snapshot(con, run)
    assert isinstance(result, surface.SurfaceSnapshot)
    assert (result.image_id, result.manifest_sha256, result.worklist_sha256) == (
        "target", summary.manifest_sha256, summary.worklist_sha256)
    assert result.result_evidence == tuple(sorted(
        (artifact.relative_to(run).as_posix(), hashlib.sha256(artifact.read_bytes()).hexdigest())
        for artifact in artifacts))
    assert len(result.snapshot_sha256) == 64
    con.execute("PRAGMA reverse_unordered_selects=ON")
    assert surface.verified_snapshot(con, run) == result
    assert snapshot(con) == before and con.total_changes == writes
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.image_id = "changed"


def test_verified_snapshot_ignores_timestamps_and_host_run_roots(complete_run, tmp_path):
    # Breaks: allowing host paths or volatile SQL timestamps into snapshot identity.
    con, run, *_ = complete_run
    surface.check(con)
    expected = surface.verified_snapshot(con, run)
    for table in ("cba_firmware_surfaces", "cba_unknowns"):
        con.execute(f"UPDATE {table} SET recorded_at='different time'")
    con.execute("UPDATE cba_surface_runs SET prepared_at='later',completed_at='later'")
    con.commit()
    assert surface.verified_snapshot(con, run) == expected
    relocated = tmp_path / "relocated-run"
    shutil.copytree(run, relocated)
    with db.connect(relocated / "audit.db") as moved:
        moved.execute("UPDATE cba_surface_runs SET worklist_path=replace(worklist_path,?,?)",
                      (str(run), str(relocated)))
        for table in ("cba_firmware_surfaces", "cba_unknowns"):
            moved.execute(f"UPDATE {table} SET artifact_path=replace(artifact_path,?,?)",
                          (str(run), str(relocated)))
        moved.commit()
        assert surface.verified_snapshot(moved, relocated) == expected


def test_verified_snapshot_changes_when_rechecked_result_evidence_changes(complete_run):
    # Breaks: binding only the surface worklist rather than the analyzed evidence.
    con, run, summary, _, decisions = complete_run
    surface.check(con)
    before = surface.verified_snapshot(con, run)
    changed = copy.deepcopy(decisions)
    changed["a/config.conf"]["reason"] = "Configuration read directly; no dispatcher exists."
    import_batches(con, run, summary, changed, replace=True)
    surface.check(con)
    after = surface.verified_snapshot(con, run)
    assert before.worklist_sha256 == after.worklist_sha256
    assert before.result_evidence != after.result_evidence
    assert before.snapshot_sha256 != after.snapshot_sha256


@pytest.mark.parametrize("damage", ["pending", "manifest", "result", "worklist", "wrong-run"])
def test_verified_snapshot_refuses_pending_stale_or_noncanonical_without_writes(complete_run, damage):
    # Breaks: promoting pending surface state or trusting a damaged completed run.
    con, run, summary, artifacts, _ = complete_run
    if damage != "pending":
        surface.check(con)
    if damage == "manifest":
        con.execute("UPDATE cba_firmware_files SET sha256=? WHERE path='d/assets'", ("b" * 64,))
        con.commit()
    elif damage == "result":
        artifacts[0].write_bytes(artifacts[0].read_bytes() + b" ")
    elif damage == "worklist":
        pathlib.Path(summary.worklist_path).write_bytes(b"{}")
    before, writes = snapshot(con), con.total_changes
    with pytest.raises(surface.SurfaceError):
        surface.verified_snapshot(con, run / "elsewhere" if damage == "wrong-run" else run)
    assert snapshot(con) == before and con.total_changes == writes
    if damage == "pending":
        assert surface.verified_snapshot(con, run, require_complete=False).image_id == "target"
        assert tuple(con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()) == ("pending", None)


@pytest.mark.parametrize("artifact", ["index", "batch"])
def test_verified_snapshot_refuses_hash_consistent_noncanonical_worklists(complete_run, artifact):
    # Breaks: treating valid hashes and structure as proof of canonical assignment bytes.
    con, run, summary, _, decisions = complete_run
    surface.check(con)
    old_index = pathlib.Path(summary.worklist_path)
    index = json.loads(old_index.read_bytes())
    files = {row["path"]: old_index.with_name(row["path"]).read_bytes() for row in index["batches"]}
    if artifact == "batch":
        name = index["batches"][0]["path"]
        files[name] = json.dumps(json.loads(files[name]), indent=2).encode()
        index["batches"][0]["sha256"] = hashlib.sha256(files[name]).hexdigest()
    files["index.json"] = (json.dumps(index, indent=2).encode() if artifact == "index"
                           else surface.canonical_bytes(index))
    digest = hashlib.sha256(files["index.json"]).hexdigest()
    destination = run / "files/surface" / digest
    surface.atomic_install(destination, files)
    con.execute("UPDATE cba_surface_runs SET worklist_path=?,worklist_sha256=?",
                (str(destination / "index.json"), digest))
    con.commit()
    import_batches(con, run, dataclasses.replace(summary, worklist_path=str(destination / "index.json"),
                   worklist_sha256=digest), decisions, replace=True)
    con.execute("UPDATE cba_surface_runs SET status='complete',completed_at='retained'")
    con.commit()
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError):
        surface.verified_snapshot(con, run)
    assert snapshot(con) == before


@pytest.mark.parametrize("damage", ["no-run", "wrong-role", "manifest", "prepared-manifest",
    "inventory-missing", "inventory-extra", "inventory-content", "missing-decision", "invalid-decision",
    "empty-manifest", "run-count", "run-status"])
@pytest.mark.parametrize("status", ["pending", "complete"])
def test_refused_prerequisites_preserve_status_and_timestamp(complete_run, damage, status):
    # Breaks: trusting stored completion or validating only a partial manifest/inventory.
    con = complete_run[0]
    con.execute("UPDATE cba_surface_runs SET status=?,completed_at='retained'", (status,))
    commands = {
        "no-run": "DELETE FROM cba_surface_runs",
        "wrong-role": "UPDATE cba_images SET role='diff-reference'",
        "manifest": "UPDATE cba_firmware_files SET sha256='" + "b" * 64 + "' WHERE path='d/assets'",
        "prepared-manifest": "UPDATE cba_surface_runs SET manifest_sha256='" + "b" * 64 + "'",
        "inventory-missing": "DELETE FROM cba_inventory WHERE unit='/firmware/6:target:d/assets'",
        "inventory-extra": "INSERT INTO cba_inventory(unit,kind,size) VALUES ('/firmware/6:target:extra','file',6)",
        "inventory-content": "UPDATE cba_inventory SET size=5 WHERE unit='/firmware/6:target:d/assets'",
        "missing-decision": "DELETE FROM cba_coverage WHERE unit='/firmware/6:target:d/assets' AND phase='surface'",
        "invalid-decision": "UPDATE cba_coverage SET state='skipped' WHERE unit='/firmware/6:target:d/assets'",
        "empty-manifest": "DELETE FROM cba_firmware_files",
        "run-count": "UPDATE cba_surface_runs SET unit_count=3",
        "run-status": "UPDATE cba_surface_runs SET status='bogus'"}
    con.execute(commands[damage])
    con.commit()
    refuses_unchanged(con, image_id="target")


@pytest.mark.parametrize("reason", ["budget", " \tbudget\n", "\u2003budget\u00a0"])
def test_budget_skips_cannot_hide_in_whitespace(complete_run, reason):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET state='not_audited',reason=? WHERE unit='/firmware/6:target:d/assets'", (reason,))
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("reason", [None, "", " \t\n", "guess"])
def test_not_audited_needs_a_legal_reason(complete_run, reason):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET state='not_audited',reason=? WHERE unit='/firmware/6:target:d/assets'", (reason,))
    con.commit()
    refuses_unchanged(con)


def test_honest_nonbudget_skip_passes_and_counts_exactly(complete_run):
    con, run, summary, _, decisions = complete_run
    changed = copy.deepcopy(decisions)
    changed["d/assets"].update(state="not_audited", reason=" \tgenerated\n")
    index = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    descriptor = index["batches"][1]
    payload = {"schema_version": 1, "image_id": "target", "manifest_sha256": summary.manifest_sha256,
        "worklist_sha256": summary.worklist_sha256, "batch_path": descriptor["path"],
        "batch_sha256": descriptor["sha256"], "decisions": [changed["c/relay"], changed["d/assets"]]}
    path = run / "replacement.json"
    path.write_text(json.dumps(payload))
    surface_results.record(con, run, path, replace=True)
    assert dataclasses.asdict(surface.check(con)) == {"image_id": "target", "manifest_units": 4,
        "analyzed": 3, "not_audited": 1, "surfaces": 2, "open_unknowns": 1,
        "resolved_unknowns": 1, "complete": True}


@pytest.mark.parametrize("column,value", [("lifecycle_required", "invalid"), ("posture_required", "invalid"),
    ("auth_required", "invalid"), ("reachability", "invalid"), ("reach_evidence", " \t"),
    ("handler", ""), ("surface_id", "../unsafe"), ("component_path", "absent")])
def test_invalid_or_dangling_surface_refuses(complete_run, column, value):
    con = complete_run[0]
    con.execute(f"UPDATE cba_firmware_surfaces SET {column}=? WHERE surface_id='http'", (value,))
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("column,value", [("field", "invalid"), ("method", "guess"), ("status", "closed"),
    ("id", "../unsafe"), ("question", " \n"), ("settling_observation", ""),
    ("surface_id", "absent"), ("surface_id", "http"), ("surface_id", ""),
    ("component_path", "absent"), ("resolution", "solved"), ("evidence", "proof")])
def test_invalid_or_dangling_unknown_refuses(complete_run, column, value):
    con = complete_run[0]
    con.execute(f"UPDATE cba_unknowns SET {column}=? WHERE id='relay-posture'", (value,))
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("column,value", [("resolution", None), ("evidence", " \t")])
def test_resolved_unknown_needs_resolution_and_evidence(complete_run, column, value):
    con = complete_run[0]
    con.execute(f"UPDATE cba_unknowns SET {column}=? WHERE id='http-posture'", (value,))
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("column", ["lifecycle_required", "posture_required", "auth_required", "reachability"])
def test_each_unknown_state_requires_its_matching_open_question(complete_run, column):
    con = complete_run[0]
    con.execute(f"UPDATE cba_firmware_surfaces SET {column}='unknown' WHERE surface_id='http'")
    con.commit()
    refuses_unchanged(con)


def test_deleting_the_matching_open_question_refuses(complete_run):
    con = complete_run[0]
    con.execute("DELETE FROM cba_unknowns WHERE id='relay-posture'")
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("damage", ["missing", "bytes", "hash", "path", "symlink", "directory-link",
    "valid-row-tamper", "unknown-row-tamper", "missing-unknown", "coverage-tamper"])
def test_artifact_integrity_and_sql_claim_binding_refuse(complete_run, damage):
    con, run, _, artifacts, _ = complete_run
    artifact = artifacts[0]
    if damage == "missing":
        artifact.unlink()
    elif damage == "bytes":
        artifact.write_bytes(artifact.read_bytes() + b" ")
    elif damage == "hash":
        con.execute("UPDATE cba_firmware_surfaces SET artifact_sha256=? WHERE surface_id='http'", ("b" * 64,))
    elif damage == "path":
        outside = run / "outside.json"
        outside.write_bytes(artifact.read_bytes())
        for table in ("cba_firmware_surfaces", "cba_unknowns"):
            con.execute(f"UPDATE {table} SET artifact_path=? WHERE artifact_path=?", (str(outside), str(artifact)))
    elif damage in ("symlink", "directory-link"):
        path = artifact if damage == "symlink" else artifact.parent
        saved = run / "saved-evidence"
        path.rename(saved)
        path.symlink_to(saved, target_is_directory=damage == "directory-link")
    elif damage == "valid-row-tamper":
        con.execute("UPDATE cba_firmware_surfaces SET handler='different' WHERE surface_id='http'")
    elif damage == "unknown-row-tamper":
        con.execute("UPDATE cba_unknowns SET question='Another valid question?' WHERE id='http-posture'")
    elif damage == "missing-unknown":
        # Keep linkage and known state valid: only reverse artifact matching can
        # detect the deleted resolved question while its surface remains.
        con.execute("DELETE FROM cba_unknowns WHERE id='http-posture'")
    else:
        con.execute("UPDATE cba_coverage SET reason='Different unsupported explanation' WHERE unit='/firmware/6:target:a/config.conf'")
    con.commit()
    refuses_unchanged(con, match="Stored unknowns differ" if damage == "missing-unknown" else None)


@pytest.mark.parametrize("damage", ["index-missing", "index-bytes", "batch-missing", "batch-bytes"])
def test_every_prepared_batch_is_verified(complete_run, damage):
    index = pathlib.Path(complete_run[2].worklist_path)
    path = index if damage.startswith("index") else index.with_name("batch-0002.json")
    if damage.endswith("missing"):
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b" ")
    refuses_unchanged(complete_run[0])


def test_prepared_worklist_path_needs_the_generation_structure(complete_run):
    con = complete_run[0]
    con.execute("UPDATE cba_surface_runs SET worklist_path='index.json'")
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("damage", ["empty-batches", "overlapping-batches"])
def test_hash_consistent_worklist_still_needs_the_exact_denominator(complete_run, damage):
    # Breaks: trusting digests/counts while assignments duplicate and omit units.
    con, run, summary, *_ = complete_run
    old_index = pathlib.Path(summary.worklist_path)
    index = json.loads(old_index.read_bytes())
    files = {descriptor["path"]: old_index.with_name(descriptor["path"]).read_bytes()
             for descriptor in index["batches"]}
    if damage == "empty-batches":
        index["batches"] = []
    else:
        first = json.loads(files["batch-0001.json"])
        second = json.loads(files["batch-0002.json"])
        second["units"] = first["units"]
        files["batch-0002.json"] = json.dumps(second).encode()
        index["batches"][1]["sha256"] = hashlib.sha256(files["batch-0002.json"]).hexdigest()
    content = json.dumps(index).encode()
    digest = hashlib.sha256(content).hexdigest()
    destination = run / "files/surface" / digest
    destination.mkdir()
    (destination / "index.json").write_bytes(content)
    for name, data in files.items():
        (destination / name).write_bytes(data)
    con.execute("UPDATE cba_surface_runs SET worklist_path=?,worklist_sha256=?",
                (str(destination / "index.json"), digest))
    con.commit()
    refuses_unchanged(con)


def test_hash_consistent_result_artifact_must_still_be_canonical(complete_run):
    con, run, _, artifacts, _ = complete_run
    old = artifacts[0]
    content = json.dumps(json.loads(old.read_bytes()), indent=2).encode()
    digest = hashlib.sha256(content).hexdigest()
    destination = run / "artifacts/surface" / digest
    destination.mkdir()
    artifact = destination / "result.json"
    artifact.write_bytes(content)
    for table in ("cba_firmware_surfaces", "cba_unknowns"):
        con.execute(f"UPDATE {table} SET artifact_path=?,artifact_sha256=? WHERE artifact_path=?",
                    (str(artifact), digest, str(old)))
    con.commit()
    refuses_unchanged(con)


def test_coverage_reason_cannot_be_a_sqlite_blob(complete_run):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET reason=? WHERE unit='/firmware/6:target:d/assets'", (b"generated",))
    con.commit()
    refuses_unchanged(con)


def test_a_not_audited_unit_cannot_publish_a_surface(complete_run):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET state='not_audited',reason='generated' WHERE unit='/firmware/6:target:b/http'")
    con.commit()
    refuses_unchanged(con)


def test_full_201_unit_denominator_is_counted_and_last_gap_refuses(tmp_path):
    # Breaks: using bounded db.rows or accepting a stored complete status on recheck.
    con, run, root = make_run(tmp_path, [f"unit-{n:03}" for n in range(201)])
    try:
        summary = surface.prepare(con, run, root)
        decisions = {f"unit-{n:03}": {"path": f"unit-{n:03}", "state": "analyzed",
            "reason": "No dispatch surface in this file.", "surfaces": [], "unknowns": []}
            for n in range(201)}
        artifacts = import_batches(con, run, summary, decisions)
        assert len(artifacts) == 5
        assert dataclasses.asdict(surface.check(con)) == {"image_id": "target", "manifest_units": 201,
            "analyzed": 201, "not_audited": 0, "surfaces": 0, "open_unknowns": 0,
            "resolved_unknowns": 0, "complete": True}
        con.execute("DELETE FROM cba_coverage WHERE unit='/firmware/6:target:unit-200' AND phase='surface'")
        con.commit()
        refuses_unchanged(con)
    finally:
        con.close()


@pytest.mark.parametrize("remove_artifact", [False, True])
@pytest.mark.parametrize("status", ["pending", "complete"])
def test_deleting_a_batchs_final_claims_cannot_leave_certified_coverage(complete_run, remove_artifact, status):
    # Breaks: discovering results only through surviving surface/unknown pointers.
    con, _, _, artifacts, _ = complete_run
    con.execute("UPDATE cba_surface_runs SET status=?,completed_at='retained'", (status,))
    con.execute("DELETE FROM cba_unknowns WHERE id='http-posture'")
    con.execute("DELETE FROM cba_firmware_surfaces WHERE surface_id='http'")
    con.commit()
    if remove_artifact:
        artifacts[0].unlink()
    assert tuple(con.execute("SELECT state,reason FROM cba_coverage WHERE unit='/firmware/6:target:b/http'").fetchone()) == ("analyzed", None)
    refuses_unchanged(con, match="No matching current surface result artifact for batch batch-0001.json")


def test_truly_claim_free_batches_have_complete_artifact_backed_decisions(claim_free_run):
    con = claim_free_run[0]
    assert dataclasses.asdict(surface.check(con)) == {"image_id": "target", "manifest_units": 2,
        "analyzed": 2, "not_audited": 0, "surfaces": 0, "open_unknowns": 0,
        "resolved_unknowns": 0, "complete": True}


def test_claim_free_batch_still_requires_its_result_artifact(claim_free_run):
    claim_free_run[3][0].unlink()
    refuses_unchanged(claim_free_run[0])


def test_coverage_without_any_result_directory_cannot_complete(tmp_path):
    con, run, root = make_run(tmp_path, ["unit-000"])
    try:
        surface.prepare(con, run, root)
        db.put(con, "cba_coverage", {"unit": "/firmware/6:target:unit-000", "phase": "surface", "state": "analyzed",
                                  "reason": "No dispatch surface in this file."})
        assert not (run / "artifacts/surface").exists()
        refuses_unchanged(con)
    finally:
        con.close()


@pytest.mark.parametrize("orphan", ["different-image", "old-worklist", "blank-explanation", "old-coverage",
    "malformed", "wrong-hash", "oversized", "symlink", "noncontent-addressed"])
def test_unrelated_or_nonmatching_orphan_does_not_fail_a_complete_run(claim_free_run, orphan):
    con, run, _, artifacts, _ = claim_free_run
    payload = json.loads(artifacts[0].read_bytes())
    if orphan == "different-image":
        payload["image_id"] = "reference"
    elif orphan == "old-worklist":
        payload["worklist_sha256"] = "b" * 64
    elif orphan == "blank-explanation":
        payload["decisions"][0]["reason"] = " \t"
    elif orphan == "old-coverage":
        payload["decisions"][0]["reason"] = "An outdated explanation."
    else:
        payload["decisions"][0]["reason"] = "An orphan explanation."
    content = (json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if orphan == "malformed":
        content = b"{"
    elif orphan == "oversized":
        content = b" " * (8 * 1024 * 1024 + 1)
    name = "not-a-content-address" if orphan == "noncontent-addressed" else hashlib.sha256(content).hexdigest()
    if orphan == "wrong-hash":
        name = "f" * 64
    destination = run / "artifacts/surface" / name
    destination.mkdir()
    artifact = destination / "result.json"
    if orphan == "symlink":
        artifact.symlink_to(artifacts[0])
    else:
        artifact.write_bytes(content)
    assert dataclasses.asdict(surface.check(con)) == {"image_id": "target", "manifest_units": 2,
        "analyzed": 2, "not_audited": 0, "surfaces": 0, "open_unknowns": 0,
        "resolved_unknowns": 0, "complete": True}


@pytest.mark.parametrize("remove_current", [False, True])
def test_claim_free_replacement_requires_a_matching_current_candidate(claim_free_run, remove_current):
    con, run, summary, old_artifacts, decisions = claim_free_run
    changed = copy.deepcopy(decisions)
    changed["unit-000"]["reason"] = "Revised analysis proves no dispatcher."
    current = import_batches(con, run, summary, changed, replace=True)
    assert current[0] != old_artifacts[0]
    if remove_current:
        current[0].unlink()
        refuses_unchanged(con)
    else:
        assert dataclasses.asdict(surface.check(con)) == {"image_id": "target", "manifest_units": 2,
            "analyzed": 2, "not_audited": 0, "surfaces": 0, "open_unknowns": 0,
            "resolved_unknowns": 0, "complete": True}


def test_multiple_candidates_can_match_normalized_skip_decisions(claim_free_run):
    con, run, summary, _, decisions = claim_free_run
    changed = copy.deepcopy(decisions)
    changed["unit-000"].update(state="not_audited", reason="generated")
    first = import_batches(con, run, summary, changed, replace=True)
    changed["unit-000"]["reason"] = " \tgenerated\n"
    second = import_batches(con, run, summary, changed, replace=True)
    assert first[0] != second[0]
    want = {"image_id": "target", "manifest_units": 2, "analyzed": 1, "not_audited": 1,
            "surfaces": 0, "open_unknowns": 0, "resolved_unknowns": 0, "complete": True}
    assert dataclasses.asdict(surface.check(con)) == want
    timestamp = con.execute("SELECT completed_at FROM cba_surface_runs").fetchone()[0]
    second[0].unlink()
    assert dataclasses.asdict(surface.check(con)) == want
    assert con.execute("SELECT completed_at FROM cba_surface_runs").fetchone()[0] == timestamp


def test_candidate_sql_failure_is_named_and_preserves_the_run(claim_free_run):
    con, run, *_ = claim_free_run
    before = snapshot(con)
    class CandidateReadFailure(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql.startswith("SELECT surface_id,component_path FROM cba_firmware_surfaces"):
                raise sqlite3.OperationalError("injected candidate SQL read")
            return super().execute(sql, *args, **kwargs)
    failing = sqlite3.connect(run / "audit.db", factory=CandidateReadFailure)
    try:
        with pytest.raises(surface.SurfaceError, match="injected candidate SQL read"):
            surface.check(failing)
        assert snapshot(con) == before and not failing.in_transaction
    finally:
        failing.close()


def test_candidate_directory_read_failure_is_named_and_preserves_the_run(claim_free_run, monkeypatch):
    con, run, *_ = claim_free_run
    original = pathlib.Path.iterdir
    def denied(path):
        if path == run / "artifacts/surface":
            raise PermissionError("injected candidate directory read")
        return original(path)
    monkeypatch.setattr(pathlib.Path, "iterdir", denied)
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError, match="injected candidate directory read"):
        surface.check(con)
    assert snapshot(con) == before and not con.in_transaction


def test_explicit_target_ignores_reference_claims_and_other_phases(complete_run):
    con = complete_run[0]
    db.put(con, "cba_images", {"id": "reference", "role": "diff-reference", "vendor": "v",
        "model": "m", "version": "0", "path": "reference.bin", "sha256": "b" * 64})
    con.execute("INSERT INTO cba_firmware_surfaces SELECT 'reference',surface_id,'elsewhere',entry_point,protocol,dispatch_path,handler,lifecycle_required,posture_required,auth_required,reachability,reach_evidence,'missing','invalid',recorded_at FROM cba_firmware_surfaces WHERE surface_id='http'")
    db.put(con, "cba_coverage", {"unit": "elsewhere", "phase": "surface", "state": "not_audited", "reason": "budget"})
    db.put(con, "cba_coverage", {"unit": "d/assets", "phase": "hunt", "state": "not_audited", "reason": "budget"})
    assert dataclasses.asdict(surface.check(con, image_id="target")) == {"image_id": "target", "manifest_units": 4,
        "analyzed": 4, "not_audited": 0, "surfaces": 2, "open_unknowns": 1,
        "resolved_unknowns": 1, "complete": True}


def test_sql_read_failure_is_named_and_preserves_prepared_state(complete_run):
    con, run, *_ = complete_run
    before = snapshot(con)
    class ReadFailure(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if "SELECT" in sql and "cba_firmware_files" in sql:
                raise sqlite3.OperationalError("injected gate read")
            return super().execute(sql, *args, **kwargs)
    failing = sqlite3.connect(run / "audit.db", factory=ReadFailure)
    try:
        with pytest.raises(surface.SurfaceError, match="injected gate read"):
            surface.check(failing)
        assert snapshot(con) == before
        assert not failing.in_transaction
    finally:
        failing.close()


@pytest.mark.parametrize("failure", ["update", "commit"])
def test_publication_failure_rolls_back_completion(complete_run, failure):
    con, run, *_ = complete_run
    before = snapshot(con)
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected gate commit")
    if failure == "update":
        con.execute("CREATE TRIGGER refuse_complete BEFORE UPDATE ON cba_surface_runs BEGIN SELECT RAISE(ABORT,'injected gate update'); END")
        con.commit()
        failing = con
    else:
        failing = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    try:
        with pytest.raises(surface.SurfaceError, match="injected gate"):
            surface.check(failing)
        assert snapshot(con) == before
        assert not failing.in_transaction
    finally:
        if failure == "commit":
            failing.close()


def test_caller_transaction_is_preserved(complete_run):
    con = complete_run[0]
    con.execute("UPDATE cba_surface_runs SET completed_at='caller-owned'")
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError, match="active transaction"):
        surface.check(con)
    assert snapshot(con) == before and con.in_transaction


@pytest.mark.parametrize("change", ["gap", "generation"])
def test_concurrent_inputs_are_revalidated_under_the_publication_lock(complete_run, change):
    # Breaks: marking complete using validation performed before another writer.
    con, run, *_ = complete_run
    class RacingConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == "BEGIN IMMEDIATE":
                with db.connect(run / "audit.db") as other:
                    if change == "gap":
                        other.execute("DELETE FROM cba_coverage WHERE unit='/firmware/6:target:d/assets' AND phase='surface'")
                    else:
                        other.execute("UPDATE cba_surface_runs SET prepared_at='concurrent-generation'")
                    other.commit()
            return super().execute(sql, *args, **kwargs)
    racing = sqlite3.connect(run / "audit.db", factory=RacingConnection)
    try:
        with pytest.raises(surface.SurfaceError):
            surface.check(racing)
        assert tuple(con.execute("SELECT status,completed_at FROM cba_surface_runs").fetchone()) == ("pending", None)
        if change == "gap":
            assert con.execute("SELECT COUNT(*) FROM cba_coverage WHERE phase='surface'").fetchone()[0] == 3
        else:
            assert con.execute("SELECT prepared_at FROM cba_surface_runs").fetchone()[0] == "concurrent-generation"
        assert not racing.in_transaction
    finally:
        racing.close()


def scoped_key(image_id, path):
    # Independent literal oracle: lengths count Python Unicode characters.
    return f"/firmware/{len(image_id)}:{image_id}:{path}"


def test_firmware_unit_keys_are_unambiguous_with_validator_accepted_delimiters():
    # Breaks: joining identifiers/paths without framing or normalizing their text.
    image_ids = ["a", "a:b", "a|b|target", "3:a", "/firmware/", "雪", 'a"b', "a\nb", "a%_b"]
    paths = ["shared", "b:shared", "3:a:shared", "a|b|target", "firmware/1:a:shared", "雪", 'a"b', "a\nb", "a%_b"]
    keys = set()
    for image_id in image_ids:
        for path in paths:
            # These values really pass the existing image/manifest validators.
            db.TABLE_SPECS["cba_images"].validate({"role": "target"})
            surface.canonical_manifest([{"path": path, "kind": "file", "size": 1, "sha256": "a" * 64}])
            key = db.firmware_unit_key(image_id, path)
            assert key == scoped_key(image_id, path)
            assert key not in keys and key not in paths
            keys.add(key)
            framed = key.removeprefix("/firmware/")
            count, value = framed.split(":", 1)
            assert (value[:int(count)], value[int(count) + 1:]) == (image_id, path)
    assert db.firmware_unit_key(db.FIRMWARE_IMAGE_UNSCOPED, "shared") == "shared"


@pytest.fixture
def overlapping_targets(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261016-000000")
    con = db.connect(run / "audit.db")
    targets = []
    for model, content in (("a", b"aaaa"), ("b", b"bbbb")):
        root = tmp_path / model
        root.mkdir()
        (root / "shared").write_bytes(content)
        (root / "settings").write_bytes(b"same")
        image = tmp_path / f"{model}.bin"
        image.write_bytes(content)
        args = dict(vendor="acme", model=model, version="1", role="target", path=image, source="local")
        image_id = acquire.record(con, **args).id
        triage.run(con, root, image_id=image_id, allow_no_elf=True)
        targets.append((image_id, root, args))
    yield con, run, targets
    con.close()


def import_target(con, run, summary, *, skip=False, replace=False):
    index = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    for descriptor in index["batches"]:
        batch = json.loads(pathlib.Path(summary.worklist_path).with_name(descriptor["path"]).read_bytes())
        decisions = [{"path": unit["path"], "state": "analyzed", "reason": "No dispatch in this file.",
                      "surfaces": [], "unknowns": []} for unit in batch["units"]]
        for decision in decisions:
            if decision["path"] == "shared":
                if skip:
                    decision.update(state="not_audited", reason=skip if isinstance(skip, str) else "generated")
                else:
                    decision.update(reason=None, surfaces=[handler("shared", "http")],
                        unknowns=[question("shared", summary.image_id.replace("|", "-") + "-posture", "http", "resolved")])
        payload = {"schema_version": 1, "image_id": summary.image_id,
            "manifest_sha256": summary.manifest_sha256, "worklist_sha256": summary.worklist_sha256,
            "batch_path": descriptor["path"], "batch_sha256": descriptor["sha256"], "decisions": decisions}
        path = run / "overlap-result.json"
        path.write_text(json.dumps(payload))
        surface_results.record(con, run, path, replace=replace)


def prepare_targets(overlapping_targets):
    con, run, targets = overlapping_targets
    return [surface.prepare(con, run, root, image_id=image_id)
            for image_id, root, _ in targets]


def other_image_snapshot(con, image_id):
    """Full rows and timestamps for everything outside one image's ownership."""
    result = snapshot(con)
    for table in ("cba_images", "cba_firmware_files", "cba_binfacts", "cba_services",
                  "cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns"):
        column = db.TABLE_SPECS[table].columns.index("id" if table == "cba_images" else "image_id")
        result[table] = [row for row in result[table] if row[column] != image_id]
    for table in ("cba_inventory", "cba_coverage"):
        result[table] = [row for row in result[table] if not row[0].startswith(scoped_key(image_id, ""))]
    return result


def test_explicit_triage_owns_qualified_inventory_and_retains_raw_manifest(overlapping_targets):
    # Breaks: global path upserts collapse two image inventories into one.
    con, _, targets = overlapping_targets
    assert {row[0] for row in con.execute("SELECT unit FROM cba_inventory")} == {
        scoped_key(image_id, path) for image_id, _, _ in targets for path in ("shared", "settings")}
    manifests = [tuple(row) for row in con.execute(
        "SELECT image_id,path,kind,size,sha256 FROM cba_firmware_files WHERE path='shared' ORDER BY image_id")]
    assert [row[1:4] for row in manifests] == [("shared", "file", 4)] * 2
    assert manifests[0][4] != manifests[1][4]
    sibling = other_image_snapshot(con, targets[0][0])
    triage.run(con, targets[0][1], image_id=targets[0][0], allow_no_elf=True)
    assert other_image_snapshot(con, targets[0][0]) == sibling


@pytest.mark.parametrize("different", [False, True])
def test_overlapping_first_import_replace_and_gate_are_image_owned(overlapping_targets, different):
    # Breaks: duplicate/refusal, replace, gate decision matching or totals use raw keys.
    con, run, targets = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    first, second = (target[0] for target in targets)
    import_target(con, run, summaries[0])
    surface.check(con, image_id=first)
    before = other_image_snapshot(con, second)
    import_target(con, run, summaries[1], skip=different)
    assert other_image_snapshot(con, second) == before
    checked = surface.check(con, image_id=second)
    assert (checked.manifest_units, checked.analyzed, checked.not_audited) == (2, 1 if different else 2, int(different))
    sibling = other_image_snapshot(con, second)
    import_target(con, run, summaries[1], skip=not different, replace=True)
    assert other_image_snapshot(con, second) == sibling
    assert surface.check(con, image_id=first).analyzed == 2
    assert surface.check(con, image_id=second).analyzed == (2 if different else 1)
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError, match="replace"):
        import_target(con, run, summaries[1])
    assert snapshot(con) == before
    # A sibling's identical decision cannot conceal deleted selected coverage.
    con.execute("DELETE FROM cba_coverage WHERE unit=? AND phase='surface'", (scoped_key(first, "shared"),))
    con.commit()
    refuses_unchanged(con, image_id=first, match="Missing surface coverage")
    assert surface.check(con, image_id=second).complete


@pytest.mark.parametrize("change", ["batch-size", "hint"])
def test_reprepare_preserves_overlapping_complete_sibling(overlapping_targets, change):
    # Breaks: worklist invalidation deletes sibling coverage on the same raw paths.
    con, run, targets = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    for summary in summaries:
        import_target(con, run, summary)
        surface.check(con, image_id=summary.image_id)
    selected, root, _ = targets[1]
    if change == "hint":
        db.put(con, "cba_services", {"image_id": selected, "name": "service", "start_source": "settings",
               "exec_path": "shared", "evidence": "settings starts shared"})
    before = other_image_snapshot(con, selected)
    new = surface.prepare(con, run, root, image_id=selected, batch_size=1 if change == "batch-size" else 50)
    assert new.manifest_sha256 == summaries[1].manifest_sha256
    assert new.worklist_sha256 != summaries[1].worklist_sha256
    assert other_image_snapshot(con, selected) == before
    assert not [row for row in con.execute("SELECT unit FROM cba_coverage WHERE phase='surface'")
                if row[0].startswith(scoped_key(selected, ""))]
    assert tuple(con.execute("SELECT status,completed_at FROM cba_surface_runs WHERE image_id=?", (selected,)).fetchone()) == ("pending", None)
    assert surface.check(con, image_id=targets[0][0]).complete


@pytest.mark.parametrize("change", ["hash", "version"])
def test_changed_acquisition_preserves_overlapping_complete_sibling(overlapping_targets, change):
    # Breaks: acquisition's raw manifest subquery deletes another image's decisions.
    con, run, targets = overlapping_targets
    for summary in prepare_targets(overlapping_targets):
        import_target(con, run, summary)
        surface.check(con, image_id=summary.image_id)
    selected, _, args = targets[1]
    before = other_image_snapshot(con, selected)
    inventory = snapshot(con)["cba_inventory"]
    if change == "hash":
        args["path"].write_bytes(b"new acquisition")
    else:
        args["version"] = "2"
    acquire.record(con, **args, replace=True)
    assert other_image_snapshot(con, selected) == before
    assert snapshot(con)["cba_inventory"] == inventory
    for table in ("cba_firmware_files", "cba_surface_runs", "cba_firmware_surfaces", "cba_unknowns"):
        assert not con.execute(f"SELECT 1 FROM {table} WHERE image_id=?", (selected,)).fetchone()
    assert not con.execute("SELECT 1 FROM cba_coverage WHERE unit=? AND phase='surface'", (scoped_key(selected, "shared"),)).fetchone()
    assert surface.check(con, image_id=targets[0][0]).complete


@pytest.mark.parametrize("action", ["prepare", "acquire", "replace", "retriage"])
def test_overlapping_publication_failure_rolls_back_every_table(overlapping_targets, action):
    con, run, targets = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    for summary in summaries:
        import_target(con, run, summary)
        surface.check(con, image_id=summary.image_id)
    selected, root, args = targets[1]
    before = snapshot(con)
    table = "cba_inventory" if action == "retriage" else "cba_coverage"
    operation = "INSERT" if action in ("replace", "retriage") else "DELETE"
    con.execute(f"CREATE TRIGGER fail_overlap BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'overlap rollback'); END")
    con.commit()
    with pytest.raises((surface.SurfaceError, triage.TriageError, sqlite3.Error), match="overlap rollback"):
        if action == "prepare":
            surface.prepare(con, run, root, image_id=selected, batch_size=1)
        elif action == "acquire":
            acquire.record(con, **(args | {"version": "2"}), replace=True)
        elif action == "replace":
            import_target(con, run, summaries[1], skip=True, replace=True)
        else:
            triage.run(con, root, image_id=selected, allow_no_elf=True)
    assert snapshot(con) == before
    assert not con.in_transaction


@pytest.mark.parametrize("damage", ["missing", "metadata", "extra"])
def test_inventory_agreement_requires_selected_image_not_raw_or_sibling_mirror(overlapping_targets, damage):
    con, run, targets = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    first, root, _ = targets[0]
    # A valid raw legacy mirror must never repair selected-image damage.
    db.put(con, "cba_inventory", {"unit": "shared", "kind": "file", "size": "4"})
    if damage == "missing":
        con.execute("DELETE FROM cba_inventory WHERE unit=?", (scoped_key(first, "shared"),))
    elif damage == "metadata":
        con.execute("UPDATE cba_inventory SET size=5 WHERE unit=?", (scoped_key(first, "shared"),))
    else:
        db.put(con, "cba_inventory", {"unit": scoped_key(first, "extra"), "kind": "file", "size": "4"})
    con.commit()
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError, match="inventory"):
        surface.prepare(con, run, root, image_id=first)
    assert snapshot(con) == before
    assert surface.prepare(con, run, targets[1][1], image_id=targets[1][0]) == summaries[1]


def test_overlapping_inventory_metadata_is_selected_per_image(overlapping_targets):
    con, run, targets = overlapping_targets
    first, root_a, _ = targets[0]
    second, root_b, _ = targets[1]
    before = other_image_snapshot(con, second)
    (root_b / "shared").write_bytes(b"#!/bin/sh\nexit 0\n")
    triage.run(con, root_b, image_id=second, allow_no_elf=True)
    assert other_image_snapshot(con, second) == before
    summary_a = surface.prepare(con, run, root_a, image_id=first)
    summary_b = surface.prepare(con, run, root_b, image_id=second)
    for summary, expected in ((summary_a, ("file", 4)), (summary_b, ("script", 17))):
        batch = json.loads(pathlib.Path(summary.worklist_path).with_name("batch-0001.json").read_bytes())
        unit = next(unit for unit in batch["units"] if unit["path"] == "shared")
        assert (unit["kind"], unit["size"]) == expected
        import_target(con, run, summary)
        assert surface.check(con, image_id=summary.image_id).complete


def test_qualified_decisions_retain_generic_budget_and_non_surface_accounting(overlapping_targets):
    con, run, targets = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    import_target(con, run, summaries[0], skip=" \tbudget\n")
    import_target(con, run, summaries[1])
    first = targets[0][0]
    db.put(con, "cba_inventory", {"unit": "shared", "kind": "file"})
    coverage.record(con, units=["shared"], phase="audit", state="analyzed")
    report = coverage.report(con, "surface")
    assert (report.inventoried, report.analyzed, report.not_audited, report.unrecorded, report.budget_skips) == (5, 3, 1, 1, 1)
    assert not coverage.gate(report).ok
    legacy = coverage.report(con, "audit")
    assert (legacy.analyzed, legacy.budget_skips) == (1, 0)
    refuses_unchanged(con, image_id=first, match="budget")
    assert surface.check(con, image_id=targets[1][0]).complete


@pytest.mark.parametrize("replace", [False, True])
def test_ambiguous_old_raw_surface_coverage_is_refused_and_preserved(overlapping_targets, replace):
    con, run, targets = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    db.put(con, "cba_coverage", {"unit": "shared", "phase": "surface", "state": "analyzed", "reason": "Old result"})
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError, match="unqualified|legacy|ownership"):
        import_target(con, run, summaries[0], replace=replace)
    assert snapshot(con) == before
    refuses_unchanged(con, image_id=targets[0][0], match="Missing surface coverage")
    surface.prepare(con, run, targets[0][1], image_id=targets[0][0], batch_size=1)
    acquire.record(con, **(targets[0][2] | {"version": "2"}), replace=True)
    assert snapshot(con)["cba_coverage"] == before["cba_coverage"]


@pytest.mark.parametrize("replace", [False, True])
def test_unqualified_row_arriving_during_install_cannot_be_claimed(overlapping_targets, monkeypatch, replace):
    con, run, _ = overlapping_targets
    summaries = prepare_targets(overlapping_targets)
    if replace:
        import_target(con, run, summaries[0])
    original = surface.atomic_install
    concurrent = {}
    def install_with_legacy_row(destination, files):
        original(destination, files)
        with db.connect(run / "audit.db") as other:
            db.put(other, "cba_coverage", {"unit": "shared", "phase": "surface", "state": "analyzed"})
            concurrent.update(snapshot(other))
    monkeypatch.setattr(surface, "atomic_install", install_with_legacy_row)
    with pytest.raises(surface.SurfaceError, match="Unqualified"):
        import_target(con, run, summaries[0], skip=True, replace=replace)
    assert snapshot(con) == concurrent
    assert not con.in_transaction
