"""The completion claim needs the whole denominator and intact bound evidence."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, surface, surface_results, workspace


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
        db.put(con, "cba_inventory", {"unit": path, "kind": kind, "size": "6"})
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


def import_batches(con, run, summary, decisions):
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
        artifacts.append(pathlib.Path(surface_results.record(con, run, result).artifact_path))
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


def snapshot(con):
    return {table: sorted((tuple(row) for row in con.execute(f"SELECT * FROM {table}")), key=repr)
            for table in db.TABLE_SPECS}


def refuses_unchanged(con, **kwargs):
    before = snapshot(con)
    with pytest.raises(surface.SurfaceError):
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
        "inventory-missing": "DELETE FROM cba_inventory WHERE unit='d/assets'",
        "inventory-extra": "INSERT INTO cba_inventory(unit,kind,size) VALUES ('extra','file',6)",
        "inventory-content": "UPDATE cba_inventory SET size=5 WHERE unit='d/assets'",
        "missing-decision": "DELETE FROM cba_coverage WHERE unit='d/assets' AND phase='surface'",
        "invalid-decision": "UPDATE cba_coverage SET state='skipped' WHERE unit='d/assets'",
        "empty-manifest": "DELETE FROM cba_firmware_files",
        "run-count": "UPDATE cba_surface_runs SET unit_count=3",
        "run-status": "UPDATE cba_surface_runs SET status='bogus'"}
    con.execute(commands[damage])
    con.commit()
    refuses_unchanged(con, image_id="target")


@pytest.mark.parametrize("reason", ["budget", " \tbudget\n", "\u2003budget\u00a0"])
def test_budget_skips_cannot_hide_in_whitespace(complete_run, reason):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET state='not_audited',reason=? WHERE unit='d/assets'", (reason,))
    con.commit()
    refuses_unchanged(con)


@pytest.mark.parametrize("reason", [None, "", " \t\n", "guess"])
def test_not_audited_needs_a_legal_reason(complete_run, reason):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET state='not_audited',reason=? WHERE unit='d/assets'", (reason,))
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
    "valid-row-tamper", "unknown-row-tamper", "missing-surface", "coverage-tamper"])
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
    elif damage == "missing-surface":
        con.execute("DELETE FROM cba_firmware_surfaces WHERE surface_id='http'")
    else:
        con.execute("UPDATE cba_coverage SET reason='Different unsupported explanation' WHERE unit='a/config.conf'")
    con.commit()
    refuses_unchanged(con)


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
    con.execute("UPDATE cba_coverage SET reason=? WHERE unit='d/assets'", (b"generated",))
    con.commit()
    refuses_unchanged(con)


def test_a_not_audited_unit_cannot_publish_a_surface(complete_run):
    con = complete_run[0]
    con.execute("UPDATE cba_coverage SET state='not_audited',reason='generated' WHERE unit='b/http'")
    con.commit()
    refuses_unchanged(con)


def test_full_201_unit_denominator_is_counted_and_last_gap_refuses(tmp_path):
    # Breaks: using bounded db.rows or accepting a stored complete status on recheck.
    con, run, root = make_run(tmp_path, [f"unit-{n:03}" for n in range(201)])
    try:
        surface.prepare(con, run, root)
        for n in range(201):
            db.put(con, "cba_coverage", {"unit": f"unit-{n:03}", "phase": "surface",
                "state": "analyzed", "reason": "No dispatch surface in this file."})
        assert dataclasses.asdict(surface.check(con)) == {"image_id": "target", "manifest_units": 201,
            "analyzed": 201, "not_audited": 0, "surfaces": 0, "open_unknowns": 0,
            "resolved_unknowns": 0, "complete": True}
        con.execute("DELETE FROM cba_coverage WHERE unit='unit-200' AND phase='surface'")
        con.commit()
        refuses_unchanged(con)
    finally:
        con.close()


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
                        other.execute("DELETE FROM cba_coverage WHERE unit='d/assets' AND phase='surface'")
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
