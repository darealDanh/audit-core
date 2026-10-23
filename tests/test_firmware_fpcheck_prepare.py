"""Stage 4f consumes a complete, immutable and read-only Stage 4e snapshot."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, hunt, hunt_results
from tests.test_hunt_gate import fill, state
from tests.test_hunt_results import candidate, prepared  # noqa: F401


@pytest.fixture
def completed(prepared, tmp_path):
    con, run, payload, _, summary = prepared
    fill(con, run, summary, example=candidate(payload))
    # The same identifier belongs independently to the opposite lane.
    dark = copy.deepcopy(payload)
    dark_lane = summary.lanes[1]
    descriptor = json.loads(pathlib.Path(dark_lane.worklist_path).read_bytes())["batches"][0]
    dark.update(lane="l-dark", worklist_sha256=dark_lane.worklist_sha256,
                batch_sha256=descriptor["sha256"])
    candidate(dark)["dangerous_operation"] = "OTA trust boundary"
    path = run / "dark-result.json"
    path.write_text(json.dumps(dark), encoding="utf-8")
    hunt_results.record(con, run, path, replace=True)
    root = tmp_path / "root"
    for lane in db.HUNT_LANES:
        hunt.check(con, run, root, lane=lane)
    return con, run, root, summary, payload, dark


def test_snapshot_preserves_all_evidence_lane_identity_and_immutable_nested_records(completed):
    # Breaks: dropped candidate fields, mutable nested evidence, cross-lane ID collapse,
    # trusting stored JSON strings, or writing status/timestamps during a read.
    con, run, root, summary, sink, dark = completed
    before, writes = state(con), con.total_changes
    snapshot = hunt.verified_snapshot(con, run, root)
    assert isinstance(snapshot, hunt.VerifiedHuntSnapshot)
    assert (snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256) == (
        "target", summary.manifest_sha256, summary.surface_snapshot_sha256)
    assert snapshot.lanes == tuple(hunt.VerifiedHuntLane(
        lane.lane, lane.worklist_path, lane.worklist_sha256, 4, 2) for lane in summary.lanes)
    assert tuple((row.lane, row.candidate_id) for row in snapshot.candidates) == (
        ("l-sink", "shell-1"), ("l-dark", "shell-1"))
    for row, payload in zip(snapshot.candidates, (sink, dark)):
        receipt = con.execute("SELECT * FROM cba_hunt_receipts WHERE lane=? AND batch_path='batch-0001.json'",
                              (row.lane,)).fetchone()
        artifact = pathlib.Path(receipt["result_path"])
        expected = copy.deepcopy(candidate(payload)) | {
            "lane": row.lane, "surface_ids": ("http-c",),
            "blockers": ({"id": "shell-context", "question": "Which UID runs the daemon?",
                "settling_observation": "Inspect daemon UID after provisioning.", "method": "hardware"},),
            "artifact_path": artifact.relative_to(run).as_posix(),
            "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
        assert isinstance(row, hunt.VerifiedHuntCandidate)
        assert isinstance(row.blockers[0], hunt.VerifiedHuntBlocker)
        assert dataclasses.asdict(row) == expected
    for record in (snapshot, *snapshot.lanes, *snapshot.candidates, snapshot.candidates[0].blockers[0]):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, "changed")
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("completed_lanes", [(), ("l-sink",)])
def test_snapshot_refuses_pending_lanes_without_promoting_them(prepared, tmp_path, completed_lanes):
    con, run, _, _, summary = prepared
    fill(con, run, summary)
    root = tmp_path / "root"
    for lane in completed_lanes:
        hunt.check(con, run, root, lane=lane)
    before, writes = state(con), con.total_changes
    with pytest.raises(hunt.HuntError, match="complete"):
        hunt.verified_snapshot(con, run, root)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("damage", ["pending", "orphan-timestamp", "missing-timestamp", "foreign-image",
    "outside-artifact", "symlink-directory", "symlink-artifact"])
def test_snapshot_rejects_status_ownership_and_escaping_artifacts(completed, tmp_path, damage):
    con, run, root, _, _, _ = completed
    if damage == "pending":
        con.execute("UPDATE cba_hunt_runs SET status='pending',completed_at=NULL WHERE lane='l-dark'")
    elif damage == "orphan-timestamp":
        con.execute("UPDATE cba_hunt_runs SET status='pending' WHERE lane='l-dark'")
    elif damage == "missing-timestamp":
        con.execute("UPDATE cba_hunt_runs SET completed_at=NULL WHERE lane='l-dark'")
    elif damage == "foreign-image":
        con.execute("UPDATE cba_hunt_runs SET image_id='foreign' WHERE lane='l-dark'")
    else:
        receipt = con.execute("SELECT * FROM cba_hunt_receipts WHERE lane='l-sink' AND batch_path='batch-0001.json'").fetchone()
        artifact = pathlib.Path(receipt["result_path"])
        if damage == "outside-artifact":
            outside = tmp_path / "outside.json"
            outside.write_bytes(artifact.read_bytes())
            con.execute("UPDATE cba_hunt_receipts SET result_path=? WHERE result_path=?", (str(outside), str(artifact)))
            con.execute("UPDATE cba_hunt_candidates SET artifact_path=? WHERE artifact_path=?", (str(outside), str(artifact)))
        elif damage == "symlink-directory":
            outside = tmp_path / "outside"
            artifact.parent.rename(outside)
            artifact.parent.symlink_to(outside, target_is_directory=True)
        else:
            outside = tmp_path / "outside.json"
            artifact.rename(outside)
            artifact.symlink_to(outside)
    con.commit()
    before, writes = state(con), con.total_changes
    with pytest.raises(hunt.HuntError):
        hunt.verified_snapshot(con, run, root)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


def test_snapshot_works_on_read_only_sqlite_and_inside_caller_transaction(completed):
    con, run, root, *_ = completed
    with sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert len(hunt.verified_snapshot(readonly, run, root).candidates) == 2
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute("UPDATE cba_hunt_runs SET completed_at='caller-owned'")
    before, writes = state(con), con.total_changes
    assert len(hunt.verified_snapshot(con, run, root).candidates) == 2
    assert con.in_transaction and state(con) == before and con.total_changes == writes
    con.rollback()


def test_snapshot_normalizes_artifacts_with_relative_run_spelling(completed, tmp_path, monkeypatch):
    con, run, root, *_ = completed
    monkeypatch.chdir(tmp_path)
    first = hunt.verified_snapshot(con, run, root)
    assert hunt.verified_snapshot(con, run.relative_to(tmp_path), root) == first
    assert all(row.artifact_path.startswith("artifacts/hunt/") for row in first.candidates)


def test_snapshot_closed_database_is_a_domain_error(completed):
    con, run, root, *_ = completed
    con.close()
    with pytest.raises(hunt.HuntError):
        hunt.verified_snapshot(con, run, root)


def fp_api():
    from audit_core import firmware_fpcheck
    return firmware_fpcheck


# Hand-ordered canonical oracle: detects omitted evidence, provenance, lane identity,
# host paths, or timestamps. Digests below are only fixture provenance placeholders.
SMALL_CANDIDATE = ('{"artifact_path":"artifacts/hunt/result.json","artifact_sha256":"' + 'e' * 64 + '",'
    '"attacker_position":"lan","auth_required":"pre-auth","blockers":[],"bug_class":"Overflow",'
    '"candidate_id":"same","component_path":"bin/tool","confidence":6,"dangerous_operation":"Copy",'
    '"data_flow":"Input -> Copy","impact_hypothesis":"impact","input_evidence":"Read Input",'
    '"lane":"LANE","lifecycle_required":"provisioned","mitigations_checked":"guard",'
    '"operation_evidence":"Call Copy","posture_required":"sta-lan","reachability":"evidenced",'
    '"state_evidence":"state","surface_context":"context","surface_ids":["z","a"],"title":"title"}')
SMALL_SNAPSHOT = ('{"candidates":[' + SMALL_CANDIDATE.replace('LANE', 'l-dark') + ',' +
    SMALL_CANDIDATE.replace('LANE', 'l-sink') + '],"dark_worklist_sha256":"' + 'd' * 64 + '",'
    '"image_id":"target","manifest_sha256":"' + 'a' * 64 + '","schema_version":1,'
    '"sink_worklist_sha256":"' + 'c' * 64 + '","surface_snapshot_sha256":"' + 'b' * 64 + '"}\n').encode()


def small_snapshot():
    records = tuple(hunt.VerifiedHuntCandidate(**(json.loads(SMALL_CANDIDATE.replace('LANE', lane)) |
        {"surface_ids": ("z", "a"), "blockers": ()})) for lane in db.HUNT_LANES)
    return hunt.VerifiedHuntSnapshot("target", "a" * 64, "b" * 64,
        tuple(hunt.VerifiedHuntLane(lane, "/host/root/index.json", digest * 64, 1, 1)
              for lane, digest in zip(db.HUNT_LANES, ("c", "d"))), records)


def worklist_batches(snapshot, size):
    files, digest = fp_api()._worklist(snapshot, size)
    index = json.loads(files["index.json"])
    assert hashlib.sha256(files["index.json"]).hexdigest() == digest
    for descriptor in index["batches"]:
        assert dataclasses.asdict(fp_api().BatchDescriptor(**descriptor)) == descriptor
        assert hashlib.sha256(files[descriptor["path"]]).hexdigest() == descriptor["sha256"]
    return files, index, [json.loads(files[row["path"]]) for row in index["batches"]]


def test_candidate_snapshot_has_literal_canonical_bytes_and_lane_qualified_identity():
    snapshot = small_snapshot()
    assert fp_api()._candidate_snapshot(snapshot) == SMALL_SNAPSHOT
    assert hashlib.sha256(SMALL_SNAPSHOT).hexdigest() == "85dbe35fdea02583efdc0af9a11ab0df84081879aa6264f7026368de5fff039e"
    assert fp_api()._candidate_snapshot(dataclasses.replace(snapshot,
        lanes=snapshot.lanes[::-1], candidates=snapshot.candidates[::-1])) == SMALL_SNAPSHOT
    files, index, batches = worklist_batches(snapshot, 20)
    assert index["candidate_snapshot_sha256"] == hashlib.sha256(SMALL_SNAPSHOT).hexdigest()
    assert index["sink_worklist_sha256"] == "c" * 64
    assert index["dark_worklist_sha256"] == "d" * 64
    assert [(row["lane"], row["candidate_id"]) for row in batches[0]["candidates"]] == [
        ("l-dark", "same"), ("l-sink", "same")]
    for content in files.values():
        assert b"/host/root" not in content and b"_at\"" not in content
    assert all(row["artifact_path"] == "artifacts/hunt/result.json" for row in batches[0]["candidates"])


def test_similarity_normalizes_case_whitespace_and_surface_order_without_merging():
    # Breaks: lane/ID/title entering signature, omitted trace fields, unsorted IDs,
    # normalization that changes evidence, or equal hints collapsing candidates.
    snapshot = small_snapshot()
    first, second = snapshot.candidates
    changed = dataclasses.replace(second, candidate_id="other", title="other title", bug_class=" overflow ",
        dangerous_operation=" COPY\n", input_evidence=" read\tINPUT ", data_flow=" input ->\ncopy ",
        operation_evidence=" call copy ", surface_ids=("A", " Z "))
    snapshot = dataclasses.replace(snapshot, candidates=(first, changed))
    files, index, batches = worklist_batches(snapshot, 1)
    signature_bytes = ('{"bug_class":"overflow","component_path":"bin/tool","dangerous_operation":"copy",'
        '"data_flow":"input -> copy","image_id":"target","input_evidence":"read input",'
        '"operation_evidence":"call copy","surface_ids":["a","z"]}\n').encode()
    signature = hashlib.sha256(signature_bytes).hexdigest()
    assert index["candidate_count"] == 2 and len(batches) == 1
    assert [row["similarity_signature"] for row in batches[0]["candidates"]] == [signature, signature]
    assert batches[0]["candidates"][1]["bug_class"] == "Overflow"
    assert files == fp_api()._worklist(dataclasses.replace(snapshot, candidates=snapshot.candidates[::-1]), 1)[0]
    for field in ("component_path", "bug_class", "dangerous_operation", "input_evidence", "data_flow", "operation_evidence"):
        altered = dataclasses.replace(first, **{field: "different"})
        assert len(worklist_batches(dataclasses.replace(snapshot, candidates=(altered, changed)), 1)[2]) == 2


def test_clusters_are_ordered_by_signature_then_candidate_and_never_split():
    snapshot = small_snapshot()
    first = snapshot.candidates[0]
    candidates = tuple(dataclasses.replace(first, candidate_id=f"id-{n}", dangerous_operation=operation)
                       for n, operation in enumerate(("z", "z", "a", "a", "a", "b")))
    _, _, batches = worklist_batches(dataclasses.replace(snapshot, candidates=candidates[::-1]), 3)
    # The hand-authored signature projection hashes a before b before z;
    # the b singleton and z pair exactly fill the second target-size batch.
    assert [[row["candidate_id"] for row in batch["candidates"]] for batch in batches] == [
        ["id-2", "id-3", "id-4"], ["id-5", "id-0", "id-1"]]
    flattened = [row for batch in batches for row in batch["candidates"]]
    assert [(row["similarity_signature"], row["lane"], row["candidate_id"]) for row in flattened] == sorted(
        (row["similarity_signature"], row["lane"], row["candidate_id"]) for row in flattened)
    signatures = [set(row["similarity_signature"] for row in batch["candidates"]) for batch in batches]
    assert sum(map(len, signatures)) == len(set.union(*signatures)) == 3


@pytest.mark.parametrize("size", [0, 201, True, False, 1.0, "20", None])
def test_prepare_refuses_invalid_batch_sizes_without_writes(completed, size):
    con, run, root, *_ = completed
    before = state(con)
    with pytest.raises(fp_api().FpcheckError, match="batch_size"):
        fp_api().prepare(con, run, root, batch_size=size)
    assert state(con) == before and not con.in_transaction
    assert not (run / "files/firmware-fpcheck").exists()


def test_indivisible_cluster_can_reach_1000_but_cannot_exceed_it():
    snapshot = small_snapshot()
    rows = tuple(dataclasses.replace(snapshot.candidates[0], candidate_id=f"id-{n:04}") for n in range(1001))
    assert len(worklist_batches(dataclasses.replace(snapshot, candidates=rows[:1000]), 1)[2][0]["candidates"]) == 1000
    with pytest.raises(fp_api().FpcheckError, match="1,000|1000"):
        worklist_batches(dataclasses.replace(snapshot, candidates=rows), 20)


def test_large_adjacent_clusters_emit_bounded_separate_batches():
    snapshot = small_snapshot()
    rows = tuple(dataclasses.replace(snapshot.candidates[0], candidate_id=f"id-{n:04}",
        dangerous_operation="one" if n < 600 else "two") for n in range(1200))
    _, _, batches = worklist_batches(dataclasses.replace(snapshot, candidates=rows), 200)
    assert [len(batch["candidates"]) for batch in batches] == [600, 600]
    with pytest.raises(fp_api().FpcheckError, match="batch.*1,000|batch.*1000"):
        fp_api()._worklist(dataclasses.replace(snapshot, candidates=rows), 1200)


def test_empty_snapshot_emits_one_canonical_empty_batch():
    snapshot = dataclasses.replace(small_snapshot(), candidates=())
    files, index, batches = worklist_batches(snapshot, 20)
    assert index["candidate_count"] == 0
    assert len(batches) == 1 and batches[0]["candidates"] == []
    assert index["batches"][0]["candidate_count"] == 0
    assert files == fp_api()._worklist(snapshot, 20)[0]


def test_evidence_is_preserved_and_sql_insertion_order_cannot_change_bytes(completed):
    con, run, root, *_ = completed
    snapshot = hunt.verified_snapshot(con, run, root)
    summary = fp_api().prepare(con, run, root, batch_size=200)
    directory = pathlib.Path(summary.worklist_path).parent
    files = {path.name: path.read_bytes() for path in directory.iterdir()}
    assigned = [row for name, content in files.items() if name.startswith("batch-")
        for row in json.loads(content)["candidates"]]
    assert sorted(({key: value for key, value in row.items() if key != "similarity_signature"} for row in assigned),
        key=lambda row: (row["lane"], row["candidate_id"])) == json.loads(fp_api()._candidate_snapshot(snapshot))["candidates"]
    rows = [dict(row) for row in con.execute("SELECT * FROM cba_hunt_candidates ORDER BY lane,candidate_id")]
    con.execute("DELETE FROM cba_hunt_candidates")
    for row in reversed(rows):
        db.put(con, "cba_hunt_candidates", row, commit=False)
    con.commit()
    assert fp_api().prepare(con, run, root, batch_size=200) == summary
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == files


@pytest.mark.parametrize("field", ["manifest_sha256", "surface_snapshot_sha256", "lanes", "candidates"])
def test_each_candidate_snapshot_ownership_input_changes_digest(field):
    snapshot = small_snapshot()
    value = {"manifest_sha256": "f" * 64, "surface_snapshot_sha256": "f" * 64,
        "lanes": (dataclasses.replace(snapshot.lanes[0], worklist_sha256="f" * 64), snapshot.lanes[1]),
        "candidates": (dataclasses.replace(snapshot.candidates[0], artifact_sha256="f" * 64), snapshot.candidates[1])}[field]
    assert fp_api()._candidate_snapshot(dataclasses.replace(snapshot, **{field: value})) != SMALL_SNAPSHOT


def seed_fp_claims(con, image_id):
    from tests.test_firmware_fpcheck_schema import ROWS
    for table, row in ROWS:
        values = row | {"image_id": image_id}
        if table == "cba_firmware_fp_runs":
            values.update(status="complete", completed_at="retained")
        db.put(con, table, values, replace=True)


def test_prepare_publishes_one_pending_row_and_is_idempotent_without_writes(completed):
    con, run, root, *_ = completed
    summary = fp_api().prepare(con, run, root)
    assert isinstance(summary, fp_api().PreparationSummary)
    index_path = pathlib.Path(summary.worklist_path)
    assert index_path == run / "files/firmware-fpcheck" / summary.generation / "index.json"
    assert summary.worklist_sha256 == summary.generation == hashlib.sha256(index_path.read_bytes()).hexdigest()
    row = con.execute("SELECT * FROM cba_firmware_fp_runs").fetchone()
    assert (row["candidate_count"], row["batch_count"], row["status"], row["completed_at"]) == (2, 1, "pending", None)
    assert row["prepared_at"] and row["candidate_snapshot_sha256"] == summary.candidate_snapshot_sha256
    con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at='retained'")
    con.commit()
    before, writes = state(con), con.total_changes
    assert fp_api().prepare(con, run, root) == summary
    assert state(con) == before and con.total_changes == writes and not con.in_transaction
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.image_id = "changed"
    descriptor = fp_api().BatchDescriptor("batch-0001.json", "a" * 64, 2)
    with pytest.raises(dataclasses.FrozenInstanceError):
        descriptor.path = "changed"


@pytest.mark.parametrize("damage", ["pending", "root", "candidate", "artifact", "worklist"])
def test_prepare_requires_completed_verified_hunt_and_exact_live_root(completed, damage):
    con, run, root, summary, *_ = completed
    if damage == "pending":
        con.execute("UPDATE cba_hunt_runs SET status='pending',completed_at=NULL WHERE lane='l-dark'")
        con.commit()
    elif damage == "root":
        (root / "a").write_bytes(b"other\n")
    elif damage == "candidate":
        con.execute("UPDATE cba_hunt_candidates SET title='tampered'")
        con.commit()
    elif damage == "artifact":
        pathlib.Path(con.execute("SELECT artifact_path FROM cba_hunt_candidates LIMIT 1").fetchone()[0]).write_bytes(b"{}")
    else:
        pathlib.Path(summary.lanes[0].worklist_path).write_bytes(b"{}")
    before = state(con)
    with pytest.raises(fp_api().FpcheckError):
        fp_api().prepare(con, run, root)
    assert state(con) == before and not con.in_transaction


def test_prepare_refuses_caller_transaction_and_preserves_it(completed):
    con, run, root, *_ = completed
    con.execute("UPDATE cba_hunt_runs SET completed_at='caller'")
    before = state(con)
    with pytest.raises(fp_api().FpcheckError, match="transaction"):
        fp_api().prepare(con, run, root)
    assert state(con) == before and con.in_transaction
    con.rollback()


def test_preparation_is_idempotent_with_relative_run_spelling(completed, monkeypatch):
    con, run, root, *_ = completed
    summary = fp_api().prepare(con, run, root)
    con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at='retained'")
    con.commit()
    before, writes = state(con), con.total_changes
    monkeypatch.chdir(run.parent)
    assert fp_api().prepare(con, pathlib.Path(run.name), root) == summary
    assert state(con) == before and con.total_changes == writes


@pytest.mark.parametrize("commit", [False, True])
def test_invalidation_is_exact_image_scoped_and_commit_is_opt_in(completed, commit):
    con, _, _, *_ = completed
    for image in ("target", "target:%_雪|other"):
        seed_fp_claims(con, image)
    before = state(con)
    fp_api().invalidate(con, "target", commit=commit)
    after = state(con)
    for table in db.TABLE_SPECS:
        assert after[table] == ([row for row in before[table] if row[0] != "target"]
            if table in {"cba_firmware_fp_runs", "cba_firmware_fp_receipts", "cba_firmware_fp_verdicts",
                "cba_firmware_pivots", "cba_firmware_findings"} else before[table])
    assert con.in_transaction is not commit
    if not commit:
        con.rollback()
        assert state(con) == before


def test_selection_replacement_and_sibling_image_isolation(completed):
    from tests.test_hunt_prepare import add_target
    con, run, root, *_ = completed
    first = fp_api().prepare(con, run, root)
    seed_fp_claims(con, "target")
    sibling = "target:%_雪|other"
    other_root = root.parent / "other-root"
    add_target(con, run, other_root, ["a", "b", "c"], image_id=sibling)
    other_hunt = hunt.prepare(con, run, other_root, image_id=sibling)
    fill(con, run, other_hunt)
    for lane in db.HUNT_LANES:
        hunt.check(con, run, other_root, image_id=sibling, lane=lane)
    seed_fp_claims(con, sibling)
    before = state(con)
    for identifier in (None, "absent"):
        with pytest.raises(fp_api().FpcheckError):
            fp_api().prepare(con, run, root, image_id=identifier)
    assert state(con) == before
    # Batch-size changes replace only the selected generation, retaining sibling
    # rows with overlapping component paths, candidate IDs and non-ASCII image IDs.
    changed = fp_api().prepare(con, run, root, image_id="target", batch_size=1)
    assert changed.generation != first.generation
    after = state(con)
    for table in db.TABLE_SPECS:
        if table.startswith("cba_firmware_fp_") or table in ("cba_firmware_pivots", "cba_firmware_findings"):
            assert [row for row in after[table] if row[0] == sibling] == [row for row in before[table] if row[0] == sibling]
            if table != "cba_firmware_fp_runs":
                assert not [row for row in after[table] if row[0] == "target"]
        else:
            assert after[table] == before[table]
    empty = fp_api().prepare(con, run, other_root, image_id=sibling)
    assert (empty.candidate_count, empty.batch_count) == (0, 1)


@pytest.mark.parametrize("failure", ["root-drift", "hunt-drift", "installed-drift", "sql", "install"])
def test_prepare_failure_preserves_prior_sql(completed, monkeypatch, failure):
    from audit_core import surface
    con, run, root, *_ = completed
    fp_api().prepare(con, run, root)
    seed_fp_claims(con, "target")
    before = state(con)
    original = surface.atomic_install
    def install_then_damage(destination, files):
        if failure == "install":
            raise OSError("injected installation failure")
        original(destination, files)
        if failure == "root-drift":
            (root / "a").write_bytes(b"other\n")
        elif failure == "installed-drift":
            (destination / "index.json").write_bytes(b"{}")
    monkeypatch.setattr(surface, "atomic_install", install_then_damage)
    if failure == "hunt-drift":
        original_snapshot = hunt.verified_snapshot
        calls = 0
        def changed(*args, **kwargs):
            nonlocal calls
            calls += 1
            value = original_snapshot(*args, **kwargs)
            return value if calls == 1 else dataclasses.replace(value, candidates=())
        monkeypatch.setattr(hunt, "verified_snapshot", changed)
    if failure == "sql":
        con.execute("CREATE TRIGGER fail_fp_insert BEFORE INSERT ON cba_firmware_fp_runs "
            "BEGIN SELECT RAISE(FAIL, 'injected insert failure'); END")
        con.commit()
    with pytest.raises(fp_api().FpcheckError):
        fp_api().prepare(con, run, root, batch_size=1)
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("parent", ["files", "firmware-fpcheck"])
def test_prepare_rejects_symlink_parents_before_installing_outside_run(completed, tmp_path, parent):
    con, run, root, *_ = completed
    directory = run / "files" if parent == "files" else run / "files/firmware-fpcheck"
    outside = tmp_path / "outside"
    if directory.exists():
        directory.rename(outside)
    else:
        outside.mkdir()
    directory.symlink_to(outside, target_is_directory=True)
    before = state(con)
    outside_before = sorted(path.relative_to(outside).as_posix() for path in outside.rglob("*"))
    with pytest.raises(fp_api().FpcheckError):
        fp_api().prepare(con, run, root)
    assert state(con) == before and not con.in_transaction
    assert sorted(path.relative_to(outside).as_posix() for path in outside.rglob("*")) == outside_before


@pytest.mark.parametrize("damage", ["extra", "batch-symlink", "directory-symlink"])
def test_installed_artifacts_are_rechecked_under_publication_lock(completed, monkeypatch, tmp_path, damage):
    from audit_core import surface
    con, run, root, *_ = completed
    original = surface.atomic_install
    def install_then_damage(destination, files):
        original(destination, files)
        if damage == "extra":
            (destination / "extra.json").write_bytes(b"{}")
        elif damage == "batch-symlink":
            batch = destination / "batch-0001.json"
            outside = tmp_path / "batch.json"
            batch.rename(outside)
            batch.symlink_to(outside)
        else:
            outside = tmp_path / "generation"
            destination.rename(outside)
            destination.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(surface, "atomic_install", install_then_damage)
    before = state(con)
    with pytest.raises(fp_api().FpcheckError):
        fp_api().prepare(con, run, root)
    assert state(con) == before and not con.in_transaction


def test_prepare_closed_connection_is_a_domain_error(completed):
    con, run, root, *_ = completed
    con.close()
    with pytest.raises(fp_api().FpcheckError):
        fp_api().prepare(con, run, root)


def test_prepare_rolls_back_on_commit_failure(completed):
    con, run, root, *_ = completed
    seed_fp_claims(con, "target")
    class CommitFailure(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("injected commit failure")
    connection = sqlite3.connect(run / "audit.db", factory=CommitFailure)
    connection.row_factory = sqlite3.Row
    before = state(con)
    try:
        with pytest.raises(fp_api().FpcheckError, match="commit failure"):
            fp_api().prepare(connection, run, root)
        assert state(con) == before and not connection.in_transaction
    finally:
        connection.close()
