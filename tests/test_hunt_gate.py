"""Completion requires exact receipt-owned evidence in each independent lane."""
import copy
import dataclasses
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, hunt, hunt_results, surface, workspace
from tests.test_hunt_prepare import add_target
from tests.test_hunt_results import candidate, prepared  # noqa: F401


def state(con):
    return {table: sorted([tuple(row) for row in con.execute(f"SELECT * FROM {table}")], key=repr)
            for table in db.TABLE_SPECS}


def fill(con, run, summary, *, lane=None, example=None, disposition="analyzed", reason="Direct review found no surviving path."):
    for assignment in summary.lanes:
        if lane is not None and assignment.lane != lane:
            continue
        index = json.loads(pathlib.Path(assignment.worklist_path).read_bytes())
        for batch in index["batches"]:
            units = json.loads(pathlib.Path(assignment.worklist_path).with_name(batch["path"]).read_bytes())["units"]
            decisions = [{"path": unit["path"], "disposition": disposition, "reason": reason, "candidates": []}
                         for unit in units]
            if example is not None and assignment.lane == "l-sink":
                for decision in decisions:
                    if decision["path"] == "c":
                        decision.update(disposition="analyzed", reason=None, candidates=[copy.deepcopy(example)])
            payload = {"schema_version": 1, "image_id": summary.image_id, "lane": assignment.lane,
                "manifest_sha256": summary.manifest_sha256, "surface_snapshot_sha256": summary.surface_snapshot_sha256,
                "worklist_sha256": assignment.worklist_sha256, "batch_path": batch["path"],
                "batch_sha256": batch["sha256"], "decisions": decisions}
            path = run / "gate-input.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            hunt_results.record(con, run, path)


@pytest.fixture
def ready(prepared, tmp_path):
    con, run, payload, _, summary = prepared
    fill(con, run, summary, example=candidate(payload))
    return con, run, tmp_path / "root", summary


def test_lane_check_rejects_status_timestamp_disagreement_without_writes(ready):
    con, run, root, _ = ready
    con.execute("UPDATE cba_hunt_runs SET completed_at='orphan' WHERE lane='l-sink'")
    con.commit()
    before = state(con)
    with pytest.raises(hunt.HuntError, match="status and timestamp disagree"):
        hunt.check(con, run, root, lane="l-sink")
    assert state(con) == before and not con.in_transaction


def test_lane_check_rejects_invalid_lane_without_writes(ready):
    con, run, root, _ = ready
    before = state(con)
    with pytest.raises(hunt.HuntError, match="Invalid hunt lane"):
        hunt.check(con, run, root, lane="unknown")
    assert state(con) == before and not con.in_transaction


def test_lane_check_rolls_back_if_inputs_change_after_preflight(ready, monkeypatch):
    con, run, root, _ = ready
    original = hunt._check_inputs
    calls = 0

    def drift_on_recheck(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original(*args, **kwargs)
        return result if calls == 1 else result + ("changed",)

    monkeypatch.setattr(hunt, "_check_inputs", drift_on_recheck)
    before = state(con)
    with pytest.raises(hunt.HuntError, match="inputs changed before completion"):
        hunt.check(con, run, root, lane="l-sink")
    assert calls == 2
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("damage,match", [
    ("duplicate-decision", "Duplicate hunt decision ownership"),
    ("duplicate-candidate", "Duplicate hunt candidate ownership"),
    ("incomplete-denominator", "do not cover the complete manifest"),
])
def test_lane_aggregator_rejects_impossible_overlaps_at_its_boundary(ready, monkeypatch, damage, match):
    # Breaks: accepting overlapping/collapsed batch output if an upstream
    # validator ever violates its exact-worklist contract.
    con, run, _, _ = ready
    original_validate = hunt_results.validate
    original_canonical = hunt_results.canonical_bytes
    cached_bytes = {}
    first_decision = None
    first_candidate = None

    def inject_overlap(connection, run_dir, result):
        nonlocal first_decision, first_candidate
        validated = original_validate(connection, run_dir, result)
        raw_canonical = original_canonical(validated)
        if result.batch_path == "batch-0001.json":
            first_decision = validated.result.decisions[-1]
            if first_decision.candidates:
                first_candidate = first_decision.candidates[0]
        elif damage == "duplicate-decision":
            changed_result = dataclasses.replace(validated.result, decisions=(first_decision,))
            validated = dataclasses.replace(validated, result=changed_result)
        elif damage == "duplicate-candidate":
            decision = validated.result.decisions[0]
            duplicate = dataclasses.replace(first_candidate, component_path=decision.path,
                surface_ids=(), surface_context="Unmapped parser at d:10.")
            changed_result = dataclasses.replace(validated.result,
                decisions=(dataclasses.replace(decision, candidates=(duplicate,)),))
            validated = dataclasses.replace(validated, result=changed_result)
        else:
            validated = dataclasses.replace(validated,
                result=dataclasses.replace(validated.result, decisions=()))
        cached_bytes[id(validated)] = raw_canonical
        return validated

    def original_artifact_bytes(validated):
        return cached_bytes.get(id(validated), original_canonical(validated))

    monkeypatch.setattr(hunt_results, "validate", inject_overlap)
    monkeypatch.setattr(hunt_results, "canonical_bytes", original_artifact_bytes)
    if damage in ("duplicate-decision", "duplicate-candidate"):
        con.execute("UPDATE cba_hunt_receipts SET candidate_count=1 WHERE lane='l-sink' AND batch_path='batch-0002.json'")
    if damage == "incomplete-denominator":
        con.execute("UPDATE cba_hunt_receipts SET unit_count=0 WHERE lane='l-sink' AND batch_path='batch-0002.json'")
    con.commit()
    with pytest.raises(hunt.HuntError, match=match):
        hunt._checked_lane(con, run, dict(con.execute("SELECT * FROM cba_hunt_runs WHERE lane='l-sink'").fetchone()),
                           surface._manifest(con, "target"))


@pytest.mark.parametrize("lane,candidates,blockers", [("l-sink", 1, 1), ("l-dark", 0, 0)])
def test_lane_check_completes_only_selected_lane_and_rechecks_idempotently(ready, monkeypatch, lane, candidates, blockers):
    # Breaks: treating candidate-free receipts as absent, scanning orphans, or completing the sibling lane.
    con, run, root, summary = ready
    orphan = run / "artifacts/hunt/unrelated/result.json"
    orphan.parent.mkdir()
    orphan.write_text("not a result")
    original = pathlib.Path.iterdir
    def no_hunt_artifact_discovery(path):
        if path.is_relative_to(run / "artifacts/hunt"):
            raise AssertionError("Hunt artifact discovery is forbidden")
        return original(path)
    monkeypatch.setattr(pathlib.Path, "iterdir", no_hunt_artifact_discovery)
    result = hunt.check(con, run, root, lane=lane)
    assert result == hunt.HuntCheck("target", summary.manifest_sha256, summary.surface_snapshot_sha256,
        (hunt.LaneCheck("target", lane, 4, 4, 0, 0, 2, candidates, blockers, True),), True)
    rows = {row["lane"]: dict(row) for row in con.execute("SELECT * FROM cba_hunt_runs")}
    assert rows[lane]["status"] == "complete" and rows[lane]["completed_at"]
    other = "l-dark" if lane == "l-sink" else "l-sink"
    assert (rows[other]["status"], rows[other]["completed_at"]) == ("pending", None)
    before, writes = state(con), con.total_changes
    assert hunt.check(con, run, root, lane=lane) == result
    assert state(con) == before and con.total_changes == writes and not con.in_transaction
    for item in (result, result.lanes[0]):
        with pytest.raises(dataclasses.FrozenInstanceError):
            item.complete = False


def test_final_gate_requires_prior_independent_lane_completion(ready):
    # Breaks: final gate silently promoting pending lanes, or accepting one completed lane.
    con, run, root, _ = ready
    for completed in (None, "l-sink"):
        if completed:
            hunt.check(con, run, root, lane=completed)
        before = state(con)
        with pytest.raises(hunt.HuntError):
            hunt.check(con, run, root)
        assert state(con) == before
    hunt.check(con, run, root, lane="l-dark")
    before, writes = state(con), con.total_changes
    result = hunt.check(con, run, root)
    assert result.complete and tuple(row.lane for row in result.lanes) == ("l-sink", "l-dark")
    assert state(con) == before and con.total_changes == writes


@pytest.mark.parametrize("import_absolute", [True, False], ids=["absolute-to-relative", "relative-to-absolute"])
def test_equivalent_run_path_spellings_can_complete_and_recheck_both_lanes(prepared, tmp_path, monkeypatch, import_absolute):
    # Breaks: comparing normalized paths but checking ancestry with mixed absolute/relative spellings.
    con, run, payload, _, summary = prepared
    root = tmp_path / "root"
    monkeypatch.chdir(tmp_path)
    relative_run = run.relative_to(tmp_path)
    if import_absolute:
        import_run, check_run = run, relative_run
    else:
        import_run, check_run = relative_run, run
        summary = hunt.prepare(con, import_run, root)
    fill(con, import_run, summary, example=candidate(payload))
    provenance = [dict(row) for row in con.execute("SELECT * FROM cba_hunt_candidates")]
    for lane in db.HUNT_LANES:
        assert hunt.check(con, check_run, root, lane=lane).complete
    before, writes = state(con), con.total_changes
    assert hunt.check(con, check_run, root).complete
    assert state(con) == before and con.total_changes == writes and not con.in_transaction
    assert [dict(row) for row in con.execute("SELECT * FROM cba_hunt_candidates")] == provenance


@pytest.mark.parametrize("damage", ["surface-absent", "surface-pending", "surface-stale", "manifest", "snapshot",
    "index", "batch", "worklist-digest", "worklist-path", "run-count", "receipt-missing", "receipt-duplicate",
    "receipt-foreign-generation", "receipt-foreign-lane", "receipt-foreign-image", "receipt-batch-hash",
    "receipt-result-path", "receipt-result-hash", "receipt-units", "receipt-candidates", "result-corrupt",
    "result-noncanonical", "result-missing", "coverage-missing", "coverage-extra", "coverage-state", "coverage-reason",
    "candidate-missing", "candidate-extra", "candidate-evidence", "candidate-provenance", "candidate-surface"])
@pytest.mark.parametrize("reader", ["check", "snapshot"])
def test_corrupt_durable_inputs_refuse_without_changing_status_or_timestamps(ready, damage, reader):
    # Breaks: accepting drift, partial evidence, foreign ownership, or aggregate-only agreement.
    con, run, root, summary = ready
    if reader == "snapshot":
        for lane in db.HUNT_LANES:
            hunt.check(con, run, root, lane=lane)
    receipt = dict(con.execute("SELECT * FROM cba_hunt_receipts WHERE lane='l-sink' ORDER BY batch_path").fetchone())
    if damage.startswith("surface-"):
        if damage == "surface-absent":
            con.execute("DELETE FROM cba_surface_runs")
        elif damage == "surface-pending":
            con.execute("UPDATE cba_surface_runs SET status='pending',completed_at=NULL")
        else:
            next((run / "artifacts/surface").rglob("result.json")).write_text("{}")
    elif damage == "manifest":
        con.execute("UPDATE cba_firmware_files SET sha256=? WHERE path='a'", ("0" * 64,))
    elif damage in ("snapshot", "worklist-digest", "worklist-path", "run-count"):
        field, value = {"snapshot": ("surface_snapshot_sha256", "0" * 64),
            "worklist-digest": ("worklist_sha256", "0" * 64), "worklist-path": ("worklist_path", str(run / "index.json")),
            "run-count": ("unit_count", 3)}[damage]
        con.execute(f"UPDATE cba_hunt_runs SET {field}=? WHERE lane='l-sink'", (value,))
    elif damage in ("index", "batch"):
        path = pathlib.Path(summary.lanes[0].worklist_path)
        (path if damage == "index" else path.with_name("batch-0001.json")).write_text("{}")
    elif damage == "receipt-missing":
        con.execute("DELETE FROM cba_hunt_receipts WHERE lane='l-sink' AND batch_path='batch-0001.json'")
    elif damage in ("receipt-duplicate", "receipt-foreign-generation", "receipt-foreign-lane", "receipt-foreign-image"):
        changed = receipt.copy()
        changed[{"receipt-duplicate": "worklist_sha256", "receipt-foreign-generation": "worklist_sha256",
                 "receipt-foreign-lane": "lane", "receipt-foreign-image": "image_id"}[damage]] = {
                     "receipt-foreign-lane": "l-dark", "receipt-foreign-image": "foreign"}.get(damage, "0" * 64)
        if damage != "receipt-duplicate":
            con.execute("DELETE FROM cba_hunt_receipts WHERE lane='l-sink' AND batch_path='batch-0001.json'")
        # Foreign rows are inserted directly so SQLite ownership, rather than put's upsert, is tested.
        if damage == "receipt-foreign-lane":
            con.execute("DELETE FROM cba_hunt_receipts WHERE lane='l-dark' AND batch_path='batch-0001.json'")
        con.execute("INSERT INTO cba_hunt_receipts VALUES (?,?,?,?,?,?,?,?,?,?)", tuple(changed.values()))
    elif damage.startswith("receipt-"):
        field, value = {"receipt-batch-hash": ("batch_sha256", "0" * 64),
            "receipt-result-path": ("result_path", str(run / "foreign/result.json")),
            "receipt-result-hash": ("result_sha256", "0" * 64), "receipt-units": ("unit_count", 2),
            "receipt-candidates": ("candidate_count", 0)}[damage]
        con.execute(f"UPDATE cba_hunt_receipts SET {field}=? WHERE lane='l-sink' AND batch_path='batch-0001.json'", (value,))
    elif damage.startswith("result-"):
        path = pathlib.Path(receipt["result_path"])
        if damage == "result-missing":
            path.unlink()
        elif damage == "result-corrupt":
            path.write_text("{}")
        else:
            path.write_bytes(b" " + path.read_bytes())
    elif damage.startswith("coverage-"):
        key = db.firmware_unit_key("target", "a")
        if damage == "coverage-missing":
            con.execute("DELETE FROM cba_coverage WHERE unit=? AND phase='hunt-l-sink'", (key,))
        elif damage == "coverage-extra":
            db.put(con, "cba_coverage", {"unit": db.firmware_unit_key("target", "extra"), "phase": "hunt-l-sink", "state": "analyzed"})
        else:
            field, value = ("state", "not_audited") if damage == "coverage-state" else ("reason", "Different analysis")
            con.execute(f"UPDATE cba_coverage SET {field}=? WHERE unit=? AND phase='hunt-l-sink'", (value, key))
    else:
        if damage == "candidate-missing":
            con.execute("DELETE FROM cba_hunt_candidates WHERE lane='l-sink'")
        elif damage == "candidate-extra":
            row = dict(con.execute("SELECT * FROM cba_hunt_candidates").fetchone()) | {"candidate_id": "extra"}
            con.execute("INSERT INTO cba_hunt_candidates VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))
        else:
            field, value = {"candidate-evidence": ("data_flow", "fabricated evidence"),
                "candidate-provenance": ("artifact_sha256", "0" * 64), "candidate-surface": ("surface_ids", '["foreign"]')}[damage]
            con.execute(f"UPDATE cba_hunt_candidates SET {field}=? WHERE lane='l-sink'", (value,))
    con.commit()
    before, writes = state(con), con.total_changes
    with pytest.raises(hunt.HuntError):
        if reader == "snapshot":
            hunt.verified_snapshot(con, run, root)
        else:
            hunt.check(con, run, root, lane="l-sink")
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("damage", ["added", "removed", "same-size", "missing-root"])
@pytest.mark.parametrize("reader", ["check", "snapshot"])
def test_live_root_is_required_and_exact(ready, damage, reader):
    # Breaks: trusting prepared hashes, sizes alone, or an absent live root.
    con, run, root, _ = ready
    if reader == "snapshot":
        for lane in db.HUNT_LANES:
            hunt.check(con, run, root, lane=lane)
    if damage == "added":
        (root / "extra").write_bytes(b"hello\n")
    elif damage == "removed":
        (root / "a").unlink()
    elif damage == "same-size":
        (root / "a").write_bytes(b"other\n")
    else:
        root = root / "absent"
    before, writes = state(con), con.total_changes
    with pytest.raises(hunt.HuntError):
        if reader == "snapshot":
            hunt.verified_snapshot(con, run, root)
        else:
            hunt.check(con, run, root, lane="l-sink")
    assert state(con) == before and con.total_changes == writes


@pytest.mark.parametrize("disposition,reason,passes", [("not_applicable", "Data cannot participate in the lane.", True),
    ("not_audited", "binary-only", True), ("not_audited", "budget", False)])
def test_honest_partial_decisions_count_but_budget_never_completes(prepared, tmp_path, disposition, reason, passes):
    # Breaks: failing honest unresolved work or accepting a budget skip.
    con, run, _, _, summary = prepared
    fill(con, run, summary, lane="l-sink", disposition=disposition, reason=reason)
    if not passes:
        before = state(con)
        with pytest.raises(hunt.HuntError):
            hunt.check(con, run, tmp_path / "root", lane="l-sink")
        assert state(con) == before
    else:
        result = hunt.check(con, run, tmp_path / "root", lane="l-sink").lanes[0]
        assert (result.analyzed, result.not_applicable, result.not_audited) == (
            (0, 4, 0) if disposition == "not_applicable" else (0, 0, 4))


def test_other_lane_and_plain_hunt_coverage_cannot_satisfy_missing_lane(prepared, tmp_path):
    # Breaks: counting coverage by raw path or accepting aggregate cross-lane work.
    con, run, _, _, summary = prepared
    fill(con, run, summary, lane="l-sink")
    for path in ("a", "b", "c", "d"):
        db.put(con, "cba_coverage", {"unit": db.firmware_unit_key("target", path), "phase": "hunt", "state": "analyzed"})
    hunt.check(con, run, tmp_path / "root", lane="l-sink")
    for lane in ("l-dark", None):
        before = state(con)
        with pytest.raises(hunt.HuntError):
            hunt.check(con, run, tmp_path / "root", lane=lane)
        assert state(con) == before


def test_201st_unit_is_checked_beyond_the_database_display_cap(tmp_path):
    # Breaks: using capped db.query for manifests, coverage, or receipt evidence.
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    with db.connect(run / "audit.db") as con:
        root = tmp_path / "root"
        add_target(con, run, root, [f"unit-{i:03}" for i in range(201)])
        summary = hunt.prepare(con, run, root)
        fill(con, run, summary)
        for lane in db.HUNT_LANES:
            assert hunt.check(con, run, root, lane=lane).lanes[0].manifest_units == 201
        assert hunt.check(con, run, root).complete
        snapshot = hunt.verified_snapshot(con, run, root)
        assert tuple(lane.unit_count for lane in snapshot.lanes) == (201, 201)
        assert snapshot.candidates == ()
        con.execute("UPDATE cba_coverage SET reason='tampered' WHERE phase='hunt-l-sink' AND unit=?",
                    (db.firmware_unit_key("target", "unit-200"),))
        con.commit()
        before = state(con)
        with pytest.raises(hunt.HuntError):
            hunt.check(con, run, root, lane="l-sink")
        with pytest.raises(hunt.HuntError):
            hunt.verified_snapshot(con, run, root)
        assert state(con) == before


def test_overlapping_paths_and_delimiter_unicode_image_ids_keep_exact_ownership(tmp_path):
    # Breaks: guessing ownership by raw paths, substring/LIKE prefixes, or unframed image IDs.
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    with db.connect(run / "audit.db") as con:
        roots = {}
        for number, image in enumerate(("a:%_图像", "a:%_图像:other")):
            roots[image] = tmp_path / f"root-{number}"
            add_target(con, run, roots[image], ["a", "b"], image_id=image)
            summary = hunt.prepare(con, run, roots[image], image_id=image)
            fill(con, run, summary)
            for lane in db.HUNT_LANES:
                hunt.check(con, run, roots[image], image_id=image, lane=lane)
        first, second = roots
        con.execute("UPDATE cba_hunt_receipts SET unit_count=99 WHERE image_id=?", (first,))
        con.execute("DELETE FROM cba_coverage WHERE unit=? AND phase='hunt-l-dark'", (db.firmware_unit_key(first, "b"),))
        con.commit()
        before = state(con)
        assert hunt.check(con, run, roots[second], image_id=second).complete
        with pytest.raises(hunt.HuntError):
            hunt.check(con, run, roots[first], image_id=first)
        assert state(con) == before


def test_active_caller_transaction_is_preserved(ready):
    # Breaks: committing/rolling back a transaction the gate does not own.
    con, run, root, _ = ready
    con.execute("UPDATE cba_hunt_runs SET completed_at='caller-owned'")
    before = state(con)
    with pytest.raises(hunt.HuntError, match="active transaction"):
        hunt.check(con, run, root, lane="l-sink")
    assert con.in_transaction and state(con) == before
    con.rollback()


def test_malformed_index_batch_path_is_an_expected_refusal(ready):
    # Breaks: using untrusted JSON values as dictionary keys before validating the index.
    con, run, root, summary = ready
    path = pathlib.Path(summary.lanes[0].worklist_path)
    index = json.loads(path.read_bytes())
    index["batches"][0]["path"] = []
    path.write_text(json.dumps(index))
    before = state(con)
    with pytest.raises(hunt.HuntError):
        hunt.check(con, run, root, lane="l-sink")
    assert state(con) == before and not con.in_transaction


def test_closed_database_is_an_expected_read_error(ready):
    # Breaks: reading connection state outside the SQLite domain-error boundary.
    con, run, root, _ = ready
    before = state(con)
    con.close()
    with pytest.raises(hunt.HuntError):
        hunt.check(con, run, root, lane="l-sink")
    with db.connect(run / "audit.db") as current:
        assert state(current) == before


@pytest.mark.parametrize("failure", ["sqlite-read", "filesystem-read", "sqlite-transition"])
def test_expected_read_and_transition_errors_preserve_sql(ready, monkeypatch, failure):
    # Breaks: leaking expected I/O errors or leaving a partially completed generation.
    con, run, root, _ = ready
    before = state(con)
    if failure.startswith("sqlite"):
        denied = sqlite3.SQLITE_READ if failure == "sqlite-read" else sqlite3.SQLITE_UPDATE
        con.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action == denied else sqlite3.SQLITE_OK)
    else:
        original = pathlib.Path.open
        def broken(path, *args, **kwargs):
            if path.is_relative_to(run / "artifacts/hunt"):
                raise OSError("read failed")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(pathlib.Path, "open", broken)
    with pytest.raises(hunt.HuntError):
        hunt.check(con, run, root, lane="l-sink")
    con.set_authorizer(None)
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("change", ["surface", "receipt", "coverage", "candidate", "root", "batch", "result"])
def test_checks_repeat_after_publication_lock_before_transition(ready, change):
    # Breaks: transitioning from diagnostic reads before the publication lock.
    con, run, root, summary = ready
    changed = {}
    class Boundary:
        def __getattr__(self, name):
            return getattr(con, name)
        def execute(self, sql, args=()):
            if sql == "BEGIN IMMEDIATE":
                with db.connect(run / "audit.db") as other:
                    if change == "surface":
                        other.execute("UPDATE cba_surface_runs SET status='pending',completed_at=NULL")
                    elif change == "receipt":
                        other.execute("DELETE FROM cba_hunt_receipts WHERE lane='l-sink' AND batch_path='batch-0001.json'")
                    elif change == "coverage":
                        other.execute("UPDATE cba_coverage SET reason='changed' WHERE phase='hunt-l-sink'")
                    elif change == "candidate":
                        other.execute("UPDATE cba_hunt_candidates SET confidence=1")
                    elif change == "root":
                        (root / "a").write_bytes(b"other\n")
                    elif change == "batch":
                        pathlib.Path(summary.lanes[0].worklist_path).with_name("batch-0001.json").write_text("{}")
                    else:
                        receipt = other.execute("SELECT result_path FROM cba_hunt_receipts WHERE lane='l-sink'").fetchone()
                        pathlib.Path(receipt[0]).write_text("{}")
                    other.commit()
                    changed.update(state(other))
            return con.execute(sql, args)
    with pytest.raises(hunt.HuntError):
        hunt.check(Boundary(), run, root, lane="l-sink")
    assert state(con) == changed and not con.in_transaction
