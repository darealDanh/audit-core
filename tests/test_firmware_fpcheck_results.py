"""Adversarial review results are evidence-bound, read-only and variant strict."""
import copy
import dataclasses
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, firmware_fpcheck, hunt, hunt_results, workspace
from tests.test_firmware_fpcheck_prepare import completed  # noqa: F401
from tests.test_hunt_results import candidate, prepared  # noqa: F401
from tests.test_hunt_gate import fill, state
from tests.test_hunt_prepare import add_target


def api():
    from audit_core import firmware_fpcheck_results
    return firmware_fpcheck_results


TP = {"root_cause_key": "shell", "root_cause": "Unchecked shell input", "dedup_evidence": "Same call",
      "attacker_position": "lan", "data_flow": "POST to system", "impact_hypothesis": "Shell execution",
      "component_paths": ["c"], "surface_ids": ["http-c"]}
FP = {"refuting_mechanism": "Argument escaping", "pivot_id": "pivot-1", "enabled_observation": "No shell path",
      "pivot_evidence": "Escaper at c:12", "component_path": "c"}
DUP = {"target_lane": "l-sink", "target_candidate_id": "shell-1", "dedup_evidence": "Same call"}


def decision(lane, identifier, verdict, variant):
    return {"lane": lane, "candidate_id": identifier, "verdict": verdict, "reason": "Source reread",
        "attacker_advantage": "Shell capability", "rules_applied": ["HE-17"], "mitigation_analysis": "Trim only",
        "confidence": 6, "true_positive": variant if verdict == "TRUE_POSITIVE" else None,
        "false_positive": variant if verdict == "FALSE_POSITIVE" else None,
        "duplicate": variant if verdict == "DUPLICATE" else None}


# Literal hand-ordered oracle: no production serializer or dataclass projection.
# Only the fixture's unpredictable provenance digests are substituted.
ORACLE = ('{"batch_path":"batch-0001.json","batch_sha256":"BATCH","candidate_snapshot_sha256":"SNAPSHOT",'
 '"decisions":[{"attacker_advantage":"Shell capability","candidate_id":"shell-1","confidence":6,'
 '"duplicate":{"dedup_evidence":"Same call","target_candidate_id":"shell-1","target_lane":"l-sink"},'
 '"false_positive":null,"lane":"l-dark","mitigation_analysis":"Trim only","reason":"Source reread",'
 '"rules_applied":["HE-17"],"true_positive":null,"verdict":"DUPLICATE"},'
 '{"attacker_advantage":"Shell capability","candidate_id":"pivot-source","confidence":6,"duplicate":null,'
 '"false_positive":{"component_path":"c","enabled_observation":"No shell path","pivot_evidence":"Escaper at c:12",'
 '"pivot_id":"pivot-1","refuting_mechanism":"Argument escaping"},"lane":"l-sink","mitigation_analysis":"Trim only",'
 '"reason":"Source reread","rules_applied":["HE-17"],"true_positive":null,"verdict":"FALSE_POSITIVE"},'
 '{"attacker_advantage":"Shell capability","candidate_id":"shell-1","confidence":6,"duplicate":null,'
 '"false_positive":null,"lane":"l-sink","mitigation_analysis":"Trim only","reason":"Source reread",'
 '"rules_applied":["HE-17"],"true_positive":{"attacker_position":"lan","component_paths":["c"],'
 '"data_flow":"POST to system","dedup_evidence":"Same call","impact_hypothesis":"Shell execution",'
 '"root_cause":"Unchecked shell input","root_cause_key":"shell","surface_ids":["http-c"]},'
 '"verdict":"TRUE_POSITIVE"}],"image_id":"target","schema_version":1,"worklist_sha256":"WORKLIST"}\n')


@pytest.fixture
def review(completed):
    con, run, root, _, sink, _ = completed
    sink = copy.deepcopy(sink)
    extra = copy.deepcopy(candidate(sink))
    extra["candidate_id"] = "pivot-source"
    sink["decisions"][2]["candidates"].append(extra)
    source = run / "extra-hunt.json"
    source.write_text(json.dumps(sink))
    hunt_results.record(con, run, source, replace=True)
    hunt.check(con, run, root, lane="l-sink")
    summary = firmware_fpcheck.prepare(con, run, root)
    index = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    batch = index["batches"][0]
    payload = {"schema_version": 1, "image_id": "target",
        "candidate_snapshot_sha256": summary.candidate_snapshot_sha256,
        "worklist_sha256": summary.worklist_sha256, "batch_path": batch["path"], "batch_sha256": batch["sha256"],
        "decisions": [decision("l-dark", "shell-1", "DUPLICATE", copy.deepcopy(DUP)),
                      decision("l-sink", "pivot-source", "FALSE_POSITIVE", copy.deepcopy(FP)),
                      decision("l-sink", "shell-1", "TRUE_POSITIVE", copy.deepcopy(TP))]}
    expected = ORACLE.replace("BATCH", batch["sha256"]).replace("SNAPSHOT", summary.candidate_snapshot_sha256)
    expected = expected.replace("WORKLIST", summary.worklist_sha256).encode()
    return con, run, root, summary, payload, expected


def load_payload(review, payload=None):
    path = review[1] / "review-result.json"
    path.write_text(json.dumps(review[4] if payload is None else payload), encoding="utf-8")
    return api().load(path)


def validate_payload(review):
    return api().validate(review[0], review[1], load_payload(review))


def test_literal_all_variants_are_immutable_canonical_and_validation_is_read_only(review):
    con, run, _, summary, _, expected = review
    result = load_payload(review)
    before, writes = state(con), con.total_changes
    files = {str(path): path.read_bytes() for path in run.rglob("*") if path.is_file()}
    validated = api().validate(con, run, result)
    assert validated.assigned_candidates == (("l-dark", "shell-1"), ("l-sink", "pivot-source"), ("l-sink", "shell-1"))
    assert validated.index_path == summary.worklist_path
    assert api().canonical_bytes(validated) == expected
    assert isinstance(validated.result.decisions[0].duplicate, api().Duplicate)
    assert isinstance(validated.result.decisions[1].false_positive, api().FalsePositive)
    assert isinstance(validated.result.decisions[2].true_positive, api().TruePositive)
    for row in (validated, validated.result, *validated.result.decisions,
                validated.result.decisions[0].duplicate, validated.result.decisions[1].false_positive,
                validated.result.decisions[2].true_positive):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(row, dataclasses.fields(row)[0].name, "changed")
    assert state(con) == before and con.total_changes == writes and not con.in_transaction
    assert {str(path): path.read_bytes() for path in run.rglob("*") if path.is_file()} == files


@pytest.mark.parametrize("raw", [b"\xff", b"{", b"[]", b"null", b"true", b"1",
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    b"[" * 1500 + b"]" * 1500, b" " * (8 * 1024 * 1024 + 1)])
def test_load_refuses_malformed_non_object_duplicate_nonfinite_and_oversized(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().load(path)


def test_duplicate_json_keys_are_rejected_in_otherwise_valid_result_and_variant_objects(review):
    raw = json.dumps(review[4])
    path = review[1] / "duplicate-key.json"
    for token in ('"schema_version": 1', '"verdict": "DUPLICATE"', '"target_lane": "l-sink"',
                  '"pivot_id": "pivot-1"', '"root_cause_key": "shell"'):
        path.write_text(raw.replace(token, token + "," + token, 1))
        with pytest.raises(firmware_fpcheck.FpcheckError, match="Duplicate JSON key"):
            api().load(path)


@pytest.mark.parametrize("kind", ["symlink", "directory", "missing"])
def test_load_requires_regular_file(tmp_path, kind):
    path = tmp_path / "bad.json"
    if kind == "symlink":
        target = tmp_path / "target.json"
        target.write_text("{}")
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().load(path)


@pytest.mark.parametrize("level", ["result", "decision", "true_positive", "false_positive", "duplicate"])
@pytest.mark.parametrize("damage", ["missing", "worker_timestamp", "artifact_path", "recorded_at"])
def test_exact_schema_keys_at_every_level(review, level, damage):
    payload = review[4]
    row = {"result": payload, "decision": payload["decisions"][0],
        "duplicate": payload["decisions"][0]["duplicate"], "false_positive": payload["decisions"][1]["false_positive"],
        "true_positive": payload["decisions"][2]["true_positive"]}[level]
    if damage == "missing":
        row.pop(next(iter(row)))
    else:
        row[damage] = "invented"
    with pytest.raises(firmware_fpcheck.FpcheckError):
        load_payload(review)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 1.0),
    ("schema_version", 2), ("image_id", ""), ("image_id", " "),
    ("candidate_snapshot_sha256", "A" * 64), ("worklist_sha256", "g" * 64), ("batch_sha256", "a" * 63),
    ("batch_path", "../batch-0001.json"), ("batch_path", "index.json"), ("decisions", {})])
def test_invalid_result_scalars(review, field, value):
    review[4][field] = value
    with pytest.raises(firmware_fpcheck.FpcheckError):
        load_payload(review)


@pytest.mark.parametrize("field,value", [("lane", "foreign"), ("candidate_id", "unsafe/id"),
    ("verdict", "true_positive"), ("confidence", True), ("confidence", 1.0),
    ("reason", " "), ("attacker_advantage", ""), ("mitigation_analysis", None),
    ("rules_applied", []), ("rules_applied", ["HE-1", "HE-1"]), ("rules_applied", ["bad/rule"]),
    ("rules_applied", ["x" * 129]), ("reason", "\ud800")])
def test_common_decision_contract(review, field, value):
    review[4]["decisions"][0][field] = value
    with pytest.raises(firmware_fpcheck.FpcheckError):
        load_payload(review)


@pytest.mark.parametrize("rule", [*(f"HE-{n}" for n in range(1, 19)), *(f"PR-{n}" for n in range(1, 11)),
    "CV-1", "CV-2", "CV-3", "MARGINAL-GAIN"])
def test_existing_rule_identifiers_are_supported(review, rule):
    review[4]["decisions"][0]["rules_applied"] = [rule]
    assert validate_payload(review).result.decisions[0].rules_applied == (rule,)


@pytest.mark.parametrize("rule", ["HE-0", "HE-19", "HE-01", "PR-11", "CV-4", "MarginalGain", "Marginal-Gain", "MG-1"])
def test_rule_identifiers_require_canonical_known_spelling(review, rule):
    review[4]["decisions"][0]["rules_applied"] = [rule]
    with pytest.raises(firmware_fpcheck.FpcheckError):
        load_payload(review)


@pytest.mark.parametrize("variant,field,value", [
    ("true_positive", "root_cause_key", "bad/key"), ("true_positive", "root_cause", " "),
    ("true_positive", "dedup_evidence", ""), ("true_positive", "attacker_position", ""),
    ("true_positive", "data_flow", ""), ("true_positive", "impact_hypothesis", ""),
    ("true_positive", "component_paths", []), ("true_positive", "component_paths", ["c", "c"]),
    ("true_positive", "component_paths", ["../c"]), ("true_positive", "surface_ids", ["http-c", "http-c"]),
    ("true_positive", "surface_ids", ["bad/id"]), ("false_positive", "pivot_id", "bad/id"),
    ("false_positive", "refuting_mechanism", ""), ("false_positive", "enabled_observation", " "),
    ("false_positive", "pivot_evidence", ""), ("false_positive", "component_path", "/c"),
    ("duplicate", "target_lane", "foreign"), ("duplicate", "target_candidate_id", "bad/id"),
    ("duplicate", "dedup_evidence", "")])
def test_variant_fields_are_strict(review, variant, field, value):
    position = {"duplicate": 0, "false_positive": 1, "true_positive": 2}[variant]
    review[4]["decisions"][position][variant][field] = value
    with pytest.raises(firmware_fpcheck.FpcheckError):
        load_payload(review)


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("damage", ["missing", "multiple", "mismatch"])
def test_variants_are_mutually_exclusive_and_match_verdict(review, position, damage):
    row = review[4]["decisions"][position]
    own = [name for name in ("true_positive", "false_positive", "duplicate") if row[name] is not None][0]
    if damage == "missing":
        row[own] = None
    elif damage == "multiple":
        row["false_positive" if own != "false_positive" else "true_positive"] = copy.deepcopy(FP if own != "false_positive" else TP)
    else:
        row["verdict"] = "TRUE_POSITIVE" if position != 2 else "FALSE_POSITIVE"
    with pytest.raises(firmware_fpcheck.FpcheckError):
        load_payload(review)


@pytest.mark.parametrize("damage", ["image", "snapshot", "worklist", "batch", "missing", "extra", "duplicate", "same-id-other-lane"])
def test_exact_provenance_and_lane_qualified_assignment(review, damage):
    payload = review[4]
    field = {"image": "image_id", "snapshot": "candidate_snapshot_sha256", "worklist": "worklist_sha256", "batch": "batch_sha256"}.get(damage)
    if field:
        payload[field] = "foreign" if field == "image_id" else "0" * 64
    elif damage == "missing":
        payload["decisions"].pop()
    elif damage == "extra":
        payload["decisions"].append(decision("l-dark", "foreign", "TRUE_POSITIVE", copy.deepcopy(TP)))
    elif damage == "duplicate":
        payload["decisions"].append(copy.deepcopy(payload["decisions"][0]))
    else:
        payload["decisions"][1]["lane"] = "l-dark"
    before, writes = state(review[0]), review[0].total_changes
    with pytest.raises(firmware_fpcheck.FpcheckError):
        validate_payload(review)
    assert state(review[0]) == before and review[0].total_changes == writes


@pytest.mark.parametrize("damage", ["missing-hunt", "missing-run", "index-shape", "index-size", "orphan-completion",
    "pending-hunt", "run-snapshot", "run-status", "run-count", "index-drift", "batch-drift", "index-path", "symlink-parent"])
def test_stale_pending_runs_or_canonical_worklist_drift_are_rejected(review, tmp_path, damage):
    con, _, _, summary, *_ = review
    index = pathlib.Path(summary.worklist_path)
    if damage == "missing-hunt":
        con.execute("DELETE FROM cba_hunt_runs WHERE lane='l-dark'")
    elif damage == "missing-run":
        con.execute("DELETE FROM cba_firmware_fp_runs")
    elif damage == "index-shape":
        index.write_text("[]")
    elif damage == "index-size":
        content = json.loads(index.read_bytes())
        content["batch_size"] = True
        index.write_text(json.dumps(content))
    elif damage == "orphan-completion":
        con.execute("UPDATE cba_firmware_fp_runs SET completed_at='orphan'")
    elif damage == "pending-hunt":
        con.execute("UPDATE cba_hunt_runs SET status='pending',completed_at=NULL WHERE lane='l-dark'")
    elif damage == "run-snapshot":
        con.execute("UPDATE cba_firmware_fp_runs SET candidate_snapshot_sha256=?", ("0" * 64,))
    elif damage == "run-status":
        con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at=NULL")
    elif damage == "run-count":
        con.execute("UPDATE cba_firmware_fp_runs SET candidate_count=20")
    elif damage == "index-drift":
        index.write_bytes(index.read_bytes() + b" ")
    elif damage == "batch-drift":
        batch = index.with_name("batch-0001.json")
        batch.write_bytes(batch.read_bytes() + b" ")
    elif damage == "index-path":
        outside = tmp_path / "index.json"
        outside.write_bytes(index.read_bytes())
        con.execute("UPDATE cba_firmware_fp_runs SET worklist_path=?", (str(outside),))
    else:
        outside = tmp_path / "outside"
        index.parent.rename(outside)
        index.parent.symlink_to(outside, target_is_directory=True)
    con.commit()
    before, writes = state(con), con.total_changes
    with pytest.raises(firmware_fpcheck.FpcheckError):
        validate_payload(review)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


def test_complete_current_generation_remains_valid_for_replace_and_idempotent_check(review):
    con = review[0]
    con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at='2026-10-23 00:00:00'")
    con.commit()
    before, writes = state(con), con.total_changes
    assert len(validate_payload(review).result.decisions) == 3
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("timestamp", ["", " "])
def test_complete_status_requires_nonempty_completion_timestamp(review, timestamp):
    con = review[0]
    con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at=?", (timestamp,))
    con.commit()
    before, writes = state(con), con.total_changes
    with pytest.raises(firmware_fpcheck.FpcheckError):
        validate_payload(review)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction


@pytest.mark.parametrize("variant,field,value", [("true_positive", "component_paths", ["foreign"]),
    ("true_positive", "surface_ids", ["foreign"]), ("false_positive", "component_path", "foreign"),
    ("duplicate", "target_candidate_id", "foreign"), ("duplicate", "target_lane", "l-dark")])
def test_variant_ownership_and_duplicate_target_are_current_image_evidence(review, variant, field, value):
    # Foreign evidence exists durably; an unqualified path/ID lookup would accept it.
    con = review[0]
    db.put(con, "cba_images", {"id": "foreign", "role": "target", "vendor": "v",
        "model": "m", "version": "2", "path": "foreign.bin", "sha256": "f" * 64})
    component = dict(con.execute("SELECT * FROM cba_firmware_files WHERE image_id='target' AND path='c'").fetchone())
    db.put(con, "cba_firmware_files", component | {"image_id": "foreign", "path": "foreign"})
    surface_row = dict(con.execute("SELECT * FROM cba_firmware_surfaces WHERE image_id='target'").fetchone())
    db.put(con, "cba_firmware_surfaces", surface_row | {"image_id": "foreign", "surface_id": "foreign", "component_path": "foreign"})
    position = {"duplicate": 0, "false_positive": 1, "true_positive": 2}[variant]
    review[4]["decisions"][position][variant][field] = value
    with pytest.raises(firmware_fpcheck.FpcheckError):
        validate_payload(review)


def test_current_image_components_can_extend_original_candidate_and_unmapped_surface_is_allowed(review):
    # Ownership is selected-image evidence, not merely the original candidate path.
    row = review[4]["decisions"][2]["true_positive"]
    row["component_paths"] = ["a", "c"]
    row["surface_ids"] = []
    review[4]["decisions"][1]["false_positive"]["component_path"] = "b"
    assert validate_payload(review).result.decisions[2].true_positive.component_paths == ("a", "c")
    row["component_paths"] = ["a"]
    row["surface_ids"] = ["http-c"]
    with pytest.raises(firmware_fpcheck.FpcheckError):
        validate_payload(review)


def test_duplicate_target_in_another_batch_is_allowed_and_global_resolution_is_deferred(review):
    con, run, root, _, payload, _ = review
    summary = firmware_fpcheck.prepare(con, run, root, batch_size=1)
    index = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    for descriptor in index["batches"]:
        batch = json.loads(pathlib.Path(summary.worklist_path).with_name(descriptor["path"]).read_bytes())
        if [(row["lane"], row["candidate_id"]) for row in batch["candidates"]] == [("l-dark", "shell-1")]:
            payload.update(worklist_sha256=summary.worklist_sha256, batch_path=descriptor["path"], batch_sha256=descriptor["sha256"])
            break
    else:
        pytest.fail("fixture must have an independent dark batch")
    payload["decisions"] = [payload["decisions"][0]]
    payload["decisions"][0]["duplicate"]["target_candidate_id"] = "pivot-source"
    assert validate_payload(review).result.decisions[0].duplicate.target_candidate_id == "pivot-source"


def test_public_constructors_cannot_bypass_validation_and_membership_precedes_ownership(review):
    result = load_payload(review)
    forged = dataclasses.replace(result, decisions=(dataclasses.replace(result.decisions[0],
        candidate_id="unassigned", duplicate=dataclasses.replace(result.decisions[0].duplicate,
            target_candidate_id="unknown")),))
    with pytest.raises(firmware_fpcheck.FpcheckError, match="membership"):
        api().validate(review[0], review[1], forged)
    forged = dataclasses.replace(forged, decisions=(dataclasses.replace(forged.decisions[0], confidence=-1),))
    with pytest.raises(firmware_fpcheck.FpcheckError, match="membership"):
        api().validate(review[0], review[1], forged)
    forged = dataclasses.replace(forged, decisions=(dataclasses.replace(forged.decisions[0],
        reason="", true_positive=result.decisions[2].true_positive),))
    with pytest.raises(firmware_fpcheck.FpcheckError, match="membership"):
        api().validate(review[0], review[1], forged)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().validate(review[0], review[1], object())
    forged = dataclasses.replace(result, decisions=(dataclasses.replace(result.decisions[0], confidence=True), *result.decisions[1:]))
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().validate(review[0], review[1], forged)


def test_validation_is_read_only_inside_caller_transaction_and_without_live_root(review):
    con, run, root, *_ = review
    # This API has no root parameter. Prepare/final check own live-root revalidation.
    (root / "c").write_bytes(b"changed")
    result = load_payload(review)
    with sqlite3.connect(f"file:{run / 'audit.db'}?mode=ro", uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert len(api().validate(readonly, run, result).result.decisions) == 3
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute("UPDATE cba_firmware_fp_runs SET prepared_at='caller-owned'")
    before, writes = state(con), con.total_changes
    api().validate(con, run, result)
    assert con.in_transaction and state(con) == before and con.total_changes == writes
    con.rollback()


def test_closed_database_is_domain_error(review):
    result = load_payload(review)
    review[0].close()
    with pytest.raises(firmware_fpcheck.FpcheckError):
        api().validate(review[0], review[1], result)


@pytest.mark.parametrize("confidence", [-1, 11])
def test_confidence_range_is_validated_after_assignment_not_during_load(review, confidence):
    review[4]["decisions"][0]["confidence"] = confidence
    result = load_payload(review)
    assert result.decisions[0].confidence == confidence
    with pytest.raises(firmware_fpcheck.FpcheckError, match="confidence"):
        api().validate(review[0], review[1], result)


def test_unicode_delimiter_image_ids_preserve_existing_image_identity_contract(tmp_path):
    run = workspace.init_run(tmp_path / "project", timestamp="20261019-000000")
    with db.connect(run / "audit.db") as con:
        for number, image in enumerate(("a:%_图像", "a:%_图像:other")):
            root = tmp_path / f"root-{number}"
            add_target(con, run, root, ["a", "b"], image_id=image)
            summary = hunt.prepare(con, run, root, image_id=image)
            fill(con, run, summary)
            for lane in db.HUNT_LANES:
                hunt.check(con, run, root, image_id=image, lane=lane)
            summary = firmware_fpcheck.prepare(con, run, root, image_id=image)
            descriptor = json.loads(pathlib.Path(summary.worklist_path).read_bytes())["batches"][0]
            path = run / "empty-review.json"
            path.write_text(json.dumps({"schema_version": 1, "image_id": image,
                "candidate_snapshot_sha256": summary.candidate_snapshot_sha256,
                "worklist_sha256": summary.worklist_sha256, "batch_path": descriptor["path"],
                "batch_sha256": descriptor["sha256"], "decisions": []}))
            before, writes = state(con), con.total_changes
            validated = api().validate(con, run, api().load(path))
            assert validated.assigned_candidates == () and validated.result.image_id == image
            assert state(con) == before and con.total_changes == writes and not con.in_transaction


def test_exact_raw_8_mib_with_canonical_expansion_is_rejected(review):
    payload = review[4]
    # Canonical JSON adds a newline: exact compact raw expands by one byte.
    payload["decisions"][0]["reason"] = "x"
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    payload["decisions"][0]["reason"] = "x" * (8 * 1024 * 1024 - len(raw) + 1)
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    assert len(raw) == 8 * 1024 * 1024
    path = review[1] / "boundary.json"
    path.write_bytes(raw)
    with pytest.raises(firmware_fpcheck.FpcheckError, match="[Cc]anonical|size"):
        api().load(path)


def test_exact_canonical_8_mib_is_accepted(review):
    payload = review[4]
    raw = json.dumps(payload, separators=(",", ":")).encode()
    payload["decisions"][0]["reason"] += "x" * (8 * 1024 * 1024 - len(raw) - 1)
    path = review[1] / "boundary.json"
    path.write_text(json.dumps(payload, separators=(",", ":")))
    validated = api().validate(review[0], review[1], api().load(path))
    assert len(api().canonical_bytes(validated)) == 8 * 1024 * 1024


def test_validation_remains_read_only_after_batch_publication(review):
    result = load_payload(review)
    api().record(review[0], review[1], review[1] / "review-result.json")
    before, writes = state(review[0]), review[0].total_changes
    validated = api().validate(review[0], review[1], result)
    assert len(validated.assigned_candidates) == 3
    assert state(review[0]) == before and review[0].total_changes == writes and not review[0].in_transaction
