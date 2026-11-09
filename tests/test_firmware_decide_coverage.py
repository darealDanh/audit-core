"""Behavior regressions for the Stage 4i zero-allowance coverage failure.

Each test/docstring names the production mutation or authority break it catches.
Malformed frozen inputs use real JSON, hashes, files and SQL; publication races
wrap the real installer and keep its filesystem effects.
"""
import copy
import dataclasses
import hashlib
import json
import os
import sqlite3
import threading

import pytest

from audit_core import db, firmware_decide as decide
from audit_core import firmware_decide_results as results, firmware_dive as dive
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_policy import POLICY, RAW, write_policy
from tests.test_firmware_decide_package import completed_pipeline  # noqa: F401
from tests.test_firmware_decide_results import bench_id, decision_assignment  # noqa: F401
from tests.test_firmware_decide_schema import BASE, RECORDED, COMPLETE, con as schema_con  # noqa: F401
from tests.test_hunt_gate import state


def encoded(body, *, canonical=False):
    if canonical:
        return (json.dumps(body, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")) + "\n").encode()
    # ASCII escapes allow hostile lone surrogates to reach the real UTF-8 parser.
    return json.dumps(body, ensure_ascii=True).encode()


@pytest.fixture
def worker_body():
    """A small literal worker answer; no expensive graph setup for syntax tests."""
    return {
        "schema_version": 1, "image_id": "target",
        "decision_generation": "a" * 64, "worklist_sha256": "a" * 64,
        "answer": {"kind": "decision", "chain_assessments": [{
            "chain_id": "chain-a", "rank": 1, "initial_attacker_position": "LAN",
            "pre_auth": "yes", "confidence": 8, "completeness": "blocked",
            "evidence_rung": "static-chained", "member_ids": ["finding-a"],
            "edge_ordinals": [0], "open_preconditions": [{
                "kind": "unknown", "precondition_id": "unknown:question-a",
                "source_id": "question-a", "question": "Is the state present?",
                "settling_observation": "Observe the state on the unit.",
                "method": "hardware", "axes": [],
                "locations": [{"chain_id": "chain-a", "edge_ordinal": None}],
            }], "disposition": "retain", "rationale": "Inspect the recorded state.",
            "limitations": [], "evidence_refs": ["finding:finding-a#data_flow"],
        }], "bench_tests": [{
            "test_id": "firmware-decide-test-" + "b" * 64,
            "chain_ids": ["chain-a"], "subject_refs": ["unknown:question-a"],
            "title": "Observe state", "purpose": "Settle the question",
            "required_state": {"device": "target", "firmware": "c" * 64,
                               "lifecycle": "provisioned", "posture": "STA-LAN",
                               "authentication": "pre-auth"},
            "setup_steps": ["Prepare unit"], "action_steps": ["Inspect state"],
            "expected_signal": "State is present", "control_observation": "Absent in control",
            "stop_conditions": ["Unexpected state"], "limitations": [],
            "script_name": None,
        }], "proposed_scripts": []},
    }


@pytest.mark.parametrize("damage,match", [
    ("surrogate", "UTF-8"), ("empty-paths", "payout_paths"),
    ("empty-tiers", "tiers"), ("decreasing-tier", "monotonic"),
    ("duplicate-tier", "unique tier_id"), ("many-notes", "64 strings"),
    ("duplicate-notes", "sorted unique"),
])
def test_policy_rejects_authority_and_resource_bound_bypasses(tmp_path, damage, match):
    """Catches accepting malformed policy text, denominators, ranges or identities."""
    body = copy.deepcopy(POLICY)
    if damage == "surrogate":
        body["support_basis"] = "\ud800"
    elif damage == "empty-paths":
        body["payout_paths"] = []
    elif damage == "empty-tiers":
        body["tiers"] = []
    elif damage == "decreasing-tier":
        body["tiers"][1].update(payout_path_id="vendor-vdp")
    elif damage == "duplicate-tier":
        body["tiers"][1]["tier_id"] = body["tiers"][0]["tier_id"]
    elif damage == "many-notes":
        body["notes"] = ["note"] * 65
    else:
        body["notes"] *= 2
    path = tmp_path / "policy.json"
    path.write_bytes(encoded(body))
    with pytest.raises(decide.FirmwareDecideError, match=match):
        decide.load_policy(path)


def test_policy_serialization_refuses_wrong_records_and_unencodable_values():
    """Catches publishing bytes from a non-policy or an unencodable frozen record."""
    with pytest.raises(decide.FirmwareDecideError, match="frozen DecisionPolicy"):
        decide.policy_bytes(POLICY)
    policy = dataclasses.replace(decide._parse(RAW), support_basis="\ud800")
    with pytest.raises(decide.FirmwareDecideError, match="cannot be canonicalized"):
        decide.policy_bytes(policy)
    with pytest.raises(decide.FirmwareDecideError, match="cannot be canonicalized"):
        decide._canonical({"unencodable": "\ud800"})


def test_missing_input_files_raise_domain_errors(tmp_path):
    """Catches leaking raw OS failures or treating missing policy/results as empty."""
    with pytest.raises(decide.FirmwareDecideError, match="cannot read policy"):
        decide.load_policy(tmp_path / "missing-policy.json")
    with pytest.raises(results.FirmwareDecideResultError, match="cannot read decision result"):
        results.load(tmp_path / "missing-result.json")


@pytest.mark.parametrize("field", ["result_path", "result_sha256", "recorded_at"])
def test_recorded_contract_requires_result_ownership(schema_con, field):
    """Catches accepting recorded SQL authority with missing result ownership."""
    before = schema_con.total_changes
    with pytest.raises(db.DbError, match=field):
        db.put(schema_con, "cba_firmware_decide_runs", RECORDED | {field: None})
    assert schema_con.total_changes == before and not schema_con.in_transaction


@pytest.mark.parametrize("status", ["pending", "recorded"])
@pytest.mark.parametrize("field", ["bench_test_count", "script_count", "policy_match_count"])
def test_uncompleted_contract_cannot_claim_derived_counts(schema_con, status, field):
    """Catches granting completion-derived counts to pending/recorded authority."""
    row = BASE if status == "pending" else RECORDED
    with pytest.raises(db.DbError, match="must be zero"):
        db.put(schema_con, "cba_firmware_decide_runs", row | {field: 1})
    assert schema_con.total_changes == 0 and not schema_con.in_transaction


@pytest.mark.parametrize("damage,match", [
    ("digest", "lowercase SHA-256"), ("chain-id", "safe identifier"),
    ("empty-image", "nonempty UTF-8"), ("surrogate-image", "image_id requires UTF-8"),
    ("large-image", "byte bound"), ("surrogate-text", "requires UTF-8"),
    ("large-text", "text bounds"), ("empty-steps", "bounded ordered array"),
    ("duplicate-steps", "unique steps"), ("kind", "kind is invalid"),
    ("empty-members", "bounded ordered array"),
    ("duplicate-members", "unique entries"),
    ("empty-question", "nonempty copied text"),
    ("nul-question", "without NUL"), ("surrogate-question", "requires UTF-8"),
    ("precondition-id", "identity differs"), ("method", "method is invalid"),
    ("pre_auth", "pre_auth is invalid"), ("completeness", "completeness is invalid"),
    ("evidence_rung", "evidence_rung is invalid"), ("test-id", "test_id is invalid"),
    ("surrogate-script", "script requires UTF-8"), ("generation", "must equal worklist"),
])
def test_worker_parser_rejects_invalid_authority_before_use(tmp_path, worker_body, damage, match):
    """Catches relaxing worker identity, text, enum, step or script validation."""
    body = worker_body
    assessment = body["answer"]["chain_assessments"][0]
    test = body["answer"]["bench_tests"][0]
    precondition = assessment["open_preconditions"][0]
    if damage == "digest":
        body["decision_generation"] = "A" * 64
    elif damage == "chain-id":
        assessment["chain_id"] = "../outside"
    elif damage == "empty-image":
        body["image_id"] = ""
    elif damage == "surrogate-image":
        body["image_id"] = "\ud800"
    elif damage == "large-image":
        body["image_id"] = "é" * 2049
    elif damage == "surrogate-text":
        assessment["rationale"] = "\ud800"
    elif damage == "large-text":
        assessment["rationale"] = "x" * (16 * 1024 + 1)
    elif damage == "empty-steps":
        test["setup_steps"] = []
    elif damage == "duplicate-steps":
        test["action_steps"] *= 2
    elif damage == "empty-members":
        assessment["member_ids"] = []
    elif damage == "duplicate-members":
        assessment["member_ids"] *= 2
    elif damage == "empty-question":
        precondition["question"] = ""
    elif damage == "nul-question":
        precondition["settling_observation"] = "state\0"
    elif damage == "surrogate-question":
        precondition["question"] = "\ud800"
    elif damage == "kind":
        precondition["kind"] = "finding"
    elif damage == "precondition-id":
        precondition["precondition_id"] = "unknown:foreign"
    elif damage == "method":
        precondition["method"] = "guess"
    elif damage in ("pre_auth", "completeness", "evidence_rung"):
        assessment[damage] = "invented"
    elif damage == "test-id":
        test["test_id"] = "foreign"
    elif damage == "surrogate-script":
        body["answer"]["proposed_scripts"] = [{"name": "inspect.sh", "content": "\ud800"}]
    else:
        body["worklist_sha256"] = "b" * 64
    path = tmp_path / "worker.json"
    path.write_bytes(encoded(body))
    with pytest.raises(results.FirmwareDecideResultError, match=match):
        results.load(path)


def test_optional_script_and_canonical_result_boundaries(worker_body, tmp_path):
    """Catches requiring scripts, bypassing result type/variant checks or byte bounds."""
    path = tmp_path / "worker.json"
    path.write_bytes(encoded(worker_body))
    parsed = results.load(path)
    assert parsed.answer.bench_tests[0].script_name is None
    assert parsed.answer.proposed_scripts == ()
    with pytest.raises(results.FirmwareDecideResultError):
        results.canonical_bytes({})
    with pytest.raises(results.FirmwareDecideResultError):
        results.canonical_bytes(dataclasses.replace(parsed, answer="invented"))
    with pytest.raises(results.FirmwareDecideResultError, match="cannot be canonicalized"):
        results.canonical_bytes(dataclasses.replace(parsed, image_id="\ud800"))
    with pytest.raises(results.FirmwareDecideResultError, match="exceeds 8 MiB"):
        results.canonical_bytes(dataclasses.replace(parsed, image_id="x" * (8 * 1024 * 1024)))


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{'])
def test_assignment_json_rejects_ambiguous_or_malformed_authority(raw):
    """Catches duplicate/nonfinite or malformed frozen worklist JSON acceptance."""
    with pytest.raises(results.FirmwareDecideResultError):
        results._strict_json(raw, "worklist")


@pytest.mark.parametrize("kind", ["blockers", "unknowns"])
def test_graph_denominator_cannot_silently_drop_missing_subjects(decision_case, kind):
    """Catches omission of a referenced blocker/unknown from the frozen denominator."""
    graph = dataclasses.replace(decision_case[3], **{kind: ()})
    with pytest.raises(decide.FirmwareDecideError, match="denominator is not exact and open"):
        decide._open_preconditions(graph)


@pytest.mark.parametrize("damage,match", [
    ("missing", "No prepared"), ("pending", "not recorded"),
    ("multi-active", "Multiple active"), ("no-complete", "No current"),
    ("superseded", "No current"), ("tie", "Latest prepared"),
    ("implicit-empty", "exactly one"), ("implicit-multiple", "exactly one"),
])
def test_row_selection_refuses_missing_ambiguous_or_unrecorded_authority(schema_con, damage, match):
    """Catches silently selecting missing, unfinished, superseded, ambiguous or invalid SQL state."""
    image = "target"
    if damage not in ("missing", "implicit-empty"):
        base = COMPLETE if damage == "tie" else BASE
        db.put(schema_con, "cba_firmware_decide_runs", base | {"image_id": image})
    if damage in ("multi-active", "tie"):
        db.put(schema_con, "cba_firmware_decide_runs", base | {
            "image_id": image, "decision_generation": "b" * 64})
    elif damage == "implicit-multiple":
        db.put(schema_con, "cba_firmware_decide_runs", BASE | {"image_id": "sibling"})
    elif damage == "no-complete":
        schema_con.execute("UPDATE cba_firmware_decide_runs SET status='invalid'")
        schema_con.commit()
    elif damage == "superseded":
        schema_con.execute("UPDATE cba_firmware_decide_runs SET status='superseded',"
                           "superseded_at=prepared_at")
        schema_con.commit()
    before = state(schema_con)
    with pytest.raises(decide.FirmwareDecideError, match=match):
        decide._select_decision_row(schema_con, None if damage.startswith("implicit") else image)
    assert state(schema_con) == before


@pytest.mark.parametrize("damage", ["malformed", "missing", "foreign"])
def test_verified_package_rejects_invalid_image_identity(
        completed_pipeline, damage):
    """Catches accepting an invalid or non-owner cba_images projection."""
    pipeline, _ = completed_pipeline
    con, run, root = pipeline[0][:3]
    if damage == "malformed":
        con.execute("UPDATE cba_images SET sha256=? WHERE id='target'", ("A" * 64,))
    elif damage == "missing":
        con.execute("DELETE FROM cba_images WHERE id='target'")
    else:
        con.execute("UPDATE cba_images SET role='diff-reference' WHERE id='target'")
    con.commit()
    before, changes = state(con), con.total_changes
    with pytest.raises(decide.FirmwareDecideError):
        decide.verified_package(con, run, root, image_id="target")
    assert state(con) == before and con.total_changes == changes
    assert not con.in_transaction


def test_row_selection_prefers_latest_preparation_over_completion_time(schema_con):
    """Catches selecting by completed_at instead of the most recent prepare."""
    db.put(schema_con, "cba_firmware_decide_runs", COMPLETE | {"preparation_ordinal": 2})
    db.put(schema_con, "cba_firmware_decide_runs", COMPLETE | {
        "decision_generation": "b" * 64, "preparation_ordinal": 1,
        "completed_at": "2026-12-31 00:00:00"})
    db.put(schema_con, "cba_firmware_decide_runs", BASE | {
        "decision_generation": "c" * 64, "preparation_ordinal": 3,
        "status": "superseded", "superseded_at": "2026-12-31 00:00:00"})
    row = decide._select_decision_row(schema_con, BASE["image_id"])
    assert row["decision_generation"] == COMPLETE["decision_generation"]


def test_implicit_single_image_selection_preserves_exact_identity(schema_con):
    """Catches rejecting a unique implicit image or selecting another image's authority."""
    db.put(schema_con, "cba_firmware_decide_runs", RECORDED)
    row = decide._select_decision_row(schema_con, None)
    assert row["image_id"] == "路由器|r1|target" and row["status"] == "recorded"


@pytest.mark.parametrize("operation", ["prepare", "record", "check"])
def test_mutating_boundaries_preserve_caller_owned_transaction(schema_con, tmp_path, operation):
    """Catches committing/rolling back caller work through decision write boundaries."""
    schema_con.execute("BEGIN")
    db.put(schema_con, "cba_firmware_decide_runs", BASE, commit=False)
    before = state(schema_con)
    error = results.FirmwareDecideResultError if operation == "record" else decide.FirmwareDecideError
    with pytest.raises(error, match="active caller transaction"):
        if operation == "prepare":
            decide.prepare(schema_con, tmp_path, tmp_path, tmp_path / "policy.json")
        elif operation == "record":
            results.record(schema_con, tmp_path, tmp_path / "result.json")
        else:
            decide.check(schema_con, tmp_path, tmp_path)
    assert schema_con.in_transaction and state(schema_con) == before
    schema_con.rollback()
    assert not db.rows(schema_con, "cba_firmware_decide_runs")


def test_validation_rejects_nonresult_without_touching_sql(schema_con, tmp_path):
    """Catches accepting arbitrary objects as authoritative validated worker results."""
    before = schema_con.total_changes
    with pytest.raises(results.FirmwareDecideResultError, match="requires a DecisionResult"):
        results.validate(schema_con, tmp_path, {})
    assert schema_con.total_changes == before and not schema_con.in_transaction


def test_closed_database_failures_remain_domain_errors(tmp_path):
    """Catches raw SQLite errors escaping read-only package and dive input boundaries."""
    con = sqlite3.connect(":memory:")
    con.close()
    with pytest.raises(decide.FirmwareDecideError, match="database operation failed"):
        decide.verified_package(con, tmp_path, tmp_path)
    with pytest.raises(dive.FirmwareDiveError, match="database operation failed"):
        dive.verified_decision_input(con, tmp_path, tmp_path, None)


def replace_worklist(assignment, worklist, *, raw=None):
    """Publish controlled hash-consistent hostile assignment bytes using real SQL."""
    case, summary, _, body, _ = assignment
    con, run = case[:2]
    raw = encoded(worklist, canonical=True) if raw is None else raw
    digest = hashlib.sha256(raw).hexdigest()
    (run / summary.worklist_path).write_bytes(raw)
    con.execute("UPDATE cba_firmware_decide_runs SET decision_generation=?,worklist_sha256=? "
                "WHERE image_id='target'", (digest, digest))
    con.commit()
    worker = copy.deepcopy(body)
    worker.update(decision_generation=digest, worklist_sha256=digest)
    return worker


@pytest.mark.parametrize("damage,match", [
    ("result-worklist", "differs from assignment worklist"),
    ("noncanonical", "not canonical"), ("identity", "worklist identity"),
    ("technical", "technical provenance"), ("dive", "dive provenance"),
    ("policy", "policy provenance"), ("policy-path", "policy path"),
    ("projection", "policy differs"), ("graph-image", "graph identity"),
    ("graph-owner", "graph ownership"),
])
def test_frozen_assignment_refuses_hash_consistent_provenance_forgery(decision_assignment, damage, match):
    """Catches trusting frozen hashes without checking each independent ownership axis."""
    case, _, frozen, _, path = decision_assignment
    con, run = case[:2]
    worklist = copy.deepcopy(frozen)
    if damage == "result-worklist":
        parsed = dataclasses.replace(results.load(path), worklist_sha256="0" * 64)
    else:
        if damage == "identity":
            worklist["image_id"] = "foreign"
        elif damage == "technical":
            worklist["technical_provenance"]["graph_sha256"] = "0" * 64
        elif damage == "dive":
            worklist["dive"]["overlay_sha256"] = "0" * 64
        elif damage == "policy":
            worklist["policy"]["policy_id"] = "foreign-policy"
        elif damage == "policy-path":
            worklist["policy"]["path"] = "foreign.json"
        elif damage == "projection":
            worklist["policy"]["projection"]["support_basis"] = "Forged operator basis"
        elif damage == "graph-image":
            worklist["graph"]["image_id"] = "foreign"
        elif damage == "graph-owner":
            worklist["graph"]["graph_path"] = "artifacts/foreign.json"
        raw = encoded(worklist) if damage == "noncanonical" else None
        worker = replace_worklist(decision_assignment, worklist, raw=raw)
        parsed = results._parse(encoded(worker))
    before, changes = state(con), con.total_changes
    with pytest.raises(results.FirmwareDecideResultError, match=match):
        results.validate(con, run, parsed)
    assert state(con) == before and con.total_changes == changes and not con.in_transaction


@pytest.mark.parametrize("damage,match", [
    ("overlay", "overlay is invalid"), ("observation", "observation is invalid"),
    ("collections", "graph collections"), ("empty", "explicit empty"),
    ("coverage", "exactly cover"), ("rank", "contiguous"),
])
def test_assessment_boundary_rejects_inexact_graph_and_evidence_denominators(
        decision_assignment, damage, match):
    """Catches treating malformed graph/overlay data or partial ranks as authority."""
    _, _, frozen, _, path = decision_assignment
    worklist = copy.deepcopy(frozen)
    answer = results.load(path).answer
    if damage == "overlay":
        worklist["dive"]["overlay"] = {}
    elif damage == "observation":
        worklist["dive"]["overlay"]["observations"] = [None]
    elif damage == "collections":
        worklist["graph"]["edges"] = {}
    elif damage == "empty":
        worklist["graph"]["chains"] = []
    elif damage == "coverage":
        answer = dataclasses.replace(answer, chain_assessments=())
    else:
        assessment = dataclasses.replace(answer.chain_assessments[0], rank=2)
        answer = dataclasses.replace(answer, chain_assessments=(assessment,))
    with pytest.raises(results.FirmwareDecideResultError, match=match):
        results._validate_assessments(answer, worklist, results._expected_preconditions(worklist))


@pytest.mark.parametrize("damage,match", [
    ("missing-edge", "foreign edge"), ("subject", "current precondition or transition"),
    ("foreign-chain", "foreign chain"), ("owner", "chain ownership"),
    ("unused-script", "every proposed script"),
])
def test_bench_boundary_rejects_foreign_subject_ownership_and_unused_scripts(
        decision_assignment, damage, match):
    """Catches broadening bench authority or smuggling an unreferenced script."""
    _, _, frozen, _, path = decision_assignment
    worklist = copy.deepcopy(frozen)
    answer = results.load(path).answer
    test = answer.bench_tests[0]
    preconditions = results._expected_preconditions(worklist)
    if damage == "missing-edge":
        precondition = dataclasses.replace(preconditions[0], locations=(
            results.PreconditionLocation(test.chain_ids[0], 999),))
        preconditions = (precondition,)
        test = dataclasses.replace(test, subject_refs=(precondition.precondition_id,))
    elif damage == "subject":
        test = dataclasses.replace(test, subject_refs=("finding:foreign",))
    elif damage == "foreign-chain":
        test = dataclasses.replace(test, chain_ids=("foreign",))
    elif damage == "owner":
        other = copy.deepcopy(worklist["graph"]["chains"][0])
        other["chain_id"] = "other"
        worklist["graph"]["chains"].append(other)
        test = dataclasses.replace(test, chain_ids=tuple(sorted((*test.chain_ids, "other"))))
    else:
        answer = dataclasses.replace(answer, proposed_scripts=(*answer.proposed_scripts,
            results.ProposedScript("unused.sh", "echo proposed-unreviewed\n")))
    # Independent existing test helper computes the semantic worker identity.
    wire = dataclasses.asdict(test)
    test = dataclasses.replace(test, test_id=bench_id(wire))
    answer = dataclasses.replace(answer, bench_tests=(test,))
    with pytest.raises(results.FirmwareDecideResultError, match=match):
        results._validate_bench(answer, worklist, preconditions)


def test_chain_level_precondition_bench_keeps_initial_state_authority(decision_assignment):
    """Catches losing chain-only subjects or assigning them edge-local state."""
    case, _, frozen, body, _ = decision_assignment
    worklist = copy.deepcopy(frozen)
    precondition = worklist["open_preconditions"][0]
    precondition["locations"] = [{"chain_id": worklist["graph"]["chains"][0]["chain_id"],
                                  "edge_ordinal": None}]
    worker = replace_worklist(decision_assignment, worklist)
    assessment = worker["answer"]["chain_assessments"][0]
    assessment["open_preconditions"] = copy.deepcopy(worklist["open_preconditions"])
    test = worker["answer"]["bench_tests"][0]
    test["subject_refs"] = [precondition["precondition_id"]]
    test["script_name"] = None
    test["test_id"] = bench_id(test)
    worker["answer"]["proposed_scripts"] = []
    validated = results.validate(case[0], case[1], results._parse(encoded(worker)))
    assert validated.bench_tests[0].subject_refs == (precondition["precondition_id"],)
    assert validated.scripts == ()
    assert validated.bench_tests[0].required_state.authentication == "pre-auth"


@pytest.mark.parametrize("damage,match", [("another-active", "generation is active"),
                                        ("drift", "differs from current authority")])
def test_reprepare_refuses_existing_generation_authority_conflicts(
        decision_assignment, tmp_path, damage, match):
    """Catches returning an existing generation despite active siblings or row drift."""
    case, _, _, _, _ = decision_assignment
    con, run, root = case[:3]
    if damage == "another-active":
        old = dict(con.execute("SELECT * FROM cba_firmware_decide_runs").fetchone())
        db.put(con, "cba_firmware_decide_runs", old | {"decision_generation": "b" * 64})
    else:
        con.execute("UPDATE cba_firmware_decide_runs SET policy_id='different-policy'")
        con.commit()
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError, match=match):
        decide.prepare(con, run, root, write_policy(tmp_path), image_id="target")
    assert state(con) == before and not con.in_transaction


def test_prepare_refuses_valid_policy_change_during_install(decision_case, tmp_path, monkeypatch):
    """Catches publishing the first snapshot after a different valid policy wins the race."""
    con, run, root = decision_case[0][:3]
    policy_path = write_policy(tmp_path)
    original = dive._install
    def install_then_change(*args, **kwargs):
        original(*args, **kwargs)
        policy_path.write_bytes(encoded(POLICY | {"policy_id": "changed-valid-policy"}, canonical=True))
    monkeypatch.setattr(dive, "_install", install_then_change)
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError, match="inputs changed"):
        decide.prepare(con, run, root, policy_path, image_id="target")
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("damage,match", [
    ("technical", "technical input is not current"), ("policy", "policy snapshot differs"),
    ("worklist", "worklist is not current"), ("result", "result is not canonical"),
])
def test_completion_reconstructs_current_authority_before_trusting_stored_hashes(
        decision_assignment, damage, match):
    """Catches accepting self-consistent stored hashes without independent reconstruction."""
    case, summary, worklist, body, path = decision_assignment
    con, run, root = case[:3]
    record = results.record(con, run, path)
    if damage == "technical":
        con.execute("UPDATE cba_firmware_decide_runs SET graph_sha256=?", ("0" * 64,))
    elif damage == "policy":
        con.execute("UPDATE cba_firmware_decide_runs SET policy_id='foreign-policy'")
    elif damage == "worklist":
        changed = copy.deepcopy(worklist)
        changed["schema_version"] = 2
        raw = encoded(changed, canonical=True)
        (run / summary.worklist_path).write_bytes(raw)
        con.execute("UPDATE cba_firmware_decide_runs SET worklist_sha256=?",
                    (hashlib.sha256(raw).hexdigest(),))
    else:
        raw = encoded(body)
        (run / record.result_path).write_bytes(raw)
        con.execute("UPDATE cba_firmware_decide_runs SET result_sha256=?",
                    (hashlib.sha256(raw).hexdigest(),))
    con.commit()
    before = state(con)
    with pytest.raises(decide.FirmwareDecideError, match=match):
        decide.check(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("operation", ["record", "check"])
def test_publication_refuses_future_lifecycle_timestamps(decision_assignment, operation):
    """Catches publishing a lifecycle transition before its prerequisite timestamp."""
    case, _, _, _, path = decision_assignment
    con, run, root = case[:3]
    if operation == "check":
        results.record(con, run, path)
    field = "prepared_at" if operation == "record" else "recorded_at"
    con.execute(f"UPDATE cba_firmware_decide_runs SET {field}='2999-01-01 00:00:00'")
    con.commit()
    before = state(con)
    error = results.FirmwareDecideResultError if operation == "record" else decide.FirmwareDecideError
    with pytest.raises(error, match="timestamp precedes"):
        if operation == "record":
            results.record(con, run, path)
        else:
            decide.check(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("operation", ["record", "check"])
def test_publication_requires_actual_sql_transition(decision_assignment, operation):
    """Catches reporting success when a real SQL trigger prevents the compare-and-swap."""
    case, _, _, _, path = decision_assignment
    con, run, root = case[:3]
    if operation == "check":
        results.record(con, run, path)
    con.execute("CREATE TRIGGER refuse_decision_update BEFORE UPDATE ON cba_firmware_decide_runs "
                "BEGIN SELECT RAISE(IGNORE); END")
    con.commit()
    before = state(con)
    error = results.FirmwareDecideResultError if operation == "record" else decide.FirmwareDecideError
    with pytest.raises(error, match="changed before"):
        if operation == "record":
            results.record(con, run, path)
        else:
            decide.check(con, run, root, image_id="target")
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize("winner", ["recorded-conflict", "complete"])
def test_record_rechecks_lifecycle_winner_after_install(decision_assignment, monkeypatch, winner):
    """Catches overwriting a conflicting recorded/completed winner during installation."""
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    original = dive._install
    published = {}
    def install_then_publish(*args, **kwargs):
        original(*args, **kwargs)
        row = dict(con.execute("SELECT * FROM cba_firmware_decide_runs").fetchone())
        row.update(status="recorded", result_path="artifacts/winner.json",
                   result_sha256="f" * 64, recorded_at=row["prepared_at"])
        if winner == "complete":
            row.update(status="complete", package_path="artifacts/winner-package.json",
                       package_sha256="e" * 64, decision="pass", primary_reason="no-policy-match",
                       reason_codes='["no-policy-match"]', completed_at=row["prepared_at"])
        db.put(con, "cba_firmware_decide_runs", row, replace=True)
        published["state"] = state(con)
    monkeypatch.setattr(dive, "_install", install_then_publish)
    match = "conflicts" if winner == "recorded-conflict" else "pending decision"
    with pytest.raises(results.FirmwareDecideResultError, match=match):
        results.record(con, run, path)
    assert state(con) == published["state"] and not con.in_transaction


def test_completion_refuses_authority_change_during_install(decision_assignment, monkeypatch):
    """Catches completing a stale capture after another writer changes lifecycle authority."""
    case, _, _, _, path = decision_assignment
    con, run, root = case[:3]
    results.record(con, run, path)
    original = dive._install
    published = {}
    def install_then_change(*args, **kwargs):
        original(*args, **kwargs)
        con.execute("UPDATE cba_firmware_decide_runs SET recorded_at='2999-01-01 00:00:00'")
        con.commit()
        published["state"] = state(con)
    monkeypatch.setattr(dive, "_install", install_then_change)
    with pytest.raises(decide.FirmwareDecideError, match="authority changed"):
        decide.check(con, run, root, image_id="target")
    assert state(con) == published["state"] and not con.in_transaction


@pytest.mark.parametrize("kind", ["fifo", "symlink"])
def test_policy_loader_refuses_non_regular_file_without_blocking(tmp_path, kind):
    """Catches opening a FIFO policy (blocking forever) or following a symlinked policy."""
    target = write_policy(tmp_path)
    hostile = tmp_path / f"hostile-{kind}.json"
    if kind == "fifo":
        os.mkfifo(hostile)
    else:
        hostile.symlink_to(target)
    outcome = []
    def load():
        try:
            decide.load_policy(hostile)
        except BaseException as exc:  # handed to the test thread below
            outcome.append(exc)
    worker = threading.Thread(target=load, daemon=True)
    worker.start()
    worker.join(timeout=10)
    if worker.is_alive():
        # A writer releases a reader blocked in open(); then fail loudly.
        os.close(os.open(hostile, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("load_policy blocked on a non-regular policy file")
    assert len(outcome) == 1 and isinstance(outcome[0], decide.FirmwareDecideError)
    assert "cannot read policy" in str(outcome[0])


def test_stable_file_reader_refuses_identity_drift_during_read(tmp_path, monkeypatch):
    """Catches accepting bytes from a policy/result file replaced while it was read."""
    path = write_policy(tmp_path)
    assert decide.load_policy(path) == decide._parse(RAW)
    original = dive._file_identity
    calls = []
    def drifting(value):
        calls.append(value)
        return original(value) + ((len(calls),) if len(calls) == 4 else ())
    monkeypatch.setattr(dive, "_file_identity", drifting)
    with pytest.raises(decide.FirmwareDecideError, match="cannot read policy"):
        decide.load_policy(path)
    with pytest.raises(OSError, match="changed while it was read"):
        calls.clear()
        decide._read_stable_file(path, decide.MAX_POLICY_BYTES)
