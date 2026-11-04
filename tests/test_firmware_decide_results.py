"""Strict Stage 4i worker result parsing and assignment validation."""
import copy
import dataclasses
import hashlib
import json
import pathlib

import pytest

from audit_core import firmware_chain, firmware_decide as decide
from audit_core import firmware_decide_results as results
from audit_core import firmware_dive as dive, firmware_dive_results
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_policy import write_policy
from tests.test_firmware_dive_prepare import canonical


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def bench_id(value):
    projected = {key: item for key, item in value.items() if key != "test_id"}
    return "firmware-decide-test-" + hashlib.sha256(canonical_json(projected)).hexdigest()


def build_result(worklist, generation, *, scripts=True):
    graph = worklist["graph"]
    assessments = []
    for rank, chain in enumerate(graph["chains"], 1):
        chain_id = chain["chain_id"]
        preconditions = [copy.deepcopy(item) for item in worklist["open_preconditions"]
                         if any(location["chain_id"] == chain_id for location in item["locations"])]
        assessments.append({
            "chain_id": chain_id,
            "rank": rank,
            "initial_attacker_position": chain["initial_attacker_position"],
            "pre_auth": chain["pre_auth"],
            "confidence": chain["confidence"],
            "completeness": chain["completeness"],
            "evidence_rung": chain["evidence_rung"],
            "member_ids": chain["member_ids"],
            "edge_ordinals": [edge["ordinal"] for edge in graph["edges"]
                              if edge["chain_id"] == chain_id],
            "open_preconditions": preconditions,
            "disposition": "bench-priority" if rank == 1 else "retain",
            "rationale": "Prioritize the exact current chain for bounded Day-1 validation.",
            "limitations": ["This assessment does not claim exploit reliability."],
            "evidence_refs": chain["initial_evidence_refs"],
        })
    bench_tests = []
    proposed_scripts = []
    if graph["chains"]:
        chain = graph["chains"][0]
        edge = next(item for item in graph["edges"] if item["chain_id"] == chain["chain_id"])
        test = {
            "test_id": "pending",
            "chain_ids": [chain["chain_id"]],
            "subject_refs": [f"transition:{chain['chain_id']}:{edge['ordinal']}"],
            "title": "Observe the first verified transition",
            "purpose": "Confirm the exact required-to-result state transition on the acquired unit.",
            "required_state": {
                "device": graph["image_id"],
                "firmware": graph["candidate_snapshot_sha256"],
                "lifecycle": chain["initial_lifecycle"],
                "posture": chain["initial_posture"],
                "authentication": chain["initial_authentication"],
            },
            "setup_steps": ["Place the unit in the recorded initial state."],
            "action_steps": ["Exercise only the recorded transition input."],
            "expected_signal": "The recorded transition result state is observed.",
            "control_observation": "The same signal is absent without the transition input.",
            "stop_conditions": ["Stop on unexpected persistent state change."],
            "limitations": ["No destructive or paid action is authorized."],
            "script_name": "observe-transition.sh" if scripts else None,
        }
        test["test_id"] = bench_id(test)
        bench_tests.append(test)
        if scripts:
            proposed_scripts.append({
                "name": "observe-transition.sh",
                "content": "#!/bin/sh\nprintf '%s\\n' proposed-unreviewed\n",
            })
    return {
        "schema_version": 1,
        "image_id": worklist["image_id"],
        "decision_generation": generation,
        "worklist_sha256": generation,
        "answer": {
            "kind": "decision",
            "chain_assessments": assessments,
            "bench_tests": bench_tests,
            "proposed_scripts": proposed_scripts,
        },
    }


@pytest.fixture
def decision_assignment(decision_case, tmp_path):
    case = decision_case[0]
    summary = decide.prepare(*case[:3], write_policy(tmp_path), image_id="target")
    worklist = json.loads((case[1] / summary.worklist_path).read_bytes())
    body = build_result(worklist, summary.decision_generation)
    path = tmp_path / "decision-result.json"
    path.write_bytes(canonical_json(body))
    return case, summary, worklist, body, path


def save(path, body, *, canonical_bytes=True):
    path.write_bytes(canonical_json(body) if canonical_bytes else json.dumps(body, indent=2).encode())
    return path


def test_parser_literal_round_trip_frozen_records_and_no_derived_authority(decision_assignment):
    _, summary, _, body, path = decision_assignment
    parsed = results.load(path)
    assert parsed.image_id == "target"
    assert parsed.decision_generation == summary.decision_generation
    assert isinstance(parsed.answer, results.DecisionAnswer)
    assert parsed.answer.chain_assessments[0].rank == 1
    assert parsed.answer.bench_tests[0].script_name == "observe-transition.sh"
    assert parsed.answer.proposed_scripts[0].content.startswith("#!/bin/sh")
    assert results.canonical_bytes(parsed) == canonical_json(body)
    with pytest.raises((AttributeError, TypeError)):
        parsed.answer.chain_assessments += parsed.answer.chain_assessments

    for forbidden in ("decision", "recommendation", "payout_minor", "severity",
                      "cvss", "exploit_reliability", "policy_matches"):
        changed = copy.deepcopy(body)
        changed["answer"][forbidden] = "worker-owned"
        save(path, changed)
        with pytest.raises(results.FirmwareDecideResultError):
            results.load(path)


def test_parser_accepts_explicit_empty_variant(tmp_path):
    body = {
        "schema_version": 1,
        "image_id": "empty",
        "decision_generation": "a" * 64,
        "worklist_sha256": "a" * 64,
        "answer": {"kind": "empty"},
    }
    parsed = results.load(save(tmp_path / "empty.json", body, canonical_bytes=False))
    assert isinstance(parsed.answer, results.EmptyDecisionAnswer)
    assert results.canonical_bytes(parsed) == canonical_json(body)


@pytest.mark.parametrize("mutate", [
    lambda body: body.update(schema_version=True),
    lambda body: body.update(extra=True),
    lambda body: body["answer"].update(kind="other"),
    lambda body: body["answer"]["chain_assessments"][0].update(rank=True),
    lambda body: body["answer"]["chain_assessments"][0].update(disposition="acquire"),
    lambda body: body["answer"]["chain_assessments"][0].update(rationale=""),
    lambda body: body["answer"]["chain_assessments"][0].update(evidence_refs=["not-a-reference"]),
    lambda body: body["answer"]["bench_tests"][0].update(script_name="../run.sh"),
    lambda body: body["answer"]["proposed_scripts"][0].update(name="../run.sh"),
    lambda body: body["answer"]["proposed_scripts"][0].update(content="bad\0script"),
])
def test_parser_rejects_invalid_structure_and_values(decision_assignment, mutate):
    _, _, _, body, path = decision_assignment
    mutate(body)
    save(path, body)
    with pytest.raises(results.FirmwareDecideResultError):
        results.load(path)


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":NaN}',
    b'[]',
    b'\xff',
    b'{' + b' ' * (8 * 1024 * 1024) + b'}',
])
def test_parser_rejects_hostile_or_oversize_json(tmp_path, raw):
    path = tmp_path / "hostile.json"
    path.write_bytes(raw)
    with pytest.raises(results.FirmwareDecideResultError):
        results.load(path)


def test_parser_enforces_script_count_individual_and_total_bounds(decision_assignment):
    _, _, _, body, path = decision_assignment
    script = body["answer"]["proposed_scripts"][0]
    body["answer"]["proposed_scripts"] = [
        {"name": f"s{index:02}.sh", "content": script["content"]}
        for index in range(17)]
    save(path, body)
    with pytest.raises(results.FirmwareDecideResultError):
        results.load(path)
    body["answer"]["proposed_scripts"] = [{"name": "large.sh", "content": "x" * (32 * 1024 + 1)}]
    save(path, body)
    with pytest.raises(results.FirmwareDecideResultError):
        results.load(path)
    body["answer"]["proposed_scripts"] = [
        {"name": f"t{index:02}.sh", "content": "x" * (17 * 1024)}
        for index in range(16)]
    save(path, body)
    with pytest.raises(results.FirmwareDecideResultError):
        results.load(path)


def test_validate_returns_exact_complete_denominators_and_inert_script_bytes(decision_assignment):
    case, summary, worklist, body, path = decision_assignment
    before = case[0].total_changes
    validated = results.validate(case[0], case[1], results.load(path))
    assert validated.image_id == "target"
    assert validated.decision_generation == summary.decision_generation
    assert validated.result_bytes == canonical_json(body)
    assert validated.result_sha256 == hashlib.sha256(validated.result_bytes).hexdigest()
    assert [item.chain_id for item in validated.chain_assessments] == [
        item["chain_id"] for item in worklist["graph"]["chains"]]
    assert [item.precondition_id for item in validated.open_preconditions] == [
        item["precondition_id"] for item in worklist["open_preconditions"]]
    assert validated.scripts[0].name == "observe-transition.sh"
    assert validated.scripts[0].content == body["answer"]["proposed_scripts"][0]["content"].encode()
    assert case[0].total_changes == before and not case[0].in_transaction


@pytest.mark.parametrize("damage", [
    "missing-chain", "duplicate-rank", "copied-fact", "missing-precondition",
    "foreign-evidence", "bad-test-id", "foreign-subject", "bad-state", "bad-device",
    "missing-script",
])
def test_validate_rejects_incomplete_or_invented_authority(decision_assignment, damage):
    case, _, _, body, path = decision_assignment
    answer = body["answer"]
    assessment = answer["chain_assessments"][0]
    test = answer["bench_tests"][0]
    if damage == "missing-chain":
        answer["chain_assessments"] = []
    elif damage == "duplicate-rank":
        answer["chain_assessments"].append(copy.deepcopy(assessment))
    elif damage == "copied-fact":
        assessment["confidence"] -= 1
    elif damage == "missing-precondition":
        assessment["open_preconditions"] = assessment["open_preconditions"][:-1]
    elif damage == "foreign-evidence":
        assessment["evidence_refs"] = ["finding:foreign#root_cause"]
    elif damage == "bad-test-id":
        test["test_id"] = "firmware-decide-test-" + "0" * 64
    elif damage == "foreign-subject":
        test["subject_refs"] = ["transition:foreign:0"]
        test["test_id"] = bench_id(test)
    elif damage == "bad-state":
        test["required_state"]["lifecycle"] = "foreign"
        test["test_id"] = bench_id(test)
    elif damage == "bad-device":
        test["required_state"]["device"] = "foreign"
        test["test_id"] = bench_id(test)
    else:
        test["script_name"] = "missing.sh"
        test["test_id"] = bench_id(test)
    save(path, body)
    with pytest.raises(results.FirmwareDecideResultError):
        parsed = results.load(path)
        results.validate(case[0], case[1], parsed)


def test_validate_rejects_empty_variant_for_nonempty_assignment(decision_assignment):
    case, summary, _, body, path = decision_assignment
    body["answer"] = {"kind": "empty"}
    save(path, body)
    with pytest.raises(results.FirmwareDecideResultError):
        results.validate(case[0], case[1], results.load(path))


def test_validate_accepts_empty_variant_only_for_empty_graph(graph_case, tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check

    con, run = graph_case[:2]
    root = tmp_path / "empty-root"
    empty_review(con, run, root, "empty")
    chain = firmware_chain.prepare(con, run, root, image_id="empty")
    case = (con, run, root, {
        "schema_version": 1, "image_id": "empty",
        "candidate_snapshot_sha256": chain.candidate_snapshot_sha256,
        "worklist_sha256": chain.worklist_sha256,
        "blockers": [], "dispositions": [], "chains": [],
    }, {})
    chain_record(case)
    chain_check(case, image_id="empty")
    prepared_dive = dive.prepare(con, run, root, image_id="empty")
    dive_result = tmp_path / "empty-dive.json"
    dive_result.write_bytes(canonical({
        "schema_version": 1, "image_id": "empty",
        "dive_generation": prepared_dive.dive_generation, "questions": [],
    }))
    firmware_dive_results.record(con, run, dive_result)
    dive.check(con, run, root, image_id="empty")
    summary = decide.prepare(con, run, root, write_policy(tmp_path), image_id="empty")
    body = {
        "schema_version": 1, "image_id": "empty",
        "decision_generation": summary.decision_generation,
        "worklist_sha256": summary.worklist_sha256,
        "answer": {"kind": "empty"},
    }
    path = save(tmp_path / "empty-decision.json", body)
    validated = results.validate(con, run, results.load(path))
    assert validated.chain_assessments == ()
    assert validated.open_preconditions == ()
    assert validated.bench_tests == () and validated.scripts == ()


def test_dive_subject_fingerprints_match_stage4h_authority(decision_assignment):
    from audit_core import firmware_dive_questions as questions

    case, _, worklist, _, _ = decision_assignment
    snapshot = firmware_chain.verified_graph_snapshot(*case[:3], image_id="target")
    graph = worklist["graph"]
    chain_wire = graph["chains"][0]
    chain = snapshot.chains[0]
    edges = sorted((item for item in snapshot.edges if item.chain_id == chain.chain_id),
                   key=lambda item: item.ordinal)
    edge_wires = sorted(
        (item for item in graph["edges"] if item["chain_id"] == chain.chain_id),
        key=lambda item: item["ordinal"])
    assert results._chain_fingerprint(graph, chain_wire, edge_wires) == \
        questions.chain_fingerprint(snapshot, chain)
    assert [results._edge_fingerprint(graph, chain_wire, item) for item in edge_wires] == [
        questions.edge_fingerprint(snapshot, item) for item in edges]


def test_validate_rejects_assignment_chain_count_drift(decision_assignment):
    case, _, _, _, path = decision_assignment
    con, run = case[:2]
    con.execute(
        "UPDATE cba_firmware_decide_runs SET chain_count=chain_count+1 "
        "WHERE image_id='target'")
    con.commit()
    with pytest.raises(results.FirmwareDecideResultError, match="chain count"):
        results.validate(con, run, results.load(path))


def test_edge_precondition_uses_frozen_edge_required_state(decision_assignment):
    case, _, worklist, _, path = decision_assignment
    validated = results.validate(case[0], case[1], results.load(path))
    precondition = next(
        item for item in validated.open_preconditions
        if any(location.edge_ordinal is not None for location in item.locations))
    graph = copy.deepcopy(worklist["graph"])
    location = next(item for item in precondition.locations
                    if item.edge_ordinal is not None)
    edge = next(item for item in graph["edges"]
                if item["chain_id"] == location.chain_id
                and item["ordinal"] == location.edge_ordinal)
    edge["required_state"]["authentication"] = "admin"
    test = validated.bench_tests[0]
    test = dataclasses.replace(
        test, chain_ids=(location.chain_id,),
        subject_refs=(precondition.precondition_id,))
    owners, requirements = results._subject_ownership(
        precondition.precondition_id, graph, validated.open_preconditions)
    assert owners == {location.chain_id}
    with pytest.raises(results.FirmwareDecideResultError, match="required state"):
        results._validate_state(test, graph, requirements)
    corrected = dataclasses.replace(
        test, required_state=dataclasses.replace(
            test.required_state, authentication="admin"))
    results._validate_state(corrected, graph, requirements)


def test_dive_evidence_keeps_blocker_and_unknown_namespaces_distinct(decision_assignment):
    _, _, worklist, _, _ = decision_assignment
    blocker = next(item for item in worklist["open_preconditions"]
                   if item["kind"] == "blocker")
    chain = worklist["graph"]["chains"][0]
    denominator = (results._precondition(blocker),)
    observation_id = "d" * 64
    observation = {
        "observation_id": observation_id,
        "subject_refs": [f"surface-unknown:{blocker['source_id']}"],
        "settled_subject_refs": [],
        "evidence_refs": [],
    }
    changed = copy.deepcopy(worklist)
    changed["dive"]["overlay"]["observations"] = [observation]
    allowed = results._chain_evidence(
        changed["graph"], changed, chain, denominator)
    assert f"dive:{observation_id}#conclusion" not in allowed
    observation["subject_refs"] = [f"chain-blocker:{blocker['source_id']}"]
    allowed = results._chain_evidence(
        changed["graph"], changed, chain, denominator)
    assert f"dive:{observation_id}#conclusion" in allowed
