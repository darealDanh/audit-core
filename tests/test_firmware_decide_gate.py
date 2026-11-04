"""Deterministic Stage 4i policy matching and recommendation publication."""
import copy
import json

import pytest

from audit_core import firmware_chain, firmware_decide as decide, firmware_decide_results as results
from audit_core import firmware_dive as dive, firmware_dive_results
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401
from tests.test_firmware_decide_policy import POLICY
from tests.test_firmware_decide_results import bench_id, build_result, save
from tests.test_firmware_dive_prepare import rows
from tests.test_hunt_gate import state


def matching_policy(graph, *, support="supported", path_status="eligible",
                    cost=100, maximum=1000, policy_id="matching-policy"):
    chain = graph.chains[0]
    return {
        "schema_version": 1,
        "policy_id": policy_id,
        "currency": "USD",
        "acquisition_cost_minor": cost,
        "max_acquisition_cost_minor": maximum,
        "support_status": support,
        "support_basis": "Operator support source checked for the test fixture.",
        "payout_paths": [{
            "path_id": "program", "status": path_status,
            "basis": "Operator payout source checked for the test fixture.",
        }],
        "tiers": [{
            "tier_id": "matching-tier", "payout_path_id": "program", "ordinal": 0,
            "minimum_minor": 10000, "maximum_minor": 50000,
            "accepted_pre_auth": [chain.pre_auth],
            "minimum_confidence": chain.confidence,
            "accepted_completeness": [chain.completeness],
            "accepted_evidence_rungs": [chain.evidence_rung],
            "physical_access_allowed": True,
        }],
        "notes": ["Policy facts are not technical evidence."],
    }


def write_policy(tmp_path, body, name="policy.json"):
    path = tmp_path / name
    path.write_bytes((json.dumps(body, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode())
    return path


def recorded_pipeline(decision_case, tmp_path, policy_body, *, mutate_result=None):
    case, _, _, graph = decision_case
    con, run, root = case[:3]
    preparation = decide.prepare(
        con, run, root, write_policy(tmp_path, policy_body), image_id="target")
    worklist = json.loads((run / preparation.worklist_path).read_bytes())
    body = build_result(worklist, preparation.decision_generation)
    if mutate_result is not None:
        mutate_result(body)
    result_path = save(tmp_path / "decision.json", body)
    results.record(con, run, result_path)
    return case, preparation, worklist, body, result_path


def test_policy_matching_and_payout_projection_are_core_derived(decision_case, tmp_path):
    graph = decision_case[3]
    policy = matching_policy(graph)
    case, preparation, _, body, _ = recorded_pipeline(decision_case, tmp_path, policy)
    summary = decide.check(*case[:3], image_id="target")
    package = decide.verified_package(*case[:3], image_id="target")

    assert summary.decision == "acquire"
    assert summary.primary_reason == "eligible-chain"
    assert summary.reason_codes == ("eligible-policy-match", "bench-plan-complete")
    assert summary.policy_match_count == 1
    match, = package.policy_matches
    assert match.chain_id == graph.chains[0].chain_id
    assert match.tier_id == "matching-tier" and match.payout_path_id == "program"
    assert match.path_status == "eligible" and match.technical_match
    assert match.eligible_match and not match.unknown_path_match
    projection, = package.payout_projections
    assert (projection.currency, projection.minimum_minor, projection.maximum_minor) == (
        "USD", 10000, 50000)
    assert package.policy.policy_id == policy["policy_id"]
    assert package.result.chain_assessments[0].rationale == \
        body["answer"]["chain_assessments"][0]["rationale"]


@pytest.mark.parametrize("support,path_status,cost,maximum,tests,decision,reason", [
    ("unsupported", "eligible", 100, 1000, True, "pass", "support-unsupported"),
    ("supported", "eligible", 1001, 1000, True, "pass", "cost-exceeds-policy"),
    ("unknown", "eligible", 100, 1000, True, "defer", "support-unknown"),
    ("supported", "eligible", 100, 1000, False, "defer", "bench-plan-incomplete"),
    ("supported", "unknown", 100, 1000, True, "defer", "payout-path-unknown"),
    ("supported", "ineligible", 100, 1000, True, "pass", "no-policy-match"),
])
def test_recommendation_precedence(decision_case, tmp_path, support, path_status,
                                   cost, maximum, tests, decision, reason):
    graph = decision_case[3]
    policy = matching_policy(
        graph, support=support, path_status=path_status, cost=cost,
        maximum=maximum, policy_id=f"case-{reason}")
    def mutate(body):
        if not tests:
            body["answer"]["bench_tests"] = []
            body["answer"]["proposed_scripts"] = []
    case, _, _, _, _ = recorded_pipeline(decision_case, tmp_path, policy, mutate_result=mutate)
    summary = decide.check(*case[:3], image_id="target")
    assert (summary.decision, summary.primary_reason) == (decision, reason)
    order = {code: index for index, code in enumerate(decide.db.FIRMWARE_DECIDE_REASON_CODES)}
    assert list(summary.reason_codes) == sorted(set(summary.reason_codes), key=order.__getitem__)
    if path_status == "eligible":
        assert "eligible-policy-match" in summary.reason_codes
        assert ("bench-plan-complete" if tests else "bench-plan-incomplete") in summary.reason_codes
    elif path_status == "unknown":
        assert "unknown-policy-path-match" in summary.reason_codes
    else:
        assert "no-policy-match" in summary.reason_codes


def test_no_technical_policy_match_is_pass(decision_case, tmp_path):
    graph = decision_case[3]
    policy = matching_policy(graph, policy_id="no-match")
    policy["tiers"][0]["minimum_confidence"] = min(10, graph.chains[0].confidence + 1)
    if policy["tiers"][0]["minimum_confidence"] == graph.chains[0].confidence:
        policy["tiers"][0]["accepted_pre_auth"] = [
            next(value for value in decide.db.FIRMWARE_CHAIN_PRE_AUTH
                 if value != graph.chains[0].pre_auth)]
    case, _, _, _, _ = recorded_pipeline(decision_case, tmp_path, policy)
    summary = decide.check(*case[:3], image_id="target")
    assert (summary.decision, summary.primary_reason) == ("pass", "no-policy-match")
    assert summary.policy_match_count == 0


def test_hardware_precondition_requires_tier_permission_and_bench_coverage(decision_case, tmp_path):
    graph = decision_case[3]
    policy = matching_policy(graph, policy_id="hardware-refusal")
    policy["tiers"][0]["physical_access_allowed"] = False
    case, _, _, _, _ = recorded_pipeline(decision_case, tmp_path, policy)
    summary = decide.check(*case[:3], image_id="target")
    hardware = [item for item in decide.verified_package(*case[:3], image_id="target").open_preconditions
                if item.method == "hardware"]
    if hardware:
        assert (summary.decision, summary.primary_reason) == ("pass", "no-policy-match")


def test_check_is_idempotent_and_publishes_exact_counts(decision_case, tmp_path):
    graph = decision_case[3]
    case, _, _, _, _ = recorded_pipeline(decision_case, tmp_path, matching_policy(graph))
    con = case[0]
    first = decide.check(*case[:3], image_id="target")
    before, changes = state(con), con.total_changes
    second = decide.check(*case[:3], image_id="target")
    assert second == first
    assert state(con) == before and con.total_changes == changes and not con.in_transaction
    row = rows(con, "cba_firmware_decide_runs")[0]
    assert row["status"] == "complete"
    assert row["decision"] == first.decision
    assert row["chain_count"] == first.chain_count
    assert row["bench_test_count"] == first.bench_test_count
    assert row["script_count"] == first.script_count
    assert row["policy_match_count"] == first.policy_match_count


def hardware_decision_case(graph_case, tmp_path):
    from tests.test_firmware_chain_import import blocked, record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    from tests.test_firmware_dive_gate import populate, check as dive_check
    from tests.test_firmware_dive_prepare import prepare as dive_prepare

    blocked(graph_case)
    chain_record(graph_case)
    chain_check(graph_case)
    dive_prepare(graph_case)
    populate(graph_case, tmp_path, "inconclusive")
    dive_check(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id="target")
    return graph_case, None, None, graph


@pytest.mark.parametrize("physical,cover,decision,reason", [
    (False, False, "pass", "no-policy-match"),
    (True, False, "defer", "bench-plan-incomplete"),
    (True, True, "acquire", "eligible-chain"),
])
def test_hardware_settlement_matching_and_exact_bench_coverage(
        graph_case, tmp_path, physical, cover, decision, reason):
    selected = hardware_decision_case(graph_case, tmp_path)
    graph = selected[3]
    policy = matching_policy(
        graph, policy_id=f"hardware-{physical}-{cover}")
    policy["tiers"][0]["physical_access_allowed"] = physical
    def mutate(body):
        if cover:
            test = body["answer"]["bench_tests"][0]
            hardware = [
                item["precondition_id"]
                for item in body["answer"]["chain_assessments"][0]["open_preconditions"]
                if item["method"] == "hardware"]
            test["subject_refs"] = sorted(set(test["subject_refs"]) | set(hardware))
            test["test_id"] = bench_id(test)
    case, _, _, _, _ = recorded_pipeline(
        selected, tmp_path, policy, mutate_result=mutate)
    summary = decide.check(*case[:3], image_id="target")
    assert (summary.decision, summary.primary_reason) == (decision, reason)
    package = decide.verified_package(*case[:3], image_id="target")
    match = package.policy_matches
    if physical:
        assert match and match[0].requires_physical_settlement
        assert package.bench_plan_complete is cover
    else:
        assert match == ()


def test_empty_graph_has_explicit_no_current_chain_decision(graph_case, tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    from tests.test_firmware_dive_prepare import canonical

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
    dive_path = tmp_path / "empty-dive.json"
    dive_path.write_bytes(canonical({
        "schema_version": 1, "image_id": "empty",
        "dive_generation": prepared_dive.dive_generation, "questions": [],
    }))
    firmware_dive_results.record(con, run, dive_path)
    dive.check(con, run, root, image_id="empty")
    preparation = decide.prepare(
        con, run, root, write_policy(tmp_path, POLICY, "empty-policy.json"),
        image_id="empty")
    result_path = save(tmp_path / "empty-decision.json", {
        "schema_version": 1, "image_id": "empty",
        "decision_generation": preparation.decision_generation,
        "worklist_sha256": preparation.worklist_sha256,
        "answer": {"kind": "empty"},
    })
    results.record(con, run, result_path)
    summary = decide.check(con, run, root, image_id="empty")
    assert (summary.decision, summary.primary_reason) == ("pass", "no-current-chain")
    assert summary.chain_count == 0
    assert summary.reason_codes == ("no-current-chain", "no-policy-match")
