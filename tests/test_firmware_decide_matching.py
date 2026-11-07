"""Fault-sensitive Stage 4i policy matching and recommendation precedence.

Each scenario isolates one rule of ``firmware_decide._technical_derivation``
with two-chain graphs whose rank order differs from identifier order, so a
derivation that keys on the wrong field, tier, or chain changes the outcome.
"""
import json

import pytest

from audit_core import firmware_decide as decide, firmware_decide_results as results


STATE = results.RequiredState("bench-unit", "0" * 64, "factory", "default", "none")


def tier(tier_id, path_id, ordinal, *, pre_auth=("yes",), completeness=("complete",),
         confidence=5, physical=False, minimum=100, maximum=200):
    return {
        "tier_id": tier_id, "payout_path_id": path_id, "ordinal": ordinal,
        "minimum_minor": minimum, "maximum_minor": maximum,
        "accepted_pre_auth": list(pre_auth), "minimum_confidence": confidence,
        "accepted_completeness": list(completeness),
        "accepted_evidence_rungs": ["static-chained"],
        "physical_access_allowed": physical,
    }


def policy(*tiers, support="supported", cost=100, maximum=1000, statuses=None):
    statuses = statuses or {"path-a": "eligible", "path-b": "eligible"}
    value = {
        "schema_version": 1, "policy_id": "matching", "currency": "USD",
        "acquisition_cost_minor": cost, "max_acquisition_cost_minor": maximum,
        "support_status": support, "support_basis": "support list checked",
        "payout_paths": [
            {"path_id": path_id, "status": status, "basis": f"{path_id} rules checked"}
            for path_id, status in sorted(statuses.items())],
        "tiers": list(tiers) or [tier("default", "path-a", 0)],
        "notes": [],
    }
    return decide._parse((json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")) + "\n").encode())


def chain(chain_id, rank, *, pre_auth="yes", confidence=8, completeness="complete",
          rung="static-chained"):
    return results.ChainAssessment(
        chain_id, rank, "network-adjacent", pre_auth, confidence, completeness, rung,
        ("member",), (0,), (), "chained", "rationale", (), ())


def hardware(identity, *chain_ids, method="hardware"):
    return results.OpenPrecondition(
        "blocker", f"blocker:{identity}", identity, "question", "observation", method,
        ("device",), tuple(results.PreconditionLocation(item, None) for item in chain_ids))


def bench(test_id, chain_ids, subjects, script_name=None):
    return results.BenchTest(
        test_id, tuple(chain_ids), tuple(subjects), "title", "purpose", STATE,
        ("setup",), ("action",), "signal", "control", ("stop",), (), script_name)


def derive(selected_policy, chains, *, preconditions=(), tests=(), scripts=()):
    validated = results.ValidatedDecisionResult(
        "target", "0" * 64, "0" * 64, b"", "0" * 64, tuple(chains),
        tuple(preconditions), tuple(tests), tuple(scripts))
    return decide._technical_derivation(selected_policy, validated)


@pytest.mark.parametrize("assessment,survivor", [
    (chain("chain-a", 1, pre_auth="unknown"), "broad"),
    (chain("chain-a", 1, completeness="blocked"), "broad"),
    (chain("chain-a", 1, confidence=6), "broad"),
    (chain("chain-a", 1, rung="dynamic-observed"), None),
], ids=["pre-auth", "completeness", "confidence", "evidence-rung"])
def test_each_technical_axis_must_be_accepted_by_the_tier(assessment, survivor):
    """Catches a tier that ignores accepted pre-auth, completeness, confidence, or rungs."""
    selected = policy(
        tier("strict", "path-a", 0, confidence=7),
        tier("broad", "path-b", 1, pre_auth=("no", "unknown", "yes"),
             completeness=("blocked", "complete")))
    derived = derive(selected, [assessment], tests=[bench("t", ["chain-a"], ["s"])])
    assert [item.tier_id for item in derived.policy_matches] == (
        [survivor] if survivor else [])
    if survivor:
        assert [(item.tier_id, item.payout_path_id)
                for item in derived.payout_projections] == [("broad", "path-b")]
        assert (derived.decision, derived.primary_reason) == ("acquire", "eligible-chain")
    else:
        assert derived.payout_projections == ()
        assert (derived.decision, derived.primary_reason) == ("pass", "no-policy-match")


def test_top_chain_is_lowest_rank_not_highest_or_identifier_order():
    """Catches top-chain selection by highest rank or by chain identifier."""
    derived = derive(policy(), [chain("chain-a", 2), chain("chain-b", 1)],
                     tests=[bench("t", ["chain-b"], ["s"])])
    assert derived.top_chain_id == "chain-b"
    assert derived.bench_plan_complete is True
    assert (derived.decision, derived.primary_reason) == ("acquire", "eligible-chain")


def test_bench_tests_for_other_chains_do_not_complete_top_chain_plan():
    """Catches bench completeness computed from tests that omit the top chain."""
    derived = derive(policy(), [chain("chain-a", 2), chain("chain-b", 1)],
                     tests=[bench("t", ["chain-a"], ["s"])])
    assert derived.top_chain_id == "chain-b"
    assert derived.bench_plan_complete is False
    assert (derived.decision, derived.primary_reason) == ("defer", "bench-plan-incomplete")
    assert "bench-plan-incomplete" in derived.reason_codes


def test_hardware_precondition_disqualifies_only_the_chain_that_owns_it():
    """Catches physical-access matching that is not scoped to the assessed chain."""
    derived = derive(policy(), [chain("chain-a", 1), chain("chain-b", 2)],
                     preconditions=[hardware("probe", "chain-b"),
                                    hardware("soft", "chain-a", method="static")],
                     tests=[bench("t", ["chain-a"], ["s"])])
    assert [(item.chain_id, item.requires_physical_settlement)
            for item in derived.policy_matches] == [("chain-a", False)]
    assert (derived.decision, derived.primary_reason) == ("acquire", "eligible-chain")


def test_bench_completeness_counts_only_top_chain_hardware_subjects():
    """Catches bench coverage that demands hardware subjects owned only by other chains."""
    physical = policy(tier("bench", "path-a", 0, physical=True))
    chains = [chain("chain-a", 1), chain("chain-b", 2)]
    elsewhere = derive(physical, chains, preconditions=[hardware("probe", "chain-b")],
                       tests=[bench("t", ["chain-a"], ["transition:chain-a:0"])])
    assert [(item.chain_id, item.requires_physical_settlement)
            for item in elsewhere.policy_matches] == [
        ("chain-a", False), ("chain-b", True)]
    assert (elsewhere.top_chain_id, elsewhere.bench_plan_complete) == ("chain-a", True)

    owned = [hardware("probe", "chain-a", "chain-b")]
    uncovered = derive(physical, chains, preconditions=owned,
                       tests=[bench("t", ["chain-a"], ["transition:chain-a:0"])])
    assert uncovered.bench_plan_complete is False
    covered = derive(physical, chains, preconditions=owned,
                     tests=[bench("t", ["chain-a"], ["blocker:probe"])])
    assert covered.bench_plan_complete is True


def test_bench_test_naming_an_absent_script_leaves_plan_incomplete():
    """Catches bench completeness that ignores missing proposed scripts."""
    tests = [bench("t", ["chain-a"], ["s"], script_name="probe.sh")]
    missing = derive(policy(), [chain("chain-a", 1)], tests=tests)
    assert missing.bench_plan_complete is False
    present = derive(policy(), [chain("chain-a", 1)], tests=tests,
                     scripts=[results.ValidatedScript("probe.sh", b"#!/bin/sh\n")])
    assert present.bench_plan_complete is True


def test_first_eligible_tier_sets_payout_projection():
    """Catches projection from the last, or lexically first, eligible tier."""
    selected = policy(tier("zeta", "path-b", 0, minimum=300, maximum=400),
                      tier("alpha", "path-a", 1, minimum=100, maximum=200))
    derived = derive(selected, [chain("chain-a", 1)])
    assert [item.tier_id for item in derived.policy_matches] == ["zeta", "alpha"]
    assert [(item.tier_id, item.payout_path_id, item.minimum_minor, item.maximum_minor)
            for item in derived.payout_projections] == [("zeta", "path-b", 300, 400)]


def test_ineligible_tier_does_not_shadow_later_eligible_tier():
    """Catches projection from the first technical match when its path is ineligible."""
    selected = policy(tier("first", "path-b", 0), tier("second", "path-a", 1),
                      statuses={"path-a": "eligible", "path-b": "ineligible"})
    derived = derive(selected, [chain("chain-a", 1)], tests=[bench("t", ["chain-a"], ["s"])])
    assert [item.tier_id for item in derived.payout_projections] == ["second"]
    assert (derived.decision, derived.primary_reason) == ("acquire", "eligible-chain")


@pytest.mark.parametrize("cost,decision,reason", [
    (1000, "acquire", "eligible-chain"),
    (1001, "pass", "cost-exceeds-policy"),
])
def test_cost_equal_to_maximum_is_within_policy(cost, decision, reason):
    """Catches a cost comparison that treats the maximum itself as exceeding policy."""
    derived = derive(policy(cost=cost, maximum=1000), [chain("chain-a", 1)],
                     tests=[bench("t", ["chain-a"], ["s"])])
    assert (derived.decision, derived.primary_reason) == (decision, reason)
    assert ("cost-exceeds-policy" in derived.reason_codes) is (cost > 1000)


def test_unsupported_precedes_cost_exceeds_policy():
    """Catches swapped unsupported and cost-exceeds precedence."""
    derived = derive(policy(support="unsupported", cost=2000, maximum=1000),
                     [chain("chain-a", 1)], tests=[bench("t", ["chain-a"], ["s"])])
    assert (derived.decision, derived.primary_reason) == ("pass", "support-unsupported")
    assert derived.reason_codes == (
        "support-unsupported", "cost-exceeds-policy", "eligible-policy-match",
        "bench-plan-complete")


def test_no_current_chain_precedes_unsupported_and_cost():
    """Catches an empty graph reported as unsupported or over cost."""
    derived = derive(policy(support="unsupported", cost=2000, maximum=1000), [])
    assert (derived.decision, derived.primary_reason) == ("pass", "no-current-chain")
    assert derived.top_chain_id is None
    assert derived.reason_codes == (
        "no-current-chain", "support-unsupported", "cost-exceeds-policy",
        "no-policy-match")


@pytest.mark.parametrize("tests", [(), (bench("t", ["chain-a"], ["s"]),)],
                         ids=["incomplete", "complete"])
def test_support_unknown_precedes_bench_plan_state(tests):
    """Catches bench-plan state reported ahead of unknown support."""
    derived = derive(policy(support="unknown"), [chain("chain-a", 1)], tests=tests)
    assert (derived.decision, derived.primary_reason) == ("defer", "support-unknown")
    expected = "bench-plan-complete" if tests else "bench-plan-incomplete"
    assert derived.reason_codes == ("support-unknown", "eligible-policy-match", expected)


def test_eligible_match_precedes_unknown_payout_path():
    """Catches an unknown payout path deferring a chain that also has an eligible match."""
    selected = policy(tier("unknown-first", "path-b", 0), tier("eligible", "path-a", 1),
                      statuses={"path-a": "eligible", "path-b": "unknown"})
    chains = [chain("chain-a", 1)]
    derived = derive(selected, chains, tests=[bench("t", ["chain-a"], ["s"])])
    assert (derived.decision, derived.primary_reason) == ("acquire", "eligible-chain")
    only_unknown = derive(policy(tier("unknown-first", "path-b", 0),
                                 statuses={"path-a": "eligible", "path-b": "unknown"}), chains)
    assert (only_unknown.decision, only_unknown.primary_reason) == (
        "defer", "payout-path-unknown")
    assert only_unknown.top_chain_id is None
