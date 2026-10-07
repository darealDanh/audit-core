# tests/test_bench_severity.py
import pytest

from audit_core import bench
from audit_core.goldens import Reference


def ref(rid, severity="CRITICAL"):
    return Reference(id=rid, title=f"ref {rid}", cwe=None,
                     locations=(f"fn_{rid}",), root_cause_key=rid,
                     severity=severity)


def finding(fid, severity):
    return bench.RunFinding(id=fid, title=f"finding {fid}", cwe=None,
                            location=f"fn_{fid}", severity=severity)


def test_severity_agreement_counts_under_rating():
    """The Stage 0 finding, in a test. REF-17 was a pre-authentication auth
    bypass filed LOW against a CRITICAL reference - three steps down the
    ladder - and nothing in the pipeline noticed."""
    refs = [ref("R1"), ref("R2"), ref("R3")]
    findings = [finding("F1", "CRITICAL"), finding("F2", "HIGH"),
                finding("F3", "LOW")]
    matched = (("R1", "F1"), ("R2", "F2"), ("R3", "F3"))

    agreement = bench.severity_agreement(refs, findings, matched)

    assert agreement.agreed == 1
    assert agreement.under_rated == 2
    assert agreement.over_rated == 0
    assert agreement.worst_steps == 3
    by_ref = {d.reference_id: d for d in agreement.deltas}
    assert by_ref["R3"].steps == 3
    assert by_ref["R3"].finding_severity == "LOW"
    assert "R1" not in by_ref          # agreements are not deltas


def test_weighted_recall_discounts_under_rated_matches():
    """Five agreed plus four under-rated by 1, 1, 2 and 3 steps is the
    tplink shape: 9/19 unweighted, 7.25/19 weighted."""
    refs = [ref(f"R{i}") for i in range(1, 10)]
    sevs = (["CRITICAL"] * 5) + ["HIGH", "HIGH", "MEDIUM", "LOW"]
    findings = [finding(f"F{i}", s) for i, s in enumerate(sevs, start=1)]
    matched = tuple((f"R{i}", f"F{i}") for i in range(1, 10))
    agreement = bench.severity_agreement(refs, findings, matched)

    result = bench.BenchResult(
        recall=9 / 19, matched=matched, unmatched_references=(),
        candidates=(), reference_count=19, finding_count=45,
        cost_per_match=None, severity=agreement)

    assert result.weighted_recall == pytest.approx(7.25 / 19)
    assert result.recall == pytest.approx(9 / 19)   # unchanged


def test_weighted_recall_is_none_without_a_severity_reading():
    result = bench.BenchResult(
        recall=0.5, matched=(), unmatched_references=(), candidates=(),
        reference_count=2, finding_count=1, cost_per_match=None)
    assert result.weighted_recall is None


def test_a_severity_outside_the_ladder_is_reported_not_raised():
    """Review Focus 3. A golden with a typo, or a vocabulary that grew, must
    not take the whole run's score down with it. `SEVERITIES.index` raises
    ValueError, and this is the one place both sides are untrusted strings."""
    refs = [ref("R1", severity="SEV-1"), ref("R2")]
    findings = [finding("F1", "CRITICAL"), finding("F2", "nonsense")]
    matched = (("R1", "F1"), ("R2", "F2"))

    agreement = bench.severity_agreement(refs, findings, matched)

    assert agreement.unrankable == 2
    assert agreement.agreed == 0
    assert agreement.under_rated == 0
    assert agreement.worst_steps == 0
    assert {d.reference_severity for d in agreement.deltas} == {"SEV-1", "CRITICAL"}


def test_severity_comparison_is_case_and_space_insensitive():
    """Severity reaches this from JSON a human typed and from a SQL column a
    subagent wrote. ' critical ' and 'CRITICAL' are the same claim."""
    refs = [ref("R1", severity=" critical ")]
    findings = [finding("F1", "CRITICAL")]
    agreement = bench.severity_agreement(refs, findings, (("R1", "F1"),))
    assert agreement.agreed == 1
    assert agreement.unrankable == 0
