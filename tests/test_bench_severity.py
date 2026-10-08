# tests/test_bench_severity.py
import sqlite3

import pytest

from audit_core import bench, readings
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


def test_over_rated_pair_is_counted_and_keeps_full_credit():
    """Pins the sign convention directly: a finding rated ABOVE its reference
    has negative steps, is not under-rated, and loses no credit."""
    refs = [ref("R1", severity="MEDIUM")]
    findings = [finding("F1", "CRITICAL")]
    matched = (("R1", "F1"),)
    agreement = bench.severity_agreement(refs, findings, matched)

    assert agreement.over_rated == 1
    assert agreement.under_rated == 0
    assert agreement.worst_steps == 0
    assert agreement.deltas[0].steps < 0

    result = bench.BenchResult(
        recall=1.0, matched=matched, unmatched_references=(), candidates=(),
        reference_count=1, finding_count=1, cost_per_match=None,
        severity=agreement)
    assert result.weighted_recall == pytest.approx(1.0)


def test_non_string_severity_is_unrankable_not_an_exception():
    refs = [ref("R1", severity=3), ref("R2")]
    findings = [finding("F1", "HIGH"), finding("F2", None)]
    agreement = bench.severity_agreement(
        refs, findings, (("R1", "F1"), ("R2", "F2")))
    assert agreement.unrankable == 2
    assert agreement.agreed == 0


def test_unrankable_pairs_keep_full_weighted_credit():
    refs = [ref("R1", severity="SEV-1")]
    findings = [finding("F1", "CRITICAL")]
    matched = (("R1", "F1"),)
    result = bench.BenchResult(
        recall=1.0, matched=matched, unmatched_references=(), candidates=(),
        reference_count=1, finding_count=1, cost_per_match=None,
        severity=bench.severity_agreement(refs, findings, matched))
    assert result.weighted_recall == pytest.approx(1.0)


def test_coverage_from_a_database_without_the_tables_is_absent(tmp_path):
    """The only audit.db that exists. `0%` would claim the run analysed
    nothing; the truth is the feature did not exist when it ran."""
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
                "cwe TEXT, location TEXT, severity TEXT)")
    con.commit()
    con.close()
    r = bench.coverage_from_db(db)
    assert r.is_absent
    assert "0" not in r.render("%")


def test_coverage_from_a_populated_database(tmp_path):
    db = tmp_path / "new.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_inventory (unit TEXT PRIMARY KEY, "
                "kind TEXT NOT NULL, group_id TEXT, size INTEGER, "
                "added_at TEXT)")
    con.execute("CREATE TABLE cba_coverage (unit TEXT NOT NULL, phase TEXT "
                "NOT NULL, state TEXT NOT NULL, reason TEXT, "
                "recorded_at TEXT, PRIMARY KEY (unit, phase))")
    con.executemany("INSERT INTO cba_inventory (unit, kind) VALUES (?, 'file')",
                    [("a",), ("b",), ("c",), ("d",)])
    con.execute("INSERT INTO cba_coverage (unit, phase, state) "
                "VALUES ('a','audit','analyzed')")
    con.commit()
    con.close()
    r = bench.coverage_from_db(db)
    assert r.state == readings.PRESENT
    assert r.value == 25.0


def test_a_matched_pair_naming_an_unknown_id_is_ignored():
    """bench.py:108 - a pair whose reference or finding is not in the lists
    contributes nothing, and does not raise."""
    refs = [ref("R1")]
    findings = [finding("F1", "LOW")]
    agreement = bench.severity_agreement(
        refs, findings, (("R9", "F1"), ("R1", "F9")))
    assert (agreement.agreed, agreement.under_rated, agreement.over_rated,
            agreement.unrankable) == (0, 0, 0, 0)
    assert agreement.deltas == ()
