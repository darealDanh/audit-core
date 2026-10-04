import sqlite3
from audit_core import bench, goldens

R1 = goldens.Reference("REF-1", "overflow in handshake", "CWE-787",
                       ("sub_E0941B4",), "klap-handshake0-unbounded-copy", "CRITICAL")
R2 = goldens.Reference("REF-2", "strcpy in records", "CWE-787",
                       ("get_doorlock_records",), "records-strcpy", "CRITICAL")

F1 = bench.RunFinding("F-1", "stack overflow", "CWE-787", "sub_E0941B4", "CRITICAL")
F9 = bench.RunFinding("F-9", "unrelated", "CWE-20", "sub_DEADBEEF", "LOW")


def test_adjudicated_match_counts_toward_recall():
    r = bench.score([R1, R2], [F1, F9], {"REF-1": "F-1"})
    assert r.matched == (("REF-1", "F-1"),)
    assert r.recall == 0.5
    assert r.unmatched_references == ("REF-2",)


def test_location_overlap_is_a_candidate_not_a_match():
    """Review Focus 5: never auto-count an unadjudicated overlap."""
    r = bench.score([R1, R2], [F1, F9], {})
    assert r.matched == ()
    assert r.recall == 0.0
    assert [c.finding_id for c in r.candidates] == ["F-1"]
    assert r.candidates[0].reference_id == "REF-1"


def test_adjudicated_pair_is_not_also_a_candidate():
    r = bench.score([R1], [F1], {"REF-1": "F-1"})
    assert r.candidates == ()


def test_adjudicated_match_to_absent_finding_does_not_count():
    r = bench.score([R1], [F9], {"REF-1": "F-404"})
    assert r.matched == ()
    assert r.recall == 0.0


def test_recall_is_zero_when_no_references():
    r = bench.score([], [F1], {})
    assert r.recall == 0.0
    assert r.reference_count == 0


def test_cost_per_match_is_none_without_cost():
    assert bench.score([R1], [F1], {"REF-1": "F-1"}).cost_per_match is None


def test_cost_per_match_divides_by_matches():
    r = bench.score([R1], [F1], {"REF-1": "F-1"}, cost_usd=50.0)
    assert r.cost_per_match == 50.0


def test_load_findings_from_cba_schema(tmp_path):
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE cba_findings (
        id TEXT PRIMARY KEY, group_id TEXT, title TEXT, severity TEXT,
        confidence INTEGER, cwe TEXT, location TEXT, root_cause TEXT,
        impact TEXT, attacker_position TEXT, boundary_crossed TEXT,
        data_flow TEXT, verified TEXT, poc TEXT, remediation TEXT,
        artifact_path TEXT, created_at TEXT)""")
    con.execute("INSERT INTO cba_findings (id, title, severity, cwe, location) "
                "VALUES ('F-1', 'overflow', 'CRITICAL', 'CWE-787', 'sub_E0941B4')")
    con.commit(); con.close()
    found = bench.load_findings_from_db(db)
    assert found == [bench.RunFinding("F-1", "overflow", "CWE-787",
                                      "sub_E0941B4", "CRITICAL")]
