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


def test_cost_per_match_with_zero_cost():
    r = bench.score([R1], [F1], {"REF-1": "F-1"}, cost_usd=0.0)
    assert r.cost_per_match == 0.0


def test_load_findings_from_cba_schema(tmp_path):
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE cba_findings (
        id TEXT PRIMARY KEY, group_id TEXT, title TEXT, severity TEXT,
        confidence INTEGER, cwe TEXT, location TEXT NOT NULL, root_cause TEXT,
        impact TEXT, attacker_position TEXT, boundary_crossed TEXT,
        data_flow TEXT, verified TEXT, poc TEXT, remediation TEXT,
        artifact_path TEXT, created_at TEXT)""")
    con.execute("INSERT INTO cba_findings (id, title, severity, cwe, location) "
                "VALUES ('F-1', 'overflow', 'CRITICAL', 'CWE-787', 'sub_E0941B4')")
    con.commit(); con.close()
    found = bench.load_findings_from_db(db)
    assert found == [bench.RunFinding("F-1", "overflow", "CWE-787",
                                      "sub_E0941B4", "CRITICAL")]


# Fixtures for the rejection / whole-token candidate rules. Named after the
# real tplink pairs they were drawn from so the reason for each is traceable.
REF10 = goldens.Reference("REF-10", "degenerate strncpy in update_bind_token",
                          "CWE-787", ("sub_E08E554", "update_bind_token", "tss"),
                          "tss-bind-token-degenerate-strncpy-heap-overflow",
                          "CRITICAL")
REF10_SHORT = goldens.Reference("REF-10", "degenerate strncpy", "CWE-787",
                                ("tss",),
                                "tss-bind-token-degenerate-strncpy-heap-overflow",
                                "CRITICAL")
REF1_SYMBOL = goldens.Reference(
    "REF-1", "BLE reassembly overflow", "CWE-191",
    ("tbtp_handle_characteristic_received",),
    "tbtp-fragment-length-integer-underflow-mcu1-overflow", "CRITICAL")
REF1_MIXEDCASE = goldens.Reference("REF-1", "KLAP handshake-1 bypass", "CWE-287",
                                   ("KlapHandshake1Handle",),
                                   "klap-handshake1-flag-byte-auth-bypass",
                                   "CRITICAL")
REF19_TBTP = goldens.Reference(
    "REF-19", "BLE reassembly overflow", "CWE-191",
    ("tbtp_handle_characteristic_received",),
    "tbtp-fragment-length-integer-underflow-mcu1-overflow", "CRITICAL")

G6F3_TSS = bench.RunFinding("G6-F3", "RSA private key over the debug UART",
                            "CWE-200", "TssRSASecretKey", "CRITICAL")
G6F3_SHARED = bench.RunFinding("G6-F3", "RSA private key over the debug UART",
                               "CWE-200", "update_bind_token@0x0E08E554",
                               "CRITICAL")
G5F1 = bench.RunFinding("G5-F1", "unbounded fragment reassembly", "CWE-787",
                        "tbtp_handle_characteristic_received@0x2001CA2C",
                        "CRITICAL")
G1F7_LOWER = bench.RunFinding("G1-F7", "auth bypass", "CWE-287",
                              "klaphandshake1handle@0x0E043264", "CRITICAL")
G5F1_BARE = bench.RunFinding("G5-F1", "unbounded fragment reassembly", "CWE-787",
                             "tbtp_handle_characteristic_received", "CRITICAL")


def test_a_rejected_pair_is_not_offered_as_a_candidate_again():
    assert bench.score([REF10], [G6F3_SHARED], {}).candidates != ()
    scored = bench.score([REF10], [G6F3_SHARED], {},
                         rejected=frozenset({("REF-10", "G6-F3")}))
    assert scored.candidates == ()
    assert scored.unmatched_references == ("REF-10",)


def test_a_short_location_token_no_longer_generates_a_candidate():
    """REF-10's bare `tss` matched TssRSASecretKey and osal_tss_init. The
    four-character floor is why that pair cannot be raised at all now."""
    assert bench.score([REF10_SHORT], [G6F3_TSS], {}).candidates == ()


def test_a_substring_of_a_longer_token_is_not_an_overlap():
    """REF-14's bare `test` used to pair with every location containing
    `latest` or `attestation`. Whole-token matching is what stops it."""
    ref = goldens.Reference("REF-14", "hardcoded credentials", "CWE-798",
                            ("test",), "hardcoded-fallback-credentials-local-api-login",
                            "CRITICAL")
    finding = bench.RunFinding("G9-F1", "stale attestation blob", "CWE-295",
                               "verify_attestation_latest@0x0E0CE450", "LOW")
    assert bench.score([ref], [finding], {}).candidates == ()


def test_a_full_symbol_still_generates_a_candidate():
    c = bench.score([REF1_SYMBOL], [G5F1], {}).candidates
    assert len(c) == 1
    assert "tbtp_handle_characteristic_received" in c[0].reason


def test_candidate_matching_is_case_insensitive():
    assert len(bench.score([REF1_MIXEDCASE], [G1F7_LOWER], {}).candidates) == 1


def test_rejecting_a_pair_does_not_hide_an_adjudicated_match():
    """A rejection silences a candidate, never a match. matches.json wins."""
    scored = bench.score([REF19_TBTP], [G5F1_BARE], {"REF-19": "G5-F1"},
                         rejected=frozenset({("REF-19", "G5-F1")}))
    assert scored.matched == (("REF-19", "G5-F1"),)
    assert scored.recall == 1.0


def test_a_rejection_for_another_reference_does_not_suppress_this_one():
    scored = bench.score([REF10], [G6F3_SHARED], {},
                         rejected=frozenset({("REF-11", "G6-F3")}))
    assert len(scored.candidates) == 1
