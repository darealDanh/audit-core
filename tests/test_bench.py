import sqlite3

import pytest

from audit_core import bench, db, goldens, workspace

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
# G6-F3's real location is tp_cmd_TPGV@0x0E041A00, which shares no token with
# REF-10. This fixture gives it REF-10's own sink instead, synthetically, so
# that the rejected pair has a live candidate to suppress - the whole point of
# rejections.json is a pair that overlaps but is not the same defect, and the
# real G6-F3 no longer overlaps at all once `tss` is under the token floor.
G6F3_SYNTHETIC_OVERLAP = bench.RunFinding(
    "G6-F3", "RSA private key over the debug UART", "CWE-200",
    "update_bind_token@0x0E08E554", "CRITICAL")
G5F1 = bench.RunFinding("G5-F1", "unbounded fragment reassembly", "CWE-787",
                        "tbtp_handle_characteristic_received@0x2001CA2C",
                        "CRITICAL")
G1F7_LOWER = bench.RunFinding("G1-F7", "auth bypass", "CWE-287",
                              "klaphandshake1handle@0x0E043264", "CRITICAL")
G5F1_BARE = bench.RunFinding("G5-F1", "unbounded fragment reassembly", "CWE-787",
                             "tbtp_handle_characteristic_received", "CRITICAL")


def test_a_rejected_pair_is_not_offered_as_a_candidate_again():
    assert bench.score([REF10], [G6F3_SYNTHETIC_OVERLAP], {}).candidates != ()
    scored = bench.score([REF10], [G6F3_SYNTHETIC_OVERLAP], {},
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
    scored = bench.score([REF10], [G6F3_SYNTHETIC_OVERLAP], {},
                         rejected=frozenset({("REF-11", "G6-F3")}))
    assert len(scored.candidates) == 1


def test_suppressed_count_is_skips_not_file_size():
    """The printed figure is what this run actually saved. A rejection for a
    pair that no longer overlaps at all suppresses nothing and must not be
    counted - otherwise the gate record overstates the mechanism."""
    live = bench.score([REF10], [G6F3_SYNTHETIC_OVERLAP], {},
                       rejected=frozenset({("REF-10", "G6-F3")}))
    assert live.suppressed_candidates == 1

    # Same rejection, but G6-F3 at its real location: no overlap, no skip.
    inert = bench.score([REF10], [G6F3_TSS], {},
                        rejected=frozenset({("REF-10", "G6-F3")}))
    assert inert.candidates == ()
    assert inert.suppressed_candidates == 0


def test_suppressed_count_is_zero_without_rejections():
    assert bench.score([REF10], [G6F3_SYNTHETIC_OVERLAP], {}
                       ).suppressed_candidates == 0


def test_a_rejection_for_an_adjudicated_reference_suppresses_nothing():
    """A matched reference never reaches the candidate loop, so its rejection
    cannot be counted as a saved adjudication."""
    scored = bench.score([REF19_TBTP], [G5F1_BARE], {"REF-19": "G5-F1"},
                         rejected=frozenset({("REF-19", "G5-F1")}))
    assert scored.suppressed_candidates == 0


def test_rejected_and_cost_usd_are_keyword_only(tmp_path):
    """`rejected` was added ahead of `cost_usd`. A caller that still passed a
    cost positionally would have it read as a set of rejected pairs, and the
    cost silently dropped - so neither is positional."""
    with pytest.raises(TypeError):
        bench.score([R1], [F1], {"REF-1": "F-1"}, frozenset(), 50.0)
    assert bench.score([R1], [F1], {"REF-1": "F-1"},
                       cost_usd=50.0).cost_per_match == 50.0


def verdicts(tmp_path, pairs):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = db.connect(run / "audit.db")
    for fid, verdict in pairs:
        row = {"finding_id": fid, "verdict": verdict}
        if verdict == "FALSE_POSITIVE":
            row["refuting_mechanism"] = "bounded by the window"
            row["enabled_observation"] = "1"
        db.put(con, "cba_fp_verdicts", row)
    con.close()
    return run / "audit.db"


def test_precision_counts_decided_verdicts_only(tmp_path):
    con = verdicts(tmp_path, [
        ("G1-F1", "TRUE_POSITIVE"), ("G1-F2", "TRUE_POSITIVE"),
        ("G1-F3", "FALSE_POSITIVE"), ("G1-F4", "DUPLICATE"),
        ("G1-F5", "NEEDS_VERIFICATION"),
    ])
    p = bench.precision_from_db(con)
    assert p.true_positives == 2
    assert p.false_positives == 1
    assert p.duplicates == 1
    assert p.needs_verification == 1
    assert p.decided == 3
    assert p.fraction == pytest.approx(2 / 3)


def test_precision_is_none_when_nothing_is_decided(tmp_path):
    """A run with only duplicates and undecided findings has no precision to
    report. Returning 0.0 would read as "everything was a false positive"."""
    p = bench.precision_from_db(verdicts(tmp_path, [
        ("G1-F1", "DUPLICATE"), ("G1-F2", "NEEDS_VERIFICATION")]))
    assert p.decided == 0
    assert p.fraction is None


def test_precision_from_a_database_with_no_verdicts_table_is_none(tmp_path):
    """bench deliberately opens a run database without db.connect()'s schema
    gate, so it keeps working against run directories older than the current
    schema. Those have no cba_fp_verdicts, and bench must still score recall
    on them rather than traceback."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
        "cwe TEXT, location TEXT, severity TEXT);")
    con.commit()
    con.close()
    assert bench.precision_from_db(path) is None


def test_score_carries_precision_through(tmp_path):
    p = bench.Precision(true_positives=3, false_positives=1,
                        duplicates=0, needs_verification=0)
    result = bench.score([], [], {}, precision=p)
    assert result.precision is p
