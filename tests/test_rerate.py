import sqlite3

from audit_core import rerate

FINDINGS_DDL = """
CREATE TABLE cba_findings (
    id TEXT PRIMARY KEY, group_id TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL, confidence INTEGER NOT NULL, cwe TEXT,
    location TEXT NOT NULL, root_cause TEXT NOT NULL, impact TEXT NOT NULL,
    attacker_position TEXT, boundary_crossed TEXT, data_flow TEXT,
    verified TEXT, poc TEXT, remediation TEXT, artifact_path TEXT,
    created_at TEXT)
"""

CHAINS_DDL = """
CREATE TABLE cba_chains (
    id TEXT PRIMARY KEY, finding_ids TEXT NOT NULL,
    attacker_position TEXT NOT NULL, pre_auth TEXT,
    completeness TEXT NOT NULL, blocking_unknowns TEXT, created_at TEXT)
"""


def _con(chains=True):
    con = sqlite3.connect(":memory:")
    con.execute(FINDINGS_DDL)
    if chains:
        con.execute(CHAINS_DDL)
    return con


def _add(con, fid, severity, **cols):
    row = {"id": fid, "group_id": "G1", "title": "t", "severity": severity,
           "confidence": 80, "location": "f.c:1", "root_cause": "rc",
           "impact": "i"}
    row.update(cols)
    keys = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    con.execute(f"INSERT INTO cba_findings ({keys}) VALUES ({marks})",
                list(row.values()))


def test_an_unauthenticated_bypass_filed_low_is_flagged():
    """REF-17, in a test. A pre-authentication authentication bypass was
    filed LOW because the overrun was scored on its own and never traced to
    the gate it overwrites - even though the finding's own text names the
    consumer branch."""
    con = _con()
    _add(con, "G1-F7", "LOW",
         title="KLAP handshake-1 overrun",
         root_cause="check-after-copy overrun reached without authentication",
         impact="overwrites the authentication gate in klap_handshake1_handle")
    con.commit()

    flags = {f.finding_id: f for f in rerate.examine(con)}

    assert "G1-F7" in flags
    assert flags["G1-F7"].implied_floor == "HIGH"
    assert any(s.rule == "unauthenticated-reach"
               for s in flags["G1-F7"].signals)
    con.close()


def test_a_finding_already_at_or_above_the_floor_is_not_flagged():
    """The report has to be short enough to read. A CRITICAL that mentions
    authentication is correctly rated and must not appear."""
    con = _con()
    _add(con, "G1-F1", "CRITICAL",
         root_cause="unauthenticated attacker bypasses authentication")
    con.commit()
    assert rerate.examine(con) == ()
    con.close()


def test_membership_of_a_pre_auth_chain_implies_critical():
    con = _con()
    _add(con, "G2-F3", "MEDIUM", root_cause="stack overflow in the parser")
    con.execute("INSERT INTO cba_chains (id, finding_ids, attacker_position, "
                "pre_auth, completeness) VALUES "
                "('C1', 'G2-F3, G1-F1', 'LAN', 'true', 'complete')")
    con.commit()
    flags = {f.finding_id: f for f in rerate.examine(con)}
    assert flags["G2-F3"].implied_floor == "CRITICAL"
    assert any(s.rule == "pre-auth-chain" for s in flags["G2-F3"].signals)
    con.close()


def test_a_database_without_cba_chains_still_runs_the_text_rules():
    """The only audit.db that exists has no cba_chains. Raising here would
    make the verb useless on the one corpus available."""
    con = _con(chains=False)
    _add(con, "G1-F7", "LOW", root_cause="reached without authentication")
    con.commit()
    flags = rerate.examine(con)
    assert len(flags) == 1
    assert flags[0].finding_id == "G1-F7"
    con.close()


def test_render_states_that_nothing_was_written():
    """The property that makes this verb safe to ship while the benchmark is
    deferred. If the output ever stops saying so, the reader has no way to
    know whether their severities were rewritten."""
    con = _con()
    _add(con, "G1-F7", "LOW", root_cause="reached without authentication")
    con.commit()
    out = rerate.render(rerate.examine(con))
    assert "No severity has been changed" in out
    assert "advisory" in out
    con.close()


def test_an_unrankable_severity_is_skipped_rather_than_raising():
    con = _con()
    _add(con, "G1-F9", "SEV-2", root_cause="reached without authentication")
    con.commit()
    assert rerate.examine(con) == ()
    con.close()


def _chain(con, cid, ids, pre_auth):
    con.execute("INSERT INTO cba_chains (id, finding_ids, attacker_position, "
                "pre_auth, completeness) VALUES (?, ?, 'LAN', ?, 'complete')",
                (cid, ids, pre_auth))


def test_chain_membership_is_a_comma_split_not_a_substring():
    con = _con()
    _add(con, "G1-F1", "LOW")
    _add(con, "G1-F10", "LOW")
    _chain(con, "C1", "G1-F10", "true")
    con.commit()
    assert {f.finding_id for f in rerate.examine(con)} == {"G1-F10"}
    con.close()


def test_a_chain_not_marked_pre_auth_flags_nothing():
    con = _con()
    _add(con, "G1-F1", "LOW")
    _chain(con, "C1", "G1-F1", "false")
    con.commit()
    assert rerate.examine(con) == ()
    con.close()


def test_the_strongest_floor_wins_not_the_weakest():
    con = _con()
    _add(con, "G1-F1", "LOW", root_cause="reached without authentication")
    _chain(con, "C1", "G1-F1", "yes")
    con.commit()
    (flag,) = rerate.examine(con)
    assert flag.implied_floor == "CRITICAL"
    assert {s.rule for s in flag.signals} == {"unauthenticated-reach",
                                              "pre-auth-chain"}
    con.close()


def test_a_finding_exactly_at_the_floor_is_not_flagged():
    con = _con()
    _add(con, "G1-F1", "HIGH", root_cause="reached without authentication")
    con.commit()
    assert rerate.examine(con) == ()
    con.close()


def test_render_says_when_the_chain_rule_did_not_run():
    out = rerate.render((), chains_absent=True)
    assert "cba_chains is not in this database" in out
    assert "cba_chains is not" not in rerate.render((), chains_absent=False)


def test_empty_segments_in_finding_ids_are_ignored():
    con = _con()
    _add(con, "G1-F1", "LOW")
    _add(con, "G2-F2", "LOW")
    _chain(con, "C1", "G1-F1,,G2-F2,", "1")
    con.commit()
    assert {f.finding_id for f in rerate.examine(con)} == {"G1-F1", "G2-F2"}
    con.close()


def test_signal_names_its_column_and_excerpt_has_no_newlines():
    con = _con()
    _add(con, "G1-F7", "LOW", root_cause="a\nb",
         attacker_position="unauthenticated\nLAN")
    con.commit()
    (flag,) = rerate.examine(con)
    (sig,) = flag.signals
    assert sig.column == "attacker_position"
    assert "\n" not in sig.evidence
    assert "[unauthenticated-reach in attacker_position]" in rerate.render((flag,))
    con.close()
