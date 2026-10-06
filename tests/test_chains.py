import pytest

from audit_core import chains, db, workspace


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def finding(con, fid, group, **over):
    # impact is NOT NULL in schema.sql / TABLE_SPECS (a finding without a
    # stated impact isn't a finding); "im" is the existing placeholder
    # convention (see tests/test_cli_stage3.py FINDING_ARGS) and is below
    # text.MIN_LOCATION_TOKEN, so it is never tokenized by _significant and
    # cannot itself produce or suppress a shared token.
    row = {"id": fid, "group_id": group, "title": fid, "severity": "HIGH",
           "confidence": "9", "location": f"src/{group}.c:1",
           "root_cause": "rc", "impact": "im", "attacker_position": "",
           "boundary_crossed": ""}
    row.update({k: v for k, v in over.items()})
    db.put(con, "cba_findings", row)


def test_an_impact_that_grants_another_findings_precondition_is_proposed(con):
    finding(con, "G1-F1", "G1",
            impact="leaks the session_token cookie to an unauthenticated caller")
    finding(con, "G2-F1", "G2",
            attacker_position="holder of a valid session_token cookie")
    p = chains.propose(con)
    assert len(p.candidates) == 1
    c = p.candidates[0]
    assert (c.enabler, c.consumer) == ("G1-F1", "G2-F1")
    assert "session_token" in c.shared


def test_two_findings_in_the_same_group_are_not_proposed(con):
    """Per-group subagents already see their own group. The whole reason
    chains were missed is that nothing crosses groups, so proposing within
    one adds noise and no information."""
    finding(con, "G1-F1", "G1", impact="leaks the session_token cookie")
    finding(con, "G1-F2", "G1", attacker_position="holder of a session_token")
    assert chains.propose(con).candidates == ()


def test_generic_english_overlap_alone_does_not_propose(con):
    """Review Focus 5. 'user', 'remote', 'file' and 'attacker' appear in
    almost every impact and almost every attacker position. Matching on them
    turns 45 findings into hundreds of candidates."""
    finding(con, "G1-F1", "G1",
            impact="allows a remote attacker to read a user file")
    finding(con, "G2-F1", "G2",
            attacker_position="remote attacker with a user account")
    assert chains.propose(con).candidates == ()


def test_a_single_shared_token_is_not_enough(con):
    finding(con, "G1-F1", "G1", impact="writes to nvram_config")
    finding(con, "G2-F1", "G2", attacker_position="needs nvram_config set")
    assert chains.propose(con).candidates == ()


def test_boundary_crossed_also_counts_as_a_precondition(con):
    finding(con, "G1-F1", "G1",
            impact="grants write access to the firmware_partition header")
    finding(con, "G2-F1", "G2",
            boundary_crossed="firmware_partition header parsed by the loader")
    assert len(chains.propose(con).candidates) == 1


def test_findings_with_no_recorded_precondition_are_counted(con):
    """The diagnostic. Both columns are optional in cba_findings, so a run
    that never filled them cannot produce a chain -- and that fact is worth
    more than the empty candidate list."""
    finding(con, "G1-F1", "G1", impact="leaks the session_token cookie")
    finding(con, "G2-F1", "G2")
    p = chains.propose(con)
    assert p.findings_scanned == 2
    assert p.without_precondition == 2
    assert p.candidates == ()


def test_the_candidate_list_is_capped(con):
    """Review Focus 5. An uncapped proposal dumping hundreds of pairs into
    the orchestrator is the exact R1 failure this mechanism exists to serve."""
    for i in range(40):
        finding(con, f"G1-F{i}", "G1",
                impact="writes the session_token into the nvram_config blob")
    for i in range(40):
        finding(con, f"G2-F{i}", "G2",
                attacker_position="needs session_token and nvram_config")
    p = chains.propose(con)
    assert len(p.candidates) == chains.MAX_CANDIDATES
    assert p.truncated is True
    assert "narrow" in chains.render(p).lower()


def test_compose_records_an_ordered_chain(con):
    finding(con, "G1-F1", "G1", impact="leaks session_token")
    finding(con, "G2-F1", "G2", attacker_position="needs session_token")
    chains.compose(con, chain_id="C1", finding_ids="G1-F1, G2-F1",
                   attacker_position="unauthenticated on the LAN",
                   completeness="complete", pre_auth="yes")
    row = db.rows(con, "cba_chains")[0]
    assert row["finding_ids"] == "G1-F1, G2-F1"
    assert row["completeness"] == "complete"


def test_compose_rejects_a_finding_that_does_not_exist(con):
    finding(con, "G1-F1", "G1")
    with pytest.raises(db.DbError) as exc:
        chains.compose(con, chain_id="C1", finding_ids="G1-F1, G9-F9",
                       attacker_position="LAN", completeness="complete")
    assert "G9-F9" in str(exc.value)


def test_a_one_finding_chain_is_rejected(con):
    """A one-finding chain is a finding. Recording it as a chain hides it
    from the finding tally and inflates the chain tally."""
    finding(con, "G1-F1", "G1")
    with pytest.raises(db.DbError) as exc:
        chains.compose(con, chain_id="C1", finding_ids="G1-F1",
                       attacker_position="LAN", completeness="complete")
    assert "two" in str(exc.value)


def test_a_chain_that_repeats_a_finding_is_rejected(con):
    finding(con, "G1-F1", "G1")
    with pytest.raises(db.DbError):
        chains.compose(con, chain_id="C1", finding_ids="G1-F1, G1-F1",
                       attacker_position="LAN", completeness="complete")


def test_an_invented_completeness_is_rejected(con):
    finding(con, "G1-F1", "G1")
    finding(con, "G2-F1", "G2")
    with pytest.raises(db.DbError) as exc:
        chains.compose(con, chain_id="C1", finding_ids="G1-F1, G2-F1",
                       attacker_position="LAN", completeness="probably")
    assert "probably" in str(exc.value)
