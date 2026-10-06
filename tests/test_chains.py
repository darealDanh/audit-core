import pytest

from audit_core import chains, db, text, workspace


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
    """Three named things in common, not two generic ones: the session_token
    itself, the routine that mints it, and the cookie_jar it lands in. That is
    what a real enabler/consumer pair looks like written out."""
    finding(con, "G1-F1", "G1",
            impact="leaks the session_token minted by klap_handshake2 out of "
                   "the cookie_jar to an unauthenticated caller")
    finding(con, "G2-F1", "G2",
            attacker_position="holder of a session_token from "
                              "klap_handshake2, present in the cookie_jar")
    p = chains.propose(con)
    assert len(p.candidates) == 1
    c = p.candidates[0]
    assert (c.enabler, c.consumer) == ("G1-F1", "G2-F1")
    assert "session_token" in c.shared
    assert len(c.shared) >= chains.MIN_SHARED_TOKENS


def test_two_findings_in_the_same_group_are_not_proposed(con):
    """Per-group subagents already see their own group. The whole reason
    chains were missed is that nothing crosses groups, so proposing within
    one adds noise and no information."""
    finding(con, "G1-F1", "G1", impact="leaks the session_token cookie")
    finding(con, "G1-F2", "G1", attacker_position="holder of a session_token")
    assert chains.propose(con).candidates == ()


def test_generic_english_overlap_alone_does_not_propose(con):
    """Review Focus 5. Words like `session`, `credential` and `physical`
    appear in almost every impact and almost every attacker position, so
    three of them together still say nothing.

    This test used to pass for a degenerate reason: its impact tokenized to
    the empty set, so the threshold was never reached and the suppression was
    never exercised. Both sides are asserted non-empty here, and the raw
    overlap is asserted to be over the threshold, so the only thing that can
    make it pass is the filtering itself.
    """
    impact = ("leaks a persistent session credential to a physical attacker "
              "holding nvram_config")
    position = ("physical attacker with a persistent session credential and "
                "access to klap_handshake2")
    finding(con, "G1-F1", "G1", impact=impact)
    finding(con, "G2-F1", "G2", attacker_position=position)

    raw = text.location_tokens(impact) & text.location_tokens(position)
    assert len(raw - text.NOISE_WORDS) >= chains.MIN_SHARED_TOKENS, (
        "the fixture no longer reaches the threshold on generic words, so "
        "this test would pass without the generic set doing anything")
    assert chains._significant(impact), "impact must not tokenize to nothing"
    assert chains._significant(position), "position must not tokenize to nothing"

    assert chains.propose(con).candidates == ()


def test_a_single_shared_token_is_not_enough(con):
    finding(con, "G1-F1", "G1", impact="writes to nvram_config")
    finding(con, "G2-F1", "G2", attacker_position="needs nvram_config set")
    assert chains.propose(con).candidates == ()


def test_boundary_crossed_also_counts_as_a_precondition(con):
    finding(con, "G1-F1", "G1",
            impact="grants write access to the firmware_partition trailer "
                   "that verify_image_hash reads during bootloader startup")
    finding(con, "G2-F1", "G2",
            boundary_crossed="firmware_partition trailer parsed by "
                             "verify_image_hash inside the bootloader")
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
                impact="writes the session_token through nvram_commit into "
                       "the nvram_config blob")
    for i in range(40):
        finding(con, f"G2-F{i}", "G2",
                attacker_position="needs session_token, nvram_commit and "
                                  "nvram_config")
    p = chains.propose(con)
    assert len(p.candidates) == chains.MAX_CANDIDATES
    assert p.truncated is True
    assert "narrow" in chains.render(p).lower()


def test_a_truncated_proposal_says_how_many_findings_it_never_examined(con):
    """IMPORTANT. The cap was a hard `break`, so most findings were never
    examined as enablers at all -- and `render` said only "capped at 100".
    On the pinned tplink run that was 33 of 45 findings silently unlooked-at.

    `sweep.render` and `sweep.record` both apply honest-truncation discipline;
    this is that discipline here. The number matters because the cross-group
    chain this mechanism exists to find is invisible if its enabler sorts
    after the cap.
    """
    for i in range(40):
        finding(con, f"G1-F{i}", "G1",
                impact="writes the session_token through nvram_commit into "
                       "the nvram_config blob")
    for i in range(40):
        finding(con, f"G2-F{i}", "G2",
                attacker_position="needs session_token, nvram_commit and "
                                  "nvram_config")
    p = chains.propose(con)
    assert p.truncated is True
    assert p.unexamined > 0
    assert p.unexamined < p.findings_scanned
    text_out = chains.render(p)
    assert f"{p.unexamined} of {p.findings_scanned}" in text_out
    assert "never examined" in text_out


def test_an_untruncated_proposal_examined_everything(con):
    finding(con, "G1-F1", "G1",
            impact="leaks the session_token minted by klap_handshake2 out of "
                   "the cookie_jar")
    finding(con, "G2-F1", "G2",
            attacker_position="holder of a session_token from "
                              "klap_handshake2, present in the cookie_jar")
    p = chains.propose(con)
    assert (p.truncated, p.unexamined) == (False, 0)
    assert "never examined" not in chains.render(p)


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


def test_compose_accepts_a_finding_past_the_row_clamp(con):
    """IMPORTANT. `compose` read the whole id set through `db.rows`, which
    clamps at `db.MAX_ROWS` with no ORDER BY -- so *which* 200 ids it knew
    about was arbitrary, and on a 259-finding run it refused F259 with
    "names finding(s) that do not exist": a false statement about a row the
    user can see, with no workaround, since the clamp is min(limit, MAX_ROWS).
    """
    total = db.MAX_ROWS + 20
    for i in range(total):
        finding(con, f"G{i % 2 + 1}-F{i}", f"G{i % 2 + 1}")
    last = f"G{(total - 1) % 2 + 1}-F{total - 1}"
    assert len(db.rows(con, "cba_findings")) == db.MAX_ROWS   # the clamp is real
    chains.compose(con, chain_id="C1", finding_ids=f"G1-F0, {last}",
                   attacker_position="unauthenticated on the LAN",
                   completeness="complete")
    assert db.rows(con, "cba_chains")[0]["finding_ids"] == f"G1-F0, {last}"


# --- IMPORTANT 6: two callers, two sets, and a test naming each one's words ---


def test_the_chain_proposer_depends_on_these_generic_tokens():
    """`text.NOISE_WORDS` and `chains.GENERIC_TOKENS` are subtracted by two
    rules that want opposite changes: growing the shared base makes
    `db.check_identity_evidence` reject more legitimate evidence, while
    growing it is the fix for the chain proposer's unreadable candidate list.

    The base docstring said "do not grow this list without checking both
    callers' tests" and those tests did not exist. This is this caller's.
    Removing any word below breaks `test_generic_english_overlap_alone_does_
    not_propose` -- here, with a message that says which word and why.
    """
    for word in ("session", "credential", "persistent", "physical"):
        assert word in chains.GENERIC_TOKENS, (
            f"{word!r} is what keeps generic audit prose from joining two "
            f"unrelated findings; test_generic_english_overlap_alone_does_"
            f"not_propose depends on it")


def test_the_two_noise_sets_stay_separate():
    """Merging them back is the ruling that was reversed. A word in both is
    a word whose next edit silently moves the identity rule too."""
    overlap = chains.GENERIC_TOKENS & text.NOISE_WORDS
    assert overlap == frozenset(), (
        f"these words are in both sets, so growing one now moves the other: "
        f"{sorted(overlap)}")


def test_every_chain_generic_token_is_above_the_token_floor():
    """Same rule as text.NOISE_WORDS': a word shorter than
    MIN_LOCATION_TOKEN can never be subtracted, because location_tokens
    never emits it."""
    for word in chains.GENERIC_TOKENS:
        assert len(word) >= text.MIN_LOCATION_TOKEN, word
        assert word == word.lower(), word
