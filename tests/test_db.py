import sqlite3

import pytest

from audit_core import db, workspace

FINDING = {
    "id": "G1-F1", "group_id": "G1", "title": "stack overflow in klap handshake",
    "severity": "HIGH", "confidence": "9", "location": "src/klap.c:120",
    "root_cause": "unbounded memcpy into a fixed stack buffer",
    "impact": "pre-auth remote code execution",
}


@pytest.fixture()
def con(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    c = db.connect(run / "audit.db")
    yield c
    c.close()


def test_connect_rejects_a_missing_database_with_the_fix_in_the_message(tmp_path):
    with pytest.raises(db.DbError) as exc:
        db.connect(tmp_path / "nope.db")
    assert "audit.py init" in str(exc.value)


def pre_stage2_db(tmp_path):
    """A run directory as this branch's predecessor left it.

    Built by truncating the real schema.sql at its own `Stage 2 additions`
    marker rather than pasting a copy of the old DDL, so the fixture tracks
    the file instead of drifting from it.
    """
    full = workspace.SCHEMA_PATH.read_text()
    head, marker, _ = full.partition("-- Stage 2 additions")
    assert marker, "schema.sql no longer carries the Stage 2 marker"
    path = tmp_path / "old-run" / "audit.db"
    path.parent.mkdir(parents=True)
    con = sqlite3.connect(path)
    try:
        con.executescript(head)
        con.commit()
    finally:
        con.close()
    return path


def test_connect_rejects_a_pre_stage2_schema_with_the_remedy_in_the_message(tmp_path):
    """The normal upgrade path: an installed skill moves forward and the next
    phase of an in-flight audit reaches an existing run directory. Six verbs
    used to answer that with `sqlite3.OperationalError: no such table`."""
    with pytest.raises(db.DbError) as exc:
        db.connect(pre_stage2_db(tmp_path))
    msg = str(exc.value)
    assert "cba_inventory" in msg               # names what is missing
    assert "cba_checkpoints" in msg
    assert "cba_findings" not in msg            # ...and only what is missing
    assert "audit.py init" in msg               # names the remedy
    assert "--timestamp" in msg                 # ...including the flag that
                                                # re-uses the run directory
    assert "IF NOT EXISTS" in msg               # ...and why it is safe


def test_connect_accepts_a_database_the_current_schema_built(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    db.connect(run / "audit.db").close()


def test_a_pre_stage2_run_is_repaired_by_init_with_its_own_timestamp(tmp_path):
    """The remedy the message names has to actually work, and has to keep the
    rows the earlier phases recorded."""
    path = pre_stage2_db(tmp_path)
    con = sqlite3.connect(path)
    con.execute("INSERT INTO cba_feature_groups (id, name) VALUES ('G1','klap')")
    con.commit()
    con.close()
    workspace.apply_schema(path)
    repaired = db.connect(path)
    try:
        assert [tuple(r) for r in db.rows(repaired, "cba_feature_groups",
                                          columns=("id", "name"))] == [("G1", "klap")]
        assert db.rows(repaired, "cba_inventory") == []
    finally:
        repaired.close()


def test_put_writes_a_row_that_rows_reads_back(con):
    db.put(con, "cba_findings", dict(FINDING))
    got = db.rows(con, "cba_findings", columns=("id", "severity", "location"))
    assert [tuple(r) for r in got] == [("G1-F1", "HIGH", "src/klap.c:120")]


def test_put_rejects_an_unknown_table(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_nope", {"id": "x"})
    assert "cba_findings" in str(exc.value)      # names what IS writable


def test_put_rejects_an_unknown_column_and_names_it(con):
    bad = dict(FINDING) | {"sevrity": "HIGH"}
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", bad)
    assert "sevrity" in str(exc.value)


def test_put_rejects_a_missing_required_column_and_names_it(con):
    bad = {k: v for k, v in FINDING.items() if k != "impact"}
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", bad)
    assert "impact" in str(exc.value)


def test_put_treats_a_blank_required_column_as_missing(con):
    """`--set impact=` is the same failure as omitting it, and `briefs.py`
    already learned that an empty value reported as success is worse than a
    loud rejection."""
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", dict(FINDING) | {"impact": "   "})
    assert "impact" in str(exc.value)


def test_put_rejects_an_invented_severity(con):
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_findings", dict(FINDING) | {"severity": "SEVERE"})
    assert "SEVERE" in str(exc.value)


def test_put_rejects_an_invented_verdict(con):
    db.put(con, "cba_findings", dict(FINDING))
    with pytest.raises(db.DbError) as exc:
        db.put(con, "cba_fp_verdicts", {"finding_id": "G1-F1", "verdict": "PROBABLY"})
    assert "PROBABLY" in str(exc.value)


def test_put_without_replace_rejects_a_duplicate_primary_key(con):
    db.put(con, "cba_findings", dict(FINDING))
    with pytest.raises(db.DbError):
        db.put(con, "cba_findings", dict(FINDING))


def test_put_with_replace_overwrites(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"severity": "CRITICAL"}, replace=True)
    assert db.rows(con, "cba_findings", columns=("severity",))[0][0] == "CRITICAL"


def test_put_binds_values_so_quotes_and_semicolons_survive_intact(con):
    """Review Focus 4. A root cause legitimately contains `'` and `;`.

    The column names are whitelisted against the TableSpec, so they can be
    interpolated; the values never are.
    """
    nasty = "strcpy(dst, src); the caller's bound is never checked -- see note"
    db.put(con, "cba_findings", dict(FINDING) | {"root_cause": nasty})
    assert db.rows(con, "cba_findings", columns=("root_cause",))[0][0] == nasty
    # The table still exists: the semicolon did not terminate a statement.
    assert db.rows(con, "cba_findings", columns=("id",))[0][0] == "G1-F1"


def test_rows_rejects_an_unknown_column_in_where(con):
    with pytest.raises(db.DbError) as exc:
        db.rows(con, "cba_findings", where={"sevrity": "HIGH"})
    assert "sevrity" in str(exc.value)


def test_rows_is_bounded_even_when_asked_for_more(con):
    for i in range(5):
        db.put(con, "cba_findings", dict(FINDING) | {"id": f"G1-F{i}"})
    assert len(db.rows(con, "cba_findings", limit=10_000)) <= db.MAX_ROWS
    assert len(db.rows(con, "cba_findings", limit=2)) == 2


def test_status_counts_groups_findings_and_verdicts(con):
    db.put(con, "cba_feature_groups", {"id": "G1", "name": "auth", "status": "complete"})
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G1-F2", "severity": "LOW"})
    db.put(con, "cba_fp_verdicts", {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})
    s = db.status(con)
    assert s.groups == (("G1", "auth", "complete"),)
    assert ("G1", "HIGH", 1) in s.findings_by_group_severity
    assert ("G1", "LOW", 1) in s.findings_by_group_severity
    assert s.verdicts == (("TRUE_POSITIVE", 1),)
    assert s.totals == {"groups": 1, "findings": 2, "verdicts": 1, "unverdicted": 1}


def test_render_status_names_the_unverdicted_gap(con):
    db.put(con, "cba_findings", dict(FINDING))
    out = db.render_status(db.status(con))
    assert "unverdicted" in out
    assert "1" in out


def test_duplicates_pairs_the_same_root_cause_across_groups(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {
        "id": "G2-F3", "group_id": "G2", "confidence": "7",
        "root_cause": "Unbounded memcpy, into a fixed stack buffer!",
        "location": "src/klap.c:124",
    })
    pairs = db.duplicates(con)
    assert len(pairs) == 1
    assert pairs[0].keep == "G1-F1"        # confidence 9 beats 7
    assert pairs[0].drop == "G2-F3"
    assert "klap" in pairs[0].shared_locations


def test_duplicates_ignores_two_findings_in_the_same_group(con):
    """Within a group one subagent wrote both; cross-group collision is the
    case phase4 asked the orchestrator to catch by eye."""
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G1-F2"})
    assert db.duplicates(con) == []


def test_duplicates_ignores_a_shared_root_cause_in_unrelated_files(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {
        "id": "G2-F1", "group_id": "G2", "location": "src/upnp/ssdp.c:41",
    })
    assert db.duplicates(con) == []


def test_duplicates_never_deletes_anything(con):
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G2-F3", "group_id": "G2"})
    db.duplicates(con)
    assert len(db.rows(con, "cba_findings")) == 2


# --- Stage 3c, Task 6: statements no test used to execute -------------------

def test_connect_read_only_refuses_a_write(tmp_path):
    """db.py:330 - the read-only path opens the file mode=ro."""
    run, _ = workspace.init_run_with_schema(tmp_path, "20260101-000000")
    con = db.connect(run / "audit.db", read_only=True)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            con.execute("INSERT INTO cba_sources (id, type) VALUES ('x', 'repo')")
        assert con.execute("SELECT COUNT(*) FROM cba_sources").fetchone()[0] == 0
    finally:
        con.close()


def test_connect_rejects_a_file_that_is_not_a_database(tmp_path):
    """db.py:337-339 - a text file named audit.db is the realistic case."""
    fake = tmp_path / "audit.db"
    fake.write_text("this is not a database\n" * 20)
    with pytest.raises(db.DbError) as excinfo:
        db.connect(fake)
    assert str(excinfo.value).startswith(f"{fake} is not a readable SQLite database: ")


def test_rows_names_every_unknown_selected_column(tmp_path):
    """db.py:466 - rows() checks `columns`; the where-check is a separate line."""
    run, _ = workspace.init_run_with_schema(tmp_path, "20260101-000000")
    con = db.connect(run / "audit.db")
    try:
        with pytest.raises(db.DbError) as excinfo:
            db.rows(con, "cba_findings", columns=("id", "nope", "also_nope"))
        # Exact text: put() words the same error differently ("; columns are:"),
        # so equality proves this came from rows().
        assert str(excinfo.value) == "cba_findings has no column(s): also_nope, nope"
    finally:
        con.close()


def test_put_replace_without_the_primary_key_inserts_and_merges_nothing(con):
    """db.py:411 - no key named means no row is provably replaced.

    cba_attack_surface's key is an autoincrement id. A replace that does not
    name it cannot target a stored row, so it is a plain insert: the existing
    row keeps its optional columns and the new row does not inherit them.
    """
    db.put(con, "cba_attack_surface", {
        "id": "1", "group_id": "G1", "endpoint": "/login", "method": "POST",
        "description": "credential check"})
    db.put(con, "cba_attack_surface", {"group_id": "G1", "endpoint": "/login"},
           replace=True)
    got = db.rows(con, "cba_attack_surface")
    assert len(got) == 2
    stored = {r["id"]: r for r in got}
    assert stored[1]["method"] == "POST"
    assert stored[1]["description"] == "credential check"
    new = next(r for r in got if r["id"] != 1)
    assert new["method"] is None and new["description"] is None


def test_put_replace_keeps_an_omitted_optional_column_when_the_key_is_named(con):
    """The documented merge contract (sibling of 411): omitted columns keep
    their stored value. Closed in stage3b: replace-blanks-optional-columns."""
    db.put(con, "cba_fp_verdicts", {
        "finding_id": "G1-F1", "verdict": "TRUE_POSITIVE", "final_id": "F-07"})
    db.put(con, "cba_fp_verdicts",
           {"finding_id": "G1-F1", "verdict": "NEEDS_VERIFICATION"}, replace=True)
    (row,) = db.rows(con, "cba_fp_verdicts")
    assert row["verdict"] == "NEEDS_VERIFICATION"
    assert row["final_id"] == "F-07"


def test_render_status_lists_groups_and_verdicts_with_counts(con):
    """db.py:522-523 and 528-529."""
    db.put(con, "cba_feature_groups", {"id": "G1", "name": "auth", "status": "complete"})
    db.put(con, "cba_feature_groups", {"id": "G2", "name": "upnp", "status": "pending"})
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G2-F1", "group_id": "G2"})
    db.put(con, "cba_fp_verdicts", {"finding_id": "G1-F1", "verdict": "TRUE_POSITIVE"})
    db.put(con, "cba_fp_verdicts", {"finding_id": "G2-F1", "verdict": "DUPLICATE"})
    lines = db.render_status(db.status(con)).splitlines()
    assert lines[0] == "groups 2   findings 2   verdicts 2   unverdicted 0"
    g = lines.index("  groups:")
    assert lines[g + 1].split() == ["G1", "auth", "complete"]
    assert lines[g + 2].split() == ["G2", "upnp", "pending"]
    v = lines.index("  verdicts:")
    assert lines[v + 1].split() == ["DUPLICATE", "1"]
    assert lines[v + 2].split() == ["TRUE_POSITIVE", "1"]


def test_duplicates_skips_a_finding_whose_root_cause_normalises_to_nothing(con):
    """db.py:560 - punctuation-only root causes would otherwise all pair up."""
    punct = dict(FINDING) | {"root_cause": "!!! ???"}
    db.put(con, "cba_findings", punct)
    db.put(con, "cba_findings", punct | {"id": "G2-F1", "group_id": "G2"})
    assert db.duplicates(con) == []


def test_duplicates_skips_a_cross_group_pair_with_different_root_causes(con):
    """db.py:566 - same location, different mechanism: not a duplicate."""
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {
        "id": "G2-F1", "group_id": "G2", "root_cause": "missing auth check"})
    assert db.duplicates(con) == []


def test_duplicates_ranks_a_non_numeric_confidence_as_zero(con):
    """db.py:578-579 - _conf falls back to 0, so a numeric score wins."""
    db.put(con, "cba_findings", dict(FINDING) | {"confidence": "high"})
    db.put(con, "cba_findings", dict(FINDING) | {
        "id": "G2-F1", "group_id": "G2", "confidence": "1"})
    (pair,) = db.duplicates(con)
    assert pair.keep == "G2-F1" and pair.drop == "G1-F1"
    assert db._conf({"confidence": "high"}) == 0
    assert db._conf({"confidence": None}) == 0


# --- Stage 3c Task 15: boundaries the first mutation sweep found unpinned ----

def test_identity_evidence_of_exactly_the_minimum_length_is_accepted():
    """db.py:157. `len < MIN` accepts exactly MIN characters; `<=` would turn
    the floor into 'more than 20'. 19 is refused, 20 is not."""
    path = "src/a.c"
    twenty = "offset 0x40: Wi-FiMAC"[:db.MIN_EVIDENCE_CHARS]
    assert len(twenty) == db.MIN_EVIDENCE_CHARS
    db.check_identity_evidence(path, twenty)
    with pytest.raises(db.DbError, match="19 characters"):
        db.check_identity_evidence(path, twenty[:-1])


def test_replace_does_not_bind_a_stored_null_over_the_columns_default(con):
    """db.py:419. The merge keeps a stored value for a column the caller did
    not name, but a stored NULL is left out so the column's DEFAULT applies on
    re-insert. With `and` turned into `or`, the NULL is carried over and bound,
    and the default is lost."""
    db.put(con, "cba_findings", dict(FINDING))
    con.execute("UPDATE cba_findings SET verified = NULL WHERE id = 'G1-F1'")
    assert db.rows(con, "cba_findings", columns=("verified",))[0][0] is None
    db.put(con, "cba_findings", dict(FINDING) | {"severity": "LOW"},
           replace=True)
    (row,) = db.rows(con, "cba_findings", columns=("severity", "verified"))
    assert row["severity"] == "LOW"
    assert row["verified"] == "source-only"


def test_duplicates_tie_on_confidence_keeps_the_earlier_finding(con):
    """db.py:570. Equal confidence is a tie, and a tie resolves to the earlier
    id (rows are ordered by id), not to whichever is listed second."""
    db.put(con, "cba_findings", dict(FINDING))
    db.put(con, "cba_findings", dict(FINDING) | {"id": "G2-F3", "group_id": "G2"})
    (pair,) = db.duplicates(con)
    assert (pair.keep, pair.drop) == ("G1-F1", "G2-F3")
