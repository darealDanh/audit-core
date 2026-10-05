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
