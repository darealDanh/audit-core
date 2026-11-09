"""Behavior regressions for the Stage 4j completion lifecycle.

Every test here names the exact guard a fault would remove: a completion that
outruns its recording, a transition that no SQL row accepted, canonical bytes
that moved between the two passes, a stored complete row that no longer
describes the canonical report, and the two diagnostics a failing database or
an unreadable run must collapse to.
"""
import sqlite3

import pytest

from audit_core import firmware_report as report
from tests.test_firmware_decide_input import graph_case, prepared  # noqa: F401
from tests.test_firmware_report_gate import (  # noqa: F401
    failing, recorded_report)
from tests.test_firmware_report_import import (  # noqa: F401
    prepared_report, record)
from tests.test_firmware_report_package import mtimes, stored_run
from tests.test_hunt_gate import state


def test_completion_refuses_a_timestamp_that_precedes_recording(recorded_report):
    """Catches publishing a completion stamped before its own recording."""
    con, run, root, assignments = recorded_report
    con.execute("UPDATE cba_firmware_report_runs SET recorded_at=? "
                "WHERE image_id='target' AND report_generation=?",
                ("2099-01-01 00:00:00", assignments.generation))
    con.commit()
    before = state(con)

    with pytest.raises(report.FirmwareReportError, match="precedes recording"):
        report.check(con, run, root, image_id="target")

    assert state(con) == before and not con.in_transaction


def test_completion_requires_an_actual_sql_transition(recorded_report):
    """Catches reporting completion when the guarded update changes no row."""
    source, run, root, _ = recorded_report
    before = state(source)

    class LostUpdate(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("UPDATE cba_firmware_report_runs SET status='complete'"):
                return super().execute("SELECT 1 WHERE 0")
            return super().execute(sql, parameters)

    con = failing(run, LostUpdate)
    try:
        with pytest.raises(report.FirmwareReportError,
                           match="completed before this check"):
            report.check(con, run, root, image_id="target")
        assert not con.in_transaction
    finally:
        con.close()

    assert state(source) == before


def test_completion_refuses_canonical_bytes_that_change_between_passes(
        recorded_report, monkeypatch):
    """Catches publishing the first pass's report after the authority moved."""
    con, run, root, _ = recorded_report
    original = report._render
    rendered = []

    def render_then_drift(*args, **kwargs):
        raw, index_raw, sections = original(*args, **kwargs)
        rendered.append(raw)
        if len(rendered) > 1:
            return raw + b"Drifted after installation.\n", index_raw, sections
        return raw, index_raw, sections

    monkeypatch.setattr(report, "_render", render_then_drift)
    before = state(con)

    with pytest.raises(report.FirmwareReportError, match="changed before publication"):
        report.check(con, run, root, image_id="target")

    assert len(rendered) == 2 and state(con) == before
    assert not con.in_transaction


def test_completion_refuses_a_complete_row_that_differs_from_the_report(
        recorded_report):
    """Catches trusting a stored complete row instead of the rebuilt report."""
    con, run, root, assignments = recorded_report
    report.check(con, run, root, image_id="target")
    con.execute("UPDATE cba_firmware_report_runs SET index_sha256=? "
                "WHERE image_id='target' AND report_generation=?",
                ("f" * 64, assignments.generation))
    con.commit()
    before, changes, stamps = state(con), con.total_changes, mtimes(run)

    with pytest.raises(report.FirmwareReportError,
                       match="differs from the canonical report"):
        report.check(con, run, root, image_id="target")

    assert stored_run(con, "target", assignments.generation)["index_sha256"] == "f" * 64
    assert state(con) == before and con.total_changes == changes
    assert mtimes(run) == stamps and not con.in_transaction


def test_closed_database_failures_remain_domain_errors(recorded_report):
    """Catches raw SQLite errors escaping the completion boundary."""
    con, run, root, _ = recorded_report
    con.close()

    with pytest.raises(report.FirmwareReportError,
                       match="database operation failed"):
        report.check(con, run, root, image_id="target")


def test_unreadable_run_inputs_remain_domain_errors(recorded_report, tmp_path):
    """Catches leaking raw OS/upstream failures from the completion boundary."""
    con, run, root, _ = recorded_report

    with pytest.raises(report.FirmwareReportError,
                       match="Cannot complete firmware report"):
        report.check(con, tmp_path / "ghost-run", root, image_id="target")

    assert not con.in_transaction
