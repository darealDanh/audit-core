import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import coverage_allowlist as al  # noqa: E402
import coverage_probe as probe  # noqa: E402


def test_parse_reads_an_entry():
    entries = al.parse("qualify.py:180:a1b2c3d4  the no-RCE verdict branch\n")
    assert len(entries) == 1
    assert entries[0].module == "qualify.py"
    assert entries[0].line == 180
    assert entries[0].digest == "a1b2c3d4"
    assert entries[0].reason == "the no-RCE verdict branch"


def test_parse_skips_comments_and_blanks():
    assert al.parse("# a comment\n\n   \n") == ()


def test_parse_refuses_an_entry_without_a_reason():
    """A gap recorded without a reason makes the denominator look accounted for."""
    with pytest.raises(al.AllowlistError, match="needs a reason"):
        al.parse("qualify.py:180:a1b2c3d4\n")


def test_parse_refuses_a_duplicate_entry():
    text = ("qualify.py:180:a1b2c3d4  first\n"
            "qualify.py:180:a1b2c3d4  second\n")
    with pytest.raises(al.AllowlistError, match="listed twice"):
        al.parse(text)


def test_parse_refuses_a_malformed_line():
    with pytest.raises(al.AllowlistError, match="malformed"):
        al.parse("this is not an entry\n")


def _report(tmp_path, name, source, unexecuted):
    (tmp_path / name).write_text(source)
    return probe.ProbeReport(
        modules=(probe.ModuleReport(name=name, executable=10,
                                    unexecuted=tuple(unexecuted)),),
        pytest_rc=0)


def test_compare_permits_a_listed_unexecuted_line(tmp_path):
    src = "a = 1\nb = 2\nc = 3\n"
    report = _report(tmp_path, "m.py", src, [2])
    entries = al.parse(f"m.py:2:{al.line_digest('b = 2')}  deliberate\n")
    result = al.compare(report, entries, tmp_path)
    assert result.ok
    assert result.permitted == ("m.py:2  deliberate",)


def test_compare_fails_on_an_unlisted_unexecuted_line(tmp_path):
    src = "a = 1\nb = 2\nc = 3\n"
    report = _report(tmp_path, "m.py", src, [2])
    result = al.compare(report, (), tmp_path)
    assert not result.ok
    assert result.regressed == ("m.py:2  b = 2",)


def test_compare_fails_on_a_listed_line_that_now_runs(tmp_path):
    """The list cannot rot into a stale blanket permission."""
    src = "a = 1\nb = 2\nc = 3\n"
    report = _report(tmp_path, "m.py", src, [])
    entries = al.parse(f"m.py:2:{al.line_digest('b = 2')}  deliberate\n")
    result = al.compare(report, entries, tmp_path)
    assert not result.ok
    assert result.executed_but_listed == ("m.py:2  deliberate",)


def test_compare_reports_a_moved_line_as_stale_not_permitted(tmp_path):
    """Review Focus 1: an edit above an entry must not silently re-aim it."""
    src = "a = 1\nINSERTED = 0\nb = 2\nc = 3\n"   # b = 2 moved 2 -> 3
    report = _report(tmp_path, "m.py", src, [2])
    entries = al.parse(f"m.py:2:{al.line_digest('b = 2')}  deliberate\n")
    result = al.compare(report, entries, tmp_path)
    assert not result.ok
    assert result.stale and "m.py:2" in result.stale[0]
    assert result.permitted == ()
    # Also verify the moved line is not reported as regressed
    assert result.regressed == ()


def test_compare_reports_stale_when_listed_file_deleted(tmp_path):
    """A listed entry whose module file has been deleted reports stale, not executed."""
    src = "a = 1\nb = 2\nc = 3\n"
    report = _report(tmp_path, "m.py", src, [])
    entries = al.parse(f"m.py:2:{al.line_digest('b = 2')}  deliberate\n")
    # Delete the file after creating it
    (tmp_path / "m.py").unlink()
    result = al.compare(report, entries, tmp_path)
    assert not result.ok
    assert result.stale == ("m.py:2  the listed line no longer exists; "
                            "re-check the reason and update the digest (deliberate)",)
    assert result.executed_but_listed == ()


def test_compare_reports_stale_when_line_past_eof(tmp_path):
    """A listed entry whose line number is past EOF reports stale, not executed."""
    src = "a = 1\nb = 2\nc = 3\n"
    report = _report(tmp_path, "m.py", src, [])
    entries = al.parse(f"m.py:100:{al.line_digest('past EOF')}  deliberate\n")
    result = al.compare(report, entries, tmp_path)
    assert not result.ok
    assert result.stale == ("m.py:100  the listed line no longer exists; "
                            "re-check the reason and update the digest (deliberate)",)
    assert result.executed_but_listed == ()


def test_line_digest_ignores_whitespace():
    """Reindenting a block should not invalidate every entry inside it."""
    assert al.line_digest("  x = 1") == al.line_digest("x = 1")


def test_compare_reports_stale_when_an_unexecuted_entry_s_file_is_gone(tmp_path):
    """The first loop's `source is None` guard.

    The entry is BOTH in the report's unexecuted set AND its file is gone,
    so this enters the first loop - unlike the second-loop cases, which
    reach their guard only because the entry is absent from `unexecuted`.
    """
    (tmp_path / "m.py").write_text("a = 1\nb = 2\n")
    entries = al.parse(f"m.py:2:{al.line_digest('b = 2')}  deliberate\n")
    (tmp_path / "m.py").unlink()          # file gone, entry still listed
    report = probe.ProbeReport(
        modules=(probe.ModuleReport(name="m.py", executable=10,
                                    unexecuted=(2,)),),
        pytest_rc=0)
    result = al.compare(report, entries, tmp_path)
    assert not result.ok
    assert len(result.stale) == 1 and "m.py:2" in result.stale[0]
    assert result.permitted == ()
    assert result.regressed == ()


def test_compare_reports_stale_when_unexecuted_line_is_past_eof(tmp_path):
    """The first loop's `source is None` guard for past-EOF case.

    The line is in the report's unexecuted set, the file exists,
    but the line number exceeds EOF, so `source` is None in the first loop.
    """
    (tmp_path / "m.py").write_text("a = 1\nb = 2\nc = 3\n")
    entries = al.parse(f"m.py:100:{al.line_digest('past EOF')}  deliberate\n")
    report = probe.ProbeReport(
        modules=(probe.ModuleReport(name="m.py", executable=10,
                                    unexecuted=(100,)),),
        pytest_rc=0)
    result = al.compare(report, entries, tmp_path)
    assert not result.ok
    assert len(result.stale) == 1 and "m.py:100" in result.stale[0]
    assert result.permitted == ()
    assert result.regressed == ()


def test_shipped_allowlist_parses_and_every_entry_has_a_reason():
    text = (pathlib.Path(__file__).resolve().parent.parent
            / "scripts" / "coverage-allowlist.txt").read_text()
    entries = al.parse(text)
    # Stage 3c closed every gap, so the shipped list may legitimately be
    # empty; what it may never hold is an entry without a reason.
    assert all(e.reason for e in entries)


def _load_harness():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "harness", pathlib.Path(__file__).resolve().parent.parent
        / "scripts" / "harness.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    return harness


def test_harness_exposes_the_coverage_gate():
    harness = _load_harness()
    assert "coverage" in harness.GATES
    assert "coverage" in harness.DEFAULT


def test_coverage_gate_skips_below_3_12_with_its_reason(monkeypatch):
    harness = _load_harness()
    monkeypatch.setattr(harness.sys, "version_info", (3, 10, 0, "final", 0))
    result = harness.gate_coverage()
    assert result.name == "coverage"
    assert result.status == harness.SKIP
    assert "3.12" in result.summary and "3.10" in result.summary


def _fake_probe(harness, monkeypatch, payload):
    import json
    import subprocess

    def fake_run(cmd, **kwargs):
        out = pathlib.Path(cmd[cmd.index("--json-out") + 1])
        out.write_text(json.dumps(payload))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(harness.subprocess, "run", fake_run)


@pytest.mark.skipif(not probe.SUPPORTED, reason="needs 3.12+")
def test_coverage_gate_fails_when_the_measured_suite_failed(monkeypatch):
    harness = _load_harness()
    _fake_probe(harness, monkeypatch, {"pytest_rc": 1, "total_executable": 0,
                                       "total_unexecuted": 0, "modules": []})
    result = harness.gate_coverage()
    assert result.status == harness.FAIL
    assert "pytest rc 1" in result.summary


@pytest.mark.skipif(not probe.SUPPORTED, reason="needs 3.12+")
def test_coverage_gate_fails_naming_an_unlisted_gap(monkeypatch):
    harness = _load_harness()
    _fake_probe(harness, monkeypatch, {
        "pytest_rc": 0, "total_executable": 10, "total_unexecuted": 1,
        "modules": [{"name": "qualify.py", "executable": 10,
                     "unexecuted": [1]}]})
    result = harness.gate_coverage()
    assert result.status == harness.FAIL
    assert "unlisted: qualify.py:1" in result.detail
    # The detail carries a ready-to-paste entry, digest included.
    first = (pathlib.Path(__file__).resolve().parent.parent
             / "audit_core" / "qualify.py").read_text().split("\n")[0]
    assert al.format_entry("qualify.py", 1, first, "<reason>") in result.detail
    assert "coverage_allowlist.py --add qualify.py:1" in result.detail


def test_add_entry_appends_in_the_modules_section():
    text = "# head\n\n# --- a.py ---\na.py:1:aaaaaaaa  r\n\n# --- b.py ---\n"
    out = al.add_entry(text, "a.py", 5, "    x = 1", "why", {("a.py", 5)})
    lines = out.split("\n")
    assert lines.index(al.format_entry("a.py", 5, "x = 1", "why")) == 4
    assert al.parse(out)[-1].line == 5 or len(al.parse(out)) == 2


def test_add_entry_creates_a_missing_section():
    out = al.add_entry("# head\n", "c.py", 2, "y", "why", {("c.py", 2)})
    assert "# --- c.py ---\nc.py:2:" in out
    assert al.parse(out)[0].digest == al.line_digest("y")


def test_add_entry_refuses_an_empty_reason():
    with pytest.raises(al.AllowlistError, match="reason"):
        al.add_entry("", "a.py", 1, "x", "   ", {("a.py", 1)})


def test_add_entry_refuses_an_executed_line():
    with pytest.raises(al.AllowlistError, match="executed"):
        al.add_entry("", "a.py", 1, "x", "why", set())


def test_add_entry_refuses_a_duplicate():
    text = al.format_entry("a.py", 1, "x", "r") + "\n"
    with pytest.raises(al.AllowlistError, match="already listed"):
        al.add_entry(text, "a.py", 1, "x", "why", {("a.py", 1)})


def test_cli_add_writes_the_file(tmp_path, monkeypatch):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "m.py").write_text("a = 1\nb = 2\n")
    f = tmp_path / "allow.txt"
    f.write_text("# head\n")
    monkeypatch.setattr(al, "PACKAGE_PATH", pkg)
    monkeypatch.setattr(al, "ALLOWLIST_PATH", f)
    monkeypatch.setattr(al, "_measure_unexecuted", lambda: {("m.py", 2)})
    assert al.main(["--add", "m.py:2", "cannot run"]) == 0
    assert al.parse(f.read_text())[0].digest == al.line_digest("b = 2")
    assert al.main(["--add", "m.py:2", "again"]) == 1      # duplicate
    assert al.main(["--add", "m.py:1", "x"]) == 1          # executed
    assert al.main(["--add", "m.py:2", " "]) == 1          # empty reason
    assert al.main(["--add", "m.py:99", "x"]) == 1         # no such line
    assert al.main(["--add", "bad", "x"]) == 2
