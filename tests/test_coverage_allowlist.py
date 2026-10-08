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
