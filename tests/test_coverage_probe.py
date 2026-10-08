import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import coverage_probe  # noqa: E402


def test_executable_statements_excludes_signature_continuations(tmp_path):
    """A multi-line def's continuation lines are not statements.

    Counting them is what turned a true 115 into a reported 171.
    """
    mod = tmp_path / "m.py"
    mod.write_text(
        "def f(a,\n"          # 1  def line
        "      b):\n"         # 2  continuation - NOT executable
        "    return a + b\n"  # 3
    )
    assert coverage_probe.executable_statements(mod) == {1, 3}


def test_executable_statements_ignores_line_zero(tmp_path):
    mod = tmp_path / "m.py"
    mod.write_text("x = 1\n")
    assert 0 not in coverage_probe.executable_statements(mod)


@pytest.mark.skipif(not coverage_probe.SUPPORTED, reason="needs sys.monitoring (3.12+)")
def test_measure_finds_the_branch_no_test_enters(tmp_path):
    """The instrument must actually detect a gap, or it reports green while blind."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text(
        "def classify(n):\n"
        "    if n < 0:\n"
        "        return 'negative'\n"
        "    return 'other'\n"
    )
    tests = tmp_path / "t"
    tests.mkdir()
    (tests / "test_m.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from pkg.m import classify\n"
        "def test_other():\n"
        "    assert classify(1) == 'other'\n"
    )
    report = coverage_probe.measure(pkg, [str(tests)])
    assert report.pytest_rc == 0
    m = next(r for r in report.modules if r.name == "m.py")
    # line 3 is `return 'negative'` - no test enters it
    assert m.unexecuted == (3,)


@pytest.mark.skipif(not coverage_probe.SUPPORTED, reason="needs sys.monitoring (3.12+)")
def test_measure_reports_a_failing_suite_rather_than_a_number(tmp_path):
    """Review Focus 5: a partial run must never yield a coverage figure."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text("def f():\n    return 1\n")
    tests = tmp_path / "t"
    tests.mkdir()
    (tests / "test_m.py").write_text("def test_broken():\n    assert False\n")
    report = coverage_probe.measure(pkg, [str(tests)])
    assert report.pytest_rc != 0
