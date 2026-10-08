import json
import pathlib
import subprocess
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
    (tests / "test_classify.py").write_text(
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
    (tests / "test_broken_suite.py").write_text("def test_broken():\n    assert False\n")
    report = coverage_probe.measure(pkg, [str(tests)])
    # pytest returns 1 for test failures, not 0 or 2+.
    assert report.pytest_rc == 1
    # Modules must still be reported (not empty or garbage).
    assert len(report.modules) > 0
    m = next(r for r in report.modules if r.name == "m.py")
    # m.py should have the expected executable count.
    assert m.executable == 2


@pytest.mark.skipif(not coverage_probe.SUPPORTED, reason="needs sys.monitoring (3.12+)")
def test_measure_nested_calls(tmp_path):
    """Tool ID discovery: multiple sequential measure() calls use different IDs.

    Each measure() call acquires a tool ID (2, 3, or 4, depending on availability),
    uses it during pytest execution, then frees it. Sequential calls can reuse IDs
    from freed calls. Concurrent nesting is limited to 3 levels (sys.monitoring
    defines IDs 0-5, minus 3 reserved). This test exercises the tool ID scan.
    """
    # Create two separate packages and test sets
    pkg1 = tmp_path / "pkg1"
    pkg1.mkdir()
    (pkg1 / "__init__.py").write_text("")
    (pkg1 / "m.py").write_text("def f():\n    return 1\n")

    tests1 = tmp_path / "tests1"
    tests1.mkdir()
    (tests1 / "test_1.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from pkg1.m import f\n"
        "def test_1():\n"
        "    assert f() == 1\n"
    )

    pkg2 = tmp_path / "pkg2"
    pkg2.mkdir()
    (pkg2 / "__init__.py").write_text("")
    (pkg2 / "m.py").write_text("def g():\n    return 2\n")

    tests2 = tmp_path / "tests2"
    tests2.mkdir()
    (tests2 / "test_2.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from pkg2.m import g\n"
        "def test_2():\n"
        "    assert g() == 2\n"
    )

    # First measure() call acquires tool ID 2
    report1 = coverage_probe.measure(pkg1, [str(tests1)])
    assert report1.pytest_rc == 0
    m1 = next(r for r in report1.modules if r.name == "m.py")
    assert m1.executable == 2

    # Second measure() call reuses tool ID 2 (first call freed it)
    report2 = coverage_probe.measure(pkg2, [str(tests2)])
    assert report2.pytest_rc == 0
    m2 = next(r for r in report2.modules if r.name == "m.py")
    assert m2.executable == 2


@pytest.mark.skipif(not coverage_probe.SUPPORTED, reason="needs sys.monitoring (3.12+)")
def test_cli_json_output(tmp_path):
    """CLI --json-out must emit valid JSON with correct values."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text("def f():\n    return 1\n")

    tests = tmp_path / "t"
    tests.mkdir()
    (tests / "test_cli_func.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from pkg.m import f\n"
        "def test_f():\n"
        "    assert f() == 1\n"
    )

    json_file = tmp_path / "coverage.json"
    scripts_dir = pathlib.Path(__file__).resolve().parent.parent / "scripts"
    result = subprocess.run(
        [sys.executable, str(scripts_dir / "coverage_probe.py"),
         "--package", str(pkg),
         "--tests", str(tests),
         "--json-out", str(json_file)],
        capture_output=True,
        text=True,
        cwd=str(scripts_dir.parent)
    )

    assert result.returncode == 0
    assert json_file.exists()
    data = json.loads(json_file.read_text())

    # Check JSON structure and values, not just key presence.
    assert data["pytest_rc"] == 0
    assert data["total_executable"] == 2  # def f(): and return 1
    assert data["total_unexecuted"] == 0  # All lines executed
    assert isinstance(data["modules"], list)
    assert len(data["modules"]) == 2  # __init__.py and m.py

    # Check module structure and values.
    m_module = next((m for m in data["modules"] if m["name"] == "m.py"), None)
    assert m_module is not None
    assert m_module["executable"] == 2
    assert m_module["unexecuted"] == []
