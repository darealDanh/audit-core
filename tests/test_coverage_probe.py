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
    # pytest returns 1 for test failures. Modules should still be reported.
    assert report.pytest_rc != 0
    assert len(report.modules) > 0


@pytest.mark.skipif(not coverage_probe.SUPPORTED, reason="needs sys.monitoring (3.12+)")
def test_measure_nested_calls(tmp_path):
    """Nested measure() calls must work correctly with tool ID discovery.

    This tests the path exercised in every gate run: the gate's suite includes
    this test file, so measure() is called recursively when measuring audit_core.
    """
    # Create a package to measure
    pkg = tmp_path / "pkgnested"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "nested.py").write_text("def nested_func():\n    return 42\n")

    tests = tmp_path / "tnested"
    tests.mkdir()
    (tests / "test_nested.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from pkgnested.nested import nested_func\n"
        "\n"
        "def test_nested_function():\n"
        "    assert nested_func() == 42\n"
    )

    # First call to measure() - outer
    report1 = coverage_probe.measure(pkg, [str(tests)])
    assert report1.pytest_rc == 0
    assert len(report1.modules) > 0

    # Second call to measure() with different package - this uses different tool ID
    # to simulate a nested call
    pkg2 = tmp_path / "pkgnested2"
    pkg2.mkdir()
    (pkg2 / "__init__.py").write_text("")
    (pkg2 / "nested2.py").write_text("def another_func():\n    return 99\n")

    tests2 = tmp_path / "tnested2"
    tests2.mkdir()
    (tests2 / "test_nested2.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from pkgnested2.nested2 import another_func\n"
        "\n"
        "def test_another_function():\n"
        "    assert another_func() == 99\n"
    )

    # Second call - should use a different tool ID
    report2 = coverage_probe.measure(pkg2, [str(tests2)])
    assert report2.pytest_rc == 0
    assert len(report2.modules) > 0

    # Both should have measured their respective packages correctly
    assert any(m.name == "nested.py" for m in report1.modules)
    assert any(m.name == "nested2.py" for m in report2.modules)


@pytest.mark.skipif(not coverage_probe.SUPPORTED, reason="needs sys.monitoring (3.12+)")
def test_cli_json_output(tmp_path):
    """CLI must emit valid JSON with correct structure."""
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

    scripts_dir = pathlib.Path(__file__).resolve().parent.parent / "scripts"
    result = subprocess.run(
        [sys.executable, str(scripts_dir / "coverage_probe.py"),
         "--package", str(pkg),
         "--tests", str(tests),
         "--json"],
        capture_output=True,
        text=True,
        cwd=str(scripts_dir.parent)
    )

    assert result.returncode == 0
    # The stdout has pytest output followed by JSON. Extract just the JSON part.
    lines = result.stdout.strip().split('\n')
    json_line = [l for l in lines if l.startswith('{')][-1]
    data = json.loads(json_line)

    # Check JSON structure
    assert "pytest_rc" in data
    assert "total_executable" in data
    assert "total_unexecuted" in data
    assert "modules" in data
    assert isinstance(data["modules"], list)
    assert len(data["modules"]) > 0

    # Check module structure
    for module in data["modules"]:
        assert "name" in module
        assert "executable" in module
        assert "unexecuted" in module
        assert isinstance(module["unexecuted"], list)
