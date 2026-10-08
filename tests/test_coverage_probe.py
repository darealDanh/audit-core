import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import coverage_probe  # noqa: E402

SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"


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
def test_measure_nests_while_the_outer_session_holds_its_id(tmp_path):
    """A real nesting test: the inner measure() runs DURING the outer one.

    Sequential calls never exercise the tool-ID scan, because the first
    call frees its ID before the second asks for one. Here the inner call
    must find a second ID while the outer still holds the first - which is
    exactly what gate_coverage does on every run.

    TOOL-ID BUDGET: sys.monitoring offers only IDs 2/3/4 to us. Under
    gate_coverage the gate's probe holds one, this test's outer measure()
    holds a second and the inner one a third: the budget is FULLY consumed.
    Do not add a nesting level here; the failure would appear only in
    `make check` (not `make test`) and would name the probe, not the gate.
    """
    inner_pkg = tmp_path / "inner_pkg"
    inner_pkg.mkdir()
    (inner_pkg / "__init__.py").write_text("")
    (inner_pkg / "m.py").write_text(
        "def classify(n):\n"
        "    if n < 0:\n"
        "        return 'negative'\n"
        "    return 'other'\n"
    )
    inner_tests = tmp_path / "inner_tests"
    inner_tests.mkdir()
    (inner_tests / "test_inner_leaf.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "from inner_pkg.m import classify\n"
        "def test_other():\n"
        "    assert classify(1) == 'other'\n"
    )

    outer_pkg = tmp_path / "outer_pkg"
    outer_pkg.mkdir()
    (outer_pkg / "__init__.py").write_text("")
    (outer_pkg / "m.py").write_text("def marker():\n    return 7\n")
    outer_tests = tmp_path / "outer_tests"
    outer_tests.mkdir()
    # This test file calls measure() itself, so it runs nested inside ours.
    (outer_tests / "test_outer_leaf.py").write_text(
        "import sys, pathlib, json\n"
        f"sys.path.insert(0, {str(SCRIPTS_DIR)!r})\n"
        f"sys.path.insert(0, {str(tmp_path)!r})\n"
        "import coverage_probe\n"
        "from outer_pkg.m import marker\n"
        "def test_inner_measure_runs_nested():\n"
        "    assert marker() == 7\n"
        "    held = [i for i in (2, 3, 4) if sys.monitoring.get_tool(i)]\n"
        "    assert len(held) <= 2, (\n"
        "        f'tool-ID budget exceeded: {len(held)} of 3 IDs held before the inner '\n"
        "        'measure(). gate_coverage holds one and the outer measure() another, '\n"
        "        'so a third nesting level or a second monitoring user leaves no ID '\n"
        "        'for the inner probe. Remove a level; do not add one.')\n"
        f"    r = coverage_probe.measure(pathlib.Path({str(inner_pkg)!r}), [{str(inner_tests)!r}])\n"
        "    assert r.pytest_rc == 0\n"
        "    m = next(x for x in r.modules if x.name == 'm.py')\n"
        "    assert m.unexecuted == (3,)\n"
        f"    pathlib.Path({str(tmp_path / 'inner-result.json')!r}).write_text(json.dumps({{'unexecuted': list(m.unexecuted)}}))\n"
    )

    outer = coverage_probe.measure(outer_pkg, [str(outer_tests)])

    # The outer suite passing is the proof the inner measure() worked while
    # the outer tool ID was held - a failed inner call fails that test.
    assert outer.pytest_rc == 0
    inner_result = json.loads((tmp_path / "inner-result.json").read_text())
    assert inner_result["unexecuted"] == [3]
    outer_m = next(x for x in outer.modules if x.name == "m.py")
    assert outer_m.unexecuted == ()


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
