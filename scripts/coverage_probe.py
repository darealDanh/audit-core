"""Which statements in a package does the test suite never execute?

Not a coverage tool. It answers one question, with the stdlib, so the
project can gate on it without taking a dependency. `sys.monitoring` is
3.12+; on an older interpreter SUPPORTED is False and the caller skips.

**CRITICAL: This module only works correctly when called from a cold import
graph.** If `audit_core` modules are already imported when `measure()` is
called, they will not re-execute their top-level statements and `def` lines.
Pre-imported modules will incorrectly report as having unexecuted statements.
Always call `measure()` in a fresh subprocess; see the CLI entry point.

**Nesting limit:** sys.monitoring defines tool IDs 0-5. Reserving 0 (debugger),
1 (coverage), and 5 (optimizer) leaves IDs 2, 3, 4 for `measure()` — a hard
ceiling of three concurrent nested calls. Each recursive invocation uses the
next available ID. Beyond that ceiling, `measure()` raises RuntimeError.

**For Task 3 integration:** The CLI exits 0 whenever it measured successfully,
including when the measured test suite failed. To distinguish a broken
instrument from a real regression, check `pytest_rc` in the JSON output:
0 means all tests passed, 1 means test failures, 2+ means collection errors.

Two counting rules earn their keep:

  * Line 0 is an artifact of `co_lines()` and is never a statement.
  * The continuation lines of a multi-line `def` are not statements. The
    `def` line executes; `      b):` does not. On audit_core: 115 of 2,392
    statements are never executed; 95.2% coverage.
"""
from __future__ import annotations

import ast
import collections
import dataclasses
import json
import os
import pathlib
import sys

SUPPORTED = sys.version_info >= (3, 12)


@dataclasses.dataclass(frozen=True, slots=True)
class ModuleReport:
    name: str
    executable: int
    unexecuted: tuple[int, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ProbeReport:
    modules: tuple[ModuleReport, ...]
    pytest_rc: int

    @property
    def total_executable(self) -> int:
        return sum(m.executable for m in self.modules)

    @property
    def total_unexecuted(self) -> int:
        return sum(len(m.unexecuted) for m in self.modules)


def _signature_continuations(tree: ast.AST) -> set[int]:
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for line in range(node.lineno + 1, node.body[0].lineno):
                out.add(line)
    return out


def executable_statements(path: pathlib.Path) -> set[int]:
    source = path.read_text()
    code = compile(source, str(path), "exec")
    lines: set[int] = set()
    stack = [code]
    while stack:
        current = stack.pop()
        for _, _, line in current.co_lines():
            if line:
                lines.add(line)
        for const in current.co_consts:
            if hasattr(const, "co_lines"):
                stack.append(const)
    # A `def` line is executable; its continuation lines are not.
    return lines - _signature_continuations(ast.parse(source))


def measure(package: pathlib.Path, pytest_args: list[str]) -> ProbeReport:
    if not SUPPORTED:
        raise RuntimeError("sys.monitoring requires Python 3.12 or newer")
    package = package.resolve()
    hit: dict[str, set[int]] = collections.defaultdict(set)
    prefix = str(package) + os.sep

    # sys.monitoring defines tool IDs 0-5. Reserved: 0 (debugger), 1 (coverage),
    # 5 (optimizer). Available: 2, 3, 4 (hard ceiling of 3 concurrent nesting levels).
    # BUDGET: fully consumed under gate_coverage. The gate's probe holds one ID
    # and tests/test_coverage_probe.py nests two more inside it - exactly 3.
    # A further nesting level, or any other sys.monitoring user, makes
    # `make check` fail while `make test` passes.
    tool = None
    for tool_id in (2, 3, 4):
        try:
            sys.monitoring.use_tool_id(tool_id, "coverage_probe")
            tool = tool_id
            break
        except ValueError:
            continue
    if tool is None:
        raise RuntimeError(
            "No available sys.monitoring tool IDs. The budget (IDs 2-4) is "
            "fully consumed under gate_coverage: the gate's probe plus two "
            "nested levels in tests/test_coverage_probe.py. Another nesting "
            "level or a second monitoring user (debugger, profiler) exhausts it.")

    def on_line(code, line_number):
        filename = code.co_filename
        if filename.startswith(prefix):
            hit[filename].add(line_number)
            return None
        return sys.monitoring.DISABLE

    try:
        sys.monitoring.register_callback(tool, sys.monitoring.events.LINE, on_line)
        sys.monitoring.set_events(tool, sys.monitoring.events.LINE)
        import pytest
        rc = int(pytest.main([*pytest_args, "-q", "--no-header",
                              "-p", "no:cacheprovider"]))
    finally:
        sys.monitoring.set_events(tool, 0)
        sys.monitoring.restart_events()
        sys.monitoring.free_tool_id(tool)

    reports = []
    for path in sorted(package.glob("*.py")):
        statements = executable_statements(path)
        executed = hit.get(str(path), set())
        reports.append(ModuleReport(
            name=path.name,
            executable=len(statements),
            unexecuted=tuple(sorted(statements - executed))))
    return ProbeReport(modules=tuple(reports), pytest_rc=rc)


def main() -> int:
    """CLI entry point for coverage measurement.

    With --json-out PATH: writes JSON object with pytest_rc, total_executable,
    total_unexecuted, and modules list to PATH. Stdout reserved for pytest.

    Without --json-out: prints human-readable summary to stdout.

    Exit 0 on successful measurement (regardless of coverage result);
    exit non-zero on measurement failure (with error on stderr).

    Consumers of --json-out must check pytest_rc to distinguish test failures
    (rc=1) from collection errors (rc=2+) or other issues.
    """
    import argparse

    if not SUPPORTED:
        sys.stderr.write("Error: sys.monitoring requires Python 3.12 or newer\n")
        return 1

    parser = argparse.ArgumentParser(description="Measure unexecuted statements in a package")
    parser.add_argument("--package", type=pathlib.Path, required=True, help="Package to measure")
    parser.add_argument("--tests", type=str, required=True, help="Test directory or pytest argument")
    parser.add_argument("--json-out", type=pathlib.Path, help="Write JSON output to file")
    args = parser.parse_args()

    try:
        report = measure(args.package, [args.tests])

        if args.json_out:
            output = {
                "pytest_rc": report.pytest_rc,
                "total_executable": report.total_executable,
                "total_unexecuted": report.total_unexecuted,
                "modules": [
                    {
                        "name": m.name,
                        "executable": m.executable,
                        "unexecuted": m.unexecuted,
                    }
                    for m in report.modules
                ]
            }
            args.json_out.write_text(json.dumps(output))
        else:
            # Human-readable output to stdout
            print(f"{report.total_unexecuted} / {report.total_executable}")
            for m in report.modules:
                if m.unexecuted:
                    print(f"  {m.name}: {', '.join(map(str, m.unexecuted))}")

        return 0
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
