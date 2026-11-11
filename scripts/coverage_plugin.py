"""Per-process line coverage for the parallel coverage gate.

`coverage_probe.measure` monitors in-process, which only sees tests that run
in that same process. Under `pytest-xdist` the tests run in worker
subprocesses, so the parent records nothing. This plugin moves the monitoring
into whichever process actually executes the tests: each worker measures the
package itself and writes its hit set to a fragment file, and
`coverage_probe.measure_parallel` unions the fragments afterwards.

Line coverage is a union, so splitting it across workers is exact: a
statement is executed if any worker executed it, and no worker can hide a
statement another one missed.

TOOL-ID BUDGET: this plugin holds one `sys.monitoring` ID (2/3/4) inside each
test process. That is the same single ID `gate_coverage`'s probe used to hold
in the parent, so the budget documented in `coverage_probe.measure` and
`tests/test_coverage_probe.py` is unchanged: plugin, then that file's outer
`measure()`, then its inner one - exactly three, per process.

Configured by environment, not by command line, so the setting survives the
`-p` plugin load in every worker:

    COVERAGE_PROBE_PACKAGE    absolute path of the package to measure
    COVERAGE_PROBE_FRAGMENTS  directory to write `<worker>-<pid>.json` into
"""

from __future__ import annotations

import collections
import json
import os
import pathlib
import sys

PACKAGE_ENV = "COVERAGE_PROBE_PACKAGE"
FRAGMENTS_ENV = "COVERAGE_PROBE_FRAGMENTS"

_state: dict[str, object] = {}


def _enabled() -> bool:
    return bool(os.environ.get(PACKAGE_ENV) and os.environ.get(FRAGMENTS_ENV))


def pytest_configure(config) -> None:                        # noqa: ARG001
    """Start monitoring this process before any test runs."""
    if not _enabled() or sys.version_info < (3, 12):
        return

    prefix = str(pathlib.Path(os.environ[PACKAGE_ENV]).resolve()) + os.sep
    hit: dict[str, set[int]] = collections.defaultdict(set)

    tool = None
    for tool_id in (2, 3, 4):
        try:
            sys.monitoring.use_tool_id(tool_id, "coverage_plugin")
            tool = tool_id
            break
        except ValueError:
            continue
    if tool is None:
        # Refuse rather than report a silently partial measurement: a gate
        # that cannot measure must fail, not pass with a smaller number.
        raise RuntimeError(
            "coverage_plugin: no free sys.monitoring tool ID (2/3/4) in this "
            "process. Another monitoring user (debugger, profiler, or a "
            "nested probe) holds them all.")

    def on_line(code, line_number):
        filename = code.co_filename
        if filename.startswith(prefix):
            hit[filename].add(line_number)
            return None
        return sys.monitoring.DISABLE

    sys.monitoring.register_callback(tool, sys.monitoring.events.LINE, on_line)
    sys.monitoring.set_events(tool, sys.monitoring.events.LINE)
    _state["tool"] = tool
    _state["hit"] = hit


def pytest_sessionfinish(session, exitstatus) -> None:       # noqa: ARG001
    """Stop monitoring and write this process's hits as one fragment."""
    tool = _state.pop("tool", None)
    if tool is None:
        return
    hit: dict[str, set[int]] = _state.pop("hit")             # type: ignore[assignment]
    try:
        sys.monitoring.set_events(tool, 0)
        sys.monitoring.restart_events()
    finally:
        sys.monitoring.free_tool_id(tool)

    fragments = pathlib.Path(os.environ[FRAGMENTS_ENV])
    fragments.mkdir(parents=True, exist_ok=True)
    worker = os.environ.get("PYTEST_XDIST_WORKER", "controller")
    payload = {name: sorted(lines) for name, lines in hit.items()}
    # Name by worker *and* pid: a crashed-and-restarted worker reuses its
    # name, and losing the first one's hits would report false unexecuted
    # statements.
    path = fragments / f"{worker}-{os.getpid()}.json"
    path.write_text(json.dumps(payload))
