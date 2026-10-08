# Stage 3c — Core Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the 115 statements in `audit_core` that no test executes, and ship two instruments — a coverage gate and a mutation harness — that stop the condition recurring.

**Architecture:** Two stdlib detectors under `scripts/`, neither inside `audit_core`. `coverage_probe.py` runs the suite under a `sys.monitoring` LINE callback and compares the unexecuted set against a reasoned, content-hashed allowlist, failing in both directions. `mutate.py` applies one AST mutation at a time to a temp copy of the tree and reports mutants that no test kills. The coverage half runs first; the mutation sweep then validates the tests that half produced.

**Tech Stack:** Python 3.14 (floor 3.10), stdlib only — `sys.monitoring`, `ast`, `hashlib`, `subprocess`, `tempfile`. `pytest` 9.1.1 as the only dev dependency. No new dependencies.

**Spec:** [`docs/superpowers/specs/2026-10-08-stage3c-core-hardening-design.md`](../specs/2026-10-08-stage3c-core-hardening-design.md)

## Global Constraints

- `audit_core` stays **stdlib-only**. `pyproject.toml` declares `dependencies = []` and `requires-python = ">=3.10"`. Neither changes. Both instruments live in `scripts/`, never in `audit_core`.
- `sys.monitoring` is **3.12+**. CI runs a 3.10 / 3.12 / 3.13 matrix. `gate_coverage` must **SKIP** on 3.10 with its reason printed, never fail.
- **Never write into `audit_core` from a tool.** `mutate.py` copies to a temp directory. `main` is 124 commits ahead of an unreachable origin and has never been pushed.
- **No shipped-prose edits.** This stage touches no `SKILL.md`, no `workflows/`, no `references/`. Rule 6's derivation requirement does not bind. If a task finds itself editing shipped prose, stop — that is out of scope.
- **No change to audit behaviour.** No task may alter what an audit records or costs.
- `tests/goldens/*/matches.json` and `rejections.json` are **never written** by any tool or test.
- Every new test asserts **observable behaviour** — message text, exit code, refusal, the row written or not written. Never merely that a line ran.
- Every gap resolves one of three ways: a real test, a deletion, or an allowlist entry **with a reason**. Never a test that exists to move the number.
- New feature → `feature_lists.json` entry with `tests`, `modules`, `docs`, or the `manifest` gate fails.
- Run `make all` before proposing a merge.

## Review Focus

These five are implied by the spec, are the most likely to bite in practice, and each gets its test pinned to the task that owns the code.

1. **Allowlist entries rot silently when a file is edited above them.** A line-number key points at a different statement after any insertion, so the gate would permit the wrong thing while reporting green. Entries carry a content hash; a hash mismatch is a distinct "stale" failure, not a pass. — Task 2.
2. **A mutant that never terminates.** An `and`→`or` flip inside a loop condition can hang. Without a per-mutant timeout, the sweep stops dead and is never run again. A timed-out mutant is reported as `timeout`, not as `killed`. — Task 12.
3. **A mutant that breaks import.** A constant perturbation can make a module raise at import time, so every test errors rather than fails. That is a killed mutant, but it must be classified `error` and not confused with a genuine assertion kill. — Task 12.
4. **The probe reporting green because it is broken.** An instrument that measures nothing reports zero gaps. The probe is tested against a fixture package with known-unexecuted lines, and the mutation harness against a fixture with a known-surviving mutant. — Tasks 1 and 11.
5. **A test that errors during the probe run.** If the suite fails, the probe must not emit a coverage number computed from a partial run. A non-zero pytest return code makes the gate FAIL with that reason, never PASS. — Task 1.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/coverage_probe.py` | Create. Measure executed/unexecuted statements in a package under a pytest run. No allowlist knowledge. |
| `scripts/coverage_allowlist.py` | Create. Parse, hash-verify and compare the allowlist against a probe report. |
| `scripts/coverage-allowlist.txt` | Create. The reasoned contract file. |
| `scripts/mutate.py` | Create. Mutation operators, runner, resume, reporting. |
| `scripts/mutation-allowlist.txt` | Create. Permitted survivors with reasons. |
| `scripts/harness.py` | Modify. Add `gate_coverage` to `GATES` and `DEFAULT`; add `gate_mutate` to `GATES` only. |
| `Makefile` | Modify. Add `mutate` target. |
| `feature_lists.json` | Modify. Entries for both instruments and both gates. |
| `tests/test_coverage_probe.py` | Create. |
| `tests/test_coverage_allowlist.py` | Create. |
| `tests/test_mutate.py` | Create. |
| `tests/test_qualify.py` … | Modify. Gap-closing tests, per module. |
| `docs/baselines/2026-10-08-mutation-sweep.md` | Create. The measurement. |

---

## Task 1: The coverage probe

**Files:**
- Create: `scripts/coverage_probe.py`
- Test: `tests/test_coverage_probe.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `SUPPORTED: bool` — `sys.version_info >= (3, 12)`.
  - `executable_statements(path: pathlib.Path) -> set[int]` — executable line numbers, excluding multi-line function-signature continuation lines.
  - `@dataclass(frozen=True) ModuleReport(name: str, executable: int, unexecuted: tuple[int, ...])`
  - `@dataclass(frozen=True) ProbeReport(modules: tuple[ModuleReport, ...], pytest_rc: int)` with properties `total_executable: int`, `total_unexecuted: int`.
  - `measure(package: pathlib.Path, pytest_args: list[str]) -> ProbeReport`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_coverage_probe.py
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_coverage_probe.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'coverage_probe'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/coverage_probe.py
"""Which statements in a package does the test suite never execute?

Not a coverage tool. It answers one question, with the stdlib, so the
project can gate on it without taking a dependency. `sys.monitoring` is
3.12+; on an older interpreter SUPPORTED is False and the caller skips.

Two counting rules earn their keep:

  * Line 0 is an artifact of `co_lines()` and is never a statement.
  * The continuation lines of a multi-line `def` are not statements. The
    `def` line executes; `      b):` does not. Counting them inflated this
    project's first measurement from 115 to 171, and the flattering version
    of that error - filtering the numerator only - would have reported
    95.4%; filtering out the `def` line along with its continuations gave
    a second wrong answer of 94.9%. Both are wrong. A `def` IS executable:
    it runs at import. Only the CONTINUATION lines of a multi-line signature
    are excluded, and the true figure is 115 unexecuted of 2,392.
"""
from __future__ import annotations

import ast
import collections
import dataclasses
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
            for line in range(node.lineno, node.body[0].lineno):
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
    prefix = str(package)

    tool = sys.monitoring.PROFILER_ID
    sys.monitoring.use_tool_id(tool, "coverage_probe")

    def on_line(code, line_number):
        filename = code.co_filename
        if filename.startswith(prefix):
            hit[filename].add(line_number)
            return None
        return sys.monitoring.DISABLE

    sys.monitoring.register_callback(tool, sys.monitoring.events.LINE, on_line)
    sys.monitoring.set_events(tool, sys.monitoring.events.LINE)
    try:
        import pytest
        rc = int(pytest.main([*pytest_args, "-q", "--no-header",
                              "-p", "no:cacheprovider"]))
    finally:
        sys.monitoring.set_events(tool, 0)
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_coverage_probe.py -v`
Expected: PASS, 4 tests

- [ ] **Step 5: Verify it reproduces the spec's headline figure**

Run:
```bash
python3 -c "
import pathlib, sys
sys.path.insert(0, 'scripts')
import coverage_probe as p
r = p.measure(pathlib.Path('audit_core'), ['tests'])
print(r.total_unexecuted, '/', r.total_executable)
"
```
Expected: `115 / 2392`. A different number is not automatically wrong — the suite may have grown — but it must be explained before continuing, because every later task's scope is derived from this one.

- [ ] **Step 6: Commit**

```bash
git add scripts/coverage_probe.py tests/test_coverage_probe.py
git commit -m "feat: stdlib coverage probe over audit_core

Answers one question - which statements does the suite never execute -
with sys.monitoring and ast, so the project can gate on it without a
dependency. Filters line 0 and multi-line signature continuations on
both sides of the ratio."
```

---

## Task 2: The allowlist, content-hashed

**Files:**
- Create: `scripts/coverage_allowlist.py`
- Test: `tests/test_coverage_allowlist.py`

**Do NOT create `scripts/coverage-allowlist.txt` here.** Task 3 generates it
from a real probe run. Creating a stub now means Task 3 either overwrites it
or appends to it, and both silently change what the gate permits.

**Why a hash.** An entry keyed only by `qualify.py:180` points at a different statement the moment anyone inserts a line above it, so the gate would permit the wrong thing and still report green. Each entry carries the first 8 hex of the SHA-1 of the *stripped* source line. Three outcomes, not two: permitted, regressed, **stale**.

**Interfaces:**
- Consumes: `coverage_probe.ProbeReport`, `coverage_probe.executable_statements`.
- Produces:
  - `@dataclass(frozen=True) Entry(module: str, line: int, digest: str, reason: str)`
  - `line_digest(text: str) -> str` — first 8 hex of SHA-1 of `text.strip()`.
  - `parse(text: str) -> tuple[Entry, ...]` — raises `AllowlistError` on a malformed or duplicate entry.
  - `format_entry(module: str, line: int, source_line: str, reason: str) -> str`
  - `@dataclass(frozen=True) Comparison(regressed, stale, permitted, executed_but_listed)` — each a tuple of human-readable strings; `ok` property is True when `regressed`, `stale` and `executed_but_listed` are all empty.
  - `compare(report, entries, package: pathlib.Path) -> Comparison`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_coverage_allowlist.py
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_coverage_allowlist.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'coverage_allowlist'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/coverage_allowlist.py
"""The contract for statements permitted to go unexecuted.

Format, one entry per line:

    <module>:<line>:<digest>  <reason>

`digest` is the first 8 hex of the SHA-1 of the stripped source line. It is
there because a line-number key re-aims itself at an unrelated statement the
moment anyone inserts a line above it - the gate would then permit the wrong
thing and still report green. With the digest there are three outcomes, not
two: permitted, regressed, and stale.

A percentage floor was rejected for the same family of reason: it lets a new
untested refusal path hide behind new tested code elsewhere, which is exactly
how 115 unexecuted statements accumulated while every stage reported its tests
passing.
"""
from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import re

ENTRY = re.compile(r"^(?P<module>[\w.\-]+\.py):(?P<line>\d+):(?P<digest>[0-9a-f]{8})"
                   r"(?:\s+(?P<reason>\S.*))?$")


class AllowlistError(Exception):
    """The allowlist file is malformed."""


@dataclasses.dataclass(frozen=True, slots=True)
class Entry:
    module: str
    line: int
    digest: str
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class Comparison:
    regressed: tuple[str, ...]
    stale: tuple[str, ...]
    permitted: tuple[str, ...]
    executed_but_listed: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (self.regressed or self.stale or self.executed_but_listed)


def line_digest(text: str) -> str:
    return hashlib.sha1(text.strip().encode()).hexdigest()[:8]


def format_entry(module: str, line: int, source_line: str, reason: str) -> str:
    return f"{module}:{line}:{line_digest(source_line)}  {reason}"


def parse(text: str) -> tuple[Entry, ...]:
    out: list[Entry] = []
    seen: set[tuple[str, int]] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = ENTRY.match(line)
        if not match:
            raise AllowlistError(
                f"line {number}: malformed entry {line!r}; expected "
                "<module>.py:<line>:<8-hex digest>  <reason>")
        if not (match.group("reason") or "").strip():
            raise AllowlistError(
                f"line {number}: {match.group('module')}:{match.group('line')} "
                "needs a reason. A gap recorded without one makes the "
                "denominator look accounted for.")
        key = (match.group("module"), int(match.group("line")))
        if key in seen:
            raise AllowlistError(f"line {number}: {key[0]}:{key[1]} is listed twice")
        seen.add(key)
        out.append(Entry(module=key[0], line=key[1],
                         digest=match.group("digest"),
                         reason=match.group("reason").strip()))
    return tuple(out)


def _source_line(package: pathlib.Path, module: str, line: int) -> str | None:
    path = package / module
    if not path.is_file():
        return None
    lines = path.read_text().splitlines()
    if not 1 <= line <= len(lines):
        return None
    return lines[line - 1]


def compare(report, entries, package: pathlib.Path) -> Comparison:
    by_key = {(e.module, e.line): e for e in entries}
    unexecuted = {(m.name, line) for m in report.modules for line in m.unexecuted}

    regressed: list[str] = []
    stale: list[str] = []
    permitted: list[str] = []
    executed_but_listed: list[str] = []

    for key in sorted(unexecuted):
        module, line = key
        entry = by_key.get(key)
        source = _source_line(package, module, line)
        if entry is None:
            regressed.append(f"{module}:{line}  {(source or '').strip()}")
            continue
        if source is None or line_digest(source) != entry.digest:
            stale.append(
                f"{module}:{line}  the listed line moved or changed; "
                f"re-check the reason and update the digest "
                f"({entry.reason})")
            continue
        permitted.append(f"{module}:{line}  {entry.reason}")

    for key in sorted(set(by_key) - unexecuted):
        module, line = key
        executed_but_listed.append(f"{module}:{line}  {by_key[key].reason}")

    return Comparison(tuple(regressed), tuple(stale), tuple(permitted),
                      tuple(executed_but_listed))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_coverage_allowlist.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/coverage_allowlist.py tests/test_coverage_allowlist.py
git commit -m "feat: content-hashed coverage allowlist

Entries carry the digest of their source line, so an edit above an entry
reports stale rather than silently re-aiming the permission at an
unrelated statement. Fails in both directions: an unlisted gap is a
regression, a listed line that now runs is a stale entry."
```

---

## Task 3: Seed the allowlist and register the gate

The allowlist is seeded with all 115 current gaps so the gate is green from here on. Tasks 4–10 then *remove* entries as they close gaps, which makes progress visible and keeps `make all` passing throughout.

**Files:**
- Create: `scripts/coverage-allowlist.txt`
- Modify: `scripts/harness.py` (`GATES`, `DEFAULT`, new `gate_coverage`)
- Modify: `feature_lists.json`
- Test: `tests/test_coverage_allowlist.py` (append)

**Interfaces:**
- Consumes: Task 1's `measure`, Task 2's `parse`/`compare`.
- Produces: `gate_coverage() -> Result` in `scripts/harness.py`.

- [ ] **Step 1: Generate the seeded allowlist**

Run:
```bash
python3 - <<'PY'
import pathlib, sys
sys.path.insert(0, "scripts")
import coverage_probe as probe, coverage_allowlist as al

pkg = pathlib.Path("audit_core")
report = probe.measure(pkg, ["tests"])
assert report.pytest_rc == 0, "suite must be green before seeding"

header = '''# Statements in audit_core that no test executes.
#
# This is a contract, not a scoreboard. Every entry needs a reason, and the
# gate fails in BOTH directions: an unexecuted statement that is not listed
# here is a regression, and a listed statement that now runs is a stale entry.
#
# The digest is the first 8 hex of the SHA-1 of the stripped source line. A
# line-number key alone re-aims itself at an unrelated statement after any
# insertion above it; the digest turns that into a loud "stale" rather than a
# silent wrong permission.
#
# Entries below marked "Stage 3c: not yet closed" are the 115 statements
# measured on 2026-10-08. They are debt, seeded so the gate can be switched on
# before the debt is paid. Stage 3c removes them. An entry that outlives the
# stage must be rewritten with a real reason or its code deleted.
#
# Format: <module>.py:<line>:<digest>  <reason>

'''
lines = [header]
for module in report.modules:
    if not module.unexecuted:
        continue
    src = (pkg / module.name).read_text().splitlines()
    lines.append(f"# --- {module.name} ---")
    for n in module.unexecuted:
        lines.append(al.format_entry(module.name, n, src[n - 1],
                                     "Stage 3c: not yet closed"))
    lines.append("")
pathlib.Path("scripts/coverage-allowlist.txt").write_text("\n".join(lines) + "\n")
print("seeded", report.total_unexecuted, "entries")
PY
```
Expected: `seeded 115 entries`

- [ ] **Step 2: Write the failing gate test**

```python
# append to tests/test_coverage_allowlist.py

def test_shipped_allowlist_parses_and_every_entry_has_a_reason():
    text = (pathlib.Path(__file__).resolve().parent.parent
            / "scripts" / "coverage-allowlist.txt").read_text()
    entries = al.parse(text)
    assert entries, "the shipped allowlist is empty"
    assert all(e.reason for e in entries)


def test_harness_exposes_the_coverage_gate():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "harness", pathlib.Path(__file__).resolve().parent.parent
        / "scripts" / "harness.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    assert "coverage" in harness.GATES
    assert "coverage" in harness.DEFAULT
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_coverage_allowlist.py -k "shipped or harness" -v`
Expected: FAIL — `AssertionError: assert 'coverage' in {...}`

- [ ] **Step 4: Add the gate to `scripts/harness.py`**

Add beside the other `gate_*` functions.

**`Result`'s signature is `(name, status, summary, detail="", seconds=0.0)` — name FIRST, then status.** Verified against `scripts/harness.py:62`. Getting that order backwards produces a gate that "passes" with the status string in the name column, which the harness will render without complaint. `ROOT`, `PASS`, `FAIL`, `SKIP` and `sys` are all already defined and imported in that file.

```python
def gate_coverage() -> Result:
    """Every unexecuted statement in audit_core is listed, with a reason.

    SKIPs below 3.12: sys.monitoring does not exist there and 3.10 is the
    declared floor. A skip is reported, not swallowed.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import coverage_probe as probe
    import coverage_allowlist as allowlist

    if not probe.SUPPORTED:
        return Result("coverage", SKIP,
                      f"needs Python 3.12+ for sys.monitoring; running "
                      f"{sys.version_info.major}.{sys.version_info.minor}")

    report = probe.measure(ROOT / "audit_core", [str(ROOT / "tests")])
    if report.pytest_rc != 0:
        return Result("coverage", FAIL,
                      "the suite did not pass, so the measurement is from a "
                      f"partial run (pytest rc {report.pytest_rc})")

    entries = allowlist.parse(
        (ROOT / "scripts" / "coverage-allowlist.txt").read_text())
    result = allowlist.compare(report, entries, ROOT / "audit_core")

    summary = (f"{report.total_unexecuted} unexecuted / "
               f"{report.total_executable} statements, "
               f"{len(result.permitted)} allowed")
    if result.ok:
        return Result("coverage", PASS, summary)

    detail = []
    for label, items in (("unlisted", result.regressed),
                         ("stale", result.stale),
                         ("now executed, remove from the list",
                          result.executed_but_listed)):
        for item in items:
            detail.append(f"  {label}: {item}")
    return Result("coverage", FAIL, summary, detail="\n".join(detail))
```

Register it:

```python
GATES = {
    "tests": gate_tests,
    "selftest": gate_selftest,
    "lint": gate_lint,
    "eol": gate_eol,
    "manifest": gate_manifest,
    "install": gate_install,
    "coverage": gate_coverage,
    "bench": gate_bench,
}

DEFAULT = ["tests", "selftest", "lint", "eol", "manifest", "install", "coverage"]
```

- [ ] **Step 5: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: `PASS  coverage   115 unexecuted / 2392 statements, 115 allowed`

- [ ] **Step 6: Prove the gate fails on a regression**

Run:
```bash
cp scripts/coverage-allowlist.txt /tmp/cba-allowlist.bak
grep -v '^qualify.py:180:' scripts/coverage-allowlist.txt > /tmp/al && mv /tmp/al scripts/coverage-allowlist.txt
python3 scripts/harness.py --only coverage; echo "exit=$?"
cp /tmp/cba-allowlist.bak scripts/coverage-allowlist.txt
```
Expected: `FAIL` naming `unlisted: qualify.py:180`, `exit=1`. Then restored.

- [ ] **Step 7: Add both features to `feature_lists.json`**

Add to `features`, matching the existing entry shape exactly (read a neighbouring entry first):

```json
{
  "id": "coverage-probe",
  "name": "Statement coverage probe over audit_core",
  "area": "harness",
  "status": "shipped",
  "summary": "sys.monitoring probe reporting which audit_core statements the suite never executes. Filters line 0 and multi-line signature continuations on both sides of the ratio.",
  "modules": ["scripts/coverage_probe.py"],
  "tests": ["tests/test_coverage_probe.py"],
  "docs": ["docs/superpowers/specs/2026-10-08-stage3c-core-hardening-design.md"]
},
{
  "id": "coverage-gate",
  "name": "Coverage allowlist gate",
  "area": "harness",
  "status": "shipped",
  "summary": "Eighth gate. Every unexecuted statement must be listed with a reason; fails on an unlisted gap, a stale digest, and a listed line that now runs. SKIPs below Python 3.12.",
  "modules": ["scripts/coverage_allowlist.py", "scripts/harness.py"],
  "tests": ["tests/test_coverage_allowlist.py"],
  "docs": ["docs/superpowers/specs/2026-10-08-stage3c-core-hardening-design.md"]
}
```

- [ ] **Step 8: Run the full gate set**

Run: `make all`
Expected: 8 gates, all PASS (or `bench` SKIP off the operator's machine).

- [ ] **Step 9: Commit**

```bash
git add scripts/coverage-allowlist.txt scripts/harness.py feature_lists.json tests/test_coverage_allowlist.py
git commit -m "feat: coverage gate, seeded with the 115 known gaps

Gate is green from here and the debt is explicit: every one of the 115
statements is listed as 'Stage 3c: not yet closed'. Tasks that follow
remove entries as they close gaps, so make all passes throughout and
progress is visible as the file shrinks."
```

---

## Tasks 4–10: Close the gaps

**These seven tasks share one shape.** For each:

1. Write tests asserting the **observable behaviour** of each listed statement — the exact message, the exception type, the returned value, the row written. Never `assert True` after calling something, and never a test whose only effect is to touch a line.
2. Run them; they must pass against the existing implementation. **If a test fails, the code is wrong** — that is a finding, not a test bug. Stop and report it before changing anything.

2a. **Then prove the tests would fail if the code broke.** Passing against
   working code proves nothing: a test can name a branch in its title, sit in
   the right file, and take a different code path entirely. This has already
   happened three times in this branch's own instruments, and line coverage
   called every one of them green.

   Copy the tree to a temp directory (`mktemp -d`, never mutate the real
   tree). Pick **three** of the statements this task closes — favour a
   refusal message, a verdict branch, and a renderer. Break each one in turn:
   inverting a comparison, changing a message string, or returning the other
   value. Run the suite each time and confirm the test that names that
   statement is the one that fails.

   Record all three in the commit message and the report: what you broke, and
   which test caught it. If a test does NOT fail when its subject is broken,
   it is not testing what it claims — rewrite it and say so.
3. If a statement cannot be reached by any input, **delete it** and say so in the commit. Do not contort a test into reaching it.
4. If it is reachable only in conditions a test cannot create, keep the allowlist entry and **replace the reason** with the real one.
5. Remove the closed entries from `scripts/coverage-allowlist.txt`.
6. Run `python3 scripts/harness.py --only coverage` — it must PASS with a smaller count.
7. Commit.

Each task's commit message states the count closed, deleted and re-reasoned.

---

### Task 4: `qualify.py` — 16 statements

**Files:**
- Modify: `tests/test_qualify.py`
- Modify: `scripts/coverage-allowlist.txt`

**The statements:** 72, 73 (`except (UnicodeDecodeError, csv.Error)` on the header read), 94 (`unexpected:` in the header-mismatch message), 106 (`continue` on `rce_cves < 0`), 133, 134 (the same `except` on the row loop), 180 (`"no RCE CVEs on record"`), 256–262 (thin support evidence), 344, 345, 347 (the NO-GO footer prose). Sixteen — and line 305 is deliberately NOT among them: it is a continuation line of a multi-line `def`, which the corrected probe does not count as a statement.

**Interfaces:**
- Consumes: `audit_core.qualify.load_scores`, `filter_proven_bad`, `filter_supported`, `qualify`, `render`; `audit_core.qualify.QualifyError`.
- Produces: nothing for later tasks.

- [ ] **Step 1: Write the tests**

```python
# append to tests/test_qualify.py
import pathlib

import pytest

from audit_core import qualify


HEADER = ",".join(qualify.EXPECTED_HEADER)


# EXPECTED_HEADER is TEN columns, verified against audit_core/qualify.py:30:
#   vendor, model, rce_cves, slop_pct, max_cvss,
#   first_pub, last_pub, top_source, top_ref_hosts, sample_cves
# A short row does not raise - csv.DictReader pads with None and every later
# column reads the wrong field - so rows here are always full width.
def _row(vendor="acme", model="widget", rce_cves="3", slop_pct="10.0",
         max_cvss="9.8", first_pub="2024-01-01", last_pub="2025-01-01",
         top_source="nvd", top_ref_hosts="example.com", sample_cves="CVE-2024-1"):
    return ",".join([vendor, model, rce_cves, slop_pct, max_cvss,
                     first_pub, last_pub, top_source, top_ref_hosts,
                     sample_cves])


def _csv(tmp_path, body, name="scores.csv"):
    path = tmp_path / name
    path.write_text(f"{HEADER}\n{body}")
    return path


def test_load_scores_reports_an_undecodable_header(tmp_path):
    """qualify.py:72-73 - the encoding handler c4d9021 added and nothing ran."""
    path = tmp_path / "scores.csv"
    path.write_bytes(b"\xff\xfe\x00bad header\n")
    with pytest.raises(qualify.QualifyError, match="cannot read"):
        qualify.load_scores(path)


def test_load_scores_reports_an_undecodable_row(tmp_path):
    """qualify.py:133-134 - same handler, the row loop."""
    path = tmp_path / "scores.csv"
    path.write_bytes(HEADER.encode() + b"\n" + b"acme,x,1,0.0,9.8,\xff\xfe,"
                     b"2025-01-01,nvd,example.com,CVE-2024-1\n")
    with pytest.raises(qualify.QualifyError, match="cannot read"):
        qualify.load_scores(path)


def test_header_mismatch_names_the_unexpected_column(tmp_path):
    """qualify.py:94 - the operator needs to know which column is the stranger."""
    path = tmp_path / "scores.csv"
    path.write_text(HEADER + ",surprise\n")
    with pytest.raises(qualify.QualifyError) as excinfo:
        qualify.load_scores(path)
    assert "unexpected: surprise" in str(excinfo.value)


def test_a_negative_rce_count_is_skipped_not_trusted(tmp_path):
    """qualify.py:106. The existing test used a Unicode minus, so int()
    rejected the value before this branch could run and the branch has never
    executed. An ASCII '-1' is the input the finding actually named."""
    path = _csv(tmp_path, _row(rce_cves="-1") + "\n")
    scores = qualify.load_scores(path)
    assert ("acme", "widget") not in scores


def test_zero_rce_cves_is_a_no_go_naming_the_cause(tmp_path):
    """qualify.py:180 - a GO/NO-GO verdict branch with no test."""
    path = _csv(tmp_path, _row(rce_cves="0") + "\n")
    scores = qualify.load_scores(path)
    result = qualify.filter_proven_bad(scores.get(("acme", "widget")))
    assert result.passed is False
    assert result.detail == "no RCE CVEs on record"


def test_thin_support_evidence_is_refused_and_counted():
    """qualify.py:256-262 - the message 65f6c07 rewrote and nothing ran."""
    result = qualify.filter_supported("acme", "widget", True, "yes")
    assert result.passed is False
    assert "too thin" in result.detail
    assert "(3 characters given)" in result.detail


def test_missing_support_evidence_is_refused():
    result = qualify.filter_supported("acme", "widget", True, "")
    assert result.passed is False
    assert "(0 characters given)" in result.detail
```

For statements 344, 345 and 347 — the NO-GO footer prose — the implementer must read `audit_core/qualify.py:300-350` and write one test per reachable branch, asserting the **exact** sentence rendered. The two branches are "strip-mined" and "no proven RCE history". Follow the shape above: construct a `Qualification` through `qualify.qualify(...)` with inputs that reach each branch, call `qualify.render(...)`, and assert the sentence appears.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/test_qualify.py -v`
Expected: PASS. **A failure here is a defect in `qualify.py`, not in the test** — stop and report it.

- [ ] **Step 3: Remove the closed entries from the allowlist**

Run:
```bash
python3 - <<'PY'
import pathlib
closed = {72, 73, 94, 106, 133, 134, 180, 256, 257, 258, 259, 260, 262, 344, 345, 347}
p = pathlib.Path("scripts/coverage-allowlist.txt")
out = [l for l in p.read_text().splitlines()
       if not (l.startswith("qualify.py:")
               and int(l.split(":")[1]) in closed)]
p.write_text("\n".join(out) + "\n")
PY
```

- [ ] **Step 4: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: PASS, `99 unexecuted / 2392 statements, 99 allowed`. If it reports `stale` or `now executed, remove from the list`, reconcile before committing.

- [ ] **Step 5: Commit**

```bash
git add tests/test_qualify.py scripts/coverage-allowlist.txt
git commit -m "test: close qualify's 16 unexecuted statements

Includes the branch the Stage 4a review found illusory: the existing
negative-rce_cves test used a Unicode minus, so int() rejected it before
rce_cves < 0 could run. An ASCII -1 is the input the finding named.

Also covers the encoding handlers from c4d9021 and the NO-GO messages
from 65f6c07 - both shipped as fixes, neither ever executed."
```

---

### Task 5: `coverage.py` — 16 statements

**Files:**
- Modify: `tests/test_coverage.py`
- Modify: `scripts/coverage-allowlist.txt`

**The statements:** 60 (missing `--phase`), 63–64 (illegal state), 70–72 (past `MAX_UNITS_PER_CALL`), 88–90 (`render_record`), 200–204 (the unrecorded-units advice), 272–275 (`render_gate`).

**Interfaces:**
- Consumes: `audit_core.coverage.record`, `render_record`, `render_gate`, `MAX_UNITS_PER_CALL`, `COVERAGE_STATES`; `audit_core.db.DbError`.

- [ ] **Step 1: Write the tests**

```python
# append to tests/test_coverage.py
import pytest

from audit_core import coverage, db


def test_record_without_a_phase_says_what_a_phase_is_for(tmp_path, conn):
    with pytest.raises(db.DbError, match="needs a --phase"):
        coverage.record(conn, units=["a.py"], phase="", state="analyzed")


def test_record_rejects_a_state_outside_the_enum(tmp_path, conn):
    with pytest.raises(db.DbError) as excinfo:
        coverage.record(conn, units=["a.py"], phase="audit", state="maybe")
    assert "state='maybe'" in str(excinfo.value)
    for state in coverage.COVERAGE_STATES:
        assert state in str(excinfo.value)


def test_record_refuses_a_unit_list_that_is_really_a_whole_tree(conn):
    units = [f"f{i}.py" for i in range(coverage.MAX_UNITS_PER_CALL + 1)]
    with pytest.raises(db.DbError) as excinfo:
        coverage.record(conn, units=units, phase="audit", state="analyzed")
    message = str(excinfo.value)
    assert str(len(units)) in message
    assert str(coverage.MAX_UNITS_PER_CALL) in message
    assert "split the list" in message


def test_render_record_states_count_state_and_phase(conn):
    result = coverage.record(conn, units=["a.py", "b.py"], phase="audit",
                             state="analyzed")
    rendered = coverage.render_record(result)
    assert "2 unit(s)" in rendered
    assert "analyzed" in rendered
    assert "phase audit" in rendered


def test_render_record_includes_the_reason_when_there_is_one(conn):
    result = coverage.record(conn, units=["a.py"], phase="audit",
                             state="not_audited", reason="budget")
    assert "reason=budget" in coverage.render_record(result)
```

The implementer writes the remaining two renderers the same way: read `audit_core/coverage.py:195-210` and `:268-276`, build a gate result with at least one failure and one warning, and assert that `render_gate` prints `coverage gate: FAIL`, the `FAIL` line and the `warn` line. For `:200-204`, build a database with inventoried units and no coverage rows and assert the advice names the unrecorded count and the `not_audited` reason list.

**Note on the `conn` fixture:** `tests/test_coverage.py` already has one. Read it before writing; do not create a second.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/test_coverage.py -v`
Expected: PASS

- [ ] **Step 3: Remove entries 60, 63, 64, 70, 71, 72, 88, 89, 90, 200, 202, 204, 272, 273, 274, 275 from the allowlist**

Use the Task 4 Step 3 script with `closed = {60, 63, 64, 70, 71, 72, 88, 89, 90, 200, 202, 204, 272, 273, 274, 275}` and `coverage.py:`.

- [ ] **Step 4: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: PASS, `83 unexecuted`

- [ ] **Step 5: Commit**

```bash
git add tests/test_coverage.py scripts/coverage-allowlist.txt
git commit -m "test: close coverage.py's 16 unexecuted statements

All three input guards on the recorder - missing phase, illegal state,
past the per-call unit bound - plus the three renderers. The guards are
what stop a coverage denominator being written wrong; none had a test."
```

---

### Task 6: `db.py` — 14 statements

**Files:**
- Modify: `tests/test_db.py`
- Modify: `scripts/coverage-allowlist.txt`

**The statements:** 330 (read-only connect), 337–339 (`not a readable SQLite database`), 411 (`_merge_with_stored` early return), 466 (`has no column(s)`), 522–523 and 528–529 (`status` renderer group and verdict blocks), 560, 566 (loop `continue`s), 578–579 (`_as_int` fallback).

**Interfaces:**
- Consumes: `audit_core.db.connect`, `rows`, `status`, `render_status`, `DbError`.

- [ ] **Step 1: Write the tests**

```python
# append to tests/test_db.py
import sqlite3

import pytest

from audit_core import db, workspace


def test_connect_read_only_refuses_a_write(tmp_path):
    """db.py:330 - the read-only path has never been opened."""
    run, _ = workspace.init_run_with_schema(tmp_path, "20260101-000000")
    con = db.connect(run / "audit.db", read_only=True)
    with pytest.raises(sqlite3.OperationalError):
        con.execute("INSERT INTO cba_sources (id) VALUES ('x')")
    con.close()


def test_connect_rejects_a_file_that_is_not_a_database(tmp_path):
    """db.py:337-339 - a text file with the right name is the realistic case."""
    fake = tmp_path / "audit.db"
    fake.write_text("this is not a database\n")
    with pytest.raises(db.DbError, match="is not a readable SQLite database"):
        db.connect(fake)


def test_rows_names_every_unknown_column(tmp_path):
    """db.py:466 - the error that makes put a contract rather than an INSERT."""
    run, _ = workspace.init_run_with_schema(tmp_path, "20260101-000000")
    con = db.connect(run / "audit.db")
    with pytest.raises(db.DbError) as excinfo:
        db.rows(con, "cba_findings", columns=("nope", "also_nope"))
    message = str(excinfo.value)
    assert "cba_findings has no column(s)" in message
    assert "nope" in message and "also_nope" in message
    con.close()
```

For 411, 522–523, 528–529, 560, 566 and 578–579 the implementer reads each site and writes a test asserting the behaviour:

- **411** — CORRECTED after reading the code: this is the early `return row` in `_merge_with_stored`, taken when the caller does not name the whole primary key. It is NOT the "omitted optional column keeps its stored value" path. With `replace=True` and no key named, `put` performs a plain INSERT and merges nothing. Pin that. The merge path proper deserves its own sibling test, but it is not line 411. Note also that `replace-blanks-optional-columns` is **closed** (`closed_in: stage3b`), not open as an earlier draft of this plan said.
- **522–523, 528–529** — build a run with two feature groups and two verdicts, call `status` then `render_status`, and assert both the `groups:` block and the `verdicts:` block appear with their counts.
- **560, 566** — read the loop at `db.py:550-570` and supply the input each `continue` skips.
- **578–579** — call `_as_int` with a non-numeric value and assert it returns `0`.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/test_db.py -v`
Expected: PASS

- [ ] **Step 3: Remove the closed `db.py` entries from the allowlist**

- [ ] **Step 4: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: PASS, `69 unexecuted`

- [ ] **Step 5: Commit**

```bash
git add tests/test_db.py scripts/coverage-allowlist.txt
git commit -m "test: close db.py's 14 unexecuted statements

Contract enforcement first: 'has no column(s)' and 'not a readable
SQLite database' are what make db.put a contract, and neither had a
test. Also pins the documented merge-on-replace limitation."
```

---

### Task 7: `indicators.py` — 21 statements

**Files:**
- Modify: `tests/test_indicators.py`
- Modify: `scripts/coverage-allowlist.txt`

**The statements:** 62 (`cba_attack_surface is not in this database`), 180–192 (`write_snapshot`: mkdir, exclusive create, the `FileExistsError` refusal), 247 and 249 (the before/after accumulators in the comparison), 256–264 (`render_comparison`). Twenty-one — line 255 is a multi-line `def` continuation and is not a statement.

The exclusive-create refusal is `SESSION_HANDOFF.md` rule 4 enforced in code — *"Measurements are never edited in place"* — and nothing tests that it holds. That is the highest-value test in this task.

**Interfaces:**
- Consumes: `audit_core.indicators.write_snapshot`, `snapshot_path`, `compare`, `render_comparison`, `IndicatorError`, `Reading`.

- [ ] **Step 1: Write the tests**

```python
# append to tests/test_indicators.py
import datetime
import json
import pathlib

import pytest

from audit_core import indicators


def test_write_snapshot_creates_parent_directories(tmp_path, an_indicator_set):
    target = tmp_path / "docs" / "indicators" / "2026-10-08-tplink.json"
    written = indicators.write_snapshot(target, an_indicator_set)
    assert written == target
    assert json.loads(target.read_text())


def test_write_snapshot_refuses_to_overwrite_a_measurement(tmp_path, an_indicator_set):
    """Rule 4 in code: a superseded measurement stays visible in git history.

    Silently overwriting this morning's snapshot with this afternoon's would
    destroy the morning's measurement and leave no trace it existed.
    """
    target = tmp_path / "2026-10-08-tplink.json"
    indicators.write_snapshot(target, an_indicator_set)
    before = target.read_text()
    with pytest.raises(indicators.IndicatorError) as excinfo:
        indicators.write_snapshot(target, an_indicator_set)
    assert "already exists" in str(excinfo.value)
    assert "never edited in place" in str(excinfo.value)
    assert target.read_text() == before, "the refused write must change nothing"
```

The implementer adds, in the same style:

- **62** — call the reading that inspects `cba_attack_surface` against a database created without that table, and assert the `Reading` is `absent` with that exact message.
- **247, 249** — build two snapshots whose values differ and assert the accumulated `before` and `after` totals.
- **256–264** — call `render_comparison` on a set of deltas including at least one `not comparable`, and assert the header row, one delta row, and the explanatory footer all appear.

**Note:** `an_indicator_set` above is a placeholder for whatever fixture `tests/test_indicators.py` already uses to build an indicator set. Read the file first and use the existing fixture; do not add a second.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/test_indicators.py -v`
Expected: PASS

- [ ] **Step 3: Remove the closed `indicators.py` entries from the allowlist**

- [ ] **Step 4: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: PASS, `48 unexecuted`

- [ ] **Step 5: Commit**

```bash
git add tests/test_indicators.py scripts/coverage-allowlist.txt
git commit -m "test: close indicators.py's 21 unexecuted statements

Chiefly the snapshot write: handoff rule 4 - measurements are never
edited in place - is enforced by an open(path, 'x') and a refusal, and
nothing tested that it holds. The refusal now also asserts the existing
file is unchanged."
```

---

### Task 8: `goldens.py` and `identity.py` — 18 statements

**Files:**
- Modify: `tests/test_goldens.py`, `tests/test_identity.py`
- Modify: `scripts/coverage-allowlist.txt`

**`goldens.py` (9):** lines 30, 31, 33, 40, 60, 61, 63, 81, 82 — the loader validations added by `f423efa`. These guard `tests/goldens/*/matches.json` and `rejections.json`, which `SESSION_HANDOFF.md` rule 3 names as the benchmark's only independent reference. Malformed input has never reached them.

**`identity.py` (9):** lines 43–54 — `render` in its entirety, including the empty-set guidance text.

- [ ] **Step 1: Write the tests**

```python
# append to tests/test_goldens.py
import pytest

from audit_core import goldens


import json

# Verified against audit_core/goldens.py: the loader is load_reference
# (SINGULAR), and _REQUIRED is five keys, not four:
#   ("id", "title", "locations", "root_cause_key", "severity")
# Omitting root_cause_key makes the empty-locations test fail on the WRONG
# guard, which would look like a pass for the wrong reason.
def _ref(**over):
    base = {"id": "REF-1", "title": "t", "locations": ["a.c:1"],
            "root_cause_key": "cmdi", "severity": "HIGH"}
    base.update(over)
    return base


def test_reference_load_reports_unreadable_json(tmp_path):
    path = tmp_path / "refs.json"
    path.write_text("{not json")
    with pytest.raises(goldens.GoldenError, match="cannot read"):
        goldens.load_reference(path)


def test_reference_load_requires_a_list(tmp_path):
    path = tmp_path / "refs.json"
    path.write_text('{"id": "REF-1"}')
    with pytest.raises(goldens.GoldenError, match="expected a list"):
        goldens.load_reference(path)


def test_reference_load_names_the_index_of_the_bad_entry(tmp_path):
    path = tmp_path / "refs.json"
    path.write_text(json.dumps([_ref(), {"id": "REF-2"}]))
    with pytest.raises(goldens.GoldenError) as excinfo:
        goldens.load_reference(path)
    assert "[1]" in str(excinfo.value)
    assert "missing" in str(excinfo.value)


def test_reference_load_refuses_empty_locations(tmp_path):
    """Every required key present, so this reaches the locations guard and
    not the missing-key guard above it."""
    path = tmp_path / "refs.json"
    path.write_text(json.dumps([_ref(locations=[])]))
    with pytest.raises(goldens.GoldenError, match="must be non-empty"):
        goldens.load_reference(path)
```

The implementer reads `audit_core/goldens.py` for the exact required-key set and the names of the matches and rejections loaders, and adds the equivalent four tests for each of them (lines 60–63 and 81–82). **`tests/goldens/` is read-only — every fixture goes in `tmp_path`.**

```python
# append to tests/test_identity.py
from audit_core import db, identity


def test_render_with_no_components_tells_the_operator_what_to_do():
    out = identity.render([])
    assert "none asserted" in out
    assert "audit.py identify" in out
    assert "A filename is an assertion by whoever named it." in out


def test_render_lists_path_kind_identity_and_evidence(conn):
    identity.record(conn, path="bin/httpd", kind="binary",
                    identity="GoAhead webserver",
                    evidence="DT_NEEDED libgoahead.so.1 and the string "
                             "'GoAhead-Webs/3.6.5' at .rodata+0x4120",
                    confidence=80)
    out = identity.render(db.rows(conn, "cba_components"))
    assert "components: 1 asserted" in out
    assert "bin/httpd" in out
    assert "binary: GoAhead webserver (confidence 80)" in out
    assert "evidence: DT_NEEDED" in out


def test_render_omits_the_confidence_suffix_when_absent(conn):
    identity.record(conn, path="bin/other", kind="binary",
                    identity="BusyBox",
                    evidence="applet table at .rodata+0x9000 lists 212 applets")
    out = identity.render(db.rows(conn, "cba_components"))
    assert "(confidence" not in out
```

Read both test files for their existing `conn` fixture and import list before writing; do not add duplicates.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/test_goldens.py tests/test_identity.py -v`
Expected: PASS

- [ ] **Step 3: Remove the closed entries**

- [ ] **Step 4: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: PASS, `30 unexecuted`

- [ ] **Step 5: Commit**

```bash
git add tests/test_goldens.py tests/test_identity.py scripts/coverage-allowlist.txt
git commit -m "test: close goldens.py and identity.py - 18 statements

goldens' loader validations guard the benchmark's only independent
reference and had never seen malformed input. identity.render was
entirely untested, including the empty-set guidance."
```

---

### Task 9: `transcript`, `pivot`, `preflight`, `sweep` — 22 statements

**Files:**
- Modify: `tests/test_transcript.py`, `tests/test_pivot.py`, `tests/test_preflight.py`, `tests/test_sweep.py`
- Modify: `scripts/coverage-allowlist.txt`

**The statements, with what each is:**

| Module | Lines | What |
|---|---|---|
| `transcript.py` | 114, 177, 198 | three `continue`s skipping malformed entries |
| | 202 | the `json.dumps(payload)` fallback for a non-string payload |
| | 206, 207 | the `type == "text"` block branch and its classifier call |
| `pivot.py` | 45, 46 | `a pivot needs --enables` |
| | 107–109, 112 | `render` |
| `preflight.py` | 35, 36 | `is not valid JSON` |
| | 38 | `does not contain a JSON object` |
| | 51, 52 | `server <name> is not a JSON object` |
| `sweep.py` | 90 | `continue` on a skipped path |
| | 98, 99 | `except OSError: continue` on an unreadable file |
| | 174, 175 | the skipped-files line in the renderer |

- [ ] **Step 1: Write the tests**

One per statement, asserting observable behaviour. Two worked examples; the implementer follows the pattern for the rest, reading each site first.

```python
# append to tests/test_preflight.py
import pytest

from audit_core import preflight


def test_load_servers_reports_invalid_json(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text("{not json")
    with pytest.raises(preflight.PreflightError, match="is not valid JSON"):
        preflight.load_servers(config, ["autorev"])


def test_load_servers_requires_an_object_at_the_top_level(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text("[]")
    with pytest.raises(preflight.PreflightError,
                       match="does not contain a JSON object"):
        preflight.load_servers(config, ["autorev"])


def test_load_servers_refuses_a_server_that_is_not_an_object(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {"autorev": "uvx autorev"}}')
    with pytest.raises(preflight.PreflightError) as excinfo:
        preflight.load_servers(config, ["autorev"])
    assert "'autorev'" in str(excinfo.value)
    assert "is not a JSON object" in str(excinfo.value)
```

```python
# append to tests/test_sweep.py
import pathlib

from audit_core import sweep


def test_an_unreadable_file_is_skipped_not_fatal(tmp_path):
    """sweep.py:98-99. A tree with one unreadable file must still be swept."""
    good = tmp_path / "good.c"
    good.write_text("strcpy(dst, src);\n")
    bad = tmp_path / "bad.c"
    bad.write_text("strcpy(dst, src);\n")
    bad.chmod(0o000)
    try:
        # sweep.run(root, regex, *, pattern_id="", suffixes=None, max_hits=...)
        # - `regex` is POSITIONAL, verified against audit_core/sweep.py:110.
        result = sweep.run(tmp_path, r"strcpy", suffixes=(".c",))
        assert any("good.c" in hit.path for hit in result.hits)
    finally:
        bad.chmod(0o644)
```

**Note:** `preflight.load_servers` and `sweep.run` signatures above are from reading the modules; the implementer confirms them against the source before writing, and adjusts the call, not the assertion.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/test_transcript.py tests/test_pivot.py tests/test_preflight.py tests/test_sweep.py -v`
Expected: PASS

- [ ] **Step 3: Remove the closed entries**

- [ ] **Step 4: Run the gate**

Run: `python3 scripts/harness.py --only coverage`
Expected: PASS, `8 unexecuted`

- [ ] **Step 5: Commit**

```bash
git add tests/test_transcript.py tests/test_pivot.py tests/test_preflight.py tests/test_sweep.py scripts/coverage-allowlist.txt
git commit -m "test: close transcript, pivot, preflight and sweep - 22 statements

Mostly skip-and-continue paths over malformed input, which is exactly
the class that fails silently: a sweep that skips every file reports a
clean tree."
```

---

### Task 10: The last 8 — `extract`, `budget`, `bench`, `ceiling`, `patterns`

**Files:**
- Modify: `tests/test_extract.py`, `tests/test_budget_epochs.py`, `tests/test_bench.py`, `tests/test_ceiling.py`, `tests/test_patterns.py`
- Modify: `scripts/coverage-allowlist.txt`

| Module | Lines | What |
|---|---|---|
| `extract.py` | 129, 130 | `is not valid JSON` on the manifest |
| | 186 | `source root is gone` |
| `budget.py` | 63 | the all-zero `Stats` for an empty transcript set |
| | 110 | a `continue` over an unusable record |
| `bench.py` | 108 | a `continue` over a skipped row |
| `ceiling.py` | 104 | `no epoch long enough to judge the growth model` |
| `patterns.py` | 87 | `patterns: none registered.` |

- [ ] **Step 1: Write the tests**

```python
# append to tests/test_patterns.py
from audit_core import patterns


def test_render_with_nothing_registered_says_so_and_says_what_to_do():
    out = patterns.render([])
    assert out.startswith("patterns: none registered.")
```

```python
# append to tests/test_ceiling.py
from audit_core import ceiling


def test_linearity_declines_to_judge_a_short_history():
    """ceiling.py:104 - refusing to model is a result, and it has a sentence."""
    out = ceiling.render_linearity([])
    assert "no epoch long enough to judge the growth model" in out
```

```python
# append to tests/test_extract.py
import pytest

from audit_core import extract


def test_a_corrupt_manifest_is_reported_not_swallowed(tmp_path):
    """extract.py:129-130. The class is ExtractStore(run_dir) and the public
    accessor is .manifest(); _load() is private and .manifest() calls it."""
    run = tmp_path / "run"
    (run / "extract").mkdir(parents=True)
    (run / "extract" / "manifest.json").write_text("{not json")
    with pytest.raises(extract.ExtractError, match="is not valid JSON"):
        extract.ExtractStore(run).manifest()


def test_a_vanished_source_root_is_reported(tmp_path):
    """extract.py:186 - SourceTree.assert_ready, not ExtractStore."""
    missing = tmp_path / "gone"
    with pytest.raises(extract.ExtractError, match="source root is gone"):
        extract.SourceTree(missing).assert_ready()
```

`patterns.render(items)`, `ceiling.render_linearity(checks)`, `extract.ExtractStore(run_dir).manifest()` and `extract.SourceTree(root).assert_ready()` are verified. `budget`'s stats entry point and `bench`'s row loop are NOT — confirm those two against the module before writing, and adjust the call, never the assertion. The remaining three (budget 63 and 110, bench 108) follow the same shape.

- [ ] **Step 2: Run the tests**

Run: `python3 -m pytest tests/ -q`
Expected: PASS, suite total now well above 621.

- [ ] **Step 3: Remove the closed entries**

- [ ] **Step 4: Run the gate and the whole harness**

Run: `python3 scripts/harness.py --only coverage && make all`
Expected: coverage PASS with `0 unexecuted / 2392 statements, 0 allowed`, or a small number of entries each carrying a **real** reason — never `Stage 3c: not yet closed`.

- [ ] **Step 5: Verify no seeded reason survived**

Run: `grep -c "Stage 3c: not yet closed" scripts/coverage-allowlist.txt || true`
Expected: `0`. Any survivor must be rewritten with its real reason or its code deleted.

- [ ] **Step 6: Commit**

```bash
git add tests/ scripts/coverage-allowlist.txt
git commit -m "test: close the last 8 unexecuted statements in audit_core

Zero unexplained gaps. Any entry remaining in the allowlist now carries
a real reason, not the seeded placeholder."
```

---

## Task 11: Mutation operators

**Files:**
- Create: `scripts/mutate.py` (operators only; the runner is Task 12)
- Test: `tests/test_mutate.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `@dataclass(frozen=True) Mutation(module: str, lineno: int, col: int, operator: str, before: str, after: str)`
  - `enumerate_mutations(source: str, module: str) -> tuple[Mutation, ...]`
  - `apply_mutation(source: str, mutation: Mutation) -> str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_mutate.py
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import mutate  # noqa: E402


def test_enumerates_a_comparison_flip():
    muts = mutate.enumerate_mutations("def f(n):\n    return n < 0\n", "m.py")
    ops = {(m.operator, m.before, m.after) for m in muts}
    assert ("compare", "Lt", "LtE") in ops


def test_enumerates_a_boolop_swap():
    muts = mutate.enumerate_mutations("def f(a, b):\n    return a and b\n", "m.py")
    assert any(m.operator == "boolop" for m in muts)


def test_enumerates_a_constant_perturbation():
    muts = mutate.enumerate_mutations("LIMIT = 200\n", "m.py")
    assert any(m.operator == "constant" and m.after == "201" for m in muts)


def test_does_not_mutate_a_docstring():
    """Perturbing prose produces noise, not a test signal."""
    muts = mutate.enumerate_mutations('def f():\n    """Doc."""\n    return 1\n',
                                      "m.py")
    assert all("Doc." not in m.before for m in muts)


def test_apply_mutation_changes_exactly_one_site():
    source = "def f(a, b):\n    return a < b or a < 0\n"
    muts = [m for m in mutate.enumerate_mutations(source, "m.py")
            if m.operator == "compare"]
    assert len(muts) == 2
    mutated = mutate.apply_mutation(source, muts[0])
    assert mutated != source
    assert mutated.count("<=") == 1


def test_apply_mutation_produces_parseable_source():
    import ast
    source = "def f(n):\n    return n == 0\n"
    for m in mutate.enumerate_mutations(source, "m.py"):
        ast.parse(mutate.apply_mutation(source, m))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_mutate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mutate'`

- [ ] **Step 3: Write the operators**

```python
# scripts/mutate.py
"""Find tests that execute a line while asserting nothing that depends on it.

Line coverage cannot see this class. The project has recorded one instance by
name - "the Task 2 test that substituted an easier input for the one its
finding named" - and the only instrument that finds it is mutation: change the
code, and if every test still passes, no test was checking.

Operators are deliberately few. Each produces source that still parses, so a
surviving mutant means a real gap rather than a syntax error nobody noticed.
Docstrings are never mutated: perturbing prose produces noise, not signal.
"""
from __future__ import annotations

import ast
import dataclasses

COMPARE_FLIPS = {
    "Lt": "LtE", "LtE": "Lt",
    "Gt": "GtE", "GtE": "Gt",
    "Eq": "NotEq", "NotEq": "Eq",
    "In": "NotIn", "NotIn": "In",
    "Is": "IsNot", "IsNot": "Is",
}
BOOLOP_FLIPS = {"And": "Or", "Or": "And"}


@dataclasses.dataclass(frozen=True, slots=True)
class Mutation:
    module: str
    lineno: int
    col: int
    operator: str
    before: str
    after: str

    @property
    def label(self) -> str:
        return (f"{self.module}:{self.lineno}:{self.col} "
                f"{self.operator} {self.before}->{self.after}")


def _docstring_nodes(tree: ast.AST) -> set[int]:
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                out.add(id(body[0].value))
    return out


def enumerate_mutations(source: str, module: str) -> tuple[Mutation, ...]:
    # KNOWN LIMITATION: a chained comparison whose operators are identical
    # (`a < b < c`) yields two Mutations with the same (lineno, col, before),
    # hence the same label, and the transformer applies only the first. The
    # second is a duplicate that can never be independently killed. Accepted:
    # same-operator chains are rare, and de-duplicating by operator INDEX
    # would complicate the transformer for a case audit_core does not contain.
    # If a survivor's label is ambiguous, this is why.
    tree = ast.parse(source)
    skip = _docstring_nodes(tree)
    out: list[Mutation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op in node.ops:
                name = type(op).__name__
                if name in COMPARE_FLIPS:
                    out.append(Mutation(module, op.lineno if hasattr(op, "lineno")
                                        else node.lineno, node.col_offset,
                                        "compare", name, COMPARE_FLIPS[name]))
        elif isinstance(node, ast.BoolOp):
            name = type(node.op).__name__
            out.append(Mutation(module, node.lineno, node.col_offset,
                                "boolop", name, BOOLOP_FLIPS[name]))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            out.append(Mutation(module, node.lineno, node.col_offset,
                                "not", "Not", "removed"))
        elif isinstance(node, ast.Constant) and id(node) not in skip:
            value = node.value
            if isinstance(value, bool):
                out.append(Mutation(module, node.lineno, node.col_offset,
                                    "constant", repr(value), repr(not value)))
            elif isinstance(value, int):
                out.append(Mutation(module, node.lineno, node.col_offset,
                                    "constant", repr(value), repr(value + 1)))
            elif isinstance(value, str) and value:
                out.append(Mutation(module, node.lineno, node.col_offset,
                                    "constant", repr(value), "''"))
    return tuple(out)


class _Transformer(ast.NodeTransformer):
    def __init__(self, target: Mutation) -> None:
        self.target = target
        self.applied = False

    def _matches(self, node: ast.AST) -> bool:
        return (not self.applied
                and getattr(node, "lineno", None) == self.target.lineno
                and getattr(node, "col_offset", None) == self.target.col)

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        if self.target.operator == "compare" and self._matches(node):
            for i, op in enumerate(node.ops):
                if type(op).__name__ == self.target.before:
                    node.ops[i] = getattr(ast, self.target.after)()
                    self.applied = True
                    break
        return node

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        if self.target.operator == "boolop" and self._matches(node):
            node.op = getattr(ast, self.target.after)()
            self.applied = True
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        if (self.target.operator == "not" and self._matches(node)
                and isinstance(node.op, ast.Not)):
            self.applied = True
            return node.operand
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if self.target.operator == "constant" and self._matches(node):
            node.value = ast.literal_eval(self.target.after)
            self.applied = True
        return node


def apply_mutation(source: str, mutation: Mutation) -> str:
    tree = _Transformer(mutation).visit(ast.parse(source))
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_mutate.py -v`
Expected: PASS, 6 tests

- [ ] **Step 5: Check the mutant count against the spec's figure**

Run:
```bash
python3 -c "
import pathlib, sys
sys.path.insert(0, 'scripts')
import mutate
n = sum(len(mutate.enumerate_mutations(p.read_text(), p.name))
        for p in pathlib.Path('audit_core').glob('*.py'))
print('mutants:', n)
"
```
Expected: in the region of 647. A much larger number means an operator is over-firing; investigate before Task 12, because the sweep's runtime is linear in this number.

- [ ] **Step 6: Commit**

```bash
git add scripts/mutate.py tests/test_mutate.py
git commit -m "feat: AST mutation operators for audit_core

Comparison flips, and/or swap, not-removal and constant perturbation.
Docstrings are never mutated - perturbing prose is noise. Every mutant
still parses, so a survivor is a real gap and not a syntax error."
```

---

## Task 12: The mutation runner

**Files:**
- Modify: `scripts/mutate.py`
- Test: `tests/test_mutate.py` (append)

**Interfaces:**
- Consumes: Task 11's `enumerate_mutations`, `apply_mutation`, `Mutation`.
- Produces:
  - `select_tests(module: str, tests_dir: pathlib.Path) -> tuple[list[str], bool]` — the test paths, and whether this is the whole-suite fallback.
  - `@dataclass(frozen=True) MutantResult(mutation: Mutation, outcome: str)` — outcome in `{"killed", "survived", "timeout", "error"}`.
  - `run_sweep(package, tests_dir, state_path, timeout=60) -> tuple[MutantResult, ...]` — resumable.

**Three classifications that are not "killed".** Review Focus 2 and 3: a mutant that hangs is `timeout`, a mutant that breaks import is `error`, and neither is a survivor. Only a clean pass of the selected tests is `survived`, and a survivor is re-run against the **whole** suite before being reported — a narrowed selection can otherwise report a false survivor whose killing test lived in a file the selection skipped.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_mutate.py

def test_select_tests_prefers_the_matching_file(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_qualify.py").write_text("")
    (tests / "test_db.py").write_text("")
    paths, fallback = mutate.select_tests("qualify.py", tests)
    assert fallback is False
    assert [pathlib.Path(p).name for p in paths] == ["test_qualify.py"]


def test_select_tests_includes_prefixed_siblings(tmp_path):
    """budget is the one module with no test_budget.py; it has three siblings."""
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("test_budget_epochs.py", "test_budget_attribution.py",
                 "test_db.py"):
        (tests / name).write_text("")
    paths, fallback = mutate.select_tests("budget.py", tests)
    assert fallback is False
    assert sorted(pathlib.Path(p).name for p in paths) == [
        "test_budget_attribution.py", "test_budget_epochs.py"]


def test_select_tests_falls_back_to_the_whole_suite(tmp_path):
    """A silent fallback turns a 20-minute sweep into a 5-hour one."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_other.py").write_text("")
    paths, fallback = mutate.select_tests("nothing.py", tests)
    assert fallback is True
    assert paths == [str(tests)]


def test_a_hanging_mutant_is_a_timeout_not_a_survivor(tmp_path):
    """Review Focus 2."""
    result = mutate._classify(rc=None, timed_out=True, import_error=False)
    assert result == "timeout"


def test_a_mutant_that_breaks_import_is_an_error_not_a_kill(tmp_path):
    """Review Focus 3: an import failure is not evidence a test asserted anything."""
    result = mutate._classify(rc=2, timed_out=False, import_error=True)
    assert result == "error"


def test_a_clean_pass_is_a_survivor():
    assert mutate._classify(rc=0, timed_out=False, import_error=False) == "survived"


def test_a_test_failure_is_a_kill():
    assert mutate._classify(rc=1, timed_out=False, import_error=False) == "killed"


def test_sweep_resumes_from_its_state_file(tmp_path):
    """A 20-minute run that dies at minute 18 and restarts from zero is a
    run that never happens twice."""
    state = tmp_path / "state.json"
    done = mutate.Mutation("m.py", 2, 11, "compare", "Lt", "LtE")
    mutate.save_state(state, {done.label: "killed"})
    assert mutate.load_state(state) == {done.label: "killed"}


def test_sweep_finds_a_known_surviving_mutant_end_to_end(tmp_path):
    """Review Focus 4: an instrument that measures nothing reports zero
    findings. This fixture contains one weak test and one strong one, and
    the sweep must report exactly the weak one's mutant as surviving.
    """
    repo = tmp_path / "repo"
    pkg = repo / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text(
        "def over(n):\n"
        "    return n > 10\n"
        "\n"
        "def under(n):\n"
        "    return n < 10\n"
    )
    tests = repo / "tests"
    tests.mkdir()
    # `over` is tested at the boundary, so Gt->GtE is killed.
    # `under` is tested only far from the boundary, so Lt->LtE survives.
    (tests / "test_m.py").write_text(
        "import sys, pathlib\n"
        f"sys.path.insert(0, {str(repo)!r})\n"
        "from pkg.m import over, under\n"
        "def test_over_at_the_boundary():\n"
        "    assert over(10) is False\n"
        "def test_under_far_from_it():\n"
        "    assert under(0) is True\n"
    )
    results = mutate.run_sweep(pkg, tests, tmp_path / "state.json", timeout=60)
    survived = {r.mutation.label for r in results if r.outcome == "survived"}
    killed = {r.mutation.label for r in results if r.outcome == "killed"}
    assert any("Lt->LtE" in label for label in survived), (
        "the sweep failed to find the planted weak test")
    assert any("Gt->GtE" in label for label in killed), (
        "the sweep reported a killed mutant as surviving")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_mutate.py -v`
Expected: FAIL — `AttributeError: module 'mutate' has no attribute 'select_tests'`

- [ ] **Step 3: Write the runner**

```python
# append to scripts/mutate.py
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

OUTCOMES = ("killed", "survived", "timeout", "error")


@dataclasses.dataclass(frozen=True, slots=True)
class MutantResult:
    mutation: Mutation
    outcome: str


def select_tests(module: str, tests_dir: pathlib.Path) -> tuple[list[str], bool]:
    """`tests/test_<module>.py`, plus any `test_<module>*` sibling.

    22 of the 23 audit_core modules have the exact file; `budget` is the
    exception and is covered by test_budget_epochs.py and
    test_budget_attribution.py, which the prefix match picks up.
    """
    stem = pathlib.Path(module).stem
    matches = sorted(p for p in tests_dir.glob(f"test_{stem}*.py"))
    if matches:
        return [str(p) for p in matches], False
    return [str(tests_dir)], True


def _classify(rc: int | None, timed_out: bool, import_error: bool) -> str:
    if timed_out:
        return "timeout"
    if import_error:
        return "error"
    return "survived" if rc == 0 else "killed"


def load_state(path: pathlib.Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def save_state(path: pathlib.Path, state: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def _run(tree: pathlib.Path, test_paths: list[str], timeout: int):
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", *test_paths, "-q", "--no-header",
             "-p", "no:cacheprovider", "-x"],
            cwd=tree, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, True, False
    output = proc.stdout + proc.stderr
    import_error = ("ImportError" in output or "SyntaxError" in output
                    or "collection error" in output)
    return proc.returncode, False, import_error


def run_sweep(package: pathlib.Path, tests_dir: pathlib.Path,
              state_path: pathlib.Path, timeout: int = 60
              ) -> tuple[MutantResult, ...]:
    """Mutate a COPY of the tree. audit_core is never written to."""
    package = package.resolve()
    repo = package.parent
    state = load_state(state_path)
    results: list[MutantResult] = []

    for source_path in sorted(package.glob("*.py")):
        original = source_path.read_text()
        mutations = enumerate_mutations(original, source_path.name)
        test_paths, fallback = select_tests(source_path.name, tests_dir)
        if fallback:
            print(f"  NOTE {source_path.name}: no matching test file; "
                  f"falling back to the whole suite (~28s per mutant)")
        for mutation in mutations:
            if mutation.label in state:
                results.append(MutantResult(mutation, state[mutation.label]))
                continue
            with tempfile.TemporaryDirectory() as tmp:
                tree = pathlib.Path(tmp) / repo.name
                shutil.copytree(repo, tree, symlinks=True,
                                ignore=shutil.ignore_patterns(
                                    ".git", "__pycache__", ".pytest_cache"))
                target = tree / package.name / source_path.name
                target.write_text(apply_mutation(original, mutation))
                rel = [str(tree / pathlib.Path(p).relative_to(repo))
                       for p in test_paths]
                rc, timed_out, import_error = _run(tree, rel, timeout)
                outcome = _classify(rc, timed_out, import_error)

                # A narrowed selection can report a false survivor whose
                # killing test lived in a file the selection skipped.
                if outcome == "survived" and not fallback:
                    rc2, t2, e2 = _run(tree, [str(tree / tests_dir.name)],
                                       timeout * 4)
                    outcome = _classify(rc2, t2, e2)

            state[mutation.label] = outcome
            save_state(state_path, state)
            results.append(MutantResult(mutation, outcome))
    return tuple(results)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_mutate.py -v`
Expected: PASS, 15 tests

- [ ] **Step 5: Smoke-test the runner on one module**

Run:
```bash
python3 -c "
import pathlib, sys
sys.path.insert(0, 'scripts')
import mutate
r = mutate.run_sweep(pathlib.Path('audit_core'), pathlib.Path('tests'),
                     pathlib.Path('/tmp/cba-mutate-smoke.json'))
" 2>&1 | tail -5
```
This runs the full sweep; stop it after a minute with Ctrl-C and confirm `/tmp/cba-mutate-smoke.json` holds partial results. Re-run and confirm it resumes rather than restarting.

- [ ] **Step 6: Commit**

```bash
git add scripts/mutate.py tests/test_mutate.py
git commit -m "feat: resumable mutation runner over a temp copy of the tree

Never writes into audit_core. Classifies timeout and import-error
separately from killed, re-runs the whole suite against each apparent
survivor so a narrowed test selection cannot manufacture one, and
checkpoints after every mutant so a 20-minute run survives being
interrupted."
```

---

## Task 13: The mutation gate

**Files:**
- Create: `scripts/mutation-allowlist.txt`
- Modify: `scripts/mutate.py` (CLI entry point)
- Modify: `scripts/harness.py` (`gate_mutate` in `GATES` **only**)
- Modify: `Makefile`
- Modify: `feature_lists.json`
- Test: `tests/test_mutate.py` (append)

**`mutate` is excluded from `DEFAULT` and from `--all`.** `bench` is in `--all` only because it SKIPs on a runner; a mutation gate would not skip, and `ci.yml` runs `--all` across three Python versions, so inclusion would mean roughly 60 minutes of CI per push. `main` has never been pushed and CI has never run, which makes this a debt that comes due the day origin returns rather than a cost today — exactly when it should not have been done carelessly.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_mutate.py

def test_harness_exposes_mutate_but_keeps_it_out_of_default_and_all():
    import importlib.util
    root = pathlib.Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("harness", root / "scripts" / "harness.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    assert "mutate" in harness.GATES
    assert "mutate" not in harness.DEFAULT
    assert "mutate" not in harness.ALL_EXTRA, (
        "ci.yml runs --all across three Python versions; a 20-minute "
        "non-skipping gate there is 60 minutes per push")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_mutate.py -k harness -v`
Expected: FAIL — `AssertionError: assert 'mutate' in {...}`

- [ ] **Step 3: Make `--all`'s extra set explicit in `scripts/harness.py`**

Today `--all` means "every gate in `GATES`". That silently swallows any new gate, which is the mechanism the test above exists to prevent. Make the opt-in set explicit:

```python
# `make check` runs DEFAULT. `--all` adds ALL_EXTRA. Anything in GATES but in
# neither is reachable only by `--only <name>`: that is where a gate whose cost
# is minutes rather than seconds belongs, because ci.yml runs `--all`.
DEFAULT = ["tests", "selftest", "lint", "eol", "manifest", "install", "coverage"]
ALL_EXTRA = ["bench"]
```

and in `main`, replace the `--all` branch:

```python
selected = (DEFAULT + ALL_EXTRA) if args.all else list(DEFAULT)
```

- [ ] **Step 4: Add `gate_mutate`**

```python
def gate_mutate() -> Result:
    """No surviving mutant that is not on the allowlist, with a reason.

    Opt-in: ~20 minutes plus the confirmation re-run per survivor. Reachable
    by `--only mutate` or `make mutate`, and deliberately not by `--all`.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    import mutate
    import coverage_allowlist as allowlist

    results = mutate.run_sweep(ROOT / "audit_core", ROOT / "tests",
                               ROOT / ".mutate-state.json")
    survivors = [r for r in results if r.outcome == "survived"]
    permitted = {
        line.split("#", 1)[0].strip()
        for line in (ROOT / "scripts" / "mutation-allowlist.txt").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")}

    unexplained = [r for r in survivors if r.mutation.label not in permitted]
    summary = (f"{len(results)} mutants, {len(survivors)} survived, "
               f"{len(unexplained)} unexplained")
    if not unexplained:
        return Result("mutate", PASS, summary)
    detail = "\n".join(f"  survived: {r.mutation.label}" for r in unexplained)
    return Result("mutate", FAIL, summary, detail=detail)
```

Same signature note as Task 3: `Result(name, status, summary, detail="")`, name first.

Register in `GATES` only:

```python
    "coverage": gate_coverage,
    "bench": gate_bench,
    "mutate": gate_mutate,
}
```

- [ ] **Step 5: Create the allowlist**

```bash
cat > scripts/mutation-allowlist.txt <<'EOF'
# Mutants that survive and are permitted to.
#
# A surviving mutant normally means no test asserts anything that depends on
# the mutated line. Some are EQUIVALENT: the change has no observable effect,
# so no test can kill it and demanding one is make-work. Those go here, with
# the reason.
#
# An entry without a reason is not an explanation. Format:
#
#   <module>.py:<line>:<col> <operator> <before>-><after>  # why it is unkillable
#
# Populated by Task 14 from the first sweep.
EOF
```

- [ ] **Step 6: Add the `Makefile` target**

Read the existing targets first and match their style:

```make
mutate:  ## Mutation sweep over audit_core (~20 min; not part of `make all`)
	python3 scripts/harness.py --only mutate
```

- [ ] **Step 7: Add the feature entry to `feature_lists.json`**

```json
{
  "id": "mutation-harness",
  "name": "Mutation harness and gate",
  "area": "harness",
  "status": "shipped",
  "summary": "AST mutation over a temp copy of the tree, finding tests that execute a line while asserting nothing that depends on it. Opt-in: in GATES, not in DEFAULT and not in ALL_EXTRA, because ci.yml runs --all across three Python versions.",
  "modules": ["scripts/mutate.py", "scripts/harness.py"],
  "tests": ["tests/test_mutate.py"],
  "docs": ["docs/superpowers/specs/2026-10-08-stage3c-core-hardening-design.md"]
}
```

- [ ] **Step 8: Verify the gate set**

Run: `python3 scripts/harness.py --list && make all`
Expected: `mutate` listed; `make all` runs 8 gates and does **not** run `mutate`.

- [ ] **Step 9: Commit**

```bash
git add scripts/mutate.py scripts/mutation-allowlist.txt scripts/harness.py Makefile feature_lists.json tests/test_mutate.py
git commit -m "feat: mutation gate, opt-in and kept out of --all

Makes --all's extra set explicit (ALL_EXTRA) so a new gate can no longer
be swallowed into CI by default. ci.yml runs --all on three Python
versions; a 20-minute non-skipping gate there is an hour per push."
```

---

## Task 14: Run the sweep and record the measurement

**Files:**
- Create: `docs/baselines/2026-10-08-mutation-sweep.md`
- Modify: `scripts/mutation-allowlist.txt`

This is a measurement, so `SESSION_HANDOFF.md` rule 4 binds: **the document is never edited in place.** A correction is a new dated file or an appended, dated note.

- [ ] **Step 1: Run the full sweep**

Run: `time make mutate 2>&1 | tee /tmp/cba-mutation-run.log`
Expected: ~20 minutes plus ~28s per survivor. It will likely FAIL on the first run — that is the point.

- [ ] **Step 2: Triage every survivor**

For each, decide and record which it is:

| Verdict | Meaning | Action |
|---|---|---|
| **Weak test** | a test executes the line but asserts nothing that depends on it | strengthen the assertion — Task 15 |
| **Missing test** | nothing asserts this behaviour at all | write one — Task 15 |
| **Equivalent mutant** | the change has no observable effect; no test can kill it | allowlist entry with that reason |
| **Real defect** | the mutated behaviour is *correct* and the original is wrong | fix the code — Task 15, and say so loudly |

- [ ] **Step 3: Write the baseline document**

```markdown
# Mutation sweep — audit_core, 2026-10-08

**Measured against:** `main` at <commit>, <N> tests, after Stage 3c closed
the 115 unexecuted statements.
**Instrument:** `scripts/mutate.py`, `make mutate`.
**Runtime:** <actual>.

## Result

| | count |
|---|---|
| mutants | |
| killed | |
| survived | |
| timeout | |
| error (import) | |

**Mutation score:** killed / (killed + survived).

## Survivors, triaged

| mutant | verdict | action |
|---|---|---|

## What this measurement is for

Line coverage finds the branch no test enters. This finds the branch a test
enters while asserting too little - the class this project recorded as "the
Task 2 test that substituted an easier input for the one its finding named."
A second sweep after any substantial change to `audit_core` compares against
this table.
```

Fill every cell from the run. No blanks.

- [ ] **Step 4: Populate the mutation allowlist with the equivalent mutants only**

Each entry carries the reason it is unkillable. A survivor that is a weak or missing test does **not** go on the list — it goes to Task 15.

- [ ] **Step 5: Commit**

```bash
git add docs/baselines/2026-10-08-mutation-sweep.md scripts/mutation-allowlist.txt
git commit -m "docs: the first mutation sweep over audit_core

A measurement, so rule 4 binds: never edited in place. Allowlist holds
only equivalent mutants; weak and missing tests are the next task."
```

---

## Task 15: Fix what the sweep found

**Files:**
- Modify: the test files and `audit_core` modules the triage named.
- Modify: `scripts/mutation-allowlist.txt`

- [ ] **Step 1: Strengthen each weak test**

For each weak-test survivor, change the assertion so it depends on the mutated line. Re-run that one mutant to confirm it is now killed:

```bash
python3 -c "
import pathlib, sys
sys.path.insert(0, 'scripts')
import mutate
# narrow the state file to force a re-run of this label
"
```
Simplest reliable method: delete `.mutate-state.json` entries for the labels being fixed, then `make mutate`.

- [ ] **Step 2: Fix any real defect the sweep exposed**

A mutant whose mutated behaviour is correct means the original is wrong. Fix the code, add the test that proves it, and **state it plainly in the commit message** — a defect found by an instrument this stage built is the strongest evidence the stage was worth doing.

- [ ] **Step 3: Re-run the sweep to green**

Run: `make mutate`
Expected: PASS, `<N> mutants, <M> survived, 0 unexplained`

- [ ] **Step 4: Run every gate**

Run: `make all`
Expected: 8 PASS (or `bench` SKIP off the operator's machine).

- [ ] **Step 5: Commit**

```bash
git add tests/ audit_core/ scripts/mutation-allowlist.txt
git commit -m "fix: strengthen the tests the mutation sweep found hollow

<n> weak assertions rewritten, <n> missing tests added, <n> real defects
fixed. Every remaining survivor is an equivalent mutant with a written
reason."
```

---

## Task 16: Update the record

**Files:**
- Modify: `progress.md`, `ARCHITECTURE.md`, `feature_lists.json`, `SESSION_HANDOFF.md`

No shipped prose — `SKILL.md`, `workflows/` and `references/` are untouched, so rule 6's derivation requirement does not apply. Confirm that is still true before writing.

- [ ] **Step 1: Confirm no shipped prose moved**

Run: `git diff --stat main...HEAD -- SKILL.md workflows/ references/`
Expected: empty output. If not, stop — that is out of scope for this stage.

- [ ] **Step 2: Update `progress.md`**

Add Stage 3c to the stage table with status **shipped** and gate *none — no audit run*. Record: the measured starting point (115 unexecuted of 2,392, 95.2%), the finishing point, the mutation score, and the two new gates. State plainly that this stage **cannot** have moved recall or precision and claims neither.

- [ ] **Step 3: Update `ARCHITECTURE.md`**

Add the two instruments to the harness section: what each measures, which defect class it catches, and why `mutate` is excluded from `--all`.

- [ ] **Step 4: Update `feature_lists.json`**

Add a `stage3c` entry to `stages`, status `shipped`, gate `none - no audit run`. Close the `qualify-negative-rce-branch-untested` open item with `status: closed`, `closed_in: stage3c`.

- [ ] **Step 5: Update `SESSION_HANDOFF.md`**

Refresh the header (branch, commit, test count, `8/8` gates), the expected `make all` output block, and §4 "What to do next". Add to §5 "If you add a feature": a new unexecuted statement needs an allowlist entry with a reason, or a test.

Correct two stale figures while there: §2 says `main` is 122 commits ahead of origin — it is 124 as of the start of this stage — and the header says 615 tests, which was already 621 before this stage began.

- [ ] **Step 6: Run every gate**

Run: `make all`
Expected: 8 PASS.

- [ ] **Step 7: Commit**

```bash
git add progress.md ARCHITECTURE.md feature_lists.json SESSION_HANDOFF.md
git commit -m "docs: Stage 3c in the record

115 unexecuted statements of 2,392 at the start, measured not assumed.
Two instruments shipped: a coverage gate in DEFAULT and a mutation gate
deliberately out of --all. This stage changed no audit behaviour and
claims no movement in recall or precision."
```

---

## Whole-branch review

**Do not skip this.** In both Stage 2 and Stage 3 it found Criticals that every task-scoped review was structurally blind to — a per-task reviewer cannot see a writer that no task was assigned to build. Stage 3's coverage gate shipped with no writer side and produced FAIL on a correct run.

Use `superpowers:requesting-code-review` against the whole branch, with these as the specific questions:

1. Does `gate_coverage` fail on a **regressed** gap, a **stale** digest, and a **listed-but-now-executed** line? All three, demonstrated, not asserted.
2. Is there any new test whose assertion would survive its subject being wrong? That is the defect this stage exists to remove, and writing it here would be the stage failing at its own purpose.
3. Did any tool write into `audit_core`, `tests/goldens/`, or `~/Documents/Offsec/Opswat/Devices/`?
4. Does `make all` still finish in a time anyone will tolerate, and is `mutate` genuinely absent from both `DEFAULT` and `ALL_EXTRA`?
5. Is any statement still allowlisted with the seeded `Stage 3c: not yet closed` reason?

Then `superpowers:finishing-a-development-branch`.
