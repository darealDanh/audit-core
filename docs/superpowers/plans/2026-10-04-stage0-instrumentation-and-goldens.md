# Stage 0: Instrumentation and Goldens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the measurement harness that every later stage is gated on — a transcript economics analyzer and a golden-set recall scorer — and record the baseline from the existing tplink audit.

**Architecture:** Three stdlib-only Python modules behind one verb-dispatch CLI. `transcript.py` parses a Claude Code JSONL session into typed records and classifies every token added to message history **by record type, never by substring**. `budget.py` turns those records into per-epoch economics with exact residency attribution. `bench.py` scores a completed audit against a golden reference set, counting only human-adjudicated matches. Nothing in this stage changes any skill's behaviour.

**Tech Stack:** Python 3.10+, stdlib only (`json`, `sqlite3`, `dataclasses`, `statistics`, `pathlib`, `argparse`). `pytest` for tests.

**Spec:** `docs/superpowers/specs/2026-10-04-audit-suite-design.md`

## Global Constraints

- **No third-party runtime dependencies.** `audit_core` imports stdlib only. `pytest` is a dev dependency.
- **Python floor 3.10.** Dataclasses with `slots=True`, `X | None` unions.
- **Build at the current repo root.** `audit_core/`, `audit.py`, `tests/`, `pyproject.toml` go at `Tools/codebase-audit/`. Do **not** move `SKILL.md`, `workflows/` or `references/` — the `skills/<name>/` migration is Stage 2. The existing installer copies only `SKILL.md`, `workflows/*.md` and `references/*.md`, so new root directories change nothing installed.
- **Classification is by record type, never by substring.** A component is identified by `type`, `attachment.type`, and content-block `type`. Searching raw line text for a marker is the defect this stage exists to prevent; it produced a 14x error in the spec's first draft.
- **No network access** in any module or test.
- **Transcripts are read-only.** Never write to anything under `~/.claude/projects/`.
- **Real transcript paths** for manual verification: `~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices*/**.jsonl` (9 files). Tests use synthetic fixtures only.

## Review Focus

Five failure modes the spec implies that no task's happy path exercises. Each has a test assigned to the task that owns the code.

1. **Substring classification leaking across components** — assistant text containing the literal `<task-notification>` must not be counted as a subagent result. Owned by Task 2.
2. **Zero-context turns** — continuation iterations report `context == 0` and appear in 2 of tplink's 7 epochs. They must be excluded from floor, mean and growth, or the prefix floor reads 0. Owned by Task 3.
3. **Truncated final line** — transcripts are appended live, so the last line may be partial JSON. Parsing must skip it, not raise. Owned by Task 2.
4. **Single-turn epoch** — growth rate divides by `turns - 1`. An epoch with one turn must yield `0.0`, not `ZeroDivisionError`. Owned by Task 3.
5. **Unadjudicated candidate counted as a match** — a run finding sharing a location token with a reference must be reported as a *candidate*, never counted in recall. Owned by Task 7.

---

### Task 1: Repository skeleton and `selftest`

**Files:**
- Create: `pyproject.toml`
- Create: `audit_core/__init__.py`
- Create: `audit.py`
- Create: `tests/__init__.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `audit.py` dispatching `selftest`; `audit_core.__version__` (str).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import subprocess, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

def run(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), *args],
        capture_output=True, text=True,
    )

def test_selftest_exits_zero_and_reports_version():
    r = run("selftest")
    assert r.returncode == 0, r.stderr
    assert "audit_core" in r.stdout

def test_unknown_verb_exits_nonzero():
    r = run("nosuchverb")
    assert r.returncode != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: FAIL — `audit.py` does not exist (`returncode == 2`, stderr mentions `can't open file`).

- [ ] **Step 3: Write minimal implementation**

```toml
# pyproject.toml
[project]
name = "audit-suite"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

```python
# audit_core/__init__.py
__version__ = "0.1.0"
```

```python
#!/usr/bin/env python3
"""audit.py - verb dispatch for the audit suite."""
import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import audit_core  # noqa: E402


def cmd_selftest(_args: argparse.Namespace) -> int:
    print(f"audit_core {audit_core.__version__} ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit.py")
    sub = p.add_subparsers(dest="verb", required=True)
    sub.add_parser("selftest", help="verify the vendored core is importable")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"selftest": cmd_selftest}[args.verb](args)


if __name__ == "__main__":
    raise SystemExit(main())
```

```python
# tests/__init__.py
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: PASS, 2 passed.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml audit_core/__init__.py audit.py tests/__init__.py tests/test_cli.py
git commit -m "feat: audit.py verb dispatch skeleton with selftest"
```

---

### Task 2: Transcript parsing and component classification

**Files:**
- Create: `audit_core/transcript.py`
- Create: `tests/test_transcript.py`
- Create: `tests/fixtures/__init__.py`
- Create: `tests/fixtures/build.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `COMPONENTS: tuple[str, ...]`
  - `Turn(index: int, context: int, output: int, thinking: int, epoch: int)`
  - `Addition(component: str, tokens: int, turn_index: int, epoch: int)`
  - `ToolCall(name: str, input_tokens: int, result_tokens: int)`
  - `Transcript(path: str, session_id: str, turns: list[Turn], additions: list[Addition], tool_calls: list[ToolCall], cost_usd: float | None, model_usage: dict)`
  - `parse(path: str | pathlib.Path) -> Transcript`
  - `estimate_tokens(text: str) -> int`

- [ ] **Step 1: Write the fixture builder**

```python
# tests/fixtures/build.py
"""Synthetic Claude Code JSONL transcripts. No real session data."""
import json


def line(obj) -> str:
    return json.dumps(obj) + "\n"


def assistant(content, cache_read=0, cache_creation=0, inp=0, output=0, thinking=0):
    return line({
        "type": "assistant",
        "isSidechain": False,
        "sessionId": "test-session",
        "message": {
            "content": content,
            "usage": {
                "input_tokens": inp,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": cache_creation,
                "output_tokens": output,
                "output_tokens_details": {"thinking_tokens": thinking},
            },
        },
    })


def user_text(text):
    return line({"type": "user", "isSidechain": False, "sessionId": "test-session",
                 "message": {"content": text}})


def user_blocks(blocks):
    return line({"type": "user", "isSidechain": False, "sessionId": "test-session",
                 "message": {"content": blocks}})


def compact_summary(text="summary"):
    return line({"type": "user", "isSidechain": False, "isCompactSummary": True,
                 "sessionId": "test-session", "message": {"content": text}})


def attachment(atype, payload="x"):
    return line({"type": "attachment", "isSidechain": False, "sessionId": "test-session",
                 "attachment": {"type": atype, "payload": payload}})


def cost_state(usd=1.25):
    return line({"type": "cost-state", "sessionId": "test-session",
                 "totalCostUSD": usd, "modelUsage": {"claude-opus-5": {"costUSD": usd}}})
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_transcript.py
import pathlib
from audit_core import transcript as T
from tests.fixtures import build as B


def write(tmp_path, *lines) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text("".join(lines))
    return p


def test_turns_carry_context_and_epoch(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000, output=10),
              B.assistant([{"type": "text", "text": "b"}], cache_read=2000, output=10))
    t = T.parse(p)
    assert [x.context for x in t.turns] == [1000, 2000]
    assert {x.epoch for x in t.turns} == {0}


def test_compaction_starts_a_new_epoch(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"}], cache_read=1000),
              B.compact_summary(),
              B.assistant([{"type": "text", "text": "b"}], cache_read=500))
    t = T.parse(p)
    assert [x.epoch for x in t.turns] == [0, 1]


def test_task_notification_marker_in_assistant_text_is_not_a_subagent_result(tmp_path):
    """Review Focus 1: classify by record type, never by substring."""
    p = write(tmp_path,
              B.assistant([{"type": "text",
                            "text": "I will emit <task-notification> when done"}]))
    t = T.parse(p)
    kinds = {a.component for a in t.additions}
    assert "subagent_result" not in kinds
    assert "assistant_text" in kinds


def test_task_notification_in_user_message_is_a_subagent_result(tmp_path):
    p = write(tmp_path, B.user_text("<task-notification>agent done</task-notification>"))
    t = T.parse(p)
    assert [a.component for a in t.additions] == ["subagent_result"]


def test_truncated_final_line_is_skipped(tmp_path):
    """Review Focus 3."""
    p = tmp_path / "s.jsonl"
    p.write_text(B.assistant([{"type": "text", "text": "a"}], cache_read=10)
                 + '{"type": "assistant", "mess')
    t = T.parse(p)
    assert len(t.turns) == 1


def test_tool_calls_pair_input_with_result(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "tool_use", "id": "t1", "name": "Bash",
                            "input": {"command": "ls -la /tmp"}}]),
              B.user_blocks([{"type": "tool_result", "tool_use_id": "t1",
                              "content": "a" * 400}]))
    t = T.parse(p)
    assert len(t.tool_calls) == 1
    assert t.tool_calls[0].name == "Bash"
    assert t.tool_calls[0].result_tokens == 100


def test_attachment_types_are_distinct_components(tmp_path):
    p = write(tmp_path,
              B.attachment("total_tokens_reminder"),
              B.attachment("invoked_skills"))
    t = T.parse(p)
    assert {a.component for a in t.additions} == {
        "attachment:total_tokens_reminder", "attachment:invoked_skills"}


def test_cost_state_is_read(tmp_path):
    p = write(tmp_path, B.assistant([], cache_read=1), B.cost_state(3.5))
    assert T.parse(p).cost_usd == 3.5


def test_missing_cost_state_yields_none(tmp_path):
    p = write(tmp_path, B.assistant([], cache_read=1))
    assert T.parse(p).cost_usd is None


def test_every_addition_component_is_declared(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a"},
                           {"type": "thinking", "thinking": "t"},
                           {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}]),
              B.user_text("hello"),
              B.attachment("date"))
    t = T.parse(p)
    for a in t.additions:
        assert a.component in T.COMPONENTS or a.component.startswith("attachment:")
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_transcript.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.transcript'`.

- [ ] **Step 4: Write the implementation**

```python
# audit_core/transcript.py
"""Parse a Claude Code JSONL session into typed records.

Classification is by record type and attachment type only. Never search raw
line text for a marker: the system prompt is itself written into the
transcript as a `prompt_snapshot` attachment, so substring matching
misattributes system-prompt text to whatever component the marker names.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

CHARS_PER_TOKEN = 4

COMPONENTS: tuple[str, ...] = (
    "thinking_block",
    "assistant_text",
    "tool_use_input",
    "tool_result",
    "subagent_result",
    "user_text",
)

# Attachment types that are injected into the model's context. Types absent
# from this set (notably `prompt_snapshot`, which is a logging artefact of the
# system prompt) are recorded in the transcript but never charged to context.
CONTEXT_ATTACHMENTS: frozenset[str] = frozenset({
    "total_tokens_reminder", "environment", "date", "session_context",
    "instructions", "invoked_skills", "skill_listing", "deferred_tools_record",
    "deferred_tools_delta", "mcp_instructions_delta", "agent_listing_delta",
    "hook_additional_context", "hook_success", "file", "edited_text_file",
    "compact_file_reference", "queued_command", "model", "auto_mode",
    "command_permissions", "remote_session_change",
})

SUBAGENT_MARKER = "<task-notification"


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN


@dataclass(frozen=True, slots=True)
class Turn:
    index: int
    context: int
    output: int
    thinking: int
    epoch: int


@dataclass(frozen=True, slots=True)
class Addition:
    component: str
    tokens: int
    turn_index: int
    epoch: int


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    input_tokens: int
    result_tokens: int


@dataclass(frozen=True, slots=True)
class Transcript:
    path: str
    session_id: str
    turns: list[Turn] = field(default_factory=list)
    additions: list[Addition] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    cost_usd: float | None = None
    model_usage: dict = field(default_factory=dict)


def _iter_records(path: pathlib.Path):
    with path.open(errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                continue  # truncated tail of a live transcript


def parse(path: str | pathlib.Path) -> Transcript:
    path = pathlib.Path(path)
    turns: list[Turn] = []
    additions: list[Addition] = []
    tool_calls: list[ToolCall] = []
    pending: dict[str, tuple[str, int]] = {}
    session_id = ""
    cost_usd: float | None = None
    model_usage: dict = {}
    epoch = 0
    turn_index = -1

    def add(component: str, tokens: int) -> None:
        if tokens > 0:
            additions.append(Addition(component, tokens, max(turn_index, 0), epoch))

    for rec in _iter_records(path):
        session_id = session_id or rec.get("sessionId", "")
        rtype = rec.get("type")

        if rtype == "cost-state":
            cost_usd = rec.get("totalCostUSD")
            model_usage = rec.get("modelUsage") or {}

        elif rtype == "assistant":
            msg = rec.get("message") or {}
            usage = msg.get("usage") or {}
            context = (usage.get("cache_read_input_tokens", 0)
                       + usage.get("cache_creation_input_tokens", 0)
                       + usage.get("input_tokens", 0))
            turn_index += 1
            turns.append(Turn(
                index=turn_index,
                context=context,
                output=usage.get("output_tokens", 0),
                thinking=(usage.get("output_tokens_details") or {}).get("thinking_tokens", 0),
                epoch=epoch,
            ))
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "text":
                        add("assistant_text", estimate_tokens(block.get("text", "")))
                    elif btype == "thinking":
                        add("thinking_block", estimate_tokens(json.dumps(block)))
                    elif btype == "tool_use":
                        n = estimate_tokens(json.dumps(block.get("input", {})))
                        add("tool_use_input", n)
                        pending[block.get("id", "")] = (block.get("name", "?"), n)

        elif rtype == "user":
            if rec.get("isCompactSummary"):
                epoch += 1
                continue
            content = (rec.get("message") or {}).get("content")
            if isinstance(content, str):
                _classify_user_text(content, add)
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        payload = block.get("content", "")
                        n = estimate_tokens(payload if isinstance(payload, str)
                                            else json.dumps(payload))
                        add("tool_result", n)
                        name, in_tokens = pending.pop(block.get("tool_use_id", ""), ("?", 0))
                        tool_calls.append(ToolCall(name, in_tokens, n))
                    elif block.get("type") == "text":
                        _classify_user_text(block.get("text", ""), add)

        elif rtype == "attachment":
            atype = (rec.get("attachment") or {}).get("type", "?")
            if atype in CONTEXT_ATTACHMENTS:
                add(f"attachment:{atype}", estimate_tokens(json.dumps(rec)))

    return Transcript(str(path), session_id, turns, additions, tool_calls,
                      cost_usd, model_usage)


def _classify_user_text(text: str, add) -> None:
    component = "subagent_result" if SUBAGENT_MARKER in text else "user_text"
    add(component, estimate_tokens(text))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_transcript.py -v`
Expected: PASS, 10 passed.

- [ ] **Step 6: Commit**

```bash
git add audit_core/transcript.py tests/test_transcript.py tests/fixtures/
git commit -m "feat: transcript parser with record-type component classification"
```

---

### Task 3: Epoch economics — floor, growth, aggregate statistics

**Files:**
- Create: `audit_core/budget.py`
- Create: `tests/test_budget_epochs.py`

**Interfaces:**
- Consumes: `audit_core.transcript.Transcript`, `Turn`.
- Produces:
  - `Epoch(index: int, turns: int, floor: int, peak: int, mean: int, total: int, growth_per_turn: float)`
  - `epochs_of(t: Transcript) -> list[Epoch]`
  - `Stats(turns: int, sum_context: int, mean_context: int, median_context: int, p90_context: int, max_context: int, prefix_floor: int, growth_per_turn: float)`
  - `stats_of(t: Transcript) -> Stats`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_budget_epochs.py
import pathlib
from audit_core import budget, transcript as T
from tests.fixtures import build as B


def write(tmp_path, *lines) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text("".join(lines))
    return p


def test_zero_context_turns_excluded_from_floor(tmp_path):
    """Review Focus 2: continuation iterations report context 0."""
    p = write(tmp_path,
              B.assistant([], cache_read=50_000),
              B.assistant([], cache_read=0),
              B.assistant([], cache_read=70_000))
    e = budget.epochs_of(T.parse(p))
    assert len(e) == 1
    assert e[0].floor == 50_000
    assert e[0].turns == 2


def test_single_turn_epoch_has_zero_growth(tmp_path):
    """Review Focus 4: growth divides by turns - 1."""
    p = write(tmp_path, B.assistant([], cache_read=50_000))
    assert budget.epochs_of(T.parse(p))[0].growth_per_turn == 0.0


def test_growth_is_span_over_turn_gaps(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=10_000),
              B.assistant([], cache_read=20_000),
              B.assistant([], cache_read=30_000))
    assert budget.epochs_of(T.parse(p))[0].growth_per_turn == 10_000.0


def test_epoch_split_on_compaction(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=90_000),
              B.compact_summary(),
              B.assistant([], cache_read=40_000))
    e = budget.epochs_of(T.parse(p))
    assert [x.floor for x in e] == [90_000, 40_000]


def test_epoch_with_only_zero_context_turns_is_dropped(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=0),
              B.compact_summary(),
              B.assistant([], cache_read=40_000))
    assert [x.floor for x in budget.epochs_of(T.parse(p))] == [40_000]


def test_stats_prefix_floor_is_lowest_nonzero_epoch_floor(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=80_000),
              B.compact_summary(),
              B.assistant([], cache_read=45_000),
              B.assistant([], cache_read=95_000))
    s = budget.stats_of(T.parse(p))
    assert s.prefix_floor == 45_000
    assert s.sum_context == 220_000
    assert s.turns == 3
    assert s.max_context == 95_000
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_budget_epochs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.budget'`.

- [ ] **Step 3: Write the implementation**

```python
# audit_core/budget.py
"""Economics of a Claude Code session: epochs, prefix, growth, attribution."""
from __future__ import annotations

import statistics
from dataclasses import dataclass

from audit_core.transcript import Transcript, Turn


@dataclass(frozen=True, slots=True)
class Epoch:
    index: int
    turns: int
    floor: int
    peak: int
    mean: int
    total: int
    growth_per_turn: float


@dataclass(frozen=True, slots=True)
class Stats:
    turns: int
    sum_context: int
    mean_context: int
    median_context: int
    p90_context: int
    max_context: int
    prefix_floor: int
    growth_per_turn: float


def _billed(turns: list[Turn]) -> list[Turn]:
    """Turns that cost context. Continuation iterations report 0."""
    return [t for t in turns if t.context > 0]


def epochs_of(t: Transcript) -> list[Epoch]:
    by_epoch: dict[int, list[Turn]] = {}
    for turn in _billed(t.turns):
        by_epoch.setdefault(turn.epoch, []).append(turn)

    out: list[Epoch] = []
    for i, key in enumerate(sorted(by_epoch)):
        ctx = [x.context for x in by_epoch[key]]
        span = max(ctx) - min(ctx)
        gaps = len(ctx) - 1
        out.append(Epoch(
            index=i,
            turns=len(ctx),
            floor=min(ctx),
            peak=max(ctx),
            mean=sum(ctx) // len(ctx),
            total=sum(ctx),
            growth_per_turn=(span / gaps) if gaps else 0.0,
        ))
    return out


def stats_of(t: Transcript) -> Stats:
    ctx = sorted(x.context for x in _billed(t.turns))
    if not ctx:
        return Stats(0, 0, 0, 0, 0, 0, 0, 0.0)
    eps = epochs_of(t)
    weighted = sum(e.growth_per_turn * e.turns for e in eps)
    total_turns = sum(e.turns for e in eps)
    return Stats(
        turns=len(ctx),
        sum_context=sum(ctx),
        mean_context=sum(ctx) // len(ctx),
        median_context=int(statistics.median(ctx)),
        p90_context=ctx[min(int(len(ctx) * 0.9), len(ctx) - 1)],
        max_context=ctx[-1],
        prefix_floor=min(e.floor for e in eps),
        growth_per_turn=(weighted / total_turns) if total_turns else 0.0,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_budget_epochs.py -v`
Expected: PASS, 6 passed.

- [ ] **Step 5: Commit**

```bash
git add audit_core/budget.py tests/test_budget_epochs.py
git commit -m "feat: per-epoch context economics with zero-turn and single-turn handling"
```

---

### Task 4: Composition and exact residency attribution

**Files:**
- Modify: `audit_core/budget.py` (append)
- Create: `tests/test_budget_attribution.py`

**Interfaces:**
- Consumes: `Epoch`, `Stats`, `Transcript`, `Addition`.
- Produces:
  - `Report(session_id, path, stats: Stats, epochs: list[Epoch], composition: dict[str, int], attribution: dict[str, int], prefix_term: int, accumulation_term: int, cost_usd: float | None, tool_result_tokens: int, tool_input_tokens: int, tool_calls_by_name: dict[str, int])`
  - `analyze(t: Transcript) -> Report`
  - `render(r: Report) -> str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_budget_attribution.py
import pathlib
from audit_core import budget, transcript as T
from tests.fixtures import build as B


def write(tmp_path, *lines) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text("".join(lines))
    return p


def test_composition_sums_additions_by_component(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.assistant([{"type": "text", "text": "b" * 800}], cache_read=2000))
    r = budget.analyze(T.parse(p))
    assert r.composition["assistant_text"] == 300


def test_attribution_charges_tokens_for_remaining_turns_in_epoch(tmp_path):
    """An addition on turn 0 of a 3-turn epoch is resident for 3 turns."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.assistant([], cache_read=2000),
              B.assistant([], cache_read=3000))
    r = budget.analyze(T.parse(p))
    assert r.attribution["assistant_text"] == 300


def test_attribution_resets_at_compaction(tmp_path):
    """An addition in epoch 0 is not charged for epoch 1's turns."""
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.compact_summary(),
              B.assistant([], cache_read=500),
              B.assistant([], cache_read=600))
    r = budget.analyze(T.parse(p))
    assert r.attribution["assistant_text"] == 100


def test_prefix_and_accumulation_partition_total_context(tmp_path):
    p = write(tmp_path,
              B.assistant([], cache_read=50_000),
              B.assistant([], cache_read=70_000))
    r = budget.analyze(T.parse(p))
    assert r.prefix_term == 100_000
    assert r.accumulation_term == 20_000
    assert r.prefix_term + r.accumulation_term == r.stats.sum_context


def test_tool_totals_are_split_by_direction(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "tool_use", "id": "t1", "name": "Bash",
                            "input": {"command": "x" * 200}}], cache_read=1000),
              B.user_blocks([{"type": "tool_result", "tool_use_id": "t1",
                              "content": "y" * 800}]))
    r = budget.analyze(T.parse(p))
    assert r.tool_result_tokens == 200
    assert r.tool_input_tokens > 0
    assert r.tool_calls_by_name["Bash"] == 1


def test_render_includes_every_nonzero_component(tmp_path):
    p = write(tmp_path,
              B.assistant([{"type": "text", "text": "a" * 400}], cache_read=1000),
              B.attachment("total_tokens_reminder"))
    text = budget.render(budget.analyze(T.parse(p)))
    assert "assistant_text" in text
    assert "attachment:total_tokens_reminder" in text
    assert "prefix" in text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_budget_attribution.py -v`
Expected: FAIL — `AttributeError: module 'audit_core.budget' has no attribute 'analyze'`.

- [ ] **Step 3: Append the implementation to `audit_core/budget.py`**

```python
@dataclass(frozen=True, slots=True)
class Report:
    session_id: str
    path: str
    stats: Stats
    epochs: list[Epoch]
    composition: dict[str, int]
    attribution: dict[str, int]
    prefix_term: int
    accumulation_term: int
    cost_usd: float | None
    tool_result_tokens: int
    tool_input_tokens: int
    tool_calls_by_name: dict[str, int]


def analyze(t: Transcript) -> Report:
    stats = stats_of(t)
    eps = epochs_of(t)

    # Last billed turn index within each epoch, for residency.
    last_turn: dict[int, int] = {}
    turns_in: dict[int, int] = {}
    for turn in _billed(t.turns):
        last_turn[turn.epoch] = max(last_turn.get(turn.epoch, 0), turn.index)
        turns_in[turn.epoch] = turns_in.get(turn.epoch, 0) + 1

    composition: dict[str, int] = {}
    attribution: dict[str, int] = {}
    for a in t.additions:
        composition[a.component] = composition.get(a.component, 0) + a.tokens
        if a.epoch not in last_turn:
            continue
        resident = max(0, last_turn[a.epoch] - a.turn_index + 1)
        attribution[a.component] = attribution.get(a.component, 0) + a.tokens * resident

    prefix_term = sum(e.floor * e.turns for e in eps)
    tool_calls_by_name: dict[str, int] = {}
    for call in t.tool_calls:
        tool_calls_by_name[call.name] = tool_calls_by_name.get(call.name, 0) + 1

    return Report(
        session_id=t.session_id,
        path=t.path,
        stats=stats,
        epochs=eps,
        composition=composition,
        attribution=attribution,
        prefix_term=prefix_term,
        accumulation_term=stats.sum_context - prefix_term,
        cost_usd=t.cost_usd,
        tool_result_tokens=sum(c.result_tokens for c in t.tool_calls),
        tool_input_tokens=sum(c.input_tokens for c in t.tool_calls),
        tool_calls_by_name=tool_calls_by_name,
    )


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:5.1f}%" if whole else "    - "


def render(r: Report) -> str:
    s = r.stats
    out: list[str] = []
    out.append(f"session {r.session_id}  ({r.path})")
    cost = f"${r.cost_usd:.2f}" if r.cost_usd is not None else "unknown"
    out.append(f"  cost {cost}   turns {s.turns}   epochs {len(r.epochs)}")
    out.append(f"  sum_context {s.sum_context:,}   mean {s.mean_context:,}   "
               f"median {s.median_context:,}   p90 {s.p90_context:,}   max {s.max_context:,}")
    out.append(f"  prefix_floor {s.prefix_floor:,}   growth {s.growth_per_turn:,.0f} tok/turn")
    out.append(f"  prefix term      {r.prefix_term:,} ({_pct(r.prefix_term, s.sum_context)})")
    out.append(f"  accumulation     {r.accumulation_term:,} "
               f"({_pct(r.accumulation_term, s.sum_context)})")
    out.append("")
    out.append(f"  {'component':40s} {'added':>12s} {'share':>7s} {'attributed':>14s}")
    total_added = sum(r.composition.values())
    for name, tokens in sorted(r.composition.items(), key=lambda kv: -kv[1]):
        out.append(f"  {name:40s} {tokens:12,} {_pct(tokens, total_added)} "
                   f"{r.attribution.get(name, 0):14,}")
    out.append("")
    out.append(f"  {'epoch':>5s} {'turns':>6s} {'floor':>10s} {'peak':>10s} "
               f"{'mean':>10s} {'g/turn':>9s}")
    for e in r.epochs:
        out.append(f"  {e.index:5d} {e.turns:6d} {e.floor:10,} {e.peak:10,} "
                   f"{e.mean:10,} {e.growth_per_turn:9,.0f}")
    return "\n".join(out)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_budget_attribution.py -v`
Expected: PASS, 6 passed.

- [ ] **Step 5: Commit**

```bash
git add audit_core/budget.py tests/test_budget_attribution.py
git commit -m "feat: exact residency attribution and economics report rendering"
```

---

### Task 5: `audit.py budget --report` and verification against the nine real sessions

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_budget.py`
- Create: `docs/baselines/README.md`

**Interfaces:**
- Consumes: `audit_core.budget.analyze`, `render`; `audit_core.transcript.parse`.
- Produces: CLI `audit.py budget --report <path>... [--json]`, exit 0 on success, exit 1 when no input file exists.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli_budget.py
import json, pathlib, subprocess, sys
from tests.fixtures import build as B

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *args],
                          capture_output=True, text=True)


def session(tmp_path) -> pathlib.Path:
    p = tmp_path / "s.jsonl"
    p.write_text(B.assistant([{"type": "text", "text": "a" * 400}], cache_read=50_000)
                 + B.assistant([], cache_read=70_000)
                 + B.cost_state(2.0))
    return p


def test_budget_report_prints_human_summary(tmp_path):
    r = run("budget", "--report", str(session(tmp_path)))
    assert r.returncode == 0, r.stderr
    assert "sum_context" in r.stdout
    assert "assistant_text" in r.stdout


def test_budget_report_json_is_machine_readable(tmp_path):
    r = run("budget", "--report", str(session(tmp_path)), "--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload[0]["stats"]["sum_context"] == 120_000
    assert payload[0]["cost_usd"] == 2.0


def test_missing_file_exits_one(tmp_path):
    r = run("budget", "--report", str(tmp_path / "nope.jsonl"))
    assert r.returncode == 1
    assert "not found" in (r.stdout + r.stderr).lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli_budget.py -v`
Expected: FAIL — `argparse` rejects the `budget` verb, exit code 2.

- [ ] **Step 3: Extend `audit.py`**

Add these imports and functions, and register the subparser:

```python
import dataclasses
import json

from audit_core import budget as budget_mod       # noqa: E402
from audit_core import transcript as transcript_mod  # noqa: E402


def cmd_budget(args: argparse.Namespace) -> int:
    reports = []
    for raw in args.report:
        path = pathlib.Path(raw).expanduser()
        if not path.is_file():
            print(f"not found: {path}", file=sys.stderr)
            return 1
        reports.append(budget_mod.analyze(transcript_mod.parse(path)))
    if args.json:
        print(json.dumps([dataclasses.asdict(r) for r in reports], indent=2))
    else:
        for r in reports:
            print(budget_mod.render(r))
            print()
    return 0
```

In `build_parser`, after the `selftest` line:

```python
    b = sub.add_parser("budget", help="economics report for session transcripts")
    b.add_argument("--report", nargs="+", required=True, metavar="JSONL")
    b.add_argument("--json", action="store_true")
```

In `main`, extend the dispatch table:

```python
    return {"selftest": cmd_selftest, "budget": cmd_budget}[args.verb](args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/ -v`
Expected: PASS, all tests green.

- [ ] **Step 5: Run against the nine real sessions and sanity-check tplink**

```bash
python3 audit.py budget --report ~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices*/*.jsonl
```

Expected for the tplink session (`d87d98a0-…`), within rounding:
- `sum_context` ≈ 521,900,000
- `turns` ≈ 1,894
- `epochs` = 7
- `prefix_floor` between 40,000 and 67,000
- `growth` between 900 and 1,500 tok/turn
- `prefix term` ≈ 19% of `sum_context`
- top composition rows in order: `thinking_block`, `tool_result`, `tool_use_input`, `attachment:total_tokens_reminder`
- `subagent_result` ≈ 32,700 — **if this reads in the millions, classification has regressed to substring matching; stop and fix Task 2.**

If any figure falls outside these ranges, do not proceed. Record the discrepancy and investigate before Task 6.

- [ ] **Step 6: Write the baselines README**

```markdown
# Baselines

Economics and recall baselines for the audit suite, recorded before any
Stage 1 change. Regenerate with:

    python3 audit.py budget --report <session.jsonl> --json
    python3 audit.py bench --golden tests/goldens/<target> --db <audit.db>

Each baseline file is dated and never edited in place; a new measurement
gets a new file so regressions stay visible in git history.
```

- [ ] **Step 7: Commit**

```bash
git add audit.py tests/test_cli_budget.py docs/baselines/README.md
git commit -m "feat: audit.py budget --report, verified against nine real sessions"
```

---

### Task 6: Golden reference format and the tplink golden

**Files:**
- Create: `audit_core/goldens.py`
- Create: `tests/test_goldens.py`
- Create: `tests/goldens/tplink-dl110v2-1.0.11/reference.json`
- Create: `tests/goldens/tplink-dl110v2-1.0.11/matches.json`
- Create: `tests/goldens/tplink-dl110v2-1.0.11/README.md`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `Reference(id: str, title: str, cwe: str | None, locations: tuple[str, ...], root_cause_key: str, severity: str)`
  - `load_reference(path: str | pathlib.Path) -> list[Reference]`
  - `load_matches(path: str | pathlib.Path) -> dict[str, str]`  (reference_id -> run_finding_id)
  - `GoldenError(Exception)`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_goldens.py
import json, pathlib, pytest
from audit_core import goldens

HERE = pathlib.Path(__file__).resolve().parent
TPLINK = HERE / "goldens" / "tplink-dl110v2-1.0.11"


def test_reference_entries_load(tmp_path):
    p = tmp_path / "reference.json"
    p.write_text(json.dumps([{
        "id": "REF-13", "title": "KLAP handshake0 overflow", "cwe": "CWE-787",
        "locations": ["sub_E0941B4", "0x0E0941B4"],
        "root_cause_key": "klap-handshake0-unbounded-copy", "severity": "CRITICAL",
    }]))
    refs = goldens.load_reference(p)
    assert refs[0].id == "REF-13"
    assert "sub_E0941B4" in refs[0].locations


def test_duplicate_reference_ids_rejected(tmp_path):
    p = tmp_path / "reference.json"
    p.write_text(json.dumps([
        {"id": "REF-1", "title": "a", "cwe": None, "locations": ["f"],
         "root_cause_key": "k1", "severity": "CRITICAL"},
        {"id": "REF-1", "title": "b", "cwe": None, "locations": ["g"],
         "root_cause_key": "k2", "severity": "HIGH"},
    ]))
    with pytest.raises(goldens.GoldenError):
        goldens.load_reference(p)


def test_reference_without_locations_rejected(tmp_path):
    p = tmp_path / "reference.json"
    p.write_text(json.dumps([{"id": "REF-1", "title": "a", "cwe": None,
                              "locations": [], "root_cause_key": "k",
                              "severity": "CRITICAL"}]))
    with pytest.raises(goldens.GoldenError):
        goldens.load_reference(p)


def test_matches_file_loads_as_mapping(tmp_path):
    p = tmp_path / "matches.json"
    p.write_text(json.dumps({"REF-13": "F-1"}))
    assert goldens.load_matches(p) == {"REF-13": "F-1"}


def test_missing_matches_file_is_empty_mapping(tmp_path):
    assert goldens.load_matches(tmp_path / "absent.json") == {}


def test_tplink_golden_has_nineteen_criticals():
    refs = goldens.load_reference(TPLINK / "reference.json")
    assert len([r for r in refs if r.severity == "CRITICAL"]) == 19
    assert len({r.id for r in refs}) == len(refs)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_goldens.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.goldens'`.

- [ ] **Step 3: Write the implementation**

```python
# audit_core/goldens.py
"""Golden reference sets and adjudicated match records."""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass


class GoldenError(Exception):
    """A golden file is malformed."""


@dataclass(frozen=True, slots=True)
class Reference:
    id: str
    title: str
    cwe: str | None
    locations: tuple[str, ...]
    root_cause_key: str
    severity: str


_REQUIRED = ("id", "title", "locations", "root_cause_key", "severity")


def load_reference(path: str | pathlib.Path) -> list[Reference]:
    path = pathlib.Path(path)
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldenError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise GoldenError(f"{path}: expected a list of reference objects")

    refs: list[Reference] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        for key in _REQUIRED:
            if key not in item:
                raise GoldenError(f"{path}[{i}]: missing '{key}'")
        if not item["locations"]:
            raise GoldenError(f"{path}[{i}]: 'locations' must be non-empty")
        if item["id"] in seen:
            raise GoldenError(f"{path}: duplicate reference id {item['id']}")
        seen.add(item["id"])
        refs.append(Reference(
            id=item["id"], title=item["title"], cwe=item.get("cwe"),
            locations=tuple(item["locations"]),
            root_cause_key=item["root_cause_key"], severity=item["severity"],
        ))
    return refs


def load_matches(path: str | pathlib.Path) -> dict[str, str]:
    path = pathlib.Path(path)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise GoldenError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise GoldenError(f"{path}: expected an object mapping reference id to finding id")
    return {str(k): str(v) for k, v in raw.items()}
```

- [ ] **Step 4: Build the tplink golden**

Source: `~/Documents/Offsec/Opswat/Devices/tplink/findings.txt` (the independent
report; 324 KB). Extract every entry rated CRITICAL — there are 19.

For each, write one object in `tests/goldens/tplink-dl110v2-1.0.11/reference.json`
using this exact schema. `locations` holds every function symbol, address, or
file path the entry cites; `root_cause_key` is a lowercase hyphenated phrase
naming the defect mechanism, chosen so that two reports describing the same bug
in different words produce the same key.

```json
[
  {
    "id": "REF-13",
    "title": "KLAP handshake0 unbounded copy into a fixed stack buffer",
    "cwe": "CWE-787",
    "locations": ["sub_E0941B4", "0x0E0941B4", "/app/handshake0"],
    "root_cause_key": "klap-handshake0-unbounded-copy",
    "severity": "CRITICAL"
  }
]
```

Read the file in slices to keep context small, for example
`grep -n '^## \|CRITICAL' findings.txt` to locate entries, then
`sed -n '<start>,<end>p' findings.txt` per entry.

Then seed `matches.json` with the eight correspondences the prior post-mortem
established, using the reference ids you assigned and the finding ids from
`~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db`
(`SELECT id, title FROM cba_findings;`):

| Reference | Our finding |
|---|---|
| AT+WREG via `exec_atcmd` | F-4 |
| `get_doorlock_records` strcpy | F-2 |
| `cmd_tip_message_handl` | F-15 |
| dispatcher missing authz | F-21 |
| KLAP handshake0 overflow | F-1 |
| `test@tp-link.net` / `test` credentials | F-19 |
| `sa_user_id` drives the deadbolt | F-10 |
| KLAP handshake1 auth bypass | F-35 |

```json
{
  "REF-13": "F-1"
}
```

Write `README.md` in the golden directory recording: firmware build
(`DL110V2_US_1.0.11_Build_260506_Rel.164323`), the source of the reference set,
the date, and the rule that `matches.json` is appended to only after a human
adjudicates a candidate.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_goldens.py -v`
Expected: PASS, 6 passed — including `test_tplink_golden_has_nineteen_criticals`.

- [ ] **Step 6: Commit**

```bash
git add audit_core/goldens.py tests/test_goldens.py tests/goldens/
git commit -m "feat: golden reference format and the tplink DL110 v2 golden set"
```

---

### Task 7: Recall scoring with adjudication

**Files:**
- Create: `audit_core/bench.py`
- Create: `tests/test_bench.py`

**Interfaces:**
- Consumes: `audit_core.goldens.Reference`, `load_reference`, `load_matches`.
- Produces:
  - `RunFinding(id: str, title: str, cwe: str | None, location: str, severity: str)`
  - `load_findings_from_db(db_path: str | pathlib.Path) -> list[RunFinding]`
  - `Candidate(reference_id: str, finding_id: str, reason: str)`
  - `BenchResult(recall: float, matched: tuple[tuple[str, str], ...], unmatched_references: tuple[str, ...], candidates: tuple[Candidate, ...], reference_count: int, finding_count: int, cost_per_match: float | None)`
  - `score(refs, findings, adjudicated: dict[str, str], cost_usd: float | None = None) -> BenchResult`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_bench.py
import sqlite3
from audit_core import bench, goldens

R1 = goldens.Reference("REF-1", "overflow in handshake", "CWE-787",
                       ("sub_E0941B4",), "klap-handshake0-unbounded-copy", "CRITICAL")
R2 = goldens.Reference("REF-2", "strcpy in records", "CWE-787",
                       ("get_doorlock_records",), "records-strcpy", "CRITICAL")

F1 = bench.RunFinding("F-1", "stack overflow", "CWE-787", "sub_E0941B4", "CRITICAL")
F9 = bench.RunFinding("F-9", "unrelated", "CWE-20", "sub_DEADBEEF", "LOW")


def test_adjudicated_match_counts_toward_recall():
    r = bench.score([R1, R2], [F1, F9], {"REF-1": "F-1"})
    assert r.matched == (("REF-1", "F-1"),)
    assert r.recall == 0.5
    assert r.unmatched_references == ("REF-2",)


def test_location_overlap_is_a_candidate_not_a_match():
    """Review Focus 5: never auto-count an unadjudicated overlap."""
    r = bench.score([R1, R2], [F1, F9], {})
    assert r.matched == ()
    assert r.recall == 0.0
    assert [c.finding_id for c in r.candidates] == ["F-1"]
    assert r.candidates[0].reference_id == "REF-1"


def test_adjudicated_pair_is_not_also_a_candidate():
    r = bench.score([R1], [F1], {"REF-1": "F-1"})
    assert r.candidates == ()


def test_adjudicated_match_to_absent_finding_does_not_count():
    r = bench.score([R1], [F9], {"REF-1": "F-404"})
    assert r.matched == ()
    assert r.recall == 0.0


def test_recall_is_zero_when_no_references():
    r = bench.score([], [F1], {})
    assert r.recall == 0.0
    assert r.reference_count == 0


def test_cost_per_match_is_none_without_cost():
    assert bench.score([R1], [F1], {"REF-1": "F-1"}).cost_per_match is None


def test_cost_per_match_divides_by_matches():
    r = bench.score([R1], [F1], {"REF-1": "F-1"}, cost_usd=50.0)
    assert r.cost_per_match == 50.0


def test_load_findings_from_cba_schema(tmp_path):
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE cba_findings (
        id TEXT PRIMARY KEY, group_id TEXT, title TEXT, severity TEXT,
        confidence INTEGER, cwe TEXT, location TEXT, root_cause TEXT,
        impact TEXT, attacker_position TEXT, boundary_crossed TEXT,
        data_flow TEXT, verified TEXT, poc TEXT, remediation TEXT,
        artifact_path TEXT, created_at TEXT)""")
    con.execute("INSERT INTO cba_findings (id, title, severity, cwe, location) "
                "VALUES ('F-1', 'overflow', 'CRITICAL', 'CWE-787', 'sub_E0941B4')")
    con.commit(); con.close()
    found = bench.load_findings_from_db(db)
    assert found == [bench.RunFinding("F-1", "overflow", "CWE-787",
                                      "sub_E0941B4", "CRITICAL")]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_bench.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.bench'`.

- [ ] **Step 3: Write the implementation**

```python
# audit_core/bench.py
"""Score an audit run against a golden reference set.

Only human-adjudicated pairs count toward recall. Location overlap produces a
candidate for adjudication, never a match: auto-matching on a shared symbol
inflates recall and would let a regression pass the gate.
"""
from __future__ import annotations

import pathlib
import sqlite3
from dataclasses import dataclass

from audit_core.goldens import Reference


@dataclass(frozen=True, slots=True)
class RunFinding:
    id: str
    title: str
    cwe: str | None
    location: str
    severity: str


@dataclass(frozen=True, slots=True)
class Candidate:
    reference_id: str
    finding_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class BenchResult:
    recall: float
    matched: tuple[tuple[str, str], ...]
    unmatched_references: tuple[str, ...]
    candidates: tuple[Candidate, ...]
    reference_count: int
    finding_count: int
    cost_per_match: float | None


def load_findings_from_db(db_path: str | pathlib.Path) -> list[RunFinding]:
    con = sqlite3.connect(f"file:{pathlib.Path(db_path)}?mode=ro", uri=True)
    try:
        rows = con.execute(
            "SELECT id, title, cwe, location, severity FROM cba_findings ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    return [RunFinding(r[0], r[1], r[2], r[3], r[4]) for r in rows]


def score(
    refs: list[Reference],
    findings: list[RunFinding],
    adjudicated: dict[str, str],
    cost_usd: float | None = None,
) -> BenchResult:
    by_id = {f.id: f for f in findings}

    matched: list[tuple[str, str]] = []
    for ref in refs:
        finding_id = adjudicated.get(ref.id)
        if finding_id and finding_id in by_id:
            matched.append((ref.id, finding_id))

    matched_refs = {r for r, _ in matched}
    matched_findings = {f for _, f in matched}

    candidates: list[Candidate] = []
    for ref in refs:
        if ref.id in matched_refs:
            continue
        for finding in findings:
            if finding.id in matched_findings:
                continue
            hit = next((loc for loc in ref.locations
                        if loc and loc.lower() in finding.location.lower()), None)
            if hit:
                candidates.append(Candidate(ref.id, finding.id, f"location overlap: {hit}"))

    recall = len(matched) / len(refs) if refs else 0.0
    cost_per_match = (cost_usd / len(matched)) if (cost_usd and matched) else None

    return BenchResult(
        recall=recall,
        matched=tuple(matched),
        unmatched_references=tuple(r.id for r in refs if r.id not in matched_refs),
        candidates=tuple(candidates),
        reference_count=len(refs),
        finding_count=len(findings),
        cost_per_match=cost_per_match,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_bench.py -v`
Expected: PASS, 8 passed.

- [ ] **Step 5: Commit**

```bash
git add audit_core/bench.py tests/test_bench.py
git commit -m "feat: recall scoring with adjudicated matches and overlap candidates"
```

---

### Task 8: `audit.py bench` and the recorded baseline

**Files:**
- Modify: `audit.py`
- Create: `tests/test_cli_bench.py`
- Create: `docs/baselines/2026-10-04-tplink-baseline.md`

**Interfaces:**
- Consumes: `audit_core.bench`, `audit_core.goldens`.
- Produces: CLI `audit.py bench --golden <dir> --db <audit.db> [--cost <usd>] [--json]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli_bench.py
import json, pathlib, sqlite3, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    return subprocess.run([sys.executable, str(ROOT / "audit.py"), *args],
                          capture_output=True, text=True)


def make_golden(tmp_path):
    g = tmp_path / "golden"
    g.mkdir()
    (g / "reference.json").write_text(json.dumps([{
        "id": "REF-1", "title": "overflow", "cwe": "CWE-787",
        "locations": ["sub_E0941B4"], "root_cause_key": "k", "severity": "CRITICAL"}]))
    (g / "matches.json").write_text(json.dumps({"REF-1": "F-1"}))
    return g


def make_db(tmp_path):
    db = tmp_path / "audit.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cba_findings (id TEXT PRIMARY KEY, title TEXT, "
                "severity TEXT, cwe TEXT, location TEXT)")
    con.execute("INSERT INTO cba_findings VALUES "
                "('F-1','overflow','CRITICAL','CWE-787','sub_E0941B4')")
    con.commit(); con.close()
    return db


def test_bench_reports_recall(tmp_path):
    r = run("bench", "--golden", str(make_golden(tmp_path)),
            "--db", str(make_db(tmp_path)))
    assert r.returncode == 0, r.stderr
    assert "recall" in r.stdout.lower()
    assert "1/1" in r.stdout or "100.0%" in r.stdout


def test_bench_json_output(tmp_path):
    r = run("bench", "--golden", str(make_golden(tmp_path)),
            "--db", str(make_db(tmp_path)), "--json")
    payload = json.loads(r.stdout)
    assert payload["recall"] == 1.0
    assert payload["matched"] == [["REF-1", "F-1"]]


def test_bench_missing_golden_exits_one(tmp_path):
    r = run("bench", "--golden", str(tmp_path / "nope"), "--db", str(make_db(tmp_path)))
    assert r.returncode == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli_bench.py -v`
Expected: FAIL — argparse rejects the `bench` verb, exit code 2.

- [ ] **Step 3: Extend `audit.py`**

`json` and `dataclasses` are already imported by Task 5; add only these two:

```python
from audit_core import bench as bench_mod      # noqa: E402
from audit_core import goldens as goldens_mod  # noqa: E402


def cmd_bench(args: argparse.Namespace) -> int:
    golden = pathlib.Path(args.golden).expanduser()
    db = pathlib.Path(args.db).expanduser()
    if not (golden / "reference.json").is_file():
        print(f"not found: {golden / 'reference.json'}", file=sys.stderr)
        return 1
    if not db.is_file():
        print(f"not found: {db}", file=sys.stderr)
        return 1

    refs = goldens_mod.load_reference(golden / "reference.json")
    adjudicated = goldens_mod.load_matches(golden / "matches.json")
    findings = bench_mod.load_findings_from_db(db)
    result = bench_mod.score(refs, findings, adjudicated, cost_usd=args.cost)

    if args.json:
        print(json.dumps(dataclasses.asdict(result), indent=2))
        return 0

    print(f"golden   {golden.name}")
    print(f"recall   {len(result.matched)}/{result.reference_count} "
          f"({100 * result.recall:.1f}%)")
    print(f"findings {result.finding_count}")
    if result.cost_per_match is not None:
        print(f"cost per matched finding  ${result.cost_per_match:.2f}")
    if result.unmatched_references:
        print("missed:     " + ", ".join(result.unmatched_references))
    if result.candidates:
        print("candidates needing adjudication:")
        for c in result.candidates:
            print(f"  {c.reference_id} ~ {c.finding_id}  ({c.reason})")
    return 0
```

Register the subparser in `build_parser`:

```python
    n = sub.add_parser("bench", help="score a run against a golden reference set")
    n.add_argument("--golden", required=True, metavar="DIR")
    n.add_argument("--db", required=True, metavar="AUDIT_DB")
    n.add_argument("--cost", type=float, default=None)
    n.add_argument("--json", action="store_true")
```

And extend the dispatch table in `main`:

```python
    return {"selftest": cmd_selftest, "budget": cmd_budget,
            "bench": cmd_bench}[args.verb](args)
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest tests/ -v`
Expected: PASS, all tests green.

- [ ] **Step 5: Produce the real baseline**

```bash
python3 audit.py bench \
  --golden tests/goldens/tplink-dl110v2-1.0.11 \
  --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db \
  --cost 347.68
```

Expected: `recall 8/19 (42.1%)`, 45 findings, cost per matched finding $43.46.

If recall is not 8, adjudicate the reported candidates by hand against
`findings.txt` and the audit database, append confirmed pairs to
`matches.json`, and re-run. Do not change `score()` to make the number move.

- [ ] **Step 6: Write the baseline record**

```markdown
# tplink DL110 v2 baseline — 2026-10-04

Recorded before any Stage 1 change. Regenerate with the commands below.

Target: `DL110V2_US_1.0.11_Build_260506_Rel.164323`
Session: `~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices-tplink/d87d98a0-….jsonl`
Audit DB: `Devices/tplink/reports/audit-20260928-073457/audit.db`

## Economics

| Metric | Value |
|---|---|
| Cost | $347.68 |
| Turns (billed) | 1,894 |
| Compaction epochs | 7 |
| Σ context | 521.9M |
| Mean context | 267.6k |
| Prefix floor | 40.9k – 66.0k |
| Growth rate | ~1,150 tok/turn |
| Prefix term | ~19% |
| Accumulation term | ~81% |

Largest accumulation components: thinking blocks 33.6%, tool results 23.2%,
tool-use inputs 12.9%.

## Recall

| Metric | Value |
|---|---|
| Reference CRITICALs | 19 |
| Matched (adjudicated) | 8 |
| Recall | 42.1% |
| Run findings | 45 |
| Cost per matched finding | $43.46 |

## Stage 4 gate

Recall ≥ 12/19 at ≤ $45 total, with the asus golden also passing.
```

Replace every figure above with the actual tool output. If a measured value
differs from this plan's expectation, the tool output is authoritative —
record it and note the discrepancy.

- [ ] **Step 7: Commit**

```bash
git add audit.py tests/test_cli_bench.py docs/baselines/2026-10-04-tplink-baseline.md
git commit -m "feat: audit.py bench and the recorded tplink baseline"
```

---

## Done when

- [ ] `python3 -m pytest tests/ -v` is green (44 tests across 8 files).
- [ ] `python3 audit.py selftest` exits 0.
- [ ] `python3 audit.py budget --report` runs over all nine real sessions and tplink reproduces the Task 5 ranges, with `subagent_result` near 32,700 rather than in the millions.
- [ ] `tests/goldens/tplink-dl110v2-1.0.11/reference.json` holds 19 CRITICAL references with unique ids.
- [ ] `python3 audit.py bench` reports 8/19 against the historical tplink audit.
- [ ] `docs/baselines/2026-10-04-tplink-baseline.md` records measured values, not the plan's expectations.
- [ ] Nothing under `SKILL.md`, `workflows/` or `references/` changed.
