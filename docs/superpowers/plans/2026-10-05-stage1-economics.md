# Stage 1: Economics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut orchestrator context cost on the five measured levers without changing what the audit looks for, and make the economics rules lint-checkable rather than aspirational.

**Architecture:** Four new `audit.py` verbs replace boilerplate the orchestrator currently retypes (`init`, `preflight`, `brief`), plus one that enforces the rules (`lint-skill`). The shipped skill's prose then adopts them: a model/effort tiering table replaces the blanket "strongest model" mandate, subagent prompt templates move out of the dispatch and into rendered brief files, and the templates gain a one-line return contract. The installer is fixed first, because the moment a workflow invokes `audit.py` every installed copy that lacks it breaks.

**Tech Stack:** Python 3.10+, stdlib only (`sqlite3`, `json`, `re`, `pathlib`, `argparse`). `pytest` for tests. Bash and PowerShell for the installers.

**Spec:** `docs/superpowers/specs/2026-10-04-audit-suite-design.md` — Stage 1 in §7, rules R2/R4/R5/R6 in §5, measured levers in §1.1 and §1.2.

## Global Constraints

- **No third-party runtime dependencies.** `audit_core` imports stdlib only. `pytest` is a dev dependency.
- **Python floor 3.10.** `requires-python = ">=3.10"`.
- **Do not change measurement behaviour.** `audit_core/transcript.py`, `audit_core/budget.py`, `audit_core/bench.py` and `audit_core/goldens.py` are Stage 0's verified output. No task here modifies them; `audit.py`'s existing `selftest`, `budget` and `bench` verbs keep their current behaviour and output.
- **Everything under `~/Documents/Offsec/Opswat/Devices/` and `~/.claude/projects/` is READ-ONLY.**
- **The shipped skill becomes editable in this stage** — the first stage to do so. `SKILL.md` must remain loadable with its YAML frontmatter intact, and the Phase Router table, the Cross-client tool mapping table and the Workflow Entry section must keep naming every phase that has a workflow file.
- **Measured baselines this stage is judged against** (from `docs/baselines/2026-10-05-tplink-baseline.md`): thinking 18.0% of attributed context, prefix 20.9%, tool-use input 9.8%, subagent results 1.4%. Dispatch prompts are 196,996 tokens over 117 dispatches, averaging 1,684.
- **No network access** in any module or test.
- **Add new commits; never amend.** Amending breaks the review tooling's descendant check.

## Review Focus

Five failure modes the spec implies that no task's happy path exercises. Each has a test assigned to the task that owns the code.

1. **A workflow names an `audit.py` verb that does not exist** — a typo in prose ships silently and fails only mid-audit. Owned by Task 8 (`lint-skill` resolves every `audit.py <verb>` mention against the real parser).
2. **`audit.py brief` renders a template with a placeholder left unsubstituted** — `{group_id}` reaching a subagent is worse than failing, because the agent will guess. Owned by Task 3 (render must exit non-zero and name the placeholder).
3. **`audit.py preflight` clobbers an existing project MCP config** — a user's `.mcp.json` is their configuration, not ours. Owned by Task 2 (refuse to overwrite without `--force`).
4. **An installed skill copy lacks `audit_core/`** — the live defect today, and silent: the skill loads, then dies at the first `audit.py` call. Owned by Task 4 (post-install `selftest` must fail the install loudly).
5. **`audit.py init` run twice against the same directory** — re-running a phase must not destroy findings already recorded. Owned by Task 1 (idempotent; existing rows survive).

---

### Task 1: `audit.py init` — audit workspace and schema

**Files:**
- Create: `audit_core/schema.sql`
- Create: `audit_core/workspace.py`
- Modify: `audit.py` (imports, `cmd_init`, subparser, dispatch entry)
- Test: `tests/test_workspace.py`

**Interfaces:**
- Consumes: nothing from other Stage 1 tasks.
- Produces:
  - `init_run(root: pathlib.Path, timestamp: str | None = None) -> pathlib.Path` — creates `reports/audit-<ts>/{files,artifacts,archived-poc,briefs}/`, applies `schema.sql` to `audit.db`, returns the run directory.
  - `apply_schema(db_path: pathlib.Path) -> list[str]` — applies the DDL, returns the table names present afterwards, sorted.
  - CLI `audit.py init [--root DIR] [--timestamp TS]`, printing the run directory path on stdout as its last line.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_workspace.py
import pathlib
import sqlite3
import subprocess
import sys

from audit_core import workspace

ROOT = pathlib.Path(__file__).resolve().parent.parent

EXPECTED_TABLES = [
    "cba_attack_surface", "cba_feature_groups", "cba_findings",
    "cba_fp_verdicts", "cba_known_findings", "cba_security_observations",
    "cba_sources",
]


def test_init_creates_directories_and_db(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    assert run == tmp_path / "reports" / "audit-20260105-120000"
    for sub in ("files", "artifacts", "archived-poc", "briefs"):
        assert (run / sub).is_dir()
    assert (run / "audit.db").is_file()


def test_schema_creates_every_cba_table(tmp_path):
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    tables = workspace.apply_schema(run / "audit.db")
    for name in EXPECTED_TABLES:
        assert name in tables


def test_init_is_idempotent_and_preserves_rows(tmp_path):
    """Review Focus 5: re-running a phase must not destroy recorded findings."""
    run = workspace.init_run(tmp_path, timestamp="20260105-120000")
    con = sqlite3.connect(run / "audit.db")
    con.execute(
        "INSERT INTO cba_findings (id, group_id, title, severity, confidence, "
        "location, root_cause, impact) VALUES "
        "('G1-F1','G1','t','HIGH',9,'f.c:1','rc','im')"
    )
    con.commit()
    con.close()

    again = workspace.init_run(tmp_path, timestamp="20260105-120000")
    assert again == run
    con = sqlite3.connect(run / "audit.db")
    assert con.execute("SELECT COUNT(*) FROM cba_findings").fetchone()[0] == 1
    con.close()


def test_timestamp_defaults_to_utc_now(tmp_path):
    run = workspace.init_run(tmp_path)
    assert run.name.startswith("audit-")
    assert len(run.name) == len("audit-20260105-120000")


def test_cli_init_prints_the_run_directory(tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "init",
         "--root", str(tmp_path), "--timestamp", "20260105-120000"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == str(
        tmp_path / "reports" / "audit-20260105-120000")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_workspace.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.workspace'`.

- [ ] **Step 3: Write the schema**

```sql
-- audit_core/schema.sql
-- Schema for a codebase-audit run. Applied by audit_core.workspace.apply_schema.
-- Every statement is IF NOT EXISTS: init is idempotent, and re-running a phase
-- must never destroy rows an earlier phase recorded.

CREATE TABLE IF NOT EXISTS cba_sources (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, source_path TEXT, source_language TEXT,
    source_file_count INTEGER, ida_binary TEXT, ida_port INTEGER, ida_arch TEXT,
    confirmed_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_feature_groups (
    id TEXT PRIMARY KEY, name TEXT, description TEXT, key_paths TEXT,
    status TEXT DEFAULT 'pending', created_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_attack_surface (
    id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, endpoint TEXT, method TEXT,
    auth_required TEXT, description TEXT);

CREATE TABLE IF NOT EXISTS cba_security_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT, observation TEXT,
    severity_hint TEXT, location TEXT);

CREATE TABLE IF NOT EXISTS cba_known_findings (
    id TEXT PRIMARY KEY, title TEXT, location TEXT, source TEXT,
    patched_in TEXT, severity TEXT, raw TEXT);

CREATE TABLE IF NOT EXISTS cba_findings (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    cwe TEXT,
    location TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    impact TEXT NOT NULL,
    attacker_position TEXT,
    boundary_crossed TEXT,
    data_flow TEXT,
    verified TEXT DEFAULT 'source-only',
    poc TEXT,
    remediation TEXT,
    artifact_path TEXT,
    created_at TEXT DEFAULT (datetime('now')));

CREATE TABLE IF NOT EXISTS cba_fp_verdicts (
    finding_id TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    reason TEXT,
    final_severity TEXT,
    final_id TEXT,
    merged_into TEXT,
    rule_applied TEXT,
    reviewed_at TEXT DEFAULT (datetime('now')));
```

- [ ] **Step 4: Write the module**

```python
# audit_core/workspace.py
"""Create a codebase-audit run directory and apply its schema.

This replaces the CREATE TABLE blocks that were spread across four workflow
files and retyped by the orchestrator on every run. See spec rule R5.
"""
from __future__ import annotations

import datetime
import pathlib
import sqlite3

SUBDIRS = ("files", "artifacts", "archived-poc", "briefs")
SCHEMA_PATH = pathlib.Path(__file__).resolve().parent / "schema.sql"


def apply_schema(db_path: str | pathlib.Path) -> list[str]:
    """Apply schema.sql to db_path. Idempotent. Returns the table names present."""
    con = sqlite3.connect(pathlib.Path(db_path))
    try:
        con.executescript(SCHEMA_PATH.read_text())
        con.commit()
        rows = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    finally:
        con.close()
    return [r[0] for r in rows]


def init_run(root: str | pathlib.Path,
             timestamp: str | None = None) -> pathlib.Path:
    """Create reports/audit-<ts>/ under root, with its subdirs and audit.db."""
    if timestamp is None:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d-%H%M%S")
    run = pathlib.Path(root) / "reports" / f"audit-{timestamp}"
    for sub in SUBDIRS:
        (run / sub).mkdir(parents=True, exist_ok=True)
    apply_schema(run / "audit.db")
    return run
```

- [ ] **Step 5: Wire the CLI**

Add to `audit.py` alongside the existing imports:

```python
from audit_core import workspace as workspace_mod  # noqa: E402


def cmd_init(args: argparse.Namespace) -> int:
    run = workspace_mod.init_run(args.root, timestamp=args.timestamp)
    print(f"tables: {', '.join(workspace_mod.apply_schema(run / 'audit.db'))}")
    print(run)
    return 0
```

In `build_parser`, after the existing subparsers:

```python
    i = sub.add_parser("init", help="create an audit run directory and its schema")
    i.add_argument("--root", default=".", metavar="DIR")
    i.add_argument("--timestamp", default=None, metavar="TS")
```

In `main`, extend the dispatch dict — **both sites must change together**:

```python
    return {"selftest": cmd_selftest, "budget": cmd_budget,
            "bench": cmd_bench, "init": cmd_init}[args.verb](args)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_workspace.py -v`
Expected: PASS, 5 passed.

- [ ] **Step 7: Run the full suite**

Run: `python3 -m pytest tests/ -q`
Expected: 62 passed (57 pre-existing + 5 new).

- [ ] **Step 8: Commit**

```bash
git add audit_core/schema.sql audit_core/workspace.py audit.py tests/test_workspace.py
git commit -m "feat: audit.py init creates the run workspace and applies the schema"
```

---

### Task 2: `audit.py preflight` — scoped MCP config

**Files:**
- Create: `audit_core/preflight.py`
- Modify: `audit.py` (import, `cmd_preflight`, subparser, dispatch entry)
- Test: `tests/test_preflight.py`

**Interfaces:**
- Consumes: nothing from other Stage 1 tasks.
- Produces:
  - `MCP_CONFIG_NAME = ".audit-mcp.json"`
  - `write_config(path, servers: dict[str, dict], force: bool = False) -> None` — raises `FileExistsError` if `path` exists and `force` is false.
  - `launch_command(config_path: pathlib.Path) -> str`
  - CLI `audit.py preflight [--out PATH] [--server NAME=COMMAND ...] [--force]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_preflight.py
import json
import pathlib
import subprocess
import sys

import pytest

from audit_core import preflight

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_write_config_emits_mcpServers_shape(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    preflight.write_config(out, {"autorev": {"command": "autorev-mcp"}})
    payload = json.loads(out.read_text())
    assert payload == {"mcpServers": {"autorev": {"command": "autorev-mcp"}}}


def test_write_config_refuses_to_clobber(tmp_path):
    """Review Focus 3: a user's MCP config is theirs, not ours."""
    out = tmp_path / ".audit-mcp.json"
    out.write_text('{"mcpServers": {"theirs": {}}}')
    with pytest.raises(FileExistsError):
        preflight.write_config(out, {"autorev": {"command": "x"}})
    assert json.loads(out.read_text())["mcpServers"] == {"theirs": {}}


def test_write_config_force_overwrites(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    out.write_text('{"mcpServers": {"theirs": {}}}')
    preflight.write_config(out, {"autorev": {"command": "x"}}, force=True)
    assert "autorev" in json.loads(out.read_text())["mcpServers"]


def test_launch_command_names_both_flags(tmp_path):
    cmd = preflight.launch_command(tmp_path / ".audit-mcp.json")
    assert "--strict-mcp-config" in cmd
    assert "--mcp-config" in cmd


def test_cli_preflight_writes_and_prints(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(out), "--server", "autorev=autorev-mcp"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "--strict-mcp-config" in r.stdout
    assert json.loads(out.read_text())["mcpServers"]["autorev"]["command"] == "autorev-mcp"


def test_cli_preflight_exits_one_on_existing_file(tmp_path):
    out = tmp_path / ".audit-mcp.json"
    out.write_text("{}")
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(out), "--server", "autorev=autorev-mcp"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "exists" in (r.stdout + r.stderr).lower()


def test_cli_preflight_rejects_malformed_server_spec(tmp_path):
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "preflight",
         "--out", str(tmp_path / "c.json"), "--server", "noequalssign"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "NAME=COMMAND" in (r.stdout + r.stderr)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_preflight.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.preflight'`.

- [ ] **Step 3: Write the module**

```python
# audit_core/preflight.py
"""Write a project-scoped MCP config naming only the servers a run needs.

Unused MCP tool schemas sit in the resident prefix, which is 20.9% of
measured context cost, and deferred-tool records are charged again in
accumulation. See spec rule R4.
"""
from __future__ import annotations

import json
import pathlib

MCP_CONFIG_NAME = ".audit-mcp.json"


def write_config(path: str | pathlib.Path,
                 servers: dict[str, dict],
                 force: bool = False) -> None:
    path = pathlib.Path(path)
    if path.exists() and not force:
        raise FileExistsError(
            f"{path} exists; refusing to overwrite an MCP config we did not write "
            f"(pass --force to replace it)")
    path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")


def launch_command(config_path: str | pathlib.Path) -> str:
    return f"claude --strict-mcp-config --mcp-config {pathlib.Path(config_path)}"
```

- [ ] **Step 4: Wire the CLI**

```python
from audit_core import preflight as preflight_mod  # noqa: E402


def cmd_preflight(args: argparse.Namespace) -> int:
    servers: dict[str, dict] = {}
    for spec in args.server:
        name, sep, command = spec.partition("=")
        if not sep or not name or not command:
            print(f"bad --server {spec!r}; expected NAME=COMMAND", file=sys.stderr)
            return 1
        servers[name] = {"command": command}
    out = pathlib.Path(args.out).expanduser()
    try:
        preflight_mod.write_config(out, servers, force=args.force)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"wrote {out} with {len(servers)} server(s): {', '.join(sorted(servers)) or '(none)'}")
    print("relaunch with:")
    print(f"  {preflight_mod.launch_command(out)}")
    return 0
```

In `build_parser`:

```python
    pf = sub.add_parser("preflight", help="write a project-scoped MCP config")
    pf.add_argument("--out", default=preflight_mod.MCP_CONFIG_NAME, metavar="PATH")
    pf.add_argument("--server", action="append", default=[], metavar="NAME=COMMAND")
    pf.add_argument("--force", action="store_true")
```

In `main`, add `"preflight": cmd_preflight` to the dispatch dict.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_preflight.py -v`
Expected: PASS, 7 passed.

- [ ] **Step 6: Commit**

```bash
git add audit_core/preflight.py audit.py tests/test_preflight.py
git commit -m "feat: audit.py preflight writes a scoped MCP config"
```

---

### Task 3: `audit.py brief` — render a dispatch brief from a template

**Files:**
- Create: `audit_core/briefs.py`
- Modify: `audit.py` (import, `cmd_brief`, subparser, dispatch entry)
- Test: `tests/test_briefs.py`

**Interfaces:**
- Consumes: nothing from other Stage 1 tasks. Task 6 creates the templates this renders; Task 7 calls the CLI.
- Produces:
  - `BriefError(Exception)`
  - `TEMPLATE_DIR` — `references/briefs/` resolved relative to the repository root.
  - `render(template_text: str, variables: dict[str, str]) -> str` — substitutes `{name}` placeholders, raises `BriefError` naming every placeholder left unfilled.
  - `write_brief(phase: str, unit: str, run_dir, variables) -> pathlib.Path` — renders `TEMPLATE_DIR/<phase>-brief.md` to `<run_dir>/briefs/<phase>-<unit>-brief.md`, returns the path.
  - CLI `audit.py brief --phase P --unit U --run DIR [--var k=v ...]`, printing the brief path as its last line.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_briefs.py
import pathlib
import subprocess
import sys

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_render_substitutes_placeholders():
    out = briefs.render("group {group_id} covers {scope}",
                        {"group_id": "G7", "scope": "nvram"})
    assert out == "group G7 covers nvram"


def test_render_rejects_unsubstituted_placeholder():
    """Review Focus 2: an unfilled {placeholder} reaching an agent is worse
    than failing, because the agent will guess at it."""
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("group {group_id} covers {scope}", {"group_id": "G7"})
    assert "scope" in str(exc.value)


def test_render_leaves_unrelated_braces_alone():
    out = briefs.render("use {group_id} and shell ${HOME} and json {}",
                        {"group_id": "G7"})
    assert "${HOME}" in out and "{}" in out


def test_render_reports_every_missing_placeholder_at_once():
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("{a} {b} {c}", {"b": "x"})
    message = str(exc.value)
    assert "a" in message and "c" in message


def test_write_brief_creates_the_file(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    path = briefs.write_brief("audit", "G7", run, {"group_id": "G7"},
                              template_dir=tpl_dir)
    assert path == run / "briefs" / "audit-G7-brief.md"
    assert path.read_text() == "audit G7"


def test_write_brief_unknown_phase_raises(tmp_path):
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    with pytest.raises(briefs.BriefError) as exc:
        briefs.write_brief("nosuchphase", "G7", run, {}, template_dir=tmp_path)
    assert "nosuchphase" in str(exc.value)


def test_cli_brief_prints_path(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "audit",
         "--unit", "G7", "--run", str(run), "--var", "group_id=G7",
         "--template-dir", str(tpl_dir)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == str(
        run / "briefs" / "audit-G7-brief.md")


def test_cli_brief_exits_one_on_missing_variable(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id} {scope}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "audit",
         "--unit", "G7", "--run", str(run), "--var", "group_id=G7",
         "--template-dir", str(tpl_dir)],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "scope" in (r.stdout + r.stderr)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_briefs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.briefs'`.

- [ ] **Step 3: Write the module**

```python
# audit_core/briefs.py
"""Render a subagent dispatch brief from a template.

Dispatch prompts are the largest single category of tool-call input - 196,996
tokens over 117 dispatches in the measured sessions, averaging 1,684 each -
and most of each one is boilerplate the orchestrator retyped. Rendering from a
template on disk means the dispatch carries a path, not the template. See
spec rule R6.
"""
from __future__ import annotations

import pathlib
import re

TEMPLATE_DIR = pathlib.Path(__file__).resolve().parent.parent / "references" / "briefs"

# A placeholder is {name} where name is an identifier. This deliberately does
# not match ${HOME}, {} or {"json": ...}.
_PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


class BriefError(Exception):
    """A brief template is missing, or a placeholder was left unfilled."""


def render(template_text: str, variables: dict[str, str]) -> str:
    missing: list[str] = []

    def replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in variables:
            missing.append(name)
            return match.group(0)
        return str(variables[name])

    out = _PLACEHOLDER.sub(replace, template_text)
    if missing:
        raise BriefError(
            "unsubstituted placeholder(s): " + ", ".join(sorted(set(missing))))
    return out


def write_brief(phase: str,
                unit: str,
                run_dir: str | pathlib.Path,
                variables: dict[str, str],
                template_dir: str | pathlib.Path | None = None) -> pathlib.Path:
    tpl_dir = pathlib.Path(template_dir) if template_dir else TEMPLATE_DIR
    template = tpl_dir / f"{phase}-brief.md"
    if not template.is_file():
        raise BriefError(f"no brief template for phase {phase!r} at {template}")
    out_dir = pathlib.Path(run_dir) / "briefs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{phase}-{unit}-brief.md"
    out.write_text(render(template.read_text(), variables))
    return out
```

- [ ] **Step 4: Wire the CLI**

```python
from audit_core import briefs as briefs_mod  # noqa: E402


def cmd_brief(args: argparse.Namespace) -> int:
    variables: dict[str, str] = {}
    for spec in args.var:
        name, sep, value = spec.partition("=")
        if not sep or not name:
            print(f"bad --var {spec!r}; expected NAME=VALUE", file=sys.stderr)
            return 1
        variables[name] = value
    try:
        path = briefs_mod.write_brief(args.phase, args.unit, args.run, variables,
                                      template_dir=args.template_dir)
    except briefs_mod.BriefError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(path)
    return 0
```

In `build_parser`:

```python
    br = sub.add_parser("brief", help="render a subagent dispatch brief")
    br.add_argument("--phase", required=True)
    br.add_argument("--unit", required=True)
    br.add_argument("--run", required=True, metavar="RUN_DIR")
    br.add_argument("--var", action="append", default=[], metavar="NAME=VALUE")
    br.add_argument("--template-dir", default=None, metavar="DIR")
```

In `main`, add `"brief": cmd_brief` to the dispatch dict.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_briefs.py -v`
Expected: PASS, 8 passed.

- [ ] **Step 6: Commit**

```bash
git add audit_core/briefs.py audit.py tests/test_briefs.py
git commit -m "feat: audit.py brief renders a dispatch brief from a template"
```

---

### Task 4: Fix the installers so an installed skill carries `audit.py`

**Files:**
- Modify: `install.sh` (`install_skill_files`, and the per-client install functions' completion message)
- Modify: `install.ps1` (the copy function)
- Test: `tests/test_install.py`

**Interfaces:**
- Consumes: `audit.py selftest` from Stage 0.
- Produces: an installed tree containing `SKILL.md`, `workflows/`, `references/`, `audit_core/`, `audit.py`, verified by `selftest`.

This task must land **before** Tasks 7 and 8, which make the workflows invoke `audit.py`. Until it does, every installed copy of the skill is one `audit.py` call away from breaking.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_install.py
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_sh_copies_the_tool_and_selftest_passes(tmp_path):
    """Review Focus 4: an installed copy without audit_core/ loads fine and
    then dies at the first audit.py call. The install must fail loudly."""
    home = tmp_path / "home"
    home.mkdir()
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "claude"],
        capture_output=True, text=True,
        env={"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/local/bin",
             "CLAUDE_CONFIG_DIR": str(home / ".claude")},
        cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    target = home / ".claude" / "skills" / "codebase-audit"
    assert (target / "SKILL.md").is_file()
    assert (target / "workflows").is_dir()
    assert (target / "references").is_dir()
    assert (target / "audit.py").is_file()
    assert (target / "audit_core" / "__init__.py").is_file()
    assert (target / "audit_core" / "schema.sql").is_file()

    s = subprocess.run([sys.executable, str(target / "audit.py"), "selftest"],
                       capture_output=True, text=True)
    assert s.returncode == 0, s.stderr
    assert "audit_core" in s.stdout
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_install.py -v`
Expected: FAIL — the assertion on `audit.py` being present, because `install_skill_files` copies only `SKILL.md`, `workflows/*.md` and `references/*.md`.

- [ ] **Step 3: Fix `install.sh`**

Replace the body of `install_skill_files` with:

```bash
install_skill_files() {
  local target="$1"
  mkdir -p "${target}"
  local abs_target
  abs_target="$(cd "${target}" && pwd -P)"
  if [[ "${SCRIPT_DIR}" == "${abs_target}" ]]; then
    echo "  (source dir IS install dir; skipping skill file copy)"
    return
  fi
  echo "  Copying skill content -> ${target}"
  cp -f "${SCRIPT_DIR}/SKILL.md" "${target}/SKILL.md"
  cp -f "${SCRIPT_DIR}/audit.py" "${target}/audit.py"
  for sub in workflows references; do
    if [[ -d "${SCRIPT_DIR}/${sub}" ]]; then
      mkdir -p "${target}/${sub}"
      cp -Rf "${SCRIPT_DIR}/${sub}/." "${target}/${sub}/"
    fi
  done
  # audit_core carries .py and .sql; copy the package wholesale minus caches.
  rm -rf "${target}/audit_core"
  mkdir -p "${target}/audit_core"
  cp -Rf "${SCRIPT_DIR}/audit_core/." "${target}/audit_core/"
  find "${target}/audit_core" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

  # The install is not complete until the tool runs from where it landed.
  if ! python3 "${target}/audit.py" selftest >/dev/null 2>&1; then
    echo "ERROR: audit.py selftest failed in ${target} — the install is incomplete." >&2
    exit 1
  fi
  echo "  selftest OK"
}
```

- [ ] **Step 4: Fix `install.ps1`**

In the copy function, after the `SKILL.md` copy, add the same three pieces:

```powershell
    Copy-Item -Force (Join-Path $ScriptDir 'audit.py') (Join-Path $Target 'audit.py')
    $coreSrc = Join-Path $ScriptDir 'audit_core'
    $coreDst = Join-Path $Target 'audit_core'
    if (Test-Path $coreDst) { Remove-Item -Recurse -Force $coreDst }
    New-Item -ItemType Directory -Path $coreDst | Out-Null
    Copy-Item -Recurse -Force (Join-Path $coreSrc '*') $coreDst
    Get-ChildItem -Path $coreDst -Recurse -Directory -Filter '__pycache__' |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    & python3 (Join-Path $Target 'audit.py') selftest | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "audit.py selftest failed in $Target - the install is incomplete."
        exit 1
    }
```

Also change the `foreach ($sub in @('workflows', 'references'))` body's `Copy-Item -Force (Join-Path $srcSub '*.md') $dstSub` to `Copy-Item -Recurse -Force (Join-Path $srcSub '*') $dstSub`, so `references/briefs/` is carried.

- [ ] **Step 5: Install to both Codex skill directories**

§3.2 names a second defect: this installer writes `~/.agents/skills/`, while
`grey-audit`'s writes `$CODEX_HOME/skills/`. Both directories exist on real
machines and it is not knowable from here which one a given Codex build reads.
In `install.sh`, change `CODEX_SKILL_DIR` to install to both:

```bash
CODEX_SKILL_DIRS=(
  "${HOME}/.agents/skills/${SKILL_NAME}"
  "${CODEX_HOME:-${HOME}/.codex}/skills/${SKILL_NAME}"
)
```

and in `install_codex`, loop `install_skill_files` over `"${CODEX_SKILL_DIRS[@]}"`
instead of the single path. Make the same change in `install.ps1`, using
`$env:CODEX_HOME` with `$HOME\.codex` as the fallback.

Add this assertion to the test:

```python
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_sh_covers_both_codex_directories(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    r = subprocess.run(
        ["bash", str(ROOT / "install.sh"), "codex"],
        capture_output=True, text=True,
        env={"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/local/bin"},
        cwd=str(ROOT),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    for d in (home / ".agents" / "skills", home / ".codex" / "skills"):
        assert (d / "codebase-audit" / "audit.py").is_file(), f"missing under {d}"
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_install.py -v`
Expected: PASS, 2 passed.

- [ ] **Step 7: Run the full suite**

Run: `python3 -m pytest tests/ -q`
Expected: 79 passed.

- [ ] **Step 8: Commit**

```bash
git add install.sh install.ps1 tests/test_install.py
git commit -m "fix: installers copy audit.py and audit_core, install to both Codex dirs, and verify with selftest"
```

---

### Task 5: `SKILL.md` — model tiering and the economics rules

**Files:**
- Modify: `SKILL.md:88` (the "strongest model" rule), `SKILL.md:170-177` (Subagent Configuration table), plus a new "Economics Contract" section after *Essential Principles*.

**Interfaces:**
- Consumes: the verb names from Tasks 1-3 (`init`, `preflight`, `brief`).
- Produces: the tiering table and rule text that Task 7's workflows and Task 8's lint both read.

- [ ] **Step 1: Replace the blanket model mandate**

`SKILL.md:88` currently reads:

> **Two rules hold on every client:** (1) any subagent that writes artifacts, runs SQL inserts, or hits the live instance MUST be a **writable** agent — a read-only agent silently produces nothing; (2) use the **strongest model your client offers** (e.g. the latest Claude Opus on Claude/Copilot; the default high-capability model on Codex).

Replace clause (2) with:

> (2) choose the model and reasoning effort from the *Model and effort tiering* table below — not the strongest available for everything. Retained thinking is 18.0% of measured context cost, and lower tiers emit far less of it.

- [ ] **Step 2: Add the Economics Contract section**

Insert after the *Essential Principles* list, before *Sub-Command Router*:

```markdown
## Economics Contract

Measured across nine real audits: 449.9M context tokens re-read for $2,053.64.
Cost follows `Σ over turns of context(turn)`, so **a token admitted to the
orchestrator's context at turn N is paid for on every remaining turn**. The
orchestrator's context is a budget, not a buffer.

### Model and effort tiering

| Work | Model | Reasoning effort |
|---|---|---|
| Workspace setup, CVE ingest, pattern sweeps, SQL bookkeeping | script or cheapest tier | low |
| Feature mapping, FP-check batches, report drafting | mid tier | low to medium |
| Deep audit, chain reasoning, final severity calls, adversarial review | strongest tier | high |

Reasoning effort is tiered with the model: retained thinking is the largest
single component of accumulated context, so only the strongest-tier work runs
at high effort.

### R2 — Return contracts

A subagent writes its work to SQL and an artifact, then returns **one line**:

    <unit_id> <DONE|PARTIAL|FAILED> rows=<n> artifact=<relpath> [flags=<csv>]

The orchestrator never acts on the return text. Its next action is an
`audit.py` verb or a bounded SQL query. Prose returned anyway is dead weight
for one turn instead of permanently resident.

### R4 — MCP preflight

Before a run, write a project-scoped MCP config naming only what the run
needs, and relaunch against it:

    python3 __SKILL_DIR__/audit.py preflight --server autorev=<command>
    claude --strict-mcp-config --mcp-config .audit-mcp.json

Unused MCP tool schemas sit in the resident prefix (20.9% of cost) and are
charged again in accumulation as deferred-tool records.

### R5 — Reusable logic is an `audit.py` verb, never an inline heredoc

Workspace creation and schema are `audit.py init`. MCP config is
`audit.py preflight`. Dispatch briefs are `audit.py brief`. A target-specific
script longer than ~10 lines is written once into the run's `files/`
directory and invoked by path thereafter — never retyped.

### R6 — Dispatch briefs are files

A subagent's task is rendered to a file with `audit.py brief`; the dispatch
carries the path plus only what the brief cannot know (where the task fits,
interfaces from earlier phases, the report-file path). Never paste prior
phases' summaries into a dispatch.
```

- [ ] **Step 3: Update the Subagent Configuration table**

Replace the `Model` column values in the table at `SKILL.md:170-177`:

| Phase | Model column becomes |
|---|---|
| recon (mapping) | `mid tier, low effort` |
| audit | `strongest tier, high effort` |
| fpcheck | `mid tier, medium effort` |
| verify (review) | `strongest tier, high effort` |

- [ ] **Step 4: Add the rejection-table rows**

Append to the *Rationalizations to Reject* table:

```markdown
| "Use the strongest model everywhere, it's safer" | Retained thinking is 18.0% of context cost. Tier per the *Model and effort tiering* table; only strongest-tier work runs at high effort. |
| "I'll paste the task into the dispatch, it's quicker" | Dispatch prompts are the largest single category of tool-call input (1,684 tokens average). Render the brief with `audit.py brief` and send the path. |
| "I'll just write the SQL inline, it's only a few tables" | `audit.py init` applies the whole schema. Inline DDL is retyped after every compaction. |
| "The MCP servers are already connected, leave them" | Unused schemas are resident on every turn. Run `audit.py preflight` and relaunch strict. |
```

- [ ] **Step 5: Verify the skill still parses and routes**

Run:

```bash
python3 - <<'PY'
import pathlib, re
s = pathlib.Path("SKILL.md").read_text()
assert s.startswith("---\n"), "frontmatter missing"
assert re.search(r"^name:\s*codebase-audit\s*$", s, re.M), "name field missing"
for phase in ("recon", "deploy", "audit", "fpcheck", "verify", "report", "source"):
    assert f"workflows/{phase}.md" in s, f"router lost {phase}"
print("SKILL.md OK")
PY
```

Expected: `SKILL.md OK`.

- [ ] **Step 6: Commit**

```bash
git add SKILL.md
git commit -m "feat: model and effort tiering plus the economics contract in SKILL.md"
```

---

### Task 6: Brief templates with return contracts

**Files:**
- Create: `references/briefs/recon-brief.md`, `references/briefs/audit-brief.md`, `references/briefs/fpcheck-brief.md`
- Modify: `references/phase2-feature-mapping.md` (replace the inline *Subagent Prompt Template* with a pointer), `references/phase4-deep-audit.md` (same), `references/phase5-fp-check.md` (same)
- Test: `tests/test_brief_templates.py`

**Interfaces:**
- Consumes: `audit_core.briefs.render`, `BriefError`, `TEMPLATE_DIR` from Task 3.
- Produces: the three templates Task 7's workflows render and Task 8's lint checks.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_brief_templates.py
import pathlib
import re

import pytest

from audit_core import briefs

TEMPLATES = sorted(briefs.TEMPLATE_DIR.glob("*-brief.md"))
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")

RETURN_CONTRACT = "rows=<n> artifact="


def test_three_templates_exist():
    names = {p.name for p in TEMPLATES}
    assert names == {"recon-brief.md", "audit-brief.md", "fpcheck-brief.md"}


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_every_template_states_the_return_contract(path):
    assert RETURN_CONTRACT in path.read_text(), (
        f"{path.name} must carry the R2 one-line return contract")


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_every_template_renders_with_its_declared_variables(path):
    text = path.read_text()
    names = sorted(set(PLACEHOLDER.findall(text)))
    filled = {n: f"<{n}>" for n in names}
    out = briefs.render(text, filled)
    assert not PLACEHOLDER.search(out)


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_no_template_tells_the_agent_to_return_findings_inline(path):
    text = path.read_text().lower()
    for banned in ("return findings as a markdown list",
                   "return a structured markdown document"):
        assert banned not in text, f"{path.name} still asks for an inline dump"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_brief_templates.py -v`
Expected: FAIL — `test_three_templates_exist` fails because `references/briefs/` does not exist.

- [ ] **Step 3: Write `references/briefs/audit-brief.md`**

```markdown
# Deep audit brief — {group_id}

You are a senior security researcher auditing one feature group for real,
exploitable vulnerabilities. No theoretical concerns.

## Assignment

Feature group: {group_id} — {group_name}
Audit run directory: {run_dir}
Mapping to work from: {mapping_path}

## Source access

{source_access}

## Known findings — do NOT re-discover these

{known_findings}

## What to hunt

Priority order by typical severity. For each, trace a complete path from
attacker-controlled input to the sink, and state which mitigations you checked
and found absent.

1. Injection — SQL, command, LDAP, XPath, template
2. Authentication bypass — session fixation, token forgery, missing checks
3. SSRF, including scheme and IP-validation bypasses
4. Path traversal — read or write outside the intended root
5. Insecure deserialization of untrusted data
6. Any path from input to code execution
7. Authorization bypass — horizontal and vertical
8. Cryptographic defects, weak randomness, key exposure
9. Race conditions — TOCTOU, check-then-act without a lock
10. Resource exhaustion with an amplification factor

## Rules of engagement

1. Read the actual code. Every claim cites file, function and line.
2. If you cannot trace the data flow, do not report it.
3. Check for existing mitigations before reporting.
4. Do not report a library vulnerability unless this application triggers the
   vulnerable path.
5. Apply the Marginal Gain Test: if the attacker's starting position already
   grants the claimed impact, it is not a finding.
6. Confidence must be at least 8 of 10.

## Where your output goes

Write every finding as a row in `cba_findings` in `{run_dir}/audit.db`, and
the detailed write-up to `{artifact_path}`. The finding schema is in
`references/phase4-deep-audit.md` under *Finding Schema*.

## What you return

Return exactly one line, and nothing else:

    {group_id} <DONE|PARTIAL|FAILED> rows=<n> artifact={artifact_path} [flags=<csv>]

Your prose does not reach the orchestrator's reasoning — it reads your rows
from SQL. A finding that is not in the database did not happen.
```

- [ ] **Step 4: Write `references/briefs/recon-brief.md`**

```markdown
# Feature mapping brief — {group_id}

You are mapping features to code for a security audit. Map thoroughly; do not
investigate vulnerabilities deeply — note them and move on.

## Assignment

Feature group: {group_id} — {group_name}
Description: {group_description}
Key directories: {key_directories}
Audit run directory: {run_dir}

## Source access

{source_access}

## What to map, per feature

1. Feature name and what it does
2. Entry points — endpoints, CLI commands, event handlers, scheduled tasks
3. Key source files that implement it
4. Authentication requirement — none, user, admin, internal-only
5. Input sources — headers, query, body, uploads, environment, database
6. Data flow from input through processing to sink
7. Trust boundaries crossed — privilege, network, or process
8. Security-relevant observations, noted not investigated

Read every file in the assigned directories. Do not skip a file because it
looks uninteresting; follow imports to understand dependencies.

## Known prior art

{known_findings}

## Where your output goes

Write the full mapping to `{mapping_path}`. Insert one row per entry point
into `cba_attack_surface`, and one row per observation into
`cba_security_observations`, in `{run_dir}/audit.db`.

## What you return

Return exactly one line, and nothing else:

    {group_id} <DONE|PARTIAL|FAILED> rows=<n> artifact={mapping_path} [flags=<csv>]
```

- [ ] **Step 5: Write `references/briefs/fpcheck-brief.md`**

```markdown
# False-positive check brief — batch {batch_id}

You are a False Positive Verifier. You are adversarial: you WANT to find false
positives. This review is **static only** — do not use a live instance.

## Assignment

Batch: {batch_id}
Findings to verify: {finding_ids}
Audit run directory: {run_dir}

## Source access

{source_access}

## Method, in order

1. Restate each finding's claim precisely.
2. Apply the attacker-advantage test FIRST: if the attacker's position already
   grants the claimed impact, the finding fails.
3. Apply all 18 Hard Exclusions and 10 Precedent rules from
   `references/phase5-fp-check.md`.
4. Apply Capability Validity checks CV-1 to CV-3.
5. Re-read every cited file. The cited code must exist and match the claim.
6. Check for mitigations the original analyst may have missed.
7. Issue a verdict: TRUE_POSITIVE, FALSE_POSITIVE or DUPLICATE.

## Where your output goes

Write one row per finding into `cba_fp_verdicts` in `{run_dir}/audit.db`, and
the reasoning to `{artifact_path}`.

## What you return

Return exactly one line, and nothing else:

    {batch_id} <DONE|PARTIAL|FAILED> rows=<n> artifact={artifact_path} [flags=<csv>]
```

- [ ] **Step 6: Replace the inline templates with pointers**

In `references/phase4-deep-audit.md`, replace the whole `## Subagent Prompt Template` section (the fenced block and its heading) with:

```markdown
## Subagent Brief

The dispatch brief is a template at `references/briefs/audit-brief.md`,
rendered per group by `audit.py brief`. Do not paste its contents into a
dispatch — render it and send the path (spec rule R6):

    python3 __SKILL_DIR__/audit.py brief --phase audit --unit G7 --run "$AUDIT_DIR" \
      --var group_id=G7 --var group_name='...' --var run_dir="$AUDIT_DIR" \
      --var mapping_path="$AUDIT_DIR/files/G7-mapping.md" \
      --var artifact_path="$AUDIT_DIR/artifacts/G7-findings.md" \
      --var source_access='...' --var known_findings='...'

The *Finding Schema* below remains the authority for what a finding row must
contain.
```

Apply the same substitution in `references/phase2-feature-mapping.md` (phase
`recon`, template `recon-brief.md`) and `references/phase5-fp-check.md`
(phase `fpcheck`, template `fpcheck-brief.md`), adjusting the `--var` names to
those each template declares.

- [ ] **Step 7: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_brief_templates.py -v`
Expected: PASS, 10 passed.

- [ ] **Step 8: Commit**

```bash
git add references/briefs tests/test_brief_templates.py references/phase2-feature-mapping.md references/phase4-deep-audit.md references/phase5-fp-check.md
git commit -m "feat: brief templates carrying the R2 return contract"
```

---

### Task 7: Workflows adopt the verbs and the tiers

**Files:**
- Modify: `workflows/recon.md` (Step 1 workspace creation, Step 5 dispatch, new Step 0 preflight)
- Modify: `workflows/audit.md:67` (CREATE TABLE block), `:90` (agent type and model)
- Modify: `workflows/fpcheck.md:13` (CREATE TABLE block), `:43` (agent type and model)
- Test: `tests/test_workflow_prose.py`

**Interfaces:**
- Consumes: `audit.py init`, `audit.py preflight`, `audit.py brief` from Tasks 1-3; the templates from Task 6; the tiering table from Task 5.
- Produces: the workflow text Task 8's lint validates.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_workflow_prose.py
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / "workflows").glob("*.md"))
LIVE = [p for p in WORKFLOWS if not p.name.startswith("_")]


@pytest.mark.parametrize("path", LIVE, ids=lambda p: p.name)
def test_no_live_workflow_carries_inline_ddl(path):
    """R5: schema lives in audit_core/schema.sql, applied by audit.py init."""
    assert "CREATE TABLE" not in path.read_text(), (
        f"{path.name} still has inline DDL; use audit.py init")


def test_recon_uses_init_and_preflight():
    text = (ROOT / "workflows" / "recon.md").read_text()
    assert "audit.py init" in text
    assert "audit.py preflight" in text


@pytest.mark.parametrize("name", ["recon.md", "audit.md", "fpcheck.md"])
def test_dispatching_workflows_render_a_brief(name):
    text = (ROOT / "workflows" / name).read_text()
    assert "audit.py brief" in text, f"{name} must render its brief, not paste it"


@pytest.mark.parametrize("name", ["recon.md", "audit.md", "fpcheck.md"])
def test_dispatching_workflows_name_a_model_tier(name):
    text = (ROOT / "workflows" / name).read_text().lower()
    assert re.search(r"(cheapest|mid|strongest) tier", text), (
        f"{name} must name a model tier from SKILL.md's tiering table")


@pytest.mark.parametrize("path", LIVE, ids=lambda p: p.name)
def test_no_live_workflow_mandates_the_strongest_model_for_everything(path):
    text = path.read_text().lower()
    assert "strongest model your client offers" not in text, (
        f"{path.name} still carries the blanket model mandate")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_workflow_prose.py -v`
Expected: FAIL — inline DDL present in `audit.md` and `fpcheck.md`; no workflow mentions `audit.py`; `audit.md` and `fpcheck.md` still carry the blanket mandate.

- [ ] **Step 3: Rewrite `workflows/recon.md` Step 0 and Step 1**

Insert a new Step 0 before the existing Step 1:

```markdown
## Step 0 — MCP preflight

Unused MCP tool schemas are resident on every turn and are charged again in
accumulation. Before anything else, scope the run's MCP surface:

    python3 __SKILL_DIR__/audit.py preflight --server autorev=<autorev-command>

Then relaunch against it, as the command's own output states:

    claude --strict-mcp-config --mcp-config .audit-mcp.json

If the target needs no binary tooling, run `audit.py preflight` with no
`--server` at all. If `.audit-mcp.json` already exists, it is the user's —
read it, and pass `--force` only if they confirm.
```

Replace Step 1's body with:

```markdown
    AUDIT_DIR=$(python3 __SKILL_DIR__/audit.py init | tail -1)

`init` creates `files/`, `artifacts/`, `archived-poc/` and `briefs/`, and
applies the full schema to `audit.db`. It is idempotent: re-running a phase
never destroys rows an earlier phase recorded.

Record `AUDIT_DIR`. **Stay at the project root for the whole audit** —
reference `${AUDIT_DIR}` by path, never `cd` into it (SKILL.md Essential
Principle #10).
```

- [ ] **Step 4: Rewrite Step 5's dispatch in `workflows/recon.md`**

Replace the "Each subagent prompt (template from ...) must include:" paragraph and its bullet list with:

```markdown
For each group, render the brief and dispatch with its path:

    python3 __SKILL_DIR__/audit.py brief --phase recon --unit "$G" --run "$AUDIT_DIR" \
      --var group_id="$G" --var group_name="$NAME" \
      --var group_description="$DESC" --var key_directories="$DIRS" \
      --var run_dir="$AUDIT_DIR" --var source_access="$SRC" \
      --var known_findings="$KNOWN" \
      --var mapping_path="$AUDIT_DIR/files/$G-mapping.md"

The dispatch carries the brief path plus only what the brief cannot know.
Do not paste the brief's contents into the prompt, and never paste prior
phases' summaries (spec rule R6).

**Model:** mid tier, low effort — mapping is pattern work against clear
criteria. See SKILL.md → *Model and effort tiering*.

Each subagent returns one line. Read the results from SQL, not from the
return text.
```

- [ ] **Step 5: Fix `workflows/audit.md`**

Delete the `CREATE TABLE IF NOT EXISTS cba_findings (...)` block at line 67 and replace it with:

```markdown
The schema is already applied by `audit.py init` (recon Step 1). If you are
entering this phase against an existing run directory, re-apply it safely
with `python3 __SKILL_DIR__/audit.py init --root . --timestamp <existing-ts>`.
```

Replace line 90's sentence with:

```markdown
**Agent type**: a **writable** subagent (must write artifacts + SQL — not a
read-only one). **Model:** strongest tier, high effort — this is the phase
where adversarial reasoning earns its cost. See SKILL.md → *Cross-client tool
mapping* and *Model and effort tiering*.

Render each group's brief with `audit.py brief --phase audit --unit <G>` and
dispatch the path (spec rule R6).
```

- [ ] **Step 6: Fix `workflows/fpcheck.md`**

Delete the `CREATE TABLE IF NOT EXISTS cba_fp_verdicts (...)` block at line 13 and replace it with:

```markdown
The `cba_fp_verdicts` table is created by `audit.py init`.
```

Replace line 43's sentence with:

```markdown
**Agent type**: a **writable** subagent — a read-only agent cannot write the
SQL inserts, so ALL verdicts would be lost. **Model:** mid tier, medium effort
— FP-check applies fixed rules to a bounded list. See SKILL.md →
*Cross-client tool mapping* and *Model and effort tiering*.

Render each batch's brief with `audit.py brief --phase fpcheck --unit <batch>`
and dispatch the path (spec rule R6).
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_workflow_prose.py -v`
Expected: PASS, 21 passed — two of the five tests are parametrized over the
seven live workflow files (`recon`, `deploy`, `audit`, `fpcheck`, `verify`,
`report`, `source`; the leading-underscore archive is excluded), and two over
the three dispatching workflows: 7 + 1 + 3 + 3 + 7 = 21.

- [ ] **Step 8: Commit**

```bash
git add workflows/recon.md workflows/audit.md workflows/fpcheck.md tests/test_workflow_prose.py
git commit -m "feat: workflows use audit.py init/preflight/brief and name model tiers"
```

---

### Task 8: `audit.py lint-skill` — make the rules checkable

**Files:**
- Create: `audit_core/skill_lint.py`
- Modify: `audit.py` (import, `cmd_lint_skill`, subparser, dispatch entry)
- Test: `tests/test_skill_lint.py`

**Interfaces:**
- Consumes: everything Tasks 1-7 produced; `audit.py`'s own `build_parser` for verb resolution.
- Produces: `Finding(rule: str, path: str, detail: str)`, `lint(root: pathlib.Path, known_verbs: set[str]) -> list[Finding]`, CLI `audit.py lint-skill [--root DIR]` exiting 1 when findings exist.

The spec's own lesson is that prose discipline failed empirically — `recon.md`
already told subagents to return compact summaries, and 30k-token reports
arrived anyway. This task is the enforcement that makes R2, R5 and R6 testable
instead of aspirational.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_skill_lint.py
import pathlib
import subprocess
import sys

from audit_core import skill_lint

ROOT = pathlib.Path(__file__).resolve().parent.parent
KNOWN = {"selftest", "budget", "bench", "init", "preflight", "brief", "lint-skill"}


def test_shipped_skill_passes_its_own_lint():
    assert skill_lint.lint(ROOT, KNOWN) == []


def test_unknown_verb_is_flagged(tmp_path):
    """Review Focus 1: a typo'd verb in prose ships silently and fails
    only mid-audit."""
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("see audit.py innit for setup")
    (tmp_path / "workflows" / "recon.md").write_text("x")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "unknown-verb" and "innit" in f.detail for f in findings)


def test_inline_ddl_is_flagged(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "audit.md").write_text("CREATE TABLE x (a INT);")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "inline-ddl" for f in findings)


def test_template_without_return_contract_is_flagged(tmp_path):
    (tmp_path / "workflows").mkdir()
    briefs = tmp_path / "references" / "briefs"
    briefs.mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (briefs / "audit-brief.md").write_text("do the audit and tell me about it")
    findings = skill_lint.lint(tmp_path, KNOWN)
    assert any(f.rule == "no-return-contract" for f in findings)


def test_archived_workflows_are_ignored(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "_old-archive.md").write_text("CREATE TABLE x (a INT);")
    assert skill_lint.lint(tmp_path, KNOWN) == []


def test_cli_lint_skill_exits_zero_on_the_real_skill():
    r = subprocess.run([sys.executable, str(ROOT / "audit.py"), "lint-skill"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout.lower()


def test_cli_lint_skill_exits_one_when_findings_exist(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "references" / "briefs").mkdir(parents=True)
    (tmp_path / "SKILL.md").write_text("ok")
    (tmp_path / "workflows" / "audit.md").write_text("CREATE TABLE x (a INT);")
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "lint-skill", "--root", str(tmp_path)],
        capture_output=True, text=True)
    assert r.returncode == 1
    assert "inline-ddl" in r.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_skill_lint.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'audit_core.skill_lint'`.

- [ ] **Step 3: Write the module**

```python
# audit_core/skill_lint.py
"""Check the shipped skill against the economics contract.

The spec's own lesson is that prose discipline failed empirically: recon.md
already asked subagents for compact summaries, and 30k-token reports arrived
anyway. These checks make R2, R5 and R6 enforceable rather than aspirational.
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

VERB_MENTION = re.compile(r"audit\.py\s+([a-z][a-z-]*)")
RETURN_CONTRACT = "rows=<n> artifact="
BLANKET_MANDATE = "strongest model your client offers"


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    path: str
    detail: str


def _live_markdown(root: pathlib.Path) -> list[pathlib.Path]:
    """Skill prose that ships. Archived files (leading underscore) are history."""
    out: list[pathlib.Path] = []
    skill = root / "SKILL.md"
    if skill.is_file():
        out.append(skill)
    for sub in ("workflows", "references"):
        d = root / sub
        if d.is_dir():
            out.extend(p for p in sorted(d.rglob("*.md"))
                       if not p.name.startswith("_"))
    return out


def lint(root: str | pathlib.Path, known_verbs: set[str]) -> list[Finding]:
    root = pathlib.Path(root)
    findings: list[Finding] = []

    for path in _live_markdown(root):
        rel = str(path.relative_to(root))
        text = path.read_text()

        for verb in sorted(set(VERB_MENTION.findall(text))):
            if verb not in known_verbs:
                findings.append(Finding(
                    "unknown-verb", rel,
                    f"prose names `audit.py {verb}`, which is not a real verb"))

        if path.parent.name == "workflows" and "CREATE TABLE" in text:
            findings.append(Finding(
                "inline-ddl", rel,
                "inline DDL; the schema belongs in audit_core/schema.sql via audit.py init"))

        if BLANKET_MANDATE in text and path.name != "SKILL.md":
            findings.append(Finding(
                "blanket-model-mandate", rel,
                "mandates the strongest model for everything; tier it instead"))

    briefs = root / "references" / "briefs"
    if briefs.is_dir():
        for path in sorted(briefs.glob("*-brief.md")):
            if RETURN_CONTRACT not in path.read_text():
                findings.append(Finding(
                    "no-return-contract", str(path.relative_to(root)),
                    "brief template does not state the R2 one-line return contract"))

    return findings
```

- [ ] **Step 4: Wire the CLI**

First, collapse the dispatch dict into a module-level `HANDLERS` map. Two
reviewers flagged that the dict inside `main()` is a second edit site for
every verb; giving `lint-skill` its verb list is the reason to fix it now,
and it removes a sync site rather than adding one.

Add the import and the handler first:

```python
from audit_core import skill_lint as skill_lint_mod  # noqa: E402


def cmd_lint_skill(args: argparse.Namespace) -> int:
    findings = skill_lint_mod.lint(args.root, set(HANDLERS))
    if not findings:
        print("skill lint: clean")
        return 0
    for f in findings:
        print(f"  [{f.rule}] {f.path}: {f.detail}")
    print(f"skill lint: {len(findings)} finding(s)")
    return 1
```

In `build_parser`:

```python
    ls = sub.add_parser("lint-skill", help="check the skill against the economics contract")
    ls.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent),
                    metavar="DIR")
```

Then define `HANDLERS` **below every `cmd_*` function**, immediately above
`build_parser`, and dispatch through it. `cmd_lint_skill` refers to `HANDLERS`
only at call time, so the forward reference is fine; `HANDLERS` refers to the
functions at definition time, so it must come last.

```python
# The single source of truth for which verbs exist. `main` dispatches through
# it and `lint-skill` reads its keys, so a verb cannot exist in one and not
# the other.
HANDLERS = {
    "selftest": cmd_selftest,
    "budget": cmd_budget,
    "bench": cmd_bench,
    "init": cmd_init,
    "preflight": cmd_preflight,
    "brief": cmd_brief,
    "lint-skill": cmd_lint_skill,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return HANDLERS[args.verb](args)
```

Earlier tasks' instructions to extend the dispatch-dict literal are superseded
here: after this task there is exactly one place a verb is registered for
dispatch, plus its subparser in `build_parser`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_skill_lint.py -v`
Expected: PASS, 7 passed. If `test_shipped_skill_passes_its_own_lint` fails, the lint has found a real violation left by Tasks 5-7 — fix the prose, not the lint.

- [ ] **Step 6: Run the full suite and the real lint**

```bash
python3 -m pytest tests/ -q
python3 audit.py lint-skill
python3 audit.py selftest
```

Expected: 116 passed; `skill lint: clean`; `audit_core 0.1.0 ok`.

- [ ] **Step 7: Commit**

```bash
git add audit_core/skill_lint.py audit.py tests/test_skill_lint.py
git commit -m "feat: audit.py lint-skill enforces the economics contract"
```

---

## Done when

- [ ] `python3 -m pytest tests/ -v` is green (116 tests across 15 files) — 57 from Stage 0 plus 5+7+8+2+10+21+7 from Tasks 1-8.
- [ ] `python3 audit.py selftest`, `init`, `preflight`, `brief`, `lint-skill`, `budget` and `bench` all run; `lint-skill` reports clean.
- [ ] `audit.py budget` and `audit.py bench` still reproduce the Stage 0 baseline exactly: tplink Σ context 224,151,346, 843 billed turns, recall 9/19, $73.15 per matched finding.
- [ ] A fresh `./install.sh claude` produces a tree containing `audit.py` and `audit_core/`, and its post-install `selftest` passes.
- [ ] No live workflow contains `CREATE TABLE` or the blanket model mandate.
- [ ] All three brief templates carry the R2 return contract and render with no unsubstituted placeholder.
- [ ] `SKILL.md` keeps its frontmatter and still routes every phase that has a workflow file.
