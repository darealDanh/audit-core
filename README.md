# codebase-audit

A structured, multi-phase security audit skill that drives parallel subagents through **recon → deploy → audit → fpcheck → verify → report**. Works with **GitHub Copilot Chat**, **Claude Code CLI**, and **OpenAI Codex CLI**.

Codifies hard-won lessons from actual audits (see [`references/lessons-learned.md`](references/lessons-learned.md)).

## What it does

```
recon ──► deploy ──► audit ──► fpcheck ──► [1 fork per finding, serial]
  │         │         │           │                   │
  │         │         │           │                   ▼
  │         │         │           │   verify-<id>.md + <id>-vuln-report.md
  └─────────┴─────────┴───────────┴───────────────────┘
                       SQLite audit.db (single source of truth)
                       (source-only run: one consolidated report.md, no forks)
```

The pipeline produces a `reports/audit-<timestamp>/` directory containing a SQLite `audit.db` (single source of truth for findings, FP verdicts, attack surface), per-group/per-batch markdown artifacts, and the vulnerability reports: one lean `<id>-vuln-report.md` per confirmed finding for a live run (written in the verify fork, with its PoC scripts in a project-root `poc/`), or a single consolidated `report.md` for a source-only run.

## The six workflows

Each phase is one file in [`workflows/`](workflows/). Run them individually (recommended on first use, so you understand what each does) or let the full pipeline run them in order with user gates between phases.

### 1. [`recon`](workflows/recon.md) — source detection + parallel feature mapping
Detects whether the target is a source tree, an IDA Pro MCP binary, or both, then enumerates the attack surface (HTTP routes, gRPC services, CLI entrypoints, message handlers, file/network sinks). Splits the codebase into **feature groups** (G1, G2, …) and spawns one writable subagent per group to produce `files/G<n>-mapping.md`. Populates `cba_feature_groups`, `cba_attack_surface`, `cba_security_observations` in `audit.db`. Ends by writing the resume note to session memory.

### 2. [`deploy`](workflows/deploy.md) — live-instance setup
Makes sure a live instance is reachable so later phases have a reproduction target. Supports two modes:

- **`local-managed`** — we bring it up from the repo (Docker Compose, `make run`, etc.); we own the lifecycle, config files, and restart.
- **`external-provided`** — instance is already running somewhere we don't own (staging, customer VM, remote host); we have only HTTP-layer access, **no config edits, no restart**.

Either way, produces a single repo-memory artifact `/memories/repo/<project>-live-instance.md` documenting **deployment mode, capabilities, base URLs, the operator-supplied liveness command, off-limits surface**, and (for local-managed) bind-mounted configs and common ops. Every later phase and every verify fork reads this note first.

### 3. [`audit`](workflows/audit.md) — CVE ingest + patch-bypass mining + parallel deep audit
Fetches prior CVEs/GHSAs and their patch diffs (populating `cba_known_findings`). For each patch, checks sibling files for the **same root cause left untouched** — historically the highest-yield class of findings. Then spawns one writable subagent per feature group to do adversarial source-level audit, populating `cba_findings` and writing per-group `artifacts/G<n>-findings.md`.

### 4. [`fpcheck`](workflows/fpcheck.md) — parallel static false-positive review
Batches the raw findings (~8–12 per batch) and spawns parallel subagents to apply the **18 Hard Exclusions + 10 Precedent rules + Marginal Gain Test**. Static review only — does not touch the live instance (that's verify's job; separating them keeps "I couldn't reproduce" handwaves from killing real source-level bugs). Populates `cba_fp_verdicts` and writes per-batch `artifacts/phase5-batch<X>.md`.

### 5. [`verify`](workflows/verify.md) — per-finding live PoC, **runs in a forked conversation**
For each true positive: build the PoC against the documented base URL, capture full HTTP request/response (`curl -i`), determine **CONFIRMED / REFUTED / INCONCLUSIVE**, and write `artifacts/verify-<finding-id>.md`. After the PoCs, the fork **adversarially reviews** each CONFIRMED finding with fresh, unbiased subagents — real-bug / valid-PoC / intentionally-vulnerable-or-test-code checks (Claude-only: an optional agent-team for interactive debate) — reconciles disputes, and records the outcome in the artifact. For `local-managed` instances, may back up + edit + restart configs (always restored at end). For `external-provided` instances, any finding requiring config changes or restart is marked **INCONCLUSIVE** with the required operator action — the fork must never substitute `127.0.0.1` for a remote host (would silently test the wrong service).

**One fork per finding**, run **one at a time** — each finding gets its own fresh context, and serial execution keeps parallel PoCs from racing on the shared live instance's config backup/restart. After confirming a finding, the fork itself writes that finding's lean `<id>-vuln-report.md` (the [`report`](workflows/report.md) phase runs in the fork). The command **requires** a finding-ID list and refuses to run without one; there is no orchestrator consolidation step.

### 6. [`report`](workflows/report.md) — the vulnerability report(s)
Writes the maintainer-facing report in a lean fixed format: a title, Affected Version, Summary, Root Cause, Steps to reproduce, Impact. Two modes:
- **Live (per finding, in the verify fork):** each confirmed finding gets its own `artifacts/<id>-vuln-report.md`, with the PoC inlined, a runnable copy in the project-root `poc/`, and the real captured output. No orchestrator consolidation.
- **Source-only (consolidated, in the orchestrator):** one `report.md` covering all findings, where *Steps to reproduce* is a reproduction guide (no live PoC, no captured output).

Reports never reference a `reports/audit-<ts>/` path (the maintainer won't have it), carry no CVSS/severity tables or advisory boilerplate, no em-dashes, and minimal bold/italic. After sending a report, the user archives it plus its `poc/` into `reports/audit-<ts>/archived-poc/<finding-id>/`.

## Automated source-only run (`source`)

For product teams who just want a **security report on their source before a release** — no live instance, no human in the loop — there's a composite **`source`** run that chains **recon → audit → fpcheck → report** unattended:

- Skips `deploy` and `verify` (no live instance, no live PoC).
- Auto-proceeds through every user gate; auto-accepts source detection and the feature-group split.
- CVE / patch-bypass ingest is best-effort (continues if the network is unavailable).
- Produces one consolidated `report.md` (+ `audit.db`) under `reports/audit-<timestamp>/`, where each finding's *Steps to reproduce* is a source-level reproduction guide, with a clear caveat that findings are **static true-positives that were NOT live-verified** — run the interactive `verify` phase against a live instance before any external disclosure.

See [`workflows/source.md`](workflows/source.md) for the exact per-phase overrides and the [Usage](#usage) section for how to invoke it on each client.

## Typical audit walkthrough

1. **Open the target project's workspace** in VS Code (or `cd` into it for Claude / Codex CLI).
2. **Start with recon**:
   - Copilot: `/codebase-audit` → type `recon`
   - Claude: `/codebase-audit:recon`
   - Codex: `$codebase-audit recon`

   The orchestrator detects source/IDA, proposes a feature-group split, asks you to confirm, then spawns mapping subagents in parallel. Output: `files/G<n>-mapping.md`, populated SQL tables, resume note.

3. **Deploy** (run the `deploy` phase — see Usage for your client's syntax).
   Tell the orchestrator whether the instance is `local-managed` or `external-provided`. For external, hand it the base URLs, sample auth tokens, off-limits surface, and the exact liveness command the operator considers authoritative. Output: `/memories/repo/<project>-live-instance.md`.

4. **Audit** (run the `audit` phase).
   Ingests CVEs, mines patch-bypass surfaces, then spawns one deep-audit subagent per group in parallel. Reviews each `artifacts/G<n>-findings.md` as it lands. Output: populated `cba_findings`, per-group artifacts.

5. **FP-check** (run the `fpcheck` phase).
   Batches findings and spawns FP-review subagents. Output: `cba_fp_verdicts` and per-batch artifacts. The orchestrator surfaces the TP-only list and asks you to open verify forks.

6. **Verify** — open one forked chat **per finding**, one at a time.
   In each fork: `/codebase-audit:verify G1-F1,G1-F2,G2-F5` (Claude); in Codex, open a new conversation (`/new`) and run `$codebase-audit verify G1-F1,G1-F2,G2-F5`; in Copilot Chat, paste the orchestrator's fork-prompt with `verify` as the phase. The fork runs PoCs and writes `verify-<id>.md` artifacts directly to `reports/audit-<timestamp>/artifacts/`, then **adversarially reviews** each CONFIRMED finding with fresh, unbiased subagents — real-bug / valid-PoC / intentionally-vulnerable-or-test-code lenses, with the auditor's own conclusion withheld from them (on Claude Code, an optional agent-team can debate counter-opinions) — reconciles any dispute, and records the outcome in the artifact. Then, for a confirmed finding, the fork writes its own lean `<id>-vuln-report.md` (the report phase runs in the fork). **You don't need to paste anything back to the orchestrator**, and there is no separate orchestrator report step.

7. **Done** — the per-finding `<id>-vuln-report.md` files (each with its `poc/` scripts) are the deliverables. Review each, then send to the maintainer; archive each finalized report + `poc/` into `reports/audit-<timestamp>/archived-poc/<finding-id>/`. (A source-only run instead produces one consolidated `report.md`.) Never auto-disclose — that is your call.

### Checking verify progress mid-flight

There is no dedicated "verify status" command — just ask the orchestrator in plain English, e.g.:

> *"How many verify forks have finished? Which TPs still need a fork?"*

The orchestrator will `ls reports/audit-*/artifacts/*-vuln-report.md` (and `verify-*.md`), query the TPs from `cba_fp_verdicts`, and answer with a status table of which findings still need a fork.

At any point, context compaction is recoverable: every phase rewrites a resume note in `/memories/session/<project>-audit-resume.md`. A fresh orchestrator instance can read it and pick up exactly where the previous one left off.

### Manually compact between phases

**At every user gate, before saying "go" to the next phase, run a manual compact** (`/compact` in Claude Code CLI or Codex CLI; the Compact action in Copilot Chat). The phase you just finished has already written its artifacts to disk and refreshed the resume note, so compacting at that boundary is lossless. Letting auto-compaction fire mid-phase is the most common cause of corrupted audits — it silently drops subagent outputs, dedup decisions, and partial findings that haven't been flushed to SQL yet. Compacting early costs nothing; compacting late costs the phase.

## Install

```bash
git clone https://github.com/th4s1s/codebase-audit.git
cd codebase-audit
./install.sh                # install for all clients
# or:
./install.sh copilot        # Copilot Chat only
./install.sh claude         # Claude Code CLI only
./install.sh codex          # Codex CLI only
./install.sh --insiders     # use VS Code Insiders paths
./install.sh --uninstall    # remove selected clients' launchers AND skill dirs
```

**Windows (PowerShell)** — no bash required; use the equivalent `install.ps1`:

```powershell
git clone https://github.com/th4s1s/codebase-audit.git
cd codebase-audit
.\install.ps1                 # install for all clients
# or:
.\install.ps1 copilot         # Copilot Chat only
.\install.ps1 claude          # Claude Code CLI only
.\install.ps1 codex           # Codex CLI only
.\install.ps1 -Insiders       # use VS Code Insiders paths
.\install.ps1 -Uninstall      # remove selected clients' launchers AND skill dirs
```

If PowerShell blocks the script, allow it for the session: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. (`install.sh` also works on Windows under Git Bash / WSL.) On Windows the install roots are the same names under your profile — `%USERPROFILE%\.claude\...`, `%USERPROFILE%\.copilot\...`, and `%USERPROFILE%\.agents\skills\...` for Codex — and the Claude launchers receive a forward-slash `__SKILL_DIR__` path, which Claude Code accepts.

### Where things go

Each client gets its **own self-contained copy** of the skill — installing one does not touch the other.

| Client | Skill content (`SKILL.md` + `workflows/` + `references/`) | Launcher(s) |
|---|---|---|
| **Copilot Chat** | `~/.copilot/skills/codebase-audit/` | _none_ — `SKILL.md` is auto-registered as `/codebase-audit` |
| **Claude Code CLI** | `~/.claude/skills/codebase-audit/` *(Claude auto-discovers via description triggers)* | `~/.claude/commands/codebase-audit.md` and `~/.claude/commands/codebase-audit/*.md` |
| **Codex CLI** | `~/.agents/skills/codebase-audit/` *(Codex auto-discovers via description triggers)* | _none_ — invoked as `$codebase-audit` (like Copilot, no launcher) |

### How the skill and its launchers find themselves

The literal string `__SKILL_DIR__` is an installer sentinel. It appears in the Claude launcher templates under [`claude/commands/`](claude/commands/) **and** in the skill content itself — `SKILL.md`, `workflows/*.md` and `references/**/*.md` all document `python3 __SKILL_DIR__/audit.py ...` commands. `install.sh` (and `install.ps1`) `sed`-substitutes every occurrence with the per-client skill dir on copy, so the launchers point at `~/.claude/skills/codebase-audit/...` and every `audit.py` command in the installed skill resolves to that same copy. Nothing in an installed tree should contain `__SKILL_DIR__`; `audit.py lint-skill` fails an installed tree that does.

You can `./install.sh claude` on a machine that has no VS Code, and nothing ever touches `~/.copilot/`.

### Special case: cloning directly into an install dir

If you cloned the repo into one of the per-client skill dirs (e.g. directly into `~/.copilot/skills/codebase-audit/`), the installer detects that and skips the skill-file copy for that target — there's nothing to copy onto itself. The launcher install still happens. To get the skill content into the **other** clients' dirs, run `./install.sh` with all targets (default) or just that target.

## Usage

### GitHub Copilot Chat (VS Code)

Copilot Chat does **not** support namespaced sub-commands (`/foo:bar`) — it only autocompletes top-level slash commands from prompt files. So there is **one** slash command, and you specify the phase as an argument.

After reloading the window, type:

```
/codebase-audit
```

Copilot will prompt you for a phase. Accepted values:

| Argument | Phase |
|---|---|
| `recon` | source detection + feature mapping |
| `deploy` | live instance deployment |
| `audit` | CVE ingest + patch-bypass mining + deep audit |
| `fpcheck` | static false-positive review |
| `verify` | per-finding live PoC (run inside a forked chat) |
| `report` | vuln report (per-finding in the verify fork; source = one consolidated report) |
| *(blank or `full`)* | run all phases in order, gating between each |

You can also type the phase inline (`/codebase-audit audit`) or trigger by free-text phrase (*"audit this app"*, *"find vulnerabilities in this project"*).

### Claude Code CLI

Claude Code natively supports namespaced sub-commands via subdirectories under `~/.claude/commands/`. All of these autocomplete:

| Slash command | Phase |
|---|---|
| `/codebase-audit` | full pipeline |
| `/codebase-audit:recon` | source detection + feature mapping |
| `/codebase-audit:deploy` | live instance deployment |
| `/codebase-audit:audit` | CVE ingest + patch-bypass mining + deep audit |
| `/codebase-audit:fpcheck` | static false-positive review |
| `/codebase-audit:verify G1-F1,G1-F2,G2-F5` | per-finding live PoC (run in a forked session) |
| `/codebase-audit:report` | vuln report (per-finding in the verify fork; source = one consolidated report) |

Claude also auto-loads the skill from `~/.claude/skills/codebase-audit/SKILL.md` based on description triggers (*"audit this app"*, *"security audit this codebase"*), so the slash commands are optional.

All sub-commands accept `$ARGUMENTS` for optional notes (`/codebase-audit:audit focus on G3`).

### Codex CLI

Codex auto-discovers the skill from `~/.agents/skills/codebase-audit/`. Like Copilot Chat, Codex does **not** expose namespaced per-phase slash commands — there is **one** invocation and you specify the phase as an argument.

After installing, **restart Codex** (or run `/skills`) to pick up the new skill, then invoke it explicitly:

```
$codebase-audit
```

| Argument | Phase |
|---|---|
| `recon` | source detection + feature mapping |
| `deploy` | live instance deployment |
| `audit` | CVE ingest + patch-bypass mining + deep audit |
| `fpcheck` | static false-positive review |
| `verify` | per-finding live PoC (run inside a forked session) |
| `report` | vuln report (per-finding in the verify fork; source = one consolidated report) |
| *(blank or `full`)* | run all phases in order, gating between each |

Pass the phase inline (`$codebase-audit audit`), or trigger by free-text phrase (*"audit this app"*, *"find vulnerabilities in this project"*) — Codex loads the skill into context by its description, so the explicit `$codebase-audit` invocation is optional. Use `/skills` to confirm it is installed. Manual compaction between phases is `/compact` (same as Claude Code).

### Automated source-only audit (`source`)

A single command runs the whole pipeline **unattended and source-only** — for product teams scanning a codebase before release (see [Automated source-only run](#automated-source-only-run-source) above for what it does).

| Client | Invoke |
|---|---|
| Claude Code CLI | `/codebase-audit:source` |
| GitHub Copilot Chat | `/codebase-audit source` |
| OpenAI Codex CLI | `$codebase-audit source` |
| Free-text (any) | "run the automated source-only audit" |

It runs **recon → audit → fpcheck → report** with no gates and no live instance, then writes one consolidated `report.md` (+ `audit.db`) and prints a counts-by-severity summary. Findings are **source-only (not live-verified)** — the report says so, with source-level reproduction guides, and recommends the `verify` phase before disclosure.

**Headless / unattended** (e.g. a scheduled scan on a runner — note it only *produces a report*, it does not gate a build):

```bash
claude -p "/codebase-audit:source"        # Claude Code CLI, non-interactive
codex exec '$codebase-audit source'       # OpenAI Codex CLI, non-interactive
```

(Copilot Chat runs it interactively in VS Code; it has no headless print mode.)

### Workflow-accelerated mode (Claude Code + ultracode)

On Claude Code with **ultracode** on (the Workflow tool available), both the full `/codebase-audit` pipeline and `source` can run **gateless, end-to-end** as one deterministic [workflow](https://code.claude.com/docs/en/workflows): the script fans out the within-phase work (mapping / deep-audit / FP-check) and runs **verify strictly one finding at a time** (parallel live PoCs would race on the shared instance). Each workflow step executes the existing phase docs (it doesn't type slash commands, and subagents can't nest — so the *script* does the fan-out). It's a Claude-only accelerator layered on the client-agnostic default — Copilot/Codex and non-ultracode Claude run the phases the normal way (full pipeline human-gated, `source` unattended). See [`references/workflow-orchestration.md`](references/workflow-orchestration.md) for the rules + script skeletons.

### Differences at a glance

| Aspect | Copilot Chat | Claude Code CLI | Codex CLI |
|---|---|---|---|
| Invocation surface | One: `/codebase-audit` (phase as argument) | Eight: `/codebase-audit[:phase]` (incl. `:source`) | One: `$codebase-audit` (phase as argument) |
| Sub-command autocomplete | ❌ not supported | ✅ via `commands/<name>/<sub>.md` | ❌ not supported |
| Skill auto-load by description | ✅ via user-level skills index | ✅ via `~/.claude/skills/<name>/SKILL.md` | ✅ via `~/.agents/skills/<name>/SKILL.md` |
| Argument passing | `${input:phase:...}` prompt or inline | `$ARGUMENTS` substitution | free-text after `$codebase-audit` |
| Reload required after install | ✅ Developer: Reload Window | ❌ picked up automatically | ✅ restart Codex (or `/skills`) |
| File-reference syntax | `[label](path)` markdown links | `@absolute/path` | `@path` / markdown links |

## Layout

```
codebase-audit/                 # this repo (the clone)
├── SKILL.md                    # entrypoint; sub-command router; lessons summary
├── README.md
├── install.sh                  # per-client installer (sed-substitutes __SKILL_DIR__ everywhere)
├── install.ps1                 # same installer for Windows PowerShell
├── LICENSE
├── workflows/                  # one per phase (the actual audit logic)
│   ├── recon.md
│   ├── deploy.md
│   ├── audit.md
│   ├── fpcheck.md
│   ├── verify.md
│   ├── report.md
│   └── source.md             # composite: automated source-only run
├── references/
│   ├── phase0-source-detection.md
│   ├── phase2-feature-mapping.md
│   ├── phase4-deep-audit.md
│   ├── phase5-fp-check.md
│   ├── phase6-report.md
│   ├── resume-note-template.md
│   ├── live-instance-template.md
│   └── lessons-learned.md
└── claude/commands/            # Claude launcher templates (also use __SKILL_DIR__)
    ├── codebase-audit.md
    └── codebase-audit/
        ├── recon.md
        ├── deploy.md
        ├── audit.md
        ├── fpcheck.md
        ├── verify.md
        ├── report.md
        └── source.md
```

After `./install.sh` (all targets), the *installed* state looks like:

```
~/.copilot/skills/codebase-audit/        # Copilot skill copy
~/.claude/skills/codebase-audit/         # Claude skill copy (independent)
~/.claude/commands/codebase-audit.md
~/.claude/commands/codebase-audit/{recon,deploy,audit,fpcheck,verify,report,source}.md
~/.agents/skills/codebase-audit/         # Codex skill copy (independent)
```

## Customizing the launchers

The launcher templates in `claude/commands/` are tracked in git and free to edit. Every occurrence of the literal string `__SKILL_DIR__` — in those templates and in the skill content (`SKILL.md`, `workflows/`, `references/`) — is substituted at install time with the per-client install path. After edits, re-run `./install.sh` to copy the updates into place.

## Key design choices

- **Per-client self-contained installs**: Copilot stuff under `~/.copilot/`, Claude stuff under `~/.claude/`, Codex stuff under `~/.agents/skills/`. Any one can be installed alone; none needs the others' tooling on the machine.
- **Parallel-first**: feature mapping, deep audit, and FP-check each spawn subagents per group/batch. Verification spawns one fork per finding.
- **Memory-persistent across compactions**: every phase rewrites a resume note in session memory and a live-instance note in repo memory.
- **Writable subagents only** for write-needed work — read-only agents (Claude/Copilot `Explore`) silently produce no artifacts; Codex `spawn_agent` is writable by default (a real-audit lesson). See SKILL.md → *Cross-client tool mapping*.
- **FP-check is static, verify is live** — separated so "I couldn't reproduce" handwaves don't kill real source-level bugs.
- **Adversarial review in-fork** — after the PoCs, each verify fork re-tests its own findings with fresh, unbiased subagents (the auditor's conclusion is withheld from them), catching bias and intentionally-vulnerable/test code before anything reaches the report.
- **Patch-bypass mining** — for every prior CVE, fetch the patch diff and check sibling files for the same root cause untouched. Highest-value class in practice.
- **No content duplication inside a client install** — launchers are tiny routing stubs; the audit logic lives only in `workflows/` and `SKILL.md`.

## Requirements

- VS Code with GitHub Copilot Chat, and/or Claude Code CLI, and/or OpenAI Codex CLI
- For install: a POSIX shell (`bash`) on macOS / Linux / WSL / Git Bash, **or** PowerShell 5.1+ on Windows (`install.ps1`)
- Typically `sqlite3` for `audit.db` queries during audits

## License

MIT (see [LICENSE](LICENSE)).
