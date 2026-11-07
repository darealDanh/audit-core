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

### Do not clone into an install dir

Clone the repo somewhere of its own and install **from** there **into** the client skill dirs. If the clone *is* one of the per-client skill dirs (e.g. you cloned directly into `~/.copilot/skills/codebase-audit/`), the installer refuses that target with a non-zero exit, because the `__SKILL_DIR__` substitution cannot run in place: performing it would rewrite the files of your git checkout, and skipping it would leave the sentinel in the installed skill so every `audit.py` command fails. Re-clone to a separate directory and run the installer from there.

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

## Firmware surface mapping (Stage 4d)

The shared CLI has 31 verbs, including `surface`, `hunt`, firmware
`fpcheck`, `dive`, and `decide`. Stage 4d is the fifth firmware phase (`qualify`, `acquire`, `triage`,
`diff`, `surface`); the separate `firmware-audit` skill tree is still planned. Start with an initialized
run, an acquired `target` image, and its image-scoped triage manifest. In an installed
copy, use that client's skill directory as the path to `audit.py`.

```bash
python3 audit.py surface --run RUN --root ROOT [--image-id ID] [--batch-size N] [--json]
python3 audit.py surface --run RUN --record RESULT.json [--replace] [--json]
python3 audit.py surface --run RUN --check [--image-id ID] [--json]
```

Square brackets above denote optional arguments. Prepare is the default mode;
record and check are mutually exclusive. `--root` and `--batch-size` are prepare
only, `--replace` is record only, and `--image-id` selects a target for prepare
or check. The default batch size is 50 (allowed range 1–1000).

Preparation verifies the entire live carved root against the stored target's
`cba_firmware_files` manifest: relative path, kind, size, and SHA-256 must agree,
as must the target inventory. Every regular-file manifest unit enters exactly
one batch, including configuration, wrappers, and libraries. ELF, service, and
component hints annotate work; they never reduce this denominator. Missing,
ambiguous, wrong-role, legacy-unscoped, or stale inputs refuse before SQL
publication. The shared fail-closed scanner excludes symlinks and nonregular
entries and reports traversal/read failures. A final rescan precedes publication.

Database ownership is image-qualified without changing the schema. Target
triage writes `cba_inventory.unit`, and surface import writes
`cba_coverage.unit`, using `db.firmware_unit_key(image_id, path)`:
`/firmware/<image-ID Unicode character count>:<exact image ID>:<raw path>`.
The length framing preserves arbitrary image/path text without collisions.
Inventory agreement, prepare/import/check, replacement, and acquisition
invalidation select that image's keys, so overlapping target paths remain
independent. Generic coverage joins still match inventory and decisions.
`legacy-unscoped` inventory keeps raw keys; unrelated non-surface coverage
writes are unchanged. Manifests, worklists, results, surface/unknown component
paths, and surface-facing output retain raw paths. ELF/service hints are
image-scoped; globally keyed component hints remain advisory.

Old unqualified inventory cannot stand in for an acquired image's inventory.
An old raw `surface` coverage row has unprovable ownership: import refuses an
overlapping row even with `--replace`, including a row arriving during artifact
installation. Invalidation preserves those rows instead of guessing ownership.
Use a fresh run when old raw surface rows obstruct import; there is no automatic
ownership migration. Triage still upserts observed paths without pruning.

Worklists live at `RUN/files/surface/<worklist-sha256>/index.json` with sibling
`batch-0001.json` files. Their canonical UTF-8 JSON excludes host paths and
timestamps from content identity. Render
[`references/briefs/surface-brief.md`](references/briefs/surface-brief.md)
through `audit.py brief`, supplying `run_dir`, `db_path`, `rootfs`, `image_id`,
`manifest_sha256`, `worklist_index`, `batch_path`, and `result_path`; dispatch
file paths to the worker. Its JSON result must decide every assigned unit
exactly once and bind image, manifest, worklist, and batch digests. The strict
schema is in `audit_core/surface_results.py`; result input is capped at 8 MiB.

Three new tables hold the result: `cba_surface_runs` binds the generation and
pending/complete state; `cba_firmware_surfaces` records dispatchers, concrete
handlers, protocol, lifecycle, posture, authentication, and reachability
evidence; `cba_unknowns` records unresolved questions and the observations and
methods that would settle them. Every `unknown` state needs a matching open
question. Resolved questions require resolution and evidence; honest open
questions can pass completion. An analyzed unit with no surface needs a
retained explanation or explanatory unknown. Missing decisions and budget
skips fail the explicit check.

Import installs `RUN/artifacts/surface/<sha256>/result.json` before atomically
publishing batch-owned claims and `surface` coverage. Duplicate import refuses;
`--replace` changes only the assigned batch. Import sets the run pending;
only `--check` can certify the full current denominator and mark it complete,
verifying canonical result evidence even for batches without surface claims.
Same-input prepare is idempotent; a changed worklist generation clears that
target's old claims and prior-unit surface coverage atomically. A changed
target acquisition hash/version also clears its manifest and dependent surface
state in the acquisition transaction. SQL failures preserve the prior state
and may leave an unreferenced artifact. Triage still upserts without pruning
vanished files; use a fresh image scope/run and retriage a changed carved tree.

Terminal output stays bounded: prepare prints image/counts, digests, and index
path; record prints batch/counts and artifact path; check prints aggregate
coverage, surfaces, open/resolved unknowns, and status. `--json` emits the same
summary fields. Expected domain/database errors exit 1 without a traceback;
argparse usage errors exit 2, and success exits 0.
SQLite-caused errors print exactly `surface: database operation failed`.
Other expected diagnostics escape controls/non-ASCII and are capped at 512
ASCII characters plus a newline; unexpected programming exceptions propagate.

The completion gate currently scans retained orphan result candidates to find
evidence for claim-free batches. Runtime grows with retained generations; a
future durable batch receipt could avoid this scan. This is a local-run
performance limitation, not a limit on the coverage denominator.

Surface mapping does not fetch, carve, modify or execute firmware, infer live
listeners, assign severity, emulate, or inspect kernels and bootloaders. No
audit, paid milestone benchmark, new indicator snapshot, or mutation sweep was
run for Stage 4d. The Stage 4d completion check still scans retained orphan
result candidates for claim-free batches; runtime grows with retained
generations. See
[`SESSION_HANDOFF.md`](SESSION_HANDOFF.md) for measured harness results and
the remaining milestone/restructure prerequisites.

## Firmware candidate hunting (Stage 4e)

Stage 4e adds firmware `hunt` to the shared `codebase-audit` CLI. It is
firmware-audit functionality on the shared repository; a separately packaged
`firmware-audit` skill tree and the monorepo/submodule decision remain open.
Prepare requires an acquired target, its image-scoped triage manifest, a
completed current Stage 4d surface generation, and the live carved root. Both
independent lanes assign every target regular file exactly once: L-sink traces
attacker-controlled input to dangerous operations, while L-dark assesses the
specified protocol, IPC, OTA, trust, and heap-corruption surfaces. Hints never
shrink either denominator.

```bash
python3 audit.py hunt --run "$AUDIT_DIR" --root "$ROOTFS" --image-id "$IMAGE_ID" \
  [--sink-batch-size N] [--dark-batch-size N] [--json]
python3 audit.py hunt --run "$AUDIT_DIR" --record "$RESULT_PATH" [--replace] [--json]
python3 audit.py hunt --run "$AUDIT_DIR" --check --root "$ROOTFS" --image-id "$IMAGE_ID" --lane l-sink
python3 audit.py hunt --run "$AUDIT_DIR" --check --root "$ROOTFS" --image-id "$IMAGE_ID" --lane l-dark
python3 audit.py hunt --run "$AUDIT_DIR" --check --root "$ROOTFS" --image-id "$IMAGE_ID"  # final two-lane check
```

Prepare and check require `--root`; both compare the live root to the target
manifest by path, kind, size, and SHA-256, and check repeats that verification
before completion. Record accepts a worker result and does not accept `--root`.
The default batch size is 50 in each lane; the two sizes can be set separately
from 1 through 1000. Omit `--lane` from check for the final gate, which passes
only when both lanes are complete against the same manifest and surface
snapshot.

The worker reads immutable lane indexes and batches below
`RUN/files/hunt/<generation>/<lane>/`, then writes one bounded strict JSON
result per batch. `--record` validates ownership, installs canonical evidence
under `RUN/artifacts/hunt/<generation>/<lane>/<result-sha256>/result.json`, and
atomically publishes a durable receipt, one image-qualified coverage decision
per unit, and any candidates. Receipts make candidate-free batches explicit.
Candidates belong to one image, lane, assigned component, result, and batch;
the CLI returns bounded aggregates and never prints candidate evidence.

Each lane's denominator is the complete selected target manifest, with its own
worklist, receipts, coverage phase, pending/complete state, and completion
time. A result disposition of `not_applicable` is stored as `state='analyzed'`
in shared coverage, with its evidence-backed explanation retained as the
reason; `not_audited` remains `not_audited`, and a budget skip fails the gate.
Replacing a batch requires `--replace`, removes only that batch's owned rows,
and returns only its lane to pending when the durable evidence changes. A
byte-identical replacement with matching receipt, coverage and candidate rows
preserves completion and timestamps. Changed acquisition, target triage, or
surface evidence invalidates dependent hunt state for that image. Ambiguous
legacy raw hunt coverage is preserved and refused because its image ownership
cannot be proven.

Expected SQLite failures print exactly `hunt: database operation failed`;
other expected diagnostics are escaped and capped at 512 ASCII characters plus
a newline. Usage errors exit 2, expected domain/database errors exit 1, and
success exits 0. Stage 4e records candidates for later firmware `fpcheck`; it
does not adjudicate false positives, set final severity, execute or emulate
firmware, exploit candidates, or promote them into generic findings. It
inherits triage's upsert-only manifest behavior and Stage 4d's retained-orphan
scan scaling. Firmware `fpcheck`, `chain`, `dive` and `decide` are merged
locally; Stage 4i review fixes are merged at `9e4632c`. Stage 4j `report`
is next. The Asus golden and the
monorepo/submodule decision remain prerequisites for the later overall Stage 4
milestone and restructure.

## Firmware static review (Stage 4f)

Stage 4f is merged into local `main` at `303232e` after clean scoped re-review;
`chain`, `dive` and Stage 4i `decide` are also merged; Stage 4i review fixes
are merged at `9e4632c`; Stage 4j `report` is next. Firmware review uses
the shared CLI; the
separate `firmware-audit` skill tree remains planned. Ordinary source-code
`fpcheck` keeps its existing workflow and generic verdict commands.

```bash
python3 audit.py fpcheck --run RUN --prepare --root ROOT [--image-id ID] [--batch-size N] [--json]
python3 audit.py fpcheck --run RUN --record RESULT.json [--replace] [--json]
python3 audit.py fpcheck --run RUN --check --root ROOT [--image-id ID] [--json]
```

Exactly one explicit mode is required. Prepare/check require the live carved
root; record takes no root or image selector because the result binds ownership.
`--batch-size` belongs to prepare (default 20, integer range 1–200); `--replace`
belongs to record. All flags are validated before database I/O. In installed
copies, invoke `audit.py` from that client's skill directory.

Preparation requires an acquired target, its current image-scoped manifest and
surface generation, and both hunt lanes already complete against identical
provenance. It uses the full read-only hunt verifier and checks live paths,
kinds, sizes and SHA-256 against the manifest. Every candidate enters a canonical
snapshot keyed by `(image_id, lane, candidate_id)`, retaining both lane worklist
digests and owning result artifacts. Raw IDs repeated in different lanes remain
separate decisions. Host roots and timestamps are excluded from content identity.
The candidate snapshot digest binds evidence; the index digest identifies the
review generation, including batch policy.

Canonical worklists live at `RUN/files/firmware-fpcheck/<generation>/index.json`
and sibling `batch-NNNN.json` files. Similarity signatures only place related
candidates with one reviewer; equal-signature clusters remain indivisible and
may exceed the requested target size. Clusters and batches cannot exceed 1,000
candidates. A candidate-free hunt still gets one empty batch and requires an
empty-result receipt before completion.

Render `references/briefs/firmware-fpcheck-brief.md` with
`audit.py brief --phase firmware-fpcheck --unit batch-NNNN`, supplying
`run_dir`, `db_path`, `rootfs`, `image_id`, `candidate_snapshot_sha256`,
`worklist_index`, `batch_path`, and `result_path`. Dispatch the brief file path.
The worker rereads static evidence and applies attacker advantage first, followed
by shared HE/PR/CV/Marginal Gain rules. It returns result-only JSON; SQL,
canonical artifact installation and state transitions belong to deterministic code.
The carved root is read-only access context; workers must keep its absolute host
path out of persisted evidence and use relative component/run provenance.
A PARTIAL checkpoint preserves work but cannot be imported as a complete batch.

The authoritative strict schema is `audit_core/firmware_fpcheck_results.py`.
UTF-8 input and canonical output are each capped at 8 MiB; duplicate JSON keys,
non-finite values, extra fields and invalid verdict variants are refused. Results
bind image/snapshot/worklist/batch provenance and decide every assigned
`(lane, candidate_id)` exactly once. Every decision retains adversarial reason,
attacker advantage, applied canonical rules, mitigation analysis and confidence
0–10. TRUE_POSITIVE requires reviewed root-cause and attacker/data-flow/impact
and component/surface evidence. FALSE_POSITIVE requires a refuting mechanism and
exactly one durable pivot describing what it enables, including evidence-backed
absence of an attacker-controlled path. DUPLICATE requires an explicit in-snapshot
lane/ID target and shared-root evidence. Pivots never automatically become candidates.

Exact `root_cause_key` equality is the only automatic finding grouping rule;
different keys remain separate even when similarity hints match. Duplicates may
cross lanes and batches, but global transitive resolution must terminate at a
TRUE_POSITIVE; self/missing/foreign targets, cycles and false-positive terminals
refuse completion. The lexicographically first TRUE_POSITIVE supplies canonical
scalars; sorted unions retain all contributors/components/surfaces, and confidence
is the minimum across contributors, including duplicates. Finding IDs bind image,
snapshot and root key; evidence rung is `static-reviewed`.

Five dedicated tables own state: `cba_firmware_fp_runs` (generation/status),
`cba_firmware_fp_receipts` (batch evidence/counts), `cba_firmware_fp_verdicts`
(lane-qualified decisions), `cba_firmware_pivots` (one per false positive), and
`cba_firmware_findings` (derived reviewed groups). Generic `cba_findings` and
`cba_fp_verdicts` are untouched. Record installs canonical evidence at
`RUN/artifacts/firmware-fpcheck/<generation>/<result-sha256>/result.json` before
one immediate transaction and repeats mutable ownership checks under lock.
Duplicate imports refuse without `--replace`; replacement affects only that
image/snapshot/batch's receipt/verdicts/pivots, clears selected-image findings and
returns its run to pending. Sibling batches/images and immutable artifacts survive.

Check revalidates completed hunt/live root, canonical worklists/results, exact
candidate coverage, receipt counts, pivot ownership and duplicate chains before
installing canonical `findings.json` under the generation and content digest.
It repeats checks under lock, atomically derives dedicated findings and marks
complete. Empty or all-false-positive generations complete with zero findings.
Unchanged completed rechecks verify existing artifacts/rows and preserve timestamps.
Read/install/SQL/commit failures preserve prior SQL; unreferenced immutable
artifacts can remain after failed publication.

Changed selected-target acquisition, triage manifest, surface or hunt evidence
invalidates all five review tables for that image inside the upstream transaction.
Real hunt completion transitions and repairs to damaged durable hunt rows also
invalidate review. Byte-identical upstream operations and reference/sibling image
changes preserve it. Invalidation failure rolls back upstream publication too;
final check independently refuses stale evidence. Triage remains upsert-only,
and the inherited Stage 4d orphan-result scan can grow with retained generations.

Success exits 0 with scalar aggregates/provenance and artifact paths, never raw
review evidence. Human text escapes controls/non-ASCII, redacts the supplied root,
and caps each field at 512 ASCII characters. `--json` uses a fixed scalar field
set and serializes identities and artifact paths losslessly with normal JSON
escaping; these values can exceed human display limits. Syntax errors exit 2;
semantic flag and expected domain/filesystem/database errors exit 1. SQLite
failures print exactly `fpcheck: database operation failed`. Other expected
diagnostics escape controls/non-ASCII, redact the supplied root, and cap at 512
ASCII characters plus a newline; unexpected programming errors propagate.

Static review does not fetch, carve, modify, execute, emulate or exploit firmware,
settle runtime/hardware blockers, inspect new kernel/bootloader surfaces, assign
final severity/CVSS, claim live reachability, compose chains or write disclosure
reports. The Asus golden and monorepo/submodule decision remain milestone and
restructure prerequisites. Deterministic harness success verifies contracts;
paid semantic quality, recall and audit-cost improvement remain unmeasured.
`make mutate` remains separate and opt-in.

## Firmware acquisition decisions (Stage 4i)

Stage 4i is merged into local `main` at `02cb6c0`. Review fixes through
`92562c4` passed all eight `make all` gates (8,682
tests; six migrations; 0/13,174 unexecuted statements); the final
post-documentation `make all` also passed, the fixes are merged into local `main` at `9e4632c` (fast-forward), and nothing is pushed. Stage 4j `report` is the
next implementation stage and must consume only a verified current package.

Stage 4i adds `audit.py decide` after the current firmware chain and dive gates.
`--prepare` freezes the current graph, exact non-contested dive overlay, and a
separately hashed operator policy into one immutable global worklist. A single
worker writes strict result-only JSON covering every chain and open
precondition; `--record` imports it, and `--check` mechanically publishes the
current `acquire`, `defer`, or `pass` package.

The package keeps observed technical facts separate from policy matches and
payout projections. Proposed scripts are inert, bounded, mode `0600`, and never
executed by the workflow. Historical packages remain retained, while
`verified_package` returns only the exact current graph/dive/policy result.
The lifecycle table `cba_firmware_decide_runs` has one row per image and decision
generation; completed historical generations survive. The authority modules are
`audit_core/firmware_decide.py` and `audit_core/firmware_decide_results.py`, with
current graph/dive reconstruction supplied by `audit_core/firmware_dive.py`.

The latest preparation is current. Each prepare that publishes or re-selects a
generation, including an identical re-prepare of an older one, records a higher
`preparation_ordinal`; `--check` and `verified_package` select only the highest
pending, recorded or complete generation, refuse when it is not yet complete,
and never fall back to an older package. When the graph or dive input changes,
prepare marks the stale active generation `superseded` (row and artifacts kept,
never recordable or current) and creates a new one; a changed policy over
unchanged input is refused while a generation is active. A superseded
generation cannot be prepared again; change the policy bytes to create a new
generation. Upgrading an existing run adds `superseded_at` and
`preparation_ordinal` and ranks stored rows per image (the active row highest,
then completed rows by completion, recording and preparation time) so the
generation selected before the upgrade stays current.

```bash
python3 audit.py decide --run RUN --root ROOT --prepare --policy POLICY [--image-id ID]
python3 audit.py decide --run RUN --record RESULT
python3 audit.py decide --run RUN --root ROOT --check [--image-id ID]
```

Prepare requires an explicit completed dive denominator, including the empty
case, and refuses pending, stale or contested input. Worker ranks cover every
current chain; policy matching, payout projections and recommendation precedence
remain deterministic. JSON summaries preserve exact scalar identities and paths;
human summaries and expected diagnostics remain escaped and bounded.

Canonical run-relative artifacts are:

- `files/firmware-decide/<decision-generation>/policy.json`
- `files/firmware-decide/<decision-generation>/worklist.json`
- `artifacts/firmware-decide-results/<decision-generation>/<result-sha256>/result.json`
- `artifacts/firmware-decide/<decision-generation>/<package-sha256>/decision.json`
- `artifacts/firmware-decide/<decision-generation>/<package-sha256>/bench/<name>`

See `references/briefs/firmware-decide-brief.md` and the Stage 4i section of
`SKILL.md` for the one-global-worker route, and
`docs/superpowers/specs/2026-11-04-stage4i-firmware-decide-design.md` for its
contract. Mutation, paid audit/milestone, Asus golden, second indicator snapshot,
real hardware/corpus execution, Linux/alternate-interpreter execution, the
separate firmware skill tree and monorepo/submodule decision remain open.
Triage remains upsert-only; Stage 4d retains its orphan-result scan scaling limit.

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
