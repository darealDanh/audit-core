---
name: codebase-audit
description: >-
  Runs a structured multi-phase security audit of an application using parallel
  subagents for recon, live-instance deployment, deep vulnerability hunting,
  false-positive verification, live PoC verification, and final reporting.
  Supports source code, IDA Pro MCP binary reverse engineering, or both. Use for
  full app/repo audits, bug bounty audits, patch-bypass research, and automated
  source-only scans. Triggers on 'audit this app', 'security audit this
  codebase', 'find vulnerabilities in this project', 'run the codebase audit',
  '$codebase-audit', '/codebase-audit', phase requests like recon/deploy/audit/
  fpcheck/verify/report/source, and 'automated source-only audit'. NOT for
  single-file review, quick pattern scans, PR diff review, threat modeling only,
  or post-audit cleanup.
---

# Codebase Audit — Parallel Feature-Mapped Vulnerability Hunting

A battle-tested methodology for auditing applications at scale. The workflow divides the target into feature groups, deploys a live instance, hunts vulnerabilities in parallel, eliminates false positives via static review, and verifies each survivor against the live instance via forked conversations.

## Essential Principles

1. **Source-agnostic**: Works with source directories, IDA Pro MCP, or both. Detection happens automatically in recon; user confirms.

2. **Parallel-first, except verify**: Feature mapping, deep audit, and FP-check each spawn subagents per group/batch (independent work — parallelize it). **Per-finding verification is the exception: one fork/agent per finding, run *serially* (one at a time)** — they share a single live instance, so parallel PoCs race on config backup/restart.

3. **Memory-persistent across compactions**: Every major phase ends by **rewriting the audit resume note** (see `references/resume-note-template.md`). This single file lets the orchestrator survive arbitrary context compactions without losing state. SQLite (`audit.db`) holds the structured data; the resume note holds the working strategy.

4. **Manually compact between phases, never mid-phase**: Auto-compaction is unpredictable and frequently drops the exact reasoning/state the next phase needs (subagent outputs, dedup decisions, partial findings not yet flushed to SQL). At every user gate, **before saying "go" to the next phase**, run a manual compact (`/compact` in Claude Code or Codex CLI, the Compact action in Copilot Chat). The phase you just finished has already written its artifacts to disk + a fresh resume note, so compacting at that boundary is lossless; compacting mid-phase is not.

5. **Subagent capability matters**: any subagent that must write artifacts, run SQL inserts, or hit the live instance needs a **writable** agent — never a read-only one (which silently produces no files/SQL). See the *Cross-client tool mapping* for each client's writable agent (Claude/Copilot `general-purpose`, NOT read-only `Explore`; Codex `spawn_agent`). (Lesson learned the hard way — see `references/lessons-learned.md`.)

6. **Live verification is forked, not in-line**: After FP-check produces N true positives, each finding is verified in its **own forked conversation** (one fork/agent **per finding**), run **one at a time** so parallel PoCs don't race on the shared live instance. Each fork writes `verify-<finding-id>.md`, **adversarially reviews** its finding with fresh, read-only subagents (verify Step 2), and then - if it is a real, worth-reporting vuln - writes its own lean `<finding-id>-vuln-report.md` (the **report phase runs in the fork**; there is **no** orchestrator consolidation). On Claude Code with the Workflow tool (ultracode), this runs as a serial loop of fresh agents — see [references/workflow-orchestration.md](references/workflow-orchestration.md).

7. **User gates control pacing**: User explicitly approves transitions between phases. Never auto-advance past a gate.

8. **FP-check is static-only**: FP-check subagents re-read source and apply 18 Hard Exclusions + 10 Precedent rules. They do NOT use the live instance — that is what verify forks are for. This separation prevents an "I couldn't reproduce it" handwave from killing a real source-level bug.

9. **Honest impact over inflated severity; PoC on the real build**: A finding is a vulnerability only when impact is demonstrated on the **real, unmodified** target via the **genuine attacker path with attacker-controlled inputs** — not a self-written harness, a sanitizer abort, or a debugger-injected condition (those prove a *defect*, not impact). Apply the attacker-advantage test first; if the stock-build outcome is unobservable or self-healing, it is Informational. Lead with the honest verdict and never defend an overstated severity under pushback. (See `references/lessons-learned.md` items 11–16.)

10. **Stay at the project root — never `cd` into the audit dir**: Keep the orchestrator's working directory at the **project root** for the entire audit. Reference the audit dir (`reports/audit-<ts>/`) and `audit.db` by their path — never `cd` into them. Two reasons: the resume note's resumption commands are relative to the project root, and — critically — **verify forks/branches inherit the orchestrator's current working directory**. Claude's resume picker groups sessions by that directory, so if the cwd has drifted into `reports/audit-<ts>/`, the forks are filed under a *different* project and disappear from the picker (resumable by id, but hard to find), and their relative artifact writes mis-resolve. **Open every fork from the project root.** (See `references/lessons-learned.md` item 17.)

## Economics Contract

Measured across nine real audits: 449.9M context tokens re-read for $2,053.64.
Cost follows `Σ over turns of context(turn)`, so **a token admitted to the
orchestrator's context at turn N is paid for on every remaining turn**. The
orchestrator's context is a budget, not a buffer. The rules below are the
economics contract in full: R1 and R3 govern what enters the orchestrator's
context and for how long; R2, R4, R5 and R6 govern each of the ways it gets
in.

### R1 — The orchestrator never holds raw material

Banned from the orchestrator's context: decompiler pseudocode, disassembly,
hexdumps, strings dumps, file reads over ~100 lines, and subagent prose.

Snapshot the material once, then read paths:

    python3 __SKILL_DIR__/audit.py extract --run ${AUDIT_DIR} --root . \
      --unit G1 --from-file ${AUDIT_DIR}/files/G1-paths.txt

Everything downstream reads files out of `${AUDIT_DIR}/extract/`, so fan-out
is bounded by nothing. This is the one rule where the cost argument and the
quality argument are the same argument: work that stays in the orchestrator
is serial, and serial work is why surfaces went unopened.

The orchestrator's own reads are bounded too. `audit.py rows` caps at 200
rows; `audit.py status` and `audit.py coverage` return aggregate counts
rather than rows; comprehension comes from `audit.py note`, which returns
one line per key, not the analysis behind it.

### R3 — Context ceiling with checkpoint-restart

Ceiling **100k**, checkpoint at 80%. On a trip, write the resume note and the
journal, record the checkpoint, and end the phase; the next phase starts
fresh at a ~45k prefix.

    python3 __SKILL_DIR__/audit.py checkpoint --db ${AUDIT_DIR}/audit.db \
      --phase audit --reason ceiling --turns <n> \
      --resume-note /memories/session/<project>-audit-resume.md

Compaction is not the mechanism: it costs a full-context read plus a summary,
lands at 60k-80k of lossy summary rather than 45k of real prefix, and discards
the technical state the next step needs.
`audit.py budget --project --report <session.jsonl>` reports the measured
prefix and growth and how many turns they leave.

**The budget governs where tokens are spent, never whether a surface is
opened.** A group skipped for budget is a `not_audited(reason='budget')` row.
In Stage 2 that row is recorded and reported, not enforced: it is excluded
from the analyzed total and `audit.py coverage` prints a WARNING naming it.
Gating on coverage is a Stage 3 change, benchmarked on its own so that if
recall moves we know which change moved it.

### Model and effort tiering

| Work | Model | Reasoning effort |
|---|---|---|
| Workspace setup, CVE ingest, pattern sweeps, SQL bookkeeping | script or cheapest tier | low |
| Report drafting | mid tier | low to medium |
| Feature mapping, FP-check batches | strongest tier, effort tiered down | low to medium |
| Deep audit, chain reasoning, final severity calls, adversarial review | strongest tier | high |

Reasoning effort is tiered with the model: retained thinking is the largest
single component of accumulated context, so only the strongest-tier work runs
at high effort. Effort is the lever that is safe to pull on its own — it cuts
retained thinking without changing which model reads the code.

**Feature mapping and FP-check keep the strongest model and tier only their
effort.** Both decide what gets looked at and what survives, so a model
downgrade there can cost recall and precision. That change is not free and is
not Stage 1's to make: it waits until precision is measured before and after.

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

The resident prefix is 20.9% of measured cost, and unused MCP tool schemas are
a large part of it: the prefix floor grows by 11.5k-25.1k tokens mid-session as
servers load, which on the largest measured session is 38% of the peak prefix.
Those schemas are then charged a second time in accumulation, as deferred-tool
records.

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

## Sub-Command Router

The skill supports six phases (invoke them individually after the prior phase completes, or run the full pipeline), plus an automated **`source`** run that chains recon → audit → fpcheck → report unattended for source-only scans.

### Phase → workflow mapping

| Phase | Workflow file | Purpose | Entry condition | Output |
|---|---|---|---|---|
| `recon` | [workflows/recon.md](workflows/recon.md) | Source detection, reconnaissance, **parallel feature mapping**, write resume note | Fresh start (or new target) | `cba_feature_groups`, `cba_attack_surface`, `cba_security_observations` populated; `files/G<n>-mapping.md` per group; resume note ready for compact |
| `deploy` | [workflows/deploy.md](workflows/deploy.md) | Deploy live instance from source (Docker, build artifact, or local run); document in `/memories/repo/<project>-live-instance.md` | Recon done OR independent setup task | Live instance running; endpoints documented; live-instance note saved to repo memory |
| `audit` | [workflows/audit.md](workflows/audit.md) | Load prior CVEs/advisories (find patch-bypass surfaces), **parallel deep-audit subagents** per group, write resume note | Recon + deploy done | `cba_known_findings`, `cba_findings` populated; per-group `artifacts/G<n>-findings.md`; resume note updated |
| `fpcheck` | [workflows/fpcheck.md](workflows/fpcheck.md) | **Parallel FP-check subagents** apply Hard Exclusions / Precedent rules / Marginal Gain Test — **static review only**, no live testing; write resume note | Audit done | `cba_fp_verdicts` populated; per-batch `artifacts/phase5-<batch>.md`; resume note updated |
| `verify` | [workflows/verify.md](workflows/verify.md) | **Runs in a forked conversation**, requires finding-ID list. Per-finding live PoC, **adversarial review** (Step 2), then writes `artifacts/verify-<finding-id>.md` and - for a confirmed finding - runs the report phase in the same fork. Refuses to run without IDs. | FP-check produced TPs; user opened a fork and passed `<ids>`. | `verify-<id>.md` per finding (CONFIRMED / REFUTED / INCONCLUSIVE) + `<id>-vuln-report.md` per confirmed finding. |
| `report` | [workflows/report.md](workflows/report.md) | Write the vulnerability report(s) in the lean maintainer format (Summary / Root Cause / Steps + PoC / Impact). **Live: per-finding, run IN THE FORK** after verify → `artifacts/<id>-vuln-report.md` with real PoC + captured output. **Source: consolidated, run in the orchestrator** → one `report.md`, Steps = reproduction guide (no run/output). No consolidation, no `disclosure-summary.md`. | Live: a finding confirmed in its verify fork. Source: end of the `source` run. | Live: `artifacts/<id>-vuln-report.md` per confirmed finding + scripts in project-root `poc/`. Source: one consolidated `report.md`. |
| `source` | [workflows/source.md](workflows/source.md) | **Automated source-only run** (composite): chains recon → audit → fpcheck → report **unattended** — no deploy, no live instance, no verify, **no user gates**. For product teams scanning a codebase before release. CVE ingest best-effort. | Fresh start; source tree present; no human supervision wanted | one consolidated `report.md` + `audit.db`; all findings `verified='source-only'` (not live-verified) |

**Full pipeline mode**: orchestrator runs recon → deploy → audit → fpcheck → user opens one fork per finding (each fork verifies, reviews, and writes its own `<id>-vuln-report.md`). Each transition is gated; there is no separate orchestrator report step.

**Automated source-only mode**: the **`source`** run does recon → audit → fpcheck → report **unattended and without a live instance** — every gate auto-proceeds, deploy and verify are skipped, and the orchestrator ends by writing one consolidated source-only `report.md` (Steps to reproduce are reproduction guides, no live PoC) (see [workflows/source.md](workflows/source.md)).

### How phases are invoked per client

| Client | Full pipeline | Specific phase |
|---|---|---|
| **GitHub Copilot Chat** (VS Code) | `/codebase-audit` | `/codebase-audit recon` / `deploy` / `audit` / `fpcheck` / `verify <ids>` / `report` — Copilot does NOT support namespaced slash commands, so the phase is passed as a free-text argument after the slash command. |
| **Claude Code CLI** | `/codebase-audit` | `/codebase-audit:recon`, `/codebase-audit:deploy`, `/codebase-audit:audit`, `/codebase-audit:fpcheck`, `/codebase-audit:verify <ids>`, `/codebase-audit:report` |
| **OpenAI Codex CLI** | `$codebase-audit` | `$codebase-audit recon` / `deploy` / `audit` / `fpcheck` / `verify <ids>` / `report` — like Copilot, Codex has no namespaced slash commands, so the phase is passed as a free-text argument after the skill invocation. |
| **Free-text** (any) | "audit this app" | "run the codebase-audit recon phase" |

**Automated source-only run:** invoke the **`source`** command (Claude `/codebase-audit:source`; Copilot `/codebase-audit source`; Codex `$codebase-audit source`; or free-text "run the automated source-only audit") to chain recon → audit → fpcheck → report **unattended** with no live instance — see [workflows/source.md](workflows/source.md).

### Cross-client tool mapping

The workflows name **capabilities**, not one client's tool IDs. Use your client's equivalent:

| Capability | Copilot Chat | Claude Code CLI | OpenAI Codex CLI |
|---|---|---|---|
| Ask the user to choose | `vscode_askQuestions` | `AskUserQuestion` | present the options in text and wait for the reply |
| Spawn a subagent | `runSubagent` (or `task`) | `Task` | `spawn_agent` (+ `wait_agent` / `close_agent`) |
| Run a command in a subagent | `execution_subagent` | a `general-purpose` `Task` | `spawn_agent` |
| **Writable** subagent (writes files/SQL) vs read-only | `general-purpose` vs read-only `explore` | `general-purpose` vs read-only `Explore` | `spawn_agent` (writable by default — no read-only type) |
| Read / search files | `view` / `grep` / `glob` | `Read` / `Grep` / `Glob` | your native file tools |
| Semantic / codebase search | `semantic_search` | agentic search (`Grep`/`Glob` + exploration) | native code search |
| Manual context compaction | Compact action | `/compact` | `/compact` |

**Two rules hold on every client:** (1) any subagent that writes artifacts, runs SQL inserts, or hits the live instance MUST be a **writable** agent — a read-only agent silently produces nothing; (2) choose the model and reasoning effort from the *Model and effort tiering* table below — not the strongest available for everything. Retained thinking is 18.0% of measured context cost, and lower tiers emit far less of it.

### Workflow-accelerated mode (Claude Code + ultracode)

On Claude Code, when the **Workflow tool is available to you** (ultracode is on), you may drive a whole run as one deterministic workflow instead of executing phases by hand — and under ultracode **both** the full `/codebase-audit` pipeline and `source` run **gateless, end-to-end**. See **[references/workflow-orchestration.md](references/workflow-orchestration.md)** for the rules + script skeletons. Three things that are easy to get wrong: the **script** must do the fan-out (subagents can't spawn subagents); each `agent()` **executes the phase `.md`** for its unit (it can't run a `/codebase-audit:<phase>` slash command); and **verify runs strictly serially** (one finding at a time — shared live instance). Without the Workflow tool (Copilot, Codex, or Claude without ultracode), ignore this and run inline as usual: full pipeline **human-gated**, `source` **unattended**.

## When to Use

- Full security audit of an application targeting CVE/GHSA disclosure
- Bug bounty hunting with systematic coverage
- Auditing a compiled application via IDA Pro MCP
- Patch-bypass research on a project with existing CVEs
- Re-auditing after major changes (reuse mappings as starting point)

## When NOT to Use

- Single-file or single-function code review → `code-reviewer`
- Quick pattern-based scan → `semgrep`
- Reviewing a specific PR diff → `differential-review`
- Threat modeling without code verification → `security-threat-model`
- Post-audit FP verification only → `fp-check-pivot` directly

## Architecture

```
                                  ┌─ resume note ←─ rewritten each phase
                                  │
recon ──► deploy ──► audit ──► fpcheck ──► [1 fork PER FINDING, serial]
  │         │         │           │                    │
  │         │         │           │                    ▼
  │         │         │           │     verify-<id>.md  +  <id>-vuln-report.md
  │         │         │           │     (verify + review + report, all in the fork)
  └─────────┴─────────┴───────────┴────────────────────┘
                       SQLite audit.db (single source of truth)
                       reports/audit-<timestamp>/artifacts/*.md
                       (source-only run: one consolidated report.md, no forks)
```

The automated **`source`** run uses the same diagram **minus deploy and the verify forks**: recon → audit → fpcheck → report, unattended (see [workflows/source.md](workflows/source.md)).

## Quick Reference

### SQL Tables (in `reports/audit-<timestamp>/audit.db`)

| Table | Purpose | Created In |
|---|---|---|
| `cba_sources` | Source configuration (path, IDA, both) | recon |
| `cba_feature_groups` | Group definitions + status | recon |
| `cba_attack_surface` | Endpoints/entry points per group | recon |
| `cba_security_observations` | Pre-audit observations from mapping | recon |
| `cba_known_findings` | Prior CVEs/advisories + patch-bypass intel | audit |
| `cba_findings` | Candidate findings from deep audit (col `artifact_path`) | audit |
| `cba_fp_verdicts` | FP-check verdicts | fpcheck |
| `cba_inventory` | One row per analysable unit — the coverage denominator | recon |
| `cba_coverage` | `analyzed` / `not_audited(reason)` per unit per phase | every phase |
| `cba_patterns` | Confirmed bug patterns, with the finding they came from | audit |
| `cba_pattern_hits` | Sweep candidates awaiting triage | audit |
| `cba_checkpoints` | Phase exits and ceiling trips | every phase |

### Artifact Layout

```
reports/audit-<YYYYMMDD-HHMMSS>/
├── audit.db                        # SQLite source of truth
├── briefs/                         # rendered dispatch briefs (audit.py brief)
│   └── <phase>-<unit>-brief.md     # one per dispatched subagent
├── extract/                        # snapshotted material (audit.py extract)
│   ├── manifest.json               # sha256 + version per snapshot
│   └── G<n>/<flattened-path>       # one directory per feature group
├── journal.jsonl                   # annotation journal (audit.py note)
├── files/
│   ├── G<n>-mapping.md             # per-group feature mapping (recon)
│   └── known-findings.md           # advisories + patch-bypass surface (audit)
├── artifacts/
│   ├── G<n>-findings.md            # per-group deep-audit output (audit)
│   ├── phase5-<batch>.md           # per-batch FP-check verdicts (fpcheck)
│   ├── verify-<finding-id>.md      # per-finding verification record (verify)
│   └── <finding-id>-vuln-report.md # per-finding vuln report — LIVE (report, in the fork)
├── archived-poc/<finding-id>/      # (user-managed) finalized report + poc, after sending
└── report.md                       # ONE consolidated report — SOURCE-only run only (report)
```

Plus `poc/` at the **project root** (outside `reports/`): runnable PoC scripts referenced by live reports as `poc/<name>`. Reports never reference a `reports/audit-<ts>/` path (the maintainer won't have it).

### Resume Note + Live-Instance Note

| File | Scope | Template | Purpose |
|---|---|---|---|
| `/memories/session/<project>-audit-resume.md` | Session | [references/resume-note-template.md](references/resume-note-template.md) | Survive context compactions; rewritten after every phase |
| `/memories/repo/<project>-live-instance.md` | Repo (workspace) | [references/live-instance-template.md](references/live-instance-template.md) | Persistent deployment info; survives across sessions |

### Subagent Configuration

| Phase | Agent type | Model | Count | Task |
|---|---|---|---|---|
| recon (mapping) | **writable** subagent (writes SQL/artifacts — see *Cross-client tool mapping*) | strongest tier, low effort | 1 per group | Map features → code |
| audit | **writable** subagent | strongest tier, high effort | 1 per group | Deep adversarial audit |
| fpcheck | **writable** subagent | strongest tier, medium effort | 1 per batch of 8-12 findings | Static FP review |
| verify | n/a — forked **root** conversation (or a fresh workflow agent) | — | 1 fork/agent **per finding**, **serial** | Live PoC against deployed instance |
| verify (review) | **writable** subagent, **fresh** (no fork/audit context) | strongest tier, high effort | 2-3 per CONFIRMED finding | Adversarial review of each finding/PoC — neutral prompt; real-bug / valid-PoC / intentionally-vulnerable-code lenses (optional interactive multi-agent debate where the client supports it, e.g. a Claude agent-team) |

## Rationalizations to Reject

| Rationalization | Required Action |
|---|---|
| "The code looks clean, skip deep analysis" | Analyze every entry point. Surface appearance is not security. |
| "I found enough bugs, stop early" | Complete all groups. Coverage gaps hide the worst bugs. |
| "This group is just config, skip it" | Config bugs (SSRF, injection, supply chain) are often the most critical findings. |
| "Admin-only feature isn't interesting" | Apply Marginal Gain Test — admin → cross-tenant, supply chain, persistence are all valid. |
| "Static analysis is enough, skip live verify" | Live PoC is mandatory for vendor credibility. Use a fork. |
| "Use a read-only / Explore agent for the subagents" | Use a **writable** subagent (Claude/Copilot `general-purpose`, NOT read-only `Explore`; Codex `spawn_agent`) — a read-only agent cannot write SQL/artifacts. |
| "Verify in the main conversation to save tokens" | Forks isolate failure and noise. Always fork for verification. |
| "Let the orchestrator consolidate one big report" | No. Each verify fork writes its own lean `<id>-vuln-report.md` (live); only the `source` run writes a single consolidated `report.md`. No `disclosure-summary.md`. |
| "Reference the PoC at `reports/audit-<ts>/...` / paste lots of bold + em-dashes + a CVSS table" | The maintainer won't have that path — reference `poc/<name>`. Keep reports lean: six headings only, no em-dashes, minimal `**`/`*`, no CVSS/severity tables/boilerplate. |
| "Skip the resume note this phase, it's fine" | Compaction is unpredictable. Always rewrite the resume note at phase end. |
| "Context is still big enough, don't bother compacting yet" | Manual compact at every gate. Letting auto-compaction fire mid-phase frequently drops the exact state the next phase needs. The cost of compacting too early is zero; the cost of compacting too late is a corrupted audit. |
| "My harness / ASan triggers it — that's a PoC" | A self-written harness, sanitizer abort, or debugger-injected condition proves a *defect*, not impact. Reproduce on the **stock production build** via the genuine attacker path with attacker-controlled inputs only. If the stock outcome is unobservable → Informational. |
| "Just patch the target so the bug fires" | For trust-boundary bugs, patch the **attacker** component and keep the **victim** binary 100% stock (verify via `/proc/<pid>/exe`). Modifying the victim proves nothing. |
| "It obviously hangs / crashes — no need to measure" | Quantify on the real binary: `top -bH` + `/proc/.../stat` for a spin, exit/signal for a crash, N-trial counts. 100% CPU ≠ a blocked wait. Pair with an honest-input control run. |
| "Call it an infinite loop / say it always crashes" | Use precise, measured wording ("effectively unbounded, expected N iters"; "observed M/N"). Overstatement gets bug-bounty submissions rejected — adversarially verify every claim before shipping. |
| "Use the strongest model everywhere, it's safer" | Retained thinking is 18.0% of context cost. Tier per the *Model and effort tiering* table; only strongest-tier work runs at high effort. |
| "I'll paste the task into the dispatch, it's quicker" | Dispatch prompts are the largest single category of tool-call input (1,684 tokens average). Render the brief with `audit.py brief` and send the path. |
| "I'll just write the SQL inline, it's only a few tables" | `audit.py init` applies the whole schema. Inline DDL is retyped after every compaction. |
| "The MCP servers are already connected, leave them" | Unused schemas are resident on every turn. Run `audit.py preflight` and relaunch strict. |
| "Near the ceiling — skip this group" | Checkpoint and restart. A group skipped for budget is a `not_audited(reason='budget')` row: in Stage 2 it is counted out of the analyzed total and raises a WARNING from `audit.py coverage`; gating on it is a Stage 3 change. The budget governs where tokens are spent, never whether a surface is opened. |
| "I'll just read the file into my own context to check one thing" | R1. Snapshot it with `audit.py extract` and send a subagent the path, or read the rows with `audit.py rows`. A token admitted at turn N is paid for on every remaining turn. |
| "We confirmed the pattern here; the other call sites are probably fine" | A confirmed finding is a hypothesis about every other call site. Register it with `audit.py put --table cba_patterns` and sweep. |

## Lessons Learned (FROM REAL AUDITS — READ BEFORE STARTING)

See [references/lessons-learned.md](references/lessons-learned.md) for the full list. Key items:

1. **Never use a read-only agent for write-needed work** (Claude/Copilot `Explore`) — it silently produces no artifacts; use a writable subagent.
2. **Always back up live-instance config before PoC** (e.g., `cp .docker_compose/rules.json /tmp/rules.json.bak.fork-<X>`) and verify restore at end.
3. **User may hand-edit live-instance config between phases** — always re-read configs before edits.
4. **Patch-bypass class is gold** — when ingesting CVEs, look at the patch diff and check sibling files for the same root cause untouched. (Highest-severity findings in real audits come from this.)
5. **Operator-config "vulns" usually fail the Marginal Gain Test** — if the operator could already do X via documented config, finding a second way is not a CVE.
6. **Session memory drops** from subagents accumulate — clean them up after consolidating into `artifacts/`.
7. **PoC rigor** — reproduce impact on the real production-flag build via the genuine attacker path; a self-harness / sanitizer abort / debugger-injected condition proves a *defect*, not impact (downrate to Informational if the stock-build outcome is unobservable).
8. **Trust-boundary PoCs: patch the attacker, keep the victim stock** — for client↔server / server→client bugs, control the attacker's component (let its real serializer emit wire-correct bytes) and verify the victim is the unmodified binary (`readlink /proc/<pid>/exe`).
9. **DoS / hang / non-HTTP findings need OS-level proof + a control** — quantify with `top -bH` + `/proc/<pid>/task/<tid>/stat` (spin), exit code (crash), or RSS (memory); 100% CPU distinguishes a spin from a blocked wait; always pair with an honest-input control run.
10. **State outcomes precisely + adversarially verify the report** — "effectively unbounded (expected N iters)" not "infinite", "observed X" not "would X"; run an independent pass over citations / mechanism / severity before shipping.
11. **Live-instance footguns** — `kill -9` hung processes (they ignore SIGTERM and squat ports); persist ephemeral state before restarting between runs; flush state to disk before any cross-process handoff; lifecycle ops may need the sandbox disabled.
12. **Attacker-advantage test FIRST** — a node dropping a misbehaving peer, or a self-healing / operator-misconfig condition, is not a vuln; lead with the honest verdict.

## Workflow Entry

To begin, route to the appropriate workflow:

- "audit this app" or no specific sub-command → start with [workflows/recon.md](workflows/recon.md)
- A specific-phase invocation (per *How phases are invoked per client* — Claude `/codebase-audit:<phase>`, Copilot `/codebase-audit <phase>`, Codex `$codebase-audit <phase>`) → load `workflows/<phase>.md` and execute
- The `source` run / "automated source-only audit" → load [workflows/source.md](workflows/source.md) and run recon → audit → fpcheck → report unattended (no deploy, no live instance, no verify, no user gates)

## Phase Reference Index (technical details for sub-workflows)

| File | Content |
|---|---|
| [references/phase0-source-detection.md](references/phase0-source-detection.md) | Source detection logic, IDA Pro MCP probing, user prompts |
| [references/briefs/](references/briefs/) | The three dispatch brief templates (`recon-`, `audit-`, `fpcheck-brief.md`) rendered by `audit.py brief`; `references/phase5-fp-check.md` holds the FP rules they cite |
| [references/phase2-feature-mapping.md](references/phase2-feature-mapping.md) | Feature group taxonomy, the recon brief's `--var` values, mapping format |
| [references/phase4-deep-audit.md](references/phase4-deep-audit.md) | The audit brief's `--var` values, finding schema, dedup |
| [references/phase5-fp-check.md](references/phase5-fp-check.md) | Batching strategy, FP rules, verdict schema |
| [references/phase6-report.md](references/phase6-report.md) | Lean per-finding + consolidated report template (Redis-style) + annotated example |
| [references/resume-note-template.md](references/resume-note-template.md) | Standard resume-note format for compact survival |
| [references/live-instance-template.md](references/live-instance-template.md) | Standard live-instance doc format |
| [references/lessons-learned.md](references/lessons-learned.md) | Pitfalls observed in real audits |
| [references/workflow-orchestration.md](references/workflow-orchestration.md) | Claude-only: drive the pipeline / `source` as a Workflow-tool workflow (ultracode) — rules + script skeletons |

## Success Criteria

- [ ] All feature groups have mappings in SQL + `files/G<n>-mapping.md`
- [ ] Live instance is running and documented in repo memory
- [ ] Every group was deep-audited; findings in `cba_findings` + `artifacts/G<n>-findings.md`
- [ ] Every finding has a FP-check verdict in `cba_fp_verdicts`
- [ ] Every TRUE_POSITIVE has a `verify-<id>.md` artifact OR a documented "infra-blocked, source-only" reason
- [ ] Live: every confirmed vuln has its own lean `<id>-vuln-report.md` (real PoC + captured output; scripts in `poc/`). Source-only: one consolidated `report.md` with source-level reproduction guides
- [ ] Resume note exists and reflects current state (would let a fresh orchestrator resume cleanly)

**For the automated `source` run:** the *live instance* and *verify artifact* criteria do **not** apply — deploy and verify are skipped. Instead: every TRUE_POSITIVE is `verified='source-only'`; the single consolidated `report.md` carries the not-live-verified caveat and its Steps are reproduction guides; and the final severity-counts summary was printed.
