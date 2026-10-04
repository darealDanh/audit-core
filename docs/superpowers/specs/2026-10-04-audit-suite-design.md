# Audit Suite — shared core, firmware-audit sibling, and an enforced cost contract

Date: 2026-10-04
Status: design approved in brainstorming; not yet planned or implemented
Scope: `codebase-audit`, `grey-audit`, and a new `firmware-audit` skill

## 1. Problem

Nine security-audit sessions under `~/Documents/Offsec/Opswat/Devices/` were
measured from their Claude Code transcripts. All nine were IoT firmware audits
driven by the `codebase-audit` skill.

### 1.1 Cost

| Quantity | Measured |
|---|---|
| Orchestrator cost, 9 sessions | $1,742.95 |
| Orchestrator API turns | 4,223 |
| Context tokens re-read | 1,058,000,000 |
| Tool-result tokens (new information) | ~800,000 |
| Output tokens | 7,682,870 |

Subagent cost is not recorded in these transcripts, so the true total is higher.

Per-session detail for the three most expensive runs:

| Session | Cost | Turns | Median ctx | p90 ctx | Max ctx | Compactions |
|---|---|---|---|---|---|---|
| asus-AX1800S | $787.75 | 842 | 207,564 | 423,483 | 488,354 | 2 |
| unifi/100fcb | $359.07 | 555 | 353,858 | 580,842 | 631,139 | 0 |
| tplink | $347.68 | 1,894 | 251,559 | 503,640 | 711,826 | 6 |

Cache reads are roughly 70% of the bill. Cost follows
`Σ over turns of context(turn)`, so a token admitted to the orchestrator's
context at turn N is paid for on every remaining turn.

### 1.2 Where the context actually goes

> **Correction pending (2026-10-05).** The tplink transcript was still being
> appended to while this section was first measured, so its cost and turn
> counts come from a shorter read of the file than its composition figures do.
> Known-stale: cost $347.68 (actual $658.37) and turns 1,894 (actual 1,936
> billed, 1,950 records). Confirmed stable: 521.9M sum_context, 7 epochs, and
> every composition figure below. Stage 0 Task 5 regenerates all nine sessions
> from `audit.py budget --report` and Task 8 records them; this section is
> corrected once from that output, not by further hand arithmetic.


Measured on tplink (1,894 turns with usage, 521.9M context tokens re-read,
6 compactions). Context splits into a **prefix** paid on every turn and an
**accumulation** that grows within each compaction epoch.

| Term | Tokens | Share |
|---|---|---|
| Prefix (system prompt, tool schemas, MCP schemas, skill) | ~97M | 19% |
| Accumulated message history | ~425M | 81% |

Epoch floors measure the prefix directly: 40,926 at session start, rising to
66,010 once MCP servers loaded. Growth rate within an epoch is 909-1,479
tokens/turn across the six epochs, mean ~1,150.

Total added to message history over the session: 1,730,471 tokens.

| Component | Tokens | Share of additions | Est. share of 522M |
|---|---|---|---|
| Thinking blocks retained in history | 580,634 | 33.6% | ~27% |
| Tool results | 401,201 | 23.2% | ~19% |
| Tool-use inputs (the model's own inline Bash/Python) | 223,757 | 12.9% | ~10% |
| `total_tokens_reminder` attachments | 139,049 | 8.0% | ~7% |
| Assistant text | 100,820 | 5.8% | ~5% |
| Skill re-injection (`invoked_skills` + `skill_listing`) | 82,438 | 4.8% | ~4% |
| Deferred-tool records and deltas | 65,227 | 3.8% | ~3% |
| Subagent results (`<task-notification>`) | 32,704 | 1.9% | ~2% |
| User text | 40,596 | 2.3% | ~2% |
| Other attachments | 64,045 | 3.7% | ~3% |

The right-hand column distributes the 81% accumulation term in proportion to
each component's share of additions. That assumes uniform residency, which
over-weights late additions; it is an estimate, and `audit.py budget --report`
replaces it with per-turn attribution in Stage 0.

**Ranked levers, from the measurement:**

1. **Accumulation is 81% of cost.** Capping it caps the bill regardless of
   composition. This is why the context ceiling (R3) is the master lever, not
   any single component.
2. **Retained thinking is the largest single component (~27%).** Addressed by
   model and reasoning-effort tiering, and by shorter phases.
3. **Tool results plus tool-use inputs are ~29% combined.** Addressed by
   extract-then-fan-out (R1) and by moving reusable logic into `audit.py`
   instead of regenerating inline heredocs (R5) - the model wrote 223,757
   tokens of inline scripts in this session.
4. **Prefix is 19%**, and unused MCP tool schemas are a large part of it (R4).
5. **Subagent results are ~2%.** Return contracts (R2) are worth doing because
   they are free, but they are not a headline lever.

Two further measured facts:

- **The skill re-reads itself from disk after compaction.** `cat SKILL.md` costs
  7,140 tokens; each of five workflow files costs 3.0k-3.8k. Separately, 82,438
  tokens of skill re-injection attachments appear in the history.
- **Model monoculture.** Opus is ~100% of spend; Haiku totals $0.50 across all
  nine sessions, against a SKILL.md rule mandating the strongest available model
  for every subagent. Lower tiers also emit far less thinking, which is lever 2.

### 1.3 Quality

Against an independent 19-item CRITICAL reference set for the same tplink
firmware, the audit found 8. The session's own post-mortem identified the causes,
and they are design gaps rather than analysis failures:

- **Whole layers never opened.** No finding sits below the IP layer; the Wi-Fi
  driver underneath the audited application was never examined. Six of ten
  missed CRITICALs are on unopened surfaces. The feature-group taxonomy in
  `references/phase2-feature-mapping.md` is web-application shaped.
- **A self-assigned filename became a fact.** `km0_boot_0C000020.elf` was treated
  as a bootloader for the whole run; it holds the Realtek Wi-Fi driver and
  several CRITICALs.
- **FP-check terminates instead of pivoting.** A finding was correctly refuted by
  a 300-byte sliding-window flush; that same flush mechanism is the attack
  surface for a reference-set CRITICAL. The verdict schema records no pivot.
- **Chains were never composed.** Two findings held both halves of an exploit
  chain and were never joined, because findings are born inside per-group
  subagents and nothing crosses them.
- **Confirmed patterns were never swept.** `strncpy(dst, src, strlen(src))` was
  found twice, recognised as a pattern, and never grepped for. Two reference
  CRITICALs are that pattern elsewhere.
- **Discovery budget was consumed by weaponization.** Exploit development for one
  chain came out of the coverage budget.
- **Reachability was argued, not recorded.** Severity disputes ("is port 80 open
  on a bound lock", "which surfaces are LAN-reachable", "x-setting is 1 on a real
  router") consumed dozens of turns and were never written anywhere a later
  phase could read.
- **`verify` is structurally unusable for firmware.** It requires a deployed live
  instance. Every firmware session worked around it. tplink's verification tail
  was 103 user prompts of manual analysis inside a 250k-700k context, and that
  tail is where most of its $347.68 went.
- **Compaction destroyed technical state.** The resume note carries pipeline
  status, not function semantics, structs, or chain state. The user observed
  answers changing between asks.

### 1.4 The governing insight

The largest cost leak and the largest quality gap are the same defect. The
`autorev` MCP resolves every caller to one shared stdio session, so parallel
subagents clobber each other's database. Work therefore stayed serial and in the
orchestrator's context: cost grew, and fan-out was capped, which is what left
surfaces unopened. `grey-audit` already solves this by extracting to files before
fanning out. Removing the resident raw material raises coverage and lowers cost
together; they are not in tension.

## 2. Goals and non-goals

### Goals

- Cut orchestrator context re-reads by roughly an order of magnitude on a
  tplink-class run, with recall against the golden set equal or higher.
- Give firmware targets a phase structure that matches how they are actually
  worked: scanned before purchase, partial images, usually no emulation.
- Share one core across `codebase-audit`, `grey-audit`, and `firmware-audit`.
- Make coverage, reachability, and cost measurable rather than asserted.

### Non-goals

- Weaponization or exploit reliability engineering. Rung 4 is a confirmed
  vulnerability, not a working exploit.
- Full-system firmware emulation as a pipeline dependency.
- Replacing `grey-audit`'s Windows-specific machinery.
- Any change to how the three skills are invoked by the user.

### Constraints taken as given

- Firmware is audited **before** the device is purchased. The deliverable is an
  acquisition decision, not a live verdict.
- Extracted images are partial. Full-system emulation usually fails and never
  works for RTOS/bare-metal targets.
- The suite must keep working on Claude Code, OpenAI Codex CLI, and GitHub
  Copilot Chat.
- No third-party Python dependencies in the shared core.

## 3. Architecture

### 3.1 Repository layout

One repository is the source; each installed skill is a self-contained
directory. The shared pieces are vendored in at install time, so nothing reaches
outside the skill directory at runtime.

```
Tools/audit-suite/
├── core/                      # shared prose contracts
│   ├── economics.md
│   ├── evidence-ladder.md
│   ├── fp-rules.md
│   ├── reachability.md
│   ├── chains.md
│   ├── identity.md
│   ├── report-format.md
│   └── lessons-learned.md
├── audit_core/                # shared Python, stdlib only
│   ├── db.py
│   ├── schema.sql
│   ├── annotations.py
│   ├── extract.py
│   ├── budget.py
│   ├── sweep.py
│   ├── coverage.py
│   ├── chains.py
│   └── report.py
├── skills/
│   ├── codebase-audit/
│   ├── grey-audit/
│   └── firmware-audit/
│       ├── SKILL.md
│       ├── workflows/*.md
│       ├── references/*.md
│       └── audit.py
├── tests/
│   ├── goldens/
│   └── test_*.py
├── install.sh
└── install.ps1
```

`grey-audit` currently lives in a separate tree (`~/Documents/skills/grey-audit`).
If it must remain a separate repository, the fallback is core as a git submodule
plus a `sync.sh`; the monorepo is preferred and is assumed below.

### 3.2 Install

`install.sh` vendors `core/` and `audit_core/` into each skill directory, then
installs per client:

| Client | Skill root | Launchers |
|---|---|---|
| Claude Code | `~/.claude/skills/<name>/` | `~/.claude/commands/<name>/*.md` |
| Codex CLI | `~/.agents/skills/<name>/` **and** `~/.codex/skills/<name>/` | none (auto-discovered) |
| Copilot Chat | `~/.copilot/skills/<name>/` | prompts dir |

Two modes, matching `grey-audit` today: `--link` (symlink the checkout, for
development) and `--copy` (vendor and copy, for release).

**Path resolution.** `codebase-audit/install.sh` already sed-substitutes
`__SKILL_DIR__` into Claude launchers. That substitution is extended to the
installed `SKILL.md` and `workflows/*.md`, so every file contains literal
absolute paths after install. No runtime discovery, identical behaviour on all
three clients.

**Entry point.** One verb-dispatch CLI per skill, so one command shape is
learned rather than eight script paths:

```
audit.py init | extract | sweep | coverage | chains | unknowns | finding
       | budget | bench | preflight | report | selftest
```

`audit.py` inserts its own directory on `sys.path` and imports `audit_core`. No
`PYTHONPATH`, no venv, no pip. `audit_core` is stdlib-only (`sqlite3`, `json`,
`re`, `pathlib`); `grey-audit`'s `lief` dependency remains a per-sibling optional
extra with a documented fallback.

**Two installer defects to fix.** `codebase-audit/install.sh` copies only
`SKILL.md`, `workflows/*.md` and `references/*.md`, so it would silently drop
`audit_core/` and `audit.py`. The unified installer copies the whole tree minus
`.git`/`__pycache__`/`.pytest_cache` and ends with `audit.py selftest`, which
verifies the vendored core is present and the schema applies, failing loudly
otherwise. Separately, the two existing installers disagree on the Codex skills
directory; the unified installer writes both.

### 3.3 Core boundary

Test applied: does this change when the target changes from a Django repository
to a `.sys` driver to a SPI flash dump? If not, it is core.

| Core | Per sibling |
|---|---|
| Economics contract, return contracts, extract-then-fan-out | How to extract (source tree / IDA / carved image) |
| Evidence ladder | What rung 4 means for that target class |
| FP rules and the pivot rule | Target-specific exclusions |
| Abstract precondition/unknowns model | The concrete state space |
| Chain primitive taxonomy and composition | Which primitives matter |
| Sweep engine and cross-target pattern library | Seed patterns per class |
| Coverage accounting | What the denominator is |
| Identity discipline | Identification evidence |
| Report format, resume note, annotation journal | — |

### 3.4 State model

One SQLite database per run, plus a JSONL annotation journal. Tables:

| Table | Holds |
|---|---|
| `runs` | run id, target, skill, start, MCP servers live, ceiling, model tiers |
| `components` | path, kind, asserted identity, **identity evidence**, confidence, version |
| `inventory` | one row per analysable unit (file or function) — the coverage denominator |
| `coverage` | unit, phase, `analyzed` or `not_audited` with reason |
| `surface` | entry point, protocol, dispatch path, auth required, **state required**, reach evidence |
| `observations` | rung-1 observations, including those emitted by the pivot rule |
| `findings` | rung 2-4, with `rung`, location, root cause, impact, attacker position, boundary, data flow, state required |
| `verdicts` | FP verdict, rule hit, **refuting mechanism**, **enabled observation id** |
| `patterns` | confirmed bug patterns, origin finding, sweep timestamp, hit count |
| `chains` | ordered finding ids, attacker position, pre-auth flag, completeness, blocking unknowns |
| `unknowns` | question, settling observation, method (static/emulate/hardware), status |

`annotations/<binary>.jsonl` holds comprehension — function semantics, struct
definitions, resolved questions — and is the source of truth; an IDA `.i64` is a
rebuildable cache. Mechanism and schema are ported from `grey-audit`.

### 3.5 Three core mechanisms that are new

1. **The pivot rule.** A `FALSE_POSITIVE` verdict is invalid unless it records
   `refuting_mechanism` and what that mechanism enables, and the latter is
   written back as a rung-1 observation. Derived from the tplink miss where the
   refuting mechanism was itself a CRITICAL.
2. **Sweep-on-confirm.** Confirming a bug pattern registers it in `patterns` and
   triggers a corpus-wide sweep by a cheap model. The pattern library persists
   across targets.
3. **Coverage as a denominator.** `not_audited` rows with reasons are mandatory.
   "Have we audited everything" is answered by `audit.py coverage`.

## 4. `firmware-audit` phases

Derived from `Devices/TARGET-HUNTING-PLAN.md` steps 0-8.

| Phase | Plan step | Does | Work location |
|---|---|---|---|
| `qualify` | §0 filters, step 0, §4 | EOL/EOS, latest-firmware date, slop index from `_intel/target-scores.csv`, payout path. **GO/NO-GO gate.** | script |
| `acquire` | 1 | Latest firmware (target) plus CVE-affected build (diff reference); versions, hashes, provenance | orchestrator |
| `triage` | 2 | Carve, arch/endian/libc, evidence-based component ID and SBOM, init scripts, nvram defaults, all listening services, mitigations, corpus inventory | script + 1 agent |
| `diff` | 3 | Patch-diff reference vs latest, extract the vendor's fix idiom, sweep unfixed sibling call sites | script sweep + agents |
| `surface` | 4 | Dispatch/handler tables per component; pre-auth vs post-auth recorded as data | fan-out, file-backed |
| `hunt` | 5 + 6 | Two lanes, separate budgets (below) | fan-out, file-backed |
| `fpcheck` | — | Static adversarial review plus the pivot rule | fan-out, batched |
| `chain` | new | Compose primitives into end-to-end chains | 1 agent over SQL |
| `dive` | new | Journal-backed interactive deep dive | fresh agent per question |
| `decide` | new | Acquisition decision package | 1 agent |
| `report` | 8 | Lean report; pre-auth proof stated explicitly | fresh agent per finding |

### 4.1 `qualify` is a hard gate

An EOL SKU pays zero and costs thousands of tokens. This phase is deterministic
script work against data already in `_intel/`, and it can refuse to start the
pipeline.

### 4.2 `diff` runs before `hunt`

`codebase-audit` buries CVE ingest inside the audit phase. The plan calls
patch-diff the highest-yield step. Learning the fix idiom once and sweeping every
unfixed sibling call site is mechanical work producing CRITICAL-grade leads.

### 4.3 `hunt` has two lanes with separate, non-transferable budgets

- **L-sink** — `system`/`popen`/`execve`/`doSystemCmd`/`twsystem`;
  `strcpy`/`sprintf`/`memcpy`/`sscanf("%s")` with attacker-controlled length;
  `nvram_set` values reaching a shell; `%s`-into-format. High volume, cheap model.
- **L-dark** — UPnP/SSDP, mDNS responders, TR-069/CWMP clients, cloud-tunnel and
  P2P pairing stacks, proprietary LAN discovery UDP/multicast, `httpd`-to-helper
  IPC over Unix sockets, OTA image signature verification, heap corruption of any
  kind. Strongest model, no volume target.

Budgets are non-transferable because the tplink post-mortem attributes the
coverage gap to discovery budget being spent on weaponization. Weaponization is
in neither lane; it belongs to `dive`, after coverage closes.

### 4.4 `decide` replaces `verify`

Terminal deliverable for a scan-before-buy workflow:

- Ranked chains with attacker position and pre-auth status
- Open preconditions as `unknowns` rows, each with its settling observation
- What physical access would settle that static analysis cannot
- Day-1 bench test plan plus runnable scripts
- Payout-tier estimate against the plan's §4 criteria

### 4.5 Emulation is a capability, not a phase

`audit.py` exposes an opportunistic userland-chroot helper (single binary plus an
nvram shim) callable from `hunt` and `dive`. It never gates a phase and no
finding's rung depends on it.

### 4.6 Device-state model

Firmware-specific; the abstract model lives in `core/reachability.md`.

```
lifecycle   factory-fresh | provisioned | bound-to-owner | cloud-registered | post-reset
posture     SoftAP-setup  | STA-LAN     | WAN-exposed    | BLE             | cloud-tunnel-only
auth        pre-auth      | session     | admin          | local-shell     | physical-UART
```

Every finding and surface row carries the state tuple it requires. Every
unresolved element becomes an `unknowns` row with its settling observation.

### 4.7 Not carried over

`deploy` and live-instance `verify` are dropped. They are `codebase-audit`
concepts that produced a "skip the deploy, source-only" workaround in every
firmware session.

## 5. Economics contract

In `core/economics.md`, enforced by `audit_core/budget.py`.

### R1 — The orchestrator never holds raw material

Banned from orchestrator context: decompiler pseudocode, disassembly, hexdumps,
strings dumps, file reads over ~100 lines, subagent prose.

`audit.py extract` performs the single RE pass — the only place
`mcp__autorev__*` is called — writing pseudocode, imports, strings and xrefs to
`extract/`. All downstream work reads files, so fan-out is unbounded. This also
removes the single-IDA-session fan-out cap. `assert_database` is called at every
batch boundary during extraction.

### R2 — Return contracts

Subagents write to SQL and an artifact, then return one line:

```
<unit_id> <DONE|PARTIAL|FAILED> rows=<n> artifact=<relpath> [flags=<csv>] [note=<=80 chars>]
```

The structural half matters more than the instruction: the orchestrator never
acts on return text. Its next action is always an `audit.py` verb reading bounded
rows from SQL. Prose returned anyway is dead weight for one turn rather than
permanently resident.

Measured scale: subagent results are ~2% of accumulation (102 notifications,
100,801 tokens across all nine sessions; 32,704 in tplink; largest single
result 7,639). R2 is retained because it is free and it keeps the orchestrator's
reasoning anchored on SQL rather than on agent prose, **not** because it is a
large saving. It must not be prioritised over R1, R3 or R5.

### R5 - Reusable logic lives in `audit.py`, never in inline heredocs

The model wrote 223,757 tokens of inline Bash and Python in tplink (12.9% of
accumulation, ~10% of total cost), much of it regenerating the same extraction
and parsing logic after each compaction. Any script longer than ~10 lines, or
written twice, becomes an `audit.py` verb. Invocations then cost one line
instead of a heredoc.

This also removes the skill-re-read cost: `cat SKILL.md` is 7,140 tokens and
each workflow file 3.0k-3.8k, re-paid after every compaction. Phase logic the
orchestrator needs after a restart belongs in the resume note and in `audit.py`,
not in a file it must re-read.

### R3 — Context ceiling with checkpoint-restart

Ceiling **100k**, checkpoint at 80%. On trip, the orchestrator writes the resume
note and journal and ends the phase; the next phase starts fresh at ~45k.

Compaction is rejected as the mechanism: it costs a full-context read plus
summary generation, lands at 60k-80k of lossy summary rather than 45k of real
prefix, and discards the technical state the next step needs.

Modelling with prefix `P`=45k, growth `g`=0.6k/turn, `W`=1,000 turns, and a
restart overhead of ~1.1M read-equivalents (one 1h-TTL cache write of the prefix
plus re-orientation):

| Ceiling | Turns/segment | Restarts | Linear term | Restart overhead | Total |
|---|---|---|---|---|---|
| 70k | 42 | 24 | 57.5M | 25.9M | 83.4M |
| 80k | 58 | 17 | 62.5M | 18.6M | 81.1M |
| 100k | 92 | 11 | 72.5M | 11.8M | 84.3M |
| 120k | 125 | 8 | 82.5M | 8.6M | 91.1M |
| 200k | 258 | 4 | 122.5M | 4.2M | 126.7M |

The curve is flat from 70k to 120k (81M-91M) and climbs steeply above. 80k is the
numeric minimum, but 100k is chosen: it is within 4% of the minimum while giving
92 turns per segment instead of 58, which matters for phase continuity and for
interactive `dive` work. `budget.py` measures `g` per phase and reports it; the
ceiling is re-tuned against measured `g` rather than this estimate.

**Anti-rationalization rule**, added to each skill's rejection table: "near the
ceiling, skip this group" is answered by checkpoint-and-restart, never by
skipping. A group skipped for budget is a `not_audited(reason='budget')` row and
**fails the quality gate**. The budget governs where tokens are spent, never
whether a surface is opened.

### R4 — MCP preflight

Each run writes a project-scoped `.audit-mcp.json` naming only the servers the
run needs (`firmware-audit`: `autorev`) and launches with:

```bash
claude --strict-mcp-config --mcp-config .audit-mcp.json
```

Both flags are verified present in the installed Claude Code CLI. The `runs` row
records which servers were live so the economics report can attribute prefix
cost. R4 is a prerequisite for R3: restart overhead scales with the prefix, so
cutting 145k to 45k is what makes a tight ceiling affordable.

### 5.1 Model tiering

Replaces the current "strongest model available" blanket rule.

| Work | Model |
|---|---|
| `qualify`, triage inventory, `extract`, sweeps, coverage accounting | script / Haiku |
| `surface` mapping, L-sink hunt, `fpcheck` batches, report drafting | Sonnet |
| L-dark hunt, `chain` composition, `dive`, final severity calls | Opus |

Reasoning effort is tiered with the model. Retained thinking is the single
largest accumulation component (33.6%), so mechanical phases run at low effort
and only the Opus-tier work runs at high effort.

### 5.2 `dive` economics

Each question spawns a fresh agent loading the journal index plus at most three
functions from `extract/`, answering, and appending to the journal. The
orchestrator holds the index, never the analysis. Per-question context is
25k-40k and flat. Answers derive from a durable journal rather than a decaying
context, which addresses the observed answer drift.

### 5.3 Measurement

`audit.py budget --report <session.jsonl>` writes one row per run: Σ context,
mean and p90 context, turns, resident prefix, tool-result bytes by tool,
subagent return distribution, cost, measured `g`, and rung-4 findings.

Headline metric: **cost per rung-4 finding**.

| Metric | tplink baseline | Target |
|---|---|---|
| Σ context re-read | 521.9M | ≤ 60M |
| Mean orchestrator context | 267.6k | ≤ 80k |
| Growth rate `g` | ~1,150 tok/turn | ≤ 400 tok/turn |
| Prefix floor | 40.9k-66.0k | ≤ 45k |
| Retained thinking, share of accumulation | 33.6% | ≤ 15% |
| Tool-use input (inline scripts) | 223,757 | ≤ 40,000 |
| Cost | $347.68 | ≤ $45 |
| CRITICALs vs. 19-item reference set | 8 | ≥ 12 |

The last row is the gate. If cost falls and recall falls with it, the design has
failed.

## 6. Quality preservation

### 6.1 Golden benchmark

```
tests/goldens/
├── tplink-dl110v2-1.0.11/   19 external CRITICALs + 38 own findings
├── asus-ax1800s/            wscd/UPnP and auth-path findings
└── unifi/                   confirmed CRITICALs
```

`audit.py bench` scores a run against a golden: recall (reference findings
rediscovered, matched on root cause and location, not title), precision (rung-4
findings surviving adversarial review), coverage (analyzed ÷ inventoried), and
cost per rung-4 finding.

Baseline recorded before any change: tplink = $347.68, 521.9M Σ context,
267.6k mean context, g ~1,150 tok/turn, 8/19 recall.

**Gate: no change merges if recall drops.** Cost targets are subordinate.

Two acknowledged limitations:

- **Non-determinism.** A single run is a noisy measurement. Milestone gates
  require two runs, and a one-finding delta is treated as noise. Between
  milestones, deterministic leading indicators are used instead: coverage
  percentage, surfaces opened, sweep hit counts, `not_audited` row count.
- **Benchmark cost.** A full re-run is itself expensive, so the benchmark runs at
  milestones only, never per-commit.

### 6.2 Machinery that must survive the refactor

Each row needs its test written before its code moves.

| Mechanism | Source | Destination | Proof |
|---|---|---|---|
| 18 Hard Exclusions / 10 Precedent / 3 Capability Validity | codebase-audit | `core/fp-rules.md` | rule-count assertion + golden FP cases |
| Adversarial review, 2-3 fresh reviewers per confirmed finding | codebase-audit | core, `decide` | precision metric on goldens |
| PoC rigor: real build, genuine attacker path, no harness/sanitizer/debugger stand-in | lessons 11-16 | `core/evidence-ladder.md` rung 4 | rung-4 schema requires the fields |
| Trust-boundary rule: patch the attacker, keep the victim stock | lesson 12 | core | rung-4 gate checklist |
| DoS/hang quantification plus a control run | lesson 13 | core | rung-4 gate checklist |
| Precise outcome wording; never "infinite" or "always" | lesson 14 | `core/report-format.md` | report lint |
| Attacker-advantage test applied first | lesson 16 | `core/fp-rules.md` | rule-ordering assertion |
| Marginal Gain Test | codebase-audit | core | golden FP cases |
| Lean report format, six headings, no CVSS table | phase6 | `core/report-format.md` | report lint |
| Writable-subagent rule | lesson 1 | `core/economics.md` | installer selftest |
| Evidence ladder vocabulary | grey-audit | `core/evidence-ladder.md` | vocabulary lint over artifacts |
| One-IDA-writer, `assert_database` at every batch boundary | grey-audit | `audit_core/extract.py` | unit test |
| Annotation journal as source of truth | grey-audit | `audit_core/annotations.py` | schema test |
| Resume-note discipline | both | core | phase-exit assertion |
| Dedup by root cause | both | `audit_core/db.py` | unit test |

Additions from this design must each demonstrate that they raise recall, not
merely that they exist: pivot rule, sweep-on-confirm, coverage denominator,
identity discipline, chain composition, two-lane hunt, device-state model,
unknowns-as-data.

## 7. Build stages

Risk rises only after the guard exists. **Each stage gets its own
implementation plan**; this spec is too large for a single one. Stages 0 and 1
may share a plan since neither changes behaviour that the benchmark measures.

**Stage 0 — Instrumentation and goldens.** No behaviour change, no quality risk.
`audit.py budget --report`, `tests/goldens/`, `audit.py bench`, baseline
recorded. Nothing else starts until this exists.

**Stage 1 — Cost wins that cannot touch quality.** Verified by budget report
alone, and ordered by the measured ranking in §1.2: R5 (`audit.py` verbs
replacing inline heredocs, ~10%); R4 preflight (part of the 19% prefix);
reasoning-effort and model tiering for mechanical work only (attacks the 27%
thinking term); R2 return contracts (~2%, free); installer fixes and
`selftest`; both installer defects from §3.2. Each independently shippable and
revertible.

**Stage 2 — Structural change.** Benchmark-gated. `audit_core` (db, extract,
annotations, coverage, sweep, budget); R1; R3; vendored into `codebase-audit`
with its existing phase semantics unchanged. Gate: tplink re-run twice — cost
must fall and recall must be ≥ 8/19.

**Stage 3 — Quality additions.** Each benchmarked separately so attribution is
possible. Pivot rule, sweep-on-confirm, coverage denominator, identity
discipline, chain composition. Then, last and alone, Sonnet tiering for
`surface`, L-sink and `fpcheck` — the one tiering change that can cost quality,
with precision measured before and after.

**Stage 4 — `firmware-audit`.** Full phase set from §4. Gate: tplink ≥ 12/19 at
≤ $45, and the asus golden must also pass to guard against overfitting.

**Stage 5 — Alignment.** Backport the core to `grey-audit`; build its Stage 2/3
(`hunt`, `fpcheck`, `verify`, `report`, Lanes B/C/D) on the shared spine.

`codebase-audit` keeps working at every stage; the core is vendored additively,
and each stage is a git tag pinnable with `install.sh --copy`.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Sonnet on `fpcheck` raises the false-positive rate | Ships last and alone, precision-gated; reverting is one table row |
| Return contracts starve the orchestrator of needed signal | Everything is in SQL and the artifact; widen the query, never the return |
| `extract/` snapshots go stale as IDA annotations improve | Extracts are versioned; `extract --refresh <fn>`; the journal stays authoritative for naming |
| Checkpoint-restart drops tacit working state | Journal plus resume note carry it; the benchmark detects it if they do not |
| Benchmark noise masks a real regression | Two runs per gate; deterministic leading indicators between gates |
| Goldens overfit to tplink | Three distinct targets (RTOS/MCU, Linux router, Linux AP); Stage 4 gate requires asus to pass as well |
| Monorepo migration disrupts `grey-audit`'s separate history | Submodule plus `sync.sh` fallback if `grey-audit` must stay separate |

## 9. Decisions taken

- Shared spine plus `firmware-audit` first, then backport — chosen over an
  economics-only retrofit, a standalone firmware skill, or finishing `grey-audit`
  Stage 2/3 first.
- Verification is a static ladder with measured reachability; hardware is a later
  activity gated on a buy decision; emulation is opportunistic only.
- Context ceiling 100k with checkpoint-restart, re-tuned against measured `g`.
- No separate skills for Windows drivers, DLLs, or services: those are
  `grey-audit` Lanes A, C and B, and lane granularity is already correct.

## 10. Open question

Whether `grey-audit` joins the monorepo or stays a separate repository consuming
the core as a submodule. The design assumes the monorepo; the fallback is
specified in §3.1 and §8.
