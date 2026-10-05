# codebase-audit — source: Automated Source-Only Audit (unattended, no live instance)

**Purpose**: Run the entire audit pipeline on source code **end-to-end with no human in the loop and no live instance** — for product teams who want a security report on a codebase before a release. Runs **recon → audit → fpcheck → report**; skips **deploy** and **verify** entirely.

**Entry**: User invokes the **source** run (see SKILL.md → *How phases are invoked per client*) or asks for an "automated source-only audit". A source tree must be present.
**Exit**: One consolidated `reports/audit-<timestamp>/report.md` (plus `audit.db`) and a printed counts-by-severity summary. No user gates, no live verification.

> **Workflow-accelerated (Claude Code + ultracode):** if the **Workflow tool is available to you**, drive this run as a deterministic workflow instead of by hand — see [../references/workflow-orchestration.md](../references/workflow-orchestration.md) (the `source` skeleton). Same source-only, gateless behavior; the script just fans out the within-phase work. Without the Workflow tool, follow the steps below inline.

---

## Automated source-only mode — precedence rules (READ FIRST)

You are running **unattended**. These rules **supersede** any conflicting instruction in the phase files you execute below:

1. **Never stop for user input.** Every "USER GATE", "ask the user", or "wait for confirmation" step in the referenced phases is **auto-resolved**: pick the best default and continue. Do not present gates; do not wait.
2. **Source only — read-only, no runtime, no mutation.** There is **no live instance**. Do **not** run the deploy phase; do **not** attempt any live PoC, `curl`, or runtime reproduction; do **not** edit, back up, restore, or write to any project/config file; do **not** start a process or send network traffic to a target. The only things you write are the audit's own `reports/` artifacts, `audit.db`, and memory notes. Every finding is recorded `verified='source-only'` (never `live-poc`).
3. **Auto-accept your own proposals.** Where a phase would ask the user to confirm (source-vs-IDA detection, the feature-group split), pick the correct/default option yourself and proceed.
4. **Best-effort network.** CVE / patch-bypass ingest is attempted but optional — if the network is unavailable, note it in the report and continue with pure source-level analysis. Never abort the run over a network failure.
5. **Compaction is automatic, not gated.** Between phases, compact context as the phase files advise (artifacts + resume note are already on disk), but do **not** pause for the user to do it.
6. **Abort only on a hard blocker**, with a clear one-line reason: no source tree found, or the target is IDA/binary-only (this mode is source-only — tell the user to run the interactive pipeline instead).

Optional free-text notes (focus area, scope hints) may arrive as `$ARGUMENTS`; honor them but never treat their absence as a reason to pause.

## Step 1 — recon (auto)

Execute [recon.md](recon.md) with these overrides:
- **Source detection (its Step 2):** auto-select the **source** target. If no source tree is detected (IDA/binary-only or empty), **abort** per precedence rule 6.
- **Feature groups (its Step 4):** propose the split per the size guidelines and **auto-accept it** — do not ask.
- **Mapping subagents (its Step 5):** run normally (writable subagents — see SKILL.md → *Cross-client tool mapping* — one per group, in parallel).
- **USER GATE (its Step 7):** **skip** — write the resume note, then continue straight to Step 2.

## Step 2 — audit (auto, source-only)

Execute [audit.md](audit.md) with these overrides:
- **CVE / patch-bypass ingest:** best-effort (rule 4) — attempt it; run `gh` **non-interactively** (ensure `GH_TOKEN` is set, or skip if `gh auth status` fails) so it can never open an auth prompt; on any auth/network error, record "CVE ingest skipped: network/auth unavailable" in the resume note + report and continue. Never abort or pause.
- **Deep-audit briefs — source-only:** render each group's brief exactly as audit.md Step 4 says, but pass the documented no-instance fallback:
  `--var test_instance='No test instance available. Provide source-level analysis only.'`
  The brief's test-instance block is conditional on an instance existing, so that value turns the live-verification steps (curl / requests / raw sockets) off by itself — do not supply URLs, credentials or any other live-instance detail.
- **`verified` is constrained (dispatch line, state it explicitly):** add to every deep-audit dispatch — *"There is no live instance. The only legal value for `cba_findings.verified` is `source-only`; never write `live-poc`."* Nobody is watching this run, so this constraint has to travel with the dispatch rather than rely on the subagent inferring it.
- **No mutation (rule 2):** **drop audit.md Step 4's "Live-instance hygiene" bullet entirely** — subagents must NOT edit, back up, or restore any project/config file. Read-only source analysis only.
- **USER GATE:** **skip** — continue straight to Step 3.

## Step 3 — fpcheck (auto)

Execute [fpcheck.md](fpcheck.md) as written (it is already **static-only**) with these overrides:
- Run the parallel FP-check subagents and populate `cba_fp_verdicts` exactly as normal.
- **Skip** the "open verify forks" step and its gate — there is no verification in this mode. Continue straight to Step 4 with the TRUE_POSITIVE list.

## Step 4 — report (auto, consolidated source-only)

Execute [report.md](report.md) **Mode B (source-only, consolidated)** in this orchestrator — there is no live instance and no forks:
- Write ONE `reports/audit-<timestamp>/report.md` covering all **TRUE_POSITIVE** verdicts from `cba_fp_verdicts`, ordered by source-assessed severity, with one section per finding using the six headings (title, Affected Version, Summary, Root Cause, Steps to reproduce, Impact).
- **Steps to reproduce is a reproduction GUIDE only:** the concrete steps, inputs, and conditions an attacker or maintainer would use to trigger each bug, derived from source (`cba_findings.poc` + the per-group `artifacts/G<n>-findings.md`). There is no live instance: do **not** run a PoC and do **not** paste or fabricate any request/response output. Label it as a source-level guide.
- **Caveat (mandatory):** state prominently near the top of `report.md` that all findings are static (source-level) true-positives that survived false-positive review but were **NOT live-verified**; running the interactive `verify` phase against a live instance is recommended before any external disclosure.
- No `disclosure-summary.md`, no per-finding `<id>-vuln-report.md` files, no CVSS / severity tables. Do not pause; do not disclose; continue to Step 5.

## Step 5 — final summary (printed, no gate)

Print a concise summary for the operator:
- Path to `reports/audit-<timestamp>/report.md`.
- Counts of TRUE_POSITIVE findings by source-assessed severity (CRITICAL / HIGH / MEDIUM / LOW / INFO).
- A one-line reminder that findings are source-only (not live-verified) and that `verify` against a live instance is recommended before disclosure.

Do **not** perform any external disclosure. Stop.

## Quality checks

- [ ] recon, audit, fpcheck, report all completed **without pausing for input**
- [ ] No deploy phase ran; no live-instance / `curl` / PoC was attempted; every finding is `verified='source-only'`
- [ ] One consolidated `report.md` + `audit.db` exist under `reports/audit-<timestamp>/` (no `disclosure-summary.md`, no per-finding files)
- [ ] The report carries the source-only / not-live-verified caveat
- [ ] Final severity-counts summary was printed; no disclosure performed
