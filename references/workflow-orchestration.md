# Workflow-accelerated mode (Claude Code + ultracode)

**When to use:** ONLY on Claude Code when the **Workflow tool is available to you** (ultracode is on, or a workflow opt-in) — i.e. you can actually call the `Workflow` tool. This is an *optional accelerator* for the full `/codebase-audit` pipeline and the `source` run. If you do **not** have the Workflow tool (GitHub Copilot, OpenAI Codex, or Claude without ultracode), **ignore this file** and run the phases the normal way: the full pipeline **human-gated** between phases, `source` **unattended-inline**. This is a Claude-only accelerator layered on top of the client-agnostic default — it never replaces it.

**What it changes:** one deterministic workflow script drives the whole run instead of you executing phases by hand. Under ultracode both flows run **gateless, end-to-end**:

- `/codebase-audit` (full): recon → deploy → audit → fpcheck → **verify (serial)** → report.
- `source`: recon → audit → fpcheck → report (source-only; no deploy, no verify).

It also **sidesteps the verify-fork resume bug** (lessons-learned #17): the workflow uses fresh `agent()`s, not `/branch` forks, so nothing drifts the session's working directory.

## Hard rules (the Workflow tool's real constraints — get these wrong and it breaks)

1. **The SCRIPT does the fan-out — never one agent "running a whole phase".** Subagents cannot spawn subagents (one nesting level only). So every per-group / per-batch / per-finding fan-out MUST be expressed in the *script* with `parallel()` / `pipeline()` / a `for`-loop, where each `agent()` does exactly **one** unit (one group, one batch, one finding). A single `agent("run the whole audit phase")` would silently **serialize** that phase's internal work.
2. **Each `agent()` executes the existing `.md` for its unit — not a slash command.** Workflow agents run prompts; they cannot invoke `/codebase-audit:<phase>`. The prompt tells the agent to read `SKILL.md` + the relevant `workflows/<phase>.md` (+ `references/…`) and do its one unit. (This is also why there is **no recursion**: a recon step reads `recon.md`; it does not "read SKILL.md and run the full pipeline".)
3. **No nested workflows.** A `workflow()` call inside an agent throws — one workflow level only.
4. **Phases are sequential; state lives on disk.** `await` each phase before the next. Hand state between phases via the audit DB (`<AUDIT_DIR>/audit.db`) and the resume note — exactly as the inline pipeline does. Pass the absolute project root + `AUDIT_DIR` into every `agent()` (via the prompt / `args`).
5. **Run from — and keep — the project root.** Launch the workflow with the orchestrator at the project root; every `agent()` operates from the project root (artifact paths are relative to it). Never `cd` into the audit dir (Essential Principle #10).
6. **Verify is serial.** Anything that touches the live instance runs **one finding at a time** — a strict `for`-await loop (concurrency 1). Parallel live PoCs race on the shared instance's config backup/restart and produce chaos. The per-finding *static* adversarial review (verify Step 2) may fan out 2–3 **read-only** reviewers, since they re-derive from source + the captured evidence and never touch the instance — but only **one finding is ever live against the instance at a time**.
7. **Never auto-disclose.** Produce the report(s) - live full pipeline: one `artifacts/<id>-vuln-report.md` per confirmed finding, written inside the verify step (no consolidation, no `disclosure-summary.md`); source: one consolidated `report.md` with source-level reproduction guides - plus `audit.db`, print a severity summary, and stop. No external disclosure without a human.

## Skeleton — `source` (source-only, gateless)

Illustrative — adapt it; the authoritative methodology for each unit lives in the phase/reference docs the agents read. `SKILL`/`recon.md`/etc. are paths under your install root (`~/.claude/skills/codebase-audit/`); pass `root` + `auditDir` via the Workflow `args`.

```javascript
export const meta = {
  name: 'codebase-audit-source',
  description: 'Automated source-only audit: recon → audit → fpcheck → report, unattended',
  phases: [{ title: 'Recon' }, { title: 'Audit' }, { title: 'FP-check' }, { title: 'Report' }],
}

const ROOT = args.root                 // absolute project root
const AUDIT = args.auditDir             // <ROOT>/reports/audit-<ts>
const SK = args.skillDir               // ~/.claude/skills/codebase-audit
const ref = `Read ${SK}/SKILL.md and work from the project root ${ROOT} (never cd into ${AUDIT}).`

const GROUPS = { type:'object', additionalProperties:false, required:['groups'], properties:{
  groups:{ type:'array', items:{ type:'object', additionalProperties:false, required:['id','name','dirs'],
    properties:{ id:{type:'string'}, name:{type:'string'}, dirs:{type:'array',items:{type:'string'}} } } } } }
const IDS = { type:'object', additionalProperties:false, required:['ids'], properties:{ ids:{type:'array',items:{type:'string'}} } }
const BATCHES = { type:'object', additionalProperties:false, required:['batches'], properties:{ batches:{type:'array',items:{type:'array',items:{type:'string'}}} } }

phase('Recon')
// One agent does recon.md Steps 1–4 in SOURCE mode and PROPOSES groups — it does NOT spawn the mapping subagents (the script fans those out).
const recon = await agent(
  `${ref} Also read ${SK}/workflows/recon.md, references/phase0-source-detection.md, references/phase2-feature-mapping.md.
   Automated SOURCE mode: auto-select the SOURCE target (ABORT if binary/IDA-only); the audit dir is ${AUDIT} (create if missing); do Steps 1–4 and PROPOSE the feature-group split. Do NOT run the mapping subagents. Return the groups.`,
  { phase:'Recon', schema: GROUPS })

await parallel(recon.groups.map(g => () =>                       // fan-out: one writable agent per group
  agent(`${ref} Read ${SK}/workflows/recon.md (Step 5) + references/phase2-feature-mapping.md. Map feature group ${g.id} "${g.name}" (dirs: ${g.dirs.join(', ')}) for a SOURCE-only audit: write ${AUDIT}/files/${g.id}-mapping.md and INSERT into ${AUDIT}/audit.db (cba_attack_surface, cba_security_observations). Return counts.`,
    { label:`map:${g.id}`, phase:'Recon' })))

await agent(`${ref} Read references/resume-note-template.md and write the resume note for ${AUDIT} (recon DONE).`, { phase:'Recon' })

phase('Audit')
await agent(`${ref} Read ${SK}/workflows/audit.md (Steps 1–3). Best-effort CVE/patch-bypass ingest into ${AUDIT}/audit.db — run gh NON-interactively; on auth/network failure note "CVE ingest skipped" and continue. Do NOT run the deep-audit subagents.`, { phase:'Audit' })

await parallel(recon.groups.map(g => () =>                       // fan-out: one writable agent per group
  agent(`${ref} Read ${SK}/workflows/audit.md (Step 4) + references/phase4-deep-audit.md. Deep-audit group ${g.id} SOURCE-ONLY: no live instance, no live PoC, no config edits; every finding verified='source-only'. Write ${AUDIT}/artifacts/${g.id}-findings.md + INSERT cba_findings. Return severity counts.`,
    { label:`audit:${g.id}`, phase:'Audit' })))

phase('FP-check')
const fp = await agent(`${ref} Read ${SK}/workflows/fpcheck.md + references/phase5-fp-check.md. Create cba_fp_verdicts in ${AUDIT}/audit.db and build static FP-check batches (8–12 findings each) from cba_findings. Return the batches (arrays of finding ids). Do NOT run the FP subagents.`, { phase:'FP-check', schema: BATCHES })

await parallel(fp.batches.map((b, i) => () =>                    // fan-out: one writable agent per batch
  agent(`${ref} Read ${SK}/workflows/fpcheck.md + references/phase5-fp-check.md. FP-check batch ${i+1} (findings: ${b.join(',')}) — STATIC review only: 18 Hard Exclusions + 10 Precedent rules + Marginal Gain Test. Write cba_fp_verdicts + ${AUDIT}/artifacts/phase5-B${i+1}.md.`,
    { label:`fp:batch${i+1}`, phase:'FP-check' })))

phase('Report')
// Mode B: ONE consolidated report; Steps to reproduce are source-level guides (no execution, no output).
await agent(`${ref} Read ${SK}/workflows/report.md (Mode B) + references/phase6-report.md. Write ONE ${AUDIT}/report.md covering all TRUE_POSITIVE verdicts, one section per finding (six headings). Steps to reproduce = a source-level reproduction GUIDE only (no PoC run, no captured output). State prominently that findings are source-only, NOT live-verified. No disclosure-summary.md, no per-finding files, no CVSS/tables. Do NOT disclose.`, { phase:'Report' })

log(`Source-only audit complete — ${AUDIT}/report.md (findings are source-only, NOT live-verified; run verify against a live instance before disclosure).`)
```

## Skeleton — full `/codebase-audit` (gateless under ultracode: adds deploy + SERIAL verify)

Recon / audit / fpcheck are the same as the `source` skeleton **minus the source-only constraints** (audit may attempt live PoC). There is **no separate orchestrator Report phase** in the full pipeline - each confirmed finding's report is written inside the Verify loop (report.md Mode A). The deltas (deploy + serial verify-then-report):

```javascript
const DEPLOY = { type:'object', additionalProperties:false, required:['live'], properties:{
  live:{type:'boolean'}, baseUrl:{type:'string'}, livenessCmd:{type:'string'} } }

phase('Deploy')   // after Recon, before Audit
const dep = await agent(`${ref} Read ${SK}/workflows/deploy.md + references/live-instance-template.md. Bring up a LOCAL-MANAGED live instance (Docker compose / make run / build) and write the live-instance note. If you cannot bring one up unattended (e.g. it needs operator-supplied URLs/tokens), do not block — return live:false. Return {live, baseUrl, livenessCmd}.`,
  { phase:'Deploy', schema: DEPLOY })
const LIVE = dep.live   // if false, the audit + report stay source-only and Verify is skipped (auto-degrade)

// ... Audit + FP-check as above (audit may attempt live PoC only when LIVE) ...

phase('Verify')   // STRICTLY SERIAL — one finding at a time
if (LIVE) {
  const tps = await agent(`${ref} SELECT finding_id FROM cba_fp_verdicts WHERE verdict='TRUE_POSITIVE' in ${AUDIT}/audit.db. Return the ids.`, { phase:'Verify', schema: IDS })
  for (const id of tps.ids) {                                    // plain for-await => concurrency 1; do NOT wrap in parallel()
    const v = await agent(
      `${ref} Read ${SK}/workflows/verify.md + the live-instance note. LIVE-verify finding ${id} ONLY, against ${dep.baseUrl} (liveness: ${dep.livenessCmd}). Build the PoC, capture \`curl -i\`, decide CONFIRMED/REFUTED/INCONCLUSIVE, write ${AUDIT}/artifacts/verify-${id}.md. Back up any config before editing and restore at end. You are the ONLY verifier touching the instance right now.`,
      { label:`verify:${id}`, phase:'Verify' })
    if (v && /CONFIRMED/.test(v)) {                              // per-finding review — read-only reviewers, safe to parallelize
      const lenses = ['real-bug', 'valid-PoC', 'intentionally-vulnerable-or-test-code']
      await parallel(lenses.map(lens => () =>
        agent(`${ref} Read ${SK}/workflows/verify.md (Step 2). FRESH, neutral reviewer of finding ${id} via the "${lens}" lens — re-derive from source + the captured evidence in ${AUDIT}/artifacts/verify-${id}.md. Do NOT touch the live instance. Return verdict + one-line reason.`,
          { label:`review:${id}:${lens}`, phase:'Verify' })))
      await agent(`${ref} Reconcile the three reviewer verdicts for ${id} into ${AUDIT}/artifacts/verify-${id}.md (Adversarial review section); if overturned, update its Status/Severity.`, { phase:'Verify' })
      // report (Mode A) — write the per-finding vuln report IF it survived review as a real vulnerability
      await agent(`${ref} Read ${SK}/workflows/report.md (Mode A) + references/phase6-report.md. If finding ${id} is still CONFIRMED as a real, worth-reporting vuln, write ${AUDIT}/artifacts/${id}-vuln-report.md (six headings; inline the PoC + paste the REAL captured output from verify-${id}.md; stage runnable scripts in poc/ referenced as poc/<name>, never a reports/audit path; lean style, no em-dashes). If it was overturned, skip the report.`,
        { label:`report:${id}`, phase:'Verify' })
    }
  }
} else {
  log('No live instance — verify skipped; findings remain source-only (not live-verified).')
}
```

## Notes

- The verify `for`-await loop is the whole point of serial verify: **do not** convert it to `parallel()`/`pipeline()`. Only the read-only per-finding review reviewers fan out.
- Resume after a stop with `Workflow({scriptPath, resumeFromRunId})` — completed `agent()` calls return cached results, so a re-run continues where it left off.
- This file is **guidance**. Adapt the skeleton to the target; keep the methodology in the phase/reference docs the agents read, not duplicated in the script.
