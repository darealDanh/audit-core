# Resume Note Template

Save to **`/memories/session/<project>-audit-resume.md`**.

Rewrite this file **at the end of every major phase**. Goal: a fresh orchestrator (post-compaction or post-resume) can read this single file + the live-instance note and pick up exactly where the last phase ended.

---

## Template (copy and fill)

````markdown
# <Project> Audit — Resume State

**Audit dir:** `<absolute-path>/reports/audit-<timestamp>/`
**SQLite DB:** `reports/audit-<timestamp>/audit.db`
**Live instance:** see `/memories/repo/<project>-live-instance.md` (proxy <port>, API <port> — running)

## Pipeline status
- Phase 0/1 (recon): DONE | NOT STARTED — <1-line summary>
- Phase 2 (feature mapping): DONE | NOT STARTED — <N groups, M observations>
- Phase 3 (known findings ingest): DONE | NOT STARTED — <N advisories>
- Phase 4 (deep audit): DONE | NOT STARTED — <N findings>
- Phase 5 (fpcheck): DONE | NOT STARTED — <N TP / N FP / N DUP>
- Phase 5.5 (verify forks): IN PROGRESS | NOT STARTED — <N forks open, N artifacts complete>
- Phase 6 (report): DONE | NOT STARTED

## Feature groups
| ID | Name | Mapping file | Status |
|---|---|---|---|
| G1 | … | `files/G1-mapping.md` | mapped/audited |
| … | … | … | … |

## Re-orient after a restart (paste-and-run)
```bash
python3 __SKILL_DIR__/audit.py status --db reports/audit-<ts>/audit.db
python3 __SKILL_DIR__/audit.py coverage --db reports/audit-<ts>/audit.db
```

## Phase-2 observation counts  (after recon)
G1: <H/M/L> | G2: <H/M/L> | …
Total: <N> observations.

## Phase-4 finding counts  (after audit)
| Group | CRIT | HIGH | MED | LOW | Notes |
|---|---|---|---|---|---|
| G1 | … | … | … | … | … |
| … | … | … | … | … | … |

**Top patch-bypass discoveries (vendor will love these):**
1. **<finding-id> (<sev>, conf <N>)** — <file:line> — <one-line root cause> — bypasses <CVE/GHSA>
2. …

## Live-PoC status
- Verified live: <list of finding IDs>
- Source-only awaiting fork: <list>
- Infra-blocked (won't verify): <list with reason>

## Phase 5.5 — verify fork strategy

**Why fork:** keeps curl/HTTP noise out of orchestrator context; parallelizable per finding; failure isolation.

**Already live-verified (don't re-verify; pull PoC from existing artifact):**
- <list with artifact path>

**Fork inventory:**
| Fork | Findings | Notes |
|---|---|---|
| A | <list> | <e.g. Tier-1 high-priority> |
| B | <list> | … |
| C | <list> | … |
| D — infra-blocked (document only) | <list> | Mark as `not-reproducible-without-extra-infra` |

**Each fork must:**
1. Read this resume note + `/memories/repo/<project>-live-instance.md` first
2. For each finding, read its section in `artifacts/G<n>-findings.md`
3. BACK UP any config before edits (`cp <file> /tmp/<file>.bak.fork-<X>-<finding-id>`); RESTORE at end
4. **WARNING:** user may have hand-edited config files between phases — re-read before editing
5. Reproduce PoC against live instance
6. Write `artifacts/verify-<finding-id>.md` per finding (status: CONFIRMED/REFUTED/INCONCLUSIVE)
7. **Adversarially review** each CONFIRMED finding with 2-3 fresh subagents — neutral prompt (code + claim + PoC only, no verdict/severity); reconcile and record the outcome in the artifact (verify.md Step 2)
8. Do NOT modify `cba_findings` or `cba_fp_verdicts`
9. Return summary table

**Fork prompt template (paste into each forked conversation):**
```
You are a forked conversation from <project> audit `audit-<timestamp>`. Workspace: <path>. **Work from the project root `<path>` — the artifact paths below are relative to it; never run from inside `reports/`.** Read /memories/session/<project>-audit-resume.md (Phase 5.5 section) AND /memories/repo/<project>-live-instance.md first. Your scope: live-verify finding <ID> (one finding per fork) as Fork <X>. If you open several forks, run them ONE AT A TIME — they share the live instance. Run this skill's verify phase for that finding (Claude: `/codebase-audit:verify <ID>`; Codex: `$codebase-audit verify <ID>`; Copilot: `/codebase-audit verify <ID>`); if you need the raw steps, read `<SKILL_DIR>/workflows/verify.md` (the orchestrator substitutes <SKILL_DIR> with its own install root — e.g. ~/.claude/skills/codebase-audit, ~/.agents/skills/codebase-audit (Codex), or ~/.copilot/skills/codebase-audit). Write the artifact at reports/audit-<ts>/artifacts/verify-<ID>.md; if it is CONFIRMED, adversarially review it with fresh read-only subagents (verify.md Step 2) and record the outcome in the artifact. Return the result when done.
```

## Phase 6 (report)
- **Live:** each verify fork wrote its finding's `reports/audit-<ts>/artifacts/<id>-vuln-report.md` (lean format; real PoC + captured output; runnable scripts in the project-root `poc/`) per `references/phase6-report.md`. There is **no** orchestrator consolidation and **no** `disclosure-summary.md`.
- **Source-only:** the orchestrator wrote ONE consolidated `reports/audit-<ts>/report.md` (Steps to reproduce are source-level reproduction guides; findings are not live-verified).

## Quirks / Lessons specific to this audit
- <e.g., "read-only subagents returned no findings — re-ran with a writable agent (Claude/Copilot general-purpose)">
- <e.g., "User hand-edited .docker_compose/rules.json on <date>">
- <any non-obvious environment thing future-me would forget>

## Resumption command
After compact, run:
```bash
ls <audit-dir>/files/ <audit-dir>/artifacts/
sqlite3 <audit-dir>/audit.db ".tables"
docker compose -f <compose-file> ps  # or equivalent live-instance health check
```
Read this file + `/memories/repo/<project>-live-instance.md` and continue from the next NOT STARTED phase.
````

---

## Rules for the resume note

1. **One file per audit.** Don't fragment.
2. **Rewrite it fully at each phase end** — don't append crufty stale sections.
3. **Update phase status FIRST** — that's what a fresh orchestrator reads first.
4. **Include SQL re-orient queries** — paste-and-run, not "you could query the DB".
5. **Be explicit about subagent quirks** — e.g., which agent type to use, which failed last time.
6. **Always include the next step's launch command/prompt** — the orchestrator should never have to derive it.
7. **Keep under 200 lines.** Resume note is auto-loaded into context; brevity is critical. Move detailed analysis into the artifact files in `audit-<ts>/artifacts/`.
