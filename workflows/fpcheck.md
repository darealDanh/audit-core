# codebase-audit — fpcheck: Parallel Static False-Positive Elimination

**Purpose**: Eliminate false positives via **static review only** — re-read every cited source file, apply 18 Hard Exclusions + 10 Precedent rules + Marginal Gain Test. No live testing in this phase (that's `verify`).

**Entry**: Audit done, `cba_findings` populated.
**Exit**: Every finding has a verdict in `cba_fp_verdicts`, per-batch artifacts written, resume note updated, user gate before verification forks.

---

## Step 1 — Confirm the verdicts schema is applied

The `cba_fp_verdicts` table is created by `audit.py init`.

## Step 2 — Build batches

Read [../references/phase5-fp-check.md](../references/phase5-fp-check.md) for full batching rules. Quick version:

- **8-12 findings per batch** (3 min, 12 max)
- Batches by **feature group affinity** (shared code context = less re-reading)
- Spread CRITICAL/HIGH findings across batches (don't load them all in one)
- If you spot candidate duplicates pre-batch (e.g., same file:line cited twice), put them in the **same** batch

Letter your batches: A, B, C, D, E, F …

## Step 3 — Pre-flag known dedup pairs

Before launching FP-check, query for finding pairs that cite the same file:line or describe the same root cause across groups. Put a note in the relevant batch prompt:

> Suspected duplicates: `G<a>-F<b>` ↔ `G<c>-F<d>` (same root cause at `<file>:<line>`). If confirmed dup, mark `verdict=DUPLICATE` and set `merged_into` to the canonical (higher-confidence) finding.

## Step 4 — Spawn parallel FP-check subagents

**Agent type**: a **writable** subagent — a read-only agent cannot write the
SQL inserts, so ALL verdicts would be lost. **Model:** strongest tier, medium
effort — the effort is tiered down because FP-check applies fixed rules to a
bounded list, but it decides which findings survive, so the model is not. See
SKILL.md → *Cross-client tool mapping* and *Model and effort tiering*.

Render each batch's brief and dispatch its path, never its contents
(spec rule R6). Set these per batch first — `AUDIT_DIR` is the only variable an
earlier step defined:

    BATCH=A                                       # batch letter from Step 2
    IDS='G1-F2, G1-F5, G3-F1, G3-F4'              # the findings in this batch
    SRC='Source tree at the project root; read any file under it.'

    python3 __SKILL_DIR__/audit.py brief --phase fpcheck --unit "$BATCH" --run "$AUDIT_DIR" \
      --var batch_id="$BATCH" --var finding_ids="$IDS" \
      --var run_dir="$AUDIT_DIR" --var source_access="$SRC" \
      --var artifact_path="$AUDIT_DIR/artifacts/phase5-$BATCH.md"

Every `--var` above is required, and an empty value is rejected as hard as a
missing one: the renderer fails loudly rather than handing a subagent a
half-filled brief.

Spawn ONE subagent per batch, ALL in parallel.

The brief carries the method, the rule references and the return contract. Two
things it does not carry, which belong in the dispatch or in your own review of
the batch:

- The Marginal Gain Test (HE-17) is the most common false-positive source for
  operator-config findings — if the operator could already do X through
  documented configuration, a second way to do X is not a vulnerability.
- The per-batch artifact at `<AUDIT_DIR>/artifacts/phase5-<batch>.md`
  must document, per verdict: the re-read excerpt of the cited file, which
  exclusion or precedent rule applied (for false positives), the reason for
  keeping (for true positives), and the merge target (for duplicates).

Each subagent returns one line; read the verdicts from `cba_fp_verdicts`, not
from the return text.

**IMPORTANT for this phase**: Subagents must NOT use the live instance, must NOT edit any project files, and must NOT modify `cba_findings`. Static review only. Per-finding live testing is the next phase (`verify`).

## Step 5 — Sanity-check verdict completeness

```sql
SELECT
    (SELECT COUNT(*) FROM cba_findings) AS findings,
    (SELECT COUNT(*) FROM cba_fp_verdicts) AS verdicts,
    (SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict='TRUE_POSITIVE') AS tp,
    (SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict='FALSE_POSITIVE') AS fp,
    (SELECT COUNT(*) FROM cba_fp_verdicts WHERE verdict='DUPLICATE') AS dup;
```

If `findings != verdicts`, identify the missing batch and re-spawn just that one. (Common cause: agent stalled — see [../references/lessons-learned.md](../references/lessons-learned.md).)

## Step 6 — Assign final IDs

Order TPs by severity (CRITICAL → HIGH → MEDIUM → LOW), then by group ID, then by original finding ID. Assign sequential `F-1, F-2, …`.

```sql
-- conceptual; do this in app code with proper ordering
UPDATE cba_fp_verdicts SET final_id = 'F-' || row_number
WHERE verdict='TRUE_POSITIVE';
```

## Step 7 — Resume-note rewrite + fork plan

Rewrite the resume note with:

- Phase status: recon/deploy/audit/fpcheck DONE; **verify IN PROGRESS via FORKED conversations**
- Final verdict tally (TP / FP / DUP counts)
- **List which findings already have live-PoC** (from `cba_findings.verified='live-poc'` carried over from audit phase, plus any new live-PoC captured by FP-check artifacts) — these do NOT need a verify fork *(Automated `source` mode: there is no live-PoC and no verify fork — record all TPs as source-only and skip the fork inventory / fork prompt; see [source.md](source.md))*
- **Fork inventory** for the remaining TPs needing live verification: **one fork per finding** (each verify fork/agent covers exactly one finding)
- The **fork prompt template** ready to paste (see [verify.md](verify.md))

## Step 8 — USER GATE

> _Automated `source` mode supersedes this gate — skip the verify forks and proceed straight to report without pausing (see [source.md](source.md))._

Present:

> FP-check complete. N verdicts: X TP / Y FP / Z DUP. K TPs already have live PoC; M still need live verification.
>
> Next: open one forked conversation **per finding** that needs live verification, **from the project root**, and run them **one at a time** (serial — they share the live instance), using the fork prompt in the resume note. Each fork verifies a single finding, writes `artifacts/verify-<id>.md`, and - if confirmed as a real vuln - writes its own `artifacts/<id>-vuln-report.md` (the report phase runs in the fork; no orchestrator consolidation). (Claude Code + ultracode: drive this as a serial workflow loop instead — see [../references/workflow-orchestration.md](../references/workflow-orchestration.md).)
>
> **Before forking, confirm your working directory is the project root** — `/branch` and forks inherit the current cwd, and Claude's resume picker groups sessions by it. If the cwd has drifted into `reports/audit-<ts>/`, `cd` back to the project root first, or the forks won't show under this project in the resume picker (lessons-learned #17).
>
> When all forks finish: come back here and say **go report** for Phase 6.
>
> **Before opening verify forks, run a manual compact here** (`/compact` in Claude Code or Codex CLI, Compact in Copilot Chat). The orchestrator only needs the FP verdicts + resume note while the verify forks run — everything else (per-finding source dives, dedup reasoning) is already on disk. Each verify fork (which verifies, reviews, and writes its own `<id>-vuln-report.md`) starts in its own clean context anyway, so this compact is purely for the orchestrator.

## Quality Checks

- [ ] `cba_fp_verdicts` row count == `cba_findings` row count
- [ ] No verdict is NULL or "UNKNOWN"
- [ ] Every DUPLICATE has a valid `merged_into` finding_id
- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule
- [ ] Per-batch artifacts exist for all batches A..N
- [ ] Resume note includes the fork prompt template + fork inventory
