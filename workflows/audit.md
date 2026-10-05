# codebase-audit — audit: Known-Findings Ingest + Parallel Deep Audit

**Purpose**: Load prior CVEs/GHSAs and **mine them for patch-bypass surface**, then spawn one deep-audit subagent per feature group to hunt for vulnerabilities. End by writing the resume note.

**Entry**: Recon + deploy complete.
**Exit**: All groups audited, findings in SQL + per-group artifacts, resume note updated, user gate before fpcheck.

---

## Step 1 — Known findings ingest (Phase 3)

For each external source, populate `cba_known_findings`:

### 1a. GitHub Security Advisories (GHSA) for the repo
```bash
gh api repos/<owner>/<repo>/security-advisories --paginate | jq -r '.[] | "\(.ghsa_id)|\(.severity)|\(.summary)"'
```

### 1b. CVEs mentioning the project
```bash
gh api search/issues --raw-field q="CVE in:title repo:<owner>/<repo>" --paginate
```

### 1c. CHANGELOG / SECURITY.md scan
```bash
grep -nEi 'cve-|ghsa-|security|advisory|fix.*injection|fix.*bypass' CHANGELOG.md SECURITY.md
```

### 1d. Dependency advisories
```bash
gh api repos/<owner>/<repo>/dependabot/alerts --paginate 2>/dev/null
```

For each advisory, record:

```sql
INSERT INTO cba_known_findings(id, title, location, source, patched_in, severity, raw)
VALUES (?,?,?,?,?,?,?);
```

## Step 2 — Patch-bypass mining (HIGH-VALUE STEP)

For each meaningful advisory, **fetch the patch commit(s)** and identify:

1. **Files the patch touched** — were they the ONLY sites of the vulnerable pattern, or are there sibling files that have the same root cause untouched? (This is where the highest-severity findings come from in real audits.)
2. **Behavioral assumptions** — did the patch add a flag, a header check, a length cap? Can an attacker make the assumption false?
3. **Adjacent code paths** — same input, different code path that wasn't visited.

Examples of patch-bypass classes that recurred in real audits:
- `X-Forwarded-*` trust only fixed in proxy code but `/decisions` API still trusts blindly.
- URL-encoding decoded once in matcher path, raw in upstream forward path.
- `aud` validation only applied to one token type but not another.

Save the patch-bypass intel to **`<AUDIT_DIR>/files/known-findings.md`** organized per advisory:

```markdown
## GHSA-xxxx-yyyy-zzzz (CVE-YYYY-NNNNN) — <title>
Patched in: <commit>
Patched files: <list>
**Probe these sibling/adjacent sites for the same root cause:**
- `<file>:<lines>` — <why suspect>
```

## Step 3 — Confirm the findings schema is applied

The schema is already applied by `audit.py init` (recon Step 1). If you are
entering this phase against an existing run directory, re-apply it safely
with `python3 __SKILL_DIR__/audit.py init --root . --timestamp <existing-ts>`.

## Step 4 — Parallel deep-audit subagents

**Agent type**: a **writable** subagent (must write artifacts + SQL — not a
read-only one). **Model:** strongest tier, high effort — this is the phase
where adversarial reasoning earns its cost. See SKILL.md → *Cross-client tool
mapping* and *Model and effort tiering*.

Render each group's brief and dispatch its path, never its contents
(spec rule R6). Set these per group first — `AUDIT_DIR` is the only variable an
earlier step defined:

    G=G1                                          # stable group id
    NAME='Authentication and session handling'    # the group's name
    SRC='Source tree at the project root; read any file under it.'
    # Step 2's patch-bypass intel. CVE ingest is best-effort (see source.md):
    # if it was skipped, known-findings.md was never written, and an empty
    # value is rejected — which would hard-fail an unattended run. Fall back
    # the way recon.md does, so the brief still says what is known.
    KNOWN="$(cat "$AUDIT_DIR/files/known-findings.md" 2>/dev/null || true)"
    KNOWN="${KNOWN:-No prior advisories ingested for this target.}"
    # Live run: the deploy phase's instance details, one line (see
    # ../references/phase4-deep-audit.md -> Test instance details).
    TEST_INSTANCE='Test instance: http://127.0.0.1:8080 (proxy) / :8081 (API). Auth: create test accounts via admin/admin123 - do NOT modify the admin account. Config is bind-mounted at .docker_compose/. Available for: HTTP requests, API testing. Not available for: destructive testing, persistence, data exfiltration.'

    python3 __SKILL_DIR__/audit.py brief --phase audit --unit "$G" --run "$AUDIT_DIR" \
      --var group_id="$G" --var group_name="$NAME" \
      --var run_dir="$AUDIT_DIR" \
      --var mapping_path="$AUDIT_DIR/files/$G-mapping.md" \
      --var artifact_path="$AUDIT_DIR/artifacts/$G-findings.md" \
      --var source_access="$SRC" --var known_findings="$KNOWN" \
      --var test_instance="$TEST_INSTANCE"

Every `--var` above is required, and an empty value is rejected as hard as a
missing one: the renderer fails loudly rather than handing a subagent a
half-filled brief. *(Automated `source` mode: there is no live instance — pass
`--var test_instance='No test instance available. Provide source-level
analysis only.'` See [source.md](source.md).)*

Spawn ONE subagent per feature group, ALL in parallel.

The brief carries the assignment, the hunt list, the rules of engagement, the
patch-bypass probe instruction, the test-instance conduct rules (including the
Do NOT list) and the return contract. The dispatch adds only what the brief
cannot know:

- Live-PoC policy: attempt a live PoC for HIGH/CRITICAL findings where feasible;
  mark `verified='live-poc'` if reproduced, otherwise `verified='source-only'`
- Live-instance hygiene: **back up any config file before editing** (e.g.
  `cp .docker_compose/rules.json /tmp/rules.json.bak.G<n>`) and restore at the
  end *(Automated `source` mode: omit this — no config edits, read-only source
  analysis only, see [source.md](source.md))*

Do not paste the mapping file's contents. The brief passes its path and the
subagent reads it itself. Each subagent returns one line; read the findings
from `cba_findings`, not from the return text.

## Step 5 — Subagent failure handling

If a subagent returns "no response" or returns analysis without writing the SQL/artifact:

1. Check whether a read-only agent was used by mistake — re-run with a **writable** subagent (Claude/Copilot: `general-purpose`, not `Explore`; Codex `spawn_agent` is always writable, so rule this out).
2. If the agent ran but its findings only exist in its return blob: materialize them yourself by writing the `artifacts/G<n>-findings.md` file and running the SQL inserts directly. Do NOT lose findings.
3. Update the resume note's "Quirks to remember" section so future runs avoid the same trap.

## Step 6 — Update group status

```sql
UPDATE cba_feature_groups SET status='audited' WHERE id IN (...);
```

## Step 7 — Summary + resume note rewrite

Present a finding-count table by group × severity:

```sql
SELECT group_id, severity, COUNT(*) FROM cba_findings GROUP BY 1,2 ORDER BY 1,2;
```

Rewrite the resume note ([../references/resume-note-template.md](../references/resume-note-template.md)) to reflect:

- Phase status: recon DONE, deploy DONE, audit DONE, fpcheck NOT STARTED
- Phase-4 finding counts table
- **Top patch-bypass discoveries** (these are the highest-value items for vendor disclosure — call them out explicitly)
- Live-PoC status (how many `verified='live-poc'` vs `'source-only'`)
- Updated "Quirks to remember"

## Step 8 — USER GATE

> _Automated `source` mode supersedes this gate — proceed straight to fpcheck without pausing (see [source.md](source.md))._

Present:

> Deep audit complete. N findings across M groups: X CRITICAL, Y HIGH, Z MEDIUM, W LOW. K already live-verified.
>
> Next: the **fpcheck** phase for static false-positive elimination (see SKILL.md for your client's phase syntax).
>
> Say **go fpcheck** to proceed.
>
> **Before continuing, run a manual compact** (`/compact` in Claude Code or Codex CLI, Compact in Copilot Chat). All findings have been written to `cba_findings` + per-group artifacts, the resume note is fresh — compacting now is lossless. fpcheck spawns more subagents and will benefit from a clean context.

## Quality Checks

- [ ] Every group has a `cba_findings` row count > 0 OR an explicit "no findings, all entry points reviewed" artifact
- [ ] Every finding has a `artifacts/G<n>-findings.md` section with full root cause + PoC
- [ ] No finding has confidence < 8
- [ ] Patch-bypass intel from Step 2 has been probed (look for "probe these sites" items reflected in findings)
- [ ] Resume note rewrites complete
