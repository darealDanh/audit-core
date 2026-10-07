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

```bash
python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_known_findings \
  --set id=GHSA-xxxx-yyyy-zzzz --set title='<advisory title>' \
  --set location='<file or component>' --set source=GHSA \
  --set patched_in='<version>' --set severity=HIGH
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

## Step 6 — Sweep confirmed patterns, and look for chains

Two passes the per-group subagents structurally cannot do, because each one
sees only its own group.

**Patterns.** A confirmed finding is evidence about one call site and a
hypothesis about every other one. For each finding whose root cause could
appear elsewhere, register it and sweep:

    python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db \
      --table cba_patterns --set id=P1 --set name='<the shape>' \
      --set regex='<the regex>' --set origin_finding=G1-F1

    python3 __SKILL_DIR__/audit.py sweep --db ${AUDIT_DIR}/audit.db \
      --pattern P1 --root . --record

Hits land in `cba_pattern_hits` as candidates for triage, never verdicts. A
truncated sweep is refused: narrow the pattern and run it again.

    python3 __SKILL_DIR__/audit.py patterns --db ${AUDIT_DIR}/audit.db --gate

exits non-zero while any registered pattern has never been swept.
`strncpy(dst, src, strlen(src))` was found twice in a real run, named as a
pattern, and never grepped for; two reference-set CRITICALs are that pattern
elsewhere.

**Chains.** Findings are born inside per-group subagents and nothing crosses
them, so a chain whose halves sit in two groups is never composed:

    python3 __SKILL_DIR__/audit.py chain --db ${AUDIT_DIR}/audit.db

proposes ordered (enabler → consumer) pairs across groups. Read both findings
in full before accepting one, then record the decision:

    python3 __SKILL_DIR__/audit.py chain --db ${AUDIT_DIR}/audit.db \
      --compose C1 --findings G1-F2,G3-F4 \
      --attacker-position 'unauthenticated on the LAN' \
      --completeness complete --pre-auth yes

The command also reports how many findings record neither
`attacker_position` nor `boundary_crossed`. Those cannot be the consumer half
of any chain, and a high count means the findings are underspecified, not
that no chain exists.

## Step 7 — Update group status

```sql
UPDATE cba_feature_groups SET status='audited' WHERE id IN (...);
```

## Step 8 — Summary + resume note rewrite

Present a finding-count table by group × severity:

```bash
python3 __SKILL_DIR__/audit.py status --db ${AUDIT_DIR}/audit.db
```

Rewrite the resume note ([../references/resume-note-template.md](../references/resume-note-template.md)) to reflect:

- Phase status: recon DONE, deploy DONE, audit DONE, fpcheck NOT STARTED
- Phase-4 finding counts table
- **Top patch-bypass discoveries** (these are the highest-value items for vendor disclosure — call them out explicitly)
- Live-PoC status (how many `verified='live-poc'` vs `'source-only'`)
- Updated "Quirks to remember"

Then record coverage for this phase and check it, the same way Step 6 checks
the pattern gate. **Record first — the gate has nothing to read until you do.**
Recon populated `cba_inventory`; this phase says what it did with each unit.

Write the list of units this phase actually opened — one per line, `#` comments
allowed — and record them all in one call. Each deep-audit subagent wrote its
own list to `files/$G-audited.txt` (see the brief), so the lists concatenate:

```bash
cat ${AUDIT_DIR}/files/G*-audited.txt > ${AUDIT_DIR}/files/audit-analyzed.txt

python3 __SKILL_DIR__/audit.py coverage --db ${AUDIT_DIR}/audit.db --record \
  --phase audit --state analyzed --from-file ${AUDIT_DIR}/files/audit-analyzed.txt
```

Every inventoried unit nobody opened needs a decision, not silence. Record one
call per reason — `budget`, `out-of-scope`, `generated`, `vendored`,
`third-party`, `unreachable`, `binary-only`:

```bash
python3 __SKILL_DIR__/audit.py coverage --db ${AUDIT_DIR}/audit.db --record \
  --phase audit --state not_audited --reason vendored \
  --unit third_party/libfoo/foo.c --unit third_party/libfoo/bar.c
```

`--unit` is repeatable and `--from-file` takes a list, so recording a whole
corpus is one invocation, not one per unit. A row written for the wrong state
is corrected with `--replace` on the same unit and phase. Then:

```bash
python3 __SKILL_DIR__/audit.py coverage --db ${AUDIT_DIR}/audit.db --gate --phase audit
```

**Run it — do not present it.** It exits non-zero on an empty inventory, on any
unit skipped for budget, and on any inventoried unit with no coverage row. The
`--phase audit` scope is load-bearing: unscoped, a unit recon ruled on and this
phase never opened still counts as analyzed, so the gate reports 100% and
passes on exactly the failure it exists to catch. A budget skip is answered by
`audit.py checkpoint` and a restart, never by skipping. Answer every failure it
names before presenting the gate below.

## Step 9 — USER GATE

> _Automated `source` mode supersedes this gate — proceed straight to fpcheck without pausing (see [source.md](source.md))._

Present:

> Deep audit complete. N findings across M groups: X CRITICAL, Y HIGH, Z MEDIUM, W LOW. K already live-verified.
>
> Next: the **fpcheck** phase for static false-positive elimination (see SKILL.md for your client's phase syntax).
>
> Coverage for this phase: A of B inventoried units analyzed; the `--phase audit`
> gate passed (or: failed on N units, each now answered — list them).
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
- [ ] `audit.py patterns --gate` exits 0 — every registered pattern has been swept
- [ ] Every unit this phase opened has an `analyzed` row, and every unit it did not has a `not_audited` row with a reason (`audit.py coverage --record`)
- [ ] `audit.py coverage --gate --phase audit` exits 0, or every failure it names has been answered
- [ ] `audit.py chain` has been run and its proposals read
