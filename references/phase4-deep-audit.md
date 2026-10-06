# Phase 4: Deep Audit

## Purpose

Hunt for vulnerabilities in each feature group using dedicated subagents. Each subagent is an adversarial security researcher with deep context about one feature group.

## Finding Schema

Each finding must include ALL of the following fields. Subagents that return incomplete findings get their output rejected and re-prompted.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | yes | `{group_id}-F{n}` (e.g., G1-F1) |
| group_id | string | yes | Feature group this belongs to |
| title | string | yes | Concise vulnerability title |
| severity | enum | yes | CRITICAL, HIGH, MEDIUM, LOW |
| confidence | integer | yes | 1-10 scale. Must be ≥ 8 to pass FP-check. |
| cwe | string | yes | CWE-NNN identifier |
| location | string | yes | Primary file:line or function@address |
| root_cause | string | yes | Technical explanation of why the bug exists |
| impact | string | yes | What an attacker achieves by exploiting this |
| attacker_position | enum | yes | unauthenticated, authenticated-user, authenticated-admin, local, physical |
| boundary_crossed | string | yes | What trust boundary is violated |
| data_flow | string | yes | Source → processing → sink path |
| verified | enum | yes | source-only, ida-confirmed, live-poc |
| poc | string | no | PoC HTTP request, script, or reproduction steps |
| remediation | string | yes | How to fix it |

## Subagent Brief

The dispatch brief is a template at `references/briefs/audit-brief.md`,
rendered per group by `audit.py brief`. Do not paste its contents into a
dispatch — render it and send the path (spec rule R6):

    python3 __SKILL_DIR__/audit.py brief --phase audit --unit G7 --run "$AUDIT_DIR" \
      --var group_id=G7 --var group_name='...' --var run_dir="$AUDIT_DIR" \
      --var mapping_path="$AUDIT_DIR/files/G7-mapping.md" \
      --var artifact_path="$AUDIT_DIR/artifacts/G7-findings.md" \
      --var source_access='...' --var known_findings='...' \
      --var test_instance='...'

The *Finding Schema* below remains the authority for what a finding row must
contain.

### Test instance details (passed as `--var test_instance=...`)

There is no prompt template to fill any more. This value is a `--var` on the
`audit.py brief` command above; the brief's *Test instance* section renders it
verbatim, together with the live-verification steps and their Do NOT list.

```
Test instance: {url}
Authentication: Create test accounts via admin/admin123 (do NOT modify admin account).
Available for: HTTP requests, API testing
Not available for: Destructive testing, persistence, data exfiltration
```

If no test instance, pass exactly:
`--var test_instance='No test instance available. Provide source-level analysis only.'`

## Post-Collection Processing

After all subagents return:

1. **Parse findings**: Extract structured data from each subagent's markdown output
2. **Assign sequential IDs**: Within each group (G1-F1, G1-F2, ..., G2-F1, ...)
3. **Insert into SQL**:
   ```bash
   python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db --table cba_findings \
     --set id=G1-F1 --set group_id=G1 --set title='<one line>' \
     --set severity=HIGH --set confidence=9 --set location='<file>:<line>' \
     --set root_cause='<mechanism>' --set impact='<consequence>' \
     --set attacker_position='<where the attacker stands>' \
     --set boundary_crossed='<trust boundary>' --set cwe=CWE-787 \
     --set artifact_path=artifacts/G1-findings.md
   ```
4. **Dedup quick-check**: If two findings from different groups describe the same vulnerability at the same code location, keep the one with higher confidence and note the duplicate.

   ```bash
   python3 __SKILL_DIR__/audit.py dedup --db ${AUDIT_DIR}/audit.db
   ```

   These are proposals. Keep the one with higher confidence and record the other as `verdict=DUPLICATE` with `merged_into` set.

5. **Register and sweep confirmed patterns**: a confirmed finding is evidence
   about one call site and a hypothesis about every other one.

   ```bash
   python3 __SKILL_DIR__/audit.py put --db ${AUDIT_DIR}/audit.db \
     --table cba_patterns --set id=P1 --set name='<the shape>' \
     --set regex='<the regex>' --set origin_finding=G1-F1
   python3 __SKILL_DIR__/audit.py sweep --db ${AUDIT_DIR}/audit.db \
     --pattern P1 --root . --record
   python3 __SKILL_DIR__/audit.py patterns --db ${AUDIT_DIR}/audit.db --gate
   ```

   Hits are candidates for triage, never verdicts.

6. **Chain pass**: findings are born inside per-group subagents, so a chain
   whose halves sit in two groups is never composed.

   ```bash
   python3 __SKILL_DIR__/audit.py chain --db ${AUDIT_DIR}/audit.db
   ```

   These are proposals. Read both findings in full, then record the decision
   with `audit.py chain --compose`.

## Quality Signals

Good findings have:
- Specific file:line citations (not "somewhere in the auth module")
- Complete data flow from source to sink
- Explicit mention of what mitigations were checked and absent
- Realistic attacker position (not "attacker with server access")
- CWE that matches the actual bug class
- A recorded `attacker_position` and `boundary_crossed` — a finding with
  neither cannot be the consumer half of any chain

Bad findings (reject and re-prompt):
- Vague locations ("in the codebase")
- No data flow trace
- Confidence < 8
- Impact requires capabilities the attacker wouldn't have
- Library vulnerability without application-specific trigger
