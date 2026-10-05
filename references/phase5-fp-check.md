# Phase 5: FP-Check Verification

## Purpose

Verify every finding from Phase 4 using the false-positive-check methodology defined in this reference (bundled in this skill — no external skill required). This phase ensures zero false positives reach the final report.

## Batching Strategy

### Batch Size
- **Target**: 8-10 findings per batch
- **Maximum**: 12 findings per batch (beyond this, verification quality degrades)
- **Minimum**: 3 findings per batch (below this, launch overhead isn't worth it)

### Batch Formation Rules
1. **Group affinity**: Prefer batching findings from the same or related feature groups (shared code context reduces re-reading)
2. **Severity mixing**: Mix severities within batches (don't put all CRITICALs in one batch — spread them for independent verification)
3. **No cross-dependencies**: If Finding A's truth value depends on Finding B, put them in the same batch

### Batch Count Calculation
```
total_findings = SELECT COUNT(*) FROM cba_findings
batch_count = CEILING(total_findings / 10)
```

## Subagent Brief

The dispatch brief is a template at `references/briefs/fpcheck-brief.md`,
rendered per batch by `audit.py brief`. Do not paste its contents into a
dispatch — render it and send the path (spec rule R6):

    python3 __SKILL_DIR__/audit.py brief --phase fpcheck --unit B1 --run "$AUDIT_DIR" \
      --var batch_id=B1 --var finding_ids='...' --var run_dir="$AUDIT_DIR" \
      --var source_access='...' --var artifact_path="$AUDIT_DIR/artifacts/B1-fpcheck.md"

The *Canonical FP Rules Summary* below remains the authority for the Hard
Exclusions, Precedent rules and Capability Validity checks the brief tells
the subagent to apply.

## Canonical FP Rules Summary

### Hard Exclusions (any one = FALSE POSITIVE)
HE-1: No source-to-sink data flow demonstrated
HE-2: Standard library function used correctly per documentation
HE-3: Input is validated/sanitized before reaching the sink
HE-4: Bug requires prerequisites the attacker cannot achieve
HE-5: Framework mitigates this class of bug by default
HE-6: The "vulnerability" is documented intended behavior
HE-7: Static analysis false positive (tool limitation)
HE-8: Code is dead/unreachable
HE-9: The exact same bug was already reported (duplicate)
HE-10: Test/example code only, not production
HE-11: Requires physical access not in threat model
HE-12: Denial of service against self only
HE-13: Race condition with astronomically unlikely timing window
HE-14: Information disclosure of non-sensitive data
HE-15: Bug is in a dependency and app doesn't trigger the vulnerable path
HE-16: Claimed severity doesn't match actual impact
HE-17: Marginal Gain Test — attacker's starting position already grants the claimed impact
HE-18: Finding relies on deprecated/removed code path

### Precedent Rules (any one = likely FALSE POSITIVE)
PR-1: "Looks unsafe" without traced data flow
PR-2: Theoretical attack with no practical exploitation path
PR-3: Requires specific configuration not in default install
PR-4: Bug class is mitigated by deployment environment
PR-5: CI/CD finding without all four required elements
PR-6: Missing CSRF token when authentication is API-key-based
PR-7: Hardcoded credential that is a default placeholder
PR-8: Weak crypto when stronger crypto is available but this path isn't sensitive
PR-9: DoS requiring sustained attack with no amplification
PR-10: IDOR when authorization model is intentionally flat

### Capability Validity
CV-1: Attacker must actually be able to reach the entry point
CV-2: Attacker must control the data that reaches the sink
CV-3: The cited code must exist and match the claim (RE-READ the file)

## Verdict Processing

After all FP-check subagents return:

### 1. Parse Verdicts
Extract structured verdicts from each subagent's output.

### 2. Insert into SQL
```sql
INSERT INTO cba_fp_verdicts (finding_id, verdict, reason, final_severity, final_id, merged_into)
VALUES (?, ?, ?, ?, ?, ?);
```

### 3. Assign Final IDs
For TRUE_POSITIVE findings, assign sequential `F-N` identifiers ordered by severity:
```
CRITICAL first → HIGH → MEDIUM → LOW
Within each tier: ordered by group (G1 before G2)
```

### 4. Deduplication
For DUPLICATE findings:
- Identify the primary finding (highest confidence, most complete analysis)
- Set `merged_into` to the primary's final ID
- If the duplicate has additional context, append it to the primary's description

### 5. Escalation Check
If a finding was marked TRUE_POSITIVE with adjusted severity (higher or lower than original):
- Document why severity changed
- Use the FP-check subagent's severity, not the original

## Quality Gates

Before proceeding to Phase 6:

- [ ] Every finding in `cba_findings` has a corresponding row in `cba_fp_verdicts`
- [ ] No verdict is empty or "UNKNOWN"
- [ ] All TRUE_POSITIVE findings have `final_id` assigned
- [ ] All DUPLICATE findings have `merged_into` pointing to a valid `final_id`
- [ ] No two TRUE_POSITIVE findings have the same `final_id`

## Statistics to Report

After verification:
```
Total findings reviewed: N
TRUE POSITIVE:  N (X CRITICAL, Y HIGH, Z MEDIUM, W LOW)
FALSE POSITIVE: N
DUPLICATE:      N

FP rate: N/total = X%
```
