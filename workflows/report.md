# codebase-audit — report: Vulnerability Report(s)

**Purpose**: Write the vulnerability report(s) in the lean, maintainer-facing format (template: [../references/phase6-report.md](../references/phase6-report.md)). There are **two modes**, decided by how the audit ran:

- **Live, per-finding, in the fork** (full pipeline). After verify + adversarial review (verify.md Steps 1-2), for a finding the fork confirmed as a real, worth-reporting vulnerability, the **fork itself** writes one report at `reports/audit-<ts>/artifacts/<FINDING-ID>-vuln-report.md`, with the real PoC and captured output. There is no orchestrator consolidation.
- **Source-only, consolidated, in the orchestrator** (the `source` run: no live instance, no forks). The **orchestrator** writes ONE `reports/audit-<ts>/report.md` covering all true positives, where *Steps to reproduce* is a reproduction guide (no PoC executed, no captured output).

**Entry**:
- Live: inside the verify fork, immediately after verify.md Step 2, for each finding the fork confirmed as real. Only real / worth-reporting findings reach this phase; REFUTED or not-worth-reporting findings stop at verify and never get a report.
- Source-only: the orchestrator, at the end of the `source` run (see [source.md](source.md)).

**Exit**:
- Live: one `artifacts/<FINDING-ID>-vuln-report.md` per confirmed finding, plus its runnable scripts staged in the project-root `poc/`.
- Source-only: one consolidated `report.md`.

No `disclosure-summary.md`, no CVSS/severity tables, no orchestrator stitch step. Never auto-disclose.

---

## Report format (both modes)

Follow the template in [../references/phase6-report.md](../references/phase6-report.md). Every report (each live per-finding file, and each finding-section of the source consolidated report) uses exactly these headings, in order:

```
# <FINDING-ID>: <one-line title (a CWE id is fine)>
## Affected Version
## Summary
## Root Cause
## Steps to reproduce
## Impact
```

Style (enforced):
- **No em-dashes** (`—`). Use a spaced hyphen ` - ` or rewrite the sentence.
- Use emphasis sparingly. Prefer `code spans` for symbols, paths, commands, and values; reserve `**bold**` for the rare load-bearing word.
- Lean. Only the six headings. No CVSS scores, no severity tables, no disclosure timeline, no coverage matrix, no methodology appendix, no executive summary, no advisory boilerplate.
- Cite source as `src/file.c:line`; reference PoC scripts as `poc/<name>`. **Never** reference a `reports/audit-<ts>/...` path - the maintainer will not have it.
- For format examples you may consult `reports/audit-<ts>/archived-poc/<finding-id>/` (it may be empty on a first run; you do not need to match it exactly).

## Mode A - Live, per-finding (run in the verify fork)

You have just finished verify.md Steps 1-2 for ONE finding and confirmed it is a real, worth-reporting vulnerability. Write `reports/audit-<ts>/artifacts/<FINDING-ID>-vuln-report.md`:

1. **Title + Affected Version** - the target product, version, and the commit/tag you tested on the live instance.
2. **Summary** - what the bug is and the genuine attacker path; state it was confirmed on the stock, unmodified build, and that a control run with honest input behaves normally.
3. **Root Cause** - the code-level explanation with `src/file.c:line` citations and minimal code blocks (the flaw, the flawed caller, the data flow from attacker input to sink).
4. **Steps to reproduce** - the bash setup; the **Control (honest-input) run first**; then the attack run(s). Inline the PoC script as a code block ("Save as `poc.py`") AND stage a runnable copy under the project-root `poc/` (see *PoC packaging* below), referenced as `poc/<name>`. Paste the **real captured output verbatim** (the `curl -i` / server log / exit status you captured in verify) - never hand-write expected output.
5. **Impact** - the concrete attacker capability and what is lost; the trust boundary crossed; honest severity in prose (no CVSS, no table).

The captured evidence already lives in your `verify-<id>.md`; reuse it. `verify-<id>.md` remains the verify-phase artifact - this report is a separate deliverable.

### PoC packaging (live)

Move or copy any custom scripts you created into a `poc/` directory at the **project root** (not under `reports/audit-<ts>/`). Each script:
- runs from a clean checkout; build any attacker-side patch from an included `.patch` - do **not** ship prebuilt binaries (the maintainer rebuilds and shouldn't trust an opaque binary);
- embeds the real captured output;
- keeps the victim stock - the patch, if any, is the **attacker** side (verify with `readlink /proc/<pid>/exe`; see verify.md "PoC rigor + evidence model").

The report inlines the script for reading AND points at `poc/<name>` for running. Per-finding / per-delivery: after a report is sent, the user archives that report + its `poc/` into `reports/audit-<ts>/archived-poc/<finding-id>/`.

## Mode B - Source-only, consolidated (run in the orchestrator)

The `source` run has no live instance and no forks. Write ONE `reports/audit-<ts>/report.md` covering all true positives.

1. Pull the TPs:
   ```bash
   python3 __SKILL_DIR__/audit.py rows --db ${AUDIT_DIR}/audit.db \
     --table cba_fp_verdicts --where verdict=TRUE_POSITIVE \
     --columns finding_id,final_severity
   ```
   Read each finding's detail from `artifacts/G<n>-findings.md` + `cba_findings`.
2. Write `report.md`: a short header (target, version/commit, audit date), then **one section per finding** ordered by severity, each using the six headings above (`#`/`##` per finding, `##`/`###` for its sub-sections - keep it consistent and skimmable).
3. **Steps to reproduce is a reproduction GUIDE only** - the concrete steps, inputs, and conditions an attacker or maintainer would use to trigger the bug, derived from source. There is **no live instance**: do NOT run a PoC and do NOT paste captured output. Label the section as a source-level guide (not live-verified).
4. State prominently near the top that all findings are **static (source-level) true-positives that survived false-positive review but were NOT live-verified**; running the interactive verify phase against a live instance is recommended before any external disclosure.

## Before you finalize (light self-check)

Re-read the report against source + (live mode) the captured evidence:
- every `src/file.c:line` and quoted snippet matches the source at the tested commit;
- the root cause re-derives from scratch and the data flow actually reaches the sink;
- every behavioral claim is backed by the captured output (live) or clearly framed as a source-level expectation (source-only); severity is honest, not inflated.

Tighten wording to what was measured: "effectively unbounded (expected N iterations)" not "infinite"; "observed M/N" not "it crashes". Fix everything this pass catches.

## Do not disclose

Produce the report file(s) and stop. Never file an advisory, open an issue, or email a vendor - disclosure is the user's call. In the live full pipeline the fork returns its summary and the user collects the per-finding reports; in source mode the orchestrator prints a severity-counts summary and the `report.md` path.
