# Stage 3 prose derivation

Written before the prose was edited, per the Stage 1 finding that rewriting
shipped prose from scratch lost instructions five times out of five and that
absence is the hardest thing to review for.

Scope: Task 8 of `2026-10-05-stage3-quality-additions` — the task that makes
the shipped skill invoke the five mechanisms Tasks 2-6 built (`pivot`,
`sweep`/`patterns`, `coverage --gate`, `identify`, `chain`).

**Every edit below is an insertion except row R10**, which replaces one line of
`workflows/fpcheck.md` and carries that line's text through verbatim inside the
replacement. No section is retyped. Line ranges are *as they stand before any
edit*, against the tree at `e7d567e`.

## 1. Intended edits

| # | Where | What is there now | What replaces it | Why — and what is dropped |
|---|---|---|---|---|
| R1 | `workflows/recon.md:43-46` (Step 2 numbered list, item 4 is the last) | `4. Insert into `cba_sources`.` — the list's last item; items 1-3 are the IDA probe, the source scan and the user prompt | **(inserted; nothing replaced)** A new item `5.` after item 4, instructing `audit.py identify --path … --kind … --identity … --evidence … --confidence 8`, with the paragraph "A filename is an assertion by whoever named it, not evidence. In a real run `km0_boot_0C000020.elf` was treated as a bootloader throughout; it holds the Wi-Fi driver and several CRITICALs. The verb rejects evidence that only repeats the path." | Task 5 built `identify`; nothing invoked it. The tplink post-mortem: a whole run treated a file as a bootloader on the strength of its filename. **Nothing dropped** — items 1-4 are untouched, byte for byte. |
| R2 | `workflows/recon.md:74` (Step 4, last line: `Insert approved groups into `cba_feature_groups` (status='pending').`) | That one line, followed by a blank line and `## Step 5 — Parallel feature mapping subagents` | **(inserted; nothing replaced)** A new paragraph after line 74: "Then populate the coverage denominator. One `cba_inventory` row per analysable unit …" plus the indented `audit.py put --table cba_inventory --set unit=<path> --set kind=file --set group_id=$G` block and the "unit nobody inventoried cannot be reported as a gap" paragraph | `coverage --gate` (Task 4) has no denominator unless recon writes `cba_inventory`. The gate added in R6 is inert without this. **Nothing dropped** — line 74 survives verbatim and Step 5's heading and body are untouched. |
| R3 | `workflows/recon.md:150-156` (Quality Checks, five bullets) | Five existing checkboxes, ending `- [ ] Resume note exists and includes the must-investigate leads list` | **(inserted; nothing replaced)** Two checkboxes appended after the existing five: one for `cba_inventory` + `audit.py coverage` naming a denominator, one for a `cba_components` row whose evidence is not the filename | A quality-check list that does not mention the new obligations is a list that will be read as complete without them. **Nothing dropped** — all five existing bullets keep their exact text and order. |
| R4 | `workflows/audit.md:134-136` (between the end of Step 5's body and the `## Step 6 — Update group status` heading) | Step 5 ends at line 134 (`3. Update the resume note's "Quirks to remember" …`); line 136 is `## Step 6 — Update group status` | **(inserted; nothing replaced)** A whole new `## Step 6 — Sweep confirmed patterns, and look for chains` section between them: the **Patterns** half (`put --table cba_patterns`, `sweep --record`, `patterns --gate`, the `strncpy(dst, src, strlen(src))` post-mortem) and the **Chains** half (`chain`, `chain --compose`, and the note about findings recording neither `attacker_position` nor `boundary_crossed`) | Tasks 3 and 6 built sweep/patterns and chain; nothing invoked either. Both are structurally impossible for a per-group subagent — it sees only its own group — so they must live in the orchestrator's own step. **Nothing dropped** — Step 5's body ends before the insertion point and Step 6's body begins after it. |
| R5 | `workflows/audit.md:136`, `:142`, `:158` (three headings) | `## Step 6 — Update group status`, `## Step 7 — Summary + resume note rewrite`, `## Step 8 — USER GATE` | Heading text only, renumbered: `## Step 7 — Update group status`, `## Step 8 — Summary + resume note rewrite`, `## Step 9 — USER GATE` | R4 inserts a new Step 6, so the three that follow shift by one. **Mechanical edit of three heading lines only; the bodies are not touched.** Three lines removed from the diff's point of view, three added, same text but for the digit. **No English instruction dropped** — the only changed token on each line is the step number. (Dispatch Correction 3: the USER GATE is old Step 8 → **Step 9**; the brief's prose says "Step 8" in one place and is wrong.) |
| R6 | `workflows/audit.md`: end of Step 8 (the resume-note rewrite), and `:168` inside the USER GATE blockquote | Step 8 ends with the bullet `- Updated "Quirks to remember"`; the gate step's blockquote runs from "Deep audit complete…" to the manual-compact line | **(inserted; nothing replaced)** **(a)** In **executable prose** at the end of Step 8, before `## Step 9 — USER GATE`: "Then record coverage for this phase and check it, the same way Step 6 checks the pattern gate", a fenced `coverage --db ${AUDIT_DIR}/audit.db --gate --phase audit`, and **"Run it — do not present it."** plus the empty-inventory / budget-skip / unrecorded-unit explanation and why `--phase audit` is load-bearing. **(b)** Inside the presented blockquote, a line that **reports the outcome** to the user ("Coverage for this phase: A of B inventoried units analyzed; the `--phase audit` gate passed (or: failed on N units, each now answered)"). | Task 4 built the gate; no phase exit consults it. Two things had to be right, and the brief and the dispatch each got one of them wrong. **Scope — Dispatch Correction 1, right:** the brief's unscoped `--gate` counts a unit analyzed if *any* phase recorded it. Reproduced on a real db — one inventoried unit analysed by recon, never opened by audit: `--gate` → `1/1 analyzed (100.0%) PASS exit 0`; `--gate --phase audit` → `0/1 FAIL exit 1`. **Placement — Dispatch Correction 1, wrong, caught in review:** it said to insert "before the 'Say go fpcheck' line", which put the invocation inside the `>` block the orchestrator **presents to the user**. There it ran in neither mode — interactively the orchestrator shows the user the command instead of executing it, and unattended `source` mode skips the whole USER GATE step (`source.md` Step 2's override list), so it never appeared. The gate is now executable prose, matching Step 6's patterns gate; the blockquote keeps a line reporting the result so the user still sees the outcome. `workflows/source.md` needs no override, confirmed against its Step 2 list. **Nothing dropped** — every pre-existing blockquote line survives in order. |
| R7 | `workflows/audit.md:172-178` (Quality Checks, five bullets) | Five existing checkboxes, ending `- [ ] Resume note rewrites complete` | **(inserted; nothing replaced)** Three checkboxes appended: `patterns --gate` exits 0, `coverage --gate` exits 0 or every failure answered, `audit.py chain` has been run and its proposals read | Same reason as R3. **Nothing dropped** — notably `- [ ] Patch-bypass intel from Step 2 has been probed …`, the check Stage 1 lost once already, keeps its exact text and position. |
| R8 | `workflows/fpcheck.md:73-75` (between the end of Step 4's body and the `## Step 5 — Sanity-check verdict completeness` heading) | Line 73 is Step 4's closing **IMPORTANT for this phase** paragraph; line 75 is `## Step 5 — Sanity-check verdict completeness` | **(inserted; nothing replaced)** A whole new `## Step 5 — The pivot rule` section between them: the `audit.py pivot` invocation, the "writes the observation and the verdict as one act" paragraph, the **unconditional** paragraph, the 300-byte sliding-window post-mortem, and `pivot --check` | Task 2 built `pivot`; nothing invoked it. The post-mortem: a finding was correctly refuted by a mechanism that is itself the attack surface for a reference-set CRITICAL, and the verdict schema recorded only the refutation. **Nothing dropped** — the **IMPORTANT for this phase** static-only paragraph (a conduct prohibition, the category Stage 1 lost once) is above the insertion point and untouched. |
| R9 | `workflows/fpcheck.md:75`, `:85`, `:95`, `:105` (four headings) | `## Step 5 — Sanity-check verdict completeness`, `## Step 6 — Assign final IDs`, `## Step 7 — Resume-note rewrite + fork plan`, `## Step 8 — USER GATE` | Heading text only, renumbered to Steps 6, 7, 8, 9 | R8 inserts a new Step 5. **Mechanical edit of four heading lines only; the bodies are not touched.** No English instruction dropped — only the digit changes. |
| R10 | `workflows/fpcheck.md:126` (Quality Checks) | `- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule` | `- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule, and records `refuting_mechanism` plus an `enabled_observation` that resolves (`audit.py pivot --check`)` | **This is the task's one and only replacement of an existing line.** The original clause survives *verbatim* as the replacement's prefix — `cites a specific HE/PR/CV rule` is asserted by `test_every_instruction_the_replaced_blocks_sat_inside_survives`, extended for exactly this reason. **One line removed, zero instructions lost:** the removed line's full text is the first clause of the line that replaces it. |
| R11 | `references/phase5-fp-check.md:85-91` (**CRLF**; `### 2. Insert into SQL` and its TRUE_POSITIVE fenced block) | The heading, then a bash fence writing `verdict=TRUE_POSITIVE` via `audit.py put` | **(inserted; nothing replaced)** New prose + a second bash fence *appended below* the existing one, inside the same section: "A `FALSE_POSITIVE` takes a different verb, because it must also record what refuted the finding and what that mechanism enables", the `audit.py pivot` invocation, and "The observation is written as a rung-1 lead, not a finding." | The existing TRUE_POSITIVE example is correct and still works; only the FALSE_POSITIVE path changed. **Nothing dropped** — the existing fence is not edited, and `### 3. Assign Final IDs` follows unchanged. File stays CRLF. |
| R12 | `references/phase5-fp-check.md:111-119` (**CRLF**; `## Quality Gates`, five checkboxes) | Five checkboxes, ending `- [ ] No two TRUE_POSITIVE findings have the same `final_id`` | **(inserted; nothing replaced)** A sixth checkbox appended: `- [ ] Every FALSE_POSITIVE has a `refuting_mechanism` and an `enabled_observation` that resolves` | Same reason as R3. **Nothing dropped.** File stays CRLF. |
| R13 | `references/phase4-deep-audit.md:77-83` (**CRLF**; `## Post-Collection Processing` item 4 and its dedup fence) | Item 4 (dedup quick-check), its `audit.py dedup` fence, and the "These are proposals. Keep the one with higher confidence …" paragraph | **(inserted; nothing replaced)** Items `5.` (register and sweep confirmed patterns: `put --table cba_patterns`, `sweep --record`, `patterns --gate`, "Hits are candidates for triage, never verdicts") and `6.` (chain pass: `audit.py chain`, "These are proposals. Read both findings in full, then record the decision with `audit.py chain --compose`.") appended after item 4's paragraph | The reference the audit phase reads for post-collection work never mentions the two passes. **Nothing dropped** — `keep the one with higher confidence`, asserted by an existing guard test, is in item 4 and untouched. File stays CRLF. |
| R14 | `references/phase4-deep-audit.md:87-92` (**CRLF**; `## Quality Signals` → "Good findings have:", five bullets) | Five bullets, ending `- CWE that matches the actual bug class` | **(inserted; nothing replaced)** A sixth bullet: "A recorded `attacker_position` and `boundary_crossed` — a finding with neither cannot be the consumer half of any chain" | `chain` can only propose from findings that record where the attacker stands. **Nothing dropped** — the "Bad findings (reject and re-prompt)" list below is untouched. File stays CRLF. |
| R15 | `references/phase0-source-detection.md:92-95` (**CRLF**; `## SQL Schema`, two sentences, end of file) | `The `cba_sources` table is created by `audit.py init` (recon Step 1). Insert the confirmed source row into it; do not create the table.` | **(inserted; nothing replaced)** Appended after those two sentences: "Record what each confirmed artifact is, with evidence:", the `audit.py identify` fence with the `km0_boot_0C000020.elf` example, and the "A filename is an assertion by whoever named it …" paragraph | Pairs with R1: recon's workflow invokes `identify`, and the reference it points at must say what evidence means. **Nothing dropped** — both existing sentences survive verbatim. File stays CRLF. |
| R16 | `references/briefs/fpcheck-brief.md:31` (method step 9, the list's last item) | `9. Issue a verdict: TRUE_POSITIVE, FALSE_POSITIVE or DUPLICATE.` | **(inserted; nothing replaced)** Step 9 kept verbatim; a new step `10.` added after it: take the pivot, name the refuting mechanism, say what it enables, record both with `audit.py pivot`, a bare FALSE_POSITIVE insert is refused, the requirement is **unconditional**, "no attacker-controlled path identified in this review" is a legitimate answer and a blank is not, plus the sliding-window post-mortem | Stage 1 lost 2 of 9 method steps in this exact file; this edit adds a 10th and touches nothing else. **Nothing dropped.** The `{batch_id}`, `{finding_ids}`, `{run_dir}`, `{source_access}` and `{artifact_path}` placeholders, the "18 Hard Exclusions and 10 Precedent rules" line, "Capability Validity checks CV-1 to CV-3" and the `rows=<n> artifact=` return contract are all outside the insertion point and are re-asserted by a new guard test (Step 11). |
| R17 | `references/briefs/audit-brief.md:83-86` (`## Where your output goes`, the `cba_findings` instruction paragraph) | "Write every finding as a row in `cba_findings` in `{run_dir}/audit.db`, and the detailed write-up to `{artifact_path}`. Set each row's `artifact_path` column … The finding schema is in `references/phase4-deep-audit.md` under *Finding Schema*." | **(inserted; nothing replaced)** One paragraph after it, before the existing `rows=0` paragraph: "If a finding's root cause is a shape that could appear elsewhere in the tree, register it: `audit.py put --table cba_patterns --set id=<id> --set name=… --set regex=… --set origin_finding=<your finding id>`. The orchestrator sweeps every registered pattern corpus-wide **with `audit.py sweep`** before the phase exits." | The subagent is the only party that knows a finding's root cause is a *shape*; the orchestrator's sweep (R4) needs registered patterns to sweep. **Deviation from the brief, flagged:** the brief's wording ends "The orchestrator sweeps every registered pattern corpus-wide before the phase exits." — no `audit.py sweep` literal. `skill_lint`'s new `pattern-registered-without-sweep` rule (R22) walks `references/**` including `briefs/`, so that wording would make this file name `--table cba_patterns` without naming `audit.py sweep` and the rule would fire on the shipped skill. Naming the verb is both truthful and the fix. **Nothing dropped** — the section is not restructured; the `rows=0` paragraph and `## What you return` follow unchanged. |
| R18 | `SKILL.md:255` (**CRLF**; `### SQL Tables`, last row `\| `cba_checkpoints` \| Phase exits and ceiling trips \| every phase \|`) | The twelve-row table ending at `cba_checkpoints` | **(inserted; nothing replaced)** Two rows appended: `cba_components` (what each artifact is, with the evidence that says so — recon) and `cba_chains` (composed exploit chains, ordered finding ids — audit) | The two tables Tasks 5 and 6 added are undocumented. **Nothing dropped** — all twelve existing rows keep their text and order. File stays CRLF. |
| R19 | `SKILL.md:41-42` (**CRLF**; end of `## Essential Principles`, which runs 1-10 and ends before `## Economics Contract` at line 43) | Principle `10. **Stay at the project root …**` is the last item | **(inserted; nothing replaced)** Five items appended, numbered **11-15**: 11 the FALSE_POSITIVE pivot rule (unconditional); 12 a confirmed pattern is swept; 13 coverage has a denominator; 14 an identity needs evidence that is not the filename; 15 chains cross groups | The brief uses `N, N+1 …` placeholders. **Dispatch Correction 2:** the list is 1-10, so the new items are 11-15. The `11.` and `12.` near line 340 belong to the *Lessons Learned* list — a different list — and are **not** touched or renumbered. **Nothing dropped** — principles 1-10 keep their exact text and numbers. File stays CRLF. |
| R20 | `SKILL.md:324` (**CRLF**; `## Rationalizations to Reject`, last row `\| "We confirmed the pattern here; the other call sites are probably fine" \| … \|`) | The existing twenty-two-row table | **(inserted; nothing replaced)** Five rows appended: "It's a false positive — verdict recorded, move on"; "No attacker-controlled path, so there's nothing to record"; "The pattern only shows up in this one file"; "It's called `km0_boot`, so it's the bootloader"; "Each group's findings are independent" | Each pins a specific post-mortem rationalization against the verb that answers it. **Load-bearing for R22:** the third row carries the literal `audit.py sweep --record`, which is what keeps `pattern-registered-without-sweep` from firing on `SKILL.md:324`'s pre-existing `audit.py put --table cba_patterns` (dispatch Correction 4). **Nothing dropped** — every existing row survives, including `"Near the ceiling — skip this group"` whose exact em-dash wording a guard test asserts. File stays CRLF. |
| R21 | `SKILL.md:257-280` (**CRLF**; `### Artifact Layout`) | The `reports/audit-<ts>/` tree and the `poc/` paragraph | **No change.** Confirmed by inspection, not assumed: every Stage 3 mechanism writes to `audit.db` (`cba_components`, `cba_chains`, `cba_inventory`, `cba_coverage`, `cba_patterns`, `cba_pattern_hits`) and none of the four verbs takes an output-path flag. | Brief Step 9(d) requires this be confirmed rather than assumed. **Nothing added, nothing dropped.** |
| R22 | `audit_core/skill_lint.py:33` (LF; after `RETIRED_QUERIES`) and `:134` (inside the per-file loop, after the `RETIRED_QUERIES` check) | `RETIRED_QUERIES` tuple and its scope-statement comment; the per-file loop's retired-query check | **(inserted; nothing replaced)** Module constants `FP_VERDICT_INSERT = ("--tablecba_fp_verdicts", "verdict=false_positive")` and `PATTERN_INSERT = "--tablecba_patterns"` with the same scope statement, plus two checks in the loop emitting `fp-verdict-without-pivot` and `pattern-registered-without-sweep` | Two shapes that are correct SQL and wrong practice. Needles carry no whitespace because `_squash` *removes* whitespace rather than collapsing it — this is deliberate and must not be "fixed". **Nothing dropped** — `RETIRED_QUERIES` and its comment are untouched. **Ordering constraint (dispatch Correction 4): R20 must land before R22**, and `lint-skill` is run immediately after the `SKILL.md` edit. |
| R23 | `tests/test_workflow_prose.py` (append) and `:260-263` (the `workflows/fpcheck.md` entry of `test_every_instruction_the_replaced_blocks_sat_inside_survives`) | The existing module; the fpcheck entry listing two needles | **(appended; one dict entry extended)** Six new tests: every Stage 3 verb appears in shipped prose; the coverage gate is invoked at a phase exit (asserting `coverage --db ${AUDIT_DIR}/audit.db --gate --phase audit`, per Correction 1); the pivot rule is stated as unconditional; the five rationalizations are in the table; `SKILL.md` lists the two new tables; the fpcheck brief kept its placeholders and return contract. The dict entry gains a third needle, `"cites a specific HE/PR/CV rule"`. | These guard tests are what later stages consume, and they are the mechanical half of the control this document is the human half of. **Nothing dropped** — the dict's two existing needles are kept. |
| R24 | `tests/test_skill_lint.py` (append) | The existing module; `KNOWN = set(audit.HANDLERS)` at module level, trees built inline per test | **(appended; nothing replaced)** Three tests: an FP verdict insert without pivot is flagged; the same file naming pivot is not flagged; a pattern insert without a sweep is flagged. Each asserts the **exact** finding list, as `test_a_retired_status_query_in_prose_is_a_finding` does. | A rule that fires alongside an unintended second rule is a rule that will be noisy on real prose. **Nothing dropped.** |

### Line-ending contract for this edit set

Load-bearing and unchecked by any test. State before the edits, verified:

| File | Must stay | CR count before |
|---|---|---|
| `SKILL.md` | CRLF | 376 |
| `references/phase0-source-detection.md` | CRLF | 95 |
| `references/phase2-feature-mapping.md` | CRLF | 126 (not edited) |
| `references/phase4-deep-audit.md` | CRLF | 99 |
| `references/phase5-fp-check.md` | CRLF | 131 |
| `workflows/*.md`, `references/briefs/*.md`, `audit_core/skill_lint.py`, `tests/*.py` | LF | 0 |

A whole-file rewrite that flips line endings produces a diff in which every
line changed and the real edit is unreviewable. Every CRLF file is edited
byte-wise with `\r\n` preserved on inserted lines.

## 2. Reconciliation against the real diff

Source: `git diff -U0 -- SKILL.md workflows/ references/` against `e7d567e`.
**23 hunks, 8 removed lines, 0 English instructions lost.**

### A note on the counting command

The brief's Step 12 says to count removed lines with `grep -c '^-[^-]'`. That
command is wrong for this diff and reported **7**. A removed markdown list item
begins `- [ ]`, so in a diff it reads `-- [ ]` and `^-[^-]` excludes it — it
silently hides exactly the category of removal this task has to account for
(the one replaced quality-check bullet). The honest count is
`grep -c '^-'` minus `grep -c '^--- '` (the file headers), which is **8**.
Both numbers appear below so the discrepancy is on the record rather than
reconciled away.

### 2.1 Every hunk, mapped to a row

| # | File | Hunk | Lines +/- | Row |
|---|---|---|---|---|
| H1 | `SKILL.md` | `@@ -42,0 +43,13 @@` | +13 / -0 | **R19** Essential Principles 11-15 |
| H2 | `SKILL.md` | `@@ -255,0 +269,2 @@` | +2 / -0 | **R18** `cba_components`, `cba_chains` table rows |
| H3 | `SKILL.md` | `@@ -324,0 +340,5 @@` | +5 / -0 | **R20** five rationalization rows |
| H4 | `references/briefs/audit-brief.md` | `@@ -87,0 +88,6 @@` | +6 / -0 | **R17** register-the-pattern paragraph |
| H5 | `references/briefs/fpcheck-brief.md` | `@@ -31,0 +32,8 @@` | +8 / -0 | **R16** method step 10 |
| H6 | `references/phase0-source-detection.md` | `@@ -95,0 +96,15 @@` | +15 / -0 | **R15** `audit.py identify` + evidence paragraph |
| H7 | `references/phase4-deep-audit.md` | `@@ -84,0 +85,24 @@` | +24 / -0 | **R13** post-collection items 5 and 6 |
| H8 | `references/phase4-deep-audit.md` | `@@ -92,0 +117,2 @@` | +2 / -0 | **R14** `attacker_position`/`boundary_crossed` quality signal |
| H9 | `references/phase5-fp-check.md` | `@@ -92,0 +93,15 @@` | +15 / -0 | **R11** the `pivot` verdict block |
| H10 | `references/phase5-fp-check.md` | `@@ -119,0 +135 @@` | +1 / -0 | **R12** sixth quality gate |
| H11 | `workflows/audit.md` | `@@ -136 +136,45 @@` | +45 / -1 | **R4 + R5** new Step 6 section; the removed line is the old `## Step 6 — Update group status` heading, re-emitted at the end of the hunk as `## Step 7 — Update group status` |
| H12 | `workflows/audit.md` | `@@ -142 +186 @@` | +1 / -1 | **R5** `## Step 7 — Summary + resume note rewrite` → `## Step 8 — …` |
| H13 | `workflows/audit.md` | `@@ -158 +202,16 @@` | +16 / -1 | **R5 + R6(a)** the removed line is the old `## Step 8 — USER GATE` heading, re-emitted at the end of the hunk as `## Step 9 — USER GATE`; the other 15 added lines are the coverage gate in **executable prose** at the end of Step 8. Git merges the two because they abut. |
| H14 | `workflows/audit.md` | `@@ -167,0 +227,3 @@` | +3 / -0 | **R6(b)** the line inside the presented blockquote that reports the gate's outcome to the user |
| H15 | `workflows/audit.md` | `@@ -178,0 +231,3 @@` | +3 / -0 | **R7** three quality checks |
| H16 | `workflows/fpcheck.md` | `@@ -75 +75,30 @@` | +30 / -1 | **R8 + R9** new Step 5 section; the removed line is the old `## Step 5 — Sanity-check verdict completeness` heading, re-emitted at the end of the hunk as `## Step 6 — …` |
| H17 | `workflows/fpcheck.md` | `@@ -85 +114 @@` | +1 / -1 | **R9** `## Step 6 — Assign final IDs` → `## Step 7 — …` |
| H18 | `workflows/fpcheck.md` | `@@ -95 +124 @@` | +1 / -1 | **R9** `## Step 7 — Resume-note rewrite + fork plan` → `## Step 8 — …` |
| H19 | `workflows/fpcheck.md` | `@@ -105 +134 @@` | +1 / -1 | **R9** `## Step 8 — USER GATE` → `## Step 9 — USER GATE` |
| H20 | `workflows/fpcheck.md` | `@@ -126 +155 @@` | +1 / -1 | **R10** the task's one replacement of an existing line |
| H21 | `workflows/recon.md` | `@@ -46,0 +47,12 @@` | +12 / -0 | **R1** Step 2 item 5, `audit.py identify` |
| H22 | `workflows/recon.md` | `@@ -75,0 +88,12 @@` | +12 / -0 | **R2** the `cba_inventory` denominator |
| H23 | `workflows/recon.md` | `@@ -156,0 +181,2 @@` | +2 / -0 | **R3** two quality checks |

No hunk is unmapped. No row in §1 that promised a prose change is missing from
this table (R21 promised *no* change to `### Artifact Layout` and correctly
produces no hunk; R22, R23 and R24 are code and tests, outside this diff's
path filter).

### 2.2 Every removed line, individually accounted for

| # | Diff line | Removed text | Row | Where its text went |
|---|---|---|---|---|
| D1 | H11 | `## Step 6 — Update group status` | R5 | Re-emitted in the same hunk as `## Step 7 — Update group status`. Only the digit changed; the title "Update group status" is byte-identical, and the step's body is not in the diff at all. |
| D2 | H12 | `## Step 7 — Summary + resume note rewrite` | R5 | Re-emitted as `## Step 8 — Summary + resume note rewrite`. Title byte-identical; body untouched. |
| D3 | H13 | `## Step 8 — USER GATE` (audit.md) | R5 | Re-emitted as `## Step 9 — USER GATE`. Title byte-identical; body untouched. (Dispatch Correction 3: the brief's prose calls this "Step 8" after the renumber; it is Step 9.) |
| D4 | H16 | `## Step 5 — Sanity-check verdict completeness` | R9 | Re-emitted at the end of the same hunk as `## Step 6 — Sanity-check verdict completeness`. Title byte-identical; body untouched. |
| D5 | H17 | `## Step 6 — Assign final IDs` | R9 | Re-emitted as `## Step 7 — Assign final IDs`. Title byte-identical; body untouched. |
| D6 | H18 | `## Step 7 — Resume-note rewrite + fork plan` | R9 | Re-emitted as `## Step 8 — Resume-note rewrite + fork plan`. Title byte-identical; body untouched. |
| D7 | H19 | `## Step 8 — USER GATE` (fpcheck.md) | R9 | Re-emitted as `## Step 9 — USER GATE`. Title byte-identical; body untouched. |
| D8 | H20 | `- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule` | R10 | Survives **verbatim as the prefix** of the line that replaces it: `- [ ] Every FALSE_POSITIVE cites a specific HE/PR/CV rule, and records `refuting_mechanism` plus an `enabled_observation` that resolves (`audit.py pivot --check`)`. Checked mechanically (`line.startswith(old)` → True) and locked by `test_every_instruction_the_replaced_blocks_sat_inside_survives`, whose `workflows/fpcheck.md` entry now carries the needle `"cites a specific HE/PR/CV rule"`. |

### 2.3 The count

> **8 lines removed from shipped prose:** 7 step headings renumbered after two
> insertions (D1-D3 in `workflows/audit.md`, D4-D7 in `workflows/fpcheck.md`) —
> each re-emitted in the same diff with an identical title and a changed digit,
> and with its body never entering the diff — plus 1 quality-check bullet
> replaced by a longer bullet that opens with the removed line's full text
> verbatim (D8). **English instructions lost: 0.**

Counting note, repeated so it cannot be read past: the brief's
`grep -c '^-[^-]'` reports **7** because it cannot see D8; the correct count is
**8**. Both are stated; neither hides a line.

### 2.4 Checks that back the "zero lost" claim rather than asserting it

- Twenty-one of twenty-three hunks are pure insertions (`-0`). Insertion cannot
  drop an instruction; only H11, H12, H13, H16, H17, H18, H19 and H20 remove
  anything, and all eight removals are itemised above.
- Not one step *body* appears in the diff. The renumbering touched heading
  lines only, which is what makes D1-D7 verifiable by inspection of eight
  lines rather than by re-reading two workflows.
- `test_every_instruction_the_replaced_blocks_sat_inside_survives` carries the
  one replaced line's surviving clause; `test_the_fpcheck_brief_kept_its_placeholders_and_return_contract`
  pins the five `{…}` placeholders, the return contract, the "18 Hard
  Exclusions and 10 Precedent rules" line and "Capability Validity checks
  CV-1 to CV-3" in the file Stage 1 lost 2 of 9 method steps from.
- The conduct prohibitions Stage 1 lost once are above both insertion points
  and untouched: `workflows/fpcheck.md`'s **IMPORTANT for this phase** static-only
  paragraph, and `workflows/audit.md`'s patch-bypass probe instruction with its
  quality check (`- [ ] Patch-bypass intel from Step 2 has been probed`).

### 2.5 Deviations from the brief, applied

| Source | Deviation | Why |
|---|---|---|
| Dispatch Correction 1 | `coverage … --gate --phase audit`, not `--gate` (R6, and the guard test's asserted string) — **scope accepted; placement corrected in review** | Scope: reproduced on a real db before editing — one inventoried unit analyzed by recon, never opened by audit → `--gate` reports `1/1 analyzed (100.0%)` and **PASS, exit 0**; `--gate --phase audit` reports `0/1` and **FAIL, exit 1**. `_states()` in `audit_core/coverage.py` aggregates with `MAX(c.state='analyzed')` over all phases unless `--phase` narrows it, so the unscoped gate passes on precisely the failure it exists to catch. Placement: the correction also said to insert it "before the 'Say go fpcheck' line", which put it inside the presented `>` block, where it executes in neither mode. Corrected in fix round 1 — see §2.6. |
| Dispatch Correction 2 | Essential Principles numbered **11-15**, not `N…N+4` | The list runs 1-10 and ends at `## Economics Contract`. The `11.`/`12.` further down belong to *Lessons Learned* and were not touched. |
| Dispatch Correction 3 | Renumber targets fixed: audit.md 6→7, 7→8, 8→9 (the USER GATE is **Step 9**, not Step 8 as the brief's prose says); fpcheck.md 5→6, 6→7, 7→8, 8→9 | Verified against the tree before editing. |
| Dispatch Correction 4 | Step 9 (`SKILL.md`) done before Step 10 (lint rules), and `lint-skill` run immediately after the `SKILL.md` edit | `SKILL.md` already carried `audit.py put --table cba_patterns` and no `audit.py sweep`, so the new rule would have fired on the shipped skill. The R20 rationalization row carrying `audit.py sweep --record` is what heals it. `lint-skill` was clean at that checkpoint and clean again with both rules live. |
| **Mine, not in the dispatch** | R17: `references/briefs/audit-brief.md` says "sweeps every registered pattern corpus-wide **with `audit.py sweep`** before the phase exits"; the brief's wording omits the verb | `skill_lint._live_markdown` walks `references/` with `rglob`, so `references/briefs/` is in scope. With the brief's verbatim wording the file names `--table cba_patterns` and no `audit.py sweep`, and the new `pattern-registered-without-sweep` rule fires on the shipped skill. Verified as a counterfactual: substituting the brief's exact wording back in makes the rule fire. Naming the verb is truthful (the orchestrator's Step 6 does run `audit.py sweep`) and is the minimal fix. |
| **Mine, not in the dispatch** | §2's removed-line count uses `grep -c '^-'` minus `grep -c '^--- '` instead of the brief's `grep -c '^-[^-]'` | The brief's command cannot see a removed markdown bullet, which is the one substantive removal in this diff. Reported as 7 by the brief's command, 8 correctly. |

### 2.6 Fix round 1 — the coverage gate was presented, not executed

Found in review, after the first commit (`765d3dd`). The invocation added by R6
sat inside the USER GATE's `>` blockquote, which is the text the orchestrator
**reads out to the user**, not the commands it runs. Consequences:

- **Interactively:** the orchestrator shows the user the command instead of
  running it.
- **Unattended `source` mode:** `source.md` rule 1 auto-resolves gates and its
  Step 2 override list says `**USER GATE:** **skip**`, so the whole step —
  and with it the gate — never appears.

So one of the five mechanisms this stage exists to add shipped **inert**. The
contrast that identifies the right shape is Step 6's `audit.py patterns --gate`,
which is executable prose outside any blockquote and was correct as written.

**Applied:** the invocation and its explanation moved into executable prose at
the end of Step 8, before `## Step 9 — USER GATE`, carrying an explicit
**"Run it — do not present it."**; the blockquote keeps a line reporting the
*outcome*; the quality-check bullet now names the scoped form
`audit.py coverage --gate --phase audit`. The `--gate --phase audit` form is
unchanged — Correction 1's scoping was right, only its placement was wrong.
`workflows/source.md` needed no edit: its Step 2 overrides name only the brief
vars, the live-instance hygiene bullet and the USER GATE skip, so a gate in
executable prose runs unattended. Verified against that list rather than assumed.

**Incremental diff vs `765d3dd`** (`workflows/audit.md` only): 3 hunks,
8 removed lines — the 7 blockquote lines that held the misplaced invocation
(their instruction text re-emitted verbatim in the executable block, which also
gained the scoping rationale and the "do not present it" warning) and the
quality-check bullet `- [ ] \`audit.py coverage --gate\` exits 0, or every
failure it names has been answered`, replaced by the same bullet naming
`--gate --phase audit`. Both removed groups are lines **this task added**, not
pre-existing shipped prose. **English instructions lost: 0.**

**Effect on the full-task reconciliation: none.** Against the pre-task base
`e7d567e` the diff is still **23 hunks and 8 removed lines**, and the 8 are the
same 8 listed in §2.2 — the moved block never existed at `e7d567e`, so
relocating it within the task changes which hunk carries it, not what was taken
out of the shipped prose. Re-verified with a pattern that can see removed
markdown bullets (`grep -c '^-'` minus `grep -c '^--- '`), never
`grep -c '^-[^-]'`.

**New guard:** `test_no_phase_gate_sits_inside_a_presented_blockquote` fails any
`audit.py … --gate` line in `workflows/audit.md`, `recon.md` or `fpcheck.md`
whose first non-space character is `>`. Confirmed it fires on the exact shipped
shape before accepting it as a guard.
