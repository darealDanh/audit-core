# tplink DL110 v2 baseline — 2026-10-05

**Supersedes `2026-10-04-tplink-baseline.md`.** The 2026-10-04 economics
figures came from a parser with two measurement defects, both now fixed:

1. It appended a `Turn` for every assistant *record*. Claude Code writes one
   record per content block, not one per API response, and every record of
   such a group repeats the same `message.id` and a byte-identical copy of the
   same `usage`. The reference transcript has 1,950 assistant records against
   857 distinct `message.id`s and **zero** groups carrying differing usage, so
   Σ context was inflated 2.33x. Duplicating a value preserves its mean and
   its ratios, which is why mean context and the prefix/accumulation split
   looked right on 2026-10-04 while the totals did not — and why growth per
   turn was wrong in the *opposite* direction, understating real per-turn
   growth by the same factor.
2. It charged each attachment `estimate_tokens(json.dumps(rec))`, i.e. the
   whole JSONL line including `uuid`, `parentUuid`, `sessionId`, `timestamp`,
   `cwd`, `gitBranch`, `version`, `userType`, `entrypoint`, `isSidechain` and
   `slug`. None of that reaches the model. Only `rendered[*].content` does.

**This is a pure re-run against identical input.** `source_bytes` and
`source_sha256` are unchanged from 2026-10-04 (15,608,662 /
`a33f2f52…`), so nothing about the session changed — only the interpretation
of it. The recall half of the baseline is untouched for the same reason: the
scorer, the golden and the cost were not modified.

Target: `DL110V2_US_1.0.11_Build_260506_Rel.164323`
Session: `~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices-tplink/d87d98a0-1430-4218-a31e-9ae93a9ba275.jsonl`
Audit DB: `Devices/tplink/reports/audit-20260928-073457/audit.db`

Regenerate with:

```bash
python3 audit.py budget --report ~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices-tplink/d87d98a0-1430-4218-a31e-9ae93a9ba275.jsonl
python3 audit.py bench \
  --golden tests/goldens/tplink-dl110v2-1.0.11 \
  --db ~/Documents/Offsec/Opswat/Devices/tplink/reports/audit-20260928-073457/audit.db \
  --cost 658.37
```

## Economics

| Metric | 2026-10-05 | 2026-10-04 (superseded) |
|---|---|---|
| Cost | $658.37 | $658.37 |
| Turns (billed) | 843 of 857 API calls | 1,936 of 1,950 records |
| Compaction epochs | 7 | 7 |
| Transcript bytes / sha256 | 15,608,662 / `a33f2f5213961c3bac5e65a7d0d3fa0c8673703972f500d54608ea3e49dfa6ca` | identical |
| Σ context | 224.2M (224,151,346) | 521.9M (521,880,415) |
| Mean context | 265.9k (265,897) | 269.6k (269,566) |
| Median context | 239,949 | 244,758 |
| p90 context | 494,198 | 500,593 |
| Max context | 711,826 | 711,826 |
| Prefix floor | 40,926 – 66,010 (range across epochs) | identical |
| Growth rate | ~2,573 tok/turn (2,572.66) | ~1,115 tok/turn (1,114.97) |
| Prefix term | 20.2% (45,378,497) | 19.9% (103,958,547) |
| Accumulation term | 79.8% (178,772,849) | 80.1% (417,921,868) |
| modelUsage reconciliation | 830,813,955 (parsed / reported = 0.27x) | not reported |

The 14-call gap between 857 API calls and 843 billed turns is continuation
iterations reporting zero context; the 2026-10-04 figures show the same 14-record
gap (1,950 → 1,936), so nothing changed there.

**Inflation removed: 2.33x** (521,880,415 / 224,151,346 = 2.3283).

Note that `max` is identical across the two runs and `mean`, `median` and `p90`
barely move. That is the C1 defect's signature: duplicating a value leaves the
distribution's shape alone and only multiplies its mass. Any future check that
looks only at mean context will not catch a recurrence; Σ context, turn count
and the reconciliation line will.

### Reconciliation against modelUsage

`cost-state.modelUsage` reports 830,813,955 context tokens
(`inputTokens` + `cacheReadInputTokens` + `cacheCreationInputTokens`, summed
over both models: `claude-opus-5[1m]` 830,708,448 and
`claude-haiku-4-5-20251001` 105,507). Parsed Σ context is 0.27x that.

This divergence is expected and is **not** evidence of a remaining parser
defect: this session dispatched subagents heavily, and a subagent's token usage
is counted in `modelUsage` while its turns live in its own transcript and never
appear in this one. The reconciliation line exists so that a divergence in the
*wrong* direction — parsed exceeding reported — is visible immediately. Under
the 2026-10-04 parser the ratio would have been 0.63x; the move toward 0.27x is
the inflation coming out.

### Composition

Added tokens by component (post-fix), attachment types collapsed:

| # | Component | Added | Share | Attributed |
|---|---|---:|---:|---:|
| 1 | thinking_block | 580,634 | 40.4% | 53,002,166 |
| 2 | tool_result | 383,363 | 26.7% | 35,788,226 |
| 3 | tool_use_input | 223,757 | 15.6% | 12,839,523 |
| 4 | attachments (all types) | 101,754 | 7.1% | 12,810,094 |
| 5 | assistant_text | 100,820 | 7.0% | 8,185,454 |
| 6 | subagent_result | 32,704 | 2.3% | 1,091,882 |
| 7 | user_text | 14,774 | 1.0% | 1,478,230 |

**A headline conclusion is inverted.** On 2026-10-04 attachments aggregated to
386,660 added tokens (22.4%) and 100,542,914 attributed — the second-largest
component of both, behind only thinking blocks and ahead of tool results. They
are now fourth on both measures, at 101,754 added (7.1%) and 12,810,094
attributed, barely ahead of plain assistant text. Three quarters of the
attachment figure was JSON envelope the model never saw.

The largest individual over-charges removed:

| Attachment type | 2026-10-04 added | 2026-10-05 added | Factor |
|---|---:|---:|---:|
| `total_tokens_reminder` | 145,604 | 17,304 | 8.4x |
| `deferred_tools_record` | 29,460 | 0 | — (see below) |
| `invoked_skills` | 55,261 | 25,990 | 2.1x |
| `deferred_tools_delta` | 37,948 | 12,685 | 3.0x |
| `environment` | 9,394 | 2,440 | 3.9x |
| `date` | 1,492 | 190 | 7.9x |

Four attachment types carry no `rendered` payload at all and now correctly cost
zero: `deferred_tools_record`, `hook_success`, `prompt_snapshot` (already
excluded from `CONTEXT_ATTACHMENTS`) and `command_permissions`.
`deferred_tools_record` is the important one — its 29,460 tokens were not merely
over-counted but *double*-counted: that content reaches the model through the
system prompt, which is already inside every epoch's prefix floor.

### Per-epoch

```
  epoch  turns      floor       peak       mean    g/turn
      0     31     40,926    121,465     82,214     2,685
      1     94     42,274    376,620    209,890     3,595
      2    264     53,412    711,826    379,418     2,503
      3    155     49,665    426,706    237,509     2,448
      4    172     66,010    451,294    271,223     2,253
      5     77     54,886    289,793    173,396     3,091
      6     50     55,145    135,159     97,810     1,633
```

### Verbatim tool output

```
session d87d98a0-1430-4218-a31e-9ae93a9ba275  (/Users/danhnguyen/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices-tplink/d87d98a0-1430-4218-a31e-9ae93a9ba275.jsonl)
  cost $658.37   turns 843   epochs 7
  sum_context 224,151,346   mean 265,897   median 239,949   p90 494,198   max 711,826
  prefix_floor 40,926   growth 2,573 tok/turn
  prefix term      45,378,497 ( 20.2%)
  accumulation     178,772,849 ( 79.8%)
  reconciliation   parsed sum_context 224,151,346  vs  modelUsage 830,813,955  (ratio 0.27x)
                   modelUsage is model-reported and counts subagent usage whose turns
                   are not in this transcript, so a large divergence is expected there.

  component                                       added   share     attributed
  thinking_block                                580,634  40.4%     53,002,166
  tool_result                                   383,363  26.7%     35,788,226
  tool_use_input                                223,757  15.6%     12,839,523
  assistant_text                                100,820   7.0%      8,185,454
  subagent_result                                32,704   2.3%      1,091,882
  attachment:invoked_skills                      25,990   1.8%      3,830,926
  attachment:total_tokens_reminder               17,304   1.2%      1,525,125
  user_text                                      14,774   1.0%      1,478,230
  attachment:skill_listing                       14,023   1.0%      2,095,842
  attachment:deferred_tools_delta                12,685   0.9%      1,634,171
  attachment:mcp_instructions_delta               7,620   0.5%        939,872
  attachment:hook_additional_context              6,090   0.4%        750,810
  attachment:agent_listing_delta                  4,795   0.3%        591,155
  attachment:environment                          2,440   0.2%        230,883
  attachment:edited_text_file                     2,164   0.2%         95,216
  attachment:queued_command                       2,099   0.1%         64,236
  attachment:file                                 1,774   0.1%        473,658
  attachment:instructions                         1,043   0.1%        147,183
  attachment:remote_session_change                1,029   0.1%        126,861
  attachment:session_context                        945   0.1%        116,505
  attachment:auto_mode                              714   0.0%         87,414
  attachment:compact_file_reference                 548   0.0%         38,634
  attachment:model                                  301   0.0%         37,109
  attachment:date                                   190   0.0%         24,494

  epoch  turns      floor       peak       mean    g/turn
      0     31     40,926    121,465     82,214     2,685
      1     94     42,274    376,620    209,890     3,595
      2    264     53,412    711,826    379,418     2,503
      3    155     49,665    426,706    237,509     2,448
      4    172     66,010    451,294    271,223     2,253
      5     77     54,886    289,793    173,396     3,091
      6     50     55,145    135,159     97,810     1,633
  source_bytes 15,608,662   source_sha256 a33f2f5213961c3b
```

`cost_usd` reported by the tool is `658.3722115`, i.e. $658.37 — unchanged, and
identical to the `--cost` figure used in the bench run below.

## Recall

**Unchanged from 2026-10-04.** Neither fix touches the scorer, the golden or
the cost, so the recall half of this baseline is a byte-identical re-run.

| Metric | Value |
|---|---|
| Reference CRITICALs | 19 |
| Matched (adjudicated) | 9 |
| Recall | 9/19 (47.4%) |
| Run findings | 45 |
| Cost per matched finding | $73.15 |

Verbatim tool output:

```
golden   tplink-dl110v2-1.0.11
recall   9/19 (47.4%)
findings 45
cost per matched finding  $73.15
missed:     REF-1, REF-2, REF-4, REF-7, REF-8, REF-9, REF-10, REF-11, REF-15, REF-18
candidates needing adjudication:
  REF-10 ~ G6-F3  (location overlap: tss)
  REF-10 ~ G6-F4  (location overlap: tss)
```

**On the two reported candidates:** unchanged from 2026-10-04. `REF-10 ~ G6-F3`
and `REF-10 ~ G6-F4` are both surfaced by a bare three-character `tss` token in
REF-10's `locations` matching `TssRSASecretKey` / `osal_tss_*`. Both were
already adjudicated and **REJECTED** as false pairs (see
`tests/goldens/tplink-dl110v2-1.0.11/README.md`, Adjudication log). The scorer
keeps no record of rejected candidates, so they reappear on every bench run by
design. They are recorded here, not acted on, and `matches.json` is unchanged.

## Stage 4 gate

Recall ≥ 12/19 at ≤ $45 total, with the asus golden also passing. Unchanged —
the gate is a recall-and-cost gate and neither moved.

## R3 ceiling projection (Task 5, `audit_core/ceiling.py`)

Run against the same pinned transcript and confirmed before recording:
`source_bytes` **15,608,662** and `source_sha256` starting **`a33f2f52`** —
both match the figures above, so this is the same input, not a re-measurement
of a changed file.

Command:

```bash
python3 audit.py budget --project --report \
  ~/.claude/projects/-Users-danhnguyen-Documents-Offsec-Opswat-Devices-tplink/d87d98a0-1430-4218-a31e-9ae93a9ba275.jsonl
```

Projection block (verbatim):

```
  ceiling 100,000   checkpoint at 80,000 (80%)
  measured prefix 40,926   growth 2,573 tok/turn
  turns to checkpoint 15   turns to ceiling 22
```

Linearity table (verbatim, every epoch):

```
  epoch  turns  measured mean  predicted mean  deviation
      0     31         82,214          81,195       1.2%
      1     94        209,890         209,447       0.2%
      2    264        379,418         382,619       0.8%
      3    155        237,509         238,185       0.3%
      4    172        271,223         258,652       4.6%
      5     77        173,396         172,339       0.6%
      6     50         97,810          95,152       2.7%
```

The worst deviation is 4.6% (epoch 4), well under the 30% threshold this step
watches for; across all 7 epochs the linear model `context(n) = floor +
g*(turns-1)/2` predicts the measured mean within single digits of percent, so
the turns-to-checkpoint figure (15 turns against a 100k ceiling, at this
session's measured prefix and growth) is a reliable read for this transcript,
not an artifact of a mismatched model.

## Correction appended 2026-10-05 — the candidate block above is no longer reproducible

**Appended, not edited.** This file's policy is that a baseline is never
rewritten in place; a correction gets appended so the superseded text and the
reason it was superseded both stay visible in git history. The "Verbatim tool
output" block and the paragraph under it are left exactly as recorded.

**What is wrong with them.** The block ends with two candidate lines:

```
  REF-10 ~ G6-F3  (location overlap: tss)
  REF-10 ~ G6-F4  (location overlap: tss)
```

and the paragraph below it says "The scorer keeps no record of rejected
candidates, so they reappear on every bench run by design." Both statements
were true of the scorer that produced the block and are false of the scorer on
this branch. An operator running the Stage 2 gate diffs their output against
this file — `2026-10-05-stage2-gate.md` §2 says the comparison is against this
file "and only against that file" — so the two lines would read as a
disappearance that needs explaining. They are not. Two independent changes
removed them, each sufficient on its own:

1. **Candidates are proposed from whole tokens, with a four-character floor.**
   `audit_core/text.MIN_LOCATION_TOKEN` is 4, and `text.location_tokens` drops
   anything shorter before the intersection is taken. REF-10's bare `tss` is
   three characters, so it is gone before either pair can be formed — the
   pairs are removed at source, not suppressed. The old rule tested substring
   containment, which is what let `tss` reach `TssRSASecretKey` and
   `osal_tss_init` in the first place.
2. **The two adjudications are recorded durably.** `rejections.json` in the
   golden now carries both pairs with the reasons from the adjudication log,
   and `bench` loads it and suppresses a rejected pair from the candidate
   list. The claim that the scorer keeps no record of rejected candidates
   describes a gap that has since been closed.

Because `tss` no longer survives tokenization, the two pairs never overlap at
all, so `rejections.json` suppresses nothing on this run and the
`N candidate(s) suppressed` line does not print either. The file is kept
deliberately: the four-character floor is a *heuristic* that could be tuned or
reverted, whereas the adjudication is a *fact* about those two pairs that
stays true however the heuristic changes.

**What did not move.** Recall **9/19 (47.4%)**, run findings **45**, cost per
matched finding **$73.15** — identical to the recorded block. Candidate
generation feeds adjudication only; the match path reads `matches.json` and
nothing else, so no change to it can move recall. The recall table above and
the Stage 4 gate stand as written.

So the reproducible output of the recorded command on this branch is the same
block with its last three lines absent:

```
golden   tplink-dl110v2-1.0.11
recall   9/19 (47.4%)
findings 45
cost per matched finding  $73.15
missed:     REF-1, REF-2, REF-4, REF-7, REF-8, REF-9, REF-10, REF-11, REF-15, REF-18
```

`tests/goldens/tplink-dl110v2-1.0.11/README.md` is the full account: the
adjudication log for both pairs, the `rejections.json` contract, the token
rule and the five generic word tokens that survive the floor and remain
latent.

---

## Appended 2026-10-07 — severity agreement (Stage 3b)

Re-scored with `audit.py bench` after Stage 3b added severity agreement. **The
underlying run is unchanged**; this is the same stored `audit.db` read by a
scorer that now compares a dimension it previously loaded and ignored. No
audit was run.

| Metric | Value |
|---|---|
| Recall (unchanged) | 9/19 |
| Severity agreement | 5/9 |
| Under-rated | 4 |
| Worst delta | 3 ladder steps (REF-17, CRITICAL filed LOW) |
| Weighted recall | 7.25/19 |

Recall is unchanged by design: it is matched on root cause and location, and
that is what the ≥ 9/19 floor and the ≥ 12/19 target are written against.
