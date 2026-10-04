# tplink DL110 v2 baseline — 2026-10-04

Recorded before any Stage 1 change. Regenerate with the commands below.

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

| Metric | Value |
|---|---|
| Cost | $658.37 |
| Turns (billed) | 1,936 (1,950 assistant records) |
| Compaction epochs | 7 |
| Transcript bytes / sha256 | 15,608,662 / `a33f2f5213961c3bac5e65a7d0d3fa0c8673703972f500d54608ea3e49dfa6ca` |
| Σ context | 521.9M (521,880,415) |
| Mean context | 269.6k (269,566) |
| Prefix floor | 40.9k – 66.0k (range across epochs) |
| Growth rate | ~1,115 tok/turn (1,114.97) |
| Prefix term | 19.9% (103,958,547 / 521,880,415) |
| Accumulation term | 80.1% (417,921,868 / 521,880,415) |

Largest accumulation components: thinking blocks 33.7%, tool results 22.3%,
tool-use inputs 13.0%.

Command used: `python3 audit.py budget --report <session.jsonl>` (and
`--json` for the exact figures above). `cost_usd` reported by the tool was
`658.3722115`, i.e. $658.37 — identical to the figure already used for
`--cost` in the bench run below, so no discrepancy to note.

## Recall

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

Every figure above matches the brief's expectation exactly (recall 9/19
(47.4%), 45 findings, $73.15 cost per matched finding) — no discrepancy to
record.

**On the two reported candidates:** `REF-10 ~ G6-F3` and `REF-10 ~ G6-F4` are
both surfaced by a bare three-character `tss` token in REF-10's `locations`
matching `TssRSASecretKey` / `osal_tss_*`. Both were already adjudicated and
**REJECTED** as false pairs (see
`tests/goldens/tplink-dl110v2-1.0.11/README.md`, Adjudication log: REF-10 is a
degenerate-`strncpy` heap overflow in `update_bind_token`; G6-F3 is RSA
private-key disclosure over debug UART, G6-F4 is key-store overwrite in
flash — different defects in both cases). The scorer keeps no record of
rejected candidates, so they reappear on every bench run by design. They are
recorded here, not acted on, and `matches.json` is unchanged.

## Stage 4 gate

Recall ≥ 12/19 at ≤ $45 total, with the asus golden also passing.
