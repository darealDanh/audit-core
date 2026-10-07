# Stage 3b prose derivation

Total rows: 3

Written before editing. Unifies batch identifiers on the workflow's form
(`workflows/fpcheck.md` letters batches A-F, `BATCH=A`; it is unchanged).
Edits are byte-level; `references/phase5-fp-check.md` stays CRLF. Expected diff:
3 `-` lines and 3 `+` lines (6 total). Four `B1` tokens across three lines (31, 32, 33); one row per line.

| # | File | Line | Before | After | Why |
|---|------|------|--------|-------|-----|
| 1 | references/phase5-fp-check.md | 31 | `--unit B1` | `--unit A` | worked example must match the workflow's batch letter |
| 2 | references/phase5-fp-check.md | 32 | `--var batch_id=B1` | `--var batch_id=A` | same |
| 3 | references/phase5-fp-check.md | 33 | `artifacts/phase5-B1.md` | `artifacts/phase5-A.md` | same; path pattern must match the id |

## 2026-10-07 fix wave: SKILL.md reader side for `indicators` and `rerate` (F1)

Rows: 2. Written before editing. `SKILL.md` is CRLF (397 CRLF, zero bare LF);
edit is byte-level (`read_bytes`/`write_bytes`), each new line ends `\r\n`.
This is a pure insertion after line 54, so no `-` lines. Expected diff:
0 `-` lines and 2 `+` lines (2 total). The "twice the row count" rule
assumes replacement pairs; for a pure insertion the expected figure is 1x the
row count (2), and that is what is reconciled.

| # | File | Line | Before | After | Why |
|---|------|------|--------|-------|-----|
| 1 | SKILL.md | after 54 | (nothing) | `16. **Measure between milestones.** `audit.py indicators` reports the four leading indicators (`--snapshot` records them); `audit.py rerate`` | the verbs had no reader side in shipped prose |
| 2 | SKILL.md | after 54 | (nothing) | `   lists findings rated below their own evidence, and writes nothing.` | same; names `rerate` and that it is read-only |
