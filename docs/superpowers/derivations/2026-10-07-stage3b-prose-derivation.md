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
