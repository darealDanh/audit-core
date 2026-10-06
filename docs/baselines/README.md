# Baselines

Economics and recall baselines for the audit suite, recorded before any
Stage 1 change. Regenerate with:

    python3 audit.py budget --report <session.jsonl> --json
    python3 audit.py bench --golden tests/goldens/<target> --db <audit.db>

Each baseline file is dated and never edited in place; a new measurement
gets a new file so regressions stay visible in git history.

## Index

Newest first. Baselines are never edited in place; a superseded one stays as
written so the correction is visible in git history.

| File | Target | Status |
|---|---|---|
| `2026-10-05-stage3-tiering-gate.md` | tplink DL110 v2 1.0.11 | **procedure, not a measurement.** The held Sonnet tiering change for feature mapping and FP-check — two before-runs, apply the diff, two after-runs, compare. **Not run; the change is not applied.** Carries the exact diff. |
| `2026-10-05-stage3-gate.md` | tplink DL110 v2 1.0.11 | **procedure, not a measurement.** The Stage 3 gate — two full re-runs covering the five quality mechanisms, cost must fall and recall must be ≥ 9/19. **The gate has not been run.** Also carries the project's open verification gaps. |
| `2026-10-05-stage2-gate.md` | tplink DL110 v2 1.0.11 | **procedure, not a measurement.** The Stage 2 gate — two full re-runs, cost must fall and recall must be ≥ 9/19. **The gate has not been run.** Also carries the project's open verification gaps. |
| `2026-10-05-tplink-baseline.md` | tplink DL110 v2 1.0.11 | **current** |
| `2026-10-04-tplink-baseline.md` | tplink DL110 v2 1.0.11 | **superseded — do not cite.** Its economics figures came from a parser that counted one turn per content block rather than per API call (Σ context 2.33x high, growth/turn 2.33x low) and charged attachments their whole JSONL envelope rather than their rendered text (attachments ~7.8x high). Its recall figures were correct. |
