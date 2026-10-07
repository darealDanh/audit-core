# Indicator snapshots

Deterministic leading indicators, per the design spec §6.1: coverage
percentage, surfaces opened, sweep hit counts, and the `not_audited` row
count. They are the between-milestone substitute for the benchmark, which
runs at milestones only because a full re-run cost $658.37.

Write one with:

    python3 audit.py indicators --db <run>/audit.db --target <name> --snapshot

Compare two with:

    python3 audit.py indicators --compare docs/indicators/<a>.json docs/indicators/<b>.json

**Never edited in place.** A second snapshot of the same target on the same
day needs `--label <word>`; the writer refuses to overwrite. A superseded
measurement stays written so a regression remains visible in git history —
the same rule `docs/baselines/` follows.

**`absent` is not `0`.** It means the table is not in that database, not that
the value was zero. The first snapshot here reads `absent` for three of the
four indicators because the only `audit.db` in existence predates Stage 2.
