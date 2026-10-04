# Baselines

Economics and recall baselines for the audit suite, recorded before any
Stage 1 change. Regenerate with:

    python3 audit.py budget --report <session.jsonl> --json
    python3 audit.py bench --golden tests/goldens/<target> --db <audit.db>

Each baseline file is dated and never edited in place; a new measurement
gets a new file so regressions stay visible in git history.
