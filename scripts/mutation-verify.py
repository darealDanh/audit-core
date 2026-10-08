"""Re-run named mutants against the CURRENT tests, one at a time.

    python3 scripts/mutation-verify.py "<label>" ...      # labels as printed by the gate
    python3 scripts/mutation-verify.py @labels.txt        # one label per line

Each label is applied alone to a temp copy of the repo and the whole suite
(minus tests/test_mutate.py, with baseline failures deselected) is run; the
outcome is `killed`, `survived`, `timeout` or `error`, classified by
mutate._classify.

Why this exists: `mutate.run_sweep` discards its entire state file whenever
any test file changes, so "narrow the state file and re-run" cannot verify a
test you have just written - it restarts the 54-minute sweep. This checks a
handful of mutants in about 30s each. Evidence from its use:
docs/baselines/2026-10-08-mutation-verify-task15-*.log.
"""
import sys, pathlib, shutil, tempfile, re
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mutate
repo = pathlib.Path(__file__).resolve().parent.parent
pkg = repo / "audit_core"
labels = [l for l in open(sys.argv[1][1:]).read().splitlines() if l] if sys.argv[1].startswith("@") else sys.argv[1:]
with tempfile.TemporaryDirectory() as t:
    tree = pathlib.Path(t).resolve() / repo.name
    shutil.copytree(repo, tree, symlinks=True, ignore=shutil.ignore_patterns(".git",".superpowers","__pycache__",".pytest_cache"))
    base = tuple(mutate._baseline_failures(tree, tree / "tests"))
    print("baseline failures:", base)
    for label in labels:
        mod = label.split(":")[0]
        src = (pkg / mod).read_text()
        ms = [m for m in mutate.enumerate_mutations(src, mod) if m.label == label]
        assert len(ms) == 1, label
        f = tree / "audit_core" / mod
        f.write_text(mutate.apply_mutation(src, ms[0]))
        rc, to, ie = mutate._run_suite(tree, tree / "tests", set(), 300, base)
        f.write_text(src)
        print(f"{label}: {mutate._classify(rc, to, ie)}", flush=True)
