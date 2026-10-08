"""usage: verify.py LABEL...  -> re-run each mutant against the CURRENT tests."""
import sys, pathlib, shutil, tempfile, re
sys.path.insert(0, "scripts")
import mutate
repo = pathlib.Path.cwd()
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
