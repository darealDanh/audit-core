# scripts/mutate.py
"""Find tests that execute a line while asserting nothing that depends on it.

Line coverage cannot see this class. The project has recorded one instance by
name - "the Task 2 test that substituted an easier input for the one its
finding named" - and the only instrument that finds it is mutation: change the
code, and if every test still passes, no test was checking.

Operators are deliberately few. Each produces source that still parses, so a
surviving mutant means a real gap rather than a syntax error nobody noticed.
Docstrings are never mutated: perturbing prose produces noise, not signal.
"""
from __future__ import annotations

import ast
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

COMPARE_FLIPS = {
    "Lt": "LtE", "LtE": "Lt",
    "Gt": "GtE", "GtE": "Gt",
    "Eq": "NotEq", "NotEq": "Eq",
    "In": "NotIn", "NotIn": "In",
    "Is": "IsNot", "IsNot": "Is",
}
BOOLOP_FLIPS = {"And": "Or", "Or": "And"}


@dataclasses.dataclass(frozen=True, slots=True)
class Mutation:
    module: str
    lineno: int
    col: int
    operator: str
    before: str
    after: str
    # Index of the operator within a Compare's `ops`; 0 for every other
    # operator. Without it, `a <= b <= c` yields two mutations with one label.
    op_index: int = 0

    @property
    def label(self) -> str:
        return (f"{self.module}:{self.lineno}:{self.col} "
                f"{self.operator}[{self.op_index}] "
                f"{self.before}->{self.after}")


def _docstring_nodes(tree: ast.AST) -> set[int]:
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                out.add(id(body[0].value))
    return out


def _decorator_constants(tree: ast.AST) -> set[int]:
    """ids of every Constant reachable from a decorator expression.

    `@dataclass(frozen=True, slots=True)` and friends are configuration, not
    logic: 84 of audit_core's 129 boolean constants are decorator keywords.
    No test should be asserting dataclass semantics, so those mutants are
    near-guaranteed survivors that mean nothing and would bury the real
    ones in triage. Same family of rule as the prose-only string filter.
    """
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            for decorator in node.decorator_list:
                for inner in ast.walk(decorator):
                    if isinstance(inner, ast.Constant):
                        out.add(id(inner))
    return out


def enumerate_mutations(source: str, module: str) -> tuple[Mutation, ...]:
    # Chained comparisons (`a <= b <= c`) carry one Mutation per operator,
    # distinguished by op_index, so labels are unique and every bound is
    # tested. (An earlier version applied only the first matching operator;
    # audit_core has three such chains.) A nested Compare such as `(a<b)<c`
    # starts at a different column from its parent, so positions never clash.
    tree = ast.parse(source)
    skip = _docstring_nodes(tree) | _decorator_constants(tree)
    out: list[Mutation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for index, op in enumerate(node.ops):
                name = type(op).__name__
                if name in COMPARE_FLIPS:
                    out.append(Mutation(module, node.lineno, node.col_offset,
                                        "compare", name, COMPARE_FLIPS[name],
                                        index))
        elif isinstance(node, ast.BoolOp):
            name = type(node.op).__name__
            out.append(Mutation(module, node.lineno, node.col_offset,
                                "boolop", name, BOOLOP_FLIPS[name]))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            out.append(Mutation(module, node.lineno, node.col_offset,
                                "not", "Not", "removed"))
        elif isinstance(node, ast.Constant) and id(node) not in skip:
            value = node.value
            if isinstance(value, bool):
                out.append(Mutation(module, node.lineno, node.col_offset,
                                    "constant", repr(value), repr(not value)))
            elif isinstance(value, int):
                out.append(Mutation(module, node.lineno, node.col_offset,
                                    "constant", repr(value), repr(value + 1)))
            elif isinstance(value, str) and " " in value:
                # Only prose-like strings (containing a space) are mutated.
                # Short space-free tokens - dict keys, enum values, file
                # names, format specifiers - break code loudly when blanked,
                # so the mutant comes back killed/error and says nothing about
                # test quality. Human-facing messages are what tests assert
                # on, so mutating them is the highest-signal string mutation.
                # A space is a cheap, explainable proxy for prose.
                out.append(Mutation(module, node.lineno, node.col_offset,
                                    "constant", repr(value), "''"))
    return tuple(out)


class _Transformer(ast.NodeTransformer):
    def __init__(self, target: Mutation) -> None:
        self.target = target
        self.applied = False

    def _matches(self, node: ast.AST) -> bool:
        return (not self.applied
                and getattr(node, "lineno", None) == self.target.lineno
                and getattr(node, "col_offset", None) == self.target.col)

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        if self.target.operator == "compare" and self._matches(node):
            i = self.target.op_index
            if (i < len(node.ops)
                    and type(node.ops[i]).__name__ == self.target.before):
                node.ops[i] = getattr(ast, self.target.after)()
                self.applied = True
        return node

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.AST:
        self.generic_visit(node)
        # An outer BoolOp shares (lineno, col) with the leftmost nested
        # BoolOp, so the node's own operator must match `before` too.
        if (self.target.operator == "boolop" and self._matches(node)
                and type(node.op).__name__ == self.target.before):
            node.op = getattr(ast, self.target.after)()
            self.applied = True
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        self.generic_visit(node)
        if (self.target.operator == "not" and self._matches(node)
                and isinstance(node.op, ast.Not)):
            self.applied = True
            return node.operand
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if (self.target.operator == "constant" and self._matches(node)
                and repr(node.value) == self.target.before):
            node.value = ast.literal_eval(self.target.after)
            self.applied = True
        return node


def apply_mutation(source: str, mutation: Mutation) -> str:
    tree = _Transformer(mutation).visit(ast.parse(source))
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


OUTCOMES = ("killed", "survived", "timeout", "error")
# pytest exit codes: 2 = interrupted (a collection/import error under -x),
# 4 = usage error, 5 = nothing collected. None of them show a test asserting.
_NOT_A_VERDICT = (2, 4, 5)


@dataclasses.dataclass(frozen=True, slots=True)
class MutantResult:
    mutation: Mutation
    outcome: str


def select_tests(module: str, tests_dir: pathlib.Path) -> tuple[list[str], bool]:
    """`tests/test_<module>.py` plus any `test_<module>*` sibling.

    Returns (paths, is_whole_suite_fallback). `budget` has no exact file and
    is covered by its prefixed siblings.
    """
    stem = pathlib.Path(module).stem
    matches = sorted(pathlib.Path(tests_dir).glob(f"test_{stem}*.py"))
    if matches:
        return [str(p) for p in matches], False
    return [str(tests_dir)], True


def _classify(rc: int | None, timed_out: bool, import_error: bool) -> str:
    """`killed` means pytest returned 1 (a test failed) and nothing else.

    Any other non-zero rc - 2 collection error, 3 internal error, 4 usage,
    5 nothing collected, or a negative signal number from an OOM kill or a
    segfault - is the instrument having a bad day, not evidence that a test
    caught the mutant, so it is `error` and never inflates the kill count.
    """
    if timed_out:
        return "timeout"
    if import_error:
        return "error"
    if rc == 0:
        return "survived"
    if rc == 1:
        return "killed"
    return "error"


def load_state(path: pathlib.Path) -> dict[str, str]:
    path = pathlib.Path(path)
    if not path.is_file():
        return {}
    return json.loads(path.read_text())


def save_state(path: pathlib.Path, state: dict[str, str]) -> None:
    """Atomic write: an interrupt mid-save must not corrupt the checkpoint."""
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def _suite_args(test_paths: list[str]) -> list[str]:
    """Whole-suite runs skip tests/test_mutate.py: it tests this tool against
    fixture packages, cannot depend on audit_core, and nests whole sweeps
    (~20s) inside every confirmation run."""
    return [f"--ignore={pathlib.Path(p) / 'test_mutate.py'}"
            for p in test_paths if pathlib.Path(p).is_dir()]


def _baseline_failures(tree: pathlib.Path, tests: pathlib.Path) -> list[str]:
    """Node ids that already fail on the UNMUTATED copy (e.g. a test that
    needs `.git`, which the copy omits). Left in, they make every whole-suite
    confirmation fail, so every survivor would be recorded as killed."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests),
             *_suite_args([str(tests)]),
             "-q", "--no-header", "--tb=no", "-rfE", "-p", "no:cacheprovider",
             f"--rootdir={tree}"],
            cwd=tree, env=env, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        raise RuntimeError("the unmutated copy's test suite hung (900s); "
                           "cannot establish a baseline") from None
    if proc.returncode == 2:
        raise RuntimeError("unmutated copy fails at collection:\n"
                           + proc.stdout[-600:])
    ids = []
    for line in proc.stdout.splitlines():
        if line.startswith(("FAILED ", "ERROR ")):
            rest = line.split(" ", 1)[1]
            if "[" in rest.split("::")[-1] and "] - " in rest:
                # parametrized id: it may itself contain " - "
                ids.append(rest[:rest.index("] - ") + 1].strip())
            else:
                # a failure message may contain " - ", an id rarely does
                ids.append(rest.split(" - ", 1)[0].strip())
    return ids


def _pytest_run(tree: pathlib.Path, test_paths: list[str], timeout: int,
                deselect: tuple[str, ...] = ()):
    """Run pytest in `tree`; return (rc, timed_out, import_error)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    skip = [a for node in deselect for a in ("--deselect", node)]
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", *test_paths, *_suite_args(test_paths),
             "-q", "--no-header",
             "-p", "no:cacheprovider", "-x", f"--rootdir={tree}", *skip],
            cwd=tree, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, True, False
    return proc.returncode, False, proc.returncode in _NOT_A_VERDICT


PROBE = pathlib.Path(__file__).resolve().parent / "coverage_probe.py"


def _probe_executed(package: pathlib.Path, test_file: pathlib.Path,
                    cwd: pathlib.Path, out: pathlib.Path
                    ) -> dict[str, list[int]]:
    """module name -> lines `test_file` executed, from a cold process."""
    proc = subprocess.run(
        [sys.executable, str(PROBE), "--package", str(package),
         "--tests", str(test_file), "--json-out", str(out)],
        cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0 or not out.is_file():
        raise RuntimeError(f"coverage probe failed on {test_file.name}: "
                           f"{proc.stderr.strip()[:300]}")
    report = json.loads(out.read_text())
    out.unlink()
    result = {}
    for m in report["modules"]:
        executable = _executable_lines(package / m["name"])
        result[m["name"]] = sorted(executable - set(m["unexecuted"]))
    return result


def _executable_lines(path: pathlib.Path) -> set[int]:
    sys.path.insert(0, str(PROBE.parent))
    try:
        import coverage_probe
    finally:
        sys.path.pop(0)
    return coverage_probe.executable_statements(path)


def _map_key(package: pathlib.Path, tests_dir: pathlib.Path) -> str:
    h = hashlib.sha256()
    for q in sorted(tests_dir.glob("test_*.py")):
        h.update(q.name.encode() + b"\0" + q.read_bytes() + b"\0")
    for q in sorted(package.glob("*.py")):
        h.update(q.name.encode() + b"\0")
    return h.hexdigest()


def build_test_map(package: pathlib.Path, tests_dir: pathlib.Path,
                   cache_path: pathlib.Path | None = None
                   ) -> dict[str, dict[str, list[int]]]:
    """test file name -> {module name -> lines it executes}, measured by one
    cold coverage_probe process per test file (not guessed from file names).

    Line-level, not module-level: a file that merely imports a module runs
    every top-level `def` line, so a module-level map says db.py is touched
    by 18 files. Subtracting an import-only baseline is wrong the other way
    (it hides mutants in import-time code). Per-line is right for both.
    Cached at `cache_path`, keyed on test contents and the module list."""
    package = pathlib.Path(package).resolve()
    tests_dir = pathlib.Path(tests_dir).resolve()
    key = _map_key(package, tests_dir)
    if cache_path is not None and cache_path.is_file():
        cached = json.loads(cache_path.read_text())
        if cached.get("key") == key:
            return cached["map"]
    result: dict[str, dict[str, list[int]]] = {}
    print("  building test->line map (one probe per test file)...",
          file=sys.stderr, flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        for test_file in sorted(tests_dir.glob("test_*.py")):
            result[test_file.name] = _probe_executed(
                package, test_file, package.parent, pathlib.Path(tmp) / "p.json")
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = cache_path.with_name(cache_path.name + ".tmp")
        tmp_path.write_text(json.dumps({"key": key, "map": result}))
        os.replace(tmp_path, cache_path)
    return result


def tests_for_mutation(test_map: dict[str, dict[str, list[int]]],
                       mutation: Mutation) -> list[str]:
    """Test files that execute the mutated line; failing that, any that
    execute the module at all (a multi-line expression's line may not be a
    statement line). Empty means no test touches the module."""
    hit = sorted(f for f, mods in test_map.items()
                 if mutation.lineno in mods.get(mutation.module, ()))
    if hit:
        return hit
    return sorted(f for f, mods in test_map.items()
                  if mods.get(mutation.module))


def _run(tree, test_paths, timeout, deselect=()):
    """Per-mutant test run (the seam the tests instrument)."""
    return _pytest_run(tree, test_paths, timeout, deselect)


def _run_suite(tree: pathlib.Path, tests: pathlib.Path, skip: set[str],
               timeout: int, deselect: tuple[str, ...], parallel: int = 8):
    """Run every test file except `skip` (already passed) and test_mutate.py,
    in parallel chunks: a survivor is the common expensive case and the suite
    is ~30s serial. Verdict precedence matches _classify: timeout, then
    error, then killed, and only all-clean is rc 0."""
    files = [str(f) for f in sorted(tests.glob("test_*.py"))
             if f.name not in skip and f.name != "test_mutate.py"]
    if not files:
        return 0, False, False
    workers = max(1, min(parallel, os.cpu_count() or 1, len(files)))
    chunks = [files[i::workers] for i in range(workers)]
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        outs = list(pool.map(
            lambda c: _run(tree, c, timeout, deselect), chunks))
    if any(t for _, t, _ in outs):
        return None, True, False
    # rc 5 here means every test in the chunk was deselected as a known
    # baseline failure, not that nothing ran.
    outs = [(0 if rc == 5 else rc, t, e and rc != 5) for rc, t, e in outs]
    if any(e for _, _, e in outs) and not any(rc == 1 for rc, _, _ in outs):
        return 2, False, True
    if any(rc == 1 for rc, _, _ in outs):
        return 1, False, False  # a real assertion failure is a real kill
    bad = [rc for rc, _, _ in outs if rc != 0]
    return (bad[0] if bad else 0), False, False


_SKIP_DIRS = {".git", ".superpowers", "__pycache__", ".pytest_cache"}


def _digest_tree(root: pathlib.Path) -> str:
    """Hash of every file under `root` (names and bytes), minus caches."""
    h = hashlib.sha256()
    for q in sorted(root.rglob("*")):
        rel = q.relative_to(root)
        if _SKIP_DIRS & set(rel.parts) or not q.is_file():
            continue
        h.update(str(rel).encode() + b"\0" + q.read_bytes() + b"\0")
    return h.hexdigest()


def _canary(tree: pathlib.Path, package: pathlib.Path,
            tests_rel: pathlib.Path, timeout: int,
            baseline: tuple[str, ...]) -> None:
    """Prove mutants reach the tests, or abort.

    A stray PYTHONPATH, an editable install, or a test that hard-codes the
    original repo path makes every test import UNMUTATED code, so every
    mutant would survive and the report would read as a catastrophic
    test-quality finding instead of a broken tool. Plant a lethal change in
    the copy (the package's __init__ raises on import) and require the suite
    to notice, and require the package to resolve inside the copy.
    """
    init = tree / package.name / "__init__.py"
    init.write_text(init.read_text()
                    + "\nraise ImportError('mutate canary')\n")
    rc, timed_out, _ = _pytest_run(tree, [str(tree / tests_rel)], timeout,
                                   baseline)
    if timed_out or rc not in (1, 2):
        raise RuntimeError(
            f"mutation canary survived (rc={rc}, timed_out={timed_out}): "
            f"the tests do not import the mutated copy of {package.name!r}. "
            f"Check PYTHONPATH, editable installs and hard-coded paths. "
            f"Aborting; no report can be trusted.")
    init.write_text(init.read_text().replace(
        "\nraise ImportError('mutate canary')\n", ""))
    probe = subprocess.run(
        [sys.executable, "-c",
         f"import {package.name} as p; print(p.__file__)"],
        cwd=tree, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        capture_output=True, text=True, timeout=timeout)
    where = pathlib.Path(probe.stdout.strip()).resolve() if probe.stdout.strip() else None
    if where is None or tree not in where.parents:
        raise RuntimeError(
            f"{package.name!r} resolves to {where} instead of the temp tree "
            f"{tree}; the sweep would measure unmutated code. Aborting.")


def _baseline_key(repo: pathlib.Path) -> str:
    """Baseline failures depend on the whole tree: fixtures, scripts/, the
    Makefile - not only the package and the test modules."""
    return _digest_tree(repo)


def _verdict_key(package: pathlib.Path, tests_dir: pathlib.Path) -> str:
    """A verdict means 'this suite did/didn't notice this change to this
    source'. It is stale when the source or any test file changes."""
    h = hashlib.sha256()
    for q in sorted(package.glob("*.py")):
        h.update(q.name.encode() + b"\0" + q.read_bytes() + b"\0")
    h.update(_digest_tree(tests_dir).encode())
    return h.hexdigest()


# Only these are durable. A timeout or error may be load-induced and is
# retried on resume.
FINAL_OUTCOMES = ("killed", "survived")


def _cached_baseline(path: pathlib.Path, key: str):
    if path.is_file():
        cached = json.loads(path.read_text())
        if cached.get("key") == key:
            return tuple(cached["failures"])
    return None


def _write_atomic(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def run_sweep(package: pathlib.Path, tests_dir: pathlib.Path,
              state_path: pathlib.Path, timeout: int = 60, jobs: int = 8
              ) -> tuple[MutantResult, ...]:
    """Mutate COPIES of the tree; the real tree is never written to.

    `jobs` workers each own one tree copy for the whole run and restore the
    mutated file after every mutant. Only the parent touches the state file:
    workers return verdicts and the parent checkpoints each as it lands, so a
    killed run resumes from the labels already recorded. The test map and the
    baseline-failure set are computed once in the parent and cached beside
    the state file. Results are returned sorted by label, so two runs report
    identically however the workers interleave.
    """
    package = pathlib.Path(package).resolve()
    tests_dir = pathlib.Path(tests_dir).resolve()
    repo = package.parent
    state_path = pathlib.Path(state_path)
    state = load_state(state_path)
    key_path = state_path.with_name(state_path.name + ".key")
    vkey = _verdict_key(package, tests_dir)
    stored = json.loads(key_path.read_text())["key"] if key_path.is_file() else None
    if state and stored != vkey:
        print(f"  NOTE the package source or the tests changed since this "
              f"state file was written; discarding {len(state)} stale "
              f"verdict(s) and starting over", file=sys.stderr, flush=True)
        state = {}
    retry = [k for k, v in state.items() if v not in FINAL_OUTCOMES]
    if retry:
        print(f"  NOTE retrying {len(retry)} timeout/error verdict(s) from "
              f"the previous run", file=sys.stderr, flush=True)
        state = {k: v for k, v in state.items() if v in FINAL_OUTCOMES}
    _write_atomic(key_path, json.dumps({"key": vkey}))
    test_map = build_test_map(
        package, tests_dir, state_path.with_name(state_path.name + ".testmap"))

    jobs_list = []  # (mutation, source, names, fallback)
    done: dict[str, MutantResult] = {}
    sources: dict[str, str] = {}
    for source_path in sorted(package.glob("*.py")):
        original = source_path.read_text()
        sources[source_path.name] = original
        mutations = enumerate_mutations(original, source_path.name)
        fallback = not any(mods.get(source_path.name)
                           for mods in test_map.values())
        pending = [m for m in mutations if m.label not in state]
        for m in mutations:
            if m.label in state:
                done[m.label] = MutantResult(m, state[m.label])
        if fallback and pending:
            print(f"  NOTE {source_path.name}: no test file executes it; "
                  f"falling back to the whole suite for every mutant "
                  f"(slow)", file=sys.stderr, flush=True)
        for m in pending:
            names = [] if fallback else tests_for_mutation(test_map, m)
            jobs_list.append((m, names, fallback))

    if jobs_list:
        _sweep_pending(package, tests_dir, repo, state_path, state, jobs_list,
                       sources, timeout, jobs, done)
    return tuple(sorted(done.values(), key=lambda r: r.mutation.label))


def _sweep_pending(package, tests_dir, repo, state_path, state, jobs_list,
                   sources, timeout, jobs, done) -> None:
    import threading
    workers = max(1, min(jobs, len(jobs_list)))
    local = threading.local()
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp).resolve()
        ignore = shutil.ignore_patterns(
            ".git", ".superpowers", "__pycache__", ".pytest_cache")

        def make_tree(name: str) -> pathlib.Path:
            tree = root / name / repo.name
            shutil.copytree(repo, tree, symlinks=True, ignore=ignore)
            return tree

        # Baseline: tests that already fail on the UNMUTATED copy.
        base_path = state_path.with_name(state_path.name + ".baseline")
        key = _baseline_key(repo)
        baseline = _cached_baseline(base_path, key)
        if baseline is None:
            tree0 = make_tree("baseline")
            baseline = tuple(_baseline_failures(
                tree0, tree0 / tests_dir.relative_to(repo)))
            _write_atomic(base_path, json.dumps(
                {"key": key, "failures": list(baseline)}))
        if baseline:
            print(f"  NOTE {len(baseline)} test(s) already fail on the "
                  f"unmutated copy and are excluded from every run: "
                  f"{', '.join(baseline)}", file=sys.stderr, flush=True)

        _canary(make_tree("canary"), package, tests_dir.relative_to(repo),
                timeout, baseline)

        counter = iter(range(10**9))
        counter_lock = threading.Lock()

        def work(item):
            mutation, names, fallback = item
            if not hasattr(local, "tree"):
                with counter_lock:
                    n = next(counter)
                local.tree = make_tree(f"w{n}")
            tree = local.tree
            tree_tests = tree / tests_dir.relative_to(repo)
            target = tree / package.name / mutation.module
            original = sources[mutation.module]
            try:
                target.write_text(apply_mutation(original, mutation))
                rel = ([str(tree_tests / n) for n in names]
                       or [str(tree_tests)])
                outcome = _classify(*_run(tree, rel, timeout, baseline))
                # A narrowed selection can manufacture a survivor whose
                # killing test lives in a skipped file: confirm on the rest
                # of the suite before reporting.
                if outcome == "survived" and rel != [str(tree_tests)]:
                    outcome = _classify(*_run_suite(
                        tree, tree_tests, set(names), timeout * 4, baseline,
                        parallel=1 if workers > 1 else 8))
            finally:
                target.write_text(original)
            return mutation, outcome

        pool = concurrent.futures.ThreadPoolExecutor(workers)
        try:
            futures = [pool.submit(work, item) for item in jobs_list]
            for future in concurrent.futures.as_completed(futures):
                mutation, outcome = future.result()
                state[mutation.label] = outcome
                save_state(state_path, state)
                done[mutation.label] = MutantResult(mutation, outcome)
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
