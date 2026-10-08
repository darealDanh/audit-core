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


def enumerate_mutations(source: str, module: str) -> tuple[Mutation, ...]:
    # Chained comparisons (`a <= b <= c`) carry one Mutation per operator,
    # distinguished by op_index, so labels are unique and every bound is
    # tested. (An earlier version applied only the first matching operator;
    # audit_core has three such chains.) A nested Compare such as `(a<b)<c`
    # starts at a different column from its parent, so positions never clash.
    tree = ast.parse(source)
    skip = _docstring_nodes(tree)
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
    if timed_out:
        return "timeout"
    if import_error:
        return "error"
    return "survived" if rc == 0 else "killed"


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
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests), *_suite_args([str(tests)]),
         "-q", "--no-header", "--tb=no", "-rfE", "-p", "no:cacheprovider",
         f"--rootdir={tree}"],
        cwd=tree, env=env, capture_output=True, text=True)
    if proc.returncode == 2:
        raise RuntimeError("unmutated copy fails at collection:\n"
                           + proc.stdout[-600:])
    ids = []
    for line in proc.stdout.splitlines():
        if line.startswith(("FAILED ", "ERROR ")):
            ids.append(line.split(" ", 1)[1].split(" - ")[0].strip())
    return ids


def _run(tree: pathlib.Path, test_paths: list[str], timeout: int,
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


def _run_suite(tree: pathlib.Path, tests: pathlib.Path, skip: set[str],
               timeout: int, deselect: tuple[str, ...]):
    """Run every test file except `skip` (already passed) and test_mutate.py,
    in parallel chunks: a survivor is the common expensive case and the suite
    is ~30s serial. Verdict precedence matches _classify: timeout, then
    error, then killed, and only all-clean is rc 0."""
    files = [str(f) for f in sorted(tests.glob("test_*.py"))
             if f.name not in skip and f.name != "test_mutate.py"]
    if not files:
        return 0, False, False
    workers = max(1, min(8, os.cpu_count() or 1, len(files)))
    chunks = [files[i::workers] for i in range(workers)]
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        outs = list(pool.map(
            lambda c: _run(tree, c, timeout, deselect), chunks))
    if any(t for _, t, _ in outs):
        return None, True, False
    # rc 5 here means every test in the chunk was deselected as a known
    # baseline failure, not that nothing ran.
    outs = [(0 if rc == 5 else rc, t, e and rc != 5) for rc, t, e in outs]
    if any(e for _, _, e in outs):
        return 2, False, True
    bad = [rc for rc, _, _ in outs if rc != 0]
    return (bad[0] if bad else 0), False, False


def run_sweep(package: pathlib.Path, tests_dir: pathlib.Path,
              state_path: pathlib.Path, timeout: int = 60
              ) -> tuple[MutantResult, ...]:
    """Mutate a COPY of the tree; the real tree is never written to.

    Resumable: every verdict is checkpointed to `state_path` as it lands, and
    labels already present there are not re-run.
    """
    package = pathlib.Path(package).resolve()
    tests_dir = pathlib.Path(tests_dir).resolve()
    repo = package.parent
    state = load_state(state_path)
    results: list[MutantResult] = []
    state_path = pathlib.Path(state_path)
    test_map = build_test_map(
        package, tests_dir,
        state_path.with_name(state_path.name + ".testmap"))

    with tempfile.TemporaryDirectory() as tmp:
        tree = pathlib.Path(tmp).resolve() / repo.name
        shutil.copytree(repo, tree, symlinks=True, ignore=shutil.ignore_patterns(
            ".git", ".superpowers", "__pycache__", ".pytest_cache"))
        tree_tests = tree / tests_dir.relative_to(repo)
        baseline = tuple(_baseline_failures(tree, tree_tests))
        if baseline:
            print(f"  NOTE {len(baseline)} test(s) already fail on the "
                  f"unmutated copy and are excluded from every run: "
                  f"{', '.join(baseline)}", file=sys.stderr, flush=True)

        for source_path in sorted(package.glob("*.py")):
            original = source_path.read_text()
            mutations = enumerate_mutations(original, source_path.name)
            if not mutations:
                continue
            fallback = not any(mods.get(source_path.name)
                               for mods in test_map.values())
            if fallback and any(m.label not in state for m in mutations):
                print(f"  NOTE {source_path.name}: no test file executes it; "
                      f"falling back to the whole suite for every mutant "
                      f"(slow)", file=sys.stderr, flush=True)
            target = tree / package.name / source_path.name
            try:
                for mutation in mutations:
                    if mutation.label in state:
                        results.append(
                            MutantResult(mutation, state[mutation.label]))
                        continue
                    target.write_text(apply_mutation(original, mutation))
                    names = ([] if fallback
                             else tests_for_mutation(test_map, mutation))
                    rel = ([str(tree_tests / n) for n in names]
                           or [str(tree_tests)])
                    outcome = _classify(*_run(tree, rel, timeout, baseline))
                    # A narrowed selection can manufacture a survivor whose
                    # killing test lives in a skipped file: confirm on the
                    # whole suite before reporting.
                    if outcome == "survived" and rel != [str(tree_tests)]:
                        outcome = _classify(*_run_suite(
                            tree, tree_tests, set(names), timeout, baseline))
                    state[mutation.label] = outcome
                    save_state(state_path, state)
                    results.append(MutantResult(mutation, outcome))
            finally:
                target.write_text(original)
    return tuple(results)
