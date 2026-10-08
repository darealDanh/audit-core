# tests/test_mutate.py
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import mutate  # noqa: E402


def test_enumerates_a_comparison_flip():
    muts = mutate.enumerate_mutations("def f(n):\n    return n < 0\n", "m.py")
    ops = {(m.operator, m.before, m.after) for m in muts}
    assert ("compare", "Lt", "LtE") in ops


def test_enumerates_a_boolop_swap():
    muts = mutate.enumerate_mutations("def f(a, b):\n    return a and b\n", "m.py")
    assert any(m.operator == "boolop" for m in muts)


def test_enumerates_a_constant_perturbation():
    muts = mutate.enumerate_mutations("LIMIT = 200\n", "m.py")
    assert any(m.operator == "constant" and m.after == "201" for m in muts)


def test_does_not_mutate_a_docstring():
    """Perturbing prose produces noise, not a test signal."""
    muts = mutate.enumerate_mutations('def f():\n    """Doc."""\n    return 1\n',
                                      "m.py")
    assert all("Doc." not in m.before for m in muts)


def test_apply_mutation_changes_exactly_one_site():
    source = "def f(a, b):\n    return a < b or a < 0\n"
    muts = [m for m in mutate.enumerate_mutations(source, "m.py")
            if m.operator == "compare"]
    assert len(muts) == 2
    mutated = mutate.apply_mutation(source, muts[0])
    assert mutated != source
    assert mutated.count("<=") == 1


def test_apply_mutation_produces_parseable_source():
    import ast
    source = "def f(n):\n    return n == 0\n"
    for m in mutate.enumerate_mutations(source, "m.py"):
        ast.parse(mutate.apply_mutation(source, m))


def test_not_removal_drops_the_negation():
    source = "def f(x):\n    return not x\n"
    muts = [m for m in mutate.enumerate_mutations(source, "m.py")
            if m.operator == "not"]
    assert len(muts) == 1
    assert "not" not in mutate.apply_mutation(source, muts[0])


def test_boolop_swap_is_applied():
    source = "def f(a, b):\n    return a and b\n"
    m = next(m for m in mutate.enumerate_mutations(source, "m.py")
             if m.operator == "boolop")
    assert (m.before, m.after) == ("And", "Or")
    assert "a or b" in mutate.apply_mutation(source, m)


def test_constant_operators_cover_bool_int_str():
    muts = mutate.enumerate_mutations("A = True\nB = 5\nC = 'x y'\n", "m.py")
    got = {(m.before, m.after) for m in muts if m.operator == "constant"}
    assert got == {("True", "False"), ("5", "6"), ("'x y'", "''")}


def test_empty_string_is_not_mutated():
    assert mutate.enumerate_mutations("A = ''\n", "m.py") == ()


DOCSTRINGS = '''"""Module doc."""
def f():
    """Func doc."""
    return 1
async def g():
    """Async doc."""
    return 2
class C:
    """Class doc."""
    x = 3
'''


def test_no_docstring_kind_is_mutated():
    befores = {m.before for m in mutate.enumerate_mutations(DOCSTRINGS, "m.py")}
    assert not any("doc" in b for b in befores)
    assert befores == {"1", "2", "3"}


def test_non_docstring_string_is_still_mutated():
    muts = mutate.enumerate_mutations('def f():\n    x = "keep me"\n    return x\n',
                                      "m.py")
    assert any(m.before == "'keep me'" for m in muts)


SAMPLE = '''"""Doc."""
def f(a, b, s):
    """Doc."""
    if not a and b or a in s:
        return a is not None and a != 3 and s == "x y"
    if 0 <= a <= 10:
        return f"value {a} is ok"
    return True if a >= b else a <= b < 9
'''


def test_every_operator_fires_and_every_mutant_parses_and_differs():
    import ast
    muts = mutate.enumerate_mutations(SAMPLE, "m.py")
    assert {m.operator for m in muts} == {"compare", "boolop", "not", "constant"}
    baseline = ast.unparse(ast.parse(SAMPLE))
    for m in muts:
        mutated = mutate.apply_mutation(SAMPLE, m)
        ast.parse(mutated)
        assert mutated != baseline, m.label


def test_labels_are_unique():
    muts = mutate.enumerate_mutations(SAMPLE, "m.py")
    labels = [m.label for m in muts]
    assert len(labels) == len(set(labels))


def test_chained_comparison_mutates_each_bound_independently():
    import ast
    source = "def f(v):\n    return 1 <= v <= 10\n"
    muts = mutate.enumerate_mutations(source, "m.py")
    assert [m.op_index for m in muts if m.operator == "compare"] == [0, 1]
    outs = [mutate.apply_mutation(source, m) for m in muts
            if m.operator == "compare"]
    assert "1 < v <= 10" in outs[0]
    assert "1 <= v < 10" in outs[1]
    assert all(ast.parse(o) for o in outs)


def test_label_format():
    m = mutate.Mutation("m.py", 3, 4, "compare", "Lt", "LtE")
    assert m.label == "m.py:3:4 compare[0] Lt->LtE"


def test_nested_boolops_sharing_a_position_each_apply():
    """`(a and b) or c`: both BoolOps start at the same column."""
    source = "def f(a, b, c):\n    return a and b or c\n"
    muts = [m for m in mutate.enumerate_mutations(source, "m.py")
            if m.operator == "boolop"]
    assert len(muts) == 2
    outs = {mutate.apply_mutation(source, m) for m in muts}
    assert len(outs) == 2
    assert all(o != mutate.apply_mutation(source, mutate.Mutation(
        "m.py", 1, 0, "none", "", "")) for o in outs)


def test_only_prose_like_strings_are_mutated():
    prose = mutate.enumerate_mutations('M = "not a valid state"\n', "m.py")
    assert any(m.operator == "constant" and m.after == "''" for m in prose)
    assert mutate.enumerate_mutations('K = "struct"\n', "m.py") == ()


# ---- Task 12: the runner ---------------------------------------------------

def test_select_tests_prefers_the_matching_file(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_qualify.py").write_text("")
    (tests / "test_db.py").write_text("")
    paths, fallback = mutate.select_tests("qualify.py", tests)
    assert fallback is False
    assert [pathlib.Path(p).name for p in paths] == ["test_qualify.py"]


def test_select_tests_includes_prefixed_siblings(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("test_budget_epochs.py", "test_budget_attribution.py",
                 "test_db.py"):
        (tests / name).write_text("")
    paths, fallback = mutate.select_tests("budget.py", tests)
    assert fallback is False
    assert sorted(pathlib.Path(p).name for p in paths) == [
        "test_budget_attribution.py", "test_budget_epochs.py"]


def test_select_tests_falls_back_to_the_whole_suite(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_other.py").write_text("")
    paths, fallback = mutate.select_tests("nothing.py", tests)
    assert fallback is True
    assert paths == [str(tests)]


def test_a_hanging_mutant_is_a_timeout_not_a_survivor():
    assert mutate._classify(rc=None, timed_out=True, import_error=False) == "timeout"


def test_a_mutant_that_breaks_import_is_an_error_not_a_kill():
    assert mutate._classify(rc=2, timed_out=False, import_error=True) == "error"


def test_a_clean_pass_is_a_survivor():
    assert mutate._classify(rc=0, timed_out=False, import_error=False) == "survived"


def test_a_test_failure_is_a_kill():
    assert mutate._classify(rc=1, timed_out=False, import_error=False) == "killed"


def test_state_round_trips(tmp_path):
    state = tmp_path / "sub" / "state.json"
    done = mutate.Mutation("m.py", 2, 11, "compare", "Lt", "LtE")
    mutate.save_state(state, {done.label: "killed"})
    assert mutate.load_state(state) == {done.label: "killed"}
    assert mutate.load_state(tmp_path / "absent.json") == {}


def _fixture_repo(tmp_path, m_source, test_source):
    repo = tmp_path / "repo"
    pkg = repo / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "m.py").write_text(m_source)
    tests = repo / "tests"
    tests.mkdir()
    # Path is derived from __file__ so the test imports the tree it lives in
    # (the mutated copy), never the original.
    (tests / "test_m.py").write_text(
        "import sys, pathlib\n"
        "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
        + test_source)
    return repo, pkg, tests


TWO_FUNCS = ("def over(n):\n    return n > 10\n\n"
             "def under(n):\n    return n < 10\n")
WEAK_AND_STRONG = (
    "from pkg.m import over, under\n"
    "def test_over_at_the_boundary():\n"
    "    assert over(10) is False\n"
    "    assert over(11) is True\n"
    "def test_under_far_from_it():\n"
    "    assert under(0) is True\n")


def test_sweep_finds_a_known_surviving_mutant_end_to_end(tmp_path):
    """Real pytest subprocesses over a real mutated copy: the weak test's
    mutant must survive and the strong test's mutant must be killed."""
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    results = mutate.run_sweep(pkg, tests, tmp_path / "state.json", timeout=60)
    by_label = {r.mutation.label: r.outcome for r in results}
    survived = {k for k, v in by_label.items() if v == "survived"}
    killed = {k for k, v in by_label.items() if v == "killed"}
    # Every mutant of the weak test's function (line 5) survives; every mutant
    # of the strongly tested function (line 2) is killed. Nothing else.
    assert survived == {k for k in by_label if k.startswith("m.py:5:")}, by_label
    assert any("Lt->LtE" in k for k in survived), by_label
    assert killed == {k for k in by_label if k.startswith("m.py:2:")}, by_label
    assert any("Gt->GtE" in k for k in killed), by_label


def test_sweep_never_writes_into_the_real_tree(tmp_path):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    before = {p: p.read_text() for p in repo.rglob("*.py")}
    mutate.run_sweep(pkg, tests, tmp_path / "state.json", timeout=60)
    assert {p: p.read_text() for p in repo.rglob("*.py")} == before


def test_a_mutant_that_breaks_import_is_reported_as_error_end_to_end(tmp_path):
    # `a in b` -> `a not in b` is fine; make a mutant that raises at import:
    # a module-level comparison evaluated on import, mutated to raise.
    repo, pkg, tests = _fixture_repo(
        tmp_path,
        "ITEMS = [1, 2]\nassert 1 in ITEMS\n\ndef f():\n    return 1\n",
        "from pkg.m import f\ndef test_f():\n    assert f() == 1\n")
    results = mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60)
    by_op = {r.mutation.before + "->" + r.mutation.after: r.outcome
             for r in results}
    assert by_op["In->NotIn"] == "error", by_op


def test_sweep_resumes_and_does_not_rerun_checkpointed_mutants(tmp_path, monkeypatch):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    state = tmp_path / "state.json"
    calls = {"n": 0}
    real_run = mutate._run

    class Boom(Exception):
        pass

    def dying_run(*a, **k):
        calls["n"] += 1
        if calls["n"] > 1:
            raise Boom
        return real_run(*a, **k)

    monkeypatch.setattr(mutate, "_run", dying_run)
    with pytest.raises(Boom):
        mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    partial = mutate.load_state(state)
    assert len(partial) == 1, "exactly the first mutant should be checkpointed"

    ran = []

    def counting_run(tree, paths, timeout, *rest):
        ran.append(paths)
        return real_run(tree, paths, timeout, *rest)

    monkeypatch.setattr(mutate, "_run", counting_run)
    results = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    total = len(mutate.enumerate_mutations(TWO_FUNCS, "m.py"))
    assert len(results) == total
    resumed_label = next(iter(partial))
    assert next(r for r in results
                if r.mutation.label == resumed_label).outcome == partial[resumed_label]
    survivors = sum(1 for r in results if r.outcome == "survived")
    # one run per non-checkpointed mutant, plus one full-suite recheck per survivor
    assert len(ran) >= total - 1
    assert len(ran) <= (total - 1) + survivors


def test_whole_suite_fallback_is_announced(tmp_path, capsys):
    """A module no test executes runs the whole suite - and says so."""
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    (pkg / "dead.py").write_text("def f(n):\n    return n > 1\n")
    results = mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60)
    assert "dead.py: no test file executes it" in capsys.readouterr().err
    dead = [r for r in results if r.mutation.module == "dead.py"]
    assert dead and all(r.outcome == "survived" for r in dead)



def _two_file_repo(tmp_path):
    """Test files named nothing like the module: only coverage can pair them."""
    repo, pkg, tests = _fixture_repo(
        tmp_path, TWO_FUNCS,
        "from pkg.m import over\ndef test_over():\n    assert over(11)\n")
    (tests / "test_m.py").rename(tests / "test_alpha.py")
    (tests / "test_beta.py").write_text(
        "import sys, pathlib\n"
        "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
        "from pkg.m import under\n"
        "def test_under():\n    assert under(0)\n")
    return repo, pkg, tests


def test_the_test_map_pairs_files_to_mutants_by_executed_line(tmp_path):
    repo, pkg, tests = _two_file_repo(tmp_path)
    tmap = mutate.build_test_map(pkg, tests)
    muts = {m.lineno: m for m in
            mutate.enumerate_mutations((pkg / "m.py").read_text(), "m.py")}
    assert mutate.tests_for_mutation(tmap, muts[2]) == ["test_alpha.py"]
    assert mutate.tests_for_mutation(tmap, muts[5]) == ["test_beta.py"]


def test_a_module_no_test_executes_has_no_selected_tests(tmp_path):
    repo, pkg, tests = _two_file_repo(tmp_path)
    (pkg / "dead.py").write_text("def f(n):\n    return n > 1\n")
    tmap = mutate.build_test_map(pkg, tests)
    mut = mutate.enumerate_mutations((pkg / "dead.py").read_text(), "dead.py")[0]
    assert mutate.tests_for_mutation(tmap, mut) == []


def test_the_test_map_is_cached_and_invalidated_by_a_changed_suite(tmp_path, monkeypatch):
    repo, pkg, tests = _two_file_repo(tmp_path)
    cache = tmp_path / "map.json"
    first = mutate.build_test_map(pkg, tests, cache)

    def boom(*a, **k):
        raise AssertionError("probe re-ran despite a valid cache")

    monkeypatch.setattr(mutate, "_probe_executed", boom)
    assert mutate.build_test_map(pkg, tests, cache) == first
    (tests / "test_beta.py").write_text((tests / "test_beta.py").read_text() + "\n# edit\n")
    with pytest.raises(AssertionError, match="re-ran"):
        mutate.build_test_map(pkg, tests, cache)


def test_a_narrow_survivor_killed_elsewhere_is_not_reported_as_a_survivor(tmp_path):
    """test_alpha only pins `over` at 11; `over(10)` is pinned by a file that
    shares no name with the module. Gt->GtE survives alpha alone and must be
    recorded killed after the whole-suite confirmation."""
    repo, pkg, tests = _two_file_repo(tmp_path)
    (tests / "test_gamma.py").write_text(
        "import sys, pathlib\n"
        "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))\n"
        "from pkg.m import over\n"
        "def test_over_boundary():\n    assert over(10) is False\n")
    results = mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60)
    gt = next(r for r in results if "Gt->GtE" in r.mutation.label)
    assert gt.outcome == "killed"


def test_a_test_that_already_fails_does_not_turn_survivors_into_kills(tmp_path):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    (tests / "test_broken.py").write_text("def test_broken():\n    assert False\n")
    results = mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60)
    lt = next(r for r in results if "Lt->LtE" in r.mutation.label)
    assert lt.outcome == "survived"


def test_decorator_constants_are_not_mutated():
    src = ("from dataclasses import dataclass\n"
           "@dataclass(frozen=True, slots=True)\n"
           "class A:\n"
           "    x: int = 5\n"
           "@cache(maxsize=3)\n"
           "def f():\n"
           "    return True\n")
    befores = {(m.lineno, m.before) for m in mutate.enumerate_mutations(src, "m.py")}
    assert (2, "True") not in befores and (5, "3") not in befores
    # the class body and function body are still mutated
    assert (4, "5") in befores and (7, "True") in befores


def test_parallel_sweep_matches_serial_and_is_sorted(tmp_path):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    serial = mutate.run_sweep(pkg, tests, tmp_path / "a.json", timeout=60, jobs=1)
    parallel = mutate.run_sweep(pkg, tests, tmp_path / "b.json", timeout=60, jobs=4)
    assert [(r.mutation.label, r.outcome) for r in parallel] == \
        [(r.mutation.label, r.outcome) for r in serial]
    labels = [r.mutation.label for r in parallel]
    assert labels == sorted(labels)
    assert mutate.load_state(tmp_path / "b.json") == {
        r.mutation.label: r.outcome for r in parallel}


def test_baseline_is_cached_beside_the_state_file(tmp_path, monkeypatch):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    state = tmp_path / "s.json"
    mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    assert (tmp_path / "s.json.baseline").is_file()
    state.unlink()  # force a second full sweep with the sidecars intact

    def boom(*a, **k):
        raise AssertionError("baseline recomputed despite a valid cache")

    monkeypatch.setattr(mutate, "_baseline_failures", boom)
    mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)


def test_only_rc_1_is_a_kill():
    """Review: every other non-zero rc is the instrument failing, not a kill."""
    for rc in (3, 4, 5, -9, -11, 137):
        assert mutate._classify(rc=rc, timed_out=False, import_error=False) == "error"
    assert mutate._classify(rc=1, timed_out=False, import_error=False) == "killed"


def test_the_confirmation_run_gets_four_times_the_timeout(tmp_path, monkeypatch):
    """A serial whole-suite pass under load exceeds the per-mutant timeout.
    Dropping the multiplier once produced 51 spurious timeouts in 231."""
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    seen = []

    def spy(tree, tests_path, skip, timeout, deselect, parallel=8):
        seen.append(timeout)
        return 0, False, False

    monkeypatch.setattr(mutate, "_run_suite", spy)
    results = mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=7, jobs=1)
    assert any(r.outcome == "survived" for r in results)
    assert seen and set(seen) == {28}


def test_stale_verdicts_are_discarded_when_a_test_changes(tmp_path, capsys):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    state = tmp_path / "s.json"
    first = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    lt = next(r for r in first if "Lt->LtE" in r.mutation.label)
    assert lt.outcome == "survived"
    # Task 15 adds the missing test: the old `survived` verdict is now wrong.
    (tests / "test_m.py").write_text(
        (tests / "test_m.py").read_text()
        + "def test_under_at_the_boundary():\n    assert under(10) is False\n")
    capsys.readouterr()
    second = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    assert "discarding" in capsys.readouterr().err
    lt2 = next(r for r in second if "Lt->LtE" in r.mutation.label)
    assert lt2.outcome == "killed"


def test_timeout_and_error_verdicts_are_retried_on_resume(tmp_path, capsys):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    state = tmp_path / "s.json"
    first = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    gt = next(r for r in first if "Gt->GtE" in r.mutation.label)
    lt = next(r for r in first if "Lt->LtE" in r.mutation.label)
    saved = mutate.load_state(state)
    saved[gt.mutation.label] = "timeout"      # load-induced, not final
    saved[lt.mutation.label] = "survived"     # final: must be kept
    mutate.save_state(state, saved)
    capsys.readouterr()
    second = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    assert "retrying 1" in capsys.readouterr().err
    assert next(r for r in second
                if r.mutation.label == gt.mutation.label).outcome == "killed"


def test_the_canary_aborts_a_sweep_whose_tests_import_the_original_tree(tmp_path):
    """The brief's own bug: tests that put the ORIGINAL repo on sys.path
    never see a mutant. The sweep must refuse to produce a report."""
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    (tests / "test_m.py").write_text(
        f"import sys\nsys.path.insert(0, {str(repo)!r})\n" + WEAK_AND_STRONG)
    with pytest.raises(RuntimeError, match="canary survived"):
        mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60, jobs=1)
    assert mutate.load_state(tmp_path / "s.json") == {}


def test_a_stray_pythonpath_cannot_hide_the_mutated_copy(tmp_path, monkeypatch):
    """cwd precedes PYTHONPATH under `python -m pytest`, so a stray PYTHONPATH
    at the original repo must not change any verdict."""
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    (tests / "test_m.py").write_text(WEAK_AND_STRONG)
    monkeypatch.setenv("PYTHONPATH", str(repo))
    results = mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60, jobs=1)
    assert any(r.outcome == "killed" and "Gt->GtE" in r.mutation.label
               for r in results)


def test_a_discarded_state_is_persisted_before_the_new_key(tmp_path):
    """Stale state + changed tests + a run that aborts before any verdict
    must not leave the stale verdicts on disk under a matching key."""
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    state = tmp_path / "s.json"
    first = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    stale = next(r for r in first if "Lt->LtE" in r.mutation.label)
    assert stale.outcome == "survived"
    # Tests change (as in Task 15) and the next run aborts at the canary,
    # before it can write a single verdict.
    (tests / "test_m.py").write_text(
        f"import sys\nsys.path.insert(0, {str(repo)!r})\n" + WEAK_AND_STRONG
        + "def test_under_at_the_boundary():\n    assert under(10) is False\n")
    with pytest.raises(RuntimeError, match="canary survived"):
        mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    assert mutate.load_state(state) == {}, "stale verdicts left on disk"
    # Fix the tests; a fresh run must re-measure, not trust the old survivor.
    (tests / "test_m.py").write_text(
        WEAK_AND_STRONG
        + "def test_under_at_the_boundary():\n    assert under(10) is False\n")
    again = mutate.run_sweep(pkg, tests, state, timeout=60, jobs=1)
    lt = next(r for r in again if "Lt->LtE" in r.mutation.label)
    assert lt.outcome == "killed"


def test_node_id_parsing_handles_both_hostile_shapes():
    # plain id; the MESSAGE holds brackets and " - "
    assert mutate._node_id(
        "tests/t.py::test_x - assert d[0] - 1 == 2") == "tests/t.py::test_x"
    assert mutate._node_id(
        "tests/t.py::test_x - AssertionError: a[1] - b") == "tests/t.py::test_x"
    # parametrized id whose PARAMETER holds " - "
    assert mutate._node_id(
        "tests/t.py::test_p[a - b] - assert 1 == 2") == "tests/t.py::test_p[a - b]"
    assert mutate._node_id("tests/t.py::test_p[a] - boom") == "tests/t.py::test_p[a]"
    assert mutate._node_id("tests/t.py::test_p") == "tests/t.py::test_p"


def test_baseline_failures_are_deselected_for_hostile_node_ids(tmp_path):
    """End to end: real failing tests with awkward ids and messages are
    recognised as baseline and deselected, so they cannot make every
    confirmation fail."""
    tests = tmp_path / "repo" / "tests"
    tests.mkdir(parents=True)
    (tests / "test_h.py").write_text(
        "import pytest\n"
        "def test_plain():\n"
        "    d = [3]\n"
        "    assert d[0] - 1 == 5\n"
        "@pytest.mark.parametrize('v', ['a - b'])\n"
        "def test_param(v):\n"
        "    assert v == 'z'\n")
    tree = (tmp_path / "repo").resolve()
    ids = mutate._baseline_failures(tree, tree / "tests")
    assert len(ids) == 2
    rc, _, _ = mutate._pytest_run(tree, [str(tree / "tests")], 60, tuple(ids))
    assert rc == 5  # everything deselected: nothing left to fail


def test_a_package_without_init_gets_a_legible_canary_error(tmp_path):
    repo, pkg, tests = _fixture_repo(tmp_path, TWO_FUNCS, WEAK_AND_STRONG)
    (pkg / "__init__.py").unlink()
    with pytest.raises(RuntimeError, match="no __init__.py"):
        mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60, jobs=1)


def _load_harness():
    import importlib.util
    root = pathlib.Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("harness_under_test", root / "scripts" / "harness.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    return harness


def test_harness_exposes_mutate_but_keeps_it_out_of_default_and_all():
    harness = _load_harness()
    assert "mutate" in harness.GATES
    assert "mutate" not in harness.DEFAULT
    assert "mutate" not in harness.ALL_EXTRA, (
        "ci.yml runs --all across three Python versions; a ~1 hour "
        "non-skipping gate there is hours per push")


def test_all_flag_selects_exactly_default_plus_extra(monkeypatch, capsys):
    harness = _load_harness()
    ran = []
    monkeypatch.setattr(harness, "GATES", {
        n: (lambda n=n: ran.append(n) or harness.Result(n, harness.PASS, "ok"))
        for n in list(harness.GATES)})
    harness.main(["--all", "--json"])
    assert ran == harness.DEFAULT + harness.ALL_EXTRA
    assert "mutate" not in ran


def test_allowlist_refuses_an_entry_without_a_reason():
    harness = _load_harness()
    ok = harness.parse_mutation_allowlist(
        "# c\n\nm.py:1:2 Compare[0] <->  <=  # equivalent: never observable\n")
    assert ok == {"m.py:1:2 Compare[0] <->  <=": "equivalent: never observable"}
    for bad in ("m.py:1:2 Compare[0] <-><=\n", "m.py:1:2 Compare[0] <-><=  #\n"):
        with pytest.raises(ValueError, match="no reason"):
            harness.parse_mutation_allowlist(bad)


ROOT = pathlib.Path(__file__).resolve().parent.parent


def _fake_sweep(monkeypatch, results=None, exc=None):
    """Real signature, records what the gate sends."""
    calls = []

    def run_sweep(package, tests_dir, state_path, timeout=60, jobs=8):
        calls.append((package, tests_dir, state_path))
        if exc:
            raise exc
        return results
    monkeypatch.setattr(mutate, "run_sweep", run_sweep)
    return calls


def _mut(line, outcome):
    return mutate.MutantResult(
        mutate.Mutation("m.py", line, 0, "Compare", "<", "<="), outcome)


def _allow(monkeypatch, harness, *results):
    monkeypatch.setattr(harness, "parse_mutation_allowlist",
                        lambda text: {r.mutation.label: "equivalent" for r in results})


def test_gate_sends_the_real_paths_to_the_sweep(monkeypatch):
    harness = _load_harness()
    calls = _fake_sweep(monkeypatch, results=(_mut(1, "killed"),))
    harness.gate_mutate()
    assert calls == [(ROOT / "audit_core", ROOT / "tests",
                      ROOT / ".mutate-state.json")]


def test_gate_fails_naming_unexplained_survivors_and_counts(monkeypatch):
    harness = _load_harness()
    _fake_sweep(monkeypatch, results=(_mut(1, "killed"), _mut(2, "survived")))
    res = harness.gate_mutate()
    assert res.name == "mutate" and res.status == harness.FAIL
    assert "m.py:2:0" in res.detail and "m.py:1:0" not in res.detail
    for frag in ("2 mutants", "1 killed", "1 survived", "0 timeout",
                 "0 error", "1 unexplained"):
        assert frag in res.summary


def test_gate_passes_when_every_survivor_is_allowlisted(monkeypatch):
    harness = _load_harness()
    surv = _mut(2, "survived")
    _fake_sweep(monkeypatch, results=(_mut(1, "killed"), surv))
    _allow(monkeypatch, harness, surv)
    res = harness.gate_mutate()
    assert res.status == harness.PASS and "0 unexplained" in res.summary


def test_gate_fails_on_a_stale_allowlist_entry(monkeypatch):
    harness = _load_harness()
    gone = _mut(9, "survived")
    _fake_sweep(monkeypatch, results=(_mut(1, "killed"),))
    _allow(monkeypatch, harness, gone)
    res = harness.gate_mutate()
    assert res.status == harness.FAIL
    assert gone.mutation.label in res.detail and "stale" in res.detail


def test_gate_fails_on_zero_mutants(monkeypatch):
    harness = _load_harness()
    _fake_sweep(monkeypatch, results=())
    res = harness.gate_mutate()
    assert res.status == harness.FAIL and "zero mutants" in res.detail


@pytest.mark.parametrize("outcome", ["timeout", "error"])
def test_gate_fails_while_timeout_or_error_mutants_remain(monkeypatch, outcome):
    harness = _load_harness()
    _fake_sweep(monkeypatch, results=(_mut(1, "killed"), _mut(2, outcome)))
    res = harness.gate_mutate()
    assert res.status == harness.FAIL
    assert f"1 {outcome}" in res.summary and "unverified" in res.detail


def test_bad_allowlist_fails_without_running_the_sweep(monkeypatch):
    harness = _load_harness()
    calls = _fake_sweep(monkeypatch, results=(_mut(1, "killed"),))
    monkeypatch.setattr(harness.pathlib.Path, "read_text",
                        lambda self, *a, **k: "m.py:1:0 Compare[0] <-><=\n")
    res = harness.gate_mutate()
    assert res.status == harness.FAIL and "no reason" in res.detail
    assert calls == []


def test_gate_surfaces_the_canary_abort_message_as_fail(monkeypatch):
    harness = _load_harness()
    _fake_sweep(monkeypatch, exc=RuntimeError("mutation canary survived (rc=0)"))
    res = harness.gate_mutate()
    assert res.status == harness.FAIL
    assert "mutation canary survived (rc=0)" in res.detail


def test_gate_does_not_swallow_other_exceptions_into_a_pass(monkeypatch):
    harness = _load_harness()
    _fake_sweep(monkeypatch, exc=OSError("disk gone"))
    with pytest.raises(OSError, match="disk gone"):
        harness.gate_mutate()
    # main() turns the raise into a FAIL row, never a PASS
    monkeypatch.setattr(harness, "GATES", {"mutate": harness.gate_mutate})
    assert harness.main(["--only", "mutate", "--json"]) != 0


def test_allowlist_refuses_duplicates_and_keeps_later_hashes_in_reason():
    harness = _load_harness()
    ok = harness.parse_mutation_allowlist("a b  # why # more\n")
    assert ok == {"a b": "why # more"}
    with pytest.raises(ValueError, match="duplicate"):
        harness.parse_mutation_allowlist("a b # x\na b # y\n")
