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
        mutate.run_sweep(pkg, tests, state, timeout=60)
    partial = mutate.load_state(state)
    assert len(partial) == 1, "exactly the first mutant should be checkpointed"

    ran = []

    def counting_run(tree, paths, timeout):
        ran.append(paths)
        return real_run(tree, paths, timeout)

    monkeypatch.setattr(mutate, "_run", counting_run)
    results = mutate.run_sweep(pkg, tests, state, timeout=60)
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
    repo, pkg, tests = _fixture_repo(tmp_path, "def f(n):\n    return n > 1\n",
                                     "from pkg.m import f\n"
                                     "def test_f():\n    assert f(5)\n")
    (tests / "test_m.py").rename(tests / "test_zzz.py")
    mutate.run_sweep(pkg, tests, tmp_path / "s.json", timeout=60)
    assert "falling back to the whole suite" in capsys.readouterr().err
