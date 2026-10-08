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
    muts = mutate.enumerate_mutations("A = True\nB = 5\nC = 'x'\n", "m.py")
    got = {(m.before, m.after) for m in muts if m.operator == "constant"}
    assert got == {("True", "False"), ("5", "6"), ("'x'", "''")}


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
    muts = mutate.enumerate_mutations('def f():\n    x = "keep"\n    return x\n',
                                      "m.py")
    assert any(m.before == "'keep'" for m in muts)


SAMPLE = '''"""Doc."""
def f(a, b, s):
    """Doc."""
    if not a and b or a in s:
        return a is not None and a != 3 and s == "x"
    return True if a >= b else a <= b < 9
'''


def test_every_operator_fires_and_every_mutant_parses():
    import ast
    muts = mutate.enumerate_mutations(SAMPLE, "m.py")
    assert {m.operator for m in muts} == {"compare", "boolop", "not", "constant"}
    for m in muts:
        mutated = mutate.apply_mutation(SAMPLE, m)
        ast.parse(mutated)
        assert mutated != mutate.apply_mutation(SAMPLE, mutate.Mutation(
            "m.py", 1, 0, "none", "", ""))


def test_label_format():
    m = mutate.Mutation("m.py", 3, 4, "compare", "Lt", "LtE")
    assert m.label == "m.py:3:4 compare Lt->LtE"


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
