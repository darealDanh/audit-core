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
import dataclasses

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
