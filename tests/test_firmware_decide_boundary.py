"""Only Stage 4i authority and schema/contract code may name the decision table."""
import ast
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
TABLE = "cba_firmware_decide_runs"
PRUNED = {".git", ".worktrees", "__pycache__", "docs", "tests"}
CODE = {".py", ".sh", ".sql"}
DB_CONTRACT = {"MIGRATIONS", "TABLE_SPECS", "_validate_firmware_decide_run"}


def owners():
    found = set()
    for directory, children, names in os.walk(ROOT):
        children[:] = sorted(item for item in children
                             if item not in PRUNED and not item.startswith("."))
        for name in names:
            path = pathlib.Path(directory, name)
            if path.suffix in CODE and TABLE in path.read_text(encoding="utf-8"):
                found.add(path.relative_to(ROOT).as_posix())
    return found


def top_level_name(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    targets = node.targets if isinstance(node, ast.Assign) else (
        [node.target] if isinstance(node, ast.AnnAssign) else [])
    names = [item.id for item in targets if isinstance(item, ast.Name)]
    return names[0] if len(names) == 1 else None


def test_only_decide_authority_and_schema_contract_name_the_decision_table():
    """Catches another stage or CLI reading or writing decision rows directly."""
    assert owners() == {
        "audit_core/db.py", "audit_core/firmware_decide.py",
        "audit_core/firmware_decide_results.py", "audit_core/schema.sql"}


def test_db_names_the_decision_table_only_in_schema_contract_code():
    """Catches generic db helpers acquiring decision-specific lifecycle behavior."""
    tree = ast.parse((ROOT / "audit_core/db.py").read_text(encoding="utf-8"))
    holders = set()
    for node in tree.body:
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and child.value == TABLE:
                holders.add(top_level_name(node))
    assert holders == DB_CONTRACT
