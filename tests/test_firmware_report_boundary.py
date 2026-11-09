"""Only Stage 4j authority and schema/contract code may name the report tables.

Stage 4j also owns exactly one input boundary: `firmware_decide.verified_package`.
It never reaches into the Stage 4g/4h verified helpers itself, and it never
builds the extended verified package type outside Stage 4i.
"""
import ast
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TABLES = ("cba_firmware_report_runs", "cba_firmware_report_items")
PRUNED = {".git", ".worktrees", "__pycache__", "docs", "tests"}
CODE = {".py", ".sh", ".sql"}
TABLE_OWNERS = {
    "audit_core/db.py", "audit_core/firmware_report.py",
    "audit_core/firmware_report_results.py", "audit_core/schema.sql"}
DB_CONTRACT = {
    "cba_firmware_report_runs": {
        "MIGRATIONS", "TABLE_SPECS", "_validate_firmware_report_run"},
    "cba_firmware_report_items": {
        "MIGRATIONS", "TABLE_SPECS", "_validate_firmware_report_item"}}
PACKAGE = "VerifiedFirmwareDecisionPackage"
STAGE4J = ("audit_core/firmware_report.py",
           "audit_core/firmware_report_results.py")
UPSTREAM = ("firmware_chain", "firmware_dive")


def code_files():
    for directory, children, names in os.walk(ROOT):
        children[:] = sorted(item for item in children
                             if item not in PRUNED and not item.startswith("."))
        for name in sorted(names):
            path = pathlib.Path(directory, name)
            if path.suffix in CODE:
                yield path.relative_to(ROOT).as_posix(), path


def owners(needle):
    return {name for name, path in code_files()
            if needle in path.read_text(encoding="utf-8")}


def top_level_name(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    targets = node.targets if isinstance(node, ast.Assign) else (
        [node.target] if isinstance(node, ast.AnnAssign) else [])
    names = [item.id for item in targets if isinstance(item, ast.Name)]
    return names[0] if len(names) == 1 else None


def tree(relative):
    return ast.parse((ROOT / relative).read_text(encoding="utf-8"))


def modules(parsed):
    """Local alias -> imported `audit_core` module name."""
    aliases = {}
    for node in ast.walk(parsed):
        if isinstance(node, ast.ImportFrom) and node.module == "audit_core":
            for item in node.names:
                aliases[item.asname or item.name] = item.name
    return aliases


def upstream_attributes(relative):
    parsed = tree(relative)
    aliases = modules(parsed)
    return {f"{aliases[node.value.id]}.{node.attr}"
            for node in ast.walk(parsed)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id in aliases and node.attr.startswith("verified_")}


@pytest.mark.parametrize("table", TABLES)
def test_only_report_authority_and_schema_contract_name_report_tables(table):
    """Catches another stage or the CLI reading or writing report rows directly."""
    assert owners(table) == TABLE_OWNERS


@pytest.mark.parametrize("table", TABLES)
def test_db_names_report_tables_only_in_schema_contract_code(table):
    """Catches generic db helpers acquiring report-specific lifecycle behavior."""
    holders = set()
    for node in tree("audit_core/db.py").body:
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and child.value == table:
                holders.add(top_level_name(node))
    assert holders == DB_CONTRACT[table]


def test_only_decide_constructs_the_extended_verified_package():
    """Catches a later stage forging an unverified decision package."""
    builders = set()
    for name, path in code_files():
        if path.suffix != ".py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            built = (isinstance(func, ast.Name) and func.id == PACKAGE) or (
                isinstance(func, ast.Attribute) and func.attr == PACKAGE)
            if built:
                builders.add(name)
    assert builders == {"audit_core/firmware_decide.py"}


@pytest.mark.parametrize("relative", STAGE4J)
def test_report_modules_use_only_the_decide_package_boundary(relative):
    """Catches Stage 4j re-deriving Stage 4g/4h evidence behind the boundary."""
    used = upstream_attributes(relative)
    assert not {name for name in used
                if name.split(".")[0] in UPSTREAM}
    assert used <= {"firmware_decide.verified_package"}


def test_report_module_reaches_the_package_boundary():
    """Keeps the boundary assertions honest about the real call site."""
    assert "firmware_decide.verified_package" in upstream_attributes(
        "audit_core/firmware_report.py")
