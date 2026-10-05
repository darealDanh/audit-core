import pathlib
import re

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / "workflows").glob("*.md"))
LIVE = [p for p in WORKFLOWS if not p.name.startswith("_")]

PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


@pytest.mark.parametrize("path", LIVE, ids=lambda p: p.name)
def test_no_live_workflow_carries_inline_ddl(path):
    """R5: schema lives in audit_core/schema.sql, applied by audit.py init."""
    assert "CREATE TABLE" not in path.read_text(), (
        f"{path.name} still has inline DDL; use audit.py init")


def test_recon_uses_init_and_preflight():
    text = (ROOT / "workflows" / "recon.md").read_text()
    assert "audit.py init" in text
    assert "audit.py preflight" in text


@pytest.mark.parametrize("name", ["recon.md", "audit.md", "fpcheck.md"])
def test_dispatching_workflows_render_a_brief(name):
    text = (ROOT / "workflows" / name).read_text()
    assert "audit.py brief" in text, f"{name} must render its brief, not paste it"


@pytest.mark.parametrize("name", ["recon.md", "audit.md", "fpcheck.md"])
def test_dispatching_workflows_name_a_model_tier(name):
    text = (ROOT / "workflows" / name).read_text().lower()
    assert re.search(r"(cheapest|mid|strongest) tier", text), (
        f"{name} must name a model tier from SKILL.md's tiering table")


@pytest.mark.parametrize("path", LIVE, ids=lambda p: p.name)
def test_no_live_workflow_mandates_the_strongest_model_for_everything(path):
    text = path.read_text().lower()
    assert "strongest model your client offers" not in text, (
        f"{path.name} still carries the blanket model mandate")


def test_no_live_reference_carries_inline_ddl():
    """R5: the schema lives in audit_core/schema.sql, applied by audit.py init.
    phase0-source-detection.md carried a cba_sources CREATE TABLE that the
    workflows' own DDL removal would otherwise have missed."""
    for path in sorted((ROOT / "references").rglob("*.md")):
        if path.name.startswith("_"):
            continue
        assert "CREATE TABLE" not in path.read_text(), (
            f"{path.relative_to(ROOT)} still has inline DDL; use audit.py init")


@pytest.mark.parametrize("phase,workflow", [
    ("recon", "recon.md"), ("audit", "audit.md"), ("fpcheck", "fpcheck.md")])
def test_workflow_supplies_every_var_its_template_declares(phase, workflow):
    """A documented `audit.py brief` command missing a --var fails at run time
    with 'unsubstituted placeholder'. The workflow and the template must agree."""
    declared = set(PLACEHOLDER.findall(
        (briefs.TEMPLATE_DIR / f"{phase}-brief.md").read_text()))
    supplied = set(re.findall(r"--var\s+([A-Za-z_][A-Za-z0-9_]*)=",
                              (ROOT / "workflows" / workflow).read_text()))
    assert declared - supplied == set(), (
        f"{workflow} never supplies {sorted(declared - supplied)}")


@pytest.mark.parametrize("name", ["recon.md", "audit.md", "fpcheck.md"])
def test_dispatching_workflow_never_asks_to_paste_brief_content(name):
    """R6: a dispatch carries the brief's path, not its contents. An earlier
    draft told the orchestrator to paste the mapping file's full content four
    lines below the sentence forbidding exactly that."""
    text = (ROOT / "workflows" / name).read_text().lower()
    for banned in ("the full content of", "return a compact summary",
                   "return a verdict tally"):
        assert banned not in text, f"{name} still says {banned!r}"
