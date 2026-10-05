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


# --- I2 / I5 / I6 / I7: prose that has to agree with itself -------------------


@pytest.mark.parametrize("name", ["recon.md", "fpcheck.md"])
def test_mapping_and_fpcheck_keep_the_strongest_model(name):
    """Spec section 7 quarantines Sonnet tiering for mapping and fpcheck to
    Stage 3, "the one tiering change that can cost quality, with precision
    measured before and after". Stage 1 tiers effort only."""
    text = (ROOT / "workflows" / name).read_text()
    assert "mid tier" not in text, (
        f"{name} downgrades the model; Stage 1 tiers effort, not the model")
    assert "strongest tier" in text


def test_skill_md_subagent_table_keeps_the_strongest_model_for_both():
    text = (ROOT / "SKILL.md").read_text()
    for row in ("| recon (mapping) |", "| fpcheck |"):
        line = next(l for l in text.splitlines() if l.startswith(row))
        assert "strongest tier" in line, line
        assert "mid tier" not in line, line


def test_the_fpcheck_artifact_has_exactly_one_name():
    """The subagent wrote `phase5-$BATCH.md` while the orchestrator was told to
    look in `phase5-batch<X>-<scope>.md`, phase5-fp-check.md showed
    `B1-fpcheck.md`, and SKILL.md's Artifact Layout said `phase5-batch<X>-*.md`."""
    paths = [ROOT / "SKILL.md",
             ROOT / "workflows" / "fpcheck.md",
             ROOT / "references" / "phase5-fp-check.md",
             ROOT / "references" / "workflow-orchestration.md"]
    for path in paths:
        text = path.read_text()
        for stale in ("phase5-batch", "B1-fpcheck", "-fpcheck.md"):
            assert stale not in text, f"{path.name} still says {stale!r}"
        assert "phase5-" in text, path.name


def test_source_md_does_not_point_at_the_deleted_prompt_template():
    """source.md is the unattended run. It told the orchestrator to fill a
    prompt template, set its Test Instance section and delete the
    live-verification instructions - none of which exist any more."""
    text = (ROOT / "workflows" / "source.md").read_text()
    for stale in ("prompt template", "*Test Instance* section",
                  "Delete the live-verification"):
        assert stale not in text, f"source.md still says {stale!r}"
    assert "--var test_instance=" in text
    # The source-mode `verified` guard is stated nowhere else.
    assert "source-only`; never write `live-poc`" in text


@pytest.mark.parametrize("name,names", [
    ("recon.md", ["G", "NAME", "DESC", "DIRS", "SRC", "KNOWN"]),
    ("audit.md", ["G", "NAME", "SRC", "KNOWN", "TEST_INSTANCE"]),
    ("fpcheck.md", ["BATCH", "IDS", "SRC"]),
])
def test_documented_commands_define_every_shell_variable_they_use(name, names):
    """Only AUDIT_DIR was ever assigned. An orchestrator pasting the block got
    a subagent with no source access and no known-findings list, and the
    renderer reported success."""
    text = (ROOT / "workflows" / name).read_text()
    used = set(re.findall(r'--var\s+[A-Za-z_][A-Za-z0-9_]*="\$\{?([A-Za-z_][A-Za-z0-9_]*)',
                          text))
    assigned = set(re.findall(r"^\s*([A-Z][A-Z0-9_]*)=", text, re.M))
    assigned.add("AUDIT_DIR")
    assert used - assigned == set(), (
        f"{name} uses undefined shell variables: {sorted(used - assigned)}")
    for n in names:
        assert n in assigned, f"{name} never assigns ${n}"
