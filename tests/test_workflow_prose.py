import os
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap

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
    """Spec section 7 ships Sonnet tiering for mapping and fpcheck "last and
    alone ... with precision measured before and after".

    Stage 3 built the measurement (`bench` now scores precision) and did not
    take the measurement: that needs two full tplink runs, which this
    repository cannot do. No precision figure exists for any run, so the
    before-number the spec conditions the change on does not exist.

    The procedure and the exact diff this test guards are in
    docs/baselines/2026-10-05-stage3-tiering-gate.md. Change this test when
    that gate has been run, and put the date in the docstring.
    """
    text = (ROOT / "workflows" / name).read_text()
    assert "mid tier" not in text, (
        f"{name} downgrades the model with no precision baseline to compare "
        f"against; see docs/baselines/2026-10-05-stage3-tiering-gate.md")
    assert "strongest tier" in text


def test_skill_md_subagent_table_keeps_the_strongest_model_for_both():
    """Same gate as test_mapping_and_fpcheck_keep_the_strongest_model: no
    precision baseline exists. docs/baselines/2026-10-05-stage3-tiering-gate.md
    holds the procedure and the exact diff."""
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


def _documented_shell_block(workflow: str, first_line_startswith: str) -> str:
    """The indented shell block an orchestrator is told to paste, dedented."""
    lines = (ROOT / "workflows" / workflow).read_text().splitlines()
    start = next(n for n, l in enumerate(lines)
                 if l.strip().startswith(first_line_startswith))
    out = []
    for line in lines[start:]:
        if not line.strip() or line.startswith("    "):
            out.append(line)
            continue
        break
    return textwrap.dedent("\n".join(out).rstrip())


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_audit_md_renders_when_cve_ingest_was_skipped(tmp_path):
    """source.md documents CVE ingest as best-effort: the orchestrator records
    "CVE ingest skipped" and continues, so files/known-findings.md was never
    written. audit.md assigned KNOWN with a bare `cat`, so the brief renderer's
    empty-value check then hard-failed the dispatch -- in an unattended run,
    with nobody watching. Each change passes alone; the composite broke."""
    run = tmp_path / "run"
    (run / "files").mkdir(parents=True)
    assert not (run / "files" / "known-findings.md").exists()

    block = _documented_shell_block("audit.md", "G=G1")
    assert "known-findings.md" in block, "extracted the wrong block"
    script = (f'set -euo pipefail\nAUDIT_DIR={run}\n'
              + block.replace("__SKILL_DIR__", str(ROOT)))
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                       env={**os.environ, "PATH": os.path.dirname(sys.executable)
                            + os.pathsep + os.environ.get("PATH", "")})
    assert r.returncode == 0, r.stdout + r.stderr
    brief = run / "briefs" / "audit-G1-brief.md"
    assert brief.is_file()
    assert "No prior advisories ingested for this target." in brief.read_text()


def test_no_workflow_var_reads_a_file_without_a_fallback():
    """Any `--var` value sourced from a file an earlier phase may legitimately
    not have produced must fall back, or the renderer's empty-value check turns
    a tolerated skip into a hard failure."""
    offenders = []
    for path in LIVE:
        for line in path.read_text().splitlines():
            m = re.match(r'\s*([A-Z][A-Z0-9_]*)="?\$\((?:cat|<)', line)
            if m and "2>/dev/null" not in line:
                offenders.append(f"{path.name}: {line.strip()}")
    assert offenders == [], (
        "file-sourced shell vars with no fallback: " + "; ".join(offenders))


# --- Stage 2: R1/R3 in the shipped prose, by replacement not rewrite ---------


def live_markdown():
    """Every markdown file an install ships: SKILL.md, the live workflows and
    the references. Archived drafts (a leading `_`) are excluded, as in LIVE."""
    out = [ROOT / "SKILL.md"]
    out.extend(LIVE)
    out.extend(sorted(p for p in (ROOT / "references").rglob("*.md")
                      if not p.name.startswith("_")))
    return out


def normalize_ws(text: str) -> str:
    """Whitespace removed, not just collapsed: the same query is hand-typed as
    `COUNT(*) FROM` in one file and `COUNT(*)  FROM` in the next, and
    `verdict = 'X'` in one and `verdict='X'` in the next."""
    return re.sub(r"\s+", "", text)


def test_every_retired_query_is_gone_from_shipped_prose():
    """The five hand-typed SQL shapes Stage 2 replaced. Each was retyped
    after every compaction restart, which is R5's target exactly."""
    retired = [
        "SELECT id,name,status FROM cba_feature_groups",
        "SELECT group_id,severity,COUNT(*) FROM cba_findings",
        "SELECT verdict,COUNT(*) FROM cba_fp_verdicts",
        "FROM cba_fp_verdicts WHERE verdict = 'TRUE_POSITIVE'",
        "INSERT INTO cba_findings",
        "INSERT INTO cba_fp_verdicts",
        "INSERT INTO cba_attack_surface",
        "INSERT INTO cba_security_observations",
        "INSERT INTO cba_known_findings",
    ]
    for path in live_markdown():
        text = normalize_ws(path.read_text(encoding="utf-8"))
        for query in retired:
            assert normalize_ws(query) not in text, f"{path.name}: {query}"


def test_every_instruction_the_replaced_blocks_sat_inside_survives():
    """Stage 1's finding: five reviews each caught a different absence and
    none caught all of them. These are the surrounding instructions, not the
    SQL - the thing a replacement must not take with it."""
    expect = {
        "workflows/audit.md": [
            "Patch-bypass mining",
            "were they the ONLY sites of the vulnerable pattern",
            "Top patch-bypass discoveries",
        ],
        "workflows/fpcheck.md": [
            "identify the missing batch and re-spawn just that one",
            "Order TPs by severity",
            "cites a specific HE/PR/CV rule",      # survived the pivot edit
        ],
        "workflows/report.md": [
            "Steps to reproduce is a reproduction GUIDE only",
            "do NOT run a PoC and do NOT paste captured output",
            "NOT live-verified",
        ],
        "references/phase2-feature-mapping.md": [
            "Save each group's full output to",
        ],
        "references/phase4-deep-audit.md": [
            "keep the one with higher confidence",
        ],
        "references/phase5-fp-check.md": [
            "Mix severities within batches",
            "If Finding A's truth value depends on Finding B",
        ],
    }
    for rel, needles in expect.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        for needle in needles:
            assert needle in text, f"{rel} lost: {needle}"


def test_skill_md_states_r1_and_r3():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "### R1 " in text
    assert "### R3 " in text
    assert "audit.py extract" in text
    assert "audit.py checkpoint" in text
    assert "100k" in text or "100,000" in text


def test_the_anti_rationalization_rule_is_in_the_rejection_table():
    """Spec R3: 'near the ceiling — skip this group' is answered by
    checkpoint-and-restart, never by skipping. The rationalization is quoted
    here with the em dash SKILL.md actually uses; an earlier draft of this
    test also allowed a comma form that the table has never contained, so
    half of it could never have fired."""
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "near the ceiling — skip this group" in text.lower()
    assert "not_audited(reason='budget')" in text


def test_skill_md_lists_the_five_new_tables():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for table in ("cba_inventory", "cba_coverage", "cba_patterns",
                  "cba_pattern_hits", "cba_checkpoints"):
        assert table in text


def test_every_documented_audit_py_invocation_parses():
    """Stage 1 shipped a documented command that exited 1. Every verb named in
    the shipped prose is checked against audit.HANDLERS, so a verb that was
    renamed or never existed fails here. The flags are not parsed: wrapped
    lines and inline backticks make that a false-failure generator, and each
    verb's own CLI tests already run real invocations as subprocesses."""
    import re as _re
    import audit
    pattern = _re.compile(r"audit\.py ([a-z-]+)(?: --[a-z-]+(?:[= ][^\s`]+)?)*")
    for path in live_markdown():
        for verb in pattern.findall(path.read_text(encoding="utf-8")):
            assert verb in audit.HANDLERS, f"{path.name}: unknown verb {verb}"


# --- Stage 3: the shipped prose invokes the five mechanisms --------------------


def test_every_stage3_verb_appears_in_shipped_prose():
    """A mechanism nothing invokes is a mechanism that does not run. Each
    verb must be named somewhere a phase actually reads."""
    text = "\n".join(p.read_text(encoding="utf-8") for p in live_markdown())
    for verb in ("audit.py pivot", "audit.py patterns", "audit.py identify",
                 "audit.py chain", "audit.py coverage"):
        assert verb in text, f"no shipped workflow or reference invokes {verb}"


def test_the_coverage_gate_is_invoked_at_a_phase_exit():
    """Phase-scoped on purpose. Unscoped, `coverage` counts a unit analyzed if
    ANY phase recorded it, so a surface recon ruled on and audit never opened
    reports 100% and the gate passes on exactly the failure it exists to
    catch (reproduced: 1/1 PASS unscoped, 0/1 FAIL with --phase audit)."""
    assert "coverage --db ${AUDIT_DIR}/audit.db --gate --phase audit" in \
        (ROOT / "workflows" / "audit.md").read_text(encoding="utf-8")


def test_no_phase_gate_sits_inside_a_presented_blockquote():
    """A gate the orchestrator PRESENTS is a gate that never runs. Shipped
    once inside the USER GATE's `>` block, the coverage gate ran in neither
    mode: interactively the orchestrator showed the user the command instead
    of executing it, and unattended `source` mode skips the USER GATE step
    outright (source.md Step 2 overrides), so it never appeared at all.

    `>` is the marker for text addressed to the user. Every `--gate`
    invocation must sit in executable prose, as Step 6's patterns gate does.

    Scoped to `live_markdown()` - every file an install ships - not to the
    three workflows this stage happened to edit. The defect is one file over
    from wherever the guard stops looking, and `workflows/report.md`,
    `source.md`, `deploy.md`, `verify.md` and the references can all grow a
    gate later."""
    for path in live_markdown():
        for n, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1):
            if "audit.py" in line and "--gate" in line:
                assert not line.lstrip().startswith(">"), (
                    f"{path.relative_to(ROOT)}:{n} presents a gate instead of "
                    f"running it: {line.strip()}")


def test_the_pivot_rule_is_stated_as_unconditional():
    """It must not soften into "where applicable". The whole value is that it
    forces the question on every false positive."""
    for rel in ("workflows/fpcheck.md", "references/briefs/fpcheck-brief.md"):
        text = (ROOT / rel).read_text(encoding="utf-8").lower()
        assert "unconditional" in text, rel
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert "refuting_mechanism" in skill


def test_the_five_stage3_rationalizations_are_in_the_rejection_table():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for needle in ("audit.py pivot", "That IS the observation",
                   "audit.py patterns --gate", "km0_boot",
                   "audit.py chain"):
        assert needle in text, needle


def test_skill_md_lists_the_two_new_tables():
    text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    for table in ("cba_components", "cba_chains"):
        assert table in text


def test_the_fpcheck_brief_kept_its_placeholders_and_return_contract():
    """The brief rewrite is the exact shape Stage 1 lost instructions in."""
    text = (ROOT / "references" / "briefs" / "fpcheck-brief.md").read_text()
    for var in ("{batch_id}", "{finding_ids}", "{run_dir}",
                "{source_access}", "{artifact_path}"):
        assert var in text, var
    assert "rows=<n> artifact=" in text
    assert "18 Hard Exclusions and 10 Precedent rules" in text
    assert "Capability Validity checks CV-1 to CV-3" in text


def test_the_tiering_gate_document_exists_and_says_it_has_not_run():
    """A spec-mandated change that was not made needs a record, or the next
    reader finds a quarantine test with no explanation and deletes it."""
    path = ROOT / "docs" / "baselines" / "2026-10-05-stage3-tiering-gate.md"
    text = path.read_text(encoding="utf-8")
    assert "NOT RUN" in text
    assert "precision" in text.lower()
    assert "mid tier" in text, "the document must carry the exact diff to apply"


def test_the_stage3_gate_document_says_it_has_not_run():
    path = ROOT / "docs" / "baselines" / "2026-10-05-stage3-gate.md"
    assert "**Status: NOT RUN.**" in path.read_text(encoding="utf-8")
