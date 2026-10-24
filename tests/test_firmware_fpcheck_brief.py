"""File-backed firmware review assignments preserve review and safety contracts."""
import pathlib
import re
import subprocess
import sys

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = briefs.TEMPLATE_DIR / "firmware-fpcheck-brief.md"
INPUTS = ("run_dir", "db_path", "rootfs", "image_id",
          "candidate_snapshot_sha256", "worklist_index", "batch_path", "result_path")
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


@pytest.fixture
def variables(tmp_path):
    run = tmp_path / "run"
    generation = run / "files" / "firmware-fpcheck" / ("b" * 64)
    return dict(run_dir=str(run), db_path=str(run / "audit.db"),
                rootfs=str(tmp_path / "rootfs"), image_id="router-target",
                candidate_snapshot_sha256="a" * 64,
                worklist_index=str(generation / "index.json"),
                batch_path=str(generation / "batch-0001.json"),
                result_path=str(run / "files" / "review-0001.json"))


def rendered(variables):
    return briefs.write_brief("firmware-fpcheck", "batch-0001",
                              variables["run_dir"], variables).read_text()


def test_firmware_review_library_and_cli_bind_paths_without_inlining(variables):
    for name in ("worklist_index", "batch_path"):
        path = pathlib.Path(variables[name])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"private_evidence":"DO-NOT-INLINE-FPCHECK-123"}')
    command = [sys.executable, str(ROOT / "audit.py"), "brief", "--phase",
               "firmware-fpcheck", "--unit", "batch-0001", "--run", variables["run_dir"]]
    for name, value in variables.items():
        command.extend(["--var", f"{name}={value}"])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    output = pathlib.Path(variables["run_dir"]) / "briefs" / "firmware-fpcheck-batch-0001-brief.md"
    assert result.stdout == f"{output}\n"
    text = output.read_text()
    assert text == rendered(variables)
    assert set(PLACEHOLDER.findall(TEMPLATE.read_text())) == set(INPUTS)
    assert not PLACEHOLDER.search(text)
    assert all(value in text for value in variables.values())
    assert "DO-NOT-INLINE-FPCHECK-123" not in text + result.stdout


@pytest.mark.parametrize("name", INPUTS)
@pytest.mark.parametrize("value", [None, ""])
def test_each_firmware_review_input_is_required(variables, name, value):
    if value is None:
        del variables[name]
    else:
        variables[name] = value
    with pytest.raises(briefs.BriefError, match=name):
        briefs.render(TEMPLATE.read_text(), variables)


def test_firmware_method_preserves_cross_lane_evidence_and_all_fp_rules(variables):
    text = " ".join(rendered(variables).split())
    for requirement in (
        "attacker-advantage test FIRST", "all 18 Hard Exclusions",
        "10 Precedent rules", "CV-1 to CV-3", "Marginal Gain Test",
        "MARGINAL-GAIN", "HE-1", "HE-18", "PR-1", "PR-10",
        "references/phase5-fp-check.md", "Re-read every cited",
        "cross-lane", "(lane, candidate_id)", "exactly one decision for every assigned candidate",
        "no other candidate", "similarity_signature", "never silently merge",
        "TRUE_POSITIVE", "root_cause_key", "FALSE_POSITIVE", "refuting_mechanism",
        "enabled_observation", "pivot_evidence", "DUPLICATE", "target_lane",
        "target_candidate_id", "dedup_evidence", "confidence threshold", "devil's advocate",
        "terminate at a TRUE_POSITIVE", "same image and candidate snapshot",
    ):
        assert requirement in text, requirement
    assert text.index("attacker-advantage test FIRST") < text.index("all 18 Hard Exclusions")


def test_firmware_result_only_safety_and_checkpoint_contract(variables):
    text = " ".join(rendered(variables).split())
    for requirement in (
        "immutable", "worklist_sha256", "batch_sha256", "FAILED",
        "firmware_fpcheck_results.py", "strict JSON", "regular UTF-8 file capped at 8 MiB",
        "duplicate keys", "extra keys", "non-finite numbers", "result-only",
        "Do not write SQL", "Do not write to the database", "deterministic importer owns SQL",
        "Do not execute", "Do not emulate", "Do not exploit", "weaponize", "assign severity",
        "generic findings", "PARTIAL", "remaining lane-qualified candidate IDs",
        "without fabricating verdicts", "orchestrator", "checkpoint", "not importable",
        "Do not persist absolute", "relative component paths", "rootfs",
    ):
        assert requirement in text, requirement


def test_firmware_return_has_exactly_one_result_line(variables):
    text = rendered(variables)
    line = "    firmware-fpcheck-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]"
    assert text.splitlines().count(line) == 1
    assert "Return exactly one line, and nothing else:" in text
    assert "Rows counts candidate decisions" in text


def test_skill_routes_firmware_review_separately_from_source_fpcheck():
    skill = (ROOT / "SKILL.md").read_text()
    assert "Stage 4f firmware fpcheck" in skill
    assert "references/briefs/firmware-fpcheck-brief.md" in skill
    for mode in ("--prepare", "--record ${RESULT_PATH}", "--check"):
        assert re.search(r"python3 __SKILL_DIR__/audit.py fpcheck[^\n]*" + re.escape(mode), skill)
    assert re.search(r"audit\.py brief --phase firmware-fpcheck\s*\\?\s*--unit batch-0001", skill)
    for name in INPUTS:
        assert f"--var {name}=" in skill
    assert "[workflows/fpcheck.md](workflows/fpcheck.md)" in skill
    assert "ordinary source-code `fpcheck`" in skill
