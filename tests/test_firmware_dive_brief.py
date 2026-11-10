"""The installed firmware dive worker receives one bounded question contract."""
import pathlib
import re

from audit_core import briefs


ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = briefs.template_path("firmware-dive")
VARIABLES = {
    "run_dir", "rootfs", "image_id", "dive_generation", "question_id",
    "packet_path", "journal_index_path", "result_path",
}


def text():
    return TEMPLATE.read_text()


def test_dive_brief_has_exact_variables_and_return_contract(tmp_path):
    source = text()
    assert set(re.findall(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}", source)) == VARIABLES
    values = {name: str(tmp_path / name) for name in VARIABLES}
    rendered = briefs.render(source.replace("__SKILL_DIR__", str(ROOT)), values)
    assert "firmware-dive <DONE|PARTIAL|FAILED> question=<question-id> artifact=<path> [flags=<csv>]" in rendered
    assert "firmware-dive-brief.md" not in rendered


def test_dive_brief_pins_one_question_evidence_and_outcomes():
    source = text().lower()
    for required in (
        "one question", "at most three", "proposition", "resolution effect",
        "observation", "inference", "supported", "refuted", "inconclusive",
        "successor", "strict json", "result-only", "regular utf-8",
        "duplicate keys", "extra keys", "non-finite", "relative",
    ):
        assert required in source


def test_dive_brief_denies_worker_authority_and_environment_inflation():
    source = text().lower()
    for prohibited_authority in (
        "do not write sql", "canonical artifact", "completion", "chain regeneration",
        "severity", "exploit", "report", "crashes", "timeouts", "tool absence",
        "inconclusive", "partial", "nonimportable", "same assignment",
    ):
        assert prohibited_authority in source
    for environment in ("lifecycle", "posture", "authentication", "firmware version", "device identifier"):
        assert environment in source


def test_skill_routes_each_frozen_question_through_fresh_worker():
    source = (ROOT / "SKILL.md").read_text()
    for required in (
        "Stage 4h firmware dive", "firmware-dive-brief.md",
        "audit.py dive --run", "--prepare", "--probe", "--capture", "--record", "--check",
        "fresh strongest", "one brief", "Workers own result JSON only",
    ):
        assert required in source
