"""The firmware report worker receives one bounded per-chain assignment."""
import os
import pathlib
import re
import shutil
import subprocess

import pytest

from audit_core import briefs, db
from audit_core import firmware_report as report
from audit_core import firmware_report_results as results


ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "references" / "briefs" / "firmware-report-brief.md"
VARIABLES = {"run_dir", "image_id", "report_generation", "assignment_path",
             "result_path"}
RETURN_LINE = ("firmware-report <DONE|FAILED> chain=<id> artifact=<path> "
               "[flags=<csv>]")


def text():
    return TEMPLATE.read_text()


def test_report_brief_has_exact_variables_and_return_contract(tmp_path):
    source = text()
    assert set(re.findall(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}", source)) == VARIABLES
    rendered = briefs.render(source.replace("__SKILL_DIR__", str(ROOT)),
                             {name: str(tmp_path / name) for name in VARIABLES})
    assert RETURN_LINE in rendered
    assert "PARTIAL" not in rendered


def test_report_brief_restates_every_parser_key():
    source = text()
    for key in (results._RESULT_KEYS + results._ANSWER_KEYS
                + results._ENVELOPE_KEYS + ("text", "citation_refs")):
        assert f"`{key}`" in source, key


# Each bound is asserted against the field it governs, so a brief that states
# the right numbers against the wrong field still fails.
FIELD_BOUNDS = {
    "title_bytes": "`title_detail`: {low} to {high}",
    "summary_paragraphs": "`summary`: {low} to {high} entries",
    "root_cause_paragraphs": "`root_cause`: {low} to {high} entries",
    "reproduction_steps": "`reproduction_steps`: {low} to {high} entries",
    "impact_paragraphs": "`impact`: {low} to {high} entries",
    "text_bytes": "Each entry `text` is {low} to {high} UTF-8 bytes",
    "severity_justification_bytes":
        "`severity_justification`: one entry whose `text` is {low} to {high}",
    "fix_direction_bytes":
        "`fix_direction`: `null`, or one entry whose `text` is {low} to {high}",
}

# The brief spells its small numbers out, so the pinned contract values are
# compared as words.
_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}


def test_report_brief_restates_the_style_contract_bounds_and_severities():
    squashed = " ".join(text().split())
    bounds = report._style_contract()["bounds"]
    for key, phrase in FIELD_BOUNDS.items():
        low, high = bounds[key]
        assert phrase.format(low=low, high=high) in squashed, key
    assert (f"`citation_refs` holds 1 to {bounds['citations_per_entry']} "
            "references") in squashed
    assert f"at most {results.MAX_RESULT_BYTES // 1024} KiB" in squashed
    assert f"schema version {results.RESULT_SCHEMA_VERSION}" in squashed
    for severity in db.FIRMWARE_REPORT_SEVERITIES:
        assert f"`{severity}`" in squashed
    repetition = report._style_contract()["repetition"]
    run = repetition["max_consecutive_same_prefix_sentences"]
    width = repetition["prefix_tokens"]
    # The lint rejects at the run length, so a brief promising one more
    # sentence of latitude than the code allows fails here.
    assert (f"or {_WORDS[run]} sentences in a row that share the same "
            f"{_WORDS[width]}-token prefix") in squashed


def test_report_brief_pins_one_fresh_per_item_worker_and_incremental_reading():
    source = text().lower()
    for required in ("one fresh strongest", "one chain", "incrementally",
                     "never partition", "strict json", "result-only",
                     "duplicate keys", "extra keys", "source-level",
                     "evidence catalog"):
        assert required in source, required


def test_report_brief_states_every_prose_rule_class():
    source = text().lower()
    for required in ("filler", "absolute", "meta", "runtime", "em dash",
                     "raw url", "emoji", "absolute path", "duplicate sentence",
                     "same three-token prefix", "sorted"):
        assert required in source, required


def test_report_brief_denies_authority():
    source = text().lower()
    for required in ("do not write sql", "ordering", "pre-authentication",
                     "layout", "completion", "do not execute", "severity"):
        assert required in source, required


def _skill_section() -> str:
    source = (ROOT / "SKILL.md").read_text()
    start = source.index("### Stage 4j firmware report")
    end = source.index("### ", start + 4)
    return source[start:end]


def test_skill_routes_prepare_writers_record_then_check():
    section = _skill_section()
    order = [section.index(marker) for marker in (
        "firmware-report --run ${AUDIT_DIR} --root ${ROOTFS} \\",
        "brief --phase firmware-report",
        "firmware-report --run ${AUDIT_DIR} --record ${RESULT_PATH}",
        "firmware-report --run ${AUDIT_DIR} --root ${ROOTFS} --check")]
    assert order == sorted(order)
    assert RETURN_LINE in section
    lowered = section.lower()
    for required in ("manifest", "one fresh strongest", "do not inline",
                     "failed is never recorded", "no script"):
        assert required in lowered, required
    assert "partial" not in lowered


def test_skill_section_carries_no_inline_worklist_or_prose():
    section = _skill_section()
    assert "severity_justification" not in section
    assert len(section) < 4000


def test_skill_md_stays_crlf():
    raw = (ROOT / "SKILL.md").read_bytes()
    assert b"\r\n" in raw
    assert raw.replace(b"\r\n", b"").count(b"\n") == 0


def test_installed_template_renders_through_write_brief(tmp_path):
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    path = briefs.write_brief("firmware-report", "chain-1", run,
                              {name: f"<{name}>" for name in VARIABLES})
    assert path.name == "firmware-report-chain-1-brief.md"
    assert "<report_generation>" in path.read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_installed_tree_carries_the_report_template_and_modules(tmp_path):
    """A brief that is not installed renders nothing on the operator's box."""
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home),
           "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "CODEX_HOME": str(home / ".codex")}
    run = subprocess.run(["bash", str(ROOT / "install.sh"), "claude"],
                         capture_output=True, text=True, env=env, cwd=str(ROOT))
    assert run.returncode == 0, run.stdout + run.stderr
    target = home / ".claude" / "skills" / "codebase-audit"
    installed = target / "references" / "briefs" / "firmware-report-brief.md"
    assert installed.is_file()
    assert "__SKILL_DIR__" not in installed.read_text()
    assert str(target) in installed.read_text()
    for module in ("firmware_report.py", "firmware_report_results.py"):
        assert (target / "audit_core" / module).is_file()
