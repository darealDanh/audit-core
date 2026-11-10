"""The firmware stages route from firmware-audit/SKILL.md, not the root skill.

The split moved every firmware stage out of codebase-audit's SKILL.md into a
second installable skill. These checks pin both halves of that move: the
firmware skill names every stage verb and each brief it cites resolves, and the
root skill no longer routes a single firmware stage.
"""
import pathlib

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIRMWARE_SKILL = ROOT / "firmware-audit" / "SKILL.md"
ROOT_SKILL = ROOT / "SKILL.md"

# Every firmware stage verb, 4a qualify through 4j report.
STAGE_VERBS = (
    "qualify", "acquire", "triage", "diff", "surface", "hunt",
    "fpcheck", "chain", "dive", "decide", "firmware-report",
)

# The brief phases the firmware router renders. qualify and acquire are
# script / orchestrator stages and render no worker brief.
BRIEF_PHASES = (
    "triage", "diff", "surface", "hunt", "firmware-fpcheck",
    "firmware-chain", "firmware-dive", "firmware-decide", "firmware-report",
)


def test_firmware_skill_exists_and_is_named():
    assert FIRMWARE_SKILL.is_file()
    head = FIRMWARE_SKILL.read_text().split("---", 2)[1]
    assert "name: firmware-audit" in head


def test_firmware_skill_triggers_are_declared():
    text = FIRMWARE_SKILL.read_text()
    assert "$firmware-audit" in text
    assert "/firmware-audit" in text


def test_firmware_skill_names_every_stage_verb():
    text = FIRMWARE_SKILL.read_text()
    for verb in STAGE_VERBS:
        assert verb in text, f"firmware SKILL.md never names the {verb!r} verb"


def test_firmware_skill_renders_each_brief_phase_and_each_resolves():
    text = FIRMWARE_SKILL.read_text()
    for phase in BRIEF_PHASES:
        assert f"brief --phase {phase}" in text, \
            f"firmware SKILL.md never renders the {phase!r} brief"
        # The cited brief must resolve to a shipped template.
        assert briefs.template_path(phase).is_file()


def test_firmware_skill_covers_stages_4a_through_4j():
    text = FIRMWARE_SKILL.read_text()
    for heading in (
        "### Stage 4a firmware qualify",
        "### Stage 4b firmware acquire",
        "### Stage 4c firmware triage",
        "### Stage 4d firmware diff and surface",
        "### Stage 4e firmware hunt",
        "### Stage 4f firmware fpcheck",
        "### Stage 4g firmware chain",
        "### Stage 4h firmware dive",
        "### Stage 4i firmware decision",
        "### Stage 4j firmware report",
    ):
        assert heading in text, f"firmware SKILL.md is missing {heading!r}"


def test_firmware_skill_ships_crlf_like_the_root_skill():
    raw = FIRMWARE_SKILL.read_bytes()
    assert b"\r\n" in raw
    assert raw.replace(b"\r\n", b"").count(b"\n") == 0


def test_root_skill_routes_no_firmware_stage():
    text = ROOT_SKILL.read_text()
    assert "### Stage 4" not in text
    for marker in ("firmware hunt", "firmware fpcheck", "firmware chain",
                   "firmware dive", "firmware decision", "firmware report"):
        assert marker not in text, f"root SKILL.md still routes {marker!r}"


def test_root_skill_renders_no_firmware_brief_line():
    text = ROOT_SKILL.read_text()
    assert "brief --phase firmware" not in text
    for phase in ("hunt", "triage", "diff", "surface"):
        assert f"brief --phase {phase}" not in text


def test_root_skill_points_to_the_firmware_skill():
    text = ROOT_SKILL.read_text()
    assert "firmware-audit" in text
