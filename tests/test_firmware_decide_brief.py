"""The firmware decision worker receives one bounded global assignment."""
import pathlib
import re

from audit_core import briefs


ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "references" / "briefs" / "firmware-decide-brief.md"
VARIABLES = {"run_dir", "image_id", "decision_generation", "worklist_path", "result_path"}


def text():
    return TEMPLATE.read_text()


def test_decide_brief_has_exact_variables_and_return_contract(tmp_path):
    source = text()
    assert set(re.findall(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}", source)) == VARIABLES
    rendered = briefs.render(source.replace("__SKILL_DIR__", str(ROOT)),
                             {name: str(tmp_path / name) for name in VARIABLES})
    assert "firmware-decide <DONE|PARTIAL|FAILED> chains=<n> artifact=<path> [flags=<csv>]" in rendered


def test_decide_brief_pins_global_complete_chain_contract():
    source = text().lower()
    for required in ("one fresh strongest", "global", "every chain", "complete",
                     "strict json", "result-only", "duplicate keys", "extra keys",
                     "partial", "nonimportable", "same immutable"):
        assert required in source


def test_decide_brief_denies_authority_and_keeps_scripts_inert():
    source = text().lower()
    for required in ("do not write sql", "policy", "recommendation", "payout",
                     "canonical", "completion", "severity", "exploit", "report",
                     "do not execute", "proposed scripts"):
        assert required in source


def test_skill_routes_one_global_decision_worker():
    source = (ROOT / "SKILL.md").read_text().lower()
    for required in ("stage 4i firmware decision", "firmware-decide-brief.md",
                     "audit.py decide --run", "--prepare", "--record", "--check",
                     "one fresh strongest", "partial", "proposed scripts"):
        assert required in source
