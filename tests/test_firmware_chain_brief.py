"""The global firmware chain worker receives paths and emits untrusted data."""
import pathlib
import re
import subprocess
import sys

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = briefs.template_path("firmware-chain")
INPUTS = ("run_dir", "db_path", "rootfs", "image_id",
          "candidate_snapshot_sha256", "worklist_path", "result_path")
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


@pytest.fixture
def variables(tmp_path):
    run = tmp_path / "run"
    return dict(run_dir=str(run), db_path=str(run / "audit.db"),
                rootfs=str(tmp_path / "rootfs"), image_id="router-target",
                candidate_snapshot_sha256="a" * 64,
                worklist_path=str(run / "files" / "firmware-chain" / ("b" * 64) / "worklist.json"),
                result_path=str(run / "files" / "chain-result.json"))


def rendered(variables):
    return briefs.write_brief("firmware-chain", "global", variables["run_dir"], variables).read_text()


def test_global_brief_library_and_cli_bind_exact_paths_without_inlining(variables):
    worklist = pathlib.Path(variables["worklist_path"])
    worklist.parent.mkdir(parents=True)
    worklist.write_text('{"private_evidence":"DO-NOT-INLINE-CHAIN-123"}')
    command = [sys.executable, str(ROOT / "audit.py"), "brief", "--phase",
               "firmware-chain", "--unit", "global", "--run", variables["run_dir"]]
    for name, value in variables.items():
        command.extend(["--var", f"{name}={value}"])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    output = pathlib.Path(variables["run_dir"]) / "briefs" / "firmware-chain-global-brief.md"
    assert result.stdout == f"{output}\n"
    text = output.read_text()
    assert text == rendered(variables)
    assert set(PLACEHOLDER.findall(TEMPLATE.read_text())) == set(INPUTS)
    assert not PLACEHOLDER.search(text)
    assert all(value in text for value in variables.values())
    assert "DO-NOT-INLINE-CHAIN-123" not in text + result.stdout


@pytest.mark.parametrize("name", INPUTS)
@pytest.mark.parametrize("value", [None, ""])
def test_each_global_chain_input_is_required(variables, name, value):
    if value is None:
        del variables[name]
    else:
        variables[name] = value
    with pytest.raises(briefs.BriefError, match=name):
        briefs.render(TEMPLATE.read_text(), variables)


@pytest.mark.parametrize("requirements", [
    ("exactly one disposition for every", "chained", "standalone", "unchainable", "blocked",
     "multiple chains", "every chain containing", "at least two", "alternative paths",
     "blocked materialized chain", "zero dispositions"),
    ("capability_kind", "link_key", "produced_capability", "required_precondition",
     "producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs",
     "finding:<finding-id>#<field>", "surface:<surface-id>#reach_evidence",
     "unknown:<unknown-id>#evidence", "middle-node continuity", "incoming", "outgoing"),
    ("initial_attacker_position", "initial_evidence_refs", "initial_state", "required_state",
     "result_state", "any", "unchanged", "carry", "reboot", "service-restart",
     "factory-reset", "reprovision", "producer and consumer evidence", "pre_auth", "derived"),
    ("settling_observation", "static", "emulate", "hardware", "affected_finding_ids",
     "affected_edges", "authentication", "lifecycle", "posture", "reachability",
     "resolved", "open", "pivot_followup_ids", "context-only", "unchainable` or `blocked"),
    ("correlation-not-causation", "privilege discontinuity", "reboot magic",
     "same-daemon assumptions", "confused-deputy claims", "pre-auth inflation", "alternative paths"),
])
def test_chain_method_covers_each_reasoning_obligation(variables, requirements):
    text = " ".join(rendered(variables).split())
    for requirement in requirements:
        assert requirement in text, requirement


def test_chain_result_only_ownership_and_static_safety(variables):
    text = " ".join(rendered(variables).split())
    for requirement in (
        "immutable", "worklist_sha256", "exact bytes", "FAILED",
        "firmware_chain_results.py", "firmware_chain.py", "strict JSON", "result-only",
        "regular UTF-8 file capped at 8 MiB", "duplicate keys", "extra keys", "non-finite numbers",
        "Do not write SQL", "Do not write to the database", "canonical artifact installation",
        "orchestrator", "identities", "completion", "Do not execute", "Do not emulate",
        "Do not exploit", "weaponize", "assign severity", "CVSS", "runtime reachability",
        "relative component paths", "Do not persist absolute", "PARTIAL", "checkpoint",
        "not importable", "remaining finding IDs", "without fabricating dispositions",
        "one global", "strongest", "no finding count cap",
    ):
        assert requirement in text, requirement


def test_chain_return_counts_dispositions_and_has_exact_one_line(variables):
    text = rendered(variables)
    line = "    firmware-chain <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]"
    assert text.splitlines().count(line) == 1
    assert "Return exactly one line, and nothing else:" in text
    assert "Rows counts finding dispositions" in text


def test_skill_routes_one_global_firmware_worker_separately_from_generic_chains():
    skill = (ROOT / "SKILL.md").read_text()
    assert "### Stage 4g firmware chain" in skill
    route = skill.split("### Stage 4g firmware chain", 1)[1].split("\n### ", 1)[0]
    assert "references/briefs/firmware-chain-brief.md" in route
    positions = []
    for mode in ("--prepare", "--record ${RESULT_PATH}", "--check"):
        match = re.search(r"python3 __SKILL_DIR__/audit.py chain[^\n]*" + re.escape(mode), route)
        assert match is not None, mode
        positions.append(match.start())
    assert positions == sorted(positions)
    brief = re.search(r"audit\.py brief --phase firmware-chain\s*\\?\s*--unit global", route)
    assert brief is not None
    assert positions[0] < brief.start() < positions[1]
    assert "one global worker" in route and "strongest" in route
    assert "dispatch only its path" in route
    assert "Do not inline" in route
    assert "PARTIAL" in route and "same immutable" in route
    assert "DONE alone" in route
    for name in INPUTS:
        assert f"--var {name}=" in route
    assert "ordinary source-code `chain`" in route
    assert "`audit.py chain` proposes; a human composes." in skill
    assert '"Each group\'s findings are independent"' in skill
