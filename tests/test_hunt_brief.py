"""The firmware hunt dispatch stays complete, lane-aware, and file-backed."""
import pathlib
import re
import subprocess
import sys

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = briefs.template_path("hunt")
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")
INPUTS = (
    "run_dir", "db_path", "rootfs", "image_id", "lane", "manifest_sha256",
    "surface_snapshot_sha256", "worklist_index", "batch_path", "result_path",
)


@pytest.fixture
def variables(tmp_path):
    run = tmp_path / "audit-1"
    generation = run / "files" / "hunt" / ("b" * 64) / "l-sink"
    return {
        "run_dir": str(run), "db_path": str(run / "audit.db"),
        "rootfs": "/carved/target-root", "image_id": "acme-r1-target",
        "lane": "l-sink", "manifest_sha256": "a" * 64,
        "surface_snapshot_sha256": "c" * 64,
        "worklist_index": str(generation / "index.json"),
        "batch_path": str(generation / "batch-0001.json"),
        "result_path": str(run / "files" / "hunt-result-0001.json"),
    }


def render_hunt(variables, unit="l-sink-batch-0001"):
    return briefs.write_brief("hunt", unit, variables["run_dir"], variables).read_text()


def test_hunt_template_renders_through_library_and_cli_without_inlining(variables):
    """The rendered brief binds all ten inputs while carrying only assigned paths."""
    assert TEMPLATE.is_file()
    for name in ("worklist_index", "batch_path"):
        path = pathlib.Path(variables[name])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"raw_evidence_marker":"DO-NOT-INLINE-HUNT-123"}')

    command = [sys.executable, str(ROOT / "audit.py"), "brief", "--phase",
               "hunt", "--unit", "l-sink-batch-0001", "--run", variables["run_dir"]]
    for name, value in variables.items():
        command.extend(["--var", f"{name}={value}"])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    output = pathlib.Path(variables["run_dir"]) / "briefs" / "hunt-l-sink-batch-0001-brief.md"
    assert result.stdout == f"{output}\n"

    template = TEMPLATE.read_text()
    rendered = output.read_text()
    assert set(PLACEHOLDER.findall(template)) == set(INPUTS)
    assert rendered == briefs.render(template, variables)
    assert rendered == render_hunt(variables)
    for name in INPUTS:
        assert variables[name] in rendered
    assert not PLACEHOLDER.search(rendered)
    assert "DO-NOT-INLINE-HUNT-123" not in result.stdout + rendered


@pytest.mark.parametrize("missing", INPUTS)
def test_hunt_brief_requires_each_provenance_value_and_path(variables, missing):
    del variables[missing]
    with pytest.raises(briefs.BriefError, match=missing):
        briefs.render(TEMPLATE.read_text(), variables)


@pytest.mark.parametrize("lane", ("l-sink", "l-dark"))
def test_hunt_brief_carries_both_lane_contracts(variables, lane):
    variables["lane"] = lane
    text = " ".join(render_hunt(variables).split())

    common = (
        "exactly one decision for every assigned unit",
        "no other unit", "Do not silently omit", "absence of a hint is not evidence of absence",
        "full attacker-input-to-operation trace", "mitigations checked",
        "device-state evidence", "lifecycle_required", "posture_required",
        "auth_required", "reachability", "Write only one strict JSON result",
        "regular UTF-8 file capped at 8 MiB", "duplicate keys", "non-finite numbers",
        "impact hypothesis", "candidate blockers",
        "audit_core/hunt_results.py", "The deterministic importer owns SQL",
        "Do not write to the database", "Only the orchestrator", "Keep all raw evidence",
        "budget", "PARTIAL", "orchestrator publishes the checkpoint",
        "do not manufacture clear decisions or publish a database checkpoint",
        "database-writing `audit.py checkpoint` command",
        "remaining unit paths", "resumption of the same lane",
        "Do not turn a budget checkpoint into not_audited(reason='budget')",
        "Do not execute binaries", "Do not emulate firmware", "Do not exploit",
        "weaponize", "assign severity",
    )
    for requirement in common:
        assert requirement in text

    if lane == "l-sink":
        for category in ("system", "popen", "execve", "doSystemCmd", "twsystem",
                         "strcpy", "sprintf", "memcpy", "unbounded `%s` scanning",
                         "NVRAM", "attacker-controlled format strings"):
            assert category in text
    else:
        for category in ("UPnP/SSDP", "mDNS", "TR-069/CWMP", "cloud tunnels",
                         "P2P pairing", "proprietary LAN discovery", "UDP",
                         "multicast", "HTTP-daemon-to-helper IPC", "Unix sockets",
                         "OTA signature", "downgrade", "trust verification",
                         "heap corruption"):
            assert category in text
        assert "name a concrete protocol, trust boundary, OTA decision, or heap-corruption mechanism" in text


def test_hunt_return_is_the_exact_one_line_contract(variables):
    rendered = render_hunt(variables)
    expected = "    hunt-<lane>-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]"
    assert rendered.splitlines().count(expected) == 1
    assert "Return exactly one line, and nothing else:" in rendered
    assert "Rows counts unit decisions" in " ".join(rendered.split())


def test_skill_router_exposes_firmware_hunt_without_inline_dispatch_content():
    skill = (ROOT / "firmware-audit" / "SKILL.md").read_bytes().decode("utf-8")
    assert "Stage 4e firmware hunt" in skill
    assert "hunt-brief.md" in skill
    assert "python3 __SKILL_DIR__/audit.py hunt --run ${AUDIT_DIR} --root ${ROOTFS}" in skill
    assert "python3 __SKILL_DIR__/audit.py hunt --run ${AUDIT_DIR} --root ${ROOTFS} --check" in skill
    assert re.search(r"audit\.py brief --phase hunt\s*\\?\s*--unit", skill)
    assert "l-sink" in skill and "l-dark" in skill
    assert "economical tier" in skill
    assert "strongest available tier" in skill
