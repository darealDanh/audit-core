"""The dispatched surface assignment preserves the evidence and artifact contract."""
import pathlib
import re
import subprocess
import sys

import pytest

import audit
from audit_core import briefs, skill_lint

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")
INPUTS = ("run_dir", "db_path", "rootfs", "image_id", "manifest_sha256",
          "worklist_index", "batch_path", "result_path")


@pytest.fixture
def variables(tmp_path):
    run = tmp_path / "audit-1"
    generation = run / "files" / "surface" / ("b" * 64)
    return {
        "run_dir": str(run), "db_path": str(run / "audit.db"),
        "rootfs": "/carved/target-root", "image_id": "acme-r1-target",
        "manifest_sha256": "a" * 64,
        "worklist_index": str(generation / "index.json"),
        "batch_path": str(generation / "batch-0001.json"),
        "result_path": str(run / "files" / "surface-result-0001.json"),
    }


def render_surface(variables):
    return briefs.write_brief(
        "surface", "batch-0001", variables["run_dir"], variables,
    ).read_text()


def test_surface_dispatch_renders_every_input_without_inlining_files(variables):
    """A missing input or pasted batch changes the real CLI dispatch artifact."""
    for name in ("worklist_index", "batch_path"):
        path = pathlib.Path(variables[name])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('DO-NOT-INLINE-SURFACE-CONTENT-123')
    command = [sys.executable, str(ROOT / "audit.py"), "brief", "--phase",
               "surface", "--unit", "batch-0001", "--run", variables["run_dir"]]
    for name, value in variables.items():
        command.extend(["--var", f"{name}={value}"])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    path = pathlib.Path(variables["run_dir"]) / "briefs" / "surface-batch-0001-brief.md"
    assert result.stdout == f"{path}\n"
    rendered = path.read_text()
    template = briefs.template_path("surface").read_text()
    assert set(PLACEHOLDER.findall(template)) == set(INPUTS)
    assert rendered == briefs.render(template, variables)
    assert rendered == render_surface(variables)
    for value in variables.values():
        assert value in rendered
    assert not PLACEHOLDER.search(rendered)
    assert "DO-NOT-INLINE-SURFACE-CONTENT-123" not in rendered + result.stdout


@pytest.mark.parametrize("missing", INPUTS)
def test_surface_dispatch_requires_each_input(variables, missing):
    """An unbound path or provenance value must fail rendering, never invite guessing."""
    template = briefs.template_path("surface").read_text()
    del variables[missing]
    with pytest.raises(briefs.BriefError, match=missing):
        briefs.render(template, variables)


@pytest.mark.parametrize("requirements", (
    (
        "exactly one decision for every assigned unit", "no unassigned unit",
        "Do not silently omit", "analyzed", "not_audited", "reason='budget'",
        "no surface", "reason", "evidence-backed explanation",
        "absence of a hint is not evidence of absence",
    ),
    (
        "service, ELF, component, imports, strings, configuration, and caller",
        "leads, not conclusions", "external entry point", "dispatcher",
        "concrete handler", "symbol, offset, key, or configuration line",
        "authentication or authorization", "before or after", "unknown",
    ),
    (
        "Record the full device-state tuple", "lifecycle_required",
        "posture_required", "auth_required", "reachability", "reach_evidence",
        "evidenced", "refuted", "static path", "different protocols",
        "entry points, or state tuples",
    ),
    (
        "Create an explicit unknown for every unresolved field", "dispatch",
        "handler", "settling_observation", "static", "emulate", "hardware",
        "matching open unknown", "same surface and field", "surface_id=null",
        "resolution=null", "evidence=null", "resolved", "non-empty",
        "Do not turn an open unknown into a negative reachability claim",
    ),
    (
        "Write only one strict JSON result", "UTF-8", "8 MiB", "schema_version=1",
        "audit_core/surface_results.py", "BatchResult", "UnitDecision",
        "SurfaceRecord", "UnknownRecord", "audit_core/surface.py",
        "audit_core/db.py", "relative batch filename", "SHA-256 of the index bytes",
        "batch_sha256", "duplicate keys", "extra keys", "timestamps",
        "The deterministic importer owns SQL", "Do not write to the database",
        "or run the importer", "Only the orchestrator", "surface --check",
    ),
    (
        "Do not hunt vulnerabilities", "assign severity", "execute exploits",
        "execute target binaries", "emulate firmware", "infer listeners",
        "expand scope", "modify the carved root", "kernel or bootloader",
        "paths, not pasted contents", "PARTIAL or FAILED", "open unknowns",
    ),
))
def test_surface_assignment_keeps_literal_operational_contracts(variables, requirements):
    """Deleting a required imperative must fail even if the template still renders."""
    rendered = " ".join(render_surface(variables).split())
    for required in requirements:
        assert required in rendered


def test_surface_return_is_exactly_one_r2_line_accepted_by_lint(variables, tmp_path):
    """The worker's status stays bounded and acceptable to the real R2 gate."""
    rendered = render_surface(variables)
    line = "    surface-<batch> <DONE|PARTIAL|FAILED> rows=<n> artifact=<path> [flags=<csv>]"
    assert rendered.splitlines().count(line) == 1
    assert "Return exactly one line, and nothing else:" in rendered
    assert "rows counts unit decisions" in " ".join(rendered.split())
    assert "DONE does not certify the run" in rendered
    root = tmp_path / "skill"
    (root / "references" / "briefs").mkdir(parents=True)
    (root / "SKILL.md").write_text("# Surface contract fixture\n")
    (root / "references" / "briefs" / "surface-brief.md").write_text(rendered)
    assert skill_lint.lint(root, set(audit.HANDLERS)) == []


@pytest.mark.parametrize("required", (
    "Replace `<batch>` with the batch's `batch_id`",
    "`<path>` with the required result file path",
    "Use DONE only for a complete valid batch result",
    "choose PARTIAL for explicit unfinished work",
    "FAILED when a valid bound result cannot be produced",
))
def test_surface_return_keeps_status_meanings_and_substitution_instructions(variables, required):
    # Breaks: losing a status meaning or leaving the worker's return placeholders ambiguous.
    assert required in " ".join(render_surface(variables).split())
