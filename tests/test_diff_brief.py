import pathlib
import subprocess
import sys

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def variables(tmp_path):
    run = tmp_path / "audit-1"
    return {
        "run_dir": str(run),
        "diff_id": "acme-r1-patch",
        "target_root": "/carved/current",
        "reference_root": "/carved/vulnerable",
        "manifest_path": str(run / "files" / "diff-manifest.json"),
        "artifact_path": str(run / "artifacts" / "semantic-diff.md"),
        "known_advisory": "CVE-2026-12345: unchecked request length",
        "patched_component": "usr/sbin/httpd",
    }


def render_diff(variables):
    return briefs.write_brief(
        "diff", variables["diff_id"], variables["run_dir"], variables,
    ).read_text()


def test_cli_dispatches_a_file_backed_brief_with_every_input(variables):
    """Dropping any input or inlining the manifest breaks the dispatch contract."""
    manifest = pathlib.Path(variables["manifest_path"])
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"raw_diff_marker": "DO-NOT-INLINE-ENTRY-123"}')
    command = [
        sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "diff",
        "--unit", variables["diff_id"], "--run", variables["run_dir"],
    ]
    for name, value in variables.items():
        command.extend(["--var", f"{name}={value}"])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    path = pathlib.Path(variables["run_dir"]) / "briefs" / (
        "diff-acme-r1-patch-brief.md")
    assert result.stdout == f"{path}\n"
    rendered = path.read_text()
    for value in variables.values():
        assert value in rendered
    assert "DO-NOT-INLINE-ENTRY-123" not in result.stdout + rendered


@pytest.mark.parametrize("missing", (
    "run_dir", "diff_id", "target_root", "reference_root", "manifest_path",
    "artifact_path", "known_advisory", "patched_component",
))
def test_diff_assignment_requires_each_declared_input(variables, missing):
    """An omitted placeholder must refuse dispatch instead of inviting guesses."""
    del variables[missing]
    with pytest.raises(briefs.BriefError, match=missing):
        # Avoid write_brief's output-directory side effect on an invalid brief.
        briefs.render(briefs.template_path("diff").read_text(),
                      variables)


@pytest.mark.parametrize("requirements", (
    (
        "Start from the known patched component",
        "file churn elsewhere is not a vulnerability signal",
        "before/after mechanism", "evidence from both builds",
        "exact locations", "compiler", "packaging", "timestamp",
        "stripping", "configuration", "uncertainty",
    ),
    (
        "audit.py put", "cba_security_observations",
        "diff-acme-r1-patch", "group_id", "observation", "location",
        "fix idiom", "evidence-backed",
    ),
    (
        "Search only the target", "unsafe side of the idiom",
        "Do not search the vulnerable reference for surviving siblings",
        "non-mechanical sibling analysis", "each surviving lead",
        "bounded observations", "exact locations and evidence",
    ),
    (
        "Only when the idiom has an honest mechanical expression",
        "cba_patterns", "audit.py sweep", "--record",
        "--root /carved/current", "misleading regex",
        "Do not force a semantic condition",
    ),
    (
        "Write the detailed analysis", "bounded", "limitations",
        "Keep raw diff contents out of the dispatch and return",
        "Read the file-backed manifest",
    ),
    (
        "Do not turn every changed file or component into a finding",
        "Do not begin broad hunting", "map handler tables", "emulate firmware",
        "Do not modify either carved tree",
    ),
))
def test_rendered_assignment_preserves_semantic_analysis_boundaries(
        variables, requirements):
    """Removing a required instruction from the dispatched assignment is a bug."""
    rendered = " ".join(render_diff(variables).split())
    for required in requirements:
        assert required in rendered


def test_diff_return_is_exactly_the_bounded_r2_contract(variables):
    """An inline analysis or a changed status/row/artifact shape breaks R2."""
    rendered = render_diff(variables)
    expected = (
        "    diff <DONE|PARTIAL|FAILED> rows=<n> artifact="
        + variables["artifact_path"] + " [flags=<csv>]"
    )
    assert rendered.splitlines().count(expected) == 1
    assert "Return exactly one line, and nothing else:" in rendered
    assert "rows counts the observations actually recorded" in rendered
