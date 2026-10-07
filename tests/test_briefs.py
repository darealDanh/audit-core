import pathlib
import subprocess
import sys

import pytest

from audit_core import briefs

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_render_substitutes_placeholders():
    out = briefs.render("group {group_id} covers {scope}",
                        {"group_id": "G7", "scope": "nvram"})
    assert out == "group G7 covers nvram"


def test_render_rejects_unsubstituted_placeholder():
    """Review Focus 2: an unfilled {placeholder} reaching an agent is worse
    than failing, because the agent will guess at it."""
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("group {group_id} covers {scope}", {"group_id": "G7"})
    assert "scope" in str(exc.value)


def test_render_leaves_unrelated_braces_alone():
    out = briefs.render("use {group_id} and shell ${HOME} and json {}",
                        {"group_id": "G7"})
    assert "${HOME}" in out and "{}" in out


def test_render_reports_every_missing_placeholder_at_once():
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("{a} {b} {c}", {"b": "x"})
    message = str(exc.value)
    assert "a" in message and "c" in message


def test_write_brief_creates_the_file(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    path = briefs.write_brief("audit", "G7", run, {"group_id": "G7"},
                              template_dir=tpl_dir)
    assert path == run / "briefs" / "audit-G7-brief.md"
    assert path.read_text() == "audit G7"


def test_write_brief_unknown_phase_raises(tmp_path):
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    with pytest.raises(briefs.BriefError) as exc:
        briefs.write_brief("nosuchphase", "G7", run, {}, template_dir=tmp_path)
    assert "nosuchphase" in str(exc.value)


def test_cli_brief_prints_path(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "audit",
         "--unit", "G7", "--run", str(run), "--var", "group_id=G7",
         "--template-dir", str(tpl_dir)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[-1] == str(
        run / "briefs" / "audit-G7-brief.md")


def test_cli_brief_exits_one_on_missing_variable(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id} {scope}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "audit",
         "--unit", "G7", "--run", str(run), "--var", "group_id=G7",
         "--template-dir", str(tpl_dir)],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "scope" in (r.stdout + r.stderr)


# --- I6: an empty value is as bad as a missing one ---------------------------


def test_render_rejects_an_empty_value():
    """`--var source_access=''` rendered a brief with a blank Source access
    section and exited 0. The subagent then has to guess where the code is -
    the same failure as an unfilled placeholder, reported as success."""
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("source: {source_access}", {"source_access": ""})
    assert "source_access" in str(exc.value)


def test_render_rejects_a_whitespace_only_value():
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("known: {known_findings}", {"known_findings": "   \n  "})
    assert "known_findings" in str(exc.value)


def test_render_reports_every_empty_placeholder_at_once():
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("{a} {b} {c}", {"a": "", "b": "ok", "c": " "})
    message = str(exc.value)
    assert "a" in message and "c" in message


def test_render_allows_empty_when_asked():
    out = briefs.render("known: {known_findings}", {"known_findings": ""},
                        allow_empty=True)
    assert out == "known: "


def test_cli_brief_exits_one_on_an_empty_variable(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id} source {source_access}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "audit",
         "--unit", "G7", "--run", str(run), "--var", "group_id=G7",
         "--var", "source_access=", "--template-dir", str(tpl_dir)],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "source_access" in (r.stdout + r.stderr)


def test_cli_brief_allow_empty_renders_the_empty_section(tmp_path):
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "audit-brief.md").write_text("audit {group_id} known {known_findings}")
    run = tmp_path / "run"
    (run / "briefs").mkdir(parents=True)
    r = subprocess.run(
        [sys.executable, str(ROOT / "audit.py"), "brief", "--phase", "audit",
         "--unit", "G7", "--run", str(run), "--var", "group_id=G7",
         "--var", "known_findings=", "--allow-empty",
         "--template-dir", str(tpl_dir)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert (run / "briefs" / "audit-G7-brief.md").read_text() == "audit G7 known "


def test_missing_and_empty_placeholders_are_reported_together():
    """Reproduced 2026-10-07: render raised on `missing` and returned, so an
    operator fixed the missing placeholder, re-ran, and only then discovered
    the empty one. Two round trips for one template."""
    with pytest.raises(briefs.BriefError) as exc:
        briefs.render("a {MISSING} and {EMPTY}", {"EMPTY": "   "})
    message = str(exc.value)
    assert "MISSING" in message
    assert "EMPTY" in message
    assert "--allow-empty" in message   # the actionable hint survives
