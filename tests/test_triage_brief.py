from audit_core import briefs


def test_triage_brief_renders_the_run_and_firmware_inputs(tmp_path):
    run = tmp_path / "audit-1"
    rendered = briefs.write_brief("triage", "firmware", run, {
        "run_dir": str(run), "rootfs": "/carved/rootfs",
        "image_id": "acme|r1|target",
    }).read_text()
    assert str(run) in rendered
    assert "/carved/rootfs" in rendered
    assert "acme|r1|target" in rendered


def test_triage_brief_keeps_evidence_boundaries(tmp_path):
    run = tmp_path / "audit-1"
    rendered = briefs.write_brief("triage", "firmware", run, {
        "run_dir": str(run), "rootfs": "/carved/rootfs", "image_id": "none",
    }).read_text()
    for required in (
        "BusyBox", "cba_components", "cba_services", "ports_evidence",
        "audit.py note", "architecture", "dynamic loader", "libc",
        "does not prove that a port listens",
        "triage <DONE|PARTIAL|FAILED> rows=<n> artifact=",
    ):
        assert required in rendered
    assert "image id: none" in rendered.lower()
