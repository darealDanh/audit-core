"""Defensive Stage 4g branches reject the exact corrupt evidence they name."""
import copy
import dataclasses
import hashlib
import json
import os
import pathlib

import pytest

from audit_core import db, firmware_chain, firmware_chain_results as results, surface
from audit_core import firmware_fpcheck_results
from tests.test_firmware_chain_gate import check, completed_with_sibling  # noqa: F401
from tests.test_firmware_chain_import import record, rows
from tests.test_firmware_chain_prepare import prepared  # noqa: F401
from tests.test_firmware_chain_validation import graph_case  # noqa: F401


def parsed(case, value=None):
    path = case[1] / "coverage-chain-result.json"
    path.write_text(json.dumps(case[3] if value is None else value))
    return results.load(path)


def validate(case, value=None):
    return results.validate(case[0], case[1], parsed(case, value))


def bind_worklist(case, frozen):
    """Install a self-consistent alternative worklist and bind the pending run."""
    con, run = case[:2]
    content = surface.canonical_bytes(frozen)
    digest = hashlib.sha256(content).hexdigest()
    destination = run / "files/firmware-chain" / digest
    surface.atomic_install(destination, {"worklist.json": content})
    con.execute(
        "UPDATE cba_firmware_chain_runs SET worklist_path=?,worklist_sha256=? WHERE image_id='target'",
        (str(destination / "worklist.json"), digest),
    )
    return dataclasses.replace(parsed(case), worklist_sha256=digest)


def retained_review_result(case, content):
    """Point the real Stage 4f receipt at immutable bytes with matching ownership."""
    con, run = case[:2]
    review = dict(con.execute("SELECT * FROM cba_firmware_fp_runs WHERE image_id='target'").fetchone())
    digest = hashlib.sha256(content).hexdigest()
    destination = run / "artifacts/firmware-fpcheck" / review["worklist_sha256"] / digest
    surface.atomic_install(destination, {"result.json": content})
    con.execute(
        "UPDATE cba_firmware_fp_receipts SET result_path=?,result_sha256=? WHERE image_id='target'",
        (str(destination / "result.json"), digest),
    )


def test_file_and_public_type_guards_reject_their_named_inputs(tmp_path, monkeypatch):
    missing = tmp_path / "missing-generation"
    with pytest.raises(firmware_chain.FirmwareChainError, match="worklist directory"):
        firmware_chain._checked_install(missing, b"{}\n")

    generation = tmp_path / "generation"
    generation.mkdir()
    (generation / "worklist.json").write_bytes(b"{}\n")
    (generation / "unexpected.json").write_bytes(b"{}\n")
    with pytest.raises(firmware_chain.FirmwareChainError, match="different artifacts"):
        firmware_chain._checked_install(generation, b"{}\n")

    with pytest.raises(firmware_chain.FirmwareChainError, match="Expected a GraphResult"):
        results.canonical_bytes(object())
    with pytest.raises(firmware_chain.FirmwareChainError, match="Expected a GraphResult"):
        results.validate(None, tmp_path, object())

    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps({
        "schema_version": 1,
        "image_id": "target",
        "candidate_snapshot_sha256": "a" * 64,
        "worklist_sha256": "b" * 64,
        "blockers": {},
        "dispositions": [],
        "chains": [],
    }))
    with pytest.raises(firmware_chain.FirmwareChainError, match="blockers requires an array"):
        results.load(malformed)

    regular = tmp_path / "regular.json"
    other = tmp_path / "other.json"
    regular.write_text("{}")
    other.write_text("{}")
    actual_fstat = results.os.fstat
    monkeypatch.setattr(results.os, "fstat", lambda descriptor: os.stat(other))
    with pytest.raises(firmware_chain.FirmwareChainError, match="regular file"):
        results.load(regular)
    monkeypatch.setattr(results.os, "fstat", actual_fstat)

    with pytest.raises(firmware_chain.FirmwareChainError, match="Invalid retained artifact path"):
        results._retained_bytes(tmp_path, "/absolute/result.json", "0" * 64)
    with pytest.raises(firmware_chain.FirmwareChainError, match="regular file"):
        results._retained_bytes(tmp_path, "absent/result.json", "0" * 64)


def test_review_index_rejects_invalid_schema_batch_size_descriptor_and_path(graph_case):
    con, run = graph_case[:2]
    original = dict(con.execute("SELECT * FROM cba_firmware_fp_runs WHERE image_id='target'").fetchone())
    cases = (
        ([], "Invalid review index"),
        ({"schema_version": 1, "batch_size": 0, "batches": []}, "Invalid review batch size"),
        ({"schema_version": 1, "batch_size": 1, "batches": [{}]}, "Invalid review batch descriptor"),
        ({"schema_version": 1, "batch_size": 1, "batches": [
            {"path": "../batch.json", "sha256": "a" * 64, "candidate_count": 1}
        ]}, "Invalid or repeated review batch path"),
    )
    for value, message in cases:
        content = surface.canonical_bytes(value)
        digest = hashlib.sha256(content).hexdigest()
        destination = run / "files/firmware-fpcheck" / digest
        surface.atomic_install(destination, {"index.json": content})
        review = original | {
            "worklist_sha256": digest,
            "worklist_path": str(destination / "index.json"),
        }
        with pytest.raises(firmware_chain.FirmwareChainError, match=message):
            results._review_index(con, run, review)


def test_review_result_path_structure_and_ownership_are_revalidated(graph_case):
    con, run = graph_case[:2]
    graph = parsed(graph_case)

    con.execute("UPDATE cba_firmware_fp_receipts SET result_path='not-canonical' WHERE image_id='target'")
    with pytest.raises(firmware_chain.FirmwareChainError, match="result path is not canonical"):
        results.validate(con, run, graph)
    con.rollback()

    retained_review_result(graph_case, b"{}\n")
    with pytest.raises(firmware_chain.FirmwareChainError, match="Invalid retained review result"):
        results.validate(con, run, graph)
    con.rollback()

    receipt_path = pathlib.Path(con.execute(
        "SELECT result_path FROM cba_firmware_fp_receipts WHERE image_id='target'"
    ).fetchone()[0])
    value = json.loads(receipt_path.read_bytes())
    value["image_id"] = "foreign"
    forged = firmware_fpcheck_results._canonical(firmware_fpcheck_results._parse(value))
    retained_review_result(graph_case, forged)
    with pytest.raises(firmware_chain.FirmwareChainError, match="result ownership differs"):
        results.validate(con, run, graph)
    con.rollback()


def test_prepared_generation_rejects_each_provenance_disagreement(graph_case):
    con, run, _, _, frozen_original = graph_case
    graph = parsed(graph_case)

    con.execute("UPDATE cba_firmware_chain_runs SET worklist_path='wrong' WHERE image_id='target'")
    with pytest.raises(firmware_chain.FirmwareChainError, match="Prepared worklist path differs"):
        results.validate(con, run, graph)
    con.rollback()

    con.execute("DELETE FROM cba_firmware_fp_runs WHERE image_id='target'")
    with pytest.raises(firmware_chain.FirmwareChainError, match="One complete firmware review"):
        results.validate(con, run, graph)
    con.rollback()

    con.execute("UPDATE cba_firmware_fp_runs SET manifest_sha256=? WHERE image_id='target'", ("0" * 64,))
    with pytest.raises(firmware_chain.FirmwareChainError, match="Current review and prepared generation differ"):
        results.validate(con, run, graph)
    con.rollback()

    invalid = bind_worklist(graph_case, [])
    with pytest.raises(firmware_chain.FirmwareChainError, match="Invalid prepared worklist"):
        results.validate(con, run, invalid)
    con.rollback()

    frozen = copy.deepcopy(frozen_original)
    frozen["findings_artifact_path"] = "artifacts/foreign/findings.json"
    rebound = bind_worklist(graph_case, frozen)
    with pytest.raises(firmware_chain.FirmwareChainError, match="Prepared findings artifact ownership differs"):
        results.validate(con, run, rebound)
    con.rollback()

    old_artifact = run / frozen_original["findings_artifact_path"]
    alternative = run / "artifacts/noncanonical/findings.json"
    alternative.parent.mkdir(parents=True, exist_ok=True)
    alternative.write_bytes(old_artifact.read_bytes())
    frozen = copy.deepcopy(frozen_original)
    frozen["findings_artifact_path"] = alternative.relative_to(run).as_posix()
    con.execute(
        "UPDATE cba_firmware_chain_runs SET fpcheck_artifact_path=? WHERE image_id='target'",
        (str(alternative),),
    )
    rebound = bind_worklist(graph_case, frozen)
    with pytest.raises(firmware_chain.FirmwareChainError, match="Findings artifact is not canonical"):
        results.validate(con, run, rebound)
    con.rollback()


def test_current_sql_filtering_and_artifact_ownership_fail_closed(graph_case):
    con, run = graph_case[:2]
    graph = parsed(graph_case)
    surface_row = dict(con.execute(
        "SELECT * FROM cba_firmware_surfaces WHERE image_id='target' LIMIT 1"
    ).fetchone())
    db.put(con, "cba_firmware_surfaces", surface_row | {
        "surface_id": "unreferenced-surface",
        "component_path": "unreferenced-component",
    }, commit=False)
    assert results.validate(con, run, graph).result == graph
    con.rollback()

    artifact = pathlib.Path(con.execute(
        "SELECT artifact_path FROM cba_firmware_findings WHERE image_id='target' LIMIT 1"
    ).fetchone()[0])
    alternative = run / "artifacts/alternate-finding.json"
    alternative.parent.mkdir(parents=True, exist_ok=True)
    alternative.write_bytes(artifact.read_bytes())
    con.execute(
        "UPDATE cba_firmware_findings SET artifact_path=? WHERE image_id='target'",
        (str(alternative),),
    )
    with pytest.raises(firmware_chain.FirmwareChainError, match="Finding artifact ownership differs"):
        results.validate(con, run, graph)
    con.rollback()

    con.execute(
        "UPDATE cba_firmware_pivots SET candidate_snapshot_sha256=? WHERE image_id='target'",
        ("0" * 64,),
    )
    with pytest.raises(firmware_chain.FirmwareChainError, match="Foreign candidate snapshot"):
        results.validate(con, run, graph)
    con.rollback()


def test_canonical_findings_artifact_must_match_rebuilt_review(graph_case):
    con, run, _, _, frozen_original = graph_case
    bad_artifact = b"{}\n"
    artifact_digest = hashlib.sha256(bad_artifact).hexdigest()
    review_digest = con.execute(
        "SELECT worklist_sha256 FROM cba_firmware_fp_runs WHERE image_id='target'"
    ).fetchone()[0]
    destination = run / "artifacts/firmware-fpcheck" / review_digest / artifact_digest
    surface.atomic_install(destination, {"findings.json": bad_artifact})
    relative = (destination / "findings.json").relative_to(run).as_posix()
    con.execute(
        "UPDATE cba_firmware_chain_runs SET fpcheck_artifact_path=?,fpcheck_artifact_sha256=? "
        "WHERE image_id='target'",
        (str(destination / "findings.json"), artifact_digest),
    )
    con.execute(
        "UPDATE cba_firmware_findings SET artifact_path=?,artifact_sha256=? WHERE image_id='target'",
        (str(destination / "findings.json"), artifact_digest),
    )
    frozen = copy.deepcopy(frozen_original)
    frozen.update(findings_artifact_path=relative, findings_artifact_sha256=artifact_digest)
    for finding in frozen["findings"]:
        finding.update(artifact_path=relative, artifact_sha256=artifact_digest)
    rebound = bind_worklist(graph_case, frozen)
    with pytest.raises(firmware_chain.FirmwareChainError, match="Canonical findings artifact differs"):
        results.validate(con, run, rebound)
    con.rollback()


def test_graph_evidence_and_blocker_ownership_reject_specific_mismatch(graph_case):
    graph = parsed(graph_case)
    frozen = copy.deepcopy(graph_case[4])
    frozen["pivots"][0]["pivot_id"] = "http-c"
    with pytest.raises(firmware_chain.FirmwareChainError, match="Pivots cannot supply evidence"):
        results._validate_graph(graph, frozen)

    first = graph_case[3]["chains"][0]["member_ids"][0]
    owned = set(next(row for row in graph_case[4]["findings"] if row["finding_id"] == first)["surface_ids"])
    foreign_surface = next(row["surface_id"] for row in graph_case[4]["surfaces"]
                           if row["surface_id"] not in owned)
    value = copy.deepcopy(graph_case[3])
    value["chains"][0]["initial_evidence_refs"] = [f"surface:{foreign_surface}#reach_evidence"]
    with pytest.raises(firmware_chain.FirmwareChainError, match="Initial surface evidence"):
        validate(graph_case, value)

    value = copy.deepcopy(graph_case[3])
    value["blockers"] = [{
        "blocker_key": "disposition",
        "question": "Does the independent primitive compose?",
        "settling_observation": "Observe a compatible consumer",
        "method": "static",
        "axes": ["reachability"],
        "affected_finding_ids": [value["chains"][0]["member_ids"][0]],
        "affected_edges": [],
    }]
    value["dispositions"][-1].update(disposition="blocked", blocker_keys=["disposition"])
    with pytest.raises(firmware_chain.FirmwareChainError, match="does not affect its finding"):
        validate(graph_case, value)

    value = copy.deepcopy(graph_case[3])
    members = value["chains"][0]["member_ids"]
    value["blockers"] = [{
        "blocker_key": "wrong-edge",
        "question": "Does another primitive persist?",
        "settling_observation": "Observe the unrelated primitive",
        "method": "hardware",
        "axes": ["lifecycle"],
        "affected_finding_ids": [],
        "affected_edges": [{"chain_key": "a", "ordinal": 1}],
    }]
    value["chains"][0]["edges"][0]["blocker_keys"] = ["wrong-edge"]
    with pytest.raises(firmware_chain.FirmwareChainError, match="does not affect this edge"):
        validate(graph_case, value)
    assert len(members) == 3


def test_validation_normalizes_unexpected_input_failures(graph_case, monkeypatch):
    graph = parsed(graph_case)
    monkeypatch.setattr(results, "_prepared_evidence", lambda *args: (_ for _ in ()).throw(ValueError("bad evidence")))
    with pytest.raises(firmware_chain.FirmwareChainError, match="Cannot validate firmware chain evidence"):
        results.validate(graph_case[0], graph_case[1], graph)


def test_existing_receipt_cannot_switch_worklist_generation(graph_case):
    record(graph_case)
    graph = dataclasses.replace(parsed(graph_case), worklist_sha256="0" * 64)
    with pytest.raises(firmware_chain.FirmwareChainError, match="different generation ownership"):
        results._publication_state(graph_case[0], graph, replace=True)


def test_completion_reconstructs_missing_run_timestamps_and_canonical_result(graph_case, monkeypatch):
    con, run = graph_case[:2]
    imported = record(graph_case)

    receipt = rows(con, "cba_firmware_chain_receipts")[0]
    receipt["recorded_at"] = ""
    table = "cba_firmware_chain_receipts"
    spec = db.TABLE_SPECS[table]
    monkeypatch.setitem(db.TABLE_SPECS, table, dataclasses.replace(spec, validate=lambda row: None))
    with pytest.raises(firmware_chain.FirmwareChainError, match="evidence timestamp"):
        firmware_chain._checked_rows([receipt], [], table)
    monkeypatch.setitem(db.TABLE_SPECS, table, spec)

    run_row = rows(con, "cba_firmware_chain_runs")[0]
    con.execute("DELETE FROM cba_firmware_chain_runs WHERE image_id='target'")
    con.commit()
    with pytest.raises(firmware_chain.FirmwareChainError, match="One prepared firmware chain generation"):
        check(graph_case)
    db.put(con, "cba_firmware_chain_runs", run_row)

    con.execute("UPDATE cba_firmware_chain_runs SET prepared_at='' WHERE image_id='target'")
    con.commit()
    table = "cba_firmware_chain_runs"
    spec = db.TABLE_SPECS[table]
    monkeypatch.setitem(db.TABLE_SPECS, table, dataclasses.replace(spec, validate=lambda row: None))
    with pytest.raises(firmware_chain.FirmwareChainError, match="preparation timestamp"):
        check(graph_case)
    monkeypatch.setitem(db.TABLE_SPECS, table, spec)
    con.execute("UPDATE cba_firmware_chain_runs SET prepared_at=? WHERE image_id='target'", (run_row["prepared_at"],))
    con.commit()

    canonical = pathlib.Path(imported.artifact_path).read_bytes()
    noncanonical = json.dumps(json.loads(canonical), ensure_ascii=False, indent=2).encode()
    digest = hashlib.sha256(noncanonical).hexdigest()
    destination = run / "artifacts/firmware-chain" / graph_case[3]["worklist_sha256"] / digest
    surface.atomic_install(destination, {"result.json": noncanonical})
    con.execute(
        "UPDATE cba_firmware_chain_receipts SET result_path=?,result_sha256=? WHERE image_id='target'",
        (str(destination / "result.json"), digest),
    )
    con.commit()
    with pytest.raises(firmware_chain.FirmwareChainError, match="result bytes are not canonical"):
        check(graph_case)


def test_missing_review_row_timestamp_forces_real_republication(completed_with_sibling):
    con, run = completed_with_sibling[:2]
    receipt_path = con.execute(
        "SELECT result_path FROM cba_firmware_fp_receipts WHERE image_id='target' LIMIT 1"
    ).fetchone()[0]
    con.execute(
        "UPDATE cba_firmware_fp_verdicts SET reviewed_at='' WHERE image_id='target' AND rowid=("
        "SELECT rowid FROM cba_firmware_fp_verdicts WHERE image_id='target' LIMIT 1)"
    )
    con.commit()
    firmware_fpcheck_results.record(con, run, receipt_path, replace=True)
    assert rows(con, "cba_firmware_chain_runs") == []
