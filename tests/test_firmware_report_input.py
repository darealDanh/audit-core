"""Deterministic Stage 4j assignment seeds, evidence and generations."""
import dataclasses
import hashlib
import json

import pytest

from audit_core import firmware_decide as decide
from audit_core import firmware_dive as dive
from audit_core import firmware_dive_questions as dive_questions
from audit_core import firmware_dive_results as dive_results
from audit_core import firmware_report as report
from tests.test_firmware_decide_package import completed_pipeline  # noqa: F401
from tests.test_firmware_decide_input import decision_case, graph_case, prepared  # noqa: F401


@pytest.fixture
def package(completed_pipeline):
    pipeline, _ = completed_pipeline
    return decide.verified_package(*pipeline[0][:3], image_id="target")


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def without_storage(value):
    return {key: item for key, item in dataclasses.asdict(value).items()
            if key != "artifact_path"}


def storage_values(value, found=None):
    """Every string anywhere in a seed that names run storage."""
    found = [] if found is None else found
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "artifact_path":
                found.append(key)
            storage_values(item, found)
    elif isinstance(value, list):
        for item in value:
            storage_values(item, found)
    elif isinstance(value, str) and (value.startswith("files/")
                                     or value.startswith("artifacts/")):
        found.append(value)
    return found


def test_assignment_seed_has_exact_shape_rank_order_and_upstream_projections(package):
    seed, = report._assignment_seeds(package)
    assessment, = package.result.chain_assessments
    chain, = package.technical_input.graph.chains
    assert tuple(seed) == (
        "schema_version", "image", "decision", "ordinal", "chain", "members",
        "edges", "open_preconditions", "evidence_catalog", "style_contract_sha256")
    assert seed["schema_version"] == 1
    assert seed["image"] == dataclasses.asdict(package.image)
    assert seed["decision"] == {
        "generation": package.decision_generation,
        "package_sha256": package.package_sha256,
        "decision": package.decision,
        "primary_reason": package.primary_reason,
    }
    assert seed["ordinal"] == 1
    assert seed["chain"] == {
        "chain_id": chain.chain_id, "rank": assessment.rank,
        "title": chain.title, "summary": chain.summary,
        "member_ids": list(chain.member_ids), "pre_auth": assessment.pre_auth,
        "confidence": assessment.confidence,
        "completeness": assessment.completeness,
        "evidence_rung": assessment.evidence_rung,
        "disposition": assessment.disposition,
        "rationale": assessment.rationale,
        "limitations": list(assessment.limitations),
    }
    findings = {item.finding_id: item for item in package.technical_input.graph.findings}
    assert seed["members"] == [without_storage(findings[item]) for item in chain.member_ids]
    assert seed["edges"] == [without_storage(item) for item in
                              package.technical_input.graph.edges]
    assert seed["open_preconditions"] == [dataclasses.asdict(item) for item in
                                           assessment.open_preconditions]
    assert all("artifact_path" not in item for item in seed["members"] + seed["edges"])
    assert all(item["artifact_sha256"] for item in seed["members"] + seed["edges"])
    assert storage_values(seed) == []
    encoded = canonical(seed).decode()
    for forbidden in ('"report_generation"', '"assignment_path"', '"result_path"',
                      '"artifact_path"'):
        assert forbidden not in encoded


def test_catalog_projects_exact_finding_surface_edge_and_assessment_evidence(package):
    seed, = report._assignment_seeds(package)
    catalog = seed["evidence_catalog"]
    refs = [item["ref"] for item in catalog]
    assert refs == sorted(set(refs))
    chain = package.technical_input.graph.chains[0]
    finding = next(item for item in package.technical_input.graph.findings
                   if item.finding_id == chain.member_ids[0])
    root = next(item for item in catalog
                if item["ref"] == f"finding:{finding.finding_id}#root_cause")
    assert root == {
        "ref": f"finding:{finding.finding_id}#root_cause", "kind": "finding",
        "owner_id": finding.finding_id, "component_path": finding.component_paths[0],
        "location": None, "field": "root_cause",
        "evidence_rung": finding.evidence_rung, "excerpt": finding.root_cause,
    }
    surface = package.technical_input.graph.surfaces[0]
    reach = next(item for item in catalog
                 if item["ref"] == f"surface:{surface.surface_id}#reach_evidence")
    assert reach["kind"] == "edge" and reach["owner_id"] == surface.surface_id
    assert reach["component_path"] == surface.component_path
    assert reach["location"] == surface.handler
    assert reach["excerpt"] == surface.reach_evidence
    assert set(package.result.chain_assessments[0].evidence_refs) <= set(refs)
    assert all(len(item["excerpt"].encode()) <= 4096 for item in catalog)


def test_generation_is_recomputed_from_ordered_seed_hashes_and_image_identity(package):
    seeds = report._assignment_seeds(package)
    expected = hashlib.sha256(canonical({
        "schema_version": 1,
        "decision_package_sha256": package.package_sha256,
        "image": dataclasses.asdict(package.image),
        "style_contract_sha256": report._style_contract_sha256(),
        "assignment_seed_sha256s": [hashlib.sha256(canonical(seed)).hexdigest()
                                    for seed in seeds],
    })).hexdigest()
    assert report._generation(package, seeds) == expected
    changed = dataclasses.replace(package, image=dataclasses.replace(
        package.image, version=package.image.version + "-changed"))
    assert report._generation(changed, report._assignment_seeds(changed)) != expected


def test_many_chains_keep_all_205_contiguous_ordinals_and_stable_display_ids(package):
    assessment = package.result.chain_assessments[0]
    chain = package.technical_input.graph.chains[0]
    edges = tuple(item for item in package.technical_input.graph.edges
                  if item.chain_id == chain.chain_id)
    assessments = tuple(dataclasses.replace(
        assessment, chain_id=f"chain-{index:03}", rank=206-index)
        for index in range(1, 206))
    chains = tuple(dataclasses.replace(chain, chain_id=item.chain_id)
                   for item in assessments)
    all_edges = tuple(dataclasses.replace(edge, chain_id=item.chain_id)
                      for item in assessments for edge in edges)
    result = dataclasses.replace(package.result, chain_assessments=assessments)
    graph = dataclasses.replace(package.technical_input.graph,
                                chains=chains, edges=all_edges)
    many = dataclasses.replace(
        package, result=result,
        technical_input=dataclasses.replace(package.technical_input, graph=graph))
    seeds = report._assignment_seeds(many)
    assert len(seeds) == 205
    assert [seed["ordinal"] for seed in seeds] == list(range(1, 206))
    assert [seed["chain"]["rank"] for seed in seeds] == list(range(1, 206))
    assert [seed["chain"]["chain_id"] for seed in seeds] == [
        f"chain-{index:03}" for index in range(205, 0, -1)]


def test_zero_chain_generation_and_manifest_are_canonical(package):
    result = dataclasses.replace(package.result, chain_assessments=())
    graph = dataclasses.replace(package.technical_input.graph, chains=(), edges=())
    empty = dataclasses.replace(
        package, result=result,
        technical_input=dataclasses.replace(package.technical_input, graph=graph))
    seeds = report._assignment_seeds(empty)
    generation = report._generation(empty, seeds)
    manifest = report._manifest(empty, generation, ())
    assert seeds == ()
    assert manifest == {
        "schema_version": 1, "image_id": package.image_id,
        "report_generation": generation,
        "decision_generation": package.decision_generation,
        "decision_package_sha256": package.package_sha256,
        "style_contract_sha256": report._style_contract_sha256(),
        "item_count": 0, "items": [],
    }


def test_catalog_projects_cited_dive_observations_with_effect_predicate(package):
    effect = dive_results.ResolutionEffect(
        dive_questions.SubjectRef("chain", package.result.chain_assessments[0].chain_id),
        "state-assertion", "Handler accepts unauthenticated requests.",
        "authentication", "pre-auth", None, None, None)
    observation = dive.CurrentDiveObservation(
        "a" * 64, "question-1", ("chain:x",), (), "supported", effect,
        "static-resolved", (), ())
    assessment = dataclasses.replace(
        package.result.chain_assessments[0],
        evidence_refs=("dive:" + "a" * 64 + "#conclusion",
                       "dive:" + "a" * 64 + "#evidence"))
    overlay = dataclasses.replace(package.technical_input.dive.overlay,
                                  observations=(observation,))
    cited = dataclasses.replace(
        package,
        result=dataclasses.replace(package.result, chain_assessments=(assessment,)),
        technical_input=dataclasses.replace(
            package.technical_input,
            dive=dataclasses.replace(package.technical_input.dive, overlay=overlay)))
    seed, = report._assignment_seeds(cited)
    catalog = {item["ref"]: item for item in seed["evidence_catalog"]}
    assert catalog["dive:" + "a" * 64 + "#conclusion"] == {
        "ref": "dive:" + "a" * 64 + "#conclusion", "kind": "observation",
        "owner_id": "a" * 64, "component_path": None, "location": None,
        "field": "conclusion", "evidence_rung": "static-resolved",
        "excerpt": "supported",
    }
    assert catalog["dive:" + "a" * 64 + "#evidence"]["excerpt"] == (
        "Handler accepts unauthenticated requests.")
    assert catalog["dive:" + "a" * 64 + "#evidence"]["kind"] == "observation"
    absent = dataclasses.replace(
        cited, technical_input=dataclasses.replace(
            cited.technical_input,
            dive=dataclasses.replace(cited.technical_input.dive,
                                     overlay=dataclasses.replace(overlay, observations=()))))
    with pytest.raises(report.FirmwareReportError, match="absent dive observation"):
        report._assignment_seeds(absent)


def test_catalog_excerpt_is_cut_on_a_character_boundary_at_four_kibibytes(package):
    long_text = "\u20ac" * 2000
    findings = tuple(
        dataclasses.replace(item, root_cause=long_text) if
        item.finding_id == package.technical_input.graph.chains[0].member_ids[0]
        else item
        for item in package.technical_input.graph.findings)
    oversized = dataclasses.replace(
        package, technical_input=dataclasses.replace(
            package.technical_input,
            graph=dataclasses.replace(package.technical_input.graph,
                                      findings=findings)))
    seed, = report._assignment_seeds(oversized)
    member = package.technical_input.graph.chains[0].member_ids[0]
    entry = next(item for item in seed["evidence_catalog"]
                 if item["ref"] == f"finding:{member}#root_cause")
    assert len(entry["excerpt"].encode()) == 4095
    assert entry["excerpt"] == long_text[:1365]
    assert canonical(seed)


def test_canonical_refuses_values_that_cannot_be_serialized():
    with pytest.raises(report.FirmwareReportError, match="canonicalized"):
        report._canonical({"value": float("nan")})
    with pytest.raises(report.FirmwareReportError, match="canonicalized"):
        report._canonical({"value": object()})
