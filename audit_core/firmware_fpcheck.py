"""Prepare immutable firmware reviews and atomically publish reviewed findings."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import sqlite3

from audit_core import db, hunt, surface


class FpcheckError(Exception):
    """Firmware review provenance or publication cannot be established."""


@dataclasses.dataclass(frozen=True, slots=True)
class BatchDescriptor:
    path: str
    sha256: str
    candidate_count: int


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    candidate_snapshot_sha256: str
    generation: str
    worklist_path: str
    worklist_sha256: str
    candidate_count: int
    batch_count: int


@dataclasses.dataclass(frozen=True, slots=True)
class FindingSummary:
    finding_id: str
    root_cause_key: str
    canonical_lane: str
    canonical_candidate_id: str
    contributor_count: int


@dataclasses.dataclass(frozen=True, slots=True)
class FpcheckSummary:
    image_id: str
    candidate_count: int
    true_positives: int
    false_positives: int
    duplicates: int
    pivots: int
    findings: tuple[FindingSummary, ...]
    artifact_path: str
    complete: bool


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareContributor:
    lane: str
    candidate_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareFinding:
    image_id: str
    finding_id: str
    candidate_snapshot_sha256: str
    root_cause_key: str
    canonical_lane: str
    canonical_candidate_id: str
    contributors: tuple[VerifiedFirmwareContributor, ...]
    lanes: tuple[str, ...]
    component_paths: tuple[str, ...]
    surface_ids: tuple[str, ...]
    title: str
    bug_class: str
    root_cause: str
    attacker_position: str
    data_flow: str
    impact_hypothesis: str
    evidence_summary: str
    confidence: int
    evidence_rung: str
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareSurface:
    image_id: str
    surface_id: str
    component_path: str
    entry_point: str
    protocol: str
    dispatch_path: str
    handler: str
    lifecycle_required: str
    posture_required: str
    auth_required: str
    reachability: str
    reach_evidence: str
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareUnknown:
    id: str
    image_id: str
    component_path: str
    surface_id: str | None
    field: str
    question: str
    settling_observation: str
    method: str
    status: str
    resolution: str | None
    evidence: str | None
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwarePivot:
    image_id: str
    pivot_id: str
    candidate_snapshot_sha256: str
    source_lane: str
    source_candidate_id: str
    component_path: str
    refuting_mechanism: str
    enabled_observation: str
    evidence: str
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareFindingsSnapshot:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    candidate_snapshot_sha256: str
    fpcheck_worklist_sha256: str
    findings_artifact_path: str
    findings_artifact_sha256: str
    findings: tuple[VerifiedFirmwareFinding, ...]
    surfaces: tuple[VerifiedFirmwareSurface, ...]
    unknowns: tuple[VerifiedFirmwareUnknown, ...]
    pivots: tuple[VerifiedFirmwarePivot, ...]


def _identity(snapshot: hunt.VerifiedHuntSnapshot) -> dict[str, object]:
    lanes = {row.lane: row.worklist_sha256 for row in snapshot.lanes}
    return {"schema_version": 1, "image_id": snapshot.image_id,
            "manifest_sha256": snapshot.manifest_sha256,
            "surface_snapshot_sha256": snapshot.surface_snapshot_sha256,
            "sink_worklist_sha256": lanes["l-sink"], "dark_worklist_sha256": lanes["l-dark"]}


def _candidate_snapshot(snapshot: hunt.VerifiedHuntSnapshot) -> bytes:
    """Preserve all verified evidence, ordered by the lane-qualified identity."""
    rows = sorted(snapshot.candidates, key=lambda row: (row.lane, row.candidate_id))
    return surface.canonical_bytes(_identity(snapshot) | {
        "candidates": [dataclasses.asdict(row) for row in rows]})


def _signature(image_id: str, candidate: hunt.VerifiedHuntCandidate) -> str:
    """Priority hint only: equality assigns a reviewer, never merges findings."""
    def normalize(value: str) -> str:
        return " ".join(value.casefold().split())

    fields = ("component_path", "bug_class", "dangerous_operation", "input_evidence",
              "data_flow", "operation_evidence")
    projection = {field: normalize(getattr(candidate, field)) for field in fields}
    projection.update(image_id=image_id, surface_ids=sorted({normalize(value) for value in candidate.surface_ids}))
    return hashlib.sha256(surface.canonical_bytes(projection)).hexdigest()


def _worklist(snapshot: hunt.VerifiedHuntSnapshot, batch_size: int) -> tuple[dict[str, bytes], str]:
    identity = _identity(snapshot) | {
        "candidate_snapshot_sha256": hashlib.sha256(_candidate_snapshot(snapshot)).hexdigest()}
    clusters: dict[str, list[dict[str, object]]] = {}
    for candidate in sorted(snapshot.candidates, key=lambda row: (row.lane, row.candidate_id)):
        signature = _signature(snapshot.image_id, candidate)
        clusters.setdefault(signature, []).append(dataclasses.asdict(candidate) | {"similarity_signature": signature})
    assignments: list[list[dict[str, object]]] = []
    pending: list[dict[str, object]] = []
    for signature in sorted(clusters):
        cluster = clusters[signature]
        if len(cluster) > 1000:
            raise FpcheckError("A firmware review cluster cannot exceed 1,000 candidates")
        if pending and len(pending) + len(cluster) > batch_size:
            assignments.append(pending)
            pending = []
        pending.extend(cluster)
    if pending or not assignments:
        assignments.append(pending)
    files = {}
    descriptors = []
    for number, assigned in enumerate(assignments, 1):
        if len(assigned) > 1000:
            raise FpcheckError("A firmware review batch cannot exceed 1,000 candidates")
        batch_id = f"batch-{number:04}"
        content = surface.canonical_bytes(identity | {"batch_id": batch_id, "candidates": assigned})
        name = batch_id + ".json"
        files[name] = content
        descriptors.append(dataclasses.asdict(BatchDescriptor(name, hashlib.sha256(content).hexdigest(), len(assigned))))
    files["index.json"] = surface.canonical_bytes(identity | {"batch_size": batch_size,
        "candidate_count": len(snapshot.candidates), "batches": descriptors})
    return files, hashlib.sha256(files["index.json"]).hexdigest()


def invalidate(con: sqlite3.Connection, image_id: str, *, commit: bool = False) -> None:
    """Delete exactly one image's Stage 4f state in the caller's transaction."""
    for table in ("cba_firmware_findings", "cba_firmware_pivots", "cba_firmware_fp_verdicts",
                  "cba_firmware_fp_receipts", "cba_firmware_fp_runs"):
        con.execute(f"DELETE FROM {table} WHERE image_id=?", (image_id,))
    if commit:
        con.commit()


def _checked_install(destination: pathlib.Path, files: dict[str, bytes]) -> None:
    """Re-read the whole installed generation while holding the publication lock."""
    for directory in (destination, *tuple(destination.parents)[:3]):
        if directory.is_symlink() or not directory.is_dir():
            raise FpcheckError("Invalid installed firmware review worklist directory")
    if {path.name for path in destination.iterdir()} != set(files):
        raise FpcheckError("Installed firmware review generation has different artifacts")
    for name, expected in files.items():
        path = destination / name
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise FpcheckError("Installed firmware review worklist differs before publication")


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None, batch_size: int = 20) -> PreparationSummary:
    """Install all assignments, reverify hunt/root under lock, publish one pending run."""
    started = False
    try:
        if con.in_transaction:
            raise FpcheckError("Preparation requires a connection without an active transaction")
        if type(batch_size) is not int or not 1 <= batch_size <= 200:
            raise FpcheckError("batch_size must be an integer from 1 to 200")
        run_dir = pathlib.Path(run_dir).absolute()
        snapshot = hunt.verified_snapshot(con, run_dir, root, image_id=image_id)
        prior = surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (snapshot.image_id,))
        files, digest = _worklist(snapshot, batch_size)
        # The index binds the snapshot AND assignment policy; changing batch size
        # cannot collide with a previously installed immutable generation.
        destination = run_dir / "files/firmware-fpcheck" / digest
        index = _identity(snapshot)
        summary = PreparationSummary(snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256,
            hashlib.sha256(_candidate_snapshot(snapshot)).hexdigest(), digest, str(destination / "index.json"),
            digest, len(snapshot.candidates), len(files) - 1)
        record = {key: value for key, value in dataclasses.asdict(summary).items() if key != "generation"}
        record.update(sink_worklist_sha256=index["sink_worklist_sha256"], dark_worklist_sha256=index["dark_worklist_sha256"])
        same = len(prior) == 1 and all(prior[0][key] == value for key, value in record.items())
        for directory in tuple(destination.parents)[:3]:
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise FpcheckError("Invalid firmware review installation parent")
        surface.atomic_install(destination, files)
        con.execute("BEGIN IMMEDIATE")
        started = True
        if (hunt.verified_snapshot(con, run_dir, root, image_id=image_id) != snapshot or
                surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (snapshot.image_id,)) != prior):
            raise FpcheckError("Firmware review inputs changed before publication")
        _checked_install(destination, files)
        if not same:
            invalidate(con, snapshot.image_id)
            db.put(con, "cba_firmware_fp_runs", record | {"status": "pending"}, commit=False)
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError, hunt.HuntError, surface.SurfaceError)):
            raise FpcheckError(f"Cannot prepare firmware review: {exc}") from exc
        raise


def _cell(value: object) -> str:
    return surface.canonical_bytes(value).decode().removesuffix("\n")


def _review_inputs(con: sqlite3.Connection, run_dir: pathlib.Path, root: str | pathlib.Path,
                   image_id: str | None) -> tuple:
    """Rebuild every receipt-owned row from current immutable review evidence."""
    from audit_core import firmware_fpcheck_results as results

    snapshot = hunt.verified_snapshot(con, run_dir, root, image_id=image_id)
    selected = snapshot.image_id
    runs = surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (selected,))
    if len(runs) != 1:
        raise FpcheckError("One prepared firmware review run is required")
    run = runs[0]
    db.TABLE_SPECS["cba_firmware_fp_runs"].validate(run)
    index_path = pathlib.Path(run["worklist_path"])
    index = results._read_json(index_path)
    if not isinstance(index, dict) or type(index.get("batch_size")) is not int or not 1 <= index["batch_size"] <= 200:
        raise FpcheckError("Invalid firmware review index")
    files, digest = _worklist(snapshot, index["batch_size"])
    expected_index = json.loads(files["index.json"])
    expected_run = {key: value for key, value in expected_index.items()
                    if key not in ("schema_version", "batch_size", "batches")}
    expected_run.update(worklist_sha256=digest, batch_count=len(files) - 1,
                        worklist_path=str(run_dir / "files/firmware-fpcheck" / digest / "index.json"))
    if any(run[key] != value for key, value in expected_run.items()):
        raise FpcheckError("Prepared review differs from current completed hunt")
    if ((run["status"] == "pending" and run["completed_at"] is not None) or
            (run["status"] == "complete" and (not isinstance(run["completed_at"], str) or not run["completed_at"].strip()))):
        raise FpcheckError("Firmware review status and completion timestamp disagree")
    _checked_install(index_path.parent, files)
    receipts = surface._query(con, "SELECT * FROM cba_firmware_fp_receipts WHERE image_id=? ORDER BY batch_path", (selected,))
    descriptors = {row["path"]: row for row in expected_index["batches"]}
    if len(receipts) != len(descriptors) or {row["batch_path"] for row in receipts} != set(descriptors):
        raise FpcheckError("Every review batch requires exactly one current receipt")
    decisions, expected_verdicts, expected_pivots = {}, {}, {}
    for receipt in receipts:
        db.TABLE_SPECS["cba_firmware_fp_receipts"].validate(receipt)
        batch = descriptors[receipt["batch_path"]]
        if (receipt["candidate_snapshot_sha256"], receipt["worklist_sha256"], receipt["batch_sha256"] ) != (
                expected_index["candidate_snapshot_sha256"], digest, batch["sha256"]):
            raise FpcheckError("Firmware review receipt has foreign provenance")
        path = pathlib.Path(receipt["result_path"])
        validated = results.validate(con, run_dir, results.load(path))
        result = validated.result
        content = results.canonical_bytes(validated)
        result_digest = hashlib.sha256(content).hexdigest()
        destination = run_dir / "artifacts/firmware-fpcheck" / digest / result_digest
        if (str(path) != str(destination / "result.json") or result_digest != receipt["result_sha256"] or
                (result.image_id, result.candidate_snapshot_sha256, result.worklist_sha256,
                 result.batch_path, result.batch_sha256) != (selected, run["candidate_snapshot_sha256"],
                 digest, receipt["batch_path"], batch["sha256"])):
            raise FpcheckError("Firmware review receipt and canonical result differ")
        results._artifact_directories(run_dir, destination)
        _checked_install(destination, {"result.json": content})
        counts = {verdict: sum(row.verdict == verdict for row in result.decisions) for verdict in db.FIRMWARE_FP_VERDICTS}
        if tuple(receipt[key] for key in ("assigned_count", "verdict_count", "true_positive_count",
                "false_positive_count", "duplicate_count", "pivot_count")) != (
                batch["candidate_count"], len(result.decisions), counts["TRUE_POSITIVE"],
                counts["FALSE_POSITIVE"], counts["DUPLICATE"], counts["FALSE_POSITIVE"]):
            raise FpcheckError("Firmware review receipt counts disagree")
        provenance = dict(image_id=selected, candidate_snapshot_sha256=run["candidate_snapshot_sha256"],
                          artifact_path=str(path), artifact_sha256=result_digest)
        for decision in result.decisions:
            identity = (decision.lane, decision.candidate_id)
            if identity in decisions:
                raise FpcheckError("Duplicate firmware review decision ownership")
            decisions[identity] = decision
            row = dict.fromkeys(db.TABLE_SPECS["cba_firmware_fp_verdicts"].columns)
            row.pop("reviewed_at")
            row.update(provenance, batch_path=result.batch_path)
            row.update({field: getattr(decision, field) for field in ("lane", "candidate_id", "verdict",
                "reason", "attacker_advantage", "mitigation_analysis", "confidence")})
            row["rules_applied"] = _cell(decision.rules_applied)
            if decision.true_positive is not None:
                variant = dataclasses.asdict(decision.true_positive)
                for field in ("attacker_position", "data_flow", "impact_hypothesis"):
                    variant["reviewed_" + field] = variant.pop(field)
                for field in ("component_paths", "surface_ids"):
                    variant[field] = _cell(variant[field])
                row.update(variant)
            elif decision.false_positive is not None:
                variant = decision.false_positive
                row.update(refuting_mechanism=variant.refuting_mechanism, pivot_id=variant.pivot_id)
                if variant.pivot_id in expected_pivots:
                    raise FpcheckError("Duplicate firmware pivot ownership")
                expected_pivots[variant.pivot_id] = provenance | dict(pivot_id=variant.pivot_id,
                    source_lane=decision.lane, source_candidate_id=decision.candidate_id,
                    component_path=variant.component_path, refuting_mechanism=variant.refuting_mechanism,
                    enabled_observation=variant.enabled_observation, evidence=variant.pivot_evidence)
            else:
                row.update(duplicate_lane=decision.duplicate.target_lane,
                    duplicate_candidate_id=decision.duplicate.target_candidate_id,
                    dedup_evidence=decision.duplicate.dedup_evidence)
            expected_verdicts[identity] = row
    if set(decisions) != {(row.lane, row.candidate_id) for row in snapshot.candidates}:
        raise FpcheckError("Review decisions do not cover the candidate snapshot")
    stored = []
    for table, expected, keys, timestamp in (
            ("cba_firmware_fp_verdicts", expected_verdicts, ("lane", "candidate_id"), "reviewed_at"),
            ("cba_firmware_pivots", expected_pivots, ("pivot_id",), "recorded_at")):
        actual_rows = surface._query(con, f"SELECT * FROM {table} WHERE image_id=? ORDER BY 1,2,3", (selected,))
        actual = {}
        for row in actual_rows:
            db.TABLE_SPECS[table].validate(row)
            identity = tuple(row[key] for key in keys) if len(keys) > 1 else row[keys[0]]
            if identity in actual:
                raise FpcheckError("Duplicate firmware review row ownership")
            actual[identity] = {key: value for key, value in row.items() if key != timestamp}
        if actual != expected:
            raise FpcheckError("Firmware review rows differ from canonical evidence")
        stored.append(actual_rows)
    findings = surface._query(con, "SELECT * FROM cba_firmware_findings WHERE image_id=? ORDER BY finding_id", (selected,))
    return snapshot, run, receipts, stored, findings, decisions


def _resolve_duplicates(decisions: dict) -> dict:
    """Resolve a functional graph iteratively with path compression, bounded by N."""
    resolved = {}
    for identity, decision in decisions.items():
        if decision.verdict == "FALSE_POSITIVE" or identity in resolved:
            continue
        path, seen, current = [], set(), identity
        while current not in resolved:
            if current in seen or current not in decisions:
                raise FpcheckError("Duplicate chain has a cycle or missing/foreign target")
            seen.add(current)
            path.append(current)
            node = decisions[current]
            if node.verdict == "TRUE_POSITIVE":
                resolved[current] = current
                break
            if node.verdict != "DUPLICATE":
                raise FpcheckError("Duplicate chain must terminate at a TRUE_POSITIVE")
            current = (node.duplicate.target_lane, node.duplicate.target_candidate_id)
        terminal = resolved[current]
        for member in path:
            resolved[member] = terminal
    return resolved


def _derive(snapshot: hunt.VerifiedHuntSnapshot, run: dict, decisions: dict) -> list[dict]:
    resolved = _resolve_duplicates(decisions)
    candidates = {(row.lane, row.candidate_id): row for row in snapshot.candidates}
    groups = {}
    for identity, terminal in resolved.items():
        key = decisions[terminal].true_positive.root_cause_key
        groups.setdefault(key, []).append(identity)
    findings = []
    for key in sorted(groups):
        members = sorted(groups[key])
        canonical = min(identity for identity in members if decisions[identity].verdict == "TRUE_POSITIVE")
        candidate, decision = candidates[canonical], decisions[canonical]
        review = decision.true_positive
        components = {candidates[identity].component_path for identity in members}
        surfaces = {surface_id for identity in members for surface_id in candidates[identity].surface_ids}
        for identity in members:
            variant = decisions[identity].true_positive
            if variant is not None:
                components.update(variant.component_paths)
                surfaces.update(variant.surface_ids)
        finding_id = "firmware-" + hashlib.sha256(surface.canonical_bytes({
            "image_id": snapshot.image_id, "candidate_snapshot_sha256": run["candidate_snapshot_sha256"],
            "root_cause_key": key})).hexdigest()
        findings.append(dict(image_id=snapshot.image_id, finding_id=finding_id,
            candidate_snapshot_sha256=run["candidate_snapshot_sha256"], root_cause_key=key,
            canonical_lane=canonical[0], canonical_candidate_id=canonical[1],
            contributors=[dict(lane=lane, candidate_id=identifier) for lane, identifier in members],
            lanes=sorted({identity[0] for identity in members}), component_paths=sorted(components),
            surface_ids=sorted(surfaces), title=candidate.title, bug_class=candidate.bug_class,
            root_cause=review.root_cause, attacker_position=review.attacker_position, data_flow=review.data_flow,
            impact_hypothesis=review.impact_hypothesis, evidence_summary=_cell(dict(reason=decision.reason,
                attacker_advantage=decision.attacker_advantage, rules_applied=decision.rules_applied,
                mitigation_analysis=decision.mitigation_analysis, dedup_evidence=review.dedup_evidence)),
            confidence=min(decisions[identity].confidence for identity in members), evidence_rung="static-reviewed"))
    return findings


def _verified_review(con: sqlite3.Connection, run_dir: pathlib.Path, root: str | pathlib.Path,
                     image_id: str | None, *, require_complete: bool = False) -> tuple:
    """Reconstruct all Stage 4f evidence; only the public check owns publication."""
    from audit_core import firmware_fpcheck_results as results

    inputs = _review_inputs(con, run_dir, root, image_id)
    snapshot, run, receipts, _, prior_findings, decisions = inputs
    if require_complete and run["status"] != "complete":
        raise FpcheckError("Firmware review run must already be complete")
    findings = _derive(snapshot, run, decisions)
    content = surface.canonical_bytes(dict(schema_version=1, image_id=snapshot.image_id,
        candidate_snapshot_sha256=run["candidate_snapshot_sha256"], worklist_sha256=run["worklist_sha256"],
        results=[dict(batch_path=row["batch_path"], result_sha256=row["result_sha256"]) for row in receipts],
        findings=findings))
    digest = hashlib.sha256(content).hexdigest()
    destination = run_dir / "artifacts/firmware-fpcheck" / run["worklist_sha256"] / digest
    artifact_path = str(destination / "findings.json")
    expected_rows = []
    for finding in findings:
        row = finding | dict(artifact_path=artifact_path, artifact_sha256=digest)
        for field in ("contributors", "lanes", "component_paths", "surface_ids"):
            row[field] = _cell(row[field])
        db.TABLE_SPECS["cba_firmware_findings"].validate(row)
        expected_rows.append(row)
    expected_rows.sort(key=lambda row: row["finding_id"])
    if run["status"] == "complete":
        if ([{key: value for key, value in row.items() if key != "derived_at"} for row in prior_findings] != expected_rows
                or any(not row["derived_at"] for row in prior_findings)):
            raise FpcheckError("Completed firmware findings differ from canonical review derivation")
        # A completed generation must already own its immutable evidence;
        # silently rebuilding a missing artifact would conceal drift.
        results._artifact_directories(run_dir, destination)
        _checked_install(destination, {"findings.json": content})
    return inputs, findings, content, expected_rows, destination, digest


def verified_findings_snapshot(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
                               *, image_id: str | None = None) -> VerifiedFirmwareFindingsSnapshot:
    """Freeze complete Stage 4f evidence read-only, including in caller transactions.

    Semantic arrays become immutable tuples. SQL timestamps are excluded and
    verified artifact descendants are returned as canonical run-relative paths.
    Pivots are context for follow-up, never reviewed findings or chain evidence.
    An owned read transaction keeps all SQL reads in the verified generation;
    existing caller transactions are neither opened nor ended here.
    """
    try:
        owned_transaction = not con.in_transaction
        if owned_transaction:
            con.execute("BEGIN")
        try:
            run_dir = pathlib.Path(run_dir).absolute()
            inputs, _, _, expected_rows, destination, digest = _verified_review(
                con, run_dir, root, image_id, require_complete=True)
            upstream, run, _, stored, _, _ = inputs

            def record(cls, row):
                fields = {field.name: row[field.name] for field in dataclasses.fields(cls)}
                fields["artifact_path"] = pathlib.Path(fields["artifact_path"]).absolute().relative_to(run_dir).as_posix()
                if cls is VerifiedFirmwareFinding:
                    fields["contributors"] = tuple(VerifiedFirmwareContributor(**value)
                        for value in json.loads(fields["contributors"]))
                    for name in ("lanes", "component_paths", "surface_ids"):
                        fields[name] = tuple(json.loads(fields[name]))
                return cls(**fields)

            findings = tuple(record(VerifiedFirmwareFinding, row) for row in expected_rows)
            surface_ids = {identifier for row in findings for identifier in row.surface_ids}
            component_paths = {path for row in findings for path in row.component_paths}
            surfaces = tuple(record(VerifiedFirmwareSurface, row) for row in surface._query(con,
                "SELECT * FROM cba_firmware_surfaces WHERE image_id=? ORDER BY surface_id", (upstream.image_id,))
                if row["surface_id"] in surface_ids)
            unknowns = tuple(record(VerifiedFirmwareUnknown, row) for row in surface._query(con,
                "SELECT * FROM cba_unknowns WHERE image_id=? ORDER BY id", (upstream.image_id,))
                if row["surface_id"] in surface_ids or row["component_path"] in component_paths)
            pivots = tuple(record(VerifiedFirmwarePivot, row) for row in sorted(stored[1], key=lambda row: row["pivot_id"]))
            return VerifiedFirmwareFindingsSnapshot(upstream.image_id, upstream.manifest_sha256,
                upstream.surface_snapshot_sha256, run["candidate_snapshot_sha256"], run["worklist_sha256"],
                (destination / "findings.json").relative_to(run_dir).as_posix(), digest,
                findings, surfaces, unknowns, pivots)
        finally:
            if owned_transaction:
                con.rollback()
    except (sqlite3.Error, OSError, ValueError, db.DbError, hunt.HuntError, surface.SurfaceError) as exc:
        raise FpcheckError("Cannot verify firmware findings snapshot") from exc


def check(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
          *, image_id: str | None = None) -> FpcheckSummary:
    """Verify all review evidence and atomically complete one static generation."""
    from audit_core import firmware_fpcheck_results as results

    started = False
    try:
        if con.in_transaction:
            raise FpcheckError("Firmware review check requires a connection without an active transaction")
        run_dir = pathlib.Path(run_dir).absolute()
        inputs, findings, content, expected_rows, destination, _ = _verified_review(con, run_dir, root, image_id)
        snapshot, run, _, _, _, decisions = inputs
        artifact_path = str(destination / "findings.json")
        results._artifact_directories(run_dir, destination)
        surface.atomic_install(destination, {"findings.json": content})
        con.execute("BEGIN IMMEDIATE")
        started = True
        if _review_inputs(con, run_dir, root, image_id) != inputs:
            raise FpcheckError("Firmware review inputs changed before completion")
        results._artifact_directories(run_dir, destination)
        _checked_install(destination, {"findings.json": content})
        if run["status"] != "complete":
            con.execute("DELETE FROM cba_firmware_findings WHERE image_id=?", (snapshot.image_id,))
            for row in expected_rows:
                db.put(con, "cba_firmware_findings", row, commit=False)
            con.execute("UPDATE cba_firmware_fp_runs SET status='complete',completed_at=datetime('now') WHERE image_id=?",
                        (snapshot.image_id,))
        con.commit()
        counts = {verdict: sum(row.verdict == verdict for row in decisions.values()) for verdict in db.FIRMWARE_FP_VERDICTS}
        return FpcheckSummary(snapshot.image_id, len(decisions), counts["TRUE_POSITIVE"], counts["FALSE_POSITIVE"],
            counts["DUPLICATE"], counts["FALSE_POSITIVE"], tuple(FindingSummary(row["finding_id"], row["root_cause_key"],
                row["canonical_lane"], row["canonical_candidate_id"], len(row["contributors"])) for row in findings),
            artifact_path, True)
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError, hunt.HuntError, surface.SurfaceError)):
            raise FpcheckError("Cannot complete firmware review") from exc
        raise
