"""Freeze, reconstruct, and complete provenance-bound static firmware chains."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import sqlite3

from audit_core import db, firmware_fpcheck, surface


class FirmwareChainError(Exception):
    """Firmware chain provenance or publication cannot be established."""


# The results parser imports FirmwareChainError. Bind its module only after
# that exception exists, while keeping public record annotations resolvable.
from audit_core import firmware_chain_results


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    candidate_snapshot_sha256: str
    generation: str
    worklist_path: str
    worklist_sha256: str
    finding_count: int
    surface_count: int
    unknown_count: int
    pivot_count: int


def _worklist(snapshot: firmware_fpcheck.VerifiedFirmwareFindingsSnapshot, overlay=None, *, legacy=False) -> bytes:
    """Preserve the complete verified input with context-only pivots, without caps."""
    projection = dataclasses.asdict(snapshot)
    projection["schema_version"] = 1
    if not legacy:
        projection["dive_overlay"] = _checked_overlay(overlay if overlay is not None else dict(schema_version=1, observations=[]))
    for collection, identifier in (("findings", "finding_id"), ("surfaces", "surface_id"),
                                   ("unknowns", "id"), ("pivots", "pivot_id")):
        projection[collection] = sorted(projection[collection], key=lambda row: row[identifier])
    projection["pivots"] = [row | {"context_only": True} for row in projection["pivots"]]
    return surface.canonical_bytes(projection)


def _checked_overlay(value) -> dict:
    """Strict additive-v1 wire; historical graphs freeze, never refresh, this value."""
    from audit_core import firmware_dive as dive, firmware_dive_questions as q, firmware_dive_results as results

    try:
        body = q._object(value, dive.CurrentDiveOverlay)
        if type(body['schema_version']) is not int or body['schema_version'] != 1 or not isinstance(body['observations'], list):
            raise ValueError('Invalid overlay schema')
        identities = []
        for raw in body['observations']:
            row = q._object(raw, dive.CurrentDiveObservation)
            identities.append(q._digest(row['observation_id']))
            q._digest(row['question_id'])
            subjects = q._subjects(row['subject_refs'])
            settled = q._subjects(row['settled_subject_refs']) if row['settled_subject_refs'] else ()
            if any(ref not in subjects or ref.kind not in ('chain-blocker', 'surface-unknown') for ref in settled):
                raise ValueError('Invalid overlay settlement authority')
            q._enum(row['outcome'], ('supported', 'refuted'))
            q._enum(row['evidence_rung'], db.FIRMWARE_DIVE_EVIDENCE_RUNGS)
            effect = results._effect(row['resolution_effect'])
            if effect is None or effect.target_subject not in subjects or (row['outcome'] == 'refuted' and effect.mode != 'boolean-claim'):
                raise ValueError('Invalid overlay resolution authority')
            for key in ('dependency_refs', 'evidence_refs'):
                q._canonical(row[key], key, minimum=1)
                for ref in row[key]: q._digest(ref)
        if identities != sorted(set(identities)):
            raise ValueError('Duplicate or unordered overlay observations')
        return body
    except (ValueError, TypeError, KeyError) as exc:
        raise FirmwareChainError('Invalid frozen dive overlay') from exc


def _current_overlay(con, run_dir, root, snapshot) -> dict:
    from audit_core import firmware_dive as dive, firmware_dive_questions as q

    try:
        return _checked_overlay(q._wire(dive.current_overlay(con, run_dir, root, snapshot)))
    except dive.FirmwareDiveError as exc:
        raise FirmwareChainError('Cannot verify current chain dive overlay') from exc


def _retained_worklist_overlay(run_dir, snapshot, worklist_sha256):
    """Recover exact historical authority, with a pre-overlay hash fallback only."""
    results = firmware_chain_results
    if hashlib.sha256(_worklist(snapshot, legacy=True)).hexdigest() == worklist_sha256:
        return None
    retained = results._retained_bytes(run_dir,
        'files/firmware-chain/' + worklist_sha256 + '/worklist.json', worklist_sha256)
    frozen = json.loads(retained, object_pairs_hook=results._pairs, parse_constant=results._constant)
    legacy = 'dive_overlay' not in frozen
    overlay = None if legacy else _checked_overlay(frozen['dive_overlay'])
    if _worklist(snapshot, overlay, legacy=legacy) != retained:
        raise FirmwareChainError('Retained worklist differs from verified review')
    return overlay


def invalidate(con: sqlite3.Connection, image_id: str, *, commit: bool = False) -> None:
    """Delete exactly one image's six Stage 4g tables in dependency order."""
    for table in ("cba_firmware_chain_edges", "cba_firmware_chains", "cba_firmware_chain_dispositions",
                  "cba_firmware_chain_unknowns", "cba_firmware_chain_receipts", "cba_firmware_chain_runs"):
        con.execute(f"DELETE FROM {table} WHERE image_id=?", (image_id,))
    if commit:
        con.commit()


def _installation_parents(destination: pathlib.Path) -> None:
    """Reject redirected or non-directory generation parents before any install."""
    for directory in tuple(destination.parents)[:3]:
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise FirmwareChainError("Invalid firmware chain installation parent")


def _checked_install(destination: pathlib.Path, content: bytes) -> None:
    """Re-read installed bytes and directory ownership under the publication lock."""
    _installation_parents(destination)
    if destination.is_symlink() or not destination.is_dir():
        raise FirmwareChainError("Invalid installed firmware chain worklist directory")
    if {path.name for path in destination.iterdir()} != {"worklist.json"}:
        raise FirmwareChainError("Installed firmware chain generation has different artifacts")
    path = destination / "worklist.json"
    if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
        raise FirmwareChainError("Installed firmware chain worklist differs before publication")


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None) -> PreparationSummary:
    """Install one global worklist, then lock and reverify before pending publication.

    Byte-identical preparation retains all imported/completed state and timestamps.
    Artifact publication precedes SQL: a failed transaction can leave only an
    unreferenced immutable worklist, never a partially replaced selected image.
    """
    started = False
    try:
        if con.in_transaction:
            raise FirmwareChainError("Preparation requires a connection without an active transaction")
        run_dir = pathlib.Path(run_dir).absolute()
        snapshot = firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, image_id=image_id)
        prior = surface._query(con, "SELECT * FROM cba_firmware_chain_runs WHERE image_id=?", (snapshot.image_id,))
        overlay = _current_overlay(con, run_dir, root, snapshot)
        content = _worklist(snapshot, overlay)
        digest = hashlib.sha256(content).hexdigest()
        destination = run_dir / "files/firmware-chain" / digest
        summary = PreparationSummary(snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256,
            snapshot.candidate_snapshot_sha256, digest, str(destination / "worklist.json"), digest,
            len(snapshot.findings), len(snapshot.surfaces), len(snapshot.unknowns), len(snapshot.pivots))
        record = {key: value for key, value in dataclasses.asdict(summary).items() if key != "generation"}
        record.update(fpcheck_artifact_path=str(run_dir / snapshot.findings_artifact_path),
                      fpcheck_artifact_sha256=snapshot.findings_artifact_sha256)
        same = len(prior) == 1 and all(prior[0][key] == value for key, value in record.items())
        _installation_parents(destination)
        surface.atomic_install(destination, {"worklist.json": content})
        con.execute("BEGIN IMMEDIATE")
        started = True
        if (firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, image_id=image_id) != snapshot or
                surface._query(con, "SELECT * FROM cba_firmware_chain_runs WHERE image_id=?", (snapshot.image_id,)) != prior or
                _current_overlay(con, run_dir, root, snapshot) != overlay):
            raise FirmwareChainError("Firmware chain inputs changed before publication")
        _checked_install(destination, content)
        if not same:
            invalidate(con, snapshot.image_id)
            db.put(con, "cba_firmware_chain_runs", record | {"status": "pending"}, commit=False)
        con.commit()
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise FirmwareChainError("database operation failed") from exc
        if isinstance(exc, (OSError, firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            raise FirmwareChainError(f"Cannot prepare firmware chain: {exc}") from exc
        raise


@dataclasses.dataclass(frozen=True, slots=True)
class ChainSummary:
    chain_id: str
    member_count: int
    edge_count: int
    completeness: str
    pre_auth: str
    confidence: int


@dataclasses.dataclass(frozen=True, slots=True)
class FirmwareChainSummary:
    image_id: str
    finding_count: int
    disposition_count: int
    blocker_count: int
    complete_chains: int
    blocked_chains: int
    chains: tuple[ChainSummary, ...]
    artifact_path: str
    complete: bool


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareDisposition:
    image_id: str
    finding_id: str
    candidate_snapshot_sha256: str
    disposition: str
    explanation: str
    chain_ids: tuple[str, ...]
    existing_unknown_ids: tuple[str, ...]
    blocker_ids: tuple[str, ...]
    pivot_followup_ids: tuple[str, ...]
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareAffectedEdge:
    chain_id: str
    ordinal: int


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareBlocker:
    image_id: str
    blocker_id: str
    candidate_snapshot_sha256: str
    question: str
    settling_observation: str
    method: str
    axes: tuple[str, ...]
    affected_finding_ids: tuple[str, ...]
    affected_edges: tuple[VerifiedFirmwareAffectedEdge, ...]
    status: str
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareChain:
    image_id: str
    chain_id: str
    candidate_snapshot_sha256: str
    title: str
    summary: str
    member_ids: tuple[str, ...]
    initial_attacker_position: str
    initial_evidence_refs: tuple[str, ...]
    initial_lifecycle: str
    initial_posture: str
    initial_authentication: str
    pre_auth: str
    confidence: int
    completeness: str
    existing_unknown_ids: tuple[str, ...]
    blocker_ids: tuple[str, ...]
    evidence_rung: str
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareEdge:
    image_id: str
    chain_id: str
    ordinal: int
    candidate_snapshot_sha256: str
    producer_finding_id: str
    consumer_finding_id: str
    capability_kind: str
    link_key: str
    produced_capability: str
    required_precondition: str
    producer_evidence_refs: tuple[str, ...]
    consumer_evidence_refs: tuple[str, ...]
    supplemental_evidence_refs: tuple[str, ...]
    required_state: firmware_chain_results.State
    result_state: firmware_chain_results.State
    transition_kind: str
    confidence: int
    existing_unknowns: tuple[firmware_chain_results.ExistingUnknownRef, ...]
    blocker_ids: tuple[str, ...]
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareGraphSnapshot:
    image_id: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    candidate_snapshot_sha256: str
    chain_worklist_sha256: str
    graph_path: str
    graph_sha256: str
    findings: tuple[firmware_fpcheck.VerifiedFirmwareFinding, ...]
    dispositions: tuple[VerifiedFirmwareDisposition, ...]
    blockers: tuple[VerifiedFirmwareBlocker, ...]
    chains: tuple[VerifiedFirmwareChain, ...]
    edges: tuple[VerifiedFirmwareEdge, ...]
    surfaces: tuple[firmware_fpcheck.VerifiedFirmwareSurface, ...]
    unknowns: tuple[firmware_fpcheck.VerifiedFirmwareUnknown, ...]


_COMPLETION_TABLES = ("cba_firmware_chain_runs", "cba_firmware_chain_receipts",
    "cba_firmware_chain_dispositions", "cba_firmware_chain_unknowns", "cba_firmware_chains",
    "cba_firmware_chain_edges")
_GRAPH_COLLECTIONS = (("dispositions", "cba_firmware_chain_dispositions"),
    ("blockers", "cba_firmware_chain_unknowns"), ("chains", "cba_firmware_chains"),
    ("edges", "cba_firmware_chain_edges"))
_GRAPH_JSON_FIELDS = frozenset(("chain_ids", "existing_unknown_ids", "blocker_ids", "pivot_followup_ids",
    "axes", "affected_finding_ids", "affected_edges", "member_ids", "initial_evidence_refs",
    "producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs", "required_state",
    "result_state", "existing_unknowns"))


def _ordered_records(records, table: str) -> list[dict]:
    rows = [dataclasses.asdict(record) for record in records]
    return sorted(rows, key=lambda row: tuple(row[key] for key in db.TABLE_SPECS[table].primary_key))


def _checked_rows(stored: list[dict], expected: list[dict], table: str) -> None:
    """Require the entire denominator, including ownership and nonempty timestamps."""
    timestamp = "derived_at" if table in ("cba_firmware_chains", "cba_firmware_chain_edges") else "recorded_at"
    for row in stored:
        db.TABLE_SPECS[table].validate(row)
        if not isinstance(row[timestamp], str) or not row[timestamp].strip():
            raise FirmwareChainError("Firmware chain evidence timestamp is missing")
    if [{key: value for key, value in row.items() if key != timestamp} for row in stored] != expected:
        raise FirmwareChainError("Firmware chain rows differ from canonical result derivation")


def _checked_graph_install(run_dir: pathlib.Path, destination: pathlib.Path, content: bytes) -> None:
    from audit_core import firmware_chain_results as results

    results._result_directories(run_dir, destination)
    if not destination.is_dir() or {path.name for path in destination.iterdir()} != {"chains.json"}:
        raise FirmwareChainError("Installed firmware chain graph has different artifacts")
    path = destination / "chains.json"
    if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
        raise FirmwareChainError("Installed firmware chain graph differs before completion")


def _verified_graph(snapshot, parsed, result_sha256: str, overlay=None) -> tuple:
    """Derive one canonical graph from verified Stage 4f evidence, without SQL.

    Historical worklist/result digests are retained provenance. In particular,
    a later dive overlay may change the worklist without changing Stage 4f.
    """
    from audit_core import firmware_chain_results as results

    results._digest(result_sha256, "result_sha256")
    if (parsed.image_id, parsed.candidate_snapshot_sha256) != (snapshot.image_id, snapshot.candidate_snapshot_sha256):
        raise FirmwareChainError("Firmware chain graph differs from verified review ownership")
    validated = results._validate_graph(parsed, json.loads(_worklist(snapshot, overlay)))
    graph = dict(schema_version=1, image_id=snapshot.image_id,
        candidate_snapshot_sha256=snapshot.candidate_snapshot_sha256,
        worklist_sha256=parsed.worklist_sha256, result_sha256=result_sha256)
    for collection, table in _GRAPH_COLLECTIONS:
        graph[collection] = [{key: json.loads(value) if key in _GRAPH_JSON_FIELDS else value
            for key, value in row.items()} for row in _ordered_records(getattr(validated, collection), table)]
    return validated, surface.canonical_bytes(graph)


def _graph_result(graph: dict):
    """Reverse the published projection through the existing hostile parser.

    Stable IDs can stand in for worker-local keys: semantic identities exclude
    those keys. Re-deriving the full projection then proves every stored field,
    including stable IDs, coverage, transitions, references and confidence.
    """
    from audit_core import firmware_chain_results as results

    def select(row, names):
        return {name: row[name] for name in names.split()}

    blockers = [select(row, "question settling_observation method axes affected_finding_ids") | dict(
        blocker_key=row["blocker_id"], affected_edges=[dict(chain_key=edge["chain_id"], ordinal=edge["ordinal"])
            for edge in row["affected_edges"]]) for row in graph["blockers"]]
    dispositions = [select(row, "finding_id disposition explanation existing_unknown_ids pivot_followup_ids") | dict(
        chain_keys=row["chain_ids"], blocker_keys=row["blocker_ids"]) for row in graph["dispositions"]]
    chains = []
    for row in graph["chains"]:
        edges = [select(edge, "producer_finding_id consumer_finding_id capability_kind link_key produced_capability "
            "required_precondition producer_evidence_refs consumer_evidence_refs supplemental_evidence_refs "
            "required_state result_state transition_kind confidence existing_unknowns") | dict(blocker_keys=edge["blocker_ids"])
            for edge in graph["edges"] if edge["chain_id"] == row["chain_id"]]
        chains.append(select(row, "title summary member_ids initial_attacker_position initial_evidence_refs") | dict(
            chain_key=row["chain_id"], initial_state=dict(lifecycle=row["initial_lifecycle"],
                posture=row["initial_posture"], authentication=row["initial_authentication"]), edges=edges))
    return results._parse(select(graph, "schema_version image_id candidate_snapshot_sha256 worklist_sha256") |
        dict(blockers=blockers, dispositions=dispositions, chains=chains))


def _graph_snapshot(snapshot, validated, relative: str, digest: str) -> VerifiedFirmwareGraphSnapshot:
    """Freeze every semantic cell; chains.json owns every projected graph row."""
    from audit_core import firmware_chain_results as results

    def record(cls, row):
        fields = dict(row)
        for name in _GRAPH_JSON_FIELDS & fields.keys():
            value = json.loads(fields[name])
            if name in ("required_state", "result_state"):
                value = results.State(**value)
            elif name == "affected_edges":
                value = tuple(VerifiedFirmwareAffectedEdge(**edge) for edge in value)
            elif name == "existing_unknowns":
                value = tuple(results.ExistingUnknownRef(ref["unknown_id"], tuple(ref["axes"])) for ref in value)
            else:
                value = tuple(value)
            fields[name] = value
        return cls(**fields, artifact_path=relative, artifact_sha256=digest)

    collections = [tuple(record(cls, row) for row in _ordered_records(getattr(validated, name), table))
        for (name, table), cls in zip(_GRAPH_COLLECTIONS, (VerifiedFirmwareDisposition,
            VerifiedFirmwareBlocker, VerifiedFirmwareChain, VerifiedFirmwareEdge))]
    return VerifiedFirmwareGraphSnapshot(snapshot.image_id, snapshot.manifest_sha256, snapshot.surface_snapshot_sha256,
        snapshot.candidate_snapshot_sha256, validated.result.worklist_sha256, relative, digest,
        snapshot.findings, *collections, snapshot.surfaces, snapshot.unknowns)


def verified_graph_snapshot(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
                            *, image_id: str | None = None) -> VerifiedFirmwareGraphSnapshot:
    """Read one verified *current completed* Stage 4g publication, never repair it.

    An owned read transaction spans all upstream and graph reads. Caller-owned
    transactions and read-only connections work unchanged. Retained dive history
    is deliberately inaccessible from this public current-generation boundary.
    """
    owned = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        run_dir = pathlib.Path(run_dir).absolute()
        snapshot, prior, validated, _, destination, digest = _completion_evidence(con, run_dir, root, image_id)
        if prior["cba_firmware_chain_runs"][0]["status"] != "complete":
            raise FirmwareChainError("Firmware chain run must already be complete")
        return _graph_snapshot(snapshot, validated, (destination / "chains.json").relative_to(run_dir).as_posix(), digest)
    except (sqlite3.Error, db.DbError, OSError, ValueError, KeyError, TypeError,
            firmware_fpcheck.FpcheckError, surface.SurfaceError) as exc:
        raise FirmwareChainError("Cannot verify firmware chain snapshot") from exc
    finally:
        if owned:
            con.rollback()


def verified_retained_graph_snapshot(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
        *, image_id: str, dive_generation: str) -> VerifiedFirmwareGraphSnapshot:
    """Verify exactly one dive-owned graph after Stage 4g SQL invalidation.

    This explicit historical boundary is for conflict preparation. The stored
    dive row owns the graph's canonical path/hash and upstream provenance; live
    Stage 4f/source evidence must still reconstruct. No Stage 4g rows or worker
    files are required, and this function never substitutes for a current graph.
    """
    from audit_core import firmware_chain_results as results

    owned = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        run_dir = pathlib.Path(run_dir).absolute()
        runs = surface._query(con, "SELECT * FROM cba_firmware_dive_runs WHERE image_id=? AND dive_generation=?",
            (image_id, dive_generation))
        if len(runs) != 1:
            raise FirmwareChainError("Exactly one owning firmware dive generation is required")
        owner = runs[0]
        db.TABLE_SPECS["cba_firmware_dive_runs"].validate(owner)
        if not isinstance(owner["prepared_at"], str) or not owner["prepared_at"].strip():
            raise FirmwareChainError("Firmware dive preparation timestamp is missing")
        snapshot = firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, image_id=image_id)
        if any(owner[name] != getattr(snapshot, name) for name in (
                "image_id", "manifest_sha256", "surface_snapshot_sha256", "candidate_snapshot_sha256")):
            raise FirmwareChainError("Retained graph upstream provenance differs from current verified review")
        relative, digest = owner["chain_graph_path"], owner["chain_graph_sha256"]
        content = results._retained_bytes(run_dir, relative, digest)
        graph = json.loads(content, object_pairs_hook=results._pairs, parse_constant=results._constant)
        parsed = _graph_result(graph)
        # Only an exact independently reconstructed pre-overlay hash can stand
        # in for a deleted historical worklist. Keyed worklists always retain
        # their original overlay; never refresh it through current_overlay.
        overlay = _retained_worklist_overlay(run_dir, snapshot, parsed.worklist_sha256)
        validated, expected = _verified_graph(snapshot, parsed, graph["result_sha256"], overlay)
        destination = run_dir / "artifacts/firmware-chain" / parsed.worklist_sha256 / digest
        if relative != (destination / "chains.json").relative_to(run_dir).as_posix() or content != expected:
            raise FirmwareChainError("Retained firmware graph is not its canonical owned projection")
        _checked_graph_install(run_dir, destination, expected)
        return _graph_snapshot(snapshot, validated, relative, digest)
    except (sqlite3.Error, db.DbError, OSError, ValueError, KeyError, TypeError,
            firmware_fpcheck.FpcheckError, surface.SurfaceError) as exc:
        raise FirmwareChainError("Cannot verify retained firmware chain snapshot") from exc
    finally:
        if owned:
            con.rollback()


def _completion_evidence(con, run_dir: pathlib.Path, root, image_id: str | None) -> tuple:
    """Rebuild live upstream, canonical worker bytes, and every receipt-owned row.

    A read snapshot keeps initial SQL inputs coherent. Inside the publication
    transaction this helper neither begins nor ends the caller's transaction.
    Complete status only changes the expected canonical provenance; it never
    skips reconstruction or permits missing artifacts to be repaired.
    """
    from audit_core import firmware_chain_results as results

    owned = not con.in_transaction
    if owned:
        con.execute("BEGIN")
    try:
        snapshot = firmware_fpcheck.verified_findings_snapshot(con, run_dir, root, image_id=image_id)
        prior = {}
        for table in _COMPLETION_TABLES:
            current_generation = table != "cba_firmware_chain_runs"
            clause = " AND candidate_snapshot_sha256=?" if current_generation else ""
            ownership = (snapshot.image_id, snapshot.candidate_snapshot_sha256) if current_generation else (snapshot.image_id,)
            prior[table] = surface._query(con,
                f"SELECT * FROM {table} WHERE image_id=?{clause} ORDER BY {','.join(db.TABLE_SPECS[table].primary_key)}",
                ownership)
        runs = prior["cba_firmware_chain_runs"]
        if len(runs) != 1:
            raise FirmwareChainError("One prepared firmware chain generation is required")
        run = runs[0]
        db.TABLE_SPECS["cba_firmware_chain_runs"].validate(run)
        if not isinstance(run["prepared_at"], str) or not run["prepared_at"].strip():
            raise FirmwareChainError("Firmware chain preparation timestamp is missing")
        overlay = _current_overlay(con, run_dir, root, snapshot)
        worklist = _worklist(snapshot, overlay)
        generation = hashlib.sha256(worklist).hexdigest()
        worklist_dir = run_dir / "files/firmware-chain" / generation
        expected_run = dict(image_id=snapshot.image_id, manifest_sha256=snapshot.manifest_sha256,
            surface_snapshot_sha256=snapshot.surface_snapshot_sha256,
            candidate_snapshot_sha256=snapshot.candidate_snapshot_sha256,
            fpcheck_artifact_path=str(run_dir / snapshot.findings_artifact_path),
            fpcheck_artifact_sha256=snapshot.findings_artifact_sha256,
            worklist_path=str(worklist_dir / "worklist.json"), worklist_sha256=generation,
            finding_count=len(snapshot.findings), surface_count=len(snapshot.surfaces),
            unknown_count=len(snapshot.unknowns), pivot_count=len(snapshot.pivots))
        if any(run[key] != value for key, value in expected_run.items()):
            raise FirmwareChainError("Prepared firmware chain inputs differ from live verified review")
        _checked_install(worklist_dir, worklist)
        receipts = prior["cba_firmware_chain_receipts"]
        if len(receipts) != 1:
            raise FirmwareChainError("Exactly one canonical firmware chain receipt is required")
        receipt = receipts[0]
        db.TABLE_SPECS["cba_firmware_chain_receipts"].validate(receipt)
        result_dir = run_dir / "artifacts/firmware-chain" / generation / receipt["result_sha256"]
        result_path = result_dir / "result.json"
        if receipt["result_path"] != str(result_path):
            raise FirmwareChainError("Firmware chain result path is not canonical")
        retained = results._retained_bytes(run_dir, result_path.relative_to(run_dir).as_posix(), receipt["result_sha256"])
        parsed = results.load(result_path)
        results._prepared_evidence(con, run_dir, parsed, root=root)
        content = results.canonical_bytes(parsed)
        if retained != content:
            raise FirmwareChainError("Firmware chain result bytes are not canonical")
        results._checked_result_install(run_dir, result_dir, content)
        validated, graph_content = _verified_graph(snapshot, parsed, receipt["result_sha256"], overlay)
        expected_receipt = dict(image_id=snapshot.image_id, candidate_snapshot_sha256=snapshot.candidate_snapshot_sha256,
            worklist_sha256=generation, result_path=str(result_path), result_sha256=hashlib.sha256(content).hexdigest(),
            disposition_count=len(validated.dispositions), blocker_count=len(validated.blockers),
            chain_count=len(validated.chains), edge_count=len(validated.edges))
        _checked_rows(receipts, [expected_receipt], "cba_firmware_chain_receipts")
        digest = hashlib.sha256(graph_content).hexdigest()
        destination = run_dir / "artifacts/firmware-chain" / generation / digest
        artifact_path = str(destination / "chains.json")
        complete = run["status"] == "complete"
        if complete:
            if (run["graph_path"], run["graph_sha256"]) != (artifact_path, digest):
                raise FirmwareChainError("Completed firmware chain graph ownership differs")
            _checked_graph_install(run_dir, destination, graph_content)
        for collection, table in _GRAPH_COLLECTIONS:
            canonical = complete and collection in ("chains", "edges")
            provenance = dict(artifact_path=artifact_path if canonical else str(result_path),
                              artifact_sha256=digest if canonical else receipt["result_sha256"])
            expected = [row | provenance for row in _ordered_records(getattr(validated, collection), table)]
            _checked_rows(prior[table], expected, table)
        return snapshot, prior, validated, graph_content, destination, digest
    finally:
        if owned:
            con.rollback()


def check(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
          *, image_id: str | None = None) -> FirmwareChainSummary:
    """Reconstruct and atomically complete static chains against the live root."""
    from audit_core import firmware_chain_results as results

    started = False
    try:
        if con.in_transaction:
            raise FirmwareChainError("Chain check requires a connection without an active transaction")
        run_dir = pathlib.Path(run_dir).absolute()
        evidence = _completion_evidence(con, run_dir, root, image_id)
        snapshot, prior, validated, content, destination, digest = evidence
        artifact_path = str(destination / "chains.json")
        results._result_directories(run_dir, destination)
        pending = prior["cba_firmware_chain_runs"][0]["status"] != "complete"
        if pending:
            surface.atomic_install(destination, {"chains.json": content})
        con.execute("BEGIN IMMEDIATE")
        started = True
        if _completion_evidence(con, run_dir, root, image_id) != evidence:
            raise FirmwareChainError("Firmware chain inputs changed before completion")
        _checked_graph_install(run_dir, destination, content)
        if pending:
            for table in ("cba_firmware_chain_edges", "cba_firmware_chains"):
                con.execute(f"DELETE FROM {table} WHERE image_id=? AND candidate_snapshot_sha256=?",
                            (snapshot.image_id, snapshot.candidate_snapshot_sha256))
            for collection, table in _GRAPH_COLLECTIONS[2:]:
                for row in _ordered_records(getattr(validated, collection), table):
                    db.put(con, table, row | dict(artifact_path=artifact_path, artifact_sha256=digest), commit=False)
            con.execute("UPDATE cba_firmware_chain_runs SET status='complete',graph_path=?,graph_sha256=?,"
                        "completed_at=datetime('now') WHERE image_id=?", (artifact_path, digest, snapshot.image_id))
        con.commit()
        chains = tuple(ChainSummary(row.chain_id, len(json.loads(row.member_ids)),
            sum(edge.chain_id == row.chain_id for edge in validated.edges), row.completeness, row.pre_auth,
            row.confidence) for row in sorted(validated.chains, key=lambda row: row.chain_id))
        return FirmwareChainSummary(snapshot.image_id, len(snapshot.findings), len(validated.dispositions),
            len(validated.blockers), sum(row.completeness == "complete" for row in validated.chains),
            sum(row.completeness == "blocked" for row in validated.chains), chains, artifact_path, True)
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError, FirmwareChainError,
                            firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            cause = exc
            while cause is not None:
                if isinstance(cause, (sqlite3.Error, db.DbError)):
                    raise FirmwareChainError("database operation failed") from exc
                cause = cause.__cause__
        if isinstance(exc, (OSError, firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            raise FirmwareChainError("Cannot complete firmware chain evidence") from exc
        raise
