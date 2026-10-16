"""Strict file-backed agent results and atomic, batch-owned publication."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3
import stat

from audit_core import db, surface
from audit_core.surface import SurfaceError

RESULT_SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 8 * 1024 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class SurfaceRecord:
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


@dataclasses.dataclass(frozen=True, slots=True)
class UnknownRecord:
    id: str
    component_path: str
    surface_id: str | None
    field: str
    question: str
    settling_observation: str
    method: str
    status: str
    resolution: str | None
    evidence: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class UnitDecision:
    path: str
    state: str
    reason: str | None
    surfaces: tuple[SurfaceRecord, ...]
    unknowns: tuple[UnknownRecord, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class BatchResult:
    schema_version: int
    image_id: str
    manifest_sha256: str
    worklist_sha256: str
    batch_path: str
    batch_sha256: str
    decisions: tuple[UnitDecision, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedBatch:
    result: BatchResult
    assigned_units: tuple[str, ...]
    index_path: str


@dataclasses.dataclass(frozen=True, slots=True)
class ImportSummary:
    image_id: str
    batch_path: str
    unit_count: int
    surface_count: int
    unknown_count: int
    artifact_path: str


def _object(value: object, keys: tuple[str, ...], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise SurfaceError(f"{label} must be an object with exactly these keys: {', '.join(keys)}")
    return value


def _string(value: object, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str):
        raise SurfaceError(f"{label} must be a string" + (" or null" if nullable else ""))
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise SurfaceError(f"{label} is not valid UTF-8 text") from exc


def _array(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise SurfaceError(f"{label} must be an array")
    return value


def _record(value: object, cls: type, nullable: tuple[str, ...] = ()):
    fields = tuple(field.name for field in dataclasses.fields(cls))
    row = _object(value, fields, cls.__name__)
    for name in fields:
        _string(row[name], name, nullable=name in nullable)
    return cls(**row)


def _parse(value: object) -> BatchResult:
    row = _object(value, tuple(field.name for field in dataclasses.fields(BatchResult)), "result")
    if type(row["schema_version"]) is not int or row["schema_version"] != RESULT_SCHEMA_VERSION:
        raise SurfaceError("result schema_version must be integer 1")
    for name in ("image_id", "manifest_sha256", "worklist_sha256", "batch_path", "batch_sha256"):
        _string(row[name], name)
    decisions = []
    for value in _array(row["decisions"], "decisions"):
        unit = _object(value, ("path", "state", "reason", "surfaces", "unknowns"), "decision")
        _string(unit["path"], "path")
        _string(unit["state"], "state")
        _string(unit["reason"], "reason", nullable=True)
        decisions.append(UnitDecision(unit["path"], unit["state"], unit["reason"],
            tuple(_record(item, SurfaceRecord) for item in _array(unit["surfaces"], "surfaces")),
            tuple(_record(item, UnknownRecord, ("surface_id", "resolution", "evidence"))
                  for item in _array(unit["unknowns"], "unknowns"))))
    return BatchResult(**(row | {"decisions": tuple(decisions)}))


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SurfaceError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise SurfaceError(f"Non-finite JSON value: {value}")


def _read_json(path: pathlib.Path, *, bounded: bool = False) -> tuple[bytes, object]:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise SurfaceError(f"Surface artifact must be a regular file: {path}")
        with path.open("rb") as stream:
            content = stream.read(MAX_RESULT_BYTES + 1) if bounded else stream.read()
        if bounded and len(content) > MAX_RESULT_BYTES:
            raise SurfaceError(f"Result size exceeds {MAX_RESULT_BYTES} bytes: {path}")
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        return content, value
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise SurfaceError(f"Cannot read surface JSON {path}: {exc}") from exc


def load(path: str | pathlib.Path) -> BatchResult:
    """Read at most the result limit plus one byte; reject coercions and extra keys."""
    return _parse(_read_json(pathlib.Path(path), bounded=True)[1])


def _sha(value: object, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SurfaceError(f"{label} requires exactly 64 lower-case hexadecimal characters")


def _identifier(value: str, label: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise SurfaceError(f"{label} requires a safe identifier of 1-128 characters")


def _nonempty(value: str, label: str) -> None:
    if not value.strip():
        raise SurfaceError(f"{label} requires non-empty text")


def _count(value: object, label: str, minimum: int = 1, maximum: int = 9223372036854775807) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SurfaceError(f"Invalid {label} count: {value!r}")


def _assigned(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult) -> tuple[tuple[str, ...], str]:
    """Re-establish assignment provenance from SQL and the prepared artifacts."""
    surface._resolve_target(surface._query(con, "SELECT id,role FROM cba_images"), result.image_id)
    manifest = surface._manifest(con, result.image_id)
    surface._inventory_agreement(con, result.image_id, manifest)
    digest = surface.manifest_sha256(manifest)
    runs = surface._query(con, "SELECT * FROM cba_surface_runs WHERE image_id=?", (result.image_id,))
    if not runs:
        raise SurfaceError("No prepared surface run for target")
    run = runs[0]
    if digest != result.manifest_sha256 or digest != run["manifest_sha256"]:
        raise SurfaceError("Current, prepared and result manifest provenance differs")
    if result.worklist_sha256 != run["worklist_sha256"]:
        raise SurfaceError("Result worklist provenance differs from prepared run")
    index_path = pathlib.Path(str(run["worklist_path"]))
    expected_path = run_dir / "files/surface" / result.worklist_sha256 / "index.json"
    if index_path.absolute() != expected_path.absolute():
        raise SurfaceError("Prepared worklist path is outside the current run generation")
    for path in (index_path.parent, index_path.parent.parent, index_path.parent.parent.parent):
        if path.is_symlink():
            raise SurfaceError(f"Prepared worklist directory is a symlink: {path}")
    content, index = _read_json(index_path)
    if hashlib.sha256(content).hexdigest() != result.worklist_sha256:
        raise SurfaceError("Prepared index SHA-256 differs")
    index = _object(index, ("schema_version", "image_id", "manifest_sha256", "batch_size", "unit_count", "batches"), "index")
    if (type(index["schema_version"]) is not int or index["schema_version"] != 1 or
            index["image_id"] != result.image_id or index["manifest_sha256"] != digest):
        raise SurfaceError("Prepared index provenance differs")
    _count(index["batch_size"], "batch_size", maximum=1000)
    _count(index["unit_count"], "unit_count")
    if index["unit_count"] != len(manifest) or run["unit_count"] != len(manifest):
        raise SurfaceError("Prepared manifest unit count differs")
    descriptors = _array(index["batches"], "batches")
    if len(descriptors) != run["batch_count"] or not descriptors:
        raise SurfaceError("Prepared batch count differs")
    names = set()
    total = 0
    selected = None
    for value in descriptors:
        descriptor = _object(value, ("path", "sha256", "unit_count"), "batch descriptor")
        name = descriptor["path"]
        if not isinstance(name, str) or re.fullmatch(r"batch-[0-9]{4,}\.json", name) is None or name in names:
            raise SurfaceError("Invalid or duplicate prepared batch path")
        names.add(name)
        _sha(descriptor["sha256"], "batch sha256")
        _count(descriptor["unit_count"], "batch unit_count", maximum=index["batch_size"])
        total += descriptor["unit_count"]
        if name == result.batch_path:
            selected = descriptor
    if total != len(manifest) or selected is None:
        raise SurfaceError("Prepared batch membership or total count differs")
    content, batch = _read_json(index_path.with_name(result.batch_path))
    if hashlib.sha256(content).hexdigest() != selected["sha256"] or selected["sha256"] != result.batch_sha256:
        raise SurfaceError("Prepared batch SHA-256 differs")
    batch = _object(batch, ("schema_version", "image_id", "manifest_sha256", "batch_id", "units"), "batch")
    if (type(batch["schema_version"]) is not int or batch["schema_version"] != 1 or
            batch["image_id"] != result.image_id or batch["manifest_sha256"] != digest or
            batch["batch_id"] != result.batch_path.removesuffix(".json")):
        raise SurfaceError("Prepared batch provenance differs")
    units = _array(batch["units"], "units")
    for unit in units:
        if not isinstance(unit, dict):
            raise SurfaceError("Prepared batch unit must be an object")
    assigned_manifest = surface.canonical_manifest(units)
    current = {unit["path"]: unit for unit in manifest}
    if (len(assigned_manifest) != selected["unit_count"] or
            any(current.get(unit["path"]) != unit for unit in assigned_manifest)):
        raise SurfaceError("Prepared assigned units differ from current manifest")
    return tuple(str(unit["path"]) for unit in assigned_manifest), str(index_path)


def _semantics(con: sqlite3.Connection, result: BatchResult, assigned: tuple[str, ...]) -> None:
    surfaces = {}
    unknowns = {}
    for decision in result.decisions:
        if decision.state not in db.COVERAGE_STATES:
            raise SurfaceError(f"Invalid coverage state for {decision.path}")
        if decision.state == "not_audited":
            if not decision.reason or decision.reason.strip() not in db.NOT_AUDITED_REASONS:
                raise SurfaceError(f"not_audited requires a valid reason for {decision.path}")
            if decision.surfaces:
                raise SurfaceError("not_audited cannot publish surfaces")
        elif (not decision.surfaces and not decision.unknowns and
              not (decision.reason and decision.reason.strip())):
            raise SurfaceError(f"Analyzed no-surface decision requires a retained explanation in reason: {decision.path}")
        for row in decision.surfaces:
            if row.component_path != decision.path:
                raise SurfaceError("Surface component must belong to its assigned decision")
            for field in dataclasses.fields(row):
                _nonempty(getattr(row, field.name), field.name)
            _identifier(row.surface_id, "surface_id")
            if row.surface_id in surfaces:
                raise SurfaceError(f"Duplicate surface ID: {row.surface_id}")
            surfaces[row.surface_id] = row
            for name, allowed in (("lifecycle_required", db.LIFECYCLE_STATES),
                    ("posture_required", db.POSTURE_STATES), ("auth_required", db.AUTH_STATES),
                    ("reachability", db.REACHABILITY_STATES)):
                if getattr(row, name) not in allowed:
                    raise SurfaceError(f"Invalid surface {name}")
        for row in decision.unknowns:
            if row.component_path != decision.path:
                raise SurfaceError("Unknown component must belong to its assigned decision")
            for name in ("id", "field", "question", "settling_observation", "method", "status"):
                _nonempty(getattr(row, name), name)
            _identifier(row.id, "unknown id")
            if row.surface_id is not None:
                _identifier(row.surface_id, "unknown surface_id")
            if row.id in unknowns:
                raise SurfaceError(f"Duplicate unknown ID: {row.id}")
            unknowns[row.id] = row
            if row.field not in db.UNKNOWN_FIELDS or row.method not in db.UNKNOWN_METHODS or row.status not in db.UNKNOWN_STATES:
                raise SurfaceError("Invalid unknown field, method or status")
            for name in ("resolution", "evidence"):
                present = bool(getattr(row, name) and getattr(row, name).strip())
                if present != (row.status == "resolved"):
                    raise SurfaceError(f"Unknown {row.status} requires {'non-empty' if row.status == 'resolved' else 'empty'} {name}")
    for row in unknowns.values():
        if row.surface_id is not None:
            linked = surfaces.get(row.surface_id)
            if linked is None or linked.component_path != row.component_path:
                raise SurfaceError("Unknown surface linkage is dangling or belongs to another component")
    open_fields = {(row.surface_id, row.field) for row in unknowns.values() if row.status == "open"}
    for row in surfaces.values():
        for column, field in (("lifecycle_required", "lifecycle"), ("posture_required", "posture"),
                              ("auth_required", "auth"), ("reachability", "reachability")):
            if getattr(row, column) == "unknown" and (row.surface_id, field) not in open_fields:
                raise SurfaceError(f"Unknown {field} requires a matching open unknown for {row.surface_id}")
    for row in surface._query(con, "SELECT surface_id,component_path FROM cba_firmware_surfaces WHERE image_id=?", (result.image_id,)):
        if row["surface_id"] in surfaces and row["component_path"] not in assigned:
            raise SurfaceError("Surface ID belongs to another batch")
    for row in surface._query(con, "SELECT id,image_id,component_path FROM cba_unknowns"):
        if row["id"] in unknowns and (row["image_id"] != result.image_id or row["component_path"] not in assigned):
            raise SurfaceError("Unknown ID belongs to another image or batch")


def validate(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult) -> ValidatedBatch:
    """Bind complete decisions before interpreting row semantics; perform only reads."""
    if not isinstance(result, BatchResult):
        raise SurfaceError("Expected a BatchResult")
    # Typed records can be constructed by callers too: do not rely on load having run.
    try:
        result = _parse(json.loads(surface.canonical_bytes(dataclasses.asdict(result))))
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SurfaceError(f"Invalid typed surface result: {exc}") from exc
    for name in ("manifest_sha256", "worklist_sha256", "batch_sha256"):
        _sha(getattr(result, name), name)
    try:
        assigned, index_path = _assigned(con, pathlib.Path(run_dir), result)
        decisions = [decision.path for decision in result.decisions]
        if len(set(decisions)) != len(decisions) or set(decisions) != set(assigned):
            raise SurfaceError("Decisions must match assigned batch membership exactly, without missing or duplicate units")
        _semantics(con, result, assigned)
    except (sqlite3.Error, OSError) as exc:
        raise SurfaceError(f"Cannot read surface result validation inputs: {exc}") from exc
    return ValidatedBatch(result, assigned, index_path)


def canonical_bytes(validated: ValidatedBatch) -> bytes:
    """Serialize only agent result data, excluding host paths and derived metadata."""
    return surface.canonical_bytes(dataclasses.asdict(validated.result))


def _refuse_existing(con: sqlite3.Connection, validated: ValidatedBatch) -> None:
    """Any existing decision or claim in an assigned unit requires replacement."""
    for unit in validated.assigned_units:
        for table in ("cba_firmware_surfaces", "cba_unknowns"):
            if con.execute(f"SELECT 1 FROM {table} WHERE image_id=? AND component_path=? LIMIT 1",
                           (validated.result.image_id, unit)).fetchone():
                raise SurfaceError(f"Surface result already exists for {unit}; pass --replace")
        if con.execute("SELECT 1 FROM cba_coverage WHERE phase='surface' AND unit=?",
                       (db.firmware_unit_key(validated.result.image_id, unit),)).fetchone():
            raise SurfaceError(f"Surface coverage already exists for {unit}; pass --replace")


def _refuse_unqualified(con: sqlite3.Connection, validated: ValidatedBatch) -> None:
    """Old raw surface rows have no provable owner, even during replacement."""
    for unit in validated.assigned_units:
        if con.execute("SELECT 1 FROM cba_coverage WHERE phase='surface' AND unit=?", (unit,)).fetchone():
            raise SurfaceError(f"Unqualified legacy surface coverage has unknown ownership for {unit}; use a fresh run")


def record(con: sqlite3.Connection, run_dir: str | pathlib.Path,
           result_path: str | pathlib.Path, *, replace: bool = False) -> ImportSummary:
    """Install immutable evidence before atomically publishing only its assigned units."""
    if con.in_transaction:
        raise SurfaceError("Surface import requires a connection without an active transaction")
    run_dir = pathlib.Path(run_dir)
    validated = validate(con, run_dir, load(result_path))
    try:
        _refuse_unqualified(con, validated)
        if not replace:
            _refuse_existing(con, validated)
        content = canonical_bytes(validated)
        digest = hashlib.sha256(content).hexdigest()
        destination = run_dir / "artifacts/surface" / digest
        artifact_path = str(destination / "result.json")
        surface.atomic_install(destination, {"result.json": content})
    except (OSError, sqlite3.Error) as exc:
        raise SurfaceError(f"Cannot install surface result: {exc}") from exc
    result = validated.result
    summary = ImportSummary(result.image_id, result.batch_path, len(validated.assigned_units),
        sum(len(unit.surfaces) for unit in result.decisions),
        sum(len(unit.unknowns) for unit in result.decisions), artifact_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        # Artifact installation can admit another writer; recheck ownership and
        # prepared provenance under the publication lock before deleting rows.
        validate(con, run_dir, result)
        _refuse_unqualified(con, validated)
        if not replace:
            _refuse_existing(con, validated)
        else:
            for table in ("cba_unknowns", "cba_firmware_surfaces"):
                con.executemany(f"DELETE FROM {table} WHERE image_id=? AND component_path=?",
                    [(result.image_id, unit) for unit in validated.assigned_units])
            con.executemany("DELETE FROM cba_coverage WHERE phase='surface' AND unit=?",
                            [(db.firmware_unit_key(result.image_id, unit),) for unit in validated.assigned_units])
        provenance = {"image_id": result.image_id, "artifact_path": artifact_path,
                      "artifact_sha256": digest}
        for decision in result.decisions:
            for row in decision.surfaces:
                db.put(con, "cba_firmware_surfaces", dataclasses.asdict(row) | provenance, commit=False)
            for row in decision.unknowns:
                db.put(con, "cba_unknowns", dataclasses.asdict(row) | provenance, commit=False)
            reason = decision.reason.strip() if decision.state == "not_audited" else decision.reason
            db.put(con, "cba_coverage", {"unit": db.firmware_unit_key(result.image_id, decision.path), "phase": "surface",
                "state": decision.state, "reason": reason}, commit=False)
        con.execute("UPDATE cba_surface_runs SET status='pending',completed_at=NULL WHERE image_id=?",
                    (result.image_id,))
        con.commit()
    except Exception as exc:
        con.rollback()
        if isinstance(exc, (sqlite3.Error, OSError, db.DbError)):
            raise SurfaceError(f"Cannot publish surface batch {result.batch_path}: {exc}") from exc
        raise
    return summary
