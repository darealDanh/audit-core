"""Strict, read-only parsing and assignment validation for firmware hunt results."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3
import stat

from audit_core import db, hunt, surface
from audit_core.hunt import HuntError

RESULT_SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 8 * 1024 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class Blocker:
    id: str
    question: str
    settling_observation: str
    method: str


@dataclasses.dataclass(frozen=True, slots=True)
class Candidate:
    candidate_id: str
    component_path: str
    title: str
    bug_class: str
    surface_ids: tuple[str, ...]
    surface_context: str
    attacker_position: str
    input_evidence: str
    data_flow: str
    dangerous_operation: str
    operation_evidence: str
    mitigations_checked: str
    lifecycle_required: str
    posture_required: str
    auth_required: str
    reachability: str
    state_evidence: str
    confidence: int
    impact_hypothesis: str
    blockers: tuple[Blocker, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class UnitDecision:
    path: str
    disposition: str
    reason: str | None
    candidates: tuple[Candidate, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class BatchResult:
    schema_version: int
    image_id: str
    lane: str
    manifest_sha256: str
    surface_snapshot_sha256: str
    worklist_sha256: str
    batch_path: str
    batch_sha256: str
    decisions: tuple[UnitDecision, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedBatch:
    result: BatchResult
    assigned_units: tuple[str, ...]
    index_path: str


def _object(value: object, cls: type) -> dict:
    keys = {field.name for field in dataclasses.fields(cls)}
    if not isinstance(value, dict) or set(value) != keys:
        raise HuntError(f"{cls.__name__} requires exactly its schema keys")
    return value


def _text(value: object, label: str, *, empty: bool = False) -> None:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise HuntError(f"{label} requires {'string' if empty else 'non-empty text'}")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise HuntError(f"{label} requires valid UTF-8 text") from exc


def _array(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise HuntError(f"{label} requires an array")
    return value


def _identifier(value: object, label: str) -> None:
    _text(value, label)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise HuntError(f"{label} requires a safe identifier of 1-128 characters")


def _path(value: object, label: str) -> None:
    _text(value, label)
    if (value.startswith("/") or "\\" in value or "\x00" in value or
            re.match(r"^[A-Za-z]:", value) or any(part in ("", ".", "..") for part in value.split("/"))):
        raise HuntError(f"{label} requires an exact relative non-escaping path")


def _sha(value: object, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise HuntError(f"{label} requires 64 lower-case hexadecimal characters")


def _enum(value: object, allowed: tuple[str, ...], label: str) -> None:
    if value not in allowed:
        raise HuntError(f"Invalid {label}")


def _parse_candidate(value: object) -> Candidate:
    row = _object(value, Candidate)
    for name in row.keys() - {"surface_ids", "blockers", "confidence"}:
        _text(row[name], name)
    _identifier(row["candidate_id"], "candidate_id")
    _path(row["component_path"], "component_path")
    # No attacker-position enum exists in the shared firmware schema.
    if len(row["attacker_position"]) > 1024:
        raise HuntError("attacker_position exceeds 1024 characters")
    if type(row["confidence"]) is not int or not 0 <= row["confidence"] <= 10:
        raise HuntError("confidence requires an integer from 0 to 10")
    for name, allowed in (("lifecycle_required", db.LIFECYCLE_STATES),
            ("posture_required", db.POSTURE_STATES), ("auth_required", db.AUTH_STATES),
            ("reachability", db.REACHABILITY_STATES)):
        _enum(row[name], allowed, name)
    ids = _array(row["surface_ids"], "surface_ids")
    for identifier in ids:
        _identifier(identifier, "surface_id")
    if len(set(ids)) != len(ids):
        raise HuntError("Duplicate surface ID")
    blockers = []
    for item in _array(row["blockers"], "blockers"):
        blocker = _object(item, Blocker)
        for name, text in blocker.items():
            _text(text, name)
        _identifier(blocker["id"], "blocker id")
        _enum(blocker["method"], db.UNKNOWN_METHODS, "blocker method")
        blockers.append(Blocker(**blocker))
    if len({blocker.id for blocker in blockers}) != len(blockers):
        raise HuntError("Duplicate blocker ID")
    return Candidate(**(row | {"surface_ids": tuple(ids), "blockers": tuple(blockers)}))


def _parse(value: object) -> BatchResult:
    row = _object(value, BatchResult)
    if type(row["schema_version"]) is not int or row["schema_version"] != RESULT_SCHEMA_VERSION:
        raise HuntError("schema_version requires integer 1")
    _text(row["image_id"], "image_id")
    _enum(row["lane"], db.HUNT_LANES, "lane")
    for name in ("manifest_sha256", "surface_snapshot_sha256", "worklist_sha256", "batch_sha256"):
        _sha(row[name], name)
    if not isinstance(row["batch_path"], str) or re.fullmatch(r"batch-[0-9]{4,}\.json", row["batch_path"]) is None:
        raise HuntError("Invalid batch path")
    decisions = []
    candidate_ids = set()
    for item in _array(row["decisions"], "decisions"):
        unit = _object(item, UnitDecision)
        _path(unit["path"], "decision path")
        _enum(unit["disposition"], db.HUNT_DISPOSITIONS, "disposition")
        if unit["reason"] is not None:
            _text(unit["reason"], "reason", empty=True)
        candidates = tuple(_parse_candidate(value) for value in _array(unit["candidates"], "candidates"))
        for candidate in candidates:
            if candidate.candidate_id in candidate_ids:
                raise HuntError("Duplicate candidate ID")
            candidate_ids.add(candidate.candidate_id)
        decisions.append(UnitDecision(**(unit | {"candidates": candidates})))
    if len({unit.path for unit in decisions}) != len(decisions):
        raise HuntError("Duplicate unit decision")
    return BatchResult(**(row | {"decisions": tuple(decisions)}))


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise HuntError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise HuntError(f"Non-finite JSON value: {value}")


def _read_json(path: pathlib.Path, *, bounded: bool = False) -> tuple[bytes, object]:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise HuntError("Hunt artifact must be a regular file")
        with path.open("rb") as stream:
            content = stream.read(MAX_RESULT_BYTES + 1) if bounded else stream.read()
        if bounded and len(content) > MAX_RESULT_BYTES:
            raise HuntError(f"Result size exceeds {MAX_RESULT_BYTES} bytes")
        return content, json.loads(content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise HuntError("Cannot read hunt JSON") from exc


def load(path: str | pathlib.Path) -> BatchResult:
    """Read a bounded UTF-8 regular file without duplicate keys or coercions."""
    return _parse(_read_json(pathlib.Path(path), bounded=True)[1])


def _assigned(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult) -> tuple[tuple[str, ...], str]:
    """Rebuild both canonical lane definitions from current verified durable state."""
    bound = surface.verified_snapshot(con, run_dir, image_id=result.image_id)
    if (result.manifest_sha256 != bound.manifest_sha256 or
            result.surface_snapshot_sha256 != bound.snapshot_sha256):
        raise HuntError("Result manifest or surface snapshot provenance differs")
    manifest = surface._manifest(con, result.image_id)
    units = hunt._units(con, result.image_id, manifest)
    runs = surface._query(con, "SELECT * FROM cba_hunt_runs WHERE image_id=?", (result.image_id,))
    if {row["lane"] for row in runs} != set(db.HUNT_LANES):
        raise HuntError("Both prepared hunt lanes are required")
    definitions = {}
    for run in runs:
        lane = run["lane"]
        _enum(run["status"], db.HUNT_RUN_STATES, "prepared status")
        if run["manifest_sha256"] != bound.manifest_sha256 or run["surface_snapshot_sha256"] != bound.snapshot_sha256:
            raise HuntError("Prepared hunt snapshot differs")
        index_path = pathlib.Path(run["worklist_path"])
        _, index = _read_json(index_path)
        if not isinstance(index, dict):
            raise HuntError("Prepared index must be an object")
        size = index.get("batch_size")
        if type(size) is not int or not 1 <= size <= 1000:
            raise HuntError("Invalid prepared batch size")
        files, digest, count = hunt._worklist(result.image_id, bound.manifest_sha256,
                                             bound.snapshot_sha256, lane, units, size)
        if (run["worklist_sha256"] != digest or run["unit_count"] != len(units) or
                run["batch_count"] != count):
            raise HuntError("Prepared hunt assignment differs from current inputs")
        definitions[lane] = (files, digest, index_path)
    generation = hashlib.sha256(surface.canonical_bytes({"image_id": result.image_id,
        "manifest_sha256": bound.manifest_sha256, "surface_snapshot_sha256": bound.snapshot_sha256,
        "lanes": {lane: value[1] for lane, value in definitions.items()}})).hexdigest()
    for lane, (files, _, index_path) in definitions.items():
        expected = run_dir / "files/hunt" / generation / lane / "index.json"
        if index_path.absolute() != expected.absolute():
            raise HuntError("Prepared worklist path is outside the current generation")
        hunt._checked_install(index_path.parent, files)
    files, digest, index_path = definitions[result.lane]
    if digest != result.worklist_sha256 or result.batch_path not in files:
        raise HuntError("Result worklist or batch provenance differs")
    content = files[result.batch_path]
    if hashlib.sha256(content).hexdigest() != result.batch_sha256:
        raise HuntError("Result batch SHA-256 differs")
    batch = json.loads(content)
    return tuple(unit["path"] for unit in batch["units"]), str(index_path)


def _semantics(con: sqlite3.Connection, result: BatchResult) -> None:
    surfaces = {row["surface_id"]: row["component_path"] for row in surface._query(con,
        "SELECT surface_id,component_path FROM cba_firmware_surfaces WHERE image_id=?", (result.image_id,))}
    for unit in result.decisions:
        if unit.disposition == "not_audited":
            if unit.reason not in db.NOT_AUDITED_REASONS:
                raise HuntError("not_audited requires a permitted reason")
        elif not unit.candidates:
            _text(unit.reason, "clear-analysis or not-applicable reason")
        if unit.disposition != "analyzed" and unit.candidates:
            raise HuntError("Only analyzed decisions may publish candidates")
        for row in unit.candidates:
            if row.component_path != unit.path:
                raise HuntError("Candidate component must belong to its assigned decision")
            if not row.surface_ids:
                _text(row.surface_context, "unmapped surface explanation")
            if any(surfaces.get(identifier) != unit.path for identifier in row.surface_ids):
                raise HuntError("Candidate surface belongs to another image or component")
            # These are documentary minimums, not proof of exploitability. Later
            # fpcheck must adversarially adjudicate the actual cited evidence.
            if result.lane == "l-sink":
                operation = row.dangerous_operation.casefold()
                if operation not in row.data_flow.casefold() or operation not in row.operation_evidence.casefold():
                    raise HuntError("L-sink requires a named operation in the trace and operation evidence")
                if not re.search(r"attacker|untrusted|external|cross[- ]trust|user[- ]controlled", row.data_flow, re.I):
                    raise HuntError("L-sink requires documented attacker influence")
            elif not re.search(r"\b(?:upnp|ssdp|mdns|tr-?069|cwmp|cloud|p2p|discovery|unix.{0,12}(socket|ipc)|ota|heap|trust boundary)\b",
                               row.dangerous_operation, re.I):
                raise HuntError("L-dark requires a named protocol, trust boundary, OTA decision or heap mechanism")


def validate(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult) -> ValidatedBatch:
    """Validate complete membership before candidate semantics; perform no writes."""
    if not isinstance(result, BatchResult):
        raise HuntError("Expected a BatchResult")
    try:
        # Public immutable constructors must not provide an unchecked bypass.
        result = _parse(json.loads(surface.canonical_bytes(dataclasses.asdict(result))))
        assigned, index_path = _assigned(con, pathlib.Path(run_dir), result)
        paths = [unit.path for unit in result.decisions]
        if len(paths) != len(assigned) or set(paths) != set(assigned):
            raise HuntError("Decisions must match assigned batch membership exactly")
        _semantics(con, result)
    except (sqlite3.Error, OSError, surface.SurfaceError, db.DbError, TypeError,
            ValueError, UnicodeError, RecursionError) as exc:
        raise HuntError("Cannot validate hunt result inputs") from exc
    return ValidatedBatch(result, assigned, index_path)


def canonical_bytes(validated: ValidatedBatch) -> bytes:
    """Serialize only worker result data, excluding derived paths and metadata."""
    return surface.canonical_bytes(dataclasses.asdict(validated.result))
