"""Strict, read-only parsing and ownership checks for firmware review results."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3
import stat

from audit_core import db, firmware_fpcheck, hunt, surface
from audit_core.firmware_fpcheck import FpcheckError

RESULT_SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 8 * 1024 * 1024
_RULE_IDS = tuple(f"{prefix}-{number}" for prefix, count in (("HE", 18), ("PR", 10), ("CV", 3))
                  for number in range(1, count + 1)) + ("MARGINAL-GAIN",)


@dataclasses.dataclass(frozen=True, slots=True)
class TruePositive:
    root_cause_key: str
    root_cause: str
    dedup_evidence: str
    attacker_position: str
    data_flow: str
    impact_hypothesis: str
    component_paths: tuple[str, ...]
    surface_ids: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class FalsePositive:
    refuting_mechanism: str
    pivot_id: str
    enabled_observation: str
    pivot_evidence: str
    component_path: str


@dataclasses.dataclass(frozen=True, slots=True)
class Duplicate:
    target_lane: str
    target_candidate_id: str
    dedup_evidence: str


@dataclasses.dataclass(frozen=True, slots=True)
class Decision:
    lane: str
    candidate_id: str
    verdict: str
    reason: str
    attacker_advantage: str
    rules_applied: tuple[str, ...]
    mitigation_analysis: str
    confidence: int
    true_positive: TruePositive | None
    false_positive: FalsePositive | None
    duplicate: Duplicate | None


@dataclasses.dataclass(frozen=True, slots=True)
class BatchResult:
    schema_version: int
    image_id: str
    candidate_snapshot_sha256: str
    worklist_sha256: str
    batch_path: str
    batch_sha256: str
    decisions: tuple[Decision, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedBatch:
    result: BatchResult
    assigned_candidates: tuple[tuple[str, str], ...]
    index_path: str


def _object(value: object, cls: type) -> dict:
    if not isinstance(value, dict) or set(value) != {field.name for field in dataclasses.fields(cls)}:
        raise FpcheckError(f"{cls.__name__} requires exactly its schema keys")
    return value


def _text(value: object, label: str, *, empty: bool = False) -> None:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise FpcheckError(f"{label} requires {'string' if empty else 'non-empty text'}")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise FpcheckError(f"{label} requires valid UTF-8 text") from exc


def _identifier(value: object, label: str) -> None:
    _text(value, label)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None:
        raise FpcheckError(f"{label} requires a safe identifier of 1-128 characters")


def _path(value: object, label: str) -> None:
    _text(value, label)
    if (value.startswith("/") or "\\" in value or "\x00" in value or re.match(r"^[A-Za-z]:", value)
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise FpcheckError(f"{label} requires an exact relative non-escaping path")


def _enum(value: object, allowed: tuple[str, ...], label: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise FpcheckError(f"Invalid {label}")


def _array(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise FpcheckError(f"{label} requires an array")
    return value


def _strings(value: object, label: str, *, paths: bool = False) -> tuple[str, ...]:
    values = _array(value, label)
    for entry in values:
        (_path if paths else _identifier)(entry, label)
    if len(set(values)) != len(values):
        raise FpcheckError(f"Duplicate {label}")
    return tuple(values)


def _variant(value: object, cls: type):
    if value is None:
        return None
    row = _object(value, cls).copy()
    for name in row:
        if name in ("component_paths", "surface_ids"):
            row[name] = _strings(row[name], name, paths=name == "component_paths")
        else:
            _text(row[name], name, empty=True)
    if cls is TruePositive:
        _identifier(row["root_cause_key"], "root_cause_key")
    elif cls is FalsePositive:
        _identifier(row["pivot_id"], "pivot_id")
        _path(row["component_path"], "component_path")
    else:
        _enum(row["target_lane"], db.HUNT_LANES, "target_lane")
        _identifier(row["target_candidate_id"], "target_candidate_id")
    return cls(**row)


def _parse(value: object) -> BatchResult:
    """Check structural types first; verdict semantics can follow assignment checks."""
    row = _object(value, BatchResult)
    if type(row["schema_version"]) is not int or row["schema_version"] != RESULT_SCHEMA_VERSION:
        raise FpcheckError("schema_version requires integer 1")
    _text(row["image_id"], "image_id")
    for name in ("candidate_snapshot_sha256", "worklist_sha256", "batch_sha256"):
        if not isinstance(row[name], str) or re.fullmatch(r"[0-9a-f]{64}", row[name]) is None:
            raise FpcheckError(f"{name} requires 64 lower-case hexadecimal characters")
    if not isinstance(row["batch_path"], str) or re.fullmatch(r"batch-[0-9]{4,}\.json", row["batch_path"]) is None:
        raise FpcheckError("Invalid batch path")
    decisions = []
    for value in _array(row["decisions"], "decisions"):
        item = _object(value, Decision)
        _enum(item["lane"], db.HUNT_LANES, "lane")
        _identifier(item["candidate_id"], "candidate_id")
        _enum(item["verdict"], db.FIRMWARE_FP_VERDICTS, "verdict")
        for name in ("reason", "attacker_advantage", "mitigation_analysis"):
            _text(item[name], name, empty=True)
        if type(item["confidence"]) is not int:
            raise FpcheckError("confidence requires an integer")
        decisions.append(Decision(**(item | {
            "rules_applied": _strings(item["rules_applied"], "rules_applied"),
            "true_positive": _variant(item["true_positive"], TruePositive),
            "false_positive": _variant(item["false_positive"], FalsePositive),
            "duplicate": _variant(item["duplicate"], Duplicate)})))
    if len({(item.lane, item.candidate_id) for item in decisions}) != len(decisions):
        raise FpcheckError("Duplicate decision membership")
    return BatchResult(**(row | {"decisions": tuple(decisions)}))


def _review_semantics(result: BatchResult) -> None:
    for row in result.decisions:
        for name in ("reason", "attacker_advantage", "mitigation_analysis"):
            _text(getattr(row, name), name)
        if not row.rules_applied:
            raise FpcheckError("rules_applied requires at least one rule identifier")
        for identifier in row.rules_applied:
            _enum(identifier, _RULE_IDS, "canonical rule identifier")
        variants = (row.true_positive, row.false_positive, row.duplicate)
        expected = db.FIRMWARE_FP_VERDICTS.index(row.verdict)
        if any((value is not None) != (number == expected) for number, value in enumerate(variants)):
            raise FpcheckError("Verdict requires exactly its matching variant object")
        variant = variants[expected]
        for field in dataclasses.fields(variant):
            value = getattr(variant, field.name)
            if isinstance(value, str):
                _text(value, field.name)
        if row.true_positive is not None and not row.true_positive.component_paths:
            raise FpcheckError("TRUE_POSITIVE requires owned component_paths")


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FpcheckError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise FpcheckError(f"Non-finite JSON value: {value}")


def _read_json(path: pathlib.Path, *, bounded: bool = False) -> object:
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise FpcheckError("Firmware review artifact must be a regular file")
        with path.open("rb") as stream:
            content = stream.read(MAX_RESULT_BYTES + 1) if bounded else stream.read()
        if bounded and len(content) > MAX_RESULT_BYTES:
            raise FpcheckError(f"Result size exceeds {MAX_RESULT_BYTES} bytes")
        return json.loads(content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise FpcheckError("Cannot read firmware review JSON") from exc


def _canonical(result: BatchResult) -> bytes:
    content = surface.canonical_bytes(dataclasses.asdict(result))
    if len(content) > MAX_RESULT_BYTES:
        raise FpcheckError(f"Canonical result size exceeds {MAX_RESULT_BYTES} bytes")
    return content


def load(path: str | pathlib.Path) -> BatchResult:
    """Read bounded UTF-8 JSON and enforce exact, mutually exclusive variants."""
    result = _parse(_read_json(pathlib.Path(path), bounded=True))
    _review_semantics(result)
    _canonical(result)
    return result


def _snapshot(con: sqlite3.Connection, run_dir: pathlib.Path, image_id: str) -> hunt.VerifiedHuntSnapshot:
    """Reuse the completed evidence verifier; live-root agreement belongs to check."""
    bound = surface.verified_snapshot(con, run_dir, image_id=image_id)
    manifest = surface._manifest(con, image_id)
    surface._inventory_agreement(con, image_id, manifest)
    hunt._refuse_unqualified_coverage(con)
    runs = surface._query(con, "SELECT * FROM cba_hunt_runs WHERE image_id=? ORDER BY lane", (image_id,))
    if len(runs) != 2 or {row["lane"] for row in runs} != set(db.HUNT_LANES):
        raise FpcheckError("Both completed hunt lanes are required")
    candidates = []
    lanes = []
    for row in runs:
        db.TABLE_SPECS["cba_hunt_runs"].validate(row)
        if (row["status"] != "complete" or
                (row["manifest_sha256"], row["surface_snapshot_sha256"]) !=
                (bound.manifest_sha256, bound.snapshot_sha256)):
            raise FpcheckError("Completed hunt snapshot differs from prepared review")
        candidates.extend(hunt._checked_lane(con, run_dir, row, manifest)[2])
        lanes.append(hunt.VerifiedHuntLane(row["lane"], row["worklist_path"], row["worklist_sha256"],
                                         row["unit_count"], row["batch_count"]))
    return hunt.VerifiedHuntSnapshot(image_id, bound.manifest_sha256, bound.snapshot_sha256,
                                     tuple(lanes), tuple(candidates))


def _assigned(con: sqlite3.Connection, run_dir: pathlib.Path, result: BatchResult):
    snapshot = _snapshot(con, run_dir, result.image_id)
    runs = surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (result.image_id,))
    if len(runs) != 1:
        raise FpcheckError("One prepared firmware review run is required")
    run = runs[0]
    db.TABLE_SPECS["cba_firmware_fp_runs"].validate(run)
    completed = run["completed_at"]
    if ((run["status"] == "pending" and completed is not None) or
            (run["status"] == "complete" and (not isinstance(completed, str) or not completed.strip()))):
        raise FpcheckError("Firmware review status and completion timestamp disagree")
    index_path = pathlib.Path(run["worklist_path"])
    index = _read_json(index_path)
    if not isinstance(index, dict):
        raise FpcheckError("Prepared review index must be an object")
    size = index.get("batch_size")
    if type(size) is not int or not 1 <= size <= 200:
        raise FpcheckError("Invalid prepared review batch size")
    files, digest = firmware_fpcheck._worklist(snapshot, size)
    expected_index = json.loads(files["index.json"])
    expected_run = {key: value for key, value in expected_index.items() if key not in ("schema_version", "batch_size", "batches")}
    expected_run.update(worklist_sha256=digest, candidate_count=len(snapshot.candidates), batch_count=len(files) - 1)
    if any(run[key] != value for key, value in expected_run.items()):
        raise FpcheckError("Prepared review identity differs from current completed hunt")
    expected_path = run_dir / "files/firmware-fpcheck" / digest / "index.json"
    if index_path.absolute() != expected_path:
        raise FpcheckError("Prepared review worklist path is outside the current generation")
    firmware_fpcheck._checked_install(index_path.parent, files)
    if (result.candidate_snapshot_sha256 != expected_index["candidate_snapshot_sha256"] or
            result.worklist_sha256 != digest or result.batch_path not in files or
            hashlib.sha256(files[result.batch_path]).hexdigest() != result.batch_sha256):
        raise FpcheckError("Result snapshot, worklist or batch provenance differs")
    assigned = tuple((row["lane"], row["candidate_id"]) for row in json.loads(files[result.batch_path])["candidates"])
    return assigned, str(index_path), snapshot


def _ownership(con: sqlite3.Connection, result: BatchResult, snapshot: hunt.VerifiedHuntSnapshot) -> None:
    components = {row["path"] for row in surface._manifest(con, result.image_id)}
    surfaces = {row["surface_id"]: row["component_path"] for row in surface._query(con,
        "SELECT surface_id,component_path FROM cba_firmware_surfaces WHERE image_id=?", (result.image_id,))}
    candidates = {(row.lane, row.candidate_id) for row in snapshot.candidates}
    for row in result.decisions:
        if row.true_positive is not None:
            variant = row.true_positive
            if not set(variant.component_paths) <= components:
                raise FpcheckError("Reviewed component belongs to another image or is absent")
            if any(surfaces.get(identifier) not in variant.component_paths for identifier in variant.surface_ids):
                raise FpcheckError("Reviewed surface belongs to another image or component")
        elif row.false_positive is not None:
            if row.false_positive.component_path not in components:
                raise FpcheckError("Pivot component belongs to another image or is absent")
        else:
            target = (row.duplicate.target_lane, row.duplicate.target_candidate_id)
            if target not in candidates or target == (row.lane, row.candidate_id):
                raise FpcheckError("Duplicate target must be a non-self candidate in the current snapshot")


def validate(con: sqlite3.Connection, run_dir: str | pathlib.Path, result: BatchResult) -> ValidatedBatch:
    """Verify exact assignment before verdict semantics, without writes or root access."""
    if not isinstance(result, BatchResult):
        raise FpcheckError("Expected a BatchResult")
    try:
        result = _parse(json.loads(_canonical(result)))
        assigned, index_path, snapshot = _assigned(con, pathlib.Path(run_dir).absolute(), result)
        identities = [(row.lane, row.candidate_id) for row in result.decisions]
        if len(identities) != len(assigned) or set(identities) != set(assigned):
            raise FpcheckError("Decisions must match assigned batch membership exactly")
        _review_semantics(result)
        if any(not 0 <= row.confidence <= 10 for row in result.decisions):
            raise FpcheckError("confidence requires an integer from 0 to 10")
        _ownership(con, result, snapshot)
        return ValidatedBatch(result, assigned, index_path)
    except (sqlite3.Error, OSError, db.DbError, hunt.HuntError, surface.SurfaceError,
            TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise FpcheckError("Cannot validate firmware review result inputs") from exc


def canonical_bytes(validated: ValidatedBatch) -> bytes:
    """Serialize worker evidence only, with the same canonical-output size bound."""
    return _canonical(validated.result)
