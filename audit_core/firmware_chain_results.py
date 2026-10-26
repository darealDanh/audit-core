"""Bounded hostile firmware-chain JSON and non-circular semantic identities.

This module's parser proves local structure only. Current-generation ownership,
evidence meaning, state continuity, and publication belong to the graph validator
and importer. Reading worker JSON and deriving IDs never writes SQL or artifacts.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import stat
import unicodedata
from collections.abc import Mapping

from audit_core import db
from audit_core.firmware_chain import FirmwareChainError

RESULT_SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_LINK_KEY_BYTES = 4096
_ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_EVIDENCE_PATTERN = re.compile(rf"(finding|surface|unknown):({_ID_PATTERN})#([a-z_]+)")
_EVIDENCE_FIELDS = {
    "finding": ("root_cause", "attacker_position", "data_flow", "impact_hypothesis", "evidence_summary"),
    "surface": ("reach_evidence",),
    "unknown": ("evidence",),
}


@dataclasses.dataclass(frozen=True, slots=True)
class State:
    lifecycle: str
    posture: str
    authentication: str


@dataclasses.dataclass(frozen=True, slots=True)
class ExistingUnknownRef:
    unknown_id: str
    axes: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class AffectedEdgeRef:
    chain_key: str
    ordinal: int


@dataclasses.dataclass(frozen=True, slots=True)
class NewBlocker:
    blocker_key: str
    question: str
    settling_observation: str
    method: str
    axes: tuple[str, ...]
    affected_finding_ids: tuple[str, ...]
    affected_edges: tuple[AffectedEdgeRef, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class FindingDisposition:
    finding_id: str
    disposition: str
    explanation: str
    chain_keys: tuple[str, ...]
    existing_unknown_ids: tuple[str, ...]
    blocker_keys: tuple[str, ...]
    pivot_followup_ids: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ChainEdge:
    producer_finding_id: str
    consumer_finding_id: str
    capability_kind: str
    link_key: str
    produced_capability: str
    required_precondition: str
    producer_evidence_refs: tuple[str, ...]
    consumer_evidence_refs: tuple[str, ...]
    supplemental_evidence_refs: tuple[str, ...]
    required_state: State
    result_state: State
    transition_kind: str
    confidence: int
    existing_unknowns: tuple[ExistingUnknownRef, ...]
    blocker_keys: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ChainResult:
    chain_key: str
    title: str
    summary: str
    member_ids: tuple[str, ...]
    initial_attacker_position: str
    initial_evidence_refs: tuple[str, ...]
    initial_state: State
    edges: tuple[ChainEdge, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GraphResult:
    schema_version: int
    image_id: str
    candidate_snapshot_sha256: str
    worklist_sha256: str
    blockers: tuple[NewBlocker, ...]
    dispositions: tuple[FindingDisposition, ...]
    chains: tuple[ChainResult, ...]


def _object(value: object, cls: type) -> dict:
    if not isinstance(value, dict) or set(value) != {field.name for field in dataclasses.fields(cls)}:
        raise FirmwareChainError(f"{cls.__name__} requires exactly its schema keys")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FirmwareChainError(f"{label} requires non-empty text")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise FirmwareChainError(f"{label} requires valid UTF-8 text") from exc
    return value


def _identifier(value: object, label: str) -> str:
    value = _text(value, label)
    if re.fullmatch(_ID_PATTERN, value) is None:
        raise FirmwareChainError(f"{label} requires a safe identifier of 1-128 characters")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise FirmwareChainError(f"{label} requires 64 lower-case hexadecimal characters")
    return value


def _enum(value: object, allowed: tuple[str, ...], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise FirmwareChainError(f"Invalid {label}")
    return value


def _integer(value: object, label: str, *, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise FirmwareChainError(f"{label} requires a nonnegative integer" +
                                 (f" at most {maximum}" if maximum is not None else ""))
    return value


def _array(value: object, label: str) -> list:
    if not isinstance(value, list):
        raise FirmwareChainError(f"{label} requires an array")
    return value


def _unique(values: tuple, label: str, *, key=None, ordered: bool = False) -> tuple:
    identities = [key(value) if key else value for value in values]
    if len(set(identities)) != len(values):
        raise FirmwareChainError(f"Duplicate {label}")
    return values if ordered else tuple(sorted(values, key=key))


def _identifiers(value: object, label: str, *, minimum: int = 0, ordered: bool = False) -> tuple[str, ...]:
    values = tuple(_identifier(entry, label) for entry in _array(value, label))
    if len(values) < minimum:
        raise FirmwareChainError(f"{label} requires at least {minimum} entries")
    return _unique(values, label, ordered=ordered)


def _axes(value: object) -> tuple[str, ...]:
    values = tuple(_enum(entry, db.FIRMWARE_CHAIN_AXES, "affected axis") for entry in _array(value, "axes"))
    if not values:
        raise FirmwareChainError("axes requires at least one affected axis")
    return _unique(values, "axes")


def _state(value: object, sentinel: str | None = None) -> State:
    row = _object(value, State)
    fields = (("lifecycle", db.FIRMWARE_CHAIN_LIFECYCLE_STATES),
              ("posture", db.FIRMWARE_CHAIN_POSTURE_STATES),
              ("authentication", db.FIRMWARE_CHAIN_AUTH_STATES))
    return State(**{name: _enum(row[name], allowed + ((sentinel,) if sentinel else ()), name)
                    for name, allowed in fields})


def _evidence_refs(value: object, label: str, *, initial: bool = False,
                   supplemental: bool = False) -> tuple[str, ...]:
    values = _array(value, label)
    if not supplemental and not values:
        raise FirmwareChainError(f"{label} requires at least one evidence reference")
    for entry in values:
        _text(entry, label)
        match = _EVIDENCE_PATTERN.fullmatch(entry)
        if match is None:
            raise FirmwareChainError(f"{label} requires machine-addressable evidence references")
        kind, _, field = match.groups()
        if (field not in _EVIDENCE_FIELDS[kind] or (supplemental and kind == "finding")
                or (not initial and not supplemental and kind != "finding")
                or (initial and (kind == "unknown" or
                    (kind == "finding" and field not in ("attacker_position", "evidence_summary"))))):
            raise FirmwareChainError(f"{label} has an invalid evidence variant")
    return _unique(tuple(values), label)


def _blocker(value: object) -> NewBlocker:
    row = _object(value, NewBlocker)
    affected = []
    for value in _array(row["affected_edges"], "affected_edges"):
        edge = _object(value, AffectedEdgeRef)
        affected.append(AffectedEdgeRef(_identifier(edge["chain_key"], "chain_key"),
                                        _integer(edge["ordinal"], "ordinal")))
    findings = _identifiers(row["affected_finding_ids"], "affected_finding_ids")
    if not findings and not affected:
        raise FirmwareChainError("Blocker requires affected finding IDs or edges")
    return NewBlocker(_identifier(row["blocker_key"], "blocker_key"),
        _text(row["question"], "question"), _text(row["settling_observation"], "settling_observation"),
        _enum(row["method"], db.FIRMWARE_CHAIN_METHODS, "method"), _axes(row["axes"]), findings,
        _unique(tuple(affected), "affected_edges", key=lambda edge: (edge.chain_key, edge.ordinal)))


def _disposition(value: object) -> FindingDisposition:
    row = _object(value, FindingDisposition)
    disposition = _enum(row["disposition"], db.FIRMWARE_CHAIN_DISPOSITIONS, "disposition")
    arrays = {name: _identifiers(row[name], name) for name in
              ("chain_keys", "existing_unknown_ids", "blocker_keys", "pivot_followup_ids")}
    if bool(arrays["chain_keys"]) != (disposition == "chained"):
        raise FirmwareChainError("chain_keys must be non-empty exactly for a chained disposition")
    if disposition == "blocked" and not (arrays["existing_unknown_ids"] or arrays["blocker_keys"]):
        raise FirmwareChainError("A blocked disposition requires an existing unknown or new blocker")
    if arrays["pivot_followup_ids"] and disposition not in ("unchainable", "blocked"):
        raise FirmwareChainError("Pivot follow-ups require an unchainable or blocked disposition")
    return FindingDisposition(_identifier(row["finding_id"], "finding_id"), disposition,
                              _text(row["explanation"], "explanation"), **arrays)


def _edge(value: object) -> ChainEdge:
    row = _object(value, ChainEdge)
    link = _text(row["link_key"], "link_key")
    if (link != link.strip() or len(link.encode("utf-8")) > MAX_LINK_KEY_BYTES
            or any(unicodedata.category(char) == "Cc" for char in link)):
        raise FirmwareChainError("link_key requires trimmed control-free UTF-8 of at most 4096 bytes")
    unknowns = []
    for value in _array(row["existing_unknowns"], "existing_unknowns"):
        unknown = _object(value, ExistingUnknownRef)
        unknowns.append(ExistingUnknownRef(_identifier(unknown["unknown_id"], "unknown_id"),
                                           _axes(unknown["axes"])))
    return ChainEdge(
        _identifier(row["producer_finding_id"], "producer_finding_id"),
        _identifier(row["consumer_finding_id"], "consumer_finding_id"),
        _enum(row["capability_kind"], db.FIRMWARE_CHAIN_CAPABILITY_KINDS, "capability_kind"), link,
        _text(row["produced_capability"], "produced_capability"),
        _text(row["required_precondition"], "required_precondition"),
        _evidence_refs(row["producer_evidence_refs"], "producer_evidence_refs"),
        _evidence_refs(row["consumer_evidence_refs"], "consumer_evidence_refs"),
        _evidence_refs(row["supplemental_evidence_refs"], "supplemental_evidence_refs", supplemental=True),
        _state(row["required_state"], "any"), _state(row["result_state"], "unchanged"),
        _enum(row["transition_kind"], db.FIRMWARE_CHAIN_TRANSITION_KINDS, "transition_kind"),
        _integer(row["confidence"], "confidence", maximum=10),
        _unique(tuple(unknowns), "existing_unknowns", key=lambda unknown: unknown.unknown_id),
        _identifiers(row["blocker_keys"], "blocker_keys"))


def _chain(value: object) -> ChainResult:
    row = _object(value, ChainResult)
    members = _identifiers(row["member_ids"], "member_ids", minimum=2, ordered=True)
    edges = tuple(_edge(value) for value in _array(row["edges"], "edges"))
    if len(edges) != len(members) - 1:
        raise FirmwareChainError("Chain requires exactly one edge for each adjacent member pair")
    if any((edge.producer_finding_id, edge.consumer_finding_id) != members[number:number + 2]
           for number, edge in enumerate(edges)):
        raise FirmwareChainError("Edge endpoints must follow the ordered member path")
    return ChainResult(_identifier(row["chain_key"], "chain_key"), _text(row["title"], "title"),
        _text(row["summary"], "summary"), members,
        _text(row["initial_attacker_position"], "initial_attacker_position"),
        _evidence_refs(row["initial_evidence_refs"], "initial_evidence_refs", initial=True),
        _state(row["initial_state"]), edges)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def canonical_blocker_id(image_id: str, candidate_snapshot_sha256: str, blocker: NewBlocker) -> str:
    """Hash blocker meaning before resolving any references to materialized chains.

    Local keys and affected-edge references are deliberately absent. Including
    chain identities here would create a cycle through each edge's blockers.
    """
    projection = {
        "image_id": image_id, "candidate_snapshot_sha256": candidate_snapshot_sha256,
        "question": blocker.question, "settling_observation": blocker.settling_observation,
        "method": blocker.method, "axes": sorted(blocker.axes),
        "affected_finding_ids": sorted(blocker.affected_finding_ids),
    }
    return "firmware-chain-blocker-" + hashlib.sha256(_json_bytes(projection)).hexdigest()


def canonical_chain_id(image_id: str, candidate_snapshot_sha256: str, chain: ChainResult,
                       blocker_ids: Mapping[str, str]) -> str:
    """Hash exact ordered semantics, replacing worker blocker keys with stable IDs."""
    edges = []
    for ordinal, edge in enumerate(chain.edges):
        try:
            resolved = sorted(blocker_ids[key] for key in edge.blocker_keys)
        except KeyError as exc:
            raise FirmwareChainError("Unknown local blocker key") from exc
        projection = dataclasses.asdict(edge)
        del projection["blocker_keys"]
        projection.update(ordinal=ordinal, blocker_ids=resolved)
        for name in ("producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs"):
            projection[name] = sorted(projection[name])
        projection["existing_unknowns"] = sorted(
            ({"unknown_id": unknown.unknown_id, "axes": sorted(unknown.axes)}
             for unknown in edge.existing_unknowns), key=lambda unknown: unknown["unknown_id"])
        edges.append(projection)
    projection = {
        "image_id": image_id, "candidate_snapshot_sha256": candidate_snapshot_sha256,
        "initial_state": dataclasses.asdict(chain.initial_state),
        "member_ids": chain.member_ids, "edges": edges,
    }
    return "firmware-chain-" + hashlib.sha256(_json_bytes(projection)).hexdigest()


def _local_graph(result: GraphResult) -> None:
    """Resolve local names in dependency order, rejecting aliases and dangling refs."""
    blocker_ids = {blocker.blocker_key: canonical_blocker_id(result.image_id,
        result.candidate_snapshot_sha256, blocker) for blocker in result.blockers}
    if len(set(blocker_ids.values())) != len(blocker_ids):
        raise FirmwareChainError("Duplicate semantic blocker identity")
    chain_ids = {chain.chain_key: canonical_chain_id(result.image_id,
        result.candidate_snapshot_sha256, chain, blocker_ids) for chain in result.chains}
    if len(set(chain_ids.values())) != len(chain_ids):
        raise FirmwareChainError("Duplicate semantic chain identity")
    chains = {chain.chain_key: chain for chain in result.chains}
    for blocker in result.blockers:
        for edge in blocker.affected_edges:
            if edge.chain_key not in chains or edge.ordinal >= len(chains[edge.chain_key].edges):
                raise FirmwareChainError("Unknown local affected edge reference")
    for disposition in result.dispositions:
        if not set(disposition.chain_keys) <= chain_ids.keys():
            raise FirmwareChainError("Unknown local disposition chain key")
        if not set(disposition.blocker_keys) <= blocker_ids.keys():
            raise FirmwareChainError("Unknown local disposition blocker key")


def _parse(value: object) -> GraphResult:
    row = _object(value, GraphResult)
    if type(row["schema_version"]) is not int or row["schema_version"] != RESULT_SCHEMA_VERSION:
        raise FirmwareChainError("schema_version requires integer 1")
    result = GraphResult(RESULT_SCHEMA_VERSION, _text(row["image_id"], "image_id"),
        _digest(row["candidate_snapshot_sha256"], "candidate_snapshot_sha256"),
        _digest(row["worklist_sha256"], "worklist_sha256"),
        _unique(tuple(_blocker(value) for value in _array(row["blockers"], "blockers")),
                "blocker keys", key=lambda blocker: blocker.blocker_key),
        _unique(tuple(_disposition(value) for value in _array(row["dispositions"], "dispositions")),
                "finding dispositions", key=lambda disposition: disposition.finding_id),
        _unique(tuple(_chain(value) for value in _array(row["chains"], "chains")),
                "chain keys", key=lambda chain: chain.chain_key))
    _local_graph(result)
    return result


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise FirmwareChainError("Duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise FirmwareChainError("Non-finite JSON value")


def canonical_bytes(validated: GraphResult) -> bytes:
    """Serialize normalized worker data; derived identities are never worker fields."""
    if not isinstance(validated, GraphResult):
        raise FirmwareChainError("Expected a GraphResult")
    content = _json_bytes(dataclasses.asdict(validated))
    if len(content) > MAX_RESULT_BYTES:
        raise FirmwareChainError(f"Canonical result size exceeds {MAX_RESULT_BYTES} bytes")
    return content


def load(path: str | pathlib.Path) -> GraphResult:
    """Read a bounded regular file and reject malformed UTF-8/JSON or local graphs."""
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise FirmwareChainError("Firmware chain result must be a regular file")
        # Optional POSIX flags refuse symlinks and avoid blocking on a replaced
        # FIFO. Identity checks also protect platforms without those flags.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                raise FirmwareChainError("Firmware chain result must be a regular file")
            content = stream.read(MAX_RESULT_BYTES + 1)
        if len(content) > MAX_RESULT_BYTES:
            raise FirmwareChainError(f"Result size exceeds {MAX_RESULT_BYTES} bytes")
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        result = _parse(value)
        canonical_bytes(result)
        return result
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise FirmwareChainError("Cannot read firmware chain JSON") from exc


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedDisposition:
    image_id: str
    finding_id: str
    candidate_snapshot_sha256: str
    disposition: str
    explanation: str
    chain_ids: str
    existing_unknown_ids: str
    blocker_ids: str
    pivot_followup_ids: str


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedBlocker:
    image_id: str
    blocker_id: str
    candidate_snapshot_sha256: str
    question: str
    settling_observation: str
    method: str
    axes: str
    affected_finding_ids: str
    affected_edges: str
    status: str


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedChain:
    image_id: str
    chain_id: str
    candidate_snapshot_sha256: str
    title: str
    summary: str
    member_ids: str
    initial_attacker_position: str
    initial_evidence_refs: str
    initial_lifecycle: str
    initial_posture: str
    initial_authentication: str
    pre_auth: str
    confidence: int
    completeness: str
    existing_unknown_ids: str
    blocker_ids: str
    evidence_rung: str


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedEdge:
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
    producer_evidence_refs: str
    consumer_evidence_refs: str
    supplemental_evidence_refs: str
    required_state: str
    result_state: str
    transition_kind: str
    confidence: int
    existing_unknowns: str
    blocker_ids: str


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedGraph:
    result: GraphResult
    blocker_ids: tuple[tuple[str, str], ...]
    chain_ids: tuple[tuple[str, str], ...]
    dispositions: tuple[ValidatedDisposition, ...]
    blockers: tuple[ValidatedBlocker, ...]
    chains: tuple[ValidatedChain, ...]
    edges: tuple[ValidatedEdge, ...]


# Stage 4d field names, deliberately independent of free-form reviewer axes.
_UNKNOWN_AXES = {"auth": "authentication", "lifecycle": "lifecycle",
                 "posture": "posture", "reachability": "reachability"}
_GENERIC_CLAIMS = frozenset(("provides access", "could help exploitation", "same component"))
_BOUNDARY_TERMS = {
    "reboot": r"\breboot(?:s|ed|ing)?\b",
    "service-restart": r"\bservice[- ]restart(?:s|ed|ing)?\b",
    "factory-reset": r"\bfactory[- ]reset(?:s|ting)?\b",
    "reprovision": r"\breprovision(?:s|ed|ing)?\b",
}


def _cell(value: object) -> str:
    return _json_bytes(value).decode("utf-8").removesuffix("\n")


def _retained_bytes(run_dir: pathlib.Path, relative: str, digest: str) -> bytes:
    """Read only canonical, non-redirected descendants of the run directory."""
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or path.as_posix() != relative or any(p in (".", "..") for p in path.parts):
        raise FirmwareChainError("Invalid retained artifact path")
    current = run_dir
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise FirmwareChainError("Retained artifact path is redirected")
    if not current.is_file():
        raise FirmwareChainError("Retained artifact must be a regular file")
    content = current.read_bytes()
    if hashlib.sha256(content).hexdigest() != digest:
        raise FirmwareChainError("Retained artifact hash differs")
    return content


def _review_index(con, run_dir: pathlib.Path, review: dict) -> list[dict]:
    """Check root-free retained review identities and receipt accounting only."""
    from audit_core import firmware_fpcheck, firmware_fpcheck_results, surface

    destination = run_dir / "files/firmware-fpcheck" / review["worklist_sha256"]
    if review["worklist_path"] != str(destination / "index.json"):
        raise FirmwareChainError("Review index path is not canonical")
    content = _retained_bytes(run_dir, (destination / "index.json").relative_to(run_dir).as_posix(),
                              review["worklist_sha256"])
    index = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
    if not isinstance(index, dict) or type(index.get("schema_version")) is not int or index["schema_version"] != 1:
        raise FirmwareChainError("Invalid review index")
    batch_size = _integer(index.get("batch_size"), "review batch size", maximum=200)
    if not batch_size:
        raise FirmwareChainError("Invalid review batch size")
    descriptors = {}
    batches = _array(index.get("batches"), "review batches")
    for batch in batches:
        if not isinstance(batch, dict) or set(batch) != {"path", "sha256", "candidate_count"}:
            raise FirmwareChainError("Invalid review batch descriptor")
        path = _text(batch["path"], "review batch path")
        if re.fullmatch(r"batch-[0-9]{4,}\.json", path) is None or path in descriptors:
            raise FirmwareChainError("Invalid or repeated review batch path")
        _digest(batch["sha256"], "review batch hash")
        _integer(batch["candidate_count"], "review batch count", maximum=1000)
        descriptors[path] = batch
    expected = {key: review[key] for key in ("image_id", "manifest_sha256", "surface_snapshot_sha256",
        "sink_worklist_sha256", "dark_worklist_sha256", "candidate_snapshot_sha256", "candidate_count")}
    expected.update(schema_version=1, batch_size=batch_size, batches=batches)
    if (_json_bytes(expected) != content or len(batches) != review["batch_count"] or not batches
            or sum(batch["candidate_count"] for batch in batches) != review["candidate_count"]):
        raise FirmwareChainError("Review index differs from current run")
    receipts = surface._query(con, "SELECT * FROM cba_firmware_fp_receipts WHERE image_id=? ORDER BY batch_path", (review["image_id"],))
    if len(receipts) != len(batches) or {r["batch_path"] for r in receipts} != descriptors.keys():
        raise FirmwareChainError("Review receipts do not cover the index batches")
    for receipt in receipts:
        db.TABLE_SPECS["cba_firmware_fp_receipts"].validate(receipt)
        batch = descriptors[receipt["batch_path"]]
        if (receipt["candidate_snapshot_sha256"], receipt["worklist_sha256"], receipt["batch_sha256"], receipt["assigned_count"]) != (
                review["candidate_snapshot_sha256"], review["worklist_sha256"], batch["sha256"], batch["candidate_count"]):
            raise FirmwareChainError("Review receipt differs from retained index")
        path = run_dir / "artifacts/firmware-fpcheck" / review["worklist_sha256"] / receipt["result_sha256"] / "result.json"
        if receipt["result_path"] != str(path):
            raise FirmwareChainError("Review result path is not canonical")
        content = _retained_bytes(run_dir, path.relative_to(run_dir).as_posix(), receipt["result_sha256"])
        try:
            # Structural parsing and accounting only: final check owns upstream
            # semantic reconstruction and live-root agreement.
            result = firmware_fpcheck_results._parse(json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant))
        except firmware_fpcheck.FpcheckError as exc:
            raise FirmwareChainError("Invalid retained review result") from exc
        if (_json_bytes(dataclasses.asdict(result)) != content or
                (result.image_id, result.candidate_snapshot_sha256, result.worklist_sha256, result.batch_path, result.batch_sha256) !=
                (review["image_id"], review["candidate_snapshot_sha256"], review["worklist_sha256"], batch["path"], batch["sha256"])):
            raise FirmwareChainError("Review result ownership differs")
        counts = {verdict: sum(d.verdict == verdict for d in result.decisions) for verdict in db.FIRMWARE_FP_VERDICTS}
        if tuple(receipt[key] for key in ("assigned_count", "verdict_count", "true_positive_count",
                "false_positive_count", "duplicate_count", "pivot_count")) != (
                len(result.decisions), len(result.decisions), counts["TRUE_POSITIVE"], counts["FALSE_POSITIVE"],
                counts["DUPLICATE"], counts["FALSE_POSITIVE"]):
            raise FirmwareChainError("Review receipt counts differ from retained result")
    return receipts


def _prepared_evidence(con, run_dir: pathlib.Path, result: GraphResult) -> dict:
    """Rebuild the exact frozen boundary from current SQL; never access live roots.

    Preparation and final check own live-root verification. Import-time validation
    proves the retained generation's complete-run identity and every evidence row.
    """
    from audit_core import firmware_chain, surface

    rows = surface._query(con, "SELECT * FROM cba_firmware_chain_runs WHERE image_id=?", (result.image_id,))
    if len(rows) != 1:
        raise FirmwareChainError("One prepared chain generation is required")
    run = rows[0]
    db.TABLE_SPECS["cba_firmware_chain_runs"].validate(run)
    if (run["candidate_snapshot_sha256"], run["worklist_sha256"]) != (
            result.candidate_snapshot_sha256, result.worklist_sha256):
        raise FirmwareChainError("Result does not own the prepared generation")
    destination = run_dir / "files/firmware-chain" / result.worklist_sha256
    if run["worklist_path"] != str(destination / "worklist.json"):
        raise FirmwareChainError("Prepared worklist path differs")
    content = _retained_bytes(run_dir, (destination / "worklist.json").relative_to(run_dir).as_posix(), result.worklist_sha256)
    firmware_chain._checked_install(destination, content)
    frozen = json.loads(content, object_pairs_hook=_pairs, parse_constant=_constant)
    if not isinstance(frozen, dict):
        raise FirmwareChainError("Invalid prepared worklist")
    reviews = surface._query(con, "SELECT * FROM cba_firmware_fp_runs WHERE image_id=?", (result.image_id,))
    if len(reviews) != 1:
        raise FirmwareChainError("One complete firmware review is required")
    review = reviews[0]
    db.TABLE_SPECS["cba_firmware_fp_runs"].validate(review)
    if (review["status"] != "complete" or not isinstance(review["completed_at"], str)
            or not review["completed_at"].strip()):
        raise FirmwareChainError("Firmware review must remain complete")
    for key in ("image_id", "manifest_sha256", "surface_snapshot_sha256", "candidate_snapshot_sha256"):
        if frozen.get(key) != run[key] or review[key] != run[key]:
            raise FirmwareChainError("Current review and prepared generation differ")
    if frozen.get("fpcheck_worklist_sha256") != review["worklist_sha256"]:
        raise FirmwareChainError("Current review worklist differs")
    receipts = _review_index(con, run_dir, review)
    artifact_relative = (pathlib.Path(run["fpcheck_artifact_path"])).relative_to(run_dir).as_posix()
    if (frozen.get("findings_artifact_path"), frozen.get("findings_artifact_sha256")) != (
            artifact_relative, run["fpcheck_artifact_sha256"]):
        raise FirmwareChainError("Prepared findings artifact ownership differs")
    artifact = _retained_bytes(run_dir, artifact_relative, run["fpcheck_artifact_sha256"])
    expected_artifact = run_dir / "artifacts/firmware-fpcheck" / review["worklist_sha256"] / run["fpcheck_artifact_sha256"] / "findings.json"
    if str(expected_artifact) != run["fpcheck_artifact_path"]:
        raise FirmwareChainError("Findings artifact is not canonical")
    rebuilt = {key: frozen[key] for key in ("schema_version", "image_id", "manifest_sha256", "surface_snapshot_sha256",
        "candidate_snapshot_sha256", "fpcheck_worklist_sha256", "findings_artifact_path", "findings_artifact_sha256")}
    components, surfaces = set(), set()
    checked_artifacts = {(artifact_relative, run["fpcheck_artifact_sha256"])}
    for collection, table, timestamp, identifier in (
        ("findings", "cba_firmware_findings", "derived_at", "finding_id"),
        ("surfaces", "cba_firmware_surfaces", "recorded_at", "surface_id"),
        ("unknowns", "cba_unknowns", "recorded_at", "id"),
        ("pivots", "cba_firmware_pivots", "recorded_at", "pivot_id")):
        records = surface._query(con, f"SELECT * FROM {table} WHERE image_id=? ORDER BY {identifier}", (result.image_id,))
        rebuilt[collection] = []
        for row in records:
            if collection == "surfaces" and row["surface_id"] not in surfaces:
                continue
            if collection == "unknowns" and row["surface_id"] not in surfaces and row["component_path"] not in components:
                continue
            db.TABLE_SPECS[table].validate(row)
            row.pop(timestamp)
            if collection == "findings":
                for field in ("contributors", "lanes", "component_paths", "surface_ids"):
                    row[field] = json.loads(row[field])
                components.update(row["component_paths"])
                surfaces.update(row["surface_ids"])
                if (row["artifact_path"], row["artifact_sha256"]) != (str(expected_artifact), run["fpcheck_artifact_sha256"]):
                    raise FirmwareChainError("Finding artifact ownership differs")
            if collection in ("findings", "pivots") and row["candidate_snapshot_sha256"] != result.candidate_snapshot_sha256:
                raise FirmwareChainError("Foreign candidate snapshot")
            row["artifact_path"] = pathlib.Path(row["artifact_path"]).relative_to(run_dir).as_posix()
            ownership = row["artifact_path"], row["artifact_sha256"]
            if ownership not in checked_artifacts:
                _retained_bytes(run_dir, *ownership)
                checked_artifacts.add(ownership)
            if collection == "pivots":
                row["context_only"] = True
            rebuilt[collection].append(row)
        if run[collection[:-1] + "_count" if collection != "unknowns" else "unknown_count"] != len(rebuilt[collection]):
            raise FirmwareChainError("Prepared evidence counts differ")
    if (type(rebuilt["schema_version"]) is not int or rebuilt["schema_version"] != 1
            or _json_bytes(rebuilt) != content):
        raise FirmwareChainError("Prepared evidence differs from current SQL")
    canonical = json.loads(artifact, object_pairs_hook=_pairs, parse_constant=_constant)
    expected = dict(schema_version=1, image_id=result.image_id, candidate_snapshot_sha256=result.candidate_snapshot_sha256,
        worklist_sha256=review["worklist_sha256"], results=[dict(batch_path=r["batch_path"], result_sha256=r["result_sha256"]) for r in receipts],
        findings=[{key: value for key, value in row.items() if key not in ("artifact_path", "artifact_sha256")} for row in sorted(rebuilt["findings"], key=lambda r: r["root_cause_key"])])
    if canonical != expected or _json_bytes(expected) != artifact or len(receipts) != review["batch_count"]:
        raise FirmwareChainError("Canonical findings artifact differs from current review")
    return rebuilt


def _validate_graph(result: GraphResult, frozen: dict) -> ValidatedGraph:
    findings = {row["finding_id"]: row for row in frozen["findings"]}
    surfaces = {row["surface_id"]: row for row in frozen["surfaces"]}
    unknowns = {row["id"]: row for row in frozen["unknowns"]}
    pivots = {row["pivot_id"] for row in frozen["pivots"]}
    blockers = {row.blocker_key: row for row in result.blockers}
    blocker_ids = {key: canonical_blocker_id(result.image_id, result.candidate_snapshot_sha256, b) for key, b in blockers.items()}
    chain_ids = {c.chain_key: canonical_chain_id(result.image_id, result.candidate_snapshot_sha256, c, blocker_ids) for c in result.chains}
    memberships = {identifier: set() for identifier in findings}
    for chain in result.chains:
        for identifier in chain.member_ids:
            if identifier not in findings or identifier in pivots:
                raise FirmwareChainError("Chain members must be current reviewed findings")
            memberships[identifier].add(chain.chain_key)
    if {d.finding_id for d in result.dispositions} != findings.keys():
        raise FirmwareChainError("Dispositions must cover every reviewed finding exactly")

    def open_unknown(identifier):
        if identifier not in unknowns or unknowns[identifier]["status"] != "open" or identifier in pivots:
            raise FirmwareChainError("Blocker must be a current open unknown")
        return unknowns[identifier]

    def evidence(refs, *, owner=None, initial=False):
        texts = []
        for ref in refs:
            kind, identifier, field = _EVIDENCE_PATTERN.fullmatch(ref).groups()
            if identifier in pivots:
                raise FirmwareChainError("Pivots cannot supply evidence")
            rows = {"finding": findings, "surface": surfaces, "unknown": unknowns}[kind]
            if identifier not in rows:
                raise FirmwareChainError("Unresolved or foreign evidence reference")
            if kind == "finding" and identifier != owner:
                raise FirmwareChainError("Evidence must be owned by the specified finding")
            if initial and kind == "surface" and identifier not in findings[owner]["surface_ids"]:
                raise FirmwareChainError("Initial surface evidence must belong to the first finding")
            if kind == "unknown" and rows[identifier]["status"] != "resolved":
                raise FirmwareChainError("Only resolved unknowns can supply evidence")
            texts.append(_text(rows[identifier][field], "retained evidence"))
        return texts

    for blocker in result.blockers:
        if not set(blocker.affected_finding_ids) <= findings.keys() or set(blocker.affected_finding_ids) & pivots:
            raise FirmwareChainError("Blocker affected findings must be reviewed findings")
    dispositions = []
    for d in result.dispositions:
        if set(d.chain_keys) != memberships[d.finding_id] or (bool(d.chain_keys) != (d.disposition == "chained")):
            raise FirmwareChainError("Disposition membership differs from graph membership")
        if not set(d.pivot_followup_ids) <= pivots:
            raise FirmwareChainError("Unknown pivot follow-up")
        for identifier in d.existing_unknown_ids:
            open_unknown(identifier)
        for key in d.blocker_keys:
            if d.finding_id not in blockers[key].affected_finding_ids:
                raise FirmwareChainError("Disposition blocker does not affect its finding")
        dispositions.append(ValidatedDisposition(result.image_id, d.finding_id, result.candidate_snapshot_sha256,
            d.disposition, d.explanation, _cell(sorted(chain_ids[k] for k in d.chain_keys)),
            _cell(d.existing_unknown_ids), _cell(sorted(blocker_ids[k] for k in d.blocker_keys)), _cell(d.pivot_followup_ids)))
    validated_chains, validated_edges = [], []
    for chain in result.chains:
        evidence(chain.initial_evidence_refs, owner=chain.member_ids[0], initial=True)
        carried = dataclasses.asdict(chain.initial_state)
        chain_unknowns, chain_blockers = set(), set()
        # Finding-level blockers are conservatively relevant even when the worker
        # omits a corresponding edge reference or disposition annotation.
        for b in result.blockers:
            if set(b.affected_finding_ids) & set(chain.member_ids) or any(r.chain_key == chain.chain_key for r in b.affected_edges):
                chain_blockers.add(blocker_ids[b.blocker_key])
        for d in result.dispositions:
            if d.finding_id in chain.member_ids:
                chain_unknowns.update(d.existing_unknown_ids)
                chain_blockers.update(blocker_ids[k] for k in d.blocker_keys)
        for ordinal, edge in enumerate(chain.edges):
            producer = evidence(edge.producer_evidence_refs, owner=edge.producer_finding_id)
            consumer = evidence(edge.consumer_evidence_refs, owner=edge.consumer_finding_id)
            evidence(edge.supplemental_evidence_refs)
            for claim in (edge.produced_capability, edge.required_precondition):
                if claim.strip().casefold().rstrip('.!') in _GENERIC_CLAIMS:
                    raise FirmwareChainError("Generic transition claim")
            if edge.capability_kind == "other-specific":
                parts = edge.link_key.split(":", 1)
                generic = {"generic", "other", "access", "capability", "resource", "state", "unknown", "any"}
                if (len(parts) != 2 or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", parts[0]) is None
                        or not parts[1].strip() or any(p.strip().casefold() in generic for p in parts)):
                    raise FirmwareChainError("other-specific requires a concrete namespace-like link key")
            required, after = dataclasses.asdict(edge.required_state), dataclasses.asdict(edge.result_state)
            for axis, value in required.items():
                if value != "any" and value != carried[axis]:
                    raise FirmwareChainError("State requirement is not satisfied by the carried state")
            if edge.transition_kind == "direct":
                if any(after[axis] not in ("unchanged", carried[axis]) for axis in ("lifecycle", "posture")):
                    raise FirmwareChainError("Direct edge cannot change lifecycle or posture")
            else:
                # This is an explicit-boundary presence check, not a prose truth
                # oracle. Both retained sides must name the claimed boundary.
                pattern = _BOUNDARY_TERMS[edge.transition_kind]
                if not all(any(re.search(pattern, text, re.IGNORECASE) for text in side) for side in (producer, consumer)):
                    raise FirmwareChainError("Transition boundary requires explicit producer and consumer evidence")
            carried.update({axis: value for axis, value in after.items() if value != "unchanged"})
            for ref in edge.existing_unknowns:
                unknown = open_unknown(ref.unknown_id)
                if ref.axes != (_UNKNOWN_AXES.get(unknown["field"], "reachability"),):
                    raise FirmwareChainError("Unknown axes differ from the frozen field mapping")
                chain_unknowns.add(ref.unknown_id)
            for key in edge.blocker_keys:
                b = blockers[key]
                if (AffectedEdgeRef(chain.chain_key, ordinal) not in b.affected_edges and
                        not set(b.affected_finding_ids) & {edge.producer_finding_id, edge.consumer_finding_id}):
                    raise FirmwareChainError("Edge blocker does not affect this edge")
                chain_blockers.add(blocker_ids[key])
            row = dataclasses.asdict(edge)
            del row["blocker_keys"]
            for key in ("producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs", "required_state", "result_state", "existing_unknowns"):
                row[key] = _cell(row[key])
            validated_edges.append(ValidatedEdge(image_id=result.image_id, chain_id=chain_ids[chain.chain_key], ordinal=ordinal,
                candidate_snapshot_sha256=result.candidate_snapshot_sha256, blocker_ids=_cell(sorted(blocker_ids[k] for k in edge.blocker_keys)), **row))
        blocked = bool(chain_unknowns or chain_blockers)
        pre_auth = "no" if chain.initial_state.authentication != "pre-auth" else "unknown" if blocked else "yes"
        validated_chains.append(ValidatedChain(result.image_id, chain_ids[chain.chain_key], result.candidate_snapshot_sha256,
            chain.title, chain.summary, _cell(chain.member_ids), chain.initial_attacker_position, _cell(chain.initial_evidence_refs),
            chain.initial_state.lifecycle, chain.initial_state.posture, chain.initial_state.authentication, pre_auth,
            min([findings[f]["confidence"] for f in chain.member_ids] + [e.confidence for e in chain.edges]),
            "blocked" if blocked else "complete", _cell(sorted(chain_unknowns)), _cell(sorted(chain_blockers)), "static-chained"))
    validated_blockers = tuple(ValidatedBlocker(result.image_id, blocker_ids[b.blocker_key], result.candidate_snapshot_sha256,
        b.question, b.settling_observation, b.method, _cell(b.axes), _cell(b.affected_finding_ids),
        _cell(sorted((dict(chain_id=chain_ids[r.chain_key], ordinal=r.ordinal) for r in b.affected_edges),
                     key=lambda r: (r["chain_id"], r["ordinal"]))), "open") for b in result.blockers)
    return ValidatedGraph(result, tuple(sorted(blocker_ids.items())), tuple(sorted(chain_ids.items())),
        tuple(dispositions), validated_blockers, tuple(validated_chains), tuple(validated_edges))


def validate(con, run_dir: str | pathlib.Path, result: GraphResult) -> ValidatedGraph:
    """Prove current ownership, coverage, transitions and conservative derivation.

    No writes, artifact installs, or live-root reads occur. An owned read snapshot
    is ended only when this call opened it; caller transactions remain untouched.
    """
    import sqlite3
    owned = False
    try:
        if not isinstance(result, GraphResult):
            raise FirmwareChainError("Expected a GraphResult")
        # Frozen dataclasses can also be built directly: recheck their full wire
        # contract rather than trusting that every caller used load().
        result = _parse(json.loads(canonical_bytes(result)))
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        frozen = _prepared_evidence(con, pathlib.Path(run_dir).absolute(), result)
        return _validate_graph(result, frozen)
    except sqlite3.Error as exc:
        raise FirmwareChainError("database operation failed") from exc
    except (OSError, ValueError, KeyError, TypeError, db.DbError) as exc:
        raise FirmwareChainError("Cannot validate firmware chain evidence") from exc
    finally:
        if owned:
            con.rollback()


@dataclasses.dataclass(frozen=True, slots=True)
class ImportSummary:
    image_id: str
    finding_count: int
    disposition_count: int
    blocker_count: int
    chain_count: int
    edge_count: int
    complete_chains: int
    blocked_chains: int
    artifact_path: str


_GRAPH_TABLES = ("cba_firmware_chain_edges", "cba_firmware_chains", "cba_firmware_chain_dispositions",
                 "cba_firmware_chain_unknowns", "cba_firmware_chain_receipts")


def _publication_state(con, result: GraphResult, *, replace: bool) -> dict:
    """Retain selected-image rows so concurrent publication cannot be lost."""
    from audit_core import surface

    prior = {}
    for table in ("cba_firmware_chain_runs", *_GRAPH_TABLES):
        order = ",".join(db.TABLE_SPECS[table].primary_key)
        prior[table] = surface._query(con, f"SELECT * FROM {table} WHERE image_id=? ORDER BY {order}",
                                      (result.image_id,))
    for receipt in prior["cba_firmware_chain_receipts"]:
        if receipt["candidate_snapshot_sha256"] != result.candidate_snapshot_sha256:
            continue
        db.TABLE_SPECS["cba_firmware_chain_receipts"].validate(receipt)
        if receipt["worklist_sha256"] != result.worklist_sha256:
            raise FirmwareChainError("Existing chain receipt has different generation ownership")
        if not replace:
            raise FirmwareChainError("Chain result already imported; pass --replace to overwrite")
    return prior


def _result_directories(run_dir: pathlib.Path, destination: pathlib.Path) -> None:
    """Refuse symlinked artifact ancestors before and after installation."""
    parts = destination.relative_to(run_dir).parts
    for depth in range(len(parts) + 1):
        directory = run_dir.joinpath(*parts[:depth])
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise FirmwareChainError("Invalid firmware chain result directory")


def _checked_result_install(run_dir: pathlib.Path, destination: pathlib.Path, content: bytes) -> None:
    _result_directories(run_dir, destination)
    if not destination.is_dir() or {p.name for p in destination.iterdir()} != {"result.json"}:
        raise FirmwareChainError("Installed chain result has different artifacts")
    path = destination / "result.json"
    if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
        raise FirmwareChainError("Installed chain result differs before publication")


def record(con: sqlite3.Connection, run_dir: str | pathlib.Path,
           result_path: str | pathlib.Path, *, replace: bool = False) -> ImportSummary:
    """Install canonical result bytes, then atomically publish one owned graph.

    Retained provenance and selected-image state are rechecked under a write
    lock before any mutation. Failure can leave an unreferenced immutable result,
    but never a partial receipt, graph, or reset completion claim.
    """
    from audit_core import surface

    started = False
    try:
        if con.in_transaction:
            raise FirmwareChainError("Chain import requires a connection without an active transaction")
        run_dir = pathlib.Path(run_dir).absolute()
        validated = validate(con, run_dir, load(result_path))
        result = validated.result
        prior = _publication_state(con, result, replace=replace)
        content = canonical_bytes(result)
        digest = hashlib.sha256(content).hexdigest()
        destination = run_dir / "artifacts/firmware-chain" / result.worklist_sha256 / digest
        artifact_path = str(destination / "result.json")
        _result_directories(run_dir, destination)
        surface.atomic_install(destination, {"result.json": content})
        con.execute("BEGIN IMMEDIATE")
        started = True
        if (validate(con, run_dir, result) != validated or
                _publication_state(con, result, replace=replace) != prior):
            raise FirmwareChainError("Firmware chain inputs changed before publication")
        _checked_result_install(run_dir, destination, content)
        ownership = (result.image_id, result.candidate_snapshot_sha256)
        # Delete only the selected image's current candidate generation. A failed
        # insert or commit restores every prior row, including completion state.
        if replace:
            for table in _GRAPH_TABLES:
                con.execute(f"DELETE FROM {table} WHERE image_id=? AND candidate_snapshot_sha256=?", ownership)
        db.put(con, "cba_firmware_chain_receipts", dict(image_id=result.image_id,
            candidate_snapshot_sha256=result.candidate_snapshot_sha256, worklist_sha256=result.worklist_sha256,
            result_path=artifact_path, result_sha256=digest, disposition_count=len(validated.dispositions),
            blocker_count=len(validated.blockers), chain_count=len(validated.chains), edge_count=len(validated.edges)),
            commit=False)
        provenance = dict(artifact_path=artifact_path, artifact_sha256=digest)
        for records, table in ((validated.dispositions, "cba_firmware_chain_dispositions"),
                               (validated.blockers, "cba_firmware_chain_unknowns"),
                               (validated.chains, "cba_firmware_chains"),
                               (validated.edges, "cba_firmware_chain_edges")):
            for row in records:
                db.put(con, table, dataclasses.asdict(row) | provenance, commit=False)
        con.execute("UPDATE cba_firmware_chain_runs SET status='pending',graph_path=NULL,graph_sha256=NULL,"
                    "completed_at=NULL WHERE image_id=? AND candidate_snapshot_sha256=? AND worklist_sha256=?",
                    (*ownership, result.worklist_sha256))
        con.commit()
        return ImportSummary(result.image_id, len(validated.dispositions), len(validated.dispositions),
            len(validated.blockers), len(validated.chains), len(validated.edges),
            sum(c.completeness == "complete" for c in validated.chains),
            sum(c.completeness == "blocked" for c in validated.chains), artifact_path)
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise FirmwareChainError("database operation failed") from exc
        if isinstance(exc, (OSError, surface.SurfaceError)):
            raise FirmwareChainError("Cannot publish firmware chain result") from exc
        raise
