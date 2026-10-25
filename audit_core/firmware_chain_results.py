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
