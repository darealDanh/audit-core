"""Strict Stage 4i worker decisions and artifact-first result publication.

Workers rank and explain exact frozen chains and propose inert bench material.
This module never derives policy matches, payout projections, or recommendations.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3

from audit_core import db, firmware_decide as decide, firmware_dive as dive, surface
from audit_core import firmware_dive_questions as dive_questions


RESULT_SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024
MAX_ARRAY_ITEMS = 4096
MAX_SCRIPTS = 16
MAX_SCRIPT_BYTES = 32 * 1024
MAX_SCRIPT_TOTAL_BYTES = 256 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SCRIPT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_TEST_ID = re.compile(r"firmware-decide-test-[0-9a-f]{64}")
_REFERENCE = re.compile(r"[A-Za-z][A-Za-z0-9-]*:[^\x00\r\n#]{1,4096}#[A-Za-z0-9._:-]{1,128}")
_DISPOSITIONS = ("bench-priority", "retain", "deprioritize")


class FirmwareDecideResultError(ValueError):
    """A worker result violates structural or frozen assignment authority."""


@dataclasses.dataclass(frozen=True, slots=True)
class PreconditionLocation:
    chain_id: str
    edge_ordinal: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class OpenPrecondition:
    kind: str
    precondition_id: str
    source_id: str
    question: str
    settling_observation: str
    method: str
    axes: tuple[str, ...]
    locations: tuple[PreconditionLocation, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ChainAssessment:
    chain_id: str
    rank: int
    initial_attacker_position: str
    pre_auth: str
    confidence: int
    completeness: str
    evidence_rung: str
    member_ids: tuple[str, ...]
    edge_ordinals: tuple[int, ...]
    open_preconditions: tuple[OpenPrecondition, ...]
    disposition: str
    rationale: str
    limitations: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class RequiredState:
    device: str
    firmware: str
    lifecycle: str
    posture: str
    authentication: str


@dataclasses.dataclass(frozen=True, slots=True)
class BenchTest:
    test_id: str
    chain_ids: tuple[str, ...]
    subject_refs: tuple[str, ...]
    title: str
    purpose: str
    required_state: RequiredState
    setup_steps: tuple[str, ...]
    action_steps: tuple[str, ...]
    expected_signal: str
    control_observation: str
    stop_conditions: tuple[str, ...]
    limitations: tuple[str, ...]
    script_name: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class ProposedScript:
    name: str
    content: str


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionAnswer:
    chain_assessments: tuple[ChainAssessment, ...]
    bench_tests: tuple[BenchTest, ...]
    proposed_scripts: tuple[ProposedScript, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class EmptyDecisionAnswer:
    """Explicit zero-chain result variant."""


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionResult:
    schema_version: int
    image_id: str
    decision_generation: str
    worklist_sha256: str
    answer: DecisionAnswer | EmptyDecisionAnswer


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedScript:
    name: str
    content: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedDecisionResult:
    image_id: str
    decision_generation: str
    worklist_sha256: str
    result_bytes: bytes
    result_sha256: str
    chain_assessments: tuple[ChainAssessment, ...]
    open_preconditions: tuple[OpenPrecondition, ...]
    bench_tests: tuple[BenchTest, ...]
    scripts: tuple[ValidatedScript, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionRecordSummary:
    image_id: str
    decision_generation: str
    result_path: str
    result_sha256: str
    chain_count: int
    bench_test_count: int
    script_count: int
    recorded: bool


def _fail(message: str):
    raise FirmwareDecideResultError(message)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate key: {key}")
        value[key] = item
    return value


def _object(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail(f"{label} keys differ")
    return value


def _digest(value, label="digest"):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        _fail(f"{label} requires a lowercase SHA-256")
    return value


def _identifier(value, label):
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(f"{label} requires a safe identifier")
    return value


def _image(value):
    if not isinstance(value, str) or not value or "\0" in value:
        _fail("image_id requires nonempty UTF-8 without NUL")
    try:
        raw = value.encode("utf-8")
    except UnicodeError as exc:
        raise FirmwareDecideResultError("image_id requires UTF-8") from exc
    if len(raw) > 4096:
        _fail("image_id exceeds byte bound")
    return value


def _text(value, label, *, maximum=MAX_TEXT_BYTES):
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        _fail(f"{label} requires nonempty text without NUL")
    try:
        raw = value.encode("utf-8")
    except UnicodeError as exc:
        raise FirmwareDecideResultError(f"{label} requires UTF-8") from exc
    if len(raw) > maximum or any(ord(char) < 0x20 and char not in "\n\t" for char in value):
        _fail(f"{label} exceeds text bounds")
    return value


def _integer(value, label, *, minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{label} requires a bounded integer without coercion")
    return value


def _copied_text(value, label):
    """Preserve frozen upstream text exactly, bounded by the artifact read cap.

    Stage 4g and Stage 4d accept these copied facts without Stage 4i's stricter
    worker-prose rules, so CR/LF and text beyond MAX_TEXT_BYTES must stay
    recordable byte-for-byte while NUL and non-UTF-8 remain invalid. The
    enclosing 8 MiB result/worklist read cap bounds the bytes.
    """
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        _fail(f"{label} requires nonempty copied text without NUL")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise FirmwareDecideResultError(f"{label} requires UTF-8") from exc
    return value


def _ordered_unique(values, label, parser, *, maximum=MAX_ARRAY_ITEMS, nonempty=False):
    """Validate an order-preserving copied sequence; graph order stays authority."""
    if not isinstance(values, list) or len(values) > maximum or (nonempty and not values):
        _fail(f"{label} requires a bounded ordered array")
    parsed = tuple(parser(value) for value in values)
    if len(set(parsed)) != len(parsed):
        _fail(f"{label} requires unique entries")
    return parsed


def _sorted_unique(values, label, parser, *, maximum=MAX_ARRAY_ITEMS, nonempty=False, key=None):
    if not isinstance(values, list) or len(values) > maximum or (nonempty and not values):
        _fail(f"{label} requires a bounded array")
    parsed = tuple(parser(value) for value in values)
    identities = tuple((key(value) if key else value) for value in parsed)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        _fail(f"{label} requires sorted unique entries")
    return parsed


def _ordered_text(values, label, *, maximum=256, nonempty=False):
    if not isinstance(values, list) or len(values) > maximum or (nonempty and not values):
        _fail(f"{label} requires a bounded ordered array")
    parsed = tuple(_text(value, label) for value in values)
    if len(set(parsed)) != len(parsed):
        _fail(f"{label} requires unique steps")
    return parsed


def _reference(value):
    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        _fail("evidence reference is invalid")
    return value


def _script_name(value, *, optional=False):
    if value is None and optional:
        return None
    if (not isinstance(value, str) or _SCRIPT_NAME.fullmatch(value) is None
            or value in (".", "..") or "/" in value or "\\" in value):
        _fail("script name requires a safe relative basename")
    return value


def _location(value):
    row = _object(value, ("chain_id", "edge_ordinal"), "precondition location")
    ordinal = row["edge_ordinal"]
    if ordinal is not None:
        ordinal = _integer(ordinal, "edge_ordinal")
    return PreconditionLocation(_identifier(row["chain_id"], "chain_id"), ordinal)


def _precondition(value):
    row = _object(value, (
        "kind", "precondition_id", "source_id", "question",
        "settling_observation", "method", "axes", "locations"), "open precondition")
    kind = row["kind"]
    if kind not in ("blocker", "unknown"):
        _fail("open precondition kind is invalid")
    source = _identifier(row["source_id"], "source_id")
    if row["precondition_id"] != f"{kind}:{source}":
        _fail("precondition identity differs from kind and source")
    method = row["method"]
    if method not in db.UNKNOWN_METHODS:
        _fail("open precondition method is invalid")
    axes = _sorted_unique(row["axes"], "precondition axes",
                          lambda item: _identifier(item, "axis"))
    locations = _sorted_unique(
        row["locations"], "precondition locations", _location, nonempty=True,
        key=lambda item: (item.chain_id, -1 if item.edge_ordinal is None else item.edge_ordinal))
    return OpenPrecondition(kind, row["precondition_id"], source,
        _copied_text(row["question"], "precondition question"),
        _copied_text(row["settling_observation"], "settling observation"),
        method, axes, locations)


def _assessment(value):
    row = _object(value, (
        "chain_id", "rank", "initial_attacker_position", "pre_auth",
        "confidence", "completeness", "evidence_rung", "member_ids",
        "edge_ordinals", "open_preconditions", "disposition", "rationale",
        "limitations", "evidence_refs"), "chain assessment")
    disposition = row["disposition"]
    if disposition not in _DISPOSITIONS:
        _fail("chain disposition is invalid")
    pre_auth = row["pre_auth"]
    if pre_auth not in db.FIRMWARE_CHAIN_PRE_AUTH:
        _fail("pre_auth is invalid")
    completeness = row["completeness"]
    if completeness not in db.FIRMWARE_CHAIN_COMPLETENESS:
        _fail("completeness is invalid")
    rung = row["evidence_rung"]
    if rung not in db.FIRMWARE_CHAIN_EVIDENCE_RUNGS:
        _fail("evidence_rung is invalid")
    return ChainAssessment(
        _identifier(row["chain_id"], "chain_id"),
        _integer(row["rank"], "rank", minimum=1),
        _copied_text(row["initial_attacker_position"], "initial_attacker_position"),
        pre_auth, _integer(row["confidence"], "confidence", maximum=10),
        completeness, rung,
        _ordered_unique(row["member_ids"], "member_ids",
                        lambda item: _identifier(item, "member_id"), nonempty=True),
        _sorted_unique(row["edge_ordinals"], "edge_ordinals",
                       lambda item: _integer(item, "edge ordinal")),
        _sorted_unique(row["open_preconditions"], "open_preconditions",
                       _precondition, key=lambda item: item.precondition_id),
        disposition, _text(row["rationale"], "rationale"),
        _sorted_unique(row["limitations"], "assessment limitations",
                       lambda item: _text(item, "assessment limitation")),
        _sorted_unique(row["evidence_refs"], "assessment evidence_refs",
                       _reference, nonempty=True))


def _state(value):
    row = _object(value, (
        "device", "firmware", "lifecycle", "posture", "authentication"),
        "required state")
    return RequiredState(*(_text(row[key], f"required state {key}", maximum=4096)
                           for key in ("device", "firmware", "lifecycle", "posture", "authentication")))


def _bench_wire(value: BenchTest, *, include_id=True):
    body = {
        "chain_ids": list(value.chain_ids),
        "subject_refs": list(value.subject_refs),
        "title": value.title,
        "purpose": value.purpose,
        "required_state": dataclasses.asdict(value.required_state),
        "setup_steps": list(value.setup_steps),
        "action_steps": list(value.action_steps),
        "expected_signal": value.expected_signal,
        "control_observation": value.control_observation,
        "stop_conditions": list(value.stop_conditions),
        "limitations": list(value.limitations),
        "script_name": value.script_name,
    }
    if include_id:
        body = {"test_id": value.test_id, **body}
    return body


def _bench_identity(value: BenchTest):
    return "firmware-decide-test-" + hashlib.sha256(
        json.dumps(_bench_wire(value, include_id=False), ensure_ascii=False,
                   allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _bench(value):
    row = _object(value, (
        "test_id", "chain_ids", "subject_refs", "title", "purpose",
        "required_state", "setup_steps", "action_steps", "expected_signal",
        "control_observation", "stop_conditions", "limitations", "script_name"),
        "bench test")
    if not isinstance(row["test_id"], str) or _TEST_ID.fullmatch(row["test_id"]) is None:
        _fail("test_id is invalid")
    test = BenchTest(
        row["test_id"],
        _sorted_unique(row["chain_ids"], "bench chain_ids",
                       lambda item: _identifier(item, "chain_id"), nonempty=True),
        _sorted_unique(row["subject_refs"], "bench subject_refs",
                       lambda item: _text(item, "subject reference", maximum=4096), nonempty=True),
        _text(row["title"], "bench title"), _text(row["purpose"], "bench purpose"),
        _state(row["required_state"]),
        _ordered_text(row["setup_steps"], "setup_steps", nonempty=True),
        _ordered_text(row["action_steps"], "action_steps", nonempty=True),
        _text(row["expected_signal"], "expected_signal"),
        _text(row["control_observation"], "control_observation"),
        _ordered_text(row["stop_conditions"], "stop_conditions", nonempty=True),
        _sorted_unique(row["limitations"], "bench limitations",
                       lambda item: _text(item, "bench limitation")),
        _script_name(row["script_name"], optional=True))
    return test


def _script(value):
    row = _object(value, ("name", "content"), "proposed script")
    name = _script_name(row["name"])
    content = row["content"]
    if not isinstance(content, str) or "\0" in content:
        _fail("proposed script requires embedded UTF-8 text without NUL")
    try:
        raw = content.encode("utf-8")
    except UnicodeError as exc:
        raise FirmwareDecideResultError("proposed script requires UTF-8") from exc
    if len(raw) > MAX_SCRIPT_BYTES:
        _fail("proposed script exceeds 32 KiB")
    return ProposedScript(name, content)


def _answer(value):
    if not isinstance(value, dict) or value.get("kind") not in ("decision", "empty"):
        _fail("answer requires an explicit decision or empty variant")
    if value["kind"] == "empty":
        _object(value, ("kind",), "empty answer")
        return EmptyDecisionAnswer()
    row = _object(value, ("kind", "chain_assessments", "bench_tests", "proposed_scripts"),
                  "decision answer")
    assessments = _sorted_unique(
        row["chain_assessments"], "chain_assessments", _assessment, nonempty=True,
        key=lambda item: item.chain_id)
    tests = _sorted_unique(row["bench_tests"], "bench_tests", _bench,
                           key=lambda item: item.test_id)
    scripts = _sorted_unique(row["proposed_scripts"], "proposed_scripts", _script,
                             maximum=MAX_SCRIPTS, key=lambda item: item.name)
    # Script names become sibling files under bench/; a case-insensitive
    # filesystem would alias names that differ only by case.
    if len({item.name.casefold() for item in scripts}) != len(scripts):
        _fail("proposed script names collide without case sensitivity")
    if sum(len(item.content.encode("utf-8")) for item in scripts) > MAX_SCRIPT_TOTAL_BYTES:
        _fail("proposed scripts exceed 256 KiB total")
    return DecisionAnswer(assessments, tests, scripts)


def _parse(raw: bytes) -> DecisionResult:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda token: _fail(f"non-finite value: {token}"))
    except FirmwareDecideResultError:
        raise
    except (ValueError, RecursionError) as exc:
        raise FirmwareDecideResultError("result requires strict UTF-8 JSON") from exc
    row = _object(value, (
        "schema_version", "image_id", "decision_generation",
        "worklist_sha256", "answer"), "decision result")
    if type(row["schema_version"]) is not int or row["schema_version"] != RESULT_SCHEMA_VERSION:
        _fail("schema_version must equal 1")
    generation = _digest(row["decision_generation"], "decision_generation")
    worklist = _digest(row["worklist_sha256"], "worklist_sha256")
    if generation != worklist:
        _fail("decision generation must equal worklist SHA-256")
    return DecisionResult(1, _image(row["image_id"]), generation, worklist,
                          _answer(row["answer"]))


def _precondition_wire(value: OpenPrecondition):
    return {
        "kind": value.kind,
        "precondition_id": value.precondition_id,
        "source_id": value.source_id,
        "question": value.question,
        "settling_observation": value.settling_observation,
        "method": value.method,
        "axes": list(value.axes),
        "locations": [dataclasses.asdict(item) for item in value.locations],
    }


def _assessment_wire(value: ChainAssessment):
    return {
        "chain_id": value.chain_id,
        "rank": value.rank,
        "initial_attacker_position": value.initial_attacker_position,
        "pre_auth": value.pre_auth,
        "confidence": value.confidence,
        "completeness": value.completeness,
        "evidence_rung": value.evidence_rung,
        "member_ids": list(value.member_ids),
        "edge_ordinals": list(value.edge_ordinals),
        "open_preconditions": [_precondition_wire(item) for item in value.open_preconditions],
        "disposition": value.disposition,
        "rationale": value.rationale,
        "limitations": list(value.limitations),
        "evidence_refs": list(value.evidence_refs),
    }


def _wire(result: DecisionResult):
    if not isinstance(result, DecisionResult):
        _fail("canonical bytes require a DecisionResult")
    if isinstance(result.answer, EmptyDecisionAnswer):
        answer = {"kind": "empty"}
    elif isinstance(result.answer, DecisionAnswer):
        answer = {
            "kind": "decision",
            "chain_assessments": [_assessment_wire(item) for item in result.answer.chain_assessments],
            "bench_tests": [_bench_wire(item) for item in result.answer.bench_tests],
            "proposed_scripts": [dataclasses.asdict(item) for item in result.answer.proposed_scripts],
        }
    else:
        _fail("result answer variant is invalid")
    return {
        "schema_version": result.schema_version,
        "image_id": result.image_id,
        "decision_generation": result.decision_generation,
        "worklist_sha256": result.worklist_sha256,
        "answer": answer,
    }


def canonical_bytes(result: DecisionResult) -> bytes:
    try:
        raw = json.dumps(_wire(result), ensure_ascii=False, allow_nan=False,
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise FirmwareDecideResultError("result cannot be canonicalized") from exc
    if len(raw) > MAX_RESULT_BYTES:
        _fail("canonical result exceeds 8 MiB")
    return raw


def load(path: str | pathlib.Path) -> DecisionResult:
    try:
        raw = decide._read_stable_file(path, MAX_RESULT_BYTES)
    except OSError as exc:
        raise FirmwareDecideResultError("cannot read decision result") from exc
    if len(raw) > MAX_RESULT_BYTES:
        _fail("result exceeds 8 MiB")
    result = _parse(raw)
    canonical_bytes(result)
    return result


def _strict_json(raw: bytes, label):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda token: _fail(f"non-finite value: {token}"))
    except FirmwareDecideResultError:
        raise
    except (ValueError, RecursionError) as exc:
        raise FirmwareDecideResultError(f"{label} requires strict UTF-8 JSON") from exc


def _assignment(con, run: pathlib.Path, result: DecisionResult):
    rows = surface._query(con,
        "SELECT * FROM cba_firmware_decide_runs WHERE image_id=? AND decision_generation=?",
        (result.image_id, result.decision_generation))
    if len(rows) != 1:
        _fail("exactly one decision assignment is required")
    row = rows[0]
    db.TABLE_SPECS["cba_firmware_decide_runs"].validate(row)
    if row["worklist_sha256"] != result.worklist_sha256:
        _fail("result differs from assignment worklist")
    raw = dive._read(run, row["worklist_path"], row["worklist_sha256"])
    worklist = _strict_json(raw, "worklist")
    if decide._canonical(worklist) != raw:
        _fail("installed decision worklist is not canonical")
    _object(worklist, (
        "schema_version", "image_id", "technical_provenance", "graph",
        "dive", "open_preconditions", "policy"), "decision worklist")
    if worklist["schema_version"] != 1 or worklist["image_id"] != row["image_id"]:
        _fail("worklist identity differs from assignment")
    provenance = worklist["technical_provenance"]
    _object(provenance, (
        "manifest_sha256", "surface_snapshot_sha256", "candidate_snapshot_sha256",
        "chain_worklist_sha256", "graph_path", "graph_sha256"), "technical provenance")
    for key, value in provenance.items():
        if row[key] != value:
            _fail("worklist technical provenance differs from assignment")
    dive_projection = worklist["dive"]
    _object(dive_projection, (
        "dive_generation", "journal_path", "journal_sha256", "overlay_sha256", "overlay"),
        "dive projection")
    for key in ("dive_generation", "journal_path", "journal_sha256", "overlay_sha256"):
        if row[key] != dive_projection[key]:
            _fail("worklist dive provenance differs from assignment")
    policy_projection = worklist["policy"]
    _object(policy_projection, ("policy_id", "path", "sha256", "projection"), "policy projection")
    if (policy_projection["policy_id"], policy_projection["sha256"]) != (
            row["policy_id"], row["policy_sha256"]):
        _fail("worklist policy provenance differs from assignment")
    if pathlib.PurePosixPath(row["policy_path"]).name != policy_projection["path"]:
        _fail("worklist policy path differs from assignment")
    policy_raw = dive._read(run, row["policy_path"], row["policy_sha256"])
    policy = decide._parse(policy_raw)
    canonical_policy_projection = json.loads(decide.policy_bytes(policy))
    if (decide.policy_bytes(policy) != policy_raw
            or canonical_policy_projection != policy_projection["projection"]):
        _fail("installed policy differs from worklist projection")
    graph = worklist["graph"]
    if not isinstance(graph, dict) or graph.get("image_id") != row["image_id"]:
        _fail("worklist graph identity differs from assignment")
    if graph.get("graph_path") != row["graph_path"] or graph.get("graph_sha256") != row["graph_sha256"]:
        _fail("worklist graph ownership differs from assignment")
    chains = graph.get("chains")
    if not isinstance(chains, list) or row["chain_count"] != len(chains):
        _fail("assignment chain count differs from frozen graph")
    return row, worklist


def _expected_preconditions(worklist):
    values = worklist["open_preconditions"]
    return _sorted_unique(values, "worklist open_preconditions", _precondition,
                          key=lambda item: item.precondition_id)


def _subject_evidence(refs):
    return [value for value in refs
            if re.fullmatch(r"dive:[0-9a-f]{64}#(?:conclusion|evidence)", value) is None]


def _chain_context(chain):
    return {
        key: (_subject_evidence(chain[key]) if key == "initial_evidence_refs" else chain[key])
        for key in ("member_ids", "initial_attacker_position", "initial_evidence_refs",
                    "initial_lifecycle", "initial_posture", "initial_authentication")
    }


def _edge_fingerprint(graph, chain, edge):
    fields = (
        "producer_finding_id", "consumer_finding_id", "capability_kind", "link_key",
        "producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs",
        "required_state", "result_state", "transition_kind")
    projection = {
        key: (_subject_evidence(edge[key]) if key.endswith("_evidence_refs") else edge[key])
        for key in fields
    }
    return dive_questions._hash({
        "image_id": graph["image_id"],
        "candidate_snapshot_sha256": graph["candidate_snapshot_sha256"],
        "context": _chain_context(chain),
        "edge": projection,
    })


def _chain_fingerprint(graph, chain, edges):
    return dive_questions._hash({
        "image_id": graph["image_id"],
        "candidate_snapshot_sha256": graph["candidate_snapshot_sha256"],
        "context": _chain_context(chain),
        "edges": [_edge_fingerprint(graph, chain, edge) for edge in edges],
    })


def _chain_evidence(graph, worklist, chain, preconditions):
    allowed = set(chain.get("initial_evidence_refs", ()))
    edges = sorted(
        (item for item in graph["edges"] if item["chain_id"] == chain["chain_id"]),
        key=lambda item: item["ordinal"])
    for edge in edges:
        for key in ("producer_evidence_refs", "consumer_evidence_refs", "supplemental_evidence_refs"):
            allowed.update(edge.get(key, ()))
    subject_tokens = {
        f"chain:{_chain_fingerprint(graph, chain, edges)}",
        *(f"edge:{_edge_fingerprint(graph, chain, edge)}" for edge in edges),
        *(f"finding:{identity}" for identity in chain["member_ids"]),
    }
    for item in preconditions:
        namespace = "chain-blocker" if item.kind == "blocker" else "surface-unknown"
        subject_tokens.add(f"{namespace}:{item.source_id}")
    overlay = worklist["dive"]["overlay"]
    if not isinstance(overlay, dict) or set(overlay) != {"schema_version", "observations"}:
        _fail("worklist dive overlay is invalid")
    for observation in overlay["observations"]:
        if not isinstance(observation, dict):
            _fail("worklist observation is invalid")
        subjects = set(observation.get("subject_refs", ())) | set(observation.get("settled_subject_refs", ()))
        if subjects & subject_tokens:
            identity = observation.get("observation_id")
            _digest(identity, "observation_id")
            allowed.add(f"dive:{identity}#conclusion")
            allowed.add(f"dive:{identity}#evidence")
    return allowed


def _validate_assessments(answer, worklist, expected_preconditions):
    graph = worklist["graph"]
    chains = graph.get("chains")
    edges = graph.get("edges")
    if not isinstance(chains, list) or not isinstance(edges, list):
        _fail("worklist graph collections are invalid")
    if not chains:
        if not isinstance(answer, EmptyDecisionAnswer):
            _fail("empty graph requires explicit empty decision answer")
        return ()
    if not isinstance(answer, DecisionAnswer):
        _fail("nonempty graph requires complete decision answer")
    expected_ids = [item.get("chain_id") for item in chains]
    actual_ids = [item.chain_id for item in answer.chain_assessments]
    if actual_ids != sorted(expected_ids) or set(actual_ids) != set(expected_ids):
        _fail("chain assessments do not exactly cover current chains")
    if {item.rank for item in answer.chain_assessments} != set(range(1, len(chains) + 1)):
        _fail("chain ranks must be exactly contiguous from one")
    by_id = {item["chain_id"]: item for item in chains}
    for assessment in answer.chain_assessments:
        chain = by_id[assessment.chain_id]
        expected_edges = tuple(sorted(item["ordinal"] for item in edges
                                      if item["chain_id"] == assessment.chain_id))
        copied = (
            assessment.initial_attacker_position, assessment.pre_auth,
            assessment.confidence, assessment.completeness, assessment.evidence_rung,
            assessment.member_ids, assessment.edge_ordinals)
        expected_copied = (
            chain["initial_attacker_position"], chain["pre_auth"],
            chain["confidence"], chain["completeness"], chain["evidence_rung"],
            tuple(chain["member_ids"]), expected_edges)
        if copied != expected_copied:
            _fail("chain assessment copied facts differ from frozen graph")
        denominator = tuple(item for item in expected_preconditions
            if any(location.chain_id == assessment.chain_id for location in item.locations))
        if assessment.open_preconditions != denominator:
            _fail("chain assessment open-precondition denominator differs")
        allowed = _chain_evidence(graph, worklist, chain, denominator)
        if not set(assessment.evidence_refs) <= allowed:
            _fail("chain assessment cites foreign or inapplicable evidence")
    return answer.chain_assessments


def _subject_ownership(subject, graph, preconditions):
    """Return a subject's owning chains and its (subject, chain, edge) state requirements."""
    precondition = {item.precondition_id: item for item in preconditions}.get(subject)
    if precondition is not None:
        owners = {item.chain_id for item in precondition.locations}
        requirements = []
        for chain_id in sorted(owners):
            locations = [item for item in precondition.locations
                         if item.chain_id == chain_id]
            edge_locations = [item for item in locations
                              if item.edge_ordinal is not None]
            if not edge_locations:
                requirements.append((subject, chain_id, None))
                continue
            for location in edge_locations:
                edge = next((item for item in graph["edges"]
                    if item["chain_id"] == chain_id
                    and item["ordinal"] == location.edge_ordinal), None)
                if edge is None:
                    _fail("precondition location references a foreign edge")
                requirements.append((subject, chain_id, edge))
        return owners, tuple(requirements)
    match = re.fullmatch(r"transition:([A-Za-z0-9][A-Za-z0-9._:-]{0,127}):(0|[1-9][0-9]*)", subject)
    if match is None:
        _fail("bench subject is not a current precondition or transition")
    chain_id, ordinal_text = match.groups()
    ordinal = int(ordinal_text)
    edge = next((item for item in graph["edges"]
                 if item["chain_id"] == chain_id and item["ordinal"] == ordinal), None)
    if edge is None:
        _fail("bench transition subject is foreign")
    return {chain_id}, ((subject, chain_id, edge),)


def _validate_state(test, graph, subject_edges):
    initial_states = {
        item["chain_id"]: {
            "lifecycle": item["initial_lifecycle"],
            "posture": item["initial_posture"],
            "authentication": item["initial_authentication"],
        } for item in graph["chains"]
    }
    carried_states = {identity: dict(value) for identity, value in initial_states.items()}
    incoming_states = {}
    for edge in sorted(graph["edges"], key=lambda item: (item["chain_id"], item["ordinal"])):
        carried = carried_states[edge["chain_id"]]
        incoming_states[edge["chain_id"], edge["ordinal"]] = dict(carried)
        carried.update({axis: value for axis, value in edge["result_state"].items()
                        if value != "unchanged"})
    actual = {key: getattr(test.required_state, key)
              for key in ("lifecycle", "posture", "authentication")}
    if (test.required_state.device != graph["image_id"]
            or test.required_state.firmware != graph["candidate_snapshot_sha256"]):
        _fail("bench device or firmware state differs from frozen graph")
    grouped = {}
    for subject, chain_id, edge in subject_edges:
        grouped.setdefault((subject, chain_id), []).append(edge)
    for (_, chain_id), edges in grouped.items():
        initial = initial_states[chain_id]
        def matches(edge):
            required = edge["required_state"] if edge is not None else initial
            incoming = incoming_states[chain_id, edge["ordinal"]] if edge is not None else initial
            return all(
                value == (incoming[axis] if required[axis] == "any" else required[axis])
                for axis, value in actual.items())
        if not any(matches(edge) for edge in edges):
            _fail("bench required state differs from frozen subject state")


def _validate_bench(answer, worklist, preconditions):
    if isinstance(answer, EmptyDecisionAnswer):
        return (), ()
    graph = worklist["graph"]
    chain_ids = {item["chain_id"] for item in graph["chains"]}
    scripts = {item.name: item for item in answer.proposed_scripts}
    referenced_scripts = set()
    for test in answer.bench_tests:
        if test.test_id != _bench_identity(test):
            _fail("bench test identity differs from semantic content")
        if not set(test.chain_ids) <= chain_ids:
            _fail("bench test references a foreign chain")
        # A test may cover a subset of a shared subject's owners: it lists the
        # chains it exercises, and state authority comes only from those chains.
        listed = set(test.chain_ids)
        owned = set()
        subject_edges = []
        for subject in test.subject_refs:
            owners, requirements = _subject_ownership(subject, graph, preconditions)
            if not owners & listed:
                _fail("bench subject is not owned by a listed chain")
            owned.update(owners)
            subject_edges.extend(item for item in requirements if item[1] in listed)
        if not listed <= owned:
            _fail("bench chain ownership differs from subject ownership")
        _validate_state(test, graph, subject_edges)
        if test.script_name is not None:
            if test.script_name not in scripts:
                _fail("bench test references a missing proposed script")
            referenced_scripts.add(test.script_name)
    if referenced_scripts != set(scripts):
        _fail("every proposed script must be referenced by a bench test")
    validated = tuple(ValidatedScript(item.name, item.content.encode("utf-8"))
                      for item in answer.proposed_scripts)
    return answer.bench_tests, validated


def validate(con: sqlite3.Connection, run_dir: str | pathlib.Path,
             result: DecisionResult) -> ValidatedDecisionResult:
    """Validate exact pending-assignment semantics without writing SQL or files."""
    owned = False
    try:
        if not isinstance(result, DecisionResult):
            _fail("validate requires a DecisionResult")
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        run = dive._selector(run_dir)
        _, worklist = _assignment(con, run, result)
        expected_preconditions = _expected_preconditions(worklist)
        assessments = _validate_assessments(result.answer, worklist, expected_preconditions)
        tests, scripts = _validate_bench(result.answer, worklist, expected_preconditions)
        raw = canonical_bytes(result)
        return ValidatedDecisionResult(
            result.image_id, result.decision_generation, result.worklist_sha256,
            raw, hashlib.sha256(raw).hexdigest(), assessments,
            expected_preconditions, tests, scripts)
    except FirmwareDecideResultError:
        raise
    except (sqlite3.Error, db.DbError, OSError, ValueError, TypeError,
            KeyError, RecursionError, decide.FirmwareDecideError,
            dive.FirmwareDiveError, surface.SurfaceError) as exc:
        raise FirmwareDecideResultError("cannot validate firmware decision result") from exc
    finally:
        if owned:
            con.rollback()


def _record_summary(validated, relative, recorded):
    return DecisionRecordSummary(
        validated.image_id, validated.decision_generation, relative,
        validated.result_sha256, len(validated.chain_assessments),
        len(validated.bench_tests), len(validated.scripts), recorded)


def record(con: sqlite3.Connection, run_dir: str | pathlib.Path,
           result_path: str | pathlib.Path) -> DecisionRecordSummary:
    """Install canonical result bytes, then atomically publish recorded ownership."""
    started = False
    try:
        if con.in_transaction:
            _fail("decision result recording requires no active caller transaction")
        run = dive._selector(run_dir)
        con.execute("BEGIN")
        started = True
        first_result = load(result_path)
        first = validate(con, run, first_result)
        row, _ = _assignment(con, run, first_result)
        destination = (run / "artifacts" / "firmware-decide-results" /
                       first.decision_generation / first.result_sha256)
        contents = {"result.json": first.result_bytes}
        relative = (destination / "result.json").relative_to(run).as_posix()
        if row["status"] == "recorded":
            if (row["result_path"], row["result_sha256"]) != (relative, first.result_sha256):
                _fail("recorded decision result conflicts with canonical result")
            dive._checked_install(destination, contents, run)
            con.rollback()
            started = False
            return _record_summary(first, relative, True)
        if row["status"] != "pending":
            _fail("only a pending decision assignment can be recorded")
        con.rollback()
        started = False
        dive._install(destination, contents, run)

        con.execute("BEGIN IMMEDIATE")
        started = True
        current_result = load(result_path)
        current = validate(con, run, current_result)
        if current != first:
            _fail("decision result or assignment changed before publication")
        dive._checked_install(destination, contents, run)
        rows = surface._query(con,
            "SELECT * FROM cba_firmware_decide_runs WHERE image_id=? AND decision_generation=?",
            (first.image_id, first.decision_generation))
        row = rows[0]
        db.TABLE_SPECS["cba_firmware_decide_runs"].validate(row)
        if row["status"] == "recorded":
            if (row["result_path"], row["result_sha256"]) != (relative, first.result_sha256):
                _fail("recorded decision result conflicts with canonical result")
            con.rollback()
            started = False
            return _record_summary(first, relative, True)
        if row["status"] != "pending":
            _fail("only a pending decision assignment can be recorded")
        recorded_at = con.execute("SELECT datetime('now')").fetchone()[0]
        if not isinstance(row["prepared_at"], str) or recorded_at < row["prepared_at"]:
            _fail("decision recording timestamp precedes preparation")
        cursor = con.execute(
            "UPDATE cba_firmware_decide_runs SET status='recorded',result_path=?,"
            "result_sha256=?,recorded_at=? WHERE image_id=? AND decision_generation=? AND status='pending'",
            (relative, first.result_sha256, recorded_at,
             first.image_id, first.decision_generation))
        if cursor.rowcount != 1:
            _fail("decision assignment changed before publication")
        con.commit()
        started = False
        return _record_summary(first, relative, True)
    except FirmwareDecideResultError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareDecideResultError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            decide.FirmwareDecideError, dive.FirmwareDiveError,
            surface.SurfaceError) as exc:
        raise FirmwareDecideResultError("cannot record firmware decision result") from exc
    finally:
        if started:
            con.rollback()
