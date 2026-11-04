"""Prepare and verify policy-bound firmware acquisition decisions.

Stage 4i keeps operator policy separate from technical evidence.  This module
owns policy parsing now; later tasks add current-input verification, immutable
preparation, deterministic completion, and the verified package boundary.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import re
import sqlite3

from audit_core import db, firmware_chain, firmware_dive, surface


class FirmwareDecideError(Exception):
    """Decision policy, provenance, or publication cannot be established."""


MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_TEXT = 4096
MAX_POLICY_NOTES = 64
MAX_PAYOUT_PATHS = 64
MAX_POLICY_TIERS = 128
MAX_MONEY_MINOR = 1_000_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


@dataclasses.dataclass(frozen=True, slots=True)
class PayoutPath:
    path_id: str
    status: str
    basis: str


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyTier:
    tier_id: str
    payout_path_id: str
    ordinal: int
    minimum_minor: int
    maximum_minor: int
    accepted_pre_auth: tuple[str, ...]
    minimum_confidence: int
    accepted_completeness: tuple[str, ...]
    accepted_evidence_rungs: tuple[str, ...]
    physical_access_allowed: bool


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionPolicy:
    schema_version: int
    policy_id: str
    currency: str
    acquisition_cost_minor: int
    max_acquisition_cost_minor: int
    support_status: str
    support_basis: str
    payout_paths: tuple[PayoutPath, ...]
    tiers: tuple[PolicyTier, ...]
    notes: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareDecisionInput:
    graph: firmware_chain.VerifiedFirmwareGraphSnapshot
    dive: firmware_dive.VerifiedDiveDecisionInput



@dataclasses.dataclass(frozen=True, slots=True)
class DecisionPreparationSummary:
    image_id: str
    decision_generation: str
    graph_sha256: str
    dive_generation: str
    overlay_sha256: str
    policy_id: str
    policy_path: str
    policy_sha256: str
    worklist_path: str
    worklist_sha256: str
    chain_count: int
    open_precondition_count: int

def _fail(message: str) -> None:
    raise FirmwareDecideError(message)


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


def _identifier(value, label):
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(f"{label} requires a safe identifier")
    return value


def _text(value, label):
    if (not isinstance(value, str) or not value.strip() or len(value) > MAX_POLICY_TEXT
            or any(ord(char) < 0x20 and char not in "\n\t" for char in value)):
        _fail(f"{label} requires bounded UTF-8 text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label} requires bounded UTF-8 text")
    return value


def _integer(value, label, maximum=MAX_MONEY_MINOR):
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(f"{label} requires an integer from 0 through {maximum}")
    return value


def _enum(value, allowed, label):
    if not isinstance(value, str) or value not in allowed:
        _fail(f"{label} is invalid")
    return value


def _strings(value, allowed, label):
    if (not isinstance(value, list) or not value or len(value) > len(allowed)
            or any(not isinstance(item, str) or item not in allowed for item in value)
            or value != sorted(set(value))):
        _fail(f"{label} requires sorted unique allowed values")
    return tuple(value)


def _wire(policy: DecisionPolicy):
    return dataclasses.asdict(policy)


def policy_bytes(policy: DecisionPolicy) -> bytes:
    if not isinstance(policy, DecisionPolicy):
        _fail("policy requires a frozen DecisionPolicy")
    try:
        return (json.dumps(_wire(policy), ensure_ascii=False, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FirmwareDecideError("policy cannot be canonicalized") from exc


def _parse(raw: bytes) -> DecisionPolicy:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda token: _fail(f"non-finite value: {token}"))
    except FirmwareDecideError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FirmwareDecideError("policy requires canonical UTF-8 JSON") from exc
    top = _object(value, (
        "schema_version", "policy_id", "currency", "acquisition_cost_minor",
        "max_acquisition_cost_minor", "support_status", "support_basis",
        "payout_paths", "tiers", "notes"), "policy")
    if type(top["schema_version"]) is not int or top["schema_version"] != 1:
        _fail("schema_version must equal 1")
    policy_id = _identifier(top["policy_id"], "policy_id")
    currency = top["currency"]
    if not isinstance(currency, str) or re.fullmatch(r"[A-Z]{3}", currency) is None:
        _fail("currency requires three uppercase ASCII letters")
    acquisition = _integer(top["acquisition_cost_minor"], "acquisition_cost_minor")
    maximum = _integer(top["max_acquisition_cost_minor"], "max_acquisition_cost_minor")
    support = _enum(top["support_status"], db.FIRMWARE_DECIDE_SUPPORT, "support_status")
    support_basis = _text(top["support_basis"], "support_basis")

    raw_paths = top["payout_paths"]
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= MAX_PAYOUT_PATHS:
        _fail("payout_paths requires 1-64 entries")
    paths = []
    for raw_path in raw_paths:
        item = _object(raw_path, ("path_id", "status", "basis"), "payout_path")
        paths.append(PayoutPath(_identifier(item["path_id"], "path_id"),
            _enum(item["status"], db.FIRMWARE_DECIDE_PAYOUT_STATUS, "status"),
            _text(item["basis"], "basis")))
    if tuple(paths) != tuple(sorted(paths, key=lambda item: item.path_id)) or len({p.path_id for p in paths}) != len(paths):
        _fail("payout_paths requires sorted unique path_id values")
    path_ids = {item.path_id for item in paths}

    raw_tiers = top["tiers"]
    if not isinstance(raw_tiers, list) or not 1 <= len(raw_tiers) <= MAX_POLICY_TIERS:
        _fail("tiers requires 1-128 entries")
    tiers = []
    previous = {}
    for index, raw_tier in enumerate(raw_tiers):
        item = _object(raw_tier, (
            "tier_id", "payout_path_id", "ordinal", "minimum_minor",
            "maximum_minor", "accepted_pre_auth", "minimum_confidence",
            "accepted_completeness", "accepted_evidence_rungs",
            "physical_access_allowed"), "tier")
        tier_id = _identifier(item["tier_id"], "tier_id")
        payout_path_id = _identifier(item["payout_path_id"], "payout_path_id")
        if payout_path_id not in path_ids:
            _fail("payout_path_id must reference a declared payout path")
        ordinal = _integer(item["ordinal"], "ordinal", MAX_POLICY_TIERS - 1)
        if ordinal != index:
            _fail("ordinal values must be contiguous from zero")
        minimum = _integer(item["minimum_minor"], "minimum_minor")
        maximum_minor = _integer(item["maximum_minor"], "maximum_minor")
        if minimum > maximum_minor:
            _fail("minimum_minor cannot exceed maximum_minor")
        prior = previous.get(payout_path_id)
        if prior is not None and (minimum < prior[0] or maximum_minor < prior[1]):
            _fail("tier ranges must be monotonic within a payout path")
        previous[payout_path_id] = (minimum, maximum_minor)
        confidence = _integer(item["minimum_confidence"], "minimum_confidence", 10)
        if type(item["physical_access_allowed"]) is not bool:
            _fail("physical_access_allowed requires a boolean")
        tiers.append(PolicyTier(tier_id, payout_path_id, ordinal, minimum, maximum_minor,
            _strings(item["accepted_pre_auth"], db.FIRMWARE_CHAIN_PRE_AUTH, "accepted_pre_auth"),
            confidence,
            _strings(item["accepted_completeness"], db.FIRMWARE_CHAIN_COMPLETENESS,
                     "accepted_completeness"),
            _strings(item["accepted_evidence_rungs"], db.FIRMWARE_CHAIN_EVIDENCE_RUNGS,
                     "accepted_evidence_rungs"),
            item["physical_access_allowed"]))
    if len({tier.tier_id for tier in tiers}) != len(tiers):
        _fail("tiers requires unique tier_id values")

    raw_notes = top["notes"]
    if (not isinstance(raw_notes, list) or len(raw_notes) > MAX_POLICY_NOTES
            or any(not isinstance(note, str) for note in raw_notes)):
        _fail("notes requires at most 64 strings")
    notes = tuple(_text(note, "notes") for note in raw_notes)
    if list(notes) != sorted(set(notes)):
        _fail("notes requires sorted unique entries")
    return DecisionPolicy(1, policy_id, currency, acquisition, maximum, support,
        support_basis, tuple(paths), tuple(tiers), notes)


def load_policy(path: str | pathlib.Path) -> DecisionPolicy:
    try:
        with pathlib.Path(path).open("rb") as stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise FirmwareDecideError("cannot read policy") from exc
    if len(raw) > MAX_POLICY_BYTES:
        _fail("policy size exceeds 1 MiB")
    policy = _parse(raw)
    if raw != policy_bytes(policy):
        _fail("policy requires canonical UTF-8 JSON")
    return policy


def verified_input(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path, *,
        image_id: str | None = None) -> VerifiedFirmwareDecisionInput:
    """Read one transactionally coherent current graph and completed dive."""
    owned = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        graph = firmware_chain.verified_graph_snapshot(
            con, run_dir, root, image_id=image_id)
        dive = firmware_dive.verified_decision_input(
            con, run_dir, root, graph)
        return VerifiedFirmwareDecisionInput(graph, dive)
    except (sqlite3.Error, db.DbError, firmware_chain.FirmwareChainError,
            firmware_dive.FirmwareDiveError, OSError, ValueError,
            TypeError, KeyError, RecursionError) as exc:
        raise FirmwareDecideError("Cannot verify firmware decision input") from exc
    finally:
        if owned:
            con.rollback()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value) -> bytes:
    try:
        return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FirmwareDecideError("decision worklist cannot be canonicalized") from exc


def _open_preconditions(graph: firmware_chain.VerifiedFirmwareGraphSnapshot) -> tuple[dict, ...]:
    locations: dict[tuple[str, str], set[tuple[str, int | None]]] = {}
    axes: dict[tuple[str, str], set[str]] = {}
    for chain in graph.chains:
        for blocker_id in chain.blocker_ids:
            locations.setdefault(("blocker", blocker_id), set()).add((chain.chain_id, None))
        for unknown_id in chain.existing_unknown_ids:
            locations.setdefault(("unknown", unknown_id), set()).add((chain.chain_id, None))
    for edge in graph.edges:
        for blocker_id in edge.blocker_ids:
            locations.setdefault(("blocker", blocker_id), set()).add((edge.chain_id, edge.ordinal))
        for unknown in edge.existing_unknowns:
            key = ("unknown", unknown.unknown_id)
            locations.setdefault(key, set()).add((edge.chain_id, edge.ordinal))
            axes.setdefault(key, set()).update(unknown.axes)
    blockers = {item.blocker_id: item for item in graph.blockers}
    unknowns = {item.id: item for item in graph.unknowns}
    projected = []
    for key in sorted(locations):
        kind, identity = key
        if kind == "blocker":
            item = blockers.get(identity)
            if item is None or item.status != "open":
                raise FirmwareDecideError("graph blocker denominator is not exact and open")
            question, settling, method, item_axes = (
                item.question, item.settling_observation, item.method, item.axes)
        else:
            item = unknowns.get(identity)
            if item is None or item.status != "open":
                raise FirmwareDecideError("graph unknown denominator is not exact and open")
            question, settling, method = (
                item.question, item.settling_observation, item.method)
            item_axes = tuple(sorted(axes.get(key, ())))
        projected.append({
            "kind": kind,
            "precondition_id": f"{kind}:{identity}",
            "source_id": identity,
            "question": question,
            "settling_observation": settling,
            "method": method,
            "axes": list(item_axes),
            "locations": [
                {"chain_id": chain_id, "edge_ordinal": ordinal}
                for chain_id, ordinal in sorted(
                    locations[key], key=lambda value: (value[0], -1 if value[1] is None else value[1]))
            ],
        })
    return tuple(projected)


def _worklist(inputs: VerifiedFirmwareDecisionInput, policy: DecisionPolicy,
        policy_sha256: str) -> tuple[bytes, int]:
    graph = inputs.graph
    preconditions = _open_preconditions(graph)
    value = {
        "schema_version": 1,
        "image_id": graph.image_id,
        "technical_provenance": {
            key: getattr(graph, key) for key in (
                "manifest_sha256", "surface_snapshot_sha256",
                "candidate_snapshot_sha256", "chain_worklist_sha256",
                "graph_path", "graph_sha256")
        },
        "graph": dataclasses.asdict(graph),
        "dive": {
            "dive_generation": inputs.dive.dive_generation,
            "journal_path": inputs.dive.journal_path,
            "journal_sha256": inputs.dive.journal_sha256,
            "overlay_sha256": inputs.dive.overlay_sha256,
            "overlay": dataclasses.asdict(inputs.dive.overlay),
        },
        "open_preconditions": list(preconditions),
        "policy": {
            "policy_id": policy.policy_id,
            "path": "policy.json",
            "sha256": policy_sha256,
            "projection": _wire(policy),
        },
    }
    return _canonical(value), len(preconditions)


def _summary(row, open_precondition_count: int) -> DecisionPreparationSummary:
    return DecisionPreparationSummary(
        row["image_id"], row["decision_generation"], row["graph_sha256"],
        row["dive_generation"], row["overlay_sha256"], row["policy_id"],
        row["policy_path"], row["policy_sha256"], row["worklist_path"],
        row["worklist_sha256"], row["chain_count"], open_precondition_count)


def _prepared_row(inputs: VerifiedFirmwareDecisionInput, policy: DecisionPolicy,
        policy_sha256: str, generation: str, chain_count: int,
        prepared_at: str) -> dict:
    graph, dive = inputs.graph, inputs.dive
    base = f"files/firmware-decide/{generation}"
    return {
        "image_id": graph.image_id,
        "decision_generation": generation,
        "manifest_sha256": graph.manifest_sha256,
        "surface_snapshot_sha256": graph.surface_snapshot_sha256,
        "candidate_snapshot_sha256": graph.candidate_snapshot_sha256,
        "chain_worklist_sha256": graph.chain_worklist_sha256,
        "graph_path": graph.graph_path,
        "graph_sha256": graph.graph_sha256,
        "dive_generation": dive.dive_generation,
        "journal_path": dive.journal_path,
        "journal_sha256": dive.journal_sha256,
        "overlay_sha256": dive.overlay_sha256,
        "policy_id": policy.policy_id,
        "policy_path": f"{base}/policy.json",
        "policy_sha256": policy_sha256,
        "worklist_path": f"{base}/worklist.json",
        "worklist_sha256": generation,
        "status": "pending",
        "chain_count": chain_count,
        "bench_test_count": 0,
        "script_count": 0,
        "policy_match_count": 0,
        "prepared_at": prepared_at,
    }


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path, policy_path: str | pathlib.Path, *,
        image_id: str | None = None) -> DecisionPreparationSummary:
    """Install and publish one exact current graph/dive/policy assignment."""
    started = False
    try:
        if con.in_transaction:
            raise FirmwareDecideError("Decision preparation requires no active caller transaction")
        run = firmware_dive._selector(run_dir)
        first_inputs = verified_input(con, run, root, image_id=image_id)
        first_policy = load_policy(policy_path)
        policy_raw = policy_bytes(first_policy)
        policy_sha256 = _digest(policy_raw)
        worklist_raw, open_count = _worklist(first_inputs, first_policy, policy_sha256)
        generation = _digest(worklist_raw)
        destination = run / "files" / "firmware-decide" / generation
        contents = {"policy.json": policy_raw, "worklist.json": worklist_raw}
        firmware_dive._install(destination, contents, run)

        con.execute("BEGIN IMMEDIATE")
        started = True
        current_inputs = verified_input(con, run, root, image_id=image_id)
        current_policy = load_policy(policy_path)
        current_policy_raw = policy_bytes(current_policy)
        current_policy_sha256 = _digest(current_policy_raw)
        current_worklist, current_open_count = _worklist(
            current_inputs, current_policy, current_policy_sha256)
        if (current_inputs != first_inputs or current_policy_raw != policy_raw or
                current_policy_sha256 != policy_sha256 or
                current_worklist != worklist_raw or current_open_count != open_count):
            raise FirmwareDecideError("Decision inputs changed before publication")
        firmware_dive._checked_install(destination, contents, run)

        active = surface._query(con,
            "SELECT * FROM cba_firmware_decide_runs WHERE image_id=? AND status IN ('pending','recorded')",
            (first_inputs.graph.image_id,))
        same = surface._query(con,
            "SELECT * FROM cba_firmware_decide_runs WHERE image_id=? AND decision_generation=?",
            (first_inputs.graph.image_id, generation))
        if same:
            if len(same) != 1:
                raise FirmwareDecideError("Decision generation ownership is ambiguous")
            if any(row["decision_generation"] != generation for row in active):
                raise FirmwareDecideError("Another firmware decision generation is active")
            existing = same[0]
            db.TABLE_SPECS["cba_firmware_decide_runs"].validate(existing)
            firmware_dive._timestamp(existing["prepared_at"])
            expected = _prepared_row(first_inputs, first_policy, policy_sha256,
                                     generation, len(first_inputs.graph.chains),
                                     existing["prepared_at"])
            for key, value in expected.items():
                if existing[key] != value and key not in ("status",):
                    raise FirmwareDecideError("Existing decision generation differs from current authority")
            con.rollback()
            started = False
            return _summary(existing, open_count)
        if active:
            raise FirmwareDecideError("Another firmware decision generation is active")
        prepared_at = con.execute("SELECT datetime('now')").fetchone()[0]
        row = _prepared_row(first_inputs, first_policy, policy_sha256,
                            generation, len(first_inputs.graph.chains), prepared_at)
        db.put(con, "cba_firmware_decide_runs", row, commit=False)
        con.commit()
        started = False
        return _summary(row, open_count)
    except FirmwareDecideError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareDecideError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            firmware_chain.FirmwareChainError, firmware_dive.FirmwareDiveError,
            surface.SurfaceError) as exc:
        raise FirmwareDecideError("Cannot prepare firmware decision") from exc
    finally:
        if started:
            con.rollback()
