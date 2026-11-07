"""Prepare and verify policy-bound firmware acquisition decisions.

Stage 4i keeps operator policy separate from technical evidence.  This module
owns policy parsing now; later tasks add current-input verification, immutable
preparation, deterministic completion, and the verified package boundary.
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
    except (ValueError, RecursionError) as exc:
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


def _read_stable_file(path: str | pathlib.Path, maximum: int) -> bytes:
    """Read at most maximum + 1 bytes of one stable operator-named regular file.

    The Stage 4h result-loader pattern: refuse a final symlink, FIFO or device
    before opening, never block on open, and refuse pathname/descriptor
    identity drift across the read. Callers own the size bound and wrap OSError.
    """
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(f"{os.fspath(path)!r} is not a regular file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = firmware_dive._file_identity
    if not (identity(before) == identity(opened) == identity(after)
            == identity(os.lstat(path))):
        raise OSError(f"{os.fspath(path)!r} changed while it was read")
    return raw


def load_policy(path: str | pathlib.Path) -> DecisionPolicy:
    try:
        raw = _read_stable_file(path, MAX_POLICY_BYTES)
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


def _technical_provenance(inputs: VerifiedFirmwareDecisionInput) -> dict:
    """The frozen graph/dive columns that must equal current verified input."""
    graph, dive = inputs.graph, inputs.dive
    return {
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
    }


def _prepared_row(inputs: VerifiedFirmwareDecisionInput, policy: DecisionPolicy,
        policy_sha256: str, generation: str, chain_count: int,
        prepared_at: str, preparation_ordinal: int) -> dict:
    base = f"files/firmware-decide/{generation}"
    return {
        "image_id": inputs.graph.image_id,
        "decision_generation": generation,
        **_technical_provenance(inputs),
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
        "preparation_ordinal": preparation_ordinal,
    }


@dataclasses.dataclass(frozen=True, slots=True)
class _PreparationState:
    same: dict | None
    stale: tuple[dict, ...]
    latest: bool
    next_ordinal: int


def _preparation_state(con, inputs, policy, policy_sha256, generation):
    """Classify an image's decision rows against one exact current assignment.

    An active row frozen on technical input that is no longer current can
    never complete, so it is returned as stale for the caller to supersede.
    An active sibling on current technical input is a policy change the
    operator must finish first. `latest` means the same generation is already
    the unique highest preparation, so an identical prepare has nothing to do.
    """
    rows = surface._query(con,
        "SELECT * FROM cba_firmware_decide_runs WHERE image_id=?",
        (inputs.graph.image_id,))
    current = _technical_provenance(inputs)
    same, stale = None, []
    for row in rows:
        if row["decision_generation"] == generation:
            same = row
        elif row["status"] in ("pending", "recorded"):
            db.TABLE_SPECS["cba_firmware_decide_runs"].validate(row)
            if all(row[key] == value for key, value in current.items()):
                raise FirmwareDecideError("Another firmware decision generation is active")
            stale.append(row)
    top = max((row["preparation_ordinal"] for row in rows), default=0)
    latest = False
    if same is not None:
        db.TABLE_SPECS["cba_firmware_decide_runs"].validate(same)
        if same["status"] == "superseded":
            raise FirmwareDecideError(
                "Decision generation was superseded; prepare a changed policy instead")
        expected = _prepared_row(inputs, policy, policy_sha256,
                                 generation, len(inputs.graph.chains),
                                 same["prepared_at"], same["preparation_ordinal"])
        for key, value in expected.items():
            if (same[key] != value
                    and key not in ("status", "bench_test_count",
                                    "script_count", "policy_match_count")):
                raise FirmwareDecideError("Existing decision generation differs from current authority")
        latest = not stale and [row["preparation_ordinal"] for row in rows].count(
            top) == 1 and same["preparation_ordinal"] == top
    return _PreparationState(same, tuple(stale), latest, top + 1)


def _publish_preparation(con, prepared, inputs, policy, policy_sha256,
                         generation, open_count):
    """Supersede stale active rows, then publish or re-rank this generation."""
    now = con.execute("SELECT datetime('now')").fetchone()[0]
    table = db.TABLE_SPECS["cba_firmware_decide_runs"]
    for row in prepared.stale:
        # The check-side guard, for supersede: a clock that moved backwards
        # never writes a supersede earlier than the row's own lifecycle.
        if now < (row["recorded_at"] or row["prepared_at"]):
            raise FirmwareDecideError(
                "Decision supersede timestamp precedes preparation or recording")
        table.validate(dict(row, status="superseded", superseded_at=now))
        con.execute(
            "UPDATE cba_firmware_decide_runs SET status='superseded',superseded_at=? "
            "WHERE image_id=? AND decision_generation=? AND status=?",
            (now, row["image_id"], row["decision_generation"], row["status"]))
    if prepared.same is not None:
        con.execute(
            "UPDATE cba_firmware_decide_runs SET preparation_ordinal=? "
            "WHERE image_id=? AND decision_generation=?",
            (prepared.next_ordinal, prepared.same["image_id"], generation))
        return _summary(prepared.same, open_count)
    row = _prepared_row(inputs, policy, policy_sha256, generation,
                        len(inputs.graph.chains), now, prepared.next_ordinal)
    db.put(con, "cba_firmware_decide_runs", row, commit=False)
    return _summary(row, open_count)


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path, policy_path: str | pathlib.Path, *,
        image_id: str | None = None) -> DecisionPreparationSummary:
    """Install and publish one exact current graph/dive/policy assignment."""
    started = False
    try:
        if con.in_transaction:
            raise FirmwareDecideError("Decision preparation requires no active caller transaction")
        run = firmware_dive._selector(run_dir)
        con.execute("BEGIN")
        started = True
        first_inputs = verified_input(con, run, root, image_id=image_id)
        first_policy = load_policy(policy_path)
        policy_raw = policy_bytes(first_policy)
        policy_sha256 = _digest(policy_raw)
        worklist_raw, open_count = _worklist(first_inputs, first_policy, policy_sha256)
        generation = _digest(worklist_raw)
        destination = run / "files" / "firmware-decide" / generation
        contents = {"policy.json": policy_raw, "worklist.json": worklist_raw}
        prepared = _preparation_state(
            con, first_inputs, first_policy, policy_sha256, generation)
        if prepared.latest:
            firmware_dive._checked_install(destination, contents, run)
            con.rollback()
            started = False
            return _summary(prepared.same, open_count)
        con.rollback()
        started = False
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

        prepared = _preparation_state(
            con, current_inputs, current_policy, policy_sha256, generation)
        if prepared.latest:
            con.rollback()
            started = False
            return _summary(prepared.same, open_count)
        summary = _publish_preparation(
            con, prepared, first_inputs, first_policy, policy_sha256,
            generation, open_count)
        con.commit()
        started = False
        return summary
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


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyMatch:
    chain_id: str
    tier_id: str
    payout_path_id: str
    path_status: str
    requires_physical_settlement: bool
    technical_match: bool
    eligible_match: bool
    unknown_path_match: bool


@dataclasses.dataclass(frozen=True, slots=True)
class PayoutProjection:
    chain_id: str
    tier_id: str
    payout_path_id: str
    currency: str
    minimum_minor: int
    maximum_minor: int


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedProposedScript:
    name: str
    path: str
    sha256: str
    size: int
    content: bytes
    status: str = "proposed_unreviewed"


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionSummary:
    image_id: str
    decision_generation: str
    decision: str
    primary_reason: str
    reason_codes: tuple[str, ...]
    chain_count: int
    bench_test_count: int
    script_count: int
    policy_match_count: int
    package_path: str
    package_sha256: str
    complete: bool


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedFirmwareDecisionPackage:
    image_id: str
    decision_generation: str
    decision: str
    primary_reason: str
    reason_codes: tuple[str, ...]
    top_chain_id: str | None
    bench_plan_complete: bool
    policy: DecisionPolicy
    result: object
    policy_matches: tuple[PolicyMatch, ...]
    payout_projections: tuple[PayoutProjection, ...]
    open_preconditions: tuple[object, ...]
    bench_tests: tuple[object, ...]
    scripts: tuple[VerifiedProposedScript, ...]
    package_path: str
    package_sha256: str
    package_bytes: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class _DerivedDecision:
    decision: str
    primary_reason: str
    reason_codes: tuple[str, ...]
    top_chain_id: str | None
    bench_plan_complete: bool
    policy_matches: tuple[PolicyMatch, ...]
    payout_projections: tuple[PayoutProjection, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class _DecisionCapture:
    row: object
    policy: DecisionPolicy
    validated: object
    derived: _DerivedDecision
    package_bytes: bytes
    package_sha256: str
    contents: object


def _technical_derivation(policy: DecisionPolicy, validated) -> _DerivedDecision:
    assessments = validated.chain_assessments
    preconditions = validated.open_preconditions
    by_chain = {item.chain_id: item for item in assessments}
    paths = {item.path_id: item for item in policy.payout_paths}
    matches = []
    for assessment in assessments:
        physical = any(
            item.method == "hardware"
            and any(location.chain_id == assessment.chain_id for location in item.locations)
            for item in preconditions)
        for tier in policy.tiers:
            technical = (
                assessment.pre_auth in tier.accepted_pre_auth
                and assessment.confidence >= tier.minimum_confidence
                and assessment.completeness in tier.accepted_completeness
                and assessment.evidence_rung in tier.accepted_evidence_rungs
                and (not physical or tier.physical_access_allowed))
            if not technical:
                continue
            path = paths[tier.payout_path_id]
            matches.append(PolicyMatch(
                assessment.chain_id, tier.tier_id, tier.payout_path_id,
                path.status, physical, True, path.status == "eligible",
                path.status == "unknown"))
    matches = tuple(sorted(matches, key=lambda item: (
        item.chain_id, next(tier.ordinal for tier in policy.tiers
                            if tier.tier_id == item.tier_id))))
    eligible = [item for item in matches if item.eligible_match]
    unknown = [item for item in matches if item.unknown_path_match]
    projections = []
    for chain_id in sorted({item.chain_id for item in eligible}):
        selected = min(
            (item for item in eligible if item.chain_id == chain_id),
            key=lambda item: next(tier.ordinal for tier in policy.tiers
                                  if tier.tier_id == item.tier_id))
        tier = next(item for item in policy.tiers if item.tier_id == selected.tier_id)
        projections.append(PayoutProjection(
            chain_id, tier.tier_id, tier.payout_path_id, policy.currency,
            tier.minimum_minor, tier.maximum_minor))
    top_chain_id = None
    bench_complete = False
    if eligible:
        top_chain_id = min(
            {item.chain_id for item in eligible},
            key=lambda identity: by_chain[identity].rank)
        tests = tuple(item for item in validated.bench_tests
                      if top_chain_id in item.chain_ids)
        hardware = {
            item.precondition_id for item in preconditions
            if item.method == "hardware"
            and any(location.chain_id == top_chain_id for location in item.locations)
        }
        covered = {subject for item in tests for subject in item.subject_refs}
        script_names = {item.name for item in validated.scripts}
        bench_complete = bool(tests) and hardware <= covered and all(
            item.script_name is None or item.script_name in script_names
            for item in tests)

    no_chain = not assessments
    no_match = not eligible and not unknown
    codes = []
    applicable = {
        "no-current-chain": no_chain,
        "support-unsupported": policy.support_status == "unsupported",
        "support-unknown": policy.support_status == "unknown",
        "cost-exceeds-policy": (
            policy.acquisition_cost_minor > policy.max_acquisition_cost_minor),
        "eligible-policy-match": bool(eligible),
        "unknown-policy-path-match": bool(unknown),
        "no-policy-match": no_match,
        "bench-plan-complete": bool(eligible) and bench_complete,
        "bench-plan-incomplete": bool(eligible) and not bench_complete,
    }
    codes.extend(code for code in db.FIRMWARE_DECIDE_REASON_CODES if applicable[code])
    if no_chain:
        decision, primary = "pass", "no-current-chain"
    elif policy.support_status == "unsupported":
        decision, primary = "pass", "support-unsupported"
    elif policy.acquisition_cost_minor > policy.max_acquisition_cost_minor:
        decision, primary = "pass", "cost-exceeds-policy"
    elif eligible:
        if policy.support_status == "unknown":
            decision, primary = "defer", "support-unknown"
        elif bench_complete:
            decision, primary = "acquire", "eligible-chain"
        else:
            decision, primary = "defer", "bench-plan-incomplete"
    elif unknown:
        decision, primary = "defer", "payout-path-unknown"
    else:
        decision, primary = "pass", "no-policy-match"
    return _DerivedDecision(
        decision, primary, tuple(codes), top_chain_id, bench_complete,
        matches, tuple(projections))


def _select_decision_row(con, image_id):
    if image_id is None:
        images = [row[0] for row in con.execute(
            "SELECT DISTINCT image_id FROM cba_firmware_decide_runs ORDER BY image_id")]
        if len(images) != 1:
            raise FirmwareDecideError("Select exactly one decision image")
        image_id = images[0]
    rows = surface._query(
        con, "SELECT * FROM cba_firmware_decide_runs WHERE image_id=?", (image_id,))
    if not rows:
        raise FirmwareDecideError("No prepared firmware decision")
    active = [row for row in rows if row["status"] in ("pending", "recorded")]
    if len(active) > 1:
        raise FirmwareDecideError("Multiple active firmware decisions are ambiguous")
    # Superseded rows are history and never current. The most recent prepare,
    # including an identical re-prepare, alone decides; an unfinished latest
    # generation never falls back to an older completed package.
    current = [row for row in rows if row["status"] in ("pending", "recorded", "complete")]
    if not current:
        raise FirmwareDecideError("No current firmware decision")
    ordinal = max(row["preparation_ordinal"] for row in current)
    selected = [row for row in current if row["preparation_ordinal"] == ordinal]
    if len(selected) != 1:
        raise FirmwareDecideError("Latest prepared firmware decision is ambiguous")
    if selected[0]["status"] == "pending":
        raise FirmwareDecideError("Firmware decision result is not recorded")
    return selected[0]


def _package_projection(row, policy, validated, derived, scripts):
    from audit_core import firmware_decide_results as results
    return {
        "schema_version": 1,
        "image_id": row["image_id"],
        "decision_generation": row["decision_generation"],
        "provenance": {
            key: row[key] for key in (
                "manifest_sha256", "surface_snapshot_sha256",
                "candidate_snapshot_sha256", "chain_worklist_sha256",
                "graph_path", "graph_sha256", "dive_generation",
                "journal_path", "journal_sha256", "overlay_sha256",
                "policy_id", "policy_path", "policy_sha256",
                "worklist_path", "worklist_sha256",
                "result_path", "result_sha256")
        },
        "policy": _wire(policy),
        "decision": derived.decision,
        "primary_reason": derived.primary_reason,
        "reason_codes": list(derived.reason_codes),
        "top_chain_id": derived.top_chain_id,
        "bench_plan_complete": derived.bench_plan_complete,
        "chain_assessments": [
            results._assessment_wire(item) for item in validated.chain_assessments],
        "open_preconditions": [
            results._precondition_wire(item) for item in validated.open_preconditions],
        "bench_tests": [
            results._bench_wire(item) for item in validated.bench_tests],
        "proposed_scripts": [{
            "name": item.name,
            "path": f"bench/{item.name}",
            "sha256": hashlib.sha256(item.content).hexdigest(),
            "size": item.size,
            "status": "proposed_unreviewed",
        } for item in scripts],
        "policy_matches": [dataclasses.asdict(item) for item in derived.policy_matches],
        "payout_projections": [
            dataclasses.asdict(item) for item in derived.payout_projections],
    }


def _require_result_assignment(row, result):
    if (result.image_id, result.decision_generation, result.worklist_sha256) != (
            row["image_id"], row["decision_generation"], row["worklist_sha256"]):
        raise FirmwareDecideError("Decision result differs from selected assignment")


def _capture_decision(con, run, root, image_id):
    from audit_core import firmware_decide_results as results
    row = _select_decision_row(con, image_id)
    db.TABLE_SPECS["cba_firmware_decide_runs"].validate(row)
    inputs = verified_input(con, run, root, image_id=row["image_id"])
    if any(row[key] != value for key, value in _technical_provenance(inputs).items()):
        raise FirmwareDecideError("Decision technical input is not current")
    policy_raw = firmware_dive._read(
        run, row["policy_path"], row["policy_sha256"], MAX_POLICY_BYTES)
    policy = _parse(policy_raw)
    if policy_bytes(policy) != policy_raw or policy.policy_id != row["policy_id"]:
        raise FirmwareDecideError("Decision policy snapshot differs")
    worklist_raw = firmware_dive._read(
        run, row["worklist_path"], row["worklist_sha256"])
    rebuilt, _ = _worklist(inputs, policy, row["policy_sha256"])
    if rebuilt != worklist_raw or _digest(rebuilt) != row["decision_generation"]:
        raise FirmwareDecideError("Decision worklist is not current")
    result_raw = firmware_dive._read(
        run, row["result_path"], row["result_sha256"], results.MAX_RESULT_BYTES)
    result = results._parse(result_raw)
    _require_result_assignment(row, result)
    if results.canonical_bytes(result) != result_raw:
        raise FirmwareDecideError("Recorded decision result is not canonical")
    validated = results.validate(con, run, result)
    _require_result_assignment(row, validated)
    derived = _technical_derivation(policy, validated)
    script_values = tuple(
        VerifiedProposedScript(
            item.name, f"bench/{item.name}", hashlib.sha256(item.content).hexdigest(),
            len(item.content), item.content)
        for item in validated.scripts)
    projection = _package_projection(
        row, policy, validated, derived, script_values)
    package_raw = _canonical(projection)
    package_sha256 = _digest(package_raw)
    contents = {"decision.json": package_raw}
    contents.update({item.path: item.content for item in script_values})
    return _DecisionCapture(
        row, policy, validated, derived, package_raw, package_sha256, contents)


def _package_path(row, package_sha256):
    return (
        f"artifacts/firmware-decide/{row['decision_generation']}/"
        f"{package_sha256}/decision.json")


def _summary_from_capture(capture):
    row, validated, derived = capture.row, capture.validated, capture.derived
    return DecisionSummary(
        row["image_id"], row["decision_generation"], derived.decision,
        derived.primary_reason, derived.reason_codes,
        len(validated.chain_assessments), len(validated.bench_tests),
        len(validated.scripts), len(derived.policy_matches),
        _package_path(row, capture.package_sha256), capture.package_sha256, True)


def _require_complete_row(capture):
    row, validated, derived = capture.row, capture.validated, capture.derived
    expected = {
        "package_path": _package_path(row, capture.package_sha256),
        "package_sha256": capture.package_sha256,
        "decision": derived.decision,
        "primary_reason": derived.primary_reason,
        "reason_codes": json.dumps(
            list(derived.reason_codes), separators=(",", ":")),
        "chain_count": len(validated.chain_assessments),
        "bench_test_count": len(validated.bench_tests),
        "script_count": len(validated.scripts),
        "policy_match_count": len(derived.policy_matches),
    }
    if row["status"] != "complete" or any(row[key] != value for key, value in expected.items()):
        raise FirmwareDecideError("Completed decision row differs from canonical package")


def check(con: sqlite3.Connection, run_dir: str | pathlib.Path,
          root: str | pathlib.Path, *, image_id: str | None = None) -> DecisionSummary:
    """Derive, install, and atomically publish one canonical decision package."""
    started = False
    try:
        if con.in_transaction:
            raise FirmwareDecideError("Decision completion requires no active caller transaction")
        run = firmware_dive._selector(run_dir)
        con.execute("BEGIN")
        started = True
        captured = _capture_decision(con, run, root, image_id)
        destination = run / pathlib.PurePosixPath(
            _package_path(captured.row, captured.package_sha256)).parent
        if captured.row["status"] == "complete":
            _require_complete_row(captured)
            firmware_dive._checked_install(
                destination, captured.contents, run, exact_mode=0o600)
            con.rollback()
            started = False
            return _summary_from_capture(captured)
        con.rollback()
        started = False
        firmware_dive._install(destination, captured.contents, run)
        con.execute("BEGIN IMMEDIATE")
        started = True
        current = _capture_decision(con, run, root, image_id)
        if current != captured:
            raise FirmwareDecideError("Decision authority changed before publication")
        firmware_dive._checked_install(
            destination, captured.contents, run, exact_mode=0o600)
        completed_at = con.execute("SELECT datetime('now')").fetchone()[0]
        if (not isinstance(current.row["recorded_at"], str)
                or completed_at < current.row["recorded_at"]):
            raise FirmwareDecideError("Decision completion timestamp precedes recording")
        values = (
            _package_path(current.row, current.package_sha256),
            current.package_sha256, current.derived.decision,
            current.derived.primary_reason,
            json.dumps(list(current.derived.reason_codes), separators=(",", ":")),
            len(current.validated.chain_assessments),
            len(current.validated.bench_tests), len(current.validated.scripts),
            len(current.derived.policy_matches), completed_at,
            current.row["image_id"], current.row["decision_generation"])
        cursor = con.execute(
            "UPDATE cba_firmware_decide_runs SET status='complete',package_path=?,"
            "package_sha256=?,decision=?,primary_reason=?,reason_codes=?,chain_count=?,"
            "bench_test_count=?,script_count=?,policy_match_count=?,completed_at=? "
            "WHERE image_id=? AND decision_generation=? AND status='recorded'", values)
        if cursor.rowcount != 1:
            raise FirmwareDecideError("Decision lifecycle changed before completion")
        con.commit()
        started = False
        return _summary_from_capture(current)
    except FirmwareDecideError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareDecideError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            firmware_chain.FirmwareChainError, firmware_dive.FirmwareDiveError,
            surface.SurfaceError) as exc:
        raise FirmwareDecideError("Cannot complete firmware decision") from exc
    finally:
        if started:
            con.rollback()


def verified_package(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path, *,
        image_id: str | None = None) -> VerifiedFirmwareDecisionPackage:
    """Reconstruct one current completed package without repair or writes."""
    owned = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        run = firmware_dive._selector(run_dir)
        captured = _capture_decision(con, run, root, image_id)
        _require_complete_row(captured)
        destination = run / pathlib.PurePosixPath(
            _package_path(captured.row, captured.package_sha256)).parent
        firmware_dive._checked_install(
            destination, captured.contents, run, exact_mode=0o600)
        scripts = tuple(
            dataclasses.replace(
                item,
                path=(pathlib.PurePosixPath(captured.row["package_path"]).parent /
                      item.path).as_posix())
            for item in (
                VerifiedProposedScript(
                    script.name, f"bench/{script.name}",
                    hashlib.sha256(script.content).hexdigest(),
                    len(script.content), script.content)
                for script in captured.validated.scripts))
        return VerifiedFirmwareDecisionPackage(
            captured.row["image_id"], captured.row["decision_generation"],
            captured.derived.decision, captured.derived.primary_reason,
            captured.derived.reason_codes, captured.derived.top_chain_id,
            captured.derived.bench_plan_complete, captured.policy,
            captured.validated, captured.derived.policy_matches,
            captured.derived.payout_projections,
            captured.validated.open_preconditions,
            captured.validated.bench_tests, scripts,
            captured.row["package_path"], captured.package_sha256,
            captured.package_bytes)
    except FirmwareDecideError:
        raise
    except (sqlite3.Error, db.DbError) as exc:
        raise FirmwareDecideError("database operation failed") from exc
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            firmware_chain.FirmwareChainError, firmware_dive.FirmwareDiveError,
            surface.SurfaceError) as exc:
        raise FirmwareDecideError("Cannot verify firmware decision package") from exc
    finally:
        if owned:
            con.rollback()
