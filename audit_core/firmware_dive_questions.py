"""Pure firmware-dive question authority, semantic identity and bounded packets.

The caller supplies a verified immutable graph and one coherent durable history
scoped to the selected image/candidate and still-current stable subjects.
This module neither verifies live dependencies nor publishes artifacts. Manifest
reading is the sole IO; preparation must revalidate history and artifacts under
its publication lock. Packet references grant exact identities, never path globs.
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

from audit_core import db, extract, firmware_chain

MAX_ANALYST_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_JOURNAL_ENTRIES = 1000
MAX_PACKET_BYTES = 1024 * 1024
MAX_EXTRACT_RECORDS = 3
_STATE_VALUES = {
    'lifecycle': db.FIRMWARE_CHAIN_LIFECYCLE_STATES,
    'posture': db.FIRMWARE_CHAIN_POSTURE_STATES,
    'authentication': db.FIRMWARE_CHAIN_AUTH_STATES,
    'reachability': ('evidenced', 'refuted'),
}


class FirmwareDiveQuestionError(ValueError):
    """A question, durable history or packet exceeds its authority."""


@dataclasses.dataclass(frozen=True, slots=True, order=True)
class SubjectRef:
    kind: str
    identity: str

    def __str__(self) -> str:
        return self.kind + ':' + self.identity


@dataclasses.dataclass(frozen=True, slots=True)
class ResolutionContract:
    target_subject: SubjectRef
    mode: str
    predicate: str
    axis: str | None
    expected_value: str | bool | None
    allowed_values: tuple[str, ...]
    other_specific: bool
    capability_kind: str | None
    link_key: str | None
    transition_kind: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class AnalystQuestion:
    subject_refs: tuple[SubjectRef, ...]
    method: str
    question: str
    settling_observation: str
    axes: tuple[str, ...]
    resolution_contract: ResolutionContract


@dataclasses.dataclass(frozen=True, slots=True)
class RetryDirective:
    question_id: str
    prior_observation_id: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class ExtractRecord:
    unit: str
    name: str
    relative_path: str
    sha256: str
    byte_count: int
    version: int
    truncated: bool
    backend: str
    manifest_record_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class DiveQuestion:
    question_id: str
    origin: str
    subject_refs: tuple[SubjectRef, ...]
    method: str
    question: str
    settling_observation: str
    axes: tuple[str, ...]
    resolution_contract: ResolutionContract
    attempt_ordinal: int = 1
    prior_observation_id: str | None = None
    supersedes_observation_ids: tuple[str, ...] = ()
    extract_records: tuple[ExtractRecord, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class QuestionHistory:
    question: DiveQuestion
    attempt_ordinal: int
    observation_id: str | None
    outcome: str | None
    resolution_value: str | bool | None
    dependency_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    dependency_current: bool
    supersedes: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class JournalIndexEntry:
    observation_id: str
    question_id: str
    subject_refs: tuple[SubjectRef, ...]
    status: str
    outcome: str
    artifact_path: str
    artifact_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class RetainedRef:
    kind: str
    logical_id: str
    relative_path: str
    sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class AcquisitionContract:
    image_id: str
    candidate_snapshot_sha256: str
    question_id: str
    attempt_ordinal: int
    subject_refs: tuple[SubjectRef, ...]
    method: str
    artifact_kinds: tuple[str, ...]
    acquisition_class: str | None
    network: str = 'none'
    max_timeout_seconds: int = 300
    max_stdout_bytes: int = 1024 * 1024
    max_stderr_bytes: int = 1024 * 1024
    max_output_bytes: int = 8 * 1024 * 1024
    max_files: int = 256
    max_capture_bytes: int = 64 * 1024 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class QuestionPacket:
    schema_version: int
    image_id: str
    candidate_snapshot_sha256: str
    question: DiveQuestion
    retained_refs: tuple[RetainedRef, ...]
    evidence_refs: tuple[str, ...]
    allowed_dependencies: tuple[RetainedRef, ...]
    extract_records: tuple[ExtractRecord, ...]
    journal_index: tuple[JournalIndexEntry, ...]
    acquisition_contract: AcquisitionContract


@dataclasses.dataclass(frozen=True, slots=True)
class QuestionSet:
    questions: tuple[DiveQuestion, ...]
    retry_projection: tuple[tuple[str, int, str | None], ...] = ()


def _wire(value):
    if isinstance(value, SubjectRef):
        return str(value)
    if dataclasses.is_dataclass(value):
        return {f.name: _wire(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (tuple, list)):
        return [_wire(item) for item in value]
    if isinstance(value, dict):
        return {key: _wire(item) for key, item in value.items()}
    return value


def _bytes(value) -> bytes:
    return json.dumps(_wire(value), sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _hash(value) -> str:
    return hashlib.sha256(_bytes(value)).hexdigest()


def _text(value, label, maximum=4096):
    if not isinstance(value, str) or not value.strip():
        raise FirmwareDiveQuestionError(f'{label} requires nonempty text')
    try:
        encoded = value.encode('utf-8')
    except UnicodeError as exc:
        raise FirmwareDiveQuestionError(f'{label} requires UTF-8') from exc
    if len(encoded) > maximum or any(unicodedata.category(c).startswith('C') for c in value):
        raise FirmwareDiveQuestionError(f'{label} contains unsafe or oversized text')
    return value


def _digest(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise FirmwareDiveQuestionError('Expected full lowercase SHA-256')
    return value


def _enum(value, allowed):
    if not isinstance(value, str) or value not in allowed:
        raise FirmwareDiveQuestionError('Value outside frozen vocabulary')
    return value


def _object(value, cls):
    if not isinstance(value, dict) or set(value) != {f.name for f in dataclasses.fields(cls)}:
        raise FirmwareDiveQuestionError(f'{cls.__name__} requires exact schema keys')
    return value


def _canonical(values, label, *, minimum=0):
    if not isinstance(values, (list, tuple)) or len(values) < minimum:
        raise FirmwareDiveQuestionError(f'{label} requires a bounded canonical array')
    if len(values) > 1000 or any(not isinstance(v, str) for v in values) or list(values) != sorted(set(values)):
        raise FirmwareDiveQuestionError(f'{label} requires sorted unique entries')
    return tuple(values)


def _subject(value) -> SubjectRef:
    if isinstance(value, SubjectRef):
        value = str(value)
    if not isinstance(value, str) or ':' not in value:
        raise FirmwareDiveQuestionError('Invalid subject reference')
    kind, identity = value.split(':', 1)
    _enum(kind, ('finding', 'surface-unknown', 'chain-blocker', 'edge', 'chain'))
    if kind in ('edge', 'chain'):
        _digest(identity)
    elif re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', identity) is None:
        raise FirmwareDiveQuestionError('Invalid stable upstream subject ID')
    return SubjectRef(kind, identity)


def _subjects(values):
    if not isinstance(values, (list, tuple)):
        raise FirmwareDiveQuestionError('Subject references require an array')
    result = tuple(_subject(v) for v in values)
    _canonical(tuple(map(str, result)), 'subject_refs', minimum=1)
    return result


def _axes(values):
    if not isinstance(values, (list, tuple)):
        raise FirmwareDiveQuestionError('Axes require an array')
    return _canonical(tuple(_enum(v, db.FIRMWARE_CHAIN_AXES) for v in values), 'axes', minimum=1)


def _contract(value) -> ResolutionContract:
    row = _object(_wire(value), ResolutionContract)
    row['target_subject'] = _subject(row['target_subject'])
    _enum(row['mode'], db.FIRMWARE_DIVE_CONTRACT_MODES)
    _enum(row['predicate'], db.FIRMWARE_DIVE_PREDICATES)
    row['allowed_values'] = _canonical(row['allowed_values'], 'allowed_values')
    if type(row['other_specific']) is not bool:
        raise FirmwareDiveQuestionError('other_specific requires a boolean')
    state = row['predicate'] in ('state-value', 'reachability')
    if state:
        _enum(row['axis'], tuple(_STATE_VALUES))
        if (row['predicate'] == 'reachability') != (row['axis'] == 'reachability'):
            raise FirmwareDiveQuestionError('Predicate and state axis mismatch')
        allowed = _STATE_VALUES[row['axis']]
        if row['other_specific'] or any(row[k] is not None for k in ('capability_kind', 'link_key', 'transition_kind')):
            raise FirmwareDiveQuestionError('State predicates use only frozen axis values')
    else:
        if row['axis'] is not None:
            raise FirmwareDiveQuestionError('Semantic predicates cannot name a state axis')
        allowed = ()
        if row['capability_kind'] is not None:
            _enum(row['capability_kind'], db.FIRMWARE_CHAIN_CAPABILITY_KINDS)
        for key in ('link_key', 'transition_kind'):
            if row[key] is not None:
                _text(row[key], key)
    if row['mode'] == 'boolean-claim':
        if row['allowed_values'] or row['other_specific']:
            raise FirmwareDiveQuestionError('Boolean claims cannot discover values')
        if state:
            _enum(row['expected_value'], allowed)
        elif type(row['expected_value']) is not bool:
            raise FirmwareDiveQuestionError('Semantic boolean claims require a boolean value')
    else:
        if row['expected_value'] is not None:
            raise FirmwareDiveQuestionError('Value discovery cannot presume an expected value')
        if state:
            if not row['allowed_values'] or any(v not in allowed for v in row['allowed_values']):
                raise FirmwareDiveQuestionError('Discovery values exceed frozen vocabulary')
        elif row['predicate'] != 'capability-present' or not row['other_specific'] or row['allowed_values']:
            raise FirmwareDiveQuestionError('Non-state discovery requires the bounded other-specific namespace')
    return ResolutionContract(**row)


def _analyst(value) -> AnalystQuestion:
    row = _object(_wire(value), AnalystQuestion)
    return AnalystQuestion(_subjects(row['subject_refs']), _enum(row['method'], db.FIRMWARE_DIVE_METHODS),
        _text(row['question'], 'question'), _text(row['settling_observation'], 'settling_observation'),
        _axes(row['axes']), _contract(row['resolution_contract']))


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise FirmwareDiveQuestionError('Duplicate JSON key')
        value[key] = item
    return value


def load_analyst_manifest(path: str | pathlib.Path | None) -> tuple[AnalystQuestion, ...]:
    if path is None:
        return ()
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise FirmwareDiveQuestionError('Analyst manifest must be a regular file')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise FirmwareDiveQuestionError('Analyst manifest file identity changed')
            raw = stream.read(MAX_ANALYST_MANIFEST_BYTES + 1)
        if len(raw) > MAX_ANALYST_MANIFEST_BYTES:
            raise FirmwareDiveQuestionError('Analyst manifest exceeds 8 MiB')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(FirmwareDiveQuestionError('Non-finite JSON')))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise FirmwareDiveQuestionError('Cannot read strict analyst manifest') from exc
    if not isinstance(value, dict) or set(value) != {'schema_version', 'questions'} or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise FirmwareDiveQuestionError('Invalid analyst manifest schema')
    if not isinstance(value['questions'], list) or len(value['questions']) > 1000:
        raise FirmwareDiveQuestionError('Questions require a bounded array')
    questions = tuple(_analyst(row) for row in value['questions'])
    if len({_bytes(row) for row in questions}) != len(questions):
        raise FirmwareDiveQuestionError('Duplicate analyst question')
    if questions != tuple(sorted(questions, key=_bytes)):
        raise FirmwareDiveQuestionError('Analyst questions require canonical entry order')
    return questions


def parse_retry_directives(values) -> tuple[RetryDirective, ...]:
    result = []
    for value in values:
        if isinstance(value, RetryDirective):
            directive = value
        else:
            if not isinstance(value, str) or value.count(':') > 1:
                raise FirmwareDiveQuestionError('Invalid retry directive')
            parts = value.split(':')
            directive = RetryDirective(parts[0], parts[1] if len(parts) == 2 else None)
        _digest(directive.question_id)
        if directive.prior_observation_id is not None:
            _digest(directive.prior_observation_id)
        result.append(directive)
    if len({r.question_id for r in result}) != len(result):
        raise FirmwareDiveQuestionError('Duplicate retry directive')
    return tuple(sorted(result, key=lambda r: r.question_id))


def _chain_context(chain):
    return {name: getattr(chain, name) for name in ('member_ids', 'initial_attacker_position',
        'initial_evidence_refs', 'initial_lifecycle', 'initial_posture', 'initial_authentication')}


def edge_fingerprint(snapshot: firmware_chain.VerifiedFirmwareGraphSnapshot, edge: firmware_chain.VerifiedFirmwareEdge) -> str:
    chain, = (c for c in snapshot.chains if c.chain_id == edge.chain_id)
    fields = ('producer_finding_id', 'consumer_finding_id', 'capability_kind', 'link_key',
        'producer_evidence_refs', 'consumer_evidence_refs', 'supplemental_evidence_refs',
        'required_state', 'result_state', 'transition_kind')
    return _hash(dict(image_id=snapshot.image_id, candidate_snapshot_sha256=snapshot.candidate_snapshot_sha256,
        context=_chain_context(chain), edge={k: getattr(edge, k) for k in fields}))


def chain_fingerprint(snapshot: firmware_chain.VerifiedFirmwareGraphSnapshot, chain: firmware_chain.VerifiedFirmwareChain) -> str:
    edges = sorted((e for e in snapshot.edges if e.chain_id == chain.chain_id), key=lambda e: e.ordinal)
    return _hash(dict(image_id=snapshot.image_id, candidate_snapshot_sha256=snapshot.candidate_snapshot_sha256,
        context=_chain_context(chain), edges=tuple(edge_fingerprint(snapshot, e) for e in edges)))


def canonical_question_id(snapshot: firmware_chain.VerifiedFirmwareGraphSnapshot, question: AnalystQuestion | DiveQuestion) -> str:
    return _hash(dict(image_id=snapshot.image_id, candidate_snapshot_sha256=snapshot.candidate_snapshot_sha256,
        subject_refs=sorted(map(str, question.subject_refs)), method=question.method, question=question.question,
        settling_observation=question.settling_observation, axes=sorted(question.axes)))


def _catalog(snapshot):
    subjects = {SubjectRef('finding', f.finding_id): f for f in snapshot.findings}
    linked_unknowns = {u for c in snapshot.chains for u in c.existing_unknown_ids} | {u for d in snapshot.dispositions for u in d.existing_unknown_ids}
    linked_unknowns |= {u.unknown_id for e in snapshot.edges for u in e.existing_unknowns}
    for unknown_id in linked_unknowns:
        found = [u for u in snapshot.unknowns if u.id == unknown_id and u.image_id == snapshot.image_id and u.status == 'open']
        if len(found) != 1:
            raise FirmwareDiveQuestionError('Referenced unknown is foreign, absent or resolved')
        subjects[SubjectRef('surface-unknown', unknown_id)] = found[0]
    linked_blockers = {b for c in snapshot.chains for b in c.blocker_ids} | {b for d in snapshot.dispositions for b in d.blocker_ids} | {b for e in snapshot.edges for b in e.blocker_ids}
    if {b.blocker_id for b in snapshot.blockers} != linked_blockers:
        raise FirmwareDiveQuestionError('Blockers must exactly belong to the completed graph')
    for blocker in snapshot.blockers:
        if blocker.image_id != snapshot.image_id or blocker.status != 'open' or blocker.candidate_snapshot_sha256 != snapshot.candidate_snapshot_sha256:
            raise FirmwareDiveQuestionError('Foreign or noncurrent blocker')
        subjects[SubjectRef('chain-blocker', blocker.blocker_id)] = blocker
    subjects.update((SubjectRef('edge', edge_fingerprint(snapshot, e)), e) for e in snapshot.edges)
    subjects.update((SubjectRef('chain', chain_fingerprint(snapshot, c)), c) for c in snapshot.chains)
    return subjects


def _validate_question(question, snapshot, catalog):
    analyst = _analyst({k: getattr(question, k) for k in ('subject_refs', 'method', 'question', 'settling_observation', 'axes', 'resolution_contract')})
    if any(s not in catalog for s in analyst.subject_refs):
        raise FirmwareDiveQuestionError('Unlinked or stale subject')
    contract = analyst.resolution_contract
    if contract.target_subject not in analyst.subject_refs:
        raise FirmwareDiveQuestionError('Contract target must be an exact question subject')
    if contract.axis is not None and contract.axis not in analyst.axes:
        raise FirmwareDiveQuestionError('Contract axis must affect the question')
    if contract.predicate not in ('state-value', 'reachability'):
        target = catalog[contract.target_subject]
        if contract.mode == 'value-discovery':
            if contract.target_subject.kind != 'surface-unknown' or target.field not in ('handler', 'dispatch'):
                raise FirmwareDiveQuestionError('Specific discovery requires a non-state upstream unknown')
            if any(getattr(contract, k) is not None for k in ('capability_kind', 'link_key', 'transition_kind')):
                raise FirmwareDiveQuestionError('Unknown discovery cannot invent graph capability identity')
        elif contract.target_subject.kind != 'edge' or (contract.capability_kind, contract.link_key) != (target.capability_kind, target.link_key):
            raise FirmwareDiveQuestionError('Semantic contract requires exact edge capability/link identity')
        elif contract.transition_kind != (target.transition_kind if contract.predicate == 'transition-observed' else None):
            raise FirmwareDiveQuestionError('Contract transition identity mismatch')
    if isinstance(question, DiveQuestion):
        _enum(question.origin, db.FIRMWARE_DIVE_ORIGINS)
        if question.question_id != canonical_question_id(snapshot, question):
            raise FirmwareDiveQuestionError('Question identity does not match its semantic projection')
        if type(question.attempt_ordinal) is not int or question.attempt_ordinal < 1:
            raise FirmwareDiveQuestionError('Attempt ordinals start at one')
        if question.prior_observation_id is not None:
            _digest(question.prior_observation_id)
        _canonical(question.supersedes_observation_ids, 'supersedes')
        for observation in question.supersedes_observation_ids:
            _digest(observation)
    return analyst


def _state_contract(subject, axis):
    return ResolutionContract(subject, 'value-discovery', 'reachability' if axis == 'reachability' else 'state-value',
        axis, None, tuple(sorted(_STATE_VALUES[axis])), False, None, None, None)


def _automatic(snapshot, catalog):
    for subject, upstream in sorted(catalog.items()):
        if subject.kind == 'chain-blocker':
            refs = {subject} | {SubjectRef('finding', f) for f in upstream.affected_finding_ids}
            affected = []
            for ref in upstream.affected_edges:
                edges = [e for e in snapshot.edges if (e.chain_id, e.ordinal) == (ref.chain_id, ref.ordinal)]
                if len(edges) != 1:
                    raise FirmwareDiveQuestionError('Blocker edge is outside the completed graph')
                affected.append(edges[0])
            contracts = [ResolutionContract(SubjectRef('edge', edge_fingerprint(snapshot, e)), 'boolean-claim',
                'edge-validity', None, True, (), False, e.capability_kind, e.link_key, None) for e in affected]
            if not contracts:
                contracts = [_state_contract(subject, axis) for axis in upstream.axes]
            for contract in contracts:
                subjects = tuple(sorted(refs | {contract.target_subject}, key=str))
                yield 'chain-blocker', AnalystQuestion(subjects, upstream.method, upstream.question,
                    upstream.settling_observation, (contract.axis,) if contract.axis else upstream.axes, contract)
        elif subject.kind == 'surface-unknown':
            axes = set()
            for edge in snapshot.edges:
                axes.update(a for u in edge.existing_unknowns if u.unknown_id == upstream.id for a in u.axes)
            axis = {'auth':'authentication', 'lifecycle':'lifecycle', 'posture':'posture', 'reachability':'reachability'}.get(upstream.field)
            if axis:
                axes.add(axis)
                contract = _state_contract(subject, axis)
            else:
                contract = ResolutionContract(subject, 'value-discovery', 'capability-present', None,
                    None, (), True, None, None, None)
            if not axes:
                axes.update(db.FIRMWARE_CHAIN_AXES)
            yield 'surface-unknown', AnalystQuestion((subject,), upstream.method, upstream.question,
                upstream.settling_observation, tuple(sorted(axes)), contract)


def _resolution_value(contract, value):
    if contract.mode == 'boolean-claim':
        valid = (type(value) is bool) if type(contract.expected_value) is bool else value in _STATE_VALUES[contract.axis]
    else:
        valid = isinstance(value, str) and (value in contract.allowed_values or
            (contract.other_specific and len(value) <= 128 and re.fullmatch(r'other-specific:[A-Za-z0-9][A-Za-z0-9._:-]*', value) is not None))
    if not valid:
        raise FirmwareDiveQuestionError('Observation value exceeds its exact contract')


def _history(snapshot, catalog, history):
    groups, attempts, observations = {}, {}, {}
    for item in history:
        if not isinstance(item, QuestionHistory):
            raise FirmwareDiveQuestionError('Durable history requires frozen QuestionHistory records')
        _validate_question(item.question, snapshot, catalog)
        if type(item.attempt_ordinal) is not int or item.attempt_ordinal < 1 or type(item.dependency_current) is not bool:
            raise FirmwareDiveQuestionError('Invalid durable attempt or currentness')
        key = (item.question.question_id, item.attempt_ordinal)
        if key in attempts:
            raise FirmwareDiveQuestionError('Duplicate durable attempt')
        attempts[key] = item
        if item.observation_id is None:
            if item.outcome is not None or item.resolution_value is not None or item.dependency_refs or item.evidence_refs or item.supersedes:
                raise FirmwareDiveQuestionError('Unobserved attempts cannot contain observation data')
        else:
            _digest(item.observation_id)
            projection = _bytes((item.question.question_id, item.outcome, item.resolution_value,
                item.dependency_refs, item.evidence_refs, item.supersedes, item.dependency_current))
            if item.observation_id in observations and observations[item.observation_id] != projection:
                raise FirmwareDiveQuestionError('Conflicting reuse of observation identity')
            observations[item.observation_id] = projection
            _enum(item.outcome, ('supported', 'refuted', 'inconclusive'))
            for refs in (item.dependency_refs, item.evidence_refs, item.supersedes):
                _canonical(refs, 'observation references')
                for ref in refs:
                    _digest(ref)
            if item.outcome != 'inconclusive':
                if not item.dependency_refs or not item.evidence_refs or (item.outcome == 'refuted' and item.question.resolution_contract.mode == 'value-discovery'):
                    raise FirmwareDiveQuestionError('Conclusive observations require dependencies/evidence and a valid outcome')
                contract = item.question.resolution_contract
                _resolution_value(contract, item.resolution_value)
                if contract.mode == 'boolean-claim' and ((item.resolution_value == contract.expected_value) != (item.outcome == 'supported')):
                    raise FirmwareDiveQuestionError('Boolean outcome contradicts the exact resolution effect')
            elif item.resolution_value is not None:
                raise FirmwareDiveQuestionError('Inconclusive observations cannot resolve a value')
            if item.supersedes != item.question.supersedes_observation_ids:
                raise FirmwareDiveQuestionError('Observation supersedes must exactly match its question')
        groups.setdefault(item.question.question_id, []).append(item)
    for values in groups.values():
        if sorted(i.attempt_ordinal for i in values) != list(range(1, len(values) + 1)):
            raise FirmwareDiveQuestionError('Durable attempt ordinals must be contiguous from one')
        if len({_bytes((i.question.origin, i.question.supersedes_observation_ids, _analyst({k: getattr(i.question, k) for k in ('subject_refs', 'method', 'question', 'settling_observation', 'axes', 'resolution_contract')}))) for i in values}) != 1:
            raise FirmwareDiveQuestionError('History cannot change an immutable question contract')
    return groups


def _conflict_text(supersedes):
    return 'Resolve conflicting observations: ' + _hash(supersedes)


def derive_questions(snapshot: firmware_chain.VerifiedFirmwareGraphSnapshot, analyst=(), history=(), retries=()) -> QuestionSet:
    catalog = _catalog(snapshot)
    questions = {}
    for origin, raw in (*_automatic(snapshot, catalog), *(('analyst', a) for a in analyst)):
        value = _validate_question(raw, snapshot, catalog)
        identity = canonical_question_id(snapshot, value)
        if identity in questions:
            raise FirmwareDiveQuestionError('Duplicate canonical question identity')
        questions[identity] = DiveQuestion(identity, origin, **{f.name: getattr(value, f.name) for f in dataclasses.fields(value)})
    groups = _history(snapshot, catalog, history)
    for identity in questions.keys() & groups.keys():
        if (questions[identity].resolution_contract, questions[identity].origin) != (groups[identity][0].question.resolution_contract, groups[identity][0].question.origin):
            raise FirmwareDiveQuestionError('Current question cannot change an immutable historical contract')
    active = tuple({i.observation_id: i for values in groups.values() for i in values
        if i.observation_id and i.dependency_current and i.outcome in ('supported', 'refuted')}.values())
    observations = {i.observation_id: i for values in groups.values() for i in values if i.observation_id}
    roots = {}

    def root(item):
        pending, visiting = [(item, False)], set()
        while pending:
            node, expanded = pending.pop()
            identity = node.question.question_id
            if identity in roots:
                continue
            if expanded:
                families = {roots[observations[ref].question.question_id] for ref in node.question.supersedes_observation_ids}
                if len(families) != 1:
                    raise FirmwareDiveQuestionError('Conflict cannot combine unrelated question histories')
                roots[identity] = families.pop()
                visiting.remove(identity)
                continue
            if identity in visiting:
                raise FirmwareDiveQuestionError('Cyclic conflict supersession')
            if node.question.origin != 'conflict':
                if node.supersedes:
                    raise FirmwareDiveQuestionError('Only conflict questions may supersede observations')
                roots[identity] = identity
                continue
            refs = node.question.supersedes_observation_ids
            if len(refs) < 2 or any(ref not in observations for ref in refs):
                raise FirmwareDiveQuestionError('Conflict requires its complete known conflicting observations')
            parents = [observations[ref] for ref in refs]
            if any(p.outcome not in ('supported', 'refuted') or
                   (p.question.subject_refs, p.question.resolution_contract, p.question.method, p.question.axes,
                    p.question.settling_observation) !=
                   (node.question.subject_refs, node.question.resolution_contract, node.question.method,
                    node.question.axes, node.question.settling_observation) for p in parents):
                raise FirmwareDiveQuestionError('Conflict may supersede only matching conclusive subjects/contracts')
            if len({_bytes((p.outcome, p.resolution_value)) for p in parents}) < 2:
                raise FirmwareDiveQuestionError('Conflict cannot supersede agreeing conclusions')
            if node.question.question != _conflict_text(refs):
                raise FirmwareDiveQuestionError('Conflict question must name its exact canonical supersedes set')
            visiting.add(identity)
            pending.append((node, True))
            pending.extend((parent, False) for parent in reversed(parents))
        return roots[item.question.question_id]

    for values in groups.values():
        for item in values:
            root(item)
    # An accepted current superseder removes its exact ancestors, never another
    # answer. New unsuperseded answers remain comparable with that superseder.
    superseded = {ref for i in active for ref in i.supersedes}
    families = {}
    for item in active:
        if item.observation_id not in superseded:
            families.setdefault(roots[item.question.question_id], []).append(item)
    for identity, current in families.items():
        effects = {_bytes((i.outcome, i.resolution_value)) for i in current}
        if len(effects) > 1:
            original = groups[identity][0].question
            supersedes = tuple(sorted(i.observation_id for i in current))
            text = _conflict_text(supersedes)
            conflict = dataclasses.replace(original, question=text, origin='conflict', attempt_ordinal=1,
                prior_observation_id=None, supersedes_observation_ids=supersedes, extract_records=())
            conflict = dataclasses.replace(conflict, question_id=canonical_question_id(snapshot, conflict))
            for family_id, family_root in roots.items():
                if family_root == identity:
                    questions.pop(family_id, None)
            if conflict.question_id in questions:
                raise FirmwareDiveQuestionError('Duplicate conflict question origin')
            questions[conflict.question_id] = conflict
    retry_projection = []
    for directive in parse_retry_directives(retries):
        if directive.question_id not in questions or directive.question_id not in groups:
            raise FirmwareDiveQuestionError('Retry must name an exact current question with durable history')
        prior = groups[directive.question_id]
        if directive.prior_observation_id is not None and directive.prior_observation_id not in {i.observation_id for i in prior}:
            raise FirmwareDiveQuestionError('Retry observation does not belong to its question')
        attempt = max(i.attempt_ordinal for i in prior) + 1
        questions[directive.question_id] = dataclasses.replace(questions[directive.question_id],
            attempt_ordinal=attempt, prior_observation_id=directive.prior_observation_id)
        retry_projection.append((directive.question_id, attempt, directive.prior_observation_id))
    return QuestionSet(tuple(questions[k] for k in sorted(questions)), tuple(retry_projection))


def _relative(value):
    value = _text(value, 'relative_path')
    if value.startswith('/') or '\\' in value or ':' in value or any(p in ('', '.', '..') for p in value.split('/')):
        raise FirmwareDiveQuestionError('Packet paths must be canonical run-relative paths')
    return value


def extract_record(record: extract.Record) -> ExtractRecord:
    """Freeze exact stable extract provenance without source text or timestamps.

    Task 4 must reconstruct this projection from the complete manifest record
    under its publication lock. Source is a canonical relative identity; absolute
    roots never enter the digest. The packet serializer checks named-file bounds.
    """
    if not isinstance(record, extract.Record):
        raise FirmwareDiveQuestionError('Expected an exact upstream extract manifest record')
    _relative(record.source)
    _relative(record.relpath)
    stable = {name: getattr(record, name) for name in
        ('unit', 'name', 'relpath', 'source', 'sha256', 'bytes', 'version', 'truncated', 'backend')}
    return ExtractRecord(record.unit, record.name, record.relpath, record.sha256,
        record.bytes, record.version, record.truncated, record.backend, _hash(stable))


def packet_bytes(question: DiveQuestion, snapshot: firmware_chain.VerifiedFirmwareGraphSnapshot, journal_index=()) -> bytes:
    catalog = _catalog(snapshot)
    _validate_question(question, snapshot, catalog)
    if len(question.extract_records) > MAX_EXTRACT_RECORDS:
        raise FirmwareDiveQuestionError('Packets authorize at most three exact extract records')
    extracts, seen = [], set()
    for record in question.extract_records:
        if not isinstance(record, ExtractRecord):
            raise FirmwareDiveQuestionError('Extracts require exact manifest records')
        for name in (record.unit, record.name):
            if not isinstance(name, str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*', name) is None:
                raise FirmwareDiveQuestionError('Unsafe extract name')
        if record.relative_path != f'extract/{record.unit}/{record.name}' or record.relative_path in seen:
            raise FirmwareDiveQuestionError('Extract path must match one unique named manifest record')
        _relative(record.relative_path)
        _digest(record.sha256)
        _digest(record.manifest_record_sha256)
        if type(record.byte_count) is not int or not 0 <= record.byte_count <= 512_100 or type(record.version) is not int or record.version < 1 or type(record.truncated) is not bool:
            raise FirmwareDiveQuestionError('Invalid bounded extract record')
        _text(record.backend, 'backend', 128)
        seen.add(record.relative_path)
        extracts.append(record)
    if not isinstance(journal_index, (tuple, list)) or len(journal_index) > MAX_JOURNAL_ENTRIES:
        raise FirmwareDiveQuestionError('Journal index exceeds bounded entry limit')
    index, seen = [], set()
    for item in journal_index:
        if not isinstance(item, JournalIndexEntry):
            raise FirmwareDiveQuestionError('Journal index forbids bodies and arbitrary keys')
        _digest(item.observation_id)
        _digest(item.question_id)
        _digest(item.artifact_sha256)
        _relative(item.artifact_path)
        _subjects(item.subject_refs)
        _enum(item.status, ('current', 'stale', 'contested'))
        _enum(item.outcome, ('supported', 'refuted', 'inconclusive'))
        if item.observation_id in seen:
            raise FirmwareDiveQuestionError('Duplicate journal observation')
        seen.add(item.observation_id)
        if set(item.subject_refs) & set(question.subject_refs):
            index.append(item)
    refs, evidence = set(), set()
    refs.add(RetainedRef('chain-artifact', snapshot.graph_sha256, snapshot.graph_path, snapshot.graph_sha256))
    records = [catalog[s] for s in question.subject_refs]
    finding_ids = {s.identity for s in question.subject_refs if s.kind == 'finding'}
    for record in tuple(records):
        if isinstance(record, firmware_chain.VerifiedFirmwareEdge):
            finding_ids.update((record.producer_finding_id, record.consumer_finding_id))
            evidence.update((*record.producer_evidence_refs, *record.consumer_evidence_refs, *record.supplemental_evidence_refs))
        elif isinstance(record, firmware_chain.VerifiedFirmwareChain):
            finding_ids.update(record.member_ids)
            evidence.update(record.initial_evidence_refs)
    records.extend(f for f in snapshot.findings if f.finding_id in finding_ids)
    surface_ids = {s for f in snapshot.findings if f.finding_id in finding_ids for s in f.surface_ids}
    surface_ids.update(r.surface_id for r in records if hasattr(r, 'surface_id') and r.surface_id)
    for ref in tuple(evidence):
        kind, identity = ref.split(':', 1)
        identity = identity.split('#', 1)[0]
        if kind == 'surface':
            surface_ids.add(identity)
        elif kind == 'unknown':
            records.extend(u for u in snapshot.unknowns if u.id == identity)
    records.extend(s for s in snapshot.surfaces if s.surface_id in surface_ids)
    for record in records:
        kind = 'finding-artifact' if hasattr(record, 'finding_id') and isinstance(record, firmware_chain.firmware_fpcheck.VerifiedFirmwareFinding) else 'surface-artifact'
        if isinstance(record, (firmware_chain.VerifiedFirmwareBlocker, firmware_chain.VerifiedFirmwareChain, firmware_chain.VerifiedFirmwareEdge)):
            continue
        logical = getattr(record, 'finding_id', getattr(record, 'id', getattr(record, 'surface_id', None)))
        refs.add(RetainedRef(kind, logical, record.artifact_path, record.artifact_sha256))
        if hasattr(record, 'id'):
            evidence.add('unknown:' + record.id + '#evidence')
    ordered = tuple(sorted(refs, key=lambda r: (r.kind, r.logical_id, r.relative_path, r.sha256)))
    for ref in ordered:
        _relative(ref.relative_path)
        _digest(ref.sha256)
    allowed = ordered + tuple(RetainedRef('extract-record', r.unit + '/' + r.name, r.relative_path, r.sha256) for r in extracts)
    acquisition = AcquisitionContract(snapshot.image_id, snapshot.candidate_snapshot_sha256, question.question_id,
        question.attempt_ordinal, question.subject_refs, question.method,
        () if question.method == 'static' else ('probe-manifest',) if question.method == 'emulate' else ('hardware-capture',),
        None if question.method == 'static' else 'no-network-isolated-probe' if question.method == 'emulate' else 'external-hardware-capture')
    packet = QuestionPacket(1, snapshot.image_id, snapshot.candidate_snapshot_sha256, question, ordered,
        tuple(sorted(evidence)), allowed, tuple(extracts), tuple(sorted(index, key=lambda i: i.observation_id)), acquisition)
    raw = _bytes(packet)
    if len(raw) > MAX_PACKET_BYTES:
        raise FirmwareDiveQuestionError('Packet exceeds byte limit')
    return raw
