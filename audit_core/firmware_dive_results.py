"""Pure strict dive worker results and content-addressed observation identities.

Only load() reads files. This module proves local structure, never prepared
ownership, packet authority, method strength, dependency currentness or SQL rows.
The caller supplies the independently derived evidence rung and candidate hash.
"""
from __future__ import annotations

import dataclasses
import hashlib
import functools
import inspect
import json
import os
import pathlib
import re
import stat

from audit_core import firmware_dive_questions as q

RESULT_SCHEMA_VERSION = 1
MAX_RESULT_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_REFERENCE_BYTES = 8192
_MAX_INTEGER = 2**63 - 1
_ID = r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}'
_KINDS = ('finding-artifact', 'surface-artifact', 'chain-artifact', 'extract-record',
          'probe-manifest', 'hardware-capture')
_RUNGS = ('static-resolved', 'emulated-observed', 'hardware-observed')


class FirmwareDiveResultError(ValueError):
    """A worker result exceeds the exact structural or identity contract."""


def _wire(value):
    if isinstance(value, DiveResult):
        return dict(schema_version=value.schema_version, image_id=value.image_id,
            dive_generation=value.dive_generation,
            questions=[] if isinstance(value.answer, EmptyAnswer) else [_wire(value.answer)])
    return q._wire(value)


def _bytes(value):
    return json.dumps(_wire(value), sort_keys=True, ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode('utf-8')


def _scalar_fields(record, *, skip=()):
    for field in dataclasses.fields(record):
        if field.name not in skip and type(getattr(record, field.name)) not in (str, int, bool, type(None)):
            raise FirmwareDiveResultError('Frozen records require immutable scalar fields')


def _freeze(record, name, cls, *, key=None):
    values = getattr(record, name)
    if not isinstance(values, (list, tuple)) or any(not isinstance(v, cls) for v in values):
        raise FirmwareDiveResultError('Frozen arrays require exact typed entries')
    object.__setattr__(record, name, tuple(sorted(values, key=key)))


@dataclasses.dataclass(frozen=True, slots=True)
class ResolutionEffect:
    target_subject: q.SubjectRef
    mode: str
    predicate: str
    axis: str | None
    value: str | bool
    capability_kind: str | None
    link_key: str | None
    transition_kind: str | None

    def __post_init__(self):
        _scalar_fields(self, skip=('target_subject',))
        ref = self.target_subject
        if not isinstance(ref, q.SubjectRef) or type(ref.kind) is not str or type(ref.identity) is not str:
            raise FirmwareDiveResultError('Effect requires a frozen subject reference')


@dataclasses.dataclass(frozen=True, slots=True)
class DependencyRef:
    kind: str
    logical_id: str
    relative_path: str
    sha256: str
    byte_count: int

    def __post_init__(self):
        _scalar_fields(self)


def _dependency_key(value):
    return (value.kind, value.logical_id, value.relative_path, value.sha256, value.byte_count)


@dataclasses.dataclass(frozen=True, slots=True)
class EvidenceRef:
    dependency_kind: str
    dependency_logical_id: str
    reference: str

    def __post_init__(self):
        _scalar_fields(self)


@dataclasses.dataclass(frozen=True, slots=True)
class SuccessorQuestion(q.AnalystQuestion):
    def __post_init__(self):
        # Reuse the existing exact question vocabulary and freeze nested arrays.
        validated = q._analyst(self)
        for field in dataclasses.fields(validated):
            object.__setattr__(self, field.name, getattr(validated, field.name))


@dataclasses.dataclass(frozen=True, slots=True)
class QuestionAnswer:
    question_id: str
    attempt_ordinal: int
    packet_sha256: str
    outcome: str
    conclusion: str
    limitations: tuple[str, ...]
    resolution_effect: ResolutionEffect | None
    dependencies: tuple[DependencyRef, ...]
    evidence: tuple[EvidenceRef, ...]
    successor_questions: tuple[SuccessorQuestion, ...]

    def __post_init__(self):
        _scalar_fields(self, skip=('limitations', 'dependencies', 'evidence', 'successor_questions', 'resolution_effect'))
        if self.resolution_effect is not None and not isinstance(self.resolution_effect, ResolutionEffect):
            raise FirmwareDiveResultError('Answer effect requires a frozen ResolutionEffect')
        _freeze(self, 'limitations', str)
        _freeze(self, 'dependencies', DependencyRef, key=_dependency_key)
        _freeze(self, 'evidence', EvidenceRef, key=_bytes)
        _freeze(self, 'successor_questions', SuccessorQuestion, key=_bytes)


@dataclasses.dataclass(frozen=True, slots=True)
class EmptyAnswer:
    """The explicit zero-question wire; external denominator is caller authority."""


@dataclasses.dataclass(frozen=True, slots=True)
class DiveResult:
    schema_version: int
    image_id: str
    dive_generation: str
    answer: QuestionAnswer | EmptyAnswer

    def __post_init__(self):
        _scalar_fields(self, skip=('answer',))
        if not isinstance(self.answer, (QuestionAnswer, EmptyAnswer)):
            raise FirmwareDiveResultError('Result requires a frozen answer variant')


def _image(value):
    if not isinstance(value, str) or not value or '\0' in value or len(value.encode('utf-8')) > 4096:
        raise FirmwareDiveResultError('image_id requires bounded nonempty UTF-8 without NUL')
    return value


def _integer(value, *, minimum=0):
    if type(value) is not int or not minimum <= value <= _MAX_INTEGER:
        raise FirmwareDiveResultError('Expected bounded integer without coercion')
    return value


def _logical(kind, value):
    q._enum(kind, _KINDS)
    if kind == 'extract-record':
        pattern = r'[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*'
    elif kind in ('chain-artifact', 'probe-manifest', 'hardware-capture'):
        return q._digest(value)
    else:
        pattern = _ID
    if not isinstance(value, str) or len(value.encode('utf-8')) > 4096 or re.fullmatch(pattern, value) is None:
        raise FirmwareDiveResultError('Invalid dependency logical identity')
    return value


def _array(value, label, *, maximum=1000, key=None):
    if not isinstance(value, list) or len(value) > maximum:
        raise FirmwareDiveResultError(f'{label} requires a bounded array')
    identities = [key(item) if key else item for item in value]
    if identities != sorted(identities) or len(set(identities)) != len(identities):
        raise FirmwareDiveResultError(f'{label} requires sorted unique entries')
    return value


def _effect(value):
    if value is None:
        return None
    row = q._object(value, ResolutionEffect)
    # A synthetic local contract validates only the effect vocabulary, never the
    # real packet predicate. validate_answer() later compares that exact contract.
    mode, observed = row['mode'], row['value']
    discovery = mode == 'value-discovery'
    contract = q._contract(dict(target_subject=row['target_subject'], mode=mode,
        predicate=row['predicate'], axis=row['axis'], expected_value=None if discovery else observed,
        allowed_values=[observed] if discovery and row['axis'] is not None else [],
        other_specific=discovery and row['axis'] is None,
        capability_kind=row['capability_kind'], link_key=row['link_key'], transition_kind=row['transition_kind']))
    q._resolution_value(contract, observed)
    return ResolutionEffect(contract.target_subject, mode, contract.predicate, contract.axis,
        observed, contract.capability_kind, contract.link_key, contract.transition_kind)


def _dependency(value):
    row = q._object(value, DependencyRef)
    return DependencyRef(q._enum(row['kind'], _KINDS), _logical(row['kind'], row['logical_id']),
        q._relative(row['relative_path']), q._digest(row['sha256']), _integer(row['byte_count']))


def _evidence(value):
    row = q._object(value, EvidenceRef)
    kind = q._enum(row['dependency_kind'], _KINDS)
    logical = _logical(kind, row['dependency_logical_id'])
    reference = q._text(row['reference'], 'reference', MAX_EVIDENCE_REFERENCE_BYTES)
    match = re.fullmatch(r'(probe|capture):([0-9a-f]{64})#(.+)', reference)
    if match:
        namespace, identity, path = match.groups()
        q._relative(path)
        parts = path.split('/')
        if len(parts) > 32 or any(len(part.encode('utf-8')) > 255 for part in parts):
            raise FirmwareDiveResultError('Dynamic evidence path exceeds acquisition component limits')
        if kind != ('probe-manifest' if namespace == 'probe' else 'hardware-capture') or logical != identity:
            raise FirmwareDiveResultError('Dynamic evidence requires its exact acquisition dependency')
    elif re.fullmatch(rf'(finding|surface|unknown):({_ID})#[a-z_]+', reference) is None and re.fullmatch(
            r'dive:[0-9a-f]{64}#(conclusion|evidence)', reference) is None:
        raise FirmwareDiveResultError('Invalid machine-addressable evidence reference')
    return EvidenceRef(kind, logical, reference)


def _answer(value):
    row = q._object(value, QuestionAnswer)
    raw_dependencies = row['dependencies']
    if not isinstance(raw_dependencies, list) or len(raw_dependencies) > 1000:
        raise FirmwareDiveResultError('Dependencies require a bounded array')
    dependencies = tuple(_dependency(item) for item in raw_dependencies)
    _array(list(dependencies), 'dependencies', key=_dependency_key)
    if len({(item.kind, item.logical_id) for item in dependencies}) != len(dependencies):
        raise FirmwareDiveResultError('Duplicate logical dependency identity')
    evidence = tuple(_evidence(item) for item in _array(row['evidence'], 'evidence', key=_bytes))
    submitted = {(item.kind, item.logical_id) for item in dependencies}
    if any((item.dependency_kind, item.dependency_logical_id) not in submitted for item in evidence):
        raise FirmwareDiveResultError('Evidence requires its submitted dependency')
    limitations = tuple(q._text(item, 'limitations') for item in _array(row['limitations'], 'limitations'))
    successors = []
    for item in _array(row['successor_questions'], 'successor_questions', maximum=100, key=_bytes):
        validated = q._analyst(item)
        successors.append(SuccessorQuestion(**{f.name:getattr(validated, f.name) for f in dataclasses.fields(validated)}))
    effect = _effect(row['resolution_effect'])
    outcome = q._enum(row['outcome'], ('supported', 'refuted', 'inconclusive'))
    if outcome == 'inconclusive':
        if effect is not None:
            raise FirmwareDiveResultError('Inconclusive answers cannot resolve an effect')
    elif not dependencies or not evidence or effect is None or (outcome == 'refuted' and effect.mode == 'value-discovery'):
        raise FirmwareDiveResultError('Conclusive answers require evidence, dependencies and a valid effect')
    return QuestionAnswer(q._digest(row['question_id']), _integer(row['attempt_ordinal'], minimum=1),
        q._digest(row['packet_sha256']), outcome, q._text(row['conclusion'], 'conclusion'), limitations,
        effect, dependencies, evidence, tuple(successors))


def _bounded(value):
    pending = [(value, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > 16:
            raise FirmwareDiveResultError('Result nesting exceeds limit')
        if isinstance(node, dict):
            pending.extend((item, depth + 1) for item in node.values())
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)


def _parse(value):
    _bounded(value)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'image_id', 'dive_generation', 'questions'}:
        raise FirmwareDiveResultError('Dive result requires exact envelope keys')
    if type(value['schema_version']) is not int or value['schema_version'] != RESULT_SCHEMA_VERSION:
        raise FirmwareDiveResultError('schema_version requires integer 1')
    entries = value['questions']
    if not isinstance(entries, list) or len(entries) > 1:
        raise FirmwareDiveResultError('Result requires zero or exactly one question answer')
    return DiveResult(RESULT_SCHEMA_VERSION, _image(value['image_id']), q._digest(value['dive_generation']),
        _answer(entries[0]) if entries else EmptyAnswer())


def _guard(function):
    """Keep hostile input failures in one public exception vocabulary."""
    signature = inspect.signature(function)
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        signature.bind(*args, **kwargs)
        try:
            return function(*args, **kwargs)
        except FirmwareDiveResultError:
            raise
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            raise FirmwareDiveResultError('Invalid strict firmware dive result') from exc
    return guarded


@_guard
def canonical_bytes(result: DiveResult) -> bytes:
    """Serialize the exact worker wire, enforcing the canonical 8 MiB cap."""
    if not isinstance(result, DiveResult) or not isinstance(result.answer, (QuestionAnswer, EmptyAnswer)):
        raise FirmwareDiveResultError('Expected a frozen DiveResult variant')
    content = _bytes(_parse(_wire(result)))
    if len(content) > MAX_RESULT_BYTES:
        raise FirmwareDiveResultError('Canonical result exceeds 8 MiB')
    return content


def _pairs(pairs):
    row = {}
    for key, value in pairs:
        if key in row:
            raise FirmwareDiveResultError('Duplicate JSON key')
        row[key] = value
    return row


def _constant(_):
    raise FirmwareDiveResultError('Non-finite JSON value')


@_guard
def load(path: str | pathlib.Path) -> DiveResult:
    """Read one bounded stable regular file; prepared assignment is Task 8."""
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise FirmwareDiveResultError('Result must be a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or _signature(before) != _signature(opened):
            raise FirmwareDiveResultError('Result file identity changed')
        raw = stream.read(MAX_RESULT_BYTES + 1)
        after = os.fstat(stream.fileno())
    if _signature(opened) != _signature(after) or _signature(after) != _signature(os.lstat(path)):
        raise FirmwareDiveResultError('Result file changed during read')
    if len(raw) > MAX_RESULT_BYTES:
        raise FirmwareDiveResultError('Raw result exceeds 8 MiB')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    result = _parse(value)
    canonical_bytes(result)
    return result


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@_guard
def validate_answer(answer: QuestionAnswer, contract: q.ResolutionContract) -> None:
    """Pure packet-contract comparison; no generation or reference authorization."""
    if not isinstance(answer, QuestionAnswer) or not isinstance(contract, q.ResolutionContract):
        raise FirmwareDiveResultError('Expected frozen answer and resolution contract')
    answer = _answer(_wire(answer))
    contract = q._contract(contract)
    if answer.outcome == 'inconclusive':
        return
    effect = answer.resolution_effect
    for name in ('target_subject', 'mode', 'predicate', 'axis', 'capability_kind', 'link_key', 'transition_kind'):
        if getattr(effect, name) != getattr(contract, name):
            raise FirmwareDiveResultError('Resolution effect exceeds the exact packet contract')
    q._resolution_value(contract, effect.value)
    if contract.mode == 'boolean-claim' and ((effect.value == contract.expected_value) != (answer.outcome == 'supported')):
        raise FirmwareDiveResultError('Outcome contradicts the packet expected value')


@_guard
def canonical_observation_id(*, image_id: str, candidate_snapshot_sha256: str,
        answer: QuestionAnswer, evidence_rung: str | None) -> str:
    """Bind exact semantic observations, with a caller-derived rung/snapshot."""
    if not isinstance(answer, QuestionAnswer):
        raise FirmwareDiveResultError('Observation requires one QuestionAnswer')
    answer = _answer(_wire(answer))
    if answer.outcome == 'inconclusive':
        if evidence_rung is not None:
            raise FirmwareDiveResultError('Inconclusive evidence rung must be null')
    else:
        q._enum(evidence_rung, _RUNGS)
    projection = dict(image_id=_image(image_id), candidate_snapshot_sha256=q._digest(candidate_snapshot_sha256),
        question_id=answer.question_id, outcome=answer.outcome, conclusion=answer.conclusion,
        limitations=answer.limitations, evidence_rung=evidence_rung, resolution_effect=answer.resolution_effect,
        dependencies=answer.dependencies, evidence=answer.evidence)
    return hashlib.sha256(_bytes(projection)).hexdigest()


@_guard
def canonical_receipt_key(*, image_id: str, dive_generation: str, result_sha256: str,
        receipt_kind: str = 'question', question_id: str | None = None,
        attempt_ordinal: int | None = None, packet_sha256: str | None = None) -> str:
    """Exact receipt projections exclude local paths, timestamps and prose."""
    projection = dict(image_id=_image(image_id), dive_generation=q._digest(dive_generation),
        result_sha256=q._digest(result_sha256))
    if receipt_kind == 'empty':
        if any(v is not None for v in (question_id, attempt_ordinal, packet_sha256)):
            raise FirmwareDiveResultError('Empty receipts forbid question/packet fields')
        projection['receipt_kind'] = 'empty'
    elif receipt_kind == 'question':
        projection.update(question_id=q._digest(question_id), attempt_ordinal=_integer(attempt_ordinal, minimum=1),
            packet_sha256=q._digest(packet_sha256))
    else:
        raise FirmwareDiveResultError('Invalid receipt variant')
    return 'firmware-dive-receipt-' + hashlib.sha256(_bytes(projection)).hexdigest()
