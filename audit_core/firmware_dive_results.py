"""Pure strict dive worker results and content-addressed observation identities.

Pure parsing and identity helpers are separate from retained assignment validation
and artifact-first receipt publication. Import reconstructs packet/acquisition
authority without a live root and always leaves the owning generation pending.
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
import sqlite3

from audit_core import db, firmware_chain, firmware_fpcheck, hunt, surface
from audit_core import firmware_dive as dive
from audit_core import firmware_dive_acquisition as acquisition
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
    try:
        object.__setattr__(record, name, tuple(sorted(values, key=key)))
    except (ValueError, TypeError) as exc:
        raise FirmwareDiveResultError('Frozen array entries cannot be ordered') from exc


def _constructor(cls):
    """Normalize malformed direct constructor calls at the public boundary."""
    original = cls.__init__
    @functools.wraps(original)
    def initialize(self, *args, **kwargs):
        try:
            original(self, *args, **kwargs)
        except FirmwareDiveResultError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            raise FirmwareDiveResultError('Invalid firmware dive result constructor') from exc
    cls.__init__ = initialize
    return cls


@_constructor
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


@_constructor
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


@_constructor
@dataclasses.dataclass(frozen=True, slots=True)
class EvidenceRef:
    dependency_kind: str
    dependency_logical_id: str
    reference: str

    def __post_init__(self):
        _scalar_fields(self)


@_constructor
@dataclasses.dataclass(frozen=True, slots=True)
class SuccessorQuestion(q.AnalystQuestion):
    def __post_init__(self):
        # Reuse the existing exact question vocabulary and freeze nested arrays.
        try:
            validated = q._analyst(self)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise FirmwareDiveResultError('Invalid successor question constructor') from exc
        for field in dataclasses.fields(validated):
            object.__setattr__(self, field.name, getattr(validated, field.name))


@_constructor
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


@_constructor
@dataclasses.dataclass(frozen=True, slots=True)
class EmptyAnswer:
    """The explicit zero-question wire; external denominator is caller authority."""


@_constructor
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


# Import authority deliberately lives below the pure worker boundary. No live
# root, worker-supplied provenance, completion gate or mutable overlay is used.
@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedDiveResult:
    receipt: dict
    observation: dict | None
    dependencies: tuple[dict, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class RecordSummary:
    image_id: str
    dive_generation: str
    receipt_key: str
    observation_id: str | None
    artifact_path: str
    dependency_count: int
    evidence_count: int
    successor_count: int


def _require(value, message):
    if not value:
        raise FirmwareDiveResultError(message)


def _cell(value):
    return _bytes(value).decode('utf-8')


def _retained_graph(con, run, owner):
    """Reconstruct the exact owner, including after current chain invalidation."""
    inputs, _, _, findings, destination, digest = firmware_fpcheck._verified_review(
        con, run, None, owner['image_id'], require_complete=True)
    upstream, review, _, stored, _, _ = inputs
    def typed(cls, row):
        values = {field.name:row[field.name] for field in dataclasses.fields(cls)}
        values['artifact_path'] = pathlib.Path(values['artifact_path']).relative_to(run).as_posix()
        if cls is firmware_fpcheck.VerifiedFirmwareFinding:
            values['contributors'] = tuple(firmware_fpcheck.VerifiedFirmwareContributor(**r)
                for r in json.loads(values['contributors']))
            for name in ('lanes','component_paths','surface_ids'):
                values[name] = tuple(json.loads(values[name]))
        return cls(**values)
    finding_records = tuple(typed(firmware_fpcheck.VerifiedFirmwareFinding, row) for row in findings)
    surface_ids = {identity for row in finding_records for identity in row.surface_ids}
    component_paths = {path for row in finding_records for path in row.component_paths}
    surfaces = tuple(typed(firmware_fpcheck.VerifiedFirmwareSurface, row) for row in surface._query(con,
        'SELECT * FROM cba_firmware_surfaces WHERE image_id=? ORDER BY surface_id',(upstream.image_id,)) if row['surface_id'] in surface_ids)
    unknowns = tuple(typed(firmware_fpcheck.VerifiedFirmwareUnknown, row) for row in surface._query(con,
        'SELECT * FROM cba_unknowns WHERE image_id=? ORDER BY id',(upstream.image_id,)) if row['surface_id'] in surface_ids or row['component_path'] in component_paths)
    snapshot = firmware_fpcheck.VerifiedFirmwareFindingsSnapshot(upstream.image_id,upstream.manifest_sha256,
        upstream.surface_snapshot_sha256,review['candidate_snapshot_sha256'],review['worklist_sha256'],
        (destination/'findings.json').relative_to(run).as_posix(),digest,finding_records,surfaces,unknowns,
        tuple(typed(firmware_fpcheck.VerifiedFirmwarePivot,row) for row in sorted(stored[1],key=lambda r:r['pivot_id'])))
    _require(all(owner[key] == getattr(snapshot,key) for key in ('image_id','manifest_sha256',
        'surface_snapshot_sha256','candidate_snapshot_sha256')), 'Prepared dive upstream ownership differs')
    relative, digest = owner['chain_graph_path'], owner['chain_graph_sha256']
    raw = dive._read(run,relative,digest)
    body = dive._json(raw,newline=True)
    parsed = firmware_chain._graph_result(body)
    overlay = firmware_chain._retained_worklist_overlay(run,snapshot,parsed.worklist_sha256)
    validated, expected = firmware_chain._verified_graph(snapshot,parsed,body['result_sha256'],overlay)
    _require(raw == expected and relative == 'artifacts/firmware-chain/' + parsed.worklist_sha256 + '/' + digest + '/chains.json',
        'Prepared dive graph is not its canonical owned projection')
    dive._checked_install(run/pathlib.PurePosixPath(relative).parent,{'chains.json':raw},run)
    return firmware_chain._graph_snapshot(snapshot,validated,relative,digest), snapshot


def _static_provenance(run, dependency, packet, owner, *, retained=False):
    """Reconstruct owners from the exact retained artifact, never worker fields."""
    ref = _wire(dependency)
    base = {key:ref[key] for key in ('kind','logical_id','relative_path','sha256')}
    _require(base in packet['allowed_dependencies'], 'Dependency is not packet-authorized')
    raw = dive._read(run,dependency.relative_path,dependency.sha256)
    _require(len(raw) == dependency.byte_count, 'Dependency byte count differs')
    if dependency.kind == 'extract-record':
        selected = [r for r in packet['extract_records'] if r['unit']+'/'+r['name'] == dependency.logical_id]
        _require(len(selected) == 1, 'Extract lacks exact packet owner')
        if not retained: dive._extracts(run,(q.ExtractRecord(**selected[0]),))
        return base | dict(extract_record=selected[0])
    if dependency.kind == 'chain-artifact':
        body = dive._json(raw,newline=True)
        _require(dependency.logical_id == dependency.sha256 and packet['candidate_snapshot_sha256'] == body['candidate_snapshot_sha256']
            and packet['image_id'] == body['image_id'], 'Chain dependency ownership differs')
        return base | dict(graph_projection=dict(image_id=body['image_id'],candidate_snapshot_sha256=body['candidate_snapshot_sha256'],
            manifest_sha256=owner['manifest_sha256'],surface_snapshot_sha256=owner['surface_snapshot_sha256'],
            chain_worklist_sha256=body['worklist_sha256'],graph_path=dependency.relative_path,graph_sha256=dependency.sha256))
    body = json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_constant)
    matches = []
    pending = [body]
    while pending:
        item = pending.pop()
        if isinstance(item,dict):
            identifier = item.get('finding_id') if dependency.kind == 'finding-artifact' else item.get('id',item.get('surface_id'))
            if identifier == dependency.logical_id:
                matches.append(item)
            pending.extend(item.values())
        elif isinstance(item,list):
            pending.extend(item)
    # A surface unknown includes surface_id plus its own id. Select its own ID
    # first, rather than accidentally attributing its bytes to the parent surface.
    if dependency.kind == 'surface-artifact':
        matches = [item for item in matches if item.get('id',item.get('surface_id')) == dependency.logical_id]
    _require(len(matches) == 1, 'Static dependency lacks one exact artifact owner')
    return base | dict(owner_sha256=q._hash(matches[0]))


def _clean_probe(manifest):
    """Eligibility follows verified status; a voluntary code is not a signal."""
    term = manifest['termination']
    if not term['executed'] or term['timed_out']:
        return False
    if term['status_source'] == 'direct-process':
        return term['reason'] == 'exited' and term['signal'] is None
    return (term['status_source'] == manifest['spec']['isolation_backend']+'-adapter' and
        term['reason'] == 'adapter-exited' and term['adapter_exit_code'] == 0 and term['adapter_signal'] is None)


def _probe_manifest_contract(manifest, spec):
    """Reconstruct the Task 6 emitted state machine, independently of its hash."""
    term = q._object(manifest['termination'], acquisition.ProbeTermination)
    for name in ('executed','timed_out','stdout_truncated','stderr_truncated'):
        _require(type(term[name]) is bool, 'Probe termination requires booleans')
    for name in ('exit_code','adapter_exit_code','signal','adapter_signal'):
        if term[name] is not None:
            _integer(term[name], minimum=1 if name.endswith('signal') else 0)
            _require(term[name] <= (127 if name.endswith('signal') else 255), 'Probe wait status exceeds OS bounds')
    source, reason = term['status_source'], term['reason']
    native = source != 'direct-process'
    _require(source in ('direct-process',spec.isolation_backend+'-adapter'), 'Probe status backend differs')
    exit_name, signal_name = ('adapter_exit_code','adapter_signal') if native else ('exit_code','signal')
    unused = ('exit_code','signal') if native else ('adapter_exit_code','adapter_signal')
    _require(all(term[name] is None for name in unused), 'Probe payload and adapter status are conflated')
    if term['executed']:
        exited, signaled = ('adapter-exited','adapter-signal') if native else ('exited','signal')
        _require(reason in (exited,signaled,'timeout','output-limit'), 'Executed probe has nonexecution reason')
        _require((term[exit_name] is None) != (term[signal_name] is None), 'Executed probe requires one exact wait status')
        _require(reason != exited or term[exit_name] is not None, 'Exited probe lacks exit status')
        _require(reason != signaled or term[signal_name] is not None, 'Signaled probe lacks signal status')
        _require(reason == 'output-limit' or term['timed_out'] == (reason == 'timeout'), 'Probe timeout flag contradicts reason')
        _require(term[signal_name] != acquisition.signal.SIGXFSZ or reason == 'output-limit', 'File-size signal requires output-limit')
    else:
        _require(reason in ('isolation-unavailable','unsupported-limits','unsupported-helper','unsupported-runner','tool-unavailable'),
            'Nonexecuted probe has execution reason')
        _require(all(term[name] is None for name in ('exit_code','signal','adapter_exit_code','adapter_signal')) and
            not any(term[name] for name in ('timed_out','stdout_truncated','stderr_truncated')), 'Nonexecuted probe has execution facts')
        if native:
            _require(reason in ('isolation-unavailable','unsupported-limits','tool-unavailable'), 'Native early refusal has wrong status source')
    runtime = manifest['runtime']
    _require(isinstance(runtime,dict) and set(runtime) == {'platform','version','stream_source','tool_runtime_limitation','system_read_roots','limitation'},
        'Probe runtime schema differs')
    q._text(runtime['platform'],'runtime platform',128)
    q._text(runtime['version'],'runtime version')
    if native:
        _require(runtime['platform'] == 'linux' if spec.isolation_backend == 'bwrap' else runtime['platform'] == 'darwin',
            'Native probe platform differs from backend')
    roots = ['/System','/usr/lib','/private/var/db/dyld','/dev/null','/dev/urandom'] if spec.isolation_backend == 'sandbox-exec' else []
    _require(runtime['stream_source'] == (source if term['executed'] else 'not-executed') and
        runtime['tool_runtime_limitation'] == 'Staged adapter host runtime before isolation is trusted tooling' and
        runtime['system_read_roots'] == roots and runtime['limitation'] ==
        ('Apple system runtime reads are not firmware library evidence' if spec.isolation_backend == 'sandbox-exec' else None),
        'Probe runtime facts differ from exact builder contract')
    deps = manifest['dependencies']
    _require(isinstance(deps,list) and 1 <= len(deps) <= 519, 'Probe dependency denominator differs')
    keys = []
    for dep in deps:
        _require(isinstance(dep,dict) and set(dep) == {'role','path','before','after'}, 'Probe dependency schema differs')
        keys.append((dep['role'],dep['path']))
    has_adapter = ('adapter',None) in keys
    has_helper = ('environment-launcher',None) in keys
    _require(has_adapter or not term['executed'] and reason == 'isolation-unavailable' and not native,
        'Probe execution/refusal lacks adapter ownership')
    _require(not native or has_adapter, 'Native probe lacks adapter')
    if has_adapter and not term['executed'] and not native:
        _require(reason != 'isolation-unavailable', 'Adapter-owned isolation refusal requires adapter status')
    needs_helper = acquisition._needs_environment_launcher(spec)
    _require(not has_helper or has_adapter and needs_helper and (native or not term['executed']), 'Probe helper exceeds backend authority')
    if native:
        _require(has_helper == needs_helper, 'Native helper denominator differs')
    if reason == 'unsupported-helper':
        _require(not native and has_helper, 'Unsupported helper refusal lacks exact native helper')
    if reason == 'unsupported-runner':
        _require(not native and has_adapter and spec.isolation_backend == 'bwrap' and spec.runner is not None,
            'Unsupported runner refusal lacks exact native runner')
    required = [('executable',spec.executable),*[('library',path) for path in spec.libraries],*[('input',path) for path in spec.inputs]]
    required += [(role,path) for role,path in (('loader',spec.loader),('nvram-shim',spec.nvram_shim),('stdin',spec.stdin)) if path is not None]
    if spec.runner is not None: required.append(('runner',None))
    if has_adapter: required.append(('adapter',None))
    if has_helper: required.append(('environment-launcher',None))
    _require(keys == required, 'Probe input roles, paths or order differ from sealed spec')
    guest, runner = {}, None
    for dep in deps:
        helper = dep['role'] == 'environment-launcher'
        for name in ('before','after'):
            fact = dep[name]
            if fact is None:
                _require(helper and not term['executed'] and not native and reason in ('unsupported-helper','unsupported-limits'),
                    'Required probe dependency lacks exact file facts')
            else:
                _require(isinstance(fact,dict) and set(fact) == {'sha256','byte_count'}, 'Probe input fact schema differs')
                q._digest(fact['sha256'])
                _integer(fact['byte_count'])
                _require(fact['byte_count'] <= acquisition.MAX_DEPENDENCY_BYTES, 'Probe dependency exceeds byte bound')
        _require(dep['before'] == dep['after'] or helper and not term['executed'] and not native and reason == 'unsupported-helper',
            'Probe dependency facts drifted outside helper refusal')
        if dep['path'] is not None:
            _require(dep['path'] not in guest or guest[dep['path']] == dep['before'], 'Aliased probe input facts differ')
            guest[dep['path']] = dep['before']
        elif dep['role'] == 'runner': runner = dep['before']
    pre_staging = not term['executed'] and not native and (
        reason in ('unsupported-limits','unsupported-helper','unsupported-runner') or
        reason == 'isolation-unavailable' and not has_adapter)
    if not pre_staging:
        reserved = ({'_runner'} if spec.runner is not None else set()) | (
            {'_environment-launcher'} if has_helper else set())
        staged = set(guest)
        _require(staged.isdisjoint(reserved), 'Probe guest conflicts with reserved staged tool')
        staged.update(reserved)
        directories = {parent.as_posix() for name in staged for parent in pathlib.PurePosixPath(name).parents}
        _require(staged.isdisjoint(directories), 'Probe staged files have ancestor/descendant collisions')
    # A sealed runner omits its host path; identical facts can alias one guest
    # file. Distinct facts must count as a distinct staged file and byte total.
    extra_runner = runner is not None and runner not in guest.values()
    _require(len(guest)+extra_runner <= 256 and sum(fact['byte_count'] for fact in guest.values())+
        (runner['byte_count'] if extra_runner else 0) <= acquisition.MAX_DEPENDENCY_BYTES, 'Probe staged input aggregate exceeds limits')
    evidence = manifest['evidence']
    _require(isinstance(evidence,list) and all(isinstance(row,dict) and set(row) == {'path','sha256','byte_count'} for row in evidence),
        'Probe evidence schema differs')
    paths = [row['path'] for row in evidence]
    _require(all(isinstance(path,str) for path in paths) and paths == sorted(set(paths)) and
        {'evidence/stdout','evidence/stderr'} <= set(paths), 'Probe evidence order/streams differ')
    output_paths = [path for path in paths if path.startswith('outputs/')]
    _require(not output_paths or term['executed'] and reason != 'output-limit' and
        (not native or reason == 'adapter-exited' and term['adapter_exit_code'] == 0), 'Probe outputs violate execution status policy')
    for name in ('stdout','stderr'):
        row = next(row for row in evidence if row['path'] == 'evidence/'+name)
        _integer(row['byte_count'])
        _require(not term[name+'_truncated'] or row['byte_count'] == acquisition.MAX_PROBE_STREAM_BYTES,
            'Probe stream truncation lacks the exact retained prefix')
        _require(term['executed'] or row['byte_count'] == 0, 'Nonexecuted probe has stream bytes')


def _sealed_acquisition(run, row, packet):
    """Verify complete acquisition identity, contract, tree and SQL projections."""
    kind, identity = row['kind'], row['acquisition_id']
    contract = packet['acquisition_contract']
    dependency_kind = 'probe-manifest' if kind == 'probe' else 'hardware-capture'
    _require(dependency_kind in contract['artifact_kinds'] and row['contract_sha256'] == q._hash(contract),
        'Acquisition exceeds packet contract')
    prefix = 'artifacts/firmware-dive-' + ('probes/' if kind == 'probe' else 'captures/') + identity
    _require((row['spec_path'],row['manifest_path']) == (prefix+'/spec.json',prefix+'/manifest.json'),
        'Acquisition paths differ from identity')
    spec_raw = dive._read(run,row['spec_path'],row['spec_sha256'],MAX_RESULT_BYTES)
    manifest_raw = dive._read(run,row['manifest_path'],row['manifest_sha256'],MAX_RESULT_BYTES)
    spec, manifest = dive._json(spec_raw), dive._json(manifest_raw)
    expected_assignment = dict(image_id=row['image_id'],dive_generation=row['dive_generation'],question_id=row['question_id'],
        packet_sha256=dive._digest(q._bytes(packet)),contract_sha256=row['contract_sha256'])
    _require(all(spec.get(key) == value for key,value in expected_assignment.items()), 'Acquisition assignment differs')
    _require(spec.get('method') == contract['method'] and type(spec.get('schema_version')) is int and spec['schema_version'] == 1,
        'Acquisition method/schema differs')
    contents = {'spec.json':spec_raw,'manifest.json':manifest_raw}
    evidence = manifest['evidence']
    _require(isinstance(evidence,list) and 1 <= len(evidence) <= 258, 'Invalid sealed evidence denominator')
    paths, total, outputs = [], 0, 0
    if kind == 'capture':
        _require(set(manifest) == set(spec) | {'kind','acquisition_id'} and manifest['kind'] == 'capture', 'Capture manifest schema differs')
        names = spec['evidence']
        synthetic = spec | dict(evidence=[dict(name=name,source_path=name) for name in names])
        parsed = acquisition._parse(q._bytes(synthetic))
        _require(q._wire(dataclasses.asdict(parsed) | dict(evidence=[name for name,_ in parsed.evidence])) == spec,
            'Capture sealed spec differs')
        _require(len(evidence) <= contract['max_files'] and [r['name'] for r in evidence] == names,
            'Capture evidence names differ')
        expected_id = q._hash(dict(kind='capture',spec=spec,evidence=evidence))
        _require(manifest == spec | dict(kind='capture',acquisition_id=identity,evidence=evidence), 'Capture spec/manifest differ')
    else:
        _require(set(manifest) == {'kind','acquisition_id','spec','network_policy','dependencies','termination','evidence','runtime'}
            and manifest['kind'] == 'probe' and manifest['spec'] == spec and manifest['network_policy'] == 'none',
            'Probe manifest schema differs')
        fixed = dict(stdout_bytes=1048576,stderr_bytes=1048576,output_bytes=8388608,output_files=256,
            process_limit=64,descriptor_limit=64,file_size_limit=8388608,output_policy='precreated-exact-files',
            user_namespace_policy='isolated-nested-disabled' if spec['isolation_backend'] == 'bwrap' else 'not-applicable')
        _require(all(spec.get(key) == value and type(spec.get(key)) is type(value) for key,value in fixed.items()),
            'Probe sealed limits differ')
        original = {key:value for key,value in spec.items() if key not in fixed}
        runner = original['runner']
        _require(runner in (None,'verified-runner'), 'Probe runner identity differs')
        original.update(adapter_path=None,runner=None if runner is None else '/verified-runner')
        parsed = acquisition._probe_parse(q._bytes(original))
        _require(set(spec) == (set(f.name for f in dataclasses.fields(acquisition.ProbeSpec)) - {'adapter_path'}) | set(fixed),
            'Probe sealed spec schema differs')
        _probe_manifest_contract(manifest, parsed)
        expected_id = q._hash({key:value for key,value in manifest.items() if key != 'acquisition_id'})
    _require(expected_id == identity == manifest['acquisition_id'], 'Acquisition content identity differs')
    for item in evidence:
        name = 'evidence/'+item['name'] if kind == 'capture' else item['path']
        _require(set(item) == ({'name','sha256','byte_count'} if kind == 'capture' else {'path','sha256','byte_count'}),
            'Acquisition evidence schema differs')
        acquisition._probe_path(name)
        q._digest(item['sha256']); _integer(item['byte_count'])
        if kind == 'probe':
            _require(name in ('evidence/stdout','evidence/stderr') or name.startswith('outputs/') and name[8:] in spec['outputs'],
                'Probe evidence is not declared')
            _require(item['byte_count'] <= (1048576 if name.startswith('evidence/') else 8388608), 'Probe evidence exceeds limits')
            if name.startswith('outputs/'): outputs += item['byte_count']
        _require(name not in contents, 'Duplicate evidence path')
        raw = dive._read(run,prefix+'/'+name,item['sha256'],64*1024*1024)
        _require(len(raw) == item['byte_count'], 'Acquisition evidence size differs')
        contents[name] = raw
        paths.append(prefix+'/'+name); total += len(raw)
    _require(total <= (contract['max_capture_bytes'] if kind == 'capture' else 10*1024*1024) and outputs <= 8388608,
        'Acquisition evidence aggregate exceeds limits')
    if kind == 'probe':
        _require({'evidence/stdout','evidence/stderr'} <= set(contents), 'Probe streams missing')
        _require(not outputs or manifest['termination']['executed'], 'Nonexecuted probe has outputs')
    _require(row['evidence_paths'] == _cell(sorted(paths,key=q._bytes)) and
        row['details'] == _cell(dict(kind=kind,byte_count=total,file_count=len(evidence))), 'Acquisition SQL projection differs')
    dive._checked_install(run/prefix,contents,run)
    semantic_spec = {key:value for key,value in spec.items() if key not in ('image_id','dive_generation','question_id','packet_sha256')}
    semantic_manifest = {key:value for key,value in manifest.items() if key not in ('image_id','dive_generation','question_id','packet_sha256','acquisition_id')}
    if kind == 'probe': semantic_manifest['spec'] = semantic_spec
    provenance = dict(kind=dependency_kind,logical_id=identity,contract_sha256=row['contract_sha256'],
        spec_sha256=row['spec_sha256'],manifest_sha256=row['manifest_sha256'],evidence_paths=json.loads(row['evidence_paths']),
        details=json.loads(row['details']),semantic_sha256=q._hash(dict(spec=semantic_spec,manifest=semantic_manifest)))
    return provenance, {path[len(prefix)+1:] for path in paths}, manifest


def _derive(run, result, owner, packet, acquisitions, graph=None, *, retained=False):
    """Derive SQL rows solely from a strict result and verified frozen owners."""
    raw = canonical_bytes(result)
    digest = dive._digest(raw)
    empty = isinstance(result.answer,EmptyAnswer)
    answer = result.answer
    identity = None if empty else answer.question_id
    common = dict(image_id=result.image_id,dive_generation=result.dive_generation)
    relative = 'artifacts/firmware-dive/'+result.dive_generation+'/'+('empty' if empty else identity)+'/'+digest+'/result.json'
    receipt = common | dict(receipt_kind='empty' if empty else 'question',question_id=identity,
        attempt_ordinal=None if empty else answer.attempt_ordinal,packet_sha256=None if empty else answer.packet_sha256,
        result_path=relative,result_sha256=digest,outcome='empty' if empty else answer.outcome,
        dependency_count=0 if empty else len(answer.dependencies),evidence_count=0 if empty else len(answer.evidence),
        successor_count=0 if empty else len(answer.successor_questions))
    receipt['receipt_key'] = canonical_receipt_key(**common,result_sha256=digest,receipt_kind=receipt['receipt_kind'],
        question_id=identity,attempt_ordinal=receipt['attempt_ordinal'],packet_sha256=receipt['packet_sha256'])
    if empty:
        _require(owner['question_count'] == 0 and packet is None, 'Empty result requires exact zero-question generation')
        return ValidatedDiveResult(receipt,None,())
    question = dive._question(packet['question'])
    _require(owner['question_count'] > 0 and (identity,answer.attempt_ordinal,answer.packet_sha256) ==
        (question.question_id,question.attempt_ordinal,dive._digest(q._bytes(packet))), 'Result assignment differs')
    validate_answer(answer,question.resolution_contract)
    if graph is not None:
        for successor in answer.successor_questions: q._validate_question(successor,graph,q._catalog(graph))
    rung = None if answer.outcome == 'inconclusive' else {'static':'static-resolved','emulate':'emulated-observed','hardware':'hardware-observed'}[question.method]
    if rung and question.method != 'static': _require(answer.limitations, 'Dynamic conclusions require limitations')
    observation_id = canonical_observation_id(image_id=result.image_id,candidate_snapshot_sha256=owner['candidate_snapshot_sha256'],
        answer=answer,evidence_rung=rung)
    dependencies, dynamic = [], {}
    for dependency in answer.dependencies:
        if dependency.kind in ('probe-manifest','hardware-capture'):
            matching = [row for row in acquisitions if row['acquisition_id'] == dependency.logical_id and
                (row['image_id'],row['dive_generation'],row['question_id'],row['kind'],row['manifest_path'],row['manifest_sha256']) ==
                (result.image_id,result.dive_generation,identity,'probe' if dependency.kind == 'probe-manifest' else 'capture',dependency.relative_path,dependency.sha256)]
            _require(len(matching) == 1,'Dynamic dependency lacks exact question-owned acquisition')
            provenance, paths, manifest = _sealed_acquisition(run,matching[0],packet)
            raw_dependency = dive._read(run,dependency.relative_path,dependency.sha256,MAX_RESULT_BYTES)
            _require(len(raw_dependency) == dependency.byte_count,'Dynamic dependency byte count differs')
            dynamic[(dependency.kind,dependency.logical_id)] = (paths,manifest)
        else:
            provenance = _static_provenance(run,dependency,packet,owner,retained=retained)
            if graph is not None:
                _require(dive._dependency_current(run,_wire(dependency),packet,graph,acquisitions), 'Static dependency is stale')
        dependencies.append(common | dict(question_id=identity,observation_id=observation_id,**_wire(dependency),source_provenance=_cell(provenance)))
    dependencies.sort(key=lambda row:q._bytes({key:value for key,value in row.items() if key not in ('image_id','dive_generation','question_id','observation_id')}))
    dependencies = tuple(row | dict(ordinal=index) for index,row in enumerate(dependencies))
    for evidence in answer.evidence:
        key = (evidence.dependency_kind,evidence.dependency_logical_id)
        if key in dynamic:
            paths, manifest = dynamic[key]
            namespace = 'probe' if key[0] == 'probe-manifest' else 'capture'
            prefix = namespace+':'+key[1]+'#'
            _require(evidence.reference.startswith(prefix) and evidence.reference[len(prefix):] in paths,
                'Evidence is not in the exact acquisition manifest')
        else:
            _require(evidence.reference in packet['evidence_refs'], 'Static evidence is not packet-enumerated')
            namespace, logical = evidence.reference.split(':',1)
            logical = logical.split('#',1)[0]
            # Graph evidence may refer to its enumerated finding/surface facts;
            # a specific static artifact must own its own logical reference.
            _require(evidence.dependency_kind == 'chain-artifact' or
                evidence.dependency_kind == 'finding-artifact' and namespace == 'finding' and logical == evidence.dependency_logical_id or
                evidence.dependency_kind == 'surface-artifact' and namespace in ('surface','unknown') and logical == evidence.dependency_logical_id,
                'Static evidence is not backed by its dependency owner')
    if rung and question.method != 'static':
        required = 'probe-manifest' if question.method == 'emulate' else 'hardware-capture'
        selected = [(key,value) for key,value in dynamic.items() if key[0] == required and any(
            (e.dependency_kind,e.dependency_logical_id) == key for e in answer.evidence)]
        _require(selected,'Dynamic conclusion lacks method-appropriate acquisition evidence')
        if required == 'probe-manifest':
            _require(all(_clean_probe(value[1]) for _,value in selected), 'Probe conclusion requires a clean verified termination')
    observation = common | dict(question_id=identity,attempt_ordinal=answer.attempt_ordinal,observation_id=observation_id,
        outcome=answer.outcome,conclusion=answer.conclusion,limitations=_cell(answer.limitations),
        resolution_effect=None if answer.resolution_effect is None else _cell(answer.resolution_effect),evidence_rung=rung,
        dependency_refs=_cell(sorted(answer.dependencies,key=q._bytes)),evidence_refs=_cell(answer.evidence),
        successor_questions=_cell(answer.successor_questions),artifact_path=relative,artifact_sha256=digest)
    value = ValidatedDiveResult(receipt,observation,dependencies)
    for table, records in (('receipts',(receipt,)),('observations',(observation,)),('dependencies',dependencies)):
        for row in records: db.TABLE_SPECS['cba_firmware_dive_'+table].validate(row)
    return value


def _semantic(validated, candidate):
    observation = validated.observation
    return ('canonical',dict(image_id=observation['image_id'],candidate_snapshot_sha256=candidate,
        **{key:observation[key] for key in ('question_id','outcome','conclusion','limitations','resolution_effect','evidence_rung','dependency_refs','evidence_refs')}),
        [{key:row[key] for key in ('kind','logical_id','relative_path','sha256','byte_count','source_provenance')} for row in validated.dependencies])


def _historical_projection(run, raw, owner, packet, receipt, observation, dependencies, acquisitions, *, retained=False):
    """Strict canonical history or an explicit pre-import opaque fallback."""
    try:
        value = json.loads(raw,object_pairs_hook=_pairs,parse_constant=_constant)
    except (UnicodeError,json.JSONDecodeError):
        try:
            text = raw.decode(json.detect_encoding(raw))
        except UnicodeError:
            text = ''
        _require(not raw.lstrip().startswith((b'{',b'[')) and not text.lstrip().startswith(('{','[')),
            'Malformed historical JSON envelope')
        _require(not receipt['result_path'].startswith('artifacts/firmware-dive/'),
            'Canonical result cannot use opaque history compatibility')
        return None
    result = _parse(value)
    _require(canonical_bytes(result) == raw, 'Historical result is not canonical')
    _require((result.image_id,result.dive_generation) == (owner['image_id'],owner['dive_generation']),
        'Historical result ownership differs')
    expected = _derive(run,result,owner,packet,acquisitions,retained=retained)
    def unstamped(row): return {key:value for key,value in row.items() if key != 'recorded_at'}
    _require(unstamped(receipt) == expected.receipt and
        (None if observation is None else unstamped(observation)) == expected.observation and
        [unstamped(row) for row in dependencies] == list(expected.dependencies), 'Historical canonical result differs from stored rows')
    return ('canonical-empty',expected.receipt) if expected.observation is None else _semantic(expected,owner['candidate_snapshot_sha256'])


def _existing(con, validated, run, rows, graph):
    """One assignment is immutable; global IDs never authorize foreign reuse."""
    receipt = validated.receipt
    same = [row for row in rows['receipts'] if (row['dive_generation'],row['question_id']) ==
        (receipt['dive_generation'],receipt['question_id'])]
    global_receipts = surface._query(con,'SELECT * FROM cba_firmware_dive_receipts WHERE receipt_key=?',(receipt['receipt_key'],))
    def exact(row, expected): return {key:value for key,value in row.items() if key != 'recorded_at'} == expected
    _require(not global_receipts or len(global_receipts) == 1 and exact(global_receipts[0],receipt), 'Global receipt ID reuse differs')
    if same:
        _require(len(same) == 1 and exact(same[0],receipt), 'Assignment already has conflicting result')
        if validated.observation is None: return True
        matching = [row for row in rows['observations'] if (row['dive_generation'],row['question_id']) ==
            (receipt['dive_generation'],receipt['question_id'])]
        deps = sorted([row for row in rows['dependencies'] if (row['dive_generation'],row['question_id']) ==
            (receipt['dive_generation'],receipt['question_id'])],key=lambda row:row['ordinal'])
        _require(len(matching) == 1 and exact(matching[0],validated.observation) and len(deps) == len(validated.dependencies)
            and all(exact(row,expected) for row,expected in zip(deps,validated.dependencies)), 'Existing observation publication differs')
    if validated.observation is not None:
        for row in surface._query(con,'SELECT * FROM cba_firmware_dive_observations WHERE observation_id=?',(validated.observation['observation_id'],)):
            _require(row['image_id'] == receipt['image_id'], 'Global observation ID reused by foreign image')
            owner = next(r for r in rows['runs'] if r['dive_generation'] == row['dive_generation'])
            assignment = next(r for r in rows['questions'] if (r['dive_generation'],r['question_id']) == (row['dive_generation'],row['question_id']))
            packet = dive._json(dive._read(run,assignment['packet_path'],assignment['packet_sha256'],q.MAX_PACKET_BYTES))
            owned_receipt = next(r for r in rows['receipts'] if (r['dive_generation'],r['question_id']) == (row['dive_generation'],row['question_id']))
            deps = sorted([d for d in rows['dependencies'] if (d['dive_generation'],d['question_id']) == (row['dive_generation'],row['question_id'])],key=lambda d:d['ordinal'])
            historical = _historical_projection(run,dive._read(run,row['artifact_path'],row['artifact_sha256'],MAX_RESULT_BYTES),owner,packet,
                owned_receipt,row,deps,[a for a in rows['acquisitions'] if (a['dive_generation'],a['question_id']) == (row['dive_generation'],row['question_id'])])
            _require(historical == _semantic(validated,graph.candidate_snapshot_sha256), 'Observation identity reused with different semantics/provenance')
    return bool(same)


def _authority(con,run,result):
    rows = dive._rows(con,result.image_id)
    owners = [r for r in rows['runs'] if r['dive_generation'] == result.dive_generation]
    _require(len(owners) == 1, 'Result requires exact prepared generation')
    owner, = owners
    _require(owner['status'] == 'pending' and owner['completed_at'] is None and owner['journal_path'] is None and owner['journal_sha256'] is None,
        'Result requires pending prepared generation')
    graph, upstream = _retained_graph(con,run,owner)
    dive._history(run,rows,graph,upstream)
    index = dive._json(dive._read(run,owner['question_index_path'],owner['question_index_sha256'],dive.MAX_INDEX_BYTES))
    assigned = [row for row in rows['questions'] if row['dive_generation'] == result.dive_generation]
    for column, origin in (('chain_blocker_count','chain-blocker'),('surface_unknown_count','surface-unknown'),
            ('analyst_question_count','analyst'),('conflict_count','conflict')):
        _require(owner[column] == sum(row['origin'] == origin for row in assigned), 'Prepared origin count differs')
    _require(owner['retry_count'] == len(index['retry_projection']) and
        all(owner[name] == 0 for name in ('supported_count','refuted_count','inconclusive_count')),
        'Pending generation derived counts differ')
    packet = None
    if isinstance(result.answer,QuestionAnswer):
        assignments = [r for r in rows['questions'] if (r['dive_generation'],r['question_id']) ==
            (result.dive_generation,result.answer.question_id)]
        _require(len(assignments) == 1, 'Result requires one exact assigned packet')
        row, = assignments
        packet = dive._json(dive._read(run,row['packet_path'],row['packet_sha256'],q.MAX_PACKET_BYTES))
    validated = _derive(run,result,owner,packet,rows['acquisitions'],graph)
    duplicate = _existing(con,validated,run,rows,graph)
    # Include all verified history and source ownership in locked comparison,
    # even if an unrelated pending sibling has no semantic influence yet.
    return validated, (rows,graph), duplicate


@_guard
def validate(con,run_dir,result: DiveResult) -> ValidatedDiveResult:
    """Read-only retained assignment validation; preserve caller transactions."""
    owned = False
    try:
        result = _parse(json.loads(canonical_bytes(result)))
        if not con.in_transaction:
            con.execute('BEGIN')
            owned = True
        return _authority(con,dive._selector(run_dir),result)[0]
    except (sqlite3.Error,db.DbError,dive.FirmwareDiveError,firmware_chain.FirmwareChainError,
            firmware_fpcheck.FpcheckError,hunt.HuntError,surface.SurfaceError,acquisition.AcquisitionError) as exc:
        raise FirmwareDiveResultError('Cannot validate firmware dive result authority') from exc
    finally:
        if owned: con.rollback()


@_guard
def record(con,run_dir,result_path) -> RecordSummary:
    """Install immutable bytes first; revalidate all authority under write lock."""
    started = False
    try:
        _require(not con.in_transaction,'Result import requires no active caller transaction')
        run,path = dive._selector(run_dir),dive._selector(result_path)
        source = acquisition._source(path,MAX_RESULT_BYTES)
        result = _parse(json.loads(source[0].decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_constant))
        raw = canonical_bytes(result)
        con.execute('BEGIN'); started = True
        validated,state,duplicate = _authority(con,run,result)
        con.rollback(); started = False
        destination = run/pathlib.PurePosixPath(validated.receipt['result_path']).parent
        dive._install(destination,{'result.json':raw},run)
        con.execute('BEGIN IMMEDIATE'); started = True
        _require(acquisition._source(path,MAX_RESULT_BYTES) == source, 'Result source changed before publication')
        current = _authority(con,run,result)
        _require(current == (validated,state,duplicate), 'Result authority changed before publication')
        dive._checked_install(destination,{'result.json':raw},run)
        if not duplicate:
            db.put(con,'cba_firmware_dive_receipts',validated.receipt,commit=False)
            if validated.observation is not None:
                db.put(con,'cba_firmware_dive_observations',validated.observation,commit=False)
            for row in validated.dependencies: db.put(con,'cba_firmware_dive_dependencies',row,commit=False)
        con.commit(); started = False
        receipt = validated.receipt
        return RecordSummary(result.image_id,result.dive_generation,receipt['receipt_key'],
            None if validated.observation is None else validated.observation['observation_id'],str(destination/'result.json'),
            receipt['dependency_count'],receipt['evidence_count'],receipt['successor_count'])
    except (sqlite3.Error,db.DbError,dive.FirmwareDiveError,firmware_chain.FirmwareChainError,
            firmware_fpcheck.FpcheckError,hunt.HuntError,surface.SurfaceError,acquisition.AcquisitionError) as exc:
        raise FirmwareDiveResultError('Cannot publish firmware dive result') from exc
    finally:
        if started: con.rollback()
