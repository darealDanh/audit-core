"""Seal external, question-owned hardware bytes without interpreting or acquiring them.

Source paths are local input only. Neither paths nor timestamps establish a
capture identity. A capture is an immutable acquisition receipt, never an answer.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import pathlib
import sqlite3

from audit_core import db, firmware_chain, firmware_fpcheck, surface
from audit_core import firmware_dive as dive
from audit_core import firmware_dive_questions as q
from audit_core.firmware_dive_questions import AcquisitionContract

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_FILES = 256
MAX_SPEC_BYTES = 1024 * 1024


class AcquisitionError(Exception):
    """Exact question ownership, stable bytes or atomic publication failed."""


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureSpec:
    schema_version: int
    image_id: str
    dive_generation: str
    question_id: str
    packet_sha256: str
    contract_sha256: str
    device_identifier: str
    firmware_version: str
    firmware_sha256: str
    lifecycle: str
    posture: str
    authentication: str
    operator: str
    source: str
    method: str
    evidence: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class AcquisitionSummary:
    image_id: str
    dive_generation: str
    question_id: str
    acquisition_id: str
    kind: str
    spec_path: str
    manifest_path: str
    file_count: int
    byte_count: int


def _require(value, message):
    if not value:
        raise AcquisitionError(message)


def _source(path, maximum):
    path = dive._selector(path)
    with contextlib.ExitStack() as stack:
        parent = dive._directory(path.parent, stack)
        return dive._read_regular(parent, path.name, maximum)


def _parse(raw):
    value = json.loads(raw, object_pairs_hook=q._pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(AcquisitionError('Non-finite capture JSON')))
    q._object(value, CaptureSpec)
    _require(type(value['schema_version']) is int and value['schema_version'] == 1, 'Invalid capture schema')
    image = value['image_id']
    _require(isinstance(image, str) and bool(image.strip()) and '\x00' not in image and
        len(image.encode('utf-8')) <= 4096, 'Invalid capture image identity')
    for key in ('device_identifier','firmware_version','operator','source'):
        q._text(value[key], key)
    for key in ('dive_generation','question_id','packet_sha256','contract_sha256','firmware_sha256'):
        q._digest(value[key])
    for key, states in (('lifecycle',db.FIRMWARE_CHAIN_LIFECYCLE_STATES),
            ('posture',db.FIRMWARE_CHAIN_POSTURE_STATES), ('authentication',db.FIRMWARE_CHAIN_AUTH_STATES)):
        q._enum(value[key], states)
    q._enum(value['method'], ('hardware',))
    evidence = value['evidence']
    _require(isinstance(evidence, list) and 1 <= len(evidence) <= MAX_CAPTURE_FILES, 'Invalid capture file count')
    parsed = []
    for item in evidence:
        _require(isinstance(item, dict) and set(item) == {'name','source_path'}, 'Invalid evidence schema')
        name, source = item['name'], item['source_path']
        q._relative(name)
        q._relative(source)
        q._text(name, 'evidence name', 255)
        q._text(source, 'source path')
        _require('/' not in name, 'Evidence name must be a flat basename')
        parsed.append((name, source))
    _require(parsed == sorted(parsed) and len({name for name,_ in parsed}) == len(parsed),
        'Evidence names require sorted unique entries')
    return CaptureSpec(**(value | dict(evidence=tuple(parsed))))


def load_capture_spec(path) -> CaptureSpec:
    """Load a bounded strict spec; paths resolve relative to its no-follow parent."""
    try:
        return _parse(_source(path, MAX_SPEC_BYTES)[0])
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            dive.FirmwareDiveError, q.FirmwareDiveQuestionError) as exc:
        raise AcquisitionError('Cannot load capture specification') from exc


def _inputs(path):
    raw, identity = _source(path, MAX_SPEC_BYTES)
    spec = _parse(raw)
    contents, sources, total = {}, [], 0
    for name, relative in spec.evidence:
        evidence, signature = _source(pathlib.Path(path).parent / relative, MAX_CAPTURE_BYTES - total)
        total += len(evidence)
        contents['evidence/' + name] = evidence
        sources.append((relative, signature, evidence))
    return spec, raw, identity, tuple(sources), contents


def _ownership(con, run, root, spec):
    graph = firmware_chain.verified_retained_graph_snapshot(con, run, root,
        image_id=spec.image_id, dive_generation=spec.dive_generation)
    rows = dive._rows(con, spec.image_id)
    dive._history(run, rows, graph)
    owners = [row for row in rows['runs'] if row['dive_generation'] == spec.dive_generation]
    assignments = [row for row in rows['questions'] if
        (row['dive_generation'],row['question_id']) == (spec.dive_generation,spec.question_id)]
    _require(len(owners) == len(assignments) == 1, 'Capture requires exactly one prepared question')
    row, = assignments
    raw = dive._read(run, row['packet_path'], row['packet_sha256'], q.MAX_PACKET_BYTES)
    packet = dive._json(raw)
    contract = packet['acquisition_contract']
    _require(row['packet_sha256'] == spec.packet_sha256 and q._hash(contract) == spec.contract_sha256,
        'Capture packet or contract differs')
    question = dive._question(packet['question'])
    expected = json.loads(q.packet_bytes(question, graph))['acquisition_contract']
    _require(contract == expected and contract['image_id'] == spec.image_id and
        contract['question_id'] == spec.question_id and contract['method'] == spec.method == 'hardware' and
        contract['artifact_kinds'] == ['hardware-capture'] and
        contract['acquisition_class'] == 'external-hardware-capture' and
        contract['max_files'] == MAX_CAPTURE_FILES and contract['max_capture_bytes'] == MAX_CAPTURE_BYTES,
        'Capture exceeds exact question acquisition authority')
    dive._extracts(run, question.extract_records)
    return graph, rows, raw


def _build(run, inputs):
    spec, _, _, sources, contents = inputs
    sealed = dataclasses.asdict(spec) | dict(evidence=[name for name,_ in spec.evidence])
    evidence = [dict(name=name, sha256=dive._digest(contents['evidence/' + name]),
        byte_count=len(contents['evidence/' + name])) for name,_ in spec.evidence]
    identity = q._hash(dict(kind='capture', spec=sealed, evidence=evidence))
    manifest = sealed | dict(kind='capture', acquisition_id=identity, evidence=evidence)
    contents = contents | {'spec.json':q._bytes(sealed), 'manifest.json':q._bytes(manifest)}
    relative = 'artifacts/firmware-dive-captures/' + identity
    total = sum(len(raw) for _,_,raw in sources)
    summary = AcquisitionSummary(spec.image_id, spec.dive_generation, spec.question_id, identity, 'capture',
        str(run / relative / 'spec.json'), str(run / relative / 'manifest.json'), len(evidence), total)
    record = dict(image_id=spec.image_id, dive_generation=spec.dive_generation, question_id=spec.question_id,
        acquisition_id=identity, kind='capture', contract_sha256=spec.contract_sha256,
        spec_path=relative + '/spec.json', spec_sha256=dive._digest(contents['spec.json']),
        manifest_path=relative + '/manifest.json', manifest_sha256=dive._digest(contents['manifest.json']),
        evidence_paths=q._bytes(sorted([relative + '/evidence/' + row['name'] for row in evidence], key=q._bytes)).decode(),
        details=q._bytes(dict(kind='capture', byte_count=total, file_count=len(evidence))).decode())
    return summary, contents, record


def seal_capture(con, run_dir, root, spec_path) -> AcquisitionSummary:
    """Install stable bytes first, then repeat authority and byte checks under lock."""
    started = False
    try:
        _require(not con.in_transaction, 'Capture sealing requires no active transaction')
        run, path = dive._selector(run_dir), dive._selector(spec_path)
        inputs = _inputs(path)
        con.execute('BEGIN')
        started = True
        ownership = _ownership(con, run, root, inputs[0])
        con.rollback()
        started = False
        summary, contents, record = _build(run, inputs)
        destination = pathlib.Path(summary.manifest_path).parent
        dive._install(destination, contents, run)
        con.execute('BEGIN IMMEDIATE')
        started = True
        _require(_inputs(path) == inputs and _ownership(con, run, root, inputs[0]) == ownership,
            'Capture inputs changed before publication')
        dive._checked_install(destination, contents, run)
        prior = surface._query(con, 'SELECT * FROM cba_firmware_dive_acquisitions WHERE acquisition_id=?',
            (summary.acquisition_id,))
        if prior:
            _require(len(prior) == 1 and all(prior[0][key] == value for key,value in record.items()),
                'Existing capture ownership differs')
        else:
            db.put(con, 'cba_firmware_dive_acquisitions', record, commit=False)
        con.commit()
        started = False
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise AcquisitionError('database operation failed') from exc
        if isinstance(exc, (OSError, ValueError, TypeError, KeyError, RecursionError,
                dive.FirmwareDiveError, q.FirmwareDiveQuestionError,
                firmware_chain.FirmwareChainError, firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            raise AcquisitionError('Cannot seal hardware capture') from exc
        raise
