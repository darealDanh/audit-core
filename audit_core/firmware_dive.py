"""Freeze provenance-bound, immutable firmware investigation assignments.

Canonical results reconstruct exact receipt, observation and dependency rows.
Legacy opaque receipts retain exact byte/SQL checks; journal reconstruction is
owned by completion. Worker JSON never establishes new authority.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import secrets
import sqlite3
import stat

from audit_core import db, extract, firmware_chain, firmware_fpcheck, surface
from audit_core import firmware_dive_questions as q


class FirmwareDiveError(Exception):
    """Dive preparation cannot establish exact authority or provenance."""


@dataclasses.dataclass(frozen=True, slots=True)
class PreparationSummary:
    image_id: str
    dive_generation: str
    graph_sha256: str
    analyst_manifest_sha256: str
    journal_input_path: str
    question_index_path: str
    question_count: int
    chain_blocker_count: int
    surface_unknown_count: int
    analyst_question_count: int
    retry_count: int
    conflict_count: int


_TABLES = tuple('cba_firmware_dive_' + name for name in
    ('runs', 'questions', 'receipts', 'observations', 'dependencies', 'acquisitions'))
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_JOURNAL_BYTES = 8 * 1024 * 1024
_GRAPH_KEYS = ('image_id', 'manifest_sha256', 'surface_snapshot_sha256',
    'candidate_snapshot_sha256', 'chain_worklist_sha256', 'graph_path', 'graph_sha256')


def _require(condition, message):
    if not condition:
        raise FirmwareDiveError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw, *, newline=False):
    value = json.loads(raw, object_pairs_hook=q._pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(FirmwareDiveError('Non-finite retained JSON')))
    _require(q._bytes(value) + (b'\n' if newline else b'') == raw, 'Retained JSON is not canonical')
    return value


def _selector(path):
    """Normalize an explicit selector lexically without following symlinks."""
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def _directory(path, stack):
    """Open an absolute directory through no-follow component descriptors."""
    path = pathlib.Path(path).absolute()
    _require('..' not in path.parts, 'Directory path traverses parents')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    stack.callback(os.close, descriptor)
    for part in path.parts[1:]:
        descriptor = os.open(part, flags, dir_fd=descriptor)
        stack.callback(os.close, descriptor)
    return descriptor


def _file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns)


def _read_regular(parent, name, maximum):
    """Read one bounded file and refuse pathname/descriptor identity or byte drift."""
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
        'Artifact must be a bounded regular file')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=parent), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _require(_file_identity(before) == _file_identity(opened), 'Artifact identity changed before read')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    final = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _require(len(raw) <= maximum and len(raw) == before.st_size and
        _file_identity(before) == _file_identity(after) == _file_identity(final),
        'Artifact identity or bytes changed during read')
    return raw, _file_identity(final)


def _read(run, relative, digest=None, maximum=64 * 1024 * 1024):
    q._relative(relative)
    with contextlib.ExitStack() as stack:
        parent = _directory(run / pathlib.Path(relative).parent, stack)
        raw, _ = _read_regular(parent, pathlib.Path(relative).name, maximum)
    _require(digest is None or _digest(raw) == digest, 'Artifact hash differs')
    return raw


def _tree_directories(contents):
    directories = {''}
    for name in contents:
        q._relative(name)
        directories.update(str(parent) for parent in pathlib.PurePosixPath(name).parents if str(parent) != '.')
    _require(not set(contents).intersection(directories), 'Artifact file/directory collision')
    return sorted(directories, key=lambda name: (name.count('/') + bool(name), name))


def _tree_owners(parent, directories, stack, *, create=False):
    owners = {'': parent}
    for name in directories:
        if not name:
            continue
        relative = pathlib.PurePosixPath(name)
        owner = owners[str(relative.parent) if str(relative.parent) != '.' else '']
        if create:
            os.mkdir(relative.name, mode=0o700, dir_fd=owner)
        descriptor = os.open(relative.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=owner)
        stack.callback(os.close, descriptor)
        owners[name] = descriptor
    return owners


def _directory_names(parent, maximum):
    """Bound hostile directory enumeration without reading child objects."""
    names = set()
    with os.scandir(parent) as entries:
        for entry in entries:
            _require(len(names) < maximum, 'Artifact directory exceeds entry limit')
            names.add(entry.name)
    return names


def _checked_install(destination, contents, run):
    directories = _tree_directories(contents)
    with contextlib.ExitStack() as stack:
        parent = _directory(destination, stack)
        owners = _tree_owners(parent, directories, stack)
        for directory, owner in owners.items():
            expected = {pathlib.PurePosixPath(name).name for name in [*contents, *directories]
                if name and ('' if str(pathlib.PurePosixPath(name).parent) == '.' else str(pathlib.PurePosixPath(name).parent)) == directory}
            # Compare components, never resolve or follow directory links.
            _require(_directory_names(owner, len(expected)) == expected, 'Installed directory contains different artifacts')
        for name, raw in contents.items():
            relative = pathlib.PurePosixPath(name)
            owner = owners[str(relative.parent) if str(relative.parent) != '.' else '']
            actual, _ = _read_regular(owner, relative.name, max(len(raw), 1))
            _require(actual == raw, 'Installed artifact bytes differ')


def _install(destination, contents, run):
    # Hold every traversed directory open. A replaced pathname must never
    # redirect creation, writes, rename, fsync or cleanup outside this run.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directories = _tree_directories(contents)
    with contextlib.ExitStack() as stack:
        def directory(name, parent=None):
            descriptor = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, descriptor)
            return descriptor
        parent = _directory(run, stack)
        for part in destination.parent.relative_to(run).parts:
            try:
                os.mkdir(part, dir_fd=parent)
            except FileExistsError:
                pass
            else:
                os.fsync(parent)
            parent = directory(part, parent)
        if destination.name in os.listdir(parent):
            _checked_install(destination, contents, run)
            return
        temporary = '.dive-' + secrets.token_hex(16)
        os.mkdir(temporary, mode=0o700, dir_fd=parent)
        created, owners = [], {}
        try:
            staging = directory(temporary, parent)
            owners = _tree_owners(staging, directories, stack, create=True)
            for name, raw in contents.items():
                relative = pathlib.PurePosixPath(name)
                owner = owners[str(relative.parent) if str(relative.parent) != '.' else '']
                descriptor = os.open(relative.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=owner)
                created.append((owner, relative.name))
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            for owner in reversed(tuple(owners.values())):
                os.fsync(owner)
            try:
                os.rename(temporary, destination.name, src_dir_fd=parent, dst_dir_fd=parent)
            except OSError:
                if destination.name not in os.listdir(parent):
                    raise
                _checked_install(destination, contents, run)
            else:
                temporary = None
            os.fsync(parent)
        finally:
            if temporary is not None:
                for owner, name in created:
                    os.unlink(name, dir_fd=owner)
                for name in reversed(directories):
                    if name and name in owners:
                        relative = pathlib.PurePosixPath(name)
                        owner = owners[str(relative.parent) if str(relative.parent) != '.' else '']
                        os.rmdir(relative.name, dir_fd=owner)
                os.rmdir(temporary, dir_fd=parent)
                os.fsync(parent)


def _rows(con, image):
    result = {}
    for table in _TABLES:
        spec = db.TABLE_SPECS[table]
        values = surface._query(con, f'SELECT * FROM {table} WHERE image_id=? ORDER BY ' + ','.join(spec.primary_key), (image,))
        for row in values:
            spec.validate(row)
            stamp = 'prepared_at' if table.endswith('_runs') else 'recorded_at'
            _require(isinstance(row[stamp], str) and bool(row[stamp].strip()), 'History timestamp missing')
        result[table.removeprefix('cba_firmware_dive_')] = values
    return result


def _question(value):
    value = dict(value)
    value['subject_refs'] = q._subjects(value['subject_refs'])
    value['resolution_contract'] = q._contract(value['resolution_contract'])
    for key in ('axes', 'supersedes_observation_ids'):
        value[key] = tuple(value[key])
    value['extract_records'] = tuple(q.ExtractRecord(**row) for row in value['extract_records'])
    return q.DiveQuestion(**value)


def _question_row(question, image, generation, path, raw, ordinal):
    record = {name: getattr(question, name) for name in ('question_id', 'attempt_ordinal', 'origin',
        'method', 'question', 'settling_observation', 'prior_observation_id')}
    record.update({name:q._bytes(getattr(question, name)).decode() for name in
        ('subject_refs', 'resolution_contract', 'axes', 'supersedes_observation_ids')})
    return record | dict(image_id=image, dive_generation=generation, packet_path=path,
        packet_sha256=_digest(raw), ordinal=ordinal)


def _extracts(run, records):
    if not records:
        return
    manifest = _json_manifest(_read(run, 'extract/manifest.json', maximum=8 * 1024 * 1024))
    for record in records:
        upstream = extract.Record(**manifest[record.unit + '/' + record.name])
        _require(q.extract_record(upstream) == record, 'Extract manifest projection changed')
        _require(len(_read(run, record.relative_path, record.sha256, 512_100)) == record.byte_count,
            'Extract byte count differs')


def _json_manifest(raw):
    # Upstream extract manifests intentionally use indented JSON.
    value = json.loads(raw, object_pairs_hook=q._pairs)
    _require(isinstance(value, dict), 'Invalid extract manifest')
    return value


def _finding_refs(graph):
    return tuple(sorted((dict(logical_id=f.finding_id, relative_path=f.artifact_path,
        sha256=f.artifact_sha256) for f in graph.findings), key=lambda r:r['logical_id']))


def _provenance(raw):
    """Bound opaque provenance and exclude host/traversing path identities."""
    _require(len(raw.encode('utf-8')) <= MAX_JOURNAL_BYTES, 'Dependency provenance exceeds byte bound')
    pending, visited = [(_json(raw.encode('utf-8')), 0)], 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        _require(depth <= 16 and visited <= 10000, 'Dependency provenance exceeds structural bound')
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            tokens = re.split(r'[\s="\'(),;]+', value)
            _require(all(not token.startswith('/') and not re.match(r'^[A-Za-z]:', token) and
                '\\' not in token and '..' not in token.split('/') for token in tokens),
                'Dependency provenance contains a host or traversing path')


def _dependency_current(run, dep, packet, graph, acquisitions):
    raw = _read(run, dep['relative_path'], dep['sha256'])
    _require(len(raw) == dep['byte_count'], 'Dependency byte count differs')
    identity = {key:dep[key] for key in ('kind', 'logical_id', 'relative_path', 'sha256')}
    if dep['kind'] in ('finding-artifact', 'surface-artifact', 'chain-artifact', 'extract-record'):
        _require(identity in packet['allowed_dependencies'], 'Static dependency is not packet-authorized')
    if dep['kind'] in ('finding-artifact', 'surface-artifact'):
        records = graph.findings if dep['kind'] == 'finding-artifact' else (*graph.surfaces, *graph.unknowns)
        return any((getattr(row, 'finding_id', getattr(row, 'id', getattr(row, 'surface_id', None))),
            row.artifact_path, row.artifact_sha256) == (dep['logical_id'], dep['relative_path'], dep['sha256']) for row in records)
    if dep['kind'] == 'chain-artifact':
        return identity in packet['allowed_dependencies']
    if dep['kind'] == 'extract-record':
        selected = tuple(q.ExtractRecord(**r) for r in packet['extract_records'] if
            (r['unit'] + '/' + r['name'], r['relative_path'], r['sha256']) ==
            (dep['logical_id'], dep['relative_path'], dep['sha256']))
        _require(len(selected) == 1, 'Extract dependency is not packet-authorized')
        _extracts(run, selected)
        return True
    matching = [a for a in acquisitions if a['acquisition_id'] == dep['logical_id'] and
        a['kind'] == ('probe' if dep['kind'] == 'probe-manifest' else 'capture') and
        (a['manifest_path'], a['manifest_sha256']) == (dep['relative_path'], dep['sha256'])]
    _require(len(matching) == 1 and dep['kind'] in packet['acquisition_contract']['artifact_kinds'],
        'Dynamic dependency lacks exact question-owned acquisition')
    return True


def _history(run, rows, graph):
    """Validate every retained row/artifact; scope only derivation, never integrity."""
    runs = {r['dive_generation']:r for r in rows['runs']}
    assignments, observations, receipts, dependencies, acquisitions = {}, {}, {}, {}, {}
    for name, output, key in (('observations', observations, 'question_id'),
            ('receipts', receipts, 'question_id'), ('dependencies', dependencies, 'question_id'),
            ('acquisitions', acquisitions, 'question_id')):
        for row in rows[name]:
            _require(row['dive_generation'] in runs, 'Orphan dive history row')
            output.setdefault((row['dive_generation'], row[key]), []).append(row)
    _require(all(row['dive_generation'] in runs for row in rows['questions']), 'Orphan question assignment')
    inputs, packets, authoritative = {}, {}, []
    for generation, owner in runs.items():
        prefix = 'files/firmware-dive/' + generation
        _require(owner['question_index_path'] == prefix + '/index.json' and
            owner['journal_input_path'] == prefix + '/journal-input.json', 'Historical generation paths differ')
        index = _json(_read(run, owner['question_index_path'], owner['question_index_sha256'], MAX_INDEX_BYTES))
        journal = _json(_read(run, owner['journal_input_path'], owner['journal_input_sha256'], 8 * 1024 * 1024))
        _require((index['image_id'], index['dive_generation'], index['graph_sha256'], index['analyst_manifest_sha256'],
            index['journal_input_sha256']) == (graph.image_id, generation, owner['chain_graph_sha256'],
            owner['analyst_manifest_sha256'], owner['journal_input_sha256']), 'Historical index ownership differs')
        _require(q._hash(index['analyst_manifest']) == owner['analyst_manifest_sha256'] and
            owner['analyst_manifest_path'] == owner['question_index_path'], 'Historical analyst manifest differs')
        expected_keys = {'schema_version','image_id','dive_generation','graph_sha256','analyst_manifest',
            'analyst_manifest_sha256','journal_input_sha256','questions','graph_projection','input_overlay','retry_projection'}
        _require(set(index) == expected_keys and type(index['schema_version']) is int and index['schema_version'] == 1, 'Historical index schema differs')
        graph_projection = index['graph_projection']
        _require(set(graph_projection) == set(_GRAPH_KEYS) and all(graph_projection[k] == owner[v] for k,v in
            (('image_id','image_id'),('manifest_sha256','manifest_sha256'),
             ('surface_snapshot_sha256','surface_snapshot_sha256'),('candidate_snapshot_sha256','candidate_snapshot_sha256'),
             ('graph_path','chain_graph_path'),('graph_sha256','chain_graph_sha256'))), 'Historical graph projection differs')
        graph_body = _json(_read(run, owner['chain_graph_path'], owner['chain_graph_sha256']), newline=True)
        _require(graph_body['worklist_sha256'] == graph_projection['chain_worklist_sha256'], 'Historical graph provenance differs')
        _require(set(journal) == {'schema_version','image_id','candidate_snapshot_sha256','finding_artifacts','observations'} and
            type(journal['schema_version']) is int and journal['schema_version'] == 1 and journal['image_id'] == owner['image_id'] and
            journal['candidate_snapshot_sha256'] == owner['candidate_snapshot_sha256'], 'Historical journal input ownership differs')
        authoritative.extend(index['input_overlay'])
        for ref in journal['finding_artifacts']:
            _require(set(ref) == {'logical_id','relative_path','sha256'}, 'Invalid finding provenance')
            _read(run, ref['relative_path'], ref['sha256'])
        inputs[generation] = journal
        selected = [r for r in rows['questions'] if r['dive_generation'] == generation]
        selected.sort(key=lambda r:r['ordinal'])
        _require(len(selected) == owner['question_count'] and [r['ordinal'] for r in selected] == list(range(len(selected))),
            'Historical question denominator differs')
        manifest, frozen_questions = [], []
        for row in selected:
            raw = _read(run, row['packet_path'], row['packet_sha256'], q.MAX_PACKET_BYTES)
            packet = _json(raw)
            _require(set(packet) == {f.name for f in dataclasses.fields(q.QuestionPacket)} and
                type(packet['schema_version']) is int and packet['schema_version'] == 1, 'Historical packet schema differs')
            question = _question(packet['question'])
            identity_graph = dataclasses.replace(graph, candidate_snapshot_sha256=owner['candidate_snapshot_sha256'])
            _require(q.canonical_question_id(identity_graph, question) == question.question_id, 'Historical question identity differs')
            q._analyst({f.name:getattr(question,f.name) for f in dataclasses.fields(q.AnalystQuestion)})
            _require(row['packet_path'] == prefix + '/questions/' + question.question_id + '.json', 'Historical packet path differs')
            _require(packet['extract_records'] == q._wire(question.extract_records) and packet['allowed_dependencies'] == packet['retained_refs'] +
                [dict(kind='extract-record', logical_id=r.unit + '/' + r.name, relative_path=r.relative_path, sha256=r.sha256)
                 for r in question.extract_records], 'Historical packet dependency authority differs')
            for ref in packet['retained_refs']:
                _require(set(ref) == {f.name for f in dataclasses.fields(q.RetainedRef)}, 'Invalid retained reference')
                _read(run, ref['relative_path'], ref['sha256'])
            if owner['candidate_snapshot_sha256'] == graph.candidate_snapshot_sha256 and set(question.subject_refs) <= set(q._catalog(graph)):
                expected_packet = json.loads(q.packet_bytes(question, dataclasses.replace(graph,
                    graph_path=owner['chain_graph_path'], graph_sha256=owner['chain_graph_sha256'])))
                _require([(r['kind'],r['logical_id']) for r in packet['retained_refs']] ==
                    [(r['kind'],r['logical_id']) for r in expected_packet['retained_refs']] and
                    [r for r in packet['retained_refs'] if r['kind'] == 'chain-artifact'] ==
                    [r for r in expected_packet['retained_refs'] if r['kind'] == 'chain-artifact'] and
                    all({k:r[k] for k in ('logical_id','relative_path','sha256')} in journal['finding_artifacts']
                        for r in packet['retained_refs'] if r['kind'] == 'finding-artifact') and
                    packet['acquisition_contract'] == expected_packet['acquisition_contract'] and
                    packet['evidence_refs'] == expected_packet['evidence_refs'], 'Historical packet exceeds exact subject authority')
            frozen_questions.append(question)
            expected = _question_row(question, graph.image_id, generation, row['packet_path'], raw, row['ordinal'])
            _require(all(row[k] == v for k,v in expected.items()) and packet['image_id'] == graph.image_id and
                packet['candidate_snapshot_sha256'] == owner['candidate_snapshot_sha256'], 'Historical packet assignment differs')
            key = (generation, question.question_id)
            assignments[key] = (question, owner)
            packets[key] = packet
            manifest.append(dict(question_id=question.question_id, attempt_ordinal=question.attempt_ordinal,
                packet_path=row['packet_path'], packet_sha256=row['packet_sha256']))
        _require(index['questions'] == manifest, 'Historical packet manifest differs')
        projection = dict(schema_version=1, graph=graph_projection, analyst_manifest=index['analyst_manifest'],
            input_overlay=index['input_overlay'], retry_projection=index['retry_projection'], questions=frozen_questions)
        _require(q._hash(projection) == generation, 'Historical generation identity differs')
        if owner['status'] == 'complete':
            _read(run, owner['journal_path'], owner['journal_sha256'], 8 * 1024 * 1024)
    for key in (*observations, *dependencies, *acquisitions):
        _require(key in assignments, 'History row lacks question assignment')
    for key, values in receipts.items():
        _require(len(values) == 1 and (key in assignments or
            key[1] is None and runs[key[0]]['question_count'] == 0), 'Receipt denominator differs')
        receipt = values[0]
        _read(run, receipt['result_path'], receipt['result_sha256'], 8 * 1024 * 1024)
        if key[1] is not None:
            _require(key in observations, 'Question receipt lacks observation')
        else:
            from audit_core import firmware_dive_results as results
            results._historical_projection(run,
                _read(run, receipt['result_path'], receipt['result_sha256'], 8 * 1024 * 1024),
                runs[key[0]], None, receipt, None, [], ())
    for generation, owner in runs.items():
        if owner['status'] == 'complete':
            expected = {(generation, row['question_id']) for row in rows['questions'] if row['dive_generation'] == generation}
            actual = {key for key in receipts if key[0] == generation}
            _require(actual == (expected if expected else {(generation, None)}), 'Completed receipt denominator differs')
            values = [row for row in rows['observations'] if row['dive_generation'] == generation]
            _require(tuple(owner[name + '_count'] for name in ('supported', 'refuted', 'inconclusive')) ==
                tuple(sum(row['outcome'] == name for row in values) for name in ('supported', 'refuted', 'inconclusive')),
                'Completed outcome counts differ')
    catalog = q._catalog(graph)
    history, journal_index, overlays, attempts, repeated, accepted = [], {}, [], {}, {}, {}
    for key, (question, owner) in assignments.items():
        packet = packets[key]
        for acquisition in acquisitions.get(key, ()):
            kind = 'probe-manifest' if acquisition['kind'] == 'probe' else 'hardware-capture'
            _require(kind in packet['acquisition_contract']['artifact_kinds'], 'Acquisition exceeds method authority')
            _require(acquisition['contract_sha256'] == q._hash(packet['acquisition_contract']), 'Acquisition contract differs')
            _read(run, acquisition['spec_path'], acquisition['spec_sha256'], 8 * 1024 * 1024)
            _read(run, acquisition['manifest_path'], acquisition['manifest_sha256'], 8 * 1024 * 1024)
        observed = observations.get(key, ())
        _require(len(observed) <= 1, 'Duplicate observation assignment')
        current_subjects = owner['candidate_snapshot_sha256'] == graph.candidate_snapshot_sha256 and set(question.subject_refs) <= set(catalog)
        if not observed:
            _require(not dependencies.get(key), 'Unobserved question has dependencies')
            item = q.QuestionHistory(question, question.attempt_ordinal, None, None, None, (), (), False)
        else:
            observation = observed[0]
            receipt, = receipts.get(key, ())
            deps = dependencies.get(key, [])
            deps.sort(key=lambda d:d['ordinal'])
            _require(len(json.loads(observation['dependency_refs'])) == len(deps), 'Dependency reference denominator differs')
            _require([d['ordinal'] for d in deps] == list(range(len(deps))) and
                len({(d['kind'], d['logical_id']) for d in deps}) == len(deps), 'Dependency ordinals or identities differ')
            _require(all(d['observation_id'] == observation['observation_id'] for d in deps), 'Dependency observation differs')
            _require((receipt['attempt_ordinal'], receipt['packet_sha256'], receipt['result_path'], receipt['result_sha256'],
                receipt['outcome'], receipt['dependency_count'], receipt['evidence_count'], receipt['successor_count']) ==
                (question.attempt_ordinal, _digest(q._bytes(packet)), observation['artifact_path'], observation['artifact_sha256'],
                observation['outcome'], len(deps), len(json.loads(observation['evidence_refs'])), len(json.loads(observation['successor_questions']))) and
                observation['attempt_ordinal'] == question.attempt_ordinal, 'Observation/receipt cross-fields differ')
            if observation['outcome'] != 'inconclusive':
                rung = {'static':'static-resolved', 'emulate':'emulated-observed', 'hardware':'hardware-observed'}[question.method]
                _require(observation['evidence_rung'] == rung, 'Observation rung differs from question method')
                if question.method != 'static':
                    kind = 'probe-manifest' if question.method == 'emulate' else 'hardware-capture'
                    _require(any(d['kind'] == kind for d in deps), 'Dynamic conclusion lacks method-owned evidence')
            raw = _read(run, observation['artifact_path'], observation['artifact_sha256'], 8 * 1024 * 1024)
            for dependency in deps:
                _provenance(dependency['source_provenance'])
            dep_projection = [{k:v for k,v in d.items() if k not in ('image_id','dive_generation','question_id','ordinal','observation_id','recorded_at')} for d in deps]
            _require(dep_projection == sorted(dep_projection, key=q._bytes), 'Dependency projection order differs')
            from audit_core import firmware_dive_results as results
            canonical = results._historical_projection(run, raw, owner, packet, receipt, observation, deps, acquisitions.get(key, ()))
            full = canonical if canonical is not None else ('opaque',
                {k:v for k,v in observation.items() if k not in ('image_id','dive_generation','attempt_ordinal','recorded_at','artifact_path')}, dep_projection, raw)
            identity = observation['observation_id']
            _require(identity not in repeated or repeated[identity] == full, 'Observation identity reused with different stored content')
            repeated[identity] = full
            # Rehash all dependencies, even when their subjects/candidate are stale.
            checks = [_dependency_current(run, d, packet, graph, acquisitions.get(key, ())) for d in deps]
            finding_provenance = inputs[key[0]]['finding_artifacts'] == list(_finding_refs(graph))
            current = current_subjects and owner['status'] == 'complete' and all(checks) and finding_provenance
            value = json.loads(observation['resolution_effect'])['value'] if observation['resolution_effect'] else None
            dependency_refs = tuple(json.loads(observation['dependency_refs']))
            evidence_refs = tuple(json.loads(observation['evidence_refs']))
            if canonical is not None:
                dependency_refs = tuple(sorted(q._hash(ref) for ref in dependency_refs))
                evidence_refs = tuple(sorted(q._hash(ref) for ref in evidence_refs))
            item = q.QuestionHistory(question, question.attempt_ordinal, identity, observation['outcome'], value,
                dependency_refs, evidence_refs, current, question.supersedes_observation_ids)
            entry = q.JournalIndexEntry(identity, question.question_id, question.subject_refs,
                'current' if current else 'stale', observation['outcome'], observation['artifact_path'], observation['artifact_sha256'])
            journal_index[identity] = entry
            if owner['status'] == 'complete' and observation['outcome'] in ('supported', 'refuted'):
                projection = dict(observation_id=identity, question_id=question.question_id,
                    resolution_effect=json.loads(observation['resolution_effect']), dependency_refs=item.dependency_refs,
                    evidence_refs=item.evidence_refs, dependencies=tuple(q._hash(d) for d in dep_projection))
                accepted[identity] = projection
                if current:
                    overlays.append(projection)
        if current_subjects:
            attempt = (question.question_id, question.attempt_ordinal)
            prior = attempts.get(attempt)
            _require(prior is None or prior.question == item.question and
                (prior.observation_id is None or item.observation_id is None or prior == item),
                'Duplicate attempt has different durable history')
            if prior is None or item.observation_id is not None:
                attempts[attempt] = item
    _require(all(row.get('observation_id') in accepted and q._bytes(row) ==
        q._bytes(accepted[row['observation_id']]) for row in authoritative), 'Historical accepted input differs from durable evidence')
    history = tuple(attempts[k] for k in sorted(attempts))
    # The pure derivation validates contracts, attempts and complete supersession.
    q._history(graph, catalog, history)
    overlay = tuple({q._bytes(i):i for i in overlays}[key] for key in sorted({q._bytes(i) for i in overlays}))
    return history, tuple(journal_index[k] for k in sorted(journal_index)[:q.MAX_JOURNAL_ENTRIES]), overlay


def _capture(con, run, root, image_id, analyst, retries):
    upstream = firmware_fpcheck.verified_findings_snapshot(con, run, root, image_id=image_id)
    rows = _rows(con, upstream.image_id)
    chain_runs = surface._query(con, 'SELECT * FROM cba_firmware_chain_runs WHERE image_id=?', (upstream.image_id,))
    conflict_only = not chain_runs
    if not conflict_only:
        graph = firmware_chain.verified_graph_snapshot(con, run, root, image_id=upstream.image_id)
        history, index, overlay = _history(run, rows, graph)
        questions = q.derive_questions(graph, analyst, history, retries)
    else:
        _require(not analyst, 'Conflict-only preparation refuses analyst questions')
        candidates = []
        for owner in rows['runs']:
            if owner['status'] != 'complete' or owner['candidate_snapshot_sha256'] != upstream.candidate_snapshot_sha256:
                continue
            graph = firmware_chain.verified_retained_graph_snapshot(con, run, root,
                image_id=upstream.image_id, dive_generation=owner['dive_generation'])
            history, index, overlay = _history(run, rows, graph)
            derived = q.derive_questions(graph, (), history)
            conflicts = tuple(question for question in derived.questions if question.origin == 'conflict')
            contested = {ref for question in conflicts for ref in question.supersedes_observation_ids}
            owned = {o['observation_id'] for o in rows['observations'] if o['dive_generation'] == owner['dive_generation']}
            if conflicts and owned & contested:
                candidates.append((owner, graph, history, index, overlay, conflicts))
        _require(bool(candidates), 'No exact current retained conflict family')
        latest = max(c[0]['completed_at'] for c in candidates)
        tied = [c for c in candidates if c[0]['completed_at'] == latest]
        _require(len({(c[1].graph_path,c[1].graph_sha256) for c in tied}) == 1, 'Ambiguous most recent retained graph')
        _, graph, history, index, overlay, conflicts = max(tied, key=lambda c:c[0]['dive_generation'])
        _require(all(d.question_id in {c.question_id for c in conflicts} for d in retries),
            'Conflict-only preparation refuses ordinary retries')
        derived = q.derive_questions(graph, (), history, retries)
        questions = q.QuestionSet(tuple(question for question in derived.questions if question.origin == 'conflict'),
            derived.retry_projection)
    # Optional extracts are granted only by exact historical questions.
    previous = {h.question.question_id:h.question for h in history}
    retained = []
    for question in questions.questions:
        source = previous.get(question.question_id)
        records = source.extract_records if source else ()
        if question.origin == 'conflict' and not records:
            parents = [h.question.extract_records for h in history if h.observation_id in question.supersedes_observation_ids]
            _require(not parents or all(r == parents[0] for r in parents), 'Conflict extracts disagree')
            records = parents[0] if parents else ()
        _extracts(run, records)
        retained.append(dataclasses.replace(question, extract_records=records))
    questions = q.QuestionSet(tuple(retained), questions.retry_projection)
    contested = {r for question in questions.questions if question.origin == 'conflict' for r in question.supersedes_observation_ids}
    index = tuple(dataclasses.replace(i, status='contested') if i.observation_id in contested else i for i in index)
    return graph, rows, history, index, overlay, questions


def _build(run, captured, analyst):
    graph, rows, history, journal, overlay, questions = captured
    manifest = dict(schema_version=1, questions=analyst)
    analyst_hash = q._hash(manifest)
    projection = dict(schema_version=1, graph={key:getattr(graph,key) for key in _GRAPH_KEYS},
        analyst_manifest=manifest, input_overlay=overlay, retry_projection=questions.retry_projection,
        questions=questions.questions)
    generation = q._hash(projection)
    relative = 'files/firmware-dive/' + generation
    prior = [r for r in rows['runs'] if r['dive_generation'] == generation]
    if prior:
        frozen = _json(_read(run, prior[0]['journal_input_path'], prior[0]['journal_input_sha256'], 8 * 1024 * 1024))
        journal = tuple(q.JournalIndexEntry(**(row | {'subject_refs':q._subjects(row['subject_refs'])})) for row in frozen['observations'])
    contents, packets = {}, []
    for ordinal, question in enumerate(questions.questions):
        raw = q.packet_bytes(question, graph, journal)
        name = 'questions/' + question.question_id + '.json'
        contents[name] = raw
        packets.append(_question_row(question, graph.image_id, generation, relative + '/' + name, raw, ordinal))
    journal_raw = q._bytes(dict(schema_version=1, image_id=graph.image_id,
        candidate_snapshot_sha256=graph.candidate_snapshot_sha256, finding_artifacts=_finding_refs(graph), observations=journal))
    contents['journal-input.json'] = journal_raw
    contents['index.json'] = q._bytes(dict(schema_version=1, image_id=graph.image_id,
        dive_generation=generation, graph_sha256=graph.graph_sha256, analyst_manifest=manifest,
        analyst_manifest_sha256=analyst_hash, journal_input_sha256=_digest(journal_raw),
        graph_projection=projection['graph'], input_overlay=overlay, retry_projection=questions.retry_projection,
        questions=[{key:p[key] for key in ('question_id','attempt_ordinal','packet_path','packet_sha256')} for p in packets]))
    _require(len(contents['index.json']) <= MAX_INDEX_BYTES and len(journal_raw) <= MAX_JOURNAL_BYTES,
        'Generation index or journal exceeds artifact byte bound')
    counts = {origin:sum(question.origin == origin for question in questions.questions) for origin in db.FIRMWARE_DIVE_ORIGINS}
    summary = PreparationSummary(graph.image_id, generation, graph.graph_sha256, analyst_hash,
        str(run / relative / 'journal-input.json'), str(run / relative / 'index.json'), len(packets),
        counts['chain-blocker'], counts['surface-unknown'], counts['analyst'], len(questions.retry_projection), counts['conflict'])
    record = dict(image_id=graph.image_id, dive_generation=generation, manifest_sha256=graph.manifest_sha256,
        surface_snapshot_sha256=graph.surface_snapshot_sha256, candidate_snapshot_sha256=graph.candidate_snapshot_sha256,
        chain_graph_path=graph.graph_path, chain_graph_sha256=graph.graph_sha256,
        analyst_manifest_path=relative + '/index.json', analyst_manifest_sha256=analyst_hash,
        journal_input_path=relative + '/journal-input.json', journal_input_sha256=_digest(journal_raw),
        question_index_path=relative + '/index.json', question_index_sha256=_digest(contents['index.json']),
        **{name:getattr(summary,name) for name in ('question_count','chain_blocker_count','surface_unknown_count',
            'analyst_question_count','retry_count','conflict_count')}, status='pending',
        supported_count=0, refuted_count=0, inconclusive_count=0)
    return summary, contents, record, packets


def prepare(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
            *, image_id: str | None = None, questions_path=None, retry=()) -> PreparationSummary:
    """Install one exact immutable denominator, then revalidate and append under lock."""
    started = False
    try:
        _require(not con.in_transaction, 'Preparation requires no active transaction')
        run = _selector(run_dir)
        analyst = q.load_analyst_manifest(questions_path)
        retries = q.parse_retry_directives(retry)
        con.execute('BEGIN')
        started = True
        captured = _capture(con, run, root, image_id, analyst, retries)
        con.rollback()
        started = False
        summary, contents, record, packets = _build(run, captured, analyst)
        destination = pathlib.Path(summary.question_index_path).parent
        _install(destination, contents, run)
        con.execute('BEGIN IMMEDIATE')
        started = True
        _require(q.load_analyst_manifest(questions_path) == analyst and
            _capture(con, run, root, image_id, analyst, retries) == captured,
            'Firmware dive inputs changed before publication')
        _checked_install(destination, contents, run)
        prior = [r for r in captured[1]['runs'] if r['dive_generation'] == summary.dive_generation]
        if prior:
            _require(all(prior[0][key] == value for key,value in record.items() if key not in
                ('status','supported_count','refuted_count','inconclusive_count')), 'Existing generation ownership differs')
        else:
            db.put(con, 'cba_firmware_dive_runs', record, commit=False)
            for packet in packets:
                db.put(con, 'cba_firmware_dive_questions', packet, commit=False)
        con.commit()
        started = False
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise FirmwareDiveError('database operation failed') from exc
        if isinstance(exc, (OSError, ValueError, KeyError, TypeError,
                firmware_chain.FirmwareChainError, firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            raise FirmwareDiveError('Cannot prepare firmware dive') from exc
        raise
