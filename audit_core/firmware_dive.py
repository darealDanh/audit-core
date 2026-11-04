"""Prepare and complete provenance-bound, immutable firmware investigations.

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
    """Dive authority, provenance or publication cannot be established."""


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



def _opaque_lineage(parents, opaque):
    """Opaque history and every resolver depending on it lack current authority."""
    children = {}
    for identity, refs in parents.items():
        for ref in refs: children.setdefault(ref, set()).add(identity)
    excluded, pending = set(opaque), list(opaque)
    while pending:
        for child in children.get(pending.pop(), ()):
            if child not in excluded:
                excluded.add(child)
                pending.append(child)
    return excluded


def _coalesce_attempt(prior, item):
    """An exact duplicate assignment may differ only in recomputed freshness."""
    _require(prior.question == item.question, 'Duplicate attempt changes its assignment')
    if prior.observation_id is None: return item
    if item.observation_id is None: return prior
    _require(dataclasses.replace(prior,dependency_current=False) == dataclasses.replace(item,dependency_current=False),
        'Duplicate attempt has different durable history')
    return dataclasses.replace(prior,dependency_current=prior.dependency_current or item.dependency_current)


def _history(run, rows, graph, upstream=None):
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
        manifest, frozen_questions, historical = [], [], None
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
                if historical is None:
                    historical = (_historical_graph(run, owner, index, upstream) if upstream is not None else
                        dataclasses.replace(graph, graph_path=owner['chain_graph_path'], graph_sha256=owner['chain_graph_sha256']))
                expected_packet = json.loads(q.packet_bytes(question, historical))
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
    parents, opaque = {}, set()
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
            parents[identity] = question.supersedes_observation_ids
            if canonical is None: opaque.add(identity)
            # Rehash all dependencies, even when their subjects/candidate are stale.
            checks = [_dependency_current(run, d, packet, graph, acquisitions.get(key, ())) for d in deps]
            finding_provenance = inputs[key[0]]['finding_artifacts'] == list(_finding_refs(graph))
            current = canonical is not None and current_subjects and owner['status'] == 'complete' and all(checks) and finding_provenance
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
            attempts[attempt] = item if prior is None else _coalesce_attempt(prior,item)
    _require(all(row.get('observation_id') in accepted and q._bytes(row) ==
        q._bytes(accepted[row['observation_id']]) for row in authoritative), 'Historical accepted input differs from durable evidence')
    excluded = _opaque_lineage(parents, opaque)
    history = tuple(dataclasses.replace(attempts[k], dependency_current=False) if attempts[k].observation_id in excluded
        else attempts[k] for k in sorted(attempts))
    journal_index = {identity:dataclasses.replace(entry, status='stale') if identity in excluded else entry
        for identity,entry in journal_index.items()}
    overlays = [item for item in overlays if item['observation_id'] not in excluded]
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
        history, index, overlay = _history(run, rows, graph, upstream)
        questions = q.derive_questions(graph, analyst, history, retries)
    else:
        _require(not analyst, 'Conflict-only preparation refuses analyst questions')
        candidates = []
        for owner in rows['runs']:
            if owner['status'] != 'complete' or owner['candidate_snapshot_sha256'] != upstream.candidate_snapshot_sha256:
                continue
            graph = firmware_chain.verified_retained_graph_snapshot(con, run, root,
                image_id=upstream.image_id, dive_generation=owner['dive_generation'])
            history, index, overlay = _history(run, rows, graph, upstream)
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


@dataclasses.dataclass(frozen=True, slots=True)
class DiveQuestionSummary:
    question_id: str
    attempt_ordinal: int
    observation_id: str
    outcome: str
    evidence_rung: str | None
    status: str


@dataclasses.dataclass(frozen=True, slots=True)
class FirmwareDiveSummary:
    image_id: str
    dive_generation: str
    question_count: int
    supported_count: int
    refuted_count: int
    inconclusive_count: int
    current_count: int
    stale_count: int
    contested_count: int
    questions: tuple[DiveQuestionSummary, ...]
    journal_path: str
    journal_sha256: str
    overlay_sha256: str
    complete: bool


@dataclasses.dataclass(frozen=True, slots=True)
class CurrentDiveObservation:
    observation_id: str
    question_id: str
    subject_refs: tuple[str, ...]
    settled_subject_refs: tuple[str, ...]
    outcome: str
    resolution_effect: object
    evidence_rung: str
    dependency_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class CurrentDiveOverlay:
    schema_version: int = 1
    observations: tuple[CurrentDiveObservation, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedDiveDecisionInput:
    image_id: str
    dive_generation: str
    journal_path: str
    journal_sha256: str
    overlay_sha256: str
    overlay: CurrentDiveOverlay


_PROVENANCE = ('manifest_sha256','surface_snapshot_sha256','candidate_snapshot_sha256',
    'chain_graph_path','chain_graph_sha256','analyst_manifest_path','analyst_manifest_sha256',
    'journal_input_path','journal_input_sha256','question_index_path','question_index_sha256')
_COUNTS = ('question_count','chain_blocker_count','surface_unknown_count','analyst_question_count',
    'retry_count','conflict_count','supported_count','refuted_count','inconclusive_count')


def _timestamp(value):
    import datetime
    _require(isinstance(value,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',value),
        'Invalid dive timestamp')
    datetime.datetime.strptime(value,'%Y-%m-%d %H:%M:%S')
    return value


def _journal(owner, owned, completed_at, counts):
    raw = q._bytes(dict(schema_version=1,image_id=owner['image_id'],dive_generation=owner['dive_generation'],
        provenance={key:owner[key] for key in _PROVENANCE},prepared_at=owner['prepared_at'],completed_at=completed_at,
        counts=counts,**{key:owned[key] for key in ('questions','receipts','observations','dependencies','acquisitions')}))
    _require(len(raw) <= MAX_JOURNAL_BYTES,'Journal exceeds byte bound')
    return raw


def _historical_graph(run, owner, index, upstream):
    """Historical authority is immutable; current SQL only supplies a matching snapshot."""
    projection = index['graph_projection']
    worklist_hash = projection['chain_worklist_sha256']
    overlay = None
    if all(owner[key] == getattr(upstream,key) for key in ('image_id','manifest_sha256',
            'surface_snapshot_sha256','candidate_snapshot_sha256')) and _digest(firmware_chain._worklist(upstream,legacy=True)) == worklist_hash:
        snapshot = upstream
    else:
        raw = _read(run,'files/firmware-chain/'+worklist_hash+'/worklist.json',worklist_hash)
        body = _json(raw,newline=True)
        _require(type(body['schema_version']) is int and body.pop('schema_version') == 1, 'Historical worklist version differs')
        legacy = 'dive_overlay' not in body
        overlay = None if legacy else firmware_chain._checked_overlay(body.pop('dive_overlay'))
        classes = dict(findings=firmware_fpcheck.VerifiedFirmwareFinding,surfaces=firmware_fpcheck.VerifiedFirmwareSurface,
            unknowns=firmware_fpcheck.VerifiedFirmwareUnknown,pivots=firmware_fpcheck.VerifiedFirmwarePivot)
        for name, cls in classes.items():
            parsed = []
            for value in body[name]:
                value = dict(value)
                if name == 'findings':
                    value['contributors'] = tuple(firmware_fpcheck.VerifiedFirmwareContributor(**r) for r in value['contributors'])
                    for key in ('lanes','component_paths','surface_ids'): value[key] = tuple(value[key])
                if name == 'pivots': _require(value.pop('context_only') is True, 'Historical pivot is not context-only')
                record = cls(**value)
                artifact = json.loads(_read(run,record.artifact_path,record.artifact_sha256),object_pairs_hook=q._pairs)
                expected = q._wire(record)
                expected.pop('artifact_path'); expected.pop('artifact_sha256')
                _require(artifact['image_id'] == owner['image_id'], 'Historical artifact image differs')
                if name in ('surfaces','unknowns'):
                    from audit_core import surface_results
                    result = surface_results._parse(artifact)
                    _require(result.manifest_sha256 == owner['manifest_sha256'], 'Historical surface manifest differs')
                    candidates = [dataclasses.asdict(item) | dict(image_id=result.image_id)
                        for decision in result.decisions for item in getattr(decision,name)]
                elif name == 'pivots':
                    from audit_core import firmware_fpcheck_results
                    result = firmware_fpcheck_results._parse(artifact)
                    candidates = [dict(image_id=result.image_id,candidate_snapshot_sha256=result.candidate_snapshot_sha256,
                        source_lane=decision.lane,source_candidate_id=decision.candidate_id,
                        pivot_id=decision.false_positive.pivot_id,component_path=decision.false_positive.component_path,
                        refuting_mechanism=decision.false_positive.refuting_mechanism,
                        enabled_observation=decision.false_positive.enabled_observation,evidence=decision.false_positive.pivot_evidence)
                        for decision in result.decisions if decision.false_positive is not None]
                else:
                    _require(artifact['candidate_snapshot_sha256'] == owner['candidate_snapshot_sha256'], 'Historical finding candidate differs')
                    candidates = artifact['findings']
                _require(sum(item == expected for item in candidates) == 1, 'Historical typed owner differs from immutable artifact')
                parsed.append(record)
            body[name] = tuple(parsed)
        snapshot = firmware_fpcheck.VerifiedFirmwareFindingsSnapshot(**body)
        _require(firmware_chain._worklist(snapshot,overlay,legacy=legacy) == raw, 'Historical worklist is not exact typed projection')
        _read(run,snapshot.findings_artifact_path,snapshot.findings_artifact_sha256)
    _require(all(owner[key] == getattr(snapshot,key) for key in ('image_id','manifest_sha256',
        'surface_snapshot_sha256','candidate_snapshot_sha256')), 'Historical upstream ownership differs')
    raw = _read(run,owner['chain_graph_path'],owner['chain_graph_sha256'])
    graph_body = _json(raw,newline=True)
    parsed = firmware_chain._graph_result(graph_body)
    validated, expected = firmware_chain._verified_graph(snapshot,parsed,graph_body['result_sha256'],overlay)
    _require(raw == expected and parsed.worklist_sha256 == worklist_hash and
        owner['chain_graph_path'] == 'artifacts/firmware-chain/'+worklist_hash+'/'+owner['chain_graph_sha256']+'/chains.json',
        'Historical canonical graph differs')
    _checked_install(run/pathlib.PurePosixPath(owner['chain_graph_path']).parent,{'chains.json':raw},run)
    return firmware_chain._graph_snapshot(snapshot,validated,owner['chain_graph_path'],owner['chain_graph_sha256'])


def _live_attempt(run, root, owner, packet, graph, upstream, dependencies, acquisitions):
    """Freshness compares current owners, never a replacement graph publication."""
    if any(owner[k] != getattr(upstream,k) for k in ('image_id','manifest_sha256','surface_snapshot_sha256','candidate_snapshot_sha256')):
        return False
    current = dataclasses.replace(graph,findings=upstream.findings,surfaces=upstream.surfaces,unknowns=upstream.unknowns)
    if not set(_question(packet['question']).subject_refs) <= set(q._catalog(current)):
        return False
    for name in ('findings','surfaces','unknowns'):
        if getattr(graph,name) != getattr(current,name): return False
    for record in packet['extract_records']:
        manifest = _json_manifest(_read(run,'extract/manifest.json',maximum=8*1024*1024))
        value = manifest.get(record['unit']+'/'+record['name'])
        if value is None or q._wire(q.extract_record(extract.Record(**value))) != record: return False
    for dep in dependencies:
        if dep['kind'] == 'probe-manifest':
            acquisition = next(a for a in acquisitions if a['acquisition_id'] == dep['logical_id'])
            manifest = _json(_read(run,acquisition['manifest_path'],acquisition['manifest_sha256']))
            for source in manifest['dependencies']:
                if source['path'] is not None:
                    raw = _read(_selector(root),source['path'])
                    if source['before'] != dict(sha256=_digest(raw),byte_count=len(raw)): return False
    return True



def _legacy_attempt(run, packet, receipt, observation, dependencies, acquisitions):
    """Preserve the old byte-exact boundary without granting conclusion authority."""
    if observation is None: return
    question = _question(packet['question'])
    _require((receipt['attempt_ordinal'],receipt['packet_sha256'],receipt['result_path'],receipt['result_sha256'],
        receipt['outcome'],receipt['dependency_count'],receipt['evidence_count'],receipt['successor_count']) ==
        (question.attempt_ordinal,_digest(q._bytes(packet)),observation['artifact_path'],observation['artifact_sha256'],
        observation['outcome'],len(dependencies),len(json.loads(observation['evidence_refs'])),len(json.loads(observation['successor_questions']))) and
        observation['attempt_ordinal'] == question.attempt_ordinal, 'Legacy observation/receipt cross-fields differ')
    _require(len(json.loads(observation['dependency_refs'])) == len(dependencies) and
        [d['ordinal'] for d in dependencies] == list(range(len(dependencies))) and
        len({(d['kind'],d['logical_id']) for d in dependencies}) == len(dependencies), 'Legacy dependency denominator differs')
    projection = []
    for dependency in dependencies:
        _require(dependency['observation_id'] == observation['observation_id'], 'Legacy dependency observation differs')
        raw = _read(run,dependency['relative_path'],dependency['sha256'])
        _require(len(raw) == dependency['byte_count'],'Legacy dependency byte count differs')
        _provenance(dependency['source_provenance'])
        identity = {key:dependency[key] for key in ('kind','logical_id','relative_path','sha256')}
        if dependency['kind'] in ('probe-manifest','hardware-capture'):
            _require(any((a['acquisition_id'],a['manifest_path'],a['manifest_sha256']) ==
                (dependency['logical_id'],dependency['relative_path'],dependency['sha256']) for a in acquisitions), 'Legacy acquisition ownership differs')
        else: _require(identity in packet['allowed_dependencies'],'Legacy static dependency exceeds packet')
        projection.append({k:v for k,v in dependency.items() if k not in ('image_id','dive_generation','question_id','ordinal','observation_id','recorded_at')})
    _require(projection == sorted(projection,key=q._bytes),'Legacy dependency order differs')
    if observation['outcome'] != 'inconclusive':
        _require(observation['evidence_rung'] == {'static':'static-resolved','emulate':'emulated-observed','hardware':'hardware-observed'}[question.method],
            'Legacy evidence rung differs')
        if question.method != 'static':
            kind = 'probe-manifest' if question.method == 'emulate' else 'hardware-capture'
            _require(any(d['kind'] == kind for d in dependencies),'Legacy dynamic conclusion lacks its method')


def _reconstruct(con, run, root, upstream):
    """Rebuild every assignment and canonical result before deriving any live state."""
    from audit_core import firmware_dive_results as results
    rows = _rows(con,upstream.image_id)
    owners = {r['dive_generation']:r for r in rows['runs']}
    for name in ('questions','receipts','observations','dependencies','acquisitions'):
        _require(all(r['dive_generation'] in owners for r in rows[name]), 'Foreign/orphan dive row')
        if owners:
            marks = ','.join('?' for _ in owners)
            foreign = con.execute(f'SELECT 1 FROM cba_firmware_dive_{name} WHERE dive_generation IN ({marks}) AND image_id<>? LIMIT 1',
                (*owners,upstream.image_id)).fetchone()
            _require(foreign is None,'Foreign image reuses dive generation')
    attempts, generations, semantics = [], {}, {}
    for generation, owner in owners.items():
        _timestamp(owner['prepared_at'])
        owned = {name:[r for r in values if r['dive_generation'] == generation] for name,values in rows.items() if name != 'runs'}
        for values in owned.values():
            for row in values: _require(_timestamp(row['recorded_at']) >= owner['prepared_at'],'Dive row predates preparation')
        prefix = 'files/firmware-dive/'+generation
        _require(owner['question_index_path'] == prefix+'/index.json' and owner['journal_input_path'] == prefix+'/journal-input.json' and
            owner['analyst_manifest_path'] == owner['question_index_path'], 'Frozen generation path differs')
        index_raw = _read(run,owner['question_index_path'],owner['question_index_sha256'],MAX_INDEX_BYTES)
        index = _json(index_raw)
        journal_raw = _read(run,owner['journal_input_path'],owner['journal_input_sha256'],MAX_JOURNAL_BYTES)
        inputs = _json(journal_raw)
        graph = _historical_graph(run,owner,index,upstream)
        graph_projection = {key:getattr(graph,key) for key in _GRAPH_KEYS}
        journal_index = tuple(q.JournalIndexEntry(**(r | {'subject_refs':q._subjects(r['subject_refs'])})) for r in inputs['observations'])
        identities = [entry.observation_id for entry in journal_index]
        _require(len(journal_index) <= q.MAX_JOURNAL_ENTRIES and identities == sorted(set(identities)),
            'Frozen journal index requires bounded sorted unique identities')
        _require(journal_raw == q._bytes(dict(schema_version=1,image_id=owner['image_id'],candidate_snapshot_sha256=owner['candidate_snapshot_sha256'],
            finding_artifacts=list(_finding_refs(graph)),observations=journal_index)), 'Frozen journal input differs')
        manifest = index['analyst_manifest']
        _require(set(manifest) == {'schema_version','questions'} and type(manifest['schema_version']) is int and manifest['schema_version'] == 1 and
            q._hash(manifest) == owner['analyst_manifest_sha256'], 'Frozen analyst manifest differs')
        for value in manifest['questions']: q._analyst(value)
        questions, packets, packet_manifest = [], {}, []
        contents = {'index.json':index_raw,'journal-input.json':journal_raw}
        assigned = sorted(owned['questions'],key=lambda r:r['ordinal'])
        _require([r['ordinal'] for r in assigned] == list(range(len(assigned))), 'Assignment ordinal denominator differs')
        for row in assigned:
            raw = _read(run,row['packet_path'],row['packet_sha256'],q.MAX_PACKET_BYTES)
            packet = _json(raw)
            contents['questions/'+row['question_id']+'.json'] = raw
            question = _question(packet['question'])
            _require(q.canonical_question_id(graph,question) == question.question_id and
                row['packet_path'] == prefix+'/questions/'+question.question_id+'.json', 'Frozen question identity differs')
            _require(q.packet_bytes(question,graph,journal_index) == raw, 'Frozen packet authority differs')
            expected = _question_row(question,owner['image_id'],generation,row['packet_path'],raw,row['ordinal'])
            _require({k:v for k,v in row.items() if k != 'recorded_at'} == expected, 'Frozen question row differs')
            questions.append(question); packets[question.question_id] = packet
            packet_manifest.append({k:row[k] for k in ('question_id','attempt_ordinal','packet_path','packet_sha256')})
        _checked_install(run/prefix,contents,run)
        _require([i.question_id for i in questions] == sorted(i.question_id for i in questions), 'Question dispatch order differs')
        retries = index['retry_projection']
        _require(retries == [[i.question_id,i.attempt_ordinal,i.prior_observation_id] for i in questions if i.attempt_ordinal > 1],
            'Retry projection differs')
        expected_index = dict(schema_version=1,image_id=owner['image_id'],dive_generation=generation,graph_sha256=graph.graph_sha256,
            analyst_manifest=manifest,analyst_manifest_sha256=owner['analyst_manifest_sha256'],journal_input_sha256=owner['journal_input_sha256'],
            graph_projection=graph_projection,input_overlay=index['input_overlay'],retry_projection=retries,questions=packet_manifest)
        _require(q._bytes(expected_index) == index_raw and q._hash(dict(schema_version=1,graph=graph_projection,analyst_manifest=manifest,
            input_overlay=index['input_overlay'],retry_projection=retries,questions=questions)) == generation, 'Frozen generation identity differs')
        counts = dict(question_count=len(questions),retry_count=len(retries),**{name:sum(i.origin == origin for i in questions) for name,origin in
            (('chain_blocker_count','chain-blocker'),('surface_unknown_count','surface-unknown'),('analyst_question_count','analyst'),('conflict_count','conflict'))})
        _require(all(owner[k] == v for k,v in counts.items()), 'Prepared denominator/counts differ')
        for name in ('observations','dependencies','acquisitions'):
            _require(all(r['question_id'] in packets for r in owned[name]), 'History row lacks exact question')
        for acquisition in owned['acquisitions']:
            global_owners = surface._query(con,
                'SELECT image_id,dive_generation,question_id FROM cba_firmware_dive_acquisitions WHERE acquisition_id=?',
                (acquisition['acquisition_id'],))
            _require(global_owners == [{key:acquisition[key] for key in ('image_id','dive_generation','question_id')}],
                'Acquisition identity has multiple or foreign owners')
            results._sealed_acquisition(run,acquisition,packets[acquisition['question_id']])
        receipts = {r['question_id']:r for r in owned['receipts']}
        _require(len(receipts) == len(owned['receipts']) and set(receipts) <= (set(packets) if packets else {None}), 'Receipt denominator differs')
        observations = {r['question_id']:r for r in owned['observations']}
        _require(set(observations) == set(receipts)-{None}, 'Observation denominator differs')
        _require(all(r['question_id'] in observations for r in owned['dependencies']), 'Orphan dependency')
        full = set(receipts) == (set(packets) if packets else {None})
        for identity, receipt in receipts.items():
            packet = packets.get(identity)
            observed = observations.get(identity)
            deps = sorted([r for r in owned['dependencies'] if r['question_id'] == identity],key=lambda r:r['ordinal'])
            acquisitions = [r for r in owned['acquisitions'] if r['question_id'] == identity]
            raw = _read(run,receipt['result_path'],receipt['result_sha256'],MAX_JOURNAL_BYTES)
            projection = results._historical_projection(run,raw,owner,packet,receipt,observed,deps,acquisitions,retained=True)
            for table,column,value in [('receipts','receipt_key',receipt['receipt_key']),
                    *([] if observed is None else [('observations','observation_id',observed['observation_id'])])]:
                foreign = con.execute(f'SELECT 1 FROM cba_firmware_dive_{table} WHERE {column}=? AND image_id<>? LIMIT 1',
                    (value,upstream.image_id)).fetchone()
                _require(foreign is None, 'Global dive identity reused by foreign image')
            if projection is not None:
                parsed = results._parse(json.loads(raw,object_pairs_hook=q._pairs))
                if packet is not None:
                    for successor in parsed.answer.successor_questions: q._validate_question(successor,graph,q._catalog(graph))
                _checked_install(run/pathlib.PurePosixPath(receipt['result_path']).parent,{'result.json':raw},run)
            if projection is None: _legacy_attempt(run,packet,receipt,observed,deps,acquisitions)
            if observed is not None:
                semantic = projection if projection is not None else ('opaque',raw,
                    {k:v for k,v in observed.items() if k not in ('image_id','dive_generation','attempt_ordinal','recorded_at','artifact_path')},
                    [{k:v for k,v in d.items() if k not in ('image_id','dive_generation','question_id','ordinal','observation_id','recorded_at')} for d in deps])
                oid = observed['observation_id']
                _require(oid not in semantics or semantics[oid] == semantic, 'Observation semantic identity differs')
                semantics[oid] = semantic
                question = _question(packet['question'])
                current = projection is not None and _live_attempt(run,root,owner,packet,graph,upstream,deps,acquisitions)
                attempts.append(dict(owner=owner,question=question,observation=observed,dependencies=deps,current=current,canonical=projection is not None))
        counts.update({name+'_count':sum(r['outcome'] == name for r in owned['observations']) for name in ('supported','refuted','inconclusive')})
        if owner['status'] == 'complete':
            _require(full and all(owner[k] == v for k,v in counts.items()), 'Completed denominator/counts differ')
            stamp = _timestamp(owner['completed_at'])
            _require(stamp >= owner['prepared_at'] and all(r['recorded_at'] <= stamp for values in owned.values() for r in values),
                'Completed timestamp precedes evidence')
            raw = _journal(owner,owned,stamp,counts)
            relative = 'artifacts/firmware-dive/'+generation+'/'+_digest(raw)+'/journal.json'
            _require(owner['journal_path'] == relative and owner['journal_sha256'] == _digest(raw), 'Completed journal provenance differs')
            _checked_install(run/pathlib.PurePosixPath(relative).parent,{'journal.json':raw},run)
        else:
            _require(owner['status'] == 'pending' and owner['completed_at'] is None and owner['journal_path'] is None and owner['journal_sha256'] is None and
                all(owner[name+'_count'] == 0 for name in ('supported','refuted','inconclusive')), 'Pending publication state differs')
        generations[generation] = (owner,owned,counts,full,index,graph)
    excluded = _opaque_lineage({a['observation']['observation_id']:a['question'].supersedes_observation_ids for a in attempts},
        {a['observation']['observation_id'] for a in attempts if not a['canonical']})
    for attempt in attempts:
        if attempt['observation']['observation_id'] in excluded: attempt['current'] = False
    history = _histories(run,generations,attempts)
    _frozen_links(run,generations,attempts,history)
    return rows,generations,attempts



def _histories(run,generations,attempts):
    """Verify immutable contracts and contiguous retries across every retained graph."""
    observed = {(a['owner']['dive_generation'],a['question'].question_id):a for a in attempts}
    history = []
    for owner,owned,counts,full,index,graph in generations.values():
        for row in owned['questions']:
            item = observed.get((owner['dive_generation'],row['question_id']))
            if item is None:
                question = _question(_json(_read(run,row['packet_path'],row['packet_sha256']))['question'])
                entry = q.QuestionHistory(question,question.attempt_ordinal,None,None,None,(),(),False)
            else:
                question,observation = item['question'],item['observation']
                refs = [tuple(json.loads(observation[name])) for name in ('dependency_refs','evidence_refs')]
                if item['canonical']: refs = [tuple(sorted(q._hash(ref) for ref in values)) for values in refs]
                effect = json.loads(observation['resolution_effect']) if observation['resolution_effect'] else None
                entry = q.QuestionHistory(question,question.attempt_ordinal,observation['observation_id'],observation['outcome'],
                    None if effect is None else effect['value'],*refs,item['current'] and owner['status']=='complete',question.supersedes_observation_ids)
            history.append((owner['candidate_snapshot_sha256'],entry))
    for owner,owned,counts,full,index,graph in generations.values():
        catalog,unique = q._catalog(graph),{}
        for candidate,item in history:
            if candidate != graph.candidate_snapshot_sha256 or not set(item.question.subject_refs) <= set(catalog): continue
            key = (item.question.question_id,item.attempt_ordinal)
            unique[key] = _coalesce_attempt(unique[key],item) if key in unique else item
        q._history(graph,catalog,tuple(unique.values()))
    return history


def _frozen_links(run,generations,attempts,history=None):
    """Frozen input references remain accountable to exact retained attempts."""
    if history is None: history = _histories(run,generations,attempts)
    known = {}
    for item in attempts:
        known.setdefault(item['observation']['observation_id'],[]).append(item)
    for owner,owned,counts,full,index,graph in generations.values():
        inputs = _json(_read(run,owner['journal_input_path'],owner['journal_input_sha256'],MAX_JOURNAL_BYTES))
        for ref in inputs['observations']:
            _require(ref['status'] in ('current','stale','contested') and any(
                {k:ref[k] for k in ('question_id','subject_refs','outcome','artifact_path','artifact_sha256')} ==
                dict(question_id=a['question'].question_id,subject_refs=q._wire(a['question'].subject_refs),
                    **{k:a['observation'][k] for k in ('outcome','artifact_path','artifact_sha256')})
                for a in known.get(ref['observation_id'],())), 'Journal index has no exact historical observation')
        for ref in index['input_overlay']:
            matches = []
            for item in known.get(ref.get('observation_id'),()):
                observed = item['observation']
                if item['owner']['status'] != 'complete' or observed['outcome'] not in ('supported','refuted'): continue
                source_graph = generations[item['owner']['dive_generation']][-1]
                if (any(item['owner'][key] != owner[key] for key in ('image_id','manifest_sha256','surface_snapshot_sha256','candidate_snapshot_sha256')) or
                        item['owner']['completed_at'] > owner['prepared_at'] or
                        not set(item['question'].subject_refs) <= set(q._catalog(graph)) or
                        any(getattr(source_graph,name) != getattr(graph,name) for name in ('findings','surfaces','unknowns'))):
                    continue
                def refs(name):
                    values = json.loads(observed[name])
                    return tuple(sorted(q._hash(value) for value in values)) if item['canonical'] else tuple(values)
                dependencies = [{k:v for k,v in d.items() if k not in ('image_id','dive_generation','question_id','ordinal','observation_id','recorded_at')} for d in item['dependencies']]
                projection = dict(observation_id=observed['observation_id'],question_id=observed['question_id'],
                    resolution_effect=json.loads(observed['resolution_effect']),dependency_refs=refs('dependency_refs'),
                    evidence_refs=refs('evidence_refs'),dependencies=tuple(q._hash(d) for d in dependencies))
                matches.append(q._bytes(projection) == q._bytes(ref))
            _require(any(matches), 'Frozen input overlay differs from durable evidence')
        _require(index['input_overlay'] == sorted({q._bytes(row):row for row in index['input_overlay']}.values(),key=q._bytes),
            'Frozen input overlay ordering differs')
        # Reproduce old frozen denominators using exact historical context, including
        # legacy inputs. This never restores their independently excluded live authority.
        frozen_context = {ref['observation_id'] for ref in index['input_overlay']}
        selected,catalog = {},q._catalog(graph)
        for candidate,item in history:
            if candidate != graph.candidate_snapshot_sha256 or not set(item.question.subject_refs) <= set(catalog): continue
            item = dataclasses.replace(item,dependency_current=item.observation_id in frozen_context)
            key = (item.question.question_id,item.attempt_ordinal)
            selected[key] = _coalesce_attempt(selected[key],item) if key in selected else item
        questions = [_question(_json(_read(run,row['packet_path'],row['packet_sha256']))['question']) for row in owned['questions']]
        _generation_authority(graph,index['analyst_manifest'],questions,tuple(selected.values()))


def _generation_authority(graph,manifest,questions,history):
    """Re-derive the original frozen denominator, including exact conflict sets."""
    analyst = tuple(q._analyst(value) for value in manifest['questions'])
    _require(q._wire(analyst) == sorted({q._bytes(i):q._wire(i) for i in analyst}.values(),key=q._bytes),
        'Analyst manifest ordering differs')
    expected = q.derive_questions(graph,analyst,history).questions
    if questions and all(i.origin == 'conflict' for i in questions) and not analyst:
        expected = tuple(i for i in expected if i.origin == 'conflict')
    derived = {i.question_id:i for i in expected}
    _require(set(derived) == {i.question_id for i in questions},'Frozen question denominator differs from derivation')
    for question in questions:
        expected_question = dataclasses.replace(derived[question.question_id],attempt_ordinal=question.attempt_ordinal,
            prior_observation_id=question.prior_observation_id,extract_records=question.extract_records)
        _require(expected_question == question,'Frozen question differs from independent derivation')
        if question.prior_observation_id is not None:
            _require(any(i.question.question_id == question.question_id and i.attempt_ordinal < question.attempt_ordinal and
                i.observation_id == question.prior_observation_id for i in history), 'Retry prior observation is not an earlier exact attempt')


def _overlay(attempts, prospective=None):
    """Resolve exact sets, without timestamp or generation ordering winners."""
    from audit_core import firmware_dive_results as results
    contracts = {}
    for attempt in attempts:
        question = attempt['question']
        identity = (attempt['owner']['candidate_snapshot_sha256'],question.question_id)
        contract = q._bytes((question.origin,question.subject_refs,question.method,question.question,
            question.settling_observation,question.axes,question.resolution_contract,question.supersedes_observation_ids))
        _require(identity not in contracts or contracts[identity] == contract, 'History changes an immutable question contract')
        contracts[identity] = contract
    all_observations = {a['observation']['observation_id']:a for a in attempts}
    excluded = _opaque_lineage({identity:a['question'].supersedes_observation_ids for identity,a in all_observations.items()},
        {identity for identity,a in all_observations.items() if not a['canonical']})
    roots, visiting = {}, set()
    for identity in all_observations:
        pending = [(identity,False)]
        while pending:
            node,expanded = pending.pop()
            if node in roots: continue
            question = all_observations[node]['question']
            refs = question.supersedes_observation_ids
            if expanded:
                families = {roots[ref] for ref in refs}
                _require(len(families) == 1,'Conflict combines unrelated questions')
                roots[node] = families.pop()
                visiting.remove(node)
                continue
            _require(node not in visiting,'Cyclic dive supersession')
            if question.origin != 'conflict':
                _require(not refs,'Ordinary question cannot supersede observations')
                roots[node] = question.question_id
                continue
            _require(len(refs) >= 2 and all(ref in all_observations for ref in refs),'Conflict lacks its exact known ancestors')
            parents = [all_observations[ref] for ref in refs]
            contract = lambda value: (value.subject_refs,value.method,value.axes,value.settling_observation,value.resolution_contract)
            _require(all(contract(parent['question']) == contract(question) and parent['observation']['outcome'] in ('supported','refuted') for parent in parents),
                'Conflict combines incompatible question contracts')
            _require(question.question == q._conflict_text(refs),'Conflict question text differs')
            visiting.add(node)
            pending.append((node,True))
            pending.extend((ref,False) for ref in reversed(refs))
    active = {}
    for attempt in attempts:
        observation = attempt['observation']
        if observation['observation_id'] not in excluded and attempt['current'] and (attempt['owner']['status'] == 'complete' or attempt['owner']['dive_generation'] == prospective) and observation['outcome'] in ('supported','refuted'):
            active[observation['observation_id']] = attempt
    superseded = {ref for item in active.values() if item['question'].origin == 'conflict'
        for ref in item['question'].supersedes_observation_ids}
    families = {}
    for identity,attempt in active.items():
        if identity not in superseded: families.setdefault(roots[identity],{})[identity] = attempt
    accepted,contested = {},set()
    for remaining in families.values():
        effects = {q._bytes((item['observation']['outcome'],json.loads(item['observation']['resolution_effect']))) for item in remaining.values()}
        if len(effects) > 1: contested.update(remaining)
        else: accepted.update(remaining)
    observations = []
    for identity,item in sorted(accepted.items()):
        observed, question = item['observation'],item['question']
        target = question.resolution_contract.target_subject
        settled = {target} if target.kind in ('chain-blocker', 'surface-unknown') else set()
        family_origins = {attempt['question'].origin for attempt in attempts
            if attempt['question'].question_id == roots[identity]
            and attempt['question'].origin != 'conflict'}
        _require(len(family_origins) == 1, 'Dive family has ambiguous settlement authority')
        if family_origins == {'chain-blocker'}:
            settled.update(ref for ref in question.subject_refs if ref.kind == 'chain-blocker')
        observations.append(CurrentDiveObservation(identity,question.question_id,tuple(str(r) for r in question.subject_refs),
            tuple(sorted(map(str, settled))), observed['outcome'],
            results._effect(json.loads(observed['resolution_effect'])),observed['evidence_rung'],
            tuple(sorted(q._hash(ref) for ref in json.loads(observed['dependency_refs']))),
            tuple(sorted(q._hash(ref) for ref in json.loads(observed['evidence_refs'])))))
    return CurrentDiveOverlay(observations=tuple(observations)),contested


def _selected(con, image_id):
    if image_id is None:
        images = [row[0] for row in con.execute('SELECT DISTINCT image_id FROM cba_firmware_dive_runs ORDER BY image_id')]
        _require(len(images) == 1, 'Select exactly one dive image')
        image_id = images[0]
    owners = surface._query(con,'SELECT * FROM cba_firmware_dive_runs WHERE image_id=?',(image_id,))
    _require(owners,'No prepared dive generation')
    pending = [r for r in owners if r['status'] == 'pending']
    _require(len(pending) <= 1,'Multiple pending dive generations are ambiguous')
    if pending: return image_id,pending[0]['dive_generation']
    stamp = max(_timestamp(r['completed_at']) for r in owners)
    tied = [r for r in owners if r['completed_at'] == stamp]
    _require(len({tuple(r[k] for k in ('candidate_snapshot_sha256','chain_graph_path','chain_graph_sha256')) for r in tied}) == 1,
        'Ambiguous tied completed dive ownership')
    return image_id,max(r['dive_generation'] for r in tied)


def _completion(con, run, root, image_id):
    image,generation = _selected(con,image_id)
    upstream = firmware_fpcheck.verified_findings_snapshot(con,run,root,image_id=image)
    rows,generations,attempts = _reconstruct(con,run,root,upstream)
    owner,owned,counts,full,_,_ = generations[generation]
    _require(full,'Every frozen question requires its exact receipt, including empty')
    old,_ = _overlay(attempts)
    prospective,contested = _overlay(attempts,generation)
    return upstream,rows,generation,owner,owned,counts,attempts,old,prospective,contested


def _summary(run, captured, relative, digest):
    upstream,rows,generation,owner,owned,counts,attempts,old,overlay,contested = captured
    questions = tuple(DiveQuestionSummary(a['question'].question_id,a['question'].attempt_ordinal,
        a['observation']['observation_id'],a['observation']['outcome'],a['observation']['evidence_rung'],
        'stale' if not a['current'] else 'contested' if a['observation']['observation_id'] in contested else 'current')
        for a in sorted(attempts,key=lambda a:a['question'].question_id) if a['owner']['dive_generation'] == generation)
    return FirmwareDiveSummary(upstream.image_id,generation,counts['question_count'],counts['supported_count'],counts['refuted_count'],
        counts['inconclusive_count'],*(sum(i.status == status for i in questions) for status in ('current','stale','contested')),
        questions,str(run/relative),digest,_digest(q._bytes(overlay)),True)


def check(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
          *, image_id: str | None = None) -> FirmwareDiveSummary:
    """Complete a reconstructed denominator and invalidate graph feedback atomically."""
    started = False
    try:
        _require(not con.in_transaction,'Dive completion requires no active caller transaction')
        run = _selector(run_dir)
        con.execute('BEGIN'); started = True
        captured = _completion(con,run,root,image_id)
        owner,owned,counts = captured[3:6]
        if owner['status'] == 'complete':
            return _summary(run,captured,owner['journal_path'],owner['journal_sha256'])
        completed_at = _timestamp(con.execute("SELECT datetime('now')").fetchone()[0])
        _require(completed_at >= owner['prepared_at'] and all(r['recorded_at'] <= completed_at for values in owned.values() for r in values),
            'Completion timestamp precedes evidence')
        raw = _journal(owner,owned,completed_at,counts)
        digest = _digest(raw)
        relative = 'artifacts/firmware-dive/'+owner['dive_generation']+'/'+digest+'/journal.json'
        destination = run/pathlib.PurePosixPath(relative).parent
        con.rollback(); started = False
        _install(destination,{'journal.json':raw},run)
        con.execute('BEGIN IMMEDIATE'); started = True
        _require(_completion(con,run,root,image_id) == captured,'Dive completion authority changed before publication')
        _checked_install(destination,{'journal.json':raw},run)
        con.execute("UPDATE cba_firmware_dive_runs SET status='complete',journal_path=?,journal_sha256=?,completed_at=?,supported_count=?,refuted_count=?,inconclusive_count=? WHERE image_id=? AND dive_generation=?",
            (relative,digest,completed_at,counts['supported_count'],counts['refuted_count'],counts['inconclusive_count'],owner['image_id'],owner['dive_generation']))
        if q._bytes(captured[7]) != q._bytes(captured[8]): firmware_chain.invalidate(con,owner['image_id'],commit=False)
        con.commit(); started = False
        return _summary(run,captured,relative,digest)
    except Exception as exc:
        from audit_core import firmware_dive_results as results
        from audit_core import firmware_dive_acquisition as acquisition
        if isinstance(exc,(sqlite3.Error,db.DbError)): raise FirmwareDiveError('database operation failed') from exc
        if isinstance(exc,(OSError,ValueError,TypeError,KeyError,RecursionError,firmware_chain.FirmwareChainError,
                firmware_fpcheck.FpcheckError,surface.SurfaceError,results.FirmwareDiveResultError,acquisition.AcquisitionError)):
            raise FirmwareDiveError('Cannot complete firmware dive') from exc
        raise
    finally:
        if started: con.rollback()


def current_overlay(con: sqlite3.Connection, run_dir: str | pathlib.Path, root: str | pathlib.Path,
                    verified_findings_snapshot: firmware_fpcheck.VerifiedFirmwareFindingsSnapshot) -> CurrentDiveOverlay:
    """Read-only current conclusions, independently verifying the caller's snapshot."""
    owned = False
    try:
        if not con.in_transaction: con.execute('BEGIN'); owned = True
        run = _selector(run_dir)
        _require(isinstance(verified_findings_snapshot,firmware_fpcheck.VerifiedFirmwareFindingsSnapshot),'Invalid findings snapshot')
        upstream = firmware_fpcheck.verified_findings_snapshot(con,run,root,image_id=verified_findings_snapshot.image_id)
        _require(upstream == verified_findings_snapshot,'Supplied findings snapshot differs from current authority')
        _,_,attempts = _reconstruct(con,run,root,upstream)
        return _overlay(attempts)[0]
    except Exception as exc:
        from audit_core import firmware_dive_acquisition as acquisition
        if isinstance(exc,(sqlite3.Error,db.DbError)): raise FirmwareDiveError('database operation failed') from exc
        if isinstance(exc,(OSError,ValueError,TypeError,KeyError,RecursionError,firmware_chain.FirmwareChainError,
                firmware_fpcheck.FpcheckError,surface.SurfaceError,acquisition.AcquisitionError)):
            raise FirmwareDiveError('Cannot verify current dive overlay') from exc
        raise
    finally:
        if owned: con.rollback()


def verified_decision_input(con: sqlite3.Connection, run_dir: str | pathlib.Path,
        root: str | pathlib.Path,
        graph_snapshot: firmware_chain.VerifiedFirmwareGraphSnapshot) -> VerifiedDiveDecisionInput:
    """Verify the exact current graph and its latest completed dive denominator."""
    owned = False
    try:
        if not con.in_transaction:
            con.execute("BEGIN")
            owned = True
        run = _selector(run_dir)
        _require(isinstance(graph_snapshot, firmware_chain.VerifiedFirmwareGraphSnapshot),
                 "Invalid graph snapshot")
        current_graph = firmware_chain.verified_graph_snapshot(
            con, run, root, image_id=graph_snapshot.image_id)
        _require(current_graph == graph_snapshot,
                 "Supplied graph snapshot differs from current authority")
        owners = surface._query(
            con, "SELECT * FROM cba_firmware_dive_runs WHERE image_id=?",
            (graph_snapshot.image_id,))
        _require(owners, "A completed dive denominator is required")
        _require(not any(row["status"] == "pending" for row in owners),
                 "A completed dive denominator is required; pending work remains")
        captured = _completion(con, run, root, graph_snapshot.image_id)
        generation, owner, owned_rows, counts, overlay = (
            captured[2], captured[3], captured[4], captured[5], captured[7])
        _require(not captured[9],
                 "A non-contested dive denominator is required")
        _require(owner["status"] == "complete",
                 "A completed dive denominator is required")
        _require(
            owner["candidate_snapshot_sha256"] == graph_snapshot.candidate_snapshot_sha256
            and owner["chain_graph_path"] == graph_snapshot.graph_path
            and owner["chain_graph_sha256"] == graph_snapshot.graph_sha256,
            "Completed dive denominator belongs to a different graph")
        journal = _read(run, owner["journal_path"], owner["journal_sha256"])
        expected = _journal(owner, owned_rows, owner["completed_at"], counts)
        _require(journal == expected, "Completed dive journal differs from reconstructed authority")
        overlay_sha256 = _digest(q._bytes(overlay))
        return VerifiedDiveDecisionInput(
            graph_snapshot.image_id, generation, owner["journal_path"],
            owner["journal_sha256"], overlay_sha256, overlay)
    except Exception as exc:
        from audit_core import firmware_dive_acquisition as acquisition
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise FirmwareDiveError("database operation failed") from exc
        if isinstance(exc, (OSError, ValueError, TypeError, KeyError, RecursionError,
                firmware_chain.FirmwareChainError, firmware_fpcheck.FpcheckError,
                surface.SurfaceError, acquisition.AcquisitionError)):
            raise FirmwareDiveError("Cannot verify dive decision input") from exc
        raise
    finally:
        if owned:
            con.rollback()
