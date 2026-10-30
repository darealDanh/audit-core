"""Question-owned hardware receipts, stable local evidence and atomic publication."""
import dataclasses
import json
import os
import pathlib
import socket
import sqlite3

import pytest

from audit_core import db, firmware_chain
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_prepare import canonical, sha, prepare, rows, files
from tests.test_firmware_dive_snapshot import complete
from tests.test_hunt_gate import state


def api():
    from audit_core import firmware_dive_acquisition
    return firmware_dive_acquisition


@pytest.fixture
def capture(graph_case, tmp_path):
    complete(graph_case)
    generation = prepare(graph_case)
    question = next(r for r in rows(graph_case[0], 'cba_firmware_dive_questions') if r['method'] == 'hardware')
    packet = json.loads((graph_case[1] / question['packet_path']).read_bytes())
    source = tmp_path / 'input'
    source.mkdir()
    (source / 'uart.txt').write_bytes(b'UART observation\n')
    spec = dict(schema_version=1, image_id='target', dive_generation=generation.dive_generation,
        question_id=question['question_id'], packet_sha256=question['packet_sha256'],
        contract_sha256=sha(canonical(packet['acquisition_contract'])), device_identifier='serial-123',
        firmware_version='v1.0', firmware_sha256='f'*64, lifecycle='provisioned', posture='STA-LAN',
        authentication='physical-UART', operator='operator-1', source='bench UART recorder',
        method='hardware', evidence=[dict(name='uart.txt', source_path='uart.txt')])
    path = source / 'capture.json'
    path.write_bytes(canonical(spec))
    return graph_case, path, spec


def seal(capture, con=None):
    case, path, _ = capture
    return api().seal_capture(con or case[0], case[1], case[2], path)


def save(capture):
    capture[1].write_bytes(canonical(capture[2]))


def test_literal_spec_manifest_id_and_receipt_are_owned_without_answer(capture):
    case, path, value = capture
    con, run = case[:2]
    before = {table: rows(con, table) for table in ('cba_firmware_dive_runs', 'cba_firmware_dive_questions',
        'cba_firmware_dive_observations', 'cba_firmware_dive_receipts', 'cba_firmware_dive_dependencies',
        'cba_firmware_chain_runs', 'cba_firmware_findings')}
    spec = value | dict(evidence=['uart.txt'])
    evidence = [dict(name='uart.txt', byte_count=17, sha256='d4cd9a85949cb859999afbcacddbe32596bebbed8312b8ee15b6fe97d2b2c36e')]
    identity = sha(canonical(dict(kind='capture', spec=spec, evidence=evidence)))
    expected_manifest = spec | dict(kind='capture', acquisition_id=identity, evidence=evidence)
    result = seal(capture)
    directory = run / 'artifacts/firmware-dive-captures' / identity
    assert result.acquisition_id == identity and result.image_id == 'target'
    assert result.dive_generation == value['dive_generation'] and result.question_id == value['question_id']
    assert result.kind == 'capture' and result.file_count == 1 and result.byte_count == 17
    assert (directory / 'spec.json').read_bytes() == canonical(spec)
    assert (directory / 'manifest.json').read_bytes() == canonical(expected_manifest)
    assert (directory / 'evidence/uart.txt').read_bytes() == b'UART observation\n'
    assert sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()) == ['evidence/uart.txt', 'manifest.json', 'spec.json']
    row, = rows(con, 'cba_firmware_dive_acquisitions')
    assert row['acquisition_id'] == identity and row['contract_sha256'] == value['contract_sha256']
    assert row['spec_path'] == (directory / 'spec.json').relative_to(run).as_posix()
    assert row['manifest_path'] == (directory / 'manifest.json').relative_to(run).as_posix()
    assert row['spec_sha256'] == sha(canonical(spec)) and row['manifest_sha256'] == sha(canonical(expected_manifest))
    assert json.loads(row['evidence_paths']) == [(directory / 'evidence/uart.txt').relative_to(run).as_posix()]
    assert json.loads(row['details']) == dict(kind='capture', byte_count=17, file_count=1)
    assert all(rows(con, table) == expected for table, expected in before.items())
    assert str(path.parent).encode() not in (directory / 'spec.json').read_bytes()
    assert b'source_path' not in (directory / 'manifest.json').read_bytes()
    loaded = api().load_capture_spec(path)
    with pytest.raises(dataclasses.FrozenInstanceError): loaded.method = 'static'
    with pytest.raises(dataclasses.FrozenInstanceError): result.kind = 'probe'


def test_identical_retry_is_no_write_and_local_path_or_mtime_does_not_define_id(capture, tmp_path):
    first = seal(capture)
    case, path, value = capture
    moved = tmp_path / 'moved'
    moved.mkdir()
    (moved / 'different-local-name').write_bytes(b'UART observation\n')
    value['evidence'][0]['source_path'] = 'different-local-name'
    second_path = moved / 'spec.json'
    second_path.write_bytes(json.dumps(value, indent=2).encode())
    before, changes, artifacts = state(case[0]), case[0].total_changes, files(case[1])
    assert api().seal_capture(*case[:3], second_path) == first
    assert state(case[0]) == before and case[0].total_changes == changes and files(case[1]) == artifacts


@pytest.mark.parametrize('damage', ['unknown', 'missing', 'bool-version', 'wrong-version', 'digest', 'lifecycle',
    'posture', 'authentication', 'method', 'blank', 'oversized', 'control', 'surrogate', 'duplicate-name',
    'reversed', 'empty-evidence', 'extra-evidence-key', 'evidence-object', 'too-many', 'absolute-name',
    'traversal-name', 'nested-name', 'backslash-name', 'absolute-source', 'traversal-source', 'dot-source',
    'duplicate-source-key', 'duplicate-key', 'nonfinite', 'deep', 'metadata-overflow', 'not-object'])
def test_strict_spec_rejects_ambiguous_or_unbounded_input(capture, damage):
    case, path, value = capture
    if damage == 'unknown': value['conclusion'] = 'supported'
    elif damage == 'missing': del value['operator']
    elif damage == 'bool-version': value['schema_version'] = True
    elif damage == 'wrong-version': value['schema_version'] = 2
    elif damage == 'digest': value['firmware_sha256'] = 'F'*64
    elif damage in ('lifecycle','posture','authentication'): value[damage] = 'unknown'
    elif damage == 'method': value['method'] = 'static'
    elif damage == 'blank': value['source'] = ' '
    elif damage == 'oversized': value['device_identifier'] = 'x'*4097
    elif damage == 'control': value['operator'] = 'line\nbreak'
    elif damage == 'surrogate':
        path.write_text(json.dumps(value | {'source':'\ud800'}))
    elif damage == 'duplicate-name': value['evidence'] *= 2
    elif damage == 'reversed': value['evidence'] = [dict(name='z',source_path='z'),dict(name='a',source_path='a')]
    elif damage == 'empty-evidence': value['evidence'] = []
    elif damage == 'extra-evidence-key': value['evidence'][0]['hash'] = 'a'*64
    elif damage == 'evidence-object': value['evidence'] = {}
    elif damage == 'too-many': value['evidence'] = [dict(name=f'{n:03}.txt',source_path=f'{n:03}.txt') for n in range(257)]
    elif damage.endswith('-name'):
        value['evidence'][0]['name'] = {'absolute-name':'/x','traversal-name':'..','nested-name':'dir/x','backslash-name':'a\\b'}[damage]
    elif damage.endswith('-source'):
        value['evidence'][0]['source_path'] = {'absolute-source':'/x','traversal-source':'../x','dot-source':'./uart.txt'}[damage]
    elif damage == 'duplicate-source-key':
        path.write_bytes(canonical(value).replace(b'"source_path":"uart.txt"',b'"source_path":"uart.txt","source_path":"other"'))
    elif damage == 'duplicate-key': path.write_bytes(canonical(value)[:-1]+b',"method":"hardware"}')
    elif damage == 'nonfinite': path.write_bytes(canonical(value).replace(b'"schema_version":1',b'"schema_version":NaN'))
    elif damage == 'deep': path.write_bytes(b'['*2000+b'0'+b']'*2000)
    elif damage == 'metadata-overflow': path.write_bytes(b' '*1048577)
    elif damage == 'not-object': path.write_bytes(b'[]')
    if damage not in ('duplicate-source-key','duplicate-key','nonfinite','deep','metadata-overflow','surrogate','not-object'): save(capture)
    before, artifacts = state(case[0]), files(case[1])
    with pytest.raises(api().AcquisitionError): api().load_capture_spec(path)
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(case[1]) == artifacts


@pytest.mark.parametrize('field', ['image_id','dive_generation','question_id','packet_sha256','contract_sha256'])
def test_spec_ownership_cannot_relabel_prepared_question(capture, field):
    case, _, value = capture
    value[field] = 'foreign' if field == 'image_id' else '0'*64
    save(capture)
    before, artifacts = state(case[0]), files(case[1])
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(case[1]) == artifacts


@pytest.mark.parametrize('damage', ['leaf-link', 'parent-link', 'spec-link', 'spec-parent-link', 'directory', 'fifo', 'socket', 'device', 'bytes'])
def test_sources_and_spec_are_bounded_regular_files_without_links(capture, tmp_path, monkeypatch, damage):
    case, path, value = capture
    evidence = path.parent / 'uart.txt'
    listener = None
    if damage in ('leaf-link','device'):
        evidence.unlink()
        evidence.symlink_to('/dev/null' if damage == 'device' else tmp_path / 'external')
        if damage == 'leaf-link': (tmp_path / 'external').write_bytes(b'UART observation\n')
    elif damage in ('parent-link','spec-parent-link'):
        external = tmp_path / 'external'
        path.parent.rename(external)
        path.parent.symlink_to(external, target_is_directory=True)
    elif damage == 'spec-link':
        path.rename(tmp_path / 'real-spec')
        path.symlink_to(tmp_path / 'real-spec')
    elif damage == 'bytes':
        with evidence.open('wb') as stream: stream.truncate(64*1024*1024+1)
    else:
        evidence.unlink()
        if damage == 'directory': evidence.mkdir()
        elif damage == 'fifo': os.mkfifo(evidence)
        else:
            listener = socket.socket(socket.AF_UNIX)
            with monkeypatch.context() as scoped:
                scoped.chdir(path.parent)
                listener.bind('uart.txt')
    before, artifacts = state(case[0]), files(case[1])
    try:
        with pytest.raises(api().AcquisitionError): seal(capture)
        assert state(case[0]) == before and files(case[1]) == artifacts
    finally:
        if listener: listener.close()


@pytest.mark.parametrize('damage', ['source', 'spec', 'installed', 'upstream', 'question', 'contract'])
def test_install_precedes_locked_revalidation_and_races_cannot_publish(capture, monkeypatch, damage):
    case, path, value = capture
    module = api()
    from audit_core import firmware_dive
    real = firmware_dive._install
    before = state(case[0])
    def race(destination, contents, run):
        assert rows(case[0], 'cba_firmware_dive_acquisitions') == []
        real(destination, contents, run)
        if damage == 'source': (path.parent / 'uart.txt').write_bytes(b'drift')
        elif damage == 'spec': value['operator'] = 'changed'; save(capture)
        elif damage == 'installed': (destination / 'evidence/uart.txt').write_bytes(b'drift')
        elif damage == 'upstream': (case[2] / 'c').write_bytes(b'drift\n')
        else:
            case[0].execute('UPDATE cba_firmware_dive_questions SET '+('question' if damage == 'question' else 'packet_sha256')+'=? WHERE question_id=?',
                ('changed' if damage == 'question' else '0'*64,value['question_id']))
            case[0].commit()
    monkeypatch.setattr(firmware_dive, '_install', race)
    with pytest.raises(module.AcquisitionError): seal(capture)
    assert not case[0].in_transaction and rows(case[0], 'cba_firmware_dive_acquisitions') == []
    if damage not in ('question','contract'): assert state(case[0]) == before
    assert rows(case[0], 'cba_firmware_chain_runs')[0]['status'] == 'complete'
    assert list((case[1] / 'artifacts/firmware-dive-captures').iterdir())


@pytest.mark.parametrize('failure', ['sql','commit','unexpected'])
def test_failed_receipt_publication_rolls_back_without_touching_siblings(capture, monkeypatch, failure):
    case = capture[0]
    before = state(case[0])
    connection = case[0]
    if failure == 'commit':
        class Connection(sqlite3.Connection):
            def commit(self): raise sqlite3.OperationalError('injected commit failure')
        connection = sqlite3.connect(case[1] / 'audit.db', factory=Connection)
        connection.row_factory = sqlite3.Row
    else:
        real = db.put
        def fail(con, table, row, **kwargs):
            if table == 'cba_firmware_dive_acquisitions':
                raise RuntimeError('unexpected') if failure == 'unexpected' else sqlite3.OperationalError('injected SQL failure')
            return real(con, table, row, **kwargs)
        monkeypatch.setattr(db, 'put', fail)
    try:
        with pytest.raises(RuntimeError if failure == 'unexpected' else api().AcquisitionError): seal(capture, connection)
        assert state(case[0]) == before and not connection.in_transaction
    finally:
        if connection is not case[0]: connection.close()


def test_write_lock_contention_retains_sql_and_only_unreferenced_artifact(capture):
    case = capture[0]
    before = state(case[0])
    with sqlite3.connect(case[1] / 'audit.db', timeout=0) as connection:
        connection.row_factory = sqlite3.Row
        case[0].execute('BEGIN IMMEDIATE')
        try:
            with pytest.raises(api().AcquisitionError): seal(capture, connection)
            assert state(case[0]) == before and not connection.in_transaction
        finally:
            case[0].rollback()


def test_active_transaction_is_preserved(capture):
    con = capture[0][0]
    con.execute('BEGIN')
    try:
        with pytest.raises(api().AcquisitionError): seal(capture)
        assert con.in_transaction
    finally: con.rollback()


@pytest.mark.parametrize('damage', ['row', 'spec', 'manifest', 'evidence', 'extra', 'evidence-link'])
def test_conflicting_duplicate_refuses_without_repair(capture, tmp_path, damage):
    result = seal(capture)
    case = capture[0]
    directory = pathlib.Path(result.manifest_path).parent
    if damage == 'row':
        case[0].execute("UPDATE cba_firmware_dive_acquisitions SET details='{}'")
        case[0].commit()
    elif damage == 'extra': (directory / 'extra').write_bytes(b'extra')
    elif damage == 'evidence-link':
        (directory / 'evidence/uart.txt').unlink()
        external = tmp_path / 'external'; external.write_bytes(b'UART observation\n')
        (directory / 'evidence/uart.txt').symlink_to(external)
    else: (directory / ('evidence/uart.txt' if damage == 'evidence' else damage+'.json')).write_bytes(b'drift')
    before, artifacts = state(case[0]), files(case[1])
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(case[1]) == artifacts


def test_complete_question_can_seal_with_retained_graph_after_chain_invalidation(capture):
    from tests.test_firmware_dive_prepare import accepted
    case, _, value = capture
    summary = prepare(case)
    accepted(case, summary, question_id=value['question_id'], outcome='inconclusive')
    firmware_chain.invalidate(case[0], 'target')
    case[0].commit()
    before = state(case[0])
    result = seal(capture)
    assert result.question_id == value['question_id']
    after = state(case[0])
    assert all(after[table] == expected for table, expected in before.items() if table != 'cba_firmware_dive_acquisitions')
    assert len(after['cba_firmware_dive_acquisitions']) == 1


@pytest.mark.parametrize('boundary', ['files', 'bytes', 'sum-overflow'])
def test_capture_limits_apply_to_whole_evidence_set_with_nested_sources(capture, boundary):
    case, path, value = capture
    (path.parent / 'nested').mkdir()
    count = 256 if boundary == 'files' else 2
    value['evidence'] = [dict(name=f'{n:03}.bin',source_path=f'nested/{n:03}.bin') for n in range(count)]
    for n in range(count):
        with (path.parent / f'nested/{n:03}.bin').open('wb') as stream:
            stream.truncate(1 if boundary == 'files' else 32*1024*1024+(1 if boundary == 'sum-overflow' else 0))
    save(capture)
    if boundary == 'sum-overflow':
        before, artifacts = state(case[0]), files(case[1])
        with pytest.raises(api().AcquisitionError): seal(capture)
        assert state(case[0]) == before and files(case[1]) == artifacts
    else:
        result = seal(capture)
        assert result.file_count == count
        assert result.byte_count == (256 if boundary == 'files' else 67108864)
        assert len(list((pathlib.Path(result.manifest_path).parent / 'evidence').iterdir())) == count


@pytest.mark.parametrize('moment', ['open', 'after-read', 'replace-after-read'])
def test_source_identity_and_bytes_are_stable_across_descriptor_read(capture, monkeypatch, moment):
    from audit_core import firmware_dive
    case, path, _ = capture
    evidence = path.parent / 'uart.txt'
    before = state(case[0])
    attacked = False
    real_open, real_fstat = firmware_dive.os.open, firmware_dive.os.fstat
    def opened(name, flags, *args, **kwargs):
        nonlocal attacked
        descriptor = real_open(name, flags, *args, **kwargs)
        if moment == 'open' and name == 'uart.txt' and not attacked:
            attacked = True
            evidence.write_bytes(b'changed after open')
        return descriptor
    def inspected(descriptor):
        nonlocal attacked
        value = real_fstat(descriptor)
        if moment != 'open' and not attacked and value.st_ino == evidence.stat().st_ino:
            inspected.count += 1
            if inspected.count == 2:
                attacked = True
                if moment == 'replace-after-read':
                    evidence.rename(evidence.with_name('original'))
                    evidence.write_bytes(b'UART observation\n')
                else: evidence.write_bytes(b'changed after read')
        return value
    inspected.count = 0
    monkeypatch.setattr(firmware_dive.os, 'open', opened)
    monkeypatch.setattr(firmware_dive.os, 'fstat', inspected)
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert attacked and state(case[0]) == before and not case[0].in_transaction
    assert not (case[1] / 'artifacts/firmware-dive-captures').exists()


@pytest.mark.parametrize('phase', ['parent-create', 'temp-create', 'file-open', 'rename', 'cleanup'])
def test_capture_installer_stays_anchored_when_parent_path_is_replaced(capture, monkeypatch, tmp_path, phase):
    from audit_core import firmware_dive
    case, _, _ = capture
    parent = case[1] / 'artifacts/firmware-dive-captures'
    retained = case[1] / 'retained-captures'
    outside = tmp_path / 'outside'
    outside.mkdir()
    before = state(case[0])
    attacked = False
    def redirect():
        nonlocal attacked
        attacked = True
        parent.rename(retained)
        parent.symlink_to(outside, target_is_directory=True)
    real_open, real_mkdir, real_rename = firmware_dive.os.open, firmware_dive.os.mkdir, firmware_dive.os.rename
    def mkdir(name, *args, **kwargs):
        if not attacked and phase == 'temp-create' and str(name).startswith('.dive-'): redirect()
        result = real_mkdir(name, *args, **kwargs)
        if not attacked and phase == 'parent-create' and name == 'firmware-dive-captures': redirect()
        return result
    def opened(name, flags, *args, **kwargs):
        if not attacked and phase == 'file-open' and flags & os.O_WRONLY: redirect()
        return real_open(name, flags, *args, **kwargs)
    def rename(name, destination, **kwargs):
        if not attacked and phase in ('rename','cleanup') and str(name).startswith('.dive-'):
            redirect()
            if phase == 'cleanup':
                decoy = outside / name
                decoy.mkdir()
                (decoy / 'sentinel').write_bytes(b'outside-owned')
                raise OSError('injected rename failure')
        return real_rename(name, destination, **kwargs)
    monkeypatch.setattr(firmware_dive.os,'mkdir',mkdir)
    monkeypatch.setattr(firmware_dive.os,'open',opened)
    monkeypatch.setattr(firmware_dive.os,'rename',rename)
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert attacked and state(case[0]) == before and not case[0].in_transaction
    assert not list(retained.glob('.dive-*'))
    if phase == 'cleanup':
        assert [p.read_bytes() for p in outside.glob('*/sentinel')] == [b'outside-owned']
        assert not list(retained.iterdir())
    else: assert not list(outside.iterdir())


@pytest.mark.parametrize('component', ['run', 'artifacts', 'firmware-dive-captures', 'capture', 'evidence'])
def test_each_existing_artifact_directory_component_refuses_symlinks(capture, tmp_path, component):
    result = seal(capture)
    case = capture[0]
    destination = pathlib.Path(result.manifest_path).parent
    path = {'run':case[1], 'artifacts':case[1]/'artifacts',
        'firmware-dive-captures':destination.parent,'capture':destination,'evidence':destination/'evidence'}[component]
    retained = tmp_path / 'retained'
    path.rename(retained)
    path.symlink_to(retained, target_is_directory=True)
    before, artifacts = state(case[0]), files(retained)
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(retained) == artifacts


def test_one_capture_id_cannot_be_owned_by_a_foreign_image(capture):
    seal(capture)
    con = capture[0][0]
    first, = rows(con,'cba_firmware_dive_acquisitions')
    db.put(con,'cba_firmware_dive_acquisitions',first | dict(image_id='foreign'))
    before = state(con)
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(con) == before


def test_static_question_cannot_gain_hardware_authority_from_spec(capture):
    case, _, value = capture
    question = next(r for r in rows(case[0], 'cba_firmware_dive_questions') if r['method'] == 'static')
    packet = json.loads((case[1]/question['packet_path']).read_bytes())
    value.update(question_id=question['question_id'],packet_sha256=question['packet_sha256'],
        contract_sha256=sha(canonical(packet['acquisition_contract'])))
    save(capture)
    before, artifacts = state(case[0]), files(case[1])
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(case[1]) == artifacts


@pytest.mark.parametrize('field', ['device_identifier','firmware_version','firmware_sha256','lifecycle','posture','authentication','operator','source'])
def test_each_recorded_hardware_fact_changes_identity_without_widening_question(capture, field):
    first = seal(capture)
    case, _, value = capture
    value[field] = {'firmware_sha256':'e'*64,'lifecycle':'post-reset','posture':'BLE','authentication':'admin'}.get(field,'another recorded fact')
    save(capture)
    second = seal(capture)
    assert first.acquisition_id != second.acquisition_id
    assert first.question_id == second.question_id and first.dive_generation == second.dive_generation
    assert len(rows(case[0],'cba_firmware_dive_acquisitions')) == 2
    assert rows(case[0],'cba_firmware_dive_receipts') == rows(case[0],'cba_firmware_dive_observations') == []


def test_unicode_and_punctuation_names_preserve_capture_order_and_canonical_sql_paths(capture):
    case, _, value = capture
    names = ['"a.txt', 'A.txt', '雪.txt']
    value['evidence'] = [dict(name=name,source_path='uart.txt') for name in names]
    save(capture)
    result = seal(capture)
    directory = pathlib.Path(result.manifest_path).parent
    assert json.loads((directory/'spec.json').read_bytes())['evidence'] == names
    assert [r['name'] for r in json.loads((directory/'manifest.json').read_bytes())['evidence']] == names
    stored, = rows(case[0],'cba_firmware_dive_acquisitions')
    paths = [(directory/'evidence'/name).relative_to(case[1]).as_posix() for name in names]
    assert stored['evidence_paths'] == canonical(sorted(paths,key=canonical)).decode()
    assert all((directory/'evidence'/name).read_bytes() == b'UART observation\n' for name in names)


@pytest.mark.parametrize('image', ['target\n', '路由器|r1|雪:%_\n"'])
def test_upstream_scalar_image_identity_preserves_delimiters_and_escaped_controls(capture, image):
    case, path, value = capture
    value['image_id'] = image
    save(capture)
    assert api().load_capture_spec(path).image_id == image
    before, artifacts = state(case[0]), files(case[1])
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(case[1]) == artifacts


@pytest.mark.parametrize('image', ['target\x00', 'x'*4097, ' ', '\ud800', 7])
def test_image_identity_remains_bounded_nonempty_utf8_and_never_contains_nul(capture, image):
    case, path, value = capture
    value['image_id'] = image
    path.write_text(json.dumps(value))
    before, artifacts = state(case[0]), files(case[1])
    with pytest.raises(api().AcquisitionError): api().load_capture_spec(path)
    with pytest.raises(api().AcquisitionError): seal(capture)
    assert state(case[0]) == before and files(case[1]) == artifacts


@pytest.mark.parametrize('operation', ['load', 'seal', 'prepare'])
def test_explicit_selectors_use_absolute_lexical_targets_without_changing_identity(capture, monkeypatch, operation):
    case, path, _ = capture
    con, run, root = case[:3]
    first = seal(capture)
    first_preparation = prepare(case)
    before, changes, artifacts = state(con), con.total_changes, files(run)
    monkeypatch.chdir(path.parent)
    selected_spec = pathlib.Path('absent/../capture.json')
    selected_run = pathlib.Path(os.path.relpath(run, path.parent)) / 'absent/..'
    if operation == 'load':
        assert api().load_capture_spec(selected_spec) == api().load_capture_spec(path)
    elif operation == 'seal':
        assert api().seal_capture(con, selected_run, root, selected_spec) == first
    else:
        from audit_core import firmware_dive
        assert firmware_dive.prepare(con, selected_run, root, image_id='target') == first_preparation
    assert state(con) == before and con.total_changes == changes and files(run) == artifacts
