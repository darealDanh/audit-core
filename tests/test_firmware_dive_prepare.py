"""Immutable denominators and artifact-first, append-only dive preparation."""
import dataclasses
import hashlib
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, firmware_chain, surface
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_chain_import import rows, record
from tests.test_firmware_chain_prepare import files, empty_review
from tests.test_firmware_dive_snapshot import complete, snapshot
from tests.test_firmware_chain_gate import check
from tests.test_firmware_dive_questions import entry
from tests.test_hunt_gate import state


def api():
    from audit_core import firmware_dive
    return firmware_dive


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare(case, **kwargs):
    return api().prepare(*case[:3], image_id='target', **kwargs)


def manifest(tmp_path, entries):
    path = tmp_path / 'analyst.json'
    path.write_bytes(canonical(dict(schema_version=1, questions=sorted(entries, key=canonical))))
    return path


def test_current_graph_is_required_without_writing_gate_or_retained_fallback(graph_case, monkeypatch):
    dive = api()
    record(graph_case)
    before, artifacts = state(graph_case[0]), files(graph_case[1])
    monkeypatch.setattr(firmware_chain, 'check', lambda *a, **k: pytest.fail('prepare called writing gate'))
    with pytest.raises(dive.FirmwareDiveError):
        prepare(graph_case)
    assert state(graph_case[0]) == before and files(graph_case[1]) == artifacts


def test_literal_canonical_empty_index_generation_and_unicode_image(graph_case, tmp_path):
    con, run = graph_case[:2]
    image = '路由器|r1|雪:%_\n"'
    root = tmp_path / 'empty-root'
    empty_review(con, run, root, image)
    chain = firmware_chain.prepare(con, run, root, image_id=image)
    case = (con, run, root, dict(schema_version=1, image_id=image,
        candidate_snapshot_sha256=chain.candidate_snapshot_sha256, worklist_sha256=chain.worklist_sha256,
        blockers=[], dispositions=[], chains=[]), {})
    record(case)
    check(case, image_id=image)
    graph = firmware_chain.verified_graph_snapshot(con, run, root, image_id=image)
    result = api().prepare(con, run, root, image_id=image)
    analyst = {'questions': [], 'schema_version': 1}
    graph_projection = {key:getattr(graph, key) for key in ('image_id', 'manifest_sha256',
        'surface_snapshot_sha256', 'candidate_snapshot_sha256', 'chain_worklist_sha256', 'graph_path', 'graph_sha256')}
    generation_projection = dict(schema_version=1, graph=graph_projection,
        analyst_manifest=analyst, input_overlay=[], retry_projection=[], questions=[])
    generation = sha(canonical(generation_projection))
    assert result.dive_generation == generation
    assert result.analyst_manifest_sha256 == sha(b'{"questions":[],"schema_version":1}')
    directory = run / 'files/firmware-dive' / generation
    journal = dict(schema_version=1, image_id=image, candidate_snapshot_sha256=graph.candidate_snapshot_sha256,
        finding_artifacts=[], observations=[])
    assert (directory / 'journal-input.json').read_bytes() == canonical(journal)
    index = dict(schema_version=1, image_id=image, dive_generation=generation,
        graph_sha256=graph.graph_sha256, analyst_manifest=analyst,
        analyst_manifest_sha256=result.analyst_manifest_sha256,
        journal_input_sha256=sha(canonical(journal)), questions=[],
        graph_projection=graph_projection, input_overlay=[], retry_projection=[])
    assert (directory / 'index.json').read_bytes() == canonical(index)
    assert sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()) == ['index.json', 'journal-input.json']
    assert result.question_count == 0 and rows(con, 'cba_firmware_dive_questions') == []
    stored, = rows(con, 'cba_firmware_dive_runs', image)
    assert stored['status'] == 'pending' and stored['question_count'] == 0
    assert stored['analyst_manifest_path'] == (directory / 'index.json').relative_to(run).as_posix()
    assert rows(con, 'cba_firmware_dive_receipts') == []


def test_complete_packets_idempotence_and_no_stage4g_invalidation(graph_case, monkeypatch):
    con, run = graph_case[:2]
    complete(graph_case)
    monkeypatch.setattr(firmware_chain, 'invalidate', lambda *a, **k: pytest.fail('prepare invalidated graph'))
    result = prepare(graph_case)
    assert (result.question_count, result.chain_blocker_count, result.surface_unknown_count,
        result.analyst_question_count, result.retry_count, result.conflict_count) == (3, 1, 2, 0, 0, 0)
    stored = rows(con, 'cba_firmware_dive_questions')
    assert [r['ordinal'] for r in stored] == [0, 1, 2]
    assert [r['question_id'] for r in stored] == sorted(r['question_id'] for r in stored)
    for row in stored:
        raw = (run / row['packet_path']).read_bytes()
        packet = json.loads(raw)
        assert sha(raw) == row['packet_sha256']
        assert packet['question']['question_id'] == row['question_id']
        assert str(graph_case[2]).encode() not in raw
        assert all(f.data_flow.encode() not in raw for f in snapshot(graph_case).findings)
    before, writes, artifacts = state(con), con.total_changes, files(run)
    con.execute('PRAGMA reverse_unordered_selects=ON')
    assert prepare(graph_case) == result
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


def test_manifest_scale_and_older_generation_survive(graph_case, tmp_path):
    con, run = graph_case[:2]
    complete(graph_case)
    old = prepare(graph_case)
    artifacts = files(run)
    graph = snapshot(graph_case)
    path = manifest(tmp_path, [entry(graph) | {'question': f'Question {i:03}'} for i in range(205)])
    result = prepare(graph_case, questions_path=path)
    assert result.question_count == 208 and result.analyst_question_count == 205
    assert result.dive_generation != old.dive_generation
    assert len(rows(con, 'cba_firmware_dive_runs')) == 2
    index = json.loads(pathlib.Path(result.question_index_path).read_bytes())
    assert len(index['questions']) == 208
    assert all(files(run)[name] == raw for name, raw in artifacts.items())
    before, writes, artifacts = state(con), con.total_changes, files(run)
    path.write_bytes(b'{"questions":[],"schema_version":1}')
    assert prepare(graph_case, questions_path=path) == old
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts


@pytest.mark.parametrize('damage', ['extra', 'index', 'journal', 'packet', 'symlink-file', 'symlink-questions', 'symlink-generation', 'parent-file', 'parent-symlink'])
def test_existing_artifact_drift_is_never_repaired(graph_case, tmp_path, damage):
    con, run = graph_case[:2]
    complete(graph_case)
    result = prepare(graph_case)
    directory = pathlib.Path(result.question_index_path).parent
    if damage == 'extra': (directory / 'extra').write_bytes(b'extra')
    elif damage in ('index', 'journal', 'packet'):
        name = {'index':directory / 'index.json', 'journal':directory / 'journal-input.json',
            'packet':next((directory / 'questions').iterdir())}[damage]
        name.write_bytes(b'{}')
    elif damage == 'symlink-file':
        name = directory / 'index.json'
        outside = tmp_path / 'index.json'
        name.rename(outside)
        name.symlink_to(outside)
    elif damage == 'symlink-questions':
        name = directory / 'questions'
        outside = tmp_path / 'questions'
        name.rename(outside)
        name.symlink_to(outside, target_is_directory=True)
    else:
        name = directory if damage == 'symlink-generation' else directory.parent
        outside = tmp_path / 'moved'
        name.rename(outside)
        if damage == 'parent-file': name.write_bytes(b'blocked')
        else: name.symlink_to(outside, target_is_directory=True)
    before, artifacts = state(con), files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


def test_active_transaction_is_preserved(graph_case):
    con = graph_case[0]
    con.execute('BEGIN')
    before, artifacts = state(con), files(graph_case[1])
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert con.in_transaction and state(con) == before and files(graph_case[1]) == artifacts
    con.rollback()


@pytest.mark.parametrize('damage', ['root', 'manifest', 'history', 'installed'])
def test_post_install_mutable_inputs_are_rechecked(graph_case, tmp_path, monkeypatch, damage):
    con, run, root = graph_case[:3]
    complete(graph_case)
    path = manifest(tmp_path, [entry(snapshot(graph_case))])
    before = state(con)
    dive = api()
    real = dive._install
    def race(*args, **kwargs):
        real(*args, **kwargs)
        if damage == 'root': (root / 'c').write_bytes(b'drift\n')
        elif damage == 'manifest': path.write_bytes(b'{"questions":[],"schema_version":1}')
        elif damage == 'history':
            con.execute("UPDATE cba_firmware_dive_runs SET prepared_at='changed'")
            con.commit()
        else: (args[0] / 'index.json').write_bytes(b'{}')
    if damage == 'history': prepare(graph_case)
    before = state(con)
    monkeypatch.setattr(dive, '_install', race)
    with pytest.raises(dive.FirmwareDiveError): prepare(graph_case, questions_path=path)
    if damage != 'history': assert state(con) == before
    assert not con.in_transaction
    assert rows(con, 'cba_firmware_chain_runs')[0]['status'] == 'complete'


@pytest.mark.parametrize('fail_at', ['run', 'question', 'commit', 'unexpected'])
def test_publication_failure_preserves_prior_sql(graph_case, tmp_path, monkeypatch, fail_at):
    con, run = graph_case[:2]
    complete(graph_case)
    prepare(graph_case)
    path = manifest(tmp_path, [entry(snapshot(graph_case))])
    before = state(con)
    dive = api()
    real = db.put
    if fail_at in ('run', 'question', 'unexpected'):
        def fail(connection, table, row, **kwargs):
            if table == ('cba_firmware_dive_runs' if fail_at == 'run' else 'cba_firmware_dive_questions'):
                raise RuntimeError('unexpected') if fail_at == 'unexpected' else sqlite3.OperationalError('injected')
            return real(connection, table, row, **kwargs)
        monkeypatch.setattr(db, 'put', fail)
        connection = con
    else:
        class Connection(sqlite3.Connection):
            def commit(self): raise sqlite3.OperationalError('injected')
        connection = sqlite3.connect(run / 'audit.db', factory=Connection)
        connection.row_factory = sqlite3.Row
    with pytest.raises(RuntimeError if fail_at == 'unexpected' else dive.FirmwareDiveError):
        dive.prepare(connection, run, graph_case[2], image_id='target', questions_path=path)
    assert state(con) == before and not connection.in_transaction
    if connection is not con: connection.close()


def test_two_connection_write_contention_preserves_prior_sql(graph_case, tmp_path):
    con, run = graph_case[:2]
    complete(graph_case)
    prepare(graph_case)
    before = state(con)
    with sqlite3.connect(run / 'audit.db', timeout=0) as reader:
        reader.row_factory = sqlite3.Row
        con.execute('BEGIN IMMEDIATE')
        with pytest.raises(api().FirmwareDiveError, match='database operation failed'):
            api().prepare(reader, run, graph_case[2], image_id='target')
        assert not reader.in_transaction and state(con) == before and con.in_transaction
        con.rollback()


def accepted(case, summary, *, value='admin', outcome='supported', identity='1' * 64, question_id=None, _fill=True):
    """Future importer boundary: coherent SQL plus exact opaque artifact bytes."""
    from tests.test_firmware_dive_schema import RECEIPT, OBSERVATION
    con, run = case[:2]
    question = next(r for r in rows(con, 'cba_firmware_dive_questions')
        if r['dive_generation'] == summary.dive_generation and
        (r['question_id'] == question_id if question_id else r['origin'] == 'surface-unknown' and 'overlap' in r['subject_refs']))
    packet = json.loads((run / question['packet_path']).read_bytes())
    refs = [r for r in packet['allowed_dependencies'] if r['kind'] == 'finding-artifact']
    if not refs:
        refs = [r for r in packet['allowed_dependencies'] if r['kind'] == 'surface-artifact']
    ref = refs[0]
    content = (run / ref['relative_path']).read_bytes()
    projection = ref | {'byte_count': len(content), 'source_provenance': {}}
    dep_id = sha(canonical(projection))
    result = b'opaque verified future result bytes ' + identity.encode()
    artifact = run / 'artifacts/test-dive' / identity / 'result.json'
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(result)
    relative = artifact.relative_to(run).as_posix()
    owner = dict(image_id='target', dive_generation=summary.dive_generation, question_id=question['question_id'])
    obs = OBSERVATION | owner | dict(attempt_ordinal=question['attempt_ordinal'], observation_id=identity,
        outcome=outcome, conclusion='Measured authority', limitations='Fixture scope only',
        resolution_effect=None if outcome == 'inconclusive' else canonical({'value':value}).decode(),
        evidence_rung=None if outcome == 'inconclusive' else 'static-resolved',
        dependency_refs=canonical([dep_id]).decode(), evidence_refs=canonical(['e' * 64]).decode(),
        artifact_path=relative, artifact_sha256=sha(result))
    db.put(con, 'cba_firmware_dive_observations', obs)
    db.put(con, 'cba_firmware_dive_receipts', RECEIPT | owner | dict(
        receipt_key='firmware-dive-receipt-' + identity, attempt_ordinal=question['attempt_ordinal'],
        packet_sha256=question['packet_sha256'], result_path=relative, result_sha256=sha(result),
        outcome=outcome, dependency_count=1, evidence_count=1, successor_count=0))
    db.put(con, 'cba_firmware_dive_dependencies', owner | dict(ordinal=0, observation_id=identity,
        **ref, byte_count=len(content), source_provenance='{}'))
    journal = run / 'artifacts/test-dive' / summary.dive_generation / 'journal.json'
    journal.parent.mkdir(parents=True, exist_ok=True)
    journal.write_bytes(b'opaque accepted journal')
    con.execute("UPDATE cba_firmware_dive_runs SET status='complete',journal_path=?,journal_sha256=?,completed_at='2026-01-02 03:04:05',supported_count=?,inconclusive_count=? WHERE image_id=? AND dive_generation=?",
        (journal.relative_to(run).as_posix(), sha(journal.read_bytes()), int(outcome == 'supported'),
        int(outcome == 'inconclusive'), 'target', summary.dive_generation))
    con.commit()
    if _fill:
        present = {r['question_id'] for r in rows(con, 'cba_firmware_dive_observations') if r['dive_generation'] == summary.dive_generation}
        for row in rows(con, 'cba_firmware_dive_questions'):
            if row['dive_generation'] == summary.dive_generation and row['question_id'] not in present:
                accepted(case, summary, outcome='inconclusive',
                    identity=sha(canonical([row['question_id'], row['attempt_ordinal']])),
                    question_id=row['question_id'], _fill=False)
        values = [r for r in rows(con, 'cba_firmware_dive_observations') if r['dive_generation'] == summary.dive_generation]
        con.execute('UPDATE cba_firmware_dive_runs SET supported_count=?,refuted_count=?,inconclusive_count=? WHERE dive_generation=?',
            (*(sum(r['outcome'] == outcome for r in values) for outcome in ('supported','refuted','inconclusive')), summary.dive_generation))
        con.commit()
    return question, obs


def test_retry_uses_durable_attempts_and_preserves_older_generations(graph_case):
    con, run = graph_case[:2]
    complete(graph_case)
    first = prepare(graph_case)
    question, obs = accepted(graph_case, first, outcome='inconclusive')
    older = state(con)
    result = prepare(graph_case, retry=(question['question_id'] + ':' + obs['observation_id'],))
    assert result.dive_generation != first.dive_generation and result.retry_count == 1
    row = next(r for r in rows(con, 'cba_firmware_dive_questions') if r['dive_generation'] == result.dive_generation and r['question_id'] == question['question_id'])
    assert row['attempt_ordinal'] == 2 and row['prior_observation_id'] == obs['observation_id']
    for table, previous in older.items():
        if table.startswith('cba_firmware_dive'):
            assert all(r in state(con)[table] for r in previous)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case, retry=('0' * 64,))


def canonical_accepted(case, summary, *, value='admin', outcome='supported', question_id=None):
    """Current preparation fixtures require independently reconstructible canonical results."""
    from tests.test_firmware_dive_import import build, record as dive_record, save
    con,run=case[:2]
    assigned=[r for r in rows(con,'cba_firmware_dive_questions') if r['dive_generation']==summary.dive_generation]
    question=next(r for r in assigned if r['question_id']==question_id) if question_id else next(
        r for r in assigned if r['origin']=='surface-unknown' and 'overlap' in r['subject_refs'])
    for n,row in enumerate(assigned):
        directory=run/'scratch-canonical-history'/summary.dive_generation/str(n);directory.mkdir(parents=True,exist_ok=True)
        selected=row['question_id']==question['question_id']
        item=build(case,row,directory,outcome=outcome if selected else 'inconclusive')
        if selected and outcome!='inconclusive':
            item[2]['questions'][0]['resolution_effect']['value']=value
            save(item)
        dive_record(item)
    journal=run/'artifacts/test-dive'/summary.dive_generation/'journal.json'
    journal.parent.mkdir(parents=True,exist_ok=True);journal.write_bytes(b'preparation fixture journal')
    values=[r for r in rows(con,'cba_firmware_dive_observations') if r['dive_generation']==summary.dive_generation]
    con.execute("UPDATE cba_firmware_dive_runs SET status='complete',journal_path=?,journal_sha256=?,completed_at='2026-01-02 03:04:05',supported_count=?,refuted_count=?,inconclusive_count=? WHERE dive_generation=?",
        (journal.relative_to(run).as_posix(),sha(journal.read_bytes()),*(sum(r['outcome']==name for r in values) for name in ('supported','refuted','inconclusive')),summary.dive_generation))
    con.commit()
    return question,next(r for r in values if r['question_id']==question['question_id'])


def contested(case):
    first = prepare(case)
    question, one = canonical_accepted(case, first)
    second = prepare(case, retry=(question['question_id'],))
    _, two = canonical_accepted(case, second, value='pre-auth', question_id=question['question_id'])
    firmware_chain.invalidate(case[0], 'target', commit=True)
    return first, second, question, one, two


def test_conflict_only_after_invalidation_and_exact_inconclusive_retry(graph_case):
    complete(graph_case)
    first, second, question, one, two = contested(graph_case)
    result = prepare(graph_case)
    assert result.question_count == result.conflict_count == 1
    before,writes,artifacts=state(graph_case[0]),graph_case[0].total_changes,files(graph_case[1])
    assert prepare(graph_case)==result
    assert state(graph_case[0])==before and graph_case[0].total_changes==writes and files(graph_case[1])==artifacts
    row = next(r for r in rows(graph_case[0], 'cba_firmware_dive_questions') if r['dive_generation'] == result.dive_generation)
    assert json.loads(row['supersedes_observation_ids']) == sorted([one['observation_id'], two['observation_id']])
    accepted(graph_case, result, outcome='inconclusive', identity='3' * 64, question_id=row['question_id'])
    retry = prepare(graph_case, retry=(row['question_id'],))
    assert retry.question_count == retry.conflict_count == retry.retry_count == 1
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case, retry=(question['question_id'],))


def test_conflict_retry_ignores_older_owner_without_later_linked_subject(graph_case):
    con, run, root = graph_case[:3]
    complete(graph_case)
    graph_case[3]['chains'][0]['edges'][1]['existing_unknowns'] = []
    record(graph_case, replace=True)
    check(graph_case)
    older = prepare(graph_case)
    old_question = next(r for r in rows(con, 'cba_firmware_dive_questions')
        if r['dive_generation'] == older.dive_generation and r['origin'] == 'chain-blocker')
    canonical_accepted(graph_case, older, outcome='inconclusive', question_id=old_question['question_id'])
    firmware_chain.invalidate(con, 'target', commit=True)
    prepared = firmware_chain.prepare(con, run, root, image_id='target')
    graph_case[3]['worklist_sha256'] = prepared.worklist_sha256
    graph_case[3]['chains'][0]['edges'][1]['existing_unknowns'] = [
        dict(unknown_id='overlap', axes=['authentication'])]
    record(graph_case)
    check(graph_case)
    first, second, question, one, two = contested(graph_case)
    conflict = prepare(graph_case)
    row = next(r for r in rows(con, 'cba_firmware_dive_questions')
        if r['dive_generation'] == conflict.dive_generation)
    accepted(graph_case, conflict, outcome='inconclusive', identity='3' * 64,
        question_id=row['question_id'])
    retried = prepare(graph_case, retry=(row['question_id'] + ':' + '3' * 64,))
    assert retried.question_count == retried.conflict_count == retried.retry_count == 1
    packet = json.loads(next((pathlib.Path(retried.question_index_path).parent / 'questions').iterdir()).read_bytes())
    assert packet['question']['attempt_ordinal'] == 2
    assert packet['question']['supersedes_observation_ids'] == sorted([one['observation_id'], two['observation_id']])
    assert retried.graph_sha256 == second.graph_sha256 != older.graph_sha256


@pytest.mark.parametrize('phase', ['parent-create', 'temp-create'])
def test_install_parent_replacement_never_writes_outside_run(graph_case, tmp_path, monkeypatch, phase):
    con, run = graph_case[:2]
    complete(graph_case)
    dive = api()
    outside = tmp_path / 'external'
    outside.mkdir()
    parent = run / 'files/firmware-dive'
    real_mkdir = dive.os.mkdir
    attacked = False
    def mkdir(path, *args, **kwargs):
        nonlocal attacked
        name = pathlib.Path(path).name
        if not attacked and phase == 'temp-create' and name.startswith('.dive-'):
            attacked = True
            parent.rename(run / 'retained-parent')
            parent.symlink_to(outside, target_is_directory=True)
        result = real_mkdir(path, *args, **kwargs)
        if not attacked and phase == 'parent-create' and name == 'firmware-dive':
            attacked = True
            parent.rename(run / 'retained-parent')
            parent.symlink_to(outside, target_is_directory=True)
        return result
    monkeypatch.setattr(dive.os, 'mkdir', mkdir)
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError): prepare(graph_case)
    assert attacked and not list(outside.iterdir())
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize('phase', ['file-open', 'rename', 'cleanup'])
def test_open_parent_anchor_survives_late_replacement(graph_case, tmp_path, monkeypatch, phase):
    con, run = graph_case[:2]
    complete(graph_case)
    dive = api()
    outside = tmp_path / 'external'
    outside.mkdir()
    parent = run / 'files/firmware-dive'
    retained = run / 'retained-parent'
    attacked = False
    def redirect():
        nonlocal attacked
        attacked = True
        parent.rename(retained)
        parent.symlink_to(outside, target_is_directory=True)
    real_open, real_rename = dive.os.open, dive.os.rename
    def opened(path, flags, *args, **kwargs):
        if not attacked and phase == 'file-open' and flags & dive.os.O_WRONLY:
            redirect()
        return real_open(path, flags, *args, **kwargs)
    def renamed(source, destination, *args, **kwargs):
        if not attacked and phase in ('rename', 'cleanup') and pathlib.Path(source).name.startswith('.dive-'):
            redirect()
            if phase == 'cleanup':
                decoy = outside / pathlib.Path(source).name
                decoy.mkdir()
                (decoy / 'sentinel').write_bytes(b'external-owned')
                raise OSError('injected publication failure after redirect')
        return real_rename(source, destination, *args, **kwargs)
    monkeypatch.setattr(dive.os, 'open', opened)
    monkeypatch.setattr(dive.os, 'rename', renamed)
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError): prepare(graph_case)
    assert attacked and state(con) == before and not con.in_transaction
    assert not list(retained.glob('.dive-*'))
    if phase == 'cleanup':
        assert [p.read_bytes() for p in outside.glob('*/sentinel')] == [b'external-owned']
        assert not list(retained.iterdir())
    else:
        assert not list(outside.iterdir())
        generation, = retained.iterdir()
        assert {p.name for p in generation.iterdir()} == {'index.json', 'journal-input.json', 'questions'}


@pytest.mark.parametrize('damage', ['analyst', 'finding-provenance', 'root', 'missing-observation', 'repeat-prose', 'dependency', 'receipt', 'packet', 'journal'])
def test_conflict_only_rejects_foreign_incomplete_or_stale_history(graph_case, tmp_path, damage):
    con, run, root = graph_case[:3]
    complete(graph_case)
    graph = snapshot(graph_case)
    first, second, question, one, two = contested(graph_case)
    kwargs = {}
    if damage == 'analyst': kwargs['questions_path'] = manifest(tmp_path, [entry(graph)])
    elif damage == 'root': (root / 'c').write_bytes(b'drift\n')
    elif damage == 'missing-observation': con.execute('DELETE FROM cba_firmware_dive_observations WHERE observation_id=?', (two['observation_id'],))
    elif damage == 'repeat-prose': con.execute('UPDATE cba_firmware_dive_observations SET observation_id=?,limitations=? WHERE observation_id=?', (one['observation_id'], 'changed prose', two['observation_id']))
    elif damage == 'dependency': con.execute('UPDATE cba_firmware_dive_dependencies SET sha256=?', ('0' * 64,))
    elif damage == 'receipt': con.execute('UPDATE cba_firmware_dive_receipts SET dependency_count=9')
    elif damage == 'packet': (run / question['packet_path']).write_bytes(b'{}')
    elif damage == 'journal':
        owner = next(r for r in rows(con, 'cba_firmware_dive_runs') if r['dive_generation'] == first.dive_generation)
        (run / owner['journal_path']).write_bytes(b'changed')
    else:
        # The snapshot verifier can remain valid under administratively replaced
        # findings; exact journal-input provenance must independently refuse it.
        path = run / 'files/firmware-dive' / first.dive_generation / 'journal-input.json'
        body = json.loads(path.read_bytes())
        body['finding_artifacts'][0]['sha256'] = '0' * 64
        raw = canonical(body)
        path.write_bytes(raw)
        con.execute('UPDATE cba_firmware_dive_runs SET journal_input_sha256=? WHERE dive_generation=?', (sha(raw), first.dive_generation))
        index_path=path.with_name('index.json')
        index=json.loads(index_path.read_bytes())
        index['journal_input_sha256']=sha(raw)
        index_raw=canonical(index)
        index_path.write_bytes(index_raw)
        con.execute('UPDATE cba_firmware_dive_runs SET question_index_sha256=? WHERE dive_generation=?',(sha(index_raw),first.dive_generation))
    con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case, **kwargs)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


def test_later_inconclusive_history_reuses_frozen_generation_without_writes(graph_case):
    con, run = graph_case[:2]
    complete(graph_case)
    first = prepare(graph_case)
    accepted(graph_case, first, outcome='inconclusive')
    before, writes, artifacts = state(con), con.total_changes, files(run)
    assert prepare(graph_case) == first
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts


def test_static_dependency_must_be_authorized_by_exact_packet_subjects(graph_case):
    con = graph_case[0]
    complete(graph_case)
    first = prepare(graph_case)
    question, observation = accepted(graph_case, first)
    graph = snapshot(graph_case)
    # Valid current finding bytes are still unauthorized for this unknown-only
    # packet, which grants its own surface and chain references.
    finding = graph.findings[0]
    con.execute('UPDATE cba_firmware_dive_dependencies SET kind=?,logical_id=?,relative_path=?,sha256=?,byte_count=?',
        ('finding-artifact', finding.finding_id, finding.artifact_path, finding.artifact_sha256,
        len((graph_case[1] / finding.artifact_path).read_bytes())))
    con.commit()
    before, artifacts = state(con), files(graph_case[1])
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con) == before and files(graph_case[1]) == artifacts


def historical_extract(case):
    from audit_core import extract, firmware_dive_questions as questions
    con, run = case[:2]
    first = prepare(case)
    graph = snapshot(case)
    record = extract.ExtractStore(run).write('daemon', 'gate.c', b'bounded gate source', source='src/gate.c')
    directory = pathlib.Path(first.question_index_path).parent
    index = json.loads((directory / 'index.json').read_bytes())
    packets = [json.loads((run / r['packet_path']).read_bytes()) for r in index['questions']]
    packets[0]['question']['extract_records'] = [dataclasses.asdict(questions.extract_record(record))]
    exact_questions = [p['question'] for p in packets]
    projection = dict(schema_version=1, graph={k:getattr(graph,k) for k in ('image_id','manifest_sha256',
        'surface_snapshot_sha256','candidate_snapshot_sha256','chain_worklist_sha256','graph_path','graph_sha256')},
        analyst_manifest={'schema_version':1,'questions':[]}, input_overlay=[], retry_projection=[], questions=exact_questions)
    generation = sha(canonical(projection))
    destination = directory.with_name(generation)
    directory.rename(destination)
    for ordinal, packet in enumerate(packets):
        question = questions.DiveQuestion(**(packet['question'] | {
            'subject_refs':tuple(questions.SubjectRef(*s.split(':',1)) for s in packet['question']['subject_refs']),
            'axes':tuple(packet['question']['axes']),
            'resolution_contract':questions.ResolutionContract(**(packet['question']['resolution_contract'] | {
                'target_subject':questions.SubjectRef(*packet['question']['resolution_contract']['target_subject'].split(':',1)),
                'allowed_values':tuple(packet['question']['resolution_contract']['allowed_values'])})),
            'supersedes_observation_ids':tuple(packet['question']['supersedes_observation_ids']),
            'extract_records':tuple(questions.ExtractRecord(**r) for r in packet['question']['extract_records'])}))
        raw = questions.packet_bytes(question, graph)
        name = 'files/firmware-dive/' + generation + '/questions/' + question.question_id + '.json'
        (run / name).write_bytes(raw)
        con.execute('UPDATE cba_firmware_dive_questions SET dive_generation=?,packet_path=?,packet_sha256=? WHERE dive_generation=? AND question_id=?',
            (generation, name, sha(raw), first.dive_generation, question.question_id))
        index['questions'][ordinal].update(packet_path=name, packet_sha256=sha(raw))
    index['dive_generation'] = generation
    raw = canonical(index)
    (destination / 'index.json').write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_runs SET dive_generation=?,analyst_manifest_path=?,journal_input_path=?,question_index_path=?,question_index_sha256=? WHERE dive_generation=?',
        (generation, f'files/firmware-dive/{generation}/index.json', f'files/firmware-dive/{generation}/journal-input.json',
        f'files/firmware-dive/{generation}/index.json', sha(raw), first.dive_generation))
    con.commit()
    return generation


@pytest.mark.parametrize('damage', ['none','timestamp','source','absolute-source','bytes','symlink'])
def test_only_exact_historical_extract_records_are_retained_and_rechecked(graph_case, tmp_path, damage):
    con, run = graph_case[:2]
    complete(graph_case)
    generation = historical_extract(graph_case)
    path = run / 'extract/manifest.json'
    manifest = json.loads(path.read_bytes())
    if damage in ('source', 'absolute-source', 'timestamp'):
        key = 'extracted_at' if damage == 'timestamp' else 'source'
        manifest['daemon/gate.c'][key] = 'changed' if damage == 'timestamp' else '/absolute/source.c' if damage == 'absolute-source' else 'src/other.c'
        path.write_bytes(canonical(manifest))
    elif damage == 'bytes': (run / 'extract/daemon/gate.c').write_bytes(b'changed')
    elif damage == 'symlink':
        source = run / 'extract/daemon/gate.c'
        outside = tmp_path / 'outside.c'
        source.rename(outside)
        source.symlink_to(outside)
    before, writes, artifacts = state(con), con.total_changes, files(run)
    if damage in ('none', 'timestamp'):
        assert prepare(graph_case).dive_generation == generation
        assert con.total_changes == writes
    else:
        with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con) == before and files(run) == artifacts


def test_literal_nonempty_packet_and_reversed_sql_insertion(graph_case):
    con, run = graph_case[:2]
    complete(graph_case)
    graph = snapshot(graph_case)
    result = prepare(graph_case)
    unknown = next(u for u in graph.unknowns if u.id == 'overlap')
    projection = dict(image_id='target', candidate_snapshot_sha256=graph.candidate_snapshot_sha256,
        subject_refs=['surface-unknown:overlap'], method=unknown.method, question=unknown.question,
        settling_observation=unknown.settling_observation, axes=['authentication'])
    identity = sha(canonical(projection))
    contract = dict(target_subject='surface-unknown:overlap', mode='value-discovery', predicate='state-value',
        axis='authentication', expected_value=None, allowed_values=['admin','local-shell','physical-UART','pre-auth','session'],
        other_specific=False, capability_kind=None, link_key=None, transition_kind=None)
    question = dict(question_id=identity, origin='surface-unknown', subject_refs=['surface-unknown:overlap'],
        method=unknown.method, question=unknown.question, settling_observation=unknown.settling_observation,
        axes=['authentication'], resolution_contract=contract, attempt_ordinal=1, prior_observation_id=None,
        supersedes_observation_ids=[], extract_records=[])
    upstream_surface = next(s for s in graph.surfaces if s.surface_id == unknown.surface_id)
    refs = [dict(kind='chain-artifact', logical_id=graph.graph_sha256, relative_path=graph.graph_path, sha256=graph.graph_sha256),
        dict(kind='surface-artifact', logical_id=unknown.id, relative_path=unknown.artifact_path, sha256=unknown.artifact_sha256),
        dict(kind='surface-artifact', logical_id=upstream_surface.surface_id, relative_path=upstream_surface.artifact_path, sha256=upstream_surface.artifact_sha256)]
    refs.sort(key=lambda r:(r['kind'],r['logical_id'],r['relative_path'],r['sha256']))
    acquisition = dict(image_id='target', candidate_snapshot_sha256=graph.candidate_snapshot_sha256,
        question_id=identity, attempt_ordinal=1, subject_refs=['surface-unknown:overlap'], method=unknown.method,
        artifact_kinds=[], acquisition_class=None, network='none', max_timeout_seconds=300,
        max_stdout_bytes=1048576, max_stderr_bytes=1048576, max_output_bytes=8388608, max_files=256,
        max_capture_bytes=67108864)
    expected = dict(schema_version=1, image_id='target', candidate_snapshot_sha256=graph.candidate_snapshot_sha256,
        question=question, retained_refs=refs, evidence_refs=['unknown:overlap#evidence'],
        allowed_dependencies=refs, extract_records=[], journal_index=[], acquisition_contract=acquisition)
    stored = next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id'] == identity)
    assert (run / stored['packet_path']).read_bytes() == canonical(expected)
    assert stored['packet_sha256'] == sha(canonical(expected))
    prior = rows(con,'cba_firmware_dive_questions')
    con.execute('DELETE FROM cba_firmware_dive_questions')
    for row in reversed(prior): db.put(con,'cba_firmware_dive_questions',row,commit=False)
    con.commit()
    before, writes, artifacts = state(con), con.total_changes, files(run)
    assert prepare(graph_case) == result
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts


@pytest.mark.parametrize('damage', ['orphan-question','orphan-observation','missing-receipt','no-timestamp',
    'receipt-hash','observation-attempt','dependency-owner','dependency-ordinal','duplicate-dependency',
    'index-question','question-count','analyst-digest','result-hash','noncanonical-journal','special-result','oversize-result'])
def test_history_corruption_refuses_without_publication(graph_case, damage):
    con, run = graph_case[:2]
    complete(graph_case)
    first = prepare(graph_case)
    question, observation = accepted(graph_case, first)
    if damage == 'orphan-question': con.execute('UPDATE cba_firmware_dive_questions SET dive_generation=?', ('0'*64,))
    elif damage == 'orphan-observation': con.execute('UPDATE cba_firmware_dive_observations SET question_id=? WHERE question_id=?', ('0'*64,question['question_id']))
    elif damage == 'missing-receipt': con.execute('DELETE FROM cba_firmware_dive_receipts')
    elif damage == 'no-timestamp': con.execute('UPDATE cba_firmware_dive_observations SET recorded_at=NULL')
    elif damage == 'receipt-hash': con.execute('UPDATE cba_firmware_dive_receipts SET packet_sha256=?', ('0'*64,))
    elif damage == 'observation-attempt': con.execute('UPDATE cba_firmware_dive_observations SET attempt_ordinal=9')
    elif damage == 'dependency-owner': con.execute('UPDATE cba_firmware_dive_dependencies SET observation_id=?', ('0'*64,))
    elif damage == 'dependency-ordinal': con.execute('UPDATE cba_firmware_dive_dependencies SET ordinal=9')
    elif damage == 'duplicate-dependency':
        dep = rows(con,'cba_firmware_dive_dependencies')[0]
        db.put(con,'cba_firmware_dive_dependencies',dep | {'ordinal':1})
    elif damage == 'index-question': con.execute("UPDATE cba_firmware_dive_questions SET question='changed'")
    elif damage == 'question-count': con.execute('UPDATE cba_firmware_dive_runs SET question_count=9')
    elif damage == 'analyst-digest': con.execute('UPDATE cba_firmware_dive_runs SET analyst_manifest_sha256=?', ('0'*64,))
    elif damage == 'result-hash': (run / observation['artifact_path']).write_bytes(b'changed')
    elif damage == 'noncanonical-journal':
        path = pathlib.Path(first.journal_input_path)
        path.write_bytes(path.read_bytes()+b'\n')
        con.execute('UPDATE cba_firmware_dive_runs SET journal_input_sha256=?', (sha(path.read_bytes()),))
    elif damage == 'special-result':
        path = run / observation['artifact_path']
        path.unlink()
        path.mkdir()
    else:
        path = run / observation['artifact_path']
        with path.open('wb') as stream: stream.truncate(8*1024*1024+1)
        con.execute('UPDATE cba_firmware_dive_observations SET artifact_sha256=?', (sha(path.read_bytes()),))
        con.execute('UPDATE cba_firmware_dive_receipts SET result_sha256=?', (sha(path.read_bytes()),))
    con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


@pytest.mark.parametrize('damage',['missing-answer','counts'])
def test_completed_history_requires_exact_denominator_and_outcome_counts(graph_case,damage):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,obs=accepted(graph_case,first)
    if damage=='counts': con.execute('UPDATE cba_firmware_dive_runs SET supported_count=9')
    else:
        other=next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id']!=question['question_id'])
        for table in ('cba_firmware_dive_dependencies','cba_firmware_dive_observations','cba_firmware_dive_receipts'):
            con.execute(f'DELETE FROM {table} WHERE question_id=?',(other['question_id'],))
    con.commit()
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con)==before and files(run)==artifacts


def capture_history(case, *, capture=True):
    from tests.test_firmware_dive_schema import ACQUISITION
    con, run = case[:2]
    first = prepare(case)
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['method']=='hardware')
    question, obs = accepted(case, first, value=True, question_id=question['question_id'])
    if capture:
        packet = json.loads((run/question['packet_path']).read_bytes())
        directory = run/'artifacts/test-capture'
        directory.mkdir()
        (directory/'spec.json').write_bytes(b'opaque verified spec')
        (directory/'manifest.json').write_bytes(b'opaque verified manifest')
        owner = dict(image_id='target',dive_generation=first.dive_generation,question_id=question['question_id'])
        row = ACQUISITION | owner | dict(kind='capture',acquisition_id='a'*64,
            contract_sha256=sha(canonical(packet['acquisition_contract'])),
            spec_path='artifacts/test-capture/spec.json',spec_sha256=sha(b'opaque verified spec'),
            manifest_path='artifacts/test-capture/manifest.json',manifest_sha256=sha(b'opaque verified manifest'),details='{"kind":"capture"}')
        db.put(con,'cba_firmware_dive_acquisitions',row)
        con.execute('UPDATE cba_firmware_dive_dependencies SET kind=?,logical_id=?,relative_path=?,sha256=?,byte_count=? WHERE question_id=?',
            ('hardware-capture','a'*64,row['manifest_path'],row['manifest_sha256'],len(b'opaque verified manifest'),question['question_id']))
        con.execute("UPDATE cba_firmware_dive_observations SET evidence_rung='hardware-observed' WHERE question_id=?",(question['question_id'],))
        con.commit()
    return first, question


@pytest.mark.parametrize('damage',['none','contract','foreign-owner','manifest','spec','rung','static-only'])
def test_dynamic_history_requires_exact_owned_acquisition_and_method_rung(graph_case,damage):
    con,run=graph_case[:2]
    complete(graph_case)
    first, question=capture_history(graph_case,capture=damage!='static-only')
    if damage=='contract': con.execute('UPDATE cba_firmware_dive_acquisitions SET contract_sha256=?',('0'*64,))
    elif damage=='foreign-owner': con.execute('UPDATE cba_firmware_dive_acquisitions SET question_id=?',('0'*64,))
    elif damage in ('manifest','spec'): (run/f'artifacts/test-capture/{damage}.json').write_bytes(b'changed')
    elif damage=='rung': con.execute("UPDATE cba_firmware_dive_observations SET evidence_rung='static-resolved' WHERE question_id=?",(question['question_id'],))
    con.commit()
    before,artifacts=state(con),files(run)
    if damage=='none':
        second=prepare(graph_case)
        assert second.dive_generation==first.dive_generation
        assert state(con)==before and files(run)==artifacts
        assert json.loads(pathlib.Path(second.question_index_path).read_bytes())['input_overlay']==[]
    else:
        with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
        assert state(con)==before and files(run)==artifacts


@pytest.mark.parametrize('race',['failure','winner'])
def test_install_rename_failure_and_concurrent_identical_winner(graph_case,monkeypatch,race):
    con,run=graph_case[:2]
    complete(graph_case)
    dive=api()
    def rename(source,destination,**kwargs):
        if race=='winner':
            import shutil
            parent = run / 'files/firmware-dive'
            shutil.copytree(parent / source, parent / destination)
        raise OSError('injected rename race')
    monkeypatch.setattr(dive.os,'rename',rename)
    before=state(con)
    if race=='failure':
        with pytest.raises(dive.FirmwareDiveError): prepare(graph_case)
        assert state(con)==before
    else:
        result=prepare(graph_case)
        assert result.question_count==3
    assert not list((run/'files/firmware-dive').glob('.dive-*'))
    assert not con.in_transaction


def test_scoped_derivation_keeps_removed_subject_history_only_in_journal(graph_case):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    old_question,_=accepted(graph_case,first,outcome='inconclusive')
    # Regenerate the graph without overlap's stable subject while preserving its
    # immutable upstream evidence and every historical dive row/artifact.
    firmware_chain.invalidate(con,'target',commit=True)
    prepared=firmware_chain.prepare(con,run,graph_case[2],image_id='target')
    graph_case[3]['worklist_sha256']=prepared.worklist_sha256
    graph_case[3]['chains'][0]['edges'][1]['existing_unknowns']=[]
    record(graph_case)
    check(graph_case)
    result=prepare(graph_case)
    assert result.question_count==2
    journal=json.loads(pathlib.Path(result.journal_input_path).read_bytes())
    historical=next(r for r in journal['observations'] if r['question_id']==old_question['question_id'])
    assert historical['status']=='stale'
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case,retry=(old_question['question_id'],))


def test_index_reconstructs_complete_generation_without_informational_journal(graph_case):
    complete(graph_case)
    result=prepare(graph_case)
    index=json.loads(pathlib.Path(result.question_index_path).read_bytes())
    projection=dict(schema_version=1,graph=index['graph_projection'],analyst_manifest=index['analyst_manifest'],
        input_overlay=index['input_overlay'],retry_projection=index['retry_projection'],
        questions=[json.loads((graph_case[1]/row['packet_path']).read_bytes())['question'] for row in index['questions']])
    assert sha(canonical(projection))==result.dive_generation


def test_conflict_retained_owner_chronology_and_ambiguous_ties(graph_case):
    con,run,root=graph_case[:3]
    complete(graph_case)
    first=prepare(graph_case)
    question,one=canonical_accepted(graph_case,first)
    firmware_chain.invalidate(con,'target',commit=True)
    prep=firmware_chain.prepare(con,run,root,image_id='target')
    graph_case[3]['worklist_sha256']=prep.worklist_sha256
    graph_case[3]['chains'][0]['title']='A newer retained display title'
    record(graph_case)
    check(graph_case)
    second=prepare(graph_case,retry=(question['question_id'],))
    canonical_accepted(graph_case,second,value='pre-auth',question_id=question['question_id'])
    assert first.graph_sha256!=second.graph_sha256
    firmware_chain.invalidate(con,'target',commit=True)
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError,match='Ambiguous'): prepare(graph_case)
    assert state(con)==before and files(run)==artifacts
    con.execute("UPDATE cba_firmware_dive_runs SET completed_at='2026-01-02 03:04:06' WHERE dive_generation=?",(second.dive_generation,))
    con.commit()
    assert prepare(graph_case).graph_sha256==second.graph_sha256


@pytest.mark.parametrize('damage',['none','prose','limitations','successors','dependency-provenance'])
def test_repeated_observation_identity_requires_complete_stored_equivalence(graph_case,damage):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,one=accepted(graph_case,first)
    second=prepare(graph_case,retry=(question['question_id'],))
    accepted(graph_case,second,identity=one['observation_id'],question_id=question['question_id'])
    if damage in ('prose','limitations','successors'):
        field={'prose':'conclusion','limitations':'limitations','successors':'successor_questions'}[damage]
        value='[{}]' if damage=='successors' else 'changed stored prose'
        con.execute(f'UPDATE cba_firmware_dive_observations SET {field}=? WHERE dive_generation=? AND question_id=?',
            (value,second.dive_generation,question['question_id']))
        if damage=='successors': con.execute('UPDATE cba_firmware_dive_receipts SET successor_count=1 WHERE dive_generation=? AND question_id=?',(second.dive_generation,question['question_id']))
    elif damage=='dependency-provenance':
        con.execute('UPDATE cba_firmware_dive_dependencies SET source_provenance=? WHERE dive_generation=? AND question_id=?',
            ('{"source":"changed"}',second.dive_generation,question['question_id']))
    con.commit()
    before,artifacts=state(con),files(run)
    if damage=='none':
        third=prepare(graph_case,retry=(question['question_id'],))
        row=next(r for r in rows(con,'cba_firmware_dive_questions') if r['dive_generation']==third.dive_generation and r['question_id']==question['question_id'])
        assert row['attempt_ordinal']==3
    else:
        with pytest.raises(api().FirmwareDiveError,match='Observation identity'): prepare(graph_case)
        assert state(con)==before and files(run)==artifacts


@pytest.mark.parametrize('provenance',['{"path":"/Users/private/source"}','{"path":"C:/private/source"}',
    '{"path":"C:\\\\private\\\\source"}','{"path":"\\\\\\\\host\\\\share"}',
    '{"path":"src/../private"}','{"nested":{"path":"read /private/source"}}',
    '{"nested":'+'['*20+'"deep"'+']'*20+'}'])
def test_dependency_provenance_rejects_root_and_traversal_before_generation_hash(graph_case,provenance):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,obs=accepted(graph_case,first)
    con.execute('UPDATE cba_firmware_dive_dependencies SET source_provenance=? WHERE question_id=?',(provenance,question['question_id']))
    con.commit()
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con)==before and files(run)==artifacts


def test_private_dependency_provenance_stays_behind_index_digest(graph_case):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,obs=accepted(graph_case,first)
    private='opaque private provenance body sentinel'
    con.execute('UPDATE cba_firmware_dive_dependencies SET source_provenance=? WHERE question_id=?',(canonical({'note':private}).decode(),question['question_id']))
    con.commit()
    result=prepare(graph_case)
    raw=pathlib.Path(result.question_index_path).read_bytes()
    assert private.encode() not in raw
    index=json.loads(raw)
    assert index['input_overlay']==[]  # Opaque provenance remains historical, never accepted input.


@pytest.mark.parametrize('kind',['chain-artifact','extract-record'])
def test_historical_exact_chain_and_extract_dependencies(graph_case,kind):
    con,run=graph_case[:2]
    complete(graph_case)
    historical_extract(graph_case)
    first=prepare(graph_case)
    selected=next(r for r in rows(con,'cba_firmware_dive_questions') if json.loads((run/r['packet_path']).read_bytes())['extract_records'])
    question,obs=accepted(graph_case,first,outcome='inconclusive',question_id=selected['question_id'])
    packet=json.loads((run/question['packet_path']).read_bytes())
    ref=next(r for r in packet['allowed_dependencies'] if r['kind']==kind)
    con.execute('UPDATE cba_firmware_dive_dependencies SET kind=?,logical_id=?,relative_path=?,sha256=?,byte_count=? WHERE question_id=?',
        (ref['kind'],ref['logical_id'],ref['relative_path'],ref['sha256'],len((run/ref['relative_path']).read_bytes()),question['question_id']))
    con.commit()
    before,writes,artifacts=state(con),con.total_changes,files(run)
    assert prepare(graph_case)==first
    assert state(con)==before and con.total_changes==writes and files(run)==artifacts


def test_historical_packet_cannot_expand_static_authority_with_coordinated_hash_updates(graph_case):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,obs=accepted(graph_case,first)
    graph=snapshot(graph_case)
    finding=graph.findings[0]
    ref=dict(kind='finding-artifact',logical_id=finding.finding_id,relative_path=finding.artifact_path,sha256=finding.artifact_sha256)
    path=run/question['packet_path']
    packet=json.loads(path.read_bytes())
    packet['retained_refs'].append(ref)
    packet['retained_refs'].sort(key=lambda r:(r['kind'],r['logical_id'],r['relative_path'],r['sha256']))
    packet['allowed_dependencies']=packet['retained_refs']
    raw=canonical(packet)
    path.write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_questions SET packet_sha256=? WHERE question_id=?',(sha(raw),question['question_id']))
    con.execute('UPDATE cba_firmware_dive_receipts SET packet_sha256=? WHERE question_id=?',(sha(raw),question['question_id']))
    index_path=pathlib.Path(first.question_index_path)
    index=json.loads(index_path.read_bytes())
    next(r for r in index['questions'] if r['question_id']==question['question_id'])['packet_sha256']=sha(raw)
    index_raw=canonical(index)
    index_path.write_bytes(index_raw)
    con.execute('UPDATE cba_firmware_dive_runs SET question_index_sha256=?',(sha(index_raw),))
    con.execute('UPDATE cba_firmware_dive_dependencies SET kind=?,logical_id=?,relative_path=?,sha256=?,byte_count=? WHERE question_id=?',
        (ref['kind'],ref['logical_id'],ref['relative_path'],ref['sha256'],len((run/ref['relative_path']).read_bytes()),question['question_id']))
    con.commit()
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con)==before and files(run)==artifacts


def test_deep_corrupt_history_uses_domain_refusal_and_preserves_sql(graph_case):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,obs=accepted(graph_case,first)
    con.execute('UPDATE cba_firmware_dive_dependencies SET source_provenance=? WHERE question_id=?',
        ('['*2000+'0'+']'*2000,question['question_id']))
    con.commit()
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError): prepare(graph_case)
    assert state(con)==before and files(run)==artifacts and not con.in_transaction


@pytest.mark.parametrize('artifact',['index','journal','packet'])
def test_historical_artifact_schema_version_refuses_boolean_even_with_rehashed_provenance(graph_case,tmp_path,artifact):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    row=rows(con,'cba_firmware_dive_questions')[0]
    path=pathlib.Path(first.question_index_path) if artifact=='index' else pathlib.Path(first.journal_input_path) if artifact=='journal' else run/row['packet_path']
    value=json.loads(path.read_bytes());value['schema_version']=True
    raw=canonical(value);path.write_bytes(raw)
    index_path=pathlib.Path(first.question_index_path)
    index=json.loads(index_path.read_bytes())
    if artifact=='packet':
        con.execute('UPDATE cba_firmware_dive_questions SET packet_sha256=? WHERE question_id=?',(sha(raw),row['question_id']))
        next(r for r in index['questions'] if r['question_id']==row['question_id'])['packet_sha256']=sha(raw)
    elif artifact=='journal':
        con.execute('UPDATE cba_firmware_dive_runs SET journal_input_sha256=?',(sha(raw),))
        index['journal_input_sha256']=sha(raw)
    index_raw=canonical(index);index_path.write_bytes(index_raw)
    con.execute('UPDATE cba_firmware_dive_runs SET question_index_sha256=?',(sha(index_raw),));con.commit()
    manifest_path=manifest(tmp_path,[entry(snapshot(graph_case))])
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError):prepare(graph_case,questions_path=manifest_path)
    assert state(con)==before and files(run)==artifacts


def test_deep_extract_manifest_is_a_domain_refusal(graph_case):
    con,run=graph_case[:2]
    complete(graph_case)
    historical_extract(graph_case)
    (run/'extract/manifest.json').write_bytes(b'['*2000+b'0'+b']'*2000)
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError):prepare(graph_case)
    assert state(con)==before and files(run)==artifacts and not con.in_transaction


def test_historical_chain_dependency_cannot_relabel_foreign_retained_bytes(graph_case,tmp_path):
    con,run=graph_case[:2]
    complete(graph_case)
    first=prepare(graph_case)
    question,obs=accepted(graph_case,first)
    path=run/question['packet_path'];packet=json.loads(path.read_bytes())
    # Keep owner graph's logical identity but substitute a different valid file.
    foreign=run/'artifacts/foreign-chain.json';foreign.write_bytes(b'foreign retained graph bytes')
    ref=next(r for r in packet['retained_refs'] if r['kind']=='chain-artifact')
    ref.update(relative_path=foreign.relative_to(run).as_posix(),sha256=sha(foreign.read_bytes()))
    packet['allowed_dependencies']=packet['retained_refs']
    raw=canonical(packet);path.write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_questions SET packet_sha256=? WHERE question_id=?',(sha(raw),question['question_id']))
    con.execute('UPDATE cba_firmware_dive_receipts SET packet_sha256=? WHERE question_id=?',(sha(raw),question['question_id']))
    index_path=pathlib.Path(first.question_index_path);index=json.loads(index_path.read_bytes())
    next(r for r in index['questions'] if r['question_id']==question['question_id'])['packet_sha256']=sha(raw)
    raw=canonical(index);index_path.write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_runs SET question_index_sha256=?',(sha(raw),))
    con.execute('UPDATE cba_firmware_dive_dependencies SET kind=?,logical_id=?,relative_path=?,sha256=?,byte_count=? WHERE question_id=?',
        ('chain-artifact',ref['logical_id'],ref['relative_path'],ref['sha256'],len(foreign.read_bytes()),question['question_id']))
    con.commit()
    before,artifacts=state(con),files(run)
    with pytest.raises(api().FirmwareDiveError):prepare(graph_case,questions_path=manifest(tmp_path,[entry(snapshot(graph_case))]))
    assert state(con)==before and files(run)==artifacts
