"""Exact prepared authority, immutable imports, and semantic retry identities."""
import copy
import dataclasses
import json
import os
import pathlib
import shutil
import sqlite3

import pytest

from audit_core import db, firmware_chain, firmware_dive as dive
from audit_core import firmware_dive_results as results
from audit_core import firmware_dive_questions as q
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_prepare import canonical, sha, prepare, rows, files, manifest
from tests.test_firmware_dive_snapshot import complete, snapshot
from tests.test_firmware_dive_questions import entry
from tests.test_firmware_dive_capture import capture, seal  # noqa: F401
from tests.test_firmware_dive_probe import probe, run as probe_run, executable  # noqa: F401
from tests.test_hunt_gate import state


@pytest.fixture
def assignment(graph_case, tmp_path):
    complete(graph_case)
    generation = prepare(graph_case)
    question = next(r for r in rows(graph_case[0], 'cba_firmware_dive_questions') if r['method'] == 'static')
    return build(graph_case, question, tmp_path)


def build(case, question, directory, acquisition=None, outcome='supported'):
    packet = json.loads((case[1] / question['packet_path']).read_bytes())
    contract = packet['question']['resolution_contract']
    if acquisition is None:
        candidates = [r for r in packet['allowed_dependencies'] if r['kind'] == 'surface-artifact']
        ref = next((r for r in candidates if 'unknown:' + r['logical_id'] + '#evidence' in packet['evidence_refs']), None)
        if ref is None:
            ref = packet['allowed_dependencies'][0]
            evidence = packet['evidence_refs'][0] if packet['evidence_refs'] else None
        else:
            evidence = 'unknown:' + ref['logical_id'] + '#evidence'
    else:
        kind = 'probe-manifest' if acquisition.kind == 'probe' else 'hardware-capture'
        relative = pathlib.Path(acquisition.manifest_path).relative_to(case[1]).as_posix()
        ref = dict(kind=kind, logical_id=acquisition.acquisition_id, relative_path=relative, sha256=sha((case[1]/relative).read_bytes()))
        evidence_path = 'evidence/stdout' if acquisition.kind == 'probe' else 'evidence/uart.txt'
        evidence = ('probe:' if acquisition.kind == 'probe' else 'capture:') + acquisition.acquisition_id + '#' + evidence_path
    dep = ref | dict(byte_count=len((case[1]/ref['relative_path']).read_bytes()))
    effect = {k:contract[k] for k in ('target_subject','mode','predicate','axis','capability_kind','link_key','transition_kind')}
    effect['value'] = contract['expected_value'] if contract['mode'] == 'boolean-claim' else contract['allowed_values'][0] if contract['allowed_values'] else 'other-specific:verified'
    answer = dict(question_id=question['question_id'], attempt_ordinal=question['attempt_ordinal'], packet_sha256=question['packet_sha256'],
        outcome=outcome, conclusion='Exact observation' if outcome != 'inconclusive' else 'Could not settle the question',
        limitations=['Only the recorded method and inputs'], resolution_effect=effect if outcome != 'inconclusive' else None,
        dependencies=[dep] if evidence else [], evidence=[dict(dependency_kind=dep['kind'], dependency_logical_id=dep['logical_id'], reference=evidence)] if evidence else [], successor_questions=[])
    value = dict(schema_version=1, image_id='target', dive_generation=question['dive_generation'], questions=[answer])
    path = directory / 'dive-result.json'
    path.write_bytes(canonical(value))
    return case, path, value, packet


def save(item):
    item[1].write_bytes(canonical(item[2]))


def validate(item, con=None):
    return results.validate(con or item[0][0], item[0][1], results.load(item[1]))


def record(item, con=None):
    return results.record(con or item[0][0], item[0][1], item[1])


def test_sql_ready_validation_is_readonly_caller_compatible_and_live_root_free(assignment):
    case, path, value, packet = assignment
    con, run, root = case[:3]
    shutil.rmtree(root)
    before, artifacts, changes = state(con), files(run), con.total_changes
    validated = validate(assignment)
    assert set(dataclasses.asdict(validated)) == {'receipt','observation','dependencies'}
    assert validated.receipt['question_id'] == value['questions'][0]['question_id']
    assert validated.observation['evidence_rung'] == 'static-resolved'
    assert json.loads(validated.observation['dependency_refs']) == value['questions'][0]['dependencies']
    assert json.loads(validated.observation['evidence_refs']) == value['questions'][0]['evidence']
    assert json.loads(validated.observation['limitations']) == value['questions'][0]['limitations']
    assert validated.dependencies[0]['ordinal'] == 0
    assert json.loads(validated.dependencies[0]['source_provenance'])
    con.execute('BEGIN')
    assert validate(assignment) == validated and con.in_transaction
    con.rollback()
    readonly = sqlite3.connect('file:' + str(run/'audit.db') + '?mode=ro', uri=True)
    readonly.row_factory = sqlite3.Row
    try:
        assert validate(assignment, readonly) == validated
    finally:
        readonly.close()
    assert state(con) == before and files(run) == artifacts and con.total_changes == changes
    assert not con.in_transaction


def test_record_publishes_exact_rows_leaves_pending_and_duplicate_is_zero_write(assignment):
    con, run = assignment[0][:2]
    validated = validate(assignment)
    before = {t:rows(con,t) for t in ('cba_firmware_dive_runs','cba_firmware_dive_questions','cba_firmware_chain_runs','cba_firmware_findings')}
    summary = record(assignment)
    assert summary.receipt_key == validated.receipt['receipt_key']
    assert summary.observation_id == validated.observation['observation_id']
    path = pathlib.Path(summary.artifact_path)
    assert path == run/'artifacts/firmware-dive'/assignment[2]['dive_generation']/assignment[2]['questions'][0]['question_id']/sha(canonical(assignment[2]))/'result.json'
    assert path.read_bytes() == canonical(assignment[2])
    for name, expected in [('receipts',[validated.receipt]),('observations',[validated.observation]),('dependencies',list(validated.dependencies))]:
        actual = rows(con,'cba_firmware_dive_'+name)
        assert [{k:v for k,v in r.items() if k != 'recorded_at'} for r in actual] == expected
        assert all(r['recorded_at'] for r in actual)
    assert all(rows(con,t) == v for t,v in before.items())
    before, artifacts, changes, mtime = state(con), files(run), con.total_changes, path.stat().st_mtime_ns
    assert record(assignment) == summary
    assert state(con) == before and files(run) == artifacts and con.total_changes == changes
    assert path.stat().st_mtime_ns == mtime and not con.in_transaction


@pytest.mark.parametrize('field,value', [('image_id','foreign'),('dive_generation','0'*64),('question_id','0'*64),('attempt_ordinal',2),('packet_sha256','0'*64)])
def test_exact_assignment_refuses_foreign_scalars_without_writes(assignment, field, value):
    envelope = assignment[2] if field in ('image_id','dive_generation') else assignment[2]['questions'][0]
    envelope[field] = value
    save(assignment)
    before, artifacts = state(assignment[0][0]), files(assignment[0][1])
    with pytest.raises(results.FirmwareDiveResultError): validate(assignment)
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert state(assignment[0][0]) == before and files(assignment[0][1]) == artifacts


@pytest.mark.parametrize('damage', ['complete','empty','packet','index','journal','graph','question-row','candidate','missing-assignment'])
def test_assignment_authority_is_rebuilt_not_trusted(assignment, damage):
    con, run = assignment[0][:2]
    row = next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id'] == assignment[2]['questions'][0]['question_id'])
    owner, = rows(con,'cba_firmware_dive_runs')
    if damage == 'complete':
        con.execute("UPDATE cba_firmware_dive_runs SET status='complete',completed_at='x',journal_path='x',journal_sha256=?",('a'*64,))
    elif damage == 'empty': assignment[2]['questions'] = []; save(assignment)
    elif damage in ('packet','index','journal','graph'):
        key = {'packet':'packet_path','index':'question_index_path','journal':'journal_input_path','graph':'chain_graph_path'}[damage]
        (run / (row if damage == 'packet' else owner)[key]).write_bytes(b'{}')
    elif damage == 'question-row': con.execute("UPDATE cba_firmware_dive_questions SET question='forged'")
    elif damage == 'candidate': con.execute("UPDATE cba_firmware_dive_runs SET candidate_snapshot_sha256=?",('f'*64,))
    else: con.execute('DELETE FROM cba_firmware_dive_questions WHERE question_id=?',(row['question_id'],))
    con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(results.FirmwareDiveResultError): validate(assignment)
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('damage', ['path','hash','size','logical','foreign-evidence','unbacked','effect','outcome','successor-subject','successor-contract'])
def test_static_dependencies_effects_and_successors_are_exact(assignment, damage):
    answer = assignment[2]['questions'][0]
    dependency = answer['dependencies'][0]
    if damage == 'path': dependency['relative_path'] = 'files/arbitrary.json'
    elif damage == 'hash': dependency['sha256'] = '0'*64
    elif damage == 'size': dependency['byte_count'] += 1
    elif damage == 'logical': dependency['logical_id'] = 'foreign'; answer['evidence'][0]['dependency_logical_id'] = 'foreign'
    elif damage == 'foreign-evidence': answer['evidence'][0]['reference'] = 'finding:foreign#root_cause'
    elif damage == 'unbacked': answer['evidence'][0]['dependency_kind'] = 'finding-artifact'
    elif damage == 'effect': answer['resolution_effect']['target_subject'] = 'surface-unknown:foreign'
    elif damage == 'outcome': answer['outcome'] = 'refuted'
    else:
        proposed = entry(snapshot(assignment[0]))
        if damage == 'successor-subject': proposed['subject_refs'] = ['finding:foreign']
        else: proposed['resolution_contract']['target_subject'] = 'surface-unknown:foreign'
        answer['successor_questions'] = [proposed]
    save(assignment)
    before, artifacts = state(assignment[0][0]), files(assignment[0][1])
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert state(assignment[0][0]) == before and files(assignment[0][1]) == artifacts


def test_inconclusive_partial_or_no_evidence_and_successor_proposals(assignment):
    answer = assignment[2]['questions'][0]
    answer.update(outcome='inconclusive',resolution_effect=None,dependencies=[],evidence=[])
    answer['successor_questions'] = [entry(snapshot(assignment[0]))]
    save(assignment)
    validated = validate(assignment)
    assert validated.observation['evidence_rung'] is None and not validated.dependencies
    record(assignment)
    assert len(rows(assignment[0][0],'cba_firmware_dive_questions')) == 3
    assert json.loads(rows(assignment[0][0],'cba_firmware_dive_observations')[0]['successor_questions']) == answer['successor_questions']


@pytest.mark.parametrize('kind', ['capture','probe'])
def test_dynamic_exact_acquisition_derives_rung(request, tmp_path, monkeypatch, kind):
    selected = request.getfixturevalue(kind)
    # Both fixture generations coexist; locate the exact selected question.
    if kind == 'probe': executable(selected,monkeypatch,"print('verified fact')")
    acquisition = seal(selected) if kind == 'capture' else probe_run(selected)
    question = next(r for r in rows(selected[0][0],'cba_firmware_dive_questions') if (r['dive_generation'],r['question_id']) == (selected[2]['dive_generation'],selected[2]['question_id']))
    item = build(selected[0],question,tmp_path,acquisition)
    assert validate(item).observation['evidence_rung'] == ('hardware-observed' if kind == 'capture' else 'emulated-observed')
    record(item)


@pytest.mark.parametrize('damage', ['missing','foreign-question','foreign-contract','manifest','spec','evidence','paths','details','wrong-method','limitations','missing-file','symlink'])
def test_capture_acquisition_reconstructed_from_sealed_bytes(capture, tmp_path, damage):
    acquisition = seal(capture)
    con, run = capture[0][:2]
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id'] == capture[2]['question_id'])
    item = build(capture[0],question,tmp_path,acquisition)
    if damage == 'missing': con.execute('DELETE FROM cba_firmware_dive_acquisitions')
    elif damage == 'foreign-question': con.execute('UPDATE cba_firmware_dive_acquisitions SET question_id=?',('0'*64,))
    elif damage == 'foreign-contract': con.execute('UPDATE cba_firmware_dive_acquisitions SET contract_sha256=?',('0'*64,))
    elif damage == 'paths': con.execute("UPDATE cba_firmware_dive_acquisitions SET evidence_paths='[]'")
    elif damage == 'details': con.execute('UPDATE cba_firmware_dive_acquisitions SET details=?',('{"byte_count":0,"file_count":0,"kind":"capture"}',))
    elif damage == 'wrong-method': item[2]['questions'][0]['evidence'][0]['reference'] = 'capture:' + acquisition.acquisition_id + '#other'
    elif damage == 'limitations': item[2]['questions'][0]['limitations'] = []
    else:
        target = pathlib.Path(acquisition.manifest_path) if damage == 'manifest' else pathlib.Path(acquisition.spec_path) if damage == 'spec' else pathlib.Path(acquisition.manifest_path).parent/'evidence/uart.txt'
        if damage == 'missing-file': target.unlink()
        elif damage == 'symlink': target.unlink(); target.symlink_to(capture[1].parent/'uart.txt')
        else: target.write_bytes(b'changed')
    con.commit(); save(item)
    before, artifacts = state(con), files(run)
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('damage', ['no-execution','missing-limitations','foreign-evidence','termination','manifest-identity'])
def test_probe_unavailable_cannot_be_conclusive_and_manifests_are_verified(probe,tmp_path,damage):
    acquisition = probe_run(probe)
    con,run = probe[0][:2]
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id'] == probe[2]['question_id'])
    item = build(probe[0],question,tmp_path,acquisition)
    if damage == 'missing-limitations': item[2]['questions'][0]['limitations'] = []
    elif damage == 'foreign-evidence': item[2]['questions'][0]['evidence'][0]['reference'] = 'probe:' + acquisition.acquisition_id + '#outputs/absent'
    elif damage in ('termination','manifest-identity'):
        path = pathlib.Path(acquisition.manifest_path)
        body = json.loads(path.read_bytes())
        if damage == 'termination': body['termination']['executed'] = True
        else: body['acquisition_id'] = '0'*64
        path.write_bytes(canonical(body))
        con.execute('UPDATE cba_firmware_dive_acquisitions SET manifest_sha256=?',(sha(path.read_bytes()),)); con.commit()
        item[2]['questions'][0]['dependencies'][0].update(sha256=sha(path.read_bytes()),byte_count=len(path.read_bytes()))
    save(item)
    with pytest.raises(results.FirmwareDiveResultError): record(item)


@pytest.mark.parametrize('failure', ['receipts','observations','dependencies','commit'])
def test_publication_failure_rolls_back_all_rows_and_preserves_siblings(assignment,monkeypatch,failure):
    con,run = assignment[0][:2]
    before,artifacts = state(con),files(run)
    original = db.put
    def put(connection,table,*args,**kwargs):
        if table == 'cba_firmware_dive_'+failure: raise sqlite3.OperationalError('injected')
        return original(connection,table,*args,**kwargs)
    monkeypatch.setattr(db,'put',put)
    if failure == 'commit':
        class CommitFailure:
            def __getattr__(self,name): return getattr(con,name)
            def commit(self): raise sqlite3.OperationalError('commit injected')
        selected = CommitFailure()
    else: selected = con
    with pytest.raises(results.FirmwareDiveResultError): record(assignment,selected)
    assert state(con) == before and not con.in_transaction
    assert all(files(run)[key] == raw for key,raw in artifacts.items())
    assert not rows(con,'cba_firmware_dive_receipts')


@pytest.mark.parametrize('damage',['packet','source','installed','sql','history'])
def test_post_install_revalidation_refuses_all_input_races(assignment,monkeypatch,damage):
    con,run = assignment[0][:2]
    original = dive._install
    def install(destination,contents,selected):
        original(destination,contents,selected)
        if damage == 'packet':
            question = rows(con,'cba_firmware_dive_questions')[0]
            (run/question['packet_path']).write_bytes(b'{}')
        elif damage == 'source': assignment[1].write_bytes(canonical(assignment[2] | dict(image_id='foreign')))
        elif damage == 'installed': (destination/'result.json').write_bytes(b'{}')
        elif damage == 'sql': con.execute("UPDATE cba_firmware_dive_questions SET question='raced'"); con.commit()
        else: con.execute("UPDATE cba_firmware_dive_runs SET prepared_at=''"); con.commit()
    monkeypatch.setattr(dive,'_install',install)
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert not rows(con,'cba_firmware_dive_receipts') and not con.in_transaction


@pytest.mark.parametrize('damage',['source-leaf','source-parent','destination-leaf','destination-parent','active-transaction','conflict'])
def test_import_refuses_links_transactions_and_conflicting_duplicates(assignment,tmp_path,damage):
    con,run = assignment[0][:2]
    if damage == 'active-transaction': con.execute('BEGIN')
    elif damage == 'conflict': record(assignment); assignment[2]['questions'][0]['conclusion'] += ' changed'; save(assignment)
    elif damage.startswith('source'):
        alternate = tmp_path/'source'; alternate.mkdir(); target = alternate/'actual.json'; target.write_bytes(assignment[1].read_bytes())
        assignment[1].unlink()
        if damage == 'source-leaf': assignment[1].symlink_to(target)
        else:
            parent = tmp_path/'linked'; parent.symlink_to(alternate,target_is_directory=True)
            assignment = (assignment[0],parent/'actual.json',assignment[2],assignment[3])
    else:
        parent = run/'artifacts/firmware-dive'/assignment[2]['dive_generation']/assignment[2]['questions'][0]['question_id']
        parent.mkdir(parents=True,exist_ok=True)
        if damage == 'destination-parent': parent.rmdir(); parent.symlink_to(tmp_path,target_is_directory=True)
        else: (parent/sha(canonical(assignment[2]))).symlink_to(tmp_path,target_is_directory=True)
    before = state(con)
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert state(con) == before
    assert con.in_transaction == (damage == 'active-transaction')
    if con.in_transaction: con.rollback()


def test_semantically_identical_observation_across_generations_retains_receipt_successors(assignment,tmp_path):
    con,run = assignment[0][:2]
    first = record(assignment)
    generation = prepare(assignment[0],questions_path=manifest(tmp_path,[entry(snapshot(assignment[0]))]))
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['dive_generation'] == generation.dive_generation and r['question_id'] == assignment[2]['questions'][0]['question_id'])
    second = build(assignment[0],question,tmp_path)
    second[2]['questions'][0]['successor_questions'] = [entry(snapshot(assignment[0]))]
    save(second)
    newer = record(second)
    assert newer.observation_id == first.observation_id
    assert newer.receipt_key != first.receipt_key and newer.artifact_path != first.artifact_path
    assert len(rows(con,'cba_firmware_dive_receipts')) == 2
    prepare(assignment[0])
    observations = rows(con,'cba_firmware_dive_observations')
    assert {r['successor_questions'] for r in observations} == {'[]',canonical(second[2]['questions'][0]['successor_questions']).decode()}


@pytest.mark.parametrize('corrupt_raw',[b'{"schema_version":true}',b'opaque replacement',b'null'])
def test_empty_variant_requires_exact_zero_denominator(graph_case,tmp_path,corrupt_raw):
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check
    con,run = graph_case[:2]
    root = tmp_path/'empty-root'
    empty_review(con,run,root,'empty')
    chain = firmware_chain.prepare(con,run,root,image_id='empty')
    case = (con,run,root,dict(schema_version=1,image_id='empty',candidate_snapshot_sha256=chain.candidate_snapshot_sha256,worklist_sha256=chain.worklist_sha256,blockers=[],dispositions=[],chains=[]),{})
    chain_record(case); check(case,image_id='empty')
    generation = dive.prepare(con,run,root,image_id='empty')
    path = tmp_path/'empty-result.json'; path.write_bytes(canonical(dict(schema_version=1,image_id='empty',dive_generation=generation.dive_generation,questions=[])))
    validated = results.validate(con,run,results.load(path))
    assert validated.observation is None and validated.dependencies == ()
    summary = results.record(con,run,path)
    assert summary.observation_id is None
    assert rows(con,'cba_firmware_dive_receipts','empty')[0]['receipt_kind'] == 'empty'
    for table in ('observations','dependencies','acquisitions'): assert not rows(con,'cba_firmware_dive_'+table,'empty')
    before,changes = state(con),con.total_changes
    assert results.record(con,run,path) == summary
    assert state(con) == before and con.total_changes == changes
    receipt, = rows(con,'cba_firmware_dive_receipts','empty')
    raw = corrupt_raw
    (run/receipt['result_path']).write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_receipts SET result_sha256=? WHERE image_id=?',(sha(raw),'empty')); con.commit()
    with pytest.raises(dive.FirmwareDiveError): dive.prepare(con,run,root,image_id='empty')


@pytest.mark.parametrize('column',['chain_blocker_count','surface_unknown_count','analyst_question_count','retry_count','conflict_count','supported_count','refuted_count','inconclusive_count'])
def test_prepared_derived_counts_are_reconstructed(assignment,column):
    con = assignment[0][0]
    con.execute('UPDATE cba_firmware_dive_runs SET '+column+'='+column+'+1'); con.commit()
    with pytest.raises(results.FirmwareDiveResultError): validate(assignment)


@pytest.mark.parametrize('table,column,value',[('receipts','receipt_key','firmware-dive-receipt-'+'0'*64),
    ('receipts','successor_count',1),('observations','conclusion','forged'),('observations','successor_questions','[]'),
    ('dependencies','source_provenance','{}'),('dependencies','ordinal',4),('observations','dependency_refs','[]')])
def test_existing_canonical_result_reconstructs_every_attempt_local_row(assignment,table,column,value):
    if column == 'successor_questions':
        assignment[2]['questions'][0]['successor_questions'] = [entry(snapshot(assignment[0]))]; save(assignment)
    record(assignment)
    con = assignment[0][0]
    con.execute('UPDATE cba_firmware_dive_'+table+' SET '+column+'=?',(value,)); con.commit()
    before = state(con)
    with pytest.raises(results.FirmwareDiveResultError): validate(assignment)
    with pytest.raises(dive.FirmwareDiveError): prepare(assignment[0])
    assert state(con) == before


@pytest.mark.parametrize('raw',[b'{"schema_version":1}',b'{bad',b'[]',b'{"schema_version":true,"questions":[]}'])
def test_malformed_historical_envelope_never_uses_opaque_compatibility(assignment,raw):
    record(assignment)
    con,run = assignment[0][:2]
    observation, = rows(con,'cba_firmware_dive_observations')
    path = run/observation['artifact_path']; path.write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_observations SET artifact_sha256=?',(sha(raw),))
    con.execute('UPDATE cba_firmware_dive_receipts SET result_sha256=?',(sha(raw),)); con.commit()
    with pytest.raises(dive.FirmwareDiveError): prepare(assignment[0])


def test_canonical_and_opaque_history_cannot_reuse_observation_id(assignment,tmp_path):
    from tests.test_firmware_dive_prepare import accepted
    con,run = assignment[0][:2]
    validated = validate(assignment)
    owner, = rows(con,'cba_firmware_dive_runs')
    accepted(assignment[0],type('Generation',(),owner)(),question_id=assignment[2]['questions'][0]['question_id'],
        identity=validated.observation['observation_id'],outcome='inconclusive')
    newer = prepare(assignment[0],questions_path=manifest(tmp_path,[entry(snapshot(assignment[0]))]),retry=(assignment[2]['questions'][0]['question_id'],))
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['dive_generation'] == newer.dive_generation and r['question_id'] == assignment[2]['questions'][0]['question_id'])
    item = build(assignment[0],question,tmp_path)
    with pytest.raises(results.FirmwareDiveResultError): record(item)


@pytest.mark.parametrize('kind',['receipt','observation'])
def test_global_identifiers_refuse_foreign_ownership(assignment,kind):
    con = assignment[0][0]
    validated = validate(assignment)
    row = copy.deepcopy(validated.receipt if kind == 'receipt' else validated.observation)
    row['image_id'] = 'foreign'
    db.put(con,'cba_firmware_dive_'+('receipts' if kind == 'receipt' else 'observations'),row)
    before = state(con)
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert state(con) == before


@pytest.mark.parametrize('damage',['manifest','evidence','row'])
def test_post_install_acquisition_race_cannot_publish(capture,tmp_path,monkeypatch,damage):
    acquisition = seal(capture)
    con,run = capture[0][:2]
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id'] == capture[2]['question_id'])
    item = build(capture[0],question,tmp_path,acquisition)
    original = dive._install
    def install(destination,contents,selected):
        original(destination,contents,selected)
        if damage == 'row': con.execute("UPDATE cba_firmware_dive_acquisitions SET details='{}'"); con.commit()
        else:
            path = pathlib.Path(acquisition.manifest_path) if damage == 'manifest' else pathlib.Path(acquisition.manifest_path).parent/'evidence/uart.txt'
            path.write_bytes(b'changed')
    monkeypatch.setattr(dive,'_install',install)
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    assert not rows(con,'cba_firmware_dive_receipts')


def test_write_lock_contention_preserves_sql_and_candidate_is_unreferenced(assignment):
    con,run = assignment[0][:2]
    second = db.connect(run/'audit.db')
    second.execute('PRAGMA busy_timeout=1')
    con.execute('BEGIN IMMEDIATE')
    before = state(con)
    try:
        with pytest.raises(results.FirmwareDiveResultError): record(assignment,second)
        assert state(con) == before and not second.in_transaction
    finally:
        con.rollback(); second.close()


def test_completed_and_pending_retry_share_semantics_without_stale_overlay(assignment,tmp_path):
    con,run = assignment[0][:2]
    first = record(assignment)
    target = assignment[2]['questions'][0]['question_id']
    for row in rows(con,'cba_firmware_dive_questions'):
        if row['question_id'] != target:
            record(build(assignment[0],row,tmp_path,outcome='inconclusive'))
    journal = run/'test-completed-journal'; journal.write_bytes(b'opaque completed Task 4 journal')
    con.execute("UPDATE cba_firmware_dive_runs SET status='complete',completed_at='2026-01-01',journal_path=?,journal_sha256=?,supported_count=1,inconclusive_count=2",
        (journal.relative_to(run).as_posix(),sha(journal.read_bytes())))
    con.commit()
    newer = prepare(assignment[0],retry=(target,))
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['dive_generation'] == newer.dive_generation and r['question_id'] == target)
    second = build(assignment[0],question,tmp_path)
    summary = record(second)
    assert summary.observation_id == first.observation_id
    validate(second)
    history,_,overlay = dive._history(run,dive._rows(con,'target'),snapshot(assignment[0]))
    matching = [h for h in history if h.observation_id == first.observation_id]
    assert len(matching) == 2 and sorted(h.dependency_current for h in matching) == [False,True]
    assert len(overlay) == 1 and overlay[0]['observation_id'] == first.observation_id
    assert all(isinstance(ref,str) for ref in overlay[0]['dependency_refs'])


def test_all_static_dependency_owners_and_ordinals_are_reconstructed(assignment):
    con,run = assignment[0][:2]
    answer = assignment[2]['questions'][0]
    answer.update(outcome='inconclusive',resolution_effect=None,evidence=[])
    answer['dependencies'] = [ref | dict(byte_count=len((run/ref['relative_path']).read_bytes())) for ref in assignment[3]['allowed_dependencies']]
    answer['dependencies'].sort(key=lambda d:(d['kind'],d['logical_id'],d['relative_path'],d['sha256'],d['byte_count']))
    save(assignment)
    validated = validate(assignment)
    projections = [{k:v for k,v in d.items() if k not in ('image_id','dive_generation','question_id','observation_id','ordinal')} for d in validated.dependencies]
    assert projections == sorted(projections,key=canonical)
    assert [d['ordinal'] for d in validated.dependencies] == list(range(len(projections)))
    owner, = rows(con,'cba_firmware_dive_runs')
    index = json.loads((run/owner['question_index_path']).read_bytes())
    chain = next(d for d in validated.dependencies if d['kind'] == 'chain-artifact')
    assert json.loads(chain['source_provenance'])['graph_projection'] == index['graph_projection']
    record(assignment)
    validate(assignment)


def test_exact_extract_dependency_binds_manifest_projection(graph_case,tmp_path):
    from tests.test_firmware_dive_prepare import historical_extract
    complete(graph_case)
    historical_extract(graph_case)
    con,run = graph_case[:2]
    question = next(row for row in rows(con,'cba_firmware_dive_questions') if json.loads((run/row['packet_path']).read_bytes())['extract_records'])
    item = build(graph_case,question,tmp_path,outcome='inconclusive')
    ref = next(ref for ref in item[3]['allowed_dependencies'] if ref['kind'] == 'extract-record')
    item[2]['questions'][0].update(dependencies=[ref | dict(byte_count=len((run/ref['relative_path']).read_bytes()))],evidence=[])
    save(item)
    validated = validate(item)
    assert json.loads(validated.dependencies[0]['source_provenance'])['extract_record'] == item[3]['extract_records'][0]
    record(item)
    validate(item)


def test_probe_sealed_inputs_outputs_runner_and_unavailable_partial_facts(probe,tmp_path,monkeypatch):
    import sys
    from tests.test_firmware_dive_probe import save as save_probe
    probe[2].update(runner=str(pathlib.Path(sys.executable).resolve()),outputs=['nested/fact'])
    save_probe(probe)
    executable(probe,monkeypatch,"import pathlib,sys; pathlib.Path(sys.argv[2],'nested/fact').write_bytes(b'fact'); print('observed')")
    acquisition = probe_run(probe)
    question = next(r for r in rows(probe[0][0],'cba_firmware_dive_questions') if r['question_id'] == probe[2]['question_id'])
    item = build(probe[0],question,tmp_path,acquisition)
    item[2]['questions'][0]['evidence'][0]['reference'] = 'probe:'+acquisition.acquisition_id+'#outputs/nested/fact'
    save(item)
    record(item)
    validate(item)


def test_unavailable_probe_is_valid_inconclusive_acquisition_evidence(probe,tmp_path):
    acquisition = probe_run(probe)
    question = next(r for r in rows(probe[0][0],'cba_firmware_dive_questions') if r['question_id'] == probe[2]['question_id'])
    item = build(probe[0],question,tmp_path,acquisition,outcome='inconclusive')
    assert validate(item).observation['evidence_rung'] is None
    record(item)
    validate(item)


def test_failed_sibling_question_import_preserves_existing_receipt_and_artifact(assignment,tmp_path,monkeypatch):
    con,run = assignment[0][:2]
    record(assignment)
    row = next(r for r in rows(con,'cba_firmware_dive_questions') if r['question_id'] != assignment[2]['questions'][0]['question_id'])
    sibling = build(assignment[0],row,tmp_path,outcome='inconclusive')
    before,artifacts = state(con),files(run)
    original = db.put
    def put(connection,table,*args,**kwargs):
        if table == 'cba_firmware_dive_observations': raise sqlite3.OperationalError('failure')
        return original(connection,table,*args,**kwargs)
    monkeypatch.setattr(db,'put',put)
    with pytest.raises(results.FirmwareDiveResultError): record(sibling)
    assert state(con) == before and all(files(run)[key] == raw for key,raw in artifacts.items())


def test_upstream_ambiguous_legacy_coverage_uses_result_error_and_preserves_transaction(assignment):
    con = assignment[0][0]
    con.execute("INSERT INTO cba_coverage(unit,phase,state) VALUES('legacy-path','hunt-l-sink','analyzed')")
    before = state(con)
    with pytest.raises(results.FirmwareDiveResultError): validate(assignment)
    assert con.in_transaction and state(con) == before
    con.rollback()


def test_exact_retained_graph_import_survives_current_chain_invalidation(assignment):
    con,run,root = assignment[0][:3]
    firmware_chain.invalidate(con,'target'); con.commit()
    shutil.rmtree(root)
    shutil.rmtree(run/'files/firmware-chain')
    validated = validate(assignment)
    summary = record(assignment)
    assert summary.observation_id == validated.observation['observation_id']
    assert not rows(con,'cba_firmware_chain_runs')


@pytest.mark.parametrize('phase',['temp-create','file-open','rename','cleanup'])
def test_result_installer_remains_descriptor_anchored_after_redirection(assignment,tmp_path,monkeypatch,phase):
    con,run = assignment[0][:2]
    parent = run/'artifacts/firmware-dive'
    parent.mkdir()
    retained = run/'retained-dive-results'
    outside = tmp_path/'outside'; outside.mkdir()
    before = state(con)
    attacked = False
    def redirect():
        nonlocal attacked
        attacked = True
        parent.rename(retained); parent.symlink_to(outside,target_is_directory=True)
    real_open,real_mkdir,real_rename = os.open,os.mkdir,os.rename
    def mkdir(name,*args,**kwargs):
        if not attacked and phase == 'temp-create' and str(name).startswith('.dive-'): redirect()
        return real_mkdir(name,*args,**kwargs)
    def opened(name,flags,*args,**kwargs):
        if not attacked and phase == 'file-open' and flags & os.O_WRONLY: redirect()
        return real_open(name,flags,*args,**kwargs)
    def rename(name,destination,**kwargs):
        if not attacked and phase in ('rename','cleanup') and str(name).startswith('.dive-'):
            redirect()
            if phase == 'cleanup':
                decoy = outside/name; decoy.mkdir(); (decoy/'sentinel').write_bytes(b'outside-owned')
                raise OSError('injected rename failure')
        return real_rename(name,destination,**kwargs)
    monkeypatch.setattr(os,'mkdir',mkdir); monkeypatch.setattr(os,'open',opened); monkeypatch.setattr(os,'rename',rename)
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert attacked and state(con) == before and not con.in_transaction
    if phase == 'cleanup': assert [p.read_bytes() for p in outside.glob('*/sentinel')] == [b'outside-owned']
    else: assert not list(outside.iterdir())
    assert not list(retained.rglob('.dive-*'))


@pytest.mark.parametrize('encoding',['utf-16','utf-8-sig'])
def test_record_preserves_task7_strict_utf8_source_boundary(assignment,encoding):
    assignment[1].write_bytes(canonical(assignment[2]).decode().encode(encoding))
    before,artifacts = state(assignment[0][0]),files(assignment[0][1])
    with pytest.raises(results.FirmwareDiveResultError): results.load(assignment[1])
    with pytest.raises(results.FirmwareDiveResultError): record(assignment)
    assert state(assignment[0][0]) == before and files(assignment[0][1]) == artifacts
