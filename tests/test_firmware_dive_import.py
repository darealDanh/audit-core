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


def test_completed_and_pending_retry_share_semantics_without_stale_overlay(graph_case, tmp_path):
    from tests.test_firmware_dive_prepare import retry_manifest
    from tests.test_firmware_dive_gate import regenerate
    case = graph_case
    complete(case)
    path = retry_manifest(case)
    generation = prepare(case, questions_path=path)
    question = next(r for r in rows(case[0], 'cba_firmware_dive_questions') if r['origin'] == 'analyst')
    assignment = build(case, question, tmp_path)
    first = record(assignment)
    target = question['question_id']
    for row in rows(case[0], 'cba_firmware_dive_questions'):
        if row['question_id'] != target:
            record(build(case, row, tmp_path, outcome='inconclusive'))
    dive.check(*case[:3], image_id='target')
    regenerate(case)
    con, run = case[:2]
    newer = prepare(case, questions_path=path, retry=(target,))
    question = next(r for r in rows(con, 'cba_firmware_dive_questions') if r['dive_generation'] == newer.dive_generation and r['question_id'] == target)
    second = build(case, question, tmp_path)
    summary = record(second)
    assert summary.observation_id == first.observation_id
    validate(second)
    history, _, accepted_overlay = dive._history(run, dive._rows(con, 'target'), snapshot(case))
    matching = [h for h in history if h.observation_id == first.observation_id]
    assert len(matching) == 2 and sorted(h.dependency_current for h in matching) == [False, True]
    assert len(accepted_overlay) == 1 and accepted_overlay[0]['observation_id'] == first.observation_id
    assert all(isinstance(ref, str) for ref in accepted_overlay[0]['dependency_refs'])


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


@pytest.mark.parametrize('delete_worklist', [False, True])
def test_exact_retained_graph_import_survives_current_chain_invalidation(assignment, delete_worklist):
    con,run,root = assignment[0][:3]
    firmware_chain.invalidate(con,'target'); con.commit()
    shutil.rmtree(root)
    if delete_worklist:
        shutil.rmtree(run/'files/firmware-chain')
        before = state(con)
        with pytest.raises(results.FirmwareDiveResultError): validate(assignment)
        assert state(con) == before
        return
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


# Coherent resealing preserves every content-address/path/SQL projection so
# these cases exercise semantic reconstruction rather than a hash mismatch.
def reseal_probe(probe, acquisition, mutate):
    con, run = probe[0][:2]
    old = pathlib.Path(acquisition.manifest_path).parent
    body = json.loads((old/'manifest.json').read_bytes())
    replacements = mutate(body) or {}
    contents = {name: (old/name).read_bytes() for name in [row['path'] for row in body['evidence']] if (old/name).is_file()}
    contents.update(replacements)
    for row in body['evidence']:
        if row['path'] in replacements:
            row.update(sha256=sha(contents[row['path']]),byte_count=len(contents[row['path']]))
    identity = sha(canonical({key:value for key,value in body.items() if key != 'acquisition_id'}))
    body['acquisition_id'] = identity
    relative = 'artifacts/firmware-dive-probes/'+identity
    destination = run/relative
    destination.mkdir(parents=True,exist_ok=True)
    for name,raw in contents.items():
        (destination/name).parent.mkdir(parents=True,exist_ok=True); (destination/name).write_bytes(raw)
    (destination/'spec.json').write_bytes(canonical(body['spec']))
    (destination/'manifest.json').write_bytes(canonical(body))
    row = next(r for r in rows(con,'cba_firmware_dive_acquisitions') if r['acquisition_id'] == acquisition.acquisition_id)
    row.pop('recorded_at')
    row.update(acquisition_id=identity,spec_path=relative+'/spec.json',spec_sha256=sha(canonical(body['spec'])),
        manifest_path=relative+'/manifest.json',manifest_sha256=sha(canonical(body)),
        evidence_paths=canonical(sorted([relative+'/'+r['path'] for r in body['evidence']],key=canonical)).decode(),
        details=canonical(dict(kind='probe',file_count=len(body['evidence']),byte_count=sum(r['byte_count'] for r in body['evidence']))).decode())
    con.execute('DELETE FROM cba_firmware_dive_acquisitions WHERE acquisition_id=?',(acquisition.acquisition_id,)); con.commit()
    db.put(con,'cba_firmware_dive_acquisitions',row)
    return dataclasses.replace(acquisition,acquisition_id=identity,spec_path=str(destination/'spec.json'),manifest_path=str(destination/'manifest.json'))


def probe_item(probe, acquisition, tmp_path, *, outcome='supported'):
    question = next(r for r in rows(probe[0][0],'cba_firmware_dive_questions') if r['question_id'] == probe[2]['question_id'])
    return build(probe[0],question,tmp_path,acquisition,outcome=outcome)


_PROBE_CORRUPTIONS = ['reviewer-case','runtime-empty','runtime-extra','runtime-missing','runtime-source','runtime-roots',
    'runtime-limitation','runtime-tool','runtime-platform','runtime-version','null-executable','null-adapter','null-before',
    'fact-extra','fact-sha','fact-size','fact-bool','facts-drift','input-null-path','adapter-host-path','missing-adapter',
    'dependency-order','extra-helper','helper-null','alias-drift','exit-and-signal','exited-no-exit','exited-timeout',
    'exited-adapter-status','exit-overflow','signal-zero','signal-overflow','signal-exit','signal-file-limit',
    'timeout-no-flag','executed-unavailable','executed-unsupported','executed-tool','nonexecuted-exit','source-backend',
    'evidence-order','false-truncation','nonexecuted-stream','nonexecuted-zero-output','native-failed-zero-output']


def corrupt_probe(body, damage):
    term, deps, runtime = body['termination'],body['dependencies'],body['runtime']
    if damage == 'reviewer-case':
        term.update(executed=True,reason='isolation-unavailable',exit_code=None)
        body['runtime'] = {}; deps[0].update(before=None,after=None)
    elif damage == 'runtime-empty': body['runtime'] = {}
    elif damage == 'runtime-extra': runtime['unowned'] = True
    elif damage == 'runtime-missing': runtime.pop('version')
    elif damage == 'runtime-source': runtime['stream_source'] = 'not-executed'
    elif damage == 'runtime-roots': runtime['system_read_roots'] = ['/private']
    elif damage == 'runtime-limitation': runtime['limitation'] = 'invented'
    elif damage == 'runtime-tool': runtime['tool_runtime_limitation'] = 'omitted trust boundary'
    elif damage == 'runtime-platform': runtime['platform'] = ''
    elif damage == 'runtime-version': runtime['version'] = 1
    elif damage in ('null-executable','null-adapter'):
        deps[0 if damage == 'null-executable' else -1].update(before=None,after=None)
    elif damage == 'null-before': deps[0]['before'] = None
    elif damage == 'fact-extra': deps[0]['before']['extra'] = 1; deps[0]['after'] = copy.deepcopy(deps[0]['before'])
    elif damage == 'fact-sha': deps[0]['before']['sha256'] = 'bad'; deps[0]['after'] = copy.deepcopy(deps[0]['before'])
    elif damage in ('fact-size','fact-bool'):
        deps[0]['before']['byte_count'] = 67108865 if damage == 'fact-size' else True; deps[0]['after'] = copy.deepcopy(deps[0]['before'])
    elif damage == 'facts-drift': deps[0]['after']['sha256'] = '0'*64
    elif damage == 'input-null-path': deps[0]['path'] = None
    elif damage == 'adapter-host-path': deps[-1]['path'] = 'local-adapter'
    elif damage == 'missing-adapter': deps.pop()
    elif damage == 'dependency-order': deps.reverse()
    elif damage in ('extra-helper','helper-null'):
        deps.append(dict(role='environment-launcher',path=None,before=None if damage == 'helper-null' else copy.deepcopy(deps[0]['before']),after=None if damage == 'helper-null' else copy.deepcopy(deps[0]['after'])))
    elif damage == 'alias-drift':
        body['spec']['inputs'] = ['a']; dep = copy.deepcopy(deps[0]); dep['role'] = 'input'; dep['before']['sha256'] = dep['after']['sha256'] = '0'*64; deps.insert(1,dep)
    elif damage == 'exit-and-signal': term['signal'] = 15
    elif damage == 'exited-no-exit': term['exit_code'] = None
    elif damage == 'exited-timeout': term['timed_out'] = True
    elif damage == 'exited-adapter-status': term['adapter_exit_code'] = 0
    elif damage == 'exit-overflow': term['exit_code'] = 256
    elif damage in ('signal-zero','signal-overflow','signal-exit','signal-file-limit'):
        term.update(reason='signal',exit_code=None,signal={'signal-zero':0,'signal-overflow':128,'signal-exit':15,'signal-file-limit':25}[damage])
        if damage == 'signal-exit': term['exit_code'] = 0
    elif damage == 'timeout-no-flag': term.update(reason='timeout',exit_code=None,signal=9)
    elif damage in ('executed-unavailable','executed-unsupported','executed-tool'):
        term.update(reason={'executed-unavailable':'isolation-unavailable','executed-unsupported':'unsupported-limits','executed-tool':'tool-unavailable'}[damage],exit_code=None)
    elif damage == 'nonexecuted-exit': term['executed'] = False; runtime['stream_source'] = 'not-executed'
    elif damage == 'source-backend': term.update(status_source='sandbox-exec-adapter',exit_code=None,adapter_exit_code=0,reason='adapter-exited'); runtime['stream_source'] = term['status_source']
    elif damage == 'evidence-order': body['evidence'].reverse()
    elif damage == 'false-truncation': term['stdout_truncated'] = True
    elif damage in ('nonexecuted-stream','nonexecuted-zero-output'):
        term.update(executed=False,reason='tool-unavailable',exit_code=None); runtime['stream_source'] = 'not-executed'
        if damage == 'nonexecuted-zero-output':
            body['spec']['outputs'] = ['zero']; body['evidence'].append(dict(path='outputs/zero',sha256=sha(b''),byte_count=0))
            return {'evidence/stdout':b'','outputs/zero':b''}
    elif damage == 'native-failed-zero-output':
        body['spec']['outputs'] = ['zero']; body['evidence'].append(dict(path='outputs/zero',sha256=sha(b''),byte_count=0))
        term.update(status_source='bwrap-adapter',reason='adapter-exited',adapter_exit_code=7,exit_code=None)
        runtime.update(platform='linux',stream_source='bwrap-adapter')
        return {'outputs/zero':b''}


@pytest.mark.parametrize('damage',_PROBE_CORRUPTIONS)
def test_coherently_resealed_probe_malformed_facts_refuse_even_inconclusive(probe,tmp_path,monkeypatch,damage):
    executable(probe,monkeypatch,"print('recorded fact')")
    sealed = probe_run(probe)
    sealed = reseal_probe(probe,sealed,lambda body:corrupt_probe(body,damage))
    item = probe_item(probe,sealed,tmp_path,outcome='inconclusive')
    before = state(probe[0][0])
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    assert state(probe[0][0]) == before


@pytest.mark.parametrize('failure',['timeout','signal','output-limit'])
def test_real_failed_probe_is_inconclusive_only(probe,tmp_path,monkeypatch,failure):
    from tests.test_firmware_dive_probe import save as save_probe
    if failure == 'timeout':
        probe[2]['timeout_seconds'] = 1; program = 'import time; time.sleep(10)'
    elif failure == 'signal': program = 'import os,signal; os.kill(os.getpid(),signal.SIGTERM)'
    else:
        probe[2]['outputs'] = ['limit']; program = "import pathlib,sys,signal; signal.signal(signal.SIGXFSZ,signal.SIG_DFL); pathlib.Path(sys.argv[2],'limit').write_bytes(b'x'*(9*1024*1024))"
    save_probe(probe); executable(probe,monkeypatch,program)
    sealed = probe_run(probe)
    body = json.loads(pathlib.Path(sealed.manifest_path).read_bytes())
    assert body['termination']['reason'] == failure and body['termination']['executed']
    item = probe_item(probe,sealed,tmp_path)
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    item[2]['questions'][0].update(outcome='inconclusive',resolution_effect=None); save(item)
    record(item)


@pytest.mark.parametrize('code',[0,7,143])
def test_clean_direct_voluntary_exit_is_not_decoded_as_signal(probe,tmp_path,monkeypatch,code):
    executable(probe,monkeypatch,f"print('fact'); raise SystemExit({code})")
    sealed = probe_run(probe)
    item = probe_item(probe,sealed,tmp_path)
    assert validate(item).observation['evidence_rung'] == 'emulated-observed'
    record(item)


def test_clean_truncated_stream_preserves_conclusive_eligibility(probe,tmp_path,monkeypatch):
    executable(probe,monkeypatch,"print('x'*(1024*1024+1))")
    sealed = probe_run(probe)
    assert json.loads(pathlib.Path(sealed.manifest_path).read_bytes())['termination']['stdout_truncated']
    record(probe_item(probe,sealed,tmp_path))


@pytest.mark.parametrize('backend',['bwrap','sandbox-exec'])
@pytest.mark.parametrize('code',[0,143,'signal','timeout','output-limit','unavailable'])
def test_builder_native_adapter_contract_and_clean_conclusive_control(probe,tmp_path,monkeypatch,backend,code):
    from audit_core import firmware_dive_acquisition as acq
    from tests.test_firmware_dive_probe import save as save_probe
    probe[2]['isolation_backend'] = backend; save_probe(probe)
    tool = tmp_path/backend; tool.write_bytes(b'purpose fixture adapter')
    monkeypatch.setattr(acq.sys,'platform','linux' if backend == 'bwrap' else 'darwin')
    monkeypatch.setattr(acq,'_select_adapter',lambda spec:acq._IsolationAdapter(backend,tool))
    monkeypatch.setattr(acq,'_adapter_ready',lambda adapter:True)
    termination = (acq.ProbeTermination(False,'tool-unavailable',None,None,False,False,False) if code == 'unavailable' else
        acq.ProbeTermination(True,code,None,25 if code == 'output-limit' else 9 if code == 'timeout' else 15,code == 'timeout',False,False) if isinstance(code,str) else
        acq.ProbeTermination(True,'exited',code,None,False,False,False))
    monkeypatch.setattr(acq,'_process',lambda *a,**k:(termination,b'native fact' if termination.executed else b'',b''))
    sealed = probe_run(probe)
    item = probe_item(probe,sealed,tmp_path)
    if code:
        with pytest.raises(results.FirmwareDiveResultError): record(item)
        item[2]['questions'][0].update(outcome='inconclusive',resolution_effect=None); save(item)
    record(item)


_JSON_ENCODINGS=['utf-8-sig','utf-16-le','utf-16-be','utf-32-le','utf-32-be']
@pytest.mark.parametrize('encoding',_JSON_ENCODINGS)
@pytest.mark.parametrize('text',['{"schema_version":true,"questions":[]}','0','null','"scalar"'])
def test_json_byte_encodings_never_use_legacy_opaque_fallback(tmp_path,encoding,text):
    raw = text.encode(encoding)
    with pytest.raises(results.FirmwareDiveResultError):
        results._historical_projection(tmp_path,raw,{},None,{'result_path':'artifacts/test-dive/legacy'},None,[],())


@pytest.mark.parametrize('encoding',_JSON_ENCODINGS)
def test_prepare_rejects_encoded_envelope_in_existing_opaque_history(graph_case,encoding):
    from tests.test_firmware_dive_prepare import accepted
    complete(graph_case); generation = prepare(graph_case)
    question,observation = accepted(graph_case,generation)
    con,run = graph_case[:2]
    raw = '{"schema_version":true,"questions":[]}'.encode(encoding)
    (run/observation['artifact_path']).write_bytes(raw)
    con.execute('UPDATE cba_firmware_dive_observations SET artifact_sha256=? WHERE question_id=?',(sha(raw),question['question_id']))
    con.execute('UPDATE cba_firmware_dive_receipts SET result_sha256=? WHERE question_id=?',(sha(raw),question['question_id'])); con.commit()
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError): prepare(graph_case)
    assert state(con) == before


def test_true_nonjson_legacy_bytes_keep_opaque_control(tmp_path):
    assert results._historical_projection(tmp_path,b'opaque historical bytes\x00',{},None,{'result_path':'artifacts/test-dive/legacy'},None,[],()) is None


def test_clean_probe_cannot_launder_cited_real_timeout(probe,tmp_path,monkeypatch):
    from tests.test_firmware_dive_probe import save as save_probe
    executable(probe,monkeypatch,"print('clean fact')")
    clean = probe_run(probe)
    probe[2]['timeout_seconds'] = 1; save_probe(probe)
    executable(probe,monkeypatch,'import time; time.sleep(10)')
    failed = probe_run(probe)
    item = probe_item(probe,clean,tmp_path)
    answer = item[2]['questions'][0]
    relative = pathlib.Path(failed.manifest_path).relative_to(probe[0][1]).as_posix()
    raw = pathlib.Path(failed.manifest_path).read_bytes()
    answer['dependencies'].append(dict(kind='probe-manifest',logical_id=failed.acquisition_id,relative_path=relative,sha256=sha(raw),byte_count=len(raw)))
    answer['dependencies'].sort(key=lambda row:(row['kind'],row['logical_id'],row['relative_path'],row['sha256'],row['byte_count']))
    answer['evidence'].append(dict(dependency_kind='probe-manifest',dependency_logical_id=failed.acquisition_id,reference='probe:'+failed.acquisition_id+'#evidence/stdout'))
    answer['evidence'].sort(key=canonical); save(item)
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    answer['evidence'] = [e for e in answer['evidence'] if e['dependency_logical_id'] == clean.acquisition_id]; save(item)
    record(item)


def test_native_runtime_platform_requires_exact_builder_value(probe,tmp_path,monkeypatch):
    executable(probe,monkeypatch,"print('fact')")
    sealed = probe_run(probe)
    def mutate(body):
        body['termination'].update(status_source='bwrap-adapter',reason='adapter-exited',adapter_exit_code=0,exit_code=None)
        body['runtime'].update(platform='linux-invented',stream_source='bwrap-adapter')
    sealed = reseal_probe(probe,sealed,mutate)
    with pytest.raises(results.FirmwareDiveResultError): record(probe_item(probe,sealed,tmp_path,outcome='inconclusive'))


@pytest.mark.parametrize('raw',[b'\xffopaque\x00\xff',b'not JSON at all'])
def test_invalid_unicode_or_plain_opaque_history_retains_control(tmp_path,raw):
    assert results._historical_projection(tmp_path,raw,{},None,{'result_path':'artifacts/test-dive/legacy'},None,[],()) is None


@pytest.mark.parametrize('encoding',['utf-8','utf-8-sig','utf-16','utf-32'])
def test_malformed_encoded_object_never_downgrades_to_opaque(tmp_path,encoding):
    with pytest.raises(results.FirmwareDiveResultError):
        results._historical_projection(tmp_path,'{broken'.encode(encoding),{},None,{'result_path':'artifacts/test-dive/legacy'},None,[],())


@pytest.mark.parametrize('failure',['missing-helper','drifting-helper','unsupported-limits','unsupported-runner','adapter-unready'])
def test_exact_builder_early_refusals_and_helper_drift_remain_inconclusive(probe,tmp_path,monkeypatch,failure):
    from audit_core import firmware_dive_acquisition as acq
    from tests.test_firmware_dive_probe import save as save_probe
    backend = 'bwrap' if failure in ('unsupported-runner','adapter-unready') else 'sandbox-exec'
    probe[2].update(isolation_backend=backend,environment={'MODE':'fixture'} if backend == 'sandbox-exec' else {})
    if failure == 'unsupported-runner':
        runner = tmp_path/'runner'; runner.write_bytes(b'not a static ELF'); probe[2]['runner'] = str(runner)
    save_probe(probe)
    tool = tmp_path/backend; tool.write_bytes(b'fixture tool')
    monkeypatch.setattr(acq.sys,'platform','linux' if backend == 'bwrap' else 'darwin')
    monkeypatch.setattr(acq,'_select_adapter',lambda spec:acq._IsolationAdapter(backend,tool))
    monkeypatch.setattr(acq,'_adapter_ready',lambda adapter:False)
    monkeypatch.setattr(acq,'_limits_available',lambda:failure != 'unsupported-limits')
    calls = 0
    def helper():
        nonlocal calls
        calls += 1
        return (b'not-macho',(1,2,3)) if failure == 'drifting-helper' and calls == 1 else (None,None)
    monkeypatch.setattr(acq,'_environment_launcher',helper)
    monkeypatch.setattr(acq,'_process',lambda *a,**k:pytest.fail('early refusal executed tooling'))
    sealed = probe_run(probe)
    term = json.loads(pathlib.Path(sealed.manifest_path).read_bytes())['termination']
    assert not term['executed']
    assert term['reason'] == ('unsupported-helper' if 'helper' in failure else 'isolation-unavailable' if failure == 'adapter-unready' else failure)
    item = probe_item(probe,sealed,tmp_path)
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    item[2]['questions'][0].update(outcome='inconclusive',resolution_effect=None); save(item)
    record(item); validate(item)


def test_builder_aliases_share_exact_guest_file_facts(probe,tmp_path,monkeypatch):
    from tests.test_firmware_dive_probe import save as save_probe
    probe[2].update(libraries=['a'],inputs=['a'],loader='a',nvram_shim='a',stdin='a'); save_probe(probe)
    executable(probe,monkeypatch,"print('aliased fact')")
    sealed = probe_run(probe)
    record(probe_item(probe,sealed,tmp_path))


@pytest.mark.parametrize('damage',['aggregate-bytes','aggregate-files'])
def test_resealed_staged_input_aggregates_cannot_exceed_builder_limits(probe,tmp_path,monkeypatch,damage):
    executable(probe,monkeypatch,"print('fact')")
    sealed = probe_run(probe)
    def mutate(body):
        deps = body['dependencies']
        paths = ['extra'] if damage == 'aggregate-bytes' else [f'input{i:03}' for i in range(256)]
        body['spec']['inputs'] = paths
        if damage == 'aggregate-bytes': deps[0]['before']['byte_count'] = deps[0]['after']['byte_count'] = 40*1024*1024
        for ordinal,path in enumerate(paths):
            row = copy.deepcopy(deps[0]); row.update(role='input',path=path); deps.insert(ordinal+1,row)
    sealed = reseal_probe(probe,sealed,mutate)
    with pytest.raises(results.FirmwareDiveResultError): record(probe_item(probe,sealed,tmp_path,outcome='inconclusive'))


@pytest.mark.parametrize('raw',[b'{"schema_version":\xff}',b'[\xff]'])
def test_undecodable_ascii_envelope_prefix_never_uses_opaque_fallback(tmp_path,raw):
    with pytest.raises(results.FirmwareDiveResultError):
        results._historical_projection(tmp_path,raw,{},None,{'result_path':'artifacts/test-dive/legacy'},None,[],())


def test_builder_many_role_aliases_preserve_unique_staged_file_limit(probe):
    from audit_core import firmware_dive_acquisition as acq
    parsed = acq.load_probe_spec(probe[1])
    paths = ['a',*[f'p{i:03}' for i in range(255)]]
    spec = dataclasses.replace(parsed,libraries=tuple(paths),inputs=tuple(paths))
    dependencies = [('executable','a',None,b'guest'),*[('library',path,None,b'guest') for path in paths],*[('input',path,None,b'guest') for path in paths]]
    inputs = (spec,b'',None,tuple(dependencies))
    summary,contents,row = acq._probe_build(probe[0][1],inputs,acq.ProbeTermination(False,'isolation-unavailable',None,None,False,False,False),b'',b'',{},inputs)
    dive._install(pathlib.Path(summary.manifest_path).parent,contents,probe[0][1])
    question = next(r for r in rows(probe[0][0],'cba_firmware_dive_questions') if r['question_id'] == spec.question_id)
    packet = json.loads((probe[0][1]/question['packet_path']).read_bytes())
    provenance,paths,manifest = results._sealed_acquisition(probe[0][1],row,packet)
    assert len(manifest['dependencies']) == 513
    assert provenance['logical_id'] == summary.acquisition_id


_STAGED_TOPOLOGY_STATES = ['direct-exited','native-exited','adapter-unready','native-limits','direct-tool-unavailable','native-tool-unavailable']
_NATIVE_TOPOLOGY_STATES = ['native-exited','adapter-unready','native-limits','native-tool-unavailable']


def topology_probe(body, state, shape, role='input'):
    spec = body['spec']
    spec.update(executable='a',argv=['a'],libraries=[],inputs=[],loader=None,nvram_shim=None,stdin=None,
        runner=None,environment={},isolation_backend='bwrap',user_namespace_policy='isolated-nested-disabled')
    guest = [('executable','a')]
    runner = shape.startswith('runner-') or state == 'early-runner'
    helper = shape.startswith('helper-') or state == 'early-helper'
    if shape in ('descendant','ancestor','alias'):
        executable_path,other_path = ('a/child','a') if shape == 'ancestor' else ('a','a' if shape == 'alias' else 'a/child')
        spec.update(executable=executable_path,argv=[executable_path])
        guest = [('executable',executable_path),(role,other_path)]
    else:
        prefix = '_runner' if shape.startswith(('runner-','absent-runner-')) else '_environment-launcher'
        suffix = '/child' if shape.endswith('child') else '-sibling/child' if shape.endswith('sibling') else ''
        path = prefix+suffix
        spec.update(executable=path,argv=[path]); guest = [('executable',path)]
    for kind,path in guest[1:]:
        if kind in ('input','library'): spec['inputs' if kind == 'input' else 'libraries'] = [path]
        else: spec[{'nvram-shim':'nvram_shim'}.get(kind,kind)] = path
    if runner: spec['runner'] = 'verified-runner'
    if helper:
        spec.update(isolation_backend='sandbox-exec',user_namespace_policy='not-applicable',environment={'MODE':'fixture'})
    native = state in _NATIVE_TOPOLOGY_STATES
    executed = state in ('direct-exited','native-exited')
    reason = {'direct-exited':'exited','native-exited':'adapter-exited','adapter-unready':'isolation-unavailable',
        'native-limits':'unsupported-limits','direct-tool-unavailable':'tool-unavailable','native-tool-unavailable':'tool-unavailable',
        'early-none':'isolation-unavailable','early-limits':'unsupported-limits','early-helper':'unsupported-helper','early-runner':'unsupported-runner'}[state]
    source = spec['isolation_backend']+'-adapter' if native else 'direct-process'
    body['termination'] = dict(executed=executed,reason=reason,exit_code=0 if executed and not native else None,
        signal=None,timed_out=False,stdout_truncated=False,stderr_truncated=False,
        adapter_exit_code=0 if executed and native else None,adapter_signal=None,status_source=source)
    body['runtime'].update(platform='darwin' if helper else 'linux' if native else body['runtime']['platform'],
        stream_source=source if executed else 'not-executed',
        system_read_roots=['/System','/usr/lib','/private/var/db/dyld','/dev/null','/dev/urandom'] if helper else [],
        limitation='Apple system runtime reads are not firmware library evidence' if helper else None)
    fact = dict(sha256=sha(b'guest'),byte_count=5)
    ordered = [('executable',spec['executable']),*[('library',path) for path in spec['libraries']],*[('input',path) for path in spec['inputs']]]
    ordered += [(kind,spec[key]) for kind,key in (('loader','loader'),('nvram-shim','nvram_shim'),('stdin','stdin')) if spec[key] is not None]
    if runner: ordered.append(('runner',None))
    if state != 'early-none': ordered.append(('adapter',None))
    if helper: ordered.append(('environment-launcher',None))
    body['dependencies'] = [dict(role=kind,path=path,before=None if kind == 'environment-launcher' and state == 'early-helper' else copy.deepcopy(fact),
        after=None if kind == 'environment-launcher' and state == 'early-helper' else copy.deepcopy(fact)) for kind,path in ordered]


_TOPOLOGY_COLLISIONS = [(state,shape,'input') for state in _STAGED_TOPOLOGY_STATES for shape in ('descendant','ancestor','runner-exact','runner-child')]
_TOPOLOGY_COLLISIONS += [(state,shape,'input') for state in _NATIVE_TOPOLOGY_STATES for shape in ('helper-exact','helper-child')]
_TOPOLOGY_COLLISIONS += [('direct-exited',shape,role) for shape in ('descendant','ancestor') for role in ('library','loader','nvram-shim','stdin')]
@pytest.mark.parametrize('state_name,shape,role',_TOPOLOGY_COLLISIONS)
def test_resealed_staged_topology_cannot_claim_impossible_regular_files(probe,tmp_path,state_name,shape,role):
    sealed = probe_run(probe)
    sealed = reseal_probe(probe,sealed,lambda body:topology_probe(body,state_name,shape,role))
    item = probe_item(probe,sealed,tmp_path,outcome='supported' if state_name in ('direct-exited','native-exited') else 'inconclusive')
    before = state(probe[0][0])
    with pytest.raises(results.FirmwareDiveResultError): record(item)
    assert state(probe[0][0]) == before


_TOPOLOGY_CONTROLS = [(state,shape) for state in _STAGED_TOPOLOGY_STATES for shape in
    ('alias','absent-runner-exact','absent-runner-child','absent-helper-exact','absent-helper-child','runner-sibling')]
_TOPOLOGY_CONTROLS += [(state,'helper-sibling') for state in _NATIVE_TOPOLOGY_STATES]
@pytest.mark.parametrize('state_name,shape',_TOPOLOGY_CONTROLS)
def test_resealed_staged_aliases_and_unreserved_names_remain_valid(probe,tmp_path,state_name,shape):
    sealed = probe_run(probe)
    sealed = reseal_probe(probe,sealed,lambda body:topology_probe(body,state_name,shape))
    item = probe_item(probe,sealed,tmp_path,outcome='supported' if state_name in ('direct-exited','native-exited') else 'inconclusive')
    record(item); validate(item)


_EARLY_TOPOLOGY_CONTROLS = [(state,shape) for state in ('early-none','early-limits','early-helper','early-runner') for shape in
    ('descendant','ancestor','runner-exact','runner-child')]
_EARLY_TOPOLOGY_CONTROLS += [(state,shape) for state in ('early-limits','early-helper') for shape in ('helper-exact','helper-child')]
@pytest.mark.parametrize('state_name,shape',_EARLY_TOPOLOGY_CONTROLS)
def test_true_pre_staging_refusal_keeps_unrealized_topology(probe,tmp_path,state_name,shape):
    sealed = probe_run(probe)
    sealed = reseal_probe(probe,sealed,lambda body:topology_probe(body,state_name,shape))
    item = probe_item(probe,sealed,tmp_path,outcome='inconclusive')
    record(item); validate(item)


@pytest.mark.parametrize('collision',['guest-prefix','reserved-runner'])
def test_task6_stager_independently_rejects_reviewer_topologies(tmp_path,collision):
    from audit_core import firmware_dive_acquisition as acq
    staged = tmp_path/'stage'; staged.mkdir()
    deps = [('executable','a',None,b'guest'),('input','a/child',None,b'guest')] if collision == 'guest-prefix' else [
        ('executable','_runner',None,b'guest'),('runner','unused-host-identity',None,b'runner')]
    with pytest.raises((dive.FirmwareDiveError,acq.AcquisitionError)):
        acq._stage_probe(staged,deps)
