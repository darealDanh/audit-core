"""Independent completion, immutable journals and transactional overlay feedback."""
import dataclasses
import json
import pathlib
import sqlite3

import pytest

from audit_core import firmware_chain, firmware_fpcheck, firmware_dive as dive
from audit_core import firmware_dive_results as results
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_prepare import prepare, rows, files, canonical, sha
from tests.test_firmware_dive_import import build, record, save
from tests.test_hunt_gate import state



def complete(case):
    from tests.test_firmware_chain_import import blocked, record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    blocked(case)
    case[3]['blockers'][0]['method'] = 'static'
    case[3]['chains'][0]['edges'][1]['existing_unknowns'] = [dict(unknown_id='overlap',axes=['authentication'])]
    chain_record(case)
    return chain_check(case)


def check(case, con=None):
    helper = getattr(dive, 'check', None)
    assert callable(helper), 'Task 9 independent completion is missing'
    return helper(con or case[0], *case[1:3], image_id='target')


def overlay(case, con=None, snapshot=None):
    helper = getattr(dive, 'current_overlay', None)
    assert callable(helper), 'Task 9 current overlay is missing'
    snapshot = snapshot or firmware_fpcheck.verified_findings_snapshot(*case[:3], image_id='target')
    return helper(con or case[0], *case[1:3], snapshot)


def populate(case, tmp_path, outcome='inconclusive', generation=None):
    selected = [r for r in rows(case[0], 'cba_firmware_dive_questions') if generation is None or r['dive_generation'] == generation]
    for n, question in enumerate(selected):
        directory = tmp_path / str(n)
        directory.mkdir(exist_ok=True)
        answer = outcome if question['method'] == 'static' and json.loads((case[1]/question['packet_path']).read_bytes())['question']['resolution_contract']['mode'] == 'boolean-claim' else 'inconclusive'
        item = build(case, question, directory, outcome=answer)
        if answer == 'refuted':
            effect = item[2]['questions'][0]['resolution_effect']
            effect['value'] = 'refuted' if effect['predicate'] == 'reachability' else False
            save(item)
        record(item)


@pytest.fixture
def pending(graph_case, tmp_path):
    complete(graph_case)
    prepare(graph_case)
    populate(graph_case, tmp_path)
    return graph_case


def test_empty_overlay_literal_and_verified_snapshot_boundary(graph_case):
    complete(graph_case)
    before, artifacts = state(graph_case[0]), files(graph_case[1])
    value = overlay(graph_case)
    assert canonical(dataclasses.asdict(value)) == b'{"observations":[],"schema_version":1}'
    upstream = firmware_fpcheck.verified_findings_snapshot(*graph_case[:3], image_id='target')
    with pytest.raises(dive.FirmwareDiveError):
        overlay(graph_case, snapshot=dataclasses.replace(upstream, candidate_snapshot_sha256='a'*64))
    assert state(graph_case[0]) == before and files(graph_case[1]) == artifacts


@pytest.mark.parametrize('outcome', ['supported', 'refuted', 'inconclusive'])
def test_complete_exact_denominator_journal_overlay_and_readonly_recheck(graph_case, tmp_path, outcome):
    complete(graph_case)
    prepared_run = prepare(graph_case)
    populate(graph_case, tmp_path, outcome)
    result = check(graph_case)
    assert result.complete and result.question_count == prepared_run.question_count
    assert result.supported_count + result.refuted_count + result.inconclusive_count == result.question_count
    owner, = rows(graph_case[0], 'cba_firmware_dive_runs')
    journal = pathlib.Path(result.journal_path)
    assert journal == graph_case[1] / 'artifacts/firmware-dive' / prepared_run.dive_generation / result.journal_sha256 / 'journal.json'
    assert sha(journal.read_bytes()) == result.journal_sha256
    body = json.loads(journal.read_bytes())
    for name in ('questions','receipts','observations','dependencies','acquisitions'):
        assert body[name] == rows(graph_case[0], 'cba_firmware_dive_'+name)
    assert body['completed_at'] == owner['completed_at']
    accepted = overlay(graph_case)
    assert len(accepted.observations) == (0 if outcome == 'inconclusive' else 1)
    assert bool(rows(graph_case[0], 'cba_firmware_chain_runs')) == (outcome == 'inconclusive')
    before, artifacts, changes = state(graph_case[0]), files(graph_case[1]), graph_case[0].total_changes
    assert check(graph_case) == result
    readonly = sqlite3.connect('file:'+str(graph_case[1]/'audit.db')+'?mode=ro', uri=True)
    readonly.row_factory = sqlite3.Row
    try:
        assert check(graph_case, readonly) == result
        readonly.execute('BEGIN')
        assert overlay(graph_case, readonly) == accepted and readonly.in_transaction
        readonly.rollback()
    finally:
        readonly.close()
    assert state(graph_case[0]) == before and files(graph_case[1]) == artifacts and graph_case[0].total_changes == changes


@pytest.mark.parametrize('table,column,value', [
    ('runs','question_count',99), ('runs','supported_count',1), ('runs','chain_blocker_count',99),
    ('runs','retry_count',99), ('questions','recorded_at',''), ('receipts','recorded_at',''),
    ('observations','recorded_at',''), ('dependencies','recorded_at',''),
    ('observations','conclusion','forged'), ('observations','successor_questions','[] '),
    ('receipts','dependency_count',99), ('dependencies','source_provenance','{}')])
def test_pending_reconstructs_every_row_without_repair(pending, table, column, value):
    con, run = pending[:2]
    con.execute(f'UPDATE cba_firmware_dive_{table} SET {column}=?', (value,)); con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('table', ['questions','receipts','observations','dependencies'])
def test_missing_denominator_never_completes(pending, table):
    con, run = pending[:2]
    con.execute(f'DELETE FROM cba_firmware_dive_{table} WHERE rowid=(SELECT min(rowid) FROM cba_firmware_dive_{table})'); con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('table,column', [('runs','prepared_at'),('runs','completed_at'),('questions','recorded_at'),
    ('receipts','recorded_at'),('observations','recorded_at'),('dependencies','recorded_at')])
def test_completed_journal_binds_exact_timestamps(pending, table, column):
    check(pending)
    con, run = pending[:2]
    con.execute(f"UPDATE cba_firmware_dive_{table} SET {column}='2000-01-01 00:00:00'"); con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('name', ['journal','packet','result','graph'])
def test_completed_artifact_corruption_is_not_repaired(pending, name):
    result = check(pending)
    con, run = pending[:2]
    paths = dict(journal=result.journal_path, packet=rows(con,'cba_firmware_dive_questions')[0]['packet_path'],
        result=rows(con,'cba_firmware_dive_receipts')[0]['result_path'], graph=rows(con,'cba_firmware_dive_runs')[0]['chain_graph_path'])
    (run / paths[name]).write_bytes(b'{}')
    before, artifacts = state(con), files(run)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('table', ['cba_firmware_dive_runs', *firmware_chain._COMPLETION_TABLES])
def test_completion_and_every_chain_deletion_roll_back_together(graph_case, tmp_path, table):
    complete(graph_case); prepare(graph_case); populate(graph_case,tmp_path,'supported')
    con = graph_case[0]
    operation = 'UPDATE' if table == 'cba_firmware_dive_runs' else 'DELETE'
    con.execute(f"CREATE TRIGGER refuse BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'refused'); END")
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError): check(graph_case)
    assert state(con) == before and not con.in_transaction
    assert rows(con,'cba_firmware_dive_runs')[0]['status'] == 'pending'
    assert rows(con,'cba_firmware_chain_runs')[0]['status'] == 'complete'


def test_source_change_between_install_and_lock_aborts(pending, monkeypatch):
    original = dive._install
    def race(destination, contents, run):
        original(destination, contents, run)
        if 'journal.json' in contents:
            pending[0].execute("UPDATE cba_firmware_dive_questions SET recorded_at='raced'")
            pending[0].commit()
    monkeypatch.setattr(dive,'_install',race)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert rows(pending[0],'cba_firmware_dive_runs')[0]['status'] == 'pending'
    assert rows(pending[0],'cba_firmware_chain_runs')[0]['status'] == 'complete'


def regenerate(case):
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    prepared_chain = firmware_chain.prepare(*case[:3], image_id='target')
    case[3].update(worklist_sha256=prepared_chain.worklist_sha256,candidate_snapshot_sha256=prepared_chain.candidate_snapshot_sha256)
    chain_record(case, root=case[2]); chain_check(case)


def test_retry_deduplicates_then_conflict_excludes_without_timestamp_winner(graph_case,tmp_path):
    from tests.test_firmware_dive_prepare import retry_manifest
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    chain_record(graph_case); chain_check(graph_case)
    path = retry_manifest(graph_case)
    first = prepare(graph_case, questions_path=path); populate(graph_case,tmp_path,'supported')
    check(graph_case)
    before = overlay(graph_case)
    static = next(r for r in rows(graph_case[0],'cba_firmware_dive_questions') if r['origin']=='analyst')
    regenerate(graph_case)
    second = prepare(graph_case,questions_path=path,retry=[static['question_id']])
    populate(graph_case,tmp_path,'supported',second.dive_generation)
    check(graph_case)
    assert overlay(graph_case) == before
    assert rows(graph_case[0],'cba_firmware_chain_runs')
    third = prepare(graph_case,questions_path=path,retry=[static['question_id']])
    populate(graph_case,tmp_path,'refuted',third.dive_generation)
    summary = check(graph_case)
    assert overlay(graph_case).observations == () and summary.contested_count == 1
    assert not rows(graph_case[0],'cba_firmware_chain_runs')
    resolution = prepare(graph_case)
    assert resolution.conflict_count == 1
    populate(graph_case,tmp_path,'supported',resolution.dive_generation)
    check(graph_case)
    accepted = overlay(graph_case).observations
    assert len(accepted) == 1 and accepted[0].question_id != static['question_id']
    assert len(rows(graph_case[0],'cba_firmware_dive_runs')) == 4


@pytest.mark.parametrize('legacy',[False,True])
def test_empty_requires_receipt_then_completes_truthfully(graph_case,tmp_path,legacy):
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    con,run = graph_case[:2]
    root = tmp_path/'empty-root'
    empty_review(con,run,root,'empty')
    chain = firmware_chain.prepare(con,run,root,image_id='empty')
    case = (con,run,root,dict(schema_version=1,image_id='empty',candidate_snapshot_sha256=chain.candidate_snapshot_sha256,
        worklist_sha256=chain.worklist_sha256,blockers=[],dispositions=[],chains=[]),{})
    chain_record(case); chain_check(case,image_id='empty')
    generation = dive.prepare(con,run,root,image_id='empty')
    helper = getattr(dive,'check',None)
    assert callable(helper), 'Task 9 completion missing'
    with pytest.raises(dive.FirmwareDiveError): helper(con,run,root,image_id='empty')
    path = tmp_path/'empty.json'
    path.write_bytes(canonical(dict(schema_version=1,image_id='empty',dive_generation=generation.dive_generation,questions=[])))
    results.record(con,run,path)
    if legacy:
        path = run/'artifacts/legacy-empty.bin'; path.write_bytes(b'opaque empty receipt')
        con.execute("UPDATE cba_firmware_dive_receipts SET result_path=?,result_sha256=? WHERE image_id='empty'",(path.relative_to(run).as_posix(),sha(path.read_bytes())))
        con.commit()
    summary = helper(con,run,root,image_id='empty')
    assert summary.complete and summary.question_count == 0 and summary.questions == ()
    assert rows(con,'cba_firmware_chain_runs','empty')
    assert len(json.loads(pathlib.Path(summary.journal_path).read_bytes())['receipts']) == 1


def test_multiple_pending_generations_refuse_ambiguous_selector(pending,tmp_path):
    from tests.test_firmware_dive_prepare import manifest
    from tests.test_firmware_dive_questions import entry
    from tests.test_firmware_dive_snapshot import snapshot
    prepare(pending,questions_path=manifest(tmp_path,[entry(snapshot(pending))]))
    before,artifacts = state(pending[0]),files(pending[1])
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(pending[0]) == before and files(pending[1]) == artifacts


@pytest.mark.parametrize('prior_current,new_current',[(False,False),(False,True),(True,False),(True,True)])
def test_identical_attempt_coalesces_only_recomputed_currentness(pending,prior_current,new_current):
    from audit_core import firmware_dive_questions as q
    question = dive._question(json.loads((pending[1]/rows(pending[0],'cba_firmware_dive_questions')[0]['packet_path']).read_bytes())['question'])
    observed = q.QuestionHistory(question,1,'a'*64,'inconclusive',None,(),(),prior_current)
    later = dataclasses.replace(observed,dependency_current=new_current)
    helper = getattr(dive,'_coalesce_attempt',None)
    assert callable(helper),'Exact-attempt currentness coalescing is missing'
    assert helper(observed,later) == dataclasses.replace(observed,dependency_current=prior_current or new_current)
    empty = q.QuestionHistory(question,1,None,None,None,(),(),False)
    assert helper(observed,empty) == observed and helper(empty,observed) == observed
    for changed in (dataclasses.replace(later,observation_id='b'*64),dataclasses.replace(later,question=dataclasses.replace(question,question='changed'))):
        with pytest.raises(dive.FirmwareDiveError): helper(observed,changed)


@pytest.mark.parametrize('damage',['none','details','timestamp','manifest','evidence'])
def test_full_capture_reconstruction_including_uncited_acquisitions(capture,tmp_path,damage):
    from tests.test_firmware_dive_capture import seal
    case = capture[0]
    acquired = seal(capture)
    populate(case,tmp_path)
    con,run = case[:2]
    row = rows(con,'cba_firmware_dive_acquisitions')[0]
    if damage in ('details','timestamp'):
        column,value = ('details','{}') if damage == 'details' else ('recorded_at','')
        con.execute(f'UPDATE cba_firmware_dive_acquisitions SET {column}=?',(value,)); con.commit()
    elif damage == 'manifest': (run/row['manifest_path']).write_bytes(b'{}')
    elif damage == 'evidence': (run/json.loads(row['evidence_paths'])[0]).write_bytes(b'changed')
    if damage == 'none':
        assert check(case).complete
        assert check(case).complete
    else:
        before = state(con)
        with pytest.raises(dive.FirmwareDiveError): check(case)
        assert state(con) == before


@pytest.mark.parametrize('kind',['probe','capture'])
def test_dynamic_conclusions_use_reconstructed_acquisitions(request,tmp_path,monkeypatch,kind):
    from tests.test_firmware_dive_probe import executable,run as run_probe
    from tests.test_firmware_dive_capture import seal
    chosen = request.getfixturevalue(kind)
    case = chosen[0]
    if kind == 'probe':
        executable(chosen,monkeypatch,"print('bounded observation')")
        acquired = run_probe(chosen)
    else: acquired = seal(chosen)
    generation = chosen[2]['dive_generation']
    for n,question in enumerate(rows(case[0],'cba_firmware_dive_questions')):
        if question['dive_generation'] != generation: continue
        directory = tmp_path / ('dynamic-'+str(n)); directory.mkdir()
        selected = question['question_id'] == chosen[2]['question_id']
        item = build(case,question,directory,acquired if selected else None,'supported' if selected else 'inconclusive')
        record(item)
    assert check(case).complete
    assert any(i.evidence_rung == ('emulated-observed' if kind == 'probe' else 'hardware-observed') for i in overlay(case).observations)


def test_stale_completed_history_uses_retained_worklist_and_never_repairs(pending,tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    first = check(pending)
    con,run,root = pending[:3]
    con.execute("DELETE FROM cba_images WHERE id='target'")
    con.execute("DELETE FROM cba_firmware_files WHERE image_id='target'")
    con.execute('DELETE FROM cba_inventory'); con.commit()
    root = tmp_path/'replacement-root'
    empty_review(con,run,root,'target')
    pending = (con,run,root,*pending[3:])
    before,artifacts = state(con),files(run)
    summary = check(pending)
    assert summary.stale_count == summary.question_count and summary.journal_sha256 == first.journal_sha256
    assert not overlay(pending).observations
    assert state(con) == before and files(run) == artifacts


@pytest.mark.parametrize('failure',['install','installed-bytes','commit','unexpected'])
def test_artifact_first_failures_preserve_pending_and_graph(pending,monkeypatch,failure):
    original = dive._install
    if failure in ('install','unexpected'):
        def refuse(*args): raise OSError('install') if failure == 'install' else RuntimeError('unexpected')
        monkeypatch.setattr(dive,'_install',refuse)
    elif failure == 'installed-bytes':
        def corrupt(destination,contents,run):
            original(destination,contents,run)
            (destination/'journal.json').write_bytes(b'{}')
        monkeypatch.setattr(dive,'_install',corrupt)
    con = pending[0]
    selected = con
    if failure == 'commit':
        class CommitFailure:
            def __getattr__(self,name): return getattr(con,name)
            def commit(self): raise sqlite3.OperationalError('injected commit')
        selected = CommitFailure()
    before = state(con)
    with pytest.raises(RuntimeError if failure == 'unexpected' else dive.FirmwareDiveError): check(pending,selected)
    assert state(con) == before and not con.in_transaction


def test_completion_refuses_caller_transaction_and_implicit_selector_is_exact(pending):
    con = pending[0]
    con.execute('BEGIN')
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert con.in_transaction and state(con) == before
    con.rollback()
    assert dive.check(*pending[:3]).complete
    with pytest.raises(dive.FirmwareDiveError): dive.check(*pending[:3],image_id='foreign')


from tests.test_firmware_dive_capture import capture  # noqa: E402,F401
from tests.test_firmware_dive_probe import probe  # noqa: E402,F401


def pure_attempts(pending):
    from audit_core import firmware_dive_questions as q
    owner = rows(pending[0],'cba_firmware_dive_runs')[0] | {'status':'complete'}
    assignment = next(r for r in rows(pending[0],'cba_firmware_dive_questions') if r['origin']=='chain-blocker')
    question = dive._question(json.loads((pending[1]/assignment['packet_path']).read_bytes())['question'])
    observed = next(r for r in rows(pending[0],'cba_firmware_dive_observations') if r['question_id']==question.question_id)
    effect = {k:v for k,v in q._wire(question.resolution_contract).items() if k not in ('expected_value','allowed_values','other_specific')}
    def make(identity,outcome,value,question=question,current=True):
        observation = observed | dict(observation_id=identity*64,outcome=outcome,resolution_effect=canonical(effect | {'value':value}).decode(),evidence_rung='static-resolved')
        return dict(owner=owner,question=question,observation=observation,dependencies=[],current=current,canonical=True)
    return make,question


@pytest.mark.parametrize('case',['agree','conflict','exact','stale-resolver','stale-parent','incompatible','inconclusive'])
def test_set_resolution_is_exact_and_order_independent(pending,case):
    from audit_core import firmware_dive_questions as q
    make,question = pure_attempts(pending)
    a,b = make('a','supported',True),make('b','refuted',False)
    if case == 'agree': b = make('b','supported',True)
    refs = ('a'*64,'b'*64)
    if case == 'partial': refs = ('a'*64,'c'*64)
    if case == 'extra': refs += ('c'*64,)
    conflict = dataclasses.replace(question,question_id='d'*64,origin='conflict',question=q._conflict_text(refs),supersedes_observation_ids=refs)
    values = [a,b]
    if case in ('partial','extra'): values.append(make('c','supported',True,current=case!='extra'))
    if case not in ('agree','conflict'):
        values.append(make('d','supported',True,conflict,current=case!='stale-resolver'))
    if case == 'stale-parent': b['current'] = False
    if case == 'incompatible': values.append(make('e','refuted',False,conflict))
    if case == 'inconclusive': values[-1]['observation'].update(outcome='inconclusive',resolution_effect=None,evidence_rung=None)
    result,_ = dive._overlay(values)
    assert dive._overlay(list(reversed(values)))[0] == result
    expected = {'agree':{'a','b'},'exact':{'d'},'stale-parent':{'d'}}.get(case,set())
    assert {i.observation_id for i in result.observations} == {i*64 for i in expected}

def test_conflict_resolver_preserves_root_blocker_settlement_authority(pending):
    from audit_core import firmware_dive_questions as q
    make, question = pure_attempts(pending)
    refs = ('a' * 64, 'b' * 64)
    conflict = dataclasses.replace(question, question_id='d' * 64,
        origin='conflict', question=q._conflict_text(refs),
        supersedes_observation_ids=refs)
    resolved, contested = dive._overlay([
        make('a', 'supported', True), make('b', 'refuted', False),
        make('d', 'supported', True, conflict)])
    observation, = resolved.observations
    assert not contested
    assert observation.settled_subject_refs == tuple(
        str(ref) for ref in question.subject_refs if ref.kind == 'chain-blocker')



def test_same_question_contract_cannot_change_across_attempts(pending):
    make,question = pure_attempts(pending)
    first = make('a','supported',True)
    changed = dataclasses.replace(question,attempt_ordinal=2,resolution_contract=dataclasses.replace(question.resolution_contract,expected_value=False))
    second = make('b','refuted',True,changed)
    with pytest.raises(dive.FirmwareDiveError): dive._overlay([first,second])


@pytest.mark.parametrize('damage',['none','source','timestamp'])
def test_extract_currentness_is_separate_from_immutable_history(graph_case,tmp_path,damage):
    from tests.test_firmware_dive_prepare import historical_extract
    complete(graph_case)
    historical_extract(graph_case)
    populate(graph_case,tmp_path)
    check(graph_case)
    path = graph_case[1]/'extract/manifest.json'
    value = json.loads(path.read_bytes())
    if damage != 'none':
        value['daemon/gate.c']['source' if damage=='source' else 'extracted_at'] = 'changed'
        path.write_bytes(canonical(value))
    summary = check(graph_case)
    assert summary.stale_count == (1 if damage=='source' else 0)


def test_keyed_worklist_retention_is_required_even_with_current_upstream(pending):
    check(pending)
    for path in (pending[1]/'files/firmware-chain').glob('*/worklist.json'): path.unlink()
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    with pytest.raises(dive.FirmwareDiveError): overlay(pending)


@pytest.mark.parametrize('table',['questions','receipts','observations','dependencies'])
def test_foreign_rows_cannot_reuse_selected_generation(pending,table):
    from audit_core import db
    con = pending[0]
    value = rows(con,'cba_firmware_dive_'+table)[0] | {'image_id':'foreign'}
    db.put(con,'cba_firmware_dive_'+table,value)
    before = state(con)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(con) == before


def test_unindexed_generation_file_is_not_accepted(pending):
    owner = rows(pending[0],'cba_firmware_dive_runs')[0]
    (pending[1]/owner['question_index_path']).with_name('unassigned.json').write_bytes(b'{}')
    before,artifacts = state(pending[0]),files(pending[1])
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert state(pending[0]) == before and files(pending[1]) == artifacts


@pytest.mark.parametrize('damage',['input-overlay','journal-index'])
def test_frozen_history_references_are_reconstructed(pending,damage):
    upstream = firmware_fpcheck.verified_findings_snapshot(*pending[:3],image_id='target')
    _,generations,attempts = dive._reconstruct(*pending[:3],upstream)
    owner,owned,counts,full,index,graph = next(iter(generations.values()))
    if damage == 'input-overlay': index['input_overlay'] = [{'observation_id':'f'*64}]
    else:
        path = pending[1]/owner['journal_input_path']
        body = json.loads(path.read_bytes())
        body['observations'] = [dict(observation_id='f'*64,question_id='a'*64,subject_refs=[],status='stale',outcome='inconclusive',artifact_path='missing.json',artifact_sha256='b'*64)]
        path.write_bytes(canonical(body)); owner['journal_input_sha256'] = sha(path.read_bytes())
    helper = getattr(dive,'_frozen_links',None)
    assert callable(helper),'Frozen history cross-reference reconstruction is missing'
    with pytest.raises(dive.FirmwareDiveError): helper(pending[1],generations,attempts)


def test_completion_rebuilds_contiguous_attempt_history(pending):
    upstream = firmware_fpcheck.verified_findings_snapshot(*pending[:3],image_id='target')
    _,generations,attempts = dive._reconstruct(*pending[:3],upstream)
    attempt = attempts[0]
    attempt['question'] = dataclasses.replace(attempt['question'],attempt_ordinal=9)
    helper = getattr(dive,'_histories',None)
    assert callable(helper),'Independent contiguous history reconstruction is missing'
    with pytest.raises((dive.FirmwareDiveError,ValueError)): helper(pending[1],generations,attempts)


@pytest.mark.parametrize('damage',['none','receipt-count','observation-path','dependency-observation','dependency-provenance'])
def test_opaque_legacy_history_remains_exact_but_never_overlays(graph_case,damage):
    from tests.test_firmware_dive_prepare import accepted
    complete(graph_case)
    generation = prepare(graph_case)
    accepted(graph_case,generation)
    con,run = graph_case[:2]
    con.execute("UPDATE cba_firmware_dive_runs SET status='pending',completed_at=NULL,journal_path=NULL,journal_sha256=NULL,supported_count=0,refuted_count=0,inconclusive_count=0")
    if damage == 'receipt-count': con.execute('UPDATE cba_firmware_dive_receipts SET dependency_count=7')
    elif damage == 'observation-path':
        observation = rows(con,'cba_firmware_dive_observations')[0]
        other = run/'artifacts/legacy-copy.bin'; other.write_bytes((run/observation['artifact_path']).read_bytes())
        con.execute('UPDATE cba_firmware_dive_observations SET artifact_path=? WHERE question_id=?',(other.relative_to(run).as_posix(),observation['question_id']))
    elif damage == 'dependency-observation': con.execute("UPDATE cba_firmware_dive_dependencies SET observation_id=?",('f'*64,))
    elif damage == 'dependency-provenance': con.execute('UPDATE cba_firmware_dive_dependencies SET source_provenance=?',(canonical({'host':'/private/path'}).decode(),))
    con.commit()
    if damage == 'none':
        assert check(graph_case).complete and overlay(graph_case).observations == ()
        assert rows(con,'cba_firmware_chain_runs')
    else:
        before = state(con)
        with pytest.raises(dive.FirmwareDiveError): check(graph_case)
        assert state(con) == before


def test_overlay_before_any_receipt_ignores_pending_denominator(graph_case):
    complete(graph_case); prepare(graph_case)
    before,changes = state(graph_case[0]),graph_case[0].total_changes
    assert overlay(graph_case).observations == ()
    assert state(graph_case[0]) == before and graph_case[0].total_changes == changes


def test_unavailable_stale_worklist_fails_closed(pending,tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    check(pending)
    con,run = pending[:2]
    con.execute("DELETE FROM cba_images WHERE id='target'")
    con.execute("DELETE FROM cba_firmware_files WHERE image_id='target'")
    con.execute('DELETE FROM cba_inventory');con.commit()
    root = tmp_path/'new-root'; empty_review(con,run,root,'target')
    for path in (run/'files/firmware-chain').glob('*/worklist.json'): path.unlink()
    before,artifacts = state(con),files(run)
    with pytest.raises(dive.FirmwareDiveError): dive.check(con,run,root,image_id='target')
    assert state(con) == before and files(run) == artifacts


def test_capture_legacy_opaque_retains_method_checks_but_no_overlay(capture,tmp_path):
    from tests.test_firmware_dive_capture import seal
    acquired = seal(capture)
    case = capture[0]
    for n,question in enumerate(rows(case[0],'cba_firmware_dive_questions')):
        directory = tmp_path/('legacy-dynamic-'+str(n));directory.mkdir()
        selected = question['question_id'] == capture[2]['question_id']
        record(build(case,question,directory,acquired if selected else None,'supported' if selected else 'inconclusive'))
    con,run = case[:2]
    observed = next(r for r in rows(con,'cba_firmware_dive_observations') if r['question_id'] == capture[2]['question_id'])
    path = run/'artifacts/legacy-capture.bin';path.write_bytes(b'opaque hardware receipt')
    identity = observed['question_id'];relative = path.relative_to(run).as_posix();digest = sha(path.read_bytes())
    con.execute('UPDATE cba_firmware_dive_receipts SET result_path=?,result_sha256=? WHERE question_id=?',(relative,digest,identity))
    con.execute('UPDATE cba_firmware_dive_observations SET artifact_path=?,artifact_sha256=?,dependency_refs=?,evidence_refs=? WHERE question_id=?',
        (relative,digest,canonical([sha(canonical(r)) for r in json.loads(observed['dependency_refs'])]).decode(),
         canonical([sha(canonical(r)) for r in json.loads(observed['evidence_refs'])]).decode(),identity));con.commit()
    assert check(case).complete and overlay(case).observations == ()


def test_legacy_completed_history_can_be_referenced_without_current_conclusions(graph_case,tmp_path):
    from tests.test_firmware_dive_prepare import accepted,manifest
    from tests.test_firmware_dive_questions import entry
    from tests.test_firmware_dive_snapshot import snapshot
    complete(graph_case);generation = prepare(graph_case);accepted(graph_case,generation)
    con = graph_case[0]
    con.execute("UPDATE cba_firmware_dive_runs SET status='pending',completed_at=NULL,journal_path=NULL,journal_sha256=NULL,supported_count=0,inconclusive_count=0");con.commit()
    check(graph_case)
    prepare(graph_case,questions_path=manifest(tmp_path,[entry(snapshot(graph_case))]))
    assert overlay(graph_case).observations == ()


@pytest.mark.parametrize('damage',['packet','result','root','counts'])
def test_mutable_inputs_are_rechecked_under_publication_lock(pending,monkeypatch,damage):
    original = dive._install
    con,run,root = pending[:3]
    def race(destination,contents,selected_run):
        original(destination,contents,selected_run)
        if damage == 'packet': (run/rows(con,'cba_firmware_dive_questions')[0]['packet_path']).write_bytes(b'{}')
        elif damage == 'result': (run/rows(con,'cba_firmware_dive_receipts')[0]['result_path']).write_bytes(b'{}')
        elif damage == 'root': (root/'a').write_bytes(b'changed source')
        else:
            con.execute('UPDATE cba_firmware_dive_runs SET supported_count=7');con.commit()
    monkeypatch.setattr(dive,'_install',race)
    with pytest.raises(dive.FirmwareDiveError): check(pending)
    assert rows(con,'cba_firmware_dive_runs')[0]['status']=='pending'
    assert rows(con,'cba_firmware_chain_runs')[0]['status']=='complete'


def test_two_connection_write_contention_rolls_back_only_owned_transaction(pending):
    con,run = pending[:2]
    with sqlite3.connect(run/'audit.db',timeout=0) as reader:
        reader.row_factory = sqlite3.Row
        con.execute('BEGIN IMMEDIATE')
        before = state(con)
        with pytest.raises(dive.FirmwareDiveError,match='database operation failed'): check(pending,reader)
        assert not reader.in_transaction and con.in_transaction and state(con)==before
        con.rollback()


@pytest.mark.parametrize('damage',['invalid-snapshot','corrupt-row','database','unexpected'])
def test_overlay_failure_is_readonly_and_preserves_caller_transaction(pending,monkeypatch,damage):
    con,run = pending[:2]
    upstream = firmware_fpcheck.verified_findings_snapshot(*pending[:3],image_id='target')
    if damage == 'invalid-snapshot': upstream = object()
    elif damage == 'corrupt-row': con.execute("UPDATE cba_firmware_dive_receipts SET dependency_count=99");con.commit()
    elif damage == 'database':
        def fail(*args): raise sqlite3.OperationalError('injected read')
        monkeypatch.setattr(dive,'_rows',fail)
    else:
        def fail(*args,**kwargs): raise RuntimeError('unexpected')
        monkeypatch.setattr(dive,'_reconstruct',fail)
    before,changes = state(con),con.total_changes
    con.execute('BEGIN')
    with pytest.raises(RuntimeError if damage=='unexpected' else dive.FirmwareDiveError): dive.current_overlay(*pending[:3],upstream)
    assert con.in_transaction and state(con)==before and con.total_changes==changes
    con.rollback()


@pytest.mark.parametrize('table,column',['receipts receipt_key'.split(),'observations observation_id'.split()])
def test_legacy_global_ids_cannot_be_reused_by_foreign_image(graph_case,table,column):
    from audit_core import db
    from tests.test_firmware_dive_prepare import accepted
    complete(graph_case);generation=prepare(graph_case);accepted(graph_case,generation)
    con=graph_case[0]
    con.execute("UPDATE cba_firmware_dive_runs SET status='pending',completed_at=NULL,journal_path=NULL,journal_sha256=NULL,supported_count=0,inconclusive_count=0");con.commit()
    row=rows(con,'cba_firmware_dive_'+table)[0] | dict(image_id='foreign',dive_generation='f'*64)
    db.put(con,'cba_firmware_dive_'+table,row)
    with pytest.raises(dive.FirmwareDiveError): check(graph_case)


def conflict_history(pending,active=('a','b','c')):
    from audit_core import firmware_dive_questions as q
    make,question=pure_attempts(pending)
    history=[]
    for n,identity in enumerate(('a','b','c','d'),1):
        supported=identity!='b'
        assigned=dataclasses.replace(question,attempt_ordinal=n)
        history.append(q.QuestionHistory(assigned,n,identity*64,'supported' if supported else 'refuted',supported,
            ('1'*64,),('2'*64,),identity in active))
    return question,history


@pytest.mark.parametrize('refs',[('a','b'),('a','b','c','d')])
def test_conflict_assignment_requires_its_exact_frozen_complete_set(pending,refs):
    from audit_core import firmware_dive_questions as q
    question,history=conflict_history(pending)
    graph=firmware_chain.verified_graph_snapshot(*pending[:3],image_id='target')
    ids=tuple(i*64 for i in refs)
    conflict=dataclasses.replace(question,origin='conflict',question=q._conflict_text(ids),supersedes_observation_ids=ids)
    conflict=dataclasses.replace(conflict,question_id=q.canonical_question_id(graph,conflict))
    helper=getattr(dive,'_generation_authority',None)
    assert callable(helper),'Independent frozen conflict-set authority is missing'
    with pytest.raises((dive.FirmwareDiveError,ValueError)): helper(graph,{'schema_version':1,'questions':[]},[conflict],history)


@pytest.mark.parametrize('later',['compatible','contradictory','stale-resolver'])
def test_accepted_supersession_survives_later_ordinary_observations(pending,later):
    from audit_core import firmware_dive_questions as q
    make,question=pure_attempts(pending)
    a,b=make('a','supported',True),make('b','refuted',False)
    refs=('a'*64,'b'*64)
    conflict=dataclasses.replace(question,question_id='d'*64,origin='conflict',question=q._conflict_text(refs),supersedes_observation_ids=refs)
    resolver=make('d','supported',True,conflict,current=later!='stale-resolver')
    c=make('c','refuted' if later=='contradictory' else 'supported',later!='contradictory')
    overlay_value,contested=dive._overlay([a,b,resolver,c])
    expected={'c','d'} if later=='compatible' else set()
    assert {i.observation_id for i in overlay_value.observations}=={i*64 for i in expected}
    if later=='contradictory': assert contested=={'c'*64,'d'*64}


def test_supersession_dag_is_iterative_and_independent_of_insertion_order(pending):
    from audit_core import firmware_dive_questions as q
    make,question=pure_attempts(pending)
    first=make('a','supported',True)
    values=[first];previous='a'*64
    for n in range(1050):
        ordinary_id=sha(('ordinary-'+str(n)).encode());resolver_id=sha(('resolver-'+str(n)).encode())
        ordinary=make('b','refuted',False);ordinary['observation']['observation_id']=ordinary_id
        refs=tuple(sorted((previous,ordinary_id)))
        conflict=dataclasses.replace(question,question_id=resolver_id,origin='conflict',question=q._conflict_text(refs),supersedes_observation_ids=refs)
        resolver=make('c','supported',True,conflict);resolver['observation']['observation_id']=resolver_id
        values.extend((ordinary,resolver));previous=resolver_id
    forward=dive._overlay(values)[0]
    assert dive._overlay(list(reversed(values)))[0] == forward
    assert tuple(i.observation_id for i in forward.observations)==(previous,)


def test_resealed_boolean_journal_schema_is_not_integer_version(pending):
    con,run=pending[:2];owner=rows(con,'cba_firmware_dive_runs')[0]
    path=run/owner['journal_input_path'];body=json.loads(path.read_bytes());body['schema_version']=True
    path.write_bytes(canonical(body));digest=sha(path.read_bytes())
    index_path=run/owner['question_index_path'];index=json.loads(index_path.read_bytes());index['journal_input_sha256']=digest
    index_path.write_bytes(canonical(index))
    con.execute('UPDATE cba_firmware_dive_runs SET journal_input_sha256=?,question_index_sha256=?',(digest,sha(index_path.read_bytes())));con.commit()
    with pytest.raises(dive.FirmwareDiveError): check(pending)


def test_journal_bound_applies_to_independent_completed_reconstruction(pending,monkeypatch):
    upstream=firmware_fpcheck.verified_findings_snapshot(*pending[:3],image_id='target')
    _,generations,_=dive._reconstruct(*pending[:3],upstream)
    owner,owned,counts,*_=next(iter(generations.values()))
    stamp=owner['prepared_at'];raw=dive._journal(owner,owned,stamp,counts)
    monkeypatch.setattr(dive,'MAX_JOURNAL_BYTES',len(raw)-1)
    with pytest.raises(dive.FirmwareDiveError): dive._journal(owner,owned,stamp,counts)


def revise_review(case,*,drop=False):
    from audit_core import firmware_fpcheck_results as fp_results
    from tests.test_firmware_fpcheck_results import FP
    path=case[1]/'richer-review.json';value=json.loads(path.read_bytes())
    question=next(r for r in rows(case[0],'cba_firmware_dive_questions') if r['origin']=='chain-blocker')
    finding_id=next(ref.split(':',1)[1] for ref in json.loads(question['subject_refs']) if ref.startswith('finding:'))
    candidate=next(r['canonical_candidate_id'] for r in rows(case[0],'cba_firmware_findings') if r['finding_id']==finding_id)
    decision=next(r for r in value['decisions'] if r['candidate_id']==candidate)
    if drop: decision.update(verdict='FALSE_POSITIVE',true_positive=None,false_positive=FP | {'pivot_id':'reviewed-new-pivot'})
    else: decision['true_positive']['root_cause']='Revised exact static review evidence'
    path.write_bytes(canonical(value));fp_results.record(case[0],case[1],path,replace=True)
    firmware_fpcheck.check(*case[:3],image_id='target')


@pytest.mark.parametrize('drop',[False,True])
def test_changed_review_with_same_candidate_makes_immutable_history_stale(graph_case,tmp_path,drop):
    complete(graph_case);prepare(graph_case);populate(graph_case,tmp_path,'supported')
    first=check(graph_case);assert len(overlay(graph_case).observations)==1
    candidate=rows(graph_case[0],'cba_firmware_dive_runs')[0]['candidate_snapshot_sha256']
    revise_review(graph_case,drop=drop)
    assert firmware_fpcheck.verified_findings_snapshot(*graph_case[:3],image_id='target').candidate_snapshot_sha256==candidate
    result=check(graph_case)
    assert result.journal_sha256==first.journal_sha256 and result.stale_count==result.question_count
    assert overlay(graph_case).observations==()


def test_frozen_input_overlay_cannot_claim_stale_review_ownership(graph_case,tmp_path):
    complete(graph_case);prepare(graph_case);populate(graph_case,tmp_path,'supported');check(graph_case)
    upstream=firmware_fpcheck.verified_findings_snapshot(*graph_case[:3],image_id='target')
    stored,generations,attempts=dive._reconstruct(*graph_case[:3],upstream)
    graph=next(iter(generations.values()))[-1]
    projection=dive._history(graph_case[1],stored,graph)[2]
    assert len(projection)==1
    revise_review(graph_case);regenerate(graph_case);new=prepare(graph_case)
    upstream=firmware_fpcheck.verified_findings_snapshot(*graph_case[:3],image_id='target')
    _,generations,attempts=dive._reconstruct(*graph_case[:3],upstream)
    generations[new.dive_generation][4]['input_overlay']=list(projection)
    with pytest.raises(dive.FirmwareDiveError): dive._frozen_links(graph_case[1],generations,attempts)


def test_retry_prior_observation_is_reconstructed_exactly(graph_case,tmp_path):
    from audit_core import firmware_dive_questions as q
    from tests.test_firmware_dive_prepare import retry_manifest
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    chain_record(graph_case); chain_check(graph_case)
    path = retry_manifest(graph_case)
    prepare(graph_case, questions_path=path);populate(graph_case,tmp_path,'supported');check(graph_case)
    observation=next(r for r in rows(graph_case[0],'cba_firmware_dive_observations') if r['outcome']=='supported')
    regenerate(graph_case)
    retry=prepare(graph_case,questions_path=path,retry=[q.RetryDirective(observation['question_id'],observation['observation_id'])])
    populate(graph_case,tmp_path,'supported',retry.dive_generation)
    assert check(graph_case).complete


def test_empty_generation_still_validates_unique_frozen_journal_index(pending,tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    check(pending);con,run=pending[:2]
    con.execute("DELETE FROM cba_images WHERE id='target'")
    con.execute("DELETE FROM cba_firmware_files WHERE image_id='target'")
    con.execute('DELETE FROM cba_inventory');con.commit()
    root=tmp_path/'empty-root';empty_review(con,run,root,'target')
    chain=firmware_chain.prepare(con,run,root,image_id='target')
    case=(con,run,root,dict(schema_version=1,image_id='target',candidate_snapshot_sha256=chain.candidate_snapshot_sha256,worklist_sha256=chain.worklist_sha256,blockers=[],dispositions=[],chains=[]),{})
    chain_record(case, root=case[2]);chain_check(case)
    generation=dive.prepare(con,run,root,image_id='target')
    assert generation.question_count==0
    result=tmp_path/'empty-result.json';result.write_bytes(canonical(dict(schema_version=1,image_id='target',dive_generation=generation.dive_generation,questions=[])))
    results.record(con,run,result)
    owner=next(r for r in rows(con,'cba_firmware_dive_runs') if r['dive_generation']==generation.dive_generation)
    path=run/owner['journal_input_path'];body=json.loads(path.read_bytes());assert body['observations']
    body['observations'].append(body['observations'][0]);path.write_bytes(canonical(body))
    index_path=run/owner['question_index_path'];index=json.loads(index_path.read_bytes());index['journal_input_sha256']=sha(path.read_bytes());index_path.write_bytes(canonical(index))
    con.execute('UPDATE cba_firmware_dive_runs SET journal_input_sha256=?,question_index_sha256=? WHERE dive_generation=?',(sha(path.read_bytes()),sha(index_path.read_bytes()),generation.dive_generation));con.commit()
    with pytest.raises(dive.FirmwareDiveError): dive.check(con,run,root,image_id='target')


def opaque_first(case, tmp_path):
    """One real pre-canonical conclusion, with canonical unrelated receipts."""
    from tests.test_firmware_dive_prepare import accepted
    from tests.test_firmware_chain_import import record as chain_record
    from tests.test_firmware_chain_gate import check as chain_check
    from tests.test_firmware_dive_prepare import retry_manifest
    chain_record(case); chain_check(case)
    path = retry_manifest(case)
    first = prepare(case, questions_path=path)
    con = case[0]
    question = next(r for r in rows(con,'cba_firmware_dive_questions') if r['origin']=='analyst')
    _, observed = accepted(case,first,value=False,outcome='refuted',
        question_id=question['question_id'],_fill=False)
    con.execute("UPDATE cba_firmware_dive_runs SET status='pending',completed_at=NULL,journal_path=NULL,journal_sha256=NULL,supported_count=0,refuted_count=0,inconclusive_count=0")
    con.commit()
    for n,row in enumerate(rows(con,'cba_firmware_dive_questions')):
        if row['question_id'] == question['question_id']: continue
        directory=tmp_path/('opaque-first-'+str(n));directory.mkdir()
        record(build(case,row,directory,outcome='inconclusive'))
    assert check(case).complete and overlay(case).observations == ()
    return question,observed


def test_opaque_retry_history_never_creates_current_conflict(graph_case,tmp_path):
    question,old=opaque_first(graph_case,tmp_path)
    retry=prepare(graph_case,questions_path=graph_case[1]/'scratch-analyst/analyst.json',retry=[question['question_id']+':'+old['observation_id']])
    con,run=graph_case[:2]
    row=next(r for r in rows(con,'cba_firmware_dive_questions') if r['dive_generation']==retry.dive_generation and r['question_id']==question['question_id'])
    assert row['attempt_ordinal']==2 and row['prior_observation_id']==old['observation_id']
    index=json.loads((run/next(r for r in rows(con,'cba_firmware_dive_runs') if r['dive_generation']==retry.dive_generation)['question_index_path']).read_bytes())
    assert old['observation_id'] not in {r['observation_id'] for r in index['input_overlay']}
    populate(graph_case,tmp_path,'supported',retry.dive_generation)
    assert check(graph_case).complete
    accepted=overlay(graph_case)
    assert len(accepted.observations)==1 and accepted.observations[0].outcome=='supported'
    before,artifacts,changes=state(con),files(run),con.total_changes
    assert check(graph_case).complete and overlay(graph_case)==accepted
    assert state(con)==before and files(run)==artifacts and con.total_changes==changes
    regenerate(graph_case)
    later=prepare(graph_case)
    assert later.conflict_count==0 and overlay(graph_case)==accepted


def freeze_legacy_conflict(case, old, monkeypatch):
    """Replay the old preparer's accepted opaque context to retain a real frozen owner."""
    from audit_core import firmware_dive_questions as q
    original=dive._history
    def historical(run,stored,graph,upstream=None):
        history,index,inputs=original(run,stored,graph,upstream)
        history=tuple(dataclasses.replace(h,dependency_current=True) if h.observation_id==old['observation_id'] else h for h in history)
        index=tuple(dataclasses.replace(i,status='current') if i.observation_id==old['observation_id'] else i for i in index)
        deps=[{k:v for k,v in d.items() if k not in ('image_id','dive_generation','question_id','ordinal','observation_id','recorded_at')}
            for d in stored['dependencies'] if d['observation_id']==old['observation_id']]
        projection=dict(observation_id=old['observation_id'],question_id=old['question_id'],resolution_effect=json.loads(old['resolution_effect']),
            dependency_refs=json.loads(old['dependency_refs']),evidence_refs=json.loads(old['evidence_refs']),dependencies=tuple(q._hash(d) for d in deps))
        inputs=tuple(sorted({q._bytes(i):i for i in (*inputs,projection)}.values(),key=q._bytes))
        return history,index,inputs
    with monkeypatch.context() as patch:
        patch.setattr(dive,'_history',historical)
        return prepare(case)


def test_frozen_opaque_conflict_completes_as_stale_without_poisoning_canonical_overlay(graph_case,tmp_path,monkeypatch):
    question,old=opaque_first(graph_case,tmp_path)
    retry=prepare(graph_case,questions_path=graph_case[1]/'scratch-analyst/analyst.json',retry=[question['question_id']])
    populate(graph_case,tmp_path,'supported',retry.dive_generation);check(graph_case)
    accepted=overlay(graph_case)
    regenerate(graph_case)
    frozen=freeze_legacy_conflict(graph_case,old,monkeypatch)
    assert frozen.conflict_count==1
    assert overlay(graph_case)==accepted
    populate(graph_case,tmp_path,'supported',frozen.dive_generation)
    assert overlay(graph_case)==accepted
    summary=check(graph_case)
    resolver=next(q for q in summary.questions if q.question_id!=question['question_id'] and q.outcome=='supported')
    assert resolver.status=='stale' and overlay(graph_case)==accepted
    assert rows(graph_case[0],'cba_firmware_chain_runs')
    before,artifacts,changes=state(graph_case[0]),files(graph_case[1]),graph_case[0].total_changes
    assert check(graph_case)==summary and overlay(graph_case)==accepted
    assert state(graph_case[0])==before and files(graph_case[1])==artifacts and graph_case[0].total_changes==changes
    # A later prepare must retain the historical conflict only as stale context.
    later=prepare(graph_case,questions_path=graph_case[1]/'scratch-analyst/analyst.json',retry=[question['question_id']])
    owner=next(r for r in rows(graph_case[0],'cba_firmware_dive_runs') if r['dive_generation']==later.dive_generation)
    index=json.loads((graph_case[1]/owner['question_index_path']).read_bytes())
    assert {r['observation_id'] for r in index['input_overlay']}=={accepted.observations[0].observation_id}


def clone_acquisition(con,owner):
    from audit_core import db
    row=rows(con,'cba_firmware_dive_acquisitions')[0]
    changed={'image_id':'foreign','dive_generation':'f'*64,'question_id':next(q['question_id'] for q in rows(con,'cba_firmware_dive_questions') if q['question_id']!=row['question_id'])}
    replacement={owner:changed[owner]}
    if owner=='image_id': replacement['dive_generation']=changed['dive_generation']
    db.put(con,'cba_firmware_dive_acquisitions',row | replacement)


@pytest.mark.parametrize('owner',['image_id','dive_generation','question_id'])
@pytest.mark.parametrize('boundary',['pending','complete','overlay','lock'])
def test_acquisition_global_owner_collision_is_rejected_even_uncited(capture,tmp_path,monkeypatch,owner,boundary):
    from tests.test_firmware_dive_capture import seal
    seal(capture)
    case=capture[0];con,run=case[:2]
    populate(case,tmp_path)
    if boundary=='complete': check(case)
    if boundary=='lock':
        original=dive._install
        def race(destination,contents,selected_run):
            original(destination,contents,selected_run)
            if 'journal.json' in contents: clone_acquisition(con,owner)
        monkeypatch.setattr(dive,'_install',race)
    else: clone_acquisition(con,owner)
    before=state(con)
    with pytest.raises(dive.FirmwareDiveError):
        overlay(case) if boundary=='overlay' else check(case)
    if boundary!='lock': assert state(con)==before
    else:
        assert rows(con,'cba_firmware_dive_runs')[0]['status']=='pending'
        assert rows(con,'cba_firmware_chain_runs')[0]['status']=='complete'
    assert not con.in_transaction


def test_distinct_valid_sibling_acquisitions_survive_completion_and_overlay(capture,tmp_path):
    from tests.test_firmware_dive_capture import seal,save as capture_save
    first=seal(capture)
    capture[2]['operator']='operator-2';capture_save(capture)
    second=seal(capture)
    assert first.acquisition_id!=second.acquisition_id
    case=capture[0];populate(case,tmp_path)
    assert check(case).complete and check(case).complete
    assert overlay(case).observations==() and len(rows(case[0],'cba_firmware_dive_acquisitions'))==2


def test_opaque_ancestry_excludes_all_resolvers_transitively_without_suppressing_canonical_siblings(pending):
    from audit_core import firmware_dive_questions as q
    make,question=pure_attempts(pending)
    opaque=make('a','supported',True);opaque['canonical']=False
    canonical_parent=make('b','refuted',False)
    later=make('c','refuted',False)
    def resolver(identity,refs):
        assigned=dataclasses.replace(question,question_id=identity*64,origin='conflict',
            question=q._conflict_text(refs),supersedes_observation_ids=refs)
        return make(identity,'supported',True,assigned)
    first=resolver('d',('a'*64,'b'*64))
    second=resolver('e',('c'*64,'d'*64))
    values=[opaque,canonical_parent,first,later,second]
    accepted,contested=dive._overlay(values)
    assert {r.observation_id for r in accepted.observations}=={'b'*64,'c'*64} and not contested
    assert dive._overlay(list(reversed(values)))==(accepted,contested)
