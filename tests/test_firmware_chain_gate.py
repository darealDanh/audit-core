"""Live-root completion reconstructs exact evidence and publishes atomically."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3
import time

import pytest

from audit_core import db, firmware_chain, firmware_chain_results as results, surface, workspace
from tests.test_firmware_chain_validation import graph_case, prepared, blocker  # noqa: F401
from tests.test_firmware_chain_prepare import rich_review, empty_review, files
from tests.test_firmware_chain_import import record, rows, blocked, GRAPH_TABLES
from tests.test_hunt_gate import state


def check(case, *, connection=None, image_id=None):
    con, run, root = case[:3]
    checker = getattr(firmware_chain, 'check', None)
    assert callable(checker), 'Task 7 firmware-chain completion gate is missing'
    return checker(con if connection is None else connection, run, root, image_id=image_id)


def test_complete_reconstructs_reused_paths_and_idempotently_preserves_all_bytes(graph_case):
    con, run, _, value, _ = graph_case
    chain = value['chains'][0]
    chain['edges'][0]['result_state']['authentication'] = 'admin'
    chain['edges'][1]['required_state']['authentication'] = 'admin'
    other = copy.deepcopy(chain)
    other.update(chain_key='b', member_ids=other['member_ids'][:2], edges=other['edges'][:1])
    value['chains'].append(other)
    for d in value['dispositions'][:2]: d['chain_keys'].append('b')
    imported = record(graph_case)
    prior = {t: rows(con,t) for t in GRAPH_TABLES}
    summary = check(graph_case)
    assert dataclasses.asdict(summary) | {'chains':None} == dict(image_id='target', finding_count=4,
        disposition_count=4, blocker_count=0, complete_chains=2, blocked_chains=0, chains=None,
        artifact_path=summary.artifact_path, complete=True)
    assert [(c.member_count,c.edge_count,c.completeness,c.pre_auth,c.confidence) for c in summary.chains] == [
        (len(json.loads(c['member_ids'])), len(json.loads(c['member_ids']))-1, 'complete','yes',6)
        for c in sorted(prior['cba_firmware_chains'], key=lambda r:r['chain_id'])]
    content = pathlib.Path(summary.artifact_path).read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    assert pathlib.Path(summary.artifact_path) == run / 'artifacts/firmware-chain' / value['worklist_sha256'] / digest / 'chains.json'
    graph = json.loads(content)
    assert set(graph) == {'schema_version','image_id','candidate_snapshot_sha256','worklist_sha256',
                          'result_sha256','dispositions','blockers','chains','edges'}
    assert (graph['schema_version'],graph['image_id'],graph['candidate_snapshot_sha256'],graph['worklist_sha256']) == (
        1,'target',value['candidate_snapshot_sha256'],value['worklist_sha256'])
    assert graph['result_sha256'] == hashlib.sha256(pathlib.Path(imported.artifact_path).read_bytes()).hexdigest()
    assert len(graph['dispositions']) == 4 and len(graph['chains']) == 2 and len(graph['edges']) == 3 and graph['blockers'] == []
    assert content == (json.dumps(graph, ensure_ascii=False, sort_keys=True, separators=(',',':'))+'\n').encode()
    assert str(run).encode() not in content and b'derived_at' not in content and b'recorded_at' not in content
    assert sorted(len(c['member_ids']) for c in graph['chains']) == [2,3]
    for c in graph['chains']:
        assert (c['confidence'],c['pre_auth'],c['completeness'],c['evidence_rung']) == (6,'yes','complete','static-chained')
        edges = [e for e in graph['edges'] if e['chain_id'] == c['chain_id']]
        assert [e['ordinal'] for e in edges] == list(range(len(c['member_ids'])-1))
        assert [(e['producer_finding_id'],e['consumer_finding_id']) for e in edges] == list(zip(c['member_ids'],c['member_ids'][1:]))
    for table in ('cba_firmware_chain_dispositions','cba_firmware_chain_unknowns','cba_firmware_chain_receipts'):
        assert rows(con,table) == prior[table]
    for table in ('cba_firmware_chains','cba_firmware_chain_edges'):
        assert all((r['artifact_path'],r['artifact_sha256']) == (summary.artifact_path,digest) for r in rows(con,table))
    run_row, = rows(con,'cba_firmware_chain_runs')
    assert (run_row['status'],run_row['graph_path'],run_row['graph_sha256']) == ('complete',summary.artifact_path,digest)
    assert run_row['completed_at'] and run_row['prepared_at']
    before, writes, artifacts = state(con),con.total_changes,files(run)
    assert check(graph_case) == summary
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts and not con.in_transaction
    with pytest.raises(dataclasses.FrozenInstanceError): summary.complete = False
    with pytest.raises(dataclasses.FrozenInstanceError): summary.chains[0].confidence = 10


@pytest.mark.parametrize('kind',['blocked-chain','nonchain'])
def test_blocked_and_only_nonchain_graphs_complete_truthfully(graph_case, kind):
    con, _, _, value, _ = graph_case
    if kind == 'blocked-chain':
        blocked(graph_case)
        value['chains'][0]['initial_state']['authentication'] = 'session'
    else:
        value['chains'] = []
        for n,d in enumerate(value['dispositions']):
            d.update(disposition=['standalone','unchainable','blocked','standalone'][n],chain_keys=[])
            if n == 1: d['pivot_followup_ids'] = ['pivot-000']
            if n == 2: d['existing_unknown_ids'] = ['overlap']
    record(graph_case)
    summary = check(graph_case)
    assert summary.complete and summary.finding_count == summary.disposition_count == 4
    assert (summary.complete_chains,summary.blocked_chains,summary.blocker_count) == ((0,1,1) if kind == 'blocked-chain' else (0,0,0))
    if kind == 'blocked-chain':
        assert [(c.pre_auth,c.completeness) for c in summary.chains] == [('no','blocked')]
        assert rows(con,'cba_firmware_chain_unknowns')[0]['status'] == 'open'
    else: assert summary.chains == ()


def test_empty_receipted_unicode_generation_completes_and_missing_receipt_refuses(tmp_path):
    run = workspace.init_run(tmp_path/'project')
    image = '路由器|r1|雪:%_\n"'
    with db.connect(run/'audit.db') as con:
        root = tmp_path/'root'
        empty_review(con,run,root,image)
        prep = firmware_chain.prepare(con,run,root,image_id=image)
        case = (con,run,root,dict(schema_version=1,image_id=image,candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
            worklist_sha256=prep.worklist_sha256,blockers=[],dispositions=[],chains=[]),{})
        before, artifacts = state(con),files(run)
        with pytest.raises(firmware_chain.FirmwareChainError): check(case,image_id=image)
        assert state(con) == before and files(run) == artifacts
        record(case)
        summary = check(case,image_id=image)
        assert summary.image_id == image and summary.complete and summary.chains == ()
        assert [summary.finding_count,summary.disposition_count,summary.blocker_count,summary.complete_chains,summary.blocked_chains] == [0]*5
        graph = json.loads(pathlib.Path(summary.artifact_path).read_bytes())
        assert graph['image_id'] == image and all(graph[c] == [] for c in ('dispositions','blockers','chains','edges'))
        before,writes = state(con),con.total_changes
        assert check(case,image_id=image) == summary and state(con) == before and con.total_changes == writes


# Every persisted semantic/provenance field must be reconstructed, never trusted.
ROW_FIELDS = [(table, field) for table in GRAPH_TABLES for field in db.TABLE_SPECS[table].columns]


@pytest.mark.parametrize('table,field', ROW_FIELDS)
def test_every_receipt_owned_field_corruption_refuses_without_repair(graph_case, table, field):
    blocked(graph_case)
    con = graph_case[0]
    record(graph_case)
    row = rows(con,table)[0]
    old = row[field]
    if field.endswith('_at'): changed = ''
    elif type(old) is int: changed = old+(1000 if field == 'ordinal' else 1)
    elif field.endswith('sha256'): changed = '0'*64
    elif field == 'status': changed = 'resolved'
    elif field == 'disposition': changed = 'standalone'
    elif field == 'completeness': changed = 'complete'
    elif field == 'pre_auth': changed = 'yes'
    else: changed = 'corrupt'
    con.execute(f'UPDATE {table} SET {field}=? WHERE rowid=(SELECT rowid FROM {table} WHERE image_id=? LIMIT 1)',(changed,'target'))
    con.commit()
    before, artifacts = state(con),files(graph_case[1])
    with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case)
    assert state(con) == before and files(graph_case[1]) == artifacts and not con.in_transaction


@pytest.mark.parametrize('complete',[False,True])
@pytest.mark.parametrize('damage',['same-size-root','missing-root','result','worklist','findings-artifact',
    'surface','unknown','pivot','finding','review-status','hunt-status','receipt-missing','extra-edge','receipt-generation',
    'run-count','run-status','run-completion','run-graph','run-prepared'])
def test_inputs_and_stored_complete_claims_revalidated(graph_case, complete, damage):
    con,run,root,_,worklist = graph_case
    imported = record(graph_case)
    summary = check(graph_case) if complete else None
    if damage == 'same-size-root': (root/'c').write_bytes(b'jello\n')
    elif damage == 'missing-root': (root/'c').unlink()
    elif damage == 'result': pathlib.Path(imported.artifact_path).write_bytes(b'{}')
    elif damage == 'worklist': pathlib.Path(rows(con,'cba_firmware_chain_runs')[0]['worklist_path']).write_bytes(b'{}')
    elif damage == 'findings-artifact': (run/worklist['findings_artifact_path']).write_bytes(b'{}')
    elif damage in ('surface','unknown','pivot','finding','review-status','hunt-status'):
        table,field = {'surface':('cba_firmware_surfaces','reach_evidence'),'unknown':('cba_unknowns','question'),
            'pivot':('cba_firmware_pivots','evidence'),'finding':('cba_firmware_findings','data_flow'),
            'review-status':('cba_firmware_fp_runs','status'),'hunt-status':('cba_hunt_runs','status')}[damage]
        con.execute(f'UPDATE {table} SET {field}=? WHERE image_id=?',('pending' if field == 'status' else 'corrupt','target'))
    elif damage == 'receipt-missing': con.execute('DELETE FROM cba_firmware_chain_receipts')
    elif damage in ('extra-edge','receipt-generation'):
        table = 'cba_firmware_chain_edges' if damage == 'extra-edge' else 'cba_firmware_chain_receipts'
        row = rows(con,table)[0]
        row['ordinal' if damage == 'extra-edge' else 'candidate_snapshot_sha256'] = 999 if damage == 'extra-edge' else '0'*64
        if damage == 'receipt-generation': con.execute('DELETE FROM cba_firmware_chain_receipts')
        db.put(con,table,row)
    else:
        field,changed = {'run-count':('finding_count',99),'run-status':('status','corrupt'),
            'run-completion':('completed_at',None if complete else 'forged'),
            'run-graph':('graph_path',str(run/'forged.json')),'run-prepared':('prepared_at','')}[damage]
        con.execute(f'UPDATE cba_firmware_chain_runs SET {field}=?',(changed,))
    con.commit()
    before,artifacts = state(con),files(run)
    with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction
    if summary: assert pathlib.Path(summary.artifact_path).exists()


@pytest.mark.parametrize('operation',['install','commit','unexpected','delete:chains','delete:edges','insert:chains','insert:edges','status'])
def test_publication_failure_preserves_prior_rows_and_timestamps(graph_case,monkeypatch,operation):
    blocked(graph_case)
    con,run,*_ = graph_case
    record(graph_case)
    before = state(con)
    connection,error = con,firmware_chain.FirmwareChainError
    if operation == 'install':
        def fail(*args): raise OSError('injected install failure')
        monkeypatch.setattr(surface,'atomic_install',fail)
    elif operation == 'commit':
        class Connection:
            def __getattr__(self,name): return getattr(con,name)
            def commit(self): raise sqlite3.OperationalError('injected commit failure')
        connection = Connection()
    elif operation == 'unexpected':
        original = db.put
        def fail(*args,**kwargs):
            if args[1] == 'cba_firmware_chain_edges': raise RuntimeError('unexpected failure')
            return original(*args,**kwargs)
        monkeypatch.setattr(db,'put',fail)
        error = RuntimeError
    else:
        action,table = ('UPDATE','cba_firmware_chain_runs') if operation == 'status' else operation.split(':')
        if table in ('chains','edges'): table = 'cba_firmware_'+('chains' if table == 'chains' else 'chain_edges')
        con.execute(f"CREATE TEMP TRIGGER fail_check BEFORE {action.upper()} ON {table} BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    with pytest.raises(error) as raised: check(graph_case,connection=connection)
    if operation not in ('install','unexpected'): assert str(raised.value) == 'database operation failed'
    assert state(con) == before and not con.in_transaction
    assert len(list((run/'artifacts/firmware-chain').rglob('chains.json'))) <= 1


@pytest.mark.parametrize('damage',['root','review','imported-row','receipt','worklist','result','installed-byte','installed-extra','parent-symlink'])
def test_every_mutable_boundary_repeats_after_install_under_lock(graph_case,monkeypatch,tmp_path,damage):
    con,run,root,*_ = graph_case
    imported = record(graph_case)
    before = state(con)
    concurrent = {}
    install = surface.atomic_install
    def changed(destination,generated):
        install(destination,generated)
        if damage == 'root': (root/'c').write_bytes(b'jello\n')
        elif damage == 'worklist': pathlib.Path(rows(con,'cba_firmware_chain_runs')[0]['worklist_path']).write_bytes(b'{}')
        elif damage == 'result': pathlib.Path(imported.artifact_path).write_bytes(b'{}')
        elif damage.startswith('installed-'): (destination/('chains.json' if damage == 'installed-byte' else 'extra.json')).write_bytes(b'{}')
        elif damage == 'parent-symlink':
            outside = tmp_path/'moved'
            destination.parent.rename(outside)
            destination.parent.symlink_to(outside,target_is_directory=True)
        else:
            table,field = {'review':('cba_firmware_fp_runs','status'),'imported-row':('cba_firmware_chain_edges','confidence'),
                'receipt':('cba_firmware_chain_receipts','recorded_at')}[damage]
            con.execute(f'UPDATE {table} SET {field}=?',('pending' if damage == 'review' else 2 if damage == 'imported-row' else 'changed',))
            con.commit()
            concurrent.update(state(con))
    monkeypatch.setattr(surface,'atomic_install',changed)
    with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case)
    assert state(con) == (concurrent or before) and not con.in_transaction


def test_real_lock_contention_and_caller_transaction_preserve_ownership(graph_case):
    con,run,*_ = graph_case
    record(graph_case)
    con.execute("UPDATE cba_firmware_chain_runs SET prepared_at='caller owned'")
    before,artifacts = state(con),files(run)
    with pytest.raises(firmware_chain.FirmwareChainError,match='active transaction'): check(graph_case)
    assert con.in_transaction and state(con) == before and files(run) == artifacts
    con.rollback()
    con.execute('PRAGMA busy_timeout=25')
    before = state(con)
    with sqlite3.connect(run/'audit.db',timeout=0.025) as other:
        other.execute('BEGIN IMMEDIATE')
        other.execute("UPDATE cba_firmware_chain_runs SET prepared_at='competing writer'")
        start = time.monotonic()
        with pytest.raises(firmware_chain.FirmwareChainError) as error: check(graph_case)
        assert time.monotonic()-start < 5 and str(error.value) == 'database operation failed'
        assert isinstance(error.value.__cause__,sqlite3.OperationalError) and 'locked' in str(error.value.__cause__).lower()
        assert state(con) == before and not con.in_transaction and other.in_transaction
        assert other.execute('SELECT prepared_at FROM cba_firmware_chain_runs').fetchone() == ('competing writer',)
        assert len(list((run/'artifacts/firmware-chain').rglob('chains.json'))) == 1
        other.rollback()


@pytest.mark.parametrize('damage',['missing','bytes','extra','file-symlink','directory-symlink','graph-path','graph-hash','chain','edge'])
def test_completed_canonical_graph_is_never_repaired(graph_case,tmp_path,damage):
    con,run,*_ = graph_case
    record(graph_case)
    summary = check(graph_case)
    path = pathlib.Path(summary.artifact_path)
    if damage == 'missing': path.unlink()
    elif damage == 'bytes': path.write_bytes(b'{}')
    elif damage == 'extra': path.with_name('extra.json').write_bytes(b'{}')
    elif damage == 'file-symlink':
        outside = tmp_path/'chains.json'; path.rename(outside); path.symlink_to(outside)
    elif damage == 'directory-symlink':
        outside = tmp_path/'graph-directory'; path.parent.rename(outside); path.parent.symlink_to(outside,target_is_directory=True)
    elif damage in ('graph-path','graph-hash'):
        con.execute(f"UPDATE cba_firmware_chain_runs SET {'graph_path' if damage == 'graph-path' else 'graph_sha256'}=?",('forged' if damage == 'graph-path' else '0'*64,))
    else:
        con.execute(f"UPDATE {'cba_firmware_chains' if damage == 'chain' else 'cba_firmware_chain_edges'} SET artifact_path='forged'")
    con.commit()
    before,artifacts = state(con),files(run)
    with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


def test_full_disposition_and_chain_edge_counts_beyond_200(prepared,tmp_path):
    con,run,root = rich_review(prepared,tmp_path,205)
    prep = firmware_chain.prepare(con,run,root)
    worklist = json.loads(pathlib.Path(prep.worklist_path).read_bytes())
    ids = [f['finding_id'] for f in worklist['findings']]
    initial = dict(lifecycle='provisioned',posture='STA-LAN',authentication='pre-auth')
    chain = dict(chain_key='all',title='Global path',summary='All reviewed transitions',member_ids=ids,
        initial_attacker_position='LAN attacker',initial_evidence_refs=[f'finding:{ids[0]}#attacker_position'],initial_state=initial,
        edges=[dict(producer_finding_id=a,consumer_finding_id=b,capability_kind='file-write',link_key='/etc/init.d/start',
            produced_capability='Writes the controlled startup script',required_precondition='Consumes the controlled startup script',
            producer_evidence_refs=[f'finding:{a}#data_flow'],consumer_evidence_refs=[f'finding:{b}#root_cause'],supplemental_evidence_refs=[],
            required_state=dict.fromkeys(initial,'any'),result_state=dict.fromkeys(initial,'unchanged'),transition_kind='direct',
            confidence=9,existing_unknowns=[],blocker_keys=[]) for a,b in zip(ids,ids[1:])])
    value = dict(schema_version=1,image_id='target',candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
        worklist_sha256=prep.worklist_sha256,chains=[chain],blockers=[],dispositions=[dict(finding_id=f,disposition='chained',
        explanation='Global path reviewed',chain_keys=['all'],existing_unknown_ids=[],blocker_keys=[],pivot_followup_ids=[]) for f in ids])
    case = con,run,root,value,worklist
    record(case)
    summary = check(case)
    assert summary.finding_count == summary.disposition_count == 205 and summary.chains[0].edge_count == 204
    for sql,args in [
        ('UPDATE cba_firmware_chain_dispositions SET explanation=? WHERE finding_id=?',('corrupt',ids[-1])),
        ('UPDATE cba_firmware_chain_edges SET link_key=? WHERE ordinal=203',('corrupt',)),
        ("UPDATE cba_unknowns SET question=? WHERE id='unknown-204'",('corrupt',)),
        ("UPDATE cba_firmware_surfaces SET reach_evidence=? WHERE surface_id='extra-204'",('corrupt',)),
        ("UPDATE cba_firmware_pivots SET evidence=? WHERE pivot_id='pivot-204'",('corrupt',)),
        ('UPDATE cba_firmware_findings SET title=? WHERE finding_id=?',('corrupt',ids[-1]))]:
        con.execute(sql,args); con.commit()
        before = state(con)
        with pytest.raises(firmware_chain.FirmwareChainError): check(case)
        assert state(con) == before and not con.in_transaction
        # Restore exact original rows for the next independent corruption.
        table = sql.split()[1]
        current = state(con)[table]
        assert current
        if table == 'cba_firmware_chain_dispositions': original = 'Global path reviewed'
        elif table == 'cba_firmware_chain_edges': original = '/etc/init.d/start'
        elif table == 'cba_unknowns': original = 'Which authority?'
        elif table == 'cba_firmware_surfaces': original = 'c:8 registers before authentication.'
        elif table == 'cba_firmware_pivots': original = 'Escaper at c:12'
        else: original = worklist['findings'][-1]['title']
        con.execute(sql,(original,*args[1:])); con.commit()


@pytest.mark.parametrize('damage',['review','edge','root'])
def test_mutation_after_begin_immediate_is_detected_and_rolled_back(graph_case,damage):
    con,_,root,*_ = graph_case
    record(graph_case)
    before = state(con)
    class Connection:
        def __getattr__(self,name): return getattr(con,name)
        def execute(self,sql,*args):
            cursor = con.execute(sql,*args)
            if sql == 'BEGIN IMMEDIATE':
                if damage == 'review': con.execute("UPDATE cba_firmware_fp_runs SET status='pending'")
                elif damage == 'edge': con.execute('UPDATE cba_firmware_chain_edges SET confidence=2')
                else: (root/'c').write_bytes(b'jello\n')
            return cursor
    with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case,connection=Connection())
    assert state(con) == before and not con.in_transaction


def test_completion_preserves_sibling_graph_and_generic_tables(graph_case):
    con = graph_case[0]
    record(graph_case)
    blocked_rows = [dict(table=t,row=r) for t in ('cba_firmware_chain_runs',*GRAPH_TABLES) for r in rows(con,t)]
    for entry in blocked_rows: db.put(con,entry['table'],entry['row'] | {'image_id':'sibling'})
    before = state(con)
    check(graph_case,image_id='target')
    after = state(con)
    for table in before:
        if table in ('cba_firmware_chain_runs',*GRAPH_TABLES):
            assert [r for r in after[table] if r[0] == 'sibling'] == [r for r in before[table] if r[0] == 'sibling']
        else: assert after[table] == before[table]


def test_chain_and_blocker_rows_beyond_200_are_never_truncated(graph_case):
    con,_,_,value,_ = graph_case
    prototype = value['chains'][0]
    value['chains'] = []
    value['blockers'] = []
    for n in range(205):
        c = copy.deepcopy(prototype)
        c.update(chain_key=f'route-{n:03}')
        c['edges'][0]['link_key'] = f'/etc/init.d/start-{n:03}'
        c['edges'][0]['blocker_keys'] = [f'block-{n:03}']
        value['chains'].append(c)
        b = blocker(value)
        b.update(blocker_key=f'block-{n:03}',question=f'Does startup resource {n} persist?',
            affected_edges=[dict(chain_key=c['chain_key'],ordinal=0)])
        value['blockers'].append(b)
    for d in value['dispositions'][:3]: d['chain_keys'] = [c['chain_key'] for c in value['chains']]
    record(graph_case)
    summary = check(graph_case)
    assert (summary.blocker_count,summary.complete_chains,summary.blocked_chains,len(summary.chains)) == (205,0,205,205)
    assert all((c.pre_auth,c.completeness) == ('unknown','blocked') for c in summary.chains)
    for table,identifier,field in [('cba_firmware_chains','chain_id','summary'),
        ('cba_firmware_chain_unknowns','blocker_id','question')]:
        selected = sorted(rows(con,table),key=lambda r:r[identifier])[-1]
        con.execute(f'UPDATE {table} SET {field}=? WHERE {identifier}=?',('corrupt',selected[identifier])); con.commit()
        before = state(con)
        with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case)
        assert state(con) == before and not con.in_transaction
        con.execute(f'UPDATE {table} SET {field}=? WHERE {identifier}=?',(selected[field],selected[identifier])); con.commit()


@pytest.mark.parametrize('boundary',['snapshot','validation'])
def test_sql_read_failures_always_use_fixed_database_diagnostic(graph_case,monkeypatch,boundary):
    from audit_core import firmware_fpcheck
    con = graph_case[0]
    record(graph_case)
    before = state(con)
    if boundary == 'snapshot':
        original = firmware_fpcheck.verified_findings_snapshot
        def fail(*args,**kwargs):
            class Connection:
                def __getattr__(self,name): return getattr(args[0],name)
                def execute(self,sql,*params):
                    if sql.startswith('SELECT'): raise sqlite3.OperationalError('injected SQL read')
                    return args[0].execute(sql,*params)
            return original(Connection(),*args[1:],**kwargs)
        monkeypatch.setattr(firmware_fpcheck,'verified_findings_snapshot',fail)
    else:
        original = results.validate
        def fail(*args,**kwargs):
            class Connection:
                def __getattr__(self,name): return getattr(args[0],name)
                def execute(self,sql,*params):
                    if sql.startswith('SELECT'): raise sqlite3.OperationalError('injected SQL read')
                    return args[0].execute(sql,*params)
            return original(Connection(),*args[1:],**kwargs)
        monkeypatch.setattr(results,'validate',fail)
    with pytest.raises(firmware_chain.FirmwareChainError) as error: check(graph_case)
    assert str(error.value) == 'database operation failed'
    assert state(con) == before and not con.in_transaction


def test_current_completion_ignores_and_preserves_complete_historical_generation(graph_case):
    blocked(graph_case)
    con,run,_,value,_ = graph_case
    record(graph_case)
    previous = check(graph_case)
    historical = {}
    old = '0'*64
    for table in GRAPH_TABLES:
        historical[table] = []
        for row in rows(con,table):
            row = row | {'candidate_snapshot_sha256':old}
            for field in ('finding_id','blocker_id','chain_id'):
                if field in row: row[field] = 'older-'+row[field]
            for field in ('member_ids','affected_finding_ids','chain_ids','blocker_ids'):
                if field in row: row[field] = json.dumps(['older-'+v for v in json.loads(row[field])],separators=(',',':'))
            if 'affected_edges' in row:
                row['affected_edges'] = json.dumps([r | {'chain_id':'older-'+r['chain_id']} for r in json.loads(row['affected_edges'])],sort_keys=True,separators=(',',':'))
            for field in ('producer_finding_id','consumer_finding_id'):
                if field in row: row[field] = 'older-'+row[field]
            historical[table].append(row)
    value['chains'][0]['title'] = 'Current reviewed graph'
    record(graph_case,replace=True)
    for table,records in historical.items():
        for row in records: db.put(con,table,row)
    before = state(con)
    summary = check(graph_case)
    assert summary.complete and summary.finding_count == summary.disposition_count == 4 and summary.blocked_chains == 1
    assert pathlib.Path(previous.artifact_path).is_file()
    for table in GRAPH_TABLES:
        index = db.TABLE_SPECS[table].columns.index('candidate_snapshot_sha256')
        assert [r for r in state(con)[table] if r[index] == old] == [r for r in before[table] if r[index] == old]
    before,writes = state(con),con.total_changes
    assert check(graph_case) == summary and state(con) == before and con.total_changes == writes


@pytest.mark.parametrize('operation',['remove','rename'])
def test_completed_recheck_never_recreates_graph_lost_after_initial_verification(graph_case,monkeypatch,tmp_path,operation):
    import shutil
    con,run,*_ = graph_case
    record(graph_case)
    summary = check(graph_case)
    graph = pathlib.Path(summary.artifact_path)
    content = graph.read_bytes()
    before,writes,artifacts = state(con),con.total_changes,files(run)
    original = firmware_chain._completion_evidence
    changed = False
    moved = tmp_path/'removed-completed-graph'
    def lost_after_verification(*args,**kwargs):
        nonlocal changed
        evidence = original(*args,**kwargs)
        if not changed:
            changed = True
            if operation == 'remove': shutil.rmtree(graph.parent)
            else: graph.parent.rename(moved)
        return evidence
    monkeypatch.setattr(firmware_chain,'_completion_evidence',lost_after_verification)
    with pytest.raises(firmware_chain.FirmwareChainError): check(graph_case)
    assert state(con) == before and con.total_changes == writes and not con.in_transaction
    assert not graph.parent.exists()
    assert files(run) == {name:value for name,value in artifacts.items() if name != graph.relative_to(run).as_posix()}
    if operation == 'rename': assert (moved/'chains.json').read_bytes() == content
