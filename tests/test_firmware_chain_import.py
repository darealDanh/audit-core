"""Artifact-first graph publication and real SQLite transaction failures."""
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
from tests.test_firmware_chain_prepare import empty_review, files
from tests.test_hunt_gate import state


GRAPH_TABLES = ('cba_firmware_chain_edges', 'cba_firmware_chains', 'cba_firmware_chain_dispositions',
                'cba_firmware_chain_unknowns', 'cba_firmware_chain_receipts')


def record(case, *, connection=None, replace=False):
    con, run, _, value, _ = case
    path = run / 'worker-graph.json'
    path.write_text(json.dumps(value, ensure_ascii=False))
    importer = getattr(results, 'record', None)
    assert callable(importer), 'Task 6 atomic importer is missing'
    return importer(con if connection is None else connection, run, path, replace=replace)


def rows(con, table, image='target'):
    return [dict(row) for row in con.execute(f'SELECT * FROM {table} WHERE image_id=? ORDER BY 1,2', (image,))]


def blocked(case):
    value = case[3]
    value['blockers'] = [blocker(value)]
    value['chains'][0]['edges'][0]['blocker_keys'] = ['boot']
    value['dispositions'][-1].update(disposition='blocked', existing_unknown_ids=['component-only'],
                                      pivot_followup_ids=['pivot-000'])


def test_first_import_exact_rows_canonical_artifact_counts_and_pending_run(graph_case):
    blocked(graph_case)
    con, run, _, value, _ = graph_case
    summary = record(graph_case)
    content = pathlib.Path(summary.artifact_path).read_bytes()
    expected = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    # The parser sorts unordered collections; this fixture is already in that order.
    assert json.loads(content) == value
    assert content == expected
    digest = hashlib.sha256(content).hexdigest()
    assert pathlib.Path(summary.artifact_path) == run / 'artifacts/firmware-chain' / value['worklist_sha256'] / digest / 'result.json'
    assert dataclasses.asdict(summary) == dict(image_id='target', finding_count=4, disposition_count=4,
        blocker_count=1, chain_count=1, edge_count=2, complete_chains=0, blocked_chains=1, artifact_path=summary.artifact_path)
    receipt, = rows(con, 'cba_firmware_chain_receipts')
    assert {k: receipt[k] for k in ('disposition_count','blocker_count','chain_count','edge_count')} == dict(
        disposition_count=4, blocker_count=1, chain_count=1, edge_count=2)
    assert (receipt['result_path'], receipt['result_sha256'], receipt['worklist_sha256']) == (summary.artifact_path, digest, value['worklist_sha256'])
    assert receipt['recorded_at']
    chain, = rows(con, 'cba_firmware_chains')
    unknown, = rows(con, 'cba_firmware_chain_unknowns')
    assert (chain['pre_auth'], chain['completeness'], chain['evidence_rung']) == ('unknown','blocked','static-chained')
    assert json.loads(chain['member_ids']) == value['chains'][0]['member_ids']
    assert json.loads(chain['blocker_ids']) == [unknown['blocker_id']]
    assert json.loads(unknown['affected_edges']) == [dict(chain_id=chain['chain_id'], ordinal=0)]
    assert json.loads(unknown['axes']) == ['lifecycle']
    dispositions = rows(con, 'cba_firmware_chain_dispositions')
    assert len(dispositions) == 4 and [d['disposition'] for d in dispositions] == ['chained'] * 3 + ['blocked']
    for d in dispositions[:3]:
        assert json.loads(d['chain_ids']) == [chain['chain_id']]
    assert json.loads(dispositions[-1]['pivot_followup_ids']) == ['pivot-000']
    edges = rows(con, 'cba_firmware_chain_edges')
    assert [e['ordinal'] for e in edges] == [0,1]
    assert [(e['producer_finding_id'], e['consumer_finding_id']) for e in edges] == list(zip(value['chains'][0]['member_ids'], value['chains'][0]['member_ids'][1:]))
    for table in GRAPH_TABLES[:-1]:
        for row in rows(con, table):
            assert (row['artifact_path'], row['artifact_sha256']) == (summary.artifact_path, digest)
            assert row.get('recorded_at', row.get('derived_at'))
            for key, cell in row.items():
                if isinstance(cell, str) and cell.startswith(('[', '{')):
                    assert cell == json.dumps(json.loads(cell), sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    run_row, = rows(con, 'cba_firmware_chain_runs')
    assert run_row['status'] == 'pending' and run_row['graph_path'] is run_row['graph_sha256'] is run_row['completed_at'] is None
    assert not con.in_transaction
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.image_id = 'foreign'


def test_receipted_empty_generation_and_lossless_unicode_image(tmp_path):
    run = workspace.init_run(tmp_path / 'project')
    image = '路由器|r1|雪:%_\n"'
    with db.connect(run / 'audit.db') as con:
        root = tmp_path / 'root'
        empty_review(con, run, root, image)
        prep = firmware_chain.prepare(con, run, root, image_id=image)
        value = dict(schema_version=1, image_id=image, candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
                     worklist_sha256=prep.worklist_sha256, blockers=[], chains=[], dispositions=[])
        summary = record((con,run,root,value,{}))
        assert summary.image_id == image
        assert [summary.finding_count, summary.disposition_count, summary.blocker_count, summary.chain_count,
                summary.edge_count, summary.complete_chains, summary.blocked_chains] == [0]*7
        assert json.loads(pathlib.Path(summary.artifact_path).read_bytes())['image_id'] == image
        assert len(rows(con, 'cba_firmware_chain_receipts', image)) == 1
        assert all(rows(con, t, image) == [] for t in GRAPH_TABLES[:-1])


def test_duplicate_refused_and_replacement_clears_completion_preserves_siblings(graph_case):
    blocked(graph_case)
    con, run, _, value, _ = graph_case
    first = record(graph_case)
    # Overlapping semantic and result-local identities are scoped to each image.
    for table in ('cba_firmware_chain_runs', *GRAPH_TABLES):
        for row in rows(con, table):
            db.put(con, table, row | {'image_id':'sibling'})
    con.execute("UPDATE cba_firmware_chain_runs SET status='complete',graph_path=?,graph_sha256=?,completed_at='prior completion' WHERE image_id='target'",
                (str(run / 'old-graph.json'), 'a'*64))
    con.commit()
    before, artifacts = state(con), files(run)
    with pytest.raises(results.FirmwareChainError, match='replace'):
        record(graph_case)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction
    first_ids = [(t, [(r.get('chain_id'),r.get('blocker_id')) for r in rows(con,t)]) for t in GRAPH_TABLES[:-1]]
    value['chains'][0]['chain_key'] = 'renamed'
    value['blockers'][0]['blocker_key'] = 'renamed-blocker'
    value['blockers'][0]['affected_edges'][0]['chain_key'] = 'renamed'
    value['chains'][0]['edges'][0]['blocker_keys'] = ['renamed-blocker']
    for d in value['dispositions'][:3]: d['chain_keys'] = ['renamed']
    second = record(graph_case, replace=True)
    assert second.artifact_path != first.artifact_path
    assert first_ids == [(t, [(r.get('chain_id'),r.get('blocker_id')) for r in rows(con,t)]) for t in GRAPH_TABLES[:-1]]
    for table in ('cba_firmware_chain_runs', *GRAPH_TABLES):
        assert [r for r in state(con)[table] if r[0] == 'sibling'] == [r for r in before[table] if r[0] == 'sibling']
    run_row, = rows(con, 'cba_firmware_chain_runs')
    assert run_row['status'] == 'pending' and run_row['graph_path'] is run_row['graph_sha256'] is run_row['completed_at'] is None
    assert pathlib.Path(first.artifact_path).is_file()


@pytest.mark.parametrize('operation', ['source-read','install','commit','unexpected',
    *['delete:'+t for t in GRAPH_TABLES], *['insert:'+t for t in GRAPH_TABLES], 'update-run'])
def test_failed_replacement_preserves_exact_prior_sql(graph_case, monkeypatch, operation):
    blocked(graph_case)
    con, run, *_ = graph_case
    first = record(graph_case)
    graph_case[3]['chains'][0]['title'] = 'Replacement title'
    before = state(con)
    connection = con
    error = results.FirmwareChainError
    if operation == 'source-read':
        def unreadable(path):
            raise results.FirmwareChainError('Cannot read firmware chain JSON')
        monkeypatch.setattr(results, 'load', unreadable)
    elif operation == 'install':
        def broken(*args): raise OSError('injected install failure')
        monkeypatch.setattr(surface, 'atomic_install', broken)
    elif operation in ('commit', 'unexpected'):
        class Connection:
            def __getattr__(self, name): return getattr(con, name)
            def commit(self): raise sqlite3.OperationalError('injected commit failure')
        connection = Connection()
        if operation == 'unexpected':
            original = db.put
            def fail(*args, **kwargs):
                if args[1] == 'cba_firmware_chain_edges': raise RuntimeError('unexpected insertion failure')
                return original(*args, **kwargs)
            monkeypatch.setattr(db, 'put', fail)
            error = RuntimeError
    else:
        action, table = ('UPDATE', 'cba_firmware_chain_runs') if operation == 'update-run' else operation.split(':')
        con.execute(f"CREATE TEMP TRIGGER fail_import BEFORE {action.upper()} ON {table} BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    with pytest.raises(error) as raised:
        record(graph_case, connection=connection, replace=True)
    if operation.startswith(('delete:', 'insert:')) or operation in ('commit', 'update-run'):
        assert str(raised.value) == 'database operation failed'
    assert state(con) == before and not con.in_transaction
    assert pathlib.Path(first.artifact_path).is_file()


@pytest.mark.parametrize('damage', ['worklist','review','finding','surface','unknown','pivot','run','receipt',
    'installed-byte','installed-extra','parent-symlink'])
def test_revalidates_mutable_evidence_and_installed_bytes_under_lock(graph_case, monkeypatch, tmp_path, damage):
    con, run, _, value, _ = graph_case
    record(graph_case)
    value['chains'][0]['title'] = 'New title'
    before = state(con)
    install = surface.atomic_install
    concurrent = {}
    def changed(destination, generated):
        install(destination, generated)
        if damage == 'worklist':
            pathlib.Path(rows(con, 'cba_firmware_chain_runs')[0]['worklist_path']).write_bytes(b'{}')
        elif damage.startswith('installed-'):
            (destination / ('result.json' if damage == 'installed-byte' else 'extra.json')).write_bytes(b'{}')
        elif damage == 'parent-symlink':
            outside = tmp_path / 'moved'
            destination.parent.rename(outside)
            destination.parent.symlink_to(outside, target_is_directory=True)
        else:
            table, field = {'review':('cba_firmware_fp_runs','status'), 'finding':('cba_firmware_findings','data_flow'),
                'surface':('cba_firmware_surfaces','reach_evidence'), 'unknown':('cba_unknowns','question'),
                'pivot':('cba_firmware_pivots','evidence'), 'run':('cba_firmware_chain_runs','prepared_at'),
                'receipt':('cba_firmware_chain_receipts','recorded_at')}[damage]
            con.execute(f"UPDATE {table} SET {field}=? WHERE image_id='target'", ('pending' if damage == 'review' else 'concurrent',))
            con.commit()
            concurrent.update(state(con))
    monkeypatch.setattr(surface, 'atomic_install', changed)
    with pytest.raises(results.FirmwareChainError): record(graph_case, replace=True)
    assert state(con) == (concurrent or before) and not con.in_transaction


def test_active_caller_transaction_is_never_committed_or_rolled_back(graph_case):
    con, run, *_ = graph_case
    con.execute("UPDATE cba_firmware_chain_runs SET prepared_at='caller owned'")
    before, artifacts = state(con), files(run)
    with pytest.raises(results.FirmwareChainError, match='active transaction'): record(graph_case)
    assert con.in_transaction and state(con) == before and files(run) == artifacts
    con.rollback()


def test_real_competing_writer_retains_its_transaction_and_prior_sql(graph_case):
    con, run, *_ = graph_case
    con.execute('PRAGMA busy_timeout=25')
    before = state(con)
    with sqlite3.connect(run / 'audit.db', timeout=0.025) as other:
        other.execute('BEGIN IMMEDIATE')
        other.execute("UPDATE cba_firmware_chain_runs SET prepared_at='competitor'")
        start = time.monotonic()
        with pytest.raises(results.FirmwareChainError) as error: record(graph_case)
        assert time.monotonic() - start < 5
        assert str(error.value) == 'database operation failed'
        assert isinstance(error.value.__cause__, sqlite3.OperationalError)
        assert 'locked' in str(error.value.__cause__).lower()
        assert state(con) == before and not con.in_transaction and other.in_transaction
        assert other.execute('SELECT prepared_at FROM cba_firmware_chain_runs').fetchone() == ('competitor',)
        artifact, = (run / 'artifacts/firmware-chain').rglob('result.json')
        assert json.loads(artifact.read_bytes())['chains']
        other.rollback()
    assert state(con) == before


@pytest.mark.parametrize('damage', ['bytes','extra','file-symlink','directory-symlink'])
def test_existing_result_generation_is_never_repaired(graph_case, tmp_path, damage):
    con, run, *_ = graph_case
    summary = record(graph_case)
    path = pathlib.Path(summary.artifact_path)
    if damage == 'bytes': path.write_bytes(b'{}')
    elif damage == 'extra': path.with_name('extra.json').write_bytes(b'{}')
    elif damage == 'file-symlink':
        outside = tmp_path / 'result.json'
        path.rename(outside)
        path.symlink_to(outside)
    else:
        outside = tmp_path / 'result-directory'
        path.parent.rename(outside)
        path.parent.symlink_to(outside, target_is_directory=True)
    before, artifacts = state(con), files(run)
    with pytest.raises(results.FirmwareChainError): record(graph_case, replace=True)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


def test_replacement_preserves_same_image_other_snapshot_rows(graph_case):
    con, run, *_ = graph_case
    record(graph_case)
    old = '0' * 64
    for table in GRAPH_TABLES:
        for row in rows(con, table):
            other = row | dict(candidate_snapshot_sha256=old)
            for field in ('finding_id','blocker_id','chain_id'):
                if field in other: other[field] = 'older-' + other[field]
            db.put(con, table, other)
    before = state(con)
    graph_case[3]['chains'][0]['title'] = 'Replacement title'
    record(graph_case, replace=True)
    for table in GRAPH_TABLES:
        spec = db.TABLE_SPECS[table]
        index = spec.columns.index('candidate_snapshot_sha256')
        assert [r for r in state(con)[table] if r[index] == old] == [r for r in before[table] if r[index] == old]


def clone_retained_image(case, image):
    """Coherently copy retained evidence, deliberately retaining all local IDs.

    Finding IDs normally differ between images; this adversarial root-free
    fixture forces overlapping finding/surface/pivot IDs while preserving real
    receipt JSON, canonical artifacts, and exact hash ownership for validation.
    """
    con, run, root, value, frozen = case
    def canonical(value):
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    def install(relative, value):
        content = canonical(value)
        digest = hashlib.sha256(content).hexdigest()
        path = run / relative.replace('DIGEST', digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return str(path), digest
    review, = rows(con, 'cba_firmware_fp_runs')
    index = json.loads(pathlib.Path(review['worklist_path']).read_bytes())
    index['image_id'] = image
    index_path, review_hash = install('files/firmware-fpcheck/DIGEST/index.json', index)
    db.put(con, 'cba_firmware_fp_runs', review | dict(image_id=image, worklist_path=index_path, worklist_sha256=review_hash))
    receipts = []
    artifact_map = {}
    for row in rows(con, 'cba_firmware_fp_receipts'):
        result = json.loads(pathlib.Path(row['result_path']).read_bytes())
        result.update(image_id=image, worklist_sha256=review_hash)
        path, digest = install('artifacts/firmware-fpcheck/' + review_hash + '/DIGEST/result.json', result)
        artifact_map[row['result_path']] = (path, digest)
        updated = row | dict(image_id=image, worklist_sha256=review_hash, result_path=path, result_sha256=digest)
        receipts.append(updated)
        db.put(con, 'cba_firmware_fp_receipts', updated)
    run_row, = rows(con, 'cba_firmware_chain_runs')
    artifact = json.loads(pathlib.Path(run_row['fpcheck_artifact_path']).read_bytes())
    artifact.update(image_id=image, worklist_sha256=review_hash,
                    results=[dict(batch_path=r['batch_path'], result_sha256=r['result_sha256']) for r in receipts])
    for finding in artifact['findings']: finding['image_id'] = image
    artifact_path, artifact_hash = install('artifacts/firmware-fpcheck/' + review_hash + '/DIGEST/findings.json', artifact)
    cloned = copy.deepcopy(frozen)
    cloned.update(image_id=image, fpcheck_worklist_sha256=review_hash,
                  findings_artifact_path=pathlib.Path(artifact_path).relative_to(run).as_posix(), findings_artifact_sha256=artifact_hash)
    # Stage 4d unknown IDs use a global primary key, unlike image-scoped finding,
    # surface, pivot, and Stage 4g keys.
    unknown_ids = {r['id']: 'sibling-' + r['id'] for r in cloned['unknowns']}
    for unknown in cloned['unknowns']: unknown['id'] = unknown_ids[unknown['id']]
    for collection, table, timestamp in (('findings','cba_firmware_findings','derived_at'),
        ('surfaces','cba_firmware_surfaces','recorded_at'), ('unknowns','cba_unknowns','recorded_at'),
        ('pivots','cba_firmware_pivots','recorded_at')):
        for record_row in cloned[collection]:
            record_row['image_id'] = image
            if collection == 'findings':
                record_row.update(artifact_path=cloned['findings_artifact_path'], artifact_sha256=artifact_hash)
            elif collection == 'pivots':
                path, digest = artifact_map[str(run / record_row['artifact_path'])]
                record_row.update(artifact_path=pathlib.Path(path).relative_to(run).as_posix(), artifact_sha256=digest)
            sql_row = copy.deepcopy(record_row)
            sql_row.pop('context_only', None)
            sql_row['artifact_path'] = str(run / sql_row['artifact_path'])
            for key in ('contributors','lanes','component_paths','surface_ids'):
                if key in sql_row: sql_row[key] = canonical(sql_row[key]).decode().removesuffix('\n')
            db.put(con, table, sql_row)
    worklist_path, worklist_hash = install('files/firmware-chain/DIGEST/worklist.json', cloned)
    db.put(con, 'cba_firmware_chain_runs', run_row | dict(image_id=image, fpcheck_artifact_path=artifact_path,
        fpcheck_artifact_sha256=artifact_hash, worklist_path=worklist_path, worklist_sha256=worklist_hash))
    other = copy.deepcopy(value)
    other.update(image_id=image, worklist_sha256=worklist_hash)
    for disposition in other['dispositions']:
        disposition['existing_unknown_ids'] = [unknown_ids[u] for u in disposition['existing_unknown_ids']]
    for chain in other['chains']:
        for edge in chain['edges']:
            for unknown in edge['existing_unknowns']: unknown['unknown_id'] = unknown_ids[unknown['unknown_id']]
            edge['supplemental_evidence_refs'] = [
                'unknown:' + unknown_ids[ref.split(':', 1)[1].split('#')[0]] + '#' + ref.split('#')[1]
                if ref.startswith('unknown:') else ref for ref in edge['supplemental_evidence_refs']]
    return con, run, root, other, cloned


def test_two_imports_with_unicode_delimiters_and_overlapping_evidence_ids(graph_case):
    blocked(graph_case)
    con = graph_case[0]
    image = '路由器|r1|雪:%_\n"'
    sibling = clone_retained_image(graph_case, image)
    first = record(graph_case)
    before = state(con)
    second = record(sibling)
    assert second.image_id == image and second.artifact_path != first.artifact_path
    assert second.blocker_count == second.blocked_chains == 1
    for table in ('cba_firmware_chain_runs', *GRAPH_TABLES):
        assert [r for r in state(con)[table] if r[0] == 'target'] == [r for r in before[table] if r[0] == 'target']
    assert [r['finding_id'] for r in rows(con, 'cba_firmware_chain_dispositions', image)] == [r['finding_id'] for r in rows(con, 'cba_firmware_chain_dispositions')]
    target_chain, = rows(con, 'cba_firmware_chains')
    sibling_chain, = rows(con, 'cba_firmware_chains', image)
    assert target_chain['chain_id'] != sibling_chain['chain_id']
    assert target_chain['member_ids'] == sibling_chain['member_ids']
    sibling[3]['chains'][0]['title'] = 'Sibling replacement'
    before = state(con)
    record(sibling, replace=True)
    for table in ('cba_firmware_chain_runs', *GRAPH_TABLES):
        assert [r for r in state(con)[table] if r[0] == 'target'] == [r for r in before[table] if r[0] == 'target']
