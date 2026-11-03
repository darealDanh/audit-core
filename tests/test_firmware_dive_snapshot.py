"""The Stage 4h read boundary never repairs or falls back to retained history."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3
import typing

import pytest

from audit_core import db, firmware_chain, firmware_fpcheck, surface
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_chain_import import record, rows, blocked
from tests.test_firmware_chain_prepare import files, empty_review
from tests.test_firmware_chain_gate import check
from tests.test_firmware_dive_schema import RUN
from tests.test_hunt_gate import state


def snapshot(case, con=None):
    helper = getattr(firmware_chain, 'verified_graph_snapshot', None)
    assert callable(helper), 'Task 2 verified graph snapshot is missing'
    return helper(case[0] if con is None else con, *case[1:3], image_id='target')


def retained(case, *, image_id='target', dive_generation='a' * 64, con=None):
    helper = getattr(firmware_chain, 'verified_retained_graph_snapshot', None)
    assert callable(helper), 'Task 2 explicit retained graph verifier is missing'
    return helper(case[0] if con is None else con, *case[1:3],
                  image_id=image_id, dive_generation=dive_generation)


def own_graph(case):
    con, run, root = case[:3]
    upstream = firmware_fpcheck.verified_findings_snapshot(con, run, root, image_id='target')
    chain_run, = rows(con, 'cba_firmware_chain_runs')
    row = RUN | dict(image_id='target', manifest_sha256=upstream.manifest_sha256,
        surface_snapshot_sha256=upstream.surface_snapshot_sha256,
        candidate_snapshot_sha256=upstream.candidate_snapshot_sha256,
        chain_graph_path=pathlib.Path(chain_run['graph_path']).relative_to(run).as_posix(),
        chain_graph_sha256=chain_run['graph_sha256'])
    db.put(con, 'cba_firmware_dive_runs', row)
    return row


def complete(case):
    blocked(case)
    case[3]['chains'][0]['edges'][1]['existing_unknowns'] = [
        dict(unknown_id='overlap', axes=['authentication'])]
    record(case)
    return check(case)


def test_snapshot_record_type_annotations_resolve():
    from audit_core import firmware_chain_results as results

    annotations = typing.get_type_hints(firmware_chain.VerifiedFirmwareEdge)
    assert annotations['required_state'] is results.State
    assert annotations['result_state'] is results.State
    assert annotations['existing_unknowns'] == tuple[results.ExistingUnknownRef, ...]


def test_current_snapshot_exact_sorted_immutable_rows_and_provenance(graph_case):
    con, run, root, value, worklist = graph_case
    summary = complete(graph_case)
    graph = json.loads(pathlib.Path(summary.artifact_path).read_bytes())
    before, writes, artifacts = state(con), con.total_changes, files(run)
    actual = snapshot(graph_case)
    assert isinstance(actual, firmware_chain.VerifiedFirmwareGraphSnapshot)
    upstream = firmware_fpcheck.verified_findings_snapshot(con, run, root)
    assert (actual.image_id, actual.manifest_sha256, actual.surface_snapshot_sha256,
        actual.candidate_snapshot_sha256, actual.chain_worklist_sha256, actual.graph_path,
        actual.graph_sha256) == ('target', upstream.manifest_sha256, upstream.surface_snapshot_sha256,
        value['candidate_snapshot_sha256'], value['worklist_sha256'],
        pathlib.Path(summary.artifact_path).relative_to(run).as_posix(),
        hashlib.sha256(pathlib.Path(summary.artifact_path).read_bytes()).hexdigest())
    assert (actual.findings, actual.surfaces, actual.unknowns) == (upstream.findings, upstream.surfaces, upstream.unknowns)
    for name in ('dispositions', 'blockers', 'chains', 'edges'):
        actual_rows = getattr(actual, name)
        assert isinstance(actual_rows, tuple)
        expected_rows = copy.deepcopy(graph[name])
        for expected in expected_rows:
            expected.update(artifact_path=actual.graph_path, artifact_sha256=actual.graph_sha256)
        # asdict keeps tuples; JSON roundtrip gives the artifact's wire arrays.
        assert json.loads(json.dumps([dataclasses.asdict(r) for r in actual_rows])) == expected_rows
    assert len(actual.dispositions) == 4 and len(actual.blockers) == 1
    assert len(actual.chains) == 1 and len(actual.edges) == 2
    for frozen in (actual, *actual.findings, *actual.dispositions, *actual.blockers, *actual.chains,
                   *actual.edges, actual.edges[0].required_state, *actual.blockers[0].affected_edges,
                   *actual.edges[1].existing_unknowns):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(frozen, dataclasses.fields(frozen)[0].name, 'changed')
    assert isinstance(actual.chains[0].member_ids, tuple)
    assert isinstance(actual.blockers[0].axes, tuple)
    con.execute('PRAGMA reverse_unordered_selects=ON')
    assert snapshot(graph_case) == actual
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


def test_snapshot_readonly_caller_transaction_and_no_writing_gate(graph_case, monkeypatch):
    con, run, root = graph_case[:3]
    complete(graph_case)
    expected = snapshot(graph_case)
    def forbidden(*args, **kwargs):
        pytest.fail('read boundary called a writer')
    monkeypatch.setattr(firmware_chain, 'check', forbidden)
    monkeypatch.setattr(surface, 'atomic_install', forbidden)
    with sqlite3.connect(f'file:{run / "audit.db"}?mode=ro', uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert snapshot(graph_case, readonly) == expected
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute("UPDATE cba_firmware_chain_runs SET prepared_at='caller-owned'")
    before, writes, artifacts = state(con), con.total_changes, files(run)
    assert snapshot(graph_case) == expected
    assert con.in_transaction and state(con) == before and con.total_changes == writes and files(run) == artifacts
    con.rollback()


def test_pending_and_deleted_current_graph_never_use_retained_fallback(graph_case):
    con = graph_case[0]
    record(graph_case)
    with pytest.raises(firmware_chain.FirmwareChainError):
        snapshot(graph_case)
    check(graph_case)
    own_graph(graph_case)
    firmware_chain.invalidate(con, 'target', commit=True)
    before, writes, artifacts = state(con), con.total_changes, files(graph_case[1])
    with pytest.raises(firmware_chain.FirmwareChainError):
        snapshot(graph_case)
    assert state(con) == before and con.total_changes == writes and files(graph_case[1]) == artifacts


def legacy_graph(case):
    """Retain an actual pre-overlay worklist/graph, without changing live Stage4f."""
    con, run, root = case[:3]
    owner, = rows(con, 'cba_firmware_dive_runs')
    graph = json.loads((run / owner['chain_graph_path']).read_bytes())
    worklist = dict(case[4]); worklist.pop('dive_overlay')
    raw = surface.canonical_bytes(worklist)
    digest = hashlib.sha256(raw).hexdigest()
    path = run / 'files/firmware-chain' / digest / 'worklist.json'
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    graph['worklist_sha256'] = digest
    content = surface.canonical_bytes(graph); graph_hash = hashlib.sha256(content).hexdigest()
    target = run / 'artifacts/firmware-chain' / digest / graph_hash / 'chains.json'
    target.parent.mkdir(parents=True); target.write_bytes(content)
    con.execute('UPDATE cba_firmware_dive_runs SET chain_graph_path=?,chain_graph_sha256=?',
        (target.relative_to(run).as_posix(), graph_hash))
    con.commit()
    return path


def test_explicit_legacy_retained_graph_survives_sql_and_worker_artifact_deletion(graph_case):
    con, run = graph_case[:2]
    complete(graph_case)
    own_graph(graph_case)
    old_worklist = legacy_graph(graph_case)
    expected = retained(graph_case)
    chain_run, = rows(con, 'cba_firmware_chain_runs')
    receipt, = rows(con, 'cba_firmware_chain_receipts')
    firmware_chain.invalidate(con, 'target', commit=True)
    old_worklist.unlink()
    pathlib.Path(chain_run['worklist_path']).unlink()
    pathlib.Path(receipt['result_path']).unlink()
    before, writes, artifacts = state(con), con.total_changes, files(run)
    assert retained(graph_case) == expected
    from audit_core import firmware_dive
    owner, = rows(con, 'cba_firmware_dive_runs')
    index = {'graph_projection': {'chain_worklist_sha256': expected.chain_worklist_sha256}}
    upstream = firmware_fpcheck.verified_findings_snapshot(*graph_case[:3], image_id='target')
    assert firmware_dive._historical_graph(run, owner, index, upstream) == expected
    with sqlite3.connect(f'file:{run / "audit.db"}?mode=ro', uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert retained(graph_case, con=readonly) == expected
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute('BEGIN')
    assert retained(graph_case) == expected and con.in_transaction
    con.rollback()
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts


@pytest.mark.parametrize('damage', ['foreign-image', 'foreign-generation', 'missing-owner', 'owner-manifest',
    'owner-surface', 'owner-candidate', 'owner-path', 'owner-hash', 'owner-timestamp', 'missing', 'same-size', 'root',
    'finding', 'surface', 'review', 'upstream-artifact', 'graph-image', 'graph-generation',
    'graph-worklist', 'graph-result', 'graph-semantics', 'graph-extra', 'symlink'])
def test_retained_rejects_foreign_or_changed_dependencies_without_writes(graph_case, tmp_path, damage):
    con, run, root = graph_case[:3]
    summary = complete(graph_case)
    own_graph(graph_case)
    firmware_chain.invalidate(con, 'target', commit=True)
    path = pathlib.Path(summary.artifact_path)
    kwargs = {}
    if damage == 'foreign-image': kwargs['image_id'] = 'foreign'
    elif damage == 'foreign-generation': kwargs['dive_generation'] = 'b' * 64
    elif damage == 'missing-owner': con.execute('DELETE FROM cba_firmware_dive_runs')
    elif damage == 'owner-timestamp':
        con.execute("UPDATE cba_firmware_dive_runs SET prepared_at=NULL")
    elif damage.startswith('owner-'):
        field = {'owner-manifest':'manifest_sha256', 'owner-surface':'surface_snapshot_sha256',
            'owner-candidate':'candidate_snapshot_sha256', 'owner-path':'chain_graph_path',
            'owner-hash':'chain_graph_sha256'}[damage]
        con.execute(f'UPDATE cba_firmware_dive_runs SET {field}=?',
            ('artifacts/elsewhere.json' if field.endswith('path') else '0' * 64,))
    elif damage == 'missing': path.unlink()
    elif damage == 'same-size': path.write_bytes(path.read_bytes().replace(b'"status":"open"', b'"status":"oops"'))
    elif damage == 'root': (root / 'c').write_bytes(b'jello\n')
    elif damage in ('finding', 'surface', 'review'):
        table, field, value = {'finding':('cba_firmware_findings','data_flow','corrupt'),
            'surface':('cba_firmware_surfaces','reach_evidence','corrupt'),
            'review':('cba_firmware_fp_runs','status','pending')}[damage]
        con.execute(f'UPDATE {table} SET {field}=? WHERE image_id=?', (value, 'target'))
    elif damage == 'upstream-artifact':
        (run / graph_case[4]['findings_artifact_path']).write_bytes(b'{}')
    elif damage == 'symlink':
        outside = tmp_path / 'foreign.json'
        path.rename(outside)
        path.symlink_to(outside)
    else:
        graph = json.loads(path.read_bytes())
        if damage == 'graph-image': graph['image_id'] = 'foreign'
        elif damage == 'graph-generation': graph['candidate_snapshot_sha256'] = '0' * 64
        elif damage == 'graph-worklist': graph['worklist_sha256'] = '0' * 64
        elif damage == 'graph-result': graph['result_sha256'] = 'invalid'
        elif damage == 'graph-semantics': graph['chains'][0]['confidence'] = 10
        elif damage == 'graph-extra': graph['extra'] = 'unowned'
        content = surface.canonical_bytes(graph)
        digest = hashlib.sha256(content).hexdigest()
        replacement = run / 'artifacts/firmware-chain' / graph_case[3]['worklist_sha256'] / digest / 'chains.json'
        replacement.parent.mkdir()
        replacement.write_bytes(content)
        con.execute('UPDATE cba_firmware_dive_runs SET chain_graph_path=?,chain_graph_sha256=?',
            (replacement.relative_to(run).as_posix(), digest))
    con.commit()
    before, writes, artifacts = state(con), con.total_changes, files(run)
    with pytest.raises(firmware_chain.FirmwareChainError):
        retained(graph_case, **kwargs)
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts and not con.in_transaction


@pytest.mark.parametrize('damage', ['root', 'worklist', 'result', 'findings-artifact', 'surface', 'unknown',
    'finding', 'receipt', 'row', 'status', 'timestamp', 'graph-bytes', 'graph-path', 'graph-hash'])
def test_current_reconstructs_every_boundary_without_repair(graph_case, damage):
    con, run, root = graph_case[:3]
    summary = complete(graph_case)
    if damage == 'root': (root / 'c').write_bytes(b'jello\n')
    elif damage in ('worklist', 'result', 'findings-artifact', 'graph-bytes'):
        path = {'worklist':rows(con,'cba_firmware_chain_runs')[0]['worklist_path'],
            'result':rows(con,'cba_firmware_chain_receipts')[0]['result_path'],
            'findings-artifact':str(run / graph_case[4]['findings_artifact_path']),
            'graph-bytes':summary.artifact_path}[damage]
        original = pathlib.Path(path).read_bytes()
        pathlib.Path(path).write_bytes(b'!' + original[1:])
    else:
        table, field, changed = {'surface':('cba_firmware_surfaces','reach_evidence','corrupt'),
            'unknown':('cba_unknowns','question','corrupt'), 'finding':('cba_firmware_findings','data_flow','corrupt'),
            'receipt':('cba_firmware_chain_receipts','recorded_at',''),
            'row':('cba_firmware_chain_edges','confidence',10), 'status':('cba_firmware_chain_runs','status','pending'),
            'timestamp':('cba_firmware_chain_runs','completed_at',''),
            'graph-path':('cba_firmware_chain_runs','graph_path','forged'),
            'graph-hash':('cba_firmware_chain_runs','graph_sha256','0' * 64)}[damage]
        con.execute(f'UPDATE {table} SET {field}=? WHERE image_id=?', (changed, 'target'))
    con.commit()
    before, writes, artifacts = state(con), con.total_changes, files(run)
    with pytest.raises(firmware_chain.FirmwareChainError):
        snapshot(graph_case)
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts and not con.in_transaction


@pytest.mark.parametrize('retained_mode', [False, True])
def test_snapshot_keeps_one_sql_generation_during_concurrent_change(graph_case, monkeypatch, retained_mode):
    con, run = graph_case[:2]
    complete(graph_case)
    expected = snapshot(graph_case)
    if retained_mode:
        own_graph(graph_case)
        firmware_chain.invalidate(con, 'target', commit=True)
    con.execute('PRAGMA journal_mode=WAL')
    real_snapshot = firmware_fpcheck.verified_findings_snapshot
    changed = False
    def race(*args, **kwargs):
        nonlocal changed
        result = real_snapshot(*args, **kwargs)
        if not changed:
            changed = True
            with sqlite3.connect(run / 'audit.db') as writer:
                writer.execute("UPDATE cba_firmware_findings SET data_flow='changed' WHERE image_id='target'")
                if retained_mode:
                    writer.execute("UPDATE cba_firmware_dive_runs SET chain_graph_sha256=?", ('0' * 64,))
                else:
                    writer.execute("UPDATE cba_firmware_chain_edges SET confidence=10 WHERE image_id='target'")
        return result
    monkeypatch.setattr(firmware_fpcheck, 'verified_findings_snapshot', race)
    helper = retained if retained_mode else snapshot
    writes, artifacts = con.total_changes, files(run)
    assert helper(graph_case) == expected and changed
    assert con.total_changes == writes and files(run) == artifacts and not con.in_transaction
    with pytest.raises(firmware_chain.FirmwareChainError):
        helper(graph_case)


def test_retained_graph_rejects_modified_worklist_hash_even_with_owned_graph(graph_case):
    con, run = graph_case[:2]
    summary = complete(graph_case)
    expected = snapshot(graph_case)
    own_graph(graph_case)
    firmware_chain.invalidate(con, 'target', commit=True)
    graph = json.loads(pathlib.Path(summary.artifact_path).read_bytes())
    graph['worklist_sha256'] = '0' * 64
    content = surface.canonical_bytes(graph)
    digest = hashlib.sha256(content).hexdigest()
    path = run / 'artifacts/firmware-chain' / ('0' * 64) / digest / 'chains.json'
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    con.execute('UPDATE cba_firmware_dive_runs SET chain_graph_path=?,chain_graph_sha256=?',
        (path.relative_to(run).as_posix(), digest))
    con.commit()
    with pytest.raises(firmware_chain.FirmwareChainError):
        retained(graph_case)


def test_empty_unicode_snapshot_preserves_sibling_image_and_exact_selection(graph_case, tmp_path):
    con, run = graph_case[:2]
    complete(graph_case)
    sibling = snapshot(graph_case)
    image_id = '路由器|r1|雪:%_\n"'
    root = tmp_path / 'sibling-root'
    empty_review(con, run, root, image_id)
    prep = firmware_chain.prepare(con, run, root, image_id=image_id)
    case = (con, run, root, dict(schema_version=1, image_id=image_id,
        candidate_snapshot_sha256=prep.candidate_snapshot_sha256, worklist_sha256=prep.worklist_sha256,
        blockers=[], dispositions=[], chains=[]), {})
    record(case)
    check(case, image_id=image_id)
    before, writes, artifacts = state(con), con.total_changes, files(run)
    actual = firmware_chain.verified_graph_snapshot(con, run, root, image_id=image_id)
    assert actual.image_id == image_id
    assert (actual.findings, actual.dispositions, actual.blockers, actual.chains, actual.edges,
        actual.surfaces, actual.unknowns) == ((), (), (), (), (), (), ())
    assert snapshot(graph_case) == sibling
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts


def test_prepare_never_substitutes_retained_history_for_a_broken_current_publication(graph_case, monkeypatch):
    from audit_core import firmware_dive

    con, run, root = graph_case[:3]
    complete(graph_case)
    firmware_dive.prepare(con, run, root, image_id='target')
    def broken(*args, **kwargs):
        raise firmware_chain.FirmwareChainError('current graph no longer reconstructs')
    def forbidden(*args, **kwargs):
        pytest.fail('ordinary prepare attempted retained fallback')
    monkeypatch.setattr(firmware_chain, 'verified_graph_snapshot', broken)
    monkeypatch.setattr(firmware_chain, 'verified_retained_graph_snapshot', forbidden)
    before, writes, artifacts = state(con), con.total_changes, files(run)
    with pytest.raises(firmware_dive.FirmwareDiveError):
        firmware_dive.prepare(con, run, root, image_id='target')
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


@pytest.mark.parametrize('damage', ['deleted', 'modified', 'missing-key'])
def test_keyed_historical_worklist_requires_retained_exact_bytes(graph_case, damage):
    con, run = graph_case[:2]
    complete(graph_case); own_graph(graph_case)
    chain_run, = rows(con, 'cba_firmware_chain_runs')
    firmware_chain.invalidate(con, 'target', commit=True)
    path = pathlib.Path(chain_run['worklist_path'])
    if damage == 'deleted': path.unlink()
    elif damage == 'modified': path.write_bytes(path.read_bytes() + b' ')
    else:
        body = json.loads(path.read_bytes()); body.pop('dive_overlay')
        path.write_bytes(surface.canonical_bytes(body))
    before, artifacts = state(con), files(run)
    with pytest.raises(firmware_chain.FirmwareChainError): retained(graph_case)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


@pytest.mark.parametrize('missing', [False, True])
def test_stale_current_snapshot_requires_retained_legacy_worklist(graph_case, missing):
    from audit_core import firmware_dive
    from tests.test_firmware_dive_gate import revise_review
    con, run, root = graph_case[:3]
    complete(graph_case); own_graph(graph_case)
    path = legacy_graph(graph_case)
    owner, = rows(con, 'cba_firmware_dive_runs')
    graph_body = json.loads((run / owner['chain_graph_path']).read_bytes())
    index = {'graph_projection': {'chain_worklist_sha256': graph_body['worklist_sha256']}}
    from audit_core import firmware_fpcheck_results
    review_path = run / 'richer-review.json'
    review = json.loads(review_path.read_bytes())
    for decision in review['decisions']:
        if decision['true_positive'] is not None:
            decision['true_positive']['root_cause'] = 'Revised independent Stage4f evidence'
    review_path.write_bytes(surface.canonical_bytes(review))
    firmware_fpcheck_results.record(con, run, review_path, replace=True)
    firmware_fpcheck.check(con, run, root, image_id='target')
    upstream = firmware_fpcheck.verified_findings_snapshot(con, run, root, image_id='target')
    if missing: path.unlink()
    before, artifacts = state(con), files(run)
    if missing:
        with pytest.raises((OSError, firmware_dive.FirmwareDiveError)):
            firmware_dive._historical_graph(run, owner, index, upstream)
    else:
        # Public retained conflict ownership still requires the exact current
        # review; historical journal replay can reconstruct the old worklist.
        with pytest.raises(firmware_chain.FirmwareChainError, match='Retained worklist differs'):
            retained(graph_case)
        graph = firmware_dive._historical_graph(run, owner, index, upstream)
        assert graph.chain_worklist_sha256 == graph_body['worklist_sha256']
        assert graph.findings != upstream.findings
    assert state(con) == before and files(run) == artifacts
