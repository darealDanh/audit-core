"""The chain input boundary freezes complete verified Stage 4f evidence without writes."""
import copy
import dataclasses
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, firmware_fpcheck, hunt, hunt_results, surface, surface_results
from tests.test_firmware_fpcheck_results import (api, review, completed, prepared, decision, TP, FP)  # noqa: F401
from tests.test_firmware_fpcheck_gate import publish, check
from tests.test_hunt_gate import fill, state
from tests.test_hunt_results import candidate


def files(run):
    return {p.relative_to(run).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
            for parent in ('files', 'artifacts') for p in (run / parent).rglob('*') if p.is_file()}


def snapshot(review, **kwargs):
    return firmware_fpcheck.verified_findings_snapshot(*review[:3], **kwargs)


def test_verified_snapshot_preserves_exact_semantics_parses_arrays_and_freezes_records(review):
    publish(review)
    summary = check(review)
    con, run, _, prep, *_ = review
    before, writes, artifacts = state(con), con.total_changes, files(run)
    value = snapshot(review)
    assert isinstance(value, firmware_fpcheck.VerifiedFirmwareFindingsSnapshot)
    assert (value.image_id, value.manifest_sha256, value.surface_snapshot_sha256,
            value.candidate_snapshot_sha256, value.fpcheck_worklist_sha256,
            value.findings_artifact_path, value.findings_artifact_sha256) == (
        'target', prep.manifest_sha256, prep.surface_snapshot_sha256, prep.candidate_snapshot_sha256,
        prep.worklist_sha256, pathlib.Path(summary.artifact_path).relative_to(run).as_posix(),
        con.execute('SELECT artifact_sha256 FROM cba_firmware_findings').fetchone()[0])
    for collection, table, cls, timestamp in (
        (value.findings, 'cba_firmware_findings', firmware_fpcheck.VerifiedFirmwareFinding, 'derived_at'),
        (value.surfaces, 'cba_firmware_surfaces', firmware_fpcheck.VerifiedFirmwareSurface, 'recorded_at'),
        (value.pivots, 'cba_firmware_pivots', firmware_fpcheck.VerifiedFirmwarePivot, 'recorded_at')):
        stored, = [dict(row) for row in con.execute(f'SELECT * FROM {table}')]
        expected = {k: v for k, v in stored.items() if k != timestamp}
        expected['artifact_path'] = pathlib.Path(expected['artifact_path']).relative_to(run).as_posix()
        if table == 'cba_firmware_findings':
            expected.update(contributors=({'lane': 'l-dark', 'candidate_id': 'shell-1'},
                                          {'lane': 'l-sink', 'candidate_id': 'shell-1'}),
                            lanes=('l-dark', 'l-sink'), component_paths=('c',), surface_ids=('http-c',))
        record, = collection
        assert isinstance(record, cls) and dataclasses.asdict(record) == expected
    assert value.unknowns == ()
    assert value.findings[0].evidence_summary == ('{"attacker_advantage":"Shell capability",'
        '"dedup_evidence":"Same call","mitigation_analysis":"Trim only",'
        '"reason":"Source reread","rules_applied":["HE-17"]}')
    for record in (value, *value.findings, *value.surfaces, *value.pivots, *value.findings[0].contributors):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, 'changed')
    con.execute('PRAGMA reverse_unordered_selects=ON')
    assert snapshot(review) == value
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


def test_snapshot_works_readonly_and_preserves_caller_owned_transaction(review):
    publish(review)
    check(review)
    con, run, root, *_ = review
    expected = snapshot(review)
    with sqlite3.connect(f'file:{run / "audit.db"}?mode=ro', uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert firmware_fpcheck.verified_findings_snapshot(readonly, run, root) == expected
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute("UPDATE cba_firmware_fp_runs SET prepared_at='caller-owned'")
    before, writes = state(con), con.total_changes
    assert snapshot(review) == expected
    assert con.in_transaction and state(con) == before and con.total_changes == writes
    con.rollback()


@pytest.mark.parametrize('recorded', [False, True])
def test_snapshot_never_promotes_pending_run_or_installs_findings(review, recorded):
    if recorded:
        publish(review)
    con, run, *_ = review
    before, writes, artifacts = state(con), con.total_changes, files(run)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        snapshot(review)
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


def rich_review(prepared, tmp_path, count):
    """Build real receipted surface/hunt/review generations with uncapped inputs."""
    con, run, payload, *_ = prepared
    root = tmp_path / 'root'
    original = json.loads((run / 'surface-result.json').read_text())
    c = next(row for row in original['decisions'] if row['path'] == 'c')
    template = c['surfaces'][0]
    c['surfaces'] += [template | {'surface_id': f'extra-{n:03}'} for n in range(count)]
    def unknown(identifier, component='c', surface_id=None, resolved=False):
        return dict(id=identifier, component_path=component, surface_id=surface_id, field='auth',
            question='Which authority?', settling_observation='Inspect handler authority', method='static',
            status='resolved' if resolved else 'open', resolution='Handler uses session' if resolved else None,
            evidence='c:8 session read' if resolved else None)
    c['unknowns'] = [unknown('overlap', surface_id='http-c'), unknown('component-only'),
        unknown('different-surface', surface_id='extra-000', resolved=True)] + [
        unknown(f'unknown-{n:03}') for n in range(count)]
    original['decisions'][0]['unknowns'] = [unknown('unrelated', component='a')]
    path = run / 'richer-surface.json'
    path.write_text(json.dumps(original))
    surface_results.record(con, run, path, replace=True)
    surface.check(con)
    prep = hunt.prepare(con, run, root, sink_batch_size=3, dark_batch_size=3)
    example = candidate(payload)
    fill(con, run, prep)
    sink = copy.deepcopy(payload)
    lane = prep.lanes[0]
    descriptor = json.loads(pathlib.Path(lane.worklist_path).read_bytes())['batches'][0]
    sink.update(manifest_sha256=prep.manifest_sha256, surface_snapshot_sha256=prep.surface_snapshot_sha256,
                worklist_sha256=lane.worklist_sha256, batch_sha256=descriptor['sha256'])
    candidate_decision = sink['decisions'][2]
    candidate_decision['candidates'] = [copy.deepcopy(example) | {'candidate_id': f'tp-{n:03}',
        'surface_ids': ['http-c', f'extra-{n:03}']} for n in range(count)] + [
        copy.deepcopy(example) | {'candidate_id': f'fp-{n:03}'} for n in range(count)]
    path = run / 'richer-hunt.json'
    path.write_text(json.dumps(sink))
    hunt_results.record(con, run, path, replace=True)
    for name in db.HUNT_LANES:
        hunt.check(con, run, root, lane=name)
    fp = firmware_fpcheck.prepare(con, run, root)
    index = json.loads(pathlib.Path(fp.worklist_path).read_bytes())
    for descriptor in index['batches']:
        batch = json.loads(pathlib.Path(fp.worklist_path).with_name(descriptor['path']).read_bytes())
        decisions = []
        for row in batch['candidates']:
            n = int(row['candidate_id'].split('-')[1])
            is_tp = row['candidate_id'].startswith('tp')
            decisions.append(decision('l-sink', row['candidate_id'], 'TRUE_POSITIVE' if is_tp else 'FALSE_POSITIVE',
                TP | {'root_cause_key': f'root-{n:03}', 'surface_ids': row['surface_ids']} if is_tp else
                FP | {'pivot_id': f'pivot-{n:03}'}))
        result = dict(schema_version=1, image_id='target', candidate_snapshot_sha256=fp.candidate_snapshot_sha256,
            worklist_sha256=fp.worklist_sha256, batch_path=descriptor['path'], batch_sha256=descriptor['sha256'],
            decisions=decisions)
        path = run / 'richer-review.json'
        path.write_text(json.dumps(result))
        api().record(con, run, path)
    firmware_fpcheck.check(con, run, root)
    # A foreign row with overlapping paths/IDs must never enter the selected union.
    foreign = dict(con.execute("SELECT * FROM cba_unknowns WHERE id='component-only'").fetchone())
    db.put(con, 'cba_unknowns', foreign | {'id': 'foreign-unknown', 'image_id': 'foreign'})
    return con, run, root


@pytest.mark.parametrize('count', [1, 205])
def test_exact_unknown_union_and_all_records_beyond_display_cap(prepared, tmp_path, count):
    context = rich_review(prepared, tmp_path, count)
    con, run, _ = context
    before, writes, artifacts = state(con), con.total_changes, files(run)
    value = firmware_fpcheck.verified_findings_snapshot(*context, image_id='target')
    assert len(value.findings) == len(value.pivots) == count
    assert len(value.surfaces) == count + 1
    assert tuple(row.finding_id for row in value.findings) == tuple(sorted(row.finding_id for row in value.findings))
    assert tuple(row.surface_id for row in value.surfaces) == tuple(sorted(
        ['http-c'] + [f'extra-{n:03}' for n in range(count)]))
    assert tuple(row.pivot_id for row in value.pivots) == tuple(f'pivot-{n:03}' for n in range(count))
    assert tuple(row.id for row in value.unknowns) == tuple(sorted(
        ['overlap', 'component-only', 'different-surface'] + [f'unknown-{n:03}' for n in range(count)]))
    resolved = next(row for row in value.unknowns if row.id == 'different-surface')
    assert isinstance(resolved, firmware_fpcheck.VerifiedFirmwareUnknown)
    assert (resolved.status, resolved.resolution, resolved.evidence, resolved.method) == (
        'resolved', 'Handler uses session', 'c:8 session read', 'static')
    stored = dict(con.execute("SELECT * FROM cba_unknowns WHERE id='different-surface'").fetchone())
    expected = {k: v for k, v in stored.items() if k != 'recorded_at'}
    expected['artifact_path'] = pathlib.Path(expected['artifact_path']).relative_to(run).as_posix()
    assert dataclasses.asdict(resolved) == expected
    with pytest.raises(dataclasses.FrozenInstanceError):
        resolved.status = 'open'
    for row in (*value.findings, *value.surfaces, *value.unknowns, *value.pivots):
        assert not pathlib.Path(row.artifact_path).is_absolute() and (run / row.artifact_path).is_file()
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    if count > db.MAX_ROWS:
        # All four collections must fail closed on drift beyond the display cap,
        # and a refusal must not roll back a caller's transaction.
        for sql in (
            "UPDATE cba_unknowns SET question='changed' WHERE id='unknown-204'",
            "UPDATE cba_firmware_surfaces SET reach_evidence='changed' WHERE surface_id='extra-204'",
            "UPDATE cba_firmware_pivots SET evidence='changed' WHERE pivot_id='pivot-204'",
            "UPDATE cba_firmware_findings SET title='changed' WHERE finding_id=("
                "SELECT finding_id FROM cba_firmware_findings ORDER BY finding_id DESC LIMIT 1)",
        ):
            con.execute(sql)
            before, writes = state(con), con.total_changes
            with pytest.raises(firmware_fpcheck.FpcheckError):
                firmware_fpcheck.verified_findings_snapshot(*context)
            assert con.in_transaction and state(con) == before and con.total_changes == writes
            con.rollback()


@pytest.mark.parametrize('damage', ['pending', 'foreign-finding', 'outside-artifact', 'unknown',
    'hunt-worklist', 'surface-worklist', 'missing-findings', 'symlink-findings'])
def test_snapshot_refuses_status_ownership_provenance_and_artifact_drift(review, tmp_path, damage):
    publish(review)
    summary = check(review)
    con, run, *_ = review
    artifact = pathlib.Path(summary.artifact_path)
    if damage == 'pending':
        con.execute("UPDATE cba_firmware_fp_runs SET status='pending',completed_at=NULL")
    elif damage == 'foreign-finding':
        con.execute("UPDATE cba_firmware_findings SET image_id='foreign'")
    elif damage == 'outside-artifact':
        con.execute("UPDATE cba_firmware_findings SET artifact_path=?", (str(tmp_path / 'outside.json'),))
    elif damage == 'unknown':
        current = dict(con.execute('SELECT * FROM cba_firmware_surfaces').fetchone())
        db.put(con, 'cba_unknowns', dict(id='unreceipted', image_id='target', component_path='c',
            surface_id=None, field='auth', question='Who?', settling_observation='Inspect UID', method='static',
            status='open', artifact_path=current['artifact_path'], artifact_sha256=current['artifact_sha256']))
    elif damage.endswith('worklist'):
        table = 'cba_hunt_runs' if damage.startswith('hunt') else 'cba_surface_runs'
        pathlib.Path(con.execute(f'SELECT worklist_path FROM {table}').fetchone()[0]).write_bytes(b'{}')
    elif damage == 'missing-findings':
        artifact.unlink()
    else:
        outside = tmp_path / 'outside.json'
        artifact.rename(outside)
        artifact.symlink_to(outside)
    con.commit()
    before, writes, artifacts = state(con), con.total_changes, files(run)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        snapshot(review)
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


@pytest.mark.parametrize('caller_transaction', [False, True])
@pytest.mark.parametrize('changed', ['surface', 'unknown'])
def test_snapshot_keeps_verified_sql_view_when_writer_changes_post_verification_rows(
        prepared, tmp_path, monkeypatch, caller_transaction, changed):
    # A real WAL writer commits at the verification/construction boundary. The
    # returned records must still be the generation actually verified, and any
    # caller-owned transaction must remain owned by the caller.
    context = rich_review(prepared, tmp_path, 1)
    con, run, _ = context
    con.execute('PRAGMA journal_mode=WAL')
    expected = firmware_fpcheck.verified_findings_snapshot(*context)
    original = firmware_fpcheck._verified_review
    sql = ("UPDATE cba_firmware_surfaces SET reach_evidence='unverified writer bytes' WHERE surface_id='http-c'"
           if changed == 'surface' else
           "UPDATE cba_unknowns SET question='unverified writer bytes' WHERE id='component-only'")
    if caller_transaction:
        con.execute('BEGIN')
    before, writes, artifacts = state(con), con.total_changes, files(run)
    def change_after_verification(*args, **kwargs):
        verified = original(*args, **kwargs)
        with sqlite3.connect(run / 'audit.db', timeout=0.1) as writer:
            writer.execute(sql)
        return verified
    monkeypatch.setattr(firmware_fpcheck, '_verified_review', change_after_verification)
    value = firmware_fpcheck.verified_findings_snapshot(*context)
    assert value == expected
    assert con.total_changes == writes and files(run) == artifacts
    assert con.in_transaction is caller_transaction
    if caller_transaction:
        assert state(con) == before
        con.rollback()
    with sqlite3.connect(run / 'audit.db') as observer:
        assert observer.execute('SELECT count(*) FROM ' + (
            "cba_firmware_surfaces WHERE reach_evidence='unverified writer bytes'" if changed == 'surface' else
            "cba_unknowns WHERE question='unverified writer bytes'")).fetchone()[0] == 1


# Task 3 exercises the real snapshot boundary and immutable publication below.
def chain_api():
    from audit_core import firmware_chain
    return firmware_chain


@pytest.fixture
def chain_ready(review):
    publish(review)
    check(review)
    return review


def chain_prepare(context, **kwargs):
    return chain_api().prepare(*context[:3], **kwargs)


def chain_rows(con):
    return {table: [dict(row) for row in con.execute(f'SELECT * FROM {table} ORDER BY 1,2')]
            for table in db.TABLE_SPECS if table.startswith('cba_firmware_chain')}


def seed_chain_claims(con, image_id):
    from tests.test_firmware_chain_schema import ROWS
    for table, row in ROWS:
        if table != 'cba_firmware_chain_runs':
            db.put(con, table, row | {'image_id': image_id})
    con.execute("UPDATE cba_firmware_chain_runs SET status='complete',graph_path='retained/chains.json',"
                "graph_sha256=?,prepared_at='original preparation',completed_at='original completion' WHERE image_id=?",
                ('e' * 64, image_id))
    con.commit()


def test_chain_literal_global_worklist_and_idempotent_preservation(chain_ready):
    import hashlib
    con, run, root, prep, *_ = chain_ready
    finding = dict(con.execute('SELECT * FROM cba_firmware_findings').fetchone())
    current_surface = dict(con.execute('SELECT * FROM cba_firmware_surfaces').fetchone())
    pivot = dict(con.execute('SELECT * FROM cba_firmware_pivots').fetchone())
    relative = lambda value: pathlib.Path(value).relative_to(run).as_posix()
    # Literal semantic fields; only upstream cryptographic identities/provenance
    # depend on fixture bytes. Neither the snapshot projection nor serializer is
    # used to derive this oracle.
    expected = dict(schema_version=1, image_id='target', manifest_sha256=prep.manifest_sha256,
        surface_snapshot_sha256=prep.surface_snapshot_sha256,
        candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
        fpcheck_worklist_sha256=prep.worklist_sha256,
        findings_artifact_path=relative(finding['artifact_path']),
        findings_artifact_sha256=finding['artifact_sha256'], findings=[dict(
            image_id='target', finding_id=finding['finding_id'], candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
            root_cause_key='shell', canonical_lane='l-sink', canonical_candidate_id='shell-1',
            contributors=[dict(lane='l-dark', candidate_id='shell-1'), dict(lane='l-sink', candidate_id='shell-1')],
            lanes=['l-dark', 'l-sink'], component_paths=['c'], surface_ids=['http-c'],
            title='Command injection hypothesis', bug_class='command injection', root_cause='Unchecked shell input',
            attacker_position='lan', data_flow='POST to system', impact_hypothesis='Shell execution',
            evidence_summary='{"attacker_advantage":"Shell capability","dedup_evidence":"Same call",'
                '"mitigation_analysis":"Trim only","reason":"Source reread","rules_applied":["HE-17"]}',
            confidence=6, evidence_rung='static-reviewed', artifact_path=relative(finding['artifact_path']),
            artifact_sha256=finding['artifact_sha256'])], surfaces=[dict(image_id='target', surface_id='http-c',
            component_path='c', entry_point='POST /run', protocol='http', dispatch_path='route -> run', handler='run',
            lifecycle_required='provisioned', posture_required='sta-lan', auth_required='pre-auth',
            reachability='evidenced', reach_evidence='c:8 registers before authentication.',
            artifact_path=relative(current_surface['artifact_path']), artifact_sha256=current_surface['artifact_sha256'])],
        unknowns=[], pivots=[dict(image_id='target', pivot_id='pivot-1',
            candidate_snapshot_sha256=prep.candidate_snapshot_sha256, source_lane='l-sink',
            source_candidate_id='pivot-source', component_path='c', refuting_mechanism='Argument escaping',
            enabled_observation='No shell path', evidence='Escaper at c:12',
            artifact_path=relative(pivot['artifact_path']), artifact_sha256=pivot['artifact_sha256'], context_only=True)])
    content = (json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    digest = hashlib.sha256(content).hexdigest()
    summary = chain_prepare(chain_ready)
    assert dataclasses.asdict(summary) == dict(image_id='target', manifest_sha256=prep.manifest_sha256,
        surface_snapshot_sha256=prep.surface_snapshot_sha256, candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
        generation=digest, worklist_path=str(run / 'files/firmware-chain' / digest / 'worklist.json'),
        worklist_sha256=digest, finding_count=1, surface_count=1, unknown_count=0, pivot_count=1)
    assert pathlib.Path(summary.worklist_path).read_bytes() == content
    assert str(root).encode() not in content and str(run).encode() not in content
    assert b'prepared_at' not in content and b'derived_at' not in content
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.generation = 'changed'
    row = chain_rows(con)['cba_firmware_chain_runs'][0]
    assert row['status'] == 'pending' and row['completed_at'] is None and row['prepared_at']
    assert row['fpcheck_artifact_path'] == str(run / expected['findings_artifact_path'])
    assert row['fpcheck_artifact_sha256'] == expected['findings_artifact_sha256']
    seed_chain_claims(con, 'target')
    before, writes, artifacts = state(con), con.total_changes, files(run)
    assert chain_prepare(chain_ready) == summary
    assert state(con) == before and con.total_changes == writes and files(run) == artifacts
    assert not con.in_transaction


@pytest.mark.parametrize('count', [1, 205])
def test_chain_preserves_exact_relevant_unknown_union_and_global_scale(prepared, tmp_path, count):
    context = rich_review(prepared, tmp_path, count)
    summary = chain_prepare(context, image_id='target')
    content = pathlib.Path(summary.worklist_path).read_bytes()
    parsed = json.loads(content)
    assert (summary.finding_count, summary.surface_count, summary.unknown_count, summary.pivot_count) == (
        count, count + 1, count + 3, count)
    assert len(parsed['findings']) == len(parsed['pivots']) == count
    assert [row['id'] for row in parsed['unknowns']] == sorted(
        ['overlap', 'component-only', 'different-surface'] + [f'unknown-{n:03}' for n in range(count)])
    for row in parsed['unknowns']:
        stored = dict(context[0].execute('SELECT * FROM cba_unknowns WHERE id=?', (row['id'],)).fetchone())
        stored.pop('recorded_at')
        stored['artifact_path'] = pathlib.Path(stored['artifact_path']).relative_to(context[1]).as_posix()
        assert row == stored
    assert all(row['context_only'] is True for row in parsed['pivots'])
    assert 'batches' not in parsed
    # Reverse actual insertion order, preserving all original timestamps.
    for table in ('cba_firmware_findings', 'cba_firmware_surfaces', 'cba_unknowns', 'cba_firmware_pivots'):
        stored = list(context[0].execute(f'SELECT * FROM {table} ORDER BY 1,2'))
        columns = tuple(stored[0].keys())
        context[0].execute(f'DELETE FROM {table}')
        context[0].executemany(f'INSERT INTO {table} ({",".join(columns)}) VALUES ({",".join("?" for _ in columns)})',
                              [tuple(row) for row in reversed(stored)])
    context[0].commit()
    assert chain_prepare(context, image_id='target') == summary
    assert pathlib.Path(summary.worklist_path).read_bytes() == content


def empty_review(con, run, root, image_id):
    from tests.test_hunt_prepare import add_target
    add_target(con, run, root, ['a', 'b'], image_id=image_id)
    prepared_hunt = hunt.prepare(con, run, root, image_id=image_id)
    fill(con, run, prepared_hunt)
    for lane in db.HUNT_LANES:
        hunt.check(con, run, root, lane=lane, image_id=image_id)
    prep = firmware_fpcheck.prepare(con, run, root, image_id=image_id)
    batch, = json.loads(pathlib.Path(prep.worklist_path).read_bytes())['batches']
    path = run / 'empty-review.json'
    path.write_text(json.dumps(dict(schema_version=1, image_id=image_id,
        candidate_snapshot_sha256=prep.candidate_snapshot_sha256, worklist_sha256=prep.worklist_sha256,
        batch_path=batch['path'], batch_sha256=batch['sha256'], decisions=[])))
    api().record(con, run, path)
    return firmware_fpcheck.check(con, run, root, image_id=image_id)


def test_chain_empty_global_worklist_and_exact_unicode_image_selection(tmp_path):
    from audit_core import workspace
    run = workspace.init_run(tmp_path / 'project')
    image_id = '路由器|r1|雪:%_\n"'
    root = tmp_path / 'root'
    with db.connect(run / 'audit.db') as con:
        reviewed = empty_review(con, run, root, image_id)
        summary = chain_prepare((con, run, root))
        assert summary.image_id == image_id and summary.generation == summary.worklist_sha256
        content = pathlib.Path(summary.worklist_path).read_bytes()
        parsed = json.loads(content)
        assert parsed['image_id'] == image_id
        assert [parsed[name] for name in ('findings', 'surfaces', 'unknowns', 'pivots')] == [[], [], [], []]
        assert (summary.finding_count, summary.surface_count, summary.unknown_count, summary.pivot_count) == (0,0,0,0)
        assert parsed['findings_artifact_path'] == pathlib.Path(reviewed.artifact_path).relative_to(run).as_posix()
        assert image_id.encode() not in content  # newline/quote are JSON escaped
        sibling_root = tmp_path / 'sibling'
        empty_review(con, run, sibling_root, 'sibling')
        before = state(con)
        with pytest.raises(chain_api().FirmwareChainError):
            chain_prepare((con, run, root))
        assert state(con) == before and not con.in_transaction
        assert chain_prepare((con, run, root), image_id=image_id) == summary
        with pytest.raises(chain_api().FirmwareChainError):
            chain_prepare((con, run, root), image_id='absent')


@pytest.mark.parametrize('damage', ['pending', 'same-size-root', 'missing-root', 'finding-artifact'])
def test_chain_requires_complete_snapshot_and_live_root(review, damage):
    if damage != 'pending':
        publish(review)
        completed_review = check(review)
    con, run, root, *_ = review
    if damage == 'same-size-root':
        (root / 'c').write_bytes(b'jello\n')
    elif damage == 'missing-root':
        (root / 'c').unlink()
    elif damage == 'finding-artifact':
        pathlib.Path(completed_review.artifact_path).write_bytes(b'{}')
    before, artifacts = state(con), files(run)
    with pytest.raises(chain_api().FirmwareChainError):
        chain_prepare(review)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


def test_chain_active_transaction_refused_without_rollback(chain_ready):
    con = chain_ready[0]
    con.execute("UPDATE cba_firmware_fp_runs SET prepared_at='caller-owned'")
    before = state(con)
    with pytest.raises(chain_api().FirmwareChainError, match='active transaction'):
        chain_prepare(chain_ready)
    assert state(con) == before and con.in_transaction
    con.rollback()


def test_changed_input_replaces_only_selected_image_chain_state(chain_ready):
    from tests.test_firmware_chain_schema import RUN
    con = chain_ready[0]
    first = chain_prepare(chain_ready)
    seed_chain_claims(con, 'target')
    db.put(con, 'cba_firmware_chain_runs', RUN | {'image_id': 'sibling'})
    seed_chain_claims(con, 'sibling')
    payload = copy.deepcopy(chain_ready[4])
    payload['decisions'][2]['true_positive']['root_cause'] = 'Changed reviewed source evidence'
    path = chain_ready[1] / 'changed-review.json'
    path.write_text(json.dumps(payload))
    api().record(con, chain_ready[1], path, replace=True)
    check(chain_ready)
    before = chain_rows(con)
    result = chain_prepare(chain_ready)
    assert result.generation != first.generation and pathlib.Path(first.worklist_path).is_file()
    after = chain_rows(con)
    for table in before:
        assert [r for r in after[table] if r['image_id'] == 'sibling'] == [
            r for r in before[table] if r['image_id'] == 'sibling']
        target = [r for r in after[table] if r['image_id'] == 'target']
        if table == 'cba_firmware_chain_runs':
            assert len(target) == 1 and target[0]['status'] == 'pending'
            assert target[0]['completed_at'] is target[0]['graph_path'] is target[0]['graph_sha256'] is None
        else:
            assert target == []


@pytest.mark.parametrize('commit', [False, True])
def test_chain_invalidator_exact_six_tables_dependency_order_and_commit(chain_ready, commit):
    from tests.test_firmware_chain_schema import RUN
    con = chain_ready[0]
    chain_prepare(chain_ready)
    seed_chain_claims(con, 'target')
    db.put(con, 'cba_firmware_chain_runs', RUN | {'image_id': 'sibling'})
    seed_chain_claims(con, 'sibling')
    before = state(con)
    queries = []
    con.set_trace_callback(queries.append)
    chain_api().invalidate(con, 'target', commit=commit)
    con.set_trace_callback(None)
    after = state(con)
    for table in before:
        if table in chain_rows(con):
            assert after[table] == [r for r in before[table] if r[0] != 'target']
        else:
            assert after[table] == before[table]
    deleted = [q.split()[2] for q in queries if q.startswith('DELETE FROM')]
    assert deleted == ['cba_firmware_chain_edges', 'cba_firmware_chains', 'cba_firmware_chain_dispositions',
                       'cba_firmware_chain_unknowns', 'cba_firmware_chain_receipts', 'cba_firmware_chain_runs']
    assert con.in_transaction is not commit
    if not commit:
        con.rollback()
        assert state(con) == before


@pytest.mark.parametrize('parent', ['files', 'files/firmware-chain'])
def test_chain_refuses_symlink_parent_before_install(chain_ready, tmp_path, parent):
    con, run, *_ = chain_ready
    destination = run / parent
    outside = tmp_path / 'outside'
    outside.mkdir()
    if destination.exists():
        destination.rename(outside / 'retained')
    destination.symlink_to(outside, target_is_directory=True)
    before = state(con)
    with pytest.raises(chain_api().FirmwareChainError):
        chain_prepare(chain_ready)
    assert state(con) == before and not list(outside.glob('**/worklist.json'))


@pytest.mark.parametrize('damage', ['installed-byte', 'root', 'snapshot', 'prior-run', 'parent-symlink'])
def test_chain_revalidates_after_install_and_preserves_prior_sql(chain_ready, monkeypatch, tmp_path, damage):
    module = chain_api()
    con, run, root, *_ = chain_ready
    initial = chain_prepare(chain_ready)
    seed_chain_claims(con, 'target')
    before = state(con)
    install = surface.atomic_install
    def changed(destination, generated):
        install(destination, generated)
        if damage == 'installed-byte':
            (destination / 'worklist.json').write_bytes(b'{}')
        elif damage == 'root':
            (root / 'c').write_bytes(b'jello\n')
        elif damage == 'snapshot':
            con.execute("UPDATE cba_firmware_findings SET title='changed'")
            con.commit()
        elif damage == 'prior-run':
            con.execute("UPDATE cba_firmware_chain_runs SET prepared_at='concurrent change'")
            con.commit()
        else:
            outside = tmp_path / 'moved'
            destination.parent.rename(outside)
            destination.parent.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(surface, 'atomic_install', changed)
    with pytest.raises(module.FirmwareChainError):
        chain_prepare(chain_ready)
    after = state(con)
    if damage == 'snapshot':
        before['cba_firmware_findings'] = after['cba_firmware_findings']
    if damage == 'prior-run':
        before['cba_firmware_chain_runs'] = after['cba_firmware_chain_runs']
    assert after == before and not con.in_transaction
    assert pathlib.Path(initial.worklist_path).is_file()


@pytest.mark.parametrize('operation', ['delete', 'insert', 'commit', 'unexpected'])
def test_chain_failed_publication_rolls_back_prior_sql(chain_ready, monkeypatch, operation):
    module = chain_api()
    con, run, root, *_ = chain_ready
    first = chain_prepare(chain_ready)
    seed_chain_claims(con, 'target')
    # Force replacement using a stale selected-image run identity, without
    # changing the complete verified upstream generation.
    con.execute("UPDATE cba_firmware_chain_runs SET worklist_sha256=?", ('0' * 64,))
    con.commit()
    before = state(con)
    if operation in ('delete', 'insert'):
        action = 'DELETE' if operation == 'delete' else 'INSERT'
        con.execute(f"CREATE TEMP TRIGGER fail_publication BEFORE {action} ON cba_firmware_chain_runs "
                    "BEGIN SELECT RAISE(ABORT,'injected SQL failure'); END")
        connection = con
        error = module.FirmwareChainError
    else:
        class Connection:
            def __getattr__(self, name):
                return getattr(con, name)
            def commit(self):
                raise sqlite3.OperationalError('injected commit failure')
        connection = Connection()
        error = module.FirmwareChainError
        if operation == 'unexpected':
            original = db.put
            def failing_put(*args, **kwargs):
                if args[1] == 'cba_firmware_chain_runs':
                    raise RuntimeError('unexpected failure')
                return original(*args, **kwargs)
            monkeypatch.setattr(db, 'put', failing_put)
            error = RuntimeError
    with pytest.raises(error):
        module.prepare(connection, run, root)
    assert state(con) == before and not con.in_transaction
    assert pathlib.Path(first.worklist_path).is_file()


def test_chain_real_competing_writer_keeps_prior_state_and_only_unreferenced_worklist(chain_ready):
    import time
    con, run, *_ = chain_ready
    con.execute('PRAGMA busy_timeout=25')
    before = state(con)
    with sqlite3.connect(run / 'audit.db', timeout=0.025) as other:
        other.execute('BEGIN IMMEDIATE')
        other.execute("UPDATE cba_firmware_fp_runs SET prepared_at='competing writer'")
        start = time.monotonic()
        with pytest.raises(chain_api().FirmwareChainError) as error:
            chain_prepare(chain_ready)
        assert time.monotonic() - start < 5
        assert isinstance(error.value.__cause__, sqlite3.OperationalError)
        assert 'locked' in str(error.value.__cause__).lower()
        assert state(con) == before and not con.in_transaction and other.in_transaction
        assert other.execute('SELECT prepared_at FROM cba_firmware_fp_runs').fetchone() == ('competing writer',)
        artifact, = (run / 'files/firmware-chain').rglob('worklist.json')
        assert json.loads(artifact.read_bytes())['findings']
        other.rollback()
    assert state(con) == before


@pytest.mark.parametrize('damage', ['bytes', 'extra', 'file-symlink', 'directory-symlink'])
def test_chain_preexisting_generation_drift_is_never_repaired_or_published(chain_ready, tmp_path, damage):
    con, run, *_ = chain_ready
    summary = chain_prepare(chain_ready)
    seed_chain_claims(con, 'target')
    path = pathlib.Path(summary.worklist_path)
    if damage == 'bytes':
        path.write_bytes(b'{}')
    elif damage == 'extra':
        path.with_name('extra.json').write_bytes(b'{}')
    elif damage == 'file-symlink':
        outside = tmp_path / 'worklist.json'
        path.rename(outside)
        path.symlink_to(outside)
    else:
        outside = tmp_path / 'generation'
        path.parent.rename(outside)
        path.parent.symlink_to(outside, target_is_directory=True)
    before, artifacts = state(con), files(run)
    with pytest.raises(chain_api().FirmwareChainError):
        chain_prepare(chain_ready)
    assert state(con) == before and files(run) == artifacts and not con.in_transaction


def test_chain_valid_upstream_replacement_between_read_and_publication_is_refused(chain_ready, monkeypatch):
    con, run, root, *_ = chain_ready
    chain_prepare(chain_ready)
    seed_chain_claims(con, 'target')
    published_state = {}
    install = surface.atomic_install
    def replaced(destination, generated):
        install(destination, generated)
        # Complete a real new Stage 4f generation, without recursively invoking
        # this installation hook from the Stage 4f artifact publisher.
        with monkeypatch.context() as local:
            local.setattr(surface, 'atomic_install', install)
            payload = copy.deepcopy(chain_ready[4])
            payload['decisions'][2]['true_positive']['root_cause'] = 'New fully verified evidence'
            path = run / 'concurrent-review.json'
            path.write_text(json.dumps(payload))
            api().record(con, run, path, replace=True)
            check(chain_ready)
            published_state.update(chain_rows(con))
    monkeypatch.setattr(surface, 'atomic_install', replaced)
    with pytest.raises(chain_api().FirmwareChainError, match='inputs changed'):
        chain_prepare(chain_ready)
    assert published_state and chain_rows(con) == published_state and not con.in_transaction
    assert firmware_fpcheck.verified_findings_snapshot(con, run, root).findings[0].root_cause == 'New fully verified evidence'
