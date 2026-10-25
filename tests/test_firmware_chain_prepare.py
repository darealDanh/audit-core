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
