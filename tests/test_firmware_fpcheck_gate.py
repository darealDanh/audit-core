"""Global review completion refuses drift and publishes findings atomically."""
import copy
import dataclasses
import hashlib
import json
import pathlib
import sqlite3
import time

import pytest

from audit_core import db, firmware_fpcheck, hunt, surface, workspace
from tests.test_firmware_fpcheck_results import (api, review, completed, prepared, decision, TP, FP, DUP)  # noqa: F401
from tests.test_firmware_fpcheck_import import source, rows, split_payloads
from tests.test_hunt_gate import fill, state
from tests.test_hunt_prepare import add_target
from tests.test_firmware_fpcheck_schema import FINDING


def publish(review, payload=None):
    return api().record(review[0], review[1], source(review, payload))


def check(review):
    return firmware_fpcheck.check(*review[:3])


def test_complete_derives_reviewed_finding_and_idempotently_revalidates(review):
    publish(review)
    con, run, _, prep, *_ = review
    summary = check(review)
    assert (summary.image_id, summary.candidate_count, summary.true_positives, summary.false_positives,
            summary.duplicates, summary.pivots, summary.complete) == ('target', 3, 1, 1, 1, 1, True)
    finding, = rows(con, 'cba_firmware_findings')
    assert (finding['root_cause_key'], finding['confidence'], finding['evidence_rung']) == ('shell', 6, 'static-reviewed')
    assert json.loads(finding['contributors']) == [dict(lane='l-dark', candidate_id='shell-1'),
                                                  dict(lane='l-sink', candidate_id='shell-1')]
    assert json.loads(finding['lanes']) == ['l-dark', 'l-sink']
    assert json.loads(finding['component_paths']) == ['c']
    assert json.loads(finding['surface_ids']) == ['http-c']
    assert (finding['root_cause'], finding['attacker_position'], finding['data_flow'], finding['impact_hypothesis']) == (
        'Unchecked shell input', 'lan', 'POST to system', 'Shell execution')
    assert 'Source reread' in finding['evidence_summary'] and 'Same call' in finding['evidence_summary']
    assert summary.findings[0].finding_id == finding['finding_id']
    assert summary.findings[0].contributor_count == 2
    artifact = pathlib.Path(summary.artifact_path)
    content = artifact.read_bytes()
    assert finding['artifact_sha256'] == hashlib.sha256(content).hexdigest()
    assert finding['artifact_path'] == str(artifact)
    parsed = json.loads(content)
    assert parsed['candidate_snapshot_sha256'] == prep.candidate_snapshot_sha256
    assert len(parsed['findings']) == 1 and b'derived_at' not in content
    run_row, = rows(con, 'cba_firmware_fp_runs')
    assert run_row['status'] == 'complete' and run_row['completed_at'] and finding['derived_at']
    before, writes = state(con), con.total_changes
    assert check(review) == summary
    assert state(con) == before and con.total_changes == writes and artifact.read_bytes() == content
    assert rows(con, 'cba_findings') == rows(con, 'cba_fp_verdicts') == []
    with pytest.raises(dataclasses.FrozenInstanceError):
        summary.complete = False


@pytest.mark.parametrize('same_key', [True, False])
def test_exact_keys_group_and_canonical_scalars_minimum_and_sorted_unions(review, same_key):
    payload = copy.deepcopy(review[4])
    payload['decisions'] = [decision('l-dark', 'shell-1', 'TRUE_POSITIVE', TP | {
        'root_cause_key': 'shell' if same_key else 'different', 'root_cause': 'Canonical root',
        'component_paths': ['c', 'a'], 'data_flow': 'Canonical flow'}),
        payload['decisions'][1], payload['decisions'][2]]
    payload['decisions'][0]['confidence'] = 9
    payload['decisions'][2]['confidence'] = 2
    publish(review, payload)
    summary = check(review)
    findings = rows(review[0], 'cba_firmware_findings')
    assert len(summary.findings) == (1 if same_key else 2)
    canonical = next(f for f in findings if f['canonical_lane'] == 'l-dark')
    candidate = review[0].execute("SELECT title,bug_class FROM cba_hunt_candidates WHERE lane='l-dark'").fetchone()
    assert (canonical['title'], canonical['bug_class']) == tuple(candidate)
    assert (canonical['root_cause'], canonical['data_flow']) == ('Canonical root', 'Canonical flow')
    assert json.loads(canonical['component_paths']) == ['a', 'c']
    assert canonical['confidence'] == (2 if same_key else 9)


def test_receipted_empty_hunt_completes_with_zero_findings(tmp_path):
    run = workspace.init_run(tmp_path / 'project')
    root = tmp_path / 'root'
    with db.connect(run / 'audit.db') as con:
        add_target(con, run, root, ['a', 'b'])
        prepared_hunt = hunt.prepare(con, run, root)
        fill(con, run, prepared_hunt)
        for lane in db.HUNT_LANES:
            hunt.check(con, run, root, lane=lane)
        prep = firmware_fpcheck.prepare(con, run, root)
        batch, = json.loads(pathlib.Path(prep.worklist_path).read_bytes())['batches']
        payload = dict(schema_version=1, image_id='target', candidate_snapshot_sha256=prep.candidate_snapshot_sha256,
            worklist_sha256=prep.worklist_sha256, batch_path=batch['path'], batch_sha256=batch['sha256'], decisions=[])
        path = run / 'empty.json'
        path.write_text(json.dumps(payload))
        api().record(con, run, path)
        result = firmware_fpcheck.check(con, run, root)
        assert result.complete and result.candidate_count == 0 and result.findings == ()
        assert json.loads(pathlib.Path(result.artifact_path).read_bytes())['findings'] == []
        before, writes = state(con), con.total_changes
        assert firmware_fpcheck.check(con, run, root) == result
        assert state(con) == before and con.total_changes == writes


def test_all_false_positives_complete_without_findings_and_preserve_every_pivot(review):
    payload = copy.deepcopy(review[4])
    payload['decisions'] = [decision(d['lane'], d['candidate_id'], 'FALSE_POSITIVE',
        FP | {'pivot_id': f'pivot-{number}'}) for number, d in enumerate(payload['decisions'])]
    publish(review, payload)
    before = rows(review[0], 'cba_firmware_pivots')
    result = check(review)
    assert (result.candidate_count, result.true_positives, result.false_positives,
            result.duplicates, result.pivots, result.findings) == (3, 0, 3, 0, 3, ())
    assert rows(review[0], 'cba_firmware_findings') == []
    assert rows(review[0], 'cba_firmware_pivots') == before
    assert json.loads(pathlib.Path(result.artifact_path).read_bytes())['findings'] == []
    assert check(review) == result


def test_transitive_cross_batch_cross_lane_duplicates_are_global(review):
    payloads = split_payloads(review)
    for payload in payloads:
        payload['decisions'] = [decision(d['lane'], d['candidate_id'], 'DUPLICATE', DUP | {
            'target_lane': 'l-sink', 'target_candidate_id': 'pivot-source'}) if d['lane'] == 'l-dark'
            else decision(d['lane'], d['candidate_id'], 'DUPLICATE', DUP) if d['candidate_id'] == 'pivot-source'
            else d for d in payload['decisions']]
        publish(review, payload)
    result = check(review)
    assert (result.true_positives, result.duplicates, result.pivots) == (1, 2, 0)
    assert result.findings[0].contributor_count == 3


@pytest.mark.parametrize('damage', ['fp-terminal', 'cycle'])
def test_invalid_global_duplicate_graph_preserves_sql(review, damage):
    payloads = split_payloads(review)
    for payload in payloads:
        for d in payload['decisions']:
            if d['lane'] == 'l-dark':
                d['duplicate']['target_candidate_id'] = 'pivot-source'
            if damage == 'cycle' and d['candidate_id'] == 'pivot-source':
                d.update(verdict='DUPLICATE', false_positive=None,
                    duplicate=DUP | {'target_lane': 'l-dark'})
        publish(review, payload)
    before = state(review[0])
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert state(review[0]) == before and not review[0].in_transaction


@pytest.mark.parametrize('damage', ['hunt-pending', 'root', 'manifest', 'surface', 'worklist', 'candidate',
    'snapshot', 'missing-receipt', 'extra-receipt', 'missing-verdict', 'extra-verdict', 'counts', 'pivot',
    'missing-pivot', 'extra-pivot', 'result', 'self-target', 'missing-target', 'foreign-target', 'group',
    'finding', 'finding-artifact', 'timestamp'])
def test_refusal_also_revalidates_previously_complete_state(review, damage):
    imported = publish(review)
    check(review)
    con, run, root, prep, *_ = review
    if damage == 'hunt-pending':
        con.execute("UPDATE cba_hunt_runs SET status='pending',completed_at=NULL WHERE lane='l-dark'")
    elif damage == 'root':
        file = root / 'c'
        original = file.read_bytes()
        file.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    elif damage == 'manifest':
        con.execute("UPDATE cba_firmware_files SET sha256=? WHERE path='c'", ('f'*64,))
    elif damage == 'surface':
        con.execute("UPDATE cba_firmware_surfaces SET reach_evidence='changed'")
    elif damage == 'worklist':
        pathlib.Path(prep.worklist_path).write_bytes(b'{}')
    elif damage == 'candidate':
        con.execute("UPDATE cba_hunt_candidates SET title='changed'")
    elif damage == 'snapshot':
        con.execute("UPDATE cba_firmware_fp_runs SET candidate_snapshot_sha256=?", ('f'*64,))
    elif damage == 'missing-receipt':
        con.execute('DELETE FROM cba_firmware_fp_receipts')
    elif damage == 'extra-receipt':
        db.put(con, 'cba_firmware_fp_receipts', rows(con, 'cba_firmware_fp_receipts')[0] | {'batch_path':'batch-9999.json'})
    elif damage == 'missing-verdict':
        con.execute("DELETE FROM cba_firmware_fp_verdicts WHERE lane='l-dark'")
    elif damage == 'extra-verdict':
        db.put(con, 'cba_firmware_fp_verdicts', rows(con, 'cba_firmware_fp_verdicts')[0] | {'candidate_id':'extra'})
    elif damage == 'counts':
        con.execute('UPDATE cba_firmware_fp_receipts SET duplicate_count=2')
    elif damage == 'pivot':
        con.execute("UPDATE cba_firmware_pivots SET evidence='changed'")
    elif damage == 'missing-pivot':
        con.execute('DELETE FROM cba_firmware_pivots')
    elif damage == 'extra-pivot':
        db.put(con, 'cba_firmware_pivots', rows(con, 'cba_firmware_pivots')[0] | {'pivot_id':'extra'})
    elif damage == 'result':
        pathlib.Path(imported.artifact_path).write_bytes(b'{}')
    elif damage.endswith('target'):
        target_lane, target = {'self-target':('l-dark','shell-1'), 'missing-target':('l-sink','absent'),
            'foreign-target':('l-dark','foreign')}[damage]
        con.execute("UPDATE cba_firmware_fp_verdicts SET duplicate_lane=?,duplicate_candidate_id=? WHERE lane='l-dark'",
            (target_lane, target))
    elif damage == 'group':
        con.execute("UPDATE cba_firmware_fp_verdicts SET root_cause_key='' WHERE verdict='TRUE_POSITIVE'")
    elif damage == 'finding':
        con.execute("UPDATE cba_firmware_findings SET title='changed'")
    elif damage == 'finding-artifact':
        pathlib.Path(rows(con,'cba_firmware_findings')[0]['artifact_path']).write_bytes(b'{}')
    else:
        con.execute('UPDATE cba_firmware_fp_runs SET completed_at=NULL')
    con.commit()
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert state(con) == before and not con.in_transaction


def test_duplicate_confidence_is_conservative_and_cannot_be_canonical(review):
    payload = copy.deepcopy(review[4])
    payload['decisions'][0]['confidence'] = 1
    publish(review, payload)
    result = check(review)
    finding, = rows(review[0], 'cba_firmware_findings')
    assert (finding['confidence'], finding['canonical_lane'], finding['canonical_candidate_id']) == (1, 'l-sink', 'shell-1')
    assert result.findings[0].canonical_lane == 'l-sink'


def test_completed_gate_refuses_missing_canonical_artifact_instead_of_recreating_it(review):
    publish(review)
    result = check(review)
    path = pathlib.Path(result.artifact_path)
    path.unlink()
    path.parent.rmdir()
    before = state(review[0])
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert state(review[0]) == before and not path.exists()


@pytest.mark.parametrize('terminal', ['tp', 'fp', 'cycle', 'missing', 'self'])
def test_duplicate_resolver_handles_chains_beyond_python_recursion_limit(terminal):
    # Exercise the actual resolver on 2,001 nodes without deep JSON nesting.
    from audit_core.firmware_fpcheck_results import Decision, Duplicate
    graph = {}
    for number in range(2000):
        graph[('l-dark', str(number))] = Decision('l-dark', str(number), 'DUPLICATE',
            'review', 'advantage', ('HE-1',), 'mitigation', 4, None, None,
            Duplicate('l-dark', str(number + 1), 'same sink'))
    last = 'TRUE_POSITIVE' if terminal == 'tp' else 'FALSE_POSITIVE'
    graph[('l-dark', '2000')] = Decision('l-dark', '2000', last, 'review', 'advantage', ('HE-1',),
        'mitigation', 5, None, None, None)
    if terminal in ('cycle', 'missing', 'self'):
        target = {'cycle':'0', 'missing':'absent', 'self':'2000'}[terminal]
        graph[('l-dark','2000')] = dataclasses.replace(graph[('l-dark','2000')], verdict='DUPLICATE',
            duplicate=Duplicate('l-dark', target, 'same sink'))
    if terminal == 'tp':
        resolved = firmware_fpcheck._resolve_duplicates(graph)
        assert len(resolved) == 2001 and set(resolved.values()) == {('l-dark','2000')}
    else:
        with pytest.raises(firmware_fpcheck.FpcheckError):
            firmware_fpcheck._resolve_duplicates(graph)


@pytest.mark.parametrize('table', ['cba_firmware_fp_receipts', 'cba_firmware_fp_verdicts'])
def test_duplicate_read_rows_fail_closed_at_aggregation_boundary(review, monkeypatch, table):
    publish(review)
    original = surface._query
    def duplicate(con, sql, args=()):
        values = original(con, sql, args)
        if sql.startswith('SELECT * FROM ' + table + ' WHERE') and values:
            return values + [values[0]]
        return values
    monkeypatch.setattr(surface, '_query', duplicate)
    before = state(review[0])
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert state(review[0]) == before and not review[0].in_transaction


@pytest.mark.parametrize('damage,match', [('missing-run', 'One prepared'),
    ('receipt-provenance', 'foreign provenance'), ('receipt-digest', 'canonical result differ')])
def test_gate_refuses_missing_preparation_and_receipt_provenance_drift(review, damage, match):
    publish(review)
    con = review[0]
    if damage == 'missing-run':
        con.execute('DELETE FROM cba_firmware_fp_runs')
    else:
        column = 'worklist_sha256' if damage == 'receipt-provenance' else 'result_sha256'
        con.execute(f'UPDATE cba_firmware_fp_receipts SET {column}=?', ('f' * 64,))
    con.commit()
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError, match=match):
        check(review)
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize('damage,match', [('duplicate-decision', 'Duplicate firmware review decision'),
    ('duplicate-pivot', 'Duplicate firmware pivot'), ('missing-decision', 'do not cover the candidate')])
def test_aggregator_refuses_invalid_validator_output_without_publication(review, monkeypatch, damage, match):
    # Break the upstream validator contract while retaining the actual immutable
    # bytes, to pin the aggregation boundary's independent ownership checks.
    publish(review)
    con, run, *_ = review
    module = api()
    validate, canonical = module.validate, module.canonical_bytes
    original = validate(con, run, module.load(rows(con, 'cba_firmware_fp_receipts')[0]['result_path']))
    decisions = original.result.decisions
    if damage == 'duplicate-decision':
        decisions = (decisions[0], decisions[1], decisions[0])
    elif damage == 'duplicate-pivot':
        decisions = (decisions[0], decisions[1], dataclasses.replace(decisions[2],
            verdict='FALSE_POSITIVE', true_positive=None, false_positive=decisions[1].false_positive))
    else:
        decisions = decisions[:2]
    counts = {verdict: sum(d.verdict == verdict for d in decisions) for verdict in db.FIRMWARE_FP_VERDICTS}
    con.execute('UPDATE cba_firmware_fp_receipts SET verdict_count=?,true_positive_count=?,false_positive_count=?,'
        'duplicate_count=?,pivot_count=?', (len(decisions), counts['TRUE_POSITIVE'], counts['FALSE_POSITIVE'],
        counts['DUPLICATE'], counts['FALSE_POSITIVE']))
    con.commit()
    cached = {}
    def invalid_output(*args):
        verified = validate(*args)
        changed = dataclasses.replace(verified, result=dataclasses.replace(verified.result, decisions=decisions))
        cached[id(changed)] = canonical(verified)
        return changed
    monkeypatch.setattr(module, 'validate', invalid_output)
    monkeypatch.setattr(module, 'canonical_bytes', lambda value: cached[id(value)])
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError, match=match):
        check(review)
    assert state(con) == before and not con.in_transaction


def test_active_caller_transaction_is_preserved(review):
    publish(review)
    con = review[0]
    con.execute("UPDATE cba_firmware_fp_runs SET prepared_at='caller-owned'")
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert con.in_transaction and state(con) == before
    con.rollback()


def test_competing_writer_preserves_both_transactions_and_leaves_only_unreferenced_artifact(review):
    publish(review)
    con, run, *_ = review
    before = state(con)
    con.execute('PRAGMA busy_timeout=25')
    other = sqlite3.connect(run / 'audit.db', timeout=0.025)
    try:
        other.execute('BEGIN IMMEDIATE')
        other.execute("UPDATE cba_firmware_fp_runs SET prepared_at='competing writer'")
        started = time.monotonic()
        with pytest.raises(firmware_fpcheck.FpcheckError) as error:
            check(review)
        assert time.monotonic() - started < 5
        assert isinstance(error.value.__cause__, sqlite3.OperationalError)
        assert 'locked' in str(error.value.__cause__).lower()
        assert state(con) == before and not con.in_transaction
        assert other.in_transaction
        assert other.execute('SELECT prepared_at FROM cba_firmware_fp_runs').fetchone() == ('competing writer',)
        artifact, = (run / 'artifacts/firmware-fpcheck').rglob('findings.json')
        assert json.loads(artifact.read_bytes())['findings']
        assert rows(con, 'cba_firmware_findings') == []
        other.rollback()
        assert state(con) == before
    finally:
        other.close()


@pytest.mark.parametrize('operation,table', [('DELETE','cba_firmware_findings'), ('INSERT','cba_firmware_findings'),
    ('UPDATE','cba_firmware_fp_runs')])
def test_after_install_sql_failures_preserve_prior_rows(review, operation, table):
    publish(review)
    con, run, *_ = review
    db.put(con, 'cba_firmware_findings', FINDING | {'image_id':'target'})
    con.execute(f"CREATE TRIGGER fail_gate BEFORE {operation} ON {table} BEGIN SELECT RAISE(FAIL,'injected'); END")
    con.commit()
    before = state(con)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert state(con) == before and not con.in_transaction
    assert list((run / 'artifacts/firmware-fpcheck').rglob('findings.json'))


@pytest.mark.parametrize('damage', ['hunt', 'verdict', 'run', 'root', 'artifact', 'install'])
def test_install_races_reverify_inputs_under_lock(review, monkeypatch, damage):
    publish(review)
    con, run, root, *_ = review
    before = state(con)
    original = surface.atomic_install
    def install(destination, files):
        nonlocal before
        if damage == 'install':
            raise OSError('injected')
        original(destination, files)
        if damage in ('hunt','verdict','run'):
            with db.connect(run / 'audit.db') as other:
                if damage == 'hunt':
                    other.execute("UPDATE cba_hunt_candidates SET title='concurrent'")
                elif damage == 'verdict':
                    other.execute("UPDATE cba_firmware_fp_verdicts SET reason='concurrent'")
                else:
                    other.execute("UPDATE cba_firmware_fp_runs SET prepared_at='concurrent'")
                other.commit()
        elif damage == 'root':
            original_bytes = (root/'c').read_bytes()
            (root/'c').write_bytes(bytes([original_bytes[0]^1])+original_bytes[1:])
        else:
            (destination/'findings.json').write_bytes(b'{}')
        before = state(con)
    monkeypatch.setattr(surface, 'atomic_install', install)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        check(review)
    assert state(con) == before and not con.in_transaction


def test_commit_failure_rolls_back_complete_generation(review):
    publish(review)
    original, run, root, *_ = review
    class FailCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError('injected commit')
    con = sqlite3.connect(run/'audit.db', factory=FailCommit)
    con.row_factory = sqlite3.Row
    before = state(con)
    try:
        with pytest.raises(firmware_fpcheck.FpcheckError):
            firmware_fpcheck.check(con,run,root)
        assert state(con) == before and not con.in_transaction
    finally:
        con.close()


@pytest.mark.parametrize('failure', ['sql','filesystem'])
def test_read_failures_are_domain_errors_without_sql_changes(review, monkeypatch, failure):
    publish(review)
    con, run, root, *_ = review
    before = state(con)
    if failure == 'sql':
        con.set_authorizer(lambda operation, *args: sqlite3.SQLITE_DENY if operation == sqlite3.SQLITE_READ else sqlite3.SQLITE_OK)
    else:
        original = pathlib.Path.read_bytes
        def unreadable(path):
            if path.name == 'result.json':
                raise OSError('injected read')
            return original(path)
        monkeypatch.setattr(pathlib.Path, 'read_bytes', unreadable)
    with pytest.raises(firmware_fpcheck.FpcheckError):
        firmware_fpcheck.check(con,run,root)
    con.set_authorizer(None)
    assert state(con) == before and not con.in_transaction
