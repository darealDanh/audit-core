"""Read-only graph validation against real prepared, receipted evidence."""
import copy
import dataclasses
import json
import pathlib
import sqlite3

import pytest

from audit_core import db, firmware_chain, firmware_chain_results as results
from tests.test_firmware_chain_prepare import prepared, rich_review, files  # noqa: F401
from tests.test_hunt_gate import state


@pytest.fixture
def graph_case(prepared, tmp_path):
    con, run, root = rich_review(prepared, tmp_path, 4)
    summary = firmware_chain.prepare(con, run, root)
    worklist = json.loads(pathlib.Path(summary.worklist_path).read_bytes())
    ids = [f['finding_id'] for f in worklist['findings']]
    initial = dict(lifecycle='provisioned', posture='STA-LAN', authentication='pre-auth')
    def edge(a, b):
        return dict(producer_finding_id=a, consumer_finding_id=b, capability_kind='file-write',
            link_key='/etc/init.d/start', produced_capability='Writes bytes into the startup script',
            required_precondition='Startup helper executes the controlled script',
            producer_evidence_refs=[f'finding:{a}#data_flow'], consumer_evidence_refs=[f'finding:{b}#root_cause'],
            supplemental_evidence_refs=['surface:http-c#reach_evidence', 'unknown:different-surface#evidence'],
            required_state=dict.fromkeys(initial, 'any'), result_state=dict.fromkeys(initial, 'unchanged'),
            transition_kind='direct', confidence=9, existing_unknowns=[], blocker_keys=[])
    chains = [dict(chain_key='a', title='Startup control', summary='Write then consume', member_ids=ids[:3],
        initial_attacker_position='LAN attacker', initial_evidence_refs=[f'finding:{ids[0]}#attacker_position'],
        initial_state=initial, edges=[edge(ids[0], ids[1]), edge(ids[1], ids[2])])]
    dispositions = [dict(finding_id=f, disposition='chained' if n < 3 else 'standalone', explanation='Reviewed path',
        chain_keys=['a'] if n < 3 else [], existing_unknown_ids=[], blocker_keys=[], pivot_followup_ids=[])
        for n, f in enumerate(ids)]
    value = dict(schema_version=1, image_id='target', candidate_snapshot_sha256=summary.candidate_snapshot_sha256,
        worklist_sha256=summary.worklist_sha256, chains=chains, dispositions=dispositions, blockers=[])
    return con, run, root, value, worklist


def validate(case, value=None, con=None):
    connection, run, _, original, _ = case
    path = run / 'chain-result.json'
    path.write_text(json.dumps(original if value is None else value))
    parsed = results.load(path)
    validator = getattr(results, 'validate', None)
    assert callable(validator), 'Task 5 read-only validator is missing'
    return validator(connection if con is None else con, run, parsed)


def test_reuse_derived_records_and_readonly_transaction_no_live_root(graph_case):
    con, run, root, value, worklist = graph_case
    other = copy.deepcopy(value['chains'][0])
    other.update(chain_key='b', member_ids=other['member_ids'][:2], edges=other['edges'][:1])
    value['chains'].append(other)
    for d in value['dispositions'][:2]:
        d['chain_keys'].append('b')
    root.rename(root.with_name('unavailable-root'))
    before, writes, artifacts = state(con), con.total_changes, files(run)
    checked = validate(graph_case)
    assert checked.chain_ids == tuple(sorted(checked.chain_ids))
    assert len(checked.chains) == 2 and len(checked.edges) == 3
    chain = checked.chains[0]
    assert (chain.pre_auth, chain.completeness, chain.evidence_rung) == ('yes', 'complete', 'static-chained')
    assert chain.confidence == min(f['confidence'] for f in worklist['findings'][:3])
    assert json.loads(chain.member_ids) == value['chains'][0]['member_ids']
    for collection, table in ((checked.dispositions, 'cba_firmware_chain_dispositions'),
                              (checked.chains, 'cba_firmware_chains'), (checked.edges, 'cba_firmware_chain_edges')):
        for record in collection:
            row = dataclasses.asdict(record) | dict(artifact_path=str(run / 'artifacts/result.json'), artifact_sha256='a' * 64)
            db.TABLE_SPECS[table].validate(row)
    for collection in (checked.dispositions, checked.chains, checked.edges):
        for record in collection:
            with pytest.raises(dataclasses.FrozenInstanceError):
                record.image_id = 'foreign'
    with sqlite3.connect(f'file:{run / "audit.db"}?mode=ro', uri=True) as readonly:
        readonly.row_factory = sqlite3.Row
        assert validate(graph_case, con=readonly) == checked
        assert readonly.total_changes == 0 and not readonly.in_transaction
    con.execute("UPDATE cba_firmware_chain_runs SET prepared_at='caller-owned'")
    transaction_state = state(con)
    assert validate(graph_case) == checked and con.in_transaction and state(con) == transaction_state
    con.rollback()
    assert state(con) == before and con.total_changes == writes + 1 and files(run) == artifacts


@pytest.mark.parametrize('damage', ['omitted', 'extra', 'duplicate', 'membership', 'nonchained', 'pivot-member',
    'swapped', 'foreign-evidence', 'unresolved-evidence', 'initial-foreign', 'pivot-followup',
    'missing-edge', 'endpoint', 'duplicate-path', 'direct-lifecycle', 'direct-posture', 'carry',
    'other-generic', 'other-unqualified', 'generic-claim', 'transition-no-proof', 'unknown-axis',
    'unknown-resolved', 'unknown-foreign', 'blocker-foreign', 'blocker-dangling', 'snapshot', 'image', 'worklist'])
def test_invalid_graph_semantics(graph_case, damage):
    _, _, _, value, _ = graph_case
    c = value['chains'][0]
    e = c['edges'][0]
    if damage == 'omitted': value['dispositions'].pop()
    elif damage == 'extra': value['dispositions'].append(value['dispositions'][-1] | {'finding_id': 'foreign'})
    elif damage == 'duplicate': value['dispositions'].append(value['dispositions'][0])
    elif damage == 'membership': value['dispositions'][-1].update(disposition='chained', chain_keys=['a'])
    elif damage == 'nonchained': value['dispositions'][0].update(disposition='standalone', chain_keys=[])
    elif damage == 'pivot-member': c['member_ids'][0] = e['producer_finding_id'] = 'pivot-000'
    elif damage == 'swapped': e['producer_evidence_refs'] = e['consumer_evidence_refs']
    elif damage == 'foreign-evidence': e['consumer_evidence_refs'] = ['finding:foreign#data_flow']
    elif damage == 'unresolved-evidence': e['supplemental_evidence_refs'] = ['unknown:overlap#evidence']
    elif damage == 'initial-foreign': c['initial_evidence_refs'] = [f"finding:{c['member_ids'][1]}#attacker_position"]
    elif damage == 'pivot-followup': value['dispositions'][-1].update(disposition='unchainable', pivot_followup_ids=['foreign'])
    elif damage == 'missing-edge': c['edges'].pop()
    elif damage == 'endpoint': e['consumer_finding_id'] = c['member_ids'][2]
    elif damage == 'duplicate-path': value['chains'].append(copy.deepcopy(c) | {'chain_key': 'duplicate'})
    elif damage == 'direct-lifecycle': e['result_state']['lifecycle'] = 'post-reset'
    elif damage == 'direct-posture': e['result_state']['posture'] = 'BLE'
    elif damage == 'carry': c['edges'][1]['required_state']['authentication'] = 'admin'
    elif damage == 'other-generic': e.update(capability_kind='other-specific', link_key='generic:access')
    elif damage == 'other-unqualified': e.update(capability_kind='other-specific', link_key='resource')
    elif damage == 'generic-claim': e['produced_capability'] = 'provides access'
    elif damage == 'transition-no-proof': e['transition_kind'] = 'reboot'
    elif damage.startswith('unknown-'):
        e['existing_unknowns'] = [dict(unknown_id={'unknown-axis':'overlap', 'unknown-resolved':'different-surface',
            'unknown-foreign':'foreign-unknown'}[damage], axes=['reachability'])]
    elif damage.startswith('blocker-'):
        value['blockers'] = [blocker(value)]
        if damage == 'blocker-foreign': value['blockers'][0]['affected_finding_ids'] = ['pivot-000']
        else: value['blockers'][0]['affected_edges'] = [dict(chain_key='a', ordinal=99)]
    elif damage == 'snapshot': value['candidate_snapshot_sha256'] = '0' * 64
    elif damage == 'image': value['image_id'] = 'foreign'
    elif damage == 'worklist': value['worklist_sha256'] = '0' * 64
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


def blocker(value):
    return dict(blocker_key='boot', question='Does the script persist?', settling_observation='Observe persistent startup bytes',
        method='hardware', axes=['lifecycle'], affected_finding_ids=[value['chains'][0]['member_ids'][0]],
        affected_edges=[dict(chain_key='a', ordinal=0)])


def test_blockers_derive_completeness_and_nonmaterialized_disposition(graph_case):
    value = graph_case[3]
    value['blockers'] = [blocker(value)]
    value['chains'][0]['edges'][0]['blocker_keys'] = ['boot']
    value['chains'][0]['edges'][1]['existing_unknowns'] = [dict(unknown_id='overlap', axes=['authentication'])]
    value['dispositions'][-1].update(disposition='blocked', existing_unknown_ids=['component-only'], pivot_followup_ids=['pivot-000'])
    graph = validate(graph_case)
    chain, = graph.chains
    assert (chain.pre_auth, chain.completeness) == ('unknown', 'blocked')
    assert json.loads(chain.existing_unknown_ids) == ['overlap']
    assert graph.blockers[0].status == 'open'
    assert json.loads(graph.blockers[0].affected_edges) == [dict(chain_id=chain.chain_id, ordinal=0)]
    assert json.loads(chain.blocker_ids) == [graph.blockers[0].blocker_id]


@pytest.mark.parametrize('authentication,expected', [('pre-auth','yes'), ('session','no'), ('admin','no'), ('local-shell','no'), ('physical-UART','no')])
def test_state_carry_earned_auth_and_initial_stronger_auth(graph_case, authentication, expected):
    c = graph_case[3]['chains'][0]
    c['initial_state']['authentication'] = authentication
    c['edges'][0]['required_state'] = c['initial_state'].copy()
    c['edges'][0]['result_state']['authentication'] = 'admin'
    c['edges'][1]['required_state']['authentication'] = 'admin'
    assert validate(graph_case).chains[0].pre_auth == expected
    c['edges'][0]['existing_unknowns'] = [dict(unknown_id='overlap', axes=['authentication'])]
    assert validate(graph_case).chains[0].pre_auth == ('unknown' if authentication == 'pre-auth' else 'no')


@pytest.mark.parametrize('damage', ['finding', 'surface', 'unknown', 'pivot', 'artifact', 'prepared-artifact', 'pending', 'run-identity', 'new-relevant-unknown'])
def test_current_generation_drift_rejected_without_writes(graph_case, damage):
    con, run, _, value, worklist = graph_case
    if damage in ('finding', 'surface', 'unknown', 'pivot'):
        table, field = {'finding':('cba_firmware_findings','data_flow'), 'surface':('cba_firmware_surfaces','reach_evidence'),
            'unknown':('cba_unknowns','question'), 'pivot':('cba_firmware_pivots','evidence')}[damage]
        con.execute(f"UPDATE {table} SET {field}='changed' WHERE image_id='target'")
    elif damage == 'artifact': (run / worklist['findings_artifact_path']).write_bytes(b'{}')
    elif damage == 'prepared-artifact':
        path = con.execute('SELECT worklist_path FROM cba_firmware_chain_runs').fetchone()[0]
        pathlib.Path(path).write_bytes(b'{}')
    elif damage == 'pending': con.execute("UPDATE cba_firmware_fp_runs SET status='pending'")
    elif damage == 'run-identity': con.execute("UPDATE cba_firmware_fp_runs SET worklist_sha256=?", ('0'*64,))
    else:
        row = dict(con.execute("SELECT * FROM cba_unknowns WHERE id='overlap'").fetchone())
        db.put(con, 'cba_unknowns', row | {'id':'new-relevant'}, commit=False)
    before, writes, active = state(con), con.total_changes, con.in_transaction
    with pytest.raises(results.FirmwareChainError): validate(graph_case)
    assert state(con) == before and con.total_changes == writes and con.in_transaction == active


@pytest.mark.parametrize('kind', ['reboot', 'service-restart', 'factory-reset', 'reprovision'])
def test_non_direct_transition_requires_both_retained_sides(prepared, tmp_path, monkeypatch, kind):
    from tests.test_firmware_chain_prepare import TP
    monkeypatch.setitem(TP, 'data_flow', f'Writes the startup resource across {kind}')
    monkeypatch.setitem(TP, 'root_cause', f'Consumes the startup resource after {kind}')
    case = graph_case.__wrapped__(prepared, tmp_path)
    edge = case[3]['chains'][0]['edges'][0]
    edge.update(transition_kind=kind)
    edge['result_state'].update(lifecycle='post-reset', posture='SoftAP-setup')
    assert validate(case).chains[0].pre_auth == 'yes'
    edge['consumer_evidence_refs'] = [f"finding:{edge['consumer_finding_id']}#attacker_position"]
    with pytest.raises(results.FirmwareChainError): validate(case)


@pytest.mark.parametrize('field,axis', [('auth','authentication'), ('lifecycle','lifecycle'), ('posture','posture'),
    ('reachability','reachability'), ('dispatch','reachability'), ('handler','reachability'),
    ('future-field','reachability')])
def test_frozen_unknown_axis_mapping(prepared, tmp_path, monkeypatch, field, axis):
    # Use a real receipted surface unknown; freeze its field before hunt/review.
    from tests import test_firmware_chain_prepare as helpers
    if field not in db.UNKNOWN_FIELDS:
        monkeypatch.setattr(db, 'UNKNOWN_FIELDS', db.UNKNOWN_FIELDS + (field,))
    original = helpers.surface_results.record
    def record(con, run, path, **kwargs):
        value = json.loads(pathlib.Path(path).read_bytes())
        if pathlib.Path(path).name == 'richer-surface.json':
            value['decisions'][2]['unknowns'][0]['field'] = field
            pathlib.Path(path).write_text(json.dumps(value))
        return original(con, run, path, **kwargs)
    monkeypatch.setattr(helpers.surface_results, 'record', record)
    case = graph_case.__wrapped__(prepared, tmp_path)
    case[3]['chains'][0]['edges'][0]['existing_unknowns'] = [dict(unknown_id='overlap', axes=[axis])]
    assert validate(case).chains[0].pre_auth == 'unknown'


@pytest.mark.parametrize('confidence', [0, 4, 10])
def test_chain_confidence_includes_each_edge_and_member(graph_case, confidence):
    value, frozen = graph_case[3:]
    value['chains'][0]['edges'][1]['confidence'] = confidence
    expected = min(confidence, 9, *(f['confidence'] for f in frozen['findings'][:3]))
    assert validate(graph_case).chains[0].confidence == expected


def test_finding_blocker_cannot_be_hidden_by_omitting_edge_reference(graph_case):
    value = graph_case[3]
    value['blockers'] = [blocker(value) | {'affected_edges': []}]
    graph = validate(graph_case)
    assert (graph.chains[0].pre_auth, graph.chains[0].completeness) == ('unknown', 'blocked')
    assert json.loads(graph.chains[0].blocker_ids) == [graph.blockers[0].blocker_id]
    row = dataclasses.asdict(graph.blockers[0]) | dict(artifact_path=str(graph_case[1] / 'result.json'), artifact_sha256='a' * 64)
    db.TABLE_SPECS['cba_firmware_chain_unknowns'].validate(row)


def test_nonmaterialized_all_standalone_and_specific_namespace_key(graph_case):
    value = graph_case[3]
    value['chains'][0]['edges'][0].update(capability_kind='other-specific', link_key='boot-loader:startup-script')
    assert validate(graph_case).chains[0].completeness == 'complete'
    value['chains'] = []
    for disposition in value['dispositions']:
        disposition.update(disposition='standalone', chain_keys=[])
    checked = validate(graph_case)
    assert checked.chains == checked.edges == () and len(checked.dispositions) == 4


@pytest.mark.parametrize('key', [
    'boot-loader: access', 'boot-loader:   access', 'boot-loader:   AcCeSs',
    'boot-loader:\u00a0access', 'boot-loader:\taccess',
    'boot-loader :access', 'boot-loader : access', 'access :startup-script',
])
def test_other_specific_generic_tokens_reject_component_padding(graph_case, key):
    graph_case[3]['chains'][0]['edges'][0].update(capability_kind='other-specific', link_key=key)
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


def test_complete_upstream_run_requires_a_real_completion_timestamp(graph_case):
    graph_case[0].execute("UPDATE cba_firmware_fp_runs SET completed_at=' '")
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


def test_same_members_and_initial_state_allow_distinct_evidenced_semantic_paths(graph_case):
    value = graph_case[3]
    alternative = copy.deepcopy(value['chains'][0])
    alternative['chain_key'] = 'b'
    alternative['edges'][0]['link_key'] = '/etc/init.d/alternative-startup'
    alternative['edges'][0]['produced_capability'] = 'Writes the alternative startup resource'
    alternative['edges'][0]['required_precondition'] = 'Startup helper consumes the alternative resource'
    value['chains'].append(alternative)
    for disposition in value['dispositions'][:3]:
        disposition['chain_keys'].append('b')
    checked = validate(graph_case)
    assert len(checked.chains) == 2 and checked.chains[0].chain_id != checked.chains[1].chain_id


def test_prepared_worklist_schema_version_rejects_boolean_even_with_matching_hash(graph_case):
    import hashlib
    con, run, _, value, frozen = graph_case
    frozen['schema_version'] = True
    content = (json.dumps(frozen, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    digest = hashlib.sha256(content).hexdigest()
    path = run / 'files/firmware-chain' / digest / 'worklist.json'
    path.parent.mkdir()
    path.write_bytes(content)
    con.execute('UPDATE cba_firmware_chain_runs SET worklist_path=?,worklist_sha256=?', (str(path), digest))
    value['worklist_sha256'] = digest
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


@pytest.mark.parametrize('field', ['sink_worklist_sha256', 'dark_worklist_sha256', 'candidate_count', 'worklist_path'])
def test_current_review_index_owns_all_run_identities_and_counts(graph_case, field):
    con, run, *_ = graph_case
    row = dict(con.execute('SELECT * FROM cba_firmware_fp_runs').fetchone())
    if field == 'worklist_path':
        alternate = run / 'index-copy.json'
        alternate.write_bytes(pathlib.Path(row[field]).read_bytes())
        changed = str(alternate)
    else:
        changed = row[field] + 1 if field == 'candidate_count' else '0' * 64
    con.execute(f'UPDATE cba_firmware_fp_runs SET {field}=?', (changed,))
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


def test_current_review_index_bytes_must_match_its_retained_hash(graph_case):
    con = graph_case[0]
    path = pathlib.Path(con.execute('SELECT worklist_path FROM cba_firmware_fp_runs').fetchone()[0])
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


@pytest.mark.parametrize('field', ['batch_path', 'batch_sha256', 'assigned_count', 'verdict_count',
    'true_positive_count', 'false_positive_count', 'duplicate_count', 'pivot_count'])
def test_current_review_receipt_identity_and_counts_must_match_retained_review(graph_case, field):
    con = graph_case[0]
    row = dict(con.execute('SELECT * FROM cba_firmware_fp_receipts ORDER BY batch_path LIMIT 1').fetchone())
    changed = ('other-batch.json' if field == 'batch_path' else '0' * 64 if field == 'batch_sha256'
               else row[field] + 1)
    con.execute(f'UPDATE cba_firmware_fp_receipts SET {field}=? WHERE batch_path=?', (changed, row['batch_path']))
    # Keep the findings artifact intact: its result manifest does not bind these
    # receipt fields except batch_path, which is already rejected by Task 5.
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)


def test_review_receipt_cannot_relabel_counts_even_when_totals_are_consistent(graph_case):
    con = graph_case[0]
    # Shift one TP into DUPLICATE while
    # retaining assigned/verdict totals and the FP/pivot relationship.
    con.execute('UPDATE cba_firmware_fp_receipts SET true_positive_count=true_positive_count-1,'
                'duplicate_count=duplicate_count+1 WHERE true_positive_count>0')
    with pytest.raises(results.FirmwareChainError):
        validate(graph_case)
