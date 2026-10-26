"""Hostile worker JSON and identity oracles independent of production serializers."""
import copy
import dataclasses
import hashlib
import json

import pytest

from audit_core import firmware_chain_results as results
from audit_core.firmware_chain import FirmwareChainError


# Hand-ordered canonical wire fixture, including every result record. Changes to
# production serialization cannot silently rewrite this expected byte sequence.
STATE = '{"authentication":"pre-auth","lifecycle":"factory-fresh","posture":"SoftAP-setup"}'
REQUIRED = '{"authentication":"any","lifecycle":"any","posture":"any"}'
AFTER = '{"authentication":"admin","lifecycle":"provisioned","posture":"STA-LAN"}'
EDGE = ('{"blocker_keys":["boot"],"capability_kind":"file-write","confidence":7,'
 '"consumer_evidence_refs":["finding:F2#data_flow"],"consumer_finding_id":"F2",'
 '"existing_unknowns":[{"axes":["reachability"],"unknown_id":"U1"}],'
 '"link_key":"boot:/etc/init.d/启动","produced_capability":"Writes attacker bytes into boot script",'
 '"producer_evidence_refs":["finding:F1#data_flow"],"producer_finding_id":"F1",'
 '"required_precondition":"Boot helper executes that script as root","required_state":' + REQUIRED + ','
 '"result_state":' + AFTER + ',"supplemental_evidence_refs":["surface:S1#reach_evidence",'
 '"unknown:U2#evidence"],"transition_kind":"reboot"}')
CHAIN = ('{"chain_key":"route-a","edges":[' + EDGE + '],"initial_attacker_position":"Unauthenticated setup LAN",'
 '"initial_evidence_refs":["finding:F1#attacker_position","surface:S1#reach_evidence"],'
 '"initial_state":' + STATE + ',"member_ids":["F1","F2"],"summary":"Reboot composes writes and execution",'
 '"title":"启动 chain"}')
ORACLE = ('{"blockers":[{"affected_edges":[{"chain_key":"route-a","ordinal":0}],'
 '"affected_finding_ids":["F1","F2","F4"],"axes":["lifecycle","reachability"],'
 '"blocker_key":"boot","method":"hardware","question":"Is boot resource writable?",'
 '"settling_observation":"Observe script persistence over cold boot"}],'
 '"candidate_snapshot_sha256":"' + 'a' * 64 + '","chains":[' + CHAIN + ',' +
 CHAIN.replace('route-a', 'route-b').replace('finding:F2#', 'finding:F3#').replace('"F2"', '"F3"') + '],'
 '"dispositions":[{"blocker_keys":[],"chain_keys":["route-a","route-b"],"disposition":"chained",'
 '"existing_unknown_ids":[],"explanation":"Shared writer","finding_id":"F1","pivot_followup_ids":[]},'
 '{"blocker_keys":[],"chain_keys":["route-a"],"disposition":"chained","existing_unknown_ids":[],"explanation":"Boot consumer",'
 '"finding_id":"F2","pivot_followup_ids":[]},'
 '{"blocker_keys":[],"chain_keys":["route-b"],"disposition":"chained","existing_unknown_ids":[],"explanation":"Alternative consumer",'
 '"finding_id":"F3","pivot_followup_ids":[]},'
 '{"blocker_keys":["boot"],"chain_keys":[],"disposition":"blocked","existing_unknown_ids":["U1"],'
 '"explanation":"Needs boot observation","finding_id":"F4","pivot_followup_ids":["P1"]}],'
 '"image_id":"target:%_图像","schema_version":1,"worklist_sha256":"' + 'b' * 64 + '"}\n').encode()


def payload():
    return json.loads(ORACLE)


def load(tmp_path, value=None, raw=None):
    path = tmp_path / 'result.json'
    path.write_bytes(raw if raw is not None else json.dumps(payload() if value is None else value, ensure_ascii=False).encode())
    return results.load(path)


def ids(graph):
    blockers = {b.blocker_key: results.canonical_blocker_id(graph.image_id, graph.candidate_snapshot_sha256, b)
                for b in graph.blockers}
    chains = tuple(results.canonical_chain_id(graph.image_id, graph.candidate_snapshot_sha256, c, blockers)
                   for c in graph.chains)
    return tuple(blockers.values()), chains


def test_literal_records_unicode_reuse_blocked_and_reboot_roundtrip(tmp_path):
    graph = load(tmp_path)
    assert results.canonical_bytes(graph) == ORACLE
    assert graph.image_id == 'target:%_图像'
    assert graph.chains[0].member_ids == ('F1', 'F2')
    assert graph.chains[1].member_ids == ('F1', 'F3')
    assert graph.chains[0].edges[0].transition_kind == 'reboot'
    assert graph.dispositions[-1].disposition == 'blocked'
    assert graph.blockers[0].affected_edges == (results.AffectedEdgeRef('route-a', 0),)
    assert graph.chains[0].edges[0].existing_unknowns == (results.ExistingUnknownRef('U1', ('reachability',)),)
    assert graph.chains[0].initial_state == results.State('factory-fresh', 'SoftAP-setup', 'pre-auth')
    records = (graph, *graph.blockers, *graph.dispositions, *graph.chains,
               *graph.blockers[0].affected_edges, *graph.chains[0].edges,
               *graph.chains[0].edges[0].existing_unknowns, graph.chains[0].initial_state,
               graph.chains[0].edges[0].required_state, graph.chains[0].edges[0].result_state)
    assert {type(r) for r in records} == {results.GraphResult, results.NewBlocker, results.FindingDisposition,
        results.ChainResult, results.ChainEdge, results.State, results.ExistingUnknownRef, results.AffectedEdgeRef}
    for record in records:
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, 'forged')
    assert load(tmp_path, raw=results.canonical_bytes(graph)) == graph


def test_identity_projection_literal_bytes_and_full_digest(tmp_path):
    graph = load(tmp_path)
    blocker_wire = ('{"affected_finding_ids":["F1","F2","F4"],'
        '"axes":["lifecycle","reachability"],"candidate_snapshot_sha256":"' + 'a' * 64 + '",'
        '"image_id":"target:%_图像","method":"hardware","question":"Is boot resource writable?",'
        '"settling_observation":"Observe script persistence over cold boot"}\n').encode()
    blocker_id = 'firmware-chain-blocker-' + hashlib.sha256(blocker_wire).hexdigest()
    assert ids(graph)[0] == (blocker_id,)
    # The expected projection is composed from the independently hand-serialized
    # edge oracle, never from a production projection or serializer.
    edge_wire = EDGE.replace('"blocker_keys":["boot"]', '"blocker_ids":["' + blocker_id + '"]')
    edge_wire = edge_wire.replace('"produced_capability":', '"ordinal":0,"produced_capability":')
    chain_wire = ('{"candidate_snapshot_sha256":"' + 'a' * 64 + '","edges":[' + edge_wire + '],'
        '"image_id":"target:%_图像","initial_state":' + STATE + ',"member_ids":["F1","F2"]}\n').encode()
    assert ids(graph)[1][0] == 'firmware-chain-' + hashlib.sha256(chain_wire).hexdigest()
    assert len(ids(graph)[0][0]) == len('firmware-chain-blocker-') + 64
    assert len(ids(graph)[1][0]) == len('firmware-chain-') + 64


@pytest.mark.parametrize('raw', [b'\xff', b'{', b'[]', b'null', b'true', b'1', b'"s"',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'[' * 1500 + b']' * 1500,
    b' ' * (8 * 1024 * 1024 + 1)])
def test_hostile_raw_bytes(tmp_path, raw):
    with pytest.raises(FirmwareChainError):
        load(tmp_path, raw=raw)


@pytest.mark.parametrize('needle', ['"schema_version":1', '"confidence":7', '"ordinal":0', '"unknown_id":"U1"'])
def test_duplicate_keys_at_all_levels(tmp_path, needle):
    raw = ORACLE.replace(needle.encode(), (needle + ',' + needle).encode(), 1)
    with pytest.raises(FirmwareChainError):
        load(tmp_path, raw=raw)


@pytest.mark.parametrize('path', [(), ('blockers', 0), ('dispositions', 0), ('chains', 0),
    ('chains', 0, 'initial_state'), ('chains', 0, 'edges', 0),
    ('chains', 0, 'edges', 0, 'existing_unknowns', 0), ('blockers', 0, 'affected_edges', 0)])
@pytest.mark.parametrize('damage', ['missing', 'unknown', 'type'])
def test_exact_object_keys_and_types(tmp_path, path, damage):
    value = payload()
    target = value
    for part in path:
        target = target[part]
    if damage == 'missing':
        del target[next(iter(target))]
    elif damage == 'unknown':
        target['artifact_path'] = '../outside'
    elif path:
        parent = value
        for part in path[:-1]:
            parent = parent[part]
        parent[path[-1]] = []
    else:
        value = []
    with pytest.raises(FirmwareChainError):
        load(tmp_path, value)


@pytest.mark.parametrize('path,bad', [
    (('schema_version',), True), (('schema_version',), 2), (('image_id',), ''),
    (('image_id',), '\ud800'), (('candidate_snapshot_sha256',), 'A' * 64), (('worklist_sha256',), 'a' * 63),
    (('blockers', 0, 'method'), 'dynamic'), (('blockers', 0, 'question'), ' '),
    (('blockers', 0, 'settling_observation'), ''), (('blockers', 0, 'axes'), []),
    (('blockers', 0, 'axes'), ['foreign']), (('blockers', 0, 'blocker_key'), '../escape'),
    (('blockers', 0, 'affected_finding_ids'), ['bad/path']),
    (('blockers', 0, 'affected_edges', 0, 'ordinal'), True),
    (('blockers', 0, 'affected_edges', 0, 'ordinal'), -1),
    (('dispositions', 0, 'disposition'), 'complete'),
    (('dispositions', 0, 'finding_id'), 'F/1'),
    (('chains', 0, 'member_ids'), ['F1', 'F1']), (('chains', 0, 'member_ids'), ['F1']),
    (('chains', 0, 'chain_key'), '/absolute'), (('chains', 0, 'initial_evidence_refs'), []),
    (('chains', 0, 'initial_state', 'posture'), 'STA-lan'),
    (('chains', 0, 'initial_state', 'authentication'), 'any'),
    (('chains', 0, 'initial_state', 'lifecycle'), 'unchanged'),
    (('chains', 0, 'edges', 0, 'required_state', 'lifecycle'), 'unchanged'),
    (('chains', 0, 'edges', 0, 'result_state', 'lifecycle'), 'any'),
    (('chains', 0, 'edges', 0, 'confidence'), True), (('chains', 0, 'edges', 0, 'confidence'), 1.5),
    (('chains', 0, 'edges', 0, 'confidence'), -1), (('chains', 0, 'edges', 0, 'confidence'), 11),
    (('chains', 0, 'edges', 0, 'capability_kind'), 'access'),
    (('chains', 0, 'edges', 0, 'transition_kind'), 'magic'),
    (('chains', 0, 'edges', 0, 'link_key'), ''),
    (('chains', 0, 'edges', 0, 'link_key'), ' /etc/init.d/start '),
    (('chains', 0, 'edges', 0, 'link_key'), 'boot:\x00resource'),
    (('chains', 0, 'edges', 0, 'link_key'), 'boot:\nresource'),
    (('chains', 0, 'edges', 0, 'link_key'), 'boot:\x7fresource'),
    (('chains', 0, 'edges', 0, 'link_key'), 'boot:\x85resource'),
    (('chains', 0, 'edges', 0, 'link_key'), '界' * 1366),
    (('chains', 0, 'edges', 0, 'producer_evidence_refs'), []),
    (('chains', 0, 'edges', 0, 'consumer_evidence_refs'), ['pivot:P1#evidence']),
    (('chains', 0, 'edges', 0, 'consumer_evidence_refs'), ['finding:../F2#data_flow']),
    (('chains', 0, 'edges', 0, 'supplemental_evidence_refs'), ['surface:S1#unknown']),
    (('chains', 0, 'edges', 0, 'existing_unknowns', 0, 'axes'), []),
])
def test_invalid_scalars_and_variants(tmp_path, path, bad):
    value = payload()
    target = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = bad
    # ensure_ascii serializes the intentionally invalid lone surrogate for load.
    with pytest.raises(FirmwareChainError):
        load(tmp_path, raw=json.dumps(value).encode())


@pytest.mark.parametrize('path', [('blockers',), ('chains',), ('dispositions',),
    ('blockers', 0, 'axes'), ('blockers', 0, 'affected_finding_ids'), ('blockers', 0, 'affected_edges'),
    ('chains', 0, 'initial_evidence_refs'), ('chains', 0, 'edges', 0, 'producer_evidence_refs'),
    ('chains', 0, 'edges', 0, 'consumer_evidence_refs'), ('chains', 0, 'edges', 0, 'supplemental_evidence_refs'),
    ('chains', 0, 'edges', 0, 'existing_unknowns'), ('chains', 0, 'edges', 0, 'blocker_keys'),
    ('dispositions', 0, 'chain_keys'), ('dispositions', 3, 'existing_unknown_ids'),
    ('dispositions', 3, 'pivot_followup_ids')])
def test_duplicate_arrays_rejected(tmp_path, path):
    value = payload()
    target = value
    for part in path:
        target = target[part]
    target.append(copy.deepcopy(target[0]))
    with pytest.raises(FirmwareChainError):
        load(tmp_path, value)


def test_semantic_free_reordering_normalizes_and_ids_ignore_local_keys_and_display(tmp_path):
    first = load(tmp_path)
    value = payload()
    for key in ('blockers', 'dispositions', 'chains'):
        value[key].reverse()
    for b in value['blockers']:
        b['axes'].reverse()
        b['affected_finding_ids'].reverse()
    for c in value['chains']:
        c['initial_evidence_refs'].reverse()
        c['edges'][0]['supplemental_evidence_refs'].reverse()
    assert load(tmp_path, value) == first
    for b in value['blockers']:
        b['blocker_key'] = 'renamed'
        b['affected_edges'][0]['chain_key'] = 'new-a'
    for c in value['chains']:
        c['chain_key'] = c['chain_key'].replace('route-', 'new-')
        c['title'] = 'Other title'
        c['summary'] = 'Other summary'
        c['initial_attacker_position'] = 'Display-only account'
        c['edges'][0]['blocker_keys'] = ['renamed']
    for d in value['dispositions']:
        d['chain_keys'] = [s.replace('route-', 'new-') for s in d['chain_keys']]
        d['blocker_keys'] = ['renamed'] if d['blocker_keys'] else []
    assert ids(load(tmp_path, value)) == ids(first)


@pytest.mark.parametrize('link_key', ['/etc/init.d/启动', 'C:\\firmware\\boot', 'namespace:resource with spaces', 'x' * 4096])
def test_semantic_link_keys_are_not_host_paths(tmp_path, link_key):
    value = payload()
    value['chains'][0]['edges'][0]['link_key'] = link_key
    assert load(tmp_path, value).chains[0].edges[0].link_key == link_key


@pytest.mark.parametrize('field,new', [('image_id', 'another:图像'), ('candidate_snapshot_sha256', 'c' * 64)])
def test_generation_identity_changes_both_ids(tmp_path, field, new):
    before = ids(load(tmp_path))
    value = payload()
    value[field] = new
    after = ids(load(tmp_path, value))
    assert before[0] != after[0] and all(a != b for a, b in zip(before[1], after[1]))


def test_chain_initial_state_is_semantic_but_artifact_generation_is_not(tmp_path):
    before = ids(load(tmp_path))
    value = payload()
    value['worklist_sha256'] = 'c' * 64
    value['blockers'][0]['affected_edges'] = [{'chain_key': 'route-b', 'ordinal': 0}]
    assert ids(load(tmp_path, value)) == before
    value['chains'][0]['initial_state']['authentication'] = 'session'
    after = ids(load(tmp_path, value))
    assert before[0] == after[0] and before[1][0] != after[1][0] and before[1][1] == after[1][1]


@pytest.mark.parametrize('axis,new', [('authentication', 'session'), ('lifecycle', 'provisioned'), ('posture', 'BLE')])
def test_every_initial_state_axis_enters_chain_identity(tmp_path, axis, new):
    before = ids(load(tmp_path))
    value = payload()
    value['chains'][0]['initial_state'][axis] = new
    after = ids(load(tmp_path, value))
    assert before[0] == after[0] and before[1][0] != after[1][0] and before[1][1] == after[1][1]


def test_exact_requirements_and_unchanged_results_are_structurally_valid(tmp_path):
    value = payload()
    value['chains'][0]['edges'][0]['required_state'] = value['chains'][0]['initial_state'].copy()
    value['chains'][0]['edges'][0]['result_state'] = dict.fromkeys(('lifecycle', 'posture', 'authentication'), 'unchanged')
    graph = load(tmp_path, value)
    assert graph.chains[0].edges[0].required_state == graph.chains[0].initial_state
    assert graph.chains[0].edges[0].result_state == results.State('unchanged', 'unchanged', 'unchanged')


def test_empty_graph_and_nonmaterialized_disposition_variants(tmp_path):
    value = payload()
    value.update(blockers=[], chains=[], dispositions=[])
    graph = load(tmp_path, value)
    assert graph.blockers == graph.chains == graph.dispositions == ()
    value['dispositions'] = [dict(finding_id='F1', disposition='standalone', explanation='Independent primitive',
        chain_keys=[], existing_unknown_ids=[], blocker_keys=[], pivot_followup_ids=[]),
        dict(finding_id='F2', disposition='unchainable', explanation='No reviewed consumer',
        chain_keys=[], existing_unknown_ids=[], blocker_keys=[], pivot_followup_ids=['P1'])]
    assert tuple(d.disposition for d in load(tmp_path, value).dispositions) == ('standalone', 'unchainable')


def test_member_path_and_endpoint_order_enter_identity(tmp_path):
    before = ids(load(tmp_path))
    value = payload()
    chain = value['chains'][0]
    chain['member_ids'].reverse()
    edge = chain['edges'][0]
    edge['producer_finding_id'], edge['consumer_finding_id'] = edge['consumer_finding_id'], edge['producer_finding_id']
    edge['producer_evidence_refs'], edge['consumer_evidence_refs'] = edge['consumer_evidence_refs'], edge['producer_evidence_refs']
    after = ids(load(tmp_path, value))
    assert before[0] == after[0] and before[1][0] != after[1][0] and before[1][1] == after[1][1]


def test_identity_helpers_ignore_semantic_free_order_even_for_frozen_inputs(tmp_path):
    graph = load(tmp_path)
    blocker = dataclasses.replace(graph.blockers[0], axes=('reachability', 'lifecycle'),
                                   affected_finding_ids=('F4', 'F2', 'F1'))
    blocker_id = results.canonical_blocker_id(graph.image_id, graph.candidate_snapshot_sha256, blocker)
    assert blocker_id == ids(graph)[0][0]
    edge = dataclasses.replace(graph.chains[0].edges[0], supplemental_evidence_refs=(
        'unknown:U2#evidence', 'surface:S1#reach_evidence'))
    chain = dataclasses.replace(graph.chains[0], edges=(edge,))
    assert results.canonical_chain_id(graph.image_id, graph.candidate_snapshot_sha256, chain,
        {'boot': blocker_id}) == ids(graph)[1][0]


@pytest.mark.parametrize('field,new', [('question', 'Observe boot?'), ('settling_observation', 'UART boot log'),
    ('method', 'emulate'), ('axes', ['authentication']), ('affected_finding_ids', ['F1', 'F2'])])
def test_all_blocker_semantics_change_blocker_and_referencing_chain_ids(tmp_path, field, new):
    before = ids(load(tmp_path))
    value = payload()
    value['blockers'][0][field] = new
    after = ids(load(tmp_path, value))
    assert before[0] != after[0] and before[1][0] != after[1][0]


@pytest.mark.parametrize('field,new', [('capability_kind', 'config-write'), ('link_key', 'boot:other'),
    ('produced_capability', 'Writes a second boot resource'), ('required_precondition', 'Parses the boot resource'),
    ('producer_evidence_refs', ['finding:F1#root_cause']), ('consumer_evidence_refs', ['finding:F2#root_cause']),
    ('supplemental_evidence_refs', ['surface:S1#reach_evidence']), ('confidence', 6),
    ('transition_kind', 'reprovision'), ('existing_unknowns', [{'unknown_id': 'U3', 'axes': ['lifecycle']}]),
    ('existing_unknowns', [{'unknown_id': 'U1', 'axes': ['authentication']}]),
    ('blocker_keys', []),
    ('required_state', {'lifecycle': 'factory-fresh', 'posture': 'any', 'authentication': 'any'}),
    ('result_state', {'lifecycle': 'provisioned', 'posture': 'STA-LAN', 'authentication': 'session'})])
def test_all_edge_semantics_change_only_that_chain_identity(tmp_path, field, new):
    before = ids(load(tmp_path))
    value = payload()
    value['chains'][0]['edges'][0][field] = new
    after = ids(load(tmp_path, value))
    assert before[0] == after[0] and before[1][0] != after[1][0] and before[1][1] == after[1][1]


@pytest.mark.parametrize('damage', ['duplicate-blocker', 'duplicate-chain', 'dangling-blocker', 'dangling-chain',
    'bad-ordinal', 'cyclic-members', 'wrong-endpoints', 'missing-edge', 'extra-edge', 'empty-blocker',
    'chained-no-chain', 'blocked-no-blocker', 'standalone-chain', 'pivot-on-chained',
    'dangling-disposition-chain', 'dangling-disposition-blocker', 'duplicate-unknown-id'])
def test_local_reference_graph_and_variants_fail_closed(tmp_path, damage):
    value = payload()
    if damage == 'duplicate-blocker':
        value['blockers'].append(value['blockers'][0] | {'blocker_key': 'same-meaning'})
    elif damage == 'duplicate-chain':
        value['chains'].append(value['chains'][0] | {'chain_key': 'same-meaning'})
    elif damage == 'dangling-blocker':
        value['chains'][0]['edges'][0]['blocker_keys'] = ['missing']
    elif damage == 'dangling-chain':
        value['blockers'][0]['affected_edges'][0]['chain_key'] = 'missing'
    elif damage == 'bad-ordinal':
        value['blockers'][0]['affected_edges'][0]['ordinal'] = 1
    elif damage == 'cyclic-members':
        value['chains'][0]['member_ids'] = ['F1', 'F2', 'F1']
    elif damage == 'wrong-endpoints':
        value['chains'][0]['edges'][0]['producer_finding_id'] = 'F2'
    elif damage == 'missing-edge':
        value['chains'][0]['edges'] = []
    elif damage == 'extra-edge':
        value['chains'][0]['edges'] *= 2
    elif damage == 'empty-blocker':
        value['blockers'][0].update(affected_edges=[], affected_finding_ids=[])
    elif damage == 'chained-no-chain':
        value['dispositions'][0]['chain_keys'] = []
    elif damage == 'blocked-no-blocker':
        value['dispositions'][3].update(blocker_keys=[], existing_unknown_ids=[])
    elif damage == 'standalone-chain':
        value['dispositions'][0]['disposition'] = 'standalone'
    elif damage == 'dangling-disposition-chain':
        value['dispositions'][0]['chain_keys'] = ['missing']
    elif damage == 'dangling-disposition-blocker':
        value['dispositions'][3]['blocker_keys'] = ['missing']
    elif damage == 'duplicate-unknown-id':
        value['chains'][0]['edges'][0]['existing_unknowns'].append({'unknown_id': 'U1', 'axes': ['authentication']})
    else:
        value['dispositions'][0]['pivot_followup_ids'] = ['P1']
    with pytest.raises(FirmwareChainError):
        load(tmp_path, value)


@pytest.mark.parametrize('over', [False, True])
def test_raw_and_canonical_size_boundaries(tmp_path, over):
    value = payload()
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    value['chains'][0]['summary'] += 'x' * (results.MAX_RESULT_BYTES - len(raw) - 1 + int(over))
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    assert len(raw) == results.MAX_RESULT_BYTES - 1 + int(over)
    if over:
        with pytest.raises(FirmwareChainError, match='[Cc]anonical|size'):
            load(tmp_path, raw=raw)
    else:
        assert len(results.canonical_bytes(load(tmp_path, raw=raw))) == results.MAX_RESULT_BYTES


def test_non_regular_and_symlink_result_files_rejected(tmp_path):
    with pytest.raises(FirmwareChainError):
        results.load(tmp_path)
    target = tmp_path / 'target.json'
    target.write_bytes(ORACLE)
    link = tmp_path / 'link.json'
    link.symlink_to(target)
    with pytest.raises(FirmwareChainError):
        results.load(link)


def test_regular_file_loading_without_optional_posix_open_flags(tmp_path, monkeypatch):
    monkeypatch.delattr(results.os, 'O_NOFOLLOW', raising=False)
    monkeypatch.delattr(results.os, 'O_NONBLOCK', raising=False)
    assert load(tmp_path).image_id == 'target:%_图像'
    link = tmp_path / 'link.json'
    link.symlink_to(tmp_path / 'result.json')
    with pytest.raises(FirmwareChainError):
        results.load(link)


@pytest.mark.parametrize('field,value', [('pre_auth', 'yes'), ('confidence', 10), ('completeness', 'complete'),
    ('evidence_rung', 'dynamic'), ('chain_id', 'chosen')])
def test_workers_cannot_supply_derived_chain_claims(tmp_path, field, value):
    document = payload()
    document['chains'][0][field] = value
    with pytest.raises(FirmwareChainError):
        load(tmp_path, document)


@pytest.mark.parametrize('field,value', [('consumer_capability_kind', 'file-read'),
    ('producer_link_key', '/etc/other'), ('consumer_link_key', '/etc/other')])
def test_edge_contract_has_one_shared_capability_and_exact_link_key(tmp_path, field, value):
    document = payload()
    document['chains'][0]['edges'][0][field] = value
    with pytest.raises(FirmwareChainError):
        load(tmp_path, document)
