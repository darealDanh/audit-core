"""Pure dive authority boundaries: no identity by prose or acquisition by path."""
import copy
import dataclasses
import hashlib
import json
import pathlib

import pytest

from audit_core import firmware_dive_questions as q
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_snapshot import complete, snapshot


@pytest.fixture
def graph(graph_case):
    complete(graph_case)
    return snapshot(graph_case)


def conflict_text(ids):
    canonical=json.dumps(list(ids),sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
    return 'Resolve conflicting observations: '+hashlib.sha256(canonical).hexdigest()


def state_contract(subject, axis='authentication'):
    return dict(target_subject=subject, mode='value-discovery', predicate='state-value', axis=axis,
        expected_value=None, allowed_values=['admin', 'local-shell', 'physical-UART', 'pre-auth', 'session'],
        other_specific=False, capability_kind=None, link_key=None, transition_kind=None)


def entry(graph, subject=None):
    subject = subject or 'finding:' + graph.findings[0].finding_id
    return dict(subject_refs=[subject], method='static', question='Which authority is required?',
        settling_observation='Read the exact authentication gate', axes=['authentication'],
        resolution_contract=state_contract(subject))


def manifest(tmp_path, entries):
    path = tmp_path / 'questions.json'
    path.write_text(json.dumps(dict(schema_version=1, questions=entries)))
    return q.load_analyst_manifest(path)


def derived(graph, analyst=(), history=(), retries=()):
    return q.derive_questions(graph, analyst, history, retries)


def history(question, ordinal=1, observation='1' * 64, outcome='supported', value='admin', current=True,
            dependencies=('d' * 64,), evidence=('e' * 64,), supersedes=()):
    return q.QuestionHistory(question=question, attempt_ordinal=ordinal, observation_id=observation,
        outcome=outcome, resolution_value=value, dependency_refs=dependencies, evidence_refs=evidence,
        dependency_current=current, supersedes=supersedes)


def test_exact_automatic_questions_and_frozen_records(graph):
    result = derived(graph)
    assert sorted(x.origin for x in result.questions) == ['chain-blocker', 'surface-unknown', 'surface-unknown']
    blocker = next(x for x in result.questions if x.origin == 'chain-blocker')
    unknown = next(x for x in result.questions if x.origin == 'surface-unknown' and any(str(s) == 'surface-unknown:overlap' for s in x.subject_refs))
    assert blocker.question == graph.blockers[0].question
    assert blocker.settling_observation == graph.blockers[0].settling_observation
    assert blocker.method == 'hardware' and blocker.axes == ('lifecycle',)
    assert 'chain-blocker:' + graph.blockers[0].blocker_id in tuple(str(s) for s in blocker.subject_refs)
    assert 'surface-unknown:overlap' in tuple(str(s) for s in unknown.subject_refs)
    assert unknown.resolution_contract.mode == 'value-discovery'
    assert unknown.resolution_contract.axis == 'authentication'
    assert all(x.attempt_ordinal == 1 and len(x.question_id) == 64 for x in result.questions)
    for record in (result, blocker, blocker.subject_refs[0], blocker.resolution_contract):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, dataclasses.fields(record)[0].name, 'changed')
    assert derived(graph) == result


@pytest.mark.parametrize('damage', ['foreign-unknown', 'resolved-unknown', 'foreign-blocker', 'unlinked-blocker'])
def test_invalid_automatic_subjects_fail_closed(graph, damage):
    if damage == 'foreign-unknown':
        graph = dataclasses.replace(graph, unknowns=tuple(dataclasses.replace(u, image_id='foreign') if u.id == 'overlap' else u for u in graph.unknowns))
    elif damage == 'resolved-unknown':
        graph = dataclasses.replace(graph, unknowns=tuple(dataclasses.replace(u, status='resolved') if u.id == 'overlap' else u for u in graph.unknowns))
    elif damage == 'foreign-blocker':
        graph = dataclasses.replace(graph, blockers=(dataclasses.replace(graph.blockers[0], image_id='foreign'),))
    else:
        graph = dataclasses.replace(graph, blockers=(dataclasses.replace(graph.blockers[0], blocker_id='unlinked'),))
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph)


def test_unrelated_unknowns_are_not_automatic(graph):
    result = derived(graph)
    assert all('surface-unknown:different-surface' not in tuple(map(str, x.subject_refs)) for x in result.questions)


@pytest.mark.parametrize('kind', ['finding', 'surface-unknown', 'chain-blocker', 'edge', 'chain'])
def test_analyst_accepts_only_current_linked_subjects(graph, tmp_path, kind):
    subjects = dict(finding=graph.findings[0].finding_id, **{'surface-unknown':'overlap',
        'chain-blocker':graph.blockers[0].blocker_id, 'edge':q.edge_fingerprint(graph, graph.edges[0]),
        'chain':q.chain_fingerprint(graph, graph.chains[0])})
    analyst = manifest(tmp_path, [entry(graph, kind + ':' + subjects[kind])])
    result = derived(graph, analyst)
    assert len(result.questions) == 4 and len([x for x in result.questions if x.origin == 'analyst']) == 1


def test_boolean_contract_and_semantic_exactness(graph, tmp_path):
    subject = 'edge:' + q.edge_fingerprint(graph, graph.edges[0])
    value = entry(graph, subject)
    value['resolution_contract'] = dict(target_subject=subject, mode='boolean-claim', predicate='edge-validity',
        axis=None, expected_value=True, allowed_values=[], other_specific=False,
        capability_kind=graph.edges[0].capability_kind, link_key=graph.edges[0].link_key,
        transition_kind=None)
    assert len(derived(graph, manifest(tmp_path, [value])).questions) == 4
    value['resolution_contract']['link_key'] = '/unrelated'
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph, manifest(tmp_path, [value]))


@pytest.mark.parametrize('damage', ['duplicate', 'stale', 'unlinked', 'predicate', 'value', 'axis', 'method',
    'unsafe', 'surrogate', 'extra', 'noncanonical', 'duplicate-subject', 'target', 'mode', 'empty', 'type',
    'boolean-value', 'open-vocabulary'])
def test_manifest_rejects_hostile_or_ambiguous_entries(graph, tmp_path, damage):
    value = entry(graph)
    entries = [value]
    if damage == 'duplicate': entries.append(copy.deepcopy(value))
    elif damage == 'stale': value['subject_refs'] = ['edge:' + '0' * 64]
    elif damage == 'unlinked': value['subject_refs'] = ['surface-unknown:different-surface']
    elif damage == 'predicate': value['resolution_contract']['predicate'] = 'arbitrary'
    elif damage == 'value': value['resolution_contract']['allowed_values'] = ['root']
    elif damage == 'axis': value['axes'] = ['authority']
    elif damage == 'method': value['method'] = 'shell'
    elif damage == 'unsafe': value['question'] = 'hidden\x1b[31m'
    elif damage == 'surrogate': value['question'] = '\ud800'
    elif damage == 'extra': value['arbitrary'] = True
    elif damage == 'noncanonical': value['axes'] = ['lifecycle', 'authentication']
    elif damage == 'duplicate-subject': value['subject_refs'] *= 2
    elif damage == 'target': value['resolution_contract']['target_subject'] = 'finding:foreign'
    elif damage == 'mode': value['resolution_contract']['mode'] = 'freeform'
    elif damage == 'empty': value['subject_refs'] = []
    elif damage == 'type': value['axes'] = 'authentication'
    elif damage == 'boolean-value': value['resolution_contract'].update(mode='boolean-claim', expected_value=True, allowed_values=[])
    elif damage == 'open-vocabulary': value['resolution_contract'].update(allowed_values=[], other_specific=True)
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph, manifest(tmp_path, entries))


def test_manifest_io_boundaries(tmp_path):
    assert q.load_analyst_manifest(None) == ()
    path = tmp_path / 'bad.json'
    for raw in [b'{"schema_version":1,"schema_version":1,"questions":[]}', b'NaN', b'[]', b'\xff', b'{',
                b'{"schema_version":true,"questions":[]}', b'{"schema_version":1,"questions":{}}']:
        path.write_bytes(raw)
        with pytest.raises(q.FirmwareDiveQuestionError): q.load_analyst_manifest(path)
    path.write_bytes(b' ' * (8 * 1024 * 1024 + 1))
    with pytest.raises(q.FirmwareDiveQuestionError): q.load_analyst_manifest(path)
    with pytest.raises(q.FirmwareDiveQuestionError): q.load_analyst_manifest(tmp_path / 'missing')


@pytest.mark.parametrize('damage', ['oversized-integer', 'nested-entry', 'parser-depth'])
def test_manifest_parser_and_normalization_failures_are_contract_errors(tmp_path, damage):
    path = tmp_path / 'hostile.json'
    if damage == 'oversized-integer':
        raw = '{"schema_version":' + '9' * 5000 + ',"questions":[]}'
    else:
        depth = 600 if damage == 'nested-entry' else 1500
        raw = '{"schema_version":1,"questions":[{"question":' + '[' * depth + '0' + ']' * depth + '}]}'
    path.write_text(raw)
    assert path.stat().st_size < 8 * 1024 * 1024
    with pytest.raises(q.FirmwareDiveQuestionError, match='nesting' if damage == 'nested-entry' else None):
        q.load_analyst_manifest(path)


def test_conflicts_freeze_validated_history_and_retained_input_aliases(graph):
    question = next(x for x in derived(graph).questions if x.origin == 'surface-unknown'
        and any(str(s) == 'surface-unknown:overlap' for s in x.subject_refs))
    question = dataclasses.replace(question, origin='analyst', question='Which exact authority did the analyst observe?')
    question = dataclasses.replace(question, question_id=q.canonical_question_id(graph, question))
    subjects, axes = list(question.subject_refs), list(question.axes)
    allowed = list(question.resolution_contract.allowed_values)
    mutable = dataclasses.replace(question, subject_refs=subjects, axes=axes,
        resolution_contract=dataclasses.replace(question.resolution_contract, allowed_values=allowed))
    result = derived(graph, history=(history(mutable), history(mutable, 2, '2' * 64, value='session')))
    conflict, = [x for x in result.questions if x.origin == 'conflict']
    assert conflict.subject_refs == question.subject_refs
    assert conflict.axes == ('authentication',)
    assert conflict.resolution_contract.allowed_values == ('admin', 'local-shell', 'physical-UART', 'pre-auth', 'session')
    before = q.packet_bytes(conflict, graph, ())
    for values in (conflict.subject_refs, conflict.axes, conflict.resolution_contract.allowed_values):
        with pytest.raises(AttributeError):
            values.append('root')
    subjects.clear()
    axes.append('root')
    allowed.append('root')
    assert q.packet_bytes(conflict, graph, ()) == before
    with pytest.raises(dataclasses.FrozenInstanceError):
        conflict.resolution_contract.allowed_values += ('root',)


@pytest.mark.parametrize('field,value', [('produced_capability','new display'), ('required_precondition','new display'),
    ('confidence',1), ('blocker_ids',('other',)), ('artifact_sha256','0' * 64), ('artifact_path','artifacts/new.json')])
def test_edge_presentation_excluded_from_identity(graph, field, value):
    edge = graph.edges[0]
    assert q.edge_fingerprint(graph, dataclasses.replace(edge, **{field:value})) == q.edge_fingerprint(graph, edge)


@pytest.mark.parametrize('field,value', [('producer_finding_id','other'), ('consumer_finding_id','other'),
    ('capability_kind','command-execution'), ('link_key','/new'), ('producer_evidence_refs',('finding:other#data_flow',)),
    ('consumer_evidence_refs',('finding:other#root_cause',)), ('supplemental_evidence_refs',()),
    ('transition_kind','reboot'), ('required_state','required'), ('result_state','result')])
def test_every_edge_semantic_change_changes_identity(graph, field, value):
    edge = graph.edges[0]
    if field.endswith('_state'): value = dataclasses.replace(getattr(edge, field), authentication='admin')
    assert q.edge_fingerprint(graph, dataclasses.replace(edge, **{field:value})) != q.edge_fingerprint(graph, edge)


def test_chain_initial_members_candidate_and_local_identity(graph):
    chain = graph.chains[0]
    before = q.chain_fingerprint(graph, chain)
    renamed = dataclasses.replace(chain, chain_id='renamed', title='display', summary='display', blocker_ids=tuple(reversed(chain.blocker_ids)))
    renamed_graph = dataclasses.replace(graph, chains=(renamed,), edges=tuple(dataclasses.replace(e, chain_id='renamed') for e in graph.edges))
    assert q.chain_fingerprint(renamed_graph, renamed) == before
    assert q.edge_fingerprint(renamed_graph, renamed_graph.edges[0]) == q.edge_fingerprint(graph, graph.edges[0])
    for changes in [dict(member_ids=tuple(reversed(chain.member_ids))), dict(initial_lifecycle='post-reset'),
        dict(initial_posture='BLE'), dict(initial_authentication='admin'), dict(initial_attacker_position='physical attacker'),
        dict(initial_evidence_refs=('finding:other#attacker_position',))]:
        changed = dataclasses.replace(chain, **changes)
        changed_graph = dataclasses.replace(graph, chains=(changed,))
        assert q.chain_fingerprint(changed_graph, changed) != before
        assert q.edge_fingerprint(changed_graph, graph.edges[0]) != q.edge_fingerprint(graph, graph.edges[0])
    assert q.chain_fingerprint(dataclasses.replace(graph, candidate_snapshot_sha256='0' * 64), chain) != before


def test_question_identity_projection_is_canonical(graph, tmp_path):
    question = next(x for x in derived(graph).questions if x.origin == 'surface-unknown' and any(str(s) == 'surface-unknown:overlap' for s in x.subject_refs))
    projection = dict(image_id=graph.image_id, candidate_snapshot_sha256=graph.candidate_snapshot_sha256,
        subject_refs=sorted(map(str, question.subject_refs)), method=question.method, question=question.question,
        settling_observation=question.settling_observation, axes=sorted(question.axes))
    expected = hashlib.sha256(json.dumps(projection, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    assert question.question_id == expected


def test_explicit_retries_bind_contiguous_durable_history(graph):
    question = derived(graph).questions[0]
    prior = history(question)
    assert derived(graph, history=(prior,)) == derived(graph)
    directives = q.parse_retry_directives([question.question_id + ':' + '1' * 64])
    retried = derived(graph, history=(prior,), retries=directives)
    actual = next(x for x in retried.questions if x.question_id == question.question_id)
    assert actual.attempt_ordinal == 2 and actual.prior_observation_id == '1' * 64
    assert retried.retry_projection == ((question.question_id, 2, '1' * 64),)
    pending = history(question, ordinal=2, observation=None, outcome=None, value=None, dependencies=(), evidence=())
    third = derived(graph, history=(prior, pending), retries=q.parse_retry_directives([question.question_id]))
    assert next(x for x in third.questions if x.question_id == question.question_id).attempt_ordinal == 3


@pytest.mark.parametrize('damage', ['missing', 'foreign', 'gap', 'zero', 'wrong-observation', 'duplicate', 'malformed', 'duplicate-history'])
def test_retries_reject_incoherent_or_foreign_history(graph, damage):
    question = derived(graph).questions[0]
    prior = history(question)
    values = [question.question_id]
    past = (prior,)
    if damage == 'missing': past = ()
    elif damage == 'foreign': values = ['f' * 64]
    elif damage == 'gap': past = (history(question, ordinal=2),)
    elif damage == 'zero': past = (history(question, ordinal=0),)
    elif damage == 'wrong-observation': values = [question.question_id + ':' + '2' * 64]
    elif damage == 'duplicate': values *= 2
    elif damage == 'malformed': values = ['bad:id:extra']
    else: past = (prior, prior)
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph, history=past, retries=q.parse_retry_directives(values))


def test_conflicts_complete_exact_supersedes_and_no_timestamp_winner(graph):
    question = next(x for x in derived(graph).questions if x.origin == 'surface-unknown' and any(str(s) == 'surface-unknown:overlap' for s in x.subject_refs))
    one, two = history(question), history(question, 2, '2' * 64, value='session')
    result = derived(graph, history=(two, one))
    conflict, = [x for x in result.questions if x.origin == 'conflict']
    assert conflict.supersedes_observation_ids == ('1' * 64, '2' * 64)
    assert conflict.resolution_contract == question.resolution_contract and conflict.subject_refs == question.subject_refs
    assert derived(graph, history=(one, two)) == result
    assert question.question_id not in [x.question_id for x in result.questions]
    assert not [x for x in derived(graph, history=(one, dataclasses.replace(two, resolution_value='admin'))).questions if x.origin == 'conflict']
    assert not [x for x in derived(graph, history=(one, dataclasses.replace(two, dependency_current=False))).questions if x.origin == 'conflict']
    settled = history(conflict, observation='3' * 64, supersedes=('1' * 64, '2' * 64))
    assert not [x for x in derived(graph, history=(one, two, settled)).questions if x.origin == 'conflict']


def test_packet_exact_references_bounded_index_no_private_bodies(graph):
    question = derived(graph).questions[0]
    packet = json.loads(q.packet_bytes(question, graph, ()))
    assert packet['question']['question_id'] == question.question_id
    assert packet['journal_index'] == [] and len(packet['extract_records']) <= 3
    assert packet['acquisition_contract']['question_id'] == question.question_id
    assert packet['acquisition_contract']['image_id'] == graph.image_id
    assert packet['acquisition_contract']['network'] == 'none'
    assert packet['acquisition_contract']['max_files'] == 256
    assert packet['acquisition_contract']['max_output_bytes'] == 8 * 1024 * 1024
    body = q.packet_bytes(question, graph, ()).decode()
    assert graph.findings[0].root_cause not in body
    assert 'chains' not in packet and 'findings' not in packet and 'root' not in packet
    assert packet['retained_refs'] and all(set(r) == {'kind', 'logical_id', 'relative_path', 'sha256'} for r in packet['retained_refs'])
    assert graph.graph_path in [r['relative_path'] for r in packet['retained_refs']]
    with pytest.raises(q.FirmwareDiveQuestionError): q.packet_bytes(question, graph, ({'private_body':'secret'},))


def test_automatic_blockers_split_every_edge_or_axis(graph):
    blocker = graph.blockers[0]
    both = tuple(dataclasses.replace(blocker.affected_edges[0], ordinal=e.ordinal) for e in graph.edges)
    changed = dataclasses.replace(graph, blockers=(dataclasses.replace(blocker, affected_edges=both),))
    questions = [x for x in derived(changed).questions if x.origin == 'chain-blocker']
    assert len(questions) == 2
    assert all(x.resolution_contract.predicate == 'edge-validity' for x in questions)
    assert len({str(x.resolution_contract.target_subject) for x in questions}) == 2
    changed = dataclasses.replace(graph, blockers=(dataclasses.replace(blocker, affected_edges=(),
        axes=('authentication','lifecycle')),))
    questions = [x for x in derived(changed).questions if x.origin == 'chain-blocker']
    assert {x.resolution_contract.axis for x in questions} == {'authentication','lifecycle'}


def test_nonstate_discovery_is_bounded_specific_namespace(graph):
    unknowns = tuple(dataclasses.replace(u, field='handler') if u.id == 'overlap' else u for u in graph.unknowns)
    question = next(x for x in derived(dataclasses.replace(graph, unknowns=unknowns)).questions if x.origin == 'surface-unknown' and any(str(s) == 'surface-unknown:overlap' for s in x.subject_refs))
    contract = question.resolution_contract
    assert contract.predicate == 'capability-present' and contract.other_specific
    assert contract.allowed_values == () and contract.axis is None


def test_packets_only_authorize_exact_extract_records(graph):
    question = derived(graph).questions[0]
    record = q.ExtractRecord(unit='u', name='handler.c', relative_path='extract/u/handler.c',
        sha256='a' * 64, byte_count=100, version=1, truncated=False, backend='source-tree', manifest_record_sha256='b'*64)
    question = dataclasses.replace(question, extract_records=(record,))
    packet = json.loads(q.packet_bytes(question, graph, ()))
    assert packet['extract_records'] == [dataclasses.asdict(record)]
    assert any(r['kind'] == 'extract-record' for r in packet['allowed_dependencies'])
    for records in [(record,) * 4, (dataclasses.replace(record, relative_path='extract/u/other.c'),),
        (dataclasses.replace(record, relative_path='/private/root'),), (record, record)]:
        with pytest.raises(q.FirmwareDiveQuestionError):
            q.packet_bytes(dataclasses.replace(question, extract_records=records), graph, ())


def test_packet_journal_index_is_bounded_exact_and_subject_filtered(graph):
    question = derived(graph).questions[0]
    index = q.JournalIndexEntry(observation_id='1' * 64, question_id=question.question_id,
        subject_refs=question.subject_refs, status='current', outcome='supported',
        artifact_path='artifacts/result.json', artifact_sha256='2' * 64)
    packet = json.loads(q.packet_bytes(question, graph, (index,)))
    assert len(packet['journal_index']) == 1
    with pytest.raises(q.FirmwareDiveQuestionError): q.packet_bytes(question, graph, (index,) * 1001)
    with pytest.raises(q.FirmwareDiveQuestionError):
        q.packet_bytes(question, graph, (dataclasses.replace(index, artifact_path='../private'),))


def test_supersession_cannot_hide_partial_foreign_or_nonconflicting_sets(graph):
    question = next(x for x in derived(graph).questions if x.origin == 'surface-unknown')
    one, two = history(question), history(question, 2, '2' * 64, value='session')
    conflict = next(x for x in derived(graph, history=(one,two)).questions if x.origin == 'conflict')
    for supersedes in [('1' * 64,), ('1' * 64, '9' * 64)]:
        forged = dataclasses.replace(conflict, supersedes_observation_ids=supersedes,
            question=conflict_text(supersedes))
        forged = dataclasses.replace(forged, question_id=q.canonical_question_id(graph, forged))
        with pytest.raises(q.FirmwareDiveQuestionError):
            derived(graph, history=(one,two,history(forged, observation='3' * 64,supersedes=supersedes)))


def test_new_answer_after_resolution_contests_with_current_superseder(graph):
    question = next(x for x in derived(graph).questions if x.origin == 'surface-unknown')
    one,two = history(question), history(question,2,'2' * 64,value='session')
    conflict = next(x for x in derived(graph,history=(one,two)).questions if x.origin == 'conflict')
    settled = history(conflict,observation='3' * 64,supersedes=conflict.supersedes_observation_ids)
    late = history(question,3,'4' * 64,value='session')
    result = derived(graph,history=(one,two,settled,late))
    contested, = [x for x in result.questions if x.origin == 'conflict']
    assert contested.supersedes_observation_ids == ('3' * 64,'4' * 64)


def test_contract_change_cannot_reuse_existing_question_history(graph, tmp_path):
    analyst = manifest(tmp_path,[entry(graph)])
    question = next(x for x in derived(graph,analyst).questions if x.origin == 'analyst')
    altered = dataclasses.replace(analyst[0], resolution_contract=dataclasses.replace(analyst[0].resolution_contract,
        allowed_values=('admin',)))
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph,(altered,),history=(history(question),))


def test_manifest_mixed_or_unhashable_values_are_contract_errors(graph,tmp_path):
    for values in [[{}], [True], ['admin', 1]]:
        value = entry(graph)
        value['resolution_contract']['allowed_values'] = values
        with pytest.raises(q.FirmwareDiveQuestionError): manifest(tmp_path,[value])


def test_packet_hardware_has_exact_capture_limit(graph):
    question = next(x for x in derived(graph).questions if x.method == 'hardware')
    contract = json.loads(q.packet_bytes(question,graph,()))['acquisition_contract']
    assert contract['max_capture_bytes'] == 64 * 1024 * 1024
    assert contract['artifact_kinds'] == ['hardware-capture']


@pytest.mark.parametrize('damage', ['empty-text','digest','subject','subject-id','subject-array','other-type',
    'predicate-axis','semantic-axis','boolean-vocab','boolean-type','discovery-expected','semantic-vocab',
    'axis-unaffected','unknown-capability','unknown-identity','transition'])
def test_manifest_contract_boundaries(graph,tmp_path,damage):
    value = entry(graph)
    c = value['resolution_contract']
    if damage == 'empty-text': value['question'] = ' '
    elif damage == 'digest': value['subject_refs'] = ['edge:ABC']
    elif damage == 'subject': value['subject_refs'] = ['not-a-reference']
    elif damage == 'subject-id': value['subject_refs'] = ['finding:../escape']
    elif damage == 'subject-array': value['subject_refs'] = 'finding:one'
    elif damage == 'other-type': c['other_specific'] = 1
    elif damage == 'predicate-axis': c['predicate'] = 'reachability'
    elif damage == 'semantic-axis': c['predicate'] = 'edge-validity'
    elif damage == 'boolean-vocab': c.update(mode='boolean-claim', expected_value='admin')
    elif damage == 'boolean-type':
        subject = 'edge:' + q.edge_fingerprint(graph,graph.edges[0])
        value['subject_refs'] = [subject]
        c.update(target_subject=subject,mode='boolean-claim',predicate='edge-validity',axis=None,
            expected_value='yes',allowed_values=[],capability_kind=graph.edges[0].capability_kind,link_key=graph.edges[0].link_key)
    elif damage == 'discovery-expected': c['expected_value'] = 'admin'
    elif damage == 'semantic-vocab': c.update(predicate='edge-validity',axis=None,allowed_values=[])
    elif damage == 'axis-unaffected': value['axes'] = ['lifecycle']
    elif damage == 'unknown-capability': c.update(predicate='capability-present',axis=None,allowed_values=[],other_specific=True)
    elif damage == 'unknown-identity':
        graph = dataclasses.replace(graph,unknowns=tuple(dataclasses.replace(u,field='handler') if u.id=='overlap' else u for u in graph.unknowns))
        value['subject_refs'] = ['surface-unknown:overlap']
        c.update(target_subject='surface-unknown:overlap',predicate='capability-present',axis=None,allowed_values=[],other_specific=True,link_key='invented')
    else:
        subject='edge:'+q.edge_fingerprint(graph,graph.edges[0]);value['subject_refs']=[subject]
        c.update(target_subject=subject,mode='boolean-claim',predicate='transition-observed',axis=None,
            expected_value=True,allowed_values=[],capability_kind=graph.edges[0].capability_kind,
            link_key=graph.edges[0].link_key,transition_kind='reboot')
    with pytest.raises(q.FirmwareDiveQuestionError): derived(graph,manifest(tmp_path,[value]))


def test_question_packet_rejects_changed_identity_and_attempt(graph):
    question=derived(graph).questions[0]
    for changes in [dict(question_id='0'*64),dict(attempt_ordinal=0)]:
        with pytest.raises(q.FirmwareDiveQuestionError): q.packet_bytes(dataclasses.replace(question,**changes),graph,())
    retried=dataclasses.replace(question,attempt_ordinal=2,prior_observation_id='1'*64)
    assert json.loads(q.packet_bytes(retried,graph,()))['question']['prior_observation_id']=='1'*64


def test_automatic_dangling_edge_rejected(graph):
    blocker=graph.blockers[0]
    graph=dataclasses.replace(graph,blockers=(dataclasses.replace(blocker,affected_edges=(dataclasses.replace(blocker.affected_edges[0],ordinal=999),)),))
    with pytest.raises(q.FirmwareDiveQuestionError): derived(graph)


@pytest.mark.parametrize('damage', ['record','pending-data','duplicate-id','no-evidence','refuted-discovery',
    'inconclusive-effect','supersedes','contract-swap','invalid-value'])
def test_durable_history_is_strict(graph,damage):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    one=history(question)
    values=(one,)
    if damage=='record': values=({},)
    elif damage=='pending-data': values=(dataclasses.replace(one,observation_id=None),)
    elif damage=='duplicate-id': values=(one,history(question,2,value='session'))
    elif damage=='no-evidence': values=(dataclasses.replace(one,evidence_refs=()),)
    elif damage=='refuted-discovery': values=(dataclasses.replace(one,outcome='refuted'),)
    elif damage=='inconclusive-effect': values=(dataclasses.replace(one,outcome='inconclusive'),)
    elif damage=='supersedes': values=(dataclasses.replace(one,supersedes=('2'*64,)),)
    elif damage=='contract-swap':
        altered=dataclasses.replace(question,resolution_contract=dataclasses.replace(question.resolution_contract,allowed_values=('admin',)))
        values=(one,history(altered,2,'2'*64))
    else: values=(dataclasses.replace(one,resolution_value='root'),)
    with pytest.raises(q.FirmwareDiveQuestionError): derived(graph,history=values)


def test_history_accepts_boolean_claim_and_specific_discovery(graph,tmp_path):
    question=next(x for x in derived(graph).questions if x.origin=='chain-blocker')
    assert derived(graph,history=(history(question,value=True),))
    value=entry(graph)
    value['resolution_contract'].update(mode='boolean-claim',expected_value='admin',allowed_values=[])
    analyst=manifest(tmp_path,[value])
    question=next(x for x in derived(graph,analyst).questions if x.origin=='analyst')
    assert derived(graph,analyst,history=(history(question,value='admin'),))
    unknowns=tuple(dataclasses.replace(u,field='handler') if u.id=='overlap' else u for u in graph.unknowns)
    changed=dataclasses.replace(graph,unknowns=unknowns,edges=tuple(dataclasses.replace(e,existing_unknowns=()) for e in graph.edges))
    question=next(x for x in derived(changed).questions if any(str(s)=='surface-unknown:overlap' for s in x.subject_refs))
    assert derived(changed,history=(history(question,value='other-specific:auth_gate'),))
    for invalid in ['other-specific:', 'other-specific:bad/value', 'other-specific:'+'a'*128]:
        with pytest.raises(q.FirmwareDiveQuestionError): derived(changed,history=(history(question,value=invalid),))
    assert derived(graph,history=(history(next(x for x in derived(graph).questions if x.origin=='surface-unknown'),
        outcome='inconclusive',value=None),))


def test_duplicate_canonical_questions_fail_even_when_contracts_differ(graph):
    question=derived(graph).questions[0]
    analyst=q.AnalystQuestion(**{f.name:getattr(question,f.name) for f in dataclasses.fields(q.AnalystQuestion)})
    with pytest.raises(q.FirmwareDiveQuestionError): derived(graph,(analyst,))


def test_supersession_rejects_wrong_origin_contract_agreement_text_and_family(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    one,two=history(question),history(question,2,'2'*64,value='session')
    conflict=next(x for x in derived(graph,history=(one,two)).questions if x.origin=='conflict')
    for damage in ['origin','contract','agree','text','family']:
        parents=(one,two); forged=conflict
        if damage=='origin': forged=dataclasses.replace(conflict,origin='analyst')
        elif damage=='contract': forged=dataclasses.replace(conflict,method='hardware')
        elif damage=='agree': parents=(one,dataclasses.replace(two,resolution_value='admin'))
        elif damage=='text': forged=dataclasses.replace(conflict,question='Choose the latest answer')
        else:
            other=dataclasses.replace(question,question='A distinct proposition')
            other=dataclasses.replace(other,question_id=q.canonical_question_id(graph,other))
            parents=(one,history(other,observation='2'*64,value='session'))
        forged=dataclasses.replace(forged,question_id=q.canonical_question_id(graph,forged))
        with pytest.raises(q.FirmwareDiveQuestionError):
            derived(graph,history=(*parents,history(forged,observation='3'*64,supersedes=forged.supersedes_observation_ids)))


def test_conflict_supersession_cycles_are_not_authority(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    one,two=history(question),history(question,2,'2'*64,value='session')
    conflict=next(x for x in derived(graph,history=(one,two)).questions if x.origin=='conflict')
    a=dataclasses.replace(conflict,supersedes_observation_ids=('1'*64,'4'*64),question=conflict_text(('1'*64,'4'*64)))
    b=dataclasses.replace(conflict,supersedes_observation_ids=('2'*64,'3'*64),question=conflict_text(('2'*64,'3'*64)))
    a=dataclasses.replace(a,question_id=q.canonical_question_id(graph,a));b=dataclasses.replace(b,question_id=q.canonical_question_id(graph,b))
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph,history=(one,two,history(a,observation='3'*64,supersedes=a.supersedes_observation_ids),
            history(b,observation='4'*64,value='session',supersedes=b.supersedes_observation_ids)))


def test_packet_chain_authorizes_initial_evidence_without_graph_bodies(graph,tmp_path):
    subject='chain:'+q.chain_fingerprint(graph,graph.chains[0])
    analyst=manifest(tmp_path,[entry(graph,subject)])
    question=next(x for x in derived(graph,analyst).questions if x.origin=='analyst')
    packet=json.loads(q.packet_bytes(question,graph,()))
    assert set(graph.chains[0].initial_evidence_refs)<=set(packet['evidence_refs'])
    assert graph.chains[0].summary not in q.packet_bytes(question,graph,()).decode()

def test_packet_finding_subject_authorizes_all_finding_evidence(graph,tmp_path):
    finding=graph.findings[0]
    analyst=manifest(tmp_path,[entry(graph,'finding:'+finding.finding_id)])
    question=next(x for x in derived(graph,analyst).questions if x.origin=='analyst')
    packet=json.loads(q.packet_bytes(question,graph,()))
    expected={f'finding:{finding.finding_id}#{field}' for field in (
        'root_cause','attacker_position','data_flow','impact_hypothesis','evidence_summary')}
    assert expected<=set(packet['evidence_refs'])


@pytest.mark.parametrize('damage',['record','name','size','version','flag'])
def test_extract_manifest_records_are_exact_bounded_and_safe(graph,damage):
    record=q.ExtractRecord('u','n','extract/u/n','a'*64,1,1,False,'source-tree','b'*64)
    if damage=='record': record={}
    elif damage=='name': record=dataclasses.replace(record,unit='../u')
    elif damage=='size': record=dataclasses.replace(record,byte_count=512101)
    elif damage=='version': record=dataclasses.replace(record,version=0)
    else: record=dataclasses.replace(record,truncated=1)
    question=dataclasses.replace(derived(graph).questions[0],extract_records=(record,))
    with pytest.raises(q.FirmwareDiveQuestionError): q.packet_bytes(question,graph,())


def test_packet_journal_duplicate_and_total_byte_bounds(graph):
    question=derived(graph).questions[0]
    index=q.JournalIndexEntry('1'*64,question.question_id,question.subject_refs,'current','supported','artifacts/r.json','2'*64)
    with pytest.raises(q.FirmwareDiveQuestionError): q.packet_bytes(question,graph,(index,index))
    huge=tuple(dataclasses.replace(index,observation_id=f'{i:064x}',artifact_path='artifacts/'+'x'*2000) for i in range(1000))
    with pytest.raises(q.FirmwareDiveQuestionError): q.packet_bytes(question,graph,huge)


def test_boolean_history_outcomes_match_exact_effects(graph):
    question=next(x for x in derived(graph).questions if x.origin=='chain-blocker')
    for outcome,value in [('supported',False),('refuted',True)]:
        with pytest.raises(q.FirmwareDiveQuestionError): derived(graph,history=(history(question,outcome=outcome,value=value),))
    assert derived(graph,history=(history(question,outcome='refuted',value=False),))


def test_conflict_derivation_rejects_duplicate_analyst_origin(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    one,two=history(question),history(question,2,'2'*64,value='session')
    conflict=next(x for x in derived(graph,history=(one,two)).questions if x.origin=='conflict')
    analyst=q.AnalystQuestion(**{f.name:getattr(conflict,f.name) for f in dataclasses.fields(q.AnalystQuestion)})
    with pytest.raises(q.FirmwareDiveQuestionError): derived(graph,(analyst,),history=(one,two))


def test_current_inconclusive_conflict_has_explicit_durable_retry(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    one,two=history(question),history(question,2,'2'*64,value='session')
    conflict=next(x for x in derived(graph,history=(one,two)).questions if x.origin=='conflict')
    inconclusive=history(conflict,observation='3'*64,outcome='inconclusive',value=None,
        supersedes=conflict.supersedes_observation_ids)
    result=derived(graph,history=(one,two,inconclusive),
        retries=q.parse_retry_directives([conflict.question_id+':'+'3'*64]))
    retried=next(x for x in result.questions if x.origin=='conflict')
    assert retried.attempt_ordinal==2 and retried.prior_observation_id=='3'*64
    assert retried.supersedes_observation_ids==('1'*64,'2'*64)


def test_durable_question_origin_is_immutable(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    changed=dataclasses.replace(question,origin='analyst')
    with pytest.raises(q.FirmwareDiveQuestionError):
        derived(graph,history=(history(question),history(changed,2,'2'*64)))


def test_manifest_top_level_questions_require_canonical_entry_order(graph,tmp_path):
    alpha=entry(graph);alpha['question']='Alpha authority question'
    zulu=entry(graph);zulu['question']='Zulu authority question'
    with pytest.raises(q.FirmwareDiveQuestionError): manifest(tmp_path,[zulu,alpha])
    assert len(manifest(tmp_path,[alpha,zulu]))==2


def test_redundant_content_addressed_observations_preserve_attempts_and_one_conflict_id(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    one=history(question)
    identical=history(question,2)
    assert derived(graph,history=(one,identical))==derived(graph)
    other=history(question,3,'2'*64,value='session')
    conflict=next(x for x in derived(graph,history=(one,identical,other)).questions if x.origin=='conflict')
    assert conflict.supersedes_observation_ids==('1'*64,'2'*64)
    result=derived(graph,history=(one,identical),retries=q.parse_retry_directives([question.question_id]))
    assert next(x for x in result.questions if x.question_id==question.question_id).attempt_ordinal==3


def test_extract_identity_binds_stable_full_record_without_source_or_timestamp_leak(graph):
    from audit_core import extract
    upstream=extract.Record('u','handler.c','extract/u/handler.c','src/handler.c','a'*64,100,1,False,'source-tree','2026-01-01')
    stable=dict(unit='u',name='handler.c',relpath='extract/u/handler.c',source='src/handler.c',sha256='a'*64,
        bytes=100,version=1,truncated=False,backend='source-tree')
    expected=hashlib.sha256(json.dumps(stable,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    retained=q.extract_record(upstream)
    assert retained.manifest_record_sha256==expected
    assert q.extract_record(dataclasses.replace(upstream,extracted_at='2030-01-01'))==retained
    assert q.extract_record(dataclasses.replace(upstream,source='src/other.c')).manifest_record_sha256!=expected
    question=dataclasses.replace(derived(graph).questions[0],extract_records=(retained,))
    raw=q.packet_bytes(question,graph,())
    assert b'src/handler.c' not in raw and b'2026-01-01' not in raw
    assert json.loads(raw)['extract_records'][0]['manifest_record_sha256']==expected
    with pytest.raises(q.FirmwareDiveQuestionError):
        q.packet_bytes(dataclasses.replace(question,extract_records=(dataclasses.replace(retained,manifest_record_sha256='bad'),)),graph,())
    for source in ['/private/root/file','C:/root/file','../root/file','file:///private/root']:
        with pytest.raises(q.FirmwareDiveQuestionError): q.extract_record(dataclasses.replace(upstream,source=source))
    with pytest.raises(q.FirmwareDiveQuestionError): q.extract_record({})


def test_analyst_manifest_refuses_symlinks_before_reading(tmp_path):
    path=tmp_path/'questions.json';path.write_text('{"schema_version":1,"questions":[]}')
    link=tmp_path/'link.json';link.symlink_to(path)
    with pytest.raises(q.FirmwareDiveQuestionError): q.load_analyst_manifest(link)


def test_analyst_manifest_nonregular_and_open_race_fail_closed(tmp_path,monkeypatch):
    import os
    fifo=tmp_path/'fifo';os.mkfifo(fifo)
    with pytest.raises(q.FirmwareDiveQuestionError): q.load_analyst_manifest(fifo)
    path=tmp_path/'questions.json';path.write_text('{"schema_version":1,"questions":[]}')
    replacement=tmp_path/'replacement.json';replacement.write_text('{"schema_version":1,"questions":[]}')
    real_open=os.open
    def swap_open(target,flags):
        if target==path:
            path.rename(tmp_path/'old.json');replacement.rename(path)
        return real_open(target,flags)
    monkeypatch.setattr(q.os,'open',swap_open)
    with pytest.raises(q.FirmwareDiveQuestionError): q.load_analyst_manifest(path)


def test_large_complete_conflict_set_remains_packet_bounded(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    observations=tuple(history(question,i+1,f'{i+1:064x}',value='admin' if i%2 else 'session') for i in range(70))
    conflict=next(x for x in derived(graph,history=observations).questions if x.origin=='conflict')
    raw=q.packet_bytes(conflict,graph,())
    packet=json.loads(raw)
    assert packet['question']['supersedes_observation_ids']==[f'{i+1:064x}' for i in range(70)]
    assert len(packet['question']['question'].encode())<=4096
    assert packet['question']['question']==conflict_text([f'{i+1:064x}' for i in range(70)])


def test_deep_coherent_supersession_history_is_order_independent(graph):
    question=next(x for x in derived(graph).questions if x.origin=='surface-unknown')
    values=[history(question,observation=f'{1:064x}')]
    previous=f'{1:064x}'
    for ordinal in range(1,1051):
        new_id=f'{ordinal*2:064x}';sup_id=f'{ordinal*2+1:064x}'
        values.append(history(question,ordinal+1,new_id,value='session'))
        refs=tuple(sorted((previous,new_id)))
        conflict=dataclasses.replace(question,origin='conflict',question=conflict_text(refs),supersedes_observation_ids=refs)
        conflict=dataclasses.replace(conflict,question_id=q.canonical_question_id(graph,conflict))
        values.append(history(conflict,observation=sup_id,supersedes=refs))
        previous=sup_id
    assert derived(graph,history=tuple(reversed(values)))==derived(graph,history=tuple(values))


def test_repeated_observation_semantics_ignore_recomputed_currentness(graph):
    question = next(item for item in derived(graph).questions if item.origin == 'surface-unknown')
    current = history(question,current=True)
    stale = history(question,ordinal=2,current=False)
    conflicting_stale = history(question,ordinal=3,observation='2'*64,value='session',current=False)
    result = derived(graph,history=(current,stale,conflicting_stale))
    assert all(item.origin != 'conflict' for item in result.questions)
    assert result == derived(graph,history=(current,))
