"""Literal hostile-worker boundary and pure content identities; no SQL authority."""
import copy
import dataclasses
import hashlib
import json
import os

import pytest

from audit_core import firmware_dive_results as results
from audit_core import firmware_dive_questions as questions

A, B, C, D = (c * 64 for c in 'abcd')


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def effect():
    return dict(target_subject='edge:' + A, mode='boolean-claim', predicate='edge-validity',
        axis=None, value=True, capability_kind=None, link_key=None, transition_kind=None)


def contract():
    return questions.ResolutionContract(questions.SubjectRef('edge', A), 'boolean-claim',
        'edge-validity', None, True, (), False, None, None, None)


def answer():
    return dict(question_id=B, attempt_ordinal=1, packet_sha256=C, outcome='supported',
        conclusion='Observed café 接続', limitations=['Static analysis only'], resolution_effect=effect(),
        dependencies=[dict(kind='finding-artifact', logical_id='finding-1', relative_path='artifacts/findings.json',
            sha256=D, byte_count=12)],
        evidence=[dict(dependency_kind='finding-artifact', dependency_logical_id='finding-1',
            reference='finding:finding-1#evidence_summary')], successor_questions=[])


def wire():
    return dict(schema_version=1, image_id='target 雪\t|a', dive_generation=A, questions=[answer()])


def read(tmp_path, value=None, raw=None):
    path = tmp_path / 'result.json'
    path.write_bytes(raw if raw is not None else encode(wire() if value is None else value))
    return results.load(path)


def successor():
    return dict(subject_refs=['edge:' + A], method='static', question='Which edge?',
        settling_observation='Inspect exact link', axes=['authentication'],
        resolution_contract=questions._wire(contract()))


def test_literal_supported_boolean_roundtrip_and_frozen(tmp_path):
    value = read(tmp_path)
    assert isinstance(value, results.DiveResult)
    assert isinstance(value.answer, results.QuestionAnswer)
    assert value.answer.conclusion == 'Observed café 接続'
    assert value.image_id == 'target 雪\t|a'
    assert value.answer.resolution_effect.value is True
    assert value.answer.dependencies[0].byte_count == 12
    assert results.canonical_bytes(value) == encode(wire())
    results.validate_answer(value.answer, contract())
    for item in (value, value.answer, value.answer.resolution_effect, value.answer.dependencies[0], value.answer.evidence[0]):
        with pytest.raises(dataclasses.FrozenInstanceError):
            item.anything = 1


def test_refuted_boolean_and_supported_discovery(tmp_path):
    value = wire()
    value['questions'][0]['outcome'] = 'refuted'
    value['questions'][0]['resolution_effect']['value'] = False
    results.validate_answer(read(tmp_path, value).answer, contract())
    discovery = questions.ResolutionContract(questions.SubjectRef('surface-unknown', 'u1'),
        'value-discovery', 'state-value', 'authentication', None, ('admin', 'pre-auth'), False, None, None, None)
    row = value['questions'][0]
    row.update(outcome='supported', resolution_effect=dict(target_subject='surface-unknown:u1',
        mode='value-discovery', predicate='state-value', axis='authentication', value='admin',
        capability_kind=None, link_key=None, transition_kind=None))
    results.validate_answer(read(tmp_path, value).answer, discovery)
    row['resolution_effect'].update(predicate='capability-present', axis=None, value='other-specific:uart')
    other = dataclasses.replace(discovery, predicate='capability-present', axis=None, allowed_values=(), other_specific=True)
    results.validate_answer(read(tmp_path, value).answer, other)


@pytest.mark.parametrize('partial', [False, True])
def test_inconclusive_explicit_reason_partial_evidence(tmp_path, partial):
    value = wire()
    row = value['questions'][0]
    row.update(outcome='inconclusive', conclusion='Device needed to settle the claim', resolution_effect=None)
    if not partial:
        row.update(dependencies=[], evidence=[])
    parsed = read(tmp_path, value)
    results.validate_answer(parsed.answer, contract())
    assert parsed.answer.outcome == 'inconclusive' and parsed.answer.resolution_effect is None


@pytest.mark.parametrize(('namespace', 'kind'), [('probe', 'probe-manifest'), ('capture', 'hardware-capture')])
def test_dynamic_references_are_structural_only(tmp_path, namespace, kind):
    value = wire()
    row = value['questions'][0]
    row['dependencies'] = [dict(kind=kind, logical_id=B,
        relative_path=f'artifacts/acquisitions/{B}/manifest.json', sha256=C, byte_count=0)]
    row['evidence'] = [dict(dependency_kind=kind, dependency_logical_id=B,
        reference=f'{namespace}:{B}#evidence/測定.bin')]
    assert read(tmp_path, value).answer.evidence[0].reference.endswith('測定.bin')


def test_canonical_successor_and_nonaliasing(tmp_path):
    value = wire()
    value['questions'][0]['successor_questions'] = [successor()]
    parsed = read(tmp_path, value)
    item = parsed.answer.successor_questions[0]
    assert isinstance(item, results.SuccessorQuestion)
    assert str(item.subject_refs[0]) == 'edge:' + A
    assert results.canonical_bytes(parsed) == encode(value)
    mutable = ['b', 'a']
    replaced = dataclasses.replace(parsed.answer, limitations=mutable)
    mutable.append('changed')
    assert replaced.limitations == ('a', 'b')
    assert isinstance(replaced.successor_questions, tuple)
    with pytest.raises((dataclasses.FrozenInstanceError, TypeError)):
        item.question = 'changed'


def test_exact_empty_variant_and_receipt(tmp_path):
    value = wire() | {'questions': []}
    parsed = read(tmp_path, value)
    assert isinstance(parsed.answer, results.EmptyAnswer)
    assert results.canonical_bytes(parsed) == encode(value)
    # Matching prepared empty/nonempty denominator is deliberately Task 8 authority.
    projection = dict(image_id=parsed.image_id, dive_generation=A, receipt_kind='empty', result_sha256=B)
    assert results.canonical_receipt_key(image_id=parsed.image_id, dive_generation=A, result_sha256=B,
        receipt_kind='empty') == 'firmware-dive-receipt-' + hashlib.sha256(encode(projection)).hexdigest()


@pytest.mark.parametrize('extra', ['observations', 'dependencies', 'evidence', 'outcome', 'question_id', 'receipt_kind'])
def test_empty_cannot_smuggle_answer_fields(tmp_path, extra):
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, wire() | {'questions': [], extra: []})


@pytest.mark.parametrize('raw', [b'\xff', b'{', b'[]', b'null', b'{"schema_version":1,"schema_version":1}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'[' * 1100 + b']' * 1100,
    b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}'])
def test_hostile_encoding_duplicate_nonfinite_depth(tmp_path, raw):
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, raw=raw)


@pytest.mark.parametrize(('scope', 'key', 'bad'), [
    ('root', 'schema_version', True), ('root', 'schema_version', 1.0), ('root', 'schema_version', '1'),
    ('root', 'schema_version', 2), ('root', 'image_id', ''), ('root', 'image_id', 'a\0b'),
    ('root', 'image_id', '\ud800'), ('root', 'image_id', 'a' * 4097),
    ('root', 'dive_generation', 'A' * 64), ('root', 'dive_generation', 1),
    ('root', 'questions', None), ('root', 'questions', [answer(), answer()]),
    ('answer', 'question_id', 'x'), ('answer', 'packet_sha256', '../a'),
    ('answer', 'attempt_ordinal', True), ('answer', 'attempt_ordinal', '1'),
    ('answer', 'attempt_ordinal', 1.0), ('answer', 'attempt_ordinal', 0),
    ('answer', 'attempt_ordinal', 2**63), ('answer', 'outcome', 'empty'),
    ('answer', 'outcome', 'SUPPORTED'), ('answer', 'conclusion', ''),
    ('answer', 'conclusion', 'a\nb'), ('answer', 'conclusion', 'a\u202eb'),
    ('answer', 'conclusion', 'é' * 2049), ('answer', 'limitations', ['b', 'a']),
    ('answer', 'limitations', ['a', 'a']), ('answer', 'limitations', ['']),
    ('answer', 'limitations', ['x'] * 1001), ('answer', 'dependencies', []),
    ('answer', 'evidence', []), ('answer', 'resolution_effect', None),
    ('answer', 'successor_questions', [successor(), successor()]),
    ('answer', 'successor_questions', [successor()] * 101),
])
def test_hostile_scalar_variant_and_array(tmp_path, scope, key, bad):
    value = wire()
    (value if scope == 'root' else value['questions'][0])[key] = bad
    # Preserve lone-surrogate hostile wire as an ASCII JSON escape.
    raw = json.dumps(value).encode()
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, raw=raw)


@pytest.mark.parametrize('scope', ['root', 'answer', 'effect', 'dependency', 'evidence', 'successor'])
@pytest.mark.parametrize('operation', ['extra', 'missing'])
def test_exact_nested_keys(tmp_path, scope, operation):
    value = wire()
    row = value['questions'][0]
    row['successor_questions'] = [successor()]
    obj = {'root':value, 'answer':row, 'effect':row['resolution_effect'], 'dependency':row['dependencies'][0],
        'evidence':row['evidence'][0], 'successor':row['successor_questions'][0]}[scope]
    if operation == 'extra':
        obj['sql'] = 'DROP TABLE x'
    else:
        obj.pop(next(iter(obj)))
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, value)


@pytest.mark.parametrize('field', ['evidence_rung', 'observation_id', 'receipt_key', 'timestamp', 'candidate_snapshot_sha256', 'label'])
def test_worker_derived_fields_rejected(tmp_path, field):
    value = wire()
    value['questions'][0][field] = A
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, value)


@pytest.mark.parametrize(('scope', 'key', 'bad'), [
    ('dependency', 'kind', 'file'), ('dependency', 'logical_id', '../escape'),
    ('dependency', 'relative_path', '/absolute'), ('dependency', 'relative_path', 'a//b'),
    ('dependency', 'relative_path', 'a/../b'), ('dependency', 'relative_path', 'C:/a'),
    ('dependency', 'relative_path', 'a\\b'), ('dependency', 'relative_path', './a'),
    ('dependency', 'sha256', 'g' * 64), ('dependency', 'byte_count', True),
    ('dependency', 'byte_count', -1), ('dependency', 'byte_count', 1.0), ('dependency', 'byte_count', 2**63),
    ('evidence', 'dependency_kind', 'surface-artifact'), ('evidence', 'dependency_logical_id', 'other'),
    ('evidence', 'reference', 'finding:../a#evidence'), ('evidence', 'reference', 'file:/etc/passwd'),
    ('evidence', 'reference', 'probe:' + B + '#../x'),
    ('evidence', 'reference', 'capture:' + B + '#/x'),
    ('effect', 'target_subject', 'edge:not-a-digest'), ('effect', 'mode', 'freeform'),
    ('effect', 'predicate', 'arbitrary'), ('effect', 'value', 1),
    ('effect', 'axis', 'authentication'), ('effect', 'value', 'admin'),
])
def test_invalid_reference_paths_digests_types_and_effect(tmp_path, scope, key, bad):
    value = wire()
    row = value['questions'][0]
    obj = {'dependency':row['dependencies'][0], 'evidence':row['evidence'][0], 'effect':row['resolution_effect']}[scope]
    obj[key] = bad
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, value)


@pytest.mark.parametrize('field', ['dependencies', 'evidence', 'successor_questions'])
def test_duplicate_and_noncanonical_set_arrays(tmp_path, field):
    value = wire()
    row = value['questions'][0]
    if field == 'successor_questions':
        row[field] = [successor()]
    row[field].append(copy.deepcopy(row[field][0]))
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, value)
    if field == 'dependencies':
        row[field][1]['logical_id'] = 'aaa'
    elif field == 'evidence':
        row[field][1]['reference'] = 'finding:finding-1#attacker_position'
    else:
        row[field][1]['question'] = 'AAA'
    row[field].sort(key=encode, reverse=True)
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, value)


def test_duplicate_logical_dependency_identity_refused(tmp_path):
    value = wire()
    dep = copy.deepcopy(value['questions'][0]['dependencies'][0])
    dep.update(relative_path='artifacts/other.json', sha256=A)
    value['questions'][0]['dependencies'].append(dep)
    value['questions'][0]['dependencies'].sort(key=lambda x:(x['kind'], x['logical_id'], x['relative_path'], x['sha256'], x['byte_count']))
    with pytest.raises(results.FirmwareDiveResultError):
        read(tmp_path, value)


@pytest.mark.parametrize('change', ['target_subject', 'mode', 'predicate', 'axis', 'capability_kind', 'link_key', 'transition_kind', 'expected_value'])
def test_effect_must_match_exact_external_contract(tmp_path, change):
    parsed = read(tmp_path)
    bad = dataclasses.replace(contract(), **{change: {'target_subject': questions.SubjectRef('edge', B),
        'mode':'value-discovery', 'predicate':'transition-observed', 'axis':'authentication',
        'capability_kind':'read', 'link_key':'other', 'transition_kind':'other', 'expected_value':False}[change]})
    with pytest.raises(results.FirmwareDiveResultError):
        results.validate_answer(parsed.answer, bad)


def test_refuted_discovery_and_inconclusive_effect_rejected(tmp_path):
    value = wire()
    value['questions'][0].update(outcome='refuted', resolution_effect=dict(target_subject='surface-unknown:u1',
        mode='value-discovery', predicate='state-value', axis='authentication', value='admin',
        capability_kind=None, link_key=None, transition_kind=None))
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)
    value['questions'][0].update(outcome='inconclusive', resolution_effect=effect())
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


def observation(parsed, **kw):
    return results.canonical_observation_id(image_id=parsed.image_id, candidate_snapshot_sha256=D,
        answer=parsed.answer, evidence_rung='static-resolved', **kw)


def test_observation_identity_exact_projection_and_unicode(tmp_path):
    parsed = read(tmp_path)
    a = answer()
    projection = dict(image_id=parsed.image_id, candidate_snapshot_sha256=D, question_id=B,
        outcome=a['outcome'], conclusion=a['conclusion'], limitations=a['limitations'],
        evidence_rung='static-resolved', resolution_effect=a['resolution_effect'],
        dependencies=a['dependencies'], evidence=a['evidence'])
    assert observation(parsed) == hashlib.sha256(encode(projection)).hexdigest()
    assert len(observation(parsed)) == 64


@pytest.mark.parametrize('field', ['image', 'candidate', 'question', 'outcome', 'conclusion', 'limitations', 'rung', 'effect', 'dependency', 'evidence'])
def test_observation_identity_binds_every_semantic_field(tmp_path, field):
    parsed = read(tmp_path)
    image, candidate, rung, row = parsed.image_id, D, 'static-resolved', parsed.answer
    if field == 'image': image += 'x'
    elif field == 'candidate': candidate = A
    elif field == 'question': row = dataclasses.replace(row, question_id=C)
    elif field == 'outcome': row = dataclasses.replace(row, outcome='refuted', resolution_effect=dataclasses.replace(row.resolution_effect, value=False))
    elif field == 'conclusion': row = dataclasses.replace(row, conclusion='Different')
    elif field == 'limitations': row = dataclasses.replace(row, limitations=('Other',))
    elif field == 'rung': rung = 'hardware-observed'
    elif field == 'effect': row = dataclasses.replace(row, resolution_effect=dataclasses.replace(row.resolution_effect, link_key='changed'))
    elif field == 'dependency': row = dataclasses.replace(row, dependencies=(dataclasses.replace(row.dependencies[0], sha256=A),))
    elif field == 'evidence': row = dataclasses.replace(row, evidence=(dataclasses.replace(row.evidence[0], reference='finding:finding-1#root_cause'),))
    assert results.canonical_observation_id(image_id=image, candidate_snapshot_sha256=candidate,
        answer=row, evidence_rung=rung) != observation(parsed)


def test_identity_ignores_assignment_and_successor_but_normalizes_sets(tmp_path):
    parsed = read(tmp_path)
    value = wire()
    value['questions'][0]['successor_questions'] = [successor()]
    newer = read(tmp_path, value)
    newer = dataclasses.replace(newer, answer=dataclasses.replace(newer.answer, attempt_ordinal=2, packet_sha256=A))
    assert observation(newer) == observation(parsed)
    row = dataclasses.replace(parsed.answer, limitations=['a', 'b'])
    left = dataclasses.replace(parsed, answer=row)
    right = dataclasses.replace(parsed, answer=dataclasses.replace(row, limitations=['b', 'a']))
    assert observation(left) == observation(right)


def test_receipt_exact_question_projection_and_all_fields(tmp_path):
    parsed = read(tmp_path)
    args = dict(image_id=parsed.image_id, dive_generation=A, question_id=B, attempt_ordinal=1,
        packet_sha256=C, result_sha256=D)
    want = 'firmware-dive-receipt-' + hashlib.sha256(encode(args)).hexdigest()
    assert results.canonical_receipt_key(**args) == want
    for key, val in args.items():
        changed = args | {key:2 if key == 'attempt_ordinal' else val + 'x' if key == 'image_id' else 'e' * 64}
        assert results.canonical_receipt_key(**changed) != want
    with pytest.raises(TypeError): results.canonical_receipt_key(**args, result_path='/tmp/x')
    with pytest.raises(TypeError): results.canonical_receipt_key(**args, recorded_at='now')
    for key in ('image_id', 'dive_generation', 'result_sha256'):
        empty = dict(image_id='x', dive_generation=A, result_sha256=B, receipt_kind='empty')
        newer = empty | {key:'y' if key == 'image_id' else C}
        assert results.canonical_receipt_key(**empty) != results.canonical_receipt_key(**newer)


@pytest.mark.parametrize('args', [dict(receipt_kind='other'), dict(receipt_kind='empty', question_id=B),
    dict(question_id=B), dict(question_id=B, attempt_ordinal=True, packet_sha256=C),
    dict(question_id=B, attempt_ordinal=1, packet_sha256='bad')])
def test_receipt_invalid_variants_and_types(args):
    with pytest.raises(results.FirmwareDiveResultError):
        results.canonical_receipt_key(image_id='x', dive_generation=A, result_sha256=B, **args)


def test_inconclusive_rung_must_be_null_and_conclusive_rung_derived(tmp_path):
    parsed = read(tmp_path)
    for rung in (None, 'worker-says-so'):
        with pytest.raises(results.FirmwareDiveResultError):
            results.canonical_observation_id(image_id='x', candidate_snapshot_sha256=D, answer=parsed.answer, evidence_rung=rung)
    row = dataclasses.replace(parsed.answer, outcome='inconclusive', resolution_effect=None)
    digest = results.canonical_observation_id(image_id='x', candidate_snapshot_sha256=D, answer=row, evidence_rung=None)
    assert len(digest) == 64
    with pytest.raises(results.FirmwareDiveResultError):
        results.canonical_observation_id(image_id='x', candidate_snapshot_sha256=D, answer=row, evidence_rung='static-resolved')


def test_raw_and_canonical_size_caps_and_file_types(tmp_path, monkeypatch):
    payload = encode(wire())
    raw = payload + b' ' * (8 * 1024 * 1024 - len(payload))
    assert read(tmp_path, raw=raw).answer.question_id == B
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, raw=raw + b' ')
    parsed = read(tmp_path)
    monkeypatch.setattr(results, 'MAX_RESULT_BYTES', len(encode(wire())) - 1)
    with pytest.raises(results.FirmwareDiveResultError): results.canonical_bytes(parsed)
    with pytest.raises(results.FirmwareDiveResultError): results.load(tmp_path)
    with pytest.raises(results.FirmwareDiveResultError): results.load(tmp_path / 'missing')
    link = tmp_path / 'link'
    link.symlink_to(tmp_path / 'result.json')
    with pytest.raises(results.FirmwareDiveResultError): results.load(link)
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with pytest.raises(results.FirmwareDiveResultError): results.load(fifo)


def test_frozen_records_refuse_mutable_nested_aliases(tmp_path):
    parsed = read(tmp_path)
    cases = [
        lambda: dataclasses.replace(parsed.answer, successor_questions=[successor()]),
        lambda: dataclasses.replace(parsed.answer, resolution_effect={'value': True}),
        lambda: dataclasses.replace(parsed.answer.resolution_effect, value=['admin']),
        lambda: dataclasses.replace(parsed.answer.dependencies[0], logical_id=['finding-1']),
        lambda: dataclasses.replace(parsed.answer.evidence[0], reference=['finding:a#root_cause']),
        lambda: dataclasses.replace(parsed, image_id=['target']),
        lambda: dataclasses.replace(parsed, answer=answer()),
        lambda: dataclasses.replace(parsed.answer.resolution_effect, target_subject=['edge', A]),
        lambda: dataclasses.replace(parsed.answer.resolution_effect, target_subject=questions.SubjectRef('edge', [A])),
    ]
    for build in cases:
        with pytest.raises(results.FirmwareDiveResultError):
            build()


@pytest.mark.parametrize('kind', ['extract-record', 'chain-artifact', 'surface-artifact'])
def test_remaining_dependency_kinds_and_packet_static_ref_namespaces(tmp_path, kind):
    value = wire()
    row = value['questions'][0]
    logical = {'extract-record':'unit/name.txt', 'chain-artifact':A, 'surface-artifact':'u1'}[kind]
    row['dependencies'] = [dict(kind=kind, logical_id=logical, relative_path='artifacts/evidence.json', sha256=C, byte_count=2**63-1)]
    row['evidence'] = [dict(dependency_kind=kind, dependency_logical_id=logical, reference='unknown:u1#evidence')]
    assert read(tmp_path, value).answer.dependencies[0].logical_id == logical
    if kind == 'surface-artifact':
        for reference in ('surface:u1#reach_evidence', 'dive:' + B + '#conclusion', 'dive:' + B + '#evidence'):
            row['evidence'][0]['reference'] = reference
            assert read(tmp_path, value).answer.evidence[0].reference == reference


@pytest.mark.parametrize('field', ['dependencies', 'evidence', 'limitations', 'successor_questions'])
def test_array_exact_limit_and_nonarray_or_unique_oversize_refusal(tmp_path, field):
    value = wire()
    value['questions'][0][field] = None
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)
    maximum = 100 if field == 'successor_questions' else 1000
    def entries(count):
        if field == 'dependencies':
            return [answer()['dependencies'][0] | {'logical_id':f'f{i:04}'} for i in range(count)]
        if field == 'evidence':
            return [answer()['evidence'][0] | {'reference':f'finding:f{i:04}#root_cause'} for i in range(count)]
        if field == 'limitations':
            return [f'Limit {i:04}' for i in range(count)]
        return sorted([successor() | {'question':f'Question {i:04}'} for i in range(count)], key=encode)
    value = wire()
    if field == 'dependencies':
        value['questions'][0]['evidence'][0]['dependency_logical_id'] = 'f0000'
    value['questions'][0][field] = entries(maximum)
    assert len(getattr(read(tmp_path, value).answer, field)) == maximum
    value['questions'][0][field] = entries(maximum + 1)
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


@pytest.mark.parametrize('field', ['dependencies', 'evidence'])
def test_identity_normalizes_reference_sets_without_aliases(tmp_path, field):
    parsed = read(tmp_path)
    row = parsed.answer
    if field == 'dependencies':
        extra = dataclasses.replace(row.dependencies[0], logical_id='other')
    else:
        extra = dataclasses.replace(row.evidence[0], reference='finding:finding-1#root_cause')
    original = list(getattr(row, field))
    items = [*original, extra]
    first = dataclasses.replace(row, **{field:items})
    second = dataclasses.replace(row, **{field:list(reversed(items))})
    items.clear()
    assert len(getattr(first, field)) == 2
    assert observation(dataclasses.replace(parsed, answer=first)) == observation(dataclasses.replace(parsed, answer=second))


@pytest.mark.parametrize(('kind', 'logical', 'ref'), [('finding-artifact', 'finding-1', 'probe:' + B + '#stdout.bin'),
    ('probe-manifest', B, 'probe:' + C + '#stdout.bin'),
    ('hardware-capture', B, 'probe:' + B + '#stdout.bin')])
def test_dynamic_namespace_and_acquisition_identity_must_match(tmp_path, kind, logical, ref):
    value = wire()
    value['questions'][0]['evidence'] = [dict(dependency_kind=kind, dependency_logical_id=logical, reference=ref)]
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


def test_state_boolean_refutation_and_discovery_contract_boundaries(tmp_path):
    value = wire()
    row = value['questions'][0]
    row.update(outcome='refuted', resolution_effect=dict(target_subject='surface-unknown:u1', mode='boolean-claim',
        predicate='reachability', axis='reachability', value='refuted', capability_kind=None, link_key=None, transition_kind=None))
    claim = questions.ResolutionContract(questions.SubjectRef('surface-unknown', 'u1'), 'boolean-claim',
        'reachability', 'reachability', 'evidenced', (), False, None, None, None)
    results.validate_answer(read(tmp_path, value).answer, claim)
    row['resolution_effect'].update(mode='value-discovery', predicate='state-value', axis='authentication', value='admin')
    row['outcome'] = 'supported'
    discovery = dataclasses.replace(claim, mode='value-discovery', predicate='state-value', axis='authentication',
        expected_value=None, allowed_values=('pre-auth',))
    with pytest.raises(results.FirmwareDiveResultError): results.validate_answer(read(tmp_path, value).answer, discovery)


def test_public_helpers_reject_untyped_variants(tmp_path):
    parsed = read(tmp_path)
    for value in (None, wire(), parsed.answer):
        with pytest.raises(results.FirmwareDiveResultError): results.canonical_bytes(value)
    with pytest.raises(results.FirmwareDiveResultError): results.validate_answer(answer(), contract())
    with pytest.raises(results.FirmwareDiveResultError): results.validate_answer(parsed.answer, {})
    with pytest.raises(results.FirmwareDiveResultError):
        results.canonical_observation_id(image_id='x', candidate_snapshot_sha256=A, answer=results.EmptyAnswer(), evidence_rung=None)


@pytest.mark.parametrize('when', ['before-open', 'during-read', 'after-read'])
def test_result_replacement_or_rewrite_refuses_torn_snapshot(tmp_path, monkeypatch, when):
    path = tmp_path / 'r.json'
    path.write_bytes(encode(wire()))
    other = tmp_path / 'other.json'
    other.write_bytes(encode(wire() | {'image_id':'other'}))
    if when == 'before-open':
        original = os.open
        def opened(selector, flags, *args, **kwargs):
            other.replace(path)
            return original(selector, flags, *args, **kwargs)
        monkeypatch.setattr(results.os, 'open', opened)
    elif when == 'during-read':
        original = os.fstat
        calls = 0
        def checked(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                before = original(fd)
                data = path.read_bytes().replace(b'Observed', b'ObserXed')
                assert len(data) == before.st_size
                path.write_bytes(data)
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            return original(fd)
        monkeypatch.setattr(results.os, 'fstat', checked)
    else:
        original = os.lstat
        calls = 0
        def checked(selector):
            nonlocal calls
            calls += 1
            if calls == 2:
                other.replace(path)
            return original(selector)
        monkeypatch.setattr(results.os, 'lstat', checked)
    with pytest.raises(results.FirmwareDiveResultError): results.load(path)


def test_exact_bounds_for_prose_image_and_canonical_serialization(tmp_path, monkeypatch):
    value = wire()
    value['image_id'] = 'é' * 2048
    value['questions'][0]['conclusion'] = 'é' * 2048
    value['questions'][0]['limitations'] = [f'{i:04}' for i in range(1000)]
    parsed = read(tmp_path, value)
    canonical = encode(value)
    monkeypatch.setattr(results, 'MAX_RESULT_BYTES', len(canonical))
    assert results.canonical_bytes(parsed) == canonical
    assert read(tmp_path, value) == parsed


@pytest.mark.parametrize('scope', ['conclusion', 'sha256', 'value', 'reference'])
def test_nested_duplicate_keys_never_silently_override(tmp_path, scope):
    raw = encode(wire())
    needles = {'conclusion': b'"conclusion":', 'sha256': b'"sha256":', 'value': b'"value":', 'reference': b'"reference":'}
    raw = raw.replace(needles[scope], needles[scope] + b'null,' + needles[scope], 1)
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, raw=raw)


@pytest.mark.parametrize('field', ['subject_refs', 'axes'])
def test_successor_canonical_arrays_and_nested_contract_not_worker_authority(tmp_path, field):
    value = wire()
    proposed = successor()
    proposed[field] = ['z', 'a']
    value['questions'][0]['successor_questions'] = [proposed]
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


def test_result_and_observation_helpers_do_not_write(tmp_path, monkeypatch):
    parsed = read(tmp_path)
    before = {p.name:p.read_bytes() for p in tmp_path.iterdir()}
    # Real helpers receive an impossible writer; all file IO is the explicit load.
    original = os.open
    def readonly(path, flags, *args, **kwargs):
        assert flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC) == 0
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(results.os, 'open', readonly)
    assert results.load(tmp_path / 'result.json') == parsed
    assert observation(parsed)
    assert results.canonical_bytes(parsed)
    assert before == {p.name:p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.parametrize(('namespace', 'kind'), [('probe', 'probe-manifest'), ('capture', 'hardware-capture')])
@pytest.mark.parametrize('component', ['a' * 240, 'é' * 120])
def test_dynamic_reference_framing_preserves_exact_4096_byte_path_budget(tmp_path, namespace, kind, component):
    value = wire()
    row = value['questions'][0]
    row['dependencies'] = [dict(kind=kind, logical_id=B, relative_path='artifacts/acquisition/manifest.json', sha256=C, byte_count=0)]
    path = '/'.join([component] * 17)
    assert len(path.encode()) == 4096
    ref = f'{namespace}:{B}#{path}'
    row['evidence'] = [dict(dependency_kind=kind, dependency_logical_id=B, reference=ref)]
    assert read(tmp_path, value).answer.evidence[0].reference == ref
    row['evidence'][0]['reference'] += 'a'
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


@pytest.mark.parametrize(('namespace', 'kind'), [('probe', 'probe-manifest'), ('capture', 'hardware-capture')])
@pytest.mark.parametrize(('path', 'valid'), [('/'.join(['a'] * 32), True), ('/'.join(['a'] * 33), False),
    ('a' * 255, True), ('a' * 256, False)])
def test_dynamic_reference_component_limits(tmp_path, namespace, kind, path, valid):
    value = wire()
    row = value['questions'][0]
    row['dependencies'] = [dict(kind=kind, logical_id=B, relative_path='artifacts/acquisition/manifest.json', sha256=C, byte_count=0)]
    row['evidence'] = [dict(dependency_kind=kind, dependency_logical_id=B, reference=f'{namespace}:{B}#{path}')]
    if valid:
        assert read(tmp_path, value).answer.evidence[0].reference.endswith(path)
    else:
        with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


def test_evidence_total_8192_byte_bound_does_not_relax_prose(tmp_path):
    value = wire()
    reference = 'finding:f#' + 'a' * 8182
    assert len(reference.encode()) == 8192
    value['questions'][0]['evidence'][0]['reference'] = reference
    assert read(tmp_path, value).answer.evidence[0].reference == reference
    value['questions'][0]['evidence'][0]['reference'] += 'a'
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)
    value['questions'][0]['evidence'][0]['reference'] = reference
    value['questions'][0]['conclusion'] = 'a' * 4097
    with pytest.raises(results.FirmwareDiveResultError): read(tmp_path, value)


@pytest.mark.parametrize('damage',['successor-subject','successor-contract','mixed-dependency-order'])
def test_direct_constructor_failures_use_result_exception(tmp_path,damage):
    parsed = read(tmp_path)
    with pytest.raises(results.FirmwareDiveResultError):
        if damage.startswith('successor'):
            value = successor()
            value['subject_refs' if damage == 'successor-subject' else 'resolution_contract'] = None
            results.SuccessorQuestion(**value)
        else:
            dependency = dataclasses.replace(parsed.answer.dependencies[0], kind=1)
            dataclasses.replace(parsed.answer,dependencies=(parsed.answer.dependencies[0],dependency))


@pytest.mark.parametrize('constructor,args,kwargs',[
    (results.DependencyRef,(),{}),
    (results.EvidenceRef,(),{'dependency_kind':'finding-artifact'}),
    (results.ResolutionEffect,(),{'unexpected':True}),
    (results.QuestionAnswer,(),{}),
    (results.SuccessorQuestion,(),{}),
    (results.DiveResult,(),{}),
    (results.EmptyAnswer,(1,),{}),
])
def test_malformed_public_constructor_calls_share_result_exception(constructor,args,kwargs):
    with pytest.raises(results.FirmwareDiveResultError): constructor(*args,**kwargs)
