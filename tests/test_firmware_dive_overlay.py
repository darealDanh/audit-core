"""Stage 4g consumes exact current structured dive authority, never private prose."""
import copy
import dataclasses
import json
import pathlib

import pytest

from audit_core import firmware_chain, firmware_chain_results as chains, firmware_dive as dive
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_gate import complete, populate, check as dive_check, overlay
from tests.test_firmware_dive_prepare import prepare as dive_prepare, rows, files, canonical
from tests.test_hunt_gate import state


def settled(case, tmp_path, outcome='supported'):
    complete(case)
    dive_prepare(case)
    populate(case, tmp_path, outcome)
    dive_check(case)
    return overlay(case)


def regenerate(case):
    summary = firmware_chain.prepare(*case[:3], image_id='target')
    case[3]['worklist_sha256'] = summary.worklist_sha256
    return json.loads(pathlib.Path(summary.worklist_path).read_bytes())


def test_empty_overlay_is_explicit_and_frozen_in_worklist(graph_case):
    frozen = graph_case[4]
    assert frozen['dive_overlay'] == {'schema_version': 1, 'observations': []}


def test_completed_overlay_regeneration_freezes_only_structured_projection(graph_case, tmp_path):
    accepted = settled(graph_case, tmp_path)
    before = {name: rows(graph_case[0], 'cba_firmware_dive_' + name)
              for name in ('runs', 'questions', 'receipts', 'observations', 'dependencies')}
    frozen = regenerate(graph_case)
    # SubjectRef's public wire uses stable kind:identity strings.
    from audit_core import firmware_dive_questions as q
    expected = json.loads(q._bytes(accepted))
    assert frozen['dive_overlay'] == expected
    assert len(expected['observations']) == 1
    assert 'conclusion' not in expected['observations'][0]
    assert 'artifact_path' not in expected['observations'][0]
    assert all(rows(graph_case[0], 'cba_firmware_dive_' + name) == value for name, value in before.items())
    assert firmware_chain.prepare(*graph_case[:3], image_id='target').worklist_sha256 == graph_case[3]['worklist_sha256']


@pytest.mark.parametrize('outcome', ['supported', 'refuted'])
def test_settled_blocker_cannot_be_recreated_unchanged(graph_case, tmp_path, outcome):
    settled(graph_case, tmp_path, outcome)
    regenerate(graph_case)
    with pytest.raises(firmware_chain.FirmwareChainError):
        validate_current(graph_case)


@pytest.mark.parametrize('artifact', ['journal', 'packet', 'result', 'graph'])
def test_corrupt_retained_history_refuses_prepare_without_repair(graph_case, tmp_path, artifact):
    settled(graph_case, tmp_path)
    con, run = graph_case[:2]
    owner, = rows(con, 'cba_firmware_dive_runs')
    relative = {'journal': owner['journal_path'], 'graph': owner['chain_graph_path'],
        'packet': rows(con, 'cba_firmware_dive_questions')[0]['packet_path'],
        'result': rows(con, 'cba_firmware_dive_receipts')[0]['result_path']}[artifact]
    (run / relative).write_bytes(b'{}')
    before, artifacts = state(con), files(run)
    with pytest.raises(firmware_chain.FirmwareChainError):
        firmware_chain.prepare(*graph_case[:3], image_id='target')
    assert state(con) == before and files(run) == artifacts


def observed(case, tmp_path, *, predicate='state-value', target='finding', value='pre-auth', axis='authentication', outcome='supported'):
    from tests.test_firmware_chain_import import record
    from tests.test_firmware_chain_gate import check
    from tests.test_firmware_dive_prepare import manifest
    from tests.test_firmware_dive_questions import entry
    from tests.test_firmware_dive_import import build, save, record as dive_record
    from audit_core import firmware_dive_questions as q
    record(case); check(case)
    graph = firmware_chain.verified_graph_snapshot(*case[:3], image_id='target')
    edge = graph.edges[0]
    subjects = {'finding': 'finding:' + case[3]['chains'][0]['member_ids'][0],
        'edge': 'edge:' + q.edge_fingerprint(graph, edge),
        'chain': 'chain:' + q.chain_fingerprint(graph, graph.chains[0])}
    subject = subjects[target]
    question = entry(graph, subject)
    if target == 'finding':
        question['subject_refs'] = sorted([subject, subjects['chain']])
    contract = question['resolution_contract']
    if predicate in ('state-value', 'reachability'):
        from audit_core import db
        vocabulary = {'authentication': db.FIRMWARE_CHAIN_AUTH_STATES,
            'lifecycle': db.FIRMWARE_CHAIN_LIFECYCLE_STATES, 'posture': db.FIRMWARE_CHAIN_POSTURE_STATES,
            'reachability': ('evidenced', 'refuted')}[axis]
        question['axes'] = [axis]
        contract.update(predicate=predicate, axis=axis, allowed_values=sorted(vocabulary))
        if outcome == 'refuted':
            contract.update(mode='boolean-claim', expected_value=next(v for v in vocabulary if v != value), allowed_values=[])
    else:
        contract.update(mode='boolean-claim', predicate=predicate, axis=None, expected_value=True,
            allowed_values=[], capability_kind=edge.capability_kind, link_key=edge.link_key,
            transition_kind=edge.transition_kind if predicate == 'transition-observed' else None)
    dive_prepare(case, questions_path=manifest(tmp_path, [question]))
    row, = rows(case[0], 'cba_firmware_dive_questions')
    item = build(case, row, tmp_path, outcome=outcome)
    item[2]['questions'][0]['resolution_effect']['value'] = value
    save(item); dive_record(item); dive_check(case)
    accepted = overlay(case)
    observation, = accepted.observations
    regenerate(case)
    return observation


def validate_current(case):
    return chains.validate(case[0], case[1], chains._parse(case[3]), root=case[2])


@pytest.mark.parametrize('fragment', ['conclusion', 'evidence'])
@pytest.mark.parametrize('target', ['finding', 'chain'])
def test_supported_state_matches_exact_initial_subject(graph_case, tmp_path, target, fragment):
    observation = observed(graph_case, tmp_path, target=target)
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + observation.observation_id + '#' + fragment)
    result = validate_current(graph_case)
    assert result.chains[0].pre_auth == 'yes' and result.chains[0].evidence_rung == 'static-chained'
    assert result.chains[0].confidence == min(f['confidence'] for f in graph_case[4]['findings'][:3])


@pytest.mark.parametrize('predicate', ['edge-validity', 'capability-present', 'transition-observed'])
@pytest.mark.parametrize('position', ['producer_evidence_refs', 'consumer_evidence_refs', 'supplemental_evidence_refs'])
def test_supported_semantic_effect_authorizes_only_exact_edge(graph_case, tmp_path, predicate, position):
    observation = observed(graph_case, tmp_path, predicate=predicate, target='edge', value=True)
    edge = graph_case[3]['chains'][0]['edges'][0]
    edge[position].append('dive:' + observation.observation_id + '#evidence')
    checked = validate_current(graph_case)
    assert len(checked.edges) == 2
    # The same legitimate reference must not migrate to the adjacent edge.
    graph_case[3]['chains'][0]['edges'][1][position].append('dive:' + observation.observation_id + '#evidence')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


@pytest.mark.parametrize('damage', ['value', 'owner', 'foreign', 'fragment', 'digest', 'refuted'])
def test_state_references_do_not_authorize_unrelated_or_false_claims(graph_case, tmp_path, damage):
    observation = observed(graph_case, tmp_path, outcome='refuted' if damage == 'refuted' else 'supported')
    chain = graph_case[3]['chains'][0]
    reference = 'dive:' + observation.observation_id + '#evidence'
    if damage == 'value': chain['initial_state']['authentication'] = 'admin'
    elif damage == 'owner':
        chain['edges'][0]['consumer_evidence_refs'].append(reference)
    elif damage == 'foreign': reference = 'dive:' + '0' * 64 + '#evidence'
    elif damage == 'fragment': reference = reference.replace('#evidence', '#body')
    elif damage == 'digest': reference = reference.replace(observation.observation_id, 'g' * 64)
    if damage != 'owner': chain['initial_evidence_refs'].append(reference)
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


def test_refuted_edge_cannot_recur_even_without_citation(graph_case, tmp_path):
    observed(graph_case, tmp_path, predicate='edge-validity', target='edge', value=False, outcome='refuted')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)
    graph_case[3]['chains'][0]['edges'][0]['link_key'] = '/etc/other-resource'
    assert validate_current(graph_case).edges


def test_refuted_state_is_constraint_not_positive_evidence(graph_case, tmp_path):
    observed(graph_case, tmp_path, value='admin', outcome='refuted')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)
    graph_case[3]['chains'][0]['initial_state']['authentication'] = 'admin'
    assert validate_current(graph_case).chains[0].pre_auth == 'no'


def test_dive_history_requires_explicit_live_root(graph_case, tmp_path):
    observed(graph_case, tmp_path)
    with pytest.raises(firmware_chain.FirmwareChainError):
        chains.validate(graph_case[0], graph_case[1], chains._parse(graph_case[3]))
    assert validate_current(graph_case).chains
    graph_case[2].rename(graph_case[2].with_name('unavailable-root'))
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


def test_overlay_source_drift_refuses_import_and_completion(graph_case, tmp_path):
    observation = observed(graph_case, tmp_path)
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + observation.observation_id + '#evidence')
    path = graph_case[1] / 'regenerated.json'
    path.write_text(json.dumps(graph_case[3]))
    chains.record(graph_case[0], graph_case[1], path, root=graph_case[2])
    firmware_chain.check(*graph_case[:3], image_id='target')
    (graph_case[2] / 'c').write_bytes(b'changed')
    before = state(graph_case[0])
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)
    with pytest.raises(firmware_chain.FirmwareChainError): firmware_chain.check(*graph_case[:3], image_id='target')
    assert state(graph_case[0]) == before


def test_prepare_rechecks_overlay_after_install(graph_case, tmp_path, monkeypatch):
    from audit_core import surface
    complete(graph_case); dive_prepare(graph_case); populate(graph_case, tmp_path, 'supported')
    before = state(graph_case[0])
    original = surface.atomic_install
    def race(destination, contents):
        result = original(destination, contents)
        if 'worklist.json' in contents:
            # A separate completed dive changes authority after the first read.
            dive_check(graph_case)
        return result
    monkeypatch.setattr(surface, 'atomic_install', race)
    with pytest.raises(firmware_chain.FirmwareChainError):
        firmware_chain.prepare(*graph_case[:3], image_id='target')
    assert rows(graph_case[0], 'cba_firmware_dive_runs')[0]['status'] == 'complete'
    assert not rows(graph_case[0], 'cba_firmware_chain_runs')
    assert not graph_case[0].in_transaction


def test_semantic_fingerprints_exclude_only_valid_dive_references(graph_case):
    from audit_core import firmware_dive_questions as q
    from tests.test_firmware_chain_import import record
    from tests.test_firmware_chain_gate import check
    record(graph_case); check(graph_case)
    graph = firmware_chain.verified_graph_snapshot(*graph_case[:3], image_id='target')
    chain, edge = graph.chains[0], graph.edges[0]
    original_edge, original_chain = q.edge_fingerprint(graph, edge), q.chain_fingerprint(graph, chain)
    changed_chain = dataclasses.replace(chain, initial_evidence_refs=chain.initial_evidence_refs + ('dive:' + '1'*64 + '#conclusion',))
    changed_edge = dataclasses.replace(edge, supplemental_evidence_refs=edge.supplemental_evidence_refs + ('dive:' + '2'*64 + '#evidence',))
    changed = dataclasses.replace(graph, chains=(changed_chain,), edges=(changed_edge, *graph.edges[1:]))
    assert q.edge_fingerprint(changed, changed_edge) == original_edge
    assert q.chain_fingerprint(changed, changed_chain) == original_chain
    malformed = dataclasses.replace(changed_edge, supplemental_evidence_refs=changed_edge.supplemental_evidence_refs + ('dive:bad#evidence',))
    assert q.edge_fingerprint(changed, malformed) != original_edge


def test_chain_cli_forwards_optional_root_for_existing_record_route(graph_case, monkeypatch, capsys):
    import audit
    from types import SimpleNamespace
    received = []
    def record(con, run, path, **kwargs):
        received.append(kwargs)
        return SimpleNamespace(image_id='target', finding_count=0, disposition_count=0,
            blocker_count=0, chain_count=0, edge_count=0, complete_chains=0, blocked_chains=0, artifact_path='result.json')
    monkeypatch.setattr(chains, 'record', record)
    assert audit.main(['chain', '--run', str(graph_case[1]), '--record', 'result.json', '--root', str(graph_case[2])]) == 0
    assert received == [{'replace': False, 'root': graph_case[2]}]
    capsys.readouterr()


def test_supported_result_state_uses_supplemental_locus(graph_case, tmp_path):
    edge = graph_case[3]['chains'][0]['edges'][0]
    edge['result_state']['authentication'] = 'admin'
    observation = observed(graph_case, tmp_path, target='edge', value='admin')
    edge['supplemental_evidence_refs'].append('dive:' + observation.observation_id + '#evidence')
    assert validate_current(graph_case).edges
    edge['producer_evidence_refs'].append('dive:' + observation.observation_id + '#evidence')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


@pytest.mark.parametrize('value', ['evidenced', 'refuted'])
def test_reachability_effect_has_no_blanket_positive_authority(graph_case, tmp_path, value):
    observation = observed(graph_case, tmp_path, predicate='reachability', axis='reachability', value=value)
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + observation.observation_id + '#evidence')
    if value == 'evidenced': assert validate_current(graph_case).chains
    else:
        with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


def test_completed_overlay_graph_can_own_next_dive_generation(graph_case, tmp_path):
    observation = observed(graph_case, tmp_path, predicate='edge-validity', target='edge', value=True)
    graph_case[3]['chains'][0]['edges'][0]['supplemental_evidence_refs'].append('dive:' + observation.observation_id + '#evidence')
    path = graph_case[1] / 'regenerated.json'; path.write_text(json.dumps(graph_case[3]))
    chains.record(graph_case[0], graph_case[1], path, root=graph_case[2])
    firmware_chain.check(*graph_case[:3], image_id='target')
    dive_prepare(graph_case, questions_path=tmp_path / "analyst.json", retry=[observation.question_id])
    from tests.test_firmware_dive_import import build, record
    question = max(rows(graph_case[0], 'cba_firmware_dive_questions'), key=lambda r: r['attempt_ordinal'])
    record(build(graph_case, question, tmp_path))
    assert dive_check(graph_case).complete
    assert overlay(graph_case).observations
    assert firmware_chain.check(*graph_case[:3], image_id='target').complete


@pytest.mark.parametrize('failure', ['install', 'commit', 'installed-bytes'])
def test_overlay_prepare_failures_preserve_history_and_sibling(graph_case, tmp_path, monkeypatch, failure):
    from audit_core import surface
    from tests.test_firmware_chain_prepare import empty_review
    settled(graph_case, tmp_path)
    con, run, root = graph_case[:3]
    sibling = tmp_path / 'sibling-root'; empty_review(con, run, sibling, 'target-other')
    firmware_chain.prepare(con, run, sibling, image_id='target-other')
    before = state(con)
    original = surface.atomic_install
    def install(destination, contents):
        if failure == 'install': raise OSError('injected installation failure')
        result = original(destination, contents)
        if failure == 'installed-bytes': (destination / 'worklist.json').write_bytes(b'{}')
        return result
    monkeypatch.setattr(surface, 'atomic_install', install)
    class FailedCommit:
        def __getattr__(self, name): return getattr(con, name)
        def commit(self): raise __import__('sqlite3').OperationalError('injected commit failure')
    with pytest.raises(firmware_chain.FirmwareChainError):
        firmware_chain.prepare(FailedCommit() if failure == 'commit' else con, run, root, image_id='target')
    assert state(con) == before and not con.in_transaction


def test_conclusive_unknown_settles_exact_blocker_and_can_support_linked_state(graph_case, tmp_path):
    from tests.test_firmware_dive_import import build, record, save
    complete(graph_case); generation = dive_prepare(graph_case)
    selected = next(r for r in rows(graph_case[0], 'cba_firmware_dive_questions')
        if r['origin'] == 'surface-unknown' and 'overlap' in r['subject_refs'])
    for n, row in enumerate(rows(graph_case[0], 'cba_firmware_dive_questions')):
        directory = tmp_path / ('unknown-' + str(n)); directory.mkdir()
        item = build(graph_case, row, directory,
            outcome='supported' if row['question_id'] == selected['question_id'] else 'inconclusive')
        if row['question_id'] == selected['question_id']:
            item[2]['questions'][0]['resolution_effect']['value'] = 'pre-auth'; save(item)
        record(item)
    dive_check(graph_case); observation, = overlay(graph_case).observations
    regenerate(graph_case)
    with pytest.raises(firmware_chain.FirmwareChainError, match='settled'):
        validate_current(graph_case)
    graph_case[3]['chains'][0]['edges'][1]['existing_unknowns'] = []
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + observation.observation_id + '#conclusion')
    checked = validate_current(graph_case)
    assert checked.chains[0].completeness == 'blocked'  # The unrelated boot blocker remains.
    assert checked.chains[0].evidence_rung == 'static-chained'


def test_keyed_overlay_retained_graph_never_refreshes_current_overlay(graph_case, tmp_path, monkeypatch):
    observation = observed(graph_case, tmp_path, predicate='edge-validity', target='edge', value=True)
    graph_case[3]['chains'][0]['edges'][0]['supplemental_evidence_refs'].append('dive:' + observation.observation_id + '#evidence')
    path = graph_case[1] / 'regenerated.json'; path.write_text(json.dumps(graph_case[3]))
    chains.record(graph_case[0], graph_case[1], path, root=graph_case[2])
    firmware_chain.check(*graph_case[:3], image_id='target')
    generation = dive_prepare(graph_case, questions_path=tmp_path / 'analyst.json', retry=[observation.question_id])
    firmware_chain.invalidate(graph_case[0], 'target', commit=True)
    def forbidden(*args, **kwargs): pytest.fail('historical graph refreshed current overlay')
    monkeypatch.setattr(dive, 'current_overlay', forbidden)
    result = firmware_chain.verified_retained_graph_snapshot(*graph_case[:3], image_id='target', dive_generation=generation.dive_generation)
    assert result.edges[0].supplemental_evidence_refs == tuple(sorted(graph_case[3]['chains'][0]['edges'][0]['supplemental_evidence_refs']))


@pytest.mark.parametrize('damage', ['version', 'extra', 'outcome', 'effect', 'subjects', 'duplicate', 'dependency', 'evidence'])
def test_frozen_overlay_strict_schema_rejects_corruption(damage):
    row = dict(observation_id='1' * 64, question_id='2' * 64, subject_refs=['finding:f'], outcome='supported',
        resolution_effect=dict(target_subject='finding:f', mode='value-discovery', predicate='state-value',
            axis='authentication', value='pre-auth', capability_kind=None, link_key=None, transition_kind=None),
        evidence_rung='static-resolved', dependency_refs=['3' * 64], evidence_refs=['4' * 64])
    frozen = dict(schema_version=1, observations=[row])
    if damage == 'version': frozen['schema_version'] = True
    elif damage == 'extra': frozen['private'] = 'forbidden'
    elif damage == 'outcome': row['outcome'] = 'inconclusive'
    elif damage == 'effect': row['resolution_effect'] = None
    elif damage == 'subjects': row['subject_refs'] = ['finding:other']
    elif damage == 'duplicate': frozen['observations'] *= 2
    elif damage == 'dependency': row['dependency_refs'] = []
    elif damage == 'evidence': row['evidence_refs'] = ['G' * 64]
    with pytest.raises(firmware_chain.FirmwareChainError): firmware_chain._checked_overlay(frozen)


def test_overlay_record_rechecks_history_under_write_lock(graph_case, tmp_path):
    observed(graph_case, tmp_path)
    con, run, root = graph_case[:3]
    path = run / 'overlay-result.json'; path.write_text(json.dumps(graph_case[3]))
    before = state(con)
    class Connection:
        def __getattr__(self, name): return getattr(con, name)
        def execute(self, sql, *args):
            cursor = con.execute(sql, *args)
            if sql == 'BEGIN IMMEDIATE':
                con.execute("UPDATE cba_firmware_dive_observations SET conclusion='raced'")
            return cursor
    with pytest.raises(firmware_chain.FirmwareChainError): chains.record(Connection(), run, path, root=root)
    assert state(con) == before and not con.in_transaction


@pytest.mark.parametrize('failure', ['install', 'commit', 'installed-bytes'])
def test_overlay_record_failures_preserve_history_and_sibling(graph_case, tmp_path, monkeypatch, failure):
    from audit_core import surface
    from tests.test_firmware_chain_prepare import empty_review
    observed(graph_case, tmp_path)
    con, run, root = graph_case[:3]
    sibling = tmp_path / 'sibling-root'; empty_review(con, run, sibling, 'target-other')
    firmware_chain.prepare(con, run, sibling, image_id='target-other')
    before = state(con)
    path = run / 'regenerated.json'; path.write_text(json.dumps(graph_case[3]))
    original = surface.atomic_install
    def install(destination, contents):
        if failure == 'install': raise OSError('injected installation failure')
        result = original(destination, contents)
        if failure == 'installed-bytes': (destination / 'result.json').write_bytes(b'{}')
        return result
    monkeypatch.setattr(surface, 'atomic_install', install)
    class FailedCommit:
        def __getattr__(self, name): return getattr(con, name)
        def commit(self): raise __import__('sqlite3').OperationalError('injected commit failure')
    with pytest.raises(firmware_chain.FirmwareChainError):
        chains.record(FailedCommit() if failure == 'commit' else con, run, path, root=root)
    assert state(con) == before and not con.in_transaction


def test_blocker_effect_has_no_graph_evidence_slot(graph_case):
    frozen = copy.deepcopy(graph_case[4])
    frozen['dive_overlay']['observations'] = [dict(observation_id='1' * 64, question_id='2' * 64,
        subject_refs=['chain-blocker:old-question'], outcome='supported', evidence_rung='static-resolved',
        dependency_refs=['3' * 64], evidence_refs=['4' * 64], resolution_effect=dict(
            target_subject='chain-blocker:old-question', mode='value-discovery', predicate='state-value',
            axis='authentication', value='pre-auth', capability_kind=None, link_key=None, transition_kind=None))]
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + '1' * 64 + '#conclusion')
    with pytest.raises(firmware_chain.FirmwareChainError, match='exact current subject'):
        chains._validate_graph(chains._parse(graph_case[3]), frozen)


def test_rootless_import_scopes_history_to_selected_image(graph_case, tmp_path):
    from tests.test_firmware_chain_prepare import empty_review
    observed(graph_case, tmp_path)
    con, run = graph_case[:2]
    root = tmp_path / 'other-root'; empty_review(con, run, root, 'other-image')
    summary = firmware_chain.prepare(con, run, root, image_id='other-image')
    value = dict(schema_version=1, image_id='other-image', candidate_snapshot_sha256=summary.candidate_snapshot_sha256,
        worklist_sha256=summary.worklist_sha256, blockers=[], dispositions=[], chains=[])
    root.rename(root.with_name('unavailable-other-root'))
    path = run / 'other-empty.json'; path.write_text(json.dumps(value))
    assert chains.record(con, run, path).chain_count == 0


def test_foreign_image_observation_never_supplies_evidence(graph_case, tmp_path):
    from audit_core import db
    observed(graph_case, tmp_path)
    foreign = rows(graph_case[0], 'cba_firmware_dive_observations')[0] | dict(
        image_id='foreign-image', dive_generation='0' * 64, observation_id='5' * 64)
    db.put(graph_case[0], 'cba_firmware_dive_observations', foreign)
    regenerate(graph_case)
    assert validate_current(graph_case).chains
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + '5' * 64 + '#evidence')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


def test_stale_observation_cannot_be_cited_after_real_review_replacement(graph_case, tmp_path):
    from audit_core import firmware_fpcheck, firmware_fpcheck_results
    observation = observed(graph_case, tmp_path)
    con, run, root = graph_case[:3]
    path = run / 'richer-review.json'; review = json.loads(path.read_bytes())
    for decision in review['decisions']:
        if decision['true_positive'] is not None:
            decision['true_positive']['root_cause'] = 'Revised exact static evidence'
    path.write_text(json.dumps(review)); firmware_fpcheck_results.record(con, run, path, replace=True)
    firmware_fpcheck.check(con, run, root, image_id='target')
    assert regenerate(graph_case)['dive_overlay'] == {'schema_version': 1, 'observations': []}
    graph_case[3]['chains'][0]['initial_evidence_refs'].append('dive:' + observation.observation_id + '#conclusion')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)


def test_contested_observation_cannot_be_cited_after_regeneration(graph_case, tmp_path):
    from tests.test_firmware_dive_import import build, record, save
    first = observed(graph_case, tmp_path, predicate='edge-validity', target='edge', value=True)
    path = graph_case[1] / 'regenerated.json'; path.write_text(json.dumps(graph_case[3]))
    chains.record(graph_case[0], graph_case[1], path, root=graph_case[2])
    firmware_chain.check(*graph_case[:3], image_id='target')
    generation = dive_prepare(graph_case, questions_path=tmp_path / 'analyst.json', retry=[first.question_id])
    question = next(r for r in rows(graph_case[0], 'cba_firmware_dive_questions') if r['dive_generation'] == generation.dive_generation)
    item = build(graph_case, question, tmp_path, outcome='refuted')
    item[2]['questions'][0]['resolution_effect']['value'] = False; save(item); record(item); dive_check(graph_case)
    assert regenerate(graph_case)['dive_overlay'] == {'schema_version': 1, 'observations': []}
    graph_case[3]['chains'][0]['edges'][0]['producer_evidence_refs'].append('dive:' + first.observation_id + '#evidence')
    with pytest.raises(firmware_chain.FirmwareChainError): validate_current(graph_case)
