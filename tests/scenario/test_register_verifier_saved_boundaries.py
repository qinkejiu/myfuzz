"""Saved verifier documents are closed comparisons, never installed authority."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from tests.scenario.test_ordinary_apb_access_session import session
from tests.scenario.test_register_program_verifier import read_result_factory
from tests.scenario.test_register_program_runtime import request


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


@pytest.fixture(scope='module')
def sealed(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    result = session(read_result_factory(actual_factory))
    result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result); verifier = RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', operation='register_read', value=None,
        result_address=0x10004, allow_side_effect=False))
    state = verifier.report()
    assert len(state['current_certificates']) == 1
    snapshots = {alias: asdict(verifier.snapshot(alias)) for alias in runtime.sidecars}
    wrapper = dict(schema_version='register_program_verifier_session.v1',
        configuration=verifier.configuration(), state=state, verified_capabilities=snapshots)
    return json.loads(canonical(wrapper)), json.loads(canonical(runtime.configuration()))


def validate(document, configuration):
    from myfuzz.scenario import register_program_verifier as module
    return module.validate_register_program_verifier_session_document(document, configuration=configuration)


def rehash_certificate(document):
    """Keep the forged saved claim internally hash/projection-consistent."""
    changed = document['state']['historical_certificates'][0]
    old = changed['evidence_id']
    digest = hashlib.sha256(canonical({k:v for k,v in changed.items() if k!='evidence_id'}).encode()).hexdigest()
    changed['evidence_id'] = digest
    for row in document['state']['current_certificates']:
        if row['evidence_id'] == old:
            row.clear(); row.update(deepcopy(changed))
    for snapshot in document['verified_capabilities'].values():
        for operation in snapshot['operations']:
            operation['evidence_refs'] = [ref.replace(old, digest) for ref in operation['evidence_refs']]


def test_actual_nonempty_private_evidence_passes_closed_saved_validator(sealed):
    document, configuration = sealed
    assert validate(document, configuration) == document
    assert document['state']['historical_certificates'][0]['proof_scope'] == 'observed_cpu_register_readback_consistency'


@pytest.mark.parametrize('where', ['wrapper', 'configuration', 'state', 'certificate', 'association', 'access', 'snapshot'])
def test_unknown_nested_fields_even_with_rehashed_certificate_refuse(sealed, where):
    original, configuration = sealed; document = deepcopy(original)
    certificate = document['state']['historical_certificates'][0]
    objects = {'wrapper': document, 'configuration': document['configuration'],
        'state': document['state'], 'certificate': certificate,
        'association': certificate['association'], 'access': certificate['observed_accesses'][0],
        'snapshot': document['verified_capabilities']['gpio_a']}
    objects[where]['caller_annotation'] = 'not-authority'
    if where in ('certificate', 'association', 'access'): rehash_certificate(document)
    with pytest.raises(ValueError): validate(document, configuration)


@pytest.mark.parametrize('grant', ['grants_storage', 'grants_version_dependency', 'grants_prerequisites', 'grants_functional'])
def test_self_consistent_rehashed_certificate_cannot_add_grant(sealed, grant):
    original, configuration = sealed; document = deepcopy(original)
    document['state']['historical_certificates'][0][grant] = True
    rehash_certificate(document)
    with pytest.raises(ValueError): validate(document, configuration)


def test_certificate_hash_mismatch_refuses(sealed):
    original, configuration = sealed; document = deepcopy(original)
    document['state']['historical_certificates'][0]['evidence_id'] = '0'*64
    with pytest.raises(ValueError): validate(document, configuration)


def test_snapshot_unknown_reference_refuses(sealed):
    original, configuration = sealed; document = deepcopy(original)
    document['verified_capabilities']['gpio_a']['operations'][0]['evidence_refs'] = ['ordinary_register_semantic:'+'0'*64]
    with pytest.raises(ValueError): validate(document, configuration)


def test_foreign_alias_cannot_borrow_actual_snapshot(sealed):
    original, configuration = sealed; document = deepcopy(original)
    document['verified_capabilities']['gpio_b'] = document['verified_capabilities'].pop('gpio_a')
    with pytest.raises(ValueError): validate(document, configuration)


def test_complete_lifecycle_can_have_unverified_rule_gaps(sealed):
    original, configuration = sealed; document = deepcopy(original)
    document['state']['gaps'].append({'case_id':'later-unverified-case','reason':'missing_later_actual_readback'})
    assert validate(document, configuration) == document


def test_incomplete_history_is_legal_with_empty_current_projection(sealed):
    original, configuration = sealed; document = deepcopy(original)
    state = document['state']; state['status'] = 'incomplete'; state['reason'] = 'ordinary_observation_incomplete'
    state['gaps'].append({'case_id':None,'reason':state['reason']})
    state['current_certificates'] = []
    document['verified_capabilities']['gpio_a']['operations'] = []
    assert validate(document, configuration) == document


def test_incomplete_cannot_keep_current_snapshot_or_certificates(sealed):
    original, configuration = sealed; document = deepcopy(original)
    state = document['state']; state['status'] = 'incomplete'; state['reason'] = 'ordinary_observation_incomplete'
    state['gaps'].append({'case_id':None,'reason':state['reason']})
    with pytest.raises(ValueError): validate(document, configuration)


@pytest.fixture(scope='module')
def shared_sealed(actual_factory):
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    from tests.local_harness.test_ordinary_apb_access_receipts import software_transport
    def factory():
        runner = actual_factory(); begin = runner.begin_test; iterations = [0]
        def start(case_id):
            begin(case_id); software_transport(runner.sessions['gpio_a'], rdata=1)
        runner.begin_test = start
        def step(order):
            cpu = runner.sessions['cpu']; target = runner.sessions['gpio_a']
            window = next(w for w in cpu.router.windows if w.target is target)
            writing = iterations[0] == 0; iterations[0] += 1
            cpu._pending_data = None
            cpu._serve('data', int(writing), window.base+12, 1 if writing else 0, 15)
            runner._ordinary_apb_access_evidence.preflight_access(cpu.router, target)
            cpu.router.drain_one('gpio_a')
            runner._append_external_events('cpu', len(runner._events))
            runner._drain_ordinary_apb_events(1)
            runner.local_ticks['gpio_a'] = target.local_ticks
            runner._drain_tick_samples(1)
            runner._finalize_ordinary_apb_access(cpu.router, target)
            if not writing:
                cpu._pending_data = None
                cpu._serve('data', 1, 0x10004, 1, 15)
                runner._append_external_events('cpu', len(runner._events))
        runner.step_batch = step
        return runner
    result = session(factory); result.configure_ordinary_apb_access_evidence(max_records=4)
    runtime = adapter(result); verifier = RegisterProgramVerifier(runtime, max_records=4)
    result.begin()
    runtime.submit(request(target_instance='gpio_a', allow_side_effect=False))
    cpu = result.runner.sessions['cpu']
    # Model the next real fetch after consuming the preceding source response.
    cpu._pending_instr = None
    cpu._serve('instr', 0, 0x11010, 0, 15)
    runtime.submit(request(case_id='read-case', action_id='read-action',
        target_instance='gpio_a', operation='register_read', value=None,
        result_address=0x10004, allow_side_effect=False))
    state = verifier.report()
    assert len(state['current_certificates']) == 2
    writer = next(c for c in state['current_certificates'] if c['operation']=='register_write')
    reader = next(c for c in state['current_certificates'] if c['operation']=='register_read')
    assert writer['result']['readback_association'] == reader['association']
    doc = json.loads(canonical(dict(schema_version='register_program_verifier_session.v1',
        configuration=verifier.configuration(), state=state,
        verified_capabilities={a:asdict(verifier.snapshot(a)) for a in runtime.sidecars})))
    return doc, json.loads(canonical(runtime.configuration()))


def test_actual_later_requested_read_can_share_refs_with_prior_write_certificate(shared_sealed):
    doc, configuration = shared_sealed
    assert validate(doc, configuration) == doc


def test_result_commit_reference_cannot_relabel_existing_protocol_event(sealed):
    original, configuration = sealed; document = deepcopy(original)
    cert = document['state']['historical_certificates'][0]
    association = cert['association']
    candidates = [ref for ref in association['base_event_refs']
        if ref > association['delivery_event_id']]
    assert candidates  # Positive fixture has actual post-delivery protocol projections.
    cert['result']['event_id'] = candidates[-1]
    rehash_certificate(document)
    with pytest.raises(ValueError): validate(document, configuration)


def test_field_width_must_agree_with_full_declared_bus_mask(sealed):
    original, configuration = sealed; document = deepcopy(original)
    cert = document['state']['historical_certificates'][0]
    assert cert['operation_plan']['field_width'] == 32
    assert cert['operation_plan']['bus_mask'] == 0xffffffff
    cert['operation_plan']['field_width'] = 1
    rehash_certificate(document)
    with pytest.raises(ValueError): validate(document, configuration)


def test_conflicting_access_id_cannot_name_two_distinct_actual_seals(shared_sealed):
    original, configuration = shared_sealed; document = deepcopy(original)
    writer = next(c for c in document['state']['historical_certificates'] if c['operation']=='register_write')
    reader = next(c for c in document['state']['historical_certificates'] if c['operation']=='register_read')
    changed = writer['observed_accesses'][0]
    assert changed['association']['access_id'] != reader['association']['access_id']
    access_id = reader['association']['access_id']
    changed['association']['access_id'] = access_id
    changed['receipt']['access_id'] = access_id
    changed['delivery']['target_access_id'] = access_id
    changed['delivery']['target_access_receipt']['access_id'] = access_id
    writer['association']['access_id'] = access_id
    rehash_certificate(document)
    with pytest.raises(ValueError): validate(document, configuration)


@pytest.mark.parametrize('which,value', [('register','PAD.OUT'), ('field','value.extra'),
    ('register','1PADOUT'), ('field','value-name')])
def test_register_field_identifiers_match_existing_capability_scope_grammar(sealed, which, value):
    original, configuration = sealed; document = deepcopy(original)
    cert = document['state']['historical_certificates'][0]
    cert[which] = value
    cert['operation_plan'][which] = value
    operation = document['verified_capabilities']['gpio_a']['operations'][0]
    operation['scope'] = cert['register']+'.'+cert['field']
    rehash_certificate(document)
    with pytest.raises(ValueError): validate(document, configuration)
