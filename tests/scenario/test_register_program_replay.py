"""Actual objects with software command stubs; no RTL replay claim."""
import hashlib
import json
import pytest

from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session
from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
from tests.scenario.test_register_program_runtime import request
from tests.composition.test_pulp_gpio_test_capability import SIDECAR


@pytest.fixture(scope='module')
def actual_factory(tmp_path_factory):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    factory = make_ibex_pulp_dual_source_factory(tmp_path_factory.mktemp('render-only-register-replay'),
        memory_commit_receipts=True, physical_observations=True,
        persistent_memory_runtime_contract_sha256='a'*64)
    def software():
        runner = factory()
        def begin(case_id):
            runner._status = 'running'
            cpu = runner.sessions['cpu']
            cpu._case_id = 'stream'
            cpu._serve('instr',0,0x11000,0,15)
        runner.begin_test = begin
        runner.step_batch = lambda order: None
        runner.finalize = lambda: None
        return runner
    return software


def adapter(session):
    result = RegisterProgramRuntime(session,cpu_component='cpu',sidecars={'gpio_a':SIDECAR},advance_rounds=1)
    # The runtime constructor will install this automatically once its parallel
    # implementation lands; the explicit Session API is independently tested.
    if getattr(session,'_register_program_runtime',None) is None:
        session.attach_register_program_runtime(result)
    return result


def recorded(actual_factory, *, row=None, failure=None):
    session = ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',
        ('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime = adapter(session)
    if failure == 'registration':
        def reserve(action): raise RuntimeError('reservation interrupted')
        session.prerequisite_gate._slot_policy._reserve = reserve
    elif failure == 'step':
        def step(order): raise ValueError('step interrupted')
        session.runner.step_batch = step
    session.begin()
    if failure is None:
        runtime.submit(row or request(target_instance='gpio_a'))
    else:
        with pytest.raises((RuntimeError,ValueError)):
            runtime.submit(row or request(target_instance='gpio_a'))
    trace = session.finish()
    return session,session.encode_plan(),trace


def test_attached_plan_is_closed_schema16_and_replay_uses_original_request(actual_factory):
    session,plan,trace = recorded(actual_factory)
    doc = json.loads(plan)
    assert doc['schema_version'] == 16
    assert doc['register_programs']['case_manifests'][0]['request']['value'] == 1
    assert doc['register_programs']['terminal_attempt'] is None
    assert 'register_program_configuration' in session.manifest_document
    assert session.manifest_document['register_program_source_files']
    def trusted_factory():
        runner = actual_factory()
        def forbidden(*args): raise AssertionError('saved bytes cannot authorize register replay')
        runner.persistent_memory_prerequisite_gate.register_replay_case = forbidden
        return runner
    comparison = replay_online_session(plan,trusted_factory,trace,register_runtime_factory=adapter)
    assert comparison.matches


def test_register_replay_requires_trusted_factory_before_runner_creation(actual_factory):
    _,plan,trace = recorded(actual_factory)
    def forbidden(): raise AssertionError('must refuse before runner creation')
    with pytest.raises(ValueError,match='register'):
        replay_online_session(plan,forbidden,trace)


@pytest.mark.parametrize('mutation',['bytes','value','manifest_count','extra','bool_schema'])
def test_tampered_rehashed_plan_is_never_byte_authority(actual_factory,mutation):
    from dataclasses import replace
    _,plan,trace = recorded(actual_factory)
    doc = json.loads(plan)
    if mutation == 'bytes': doc['cases'][0]['source']['data_hex']='13000000'*4
    elif mutation == 'value': doc['register_programs']['case_manifests'][0]['request']['value']=2
    elif mutation == 'manifest_count': doc['register_programs']['case_manifests']=[]
    elif mutation == 'extra': doc['register_programs']['authority']=True
    else: doc['schema_version']=True
    changed = json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
    reference = replace(trace,genome_sha256=hashlib.sha256(changed).hexdigest())
    with pytest.raises(ValueError):
        replay_online_session(changed,actual_factory,reference,register_runtime_factory=adapter)


def test_case_and_action_names_use_independent_namespaces(actual_factory):
    _,plan,trace = recorded(actual_factory,row=request(target_instance='gpio_a',case_id='same',action_id='same'))
    assert replay_online_session(plan,actual_factory,trace,register_runtime_factory=adapter).matches


def test_unicode_case_and_action_identity_replays_with_exact_compiler_hash(actual_factory):
    _,plan,trace = recorded(actual_factory,row=request(target_instance='gpio_a',case_id='寄存器例',action_id='输出写入'))
    assert replay_online_session(plan,actual_factory,trace,register_runtime_factory=adapter).matches


@pytest.mark.parametrize('failure',['registration','step'])
def test_schema17_preserves_real_nullable_or_recorded_boundary(actual_factory,failure):
    session,plan,trace = recorded(actual_factory,failure=failure)
    doc = json.loads(plan)
    assert doc['schema_version']==17
    terminal = doc['register_programs']['terminal_attempt']
    assert terminal['case_index'] == (None if failure=='registration' else 0)
    assert len(doc['cases']) == (0 if failure=='registration' else 1)
    def fresh():
        runner = actual_factory()
        if failure=='registration':
            def reserve(action): raise RuntimeError('reservation interrupted')
            runner.persistent_memory_prerequisite_gate._slot_policy._reserve = reserve
        else:
            def step(order): raise ValueError('step interrupted')
            runner.step_batch = step
        return runner
    assert replay_online_session(plan,fresh,trace,register_runtime_factory=adapter).matches
    comparison = replay_online_session(plan,actual_factory,trace,register_runtime_factory=adapter)
    assert not comparison.matches
    assert comparison.difference_context['register_program_state_match'] is False


def test_unappended_terminal_attempt_counts_toward_plan_and_state_capacity(actual_factory):
    from copy import deepcopy
    from myfuzz.scenario.session_runtime import validate_register_program_plan,validate_register_program_state
    session,plan,trace = recorded(actual_factory)
    doc = json.loads(plan)
    config = doc['register_programs']['configuration']
    config['max_records']=1
    manifest = doc['register_programs']['case_manifests'][0]
    manifest['configuration']['max_records']=1
    terminal = dict(manifest=deepcopy(manifest),status='uncertain',phase='registration',case_index=None,error_type='RuntimeError')
    doc['schema_version']=17
    doc['terminal_failure']=None
    doc['register_programs']['terminal_attempt']=terminal
    with pytest.raises(ValueError,match='capacity'): validate_register_program_plan(doc)
    state = dict(schema_version='register_program_runtime_state.v1',configuration=config,uncertain=True,
        records=[dict(manifest=manifest,status='submitted',phase='submitted',case_index=0),terminal])
    with pytest.raises(ValueError,match='capacity'): validate_register_program_state(state,doc['register_programs'])


@pytest.mark.parametrize('nested',['context','program','access_context','operation_plan'])
def test_unknown_nested_fields_rejected_before_factory_even_with_rehashed_program(actual_factory,nested):
    from dataclasses import replace
    _,plan,trace = recorded(actual_factory)
    doc = json.loads(plan)
    manifest = doc['register_programs']['case_manifests'][0]
    if nested=='context': manifest['context']['saved_authority']=True
    elif nested=='program': manifest['program']['saved_authority']=True
    else: manifest['program'][nested]['saved_authority']=True
    program = manifest['program']
    canonical = json.dumps({k:v for k,v in program.items() if k!='identity_sha256'},sort_keys=True,separators=(',',':')).encode()
    program['identity_sha256']=hashlib.sha256(canonical).hexdigest()
    changed = json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
    reference = replace(trace,genome_sha256=hashlib.sha256(changed).hexdigest())
    def forbidden(): raise AssertionError('nested schema must fail before factory')
    with pytest.raises(ValueError): replay_online_session(changed,forbidden,reference,register_runtime_factory=adapter)


def test_register_manifest_pins_memory_distribution_and_actual_projection_sources(actual_factory,monkeypatch):
    from pathlib import Path
    import myfuzz.scenario.session_runtime as runtime_module
    session,plan,trace = recorded(actual_factory)
    files = {row['path']:row['sha256'] for row in session.manifest_document['register_program_source_files']}
    required = {'src/myfuzz/scenario/memory_authority_distribution.py',
        'src/myfuzz/scenario/ip_base_events.py','src/myfuzz/scenario/ip_protocol_events.py',
        'src/myfuzz/scenario/ip_protocol_checker.py'}
    assert required <= set(files)
    target = runtime_module._ROOT/'src/myfuzz/scenario/memory_authority_distribution.py'
    original = Path.read_bytes
    def changed(path): return original(path)+(b'\n# changed identity\n' if path==target else b'')
    monkeypatch.setattr(Path,'read_bytes',changed)
    with pytest.raises(ValueError,match='manifest identity'):
        replay_online_session(plan,actual_factory,trace,register_runtime_factory=adapter)


def test_self_consistent_extra_instruction_word_rejected_before_factory(actual_factory):
    from dataclasses import replace
    from myfuzz.scenario.source_actions import SourceAction
    _,plan,trace = recorded(actual_factory)
    doc = json.loads(plan)
    manifest = doc['register_programs']['case_manifests'][0]
    program = manifest['program']
    program['source']['data_hex'] += '13000000'
    program['fragment_sha256']=hashlib.sha256(bytes.fromhex(program['source']['data_hex'])).hexdigest()
    program['identity_sha256']=hashlib.sha256(json.dumps({k:v for k,v in program.items() if k!='identity_sha256'},
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    doc['cases'][0]['source']['data_hex']=program['source']['data_hex']
    for key in ('source_action','admitted_action'):
        original = SourceAction.from_document(manifest[key])
        manifest[key]=replace(original,payload={**original.payload,'words_hex':program['source']['data_hex']},action_sha256='').document()
    declaration = doc['prerequisite_admissions'][0]
    declaration['source_action']=manifest['source_action']
    declaration['admitted_action']=manifest['admitted_action']
    changed = json.dumps(doc,sort_keys=True,separators=(',',':')).encode()
    reference = replace(trace,genome_sha256=hashlib.sha256(changed).hexdigest())
    def forbidden(): raise AssertionError('source length must fail before factory')
    with pytest.raises(ValueError): replay_online_session(changed,forbidden,reference,register_runtime_factory=adapter)


def test_fresh_canonical_plan_hash_must_match_even_when_events_match(actual_factory):
    from dataclasses import replace
    _,plan,trace = recorded(actual_factory)
    changed = json.dumps(json.loads(plan),indent=2).encode()
    reference = replace(trace,genome_sha256=hashlib.sha256(changed).hexdigest())
    comparison = replay_online_session(changed,actual_factory,reference,register_runtime_factory=adapter)
    assert not comparison.matches
