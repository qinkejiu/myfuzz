"""Trusted candidate assembly declaration and CLI selection, no RTL."""
from copy import deepcopy
import hashlib
import json
import pytest


def declaration():
    return dict(schema_version='ibex_pulp_candidate_assembly.v1', run_id='trusted',
        feedback_interval=16, max_warmup_rounds=1024, candidate_exploration_max_cases=8,
        cpu_retirement=False, gpio_consumption=False, native_irq_receipts=False,
        source_actions=True, memory_commit_receipts=False, persistent_memory_prerequisites=False,
        ip_cross_case=False, result_slot_byte_store=False, closed_loop_energy=False,
        path_switch=False, initial_ram_data=False, initial_ram_data_source='default',
        initial_ram_record_hex='0000000000000000')


def validate(doc):
    from myfuzz.integration.ibex_pulp_candidate_replay import validate_candidate_assembly
    return validate_candidate_assembly(doc)


def test_closed_assembly_roundtrip_is_detached():
    value = declaration()
    result = validate(value)
    assert result == value and result is not value
    result['run_id'] = 'changed'
    assert value['run_id'] == 'trusted'


@pytest.mark.parametrize('key,value', (
    ('cpu_retirement', 1), ('closed_loop_energy', 'true'), ('path_switch', None),
    ('feedback_interval', True), ('feedback_interval', 0), ('max_warmup_rounds', 0),
    ('candidate_exploration_max_cases', True), ('candidate_exploration_max_cases', 65537),
    ('initial_ram_data_source', 'saved_callback'), ('initial_ram_record_hex', 'AB'),
    ('initial_ram_record_hex', ''), ('initial_ram_record_hex', '0'), ('run_id', ''),
    ('schema_version', 'unknown'), ('initial_ram_data', True),
    ('native_irq_receipts', True), ('persistent_memory_prerequisites', True),
))
def test_malformed_or_incoherent_assembly_is_refused(key, value):
    doc = declaration()
    doc[key] = value
    with pytest.raises(ValueError, match='assembly'):
        validate(doc)


@pytest.mark.parametrize('mutation', ('extra', 'missing'))
def test_assembly_is_a_closed_field_set(mutation):
    doc = declaration()
    if mutation == 'extra': doc['factory_module'] = 'saved.code'
    else: doc.pop('source_actions')
    with pytest.raises(ValueError, match='assembly'):
        validate(doc)


def test_declared_initial_ram_and_authenticated_observation_modes_are_supported():
    doc = declaration()
    doc.update(cpu_retirement=True, native_irq_receipts=True, gpio_consumption=True,
        memory_commit_receipts=True, persistent_memory_prerequisites=True,
        ip_cross_case=True, result_slot_byte_store=True, closed_loop_energy=True,
        path_switch=True, initial_ram_data=True, initial_ram_data_source='environment')
    assert validate(doc) == doc


@pytest.mark.parametrize('source', ('constructor', 'environment'))
@pytest.mark.parametrize('enabled', (False, True))
def test_explicit_initial_ram_origin_is_preserved(source, enabled):
    doc = declaration()
    doc.update(initial_ram_data_source=source, initial_ram_data=enabled)
    assert validate(doc) == doc


def test_executor_assembly_snapshot_is_detached_and_can_only_be_set_once():
    from tests.integration.test_scenario_candidate_exploration import configured
    executor = configured(enabled=True)
    assert executor.online_assembly_configuration() is None
    doc = declaration()
    executor.set_online_assembly_configuration(doc)
    doc['run_id'] = 'mutated'
    snapshot = executor.online_assembly_configuration()
    assert snapshot['run_id'] == 'trusted'
    snapshot['run_id'] = 'also-mutated'
    assert executor.online_assembly_configuration()['run_id'] == 'trusted'
    with pytest.raises(ValueError, match='assembly'):
        executor.set_online_assembly_configuration(declaration())


@pytest.mark.parametrize('enabled', (False, True))
def test_executor_assembly_requires_candidate_before_cases(enabled):
    from tests.integration.test_scenario_candidate_exploration import configured
    executor = configured(enabled=enabled)
    if enabled:
        from myfuzz.integration.scenario_rfuzz import InputBatch
        executor.execute_batch(InputBatch(0, 8, ((bytes(8),),)))
    with pytest.raises(ValueError, match='assembly'):
        executor.set_online_assembly_configuration(declaration())


@pytest.fixture
def assembly_bundle(tmp_path, monkeypatch):
    from myfuzz.integration import ibex_pulp_online as online
    from myfuzz.scenario.ibex_pulp_dual_source import CPU_PROFILE
    from myfuzz.scenario.ibex_pulp_online_checker import IbexPulpOnlineChecker
    from myfuzz.scenario.session_runtime import _checker_identity
    for name in ('_saved_cpu_retirement_mode', '_saved_gpio_consumption_mode',
                 '_saved_pin8_native_irq_mode', '_saved_memory_commit_mode'):
        monkeypatch.setattr(online, name, lambda *args: False)
    monkeypatch.setattr(online, '_saved_persistent_memory_mode', lambda *args: None)
    sessions = {}
    for component in ('cpu', 'gpio_a', 'gpio_b'):
        artifact = dict(kind='obi_cpu' if component == 'cpu' else 'apb_gpio',
            plan=dict(profile_path=CPU_PROFILE, instance_id=component,
                request_schema_version='local_harness.v2',
                tuning=dict(raw_tick_stream=[dict(sampling='pre_post')])),
            base_event_schema_version='ip_base_event.v1',
            raw_observation_schema_version='ip_raw_observation.v1',
            native_physical_observation_contract=dict(schema_version='native_physical_observation.v1'))
        sessions[component] = dict(identity=dict(runtime_artifact=artifact))
    sessions['cpu']['identity']['cpu_physical_tick_stream'] = dict(
        schema_version='cpu_physical_tick_stream.v1', capacity=256, sampling='pre_post')
    manifest = dict(runner=dict(sessions=sessions),
        checker=_checker_identity(IbexPulpOnlineChecker(), configuration_only=True))
    def save():
        raw = json.dumps(manifest).encode()
        (tmp_path / 'online_session_manifest.json').write_bytes(raw)
        config = dict(run_id='trusted', feedback_interval=16, closed_loop_energy=False,
            path_switch=False, online_assembly=declaration(),
            candidate_exploration=dict(schema_version='online_candidate_exploration_config.v1',
                enabled=True))
        return dict(run_config=config,
            artifacts={'online_session_manifest.json': hashlib.sha256(raw).hexdigest()})
    return tmp_path, manifest, save


def test_verified_assembly_selects_known_local_modes(assembly_bundle):
    from myfuzz.integration.ibex_pulp_candidate_replay import _verified_assembly
    output, _, save = assembly_bundle
    assert _verified_assembly(output, save()) == declaration()


@pytest.mark.parametrize('mutation', ('cpu', 'checker', 'sessions', 'raw', 'stream', 'config', 'missing'))
def test_selector_refuses_unknown_or_incoherent_assembly_before_construction(assembly_bundle, mutation):
    from myfuzz.integration.ibex_pulp_candidate_replay import _verified_assembly
    output, manifest, save = assembly_bundle
    cpu = manifest['runner']['sessions']['cpu']['identity']
    if mutation == 'cpu': cpu['runtime_artifact']['plan']['profile_path'] = 'saved/arbitrary.json'
    if mutation == 'checker': manifest['checker']['config']['result_address'] += 1
    if mutation == 'sessions': manifest['runner']['sessions']['extra'] = deepcopy(cpu)
    if mutation == 'raw': cpu['runtime_artifact']['plan']['request_schema_version'] = 'local_harness.v1'
    if mutation == 'stream': cpu.pop('cpu_physical_tick_stream')
    identity = save()
    if mutation == 'config': identity['run_config']['feedback_interval'] = True
    if mutation == 'missing': identity['run_config'].pop('online_assembly')
    with pytest.raises(ValueError, match='assembly'):
        _verified_assembly(output, identity)


@pytest.mark.parametrize('cleanup_failure', (False, True))
def test_trusted_fresh_builder_uses_saved_resolution_without_reading_environment(monkeypatch, tmp_path, cleanup_failure):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from myfuzz.integration import ibex_pulp_online as online
    from myfuzz.integration.ibex_pulp_candidate_replay import _fresh_executor
    from myfuzz.scenario import ibex_pulp_dual_source as source
    monkeypatch.setenv('MYFUZZ_INITIAL_RAM_DATA', 'invalid')
    monkeypatch.setenv('MYFUZZ_IP_CROSS_CASE', 'invalid')
    decoder = SimpleNamespace(runtime_contract=SimpleNamespace(identity_sha256='contract'))
    monkeypatch.setattr(source, 'make_ibex_pulp_dual_source_stream_bootstrap', Mock(return_value=object()))
    decode = Mock(return_value=decoder)
    monkeypatch.setattr(source, 'make_ibex_pulp_dual_source_online_decoder', decode)
    monkeypatch.setattr(source, 'make_ibex_pulp_dual_source_factory', Mock(return_value=object()))
    executor = Mock()
    session = Mock()
    assembly = Mock(return_value=SimpleNamespace(executor=executor, session=session))
    monkeypatch.setattr(online, 'make_pulp_dual_source_online_runtime', assembly)
    if cleanup_failure:
        executor.set_online_assembly_configuration.side_effect = ValueError('snapshot rejected')
        session.finish.side_effect = RuntimeError('cleanup failed')
        with pytest.raises(ValueError, match='snapshot rejected') as raised:
            _fresh_executor(tmp_path, declaration())
        assert 'cleanup failed' in raised.value.__notes__[0]
    else:
        assert _fresh_executor(tmp_path, declaration()) is executor
    assert assembly.call_args.kwargs['initial_ram_data_resolution'] == (False, 'default')
    assert assembly.call_args.kwargs['closed_loop_energy'] is False
    assert assembly.call_args.kwargs['path_switch'] is False
    assert decode.call_args.kwargs['ip_cross_case'] is False
    executor.set_online_assembly_configuration.assert_called_once_with(declaration())


def test_live_builder_preserves_snapshot_rejection_when_cleanup_fails(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from myfuzz.integration import ibex_pulp_online as online
    executor = Mock(closed_loop_energy=False, path_switch=False)
    executor.set_online_assembly_configuration.side_effect = ValueError('snapshot rejected')
    session = Mock()
    session.initial_ram_data_state.return_value = None
    session.finish.side_effect = RuntimeError('cleanup failed')
    monkeypatch.setattr(online, 'make_ibex_pulp_dual_source_factory', Mock())
    monkeypatch.setattr(online, 'make_pulp_dual_source_online_runtime',
        Mock(return_value=SimpleNamespace(executor=executor, session=session)))
    monkeypatch.delenv('MYFUZZ_IP_CROSS_CASE', raising=False)
    with pytest.raises(ValueError, match='snapshot rejected') as raised:
        online.make_ibex_pulp_online_runtime(cache_dir=tmp_path, run_id='trusted', candidate_exploration=True)
    assert 'cleanup failed' in raised.value.__notes__[0]


@pytest.mark.parametrize('consumption', (False, True))
def test_actual_gpio_native_v2_identity_regenerates_without_rtl(tmp_path, consumption):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    from myfuzz.scenario.contracts import _verify_generated_session
    runner = make_ibex_pulp_dual_source_factory(tmp_path/'cache',
        physical_observations=True, gpio_consumption=consumption)()
    identity = json.loads(json.dumps(runner.sessions['gpio_a'].identity_document()))
    _verify_generated_session(identity)
    forged = deepcopy(identity)
    forged['runtime_artifact']['plan']['tuning']['raw_tick_stream'] = []
    with pytest.raises(ValueError, match='identity mismatch|request-required'):
        _verify_generated_session(forged)
    assert all(local._process is None for local in runner.sessions.values())
