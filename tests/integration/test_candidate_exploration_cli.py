"""D8 run CLI and pre-bootstrap assembly admission, no RTL processes."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


@pytest.fixture
def cli():
    path = Path(__file__).resolve().parents[2] / 'scripts/run_ibex_pulp_online.py'
    spec = importlib.util.spec_from_file_location('_candidate_cli', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('enabled', (False, True))
def test_run_cli_forwards_only_explicit_candidate_opt_in(cli, tmp_path, monkeypatch, enabled):
    runtime = Mock(return_value=SimpleNamespace(executor=object()))
    monkeypatch.setattr(cli, 'make_ibex_pulp_online_runtime', runtime)
    monkeypatch.setattr(cli, 'run_scenario_rfuzz_live', lambda **kwargs: SimpleNamespace(
        output_dir=tmp_path / 'new', tests=1, statuses={}, elapsed_seconds=1,
        effective_search_seconds=1))
    args = ['run', '--client-binary', '/tmp/client', '--cache-dir', str(tmp_path / 'cache'),
            '--output', str(tmp_path / 'new')]
    if enabled:
        args += ['--candidate-exploration', '--candidate-exploration-max-cases', '12']
    assert cli.main(args) == 0
    kwargs = runtime.call_args.kwargs
    if enabled:
        assert kwargs['candidate_exploration'] is True
        assert kwargs['candidate_exploration_max_cases'] == 12
    else:
        assert 'candidate_exploration' not in kwargs
        assert 'candidate_exploration_max_cases' not in kwargs


@pytest.mark.parametrize('bound', ('0', '65537'))
def test_cli_candidate_capacity_refused_before_runtime(cli, tmp_path, monkeypatch, bound):
    runtime = Mock(side_effect=AssertionError('must not construct a runtime'))
    monkeypatch.setattr(cli, 'make_ibex_pulp_online_runtime', runtime)
    assert cli.main(['run', '--client-binary', '/tmp/client', '--cache-dir', str(tmp_path),
        '--output', str(tmp_path / 'new'), '--candidate-exploration',
        '--candidate-exploration-max-cases', bound]) == 1
    runtime.assert_not_called()
    assert not (tmp_path / 'new').exists()


@pytest.mark.parametrize('kwargs', ({'candidate_exploration': 1},
    {'candidate_exploration_max_cases': True}, {'candidate_exploration_max_cases': 0}))
def test_ibex_candidate_types_checked_before_render(tmp_path, kwargs):
    from myfuzz.integration import ibex_pulp_online as online
    with patch.object(online, 'make_ibex_pulp_dual_source_factory') as render:
        with pytest.raises(ValueError, match='candidate'):
            online.make_ibex_pulp_online_runtime(cache_dir=tmp_path, run_id='candidate', **kwargs)
        render.assert_not_called()


def test_actual_legacy_ibex_assembly_refuses_candidate_before_begin(tmp_path):
    from myfuzz.integration import ibex_pulp_online as online
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_online_decoder,
        make_ibex_pulp_dual_source_stream_bootstrap)
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    actual = make_ibex_pulp_dual_source_factory(tmp_path / 'cache')()
    with patch.object(online.ScenarioSession, 'begin',
                      side_effect=AssertionError('must reject before RTL begin')) as begin:
        with pytest.raises(ValueError, match='candidate.*(observation|export|physical)'):
            online.make_pulp_dual_source_online_runtime(bootstrap=bootstrap, decoder=decoder,
                factory=lambda: actual, run_id='unsupported', candidate_exploration=True,
                evidence_dir=tmp_path / 'evidence')
        begin.assert_not_called()
    assert not (tmp_path / 'evidence').exists()
    assert all(local._process is None for local in actual.sessions.values())


@pytest.mark.parametrize('fail_final', (False, True))
def test_enabled_assembly_preflights_then_builds_fresh_after_bootstrap(monkeypatch, fail_final):
    from myfuzz.integration import ibex_pulp_online as online
    monkeypatch.delenv('MYFUZZ_INITIAL_RAM_DATA', raising=False)
    order = []
    runner = SimpleNamespace(sessions={'cpu': SimpleNamespace(waiting_instruction_address=4)})
    session = Mock(runner=runner)
    session.begin.side_effect = lambda: order.append('begin')
    bootstrap = SimpleNamespace(template=object(), instruction_start=4, instruction_end=8,
                                instruction_count=1)
    decoder = SimpleNamespace(graph=object(), runtime_contract=object(), runtime_paths=(),
                              ownership=object())
    executors = []
    def construct(**kwargs):
        order.append('executor')
        assert kwargs['candidate_exploration'] is True
        assert kwargs['candidate_exploration_max_cases'] == 12
        if len(executors) == 1 and fail_final:
            raise RuntimeError('post-bootstrap observation drift')
        executor = object()
        executors.append(executor)
        return executor
    with patch.object(online, 'ScenarioSession', return_value=session), \
            patch.object(online, 'ScenarioRfuzzExecutor', side_effect=construct):
        kwargs = dict(bootstrap=bootstrap, decoder=decoder, factory=lambda: runner,
                      run_id='supported-assembly', candidate_exploration=True,
                      candidate_exploration_max_cases=12)
        if fail_final:
            with pytest.raises(RuntimeError, match='post-bootstrap'):
                online.make_pulp_dual_source_online_runtime(**kwargs)
            session.finish.assert_called_once()
        else:
            runtime = online.make_pulp_dual_source_online_runtime(**kwargs)
            assert runtime.executor is executors[1]
            assert runtime.executor is not executors[0]
            session.finish.assert_not_called()
    assert order == ['executor', 'begin', 'executor']


def test_actual_native_v2_assembly_admits_slices_and_irq_aliases_before_begin(tmp_path, monkeypatch):
    from myfuzz.integration import ibex_pulp_online as online
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_online_decoder,
        make_ibex_pulp_dual_source_stream_bootstrap)
    monkeypatch.delenv('MYFUZZ_INITIAL_RAM_DATA', raising=False)
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    actual = make_ibex_pulp_dual_source_factory(tmp_path / 'cache', physical_observations=True)()
    class ReachedBegin(RuntimeError):
        pass
    with patch.object(online.ScenarioSession, 'begin', side_effect=ReachedBegin('preflight passed')) as begin:
        with pytest.raises(ReachedBegin):
            online.make_pulp_dual_source_online_runtime(bootstrap=bootstrap, decoder=decoder,
                factory=lambda: actual, run_id='native-preflight', candidate_exploration=True,
                evidence_dir=tmp_path / 'evidence')
        begin.assert_called_once()
    assert all(local._process is None for local in actual.sessions.values())
    assert not (tmp_path / 'evidence').exists()


@pytest.mark.parametrize('enabled', (False, True))
def test_ibex_builder_selects_native_observations_only_for_candidate_opt_in(tmp_path, enabled):
    from myfuzz.integration import ibex_pulp_online as online
    factory = Mock(return_value=object())
    session = Mock()
    session.initial_ram_data_state.return_value = None
    executor = Mock(closed_loop_energy=False, path_switch=False)
    assembly = Mock(return_value=SimpleNamespace(session=session, executor=executor))
    with patch.object(online, 'make_ibex_pulp_dual_source_factory', factory), \
            patch.object(online, 'make_pulp_dual_source_online_runtime', assembly):
        online.make_ibex_pulp_online_runtime(cache_dir=tmp_path, run_id='native-selector',
                                            candidate_exploration=enabled)
    if enabled:
        assert factory.call_args.kwargs.get('physical_observations') is True
        declaration = executor.set_online_assembly_configuration.call_args.args[0]
        assert declaration['initial_ram_data_source'] == 'default'
        assert declaration['run_id'] == 'native-selector'
    else:
        assert 'physical_observations' not in factory.call_args.kwargs
        executor.set_online_assembly_configuration.assert_not_called()


@pytest.mark.parametrize('component', ('cpu', 'gpio_b'))
def test_native_mapping_profile_drift_is_refused_before_candidate_commands(tmp_path, monkeypatch, component):
    from dataclasses import replace
    from myfuzz.integration import ibex_pulp_online as online
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_online_decoder,
        make_ibex_pulp_dual_source_stream_bootstrap)
    monkeypatch.delenv('MYFUZZ_INITIAL_RAM_DATA', raising=False)
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    actual = make_ibex_pulp_dual_source_factory(tmp_path / 'cache', physical_observations=True)()
    executors = []
    constructor = online.ScenarioRfuzzExecutor
    def capture(**kwargs):
        executor = constructor(**kwargs)
        executors.append(executor)
        return executor
    class ReachedBegin(RuntimeError):
        pass
    with patch.object(online, 'ScenarioRfuzzExecutor', side_effect=capture), \
            patch.object(online.ScenarioSession, 'begin', side_effect=ReachedBegin):
        with pytest.raises(ReachedBegin):
            online.make_pulp_dual_source_online_runtime(bootstrap=bootstrap, decoder=decoder,
                factory=lambda: actual, run_id='native-drift', candidate_exploration=True)
    executor = executors[0]
    local = actual.sessions[component]
    artifact = local.artifact
    profile = artifact.plan.profile
    changed = (replace(profile, cpu=replace(profile.cpu, irq_entry_role='different'))
               if component == 'cpu' else replace(profile, port_actions=tuple(
                   a for a in profile.port_actions if a.port != 'interrupt')))
    local.artifact = replace(artifact, plan=replace(artifact.plan, profile=changed))
    state = executor.candidate_exploration_state()
    try:
        for _ in range(2):
            with pytest.raises(ValueError, match='candidate.*observation'):
                executor._candidate_exploration.prepare_case()
        assert executor.candidate_exploration_state() == state
        assert all(s._process is None for s in actual.sessions.values())
    finally:
        local.artifact = artifact
    executor._candidate_exploration.prepare_case()


@pytest.mark.parametrize('matches', (False, True))
def test_candidate_replay_cli_uses_trusted_selector_and_reports_scope(cli, tmp_path, monkeypatch, matches):
    trace = SimpleNamespace(events=(object(),), semantic_sha256='trace')
    comparison = SimpleNamespace(matches=matches, first_difference=None,
        difference_context=None, actual_trace=trace)
    replay = Mock(return_value=SimpleNamespace(matches=matches, comparison=comparison,
        verification_scope=('candidate_case_scoring', 'online_source_selection')))
    monkeypatch.setattr(cli, 'replay_ibex_pulp_candidate_files', replay, raising=False)
    assert cli.main(['replay-candidates', '--cache-dir', str(tmp_path/'cache'),
                     '--run-dir', str(tmp_path/'saved')]) == (0 if matches else 2)
    replay.assert_called_once_with(cache_dir=tmp_path/'cache', output_dir=tmp_path/'saved')
