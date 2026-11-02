"""F5-only mode retains the real GPIO/CPU path and fixed CPU support."""
import pytest
from unittest.mock import patch
from contextlib import ExitStack
from myfuzz.scenario.ibex_pulp_dual_source import (
    dual_source_wiring, make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_stream_bootstrap,
)
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
from myfuzz.scenario.runner import Binding
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.integration.ibex_pulp_online import make_pulp_dual_source_online_runtime


def test_f5_only_wiring_and_decoder_keep_fixed_cpu_support(tmp_path):
    wiring = dual_source_wiring(gpio_consumption=True, f5_only=True)
    irq = Binding('gpio_b', 'irq', 'cpu', 'irq', 1)
    assert wiring.bindings == (irq,)
    assert wiring.irq_pulse_widths == ((irq, 4),)
    decoder = make_ibex_pulp_dual_source_online_decoder(f5_only=True)
    assert len(decoder.sources) == 1
    assert decoder.sources[0].source_id == 'gpio_b.external_pin8'
    assert decoder.ownership.mutation_source('gpio_b', 'gpio_in', 8, 1,
                                             direction='IP_TO_CPU_TO_IP') == 'external_b.pin8'
    case = decoder.decode(bytes.fromhex('0000000100000000'))
    assert case.source.component == 'gpio_b' and case.source.bit_offset == 8
    assert len(case.support_instructions) == 1
    assert case.support_instructions[0].component == 'cpu'
    assert len(case.support_instructions[0].data) == 16
    restored = OnlineCaseDecoder.from_document(decoder.document())
    assert restored.decode(bytes.fromhex('0000000100000000')) == case
    factory = make_ibex_pulp_dual_source_factory(tmp_path, gpio_consumption=True,
                                                  source_actions=False, f5_only=True)
    runner = factory()
    assert runner.bindings == (irq,)
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    session = ScenarioSession(bootstrap.template, runner)
    session.declare_instruction_slots('cpu', bootstrap.instruction_start, bootstrap.instruction_count)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths, source_ownership=decoder.ownership)
    assert session.runtime_path_ids


def test_fixed_support_cannot_be_assigned_to_a_non_cpu_component():
    document = make_ibex_pulp_dual_source_online_decoder(f5_only=True).document()
    document['support_component'] = 'gpio_a'
    with pytest.raises(ValueError, match='fixed support component'):
        OnlineCaseDecoder.from_document(document)


@pytest.mark.parametrize('phase', ['begin_post_start', 'warmup'])
def test_start_or_warmup_failure_finalizes_the_started_runner(tmp_path, phase):
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(f5_only=True)
    runner = make_ibex_pulp_dual_source_factory(tmp_path, gpio_consumption=True,
        source_actions=False, f5_only=True)()
    def begin(session):
        session.runner._status = 'running'
        if phase == 'begin_post_start':
            raise RuntimeError('post-start failure')
        session._begun = True
    with ExitStack() as stack:
        stack.enter_context(patch.object(ScenarioSession, 'begin', begin))
        stack.enter_context(patch.object(ScenarioSession, 'advance_initial',
                                         side_effect=RuntimeError('warmup failure')))
        finalize = stack.enter_context(patch.object(runner, 'finalize', wraps=runner.finalize))
        closes = [stack.enter_context(patch.object(session, 'end_case'))
                  for session in runner.sessions.values()]
        with pytest.raises(RuntimeError, match='failure'):
            make_pulp_dual_source_online_runtime(bootstrap=bootstrap, decoder=decoder,
                factory=lambda: runner, run_id='f5-cleanup', source_actions=False)
        finalize.assert_called_once()
        assert all(close.call_count == 1 for close in closes)
