"""D8 production executor with software v2 physical-receipt fixtures, no RTL."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource, OnlineSource)
from myfuzz.scenario.runtime_path_contract import (
    RuntimeEdgeContract, RuntimeNode, RuntimePathContract)
from myfuzz.scenario.session_runtime import ScenarioSession
from tests.integration.test_scenario_rfuzz_acceptance import executor_for, LocalSession


class PhysicalSession(LocalSession):
    def __init__(self):
        super().__init__()
        self.samples = []
        self.reset_epoch = 0
        exports = [dict(endpoint_id='pins', role=port, physical_port=port,
                        runtime_name='rt_' + port, direction=direction,
                        bit_lo=0, bit_hi=0, width=1, encoding='integer')
                   for port, direction in (('pin', 'input'), ('pin2', 'input'), ('observed', 'output'))]
        self.artifact = SimpleNamespace(runtime_document={
            'kind': 'apb3_register_observe',
            'base_event_schema_version': 'ip_base_event.v1',
            'clock_schedule': {'primary_clock_domain': 'clk'},
            'physical_exports': exports}, plan=SimpleNamespace(
                request=SimpleNamespace(instance_id='local', document=lambda: {
                    'schema_version': 'local_harness.v2', 'instance_id': 'local'}),
                profile=SimpleNamespace(component_id='opaque', endpoints=(
                    SimpleNamespace(endpoint_id='pins', clock='clk'),))))

    def step_local(self, inputs):
        result = super().step_local(inputs)
        sample = {'observed': result['observed'], 'physical': {
            'rt_pin': inputs.get('pin', 0), 'rt_pin2': inputs.get('pin2', 0),
            'rt_observed': result['observed']}}
        self.samples.append(dict(local_tick=self.steps, pre=sample, post=sample))
        return result

    def drain_tick_samples(self):
        result, self.samples = self.samples, []
        return result


class ProtocolPhysicalSession(PhysicalSession):
    """Software raw protocol observations emitted by the real Runner pipeline."""
    def __init__(self):
        super().__init__()
        document = self.artifact.runtime_document
        document['effective_max_wait_cycles'] = 8
        document['base_protocol_trace'] = dict(schema_version='ip_protocol_trace.v1',
            protocol='apb3', endpoint_id='bus', clock_domain='clk', max_wait_cycles=8,
            signals={key: key for key in ('psel', 'penable', 'pwrite', 'paddr',
                'pwdata', 'pready', 'prdata', 'pslverr')})
        document['base_protocol_trace']['signal_widths'] = {key:
            (32 if key in ('paddr', 'pwdata', 'prdata') else 1)
            for key in document['base_protocol_trace']['signals']}
        self.artifact.plan.profile.endpoints += (SimpleNamespace(endpoint_id='bus', clock='clk'),)

    def step_local(self, inputs):
        result = super().step_local(inputs)
        for phase in ('pre', 'post'):
            self.samples[-1][phase]['backend'] = dict(psel=1, penable=int(self.steps % 2 == 0),
                pwrite=1, paddr=0, pwdata=0, pready=1, prdata=0, pslverr=0)
        return result


def configured(*, enabled=False, available=True, begin=True, change=None,
               two_sources=False, session_checker=None, checker_configuration_only=False,
               protocol=False, **kwargs):
    from myfuzz.scenario.runner import ScenarioRunner
    base = executor_for()
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    ports = ('pin', 'pin2') if two_sources else ('pin',)
    ownership = compile_ownership(tuple(InputField('local', p, 1) for p in ports),
        tuple(InputOwner('local', p, 0, 1, 'source', 'external_' + p) for p in ports))
    graph = OnlineDependencyGraph(sources=tuple(OnlineDependencySource('local.' + p,
        'source', 'local', ('IP_TO_IP',), port=p) for p in ports), rules=tuple(
        DependencyRule('local.observed', ('local.' + p,), 'EVENT_ORDER') for p in ports))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, tuple(
        RuntimeNode('local.' + p, 'local', 'physical', p, 0, 1) for p in ports) + (
        RuntimeNode('local.observed', 'local', 'physical', 'observed', 0, 1),), tuple(
            RuntimeEdgeContract(i, 0, 'causal_order') for i in range(len(ports))))
    decoder = OnlineCaseDecoder(sources=tuple(OnlineSource('local.' + p, 'source', 'local',
        'IP_TO_IP', 'local.observed', weight=2, port=p,
        coverage_target_ids=('local.observed',)) for p in ports), graph=graph,
        runtime_contract=contract, ownership=ownership,
        schedule=('local',), instruction_start=0, instruction_end=0,
        advance_rounds=1, max_input_bytes=8)
    def factory():
        return ScenarioRunner(sessions={'local': (ProtocolPhysicalSession() if protocol else
            PhysicalSession()) if available else LocalSession()},
            ownership=ownership, bindings=())
    session = ScenarioSession(replace(base.decoder.templates[0].genome,
        actions=(), max_steps=100), factory(), checker=session_checker,
        checker_configuration_only=checker_configuration_only)
    session.configure_runtime_paths(decoder.graph, contract, decoder.runtime_paths,
        source_ownership=decoder.ownership)
    if begin:
        session.begin()
    if change:
        change(session.runner)
    executor = ScenarioRfuzzExecutor(run_id='candidate-production', factory=factory,
        targets=(CoverageTarget('local.observed', 'local', 'observed', 1, 0),),
        online_decoder=decoder, session=session, candidate_exploration=enabled, **kwargs)
    return executor


def drive(executor, buffer_id=1, value=1):
    return executor.execute_batch(InputBatch(buffer_id, 8, (
        (bytes((0, 0, 0, 0, 0, value, 0, 0)),),)))


def test_protocol_base_coverage_comes_from_actual_runner_projection():
    executor = configured(enabled=True, protocol=True)
    drive(executor, buffer_id=1)
    drive(executor, buffer_id=2)
    snapshot = executor.candidate_exploration_state()
    counts = snapshot['base_coverage']['instances']['local']['counts']
    assert counts['event:bus:transaction_request'] >= 1
    assert counts['event:bus:transaction_accept'] >= 1
    assert counts['event:bus:transaction_response'] >= 1
    assert counts['response:bus:ok'] >= 1
    assert snapshot['configuration']['observations']['local']['protocol_projector']['protocol'] == 'apb3'
    assert snapshot['grants_prerequisites'] is False


def test_cached_protocol_projector_drift_is_refused_before_case():
    executor = configured(enabled=True, protocol=True)
    runner = executor.session.runner
    normalizer = runner._ip_protocol_event_normalizers['local']
    normalizer._signals['pwrite'] = 'untrusted'
    with pytest.raises(ValueError, match='candidate.*protocol'):
        drive(executor)
    assert not executor.receipts and not executor.session.cases


def test_production_coverage_context_uses_observed_features_not_saved_scores():
    executor = configured(enabled=True, protocol=True)
    drive(executor, buffer_id=1)
    state = executor.candidate_exploration_state()
    contextual = [row for row in state['discovery']['candidate_records']
                  if row['rule_id'].startswith('coverage_context:')]
    assert contextual
    assert all(row['evidence_type'] == 'candidate' for row in contextual)
    assert state['configuration']['discovery']['coverage_features']
    assert state['candidate_novelty'] <= 1
    assert state['grants_prerequisites'] is False


def test_cached_protocol_checker_drift_is_refused_before_case():
    executor = configured(enabled=True, protocol=True)
    checker = executor.session.runner._ip_protocol_checkers['local']
    checker._widths['pwrite'] = 2
    with pytest.raises(ValueError, match='candidate.*protocol'):
        drive(executor)
    assert not executor.receipts and not executor.session.cases


def test_invalid_protocol_width_contract_is_refused_before_case_commands():
    def change(runner):
        runner.sessions['local'].artifact.runtime_document['base_protocol_trace']['signal_widths']['pwrite'] = 2
    with pytest.raises(ValueError, match='candidate.*protocol'):
        configured(enabled=True, protocol=True, change=change)


@pytest.mark.parametrize('enabled', (False, True))
@pytest.mark.parametrize('policy', ('warm_all', 'cold_all'))
def test_between_case_reset_clears_pending_credit_before_next_case(enabled, policy):
    from myfuzz.integration.scenario_rfuzz import _InstructionEvidence, _GpioPinIrqEvidence
    from myfuzz.scenario.session_runtime import OnlineInstruction
    from myfuzz.scenario.batch import BatchSourceEvent
    executor = configured(enabled=enabled)
    drive(executor)
    local = executor.session.runner.sessions['local']
    def reset():
        local.reset_epoch += 1
        return {}
    local.reset_local = reset
    instruction = OnlineInstruction('old-instruction', 'local', 0, '13000000')
    pin = BatchSourceEvent('old-pin', 'local', 'pin', 1, 0, 1)
    executor._online_instruction_evidence = {instruction.action_id: _InstructionEvidence(instruction)}
    executor._online_pin_evidence = {pin.action_id: _GpioPinIrqEvidence(pin)}
    executor._online_pending_sources = {pin.action_id: (pin, (1, 0, 'local.pin'))}
    executor._online_last_gpio_step = {'local': {'event_id': 0}}
    executor.session.reset(policy)
    submit = executor.session.submit_case
    checked = []
    def check_before_submit(*args, **kwargs):
        assert instruction.action_id not in executor._online_instruction_evidence
        assert pin.action_id not in executor._online_pin_evidence
        assert pin.action_id not in executor._online_pending_sources
        assert not executor._online_last_gpio_step
        checked.append(True)
        return submit(*args, **kwargs)
    executor.session.submit_case = check_before_submit
    try:
        drive(executor, buffer_id=2)
        assert executor.receipts[-1].status == 'complete', executor.receipts[-1].error
        assert checked == [True]
        if enabled:
            assert executor.candidate_exploration_state()['cases'] == 2
        else:
            assert executor.candidate_exploration_state() is None
    finally:
        executor._finish_online_session()


def test_default_off_keeps_legacy_weights_decisions_and_receipt_feedback():
    executor = configured(available=False)
    assert executor.candidate_exploration_state() is None
    drive(executor)
    assert executor.receipts[0].status == 'complete'
    assert 'candidate_exploration' not in executor.online_decisions[0]
    assert 'candidate_novelty' not in executor.receipts[0].interaction_feedback


def test_actual_case_physical_receipts_score_next_decoder_weights_once():
    executor = configured(enabled=True)
    drive(executor)
    decision = executor.online_decisions[0]
    assert executor.receipts[0].status == 'complete'
    feedback = decision['candidate_exploration']
    assert feedback['candidate_novelty'] == 1
    assert feedback['candidate_energy'] == 1
    assert feedback['non_candidate_new_energy'] >= 10
    assert executor._online_weights()['local.pin'] == executor._online_baseline_weights()['local.pin'] + 1
    categories = executor.receipts[0].interaction_feedback
    assert categories['candidate_novelty'] == feedback
    assert categories['base_coverage']['category'] == 'base_coverage'
    assert categories['verified_dependency']['new_records'] == []
    assert categories['legacy_target_coverage']['new_target_ids'] == ['local.observed']
    assert categories['functional_coverage']['status'] == 'unknown'
    # Repeated RFuzz identity does not advance physical ticks or budget state.
    state = executor.candidate_exploration_state()
    ticks = dict(executor.session.runner.local_ticks)
    drive(executor)
    assert executor.candidate_exploration_state() == state
    assert executor.session.runner.local_ticks == ticks
    drive(executor, 2)
    assert executor.online_decisions[1]['weights'] == executor.receipts[1].online_weights
    assert executor.online_decisions[1]['candidate_exploration']['candidate_novelty'] == 0
    assert executor.online_decisions[1]['candidate_exploration']['candidate_energy'] == 0
    assert executor.online_decisions[1]['closed_loop_feedback']['enabled'] is False


def test_novelty_without_actual_new_scoring_energy_cannot_bias_selection():
    executor = configured(enabled=True)
    executor._target_hits.add('local.observed')
    drive(executor)
    feedback = executor.online_decisions[0]['candidate_exploration']
    assert feedback['candidate_novelty'] == 1
    assert feedback['non_candidate_new_energy'] == 0
    assert feedback['candidate_energy'] == 0
    assert executor._online_weights() == executor._online_baseline_weights()


def test_candidate_energy_changes_actual_next_legal_source_selection():
    executor = configured(enabled=True, two_sources=True)
    drive(executor)
    assert executor.online_decisions[0]['candidate_exploration']['candidate_energy'] == 1
    before, after = executor._online_non_candidate_weights(), executor._online_weights()
    decoder = executor.online_decoder
    boundary = None
    for seed in range(8192):
        raw = seed.to_bytes(8, 'little')
        original = decoder.decode(raw, coverage_hints=before)
        changed = decoder.decode(raw, coverage_hints=after)
        if original.source.port != changed.source.port:
            boundary = raw, original.source.port, changed.source.port
            break
    assert boundary is not None, 'expected a selection boundary for the real one-unit delta'
    raw, original_port, changed_port = boundary
    executor.execute_batch(InputBatch(2, 8, ((raw,),)))
    decision = executor.online_decisions[1]
    assert decision['source_id'] == 'local.' + changed_port
    assert decision['source_id'] != 'local.' + original_port
    assert decision['weights'] == after
    assert set(after) == {'local.pin', 'local.pin2'}


def test_unobservable_runtime_refuses_before_commands_and_output_creation(tmp_path):
    output = tmp_path / 'rejected'
    with pytest.raises(ValueError, match='candidate.*observ'):
        configured(enabled=True, available=False, begin=False, evidence_dir=output)
    assert not output.exists()


@pytest.mark.parametrize('mutation', ('port', 'width', 'direction', 'endpoint'))
def test_actual_export_must_match_runtime_node_and_input_ownership(mutation):
    def change(runner):
        export = runner.sessions['local'].artifact.runtime_document['physical_exports'][0]
        if mutation == 'port': export['physical_port'] = 'other'
        elif mutation == 'width': export.update(width=2, bit_hi=1)
        elif mutation == 'direction': export['direction'] = 'output'
        else: export['endpoint_id'] = 'unknown'
    with pytest.raises(ValueError, match='candidate'):
        configured(enabled=True, change=change)


def test_configuration_is_detached_frozen_and_runtime_drift_refuses_pre_case():
    executor = configured(enabled=True)
    state = executor.candidate_exploration_state()
    changed = deepcopy(state)
    changed['configuration'].clear()
    assert executor.candidate_exploration_state() == state
    runner = executor.session.runner
    ticks, count = dict(runner.local_ticks), runner.event_count
    runner.sessions['local'].artifact.runtime_document['physical_exports'][0]['runtime_name'] = 'other'
    with pytest.raises(ValueError, match='candidate.*changed'):
        drive(executor)
    assert runner.local_ticks == ticks and runner.event_count == count


def test_preexisting_cached_projector_cannot_hide_changed_artifact_exports():
    def change(runner):
        local = runner.sessions['local']
        runner._ip_base_event_normalizer('local', local)
        local.artifact.runtime_document['physical_exports'][0]['runtime_name'] = 'other'
    with pytest.raises(ValueError, match='candidate.*projector'):
        configured(enabled=True, change=change)


def test_case_capacity_refuses_before_physical_commands_without_evicting_state():
    executor = configured(enabled=True, candidate_exploration_max_cases=1)
    drive(executor)
    state = executor.candidate_exploration_state()
    runner = executor.session.runner
    ticks, count = dict(runner.local_ticks), runner.event_count
    with pytest.raises(ValueError, match='candidate.*capacity'):
        drive(executor, 2)
    assert runner.local_ticks == ticks and runner.event_count == count
    assert executor.candidate_exploration_state() == state


def test_cached_projector_mutation_is_rejected_before_commands():
    executor = configured(enabled=True)
    runner = executor.session.runner
    ticks, count = dict(runner.local_ticks), runner.event_count
    runner._ip_base_event_normalizers['local']._exports[0]['runtime_name'] = 'rt_observed'
    with pytest.raises(ValueError, match='candidate.*changed'):
        drive(executor)
    assert runner.local_ticks == ticks and runner.event_count == count


def test_live_saved_identity_freezes_switch_rules_sources_and_classified_feedback():
    from pathlib import Path
    from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
    from myfuzz.scenario.replay import ScenarioTrace
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    try:
        executor = configured(enabled=True)
        transport.run_transport(executor, records=(bytes((0, 0, 0, 0, 0, 1, 0, 0)),))
        envelope = json.loads((transport.output / 'online_run_identity.json').read_bytes())
        identity = envelope['identity']
        report = json.loads((transport.output / 'report.json').read_bytes())
        record = report['candidate_exploration']
        assert identity['run_config']['candidate_exploration'] == record['configuration']
        assert identity['run_config']['candidate_exploration_sha256'] == record['configuration_sha256']
        for source in record['configuration']['source_files']:
            path = Path(__file__).resolve().parents[2] / source['path']
            assert hashlib.sha256(path.read_bytes()).hexdigest() == source['sha256']
        saved = json.loads((transport.output / 'receipts.jsonl').read_text().splitlines()[0])
        assert saved['candidate_exploration'] == executor.online_decisions[0]['candidate_exploration']
        assert saved['interaction_feedback']['candidate_novelty'] == saved['candidate_exploration']
        trace_path = transport.output / 'online_final_trace.json'
        trace = ScenarioTrace(**json.loads(trace_path.read_bytes()))
        assert _verify_online_run_identity(transport.output,
            plan_path=transport.output / 'online_plan.json', trace_path=trace_path, trace=trace)
        # Change config in its identity envelope only. An envelope hash is not
        # sufficient: its own report must still agree with the frozen switch.
        identity['run_config']['candidate_exploration']['budget']['max_cases'] = 1
        envelope['sha256'] = hashlib.sha256(json.dumps(identity, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        report['online_run_identity_sha256'] = envelope['sha256']
        (transport.output / 'report.json').write_text(json.dumps(report))
        (transport.output / 'online_run_identity.json').write_text(json.dumps(envelope))
        with pytest.raises(ValueError, match='candidate'):
            _verify_online_run_identity(transport.output,
                plan_path=transport.output / 'online_plan.json', trace_path=trace_path, trace=trace)
    finally:
        transport.doCleanups()


@pytest.mark.parametrize('field', ('novelty_units_per_case', 'energy_per_unit',
                                  'max_energy_numerator', 'enabled'))
def test_report_configuration_cannot_substitute_equal_bool_and_integer(field):
    from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
    from myfuzz.scenario.replay import ScenarioTrace
    from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
    transport = TerminalIdentityTests()
    transport.setUp()
    try:
        executor = configured(enabled=True)
        transport.run_transport(executor)
        report_path = transport.output / 'report.json'
        report = json.loads(report_path.read_bytes())
        budget = report['candidate_exploration']['configuration']['budget']
        budget[field] = 1 if field == 'enabled' else True
        report_path.write_text(json.dumps(report))
        trace_path = transport.output / 'online_final_trace.json'
        trace = ScenarioTrace(**json.loads(trace_path.read_bytes()))
        with pytest.raises(ValueError, match='candidate'):
            _verify_online_run_identity(transport.output,
                plan_path=transport.output / 'online_plan.json', trace_path=trace_path, trace=trace)
    finally:
        transport.doCleanups()


@pytest.mark.parametrize('value', (None, 1, 'true'))
def test_switch_rejects_non_bool(value):
    with pytest.raises(ValueError, match='candidate'):
        configured(enabled=value)


def test_legacy_output_hits_do_not_claim_stage2_functional_proof():
    executor = configured(enabled=True)
    drive(executor)
    feedback = executor.receipts[0].interaction_feedback
    assert feedback['legacy_target_coverage']['new_target_ids'] == ['local.observed']
    assert feedback['functional_coverage']['status'] == 'unknown'
    assert feedback['functional_coverage']['new_features'] == []
    assert feedback['verified_dependency']['new_records'] == []
    assert feedback['verified_dependency']['grants_prerequisites'] is False
    assert executor.candidate_exploration_state()['classified_feedback']['functional_coverage']['status'] == 'unknown'
