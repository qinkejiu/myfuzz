"""Timer pulse declaration/source checks; no CPU or DUT process is started."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/pulp_timer_irq/component_profile.json'


def test_timer_optin_has_four_real_pulses_without_changing_default():
    from myfuzz.composition.component_profile import load_component_profile
    default = json.loads((ROOT / 'configs/peripherals/pulp_timer/component_profile.json').read_text())
    profile = load_component_profile(json.loads((ROOT / PROFILE).read_text()))
    assert default['interrupts'] == []
    assert len(profile.interrupts) == 4
    assert [(i.bit, i.trigger, i.pulse_width_cycles) for i in profile.interrupts] == [
        (bit, 'pulse', 1) for bit in range(4)]


def test_timer_source_contract_has_exact_bounded_trigger_and_no_consumption_claim():
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.pulp_timer_irq_contract import timer_irq_source_contract
    profile = load_component_profile(json.loads((ROOT / PROFILE).read_text()))
    contract = timer_irq_source_contract(profile, base_dir=ROOT)
    assert contract['native_port'] == 'irq_o'
    assert contract['width'] == 4
    assert contract['trigger_writes'] == ((4, 0), (8, 0), (0, 0xFFFFFFFF))
    assert contract['selected_bit'] == 0
    assert contract['acceptance'] == contract['serial'] == contract['isr_mmio'] == 'unknown'
    assert contract['reward_eligible'] is False


def test_unregistered_profile_does_not_inherit_timer_irq_authority():
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.pulp_timer_irq_contract import timer_irq_source_contract
    document = json.loads((ROOT / PROFILE).read_text())
    document['interrupts'][0]['bit'] = 1
    with pytest.raises(ValueError):
        timer_irq_source_contract(load_component_profile(document), base_dir=ROOT)


def _actual_timer_session(instance="timer"):
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    document = json.loads((ROOT / 'configs/peripherals/pulp_timer/irq_request.json').read_text())
    document['instance_id'] = instance
    request = load_local_harness_request(document)
    plan = plan_local_harness(request, base_dir=ROOT)
    artifact = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
    return GeneratedApb3RegisterSession(artifact, base_dir=ROOT, cache_dir=Path('/tmp/unused-timer-irq'))


def test_actual_timer_artifact_and_generic_apb_session_have_exact_vector_mapping():
    from myfuzz.local_harness.pulp_timer_irq_contract import timer_irq_runtime_mapping
    session = _actual_timer_session()
    mapping = timer_irq_runtime_mapping(session)
    assert mapping['physical_port'] == 'irq_o'
    assert mapping['source_width'] == 4
    session._outputs['irq_o'] = ('invented_wire', 4)
    with pytest.raises(ValueError):
        timer_irq_runtime_mapping(session)


def test_actual_timer_sources_assemble_with_existing_native_cpu_group():
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.irq_delivery_group import (IrqDeliveryGroup, IrqDeliveryMember,
                                                   verify_group_sessions)
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
                              initialization_seed=3, max_initialized_bytes=0x30000)
    cpu = GeneratedCve2Session(_artifact('configs/cpus/ibex_rvfi_local/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=Path('/tmp/unused-timer-native-cpu'), memory=memory,
        router=DataflowRouter(()),
        native_irq_receipts=True)
    sources = {'timer_a': _actual_timer_session('timer_a'),
               'timer_b': _actual_timer_session('timer_b')}
    group = IrqDeliveryGroup('timer-OR', 'cpu', cpu.irq_input_port, (
        IrqDeliveryMember('timer_a', 'irq_o'),
        IrqDeliveryMember('timer_b', 'irq_o', source_bit_offset=3)))
    sessions = {'cpu': cpu, **sources}
    adapters = verify_group_sessions(group, sessions)
    assert len(adapters) == 2
    assert all(row['source_width'] == 4 for row in adapters.values())
    owner = compile_ownership((InputField('cpu', cpu.irq_input_port, 1),),
        (InputOwner('cpu', cpu.irq_input_port, 0, 1, 'bound', group.owner_ref),))
    runner = ScenarioRunner(sessions=sessions, ownership=owner,
        bindings=group.member_bindings(), irq_delivery_groups=(group,))
    assert runner.irq_group_for(group.member_bindings()[0]) is group
    assert cpu.process is None and all(source.process is None for source in sources.values())
    invalid = IrqDeliveryGroup('invalid-bit', 'cpu', cpu.irq_input_port, (
        IrqDeliveryMember('timer_a', 'irq_o', source_bit_offset=4),
        IrqDeliveryMember('timer_b', 'irq_o')))
    with pytest.raises(ValueError, match='Timer native pulse mapping'):
        verify_group_sessions(invalid, sessions)


def test_declared_timer_plan_extends_actual_group_without_claiming_consumption(tmp_path):
    from scripts.generate_shared_dma_scenario import _declared_irq_shared_slot_plan
    from myfuzz.local_harness.request import load_local_harness_request
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    from myfuzz.integration.shared_declared_irq import bind_declared_irq_group
    request = load_local_harness_request(json.loads((ROOT / 'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared/requests/cpu.json').read_text()))
    plan = _declared_irq_shared_slot_plan(request, 'configs/peripherals/pulp_timer/irq_behavior.json',
        {'slot_base': 69632, 'slot_count': 8}, ROOT, 0x40003000)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
        initialization_seed=0, max_initialized_bytes=0x30000)
    cpu = GeneratedCve2Session(_artifact('configs/cpus/cv32e20/component_profile.json', 'cpu'),
        base_dir=ROOT, cache_dir=tmp_path, memory=memory, router=DataflowRouter(()), native_irq_receipts=True)
    first, timer = _actual_timer_session('timer_a'), _actual_timer_session('timer')
    group = IrqDeliveryGroup('shared-timer-test', 'cpu', cpu.irq_input_port,
        (IrqDeliveryMember('timer_a', 'irq_o', source_adapter='declared-output.v1'),))
    bound, mappings = bind_declared_irq_group(group, plan, {'cpu': cpu, 'timer_a': first, 'timer': timer})
    assert len(bound.members) == len(mappings) == 2
    assert mappings[bound.member_bindings()[1]]['cause'] == 'unknown'
    assert mappings[bound.member_bindings()[1]]['reward_eligible'] is False
    assert cpu.process is None and timer.process is None
