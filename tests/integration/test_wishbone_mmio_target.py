"""Wishbone target observations reuse saved real RTL events without native startup."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration.wishbone_mmio_target import observe_wishbone_mmio_bus, wishbone_mmio_bank_facts


ROOT = Path(__file__).resolve().parents[2]


def test_addressless_profile_reports_actual_template_and_unknown_internal_state():
    from myfuzz.composition.component_profile import load_component_profile
    profile = load_component_profile(ROOT / 'configs/peripherals/zipcpu_timer/component_profile.json')
    endpoint = SimpleNamespace(endpoint_id='timer.bus', protocol=('wishbone','classic'), function='mmio_slave')
    signals = {role:'trace_'+role for role in ('cyc','stb','we','dat_w','sel','ack','dat_r','stall')}
    artifact = SimpleNamespace(plan=SimpleNamespace(profile=profile, binding=SimpleNamespace(endpoints=[endpoint])),
        runtime_document={'kind':'wishbone_register_observe', 'base_protocol_trace':
            {'protocol':'wishbone','signals':signals}})
    facts = wishbone_mmio_bank_facts(artifact,endpoint_id='timer.bus').document()
    assert facts['template'] == ['target.wishbone','1','addressless-select-ignored']
    assert facts['internal_storage_version'] == facts['cross_case_origin'] == 'unknown'
    assert facts['reward_eligible'] is False


def test_real_wishbone_timer_read_keeps_native_request_ack_and_ram():
    events = json.loads((ROOT / 'research/input-strategy-audit-20261027/runs/'
        'declared-irq-f5-20261030/wb-timer/original/original/events.json').read_text())
    signals = {role: 'trace_' + role for role in ('cyc','stb','we','dat_w','sel','ack','dat_r','stall')}
    artifact = SimpleNamespace(runtime_document={'kind': 'wishbone_register_observe',
        'base_protocol_trace': {'protocol': 'wishbone', 'signals': signals}})
    declaration = {'candidate': {'access': {'source_component':'cpu','device_id':'wb_timer_active',
        'target_component':'wb_timer_active','address':1073745920,'register_offset':0}},
        'xor_constant':0,'result_address':68672}
    # Test only the saved read; the fixture's earlier write belongs to setup.
    selected = [e for e in events if e.get('event_id',0) >= 1400]
    result = observe_wishbone_mmio_bus(declaration, SimpleNamespace(events=selected),
        target_artifact=artifact, flow='F2')
    assert result['read_value'] == 0 and result['RAM_event'] == 1582
    assert result['joins'][0]['native_wishbone_request_event'] == 1516
    assert result['joins'][0]['native_wishbone_response_event'] == 1520

    mutated = deepcopy(selected)
    for event in mutated:
        if event.get('event_id') == 1520:
            event['outputs']['backend']['trace_ack'] = 0
    with pytest.raises(ValueError, match='native-Wishbone-completion'):
        observe_wishbone_mmio_bus(declaration, SimpleNamespace(events=mutated),
                                  target_artifact=artifact, flow='F2')


def test_wishbone_write_does_not_assume_peripheral_readback_equals_write():
    events = json.loads((ROOT / 'research/input-strategy-audit-20261027/runs/'
        'declared-irq-f5-20261030/wb-timer/original/original/events.json').read_text())
    signals = {role: 'trace_' + role for role in ('cyc','stb','we','dat_w','sel','ack','dat_r','stall')}
    artifact = SimpleNamespace(runtime_document={'kind': 'wishbone_register_observe',
        'base_protocol_trace': {'protocol': 'wishbone', 'signals': signals}})
    declaration = {'candidate': {'value':8,'access': {'source_component':'cpu','device_id':'wb_timer_active',
        'target_component':'wb_timer_active','address':1073745920,'register_offset':0}},
        'result_address':68672}
    result = observe_wishbone_mmio_bus(declaration, SimpleNamespace(events=events),
        target_artifact=artifact, flow='F4')
    assert [item['value'] for item in result['joins']] == [8, 0]
    assert result['read_value'] == 0 and result['RAM_event'] == 1582


def test_wishbone_mmio_registered_separately_from_internal_storage():
    from myfuzz.runtime.compiler import _expectation_for
    from myfuzz.runtime.registry import registrations
    from myfuzz.runtime.binding import _FACTORIES
    expectation = _expectation_for('target', ('wishbone','classic'),
        ('target.wishbone','1','word-addressed-registered-ack'), 'mmio.register-bank.v1')
    assert expectation.adapter_id == 'wishbone.mmio.v1'
    rows = [r for r in registrations() if r.adapter_id == expectation.adapter_id]
    assert len(rows) == 1 and rows[0].semantic_kinds == ('mmio.register-bank.v1',)
    assert rows[0].implementation_sha256()
    assert 'wishbone.mmio.v1' in _FACTORIES


def test_wishbone_mmio_admission_uses_actual_generated_uart_artifact():
    from dataclasses import replace
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_driver, render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.runtime.adapters.wishbone_mmio import admission_facts
    from myfuzz.runtime.registry import _select_from, registrations
    request = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path='configs/peripherals/zipcpu_uart/component_profile.json', instance_id='peripheral',
        reset_assert_ticks=2, reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies':[dict(endpoint_id='uart.bus',template_id='target.wishbone',
            template_version='1',variant_id='word-addressed-registered-ack',max_outstanding=1)],
            'fixed_inputs':[dict(endpoint_id='uart.pins',role='rx',value=1),
                            dict(endpoint_id='uart.pins',role='cts_n',value=0)]}))
    plan = plan_local_harness(request,base_dir=ROOT)
    artifact = render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
    preparation = SimpleNamespace(declared_endpoint_template=lambda *_: (
        'target.wishbone','1','word-addressed-registered-ack'))
    facts = admission_facts(artifact,preparation=preparation,base_dir=ROOT)
    assert facts['endpoints'][0]['semantic_kind'] == 'mmio.register-bank.v1'
    assert facts['facts']['internal_storage_version'] == 'unknown'
    assert _select_from(registrations(),None,facts['endpoints'][0]).adapter_id == 'wishbone.mmio.v1'
    bad = deepcopy(artifact.runtime_document)
    bad['base_protocol_trace']['signals']['ack'] = 'invented_ack'
    with pytest.raises(ValueError, match='native-trace-mismatch'):
        admission_facts(replace(artifact,runtime_document=bad),preparation=preparation,base_dir=ROOT)
    with pytest.raises(ValueError, match='native-trace-mismatch'):
        admission_facts(replace(artifact,runtime_sv=artifact.runtime_sv.replace('assign trace_ack =',
            'assign unrelated =')),preparation=preparation,base_dir=ROOT)
