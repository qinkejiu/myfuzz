"""F5 path declarations for the source-locked PULP GPIO pulse."""
import json

import pytest
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.scenario.compiled_paths import (
    DeclaredSource, PathCompilationError, PathCompileRequest, PathComponent, compile_paths, load_path_wiring,
)

ROOT = Path(__file__).resolve().parents[2]


def _compile_real_gpio(links=None, fixed_inputs=None, two_gpio=False, claims=()):
    cpu_profile = load_component_profile(ROOT / 'configs/cpus/ibex_obi_local/component_profile.json')
    gpio_profile = load_component_profile(ROOT / 'configs/peripherals/pulp_gpio_causal_local/component_profile.json')
    capability = load_ip_test_capability(
        json.loads((ROOT / 'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json').read_text()),
        profile=gpio_profile)
    cpu = PathComponent('cpu', cpu_profile)
    gpio = PathComponent('gpio_b', gpio_profile, capability, claims)
    wiring = load_path_wiring({'schema_version': 'path_wiring.v1',
        'cpu': {'instance_id': 'cpu', 'data_endpoint': 'processor.data'},
        'windows': ([{'device_id': 'gpio_a', 'target_instance': 'gpio_a',
                      'endpoint_id': 'gpio.bus', 'base': 0x40001000, 'size': 4096}]
                    if two_gpio else []) + [
                     {'device_id': 'gpio_b', 'target_instance': 'gpio_b',
                      'endpoint_id': 'gpio.bus', 'base': 0x40000000, 'size': 4096}],
        'resources': [{'resource_id': 'ram', 'component_instance': 'cpu',
            'base': 0x10000, 'size': 0x30000, 'read': True, 'write': True,
            'execute': True, 'initialization_policy': 'preload'}],
        'deliveries': [{'delivery_id': 'gpio_b_irq', 'producer_instance': 'gpio_b',
            'producer_endpoint_id': 'gpio.interrupts', 'producer_signal': 'interrupt',
            'consumer_instance': 'cpu', 'consumer_endpoint_id': 'processor.interrupts',
            'trigger': 'pulse'}],
        'environment_links': links if links is not None else [{'link_id': 'gpio_b_pins', 'component_instance': 'gpio_b',
            'endpoint_id': 'gpio.pins', 'width': 32, 'event_kind': 'pin_value'}],
        'fixed_inputs': fixed_inputs or []})
    devices = ((PathComponent('gpio_a', gpio_profile, capability), gpio)
               if two_gpio else (gpio,))
    compiled = compile_paths(PathCompileRequest(cpu, devices, wiring, {},
        'processor.data', 'processor.instruction'))
    return compiled


def test_real_pulp_gpio_f5_compiles_declared_native_pulse():
    compiled = _compile_real_gpio()
    path = next(row for row in compiled['paths'] if row['flow_id'] == 'F5')
    assert path['status'] == 'executable'
    assert path['runtime_path_identity'] is not None
    source = next(row for row in path['sources'] if row['kind'] == 'external_pin')
    assert (source['port'], source['width']) == ('gpio_in', 32)
    nodes = {row['node_id']: row for row in compiled['runtime_path_contract']['nodes']}
    assert nodes['F5.ip_irq']['port'] == 'interrupt'
    assert nodes['F5.cpu_irq_entry']['port'] == 'irq_external_i'


def test_real_gpio_bit8_environment_segment_is_the_f5_source():
    compiled = _compile_real_gpio([{'link_id': 'gpio_b_pin8', 'component_instance': 'gpio_b',
        'endpoint_id': 'gpio.pins', 'bit_offset': 8, 'width': 1, 'event_kind': 'pin_value'}])
    path = next(row for row in compiled['paths'] if row['flow_id'] == 'F5')
    source = next(row for row in path['sources'] if row['kind'] == 'external_pin')
    assert (source['bit_offset'], source['width'], source['mask']) == (8, 1, 1)
    node = next(row for row in compiled['runtime_path_contract']['nodes'] if row['node_id'] == 'F5.pin_event')
    assert (node['bit_offset'], node['width']) == (8, 1)


@pytest.mark.parametrize('links,code', [
    ([{'link_id': 'overflow', 'component_instance': 'gpio_b', 'endpoint_id': 'gpio.pins',
      'bit_offset': 31, 'width': 2}], 'wiring-link-segment-out-of-range'),
    ([{'link_id': 'a', 'component_instance': 'gpio_b', 'endpoint_id': 'gpio.pins',
      'bit_offset': 8, 'width': 2},
     {'link_id': 'b', 'component_instance': 'gpio_b', 'endpoint_id': 'gpio.pins',
      'bit_offset': 9, 'width': 1}], 'wiring-link-segment-overlap'),
    ([{'link_id': 'whole', 'component_instance': 'gpio_b', 'endpoint_id': 'gpio.pins', 'width': 32},
      {'link_id': 'part', 'component_instance': 'gpio_b', 'endpoint_id': 'gpio.pins',
       'bit_offset': 8, 'width': 1}], 'wiring-link-segment-overlap'),
])
def test_real_gpio_rejects_invalid_or_overlapping_environment_segments(links, code):
    with pytest.raises(PathCompilationError) as exc:
        _compile_real_gpio(links)
    assert exc.value.code == code


def test_nonoverlapping_segments_are_not_a_unique_f5_source():
    links = [{'link_id': name, 'component_instance': 'gpio_b', 'endpoint_id': 'gpio.pins',
              'bit_offset': offset, 'width': 1} for name, offset in [('a', 8), ('b', 9)]]
    path = next(row for row in _compile_real_gpio(links)['paths'] if row['flow_id'] == 'F5')
    assert path['status'] == 'unsupported'
    assert path['reason']['code'] == 'interrupt-source-ambiguous'
    assert path['runtime_path_identity'] is None


@pytest.mark.parametrize('endpoint', ['gpio.missing', 'gpio.bus'])
def test_explicit_segment_rejects_invalid_endpoint(endpoint):
    with pytest.raises(PathCompilationError) as exc:
        _compile_real_gpio([{'link_id': 'bad', 'component_instance': 'gpio_b',
                             'endpoint_id': endpoint, 'bit_offset': 8, 'width': 1}])
    assert exc.value.code == 'wiring-link-segment-endpoint-invalid'


def test_f5_source_may_not_overlap_fixed_input():
    with pytest.raises(PathCompilationError) as exc:
        _compile_real_gpio([{'link_id': 'pin8', 'component_instance': 'gpio_b',
                             'endpoint_id': 'gpio.pins', 'bit_offset': 8, 'width': 1}],
                           [{'component_instance': 'gpio_b', 'port': 'gpio_in',
                             'bit_offset': 8, 'width': 1, 'constant': 0}])
    assert exc.value.code == 'wiring-link-fixed-overlap'


def test_two_real_gpio_instances_have_distinct_layouts_and_physical_f5_source():
    compiled = _compile_real_gpio([{'link_id': 'pin8', 'component_instance': 'gpio_b',
        'endpoint_id': 'gpio.pins', 'bit_offset': 8, 'width': 1}], two_gpio=True)
    fields = compiled['input_constraints']['layout']['fields']
    gpio_fields = [row for row in fields if row['role'] == 'in']
    assert len(gpio_fields) == 2
    assert len({row['owner'] for row in gpio_fields}) == 2
    assert len({row['binding']['port'] for row in gpio_fields}) == 2
    path = next(row for row in compiled['paths'] if row['flow_id'] == 'F5')
    source = next(row for row in path['sources'] if row['kind'] == 'external_pin')
    assert (source['component'], source['port'], source['bit_offset'], source['width']) == (
        'gpio_b', 'gpio_in', 8, 1)


def test_two_gpio_instances_keep_constraints_on_the_declared_instance():
    claim = DeclaredSource('/sources/0', {'source_id': 'pin_b', 'flow_id': 'F5',
        'component': 'gpio_b', 'endpoint_id': 'gpio.pins', 'role': 'in', 'mask': 1})
    compiled = _compile_real_gpio([{'link_id': 'pin8', 'component_instance': 'gpio_b',
        'endpoint_id': 'gpio.pins', 'bit_offset': 8, 'width': 1}], two_gpio=True,
        claims=(claim,))
    fields = compiled['input_constraints']['layout']['fields']
    rows = {row['owner']: row for row in fields if row['role'] == 'in'}
    assert rows['gpio_b::gpio.pins']['constraint']['mask'] == 1
    assert 'mask' not in rows['gpio_a::gpio.pins']['constraint']
