"""F5 must choose the declared external source, never a routed bus input."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.scenario.compiled_paths import (PathCompilationError, PathComponent,
    PathCompileRequest, compile_paths, load_path_compile_request)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from tests.scenario.test_compiled_paths import (
    P7B_REQUEST, ROOT, load_request, probe_profile, probe_sidecar, probe_wiring, real_cpu_component,
)


def test_f5_uses_environment_link_when_bus_input_appears_first():
    document = probe_profile('probe_a', irq=True)
    # The profile intentionally lists a real routed bus input before the pins.
    document['endpoints'][0]['fields'][0].update(
        direction='input', aliases=['paddr_i'], width=12)
    profile = load_component_profile(document)
    capability = load_ip_test_capability(probe_sidecar(profile, 'probe_a'), profile=profile)
    device = PathComponent('probe_a', profile, capability, ())
    request = PathCompileRequest(real_cpu_component(), (device,),
        probe_wiring((device,)), {}, 'processor.data', 'processor.instruction')
    # The same endpoint's ownership makes the distinction explicit.
    ownership = compile_ownership(
        (InputField('probe_a', 'paddr_i', 12), InputField('probe_a', 'probe_a_pin_i', 8)),
        (InputOwner('probe_a', 'paddr_i', 0, 12, 'bound', 'ibex.data_bus'),
         InputOwner('probe_a', 'probe_a_pin_i', 0, 8, 'source', 'probe_a_pins')))
    assert ownership.mutation_source('probe_a', 'probe_a_pin_i', 0, 8,
                                     direction='IP_TO_CPU') == 'probe_a_pins'
    path = next(row for row in compile_paths(request)['paths'] if row['flow_id'] == 'F5')
    assert path['status'] == 'executable'
    sources = [row for row in path['sources'] if row['kind'] == 'external_pin']
    assert len(sources) == 1
    assert (sources[0]['endpoint_id'], sources[0]['port'], sources[0]['width']) == (
        'probe_a.pins', 'probe_a_pin_i', 8)


@pytest.mark.parametrize('case', ['missing', 'ambiguous', 'missing-width'])
def test_f5_does_not_invent_external_source_when_link_is_unusable(case):
    from tests.scenario.test_compiled_paths import probe_device
    device = probe_device('probe_a', irq=True)
    wiring = probe_wiring((device,))
    link = wiring.environment_links[0]
    links = {'missing': (), 'ambiguous': (link, replace(link, link_id='other')),
             'missing-width': (replace(link, width=None),)}[case]
    wiring = replace(wiring, environment_links=links)
    request = PathCompileRequest(real_cpu_component(), (device,), wiring, {},
                                 'processor.data', 'processor.instruction')
    path = next(row for row in compile_paths(request)['paths'] if row['flow_id'] == 'F5')
    assert not [row for row in path['sources'] if row['kind'] == 'external_pin']
    assert path['status'] == 'unsupported'
    assert path['runtime_path_identity'] is None
    assert path['reason']['code'] == ('interrupt-source-ambiguous' if case == 'ambiguous'
                                      else 'interrupt-source-missing')


@pytest.mark.parametrize('kind,field', [('environment_links', 'component_instance'),
                                       ('deliveries', 'producer_instance'),
                                       ('deliveries', 'consumer_instance')])
def test_supplement_cannot_change_instance_identity(kind, field):
    request = load_request(P7B_REQUEST)
    link = {'link_id': 'pins', 'component_instance': 'gpio', 'endpoint_id': 'gpio.pins'}
    delivery = {'delivery_id': 'irq', 'producer_instance': 'gpio',
                'consumer_instance': 'cpu', 'producer_endpoint_id': 'gpio.interrupts'}
    request['wiring'] = {'schema_version': 'path_wiring.v1',
                         'cpu': {'instance_id': 'cpu', 'data_endpoint': 'processor.data'},
                         'environment_links': [link], 'deliveries': [delivery]}
    original = link if kind == 'environment_links' else delivery
    request[kind] = [{**original, field: 'other'}]
    with pytest.raises(PathCompilationError) as exc:
        load_path_compile_request(request, base_dir=ROOT)
    assert exc.value.code == ('wiring-link-conflict' if kind == 'environment_links'
                              else 'wiring-delivery-conflict')
    assert exc.value.pointer.endswith('/' + field)


def test_fixed_input_supplement_is_loaded_and_overlap_is_rejected():
    request = load_request(P7B_REQUEST)
    fixed = {'component_instance': 'gpio', 'port': 'gpio_in',
             'bit_offset': 0, 'width': 8, 'constant': 0}
    request['fixed_inputs'] = [fixed]
    loaded = load_path_compile_request(request, base_dir=ROOT)
    assert len(loaded.wiring.fixed_inputs) == 1
    assert loaded.wiring.fixed_inputs[0].port == 'gpio_in'
    request['fixed_inputs'].append({**fixed, 'bit_offset': 7, 'width': 2})
    with pytest.raises(PathCompilationError, match='fixed-input-overlap'):
        load_path_compile_request(request, base_dir=ROOT)


def _probe_f5_path(deliveries):
    from tests.scenario.test_compiled_paths import probe_device
    device = probe_device('probe_a', irq=True)
    wiring = replace(probe_wiring((device,)), deliveries=tuple(deliveries))
    compiled = compile_paths(PathCompileRequest(real_cpu_component(), (device,), wiring, {},
                                                'processor.data', 'processor.instruction'))
    return next(row for row in compiled['paths'] if row['flow_id'] == 'F5')


@pytest.mark.parametrize('endpoint', ['processor.data', None])
def test_non_irq_or_unspecified_consumer_does_not_create_f5(endpoint):
    from tests.scenario.test_compiled_paths import probe_device
    delivery = probe_wiring((probe_device('probe_a', irq=True),)).deliveries[0]
    path = _probe_f5_path((replace(delivery, consumer_endpoint_id=endpoint),))
    assert path['status'] == 'unsupported'
    assert path['reason']['code'] == 'interrupt-delivery-missing'
    assert path['runtime_path_identity'] is None


def test_non_irq_delivery_does_not_poison_valid_irq_delivery():
    from tests.scenario.test_compiled_paths import probe_device
    delivery = probe_wiring((probe_device('probe_a', irq=True),)).deliveries[0]
    unrelated = replace(delivery, delivery_id='unrelated', consumer_endpoint_id='processor.data',
                        producer_signal='not-an-irq')
    path = _probe_f5_path((unrelated, delivery))
    assert path['status'] == 'executable'
    assert path['runtime_path_identity'] == _probe_f5_path((delivery,))['runtime_path_identity']


def test_invalid_signal_on_irq_endpoint_remains_unsupported():
    from tests.scenario.test_compiled_paths import probe_device
    delivery = probe_wiring((probe_device('probe_a', irq=True),)).deliveries[0]
    path = _probe_f5_path((replace(delivery, producer_signal='not-an-irq'),))
    assert path['status'] == 'unsupported'
    assert path['runtime_path_identity'] is None


@pytest.mark.parametrize('bad', ['alias', 'bit'])
def test_irq_physical_source_must_match_declared_field(bad):
    document = probe_profile('probe_a', irq=True)
    field = next(row for row in document['endpoints'] if row['endpoint_id'] == 'probe_a.irq')['fields'][0]
    field.update(direction='output', width=1)
    if bad == 'alias':
        document['interrupts'][0]['source_id'] = 'not_a_real_port'
    else:
        document['interrupts'][0]['bit'] = 999
    profile = load_component_profile(document)
    device = PathComponent('probe_a', profile,
                           load_ip_test_capability(probe_sidecar(profile, 'probe_a'), profile=profile))
    wiring = probe_wiring((device,))
    if bad == 'alias':
        wiring = replace(wiring, deliveries=(replace(wiring.deliveries[0],
                                                    producer_signal='not_a_real_port'),))
    path = next(row for row in compile_paths(PathCompileRequest(real_cpu_component(), (device,),
        wiring, {}, 'processor.data', 'processor.instruction'))['paths'] if row['flow_id'] == 'F5')
    assert path['status'] == 'unsupported'
    assert path['runtime_path_identity'] is None
    assert path['reason']['code'] == 'interrupt-producer-physical-port-invalid'


def test_legacy_typed_soc_interrupt_route_can_omit_consumer_endpoint():
    from tests.scenario.test_compiled_paths import probe_device
    from myfuzz.scenario.compiled_paths import SOC_RENDER_CONFIG_SCHEMA
    delivery = probe_wiring((probe_device('probe_a', irq=True),)).deliveries[0]
    path = _probe_f5_path((replace(delivery, source=SOC_RENDER_CONFIG_SCHEMA,
                                  consumer_endpoint_id=None),))
    assert path['status'] == 'executable'


def _real_uart_irq_ends(signal):
    """Static profile declarations only; no RTL execution is claimed."""
    from myfuzz.scenario.compiled_paths import _Assessment, WiringDelivery
    root = Path(__file__).resolve().parents[2]
    cpu_doc = json.loads((root / 'configs/cpus/ibex_obi_local/component_profile.json').read_text())
    uart_doc = json.loads((root / 'configs/peripherals/opentitan_uart_local/component_profile.json').read_text())
    cpu = PathComponent('cpu', load_component_profile(cpu_doc))
    uart = PathComponent('uart', load_component_profile(uart_doc))
    assessment = _Assessment('F5')
    assessment.delivery = WiringDelivery('rx_irq', 'uart', 'uart.interrupts', signal,
        'cpu', 'processor.interrupts', 'level', 'test')
    return assessment, cpu, uart


def test_f5_selects_declared_uart_rx_interrupt_physical_ends():
    from myfuzz.scenario.compiled_paths import _interrupt_physical_ends
    assessment, cpu, uart = _real_uart_irq_ends('intr_rx_watermark_o')
    assert _interrupt_physical_ends(assessment, cpu, uart) == (
        ('F5.ip_irq', 'intr_rx_watermark_o', 0),
        ('F5.cpu_irq_entry', 'irq_external_i', 0))
    rx = next(field for endpoint in uart.endpoints() if endpoint.endpoint_id == 'uart.pins'
              for field in endpoint.fields if field.role == 'rx')
    assert (rx.aliases, rx.width) == (('cio_rx_i',), 1)


@pytest.mark.parametrize('signal', [None, 'unknown_irq'])
def test_f5_does_not_guess_one_of_multiple_uart_interrupts(signal):
    from myfuzz.scenario.compiled_paths import _interrupt_physical_ends
    assessment, cpu, uart = _real_uart_irq_ends(signal)
    assert _interrupt_physical_ends(assessment, cpu, uart) is None


def test_real_uart_profile_compiles_rx_delivery_to_physical_pin_path():
    from myfuzz.scenario.compiled_paths import load_path_wiring
    assessment, cpu, uart = _real_uart_irq_ends('intr_rx_watermark_o')
    # A test-only sidecar describes the documented UART STATUS read; it
    # establishes a static compiler fixture, not a native acceptance claim.
    sidecar = {'schema_version': 'ip_test_capability.v1',
        'component_id': uart.component_id, 'profile_fingerprint': uart.profile.profile_fingerprint,
        'endpoint_capabilities': [{'endpoint_id': 'opentitan_uart.mmio',
            'operations': ['request', 'accept', 'response', 'read']}],
        'register_semantics': [{'register': 'STATUS', 'field': 'value',
            'lsb': 0, 'width': 32, 'access': 'ro', 'read_mask': 0xffffffff,
            'write_mask': 0, 'side_effect': 'none', 'reset_value': 0,
            'evidence_ref': 'test:uart-intr-state'}], 'observation_mappings': []}
    uart = replace(uart, capability=load_ip_test_capability(sidecar, profile=uart.profile))
    wiring = load_path_wiring({'schema_version': 'path_wiring.v1',
        'cpu': {'instance_id': 'cpu', 'data_endpoint': 'processor.data'},
        'windows': [{'device_id': 'uart', 'target_instance': 'uart',
                     'endpoint_id': 'opentitan_uart.mmio', 'base': 0x40000000, 'size': 4096}],
        'resources': [{'resource_id': 'ram', 'component_instance': 'cpu',
            'base': 0x10000, 'size': 0x30000, 'read': True, 'write': True,
            'execute': True, 'initialization_policy': 'preload'}],
        'deliveries': [{'delivery_id': 'rx_irq', 'producer_instance': 'uart',
            'producer_endpoint_id': 'uart.interrupts', 'producer_signal': 'intr_rx_watermark_o',
            'consumer_instance': 'cpu', 'consumer_endpoint_id': 'processor.interrupts',
            'trigger': 'level'}],
        'environment_links': [{'link_id': 'uart_rx', 'component_instance': 'uart',
            'endpoint_id': 'uart.pins', 'width': 1, 'event_kind': 'level'}]})
    compiled = compile_paths(PathCompileRequest(cpu, (uart,), wiring, {},
        'processor.data', 'processor.instruction'))
    path = next(row for row in compiled['paths'] if row['flow_id'] == 'F5')
    assert path['status'] == 'executable'
    assert path['runtime_path_identity'] is not None
    source = next(row for row in path['sources'] if row['kind'] == 'external_pin')
    assert (source['port'], source['width']) == ('cio_rx_i', 1)
    nodes = {row['node_id']: row for row in compiled['runtime_path_contract']['nodes']}
    assert nodes['F5.ip_irq']['port'] == 'intr_rx_watermark_o'
    assert nodes['F5.cpu_irq_entry']['port'] == 'irq_external_i'
    unrelated = replace(wiring.deliveries[0], delivery_id='non_irq',
                        consumer_endpoint_id='processor.data', producer_signal='unrelated')
    with_extra = replace(wiring, deliveries=(unrelated, *wiring.deliveries))
    extra = compile_paths(PathCompileRequest(cpu, (uart,), with_extra, {},
        'processor.data', 'processor.instruction'))
    extra_path = next(row for row in extra['paths'] if row['flow_id'] == 'F5')
    assert extra_path['status'] == 'executable'
    assert extra_path['runtime_path_identity'] == path['runtime_path_identity']
    for bad_signal in (None, 'unknown_irq'):
        bad = replace(wiring, deliveries=(replace(wiring.deliveries[0],
                                                producer_signal=bad_signal),))
        result = compile_paths(PathCompileRequest(cpu, (uart,), bad, {},
            'processor.data', 'processor.instruction'))
        bad_path = next(row for row in result['paths'] if row['flow_id'] == 'F5')
        assert bad_path['status'] == 'unsupported'
        assert bad_path['runtime_path_identity'] is None
    wrong_trigger = replace(wiring, deliveries=(replace(wiring.deliveries[0],
                                                      trigger='pulse'),))
    with pytest.raises(ValueError, match='interrupt-trigger-mismatch'):
        compile_paths(PathCompileRequest(cpu, (uart,), wrong_trigger, {},
            'processor.data', 'processor.instruction'))
