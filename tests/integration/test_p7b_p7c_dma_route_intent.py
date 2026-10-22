"""The P7-B static DMA route survives the real D2 -> D3 composition chain."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
from myfuzz.scenario.compiled_paths import (
    compile_paths, compiled_document_sha256, load_path_compile_request)
from myfuzz.composition.component_profile import load_component_profile


ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/ibex_obi_local/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'
GPIO_CAPABILITY = 'configs/peripherals/pulp_gpio/test_capability.json'
DMA_PROFILE = 'configs/peripherals/zipcpu_wbdmac/component_profile.json'


def _write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
    return path


def _canonical_sha256(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False, allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _dma_test_capability(profile_path: Path, output: Path) -> Path:
    """A test-only declared feature sidecar for exercising the P7-C schema."""
    profile = load_component_profile(profile_path)
    return _write(output, {
        'schema_version': 'ip_test_capability.v2',
        'component_id': profile.component_id,
        'profile_fingerprint': profile.profile_fingerprint,
        'endpoint_capabilities': [{
            'endpoint_id': 'dma.memory',
            'operations': ['request', 'accept', 'response', 'read', 'write'],
        }],
        'register_semantics': [],
        'observation_mappings': [{
            'mapping_id': 'dma-master-address-sample',
            'endpoint_id': 'dma.memory', 'role': 'adr',
            'observation_kind': 'port_sample',
            'evidence_ref': 'test:static-route-chain',
        }],
        'feature_contract': {
            'provider_id': 'test.static-dma-mover',
            'provider_version': '1',
            'operations': [{
                'endpoint_id': 'dma.memory', 'operation': 'transfer',
                'required_observation_mappings': ['dma-master-address-sample'],
                'evidence_ref': 'test:static-route-chain',
            }],
        },
    })


def test_d2_v2_route_survives_d3_supplement_merge_without_live_dma_edge(tmp_path):
    """The generated route and bindings reach D3; a resource supplement cannot erase them."""
    requests = tmp_path / 'requests'
    _write(requests / 'cpu.json', {
        'schema_version': 'local_harness.v1', 'profile_path': CPU_PROFILE,
        'instance_id': 'cpu', 'reset_assert_ticks': 2,
        'reset_release_ticks': 2, 'max_wait_cycles': 16,
    })
    _write(requests / 'gpio.json', {
        'schema_version': 'local_harness.v1', 'profile_path': GPIO_PROFILE,
        'instance_id': 'sink', 'reset_assert_ticks': 2,
        'reset_release_ticks': 2, 'max_wait_cycles': 16,
    })
    _write(requests / 'dma.json', {
        'schema_version': 'local_harness.v1', 'profile_path': DMA_PROFILE,
        'instance_id': 'mover', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })

    route = {
        'route_id': 'copy.destination',
        'initiator_instance': 'mover',
        'initiator_endpoint_id': 'dma.memory',
        'target': {
            'kind': 'peripheral', 'component_instance': 'sink',
            'device_id': 'output.window', 'endpoint_id': 'gpio.bus',
        },
        'base': 0x40000000, 'size': 0x1000,
        'operation': 'write', 'permissions': ['write'],
        'byte_enable': 15, 'readable_offsets': [],
        'writable_offsets': [12],
        'accepted_write_values': {'kind': 'range', 'start': 0,
                                  'stop': 256, 'step': 1},
    }
    # Leave ROM initialization policy absent so the D3 request exercises a
    # valid supplement merge while retaining the D2 route identity.
    memory = [
        {'resource_id': 'rom0', 'component_instance': 'cpu',
         'base': 0x10000, 'size': 0x8000,
         'read': True, 'write': False, 'execute': True},
        {'resource_id': 'ram0', 'component_instance': 'cpu',
         'base': 0x80000000, 'size': 0x10000,
         'read': True, 'write': True, 'execute': False},
    ]
    compose_path = _write(tmp_path / 'compose.json', {
        'schema_version': 'harness_compose.v2',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [
            {'device_id': 'output.window', 'instance_id': 'sink',
             'request': 'requests/gpio.json', 'bus_endpoint': 'gpio.bus',
             'base': 0x40000000, 'size': 0x1000},
            {'device_id': 'mover.control', 'instance_id': 'mover',
             'request': 'requests/dma.json', 'bus_endpoint': 'dma.control',
             'base': 0x40001000, 'size': 16,
             'template': {'template_id': 'target.wishbone-pipelined',
                          'template_version': '1',
                          'variant_id': 'dma-full-word-no-select'}},
        ],
        'memory': memory,
        'dma_master_routes': {
            'schema_version': 'dma_master_route_intent.v1', 'routes': [route],
        },
        'dma_master_route_bindings': [{
            'route_id': 'copy.destination',
            'initiator_template': {
                'template_id': 'master.wishbone-pipelined',
                'template_version': '1',
                'variant_id': 'dma-full-word-no-select',
            },
            'target_template': {
                'template_id': 'target.apb3', 'template_version': '1',
                'variant_id': 'full-word',
            },
        }],
    })
    compose = load_compose(compose_path, base_dir=ROOT)
    output = tmp_path / 'generated'
    generated = generate_harness_set(compose, base_dir=ROOT,
                                     compose_base=tmp_path, output_root=output)
    wiring_path = output / 'wiring_contract.json'
    wiring = json.loads(wiring_path.read_text(encoding='utf-8'))
    assert generated['schema_version'] == 'harness_set.v2'
    assert wiring['schema_version'] == 'wiring_contract.v2'
    assert wiring['dma_master_routes']['routes'] == [route]

    dma_capability = _dma_test_capability(
        ROOT / DMA_PROFILE, tmp_path / 'test_capabilities/dma.json')
    request_path = _write(tmp_path / 'path_compile_request.json', {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': 'cpu', 'profile': CPU_PROFILE,
                'data_endpoint': 'processor.data',
                'instruction_endpoint': 'processor.instruction'},
        'devices': [
            {'device_id': 'output.window', 'instance_id': 'sink',
             'profile': GPIO_PROFILE, 'test_capability': GPIO_CAPABILITY},
            {'device_id': 'mover.control', 'instance_id': 'mover',
             'profile': DMA_PROFILE, 'test_capability': str(dma_capability)},
        ],
        'wiring': {'source': str(wiring_path)},
        'memory': [{'resource_id': 'rom0',
                    'initialization_policy': 'commit-once'}],
    })

    request = load_path_compile_request(request_path, base_dir=ROOT)
    assert request.wiring.dma_master_routes[0].route_id == 'copy.destination'
    assert len(request.wiring.dma_master_route_bindings) == 1
    assert request.wiring.resources[0].initialization_policy == 'commit-once'
    assert request.wiring.dma_master_routes_sha256 == wiring['dma_master_routes_sha256']

    compiled = compile_paths(request)
    assert compiled['identity']['wiring']['dma_master_routes_sha256'] == \
        wiring['dma_master_routes_sha256']
    assert compiled['identity']['wiring']['dma_master_route_bindings_sha256'] == \
        _canonical_sha256(wiring['dma_master_route_bindings'])
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    assert f6['status'] == 'unsupported'
    assert f6['reason']['code'] == 'dma-route-live-topology-binding-required'
    assert f6['runtime_path_identity'] is None
    assert not any(edge.get('relation') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_path_contract']['edges'])


def _local_artifact(profile_path: str, instance_id: str):
    from myfuzz.local_harness import (load_local_harness_request,
        plan_local_harness, render_local_harness, render_local_runtime,
        render_local_driver, verify_local_source_lock)
    request = load_local_harness_request({
        'schema_version': 'local_harness.v1', 'profile_path': profile_path,
        'instance_id': instance_id, 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _caliptra_sha256_artifact():
    from myfuzz.local_harness import (load_local_harness_request,
        plan_local_harness, render_local_harness, render_local_runtime,
        render_local_driver, verify_local_source_lock)
    request = load_local_harness_request({
        'schema_version': 'local_harness.v2',
        'profile_path': 'configs/peripherals/caliptra_sha256/component_profile.json',
        'instance_id': 'sha', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
        'tuning': {'endpoint_policies': [{
            'endpoint_id': 'sha256.bus', 'template_id': 'target.ahb-lite',
            'template_version': '1', 'variant_id': 'full-word-single',
            'max_outstanding': 1,
        }]},
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _uart_test_capability(profile_path: Path, output: Path) -> Path:
    profile = load_component_profile(profile_path)
    return _write(output, {
        'schema_version': 'ip_test_capability.v3',
        'component_id': profile.component_id,
        'profile_fingerprint': profile.profile_fingerprint,
        'endpoint_capabilities': [{
            'endpoint_id': 'opentitan_uart.mmio',
            'operations': ['read', 'write'],
        }],
        'register_semantics': [],
        'observation_mappings': [],
        'register_aliases': [],
    })


def _generate_ot_uart_dma_route_d2_d3(tmp_path: Path):
    """Create the D2/D3 static rows later joined to the existing typed UART/RAM graph."""
    from myfuzz.scenario.compiled_paths import load_path_compile_request

    uart_profile = 'configs/peripherals/opentitan_uart_local/component_profile.json'
    route_rows = [
        {
            'route_id': 'route.0', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'peripheral', 'component_instance': 'uart',
                       'device_id': 'uart', 'endpoint_id': 'opentitan_uart.mmio'},
            'base': 0x50000000, 'size': 0x1000, 'operation': 'read',
            'permissions': ['read', 'write'], 'byte_enable': 15,
            'readable_offsets': [0x18], 'writable_offsets': [0x1c],
            'accepted_write_values': {'kind': 'values', 'values': [2]},
        },
        {
            'route_id': 'route.1', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'persistent_memory', 'component_instance': 'cpu',
                       'resource_id': 'ram'},
            'base': 0x1000, 'size': 0x1000, 'operation': 'write',
            'permissions': ['read', 'write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [],
            'accepted_write_values': {'kind': 'values', 'values': []},
        },
    ]
    template_dma_master = {
        'template_id': 'master.wishbone-pipelined', 'template_version': '1',
        'variant_id': 'dma-full-word-no-select',
    }
    compose_path = _write(tmp_path / 'ot_uart_compose.json', {
        'schema_version': 'harness_compose.v2',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [
            {'device_id': 'uart', 'instance_id': 'uart',
             'request': 'requests/uart.json', 'bus_endpoint': 'opentitan_uart.mmio',
             'base': 0x50000000, 'size': 0x1000,
             'template': {'template_id': 'target.tl-ul', 'template_version': '1',
                          'variant_id': 'user-integrity'}},
            {'device_id': 'dma.control', 'instance_id': 'dma',
             'request': 'requests/dma.json', 'bus_endpoint': 'dma.control',
             'base': 0x40001000, 'size': 16,
             'template': {'template_id': 'target.wishbone-pipelined',
                          'template_version': '1',
                          'variant_id': 'dma-full-word-no-select'}},
        ],
        'memory': [
            {'resource_id': 'rom0', 'component_instance': 'cpu',
             'base': 0x10000, 'size': 0x8000,
             'read': True, 'write': False, 'execute': True},
            {'resource_id': 'ram', 'component_instance': 'cpu',
             'base': 0x1000, 'size': 0x1000,
             'read': True, 'write': True, 'execute': False},
        ],
        'dma_master_routes': {
            'schema_version': 'dma_master_route_intent.v1', 'routes': route_rows,
        },
        'dma_master_route_bindings': [
            {'route_id': 'route.0', 'initiator_template': template_dma_master,
             'target_template': {'template_id': 'target.tl-ul',
                                 'template_version': '1',
                                 'variant_id': 'user-integrity'}},
            {'route_id': 'route.1', 'initiator_template': template_dma_master},
        ],
    })
    compose = load_compose(compose_path, base_dir=ROOT)
    request_root = tmp_path / 'requests'
    _write(request_root / 'cpu.json', {
        'schema_version': 'local_harness.v1', 'profile_path': CPU_PROFILE,
        'instance_id': 'cpu', 'reset_assert_ticks': 2,
        'reset_release_ticks': 2, 'max_wait_cycles': 16,
    })
    _write(request_root / 'uart.json', {
        'schema_version': 'local_harness.v1', 'profile_path': uart_profile,
        'instance_id': 'uart', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })
    _write(request_root / 'dma.json', {
        'schema_version': 'local_harness.v1', 'profile_path': DMA_PROFILE,
        'instance_id': 'dma', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })
    generated = generate_harness_set(compose, base_dir=ROOT,
        compose_base=tmp_path, output_root=tmp_path / 'ot_uart_generated')
    wiring_path = tmp_path / 'ot_uart_generated' / 'wiring_contract.json'
    wiring = json.loads(wiring_path.read_text(encoding='utf-8'))
    assert generated['schema_version'] == 'harness_set.v2'
    assert wiring['schema_version'] == 'wiring_contract.v2'

    dma_capability = _dma_test_capability(
        ROOT / DMA_PROFILE, tmp_path / 'test_capabilities/dma.json')
    uart_capability = _uart_test_capability(
        ROOT / uart_profile, tmp_path / 'test_capabilities/uart.json')
    compile_request_path = _write(tmp_path / 'ot_uart_path_compile_request.json', {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': 'cpu', 'profile': CPU_PROFILE,
                'data_endpoint': 'processor.data',
                'instruction_endpoint': 'processor.instruction'},
        'devices': [
            {'device_id': 'uart', 'instance_id': 'uart',
             'profile': uart_profile, 'test_capability': str(uart_capability)},
            {'device_id': 'dma.control', 'instance_id': 'dma',
             'profile': DMA_PROFILE, 'test_capability': str(dma_capability)},
        ],
        'wiring': {'source': str(wiring_path)},
    })
    request = load_path_compile_request(compile_request_path, base_dir=ROOT)
    compiled = compile_paths(request)
    return wiring, request, compiled


def _gpio_test_capability(profile_path: Path, output: Path) -> Path:
    profile = load_component_profile(profile_path)
    return _write(output, {
        'schema_version': 'ip_test_capability.v3',
        'component_id': profile.component_id,
        'profile_fingerprint': profile.profile_fingerprint,
        'endpoint_capabilities': [{'endpoint_id': 'gpio.bus',
                                   'operations': ['read', 'write']}],
        'register_semantics': [], 'observation_mappings': [],
        'register_aliases': [],
    })


def _generate_pulp_gpio_dma_route_d2_d3(tmp_path: Path, *,
        ram_base=0x1000, ram_size=0x1000, cpu_profile=None,
        rom_base=None, rom_size=0x8000):
    """Create D2/D3 route rows for one RAM read and one PULP PADOUT write."""
    from myfuzz.scenario.compiled_paths import load_path_compile_request

    cpu_profile = CPU_PROFILE if cpu_profile is None else str(cpu_profile)
    gpio_profile = 'configs/peripherals/pulp_gpio_causal_local/component_profile.json'
    gpio_base, gpio_size = 0x40001000, 0x1000
    rom_base = max(0x10000, ram_base + ram_size) if rom_base is None else rom_base
    values = [0x5aa55aa5]
    template_dma_master = {
        'template_id': 'master.wishbone-pipelined', 'template_version': '1',
        'variant_id': 'dma-full-word-no-select',
    }
    route_rows = [
        {
            'route_id': 'route.ram-read', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'persistent_memory', 'component_instance': 'cpu',
                       'resource_id': 'ram'},
            'base': ram_base, 'size': ram_size, 'operation': 'read',
            'permissions': ['read', 'write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [],
            'accepted_write_values': {'kind': 'values', 'values': []},
        },
        {
            'route_id': 'route.gpio-padout', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'peripheral', 'component_instance': 'gpio',
                       'device_id': 'gpio', 'endpoint_id': 'gpio.bus'},
            'base': gpio_base, 'size': gpio_size, 'operation': 'write',
            'permissions': ['write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [12],
            'accepted_write_values': {'kind': 'values', 'values': values},
        },
    ]
    compose_path = _write(tmp_path / 'pulp_gpio_compose.json', {
        'schema_version': 'harness_compose.v2',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [
            {'device_id': 'gpio', 'instance_id': 'gpio',
             'request': 'requests/gpio.json', 'bus_endpoint': 'gpio.bus',
             'base': gpio_base, 'size': gpio_size,
             'template': {'template_id': 'target.apb3',
                          'template_version': '1', 'variant_id': 'full-word'}},
            {'device_id': 'dma.control', 'instance_id': 'dma',
             'request': 'requests/dma.json', 'bus_endpoint': 'dma.control',
             'base': 0x40002000, 'size': 16,
             'template': {'template_id': 'target.wishbone-pipelined',
                          'template_version': '1',
                          'variant_id': 'dma-full-word-no-select'}},
        ],
        'memory': [
            {'resource_id': 'rom0', 'component_instance': 'cpu',
             'base': rom_base, 'size': rom_size,
             'read': True, 'write': False, 'execute': True},
            {'resource_id': 'ram', 'component_instance': 'cpu',
             'base': ram_base, 'size': ram_size,
             'read': True, 'write': True, 'execute': False},
        ],
        'dma_master_routes': {
            'schema_version': 'dma_master_route_intent.v1', 'routes': route_rows,
        },
        'dma_master_route_bindings': [
            {'route_id': 'route.ram-read', 'initiator_template': template_dma_master},
            {'route_id': 'route.gpio-padout', 'initiator_template': template_dma_master,
             'target_template': {'template_id': 'target.apb3',
                                 'template_version': '1',
                                 'variant_id': 'full-word'}},
        ],
    })
    compose = load_compose(compose_path, base_dir=ROOT)
    request_root = tmp_path / 'requests'
    for name, profile, instance in (
            ('cpu', cpu_profile, 'cpu'), ('gpio', gpio_profile, 'gpio'),
            ('dma', DMA_PROFILE, 'dma')):
        _write(request_root / f'{name}.json', {
            'schema_version': 'local_harness.v1', 'profile_path': profile,
            'instance_id': instance, 'reset_assert_ticks': 8,
            'reset_release_ticks': 8, 'max_wait_cycles': 16,
        })
    generated = generate_harness_set(compose, base_dir=ROOT,
        compose_base=tmp_path, output_root=tmp_path / 'pulp_gpio_generated')
    wiring_path = tmp_path / 'pulp_gpio_generated' / 'wiring_contract.json'
    d2_wiring = json.loads(wiring_path.read_text(encoding='utf-8'))
    assert generated['schema_version'] == 'harness_set.v2'
    assert d2_wiring['dma_master_routes']['routes'] == sorted(
        route_rows, key=lambda row: row['route_id'])

    dma_capability = _dma_test_capability(
        ROOT / DMA_PROFILE, tmp_path / 'test_capabilities/pulp-dma.json')
    gpio_capability = _gpio_test_capability(
        ROOT / gpio_profile, tmp_path / 'test_capabilities/pulp-gpio.json')
    compile_request_path = _write(tmp_path / 'pulp_gpio_path_compile_request.json', {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': 'cpu', 'profile': cpu_profile,
                'data_endpoint': 'processor.data',
                'instruction_endpoint': 'processor.instruction'},
        'devices': [
            {'device_id': 'gpio', 'instance_id': 'gpio',
             'profile': gpio_profile, 'test_capability': str(gpio_capability)},
            {'device_id': 'dma.control', 'instance_id': 'dma',
             'profile': DMA_PROFILE, 'test_capability': str(dma_capability)},
        ],
        'wiring': {'source': str(wiring_path)},
    })
    request = load_path_compile_request(compile_request_path, base_dir=ROOT)
    compiled = compile_paths(request)
    return d2_wiring, request, compiled


def _wishbone_uart_test_capability(profile_path: Path, output: Path) -> Path:
    profile = load_component_profile(profile_path)
    return _write(output, {
        'schema_version': 'ip_test_capability.v3',
        'component_id': profile.component_id,
        'profile_fingerprint': profile.profile_fingerprint,
        'endpoint_capabilities': [{'endpoint_id': 'uart.bus',
                                   'operations': ['read', 'write']}],
        'register_semantics': [], 'observation_mappings': [],
        'register_aliases': [],
    })


def _generate_zipcpu_uart_dma_route_d2_d3(tmp_path: Path, *,
        ram_base=0x1000, ram_size=0x1000):
    """Generate RAM-read and ZipCPU UART TXREG-write rows through D2/D3."""
    from myfuzz.scenario.compiled_paths import load_path_compile_request

    uart_profile = 'configs/peripherals/zipcpu_uart/component_profile.json'
    uart_base, uart_size = 0x40003000, 0x10
    rom_base = max(0x10000, ram_base + ram_size)
    template_dma_master = {
        'template_id': 'master.wishbone-pipelined', 'template_version': '1',
        'variant_id': 'dma-full-word-no-select',
    }
    route_rows = [
        {
            'route_id': 'route.ram-read', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'persistent_memory', 'component_instance': 'cpu',
                       'resource_id': 'ram'},
            'base': ram_base, 'size': ram_size, 'operation': 'read',
            'permissions': ['read', 'write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [],
            'accepted_write_values': {'kind': 'values', 'values': []},
        },
        {
            'route_id': 'route.uart-txreg', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'peripheral', 'component_instance': 'uart',
                       'device_id': 'uart', 'endpoint_id': 'uart.bus'},
            'base': uart_base, 'size': uart_size, 'operation': 'write',
            'permissions': ['write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [12],
            'accepted_write_values': {
                'kind': 'range', 'start': 0, 'stop': 256, 'step': 1},
        },
    ]
    compose_path = _write(tmp_path / 'zipcpu_uart_compose.json', {
        'schema_version': 'harness_compose.v2',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [
            {'device_id': 'uart', 'instance_id': 'uart',
             'request': 'requests/uart.json', 'bus_endpoint': 'uart.bus',
             'base': uart_base, 'size': uart_size,
             'template': {'template_id': 'target.wishbone',
                          'template_version': '1',
                          'variant_id': 'word-addressed-registered-ack'}},
            {'device_id': 'dma.control', 'instance_id': 'dma',
             'request': 'requests/dma.json', 'bus_endpoint': 'dma.control',
             'base': 0x40002000, 'size': 16,
             'template': {'template_id': 'target.wishbone-pipelined',
                          'template_version': '1',
                          'variant_id': 'dma-full-word-no-select'}},
        ],
        'memory': [
            {'resource_id': 'rom0', 'component_instance': 'cpu',
             'base': rom_base, 'size': 0x8000,
             'read': True, 'write': False, 'execute': True},
            {'resource_id': 'ram', 'component_instance': 'cpu',
             'base': ram_base, 'size': ram_size,
             'read': True, 'write': True, 'execute': False},
        ],
        'dma_master_routes': {
            'schema_version': 'dma_master_route_intent.v1', 'routes': route_rows,
        },
        'dma_master_route_bindings': [
            {'route_id': 'route.ram-read',
             'initiator_template': template_dma_master},
            {'route_id': 'route.uart-txreg',
             'initiator_template': template_dma_master,
             'target_template': {'template_id': 'target.wishbone',
                                 'template_version': '1',
                                 'variant_id': 'word-addressed-registered-ack'}},
        ],
    })
    compose = load_compose(compose_path, base_dir=ROOT)
    request_root = tmp_path / 'requests'
    for name, profile, instance in (
            ('cpu', CPU_PROFILE, 'cpu'), ('uart', uart_profile, 'uart'),
            ('dma', DMA_PROFILE, 'dma')):
        _write(request_root / f'{name}.json', {
            'schema_version': 'local_harness.v1', 'profile_path': profile,
            'instance_id': instance, 'reset_assert_ticks': 8,
            'reset_release_ticks': 8, 'max_wait_cycles': 16,
        })
    generated = generate_harness_set(compose, base_dir=ROOT,
        compose_base=tmp_path, output_root=tmp_path / 'zipcpu_uart_generated')
    wiring_path = tmp_path / 'zipcpu_uart_generated' / 'wiring_contract.json'
    d2_wiring = json.loads(wiring_path.read_text(encoding='utf-8'))
    assert generated['schema_version'] == 'harness_set.v2'
    assert d2_wiring['schema_version'] == 'wiring_contract.v2'

    dma_capability = _dma_test_capability(
        ROOT / DMA_PROFILE, tmp_path / 'test_capabilities/zipcpu-dma.json')
    uart_capability = _wishbone_uart_test_capability(
        ROOT / uart_profile, tmp_path / 'test_capabilities/zipcpu-uart.json')
    compile_request_path = _write(
        tmp_path / 'zipcpu_uart_path_compile_request.json', {
            'schema_version': 'path_compile_request.v1',
            'cpu': {'instance_id': 'cpu', 'profile': CPU_PROFILE,
                    'data_endpoint': 'processor.data',
                    'instruction_endpoint': 'processor.instruction'},
            'devices': [
                {'device_id': 'uart', 'instance_id': 'uart',
                 'profile': uart_profile,
                 'test_capability': str(uart_capability)},
                {'device_id': 'dma.control', 'instance_id': 'dma',
                 'profile': DMA_PROFILE,
                 'test_capability': str(dma_capability)},
            ],
            'wiring': {'source': str(wiring_path)},
        })
    request = load_path_compile_request(compile_request_path, base_dir=ROOT)
    compiled = compile_paths(request)
    return d2_wiring, request, compiled


def _caliptra_test_capability(profile_path: Path, output: Path) -> Path:
    profile = load_component_profile(profile_path)
    return _write(output, {
        'schema_version': 'ip_test_capability.v3',
        'component_id': profile.component_id,
        'profile_fingerprint': profile.profile_fingerprint,
        'endpoint_capabilities': [{'endpoint_id': 'sha256.bus',
                                   'operations': ['read', 'write']}],
        'register_semantics': [], 'observation_mappings': [],
        'register_aliases': [],
    })


def _generate_caliptra_sha256_dma_route_d2_d3(
        tmp_path: Path, *, ram_base: int = 0x1000, ram_size: int = 0x1000,
        ram_executable: bool = False):
    """Generate a RAM-read and Caliptra CTRL-write route through D2/D3."""
    from myfuzz.scenario.compiled_paths import load_path_compile_request

    sha_profile = 'configs/peripherals/caliptra_sha256/component_profile.json'
    sha_base, sha_size = 0x40002000, 0x1000
    dma_master_template = {
        'template_id': 'master.wishbone-pipelined', 'template_version': '1',
        'variant_id': 'dma-full-word-no-select',
    }
    route_rows = [
        {
            'route_id': 'route.ram-read', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'persistent_memory', 'component_instance': 'cpu',
                       'resource_id': 'ram'},
            'base': ram_base, 'size': ram_size, 'operation': 'read',
            'permissions': ['read', 'write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [],
            'accepted_write_values': {'kind': 'values', 'values': []},
        },
        {
            'route_id': 'route.caliptra-ctrl', 'initiator_instance': 'dma',
            'initiator_endpoint_id': 'dma.memory',
            'target': {'kind': 'peripheral', 'component_instance': 'sha',
                       'device_id': 'sha', 'endpoint_id': 'sha256.bus'},
            'base': sha_base, 'size': sha_size, 'operation': 'write',
            'permissions': ['write'], 'byte_enable': 15,
            'readable_offsets': [], 'writable_offsets': [16],
            'accepted_write_values': {'kind': 'values', 'values': [5]},
        },
    ]
    compose_path = _write(tmp_path / 'caliptra_compose.json', {
        'schema_version': 'harness_compose.v2',
        'cpu': {'instance_id': 'cpu', 'request': 'requests/cpu.json',
                'data_endpoint': 'processor.data'},
        'devices': [
            {'device_id': 'sha', 'instance_id': 'sha',
             'request': 'requests/sha.json', 'bus_endpoint': 'sha256.bus',
             'base': sha_base, 'size': sha_size,
             'template': {'template_id': 'target.ahb-lite',
                          'template_version': '1',
                          'variant_id': 'full-word-single'}},
            {'device_id': 'dma.control', 'instance_id': 'dma',
             'request': 'requests/dma.json', 'bus_endpoint': 'dma.control',
             'base': 0x40001000, 'size': 16,
             'template': {'template_id': 'target.wishbone-pipelined',
                          'template_version': '1',
                          'variant_id': 'dma-full-word-no-select'}},
        ],
        'memory': [
            {'resource_id': 'rom0', 'component_instance': 'cpu',
             'base': max(0x10000, ram_base + ram_size), 'size': 0x8000,
             'read': True, 'write': False, 'execute': True},
            {'resource_id': 'ram', 'component_instance': 'cpu',
             'base': ram_base, 'size': ram_size,
             'read': True, 'write': True, 'execute': ram_executable},
        ],
        'dma_master_routes': {
            'schema_version': 'dma_master_route_intent.v1', 'routes': route_rows,
        },
        'dma_master_route_bindings': [
            {'route_id': 'route.ram-read',
             'initiator_template': dma_master_template},
            {'route_id': 'route.caliptra-ctrl',
             'initiator_template': dma_master_template,
             'target_template': {'template_id': 'target.ahb-lite',
                                 'template_version': '1',
                                 'variant_id': 'full-word-single'}},
        ],
    })
    compose = load_compose(compose_path, base_dir=ROOT)
    request_root = tmp_path / 'requests'
    _write(request_root / 'cpu.json', {
        'schema_version': 'local_harness.v1', 'profile_path': CPU_PROFILE,
        'instance_id': 'cpu', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })
    sha_request = _write(request_root / 'sha.json', {
        'schema_version': 'local_harness.v2', 'profile_path': sha_profile,
        'instance_id': 'sha', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
        'tuning': {'endpoint_policies': [{
            'endpoint_id': 'sha256.bus', 'template_id': 'target.ahb-lite',
            'template_version': '1', 'variant_id': 'full-word-single',
            'max_outstanding': 1,
        }]},
    })
    _write(request_root / 'dma.json', {
        'schema_version': 'local_harness.v1', 'profile_path': DMA_PROFILE,
        'instance_id': 'dma', 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })
    generated = generate_harness_set(compose, base_dir=ROOT,
        compose_base=tmp_path, output_root=tmp_path / 'caliptra_generated')
    wiring_path = tmp_path / 'caliptra_generated' / 'wiring_contract.json'
    d2_wiring = json.loads(wiring_path.read_text(encoding='utf-8'))
    assert generated['schema_version'] == 'harness_set.v2'
    assert d2_wiring['dma_master_routes']['routes'] == sorted(
        route_rows, key=lambda row: row['route_id'])

    dma_capability = _dma_test_capability(
        ROOT / DMA_PROFILE, tmp_path / 'test_capabilities/caliptra-dma.json')
    sha_capability = _caliptra_test_capability(
        ROOT / sha_profile, tmp_path / 'test_capabilities/caliptra-sha.json')
    compile_request_path = _write(
        tmp_path / 'caliptra_path_compile_request.json', {
            'schema_version': 'path_compile_request.v1',
            'cpu': {'instance_id': 'cpu', 'profile': CPU_PROFILE,
                    'data_endpoint': 'processor.data',
                    'instruction_endpoint': 'processor.instruction'},
            'devices': [
                {'device_id': 'sha', 'instance_id': 'sha',
                 'profile': sha_profile,
                 'test_capability': str(sha_capability)},
                {'device_id': 'dma.control', 'instance_id': 'dma',
                 'profile': DMA_PROFILE,
                 'test_capability': str(dma_capability)},
            ],
            'wiring': {'source': str(wiring_path)},
        })
    request = load_path_compile_request(compile_request_path, base_dir=ROOT)
    compiled = compile_paths(request)
    return d2_wiring, request, compiled


def _pulp_typed_dma_fixture(issued, gpio_artifact, tmp_path):
    """Build the existing typed PULP graph over actual generated sessions."""
    from myfuzz.local_harness import GeneratedLocalSession
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
    from myfuzz.scenario.pulp_gpio_dma_paths import (
        DEFAULT_DIRECTION, GPIO_PADOUT_NODE, GPIO_PADOUT_OFFSET, RAM_SOURCE_NODE,
        RULES, _route_declarations)
    from myfuzz.scenario.runtime_path_contract import (
        PreparedRuntimePathContract, RuntimeEdgeContract, RuntimeNode, RuntimePathContract)
    from tests.scenario.test_dma_intent_topology_binding import live_fixture

    _, runner, artifact_links, _ = live_fixture(issued, tmp_path)
    memory = runner.sessions['cpu'].memory
    cpu_artifact = _local_artifact(CPU_PROFILE, 'cpu')
    cpu_session = GeneratedLocalSession(cpu_artifact, base_dir=tmp_path,
                                        cache_dir=tmp_path)
    cpu_session.memory = memory
    cpu_session.command = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError('runtime command reached'))
    runner.sessions['cpu'] = cpu_session
    gpio = GeneratedPulpGpioSession(gpio_artifact, base_dir=tmp_path,
                                    cache_dir=tmp_path)
    runner.sessions.pop('uart', None)
    runner.sessions['gpio'] = gpio
    window = MasterTargetWindow('gpio', 0x40001000, 0x1000, gpio,
                                (GPIO_PADOUT_OFFSET,), (0x5aa55aa5,))
    dma = runner.sessions['dma']
    dma.master_targets = (window,)
    region, _, routes = _route_declarations(runner, gpio_base=window.base,
        gpio_size=window.size, memory_component='cpu', resource_id='ram',
        image_id='dma_payload', direction=DEFAULT_DIRECTION)

    graph = DependencyGraph(
        sources=(FuzzableSource(RAM_SOURCE_NODE, 'cpu', 'dma_payload', 0, 32,
            (DEFAULT_DIRECTION,), kind='memory_image', image_address=region.base),),
        rules=tuple(DependencyRule(target, prerequisites, kind)
                    for target, prerequisites, kind in RULES))
    nodes = (
        RuntimeNode(RAM_SOURCE_NODE, 'cpu', 'state'),
        RuntimeNode('dma.read_data', 'dma', 'logical'),
        RuntimeNode('dma.write_data', 'dma', 'logical'),
        RuntimeNode(GPIO_PADOUT_NODE, 'gpio', 'state'),
    )
    edges = (RuntimeEdgeContract(0, 0, 'dma_master_route'),
             RuntimeEdgeContract(1, 0, 'causal_order'),
             RuntimeEdgeContract(2, 0, 'dma_master_route'))
    contract = RuntimePathContract(_canonical_sha256(graph.edge_document()),
                                   nodes, edges, dma_master_routes=routes)
    paths = graph.edge_paths_to(GPIO_PADOUT_NODE, direction=DEFAULT_DIRECTION,
                                max_depth=8, max_paths=2)
    assert len(paths) == 1
    prepared = PreparedRuntimePathContract(graph, contract,
        ((DEFAULT_DIRECTION, paths[0]),))
    return runner, artifact_links, prepared


def _dma_intent_route_matches(intent, route):
    """Compare route policy only; endpoint aliases are checked by the binder."""
    target = intent.target
    static_target_id = (target.get('device_id') if target.get('kind') == 'peripheral'
                        else target.get('resource_id'))
    return (
        intent.initiator_instance == route.initiator_component
        and target.get('kind') == route.target_kind
        and target.get('component_instance') == route.target_component
        and static_target_id == route.target_id
        and (intent.base, intent.size, intent.operation, intent.permissions,
             intent.byte_enable, intent.readable_offsets, intent.writable_offsets,
             intent.accepted_write_values)
            == (route.base, route.size, route.operation, route.permissions,
                route.byte_enable, route.readable_offsets, route.writable_offsets,
                route.accepted_write_values))


def _unique_dma_intent_route_map(d3_wiring, prepared):
    """Build the explicit route bijection without route-name/order selection."""
    routes = tuple(prepared.contract.dma_master_routes)
    if len(routes) != len(d3_wiring.dma_master_routes):
        raise AssertionError('static and prepared DMA route counts differ')
    mapping = []
    used = set()
    for intent in d3_wiring.dma_master_routes:
        candidates = [route for route in routes
                      if _dma_intent_route_matches(intent, route)]
        if len(candidates) != 1 or candidates[0].key in used:
            raise AssertionError(
                'static DMA route policy does not map to one unique prepared route')
        route = candidates[0]
        used.add(route.key)
        mapping.append((intent, route))
    if used != {route.key for route in routes}:
        raise AssertionError('static DMA route mapping is not a complete bijection')
    return tuple(mapping)


def _select_dma_read_write_routes(prepared):
    """Select one route per operation without depending on contract order."""
    routes = tuple(prepared.contract.dma_master_routes)
    reads = [route for route in routes if route.operation == 'read']
    writes = [route for route in routes if route.operation == 'write']
    if len(routes) != 2 or len(reads) != 1 or len(writes) != 1:
        raise AssertionError('expected exactly one typed DMA read and write route')
    return reads[0], writes[0]


def _dma_d4_declaration(d3_wiring, prepared, artifact_links):
    from myfuzz.scenario.dma_intent_topology_binding import prepare_dma_intent_binding

    rows = []
    for intent, route in _unique_dma_intent_route_map(d3_wiring, prepared):
        link_document = artifact_links[intent.initiator_instance]
        physical, = link_document['links']
        exact = intent.initiator_endpoint_id == route.endpoint_id
        rows.append({
            'route_id': intent.route_id,
            'rule_index': route.rule_index,
            'prerequisite_index': route.prerequisite_index,
            'runtime_route_sha256': route.identity_sha256,
            'endpoint_link': {
                'mode': 'exact_id' if exact else 'explicit_alias',
                'static_endpoint_id': intent.initiator_endpoint_id,
                'runtime_endpoint_id': route.endpoint_id,
                'artifact_endpoint_id': physical['endpoint_id'],
                'artifact_link_id': physical['link_id'],
                'artifact_link_provider_id': link_document['provider_id'],
                'operation': route.operation,
                'template_binding': physical['template_binding'],
            },
        })
    return prepare_dma_intent_binding(d3_wiring, prepared, route_links=rows)


def _pulp_d4_declaration(d3_wiring, prepared, artifact_links):
    return _dma_d4_declaration(d3_wiring, prepared, artifact_links)


def _zipcpu_uart_typed_dma_fixture(issued, uart_artifact, tmp_path):
    """Build the existing keyed RAM -> ZipCPU TXREG graph over real sessions."""
    from myfuzz.local_harness import GeneratedLocalSession
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.local_harness.wishbone_uart_session import GeneratedWishboneUartSession
    from myfuzz.scenario.zipcpu_uart_dma_paths import prepare_zipcpu_uart_dma_runtime_paths
    from tests.scenario.test_dma_intent_topology_binding import live_fixture

    _, runner, artifact_links, _ = live_fixture(issued, tmp_path)
    memory = runner.sessions['cpu'].memory
    cpu = GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'),
        base_dir=tmp_path, cache_dir=tmp_path)
    cpu.memory = memory
    cpu.command = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError('runtime command reached'))
    runner.sessions['cpu'] = cpu

    uart = GeneratedWishboneUartSession(uart_artifact,
        base_dir=tmp_path, cache_dir=tmp_path, source=b'',
        startup_writes=((0, 25, 15),))
    runner.sessions['uart'] = uart
    window = MasterTargetWindow('uart', 0x40003000, 0x10, uart,
        (12,), range(256), byte_enable=15)
    runner.sessions['dma'].master_targets = (window,)
    paths = prepare_zipcpu_uart_dma_runtime_paths(runner,
        image_id='dma_payload')
    assert runner.sessions['dma']._dma_route_validator is None
    assert runner.sessions['dma']._dma_route_admission is None
    return runner, artifact_links, paths.prepared, paths, window


def _caliptra_typed_dma_fixture(issued, sha_artifact, tmp_path):
    """Build the existing RAM-word -> Caliptra CTRL typed graph without bind."""
    from myfuzz.local_harness import GeneratedLocalSession
    from myfuzz.local_harness.ahb_lite_register_session import (
        GeneratedAhbLiteRegisterSession)
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.scenario.caliptra_sha256_dma_paths import (
        prepare_caliptra_sha256_dma_runtime_paths)
    from tests.scenario.test_dma_intent_topology_binding import live_fixture

    _, runner, artifact_links, _ = live_fixture(issued, tmp_path)
    memory = runner.sessions['cpu'].memory
    cpu = GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'),
        base_dir=tmp_path, cache_dir=tmp_path)
    cpu.memory = memory
    cpu.command = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError('runtime command reached'))
    runner.sessions['cpu'] = cpu
    runner.sessions.pop('uart', None)

    sha = GeneratedAhbLiteRegisterSession(sha_artifact,
        base_dir=tmp_path, cache_dir=tmp_path)
    runner.sessions['sha'] = sha
    window = MasterTargetWindow('sha', 0x40002000, 0x1000, sha,
        (16,), (5,), byte_enable=15)
    runner.sessions['dma'].master_targets = (window,)
    paths = prepare_caliptra_sha256_dma_runtime_paths(runner,
        image_id='dma_payload')
    assert runner.sessions['dma']._dma_route_validator is None
    assert runner.sessions['dma']._dma_route_admission is None
    return runner, artifact_links, paths, window


def _caliptra_d4_declaration(d3_wiring, prepared, artifact_links):
    return _dma_d4_declaration(d3_wiring, prepared, artifact_links)


def _zipcpu_uart_d4_declaration(d3_wiring, prepared, artifact_links):
    return _dma_d4_declaration(d3_wiring, prepared, artifact_links)


def test_d4_route_mapping_is_policy_unique_and_name_independent():
    from types import SimpleNamespace
    from tests.scenario.test_dma_intent_topology_binding import fixture

    wiring, prepared, _links = fixture()
    mapping = _unique_dma_intent_route_map(wiring, prepared)
    assert len(mapping) == len(wiring.dma_master_routes)
    assert {intent.operation for intent, _route in mapping} == {'read', 'write'}
    assert all(_dma_intent_route_matches(intent, route)
               for intent, route in mapping)
    selected = _select_dma_read_write_routes(prepared)
    assert selected == (
        next(route for _intent, route in mapping if route.operation == 'read'),
        next(route for _intent, route in mapping if route.operation == 'write'))
    reversed_prepared = SimpleNamespace(contract=SimpleNamespace(
        dma_master_routes=tuple(reversed(prepared.contract.dma_master_routes))))
    assert _select_dma_read_write_routes(reversed_prepared) == selected

    ambiguous_wiring, ambiguous_prepared, _links = fixture(identical=True)
    with pytest.raises(AssertionError,
                       match='does not map to one unique prepared route'):
        _unique_dma_intent_route_map(ambiguous_wiring, ambiguous_prepared)


def test_d2_d3_route_binds_existing_typed_topology_and_keeps_f6_closed(tmp_path):
    from copy import deepcopy
    from unittest.mock import patch

    from myfuzz.local_harness import GeneratedLocalSession
    from myfuzz.scenario.dependency import DependencyGraph
    from myfuzz.scenario.dma_intent_topology_binding import (
        bind_dma_intent_topology, prepare_dma_intent_binding)
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.scenario.test_dma_intent_topology_binding import (
        generated_instance, peripheral_fixture)

    d2_wiring, request, compiled = _generate_ot_uart_dma_route_d2_d3(tmp_path)
    d3_wiring = request.wiring
    assert d3_wiring.document['dma_master_routes'] == d2_wiring['dma_master_routes']
    assert d3_wiring.document['dma_master_route_bindings'] == \
        d2_wiring['dma_master_route_bindings']
    route_digest = d2_wiring['dma_master_routes_sha256']
    binding_digest = _canonical_sha256(d2_wiring['dma_master_route_bindings'])
    assert compiled['identity']['wiring']['dma_master_routes_sha256'] == route_digest
    assert compiled['identity']['wiring']['dma_master_route_bindings_sha256'] == binding_digest

    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    missing_codes = {row['code'] for row in f6['reason']['missing']}
    assert f6['status'] == 'unsupported'
    assert 'dma-route-live-topology-binding-required' in missing_codes
    assert f6['runtime_path_identity'] is None
    assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_dependency_graph']['edges'])
    assert not any(edge.get('relation') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_path_contract']['edges'])

    issued = generated_instance('dma')
    uart_artifact = _local_artifact(
        'configs/peripherals/opentitan_uart_local/component_profile.json', 'uart')
    base_declaration, runner, artifact_links = peripheral_fixture(
        issued, uart_artifact, tmp_path)
    base_document = base_declaration.document()
    original_prepared = PreparedRuntimePathContract.from_document(
        base_document['prepared_runtime_paths'])
    original_prepared_bytes = _canonical_sha256(original_prepared.document())
    original_runtime_bytes = _canonical_sha256(
        original_prepared.contract.document())

    cpu_artifact = _local_artifact(CPU_PROFILE, 'cpu')
    cpu_memory = runner.sessions['cpu'].memory
    cpu_session = GeneratedLocalSession(cpu_artifact, base_dir=tmp_path,
                                        cache_dir=tmp_path)
    cpu_session.memory = cpu_memory
    cpu_session.command = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError('runtime command reached'))
    runner.sessions['cpu'] = cpu_session

    route_links = base_document['route_links']
    declaration = prepare_dma_intent_binding(
        d3_wiring, original_prepared, route_links=route_links)
    declaration_document = declaration.document()
    assert declaration_document['wiring']['dma_master_routes'] == \
        d2_wiring['dma_master_routes']
    assert declaration_document['wiring']['dma_master_route_bindings'] == \
        d2_wiring['dma_master_route_bindings']
    assert _canonical_sha256(declaration_document['prepared_runtime_paths']) == \
        original_prepared_bytes
    assert _canonical_sha256(declaration_document['prepared_runtime_paths']['contract']) == \
        original_runtime_bytes

    from myfuzz.scenario.dma_intent_topology_binding import _target_binding
    for row in declaration_document['route_links']:
        intent = next(value for value in d3_wiring.dma_master_routes
                      if value.route_id == row['route_id'])
        expected_target = next(value for value in d2_wiring['dma_master_route_bindings']
                               if value['route_id'] == row['route_id'])['target']
        actual_target = _target_binding(d3_wiring, intent,
            runner.sessions[intent.target['component_instance']], '/test')
        assert actual_target == expected_target, (row['route_id'], actual_target,
                                                  expected_target)

    existing_graph_document = original_prepared.graph.edge_document()
    expected_compilation = original_prepared.bind(deepcopy(runner)).document()
    graph_constructions = []
    original_graph_init = DependencyGraph.__init__

    def graph_init_spy(graph, *args, **kwargs):
        graph_constructions.append((args, kwargs))
        return original_graph_init(graph, *args, **kwargs)

    prepared_constructions = []
    original_prepared_init = PreparedRuntimePathContract.__init__
    prepared_bind_objects = []
    original_prepared_bind = PreparedRuntimePathContract.bind

    def prepared_init_spy(prepared, *args, **kwargs):
        prepared_constructions.append((args, kwargs))
        return original_prepared_init(prepared, *args, **kwargs)

    def prepared_bind_spy(prepared, *args, **kwargs):
        prepared_bind_objects.append(prepared)
        return original_prepared_bind(prepared, *args, **kwargs)

    with patch.object(DependencyGraph, '__init__', graph_init_spy), \
         patch.object(PreparedRuntimePathContract, '__init__', prepared_init_spy), \
         patch.object(PreparedRuntimePathContract, 'bind', prepared_bind_spy):
        bound = bind_dma_intent_topology(
            declaration, runner, artifact_links=artifact_links)
        bound.validate_topology()

    new_runtime_graph_was_created = bool(graph_constructions or prepared_constructions)
    assert not new_runtime_graph_was_created
    assert prepared_bind_objects == [original_prepared]
    assert bound.document()['tier'] == 'topology_bound'
    assert bound.runtime_compilation.document()['contract_sha256'] == \
        original_prepared.contract.identity_sha256
    assert bound.runtime_compilation.document()['paths'] == \
        expected_compilation['paths']


@pytest.fixture(scope='module')
def pulp_gpio_d2_d3_material(tmp_path_factory):
    return _generate_pulp_gpio_dma_route_d2_d3(
        tmp_path_factory.mktemp('pulp-gpio-d2-d3'))


@pytest.fixture(scope='module')
def pulp_gpio_observed_artifact():
    return _local_artifact(
        'configs/peripherals/pulp_gpio_causal_local/component_profile.json', 'gpio')


@pytest.fixture(scope='module')
def pulp_gpio_unobserved_artifact():
    return _local_artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio')


@pytest.fixture(scope='module')
def caliptra_d2_d3_material(tmp_path_factory):
    return _generate_caliptra_sha256_dma_route_d2_d3(
        tmp_path_factory.mktemp('caliptra-d2-d3'))


@pytest.fixture(scope='module')
def caliptra_sha_artifact():
    return _caliptra_sha256_artifact()


def test_caliptra_ram_geometry(tmp_path):
    default_wiring, default_request, default_compiled = \
        _generate_caliptra_sha256_dma_route_d2_d3(tmp_path / 'default')
    native_wiring, native_request, native_compiled = \
        _generate_caliptra_sha256_dma_route_d2_d3(
            tmp_path / 'native', ram_base=0x10000, ram_size=0x20000)

    def check(wiring, request, compiled, base, size, rom_base):
        route = next(row for row in wiring['dma_master_routes']['routes']
                     if row['route_id'] == 'route.ram-read')
        ram = next(row for row in wiring['resources'] if row['resource_id'] == 'ram')
        rom = next(row for row in wiring['resources'] if row['resource_id'] == 'rom0')
        assert (route['base'], route['size']) == (base, size)
        assert (ram['base'], ram['size']) == (base, size)
        assert rom['base'] == rom_base
        request_ram = next(row for row in request.wiring.document['resources']
                           if row['resource_id'] == 'ram')
        request_rom = next(row for row in request.wiring.document['resources']
                           if row['resource_id'] == 'rom0')
        assert (request_ram['base'], request_ram['size']) == (base, size)
        assert request_rom['base'] == rom_base
        f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
        assert f6['status'] == 'unsupported'
        runtime_graph = compiled.get('runtime_dependency_graph') or {}
        assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
                       for edge in runtime_graph.get('edges', []))

    check(default_wiring, default_request, default_compiled, 0x1000, 0x1000, 0x10000)
    check(native_wiring, native_request, native_compiled, 0x10000, 0x20000, 0x30000)


def test_pulp_gpio_cv32_route_geometry_and_default_ibex_profile(tmp_path):
    default_wiring, default_request, _ = \
        _generate_pulp_gpio_dma_route_d2_d3(tmp_path / 'default')
    cv32_wiring, cv32_request, cv32_compiled = \
        _generate_pulp_gpio_dma_route_d2_d3(
            tmp_path / 'cv32',
            cpu_profile=Path('configs/cpus/cv32e40p/component_profile.json'),
            rom_base=0x10000, rom_size=0x8000,
            ram_base=0x20000, ram_size=0x20000)

    default_ram = next(row for row in default_wiring['resources']
                       if row['resource_id'] == 'ram')
    default_rom = next(row for row in default_wiring['resources']
                       if row['resource_id'] == 'rom0')
    assert (default_ram['base'], default_ram['size']) == (0x1000, 0x1000)
    assert (default_rom['base'], default_rom['size']) == (0x10000, 0x8000)
    assert default_request.cpu.profile.component_id == 'ibex_obi_local'

    cv32_route = next(row for row in cv32_wiring['dma_master_routes']['routes']
                      if row['route_id'] == 'route.ram-read')
    cv32_ram = next(row for row in cv32_wiring['resources']
                    if row['resource_id'] == 'ram')
    cv32_rom = next(row for row in cv32_wiring['resources']
                    if row['resource_id'] == 'rom0')
    cv32_dma_window = next(row for row in cv32_wiring['windows']
                           if row['device_id'] == 'dma.control')
    assert cv32_request.cpu.profile.component_id == 'cv32e40p'
    assert cv32_request.document['cpu']['profile'] == \
        'configs/cpus/cv32e40p/component_profile.json'
    d3_resources = {row['resource_id']: row
        for row in cv32_request.wiring.document['resources']}
    assert {key: (row['base'], row['size'], row['read'], row['write'],
                  row['execute']) for key, row in d3_resources.items()} == {
        'rom0': (0x10000, 0x8000, True, False, True),
        'ram': (0x20000, 0x20000, True, True, False),
    }
    assert (cv32_rom['base'], cv32_rom['size']) == (0x10000, 0x8000)
    assert (cv32_ram['base'], cv32_ram['size']) == (0x20000, 0x20000)
    assert (cv32_route['base'], cv32_route['size']) == (0x20000, 0x20000)
    assert 0x20000 <= 0x22000 < 0x40000
    assert 0x20000 <= 0x24000 < 0x40000
    assert (cv32_dma_window['base'], cv32_dma_window['size']) == (0x40002000, 16)
    cv32_f6, = [row for row in cv32_compiled['paths']
                if row['flow_id'] == 'F6']
    assert cv32_f6['status'] == 'unsupported'
    runtime_graph = cv32_compiled.get('runtime_dependency_graph') or {}
    assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
                   for edge in runtime_graph.get('edges', []))
    assert cv32_compiled['identity']['wiring']['dma_master_routes_sha256'] == \
        cv32_request.wiring.dma_master_routes_sha256


def test_caliptra_ahb_d2_d3_route_binds_existing_typed_topology(
        tmp_path, caliptra_d2_d3_material, caliptra_sha_artifact):
    from copy import deepcopy
    from dataclasses import replace
    from unittest.mock import patch

    from myfuzz.local_harness.template_contracts import select_template_contract
    from myfuzz.scenario.caliptra_sha256_dma_paths import (
        CaliptraSha256DmaBeatAdmission, SHA_CTRL_OFFSET,
        SHA_CTRL_START_VALUE)
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.compiled_f6_dma_handoff import (
        BoundCompiledF6DmaHandoff, bind_compiled_f6_dma_handoff,
        prepare_compiled_f6_dma_handoff)
    from myfuzz.scenario.dma_intent_topology_binding import DmaIntentBindingError
    from myfuzz.scenario.ledger import TransactionKey
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    d2_wiring, request, compiled = caliptra_d2_d3_material
    d3_wiring = request.wiring
    assert d3_wiring.document['dma_master_routes'] == d2_wiring['dma_master_routes']
    assert d3_wiring.document['dma_master_route_bindings'] == \
        d2_wiring['dma_master_route_bindings']
    target_binding = next(row['target']
        for row in d2_wiring['dma_master_route_bindings']
        if row['route_id'] == 'route.caliptra-ctrl')
    assert (target_binding['template_id'], target_binding['template_version'],
            target_binding['variant_id']) == (
                'target.ahb-lite', '1', 'full-word-single')
    assert compiled['identity']['wiring']['dma_master_routes_sha256'] == \
        d2_wiring['dma_master_routes_sha256']
    assert compiled['identity']['wiring']['dma_master_route_bindings_sha256'] == \
        _canonical_sha256(d2_wiring['dma_master_route_bindings'])
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    assert f6['status'] == 'unsupported'
    assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_dependency_graph']['edges'])
    assert not any(edge.get('relation') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_path_contract']['edges'])

    endpoint, = [row for row in caliptra_sha_artifact.plan.binding.endpoints
                 if row.endpoint_id == 'sha256.bus']
    selection = select_template_contract(endpoint,
        caliptra_sha_artifact.plan.profile.capabilities,
        template_id='target.ahb-lite', template_version='1',
        variant_id='full-word-single')
    assert selection.contract.template_id == 'target.ahb-lite'

    issued = generated_instance('dma')
    runner, artifact_links, paths, window = _caliptra_typed_dma_fixture(
        issued, caliptra_sha_artifact, tmp_path)
    assert paths.prepared is not None and paths.compiled is None
    assert window.endpoint is runner.sessions['sha']
    declaration = _caliptra_d4_declaration(d3_wiring, paths.prepared,
                                            artifact_links)
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared_object, *args, **kwargs):
        bound_objects.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        handoff = prepare_compiled_f6_dma_handoff(compiled, declaration)
        bound_handoff = bind_compiled_f6_dma_handoff(
            handoff, runner, artifact_links=artifact_links)
        bound = bound_handoff.topology_binding
    bound_handoff.validate_topology()
    bound.validate_topology()
    bound_document = bound_handoff.document()
    restored_bound = BoundCompiledF6DmaHandoff.from_document(
        bound_document, handoff=handoff, topology_binding=bound)
    restored_bound.validate_topology()
    for mutate in (
            lambda row: row['compiled_f6_handoff'].update(
                compiled_paths_sha256='0' * 64),
            lambda row: row['topology_binding'].update(
                declaration_sha256='0' * 64),
            lambda row: row['topology_binding']['routes'][0].update(
                runtime_route_sha256='0' * 64),
            lambda row: row.update(identity_sha256='0' * 64)):
        tampered = deepcopy(bound_document)
        mutate(tampered)
        with pytest.raises(ValueError):
            BoundCompiledF6DmaHandoff.from_document(
                tampered, handoff=handoff, topology_binding=bound)
    assert bound_objects == [paths.prepared]
    assert bound.document()['tier'] == 'topology_bound'
    assert bound_handoff.document()['compiled_f6_handoff'][
        'compiled_paths_sha256'] == compiled_document_sha256(compiled)
    assert bound_handoff.document()['compiled_f6_handoff']['f6']['status'] == 'unsupported'
    assert [(route.key, route.target_kind, route.target_component)
            for route in bound.runtime_compilation.dma_master_routes] == [
                ((0, 0), 'persistent_memory', 'cpu'),
                ((2, 0), 'peripheral', 'sha')]

    paths = replace(paths, admission=CaliptraSha256DmaBeatAdmission(
        image_address=paths.image_address, window=window))
    read_route, write_route = _select_dma_read_write_routes(paths.prepared)
    admission = DmaMasterRouteAdmission(paths.admission, bound_handoff,
        path_id=paths.path_id, read_route=read_route, write_route=write_route)
    admission.begin_case('caliptra-run', 'caliptra-case')
    read_key = TransactionKey('caliptra-run', 'caliptra-case', 'dma', 0,
                              'dma-memory', 1)
    write_key = TransactionKey('caliptra-run', 'caliptra-case', 'dma', 0,
                               'dma-memory', 2)
    admission.accepted(read_key, address=paths.image_address, write=False,
                       value=0, byte_enable=15, target=None)
    admission.completed(read_key, rdata=SHA_CTRL_START_VALUE, error=0)
    assert admission.state == 'expect_write'
    read_matches = admission.route_matches
    assert [row['edge_key'] for row in read_matches] == [(0, 0)]

    with pytest.raises(ValueError,
                       match='DMA route response has no exact admitted route match'):
        admission.completed(write_key, rdata=0, error=0)
    assert admission.state == 'expect_write'
    assert admission.route_matches == read_matches

    with pytest.raises(ValueError,
                       match='^DMA route match does not exactly match the selected route$'):
        admission.accepted(write_key,
            address=window.base + SHA_CTRL_OFFSET + 4, write=True,
            value=SHA_CTRL_START_VALUE, byte_enable=15, target=window)
    assert admission.state == 'expect_write'
    assert admission.route_matches == read_matches

    admission.accepted(write_key, address=window.base + SHA_CTRL_OFFSET,
        write=True, value=SHA_CTRL_START_VALUE, byte_enable=15, target=window)
    admission.completed(write_key, rdata=0, error=0)
    assert admission.state == 'complete'
    assert [row['edge_key'] for row in admission.route_matches] == [
        (0, 0), (2, 0)]

    sha = runner.sessions['sha']
    sha.dma_master_target_access = lambda *args, **kwargs: None
    with pytest.raises(DmaIntentBindingError) as method_drift:
        bound.validate_topology()
    assert method_drift.value.code == 'dma-binding-topology-changed'
    del sha.dma_master_target_access
    bound.validate_topology()

    provider_method = type(sha).dma_master_target_access
    original_code = provider_method.__code__

    def changed_provider_code(self, source_transaction, *, address, offset,
                              write, value, byte_enable, delivery_context):
        return None

    try:
        provider_method.__code__ = changed_provider_code.__code__
        with pytest.raises(DmaIntentBindingError) as code_drift:
            bound.validate_topology()
        assert code_drift.value.code == 'dma-binding-topology-changed'
    finally:
        provider_method.__code__ = original_code
    bound.validate_topology()

    sha.DMA_CTRL_START_VALUE = 6
    with pytest.raises(DmaIntentBindingError) as identity_drift:
        bound.validate_topology()
    assert identity_drift.value.code == 'dma-binding-topology-changed'
    del sha.DMA_CTRL_START_VALUE
    bound.validate_topology()

    sha.access_operation = 'STEP_AHB_REG'
    with pytest.raises(DmaIntentBindingError) as config_drift:
        bound.validate_topology()
    assert config_drift.value.code == 'dma-binding-topology-changed'
    del sha.access_operation
    bound.validate_topology()


def test_caliptra_ahb_d4_target_admission_rejects_unregistered_shapes(
        tmp_path, caliptra_d2_d3_material, caliptra_sha_artifact):
    import copy
    from dataclasses import fields, replace
    from types import SimpleNamespace
    from unittest.mock import patch

    from myfuzz.local_harness.ahb_lite_register_session import (
        GeneratedAhbLiteRegisterSession)
    from myfuzz.scenario.compiled_paths import load_path_wiring
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, _target_binding)
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    d2_wiring, request, _compiled = caliptra_d2_d3_material
    runner, _artifact_links, paths, _window = _caliptra_typed_dma_fixture(
        generated_instance('dma'), caliptra_sha_artifact, tmp_path)
    sha = runner.sessions['sha']
    wiring = load_path_wiring(request.wiring.document)
    intent = next(row for row in wiring.dma_master_routes
                  if row.route_id == 'route.caliptra-ctrl')

    for name in (
            'dma_master_target_provider_identity_document',
            'dma_master_target_access', '_check_artifact_stable', 'command',
            '_command_impl', '_expected_ready', '_take', '_take_impl'):
        setattr(sha, name, lambda *args, **kwargs: None)
        with pytest.raises(DmaIntentBindingError) as caught:
            _target_binding(wiring, intent, sha, '/caliptra-target')
        assert caught.value.code == 'dma-binding-provider-unsupported'
        delattr(sha, name)

    original_identity = GeneratedAhbLiteRegisterSession.dma_master_target_provider_identity_document

    def missing_identity_field(session):
        document = original_identity(session)
        document.pop('value')
        return document

    with patch.object(GeneratedAhbLiteRegisterSession,
                      'dma_master_target_provider_identity_document',
                      missing_identity_field):
        with pytest.raises(DmaIntentBindingError) as caught:
            _target_binding(wiring, intent, sha, '/caliptra-target')
    assert caught.value.code == 'dma-binding-provider-unsupported'

    real_artifact = sha.artifact
    real_profile = real_artifact.plan.profile
    real_endpoint, = [row for row in real_artifact.plan.binding.endpoints
                      if row.endpoint_id == 'sha256.bus']

    def artifact_view(*, component='caliptra_sha256', kind='ahb_lite_register_observe',
                      instance='sha', window=4096, protocol=('ahb-lite', '1'),
                      adapted=True, trace_mutation=None):
        profile = SimpleNamespace(component_id=component,
            address=SimpleNamespace(window_size=window,
                registers=real_profile.address.registers),
            capabilities=real_profile.capabilities,
            profile_fingerprint=real_profile.profile_fingerprint)
        endpoint = replace(real_endpoint, protocol=protocol)
        document = copy.deepcopy(real_artifact.runtime_document)
        document['kind'] = kind
        document['adapted_endpoint_ids'] = ['sha256.bus'] if adapted else []
        if trace_mutation is not None:
            trace_mutation(document['base_protocol_trace'])
        plan = SimpleNamespace(profile=profile,
            request=SimpleNamespace(instance_id=instance,
                tuning=real_artifact.plan.request.tuning),
            binding=SimpleNamespace(endpoints=(endpoint,)))
        return SimpleNamespace(plan=plan, runtime_document=document)

    artifact_refusals = (
        (artifact_view(component='other'), 'dma-binding-provider-unsupported'),
        (artifact_view(kind='other'), 'dma-binding-provider-unsupported'),
        (artifact_view(instance='other'), 'dma-binding-provider-unsupported'),
        (artifact_view(window=2048), 'dma-binding-provider-unsupported'),
        (artifact_view(protocol=('ahb-lite', '2')), 'dma-binding-target-unsupported'),
        (artifact_view(adapted=False), 'dma-binding-target-unsupported'),
        (artifact_view(trace_mutation=lambda trace: trace.update(protocol='wishbone')),
         'dma-binding-provider-unsupported'),
        (artifact_view(trace_mutation=lambda trace: trace['signals'].pop('hrdata')),
         'dma-binding-provider-unsupported'),
        (artifact_view(trace_mutation=lambda trace: trace['signals'].update(
            haddr=trace['signals']['hwdata'])),
         'dma-binding-provider-unsupported'),
        (artifact_view(trace_mutation=lambda trace: trace['signal_widths'].update(haddr=31)),
         'dma-binding-provider-unsupported'),
        (artifact_view(trace_mutation=lambda trace: trace['signal_widths'].update(hsel=True)),
         'dma-binding-provider-unsupported'),
    )
    for artifact, expected_code in artifact_refusals:
        with patch('myfuzz.scenario.dma_intent_topology_binding._actual_artifact',
                   return_value=artifact):
            with pytest.raises(DmaIntentBindingError) as caught:
                _target_binding(wiring, intent, sha, '/caliptra-target')
        assert caught.value.code == expected_code

    wrong_endpoint = replace(intent, target={**intent.target,
        'endpoint_id': 'sha256.other'})
    with pytest.raises(DmaIntentBindingError) as caught:
        _target_binding(wiring, wrong_endpoint, sha, '/caliptra-target')
    assert caught.value.code == 'dma-binding-target-unsupported'

    partial_policy = {item.name: getattr(intent, item.name)
                      for item in fields(intent)}
    partial_policy['byte_enable'] = 7
    policy_refusals = (
        replace(intent, operation='read', permissions=('read',),
                readable_offsets=(16,), writable_offsets=(),
                accepted_write_values=()),
        replace(intent, writable_offsets=(20,)),
        SimpleNamespace(**partial_policy),
        replace(intent, accepted_write_values=(6,)),
        replace(intent, size=0x800),
    )
    for wrong_policy in policy_refusals:
        with pytest.raises(DmaIntentBindingError) as caught:
            _target_binding(wiring, wrong_policy, sha, '/caliptra-target')
        assert caught.value.code == 'dma-binding-target-unsupported'

    target_bindings = [dict(row) for row in wiring.dma_master_route_bindings]
    for row in target_bindings:
        if row['route_id'] == 'route.caliptra-ctrl':
            row['target'] = dict(row['target'], variant_id='wrong-ahb-variant')
    wrong_template_wiring = SimpleNamespace(dma_master_route_bindings=tuple(target_bindings))
    with pytest.raises(DmaIntentBindingError) as caught:
        _target_binding(wrong_template_wiring, intent, sha, '/caliptra-target')
    assert caught.value.code == 'dma-binding-template-mismatch'


def test_caliptra_ahb_d4_static_refusals_precede_runtime_bind(
        tmp_path, caliptra_d2_d3_material, caliptra_sha_artifact):
    from unittest.mock import patch

    from myfuzz.local_harness.ahb_lite_register_session import (
        GeneratedAhbLiteRegisterSession)
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.scenario.compiled_paths import load_path_wiring
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, bind_dma_intent_topology,
        prepare_dma_intent_binding)
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    d2_wiring, request, _compiled = caliptra_d2_d3_material
    runner, artifact_links, paths, window = _caliptra_typed_dma_fixture(
        generated_instance('dma'), caliptra_sha_artifact, tmp_path)
    declaration = _caliptra_d4_declaration(request.wiring, paths.prepared,
                                            artifact_links)
    sha = runner.sessions['sha']
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared_object, *args, **kwargs):
        bound_objects.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        for name in (
                'dma_master_target_provider_identity_document',
                'dma_master_target_access', '_check_artifact_stable', 'command',
                '_command_impl', '_expected_ready', '_take', '_take_impl'):
            setattr(sha, name, lambda *args, **kwargs: None)
            with pytest.raises(DmaIntentBindingError) as caught:
                bind_dma_intent_topology(declaration, runner,
                    artifact_links=artifact_links)
            assert caught.value.code == 'dma-binding-provider-unsupported'
            assert bound_objects == []
            delattr(sha, name)

        wiring_document = request.wiring.document
        import copy
        changed_document = copy.deepcopy(wiring_document)
        target_row = next(row for row in changed_document['dma_master_route_bindings']
            if row['route_id'] == 'route.caliptra-ctrl')
        target_row['target']['variant_id'] = 'wrong-ahb-variant'
        changed_wiring = load_path_wiring(changed_document)
        changed_declaration = prepare_dma_intent_binding(
            changed_wiring, paths.prepared,
            route_links=declaration.document()['route_links'])
        with pytest.raises(DmaIntentBindingError) as wrong_template:
            bind_dma_intent_topology(changed_declaration, runner,
                artifact_links=artifact_links)
        assert wrong_template.value.code == 'dma-binding-template-mismatch'
        assert bound_objects == []

        runner.sessions['dma'].master_targets = (MasterTargetWindow(
            'sha', window.base, 0x800, sha, (16,), (5,), byte_enable=15),)
        with pytest.raises(DmaIntentBindingError) as changed_window:
            bind_dma_intent_topology(declaration, runner,
                artifact_links=artifact_links)
        assert changed_window.value.code == 'dma-binding-target-unsupported'
        assert bound_objects == [paths.prepared]


def test_pulp_apb3_d2_d3_route_binds_existing_typed_topology(
        tmp_path, pulp_gpio_d2_d3_material, pulp_gpio_observed_artifact):
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, bind_dma_intent_topology)
    from myfuzz.scenario.ledger import TransactionKey
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    d2_wiring, request, compiled = pulp_gpio_d2_d3_material
    d3_wiring = request.wiring
    assert d3_wiring.document['dma_master_routes'] == d2_wiring['dma_master_routes']
    assert d3_wiring.document['dma_master_route_bindings'] == \
        d2_wiring['dma_master_route_bindings']
    gpio_binding = next(row['target'] for row in d2_wiring['dma_master_route_bindings']
                        if row['route_id'] == 'route.gpio-padout')
    assert (gpio_binding['template_id'], gpio_binding['template_version'],
            gpio_binding['variant_id']) == ('target.apb3', '1', 'full-word')
    assert compiled['identity']['wiring']['dma_master_routes_sha256'] == \
        d2_wiring['dma_master_routes_sha256']
    assert compiled['identity']['wiring']['dma_master_route_bindings_sha256'] == \
        _canonical_sha256(d2_wiring['dma_master_route_bindings'])
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    assert f6['status'] == 'unsupported'
    assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_dependency_graph']['edges'])
    assert not any(edge.get('relation') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_path_contract']['edges'])

    issued = generated_instance('dma')
    runner, artifact_links, prepared = _pulp_typed_dma_fixture(
        issued, pulp_gpio_observed_artifact, tmp_path)
    declaration = _pulp_d4_declaration(d3_wiring, prepared, artifact_links)
    assert declaration._prepared_runtime_paths is prepared
    from unittest.mock import patch
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    original_bind = PreparedRuntimePathContract.bind
    bound_objects = []

    def bind_spy(prepared_object, *args, **kwargs):
        bound_objects.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound = bind_dma_intent_topology(declaration, runner,
                                         artifact_links=artifact_links)
    bound.validate_topology()
    assert bound_objects == [prepared]
    assert bound.document()['tier'] == 'topology_bound'
    assert bound.runtime_compilation.document()['contract_sha256'] == \
        prepared.contract.identity_sha256
    assert [(route.key, route.target_kind, route.target_component)
            for route in bound.runtime_compilation.dma_master_routes] == [
                ((0, 0), 'persistent_memory', 'cpu'),
                ((2, 0), 'peripheral', 'gpio')]

    import myfuzz.scenario.pulp_gpio_dma_paths as pulp_paths
    admission_type = getattr(pulp_paths, 'PulpGpioD4RouteAdmission', None)
    assert callable(admission_type)
    PulpGpioDmaBeatAdmission = pulp_paths.PulpGpioDmaBeatAdmission
    read_route, write_route = _select_dma_read_write_routes(prepared)
    window, = runner.sessions['dma'].master_targets
    beat = PulpGpioDmaBeatAdmission(image_address=read_route.base,
                                    gpio_window=window)
    admission = admission_type(beat, bound, path_id=prepared.path_ids[0],
        read_route=read_route, write_route=write_route)
    admission_identity = admission.identity_document()
    assert admission_identity['schema_version'] == 'dma_master_route_admission.v1'
    assert admission_identity['binding_identity_sha256'] == bound.identity_sha256
    assert admission_identity['path_id'] == prepared.path_ids[0]
    assert admission_identity['read_route_sha256'] == read_route.identity_sha256
    assert admission_identity['write_route_sha256'] == write_route.identity_sha256
    assert admission_identity['beat_policy'] == beat.identity_document()
    read_key = TransactionKey('native-read-run', 'native-case', 'dma', 0,
                              'dma-memory', 1)
    admission.accepted(read_key, address=0x1000, write=False, value=0,
                       byte_enable=15, target=None)
    admission.completed(read_key, rdata=0x5aa55aa5, error=0)
    assert len(admission.route_matches) == 1
    assert admission.route_matches[0]['transaction'] == vars(read_key)
    unmatched_response_key = TransactionKey('native-read-run', 'native-case',
        'dma', 0, 'dma-memory', 3)
    with pytest.raises(ValueError, match='no exact admitted route match'):
        admission.completed(unmatched_response_key, rdata=0, error=0)

    wrong_write_key = TransactionKey('native-read-run', 'native-case', 'dma', 0,
                                     'dma-memory', 2)
    with pytest.raises(ValueError):
        admission.accepted(wrong_write_key, address=0x40001010, write=True,
                           value=0x5aa55aa5, byte_enable=15, target=window)
    assert beat.state == 'expect_write'
    assert len(admission.route_matches) == 1

    path_id, = prepared.path_ids
    read_match = bound.match_dma_master_route(path_id,
        initiator_component='dma', endpoint_id='read_master',
        target_kind='persistent_memory', target_component='cpu',
        target_id='ram', base=0x1000, size=0x1000, operation='read',
        address=0x1000, byte_enable=15,
        transaction_key=TransactionKey('route-match-run', 'route-match-case',
            'dma', 0, 'dma-memory', 1))
    write_match = bound.match_dma_master_route(path_id,
        initiator_component='dma', endpoint_id='write_master',
        target_kind='peripheral', target_component='gpio', target_id='gpio',
        base=0x40001000, size=0x1000, operation='write',
        address=0x4000100c, byte_enable=15, value=0x5aa55aa5,
        transaction_key=TransactionKey('route-match-run', 'route-match-case',
            'dma', 0, 'dma-memory', 2))
    assert read_match is not None and read_match.edge_key == (0, 0)
    assert write_match is not None and write_match.edge_key == (2, 0)
    assert read_match.route_sha256 == next(route.identity_sha256
        for route in prepared.contract.dma_master_routes if route.key == (0, 0))
    assert write_match.route_sha256 == next(route.identity_sha256
        for route in prepared.contract.dma_master_routes if route.key == (2, 0))
    assert bound.match_dma_master_route(path_id,
        initiator_component='dma', endpoint_id='write_master',
        target_kind='peripheral', target_component='gpio', target_id='gpio',
        base=0x40001000, size=0x1000, operation='write',
        address=0x40001010, byte_enable=15, value=0x5aa55aa5,
        transaction_key=TransactionKey('route-match-run', 'route-match-case',
            'dma', 0, 'dma-memory', 3)) is None
    assert bound.match_dma_master_route(path_id,
        initiator_component='dma', endpoint_id='write_master',
        target_kind='peripheral', target_component='gpio', target_id='gpio',
        base=0x40001000, size=0x1000, operation='write',
        address=0x4000100c, byte_enable=15, value=0x5aa55aa6,
        transaction_key=TransactionKey('route-match-run', 'route-match-case',
            'dma', 0, 'dma-memory', 4)) is None

    gpio = runner.sessions['gpio']
    original_provider = gpio.dma_master_target_provider_identity_document
    gpio.dma_master_target_provider_identity_document = lambda: original_provider()
    with pytest.raises(DmaIntentBindingError) as changed_provider:
        bound.match_dma_master_route(path_id,
            initiator_component='dma', endpoint_id='write_master',
            target_kind='peripheral', target_component='gpio', target_id='gpio',
            base=0x40001000, size=0x1000, operation='write',
            address=0x4000100c, byte_enable=15, value=0x5aa55aa5,
            transaction_key=TransactionKey('route-match-run', 'route-match-case',
                'dma', 0, 'dma-memory', 5))
    assert changed_provider.value.code == 'dma-binding-topology-changed'
    del gpio.dma_master_target_provider_identity_document
    bound.validate_topology()


def test_zipcpu_uart_wishbone_d2_d3_route_binds_existing_typed_topology(
        tmp_path):
    from unittest.mock import patch

    from myfuzz.local_harness.template_contracts import select_template_contract
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, bind_dma_intent_topology)
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    d2_wiring, request, compiled = _generate_zipcpu_uart_dma_route_d2_d3(tmp_path)
    d3_wiring = request.wiring
    assert d3_wiring.document['dma_master_routes'] == d2_wiring['dma_master_routes']
    assert d3_wiring.document['dma_master_route_bindings'] == \
        d2_wiring['dma_master_route_bindings']
    target_binding = next(row['target']
        for row in d2_wiring['dma_master_route_bindings']
        if row['route_id'] == 'route.uart-txreg')
    assert (target_binding['template_id'], target_binding['template_version'],
            target_binding['variant_id']) == (
                'target.wishbone', '1', 'word-addressed-registered-ack')
    assert compiled['identity']['wiring']['dma_master_routes_sha256'] == \
        d2_wiring['dma_master_routes_sha256']
    assert compiled['identity']['wiring']['dma_master_route_bindings_sha256'] == \
        _canonical_sha256(d2_wiring['dma_master_route_bindings'])
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    assert f6['status'] == 'unsupported'
    assert not any(edge.get('kind') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_dependency_graph']['edges'])
    assert not any(edge.get('relation') == 'DMA_MASTER_TRANSFER'
                   for edge in compiled['runtime_path_contract']['edges'])

    uart_artifact = _local_artifact(
        'configs/peripherals/zipcpu_uart/component_profile.json', 'uart')
    runner, artifact_links, prepared, paths, window = \
        _zipcpu_uart_typed_dma_fixture(generated_instance('dma'),
                                       uart_artifact, tmp_path)
    uart = runner.sessions['uart']
    identity = uart.dma_master_target_provider_identity_document()
    assert identity['schema_version'] == 'zipcpu_uart_dma_target_provider.v1'
    assert identity['artifact_digest'] == uart.artifact.runtime_document['artifact_digest']
    assert identity['instance_id'] == 'uart'
    assert paths.prepared is prepared
    assert window.endpoint is uart
    endpoint, = [row for row in uart_artifact.plan.binding.endpoints
                 if row.endpoint_id == 'uart.bus']
    selection = select_template_contract(endpoint,
        uart_artifact.plan.profile.capabilities,
        template_id='target.wishbone', template_version='1',
        variant_id='word-addressed-registered-ack')
    assert selection.contract.template_id == 'target.wishbone'

    declaration = _zipcpu_uart_d4_declaration(
        d3_wiring, prepared, artifact_links)
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared_object, *args, **kwargs):
        bound_objects.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound = bind_dma_intent_topology(declaration, runner,
            artifact_links=artifact_links)
    bound.validate_topology()
    assert bound_objects == [prepared]
    assert bound.document()['tier'] == 'topology_bound'
    assert bound.runtime_compilation.document()['contract_sha256'] == \
        prepared.contract.identity_sha256
    assert [(route.key, route.target_kind, route.target_component)
            for route in bound.runtime_compilation.dma_master_routes] == [
                ((0, 0), 'persistent_memory', 'cpu'),
                ((2, 0), 'peripheral', 'uart')]
    uart._dma_target_require_ready = lambda: None
    with pytest.raises(DmaIntentBindingError) as changed_provider:
        bound.validate_topology()
    assert changed_provider.value.code == 'dma-binding-topology-changed'
    del uart._dma_target_require_ready
    bound.validate_topology()
    uart.startup_writes = ((0, 24, 15),)
    with pytest.raises(DmaIntentBindingError) as changed_provider_identity:
        bound.validate_topology()
    assert changed_provider_identity.value.code == 'dma-binding-topology-changed'
    uart.startup_writes = ((0, 25, 15),)
    bound.validate_topology()


def test_zipcpu_uart_d4_static_target_refusals_precede_runtime_bind(tmp_path):
    import json
    from dataclasses import fields, replace
    from types import SimpleNamespace
    from unittest.mock import patch

    from myfuzz.scenario.compiled_paths import load_path_wiring
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, _target_binding, bind_dma_intent_topology)
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    d2_wiring, request, _ = _generate_zipcpu_uart_dma_route_d2_d3(tmp_path)
    uart_artifact = _local_artifact(
        'configs/peripherals/zipcpu_uart/component_profile.json', 'uart')
    runner, artifact_links, prepared, _, _ = _zipcpu_uart_typed_dma_fixture(
        generated_instance('dma'), uart_artifact, tmp_path)
    declaration = _zipcpu_uart_d4_declaration(
        request.wiring, prepared, artifact_links)
    uart = runner.sessions['uart']
    identity = uart.dma_master_target_provider_identity_document()

    wiring = load_path_wiring(request.wiring.document)
    tx_intent = next(row for row in wiring.dma_master_routes
                     if row.route_id == 'route.uart-txreg')
    wrong_tx_policies = (
        replace(tx_intent, operation='read', permissions=('read',),
                readable_offsets=(8,), writable_offsets=(),
                accepted_write_values=()),
        replace(tx_intent, writable_offsets=(0,)),
        replace(tx_intent, accepted_write_values=range(0, 512)),
    )
    partial_policy = {item.name: getattr(tx_intent, item.name)
                      for item in fields(tx_intent)}
    partial_policy['byte_enable'] = 1
    wrong_tx_policies += (SimpleNamespace(**partial_policy),)
    subwindow_policy = dict(partial_policy, byte_enable=15, size=8)
    wrong_tx_policies += (SimpleNamespace(**subwindow_policy),)
    for wrong_policy in wrong_tx_policies:
        with pytest.raises(DmaIntentBindingError) as target_policy:
            _target_binding(wiring, wrong_policy, uart, '/zipcpu-target')
        assert target_policy.value.code == 'dma-binding-target-unsupported'

    class DerivedWishboneUart(type(uart)):
        pass

    derived_uart = object.__new__(DerivedWishboneUart)
    derived_uart.__dict__.update(uart.__dict__)
    with pytest.raises(DmaIntentBindingError) as subclass_target:
        _target_binding(wiring, tx_intent, derived_uart, '/zipcpu-target')
    assert subclass_target.value.code == 'dma-binding-target-unsupported'

    real_artifact = uart.artifact

    def artifact_view(*, component_id='zipcpu_uart', kind='wishbone_uart',
                      protocol=('wishbone', 'classic'), adapted=True):
        profile = SimpleNamespace(component_id=component_id,
            address=real_artifact.plan.profile.address,
            capabilities=real_artifact.plan.profile.capabilities)
        endpoint = SimpleNamespace(endpoint_id='uart.bus', function='mmio_slave',
                                   protocol=protocol)
        document = dict(real_artifact.runtime_document)
        document['kind'] = kind
        document['adapted_endpoint_ids'] = ['uart.bus'] if adapted else []
        return SimpleNamespace(
            plan=SimpleNamespace(profile=profile,
                binding=SimpleNamespace(endpoints=(endpoint,))),
            runtime_document=document)

    for artifact, expected_code in (
        (artifact_view(component_id='other_uart'),
         'dma-binding-provider-unsupported'),
        (artifact_view(kind='other_uart'),
         'dma-binding-provider-unsupported'),
        (artifact_view(protocol=('wishbone', 'pipelined')),
         'dma-binding-target-unsupported'),
        (artifact_view(adapted=False),
         'dma-binding-target-unsupported'),
    ):
        with patch('myfuzz.scenario.dma_intent_topology_binding._actual_artifact',
                   return_value=artifact):
            with pytest.raises(DmaIntentBindingError) as artifact_refusal:
                _target_binding(wiring, tx_intent, uart, '/zipcpu-target')
        assert artifact_refusal.value.code == expected_code

    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared_object, *args, **kwargs):
        bound_objects.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        changed_wiring_document = json.loads(json.dumps(request.wiring.document))
        tx_route = next(row for row in changed_wiring_document[
            'dma_master_route_bindings'] if row['route_id'] == 'route.uart-txreg')
        tx_route['target']['variant_id'] = 'wrong-wishbone-target-variant'
        changed_wiring = load_path_wiring(changed_wiring_document)
        changed_declaration = _zipcpu_uart_d4_declaration(
            changed_wiring, prepared, artifact_links)
        with pytest.raises(DmaIntentBindingError) as wrong_template:
            bind_dma_intent_topology(changed_declaration, runner,
                artifact_links=artifact_links)
        assert wrong_template.value.code == 'dma-binding-template-mismatch'
        assert bound_objects == []

        original_startup_writes = uart.startup_writes
        uart.startup_writes = ((0, 24, 15),)
        with pytest.raises(DmaIntentBindingError) as identity_drift:
            bind_dma_intent_topology(declaration, runner,
                artifact_links=artifact_links)
        assert identity_drift.value.code == 'dma-binding-provider-unsupported'
        assert bound_objects == []
        uart.startup_writes = original_startup_writes

        for method_name in ('_dma_exact_document',
                            'dma_master_target_provider_identity_document',
                            'dma_master_target_access',
                            '_dma_target_identity_components',
                            '_dma_target_require_ready',
                            '_dma_target_backend_values',
                            '_dma_target_check_uart_pin'):
            setattr(uart, method_name, lambda *args, **kwargs: identity)
            with pytest.raises(DmaIntentBindingError) as caught:
                bind_dma_intent_topology(declaration, runner,
                    artifact_links=artifact_links)
            assert caught.value.code == 'dma-binding-provider-unsupported'
            assert bound_objects == []
            delattr(uart, method_name)

        runner.sessions['dma'].master_targets = (MasterTargetWindow(
            'uart', 0x40004000, 0x10, uart, (12,), range(256), byte_enable=15),)
        with pytest.raises(DmaIntentBindingError) as changed_window:
            bind_dma_intent_topology(declaration, runner,
                artifact_links=artifact_links)
        assert changed_window.value.code == 'dma-binding-target-unsupported'
        assert bound_objects == [prepared]
    assert declaration._prepared_runtime_paths is prepared


def _pulp_target_binding_material(tmp_path, d2_d3, gpio_artifact):
    from myfuzz.scenario.compiled_paths import load_path_wiring
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    _, request, _ = d2_d3
    runner, artifact_links, prepared = _pulp_typed_dma_fixture(
        generated_instance('dma'), gpio_artifact, tmp_path)
    declaration = _pulp_d4_declaration(request.wiring, prepared, artifact_links)
    wiring = load_path_wiring(declaration.document()['wiring'])
    intent, = [row for row in wiring.dma_master_routes
                if row.route_id == 'route.gpio-padout']
    return wiring, intent, runner, artifact_links, prepared, declaration


@pytest.mark.parametrize('mutation', [
    'provider_version', 'provider_observation', 'missing_provider',
    'shadowed_provider',
    'wrong_template', 'wrong_offset', 'read_route', 'wrong_endpoint',
    'byte_enable', 'artifact_observation', 'non_apb_protocol',
    'unadapted_endpoint', 'target_subwindow',
    'unobserved_artifact', 'subclass_session',
])
def test_pulp_d4_target_admission_rejects_unregistered_shapes(
        tmp_path, pulp_gpio_d2_d3_material, pulp_gpio_observed_artifact,
        pulp_gpio_unobserved_artifact, mutation):
    from dataclasses import fields, replace
    import copy
    from types import SimpleNamespace
    from contextlib import nullcontext
    from unittest.mock import patch

    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, _target_binding)

    wiring, intent, runner, _, _, _ = _pulp_target_binding_material(
        tmp_path, pulp_gpio_d2_d3_material, pulp_gpio_observed_artifact)
    session = runner.sessions['gpio']
    expected_code = 'dma-binding-target-unsupported'
    artifact_view = None
    if mutation == 'provider_version':
        provider = session.dma_master_target_provider_identity_document
        session.dma_master_target_provider_identity_document = lambda: {
            **provider(), 'schema_version': 'pulp_gpio_dma_target_provider.v2'}
        expected_code = 'dma-binding-provider-unsupported'
    elif mutation == 'provider_observation':
        provider = session.dma_master_target_provider_identity_document
        session.dma_master_target_provider_identity_document = lambda: {
            **provider(), 'observation_contract': {'schema_version': 'changed'}}
        expected_code = 'dma-binding-provider-unsupported'
    elif mutation == 'missing_provider':
        session.dma_master_target_provider_identity_document = None
        expected_code = 'dma-binding-provider-unsupported'
    elif mutation == 'shadowed_provider':
        provider = session.dma_master_target_provider_identity_document()
        session.dma_master_target_provider_identity_document = lambda: provider
        expected_code = 'dma-binding-provider-unsupported'
    elif mutation == 'wrong_template':
        bindings = []
        for row in wiring.dma_master_route_bindings:
            copied = dict(row)
            if copied['route_id'] == intent.route_id:
                copied['target'] = {**copied['target'],
                    'template_id': 'target.tl-ul', 'variant_id': 'user-integrity'}
            bindings.append(copied)
        wiring = replace(wiring, dma_master_route_bindings=tuple(bindings))
        expected_code = 'dma-binding-template-mismatch'
    elif mutation == 'wrong_offset':
        intent = replace(intent, writable_offsets=(16,))
    elif mutation == 'read_route':
        intent = replace(intent, operation='read', permissions=('read',),
            readable_offsets=(12,), writable_offsets=(), accepted_write_values=())
    elif mutation == 'wrong_endpoint':
        intent = replace(intent, target={**intent.target, 'endpoint_id': 'gpio.other'})
    elif mutation == 'byte_enable':
        values = {row.name: getattr(intent, row.name) for row in fields(intent)}
        values['byte_enable'] = 7
        intent = SimpleNamespace(**values)
    elif mutation == 'artifact_observation':
        artifact = copy.deepcopy(session.artifact)
        session = GeneratedPulpGpioSession(artifact,
            base_dir=tmp_path, cache_dir=tmp_path)
        session.artifact.runtime_document['gpio_observation_contract'] = {
            'schema_version': 'changed'}
        expected_code = 'dma-binding-artifact-mismatch'
    elif mutation == 'non_apb_protocol':
        endpoint, = [row for row in session.artifact.plan.binding.endpoints
                     if row.endpoint_id == 'gpio.bus']
        bad_endpoint = replace(endpoint, protocol=('apb', '2'))
        endpoints = tuple(bad_endpoint if row.endpoint_id == 'gpio.bus' else row
                          for row in session.artifact.plan.binding.endpoints)
        binding = replace(session.artifact.plan.binding, endpoints=endpoints)
        plan = replace(session.artifact.plan, binding=binding)
        artifact_view = SimpleNamespace(plan=plan,
            runtime_document=session.artifact.runtime_document)
    elif mutation == 'unadapted_endpoint':
        document = copy.deepcopy(session.artifact.runtime_document)
        document['adapted_endpoint_ids'] = []
        artifact_view = SimpleNamespace(plan=session.artifact.plan,
            runtime_document=document)
    elif mutation == 'target_subwindow':
        intent = replace(intent, size=intent.size - 0x800)
    elif mutation == 'unobserved_artifact':
        session = GeneratedPulpGpioSession(pulp_gpio_unobserved_artifact,
            base_dir=tmp_path, cache_dir=tmp_path)
        expected_code = 'dma-binding-provider-unsupported'
    elif mutation == 'subclass_session':
        class PulpGpioLookalike(GeneratedPulpGpioSession):
            pass
        session = PulpGpioLookalike(pulp_gpio_observed_artifact,
            base_dir=tmp_path, cache_dir=tmp_path)

    artifact_context = (patch(
        'myfuzz.scenario.dma_intent_topology_binding._actual_artifact',
        return_value=artifact_view) if artifact_view is not None else nullcontext())
    with artifact_context:
        with pytest.raises(DmaIntentBindingError) as caught:
            _target_binding(wiring, intent, session, '/test')
    assert caught.value.code == expected_code


def test_pulp_d4_provider_refusal_happens_before_live_runtime_path_bind(
        tmp_path, pulp_gpio_d2_d3_material, pulp_gpio_observed_artifact):
    from unittest.mock import patch

    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, bind_dma_intent_topology)
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract

    _, _, runner, artifact_links, prepared, declaration = \
        _pulp_target_binding_material(
            tmp_path, pulp_gpio_d2_d3_material, pulp_gpio_observed_artifact)
    runner.sessions['gpio'].dma_master_target_provider_identity_document = None
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared_object, *args, **kwargs):
        bound_objects.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        with pytest.raises(DmaIntentBindingError) as caught:
            bind_dma_intent_topology(declaration, runner,
                artifact_links=artifact_links)
    assert caught.value.code == 'dma-binding-provider-unsupported'
    assert bound_objects == []
    assert declaration._prepared_runtime_paths is prepared


def test_pulp_d4_binder_rejects_a_different_live_master_target_window(
        tmp_path, pulp_gpio_d2_d3_material, pulp_gpio_observed_artifact):
    from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
    from myfuzz.scenario.dma_intent_topology_binding import (
        DmaIntentBindingError, bind_dma_intent_topology)

    _, request, _ = pulp_gpio_d2_d3_material
    from tests.scenario.test_dma_intent_topology_binding import generated_instance
    runner, artifact_links, prepared = _pulp_typed_dma_fixture(
        generated_instance('dma'), pulp_gpio_observed_artifact, tmp_path)
    declaration = _pulp_d4_declaration(request.wiring, prepared, artifact_links)
    gpio = runner.sessions['gpio']
    runner.sessions['dma'].master_targets = (
        MasterTargetWindow('gpio', 0x40001000, 0x800, gpio, (12,), (0x5aa55aa5,)),)
    with pytest.raises(DmaIntentBindingError) as caught:
        bind_dma_intent_topology(declaration, runner, artifact_links=artifact_links)
    assert caught.value.code == 'dma-binding-target-unsupported'
