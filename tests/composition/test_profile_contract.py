"""The component-profile contract the P0-1 inventory is written against.

These tests are pure declaration checks: a minimal CPU, MMIO IP and DMA profile
still normalizes through the one loader, a missing required field is refused by
its own name, and the two capabilities this increment added (a CPU model with no
``rvfi_trap`` export, and a timed-model declaration) are read from the artifact
rather than guessed.  No RTL is elaborated and no model is built.
"""
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import (
    ComponentProfileError, load_component_profile)
from myfuzz.composition.multi_target import (
    MultiTargetError, declared_targets, route_address, target_windows)

ROOT = Path(__file__).resolve().parents[2]


def minimal_cpu(**overrides):
    """The smallest CPU declaration the loader accepts, as a fresh document."""
    document = {
        'schema_version': 'component_profile.v1',
        'component_id': 'contract_cpu',
        'kind': 'cpu',
        'source': {'root': '.', 'revision': 'sha256:' + '0' * 64,
                   'top_module': 'contract_cpu_top',
                   'files': ['contract_cpu_top.sv'],
                   'elaboration': {'frontend': 'verilator-json'}},
        'clocks': [{'port': 'clk_i', 'domain': 'core', 'frequency_hz': 50_000_000}],
        'resets': [{'port': 'rst_ni', 'domain': 'sys_rst', 'polarity': 'active_low',
                    'synchronous': False, 'release': 'released on the core clock'}],
        'endpoints': [
            {'endpoint_id': 'processor.instruction',
             'function': 'instruction_memory_master', 'protocol': ['obi', '1'],
             'fields': [{'role': 'req', 'aliases': ['instr_req_o']},
                        {'role': 'gnt', 'aliases': ['instr_gnt_i']},
                        {'role': 'addr', 'aliases': ['instr_addr_o']},
                        {'role': 'rvalid', 'aliases': ['instr_rvalid_i']},
                        {'role': 'rdata', 'aliases': ['instr_rdata_i']}]},
            {'endpoint_id': 'processor.data', 'function': 'data_memory_master',
             'protocol': ['obi', '1'],
             'fields': [{'role': 'req', 'aliases': ['data_req_o']},
                        {'role': 'gnt', 'aliases': ['data_gnt_i']},
                        {'role': 'addr', 'aliases': ['data_addr_o']},
                        {'role': 'we', 'aliases': ['data_we_o']},
                        {'role': 'wdata', 'aliases': ['data_wdata_o']},
                        {'role': 'be', 'aliases': ['data_be_o']},
                        {'role': 'rvalid', 'aliases': ['data_rvalid_i']},
                        {'role': 'rdata', 'aliases': ['data_rdata_i']}]},
            {'endpoint_id': 'processor.interrupts', 'function': 'interrupt_entry',
             'fields': [{'role': 'external', 'aliases': ['irq_i'],
                         'direction': 'input', 'width': 1}]},
        ],
        'capabilities': {'address_width': 32, 'data_width': 32, 'max_outstanding': 1,
                         'byte_enable': True, 'error_response': False},
        'port_actions': [{'port': 'debug_req_i', 'action': 'constant', 'value': 0,
                          'reason': 'debug entry stays disabled in this composition'}],
        'cpu': {'family': 'riscv', 'xlen': 32, 'extensions': ['i', 'm', 'c'],
                'reset_vector': 65536,
                'master_endpoints': ['processor.instruction', 'processor.data'],
                'irq_entry_endpoint': 'processor.interrupts',
                'irq_entry_role': 'external',
                'irq_entry_polarity': 'active_high',
                'irq_semantics': 'machine_external',
                'boot_address_required': True},
        'evidence': {},
    }
    document.update(overrides)
    return document


def minimal_ip(**overrides):
    """The smallest APB3 MMIO target the loader accepts, with one IRQ source."""
    document = {
        'schema_version': 'component_profile.v1',
        'component_id': 'contract_ip',
        'kind': 'peripheral',
        'source': {'root': '.', 'revision': 'sha256:' + '0' * 64,
                   'top_module': 'contract_ip_top', 'files': ['contract_ip_top.sv'],
                   'elaboration': {'frontend': 'verilator-json'}},
        'clocks': [{'port': 'clk_i', 'domain': 'core', 'frequency_hz': 50_000_000}],
        'resets': [{'port': 'rst_ni', 'domain': 'sys_rst', 'polarity': 'active_low',
                    'synchronous': False, 'release': 'released on the core clock'}],
        'endpoints': [
            {'endpoint_id': 'ip.bus', 'function': 'mmio_slave', 'protocol': ['apb', '3'],
             'fields': [{'role': role, 'aliases': [role]}
                        for role in ('paddr', 'psel', 'penable', 'pwrite',
                                     'pwdata', 'pready', 'prdata')]},
            {'endpoint_id': 'ip.interrupts', 'function': 'interrupt_source',
             'fields': [{'role': 'irq', 'aliases': ['irq_o']}]},
        ],
        'capabilities': {'address_width': 12, 'data_width': 32, 'read': True,
                         'write': True, 'byte_enable': False, 'partial_write': False,
                         'has_error': False},
        'port_actions': [],
        'address': {'window_size': 4096, 'alignment': 4096,
                    'registers': [{'name': 'CTRL', 'offset': 0, 'width': 32,
                                   'access': 'rw'},
                                  {'name': 'COUNT', 'offset': 4, 'width': 32,
                                   'access': 'ro'}]},
        'interrupts': [{'endpoint_id': 'ip.interrupts', 'role': 'irq',
                        'polarity': 'active_high', 'clock_domain': 'core',
                        'trigger': 'level', 'hold': 'held until cleared',
                        'clear': 'write the clear register'}],
        'evidence': {},
    }
    document.update(overrides)
    return document


def minimal_dma(**overrides):
    """The smallest DMA declaration: control slave, memory master, IRQ source."""
    document = minimal_ip(component_id='contract_dma')
    # Two Wishbone endpoints of one device share role names but never physical
    # ports, so each role carries the slave/master prefix the real device uses.
    document['endpoints'] = [
        {'endpoint_id': 'dma.control', 'function': 'mmio_slave',
         'protocol': ['wishbone', 'pipelined'],
         'fields': [{'role': role, 'aliases': ['i_swb_' + suffix]}
                    for role, suffix in (('cyc', 'cyc'), ('stb', 'stb'),
                                         ('we', 'we'), ('adr', 'addr'),
                                         ('dat_w', 'data'), ('sel', 'sel'),
                                         ('stall', 'stall'), ('ack', 'ack'))] +
                   [{'role': 'dat_r', 'aliases': ['o_swb_data']}]},
        {'endpoint_id': 'dma.memory', 'function': 'memory_master',
         'protocol': ['wishbone', 'pipelined'],
         'fields': [{'role': role, 'aliases': ['o_mwb_' + suffix]}
                    for role, suffix in (('cyc', 'cyc'), ('stb', 'stb'),
                                         ('we', 'we'), ('adr', 'addr'),
                                         ('dat_w', 'data'), ('sel', 'sel'),
                                         ('stall', 'stall'), ('ack', 'ack'),
                                         ('err', 'err'))] +
                   [{'role': 'dat_r', 'aliases': ['i_mwb_data']}]},
        {'endpoint_id': 'dma.interrupt', 'function': 'interrupt_source',
         'fields': [{'role': 'irq', 'aliases': ['o_int']}]},
    ]
    document['capabilities'] = {'address_width': 2, 'data_width': 32,
                                'master_address_width': 30,
                                'master_address_units': 'word',
                                'master_byte_enable': True,
                                'master_has_error': True,
                                'wishbone_flavour': 'pipelined'}
    document['address'] = {'window_size': 16, 'alignment': 16,
                           'registers': [{'name': name, 'offset': offset,
                                          'width': 32, 'access': 'rw'}
                                         for name, offset in (
                                             ('CONTROL_STATUS', 0), ('SOURCE', 4),
                                             ('DESTINATION', 8), ('LENGTH', 12))]}
    document['interrupts'] = [{'endpoint_id': 'dma.interrupt', 'role': 'irq',
                               'polarity': 'active_high', 'clock_domain': 'core',
                               'trigger': 'level', 'hold': 'held until cleared',
                               'clear': 'write CONTROL_STATUS'}]
    document.update(overrides)
    return document


def test_a_minimal_cpu_profile_normalizes():
    profile = load_component_profile(minimal_cpu())
    assert profile.kind == 'cpu'
    assert profile.component_id == 'contract_cpu'
    assert profile.cpu.xlen == 32 and profile.cpu.extensions == ('i', 'm', 'c')
    assert [endpoint.endpoint_id for endpoint in profile.endpoints] == [
        'processor.instruction', 'processor.data', 'processor.interrupts']
    assert profile.endpoints[2].protocol is None
    assert profile.clocks[0].frequency_hz == 50_000_000
    assert profile.resets[0].polarity == 'active_low'


def test_a_minimal_mmio_profile_normalizes():
    profile = load_component_profile(minimal_ip())
    assert profile.kind == 'peripheral'
    assert profile.address.window_size == 4096 and profile.address.alignment == 4096
    assert [(row.name, row.offset, row.access) for row in profile.address.registers] == [
        ('CTRL', 0, 'rw'), ('COUNT', 4, 'ro')]
    assert profile.interrupts[0].endpoint_id == 'ip.interrupts'
    assert profile.interrupts[0].trigger == 'level'


def test_a_minimal_dma_profile_normalizes():
    profile = load_component_profile(minimal_dma())
    assert [endpoint.function for endpoint in profile.endpoints] == [
        'mmio_slave', 'memory_master', 'interrupt_source']
    assert profile.capabilities['master_address_width'] == 30
    assert profile.address.window_size == 16


@pytest.mark.parametrize('document,match', [
    # The envelope: no schema, unknown key, missing clock.
    (minimal_cpu(schema_version=None), 'unsupported-profile-schema'),
    (minimal_cpu(notes='no such field'), 'unknown-profile-field:notes'),
    (minimal_cpu(clocks=[]), 'profile-clock-required'),
    (minimal_cpu(resets=[]), 'profile-reset-required'),
    # The CPU contract: it is what makes a CPU a CPU.
    (minimal_cpu(cpu=None), 'cpu-profile-requires-cpu-contract'),
    (minimal_cpu(cpu={'family': 'riscv'}), 'invalid-cpu-xlen'),
    (minimal_cpu(cpu={'family': 'riscv', 'xlen': 32, 'reset_vector': 0,
                      'master_endpoints': []}), 'cpu-master-endpoints-required'),
    # An endpoint has to say what it is and, for a protocol function, which bus.
    (minimal_ip(endpoints=[{'endpoint_id': 'ip.bus',
                            'fields': [{'role': 'paddr', 'aliases': ['paddr']}]}]),
     'invalid-endpoint-function'),
    (minimal_ip(endpoints=[{'endpoint_id': 'ip.bus', 'function': 'mmio_slave',
                            'fields': [{'role': 'paddr', 'aliases': ['paddr']}]}]),
     'endpoint-protocol-required'),
    # The register map: a peripheral without a window is not addressable, and a
    # window has to be a power of two.
    (minimal_ip(address=None), 'peripheral-profile-requires-address'),
    (minimal_ip(address={'window_size': 3, 'alignment': 4, 'registers': []}),
     'address-window-not-power-of-two'),
    (minimal_ip(address={'window_size': 4096, 'alignment': 48, 'registers': []}),
     'address-alignment-not-power-of-two'),
    # The IRQ declaration: polarity and clock domain are the two facts the
    # delivery contract cannot invent.
    (minimal_ip(interrupts=[{'endpoint_id': 'ip.interrupts', 'role': 'irq',
                             'clock_domain': 'core', 'trigger': 'level'}]),
     'invalid-interrupt-polarity'),
    (minimal_ip(interrupts=[{'endpoint_id': 'ip.interrupts', 'role': 'irq',
                             'polarity': 'active_high', 'trigger': 'level'}]),
     'invalid-interrupt-domain'),
    (minimal_ip(interrupts=[{'endpoint_id': 'ip.interrupts', 'role': 'irq',
                             'polarity': 'active_high', 'clock_domain': 'core',
                             'trigger': 'pulse'}]),
     'interrupt-pulse-width-required'),
])
def test_a_missing_required_field_is_refused_by_name(document, match):
    with pytest.raises(ComponentProfileError, match=match):
        load_component_profile(document)


def test_a_cpu_profile_may_not_declare_an_mmio_window():
    with pytest.raises(ComponentProfileError, match='cpu-profile-must-not-declare-mmio-address'):
        load_component_profile(minimal_cpu(address=minimal_ip()['address']))


def test_the_timing_mode_is_an_optional_capability():
    plain = load_component_profile(minimal_cpu())
    assert 'verilator_timing_mode' not in plain.capabilities
    timed = load_component_profile(minimal_cpu(
        capabilities=dict(minimal_cpu()['capabilities'],
                          verilator_timing_mode='timing')))
    assert timed.capabilities['verilator_timing_mode'] == 'timing'


def test_the_checked_in_cpu_profiles_still_normalize():
    for name in ('ibex_rvfi_local', 'cv32e40p_rvfi_local', 'cv32e20',
                 'picorv32_wb_irq_rvfi'):
        profile = load_component_profile(
            ROOT / 'configs/cpus' / name / 'component_profile.json')
        assert profile.kind == 'cpu'
        assert profile.cpu.master_endpoints
        endpoint_ids = {endpoint.endpoint_id for endpoint in profile.endpoints}
        assert set(profile.cpu.master_endpoints) <= endpoint_ids


def test_the_checked_in_ip_and_dma_profiles_still_normalize():
    for name in ('pulp_timer_irq', 'pulp_i2c', 'pulp_spi', 'zipdma_smoke'):
        profile = load_component_profile(
            ROOT / 'configs/peripherals' / name / 'component_profile.json')
        assert profile.kind == 'peripheral'
        assert profile.address is not None and profile.address.window_size > 0
        assert profile.address.registers


# --- the retirement face and the address route -------------------------------

def test_a_cpu_without_the_rvfi_trap_export_is_not_a_trap_claim():
    from scripts.run_inprocess_f1f6 import cpu_rvfi_trap_port
    assert cpu_rvfi_trap_port({}) is None
    assert cpu_rvfi_trap_port({'physical_exports': [
        {'physical_port': 'rvfi_valid', 'direction': 'output'},
        {'physical_port': 'rvfi_insn', 'direction': 'output'}]}) is None
    port = cpu_rvfi_trap_port({'physical_exports': [
        {'physical_port': 'rvfi_trap', 'direction': 'output',
         'runtime_name': 'rt_rvfi_trap'}]})
    assert port == {'physical_port': 'rvfi_trap', 'direction': 'output',
                    'runtime_name': 'rt_rvfi_trap'}
    with pytest.raises(ValueError, match='ambiguous rvfi_trap'):
        cpu_rvfi_trap_port({'physical_exports': [
            {'physical_port': 'rvfi_trap', 'direction': 'output'},
            {'physical_port': 'rvfi_trap', 'direction': 'output'}]})


def three_target_config():
    return {
        'targets': [
            {'name': 'timer', 'profile': 'configs/peripherals/pulp_timer_irq/component_profile.json',
             'active_id': 'timer_active', 'window': {'base': 0x40001000, 'size': 4096}},
            {'name': 'i2c', 'profile': 'configs/peripherals/pulp_i2c/component_profile.json',
             'active_id': 'i2c_active', 'window': {'base': 0x40002000, 'size': 4096}},
            {'name': 'spi', 'profile': 'configs/peripherals/pulp_spi/component_profile.json',
             'active_id': 'spi_active', 'window': {'base': 0x20002000, 'size': 4096}},
        ],
        'image_start': 0x10000,
        'image_end': 0x30000,
    }


def test_three_declared_targets_normalize_and_route_by_address():
    config = three_target_config()
    declared = declared_targets(config)
    assert [row['name'] for row in declared] == ['timer', 'i2c', 'spi']
    assert [row['index'] for row in declared] == [0, 1, 2]
    windows = target_windows(config)
    assert windows['target_count'] == 3
    assert route_address(windows, 0x40001000) == (0, 0)
    assert route_address(windows, 0x40002004) == (1, 4)
    assert route_address(windows, 0x20002000) == (2, 0)
    # RAM, and an address outside every declared window, are not target words.
    assert route_address(windows, 0x00014000) is None
    assert route_address(windows, 0x50000000) is None


def test_three_target_overlap_and_duplicate_names_are_refused_by_name():
    config = three_target_config()
    config['targets'][2]['window'] = {'base': 0x40002800, 'size': 4096}
    with pytest.raises(MultiTargetError, match='unsupported-window-overlap:target'):
        declared_targets(config)
    config = three_target_config()
    config['targets'][1]['name'] = 'timer'
    with pytest.raises(MultiTargetError, match='unsupported-target-name-duplicate:timer'):
        declared_targets(config)
    config = three_target_config()
    config['targets'][1]['active_id'] = 'timer_active'
    with pytest.raises(MultiTargetError, match='unsupported-target-active-id-duplicate'):
        declared_targets(config)


def test_the_three_ip_scenario_declares_three_routable_windows():
    path = ROOT / 'configs/scenarios/inprocess-obi-apb-three-ip-timer-i2c-spi-f1f6.json'
    config = json.loads(path.read_text())
    windows = target_windows(config)
    assert windows['target_count'] == 3
    assert [row['base'] for row in windows['ip_targets']] == [
        0x40001000, 0x40002000, 0x20002000]
    assert route_address(windows, 0x20002018) == (2, 0x18)
