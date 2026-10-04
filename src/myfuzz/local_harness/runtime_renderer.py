"""Source-admitted runtime tops; adapters stay outside the structural wrapper.

This stage emits no C++ transport. Backend ports and physical exports retain
width/ownership metadata for the later driver and build stages.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import bind_profile, elaborate_profile, load_component_profile
from .plan import LocalHarnessPlan
from myfuzz.composition.soc_port_dispositions import build_port_dispositions
from .renderer import RenderedLocalHarness, render_local_harness, _sha
from .runtime_artifact import LocalRuntimeArtifact
from .source_lock import verify_local_source_lock
from .axi4_fields import AXI_SHAPE
from .request import LocalHarnessRequestV2
from .tlul_register_template import register_observe_policy

_NATIVE = {'valid': ('output', 1), 'addr': ('output', 32), 'wdata': ('output', 32), 'wstrb': ('output', 4), 'ready': ('input', 1), 'rdata': ('input', 32)}

_OBI_READ = {'req': ('output', 1), 'addr': ('output', 32), 'gnt': ('input', 1),
             'rvalid': ('input', 1), 'rdata': ('input', 32), 'error': ('input', 1)}
_OBI_WRITE = {**_OBI_READ, 'we': ('output', 1), 'wdata': ('output', 32), 'be': ('output', 4)}
_APB = {'paddr': ('input', 12), 'psel': ('input', 1), 'penable': ('input', 1),
        'pwrite': ('input', 1), 'pwdata': ('input', 32), 'pready': ('output', 1),
        'prdata': ('output', 32), 'pslverr': ('output', 1)}
_WISHBONE = {'cyc': ('output', 1), 'stb': ('output', 1),
             'we': ('output', 1), 'adr': ('output', 32),
             'dat_w': ('output', 32), 'sel': ('output', 4),
             'ack': ('input', 1), 'dat_r': ('input', 32)}
_WISHBONE_TIMER = {'cyc': ('input', 1), 'stb': ('input', 1),
                   'we': ('input', 1), 'dat_w': ('input', 32), 'sel': ('input', 4),
                   'ack': ('output', 1), 'stall': ('output', 1),
                   'dat_r': ('output', 32)}
_WISHBONE_UART = {**_WISHBONE_TIMER, 'adr': ('input', 2)}
_AXI_LITE = {
    'awvalid': ('output', 1), 'awready': ('input', 1), 'awaddr': ('output', 32), 'awprot': ('output', 3),
    'wvalid': ('output', 1), 'wready': ('input', 1), 'wdata': ('output', 32), 'wstrb': ('output', 4),
    'bvalid': ('input', 1), 'bready': ('output', 1),
    'arvalid': ('output', 1), 'arready': ('input', 1), 'araddr': ('output', 32), 'arprot': ('output', 3),
    'rvalid': ('input', 1), 'rready': ('output', 1), 'rdata': ('input', 32),
}
_AXI_LITE_TARGET = {
    role: ('input' if direction == 'output' else 'output',
           4 if role in ('awaddr', 'araddr') else width)
    for role, (direction, width) in {
        **_AXI_LITE, 'bresp': ('input', 2), 'rresp': ('input', 2)
    }.items()
}
_TLUL = {
    **{role: ('input', width) for role, width in (
        ('a_valid', 1), ('a_opcode', 3), ('a_param', 3), ('a_size', 2),
        ('a_source', 8), ('a_address', 32), ('a_mask', 4), ('a_data', 32),
        ('a_user', 23), ('d_ready', 1))},
    **{role: ('output', width) for role, width in (
        ('a_ready', 1), ('d_valid', 1), ('d_opcode', 3), ('d_param', 3),
        ('d_size', 2), ('d_source', 8), ('d_sink', 1), ('d_data', 32),
        ('d_user', 14), ('d_error', 1))},
}


def _obi_boot_contract(cpu, address_width, endpoints):
    """Record a configured boot base without assuming the first fetch offset."""
    if cpu is None or type(address_width) is not int or address_width < 1:
        raise ValueError('runtime-cpu-boot-contract')
    address = cpu.reset_vector
    if type(address) is not int or address < 0 or address >= 1 << address_width or address % 4:
        raise ValueError('runtime-cpu-boot-address')
    if set(cpu.master_endpoints) != {endpoint.endpoint_id for endpoint in endpoints}:
        raise ValueError('runtime-cpu-master-endpoints')
    return {'configured_boot_base': address, 'expected_first_fetch': None,
            'first_fetch_verification': 'runtime_observation_required'}


def _admit(plan, structural, supplied, root):
    path = (root / plan.request.profile_path).resolve()
    if not path.is_relative_to(root / 'configs'):
        raise ValueError('runtime-profile-outside-configs')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != plan.profile_sha256:
        raise ValueError('runtime-profile-hash-mismatch')
    if load_component_profile(json.loads(raw)) != plan.profile:
        raise ValueError('runtime-profile-object-mismatch')
    verified = verify_local_source_lock(plan.profile, base_dir=root)
    if supplied != verified:
        raise ValueError('runtime-source-verification-mismatch')
    if elaborate_profile(plan.profile, base_dir=root) != plan.facts:
        raise ValueError('runtime-physical-facts-mismatch')
    if plan.facts.revision != plan.profile.source.revision:
        raise ValueError('runtime-source-revision-mismatch')
    for name, text in plan.parameter_sources:
        source = (root / plan.profile.source.source_root / name).resolve()
        if not source.is_relative_to(root / plan.profile.source.source_root):
            raise ValueError('runtime-source-outside-root')
        if source.read_bytes() != text.encode('utf-8'):
            raise ValueError('runtime-source-snapshot-mismatch')
    if bind_profile(plan.profile, plan.facts) != plan.binding:
        raise ValueError('runtime-binding-mismatch')
    expected_ledger = build_port_dispositions(
        plan.request.instance_id, plan.binding, clock_domain='local_clock',
        reset_domain='local_reset', profile_port_actions=plan.profile.port_actions)
    if expected_ledger != plan.dispositions:
        raise ValueError('runtime-disposition-profile-mismatch')
    if render_local_harness(plan) != structural:
        raise ValueError('runtime-structural-identity-mismatch')
    if len(plan.profile.clocks) != 1 or len(plan.profile.resets) != 1:
        raise ValueError('runtime-single-clock-reset-required')
    if plan.profile.resets[0].sequence_after:
        raise ValueError('runtime-reset-sequence-unsupported')
    return verified


def _apb_local_kind(endpoints, abi=(), capabilities=None):
    """Choose the local APB executor from the declared physical pin roles."""
    if capabilities is None:
        capabilities = {}
    pins = [endpoint for endpoint in endpoints
            if endpoint.function == 'external_pins']
    if not pins:
        observed = [row for row in abi if row['disposition'] == 'observe'
                    and row['direction'] == 'output']
        if (capabilities.get('local_runtime_variant') == 'apb_timer'
                and len(observed) == 1 and observed[0]['physical_port'] == 'irq_o'
                and observed[0]['width'] == 4):
            return 'apb_timer'
        raise ValueError('runtime-external-pin-shape')
    if len(pins) != 1:
        raise ValueError('runtime-external-pin-shape')
    fields = pins[0].fields
    observed = {field.role: (field.direction, field.width) for field in fields}
    gpio = {'in': ('input', 32), 'out': ('output', 32),
            'dir': ('output', 32), 'in_sync': ('output', 32),
            'padcfg': ('output', 128)}
    spi = {'sck': ('output', 1), 'mode': ('output', 2),
           **{f'csn{i}': ('output', 1) for i in range(4)},
           **{f'sdo{i}': ('output', 1) for i in range(4)},
           **{f'sdi{i}': ('input', 1) for i in range(4)}}
    i2c = {name: (direction, 1) for name, direction in (
        ('scl_pad_i', 'input'), ('scl_pad_o', 'output'),
        ('scl_padoen_o', 'output'), ('sda_pad_i', 'input'),
        ('sda_pad_o', 'output'), ('sda_padoen_o', 'output'))}
    if len(observed) != len(fields):
        raise ValueError('runtime-external-pin-shape')
    for kind, expected in (('apb_gpio', gpio), ('apb_spi', spi),
                           ('apb_i2c', i2c)):
        if observed == expected and (kind != 'apb_i2c' or
                                     capabilities.get('local_runtime_variant') == 'apb_i2c'):
            return kind
    raise ValueError('runtime-external-pin-shape')


def _shape(endpoint, expected, abi):
    fields = {field.role: field for field in endpoint.fields}
    if len(fields) != len(endpoint.fields) or set(fields) != set(expected):
        raise ValueError('runtime-endpoint-fields:' + endpoint.endpoint_id)
    wires = {}
    for role, field in fields.items():
        direction, width = expected[role]
        if (field.direction, field.width) != (direction, width):
            raise ValueError('runtime-endpoint-width-direction:' + endpoint.endpoint_id + ':' + role)
        rows = [row for row in abi if row['endpoint_id'] == endpoint.endpoint_id and row['role'] == role]
        if len(rows) != 1:
            raise ValueError('runtime-endpoint-abi:' + endpoint.endpoint_id + ':' + role)
        row = rows[0]
        if (row['physical_port'], row['bit_lo'], row['bit_hi'], row['width'], row['direction'], row['disposition']) != (
                field.port, field.raw_lo, field.raw_hi, field.width, field.direction, 'functional'):
            raise ValueError('runtime-endpoint-span:' + endpoint.endpoint_id + ':' + role)
        wires[role] = 'link_' + row['wrapper_name']
    return wires


def render_local_runtime(plan: LocalHarnessPlan, structural: RenderedLocalHarness,
                         source_verification: dict[str, object], *, base_dir: Path) -> LocalRuntimeArtifact:
    """Authenticate one supplied plan/structure and emit its runtime adapter top.

    base_dir explicitly chooses the checkout. Verification is refreshed here,
    and the caller's receipt must equal that fresh result exactly.
    """
    root = Path(base_dir).resolve()
    verified = _admit(plan, structural, source_verification, root)
    endpoints = [endpoint for endpoint in plan.binding.endpoints if endpoint.protocol is not None]
    abi = structural.abi_document['ports']
    cpu_functions = {'instruction_memory_master', 'data_memory_master'}
    functions = {endpoint.function for endpoint in endpoints}
    if len(endpoints) == 2 and functions == cpu_functions and all(e.protocol == ('obi', '1') for e in endpoints):
        kind = 'obi_cpu'
        boot = _obi_boot_contract(plan.profile.cpu, 32, endpoints)
        adapters = ['src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv']
    elif len(endpoints) == 1 and functions <= {'memory_master', 'processor_memory_master'} and endpoints[0].protocol == ('ready-valid-memory', '1'):
        from .native_contract import native_completion_contract
        selected = native_completion_contract(endpoints[0], plan.profile.capabilities)
        native_wait = min(plan.request.max_wait_cycles,
                          plan.profile.capabilities.get('max_wait_cycles', plan.request.max_wait_cycles))
        if plan.request.reset_release_ticks > native_wait:
            raise ValueError('runtime-native-reset-release-exceeds-wait-bound')
        kind = 'native_memory_cpu'
        boot = _obi_boot_contract(plan.profile.cpu, 32, endpoints)
        adapters = ['src/myfuzz/protocols/rtl/native_completion_memory_adapter.sv']
    elif len(endpoints) == 1 and functions == {'memory_master'} and endpoints[0].protocol == ('wishbone', 'classic'):
        capabilities = plan.profile.capabilities
        if (capabilities.get('address_width'), capabilities.get('data_width'),
                capabilities.get('byte_enable'), capabilities.get('max_outstanding'),
                capabilities.get('error_response')) != (32, 32, True, 1, False):
            raise ValueError('runtime-wishbone-capabilities')
        kind = 'wishbone_cpu'
        boot = _obi_boot_contract(plan.profile.cpu, 32, endpoints)
        adapters = []
    elif (len(endpoints) == 1 and functions == {'mmio_slave'}
          and endpoints[0].protocol == ('wishbone', 'classic')
          and plan.profile.capabilities.get('wishbone_flavour') == 'registered-ack-cyc-ignored'
          and plan.profile.capabilities.get('has_address_port') is False):
        c = plan.profile.capabilities
        if tuple(c.get(k) for k in ('data_width', 'byte_enable', 'partial_write',
                                   'has_error', 'has_address_port', 'address_units',
                                   'sel_implemented', 'wishbone_flavour',
                                   'ack_requires_cyc', 'max_outstanding')) != (
                32, False, False, False, False, 'word', False,
                'registered-ack-cyc-ignored', False, 1):
            raise ValueError('runtime-wishbone-timer-capabilities')
        if (plan.facts.selection != 'all' or len(plan.facts.ports) != 12
                or plan.profile.address is None or plan.profile.address.window_size != 4):
            raise ValueError('runtime-wishbone-timer-window')
        if any(e.function in ('external_pins', 'interrupt_source')
               for e in plan.binding.endpoints):
            raise ValueError('runtime-wishbone-timer-extra-endpoint')
        ce = [row for row in plan.dispositions if row.port == 'i_ce']
        irq = [row for row in plan.dispositions if row.port == 'o_int']
        if (len(ce) != 1 or ce[0].disposition != 'constant' or ce[0].value != 1
                or ce[0].direction != 'input' or ce[0].bit_lo != 0 or ce[0].bit_hi != 0
                or len(irq) != 1 or irq[0].disposition != 'observe'
                or irq[0].direction != 'output' or irq[0].bit_lo != 0 or irq[0].bit_hi != 0
                or plan.profile.interrupts):
            raise ValueError('runtime-wishbone-timer-clock-enable-irq-policy')
        kind = 'wishbone_timer'
        boot = None
        adapters = ['src/myfuzz/protocols/rtl/beat_to_wishbone.sv']
    elif (len(endpoints) == 1 and functions == {'mmio_slave'}
          and endpoints[0].protocol == ('wishbone', 'classic')
          and plan.profile.capabilities.get('local_runtime_variant') == 'wishbone_uart'):
        c = plan.profile.capabilities
        if tuple(c.get(k) for k in ('address_width', 'data_width', 'byte_enable',
                                   'partial_write', 'has_error', 'has_address_port',
                                   'address_units', 'sel_implemented', 'wishbone_flavour',
                                   'ack_requires_cyc', 'max_outstanding')) != (
                2, 32, True, True, False, True, 'word', True,
                'registered-ack', True, 1):
            raise ValueError('runtime-wishbone-uart-capabilities')
        if (plan.facts.selection != 'all' or len(plan.facts.ports) != 19
                or plan.profile.address is None or plan.profile.address.window_size != 16):
            raise ValueError('runtime-wishbone-uart-window')
        pins = [e for e in plan.binding.endpoints if e.function == 'external_pins']
        interrupts = [e for e in plan.binding.endpoints if e.function == 'interrupt_source']
        if (len(pins) != 1 or len(interrupts) != 1
                or {f.role: (f.direction, f.width) for f in pins[0].fields} != {
                    'rx': ('input', 1), 'tx': ('output', 1),
                    'cts_n': ('input', 1), 'rts_n': ('output', 1)}
                or {f.role: (f.direction, f.width) for f in interrupts[0].fields} != {
                    'rx': ('output', 1), 'tx': ('output', 1),
                    'rxfifo': ('output', 1), 'txfifo': ('output', 1)}):
            raise ValueError('runtime-wishbone-uart-pin-shape')
        kind = 'wishbone_uart'
        boot = None
        adapters = ['src/myfuzz/protocols/rtl/beat_to_wishbone.sv']
    elif len(endpoints) == 1 and functions <= {'memory_master', 'processor_memory_master'} and endpoints[0].protocol == ('axi4-lite', '1'):
        from .template_contracts import select_template_contract
        selected = select_template_contract(endpoints[0], plan.profile.capabilities,
            template_id='cpu.axi4-lite', template_version='1', variant_id='no-response-code')
        if (plan.profile.capabilities.get('address_width'), plan.profile.capabilities.get('data_width'),
                plan.profile.capabilities.get('byte_enable'), plan.profile.capabilities.get('error_response'),
                plan.profile.capabilities.get('max_outstanding')) != (32, 32, True, False, 1):
            raise ValueError('runtime-axi-lite-capabilities')
        kind = 'axi4_lite_cpu'
        boot = _obi_boot_contract(plan.profile.cpu, 32, endpoints)
        adapters = ['src/myfuzz/protocols/rtl/axi4_lite_processor_memory_adapter.sv']
    elif (len(endpoints) == 2 and functions == cpu_functions
          and all(e.protocol == ('axi4', '1') for e in endpoints)):
        if (plan.profile.capabilities.get('address_width'),
                plan.profile.capabilities.get('data_width'),
                plan.profile.capabilities.get('id_width'),
                plan.profile.capabilities.get('bursts')) != (32, 32, 1, True):
            raise ValueError('runtime-axi4-capabilities')
        kind = 'axi4_cpu'
        boot = _obi_boot_contract(plan.profile.cpu, 32, endpoints)
        adapters = []

    elif (len(endpoints) == 1 and functions == {'mmio_slave'}
          and endpoints[0].protocol == ('axi4-lite', '1')):
        kind = 'axi4_lite_uart'
        boot = None
        c = plan.profile.capabilities
        if tuple(c.get(name) for name in ('address_width', 'data_width', 'byte_enable',
                'partial_write', 'has_error', 'max_outstanding', 'bursts', 'ids',
                'local_runtime_variant')) != (4, 32, True, True, True, 1, False,
                                                False, 'axi4_lite_uart'):
            raise ValueError('runtime-axi-lite-uart-capabilities')
        if plan.profile.address is None or plan.profile.address.window_size != 16:
            raise ValueError('runtime-axi-lite-uart-window')
        pins = [e for e in plan.binding.endpoints if e.function == 'external_pins']
        interrupts = [e for e in plan.binding.endpoints if e.function == 'interrupt_source']
        if (len(pins) != 1 or len(interrupts) != 1
                or {f.role: (f.direction, f.width) for f in pins[0].fields} != {
                    'rx': ('input', 1), 'tx': ('output', 1),
                    'cts_n': ('input', 1), 'rts_n': ('output', 1)}
                or {f.role: (f.direction, f.width) for f in interrupts[0].fields} != {
                    'rx': ('output', 1), 'tx': ('output', 1),
                    'rxfifo': ('output', 1), 'txfifo': ('output', 1)}):
            raise ValueError('runtime-axi-lite-uart-pin-shape')
        adapters = []

    elif (len(endpoints) == 1 and functions == {'mmio_slave'}
          and endpoints[0].protocol == ('tl-ul', '1')):
        variant = plan.profile.capabilities.get('local_runtime_variant')
        kind = ('tlul_register_observe' if isinstance(plan.request, LocalHarnessRequestV2) else
                'tlul_timer' if variant == 'tlul_timer' else
                'tlul_spi_host' if variant == 'tlul_spi_host' else
                'tlul_uart' if variant == 'tlul_uart' else
                'tlul_i2c' if variant == 'tlul_i2c' else 'tlul_gpio')
        boot = None
        c = plan.profile.capabilities
        if tuple(c.get(k) for k in ('address_width', 'data_width', 'byte_enable',
                                   'partial_write', 'has_error', 'integrity',
                                   'source_width', 'sink_width', 'user_width',
                                   'd_user_width', 'size_width', 'max_outstanding')) != (
                32, 32, True, True, True, 'required', 8, 1, 23, 14, 2, 1):
            raise ValueError('runtime-tlul-capabilities')
        expected_window = (plan.profile.address.window_size if
                           kind == 'tlul_register_observe' and plan.profile.address is not None
                           else 4096 if kind in ('tlul_timer', 'tlul_spi_host', 'tlul_uart') else 128)
        if plan.profile.address is None or plan.profile.address.window_size != expected_window:
            raise ValueError('runtime-tlul-window')
        pins = [e for e in plan.binding.endpoints if e.function == 'external_pins']
        if kind == 'tlul_register_observe':
            register_observe_policy(plan, abi)
        elif kind == 'tlul_gpio':
            if len(pins) != 1 or {f.role: (f.direction, f.width) for f in pins[0].fields} != {
                    'in': ('input', 32), 'out': ('output', 32), 'en': ('output', 32),
                    'strap_en': ('input', 1)}:
                raise ValueError('runtime-tlul-pin-shape')
        elif kind == 'tlul_spi_host':
            if (len(pins) != 1 or {f.role: (f.direction, f.width) for f in pins[0].fields} != {
                    'sd_i': ('input', 4), 'sck': ('output', 1),
                    'csb': ('output', 1), 'sd_o': ('output', 4),
                    'sd_en': ('output', 4)}):
                raise ValueError('runtime-tlul-spi-host-pin-shape')
            interrupts = [e for e in plan.binding.endpoints if e.function == 'interrupt_source']
            if (len(interrupts) != 1 or
                    {f.role: (f.direction, f.width) for f in interrupts[0].fields} != {
                        'event': ('output', 1), 'error': ('output', 1)}):
                raise ValueError('runtime-tlul-spi-host-irq-shape')
        elif kind == 'tlul_uart':
            if len(pins) != 1 or {f.role: (f.direction, f.width) for f in pins[0].fields} != {
                    'rx': ('input', 1), 'tx': ('output', 1),
                    'tx_en': ('output', 1)}:
                raise ValueError('runtime-tlul-uart-pin-shape')
            interrupts = [e for e in plan.binding.endpoints if e.function == 'interrupt_source']
            irq_roles = ('tx_watermark', 'tx_empty', 'rx_watermark', 'tx_done',
                         'rx_overflow', 'rx_frame_err', 'rx_break_err',
                         'rx_timeout', 'rx_parity_err')
            if len(interrupts) != 1 or {f.role: (f.direction, f.width)
                                        for f in interrupts[0].fields} != {
                    role: ('output', 1) for role in irq_roles}:
                raise ValueError('runtime-tlul-uart-irq-shape')
        elif kind == 'tlul_i2c':
            expected_pins = {'scl_i': ('input', 1), 'scl_o': ('output', 1),
                             'scl_en_o': ('output', 1), 'sda_i': ('input', 1),
                             'sda_o': ('output', 1), 'sda_en_o': ('output', 1)}
            interrupts = [e for e in plan.binding.endpoints
                          if e.function == 'interrupt_source']
            if (len(pins) != 1 or len(interrupts) != 1
                    or {f.role: (f.direction, f.width) for f in pins[0].fields}
                    != expected_pins
                    or {f.role: (f.direction, f.width) for f in interrupts[0].fields}
                    != {'irq': ('output', 15)}):
                raise ValueError('runtime-tlul-i2c-pin-irq-shape')
        elif pins:
            raise ValueError('runtime-tlul-timer-pin-shape')
        adapters = ['src/myfuzz/protocols/rtl/beat_to_tlul.sv']
    elif len(endpoints) == 1 and functions == {'mmio_slave'} and endpoints[0].protocol == ('apb', '3'):
        kind = _apb_local_kind(plan.binding.endpoints, abi, plan.profile.capabilities)
        boot = None
        capabilities = plan.profile.capabilities
        if (capabilities.get('address_width'), capabilities.get('data_width'),
                capabilities.get('byte_enable'), capabilities.get('partial_write'),
                capabilities.get('has_error')) != (12, 32, False, False, True):
            raise ValueError('runtime-apb-capabilities')
        if plan.profile.address is None or plan.profile.address.window_size != 4096:
            raise ValueError('runtime-apb-window')
        adapters = ['src/myfuzz/protocols/rtl/beat_to_apb.sv']
    else:
        raise ValueError('runtime-unsupported-protocol-shape')
    adapted = {e.endpoint_id for e in endpoints}
    # Functional nonprotocol fields are exclusively environment-owned external
    # IRQ inputs in this first scope. Peer ownership cannot silently become IO.
    for row in abi:
        if row['endpoint_id'] in adapted:
            continue
        if row['disposition'] == 'peer':
            raise ValueError('runtime-peer-ownership-unsupported')
        if row['disposition'] == 'functional' and not (
                kind == 'tlul_register_observe' and row['direction'] == 'output' or
                kind == 'apb_spi' and row['endpoint_id'] == 'spi.pins' or
                kind == 'axi4_lite_uart' and row['endpoint_id'] in
                ('uart.pins', 'uart.interrupts') or
                kind == 'wishbone_uart' and row['endpoint_id'] in
                ('uart.pins', 'uart.interrupts') or
                kind == 'apb_i2c' and row['endpoint_id'] == 'i2c.pins' or
                kind == 'tlul_gpio' and row['endpoint_id'] == 'gpio.interrupts'
                and row['direction'] == 'output' and row['width'] == 32 or
                kind == 'tlul_timer' and row['endpoint_id'] == 'timer.interrupts'
                and row['direction'] == 'output' and row['width'] == 1 or
                kind == 'tlul_spi_host' and row['endpoint_id'] == 'spi_host.interrupts'
                and row['direction'] == 'output' and row['width'] == 1 or
                kind == 'tlul_uart' and row['endpoint_id'] in ('uart.pins', 'uart.interrupts') or
                kind == 'tlul_i2c' and row['endpoint_id'] == 'i2c.interrupts'
                and row['direction'] == 'output' and row['width'] == 15 or
                kind == 'obi_cpu' and row['direction'] == 'input' and row['width'] == 1
                and row['endpoint_id'] == plan.profile.cpu.irq_entry_endpoint
                and row['role'] == plan.profile.cpu.irq_entry_role):
            raise ValueError('runtime-functional-ownership-unsupported')
    ports = [('clk', 'input', 1), ('reset', 'input', 1)]
    locals_, statements, exports, backend, instances = [], [], [], [], []
    connections = ['.clk(clk)', '.reset(reset)']
    for row in abi:
        consumed = row['endpoint_id'] in adapted
        name = ('link_' if consumed else 'rt_') + row['wrapper_name']
        if consumed:
            locals_.append(f"logic [{row['width']-1}:0] {name};")
        else:
            ports.append((name, row['direction'], row['width']))
            exports.append({**row, 'runtime_name': name,
                            'encoding': 'fixed_width_hex' if row['width'] > 64 else 'integer',
                            'hex_digits': (row['width']+3)//4})
        connections.append(f".{row['wrapper_name']}({name})")

    def beat_ports(prefix, cpu):
        directions = {'req_valid': 'output' if cpu else 'input', 'req_ready': 'input' if cpu else 'output',
                      'req_write': 'output' if cpu else 'input', 'req_addr': 'output' if cpu else 'input',
                      'req_wdata': 'output' if cpu else 'input', 'req_be': 'output' if cpu else 'input',
                      'rsp_valid': 'input' if cpu else 'output', 'rsp_ready': 'output' if cpu else 'input',
                      'rsp_rdata': 'input' if cpu else 'output', 'rsp_error': 'input' if cpu else 'output'}
        for role, direction in directions.items():
            width = 32 if role in ('req_addr', 'req_wdata', 'rsp_rdata') else 4 if role == 'req_be' else 1
            name = prefix + '_' + role
            ports.append((name, direction, width))
            backend.append(dict(name=name, direction=direction, width=width, role=role, channel=prefix))

    if kind == 'wishbone_cpu':
        wires = _shape(endpoints[0], _WISHBONE, abi)
        for role, (direction, width) in _WISHBONE.items():
            name = 'wb_' + role
            ports.append((name, direction, width))
            backend.append(dict(name=name, direction=direction, width=width,
                                role=role, channel='wb'))
            statements.append(f'assign {name} = {wires[role]};' if direction == 'output'
                              else f'assign {wires[role]} = {name};')
    elif kind == 'axi4_lite_uart':
        wires = _shape(endpoints[0], _AXI_LITE_TARGET, abi)
        for role, (direction, width) in _AXI_LITE_TARGET.items():
            name = 'axil_' + role
            ports.append((name, direction, width))
            backend.append(dict(name=name, direction=direction, width=width,
                                role=role, channel='axil'))
            statements.append(f'assign {wires[role]} = {name};' if direction == 'input'
                              else f'assign {name} = {wires[role]};')
    elif kind == 'axi4_cpu':
        for endpoint in sorted(endpoints, key=lambda e: e.function):
            prefix = 'i' if endpoint.function == 'instruction_memory_master' else 'd'
            wires = _shape(endpoint, AXI_SHAPE, abi)
            for role, (direction, width) in AXI_SHAPE.items():
                name = prefix + '_' + role
                ports.append((name, direction, width))
                backend.append(dict(name=name, direction=direction, width=width,
                                    role=role, channel=prefix))
                statements.append(f'assign {name} = {wires[role]};' if direction == 'output'
                                  else f'assign {wires[role]} = {name};')
    elif kind == 'native_memory_cpu':
        wires = _shape(endpoints[0], _NATIVE, abi)
        beat_ports('m', True)
        for name, width in [('m_fault', 1), ('m_fault_code', 2)]:
            ports.append((name, 'output', width))
            backend.append(dict(name=name, direction='output', width=width, role=name[2:], channel='m'))
        pairs = dict(clk='clk', reset='reset', valid_i=wires['valid'], ready_o=wires['ready'],
            addr_i=wires['addr'], wdata_i=wires['wdata'], wstrb_i=wires['wstrb'], rdata_o=wires['rdata'],
            fault_o='m_fault', fault_code_o='m_fault_code')
        pairs.update({role + ('_o' if row['direction'] == 'output' else '_i'): row['name']
                      for row in backend if row['role'] not in ('fault', 'fault_code') for role in [row['role']]})
        instances.append('native_completion_memory_adapter #(\n'
            f'    .MAX_WAIT_CYCLES({native_wait})\n'
            '  ) u_native_completion (\n    ' + ',\n    '.join(f'.{p}({v})' for p,v in pairs.items()) + '\n  );')
    elif kind == 'axi4_lite_cpu':
        wires = _shape(endpoints[0], _AXI_LITE, abi)
        beat_ports('m', True)
        locals_.extend(['logic [1:0] unused_bresp;', 'logic [1:0] unused_rresp;'])
        pairs = {'clk_i': 'clk', 'rst_ni': '~reset'}
        for role, wire in wires.items():
            pairs[role + ('_i' if _AXI_LITE[role][0] == 'output' else '_o')] = wire
        pairs.update({'bresp_o': 'unused_bresp', 'rresp_o': 'unused_rresp'})
        pairs.update({row['role'] + ('_o' if row['direction'] == 'output' else '_i'): row['name']
                      for row in backend})
        instances.append('axi4_lite_processor_memory_adapter #(\n'
            '    .ADDRESS_WIDTH(32), .DATA_WIDTH(32)\n'
            '  ) u_axi_lite (\n    ' + ',\n    '.join(f'.{p}({v})' for p,v in pairs.items()) + '\n  );')
    elif kind == 'obi_cpu':
        for endpoint in sorted(endpoints, key=lambda e: e.function):
            instruction = endpoint.function == 'instruction_memory_master'
            prefix = 'i' if instruction else 'd'
            wires = _shape(endpoint, _OBI_READ if instruction else _OBI_WRITE, abi)
            beat_ports(prefix, True)
            pairs = dict(clk_i='clk', rst_ni='~reset', req_i=wires['req'], gnt_o=wires['gnt'],
                         addr_i=wires['addr'], we_i="1'b0" if instruction else wires['we'],
                         wdata_i="32'b0" if instruction else wires['wdata'],
                         be_i="4'b1111" if instruction else wires['be'], rvalid_o=wires['rvalid'],
                         rdata_o=wires['rdata'], error_o=wires['error'])
            pairs.update({role + ('_o' if row['direction'] == 'output' else '_i'): row['name']
                          for row in backend if row['channel'] == prefix for role in [row['role']]})
            instances.append('obi_processor_memory_adapter #(\n'
                             f'    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .READ_ONLY({int(instruction)}),\n'
                             f'    .HAS_BE({int(not instruction)}), .HAS_ERROR(1)\n'
                             f'  ) u_adapter_{prefix} (\n    ' + ',\n    '.join(f'.{p}({v})' for p,v in pairs.items()) + '\n  );')
    elif kind in ('wishbone_timer', 'wishbone_uart'):
        channel = 'uart' if kind == 'wishbone_uart' else 'timer'
        wires = _shape(endpoints[0], _WISHBONE_UART if kind == 'wishbone_uart' else _WISHBONE_TIMER, abi)
        beat_ports(channel, False)
        ports.append((channel+'_target_stb', 'output', 1))
        backend.append(dict(name=channel+'_target_stb', direction='output', width=1,
                            role='target_stb', channel=channel))
        statements.append(f"assign {channel}_target_stb = {wires['stb']};")
        declared_wait = plan.profile.capabilities['max_wait_cycles']
        if type(declared_wait) is not int or declared_wait < 1:
            raise ValueError('runtime-wishbone-timer-wait-bound')
        wait = min(declared_wait, plan.request.max_wait_cycles)
        locals_.extend(['logic unused_request_accepted;', 'logic unused_completion;'])
        if kind == 'wishbone_timer':
            locals_.append('logic unused_adr;')
        pairs = dict(clk='clk', reset='reset', req_valid=channel+'_req_valid',
                     req_ready=channel+'_req_ready', write=channel+'_req_write',
                     addr=channel+'_req_addr', wdata=channel+'_req_wdata', be=channel+'_req_be',
                     rsp_valid=channel+'_rsp_valid', rsp_ready=channel+'_rsp_ready',
                     rdata=channel+'_rsp_rdata', error=channel+'_rsp_error',
                     request_accepted='unused_request_accepted',
                     completion='unused_completion', err="1'b0",
                     **wires)
        if kind == 'wishbone_timer':
            pairs['adr'] = 'unused_adr'
        instances.append('beat_to_wishbone #(\n'
                         f'    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .WB_FLAVOUR({1 if kind == "wishbone_uart" else 2}),\n'
                         f'    .TARGET_ADDRESS_WIDTH({2 if kind == "wishbone_uart" else 0}), .ADDRESS_UNITS(1),\n'
                         f'    .SUPPORTS_PARTIAL_WRITE({1 if kind == "wishbone_uart" else 0}), .HAS_ERR(0),\n'
                         f'    .MAX_WAIT_CYCLES({wait}), .WINDOW_BASE(32\'d0), .WINDOW_SIZE({16 if kind == "wishbone_uart" else 4})\n'
                         f'  ) u_adapter_{channel} (\n    '+',\n    '.join(f'.{p}({v})' for p,v in pairs.items())+'\n  );')
    elif kind in ('tlul_gpio', 'tlul_timer', 'tlul_spi_host', 'tlul_uart', 'tlul_i2c', 'tlul_register_observe'):
        wires = _shape(endpoints[0], _TLUL, abi)
        channel = ('reg' if kind == 'tlul_register_observe' else
                   'timer' if kind == 'tlul_timer' else
                   'spi_host' if kind == 'tlul_spi_host' else
                   'uart' if kind == 'tlul_uart' else
                   'i2c' if kind == 'tlul_i2c' else 'gpio')
        beat_ports(channel, False)
        declared_wait = plan.profile.capabilities['max_wait_cycles']
        if type(declared_wait) is not int or declared_wait < 1:
            raise ValueError('runtime-tlul-wait-bound')
        wait = min(declared_wait, plan.request.max_wait_cycles)
        pairs = dict(clk='clk', reset='reset', req_valid=channel+'_req_valid',
                     req_ready=channel+'_req_ready', write=channel+'_req_write',
                     addr=channel+'_req_addr', wdata=channel+'_req_wdata', be=channel+'_req_be',
                     rsp_valid=channel+'_rsp_valid', rsp_ready=channel+'_rsp_ready',
                     rdata=channel+'_rsp_rdata', error=channel+'_rsp_error', **wires)
        instances.append('beat_to_tlul #(\n'
                         '    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .SIZE_WIDTH(2),\n'
                         '    .SOURCE_WIDTH(8), .SINK_WIDTH(1), .USER_WIDTH(23),\n'
                         '    .DUSER_WIDTH(14), .GEN_INTEGRITY(1), .SOURCE_ID(0),\n'
                         f'    .MAX_WAIT_CYCLES({wait}), .WINDOW_BASE(32\'d0), .WINDOW_SIZE({expected_window})\n'
                         f'  ) u_adapter_{channel} (\n    '+',\n    '.join(f'.{p}({v})' for p,v in pairs.items())+'\n  );')
    else:
        wires = _shape(endpoints[0], _APB, abi)
        channel = {'apb_spi': 'spi', 'apb_gpio': 'gpio',
                   'apb_timer': 'timer', 'apb_i2c': 'i2c'}[kind]
        beat_ports(channel, False)
        locals_.append('logic [31:0] apb_paddr;')
        locals_.append('logic [3:0] unused_pstrb;')
        statements.append(f"assign {wires['paddr']} = apb_paddr[11:0];")
        declared_wait = plan.profile.capabilities['max_wait_cycles']
        if type(declared_wait) is not int or declared_wait < 1:
            raise ValueError('runtime-apb-wait-bound')
        wait = min(declared_wait, plan.request.max_wait_cycles)
        pairs = dict(clk='clk', reset='reset', req_valid=f'{channel}_req_valid', req_ready=f'{channel}_req_ready',
                     write=f'{channel}_req_write', addr=f'{channel}_req_addr', wdata=f'{channel}_req_wdata', be=f'{channel}_req_be',
                     rsp_valid=f'{channel}_rsp_valid', rsp_ready=f'{channel}_rsp_ready', rdata=f'{channel}_rsp_rdata', error=f'{channel}_rsp_error',
                     paddr='apb_paddr', pstrb='unused_pstrb', **{r: n for r,n in wires.items() if r != 'paddr'})
        instances.append('beat_to_apb #(\n    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .HAS_PSTRB(0),\n'
                         '    .SUPPORTS_PARTIAL_WRITE(0), .HAS_PSLVERR(1),\n'
                         f"    .MAX_WAIT_CYCLES({wait}), .WINDOW_BASE(32'd0), .WINDOW_SIZE(4096)\n"
                         f'  ) u_adapter_{channel} (\n    '+',\n    '.join(f'.{p}({v})' for p,v in pairs.items())+'\n  );')
    module = 'local_runtime_' + plan.request.instance_id
    declarations = [f'{direction} logic [{width-1}:0] {name}' for name,direction,width in ports]
    runtime = ('module ' + module + ' (\n  ' + ',\n  '.join(declarations) + '\n);\n'
               + '\n'.join('  '+line for line in [*locals_, *statements]) + '\n'
               + '  ' + structural.module_name + ' u_component (\n    '
               + ',\n    '.join(connections) + '\n  );\n  ' + '\n  '.join(instances) + '\nendmodule\n')
    flags = list(structural.build_document['lint_argv'])
    flags[flags.index('--top-module')+1] = module
    adapter_hashes = [dict(path=name, sha256=hashlib.sha256((root/name).read_bytes()).hexdigest()) for name in adapters]
    document = dict(schema_version='local_runtime_artifact.v1', status='top_only', kind=kind,
                    module_name=module, plan=plan.document(), structural_abi=copy.deepcopy(structural.abi_document),
                    structural_build=copy.deepcopy(structural.build_document), source_verification=copy.deepcopy(verified),
                    boot_contract=boot,
                    effective_max_wait_cycles=(wait if kind in ('apb_gpio', 'apb_spi', 'apb_timer', 'apb_i2c', 'tlul_gpio', 'tlul_timer', 'tlul_spi_host', 'tlul_uart', 'tlul_i2c', 'tlul_register_observe', 'wishbone_timer', 'wishbone_uart') else native_wait if kind == 'native_memory_cpu' else plan.request.max_wait_cycles),
                    runtime_sv_sha256=hashlib.sha256(runtime.encode()).hexdigest(), cpp_sha256=hashlib.sha256(b'').hexdigest(),
                    adapted_endpoint_ids=sorted(adapted), physical_exports=exports, backend_ports=backend,
                    runtime_ports=[dict(name=n,direction=d,width=w) for n,d,w in ports],
                    adapter_sources=adapter_hashes, lint_argv=flags+adapters,
                    wire_schema_version='local_driver.v1', driver_status='not_generated')
    if kind == 'tlul_register_observe':
        fixed, dynamic = register_observe_policy(plan, abi)
        document['fixed_physical_inputs'] = [
            {'endpoint_id': row['endpoint_id'], 'role': row['role'],
             'runtime_name': row['runtime_name'], 'width': row['width'],
             'value': fixed[(row['endpoint_id'], row['role'])]}
            for row in exports if row['direction'] == 'input'
            and (row['endpoint_id'], row['role']) in fixed]
        document['dynamic_physical_inputs'] = [
            {'endpoint_id': row['endpoint_id'], 'role': row['role'],
             'input_name': row['endpoint_id'] + '.' + row['role'],
             'runtime_name': row['runtime_name'], 'width': row['width'],
             'source_id': dynamic[(row['endpoint_id'], row['role'])]}
            for row in exports if row['direction'] == 'input'
            and (row['endpoint_id'], row['role']) in dynamic]
        document['functional_scope'] = 'tlul_register_only_pin_observe_no_serial'
    if kind in ('native_memory_cpu', 'axi4_lite_cpu'):
        document['selected_template'] = selected.document()
    if kind in ('native_memory_cpu', 'wishbone_cpu'):
        marker = plan.profile.capabilities.get('instruction_identity_port')
        if kind == 'wishbone_cpu' and (type(marker) is not str or not marker):
            raise ValueError('runtime-wishbone-instruction-observation-required')
        if marker is not None:
            rows = [row for row in exports if row['physical_port'] == marker
                    and row['direction'] == 'output' and row['width'] == 1
                    and row['disposition'] == 'observe']
            if len(rows) != 1:
                raise ValueError('runtime-cpu-instruction-observation')
            document['instruction_identity_observation'] = rows[0]['runtime_name']
    document['artifact_digest'] = _sha(document)
    return LocalRuntimeArtifact(copy.deepcopy(plan), copy.deepcopy(structural), copy.deepcopy(verified), runtime, '', document)
