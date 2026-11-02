"""Pinned SPI source facts for the two-owner elaboration closure."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, _source_locator
from myfuzz.composition.source_crawler import _content_hash


_PINNED_UNION_REVISION = 'sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230'
_PINNED_PARAMETERS = {'APB_ADDR_WIDTH': '12', 'BUFFER_DEPTH': '10'}
#: The only event outputs this RTL drives: apb_spi_master.sv:116-117 assigns
#: ``events_o[0] = s_int_tx | s_int_rx`` and ``events_o[1] = s_eot``, both one
#: cycle wide and neither read back.  A declaration may pick one of the two.
_EVENT_BITS = (0, 1)
#: Register side effects that would claim a state a handler can latch or clear.
#: The pinned RTL has none: ``spi_master_apb_if.sv:82`` decodes REG_INTSTA as a
#: read with no arm in the read mux (:210-211), so the status word reads 0.
_CLEAR_CLAIMS = ('read_clears', 'write_1_to_clear')
_EVENT_PORT = 'events_o'
_STATUS_OFFSET = 0x28


def _declared_event_sources(profile: ComponentProfile) -> list:
    """Admit event outputs declared as pulse interrupts; refuse latch/clear claims.

    The pinned RTL drives two one-cycle event bits (:116-117) and keeps no status
    bit a handler could latch, clear or read back (``spi_master_apb_if.sv:82`` with
    no read-mux arm at :210-211).  So an event output may be declared as a pulse
    interrupt source, but only as a pulse, with its own declared width, on one of
    the two real event bits, and never with a latched-status or clear claim.
    """
    endpoints = {endpoint.endpoint_id: endpoint for endpoint in profile.endpoints}
    declared = []
    for source in profile.interrupts:
        if source.trigger != 'pulse':
            # A level (or edge-detected level) declaration claims the device holds
            # the event until software acknowledges it. It does not.
            raise ValueError('pulp-spi-interrupt-must-be-pulse')
        if source.pulse_width_cycles is None:
            # The width is the capture contract the controller's per-cycle sampling
            # relies on; without it the pulse would be stretched by guesswork.
            raise ValueError('pulp-spi-interrupt-pulse-width-required')
        if source.bit is None or source.bit not in _EVENT_BITS:
            raise ValueError('pulp-spi-interrupt-bit-unsupported')
        endpoint = endpoints.get(source.endpoint_id)
        if endpoint is None or endpoint.function != 'interrupt_source':
            raise ValueError('pulp-spi-interrupt-endpoint-unsupported')
        fields = [field for field in endpoint.fields
                  if field.role == source.role and field.direction == 'output'
                  and _EVENT_PORT in field.aliases]
        if len(fields) != 1:
            raise ValueError('pulp-spi-interrupt-not-on-events_o')
        if type(fields[0].width) is int and source.bit >= fields[0].width:
            raise ValueError('pulp-spi-interrupt-bit-unsupported')
        declared.append(source)
    registers = () if profile.address is None else profile.address.registers
    for register in registers:
        if register.side_effect in _CLEAR_CLAIMS:
            raise ValueError('pulp-spi-interrupt-clear-claim-unsupported')
    return declared


def verify_pulp_spi_source_contract(profile: ComponentProfile, *, base_dir: Path) -> dict:
    """Authenticate the selected bytes/closure and the full-top union profile.

    Requires a repository checkout with scripts/verify_soc_sources.py. This
    The artifact gate calls this verifier for the exact PULP SPI union profile.
    """
    if not isinstance(profile, ComponentProfile):
        raise ValueError('pulp-spi-profile-required')
    if profile.source != _source_locator(profile.source_document):
        raise ValueError('pulp-spi-source-inconsistent')
    root = Path(base_dir).resolve()
    raw_lock = (root / 'configs/soc/sources.lock.json').read_bytes()
    lock = json.loads(raw_lock)
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_pulp_spi_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('pulp-spi-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(lock)
    records = {record['id']: record for record in lock['components']}
    selected = [records[name] for name in ('pulp_spi', 'pulp_spi_dependencies')]
    owners = verifier.document_owners(lock, root)
    allowed = verifier.document_roots(lock)
    verified = []
    for record in selected:
        if (record['source_status'], record['elaboration_status'], record['closure_status']) != (
                'source_verified', 'elaboration_verified', 'selected'):
            raise ValueError('pulp-spi-source-unverified')
        verified.append(verifier.verify_record(record, root, owners=owners,
                                               allowed_roots=allowed[record['id']], replay=False))
    record = records['pulp_spi']
    closure_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(closure_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('pulp-spi-closure-changed')
    closure = json.loads(closure_raw)
    source = profile.source_document
    files = [str(Path(item['root']).relative_to('third_party') / item['path'])
             for item in closure['closure_files']]
    expected_parameters = {item['name']: item['value'] for item in record['typed_parameters']}
    settings = source.get('elaboration', {})
    parameters = {item['name']: item['value'] for item in settings.get('parameters', [])}
    if (profile.component_id != 'pulp_spi' or source['root'] != 'third_party'
            or source['top_module'] != 'apb_spi_master'
            or source.get('top_port_selection', 'all') != 'all'
            or sorted(source.get('files', [])) != sorted(files)
            or len(source.get('files', [])) != len(files)
            or source.get('filelist') or source.get('include_roots')
            or source.get('repositories') or source.get('filelist_variables')):
        raise ValueError('pulp-spi-union-source-mismatch')
    if (settings.get('frontend') != 'verilator-json' or settings.get('defines')
            or parameters != _PINNED_PARAMETERS
            or parameters != expected_parameters
            or parameters != {item['name']: item['value'] for item in closure['parameters']}):
        raise ValueError('pulp-spi-parameters-mismatch')
    contents = {relative: (root / 'third_party' / relative).read_bytes() for relative in files}
    if (source['revision'] != _PINNED_UNION_REVISION
            or source['revision'] != _content_hash(contents)):
        raise ValueError('pulp-spi-union-pin-mismatch')
    if (len(profile.clocks) != 1 or profile.clocks[0].port != 'HCLK'
            or len(profile.resets) != 1 or profile.resets[0].port != 'HRESETn'
            or profile.resets[0].polarity != 'active_low'
            or profile.resets[0].synchronous):
        raise ValueError('pulp-spi-clock-reset-mismatch')
    expected_capabilities = {'address_width': 12, 'data_width': 32,
                             'read': True, 'write': True, 'byte_enable': False,
                             'partial_write': False, 'has_error': True}
    if any(profile.capabilities.get(name) != value
           for name, value in expected_capabilities.items()):
        raise ValueError('pulp-spi-capability-mismatch')
    declared = _declared_event_sources(profile)
    if declared:
        # One owner per physical output: an observation action and an interrupt
        # source on the same wire are two declarations of one port.
        if any(action.port == _EVENT_PORT for action in profile.port_actions):
            raise ValueError('pulp-spi-event-port-double-declared')
    elif not any(action.port == _EVENT_PORT and action.action == 'observe'
                 for action in profile.port_actions):
        raise ValueError('pulp-spi-native-event-observation-required')
    return {
        'schema_version': 'pulp_spi_native_contract.v1',
        'source_records': verified, 'closure_files': closure['closure_files'],
        'lock_sha256': hashlib.sha256(raw_lock).hexdigest(),
        'closure_sha256': hashlib.sha256(closure_raw).hexdigest(),
        'profile_union_revision': source['revision'],
        'artifact_source_gate_compatible': True,
        'artifact_source_gate_gap': None,
        'runtime_effective': False, 'dut_semantics_verified': False,
        'clock_reset': {'clock': 'HCLK', 'reset': 'HRESETn',
                        'polarity': 'active_low', 'synchronous': False},
        'apb': {'template_id': 'target.apb3', 'template_version': '1',
                'variant_id': 'full-word', 'pready': 'constant_one',
                'pslverr': 'constant_zero', 'address_decode': 'PADDR[5:2]',
                'register_alias_bytes': 64, 'partial_write': False},
        'serial': {'cpol': 0, 'cpha': 0, 'bit_order': 'msb_first',
                   'sck': 'spi_clk', 'mosi': 'spi_sdo0', 'miso': 'spi_sdi1',
                   'chip_selects': ['spi_csn0', 'spi_csn1', 'spi_csn2', 'spi_csn3'],
                   'line_width_mode': 'spi_mode', 'supported_peer_mode': 'single_line_only',
                   'setup_mode_transient': 'mode_2_selected_idle_low_before_any_edge',
                   'hclk_cycles_per_sck': '2*(CLKDIV+1)',
                   'data_length_unit': 'bits', 'fifo_word_bits': 32,
                   'software_reset_scope': 'fifos_only'},
        'environment_sources': {'spi_sdi0': 'constant_zero', 'spi_sdi1': 'native_peer_miso',
                                'spi_sdi2': 'constant_zero', 'spi_sdi3': 'constant_zero'},
        'events': [
            {'port': 'events_o', 'bit': 0, 'trigger': 'native_pulse',
             'meaning': 'tx_or_rx_threshold', 'rearm_read_offset': 0x28,
             'rearm_read_value': 0, 'level_conversion': False},
            {'port': 'events_o', 'bit': 1, 'trigger': 'native_pulse',
             'meaning': 'end_of_transfer', 'level_conversion': False},
        ],
        # What the profile declared about the event outputs, and what stays true
        # about the device regardless of the declaration.  The two are kept apart
        # so a pulse source can never be read as a status register.
        'declared_interrupts': [
            {'endpoint_id': source.endpoint_id, 'role': source.role,
             'bit': source.bit, 'trigger': source.trigger,
             'polarity': source.polarity, 'clock_domain': source.clock_domain,
             'source_id': source.source_id,
             'pulse_width_cycles': source.pulse_width_cycles}
            for source in declared],
        'interrupt_semantics': {
            'trigger': 'pulse', 'latched_status': None, 'software_clear': None,
            'status_register': {'offset': _STATUS_OFFSET, 'readback_value': 0,
                                'read_mux': 'absent',
                                'reason': 'spi_master_apb_if.sv:82,210-211 has no '
                                          'read mux arm for REG_INTSTA'},
            'trigger_source': 'native end-of-transfer event, not a status bit',
        },
    }
