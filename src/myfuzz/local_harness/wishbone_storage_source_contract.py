"""Closed, source-reviewed Wishbone storage descriptions, never live authority.

G8.1 first row: ZipCPU ``wbuart`` ``SETUP`` at word index 0.  The 32-bit read
word is stable storage; writing it also resets UART RX/TX state, and that
effect is explicitly outside this row.  This module is a documentary
descriptor, not a generated hierarchy, token or version issuer.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, EndpointSpec, ProfileField

_ID = 'zipcpu-wbuart.setup.storage.v1'
_ROOT = 'third_party/soc-zipcpu-wbuart'
_REVISION = 'git:f43a6b83c3a70fb2ac0696a45c5545b233fb860b'
_SOURCES = (
    ('rtl/wbuart.v', '9733247cdf577e41f317109b08d973f7b0a061e6566d9afdbdb915d778db1ce9'),
    ('rtl/ufifo.v', '83c8894d6b36cebd33ade16d117a0eb6f7dc183e84eb17818edda48330cf0af5'),
    ('rtl/rxuart.v', '6d7764726b82bf6daa3272f54d1a4e8496baba5501fdadc8095acdef68c27bbd'),
    ('rtl/txuart.v', '740162a836b695b4cda844c557a6aa94d02c8a0386f4d40d59c77ebf2f850cba'),
)
_PARAMETERS = dict(HARDWARE_FLOW_CONTROL_PRESENT=1, INITIAL_SETUP=25, LGFLEN=4)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _registered_document():
    # Facts read from wbuart.v at the pinned revision.  The register word is
    # stable; SETUP writes additionally reset RX/TX state (wbuart.v:284,406),
    # and that effect is not part of this row.
    doc = dict(
        schema_version='wishbone_storage_source_contract.v1', contract_id=_ID,
        scope='source_reviewed_wishbone_storage_row', authority=False,
        source_authority=False, native_verified=False, hierarchy_verified=False,
        reset_authority=False, version_authority=False,
        source=dict(root=_ROOT, revision=_REVISION, top_module='wbuart',
            files=dict(_SOURCES), include_roots=[], defines={},
            identity_basis='declared_pinned_revision_and_exact_reviewed_bytes_not_new_git_or_elaboration_verification'),
        parameters=dict(_PARAMETERS),
        register=dict(name='SETUP', canonical_offset=0, word_index=0, width=32,
            reset_value=25, read_mask=0x7fffffff, write_mask=0x7fffffff),
        clock=dict(port='i_clk', edge='posedge'),
        reset=dict(port='i_reset', polarity='active_high', synchronous=True,
            event='i_reset sampled on posedge i_clk'),
        decode=dict(address_units='word', address_width=2,
            canonical_word_index=0, window_bytes=16, mask=0x3, value=0,
            expression="i_wb_addr == 2'b00",
            child_select='localparam UART_SETUP = 2\'b00; delayed read decode r_wb_addr',
            ignored_bits=[], alias_period_bytes=16, host_alignment_bytes=4,
            host_alignment_scope='host byte offsets are converted to word index; only word 0 is SETUP'),
        storage_expression=dict(
            expression="{1'b0, u_component.u_dut.uart_setup}",
            status='prospective_not_codegen_or_native_verified',
            relative_source_storage='uart_setup',
            required_followup='verify_actual_elaborated_hierarchy_and_read_only_pre_post_probe_wiring'),
        writers=dict(complete_for_registered_source=True,
            scope='SETUP_word_storage_only',
            hold='uart_setup retains its value outside reset and selected SETUP writes',
            reset="if i_reset: uart_setup <= INITIAL_SETUP | (no-flow-control ? 31'h40000000 : 0)",
            bus_write='if i_wb_stb && i_wb_addr==UART_SETUP && i_wb_we: uart_setup byte lanes selected by i_wb_sel <= i_wb_data',
            commit='at posedge i_clk when !i_reset: selected per-byte overwrite or hold',
            read='registered mux casez(r_wb_addr): o_wb_data <= {1\'b0, uart_setup}; valid in the ACK cycle',
            priority=['synchronous_reset', 'selected_setup_byte_write', 'hold'],
            autonomous_ctrl_writers=[],
            all_alias_writes='word index 0 only; the 2-bit adr is a word index, so no byte-offset aliases',
            other_state='SETUP writes reset RX/TX state (wbuart.v:284,406); RX/TX FIFOs, serial pins and interrupts are separate effect/observation state and are not claimed',
            ready_error='o_wb_stall=0; no err pin; ACK in T+2, CYC must be held through the ACK cycle'),
        storage_scope=dict(kind='stable_word_value_only',
            effect='SETUP bits change UART baud/flow-control behaviour; UART RX/TX/FIFO/interrupt/serial behaviour is not claimed',
            excluded=['FIFO_STATUS', 'RXREG', 'TXREG', 'UART_RX', 'UART_TX',
                      'UART_RX_INT', 'UART_TX_INT', 'UART_RXFIFO_INT',
                      'UART_TXFIFO_INT']),
        source_review=[
            dict(file='rtl/wbuart.v', lines=[[63, 63], [79, 82], [87, 87],
                [114, 140], [284, 284], [488, 488], [495, 495], [502, 502],
                [512, 516], [520, 526]],
                fact='2-bit word address, UART_SETUP decode, per-byte SETUP writers/reset/read mux, registered ACK with CYC, stall tied 0; SETUP write resets RX/TX state')],
        not_claimed=['arbitrary_RTL_inference', 'native_hierarchy', 'generated_probe',
            'build_process_eligibility', 'reset_observation', 'live_register_version',
            'serialized_authority', 'complete_F4', 'P7', 'FIFO_STATUS', 'RXREG',
            'TXREG', 'UART_RX', 'UART_TX', 'UART_interrupts', 'serial_pins',
            'byte_masked_writes_at_runtime', 'STALL', 'ERR', 'G8.2_to_G8.10'])
    doc['digest'] = hashlib.sha256(_json(doc).encode()).hexdigest()
    return doc


def registered_wishbone_storage_source_contracts():
    return (_ID,)


def _verify_profile(profile, document):
    if type(profile) is not ComponentProfile:
        raise ValueError('wishbone-storage-profile-required')
    src = profile.source
    settings = src.elaboration
    source = document['source']
    register = document['register']
    if (src.source_root != source['root'] or src.revision != source['revision']
            or src.top_module != source['top_module']
            or src.files != tuple(source['files'])
            or src.filelist is not None or src.include_roots != ()
            or src.repositories != () or src.filelist_variables != ()
            or settings is None or settings.frontend != 'verilator-json'
            or settings.parameters != tuple((k, str(v)) for k, v in sorted(document['parameters'].items()))
            or settings.defines != () or settings.warning_policy != 'recorded-nonfatal'):
        raise ValueError('wishbone-storage-source-identity-unsupported')
    if (len(profile.clocks) != 1 or profile.clocks[0].port != 'i_clk'
            or len(profile.resets) != 1 or profile.resets[0].port != 'i_reset'
            or profile.resets[0].polarity != 'active_high'
            or type(profile.resets[0].synchronous) is not bool
            or profile.resets[0].synchronous is not True
            or profile.resets[0].sequence_after != ()):
        raise ValueError('wishbone-storage-clock-reset-mismatch')
    endpoints = [e for e in profile.endpoints if e.protocol is not None]
    roles = ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel', 'ack', 'stall', 'dat_r')
    if (len(endpoints) != 1 or endpoints[0].function != 'mmio_slave'
            or tuple(endpoints[0].protocol) != ('wishbone', 'classic')
            or tuple(field.role for field in endpoints[0].fields) != roles):
        raise ValueError('wishbone-storage-endpoint-mismatch')
    c = profile.capabilities
    if (c.get('data_width'), c.get('has_address_port'), c.get('address_units'),
            c.get('byte_enable'), c.get('partial_write'), c.get('has_error'),
            c.get('wishbone_flavour'), c.get('ack_requires_cyc')) != (
            32, True, 'word', True, True, False, 'registered-ack', True):
        raise ValueError('wishbone-storage-capability-mismatch')
    address = profile.address
    if (address is None or type(address.window_size) is not int
            or address.window_size != 16 or type(address.alignment) is not int
            or address.alignment != 16):
        raise ValueError('wishbone-storage-address-mismatch')
    fields = [r for r in address.registers if r.name == register['name']]
    if len(fields) != 1:
        raise ValueError('wishbone-storage-register-mismatch')
    reg = fields[0]
    if (type(reg.offset) is not int or reg.offset != register['canonical_offset']
            or type(reg.width) is not int or reg.width != register['width']
            or reg.access != 'rw' or reg.side_effect != 'write_resets_uart_state'
            or reg.clears_register is not None
            or (reg.reset_value is not None and
                (type(reg.reset_value) is not int or reg.reset_value != register['reset_value']))
            or (reg.writable_bits is not None and
                (type(reg.writable_bits) is not int or reg.writable_bits != register['write_mask']))):
        raise ValueError('wishbone-storage-register-mismatch')


def _verify_files(base_dir, document):
    root = Path(base_dir).absolute()
    for name, expected in document['source']['files'].items():
        path = root / document['source']['root'] / name
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('wishbone-storage-source-symlink')
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ValueError('wishbone-storage-source-unavailable') from error
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('wishbone-storage-reviewed-source-bytes-changed')


def select_wishbone_storage_source_contract(profile, *, base_dir, selection):
    if (type(selection) is not dict
            or set(selection) != {'contract_id', 'register'}
            or type(selection['contract_id']) is not str
            or type(selection['register']) is not str):
        raise ValueError('wishbone-storage-selection-unsupported')
    document = _registered_document()
    if (selection['contract_id'] != document['contract_id']
            or selection['register'] != document['register']['name']):
        raise ValueError('wishbone-storage-selection-unsupported')
    _verify_profile(profile, document)
    _verify_files(base_dir, document)
    return document


def _require_registered_document(document):
    try:
        serialized = _json(document)
    except (TypeError, ValueError) as error:
        raise ValueError('wishbone-storage-contract-mismatch') from error
    if serialized != _json(_registered_document()):
        raise ValueError('wishbone-storage-contract-mismatch')
    return _registered_document()


def validate_wishbone_storage_source_contract(document, profile, *, base_dir):
    expected = _require_registered_document(document)
    return select_wishbone_storage_source_contract(
        profile, base_dir=base_dir,
        selection={'contract_id': expected['contract_id'],
                   'register': expected['register']['name']})


def wishbone_word_index(byte_offset):
    """Host byte offset -> Wishbone word index for the 16-byte window."""
    if type(byte_offset) is not int or not 0 <= byte_offset < 16:
        raise ValueError('wishbone-storage-offset-out-of-range')
    if byte_offset % 4:
        raise ValueError('wishbone-storage-offset-unaligned')
    return byte_offset >> 2


def wishbone_setup_matches(document, byte_offset):
    expected = _require_registered_document(document)
    return wishbone_word_index(byte_offset) == expected['register']['word_index']
