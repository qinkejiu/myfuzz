"""Closed, source-reviewed APB storage descriptions, never live authority.

Exact source bytes select a reviewed contract. This is not arbitrary RTL
inference, a verified generated hierarchy, or a register-version issuer.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, EndpointSpec, ProfileField

_ID = 'pulp-apb-timer.ctrl0.source.v1'
_ROOT = 'third_party/soc-pulp-apb-timer'
_REVISION = 'git:03eba2e6965f5363df12621882bc70498c551a73'
_SOURCES = (
    ('src/apb_timer.sv', '22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778'),
    ('src/timer.sv', 'd352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce'),
)
_SPI_ID = 'pulp-apb-spi.spicmd.source.v1'
_SPI_SOURCES = (
    ('soc-pulp-apb-spi/apb_spi_master.sv', 'dfc82b0f3c91ba44d986288e1884b1eede0aad6ed8c5b09179a629344d547d0e'),
    ('soc-pulp-apb-spi/spi_master_apb_if.sv', 'a9a32da6cc07768cab293c48989599e36b2000bb572191667960aa1423fc790a'),
    ('soc-pulp-axi-spi/spi_master_clkgen.sv', 'dbfc81a8afe1c05a4372cf7e46f1217f6b57d56c8927bf25ee5f427761b15332'),
    ('soc-pulp-axi-spi/spi_master_controller.sv', '0ba0d90e99949939b3815ed2e69a9f95b980114ec554baca14083ab54496db76'),
    ('soc-pulp-axi-spi/spi_master_fifo.sv', '226f53f2e78a82eb9859149a505c287daa8cfd54f55c51b6c1cfa2cd90a38555'),
    ('soc-pulp-axi-spi/spi_master_rx.sv', '1290e4beaa7d4b588da9cf84da47b39923010bcfdb355641509ee90295d8ca5f'),
    ('soc-pulp-axi-spi/spi_master_tx.sv', 'ee9a7d305bc7bb574ece02dbd6dc8a3f0403729d336bd7431689da47a08558f6'),
)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _registered_document():
    # Produce fresh containers each time. These facts are registered in code;
    # neither a caller expression nor an evidence_ref can extend this registry.
    doc = dict(
        schema_version='apb_storage_source_contract.v1', contract_id=_ID,
        scope='source_reviewed_contract', authority=False, source_authority=False,
        native_verified=False, hierarchy_verified=False, reset_authority=False,
        version_authority=False,
        source=dict(root=_ROOT, revision=_REVISION, top_module='apb_timer',
            files=dict(_SOURCES), include_roots=[], defines={},
            identity_basis='declared_pinned_revision_and_exact_reviewed_bytes_not_new_git_or_elaboration_verification'),
        parameters=dict(APB_ADDR_WIDTH=12, TIMER_CNT=2),
        register=dict(name='TIMER0_CTRL', canonical_offset=4, width=32,
            reset_value=0, write_mask=0xffffffff, read_mask=0xffffffff),
        clock=dict(port='HCLK', edge='posedge'),
        reset=dict(port='HRESETn', polarity='active_low', synchronous=False,
            event='negedge HRESETn or asserted at posedge HCLK'),
        decode=dict(address_width=12, mask=0x1c, value=4,
            expression="PADDR[4:2] == 3'b001",
            top_select='slave_address_int = PADDR[4]',
            child_select='2-bit register_adr truncates PADDR[4:2] to PADDR[3:2]; REG_TIMER_CTRL=1',
            ignored_address_bits=[0, 1, 5, 6, 7, 8, 9, 10, 11],
            alias_period_bytes=32, raw_address_alias_count=512,
            aligned_word_alias_count=128, host_alignment_bytes=4,
            host_alignment_scope='separate_transport_rule_not_raw_storage_decode'),
        storage_expression=dict(
            expression='u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1]',
            status='prospective_not_codegen_or_native_verified',
            relative_source_storage='timer.regs_q[REG_TIMER_CTRL]',
            required_followup='verify_actual_elaborated_hierarchy_and_read_only_pre_post_probe_wiring'),
        writers=dict(complete_for_registered_source=True,
            scope='selected_CTRL_storage_only_not_all_timer_state',
            hold='regs_n = regs_q; no autonomous assignment to CTRL',
            reset="if !HRESETn: regs_q <= bank_of_32bit_zeroes",
            bus_write='if PSEL && PENABLE && PWRITE && PADDR[4:2]==1: next_CTRL = PWDATA',
            commit='at posedge HCLK when HRESETn: regs_q <= regs_n',
            read='selected PSEL && PENABLE && !PWRITE: PRDATA = regs_q[REG_TIMER_CTRL]',
            priority=['asynchronous_asserted_reset', 'selected_full_word_overwrite', 'hold'],
            autonomous_ctrl_writers=[],
            all_alias_writes='every raw decode match writes the same storage, including ignored low/high bits',
            other_state='COUNT changes autonomously; CMP write resets COUNT; CTRL bits affect count/prescaler behavior',
            ready_error='PREADY=1, PSLVERR=0; no error generation claim'),
        source_review=[
            dict(file='src/apb_timer.sv', lines=[[12, 17], [34, 42], [49, 59], [64, 85]],
                fact='two timers, bit4 selection, forwarded APB and output mux'),
            dict(file='src/timer.sv', lines=[[12, 18], [39, 48], [67, 105], [108, 140]],
                fact='truncated decode, complete combinational writers/read/reset/sequential commit')],
        not_claimed=['arbitrary_RTL_inference', 'native_hierarchy', 'generated_probe',
            'build_process_eligibility', 'reset_observation', 'live_register_version',
            'serialized_authority', 'complete_F4', 'P7'])
    doc['digest'] = hashlib.sha256(_json(doc).encode()).hexdigest()
    return doc


def _spi_registered_document():
    # spi_cmd has one sequential writer: asynchronous reset or a selected
    # full-word APB overwrite. The controller consumes this output, and starts
    # transfers only from the independent STATUS command strobes.
    doc = dict(
        schema_version='apb_storage_source_contract.v1', contract_id=_SPI_ID,
        scope='source_reviewed_contract', authority=False, source_authority=False,
        native_verified=False, hierarchy_verified=False, reset_authority=False,
        version_authority=False,
        source=dict(root='third_party',
            revision='sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230',
            top_module='apb_spi_master', files=dict(_SPI_SOURCES), include_roots=[], defines={},
            identity_basis='declared_pinned_revision_and_exact_reviewed_bytes_not_new_git_or_elaboration_verification'),
        parameters=dict(APB_ADDR_WIDTH=12, BUFFER_DEPTH=10),
        register=dict(name='SPICMD', canonical_offset=8, width=32,
            reset_value=0, write_mask=0xffffffff, read_mask=0xffffffff),
        clock=dict(port='HCLK', edge='posedge'),
        reset=dict(port='HRESETn', polarity='active_low', synchronous=False,
            event='negedge HRESETn or asserted at posedge HCLK'),
        decode=dict(address_width=12, mask=0x3c, value=8,
            expression="PADDR[5:2] == 4'b0010",
            top_select='PADDR is forwarded unchanged to u_axiregs',
            child_select='write_address = PADDR[5:2]; read_address = PADDR[5:2]; REG_SPICMD=2',
            ignored_address_bits=[0, 1, 6, 7, 8, 9, 10, 11],
            alias_period_bytes=64, raw_address_alias_count=256,
            aligned_word_alias_count=64, host_alignment_bytes=4,
            host_alignment_scope='separate_transport_rule_not_raw_storage_decode'),
        storage_expression=dict(
            expression='u_component.u_dut.u_axiregs.spi_cmd',
            status='prospective_not_codegen_or_native_verified',
            relative_source_storage='spi_master_apb_if.spi_cmd',
            required_followup='verify_actual_elaborated_hierarchy_and_read_only_pre_post_probe_wiring'),
        writers=dict(complete_for_registered_source=True,
            scope='selected_SPICMD_storage_only_not_all_spi_state',
            hold='spi_cmd retains its value outside reset and selected SPICMD writes',
            reset="if HRESETn == 1'b0: spi_cmd <= '0",
            bus_write='if PSEL && PENABLE && PWRITE && PADDR[5:2]==2: spi_cmd <= PWDATA',
            commit='at posedge HCLK when HRESETn: selected full-word overwrite or hold',
            read='combinational read_address==REG_SPICMD: PRDATA = spi_cmd; not gated by PSEL/PENABLE/PWRITE',
            priority=['asynchronous_asserted_reset', 'selected_full_word_overwrite', 'hold'],
            autonomous_ctrl_writers=[],
            all_alias_writes='every raw decode match writes the same storage, including ignored low/high bits',
            other_state='STATUS writes strobe transfer commands; SPICMD writes do not start serial activity',
            ready_error='PREADY=1, PSLVERR=0; no error generation claim'),
        source_review=[
            dict(file='soc-pulp-apb-spi/apb_spi_master.sv',
                lines=[[14, 29], [61, 65], [242, 275], [335, 355]],
                fact='full APB forwarding to u_axiregs; spi_cmd is consumed by controller separately from STATUS command strobes'),
            dict(file='soc-pulp-apb-spi/spi_master_apb_if.sv',
                lines=[[13, 16], [31, 48], [73, 80], [84, 110], [119, 141], [170, 191]],
                fact='complete spi_cmd writer/reset/hold; full-word overwrite; raw four-bit decode; combinational read mux')],
        not_claimed=['arbitrary_RTL_inference', 'native_hierarchy', 'generated_probe',
            'build_process_eligibility', 'reset_observation', 'live_register_version',
            'serialized_authority', 'complete_F4', 'P7', 'STATUS_transfer_strobes',
            'SPI_serial_pins', 'TX_RX_FIFOs', 'interrupts', 'other_registers'])
    doc['digest'] = hashlib.sha256(_json(doc).encode()).hexdigest()
    return doc


def registered_apb_storage_source_contracts():
    return (_ID, _SPI_ID)


def _verify_profile(profile, document):
    if type(profile) is not ComponentProfile:
        raise ValueError('apb-storage-profile-required')
    src = profile.source
    settings = src.elaboration
    source = document['source']
    register = document['register']
    if (src.source_root != source['root'] or src.revision != source['revision']
            or src.top_module != source['top_module'] or src.files != tuple(source['files'])
            or src.filelist is not None or src.include_roots != ()
            or src.repositories != () or src.filelist_variables != ()
            or settings is None or settings.frontend != 'verilator-json'
            or settings.parameters != tuple((k, str(v)) for k, v in sorted(document['parameters'].items()))
            or settings.defines != () or settings.warning_policy != 'recorded-nonfatal'):
        raise ValueError('apb-storage-source-identity-unsupported')
    if (len(profile.clocks) != 1 or profile.clocks[0].port != 'HCLK'
            or len(profile.resets) != 1 or profile.resets[0].port != 'HRESETn'
            or profile.resets[0].polarity != 'active_low'
            or type(profile.resets[0].synchronous) is not bool
            or profile.resets[0].synchronous is not False
            or profile.resets[0].sequence_after != ()):
        raise ValueError('apb-storage-clock-reset-mismatch')
    if document['contract_id'] == _SPI_ID:
        endpoints = [e for e in profile.endpoints if e.protocol is not None or e.function == 'mmio_slave']
        roles = ('paddr', 'psel', 'penable', 'pwrite', 'pwdata', 'pready', 'prdata', 'pslverr')
        if (len(endpoints) != 1 or endpoints[0] != EndpointSpec(
                endpoint_id=endpoints[0].endpoint_id, function='mmio_slave', protocol=('apb', '3'),
                fields=tuple(ProfileField(role=r, aliases=(r.upper(),)) for r in roles))):
            raise ValueError('apb-storage-endpoint-mismatch')
    if any(type(profile.capabilities.get(k)) is not int or profile.capabilities[k] != v
           for k, v in (('address_width', 12), ('data_width', 32))):
        raise ValueError('apb-storage-bus-width-mismatch')
    address = profile.address
    if (address is None or type(address.window_size) is not int or address.window_size != 4096
            or type(address.alignment) is not int or address.alignment != 4096):
        raise ValueError('apb-storage-address-mismatch')
    fields = [r for r in address.registers if r.name == register['name']]
    if len(fields) != 1:
        raise ValueError('apb-storage-register-mismatch')
    reg = fields[0]
    if (type(reg.offset) is not int or reg.offset != register['canonical_offset']
            or type(reg.width) is not int or reg.width != register['width']
            or reg.access != 'rw' or reg.side_effect != 'none' or reg.clears_register is not None
            or reg.reset_value is not None and (type(reg.reset_value) is not int or reg.reset_value != register['reset_value'])
            or reg.writable_bits is not None and (type(reg.writable_bits) is not int or reg.writable_bits != register['write_mask'])):
        raise ValueError('apb-storage-register-mismatch')


def _verify_files(base_dir, document):
    root = Path(base_dir).absolute()
    for name, expected in document['source']['files'].items():
        path = root / document['source']['root'] / name
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('apb-storage-source-symlink')
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ValueError('apb-storage-source-unavailable') from error
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('apb-storage-reviewed-source-bytes-changed')


def select_apb_storage_source_contract(profile, *, base_dir, selection):
    """Reread source and return a documentary descriptor, never a token."""
    if (type(selection) is not dict or set(selection) != {'contract_id', 'register'}
            or type(selection['contract_id']) is not str or type(selection['register']) is not str):
        raise ValueError('apb-storage-selection-unsupported')
    for factory in (_registered_document, _spi_registered_document):
        document = factory()
        if (selection['contract_id'] == document['contract_id']
                and selection['register'] == document['register']['name']):
            _verify_profile(profile, document)
            _verify_files(base_dir, document)
            return document
    raise ValueError('apb-storage-selection-unsupported')


def _require_registered_document(document):
    try:
        serialized = _json(document)
    except (TypeError, ValueError) as error:
        raise ValueError('apb-storage-contract-mismatch') from error
    for factory in (_registered_document, _spi_registered_document):
        expected = factory()
        if serialized == _json(expected):
            return expected
    raise ValueError('apb-storage-contract-mismatch')


def validate_apb_storage_source_contract(document, profile, *, base_dir):
    """Recheck exact bytes/profile and strict typed JSON; no authority issuance."""
    expected = _require_registered_document(document)
    return select_apb_storage_source_contract(profile, base_dir=base_dir,
        selection={'contract_id': expected['contract_id'], 'register': expected['register']['name']})


def apb_storage_address_matches(document, address):
    """Raw alias predicate, not a transfer acceptance or live-source check.

    Low bits are ignored by the actual storage decode. Transport alignment is
    separate. This helper does not reread source or admit a live producer.
    """
    expected = _require_registered_document(document)
    decode = expected['decode']
    if type(address) is not int or not 0 <= address < 1 << decode['address_width']:
        raise ValueError('apb-storage-address-out-of-range')
    return address & decode['mask'] == decode['value']
