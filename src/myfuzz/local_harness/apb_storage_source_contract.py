"""Closed, source-reviewed APB storage descriptions, never live authority.

Exact source bytes select a reviewed contract. This is not arbitrary RTL
inference, a verified generated hierarchy, or a register-version issuer.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile

_ID = 'pulp-apb-timer.ctrl0.source.v1'
_ROOT = 'third_party/soc-pulp-apb-timer'
_REVISION = 'git:03eba2e6965f5363df12621882bc70498c551a73'
_SOURCES = (
    ('src/apb_timer.sv', '22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778'),
    ('src/timer.sv', 'd352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce'),
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


def registered_apb_storage_source_contracts():
    return (_ID,)


def _verify_profile(profile):
    if type(profile) is not ComponentProfile:
        raise ValueError('apb-storage-profile-required')
    src = profile.source
    settings = src.elaboration
    if (src.source_root != _ROOT or src.revision != _REVISION
            or src.top_module != 'apb_timer' or src.files != tuple(n for n, _ in _SOURCES)
            or src.filelist is not None or src.include_roots != ()
            or src.repositories != () or src.filelist_variables != ()
            or settings is None or settings.frontend != 'verilator-json'
            or settings.parameters != (('APB_ADDR_WIDTH', '12'), ('TIMER_CNT', '2'))
            or settings.defines != () or settings.warning_policy != 'recorded-nonfatal'):
        raise ValueError('apb-storage-source-identity-unsupported')
    if (len(profile.clocks) != 1 or profile.clocks[0].port != 'HCLK'
            or len(profile.resets) != 1 or profile.resets[0].port != 'HRESETn'
            or profile.resets[0].polarity != 'active_low'
            or type(profile.resets[0].synchronous) is not bool
            or profile.resets[0].synchronous is not False
            or profile.resets[0].sequence_after != ()):
        raise ValueError('apb-storage-clock-reset-mismatch')
    if any(type(profile.capabilities.get(k)) is not int or profile.capabilities[k] != v
           for k, v in (('address_width', 12), ('data_width', 32))):
        raise ValueError('apb-storage-bus-width-mismatch')
    address = profile.address
    if (address is None or type(address.window_size) is not int or address.window_size != 4096
            or type(address.alignment) is not int or address.alignment != 4096):
        raise ValueError('apb-storage-address-mismatch')
    fields = [r for r in address.registers if r.name == 'TIMER0_CTRL']
    if len(fields) != 1:
        raise ValueError('apb-storage-register-mismatch')
    reg = fields[0]
    if (type(reg.offset) is not int or reg.offset != 4
            or type(reg.width) is not int or reg.width != 32
            or reg.access != 'rw' or reg.side_effect != 'none' or reg.clears_register is not None
            or reg.reset_value is not None and (type(reg.reset_value) is not int or reg.reset_value != 0)
            or reg.writable_bits is not None and (type(reg.writable_bits) is not int or reg.writable_bits != 0xffffffff)):
        raise ValueError('apb-storage-register-mismatch')


def _verify_files(base_dir):
    root = Path(base_dir).absolute()
    for name, expected in _SOURCES:
        path = root / _ROOT / name
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
            or selection['contract_id'] != _ID or selection['register'] != 'TIMER0_CTRL'):
        raise ValueError('apb-storage-selection-unsupported')
    _verify_profile(profile)
    _verify_files(base_dir)
    return _registered_document()


def _require_registered_document(document):
    expected = _registered_document()
    try:
        equal = _json(document) == _json(expected)
    except (TypeError, ValueError) as error:
        raise ValueError('apb-storage-contract-mismatch') from error
    if not equal:
        raise ValueError('apb-storage-contract-mismatch')
    return expected


def validate_apb_storage_source_contract(document, profile, *, base_dir):
    """Recheck exact bytes/profile and strict typed JSON; no authority issuance."""
    _require_registered_document(document)
    return select_apb_storage_source_contract(profile, base_dir=base_dir,
        selection={'contract_id': _ID, 'register': 'TIMER0_CTRL'})


def apb_storage_address_matches(document, address):
    """Raw alias predicate, not a transfer acceptance or live-source check.

    Low bits are ignored by the actual storage decode. Transport alignment is
    separate. This helper does not reread source or admit a live producer.
    """
    _require_registered_document(document)
    if type(address) is not int or not 0 <= address < 4096:
        raise ValueError('apb-storage-address-out-of-range')
    return address & 0x1c == 4
