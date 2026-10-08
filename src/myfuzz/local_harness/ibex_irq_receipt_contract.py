"""Authenticated parsed native external IRQ receipts for pinned Ibex RVFI.

This contract observes actual physical input and pre-edge external cause selection;
it does not authenticate handler entry or instruction operand origin.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

_SOURCE_HASHES = {'rtl/ibex_controller.sv': 'bc3211faf87435b07922e3e61646ef83247ab86c5938d4cd2e108802a4357860',
 'rtl/ibex_core.sv': '88b8bf3907472f1d413380f62234a7fbf53cb1de392a6660e6ef2d684a2416fd',
 'rtl/ibex_cs_registers.sv': '898d036f141bdf742c0c772a5493b4bccc9636ffd7c57d3cc37011d233954548',
 'rtl/ibex_pkg.sv': 'd9bfed30b16dd77981f1850a8daf56fec5ce14043789b4a0a4506c833e9a7d5a'}
_NOTIFICATION_WIDTHS = {'rvfi_valid':1,'rvfi_intr':1,'rvfi_ext_irq_valid':1,
 'rvfi_ext_pre_mip':32,'rvfi_ext_post_mip':32,'rvfi_ext_nmi':1,
 'rvfi_ext_nmi_int':1,'rvfi_ext_debug_req':1,'rvfi_ext_debug_mode':1}
# The passive serial sideband is a separate, additive observation contract. It
# records two physical measurement points; it never widens the receipt contract
# above and carries no source authority of its own.
IBEX_IRQ_SERIAL_OBSERVATION_SCHEMA = 'ibex_irq_serial_observation.v1'
IBEX_IRQ_SERIAL_DECISION_PORT = 'irq_decision_serial'
IBEX_IRQ_SERIAL_RETIREMENT_PORT = 'irq_retirement_serial'
IBEX_IRQ_SERIAL_WIDTH_BITS = 64
IBEX_IRQ_SERIAL_ZERO_SEMANTICS = 'no_provable_source_lineage'
_IBEX_IRQ_SERIAL_SAMPLING = ('pre_post_rising', 'post_rising')
_IBEX_IRQ_SERIAL_PHASES = ('pre', 'post')

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def ibex_irq_serial_observation_contract():
    """Versioned passive serial sideband observation contract."""
    return {'schema_version': IBEX_IRQ_SERIAL_OBSERVATION_SCHEMA,
        'ports': {'decision': IBEX_IRQ_SERIAL_DECISION_PORT,
                  'retirement': IBEX_IRQ_SERIAL_RETIREMENT_PORT},
        'width_bits': IBEX_IRQ_SERIAL_WIDTH_BITS,
        'sampling': {'receipt_events': 'pre_post_rising', 'retirement_events': 'post_rising'},
        'role_fields': ['physical_port', 'phase', 'value', 'status'],
        'status_values': ['observed', 'unobservable'],
        'zero_semantics': IBEX_IRQ_SERIAL_ZERO_SEMANTICS,
        'join_authority': 'exact_nonzero_token_equality_only',
        'source_authority': 'none_without_a_separate_exact_join'}

def validate_ibex_irq_serial_observation_contract(value):
    try:
        matches = _canonical(value) == _canonical(ibex_irq_serial_observation_contract())
    except (TypeError, ValueError):
        matches = False
    if not matches:
        raise ValueError('Ibex IRQ serial observation contract mismatch')

def ibex_irq_serial_observation(*, sampling, decision_value, retirement_value,
                                decision_phase, retirement_phase):
    """Build one versioned serial observation; None means physically unobservable."""
    contract = ibex_irq_serial_observation_contract()
    if type(sampling) is not str or sampling not in _IBEX_IRQ_SERIAL_SAMPLING:
        raise ValueError('invalid IRQ serial observation sampling')
    roles = {}
    for name, phase, value in (('decision', decision_phase, decision_value),
                               ('retirement', retirement_phase, retirement_value)):
        if type(phase) is not str or phase not in _IBEX_IRQ_SERIAL_PHASES:
            raise ValueError('invalid IRQ serial observation phase')
        if value is None:
            roles[name] = {'physical_port': contract['ports'][name], 'phase': phase,
                           'value': None, 'status': 'unobservable'}
            continue
        if type(value) is not int or not 0 <= value < 1 << contract['width_bits']:
            raise ValueError('invalid IRQ serial observation value')
        roles[name] = {'physical_port': contract['ports'][name], 'phase': phase,
                       'value': value, 'status': 'observed'}
    return {'schema_version': contract['schema_version'], 'sampling': sampling,
            'width_bits': contract['width_bits'],
            'zero_semantics': contract['zero_semantics'], **roles}

def ibex_irq_receipt_contract():
    core='u_component.u_dut.u_ibex.u_ibex_core'
    controller=core+'.id_stage_i.controller_i'
    return {'schema_version':'ibex_native_irq_receipts.v2',
        'profile_id':'ibex_rvfi_local','input_port':'irq_external_i','input_width':1,
        'sampling':'pre_post_rising','wire_schema_version':'local_driver.v1',
        'source':{'root':'third_party/rfuzz/upstream/ibex',
                  'revision':'git:34b0705760ef3dfa00e99637432473d2be8f22f3',
                  'sha256':dict(_SOURCE_HASHES)},
        'decision_probes':{
         'irq_masked_pre':f"~{core}.cs_registers_i.mie_q.irq_external | (({core}.cs_registers_i.priv_lvl_q == 2'b11) & ~{core}.csr_mstatus_mie)",
         'irq_taken_pre':f'{controller}.pc_set_o & {controller}.csr_save_cause_o & ({controller}.exc_pc_mux_o == ibex_pkg::EXC_PC_IRQ) & ({controller}.exc_cause_o == ibex_pkg::ExcCauseIrqExternalM)'},
        'notification_widths':dict(_NOTIFICATION_WIDTHS),
        'notification_semantics':'actual_post_extension_even_without_retirement',
        'context_semantics':'planned_binding_refs_never_source_authority',
        'generic_irq_entry_origin':'unknown',
        'retirement_receipt':{'schema_version':'cpu_retire.v2','phase':'post','rvfi_fields':44,
            'scope':'complete_parsed_STEP_CPU_receipt',
            'tick_fields':['tick_before','tick_after','new_ticks','local_tick_base']},
        'startup_reset_receipt':{'schema_version':'cpu_native_startup.v1',
            'source':'authenticated_startup_ready','initial_csr_origin':'unknown'}}

def validate_ibex_irq_receipt_contract(value):
    try:
        matches = _canonical(value) == _canonical(ibex_irq_receipt_contract())
    except (TypeError, ValueError):
        matches = False
    if not matches:
        raise ValueError('Ibex native IRQ receipt contract mismatch')

def verify_ibex_irq_receipt_artifact(artifact, *, base_dir: Path):
    from .ibex_rvfi_contract import verify_ibex_rvfi_source_contract
    if artifact.plan.profile.component_id!='ibex_rvfi_local' or artifact.runtime_document.get('kind')!='obi_cpu':
        raise ValueError('native IRQ receipts require authenticated Ibex RVFI')
    document=artifact.runtime_document
    verified=verify_ibex_rvfi_source_contract(artifact.plan.profile,base_dir=base_dir)
    if _canonical(document['source_verification'])!=_canonical(verified):
        raise ValueError('native IRQ source verification mismatch')
    if hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()!=document['runtime_sv_sha256']:
        raise ValueError('native IRQ runtime source mismatch')
    for name,digest in _SOURCE_HASHES.items():
        if hashlib.sha256((Path(base_dir)/'third_party/rfuzz/upstream/ibex'/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('native IRQ pinned source changed:'+name)
    exports=document['physical_exports']
    irq=[row for row in exports if row['physical_port']=='irq_external_i']
    if (len(irq)!=1 or irq[0]['direction']!='input' or type(irq[0]['width']) is not int
            or irq[0]['width']!=1 or type(irq[0]['bit_lo']) is not int or irq[0]['bit_lo']!=0
            or type(irq[0]['bit_hi']) is not int or irq[0]['bit_hi']!=0):
        raise ValueError('native IRQ actual input export mismatch')
    for name,expression in ibex_irq_receipt_contract()['decision_probes'].items():
        expected=f'assign probe_{name} = {expression};'
        if expected not in artifact.runtime_sv:
            raise ValueError('native IRQ actual decision expression mismatch')
        selected=[row for row in exports if row['runtime_name']=='probe_'+name]
        if len(selected)!=1 or selected[0]['direction']!='output' or type(selected[0]['width']) is not int or selected[0]['width']!=1:
            raise ValueError('native IRQ actual decision export mismatch')
    for name,width in _NOTIFICATION_WIDTHS.items():
        selected=[row for row in exports if row['physical_port']==name]
        if len(selected)!=1 or selected[0]['direction']!='output' or type(selected[0]['width']) is not int or selected[0]['width']!=width:
            raise ValueError('native IRQ notification export mismatch:'+name)
    return irq[0]['runtime_name']
