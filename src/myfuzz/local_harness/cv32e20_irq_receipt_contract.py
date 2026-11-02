"""Pinned CV32E20 external-cause receipts and passive retirement lineage.

RVFI intr alone is not source attribution: CVE2 uses it for exceptions too.
Only a real controller external decision can mint a nonzero serial; every
other trap/debug redirect destroys pending external-source lineage.
"""
import hashlib
from dataclasses import replace
import json
from pathlib import Path

ADAPTER_ID='cv32e20_native_irq_receipts.v1'


def uses_cv32e20_irq_adapter(profile):
    declared=profile.evidence.get('native_irq_adapter')
    if 'native_irq_adapter' in profile.evidence:
        if declared != ADAPTER_ID or 'native_irq_observation' in profile.evidence:
            raise ValueError('unregistered-native-IRQ-CPU-adapter')
        return True
    return profile.component_id == 'cv32e20' and 'native_irq_observation' not in profile.evidence


_PROFILE_SHA256='499b0194ed15e59de753929de66de939b7ab7d253d8567e38d8168aa42f0d0f5'
_SOURCE_HASHES={
 'cve2_controller.sv':'5f5a05d177ed7e500b28c77e4e708fe4e4af73d00fc659c9648a95bed235b865',
 'cve2_core.sv':'0320d1ee39957b44527581f3fb1bba48d7753c5cc5873918645ced9b5312b09b',
 'cve2_cs_registers.sv':'603b8325790ca56f87886bb3d6a163923cab76e2cbdc29db0f08b490614a2fb3',
 'cve2_pkg.sv':'b656d1bae7dd486e7a4a87eb67f9d99a473988212d988f19ce2753c83645c038',
 'cve2_top.sv':'d7bdb559738c0ccbe8f92ee3f194e92d7f9223f1066ed63f3a2bb1850e240b82'}
CORE='u_component.u_dut.u_cve2_core'
_NOTIFICATION_WIDTHS={'rvfi_valid':1,'rvfi_intr':1,'rvfi_ext_mip':32,
    'rvfi_ext_nmi':1,'rvfi_ext_debug_req':1}


def verify_cv32e20_irq_source_contract(profile,*,base_dir):
    from myfuzz.composition.component_profile import load_component_profile
    from .source_lock import verify_local_source_lock
    root=Path(base_dir).resolve();path=root/'configs/cpus/cv32e20/component_profile.json'
    if not uses_cv32e20_irq_adapter(profile):
        raise ValueError('cv32e20-native-IRQ-profile-mismatch')
    evidence=dict(profile.evidence)
    declared=evidence.pop('native_irq_adapter',None)
    if declared is not None:
        evidence.pop('local_source_manifest',None)
        evidence.pop('boot_fetch',None)
    has_timing='local_harness' in evidence
    timing=evidence.pop('local_harness',None)
    if has_timing:
        if (type(timing) is not dict or set(timing) != {
                'reset_assert_ticks','reset_release_ticks','max_wait_cycles'}
                or any(type(timing[key]) is not int or not minimum <= timing[key] <= 1024
                       for key,minimum in (('reset_assert_ticks',1),
                                           ('reset_release_ticks',0),('max_wait_cycles',1)))):
            raise ValueError('cv32e20-native-IRQ-profile-mismatch')
    comparable=replace(profile,evidence=evidence,component_id='cv32e20' if declared else profile.component_id)
    baseline=load_component_profile(path)
    if (path.is_symlink()
            or hashlib.sha256(path.read_bytes()).hexdigest()!=_PROFILE_SHA256
            or baseline!=comparable or baseline.source_document!=profile.source_document):
        raise ValueError('cv32e20-native-IRQ-profile-mismatch')
    for name,digest in _SOURCE_HASHES.items():
        source=root/'third_party/cv32e20_upstream_reference/rtl'/name
        if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
            raise ValueError('cv32e20-native-IRQ-source-mismatch:'+name)
    return verify_local_source_lock(profile,base_dir=root)


def cv32e20_irq_receipt_contract():
    ctrl=CORE+'.id_stage_i.controller_i'
    return dict(schema_version='cv32e20_native_irq_receipts.v1',profile_id='cv32e20',
        input_port='irq_external_i',input_width=1,sampling='pre_post_rising',wire_schema_version='local_driver.v1',
        source=dict(root='third_party/cv32e20_upstream_reference',revision='git:d079e8c8e6a08b330940ae123876ba0612bec18d',sha256={'rtl/'+name:digest for name,digest in _SOURCE_HASHES.items()}),
        decision_probes=dict(
            irq_masked_pre=f"~{CORE}.cs_registers_i.mie_q.irq_external | ~{CORE}.csr_mstatus_mie | {ctrl}.debug_mode_q | {ctrl}.nmi_mode_q",
            irq_taken_pre=f'{ctrl}.pc_set_o & {ctrl}.csr_save_cause_o & ({ctrl}.exc_pc_mux_o == cve2_pkg::EXC_PC_IRQ) & ({ctrl}.exc_cause_o == cve2_pkg::EXC_CAUSE_IRQ_EXTERNAL_M)'),
        notification_widths=dict(_NOTIFICATION_WIDTHS),notification_semantics='actual_declared_CVE2_RVFI_fields_not_source_authority',
        context_semantics='planned_binding_refs_never_source_authority',generic_irq_entry_origin='unknown',
        retirement_receipt=dict(schema_version='cpu_retire.v2',phase='post',rvfi_fields=27,
            scope='complete_parsed_STEP_CPU_receipt',tick_fields=['tick_before','tick_after','new_ticks','local_tick_base']),
        startup_reset_receipt=dict(schema_version='cpu_native_startup.v1',source='authenticated_startup_ready',initial_csr_origin='unknown'),
        serial_observation=dict(schema_version='cpu_irq_serial_observation.v1',width_bits=64,
            ports={'decision':'irq_decision_serial','retirement':'irq_retirement_serial'},
            zero_semantics='no_provable_source_lineage',source_authority='exact_nonzero_token_join_to_native_external_cause_decision'))


def cv32e20_irq_sideband():
    """Mirror the pinned one-stage RVFI trap-PC bookkeeping, never drive RTL."""
    return f'''logic [63:0] irq_sequence_q, irq_pending_q, irq_intr_q, irq_stage_q;
assign probe_irq_decision_serial = probe_irq_taken_pre && irq_sequence_q != '1
    ? irq_sequence_q + 64'd1 : 64'd0;
always_ff @(posedge {CORE}.clk_i or negedge {CORE}.rst_ni) begin
  if (!{CORE}.rst_ni) begin
    irq_sequence_q <= '0; irq_pending_q <= '0; irq_intr_q <= '0; irq_stage_q <= '0;
  end else begin
    if (probe_irq_taken_pre && irq_sequence_q != '1) irq_sequence_q <= irq_sequence_q + 64'd1;
    if ({CORE}.debug_mode || {CORE}.nmi_mode) begin
      irq_pending_q <= '0; irq_intr_q <= '0; irq_stage_q <= '0;
    end else begin
      if ({CORE}.pc_set && ({CORE}.pc_mux_id == cve2_pkg::PC_EXC))
        irq_pending_q <= probe_irq_decision_serial;
      else if ({CORE}.rvfi_id_done) irq_pending_q <= '0;
      irq_intr_q <= {CORE}.instr_first_cycle_id ? irq_pending_q : irq_intr_q;
      if ({CORE}.rvfi_id_done)
        irq_stage_q <= {CORE}.instr_first_cycle_id ? irq_pending_q : irq_intr_q;
    end
  end
end
assign probe_irq_retirement_serial = {CORE}.rvfi_valid && {CORE}.rvfi_intr
    ? irq_stage_q : 64'd0;'''


def verify_cv32e20_irq_receipt_artifact(artifact,*,base_dir):
    from .runtime_artifact import LocalRuntimeArtifact
    if type(artifact) is not LocalRuntimeArtifact or artifact.runtime_document.get('kind')!='obi_cpu':
        raise ValueError('actual-CV32E20-IRQ-artifact-required')
    verified=verify_cv32e20_irq_source_contract(artifact.plan.profile,base_dir=base_dir)
    doc=artifact.runtime_document
    if doc.get('source_verification')!=verified:
        raise ValueError('cv32e20-IRQ-artifact-source-mismatch')
    if hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()!=doc['runtime_sv_sha256']:
        raise ValueError('cv32e20-IRQ-runtime-source-mismatch')
    contract=cv32e20_irq_receipt_contract();exports=doc['physical_exports']
    required={contract['input_port']:('input',1),**{n:('output',w) for n,w in _NOTIFICATION_WIDTHS.items()},
        'irq_masked_pre':('output',1),'irq_taken_pre':('output',1),
        'irq_decision_serial':('output',64),'irq_retirement_serial':('output',64)}
    rows={}
    for name,(direction,width) in required.items():
        selected=[r for r in exports if r['physical_port']==name]
        if (len(selected)!=1 or selected[0]['direction']!=direction or selected[0]['width']!=width
                or selected[0]['bit_lo']!=0 or selected[0]['bit_hi']!=width-1):
            raise ValueError('cv32e20-IRQ-physical-export-mismatch:'+name)
        rows[name]=selected[0]
    for name,expression in contract['decision_probes'].items():
        if f'assign probe_{name} = {expression};' not in artifact.runtime_sv:
            raise ValueError('cv32e20-IRQ-decision-probe-mismatch')
    if cv32e20_irq_sideband() not in artifact.runtime_sv:
        raise ValueError('cv32e20-IRQ-passive-lineage-mismatch')
    return rows[contract['input_port']]['runtime_name']
