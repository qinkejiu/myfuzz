"""Pinned CV32E40P native IRQ receipts: real ack/id/entry-PC, no RVFI intr.

The local top assigns only the four official RVFI observation fields
(valid/order/insn/pc_rdata).  It never drives ``rvfi_intr``, ``rvfi_pc_wdata``,
``rvfi_trap``, ``rvfi_mode``, ``mem_*`` or ``halt``, so no retirement field may
mint IRQ source here.  What the core does expose is real: the controller's
combinational IRQ decision, its ``irq_ack_o``/``irq_id_o`` outputs, and the IF
stage exception PC.  Those are sampled before the rising edge that advances the
core, which is the only edge on which they name an acceptance.
"""
import hashlib
import json
from pathlib import Path

# Every authenticated input, relative to the repository root.  The local top,
# both profiles, the passive bench monitors and every RTL file whose hierarchy
# or semantics the probes read are pinned by their real bytes.
_PINS = {
    'configs/cpus/cv32e40p_rvfi_local/cv32e40p_rvfi_local_top.sv':
        '72e023451984470a154b4143cedb7f38248ea36eadc9b5a6cd9408afb6e10a28',
    'configs/cpus/cv32e40p_rvfi_local/component_profile.json':
        'fc070f6779cee320f6b008e5cfc8bbe6f7768290a7fd5268fd10876c046c6806',
    'configs/cpus/cv32e40p/component_profile.json':
        '21d04c8ad75d2e6cc1feff72b22dc1d7656b129cddd70d55bb981973d0db3e45',
    'external_designs/cv32e40p/bhv/cv32e40p_tb_wrapper.sv':
        '591124e7637913dacd62424a33910736cec555ad63c8b6c90fca2808a8f6816b',
    'external_designs/cv32e40p/bhv/cv32e40p_rvfi.sv':
        'dba0bea30f40fafd7361acc86adc3b6e898a0d025f2242cc482741920ef166d6',
    'external_designs/cv32e40p/bhv/pipe_freeze_trace.sv':
        'ebe391cad03230401840a20a9ea9cecccc898bb7f6fd12e1b9475e9a98d9509f',
    'external_designs/cv32e40p/bhv/insn_trace.sv':
        '31b72b252e56b62263cf7ac411402e4925d26307ebb063845170ad3c5a330a39',
    'external_designs/cv32e40p/bhv/include/cv32e40p_rvfi_pkg.sv':
        '55ed3c9fb98b29d986d064c7ac84bc6081d07a348072d30c03af5ce09ca7a675',
    'external_designs/cv32e40p/bhv/include/cv32e40p_tracer_pkg.sv':
        '44f2498df7c028cb07142c9eb875b8499fcc16866d2ff018deb33e1419ad212c',
    'external_designs/cv32e40p/rtl/cv32e40p_core.sv':
        '6a78a0d77d32e6795f63e5149f77b98320ce504c67c44a2e359c9aea70989224',
    'external_designs/cv32e40p/rtl/cv32e40p_cs_registers.sv':
        'e2cec8f3d273748783275c60b1ec89101336608638d7e7783b03dd6b9dbb0345',
    'external_designs/cv32e40p/rtl/cv32e40p_controller.sv':
        '858b172963e17529de0b40a5be6ddfdadfc60bdca967819e4fc558b0ed6d7b87',
    'external_designs/cv32e40p/rtl/cv32e40p_int_controller.sv':
        '24df51d9cb33f5c8760a8cfbc7931aafc94c2ab0523c7df55b2635e7778af16f',
    'external_designs/cv32e40p/rtl/cv32e40p_id_stage.sv':
        '98b246d9ada45a7073d217d5c3bbc86941ee76bb00e7e0edda61d3bbec83728e',
    'external_designs/cv32e40p/rtl/cv32e40p_if_stage.sv':
        'e2d1cc9bc433a093938f2d4e4268c611f9a9bf199101e85114d417ff04597626',
    'external_designs/cv32e40p/rtl/cv32e40p_top.sv':
        '2467f6b3c2745e687edad1a0c88ab5267b4ba8642c91e1fc0f282cf4223e5dc3',
    'external_designs/cv32e40p/rtl/include/cv32e40p_pkg.sv':
        '3fee39d262ef44bff6ee00b591fe08830e5e35cdd1b9e5eb9eb06da6f6525805',
}
_PROFILE = 'configs/cpus/cv32e40p_rvfi_local/component_profile.json'
_BASE_PROFILE = 'configs/cpus/cv32e40p/component_profile.json'
_SOURCE_ROOT = 'external_designs/cv32e40p'
_SOURCE_REVISION = 'git:6033d2b1be3295ec774d17ac4cf226faacfdeb08'
_SOURCE_HASHES = {name.removeprefix(_SOURCE_ROOT + '/'): digest
                  for name, digest in _PINS.items()
                  if name.startswith(_SOURCE_ROOT + '/')}
_RVFI_FIELDS = {'rvfi_valid': 1, 'rvfi_order': 64, 'rvfi_insn': 32, 'rvfi_pc_rdata': 32}
# ``u_component.u_dut`` is cv32e40p_rvfi_local_top, ``u_original`` is the pinned
# bench wrapper, whose ``cv32e40p_top_i`` owns the real core.
CORE = 'u_component.u_dut.u_original.cv32e40p_top_i.core_i'
CONTROLLER = CORE + '.id_stage_i.controller_i'
SOURCE_ID = 11
DECISION_PROBE_WIDTHS = {'irq_masked_pre': 1, 'irq_taken_pre': 1, 'irq_ack_pre': 1,
    'irq_id_pre': 5, 'irq_entry_pc': 32, 'irq_redirect_pre': 1,
    'irq_redirect_cause': 5}
IRQ_PORTS = {'irq_i': dict(direction='input', width=32, line_offset=SOURCE_ID),
             'irq_ack_o': dict(direction='output', width=1),
             'irq_id_o': dict(direction='output', width=5)}
IRQ_AUTHORITY_SCOPE = ('native_pre_edge_external_cause_decision_with_real_ack_id'
    '_entry_pc_and_non_irq_exception_redirect_only')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def cv32e40p_irq_receipt_contract():
    """Strict closed contract; only probes of real RTL appear in it."""
    meix = f'{CORE}.cs_registers_i.mie_q[{SOURCE_ID}]'
    return dict(
        schema_version='cv32e40p_native_irq_receipts.v1',
        profile_id='cv32e40p_rvfi_local',
        input_port='irq_i', input_width=1, input_bit_offset=SOURCE_ID,
        sampling='pre_post_rising', wire_schema_version='local_driver.v1',
        source=dict(root=_SOURCE_ROOT, revision=_SOURCE_REVISION,
                    sha256=dict(_SOURCE_HASHES)),
        decision_probes=dict(
            # The external line is masked when its MIE bit, the global MIE, or
            # the controller's debug mode blocks it.
            irq_masked_pre=f'~{meix} | ~{CORE}.cs_registers_i.mstatus_q.mie | {CONTROLLER}.debug_mode_q',
            # The real controller save/vector decision for this declared line:
            # EXC_PC_IRQ is the interrupt vector and the saved cause is the
            # encoder's real id for irq_i[11].
            irq_taken_pre=f'{CONTROLLER}.pc_set_o & {CONTROLLER}.csr_save_cause_o & '
                          f'({CONTROLLER}.exc_pc_mux_o == cv32e40p_pkg::EXC_PC_IRQ) & '
                          f'({CONTROLLER}.exc_cause_o == 5\'d{SOURCE_ID})'),
        # Additive real observations; ``decision_probes`` stays the exact
        # acceptance pair other contracts also declare.
        decision_probes_all=dict(
            irq_ack_pre=f'{CONTROLLER}.irq_ack_o',
            irq_id_pre=f'{CONTROLLER}.irq_id_o',
            irq_entry_pc=f'{CORE}.if_stage_i.exc_pc',
            # A real PC redirect to the exception vector.  ``csr_save_cause_o``
            # is asserted in the flush cycle that precedes the redirect in this
            # RTL, so conjoining it would make this probe dead; the vector
            # selector alone separates exception entry from IRQ and debug
            # entries.  Branch/jump/MRET leave exc_pc_mux_o at its EXC_PC_IRQ
            # default and therefore never assert this probe.
            irq_redirect_pre=f'{CONTROLLER}.pc_set_o & '
                             f'({CONTROLLER}.exc_pc_mux_o != cv32e40p_pkg::EXC_PC_IRQ) & '
                             f'({CONTROLLER}.exc_pc_mux_o != cv32e40p_pkg::EXC_PC_DBD) & '
                             f'({CONTROLLER}.exc_pc_mux_o != cv32e40p_pkg::EXC_PC_DBE)',
            irq_redirect_cause=f'{CONTROLLER}.exc_cause_o'),
        decision_probe_widths=dict(DECISION_PROBE_WIDTHS),
        irq_ports={name: dict(facts) for name, facts in IRQ_PORTS.items()},
        irq_authority_scope=IRQ_AUTHORITY_SCOPE,
        decision_acceptance=dict(ack_probe='irq_ack_pre', id_probe='irq_id_pre',
            source_id=SOURCE_ID, id_width=5, entry_pc_probe='irq_entry_pc'),
        redirect_probes=dict(taken='irq_redirect_pre', cause='irq_redirect_cause'),
        notification_widths=dict(rvfi_valid=1, irq_ack_o=1, irq_id_o=5),
        notification_semantics='irq_ack_o_and_irq_id_o_are_real_pre_edge_controller_outputs;'
            'rvfi_intr_is_not_driven_so_no_post_edge_notification_exists',
        retirement_authority='pc_insn_order_only',
        retirement_fields=['valid', 'order', 'insn', 'pc_rdata'],
        unobserved_retirement_fields=['intr', 'pc_wdata', 'trap', 'halt', 'mode',
            'mem_addr', 'mem_rdata', 'mem_wdata', 'mem_rmask', 'mem_wmask'],
        retirement_diversion_fields=[],
        retirement_diversion_scope='unobservable',
        retirement_receipt=dict(schema_version='cpu_retire.v2', phase='post',
            rvfi_fields=len(_RVFI_FIELDS), scope='complete_parsed_STEP_CPU_receipt',
            tick_fields=['tick_before', 'tick_after', 'new_ticks', 'local_tick_base']),
        startup_reset_receipt=dict(schema_version='cpu_native_startup.v1',
            source='authenticated_startup_ready', initial_csr_origin='unknown'))


def validate_cv32e40p_irq_receipt_contract(value):
    try:
        matches = _canonical(value) == _canonical(cv32e40p_irq_receipt_contract())
    except (TypeError, ValueError):
        matches = False
    if not matches:
        raise ValueError('cv32e40p native IRQ receipt contract mismatch')


def verify_cv32e40p_irq_source_contract(profile, *, base_dir):
    """Authenticate the pinned closure and the real IRQ port facts."""
    from myfuzz.composition.component_profile import load_component_profile, elaborate_profile
    from .cv32e40p_rvfi_contract import (verify_cv32e40p_rvfi_source_contract, cv32e40p_profile_matches)
    root = Path(base_dir).resolve()
    path = root / _PROFILE
    if (getattr(profile, 'component_id', None) != 'cv32e40p_rvfi_local'
            or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != _PINS[_PROFILE]
            or not cv32e40p_profile_matches(profile, base_dir=root)):
        raise ValueError('cv32e40p-native-IRQ-profile-mismatch')
    for name, digest in _PINS.items():
        source = root / name
        if source.is_symlink() or not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError('cv32e40p-native-IRQ-source-changed:' + name)
    if load_component_profile(root / _BASE_PROFILE).source_document.get('revision') != _SOURCE_REVISION:
        raise ValueError('cv32e40p-native-IRQ-source-revision-changed')
    observation = verify_cv32e40p_rvfi_source_contract(profile, base_dir=root)
    facts = elaborate_profile(profile, base_dir=root, mode='direct')
    ports = {port.name: (port.direction, port.width) for port in facts.ports}
    rvfi = {name: width for name, (direction, width) in ports.items()
            if name.startswith('rvfi_') and direction == 'output'}
    if rvfi != _RVFI_FIELDS:
        raise ValueError('cv32e40p-native-IRQ-observed-fields-changed')
    if ports.get('irq_i') != ('input', 32):
        raise ValueError('cv32e40p-native-IRQ-input-port-changed')
    if ports.get('irq_ack_o') != ('output', 1):
        raise ValueError('cv32e40p-native-IRQ-ack-port-changed')
    if ports.get('irq_id_o') != ('output', 5):
        raise ValueError('cv32e40p-native-IRQ-id-port-changed')
    # Return the pinned RVFI closure document unchanged.  It is the identity
    # hashed into ``cpu.source_verification_sha256`` and stored verbatim as the
    # artifact's ``source_verification``, so adding IRQ keys here would make
    # those two hashes differ.  The IRQ-only facts live in the contract
    # (``irq_ports``/``irq_authority_scope``/``decision_probe_widths``) and in
    # ``IRQ_AUTHORITY_SCOPE`` below, never in this document.
    return observation


def cv32e40p_irq_sideband():
    """Documentary-only passive take counter; it grants no authority.

    The E40 contract has no exact serial token, so no evidence consumes this
    block and the runtime renderer deliberately does not install it.  It only
    reads real RTL signals and never drives the DUT.
    """
    return f'''// Documentary counter only: no IRQ source authority, never drives the DUT.
logic [63:0] irq_take_count_q;
always_ff @(posedge {CORE}.clk_i or negedge {CORE}.rst_ni) begin
  if (!{CORE}.rst_ni) irq_take_count_q <= '0;
  else if (probe_irq_taken_pre && irq_take_count_q != '1)
    irq_take_count_q <= irq_take_count_q + 64'd1;
end'''


def verify_cv32e40p_irq_receipt_artifact(artifact, *, base_dir):
    """Require the real artifact: pinned source, exact exports, verbatim probes."""
    from .runtime_artifact import LocalRuntimeArtifact
    root = Path(base_dir).resolve()
    if type(artifact) is not LocalRuntimeArtifact or artifact.runtime_document.get('kind') != 'obi_cpu':
        raise ValueError('actual-CV32E40P-IRQ-artifact-required')
    if getattr(artifact.plan.profile, 'component_id', None) != 'cv32e40p_rvfi_local':
        raise ValueError('cv32e40p-native-IRQ-profile-mismatch')
    verified = verify_cv32e40p_irq_source_contract(artifact.plan.profile, base_dir=root)
    document = artifact.runtime_document
    if hashlib.sha256(artifact.runtime_sv.encode()).hexdigest() != document.get('runtime_sv_sha256'):
        raise ValueError('cv32e40p-IRQ-runtime-source-mismatch')
    if _canonical(document.get('source_verification')) != _canonical(verified):
        raise ValueError('cv32e40p-IRQ-source-verification-mismatch')
    contract = cv32e40p_irq_receipt_contract()
    exports = document['physical_exports']
    for row in exports:
        name = row.get('physical_port')
        if type(name) is str and name.startswith('rvfi_') and name not in _RVFI_FIELDS:
            raise ValueError('cv32e40p-IRQ-fabricated-retirement-field:' + name)
    if 'assign rvfi_intr' in artifact.runtime_sv or 'assign rvfi_pc_wdata' in artifact.runtime_sv:
        raise ValueError('cv32e40p-IRQ-fabricated-retirement-assign')
    required = {contract['input_port']: ('input', contract['input_width'],
                                         contract['input_bit_offset'],
                                         contract['input_bit_offset'])}
    for name, width in contract['notification_widths'].items():
        required[name] = ('output', width, 0, width - 1)
    for name, width in contract['decision_probe_widths'].items():
        required[name] = ('output', width, 0, width - 1)
    rows = {}
    for name, (direction, width, bit_lo, bit_hi) in required.items():
        selected = [row for row in exports if row['physical_port'] == name]
        if (len(selected) != 1 or selected[0]['direction'] != direction
                or selected[0]['width'] != width or selected[0]['bit_lo'] != bit_lo
                or selected[0]['bit_hi'] != bit_hi):
            raise ValueError('cv32e40p-IRQ-physical-export-mismatch:' + name)
        rows[name] = selected[0]
    probes = {**contract['decision_probes'], **contract['decision_probes_all']}
    for name, expression in probes.items():
        if f'assign probe_{name} = {expression};' not in artifact.runtime_sv:
            raise ValueError('cv32e40p-IRQ-decision-probe-mismatch:' + name)
    return rows[contract['input_port']]['runtime_name']
