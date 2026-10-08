"""Restricted reviewed bootstrap/CSR semantics, never generic ISR authority."""
from copy import deepcopy


def uart_controlled_irq_contract():
    return deepcopy(dict(schema_version='controlled_uart_irq_entry_contract.v1',
        profile_id='ibex_rvfi_local', external_cause=11, mtvec_base_mask=0xffffff00,
        mtvec_mode=1, initial_image_writer_kind='INITIAL_IMAGE',
        initial_image_writer_id='initial-image', image_version_sequence=0,
        source=dict(root='third_party/rfuzz/upstream/ibex',
            revision='git:34b0705760ef3dfa00e99637432473d2be8f22f3', sha256={
                'rtl/ibex_if_stage.sv':'8b99f212f06aa942e53e8a768863587ffdc29176f5a486c6e273262311c9f6ae',
                'rtl/ibex_cs_registers.sv':'898d036f141bdf742c0c772a5493b4bccc9636ffd7c57d3cc37011d233954548'}),
        entry_scope='controlled_bootstrap_external_irq', generic_isr_origin='unknown',
        operand_origin='unknown'))
