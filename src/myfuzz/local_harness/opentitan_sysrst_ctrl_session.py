"""Persistent TL-UL and physical-event session for OpenTitan sysrst_ctrl."""
from __future__ import annotations

from .tlul_register_session import GeneratedTlulRegisterSession


class GeneratedOpentitanSysrstCtrlSession(GeneratedTlulRegisterSession):
    """Run true sysrst_ctrl RTL with fixed event setup and observable readback.

    The only mutable physical input in this first profile is the externally
    driven key0 pin. Register state, the AON/core clock schedule and native
    outputs remain owned by the generated runtime and DUT.
    """

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        if (getattr(getattr(artifact, 'plan', None), 'profile', None) is None
                or artifact.plan.profile.component_id != 'opentitan_sysrst_ctrl_local'
                or getattr(artifact, 'runtime_document', {}).get('kind') !=
                'tlul_register_observe'):
            raise ValueError('generated OpenTitan sysrst_ctrl register artifact required')
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
            setup_writes=((0x44, 0x2), (0x48, 0), (0x04, 1)),
            probe_offsets=(0x40, 0xa8, 0x00), **kwargs)
        dynamic = artifact.runtime_document['dynamic_physical_inputs']
        if (len(dynamic) != 1 or dynamic[0]['endpoint_id'] !=
                'opentitan_sysrst_ctrl.pins' or dynamic[0]['role'] != 'key0'
                or dynamic[0]['source_id'] != 'sysrst_key0_environment'
                or dynamic[0]['width'] != 1):
            raise ValueError('sysrst_ctrl requires the declared key0 environment source')
        self._post_irq_captured = False
        self._high_pin_captured = False

    def identity_document(self):
        return {**super().identity_document(),
                'sysrst_ctrl_local_service_schema_version':
                    'generated_opentitan_sysrst_ctrl_service.v1',
                'key0_h2l_setup': {'key_intr_ctl': 2,
                                   'key_intr_debounce_ctl': 0,
                                   'intr_enable': 1},
                'native_outputs_observed': [
                    'intr_event_detected_o', 'rst_req_o', 'wkup_req_o',
                    'cio_key0_out_o', 'cio_ec_rst_l_o',
                ]}

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._post_irq_captured = False
        self._high_pin_captured = False

    def _step_with_inputs(self, inputs, bound_inputs):
        key0_name = 'opentitan_sysrst_ctrl.pins.key0'
        previous_key0 = self._dynamic_values.get(key0_name)
        outputs = super()._step_with_inputs(inputs, bound_inputs)
        current_key0 = self._dynamic_values.get(key0_name)
        if (not self._high_pin_captured and previous_key0 != current_key0
                and current_key0 == 1):
            self._high_pin_captured = True
            pin_value = self.read_register(0x40)
            self.local_transactions.append(dict(offset=0x40, write=False,
                read_value=pin_value, reason='key0_high_pin_readback'))
            outputs['pin_in_value_high'] = pin_value
        elif previous_key0 != current_key0 and current_key0 == 0:
            # Keep the environment-to-DUT pin update visible in the replay
            # evidence. This is a real TL-UL read of PIN_IN_VALUE after the
            # generated SOURCE_TLUL_REG command changed the physical input.
            pin_value = self.read_register(0x40)
            self.local_transactions.append(dict(offset=0x40, write=False,
                read_value=pin_value, reason='key0_low_pin_readback'))
            outputs['pin_in_value_low'] = pin_value
        # Read the sticky status through the DUT's real TL-UL interface only
        # after the native RTL interrupt has actually been observed asserted.
        if outputs.get('intr_event_detected_o') and not self._post_irq_captured:
            self._post_irq_captured = True
            key_status = self.read_register(0xa8)
            intr_state = self.read_register(0x00)
            pin_value = self.read_register(0x40)
            self.local_transactions.extend((
                dict(offset=0xa8, write=False, read_value=key_status,
                     reason='native_irq_readback'),
                dict(offset=0x00, write=False, read_value=intr_state,
                     reason='native_irq_readback'),
                dict(offset=0x40, write=False, read_value=pin_value,
                     reason='native_irq_readback'),
            ))
            outputs.update(key_intr_status=key_status, intr_state=intr_state,
                           pin_in_value=pin_value)
        return outputs

    def reset_local(self):
        result = super().reset_local()
        self._post_irq_captured = False
        self._high_pin_captured = False
        return result
