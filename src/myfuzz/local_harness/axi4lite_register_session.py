"""Component-neutral persistent AXI4-Lite register and pin-observation session.

This is the AXI4-Lite member of the generic register family.  It performs
ordinary word accesses over the IP's own AXI4-Lite slave port and observes the
IP's own pins; it never synthesizes serial traffic, interrupt results, or
register values.  The beat handshake, tick sampling, input ownership and case
lifecycle are the ones the APB3 member established, because on the generic side
of ``axi4_lite_mmio_target`` the four protocols present the same beat face.
Only what genuinely differs is declared here:

* the driver command names, so an AXI4-Lite command can never be answered by
  another protocol's driver branch;
* the response code is reported as the two bits the slave actually drove
  instead of being collapsed to a boolean.  A non-OKAY code still raises, but
  the message names the measured code so SLVERR and DECERR are distinguishable
  in the failure record.

The renderer also exposes the 19 declared AXI4-Lite roles as passive taps on
the same nets, so the component-neutral protocol-event layer projects these very
transactions without this session telling it what happened.
"""
from __future__ import annotations

from .apb3_register_session import GeneratedApb3RegisterSession

#: AXI4-Lite response codes, exactly as BRESP/RRESP carry them.
RESPONSE_OKAY = 0b00
RESPONSE_EXOKAY = 0b01
RESPONSE_SLAVE_ERROR = 0b10
RESPONSE_DECODE_ERROR = 0b11
RESPONSE_NAMES = {RESPONSE_OKAY: 'OKAY', RESPONSE_EXOKAY: 'EXOKAY',
                  RESPONSE_SLAVE_ERROR: 'SLVERR',
                  RESPONSE_DECODE_ERROR: 'DECERR'}


class GeneratedAxi4LiteRegisterSession(GeneratedApb3RegisterSession):
    """Drive one real AXI4-Lite slave port through the generic beat channel."""

    artifact_kind = 'axi4lite_register_observe'
    access_operation = 'ACCESS_AXIL_REG'
    step_operation = 'STEP_AXIL_REG'
    source_operation = 'SOURCE_AXIL_REG'
    bind_operation = 'BIND_AXIL_REG'
    transport_error_label = 'generic AXI4-Lite'
    error_response_label = 'real AXI4-Lite'

    def _access(self, write, offset, value=0, be=15):
        if (type(offset) is not int or offset % 4 or not 0 <= offset < self._window or
                type(value) is not int or not 0 <= value <= 0xffffffff or
                type(be) is not int or not 0 <= be <= 15):
            raise ValueError('invalid generic AXI4-Lite access')
        result = self._take(self.command(self.access_operation,
                                         (int(write), offset, value, be)))
        if result['error']:
            code = result['error']
            named = RESPONSE_NAMES.get(code, 'unknown')
            raise RuntimeError(
                f'real AXI4-Lite {named} response at offset {offset:#x} '
                f'(BRESP/RRESP={code:#04b})')
        return result['rdata']

    def identity_document(self):
        document = super().identity_document()
        document.pop('apb3_register_service_schema_version', None)
        document['axi4lite_register_service_schema_version'] = (
            'generated_axi4lite_register_observe.v1')
        document['response_code_policy'] = 'report_measured_native_response_code'
        return document
