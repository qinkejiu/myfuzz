"""AXI4-Lite MMIO target facts for the protocol-independent CPU executor.

The target IP's own AXI4-Lite slave port is driven through the generic beat
channel (``axi4_lite_mmio_bridge.sv``); the nineteen declared roles are also
exposed as passive protocol taps, and this module joins the routed CPU MMIO
deliveries to those real pre-edge samples.

What the observation can and cannot claim
-----------------------------------------
* A write is accepted on the edge that completes each of AW and W; AXI4-Lite
  handshakes them independently, so neither order is assumed.  The response
  join is the B handshake, which must follow both.
* A read is the AR handshake followed by the R handshake.
* ``BRESP``/``RRESP`` are physical pins of this IP.  A non-OKAY code is
  reported as an error, never collapsed into success.
* Nothing here proves internal register storage, a version, or that a case is
  independent of an earlier case: those facts stay ``unknown``.
"""
from dataclasses import asdict

from myfuzz.local_harness.axi4lite_register_session import GeneratedAxi4LiteRegisterSession
from myfuzz.runtime.adapters.apb3_mmio import RegisterBank, KIND
from myfuzz.runtime.contracts import canonical_json_bytes
from myfuzz.scenario.ip_protocol_checker import _REQUIRED_SIGNALS as _CHECKER_SIGNALS

#: The only declared AXI4-Lite target template this adapter admits.
TEMPLATE = ('target.axi4-lite', '1', 'single-outstanding-error-codes')

#: The passive trace of the driven slave port must carry exactly these roles.
_REQUIRED_SIGNALS = tuple(_CHECKER_SIGNALS['axi4-lite'])

#: Roles whose width is fixed by the protocol, not by the profile.
_FIXED_WIDTHS = {'awprot': 3, 'arprot': 3, 'wdata': 32, 'wstrb': 4,
                 'rdata': 32, 'bresp': 2, 'rresp': 2}
_BOOLEAN_ROLES = frozenset(role for role in _REQUIRED_SIGNALS
                           if role not in _FIXED_WIDTHS
                           and role not in ('awaddr', 'araddr'))

#: AXI4-Lite response codes, exactly as BRESP/RRESP carry them.
_OKAY = 0b00
_RESPONSE_NAMES = {0b00: 'OKAY', 0b01: 'EXOKAY', 0b10: 'SLVERR', 0b11: 'DECERR'}


def _profile_facts(artifact, endpoint_id):
    doc = artifact.runtime_document
    profile = artifact.plan.profile
    endpoints = [e for e in artifact.plan.binding.endpoints
                 if e.endpoint_id == endpoint_id
                 and e.protocol == ('axi4-lite', '1')
                 and e.function == 'mmio_slave']
    if len(endpoints) != 1:
        raise ValueError('AXI4-Lite-MMIO-endpoint-required')
    trace = doc.get('base_protocol_trace', {})
    signals = trace.get('signals', {})
    widths = trace.get('signal_widths', {})
    c = profile.capabilities
    address_width = c.get('address_width')
    if (doc.get('kind') != 'axi4lite_register_observe'
            or doc.get('storage_observation') is not None
            or doc.get('dynamic_physical_inputs')
            or doc.get('bound_physical_inputs')
            or trace.get('protocol') != 'axi4-lite'
            or trace.get('endpoint_id') != endpoint_id
            or not set(_REQUIRED_SIGNALS) <= set(signals)
            or set(signals) != set(widths)
            or type(address_width) is not int
            or not 1 <= address_width <= 12
            or c.get('data_width') != 32 or c.get('byte_enable') is not True
            or c.get('partial_write') is not True or c.get('has_error') is not True
            or c.get('bursts') is not False or c.get('ids') is not False
            or c.get('max_outstanding') != 1
            or any(type(widths.get(role)) is not int or widths[role] < 1
                   for role in signals)
            or widths.get('awaddr') != address_width
            or widths.get('araddr') != address_width
            or any(widths.get(role) != width for role, width in _FIXED_WIDTHS.items())
            or any(widths.get(role) != 1 for role in _BOOLEAN_ROLES)):
        raise ValueError('native-AXI4-Lite-trace-required')
    if profile.address is None or not profile.address.registers:
        raise ValueError('declared-MMIO-register-map-required')
    window = profile.address.window_size
    if (type(window) is not int or not 4 <= window <= 4096 or window % 4
            or window > 4 * (1 << address_width)):
        raise ValueError('AXI4-Lite-MMIO-window-unsupported')
    registers = []
    for register in profile.address.registers:
        if (type(register.width) is not int or register.width != 32
                or type(register.offset) is not int or register.offset % 4
                or not 0 <= register.offset < window
                or register.offset + 4 > window
                or register.access not in ('ro', 'rw', 'wo')):
            raise ValueError('AXI4-Lite-MMIO-register-shape-required')
        registers.append(asdict(register))
    return doc, profile, trace, window, registers


def _declared_template(request, access):
    """The wiring contract's admitted template identity for this target end."""
    if request is None or not hasattr(request, 'wiring'):
        raise ValueError('AXI4-Lite-MMIO-wiring-required')
    document = getattr(request.wiring, 'document', None)
    if not isinstance(document, dict):
        raise ValueError('AXI4-Lite-MMIO-wiring-required')
    windows = [row for row in document.get('windows', ())
               if row.get('target_instance') == access['target_component']
               and row.get('endpoint_id') in (None, access['target_endpoint'])]
    if len(windows) != 1:
        raise ValueError('AXI4-Lite-MMIO-one-declared-window-required')
    row = windows[0]
    if (row.get('template'), '1', row.get('variant_id')) != TEMPLATE:
        raise ValueError('AXI4-Lite-MMIO-template-mismatch')
    return row


def _access_register(registers, access):
    """The access names one declared 32-bit register, if it names one at all."""
    name = access.get('register')
    offset = access.get('register_offset')
    if name is None and offset is None:
        return None
    if type(name) is not str or type(offset) is not int:
        raise ValueError('AXI4-Lite-MMIO-access-register-required')
    matches = [row for row in registers
               if row['name'] == name and row['offset'] == offset]
    if len(matches) != 1 or matches[0]['width'] != 32:
        raise ValueError('AXI4-Lite-MMIO-access-register-mismatch')
    return matches[0]


def axi4lite_mmio_bank_facts(artifact, *, endpoint_id, access=None):
    """Derive a register-bank description from one already-admitted artifact."""
    _doc, profile, _trace, window, registers = _profile_facts(artifact, endpoint_id)
    _access_register(registers, access or {})
    return RegisterBank(canonical_json_bytes(dict(
        schema_version='mmio_register_bank.v1', kind=KIND,
        endpoint_id=endpoint_id, protocol=['axi4-lite', '1'],
        template=list(TEMPLATE), window_size=window,
        alignment=profile.address.alignment, registers=registers,
        declaration_scope='configured_register_map_not_internal_RTL_storage_proof',
        internal_storage_version='unknown', cross_case_origin='unknown',
        reward_eligible=False)))


def target_adapter(artifact, access, request):
    """Select the real AXI4-Lite target session, bank facts and observer."""
    if not isinstance(access, dict):
        raise ValueError('AXI4-Lite-MMIO-access-required')
    endpoint_id = access.get('target_endpoint')
    if type(endpoint_id) is not str or not endpoint_id:
        raise ValueError('AXI4-Lite-MMIO-endpoint-required')
    if access.get('target_component') != artifact.plan.request.instance_id:
        raise ValueError('AXI4-Lite-MMIO-target-instance-mismatch')
    _declared_template(request, access)
    bank = axi4lite_mmio_bank_facts(artifact, endpoint_id=endpoint_id, access=access)
    return ('axi4-lite', GeneratedAxi4LiteRegisterSession, bank,
            observe_axi4lite_mmio_bus)


def _backend(event):
    outputs = event.get('outputs')
    backend = outputs.get('backend') if isinstance(outputs, dict) else None
    if not isinstance(backend, dict):
        raise ValueError('native-AXI4-Lite-sample-backend-required')
    return backend


def _pin(signals, backend, role):
    value = backend.get(signals[role])
    if type(value) is not int:
        raise ValueError('native-AXI4-Lite-sample-signal-required:' + role)
    return value


def _response_error(name, role, code):
    raise ValueError('native-AXI4-Lite-' + name + '-' + role + ':'
                     + _RESPONSE_NAMES.get(code, 'unknown'))


def observe_axi4lite_mmio_bus(declaration, receipt, *, target_artifact, flow):
    """Join routed CPU MMIO to sampled AXI4-Lite request/response and RAM.

    The samples joined are the target's own pre-edge observations of the nets
    the bridge drives.  ``producer_event_id`` is the target step that executed
    this delivery, so a sample from another transaction can never be borrowed.
    """
    if flow not in ('F2', 'F4'):
        raise ValueError('AXI4-Lite-MMIO-flow-unsupported')
    document = target_artifact.runtime_document
    trace = document.get('base_protocol_trace', {})
    if document.get('kind') != 'axi4lite_register_observe' or trace.get('protocol') != 'axi4-lite':
        raise ValueError('native-AXI4-Lite-trace-required')
    signals = trace.get('signals', {})
    if not set(_REQUIRED_SIGNALS) <= set(signals):
        raise ValueError('native-AXI4-Lite-trace-required')
    access = declaration['candidate']['access']
    events = receipt.events
    deliveries = [e for e in events if e.get('kind') == 'mmio_delivery'
                  and e.get('component') == access['source_component']
                  and e.get('device_id') == access['device_id']
                  and e.get('address') == access['address']]
    writes = [e for e in deliveries if e.get('write') is True]
    reads = [e for e in deliveries if e.get('write') is False]
    if len(reads) != 1 or len(writes) != (1 if flow == 'F4' else 0):
        raise ValueError('MMIO-transfer-count')
    if writes and (writes[0].get('write_value') != declaration['candidate']['value']
                   or writes[0]['event_id'] >= reads[0]['event_id']):
        raise ValueError('MMIO-native-write-value-or-order')
    if writes and writes[0].get('byte_enable') != 15:
        raise ValueError('MMIO-native-write-byte-enable')
    joined = []
    for delivery in writes + reads:
        accepted = [e for e in events if e.get('kind') == 'mmio_acceptance'
                    and e.get('source_transaction') == delivery['source_transaction']
                    and e.get('address') == delivery['address']
                    and e.get('write') == delivery['write']
                    and e['event_id'] < delivery['event_id']]
        samples = [e for e in events if e.get('kind') == 'local_tick_sample'
                   and e.get('component') == access['target_component']
                   and e.get('phase') == 'pre'
                   and e.get('producer_event_id') == delivery.get('producer_event_id')]
        if len(accepted) != 1:
            raise ValueError('MMIO-native-AXI4-Lite-acceptance')
        if not samples:
            raise ValueError('MMIO-native-AXI4-Lite-sample-missing')
        offset = access['register_offset']
        if delivery['write']:
            aw = [e for e in samples
                  if _pin(signals, _backend(e), 'awvalid') == 1
                  and _pin(signals, _backend(e), 'awready') == 1]
            w = [e for e in samples
                 if _pin(signals, _backend(e), 'wvalid') == 1
                 and _pin(signals, _backend(e), 'wready') == 1]
            if len(aw) != 1 or len(w) != 1:
                raise ValueError('MMIO-native-AXI4-Lite-request')
            aw_event, w_event = aw[0], w[0]
            if _pin(signals, _backend(aw_event), 'awaddr') != offset:
                raise ValueError('MMIO-native-AXI4-Lite-aw-address')
            if (_pin(signals, _backend(w_event), 'wdata') != delivery['write_value']
                    or _pin(signals, _backend(w_event), 'wstrb') != 15):
                raise ValueError('MMIO-native-AXI4-Lite-write-data')
            accepted_event = max(aw_event['event_id'], w_event['event_id'])
            completion = [e for e in samples
                          if e['event_id'] > accepted_event
                          and _pin(signals, _backend(e), 'bvalid') == 1
                          and _pin(signals, _backend(e), 'bready') == 1]
            if len(completion) != 1:
                raise ValueError('MMIO-native-AXI4-Lite-completion')
            code = _pin(signals, _backend(completion[0]), 'bresp')
            if code != _OKAY:
                _response_error('write', 'bresp', code)
            row = dict(native_axi4lite_aw_event=aw_event['event_id'],
                       native_axi4lite_w_event=w_event['event_id'],
                       native_axi4lite_request_event=aw_event['event_id'],
                       native_axi4lite_response_event=completion[0]['event_id'],
                       native_axi4lite_b_event=completion[0]['event_id'])
            value = delivery['write_value']
        else:
            ar = [e for e in samples
                  if _pin(signals, _backend(e), 'arvalid') == 1
                  and _pin(signals, _backend(e), 'arready') == 1]
            if len(ar) != 1:
                raise ValueError('MMIO-native-AXI4-Lite-request')
            ar_event = ar[0]
            if _pin(signals, _backend(ar_event), 'araddr') != offset:
                raise ValueError('MMIO-native-AXI4-Lite-ar-address')
            completion = [e for e in samples
                          if e['event_id'] > ar_event['event_id']
                          and _pin(signals, _backend(e), 'rvalid') == 1
                          and _pin(signals, _backend(e), 'rready') == 1]
            if len(completion) != 1:
                raise ValueError('MMIO-native-AXI4-Lite-completion')
            response = completion[0]
            if _pin(signals, _backend(response), 'rdata') != delivery['read_value']:
                raise ValueError('MMIO-native-AXI4-Lite-read-data')
            code = _pin(signals, _backend(response), 'rresp')
            if code != _OKAY:
                _response_error('read', 'rresp', code)
            row = dict(native_axi4lite_ar_event=ar_event['event_id'],
                       native_axi4lite_request_event=ar_event['event_id'],
                       native_axi4lite_response_event=response['event_id'],
                       native_axi4lite_r_event=response['event_id'])
            value = delivery['read_value']
        joined.append(dict(row, acceptance_event=accepted[0]['event_id'],
                           delivery_event=delivery['event_id'],
                           source_transaction=delivery['source_transaction'],
                           write=delivery['write'], value=value))
    read_value = reads[0]['read_value']
    xor_constant = declaration.get('xor_constant', 0) if flow == 'F2' else 0
    if flow == 'F2' and type(xor_constant) is not int:
        raise ValueError('MMIO-native-read-xor-constant')
    result = read_value ^ xor_constant
    ram = [e for e in events if e.get('kind') == 'memory_write'
           and e.get('component') == access['source_component']
           and e.get('address') == declaration['result_address']
           and e.get('value') == result and e.get('byte_enable') == 15
           and e['event_id'] > reads[0]['event_id']]
    if len(ram) != 1:
        raise ValueError('MMIO-read-return-dependent-RAM')
    return dict(joins=joined, RAM_event=ram[0]['event_id'],
                read_value=read_value, result_value=result)
