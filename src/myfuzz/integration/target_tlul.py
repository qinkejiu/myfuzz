"""TL-UL MMIO target facts for the protocol-independent CPU executor.

The target IP's own TileLink-UL slave port is driven through the generic beat
channel (``beat_to_tlul.sv``); the fifteen declared roles are also exposed as
passive protocol taps, and this module joins the routed CPU MMIO deliveries to
those real pre-edge samples.

What the observation can and cannot claim
-----------------------------------------
* A request exists on the edge where ``a_valid`` and ``a_ready`` are both high.
  Its ``a_opcode``/``a_size``/``a_address``/``a_mask``/``a_data`` are the pins
  the generated bridge actually drove, never a host reconstruction.
* The response exists on the edge where ``d_valid`` and ``d_ready`` are both
  high and follows that request.  A read's ``d_data`` must equal the value the
  router delivered to the CPU; a write is accepted as a response without
  pretending the IP reads back the written word.
* A non-zero ``d_error`` is reported as an error, never collapsed into success.
* Nothing here proves internal register storage, a version, or that a case is
  independent of an earlier case: those facts stay ``unknown``.
"""
from dataclasses import asdict
from hashlib import sha256
import re

from myfuzz.local_harness.tlul_register_session import GeneratedTlulRegisterSession
from myfuzz.runtime.adapters.apb3_mmio import RegisterBank, KIND
from myfuzz.runtime.contracts import canonical_json_bytes
from myfuzz.scenario.ip_protocol_checker import _REQUIRED_SIGNALS

#: The only declared TL-UL target template this adapter admits.
PROTOCOL = ('tl-ul', '1')
TEMPLATE = ('target.tl-ul', '1', 'user-integrity')

#: The passive trace of the driven slave port must carry these roles.  The
#: generated generic trace also exposes a_param/a_user/d_param/d_sink/d_user;
#: those optional roles are allowed but are not required for this join.
_REQUIRED = tuple(_REQUIRED_SIGNALS['tl-ul'])

#: Roles whose width is fixed by the generic 32-bit TL-UL target contract.
_FIXED_WIDTHS = {
    'a_valid': 1, 'a_ready': 1, 'a_source': 8, 'a_opcode': 3, 'a_size': 2,
    'a_address': 32, 'a_mask': 4, 'a_data': 32,
    'd_valid': 1, 'd_ready': 1, 'd_source': 8, 'd_opcode': 3, 'd_size': 2,
    'd_data': 32, 'd_error': 1,
}

#: TL-UL opcodes used by the generated bridge.
_GET = 0b100
_PUT_FULL = 0b000
_PUT_PARTIAL = 0b001
_ACCESS_ACK = 0b000
_ACCESS_ACK_DATA = 0b001

_READABLE = ('ro', 'rw')
_WRITABLE = ('wo', 'rw')


def _declared_trace(document, *, endpoint_id=None):
    """Return the exact declared TL-UL tap contract or refuse."""
    trace = document.get('base_protocol_trace') if isinstance(document, dict) else None
    signals = trace.get('signals') if isinstance(trace, dict) else None
    widths = trace.get('signal_widths') if isinstance(trace, dict) else None
    if (document.get('kind') != 'tlul_register_observe'
            or not isinstance(trace, dict)
            or trace.get('schema_version') != 'ip_protocol_trace.v1'
            or trace.get('protocol') != 'tl-ul'
            or (endpoint_id is not None and trace.get('endpoint_id') != endpoint_id)
            or not isinstance(signals, dict) or not isinstance(widths, dict)
            or not set(_REQUIRED) <= set(signals)
            or set(signals) != set(widths)
            or any(type(name) is not str or not name for name in signals.values())
            or len(set(signals.values())) != len(signals)
            or any(type(width) is not int or width < 1 for width in widths.values())
            or any(widths[role] != width for role, width in _FIXED_WIDTHS.items())):
        raise ValueError('actual-static-TL-UL-MMIO-target-required')
    return trace, signals


def _verify_static_wires(artifact, signals):
    """Pin every declared tap to one generated wire; no synthesized taps."""
    runtime_sv = getattr(artifact, 'runtime_sv', None)
    document = artifact.runtime_document
    if (type(runtime_sv) is not str or not runtime_sv
            or document.get('runtime_sv_sha256') != sha256(runtime_sv.encode()).hexdigest()
            or any(name != 'trace_' + role for role, name in signals.items())):
        raise ValueError('TL-UL-MMIO-trace-wiring-mismatch')
    for name in signals.values():
        if len(re.findall(r'\bassign\s+' + re.escape(name) + r'\s*=', runtime_sv)) != 1:
            raise ValueError('TL-UL-MMIO-trace-wiring-mismatch')


def _mmio_endpoint(artifact, endpoint_id):
    endpoints = [e for e in artifact.plan.binding.endpoints
                 if e.endpoint_id == endpoint_id and e.protocol == PROTOCOL
                 and e.function == 'mmio_slave']
    if len(endpoints) != 1:
        raise ValueError('actual-static-TL-UL-MMIO-target-required')
    return endpoints[0]


def _profile_facts(artifact, endpoint_id):
    """Validate the generic TL-UL target shape and return its static facts."""
    doc = artifact.runtime_document
    _mmio_endpoint(artifact, endpoint_id)
    _trace, signals = _declared_trace(doc, endpoint_id=endpoint_id)
    _verify_static_wires(artifact, signals)
    if (doc.get('storage_observation') is not None
            or doc.get('dynamic_physical_inputs') or doc.get('bound_physical_inputs')):
        raise ValueError('actual-static-TL-UL-MMIO-target-required')
    profile = artifact.plan.profile
    capabilities = profile.capabilities
    if tuple(capabilities.get(name) for name in (
            'address_width', 'data_width', 'byte_enable', 'partial_write',
            'has_error', 'integrity', 'source_width', 'sink_width',
            'user_width', 'd_user_width', 'size_width', 'max_outstanding')) != (
            32, 32, True, True, True, 'required', 8, 1, 23, 14, 2, 1):
        raise ValueError('TL-UL-MMIO-profile-capabilities-unsupported')
    address = profile.address
    if address is None or not address.registers:
        raise ValueError('declared-MMIO-register-map-required')
    window = address.window_size
    if type(window) is not int or not 4 <= window <= 8192 or window % 4:
        raise ValueError('TL-UL-MMIO-window-unsupported')
    if (type(address.alignment) is not int or address.alignment < 1
            or address.alignment > window or window % address.alignment):
        raise ValueError('TL-UL-MMIO-window-unsupported')
    registers = []
    for register in address.registers:
        if (type(register.width) is not int or register.width != 32
                or type(register.offset) is not int or register.offset % 4
                or not 0 <= register.offset < window
                or register.offset + 4 > window
                or register.access not in ('ro', 'rw', 'wo')):
            raise ValueError('TL-UL-MMIO-register-shape-required')
        registers.append(asdict(register))
    return doc, profile, window, registers


def _declared_window(request, access):
    """Exactly one declared window names this target and endpoint."""
    document = getattr(getattr(request, 'wiring', None), 'document', None)
    rows = (document.get('windows', ()) if isinstance(document, dict) else ())
    windows = [row for row in rows
               if row.get('target_instance') == access['target_component']
               and row.get('endpoint_id') in (None, access['target_endpoint'])]
    if len(windows) != 1:
        raise ValueError('TL-UL-MMIO-one-declared-window-required')
    row = windows[0]
    if (row.get('template'), '1', row.get('variant_id')) != TEMPLATE:
        raise ValueError('TL-UL-MMIO-template-mismatch')
    if row.get('device_id') not in (None, access.get('device_id')):
        raise ValueError('TL-UL-MMIO-window-mismatch')
    if row.get('base') is not None and row['base'] != access.get('window_base'):
        raise ValueError('TL-UL-MMIO-window-mismatch')
    if row.get('size') is not None and row['size'] != access.get('window_size'):
        raise ValueError('TL-UL-MMIO-window-mismatch')
    return row


def _declared_tuning(artifact, endpoint_id):
    """The artifact's own tuning must be exactly one declared TL-UL policy."""
    expected = dict(endpoint_id=endpoint_id, template_id='target.tl-ul',
                    template_version='1', variant_id='user-integrity',
                    max_outstanding=1)
    records = [record.document() for record in artifact.plan.request.tuning.records
               if record.kind == 'endpoint_policies']
    if records != [expected]:
        raise ValueError('TL-UL-MMIO-tuning-mismatch')


def _declared_register(artifact, access):
    """The accessed word must be one declared aligned 32-bit register."""
    address = artifact.plan.profile.address
    registers = [r for r in address.registers
                 if r.name == access.get('register')
                 and r.offset == access.get('register_offset')]
    if len(registers) != 1:
        raise ValueError('TL-UL-MMIO-register-required')
    register = registers[0]
    if (register.width != 32 or register.offset % 4
            or register.offset + 4 > address.window_size):
        raise ValueError('TL-UL-MMIO-register-shape')
    operation = access.get('operation')
    if operation not in ('read', 'write'):
        raise ValueError('TL-UL-MMIO-register-operation')
    allowed = _READABLE if operation == 'read' else _WRITABLE
    if register.access not in allowed:
        raise ValueError('TL-UL-MMIO-register-' + operation + '-access')
    return register


def tlul_mmio_bank_facts(artifact, *, endpoint_id):
    """Derive a register-bank description from one already-admitted artifact."""
    doc, profile, window, registers = _profile_facts(artifact, endpoint_id)
    return RegisterBank(canonical_json_bytes(dict(
        schema_version='mmio_register_bank.v1', kind=KIND,
        endpoint_id=endpoint_id, protocol=list(PROTOCOL),
        template=list(TEMPLATE), window_size=window,
        alignment=profile.address.alignment, registers=registers,
        declaration_scope='configured_register_map_not_internal_RTL_storage_proof',
        internal_storage_version='unknown', cross_case_origin='unknown',
        reward_eligible=False)))


def target_adapter(artifact, access, request):
    """Select the real generated TL-UL target or refuse explicitly."""
    if not isinstance(access, dict):
        raise ValueError('TL-UL-MMIO-access-required')
    endpoint_id = access.get('target_endpoint')
    if type(endpoint_id) is not str or not endpoint_id:
        raise ValueError('TL-UL-MMIO-access-required')
    if type(access.get('device_id')) is not str or not access['device_id']:
        raise ValueError('TL-UL-MMIO-access-required')
    if access.get('target_component') != artifact.plan.request.instance_id:
        raise ValueError('TL-UL-MMIO-target-instance-mismatch')
    bank = tlul_mmio_bank_facts(artifact, endpoint_id=endpoint_id)
    _declared_window(request, access)
    _declared_tuning(artifact, endpoint_id)
    window_size = artifact.plan.profile.address.window_size
    window_base = access.get('window_base')
    offset = access.get('register_offset')
    if (type(window_base) is not int or window_base < 0
            or type(access.get('window_size')) is not int
            or access['window_size'] != window_size
            or access.get('window_alignment') != artifact.plan.profile.address.alignment
            or type(offset) is not int or offset % 4
            or access.get('address') != window_base + offset
            or access.get('width_bytes') != 4
            or access.get('access_alignment') != 4
            or access.get('allowed_byte_enables') != [15]
            or not 0 <= offset < window_size or offset + 4 > window_size):
        raise ValueError('TL-UL-MMIO-window-mismatch')
    _declared_register(artifact, access)
    return ('tl-ul', GeneratedTlulRegisterSession, bank,
            observe_tlul_mmio_bus)


def _backend(event):
    outputs = event.get('outputs')
    backend = outputs.get('backend') if isinstance(outputs, dict) else None
    if not isinstance(backend, dict):
        raise ValueError('native-TL-UL-sample-backend-required')
    return backend


def _pin(signals, backend, role):
    value = backend.get(signals[role])
    if type(value) is not int:
        raise ValueError('native-TL-UL-sample-signal-required:' + role)
    return value


def _samples_for(events, access, delivery):
    """The target's own pre-edge samples for this delivery's step."""
    return sorted((event for event in events
                   if event.get('kind') == 'local_tick_sample'
                   and event.get('component') == access['target_component']
                   and event.get('phase') == 'pre'
                   and event.get('producer_event_id') == delivery.get('producer_event_id')),
                  key=lambda event: (event.get('local_tick', 0),
                                     event.get('event_id', 0)))


def _one_request(samples, signals, *, delivery, access):
    """Exactly one accepted A-channel request for this delivery."""
    requests = [sample for sample in samples
                if _pin(signals, _backend(sample), 'a_valid') == 1
                and _pin(signals, _backend(sample), 'a_ready') == 1]
    if len(requests) != 1:
        raise ValueError('MMIO-native-TL-UL-request')
    request = requests[0]
    backend = _backend(request)
    opcode = _pin(signals, backend, 'a_opcode')
    if delivery['write']:
        if (opcode not in (_PUT_FULL, _PUT_PARTIAL)
                or _pin(signals, backend, 'a_size') != 2
                or _pin(signals, backend, 'a_address') != access['register_offset']
                or _pin(signals, backend, 'a_mask') != 0xf
                or _pin(signals, backend, 'a_data') != delivery['write_value']):
            raise ValueError('MMIO-native-TL-UL-write-request')
    else:
        if (opcode != _GET
                or _pin(signals, backend, 'a_size') != 2
                or _pin(signals, backend, 'a_address') != access['register_offset']
                or _pin(signals, backend, 'a_mask') != 0xf):
            raise ValueError('MMIO-native-TL-UL-read-request')
    return request


def _one_response(samples, signals, *, request, delivery):
    """Exactly one accepted D-channel response after the A request."""
    completions = [sample for sample in samples
                   if sample['event_id'] > request['event_id']
                   and _pin(signals, _backend(sample), 'd_valid') == 1
                   and _pin(signals, _backend(sample), 'd_ready') == 1]
    if len(completions) != 1:
        raise ValueError('MMIO-native-TL-UL-completion')
    response = completions[0]
    backend = _backend(response)
    if _pin(signals, backend, 'd_error') != 0:
        raise ValueError('MMIO-native-TL-UL-response-error')
    if (_pin(signals, backend, 'd_source')
            != _pin(signals, _backend(request), 'a_source')):
        raise ValueError('MMIO-native-TL-UL-response-source')
    expected_opcode = _ACCESS_ACK if delivery['write'] else _ACCESS_ACK_DATA
    if _pin(signals, backend, 'd_opcode') != expected_opcode:
        raise ValueError('MMIO-native-TL-UL-response-opcode')
    if _pin(signals, backend, 'd_size') != 2:
        raise ValueError('MMIO-native-TL-UL-response-size')
    if not delivery['write'] and _pin(signals, backend, 'd_data') != delivery['read_value']:
        raise ValueError('MMIO-native-TL-UL-read-data')
    return response


def observe_tlul_mmio_bus(declaration, receipt, *, target_artifact, flow):
    """Join routed CPU MMIO to sampled TL-UL A/D handshakes and RAM result."""
    if flow not in ('F2', 'F4'):
        raise ValueError('TL-UL-MMIO-flow-unsupported')
    access = declaration['candidate']['access']
    endpoint_id = access.get('target_endpoint')
    try:
        _trace, signals = _declared_trace(
            target_artifact.runtime_document,
            endpoint_id=endpoint_id if type(endpoint_id) is str else None)
    except ValueError:
        raise ValueError('native-TL-UL-trace-required') from None
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
    joined = []
    for delivery in writes + reads:
        accepted = [e for e in events if e.get('kind') == 'mmio_acceptance'
                    and e.get('source_transaction') == delivery['source_transaction']
                    and e.get('address') == delivery['address']
                    and e.get('write') == delivery['write']
                    and e['event_id'] < delivery['event_id']]
        if len(accepted) != 1:
            raise ValueError('MMIO-native-TL-UL-acceptance-join')
        if delivery.get('byte_enable') != 15:
            raise ValueError('MMIO-native-TL-UL-byte-enable')
        samples = _samples_for(events, access, delivery)
        if not samples:
            raise ValueError('MMIO-native-TL-UL-samples')
        request = _one_request(samples, signals, delivery=delivery, access=access)
        response = _one_response(samples, signals, request=request,
                                 delivery=delivery)
        value = delivery['write_value'] if delivery['write'] else delivery['read_value']
        joined.append(dict(
            native_tlul_a_event=request['event_id'],
            native_tlul_d_event=response['event_id'],
            native_tlul_request_event=request['event_id'],
            native_tlul_response_event=response['event_id'],
            native_tlul_a_opcode=_pin(signals, _backend(request), 'a_opcode'),
            native_tlul_a_address=_pin(signals, _backend(request), 'a_address'),
            native_tlul_a_mask=_pin(signals, _backend(request), 'a_mask'),
            native_tlul_d_opcode=_pin(signals, _backend(response), 'd_opcode'),
            acceptance_event=accepted[0]['event_id'],
            delivery_event=delivery['event_id'],
            source_transaction=delivery['source_transaction'],
            write=delivery['write'], value=value))
    if (flow == 'F4'
            and joined[0]['native_tlul_response_event']
            >= joined[1]['native_tlul_request_event']):
        raise ValueError('MMIO-native-TL-UL-write-read-order')
    read_value = reads[0]['read_value']
    if type(read_value) is not int:
        raise ValueError('MMIO-native-TL-UL-read-data')
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
