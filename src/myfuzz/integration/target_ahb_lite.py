"""AHB-Lite MMIO target facts for the protocol-independent CPU executor.

Observations are actual AHB-Lite address and data phases sampled from the real
generated target, never internal register/version proofs.  The generated
``target.ahb-lite@1/full-word-single`` manager presents a window-relative
offset on HADDR, accepts one address phase when HREADYOUT is high and samples
HRDATA/HRESP only in the following data phase.
"""
from dataclasses import asdict
from hashlib import sha256
import re

from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
from myfuzz.runtime.adapters.apb3_mmio import RegisterBank, KIND
from myfuzz.runtime.contracts import canonical_json_bytes

PROTOCOL = ('ahb-lite', '1')
TEMPLATE = ('target.ahb-lite', '1', 'full-word-single')
WINDOW_SIZE = 4096
#: Declared role -> physical width of the generated AHB-Lite register target.
SIGNALS = {'haddr': 32, 'hwdata': 32, 'hsel': 1, 'hwrite': 1, 'hreadyin': 1,
           'htrans': 2, 'hsize': 3, 'hresp': 1, 'hreadyout': 1, 'hrdata': 32}
_READABLE = ('ro', 'rw')
_WRITABLE = ('wo', 'rw')


def _declared_trace(document, *, endpoint_id=None):
    """Return the exact declared AHB-Lite tap contract or refuse."""
    if not isinstance(document, dict):
        raise ValueError('actual-static-AHB-Lite-MMIO-target-required')
    trace = document.get('base_protocol_trace')
    signals = trace.get('signals') if isinstance(trace, dict) else None
    if (document.get('kind') != 'ahb_lite_register_observe'
            or not isinstance(trace, dict)
            or trace.get('schema_version') != 'ip_protocol_trace.v1'
            or trace.get('protocol') != 'ahb-lite'
            or (endpoint_id is not None and trace.get('endpoint_id') != endpoint_id)
            or not isinstance(signals, dict) or set(signals) != set(SIGNALS)
            or not isinstance(trace.get('signal_widths'), dict)
            or trace['signal_widths'] != SIGNALS
            or any(type(name) is not str or not name for name in signals.values())):
        raise ValueError('actual-static-AHB-Lite-MMIO-target-required')
    return trace, signals


def _verify_static_wires(artifact, signals):
    """Pin every declared tap to one generated wire; no synthesized taps."""
    runtime_sv = getattr(artifact, 'runtime_sv', None)
    document = artifact.runtime_document
    if (type(runtime_sv) is not str or not runtime_sv
            or document.get('runtime_sv_sha256') != sha256(runtime_sv.encode()).hexdigest()
            or any(name != 'trace_' + role for role, name in signals.items())):
        raise ValueError('AHB-Lite-MMIO-trace-wiring-mismatch')
    for name in signals.values():
        if len(re.findall(r'\bassign\s+' + re.escape(name) + r'\s*=', runtime_sv)) != 1:
            raise ValueError('AHB-Lite-MMIO-trace-wiring-mismatch')


def _mmio_endpoint(artifact, endpoint_id):
    endpoints = [e for e in artifact.plan.binding.endpoints
                 if e.endpoint_id == endpoint_id and e.protocol == PROTOCOL
                 and e.function == 'mmio_slave']
    if len(endpoints) != 1:
        raise ValueError('actual-static-AHB-Lite-MMIO-target-required')
    return endpoints[0]


def ahb_lite_mmio_bank_facts(artifact, *, endpoint_id):
    """Derive a register-bank description from one already-admitted artifact."""
    doc = artifact.runtime_document
    _mmio_endpoint(artifact, endpoint_id)
    _trace, signals = _declared_trace(doc, endpoint_id=endpoint_id)
    _verify_static_wires(artifact, signals)
    if (doc.get('storage_observation') is not None
            or doc.get('dynamic_physical_inputs') or doc.get('bound_physical_inputs')):
        raise ValueError('actual-static-AHB-Lite-MMIO-target-required')
    address = artifact.plan.profile.address
    if address is None or not address.registers:
        raise ValueError('declared-MMIO-register-map-required')
    if address.window_size != WINDOW_SIZE or address.alignment != WINDOW_SIZE:
        raise ValueError('AHB-Lite-MMIO-window-size-unsupported')
    return RegisterBank(canonical_json_bytes(dict(
        schema_version='mmio_register_bank.v1', kind=KIND, endpoint_id=endpoint_id,
        protocol=['ahb-lite', '1'], template=list(TEMPLATE),
        window_size=address.window_size, alignment=address.alignment,
        registers=[asdict(r) for r in address.registers],
        declaration_scope='configured_register_map_not_internal_RTL_storage_proof',
        internal_storage_version='unknown', cross_case_origin='unknown',
        reward_eligible=False)))


def _declared_window(request, access):
    """Exactly one declared window names this target and endpoint."""
    document = getattr(getattr(request, 'wiring', None), 'document', None)
    rows = (document.get('windows', ()) if isinstance(document, dict) else ())
    windows = [row for row in rows
               if row.get('target_instance') == access['target_component']
               and row.get('endpoint_id') in (None, access['target_endpoint'])]
    if len(windows) != 1:
        raise ValueError('AHB-Lite-MMIO-one-declared-window-required')
    row = windows[0]
    if (row.get('template'), '1', row.get('variant_id')) != TEMPLATE:
        raise ValueError('AHB-Lite-MMIO-template-mismatch')
    if row.get('base') is not None and row['base'] != access.get('window_base'):
        raise ValueError('AHB-Lite-MMIO-window-mismatch')
    if row.get('size') is not None and row['size'] != WINDOW_SIZE:
        raise ValueError('AHB-Lite-MMIO-window-mismatch')
    return row


def _declared_tuning(artifact, endpoint_id):
    """The artifact's own tuning must be exactly one declared AHB policy."""
    expected = dict(endpoint_id=endpoint_id, template_id='target.ahb-lite',
                    template_version='1', variant_id='full-word-single',
                    max_outstanding=1)
    records = [record.document() for record in artifact.plan.request.tuning.records]
    if records != [expected]:
        raise ValueError('AHB-Lite-MMIO-tuning-mismatch')


def _declared_register(artifact, access):
    """The accessed word must be one declared aligned 32-bit register."""
    address = artifact.plan.profile.address
    registers = [r for r in address.registers
                 if r.name == access.get('register')
                 and r.offset == access.get('register_offset')]
    if len(registers) != 1:
        raise ValueError('AHB-Lite-MMIO-register-required')
    register = registers[0]
    if (register.width != 32 or register.offset % 4
            or register.offset + 4 > WINDOW_SIZE):
        raise ValueError('AHB-Lite-MMIO-register-shape')
    operation = access.get('operation')
    if operation not in ('read', 'write'):
        raise ValueError('AHB-Lite-MMIO-register-operation')
    allowed = _READABLE if operation == 'read' else _WRITABLE
    if register.access not in allowed:
        raise ValueError('AHB-Lite-MMIO-register-' + operation + '-access')
    return register


def target_adapter(artifact, access, request):
    """Select the real generated AHB-Lite target or refuse explicitly."""
    if not isinstance(access, dict):
        raise ValueError('AHB-Lite-MMIO-access-required')
    endpoint_id = access.get('target_endpoint')
    if type(endpoint_id) is not str or not endpoint_id:
        raise ValueError('AHB-Lite-MMIO-access-required')
    if access.get('target_component') is None:
        raise ValueError('AHB-Lite-MMIO-access-required')
    bank = ahb_lite_mmio_bank_facts(artifact, endpoint_id=endpoint_id)
    _declared_window(request, access)
    _declared_tuning(artifact, endpoint_id)
    window_base = access.get('window_base')
    window_size = access.get('window_size')
    offset = access.get('register_offset')
    if (type(window_base) is not int or window_base < 0
            or window_base % WINDOW_SIZE
            or type(window_size) is not int or window_size != WINDOW_SIZE
            or type(offset) is not int or offset % 4
            or access.get('address') != window_base + offset
            or offset + 4 > WINDOW_SIZE):
        raise ValueError('AHB-Lite-MMIO-window-mismatch')
    _declared_register(artifact, access)
    return ('ahb-lite', GeneratedAhbLiteRegisterSession, bank,
            observe_ahb_lite_mmio_bus)


def _level(event, signals, role):
    return event.get('outputs', {}).get('backend', {}).get(signals[role])


def _samples_for(events, access, delivery):
    """The target's own pre-edge samples for this delivery's step."""
    producer = delivery.get('producer_event_id')
    if type(producer) is not int:
        raise ValueError('MMIO-native-AHB-samples')
    return sorted((event for event in events
                   if event.get('kind') == 'local_tick_sample'
                   and event.get('component') == access['target_component']
                   and event.get('phase') == 'pre'
                   and event.get('producer_event_id') == producer),
                  key=lambda event: (event.get('local_tick', 0), event.get('event_id', 0)))


def _phases(samples, signals, *, delivery, access):
    """Join one delivery to exactly one address acceptance and data completion."""
    if not samples:
        raise ValueError('MMIO-native-AHB-samples')
    addresses = [sample for sample in samples
                 if _level(sample, signals, 'hsel') == 1
                 and _level(sample, signals, 'htrans') == 2]
    if not addresses:
        raise ValueError('MMIO-native-AHB-address-phase')
    for sample in addresses:
        if (_level(sample, signals, 'haddr') != access['register_offset']
                or _level(sample, signals, 'hwrite') != int(delivery['write'])
                or _level(sample, signals, 'hsize') != 2
                or (delivery['write']
                    and _level(sample, signals, 'hwdata') != delivery['write_value'])):
            raise ValueError('MMIO-native-AHB-address-mismatch')
    accepted = [sample for sample in addresses
                if _level(sample, signals, 'hreadyout') == 1]
    if len(accepted) != 1 or addresses[-1] is not accepted[0]:
        raise ValueError('MMIO-native-AHB-address-acceptance')
    request = accepted[0]
    index = next(position for position, sample in enumerate(samples)
                 if sample is request)
    completion = None
    expected_tick = request.get('local_tick')
    if type(expected_tick) is not int:
        raise ValueError('MMIO-native-AHB-samples')
    for sample in samples[index + 1:]:
        tick = sample.get('local_tick')
        if type(tick) is not int or tick != expected_tick + 1:
            raise ValueError('MMIO-native-AHB-samples')
        expected_tick = tick
        if _level(sample, signals, 'hsel') != 0 or _level(sample, signals, 'htrans') != 0:
            raise ValueError('MMIO-native-AHB-data-phase')
        if _level(sample, signals, 'hreadyout') == 1:
            completion = sample
            break
    if completion is None:
        raise ValueError('MMIO-native-AHB-completion')
    if _level(completion, signals, 'hresp') != 0:
        raise ValueError('MMIO-native-AHB-response-error')
    if not delivery['write'] and _level(completion, signals, 'hrdata') != delivery['read_value']:
        raise ValueError('MMIO-native-AHB-read-data')
    return request, completion


def observe_ahb_lite_mmio_bus(declaration, receipt, *, target_artifact, flow):
    """Join routed CPU MMIO to sampled AHB address/data phases and RAM result."""
    access = declaration['candidate']['access']
    endpoint_id = access.get('target_endpoint')
    try:
        _trace, signals = _declared_trace(
            target_artifact.runtime_document,
            endpoint_id=endpoint_id if type(endpoint_id) is str else None)
    except ValueError:
        raise ValueError('native-AHB-trace-required') from None
    events = receipt.events
    deliveries = [e for e in events if e.get('kind') == 'mmio_delivery'
                  and e.get('component') == access['source_component']
                  and e.get('device_id') == access['device_id']
                  and e.get('address') == access['address']]
    writes = [e for e in deliveries if e.get('write') is True]
    reads = [e for e in deliveries if e.get('write') is False]
    if len(reads) != 1 or len(writes) != (1 if flow == 'F4' else 0):
        raise ValueError('MMIO-transfer-count')
    if writes and (writes[0]['write_value'] != declaration['candidate']['value']
                   or writes[0]['event_id'] >= reads[0]['event_id']):
        raise ValueError('MMIO-native-write-value-or-order')
    joined = []
    for delivery in writes + reads:
        if delivery.get('byte_enable') != 15:
            raise ValueError('MMIO-native-AHB-byte-enable')
        accepted = [e for e in events if e.get('kind') == 'mmio_acceptance'
                    and e.get('source_transaction') == delivery['source_transaction']
                    and e.get('address') == delivery['address']
                    and e.get('write') == delivery['write']
                    and e['event_id'] < delivery['event_id']]
        if len(accepted) != 1:
            raise ValueError('MMIO-native-AHB-acceptance-join')
        request, completion = _phases(_samples_for(events, access, delivery), signals,
                                      delivery=delivery, access=access)
        value = delivery['write_value'] if delivery['write'] else delivery['read_value']
        joined.append(dict(native_ahb_request_event=request['event_id'],
                           native_ahb_response_event=completion['event_id'],
                           acceptance_event=accepted[0]['event_id'],
                           delivery_event=delivery['event_id'],
                           source_transaction=delivery['source_transaction'],
                           write=delivery['write'], value=value))
    read_value = reads[0]['read_value']
    result = read_value ^ (declaration['xor_constant'] if flow == 'F2' else 0)
    ram = [e for e in events if e.get('kind') == 'memory_write'
           and e.get('component') == access['source_component']
           and e.get('address') == declaration['result_address']
           and e.get('value') == result and e.get('byte_enable') == 15
           and e['event_id'] > reads[0]['event_id']]
    if len(ram) != 1:
        raise ValueError('MMIO-read-return-dependent-RAM')
    return dict(joins=joined, RAM_event=ram[0]['event_id'],
                read_value=read_value, result_value=result)
