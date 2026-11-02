"""Wishbone MMIO target facts for the protocol-independent CPU executor.

Observations are actual bus transfers, not internal register/version proofs.
"""
from dataclasses import asdict

from myfuzz.local_harness.wishbone_register_session import GeneratedWishboneRegisterSession
from myfuzz.runtime.adapters.apb3_mmio import RegisterBank, KIND
from myfuzz.runtime.contracts import canonical_json_bytes


def wishbone_mmio_bank_facts(artifact, *, endpoint_id):
    """Derive a register-bank description from one already-admitted artifact."""
    doc = artifact.runtime_document
    profile = artifact.plan.profile
    endpoints = [e for e in artifact.plan.binding.endpoints if e.endpoint_id == endpoint_id
                 and e.protocol == ('wishbone', 'classic') and e.function == 'mmio_slave']
    trace = doc.get('base_protocol_trace', {})
    signals = trace.get('signals', {})
    required = {'cyc', 'stb', 'we', 'dat_w', 'sel', 'ack', 'dat_r', 'stall'}
    if (doc.get('kind') != 'wishbone_register_observe' or len(endpoints) != 1
            or doc.get('storage_observation') is not None
            or doc.get('dynamic_physical_inputs') or doc.get('bound_physical_inputs')
            or trace.get('protocol') != 'wishbone' or not required <= set(signals)
            or 'err' in signals or profile.capabilities.get('address_units') != 'word'):
        raise ValueError('actual-static-Wishbone-MMIO-target-required')
    addressed = profile.capabilities.get('has_address_port')
    if type(addressed) is not bool or addressed != ('adr' in signals):
        raise ValueError('Wishbone-MMIO-address-port-mismatch')
    address = profile.address
    if address is None or not address.registers:
        raise ValueError('declared-MMIO-register-map-required')
    if not addressed and address.window_size != 4:
        raise ValueError('Wishbone-MMIO-addressless-window')
    return RegisterBank(canonical_json_bytes(dict(schema_version='mmio_register_bank.v1',kind=KIND,
        endpoint_id=endpoint_id,protocol=['wishbone','classic'],
        template=['target.wishbone','1',('word-addressed-registered-ack' if addressed
                                         else 'addressless-select-ignored')],
        window_size=address.window_size,alignment=address.alignment,
        registers=[asdict(r) for r in address.registers],
        declaration_scope='configured_register_map_not_internal_RTL_storage_proof',
        internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False)))


def observe_wishbone_mmio_bus(declaration, receipt, *, target_artifact, flow):
    """Join routed CPU MMIO to sampled Wishbone request/ACK and RAM result."""
    trace = target_artifact.runtime_document.get('base_protocol_trace', {})
    if target_artifact.runtime_document.get('kind') != 'wishbone_register_observe' or trace.get('protocol') != 'wishbone':
        raise ValueError('native-Wishbone-trace-required')
    signals = trace['signals']
    access = declaration['candidate']['access']
    events = receipt.events
    deliveries = [e for e in events if e.get('kind') == 'mmio_delivery'
        and e.get('component') == access['source_component'] and e.get('device_id') == access['device_id']
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
        accepted = [e for e in events if e.get('kind') == 'mmio_acceptance'
            and e.get('source_transaction') == delivery['source_transaction']
            and e.get('address') == delivery['address'] and e.get('write') == delivery['write']
            and e['event_id'] < delivery['event_id']]
        samples = [e for e in events if e.get('kind') == 'local_tick_sample'
            and e.get('component') == access['target_component'] and e.get('phase') == 'pre'
            and e.get('producer_event_id') == delivery.get('producer_event_id')]
        def fields(event): return event.get('outputs', {}).get('backend', {})
        def level(event, role): return fields(event).get(signals[role])
        requests = [e for e in samples if level(e, 'cyc') == 1 and level(e, 'stb') == 1
            and level(e, 'stall') == 0 and level(e, 'we') == int(delivery['write'])
            and ('adr' not in signals or level(e, 'adr') == access['register_offset'] >> 2)
            and (not delivery['write'] or (delivery.get('byte_enable') == 15
                and level(e, 'sel') == 15 and level(e, 'dat_w') == delivery['write_value']))]
        if len(accepted) != 1 or len(requests) != 1:
            raise ValueError('MMIO-native-Wishbone-request')
        request = requests[0]
        completions = [e for e in samples if e['event_id'] >= request['event_id']
            and level(e, 'cyc') == 1 and level(e, 'ack') == 1
            and (delivery['write'] or level(e, 'dat_r') == delivery['read_value'])]
        if len(completions) != 1:
            raise ValueError('MMIO-native-Wishbone-completion')
        value = delivery['write_value'] if delivery['write'] else delivery['read_value']
        joined.append(dict(native_wishbone_request_event=request['event_id'],
            native_wishbone_response_event=completions[0]['event_id'], acceptance_event=accepted[0]['event_id'],
            delivery_event=delivery['event_id'], source_transaction=delivery['source_transaction'],
            write=delivery['write'], value=value))
    read_value = reads[0]['read_value']
    result = read_value ^ (declaration['xor_constant'] if flow == 'F2' else 0)
    ram = [e for e in events if e.get('kind') == 'memory_write' and e.get('component') == access['source_component']
        and e.get('address') == declaration['result_address'] and e.get('value') == result
        and e.get('byte_enable') == 15 and e['event_id'] > reads[0]['event_id']]
    if len(ram) != 1:
        raise ValueError('MMIO-read-return-dependent-RAM')
    return dict(joins=joined, RAM_event=ram[0]['event_id'], read_value=read_value, result_value=result)
