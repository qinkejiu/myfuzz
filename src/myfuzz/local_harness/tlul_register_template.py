"""Restricted, component-neutral TL-UL register and pin-observation policy."""
from __future__ import annotations

from .request import LocalHarnessRequestV2
from .template_contracts import select_template_contract


def uart_peer_policy(plan):
    """Admit one bounded 8N1 peer using only profile endpoint facts and tuning."""
    rows = plan.request.tuning.records
    peers = [r.document() for r in rows if r.kind == 'uart_8n1_peers']
    startup = [r.document() for r in rows if r.kind == 'startup_writes']
    if not peers:
        if startup:
            raise ValueError('tlul-register-startup-writes-need-serial-peer')
        return None
    if len(peers) != 1:
        raise ValueError('tlul-register-one-uart-peer-required')
    peer = peers[0]
    endpoint = plan.binding.endpoint(peer['endpoint_id'])
    if endpoint.function != 'external_pins':
        raise ValueError('tlul-register-uart-external-pins-required')
    rx = plan.binding.field(peer['endpoint_id'], peer['rx_role'])
    tx = plan.binding.field(peer['endpoint_id'], peer['tx_role'])
    if ((rx.direction, rx.width, tx.direction, tx.width) !=
            ('input', 1, 'output', 1) or not rx.whole_port or not tx.whole_port):
        raise ValueError('tlul-register-uart-pin-shape')
    environment = [r.document() for r in rows if r.kind == 'environment_bindings']
    if environment != [dict(endpoint_id=peer['endpoint_id'], role=peer['rx_role'],
                            source_id=peer['source_id'])]:
        raise ValueError('tlul-register-uart-rx-source-required')
    if any(r.kind == 'bound_bindings' for r in rows):
        raise ValueError('tlul-register-uart-bound-input-unsupported')
    if len(startup) > 16 or [r['sequence'] for r in startup] != list(range(1, len(startup) + 1)):
        raise ValueError('tlul-register-uart-startup-sequence')
    window = plan.profile.address.window_size if plan.profile.address is not None else 0
    if any(r['offset'] % 4 or r['offset'] >= window or r['value'] > 0xffffffff
           for r in startup):
        raise ValueError('tlul-register-uart-startup-access')
    return {'schema_version': 'generated_tlul_uart_8n1_tuning.v1',
            'format': '8N1', 'rx_port': peer['endpoint_id'] + '.' + peer['rx_role'],
            'tx_port': tx.port, 'source_id': peer['source_id'],
            'clocks_per_bit': peer['clocks_per_bit'], 'idle_bits': peer['idle_bits'],
            'startup_writes': [[r['offset'], r['value']] for r in startup]}


def register_observe_policy(plan, abi=None):
    """Return fixed and dynamic physical inputs; reject every unowned bit.

    This template only performs TL-UL register accesses and observes pins.  It
    never synthesizes serial traffic, IRQ results, or DUT register values.
    """
    request = plan.request
    if not isinstance(request, LocalHarnessRequestV2):
        raise ValueError('tlul-register-v2-request-required')
    rows = request.tuning.records
    policies = [r.document() for r in rows if r.kind == 'endpoint_policies']
    constants = [r.document() for r in rows if r.kind == 'fixed_inputs']
    environment = [r.document() for r in rows if r.kind == 'environment_bindings']
    bound_rows = [r.document() for r in rows if r.kind == 'bound_bindings']
    if any(r.kind not in ('endpoint_policies', 'fixed_inputs', 'environment_bindings',
                          'bound_bindings', 'uart_8n1_peers', 'startup_writes') for r in rows):
        raise ValueError('tlul-register-unsupported-tuning')
    uart_peer_policy(plan)
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if len(endpoints) != 1 or endpoints[0].protocol != ('tl-ul', '1') or endpoints[0].function != 'mmio_slave':
        raise ValueError('tlul-register-target-required')
    endpoint = endpoints[0]
    expected = dict(endpoint_id=endpoint.endpoint_id, template_id='target.tl-ul',
                    template_version='1', variant_id='user-integrity', max_outstanding=1)
    if policies != [expected]:
        raise ValueError('tlul-register-template-policy-required')
    select_template_contract(endpoint, plan.profile.capabilities,
                             template_id=expected['template_id'],
                             template_version=expected['template_version'],
                             variant_id=expected['variant_id'])
    if plan.profile.address is None or not 4 <= plan.profile.address.window_size <= 8192 or plan.profile.address.window_size % 4:
        raise ValueError('tlul-register-window-unsupported')
    by_field = {}
    for row in constants:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        if field.direction != 'input' or field.endpoint_id == endpoint.endpoint_id:
            raise ValueError('tlul-register-nonbus-input-required')
        if row['value'] >= 1 << field.width:
            raise ValueError('tlul-register-constant-width')
        by_field[key] = row['value']
    dynamic = {}
    for row in environment:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        owner = plan.binding.endpoint(row['endpoint_id'])
        if (owner.function != 'external_pins' or field.direction != 'input' or
                field.endpoint_id == endpoint.endpoint_id or field.width > 64):
            raise ValueError('tlul-register-environment-input-required')
        if key in by_field:
            raise ValueError('tlul-register-overlapping-input-owners')
        dynamic[key] = row['source_id']
    bound = {}
    for row in bound_rows:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        owner = plan.binding.endpoint(row['endpoint_id'])
        if (owner.function != 'external_pins' or field.direction != 'input' or
                field.endpoint_id == endpoint.endpoint_id or field.width > 64):
            raise ValueError('tlul-register-bound-input-required')
        if key in by_field or key in dynamic:
            raise ValueError('tlul-register-overlapping-input-owners')
        bound[key] = row['producer_ref']
    if abi is None:
        return by_field, dynamic, bound
    fixed_ownership = {}
    dynamic_ownership = {}
    bound_ownership = {}
    for row in abi:
        if row['endpoint_id'] == endpoint.endpoint_id:
            continue
        if row['disposition'] == 'peer':
            raise ValueError('tlul-register-peer-unsupported')
        if row['direction'] == 'input':
            key = (row['endpoint_id'], row['role'])
            if row['width'] > 64 or (key not in by_field and key not in dynamic
                                    and key not in bound):
                raise ValueError('tlul-register-unowned-input:' + row['wrapper_name'])
            if key in dynamic:
                if row['disposition'] not in ('external', 'fuzz'):
                    raise ValueError('tlul-register-environment-disposition')
                dynamic_ownership[key] = dynamic[key]
            elif key in bound:
                if row['disposition'] not in ('external', 'fuzz'):
                    raise ValueError('tlul-register-bound-disposition')
                bound_ownership[key] = bound[key]
            else:
                fixed_ownership[key] = by_field[key]
        elif row['direction'] != 'output':
            raise ValueError('tlul-register-port-direction')
    if (set(fixed_ownership) != set(by_field) or
            set(dynamic_ownership) != set(dynamic) or
            set(bound_ownership) != set(bound)):
        raise ValueError('tlul-register-constant-not-exported')
    return fixed_ownership, dynamic_ownership, bound_ownership
