"""Restricted, component-neutral TL-UL register and pin-observation policy."""
from __future__ import annotations

from .request import LocalHarnessRequestV2
from .template_contracts import select_template_contract


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
    if any(r.kind not in ('endpoint_policies', 'fixed_inputs', 'environment_bindings') for r in rows):
        raise ValueError('tlul-register-unsupported-tuning')
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
    if abi is None:
        return by_field, dynamic
    fixed_ownership = {}
    dynamic_ownership = {}
    for row in abi:
        if row['endpoint_id'] == endpoint.endpoint_id:
            continue
        if row['disposition'] == 'peer':
            raise ValueError('tlul-register-peer-unsupported')
        if row['direction'] == 'input':
            key = (row['endpoint_id'], row['role'])
            if row['width'] > 64 or (key not in by_field and key not in dynamic):
                raise ValueError('tlul-register-unowned-input:' + row['wrapper_name'])
            if key in dynamic:
                if row['disposition'] not in ('external', 'fuzz'):
                    raise ValueError('tlul-register-environment-disposition')
                dynamic_ownership[key] = dynamic[key]
            else:
                fixed_ownership[key] = by_field[key]
        elif row['direction'] != 'output':
            raise ValueError('tlul-register-port-direction')
    if set(fixed_ownership) != set(by_field) or set(dynamic_ownership) != set(dynamic):
        raise ValueError('tlul-register-constant-not-exported')
    return fixed_ownership, dynamic_ownership
