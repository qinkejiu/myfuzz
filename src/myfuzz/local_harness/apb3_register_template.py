"""Restricted, component-neutral APB3 register and pin-observation policy."""
from __future__ import annotations

from .request import LocalHarnessRequestV2
from .template_contracts import select_template_contract

_BUS_SHAPE = {
    'paddr': ('input', 12), 'psel': ('input', 1),
    'penable': ('input', 1), 'pwrite': ('input', 1),
    'pwdata': ('input', 32), 'pready': ('output', 1),
    'prdata': ('output', 32), 'pslverr': ('output', 1),
}


def register_observe_policy(plan, abi=None):
    """Return fixed and dynamic physical inputs; reject every unowned bit.

    This template only performs APB3 register accesses and observes pins.  It
    never synthesizes serial traffic, IRQ results, or DUT register values.
    """
    request = plan.request
    if not isinstance(request, LocalHarnessRequestV2):
        raise ValueError('apb3-register-v2-request-required')
    rows = request.tuning.records
    policies = [r.document() for r in rows if r.kind == 'endpoint_policies']
    constants = [r.document() for r in rows if r.kind == 'fixed_inputs']
    environment = [r.document() for r in rows if r.kind == 'environment_bindings']
    bound_rows = [r.document() for r in rows if r.kind == 'bound_bindings']
    if any(r.kind not in ('endpoint_policies', 'fixed_inputs', 'environment_bindings',
                          'bound_bindings') for r in rows):
        raise ValueError('apb3-register-unsupported-tuning')
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if len(endpoints) != 1 or endpoints[0].protocol != ('apb', '3') or endpoints[0].function != 'mmio_slave':
        raise ValueError('apb3-register-target-required')
    endpoint = endpoints[0]
    expected = dict(endpoint_id=endpoint.endpoint_id, template_id='target.apb3',
                    template_version='1', variant_id='full-word', max_outstanding=1)
    if policies != [expected]:
        raise ValueError('apb3-register-template-policy-required')
    select_template_contract(endpoint, plan.profile.capabilities,
                             template_id=expected['template_id'],
                             template_version=expected['template_version'],
                             variant_id=expected['variant_id'])
    if ({field.role: (field.direction, field.width) for field in endpoint.fields}
            != _BUS_SHAPE or tuple(plan.profile.capabilities.get(key) for key in
            ('address_width', 'data_width', 'byte_enable', 'partial_write',
             'has_error')) != (12, 32, False, False, True)):
        raise ValueError('apb3-register-bus-shape-unsupported')
    if plan.profile.address is None or plan.profile.address.window_size != 4096:
        raise ValueError('apb3-register-window-unsupported')
    by_field = {}
    for row in constants:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        if field.direction != 'input' or field.endpoint_id == endpoint.endpoint_id:
            raise ValueError('apb3-register-nonbus-input-required')
        if row['value'] >= 1 << field.width:
            raise ValueError('apb3-register-constant-width')
        by_field[key] = row['value']
    dynamic = {}
    for row in environment:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        owner = plan.binding.endpoint(row['endpoint_id'])
        if (owner.function != 'external_pins' or field.direction != 'input' or
                field.endpoint_id == endpoint.endpoint_id or field.width > 64):
            raise ValueError('apb3-register-environment-input-required')
        if key in by_field:
            raise ValueError('apb3-register-overlapping-input-owners')
        dynamic[key] = row['source_id']
    bound = {}
    for row in bound_rows:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        owner = plan.binding.endpoint(row['endpoint_id'])
        if (owner.function != 'external_pins' or field.direction != 'input' or
                field.endpoint_id == endpoint.endpoint_id or field.width > 64):
            raise ValueError('apb3-register-bound-input-required')
        if key in by_field or key in dynamic:
            raise ValueError('apb3-register-overlapping-input-owners')
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
            raise ValueError('apb3-register-peer-unsupported')
        if row['direction'] == 'input':
            key = (row['endpoint_id'], row['role'])
            if row['width'] > 64 or (key not in by_field and key not in dynamic
                                    and key not in bound):
                raise ValueError('apb3-register-unowned-input:' + row['wrapper_name'])
            if key in dynamic:
                if row['disposition'] not in ('external', 'fuzz'):
                    raise ValueError('apb3-register-environment-disposition')
                dynamic_ownership[key] = dynamic[key]
            elif key in bound:
                if row['disposition'] not in ('external', 'fuzz'):
                    raise ValueError('apb3-register-bound-disposition')
                bound_ownership[key] = bound[key]
            else:
                fixed_ownership[key] = by_field[key]
        elif row['direction'] != 'output':
            raise ValueError('apb3-register-port-direction')
    if (set(fixed_ownership) != set(by_field) or
            set(dynamic_ownership) != set(dynamic) or
            set(bound_ownership) != set(bound)):
        raise ValueError('apb3-register-constant-not-exported')
    return fixed_ownership, dynamic_ownership, bound_ownership
