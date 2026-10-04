"""Restricted, component-neutral Wishbone register and pin-observation policy."""
from __future__ import annotations

from .request import LocalHarnessRequestV2
from .template_contracts import select_template_contract


def register_observe_policy(plan, abi=None):
    request = plan.request
    if not isinstance(request, LocalHarnessRequestV2):
        raise ValueError('wishbone-register-v2-request-required')
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if (len(endpoints) != 1 or endpoints[0].protocol != ('wishbone', 'classic')
            or endpoints[0].function != 'mmio_slave'):
        raise ValueError('wishbone-register-target-required')
    endpoint = endpoints[0]
    c = plan.profile.capabilities
    has_address = c.get('has_address_port')
    variant = ('word-addressed-registered-ack' if has_address is True else
               'addressless-select-ignored' if has_address is False else None)
    if variant is None:
        raise ValueError('wishbone-register-variant-unsupported')
    policies = [r.document() for r in request.tuning.records if r.kind == 'endpoint_policies']
    expected = dict(endpoint_id=endpoint.endpoint_id, template_id='target.wishbone',
                    template_version='1', variant_id=variant, max_outstanding=1)
    if policies != [expected]:
        raise ValueError('wishbone-register-template-policy-required')
    select_template_contract(endpoint, c, template_id='target.wishbone',
                             template_version='1', variant_id=variant)
    window = plan.profile.address.window_size if plan.profile.address else None
    address_width = c.get('address_width') if has_address else 0
    if (type(window) is not int or not 4 <= window <= 4096 or window % 4
            or (not has_address and window != 4)
            or (has_address and (type(address_width) is not int
                                 or not 1 <= address_width <= 12
                                 or window > 4 * (1 << address_width)))):
        raise ValueError('wishbone-register-window-unsupported')
    allowed = {'endpoint_policies', 'fixed_inputs'}
    if any(row.kind not in allowed for row in request.tuning.records):
        raise ValueError('wishbone-register-unsupported-tuning')
    fixed = {}
    for row in (r.document() for r in request.tuning.records if r.kind == 'fixed_inputs'):
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        if field.direction != 'input' or field.endpoint_id == endpoint.endpoint_id:
            raise ValueError('wishbone-register-nonbus-input-required')
        if field.width > 64 or row['value'] >= 1 << field.width:
            raise ValueError('wishbone-register-constant-width')
        fixed[key] = row['value']
    if abi is None:
        return fixed
    seen = set()
    for row in abi:
        if row['endpoint_id'] == endpoint.endpoint_id:
            continue
        if row['disposition'] == 'peer':
            raise ValueError('wishbone-register-peer-unsupported')
        if row['direction'] == 'input':
            key = (row['endpoint_id'], row['role'])
            if row['endpoint_id'] is None and row['disposition'] == 'constant':
                continue
            if (key not in fixed or row['width'] > 64
                    or row['disposition'] not in ('external', 'fuzz')):
                raise ValueError('wishbone-register-unowned-input:' + row['wrapper_name'])
            seen.add(key)
        elif row['direction'] != 'output':
            raise ValueError('wishbone-register-port-direction')
    if seen != set(fixed):
        raise ValueError('wishbone-register-constant-not-exported')
    return fixed
