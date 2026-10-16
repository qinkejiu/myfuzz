"""Restricted full-word AHB-Lite register target; no peer or dynamic source."""
from .request import LocalHarnessRequestV2
from .template_contracts import select_template_contract

BUS_SHAPE = {'haddr': ('input', 32), 'hwdata': ('input', 32),
    'hsel': ('input', 1), 'hwrite': ('input', 1), 'hreadyin': ('input', 1),
    'htrans': ('input', 2), 'hsize': ('input', 3), 'hresp': ('output', 1),
    'hreadyout': ('output', 1), 'hrdata': ('output', 32)}


def register_observe_policy(plan, abi=None):
    if not isinstance(plan.request, LocalHarnessRequestV2):
        raise ValueError('ahb-register-v2-required')
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if len(endpoints) != 1 or endpoints[0].function != 'mmio_slave' or endpoints[0].protocol != ('ahb-lite', '1'):
        raise ValueError('ahb-register-target-required')
    endpoint = endpoints[0]
    expected = dict(endpoint_id=endpoint.endpoint_id, template_id='target.ahb-lite',
        template_version='1', variant_id='full-word-single', max_outstanding=1)
    if ([r.document() for r in plan.request.tuning.records] != [expected]):
        raise ValueError('ahb-register-policy-required')
    select_template_contract(endpoint, plan.profile.capabilities,
        template_id='target.ahb-lite', template_version='1', variant_id='full-word-single')
    if {f.role: (f.direction, f.width) for f in endpoint.fields} != BUS_SHAPE:
        raise ValueError('ahb-register-shape-unsupported')
    if plan.profile.address is None or plan.profile.address.window_size != 4096:
        raise ValueError('ahb-register-window-unsupported')
    if abi is not None:
        for row in abi:
            if row['endpoint_id'] == endpoint.endpoint_id:
                continue
            if row['direction'] == 'input' and row['disposition'] != 'constant':
                raise ValueError('ahb-register-unowned-input')
            if row['direction'] not in ('input', 'output'):
                raise ValueError('ahb-register-port-direction')
    return {}, {}, {}
