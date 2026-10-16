"""Restricted, component-neutral AXI4-Lite register and pin-observation policy.

The other three admitted generic target protocols keep IP semantics out of the
harness by driving a narrow beat channel and observing only the declared pins.
AXI4-Lite joins them on the same terms: the real IP's own slave port is driven
by ``axi4_lite_mmio_target``, whose beat side is the generic channel, and the 19
declared AXI4-Lite roles are exposed as passive protocol taps.

Two facts make this protocol's variant selection different from Wishbone's:

* AXI4-Lite writes use two independently handshaken channels (AW and W), so a
  write is accepted on the edge that completes the pair, not on either one
  alone.  Nothing here may assume AW-then-W ordering.
* The response codes BRESP/RRESP are physical ports a real slave drives.  A
  component that declares ``has_error`` false still declares the pins, so the
  variant records whether the code can carry a failure instead of dropping it.

Nothing here claims the DUT honours the protocol; it only fixes which declared
shape the generic renderer, session and checker are allowed to build.
"""
from __future__ import annotations

from .request import LocalHarnessRequestV2
from .template_contracts import select_template_contract
# The serial-peer admission rules are transport-independent: they read the
# declared pin endpoints and the tuning records, never the bus protocol. They
# are reused here rather than copied so the two members cannot drift.
from .tlul_register_template import serial_peer_policy as _serial_peer_policy

#: The renderer's ``axi4_lite_mmio_target`` caps its own wait counter, so the
#: policy refuses a budget the kernel cannot represent rather than clamping it.
MAX_WAIT_CYCLES = 16

#: The exact slave-side shape of a real AXI4-Lite endpoint, with the address
#: width the profile declares.  Held inside ``MAX_ADDRESS_WIDTH`` because the
#: register template only addresses a window that fits in one word offset.
MIN_ADDRESS_WIDTH = 1
MAX_ADDRESS_WIDTH = 12

#: The role names of the driven AXI4-Lite bus. Every one of them is exposed as
#: a passive protocol tap of the same net, so none of them is an owned input.
def bus_shape(address_width):
    return {
        'awvalid': ('input', 1), 'awready': ('output', 1),
        'awaddr': ('input', address_width), 'awprot': ('input', 3),
        'wvalid': ('input', 1), 'wready': ('output', 1),
        'wdata': ('input', 32), 'wstrb': ('input', 4),
        'bvalid': ('output', 1), 'bready': ('input', 1), 'bresp': ('output', 2),
        'arvalid': ('input', 1), 'arready': ('output', 1),
        'araddr': ('input', address_width), 'arprot': ('input', 3),
        'rvalid': ('output', 1), 'rready': ('input', 1),
        'rdata': ('output', 32), 'rresp': ('output', 2),
    }


#: The role names of the driven AXI4-Lite bus. Every one of them is exposed as
#: a passive protocol tap of the same net, so none of them is an owned input.
_TRACE_TAP_ROLES = tuple(bus_shape(0))


class _PeerPlan:
    """Present the plan to the shared serial-peer policy.

    The peer rules ask the plan for a resolved endpoint. A plan exposes that
    through its binding, so this delegates explicitly instead of the caller
    reaching into another object's internals.
    """

    def __init__(self, plan):
        self.request = plan.request
        self.binding = plan.binding
        self.profile = plan.profile

    def endpoint(self, endpoint_id):
        return self.binding.endpoint(endpoint_id)


def register_observe_policy(plan, abi=None):
    """Return the member's four ownership maps plus its declared serial peer.

    Every call returns the same five facts, so a caller cannot silently read a
    shorter tuple in one code path than another: the three ownership maps, the
    peer document (or ``None``), and the peer's startup writes.
    """
    request = plan.request
    if not isinstance(request, LocalHarnessRequestV2):
        raise ValueError('axi4lite-register-v2-request-required')
    rows = request.tuning.records
    policies = [r.document() for r in rows if r.kind == 'endpoint_policies']
    constants = [r.document() for r in rows if r.kind == 'fixed_inputs']
    environment = [r.document() for r in rows if r.kind == 'environment_bindings']
    bound_rows = [r.document() for r in rows if r.kind == 'bound_bindings']
    if any(r.kind not in ('endpoint_policies', 'fixed_inputs', 'environment_bindings',
                          'bound_bindings', 'uart_8n1_peers', 'startup_writes')
           for r in rows):
        raise ValueError('axi4lite-register-unsupported-tuning')
    # A declared serial peer turns this member from a pure register observer
    # into a frame source/sink. The declaration is admitted by the same rules
    # the TL-UL member uses, so a peer that is legal there is legal here.
    serial_peer = _serial_peer_policy(
        _PeerPlan(plan), schema='generated_axi4lite_uart_8n1_tuning.v1',
        label='axi4lite')
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if (len(endpoints) != 1 or endpoints[0].protocol != ('axi4-lite', '1')
            or endpoints[0].function != 'mmio_slave'):
        raise ValueError('axi4lite-register-target-required')
    endpoint = endpoints[0]
    c = plan.profile.capabilities
    # A slave endpoint must declare the response codes; the variant then records
    # whether the code can carry a failure at all.
    has_error = c.get('has_error')
    if has_error is False:
        # No registered variant describes a slave without response codes yet.
        # Refusing by name is honest; silently selecting the error-code variant
        # would claim a capability the profile just denied.
        raise ValueError('axi4lite-register-okay-only-variant-unregistered')
    if has_error is not True:
        raise ValueError('axi4lite-register-variant-unsupported')
    variant = 'single-outstanding-error-codes'
    if c.get('bursts') is not False or c.get('ids') is not False:
        raise ValueError('axi4lite-register-burst-or-id-unsupported')
    if c.get('max_outstanding') != 1:
        raise ValueError('axi4lite-register-outstanding-unsupported')
    expected = dict(endpoint_id=endpoint.endpoint_id, template_id='target.axi4-lite',
                    template_version='1', variant_id=variant, max_outstanding=1)
    if policies != [expected]:
        raise ValueError('axi4lite-register-template-policy-required')
    select_template_contract(endpoint, c, template_id='target.axi4-lite',
                             template_version='1', variant_id=variant)
    address_width = c.get('address_width')
    if (type(address_width) is not int
            or not MIN_ADDRESS_WIDTH <= address_width <= MAX_ADDRESS_WIDTH
            or {field.role: (field.direction, field.width)
                for field in endpoint.fields} != bus_shape(address_width)
            or tuple(c.get(key) for key in ('data_width', 'byte_enable',
                                            'partial_write', 'has_error'))
            != (32, True, True, True)):
        raise ValueError('axi4lite-register-bus-shape-unsupported')
    if plan.profile.address is None or not 4 <= plan.profile.address.window_size <= 4096 \
            or plan.profile.address.window_size % 4:
        raise ValueError('axi4lite-register-window-unsupported')
    if plan.profile.address.window_size > 4 * (1 << address_width):
        raise ValueError('axi4lite-register-window-exceeds-address-width')
    declared_wait = c.get('max_wait_cycles')
    if (type(declared_wait) is not int or declared_wait < 1
            or declared_wait > MAX_WAIT_CYCLES
            or request.max_wait_cycles > MAX_WAIT_CYCLES):
        raise ValueError('axi4lite-register-wait-bound')
    by_field = {}
    for row in constants:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        if field.direction != 'input' or field.endpoint_id == endpoint.endpoint_id:
            raise ValueError('axi4lite-register-nonbus-input-required')
        if field.width > 64 or row['value'] >= 1 << field.width:
            raise ValueError('axi4lite-register-constant-width')
        by_field[key] = row['value']
    dynamic = {}
    for row in environment:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        owner = plan.binding.endpoint(row['endpoint_id'])
        if (owner.function != 'external_pins' or field.direction != 'input' or
                field.endpoint_id == endpoint.endpoint_id or field.width > 64):
            raise ValueError('axi4lite-register-environment-input-required')
        if key in by_field:
            raise ValueError('axi4lite-register-overlapping-input-owners')
        dynamic[key] = row['source_id']
    bound = {}
    for row in bound_rows:
        key = (row['endpoint_id'], row['role'])
        field = plan.binding.field(*key)
        owner = plan.binding.endpoint(row['endpoint_id'])
        if (owner.function != 'external_pins' or field.direction != 'input' or
                field.endpoint_id == endpoint.endpoint_id or field.width > 64):
            raise ValueError('axi4lite-register-bound-input-required')
        if key in by_field or key in dynamic:
            raise ValueError('axi4lite-register-overlapping-input-owners')
        bound[key] = row['producer_ref']
    if abi is None:
        return by_field, dynamic, bound, serial_peer, tuple(
            (row['offset'], row['value'])
            for row in sorted((r.document() for r in rows
                               if r.kind == 'startup_writes'),
                              key=lambda row: row['sequence']))
    # The protocol taps of the driven bus are passive outputs on the very nets
    # the beat adapter drives. They live in the artifact's backend ports rather
    # than its physical exports, so they need no input ownership and must not
    # be mistaken for stray wrapper inputs.
    tap_roles = set(_TRACE_TAP_ROLES)
    fixed_ownership = {}
    dynamic_ownership = {}
    bound_ownership = {}
    for row in abi:
        if row['endpoint_id'] == endpoint.endpoint_id:
            continue
        if row['role'] in tap_roles and row['disposition'] == 'functional':
            # A declared role of a driven bus, tapped passively for the
            # protocol-event layer.
            continue
        if row['disposition'] == 'peer':
            raise ValueError('axi4lite-register-peer-unsupported')
        if row['direction'] == 'output':
            # A declared non-bus output (an interrupt line, a serial pin) is
            # observed by the generic session rather than owned as an input.
            # It must still be a real endpoint field with a real role, so a
            # stray wrapper port cannot be waved through as "just an output".
            # A declared role of the driven bus is the same case: a passive
            # tap of a net the beat adapter drives, which owns no input either.
            if (row['role'] is None or row['endpoint_id'] is None
                    or row['disposition'] not in ('functional', 'external')):
                raise ValueError('axi4lite-register-port-direction:'
                                 + row['wrapper_name'])
            continue
        if row['direction'] != 'input':
            raise ValueError('axi4lite-register-port-direction')
        key = (row['endpoint_id'], row['role'])
        if row['width'] > 64 or (key not in by_field and key not in dynamic
                                 and key not in bound):
            raise ValueError('axi4lite-register-unowned-input:' + row['wrapper_name'])
        if key in dynamic:
            if row['disposition'] not in ('external', 'fuzz'):
                raise ValueError('axi4lite-register-environment-disposition')
            dynamic_ownership[key] = dynamic[key]
        elif key in bound:
            if row['disposition'] not in ('external', 'fuzz'):
                raise ValueError('axi4lite-register-bound-disposition')
            bound_ownership[key] = bound[key]
        else:
            fixed_ownership[key] = by_field[key]
    if (set(fixed_ownership) != set(by_field) or
            set(dynamic_ownership) != set(dynamic) or
            set(bound_ownership) != set(bound)):
        raise ValueError('axi4lite-register-constant-not-exported')
    return (fixed_ownership, dynamic_ownership, bound_ownership, serial_peer,
            tuple((row['offset'], row['value'])
                  for row in sorted((r.document() for r in rows
                                     if r.kind == 'startup_writes'),
                                    key=lambda row: row['sequence'])))
