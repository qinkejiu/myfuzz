"""Declared target bus-input pins that the target's own adapter drives.

A generated TL-UL ``tlul_register_observe`` target owns its local bus port: the
runtime wrapper leaves the ten A-channel/``d_ready`` inputs as internal
``link_*`` wires driven by ``beat_to_tlul.sv`` and exposes only passive
``trace_*`` outputs.  D3 still lists those IP input ports as ``external_pin``
sources because every declared input field becomes a source, but no host value
can be delivered to them:

* they are not runtime ports of the generated top;
* they are not owned host inputs (ownership only carries real environment
  fields such as ``gpio.pins.in``);
* the TL-UL register template refuses them as dynamic/bound inputs and the
  target session's only bus driver is its own ``ACCESS_TLUL_REG`` command.

This module is the single declaration authority for that pin class.

* A pin declaration names one adapter-consumed target input by
  ``(component, endpoint_id, port, bit_offset, width)``.
* Its identity is a digest of the declaration, never a dependency-graph path:
  the compiled runtime dependency graph only carries fuzzable *host* sources,
  and pin paths must not be forced into the prepared graph/contract (that would
  break the mixed-flow graph equality and the ownership checks).
* The host may record the declared candidate value, but never writes it into
  RTL or into ``ScenarioRunner`` inputs.  The target's own access commands are
  the only way the bus is driven; the passive ``trace_*`` taps are the only
  observation.

The recognition is deliberately narrow: it only accepts the fixed 32-bit TL-UL
target template's declared input role/width set on the target's own MMIO
endpoint.  Any other external pin keeps the ordinary host-driven path.
"""
from __future__ import annotations

import json
from hashlib import sha256

#: Versioned identity of one declared target bus-input pin.
SCHEMA_VERSION = 'target_bus_pin_declaration.v1'

#: A target bus input is driven from the CPU side only.
TARGET_BUS_PIN_DIRECTION = 'CPU_TO_IP'

#: The fixed 32-bit TL-UL target template's declared bus input roles/widths
#: (``ihdl``-style target port shape used by ``target.tl-ul``/1).
TLUL_TARGET_BUS_INPUTS = (
    ('a_valid', 1), ('a_opcode', 3), ('a_param', 3), ('a_size', 2),
    ('a_source', 8), ('a_address', 32), ('a_mask', 4), ('a_data', 32),
    ('a_user', 23), ('d_ready', 1),
)
TLUL_TARGET_BUS_INPUT_WIDTHS = tuple(sorted(width for _, width in TLUL_TARGET_BUS_INPUTS))
TLUL_TARGET_BUS_INPUT_ROLES = frozenset(role for role, _ in TLUL_TARGET_BUS_INPUTS)
TLUL_TARGET_BUS_INPUT_WIDTH_BY_ROLE = dict(TLUL_TARGET_BUS_INPUTS)

#: The only artifact kind whose local bus port is adapter-consumed.
TLUL_TARGET_ARTIFACT_KIND = 'tlul_register_observe'
TLUL_PROTOCOL = 'tl-ul'


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _require(condition, reason) -> None:
    if not condition:
        raise ValueError('declared-target-bus-pin-' + reason)


def pin_identity(*, component, port, bit_offset, width,
                 direction=TARGET_BUS_PIN_DIRECTION) -> str:
    """Digest one declared target bus-input pin (no graph path involved)."""
    if (type(component) is not str or not component
            or type(port) is not str or not port
            or type(bit_offset) is not int or bit_offset != 0
            or type(width) is not int or width < 1
            or direction != TARGET_BUS_PIN_DIRECTION):
        raise ValueError('declared-target-bus-pin-identity')
    return sha256(_canonical({
        'schema_version': SCHEMA_VERSION, 'direction': direction,
        'component': component, 'port': port,
        'bit_offset': bit_offset, 'width': width})).hexdigest()


def declaration(*, component, endpoint_id, port, bit_offset, width):
    """Return one canonical declaration document for a target bus input."""
    identity = pin_identity(component=component, port=port,
                            bit_offset=bit_offset, width=width)
    return {'schema_version': SCHEMA_VERSION,
            'direction': TARGET_BUS_PIN_DIRECTION,
            'component': component, 'endpoint_id': endpoint_id,
            'port': port, 'bit_offset': bit_offset, 'width': width,
            'identity': identity}


def declaration_identity(document) -> str:
    """Recompute a declaration's identity and refuse a forged document."""
    _require(type(document) is dict and set(document) == {
        'schema_version', 'direction', 'component', 'endpoint_id', 'port',
        'bit_offset', 'width', 'identity'}, 'document')
    _require(document['schema_version'] == SCHEMA_VERSION, 'schema')
    _require(document['direction'] == TARGET_BUS_PIN_DIRECTION, 'direction')
    _require(type(document['endpoint_id']) is str and document['endpoint_id'], 'endpoint')
    identity = pin_identity(component=document['component'], port=document['port'],
                            bit_offset=document['bit_offset'], width=document['width'])
    _require(document['identity'] == identity, 'identity')
    return identity


# -- admission side ---------------------------------------------------------
def tlul_declared_bus_pins(sources, *, direction, target_component,
                           target_endpoint):
    """Authenticate a compiled path's pin set as one TL-UL target bus input set.

    Every source must be a fuzzable ``external_pin`` declared on the target's
    own MMIO endpoint, at bit 0, with its whole physical width.  Together their
    widths must be exactly the TL-UL target template's declared input set, so a
    subset, a superset or an unrelated pin is refused instead of tolerated.
    """
    _require(isinstance(sources, (list, tuple)) and sources, 'sources-required')
    _require(direction == TARGET_BUS_PIN_DIRECTION, 'direction')
    _require(type(target_component) is str and target_component, 'target-component')
    _require(type(target_endpoint) is str and target_endpoint, 'target-endpoint')
    rows, ports, widths = [], set(), []
    for source in sources:
        _require(type(source) is dict and source.get('kind') == 'external_pin', 'source-kind')
        _require(source.get('component') == target_component, 'source-component')
        _require(source.get('endpoint_id') == target_endpoint, 'source-endpoint')
        port, width = source.get('port'), source.get('width')
        offset, mask = source.get('bit_offset'), source.get('mask')
        _require(type(port) is str and port and port not in ports, 'source-port')
        _require(type(width) is int and width in TLUL_TARGET_BUS_INPUT_WIDTH_BY_ROLE.values(),
                 'source-width')
        _require(type(offset) is int and offset == 0, 'source-offset')
        _require(type(mask) is int and mask == (1 << width) - 1, 'source-mask')
        _require(source.get('origin') in (None, 'fuzzable'), 'source-origin')
        _require(source.get('range') is None, 'source-range')
        _require(source.get('alignment') in (None, 1), 'source-alignment')
        _require(source.get('register') is None and source.get('field') is None,
                 'source-register')
        ports.add(port); widths.append(width)
        rows.append(source)
    _require(tuple(sorted(widths)) == TLUL_TARGET_BUS_INPUT_WIDTHS, 'source-width-set')
    return tuple(dict(source=source,
        declaration=declaration(component=target_component,
            endpoint_id=target_endpoint, port=source['port'],
            bit_offset=source['bit_offset'], width=source['width']))
        for source in rows)


# -- runtime side -----------------------------------------------------------
def artifact_declared_bus_pins(artifact):
    """Return the artifact's own declared target bus-input pins (or none).

    The authority is the generated artifact: its ``base_protocol_trace`` names
    the adapted target endpoint, ``adapted_endpoint_ids`` says that endpoint is
    consumed by the generated adapter, and the plan's port rows carry the real
    physical input names/roles/widths.  Only the fixed TL-UL target artifact
    kind is recognized; other targets return ``()`` and keep whatever host path
    they already declare.
    """
    document = getattr(artifact, 'runtime_document', None)
    if type(document) is not dict or document.get('kind') != TLUL_TARGET_ARTIFACT_KIND:
        return ()
    trace = document.get('base_protocol_trace')
    adapted = document.get('adapted_endpoint_ids')
    if type(trace) is not dict or trace.get('protocol') != TLUL_PROTOCOL:
        raise ValueError('declared-target-bus-pin-trace')
    endpoint_id = trace.get('endpoint_id')
    if (type(endpoint_id) is not str or not endpoint_id
            or type(adapted) is not list or endpoint_id not in adapted):
        raise ValueError('declared-target-bus-pin-endpoint')
    plan = document.get('plan')
    ports = plan.get('ports') if type(plan) is dict else None
    if type(ports) is not list:
        raise ValueError('declared-target-bus-pin-plan')
    rows, roles = [], set()
    for row in ports:
        if (type(row) is not dict or row.get('endpoint_id') != endpoint_id
                or row.get('direction') != 'input'):
            continue
        role = row.get('role')
        width = TLUL_TARGET_BUS_INPUT_WIDTH_BY_ROLE.get(role)
        bits = row.get('bits')
        if (width is None or role in roles
                or type(row.get('port')) is not str or not row['port']
                or type(row.get('instance_id')) is not str or not row['instance_id']
                or type(bits) is not dict or bits.get('lo') != 0
                or bits.get('hi') != width - 1 or row.get('port_width') != width):
            raise ValueError('declared-target-bus-pin-port-shape')
        roles.add(role)
        rows.append(declaration(component=row['instance_id'],
            endpoint_id=endpoint_id, port=row['port'],
            bit_offset=0, width=width))
    if roles != TLUL_TARGET_BUS_INPUT_ROLES:
        raise ValueError('declared-target-bus-pin-role-set')
    return tuple(sorted(rows, key=lambda row: row['identity']))


def bus_pin_registry(artifacts):
    """Return ``(by_identity, by_field)`` for every declared target bus pin.

    ``artifacts`` is an iterable of ``(component, artifact)`` pairs; the
    component of a declaration is the artifact's own instance id, so a registry
    entry can only name the artifact that really declares it.
    """
    by_identity, by_field = {}, {}
    for _component, artifact in artifacts:
        for document in artifact_declared_bus_pins(artifact):
            identity = declaration_identity(document)
            key = (document['component'], document['port'],
                   document['bit_offset'], document['width'])
            if identity in by_identity or key in by_field:
                raise ValueError('declared-target-bus-pin-duplicate')
            by_identity[identity] = document
            by_field[key] = document
    return by_identity, by_field
