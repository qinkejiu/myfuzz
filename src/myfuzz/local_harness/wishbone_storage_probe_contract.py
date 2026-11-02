"""Code-owned prospective Wishbone storage wiring; never a live evidence issuer.

G8.1 first row: the reviewed ``zipcpu-wbuart.setup.storage.v1`` ``SETUP`` word
at word index 0.  This module renders a *document*: the source storage
expression and the nine bound target-interface roles are documented, never
measured.  No port here is a hierarchy proof, and nothing here issues reset,
version or source authority.

Selection is a request tuning record of kind ``wishbone_storage_observations``
with exactly ``{endpoint_id, contract_id, register}``.  The endpoint must be
the single Wishbone ``mmio_slave`` of the plan and the register must be the
closed source row; both refusals happen before any port is emitted.
"""
from __future__ import annotations

import hashlib
import json

from .wishbone_storage_source_contract import (
    select_wishbone_storage_source_contract)

SCHEMA_VERSION = 'wishbone_storage_probe.v1'
SCOPE = 'generated_expression_source_mapped'
SAMPLE_GROUP = 'storage_probes'
SELECTION_KIND = 'wishbone_storage_observations'
#: Request roles in the exact declaration order of ``target.wishbone``.
ROLES = ('cyc', 'stb', 'we', 'adr', 'sel', 'dat_w', 'ack', 'dat_r', 'stall')
#: Every authority flag a prospective document must keep false.
AUTHORITY_FLAGS = ('authority', 'hierarchy_verified', 'native_verified',
                   'reset_authority', 'source_authority', 'version_authority')
DOCUMENT_KEYS = frozenset({
    'schema_version', 'scope', 'selection', 'source_contract', 'sample_group',
    'ports', 'protocol', 'address_units', *AUTHORITY_FLAGS, 'digest'})
PORT_KEYS = frozenset({'name', 'direction', 'width', 'role', 'expression'})
SELECTION_KEYS = frozenset({'endpoint_id', 'contract_id', 'register'})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def wishbone_storage_probe_digest(document):
    """Re-derive the probe digest over the exact document body.

    The digest covers every field except ``digest`` itself, including the
    embedded reviewed source contract; a caller cannot re-hash a mutated port
    or contract into a valid probe.
    """
    if type(document) is not dict:
        raise ValueError('wishbone-storage-probe-shape')
    body = {key: value for key, value in document.items() if key != 'digest'}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


def wishbone_probe_widths(source_contract):
    """Port widths of the eleven ``storage_*`` outputs, in emitted order.

    The address width comes from the reviewed row's word-index decode (2 for
    wbuart) and the data/lane widths from the reviewed register width.  These
    are the only widths this row can emit; a renderer may not widen them.
    """
    if type(source_contract) is not dict:
        raise ValueError('wishbone-storage-probe-source-contract')
    register = source_contract.get('register')
    decode = source_contract.get('decode')
    if not isinstance(register, dict) or not isinstance(decode, dict):
        raise ValueError('wishbone-storage-probe-source-contract')
    width = register.get('width')
    address = decode.get('address_width')
    if (type(width) is not int or width != 32 or type(address) is not int
            or not 1 <= address <= 12):
        raise ValueError('wishbone-storage-probe-source-contract')
    widths = {'value': width, 'reset': 1}
    for role in ROLES:
        widths[role] = {'cyc': 1, 'stb': 1, 'we': 1, 'adr': address,
                        'sel': width // 8, 'dat_w': width, 'ack': 1,
                        'dat_r': width, 'stall': 1}[role]
    return {'storage_' + role: width for role, width in widths.items()}


def wishbone_storage_probe_selection(plan):
    """Return the single validated selector row, or ``None`` when not opted in."""
    try:
        rows = [record.document() for record in plan.request.tuning.records
                if record.kind == SELECTION_KIND]
    except (AttributeError, TypeError) as error:
        raise ValueError('wishbone-storage-probe-selection-unsupported') from error
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError('wishbone-storage-probe-selection-unsupported')
    row = rows[0]
    if (type(row) is not dict or set(row) != SELECTION_KEYS
            or any(type(row[key]) is not str or not row[key]
                   for key in SELECTION_KEYS)):
        raise ValueError('wishbone-storage-probe-selection-unsupported')
    endpoints = [endpoint for endpoint in plan.binding.endpoints
                 if endpoint.protocol is not None]
    if (len(endpoints) != 1
            or tuple(endpoints[0].protocol) != ('wishbone', 'classic')
            or endpoints[0].function != 'mmio_slave'
            or row['endpoint_id'] != endpoints[0].endpoint_id):
        raise ValueError('wishbone-storage-probe-endpoint-unsupported')
    return row


def _wire_layout(wires, widths):
    """Map each declared role to its bound runtime wire and documented width.

    The renderer passes ``{role: wire_name}`` from the same closed shape it
    validated; a ``(wire_name, width)`` pair is also accepted so a renderer
    that already knows the width can state it -- but it must agree with the
    reviewed row, never widen it.
    """
    if type(wires) is not dict or set(wires) != set(ROLES):
        raise ValueError('wishbone-storage-probe-wire-shape')
    layout = {}
    for role in ROLES:
        value = wires[role]
        if type(value) is str and value:
            layout[role] = (value, widths['storage_' + role])
        elif (type(value) is tuple and len(value) == 2
                and type(value[0]) is str and value[0]
                and type(value[1]) is int):
            if value[1] != widths['storage_' + role]:
                raise ValueError('wishbone-storage-probe-wire-width')
            layout[role] = value
        else:
            raise ValueError('wishbone-storage-probe-wire-shape')
    return layout


def generate_wishbone_storage_probe(plan, wires, *, base_dir):
    """Return a closed prospective probe document, or ``None`` when not opted in."""
    selection = wishbone_storage_probe_selection(plan)
    if selection is None:
        return None
    source = select_wishbone_storage_source_contract(
        plan.profile, base_dir=base_dir,
        selection={key: selection[key] for key in ('contract_id', 'register')})
    widths = wishbone_probe_widths(source)
    layout = _wire_layout(wires, widths)
    expressions = [
        ('value', widths['storage_value'],
         source['storage_expression']['expression']),
        ('reset', widths['storage_reset'], 'reset')]
    expressions += [(role, widths['storage_' + role], layout[role][0])
                    for role in ROLES]
    ports = [dict(name='storage_' + role, direction='output', width=width,
                  role=role, expression=expression)
             for role, width, expression in expressions]
    document = dict(
        schema_version=SCHEMA_VERSION, scope=SCOPE, selection=selection,
        source_contract=source, sample_group=SAMPLE_GROUP, ports=ports,
        protocol=['wishbone', 'classic'], address_units='word',
        authority=False, hierarchy_verified=False, native_verified=False,
        reset_authority=False, source_authority=False, version_authority=False)
    document['digest'] = wishbone_storage_probe_digest(document)
    return document


def validate_wishbone_storage_probe_sample(sample, ports):
    """Validate shape only: a dict cannot establish measured hardware origin."""
    group = sample.get(SAMPLE_GROUP) if isinstance(sample, dict) else None
    if (not isinstance(group, dict) or type(ports) is not list
            or any(not isinstance(row, dict) or row.get('name') is None
                   for row in ports)
            or set(group) != {row['name'] for row in ports}):
        raise ValueError('wishbone-storage-probe-sample-shape')
    for row in ports:
        value = group[row['name']]
        if type(value) is not int or not 0 <= value < 1 << row['width']:
            raise ValueError('wishbone-storage-probe-sample-width')
    return dict(group)
