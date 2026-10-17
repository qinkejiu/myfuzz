"""P7-I2: compile per-bit physical input ownership from D3, never from a family.

The runner needs one answer for every physical environment input of a
composition: is the bit a fuzzable *source*, a *bound* delivery target, or a
declared *fixed* constant?  The shipped runtime families answer that question
with a hand-written ownership table, and a generic path must not copy it: the
plan's rule is that no input may be borrowed from a family when the compiled
document does not declare it (``ownership-source-uncompiled``).

This module compiles that answer from declarations only.

**D3 is the authority for every bit it speaks about.**

* an ``external_pin`` source in one executable path's ``sources[]`` becomes a
  ``source`` owner, and its ``(component, port, bit_offset, width)`` must name a
  real *non-protocol* ABI input of a loaded artifact (``compiled-source-not-abi-input``);
* a ``cpu_irq_input`` in one executable path's ``bound_inputs[]`` becomes a
  ``bound`` owner on the CPU's declared interrupt-entry field, and its producer
  must be the paired ``ip_irq`` declaration from the same path (a real IP output,
  never a random source) (``compiled-bound-producer-unknown``);
* ``ip_read_response``/``ip_register_commit`` describe protocol channels, not
  environment pins; they are recorded as declarations to be consumed by the
  compiled executor and never become bit owners of a protocol pin.

**Everything else must be declared fixed.**  Every remaining non-protocol ABI
input bit must be given a constant by ``wiring_contract.fixed_inputs[]``, else
the compilation refuses with ``compiled-input-owner-undeclared``.  Overlaps
between fixed/source/bound owners, a range outside its input, a width mismatch
and an overlapping declaration are all named refusals; nothing is guessed.

**A named family's declaration is a claim to be checked, not a source.**
:func:`compile_compiled_ownership` accepts ``declared`` owners (the legacy
family's table, already mapped to physical ports).  A declared bit that D3 also
declares must agree with D3 or the compilation refuses
(``compiled-owner-declaration-conflict``); a declared bit D3 does not declare may
fill the map, but it is tagged ``declared-not-compiled`` - it is *never* given
``d3-source``/``d3-bound`` provenance, and the existing admission refuses it by
name (``ownership-source-uncompiled`` / ``ownership-bound-producer-not-admitted``)
before any runtime starts.  The compiled map therefore never silently borrows a
family value; it only keeps it visible so the refusal can name it.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json

from myfuzz.scenario.ownership import (InputField, InputOwner, OwnershipMap,
                                       compile_ownership)

#: Version of this module's audit document.
COMPILED_OWNERSHIP_SCHEMA = 'compiled_ownership.v1'

#: Provenance of one owner bit, published in the audit document.
ORIGIN_D3_SOURCE = 'd3-source'
ORIGIN_D3_BOUND = 'd3-bound'
ORIGIN_FIXED = 'fixed'
ORIGIN_DECLARED = 'declared-not-compiled'

#: D3 source kinds that name a real physical environment input.
PHYSICAL_SOURCE_KINDS = frozenset(('external_pin',))
#: D3 bound-input kinds this module can place on a physical input end.
PHYSICAL_BOUND_KINDS = frozenset(('cpu_irq_input',))
#: D3 bound-input kinds that describe a protocol channel rather than a pin.
PROTOCOL_BOUND_KINDS = frozenset(('ip_read_response', 'ip_register_commit',
                                  'ip_irq'))

_SOURCE = 'source'
_BOUND = 'bound'
_FIXED = 'fixed'


class CompiledOwnershipRefused(ValueError):
    """The compiled ownership cannot be built. ``code`` names the fact."""

    def __init__(self, code: str, pointer: str = '', detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code, pointer='', detail=None):
    raise CompiledOwnershipRefused(code, pointer, detail)


@dataclass(frozen=True)
class CompiledOwnership:
    """One compiled ownership map plus the audit document that produced it."""

    ownership: OwnershipMap
    document: dict


@dataclass(frozen=True)
class _Input:
    """One non-protocol ABI input of one loaded artifact.

    ``width`` and every owner offset are expressed in the *declared role's* bit
    space: the exposed ABI spans of one physical port, concatenated in ascending
    physical order.  Most ports are one span starting at bit 0, so local and
    physical offsets agree; CV32E40P's ``irq_i`` is the counter-example (only its
    MEI bit 11 is exposed, so the declared input is one bit wide).  The absolute
    spans stay in ``physical_bits`` for the audit document.
    """

    component_id: str
    endpoint_id: str
    port: str
    role: str
    width: int
    physical_bits: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class _Owner:
    """One owner record with the provenance this module gives it."""

    component_id: str
    port: str
    bit_offset: int
    width: int
    kind: str
    producer_ref: str
    origin: str

    def input_owner(self) -> InputOwner:
        return InputOwner(self.component_id, self.port, self.bit_offset,
                          self.width, self.kind, self.producer_ref)


def _text(value, pointer, code):
    if type(value) is not str or not value:
        _refuse(code, pointer, {'value': value})
    return value


def _integer(value, pointer, code, *, minimum=0):
    if type(value) is not int or value < minimum:
        _refuse(code, pointer, {'value': value})
    return value


def _constant_name(value: int) -> str:
    """The declared constant as an audit identity, matching the family wording."""
    return 'constant_zero' if value == 0 else f'constant_0x{value:x}'


# ---------------------------------------------------------------------------
# the physical input surface of the loaded artifacts
# ---------------------------------------------------------------------------

def _surface(artifacts) -> dict[tuple[str, str], _Input]:
    """Every non-protocol input of every loaded artifact, keyed by port.

    A protocol input pin (OBI/APB/AHB/AXI field) belongs to the protocol
    producer/consumer that the wiring contract already binds; it is not an
    environment input and cannot be given a mutation owner.  Everything else -
    ``external_pins`` inputs and the CPU's interrupt-entry pin - is the physical
    input surface this map must classify completely.
    """
    if not isinstance(artifacts, Mapping) or not artifacts:
        _refuse('compiled-ownership-artifacts-required', '/artifacts',
                {'requires': 'the loaded D2 artifacts of this composition'})
    surface: dict[tuple[str, str], _Input] = {}
    for instance in sorted(artifacts):
        artifact = artifacts[instance]
        structural = getattr(artifact, 'structural', None)
        abi = getattr(structural, 'abi_document', None)
        plan = getattr(artifact, 'plan', None)
        profile = getattr(plan, 'profile', None)
        if (not isinstance(abi, Mapping) or profile is None
                or not isinstance(getattr(profile, 'endpoints', None), Sequence)):
            _refuse('compiled-ownership-artifact-invalid',
                    f'/artifacts/{instance}',
                    {'requires': 'a loaded artifact with a structural ABI and '
                                 'its declared component profile'})
        endpoints = {row.endpoint_id: row for row in profile.endpoints}
        spans: dict[str, dict] = {}
        for row in abi.get('ports', ()):
            if not isinstance(row, Mapping) or row.get('direction') != 'input':
                continue
            port = _text(row.get('physical_port'),
                         f'/artifacts/{instance}/abi/ports', 'compiled-input-port')
            width = _integer(row.get('width'),
                             f'/artifacts/{instance}/abi/ports/{port}',
                             'compiled-input-width', minimum=1)
            low = _integer(row.get('bit_lo'),
                           f'/artifacts/{instance}/abi/ports/{port}',
                           'compiled-input-bit-range')
            high = _integer(row.get('bit_hi'),
                            f'/artifacts/{instance}/abi/ports/{port}',
                            'compiled-input-bit-range')
            if high - low + 1 != width:
                _refuse('compiled-input-width-mismatch',
                        f'/artifacts/{instance}/abi/ports/{port}',
                        {'bit_lo': low, 'bit_hi': high, 'width': width})
            endpoint_id = row.get('endpoint_id')
            endpoint = endpoints.get(endpoint_id)
            if endpoint is not None and endpoint.protocol is not None:
                # A declared protocol field is the protocol's, not the environment's.
                continue
            if endpoint is None:
                _refuse('compiled-input-endpoint-undeclared',
                        f'/artifacts/{instance}/abi/ports/{port}',
                        {'endpoint_id': endpoint_id, 'port': port,
                         'declared_endpoints': sorted(endpoints)})
            declared = spans.get(port)
            if declared is not None and declared['endpoint_id'] != endpoint_id:
                _refuse('compiled-input-port-ambiguous',
                        f'/artifacts/{instance}/abi/ports/{port}',
                        {'endpoint_ids': sorted({declared['endpoint_id'],
                                                 endpoint_id})})
            record = spans.setdefault(port, {'endpoint_id': endpoint_id,
                                             'role': row.get('role'),
                                             'spans': []})
            record['spans'].append((low, high))
        for port, record in sorted(spans.items()):
            surface[(instance, port)] = _physical_input(instance, port, record)
    return surface


def _physical_input(instance, port, record) -> _Input:
    """One field per physical port, from its exposed (non-overlapping) spans.

    The ABI exposes only the roles a declaration binds: a 32-bit interrupt vector
    whose single bound role is bit 11 yields a one-bit input.  Overlapping spans
    are an illegal declaration (one physical bit would belong to two roles), so
    they are refused rather than merged.
    """
    spans = sorted(record['spans'])
    covered: set[int] = set()
    for low, high in spans:
        for bit in range(low, high + 1):
            if bit in covered:
                _refuse('compiled-input-port-overlap',
                        f'/artifacts/{instance}/abi/ports/{port}',
                        {'bit': bit, 'spans': [list(row) for row in spans]})
            covered.add(bit)
    width = sum(high - low + 1 for low, high in spans)
    return _Input(instance, record['endpoint_id'], port, record['role'], width,
                  tuple(spans))


# ---------------------------------------------------------------------------
# placement
# ---------------------------------------------------------------------------

class _Builder:
    """Place exclusive owners on the compiled input surface, or refuse by name."""

    def __init__(self, surface: Mapping[tuple[str, str], _Input]):
        self.surface = dict(surface)
        self.bits: dict[tuple[str, str], list[_Owner | None]] = {
            key: [None] * row.width for key, row in self.surface.items()}
        self.owners: list[_Owner] = []

    def place(self, owner: _Owner, *, pointer: str) -> None:
        key = (owner.component_id, owner.port)
        if key not in self.bits:
            code = ('compiled-source-not-abi-input'
                    if owner.origin == ORIGIN_D3_SOURCE
                    else 'compiled-bound-producer-unknown'
                    if owner.origin == ORIGIN_D3_BOUND
                    else 'compiled-fixed-input-not-abi-input')
            _refuse(code, pointer,
                    {'component_id': owner.component_id, 'port': owner.port,
                     'declared_inputs': [
                         {'component_id': component, 'port': port,
                          'width': row.width}
                         for (component, port), row in sorted(self.surface.items())]})
        row = self.surface[key]
        if (owner.bit_offset < 0 or owner.width < 1
                or owner.bit_offset + owner.width > row.width):
            code = ('compiled-source-not-abi-input'
                    if owner.origin == ORIGIN_D3_SOURCE
                    else 'compiled-bound-producer-unknown'
                    if owner.origin == ORIGIN_D3_BOUND
                    else 'compiled-fixed-input-range-exceeds-input')
            _refuse(code, pointer,
                    {'bit_offset': owner.bit_offset, 'width': owner.width,
                     'input_width': row.width,
                     'component_id': owner.component_id, 'port': owner.port})
        field_bits = self.bits[key]
        conflicts = []
        restated = True
        for bit in range(owner.bit_offset, owner.bit_offset + owner.width):
            current = field_bits[bit]
            if current is None:
                restated = False
                continue
            if (current.kind, current.producer_ref, current.bit_offset,
                    current.width) == (owner.kind, owner.producer_ref,
                                       owner.bit_offset, owner.width):
                continue  # the *exact* same declaration restated is not a conflict
            restated = False
            conflicts.append({'bit': bit, 'owner': current.producer_ref,
                              'declared': owner.producer_ref})
        if restated:
            # Every bit is already owned by this exact declaration; adding it
            # again would be a duplicate record, not a second owner.
            return
        if conflicts:
            if owner.origin == ORIGIN_DECLARED:
                _refuse('compiled-owner-declaration-conflict', pointer,
                        {'component_id': owner.component_id, 'port': owner.port,
                         'conflicts': conflicts,
                         'requires': 'a named family declaration may only cover '
                                     'bits the compiled document does not declare; '
                                     'a conflicting family value is never reused'})
            _refuse('compiled-input-owner-conflict', pointer,
                    {'component_id': owner.component_id, 'port': owner.port,
                     'conflicts': conflicts})
        for bit in range(owner.bit_offset, owner.bit_offset + owner.width):
            field_bits[bit] = owner
        self.owners.append(owner)

    def unowned(self) -> list[dict]:
        rows = []
        sentinel = object()
        for (component, port), field_bits in sorted(self.bits.items()):
            ranges = []
            start = None
            for bit in range(len(field_bits) + 1):
                # A non-None sentinel closes a run that reaches the last bit.
                owner = (field_bits[bit] if bit < len(field_bits) else sentinel)
                if owner is None and start is None:
                    start = bit
                elif owner is not None and start is not None:
                    ranges.append([start, bit - 1])
                    start = None
            if ranges:
                rows.append({'component_id': component, 'port': port,
                             'unowned_bits': ranges})
        return rows

    def ownership(self, fields: tuple[InputField, ...]) -> OwnershipMap:
        owners = tuple(sorted((row.input_owner() for row in self.owners),
                              key=lambda row: (row.component_id, row.port,
                                               row.bit_offset, row.width,
                                               row.kind, row.producer_ref)))
        try:
            return compile_ownership(fields, owners)
        except ValueError as error:  # pragma: no cover - defensive: rules above
            _refuse('compiled-ownership-invalid', '/inputs',
                    {'error': str(error)})


# ---------------------------------------------------------------------------
# D3 declarations
# ---------------------------------------------------------------------------

def _d3_sources(compiled: Mapping) -> tuple[list[dict], list[dict]]:
    """Physical and non-physical fuzzable sources of the compiled document."""
    physical = []
    streams = []
    for path in compiled.get('paths', ()):
        if path.get('status') != 'executable':
            continue
        for source in path.get('sources', ()):
            kind = source.get('kind')
            record = {'path_id': path.get('path_id'),
                      'flow_id': path.get('flow_id'),
                      'source_id': source.get('source_id'),
                      'kind': kind,
                      'component_id': source.get('component'),
                      'port': source.get('port'),
                      'bit_offset': source.get('bit_offset'),
                      'width': source.get('width'),
                      'mask': source.get('mask')}
            if kind in PHYSICAL_SOURCE_KINDS:
                physical.append(record)
            else:
                streams.append(record)
    return physical, streams


def _d3_bound(compiled: Mapping) -> tuple[list[dict], list[dict], list[dict]]:
    """``(physical, protocol, producer)`` bound inputs of the compiled document.

    A ``cpu_irq_input`` is paired with the ``ip_irq`` declaration of the same
    path: the producer end names the real IP output that owns the delivery.
    """
    physical = []
    protocol = []
    producers = []
    for path in compiled.get('paths', ()):
        if path.get('status') != 'executable':
            continue
        rows = list(path.get('bound_inputs', ()))
        irq = next((row for row in rows if row.get('kind') == 'ip_irq'), None)
        for row in rows:
            record = {'path_id': path.get('path_id'),
                      'flow_id': path.get('flow_id'),
                      'input_id': row.get('input_id'),
                      'kind': row.get('kind'),
                      'component_id': row.get('component'),
                      'endpoint_id': row.get('endpoint_id')}
            kind = row.get('kind')
            if kind in PHYSICAL_BOUND_KINDS:
                record['producer_input_id'] = None if irq is None else irq.get('input_id')
                physical.append(record)
            elif kind in PROTOCOL_BOUND_KINDS:
                protocol.append(record)
                if kind == 'ip_irq':
                    producers.append(record)
            else:
                _refuse('compiled-bound-producer-unknown',
                        f'/paths/{path.get("flow_id")}/bound_inputs',
                        {'input_id': row.get('input_id'), 'kind': kind,
                         'declared_kinds': sorted(PHYSICAL_BOUND_KINDS
                                                  | PROTOCOL_BOUND_KINDS)})
    return physical, protocol, producers


def _cpu_irq_input(row: Mapping, surface, artifacts) -> tuple[str, _Input]:
    """Resolve one ``cpu_irq_input`` declaration to its physical ABI input."""
    component = row.get('component_id')
    artifact = artifacts.get(component)
    plan = getattr(artifact, 'plan', None)
    profile = getattr(plan, 'profile', None)
    contract = getattr(profile, 'cpu', None)
    if contract is None or contract.irq_entry_endpoint != row.get('endpoint_id'):
        _refuse('compiled-bound-producer-unknown', '/bound_inputs',
                {'input_id': row.get('input_id'),
                 'requires': 'the CPU profile must declare this endpoint as its '
                             'irq_entry_endpoint'})
    endpoint = next((item for item in profile.endpoints
                     if item.endpoint_id == contract.irq_entry_endpoint), None)
    fields = [item for item in endpoint.fields
              if item.role == contract.irq_entry_role] if endpoint else []
    if len(fields) != 1 or not fields[0].aliases:
        _refuse('compiled-bound-producer-unknown', '/bound_inputs',
                {'input_id': row.get('input_id'),
                 'requires': 'one declared physical alias for the CPU IRQ input'})
    port = fields[0].aliases[0]
    key = (component, port)
    if key not in surface or surface[key].width != 1:
        _refuse('compiled-bound-producer-unknown', '/bound_inputs',
                {'input_id': row.get('input_id'), 'port': port,
                 'requires': 'a one-bit non-protocol ABI input at that alias'})
    if row.get('producer_input_id') is None:
        _refuse('compiled-bound-producer-unknown', '/bound_inputs',
                {'input_id': row.get('input_id'),
                 'requires': 'the paired ip_irq declaration that names the real '
                             'IP output; a bound end is never a random source'})
    return row['producer_input_id'], surface[key]


# ---------------------------------------------------------------------------
# declared fixed constants and named-family claims
# ---------------------------------------------------------------------------

def _fixed_inputs(raw) -> list[dict]:
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        _refuse('fixed-input-declaration-required', '/fixed_inputs')
    rows = []
    for index, item in enumerate(raw):
        pointer = f'/fixed_inputs/{index}'
        if not isinstance(item, Mapping):
            _refuse('fixed-input-declaration-required', pointer)
        instance = _text(item.get('component_instance'),
                         pointer + '/component_instance',
                         'fixed-input-component-undeclared')
        port = _text(item.get('port'), pointer + '/port',
                     'fixed-input-port-undeclared')
        offset = _integer(item.get('bit_offset', 0), pointer + '/bit_offset',
                          'fixed-input-range-invalid')
        width = _integer(item.get('width'), pointer + '/width',
                         'fixed-input-width-invalid', minimum=1)
        constant = _integer(item.get('constant'), pointer + '/constant',
                            'fixed-input-constant-invalid')
        if constant >= 1 << width:
            _refuse('fixed-input-constant-exceeds-width', pointer + '/constant',
                    {'constant': constant, 'width': width})
        rows.append({'component_instance': instance, 'port': port,
                     'bit_offset': offset, 'width': width, 'constant': constant,
                     'pointer': pointer})
    return rows


def _declared_claims(declared):
    """The legacy family's ownership table as validated ``(field, owner)`` claims."""
    if not declared:
        return []
    if (not isinstance(declared, (tuple, list)) or len(declared) != 2
            or not isinstance(declared[0], tuple)
            or not isinstance(declared[1], tuple)):
        _refuse('declared-ownership-invalid', '/declared',
                {'requires': '(fields, owners) tuples of InputField/InputOwner'})
    fields, owners = declared
    by_key = {}
    for field in fields:
        if not isinstance(field, InputField):
            _refuse('declared-ownership-invalid', '/declared/fields')
        key = (field.component_id, field.port)
        if key in by_key:
            _refuse('declared-ownership-invalid', '/declared/fields',
                    {'component_id': field.component_id, 'port': field.port,
                     'reason': 'duplicate declared input field'})
        by_key[key] = field
    claims = []
    for owner in owners:
        if not isinstance(owner, InputOwner):
            _refuse('declared-ownership-invalid', '/declared/owners')
        field = by_key.get((owner.component_id, owner.port))
        if field is None:
            _refuse('declared-owner-not-physical',
                    f'/declared/owners/{owner.component_id}/{owner.port}',
                    {'requires': 'a declared input field for every declared owner'})
        claims.append({'field': field, 'owner': owner})
    return claims


# ---------------------------------------------------------------------------
# the compiler
# ---------------------------------------------------------------------------

def compile_compiled_ownership(*, artifacts, compiled, fixed_inputs=(),
                               declared=()) -> CompiledOwnership:
    """Compile one composition's per-bit input ownership from D3 declarations.

    Returns the :class:`OwnershipMap` the runner and the artifact admission
    consume, plus the ``compiled_ownership.v1`` audit document.  Every rule is a
    named refusal; an input this function cannot classify is never defaulted.
    """
    if (not isinstance(compiled, Mapping)
            or compiled.get('schema_version') != 'compiled_paths.v1'):
        _refuse('compiled-paths-document-required', '/compiled',
                {'requires': 'a compiled_paths.v1 document'})
    surface = _surface(artifacts)
    builder = _Builder(surface)

    physical_sources, stream_sources = _d3_sources(compiled)
    for source in physical_sources:
        pointer = f'/paths/{source["flow_id"]}/sources/{source["source_id"]}'
        width = _integer(source.get('width'), pointer, 'compiled-source-not-abi-input',
                         minimum=1)
        offset = _integer(source.get('bit_offset'), pointer,
                          'compiled-source-not-abi-input')
        mask = source.get('mask')
        if mask is not None and mask != (1 << width) - 1:
            _refuse('compiled-source-mask-not-representable', pointer,
                    {'source_id': source['source_id'], 'mask': mask,
                     'width': width})
        builder.place(_Owner(source['component_id'], source['port'], offset,
                             width, _SOURCE, source['source_id'],
                             ORIGIN_D3_SOURCE), pointer=pointer)

    physical_bound, protocol_bound, producer_bound = _d3_bound(compiled)
    for row in physical_bound:
        pointer = f'/paths/{row["flow_id"]}/bound_inputs/{row["input_id"]}'
        producer, field = _cpu_irq_input(row, surface, artifacts)
        builder.place(_Owner(field.component_id, field.port, 0, field.width,
                             _BOUND, producer, ORIGIN_D3_BOUND), pointer=pointer)

    fixed_records = []
    for record in _fixed_inputs(fixed_inputs):
        pointer = record.pop('pointer')
        key = (record['component_instance'], record['port'])
        if key not in surface:
            _refuse('fixed-input-port-not-physical', pointer,
                    {'component_id': key[0], 'port': key[1],
                     'declared_inputs': sorted(f'{c}.{p}' for c, p in surface)})
        builder.place(_Owner(key[0], key[1], record['bit_offset'],
                             record['width'], _FIXED,
                             _constant_name(record['constant']), ORIGIN_FIXED),
                      pointer=pointer)
        fixed_records.append(record)

    claims = []
    for claim in _declared_claims(declared):
        field, owner = claim['field'], claim['owner']
        pointer = f'/declared/{owner.component_id}/{owner.port}/' \
                  f'bit{owner.bit_offset}'
        compiled_field = surface.get((field.component_id, field.port))
        if compiled_field is None or compiled_field.width != field.width:
            _refuse('declared-owner-not-physical', pointer,
                    {'component_id': field.component_id, 'port': field.port,
                     'declared_width': field.width,
                     'requires': 'a declared non-protocol ABI input of that width'})
        builder.place(_Owner(owner.component_id, owner.port, owner.bit_offset,
                             owner.width, owner.kind, owner.producer_ref,
                             ORIGIN_DECLARED), pointer=pointer)
        claims.append(owner)

    unowned = builder.unowned()
    if unowned:
        first = unowned[0]
        _refuse('compiled-input-owner-undeclared',
                f'/inputs/{first["component_id"]}/{first["port"]}',
                {'unowned_inputs': unowned,
                 'requires': 'a D3 external_pin source, a D3 cpu_irq_input bound '
                             'end, or a wiring_contract.fixed_inputs constant for '
                             'every non-protocol input bit; no owner is borrowed '
                             'from a component name or a family table'})

    fields = tuple(InputField(row.component_id, row.port, row.width)
                   for _, row in sorted(surface.items()))
    ownership = builder.ownership(fields)
    document = {
        'schema_version': COMPILED_OWNERSHIP_SCHEMA,
        'status': 'compiled',
        'inputs': [{'component_id': row.component_id,
                    'port': row.port, 'width': row.width,
                    'endpoint_id': row.endpoint_id, 'role': row.role,
                    'physical_bits': [list(span)
                                      for span in row.physical_bits]}
                   for _, row in sorted(surface.items())],
        'owners': [{'component_id': owner.component_id, 'port': owner.port,
                    'bit_offset': owner.bit_offset, 'width': owner.width,
                    'kind': owner.kind, 'producer_ref': owner.producer_ref,
                    'origin': owner.origin}
                   for owner in sorted(builder.owners,
                                       key=lambda row: (row.component_id, row.port,
                                                        row.bit_offset, row.width,
                                                        row.kind,
                                                        row.producer_ref))],
        'd3_sources': physical_sources,
        'd3_stream_sources': stream_sources,
        'd3_protocol_bound': protocol_bound,
        'd3_producer_bound': producer_bound,
        'fixed_inputs': fixed_records,
        'declared_claims': [{'component_id': row.component_id, 'port': row.port,
                             'bit_offset': row.bit_offset, 'width': row.width,
                             'kind': row.kind, 'producer_ref': row.producer_ref,
                             'origin': ORIGIN_DECLARED} for row in claims],
        'inputs_sha256': 'sha256:' + hashlib.sha256(
            json.dumps([{'component_id': row.component_id, 'port': row.port,
                         'width': row.width}
                        for _, row in sorted(surface.items())],
                       sort_keys=True, separators=(',', ':')).encode('utf-8')
        ).hexdigest(),
        'compiled_paths_sha256': 'sha256:' + hashlib.sha256(
            json.dumps(compiled, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False).encode('utf-8')
        ).hexdigest(),
        'not_claimed': [
            'rtl_operational',
            'cross_component_accepted',
            'coverage_guided_searched',
            'bug_confirmed',
            'fixed_inputs are declared constants, not proof that a runner drove '
            'them onto RTL',
            'a declared-not-compiled owner is a refused claim, not an accepted '
            'source or binding',
        ],
    }
    return CompiledOwnership(ownership=ownership, document=document)


def compiled_owner_document(*, artifacts, compiled, fixed_inputs=(),
                            declared=()) -> dict:
    """The ``compiled_ownership.v1`` audit document of one compilation."""
    return compile_compiled_ownership(
        artifacts=artifacts, compiled=compiled, fixed_inputs=fixed_inputs,
        declared=declared).document


__all__ = [
    'COMPILED_OWNERSHIP_SCHEMA', 'ORIGIN_D3_BOUND', 'ORIGIN_D3_SOURCE',
    'ORIGIN_DECLARED', 'ORIGIN_FIXED', 'PHYSICAL_BOUND_KINDS',
    'PHYSICAL_SOURCE_KINDS', 'PROTOCOL_BOUND_KINDS', 'CompiledOwnership',
    'CompiledOwnershipRefused', 'compile_compiled_ownership',
    'compiled_owner_document',
]
