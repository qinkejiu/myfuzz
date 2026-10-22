"""Closed static DMA declarations, independent of live Runner route identities.

An intent records declared endpoints and policy. Its digest identifies only
that declaration; binding actual runtime objects remains a separate operation.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType


DMA_MASTER_ROUTE_INTENT_SCHEMA = 'dma_master_route_intent.v1'
_ROW_KEYS = frozenset((
    'route_id', 'initiator_instance', 'initiator_endpoint_id', 'target',
    'base', 'size', 'operation', 'permissions', 'byte_enable',
    'readable_offsets', 'writable_offsets', 'accepted_write_values',
))
_TARGET_KEYS = {
    'persistent_memory': frozenset(('kind', 'component_instance', 'resource_id')),
    'peripheral': frozenset(('kind', 'component_instance', 'device_id', 'endpoint_id')),
}


def _fail(pointer: str, message: str) -> None:
    raise ValueError(f'{pointer}: {message}')


def _closed_keys(document: Mapping, expected: frozenset | set,
                 pointer: str) -> None:
    if set(document) != expected:
        missing = sorted(expected - set(document))
        unknown = sorted((repr(key) for key in set(document) - expected))
        _fail(pointer, f'invalid closed schema (missing={missing}, unknown={unknown})')


def _name(value: object, pointer: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value:
        _fail(pointer, 'expected a nonempty unpadded name')


def _tuple(value: object, pointer: str) -> tuple:
    if type(value) not in (tuple, list):
        _fail(pointer, 'expected an ordered tuple or list')
    return tuple(value)


def _validate_values(values: tuple[int, ...] | range, pointer: str) -> None:
    if isinstance(values, range):
        # Compute endpoints arithmetically, including descending and empty
        # ranges. Never enumerate a policy that can cover all 32-bit words.
        if values.step > 0 and values.start < values.stop:
            last = values.start + ((values.stop - 1 - values.start)
                                   // values.step) * values.step
            bounds = (values.start, last)
        elif values.step < 0 and values.start > values.stop:
            last = values.start - ((values.start - 1 - values.stop)
                                   // -values.step) * -values.step
            bounds = (values.start, last)
        else:
            bounds = ()
        if bounds and not (0 <= min(bounds) and max(bounds) <= 0xffffffff):
            _fail(pointer, 'accepted write values must be unsigned 32-bit integers')
    elif any(type(value) is not int or not 0 <= value <= 0xffffffff
             for value in values):
        _fail(pointer, 'accepted write values must be unsigned 32-bit integers')


def _values_document(values: tuple[int, ...] | range) -> dict:
    if isinstance(values, range):
        return {'kind': 'range', 'start': values.start,
                'stop': values.stop, 'step': values.step}
    return {'kind': 'values', 'values': list(values)}


def _parse_values(document: object, pointer: str) -> tuple[int, ...] | range:
    if type(document) is not dict:
        _fail(pointer, 'expected an accepted-values object')
    kind = document.get('kind')
    if kind == 'values':
        _closed_keys(document, {'kind', 'values'}, pointer)
        if type(document['values']) is not list:
            _fail(f'{pointer}/values', 'expected a JSON array')
        return tuple(document['values'])
    if kind == 'range':
        _closed_keys(document, {'kind', 'start', 'stop', 'step'}, pointer)
        for key in ('start', 'stop', 'step'):
            if type(document[key]) is not int:
                _fail(f'{pointer}/{key}', 'expected an exact integer')
        if document['step'] == 0:
            _fail(f'{pointer}/step', 'range step must be nonzero')
        return range(document['start'], document['stop'], document['step'])
    _fail(f'{pointer}/kind', 'expected values or range')


@dataclass(frozen=True)
class DmaMasterRouteIntent:
    """One immutable declaration with no graph, session, or live identity."""

    route_id: str
    initiator_instance: str
    initiator_endpoint_id: str
    target: Mapping[str, str]
    base: int
    size: int
    operation: str
    permissions: tuple[str, ...]
    byte_enable: int
    readable_offsets: tuple[int, ...]
    writable_offsets: tuple[int, ...]
    accepted_write_values: tuple[int, ...] | range

    def __post_init__(self) -> None:
        for key in ('route_id', 'initiator_instance', 'initiator_endpoint_id'):
            _name(getattr(self, key), f'/{key}')
        if not isinstance(self.target, Mapping):
            _fail('/target', 'expected a target object')
        kind = self.target.get('kind')
        if type(kind) is not str or kind not in _TARGET_KEYS:
            _fail('/target/kind', 'expected peripheral or persistent_memory')
        _closed_keys(self.target, _TARGET_KEYS[kind], '/target')
        for key, value in self.target.items():
            _name(value, f'/target/{key}')
        object.__setattr__(self, 'target', MappingProxyType(dict(self.target)))

        if type(self.base) is not int or self.base < 0 or self.base % 4:
            _fail('/base', 'expected a nonnegative word-aligned integer')
        if type(self.size) is not int or self.size < 4 or self.size % 4:
            _fail('/size', 'expected a positive word-aligned aperture')
        if self.base + self.size > 1 << 64:
            _fail('/size', 'aperture exceeds the unsigned 64-bit address space')
        if self.operation not in ('read', 'write'):
            _fail('/operation', 'expected read or write')
        permissions = _tuple(self.permissions, '/permissions')
        if (any(value not in ('read', 'write') for value in permissions)
                or len(set(permissions)) != len(permissions)
                or tuple(sorted(permissions)) != permissions
                or self.operation not in permissions):
            _fail('/permissions', 'expected unique sorted permissions including operation')
        object.__setattr__(self, 'permissions', permissions)
        if type(self.byte_enable) is not int or self.byte_enable != 15:
            _fail('/byte_enable', 'only full-word byte enable 15 is supported')

        for key in ('readable_offsets', 'writable_offsets'):
            offsets = _tuple(getattr(self, key), f'/{key}')
            if (any(type(value) is not int or value < 0 or value % 4
                    or value + 4 > self.size for value in offsets)
                    or len(set(offsets)) != len(offsets)):
                _fail(f'/{key}', 'expected unique aligned word offsets inside aperture')
            object.__setattr__(self, key, offsets)

        values = self.accepted_write_values
        if not isinstance(values, range):
            values = _tuple(values, '/accepted_write_values')
        _validate_values(values, '/accepted_write_values')
        object.__setattr__(self, 'accepted_write_values', values)
        if kind == 'peripheral':
            expected = tuple(permission for permission, offsets in (
                ('read', self.readable_offsets), ('write', self.writable_offsets))
                if offsets)
            if permissions != expected:
                _fail('/permissions', 'peripheral permissions must match declared offsets')
            if bool(self.writable_offsets) != bool(values):
                _fail('/accepted_write_values', 'write policy must match writable offsets')
        elif (self.readable_offsets or self.writable_offsets
                or type(values) is not tuple or values):
            _fail('/target', 'persistent memory requires empty peripheral offsets and values')

    def document(self) -> dict:
        """Return a fresh JSON row; derived hashes are not input fields."""
        return {
            'route_id': self.route_id,
            'initiator_instance': self.initiator_instance,
            'initiator_endpoint_id': self.initiator_endpoint_id,
            'target': dict(self.target),
            'base': self.base, 'size': self.size,
            'operation': self.operation,
            'permissions': list(self.permissions),
            'byte_enable': self.byte_enable,
            'readable_offsets': list(self.readable_offsets),
            'writable_offsets': list(self.writable_offsets),
            'accepted_write_values': _values_document(self.accepted_write_values),
        }

    @property
    def identity_sha256(self) -> str:
        """Digest the exact static policy, preserving value order and range bounds."""
        canonical = json.dumps(self.document(), sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, allow_nan=False).encode('utf-8')
        return hashlib.sha256(canonical).hexdigest()


def _canonical_routes(routes: Iterable[DmaMasterRouteIntent],
                      pointer: str) -> tuple[DmaMasterRouteIntent, ...]:
    try:
        result = tuple(routes)
    except TypeError as error:
        raise ValueError(f'{pointer}: expected an iterable of route intents') from error
    if not result or any(not isinstance(route, DmaMasterRouteIntent) for route in result):
        _fail(pointer, 'expected nonempty route intents')
    if len({route.route_id for route in result}) != len(result):
        _fail(pointer, 'duplicate route_id')
    return tuple(sorted(result, key=lambda route: route.route_id))


def parse_dma_master_route_intents(document: object, *,
        pointer: str = '/dma_master_routes') -> tuple[DmaMasterRouteIntent, ...]:
    """Parse a closed v1 wrapper, reporting declaration errors at JSON pointers."""
    if type(document) is not dict:
        _fail(pointer, 'expected a DMA master route intent object')
    _closed_keys(document, {'schema_version', 'routes'}, pointer)
    if document['schema_version'] != DMA_MASTER_ROUTE_INTENT_SCHEMA:
        _fail(f'{pointer}/schema_version', 'unsupported DMA master route intent schema')
    if type(document['routes']) is not list:
        _fail(f'{pointer}/routes', 'expected a JSON array')
    routes = []
    for index, row in enumerate(document['routes']):
        row_pointer = f'{pointer}/routes/{index}'
        if type(row) is not dict:
            _fail(row_pointer, 'expected a route object')
        _closed_keys(row, _ROW_KEYS, row_pointer)
        if type(row['target']) is not dict:
            _fail(f'{row_pointer}/target', 'expected a target object')
        for key in ('permissions', 'readable_offsets', 'writable_offsets'):
            if type(row[key]) is not list:
                _fail(f'{row_pointer}/{key}', 'expected a JSON array')
        values = _parse_values(row['accepted_write_values'],
                               f'{row_pointer}/accepted_write_values')
        try:
            route = DmaMasterRouteIntent(**{**row, 'accepted_write_values': values})
        except ValueError as error:
            raise ValueError(f'{row_pointer}{error}') from error
        routes.append(route)
    return _canonical_routes(routes, f'{pointer}/routes')


def dma_master_route_intents_document(routes: Iterable[DmaMasterRouteIntent]) -> dict:
    """Build the canonical closed wrapper, refusing empty or duplicate routes."""
    canonical = _canonical_routes(routes, '/dma_master_routes/routes')
    return {'schema_version': DMA_MASTER_ROUTE_INTENT_SCHEMA,
            'routes': [route.document() for route in canonical]}
