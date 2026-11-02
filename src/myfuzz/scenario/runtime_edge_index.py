"""Cached attribution of actual events to explicitly selected route candidates.

The index requires the session compilation document, including its prepared
``declaration``. Matches identify declared transport scope, not RTL causality.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType

from .ledger import TransactionKey
from .runtime_path_contract import (
    PreparedRuntimePathContract, RuntimePathContract, _canonical, _digest)


@dataclass(frozen=True)
class DmaMasterRouteMatch:
    """Immutable declaration identity returned for one exact DMA route query.

    This is a route lookup result only. The supplied key still has to be joined
    to the accepted native request, target operation, and response by the
    caller before it can describe a runtime transfer.
    """

    route_sha256: str
    edge_key: tuple[int, int]
    source_node_id: str
    target_node_id: str
    path_id: str
    initiator_component: str
    endpoint_id: str
    target_kind: str
    target_component: str
    target_id: str
    base: int
    size: int
    operation: str
    address: int
    byte_enable: int
    transaction_key: TransactionKey
    target_identity_sha256: str


@dataclass(frozen=True)
class DmaMasterRouteIdentity:
    """Detached immutable route declaration selected by one prepared path."""

    route_sha256: str
    edge_key: tuple[int, int]
    source_node_id: str
    target_node_id: str
    path_id: str
    initiator_component: str
    endpoint_id: str
    endpoint_identity_sha256: str
    target_kind: str
    target_component: str
    target_id: str
    base: int
    size: int
    operation: str
    permissions: tuple[str, ...]
    byte_enable: int
    readable_offsets: tuple[int, ...]
    writable_offsets: tuple[int, ...]
    accepted_write_values_kind: str | None
    accepted_write_values: tuple[int, ...]
    target_identity_sha256: str


def _row(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError('invalid nested topology row schema')


def _text(value):
    if type(value) is not str or not value or value.strip() != value:
        raise ValueError('invalid topology identifier')


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('invalid topology integer')


def _validate_topology(topology, nodes, selected_node_ids, sources):
    """Validate snapshot facts once; Python bool/int equality is insufficient."""
    expected_components = sorted({nodes[node_id].component for node_id in selected_node_ids})
    if topology['components'] != expected_components:
        raise ValueError('compiled components differ from selected nodes')
    for component in topology['components']:
        _text(component)
    binding_fields = {'source_component', 'source_port', 'target_component', 'target_port',
                      'source_bit_offset', 'target_bit_offset', 'width'}
    for binding in topology['bindings']:
        _row(binding, binding_fields)
        for key in ('source_component', 'source_port', 'target_component', 'target_port'):
            _text(binding[key])
        for key in ('source_bit_offset', 'target_bit_offset'):
            _integer(binding[key])
        _integer(binding['width'], 1)
    owners_by_endpoint = {}
    owner_fields = {'component_id', 'port', 'bit_offset', 'width', 'kind', 'producer_ref'}
    physical_endpoints = {(nodes[node_id].component, nodes[node_id].port)
                          for node_id in selected_node_ids if nodes[node_id].kind == 'physical'}
    for row in topology['ownership_inputs']:
        _row(row, {'component', 'port', 'owners'})
        _text(row['component'])
        _text(row['port'])
        endpoint = row['component'], row['port']
        if endpoint in owners_by_endpoint or endpoint not in physical_endpoints:
            raise ValueError('duplicate or unrelated topology input')
        owners = row['owners']
        if type(owners) is not list or not owners:
            raise ValueError('invalid topology bit owner array')
        for bit, owner in enumerate(owners):
            _row(owner, owner_fields)
            for key in ('component_id', 'port', 'kind', 'producer_ref'):
                _text(owner[key])
            _integer(owner['bit_offset'])
            _integer(owner['width'], 1)
            start, limit = owner['bit_offset'], owner['bit_offset'] + owner['width']
            if (owner['kind'] not in ('source', 'bound', 'fixed')
                    or (owner['component_id'], owner['port']) != endpoint
                    or not start <= bit < limit <= len(owners)
                    or any(other != owner for other in owners[start:limit])):
                raise ValueError('topology owner identity/range facts mismatch')
        owners_by_endpoint[endpoint] = owners
    for source in sources:
        if source.kind != 'source':
            continue
        owners = owners_by_endpoint.get((source.component, source.port), ())
        limit = source.bit_offset + source.width
        selected = owners[source.bit_offset:limit]
        if (len(owners) < limit or any(owner['kind'] != 'source' for owner in selected)
                or len({owner['producer_ref'] for owner in selected}) != 1):
            raise ValueError('selected actual source ownership mismatch')
    router_ids = set()
    for router in topology['routers']:
        _row(router, {'initiator', 'windows'})
        _text(router['initiator'])
        if router['initiator'] in router_ids or router['initiator'] not in expected_components:
            raise ValueError('duplicate or unrelated topology router')
        router_ids.add(router['initiator'])
        if type(router['windows']) is not list:
            raise ValueError('invalid topology windows')
        device_ids = set()
        intervals = []
        for window in router['windows']:
            _row(window, {'device_id', 'base', 'size'})
            _text(window['device_id'])
            _integer(window['base'])
            _integer(window['size'], 4)
            if window['device_id'] in device_ids or window['base'] + window['size'] > 1 << 64:
                raise ValueError('invalid topology window identity/aperture')
            device_ids.add(window['device_id'])
            intervals.append((window['base'], window['base'] + window['size']))
        intervals.sort()
        if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
            raise ValueError('overlapping topology windows')
    resource_components = set()
    for resource in topology['resources']:
        _row(resource, {'component', 'regions'})
        _text(resource['component'])
        if resource['component'] in resource_components or resource['component'] not in expected_components:
            raise ValueError('duplicate or unrelated topology resource')
        resource_components.add(resource['component'])
        if type(resource['regions']) is not list:
            raise ValueError('invalid topology regions')
        memory_ids = set()
        intervals = []
        for region in resource['regions']:
            _row(region, {'memory_id', 'base', 'size', 'aliases', 'readable', 'writable'})
            _text(region['memory_id'])
            _integer(region['base'])
            _integer(region['size'], 1)
            if (region['memory_id'] in memory_ids or type(region['aliases']) is not list
                    or type(region['readable']) is not bool or type(region['writable']) is not bool):
                raise ValueError('invalid topology resource identity/permissions')
            memory_ids.add(region['memory_id'])
            for base in (region['base'], *region['aliases']):
                _integer(base)
                if base + region['size'] > 1 << 64:
                    raise ValueError('topology memory window exceeds bounds')
                intervals.append((base, base + region['size']))
        intervals.sort()
        if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:])):
            raise ValueError('overlapping topology memory windows')


def _validate_dma_route_rows(route_documents, topology_rows, edges, nodes, topology):
    """Join v2 route snapshots to exact selected typed edges and topology facts."""
    if type(route_documents) is not list or not route_documents:
        raise ValueError('v2 runtime edge index requires declared DMA routes')
    if type(topology_rows) is not list or len(topology_rows) != len(route_documents):
        raise ValueError('compiled DMA route snapshot count differs from contract')
    routes_by_key = {}
    for route in route_documents:
        if type(route) is not dict or 'identity_sha256' not in route:
            raise ValueError('invalid canonical DMA route declaration')
        key = route.get('rule_index'), route.get('prerequisite_index')
        if (type(key[0]) is not int or key[0] < 0 or type(key[1]) is not int
                or key[1] < 0 or key in routes_by_key):
            raise ValueError('duplicate or invalid DMA route edge key')
        selected = edges.get(key)
        if selected is None:
            raise ValueError('DMA route edge is absent from selected prepared paths')
        edge = selected[0]
        if (edge.get('kind') != 'DMA_MASTER_TRANSFER'
                or edge.get('prerequisite') != route.get('source_node_id')
                or edge.get('target') != route.get('target_node_id')):
            raise ValueError('DMA route does not match selected typed graph edge')
        declaration = route
        source = nodes[edge['prerequisite']]
        target = nodes[edge['target']]
        if declaration.get('operation') == 'read':
            expected = (source.component, target.component)
        elif declaration.get('operation') == 'write':
            expected = (target.component, source.component)
        else:
            raise ValueError('invalid DMA route operation')
        if (declaration.get('target_component'),
                declaration.get('initiator_component')) != expected:
            raise ValueError('DMA route endpoint components differ from typed edge direction')
        routes_by_key[key] = (route, selected[1])

    seen = set()
    row_keys = []
    for row in topology_rows:
        if type(row) is not dict or set(row) != {
                'route', 'route_sha256', 'endpoint', 'target'}:
            raise ValueError('invalid compiled DMA route topology row')
        route = row['route']
        if type(route) is not dict:
            raise ValueError('invalid compiled DMA route document')
        key = route.get('rule_index'), route.get('prerequisite_index')
        declaration_and_paths = routes_by_key.get(key)
        if declaration_and_paths is None or key in seen:
            raise ValueError('unknown or ambiguous compiled DMA route row')
        declaration, _path_ids = declaration_and_paths
        if (_canonical(row['route']) != _canonical(declaration)
                or row['route_sha256'] != declaration['identity_sha256']):
            raise ValueError('compiled DMA route differs from contract declaration')
        endpoint = row['endpoint']
        if (type(endpoint) is not dict or set(endpoint) != {
                'component', 'endpoint_id', 'identity_sha256'}
                or any(type(endpoint[name]) is not str or not endpoint[name]
                       for name in ('component', 'endpoint_id', 'identity_sha256'))
                or endpoint != {
                    'component': declaration['initiator_component'],
                    'endpoint_id': declaration['endpoint_id'],
                    'identity_sha256': declaration['endpoint_identity_sha256']}):
            raise ValueError('compiled DMA endpoint identity differs from route declaration')
        target = row['target']
        target_fields = {'kind', 'component', 'id', 'base', 'size', 'permissions',
                         'identity_sha256', 'identity'}
        if type(target) is not dict or set(target) != target_fields:
            raise ValueError('invalid compiled DMA target topology row')
        if (any(type(target[name]) is not str or not target[name]
                for name in ('kind', 'component', 'id', 'identity_sha256'))
                or type(target['base']) is not int or type(target['size']) is not int
                or type(target['permissions']) is not list
                or any(type(value) is not str for value in target['permissions'])):
            raise ValueError('invalid compiled DMA target field types')
        expected_target = {
            'kind': declaration['target_kind'],
            'component': declaration['target_component'],
            'id': declaration['target_id'],
            'base': declaration['base'],
            'size': declaration['size'],
            'permissions': declaration['permissions'],
            'identity_sha256': declaration['target_identity_sha256'],
        }
        if any(target.get(name) != value for name, value in expected_target.items()):
            raise ValueError('compiled DMA target identity/aperture differs from route declaration')
        if (type(target['identity']) is not dict
                or _digest(target['identity']) != target['identity_sha256']):
            raise ValueError('compiled DMA target full identity digest mismatch')
        if target['kind'] == 'persistent_memory':
            if set(target['identity']) != {
                    'schema_version', 'memory_configuration', 'resource'}:
                raise ValueError('invalid DMA RAM target identity schema')
            resources = [row for row in topology['resources']
                         if row['component'] == target['component']]
            memory_configuration = target['identity'].get('memory_configuration')
            resource_identity = target['identity'].get('resource')
            if (target['identity'].get('schema_version')
                    != 'persistent_memory_route_target.v1'
                    or type(memory_configuration) is not dict
                    or set(memory_configuration) != {'regions', 'initialization_seed',
                        'initialization_algorithm', 'max_initialized_bytes'}
                    or type(memory_configuration['initialization_seed']) is not int
                    or type(memory_configuration['initialization_algorithm']) is not str
                    or type(memory_configuration['max_initialized_bytes']) is not int
                    or len(resources) != 1
                    or type(memory_configuration['regions']) is not list
                    or _canonical(memory_configuration['regions'])
                       != _canonical(resources[0]['regions'])):
                raise ValueError('DMA RAM target is absent from compiled resource topology')
            regions = [region for region in resources[0]['regions']
                       if region['memory_id'] == target['id']]
            if len(regions) != 1:
                raise ValueError('DMA RAM target resource identity is ambiguous')
            region = regions[0]
            bases = (region['base'], *region['aliases'])
            if target['base'] not in bases or target['size'] != region['size']:
                raise ValueError('DMA RAM aperture is outside its selected region aliases')
            if (type(resource_identity) is not dict
                    or set(resource_identity) != {'memory_id', 'base', 'size',
                        'canonical_base', 'is_alias', 'readable', 'writable', 'region'}
                    or type(resource_identity.get('base')) is not int
                    or type(resource_identity.get('size')) is not int
                    or type(resource_identity.get('canonical_base')) is not int
                    or type(resource_identity.get('is_alias')) is not bool
                    or type(resource_identity.get('readable')) is not bool
                    or type(resource_identity.get('writable')) is not bool
                    or resource_identity.get('memory_id') != target['id']
                    or resource_identity.get('base') != target['base']
                    or resource_identity.get('size') != target['size']
                    or resource_identity.get('canonical_base') != region['base']
                    or resource_identity.get('is_alias') is not (target['base'] != region['base'])
                    or _canonical(resource_identity.get('region')) != _canonical(region)):
                raise ValueError('DMA RAM selected aperture/resource identity mismatch')
            permissions = set(target['permissions'])
            expected_permissions = tuple(sorted(
                (['read'] if region['readable'] else [])
                + (['write'] if region['writable'] else [])))
            if (resource_identity.get('readable') is not region['readable']
                    or resource_identity.get('writable') is not region['writable']
                    or not permissions.issubset(expected_permissions)
                    or declaration.get('operation') not in expected_permissions):
                raise ValueError('DMA RAM permissions exceed its selected region')
        elif target['kind'] == 'peripheral':
            identity = target['identity']
            if set(identity) != {'schema_version', 'component', 'base', 'size',
                    'writable_offsets', 'accepted_write_values', 'readable_offsets',
                    'byte_enable', 'endpoint_identity'}:
                raise ValueError('invalid DMA peripheral target identity schema')
            accepted_values = declaration['accepted_write_values']
            expected_window = {
                'component': target['component'], 'base': target['base'],
                'size': target['size'],
                'writable_offsets': declaration['writable_offsets'],
                'accepted_write_values': accepted_values,
                'readable_offsets': declaration['readable_offsets'],
                'byte_enable': declaration['byte_enable'],
            }
            expected_permissions = tuple(sorted(
                (['read'] if declaration['readable_offsets'] else [])
                + (['write'] if declaration['writable_offsets'] else [])))
            if (identity.get('schema_version') != 'dma_master_target_window.v2'
                    or type(identity.get('base')) is not int
                    or type(identity.get('size')) is not int
                    or type(identity.get('byte_enable')) is not int
                    or type(identity.get('writable_offsets')) is not list
                    or type(identity.get('readable_offsets')) is not list
                    or any(type(value) is not int for value in
                           (*identity['writable_offsets'], *identity['readable_offsets']))
                    or type(identity.get('endpoint_identity')) is not dict
                    or _canonical({name: identity.get(name)
                                   for name in expected_window})
                       != _canonical(expected_window)
                    or tuple(declaration['permissions']) != expected_permissions):
                raise ValueError('DMA peripheral window identity differs from route declaration')
            if (('read' in declaration['permissions']
                    and not declaration['readable_offsets'])
                    or ('write' in declaration['permissions']
                        and not declaration['writable_offsets'])):
                raise ValueError('DMA peripheral permissions lack matching window offsets')
        elif target['kind'] != 'peripheral':
            raise ValueError('unknown DMA route target kind')
        seen.add(key)
        row_keys.append(key)
    if seen != set(routes_by_key):
        raise ValueError('compiled DMA route snapshot omitted a declared route')
    if row_keys != sorted(row_keys):
        raise ValueError('compiled DMA route snapshots are not in canonical edge order')


def _transaction_key(value, initiator_component):
    """Parse a live key or its detached journal form without bool/int aliasing."""
    if type(value) is TransactionKey:
        key = value
    elif type(value) is dict and set(value) == {
            'execution_id', 'testcase_id', 'source_component', 'source_epoch',
            'channel_id', 'source_sequence'}:
        if (any(type(value[name]) is not str or not value[name]
                or value[name].strip() != value[name]
                for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                or type(value['source_epoch']) is not int or value['source_epoch'] < 0
                or type(value['source_sequence']) is not int or value['source_sequence'] < 0):
            return None
        try:
            key = TransactionKey(value['execution_id'], value['testcase_id'],
                value['source_component'], value['source_epoch'], value['channel_id'],
                value['source_sequence'])
        except (TypeError, ValueError):
            return None
    else:
        return None
    if (any(type(getattr(key, name)) is not str or not getattr(key, name)
            or getattr(key, name).strip() != getattr(key, name)
            for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
            or type(key.source_epoch) is not int or key.source_epoch < 0
            or type(key.source_sequence) is not int or key.source_sequence < 0):
        return None
    return key if key.source_component == initiator_component else None


class RuntimeEdgeIndex:
    def __setattr__(self,name,value):
        if (name == '_source_owners' and hasattr(self, name)
                or name == '_dma_routes_by_key'
                and isinstance(getattr(self, name, None), MappingProxyType)):
            raise AttributeError('compiled runtime route authority is immutable')
        object.__setattr__(self,name,value)

    def __delattr__(self,name):
        if (name == '_source_owners'
                or name == '_dma_routes_by_key'
                and isinstance(getattr(self, name, None), MappingProxyType)):
            raise AttributeError('compiled runtime route authority is immutable')
        object.__delattr__(self,name)

    def __init__(self, compiled_document: dict, contract_document: dict,
                 *, prepared=None):
        try:
            self._initialize(compiled_document, contract_document,
                             prepared=prepared)
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            raise ValueError('invalid runtime edge index documents') from exc

    def _initialize(self, compiled, contract_document, *, prepared=None):
        required = {'schema_version', 'graph_sha256', 'contract_sha256',
                    'topology_sha256', 'topology', 'paths', 'proof_scope',
                    'runtime_causality_verified', 'resource_versions_verified', 'declaration'}
        if (type(compiled) is not dict or set(compiled) != required
                or compiled['schema_version'] not in (
                    'runtime_path_compilation.v1', 'runtime_path_compilation.v2')
                or compiled['proof_scope'] != 'selected_declared_topology_only'
                or compiled['runtime_causality_verified'] is not False
                or compiled['resource_versions_verified'] is not False
                or type(compiled['paths']) is not list or not compiled['paths']):
            raise ValueError('runtime edge index requires session compilation with declaration')
        contract = RuntimePathContract.from_document(contract_document)
        if prepared is None:
            prepared = PreparedRuntimePathContract.from_document(
                compiled['declaration'])
        elif (type(prepared) is not PreparedRuntimePathContract
                or _canonical(prepared.document())
                   != _canonical(compiled['declaration'])):
            raise ValueError(
                'existing prepared runtime paths differ from compilation declaration')
        else:
            prepared.validate_cached_identity()
        version_pair = (compiled['schema_version'], contract_document.get('schema_version'),
                        compiled['declaration'].get('schema_version'))
        if version_pair not in (
                ('runtime_path_compilation.v1', 'runtime_path_contract.v1',
                 'prepared_runtime_paths.v1'),
                ('runtime_path_compilation.v2', 'runtime_path_contract.v2',
                 'prepared_runtime_paths.v2')):
            raise ValueError('runtime edge index schema versions are not a matching pair')
        has_dma_routes = bool(contract.document().get('dma_master_routes', ()))
        if (has_dma_routes != (compiled['schema_version'] == 'runtime_path_compilation.v2')
                or has_dma_routes != (compiled['declaration']['schema_version']
                                      == 'prepared_runtime_paths.v2')):
            raise ValueError('runtime edge index v2 schema requires declared DMA routes')
        if (compiled['graph_sha256'] != contract.graph_sha256
                or compiled['contract_sha256'] != contract.identity_sha256
                or prepared.contract.document() != contract.document()
                or compiled['topology_sha256'] != _digest(compiled['topology'])):
            raise ValueError('runtime edge index graph/contract/topology digest mismatch')
        selections = {row['path_id']: row for row in prepared.document()['selections']}
        edges = {}
        seen_paths = set()
        selected_node_ids, selected_sources = set(), []
        for row in compiled['paths']:
            if type(row) is not dict or set(row) != {'direction', 'path_id', 'target'}:
                raise ValueError('invalid compiled selected path')
            path_id = row['path_id']
            selection = selections.get(path_id)
            if (path_id in seen_paths or selection is None
                    or row != {key: selection[key] for key in row}):
                raise ValueError('compiled path differs from prepared declaration')
            seen_paths.add(path_id)
            selected_node_ids.update((selection['target'], *selection['source_ids']))
            selected_sources.extend(prepared.source_nodes_for(path_id))
            for edge in selection['edges']:
                selected_node_ids.update((edge['prerequisite'], edge['target']))
                key = edge['rule_index'], edge['prerequisite_index']
                if key not in edges:
                    edges[key] = (edge, [])
                edges[key][1].append(path_id)
        nodes = {node.node_id: node for node in contract.nodes}
        declarations = {edge.key: edge for edge in contract.edges}
        topology = compiled['topology']
        topology_fields = {'components', 'bindings', 'ownership_inputs', 'routers', 'resources'}
        if has_dma_routes:
            topology_fields.add('dma_master_routes')
        has_irq_groups=any(e.relation=='irq_delivery_group' for e in contract.edges)
        if has_irq_groups:
            topology_fields.add('irq_delivery_groups')
        if (type(topology) is not dict or set(topology) != topology_fields
                or any(type(topology[key]) is not list for key in topology)):
            raise ValueError('invalid compiled topology')
        _validate_topology(topology, nodes, selected_node_ids, selected_sources)
        irq_groups={}
        if has_irq_groups:
            from .irq_delivery_group import IrqDeliveryGroup
            from dataclasses import asdict
            for document in topology['irq_delivery_groups']:
                group=IrqDeliveryGroup.from_document(document)
                if group.group_id in irq_groups:
                    raise ValueError('duplicate compiled IRQ delivery group')
                irq_groups[group.group_id]=group
                member_rows=[asdict(b) for b in group.member_bindings()]
                if any(topology['bindings'].count(row)!=1 for row in member_rows):
                    raise ValueError('compiled IRQ group actual member binding mismatch')
                if any((row['target_component'],row['target_port'],row['target_bit_offset']) ==
                        (group.target_component,group.target_port,group.target_bit_offset)
                        and row not in member_rows for row in topology['bindings']):
                    raise ValueError('compiled IRQ group has an unrelated additional driver')
                owners=[r['owners'] for r in topology['ownership_inputs']
                    if (r['component'],r['port'])==(group.target_component,group.target_port)]
                if (len(owners)!=1 or len(owners[0])<=group.target_bit_offset
                        or owners[0][group.target_bit_offset]['kind']!='bound'
                        or owners[0][group.target_bit_offset]['producer_ref']!=group.owner_ref):
                    raise ValueError('compiled IRQ group unique owner mismatch')
        route_documents = contract.document().get('dma_master_routes', [])
        if has_dma_routes:
            _validate_dma_route_rows(route_documents, topology['dma_master_routes'],
                                     edges, nodes, topology)
        owners_by_endpoint={(r['component'],r['port']):r['owners']
                            for r in topology['ownership_inputs']}
        source_owners={};source_owner_rows=[]
        for selection in compiled['paths']:
            for source in prepared.source_nodes_for(selection['path_id']):
                if source.kind!='source':
                    continue
                if selection['direction'] not in source.directions:
                    raise ValueError('selected source direction mismatch')
                owners=owners_by_endpoint[(source.component,source.port)]
                selected=owners[source.bit_offset:source.bit_offset+source.width]
                refs={owner['producer_ref'] for owner in selected}
                if len(selected)!=source.width or len(refs)!=1 or any(owner['kind']!='source' for owner in selected):
                    raise ValueError('selected source owner authority mismatch')
                owner_ref=next(iter(refs))
                key=(source.source_id,selection['path_id'],selection['direction'],source.component,source.port)
                value=(source.bit_offset,source.width,owner_ref)
                if key in source_owners and source_owners[key]!=value:
                    raise ValueError('conflicting selected source-owner authority')
                source_owners[key]=value
                source_owner_rows.append(dict(source_id=source.source_id,path_id=selection['path_id'],
                    direction=selection['direction'],component=source.component,port=source.port,
                    bit_lo=source.bit_offset,width=source.width,producer_ref=owner_ref))
        self._source_owners=MappingProxyType(source_owners)
        selected_declarations = [declarations[key] for key in edges if key in declarations]
        expected_routers = {edge.initiator_component for edge in selected_declarations
                            if edge.relation == 'mmio_route'}
        expected_resources = {edge.resource_component for edge in selected_declarations
                              if edge.relation == 'persistent_state'}
        expected_resources.update(route['target_component'] for route in route_documents
                                   if route['target_kind'] == 'persistent_memory')
        if ({row['initiator'] for row in topology['routers']} != expected_routers
                or {row['component'] for row in topology['resources']} != expected_resources):
            raise ValueError('compiled router/resource selection mismatch')
        self._direct, self._irq, self._mmio = {}, {}, {}
        self._irq_group_bindings = {}
        self._dma_routes_by_key = {}
        route_documents_by_key = {
            (row['rule_index'], row['prerequisite_index']): row
            for row in route_documents}
        identity_edges = []
        for key, (edge, path_ids) in sorted(edges.items()):
            declaration = declarations.get(key)
            if edge['kind'] in ('ENV_PRECONDITION', 'BASELINE_GROUPING'):
                continue
            source, target = nodes[edge['prerequisite']], nodes[edge['target']]
            if declaration is None:
                if source.component != target.component:
                    raise ValueError('selected cross-component transport lacks declaration')
                continue
            if source.component not in topology['components'] or target.component not in topology['components']:
                raise ValueError('runtime edge component missing from topology')
            candidate = {'graph_sha256': contract.graph_sha256,
                         'rule_index': key[0], 'prerequisite_index': key[1],
                         'relation': declaration.relation, 'path_ids': list(dict.fromkeys(path_ids))}
            if declaration.relation == 'irq_delivery_group':
                from .runner import Binding
                group=irq_groups.get(declaration.irq_group_id)
                if (group is None or group.identity_sha256!=declaration.irq_group_sha256
                        or source.kind!='physical' or target.kind!='physical' or source.width!=1 or target.width!=1):
                    raise ValueError('compiled IRQ group identity mismatch')
                # Contract nodes carry DUT vector bits; the installed group and
                # every runtime event address the declared host input port.
                host_target = getattr(group, 'target_bit_offset', target.bit_offset)
                binding=Binding(source.component,source.port,target.component,target.port,
                    source.width,source.bit_offset,host_target)
                if binding not in group.member_bindings():
                    raise ValueError('compiled IRQ group source membership mismatch')
                candidate.update(scope='irq_group_member',irq_group_id=group.group_id,
                    irq_group_sha256=group.identity_sha256)
                endpoint=(source.component,source.port,target.component,target.port)
                direct_key=(*endpoint,source.bit_offset,host_target,source.width)
                self._irq_group_bindings.setdefault(direct_key,[]).append(candidate)
                self._irq.setdefault(endpoint,[]).append(candidate)
            elif declaration.relation == 'direct_binding':
                if source.kind != 'physical' or target.kind != 'physical' or source.width != target.width:
                    raise ValueError('direct binding requires physical equal-width endpoints')
                # Resolve the host (port-local) target bit from the compiled
                # topology rows: contract nodes keep the DUT vector position,
                # while every binding/ownership/event here is host-local.
                candidates = [row for row in topology['bindings']
                              if row['source_component'] == source.component
                              and row['source_port'] == source.port
                              and row['target_component'] == target.component
                              and row['target_port'] == target.port
                              and row['width'] == source.width
                              and row['source_bit_offset'] == source.bit_offset]
                if len(candidates) != 1:
                    raise ValueError('compiled direct binding mismatch')
                row = candidates[0]
                host_target = row['target_bit_offset']
                binding = dict(row)
                owners = [owner_row['owners'] for owner_row in topology['ownership_inputs']
                          if (owner_row['component'], owner_row['port']) == (target.component, target.port)]
                if (len(owners) != 1 or len(owners[0]) < host_target + target.width
                        or any(owner['kind'] != 'bound'
                               or owner['producer_ref'] != f'{source.component}.{source.port}'
                               for owner in owners[0][host_target:host_target + target.width])):
                    raise ValueError('compiled direct binding ownership mismatch')
                for other in topology['bindings']:
                    if other == binding:
                        continue
                    if ((other['target_component'], other['target_port']) == (target.component, target.port)
                            and other['target_bit_offset'] < host_target + target.width
                            and host_target < other['target_bit_offset'] + other['width']):
                        raise ValueError('compiled direct binding overlapping target drivers')
                candidate['scope'] = 'binding'
                endpoint = source.component, source.port, target.component, target.port
                direct_key = (*endpoint, source.bit_offset, host_target, source.width)
                self._direct.setdefault(direct_key, []).append(candidate)
                if source.width == 1:
                    self._irq.setdefault(endpoint, []).append(candidate)
            elif declaration.relation == 'mmio_route':
                if {source.component, target.component} != {declaration.initiator_component, declaration.device_id}:
                    raise ValueError('compiled MMIO edge components mismatch')
                routers = [row for row in topology['routers'] if row['initiator'] == declaration.initiator_component]
                windows = ([row for row in routers[0]['windows'] if row['device_id'] == declaration.device_id]
                           if len(routers) == 1 else [])
                if (len(windows) != 1 or windows[0] != {'device_id': declaration.device_id,
                        'base': declaration.base, 'size': declaration.size}):
                    raise ValueError('compiled MMIO window mismatch')
                candidate['scope'] = 'route_window'
                self._mmio.setdefault((declaration.initiator_component, declaration.device_id), []).append(
                    (declaration.base, declaration.base + declaration.size, candidate))
            elif declaration.relation == 'persistent_state':
                if declaration.resource_component not in (source.component, target.component):
                    raise ValueError('persistent resource outside declared edge')
                resources = [row for row in topology['resources']
                             if row['component'] == declaration.resource_component]
                if (len(resources) != 1 or declaration.resource_id not in
                        {region['memory_id'] for region in resources[0]['regions']}):
                    raise ValueError('compiled persistent resource mismatch')
                continue
            elif declaration.relation == 'dma_master_route':
                route = route_documents_by_key.get(key)
                if route is None or edge['kind'] != 'DMA_MASTER_TRANSFER':
                    raise ValueError('selected DMA route lacks its typed route declaration')
                candidate['scope'] = 'dma_master_transfer'
                candidate['route_sha256'] = route['identity_sha256']
                candidate['edge_key'] = [key[0], key[1]]
                self._dma_routes_by_key[key] = {
                    **route, 'route_sha256': route['identity_sha256'],
                    'edge_key': [key[0], key[1]],
                    'path_ids': list(dict.fromkeys(path_ids)),
                }
            else:
                # Resource versions and causal order need separate runtime evidence.
                continue
            identity_edges.append({**candidate, 'prerequisite': edge['prerequisite'], 'target': edge['target']})
        if has_dma_routes and set(self._dma_routes_by_key) != set(route_documents_by_key):
            raise ValueError('runtime edge index selected DMA route set differs from contract')
        route_rows = {key: _canonical(value)
                      for key, value in self._dma_routes_by_key.items()}
        self._dma_routes_by_key = MappingProxyType(route_rows)
        document = {'schema_version': ('runtime_edge_index.v2' if has_dma_routes
                                       else 'runtime_edge_index.v1'),
            'graph_sha256': contract.graph_sha256, 'contract_sha256': contract.identity_sha256,
            'topology_sha256': compiled['topology_sha256'], 'compilation_sha256': _digest(compiled),
            'path_ids': [row['path_id'] for row in compiled['paths']], 'edges': identity_edges,
            'source_owner_refs': source_owner_rows,
            'runtime_causality_verified': False, 'resource_versions_verified': False}
        if has_dma_routes:
            document['dma_master_routes'] = [json.loads(self._dma_routes_by_key[key])
                for key in sorted(self._dma_routes_by_key)]
        self._document_bytes = _canonical(document)

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(self._document_bytes).hexdigest()

    def document(self) -> dict:
        return json.loads(self._document_bytes)

    def dma_master_route(self, route_sha256, rule_index, prerequisite_index):
        """Return one detached route identity only for its exact stable key."""
        if (type(route_sha256) is not str or len(route_sha256) != 64
                or any(char not in '0123456789abcdef' for char in route_sha256)
                or type(rule_index) is not int or rule_index < 0
                or type(prerequisite_index) is not int or prerequisite_index < 0):
            return None
        row = self._dma_routes_by_key.get((rule_index, prerequisite_index))
        if row is None:
            return None
        value = json.loads(row)
        return value if value['route_sha256'] == route_sha256 else None

    @staticmethod
    def _route_identity(row, path_id):
        values = row.get('accepted_write_values')
        if type(values) is dict and values.get('kind') == 'tuple':
            values_kind = 'tuple'
            values_tuple = tuple(values['values'])
        elif type(values) is dict and values.get('kind') == 'range':
            values_kind = 'range'
            values_tuple = (values['start'], values['stop'], values['step'])
        elif values is None:
            values_kind, values_tuple = None, ()
        else:
            return None
        return DmaMasterRouteIdentity(
            route_sha256=row['identity_sha256'],
            edge_key=(row['rule_index'], row['prerequisite_index']),
            source_node_id=row['source_node_id'], target_node_id=row['target_node_id'],
            path_id=path_id, initiator_component=row['initiator_component'],
            endpoint_id=row['endpoint_id'],
            endpoint_identity_sha256=row['endpoint_identity_sha256'],
            target_kind=row['target_kind'], target_component=row['target_component'],
            target_id=row['target_id'], base=row['base'], size=row['size'],
            operation=row['operation'], permissions=tuple(row['permissions']),
            byte_enable=row['byte_enable'],
            readable_offsets=tuple(row['readable_offsets']),
            writable_offsets=tuple(row['writable_offsets']),
            accepted_write_values_kind=values_kind,
            accepted_write_values=values_tuple,
            target_identity_sha256=row['target_identity_sha256'])

    def dma_master_routes_for_path(self, path_id):
        """Return immutable route declarations selected by one graph path."""
        if type(path_id) is not str or not path_id or path_id.strip() != path_id:
            return ()
        matches = []
        for key in sorted(self._dma_routes_by_key):
            row = json.loads(self._dma_routes_by_key[key])
            if path_id not in row['path_ids']:
                continue
            identity = self._route_identity(row, path_id)
            if identity is None:
                return ()
            matches.append(identity)
        return tuple(matches)

    def match_dma_master_route(self, path_id, *, initiator_component, endpoint_id,
            target_kind, target_component, target_id, base, size, operation,
            address, byte_enable, transaction_key, value=None):
        """Join a native DMA beat to one selected static route declaration.

        This only verifies that the beat identity fits the compiled route. The
        accepted request, target effect, and native response must still be
        independently joined by the caller under ``transaction_key``.
        """
        if (any(type(item) is not str or not item or item.strip() != item for item in
                (path_id, initiator_component, endpoint_id, target_kind,
                 target_component, target_id, operation))
                or any(type(item) is not int or item < 0 for item in
                       (base, size, address, byte_enable))
                or size < 1 or operation not in ('read', 'write')):
            return None
        key = _transaction_key(transaction_key, initiator_component)
        if key is None:
            return None
        matches = []
        for identity in self.dma_master_routes_for_path(path_id):
            if (identity.initiator_component != initiator_component
                    or identity.endpoint_id != endpoint_id
                    or identity.target_kind != target_kind
                    or identity.target_component != target_component
                    or identity.target_id != target_id
                    or identity.base != base or identity.size != size
                    or identity.operation != operation
                    or operation not in identity.permissions
                    or identity.byte_enable != byte_enable
                    or address < base or address + 4 > base + size
                    or address % 4):
                continue
            offset = address - base
            constraints = (identity.readable_offsets if operation == 'read'
                           else identity.writable_offsets)
            if constraints and offset not in constraints:
                continue
            if operation == 'write':
                if type(value) is not int or not 0 <= value <= 0xffffffff:
                    continue
                if identity.accepted_write_values_kind == 'tuple':
                    if (identity.accepted_write_values
                            and value not in identity.accepted_write_values):
                        continue
                elif identity.accepted_write_values_kind == 'range':
                    start, stop, step = identity.accepted_write_values
                    if step == 0 or value not in range(start, stop, step):
                        continue
            matches.append(identity)
        if len(matches) != 1:
            return None
        route = matches[0]
        return DmaMasterRouteMatch(route_sha256=route.route_sha256,
            edge_key=route.edge_key, source_node_id=route.source_node_id,
            target_node_id=route.target_node_id, path_id=path_id,
            initiator_component=route.initiator_component, endpoint_id=route.endpoint_id,
            target_kind=route.target_kind, target_component=route.target_component,
            target_id=route.target_id, base=route.base, size=route.size,
            operation=route.operation, address=address, byte_enable=byte_enable,
            transaction_key=key,
            target_identity_sha256=route.target_identity_sha256)

    def source_owner_ref(self,source_id,path_id,direction,component,port,bit_lo,width):
        """Resolve selected physical source authority, never physical consumption.

        Each query must lie wholly inside one immutable admitted graph source
        range. The result is its actual compiled topology producer reference.
        Unknown, malformed or unrelated scope returns None without mutation.
        """
        if (any(type(v) is not str or not v or v.strip()!=v
                for v in (source_id,path_id,direction,component,port))
                or type(bit_lo) is not int or bit_lo<0
                or type(width) is not int or width<1):
            return None
        authority=self._source_owners.get((source_id,path_id,direction,component,port))
        if authority is None:
            return None
        declared_lo,declared_width,owner_ref=authority
        return owner_ref if declared_lo<=bit_lo and bit_lo+width<=declared_lo+declared_width else None

    def match_event(self, event: Mapping) -> tuple[dict, ...]:
        if not isinstance(event, Mapping):
            return ()
        kind = event.get('kind')
        if kind in ('dataflow_delivery', 'source_start', 'pulse_start', 'cpu_irq_taken'):
            source, target = event.get('source'), event.get('target')
            if (not isinstance(source, (list, tuple)) or len(source) != 2
                    or not isinstance(target, (list, tuple)) or len(target) != 2
                    or any(type(value) is not str for value in (*source, *target))):
                return ()
            endpoint = (*source, *target)
            bits = tuple(event.get(key) for key in ('source_bit_offset', 'target_bit_offset', 'width'))
            if kind == 'dataflow_delivery' or any(value is not None for value in bits):
                if any(type(value) is not int for value in bits):
                    return ()
                matches = self._direct.get((*endpoint, *bits), ())
                if kind != 'dataflow_delivery':
                    matches = (*matches,*self._irq_group_bindings.get((*endpoint,*bits),()))
            else:
                matches = self._irq.get(endpoint, ())
        elif kind in ('mmio_acceptance', 'mmio_delivery'):
            transaction = event.get('source_transaction')
            address, device = event.get('address'), event.get('device_id')
            initiator = transaction.get('source_component') if isinstance(transaction, Mapping) else None
            if type(address) is not int or type(initiator) is not str or type(device) is not str:
                return ()
            matches = [candidate for base, limit, candidate in self._mmio.get((initiator, device), ())
                       if base <= address < limit]
        else:
            return ()
        return tuple(deepcopy(candidate) for candidate in matches)
