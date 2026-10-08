"""Cached attribution of actual events to explicitly selected route candidates.

The index requires the session compilation document, including its prepared
``declaration``. Matches identify declared transport scope, not RTL causality.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
from types import MappingProxyType

from .runtime_path_contract import (
    PreparedRuntimePathContract, RuntimePathContract, _canonical, _digest)


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


class RuntimeEdgeIndex:
    def __setattr__(self,name,value):
        if name=='_source_owners' and hasattr(self,name):
            raise AttributeError('compiled source-owner authority is immutable')
        object.__setattr__(self,name,value)

    def __delattr__(self,name):
        if name=='_source_owners':
            raise AttributeError('compiled source-owner authority is immutable')
        object.__delattr__(self,name)

    def __init__(self, compiled_document: dict, contract_document: dict):
        try:
            self._initialize(compiled_document, contract_document)
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            raise ValueError('invalid runtime edge index documents') from exc

    def _initialize(self, compiled, contract_document):
        required = {'schema_version', 'graph_sha256', 'contract_sha256',
                    'topology_sha256', 'topology', 'paths', 'proof_scope',
                    'runtime_causality_verified', 'resource_versions_verified', 'declaration'}
        if (type(compiled) is not dict or set(compiled) != required
                or compiled['schema_version'] != 'runtime_path_compilation.v1'
                or compiled['proof_scope'] != 'selected_declared_topology_only'
                or compiled['runtime_causality_verified'] is not False
                or compiled['resource_versions_verified'] is not False
                or type(compiled['paths']) is not list or not compiled['paths']):
            raise ValueError('runtime edge index requires session compilation with declaration')
        contract = RuntimePathContract.from_document(contract_document)
        prepared = PreparedRuntimePathContract.from_document(compiled['declaration'])
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
        if (type(topology) is not dict or set(topology) != {
                'components', 'bindings', 'ownership_inputs', 'routers', 'resources'}
                or any(type(topology[key]) is not list for key in topology)):
            raise ValueError('invalid compiled topology')
        _validate_topology(topology, nodes, selected_node_ids, selected_sources)
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
        if ({row['initiator'] for row in topology['routers']} != expected_routers
                or {row['component'] for row in topology['resources']} != expected_resources):
            raise ValueError('compiled router/resource selection mismatch')
        self._direct, self._irq, self._mmio = {}, {}, {}
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
            if declaration.relation == 'direct_binding':
                if source.kind != 'physical' or target.kind != 'physical' or source.width != target.width:
                    raise ValueError('direct binding requires physical equal-width endpoints')
                binding = {'source_component': source.component, 'source_port': source.port,
                           'target_component': target.component, 'target_port': target.port,
                           'source_bit_offset': source.bit_offset,
                           'target_bit_offset': target.bit_offset, 'width': source.width}
                if topology['bindings'].count(binding) != 1:
                    raise ValueError('compiled direct binding mismatch')
                for other in topology['bindings']:
                    if other == binding:
                        continue
                    if ((other['target_component'], other['target_port']) == (target.component, target.port)
                            and other['target_bit_offset'] < target.bit_offset + target.width
                            and target.bit_offset < other['target_bit_offset'] + other['width']):
                        raise ValueError('compiled direct binding overlapping target drivers')
                owners = [row['owners'] for row in topology['ownership_inputs']
                          if (row['component'], row['port']) == (target.component, target.port)]
                if (len(owners) != 1 or len(owners[0]) < target.bit_offset + target.width
                        or any(owner['kind'] != 'bound'
                               or owner['producer_ref'] != f'{source.component}.{source.port}'
                               for owner in owners[0][target.bit_offset:target.bit_offset + target.width])):
                    raise ValueError('compiled direct binding ownership mismatch')
                candidate['scope'] = 'binding'
                endpoint = source.component, source.port, target.component, target.port
                direct_key = (*endpoint, source.bit_offset, target.bit_offset, source.width)
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
            else:
                # Resource versions and causal order need separate runtime evidence.
                continue
            identity_edges.append({**candidate, 'prerequisite': edge['prerequisite'], 'target': edge['target']})
        self._document_bytes = _canonical({'schema_version': 'runtime_edge_index.v1',
            'graph_sha256': contract.graph_sha256, 'contract_sha256': contract.identity_sha256,
            'topology_sha256': compiled['topology_sha256'], 'compilation_sha256': _digest(compiled),
            'path_ids': [row['path_id'] for row in compiled['paths']], 'edges': identity_edges,
            'source_owner_refs': source_owner_rows,
            'runtime_causality_verified': False, 'resource_versions_verified': False})

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(self._document_bytes).hexdigest()

    def document(self) -> dict:
        return json.loads(self._document_bytes)

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
