"""Selected runtime edges use explicit declarations, never logical name hints."""
import copy
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding
from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
from myfuzz.scenario.runtime_path_contract import (
    DmaMasterRouteContract, PreparedRuntimePathContract, RuntimeNode,
    RuntimeEdgeContract, RuntimePathContract)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def fixture(relation='direct_binding', width=4, kind='DATA_BINDING'):
    graph = DependencyGraph(sources=(FuzzableSource('s', 'a', 'pin', 0, 1, ('IP_TO_IP',)),),
        rules=(DependencyRule('out', ('s',), 'EVENT_ORDER'),
               DependencyRule('target', ('out',), kind),
               DependencyRule('alias', ('out',), kind)))
    nodes = (RuntimeNode('s', 'a', 'physical', 'pin', 0, 1),
             RuntimeNode('out', 'a', 'physical', 'output', 2, width),
             RuntimeNode('target', 'b', 'physical', 'input', 3, width),
             RuntimeNode('alias', 'b', 'physical', 'input', 3, width))
    kwargs = ({'initiator_component': 'a', 'device_id': 'b', 'base': 0x1000, 'size': 0x100}
              if relation == 'mmio_route' else
              {'resource_component': 'a', 'resource_id': 'ram'}
              if relation == 'persistent_state' else {})
    contract = RuntimePathContract(digest(graph.edge_document()), nodes,
        (RuntimeEdgeContract(1, 0, relation, **kwargs), RuntimeEdgeContract(2, 0, relation, **kwargs)))
    ownership = compile_ownership((InputField('a', 'pin', 1), InputField('b', 'input', width + 3)),
        (InputOwner('a', 'pin', 0, 1, 'source', 'external'),
         InputOwner('b', 'input', 0, 3, 'fixed', 'zero'),
         InputOwner('b', 'input', 3, width, 'bound', 'a.output')))
    a, b = SimpleNamespace(), SimpleNamespace()
    a.router = DataflowRouter((DeviceWindow('b', 0x1000, 0x100, b),))
    if relation == 'persistent_state':
        from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
        a.memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                                    initialization_seed=1, max_initialized_bytes=4096)
    runner = SimpleNamespace(sessions={'a': a, 'b': b}, ownership=ownership,
        bindings=(Binding('a', 'output', 'b', 'input', width, 2, 3),))
    selections = tuple(('IP_TO_IP', graph.edge_paths_to(target, direction='IP_TO_IP')[0])
                       for target in ('target', 'alias'))
    prepared = PreparedRuntimePathContract(graph, contract, selections)
    compiled = prepared.bind(runner).document()
    compiled['declaration'] = prepared.document()
    return compiled, contract.document()


def index(*args, **kwargs):
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
    return RuntimeEdgeIndex(*args, **kwargs)


class _RouteEndpoint:
    def identity_document(self):
        return {'component': 'uart', 'profile': 'edge-index-test-uart'}

    def read_register(self, offset):
        return 0

    def write_register(self, offset, value, be=15):
        return None


class _DmaEndpoint:
    def dma_route_endpoint_identity_document(self):
        return {'schema_version': 'test-dma-route-endpoint.v1',
                'component': 'dma', 'endpoint': 'wishbone-master', 'profile': 'test'}


def dma_route_fixture():
    """Build a route-bearing compile through the real contract compiler.

    Kept module-level so saved-plan and replay tests can reuse the exact v2
    contract/prepared/compilation pair instead of hand-authoring schemas.
    """
    from types import SimpleNamespace
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource

    uart = _RouteEndpoint()
    dma_endpoint = _DmaEndpoint()
    dma = SimpleNamespace(master_targets=(), memory_service=None,
        dma_route_endpoint_identity_document=dma_endpoint.dma_route_endpoint_identity_document,
        configured_validator=None)
    dma.configure_dma_route_validator = lambda callback: setattr(
        dma, 'configured_validator', callback)
    window = MasterTargetWindow('uart', 0x1000, 0x1000, uart, (), (),
                                readable_offsets=(0x18,))
    dma.master_targets = (window,)
    graph = DependencyGraph(
        sources=(FuzzableSource('uart-read-result', 'uart', 'rdata', 0, 8,
                                ('IP_TO_IP',)),),
        rules=(DependencyRule('dma-receive', ('uart-read-result',),
                              'DMA_MASTER_TRANSFER'),))
    nodes = (RuntimeNode('uart-read-result', 'uart', 'physical', 'rdata', 0, 8),
             RuntimeNode('dma-receive', 'dma', 'logical'))
    route = DmaMasterRouteContract(
        rule_index=0, prerequisite_index=0,
        source_node_id='uart-read-result', target_node_id='dma-receive',
        initiator_component='dma', endpoint_id='wishbone-master',
        endpoint_identity_sha256=digest(dma.dma_route_endpoint_identity_document()),
        target_kind='peripheral', target_component='uart', target_id='uart',
        base=0x1000, size=0x1000, operation='read', permissions=('read',),
        byte_enable=15, readable_offsets=(0x18,), writable_offsets=(),
        accepted_write_values=(),
        target_identity_sha256=digest(window.route_identity_document()))
    contract = RuntimePathContract(digest(graph.edge_document()), nodes,
        (RuntimeEdgeContract(0, 0, 'dma_master_route'),),
        dma_master_routes=(route,))
    ownership = compile_ownership((InputField('uart', 'rdata', 8),),
        (InputOwner('uart', 'rdata', 0, 8, 'source', 'uart.rdata'),))
    runner = SimpleNamespace(sessions={'dma': dma, 'uart': uart},
                             ownership=ownership, bindings=())
    path = graph.edge_paths_to('dma-receive', direction='IP_TO_IP')[0]
    prepared = PreparedRuntimePathContract(
        graph, contract, (('IP_TO_IP', path),))
    compiled = prepared.bind(runner).document()
    compiled['declaration'] = prepared.document()
    return compiled, contract.document()


def dma_ram_route_fixture():
    """Build one write route whose target is the shared RAM resource."""
    from types import SimpleNamespace
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.runtime_path_contract import persistent_memory_route_identity_document

    dma_endpoint = _DmaEndpoint()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
        initialization_seed=1, max_initialized_bytes=4096)
    service = MemoryService(memory, TransactionLedger())
    dma = SimpleNamespace(master_targets=(), memory_service=service,
        dma_route_endpoint_identity_document=dma_endpoint.dma_route_endpoint_identity_document,
        configured_validator=None)
    dma.configure_dma_route_validator = lambda callback: setattr(
        dma, 'configured_validator', callback)
    ram = SimpleNamespace(memory=memory)
    graph = DependencyGraph(
        sources=(FuzzableSource('dma-payload', 'dma', 'payload', 0, 32,
                                ('IP_TO_IP',)),),
        rules=(DependencyRule('ram-write-effect', ('dma-payload',),
                              'DMA_MASTER_TRANSFER'),
               DependencyRule('ram-version', ('ram-write-effect',),
                              'PERSISTENT_STATE_RULE')))
    nodes = (RuntimeNode('dma-payload', 'dma', 'physical', 'payload', 0, 32),
             RuntimeNode('ram-write-effect', 'ram', 'logical'),
             RuntimeNode('ram-version', 'ram', 'state'))
    target_identity = persistent_memory_route_identity_document(
        memory, memory_id='ram', base=0x1000, size=0x1000)
    route = DmaMasterRouteContract(
        rule_index=0, prerequisite_index=0,
        source_node_id='dma-payload', target_node_id='ram-write-effect',
        initiator_component='dma', endpoint_id='wishbone-master',
        endpoint_identity_sha256=digest(dma.dma_route_endpoint_identity_document()),
        target_kind='persistent_memory', target_component='ram', target_id='ram',
        base=0x1000, size=0x1000, operation='write', permissions=('read', 'write'),
        byte_enable=15, readable_offsets=(), writable_offsets=(),
        accepted_write_values=(), target_identity_sha256=digest(target_identity))
    contract = RuntimePathContract(digest(graph.edge_document()), nodes,
        (RuntimeEdgeContract(0, 0, 'dma_master_route'),
         RuntimeEdgeContract(1, 0, 'persistent_state',
                             resource_component='ram', resource_id='ram')),
        dma_master_routes=(route,))
    ownership = compile_ownership((InputField('dma', 'payload', 32),),
        (InputOwner('dma', 'payload', 0, 32, 'source', 'dma.payload'),))
    runner = SimpleNamespace(sessions={'dma': dma, 'ram': ram},
                             ownership=ownership, bindings=())
    path = graph.edge_paths_to('ram-version', direction='IP_TO_IP')[0]
    prepared = PreparedRuntimePathContract(
        graph, contract, (('IP_TO_IP', path),))
    compiled = prepared.bind(runner).document()
    compiled['declaration'] = prepared.document()
    return compiled, contract.document()


class RuntimeEdgeIndexTests(unittest.TestCase):
    def test_direct_binding_keeps_alias_candidates_and_exact_bit_ranges(self):
        compiled, contract = fixture()
        subject = index(compiled, contract)
        event = {'kind': 'dataflow_delivery', 'source': ['a', 'output'],
                 'target': ['b', 'input'], 'source_bit_offset': 2,
                 'target_bit_offset': 3, 'width': 4}
        matches = subject.match_event(event)
        self.assertEqual([1, 2], [row['rule_index'] for row in matches])
        for row in matches:
            self.assertEqual(compiled['graph_sha256'], row['graph_sha256'])
            self.assertEqual('direct_binding', row['relation'])
            self.assertEqual('binding', row['scope'])
            self.assertEqual(1, len(row['path_ids']))
        for field, value in [('source_bit_offset', 0), ('target_bit_offset', 0),
                             ('width', 1), ('target', ['b', 'logical_alias'])]:
            with self.subTest(field=field):
                self.assertEqual((), subject.match_event({**event, field: value}))
        self.assertEqual((), subject.match_event({k: v for k, v in event.items() if k != 'width'}))

    def test_irq_without_bits_only_matches_single_bit_actual_endpoints(self):
        event = {'source': ['a', 'output'], 'target': ['b', 'input']}
        for kind in ('source_start', 'pulse_start', 'cpu_irq_taken'):
            self.assertEqual(2, len(index(*fixture(width=1)).match_event({**event, 'kind': kind})))
            self.assertEqual((), index(*fixture(width=4)).match_event({**event, 'kind': kind}))
        self.assertEqual((), index(*fixture(width=1)).match_event({'kind': 'cpu_irq_taken'}))

    def test_mmio_window_matches_explicit_initiator_device_address_without_direction_guess(self):
        subject = index(*fixture('mmio_route'))
        for kind in ('mmio_acceptance', 'mmio_delivery'):
            for write in (True, False):
                for address in (0x1000, 0x10ff):
                    event = {'kind': kind, 'source_transaction': {'source_component': 'a'},
                             'device_id': 'b', 'address': address, 'write': write}
                    rows = subject.match_event(event)
                    self.assertEqual(2, len(rows))
                    self.assertTrue(all(row['scope'] == 'route_window' for row in rows))
                    for changed in ({'address': 0x1100}, {'address': 0xfff},
                                    {'device_id': 'other'}, {'source_transaction': {'source_component': 'b'}}):
                        self.assertEqual((), subject.match_event({**event, **changed}))

    def test_nontransport_relations_and_event_kinds_do_not_claim_edge_delivery(self):
        event = {'kind': 'dataflow_delivery', 'source': ['a', 'output'], 'target': ['b', 'input'],
                 'source_bit_offset': 2, 'target_bit_offset': 3, 'width': 4}
        self.assertEqual((), index(*fixture('causal_order', kind='EVENT_ORDER')).match_event(event))
        self.assertEqual((), index(*fixture('persistent_state', kind='PERSISTENT_STATE_RULE')).match_event(event))
        subject = index(*fixture())
        self.assertEqual((), subject.match_event({**event, 'kind': 'source_injection'}))

    def test_digests_declaration_selected_path_and_topology_tampering_reject(self):
        compiled, contract = fixture()
        mutations = []
        for name in ('graph_sha256', 'contract_sha256', 'topology_sha256'):
            value = copy.deepcopy(compiled)
            value[name] = '0' * 64
            mutations.append(value)
        value = copy.deepcopy(compiled)
        value['paths'][0]['path_id'] = '0' * 64
        mutations.append(value)
        value = copy.deepcopy(compiled)
        value['declaration']['selections'][0]['edges'][1]['target'] = 'alias'
        mutations.append(value)
        value = copy.deepcopy(compiled)
        value['topology']['bindings'][0]['width'] = 1
        value['topology_sha256'] = digest(value['topology'])
        mutations.append(value)
        value = copy.deepcopy(compiled)
        value.pop('declaration')
        mutations.append(value)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                index(value, contract)
        changed_contract = copy.deepcopy(contract)
        changed_contract['nodes'][0]['component'] = 'wrong'
        with self.assertRaises(ValueError): index(compiled, changed_contract)

    def test_same_edge_on_multiple_selected_paths_keeps_every_path_id(self):
        compiled, contract = fixture()
        document = compiled['declaration']
        graph_doc = document['graph']
        original_graph = DependencyGraph.from_edge_document(graph_doc)
        graph = DependencyGraph(sources=tuple(original_graph.sources.values()),
            rules=(*original_graph._ordered_rules, DependencyRule('after', ('target',), 'EVENT_ORDER')))
        graph_doc = graph.edge_document()
        runtime_contract = RuntimePathContract.from_document(contract)
        from dataclasses import replace
        runtime_contract = replace(runtime_contract, graph_sha256=digest(graph_doc),
            nodes=(*runtime_contract.nodes, RuntimeNode('after', 'b', 'logical')))
        prepared = PreparedRuntimePathContract(graph, runtime_contract,
            tuple(('IP_TO_IP', graph.edge_paths_to(target, direction='IP_TO_IP')[0])
                  for target in ('target', 'after')))
        compiled.update(graph_sha256=runtime_contract.graph_sha256,
                        contract_sha256=runtime_contract.identity_sha256,
                        declaration=prepared.document())
        compiled['paths'] = [{key: row[key] for key in ('direction', 'path_id', 'target')}
                             for row in prepared.document()['selections']]
        subject = index(compiled, runtime_contract.document())
        event = {'kind': 'dataflow_delivery', 'source': ['a', 'output'], 'target': ['b', 'input'],
                 'source_bit_offset': 2, 'target_bit_offset': 3, 'width': 4}
        rows = subject.match_event(event)
        self.assertEqual(1, len(rows))
        self.assertEqual(2, len(rows[0]['path_ids']))

    def test_mmio_window_changed_with_recomputed_digest_still_rejects(self):
        compiled, contract = fixture('mmio_route')
        compiled['topology']['routers'][0]['windows'][0]['base'] += 4
        compiled['topology_sha256'] = digest(compiled['topology'])
        with self.assertRaises(ValueError): index(compiled, contract)

    def test_cross_component_transport_without_declaration_rejects(self):
        compiled, contract = fixture()
        contract['edges'] = []
        compiled['declaration']['contract'] = contract
        compiled['contract_sha256'] = digest(contract)
        with self.assertRaises(ValueError): index(compiled, contract)

    def test_environment_and_baseline_edges_do_not_become_transports(self):
        for kind in ('ENV_PRECONDITION', 'BASELINE_GROUPING'):
            compiled, contract = fixture()
            graph = DependencyGraph(sources=(FuzzableSource('s', 'a', 'pin', 0, 1, ('IP_TO_IP',)),),
                rules=(DependencyRule('out', ('s',), 'EVENT_ORDER'),
                       DependencyRule('target', ('out',), kind)))
            from dataclasses import replace
            runtime_contract = replace(RuntimePathContract.from_document(contract),
                graph_sha256=digest(graph.edge_document()), edges=(),
                nodes=tuple(node for node in RuntimePathContract.from_document(contract).nodes
                            if node.node_id != 'alias'))
            prepared = PreparedRuntimePathContract(graph, runtime_contract,
                (('IP_TO_IP', graph.edge_paths_to('target', direction='IP_TO_IP')[0]),))
            compiled.update(graph_sha256=runtime_contract.graph_sha256,
                contract_sha256=runtime_contract.identity_sha256, declaration=prepared.document(),
                paths=[{key: row[key] for key in ('direction', 'path_id', 'target')}
                       for row in prepared.document()['selections']])
            subject = index(compiled, runtime_contract.document())
            self.assertEqual([], subject.document()['edges'])

    def test_recomputed_digest_cannot_hide_malformed_nested_topology(self):
        for relation, mutate in (
            ('direct_binding', lambda t: t['bindings'][0].update(width=True)),
            ('direct_binding', lambda t: t['bindings'][0].update(source_bit_offset=2.0)),
            ('direct_binding', lambda t: t['bindings'][0].update(extra=1)),
            ('direct_binding', lambda t: t['components'].append('unrelated')),
            ('direct_binding', lambda t: t['components'].append(t['components'][0])),
            ('direct_binding', lambda t: t['ownership_inputs'][0]['owners'][0].update(kind='fixed')),
            ('direct_binding', lambda t: t['ownership_inputs'][0]['owners'][0].update(width=True)),
            ('direct_binding', lambda t: t['ownership_inputs'][0]['owners'][0].update(bit_offset=1)),
            ('direct_binding', lambda t: t['ownership_inputs'][0]['owners'][0].update(component_id='wrong')),
            ('direct_binding', lambda t: t['ownership_inputs'].append(copy.deepcopy(t['ownership_inputs'][0]))),
            ('mmio_route', lambda t: t['routers'].append(copy.deepcopy(t['routers'][0]))),
            ('mmio_route', lambda t: t['routers'][0]['windows'][0].update(base=4096.0)),
            ('mmio_route', lambda t: t['routers'][0]['windows'][0].update(extra=1)),
            ('direct_binding', lambda t: t['routers'].append({'initiator': 'a', 'windows': []})),
        ):
            compiled, contract = fixture(relation, width=1)
            mutate(compiled['topology'])
            compiled['topology_sha256'] = digest(compiled['topology'])
            with self.subTest(relation=relation, topology=compiled['topology']), self.assertRaises(ValueError):
                index(compiled, contract)

    def test_persistent_topology_shape_and_declared_resource_are_checked_without_claiming_delivery(self):
        for mutate in (
            lambda t: t['resources'][0]['regions'][0].update(size=True),
            lambda t: t['resources'][0]['regions'][0].update(readable=1),
            lambda t: t['resources'][0]['regions'][0].update(aliases=[False]),
            lambda t: t['resources'][0]['regions'][0].update(extra=1),
            lambda t: t['resources'][0]['regions'][0].update(memory_id='other'),
            lambda t: t['resources'].clear(),
        ):
            compiled, contract = fixture('persistent_state', kind='PERSISTENT_STATE_RULE')
            mutate(compiled['topology'])
            compiled['topology_sha256'] = digest(compiled['topology'])
            with self.subTest(topology=compiled['topology']), self.assertRaises(ValueError):
                index(compiled, contract)

    def test_documents_and_candidates_are_detached_and_hot_path_uses_cached_facts(self):
        compiled, contract = fixture()
        subject = index(compiled, contract)
        document = subject.document()
        self.assertEqual('runtime_edge_index.v1', document['schema_version'])
        self.assertEqual(compiled['graph_sha256'], document['graph_sha256'])
        self.assertEqual(compiled['contract_sha256'], document['contract_sha256'])
        self.assertEqual(compiled['topology_sha256'], document['topology_sha256'])
        self.assertFalse(document['runtime_causality_verified'])
        original = copy.deepcopy(document)
        document.clear()
        compiled.clear()
        contract.clear()
        event = {'kind': 'dataflow_delivery', 'source': ['a', 'output'], 'target': ['b', 'input'],
                 'source_bit_offset': 2, 'target_bit_offset': 3, 'width': 4}
        with patch.object(PreparedRuntimePathContract, 'from_document', side_effect=AssertionError('no scans')), \
             patch.object(DependencyGraph, 'edge_document', side_effect=AssertionError('no graph scans')):
            rows = subject.match_event(event)
            rows[0]['path_ids'].clear()
            rows[0]['rule_index'] = 99
            self.assertEqual([1, 2], [row['rule_index'] for row in subject.match_event(event)])
            self.assertEqual(1, len(subject.match_event(event)[0]['path_ids']))
        self.assertEqual(original, subject.document())

    def test_existing_prepared_cache_must_match_its_frozen_declaration(self):
        from dataclasses import replace
        from types import MappingProxyType

        compiled, contract = fixture()
        prepared = PreparedRuntimePathContract.from_document(
            compiled['declaration'])
        path_id = prepared.path_ids[0]
        selection = list(prepared._selections[path_id])
        direction, source = selection[5][0]
        selection[5] = ((direction, replace(source,
            source_id='forged-source-id')),)
        caches = dict(prepared._selections)
        caches[path_id] = tuple(selection)
        with self.assertRaises(TypeError):
            prepared._selections[path_id] = tuple(selection)
        object.__setattr__(prepared, '_selections', MappingProxyType(caches))

        with self.assertRaises(ValueError):
            index(compiled, contract, prepared=prepared)

    def test_dma_master_routes_are_indexed_by_stable_route_and_selected_edge_identity(self):
        compiled, contract = dma_route_fixture()
        subject = index(compiled, contract)
        document = subject.document()
        route = contract['dma_master_routes'][0]
        self.assertEqual('runtime_edge_index.v2', document['schema_version'])
        self.assertEqual([route['identity_sha256']],
                         [row['route_sha256'] for row in document['dma_master_routes']])
        row = document['dma_master_routes'][0]
        self.assertEqual([route['rule_index'], route['prerequisite_index']], row['edge_key'])
        self.assertEqual(route['source_node_id'], row['source_node_id'])
        self.assertEqual(route['target_node_id'], row['target_node_id'])
        self.assertEqual(digest({key: value for key, value in route.items()
                                 if key != 'identity_sha256'}), route['identity_sha256'])
        self.assertEqual(compiled['topology_sha256'], document['topology_sha256'])
        self.assertEqual(digest(compiled), document['compilation_sha256'])
        resolved = subject.dma_master_route(
            route['identity_sha256'], route['rule_index'], route['prerequisite_index'])
        self.assertEqual(row, resolved)
        resolved['path_ids'].clear()
        self.assertEqual(row, subject.dma_master_route(
            route['identity_sha256'], route['rule_index'], route['prerequisite_index']))
        self.assertIsNone(subject.dma_master_route('0' * 64, 0, 0))
        self.assertIsNone(subject.dma_master_route(route['identity_sha256'], 99, 0))

    def test_v2_route_omission_or_schema_pair_mismatch_rejects(self):
        compiled, contract = dma_route_fixture()
        value = copy.deepcopy(compiled)
        value['schema_version'] = 'runtime_path_compilation.v1'
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(compiled)
        value['topology']['dma_master_routes'].clear()
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(compiled)
        value['declaration']['contract']['dma_master_routes'].clear()
        with self.assertRaises(ValueError):
            index(value, contract)

    def test_v2_unknown_fields_and_ambiguous_route_rows_reject(self):
        compiled, contract = dma_route_fixture()
        value = copy.deepcopy(compiled)
        value['unknown'] = True
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(compiled)
        value['topology']['dma_master_routes'][0]['extra'] = True
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(compiled)
        value['topology']['dma_master_routes'].append(
            copy.deepcopy(value['topology']['dma_master_routes'][0]))
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(contract)
        value['dma_master_routes'][0]['unknown'] = 1
        with self.assertRaises(ValueError):
            index(compiled, value)

    def test_v2_wrong_selected_edge_and_topology_identity_reject(self):
        compiled, contract = dma_route_fixture()
        value = copy.deepcopy(compiled)
        value['declaration']['selections'][0]['edges'][0]['target'] = 'wrong-target'
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(compiled)
        value['topology']['dma_master_routes'][0]['endpoint']['identity_sha256'] = '0' * 64
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)
        value = copy.deepcopy(compiled)
        value['topology']['dma_master_routes'][0]['target']['identity']['base'] += 4
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)

    def test_v2_ram_target_identity_is_joined_to_memory_resource_snapshot(self):
        compiled, contract = dma_ram_route_fixture()
        subject = index(compiled, contract)
        route = contract['dma_master_routes'][0]
        path_id = compiled['paths'][0]['path_id']
        identity = subject.dma_master_routes_for_path(path_id)
        self.assertEqual(1, len(identity))
        self.assertEqual(0x1000, identity[0].base)
        self.assertEqual('ram', identity[0].target_id)
        self.assertEqual(route['identity_sha256'], identity[0].route_sha256)
        key = {'execution_id': 'exec', 'testcase_id': 'case',
            'source_component': 'dma', 'source_epoch': 0,
            'channel_id': 'dma-memory', 'source_sequence': 1}
        match = subject.match_dma_master_route(path_id,
            initiator_component='dma', endpoint_id='wishbone-master',
            target_kind='persistent_memory', target_component='ram',
            target_id='ram', base=0x1000, size=0x1000, operation='write',
            address=0x1004, byte_enable=15, transaction_key=key, value=0x12345678)
        self.assertEqual(route['identity_sha256'], match.route_sha256)
        self.assertIsNone(subject.match_dma_master_route(path_id,
            initiator_component='dma', endpoint_id='wishbone-master',
            target_kind='persistent_memory', target_component='ram',
            target_id='ram', base=0x1000, size=0x1000, operation='write',
            address=0x2000, byte_enable=15, transaction_key=key, value=0x12345678))

        value = copy.deepcopy(compiled)
        value['topology']['resources'][0]['regions'][0]['aliases'] = [0x2000]
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)

        value = copy.deepcopy(compiled)
        value['topology']['dma_master_routes'][0]['target']['identity']['resource'][
            'canonical_base'] += 4
        value['topology_sha256'] = digest(value['topology'])
        with self.assertRaises(ValueError):
            index(value, contract)

    def test_dma_master_route_does_not_fall_back_to_causal_mmio_or_binding_events(self):
        compiled, contract = dma_route_fixture()
        subject = index(compiled, contract)
        self.assertEqual((), subject.match_event({'kind': 'dataflow_delivery',
            'source': ['uart', 'rdata'], 'target': ['dma', 'receive'],
            'source_bit_offset': 0, 'target_bit_offset': 0, 'width': 8}))
        self.assertEqual((), subject.match_event({'kind': 'mmio_acceptance',
            'source_transaction': {'source_component': 'dma'}, 'device_id': 'uart',
            'address': 0x1018, 'write': False}))

    def test_dma_master_route_lookup_checks_path_target_aperture_and_transaction_key(self):
        from myfuzz.scenario.ledger import TransactionKey

        compiled, contract = dma_route_fixture()
        subject = index(compiled, contract)
        route = contract['dma_master_routes'][0]
        path_id = compiled['paths'][0]['path_id']
        key = TransactionKey('exec', 'case', 'dma', 0, 'dma-memory', 1)
        key_document = {'execution_id': key.execution_id,
            'testcase_id': key.testcase_id, 'source_component': key.source_component,
            'source_epoch': key.source_epoch, 'channel_id': key.channel_id,
            'source_sequence': key.source_sequence}
        kwargs = dict(path_id=path_id, initiator_component='dma',
            endpoint_id='wishbone-master', target_kind='peripheral',
            target_component='uart', target_id='uart', base=0x1000, size=0x1000,
            operation='read', address=0x1018, byte_enable=15,
            transaction_key=key_document)
        match = subject.match_dma_master_route(**kwargs)
        self.assertEqual(route['identity_sha256'], match.route_sha256)
        self.assertEqual((route['rule_index'], route['prerequisite_index']),
                         match.edge_key)
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs, 'path_id': '0' * 64}))
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs, 'address': 0x2000}))
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs, 'operation': 'write'}))
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs,
            'transaction_key': {**key_document, 'source_component': 'other'}}))
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs,
            'transaction_key': {'source_component': 'dma'}}))
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs,
            'transaction_key': {**key_document, 'source_epoch': True}}))
        self.assertIsNone(subject.match_dma_master_route(**{**kwargs,
            'transaction_key': {**key_document, 'extra': 1}}))
