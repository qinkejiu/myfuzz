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
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimeNode, RuntimeEdgeContract, RuntimePathContract)


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
