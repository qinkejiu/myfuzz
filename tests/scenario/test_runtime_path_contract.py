"""Static path checks use explicit endpoints and never start a harness."""
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class RuntimeContractTests(unittest.TestCase):
    def fixture(self, relation='direct_binding', kind='DATA_BINDING'):
        from myfuzz.scenario.runtime_path_contract import (
            RuntimeNode, RuntimeEdgeContract, RuntimePathContract)
        graph = DependencyGraph(sources=(FuzzableSource('s', 'a', 'pin', 0, 1,
                                                       ('IP_TO_IP',)),),
                                rules=(DependencyRule('online.a.out', ('s',), 'EVENT_ORDER'),
                                       DependencyRule('online.b.in', ('online.a.out',), kind)))
        ownership = compile_ownership((InputField('a', 'pin', 1), InputField('b', 'input', 4)),
                                     (InputOwner('a', 'pin', 0, 1, 'source', 'external'),
                                      InputOwner('b', 'input', 0, 4, 'bound', 'a.output')))
        a, b = SimpleNamespace(), SimpleNamespace()
        a.memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                                    initialization_seed=1, max_initialized_bytes=4096)
        a.router = DataflowRouter((DeviceWindow('b', 0x40000000, 4096, b),))
        runner = SimpleNamespace(sessions={'a': a, 'b': b}, ownership=ownership,
                                 bindings=(Binding('a', 'output', 'b', 'input', 4),),
                                 begin_test=Mock(side_effect=AssertionError('no begin')),
                                 step=Mock(side_effect=AssertionError('no step')),
                                 identity_document=Mock(side_effect=AssertionError('no source scan')))
        nodes = (RuntimeNode('s', 'a', 'physical', 'pin', 0, 1),
                 RuntimeNode('online.a.out', 'a', 'physical', 'output', 0, 4),
                 RuntimeNode('online.b.in', 'b', 'physical', 'input', 0, 4))
        kwargs = ({'initiator_component': 'a', 'device_id': 'b', 'base': 0x40000000, 'size': 4096}
                  if relation == 'mmio_route' else
                  {'resource_component': 'a', 'resource_id': 'ram'}
                  if relation == 'persistent_state' else {})
        edge = RuntimeEdgeContract(1, 0, relation, **kwargs)
        contract = RuntimePathContract(digest(graph.edge_document()), nodes, (edge,))
        path = graph.edge_paths_to('online.b.in', direction='IP_TO_IP')[0]
        return graph, runner, contract, path

    def compile(self, relation='direct_binding', kind='DATA_BINDING'):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        graph, runner, contract, path = self.fixture(relation, kind)
        return compile_runtime_path_contract(graph, contract, runner,
                                             paths=(('IP_TO_IP', path),)), runner

    def test_aliases_bind_exact_ranges_without_start_or_identity_scan(self):
        compiled, runner = self.compile()
        compiled.validate_topology()
        self.assertEqual('runtime_path_compilation.v1', compiled.document()['schema_version'])
        runner.begin_test.assert_not_called()
        runner.step.assert_not_called()
        runner.identity_document.assert_not_called()

    def test_missing_duplicate_wrong_range_or_producer_rejects(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        for change in ('missing', 'duplicate', 'range', 'producer'):
            graph, runner, contract, path = self.fixture()
            if change == 'missing': runner.bindings = ()
            elif change == 'duplicate': runner.bindings *= 2
            elif change == 'range': runner.bindings = (replace(runner.bindings[0], width=3),)
            else:
                runner.ownership = compile_ownership((InputField('a', 'pin', 1), InputField('b', 'input', 4)),
                    (InputOwner('a', 'pin', 0, 1, 'source', 'external'),
                     InputOwner('b', 'input', 0, 4, 'bound', 'wrong.output')))
            with self.subTest(change=change), self.assertRaises(ValueError):
                compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),))
            runner.begin_test.assert_not_called()

    def test_mmio_checks_unique_window_aperture_and_registered_object(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        for change in ('missing', 'duplicate', 'base', 'size', 'object'):
            graph, runner, contract, path = self.fixture('mmio_route')
            original = runner.sessions['a'].router.windows[0]
            if change == 'missing': windows = ()
            elif change == 'duplicate': windows = (original, original)
            elif change == 'object': windows = (replace(original, target=SimpleNamespace()),)
            elif change == 'base': windows = (replace(original, base=0x50000000),)
            else: windows = (replace(original, size=8192),)
            runner.sessions['a'].router.windows = windows
            with self.subTest(change=change), self.assertRaises(ValueError):
                compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),))
        self.compile('mmio_route')[0].validate_topology()

    def test_persistent_requires_real_declared_memory_and_rule_kind(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        self.compile('persistent_state', 'PERSISTENT_STATE_RULE')[0].validate_topology()
        graph, runner, contract, path = self.fixture('persistent_state', 'PERSISTENT_STATE_RULE')
        contract = replace(contract, edges=(replace(contract.edges[0], resource_id='padout_state'),))
        with self.assertRaisesRegex(ValueError, 'resource'):
            compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),))
        with self.assertRaises(ValueError): self.compile('persistent_state', 'DATA_BINDING')
        with self.assertRaises(ValueError): self.compile('causal_order', 'DATA_BINDING')
        self.compile('causal_order', 'EVENT_ORDER')[0].validate_topology()

    def test_contract_unknown_duplicate_missing_node_edge_and_digest_reject(self):
        from myfuzz.scenario.runtime_path_contract import RuntimeNode, compile_runtime_path_contract
        graph, runner, contract, path = self.fixture()
        mutations = [replace(contract, graph_sha256='0' * 64),
                     replace(contract, nodes=contract.nodes[:-1]),
                     replace(contract, nodes=(*contract.nodes, RuntimeNode('unknown', 'a', 'logical'))),
                     replace(contract, edges=()),
                     replace(contract, edges=(replace(contract.edges[0], rule_index=99),))]
        for changed in mutations:
            with self.assertRaises(ValueError):
                compile_runtime_path_contract(graph, changed, runner, paths=(('IP_TO_IP', path),))
        with self.assertRaises(ValueError): replace(contract, nodes=(*contract.nodes, contract.nodes[0]))
        with self.assertRaises(ValueError): replace(contract, edges=contract.edges * 2)

    def test_unselected_same_source_or_branch_does_not_require_its_binding(self):
        from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract, RuntimeEdgeContract, compile_runtime_path_contract
        graph, runner, contract, _ = self.fixture()
        graph = DependencyGraph(sources=tuple(graph.sources.values()), rules=(
            DependencyRule('out', ('s',), 'EVENT_ORDER'),
            DependencyRule('target', ('out',), 'DATA_BINDING'),
            DependencyRule('missing', ('s',), 'EVENT_ORDER'),
            DependencyRule('target', ('missing',), 'DATA_BINDING')))
        nodes = (next(n for n in contract.nodes if n.node_id == 's'), RuntimeNode('out', 'a', 'physical', 'output', 0, 4),
                 RuntimeNode('target', 'b', 'physical', 'input', 0, 4))
        contract = RuntimePathContract(digest(graph.edge_document()), nodes,
                                      (RuntimeEdgeContract(1, 0, 'direct_binding'),))
        paths = graph.edge_paths_to('target', direction='IP_TO_IP')
        selected = next(p for p in paths if any(e.rule_index == 1 for e in p.edges))
        compiled = compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', selected),))
        compiled.validate_topology()
        rejected = next(p for p in paths if any(e.rule_index == 3 for e in p.edges))
        with self.assertRaises(ValueError):
            compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', rejected),))

    def test_topology_changes_detected_without_graph_compile_or_source_scan(self):
        for change in ('session', 'bindings', 'ownership', 'window', 'memory'):
            compiled, runner = self.compile('persistent_state', 'PERSISTENT_STATE_RULE') if change == 'memory' else self.compile('mmio_route')
            if change == 'session': runner.sessions['b'] = SimpleNamespace()
            elif change == 'bindings': runner.bindings = ()
            elif change == 'ownership': runner.ownership._bits[('b', 'input')] = ()
            elif change == 'window': runner.sessions['a'].router.windows = ()
            else: runner.sessions['a'].memory = None
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'topology'):
                compiled.validate_topology()
        compiled, runner = self.compile()
        with patch.object(DependencyGraph, 'edge_paths_to', side_effect=AssertionError('no graph compile')), \
             patch.object(DependencyGraph, 'path_identity', side_effect=AssertionError('no path scan')):
            compiled.validate_topology()
        runner.identity_document.assert_not_called()

    def test_document_roundtrip_rejects_unknown_fields_schema_and_noncanonical_order(self):
        from myfuzz.scenario.runtime_path_contract import RuntimePathContract
        _, _, contract, _ = self.fixture()
        document = contract.document()
        self.assertEqual(contract, RuntimePathContract.from_document(document))
        for changed in ({**document, 'extra': 1}, {**document, 'schema_version': 'unknown'},
                        {**document, 'nodes': list(reversed(document['nodes']))}):
            with self.assertRaises(ValueError): RuntimePathContract.from_document(changed)

    def test_source_component_or_endpoint_cannot_be_relabelled_to_hide_edges(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        graph, runner, contract, path = self.fixture()
        for field, value in (('component', 'b'), ('port', 'output'), ('width', 2)):
            nodes = tuple(replace(n, **{field: value}) if n.node_id == 's' else n for n in contract.nodes)
            changed = replace(contract, nodes=nodes)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'source node'):
                compile_runtime_path_contract(graph, changed, runner, paths=(('IP_TO_IP', path),))

    def test_unrelated_mmio_or_memory_cannot_substitute_for_selected_edge(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        for relation, kind, changes in (
                ('mmio_route', 'DATA_BINDING', {'initiator_component': 'b', 'device_id': 'b'}),
                ('persistent_state', 'PERSISTENT_STATE_RULE', {'resource_component': 'other'})):
            graph, runner, contract, path = self.fixture(relation, kind)
            changed = replace(contract, edges=(replace(contract.edges[0], **changes),))
            with self.assertRaises(ValueError):
                compile_runtime_path_contract(graph, changed, runner, paths=(('IP_TO_IP', path),))

    def test_wrong_equal_window_target_replacement_is_detected(self):
        compiled, runner = self.compile('mmio_route')
        window = runner.sessions['a'].router.windows[0]
        runner.sessions['a'].router.windows = (replace(window, target=SimpleNamespace()),)
        with self.assertRaisesRegex(ValueError, 'topology'):
            compiled.validate_topology()

    def test_physical_input_range_checked_even_for_mmio_or_causal_relation(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        for relation, kind in (('mmio_route', 'DATA_BINDING'), ('causal_order', 'EVENT_ORDER')):
            graph, runner, contract, path = self.fixture(relation, kind)
            changed = replace(contract, nodes=tuple(replace(n, bit_offset=100)
                              if n.node_id == 'online.b.in' else n for n in contract.nodes))
            with self.assertRaisesRegex(ValueError, 'range'):
                compile_runtime_path_contract(graph, changed, runner, paths=(('IP_TO_IP', path),))

    def test_disjoint_binding_slices_are_allowed_and_overlapping_driver_rejected(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        graph, runner, contract, path = self.fixture()
        runner.ownership = compile_ownership((InputField('a', 'pin', 1), InputField('b', 'input', 8)),
            (InputOwner('a', 'pin', 0, 1, 'source', 'external'),
             InputOwner('b', 'input', 0, 8, 'bound', 'a.output')))
        runner.bindings += (Binding('a', 'output', 'b', 'input', 4, 4, 4),)
        compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),)).validate_topology()
        runner.bindings += (Binding('a', 'output', 'b', 'input', 1, 3, 3),)
        with self.assertRaisesRegex(ValueError, 'overlap'):
            compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),))

    def test_memory_actual_lookup_index_drift_is_rejected(self):
        from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
        compiled, runner = self.compile('persistent_state', 'PERSISTENT_STATE_RULE')
        runner.sessions['a'].memory._windows.clear()
        with self.assertRaisesRegex(ValueError, 'topology'):
            compiled.validate_topology()
        graph, runner, contract, path = self.fixture('persistent_state', 'PERSISTENT_STATE_RULE')
        runner.sessions['a'].memory._windows.clear()
        with self.assertRaisesRegex(ValueError, 'resource'):
            compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),))

    def test_strict_types_and_immutable_canonical_declarations(self):
        from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract
        from dataclasses import FrozenInstanceError
        _, _, contract, _ = self.fixture()
        for factory in (lambda: RuntimeNode('n', 'a', 'physical', 'pin', False, 1),
                        lambda: RuntimeNode('n', 'a', 'physical', 'pin', 0, True),
                        lambda: RuntimeNode('n', 'a', 'logical', 'fake_port'),
                        lambda: RuntimeEdgeContract(True, 0, 'causal_order'),
                        lambda: RuntimeEdgeContract(0, 0, 'mmio_route', 'a', 'b', True, 4096),
                        lambda: RuntimeEdgeContract(0, 0, 'direct_binding', resource_id='ram'),
                        lambda: RuntimePathContract('not-a-sha', contract.nodes, contract.edges),
                        lambda: RuntimePathContract(contract.graph_sha256, list(contract.nodes), contract.edges)):
            with self.assertRaises(ValueError): factory()
        with self.assertRaises(FrozenInstanceError): contract.graph_sha256 = '0' * 64
        document = contract.document()
        document['nodes'][0]['unknown'] = 1
        with self.assertRaises(ValueError): RuntimePathContract.from_document(document)

    def test_memory_source_is_logical_and_cannot_be_remapped_as_physical(self):
        from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract, compile_runtime_path_contract
        graph, runner, contract, _ = self.fixture()
        graph = DependencyGraph(sources=(FuzzableSource('s', 'a', 'boot', 0, 1,
                                                        ('IP_TO_IP',), 'memory_image'),),
                                rules=(DependencyRule('s_target', ('s',), 'EVENT_ORDER'),))
        path = graph.edge_paths_to('s_target', direction='IP_TO_IP')[0]
        nodes = (RuntimeNode('s', 'a', 'logical'), RuntimeNode('s_target', 'a', 'logical'))
        contract = RuntimePathContract(digest(graph.edge_document()), nodes, ())
        compile_runtime_path_contract(graph, contract, runner, paths=(('IP_TO_IP', path),))
        changed = replace(contract, nodes=(RuntimeNode('s', 'a', 'physical', 'pin', 0, 1), nodes[1]))
        with self.assertRaisesRegex(ValueError, 'masquerade'):
            compile_runtime_path_contract(graph, changed, runner, paths=(('IP_TO_IP', path),))

    def test_compile_and_admission_perform_no_file_or_tool_operations(self):
        from pathlib import Path
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('no source files')), \
             patch('subprocess.run', side_effect=AssertionError('no tool invocation')):
            compiled, runner = self.compile()
            compiled.validate_topology()
        runner.identity_document.assert_not_called()


if __name__ == '__main__':
    unittest.main()
