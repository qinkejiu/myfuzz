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


class DmaMasterRouteContractTests(unittest.TestCase):
    def fixture(self, *, duplicate_window=False, split_memory=False):
        from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
        from myfuzz.scenario.ledger import TransactionLedger
        from myfuzz.scenario.memory_service import MemoryService
        from myfuzz.scenario.runtime_path_contract import (
            DmaMasterRouteContract, RuntimeNode, RuntimeEdgeContract,
            RuntimePathContract, persistent_memory_route_identity_document)

        class Uart:
            def identity_document(self):
                return {'component': 'uart', 'profile': 'test-uart-v1'}

            def read_register(self, offset):
                return 0

            def write_register(self, offset, value, *, be):
                pass

        class Dma:
            def __init__(self, windows, service):
                self.master_targets = windows
                self.memory_service = service
                self.identity = {'component': 'dma', 'profile': 'test-wbdmac-v1'}
                self._route_validator = None

            def identity_document(self):
                return dict(self.identity)

            def configure_dma_route_validator(self, callback):
                if self._route_validator is not None:
                    raise ValueError('already configured')
                self._route_validator = callback

        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
            initialization_seed=1, max_initialized_bytes=4096)
        dma_memory = (PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 0x1000),),
            initialization_seed=1, max_initialized_bytes=4096)
            if split_memory else memory)
        uart = Uart()
        window = MasterTargetWindow('uart', 0x50000000, 0x1000, uart,
            (0x1c,), (2,), readable_offsets=(0x18,))
        windows = (window, window) if duplicate_window else (window,)
        dma = Dma(windows, MemoryService(dma_memory, TransactionLedger()))
        graph = DependencyGraph(
            sources=(FuzzableSource('uart.payload', 'uart', 'payload', 0, 8,
                ('CPU_TO_IP',), kind='memory_image'),),
            rules=(
                DependencyRule('uart.read_result', ('uart.payload',), 'EVENT_ORDER'),
                DependencyRule('dma.receive', ('uart.read_result',), 'DMA_MASTER_TRANSFER'),
                DependencyRule('dma.write_payload', ('dma.receive',), 'EVENT_ORDER'),
                DependencyRule('ram.target_effect', ('dma.write_payload',), 'DMA_MASTER_TRANSFER'),
            ))
        nodes = (
            RuntimeNode('uart.payload', 'uart', 'logical'),
            RuntimeNode('uart.read_result', 'uart', 'logical'),
            RuntimeNode('dma.receive', 'dma', 'logical'),
            RuntimeNode('dma.write_payload', 'dma', 'logical'),
            RuntimeNode('ram.target_effect', 'cpu', 'logical'),
        )
        edges = (
            RuntimeEdgeContract(0, 0, 'causal_order'),
            RuntimeEdgeContract(1, 0, 'dma_master_route'),
            RuntimeEdgeContract(2, 0, 'causal_order'),
            RuntimeEdgeContract(3, 0, 'dma_master_route'),
        )
        dma_identity_sha = digest(dma.identity_document())
        window_identity_sha = digest(window.route_identity_document())
        uart_read = DmaMasterRouteContract(
            rule_index=1, prerequisite_index=0,
            source_node_id='uart.read_result', target_node_id='dma.receive',
            initiator_component='dma', endpoint_id='dma.master',
            endpoint_identity_sha256=dma_identity_sha,
            target_kind='peripheral', target_component='uart', target_id='uart',
            base=0x50000000, size=0x1000, operation='read',
            permissions=('read', 'write'), byte_enable=15,
            readable_offsets=(0x18,), writable_offsets=(0x1c,),
            accepted_write_values=(2,), target_identity_sha256=window_identity_sha)
        memory_identity = persistent_memory_route_identity_document(
            memory, memory_id='ram', base=0x1000, size=0x1000)
        ram_write = DmaMasterRouteContract(
            rule_index=3, prerequisite_index=0,
            source_node_id='dma.write_payload', target_node_id='ram.target_effect',
            initiator_component='dma', endpoint_id='dma.master',
            endpoint_identity_sha256=dma_identity_sha,
            target_kind='persistent_memory', target_component='cpu', target_id='ram',
            base=0x1000, size=0x1000, operation='write',
            permissions=('read', 'write'), byte_enable=15,
            readable_offsets=(), writable_offsets=(), accepted_write_values=(),
            target_identity_sha256=digest(memory_identity))
        contract = RuntimePathContract(digest(graph.edge_document()), nodes, edges,
            dma_master_routes=(uart_read, ram_write))
        runner = SimpleNamespace(sessions={'uart': uart, 'dma': dma,
                                           'cpu': SimpleNamespace(memory=memory)},
            ownership=SimpleNamespace(_bits={}), bindings=())
        paths = graph.edge_paths_to('ram.target_effect', direction='CPU_TO_IP')
        self.assertEqual(1, len(paths))
        return graph, runner, contract, paths[0], dma, memory

    def test_v1_contract_document_remains_byte_compatible(self):
        _, _, contract, _ = RuntimeContractTests().fixture()
        expected = {'schema_version': 'runtime_path_contract.v1',
            'graph_sha256': contract.graph_sha256,
            'nodes': [{'node_id': n.node_id, 'component': n.component,
                       'kind': n.kind, 'port': n.port, 'bit_offset': n.bit_offset,
                       'width': n.width} for n in sorted(contract.nodes,
                                                        key=lambda n: n.node_id)],
            'edges': [{'rule_index': e.rule_index,
                       'prerequisite_index': e.prerequisite_index,
                       'relation': e.relation, 'initiator_component': e.initiator_component,
                       'device_id': e.device_id, 'base': e.base, 'size': e.size,
                       'resource_component': e.resource_component,
                       'resource_id': e.resource_id}
                      for e in sorted(contract.edges, key=lambda e: e.key)]}
        self.assertEqual(expected, contract.document())
        self.assertEqual('runtime_path_contract.v1', contract.document()['schema_version'])

    def test_v2_roundtrip_binds_two_directional_edges_and_full_topology_digest(self):
        from myfuzz.scenario.runtime_path_contract import (
            PreparedRuntimePathContract, RuntimePathContract)
        graph, runner, contract, path, dma, _memory = self.fixture()
        prepared = PreparedRuntimePathContract(graph, contract,
            (('CPU_TO_IP', path),))
        document = prepared.document()
        self.assertEqual('prepared_runtime_paths.v2', document['schema_version'])
        restored = PreparedRuntimePathContract.from_document(document)
        self.assertEqual(document, restored.document())
        compiled = restored.bind(runner)
        self.assertEqual('runtime_path_compilation.v2',
                         compiled.document()['schema_version'])
        route_rows = compiled.document()['topology']['dma_master_routes']
        self.assertEqual(2, len(route_rows))
        self.assertEqual([1, 3], [row['route']['rule_index'] for row in route_rows])
        self.assertEqual([row['route']['identity_sha256'] for row in route_rows],
                         [row['route_sha256'] for row in route_rows])
        self.assertEqual(2, len(compiled.dma_master_routes))
        compiled.validate_topology()
        self.assertIsNotNone(dma._route_validator)

    def test_v2_route_identity_is_strict_and_requires_selected_matching_edge(self):
        from dataclasses import replace
        from myfuzz.scenario.runtime_path_contract import (
            PreparedRuntimePathContract, RuntimePathContract)
        graph, _runner, contract, path, _dma, _memory = self.fixture()
        document = contract.document()
        self.assertEqual('runtime_path_contract.v2', document['schema_version'])
        self.assertEqual(contract, RuntimePathContract.from_document(document))
        changed = {**document, 'dma_master_routes': [
            {**document['dma_master_routes'][0], 'unknown': True},
            document['dma_master_routes'][1]]}
        with self.assertRaises(ValueError):
            RuntimePathContract.from_document(changed)
        bad_route = replace(contract.dma_master_routes[0], source_node_id='dma.receive')
        bad_contract = replace(contract, dma_master_routes=(bad_route,
            contract.dma_master_routes[1]))
        with self.assertRaisesRegex(ValueError, 'edge|endpoint|route'):
            PreparedRuntimePathContract(graph, bad_contract,
                (('CPU_TO_IP', path),))
        selected_prefix = graph.edge_paths_to('dma.receive', direction='CPU_TO_IP')[0]
        with self.assertRaisesRegex(ValueError, 'selected|route'):
            PreparedRuntimePathContract(graph, contract,
                (('CPU_TO_IP', selected_prefix),))

    def test_v2_peripheral_route_requires_exact_unique_window_and_endpoint_identity(self):
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        for change in ('ambiguous', 'endpoint_object', 'endpoint_identity',
                       'target_identity', 'aperture', 'permissions'):
            graph, runner, contract, path, dma, _memory = self.fixture(
                duplicate_window=(change == 'ambiguous'))
            route = contract.dma_master_routes[0]
            if change == 'endpoint_object':
                dma.master_targets = (replace(dma.master_targets[0],
                    endpoint=dma.master_targets[0].endpoint.__class__()),)
            elif change == 'endpoint_identity':
                route = replace(route, endpoint_identity_sha256='0' * 64)
            elif change == 'target_identity':
                route = replace(route, target_identity_sha256='0' * 64)
            elif change == 'aperture':
                route = replace(route, size=0x2000)
            elif change == 'permissions':
                with self.subTest(change=change), self.assertRaises(ValueError):
                    replace(route, permissions=('read',))
                continue
            routes = (route, contract.dma_master_routes[1])
            changed = replace(contract, dma_master_routes=routes)
            with self.subTest(change=change), self.assertRaises(ValueError):
                PreparedRuntimePathContract(graph, changed,
                    (('CPU_TO_IP', path),)).bind(runner)

    def test_v2_peripheral_route_uses_injective_accepted_write_range_identity(self):
        from dataclasses import replace
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        graph, runner, contract, path, dma, _memory = self.fixture()
        window = replace(dma.master_targets[0],
            accepted_write_values=range(2, 4, 2))
        dma.master_targets = (window,)
        route = replace(contract.dma_master_routes[0],
            accepted_write_values=range(2, 3, 1),
            target_identity_sha256=digest(window.route_identity_document()))
        self.assertEqual(tuple(window.accepted_write_values),
                         tuple(route.accepted_write_values))
        self.assertNotEqual(window.route_identity_document()['accepted_write_values'],
                            route.document()['accepted_write_values'])
        changed = replace(contract, dma_master_routes=(route,
            contract.dma_master_routes[1]))
        with self.assertRaisesRegex(ValueError, 'accepted.*identity|route.*identity'):
            PreparedRuntimePathContract(graph, changed,
                (('CPU_TO_IP', path),)).bind(runner)

    def test_v2_memory_route_requires_same_memory_service_memory_and_exact_region(self):
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        graph, runner, contract, path, _dma, memory = self.fixture(split_memory=True)
        with self.assertRaisesRegex(ValueError, 'memory|resource|route'):
            PreparedRuntimePathContract(graph, contract,
                (('CPU_TO_IP', path),)).bind(runner)
        graph, runner, contract, path, _dma, memory = self.fixture()
        compiled = PreparedRuntimePathContract(graph, contract,
            (('CPU_TO_IP', path),)).bind(runner)
        compiled.validate_topology()
        memory._windows.clear()
        with self.assertRaisesRegex(ValueError, 'topology|resource'):
            compiled.validate_topology()

    def test_v2_topology_mutation_detects_equal_window_replacement_and_service_or_ledger_swap(self):
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        for change in ('window', 'service', 'service_memory', 'ledger',
                       'target_memory'):
            graph, runner, contract, path, dma, _memory = self.fixture()
            compiled = PreparedRuntimePathContract(graph, contract,
                (('CPU_TO_IP', path),)).bind(runner)
            # Isolate the persistent-memory validator: the full fixture also
            # has a peripheral route which independently snapshots this tuple.
            compiled = replace(compiled, _dma_routes=tuple(snapshot
                for snapshot in compiled._dma_routes
                if snapshot.route.target_kind == 'persistent_memory'))
            if change == 'window':
                dma.master_targets = (replace(dma.master_targets[0]),)
            elif change == 'service':
                dma.memory_service = object()
            elif change == 'service_memory':
                dma.memory_service.memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x1000, 0x1000),),
                    initialization_seed=1, max_initialized_bytes=4096)
            elif change == 'target_memory':
                runner.sessions['cpu'].memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x1000, 0x1000),),
                    initialization_seed=1, max_initialized_bytes=4096)
            else:
                dma.memory_service.ledger = object()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'topology'):
                compiled.validate_topology()

    def test_v2_route_compile_rejects_windows_shadowing_routes_or_persistent_ram(self):
        from myfuzz.local_harness.wishbone_dma_session import MasterTargetWindow
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        for shadow_target in ('peripheral', 'persistent_memory'):
            graph, runner, contract, path, dma, _memory = self.fixture()
            uart = runner.sessions['uart']
            shadow_base, shadow_size = ((0x50000000, 0x2000)
                if shadow_target == 'peripheral' else (0x1000, 0x1000))
            shadow = MasterTargetWindow('uart', shadow_base, shadow_size, uart,
                (0x1c,), (2,), readable_offsets=(0x18,))
            dma.master_targets = (dma.master_targets[0], shadow)
            with self.subTest(shadow_target=shadow_target), \
                    self.assertRaisesRegex(ValueError, 'shadow|overlap'):
                PreparedRuntimePathContract(graph, contract,
                    (('CPU_TO_IP', path),)).bind(runner)


if __name__ == '__main__':
    unittest.main()


def test_optional_topology_guard_preserves_serialized_v2_and_existing_callback():
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from copy import deepcopy
    fixture = DmaMasterRouteContractTests()
    graph, runner, contract, path, dma, _ = fixture.fixture()
    prepared = PreparedRuntimePathContract(graph, contract, (('CPU_TO_IP', path),))
    legacy = prepared.bind(deepcopy(runner)).document()
    calls = []
    def guard():
        calls.append('guard')
    compiled = prepared.bind(runner, topology_guard=guard)
    assert compiled.document() == legacy
    assert calls == ['guard']
    dma._route_validator()
    assert calls == ['guard', 'guard']
    assert 'topology_guard' not in repr(compiled.document())
