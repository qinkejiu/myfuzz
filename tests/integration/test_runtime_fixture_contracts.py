"""Trusted real fixture topology compiles before any local RTL is started."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from myfuzz.scenario.runtime_path_contract import compile_runtime_path_contract
from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_templates,
    make_ibex_pulp_dual_source_online_decoder)
from myfuzz.scenario.ibex_uart_online import (
    make_ibex_uart_online_factory, make_ibex_uart_online_bootstrap,
    make_ibex_uart_online_decoder)


class RuntimeFixtureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._artifact_cache = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._artifact_cache.cleanup)
        cache = Path(cls._artifact_cache.name)
        # Render/authenticate once; each factory invocation still creates fresh
        # real Session objects, RAM, Router and ownership for every negative case.
        cls._factories = {'pulp': make_ibex_pulp_dual_source_factory(cache),
                          'uart': make_ibex_uart_online_factory(cache)}

    def fixtures(self, cache):
        yield make_ibex_pulp_dual_source_templates().decoder, self._factories['pulp']
        yield make_ibex_pulp_dual_source_online_decoder(), self._factories['pulp']
        yield make_ibex_uart_online_decoder(bootstrap=make_ibex_uart_online_bootstrap()), self._factories['uart']

    def test_actual_pulp_both_modes_and_uart_compile_without_rtl_begin(self):
        with tempfile.TemporaryDirectory() as temporary:
            for decoder, factory in self.fixtures(Path(temporary)):
                runner = factory()
                with patch.object(runner, 'begin_test', side_effect=AssertionError('no begin')) as begin, \
                     patch.object(runner, 'identity_document', side_effect=AssertionError('no scan')) as identity:
                    compiled = compile_runtime_path_contract(decoder.graph, decoder.runtime_contract, runner,
                                                             paths=decoder.runtime_paths)
                    compiled.validate_topology()
                    self.assertEqual(2, len(compiled.path_ids))
                    begin.assert_not_called()
                    identity.assert_not_called()
                self.assertTrue(all(session._process is None for session in runner.sessions.values()))

    def test_actual_required_binding_or_window_missing_rejects_before_begin(self):
        with tempfile.TemporaryDirectory() as temporary:
            for decoder, factory in self.fixtures(Path(temporary)):
                for remove in ('binding', 'window'):
                    runner = factory()
                    if remove == 'binding':
                        runner.bindings = tuple(b for b in runner.bindings if b.target_component != 'cpu')
                    else:
                        runner.sessions['cpu'].router.windows = ()
                    with patch.object(runner, 'begin_test') as begin, self.assertRaises(ValueError):
                        compile_runtime_path_contract(decoder.graph, decoder.runtime_contract, runner,
                                                      paths=decoder.runtime_paths)
                    begin.assert_not_called()
                    self.assertTrue(all(session._process is None for session in runner.sessions.values()))

    def test_pulp_low_byte_binding_is_required_by_cpu_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            decoder = make_ibex_pulp_dual_source_online_decoder()
            runner = self._factories['pulp']()
            runner.bindings = tuple(b for b in runner.bindings if b.target_component != 'gpio_b')
            selected = tuple((d, p) for d, p in decoder.runtime_paths if d == 'CPU_TO_IP_TO_CPU')
            with self.assertRaises(ValueError):
                compile_runtime_path_contract(decoder.graph, decoder.runtime_contract, runner, paths=selected)

    def test_uart_rx_path_requires_actual_watermark_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            decoder = make_ibex_uart_online_decoder(bootstrap=make_ibex_uart_online_bootstrap())
            runner = self._factories['uart']()
            runner.bindings = ()
            selected = tuple((d, p) for d, p in decoder.runtime_paths if d == 'IP_TO_CPU')
            with self.assertRaises(ValueError):
                compile_runtime_path_contract(decoder.graph, decoder.runtime_contract, runner, paths=selected)

    def test_register_state_is_never_declared_as_persistent_memory(self):
        """A persistent resource is one its component really owns.

        The legacy rows keep the relations the template contract declared
        (register state is never reclassified), and an appended
        ``persistent_state`` relation may only name a resource that its own
        component declares: a real host ``PersistentMemory`` memory id, or a
        component that declares no host ``PersistentMemory`` at all -- the PULP
        GPIO register version edge, which the compiler therefore refuses to
        treat as RAM (see
        ``test_appended_persistent_edge_compiles_only_with_a_real_resource``).
        """
        legacy_by_key = {edge.key: edge.relation
                         for edge in make_ibex_pulp_dual_source_templates()
                         .decoder.runtime_contract.edges}
        for edge in make_ibex_pulp_dual_source_online_decoder().runtime_contract.edges:
            if edge.key in legacy_by_key:
                self.assertEqual(legacy_by_key[edge.key], edge.relation)
        with tempfile.TemporaryDirectory() as temporary:
            for decoder, factory in self.fixtures(Path(temporary)):
                contract = decoder.runtime_contract
                self.assertTrue(contract.edges)
                runner = factory()
                nodes = {node.node_id: node for node in contract.nodes}
                for edge in contract.edges:
                    if edge.relation != 'persistent_state':
                        continue
                    rule = decoder.graph.ordered_rules[edge.rule_index]
                    components = {nodes[rule.target].component} | {
                        nodes[child].component for child in rule.prerequisites}
                    self.assertIn(edge.resource_component, components)
                    memory = getattr(runner.sessions[edge.resource_component], 'memory', None)
                    if memory is None:
                        self.assertNotEqual('ram', edge.resource_id)
                    else:
                        self.assertIn(edge.resource_id, memory.memory_ids)
                for source in decoder.graph.sources.values():
                    node = next(n for n in contract.nodes if n.node_id == source.source_id)
                    self.assertEqual('physical' if source.kind == 'source' else 'logical', node.kind)
                self.assertTrue(any(edge.relation == 'mmio_route' for edge in contract.edges))

    def test_appended_persistent_edge_compiles_only_with_a_real_resource(self):
        """The appended RAM edge compiles; the register edge is refused as RAM.

        Selecting the appended rule on a genuinely declared path is what decides
        this: the CPU component really owns the declared ``PersistentMemory``
        region, while the PULP GPIO session declares no host
        ``PersistentMemory`` at all, so its register version edge can never
        masquerade as RAM.
        """
        legacy_by_key = {edge.key for edge in make_ibex_pulp_dual_source_templates()
                         .decoder.runtime_contract.edges}
        with tempfile.TemporaryDirectory() as temporary:
            decoder = make_ibex_pulp_dual_source_online_decoder()
            runner = self._factories['pulp']()
            contract = decoder.runtime_contract
            selected = 0
            for edge in contract.edges:
                if edge.relation != 'persistent_state' or edge.key in legacy_by_key:
                    continue
                rule = decoder.graph.ordered_rules[edge.rule_index]
                direction, path = next(
                    (direction, candidates[0])
                    for direction in ('CPU_TO_IP_TO_CPU', 'IP_TO_CPU_TO_IP')
                    for candidates in (
                        decoder.graph.edge_paths_to(rule.target, direction=direction),)
                    if candidates)
                selected += 1
                memory = getattr(runner.sessions[edge.resource_component], 'memory', None)
                if memory is None:
                    with self.assertRaises(ValueError):
                        compile_runtime_path_contract(decoder.graph, contract, runner,
                                                      paths=((direction, path),))
                else:
                    compiled = compile_runtime_path_contract(
                        decoder.graph, contract, runner, paths=((direction, path),))
                    self.assertIn(edge.resource_component,
                                  compiled.document()['topology']['components'])
            self.assertEqual(selected, 2)

    def test_uart_warmup_uses_selected_edge_identity_before_source_admission(self):
        from myfuzz.integration.ibex_uart_online import make_ibex_uart_online_runtime
        decoder = make_ibex_uart_online_decoder(bootstrap=make_ibex_uart_online_bootstrap())
        expected = next(decoder.graph.path_identity(path, direction=direction)
                        for direction, path in decoder.runtime_paths if direction == 'IP_TO_CPU')
        session = Mock()
        session.submit_case.side_effect = RuntimeError('stop at warmup')
        with tempfile.TemporaryDirectory() as temporary, \
             patch('myfuzz.integration.ibex_uart_online.ScenarioSession', return_value=session), \
             patch('myfuzz.integration.ibex_uart_online.make_ibex_uart_online_factory', return_value=self._factories['uart']):
            with self.assertRaisesRegex(RuntimeError, 'stop at warmup'):
                make_ibex_uart_online_runtime(cache_dir=Path(temporary), run_id='warmup-contract')
        warmup = session.submit_case.call_args.args[0]
        self.assertEqual(expected, warmup.path_id)
        ownership = session.configure_runtime_paths.call_args.kwargs['source_ownership']
        self.assertEqual(decoder.ownership.document(), ownership.document())
        ordered = [call[0] for call in session.mock_calls]
        self.assertLess(ordered.index('configure_runtime_paths'), ordered.index('begin'))
        self.assertLess(ordered.index('begin'), ordered.index('submit_case'))

    def test_builders_configure_contract_before_begin_and_warmup(self):
        from myfuzz.integration.ibex_pulp_online import make_ibex_pulp_online_runtime
        from myfuzz.integration.ibex_uart_online import make_ibex_uart_online_runtime
        for module, builder in (('myfuzz.integration.ibex_pulp_online', make_ibex_pulp_online_runtime),
                                ('myfuzz.integration.ibex_uart_online', make_ibex_uart_online_runtime)):
            calls = []
            session = Mock()
            session.configure_runtime_paths.side_effect = lambda *args, **kwargs: calls.append('configure')
            session.begin.side_effect = lambda: (_ for _ in ()).throw(RuntimeError('stop before RTL'))
            factory_name = '.make_ibex_pulp_dual_source_factory' if 'pulp' in module else '.make_ibex_uart_online_factory'
            factory = self._factories['pulp' if 'pulp' in module else 'uart']
            with tempfile.TemporaryDirectory() as temporary, patch(module + '.ScenarioSession', return_value=session), \
                 patch(module + factory_name, return_value=factory):
                with self.assertRaisesRegex(RuntimeError, 'stop before RTL'):
                    builder(cache_dir=Path(temporary), run_id='preflight-test')
            self.assertEqual(['configure'], calls)
            session.advance_initial.assert_not_called()
            session.submit_case.assert_not_called()

    def test_builders_reject_trusted_source_producer_drift_before_begin(self):
        from dataclasses import replace
        from myfuzz.integration.ibex_pulp_online import make_ibex_pulp_online_runtime
        from myfuzz.integration.ibex_uart_online import make_ibex_uart_online_runtime
        for module, builder, key in (
                ('myfuzz.integration.ibex_pulp_online', make_ibex_pulp_online_runtime, 'pulp'),
                ('myfuzz.integration.ibex_uart_online', make_ibex_uart_online_runtime, 'uart')):
            runner = self._factories[key]()
            for field, owners in tuple(runner.ownership._bits.items()):
                runner.ownership._bits[field] = tuple(
                    replace(owner, producer_ref='drifted-producer') if owner.kind == 'source'
                    else owner for owner in owners)
            runner.begin_test = Mock()
            runner.identity_document = Mock()
            runner.step_batch = Mock()
            factory_name = ('.make_ibex_pulp_dual_source_factory' if key == 'pulp'
                            else '.make_ibex_uart_online_factory')
            with tempfile.TemporaryDirectory() as temporary, \
                 patch(module + factory_name, return_value=Mock(return_value=runner)):
                with self.assertRaisesRegex(ValueError, 'source ownership producer'):
                    builder(cache_dir=Path(temporary), run_id='producer-drift')
            runner.begin_test.assert_not_called()
            runner.identity_document.assert_not_called()
            runner.step_batch.assert_not_called()
            self.assertTrue(all(session._process is None for session in runner.sessions.values()))


if __name__ == '__main__':
    unittest.main()
