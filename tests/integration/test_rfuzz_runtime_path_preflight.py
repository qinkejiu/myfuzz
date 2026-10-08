"""Contract mismatches reject the actual fresh runner before RTL or checker."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
from myfuzz.scenario.dependency import DependencyGraph, SourceBinding, SourceBindings
from myfuzz.scenario.rfuzz_decoder import GenomeRecordDecoder
from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract
from tests.integration.test_scenario_rfuzz_acceptance import executor_for


def contract_executor():
    base = executor_for()
    graph = base.decoder.graph
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
                separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('local.pin', 'local', 'physical', 'pin', 0, 1),
        RuntimeNode('local.observed', 'local', 'logical'),), ())
    bindings = SourceBindings((SourceBinding('local.pin', 'source', 'local',
                                             'pin', 0, 1, 'external_pin'),))
    decoder = GenomeRecordDecoder(graph=graph, ownership=base.decoder.ownership,
        templates=base.decoder.templates, source_bindings=bindings,
        runtime_contract=contract)
    return ScenarioRfuzzExecutor(run_id='contract-case', decoder=decoder,
               factory=base.factory, targets=base.targets)


def online_contract_executor(*, flow_by_target=None):
    from myfuzz.scenario.online_case_decoder import (
        OnlineCaseDecoder, OnlineSource, OnlineDependencyGraph, OnlineDependencySource)
    from myfuzz.scenario.dependency import DependencyRule
    from myfuzz.scenario.session_runtime import ScenarioSession
    base = executor_for()
    graph = OnlineDependencyGraph(sources=(OnlineDependencySource('local.pin',
        'source', 'local', ('IP_TO_IP',), port='pin'),), rules=(
        DependencyRule('local.observed', ('local.pin',), 'EVENT_ORDER'),))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
                separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest, (
        RuntimeNode('local.pin', 'local', 'physical', 'pin', 0, 1),
        RuntimeNode('local.observed', 'local', 'logical'),), ())
    decoder = OnlineCaseDecoder(sources=(OnlineSource('local.pin', 'source',
        'local', 'IP_TO_IP', 'local.observed', port='pin',
        coverage_target_ids=('local.observed',)),), ownership=base.decoder.ownership,
        graph=graph, runtime_contract=contract, schedule=('local',),
        instruction_start=0, instruction_end=0, advance_rounds=3, max_input_bytes=8,
        flow_by_target=flow_by_target)
    session = ScenarioSession(replace(base.decoder.templates[0].genome,
                                     actions=(), max_steps=100), base.factory())
    session.configure_runtime_paths(decoder.graph, contract, decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    return ScenarioRfuzzExecutor(run_id='online-contract', factory=base.factory,
        targets=base.targets, online_decoder=decoder, session=session)


class RuntimePathExecutorTests(unittest.TestCase):
    def test_online_decision_records_declared_flow_and_path_identity(self):
        executor = online_contract_executor(flow_by_target={'local.observed': 'F2'})
        executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        decision = executor.online_decisions[0]
        self.assertEqual('F2', decision['flow_id'])
        self.assertEqual('local.observed', decision['target_id'])
        self.assertEqual('IP_TO_IP', decision['direction'])
        self.assertEqual('local.pin', decision['source_id'])
        self.assertEqual(executor.receipts[0].path_id, decision['path_id'])
        self.assertEqual('complete', executor.receipts[0].status)

    def test_v3_flow_decision_keeps_online_identity_and_fresh_prefix_replay(self):
        from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
        from myfuzz.scenario.replay import ScenarioTrace
        from myfuzz.scenario.session_runtime import replay_online_session
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests

        transport = TerminalIdentityTests()
        transport.setUp()
        try:
            executor = online_contract_executor(flow_by_target={'local.observed': 'F2'})
            transport.run_transport(executor)
            output = transport.output
            manifest = json.loads((output / 'decoder_manifest.json').read_bytes())
            self.assertEqual('online_case_decoder.v3', manifest['schema_version'])
            self.assertEqual(manifest, json.loads(json.dumps(
                OnlineCaseDecoder.from_document(manifest).document())))
            trace_path = output / 'online_final_trace.json'
            reference = ScenarioTrace(**json.loads(trace_path.read_bytes()))
            self.assertIsNotNone(_verify_online_run_identity(
                output, plan_path=output / 'online_plan.json',
                trace_path=trace_path, trace=reference))
            comparison = replay_online_session(
                (output / 'online_plan.json').read_bytes(), executor.factory, reference)
            self.assertTrue(comparison.matches, comparison.difference_context)
            self.assertEqual('F2', executor.online_decisions[0]['flow_id'])
        finally:
            transport.doCleanups()

    def test_online_feedback_uses_trusted_internal_event_lookup(self):
        executor = online_contract_executor()
        lookup = executor._interaction._event_lookup
        self.assertIs(lookup.__self__, executor.session.runner)
        self.assertIs(lookup.__func__, executor.session.runner._event_ref_by_id.__func__)

    def test_online_reconstructed_decoder_cannot_be_used_for_search(self):
        from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
        base = online_contract_executor()
        rebuilt = OnlineCaseDecoder.from_document(base.online_decoder.document())
        with self.assertRaisesRegex(ValueError, 'replay-only'):
            ScenarioRfuzzExecutor(run_id='reconstructed-search', online_decoder=rebuilt,
                factory=base.factory, targets=base.targets, session=base.session)

    def test_online_configuration_requires_trusted_source_ownership(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        base = online_contract_executor()
        session = ScenarioSession(base.session.template, base.factory())
        with self.assertRaisesRegex(ValueError, 'trusted source ownership'):
            session.configure_runtime_paths(base.online_decoder.graph,
                base.runtime_contract, base.online_decoder.runtime_paths)
        self.assertFalse(session._begun)

    def test_already_begun_wrong_source_owner_rejects_executor_construction(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        from myfuzz.scenario.ownership import InputOwner
        base = online_contract_executor()
        runner = base.factory()
        runner.ownership._bits[('local', 'pin')] = (
            InputOwner('local', 'pin', 0, 1, 'source', 'changed_external_ref'),)
        session = ScenarioSession(base.session.template, runner)
        session.configure_runtime_paths(base.online_decoder.graph,
            base.runtime_contract, base.online_decoder.runtime_paths,
            source_ownership=runner.ownership)
        session.begin()
        with self.assertRaisesRegex(ValueError, 'source ownership producer'):
            ScenarioRfuzzExecutor(run_id='wrong-owner', online_decoder=base.online_decoder,
                factory=base.factory, targets=base.targets, session=session)
    def test_online_trusted_source_producer_rejects_before_begin(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        from myfuzz.scenario.ownership import InputOwner
        base = online_contract_executor()
        runner = base.factory()
        runner.ownership._bits[('local', 'pin')] = (
            InputOwner('local', 'pin', 0, 1, 'source', 'changed_external_ref'),)
        runner.begin_test = Mock()
        runner.identity_document = Mock()
        session = ScenarioSession(base.session.template, runner)
        with self.assertRaisesRegex(ValueError, 'source ownership producer'):
            session.configure_runtime_paths(base.online_decoder.graph,
                base.runtime_contract, base.online_decoder.runtime_paths,
                source_ownership=base.online_decoder.ownership)
        runner.begin_test.assert_not_called()
        runner.identity_document.assert_not_called()
        self.assertEqual({'local': 0}, runner.local_ticks)

    def test_online_configure_to_begin_producer_drift_rejects_before_identity(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        from myfuzz.scenario.ownership import InputOwner
        base = online_contract_executor()
        runner = base.factory()
        session = ScenarioSession(base.session.template, runner)
        session.configure_runtime_paths(base.online_decoder.graph,
            base.runtime_contract, base.online_decoder.runtime_paths,
            source_ownership=base.online_decoder.ownership)
        runner.ownership._bits[('local', 'pin')] = (
            InputOwner('local', 'pin', 0, 1, 'source', 'changed_external_ref'),)
        runner.begin_test = Mock()
        runner.identity_document = Mock()
        with self.assertRaisesRegex(ValueError, 'ownership'):
            session.begin()
        runner.begin_test.assert_not_called()
        runner.identity_document.assert_not_called()

    def test_online_partial_step_failure_keeps_uncertain_effect(self):
        executor = online_contract_executor()
        executor.session.runner.step_batch = Mock(side_effect=RuntimeError(
            'local command lost response after admission'))
        executor.checker = Mock()
        coverage = executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        self.assertEqual('uncertain_effect', executor.receipts[0].status)
        self.assertEqual('uncertain_effect', executor.receipts[0].trace.status)
        self.assertEqual('step', executor.session._terminal_failure['phase'])
        self.assertEqual((b'\0',), coverage)
        executor.checker.assert_not_called()

    def test_online_protocol_step_failure_keeps_environment_error(self):
        from myfuzz.scenario.contracts import ProtocolEnvironmentError
        executor = online_contract_executor()
        executor.session.runner.step_batch = Mock(side_effect=ProtocolEnvironmentError(
            'invalid local response'))
        executor.checker = Mock()
        coverage = executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        self.assertEqual('environment_error', executor.receipts[0].status)
        self.assertEqual((b'\0',), coverage)
        executor.checker.assert_not_called()

    def test_online_replay_producer_drift_rejects_before_identity_and_begin(self):
        from myfuzz.scenario.session_runtime import replay_online_session
        from myfuzz.scenario.ownership import InputOwner
        executor = online_contract_executor()
        executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        reference = executor.session.finish()
        plan = executor.session.encode_plan()
        material = json.loads(plan)['runtime_paths']['topology']['ownership_inputs']
        self.assertEqual('external_pin', material[0]['owners'][0]['producer_ref'])
        runner = executor.factory()
        runner.ownership._bits[('local', 'pin')] = (
            InputOwner('local', 'pin', 0, 1, 'source', 'changed_external_ref'),)
        runner.begin_test = Mock()
        runner.identity_document = Mock()
        with self.assertRaisesRegex(ValueError, 'runtime path topology mismatch'):
            replay_online_session(plan, Mock(return_value=runner), reference)
        runner.begin_test.assert_not_called()
        runner.identity_document.assert_not_called()

    def bundle(self, output):
        from tests.integration.test_fresh_run_identity import FreshRunIdentityTests
        executor = contract_executor()
        with patch('tests.integration.test_fresh_run_identity.executor_for', return_value=executor):
            FreshRunIdentityTests().make_bundle(output)
        return executor

    def test_actual_runner_mismatch_rejects_before_identity_begin_checker_and_later_factory(self):
        executor = contract_executor()
        original_factory = executor.factory
        runners = []
        def bad_factory():
            runner = original_factory()
            runner.ownership = Mock()
            runner.ownership.mutation_source.side_effect = ValueError('contract source range mismatch')
            runner.begin_test = Mock(side_effect=AssertionError('must not begin'))
            runner.identity_document = Mock(side_effect=AssertionError('must not scan identity'))
            runners.append(runner)
            return runner
        executor.factory = Mock(side_effect=bad_factory)
        executor.checker = Mock(side_effect=AssertionError('must not check'))
        coverage = executor.execute_batch(InputBatch(1, 8, ((bytes(8),), (bytes(8),))))
        self.assertEqual((b'\0', b'\0'), coverage)
        self.assertEqual(['environment_error']*2, [r.status for r in executor.receipts])
        self.assertEqual(1, executor.factory.call_count)
        executor.checker.assert_not_called()
        runners[0].begin_test.assert_not_called()
        runners[0].identity_document.assert_not_called()
        self.assertIsNotNone(executor._session_stop_reason)

    def test_fresh_source_reference_drift_rejects_before_identity_begin(self):
        from myfuzz.scenario.ownership import InputOwner
        executor = contract_executor()
        runner = executor.factory()
        runner.ownership._bits[('local', 'pin')] = (
            InputOwner('local', 'pin', 0, 1, 'source', 'changed_external_ref'),)
        runner.begin_test = Mock(side_effect=AssertionError('must not begin'))
        runner.identity_document = Mock(side_effect=AssertionError('must not scan'))
        executor.factory = Mock(return_value=runner)
        coverage = executor.execute_batch(InputBatch(1, 8, ((bytes(8),), (bytes(8),))))
        self.assertEqual((b'\0', b'\0'), coverage)
        self.assertIn('source ownership producer', executor.receipts[0].error)
        executor.factory.assert_called_once()
        runner.begin_test.assert_not_called()
        runner.identity_document.assert_not_called()

    def test_fresh_preflight_uses_cached_graph_paths_and_no_extra_factory(self):
        executor = contract_executor()
        executor.factory = Mock(wraps=executor.factory)
        with patch.object(DependencyGraph, 'paths_to', side_effect=AssertionError('no legacy paths')), \
             patch.object(DependencyGraph, 'edge_paths_to', side_effect=AssertionError('no graph expansion')), \
             patch.object(DependencyGraph, 'path_identity', side_effect=AssertionError('no graph hash')), \
             patch.object(DependencyGraph, 'edge_document', side_effect=AssertionError('no graph materialize')):
            executor.mutation_hint()
            coverage = executor.execute_batch(InputBatch(1, 8, ((bytes(8),), (bytes(8),))))
        self.assertEqual(2, executor.factory.call_count)
        self.assertTrue(all(r.status == 'complete' for r in executor.receipts))
        self.assertTrue(executor.fresh_runtime_path_documents)
        self.assertEqual(1, len(executor.fresh_runtime_path_documents))

    def test_legacy_remains_explicitly_unchecked(self):
        executor = executor_for()
        executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        self.assertEqual('complete', executor.receipts[0].status)
        self.assertEqual('legacy_unchecked', executor.runtime_path_status)
        self.assertFalse(executor.fresh_runtime_path_documents)

    def test_continuous_must_be_configured_before_begin(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        executor = contract_executor()
        session = ScenarioSession(replace(executor.decoder.templates[0].genome,
                                   actions=(), max_steps=100), executor.factory())
        with self.assertRaisesRegex(ValueError, 'configured'):
            ScenarioRfuzzExecutor(run_id='not-configured', decoder=executor.decoder,
                factory=executor.factory, targets=executor.targets, session=session)
        self.assertFalse(session._begun)

    def test_versioned_fresh_bundle_binds_contract_path_topology_and_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'run'
            executor = self.bundle(output)
            identity = json.loads((output / 'run_identity.json').read_bytes())['identity']
            paths = identity['runtime_paths']
            self.assertEqual('contract_preflight', paths['status'])
            self.assertEqual(executor.decoder.document()['path_mapping'],
                             paths['declaration']['selections'])
            self.assertEqual(1, len(paths['compiled']))
            replay = replay_scenario_rfuzz_corpus(output, executor.factory)
            self.assertEqual(1, replay.matched_entries, replay.mismatches)

    def test_tampered_or_deleted_contract_path_topology_rejects_before_factory(self):
        for change in ('missing', 'declaration', 'path', 'topology', 'compiled_deleted'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'run'
                self.bundle(output)
                envelope = json.loads((output / 'run_identity.json').read_bytes())
                material = envelope['identity']['runtime_paths']
                if change == 'missing':
                    envelope['identity'].pop('runtime_paths')
                elif change == 'declaration':
                    material['declaration']['selections'][0]['path_id'] = '0'*64
                elif change == 'compiled_deleted':
                    material['compiled'].clear()
                else:
                    document = next(iter(material['compiled'].values()))
                    if change == 'path': document['paths'][0]['path_id'] = '0'*64
                    else: document['topology']['bindings'] = [{'invented': True}]
                envelope['sha256'] = hashlib.sha256(json.dumps(envelope['identity'],
                    sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
                (output / 'run_identity.json').write_text(json.dumps(envelope))
                report = json.loads((output / 'report.json').read_bytes())
                report['run_identity_sha256'] = envelope['sha256']
                (output / 'report.json').write_text(json.dumps(report))
                factory = Mock(side_effect=AssertionError('must not construct'))
                with self.assertRaisesRegex(ValueError, 'runtime path'):
                    replay_scenario_rfuzz_corpus(output, factory)
                factory.assert_not_called()

    def test_replay_actual_topology_mismatch_rejects_before_identity_or_begin(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'run'
            executor = self.bundle(output)
            runner = executor.factory()
            runner.ownership = Mock()
            runner.ownership.mutation_source.side_effect = ValueError('topology mismatch')
            runner.begin_test = Mock(side_effect=AssertionError('must not begin'))
            runner.identity_document = Mock(side_effect=AssertionError('must not scan'))
            factory = Mock(return_value=runner)
            result = replay_scenario_rfuzz_corpus(output, factory)
            self.assertEqual(0, result.matched_entries)
            factory.assert_called_once()
            runner.begin_test.assert_not_called()
            runner.identity_document.assert_not_called()

    def test_configured_continuous_keeps_complete_contract_prefix_and_replays(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_continuous
        from tests.integration.test_scenario_rfuzz_terminal_identity import (
            TerminalIdentityTests, case_checker, decoder_checker)
        transport = TerminalIdentityTests()
        transport.setUp()
        try:
            base = contract_executor()
            session = ScenarioSession(replace(base.decoder.templates[0].genome,
                                     actions=(), max_steps=100), base.factory(),
                                      checker=case_checker)
            session.configure_runtime_paths(base.decoder.graph, base.runtime_contract,
                                            base.decoder.runtime_paths,
                                            source_ownership=base.decoder.ownership)
            executor = ScenarioRfuzzExecutor(run_id='configured-continuous',
                decoder=base.decoder, factory=base.factory, targets=base.targets,
                checker=decoder_checker, session=session)
            transport.run_transport(executor, tests=((bytes(8),),
                              (bytes((0,0,0,0,0,1,0,0)),)))
            self.assertEqual(2, len(session.cases))
            saved = json.loads((transport.output / 'online_run_identity.json').read_bytes())
            self.assertEqual('contract_preflight', saved['identity']['runtime_paths']['status'])
            comparison = replay_scenario_rfuzz_continuous(transport.output, base.factory,
                session_checker=case_checker, decoder_checker=decoder_checker)
            self.assertTrue(comparison.matches, comparison.comparison.difference_context)
        finally:
            transport.doCleanups()

    def test_online_candidate_uses_cached_paths_and_rejects_topology_without_steps_checker(self):
        executor = online_contract_executor()
        with patch.object(DependencyGraph, 'edge_paths_to', side_effect=AssertionError('no expansion')), \
             patch.object(DependencyGraph, 'path_identity', side_effect=AssertionError('no path scan')), \
             patch.object(DependencyGraph, 'edge_document', side_effect=AssertionError('no graph scan')):
            executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        self.assertEqual('complete', executor.receipts[0].status)
        self.assertNotEqual('local.observed', executor.receipts[0].path_id)
        ticks = dict(executor.session.runner.local_ticks)
        executor.session.runner.step_batch = Mock(side_effect=AssertionError('must not step'))
        executor.checker = Mock(side_effect=AssertionError('must not check'))
        executor.session.runner.ownership._bits[('local', 'pin')] = ()
        coverage = executor.execute_batch(InputBatch(2, 8, ((bytes(8),), (bytes(8),))))
        self.assertEqual((b'\0', b'\0'), coverage)
        self.assertEqual('environment_error', executor.receipts[-1].status)
        self.assertEqual(ticks, executor.session.runner.local_ticks)
        executor.session.runner.step_batch.assert_not_called()
        executor.checker.assert_not_called()
        self.assertEqual(1, len(executor.session.cases))

    def test_online_saved_material_binds_decoder_session_topology_and_rejects_tamper(self):
        from tests.integration.test_scenario_rfuzz_terminal_identity import TerminalIdentityTests
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        from myfuzz.scenario.replay import ScenarioTrace
        transport = TerminalIdentityTests()
        transport.setUp()
        try:
            executor = online_contract_executor()
            transport.run_transport(executor)
            output = transport.output
            plan_path = output / 'online_plan.json'
            trace_path = output / 'online_final_trace.json'
            trace = ScenarioTrace(**json.loads(trace_path.read_bytes()))
            verified = _verify_online_run_identity(output, plan_path=plan_path,
                                                  trace_path=trace_path, trace=trace)
            self.assertEqual('contract_preflight', verified['runtime_paths']['status'])
            self.assertEqual(10, json.loads(plan_path.read_bytes())['schema_version'])
            envelope = json.loads((output / 'online_run_identity.json').read_bytes())
            envelope['identity']['runtime_paths']['compiled']['session']['topology_sha256'] = '0'*64
            envelope['sha256'] = hashlib.sha256(json.dumps(envelope['identity'],
                sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
            (output / 'online_run_identity.json').write_text(json.dumps(envelope))
            report = json.loads((output / 'report.json').read_bytes())
            report['online_run_identity_sha256'] = envelope['sha256']
            (output / 'report.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'runtime path.*topology'):
                _verify_online_run_identity(output, plan_path=plan_path,
                                           trace_path=trace_path, trace=trace)
        finally:
            transport.doCleanups()
