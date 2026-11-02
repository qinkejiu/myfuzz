"""Configured sessions bind route identity before startup and source admission."""
from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import Mock, patch

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract
from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCase, replay_online_session


class _Pin:
    def identity_document(self):
        return {'fixture': 'runtime_path_pin.v1'}

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {'out': inputs.get('pin', 0)}

    def end_case(self):
        pass


def factory():
    ownership = compile_ownership((InputField('a', 'pin', 1), InputField('b', 'pin', 1)),
        (InputOwner('a', 'pin', 0, 1, 'source', 'external'),
         InputOwner('b', 'pin', 0, 1, 'bound', 'a.out')))
    return ScenarioRunner(sessions={'a': _Pin(), 'b': _Pin()}, ownership=ownership,
                          bindings=(Binding('a', 'out', 'b', 'pin', 1),))


def declaration():
    graph = DependencyGraph(sources=(FuzzableSource('s', 'a', 'pin', 0, 1, ('IP_TO_IP',)),),
        rules=(DependencyRule('out', ('s',), 'EVENT_ORDER'),
               DependencyRule('target', ('out',), 'DATA_BINDING')))
    digest = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    contract = RuntimePathContract(digest,
        (RuntimeNode('s', 'a', 'physical', 'pin', 0, 1),
         RuntimeNode('out', 'a', 'physical', 'out', 0, 1),
         RuntimeNode('target', 'b', 'physical', 'pin', 0, 1)),
        (RuntimeEdgeContract(1, 0, 'direct_binding'),))
    paths = tuple(('IP_TO_IP', p) for p in graph.edge_paths_to('target', direction='IP_TO_IP'))
    return graph, contract, paths


def configured(runner=None):
    session = ScenarioSession(ScenarioGenome('paths', 'IP_TO_IP', 'template', ('a', 'b'), 8, ()),
                              factory() if runner is None else runner)
    graph, contract, paths = declaration()
    session.configure_runtime_paths(graph, contract, paths, source_ownership=factory().ownership)
    return session


def case(session):
    return OnlineCase('one', 'IP_TO_IP', session.runtime_path_ids[0],
                     BatchSourceEvent('one:s', 'a', 'pin', 1, 0, 1),
                     (BatchAdvance(('a', 'b')),))


def test_bounded_event_copy_does_not_visit_later_events():
    runner = factory()
    runner._events.append({'kind': 'first', 'payload': {'value': 1}})

    class UncopyableTail(dict):
        def __deepcopy__(self, memo):
            raise AssertionError('bounded read visited a later event')

    runner._events.append(UncopyableTail(kind='later'))
    events = runner.events_since(0, stop=1)
    assert len(events) == 1
    events[0]['payload']['value'] = 2
    assert runner.events_since(0, stop=1)[0]['payload']['value'] == 1


def test_old_case_receipt_and_retry_keep_metadata_detached():
    session = configured()
    session.begin()
    first = case(session)
    submitted = session.submit_case(first)
    second = replace(first, case_id='two', source=replace(first.source, action_id='two:s'))
    session.submit_case(second)
    for receipt in (session.case_receipt('one'), session.submit_case(first)):
        assert receipt.events == submitted.events
        assert len(receipt.events) == receipt.event_end - receipt.event_start
        receipt.local_ticks_after['a'] = -1
        receipt.events[0]['kind'] = 'changed-by-caller'
    retained = session.case_receipt('one')
    assert retained.local_ticks_after['a'] == submitted.local_ticks_after['a']
    assert retained.events[0]['kind'] != 'changed-by-caller'


class SessionRuntimePathTests(unittest.TestCase):
    def test_missing_binding_rejects_before_identity_scan_or_begin(self):
        runner = factory()
        runner.bindings = ()
        runner.begin_test = Mock(side_effect=AssertionError('no begin'))
        runner.identity_document = Mock(side_effect=AssertionError('no source scan'))
        with self.assertRaisesRegex(ValueError, 'Binding'):
            configured(runner)
        runner.begin_test.assert_not_called()
        runner.identity_document.assert_not_called()

    def test_complete_prefix_replay_and_manifest_bind_configured_paths(self):
        session = configured()
        session.begin()
        self.assertIn('runtime_paths', session.manifest_document)
        session.submit_case(case(session))
        reference = session.finish()
        plan = session.encode_plan()
        self.assertEqual(10, json.loads(plan)['schema_version'])
        result = replay_online_session(plan, factory, reference)
        self.assertTrue(result.matches, result.difference_context)

    def test_topology_drift_rejects_before_source_or_steps_or_checker(self):
        session = configured()
        session.begin()
        candidate = case(session)
        before = (session.runner.event_count, dict(session.runner.local_ticks))
        session.runner.bindings = ()
        session.checker = Mock(side_effect=AssertionError('no checker'))
        with self.assertRaisesRegex(ValueError, 'topology'):
            session.submit_case(candidate)
        self.assertEqual(before, (session.runner.event_count, session.runner.local_ticks))
        self.assertEqual((), session.cases)
        session.checker.assert_not_called()

    def test_wrong_path_direction_and_source_are_side_effect_free(self):
        for change in ('path', 'direction', 'source'):
            session = configured()
            session.begin()
            candidate = case(session)
            if change == 'path': candidate = replace(candidate, path_id='unknown')
            elif change == 'direction': candidate = replace(candidate, direction='CPU_TO_IP')
            else: candidate = replace(candidate, source=replace(candidate.source, component='b'))
            before = session.runner.event_count
            with self.subTest(change=change), self.assertRaises(ValueError):
                session.submit_case(candidate)
            self.assertEqual(before, session.runner.event_count)
            self.assertEqual((), session.cases)

    def test_case_path_cache_does_not_repeat_graph_or_source_scans(self):
        session = configured()
        session.begin()
        candidate = case(session)
        with patch.object(DependencyGraph, 'edge_paths_to', side_effect=AssertionError('no graph compile')), \
             patch.object(DependencyGraph, 'path_identity', side_effect=AssertionError('no path scan')), \
             patch.object(session.runner, 'identity_document', side_effect=AssertionError('no source scan')):
            session.submit_case(candidate)

    def test_submit_case_step_observer_runs_after_each_component_before_next_step(self):
        session = configured()
        session.begin()
        observed = []

        def observe(component, outputs):
            observed.append((component, dict(outputs), dict(session.runner.local_ticks)))

        session.submit_case(case(session), step_observer=observe)

        self.assertEqual(['a', 'b'], [component for component, _, _ in observed])
        self.assertEqual((1, 0), (observed[0][2]['a'], observed[0][2]['b']))
        self.assertEqual((1, 1), (observed[1][2]['a'], observed[1][2]['b']))

    def test_submit_case_stop_after_advance_stops_only_after_complete_batch(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a', 'b')), BatchAdvance(('a', 'b')),
            BatchAdvance(('a', 'b'))))
        observed = []

        def stop_after_advance(index):
            observed.append((index, dict(session.runner.local_ticks)))
            return index == 0

        receipt = session.submit_case(candidate,
            stop_after_advance=stop_after_advance)

        self.assertEqual([(0, {'a': 1, 'b': 1})], observed)
        self.assertEqual({'a': 1, 'b': 1}, receipt.local_ticks_after)
        self.assertEqual(receipt.event_end, session.runner.event_count)
        self.assertEqual(receipt.events,
            session.runner.events_since(receipt.event_start))
        self.assertEqual('running', receipt.status)
        self.assertFalse(session._halted)
        event_count = session.runner.event_count
        retry = session.submit_case(candidate,
            stop_after_advance=stop_after_advance)
        self.assertEqual(receipt, retry)
        self.assertEqual([(0, {'a': 1, 'b': 1})], observed)
        self.assertEqual(event_count, session.runner.event_count)

        reference = session.finish()
        document = json.loads(session.encode_plan())
        self.assertEqual([['a', 'b']], document['cases'][0]['advances'])
        replay = replay_online_session(session.encode_plan(), factory, reference)
        self.assertTrue(replay.matches, replay.difference_context)

    def test_runner_failure_after_single_component_advance_preserves_primary_status(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a',)), BatchAdvance(('b',))))
        stop_calls = []

        def observe(component, _outputs):
            if component == 'a':
                session.runner.failure_status = 'protocol_violation'
                session.runner._status = 'failed'

        receipt = session.submit_case(candidate,
            step_observer=observe,
            stop_after_advance=lambda index: stop_calls.append(index) or False,
            stop_on_runner_failure=True)

        self.assertEqual('protocol_violation', receipt.status)
        self.assertEqual({'a': 1, 'b': 0}, receipt.local_ticks_after)
        self.assertEqual([], stop_calls)
        self.assertTrue(session._halted)
        self.assertEqual('protocol_violation', session._halt_reason)
        document = json.loads(session.encode_plan())
        self.assertEqual(11, document['schema_version'])
        self.assertEqual([['a']], document['cases'][0]['advances'])
        self.assertEqual({
            'phase': 'step', 'case_index': 0, 'case_id': candidate.case_id,
            'command_index': 0, 'error_type': 'RunnerFailed',
            'error_message': 'protocol_violation'}, document['terminal_failure'])

    def test_runner_failure_prefix_mode_rejects_multi_component_advance_before_effects(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(BatchAdvance(('a', 'b')),))

        with self.assertRaisesRegex(ValueError,
                'stop_on_runner_failure requires singleton advances'):
            session.submit_case(candidate, stop_on_runner_failure=True)

        self.assertEqual({'a': 0, 'b': 0}, session.runner.local_ticks)
        self.assertEqual((), session.cases)

    def test_runner_failure_prefix_does_not_require_stop_predicate(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a',)), BatchAdvance(('b',))))

        def observe(component, _outputs):
            if component == 'a':
                session.runner.failure_status = 'protocol_violation'
                session.runner._status = 'failed'

        receipt = session.submit_case(candidate, step_observer=observe,
            stop_on_runner_failure=True)

        self.assertEqual('protocol_violation', receipt.status)
        self.assertEqual({'a': 1, 'b': 0}, receipt.local_ticks_after)
        self.assertTrue(session._halted)
        self.assertEqual([['a']], json.loads(session.encode_plan())['cases'][0]['advances'])

    def test_runner_failure_prefix_replays_and_rejects_unexecuted_suffix(self):
        def failing_factory():
            runner = factory()
            component = runner.sessions['a']
            original = component.step_local

            def fail_after_step(inputs):
                outputs = original(inputs)
                runner.failure_status = 'protocol_violation'
                runner._status = 'failed'
                return outputs

            component.step_local = fail_after_step
            return runner

        session = configured(failing_factory())
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a',)), BatchAdvance(('b',))))
        receipt = session.submit_case(candidate, stop_on_runner_failure=True)
        self.assertEqual('protocol_violation', receipt.status)
        reference = session.finish()
        plan = session.encode_plan()

        replay = replay_online_session(plan, failing_factory, reference)
        self.assertTrue(replay.matches, replay.difference_context)

        altered = json.loads(plan)
        altered['cases'][-1]['advances'].append(['b'])
        malformed = json.dumps(altered, sort_keys=True,
            separators=(',', ':'), ensure_ascii=False).encode()
        with self.assertRaisesRegex(ValueError, 'invalid online terminal failure'):
            replay_online_session(malformed, failing_factory, reference)

    def test_runner_step_exception_saves_only_through_failed_singleton_and_replays(self):
        def failing_factory():
            runner = factory()
            original = runner.sessions['b'].step_local

            def fail_step(_inputs):
                raise RuntimeError('injected component command failure')

            runner.sessions['b'].step_local = fail_step
            return runner

        session = configured(failing_factory())
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a',)), BatchAdvance(('b',)), BatchAdvance(('a',))))

        with self.assertRaisesRegex(RuntimeError,
                'injected component command failure'):
            session.submit_case(candidate, stop_on_runner_failure=True)

        document = json.loads(session.encode_plan())
        self.assertEqual([['a'], ['b']], document['cases'][0]['advances'])
        self.assertEqual({
            'phase': 'step', 'case_index': 0, 'case_id': candidate.case_id,
            'command_index': 1, 'error_type': 'RunnerFailed',
            'error_message': 'uncertain_effect'}, document['terminal_failure'])
        reference = session.finish()
        replay = replay_online_session(session.encode_plan(), failing_factory,
            reference)
        self.assertTrue(replay.matches, replay.difference_context)

    def test_submit_case_without_stop_predicate_executes_full_schedule(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a', 'b')), BatchAdvance(('a', 'b')),
            BatchAdvance(('a', 'b'))))
        receipt = session.submit_case(candidate)

        self.assertEqual({'a': 3, 'b': 3}, receipt.local_ticks_after)
        self.assertEqual(receipt.event_end, session.runner.event_count)
        self.assertFalse(session._halted)

    def test_submit_case_invalid_stop_result_halts_after_uncertain_effect(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a', 'b')), BatchAdvance(('a', 'b'))))

        with self.assertRaisesRegex(ValueError, 'stop_after_advance must return bool'):
            session.submit_case(candidate, stop_after_advance=lambda _index: 1)

        self.assertEqual({'a': 1, 'b': 1}, session.runner.local_ticks)
        self.assertTrue(session._halted)
        self.assertEqual('uncertain_effect', session._halt_reason)

    def test_submit_case_raising_stop_callback_retains_primary_failure(self):
        session = configured()
        session.begin()
        candidate = replace(case(session), advances=(
            BatchAdvance(('a', 'b')), BatchAdvance(('a', 'b'))))

        def stop_after_advance(_index):
            raise LookupError('stop predicate failed')

        with self.assertRaisesRegex(LookupError, 'stop predicate failed'):
            session.submit_case(candidate, stop_after_advance=stop_after_advance)

        self.assertEqual({'a': 1, 'b': 1}, session.runner.local_ticks)
        self.assertTrue(session._halted)
        self.assertEqual('uncertain_effect', session._halt_reason)
        self.assertEqual('step', session._terminal_failure['phase'])
        self.assertEqual(0, session._terminal_failure['command_index'])
        document = json.loads(session.encode_plan())
        self.assertEqual([['a', 'b']], document['cases'][0]['advances'])

    def test_submit_case_non_callable_stop_predicate_refuses_before_effects(self):
        session = configured()
        session.begin()
        before = (session.runner.event_count, dict(session.runner.local_ticks))

        with self.assertRaisesRegex(ValueError,
                'online stop_after_advance must be callable'):
            session.submit_case(case(session), stop_after_advance=object())

        self.assertEqual(before,
            (session.runner.event_count, dict(session.runner.local_ticks)))
        self.assertEqual((), session.cases)
        self.assertFalse(session._halted)

    def test_submit_case_legacy_execute_override_gets_no_empty_keywords(self):
        from types import SimpleNamespace

        session = configured()
        session.begin()
        calls = []
        receipt = SimpleNamespace(case_id='one')

        def execute(*args):
            calls.append(args)
            return receipt

        session._execute_case = execute
        self.assertIs(session.submit_case(case(session)), receipt)
        self.assertEqual(4, len(calls[0]))

    def test_tampered_contract_rejects_before_factory(self):
        session = configured()
        session.begin()
        reference = session.finish()
        document = json.loads(session.encode_plan())
        document['runtime_paths']['declaration']['contract']['graph_sha256'] = '0' * 64
        plan = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
        reference = replace(reference, genome_sha256=hashlib.sha256(plan).hexdigest())
        fail = Mock(side_effect=AssertionError('no factory'))
        with self.assertRaises(ValueError):
            replay_online_session(plan, fail, reference)
        fail.assert_not_called()


if __name__ == '__main__':
    unittest.main()
