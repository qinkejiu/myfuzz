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
