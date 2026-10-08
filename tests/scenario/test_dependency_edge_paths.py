"""Edge-aware proof DAGs retain OR identity without changing legacy mapping."""
from dataclasses import replace
import unittest

from myfuzz.scenario.dependency import DependencyGraph, DependencyPath, DependencyRule, FuzzableSource

DIRECTION = 'IP_TO_CPU'


def source(name):
    return FuzzableSource(name, 'ip', name, 0, 1, (DIRECTION,))


def rule(target, *children, kind='DATA_BINDING'):
    return DependencyRule(target, tuple(children), kind)


class DependencyEdgePathTests(unittest.TestCase):
    def test_same_source_or_remains_distinct_and_legacy_unchanged(self):
        graph = DependencyGraph(sources=(source('s'),), rules=(rule('t', 's'), rule('t', 's', kind='EVENT_ORDER')))
        self.assertEqual((DependencyPath('t', ('s',)),), graph.paths_to('t', direction=DIRECTION))
        paths = graph.edge_paths_to('t', direction=DIRECTION)
        self.assertEqual(2, len(paths))
        self.assertEqual([(0,), (1,)], [tuple(edge.rule_index for edge in path.edges) for path in paths])
        self.assertNotEqual(graph.path_identity(paths[0], direction=DIRECTION), graph.path_identity(paths[1], direction=DIRECTION))

    def test_and_keeps_all_prerequisite_edges_and_rejects_missing_member(self):
        graph = DependencyGraph(sources=(source('a'), source('b')), rules=(rule('t', 'a', 'b'),))
        path, = graph.edge_paths_to('t', direction=DIRECTION)
        self.assertEqual(('a', 'b'), path.source_ids)
        self.assertEqual((0, 1), tuple(edge.prerequisite_index for edge in path.edges))
        with self.assertRaises(ValueError):
            graph.path_identity(replace(path, edges=path.edges[:1]), direction=DIRECTION)

    def test_shared_or_uses_consistent_rule_and_deduplicates_shared_edges(self):
        graph = DependencyGraph(sources=(source('s'),), rules=(
            rule('t', 'left', 'right'), rule('left', 'shared'), rule('right', 'shared'),
            rule('shared', 's'), rule('shared', 's', kind='EVENT_ORDER')))
        paths = graph.edge_paths_to('t', direction=DIRECTION)
        self.assertEqual(2, len(paths))
        self.assertEqual([3, 4], [next(edge.rule_index for edge in p.edges if edge.target == 'shared') for p in paths])
        for path in paths:
            self.assertEqual(5, len(path.edges))
            self.assertEqual(('s',), path.source_ids)
            self.assertEqual(64, len(graph.path_identity(path, direction=DIRECTION)))

    def test_cycles_direction_depth_and_source_less_rules(self):
        graph = DependencyGraph(sources=(source('s'),), rules=(rule('t', 'loop'), rule('loop', 't'), rule('t', 's')))
        self.assertEqual(1, len(graph.edge_paths_to('t', direction=DIRECTION)))
        self.assertEqual((), graph.edge_paths_to('loop', direction=DIRECTION, max_depth=1))
        self.assertEqual((), graph.edge_paths_to('t', direction='CPU_TO_IP'))
        dead = DependencyGraph(sources=(), rules=(rule('t', 'missing'),))
        self.assertEqual((), dead.edge_paths_to('t', direction=DIRECTION))
        with self.assertRaises(ValueError):
            dead.path_identity(DependencyPath('t', ()), direction=DIRECTION)

    def test_global_rule_order_roundtrip_and_identity_bind_entire_graph(self):
        graph = DependencyGraph(sources=(source('z'), source('a')), rules=(rule('z_target', 'z'), rule('a_target', 'a'), rule('z_target', 'a')))
        doc = graph.edge_document()
        self.assertEqual(['z_target', 'a_target', 'z_target'], [r['target'] for r in doc['rules']])
        restored = DependencyGraph.from_edge_document(doc)
        self.assertEqual(doc, restored.edge_document())
        path = graph.edge_paths_to('z_target', direction=DIRECTION)[0]
        self.assertEqual(graph.path_identity(path, direction=DIRECTION), restored.path_identity(path, direction=DIRECTION))
        changed = DependencyGraph(sources=(source('z'), source('a')), rules=(rule('z_target', 'z'), rule('a_target', 'a', kind='EVENT_ORDER'), rule('z_target', 'a')))
        self.assertNotEqual(graph.path_identity(path, direction=DIRECTION), changed.path_identity(path, direction=DIRECTION))
        doc['edges'][0]['kind'] = 'EVENT_ORDER'
        with self.assertRaises(ValueError):
            DependencyGraph.from_edge_document(doc)

    def test_forged_edge_source_target_order_and_selected_cycle_rejected(self):
        graph = DependencyGraph(sources=(source('s'),), rules=(rule('t', 'middle'), rule('middle', 's'), rule('middle', 't')))
        path, = graph.edge_paths_to('t', direction=DIRECTION)
        invalid = [replace(path, source_ids=('unknown',)), replace(path, target='other'),
                   replace(path, edges=tuple(reversed(path.edges))),
                   replace(path, edges=(replace(path.edges[0], kind='EVENT_ORDER'), path.edges[1])),
                   replace(path, edges=(path.edges[0], graph.edge_paths_to('s', direction=DIRECTION)[0].edges))]
        for forged in invalid:
            with self.subTest(path=forged), self.assertRaises(ValueError):
                graph.path_identity(forged, direction=DIRECTION)
        from myfuzz.scenario.dependency import DependencyEdge
        cycle = DependencyPath('t', ('s',), (path.edges[0], DependencyEdge(2, 0, 't', 'middle', 'DATA_BINDING')))
        with self.assertRaises(ValueError):
            graph.path_identity(cycle, direction=DIRECTION)

    def test_strict_request_limits_and_path_count(self):
        graph = DependencyGraph(sources=(source('s'),), rules=tuple(rule('t', 's') for _ in range(8)))
        self.assertEqual(3, len(graph.edge_paths_to('t', direction=DIRECTION, max_paths=3)))
        for changes in ({'max_depth': True}, {'max_paths': 1.5}, {'max_depth': 0}, {'max_paths': 0}, {'max_depth': 10000}, {'max_paths': 10000000}, {'direction': 1}):
            options = {'direction': DIRECTION, **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                graph.edge_paths_to('t', **options)

    def test_wide_and_product_stops_at_explicit_work_bound(self):
        sources = tuple(source('s' + str(i)) for i in range(2))
        rules = [rule('t', *tuple('n' + str(i) for i in range(24)))]
        rules.extend(rule('n' + str(i), 's' + str(j)) for i in range(24) for j in range(2))
        graph = DependencyGraph(sources=sources, rules=tuple(rules))
        self.assertEqual(3, len(graph.edge_paths_to('t', direction=DIRECTION, max_paths=3)))
        dead = DependencyGraph(sources=sources,
            rules=(rule('dead', 't', 'missing'), *rules))
        self.assertEqual((), dead.edge_paths_to('dead', direction=DIRECTION, max_paths=1))
        from unittest.mock import patch
        with patch('myfuzz.scenario.dependency._EDGE_WORK_LIMIT', 16), self.assertRaisesRegex(ValueError, 'work limit'):
            graph.edge_paths_to('t', direction=DIRECTION, max_paths=1)

    def test_online_roundtrip_requires_explicit_online_source_factory(self):
        from myfuzz.scenario.online_case_decoder import OnlineDependencyGraph, OnlineDependencySource
        graph = OnlineDependencyGraph(sources=(OnlineDependencySource('instruction', 'instruction', 'cpu', ('CPU_TO_IP',)),), rules=(rule('t', 'instruction'),))
        doc = graph.edge_document()
        with self.assertRaises(ValueError):
            DependencyGraph.from_edge_document(doc)
        restored = OnlineDependencyGraph.from_edge_document(doc, source_factory=OnlineDependencySource)
        self.assertEqual(doc, restored.edge_document())
        path, = restored.edge_paths_to('t', direction='CPU_TO_IP')
        self.assertEqual(('instruction',), path.source_ids)

    def test_sources_are_terminal_even_when_rule_target_and_repeated_and_keeps_indices(self):
        graph = DependencyGraph(sources=(source('s'),), rules=(rule('s', 'unresolved'), rule('t', 's', 's')))
        direct, = graph.edge_paths_to('s', direction=DIRECTION)
        self.assertEqual(DependencyPath('s', ('s',)), direct)
        graph.path_identity(direct, direction=DIRECTION)
        path, = graph.edge_paths_to('t', direction=DIRECTION)
        self.assertEqual((0, 1), tuple(edge.prerequisite_index for edge in path.edges))
        self.assertEqual(('s',), path.source_ids)
        graph.path_identity(path, direction=DIRECTION)

    def test_deep_selected_path_identity_does_not_reapply_default_depth(self):
        graph = DependencyGraph(sources=(source('s'),), rules=tuple(
            rule('n' + str(i), 'n' + str(i + 1) if i < 30 else 's') for i in range(31)))
        self.assertEqual((), graph.edge_paths_to('n0', direction=DIRECTION))
        path, = graph.edge_paths_to('n0', direction=DIRECTION, max_depth=32)
        self.assertEqual(31, len(path.edges))
        self.assertEqual(64, len(graph.path_identity(path, direction=DIRECTION)))

    def test_disconnected_extra_edge_and_multiple_or_rules_are_not_paths(self):
        graph = DependencyGraph(sources=(source('s'),), rules=(rule('t', 's'), rule('t', 's', kind='EVENT_ORDER'), rule('unrelated', 's')))
        a, b = graph.edge_paths_to('t', direction=DIRECTION)
        unrelated, = graph.edge_paths_to('unrelated', direction=DIRECTION)
        for forged in (replace(a, edges=a.edges + b.edges), replace(a, edges=a.edges + unrelated.edges)):
            with self.assertRaises(ValueError):
                graph.path_identity(forged, direction=DIRECTION)

    def test_edge_fields_and_document_indices_reject_boolean_and_nonstrings(self):
        from myfuzz.scenario.dependency import DependencyEdge
        fields = dict(rule_index=0, prerequisite_index=0, prerequisite='s', target='t', kind='DATA_BINDING')
        for changes in ({'rule_index': True}, {'prerequisite_index': -1}, {'kind': []}, {'target': 1}, {'prerequisite': ''}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DependencyEdge(**{**fields, **changes})
        graph = DependencyGraph(sources=(source('s'),), rules=(rule('t', 's'),))
        doc = graph.edge_document()
        doc['edges'][0]['rule_index'] = False
        with self.assertRaises(ValueError):
            DependencyGraph.from_edge_document(doc)
