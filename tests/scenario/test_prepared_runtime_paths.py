"""Static graph work is performed once; runner binding checks only topology."""
import unittest
from unittest.mock import patch
from tests.scenario import test_runtime_path_contract as fixtures


class PreparedRuntimePathsTests(unittest.TestCase):
    def fixture(self):
        return fixtures.RuntimeContractTests().fixture()

    def test_bind_reuses_static_material_without_graph_work(self):
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        graph, runner, contract, path = self.fixture()
        prepared = PreparedRuntimePathContract(graph, contract, (('IP_TO_IP', path),))
        with patch.object(type(graph), 'edge_document', side_effect=AssertionError('no graph scan')), \
             patch.object(type(graph), 'path_identity', side_effect=AssertionError('no path hash')), \
             patch.object(type(graph), 'edge_paths_to', side_effect=AssertionError('no enumeration')):
            first = prepared.bind(runner)
            second = prepared.bind(runner, path_ids=prepared.path_ids)
            first.validate_topology()
        self.assertEqual(first.identity_sha256, second.identity_sha256)
        self.assertEqual(('IP_TO_IP', path), prepared.resolve_path_id(prepared.path_ids[0]))

    def test_document_roundtrip_and_tampered_identity_rejection(self):
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        graph, runner, contract, path = self.fixture()
        prepared = PreparedRuntimePathContract(graph, contract, (('IP_TO_IP', path),))
        doc = prepared.document()
        restored = PreparedRuntimePathContract.from_document(doc)
        self.assertEqual(doc, restored.document())
        self.assertEqual(prepared.bind(runner).identity_sha256, restored.bind(runner).identity_sha256)
        doc['selections'][0]['path_id'] = '0' * 64
        with self.assertRaises(ValueError):
            PreparedRuntimePathContract.from_document(doc)

    def test_missing_binding_and_unknown_selected_id_reject_without_start(self):
        from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
        graph, runner, contract, path = self.fixture()
        prepared = PreparedRuntimePathContract(graph, contract, (('IP_TO_IP', path),))
        with self.assertRaises(ValueError):
            prepared.bind(runner, path_ids=('unknown',))
        runner.bindings = ()
        with self.assertRaises(ValueError):
            prepared.bind(runner)
        runner.begin_test.assert_not_called()
        runner.identity_document.assert_not_called()


if __name__ == '__main__':
    unittest.main()
