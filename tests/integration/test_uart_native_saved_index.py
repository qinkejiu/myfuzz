"""Saved native model index uses authenticated compiled declarations, not aliases."""
from copy import deepcopy
import unittest
from tests.scenario.test_runtime_edge_index import fixture,index

class NativeSavedIndexTests(unittest.TestCase):
    def documents(self):
        compiled,contract=fixture();subject=index(compiled,contract)
        configuration={'schema_version':'source_provenance_configuration.v1',
            'edge_index':subject.document(),'edge_index_sha256':subject.identity_sha256}
        return {'runtime_paths':compiled,'provenance_configuration':configuration}, {'runtime_paths':deepcopy(compiled),'provenance_configuration':deepcopy(configuration)}
    def test_real_compiled_index_is_rebuilt_and_exactly_bound(self):
        from tests.integration.test_uart_native_irq_taken_real import _verified_saved_native_index
        plan,manifest=self.documents();subject=_verified_saved_native_index(plan,manifest)
        self.assertEqual(subject.identity_sha256,plan['provenance_configuration']['edge_index_sha256'])
        self.assertEqual(subject.source_owner_ref('s',subject.document()['source_owner_refs'][0]['path_id'],'IP_TO_IP','a','pin',0,1),'external')
    def test_missing_altered_index_contract_and_manifest_rejected(self):
        from tests.integration.test_uart_native_irq_taken_real import _verified_saved_native_index
        for mode in ('hash','index','manifest','contract','missing','owner','numeric'):
            plan,manifest=self.documents()
            if mode=='hash':plan['provenance_configuration']['edge_index_sha256']='0'*64
            if mode=='index':plan['provenance_configuration']['edge_index']['schema_version']='forged'
            if mode=='manifest':manifest['runtime_paths']['graph_sha256']='0'*64
            if mode=='contract':plan['runtime_paths']['declaration']['contract']['graph_sha256']='0'*64
            if mode=='missing':plan.pop('provenance_configuration')
            if mode=='owner':plan['provenance_configuration']['edge_index']['source_owner_refs'][0]['producer_ref']='s'
            if mode=='numeric':plan['provenance_configuration']['edge_index']['source_owner_refs'][0]['width']=1.0
            with self.subTest(mode=mode),self.assertRaises(ValueError):_verified_saved_native_index(plan,manifest)

class NativeWirePrefixEqualityTests(unittest.TestCase):
    def test_wire_tuple_list_equal_but_numeric_types_remain_distinct(self):
        from tests.integration.test_uart_native_irq_taken_real import _assert_full_wire_prefix
        _assert_full_wire_prefix(self,[{'event_id':1,'source':('uart','irq')}],[{'event_id':1,'source':['uart','irq']}])
        for actual in (True,1.0):
            with self.subTest(actual=actual),self.assertRaises(AssertionError):
                _assert_full_wire_prefix(self,[{'event_id':1,'value':actual}],[{'event_id':1,'value':1}])
    def test_count_and_first_changed_event_have_compact_diagnostics(self):
        from tests.integration.test_uart_native_irq_taken_real import _assert_full_wire_prefix
        with self.assertRaisesRegex(AssertionError,'event count'):_assert_full_wire_prefix(self,[],[{'event_id':1}])
        with self.assertRaisesRegex(AssertionError,'index=1.*event_id=8'):
            _assert_full_wire_prefix(self,[{'event_id':7},{'event_id':8,'value':2}],[{'event_id':7},{'event_id':8,'value':3}])
