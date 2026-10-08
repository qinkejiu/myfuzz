"""Witness metadata never creates or strengthens an interaction edge."""
from copy import deepcopy
import unittest

from myfuzz.scenario.event_journal import EventJournal
from myfuzz.scenario.interaction_feedback import InteractionFeedback, summarize_interactions


def metadata(case='old', origins=(), candidates=(), resource=None):
    return dict(schema_version='event_source_provenance.v1',
                observed_case={'case_id': case, 'case_index': 0 if case == 'old' else 1},
                origin_admission_ids=list(origins), origin_status='known' if origins else 'unknown',
                unknown_writer_ids=[], proof_scope='observation_only',
                edge_candidates=list(candidates), resource=resource)


def bound_events():
    return [
        {'event_id': 1, 'component': 'a', 'outputs': {'out': 7},
         'provenance': metadata(origins=['origin-a'], candidates=[{'rule_index': 999}],
                                resource={'memory_id': 'ram', 'version': 3})},
        {'event_id': 2, 'kind': 'dataflow_delivery', 'source': ['a', 'out'],
         'target': ['b', 'in'], 'value': 7, 'producer_event_id': 1,
         'provenance': metadata(origins=['origin-a'], candidates=[{'rule_index': 1}, {'rule_index': 2}])},
        {'event_id': 3, 'component': 'b', 'inputs': {'in': 7},
         'provenance': metadata('new')},
    ]


class InteractionEdgeProvenanceTests(unittest.TestCase):
    def test_consumed_bound_edge_keeps_delivery_ambiguity_and_consumer_case(self):
        summary = summarize_interactions(bound_events())
        edge = summary['edges'][0]
        self.assertEqual(edge['provenance'], {
            'schema_version': 'interaction_edge_provenance.v1',
            'observed_case': {'case_id': 'new', 'case_index': 1},
            'origin_admission_ids': ['origin-a'],
            'edge_candidates': [{'rule_index': 1}, {'rule_index': 2}],
            'resource_snapshots': [{'event_id': 1, 'resource': {'memory_id': 'ram', 'version': 3}}],
            'proof_scope': 'witness_metadata_only'})
        self.assertEqual(summary['closed_loops'], [])

    def test_missing_delivery_consumer_wrong_values_never_create_edge(self):
        for mode in ('delivery', 'consumer', 'producer_value', 'consumer_value'):
            events = bound_events()
            if mode == 'delivery':
                events.pop(1)
            elif mode == 'consumer':
                events.pop(2)
            elif mode == 'producer_value':
                events[0]['outputs']['out'] = 9
            else:
                events[2]['inputs']['in'] = 9
            with self.subTest(mode=mode):
                self.assertEqual([], summarize_interactions(events)['edges'])

    def test_unknown_and_unrelated_history_do_not_manufacture_origins(self):
        events = bound_events()
        for event in events:
            event['provenance']['origin_admission_ids'] = []
        events[0]['provenance']['unknown_writer_ids'] = ['writer:old']
        events.insert(0, {'event_id': 0, 'kind': 'source_injection', 'component': 'a',
                         'port': 'in', 'provenance': metadata(origins=['unrelated'])})
        for event in events:
            event['event_id'] += 1
            if 'producer_event_id' in event:
                event['producer_event_id'] += 1
        edge = summarize_interactions(events)['edges'][0]
        self.assertEqual([], edge['provenance']['origin_admission_ids'])

    def test_legacy_shape_counts_and_mixed_witnesses_are_preserved(self):
        events = bound_events()
        legacy = [{k: deepcopy(v) for k, v in row.items() if k != 'provenance'} for row in events]
        original = summarize_interactions(legacy)
        self.assertNotIn('provenance', original['edges'][0])
        del events[0]['provenance']
        mixed = summarize_interactions(events)
        self.assertEqual(original['feature_counts'], mixed['feature_counts'])
        self.assertEqual(original['edges'][0], {k: v for k, v in mixed['edges'][0].items() if k != 'provenance'})
        self.assertEqual(['origin-a'], mixed['edges'][0]['provenance']['origin_admission_ids'])

    def test_suffix_journal_lookup_matches_offline_without_history_scan(self):
        events = bound_events()
        journal = EventJournal(chunk_size=1)
        calls = []
        def lookup(event_id):
            calls.append(event_id)
            return journal[event_id - 1] if 0 < event_id <= len(journal) else None
        online = InteractionFeedback(event_lookup=lookup)
        offline = InteractionFeedback()
        for event in events:
            journal.append(deepcopy(event))
            online.ingest([event])
            offline.ingest([event])
            self.assertEqual(offline.incremental_summary(), online.incremental_summary())
        self.assertEqual(summarize_interactions(events), online.summary())
        self.assertLess(len(calls), 25)
        result = online.summary()
        result['edges'][0]['provenance']['edge_candidates'].clear()
        self.assertEqual(2, len(online.summary()['edges'][0]['provenance']['edge_candidates']))
        self.assertEqual(events[0], journal[0])
        journal.close()

    def test_mmio_consumption_only_uses_real_delivery_candidates(self):
        tx = {'source_component': 'cpu', 'source_epoch': 0, 'source_sequence': 1}
        fields = dict(device_id='uart', source_transaction=tx, write=False, address=0x1018,
                      offset=0x18, beat_bytes=4, byte_enable=15, write_value=None)
        events = [
            {'event_id': 1, 'kind': 'mmio_acceptance', **fields,
             'provenance': metadata(origins=['request'], candidates=[{'rule_index': 999}])},
            {'event_id': 2, 'kind': 'mmio_delivery', **fields, 'read_value': 65,
             'provenance': metadata(origins=['rx-frame'], candidates=[{'rule_index': 7}])},
            {'event_id': 3, 'component': 'cpu', 'inputs': {},
             'outputs': dict(data_rsp_consumed=1, data_rsp_source_epoch=0,
                             data_rsp_source_sequence=1, data_rsp_rdata=65),
             'provenance': metadata('new')},
        ]
        consumed = summarize_interactions(events)['edges'][-1]
        self.assertEqual('mmio_read_consumed', consumed['kind'])
        self.assertEqual(['rx-frame'], consumed['provenance']['origin_admission_ids'])
        self.assertEqual([{'rule_index': 7}], consumed['provenance']['edge_candidates'])
        for mode in ('missing_delivery', 'missing_consumer', 'wrong_value'):
            changed = deepcopy(events)
            if mode == 'missing_delivery':
                changed.pop(1)
            elif mode == 'missing_consumer':
                changed.pop(2)
            else:
                changed[2]['outputs']['data_rsp_rdata'] = 66
            with self.subTest(mode=mode):
                self.assertFalse(any(edge['kind'] == 'mmio_read_consumed'
                                     for edge in summarize_interactions(changed)['edges']))

    def test_irq_actual_witnesses_carry_metadata_without_path_promotion(self):
        endpoints = dict(source=['uart', 'irq'], target=['cpu', 'irq'], source_event_id=1)
        events = [
            {'event_id': 1, 'kind': 'source_start', **endpoints,
             'provenance': metadata(candidates=[{'rule_index': 8}])},
            {'event_id': 2, 'kind': 'pulse_start', **endpoints,
             'start_cpu_tick': 4, 'end_cpu_tick_exclusive': 5,
             'provenance': metadata(candidates=[{'rule_index': 8}, {'rule_index': 9}])},
            {'event_id': 3, 'component': 'cpu', 'inputs': {'irq': 1}, 'local_tick': 4,
             'provenance': metadata('new')},
        ]
        result = summarize_interactions(events)
        edge = result['edges'][0]
        self.assertEqual([{'rule_index': 8}, {'rule_index': 9}], edge['provenance']['edge_candidates'])
        self.assertEqual([], result['observed_paths'])
        self.assertEqual([], result['closed_loops'])

    def test_mmio_context_uses_consumer_step_without_importing_its_origins(self):
        fields = dict(device_id='uart', source_transaction={'source_component': 'cpu'},
                      write=True, address=0x101c, offset=0x1c, beat_bytes=4,
                      byte_enable=15, write_value=65)
        events = [
            {'event_id': 1, 'kind': 'mmio_acceptance', **fields,
             'provenance': metadata(origins=['request'])},
            {'event_id': 2, 'component': 'uart', 'outputs': {},
             'provenance': metadata('new', origins=['unrelated-consumer-context'],
                                    candidates=[{'rule_index': 999}])},
            {'event_id': 3, 'kind': 'mmio_delivery', **fields, 'producer_event_id': 2,
             'provenance': metadata('old', candidates=[{'rule_index': 7}])},
        ]
        edge = summarize_interactions(events)['edges'][0]
        self.assertEqual('new', edge['provenance']['observed_case']['case_id'])
        self.assertEqual(['request'], edge['provenance']['origin_admission_ids'])
        self.assertEqual([{'rule_index': 7}], edge['provenance']['edge_candidates'])
        del events[1]['provenance']
        self.assertIsNone(summarize_interactions(events)['edges'][0]['provenance']['observed_case'])

    def test_wrong_metadata_schema_is_ignored_without_changing_legacy_edge(self):
        events = bound_events()
        legacy = [{k: deepcopy(v) for k, v in row.items() if k != 'provenance'} for row in events]
        for event in events:
            event['provenance']['schema_version'] = 'unrecognized'
        self.assertEqual(summarize_interactions(legacy), summarize_interactions(events))

    def test_consumer_in_witness_keeps_resource_but_cannot_add_unrelated_origin(self):
        events = bound_events()
        events[-1]['provenance'] = metadata('new', origins=['unrelated-consumer'],
                                           resource={'memory_id': 'consumer_ram', 'version': 4})
        provenance = summarize_interactions(events)['edges'][0]['provenance']
        self.assertEqual(['origin-a'], provenance['origin_admission_ids'])
        self.assertEqual({'event_id': 3, 'resource': {'memory_id': 'consumer_ram', 'version': 4}},
                         provenance['resource_snapshots'][-1])

    def test_explicit_mmio_producer_step_metadata_is_preserved_by_point_lookup(self):
        fields = dict(device_id='uart', source_transaction={'source_component': 'cpu'},
                      write=True, address=0x101c, offset=0x1c, beat_bytes=4,
                      byte_enable=15, write_value=65)
        events = [
            {'event_id': 1, 'component': 'cpu',
             'outputs': dict(data_req_accepted=1, data_write=1, data_addr=0x101c, data_wdata=65),
             'provenance': metadata(origins=['producer'], resource={'memory_id': 'ram', 'version': 3})},
            {'event_id': 2, 'kind': 'mmio_acceptance', **fields, 'producer_event_id': 1},
            {'event_id': 3, 'component': 'uart', 'outputs': {}, 'provenance': metadata('new')},
            {'event_id': 4, 'kind': 'mmio_delivery', **fields, 'producer_event_id': 3},
        ]
        edge = summarize_interactions(events)['edges'][0]
        self.assertEqual([2, 4], edge['witness_event_ids'])
        self.assertEqual(['producer'], edge['provenance']['origin_admission_ids'])
        self.assertEqual([{'event_id': 1, 'resource': {'memory_id': 'ram', 'version': 3}}],
                         edge['provenance']['resource_snapshots'])
