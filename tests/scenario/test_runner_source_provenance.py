"""Evidence preserves input origins independently of later observation cases."""
from dataclasses import asdict
import hashlib
import unittest
from types import SimpleNamespace

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
from myfuzz.scenario.source_provenance import SourceAdmission
from tests.scenario.test_session_runtime_paths import declaration, factory


def configured_runner(journal=False, gpio_causal=False):
    runner = factory()
    if gpio_causal:
        runner.sessions['b'].routed_register_access_enabled = True
    if journal:
        runner.enable_event_journal(chunk_size=2)
    graph, contract, paths = declaration()
    prepared = PreparedRuntimePathContract(graph, contract, paths)
    material = {**prepared.bind(runner).document(), 'declaration': prepared.document()}
    runner.configure_provenance(RuntimeEdgeIndex(material, contract.document()))
    return runner, paths[0][0], prepared.path_ids[0]


def admission(direction, path, *, role='fuzz_source', action='instruction-a'):
    return SourceAdmission.create(case_id='case-a', case_index=0, source_id='s',
        path_id=path, direction=direction, component='a', action_id=action,
        role=role, input_kind='instruction', input_sha256=hashlib.sha256(b'\x13\0\0\0').hexdigest())


class RunnerSourceProvenanceTests(unittest.TestCase):
    def test_uart_fifo_stream_has_exact_receipt_bridge_and_preserves_raw_nonce(self):
        runner = factory()
        runner.sessions['a'].uart_fifo_observation_enabled = True
        graph, contract, paths = declaration()
        prepared = PreparedRuntimePathContract(graph, contract, paths)
        runner.configure_provenance(RuntimeEdgeIndex(
            {**prepared.bind(runner).document(), 'declaration': prepared.document()}, contract.document()))
        received = []
        runner._uart_consumption_tracker = SimpleNamespace(consume=lambda event: received.append(event) or ())
        scope = {'component': 'a', 'reset_epoch': 0, 'command_sequence': 7}
        nonce = {'execution': 'physical-nonce', 'sequence': 7}
        drive = {'receipt_id': nonce, 'action_id': 'unknown', 'frame_id': 'frame0',
                 'admission_id': None, 'drive_tick': 1, 'bit_index': 0, 'bit_value': 0}
        raw = [{'kind': 'uart_tick_observation', 'reset_epoch': 0, 'command_scope': scope,
                'local_tick': 1, 'receipt_id': nonce, 'physical_rx_ref': drive},
               {'kind': 'uart_rdata_access', 'reset_epoch': 0, 'command_scope': scope,
                'local_tick': 1, 'request_tick': 1, 'response_tick': 1,
                'read_capture': {'actual_receipt_ref': {'command_scope': scope, 'local_tick': 1}},
                'response_capture': {'actual_receipt_ref': {'command_scope': scope, 'local_tick': 1}}}]
        runner.sessions['a'].uart_events = raw
        runner._append_external_events('a', 1)
        self.assertEqual(2, len(received))
        self.assertEqual(received[0]['event_id'], received[1]['actual_request_event_id'])
        self.assertEqual(received[0]['event_id'], received[1]['actual_response_event_id'])
        self.assertEqual('physical-nonce', raw[0]['receipt_id']['execution'])
        self.assertEqual('local-driver:a:1', received[0]['receipt_id']['execution'])
        self.assertEqual(7, received[0]['receipt_id']['sequence'])
        self.assertIsNone(runner._gpio_consumption_tracker)
        from copy import deepcopy
        malformed = deepcopy(raw[1])
        malformed['read_capture']['actual_receipt_ref']['command_scope'] = dict(scope, command_sequence=99)
        malformed['response_capture']['actual_receipt_ref']['command_scope'] = dict(scope, command_sequence=99)
        malformed['actual_request_event_id'] = received[0]['event_id']
        malformed['actual_response_event_id'] = received[0]['event_id']
        # A forged event ID cannot repair a mismatching measured command scope.
        runner.sessions['a'].uart_events.append(malformed)
        runner._append_external_events('a', 1)
        self.assertNotIn('actual_request_event_id', received[-1])
        self.assertNotIn('actual_response_event_id', received[-1])
        self.assertEqual('physical-nonce', raw[0]['physical_rx_ref']['receipt_id']['execution'])
        bool_reference = deepcopy(raw[1])
        bool_reference['read_capture']['actual_receipt_ref']['local_tick'] = True
        runner.sessions['a'].uart_events.append(bool_reference)
        runner._append_external_events('a', 1)
        self.assertNotIn('actual_request_event_id', received[-1])

    def test_registered_logical_source_uses_compiled_physical_owner_alias(self):
        from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
        from myfuzz.scenario.ownership import compile_ownership, InputField, InputOwner
        from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract
        from tests.scenario.test_runtime_edge_index import digest
        from tests.scenario.test_gpio_consumption_versions import tick, probes
        runner = factory()
        runner.sessions['b'].routed_register_access_enabled = True
        runner.ownership = compile_ownership((InputField('b', 'gpio_in', 32),),
            (InputOwner('b', 'gpio_in', 0, 8, 'fixed', 'zero'),
             InputOwner('b', 'gpio_in', 8, 1, 'source', 'external_b.pin8'),
             InputOwner('b', 'gpio_in', 9, 23, 'fixed', 'zero')))
        graph = DependencyGraph(sources=(FuzzableSource('b.external_pin8', 'b', 'gpio_in',
            8, 1, ('IP_TO_CPU',)),), rules=(DependencyRule('sample', ('b.external_pin8',), 'EVENT_ORDER'),))
        contract = RuntimePathContract(digest(graph.edge_document()),
            (RuntimeNode('b.external_pin8', 'b', 'physical', 'gpio_in', 8, 1),
             RuntimeNode('sample', 'b', 'physical', 'gpio_in_sync', 8, 1)), ())
        paths = tuple(('IP_TO_CPU', p) for p in graph.edge_paths_to('sample', direction='IP_TO_CPU'))
        prepared = PreparedRuntimePathContract(graph, contract, paths)
        material = {**prepared.bind(runner).document(), 'declaration': prepared.document()}
        runner.configure_provenance(RuntimeEdgeIndex(material, contract.document()))
        origin = SourceAdmission.create(case_id='original', case_index=0,
            source_id='b.external_pin8', path_id=prepared.path_ids[0], direction='IP_TO_CPU',
            component='b', action_id='admitted-pin8', role='fuzz_source', input_kind='source_event',
            input_sha256=hashlib.sha256(b'\x01').hexdigest())
        runner.register_source_admission(origin)
        scope = {'component': 'b', 'reset_epoch': 0, 'command_sequence': 1}
        pre = probes(gpioen=256, input_clock_enable=4)
        post = probes(gpioen=256, input_clock_enable=4, sync0=256)
        pre['gpio_in'] = post['gpio_in'] = 256
        runner.sessions['b'].gpio_events = [
            {**tick(1, pre, post, component='b'), 'command_scope': scope},
            {'kind': 'gpio_input_applied', 'component': 'b', 'reset_epoch': 0,
             'local_tick': 1, 'command_scope': scope,
             'actual_receipt_ref': {'command_scope': scope, 'local_tick': 1},
             'actual_input_value': 256, 'segments': [{'bit_lo': 8, 'width': 1, 'value': 1,
                 'origin': {'kind': 'source_admission', 'action_id': origin.action_id}}]}]
        runner._append_external_events('b', 1)
        sample = next(e for e in runner.events if e['kind'] == 'gpio_input_sample')
        resource = sample['stages']['sync0'][8]
        self.assertEqual('known', resource['origin_status'])
        self.assertEqual([origin.document()], resource['origin_refs'])

    def test_gpio_observation_horizon_survives_bootstrap_sized_prefix(self):
        from tests.scenario.test_gpio_consumption_versions import tick, probes
        runner, _, _ = configured_runner(gpio_causal=True)
        stream = []
        for n in range(1, 301):
            scope = {'component': 'b', 'reset_epoch': 0, 'command_sequence': n}
            pre, post = probes(), probes()
            pre['gpio_in'] = post['gpio_in'] = 1
            stream.append({**tick(n, pre, post, component='b'), 'command_scope': scope})
            stream.append({'kind': 'gpio_input_applied', 'component': 'b', 'reset_epoch': 0,
                'source_epoch': 0, 'local_tick': n, 'command_scope': scope,
                'actual_receipt_ref': {'command_scope': scope, 'local_tick': n},
                'actual_input_value': 1, 'segments': [{'bit_lo': 0, 'width': 1, 'value': 1,
                'origin': {'kind': 'source_admission', 'action_id': 'unknown'}}]})
        runner.sessions['b'].gpio_events = stream
        runner._append_external_events('b', 1)
        samples = [e for e in runner.events if e['kind'] == 'gpio_input_sample']
        self.assertEqual(300, len(samples))
        self.assertTrue(all(e['status'] == 'observed' for e in samples))
        self.assertLessEqual(runner._gpio_consumption_tracker.max_completed_accesses, 8192)

    def test_successful_gpio_reset_is_drained_before_next_step(self):
        runner, _, _ = configured_runner(gpio_causal=True)
        for session in runner.sessions.values():
            session.reset_local = lambda: {'cancelled_responses': 0}
        def reset_gpio():
            runner.sessions['b'].gpio_events = [{'kind': 'gpio_reset', 'component': 'b',
                'reset_epoch': 1, 'source_epoch': 1, 'local_tick': 4}]
            return {'cancelled_responses': 0}
        runner.sessions['b'].reset_local = reset_gpio
        runner._status = 'running'
        runner._gpio_input_origins['b'] = [{'kind': 'source_admission', 'action_id': 'old'}]
        runner.reset_all('warm_all')
        self.assertEqual({}, runner._gpio_input_origins)
        self.assertEqual(1, len([e for e in runner.events if e['kind'] == 'gpio_reset_resource']))

    def test_logical_gpio_source_is_staged_before_step_with_original_action(self):
        from myfuzz.scenario.ownership import compile_ownership, InputField, InputOwner
        runner, _, _ = configured_runner(gpio_causal=True)
        runner.ownership = compile_ownership((InputField('b', 'gpio_in', 32),),
            (InputOwner('b', 'gpio_in', 0, 8, 'fixed', 'fixed'),
             InputOwner('b', 'gpio_in', 8, 1, 'source', 'pin8'),
             InputOwner('b', 'gpio_in', 9, 23, 'fixed', 'fixed')))
        captured = []
        runner.sessions['b'].set_next_gpio_input_context = captured.append
        runner._status = 'running'
        runner.inject_source('b', 'gpio_in', 1, direction='IP_TO_CPU',
                             bit_offset=8, width=1, action_id='source-case-a')
        runner._step_once('b')
        self.assertEqual(1, len(captured))
        self.assertEqual({'bit_lo': 8, 'width': 1, 'value': 1,
            'origin': {'kind': 'source_admission', 'action_id': 'source-case-a'}},
            captured[0]['segments'][0])

    def test_gpio_paired_sample_and_applied_marker_bind_exact_receipt(self):
        from tests.scenario.test_gpio_consumption_versions import tick, probes
        runner, _, _ = configured_runner(gpio_causal=True)
        scope = {'component': 'b', 'reset_epoch': 0, 'command_sequence': 1}
        pre, post = probes(), probes()
        pre['gpio_in'] = post['gpio_in'] = 1
        sample = {**tick(1, pre, post, component='b'), 'command_scope': scope}
        marker = {'kind': 'gpio_input_applied', 'component': 'b', 'reset_epoch': 0,
                  'source_epoch': 0, 'local_tick': 1, 'command_scope': scope,
                  'actual_receipt_ref': {'command_scope': scope, 'local_tick': 1},
                  'actual_input_value': 1, 'segments': [{'bit_lo': 0, 'width': 1,
                  'value': 1, 'origin': {'kind': 'source_admission', 'action_id': 'unknown'}}]}
        runner.sessions['b'].gpio_events = [sample, marker]
        runner._append_external_events('b', 3)
        records = runner.events
        resources = [e for e in records if e['kind'] == 'gpio_input_applied_resource']
        self.assertEqual(1, len(resources))
        self.assertEqual('unknown', resources[0]['origin_status'])
        fragments = [e for e in records if e['kind'] == 'gpio_input_segment_applied']
        self.assertEqual(1, len(fragments))
        actual = runner.event_by_id(fragments[0]['actual_receipt_event_id'])
        self.assertEqual('gpio_tick_observation', actual['kind'])
        self.assertEqual(1, actual['pre']['gpio_in'])
        self.assertEqual(1, len([e for e in records if e['kind'] == 'gpio_input_sample']))
        count = runner.event_count
        runner._append_external_events('b', 3)
        self.assertEqual(count, runner.event_count)

    def test_measured_gpio_delivery_links_to_logged_retirement_once(self):
        from tests.scenario.test_retirement_delivery import match, delivery
        runner, _, _ = configured_runner(gpio_causal=True)
        m, d = match(), delivery()
        m['cpu_scope']['source_component'] = 'a'
        for value in m['transaction_keys']:
            value['source_component'] = 'a'
        for value in m['instruction_responses']:
            value['transaction']['source_component'] = 'a'
        for value in m['data_beats']:
            value['transaction']['source_component'] = 'a'
            value['response']['transaction']['source_component'] = 'a'
        d['source_transaction']['source_component'] = 'a'
        d['device_id'] = 'b'
        for field in ('target_request', 'target_response', 'target_apb_access'):
            d[field]['source_transaction']['source_component'] = 'a'
            d[field]['command_scope']['component'] = 'b'
        runner.sessions['a'].router = SimpleNamespace(acceptances=[], deliveries=[d])
        runner.sessions['a'].cpu_events = [{'kind': 'cpu_retire'}]
        runner._cpu_retirement_matcher = SimpleNamespace(consume=lambda record: (m,))
        runner._append_external_events('a', 9)
        linked = [e for e in runner.events if e['kind'] == 'cpu_retired_transaction_target_delivery']
        self.assertEqual(1, len(linked))
        self.assertEqual('linked_raw', linked[0]['status'])
        self.assertEqual([], linked[0]['provenance']['origin_admission_ids'])
        self.assertFalse(linked[0]['known_fuzz_origin'])
        self.assertEqual('cpu_retirement_match', runner.event_by_id(linked[0]['retirement_event_id'])['kind'])
        self.assertEqual('mmio_delivery', runner.event_by_id(linked[0]['delivery_event_id'])['kind'])
        count = runner.event_count
        runner._append_external_events('a', 9)
        self.assertEqual(count, runner.event_count)

    def test_gpio_raw_access_stream_survives_drain_without_claiming_origin(self):
        runner, _, _ = configured_runner()
        raw = {'kind': 'gpio_apb_access', 'source_transaction': {'source_sequence': 7},
               'pre': {'gpio_probe_out': 1}, 'post': {'gpio_probe_out': 2}}
        runner.sessions['a'].gpio_events = [raw]
        runner._append_external_events('a', 3)
        self.assertEqual('gpio_apb_access', runner.events[-1]['kind'])
        self.assertEqual([], runner.events[-1]['provenance']['origin_admission_ids'])
        count = runner.event_count
        runner._append_external_events('a', 3)
        self.assertEqual(count, runner.event_count)
        raw['post']['gpio_probe_out'] = 9
        self.assertEqual(2, runner.events[-1]['post']['gpio_probe_out'])

    def test_configuration_enables_actual_session_source_stream(self):
        runner = factory()
        enabled = []
        runner.sessions['a'].enable_source_provenance = lambda: enabled.append('a')
        graph, contract, paths = declaration()
        prepared = PreparedRuntimePathContract(graph, contract, paths)
        material = {**prepared.bind(runner).document(), 'declaration': prepared.document()}
        runner.configure_provenance(RuntimeEdgeIndex(material, contract.document()))
        self.assertEqual(['a'], enabled)

    def test_frame_stream_preserves_original_action_across_case_and_drain_retry(self):
        runner, direction, path = configured_runner()
        origin = SourceAdmission.create(case_id='case-a', case_index=0, source_id='s',
            path_id=path, direction=direction, component='a', action_id='frame-a',
            role='fuzz_source', input_kind='source_event', input_sha256='0' * 64)
        runner.register_source_admission(origin)
        runner.set_observation_case('case-b', 1)
        raw = {'kind': 'uart_source_frame_end', 'schema_version': 'uart_source_frames.v1',
               'action_id': origin.action_id, 'frame_id': 'frame:1',
               'start_tick': 10, 'end_tick': 330, 'waveform_matched': True,
               'fifo_origin': 'unknown', 'bit_witness': [{'actual_pre_level': 0}]}
        runner.sessions['a'].source_events = [raw]
        runner._append_external_events('a', 5)
        item = runner.events[-1]
        self.assertEqual('uart_source_frame_end', item['kind'])
        self.assertEqual([origin.admission_id], item['provenance']['origin_admission_ids'])
        self.assertEqual('uart_pin_drive', item['provenance']['proof_scope'])
        self.assertEqual({'case_id': 'case-b', 'case_index': 1}, item['provenance']['observed_case'])
        self.assertEqual('unknown', item['fifo_origin'])
        count = runner.event_count
        runner._append_external_events('a', 5)
        self.assertEqual(count, runner.event_count)
        raw['bit_witness'][0]['actual_pre_level'] = 1
        self.assertEqual(0, runner.events[-1]['bit_witness'][0]['actual_pre_level'])

    def test_cpu_stream_retains_kind_without_inventing_origins(self):
        runner, _, _ = configured_runner()
        runner.sessions['a'].cpu_events = [{'kind': 'cpu_retire', 'order': 1,
                                         'pc': 0x1000, 'insn': 0x13}]
        runner._append_external_events('a', 4)
        raw = next(item for item in runner.events if item['kind'] == 'cpu_retire')
        self.assertEqual([], raw['provenance']['origin_admission_ids'])

    def test_uart_transport_nonce_is_scoped_for_fresh_replay_without_changing_raw_receipt(self):
        snapshots = []
        for nonce in ('first-process-random-nonce', 'fresh-replay-random-nonce'):
            runner, _, _ = configured_runner()
            stream = [{'kind': 'uart_source_frame_end', 'action_id': 'unknown',
                       'frame_id': 'uart-frame:0:1', 'bit_witness': [
                           {'receipt': {'execution': nonce, 'sequence': 17}},
                           {'receipt': {'execution': nonce, 'sequence': 49}}]}]
            runner.sessions['a'].source_events = stream
            runner._append_external_events('a', 1)
            snapshots.append(runner.events[-1])
            self.assertEqual(nonce, stream[0]['bit_witness'][0]['receipt']['execution'])
            self.assertEqual(17, snapshots[-1]['bit_witness'][0]['receipt']['sequence'])
            # A new physical process is a distinct logical transport scope.
            stream.append({'kind': 'uart_source_frame_end', 'bit_witness': [
                {'receipt': {'execution': nonce + ':restart', 'sequence': 17}}]})
            runner._append_external_events('a', 2)
            self.assertNotEqual(snapshots[-1]['bit_witness'][0]['receipt']['execution'],
                                runner.events[-1]['bit_witness'][0]['receipt']['execution'])
            stream.append({'kind': 'uart_source_frame_cancel', 'bit_witness': [
                {'receipt': {'execution': nonce, 'sequence': 50}}]})
            runner._append_external_events('a', 3)
            self.assertEqual(snapshots[-1]['bit_witness'][0]['receipt']['execution'],
                             runner.events[-1]['bit_witness'][0]['receipt']['execution'])
        self.assertEqual(snapshots[0], snapshots[1])

    def test_only_accepted_retirement_match_resolves_typed_instruction_origin(self):
        from tests.scenario.test_cpu_retirement import fetch, beat, response, retire
        runner, direction, path = configured_runner()
        origin = admission(direction, path, action='action-A')
        runner.register_source_admission(origin)
        runner.set_observation_case('case-b', 1)
        items = [fetch(), beat(), response(), retire()]
        for item in items:
            item['source_component'] = 'a'
            if 'transaction' in item:
                item['transaction']['source_component'] = 'a'
        runner.sessions['a'].cpu_events = items
        runner._append_external_events('a', 4)
        match = runner.events[-1]
        self.assertEqual('cpu_retirement_match', match['kind'])
        self.assertEqual('accepted', match['status'])
        self.assertEqual([origin.admission_id], match['provenance']['origin_admission_ids'])
        self.assertEqual('retired_instruction_origin', match['provenance']['proof_scope'])
        self.assertEqual('retired_instruction_bytes', match['origin_relation'])
        self.assertEqual('case-b', match['provenance']['observed_case']['case_id'])
        count = runner.event_count
        runner._append_external_events('a', 4)
        self.assertEqual(count, runner.event_count)
        # Ambiguous/rejected results preserve candidate refs without certifying origins.
        runner._events.append({'kind': 'cpu_retirement_match', 'status': 'ambiguous',
            'component': 'a', 'source_refs': ['action-A'], 'event_id': count + 1})
        self.assertEqual([], runner.events[-1]['provenance']['origin_admission_ids'])

    def test_frame_cannot_alias_instruction_or_another_component_action(self):
        runner, direction, path = configured_runner()
        origin = admission(direction, path)
        runner.register_source_admission(origin)
        runner._events.append({'kind': 'uart_source_frame_end', 'component': 'a',
            'action_id': origin.action_id, 'event_id': runner.event_count + 1})
        self.assertEqual([], runner.events[-1]['provenance']['origin_admission_ids'])
        runner._events.append({'kind': 'cpu_retirement_match', 'status': 'accepted',
            'component': 'a', 'cpu_scope': {'source_component': 'b'},
            'source_refs': [origin.action_id], 'event_id': runner.event_count + 1})
        self.assertEqual([], runner.events[-1]['provenance']['origin_admission_ids'])

    def test_real_ram_snapshot_keeps_writer_case_a_when_observed_in_case_b(self):
        for journal in (False, True):
            with self.subTest(journal=journal):
                runner, direction, path = configured_runner(journal)
                origin = admission(direction, path)
                runner.set_observation_case('case-a', 0)
                runner.register_source_admission(origin)
                memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 64, aliases=(0x2000,)),),
                                          initialization_seed=1, max_initialized_bytes=64)
                service = MemoryService(memory, TransactionLedger())
                service.include_writer_kinds = True
                memory.declare_instruction_slots(0x1000)
                service.accept_instructions(0x1000, b'\x13\0\0\0', source_event_id=origin.action_id)
                runner.clear_observation_case()
                runner.set_observation_case('case-b', 1)
                key = TransactionKey('execution', 'case-b', 'a', 0, 'instr', 1)
                snapshot = service.read(key, 0x2000, width_bytes=4)
                for item in service.events:
                    runner._events.append({**item, 'event_id': runner.event_count + 1, 'component': 'a'})
                event = runner.events[-1]
                meta = event['provenance']
                self.assertEqual({'case_id': 'case-b', 'case_index': 1}, meta['observed_case'])
                self.assertEqual([origin.admission_id], meta['origin_admission_ids'])
                self.assertEqual('known', meta['origin_status'])
                self.assertEqual('memory_writer_snapshot', meta['proof_scope'])
                self.assertEqual(list(snapshot.versions), meta['resource']['versions'])
                self.assertEqual(list(snapshot.writer_event_ids), meta['resource']['writer_event_ids'])
                self.assertEqual('case-a', runner.source_admissions['admissions'][0]['case_id'])
                before = runner.event_by_id(event['event_id'])
                runner.set_observation_case('case-c', 2)
                self.assertEqual(before, runner.event_by_id(event['event_id']))

    def test_latest_instruction_does_not_attribute_cpu_mmio_or_outputs(self):
        runner, direction, path = configured_runner()
        record = admission(direction, path)
        runner.set_observation_case('case-a', 0)
        runner.register_source_admission(record)
        for event in ({'kind': 'mmio_delivery', 'source_transaction': {'source_component': 'a'},
                       'device_id': 'b', 'address': 0x40000000},
                      {'component': 'a', 'inputs': {'pin': 1}, 'outputs': {'out': 1}}):
            runner._events.append({**event, 'event_id': runner.event_count + 1})
            self.assertEqual([], runner.events[-1]['provenance']['origin_admission_ids'])
            self.assertEqual('unknown', runner.events[-1]['provenance']['origin_status'])

    def test_real_store_writer_cannot_alias_an_instruction_action_id(self):
        runner, direction, path = configured_runner()
        key = TransactionKey('execution', 'case-b', 'a', 0, 'data', 1)
        origin = admission(direction, path, action=str(key))
        runner.register_source_admission(origin)
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x1000, 64),),
                                  initialization_seed=1, max_initialized_bytes=64)
        service = MemoryService(memory, TransactionLedger())
        service.include_writer_kinds = True
        service.write(key, 0x1000, 0x13, width_bytes=4, byte_enable=15)
        service.read(TransactionKey('execution', 'case-b', 'a', 0, 'data', 2),
                     0x1000, width_bytes=4)
        item = service.events[-1]
        runner._events.append({**item, 'event_id': runner.event_count + 1})
        self.assertEqual([], runner.events[-1]['provenance']['origin_admission_ids'])
        self.assertEqual('unknown', runner.events[-1]['provenance']['origin_status'])

    def test_fixed_support_role_and_unknown_writers_not_promoted(self):
        runner, direction, path = configured_runner()
        record = admission(direction, path, role='fixed_support')
        runner.register_source_admission(record)
        runner._events.append({'event_id': runner.event_count + 1, 'kind': 'memory_read',
            'writer_event_ids': (record.action_id, 'first-read'), 'versions': ((0, 1), (0, 2)),
            'writer_kinds': ('INSTRUCTION_SOURCE', 'FIRST_READ'),
            'memory_id': 'ram', 'generation': 0, 'byte_offset': 0})
        meta = runner.events[-1]['provenance']
        self.assertEqual('partial', meta['origin_status'])
        self.assertEqual(['first-read'], meta['unknown_writer_ids'])
        self.assertEqual('fixed_support', runner.source_admissions['admissions'][0]['role'])

        runner._events.append_unchecked({'event_id': runner.event_count + 1,
            'kind': 'memory_read', 'writer_event_ids': (record.action_id, False),
            'writer_kinds': ('INSTRUCTION_SOURCE', 'STORE')})
        self.assertEqual('partial', runner.events[-1]['provenance']['origin_status'])

    def test_precise_binding_candidate_detached_from_event_and_index(self):
        runner, direction, path = configured_runner()
        item = {'event_id': 1, 'kind': 'dataflow_delivery', 'source': ('a', 'out'),
                'target': ('b', 'pin'), 'source_bit_offset': 0, 'target_bit_offset': 0,
                'width': 1, 'value': 1}
        runner._events.append(item)
        event = runner.events[-1]
        self.assertNotIn('provenance', item)
        candidate = event['provenance']['edge_candidates'][0]
        self.assertEqual(1, candidate['rule_index'])
        self.assertEqual([path], candidate['path_ids'])
        self.assertEqual('binding', candidate['scope'])
        self.assertEqual('transport_candidates_only', event['provenance']['proof_scope'])
        event['provenance']['edge_candidates'].clear()
        self.assertEqual(1, len(runner.event_by_id(1)['provenance']['edge_candidates']))

    def test_idempotent_registration_and_unchecked_append_preserve_metadata(self):
        runner, direction, path = configured_runner(journal=True)
        record = admission(direction, path)
        runner.register_source_admission(record)
        count = runner.event_count
        runner.register_source_admission(record)
        self.assertEqual(count, runner.event_count)
        changed = SourceAdmission.create(**{k: v for k, v in asdict(record).items()
                                            if k != 'admission_id'} | {'case_id': 'different'})
        with self.assertRaises(ValueError):
            runner.register_source_admission(changed)
        self.assertEqual(count, runner.event_count)
        runner.clear_observation_case()
        runner._events.append_unchecked({'event_id': count + 1, 'kind': 'budget_exhausted'})
        self.assertIsNone(runner.events[-1]['provenance']['observed_case'])

    def test_malformed_output_metadata_cannot_mask_authoritative_failure(self):
        runner, _, _ = configured_runner()
        for item in ({'kind': 'memory_read', 'writer_event_ids': [False, {'bad': 1}, ' ']},
                     {'kind': 'dataflow_delivery', 'source': None, 'target': 'bad'},
                     {'kind': 'harness_failure', 'error_type': 'LostResponse'}):
            runner._events.append_unchecked({**item, 'event_id': runner.event_count + 1})
        self.assertEqual('harness_failure', runner.events[-1]['kind'])
        self.assertEqual('unknown', runner.events[-1]['provenance']['origin_status'])

    def test_caller_cannot_rewrite_appended_raw_failure_payload(self):
        for journal in (False, True):
            with self.subTest(journal=journal):
                runner, _, _ = configured_runner(journal)
                record = {'event_id': 1, 'kind': 'harness_failure', 'outputs': {'out': 1}}
                runner._events.append_unchecked(record)
                record['outputs']['out'] = 2
                self.assertEqual(1, runner.event_by_id(1)['outputs']['out'])
                # Cross the journal chunk boundary and check the same prefix.
                runner._events.append_unchecked({'event_id': 2, 'kind': 'marker'})
                record['outputs']['out'] = 3
                self.assertEqual(1, runner.event_by_id(1)['outputs']['out'])

    def test_irq_candidates_use_actual_binding_bits(self):
        runner, _, path = configured_runner()
        binding = runner.bindings[0]
        runner._irq_pulses[binding] = SimpleNamespace(events=[{'kind': 'source_start', 'source_event_id': 1}])
        runner._irq_event_offsets[binding] = 0
        runner._append_irq_events(binding)
        event = runner.events[-1]
        self.assertEqual((binding.source_bit_offset, binding.target_bit_offset, binding.width),
                         (event['source_bit_offset'], event['target_bit_offset'], event['width']))
        self.assertEqual([path], event['provenance']['edge_candidates'][0]['path_ids'])

    def test_legacy_runner_has_no_implicit_provenance_or_origin_registry(self):
        runner = factory()
        self.assertIsNone(runner.provenance_configuration)
        self.assertIsNone(runner.source_admissions)
        runner._events.append({'event_id': 1, 'kind': 'legacy'})
        self.assertNotIn('provenance', runner.events[-1])


if __name__ == '__main__':
    unittest.main()
