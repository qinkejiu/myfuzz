"""Live native read issuance is tied to the actual service callback."""

from dataclasses import asdict
from dataclasses import replace
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.batch import BatchAdvance
from myfuzz.scenario.memory import (InstructionAcceptance, MemoryRegion, PersistentMemory, ReadSnapshot,
                                    _VALIDATE_ACTUAL_SNAPSHOT)
from myfuzz.scenario.memory_service import (MemoryService, _ARM_ISSUED_READ,
                                             _LOOKUP_ISSUED_READ, _REVOKE_ISSUED_READ,
                                             _VALIDATE_ISSUED_READ)
from myfuzz.scenario.native_instruction_source_binding import (
    NativeInstructionSourceBinding, _binding_document, _classify_native_source_read,
    lookup_issued_source_for_read)
from myfuzz.scenario.native_instruction_bus_completion import (
    NativeInstructionBusCompletion, validate_issued_native_completion,
    _scopes_share_execution)
from myfuzz.scenario.native_cpu_events import NativeBusObserver
from myfuzz.scenario.native_packet_session import (NativePacketSession,
    native_packet_source_binding_configuration, native_packet_source_completion_configuration)
from myfuzz.scenario.native_replay_identity import native_observation_comparison_events
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import (OnlineCase, OnlineInstruction, ScenarioTrace,
                                             replay_online_session)
from myfuzz.scenario.source_provenance import SourceAdmission


class NativeReadIssuanceTests(unittest.TestCase):
    def test_completion_execution_must_match_accepted_and_response(self):
        self.assertTrue(_scopes_share_execution(('same', 1, 0, 1),
            ('same', 2, 0, 2), ('same', 3, 0, 3)))
        self.assertFalse(_scopes_share_execution(('same', 1, 0, 1),
            ('same', 2, 0, 2), ('other', 3, 0, 3)))

    def setUp(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x80000000, 0x1000),),
            initialization_seed=1, max_initialized_bytes=64)
        self.service = MemoryService(self.memory, TransactionLedger(),
                                     include_writer_kinds=True)
        self.key = TransactionKey('execution', 'case', 'cpu', 0, 'instruction', 1)
        self.address = 0x80000040
        _ARM_ISSUED_READ(self.service, self.key)

    def read(self):
        return self.service.read(self.key, self.address, width_bytes=4)

    def test_actual_read_issues_handle_bound_to_completed_entry(self):
        snapshot = self.read()
        handle = _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, snapshot)
        self.assertIs(snapshot, _VALIDATE_ISSUED_READ(
            self.service, self.memory, self.key, snapshot, handle))
        self.assertIs(handle, _LOOKUP_ISSUED_READ(
            self.service, self.memory, self.key, self.read()))
        self.assertIs(snapshot, self.service.ledger._entries[self.key].receipt)

    def test_issued_read_remains_valid_after_runner_drains_service_events(self):
        snapshot = self.read()
        handle = _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, snapshot)
        event = self.service.events[-1]
        journal_copy = deepcopy(dict(event))

        # Runner copies service events into its bounded journal, then clears
        # the producer list. The live read issuance must survive that drain.
        self.service.events.clear()
        self.assertEqual([], self.service.events)
        self.assertEqual(journal_copy, event)
        self.assertIs(snapshot, _VALIDATE_ISSUED_READ(
            self.service, self.memory, self.key, snapshot, handle))

        # The issuance still pins the original event material after the list
        # is drained, so mutation through a retained reference is rejected.
        event['data_hex'] = '00000000'
        with self.assertRaises(ValueError):
            _VALIDATE_ISSUED_READ(
                self.service, self.memory, self.key, snapshot, handle)

    def test_equal_reconstructed_snapshot_cannot_obtain_or_use_handle(self):
        snapshot = self.read()
        copy = ReadSnapshot(**asdict(snapshot))
        self.assertEqual(snapshot, copy)
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, copy)
        handle = _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, snapshot)
        with self.assertRaises(ValueError):
            _VALIDATE_ISSUED_READ(self.service, self.memory, self.key, copy, handle)

    def test_other_service_or_memory_cannot_claim_issued_read(self):
        snapshot = self.read()
        other_service = MemoryService(self.memory, TransactionLedger(),
                                      include_writer_kinds=True)
        other_memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x80000000, 0x1000),),
            initialization_seed=1, max_initialized_bytes=64)
        for service, memory in ((other_service, self.memory),
                                (self.service, other_memory)):
            with self.subTest(service=service, memory=memory), self.assertRaises(ValueError):
                _LOOKUP_ISSUED_READ(service, memory, self.key, snapshot)

    def test_equal_transaction_key_object_cannot_claim_issued_read(self):
        snapshot = self.read()
        equal_key = TransactionKey(**asdict(self.key))
        self.assertEqual(self.key, equal_key)
        self.assertIsNot(self.key, equal_key)
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.service, self.memory, equal_key, snapshot)

    def test_event_append_failure_never_issues_a_read_handle(self):
        self.memory.preload(self.address, b'\x13\x00\x00\x00')
        class FailingEvents(list):
            def append(self, event):
                if event['kind'] == 'memory_read':
                    raise RuntimeError('event append failed')
                super().append(event)

        self.service.events = FailingEvents()
        with self.assertRaisesRegex(RuntimeError, 'event append failed'):
            self.read()
        entry = self.service.ledger._entries[self.key]
        self.assertEqual('uncertain_effect', entry.status)
        self.assertIsNone(entry.receipt)
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.service, self.memory, self.key,
                                self.memory.read(self.address, 4, transaction_id=str(self.key)))

    def test_substituted_memory_helper_cannot_enroll_equal_snapshot(self):
        self.memory.preload(self.address, b'\x13\x00\x00\x00')
        actual = self.memory.read(self.address, 4, transaction_id=str(self.key))
        forged = ReadSnapshot(**asdict(actual))
        with patch('myfuzz.scenario.memory_service._READ_ACTUAL_SNAPSHOT',
                   return_value=forged):
            with self.assertRaises(ValueError):
                self.read()
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, forged)

    def test_unarmed_read_has_no_native_handle(self):
        _REVOKE_ISSUED_READ(self.service)
        snapshot = self.read()
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, snapshot)

    def test_revocation_invalidates_the_live_handle(self):
        snapshot = self.read()
        handle = _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, snapshot)
        _REVOKE_ISSUED_READ(self.service)
        with self.assertRaises(ValueError):
            _VALIDATE_ISSUED_READ(self.service, self.memory, self.key, snapshot, handle)
        with self.assertRaises(ValueError):
            _VALIDATE_ACTUAL_SNAPSHOT(self.memory, self.service, snapshot)

    def test_separate_service_issuance_on_shared_memory_keeps_each_owner(self):
        first = self.read()
        first_handle = _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, first)
        other = MemoryService(self.memory, TransactionLedger(), include_writer_kinds=True)
        other_key = TransactionKey('execution', 'case', 'other-cpu', 0, 'instruction', 1)
        _ARM_ISSUED_READ(other, other_key)
        second = other.read(other_key, self.address, width_bytes=4)
        second_handle = _LOOKUP_ISSUED_READ(other, self.memory, other_key, second)
        self.assertIs(first, _VALIDATE_ISSUED_READ(
            self.service, self.memory, self.key, first, first_handle))
        self.assertIs(second, _VALIDATE_ISSUED_READ(
            other, self.memory, other_key, second, second_handle))

    def test_failed_armed_read_revokes_after_address_validation(self):
        with self.assertRaisesRegex(ValueError, 'unmapped'):
            self.service.read(self.key, 0x40000000, width_bytes=4)
        _ARM_ISSUED_READ(self.service, self.key)

    def test_failed_armed_read_revokes_after_key_mismatch(self):
        equal_key = TransactionKey(**asdict(self.key))
        with self.assertRaisesRegex(ValueError, 'differs from armed transaction'):
            self.service.read(equal_key, self.address, width_bytes=4)
        _ARM_ISSUED_READ(self.service, self.key)

    def test_append_hook_cannot_change_read_event_before_issuance(self):
        self.memory.preload(self.address, b'\x13\x00\x00\x00')

        class MutatingEvents(list):
            def append(self, event):
                if event['kind'] == 'memory_read':
                    event['value'] = 0
                    event['data_hex'] = '00000000'
                super().append(event)

        self.service.events = MutatingEvents()
        with self.assertRaises(ValueError):
            self.read()
        snapshot = self.service.ledger._entries[self.key].receipt
        with self.assertRaises(ValueError):
            _LOOKUP_ISSUED_READ(self.service, self.memory, self.key, snapshot)
        with self.assertRaises(ValueError):
            _VALIDATE_ACTUAL_SNAPSHOT(self.memory, self.service, snapshot)

    def test_append_hook_cannot_change_optional_writer_kinds(self):
        self.memory.preload(self.address, b'\x13\x00\x00\x00')

        class MutatingEvents(list):
            def append(self, event):
                if event['kind'] == 'memory_read':
                    event['writer_kinds'] = ('STORE',) * 4
                super().append(event)

        self.service.events = MutatingEvents()
        with self.assertRaises(ValueError):
            self.read()

    def test_append_hook_cannot_replace_numeric_value_with_boolean(self):
        self.memory.preload(self.address, b'\x01\x00\x00\x00')

        class MutatingEvents(list):
            def append(self, event):
                if event['kind'] == 'memory_read':
                    event['value'] = True
                super().append(event)

        self.service.events = MutatingEvents()
        with self.assertRaises(ValueError):
            self.read()

    def test_existing_native_memory_channel_key_can_be_armed(self):
        _REVOKE_ISSUED_READ(self.service)
        key = TransactionKey('execution', 'case', 'cpu', 0, 'memory', 1)
        _ARM_ISSUED_READ(self.service, key)
        snapshot = self.service.read(key, self.address, width_bytes=4)
        handle = _LOOKUP_ISSUED_READ(self.service, self.memory, key, snapshot)
        self.assertIs(snapshot, _VALIDATE_ISSUED_READ(
            self.service, self.memory, key, snapshot, handle))

    def test_ordinary_reads_skip_native_memory_registration(self):
        _REVOKE_ISSUED_READ(self.service)
        with patch('myfuzz.scenario.memory._REGISTER_ACTUAL_SNAPSHOT',
                   side_effect=AssertionError('ordinary read registered native provenance')):
            self.memory.read(self.address, 4, transaction_id='ordinary')
            self.read()


class NativeSourceCandidatePolicyTests(unittest.TestCase):
    """Pure policy fixtures never enroll a source binding in the live registry."""

    def setUp(self):
        self.address = 0x80000040
        self.source = OnlineInstruction('action-1', 'cpu', self.address, '13000000')
        encoded = json.dumps({**asdict(self.source), 'kind': 'instruction'},
                             sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode()
        self.admission = SourceAdmission.create(
            case_id='case-1', case_index=0, source_id='source-1', path_id='path-1',
            direction='CPU_TO_IP_TO_CPU', component='cpu', action_id='action-1',
            role='fuzz_source', input_kind='instruction',
            input_sha256=hashlib.sha256(encoded).hexdigest())
        self.versions = ((0, 1),) * 4
        self.ids = ('action-1',) * 4
        self.kinds = ('INSTRUCTION_SOURCE',) * 4
        self.acceptance = InstructionAcceptance(
            'ram', self.address, 0x40, 0, self.source.data, 'action-1',
            self.versions, self.ids, self.kinds)
        self.binding = NativeInstructionSourceBinding(
            'cpu', 'native-execution', 0, 0, self.admission, self.source,
            self.acceptance)
        self.case = SimpleNamespace(case_id='case-1', path_id='path-1',
                                    direction='CPU_TO_IP_TO_CPU', source=self.source)
        self.key = TransactionKey('local-execution', 'testcase', 'cpu', 0, 'memory', 1)
        self.snapshot = ReadSnapshot(str(self.key), 'ram', 0, 0x40,
                                     self.source.data, self.versions, self.ids,
                                     writer_kinds=self.kinds)
        self.span = ('ram', 0, 0x40)

    def rows(self, binding=None, case=None, admission=None, source_id=None, role='fuzz_source'):
        return ((binding or self.binding, case or self.case,
                 admission or self.admission, source_id or 'source-1', role),)

    def classify(self, *, rows=None, snapshot=None, key=None, address=None,
                 span=None, epoch=0, component='cpu', testcase_id='testcase',
                 anchors=None, current_case_index=0):
        return _classify_native_source_read(
            self.rows() if rows is None else rows,
            self.snapshot if snapshot is None else snapshot,
            self.key if key is None else key,
            self.address if address is None else address,
            self.span if span is None else span,
            epoch=epoch, component=component, testcase_id=testcase_id,
            anchors=anchors, current_case_index=current_case_index)

    def refused(self, **changes):
        with self.assertRaisesRegex(ValueError, 'native_source_candidate_refused'):
            self.classify(**changes)

    def test_matching_live_candidate_policy_selects_original_object(self):
        self.assertIs(self.binding, self.classify())

    def test_unrelated_bootstrap_or_nop_fetch_is_diagnostic_only(self):
        self.assertIsNone(self.classify(address=0x80000000,
                                        span=('ram', 0, 0)))
        self.assertIsNone(self.classify(address=0x80000044,
                                        span=('ram', 0, 0x44)))

    def test_old_source_fetch_during_later_case_refuses_selected_candidate(self):
        self.refused(current_case_index=1)
        self.assertIsNone(self.classify(current_case_index=1,
                                        address=0x80000044,
                                        span=('ram', 0, 0x44)))

    def test_alias_and_multiple_selected_candidates_refuse(self):
        self.refused(address=0x90000040, span=self.span)
        self.refused(rows=self.rows() + self.rows())

    def test_pinned_issuance_span_still_selects_moved_binding_for_refusal(self):
        moved_source = replace(self.source, address=self.address + 4)
        moved_acceptance = replace(self.acceptance, address=self.address + 4,
                                   byte_offset=0x44)
        moved = replace(self.binding, source=moved_source,
                        acceptance=moved_acceptance)
        original_anchor = (self.address, 4, 'ram', 0, 0x40)
        self.refused(rows=self.rows(binding=moved), anchors=(original_anchor,))

    def test_case_path_admission_and_owner_contradictions_refuse(self):
        self.refused(rows=self.rows(case=SimpleNamespace(
            case_id='case-1', path_id='other-path',
            direction='CPU_TO_IP_TO_CPU', source=self.source)))
        self.refused(rows=self.rows(admission=SourceAdmission.create(
            case_id='case-1', case_index=0, source_id='source-1', path_id='path-1',
            direction='CPU_TO_IP_TO_CPU', component='cpu', action_id='other-action',
            role='fuzz_source', input_kind='instruction',
            input_sha256=self.admission.input_sha256)))
        self.refused(rows=self.rows(role='fixed_support'))
        self.refused(component='other-cpu')
        self.refused(testcase_id='other-testcase')

    def test_byte_writer_version_and_epoch_contradictions_refuse(self):
        self.refused(snapshot=replace(self.snapshot, data=b'\x73\x00\x10\x00'))
        self.refused(snapshot=replace(self.snapshot, writer_kinds=(
            'STORE', *self.kinds[1:])))
        self.refused(snapshot=replace(self.snapshot, writer_event_ids=(
            'other-action', *self.ids[1:])))
        self.refused(snapshot=replace(self.snapshot, versions=(
            (0, 2), *self.versions[1:])))
        self.refused(epoch=1)

    def test_memory_generation_is_independent_of_native_epoch(self):
        versions = ((2, 1),) * 4
        acceptance = replace(self.acceptance, generation=2, versions=versions)
        binding = replace(self.binding, acceptance=acceptance)
        snapshot = replace(self.snapshot, generation=2, versions=versions)
        self.assertIs(binding, self.classify(rows=self.rows(binding=binding),
                                             snapshot=snapshot,
                                             span=('ram', 2, 0x40)))

    def test_absent_live_session_cannot_turn_policy_fixture_into_authority(self):
        with self.assertRaises(ValueError):
            lookup_issued_source_for_read(object(), object(), object(),
                                          self.key, self.snapshot, self.address, 0)

    def test_constructed_equal_completion_has_no_live_issuance(self):
        candidate = NativeInstructionBusCompletion(
            self.key, self.snapshot, self.binding, self.address,
            self.snapshot.data, 0,
            ('native-execution', 1, 0, 1),
            ('native-execution', 2, 0, 2),
            ('native-execution', 3, 0, 3),
            (1, 1, self.address, 0, self.snapshot.value, 1))
        self.assertEqual('native_instruction_bus_completion.v1',
                         candidate.schema_version)
        self.assertFalse(candidate.grants_source_authority)
        with self.assertRaises(ValueError):
            validate_issued_native_completion(object(), candidate)


class NativeCompletionReplayPolicyTests(unittest.TestCase):
    @staticmethod
    def _normalize(events, execution):
        return native_observation_comparison_events(events, component='cpu',
            reset_epoch=0, execution=execution,
            native_trace_signals={name: name for name in
                ('valid', 'ready', 'addr', 'wdata', 'wstrb', 'rdata')},
            native_instruction_marker='instr')

    def _completion_journal(self, execution):
        admission = {'schema_version': 'source_admission.v1',
            'admission_id': 'admission-1', 'case_id': 'case-1', 'case_index': 0,
            'source_id': 'source-1', 'path_id': 'path-1',
            'direction': 'CPU_TO_IP_TO_CPU', 'component': 'cpu',
            'action_id': 'action-1', 'role': 'fuzz_source',
            'input_kind': 'instruction', 'input_sha256': 'a' * 64}
        source = {'kind': 'instruction', 'component': 'cpu', 'action_id': 'action-1',
                  'address': 0x80000040, 'data_hex': '13000000'}
        acceptance = {'memory_id': 'ram', 'address': 0x80000040,
            'byte_offset': 0x40, 'generation': 0, 'data_hex': '13000000',
            'source_event_id': 'action-1', 'versions': [[0, 1]] * 4,
            'writer_event_ids': ['action-1'] * 4,
            'writer_kinds': ['INSTRUCTION_SOURCE'] * 4}
        binding = dict(component='cpu', execution=execution, reset_epoch=0,
                       case_index=0, admission=admission, source=source,
                       acceptance=acceptance)
        rows = [
            dict(event_id=1, kind='source_admission', admission=admission),
            dict(event_id=2, kind='instruction_source', component='cpu',
                 address=0x80000040, data_hex='13000000', generation=0,
                 source_event_id='action-1', producer_event_id=1),
            dict(event_id=3, producer_event_id=2,
                 schema_version='native_instruction_source_binding.v1',
                 kind='native_instruction_source_bound', component='cpu',
                 execution=execution, reset_epoch=0,
                 proof_scope='host_instruction_input_bound',
                 grants_source_authority=False, native_bus_completion_observed=False,
                 retirement=False, grants_feedback=False, admission_event_id=1,
                 source=source, **{k: v for k, v in binding.items()
                                   if k not in ('component', 'execution', 'reset_epoch',
                                                'source')}),
        ]
        scopes = [dict(execution=execution, command_sequence=n,
                       reset_epoch=0, local_tick=n) for n in (1, 2, 3)]
        raw_ids = (4, 6, 8)
        projection_ids = (5, 7, 9)
        native_kinds = ('native_backend_request_accepted',
                        'native_backend_response_consumed', 'native_bus_completed')
        for scope, raw_id, projected_id, kind in zip(
                scopes, raw_ids, projection_ids, native_kinds):
            rows.append(dict(event_id=raw_id, kind='local_tick_sample',
                producer_event_id=0, component='cpu', local_tick=scope['local_tick'],
                phase='pre', native_driver_scope=scope,
                outputs={'protocol_taps': {'valid': 1,
                    'ready': 1 if kind == 'native_bus_completed' else 0,
                    'addr': 0x80000040, 'wstrb': 0, 'wdata': 0,
                    'rdata': 0x13 if kind == 'native_bus_completed' else 0},
                    'physical': {'instr': 1}}))
            projected = dict(event_id=projected_id, schema_version='native_bus_observation.v1',
                kind=kind, component='cpu', phase='pre', producer_event_id=raw_id,
                transaction=dict(execution_id='local-execution',
                    testcase_id='case-1', source_component='cpu', source_epoch=0,
                    channel_id='memory', source_sequence=1), **scope)
            if kind == 'native_bus_completed':
                projected.update(accepted_scope=scopes[0], response_scope=scopes[1],
                                 native={'valid': 1, 'ready': 1,
                                     'addr': 0x80000040, 'wstrb': 0,
                                     'wdata': 0, 'rdata': 0x13,
                                     'instruction': 1})
            elif kind == 'native_backend_request_accepted':
                projected['native'] = {'valid': 1, 'ready': 0,
                    'addr': 0x80000040, 'wstrb': 0, 'wdata': 0,
                    'rdata': 0, 'instruction': 1}
            else:
                projected.update(value=0x13, native_post_is_offer_only=True)
            rows.append(projected)
        key = dict(execution_id='local-execution', testcase_id='case-1',
            source_component='cpu', source_epoch=0, channel_id='memory', source_sequence=1)
        snapshot = dict(transaction_id=str(TransactionKey(**key)), memory_id='ram',
            generation=0, byte_offset=0x40, versions=[[0, 1]] * 4,
            writer_event_ids=['action-1'] * 4, materialized_offsets=[],
            writer_kinds=['INSTRUCTION_SOURCE'] * 4, data_hex='13000000')
        provenance = dict(schema_version='event_source_provenance.v1',
            edge_candidates=[], invalid_origin_references=0,
            observed_case={'case_id': 'case-1', 'case_index': 0},
            origin_admission_ids=[], origin_status='unknown',
            proof_scope='observation_only', resource=None, unknown_writer_ids=[])
        completion = dict(schema_version='native_instruction_bus_completion.v1',
            kind='native_instruction_bus_completion', proof_scope='native_instruction_bus_transfer_completed',
            grants_source_authority=False, component='cpu', event_id=10,
            producer_event_id=8,
            key=key, snapshot=snapshot, binding=binding,
            address=0x80000040, data_hex='13000000',
            reset_epoch=0, accepted_scope=scopes[0], response_scope=scopes[1],
            completion_scope=scopes[2], native_pre=[1, 1, 0x80000040, 0, 0x13, 1],
            admission_event_id=1, host_binding_event_id=3, service_event_id=2,
            native_accepted_event_id=5, native_response_event_id=7,
            native_completed_event_id=9, provenance=provenance)
        rows.append(completion)
        return rows

    def test_full_fresh_comparison_normalizes_only_completion_owned_nonce_fields(self):
        old = self._completion_journal('a' * 32)
        fresh = self._completion_journal('b' * 32)
        expected = self._normalize(old, 'a' * 32)
        actual = self._normalize(fresh, 'b' * 32)
        self.assertEqual(expected, actual)
        completion = expected[-1]
        self.assertEqual('native-process:cpu:epoch:0',
                         completion['completion_scope']['execution'])
        self.assertEqual('native-process:cpu:epoch:0',
                         completion['binding']['execution'])
        self.assertEqual('local-execution', completion['key']['execution_id'])
        self.assertEqual(0x80000040, completion['address'])

    def test_live_completion_accepts_typed_tuple_projections(self):
        rows = self._completion_journal('a' * 32)
        acceptance_rows = (rows[2]['acceptance'],
                           rows[-1]['binding']['acceptance'])
        for acceptance in acceptance_rows:
            acceptance['versions'] = ((0, 1),) * 4
            acceptance['writer_event_ids'] = ('action-1',) * 4
            acceptance['writer_kinds'] = ('INSTRUCTION_SOURCE',) * 4
        snapshot = rows[-1]['snapshot']
        snapshot['versions'] = ((0, 1),) * 4
        snapshot['writer_event_ids'] = ('action-1',) * 4
        snapshot['writer_kinds'] = ('INSTRUCTION_SOURCE',) * 4
        snapshot['materialized_offsets'] = ()

        normalized = self._normalize(rows, 'a' * 32)
        self.assertEqual(((0, 1),) * 4,
                         normalized[-1]['snapshot']['versions'])
        self.assertEqual(('action-1',) * 4,
                         normalized[-1]['binding']['acceptance']['writer_event_ids'])

    def test_live_tuple_projection_still_rejects_malformed_source_values(self):
        mutations = (
            ('boolean version', lambda row: row['binding']['acceptance'].__setitem__(
                'versions', ((False, 1),) + ((0, 1),) * 3)),
            ('wrong tuple writer', lambda row: row['snapshot'].__setitem__(
                'writer_event_ids', ('wrong-writer',) * 4)),
            ('materialized tuple', lambda row: row['snapshot'].__setitem__(
                'materialized_offsets', (0x40,))),
        )
        for name, mutate in mutations:
            with self.subTest(field=name):
                rows = self._completion_journal('a' * 32)
                mutate(rows[-1])
                with self.assertRaises(ValueError):
                    self._normalize(rows, 'a' * 32)

    def test_completion_provenance_must_remain_observation_only_and_case_bound(self):
        mutations = (
            ('origin_status', lambda row: row['provenance'].__setitem__(
                'origin_status', 'known')),
            ('origin_admission_ids', lambda row: row['provenance'].__setitem__(
                'origin_admission_ids', ['admission-1'])),
            ('edge_candidates', lambda row: row['provenance'].__setitem__(
                'edge_candidates', [{'kind': 'source'}])),
            ('observed_case', lambda row: row['provenance']['observed_case'].__setitem__(
                'case_id', 'other-case')),
            ('missing field', lambda row: row['provenance'].pop('resource')),
            ('extra field', lambda row: row['provenance'].__setitem__(
                'extra', 'unreviewed')),
        )
        for name, mutate in mutations:
            with self.subTest(field=name):
                rows = self._completion_journal('a' * 32)
                mutate(rows[-1])
                with self.assertRaisesRegex(
                        ValueError, 'native-comparison-completion-provenance'):
                    self._normalize(rows, 'a' * 32)

    def test_admission_and_binding_case_indices_must_match(self):
        rows = self._completion_journal('a' * 32)
        # Keep the admission receipt and its event at case 0, while the
        # host-binding and completion documents consistently claim case 1.
        # Case provenance agrees with the binding, so only the cross-event
        # admission/binding join can reject this forged relation.
        rows[2]['case_index'] = 1
        rows[-1]['binding']['case_index'] = 1
        rows[-1]['provenance']['observed_case']['case_index'] = 1
        with self.assertRaises(ValueError):
            self._normalize(rows, 'a' * 32)

    def test_admission_case_index_must_be_a_nonnegative_exact_integer(self):
        for bad_index in (True, -1):
            with self.subTest(case_index=bad_index):
                rows = self._completion_journal('a' * 32)
                rows[0]['admission']['case_index'] = bad_index
                rows[2]['admission']['case_index'] = bad_index
                rows[-1]['binding']['admission']['case_index'] = bad_index
                with self.assertRaises(ValueError):
                    self._normalize(rows, 'a' * 32)

    def test_completion_references_must_identify_the_unique_prior_events(self):
        reference_fields = (
            'admission_event_id', 'host_binding_event_id', 'service_event_id',
            'native_accepted_event_id', 'native_response_event_id',
            'native_completed_event_id')
        wrong_prior_ids = (2, 2, 1, 7, 5, 5)
        for name, wrong_id in zip(reference_fields, wrong_prior_ids):
            with self.subTest(reference=name):
                rows = self._completion_journal('a' * 32)
                rows[-1][name] = wrong_id
                with self.assertRaises(ValueError):
                    self._normalize(rows, 'a' * 32)

    def test_completion_snapshot_and_acceptance_must_match_exact_source_slice(self):
        mutations = (
            ('acceptance.byte_offset', lambda row: row['binding']['acceptance'].__setitem__('byte_offset', 0x44)),
            ('acceptance.versions', lambda row: row['binding']['acceptance'].__setitem__('versions', [[0, 2]] * 4)),
            ('acceptance.writer_event_ids', lambda row: row['binding']['acceptance'].__setitem__('writer_event_ids', ['other'] * 4)),
            ('acceptance.writer_kinds', lambda row: row['binding']['acceptance'].__setitem__('writer_kinds', ['STORE'] * 4)),
            ('snapshot.materialized_offsets', lambda row: row['snapshot'].__setitem__('materialized_offsets', [0x40])),
            ('snapshot.data_hex', lambda row: row['snapshot'].__setitem__('data_hex', '00000000')),
        )
        for name, mutate in mutations:
            with self.subTest(field=name):
                rows = self._completion_journal('a' * 32)
                mutate(rows[-1])
                with self.assertRaises(ValueError):
                    self._normalize(rows, 'a' * 32)

    def test_completed_projection_native_tuple_must_match_issued_native_pre(self):
        rows = self._completion_journal('a' * 32)
        completed = next(row for row in rows if row.get('kind') == 'native_bus_completed')
        completed['native']['rdata'] = 0x14
        with self.assertRaises(ValueError):
            self._normalize(rows, 'a' * 32)

    def test_service_accepted_request_and_response_are_joined_to_completion(self):
        mutators = (
            ('service.data_hex', lambda rows: rows[1].__setitem__('data_hex', 'deadbeef')),
            ('accepted.native.addr', lambda rows: next(row for row in rows
                if row.get('kind') == 'native_backend_request_accepted')['native'].__setitem__(
                    'addr', 0x80000044)),
            ('response.value', lambda rows: next(row for row in rows
                if row.get('kind') == 'native_backend_response_consumed').__setitem__(
                    'value', 0x14)),
        )
        for name, mutate in mutators:
            with self.subTest(field=name):
                rows = self._completion_journal('a' * 32)
                mutate(rows)
                with self.assertRaises(ValueError):
                    self._normalize(rows, 'a' * 32)

    def test_completion_plan_rejects_changed_saved_capacity_before_factory(self):
        from myfuzz.scenario.native_packet_session import (
            native_packet_source_binding_configuration,
            native_packet_source_completion_configuration)

        policy = native_packet_source_binding_configuration(2)
        completion_policy = native_packet_source_completion_configuration(2)
        completion_policy['max_native_raw_samples'] = 4095
        plan = json.dumps({'schema_version': 22,
            'native_packet_configuration': policy,
            'native_source_completion': completion_policy}).encode()
        trace = ScenarioTrace('plan', 'complete', (), {}, 'semantic', 'manifest')

        def forbidden_factory():
            self.fail('changed saved bounds must be rejected before fresh construction')

        with self.assertRaisesRegex(ValueError, 'native saved configuration'):
            replay_online_session(plan, forbidden_factory, trace,
                native_max_cases=2, native_reference_execution='a' * 32,
                native_source_binding=True, native_source_completion=True)

    def test_completion_plan_rejects_warmup_above_saved_bound_before_factory(self):
        from myfuzz.scenario.native_packet_session import (
            native_packet_source_binding_configuration,
            native_packet_source_completion_configuration)
        plan = json.dumps({'schema_version': 22,
            'native_packet_configuration': native_packet_source_binding_configuration(2),
            'native_source_completion': native_packet_source_completion_configuration(2),
            'warmup_advances': [['cpu']] * 513, 'cases': []}).encode()

        def forbidden_factory():
            self.fail('excess warmup must be rejected before fresh construction')

        with self.assertRaisesRegex(ValueError, 'saved plan exceeds'):
            replay_online_session(plan, forbidden_factory,
                ScenarioTrace('plan', 'complete', (), {}, 'semantic', 'manifest'),
                native_max_cases=2, native_reference_execution='a' * 32,
                native_source_binding=True, native_source_completion=True,
                native_reference_session=object())


class NativeCompletionRunnerConsumerTests(unittest.TestCase):
    def _consumer_fixture(self):
        execution = 'e' * 32
        address = 0x80000040
        source = OnlineInstruction('action-1', 'cpu', address, '13000000')
        encoded = json.dumps({**asdict(source), 'kind': 'instruction'},
            sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode()
        admission = SourceAdmission.create(case_id='case-1', case_index=0,
            source_id='source-1', path_id='path-1', direction='CPU_TO_IP_TO_CPU',
            component='cpu', action_id=source.action_id, role='fuzz_source',
            input_kind='instruction', input_sha256=hashlib.sha256(encoded).hexdigest())
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x80000000, 0x1000),),
            initialization_seed=1, max_initialized_bytes=64)
        memory.declare_instruction_slots(address, 1)
        acceptance = memory.accept_instructions(address, source.data,
                                                 source_event_id=source.action_id)
        binding = NativeInstructionSourceBinding('cpu', execution, 0, 0,
            admission, source, acceptance)
        case = OnlineCase('case-1', admission.direction, admission.path_id,
                          source, (BatchAdvance(('cpu', 'gpio')),), ())

        runner = object.__new__(ScenarioRunner)
        runner.sessions = {}
        runner._native_source_completion_objects = {}
        runner._provenance = SimpleNamespace(registry=SimpleNamespace(
            get=lambda action_id: admission if action_id == source.action_id else None))
        runner._events = []
        runner.event_by_id = lambda event_id: next((event for event in runner._events
            if event.get('event_id') == event_id), None)
        runner._append_ordinary_observed_event = lambda record: runner._events.append(record)

        source_session = object.__new__(NativePacketSession)
        source_session.runner = runner
        source_session._packet_max_cases = 2
        source_session._native_source_binding_configuration_json = json.dumps(
            native_packet_source_binding_configuration(2), sort_keys=True,
            separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
        source_session._native_source_completion_configuration_json = json.dumps(
            native_packet_source_completion_configuration(2), sort_keys=True,
            separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
        source_session._manifest_document = None
        source_session._native_source_binding_installed = True
        source_session._cases = [case]
        source_session._case_source_roles = {'case-1': 'fuzz_source'}

        artifact = SimpleNamespace(runtime_document={'artifact_digest': 'digest'},
            plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu')))
        cpu = SimpleNamespace(artifact=artifact, reset_epoch=0, _execution=execution,
            _sequence=0, _sequence_memory=0, _tick_base=0, _case_id='case-1',
            _native_source_completion_session=source_session, memory=memory)
        cpu.service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True)
        observer = object.__new__(NativeBusObserver)
        observer.session = cpu
        observer.contract = {'instruction_marker': {'signal': 'instr'},
                             'endpoint_id': 'cpu', 'clock_domain': 'clk'}
        observer.trace = {'signals': {name: name for name in
            ('valid', 'ready', 'addr', 'wdata', 'wstrb', 'rdata')},
            'signal_widths': {'valid': 1, 'ready': 1, 'addr': 32,
                'wdata': 32, 'wstrb': 4, 'rdata': 32}, 'max_wait_cycles': 4}
        observer.pending = None
        observer.epoch = None
        observer.execution = None
        observer.sequence = 0
        observer.tick = None
        observer.memory_sequence = 0
        observer.samples = []
        observer.offered = None
        observer.failed = False
        observer._source_completions = []
        cpu._native_bus_observer = observer
        runner.sessions['cpu'] = cpu

        def phase(*, ready=0, rdata=0):
            return {'protocol_taps': {'valid': 1, 'ready': ready,
                    'addr': address, 'wdata': 0, 'wstrb': 0, 'rdata': rdata},
                    'physical': {'instr': 1}}

        def edge(tick, *, accepted=False, consumed=False, ready=0, rdata=0,
                 pending_response=None):
            cpu._sequence = tick
            backend = {'m_req_valid': int(accepted), 'm_req_ready': int(accepted),
                'm_req_addr': address, 'm_req_write': 0, 'm_req_be': 15,
                'm_req_wdata': 0, 'm_rsp_valid': int(consumed),
                'm_rsp_ready': int(consumed), 'm_rsp_error': 0,
                'm_rsp_rdata': rdata if consumed else 0}
            pre = {**phase(ready=ready, rdata=rdata), 'backend': backend}
            post = phase(ready=1 if consumed else ready, rdata=rdata)
            receipt = SimpleNamespace(status='result', new_ticks=1,
                execution=execution, sequence=tick, tick_before=tick - 1,
                tick_after=tick, payload={'samples': [dict(local_tick=tick,
                    pre=pre, post=post)]})
            return observer.observe(receipt, pending_response)

        key = edge(1, accepted=True)
        cpu._sequence_memory = 1
        snapshot = cpu.service.read(key, address, width_bytes=4)
        observer.bind_read_snapshot(key, snapshot)
        edge(2, consumed=True, rdata=snapshot.value,
             pending_response=(snapshot.value, key.source_sequence))
        with patch('myfuzz.scenario.native_instruction_bus_completion.lookup_issued_source_for_read',
                   return_value=binding):
            edge(3, ready=1, rdata=snapshot.value)
        completion, = observer.drain_source_completions()
        observer._source_completions.append(completion)

        binding_doc = _binding_document(binding)
        admission_doc = admission.document()
        transaction = asdict(completion.key)
        accepted_scope, response_scope, completion_scope = (
            dict(zip(('execution', 'command_sequence', 'reset_epoch', 'local_tick'), scope))
            for scope in (completion.accepted_scope, completion.response_scope,
                          completion.completion_scope))
        native = {'valid': 1, 'ready': 1, 'addr': address, 'wstrb': 0,
                  'wdata': 0, 'rdata': snapshot.value, 'instruction': 1}
        runner._events = [
            dict(event_id=1, kind='source_admission', admission=admission_doc),
            dict(event_id=2, kind='instruction_source', component='cpu',
                 address=source.address, data_hex=source.data_hex,
                 generation=acceptance.generation, source_event_id=source.action_id,
                 producer_event_id=1),
            {**binding_doc, 'event_id': 3, 'kind': 'native_instruction_source_bound',
             'schema_version': 'native_instruction_source_binding.v1',
             'producer_event_id': 2, 'admission_event_id': 1,
             'proof_scope': 'host_instruction_input_bound',
             'grants_source_authority': False, 'native_bus_completion_observed': False,
             'retirement': False, 'grants_feedback': False},
        ]
        scopes = (accepted_scope, response_scope, completion_scope)
        raw_ids, projected_ids = (4, 6, 8), (5, 7, 9)
        kinds = ('native_backend_request_accepted',
                 'native_backend_response_consumed', 'native_bus_completed')
        for scope, raw_id, projected_id, kind in zip(scopes, raw_ids, projected_ids, kinds):
            raw = dict(event_id=raw_id, kind='local_tick_sample', component='cpu',
                phase='pre', local_tick=scope['local_tick'], native_driver_scope=scope,
                outputs={'protocol_taps': {'valid': 1, 'ready': 1 if kind == kinds[2] else 0,
                    'addr': address, 'wstrb': 0, 'wdata': 0,
                    'rdata': snapshot.value if kind == kinds[2] else 0},
                    'physical': {'instr': 1}})
            projected = dict(event_id=projected_id,
                schema_version='native_bus_observation.v1', kind=kind,
                component='cpu', phase='pre', producer_event_id=raw_id,
                transaction=transaction, **scope)
            if kind == kinds[2]:
                projected.update(accepted_scope=accepted_scope,
                    response_scope=response_scope, native=native)
            elif kind == kinds[0]:
                projected['native'] = {'valid': 1, 'ready': 0,
                    'addr': address, 'wstrb': 0, 'wdata': 0, 'rdata': 0,
                    'instruction': 1}
            else:
                projected.update(value=snapshot.value, native_post_is_offer_only=True)
            runner._events.extend((raw, projected))
        return runner, observer, completion, binding, raw_ids[-1]

    def test_runner_consumes_original_live_issued_object_once(self):
        runner, observer, completion, binding, raw_id = self._consumer_fixture()
        with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                   return_value=binding):
            runner._drain_native_source_completions('cpu', raw_id)
            published = runner._events[-1]
            self.assertEqual('native_instruction_bus_completion', published['kind'])
            self.assertEqual((1, 3, 2, 5, 7, 9), (
                published['admission_event_id'], published['host_binding_event_id'],
                published['service_event_id'], published['native_accepted_event_id'],
                published['native_response_event_id'], published['native_completed_event_id']))
            self.assertIs(runner._native_source_completion_objects[id(completion)], completion)
            observer._source_completions.append(completion)
            with self.assertRaisesRegex(ValueError, 'already consumed'):
                runner._drain_native_source_completions('cpu', raw_id)

    def test_runner_rejects_wrong_raw_pre_or_completed_projection(self):
        for target in ('raw', 'projection'):
            with self.subTest(target=target):
                runner, _, _, binding, raw_id = self._consumer_fixture()
                if target == 'raw':
                    runner._events[7]['outputs']['protocol_taps']['rdata'] = 0x14
                else:
                    runner._events[8]['native']['rdata'] = 0x14
                with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                           return_value=binding):
                    with self.assertRaises(ValueError):
                        runner._drain_native_source_completions('cpu', raw_id)

    def test_runner_rejects_tampered_host_binding_acceptance(self):
        runner, _, _, binding, raw_id = self._consumer_fixture()
        runner._events[2]['acceptance']['data_hex'] = 'deadbeef'
        with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                   return_value=binding):
            with self.assertRaises(ValueError):
                runner._drain_native_source_completions('cpu', raw_id)

    def test_runner_rejects_service_or_native_projection_tampering(self):
        mutations = (
            ('service.data_hex', lambda runner: runner._events[1].__setitem__(
                'data_hex', 'deadbeef')),
            ('accepted.native.addr', lambda runner: runner._events[4]['native'].__setitem__(
                'addr', 0x80000044)),
            ('response.value', lambda runner: runner._events[6].__setitem__('value', 0x14)),
        )
        for name, mutate in mutations:
            with self.subTest(field=name):
                runner, _, _, binding, raw_id = self._consumer_fixture()
                mutate(runner)
                with patch('myfuzz.scenario.native_instruction_bus_completion.validate_issued_binding',
                           return_value=binding):
                    with self.assertRaises(ValueError):
                        runner._drain_native_source_completions('cpu', raw_id)

    def test_completion_plan_rejects_case_count_above_saved_bound_before_factory(self):
        from myfuzz.scenario.native_packet_session import (
            native_packet_source_binding_configuration,
            native_packet_source_completion_configuration)
        plan = json.dumps({'schema_version': 22,
            'native_packet_configuration': native_packet_source_binding_configuration(2),
            'native_source_completion': native_packet_source_completion_configuration(2),
            'warmup_advances': [], 'cases': [{}] * 3}).encode()

        def forbidden_factory():
            self.fail('case count above saved policy must be rejected before fresh construction')

        with self.assertRaisesRegex(ValueError, 'saved plan exceeds'):
            replay_online_session(plan, forbidden_factory,
                ScenarioTrace('plan', 'complete', (), {}, 'semantic', 'manifest'),
                native_max_cases=2, native_reference_execution='a' * 32,
                native_source_binding=True, native_source_completion=True,
                native_reference_session=object())


if __name__ == '__main__':
    unittest.main()
