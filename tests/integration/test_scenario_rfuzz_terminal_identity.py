"""Transport failures retain actual execution identity and stateful history."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, MagicMock, patch

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.integration.scenario_rfuzz_live import _online_decision_for_receipt
from myfuzz.integration.scenario_rfuzz_replay import (
    replay_scenario_rfuzz_continuous, replay_scenario_rfuzz_corpus,
)
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder, OnlineSource
from tests.integration.test_scenario_rfuzz_acceptance import executor_for


def case_checker(receipt):
    return ()


def decoder_checker(trace):
    return ()


def admission_failure_factory():
    runner = executor_for().factory()
    actual_inject = runner.inject_source
    def inject_then_fail(*args, **kwargs):
        actual_inject(*args, **kwargs)
        raise RuntimeError('admission failed')
    runner.inject_source = inject_then_fail
    return runner


class TerminalIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'client'
        self.binary.write_bytes(b'client')
        self.output = self.root / 'run'

    def run_transport(self, executor, *, error=None, startup_error=None, records=None,
                      tests=None, repeat=False, compressed_trace=False):
        endpoint = MagicMock()
        endpoint.directory = self.root / 'fifo'
        endpoint.receive.side_effect = ([(1, 2), error] if error else
                                        [(1, 2), (1, 2)] if repeat else [(1, 2)])
        client = Mock(pid=123456789, returncode=0)
        client.poll.side_effect = None if error else [None, None, 0] if repeat else [None, 0]
        if error:
            client.poll.return_value = None
        self.client = client
        batch = InputBatch(1, 8, tests or (records or (bytes(8),),))
        def process(*args, on_receipt, **kwargs):
            executor.execute_batch(batch, on_receipt=on_receipt)
            return (1, 2)
        with patch('myfuzz.integration.scenario_rfuzz_live.FifoEndpoint') as endpoint_type, \
             patch('myfuzz.integration.scenario_rfuzz_live.subprocess.Popen',
                   side_effect=startup_error, return_value=client), \
             patch('myfuzz.integration.scenario_rfuzz_live.os.killpg'), \
             patch('myfuzz.integration.scenario_rfuzz_live._rfuzz_client_identity',
                   return_value={'binary_sha256': hashlib.sha256(b'client').hexdigest()}) as identity, \
             patch.object(executor, 'process_owned_pair', side_effect=process):
            endpoint_type.return_value.__enter__.return_value = endpoint
            try:
                return run_scenario_rfuzz_live(executor=executor, client_binary=self.binary,
                    output_dir=self.output, duration_seconds=1, max_tests=len(batch.tests),
                    compressed_trace=compressed_trace)
            finally:
                self.assertEqual(1, identity.call_count)

    def continuous(self, factory=None):
        executor = executor_for(checker=decoder_checker)
        self.factory = factory or executor.factory
        runner = self.factory()
        runner.identity_document = Mock(wraps=runner.identity_document)
        template = replace(executor.decoder.templates[0].genome, actions=(), max_steps=100)
        executor.session = ScenarioSession(template, runner, checker=case_checker)
        executor.factory = Mock(side_effect=AssertionError('extra factory'))
        return executor

    def online(self):
        base = executor_for()
        self.factory = base.factory
        runner = self.factory()
        template = replace(base.decoder.templates[0].genome, actions=(), max_steps=100)
        session = ScenarioSession(template, runner, checker=case_checker)
        session.begin()
        decoder = OnlineCaseDecoder(
            sources=(OnlineSource('pin', 'source', 'local', 'IP_TO_IP', 'local',
                                  port='pin', coverage_target_ids=('local.observed',)),),
            ownership=runner.ownership, schedule=('local',),
            instruction_start=0, instruction_end=0,
            advance_rounds=3, max_input_bytes=8)
        return ScenarioRfuzzExecutor(run_id='online-transport', factory=self.factory,
            targets=base.targets, session=session, online_decoder=decoder)

    def test_online_duration_budget_stops_within_one_multi_slot_buffer(self):
        executor = self.online()
        executor._online_live_duration_seconds = 1.0
        batch = InputBatch(7, 8, ((bytes(8),),) * 3)

        def expire_after_first(receipt):
            executor.first_receipt_completed_at = time.monotonic() - 2.0

        coverage = executor.execute_batch(batch, on_receipt=expire_after_first)
        self.assertEqual(3, len(coverage))
        self.assertEqual(1, len(executor.receipts))
        self.assertEqual(1, len(executor.session.cases))
        self.assertEqual((bytes(len(coverage[0])),) * 2, coverage[1:])
        self.assertEqual('duration_budget', executor._session_stop_reason)
        self.assertEqual(coverage, executor.execute_batch(batch))
        self.assertEqual(1, len(executor.session.cases))

    def test_repeated_online_chunk_reuses_receipt_without_duplicate_journal_row(self):
        executor = self.online()
        result = self.run_transport(executor, repeat=True)
        rows = [json.loads(line) for line in
                (self.output / 'receipts.jsonl').read_text().splitlines()]
        self.assertEqual(1, len(executor.session.cases))
        self.assertEqual(1, len(executor.receipts))
        self.assertEqual(1, len(rows))
        self.assertEqual(1, result.statuses['complete'])

    def test_online_receipt_journals_selected_path_and_feedback_credit(self):
        executor = self.online()
        self.run_transport(executor)
        row = json.loads((self.output / 'receipts.jsonl').read_text().splitlines()[0])
        decision = executor.online_decisions[0]
        for field in ('case_id', 'direction', 'flow_id', 'target_id', 'source_id',
                      'path_id', 'operator_id', 'candidate_id',
                      'source_selection_reason', 'candidate_disposition',
                      'candidate_disposition_reason', 'interaction_source_gains'):
            self.assertIn(field, row)
            self.assertEqual(decision.get(field), row[field])
        self.assertEqual('admitted', row['candidate_disposition'])
        self.assertEqual('rtl_case_committed', row['candidate_disposition_reason'])
        self.assertIn(row['source_selection_reason'],
                      ('direct_source_byte', 'feedback_weighted_legal_source'))

    def test_online_receipt_marks_weighted_source_fallback_when_direct_byte_is_illegal(self):
        executor = self.online()
        self.run_transport(executor, records=(bytes((0, 0, 255, 0, 0, 0, 0, 0)),))
        row = json.loads((self.output / 'receipts.jsonl').read_text().splitlines()[0])
        self.assertEqual('feedback_weighted_legal_source', row['source_selection_reason'])
        self.assertEqual('admitted', row['candidate_disposition'])

    def test_online_receipt_journals_case_phase_timings(self):
        executor = self.online()
        self.run_transport(executor)
        row = json.loads((self.output / 'receipts.jsonl').read_text().splitlines()[0])
        timing = row['online_phase_timing_seconds']
        phases = ('selection_decode', 'rtl_submit', 'trace_digest',
                  'interaction_ingest', 'checker', 'feedback_credit',
                  'receipt_build')
        self.assertEqual(set(phases) | {'total'}, set(timing))
        self.assertTrue(all(type(value) is float and value >= 0
                            for value in timing.values()))
        self.assertGreaterEqual(timing['total'], sum(timing[name] for name in phases))
        self.assertEqual(timing, executor.online_decisions[0]['phase_timing_seconds'])
        submit = row['online_submit_timing_seconds']
        self.assertEqual(submit, executor.online_decisions[0]['submit_timing_seconds'])
        self.assertEqual({'local_command_roundtrip', 'host_remainder',
                          'local_command_count'}, set(submit))
        self.assertGreaterEqual(submit['local_command_count'], 0)
        self.assertGreaterEqual(submit['local_command_roundtrip'], 0)
        self.assertGreaterEqual(submit['host_remainder'], 0)
        self.assertAlmostEqual(timing['rtl_submit'],
                               submit['local_command_roundtrip'] + submit['host_remainder'],
                               places=6)

    def test_online_candidate_rejection_reasons_distinguish_decode_and_validation(self):
        batch = InputBatch(1, 8, ((bytes(8),),))
        decode_rejected = self.online()
        decode_rejected.online_decoder.max_input_bytes = 1
        decode_rejected.execute_batch(batch)
        self.assertEqual('input_invalid', decode_rejected.receipts[0].status)
        self.assertEqual('rejected', decode_rejected.online_decisions[0]['candidate_disposition'])
        self.assertEqual('decode_rejected',
                         decode_rejected.online_decisions[0]['candidate_disposition_reason'])
        self.assertIsNone(decode_rejected.online_decisions[0]['candidate_id'])

        validation_rejected = self.online()
        with patch.object(validation_rejected, '_validate_online_runtime_selection',
                          side_effect=ValueError('selection rejected')):
            validation_rejected.execute_batch(batch)
        decision = validation_rejected.online_decisions[0]
        self.assertEqual('rejected', decision['candidate_disposition'])
        self.assertEqual('pre_submit_validation_rejected',
                         decision['candidate_disposition_reason'])
        self.assertTrue(decision['candidate_id'].startswith('online-candidate.v1:'))

        submit_failed = self.online()
        with patch.object(submit_failed.session, 'submit_case',
                          side_effect=RuntimeError('submit failed after attempt')):
            submit_failed.execute_batch(batch)
        decision = submit_failed.online_decisions[0]
        self.assertEqual('uncertain', decision['candidate_disposition'])
        self.assertEqual('rtl_submit_failed_or_partial',
                         decision['candidate_disposition_reason'])
        self.assertFalse(decision['committed'])

    def test_online_report_records_finalization_phase_costs(self):
        executor = self.online()
        self.run_transport(executor)
        report = json.loads((self.output / 'report.json').read_bytes())
        timing = report['finalization_timing_seconds']
        self.assertEqual({'session_finish', 'plan_write', 'trace_write',
                          'identity_write', 'total_before_report'}, set(timing))
        self.assertTrue(all(type(value) is float and value >= 0
                            for value in timing.values()))
        self.assertGreaterEqual(timing['total_before_report'],
                                sum(timing[name] for name in timing
                                    if name != 'total_before_report'))

    def test_large_jsonl_streamed_sha_is_persisted_and_fresh_replay_matches(self):
        executor = self.continuous()
        with patch('myfuzz.integration.scenario_rfuzz_live._JSONL_TRACE_EVENT_THRESHOLD', 1):
            self.run_transport(executor)
        metadata = json.loads((self.output / 'online_final_trace.meta.json').read_bytes())
        events = [json.loads(line) for line in
                  (self.output / 'online_events.jsonl').read_text().splitlines()]
        payload = {'status': metadata['status'], 'events': events,
                   'local_ticks': metadata['local_ticks']}
        expected = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode('utf-8')).hexdigest()
        self.assertEqual(expected, metadata['semantic_sha256'])
        self.assertEqual(expected, executor._online_final_trace.semantic_sha256)
        self.assertEqual('jsonl.v1', json.loads(
            (self.output / 'online_run_identity.json').read_bytes())['identity']['trace_format'])
        replayed = replay_scenario_rfuzz_continuous(
            self.output, self.factory, session_checker=case_checker,
            decoder_checker=decoder_checker)
        self.assertTrue(replayed.matches)

    def test_opt_in_compressed_trace_has_identity_and_fresh_replay(self):
        executor = self.continuous()
        self.run_transport(executor, compressed_trace=True)
        metadata = json.loads((self.output / 'online_final_trace.meta.json').read_bytes())
        identity = json.loads((self.output / 'online_run_identity.json').read_bytes())['identity']
        self.assertEqual('online_trace_zlib_chunks.v1', metadata['schema_version'])
        self.assertEqual('zlib_chunks.v1', identity['trace_format'])
        self.assertIn('online_events.zlib', identity['artifacts'])
        self.assertFalse((self.output / 'online_events.jsonl').exists())
        replayed = replay_scenario_rfuzz_continuous(
            self.output, self.factory, session_checker=case_checker,
            decoder_checker=decoder_checker)
        self.assertTrue(replayed.matches)

    def test_compressed_trace_corruption_fails_before_fresh_replay(self):
        executor = self.continuous()
        self.run_transport(executor, compressed_trace=True)
        event_file = self.output / 'online_events.zlib'
        event_file.write_bytes(event_file.read_bytes()[:-1])
        fresh_factory = Mock(side_effect=AssertionError('fresh RTL started'))
        with self.assertRaises(ValueError):
            replay_scenario_rfuzz_continuous(
                self.output, fresh_factory, session_checker=case_checker,
                decoder_checker=decoder_checker)
        fresh_factory.assert_not_called()

    def test_compressed_trace_write_failure_has_no_complete_identity(self):
        executor = self.continuous()
        with patch('myfuzz.integration.scenario_rfuzz_live._write_online_trace_zlib',
                   side_effect=OSError('compressed event stream failed')):
            with self.assertRaisesRegex(OSError, 'compressed event stream failed'):
                self.run_transport(executor, compressed_trace=True)
        self.assertFalse((self.output / 'online_run_identity.json').exists())
        self.assertTrue((self.output / 'incomplete_run_identity.json').exists())

    def test_explicit_deferred_finish_only_skips_terminal_semantic_digest(self):
        executor = self.online()
        executor.execute_batch(InputBatch(1, 8, ((bytes(8),),)))
        trace, plan_hex = executor._finish_online_session(defer_semantic_hash=True)
        self.assertEqual('', trace.semantic_sha256)
        self.assertIsNotNone(plan_hex)
        self.assertEqual('complete', trace.status)

    def test_large_jsonl_write_failure_has_no_complete_run_identity(self):
        executor = self.continuous()
        with patch('myfuzz.integration.scenario_rfuzz_live._JSONL_TRACE_EVENT_THRESHOLD', 1), \
             patch('myfuzz.integration.scenario_rfuzz_live._write_online_trace_jsonl',
                   side_effect=OSError('event stream failed')):
            with self.assertRaisesRegex(OSError, 'event stream failed'):
                self.run_transport(executor)
        self.assertFalse((self.output / 'online_run_identity.json').exists())
        self.assertFalse((self.output / 'online_final_trace.meta.json').exists())
        self.assertTrue((self.output / 'incomplete_run_identity.json').exists())

    def test_failed_trace_write_records_elapsed_phase_time(self):
        executor = self.online()

        def fail_after_work(*args, **kwargs):
            time.sleep(0.01)
            raise OSError('trace write failed')

        with patch('myfuzz.integration.scenario_rfuzz_live._write_online_trace',
                   side_effect=fail_after_work), patch(
                       'myfuzz.integration.scenario_rfuzz_live._write_online_trace_jsonl',
                       side_effect=fail_after_work):
            with self.assertRaisesRegex(OSError, 'trace write failed'):
                self.run_transport(executor)
        report = json.loads((self.output / 'report.json').read_bytes())
        self.assertEqual('incomplete', report['execution_status'])
        self.assertGreaterEqual(
            report['finalization_timing_seconds']['trace_write'], 0.01)

    def test_older_online_slot_retry_keeps_its_original_raw_decision(self):
        executor = self.online()
        first = InputBatch(1, 8, ((bytes(8),),))
        second = InputBatch(2, 8, ((bytes((0, 0, 0, 0, 0, 1, 0, 0)),),))
        executor.execute_batch(first)
        original = executor.receipts[0]
        executor.execute_batch(second)
        replayed = []
        executor.execute_batch(first, on_receipt=replayed.append)
        self.assertEqual([original], replayed)
        self.assertEqual([bytes(8).hex()],
                         _online_decision_for_receipt(executor, replayed[0])['raw_records_hex'])

    def test_online_transport_failure_retains_actual_prefix_identity(self):
        from myfuzz.scenario.session_runtime import replay_online_session
        from myfuzz.scenario.replay import ScenarioTrace
        executor = self.online()
        with self.assertRaisesRegex(OSError, 'transport broke'):
            self.run_transport(executor, error=OSError('transport broke'))
        self.assertEqual(1, len(executor.session.cases))
        report = json.loads((self.output / 'report.json').read_bytes())
        self.assertEqual('failed', report['execution_status'])
        identity = json.loads((self.output / 'online_run_identity.json').read_bytes())
        self.assertEqual(report['online_run_identity_sha256'], identity['sha256'])
        reference = ScenarioTrace(**json.loads((self.output / 'online_final_trace.json').read_bytes()))
        comparison = replay_online_session((self.output / 'online_plan.json').read_bytes(),
                         self.factory, reference, checker=case_checker)
        self.assertTrue(comparison.matches)

    def test_fresh_transport_error_after_case_keeps_failed_identity_and_closes_client(self):
        executor = executor_for()
        executor.factory = Mock(wraps=executor.factory)
        with self.assertRaisesRegex(OSError, 'transport broke'):
            self.run_transport(executor, error=OSError('transport broke'))
        report = json.loads((self.output / 'report.json').read_bytes())
        self.assertEqual('failed', report['execution_status'])
        self.assertEqual(1, report['tests'])
        self.assertEqual(1, executor.factory.call_count)
        self.client.wait.assert_called_once()
        envelope = json.loads((self.output / 'run_identity.json').read_bytes())
        self.assertEqual('observed', envelope['identity']['runner']['status'])
        self.assertEqual(report['run_identity_sha256'], envelope['sha256'])
        self.assertIn('receipts.jsonl', envelope['identity']['artifacts'])

    def test_prestart_failure_has_no_fabricated_runner_or_trace(self):
        executor = executor_for()
        executor.factory = Mock(side_effect=AssertionError('must not begin'))
        with self.assertRaisesRegex(OSError, 'spawn failed'):
            self.run_transport(executor, startup_error=OSError('spawn failed'))
        envelope = json.loads((self.output / 'run_identity.json').read_bytes())
        self.assertEqual('no_runner_observed', envelope['identity']['runner']['status'])
        self.assertFalse((self.output / 'online_final_trace.json').exists())
        executor.factory.assert_not_called()

    def test_preflight_existing_output_remains_byte_identical(self):
        self.output.mkdir()
        sentinel = self.output / 'report.json'
        sentinel.write_bytes(b'previous report')
        executor = executor_for()
        with self.assertRaisesRegex(ValueError, 'must be new'):
            run_scenario_rfuzz_live(executor=executor, client_binary=self.binary,
                                   output_dir=self.output, duration_seconds=1)
        self.assertEqual(b'previous report', sentinel.read_bytes())
        self.assertEqual({'report.json'}, {path.name for path in self.output.iterdir()})

    def test_record_only_continuous_is_rejected_without_execution(self):
        executor = executor_for()
        executor.session = Mock()
        with self.assertRaisesRegex(ValueError, 'record-only'):
            run_scenario_rfuzz_live(executor=executor, client_binary=self.binary,
                                   output_dir=self.output, duration_seconds=1)
        executor.session.record.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_continuous_full_prefix_replay_and_distinct_checker_layers(self):
        executor = self.continuous()
        self.run_transport(executor, tests=((bytes(8),),
                           (bytes((0, 0, 0, 0, 0, 1, 0, 0)),)))
        self.assertEqual(2, len(executor.session.cases))
        self.assertEqual(1, executor.session.runner.identity_document.call_count)
        executor.factory.assert_not_called()
        result = replay_scenario_rfuzz_continuous(self.output, self.factory,
                    session_checker=case_checker, decoder_checker=decoder_checker)
        self.assertTrue(result.matches)
        self.assertIn('decoder_checker_identity', result.verification_scope)
        with self.assertRaisesRegex(ValueError, 'continuous history'):
            replay_scenario_rfuzz_corpus(self.output, Mock())
        factory = Mock(side_effect=AssertionError('must not construct'))
        with self.assertRaisesRegex(ValueError, 'decoder checker identity'):
            replay_scenario_rfuzz_continuous(self.output, factory, session_checker=case_checker)
        factory.assert_not_called()

    def test_continuous_transport_failure_replays_admitted_prefix(self):
        executor = self.continuous()
        with self.assertRaisesRegex(OSError, 'transport broke'):
            self.run_transport(executor, error=OSError('transport broke'))
        result = replay_scenario_rfuzz_continuous(self.output, self.factory,
                    session_checker=case_checker, decoder_checker=decoder_checker)
        self.assertTrue(result.matches)
        report = json.loads((self.output / 'report.json').read_bytes())
        self.assertEqual('failed', report['execution_status'])

    def test_continuous_failed_admission_preserves_and_replays_actual_attempt(self):
        executor = self.continuous(admission_failure_factory)
        self.run_transport(executor)
        self.assertEqual('environment_error', executor.receipts[0].status)
        plan = json.loads((self.output / 'online_plan.json').read_bytes())
        self.assertEqual('source_admission', plan['terminal_failure']['phase'])
        result = replay_scenario_rfuzz_continuous(self.output, self.factory,
                    session_checker=case_checker, decoder_checker=decoder_checker)
        self.assertTrue(result.matches, result.comparison.difference_context)

    def test_finish_failure_retains_unfinished_prefix_and_original_exception(self):
        executor = self.continuous()
        executor.session.runner.finalize = Mock(side_effect=OSError('cleanup failed'))
        with self.assertRaisesRegex(OSError, 'transport broke'):
            self.run_transport(executor, error=OSError('transport broke'))
        executor._finish_online_session()
        executor.session.runner.finalize.assert_called_once()
        trace = json.loads((self.output / 'online_final_trace.json').read_bytes())
        self.assertEqual('running', trace['status'])
        report = json.loads((self.output / 'report.json').read_bytes())
        self.assertIn('cleanup failed', report['finalization_errors'][0])
        self.assertEqual('failed', report['execution_status'])

    def test_identity_write_failure_keeps_original_and_binds_incomplete_observed_runner(self):
        executor = executor_for()
        with patch('myfuzz.integration.scenario_rfuzz_live._write_fresh_run_identity',
                   side_effect=OSError('identity write failed')):
            with self.assertRaisesRegex(OSError, 'transport broke'):
                self.run_transport(executor, error=OSError('transport broke'))
        report = json.loads((self.output / 'report.json').read_bytes())
        self.assertEqual('incomplete', report['execution_status'])
        fallback = json.loads((self.output / 'incomplete_run_identity.json').read_bytes())
        self.assertEqual(executor.fresh_manifest_document, fallback['identity']['runner'])
        self.assertEqual(executor.run_id, fallback['identity']['run_config']['run_id'])
        self.assertIn('identity write failed', report['finalization_errors'][0])

    def test_continuous_sidecar_deleted_and_receipts_tampered_reject_before_factory(self):
        for filename in ('online_run_identity.json', 'receipts.jsonl'):
            with self.subTest(filename=filename):
                self.output = self.root / filename.replace('.', '-')
                executor = self.continuous()
                self.run_transport(executor)
                if filename == 'online_run_identity.json':
                    (self.output / filename).unlink()
                else:
                    (self.output / filename).write_text('{}\n')
                factory = Mock(side_effect=AssertionError('must not construct'))
                with self.assertRaises(ValueError):
                    replay_scenario_rfuzz_continuous(self.output, factory,
                        session_checker=case_checker, decoder_checker=decoder_checker)
                factory.assert_not_called()

    def test_wrong_report_hash_rejects_continuous_before_factory(self):
        executor = self.continuous()
        self.run_transport(executor)
        report = json.loads((self.output / 'report.json').read_bytes())
        report['online_run_identity_sha256'] = '0' * 64
        (self.output / 'report.json').write_text(json.dumps(report))
        factory = Mock(side_effect=AssertionError('must not construct'))
        with self.assertRaisesRegex(ValueError, 'report identity'):
            replay_scenario_rfuzz_continuous(self.output, factory,
                session_checker=case_checker, decoder_checker=decoder_checker)
        factory.assert_not_called()
