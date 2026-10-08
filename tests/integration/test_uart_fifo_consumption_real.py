"""Actual UART FIFO subset, enabled only after coordinated source freeze.

No CPU identity is manufactured: CPU operand and ISR origins remain unknown.
Clear/error-waveform and simultaneous serial/ACCESS corners require a separate
trusted driver policy and are deliberately outside this public-session fixture.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_UART_FIFO_REAL') == '1',
    'requires MYFUZZ_UART_FIFO_REAL=1 after coordinated source freeze')
class UartFifoConsumptionRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from myfuzz.local_harness import (load_local_harness_request,
            plan_local_harness, render_local_harness, render_local_runtime,
            verify_local_source_lock)
        from myfuzz.local_harness.driver_renderer import render_local_driver
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-uart-fifo-real-')
        cls.cache = Path(os.environ.get('MYFUZZ_UART_FIFO_CACHE_DIR',
                                       str(Path(cls.temp.name) / 'cache')))
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_uart_fifo_local/component_profile.json',
            instance_id='uart', reset_assert_ticks=8, reset_release_ticks=8,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        runtime = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(runtime, base_dir=ROOT)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_fifo(self, count):
        from myfuzz.local_harness import GeneratedOpentitanUartSession
        from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
        from myfuzz.scenario.router import DataflowRouter, DeviceWindow
        from myfuzz.scenario.uart_consumption import UartConsumptionTracker
        from myfuzz.scenario.batch import BatchSourceEvent
        from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
        from myfuzz.scenario.ownership import compile_ownership, InputField, InputOwner
        uart = GeneratedOpentitanUartSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, source=None,
            startup_writes=((0x10, 0x80000003, 15),))
        uart.enable_source_provenance()
        uart.begin_case('fifo-source-case')
        self.addCleanup(uart.end_case)
        router = DataflowRouter((DeviceWindow('uart', 0x40000000, 4096, uart),))
        ledger = TransactionLedger()
        # Keep raw native observations and source actions detached. The real
        # gate must fail if the new passive profile does not provide events.
        self.assertTrue(hasattr(uart, 'uart_events'))
        tracker = UartConsumptionTracker()
        registry = AdmissionRegistry()
        ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8),),
            (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'rx'),))
        source_tracker = UartConsumptionTracker(admission_registry=registry,
                                                ownership=ownership)
        cursor = 0
        resources = []
        source_resources = []
        actual_tick_ids = {}
        active_scope = None
        selected = []
        prefix = hashlib.sha256()

        def normalize(value):
            if isinstance(value, dict):
                return {key: ('actual-process' if key == 'execution' else normalize(item))
                        for key, item in value.items()}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            return value

        def drain():
            nonlocal cursor, active_scope
            for event in uart.uart_events[cursor:]:
                fact = deepcopy(event)
                # Journal order is allocated when observing the actual stream;
                # all native command receipts and source IDs remain original.
                fact['event_id'] = cursor + 1
                cursor += 1
                prefix.update(json.dumps(normalize(fact), sort_keys=True,
                    separators=(',', ':')).encode() + b'\n')
                source_fact = deepcopy(fact)
                def bind_admission(value):
                    if isinstance(value, list):
                        for child in value:
                            bind_admission(child)
                    elif isinstance(value, dict):
                        action = value.get('action_id')
                        if 'admission_id' in value and isinstance(action, str):
                            admission = registry.get(action)
                            value['admission_id'] = (admission.admission_id
                                if admission is not None else None)
                        for child in value.values():
                            bind_admission(child)
                bind_admission(source_fact)
                scope = source_fact['command_scope']
                if scope != active_scope:
                    actual_tick_ids.clear()
                    active_scope = deepcopy(scope)
                if source_fact['kind'] == 'uart_tick_observation':
                    self.assertNotIn(source_fact['local_tick'], actual_tick_ids)
                    actual_tick_ids[source_fact['local_tick']] = source_fact['event_id']
                elif source_fact['kind'] == 'uart_rdata_access':
                    for role, capture_name in (('request', 'read_capture'),
                                               ('response', 'response_capture')):
                        native_tick = source_fact[role + '_tick']
                        self.assertEqual({'command_scope': scope, 'local_tick': native_tick},
                            source_fact[capture_name]['actual_receipt_ref'])
                        source_fact['actual_' + role + '_event_id'] = actual_tick_ids[native_tick]
                        fact['actual_' + role + '_event_id'] = actual_tick_ids[native_tick]
                source_resources.extend(record for record in source_tracker.consume(source_fact)
                                        if record['kind'] != 'uart_irq_update')
                # Consume every actual terminal to close command scope, while
                # preserving raw admissionNone and explicitly unknown origins.
                native_records = tracker.consume(fact)
                for record in native_records:
                    if record['kind'] != 'uart_irq_update':
                        resources.append(record)
                if fact['kind'] != 'uart_tick_observation':
                    selected.append(fact)
                else:
                    pre = fact['pre']
                    if any(pre.get('probe_uart_' + key, 0) for key in
                           ('fifo_incr_wptr', 'fifo_incr_rptr', 'a_accept',
                            'd_accept', 'fifo_clear', 'rx_valid')):
                        selected.append(fact)
            uart.drain_tick_samples()
        for index in range(count):
            action = BatchSourceEvent(f'equal-frame-{index}', 'uart',
                                      'uart_rx_byte', 0x5a, bit_offset=0, width=8)
            admitted_bytes = json.dumps({**asdict(action), 'kind': 'source_event'},
                sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                allow_nan=False).encode()
            registry.register(SourceAdmission.create(case_id='fifo-source-case',
                case_index=0, source_id='rx', path_id='direct-uart-source',
                direction='IP_TO_CPU', component=action.component,
                action_id=action.action_id, role='fuzz_source', input_kind='source_event',
                input_sha256=hashlib.sha256(admitted_bytes).hexdigest()))
            uart.admit_source_event(action.port, action.value, bit_offset=action.bit_offset,
                width=action.width, action_id=action.action_id)
            uart.step_local({'uart_rx_byte': 0x5a})
            drain()
            while uart.local_ticks < uart.peer.source_end_tick + 4:
                uart.step_local({'uart_rx_byte': 0x5a})
                drain()
        frames = deepcopy(uart.source_events)
        ends = [e for e in frames if e['kind'] == 'uart_source_frame_end']
        self.assertEqual(count, len(ends))
        self.assertEqual(count, len({e['frame_id'] for e in ends}))
        self.assertEqual([f'equal-frame-{i}' for i in range(count)],
                         [e['action_id'] for e in ends])
        self.assertTrue(all(e['waveform_matched'] for e in ends))
        self.assertTrue(all(e['fifo_origin'] == 'unknown' for e in ends))
        # Ordinary case change is not a hardware reset. All read origins must
        # retain the source case and the original actual frame identities.
        epoch = uart.reset_epoch
        # Keep this actual process alive. Session begin/end are process
        # lifecycle operations; routed keys define the logical second case.
        self.assertEqual(epoch, uart.reset_epoch)
        for index in range(min(count, 64) + 1):
            key = TransactionKey('uart-fifo-real', 'fifo-read-case',
                                 'host', 0, 'data', index + 1)
            response = router.transact(ledger, key, address=0x40000018,
                write=False, wdata=0, be=15, beat_bytes=4)
            self.assertEqual((0x5a if index < min(count, 64) else 0, 0), response)
            self.assertEqual(asdict(key), asdict(router.deliveries[-1]['source_transaction']))
            observed = router.deliveries[-1]['target_uart_access']
            self.assertEqual('observed', observed['status'])
            self.assertEqual(asdict(key), observed['source_transaction'])
            self.assertEqual(0x18, observed['raw_offset'])
            self.assertEqual(response[0], observed['read_value'])
            self.assertEqual(0, observed['error'])
            self.assertLessEqual(observed['request_tick'], observed['response_tick'])
            self.assertLessEqual(observed['response_tick'], observed['local_tick'])
            drain()
        completions = [r for r in resources if r['kind'] == 'uart_rx_receiver_complete']
        pushes = [r for r in resources if r['kind'] == 'uart_fifo_push' and r['retained']]
        pops = [r for r in resources if r['kind'] == 'uart_fifo_pop']
        self.assertEqual(count, len(completions))
        self.assertTrue(all(len(r['sample_refs']) == 10 for r in completions))
        self.assertEqual(min(count, 64), len(pushes))
        self.assertEqual(min(count, 64), len(pops))
        self.assertEqual(len(pushes), len({tuple(r['entry_id']) for r in pushes}))
        self.assertEqual([r['entry_id'] for r in pushes], [r['entry_id'] for r in pops])
        self.assertEqual([r['receiver_id'] for r in completions[:64]],
                         [r['receiver_id'] for r in pushes])
        self.assertFalse(any(r.get('status') == 'accepted' for r in resources))
        unknowns = [r for r in resources if r.get('status') == 'incomplete']
        self.assertEqual(count, len([r for r in unknowns
            if r['reason'] == 'unproven_uart_source_authority']))
        self.assertEqual(min(count, 64), len([r for r in unknowns
            if r['reason'] == 'uart_unknown_entry_origin']))
        self.assertEqual(1, len([r for r in unknowns if r['reason'] == 'uart_empty_read']))
        self.assertTrue(all(r['reason'] in ('unproven_uart_source_authority',
            'uart_unknown_entry_origin', 'uart_empty_read') for r in unknowns), unknowns[-8:])
        self.assertTrue(all(r['origin_status'] == 'unknown' for r in pushes + pops))
        retained_proofs = [r for r in source_resources if r.get('status') == 'accepted'
                           and r.get('proof_scope') == 'uart_fifo_retention']
        read_proofs = [r for r in source_resources if r.get('status') == 'accepted'
                       and r.get('proof_scope') == 'uart_fifo_read_consumption']
        self.assertEqual(min(count, 64), len(retained_proofs))
        self.assertEqual(min(count, 64), len(read_proofs))
        self.assertEqual([r['entry_id'] for r in pushes],
                         [r['entry_id'] for r in retained_proofs])
        self.assertEqual([r['entry_id'] for r in retained_proofs],
                         [r['entry_id'] for r in read_proofs])
        self.assertEqual([f'equal-frame-{i}' for i in range(min(count, 64))],
                         [r['source_admission']['action_id'] for r in read_proofs])
        self.assertEqual(min(count, 64),
                         len({r['source_admission']['admission_id'] for r in read_proofs}))
        self.assertTrue(all(r['graph_path_certified'] is False and r['path_id'] is None
                           for r in retained_proofs + read_proofs))
        self.assertTrue(all(r['source_admission']['case_id'] == 'fifo-source-case'
                           and r['source_transaction']['testcase_id'] == 'fifo-read-case'
                           for r in read_proofs))
        failures = [r for r in source_resources if r.get('status') == 'incomplete']
        self.assertEqual(['uart_empty_read'], [r['reason'] for r in failures])
        self.assertTrue(all(e.get('physical_rx_ref') is None
            or e['physical_rx_ref']['admission_id'] is None for e in uart.uart_events))
        pending = None
        read_chains = []
        for fact in selected:
            if fact['kind'] != 'uart_tick_observation':
                continue
            pre, post = fact['pre'], fact['post']
            if pre['probe_uart_a_accept'] and pre['probe_uart_reg_rdata_re']:
                self.assertIsNone(pending)
                self.assertEqual(0x18, pre['probe_uart_reg_addr'])
                self.assertEqual(4, pre['probe_uart_tl_a_opcode'])  # TL Get
                self.assertEqual(0, pre['probe_uart_reg_error'])
                self.assertEqual(pre['probe_uart_fifo_head'], post['probe_uart_captured_rdata'])
                self.assertEqual(pre['probe_uart_tl_a_source'], post['probe_uart_captured_source'])
                pending = dict(command_scope=fact['command_scope'],
                    source=pre['probe_uart_tl_a_source'], value=pre['probe_uart_fifo_head'],
                    popped=bool(pre['probe_uart_fifo_incr_rptr']))
            if pre['probe_uart_d_accept'] and pending is not None:
                self.assertEqual(pending['source'], pre['probe_uart_tl_d_source'])
                self.assertEqual(pending['value'], pre['probe_uart_tl_d_data'])
                self.assertEqual(0, pre['probe_uart_tl_d_error'])
                self.assertEqual(pending['command_scope'], fact['command_scope'])
                read_chains.append(pending)
                pending = None
        self.assertIsNone(pending)
        self.assertEqual(min(count, 64) + 1, len(read_chains))
        self.assertEqual([True] * min(count, 64) + [False],
                         [read['popped'] for read in read_chains])
        if count == 65:
            overflow = [e for e in selected if e['kind'] == 'uart_tick_observation'
                and e['pre']['probe_uart_event_rx_overflow']]
            self.assertEqual(1, len(overflow))
            self.assertEqual(64, overflow[0]['pre']['probe_uart_fifo_depth'])
            self.assertEqual(0, overflow[0]['pre']['probe_uart_fifo_wready'])
        uart.end_case()
        return normalize(dict(frames=frames, events=selected, resources=resources,
            source_resources=source_resources, admissions=registry.document(),
            rdata_chains=read_chains,
            full_actual_prefix_sha256=prefix.hexdigest(),
            deliveries=[{**d, 'source_transaction':asdict(d['source_transaction'])}
                        for d in router.deliveries],
            cpu_operand_origin='unknown', irq_isr_origin='unknown'))

    def test_equal_frames_cross_case_and_empty_read(self):
        evidence = self.run_fifo(2)
        self.assertTrue(evidence['events'])
        fresh = self.run_fifo(2)
        self.assertEqual(evidence, fresh)
        destination = os.environ.get('MYFUZZ_UART_FIFO_EVIDENCE')
        if destination:
            directory = Path(destination)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'uart-fifo-equal-cross-case.json').write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + '\n')

    def test_full_fifo_65th_frame_is_not_retained(self):
        evidence = self.run_fifo(65)
        self.assertTrue(evidence['events'])


if __name__ == '__main__':
    unittest.main()
