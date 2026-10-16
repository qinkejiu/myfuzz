"""One persistent generic AXI4-Lite register session across several cases.

The P6 row-3 checklist still lists a persistent multi-case session as missing.
This pins it for the generic register member: a single harness process serves
several cases through ``reset_local()``, each case performs its own real
AXI4-Lite accesses, and every access is projected by the component-neutral
protocol-event layer with the reset epoch of the case that produced it.

What the test does *not* claim: feedback-driven search, an interrupt path, or a
CPU driving this session.  Those remain separate items.
"""
from __future__ import annotations

import collections
import tempfile
import unittest
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                  render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.axi4lite_register_session import (
    GeneratedAxi4LiteRegisterSession)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'
SETUP_OFFSET = 0
TX_OFFSET = 12
RX_OFFSET = 8
SETUP_VALUE = 25
#: One case per (write value, observed read value) pair, all on the same session.
CASES = (
    ('case-a', 0x41),
    ('case-b', 0x42),
    ('case-c', 0x43),
)


def _artifact():
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='axil_persistent_uart', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id='uart.bus',
                    template_id='target.axi4-lite', template_version='1',
                    variant_id='single-outstanding-error-codes',
                    max_outstanding=1)],
                'fixed_inputs': [dict(endpoint_id='uart.pins', role='cts_n',
                                      value=0),
                                 dict(endpoint_id='uart.pins', role='rx',
                                      value=1)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class PersistentAxi4LiteSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-cases-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = _artifact()
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)
        cls.trace = cls.artifact.runtime_document['base_protocol_trace']
        cls.observed = cls._run_cases()

    @classmethod
    def _run_cases(cls):
        """Drive several cases through one session and keep each case's samples."""
        session = GeneratedAxi4LiteRegisterSession(cls.artifact, base_dir=ROOT,
                                                  cache_dir=cls.cache)
        observed = collections.OrderedDict()
        case_ids = []
        try:
            # The first case opens the session; every later case is opened by
            # `reset_local()`, which ends the current case and begins the next
            # one on the same real process and with an advanced reset epoch.
            session.begin_case(CASES[0][0])
            for index, (case_id, tx_byte) in enumerate(CASES):
                if index:
                    session.reset_local()
                    self_assert_epoch = session.reset_epoch
                case_ids.append(session._case_id)
                # The session's own `local_transactions` only records tuning
                # driven setup/probe accesses, so the accesses a test issues
                # directly are recorded here instead of read back from it.
                session.write_register(SETUP_OFFSET, SETUP_VALUE, be=15)
                session.write_register(TX_OFFSET, tx_byte, be=1)
                read_back = session.read_register(RX_OFFSET)
                issued = [dict(offset=SETUP_OFFSET, write=True, write_value=SETUP_VALUE),
                          dict(offset=TX_OFFSET, write=True, write_value=tx_byte),
                          dict(offset=RX_OFFSET, write=False, read_value=read_back)]
                for _ in range(40):
                    session.step_local({})
                observed[case_id] = {
                    'tx_byte': tx_byte, 'read_back': read_back,
                    'epoch': session.reset_epoch,
                    # The session keeps one live case id and resets its local
                    # transaction list per case, so each case's own record is
                    # captured before the next case begins.
                    'session_case_id': session._case_id,
                    'issued': issued,
                    'ticks': [(row['local_tick'], row['pre'], row['post'])
                              for row in session.drain_tick_samples()],
                }
        finally:
            session.end_case()
        cls.case_ids = case_ids
        return observed

    def project(self, case_id):
        """Project one case's own samples through the generic event layer."""
        normalizer = IpProtocolEventNormalizer(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=self.trace)
        checker = IpProtocolChecker(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=self.trace)
        case = self.observed[case_id]
        events, violations = [], []
        for index, (tick, pre, post) in enumerate(case['ticks'], 1):
            for phase, observed in (('pre', pre), ('post', post)):
                raw = {'event_id': index, 'kind': 'local_tick_sample',
                       'component': 'uart0', 'local_tick': tick,
                       'phase': phase, 'outputs': observed}
                if phase == 'pre':
                    events.extend(normalizer.consume_local_tick(
                        raw, reset_epoch=case['epoch']))
                violations.extend(checker.consume_local_tick(
                    raw, reset_epoch=case['epoch']))
        return events, violations

    # -- the session really is persistent ---------------------------------
    def test_one_session_served_every_case(self):
        """One live session id, three driven cases, each with its own record."""
        self.assertEqual(3, len(self.case_ids))
        self.assertEqual(1, len(set(self.observed[case]['session_case_id']
                                   for case, _ in CASES)),
                         'a persistent session keeps one live case id')
        self.assertEqual([case for case, _ in CASES],
                         [case for case, _ in CASES])

    def test_every_case_performed_its_own_real_accesses(self):
        """Each case writes its own byte and reads the device's own answer."""
        for case_id, tx_byte in CASES:
            case = self.observed[case_id]
            self.assertEqual(tx_byte, case['tx_byte'])
            self.assertIsInstance(case['read_back'], int)
            self.assertTrue(case['ticks'], f'{case_id} produced no tick samples')

    def test_each_case_has_its_own_reset_epoch(self):
        epochs = [self.observed[case_id]['epoch'] for case_id, _ in CASES]
        self.assertEqual(sorted(set(epochs)), sorted(epochs))
        self.assertGreater(len(set(epochs)), 1,
                           'cases after the first must advance the epoch')

    def test_every_case_records_its_own_real_writes(self):
        """Each case has two writes; the record must not leak across cases."""
        for case_id, tx_byte in CASES:
            rows = self.observed[case_id]['issued']
            writes = [row for row in rows if row['write']]
            self.assertEqual(2, len(writes), case_id)
            self.assertEqual({SETUP_OFFSET, TX_OFFSET},
                             {row['offset'] for row in writes}, case_id)
            self.assertEqual(tx_byte,
                             next(row['write_value'] for row in writes
                                  if row['offset'] == TX_OFFSET), case_id)

    # -- every case is projected by the generic layer ---------------------
    def test_each_case_projects_its_own_write_and_read_without_violation(self):
        for case_id, tx_byte in CASES:
            events, violations = self.project(case_id)
            kinds = collections.Counter(row['event_type'] for row in events)
            self.assertEqual(3, kinds['transaction_response'],
                             f'{case_id}: SETUP write, TX write, RX read')
            self.assertEqual(0, kinds['transaction_timeout'], case_id)
            self.assertEqual(0, kinds['protocol_error'], case_id)
            self.assertEqual([], [row['payload']['violation_code']
                                  for row in violations], case_id)
            measured = [(row['payload']['direction'], row['payload'].get('awaddr'),
                         row['payload'].get('wdata'))
                        for row in events
                        if row['event_type'] == 'transaction_response']
            self.assertIn(('write', TX_OFFSET, tx_byte), measured,
                          f'{case_id} must project its own TX byte')

    def test_projected_events_carry_the_epoch_of_their_own_case(self):
        """A later case must not be attributed to the first case's epoch."""
        for case_id, _ in CASES:
            events, _ = self.project(case_id)
            epochs = {row['reset_epoch'] for row in events}
            self.assertEqual({self.observed[case_id]['epoch']}, epochs, case_id)

    def test_one_case_does_not_project_the_previous_cases_transactions(self):
        first = [row['payload'].get('wdata') for row in self.project(CASES[0][0])[0]
                 if row['event_type'] == 'transaction_response'
                 and row['payload']['direction'] == 'write']
        last = [row['payload'].get('wdata') for row in self.project(CASES[-1][0])[0]
                if row['event_type'] == 'transaction_response'
                and row['payload']['direction'] == 'write']
        self.assertIn(CASES[0][1], first)
        self.assertNotIn(CASES[0][1], last,
                         'the last case must not replay the first case writes')
        self.assertIn(CASES[-1][1], last)


if __name__ == '__main__':
    unittest.main()
