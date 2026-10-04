"""A rejected timer write cannot invent or resurrect a native IRQ."""
from collections import deque
import unittest
from unittest.mock import patch

from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.zip_timer_session import GeneratedZipTimerSession


class ZipTimerPendingTests(unittest.TestCase):
    def test_begin_case_keeps_append_only_transaction_history_across_reset(self):
        timer = object.__new__(GeneratedZipTimerSession)
        timer.local_transactions = [{'offset': 0, 'write_value': 5}]
        timer._samples = deque()
        with patch.object(GeneratedLocalSession, 'begin_case', return_value=None):
            timer.begin_case('same-case-after-reset')
        self.assertEqual([{'offset': 0, 'write_value': 5}],
                         timer.local_transactions)

    def _session(self, prior_pending, observed_pulse):
        timer = object.__new__(GeneratedZipTimerSession)
        timer._await_irq = prior_pending
        timer._samples = deque()
        timer._tick_base = 0
        sample = {'local_tick': 1,
                  'pre': {'interrupt': 0},
                  'post': {'interrupt': int(observed_pulse)}}
        timer.command = lambda operation, fields: DriverReceipt(
            status='result', execution='0' * 32, sequence=1,
            tick_before=0, tick_after=1, new_ticks=1,
            payload={'observations': {'interrupt': 0},
                     'samples': [sample], 'error': 1, 'rdata': 0})
        return timer

    def test_rejected_write_preserves_only_unobserved_pending_pulse(self):
        for observed_pulse, expected in ((False, 1), (True, 0)):
            with self.subTest(observed_pulse=observed_pulse):
                timer = self._session(True, observed_pulse)
                with self.assertRaisesRegex(RuntimeError, 'Wishbone write error'):
                    timer.write_register(0, 7, be=1)
                self.assertEqual(expected, timer.pending_events)

    def test_old_pulse_before_write_does_not_clear_new_countdown(self):
        for new_pulse, expected in ((False, 1), (True, 0)):
            with self.subTest(new_pulse=new_pulse):
                timer = object.__new__(GeneratedZipTimerSession)
                timer._await_irq = True
                timer._samples = deque()
                timer._tick_base = 0
                def sample(tick, strobe, pre_irq, post_irq):
                    return {'local_tick': tick,
                            'pre': {'interrupt': pre_irq,
                                    'backend': {'timer_target_stb': strobe}},
                            'post': {'interrupt': post_irq,
                                     'backend': {'timer_target_stb': strobe}}}
                samples = [sample(1, 0, 0, 1), sample(2, 1, 1, 0),
                           sample(3, 0, 0, int(new_pulse))]
                timer.command = lambda operation, fields: DriverReceipt(
                    status='result', execution='0' * 32, sequence=1,
                    tick_before=0, tick_after=3, new_ticks=3,
                    payload={'observations': {'interrupt': int(new_pulse)},
                             'samples': samples, 'error': 0, 'rdata': 0})
                timer.write_register(0, 5)
                self.assertEqual(expected, timer.pending_events)


if __name__ == '__main__':
    unittest.main()
