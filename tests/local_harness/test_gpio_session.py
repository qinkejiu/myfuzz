"""Generated PULP GPIO session keeps environmental inputs and RTL receipts."""
from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.wire import DriverReceipt


def receipt(tick, *, out=0, irq=0, rdata=0, error=0):
    snapshot = {'gpio_out': out, 'gpio_dir': 0, 'gpio_in_sync': 0,
                'gpio_padcfg': '0' * 32, 'interrupt': irq,
                'backend': {}, 'physical': {}}
    payload = {'samples': [{'local_tick': tick, 'pre': snapshot, 'post': snapshot}],
               'observations': snapshot, 'rdata': rdata, 'error': error}
    return DriverReceipt('result', 'a' * 32, tick, tick-1, tick, 1, payload=payload)


class GeneratedGpioSessionTests(unittest.TestCase):
    def make_session(self, *replies):
        document = {'schema_version': 'local_runtime_artifact.v1',
                    'driver_schema_version': 'local_driver_generation.v1',
                    'status': 'driver_generated', 'driver_status': 'generated',
                    'kind': 'apb_gpio', 'artifact_digest': 'a'*64,
                    'driver_reset': {'schema_version': 'generated_local_reset.v1',
                                     'reset_assert_ticks': 8, 'reset_release_ticks': 4},
                    'effective_max_wait_cycles': 8}
        artifact = type('Artifact', (), {'runtime_document': document})()
        session = GeneratedPulpGpioSession(artifact, base_dir=Path('.'), cache_dir=Path('.'))
        session.command = Mock(side_effect=replies)
        return session

    def test_environment_pin_persists_through_access_and_outputs_come_from_receipt(self):
        session = self.make_session(receipt(1, out=0xa5), receipt(2, out=0xa5),
                                    receipt(3, out=0xa5, rdata=0xa5))
        observed = session.step_local({'gpio_in': 3})
        session.write_register(0x0c, 0xa5)
        readback = session.read_register(0x0c)
        self.assertEqual(0xa5, observed['gpio_out'])
        self.assertEqual(0xa5, readback)
        self.assertEqual([('STEP_GPIO', (3,)),
                          ('ACCESS_GPIO', (3, 1, 0x0c, 0xa5, 15)),
                          ('ACCESS_GPIO', (3, 0, 0x0c, 0, 15))],
                         [call.args for call in session.command.call_args_list])

    def test_partial_write_rejected_before_rtl_command(self):
        session = self.make_session()
        with self.assertRaisesRegex(ValueError, 'full-word'):
            session.write_register(0x0c, 0xffff, be=1)
        session.command.assert_not_called()

    def test_irq_pulse_samples_are_preserved(self):
        session = self.make_session(receipt(1, irq=1))
        self.assertEqual(1, session.step_local({'gpio_in': 1})['irq'])
        samples = session.drain_tick_samples()
        self.assertEqual(1, len(samples))
        self.assertEqual(1, samples[0]['post']['interrupt'])
        self.assertEqual([], session.drain_tick_samples())

    def test_explicit_reset_discards_undelivered_pre_reset_samples(self):
        session = self.make_session(receipt(1, irq=1))
        session.step_local({'gpio_in': 1})
        self.assertEqual(1, len(session._samples))
        with patch.object(GeneratedLocalSession, 'reset_local', return_value={'cancelled_responses': 0}):
            session.reset_local()
        self.assertEqual([], session.drain_tick_samples())
        self.assertEqual(0, session._gpio_in)


if __name__ == '__main__':
    unittest.main()
