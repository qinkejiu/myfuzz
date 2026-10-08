"""Bounded PULP I2C IRQ acknowledgement protocol."""
from collections import deque
from types import SimpleNamespace
import unittest

from myfuzz.local_harness.i2c_session import GeneratedPulpI2cSession


def _snapshot(irq):
    return {
        'interrupt_o': irq,
        'scl_pad_i': 1,
        'scl_pad_o': 0,
        'scl_padoen_o': 1,
        'sda_pad_i': 1,
        'sda_pad_o': 0,
        'sda_padoen_o': 1,
    }


def _payload(*, before_irq, after_irq):
    samples = []
    if before_irq is not None:
        samples.append({'local_tick': 1, 'pre': _snapshot(before_irq),
                        'post': _snapshot(after_irq)})
    return {'samples': samples,
            'observations': _snapshot(after_irq),
            'error': False,
            'rdata': 0}


def _session_with_replies(access_payload, step_payload=None):
    session = object.__new__(GeneratedPulpI2cSession)
    session._peer_response = 0x5a
    session._write_stage = 6  # Read command issued; wait for completion IRQ.
    session._irq_level = 1
    session._tick_base = 0
    session._samples = deque()
    session.irq_edges = []
    calls = []

    def command(operation, fields):
        calls.append((operation, fields))
        payload = step_payload if operation == 'STEP_I2C' and step_payload is not None \
            else access_payload
        return SimpleNamespace(status='result', payload=payload,
                               error_code=None)

    session.command = command
    return session, calls


class PulpI2cIrqFsmTests(unittest.TestCase):
    def test_second_iack_is_accepted_only_after_read_completion_and_clears_irq(self):
        session, calls = _session_with_replies(
            _payload(before_irq=1, after_irq=1),
            _payload(before_irq=1, after_irq=0))

        session.write_register(20, 1)

        self.assertEqual([('ACCESS_I2C', (1, 20, 1, 15)),
                          ('STEP_I2C', (0,))], calls)
        self.assertEqual(7, session._write_stage)
        self.assertEqual(0, session._irq_level)
        self.assertEqual([{'local_tick': 1, 'phase': 'post', 'level': 0}],
                         session.irq_edges)

    def test_second_iack_requires_native_irq_high_before_access(self):
        session, calls = _session_with_replies(_payload(before_irq=0, after_irq=0))
        session._irq_level = 0

        with self.assertRaisesRegex(ValueError, 'native .*IRQ.*high'):
            session.write_register(20, 1)

        self.assertEqual([], calls)
        self.assertEqual(6, session._write_stage)

    def test_second_iack_rejects_rtl_receipt_when_irq_stays_high(self):
        session, calls = _session_with_replies(
            _payload(before_irq=1, after_irq=1),
            _payload(before_irq=1, after_irq=1))

        with self.assertRaisesRegex(RuntimeError, 'IACK.*did not clear.*IRQ'):
            session.write_register(20, 1)

        self.assertEqual([('ACCESS_I2C', (1, 20, 1, 15))]
                         + [('STEP_I2C', (0,))] * 8, calls)
        self.assertEqual(6, session._write_stage)
        self.assertEqual(1, session._irq_level)

    def test_existing_first_iack_then_single_byte_read_order_remains_valid(self):
        session, calls = _session_with_replies(_payload(before_irq=None, after_irq=1))
        session._write_stage = 0
        session._irq_level = 0

        for offset, value in ((0, 2), (4, 0xc0), (16, 0x85), (20, 0x90)):
            session.write_register(offset, value)
        session._irq_level = 1
        session.write_register(20, 1)
        session._irq_level = 0
        session.write_register(20, 0x68)

        self.assertEqual(6, session._write_stage)
        self.assertEqual([
            ('ACCESS_I2C', (1, 0, 2, 15)),
            ('ACCESS_I2C', (1, 4, 0xc0, 15)),
            ('ACCESS_I2C', (1, 16, 0x85, 15)),
            ('ACCESS_I2C', (1, 20, 0x90, 15)),
            ('ACCESS_I2C', (1, 20, 1, 15)),
            ('ACCESS_I2C', (1, 20, 0x68, 15)),
        ], calls)


if __name__ == '__main__':
    unittest.main()
