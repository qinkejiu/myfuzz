"""TX-01: source retransmission never repeats a FIFO target effect."""

from collections import deque
import unittest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger


class Tx01FifoTests(unittest.TestCase):
    def test_duplicate_before_acceptance_and_after_completion_uses_one_receipt(self):
        ledger = TransactionLedger()
        key = TransactionKey("exec", "case", "cpu", 0, "data", 1)
        payload = {"target": "fifo", "operation": "pop_push", "count": 1}
        fifo = deque([0xA5])
        pushed = []
        calls = []

        def target_operation():
            calls.append("target")
            value = fifo.popleft()
            pushed.append(value ^ 0xFF)
            return {"read_data": value, "pushed_data": pushed[-1]}

        self.assertTrue(ledger.accept(key, payload))
        self.assertFalse(ledger.accept(key, payload))
        self.assertEqual([0xA5], list(fifo))
        self.assertEqual([], pushed)

        first = ledger.complete_accepted(key, payload, target_operation)
        after_completion = ledger.complete_accepted(
            key, payload, target_operation)
        after_transport_retry = ledger.execute_once(
            key, payload, target_operation)
        self.assertEqual({"read_data": 0xA5, "pushed_data": 0x5A}, first)
        self.assertIs(first, after_completion)
        self.assertIs(first, after_transport_retry)
        self.assertEqual(["target"], calls)
        self.assertEqual([], list(fifo))
        self.assertEqual([0x5A], pushed)
        self.assertEqual((), ledger.unresolved_keys)


if __name__ == "__main__":
    unittest.main()
