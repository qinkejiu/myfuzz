"""TX-04: local transport reordering must preserve each source channel."""

import unittest

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


class TransactionOrderTests(unittest.TestCase):
    def test_blocked_target_step_uses_only_its_own_local_tick_budget(self):
        class Target:
            max_local_ticks_per_step = 1
            max_local_ticks_per_register_access = 5

            def __init__(self):
                self.local_ticks = 0
                self.writes = []

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                self.local_ticks += 1
                return {}

            def write_register(self, offset, value, *, be=15):
                self.writes.append(value)

            def read_register(self, offset):
                return 0

            def end_case(self):
                pass

        class Source:
            max_local_ticks_per_step = 1
            max_mmio_target_accesses_per_step = 0
            max_transaction_events_per_step = 0

            def __init__(self, router):
                self.router = router
                self.ledger = TransactionLedger()
                self.local_ticks = 0

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                self.local_ticks += 1
                for sequence, address in ((1, 0x40000014),
                                          (2, 0x50000014)):
                    self.router.enqueue(
                        self.ledger,
                        TransactionKey("exec", "case", "cpu", 0,
                                       "data", sequence),
                        address=address, write=True, wdata=sequence,
                        be=15, beat_bytes=4, callback=lambda _receipt: None)
                return {}

            def end_case(self):
                pass

        a, b = Target(), Target()
        router = DataflowRouter((
            DeviceWindow("a", 0x40000000, 0x1000, a),
            DeviceWindow("b", 0x50000000, 0x1000, b)))
        runner = ScenarioRunner(
            sessions={"cpu": Source(router), "a": a, "b": b},
            ownership=compile_ownership((), ()), bindings=())
        runner.set_resource_budget(ResourceBudget(
            max_local_cycles_per_component=1,
            max_scheduler_steps=10, max_transactions=1))
        runner.begin_test("blocked-target-budget")
        try:
            runner.step("cpu")
            runner.step("b")
            self.assertEqual(1, b.local_ticks)
            self.assertEqual([], b.writes)
            self.assertEqual({"a": 1, "b": 1}, runner.final_state_document()[
                "pending_target_requests"])
            self.assertIsNone(runner.failure_status)
        finally:
            runner.finalize()

    def test_later_request_to_other_target_waits_for_source_channel_order(self):
        class Target:
            def __init__(self):
                self.writes = []

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": len(self.writes)}

            def write_register(self, offset, value, *, be=15):
                self.writes.append(value)

            def read_register(self, offset):
                return 0

            def end_case(self):
                pass

        class Source:
            def __init__(self, router):
                self.router = router
                self.ledger = TransactionLedger()

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                for sequence, address in ((1, 0x40000014),
                                          (2, 0x50000014)):
                    self.router.enqueue(
                        self.ledger,
                        TransactionKey("exec", "case", "cpu", 0,
                                       "data", sequence),
                        address=address, write=True, wdata=sequence,
                        be=15, beat_bytes=4, callback=lambda _receipt: None)
                return {"out": 0}

            def end_case(self):
                pass

        a, b = Target(), Target()
        router = DataflowRouter((
            DeviceWindow("a", 0x40000000, 0x1000, a),
            DeviceWindow("b", 0x50000000, 0x1000, b)))
        runner = ScenarioRunner(
            sessions={"cpu": Source(router), "a": a, "b": b},
            ownership=compile_ownership((), ()), bindings=())
        runner.begin_test("cross-target-order")
        try:
            runner.step("cpu")
            self.assertEqual(("a",), router.ready_targets)
            runner.step("b")
            self.assertEqual([], b.writes)
            self.assertEqual({"a": 1, "b": 1}, runner.final_state_document()[
                "pending_target_requests"])
            runner.step("a")
            self.assertEqual(("b",), router.ready_targets)
            runner.step("b")
            self.assertEqual([1], a.writes)
            self.assertEqual([2], b.writes)
            self.assertEqual([1, 2], [entry["source_sequence"]
                                      for entry in router.deliveries])
        finally:
            runner.finalize()

    def test_separate_routers_cannot_drive_same_local_target(self):
        class Target:
            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {}

            def end_case(self):
                pass

        class Source:
            def __init__(self, router):
                self.router = router

        target = Target()
        first = DataflowRouter((DeviceWindow(
            "target", 0x40000000, 0x1000, target),))
        second = DataflowRouter((DeviceWindow(
            "target", 0x40000000, 0x1000, target),))
        with self.assertRaisesRegex(ValueError, "shared target router"):
            ScenarioRunner(
                sessions={"a": Source(first), "b": Source(second),
                          "target": target},
                ownership=compile_ownership((), ()), bindings=())

    def test_router_target_must_be_registered_local_harness(self):
        class Target:
            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {}

            def end_case(self):
                pass

        class Source:
            def __init__(self, router):
                self.router = router

        declared, hidden = Target(), Target()
        router = DataflowRouter((DeviceWindow(
            "target", 0x40000000, 0x1000, hidden),))
        with self.assertRaisesRegex(ValueError, "registered local harness"):
            ScenarioRunner(
                sessions={"cpu": Source(router), "target": declared},
                ownership=compile_ownership((), ()), bindings=())

    def test_shared_target_queue_drains_one_request_per_step_in_acceptance_order(self):
        class Target:
            def __init__(self):
                self.writes = []

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": len(self.writes)}

            def write_register(self, offset, value, *, be=15):
                self.writes.append(value)

            def read_register(self, offset):
                return 0

            def end_case(self):
                pass

        class Source:
            def __init__(self, name, router):
                self.name = name
                self.router = router
                self.ledger = TransactionLedger()

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                self.router.enqueue(
                    self.ledger, TransactionKey("exec", "case", self.name,
                                                0, "data", 1),
                    address=0x40000014, write=True,
                    wdata=1 if self.name == "b" else 2, be=15,
                    beat_bytes=4, callback=lambda _receipt: None)
                return {"out": 0}

            def end_case(self):
                pass

        target = Target()
        router = DataflowRouter((DeviceWindow(
            "target", 0x40000000, 0x1000, target),))
        runner = ScenarioRunner(
            sessions={"a": Source("a", router),
                      "b": Source("b", router), "target": target},
            ownership=compile_ownership((), ()), bindings=())
        runner.begin_test("shared-target-order")
        try:
            runner.step("b")
            runner.step("a")
            self.assertEqual({"target": 2}, runner.final_state_document()[
                "pending_target_requests"])
            runner.step("target")
            self.assertEqual([1], target.writes)
            self.assertEqual({"target": 1}, runner.final_state_document()[
                "pending_target_requests"])
            runner.step("target")
            self.assertEqual([1, 2], target.writes)
            self.assertEqual(["b", "a"], [item["source_transaction"].source_component
                                          for item in router.deliveries])
        finally:
            runner.finalize()

    def key(self, channel: str, sequence: int) -> TransactionKey:
        return TransactionKey("execution", "case", "cpu", 0,
                              channel, sequence)

    def test_later_same_channel_request_cannot_run_before_first(self):
        ledger = TransactionLedger()
        effects = []

        def execute(sequence):
            effects.append(sequence)
            return {"sequence": sequence}

        with self.assertRaisesRegex(ValueError, "out_of_order"):
            ledger.execute_once(self.key("data", 2), {"value": 2},
                                lambda: execute(2))
        self.assertEqual([], effects)
        first = ledger.execute_once(self.key("data", 1), {"value": 1},
                                    lambda: execute(1))
        second = ledger.execute_once(self.key("data", 2), {"value": 2},
                                     lambda: execute(2))
        self.assertEqual([1, 2], effects)
        self.assertEqual({"sequence": 1}, first)
        self.assertEqual({"sequence": 2}, second)
        self.assertIs(first, ledger.execute_once(self.key("data", 1),
                    {"value": 1}, lambda: execute(1)))
        self.assertEqual([1, 2], effects)

    def test_independent_local_channels_have_independent_order(self):
        ledger = TransactionLedger()
        effects = []
        ledger.execute_once(self.key("instruction", 1), {"address": 0},
                            lambda: effects.append("instruction-1"))
        ledger.execute_once(self.key("data", 1), {"address": 4},
                            lambda: effects.append("data-1"))
        self.assertEqual(["instruction-1", "data-1"], effects)
        with self.assertRaisesRegex(ValueError, "out_of_order"):
            ledger.execute_once(self.key("data", 3), {"address": 12},
                                lambda: effects.append("data-3"))
        self.assertEqual(["instruction-1", "data-1"], effects)

    def test_accepted_requests_wait_for_ordered_target_completion(self):
        ledger = TransactionLedger()
        effects = []
        first, second = self.key("data", 1), self.key("data", 2)
        self.assertTrue(ledger.accept(first, {"value": 1}))
        self.assertFalse(ledger.accept(first, {"value": 1}))
        self.assertTrue(ledger.accept(second, {"value": 2}))
        self.assertEqual((first, second), ledger.pending_keys)
        self.assertEqual([], effects)
        with self.assertRaisesRegex(ValueError, "out_of_order_target_delivery"):
            ledger.complete_accepted(second, {"value": 2},
                                     lambda: effects.append(2))
        self.assertEqual([], effects)
        receipt = ledger.complete_accepted(
            first, {"value": 1}, lambda: effects.append(1) or {"value": 1})
        self.assertIs(receipt, ledger.complete_accepted(
            first, {"value": 1}, lambda: effects.append(1)))
        ledger.complete_accepted(second, {"value": 2},
                                 lambda: effects.append(2))
        self.assertEqual([1, 2], effects)
        self.assertEqual((), ledger.pending_keys)

    def test_cancelled_accepted_request_has_no_target_effect(self):
        ledger = TransactionLedger()
        key = self.key("data", 1)
        ledger.accept(key, {"value": 1})
        ledger.cancel_accepted(key, {"value": 1})
        self.assertEqual((), ledger.pending_keys)
        self.assertEqual((), ledger.unresolved_keys)
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            ledger.complete_accepted(key, {"value": 1}, lambda: 1)


if __name__ == "__main__":
    unittest.main()
