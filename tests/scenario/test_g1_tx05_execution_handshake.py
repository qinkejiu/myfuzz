"""TX-05: one genome across executions, a stale reply, and held valid."""

from io import StringIO
from types import SimpleNamespace
import unittest

from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.runner import ScenarioRunner


ADDRESS = 0x80000040


def result(token, sequence, *, request, response_ready):
    return (f"RESULT {token} {sequence:x} {request:x} 1 {ADDRESS:x} "
            f"11223344 ff {response_ready:x} {sequence:x}\n")


class _WireCva6Fixture:
    """Run the production CVA6 command parser against declared wire replies."""

    max_transaction_events_per_step = 1
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, token, *, stale_token="", lose_pending=False):
        self.token = token
        self.stale_token = stale_token
        self.lose_pending = lose_pending
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x1000),),
            initialization_seed=3, max_initialized_bytes=64)
        self.service = MemoryService(self.memory, TransactionLedger())
        self.local_ticks = 0
        self.reset_epoch = 0
        self._pending = None
        self._queued_mmio = False
        self._quiescing = False
        self._sequence = 0
        self._command_sequence = 0
        self._wire_execution = ""
        self._process = None
        self._testcase_id = ""
        self.router = None
        self.memory_write_count = 0
        self.memory_read_count = 0
        self.mmio_write_count = 0
        self.mmio_read_count = 0
        self.begins = 0
        self.reads = 0
        self.commands = ""

    def identity_document(self):
        return {"fixture": "tx05-wire-held-valid-v1"}

    def begin_case(self, testcase_id):
        self.begins += 1
        self._testcase_id = testcase_id
        self._wire_execution = self.token
        replies = ([result(self.stale_token, 1, request=0,
                           response_ready=0)] if self.stale_token else [])
        replies += [result(self.token, tick, request=int(tick <= 3),
                           response_ready=int(tick == 4))
                    for tick in range(1, 6)]
        self._process = SimpleNamespace(
            poll=lambda: None, stdin=StringIO(), stdout=_CountingStream(replies))

    def step_local(self, inputs):
        if self.lose_pending and self.local_ticks in (1, 2):
            self._pending = None  # injection: forget accepted held-valid request
        return Cva6CpuSession.step_local(self, inputs)

    def end_case(self):
        self.reads = self._process.stdout.reads
        self.commands = self._process.stdin.getvalue()
        self._process = None


class _CountingStream:
    def __init__(self, lines):
        self.lines = list(lines)
        self.reads = 0

    def readline(self):
        self.reads += 1
        return self.lines.pop(0) if self.lines else ""


class Tx05ExecutionHandshakeTests(unittest.TestCase):
    genome = ScenarioGenome("tx05-same-case", "CPU_TO_IP", "tx05-held-valid",
                            ("cpu",), 5, ())

    def run_case(self, token, *, stale_token="", lose_pending=False):
        fixture = _WireCva6Fixture(token, stale_token=stale_token,
                                   lose_pending=lose_pending)

        def factory():
            return ScenarioRunner(sessions={"cpu": fixture},
                                  ownership=compile_ownership((), ()),
                                  bindings=())

        trace = record_scenario(self.genome, factory)
        return fixture, trace

    def assert_one_accepted_write(self, fixture, trace, *, stale_count):
        self.assertEqual("complete", trace.status)
        self.assertEqual(1, fixture.begins)
        self.assertEqual(5, fixture.local_ticks)
        self.assertEqual(5 + stale_count, fixture.reads)
        self.assertEqual(5, fixture._command_sequence)
        commands = fixture.commands.splitlines()
        self.assertEqual(5, len(commands))
        self.assertTrue(all(line.startswith(f"CMD {fixture.token} ")
                            for line in commands))
        self.assertEqual(1, fixture._sequence)
        self.assertEqual(1, fixture.memory_write_count)
        self.assertEqual(1, len([event for event in fixture.service.events
                                 if event["kind"] == "memory_write"]))
        read = fixture.memory.read(ADDRESS, 8, transaction_id="check")
        self.assertEqual(0x11223344, read.value & 0xFFFFFFFF)
        self.assertEqual(1, read.versions[0][1])
        self.assertEqual(5, trace.local_ticks["cpu"])
        outputs = [event["outputs"] for event in trace.events
                   if event.get("component") == "cpu" and "outputs" in event]
        self.assertEqual([1, 1, 1, 0, 0],
                         [output["req_valid"] for output in outputs])
        self.assertEqual([0, 0, 0, 1, 0],
                         [output["response_consumed"] for output in outputs])

    def test_same_genome_two_executions_skip_old_reply_and_hold_valid(self):
        first, first_trace = self.run_case("execution-one")
        self.assert_one_accepted_write(first, first_trace, stale_count=0)
        second, second_trace = self.run_case(
            "execution-two", stale_token="execution-one")
        self.assert_one_accepted_write(second, second_trace, stale_count=1)
        self.assertEqual(first_trace.events, second_trace.events)
        self.assertEqual(first_trace.semantic_sha256,
                         second_trace.semantic_sha256)

    def test_held_valid_duplicate_acceptance_fault_is_detected(self):
        fixture, trace = self.run_case("execution-one", lose_pending=True)
        with self.assertRaises(AssertionError, msg="TX-05 held-valid fault not detected"):
            self.assert_one_accepted_write(fixture, trace, stale_count=0)
        self.assertGreater(fixture.memory_write_count, 1)

    def test_old_reply_token_reuse_fault_is_detected(self):
        # Injection: a new execution accidentally reuses the previous wire token.
        fixture, trace = self.run_case(
            "execution-one", stale_token="execution-one")
        self.assertEqual("uncertain_effect", trace.status)
        self.assertEqual(1, fixture.local_ticks)
        self.assertEqual(0, fixture.memory_write_count)
        self.assertEqual(2, fixture.reads)
        self.assertTrue(any(event.get("kind") == "harness_failure"
                            for event in trace.events))


if __name__ == "__main__":
    unittest.main()
