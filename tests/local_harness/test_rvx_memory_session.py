"""Stateful exact-once service tests for the RVX completion interface."""
from pathlib import Path
from types import SimpleNamespace
import unittest

from myfuzz.local_harness.rvx_memory_session import GeneratedRvxMemorySession
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory


def _backend(*, addr=0, read=0, write=0, write_data=0, write_strobe=0,
             read_response=0, write_response=0, read_data=0):
    return {
        "rvx_addr": addr,
        "rvx_read_request": read,
        "rvx_read_response": read_response,
        "rvx_read_data": read_data,
        "rvx_write_request": write,
        "rvx_write_response": write_response,
        "rvx_write_data": write_data,
        "rvx_write_strobe": write_strobe,
    }


def _receipt(pre, post=None, observation_backend=None):
    post = pre if post is None else post
    observation_backend = post if observation_backend is None else observation_backend
    sample = {"local_tick": 1, "pre": {"backend": dict(pre), "physical": {}},
              "post": {"backend": dict(post), "physical": {}}}
    payload = {"pre_backend": dict(pre), "samples": [sample],
               "observations": {"backend": dict(observation_backend), "physical": {}}}
    return SimpleNamespace(status="result", new_ticks=1, payload=payload,
                           tick_before=0, tick_after=1)


class FakeRvxMemorySession(GeneratedRvxMemorySession):
    def __init__(self, *, memory, receipts, response_latency_ticks=1):
        plan = SimpleNamespace(request=SimpleNamespace(instance_id="rvx_cpu"))
        artifact = SimpleNamespace(runtime_document={"kind": "rvx_memory_cpu",
                                                    "effective_max_wait_cycles": 16},
                                   plan=plan)
        super().__init__(artifact, base_dir=Path("/tmp"), cache_dir=Path("/tmp"),
                         memory=memory,
                         response_latency_ticks=response_latency_ticks)
        self.receipts = list(receipts)
        self.commands = []
        self._case_id = "case0"
        self._process = object()

    def command(self, operation, fields):
        self.commands.append((operation, fields))
        if operation != "STEP_RVX_MEMORY" or not self.receipts:
            raise AssertionError("unexpected RVX driver command")
        return self.receipts.pop(0)

    def begin_case(self, testcase_id):
        self._case_id = testcase_id
        self._process = object()
        self._pending = None
        self._sequence_memory = 0

    def end_case(self):
        self._process = None

    def _abort(self):
        self._process = None


def _memory():
    return PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x1000, readable=True, writable=True),),
        initialization_seed=19,
        max_initialized_bytes=0x1000,
    )


class RvxMemorySessionTests(unittest.TestCase):
    def test_held_write_is_committed_once_then_identical_completion_edge_is_new(self):
        memory = _memory()
        request = dict(addr=0x100, write=1, write_data=0xA1B2C3D4,
                       write_strobe=0xF)
        session = FakeRvxMemorySession(
            memory=memory,
            response_latency_ticks=2,
            receipts=[
                _receipt(_backend(**request)),
                _receipt(_backend(**request)),
                _receipt(_backend(**request, write_response=1)),
            ],
        )

        first = session.step_local({})
        held = session.step_local({})
        second = session.step_local({})

        writes = [event for event in session.service.events if event["kind"] == "memory_write"]
        self.assertEqual(len(writes), 2)
        self.assertEqual([item["transaction"]["source_sequence"] for item in writes], [1, 2])
        self.assertEqual(first["data_req_accepted"], 1)
        self.assertEqual(held["data_req_accepted"], 0)
        self.assertEqual(held["data_rsp_consumed"], 0)
        self.assertEqual(second["data_rsp_consumed"], 1)
        self.assertEqual(second["data_req_accepted"], 1)
        self.assertEqual(session.commands, [
            ("STEP_RVX_MEMORY", (0, 0, 0)),
            ("STEP_RVX_MEMORY", (0, 0, 0)),
            ("STEP_RVX_MEMORY", (0, 1, 0)),
        ])

    def test_byte_enable_updates_only_selected_lane(self):
        memory = _memory()
        memory.preload(0x100, (0x12345678).to_bytes(4, "little"))
        session = FakeRvxMemorySession(
            memory=memory,
            receipts=[_receipt(_backend(addr=0x100, write=1,
                                        write_data=0x00005500, write_strobe=0b0010))],
        )
        session.step_local({})
        self.assertEqual(memory.read(0x100, 4, transaction_id="inspect").value,
                         0x12345578)
        event = next(event for event in session.service.events
                     if event["kind"] == "memory_write")
        self.assertEqual(event["byte_enable"], 0b0010)

    def test_uninitialized_read_snapshot_is_frozen_until_completion(self):
        memory = _memory()
        session = FakeRvxMemorySession(
            memory=memory,
            receipts=[_receipt(_backend(addr=0x200, read=1))],
        )
        session.step_local({})
        frozen = session._pending["response_data"]
        memory.write(0x200, 0xDEADBEEF, width_bytes=4, byte_enable=0xF,
                     writer_event_id="external-update")
        session.receipts.append(_receipt(_backend(addr=0x200, read=1,
                                                  read_response=1, read_data=frozen)))
        result = session.step_local({})
        self.assertEqual(result["data_rsp_rdata"], frozen)
        self.assertEqual(session.commands[-1][1], (1, 0, frozen))
        self.assertNotEqual(memory.read(0x200, 4, transaction_id="inspect").value, frozen)

    def test_rejects_post_edge_observation_that_disagrees_with_tick_sample(self):
        memory = _memory()
        sample_post = _backend(addr=0x200, read=1)
        inconsistent_observation = _backend(addr=0x204, read=1)
        session = FakeRvxMemorySession(
            memory=memory,
            receipts=[_receipt(_backend(addr=0x200, read=1), post=sample_post,
                               observation_backend=inconsistent_observation)],
        )

        with self.assertRaisesRegex(ProtocolEnvironmentError, "post-edge snapshots disagree"):
            session.step_local({})
        self.assertEqual(session.service.events, [])
        self.assertEqual(memory.initialized_bytes, 0)

    def test_unaligned_and_unmapped_requests_terminate_as_environment_errors(self):
        for address in (0x101, 0x1000):
            with self.subTest(address=address):
                session = FakeRvxMemorySession(
                    memory=_memory(),
                    receipts=[_receipt(_backend(addr=address, read=1))],
                )
                with self.assertRaises(ProtocolEnvironmentError):
                    session.step_local({})

    def test_warm_reset_cancels_pending_without_rolling_back_committed_write(self):
        memory = _memory()
        session = FakeRvxMemorySession(
            memory=memory,
            receipts=[_receipt(_backend(addr=0x300, write=1,
                                        write_data=0xCAFEBABE, write_strobe=0xF))],
        )
        session.step_local({})
        self.assertEqual(session.pending_responses, 1)
        session.reset_local()
        self.assertEqual(session.pending_responses, 0)
        self.assertEqual(memory.read(0x300, 4, transaction_id="inspect").value,
                         0xCAFEBABE)


if __name__ == "__main__":
    unittest.main()
