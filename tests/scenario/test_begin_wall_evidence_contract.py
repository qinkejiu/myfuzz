"""Evidence validation for watchdog cuts during local harness startup."""

import unittest
from dataclasses import asdict
from types import SimpleNamespace

from myfuzz.scenario.cva6_session import Cva6CpuSession
from myfuzz.scenario.evidence import (_evidence_record_bound,
                                      _final_state_growth_bound,
                                      _wall_cut_event)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import _canonical


class BeginWallEvidenceContractTests(unittest.TestCase):
    def test_real_memory_service_store_then_load_with_long_runner_name(self):
        component = "cva6-" + "x" * 5000
        genome = ScenarioGenome(testcase_id="stored-read",
                                direction="CPU_TO_IP", path_id="memory",
                                schedule_order=(component,), max_steps=1,
                                actions=())
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=1, max_initialized_bytes=0x100)
        service = MemoryService(memory, TransactionLedger())
        store_key = TransactionKey("local-execution", genome.testcase_id,
                                   "cva6", 0, "unified", 1)
        load_key = TransactionKey("local-execution", genome.testcase_id,
                                  "cva6", 0, "unified", 2)
        service.write(store_key, 0x1000, 0x1122334455667788,
                      width_bytes=8, byte_enable=255)
        snapshot = service.read(load_key, 0x1000, width_bytes=8)
        self.assertEqual((str(store_key),) * 8,
                         snapshot.writer_event_ids)
        record = {"event_id": 2, "component": component,
                  **service.events[-1]}
        session = object.__new__(Cva6CpuSession)
        session.memory = memory
        runner = SimpleNamespace(sessions={component: session})
        self.assertGreaterEqual(
            _evidence_record_bound(genome, runner, ResourceBudget()),
            len(_canonical(record)) + 1)

    def test_cva6_read_record_bounds_eight_persisted_writer_identities(self):
        testcase_id = "case-" + "x" * 5000
        genome = ScenarioGenome(testcase_id=testcase_id,
                                direction="CPU_TO_IP", path_id="memory",
                                schedule_order=("cpu",), max_steps=1,
                                actions=())
        runner = SimpleNamespace(sessions={"cpu": object.__new__(Cva6CpuSession)})
        key = TransactionKey("local-execution", testcase_id, "cva6", 0,
                             "unified", 1)
        record = {"event_id": 1, "kind": "memory_read", "component": "cpu",
                  "transaction": asdict(key), "address": 0, "width_bytes": 8,
                  "memory_id": "ram", "generation": 0, "byte_offset": 0,
                  "value": 0, "data_hex": "0000000000000000",
                  "versions": ((0, 1),) * 8,
                  "writer_event_ids": (str(key),) * 8}
        self.assertGreaterEqual(
            _evidence_record_bound(genome, runner, ResourceBudget()),
            len(_canonical(record)) + 1)

    def test_reset_record_bound_includes_all_memory_region_names(self):
        genome = ScenarioGenome(testcase_id="reset", direction="CPU_TO_IP",
                                path_id="memory", schedule_order=("cpu",),
                                max_steps=1, actions=())
        memory_ids = tuple(f"region-{index}-" + "x" * 2000
                           for index in range(10))
        session = object.__new__(Cva6CpuSession)
        session.memory = SimpleNamespace(memory_ids=memory_ids)
        runner = SimpleNamespace(sessions={"cpu": session})
        record = {"event_id": 1, "kind": "reset_barrier",
                  "policy": "warm_all",
                  "memory_generations": {name: 1 for name in memory_ids},
                  "cancelled_responses": {},
                  "cancelled_target_requests": {},
                  "pending_responses_before_reset": {"cpu": 0},
                  "pending_events_before_reset": {},
                  "pending_events_after_reset": {},
                  "cancelled_dataflow_targets": (),
                  "cancelled_irq_pulses": {}}
        self.assertGreaterEqual(
            _evidence_record_bound(genome, runner, ResourceBudget()),
            len(_canonical(record)) + 1)

    def test_first_read_bound_includes_region_name_in_each_writer_id(self):
        genome = ScenarioGenome(testcase_id="first-read", direction="CPU_TO_IP",
                                path_id="memory", schedule_order=("cpu",),
                                max_steps=1, actions=())
        memory_id = "ram-" + "x" * 5000
        session = object.__new__(Cva6CpuSession)
        session.memory = SimpleNamespace(memory_ids=(memory_id,))
        runner = SimpleNamespace(sessions={"cpu": session})
        key = TransactionKey("local-execution", "first-read", "cva6", 0,
                             "unified", 1)
        record = {"event_id": 1, "kind": "memory_read", "component": "cpu",
                  "transaction": asdict(key), "address": 0, "width_bytes": 8,
                  "memory_id": memory_id, "generation": 0, "byte_offset": 0,
                  "value": 0, "data_hex": "0000000000000000",
                  "versions": ((0, 1),) * 8,
                  "writer_event_ids": tuple(f"init:{memory_id}:{lane}"
                                            for lane in range(8))}
        self.assertGreaterEqual(
            _evidence_record_bound(genome, runner, ResourceBudget()),
            len(_canonical(record)) + 1)

    def test_source_record_bound_includes_ownership_source_reference(self):
        genome = ScenarioGenome(testcase_id="pin", direction="IP_TO_IP",
                                path_id="pin", schedule_order=("gpio",),
                                max_steps=1, actions=())
        source_ref = "external-" + "x" * 20000
        ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", source_ref),))
        from myfuzz.scenario.gpio_session import OpenTitanGpioSession
        runner = SimpleNamespace(
            sessions={"gpio": object.__new__(OpenTitanGpioSession)},
            ownership=ownership)
        record = {"event_id": 1, "kind": "source_injection",
                  "action_id": "rise", "component": "gpio", "port": "pin",
                  "source_ref": source_ref, "direction": "IP_TO_IP",
                  "bit_offset": 0, "width": 1, "value": 1}
        self.assertGreaterEqual(
            _evidence_record_bound(genome, runner, ResourceBudget()),
            len(_canonical(record)) + 1)

    def test_mmio_record_bound_includes_window_device_identity(self):
        genome = ScenarioGenome(testcase_id="mmio", direction="CPU_TO_IP",
                                path_id="mmio", schedule_order=("cpu",),
                                max_steps=1, actions=())
        device_id = "device-" + "x" * 20000
        session = object.__new__(Cva6CpuSession)
        session.router = SimpleNamespace(
            windows=(SimpleNamespace(device_id=device_id),))
        runner = SimpleNamespace(sessions={"cpu": session})
        record = {"event_id": 1, "kind": "mmio_delivery",
                  "component": "cpu", "device_id": device_id,
                  "source_sequence": 1, "address": 0,
                  "beat_bytes": 8, "offset": 0, "write": True,
                  "byte_enable": 255, "write_value": 1,
                  "read_value": None}
        self.assertGreaterEqual(
            _evidence_record_bound(genome, runner, ResourceBudget()),
            len(_canonical(record)) + 1)

    def test_one_step_state_growth_includes_queued_window_identity(self):
        genome = ScenarioGenome(testcase_id="queued-mmio",
                                direction="CPU_TO_IP", path_id="mmio",
                                schedule_order=("cpu",), max_steps=1,
                                actions=())
        device_id = "device-" + "x" * 20000
        session = object.__new__(Cva6CpuSession)
        session.router = SimpleNamespace(
            windows=(SimpleNamespace(device_id=device_id),))
        runner = SimpleNamespace(sessions={"cpu": session})
        growth = len(_canonical({"pending_target_requests": {device_id: 1}}))
        self.assertGreaterEqual(
            _final_state_growth_bound(genome, runner, ResourceBudget()),
            growth)

    def test_begin_wall_markers_have_a_replayable_prefix(self):
        initial = {"event_id": 1, "kind": "initial_image"}
        for phase, effect in (("before_begin", False),
                              ("inflight_begin", True)):
            with self.subTest(phase=phase):
                marker = {
                    "event_id": 2, "kind": "budget_exhausted",
                    "limit": "max_wall_time_ms", "phase": phase,
                    "effect_may_have_occurred": effect,
                    "prefix_event_count": 1,
                    "prefix_local_ticks": {"cpu": 0, "gpio": 0},
                    "local_ticks": {"cpu": 0, "gpio": 0},
                    "failed_component": "gpio",
                    "started_components": ("cpu",),
                }
                self.assertEqual(marker, _wall_cut_event(
                    "budget_exhausted", (initial, marker)))

    def test_begin_wall_marker_requires_valid_boundary_and_components(self):
        initial = {"event_id": 1, "kind": "initial_image"}
        marker = {
            "event_id": 2, "kind": "budget_exhausted",
            "limit": "max_wall_time_ms", "phase": "inflight_begin",
            "effect_may_have_occurred": True,
            "prefix_event_count": 1,
            "prefix_local_ticks": {"cpu": 0, "gpio": 0},
            "local_ticks": {"cpu": 0, "gpio": 0},
            "failed_component": "gpio",
            "started_components": ("cpu",),
        }
        for change in ({"prefix_event_count": 0},
                       {"effect_may_have_occurred": False},
                       {"failed_component": ""},
                       {"started_components": ("gpio",)}):
            with self.subTest(change=change):
                invalid = {**marker, **change}
                with self.assertRaisesRegex(ValueError, "begin wall"):
                    _wall_cut_event("budget_exhausted", (initial, invalid))

    def test_finalize_wall_marker_is_an_uncertain_prefix(self):
        prior = {"event_id": 1, "kind": "source_injection"}
        marker = {"event_id": 2, "kind": "budget_exhausted",
                  "limit": "max_wall_time_ms", "phase": "inflight_finalize",
                  "effect_may_have_occurred": True,
                  "prefix_event_count": 1,
                  "prefix_local_ticks": {"gpio": 1},
                  "local_ticks": {"gpio": 1}}
        self.assertEqual(marker, _wall_cut_event(
            "budget_exhausted", (prior, marker)))
        for change in ({"prefix_event_count": 0},
                       {"effect_may_have_occurred": False}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "inflight wall"):
                    _wall_cut_event("budget_exhausted",
                                    (prior, {**marker, **change}))


if __name__ == "__main__":
    unittest.main()
