"""Real CV32E40P OBI execution with persistent testcase memory and replay."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_driver,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
PROFILE = "configs/cpus/cv32e40p/component_profile.json"
PROGRAM = (
    0x000200B7,  # lui  x1, 0x20          ; x1 = 0x20000
    0x12345137,  # lui  x2, 0x12345
    0x67810113,  # addi x2, x2, 0x678     ; x2 = 0x12345678
    0x0020A023,  # sw   x2, 0(x1)          ; M[0x20000] = 0x12345678
    0x0010C183,  # lbu  x3, 1(x1)          ; read byte lane 1 from persistent memory
    0x00118193,  # addi x3, x3, 1          ; x3 = 0x57
    0x003080A3,  # sb   x3, 1(x1)          ; update only byte lane 1
    0x0000A203,  # lw   x4, 0(x1)          ; read back the updated full word
    0x0040A223,  # sw   x4, 4(x1)          ; copy the observed value
    0x0000006F,  # jal  x0, 0              ; keep this testcase running
)
PROGRAM_HEX = "".join(word.to_bytes(4, "little").hex() for word in PROGRAM)


class UnusedTarget:
    def read_register(self, offset: int) -> int:
        raise AssertionError("unexpected MMIO read")

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        raise AssertionError("unexpected MMIO write")


def make_artifact():
    request = load_local_harness_request({
        "schema_version": "local_harness.v1",
        "profile_path": PROFILE,
        "instance_id": "cpu",
        "reset_assert_ticks": 8,
        "reset_release_ticks": 8,
        "max_wait_cycles": 16,
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    source = verify_local_source_lock(plan.profile, base_dir=ROOT)
    structural = render_local_harness(plan)
    return render_local_driver(
        render_local_runtime(plan, structural, source, base_dir=ROOT),
        base_dir=ROOT,
    )


class Cv32e40pObiRuntimeAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory(prefix="myfuzz-cv32e40p-obi-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(tempfile.gettempdir()) / "myfuzz-cv32e40p-obi-build-cache"
        cls.cpu_artifact = make_artifact()
        build_local_harness(cls.cpu_artifact, base_dir=ROOT, cache_dir=cls.cache)

    @staticmethod
    def make_memory() -> PersistentMemory:
        return PersistentMemory(
            regions=(MemoryRegion("ram", 0, 0x30000),),
            initialization_seed=19,
            max_initialized_bytes=0x30000,
        )

    def make_cpu(self, memory: PersistentMemory) -> GeneratedCve2Session:
        cpu = GeneratedCve2Session(
            self.cpu_artifact,
            base_dir=ROOT,
            cache_dir=self.cache,
            memory=memory,
            router=DataflowRouter((DeviceWindow(
                "cpu", 0x40000000, 0x1000, UnusedTarget()),)),
        )
        cpu.router = DataflowRouter((DeviceWindow("cpu", 0x40000000, 0x1000, cpu),))
        return cpu

    def test_real_fetch_store_load_byte_enable_and_state_persist_within_case(self) -> None:
        memory = self.make_memory()
        memory.preload(0x10000, bytes.fromhex(PROGRAM_HEX))
        cpu = self.make_cpu(memory)
        initial_epoch = cpu.reset_epoch
        cpu.begin_case("cv32e40p-continuous-memory")
        try:
            samples = []
            for _ in range(160):
                samples.append(cpu.step_local({"irq": 0}))
                if cpu.memory_write_count == 3:
                    break
        finally:
            cpu.end_case()

        self.assertEqual(3, cpu.memory_write_count)
        self.assertEqual(initial_epoch, cpu.reset_epoch)
        self.assertEqual(0x10000, next(
            row["instr_addr"] for row in samples if row["instr_req_accepted"]
        ))
        self.assertTrue(any(row["data_req_accepted"] and not row["data_write"]
                            for row in samples))
        bus_writes = [row for row in samples
                      if row["data_req_accepted"] and row["data_write"]]
        self.assertEqual([0x20000, 0x20001, 0x20004],
                         [row["data_addr"] for row in bus_writes])
        self.assertEqual([0x12345678, 0x00005700, 0x12345778],
                         [row["data_wdata"] for row in bus_writes])
        self.assertEqual([15, 2, 15], [row["data_be"] for row in bus_writes])
        writes = [row for row in cpu.service.events
                  if row["kind"] == "memory_write"
                  and row["transaction"]["channel_id"] == "data"]
        self.assertEqual([15, 2, 15], [row["byte_enable"] for row in writes])
        self.assertEqual([0x20000, 0x20000, 0x20004],
                         [row["address"] for row in writes])
        self.assertEqual([0x12345678, 0x00005700, 0x12345778],
                         [row["value"] for row in writes])
        reads = [row["value"] for row in cpu.service.events
                 if row["kind"] == "memory_read"
                 and row["transaction"]["channel_id"] == "data"]
        self.assertEqual([0x12345678, 0x12345778], reads)
        self.assertEqual(0x12345778, memory.read(
            0x20000, 4, transaction_id="cv32-final-word").value)
        self.assertEqual(0x12345778, memory.read(
            0x20004, 4, transaction_id="cv32-copied-word").value)
        self.assertEqual(3, len({row["transaction"]["source_sequence"] for row in writes}))

    def test_stateful_program_bundle_replays_on_fresh_cv32e40p(self) -> None:
        instances = []

        def factory() -> ScenarioRunner:
            memory = self.make_memory()
            cpu = self.make_cpu(memory)
            runner = ScenarioRunner(
                sessions={"cpu": cpu},
                ownership=compile_ownership((), ()),
                bindings=(),
            )
            instances.append((runner, cpu, memory))
            return runner

        case = ScenarioGenome(
            testcase_id="cv32e40p-obi-memory-replay",
            direction="CPU_TO_IP",
            path_id="cv32e40p-split-obi-memory",
            schedule_order=("cpu",),
            max_steps=100,
            actions=(),
            initial_images=(MemoryImage("program", "cpu", 0x10000, PROGRAM_HEX),),
        )
        bundle = Path(self.directory.name) / "evidence"
        trace = save_evidence_bundle(
            case,
            factory,
            bundle,
            budget=ResourceBudget(
                max_wall_time_ms=180000,
                max_materialized_bytes_per_memory=0x30000,
            ),
        )
        self.assertEqual("complete", trace.status, {
            "events": trace.events[-10:],
            "ticks": trace.local_ticks,
            "runner_status": instances[0][0]._status,
            "runner_failure": instances[0][0].failure_status,
        })
        self.assertEqual(0x12345778, instances[0][2].read(
            0x20004, 4, transaction_id="cv32-bundle-check").value)
        manifest = json.loads((bundle / "manifest.json").read_text())
        self.assertEqual("cv32e40p", manifest["sessions"]["cpu"]["identity"]
                         ["runtime_artifact"]["plan"]["component_id"])

        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay)
        self.assertEqual(0x12345778, instances[1][2].read(
            0x20004, 4, transaction_id="cv32-replay-check").value)
        self.assertNotEqual(instances[0][1]._execution, instances[1][1]._execution)


if __name__ == "__main__":
    unittest.main()
