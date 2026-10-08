"""Standalone real RVX execution, persistent memory and fresh-process replay."""
from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myfuzz.local_harness import GeneratedRvxMemorySession
from myfuzz.local_harness import render_local_driver, render_local_harness, render_local_runtime
from myfuzz.local_harness import verify_local_source_lock
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_renderer import ROOT, real_plan


def _lui(rd: int, upper: int) -> int:
    return (upper << 12) | (rd << 7) | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return ((immediate & 0xFFF) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def _lw(rd: int, rs1: int, offset: int) -> int:
    return ((offset & 0xFFF) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return (((offset >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | \
        (2 << 12) | ((offset & 0x1F) << 7) | 0x23


def _sb(rs2: int, rs1: int, offset: int) -> int:
    return (((offset >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | \
        ((offset & 0x1F) << 7) | 0x23


def _program() -> bytes:
    # x1=0x100; write a word, overwrite byte lane one, read it back,
    # copy the result, then publish a completion marker at 0x108.
    words = (
        _addi(1, 0, 0x100),
        _lui(2, 0x12345),
        _addi(2, 2, 0x678),
        _sw(2, 1, 0),
        _addi(3, 0, 0x55),
        _sb(3, 1, 1),
        _lw(4, 1, 0),
        _sw(4, 1, 4),
        _addi(5, 0, 1),
        _sw(5, 1, 8),
        0x0000006F,  # jal x0,0: stay inside the 128-step scenario.
    )
    return b"".join(word.to_bytes(4, "little") for word in words)


def _artifact():
    plan = real_plan("configs/cpus/rvx_core/component_profile.json", "rvx_cpu")
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT,
                                        allow_source_only=True)
    top = render_local_runtime(plan, render_local_harness(plan), verified,
                               base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "actual RVX RTL acceptance is opt-in")
class RvxPersistentMemoryRealTests(unittest.TestCase):
    def test_128_local_ticks_persist_and_replay_the_real_rvx_rtl(self):
        artifact = _artifact()
        instances = []
        with TemporaryDirectory() as cache:
            cache_dir = Path(cache)

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion("ram", 0, 4096),),
                    initialization_seed=0x525658,
                    max_initialized_bytes=4096,
                )
                cpu = GeneratedRvxMemorySession(
                    artifact, base_dir=ROOT, cache_dir=cache_dir, memory=memory,
                    response_latency_ticks=1,
                )
                runner = ScenarioRunner(
                    sessions={"cpu": cpu}, ownership=compile_ownership((), ()),
                    bindings=(),
                )
                instances.append((runner, cpu, memory))
                return runner

            genome = ScenarioGenome(
                testcase_id="rvx-byte-store-load-replay",
                direction="CPU_TO_IP",
                path_id="rvx-standalone-persistent-ram",
                schedule_order=("cpu",),
                max_steps=128,
                actions=(),
                initial_images=(
                    MemoryImage("rvx.program", "cpu", 0, _program().hex()),
                    MemoryImage("rvx.data", "cpu", 0x100, bytes(12).hex()),
                ),
            )
            bundle = cache_dir / "evidence"
            trace = save_evidence_bundle(
                genome, factory, bundle,
                budget=ResourceBudget(
                    max_wall_time_ms=90000,
                    max_scheduler_steps=128,
                    max_materialized_bytes_per_memory=4096,
                ),
            )

            self.assertEqual(trace.status, "complete", trace.status)
            self.assertEqual(trace.local_ticks, {"cpu": 128})
            first_runner, first_cpu, first_memory = instances[0]
            self.assertEqual(first_cpu.reset_epoch, 0)
            self.assertTrue(all(0 <= address < 4096
                                for address in first_cpu.accepted_addresses))
            self.assertIn(0, first_cpu.accepted_addresses)
            self.assertIn(0x100, first_cpu.accepted_addresses)
            self.assertEqual(first_memory.read(0x100, 4, transaction_id="check").value,
                             0x12345578)
            self.assertEqual(first_memory.read(0x104, 4, transaction_id="check").value,
                             0x12345578)
            self.assertEqual(first_memory.read(0x108, 4, transaction_id="check").value, 1)

            writes = [event for event in first_cpu.service.events
                      if event["kind"] == "memory_write"]
            self.assertEqual([(event["address"], event["value"], event["byte_enable"])
                              for event in writes], [
                                  (0x100, 0x12345678, 0xF),
                                  (0x100, 0x00005500, 0b0010),
                                  (0x104, 0x12345578, 0xF),
                                  (0x108, 1, 0xF),
                              ])
            self.assertEqual(writes[-1]["local_tick"] <= 128, True)
            reads = [event for event in first_cpu.service.events
                     if event["kind"] == "memory_read"]
            transactions = [event for event in first_cpu.service.events
                            if event["kind"] in ("memory_read", "memory_write")]
            transaction_keys = [tuple(sorted(event["transaction"].items()))
                                for event in transactions]
            self.assertEqual(len(transactions), len(first_cpu.accepted_addresses))
            self.assertEqual(len(set(transaction_keys)), len(transaction_keys))
            self.assertEqual(first_cpu.service.ledger.unresolved_keys, ())
            self.assertEqual(reads[0]["address"], 0)
            data_reads = [event for event in reads if event["address"] == 0x100]
            self.assertEqual([event["value"] for event in data_reads], [0x12345578])
            self.assertEqual(first_cpu.memory_write_count, 4)

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            second_runner, second_cpu, second_memory = instances[1]
            self.assertNotEqual(first_cpu._execution, second_cpu._execution)
            self.assertEqual(first_memory.state_summary(), second_memory.state_summary())
            self.assertEqual(first_cpu.service.events, second_cpu.service.events)
            self.assertEqual(second_runner.local_ticks, {"cpu": 128})


if __name__ == "__main__":
    unittest.main()
