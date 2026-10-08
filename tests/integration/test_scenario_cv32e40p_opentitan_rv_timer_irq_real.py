"""Real CV32E40P machine-timer interrupt through an OpenTitan RV Timer."""
from __future__ import annotations

import os
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
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_rv_timer_session import GeneratedOpentitanRvTimerSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
TIMER_BASE = 0x40000000
TIMER_COMPARE = 128
RESULT = 0x20000
VECTOR = 0x10100
ISR = 0x10200


def _artifact(profile: str, instance: str):
    request = load_local_harness_request({
        "schema_version": "local_harness.v1",
        "profile_path": profile,
        "instance_id": instance,
        "reset_assert_ticks": 8,
        "reset_release_ticks": 8,
        "max_wait_cycles": 16,
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(
        plan,
        render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT),
        base_dir=ROOT,
    )
    return render_local_driver(runtime, base_dir=ROOT)


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xFFF) << 20 | rs1 << 15 | rd << 7 | 0x13


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xFFF) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _csr(funct3: int, rd: int, csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | 0x73


def _jal(rd: int, offset: int) -> int:
    immediate = offset & 0x1FFFFF
    return (((immediate >> 20) & 1) << 31
            | ((immediate >> 1) & 0x3FF) << 21
            | ((immediate >> 11) & 1) << 20
            | ((immediate >> 12) & 0xFF) << 12
            | rd << 7 | 0x6F)


def _word_image(words: tuple[int, ...] | list[int]) -> bytes:
    return b"".join(word.to_bytes(4, "little") for word in words)


def _program() -> tuple[bytes, bytes, bytes]:
    main = (
        _lui(1, VECTOR >> 12),
        _addi(1, 1, VECTOR & 0xFFF),
        _csr(1, 0, 0x305, 1),             # direct mtvec = 0x10100
        _addi(1, 0, 1 << 7),
        _csr(1, 0, 0x304, 1),             # mie.MTIE = 1
        _addi(1, 0, 1 << 3),
        _csr(2, 0, 0x300, 1),             # mstatus.MIE = 1
        _lui(10, TIMER_BASE >> 12),
        _addi(11, 0, TIMER_COMPARE),
        _sw(11, 10, 0x118),               # compare lower
        _sw(0, 10, 0x11C),                # compare upper
        _addi(12, 0, 1),
        _sw(12, 10, 0x100),               # INTR_ENABLE0
        _sw(12, 10, 0x004),               # start CTRL
        0x0000006F,                       # wait for the real Timer IRQ
    )

    # Direct mode enters at VECTOR and explicitly jumps over the vector table.
    # If the core accidentally uses vectored mode, IRQ 7 lands at 0x1011c and
    # stops there instead of falling through to the real handler.
    vector_table = [_jal(0, 0)] * 8
    vector_table[0] = _jal(0, ISR - VECTOR)
    vector_table[7] = _jal(0, 0)

    isr = (
        _lui(10, TIMER_BASE >> 12),
        _lui(20, RESULT >> 12),
        _lw(11, 10, 0x104),               # real INTR_STATE0
        _lw(12, 10, 0x110),               # real TIMER_V_LOWER0
        _csr(2, 13, 0x342, 0),             # actual mcause, M_TIMER cause 7
        _sw(11, 20, 0),
        _sw(12, 20, 4),
        _sw(13, 20, 8),
        _sw(0, 10, 0x100),                 # disable further IRQ delivery
        _sw(0, 10, 0x004),                 # stop the counter
        _addi(14, 0, 1),
        _sw(14, 10, 0x104),                # W1C INTR_STATE0
        _lw(15, 10, 0x104),                # read back the real clear
        _sw(15, 20, 12),
        _addi(16, 0, 0x55),
        _sw(16, 20, 16),                   # completion marker
        0x30200073,                        # mret
    )
    return (
        _word_image(main),
        _word_image(vector_table),
        _word_image(isr),
    )


def _ownership():
    return compile_ownership(
        (InputField("cpu", "irq", 1),),
        (InputOwner("cpu", "irq", 0, 1, "bound", "timer.irq"),),
    )


def _genome() -> ScenarioGenome:
    main, vector, isr = _program()
    return ScenarioGenome(
        testcase_id="cv32e40p-opentitan-rv-timer-mtimer",
        direction="CPU_TO_IP_TO_CPU",
        path_id="cv32e40p-mtimer-tlul-obi-persistent-ram",
        schedule_order=("cpu", "timer"),
        max_steps=500,
        actions=(),
        initial_images=(
            MemoryImage("cpu.main", "cpu", 0x10000, main.hex()),
            MemoryImage("cpu.vector", "cpu", VECTOR, vector.hex()),
            MemoryImage("cpu.mtimer_isr", "cpu", ISR, isr.hex()),
            MemoryImage("cpu.results", "cpu", RESULT, bytes(20).hex()),
        ),
    )


def _make_factory(cpu_artifact, timer_artifact, cache_dir: Path):
    ownership = _ownership()
    binding = Binding("timer", "irq", "cpu", "irq", 1)
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x10000, 0x20000),),
            initialization_seed=19,
            max_initialized_bytes=0x20000,
        )
        timer = GeneratedOpentitanRvTimerSession(
            timer_artifact, base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow("timer", TIMER_BASE, 0x1000, timer),))
        cpu = GeneratedCve2Session(
            cpu_artifact,
            base_dir=ROOT,
            cache_dir=cache_dir,
            memory=memory,
            router=router,
            defer_mmio=True,
            command_timeout_seconds=60,
        )
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "timer": timer},
            ownership=ownership,
            bindings=(binding,),
        )
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(
    os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
    "set MYFUZZ_SCENARIO_REAL=1 for pinned CV32E40P and OpenTitan RTL",
)
class GeneratedCv32e40pOpentitanRvTimerMtiTests(unittest.TestCase):
    def test_real_machine_timer_irq_is_serviced_and_replays_on_fresh_harnesses(self):
        # Keep the bounded evidence bundle outside the repository for review.
        work = Path(tempfile.mkdtemp(
            prefix="myfuzz-cv32e40p-opentitan-rv-timer-mti-"))
        cpu_artifact = _artifact(
            "configs/cpus/cv32e40p_mtimer/component_profile.json", "cpu")
        timer_artifact = _artifact(
            "configs/peripherals/opentitan_rv_timer_local/component_profile.json",
            "timer",
        )
        factory, instances = _make_factory(cpu_artifact, timer_artifact, work / "cache")
        genome = _genome()
        bundle = work / "evidence"
        budget = ResourceBudget(
            max_local_cycles_per_component=2048,
            max_scheduler_steps=1024,
            max_materialized_bytes_per_memory=0x20000,
            max_transactions=512,
            max_semantic_records=20_000,
            max_evidence_bytes=32 * 1024 * 1024,
            evidence_termination_reserve_bytes=2 * 1024 * 1024,
            max_wall_time_ms=300_000,
        )
        trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
        self.assertEqual("complete", trace.status, trace.events[-12:])

        first = instances[0]
        cpu, timer = first.sessions["cpu"], first.sessions["timer"]
        events = trace.events
        deliveries = [event for event in events
                      if event.get("kind") == "mmio_delivery"
                      and event.get("device_id") == "timer"]
        writes = [event for event in deliveries if event.get("write")]
        reads = [event for event in deliveries if not event.get("write")]
        self.assertEqual(
            [(0x118, TIMER_COMPARE), (0x11C, 0), (0x100, 1),
             (0x004, 1), (0x100, 0), (0x004, 0), (0x104, 1)],
            [(event["offset"], event["write_value"]) for event in writes],
            "CV32E40P must configure, stop, disable, and W1C the real Timer",
        )
        self.assertEqual([0x104, 0x110, 0x104],
                         [event["offset"] for event in reads])
        self.assertEqual(1, reads[0]["read_value"] & 1,
                         "ISR must read the real asserted INTR_STATE0")
        self.assertGreaterEqual(reads[1]["read_value"], TIMER_COMPARE,
                                "ISR must read the real Timer count")
        self.assertEqual(0, reads[2]["read_value"] & 1,
                         "Timer W1C must clear the real INTR_STATE0")

        irq_deliveries = [event for event in events
            if event.get("kind") == "dataflow_delivery"
            and tuple(event.get("source", ())) == ("timer", "irq")
            and tuple(event.get("target", ())) == ("cpu", "irq")
            and event.get("value") == 1]
        self.assertTrue(irq_deliveries, "real Timer IRQ never reached the CPU binding")
        irq_delivery = irq_deliveries[0]
        irq_source = next(event for event in events
            if event.get("event_id") == irq_delivery["producer_event_id"])
        self.assertEqual("local_tick_sample", irq_source.get("kind"))
        self.assertEqual("timer", irq_source.get("component"))
        self.assertEqual(1, irq_source.get("outputs", {}).get(
            "irq", irq_source.get("outputs", {}).get("interrupt")))

        cpu_steps = [event for event in events
                     if event.get("component") == "cpu"
                     and isinstance(event.get("outputs"), dict)]
        irq_ack = next((event for event in cpu_steps
            if event.get("inputs", {}).get("irq") == 1
            and event["outputs"].get("irq_ack_o") == 1
            and event["outputs"].get("irq_id_o") == 7), None)
        self.assertIsNotNone(irq_ack,
            "CV32E40P must sample MTI and acknowledge physical irq_i[7]")
        post_ack_fetch = next((event for event in cpu_steps
            if event.get("event_id", 0) > irq_ack["event_id"]
            and event.get("outputs", {}).get("instr_req_accepted") == 1), None)
        self.assertIsNotNone(post_ack_fetch,
                             "CPU did not fetch after accepting the MTI")
        self.assertEqual(VECTOR, post_ack_fetch["outputs"].get("instr_addr"),
            "direct-mode entry must fetch 0x10100; 0x1011c is a self-loop")
        self.assertLess(irq_source["event_id"], irq_delivery["event_id"])
        self.assertLess(irq_delivery["event_id"], irq_ack["event_id"])
        self.assertLess(irq_ack["event_id"], post_ack_fetch["event_id"])
        self.assertLess(post_ack_fetch["event_id"], reads[0]["event_id"])

        result_word = lambda offset: cpu.memory.read(
            RESULT + offset, 4, transaction_id=f"cv32-mti-result-{offset:x}").value
        self.assertEqual(1, result_word(0))
        self.assertGreaterEqual(result_word(4), TIMER_COMPARE)
        self.assertEqual(0x80000007, result_word(8),
                         "actual mcause must identify machine-timer interrupt 7")
        self.assertEqual(0, result_word(12), "ISR must store the W1C readback")
        self.assertEqual(0x55, result_word(16), "ISR completion marker is missing")
        self.assertGreaterEqual(cpu.mmio_read_count, 3)
        self.assertGreaterEqual(cpu.mmio_write_count, 7)

        mmio_transactions = [event for event in events
            if event.get("kind") == "mmio_delivery"]
        keys = [tuple(event["source_transaction"][field] for field in
            ("source_component", "source_epoch", "channel_id", "source_sequence"))
            for event in mmio_transactions]
        self.assertEqual(len(keys), len(set(keys)), "MMIO transaction identity was repeated")
        self.assertEqual({"cpu"}, {key[0] for key in keys})
        self.assertEqual({0}, {key[1] for key in keys})
        self.assertEqual({0}, {session.reset_epoch for session in first.sessions.values()})
        self.assertFalse(any(event.get("kind") in ("reset_barrier", "reset_failure")
                             for event in events))

        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)
        self.assertIsNot(instances[0].sessions["cpu"], instances[1].sessions["cpu"])
        self.assertIsNot(instances[0].sessions["timer"], instances[1].sessions["timer"])
        replay_cpu = instances[1].sessions["cpu"]
        self.assertEqual(0x80000007, replay_cpu.memory.read(
            RESULT + 8, 4, transaction_id="cv32-mti-replay-mcause").value)


if __name__ == "__main__":
    unittest.main()
