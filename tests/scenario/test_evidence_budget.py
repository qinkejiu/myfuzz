"""Opt-in evidence resource budgets reject before writes where possible."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.checker import check_gpio_direct_out
from myfuzz.scenario.evidence import (_checker_config_bytes,
                                      _event_file_copy_counts,
                                      _evidence_base_bytes, _factory_identity,
                                      _final_state_growth_bound,
                                      replay_evidence_bundle, save_evidence_bundle)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import (Action, MemoryImage, ResetAction,
                                    ScenarioGenome, Trigger)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.protocol_io import BoundedLineReader, read_startup_ready
from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded
from myfuzz.scenario.replay import _canonical, record_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.runner import ScenarioBudgetExhausted, ScenarioRunner


class _Session:
    max_final_state_growth_bytes_per_operation = 65536
    max_evidence_record_bytes = 8192

    def __init__(self, memory=False):
        self.begins = 0
        self.steps = 0
        if memory:
            self.memory = PersistentMemory(
                regions=(MemoryRegion("ram", 0, 64),),
                initialization_seed=1, max_initialized_bytes=64)

    def identity_document(self):
        return {"fixture": "budget"}

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        self.steps += 1
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


class EvidenceBudgetTests(unittest.TestCase):
    def test_independent_command_deadline_is_not_wall_budget_exhaustion(self):
        for budget in (None, ResourceBudget(max_wall_time_ms=1000)):
            with self.subTest(budgeted=budget is not None):
                runner = self.factory()
                session = runner.sessions["gpio"]

                def timeout(_inputs):
                    raise LocalCommandDeadlineExceeded("independent command deadline")

                session.step_local = timeout
                if budget is not None:
                    runner.set_resource_budget(budget)
                with patch("myfuzz.scenario.runner.time.monotonic",
                           return_value=100.0):
                    runner.begin_test("independent-timeout")
                with patch("myfuzz.scenario.runner.time.monotonic",
                           return_value=100.1):
                    with self.assertRaises(LocalCommandDeadlineExceeded):
                        runner.step("gpio")
                self.assertEqual("uncertain_effect", runner.failure_status)
                self.assertFalse(any(event.get("kind") == "budget_exhausted"
                                     for event in runner.events))
                self.assertEqual("uncertain_effect",
                                 runner.events[-1]["status"])
                runner.finalize()

    def test_missing_record_bound_rejects_before_begin(self):
        def unbounded_factory():
            runner = self.factory()
            runner.sessions["gpio"].max_evidence_record_bytes = None
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unbounded-record"
            with self.assertRaisesRegex(ValueError, "evidence record bound"):
                save_evidence_bundle(self.genome, unbounded_factory, output,
                                     budget=ResourceBudget())
            self.assertEqual(0, self.sessions[-1].begins)

    def test_record_bound_larger_than_tail_rejects_before_begin(self):
        def huge_record_factory():
            runner = self.factory()
            runner.sessions["gpio"].max_evidence_record_bytes = 2 * 1024 * 1024
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "huge-record"
            with self.assertRaisesRegex(ValueError, "termination reserve"):
                save_evidence_bundle(
                    self.genome, huge_record_factory, output,
                    budget=ResourceBudget(
                        max_evidence_bytes=3 * 1024 * 1024,
                        evidence_termination_reserve_bytes=1024 * 1024))
            self.assertEqual(0, self.sessions[-1].begins)

    def test_false_evidence_record_declaration_is_harness_failure(self):
        def false_record_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            session.max_evidence_record_bytes = 100

            def step(_inputs):
                session.steps += 1
                return {"x" * 20000: 1}

            session.step_local = step
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "false-record"
            trace = save_evidence_bundle(
                self.genome, false_record_factory, output,
                budget=ResourceBudget())
            self.assertEqual("environment_error", trace.status)
            self.assertEqual("ScenarioEvidenceRecordViolation",
                             trace.events[-1]["error_type"])
            self.assertTrue(replay_evidence_bundle(
                output, false_record_factory).matches)

    def test_builtin_growth_bound_includes_component_name(self):
        from myfuzz.scenario.gpio_session import OpenTitanGpioSession

        name = "gpio-" + "x" * 10000
        runner = SimpleNamespace(sessions={name: OpenTitanGpioSession()})
        self.assertGreaterEqual(
            _final_state_growth_bound(self.genome, runner, ResourceBudget()),
            4 * len(name))

    def test_unknown_session_without_state_growth_bound_rejects_before_begin(self):
        def unbounded_factory():
            runner = self.factory()
            runner.sessions["gpio"].max_final_state_growth_bytes_per_operation = None
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unbounded"
            with self.assertRaisesRegex(ValueError, "final state growth bound"):
                save_evidence_bundle(self.genome, unbounded_factory, output,
                                     budget=ResourceBudget())
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(output.exists())

    def test_one_operation_growth_larger_than_tail_rejects_before_begin(self):
        def burst_factory():
            runner = self.factory()
            runner.sessions["gpio"].max_final_state_growth_bytes_per_operation = 2 * 1024 * 1024
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "burst"
            with self.assertRaisesRegex(ValueError, "termination reserve"):
                save_evidence_bundle(
                    self.genome, burst_factory, output,
                    budget=ResourceBudget(
                        max_evidence_bytes=3 * 1024 * 1024,
                        evidence_termination_reserve_bytes=1024 * 1024))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(output.exists())

    def test_false_state_growth_declaration_is_harness_failure(self):
        def false_bound_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            session.max_final_state_growth_bytes_per_operation = 128
            uncertain = []
            session.service = SimpleNamespace(
                ledger=SimpleNamespace(uncertain_keys=uncertain))
            original_step = session.step_local

            def step(inputs):
                uncertain.append("x" * 4096)
                return original_step(inputs)

            session.step_local = step
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "false-bound"
            trace = save_evidence_bundle(
                self.genome, false_bound_factory, output,
                budget=ResourceBudget())
            self.assertEqual("environment_error", trace.status)
            self.assertEqual("harness_failure", trace.events[-1]["kind"])
            self.assertEqual("ScenarioFinalStateGrowthViolation",
                             trace.events[-1]["error_type"])
            self.assertTrue(replay_evidence_bundle(
                output, false_bound_factory).matches)

    def test_replay_rejects_changed_state_growth_contract_before_begin(self):
        declared = [65536]

        def mutable_factory():
            runner = self.factory()
            runner.sessions["gpio"].max_final_state_growth_bytes_per_operation = declared[0]
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bound-identity"
            save_evidence_bundle(self.genome, mutable_factory, output,
                                 budget=ResourceBudget())
            declared[0] = 32768
            with self.assertRaisesRegex(ValueError, "final state growth bound mismatch"):
                replay_evidence_bundle(output, mutable_factory)
            self.assertEqual(0, self.sessions[-1].begins)

    def test_begin_state_growth_exhausts_before_first_step(self):
        genome = replace(self.genome, actions=())

        def begin_growth_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            uncertain = []
            session.service = SimpleNamespace(
                ledger=SimpleNamespace(uncertain_keys=uncertain))
            original_begin = session.begin_case

            def begin(case_id):
                original_begin(case_id)
                uncertain.append("b" * 30000)

            session.begin_case = begin
            return runner

        sample = begin_growth_factory()
        base = _evidence_base_bytes(
            genome, sample.identity_document(),
            _factory_identity(begin_growth_factory))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "begin-growth"
            trace = save_evidence_bundle(
                genome, begin_growth_factory, output,
                budget=ResourceBudget(
                    max_evidence_bytes=1024 * 1024 + base + 10000,
                    evidence_termination_reserve_bytes=1024 * 1024))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(0, self.sessions[-1].steps)
            self.assertEqual("max_evidence_bytes", trace.events[-1]["limit"])
            self.assertTrue(replay_evidence_bundle(
                output, begin_growth_factory).matches)

    def test_finalization_state_growth_marks_budgeted_trace(self):
        def end_growth_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            uncertain = []
            session.service = SimpleNamespace(
                ledger=SimpleNamespace(uncertain_keys=uncertain))

            def end():
                uncertain.append("e" * 30000)

            session.end_case = end
            return runner

        sample = end_growth_factory()
        base = _evidence_base_bytes(
            self.genome, sample.identity_document(),
            _factory_identity(end_growth_factory))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "end-growth"
            trace = save_evidence_bundle(
                self.genome, end_growth_factory, output,
                budget=ResourceBudget(
                    max_evidence_bytes=1024 * 1024 + base + 10000,
                    evidence_termination_reserve_bytes=1024 * 1024))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_evidence_bytes", trace.events[-1]["limit"])
            self.assertEqual(trace.status, json.loads(
                (output / "result.json").read_text())["status"])
            self.assertEqual(trace.semantic_sha256, json.loads(
                (output / "trace.json").read_text())["semantic_sha256"])
            self.assertTrue(replay_evidence_bundle(
                output, end_growth_factory).matches)

    def test_final_state_meter_does_not_rehash_memory_for_each_event(self):
        runner = self.factory(memory=True)
        memory = runner.sessions["gpio"].memory
        memory.preload(0, bytes(range(64)))
        expected_size = len(_canonical(runner.final_state_document())) + 1
        runner.set_resource_budget(ResourceBudget())
        with patch.object(memory, "state_summary",
                          side_effect=AssertionError("rehashed memory")):
            runner.arm_evidence_meter(0, {})
            self.assertEqual(expected_size, runner._evidence_final_state_bytes)
            runner.begin_test("meter-memory")
            runner.step("gpio")
            runner.finalize()
        self.assertEqual(len(_canonical(runner.final_state_document())) + 1,
                         runner._evidence_final_state_bytes)

    def test_growing_final_state_exhausts_evidence_before_remaining_steps(self):
        genome = replace(self.genome, max_steps=8, actions=())

        def growing_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            uncertain = []
            session.service = SimpleNamespace(
                ledger=SimpleNamespace(uncertain_keys=uncertain))
            original_step = session.step_local

            def step(inputs):
                uncertain.extend(f"{session.steps}-{index}-" + "x" * 80
                                 for index in range(300))
                return original_step(inputs)

            session.step_local = step
            return runner

        sample = growing_factory()
        base = _evidence_base_bytes(
            genome, sample.identity_document(), _factory_identity(growing_factory))
        reserve = 1024 * 1024
        budget = ResourceBudget(
            max_evidence_bytes=reserve + base + 55000,
            evidence_termination_reserve_bytes=reserve)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "growing-final-state"
            trace = save_evidence_bundle(genome, growing_factory, output,
                                         budget=budget)
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_evidence_bytes", trace.events[-1]["limit"])
            self.assertLess(self.sessions[-1].steps, genome.max_steps)
            self.assertTrue(replay_evidence_bundle(
                output, growing_factory).matches)

    def test_deferred_mmio_target_ticks_are_reserved_before_target_step(self):
        class Target(_Session):
            max_local_ticks_per_step = 1
            max_local_ticks_per_register_access = 5

            def __init__(self):
                super().__init__()
                self.local_ticks = 3
                self.writes = []

            def step_local(self, inputs):
                self.steps += 1
                self.local_ticks += 1
                return {"out": 0}

            def write_register(self, offset, value, *, be=15):
                self.writes.append((offset, value, be))
                self.local_ticks += 5

            def read_register(self, offset):
                self.local_ticks += 5
                return 0

        class Cpu(_Session):
            max_local_ticks_per_step = 1
            max_mmio_target_accesses_per_step = 0
            max_transaction_events_per_step = 0

            def __init__(self, target):
                super().__init__()
                self.local_ticks = 0
                self.router = DataflowRouter((DeviceWindow(
                    "gpio", 0x40000000, 0x1000, target),))
                self.ledger = TransactionLedger()

            def step_local(self, inputs):
                self.local_ticks += 1
                self.router.enqueue(
                    self.ledger, TransactionKey("exec", "case", "cpu", 0,
                                                "data", 1),
                    address=0x40000014, write=True, wdata=7,
                    be=15, beat_bytes=4, callback=lambda _receipt: None)
                return {"out": 0}

        target = Target()
        cpu = Cpu(target)
        ownership = compile_ownership((), ())
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": target},
                                ownership=ownership, bindings=())
        runner.set_resource_budget(ResourceBudget(
            max_local_cycles_per_component=8))
        runner.begin_test("deferred-target-tick-budget")
        try:
            runner.step("cpu")
            with self.assertRaises(ScenarioBudgetExhausted):
                runner.step("gpio")
            self.assertEqual("before_step", runner.events[-1]["phase"])
            self.assertEqual(0, target.steps)
            self.assertEqual([], target.writes)
            self.assertEqual(("gpio",), cpu.router.pending_targets)
        finally:
            runner.finalize()

    def test_gpio_checker_findings_consume_execution_evidence_capacity(self):
        genome = replace(self.genome, max_steps=12, actions=())

        def mismatch_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            session.router = SimpleNamespace(windows=(), deliveries=[])
            session.max_transaction_events_per_step = 1

            def step(_inputs):
                session.steps += 1
                session.router.deliveries.append({
                    "device_id": "gpio", "offset": 0x14, "write": True,
                    "byte_enable": 15, "write_value": 1})
                return {"gpio_out": 0}

            session.step_local = step
            return runner

        baseline = record_scenario(genome, mismatch_factory)
        findings = check_gpio_direct_out(baseline.events, ("gpio",))
        self.assertGreater(len(findings), 5)
        sample = mismatch_factory()
        base = (_evidence_base_bytes(
            genome, sample.identity_document(), _factory_identity(mismatch_factory))
            + _checker_config_bytes(({"checker": "gpio_direct_out.v1",
                                      "devices": ("gpio",)},)))
        copies = _event_file_copy_counts()
        event_bytes = sum((len(_canonical(event)) + 1) *
                          (1 + copies.get(event.get("kind", ""), 0)
                           + int("outputs" in event))
                          for event in baseline.events)
        finding_bytes = sum(len(_canonical(finding.__dict__)) + 1
                            for finding in findings)
        reserve = 1024 * 1024
        budget = ResourceBudget(
            max_evidence_bytes=reserve + base + event_bytes + finding_bytes // 4,
            evidence_termination_reserve_bytes=reserve)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "checker-cap"
            trace = save_evidence_bundle(
                genome, mismatch_factory, bundle,
                gpio_check_devices=("gpio",), budget=budget)
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_evidence_bytes", trace.events[-1]["limit"])
            self.assertLess(self.sessions[-1].steps, genome.max_steps)
            self.assertTrue(replay_evidence_bundle(
                bundle, mismatch_factory).matches)

    def test_chain_checker_future_findings_are_reserved_before_rtl_start(self):
        sample = self.factory()
        checks = ({"checker": "cpu_gpio_closed_chain.v1",
                   "expected_value": 1, "min_rounds": 100},)
        base = (_evidence_base_bytes(
            self.genome, sample.identity_document(), _factory_identity(self.factory))
            + _checker_config_bytes(checks))
        reserve = 1024 * 1024
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "chain-checker-cap"
            with self.assertRaisesRegex(ValueError, "max_evidence_bytes"):
                save_evidence_bundle(
                    self.genome, self.factory, bundle,
                    closed_chain_expected_value=1,
                    closed_chain_min_rounds=100,
                    budget=ResourceBudget(
                        max_evidence_bytes=reserve + base + 1000,
                        evidence_termination_reserve_bytes=reserve,
                        max_semantic_records=1200))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(bundle.exists())

    def test_tiny_termination_reserve_rejects_before_rtl_start(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "no-tail"
            with self.assertRaisesRegex(ValueError, "termination reserve"):
                save_evidence_bundle(
                    self.genome, self.factory, bundle,
                    budget=ResourceBudget(
                        max_evidence_bytes=1024 * 1024,
                        evidence_termination_reserve_bytes=1))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(bundle.exists())

    def test_termination_index_counts_all_declared_image_files(self):
        genome = replace(
            self.genome, max_steps=1, actions=(),
            initial_images=tuple(MemoryImage(
                f"byte-{index}", "gpio", index, f"{index:02x}")
                for index in range(64)))

        def memory_factory():
            return self.factory(memory=True)

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "many-images"
            with self.assertRaisesRegex(ValueError, "termination reserve"):
                save_evidence_bundle(
                    genome, memory_factory, bundle,
                    budget=ResourceBudget(
                        max_materialized_bytes_per_memory=64,
                        max_evidence_bytes=1024 * 1024,
                        evidence_termination_reserve_bytes=10000))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(bundle.exists())

    def test_local_harness_exceeding_declared_tick_bound_is_uncertain(self):
        class Misdeclared(_Session):
            max_local_ticks_per_step = 1

            def __init__(self):
                super().__init__()
                self.local_ticks = 0

            def step_local(self, inputs):
                self.local_ticks += 2
                return super().step_local(inputs)

        session = Misdeclared()
        runner = ScenarioRunner(sessions={"gpio": session},
                                ownership=self.ownership, bindings=())
        runner.set_resource_budget(ResourceBudget(max_local_cycles_per_component=10))
        runner.begin_test("misdeclared-tick-bound")
        try:
            with self.assertRaisesRegex(RuntimeError, "tick bound"):
                runner.step("gpio")
            self.assertEqual("uncertain_effect", runner.failure_status)
            self.assertEqual(2, runner.local_ticks["gpio"])
            self.assertEqual("post_step_processing", runner.events[-1]["phase"])
        finally:
            runner.finalize()

    def test_cpu_step_reserves_real_target_local_ticks_before_mmio(self):
        class Target:
            max_local_ticks_per_step = 1
            max_local_ticks_per_register_access = 5

            def __init__(self):
                self.local_ticks = 0
                self.writes = 0

            def begin_case(self, _case):
                pass

            def step_local(self, _inputs):
                self.local_ticks += 1
                return {"out": self.writes}

            def write_register(self, _offset, _value, *, be=15):
                self.local_ticks += 5
                self.writes += 1

            def read_register(self, _offset):
                self.local_ticks += 5
                return self.writes

            def end_case(self):
                pass

        class Cpu:
            max_local_ticks_per_step = 1
            max_mmio_target_accesses_per_step = 1
            max_transaction_events_per_step = 1

            def __init__(self, target):
                self.local_ticks = 0
                self.router = DataflowRouter((DeviceWindow(
                    "ip", 0x40000000, 0x1000, target),))
                self.ledger = TransactionLedger()
                self.sequence = 0

            def begin_case(self, _case):
                pass

            def step_local(self, _inputs):
                self.sequence += 1
                self.router.transact(
                    self.ledger,
                    TransactionKey("execution", "case", "cpu", 0, "data",
                                   self.sequence),
                    address=0x40000014, write=True, wdata=self.sequence,
                    be=15, beat_bytes=4)
                self.local_ticks += 1
                return {"out": self.sequence}

            def end_case(self):
                pass

        for cap, expected_writes in ((4, 0), (5, 1)):
            with self.subTest(cap=cap):
                target = Target()
                cpu = Cpu(target)
                runner = ScenarioRunner(
                    sessions={"cpu": cpu, "ip": target},
                    ownership=compile_ownership((), ()), bindings=())
                runner.set_resource_budget(ResourceBudget(
                    max_local_cycles_per_component=cap))
                runner.begin_test("target-local-cycle-cap")
                try:
                    if cap == 5:
                        runner.step("cpu")
                    with self.assertRaises(ScenarioBudgetExhausted):
                        runner.step("cpu")
                    self.assertEqual(expected_writes, target.writes)
                    self.assertEqual(5 * expected_writes, target.local_ticks)
                    self.assertEqual("max_local_cycles_per_component",
                                     runner.events[-1]["limit"])
                    self.assertEqual("before_step", runner.events[-1]["phase"])
                finally:
                    runner.finalize()

    def test_atomic_publish_rejects_racing_empty_destination(self):
        from myfuzz.scenario.evidence import _publish_new_evidence_directory

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "bundle"
            staged = [root / "first", root / "second"]
            for index, path in enumerate(staged):
                path.mkdir()
                (path / "marker").write_text(str(index))
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(
                    lambda path: self._publish_outcome(
                        _publish_new_evidence_directory, path, destination),
                    staged))
            self.assertEqual(["published", "already_exists"], sorted(outcomes,
                             key=lambda item: item != "published"))
            self.assertEqual(1, len(list(destination.iterdir())))
            self.assertIn((destination / "marker").read_text(), ("0", "1"))
            self.assertEqual(1, sum(path.exists() for path in staged))

    @staticmethod
    def _publish_outcome(publish, staged, destination):
        try:
            publish(staged, destination)
        except ValueError as exc:
            if "evidence directory must be new" not in str(exc):
                raise
            return "already_exists"
        return "published"

    def setUp(self):
        self.sessions = []
        self.ownership = compile_ownership(
            (InputField("gpio", "pin", 1),),
            (InputOwner("gpio", "pin", 0, 1, "source", "external"),))
        self.genome = ScenarioGenome(
            testcase_id="budget", direction="IP_TO_IP", path_id="pin",
            schedule_order=("gpio",), max_steps=3,
            actions=(Action("a", "gpio", "pin", 1, "IP_TO_IP",
                            Trigger("START"), width=1),))

    def factory(self, memory=False):
        session = _Session(memory)
        self.sessions.append(session)
        return ScenarioRunner(sessions={"gpio": session},
                              ownership=self.ownership, bindings=())

    def test_source_actions_and_steps_reject_before_begin_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            with self.assertRaisesRegex(ValueError, "max_source_actions"):
                save_evidence_bundle(self.genome, self.factory, output,
                                     budget=ResourceBudget(max_source_actions=0))
            self.assertEqual([], self.sessions)
            self.assertFalse(output.exists())
            with self.assertRaisesRegex(ValueError, "max_scheduler_steps"):
                save_evidence_bundle(self.genome, self.factory, output,
                                     budget=ResourceBudget(max_scheduler_steps=2))
            self.assertEqual([], self.sessions)
            self.assertFalse(output.exists())

    def test_materialized_byte_preflight_rejects_before_begin(self):
        genome = replace(self.genome, initial_images=(
            MemoryImage("image", "gpio", 0, "010203"),))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            with self.assertRaisesRegex(ValueError, "max_materialized_bytes_per_memory"):
                save_evidence_bundle(genome, lambda: self.factory(memory=True), output,
                                     budget=ResourceBudget(max_materialized_bytes_per_memory=2))
            self.assertEqual(0, self.sessions[0].begins)
            self.assertFalse(output.exists())

    def test_initial_image_event_bytes_reject_before_begin(self):
        genome = replace(self.genome, initial_images=(
            MemoryImage("image", "gpio", 0, "010203"),))

        def memory_factory():
            return self.factory(memory=True)

        sample = memory_factory()
        base = _evidence_base_bytes(
            genome, sample.identity_document(),
            _factory_identity(memory_factory))
        reserve = 1024 * 1024
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            with self.assertRaisesRegex(ValueError, "max_evidence_bytes"):
                save_evidence_bundle(
                    genome, memory_factory, output,
                    budget=ResourceBudget(
                        max_evidence_bytes=reserve + base + 1,
                        evidence_termination_reserve_bytes=reserve))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertEqual(0, self.sessions[-1].memory.state_summary()[
                "initialized_bytes"])
            self.assertFalse(output.exists())

    def test_oversized_coverage_metadata_rejects_before_rtl_begin(self):
        sample = self.factory()
        base = _evidence_base_bytes(
            self.genome, sample.identity_document(),
            _factory_identity(self.factory))
        target = CoverageTarget("long-" + "x" * 4096, "gpio", "out", 1, 1)
        reserve = 1024 * 1024
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "coverage-overflow"
            with self.assertRaisesRegex(ValueError, "max_evidence_bytes"):
                save_evidence_bundle(
                    self.genome, self.factory, bundle,
                    coverage_targets=(target,),
                    budget=ResourceBudget(
                        max_evidence_bytes=reserve + base + 1000,
                        evidence_termination_reserve_bytes=reserve))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(bundle.exists())

    def test_oversized_checker_configuration_rejects_before_rtl_begin(self):
        sample = self.factory()
        base = _evidence_base_bytes(
            self.genome, sample.identity_document(),
            _factory_identity(self.factory))
        reserve = 1024 * 1024
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "checker-overflow"
            with self.assertRaisesRegex(ValueError, "max_evidence_bytes"):
                save_evidence_bundle(
                    self.genome, self.factory, bundle,
                    gpio_check_devices=("gpio-" + "x" * 4096,),
                    budget=ResourceBudget(
                        max_evidence_bytes=reserve + base + 1000,
                        evidence_termination_reserve_bytes=reserve))
            self.assertEqual(0, self.sessions[-1].begins)
            self.assertFalse(bundle.exists())

    def test_semantic_limit_stops_before_next_step_and_saves_termination(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(self.genome, self.factory, output,
                                         budget=ResourceBudget(max_semantic_records=3))
            self.assertEqual(1, self.sessions[0].begins)
            self.assertEqual(1, self.sessions[0].steps)
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertEqual(3, len(trace.events))
            self.assertEqual("budget_exhausted", trace.events[-1]["kind"])
            self.assertTrue((output / "bundle_index.json").is_file())
            self.assertTrue(replay_evidence_bundle(output, self.factory).matches)

    def test_local_cycle_limit_stops_before_unaffordable_step(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                self.genome, self.factory, output,
                budget=ResourceBudget(max_local_cycles_per_component=1))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(1, self.sessions[0].steps)
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertEqual("max_local_cycles_per_component",
                             trace.events[-1]["limit"])
            self.assertTrue(replay_evidence_bundle(output, self.factory).matches)

    def test_direct_quiesce_request_above_budget_rejects_before_local_step(self):
        runner = self.factory()
        runner.set_resource_budget(ResourceBudget(max_quiesce_steps=2))
        try:
            runner.begin_test("quiesce-request-budget")
            with self.assertRaisesRegex(ValueError, "max_quiesce_steps"):
                runner.quiesce(3)
            self.assertEqual(0, self.sessions[-1].steps)
            self.assertFalse(any(event.get("kind") == "quiesce_start"
                                 for event in runner.events))
        finally:
            runner.finalize()

    def test_transaction_limit_stops_before_another_target_commit(self):
        def transaction_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            session.router = SimpleNamespace(windows=(), deliveries=[])
            session.max_transaction_events_per_step = 1

            def step(inputs):
                session.steps += 1
                session.router.deliveries.append({
                    "device_id": "fixture", "source_sequence": session.steps})
                return {"out": inputs.get("pin", 0)}

            session.step_local = step
            return runner

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                self.genome, transaction_factory, bundle,
                budget=ResourceBudget(max_transactions=1))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual("max_transactions", trace.events[-1]["limit"])
            self.assertEqual("before_step", trace.events[-1]["phase"])
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertEqual(1, sum(event.get("kind") == "mmio_delivery"
                                    for event in trace.events))
            self.assertTrue(replay_evidence_bundle(bundle, transaction_factory).matches)

    def test_declared_transaction_step_bound_is_checked_against_observed_commits(self):
        runner = self.factory()
        session = runner.sessions["gpio"]
        session.router = SimpleNamespace(windows=(), deliveries=[])
        session.max_transaction_events_per_step = 1

        def step(_inputs):
            session.router.deliveries.extend((
                {"device_id": "fixture", "source_sequence": 1},
                {"device_id": "fixture", "source_sequence": 2}))
            return {"out": 0}

        session.step_local = step
        runner.set_resource_budget(ResourceBudget(max_transactions=3))
        try:
            runner.begin_test("bad-transaction-bound")
            with self.assertRaisesRegex(RuntimeError, "transaction event bound"):
                runner.step("gpio")
            self.assertEqual("uncertain_effect", runner.failure_status)
            self.assertEqual(2, sum(event.get("kind") == "mmio_delivery"
                                    for event in runner.events))
        finally:
            runner.finalize()

    def test_wall_budget_stops_before_a_new_local_step(self):
        runner = self.factory()
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=1))
        with patch("myfuzz.scenario.runner.time.monotonic",
                   side_effect=(10.0, 10.0, 10.002)):
            runner.begin_test("wall-budget")
            with self.assertRaisesRegex(ValueError, "max_wall_time_ms"):
                runner.step("gpio")
        self.assertEqual(0, self.sessions[0].steps)
        self.assertEqual("budget_exhausted", runner.failure_status)
        self.assertEqual("max_wall_time_ms", runner.events[-1]["limit"])
        runner.finalize()

    def test_wall_timeout_saves_and_replays_real_prefix_without_timing(self):
        def slow_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            original = session.step_local

            def slow_step(inputs):
                time.sleep(0.03)
                return original(inputs)

            session.step_local = slow_step
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                self.genome, slow_factory, output,
                budget=ResourceBudget(max_wall_time_ms=20))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertEqual("max_wall_time_ms", trace.events[-1]["limit"])
            self.assertTrue(replay_evidence_bundle(
                output, self.factory, allow_factory_mismatch=True).matches)

    def test_inflight_reply_timeout_preserves_uncertain_prefix(self):
        def blocked_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            read_fd, write_fd = os.pipe()
            stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
            reader = BoundedLineReader()

            def blocked_step(_inputs):
                session.steps += 1
                reader.readline(stream)
                return {"out": 0}

            def close():
                os.close(write_fd)
                stream.close()

            session.step_local = blocked_step
            session.end_case = close
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                self.genome, blocked_factory, output,
                budget=ResourceBudget(max_wall_time_ms=20))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(0, trace.local_ticks["gpio"])
            self.assertTrue(trace.events[-1].get("effect_may_have_occurred"),
                            trace.events[-3:])
            self.assertEqual("inflight_step", trace.events[-1]["phase"])
            comparison = replay_evidence_bundle(
                output, self.factory, allow_factory_mismatch=True)
            self.assertTrue(comparison.matches)
            self.assertEqual("semantic_prefix", comparison.verification_scope)

    def test_inflight_reset_ready_timeout_preserves_uncertain_prefix(self):
        genome = replace(self.genome, encoding_version=3, reset_actions=(
            ResetAction("restart", "warm_all", Trigger("START")),))

        def blocked_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            read_fd, write_fd = os.pipe()
            stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)
            reader = BoundedLineReader()

            def blocked_reset():
                reader.readline(stream)
                return {"cancelled_responses": 0}

            def close():
                os.close(write_fd)
                stream.close()

            session.reset_local = blocked_reset
            session.end_case = close
            return runner

        def normal_factory():
            runner = self.factory()
            runner.sessions["gpio"].reset_local = lambda: {"cancelled_responses": 0}
            return runner

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, blocked_factory, output,
                budget=ResourceBudget(max_wall_time_ms=20))
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(0, trace.local_ticks["gpio"])
            self.assertEqual("inflight_reset", trace.events[-1]["phase"])
            self.assertTrue(trace.events[-1]["effect_may_have_occurred"])
            comparison = replay_evidence_bundle(
                output, normal_factory, allow_factory_mismatch=True)
            self.assertTrue(comparison.matches)
            self.assertEqual("semantic_prefix", comparison.verification_scope)

    def test_reset_ready_startup_limit_is_environment_failure_before_wall_limit(self):
        genome = replace(self.genome, encoding_version=3, reset_actions=(
            ResetAction("restart", "warm_all", Trigger("START")),))

        def blocked_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]
            read_fd, write_fd = os.pipe()
            stream = os.fdopen(read_fd, "r", encoding="ascii", buffering=1)

            def blocked_reset():
                read_startup_ready(BoundedLineReader(), stream)
                return {"cancelled_responses": 0}

            def close():
                os.close(write_fd)
                stream.close()

            session.reset_local = blocked_reset
            session.end_case = close
            return runner

        with tempfile.TemporaryDirectory() as directory, patch(
                "myfuzz.scenario.protocol_io.DEFAULT_READY_TIMEOUT_SECONDS", 0.02):
            bundle = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, blocked_factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=1000))
            self.assertEqual("environment_error", trace.status)
            self.assertEqual("reset_failure", trace.events[-1]["kind"])
            self.assertEqual("LocalCommandDeadlineExceeded",
                             trace.events[-1]["error_type"])
            self.assertTrue(replay_evidence_bundle(bundle, blocked_factory).matches)

    def test_evidence_bytes_reject_before_evidence_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            with self.assertRaisesRegex(ValueError, "max_evidence_bytes"):
                save_evidence_bundle(self.genome, self.factory, output,
                                     budget=ResourceBudget(
                                         max_evidence_bytes=8 * 1024 * 1024 + 100))
            self.assertEqual(0, self.sessions[0].begins)
            self.assertFalse(output.exists())

    def test_evidence_growth_stops_after_observed_large_local_output(self):
        large = 10 ** 1000

        def large_factory():
            runner = self.factory()
            session = runner.sessions["gpio"]

            def step(inputs):
                session.steps += 1
                return {"out": large}

            session.step_local = step
            return runner

        sample = large_factory()
        base = _evidence_base_bytes(
            self.genome, sample.identity_document(),
            _factory_identity(large_factory))
        reserve = 1024 * 1024
        budget = ResourceBudget(
            max_evidence_bytes=reserve + base + 1000,
            evidence_termination_reserve_bytes=reserve)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                self.genome, large_factory, output, budget=budget)
            self.assertEqual("budget_exhausted", trace.status)
            self.assertEqual(1, trace.local_ticks["gpio"])
            self.assertEqual("max_evidence_bytes", trace.events[-1]["limit"])
            self.assertTrue(any(e.get("outputs", {}).get("out") == large
                                for e in trace.events))
            self.assertTrue(replay_evidence_bundle(output, large_factory).matches)

    def test_final_metadata_can_use_reserved_bytes_without_overrunning_hard_cap(self):
        genome = replace(self.genome, max_steps=1, actions=())
        sample = self.factory()
        base = _evidence_base_bytes(
            genome, sample.identity_document(), _factory_identity(self.factory))
        reserve = 1024 * 1024
        budget = ResourceBudget(
            max_evidence_bytes=reserve + base + 1000,
            evidence_termination_reserve_bytes=reserve)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "final-tail"
            trace = save_evidence_bundle(genome, self.factory, bundle, budget=budget)
            self.assertEqual("complete", trace.status)
            result = json.loads((bundle / "result.json").read_text())
            actual_bytes = result["resource_usage"]["evidence_bytes"]
            self.assertGreater(actual_bytes, budget.max_evidence_bytes - reserve)
            self.assertLessEqual(actual_bytes, budget.max_evidence_bytes)
            self.assertTrue(replay_evidence_bundle(bundle, self.factory).matches)

    def test_result_records_measured_usage_and_declared_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            budget = ResourceBudget()
            save_evidence_bundle(self.genome, self.factory, output, budget=budget)
            result = json.loads((output / "result.json").read_text())
            usage = result["resource_usage"]
            self.assertEqual(3, usage["scheduler_steps"])
            self.assertEqual(1, usage["source_actions"])
            self.assertEqual(result["event_count"], usage["semantic_records"])
            self.assertEqual(sum(path.stat().st_size for path in output.rglob("*")
                                 if path.is_file()), usage["evidence_bytes"])
            self.assertEqual(budget.to_document(), result["resource_budget"])
            self.assertTrue(replay_evidence_bundle(output, self.factory).matches)

    def test_replay_rejects_forged_usage_before_begin(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            save_evidence_bundle(self.genome, self.factory, output,
                                 budget=ResourceBudget())
            result_path = output / "result.json"
            result = json.loads(result_path.read_text())
            result["resource_usage"]["semantic_records"] += 1
            result_path.write_text(json.dumps(result))
            index_path = output / "bundle_index.json"
            index = json.loads(index_path.read_text())
            index["files"]["result.json"] = hashlib.sha256(
                result_path.read_bytes()).hexdigest()
            index_path.write_text(json.dumps(index))
            before = len(self.sessions)
            with self.assertRaisesRegex(ValueError, "resource_usage.semantic_records"):
                replay_evidence_bundle(output, self.factory)
            self.assertEqual(before, len(self.sessions))

    def test_budgeted_write_failure_does_not_publish_partial_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            original_write = Path.write_bytes

            def fail_result(path, data):
                if path.name == "result.json":
                    raise OSError("injected evidence storage failure")
                return original_write(path, data)

            with patch.object(Path, "write_bytes", fail_result):
                with self.assertRaisesRegex(OSError, "injected evidence"):
                    save_evidence_bundle(self.genome, self.factory, output,
                                         budget=ResourceBudget())
            self.assertFalse(output.exists())
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_unbudgeted_write_failure_does_not_publish_partial_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            original_write = Path.write_bytes

            def fail_result(path, data):
                if path.name == "result.json":
                    raise OSError("injected evidence storage failure")
                return original_write(path, data)

            with patch.object(Path, "write_bytes", fail_result):
                with self.assertRaisesRegex(OSError, "injected evidence"):
                    save_evidence_bundle(self.genome, self.factory, output)
            self.assertFalse(output.exists())
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_existing_evidence_is_rejected_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            save_evidence_bundle(self.genome, self.factory, output,
                                 budget=ResourceBudget())
            index_before = (output / "bundle_index.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "evidence directory must be new"):
                save_evidence_bundle(self.genome, self.factory, output,
                                     budget=ResourceBudget())
            self.assertEqual(index_before, (output / "bundle_index.json").read_bytes())
            self.assertTrue(replay_evidence_bundle(output, self.factory).matches)


if __name__ == "__main__":
    unittest.main()
