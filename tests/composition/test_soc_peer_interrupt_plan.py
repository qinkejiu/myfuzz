"""Generation contract for heterogeneous peer/external interrupt sources."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_boot_program import ProgramRequest, build_boot_program
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.input_constraints import compile_input_constraints
from myfuzz.composition.soc_failure_evidence import build_evidence_package, replay_package
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    ExternalEvent,
    PeerStimulusEvent,
    RuntimeSample,
    build_profile_runtime,
    run_sample,
)

from tests.composition.soc_generation_fixture import ROOT


class HeterogeneousInterruptPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        document = json.loads(
            (ROOT / "examples/soc_generation/request-ibex.json").read_text())
        document["request_id"] = "ibex-peer-uart-gpio-interrupt-plan"
        document["peripherals"] = [
            {"instance_id": "uart0",
             "profile": "examples/soc_generation/profiles/novauart_link.json",
             "parameters": {"SERIAL_WIDTH": 8, "BAUD_DIV": 8,
                            "STOP_BITS": 1, "IDLE_LEVEL": 1}},
            {"instance_id": "gpio0",
             "profile": "examples/soc_generation/profiles/novagpio.json",
             "parameters": {}},
        ]
        document["peer_models"] = [{
            "instance_id": "uart0", "endpoint_id": "link.pins", "attach": True,
            "parameters": {"DATA_WIDTH": 8, "BAUD_DIV": 8,
                            "STOP_BITS": 1, "IDLE_LEVEL": 1,
                            "TIMEOUT_BITS": 64},
        }]
        profiles = {}
        for relative in (
                "configs/cpus/ibex/component_profile.json",
                "examples/soc_generation/profiles/novauart_link.json",
                "examples/soc_generation/profiles/novagpio.json"):
            profile = load_component_profile(ROOT / relative)
            profiles[relative] = profile
            profiles.setdefault(profile.component_id, profile)
        request = load_composition_request(document, profiles=profiles)
        cls.request_document = document
        cls.profiles = profiles
        cls.plan = build_composition(request, base_dir=ROOT)

    def test_peer_and_external_sources_have_distinct_trigger_kinds(self) -> None:
        program = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True))
        trigger = program.document["trigger"]
        self.assertEqual("combined_event_plan", trigger["kind"])
        self.assertEqual(2, len(trigger["source_ids"]))
        self.assertTrue(trigger["events"], "GPIO keeps an external input trigger")
        self.assertTrue(trigger["peer_events"], "UART uses the attached peer event ABI")
        self.assertTrue(all("payload" in item for item in trigger["peer_events"]))
        self.assertEqual("uart0", trigger["peer_events"][0]["instance_id"])
        self.assertEqual("gpio0", trigger["instance_ids"][0])

    def test_peer_trigger_prerequisites_are_profile_facts_in_the_program(self) -> None:
        program = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True))
        uart = next(item for item in program.document["sources"]
                    if item["instance_id"] == "uart0")
        self.assertEqual([{"register": "CTRL", "offset": 0, "mask": 1,
                           "reason": "enable UART receiver before peer frame",
                           "operation": "set_bits"}],
                         uart["prerequisites"])


class SpiInterruptPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        document = json.loads(
            (ROOT / "examples/soc_generation/request-ibex.json").read_text())
        document["request_id"] = "ibex-peer-spi-gpio-interrupt-plan"
        document["peripherals"] = [
            {"instance_id": "spi0",
             "profile": "examples/soc_generation/profiles/novaspi.json",
             "parameters": {"BITS": 8, "CPOL": 0, "CPHA": 0,
                            "SCK_HALF_DIV": 4, "CS_SETUP": 2, "CS_HOLD": 2}},
            {"instance_id": "gpio0",
             "profile": "examples/soc_generation/profiles/novagpio.json",
             "parameters": {}},
        ]
        document["peer_models"] = [{
            "instance_id": "spi0", "endpoint_id": "spi.pins", "attach": True,
            "parameters": {"BITS": 8, "CPOL": 0, "CPHA": 0,
                           "CS_ACTIVE_LOW": 1},
        }]
        profiles = {}
        for relative in (
                "configs/cpus/ibex/component_profile.json",
                "examples/soc_generation/profiles/novaspi.json",
                "examples/soc_generation/profiles/novagpio.json"):
            profile = load_component_profile(ROOT / relative)
            profiles[relative] = profile
            profiles.setdefault(profile.component_id, profile)
        request = load_composition_request(document, profiles=profiles)
        cls.request_document = document
        cls.profiles = profiles
        cls.plan = build_composition(request, base_dir=ROOT)

    def test_spi_peer_trigger_declares_cpu_mmio_start_after_peer_arm(self) -> None:
        program = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True))
        trigger = program.document["trigger"]
        self.assertEqual("combined_event_plan", trigger["kind"])
        self.assertEqual("spi.arm_byte", trigger["peer_events"][0]["slot_name"])
        self.assertEqual(["TXDATA", "CTRL"],
                         [item["register"] for item in trigger["mmio_writes"]])
        self.assertGreater(trigger["mmio_writes"][0]["after_cycle"],
                           trigger["peer_events"][0]["cycle"])
        self.assertEqual([0x5A, 3],
                         [item["value"] for item in trigger["mmio_writes"]])
        self.assertTrue(any("source spi0 trigger: write TXDATA" in line
                            for line in program.document["listing"]))

    def test_spi_mmio_actions_are_not_dropped_when_pins_are_exported(self) -> None:
        document = json.loads(json.dumps(self.request_document))
        document["peer_models"] = []
        request = load_composition_request(document, profiles=self.profiles)
        plan = build_composition(request, base_dir=ROOT)
        program = build_boot_program(
            plan, request=ProgramRequest(exercise_all_sources=True))
        self.assertEqual(["TXDATA", "CTRL"],
                         [item["register"] for item in
                          program.document["trigger"]["mmio_writes"]])


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for SPI peer interrupt RTL")
class SpiInterruptRuntimeTests(SpiInterruptPlanTests):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        tool = shutil.which("verilator")
        if tool is None:
            raise AssertionError("Verilator is required for SPI peer interrupt RTL")
        cls._temporary = tempfile.TemporaryDirectory(prefix="myfuzz-spi-gpio-irq-")
        root = Path(cls._temporary.name)
        cls.program = build_boot_program(
            cls.plan, request=ProgramRequest(exercise_all_sources=True))
        image = root / "boot.hex"
        image.write_text("".join(f"{byte:02x}\n" for byte in cls.program.image),
                         encoding="utf-8")
        files = render_composition(cls.plan)
        source_records = source_list(cls.plan)
        sources = [item["path"] for item in source_records
                   if item["role"] != "include_root"]
        include_roots = sorted({item["path"] for item in source_records
                                if item["role"] == "include_root"})
        flags = [f"-I{ROOT / item}" for item in include_roots]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        wrapper = root / "verilator-with-profile-flags.sh"
        wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" %
                           (tool, " ".join(flags)), encoding="utf-8")
        wrapper.chmod(0o755)
        cls.build = build_profile_runtime(
            cls.plan, output_dir=root / "build", base_dir=ROOT,
            top_text=files["myfuzz_soc_top.sv"], sources=sources,
            boot_image=image, verilator=wrapper.as_posix(), timeout_seconds=1800,
            spi_wire_contracts={"spi0": {
                "txdata_address": 0x40001008,
                "basis": "fixture SPI register norm: TXDATA at MMIO base + 8"}})

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def test_real_spi_and_gpio_sources_complete(self) -> None:
        trigger = self.program.document["trigger"]
        sample = RuntimeSample(
            request_id=2, raw=(0,) * 20000,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]),
            peer_events=tuple(PeerStimulusEvent(slot=int(item["slot"]),
                                                cycle=int(item["cycle"]),
                                                payload=int(item["payload"]))
                              for item in trigger["peer_events"]))
        result = run_sample(self.build, sample, timeout_seconds=1800)
        self.assertEqual("OK", result.status, result.reason or result.stderr[-1000:])
        self.assertEqual("pass", result.peer_oracle["status"])
        self.assertEqual(1, result.observations["spi0__rx_count_o"])
        self.assertGreater(len(result.peer_wire_trace), 8)
        self.assertEqual("spi0", result.peer_wire_status[0]["instance_id"])
        self.assertFalse(result.peer_wire_status[0]["truncated"])
        wire_check = next((item for item in result.peer_oracle["checks"]
                           if item["check_id"] == "spi-transfer-wire"), None)
        self.assertIsNotNone(wire_check, (result.peer_oracle, result.requests[:20]))
        self.assertEqual("pass", wire_check["status"], wire_check)
        self.assertTrue(any(item["addr"] == 0x40001008 and item["wdata"] == 0x5A
                            for item in result.requests))
        memory = {name: int(value) for name, value in result.observations.items()
                  if name.startswith("u_mem_1[")}
        def read32(address: int) -> int:
            offset = address - int(self.program.document["memory"]["ram_base"])
            word, lane = divmod(offset, 8)
            return (memory[f"u_mem_1[{word}]"] >> (lane * 8)) & 0xFFFF_FFFF
        report = int(self.program.report_address)
        self.assertEqual(1, read32(report + 0x4C), result.observations)
        self.assertEqual(2, read32(report + 0xE8), result.observations)
        self.assertEqual(1, read32(report + 0xEC), result.observations)
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        package = build_evidence_package(
            self.plan, self.build, policy, [result], samples=[sample],
            kind="heterogeneous_interrupt",
            criteria=[{"criterion_id": "interrupt-loop-closed",
                        "description": "both source ids are claimed and completed"}],
            notes=("SPI peer + GPIO real Ibex run",))
        self.assertEqual(result.peer_oracle["oracle_hash"],
                         package.result(0)["peer_oracle"]["oracle_hash"])
        replay = replay_package(package, self.build, timeout_seconds=1800)
        self.assertEqual("agreement", replay.status, replay.reason)

    def test_peer_arm_without_cpu_mmio_start_does_not_claim_spi(self) -> None:
        disabled = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True,
                                              trigger_event=False))
        image = Path(self._temporary.name) / "boot-without-spi-start.hex"
        image.write_text("".join(f"{byte:02x}\n" for byte in disabled.image),
                         encoding="utf-8")
        trigger = self.program.document["trigger"]
        sample = RuntimeSample(
            request_id=3, raw=(0,) * 20000,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]),
            peer_events=tuple(PeerStimulusEvent(slot=int(item["slot"]),
                                                cycle=int(item["cycle"]),
                                                payload=int(item["payload"]))
                              for item in trigger["peer_events"]))
        result = run_sample(replace(self.build, boot_image=image), sample,
                            timeout_seconds=1800)
        self.assertEqual("OK", result.status, result.reason or result.stderr[-1000:])
        self.assertEqual(0, result.observations["spi0__rx_count_o"])
        self.assertEqual("pass", result.peer_oracle["status"])
        memory = {name: int(value) for name, value in result.observations.items()
                  if name.startswith("u_mem_1[")}
        report = int(disabled.report_address)
        offset = report + 0xEC - int(disabled.document["memory"]["ram_base"])
        word, lane = divmod(offset, 8)
        self.assertEqual(0, (memory[f"u_mem_1[{word}]"] >> (lane * 8)) & 0xFFFF_FFFF)


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for heterogeneous peer interrupt RTL")
class HeterogeneousInterruptRuntimeTests(HeterogeneousInterruptPlanTests):
    """One real Ibex run proves the peer and GPIO sources share the controller."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        tool = shutil.which("verilator")
        if tool is None:
            raise AssertionError("Verilator is required for heterogeneous peer interrupt RTL")
        cls._temporary = tempfile.TemporaryDirectory(prefix="myfuzz-hetero-irq-")
        root = Path(cls._temporary.name)
        output = root / "build"
        image = root / "boot.hex"
        program = build_boot_program(cls.plan, request=ProgramRequest(exercise_all_sources=True))
        image.write_text("".join(f"{byte:02x}\n" for byte in program.image), encoding="utf-8")
        files = render_composition(cls.plan)
        source_records = source_list(cls.plan)
        sources = [item["path"] for item in source_records if item["role"] != "include_root"]
        include_roots = sorted({item["path"] for item in source_records
                                if item["role"] == "include_root"})
        flags = [f"-I{ROOT / item}" for item in include_roots]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        wrapper = root / "verilator-with-profile-flags.sh"
        wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" %
                           (tool, " ".join(flags)), encoding="utf-8")
        wrapper.chmod(0o755)
        cls.program = program
        cls.build = build_profile_runtime(
            cls.plan, output_dir=output, base_dir=ROOT,
            top_text=files["myfuzz_soc_top.sv"], sources=sources,
            boot_image=image, verilator=wrapper.as_posix(), timeout_seconds=1800)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def test_real_cpu_claims_peer_and_external_sources(self) -> None:
        trigger = self.program.document["trigger"]
        sample = RuntimeSample(
            request_id=1, raw=(0,) * 20000,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]),
            peer_events=tuple(PeerStimulusEvent(slot=int(item["slot"]),
                                                cycle=int(item["cycle"]),
                                                payload=int(item["payload"]))
                              for item in trigger["peer_events"]))
        result = run_sample(self.build, sample, timeout_seconds=1800)
        self.assertEqual("OK", result.status, result.reason or result.stderr[-1000:])
        self.assertEqual("pass", result.peer_oracle["status"])
        self.assertEqual(1, len(result.peer_applied))
        self.assertEqual(0x5A, result.peer_applied[0]["value"])
        policy = compile_input_constraints(self.plan, drive_profile="cpu_execute")
        package = build_evidence_package(
            self.plan, self.build, policy, [result], samples=[sample],
            kind="heterogeneous_interrupt",
            criteria=[{"criterion_id": "interrupt-loop-closed",
                        "description": "all declared source ids are claimed, cleared and completed"}],
            legality={"environment_legality": "confirmed",
                      "driver_violations": [], "constraint_rejections": [],
                      "monitor_results": [{"name": "peer-event-transport", "status": "pass"}]},
            notes=("UART peer + GPIO real Ibex run",))
        packaged_result = package.result(0)
        self.assertEqual("pass", packaged_result["peer_oracle"]["status"])
        self.assertEqual(result.peer_oracle["oracle_hash"],
                         packaged_result["peer_oracle"]["oracle_hash"])
        self.assertEqual(sample.peer_events[0].document(),
                         package.sample(0).peer_events[0].document())
        self.assertEqual("heterogeneous_interrupt", package.document()["kind"])
        replay = replay_package(package, self.build, timeout_seconds=1800)
        self.assertEqual("agreement", replay.status, replay.reason)
        self.assertFalse(replay.mismatching_fields, replay.mismatching_fields)
        # RAM readback is byte-addressed and little-endian in the generated
        # memory model.  These fields are the CPU's own claim/COMPLETE ledger.
        memory = {name: int(value) for name, value in result.observations.items()
                  if name.startswith("u_mem_1[")}
        def read32(address: int) -> int:
            offset = address - int(self.program.document["memory"]["ram_base"])
            word, lane = divmod(offset, 8)
            return (memory[f"u_mem_1[{word}]"] >> (lane * 8)) & 0xFFFF_FFFF
        report = int(self.program.report_address)
        fields = {name: offset for name, offset in (
            ("loop_closed", 0x4C), ("interrupt_completions", 0xE8),
             ("all_sources_closed", 0xEC))}
        self.assertEqual(1, read32(report + fields["loop_closed"]))
        self.assertEqual(2, read32(report + fields["interrupt_completions"]))
        self.assertEqual(1, read32(report + fields["all_sources_closed"]))


if __name__ == "__main__":
    unittest.main()
