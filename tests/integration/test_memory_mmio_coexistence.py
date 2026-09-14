"""Task P4: constrained memory must coexist with real MMIO targets.

The module-level tests simulate the generated contract transducer directly and
compare every cycle against the Python reference (ContractRuntime over
CoherentMemoryState).  The integration tests build a real generated top
through the generic composition pipeline (CPU fixture + a real counter/GPIO
style peripheral instance + the constrained memory target), simulate it with
Icarus Verilog, and prove that MMIO traffic reaches the peripheral while the
transducer answers only inside its declared windows.

The old address_space contract mode is deliberately exercised as well: it must
keep mapping the whole address space and keep dropping component instances, so
the new behaviour stays version-isolated.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import random
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    source_tree_hash,
)
from myfuzz.composition.contract_transducer import ContractRuntime, compile_contract_transducer
from myfuzz.composition.cycle_input import TestHeader
from myfuzz.composition.processor_backend import build_processor_backend
from myfuzz.composition.processor_renderer import _render_processor_top
from myfuzz.composition.protocol_transducer import ProcessorBeatRequest
from myfuzz.composition.transducer_rtl import render_transducer_rtl
from myfuzz.isa.constraints import IsaContract
from myfuzz.isa.transducer import RiscvInstructionTransducer
from myfuzz.protocols.catalog import load_protocol_catalog


ROOT = Path(__file__).resolve().parents[2]
RAM_WINDOW = (0x1000, 0x1000, "read_write")
ROM_WINDOW = (0x2000, 0x100, "read_only")
MMIO_BASE = 0x0
MMIO_SIZE = 0x10
UNMAPPED_ADDRESS = 0x8000
MEMORY_ENTROPY = 0x51D3C0DE
SECOND_ENTROPY = 0xA5A5A5A5
ALIAS_WINDOWS = (
    {"base": 0x1000, "size": 0x100, "permissions": "read_write",
     "physical_memory_id": "shared_ram", "initialization_policy": "on_demand"},
    {"base": 0x3000, "size": 0x100, "permissions": "read_write",
     "physical_memory_id": "shared_ram", "initialization_policy": "on_demand"},
    {"base": 0x4000, "size": 0x100, "permissions": "read_write",
     "physical_memory_id": "other_ram", "initialization_policy": "on_demand"},
)
IMAGE_WINDOWS = (
    {"base": 0x5000, "size": 0x20, "permissions": "read_only",
     "physical_memory_id": "boot_image", "initialization_policy": "rom"},
    {"base": 0x6000, "size": 0x20, "permissions": "read_only",
     "physical_memory_id": "boot_image", "initialization_policy": "rom"},
    {"base": 0x7000, "size": 0x20, "permissions": "read_write",
     "physical_memory_id": "data_image", "initialization_policy": "preload"},
    {"base": 0x7100, "size": 0x20, "permissions": "read_write",
     "physical_memory_id": "scratch", "initialization_policy": "on_demand"},
)
BOOT_IMAGE = (0x13, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12)


def run_iverilog(directory: Path, sources, *, top: str = "tb", timeout: int = 180) -> str:
    compiler, runtime = shutil.which("iverilog"), shutil.which("vvp")
    if compiler is None or runtime is None:
        raise AssertionError("Icarus Verilog (iverilog and vvp) is required for P4 RTL evidence")
    executable = directory / "simulation.vvp"
    compiled = subprocess.run(
        (compiler, "-g2012", "-s", top, "-o", str(executable), *map(str, sources)),
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if compiled.returncode:
        raise AssertionError("iverilog failed:\n" + compiled.stdout + compiled.stderr)
    simulated = subprocess.run(
        (runtime, str(executable)), capture_output=True, text=True, timeout=timeout, check=False,
    )
    if simulated.returncode:
        raise AssertionError("vvp failed:\n" + simulated.stdout + simulated.stderr)
    return simulated.stdout


def constrained_plan(**overrides):
    args = dict(
        isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
        protocol=("processor-memory-beat", "1"), address_width=32, data_width=32,
        max_wait_cycles=3, memory_capacity_entries=8, allow_error=False,
        memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
        memory_mode="declared_windows", memory_windows=(RAM_WINDOW, ROM_WINDOW),
    )
    return compile_contract_transducer(**(args | overrides))


def legacy_plan(**overrides):
    args = dict(
        isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
        protocol=("processor-memory-beat", "1"), address_width=32, data_width=32,
        max_wait_cycles=3, memory_capacity_entries=8, allow_error=False,
        memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
    )
    return compile_contract_transducer(**(args | overrides))


def initialized_plan(**overrides):
    args = {"memory_windows": IMAGE_WINDOWS,
            "memory_images": {"boot_image": BOOT_IMAGE, "data_image": (0xAA, 0xBB)}}
    return constrained_plan(**(args | overrides))


def header_for(plan, **overrides):
    values = dict(schema_version="cycle_test.v1", layout_hash=plan.cycle_layout.layout_hash,
                  contract_hash=plan.contract_hash, reset_cycles=2, execution_cycles=100000,
                  boot_address=0x1000, hart_id=0)
    values.update(overrides)
    return TestHeader(**values)


def request_for(plan, address, *, instruction=False, **kwargs):
    function = "instruction_memory_master" if instruction else "data_memory_master"
    return ProcessorBeatRequest(address, function, dict(plan.memory_domains)[function], **kwargs)


def raw_for(plan, **values):
    assert set(values) <= {field.name for field in plan.cycle_layout.fields}
    return sum(values.get(field.name, 0) << field.raw_lo for field in plan.cycle_layout.fields)


@dataclass(frozen=True)
class Cycle:
    entropy: int = 0
    request: ProcessorBeatRequest | None = None
    reset: bool = False
    begin: TestHeader | None = None


def accepted(plan, req, **values):
    return Cycle(raw_for(plan, **({"response_choice": 1} | values)), req)


def answered(plan, **values):
    return Cycle(raw_for(plan, **({"response_choice": 2} | values)))


def held(plan, **values):
    return Cycle(raw_for(plan, **values))


def reset_cycle():
    return Cycle(reset=True)


class TransducerMemoryModeTests(unittest.TestCase):
    """The explicit mode, its identity, and its isolation from the old mode."""

    def test_declared_windows_mode_is_explicit_and_recorded_in_identity(self):
        plan = constrained_plan()
        document = plan.document()
        self.assertEqual(plan.memory_mode, "declared_windows")
        self.assertEqual(tuple(tuple(window) for window in plan.memory_windows), (RAM_WINDOW, ROM_WINDOW))
        self.assertEqual(document["memory_mode"], "declared_windows")
        self.assertEqual(document["schema_version"], "contract_transducer.v2")
        self.assertEqual(document["memory_windows"], [
            {"base": RAM_WINDOW[0], "size": RAM_WINDOW[1], "permissions": "read_write",
             "physical_memory_id": "virtual:1000:1000", "initialization_policy": "on_demand"},
            {"base": ROM_WINDOW[0], "size": ROM_WINDOW[1], "permissions": "read_only",
             "physical_memory_id": "virtual:2000:100", "initialization_policy": "on_demand"},
        ])
        self.assertEqual(document["contract_hash"], plan.contract_hash)

    def test_old_mode_keeps_its_document_and_rejects_windows(self):
        plan = legacy_plan()
        document = plan.document()
        self.assertEqual(plan.memory_mode, "address_space")
        self.assertEqual(plan.memory_windows, ())
        self.assertNotIn("memory_mode", document)
        self.assertNotIn("memory_windows", document)
        self.assertEqual(document["schema_version"], "contract_transducer.v1")
        with self.assertRaisesRegex(ValueError, "memory_windows"):
            legacy_plan(memory_windows=(RAM_WINDOW,))

    def test_window_records_are_rejected_when_unusable(self):
        for windows, reason in (
            ((), "requires memory windows"),
            (((0x1002, 0x100, "read_write"),), "aligned"),
            (((0x1000, 0, "read_write"),), "window"),
            (((0x1000, 0x100, "execute"),), "permissions"),
            (((0x1000, 0x100, "read_write"), (0x1080, 0x100, "read_write")), "overlap"),
            (((0x1000, 0x100, "read_write"), (0xFFFFFFF0, 0x100, "read_write")), "window"),
            (((0x1000, 0x100),), "permissions"),
            (({"base": 0x1000, "size": 0x100},), "permissions"),
        ):
            with self.subTest(windows=windows):
                with self.assertRaisesRegex(ValueError, reason):
                    constrained_plan(memory_windows=windows)
        with self.assertRaisesRegex(ValueError, "memory_mode"):
            constrained_plan(memory_mode="anything")

    def test_physical_identity_and_initialization_policy_survive_normalization(self):
        plan = constrained_plan(memory_windows=ALIAS_WINDOWS)
        records = plan.document()["memory_windows"]
        self.assertEqual(records[0]["physical_memory_id"], "shared_ram")
        self.assertEqual(records[0]["initialization_policy"], "on_demand")
        self.assertEqual(records[1]["physical_memory_id"], "shared_ram")

    def test_conflicting_alias_size_or_initialization_state_is_rejected(self):
        base = dict(ALIAS_WINDOWS[0])
        for changed in (
            base | {"base": 0x5000, "size": 0x80},
            base | {"base": 0x5000, "initialization_policy": "preload"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "conflicting physical memory"):
                    constrained_plan(memory_windows=(base, changed))

    def test_initialization_images_are_exact_contract_identity(self):
        plan = initialized_plan()
        self.assertEqual(dict(plan.memory_images), {
            "boot_image": BOOT_IMAGE, "data_image": (0xAA, 0xBB),
        })
        self.assertEqual(plan.document()["memory_images"], {
            "boot_image": list(BOOT_IMAGE), "data_image": [0xAA, 0xBB],
        })
        self.assertNotEqual(plan.contract_hash, initialized_plan(
            memory_images={"boot_image": BOOT_IMAGE[:-1] + (0x99,),
                           "data_image": (0xAA, 0xBB)}).contract_hash)

    def test_initialization_images_fail_closed(self):
        cases = (
            ({"data_image": ()}, "requires an explicit image"),
            ({"boot_image": BOOT_IMAGE, "data_image": (), "unknown": ()}, "unknown physical"),
            ({"boot_image": BOOT_IMAGE, "data_image": (), "scratch": ()}, "on_demand"),
            ({"boot_image": tuple(range(33)), "data_image": ()}, "exceeds physical memory"),
            ({"boot_image": (256,), "data_image": ()}, "byte"),
        )
        for images, reason in cases:
            with self.subTest(images=images):
                with self.assertRaisesRegex(ValueError, reason):
                    constrained_plan(memory_windows=IMAGE_WINDOWS, memory_images=images)
        with self.assertRaisesRegex(ValueError, "capacity"):
            initialized_plan(memory_capacity_entries=1)

    def test_direct_compile_rejects_unsupported_policies_and_writable_rom(self):
        base = {"base": 0x5000, "size": 0x20, "permissions": "read_only",
                "physical_memory_id": "memory0"}
        for policy in ("alias", "none", "zero"):
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(ValueError, "unsupported|initialization_policy"):
                    constrained_plan(memory_windows=(base | {"initialization_policy": policy},))
        with self.assertRaisesRegex(ValueError, "ROM.*read-only"):
            constrained_plan(memory_windows=(base | {
                "permissions": "read_write", "initialization_policy": "rom",
            },), memory_images={"memory0": ()})

    def test_images_are_rejected_for_every_non_image_policy(self):
        window = {"base": 0x5000, "size": 0x20, "permissions": "read_only",
                  "physical_memory_id": "memory0", "initialization_policy": "on_demand"}
        with self.assertRaisesRegex(ValueError, "does not accept an image"):
            constrained_plan(memory_windows=(window,), memory_images={"memory0": ()})

    def test_windows_and_versions_are_hash_isolated(self):
        plan = constrained_plan()
        self.assertNotEqual(plan.contract_hash, legacy_plan().contract_hash)
        self.assertNotEqual(plan.contract_hash, constrained_plan(
            memory_windows=(RAM_WINDOW, ROM_WINDOW, (0x3000, 0x100, "read_write"))).contract_hash)
        self.assertNotEqual(plan.contract_hash, constrained_plan(
            memory_windows=((0x1000, 0x1000, "read_write"), (0x2000, 0x100, "read_write"))).contract_hash)
        self.assertEqual(plan.contract_hash, constrained_plan(
            memory_windows=(ROM_WINDOW, RAM_WINDOW)).contract_hash)


class TransducerRtlReferenceTests(unittest.TestCase):
    """Cycle-for-cycle RTL/reference equivalence for the new memory semantics."""

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="p4-memory-")
        self.directory = Path(self._temporary.name)

    def tearDown(self):
        self._temporary.cleanup()

    def reference(self, plan, trace):
        runtime = ContractRuntime(plan)
        results = []
        for cycle in trace:
            if cycle.begin is not None:
                runtime.begin_test(cycle.begin)
                results.append((0, 0, 0, 0))
                continue
            result = runtime.step(cycle.entropy, {"request": cycle.request, "reset": cycle.reset})
            results.append((int(result.req_ready), int(result.rsp_valid),
                            result.rsp_data, int(result.rsp_error)))
        return results, runtime

    def simulate(self, plan, trace):
        width = plan.data_width
        address_width = plan.address_width
        raw_width = plan.cycle_layout.raw_width
        statements = []
        for index, cycle in enumerate(trace):
            req = cycle.request
            header = cycle.begin or header_for(plan)
            byte_enable = ((1 << (width // 8)) - 1 if req is None or req.byte_enable is None
                           else req.byte_enable)
            statements.append(f"""
        reset_i = 1'b{int(not cycle.reset)}; test_begin_i = 1'b{int(cycle.begin is not None)};
        test_boot_address_i = {address_width}'h{header.boot_address:x};
        test_illegal_instruction_i = 1'b{int(header.illegal_instruction)};
        rfuzz_cycle_bits = {raw_width}'h{cycle.entropy:x}; req_valid_i = 1'b{int(req is not None)};
        req_instruction_i = 1'b{int(req is not None and req.function == 'instruction_memory_master')};
        req_addr_i = {address_width}'h{req.address if req else 0:x};
        req_write_i = 1'b{int(req is not None and req.write)};
        req_wdata_i = {width}'h{req.write_data if req else 0:x}; req_be_i = {width // 8}'h{byte_enable:x};
        #4; $display("TRACE {index} %0d %0d %0h %0d", req_ready_o, rsp_valid_o, rsp_data_o, rsp_error_o);
        clock_i = 1; #5; clock_i = 0; #1;
        """)
        bench = f"""
    module tb;
      logic clock_i = 0, reset_i = 1, test_begin_i = 0;
      logic [{address_width-1}:0] test_boot_address_i, req_addr_i;
      logic test_illegal_instruction_i, req_valid_i, req_instruction_i, req_write_i;
      logic [{raw_width-1}:0] rfuzz_cycle_bits;
      logic [{width-1}:0] req_wdata_i, rsp_data_o;
      logic [{width//8-1}:0] req_be_i;
      logic req_ready_o, rsp_valid_o, rsp_error_o;
      myfuzz_contract_transducer dut (.*);
      initial begin
        {''.join(statements)}
        $finish;
      end
    endmodule
    """
        rtl = self.directory / "backend.sv"
        bench_path = self.directory / "tb.sv"
        rtl.write_text(render_transducer_rtl(plan), encoding="utf-8")
        bench_path.write_text(bench, encoding="utf-8")
        output = run_iverilog(self.directory, (rtl, bench_path))
        lines = [line.split() for line in output.splitlines() if line.startswith("TRACE ")]
        self.assertEqual(len(lines), len(trace), output)
        return [(int(line[2]), int(line[3]), int(line[4], 16), int(line[5])) for line in lines]

    def equivalent(self, plan, trace):
        expected, runtime = self.reference(plan, trace)
        actual = self.simulate(plan, trace)
        difference = next(((index, trace[index], got, want)
                           for index, (got, want) in enumerate(zip(actual, expected)) if got != want), None)
        self.assertIsNone(difference, "RTL and reference differ: " + repr(difference) + "\nactual=" + repr(actual))
        return actual, runtime

    def test_first_read_initialises_from_the_accepted_cycle_and_repeats(self):
        plan = constrained_plan()
        fetch = request_for(plan, 0x1000, instruction=True)
        trace = [
            Cycle(begin=header_for(plan)),
            accepted(plan, fetch, instruction_selector=0, instruction_payload=0x00000013),
            answered(plan),
            accepted(plan, fetch, instruction_selector=255, instruction_payload=0xFFFFFFFF),
            answered(plan, instruction_payload=0xDEADBEEF),
        ]
        actual, runtime = self.equivalent(plan, trace)
        expected = RiscvInstructionTransducer(plan.isa).repair(0, 0x00000013).word
        self.assertEqual(actual[2], (0, 1, expected, 0))
        self.assertEqual(actual[4][2], expected)
        self.assertEqual(runtime.memory.bytes_at("virtual:1000:1000", 0, 4), expected.to_bytes(4, "little"))

    def test_cpu_partial_write_is_visible_to_a_later_instruction_fetch(self):
        plan = constrained_plan()
        data = request_for(plan, 0x1000)
        fetch = request_for(plan, 0x1000, instruction=True)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, data, response_data=0x12345678), answered(plan)]
        trace += [accepted(plan, replace(data, write=True, write_data=0x0000AA00,
                                         byte_enable=0b0010)), answered(plan)]
        trace += [accepted(plan, fetch, response_data=0x11223344), answered(plan)]
        trace += [accepted(plan, fetch, response_data=0xFFFFFFFF), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[6][2], 0x1234AA78)
        self.assertEqual(actual[8][2], 0x1234AA78)
        self.assertEqual(runtime.memory.bytes_at("virtual:1000:1000", 0, 4), bytes((0x78, 0xAA, 0x34, 0x12)))

    def test_virtual_aliases_share_physical_bytes_but_distinct_ids_are_isolated(self):
        plan = constrained_plan(memory_windows=ALIAS_WINDOWS)
        alias_write = replace(request_for(plan, 0x1004), write=True,
                              write_data=0xA1B2C3D4, byte_enable=0b0110)
        alias_fetch = request_for(plan, 0x3004, instruction=True)
        isolated_read = request_for(plan, 0x4004)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, alias_write), answered(plan)]
        trace += [accepted(plan, alias_fetch, response_data=0x11223344), answered(plan)]
        trace += [accepted(plan, isolated_read, response_data=0x55667788), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[4], (0, 1, 0x11B2C344, 0))
        self.assertEqual(actual[6], (0, 1, 0x55667788, 0))
        self.assertEqual(runtime.memory.bytes_at("shared_ram", 4, 4), bytes((0x44, 0xC3, 0xB2, 0x11)))
        self.assertEqual(runtime.memory.bytes_at("other_ram", 4, 4), bytes((0x88, 0x77, 0x66, 0x55)))

    def test_rom_image_is_raw_independent_alias_coherent_and_reloaded_at_test_begin(self):
        plan = initialized_plan()
        primary = request_for(plan, 0x5000, instruction=True)
        alias = request_for(plan, 0x6004)
        illegal_write = replace(request_for(plan, 0x6000), write=True,
                                write_data=0xFFFFFFFF, byte_enable=0xF)
        trace = [Cycle(begin=header_for(plan, boot_address=0x5000))]
        trace += [accepted(plan, primary, instruction_payload=0xFFFFFFFF), answered(plan)]
        trace += [accepted(plan, alias, response_data=0xDEADBEEF), answered(plan)]
        trace += [accepted(plan, illegal_write), answered(plan)]
        trace += [Cycle(begin=header_for(plan, boot_address=0x5000))]
        trace += [accepted(plan, primary, instruction_payload=0), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[2], (0, 1, 0x00000013, 0))
        self.assertEqual(actual[4], (0, 1, 0x12345678, 0))
        self.assertEqual(actual[6], (0, 1, 0, 1))
        self.assertEqual(actual[9], (0, 1, 0x00000013, 0))
        self.assertEqual(runtime.memory.bytes_at("boot_image", 0, 8), bytes(BOOT_IMAGE))

    def test_preload_zero_fills_unspecified_bytes_and_ram_remains_on_demand(self):
        plan = initialized_plan()
        preload = request_for(plan, 0x7000)
        scratch = request_for(plan, 0x7100)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, preload, response_data=0xFFFFFFFF), answered(plan)]
        trace += [accepted(plan, scratch, response_data=0xA5A5A5A5), answered(plan)]
        trace += [accepted(plan, replace(preload, write=True, write_data=0x11223344,
                                         byte_enable=0xF)), answered(plan)]
        trace += [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, preload, response_data=0xDEADBEEF), answered(plan)]
        actual, _ = self.equivalent(plan, trace)
        self.assertEqual(actual[2], (0, 1, 0x0000BBAA, 0))
        self.assertEqual(actual[4], (0, 1, 0xA5A5A5A5, 0))
        self.assertEqual(actual[9], (0, 1, 0x0000BBAA, 0))

    def test_partial_write_to_untouched_preload_beat_keeps_zero_fill(self):
        plan = initialized_plan()
        preload = request_for(plan, 0x7004)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, replace(preload, write=True, write_data=0x00CC0000,
                                         byte_enable=0b0100), response_data=0xFFFFFFFF),
                  answered(plan)]
        trace += [accepted(plan, preload, response_data=0xA5A5A5A5), answered(plan)]
        actual, _ = self.equivalent(plan, trace)
        self.assertEqual(actual[4], (0, 1, 0x00CC0000, 0))

    def test_zero_tail_rom_data_read_then_instruction_alias_stays_preloaded(self):
        plan = initialized_plan()
        data = request_for(plan, 0x5010)
        instruction_alias = request_for(plan, 0x6010, instruction=True)
        trace = [Cycle(begin=header_for(plan, boot_address=0x5000))]
        trace += [accepted(plan, data, response_data=0xDEADBEEF), answered(plan)]
        trace += [accepted(plan, instruction_alias, instruction_payload=0xFFFFFFFF,
                           response_data=0xA5A5A5A5), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[2], (0, 1, 0, 0))
        self.assertEqual(actual[4], (0, 1, 0, 0))
        self.assertEqual(runtime.memory_provenance[("boot_image", 0x10)], "preloaded")

    def test_compressed_halfword_and_word_fetch_share_physical_bytes(self):
        for data_width in (32, 64):
            with self.subTest(data_width=data_width):
                plan = constrained_plan(data_width=data_width)
                word_fetch = request_for(plan, 0x1000, instruction=True)
                half_fetch = request_for(plan, 0x1002, instruction=True)
                payload = 0x123456789ABCDEF0 & ((1 << data_width) - 1)
                trace = [
                    Cycle(begin=header_for(plan)),
                    accepted(plan, word_fetch, instruction_selector=3, instruction_payload=payload),
                    answered(plan),
                    accepted(plan, half_fetch, instruction_compressed=1, instruction_selector=7,
                             instruction_payload=0xFFFFFFFF),
                    answered(plan),
                    accepted(plan, word_fetch, instruction_payload=0),
                    answered(plan),
                ]
                actual, runtime = self.equivalent(plan, trace)
                word, half = actual[2][2], actual[4][2]
                self.assertFalse(actual[2][3] or actual[4][3])
                # The halfword request at +2 aliases the same physical word, so
                # the whole beat and its byte-2 halfword are identical.
                self.assertEqual(half, word)
                self.assertEqual((half >> 16) & 0xFFFF, (word >> 16) & 0xFFFF)
                self.assertEqual(actual[6][2], word)
                self.assertEqual(runtime.memory.bytes_at("virtual:1000:1000", 0, data_width // 8),
                                 word.to_bytes(data_width // 8, "little"))

    def test_halfword_first_initialisation_stays_byte_consistent_for_a_word_fetch(self):
        plan = constrained_plan()
        payload = 0x1234ABCD
        trace = [
            Cycle(begin=header_for(plan, boot_address=0x1002)),
            accepted(plan, request_for(plan, 0x1002, instruction=True), instruction_compressed=1,
                     instruction_selector=1, instruction_payload=payload,
                     instruction_selector_1=2),
            answered(plan),
            accepted(plan, request_for(plan, 0x1000, instruction=True), instruction_payload=0),
            answered(plan),
        ]
        actual, runtime = self.equivalent(plan, trace)
        instruction = RiscvInstructionTransducer(plan.isa)
        low = instruction.repair(1, payload & 0xFFFF, width=16).word
        high = instruction.repair(2, (payload >> 16) & 0xFFFF, width=16).word
        self.assertEqual(actual[2][2], low | (high << 16))
        self.assertEqual(actual[4][2], actual[2][2])
        self.assertEqual(runtime.memory.bytes_at("virtual:1000:1000", 0, 4), actual[2][2].to_bytes(4, "little"))

    def test_stalled_acceptance_does_not_resample_initialisation_entropy(self):
        plan = constrained_plan()
        fetch = request_for(plan, 0x1000, instruction=True)
        first = RiscvInstructionTransducer(plan.isa).repair(0, 0x00000013).word
        data = request_for(plan, 0x1000)
        rom = request_for(plan, 0x2000)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, fetch, instruction_selector=0, instruction_payload=0x00000013),
                  held(plan, instruction_payload=0xFFFFFFFF), held(plan, instruction_payload=0x55555555),
                  answered(plan, instruction_payload=0xAAAAAAAA)]
        trace += [accepted(plan, fetch, instruction_payload=0x33333333), answered(plan)]
        trace += [accepted(plan, request_for(plan, 0x1004), response_data=MEMORY_ENTROPY),
                  held(plan, response_data=0x11111111), answered(plan, response_data=0x22222222)]
        trace += [accepted(plan, request_for(plan, 0x1004)), answered(plan, response_data=0x55555555)]
        trace += [accepted(plan, rom, response_data=0x0BADF00D), held(plan, response_data=0x33333333),
                  answered(plan, response_data=0x44444444)]
        trace += [accepted(plan, rom), answered(plan, response_data=0x66666666)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[4][2], first)
        self.assertEqual(actual[6][2], first)
        self.assertEqual(actual[9][2], MEMORY_ENTROPY)
        self.assertEqual(actual[11][2], MEMORY_ENTROPY)
        self.assertEqual(actual[14][2], 0x0BADF00D)
        self.assertEqual(actual[16][2], 0x0BADF00D)

    def test_read_only_window_write_errors_without_side_effect(self):
        plan = constrained_plan()
        rom = request_for(plan, 0x2000)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, rom, response_data=0x11223344), answered(plan)]
        trace += [accepted(plan, replace(rom, write=True, write_data=0x99, byte_enable=0xF)),
                  answered(plan)]
        trace += [accepted(plan, rom), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[2], (0, 1, 0x11223344, 0))
        self.assertEqual(actual[4], (0, 1, 0, 1))
        self.assertEqual(actual[6], (0, 1, 0x11223344, 0))
        self.assertEqual(runtime.memory.bytes_at("virtual:2000:100", 0, 4), bytes((0x44, 0x33, 0x22, 0x11)))
        self.assertEqual(runtime.fault_counts.get("read_only_write_error"), 1)

    def test_requests_outside_the_declared_windows_are_never_answered(self):
        plan = constrained_plan()
        outside = request_for(plan, UNMAPPED_ADDRESS)
        trace = [Cycle(begin=header_for(plan))]
        trace += [Cycle(raw_for(plan, response_choice=1, response_data=0xFFFFFFFF), outside)
                  for _ in range(plan.max_wait_cycles + 2)]
        trace += [Cycle(raw_for(plan, response_choice=2, response_data=0xFFFFFFFF), outside)
                  for _ in range(3)]
        trace += [accepted(plan, request_for(plan, 0x1000), response_data=MEMORY_ENTROPY), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        for result in actual[1:len(actual) - 2]:
            self.assertEqual(result, (0, 0, 0, 0), "the transducer answered outside its windows")
        self.assertEqual(actual[-1][2], MEMORY_ENTROPY)
        self.assertEqual(dict(runtime.memory_provenance), {("virtual:1000:1000", 0): "data_generated"})

    def test_dut_reset_preserves_memory_until_explicit_test_begin(self):
        plan = constrained_plan()
        data = request_for(plan, 0x1000)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, data, response_data=MEMORY_ENTROPY), answered(plan)]
        trace += [reset_cycle()]
        trace += [accepted(plan, data, response_data=SECOND_ENTROPY), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[2][2], MEMORY_ENTROPY)
        self.assertEqual(actual[5][2], MEMORY_ENTROPY)
        self.assertEqual(dict(runtime.memory_provenance), {("virtual:1000:1000", 0): "data_generated"})
        trace += [Cycle(begin=header_for(plan)),
                  accepted(plan, data, response_data=0x0BADF00D), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[-1][2], 0x0BADF00D)

    def test_capacity_exhaustion_completes_with_an_error_without_eviction(self):
        plan = constrained_plan(memory_capacity_entries=1)
        first = request_for(plan, 0x1000)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, first, response_data=0x11111111), answered(plan)]
        trace += [accepted(plan, request_for(plan, 0x1004), response_data=0x22222222), answered(plan)]
        trace += [accepted(plan, first), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        self.assertEqual(actual[2][2], 0x11111111)
        self.assertEqual(actual[4], (0, 1, 0, 1))
        self.assertEqual(actual[6][2], 0x11111111)
        self.assertEqual(runtime.fault_counts.get("capacity_error"), 1)

    def test_64_bit_fetch_and_byte_enable_writes_are_byte_consistent(self):
        plan = constrained_plan(data_width=64)
        data = request_for(plan, 0x1000)
        fetch = request_for(plan, 0x1000, instruction=True)
        trace = [Cycle(begin=header_for(plan))]
        trace += [accepted(plan, replace(data, write=True, write_data=0x89ABCDEF, byte_enable=0b1111),
                           response_data=0x1122334455667788), answered(plan)]
        trace += [accepted(plan, fetch, response_data=0x99AABBCCDDEEFF00), answered(plan)]
        trace += [accepted(plan, fetch, response_data=0), answered(plan)]
        actual, runtime = self.equivalent(plan, trace)
        # Written lanes keep their bytes; unwritten lanes initialise from the
        # response data of the accepted fetch: lanes 4..7 come from bytes 4..7.
        expected = 0x99AABBCC89ABCDEF
        self.assertEqual(actual[4][2], expected)
        self.assertEqual(actual[6][2], expected)
        self.assertEqual(runtime.memory.bytes_at("virtual:1000:1000", 0, 8), expected.to_bytes(8, "little"))

    def test_seeded_mixed_window_trace_matches_the_reference(self):
        plan = constrained_plan(memory_capacity_entries=6, max_wait_cycles=4)
        generator = random.Random(0x9E3779B9)
        addresses = [0x1000, 0x1004, 0x1008, 0x100C, 0x2000, 0x2004]
        trace = [Cycle(begin=header_for(plan))]
        pending = False
        for _ in range(600):
            entropy = {"response_data": generator.getrandbits(plan.data_width),
                       "instruction_payload": generator.getrandbits(plan.data_width)}
            if pending:
                choice = generator.randrange(2)
                trace.append(held(plan, **({"response_choice": choice} | entropy)))
                pending = choice == 0
                continue
            roll = generator.randrange(60)
            if roll == 0:
                trace.append(Cycle(begin=header_for(plan, boot_address=generator.choice((0x1000, 0x1002)))))
                continue
            if roll == 1:
                trace.append(reset_cycle())
                continue
            instruction = bool(generator.randrange(2))
            write = not instruction and bool(generator.randrange(3))
            req = request_for(plan, generator.choice(addresses), instruction=instruction, write=write,
                              write_data=generator.getrandbits(plan.data_width),
                              byte_enable=generator.getrandbits(plan.data_width // 8))
            values = {"response_choice": generator.randrange(2)} | entropy
            if "instruction_compressed" in {field.name for field in plan.cycle_layout.fields}:
                values["instruction_compressed"] = generator.randrange(2)
            trace.append(Cycle(raw_for(plan, **values), req))
            pending = values["response_choice"] == 1
        self.equivalent(plan, trace)


CPU_SOURCE = """module coexistence_cpu (
    input  logic clock_pin,
    input  logic reset_pin,
    input  logic ext_valid,
    input  logic ext_instruction,
    input  logic [31:0] ext_address,
    input  logic ext_write,
    input  logic [31:0] ext_wdata,
    input  logic [3:0] ext_bytes,
    output logic i_request,
    input  logic i_grant,
    output logic [31:0] i_address,
    input  logic i_response,
    input  logic [31:0] i_read_data,
    input  logic i_fault,
    output logic d_request,
    input  logic d_grant,
    output logic [31:0] d_address,
    output logic d_write,
    output logic [31:0] d_write_data,
    output logic [3:0] d_bytes,
    input  logic d_response,
    input  logic [31:0] d_read_data,
    input  logic d_fault,
    output logic [31:0] obs_rdata,
    output logic obs_error,
    output logic [7:0] obs_count,
    output logic obs_active
);
  assign i_request = ext_valid && ext_instruction && !obs_active;
  assign i_address = ext_address;
  assign d_request = ext_valid && !ext_instruction && !obs_active;
  assign d_address = ext_address;
  assign d_write = ext_write;
  assign d_write_data = ext_wdata;
  assign d_bytes = ext_bytes;
  always_ff @(posedge clock_pin or negedge reset_pin) begin
    if (!reset_pin) begin
      obs_rdata <= '0;
      obs_error <= 1'b0;
      obs_count <= '0;
      obs_active <= 1'b0;
    end else begin
      if ((i_request && i_grant) || (d_request && d_grant)) obs_active <= 1'b1;
      if (i_response || d_response) begin
        obs_active <= 1'b0;
        obs_rdata <= i_response ? i_read_data : d_read_data;
        obs_error <= i_response ? i_fault : d_fault;
        obs_count <= obs_count + 8'd1;
      end
    end
  end
endmodule
"""

MMIO_SOURCE = """module coexistence_mmio (
    input  logic clock,
    input  logic reset,
    input  logic req_valid,
    output logic req_ready,
    input  logic write,
    input  logic [31:0] addr,
    input  logic [31:0] wdata,
    input  logic [3:0] be,
    output logic rsp_valid,
    input  logic rsp_ready,
    output logic [31:0] rdata,
    output logic error
);
  logic pending_q, write_q;
  logic [31:0] addr_q, wdata_q;
  logic [3:0] be_q;
  logic [31:0] control_q, scratch_q, count_q;
  assign req_ready = !pending_q;
  assign rsp_valid = pending_q;
  assign error = 1'b0;
  // Read data must be valid in the same cycle rsp_valid is asserted, like
  // every other processor-memory-beat target in this fabric.
  always_comb begin
    case (addr_q[3:2])
      2'd0: rdata = control_q;
      2'd1: rdata = count_q;
      2'd2: rdata = scratch_q;
      default: rdata = 32'h5a5a5a5a;
    endcase
  end
  always_ff @(posedge clock or negedge reset) begin
    if (!reset) begin
      pending_q <= 1'b0; write_q <= 1'b0; addr_q <= '0; wdata_q <= '0; be_q <= '0;
      control_q <= '0; scratch_q <= '0; count_q <= '0;
    end else begin
      if (req_valid && req_ready) begin
        pending_q <= 1'b1;
        write_q <= write;
        addr_q <= addr;
        wdata_q <= wdata;
        be_q <= be;
        count_q <= count_q + 32'd1;
      end
      if (rsp_valid && rsp_ready) pending_q <= 1'b0;
      if (pending_q) begin
        if (write_q) begin
          case (addr_q[3:2])
            2'd0: begin
              if (be_q[0]) control_q[7:0] <= wdata_q[7:0];
              if (be_q[1]) control_q[15:8] <= wdata_q[15:8];
              if (be_q[2]) control_q[23:16] <= wdata_q[23:16];
              if (be_q[3]) control_q[31:24] <= wdata_q[31:24];
            end
            2'd2: begin
              if (be_q[0]) scratch_q[7:0] <= wdata_q[7:0];
              if (be_q[1]) scratch_q[15:8] <= wdata_q[15:8];
              if (be_q[2]) scratch_q[23:16] <= wdata_q[23:16];
              if (be_q[3]) scratch_q[31:24] <= wdata_q[31:24];
            end
            default: ;
          endcase
        end
      end
    end
  end
endmodule
"""


def _interface_description(module: str, revision: str):
    def route(endpoint: str, function: str, fields):
        return {"endpoint_id": endpoint, "function": function, "module": module,
                "protocol": ["obi", "1"], "clock": "clock_pin", "reset": "reset_pin",
                "fields": [{"role": role, "aliases": [port]} for role, port in fields]}

    return load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {"root": "source", "revision": revision, "top_module": module,
                   "files": ["rtl/coexistence_cpu.sv"], "elaboration": {"frontend": "verilator-json"}},
        "endpoints": [
            {"endpoint_id": "timing.clock", "function": "clock", "module": module,
             "fields": [{"role": "clock", "aliases": ["clock_pin"]}]},
            {"endpoint_id": "timing.reset", "function": "reset", "module": module,
             "fields": [{"role": "reset", "aliases": ["reset_pin"]}]},
            route("route.instruction", "instruction_memory_master", (
                ("req", "i_request"), ("gnt", "i_grant"), ("addr", "i_address"),
                ("rvalid", "i_response"), ("rdata", "i_read_data"), ("error", "i_fault"))),
            route("route.data", "data_memory_master", (
                ("req", "d_request"), ("gnt", "d_grant"), ("addr", "d_address"),
                ("we", "d_write"), ("wdata", "d_write_data"), ("be", "d_bytes"),
                ("rvalid", "d_response"), ("rdata", "d_read_data"), ("error", "d_fault"))),
            {"endpoint_id": "status", "function": "observation", "module": module,
             "fields": [{"role": role, "aliases": [port]} for role, port in (
                 ("obs_rdata", "obs_rdata"), ("obs_error", "obs_error"),
                 ("obs_count", "obs_count"), ("obs_active", "obs_active"),
                 ("ext_valid", "ext_valid"), ("ext_instruction", "ext_instruction"),
                 ("ext_address", "ext_address"), ("ext_write", "ext_write"),
                 ("ext_wdata", "ext_wdata"), ("ext_bytes", "ext_bytes"))]},
        ],
    })


def _mmio_profile():
    return PeripheralProfile(
        "coexistence_mmio", "coexistence_mmio", (("processor-memory-beat", "1"),),
        4, MMIO_SIZE, False, (), "implemented", ("coexistence_mmio.sv",), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
    )


def _top_fixture(root: Path):
    source_root = root / "source"
    source = source_root / "rtl/coexistence_cpu.sv"
    source.parent.mkdir(parents=True)
    source.write_text(CPU_SOURCE, encoding="utf-8")
    (root / "coexistence_mmio.sv").write_text(MMIO_SOURCE, encoding="utf-8")
    for relative in ("src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
                     "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    description = _interface_description("coexistence_cpu", source_tree_hash(source_root, (source,)))
    plan = plan_generic_composition(
        GenericCompositionRequest(description, ("coexistence_mmio",)), base_dir=root,
        component_catalog=ComponentCatalog((_mmio_profile(),)),
        protocol_catalog=load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins"),
    )
    backend = build_processor_backend(plan.processor_execution, plan.ir["address_regions"])
    return plan, backend


_PORT_DECLARATION = re.compile(r"^\s+(input|output)\s+(.*?)([A-Za-z_][A-Za-z0-9_$]*),?\s*$")


def _top_ports(top: str):
    header = re.search(r"module generic_composition_top \(\n(.*?)\n\);", top, re.S)
    if header is None:
        raise AssertionError("generated top header was not found")
    ports = []
    for line in header.group(1).splitlines():
        matched = _PORT_DECLARATION.match(line)
        if matched is None:
            raise AssertionError("unparsed generated port declaration: " + repr(line))
        ports.append((matched.group(1), matched.group(2).strip(), matched.group(3)))
    return ports


def _source_signals(top: str, module: str):
    block = re.search(r"^  " + module + r" u_[0-9a-f]+ \($\n(.*?)^  \);$", top, re.S | re.M)
    if block is None:
        raise AssertionError("generated source instance was not found")
    return {port: signal for port, signal in
            re.findall(r"\.([A-Za-z_][A-Za-z0-9_$]*)\(([A-Za-z_][A-Za-z0-9_$]*)\)", block.group(1))}


def _testbench(top: str, signals, body, byte_count: int) -> str:
    declarations = [("  " + shape + " " + name + ";") for _, shape, name in _top_ports(top)]
    clock, reset = signals["clock_pin"], signals["reset_pin"]
    windows = " || ".join(
        "(dut.u_contract_transducer.pending_base >= 32'h" + format(base, "x") +
        " && dut.u_contract_transducer.pending_base <= 32'h" + format(base + size - byte_count, "x") + ")"
        for base, size, _ in (RAM_WINDOW, ROM_WINDOW)
    )
    access_task = "".join((
        "  task automatic access(input logic instr, input logic wr, input logic [31:0] address,\n",
        "                        input logic [31:0] data, input logic [3:0] bytes);\n",
        "    logic [7:0] previous_count;\n",
        "    begin\n",
        "      previous_count = " + signals["obs_count"] + ";\n",
        "      @(negedge " + clock + ");\n",
        "      " + signals["ext_valid"] + " = 1'b1; " + signals["ext_instruction"] + " = instr;\n",
        "      " + signals["ext_address"] + " = address; " + signals["ext_write"] + " = wr;\n",
        "      " + signals["ext_wdata"] + " = data; " + signals["ext_bytes"] + " = bytes;\n",
        "      @(negedge " + clock + ");\n",
        "      " + signals["ext_valid"] + " = 1'b0;\n",
        "      wait (" + signals["obs_count"] + " !== previous_count);\n",
        "      @(negedge " + clock + ");\n",
        "    end\n",
        "  endtask",
    ))
    monitor = "".join((
        "  always @(posedge " + clock + ") begin\n",
        "    if (dut.u_contract_transducer.pending_q && !(" + windows + "))\n",
        '      $fatal(1, "the transducer held an address outside its declared windows");\n',
        "  end",
    ))
    return "\n".join((
        "module tb;",
        *declarations,
        "  integer failures = 0;",
        "  logic [31:0] observed_first;",
        "  generic_composition_top dut (.*);",
        "  initial " + clock + " = 1'b0;",
        "  always #5 " + clock + " = ~" + clock + ";",
        access_task,
        monitor,
        "  initial begin",
        *body,
        '    if (failures) $fatal(1, "failed checks");',
        '    $display("ALL_CHECKS_PASSED");',
        "    $finish;",
        "  end",
        '  initial begin #2000000; $fatal(1, "simulation timeout"); end',
        "endmodule",
    ))


class MmioCoexistenceTopTests(unittest.TestCase):
    """The generated top keeps real instances and routes MMIO away from memory."""

    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="p4-top-")
        self.directory = Path(self._temporary.name)
        self.plan, self.backend = _top_fixture(self.directory)
        self.contract = constrained_plan()
        self.top = _render_processor_top(self.plan, self.backend, contract_transducer=self.contract)
        self.signals = _source_signals(self.top, "coexistence_cpu")
        (self.directory / "top.sv").write_text(self.top, encoding="utf-8")
        (self.directory / "contract_transducer.sv").write_text(
            render_transducer_rtl(self.contract), encoding="utf-8")
        self.sources = (
            self.directory / "top.sv",
            self.directory / "source/rtl/coexistence_cpu.sv",
            self.directory / "coexistence_mmio.sv",
            self.directory / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
            self.directory / "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv",
            self.directory / "contract_transducer.sv",
        )

    def tearDown(self):
        self._temporary.cleanup()

    def signal(self, port: str) -> str:
        return self.signals[port]

    def clock(self) -> str:
        return self.signals["clock_pin"]

    def reset(self) -> str:
        return self.signals["reset_pin"]

    def set_entropy(self, response_data: int, instruction_payload: int = 0x00000013) -> str:
        bits = raw_for(self.contract, response_choice=3, response_data=response_data,
                       instruction_payload=instruction_payload)
        return "    rfuzz_cycle_bits = " + str(self.contract.cycle_layout.raw_width) + "'h" + format(bits, "x") + ";"

    def preamble(self, *, begin: bool = True):
        lines = [
            "    " + self.reset() + " = 1'b0;",
            "    repeat (4) @(posedge " + self.clock() + ");",
            "    " + self.reset() + " = 1'b1;",
            "    repeat (2) @(posedge " + self.clock() + ");",
        ]
        if begin:
            lines += [
                self.set_entropy(MEMORY_ENTROPY),
                "    test_boot_address = 32'h1000;",
                "    test_illegal_instruction = 1'b0;",
                "    test_begin = 1'b1;",
                "    @(posedge " + self.clock() + ");",
                "    test_begin = 1'b0;",
                "    repeat (2) @(posedge " + self.clock() + ");",
            ]
        return lines

    def check(self, expression: str, expected: str, label: str) -> str:
        return ("    if ((" + expression + ") !== " + expected + ") begin failures = failures + 1; "
                '$display("FAIL ' + label + ': got %0h", ' + expression + "); end "
                'else $display("PASS ' + label + '");')

    def access(self, *, instruction: bool, write: bool, address: int, data: int = 0,
               byte_enable: int = 0, label: str) -> str:
        return ("    access(1'b" + str(int(instruction)) + ", 1'b" + str(int(write)) + ", 32'h" +
                format(address, "x") + ", 32'h" + format(data, "x") + ", 4'h" +
                format(byte_enable, "x") + '); $display("ACCESS ' + label + '");')

    def simulate(self, body) -> str:
        bench = _testbench(self.top, self.signals, body, self.contract.data_width // 8)
        bench_path = self.directory / "tb.sv"
        bench_path.write_text(bench, encoding="utf-8")
        output = run_iverilog(self.directory, (*self.sources, bench_path))
        self.assertIn("ALL_CHECKS_PASSED", output)
        return output

    def test_generated_top_keeps_real_instances_and_never_maps_everything(self):
        self.assertIn("coexistence_mmio u_", self.top)
        self.assertIn("myfuzz_contract_transducer u_contract_transducer", self.top)
        self.assertIn("backend_target_memory_select", self.top)
        mapped = [(name, expression) for name, expression in re.findall(r"assign (\w+) = ([^;]*);", self.top)
                  if name.endswith("mapped")]
        self.assertTrue(mapped)
        for name, expression in mapped:
            self.assertNotEqual(expression.strip(), "1'b1",
                                "constrained windows must not map the whole address space")
        for base in (RAM_WINDOW[0], ROM_WINDOW[0]):
            self.assertIn("32'h" + format(base, "x"), self.top)
        # The old contract mode stays reproducible and version-isolated.
        legacy = compile_contract_transducer(
            isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
            protocol=("processor-memory-beat", "1"), address_width=32, data_width=32,
            memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
        )
        legacy_top = _render_processor_top(self.plan, self.backend, contract_transducer=legacy)
        self.assertNotEqual(legacy.contract_hash, self.contract.contract_hash)
        self.assertIn("assign backend_mapped = 1'b1;", legacy_top)
        self.assertNotIn("coexistence_mmio u_", legacy_top)

    def test_full_publication_keeps_real_instances_and_declared_windows(self):
        from myfuzz.composition import write_generic_composition

        output = self.directory / "published"
        summary = write_generic_composition(
            self.plan, output, base_dir=self.directory, contract_transducer=self.contract,
        )
        self.assertTrue(summary["complete"])
        top = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
        self.assertIn("coexistence_mmio u_", top)
        self.assertIn("myfuzz_contract_transducer u_contract_transducer", top)
        self.assertNotIn("assign backend_mapped = 1'b1;", top)
        self.assertIn("coexistence_mmio.sv", (output / "sources.f").read_text(encoding="utf-8"))

    def test_mmio_reaches_the_real_peripheral_and_memory_coexists(self):
        lines = self.preamble()
        lines += [
            self.access(instruction=False, write=True, address=MMIO_BASE, data=0xDEADBEEF,
                        byte_enable=0xF, label="mmio control write"),
            self.check(self.signal("obs_error"), "1'b0", "mmio write has no error"),
            self.access(instruction=False, write=False, address=MMIO_BASE, label="mmio control read"),
            self.check(self.signal("obs_rdata"), "32'hDEADBEEF", "mmio reads back the written register"),
            self.access(instruction=False, write=False, address=MMIO_BASE + 4, label="mmio counter read"),
            self.check(self.signal("obs_rdata"), "32'h00000003", "real counter counts every access"),
            self.access(instruction=False, write=True, address=MMIO_BASE + 8, data=0x0BADF00D,
                        byte_enable=0xF, label="mmio scratch write"),
            self.access(instruction=False, write=False, address=MMIO_BASE + 8, label="mmio scratch read"),
            self.check(self.signal("obs_rdata"), "32'h0BADF00D", "gpio-style register keeps its state"),
            self.access(instruction=False, write=False, address=0x1000, label="memory first read"),
            self.check(self.signal("obs_rdata"), "32'h" + format(MEMORY_ENTROPY, "08x"),
                       "program read initialised from entropy"),
            self.set_entropy(SECOND_ENTROPY),
            self.access(instruction=False, write=False, address=0x1000, label="memory repeat read"),
            self.check(self.signal("obs_rdata"), "32'h" + format(MEMORY_ENTROPY, "08x"),
                       "repeated read is byte-identical"),
            self.set_entropy(MEMORY_ENTROPY),
            self.access(instruction=False, write=True, address=0x1010, data=0x0000AA00,
                        byte_enable=0b0010, label="partial write"),
            self.access(instruction=True, write=False, address=0x1010, label="instruction fetch"),
            self.check(self.signal("obs_rdata"), "32'h51D3AADE", "fetch sees the CPU-written bytes"),
            self.check(self.signal("obs_error"), "1'b0", "fetch of CPU-written memory has no error"),
        ]
        self.simulate(lines)

    def test_unmapped_access_completes_with_an_error_instead_of_memory_data(self):
        lines = self.preamble()
        lines += [
            self.access(instruction=False, write=False, address=UNMAPPED_ADDRESS, label="unmapped read"),
            self.check(self.signal("obs_error"), "1'b1", "unmapped read is an explicit error"),
            self.check(self.signal("obs_rdata"), "32'h00000000", "unmapped read returns no memory data"),
            self.access(instruction=False, write=True, address=UNMAPPED_ADDRESS, data=0xFFFFFFFF,
                        byte_enable=0xF, label="unmapped write"),
            self.check(self.signal("obs_error"), "1'b1", "unmapped write is an explicit error"),
            self.access(instruction=False, write=False, address=UNMAPPED_ADDRESS, label="unmapped read again"),
            self.check(self.signal("obs_rdata"), "32'h00000000", "no silent memory appeared"),
        ]
        self.simulate(lines)

    def test_last_byte_address_routes_to_its_aligned_memory_beat(self):
        lines = self.preamble()
        lines += [
            self.access(instruction=False, write=False, address=0x1FFF,
                        label="last byte of RAM window"),
            self.check(self.signal("obs_error"), "1'b0", "last RAM byte is mapped"),
            self.check(self.signal("obs_rdata"), "32'h" + format(MEMORY_ENTROPY, "08x"),
                       "last RAM byte returns its aligned beat"),
        ]
        self.simulate(lines)

    def test_top_dut_reset_preserves_memory_and_test_begin_clears_it(self):
        lines = self.preamble()
        lines += [
            self.access(instruction=False, write=False, address=0x1000, label="initialise from first entropy"),
            self.check(self.signal("obs_rdata"), "32'h" + format(MEMORY_ENTROPY, "08x"),
                       "initial entropy stored"),
            self.set_entropy(SECOND_ENTROPY),
            self.access(instruction=False, write=False, address=0x1000, label="stored bytes before reset"),
            self.check(self.signal("obs_rdata"), "32'h" + format(MEMORY_ENTROPY, "08x"),
                       "stored bytes survive reads"),
            "    " + self.reset() + " = 1'b0;",
            "    repeat (4) @(posedge " + self.clock() + ");",
            "    " + self.reset() + " = 1'b1;",
            "    repeat (2) @(posedge " + self.clock() + ");",
            self.access(instruction=False, write=False, address=0x1000, label="read after reset"),
            self.check(self.signal("obs_rdata"), "32'h" + format(MEMORY_ENTROPY, "08x"),
                       "DUT reset preserved physical memory"),
            "    @(negedge " + self.clock() + "); test_begin = 1'b1;",
            "    @(negedge " + self.clock() + "); test_begin = 1'b0;",
            self.access(instruction=False, write=False, address=0x1000, label="read after test begin"),
            self.check(self.signal("obs_rdata"), "32'h" + format(SECOND_ENTROPY, "08x"),
                       "explicit test begin cleared the memory model test state"),
        ]
        self.simulate(lines)

    def test_program_region_first_fetch_initialises_and_repeats_in_the_top(self):
        lines = self.preamble()
        lines += [
            self.access(instruction=True, write=False, address=0x1000, label="first instruction fetch"),
            self.check(self.signal("obs_error"), "1'b0", "instruction fetch has no error"),
            "    observed_first = " + self.signal("obs_rdata") + ";",
            self.set_entropy(SECOND_ENTROPY, instruction_payload=0xFFFFFFFF),
            self.access(instruction=True, write=False, address=0x1000, label="repeat instruction fetch"),
            self.check(self.signal("obs_error"), "1'b0", "repeat fetch has no error"),
            self.check(self.signal("obs_rdata"), "observed_first", "repeated fetch is identical"),
        ]
        self.simulate(lines)


if __name__ == "__main__":
    unittest.main()
