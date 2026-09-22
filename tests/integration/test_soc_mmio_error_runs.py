"""Item 11: real runs of the generated program's MMIO and error behaviour.

One real Ibex composition (the one ``tests/integration/test_soc_interrupt_lifecycle.py``
builds) runs the generated boot program several times.  The program's declared-register
phase and its permission probes turn every behaviour this item names into a field of the
RAM report record, and each case below asserts the field the target really produced:

=======================================  ==================================================
behaviour                                positive / negative case
=======================================  ==================================================
unmapped address                         ``expect_error_access`` load (mcause 5) and store
                                         (mcause 7); the negative is a program without the
                                         scenario, whose causes stay 0
ROM write                                the store into the plan's read-only region is
                                         refused (mcause 7) and the image survives; the
                                         negative patches that store to a ``nop``, so the
                                         promised cause and the surviving image disagree
permission error                         writes to uart0's declared read-only registers and
                                         a read of its write-only register are answered with
                                         an error (per-probe mask); the same probes on gpio0
                                         are *accepted* by the DUT and the mask records that
                                         divergence instead of hiding it
read-clear / write-1-to-clear            the declared clear checks are confirmed, with the
                                         observed before/after values; the negative patches
                                         the declared access to a ``nop`` and the check fails
write + read-back                        every declared plain read/write register matches its
                                         offset-derived pattern; the negative patches one
                                         store and that register's result bit clears
=======================================  ==================================================

Every case writes its report record into ``runs/soc-mmio-error-verification/``, together
with the patched word and the run's status, so the evidence is a file and not a claim.

``MYFUZZ_SOC_REAL=1`` opts in.  When the flag is set nothing skips: a missing Verilator,
a failed build or a failed run fails the tests with that exact reason.
"""
from __future__ import annotations

import json
import os
import re
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.soc_boot_program import (
    COMPLETION_FLAG,
    ProgramRequest,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_runtime import ExternalEvent, RuntimeSample, run_sample

from tests.integration.test_soc_interrupt_lifecycle import (
    CYCLES,
    SocInterruptLifecycleTests as _Lifecycle,
    read32,
)

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
RUN_ROOT = ROOT / "runs/soc-mmio-error-verification"
CASE_ROOT = RUN_ROOT / "cases"
RAM_BASE = 0x8000_0000

#: mcause values the RISC-V privileged spec fixes for these faults.
LOAD_ACCESS_FAULT = 5
STORE_ACCESS_FAULT = 7

#: The declared register the uart probes hit, and the gpio ones they do not.
UART_RO_WRITE_PROBES = ("_sw_pp_probe_uart0_4", "_sw_pp_probe_uart0_c")
UART_WO_READ_PROBE = "_sw_pp_probe_uart0_8"
GPIO_RO_WRITE_PROBES = ("_sw_pp_probe_gpio0_8", "_sw_pp_probe_gpio0_10")


def _listing_rows(program) -> list[dict]:
    rows: list[dict] = []
    for entry in program.document["listing"]:
        parts = str(entry).split()
        if len(parts) < 2 or not re.fullmatch(r"[0-9a-f]{8}", parts[0]):
            continue
        address = int(parts[0], 16)
        if re.fullmatch(r"[0-9a-f]{8}", parts[1]):
            rows.append({"kind": "instruction", "address": address,
                         "word": int(parts[1], 16), "text": " ".join(parts[2:])})
        else:
            rows.append({"kind": "label", "address": address,
                         "text": " ".join(parts[1:]).rstrip(":")})
    return rows


def step_address(program, label: str) -> int:
    """The address of the instruction a generated step's label names."""
    rows = _listing_rows(program)
    for index, row in enumerate(rows):
        if row["kind"] != "label" or row["text"] != label:
            continue
        for following in rows[index + 1:]:
            if following["kind"] == "instruction":
                return int(following["address"])
        raise AssertionError(f"the label {label} names no instruction")
    raise AssertionError(f"the program has no step called {label}")


def patch_step(program, label: str) -> dict:
    """Replace the instruction a generated step names with a ``nop``.

    The patched word is recorded, so an artifact says exactly which generated
    step was disabled instead of only that something was.
    """
    address = step_address(program, label)
    rom_base = int(program.document["entry"]["rom_base"])
    offset = address - rom_base
    before = int.from_bytes(program.image[offset:offset + 4], "little")
    patched = bytearray(program.image)
    patched[offset:offset + 4] = (0x00000013).to_bytes(4, "little")
    return {"label": label, "address": address, "word_before": before, "word_after": 0x13,
            "image": bytes(patched)}


def write_case_image(name: str, image: bytes) -> Path:
    CASE_ROOT.mkdir(parents=True, exist_ok=True)
    path = CASE_ROOT / f"{name}.hex"
    path.write_text(image_hex(image), encoding="utf-8")
    return path


class _RunCase:
    """One boot image and the report record the composition really produced."""

    def __init__(self, name: str, program, patched: dict | None, result, layout: dict):
        self.name = name
        self.program = program
        self.patched = patched
        self.result = result
        self.layout = layout
        self.report = {field: read32(result, program.report_address + offset)
                       for field, offset in layout.items()}

    def document(self) -> dict:
        return {
            "case": self.name,
            "status": self.result.status,
            "cycles": self.result.cycles,
            "patched_step": (None if self.patched is None else
                             {key: value for key, value in self.patched.items()
                              if key != "image"}),
            "report": dict(sorted(self.report.items())),
            "promises": {name: int(value)
                         for name, value in sorted(self.program.observations.items())},
            "promise_violations": sorted(
                name for name, value in self.program.observations.items()
                if name != "completion_flag"
                and self.report.get(name) != int(value)),
            "completion_flag": read32(self.result, self.program.flag_address),
        }


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real MMIO error runs")
class SocMmioErrorRunTests(unittest.TestCase):
    """The declared-register phase and the permission probes, on real hardware."""

    blocker: str | None = None
    cases: dict[str, _RunCase] = {}
    program = None
    layout: dict = {}

    @classmethod
    def setUpClass(cls):
        try:
            cls._prepare()
        except Exception as error:                    # noqa: BLE001 - reported verbatim
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def _prepare(cls) -> None:
        # The lifecycle test's own preparation builds the plan, the rendered top
        # and the runtime; reusing it keeps one real build for both modules and
        # makes the blocker reason identical when the composition cannot build.
        _Lifecycle._prepare()
        cls.plan = _Lifecycle.plan
        cls.build = _Lifecycle.build
        cls.layout = dict(_Lifecycle.observations_layout)

        # The control: only the declared-register phase, so nothing faults.
        cls.plain = build_boot_program(cls.plan)
        # The positive: the same phase plus the permission probes and the error
        # scenario, every one of which the program records by name.
        cls.program = build_boot_program(
            cls.plan, request=ProgramRequest(probe_permissions=True,
                                             expect_error_access=True))

        plain_image = write_case_image("plain", cls.plain.image)
        probed_image = write_case_image("probed", cls.program.image)
        cls.cases["probed"] = cls._run("probed", cls.program, probed_image, None, 0x11)
        cls.cases["plain"] = cls._run("plain", cls.plain, plain_image, None, 0x12)

        # One negative per check: a generated step is disabled and the check that
        # depends on it must fail.
        for name, program, label, request_id in (
                ("no-rom-store", cls.program, "_sw_rom_store", 0x13),
                ("no-w1c-clear", cls.program, "_sw_se_access_uart0_10", 0x14),
                ("no-writeback-store", cls.program, "_sw_wb_store_gpio0_0", 0x15),
                ("no-permission-probe", cls.program, UART_RO_WRITE_PROBES[0], 0x16),
        ):
            patched = patch_step(program, label)
            image = write_case_image(name, patched["image"])
            cls.cases[name] = cls._run(name, program, image, patched, request_id)
        cls._write_artifact()

    @classmethod
    def _run(cls, name: str, program, image: Path, patched, request_id: int) -> _RunCase:
        trigger = program.document["trigger"]
        sample = RuntimeSample(
            request_id=request_id, raw=(0,) * CYCLES,
            events=tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                       value=int(item["value"]))
                         for item in trigger["events"]))
        build = replace(cls.build, boot_image=image.resolve())
        result = run_sample(build, sample)
        case = _RunCase(name, program, patched, result, cls.layout)
        print("MYFUZZ_MMIO_RUN case=%s status=%s cycles=%d violations=%s"
              % (name, result.status, result.cycles, case.document()["promise_violations"]))
        return case

    @classmethod
    def _write_artifact(cls) -> None:
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        document = {
            "schema_version": "soc_mmio_error_runs.v1",
            "provenance": ("tests/integration/test_soc_mmio_error_runs.py: real Ibex runs "
                           "of the generated boot program on the composed SoC"),
            "plan_hash": cls.plan.plan_hash,
            "build": str(cls.build.output_dir),
            "program": {
                "verify_peripherals": True,
                "probe_permissions": True,
                "expect_error_access": True,
                "software": cls.program.document["software"]["totals"],
                "software_checks": cls.program.document["software"]["checks"],
                "rom_check": cls.program.document["software"]["rom_check"],
                "permission_probes": cls.program.document["software"]["permission_probes"],
                "error_scenario": cls.program.document["error_scenario"],
                "report_layout": {item["name"]: item["offset"]
                                  for item in cls.program.document["report"]["layout"]},
            },
            "cases": {name: case.document() for name, case in cls.cases.items()},
        }
        (RUN_ROOT / "mmio_error_runs.json").write_text(
            json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    def setUp(self) -> None:
        if self.blocker is not None:
            self.fail("the MMIO error runs could not be prepared: %s" % self.blocker)

    def case(self, name: str) -> _RunCase:
        case = self.cases.get(name)
        self.assertIsNotNone(case, f"the case {name} was not run")
        assert case is not None
        self.assertEqual("OK", case.result.status, f"{name}: the run must complete")
        self.assertEqual(COMPLETION_FLAG, case.document()["completion_flag"],
                         f"{name}: the CPU wrote its completion flag")
        return case

    # -- the declared software phase --------------------------------------

    def test_the_probed_run_records_every_declared_register_step(self) -> None:
        case = self.case("probed")
        report = case.report
        self.assertEqual(1, report["software_phase"])
        self.assertEqual(10, report["software_registers"])
        # One declared side effect in this plan is unobservable through the
        # declared register map (novauart RXDATA's read-clears clears rx_valid,
        # which no declared register exposes), so it is recorded as a coverage
        # note and never guessed at.  It used to be two: novagpio IRQ_STATUS
        # declared read_clears while novagpio.sv clears irq_stat_q only on a
        # DATA_IN access, so that declaration was corrected to `none`.  A
        # declared fact about the DUT that the RTL does not implement is a
        # profile defect, not a coverage gap to record.
        self.assertEqual(1, report["software_skipped"])
        self.assertEqual(4, report["software_init_writes"])
        self.assertEqual(9, report["software_reads"])
        self.assertEqual(0, report["software_read_traps"],
                         "no declared readable register trapped the CPU")
        self.assertEqual(0, report["software_traps"],
                         "and no declared register access of the phase trapped at all")
        self.assertEqual(4, report["software_writeback_checks"])
        self.assertEqual(4, report["software_writeback_matches"])
        self.assertEqual(0b1111, report["software_writeback_mask"])
        self.assertEqual(2, report["software_status_checks"])

    def test_every_planned_case_run_is_self_consistent(self) -> None:
        for name, case in self.cases.items():
            with self.subTest(case=name):
                self.assertEqual("OK", case.result.status)

    # -- unmapped address --------------------------------------------------

    def test_the_unmapped_load_and_store_record_their_own_causes(self) -> None:
        case = self.case("probed")
        self.assertEqual(1, case.report["error_access_requested"])
        self.assertEqual(LOAD_ACCESS_FAULT, case.report["error_cause"])
        self.assertEqual(STORE_ACCESS_FAULT, case.report["unmapped_store_cause"])
        scenario = case.program.document["error_scenario"]
        windows = self.plan.plan["fabric"]["decode"]["windows"]
        address = int(scenario["address"])
        for row in windows:
            self.assertFalse(int(row["base"]) <= address < int(row["base"]) + int(row["size"]),
                             "the scenario address must decode to no declared window")

    def test_without_the_scenario_no_unmapped_access_is_recorded(self) -> None:
        case = self.case("plain")
        self.assertEqual(0, case.report["error_access_requested"])
        self.assertEqual(0, case.report["error_cause"])
        self.assertEqual(0, case.report["unmapped_store_cause"])
        self.assertEqual(0, case.report["permission_probes"])
        self.assertEqual(0, case.report["rom_write_requested"])

    # -- ROM write ---------------------------------------------------------

    def test_the_store_into_the_read_only_region_is_refused_and_the_image_survives(self) -> None:
        case = self.case("probed")
        check = case.program.document["software"]["rom_check"]
        self.assertEqual(1, case.report["rom_write_requested"])
        self.assertEqual(STORE_ACCESS_FAULT, case.report["rom_write_cause"],
                         "the plan declares the region read-only, so the fabric must "
                         "answer the store with an error")
        self.assertEqual(1, case.report["rom_unchanged"])
        self.assertEqual(case.report["rom_value_before"], case.report["rom_value_after"])
        self.assertNotEqual(0, case.report["rom_value_before"],
                            "the probe word must be a real image word")
        regions = {str(item["region_id"]): item
                   for item in self.plan.plan["address_map"]["memory_regions"]}
        region = regions[str(check["region_id"])]
        self.assertTrue((region.get("permissions") or {}).get("execute"))
        self.assertFalse((region.get("permissions") or {}).get("write"))

    def test_disabling_the_rom_store_makes_its_check_fail(self) -> None:
        case = self.case("no-rom-store")
        positive = self.case("probed")
        self.assertEqual(0x13, case.patched["word_after"])
        self.assertEqual(0, case.report["rom_write_cause"],
                         "with the store removed no refusal can be observed")
        self.assertNotEqual(positive.report["rom_write_cause"],
                            case.report["rom_write_cause"])
        self.assertEqual(1, case.report["rom_unchanged"],
                         "and the image still survives, so only the cause check fails")
        self.assertIn("rom_write_cause", case.document()["promise_violations"],
                      "the program's own promise is what the check is measured against")

    # -- permission errors --------------------------------------------------

    def test_the_declared_read_only_and_write_only_probes_record_the_real_response(self) -> None:
        case = self.case("probed")
        probes = {item["index"]: item
                  for item in case.program.document["software"]["permission_probes"]}
        self.assertEqual(5, case.report["permission_probes"])
        mask = case.report["permission_error_mask"]
        errored = {index for index, item in probes.items() if mask & (1 << index)}
        expected = {index for index, item in probes.items()
                    if item["instance_id"] == "uart0"}
        self.assertEqual(expected, errored,
                         "every direction violation on the uart is answered with an error")
        self.assertEqual(3, case.report["permission_errors"])
        self.assertEqual(0, mask & 0b11,
                         "the gpio's declared read-only registers are written by its RTL "
                         "without an error: the recorded mask says so instead of hiding it")
        self.assertIn(case.report["permission_last_mcause"], (LOAD_ACCESS_FAULT,
                                                              STORE_ACCESS_FAULT))

    def test_the_permission_probes_can_fail(self) -> None:
        case = self.case("no-permission-probe")
        positive = self.case("probed")
        index = next(item["index"] for item in
                     positive.program.document["software"]["permission_probes"]
                     if item["register"] == "STATUS"
                     and item["instance_id"] == "uart0")
        self.assertFalse(case.report["permission_error_mask"] & (1 << index),
                         "the disabled probe cannot report its error")
        self.assertEqual(positive.report["permission_error_mask"]
                         & ~(1 << index), case.report["permission_error_mask"])
        self.assertEqual(positive.report["permission_errors"] - 1,
                         case.report["permission_errors"])
        self.assertEqual(positive.report["permission_probes"],
                         case.report["permission_probes"],
                         "the probe is still counted, so the missing error is visible")

    # -- declared side effects ---------------------------------------------

    def test_the_declared_clear_checks_confirm_the_real_side_effect(self) -> None:
        case = self.case("probed")
        report = case.report
        self.assertEqual(2, report["software_side_effects"])
        self.assertEqual(2, report["software_side_effects_confirmed"])
        self.assertEqual(0b11, report["software_side_effect_mask"])
        # The last declared clear is the uart's write-1-to-clear, and it really
        # had something to clear: the receive path latches its interrupt at reset.
        self.assertEqual(1, report["software_side_effect_last_before"],
                         "the declared clear check must not be vacuous")
        self.assertEqual(0, report["software_side_effect_last_after"])
        checks = {item["instance_id"]: item
                  for peripheral in case.program.document["software"]["peripherals"]
                  for item in peripheral["registers"] if item["side_effect_check"]}
        self.assertIn("uart0", checks)
        self.assertEqual("IRQ_STATUS", checks["uart0"]["clears_register"])

    def test_removing_the_declared_clear_access_makes_the_check_fail(self) -> None:
        case = self.case("no-w1c-clear")
        positive = self.case("probed")
        self.assertEqual(0x13, case.patched["word_after"])
        self.assertEqual(positive.report["software_side_effects"],
                         case.report["software_side_effects"],
                         "the access is still attempted, so it is still counted")
        self.assertEqual(positive.report["software_side_effects_confirmed"] - 1,
                         case.report["software_side_effects_confirmed"],
                         "without the declared write the clear cannot happen")
        self.assertEqual(1, case.report["software_side_effect_last_before"])
        self.assertEqual(1, case.report["software_side_effect_last_after"],
                         "the state the declared access had to clear is still set")
        self.assertNotEqual(positive.report["software_side_effect_mask"],
                            case.report["software_side_effect_mask"])

    # -- write + read-back --------------------------------------------------

    def test_the_write_back_compares_the_offset_derived_pattern(self) -> None:
        case = self.case("probed")
        report = case.report
        self.assertEqual(report["software_writeback_checks"],
                         report["software_writeback_matches"])
        self.assertEqual(0x5A, report["software_writeback_last_expected"],
                         "the last declared plain read/write register is the uart's CTRL "
                         "and the pattern is a function of its offset")
        self.assertEqual(report["software_writeback_last_expected"],
                         report["software_writeback_last_observed"])

    def test_removing_one_write_back_store_makes_that_comparison_fail(self) -> None:
        case = self.case("no-writeback-store")
        positive = self.case("probed")
        self.assertEqual(0x13, case.patched["word_after"])
        self.assertEqual(positive.report["software_writeback_checks"],
                         case.report["software_writeback_checks"])
        self.assertEqual(positive.report["software_writeback_matches"] - 1,
                         case.report["software_writeback_matches"])
        self.assertEqual(0, case.report["software_writeback_mask"] & 0b1,
                         "the disabled register's own result bit is clear")
        self.assertEqual(positive.report["software_writeback_mask"] & ~0b1,
                         case.report["software_writeback_mask"])

    # -- the artifact -------------------------------------------------------

    def test_the_artifact_records_every_case(self) -> None:
        document = json.loads((RUN_ROOT / "mmio_error_runs.json").read_text(
            encoding="utf-8"))
        self.assertEqual(set(self.cases), set(document["cases"]))
        self.assertTrue(document["program"]["rom_check"]["region_id"])
        self.assertEqual(5, len(document["program"]["permission_probes"]))
        self.assertEqual(LOAD_ACCESS_FAULT,
                         document["cases"]["probed"]["report"]["error_cause"])
        self.assertEqual(STORE_ACCESS_FAULT,
                         document["cases"]["probed"]["report"]["unmapped_store_cause"])
        for name, case in document["cases"].items():
            with self.subTest(case=name):
                self.assertEqual("OK", case["status"])
                self.assertTrue((CASE_ROOT / f"{name}.hex").is_file(),
                                "every case keeps the boot image it ran")


if __name__ == "__main__":
    unittest.main()
