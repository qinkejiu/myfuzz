"""P7 stimulus compiler tests: fixed raw ABI, address strategies, driver rules.

The behavioural proof of the generated driver is the real Icarus simulation in
tests/protocols/test_fuzz_mmio_master_rtl.py.  This module proves that the
compiled soc_stimulus.v1 document declares exactly those semantics: three
fixed raw segments with one shared field table for all three test modes, the six
MMIO fields the driver consumes, two documented address strategies, the
idle/request/response driver rules with a counted busy-drop counter, recorded
errors instead of rewrites, and separate CPU/peripheral reset semantics.

The plan fixture mirrors pinned peripheral facts: the read-only boot ROM is not
a fuzz-MMIO target and the PULP APB GPIO has no PSTRB (partial_write false),
so both error classes have real witnesses.
"""
from __future__ import annotations

import copy
import json
import re
import unittest

from myfuzz.composition.soc_contracts import (
    SOC_MODES,
    soc_plan_hash,
    validate_soc_plan,
    validate_soc_stimulus,
)
from myfuzz.composition.soc_plan import build_soc_plan
from myfuzz.composition.soc_stimulus import (
    STIMULUS_SCHEMA,
    SocStimulusError,
    compile_soc_stimulus,
)
from myfuzz.contracts import content_hash

HASH_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

#: The six functional MMIO fields the driver consumes, in raw-bit order.
MMIO_FIELDS = ("offer", "target_selector", "offset", "write", "wdata", "be")
#: The payload fields latched at acceptance (offer is the accept trigger).
MMIO_LATCHED = ("target_selector", "offset", "write", "wdata", "be")

#: Windows sorted by (base, target_id) as the compiler records them.
ROM_BASE, ROM_SIZE = 0x00010000, 0x00008000
UART_BASE, UART_SIZE = 0x40000000, 0x00001000
GPIO_BASE, GPIO_SIZE = 0x50000000, 0x00001000
RAM_BASE, RAM_SIZE = 0x80000000, 0x00010000
WINDOW_ORDER = ("rom0_win", "uart0_win", "gpio0_win", "ram0_win")


# ---------------------------------------------------------------------------
# fixtures: a plan built from real peripheral facts
# ---------------------------------------------------------------------------


def spec_fixture() -> dict:
    """CPU + RAM + ROM + a real TL-UL UART + a real APB GPIO."""
    return {
        "schema_version": "soc_spec.v1",
        "spec_id": "p7-stimulus-fixture",
        "source_locks": ["ibex", "soc_ram_model", "soc_rom_model", "opentitan_uart",
                         "pulp_gpio", "soc_clock_reset_harness"],
        "components": [
            {
                "component_id": "cpu",
                "kind": "cpu",
                "source_lock": "ibex",
                "top_module": "ibex_top",
                "clock_domain": "core",
                "reset_domain": "cpu_rst",
                "instances": [{"instance_id": "cpu0", "parameters": {"RV32M": 1}}],
                "capability_evidence": {"isa": "rv32imc", "provenance": "configs/soc/sources.lock.json"},
            },
            {
                "component_id": "ram",
                "kind": "memory",
                "source_lock": "soc_ram_model",
                "top_module": "soc_ram_2p",
                "clock_domain": "core",
                "reset_domain": "sys_rst",
                "instances": [{"instance_id": "ram0", "parameters": {"WORDS": 4096}}],
                "capability_evidence": {"model": "coherent dual-port RAM", "provenance": "P4"},
            },
            {
                "component_id": "rom",
                "kind": "memory",
                "source_lock": "soc_rom_model",
                "top_module": "soc_rom_1p",
                "clock_domain": "core",
                "reset_domain": "sys_rst",
                "instances": [{"instance_id": "rom0", "parameters": {"WORDS": 2048}}],
                "capability_evidence": {"model": "read-only boot ROM", "provenance": "P4"},
            },
            {
                "component_id": "uart",
                "kind": "peripheral",
                "source_lock": "opentitan_uart",
                "top_module": "uart",
                "clock_domain": "core",
                "reset_domain": "sys_rst",
                "instances": [{"instance_id": "uart0", "parameters": {"AlertEnable": 0}}],
                "capability_evidence": {
                    "protocol": "tl-ul",
                    "provenance": "configs/soc/closures/opentitan_uart.json",
                },
            },
            {
                "component_id": "gpio",
                "kind": "peripheral",
                "source_lock": "pulp_gpio",
                "top_module": "apb_gpio",
                "clock_domain": "core",
                "reset_domain": "sys_rst",
                "instances": [{"instance_id": "gpio0", "parameters": {"PAD_NUM": 32}}],
                "capability_evidence": {
                    "protocol": "apb",
                    "provenance": "configs/soc/closures/pulp_gpio.json",
                },
            },
            {
                "component_id": "harness",
                "kind": "clock_reset",
                "source_lock": "soc_clock_reset_harness",
                "top_module": "soc_harness",
                "clock_domain": "core",
                "reset_domain": "sys_rst",
                "instances": [{"instance_id": "harness0", "parameters": {"CYCLES": 100000}}],
                "capability_evidence": {"model": "clock/reset/environment harness", "provenance": "P7"},
            },
        ],
        "memory_regions": [
            {
                "region_id": "ram0_data",
                "component_id": "ram",
                "base": RAM_BASE,
                "size": RAM_SIZE,
                "permissions": {"read": True, "write": True, "execute": True},
                "physical_memory_id": "sram0",
                "initialization_policy": "on_demand",
            },
            {
                "region_id": "rom0_code",
                "component_id": "rom",
                "base": ROM_BASE,
                "size": ROM_SIZE,
                "permissions": {"read": True, "write": False, "execute": True},
                "physical_memory_id": "bootrom0",
                "initialization_policy": "rom",
            },
        ],
        "masters": [
            {
                "source_id": "cpu_ifetch",
                "kind": "cpu_instruction",
                "component_id": "cpu",
                "port": "instr",
                "protocol": ["obi", "1"],
                "data_width": 32,
                "address_width": 32,
                "test_modes": ["cpu_only", "mixed"],
            },
            {
                "source_id": "cpu_data",
                "kind": "cpu_data",
                "component_id": "cpu",
                "port": "data",
                "protocol": ["obi", "1"],
                "data_width": 32,
                "address_width": 32,
                "test_modes": ["cpu_only", "mixed"],
            },
            {
                "source_id": "fuzz_mmio",
                "kind": "fuzz_mmio",
                "component_id": "harness",
                "port": "mmio",
                "protocol": ["processor-memory-beat", "1"],
                "data_width": 32,
                "address_width": 32,
                "test_modes": ["mmio_only", "mixed"],
            },
        ],
        "targets": [
            {
                "target_id": "rom0_win",
                "component_id": "rom",
                "port": "rom",
                "protocol": ["ready-valid-memory", "1"],
                "window": {"base": ROM_BASE, "size": ROM_SIZE},
                "request_sources": ["cpu_ifetch"],
                "response_owner": "soc_fabric",
                "byte_enable": False,
            },
            {
                "target_id": "uart0_win",
                "component_id": "uart",
                "port": "tl",
                "protocol": ["tl-ul", "1"],
                "window": {"base": UART_BASE, "size": UART_SIZE},
                "request_sources": ["cpu_data", "fuzz_mmio"],
                "response_owner": "soc_fabric",
                "byte_enable": True,
            },
            {
                "target_id": "gpio0_win",
                "component_id": "gpio",
                "port": "apb",
                "protocol": ["apb", "3"],
                "window": {"base": GPIO_BASE, "size": GPIO_SIZE},
                "request_sources": ["cpu_data", "fuzz_mmio"],
                "response_owner": "soc_fabric",
                "byte_enable": False,
            },
            {
                "target_id": "ram0_win",
                "component_id": "ram",
                "port": "sram",
                "protocol": ["ready-valid-memory", "1"],
                "window": {"base": RAM_BASE, "size": RAM_SIZE},
                "request_sources": ["cpu_data", "fuzz_mmio"],
                "response_owner": "soc_fabric",
                "byte_enable": True,
            },
        ],
        "interrupt_routes": [
            {
                "route_id": "uart0_irq",
                "source": {"component_id": "uart", "signal": "intr_uart", "trigger": "level"},
                "sink": {"master_id": "cpu_data", "irq": 3},
                "mask_ack": {"register": "uart0.intr_state", "semantics": "write-1-to-clear"},
            }
        ],
        "environment_links": [
            {
                "link_id": "uart0_pins",
                "component_id": "uart",
                "protocol": ["uart-serial", "1"],
                "parameters": {"baud": 115200},
            }
        ],
        "resources": {
            "clock_domains": [{"name": "core", "frequency_hz": 50000000}],
            "resets": [
                {"name": "rst_sys_ni", "domain": "sys_rst", "polarity": "active_low", "synchronous": True},
                {"name": "rst_cpu_ni", "domain": "cpu_rst", "polarity": "active_low", "synchronous": True},
            ],
            "clock_adapters": [],
            "limits": {
                "build_timeout_s": 600,
                "run_timeout_s": 120,
                "rss_limit_mb": 2048,
                "cycles_per_sample": 100000,
            },
        },
        "assumptions": [
            {
                "assumption_id": "single_runtime_clock",
                "statement": "Every selected IP runs on the single runtime clock domain.",
                "provenance": "configs/soc/closures/pulp_gpio.json",
            }
        ],
        "provenance": {"components": "configs/soc/sources.lock.json"},
    }


def target_contracts_fixture() -> list:
    return [
        {
            "target_id": "rom0_win",
            "component_id": "rom",
            "port": "rom",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": "beat_to_rom",
            "adapter_source": "protocols/rtl/beat_to_rom.sv",
            "capabilities": {"partial_write": False, "read": True, "write": False, "data_width": 32},
            "evidence": {"provenance": "configs/soc/closures/zipcpu_timer.json"},
        },
        {
            "target_id": "uart0_win",
            "component_id": "uart",
            "port": "tl",
            "protocol": ["tl-ul", "1"],
            "adapter_module": "beat_to_tlul",
            "adapter_source": "protocols/rtl/beat_to_tlul.sv",
            "capabilities": {"partial_write": True, "read": True, "write": True, "data_width": 32},
            "evidence": {"provenance": "configs/soc/closures/opentitan_uart.json"},
        },
        {
            # Real PULP APB GPIO: APB3 signal set without PSTRB, so a partial write
            # cannot be expressed and is not claimed as supported.
            "target_id": "gpio0_win",
            "component_id": "gpio",
            "port": "apb",
            "protocol": ["apb", "3"],
            "adapter_module": "beat_to_apb",
            "adapter_source": "protocols/rtl/beat_to_apb.sv",
            "capabilities": {"partial_write": False, "read": True, "write": True, "data_width": 32},
            "evidence": {"provenance": "configs/soc/closures/pulp_gpio.json"},
        },
        {
            "target_id": "ram0_win",
            "component_id": "ram",
            "port": "sram",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": "beat_to_ram",
            "adapter_source": "protocols/rtl/beat_to_ram.sv",
            "capabilities": {"partial_write": True, "read": True, "write": True, "data_width": 32},
            "evidence": {"provenance": "configs/soc/closures/pulp_spi.json"},
        },
    ]


def processor_execution_fixture() -> dict:
    route = {
        "source_protocol": ["obi", "1"],
        "target_protocol": ["processor-memory-beat", "1"],
        "adapter_id": "obi_beat",
        "rtl_module": "obi_to_beat",
        "rtl_source": "protocols/rtl/obi_to_beat.sv",
        "parameters": {"ADDR_WIDTH": 32, "READ_ONLY": 0},
        "widths": {"address": 32, "data": 32},
        "field_connections": [],
        "extension_policies": [],
        "reset_contract": {"polarity": "active_low", "synchrony": "sync"},
        "backend_contract": {"mode": "single_outstanding_request_response", "protocol": ["processor-memory-beat", "1"], "capabilities": {"max_outstanding": 1, "max_wait_cycles": 32}},
    }
    return {
        "schema_version": "processor_execution.v1",
        "adapter_sources": ["protocols/rtl/obi_to_beat.sv"],
        "classification": None,
        "routes": [
            dict(route, route_id=11, function="instruction_memory_master", parameters={"ADDR_WIDTH": 32, "READ_ONLY": 1}),
            dict(route, route_id=12, function="data_memory_master"),
        ],
        "execution_hash": "sha256:" + "a" * 64,
    }


def plan_fixture() -> dict:
    plan = build_soc_plan(spec_fixture(), processor_execution_fixture(), target_contracts_fixture())
    validate_soc_plan(plan)
    return plan


def policy(mode: str = "mixed", strategy: str = "biased", **rules) -> dict:
    result = {"mode": mode, "address_strategy": strategy}
    if rules:
        result["rules"] = rules
    return result


def compile_document(mode: str = "mixed", strategy: str = "biased", **rules) -> dict:
    return compile_soc_stimulus(plan_fixture(), policy(mode, strategy, **rules))


def mmio_fields(document: dict) -> list:
    segment = next(item for item in document["raw_layout"]["segments"] if item["segment_id"] == "mmio")
    return [field for field in segment["fields"] if not field["padding"]]


def driver(document: dict, driver_id: str = "fuzz_mmio_master") -> dict:
    by_id = {entry["driver_id"]: entry for entry in document["drivers"]}
    return by_id[driver_id]


def witness(document: dict, name: str) -> dict:
    by_name = {entry["name"]: entry for entry in document["address_strategy"]["witnesses"]}
    return by_name[name]


def error_class(document: dict, error_id: str) -> dict:
    by_id = {entry["error_id"]: entry for entry in document["error_recording"]["classes"]}
    return by_id[error_id]


def field_table(document: dict) -> list:
    """The shared raw field table with the per-mode mask flags removed."""
    table = []
    for segment in document["raw_layout"]["segments"]:
        table.append({
            "segment_id": segment["segment_id"],
            "base_bit": segment["base_bit"],
            "bit_width": segment["bit_width"],
            "fields": [
                {key: value for key, value in field.items()
                 if key not in ("mode_masked", "mode_mask_reason")}
                for field in segment["fields"]
            ],
        })
    return table


class _DocumentedDriver:
    """Applies the state-machine rules recorded in the document, literally.

    Every rule is read from the document, so a missing latch, accept, drop or
    completion rule fails the test instead of being silently assumed.
    """

    def __init__(self, driver_document: dict) -> None:
        machine = driver_document["state_machine"]
        self.accept = machine["accept"]
        self.drop = machine["drop"]
        self.complete = machine["complete"]
        self.busy_states = tuple(machine["busy_states"])
        self.latched_fields = tuple(machine["latch"]["fields"])
        self.state = machine["initial_state"]
        self.latch = None
        self.busy_drop_count = 0
        self.completions = 0

    def cycle(self, offer=None, response=None, *, req_ready: bool = False):
        if self.state == "idle":
            if offer is not None:
                assert self.accept["state"] == "idle", "accept must be an idle-state rule"
                self.latch = {name: offer[name] for name in self.latched_fields}
                self.state = self.accept["next_state"]
        else:
            assert self.state in self.busy_states, "busy state must be declared"
            if offer is not None:
                assert self.drop["condition"] == "offer", "busy drop must trigger on the offer field"
                self.busy_drop_count += self.drop["increment"]
            if self.state == "request" and req_ready:
                self.state = "response"
            elif self.state == "response" and response is not None:
                assert self.complete["completions_per_accepted"] == 1
                self.completions += 1
                self.state = self.complete["next_state"]
                self.latch = None
        return self.latch


# ---------------------------------------------------------------------------
# frozen contract
# ---------------------------------------------------------------------------


class SocStimulusContractTests(unittest.TestCase):
    def test_document_passes_the_frozen_contract_in_every_mode_and_strategy(self) -> None:
        plan = plan_fixture()
        for mode in SOC_MODES:
            for strategy in ("bias_off", "biased"):
                with self.subTest(mode=mode, strategy=strategy):
                    document = compile_soc_stimulus(plan, policy(mode, strategy))
                    self.assertIsNone(validate_soc_stimulus(document))
                    self.assertEqual(document["schema_version"], STIMULUS_SCHEMA)
                    self.assertEqual(document["mode"], mode)
                    self.assertEqual(document["mode_selection"]["selected_at"], "test_begin")
                    self.assertEqual(document["plan_hash"], soc_plan_hash(plan))

    def test_layout_has_the_three_fixed_segments_in_order(self) -> None:
        for mode in SOC_MODES:
            with self.subTest(mode=mode):
                layout = compile_document(mode)["raw_layout"]
                self.assertEqual(
                    [segment["segment_id"] for segment in layout["segments"]],
                    ["instruction", "mmio", "environment"],
                )
                self.assertEqual(
                    layout["total_bits"],
                    sum(segment["bit_width"] for segment in layout["segments"]),
                )
                # segments are contiguous, word aligned and never overlap
                cursor = 0
                for segment in layout["segments"]:
                    self.assertEqual(segment["base_bit"], cursor)
                    self.assertEqual(segment["bit_width"] % 32, 0)
                    self.assertGreater(segment["bit_width"], 0)
                    cursor += segment["bit_width"]
                self.assertEqual(cursor, layout["total_bits"])

    def test_every_field_offset_width_padding_and_mapping_is_explicit(self) -> None:
        layout = compile_document()["raw_layout"]
        for segment in layout["segments"]:
            self.assertTrue(segment["fields"])
            for field in segment["fields"]:
                self.assertIn("lsb", field)
                self.assertIn("width", field)
                self.assertIsInstance(field["padding"], bool)
                self.assertIsInstance(field["validity_bit"], bool)
                self.assertIn("encoding", field)
                self.assertIn("values", field)
                self.assertIn("consumed_when", field)
                self.assertEqual(field["bit_offset"], segment["base_bit"] + field["lsb"])
                self.assertLessEqual(field["lsb"] + field["width"], segment["bit_width"])
                for other in segment["fields"]:
                    if other is field:
                        continue
                    self.assertFalse(
                        field["lsb"] < other["lsb"] + other["width"]
                        and other["lsb"] < field["lsb"] + field["width"],
                        f"{field['name']} overlaps {other['name']}",
                    )

    def test_mmio_segment_exposes_exactly_the_driver_fields(self) -> None:
        document = compile_document()
        fields = mmio_fields(document)
        self.assertEqual(tuple(field["name"] for field in fields), MMIO_FIELDS)
        segment = next(
            item for item in document["raw_layout"]["segments"] if item["segment_id"] == "mmio"
        )
        by_name = {field["name"]: field for field in segment["fields"]}
        self.assertEqual(by_name["offer"]["lsb"], 0)
        self.assertEqual(by_name["offer"]["width"], 1)
        self.assertTrue(by_name["offer"]["validity_bit"])
        self.assertEqual(by_name["target_selector"]["lsb"], 1)
        self.assertEqual(by_name["offset"]["lsb"], 1 + by_name["target_selector"]["width"])
        self.assertEqual(by_name["offset"]["width"], 32)
        self.assertEqual(by_name["write"]["lsb"], by_name["offset"]["lsb"] + 32)
        self.assertEqual(by_name["write"]["width"], 1)
        self.assertEqual(by_name["wdata"]["lsb"], by_name["write"]["lsb"] + 1)
        self.assertEqual(by_name["wdata"]["width"], 32)
        self.assertEqual(by_name["be"]["lsb"], by_name["wdata"]["lsb"] + 32)
        self.assertEqual(by_name["be"]["width"], 4)
        # reserved bits keep a defined mapping instead of being claimed as data
        reserved = [field for field in segment["fields"] if field["padding"]]
        self.assertEqual(len(reserved), 1)
        self.assertEqual(reserved[0]["lsb"] + reserved[0]["width"], segment["bit_width"])

    def test_selector_enumeration_lists_every_target_plus_the_invalid_value(self) -> None:
        document = compile_document()
        selector = document["address_strategy"]["target_selector"]
        windows = document["address_strategy"]["windows"]
        self.assertEqual([entry["target_id"] for entry in windows], list(WINDOW_ORDER))
        self.assertEqual(selector["field"], "mmio/target_selector")
        self.assertEqual(selector["invalid_value"], len(windows))
        values = {entry["value"]: entry for entry in selector["values"]}
        self.assertEqual(sorted(values), list(range(len(windows) + 1)))
        for index, window in enumerate(windows):
            self.assertEqual(values[index]["target_id"], window["target_id"])
            self.assertEqual(values[index]["name"], window["target_id"])
        self.assertIsNone(values[selector["invalid_value"]]["target_id"])
        self.assertEqual(values[selector["invalid_value"]]["name"], "invalid")
        self.assertLess(selector["invalid_value"], 1 << selector["width"])

    def test_mode_masking_is_recorded_per_entry_with_a_reason(self) -> None:
        expected = {
            "cpu_only": {"mmio"},
            "mmio_only": {"instruction"},
            "mixed": set(),
        }
        for mode, masked_segments in expected.items():
            with self.subTest(mode=mode):
                document = compile_document(mode)
                masking = document["mode_masking"]
                self.assertEqual(masking["mode"], mode)
                self.assertEqual(set(masking["masked_segments"]), masked_segments)
                for segment in document["raw_layout"]["segments"]:
                    for field in segment["fields"]:
                        if field["padding"]:
                            self.assertFalse(field["mode_masked"])
                            continue
                        if segment["segment_id"] in masked_segments:
                            self.assertTrue(field["mode_masked"])
                            self.assertTrue(field["mode_mask_reason"])
                        else:
                            self.assertFalse(field["mode_masked"])
                            self.assertIsNone(field["mode_mask_reason"])
                for segment in document["raw_layout"]["segments"]:
                    self.assertGreater(segment["bit_width"], 0)
                    for field in segment["fields"]:
                        self.assertGreater(field["width"], 0)
                        self.assertIn("consumed_when", field)

    def test_every_segment_is_consumed_by_exactly_one_bounded_driver(self) -> None:
        document = compile_document()
        consumption = {entry["segment_id"]: entry for entry in document["consumption"]}
        self.assertEqual(set(consumption), {"instruction", "mmio", "environment"})
        for entry in consumption.values():
            self.assertEqual(entry["latch_policy"], "latch_until_completion")
            self.assertEqual(entry["busy_policy"], "deterministic_drop_counted")
            self.assertEqual(entry["max_pending"], 1)
            self.assertEqual(entry["queue_depth"], 0)


# ---------------------------------------------------------------------------
# three modes share one field table
# ---------------------------------------------------------------------------


class SocStimulusModeLayoutTests(unittest.TestCase):
    def test_the_three_modes_share_one_field_table(self) -> None:
        documents = {mode: compile_document(mode) for mode in SOC_MODES}
        baseline = field_table(documents["mixed"])
        for mode in ("cpu_only", "mmio_only"):
            with self.subTest(mode=mode):
                self.assertEqual(field_table(documents[mode]), baseline)
                self.assertEqual(
                    documents[mode]["raw_layout"]["total_bits"],
                    documents["mixed"]["raw_layout"]["total_bits"],
                )
        # the only per-mode field difference is the recorded mask
        for mode in ("cpu_only", "mmio_only"):
            with self.subTest(mode=mode):
                for segment in documents[mode]["raw_layout"]["segments"]:
                    other = next(
                        item for item in documents["mixed"]["raw_layout"]["segments"]
                        if item["segment_id"] == segment["segment_id"]
                    )
                    def unmasked(fields):
                        return [
                            {k: v for k, v in field.items()
                             if k not in ("mode_masked", "mode_mask_reason")}
                            for field in fields
                        ]
                    self.assertEqual(unmasked(segment["fields"]), unmasked(other["fields"]))

    def test_a_changed_mode_changes_the_layout_hash(self) -> None:
        hashes = {mode: compile_document(mode)["layout_hash"] for mode in SOC_MODES}
        self.assertEqual(len(set(hashes.values())), len(SOC_MODES))
        for value in hashes.values():
            self.assertRegex(value, HASH_RE)
        self.assertEqual(hashes["mixed"], compile_document("mixed")["layout_hash"])


# ---------------------------------------------------------------------------
# driver semantics
# ---------------------------------------------------------------------------


class SocStimulusDriverSemanticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = compile_document()
        self.driver = driver(self.document)

    def test_state_machine_is_idle_request_response(self) -> None:
        machine = self.driver["state_machine"]
        self.assertEqual(machine["states"], ["idle", "request", "response"])
        self.assertEqual(machine["initial_state"], "idle")
        self.assertEqual(machine["busy_states"], ["request", "response"])
        self.assertEqual(machine["accept"]["state"], "idle")
        self.assertEqual(machine["accept"]["next_state"], "request")
        self.assertEqual(machine["accept"]["trigger_field"], "offer")
        self.assertEqual(machine["complete"]["condition"], "rsp_valid && rsp_ready")
        self.assertEqual(machine["complete"]["completions_per_accepted"], 1)
        self.assertEqual(machine["complete"]["next_state"], "idle")
        self.assertEqual(machine["max_pending"], 1)
        self.assertEqual(machine["queue_depth"], 0)

    def test_every_consumed_payload_field_is_latched_until_completion(self) -> None:
        machine = self.driver["state_machine"]
        self.assertEqual(tuple(machine["latch"]["fields"]), MMIO_LATCHED)
        self.assertEqual(machine["latch"]["until"], "completion")
        self.assertEqual(machine["latch"]["raw_input_sampled_in"], ["idle"])
        consumed = tuple(
            field["name"] for field in mmio_fields(self.document) if field["name"] != "offer"
        )
        self.assertEqual(tuple(machine["latch"]["fields"]), consumed)

    def test_idle_accepts_a_and_a_later_offer_b_does_not_change_the_latched_fields(self) -> None:
        machine = _DocumentedDriver(self.driver)
        offer_a = {"target_selector": 1, "offset": 0x40000004, "write": True,
                   "wdata": 0xCAFEBABE, "be": 0xF}
        offer_b = {"target_selector": 2, "offset": 0x50000008, "write": False,
                   "wdata": 0x0BADF00D, "be": 0x3}

        # idle accepts A and latches every payload field
        machine.cycle(offer=offer_a)
        self.assertEqual(machine.latch, offer_a)
        self.assertEqual(machine.state, "request")

        # new raw bits B while stalled must not change the in-flight transaction
        for _ in range(3):
            latched = machine.cycle(offer=offer_b)
            self.assertEqual(latched, offer_a)
        self.assertEqual(machine.busy_drop_count, 3)
        self.assertEqual(machine.completions, 0)

        # the fabric accepts, the response completes exactly once
        machine.cycle(req_ready=True)
        self.assertEqual(machine.state, "response")
        machine.cycle(offer=offer_b, response={"error": False})
        self.assertEqual(machine.state, "idle")
        self.assertEqual(machine.completions, 1)
        self.assertEqual(machine.busy_drop_count, 4)

        # a second response cannot complete the same transaction again
        machine.cycle(response={"error": False})
        self.assertEqual(machine.completions, 1)

    def test_busy_drop_count_counts_offers_presented_while_busy(self) -> None:
        machine = self.driver["state_machine"]
        drop = machine["drop"]
        self.assertEqual(drop["states"], ["request", "response"])
        self.assertEqual(drop["condition"], "offer")
        self.assertEqual(drop["counter"], "busy_drop_count")
        self.assertEqual(drop["increment"], 1)
        counters = {entry["name"]: entry for entry in self.driver["counters"]}
        self.assertIn("busy_drop_count", counters)
        self.assertEqual(counters["busy_drop_count"]["cleared_by"], "test_reset")
        self.assertTrue(counters["busy_drop_count"]["increments_when"])
        self.assertEqual(self.driver["busy_policy"]["counter"], "busy_drop_count")
        self.assertEqual(self.driver["busy_policy"]["rule"], "deterministic_drop_counted")

        model = _DocumentedDriver(self.driver)
        offer = {"target_selector": 1, "offset": 0x40000004, "write": True,
                 "wdata": 0xCAFEBABE, "be": 0xF}
        model.cycle(offer=offer)
        for expected in range(1, 5):
            model.cycle(offer=offer)
            self.assertEqual(model.busy_drop_count, expected)

    def test_at_most_one_pending_transaction_and_no_queue(self) -> None:
        for entry in self.document["drivers"]:
            with self.subTest(driver=entry["driver_id"]):
                self.assertEqual(entry["max_pending"], 1)
                self.assertEqual(entry["queue_depth"], 0)


# ---------------------------------------------------------------------------
# address strategies
# ---------------------------------------------------------------------------


class SocStimulusAddressStrategyTests(unittest.TestCase):
    def test_plan_owned_participation_masks_mmio_when_mode_omits_fuzz_source(self) -> None:
        plan = plan_fixture()
        plan["stimulus"]["modes"]["mixed"]["participants"] = ["cpu_data", "cpu_ifetch"]
        document = compile_soc_stimulus(plan, policy("mixed", "biased"))
        self.assertEqual(["mmio"], document["mode_masking"]["masked_segments"])
        mmio = next(segment for segment in document["raw_layout"]["segments"]
                    if segment["segment_id"] == "mmio")
        self.assertTrue(all(field["mode_masked"] for field in mmio["fields"] if not field["padding"]))
        self.assertIn("does not participate", document["mode_masking"]["segments"]["mmio"]["reason"])

    def test_bias_rule_switch_disables_rewriting_even_when_biased_is_selected(self) -> None:
        document = compile_document(strategy="biased", mmio_reachability_bias=False)
        strategy = document["address_strategy"]
        self.assertEqual("biased", strategy["selected"])
        self.assertEqual("bias_off", strategy["effective"])
        self.assertFalse(strategy["bias_enabled"])
        self.assertEqual(0, document["rtl_projection"]["parameters"]["ADDRESS_STRATEGY"])
        self.assertTrue(any(item["name"] == "raw_address" for item in strategy["witnesses"]))
        self.assertFalse(any(item["name"] == "region_biased_address" for item in strategy["witnesses"]))

    def test_both_strategies_are_recorded_and_selectable(self) -> None:
        for strategy in ("bias_off", "biased"):
            with self.subTest(strategy=strategy):
                document = compile_document(strategy=strategy)
                recorded = document["address_strategy"]
                self.assertEqual(recorded["selected"], strategy)
                self.assertEqual(recorded["options"], ["bias_off", "biased"])
                self.assertIn(strategy, recorded["rules"])
                self.assertEqual(recorded["address_field"], "mmio/offset")
                self.assertEqual(recorded["selector_field"], "mmio/target_selector")
        self.assertEqual(
            compile_document(strategy="bias_off")["address_strategy"]["selected"], "bias_off"
        )

    def test_bias_off_uses_the_raw_address_bits_without_region_bias(self) -> None:
        document = compile_document(strategy="bias_off")
        recorded = document["address_strategy"]
        self.assertFalse(recorded["bias_off"]["region_bias"])
        self.assertEqual(recorded["bias_off"]["mask"], (1 << recorded["address_width"]) - 1)
        raw = witness(document, "raw_address")
        self.assertEqual(raw["kind"], "request")
        self.assertEqual(raw["outcome"]["result"], "request")
        self.assertEqual(
            raw["outcome"]["address"],
            raw["offer"]["offset"] & ((1 << recorded["address_width"]) - 1),
        )
        window = next(
            item for item in recorded["windows"] if item["target_id"] == raw["outcome"]["target_id"]
        )
        self.assertLess(raw["outcome"]["address"], window["base"] + window["size"])
        self.assertGreaterEqual(raw["outcome"]["address"], window["base"])

    def test_a_biased_draw_lands_inside_a_declared_window(self) -> None:
        document = compile_document(strategy="biased")
        recorded = document["address_strategy"]
        self.assertTrue(recorded["biased"]["region_bias"])
        biased = witness(document, "region_biased_address")
        self.assertEqual(biased["kind"], "request")
        outcome = biased["outcome"]
        self.assertEqual(outcome["result"], "request")
        window = next(item for item in recorded["windows"] if item["target_id"] == outcome["target_id"])
        self.assertGreaterEqual(outcome["address"], window["base"])
        self.assertLess(outcome["address"], window["base"] + window["size"])
        # the recorded rule is exactly base + (raw offset modulo the window size)
        self.assertEqual(
            outcome["address"],
            window["base"] + (biased["offer"]["offset"] & (window["size"] - 1)),
        )
        # a raw offset far outside the window still resolves inside it
        self.assertGreaterEqual(biased["offer"]["offset"], window["size"])

    def test_the_two_strategies_share_the_protocol_base_state(self) -> None:
        raw = compile_document(strategy="bias_off")
        biased = compile_document(strategy="biased")
        for key in ("raw_layout", "mode_masking", "drivers", "consumption",
                    "error_recording", "reset_semantics"):
            with self.subTest(key=key):
                self.assertEqual(raw[key], biased[key])
        self.assertNotEqual(raw["address_strategy"], biased["address_strategy"])
        self.assertNotEqual(raw["layout_hash"], biased["layout_hash"])
        self.assertEqual(
            raw["address_strategy"]["bias_off"], biased["address_strategy"]["bias_off"]
        )
        self.assertEqual(
            raw["address_strategy"]["biased"], biased["address_strategy"]["biased"]
        )


# ---------------------------------------------------------------------------
# recorded errors, never rewrites
# ---------------------------------------------------------------------------


class SocStimulusErrorRecordingTests(unittest.TestCase):
    def test_error_classes_are_recorded_with_a_reason_and_no_retry(self) -> None:
        document = compile_document(strategy="bias_off")
        recording = document["error_recording"]
        self.assertEqual(recording["policy"], "record_no_retry")
        self.assertEqual(recording["retry"], "never")
        self.assertEqual(recording["rewrite"], "forbidden")
        classes = {entry["error_id"]: entry for entry in recording["classes"]}
        for error_id in ("invalid_target_selector", "unmapped_address",
                         "unsupported_source", "unsupported_operation"):
            with self.subTest(error_id=error_id):
                self.assertIn(error_id, classes)
                self.assertTrue(classes[error_id]["reason"])
                self.assertTrue(classes[error_id]["condition"])
                self.assertTrue(classes[error_id]["detected_by"])
                self.assertEqual(classes[error_id]["side_effects"], "none")
        completion = recording["completion_on_error"]
        self.assertTrue(completion["rsp_error"])
        self.assertEqual(completion["rdata"], 0)
        self.assertEqual(completion["side_effects"], "none")

    def test_invalid_selector_is_recorded_and_not_rewritten(self) -> None:
        for strategy in ("bias_off", "biased"):
            with self.subTest(strategy=strategy):
                document = compile_document(strategy=strategy)
                selector = document["address_strategy"]["target_selector"]
                entry = witness(document, "invalid_target_selector")
                self.assertEqual(entry["offer"]["target_selector"], selector["invalid_value"])
                outcome = entry["outcome"]
                self.assertEqual(outcome["result"], "error")
                self.assertEqual(outcome["error_id"], "invalid_target_selector")
                self.assertFalse(outcome["request_issued"])
                self.assertIsNone(outcome["target_id"])
                self.assertIsNone(outcome["address"])
                self.assertEqual(outcome["side_effects"], "none")
                self.assertEqual(
                    error_class(document, "invalid_target_selector")["detected_by"],
                    "fuzz_mmio_master",
                )

    def test_unmapped_address_is_recorded_and_not_rounded_into_a_window(self) -> None:
        document = compile_document(strategy="bias_off")
        entry = witness(document, "unmapped_address")
        outcome = entry["outcome"]
        address = entry["offer"]["offset"]
        self.assertEqual(outcome["result"], "error")
        self.assertEqual(outcome["error_id"], "unmapped_address")
        self.assertEqual(outcome["address"], address)
        self.assertIsNone(outcome["target_id"])
        self.assertFalse(outcome["request_issued"])
        for window in document["address_strategy"]["windows"]:
            self.assertFalse(
                window["base"] <= address < window["base"] + window["size"],
                f"witness address {address:#x} was silently rounded into {window['target_id']}",
            )

    def test_biased_addressing_cannot_produce_an_unmapped_address(self) -> None:
        document = compile_document(strategy="biased")
        entry = witness(document, "unmapped_address")
        self.assertFalse(entry["possible"])
        self.assertTrue(entry["reason"])

    def test_unsupported_source_and_operation_are_recorded(self) -> None:
        for strategy in ("bias_off", "biased"):
            with self.subTest(strategy=strategy):
                document = compile_document(strategy=strategy)
                source = witness(document, "unsupported_source")
                self.assertEqual(source["outcome"]["result"], "error")
                self.assertEqual(source["outcome"]["error_id"], "unsupported_source")
                self.assertFalse(source["outcome"]["request_issued"])
                operation = witness(document, "unsupported_operation")
                self.assertEqual(operation["outcome"]["result"], "error")
                self.assertEqual(operation["outcome"]["error_id"], "unsupported_operation")
                self.assertFalse(operation["outcome"]["request_issued"])
                self.assertTrue(operation["operation"])

    def test_per_target_operation_facts_come_from_the_plan(self) -> None:
        plan = plan_fixture()
        document = compile_soc_stimulus(plan, policy())
        facts = {entry["target_id"]: entry for entry in document["error_recording"]["target_operations"]}
        self.assertEqual(set(facts), set(WINDOW_ORDER))
        self.assertFalse(facts["rom0_win"]["write"])
        self.assertFalse(facts["rom0_win"]["fuzz_mmio_requester"])
        self.assertFalse(facts["gpio0_win"]["partial_write"])
        self.assertTrue(facts["gpio0_win"]["write"])
        self.assertTrue(facts["uart0_win"]["partial_write"])
        for target_id, entry in facts.items():
            self.assertEqual(
                entry["capabilities"], plan["target_capabilities"][target_id]["capabilities"]
            )


# ---------------------------------------------------------------------------
# reset semantics and CPU isolation
# ---------------------------------------------------------------------------


class SocStimulusResetSemanticsTests(unittest.TestCase):
    def test_cpu_and_peripheral_reset_semantics_are_explicit(self) -> None:
        for mode in SOC_MODES:
            with self.subTest(mode=mode):
                reset = compile_document(mode)["reset_semantics"]
                self.assertEqual(reset["mode"], mode)
                self.assertEqual(
                    reset["cpu_reset"]["held_in_reset_whole_test"], mode == "mmio_only"
                )
                self.assertEqual(reset["cpu_reset"]["released_at"], "test_begin")
                self.assertFalse(reset["peripheral_reset"]["held_in_reset_whole_test"])
                self.assertEqual(reset["peripheral_reset"]["released_at"], "test_begin")
                self.assertTrue(reset["test_reset"]["separate_from_cpu_reset"])
                self.assertTrue(reset["test_reset"]["asserted_at"])
                self.assertIn("driver", reset["test_reset"]["clears"])

    def test_the_mmio_only_cpu_reset_is_not_wired_to_the_peripheral_ip_reset(self) -> None:
        plan = plan_fixture()
        document = compile_soc_stimulus(plan, policy(mode="mmio_only"))
        reset = document["reset_semantics"]
        self.assertTrue(reset["cpu_reset"]["held_in_reset_whole_test"])
        self.assertFalse(reset["peripheral_reset"]["held_in_reset_whole_test"])
        wiring = reset["reset_wiring"]
        self.assertFalse(wiring["cpu_reset_wired_to_peripheral_ip_reset"])
        self.assertFalse(wiring["peripheral_ip_reset_wired_to_cpu_reset"])
        self.assertFalse(wiring["shared_reset_net"])
        self.assertEqual(wiring["cpu_reset_net"], plan["reset"]["cpu_reset"]["name"])
        self.assertEqual(wiring["peripheral_ip_reset_net"], plan["reset"]["test_reset"]["name"])
        self.assertEqual(wiring["cpu_reset_sinks"], plan["reset"]["cpu_reset"]["sinks"])
        self.assertTrue(wiring["cpu_reset_sinks"])
        for sink in wiring["peripheral_ip_reset_sinks"]:
            self.assertNotIn(sink, wiring["cpu_reset_sinks"])
        self.assertTrue(wiring["statement"])

    def test_peripherals_release_reset_in_every_mode(self) -> None:
        for mode in SOC_MODES:
            with self.subTest(mode=mode):
                wiring = compile_document(mode)["reset_semantics"]["reset_wiring"]
                self.assertFalse(wiring["peripheral_ip_held_in_reset_whole_test"])
                self.assertEqual(wiring["peripheral_ip_released_at"], "test_begin")

    def test_cpu_internal_responses_are_never_randomly_driven(self) -> None:
        document = compile_document()
        isolation = document["cpu_isolation"]
        self.assertFalse(isolation["random_drive_cpu_internal_responses"])
        self.assertTrue(isolation["cpu_response_sources"])
        self.assertTrue(isolation["statement"])
        for segment in document["raw_layout"]["segments"]:
            for field in segment["fields"]:
                self.assertNotIn("rsp", field.get("port") or "")
                self.assertNotIn("response", field["name"])


# ---------------------------------------------------------------------------
# determinism and identity
# ---------------------------------------------------------------------------


class SocStimulusDeterminismTests(unittest.TestCase):
    def test_the_same_plan_and_policy_are_byte_identical(self) -> None:
        first = compile_soc_stimulus(plan_fixture(), policy())
        second = compile_soc_stimulus(plan_fixture(), policy())
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )
        self.assertEqual(first["layout_hash"], second["layout_hash"])

    def test_layout_hash_is_the_identity_of_the_whole_document(self) -> None:
        document = compile_document()
        self.assertRegex(document["layout_hash"], HASH_RE)
        without_hash = {key: value for key, value in document.items() if key != "layout_hash"}
        self.assertEqual(document["layout_hash"], content_hash(without_hash))

    def test_a_changed_policy_changes_the_layout_hash(self) -> None:
        baseline = compile_document(mode="mixed", strategy="biased")
        alternatives = (
            compile_document(mode="cpu_only", strategy="biased"),
            compile_document(mode="mmio_only", strategy="biased"),
            compile_document(mode="mixed", strategy="bias_off"),
            compile_document(mode="mixed", strategy="biased", mmio_reachability_bias=False),
        )
        for alternative in alternatives:
            with self.subTest(mode=alternative["mode"], strategy=alternative["address_strategy"]["selected"]):
                self.assertNotEqual(baseline["layout_hash"], alternative["layout_hash"])

    def test_a_changed_plan_changes_the_layout_hash(self) -> None:
        baseline = compile_document()
        changed = copy.deepcopy(plan_fixture())
        entry = next(
            item for item in changed["address_map"]["windows"] if item["target_id"] == "gpio0_win"
        )
        entry["window"]["base"] += 0x1000
        entry["base"] += 0x1000
        fabric_entry = next(
            item for item in changed["fabric"]["decode"]["windows"]
            if item["target_id"] == "gpio0_win"
        )
        fabric_entry["base"] += 0x1000
        fabric_entry["end"] += 0x1000
        fabric_entry["target_base"] += 0x1000
        changed["fabric"]["rtl"]["parameters"]["WINDOW_TARGET_BASE"] = sum(
            item["target_base"] << (index * 32)
            for index, item in enumerate(changed["fabric"]["decode"]["windows"])
        )
        document = compile_soc_stimulus(changed, policy())
        self.assertNotEqual(baseline["plan_hash"], document["plan_hash"])
        self.assertNotEqual(baseline["layout_hash"], document["layout_hash"])

    def test_document_is_json_serializable(self) -> None:
        for mode in SOC_MODES:
            with self.subTest(mode=mode):
                json.dumps(compile_document(mode))

    def test_rule_classes_separate_constraints_from_bias(self) -> None:
        biased = compile_document(strategy="biased")
        raw = compile_document(strategy="bias_off")
        by_id = {entry["rule_id"]: entry for entry in biased["rule_classes"]}
        self.assertEqual(by_id["protocol_base"]["category"], "constraint")
        self.assertTrue(by_id["protocol_base"]["enabled"])
        self.assertEqual(by_id["isa_legal"]["category"], "constraint")
        self.assertEqual(by_id["mmio_reachability_bias"]["category"], "bias")
        self.assertTrue(by_id["mmio_reachability_bias"]["enabled"])
        raw_rules = {entry["rule_id"]: entry for entry in raw["rule_classes"]}
        self.assertFalse(raw_rules["mmio_reachability_bias"]["enabled"])
        cpu_only = compile_document(mode="cpu_only", strategy="biased")
        cpu_rules = {entry["rule_id"]: entry for entry in cpu_only["rule_classes"]}
        self.assertFalse(cpu_rules["mmio_reachability_bias"]["enabled"])


# ---------------------------------------------------------------------------
# RTL projection
# ---------------------------------------------------------------------------


class SocStimulusRtlProjectionTests(unittest.TestCase):
    def test_rtl_projection_matches_the_recorded_layout(self) -> None:
        document = compile_document(strategy="biased")
        projection = document["rtl_projection"]
        self.assertEqual(projection["module"], "fuzz_mmio_master")
        self.assertEqual(
            projection["source"], "src/myfuzz/protocols/rtl/fuzz_mmio_master.sv"
        )
        parameters = projection["parameters"]
        strategy = document["address_strategy"]
        fields = {field["name"]: field for field in mmio_fields(document)}
        self.assertEqual(parameters["ADDRESS_WIDTH"], strategy["address_width"])
        self.assertEqual(parameters["ADDRESS_WIDTH"], fields["offset"]["width"])
        self.assertEqual(parameters["DATA_WIDTH"], fields["wdata"]["width"])
        self.assertEqual(parameters["DATA_WIDTH"] // 8, fields["be"]["width"])
        self.assertEqual(parameters["SELECTOR_WIDTH"], strategy["target_selector"]["width"])
        self.assertEqual(parameters["SELECTOR_INVALID"], strategy["target_selector"]["invalid_value"])
        self.assertEqual(parameters["NUM_WINDOWS"], len(strategy["windows"]))
        self.assertEqual(parameters["ADDRESS_STRATEGY"], 1)
        self.assertEqual(
            parameters["WINDOW_BASE"], [window["base"] for window in strategy["windows"]]
        )
        self.assertEqual(
            parameters["WINDOW_SIZE"], [window["size"] for window in strategy["windows"]]
        )
        self.assertEqual(
            projection["parameters_encoding"]["ADDRESS_STRATEGY"],
            {"bias_off": 0, "biased": 1},
        )
        raw_projection = compile_document(strategy="bias_off")["rtl_projection"]
        self.assertEqual(raw_projection["parameters"]["ADDRESS_STRATEGY"], 0)

    def test_rtl_ports_follow_the_beat_contract(self) -> None:
        ports = compile_document()["rtl_projection"]["ports"]
        for name in ("clk", "reset", "req_valid", "req_ready", "write", "addr", "wdata", "be",
                     "rsp_valid", "rsp_ready", "rdata", "error"):
            with self.subTest(port=name):
                self.assertIn(name, ports)
        self.assertEqual(ports["clk"], "input")
        self.assertEqual(ports["reset"], "input")
        self.assertEqual(ports["req_valid"], "output")
        self.assertEqual(ports["req_ready"], "input")
        self.assertEqual(ports["rsp_valid"], "input")
        self.assertEqual(ports["rsp_ready"], "output")
        self.assertEqual(ports["error"], "input")
        self.assertEqual(ports["busy_drop_count"], "output")
        for field in MMIO_FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"stim_{field}", ports)
                self.assertEqual(ports[f"stim_{field}"], "input")


# ---------------------------------------------------------------------------
# policy and plan validation
# ---------------------------------------------------------------------------


class SocStimulusPolicyValidationTests(unittest.TestCase):
    def reject(self, prefix: str, plan=None, policy_document=None) -> SocStimulusError:
        with self.assertRaises(SocStimulusError) as raised:
            compile_soc_stimulus(
                plan_fixture() if plan is None else plan,
                {"mode": "mixed", "address_strategy": "biased"}
                if policy_document is None else policy_document,
            )
        self.assertTrue(
            str(raised.exception).startswith(prefix), f"{raised.exception} !~ {prefix}"
        )
        return raised.exception

    def test_invalid_plan_rejected(self) -> None:
        self.reject("invalid-plan", plan=[])
        broken = plan_fixture()
        del broken["address_map"]
        self.reject("invalid-plan", plan=broken)

    def test_policy_object_required(self) -> None:
        self.reject("invalid-policy", policy_document=[])

    def test_missing_policy_key_rejected(self) -> None:
        self.reject("missing-policy-key:mode", policy_document={"address_strategy": "biased"})
        self.reject("missing-policy-key:address_strategy", policy_document={"mode": "mixed"})

    def test_unknown_policy_key_rejected(self) -> None:
        self.reject(
            "unknown-policy-key:random_seed",
            policy_document={"mode": "mixed", "address_strategy": "biased", "random_seed": 1},
        )

    def test_invalid_policy_field_rejected(self) -> None:
        self.reject(
            "invalid-policy-field:address_strategy",
            policy_document={"mode": "mixed", "address_strategy": "biased_always"},
        )
        self.reject(
            "invalid-policy-field:mode",
            policy_document={"mode": "fuzz_only", "address_strategy": "biased"},
        )

    def test_mode_not_declared_by_the_plan_rejected(self) -> None:
        plan = plan_fixture()
        plan["stimulus"] = dict(plan["stimulus"], available_modes=["mixed"])
        self.reject(
            "mode-not-declared:mmio_only",
            plan=plan,
            policy_document={"mode": "mmio_only", "address_strategy": "biased"},
        )

    def test_non_power_of_two_window_rejected_for_biased_addressing(self) -> None:
        plan = copy.deepcopy(plan_fixture())
        plan["address_map"]["windows"][0]["window"]["size"] = 0x1800
        self.reject(
            "unsupported-address-strategy",
            plan=plan,
            policy_document={"mode": "mixed", "address_strategy": "biased"},
        )
        # the same plan is still usable with bias_off, which never masks by size
        document = compile_soc_stimulus(
            plan, {"mode": "mixed", "address_strategy": "bias_off"}
        )
        self.assertEqual(document["address_strategy"]["selected"], "bias_off")

    def test_rule_switches_are_validated(self) -> None:
        self.reject(
            "unknown-rule-id:event_rate",
            policy_document={"mode": "mixed", "address_strategy": "biased",
                             "rules": {"event_rate": True}},
        )
        self.reject(
            "unsupported-rule-disable:protocol_base",
            policy_document={"mode": "mixed", "address_strategy": "biased",
                             "rules": {"protocol_base": False}},
        )
        document = compile_soc_stimulus(
            plan_fixture(),
            {"mode": "mixed", "address_strategy": "biased", "rules": {"isa_legal": False}},
        )
        rules = {entry["rule_id"]: entry for entry in document["rule_classes"]}
        self.assertFalse(rules["isa_legal"]["enabled"])


if __name__ == "__main__":
    unittest.main()
