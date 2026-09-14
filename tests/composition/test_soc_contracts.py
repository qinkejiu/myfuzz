"""P3 contract tests: soc_spec.v1, soc_plan.v1 and soc_stimulus.v1.

Every rejection reason required by the P3 task is covered by a dedicated test:

===========================  ============================================
reason prefix                covering test
===========================  ============================================
missing-field:               test_missing_required_field_rejected
invalid-field:               test_wrong_type_rejected
overlapping-memory-regions   test_overlapping_memory_regions_rejected
duplicate-source-id          test_duplicate_source_id_rejected
duplicate-input-driver       test_duplicate_input_driver_rejected
unknown-source-id            test_unknown_source_id_rejected
missing-target-requester     test_empty_request_sources_rejected
invalid-response-owner       test_invalid_response_owner_rejected
duplicate-response-driver    test_duplicate_response_driver_rejected
writable-rom                 test_writable_rom_rejected
conflicting-physical-memory  test_conflicting_physical_memory_rejected
cross-clock-without-adapter  test_cross_clock_without_adapter_rejected
overlapping-target-windows   test_overlapping_target_windows_rejected
unsupported-partial-write    test_unsupported_partial_write_rejected
unknown-source-lock          test_unknown_source_lock_rejected
mode-not-declared            test_mode_not_declared_rejected
===========================  ============================================

The hash tests pin both directions of the requirement: permuting every list and
reordering every object key must not change the digest, while changing a
protocol tuple, a base/size, a permission, an initialization policy or a
master/target binding must change it.
"""
from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path

from myfuzz.composition.soc_contracts import (
    SOC_PLAN_SCHEMA,
    SOC_SPEC_SCHEMA,
    SOC_STIMULUS_SCHEMA,
    SocContractError,
    soc_plan_hash,
    soc_spec_hash,
    validate_soc_plan,
    validate_soc_spec,
    validate_soc_stimulus,
)
from myfuzz.composition.soc_plan import build_soc_plan

try:  # jsonschema is present in the dev environment; the schema checks skip without it.
    import jsonschema
except ImportError:  # pragma: no cover - exercised only on minimal installs.
    jsonschema = None

REPO_ROOT = Path(__file__).resolve().parents[2]
HASH_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

LOCK_IDS = (
    "ibex",
    "opentitan_uart",
    "soc_clock_reset_harness",
    "soc_ram_model",
    "soc_rom_model",
)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def spec_fixture() -> dict:
    """A small but complete single-clock SoC: CPU + RAM + ROM + TL-UL UART."""
    return {
        "schema_version": "soc_spec.v1",
        "spec_id": "ibex-opentitan-smoke",
        "components": [
            {
                "component_id": "cpu",
                "kind": "cpu",
                "source_lock": "ibex",
                "top_module": "ibex_top",
                "clock_domain": "core",
                "reset_domain": "cpu_rst",
                "instances": [{"instance_id": "cpu0", "parameters": {"RV32M": 1, "PMPEnable": 0}}],
                "capability_evidence": {
                    "isa": "rv32imc",
                    "provenance": "configs/soc/sources.lock.json#/components/0/interface_description",
                },
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
                    "provenance": "configs/soc/families/opentitan.json#/peripherals/0",
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
                "base": 0x80000000,
                "size": 0x10000,
                "permissions": {"read": True, "write": True, "execute": True},
                "physical_memory_id": "sram0",
                "initialization_policy": "on_demand",
            },
            {
                "region_id": "rom0_code",
                "component_id": "rom",
                "base": 0x00010000,
                "size": 0x8000,
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
                "target_id": "ram0_win",
                "component_id": "ram",
                "port": "sram",
                "protocol": ["ready-valid-memory", "1"],
                "window": {"base": 0x80000000, "size": 0x10000},
                "request_sources": ["cpu_data", "fuzz_mmio"],
                "response_owner": "cpu_data",
                "byte_enable": True,
            },
            {
                "target_id": "rom0_win",
                "component_id": "rom",
                "port": "rom",
                "protocol": ["ready-valid-memory", "1"],
                "window": {"base": 0x00010000, "size": 0x8000},
                "request_sources": ["cpu_ifetch"],
                "response_owner": "cpu_ifetch",
                "byte_enable": False,
            },
            {
                "target_id": "uart0_win",
                "component_id": "uart",
                "port": "tl",
                "protocol": ["tl-ul", "1"],
                "window": {"base": 0x40000000, "size": 0x1000},
                "request_sources": ["cpu_data", "fuzz_mmio"],
                "response_owner": "cpu_data",
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
                "provenance": "configs/soc/families/opentitan.json#/peripherals/0/clock_policy",
            }
        ],
        "provenance": {
            "components": "configs/soc/sources.lock.json",
            "memory_regions": "configs/soc/board.json",
        },
    }


def target_contracts_fixture() -> list:
    return [
        {
            "target_id": "ram0_win",
            "component_id": "ram",
            "port": "sram",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": "beat_to_ram",
            "adapter_source": "protocols/rtl/beat_to_ram.sv",
            "capabilities": {"partial_write": True, "read": True, "write": True, "max_wait_cycles": 16},
            "evidence": {
                "provenance": "configs/soc/families/pulp.json#/peripherals/0/capabilities/0",
                "runtime_status": "runtime_unverified",
            },
        },
        {
            "target_id": "rom0_win",
            "component_id": "rom",
            "port": "rom",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": "beat_to_rom",
            "adapter_source": "protocols/rtl/beat_to_rom.sv",
            "capabilities": {"partial_write": False, "read": True, "write": False, "max_wait_cycles": 2},
            "evidence": {
                "provenance": "configs/soc/families/zipcpu.json#/peripherals/1/capabilities/0",
                "runtime_status": "runtime_unverified",
            },
        },
        {
            "target_id": "uart0_win",
            "component_id": "uart",
            "port": "tl",
            "protocol": ["tl-ul", "1"],
            "adapter_module": "beat_to_tlul",
            "adapter_source": "protocols/rtl/beat_to_tlul.sv",
            "capabilities": {
                "partial_write": True,
                "read": True,
                "write": True,
                "integrity": False,
                "alert": False,
            },
            "evidence": {
                "provenance": "configs/soc/families/opentitan.json#/peripherals/0/capabilities/0",
                "source_sha256": "1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef",
            },
        },
    ]


def processor_execution_fixture() -> dict:
    return {
        "schema_version": "processor_execution.v1",
        "adapter_sources": ["protocols/rtl/obi_to_beat.sv"],
        "classification": None,
        "routes": [
            {
                "route_id": 11,
                "function": "instruction_memory_master",
                "source_protocol": ["obi", "1"],
                "target_protocol": ["processor-memory-beat", "1"],
                "adapter_id": "obi_beat_i",
                "rtl_module": "obi_to_beat",
                "rtl_source": "protocols/rtl/obi_to_beat.sv",
                "parameters": {"ADDR_WIDTH": 32},
                "widths": {"addr": 32, "data": 32},
                "field_connections": [],
                "extension_policies": [],
                "reset_contract": {"polarity": "active_low", "synchrony": "sync"},
                "backend_contract": {"max_outstanding": 1},
            },
            {
                "route_id": 12,
                "function": "data_memory_master",
                "source_protocol": ["obi", "1"],
                "target_protocol": ["processor-memory-beat", "1"],
                "adapter_id": "obi_beat_d",
                "rtl_module": "obi_to_beat",
                "rtl_source": "protocols/rtl/obi_to_beat.sv",
                "parameters": {"ADDR_WIDTH": 32},
                "widths": {"addr": 32, "data": 32},
                "field_connections": [],
                "extension_policies": [],
                "reset_contract": {"polarity": "active_low", "synchrony": "sync"},
                "backend_contract": {"max_outstanding": 1},
            },
        ],
        "execution_hash": "sha256:" + "a" * 64,
    }


def stimulus_fixture(plan: dict, mode: str = "mixed") -> dict:
    held = mode == "mmio_only"
    return {
        "schema_version": "soc_stimulus.v1",
        "plan_hash": soc_plan_hash(plan),
        "mode": mode,
        "mode_selection": {"selected_at": "test_begin", "source": "soc_plan.v1#/stimulus"},
        "raw_layout": {
            "version": "soc_raw_layout.v1",
            "total_bits": 512,
            "segments": [
                {
                    "segment_id": "instruction",
                    "base_bit": 0,
                    "bit_width": 256,
                    "fields": [
                        {"name": "init_address", "lsb": 0, "width": 32, "role": "address", "padding": False},
                        {"name": "init_data", "lsb": 32, "width": 64, "role": "data", "padding": False},
                        {"name": "init_valid", "lsb": 96, "width": 1, "role": "valid", "padding": False},
                        {"name": "init_padding", "lsb": 97, "width": 159, "role": "padding", "padding": True},
                    ],
                },
                {
                    "segment_id": "mmio",
                    "base_bit": 256,
                    "bit_width": 128,
                    "fields": [
                        {"name": "offer", "lsb": 0, "width": 1, "role": "valid", "padding": False},
                        {"name": "target_selector", "lsb": 1, "width": 4, "role": "target_selector", "padding": False},
                        {"name": "offset", "lsb": 5, "width": 16, "role": "address", "padding": False},
                        {"name": "write", "lsb": 21, "width": 1, "role": "write", "padding": False},
                        {"name": "wdata", "lsb": 22, "width": 32, "role": "data", "padding": False},
                        {"name": "be", "lsb": 54, "width": 4, "role": "byte_enable", "padding": False},
                        {"name": "mmio_padding", "lsb": 58, "width": 70, "role": "padding", "padding": True},
                    ],
                },
                {
                    "segment_id": "environment",
                    "base_bit": 384,
                    "bit_width": 128,
                    "fields": [
                        {"name": "uart_rx", "lsb": 0, "width": 1, "role": "pin", "padding": False},
                        {"name": "spi_miso", "lsb": 1, "width": 1, "role": "pin", "padding": False},
                        {"name": "env_padding", "lsb": 2, "width": 126, "role": "padding", "padding": True},
                    ],
                },
            ],
        },
        "rule_classes": [
            {"rule_id": "protocol_base", "class": "protocol_base", "category": "constraint", "enabled": True},
            {"rule_id": "isa_legal", "class": "isa_legal", "category": "constraint", "enabled": True},
            {
                "rule_id": "mmio_reachability_bias",
                "class": "mmio_reachability_bias",
                "category": "bias",
                "enabled": mode != "cpu_only",
            },
        ],
        "consumption": [
            {
                "segment_id": "instruction",
                "driver": "instruction_init",
                "latch_policy": "latch_until_completion",
                "busy_policy": "deterministic_drop_counted",
                "max_pending": 1,
            },
            {
                "segment_id": "mmio",
                "driver": "fuzz_mmio_master",
                "latch_policy": "latch_until_completion",
                "busy_policy": "deterministic_drop_counted",
                "max_pending": 1,
            },
            {
                "segment_id": "environment",
                "driver": "environment_pins",
                "latch_policy": "latch_until_completion",
                "busy_policy": "deterministic_drop_counted",
                "max_pending": 1,
            },
        ],
        "reset_semantics": {
            "mode": mode,
            "cpu_reset": {"held_in_reset_whole_test": held, "released_at": "test_begin"},
            "peripheral_reset": {"held_in_reset_whole_test": False, "released_at": "test_begin"},
            "test_reset": {
                "asserted_at": ["test_begin"],
                "clears": ["cpu", "memory", "peripheral", "driver", "irq", "coverage"],
                "separate_from_cpu_reset": True,
            },
        },
        "provenance": {"plan": "soc_plan.v1#/stimulus", "raw_layout": "P7"},
    }


def permuted(value):
    """Deep copy with every list reversed and every object key reordered."""
    if isinstance(value, dict):
        items = list(value.items())
        items.reverse()
        return {key: permuted(item) for key, item in items}
    if isinstance(value, list):
        return [permuted(item) for item in reversed(value)]
    return copy.deepcopy(value)


# --------------------------------------------------------------------------
# soc_spec.v1 validation
# --------------------------------------------------------------------------


class SocSpecValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = spec_fixture()

    def reject(self, prefix: str, spec=None, **kwargs) -> SocContractError:
        target = self.spec if spec is None else spec
        with self.assertRaises(SocContractError) as raised:
            validate_soc_spec(target, **kwargs)
        message = str(raised.exception)
        self.assertTrue(message.startswith(prefix), f"{message!r} does not start with {prefix!r}")
        # the reason is a stable token and the message is exactly reason[:pointer]
        self.assertTrue(raised.exception.reason)
        self.assertNotIn(":", raised.exception.reason)
        pointer = raised.exception.pointer
        self.assertEqual(message, f"{raised.exception.reason}:{pointer}" if pointer else raised.exception.reason)
        return raised.exception

    def test_valid_spec_is_accepted(self) -> None:
        self.assertIsNone(validate_soc_spec(self.spec))
        self.assertIsNone(validate_soc_spec(self.spec, source_lock_ids=LOCK_IDS))

    def test_schema_version_mismatch_rejected(self) -> None:
        self.spec["schema_version"] = "soc_spec.v2"
        error = self.reject("invalid-field:schema_version")
        self.assertEqual(error.pointer, "schema_version")

    def test_missing_required_field_rejected(self) -> None:
        cases = (
            ((), "targets"),
            (("components", 0), "top_module"),
            (("memory_regions", 1), "size"),
            (("masters", 0), "protocol"),
            (("targets", 2), "window"),
            (("targets", 2, "window"), "size"),
            (("resources",), "limits"),
            (("resources",), "clock_adapters"),
        )
        for path, field in cases:
            with self.subTest(field=field):
                spec = spec_fixture()
                container = spec
                for step in path:
                    container = container[step]
                del container[field]
                error = self.reject("missing-field:", spec)
                self.assertEqual(error.pointer, "/".join(str(step) for step in path + (field,)))

    def test_wrong_type_rejected(self) -> None:
        cases = (
            (("memory_regions", 0), "base", "zero"),
            (("memory_regions", 0, "permissions"), "write", "yes"),
            (("memory_regions", 0), "size", -1),
            (("masters", 0), "protocol", "obi"),
            (("masters", 0), "data_width", True),
            (("targets", 2), "byte_enable", "yes"),
            (("targets", 2), "request_sources", "cpu_data"),
            (("interrupt_routes", 0, "sink"), "irq", "three"),
            (("components", 0, "instances", 0), "parameters", []),
            (("resources", "limits"), "cycles_per_sample", 0),
            (("provenance",), "components", 7),
            (("assumptions", 0), "provenance", {"file": "x"}),
        )
        for path, field, value in cases:
            with self.subTest(field=field):
                spec = spec_fixture()
                container = spec
                for step in path:
                    container = container[step]
                container[field] = value
                self.reject("invalid-field:", spec)

    def test_overlapping_memory_regions_rejected(self) -> None:
        self.spec["memory_regions"].append(
            {
                "region_id": "ram0_alias",
                "component_id": "ram",
                "base": 0x80008000,
                "size": 0x1000,
                "permissions": {"read": True, "write": True, "execute": True},
                "physical_memory_id": "sram0_alias",
                "initialization_policy": "alias",
            }
        )
        self.reject("overlapping-memory-regions")

    def test_conflicting_physical_memory_rejected(self) -> None:
        alias = {
            "region_id": "rom0_alias",
            "component_id": "rom",
            "base": 0x20000000,
            "size": 0x4000,
            "permissions": {"read": True, "write": False, "execute": True},
            "physical_memory_id": "bootrom0",
            "initialization_policy": "rom",
        }
        self.spec["memory_regions"].append(copy.deepcopy(alias))
        self.reject("conflicting-physical-memory", self.spec)

        # Identical attributes at a different base is the legal I/D alias case.
        alias["size"] = 0x8000
        self.spec["memory_regions"][-1] = alias
        self.assertIsNone(validate_soc_spec(self.spec))

        alias["permissions"] = {"read": True, "write": False, "execute": False}
        self.reject("conflicting-physical-memory", self.spec)

    def test_writable_rom_rejected(self) -> None:
        self.spec["memory_regions"][1]["permissions"]["write"] = True
        error = self.reject("writable-rom")
        self.assertEqual(error.pointer, "memory_regions/rom0_code")

    def test_duplicate_source_id_rejected(self) -> None:
        duplicate = copy.deepcopy(self.spec["masters"][0])
        duplicate["port"] = "instr_alt"
        self.spec["masters"].append(duplicate)
        self.reject("duplicate-source-id")

    def test_duplicate_input_driver_rejected(self) -> None:
        duplicate = copy.deepcopy(self.spec["masters"][0])
        duplicate["source_id"] = "cpu_ifetch_alt"
        self.spec["masters"].append(duplicate)
        self.reject("duplicate-input-driver")

    def test_unknown_source_id_rejected(self) -> None:
        self.spec["targets"][2]["request_sources"] = ["cpu_data", "ghost_master"]
        self.reject("unknown-source-id")

    def test_interrupt_sink_unknown_master_rejected(self) -> None:
        self.spec["interrupt_routes"][0]["sink"]["master_id"] = "ghost_master"
        self.reject("unknown-source-id")

    def test_unknown_component_reference_rejected(self) -> None:
        self.spec["targets"][0]["component_id"] = "ghost"
        self.reject("unknown-component-id")

    def test_empty_request_sources_rejected(self) -> None:
        self.spec["targets"][0]["request_sources"] = []
        self.reject("missing-target-requester")

    def test_invalid_response_owner_rejected(self) -> None:
        self.spec["targets"][0]["response_owner"] = "cpu_ifetch"
        self.reject("invalid-response-owner")

    def test_duplicate_response_driver_rejected(self) -> None:
        self.spec["targets"].append(
            {
                "target_id": "uart0_win_hi",
                "component_id": "uart",
                "port": "tl",
                "protocol": ["tl-ul", "1"],
                "window": {"base": 0x40010000, "size": 0x1000},
                "request_sources": ["fuzz_mmio"],
                "response_owner": "fuzz_mmio",
                "byte_enable": True,
            }
        )
        self.reject("duplicate-response-driver")

    def test_cross_clock_without_adapter_rejected(self) -> None:
        self.spec["components"][3]["clock_domain"] = "periph"
        self.spec["resources"]["clock_domains"].append({"name": "periph", "frequency_hz": 25000000})

        # target link crossing core -> periph
        error = self.reject("cross-clock-without-adapter")
        self.assertEqual(error.pointer, "uart0_win")

        # adapter naming the target link clears the target, the interrupt still crosses
        self.spec["resources"]["clock_adapters"] = [{"adapter_id": "cdc_uart0_win", "link_id": "uart0_win"}]
        self.reject("cross-clock-without-adapter")

        # adapter naming the interrupt route clears that too
        self.spec["resources"]["clock_adapters"].append({"adapter_id": "cdc_uart0_irq", "link_id": "uart0_irq"})
        self.assertIsNone(validate_soc_spec(self.spec))

        # an environment link whose peer runs on another domain also needs an adapter
        self.spec["environment_links"][0]["parameters"]["clock_domain"] = "core"
        self.reject("cross-clock-without-adapter")
        self.spec["resources"]["clock_adapters"].append({"adapter_id": "cdc_uart0_pins", "link_id": "uart0_pins"})
        self.assertIsNone(validate_soc_spec(self.spec))

    def test_clock_adapter_naming_unknown_link_rejected(self) -> None:
        self.spec["resources"]["clock_adapters"] = [{"adapter_id": "cdc_ghost", "link_id": "ghost_link"}]
        self.reject("unknown-clock-adapter-link")

    def test_overlapping_target_windows_rejected(self) -> None:
        # target against target
        self.spec["targets"][1]["window"] = {"base": 0x80000000, "size": 0x1000}
        self.reject("overlapping-target-windows")

        # target against a memory region the target's component does not own
        spec = spec_fixture()
        spec["targets"][2]["window"] = {"base": 0x80000000, "size": 0x1000}
        self.reject("overlapping-target-windows", spec)

        # a target owning its own component's region is legal (the fixture already does this)
        self.assertIsNone(validate_soc_spec(spec_fixture()))

    def test_unknown_source_lock_rejected(self) -> None:
        error = self.reject("unknown-source-lock", source_lock_ids=("cva6",))
        self.assertEqual(error.pointer, "components/0/source_lock")

        self.spec["source_locks"] = ["ibex"]
        self.reject("unknown-source-lock")

        self.spec["source_locks"] = list(LOCK_IDS)
        self.assertIsNone(validate_soc_spec(self.spec))

    def test_source_lock_document_accepted(self) -> None:
        self.spec["source_locks"] = {"components": [{"id": lock_id} for lock_id in LOCK_IDS]}
        self.assertIsNone(validate_soc_spec(self.spec))

    def test_mode_not_declared_rejected(self) -> None:
        # the fuzz master is used in mixed, but declares only mmio_only
        self.spec["test_modes"] = ["mixed"]
        self.spec["masters"][2]["test_modes"] = ["mmio_only"]
        self.reject("mode-not-declared")

        # a data master is used in cpu_only, but declares only mixed
        spec = spec_fixture()
        spec["test_modes"] = ["cpu_only"]
        spec["masters"][1]["test_modes"] = ["mixed"]
        self.reject("mode-not-declared", spec)

        # a kind declaring a mode its kind cannot be used in
        spec = spec_fixture()
        spec["masters"][2]["test_modes"] = ["cpu_only", "mixed"]
        self.reject("mode-not-declared", spec)

        # explicit selection argument behaves like the spec field
        spec = spec_fixture()
        spec["masters"][0]["test_modes"] = ["cpu_only"]
        self.reject("mode-not-declared", spec, test_modes=["mixed"])

        # every master declares mixed, so the mode check passes
        spec = spec_fixture()
        spec["test_modes"] = ["mixed"]
        self.assertIsNone(validate_soc_spec(spec))

        # a CPU held in reset is not used in mmio_only, so it need not declare it
        spec = spec_fixture()
        spec["test_modes"] = ["mmio_only"]
        self.assertIsNone(validate_soc_spec(spec))

    def test_empty_test_modes_rejected(self) -> None:
        self.spec["masters"][0]["test_modes"] = []
        self.reject("invalid-field:")


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------


class SocSpecHashTests(unittest.TestCase):
    def test_hash_format(self) -> None:
        self.assertRegex(soc_spec_hash(spec_fixture()), HASH_RE)

    def test_hash_is_permutation_invariant(self) -> None:
        baseline = spec_fixture()
        self.assertNotEqual(baseline, permuted(baseline))
        self.assertEqual(soc_spec_hash(baseline), soc_spec_hash(permuted(baseline)))

    def test_protocol_change_changes_hash(self) -> None:
        baseline = spec_fixture()
        for section, index, value in (("masters", 0, ["obi", "2"]), ("targets", 2, ["tl-ul", "2"])):
            with self.subTest(section=section, index=index):
                spec = spec_fixture()
                spec[section][index]["protocol"] = value
                self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(spec))

    def test_address_map_change_changes_hash(self) -> None:
        baseline = spec_fixture()
        for section, index, field, value in (
            ("memory_regions", 0, "base", 0x80010000),
            ("memory_regions", 0, "size", 0x20000),
            ("targets", 2, "window", {"base": 0x40001000, "size": 0x1000}),
        ):
            with self.subTest(field=field):
                spec = spec_fixture()
                spec[section][index][field] = value
                self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(spec))

    def test_permission_change_changes_hash(self) -> None:
        baseline = spec_fixture()
        spec = spec_fixture()
        spec["memory_regions"][0]["permissions"]["execute"] = False
        self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(spec))

    def test_initialization_policy_change_changes_hash(self) -> None:
        baseline = spec_fixture()
        spec = spec_fixture()
        spec["memory_regions"][0]["initialization_policy"] = "preload"
        self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(spec))

    def test_master_and_target_binding_change_changes_hash(self) -> None:
        baseline = spec_fixture()
        cases = (
            ("request_sources", ["cpu_ifetch"]),
            ("response_owner", "fuzz_mmio"),
            ("component_id", "rom"),
            ("port", "sram_alt"),
            ("byte_enable", False),
        )
        for field, value in cases:
            with self.subTest(field=field):
                spec = spec_fixture()
                spec["targets"][0][field] = value
                self.assertNotEqual(soc_spec_hash(baseline), soc_spec_hash(spec))

    def test_hash_is_stable_and_process_independent(self) -> None:
        spec = spec_fixture()
        self.assertEqual(soc_spec_hash(spec), soc_spec_hash(spec_fixture()))
        # python -R (hash randomisation) must not influence the digest
        self.assertEqual(soc_spec_hash(spec), soc_spec_hash(permuted(spec)))
        self.assertEqual(soc_spec_hash(spec), soc_spec_hash(spec))


# --------------------------------------------------------------------------
# soc_plan.v1
# --------------------------------------------------------------------------


class SocPlanTests(unittest.TestCase):
    def build(self, spec=None, execution=None, contracts=None, **kwargs) -> dict:
        return build_soc_plan(
            spec_fixture() if spec is None else spec,
            processor_execution_fixture() if execution is None else execution,
            target_contracts_fixture() if contracts is None else contracts,
            **kwargs,
        )

    def test_plan_binds_instances_adapters_nets_and_address_map(self) -> None:
        spec = spec_fixture()
        plan = self.build(spec)
        self.assertEqual(plan["schema_version"], SOC_PLAN_SCHEMA)
        self.assertEqual(plan["spec_hash"], soc_spec_hash(spec))
        self.assertEqual(plan["spec_id"], spec["spec_id"])
        self.assertIsNone(validate_soc_plan(plan))

        instances = {(item["component_id"], item["instance_id"]) for item in plan["instances"]}
        self.assertEqual(
            instances,
            {("cpu", "cpu0"), ("ram", "ram0"), ("rom", "rom0"), ("uart", "uart0"), ("harness", "harness0")},
        )
        by_instance = {item["instance_id"]: item for item in plan["instances"]}
        self.assertEqual(by_instance["cpu0"]["top_module"], "ibex_top")
        self.assertEqual(by_instance["cpu0"]["parameters"], {"RV32M": 1, "PMPEnable": 0})

        adapters = {(item["source_id"], item["target_id"], item["module"]) for item in plan["adapters"]}
        self.assertEqual(
            adapters,
            {
                ("cpu_ifetch", "rom0_win", "beat_to_rom"),
                ("cpu_data", "ram0_win", "beat_to_ram"),
                ("fuzz_mmio", "ram0_win", "beat_to_ram"),
                ("cpu_data", "uart0_win", "beat_to_tlul"),
                ("fuzz_mmio", "uart0_win", "beat_to_tlul"),
            },
        )
        for adapter in plan["adapters"]:
            self.assertEqual(adapter["role"], "initiator_to_target")
            self.assertTrue(adapter["adapter_id"])

        windows = {item["target_id"]: item for item in plan["address_map"]["windows"]}
        self.assertEqual(set(windows), {"ram0_win", "rom0_win", "uart0_win"})
        self.assertEqual(windows["uart0_win"]["base"], 0x40000000)
        self.assertEqual(plan["address_map"]["unmapped"]["behavior"], "error")
        self.assertEqual(len(plan["address_map"]["memory_regions"]), 2)

    def test_plan_records_one_driver_per_net_with_evidence(self) -> None:
        plan = self.build()
        net_ids = [net["net_id"] for net in plan["nets"]]
        self.assertEqual(len(net_ids), len(set(net_ids)))
        drivers = {item["net_id"]: item for item in plan["net_drivers"]}
        self.assertEqual(set(drivers), set(net_ids))
        for net_id, record in drivers.items():
            with self.subTest(net_id=net_id):
                self.assertEqual(record["driver_count"], 1)
                self.assertTrue(record["evidence"]["unique"])
                self.assertEqual(record["evidence"]["observed_drivers"], 1)
                self.assertTrue(record["evidence"]["rules"])
        # the uart target is reachable from two masters, but the fabric is its only driver
        uart_net = next(net for net in plan["nets"] if net["net_id"] == "target:uart0_win")
        self.assertEqual(sorted(uart_net["request_sources"]), ["cpu_data", "fuzz_mmio"])
        self.assertEqual(uart_net["driver"]["role"], "fabric")
        self.assertEqual(uart_net["response_owner"], "cpu_data")

    def test_plan_keeps_cpu_and_test_reset_separate(self) -> None:
        plan = self.build()
        reset = plan["reset"]
        self.assertEqual(reset["cpu_reset"]["domain"], "cpu_rst")
        self.assertEqual(reset["cpu_reset"]["sinks"], ["cpu0"])
        self.assertNotEqual(reset["cpu_reset"]["name"], reset["test_reset"]["name"])
        self.assertEqual(reset["test_reset"]["domain"], "sys_rst")
        self.assertEqual(
            sorted(item["instance_id"] for item in plan["instances"]),
            sorted(reset["test_reset"]["sinks"]),
        )
        for state in ("memory", "peripheral", "driver", "irq", "coverage", "cpu"):
            self.assertIn(state, reset["test_reset"]["clears"])
        self.assertTrue(reset["test_reset"]["independent_of_cpu_reset"])

    def test_plan_records_modes_and_reset_semantics(self) -> None:
        plan = self.build()
        stimulus = plan["stimulus"]
        self.assertEqual(stimulus["mode_selection"], "test_begin")
        self.assertIsNone(stimulus["selected_mode"])
        self.assertEqual(set(stimulus["modes"]), {"cpu_only", "mmio_only", "mixed"})
        self.assertEqual(sorted(stimulus["modes"]["cpu_only"]["participants"]), ["cpu_data", "cpu_ifetch"])
        self.assertEqual(stimulus["modes"]["mmio_only"]["participants"], ["fuzz_mmio"])
        self.assertEqual(
            sorted(stimulus["modes"]["mixed"]["participants"]),
            ["cpu_data", "cpu_ifetch", "fuzz_mmio"],
        )
        self.assertTrue(stimulus["modes"]["mmio_only"]["cpu_reset"]["held_in_reset_whole_test"])
        self.assertFalse(stimulus["modes"]["mmio_only"]["peripheral_reset"]["held_in_reset_whole_test"])
        for mode in ("cpu_only", "mixed"):
            self.assertFalse(stimulus["modes"][mode]["cpu_reset"]["held_in_reset_whole_test"])
        self.assertTrue(stimulus["modes"]["mixed"]["test_reset"]["clears"])

    def test_plan_selected_mode_is_validated(self) -> None:
        plan = self.build(test_mode="mmio_only")
        self.assertEqual(plan["stimulus"]["selected_mode"], "mmio_only")
        self.assertEqual(plan["stimulus"]["available_modes"], ["cpu_only", "mmio_only", "mixed"])

        # a pinned spec rejects selecting a mode it was not configured for
        pinned = spec_fixture()
        pinned["test_modes"] = ["mixed"]
        with self.assertRaises(SocContractError) as raised:
            self.build(spec=pinned, test_mode="cpu_only")
        self.assertTrue(str(raised.exception).startswith("mode-not-declared:"))

        # a mode nobody can drive is rejected rather than silently empty
        fuzzless = spec_fixture()
        fuzzless["masters"] = [m for m in fuzzless["masters"] if m["kind"] != "fuzz_mmio"]
        fuzzless["targets"][0]["request_sources"] = ["cpu_data"]
        fuzzless["targets"][2]["request_sources"] = ["cpu_data"]
        with self.assertRaises(SocContractError) as raised:
            self.build(spec=fuzzless, test_mode="mmio_only")
        self.assertTrue(str(raised.exception).startswith("mode-not-declared:"))

    def test_plan_copies_per_target_capability_evidence(self) -> None:
        contracts = target_contracts_fixture()
        plan = self.build(contracts=contracts)
        by_id = {item["target_id"]: item for item in contracts}
        self.assertEqual(set(plan["target_capabilities"]), set(by_id))
        uart = plan["target_capabilities"]["uart0_win"]
        self.assertEqual(uart["capabilities"], by_id["uart0_win"]["capabilities"])
        self.assertEqual(uart["evidence"], by_id["uart0_win"]["evidence"])
        self.assertFalse(uart["capabilities"]["integrity"])
        self.assertEqual(uart["adapter"], {"module": "beat_to_tlul", "source": "protocols/rtl/beat_to_tlul.sv"})
        self.assertNotIn("missing", json.dumps(plan["target_capabilities"]))

    def test_plan_records_clock_domains(self) -> None:
        plan = self.build()
        self.assertEqual([item["name"] for item in plan["clock_domains"]], ["core"])
        self.assertEqual(plan["clock_domains"][0]["frequency_hz"], 50000000)
        self.assertTrue(plan["clock_domains"][0]["single_runtime_clock"])

    def test_plan_records_processor_execution(self) -> None:
        plan = self.build()
        self.assertEqual(plan["processor_execution"]["execution_hash"], "sha256:" + "a" * 64)
        self.assertEqual(
            sorted(route["rtl_module"] for route in plan["processor_execution"]["routes"]),
            ["obi_to_beat", "obi_to_beat"],
        )

    def test_plan_is_json_serializable(self) -> None:
        json.dumps(self.build())

    def test_plan_rejects_unvalidated_spec(self) -> None:
        spec = spec_fixture()
        spec["memory_regions"].append(
            {
                "region_id": "ram0_alias",
                "component_id": "ram",
                "base": 0x80008000,
                "size": 0x1000,
                "permissions": {"read": True, "write": True, "execute": True},
                "physical_memory_id": "sram0_alias",
                "initialization_policy": "alias",
            }
        )
        with self.assertRaises(SocContractError) as raised:
            self.build(spec=spec)
        self.assertTrue(str(raised.exception).startswith("overlapping-memory-regions"))

    def test_plan_requires_target_contract(self) -> None:
        contracts = [c for c in target_contracts_fixture() if c["target_id"] != "uart0_win"]
        with self.assertRaises(SocContractError) as raised:
            self.build(contracts=contracts)
        self.assertTrue(str(raised.exception).startswith("missing-target-contract:uart0_win"))

    def test_plan_rejects_duplicate_target_contract(self) -> None:
        contracts = target_contracts_fixture()
        contracts.append(copy.deepcopy(contracts[0]))
        with self.assertRaises(SocContractError) as raised:
            self.build(contracts=contracts)
        self.assertTrue(str(raised.exception).startswith("duplicate-target-contract:ram0_win"))

    def test_plan_fails_closed_on_missing_capability(self) -> None:
        contracts = target_contracts_fixture()
        del contracts[2]["capabilities"]["partial_write"]
        with self.assertRaises(SocContractError) as raised:
            self.build(contracts=contracts)
        self.assertTrue(str(raised.exception).startswith("missing-target-capability:uart0_win:partial_write"))

    def test_unsupported_partial_write_rejected(self) -> None:
        contracts = target_contracts_fixture()
        contracts[2]["capabilities"]["partial_write"] = False
        with self.assertRaises(SocContractError) as raised:
            self.build(contracts=contracts)
        self.assertTrue(str(raised.exception).startswith("unsupported-partial-write:uart0_win"))

        # byte_enable false does not require partial-write support
        spec = spec_fixture()
        spec["targets"][2]["byte_enable"] = False
        plan = self.build(spec=spec, contracts=contracts)
        self.assertFalse(plan["target_capabilities"]["uart0_win"]["capabilities"]["partial_write"])

    def test_plan_rejects_target_contract_mismatch(self) -> None:
        contracts = target_contracts_fixture()
        contracts[2]["component_id"] = "ram"
        with self.assertRaises(SocContractError) as raised:
            self.build(contracts=contracts)
        self.assertTrue(str(raised.exception).startswith("target-contract-mismatch:uart0_win"))

    def test_plan_rejects_missing_adapter_module(self) -> None:
        contracts = target_contracts_fixture()
        del contracts[2]["adapter_module"]
        with self.assertRaises(SocContractError) as raised:
            self.build(contracts=contracts)
        self.assertTrue(str(raised.exception).startswith("missing-adapter-module:uart0_win"))

    def test_plan_rejects_invalid_processor_execution(self) -> None:
        with self.assertRaises(SocContractError) as raised:
            self.build(execution={"schema_version": "processor_execution.v2"})
        self.assertTrue(str(raised.exception).startswith("invalid-field:processor_execution"))

    def test_plan_hash_is_order_independent(self) -> None:
        plan = self.build()
        self.assertNotEqual(plan, permuted(plan))
        self.assertEqual(soc_plan_hash(plan), soc_plan_hash(permuted(plan)))

    def test_plan_hash_changes_with_binding_and_address(self) -> None:
        plan = self.build()
        other = self.build()
        other["address_map"]["windows"][0]["base"] = 0x80010000
        self.assertNotEqual(soc_plan_hash(plan), soc_plan_hash(other))

        other = self.build()
        other["target_capabilities"]["uart0_win"]["capabilities"]["partial_write"] = False
        self.assertNotEqual(soc_plan_hash(plan), soc_plan_hash(other))

    def test_plan_hash_format(self) -> None:
        self.assertRegex(soc_plan_hash(self.build()), HASH_RE)


# --------------------------------------------------------------------------
# soc_stimulus.v1
# --------------------------------------------------------------------------


class SocStimulusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = build_soc_plan(
            spec_fixture(), processor_execution_fixture(), target_contracts_fixture()
        )

    def reject(self, prefix: str, stimulus, **kwargs) -> SocContractError:
        with self.assertRaises(SocContractError) as raised:
            validate_soc_stimulus(stimulus, **kwargs)
        message = str(raised.exception)
        self.assertTrue(message.startswith(prefix), f"{message!r} does not start with {prefix!r}")
        return raised.exception

    def test_valid_stimulus_is_accepted(self) -> None:
        for mode in ("cpu_only", "mmio_only", "mixed"):
            with self.subTest(mode=mode):
                stimulus = stimulus_fixture(self.plan, mode)
                self.assertIsNone(validate_soc_stimulus(stimulus))

    def test_schema_version_and_required_fields(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["schema_version"] = "soc_stimulus.v2"
        self.reject("invalid-field:", stimulus)

        stimulus = stimulus_fixture(self.plan)
        del stimulus["rule_classes"]
        self.reject("missing-field:", stimulus)

        stimulus = stimulus_fixture(self.plan)
        del stimulus["raw_layout"]["segments"][1]["fields"]
        self.reject("missing-field:", stimulus)

    def test_invalid_mode_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["mode"] = "fuzz_only"
        self.reject("invalid-field:mode", stimulus)

    def test_invalid_plan_hash_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["plan_hash"] = "deadbeef"
        self.reject("invalid-field:plan_hash", stimulus)

    def test_overlapping_raw_fields_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["raw_layout"]["segments"][1]["fields"][1]["lsb"] = 0
        self.reject("overlapping-raw-fields", stimulus)

    def test_overlapping_raw_segments_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["raw_layout"]["segments"][1]["base_bit"] = 128
        self.reject("overlapping-raw-segments", stimulus)

    def test_field_outside_segment_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["raw_layout"]["segments"][0]["fields"][0]["width"] = 300
        self.reject("invalid-field:", stimulus)

    def test_unknown_segment_in_consumption_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["consumption"][0]["segment_id"] = "ghost"
        self.reject("unknown-segment", stimulus)

    def test_unconsumed_segment_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        del stimulus["consumption"][2]
        self.reject("unconsumed-segment", stimulus)

    def test_pending_queue_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan)
        stimulus["consumption"][0]["max_pending"] = 4
        self.reject("invalid-field:", stimulus)

    def test_mmio_only_reset_mismatch_rejected(self) -> None:
        stimulus = stimulus_fixture(self.plan, "mmio_only")
        stimulus["reset_semantics"]["cpu_reset"]["held_in_reset_whole_test"] = False
        self.reject("mode-reset-mismatch", stimulus)

        stimulus = stimulus_fixture(self.plan, "cpu_only")
        stimulus["reset_semantics"]["cpu_reset"]["held_in_reset_whole_test"] = True
        self.reject("mode-reset-mismatch", stimulus)

        stimulus = stimulus_fixture(self.plan, "mmio_only")
        stimulus["reset_semantics"]["mode"] = "mixed"
        self.reject("mode-reset-mismatch", stimulus)


# --------------------------------------------------------------------------
# schema documents
# --------------------------------------------------------------------------


class SchemaDocumentTests(unittest.TestCase):
    def load(self, name: str) -> dict:
        return json.loads((REPO_ROOT / "schemas" / name).read_text(encoding="utf-8"))

    def test_schema_documents_declare_the_frozen_ids(self) -> None:
        for name, schema_id in (
            ("soc_spec.v1.schema.json", SOC_SPEC_SCHEMA),
            ("soc_plan.v1.schema.json", SOC_PLAN_SCHEMA),
            ("soc_stimulus.v1.schema.json", SOC_STIMULUS_SCHEMA),
        ):
            with self.subTest(name=name):
                schema = self.load(name)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertEqual(schema["$id"], schema_id)
                self.assertEqual(schema["properties"]["schema_version"]["const"], schema_id)
                self.assertIn("schema_version", schema["required"])

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_documents_conform_to_their_schemas(self) -> None:
        spec = spec_fixture()
        plan = build_soc_plan(spec, processor_execution_fixture(), target_contracts_fixture())
        documents = (
            ("soc_spec.v1.schema.json", spec),
            ("soc_plan.v1.schema.json", plan),
            ("soc_stimulus.v1.schema.json", stimulus_fixture(plan)),
        )
        for name, document in documents:
            with self.subTest(name=name):
                jsonschema.validate(document, self.load(name))

    def test_schema_required_fields_are_present_in_real_documents(self) -> None:
        spec = spec_fixture()
        plan = build_soc_plan(spec, processor_execution_fixture(), target_contracts_fixture())
        documents = (
            ("soc_spec.v1.schema.json", spec),
            ("soc_plan.v1.schema.json", plan),
            ("soc_stimulus.v1.schema.json", stimulus_fixture(plan)),
        )
        for name, document in documents:
            with self.subTest(name=name):
                schema = self.load(name)
                self.assertTrue(set(schema["required"]).issubset(document))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
