"""P12 renderer generalization tests across the eight composition cells.

Every cell in ``configs/soc/matrix.json`` is planned from its real cell config
(plus the base profile it declares), compiled into a ``soc_stimulus.v1``
document and rendered by ``render_soc``.  The assertions below only accept a
source-backed rendering: the real IP files recorded by task P1 closures must be
present, the target adapter must be the one ``resolve_target_adapter`` selects
for that peripheral's protocol, and a corrupted protocol or a missing closure
must fail closed with a ``SocRenderError`` naming the cell and the peripheral.

The Verilator elaboration test compiles the rendered ``myfuzz_soc_top`` from
the manifest closure.  Cells whose real sources are absent skip only when
``MYFUZZ_SOC_REAL`` is unset; with ``MYFUZZ_SOC_REAL=1`` a missing source is a
loud failure (never a silent skip).
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.composition.soc_plan import build_soc_plan
from myfuzz.composition.soc_renderer import SocRenderError, render_soc
from myfuzz.composition.soc_stimulus import compile_soc_stimulus
from myfuzz.composition.target_adapters import resolve_target_adapter


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "configs/soc/matrix.json"
CLOSURE_DIR = "configs/soc/closures"

# ---------------------------------------------------------------------------
# task P1 facts: real top module, protocol, window and recorded capabilities
# ---------------------------------------------------------------------------

#: Capability facts and the closure finding each one was read from.  These are
#: the same facts tests/protocols/test_soc_target_adapters_rtl.py records, so a
#: renderer that silently invents a capability fails the resolver here.
_TLUL_EVIDENCE = {
    "byte_enable": "tlul_channel_structure",
    "partial_write": "tlul_opcodes",
    "has_error": "d_error_production",
    "integrity": "integrity_check_path",
    "source_width": "tlul_widths",
    "sink_width": "tlul_widths",
    "user_width": "tlul_widths",
    "size_width": "tlul_widths",
}
_APB_EVIDENCE = {
    "byte_enable": "byte_strobes",
    "partial_write": "byte_strobes",
    "has_error": "pslverr_handling",
}
_ZIPCPU_UART_EVIDENCE = {
    "byte_enable": "byte_enable_setup_register",
    "partial_write": "generic_byte_masked_word_write",
    "has_error": "wishbone_error_retry_and_burst",
    "has_address_port": "address_unit",
    "address_units": "address_unit",
    "sel_implemented": "byte_enable_tx_register",
    "wishbone_flavour": "wishbone_subset",
    "ack_requires_cyc": "cyc_stb_semantics",
}
_ZIPCPU_TIMER_EVIDENCE = {
    "byte_enable": "byte_enable_and_partial_writes",
    "partial_write": "partial_write",
    "has_error": "wishbone_error_retry_and_burst",
    "has_address_port": "address_unit_and_single_register_window",
    "address_units": "address_unit_and_single_register_window",
    "sel_implemented": "byte_enable_and_partial_writes",
    "wishbone_flavour": "wishbone_subset",
    "ack_requires_cyc": "cyc_stb_semantics",
}

#: One entry per pinned real peripheral.  ``spot_check`` is the real IP source
#: file the rendered document must name; it is recorded by the closure.
PERIPHERAL_FACTS = {
    "opentitan_uart": {
        "source_lock": "opentitan_uart",
        "top_module": "uart",
        "protocol": ["tl-ul", "1"],
        "window": {"base": 0x4000_0000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {
            "byte_enable": True, "partial_write": True, "has_error": True,
            "integrity": "required", "source_width": 8, "sink_width": 1,
            "user_width": 23, "size_width": 2,
        },
        "evidence_topics": _TLUL_EVIDENCE,
        "irq": {"signal": "intr_rx_watermark_o", "trigger": "level"},
        "environment": {"protocol": ["uart-serial", "1"],
                        "parameters": {"bits": 8, "baud_div": 1, "frame_bits": 10}},
        "spot_check": "third_party/soc-opentitan/hw/ip/uart/rtl/uart.sv",
    },
    "opentitan_gpio": {
        "source_lock": "opentitan_gpio",
        "top_module": "gpio",
        "protocol": ["tl-ul", "1"],
        "window": {"base": 0x4000_1000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {
            "byte_enable": True, "partial_write": True, "has_error": True,
            "integrity": "required", "source_width": 8, "sink_width": 1,
            "user_width": 23, "size_width": 2,
        },
        "evidence_topics": _TLUL_EVIDENCE,
        "irq": {"signal": "intr_gpio_o", "trigger": "level"},
        "environment": {"protocol": ["gpio-event", "1"],
                        "parameters": {"width": 8, "synchronizer_stages": 3,
                                       "event_kind": "edge"}},
        "spot_check": "third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/gpio/rtl/gpio.sv",
    },
    "pulp_gpio": {
        "source_lock": "pulp_gpio",
        "top_module": "apb_gpio",
        "protocol": ["apb", "3"],
        "window": {"base": 0x5000_0000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {"byte_enable": False, "partial_write": False,
                         "has_error": False},
        "evidence_topics": _APB_EVIDENCE,
        "irq": {"signal": "interrupt", "trigger": "edge"},
        "environment": {"protocol": ["gpio-event", "1"],
                        "parameters": {"width": 8, "synchronizer_stages": 3,
                                       "event_kind": "edge"}},
        "spot_check": "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
    },
    "pulp_spi": {
        "source_lock": "pulp_spi",
        "top_module": "apb_spi_master",
        "protocol": ["apb", "3"],
        "window": {"base": 0x5000_1000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {"byte_enable": False, "partial_write": False,
                         "has_error": False},
        "evidence_topics": _APB_EVIDENCE,
        "irq": {"signal": "events_o", "trigger": "edge"},
        "environment": {"protocol": ["spi-miso", "1"],
                        "parameters": {"bits": 8, "cpol": 0, "cpha": 0,
                                       "msb_first": True}},
        "spot_check": "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
    },
    "zipcpu_uart": {
        "source_lock": "zipcpu_uart",
        "top_module": "wbuart",
        "protocol": ["wishbone", "classic"],
        "window": {"base": 0x6000_0000, "size": 0x10},
        "data_width": 32,
        "capabilities": {
            "byte_enable": True, "partial_write": False, "has_error": False,
            "has_address_port": True, "address_units": "word",
            "sel_implemented": True, "wishbone_flavour": "registered-ack",
            "ack_requires_cyc": True,
        },
        "evidence_topics": _ZIPCPU_UART_EVIDENCE,
        "irq": {"signal": "o_uart_rx_int", "trigger": "level"},
        "environment": {"protocol": ["uart-serial", "1"],
                        "parameters": {"bits": 8, "baud_div": 1, "frame_bits": 10}},
        "spot_check": "third_party/soc-zipcpu-wbuart/rtl/wbuart.v",
    },
    "zipcpu_timer": {
        "source_lock": "zipcpu_timer",
        "top_module": "ziptimer",
        "protocol": ["wishbone", "classic"],
        "window": {"base": 0x6000_0010, "size": 4},
        "data_width": 32,
        "capabilities": {
            "byte_enable": False, "partial_write": False, "has_error": False,
            "has_address_port": False, "address_units": "word",
            "sel_implemented": False,
            "wishbone_flavour": "registered-ack-cyc-ignored",
            "ack_requires_cyc": False,
        },
        "evidence_topics": _ZIPCPU_TIMER_EVIDENCE,
        "irq": {"signal": "o_int", "trigger": "edge"},
        "environment": None,
        "spot_check": "third_party/soc-zipcpu/rtl/peripherals/ziptimer.v",
    },
}


def wrapper_module(source_lock: str) -> str:
    """The wrapper module the renderer resolves from the peripheral lock."""
    return "soc_" + source_lock + "_target"


def adapter_module(protocol: str) -> str:
    return {"apb": "beat_to_apb", "tl-ul": "beat_to_tlul",
            "wishbone": "beat_to_wishbone"}[protocol]


# ---------------------------------------------------------------------------
# cell -> spec/plan/stimulus
# ---------------------------------------------------------------------------


def load_matrix() -> dict:
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def cell_entries() -> list:
    return list(load_matrix()["cells"])


def load_cell_config(cell: dict) -> dict:
    config = json.loads((ROOT / cell["config"]).read_text(encoding="utf-8"))
    base_path = config.get("base_profile")
    if base_path:
        base = json.loads((ROOT / base_path).read_text(encoding="utf-8"))
        merged = copy.deepcopy(base)
        merged["cell_id"] = config.get("cell_id", cell["cell_id"])
        merged["families"] = list(config.get("families", base.get("families", [])))
        merged["peripherals"] = copy.deepcopy(config["peripherals"])
        merged["base_profile_config"] = base_path
        merged["matrix_cell"] = config
        return merged
    return config


def _closure_parameters(closure_path: str) -> dict:
    document = json.loads((ROOT / closure_path).read_text(encoding="utf-8"))
    return {item["name"]: item["value"] for item in document.get("parameters", [])
            if item["name"].isidentifier()}


def peripheral_records(config: dict) -> list:
    """Normalise the cell config's peripheral declarations into full records."""
    records = []
    for entry in config["peripherals"]:
        if isinstance(entry, dict):
            facts = PERIPHERAL_FACTS[entry["source_lock"]]
            record = copy.deepcopy(facts)
            record.update(copy.deepcopy(entry))
            record.setdefault("id", entry["source_lock"])
            record.setdefault("closure", "%s/%s.json" % (CLOSURE_DIR, record["source_lock"]))
            record.setdefault("runtime_status", "runtime_unverified")
            records.append(record)
            continue
        facts = copy.deepcopy(PERIPHERAL_FACTS[entry])
        facts["id"] = entry
        facts["closure"] = "%s/%s.json" % (CLOSURE_DIR, facts["source_lock"])
        facts["runtime_status"] = "runtime_unverified"
        facts["parameters"] = _closure_parameters(facts["closure"])
        records.append(facts)
    return records


def _evidence(record: dict) -> dict:
    """Evidence keyed by capability fact (the shape soc_plan records)."""
    return {
        fact: {"topic": record["evidence_topics"][fact],
               "evidence_path": record["closure"], "provenance": "rtl_read"}
        for fact in sorted(record["capabilities"])
    }


def build_spec(cell: dict, config: dict, records: list) -> dict:
    cpu = config["cpu"]
    cpu_lock = cpu["source_lock"]
    width = 64 if cpu["xlen"] == 64 else 32
    address_width = width
    is_unified = list(cpu["protocol"])[0] == "axi4"

    components = [{
        "component_id": "cpu",
        "kind": "cpu",
        "source_lock": cpu_lock,
        "top_module": cpu["top_module"],
        "clock_domain": "core",
        "reset_domain": "cpu_rst",
        "instances": [{"instance_id": "cpu0",
                       "parameters": dict(cpu.get("parameters", {}))}],
        "capability_evidence": {"isa": "rv%d" % cpu["xlen"],
                                "provenance": cpu.get("source_provenance", cell["config"])},
    }]
    for region in config["memory_regions"]:
        component_id = region["region_id"]
        components.append({
            "component_id": component_id,
            "kind": "memory",
            "source_lock": "soc_%s_model" % ("rom" if not region["permissions"]["write"] else "ram"),
            "top_module": "riscv_boot_memory_%d" % width,
            "clock_domain": "core",
            "reset_domain": "sys_rst",
            "instances": [{"instance_id": component_id,
                           "parameters": {"BASE_ADDR": region["base"],
                                          "BYTES": region["size"]}}],
            "capability_evidence": {"model": "byte image memory model",
                                    "provenance": "src/myfuzz/integration/rtl/riscv_boot_memory.sv"},
        })

    for record in records:
        components.append({
            "component_id": record["id"],
            "kind": "peripheral",
            "source_lock": record["source_lock"],
            "top_module": record["top_module"],
            "clock_domain": "core",
            "reset_domain": "sys_rst",
            "instances": [{"instance_id": record["id"],
                           "parameters": dict(record.get("parameters") or {})}],
            "capability_evidence": {
                "protocol": list(record["protocol"]),
                "closure": record["closure"],
                "provenance": record["closure"],
            },
        })
    components.append({
        "component_id": "harness",
        "kind": "clock_reset",
        "source_lock": "soc_clock_reset_harness",
        "top_module": "soc_harness",
        "clock_domain": "core",
        "reset_domain": "sys_rst",
        "instances": [{"instance_id": "harness0", "parameters": {"CYCLES": 100000}}],
        "capability_evidence": {"model": "clock/reset/environment harness",
                                "provenance": "P7"},
    })

    masters = []
    if is_unified:
        masters.append({
            "source_id": "cpu_unified", "kind": "cpu_unified", "component_id": "cpu",
            "port": "noc", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": address_width, "test_modes": ["cpu_only", "mixed"],
        })
    else:
        masters.append({
            "source_id": "cpu_ifetch", "kind": "cpu_instruction", "component_id": "cpu",
            "port": "instr", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": address_width, "test_modes": ["cpu_only", "mixed"],
        })
        masters.append({
            "source_id": "cpu_data", "kind": "cpu_data", "component_id": "cpu",
            "port": "data", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": address_width, "test_modes": ["cpu_only", "mixed"],
        })
    masters.append({
        "source_id": "fuzz_mmio", "kind": "fuzz_mmio", "component_id": "harness",
        "port": "mmio", "protocol": ["processor-memory-beat", "1"],
        "data_width": width, "address_width": address_width,
        "test_modes": ["mmio_only", "mixed"],
    })

    memory_targets = []
    for region in config["memory_regions"]:
        writable = bool(region["permissions"]["write"])
        sources = ["cpu_unified"] if is_unified else ["cpu_ifetch", "cpu_data"]
        if writable:
            sources = sources + ["fuzz_mmio"]
        memory_targets.append({
            "target_id": "%s_win" % region["region_id"],
            "component_id": region["region_id"],
            "port": "mem",
            "protocol": ["ready-valid-memory", "1"],
            "window": {"base": region["base"], "size": region["size"]},
            "request_sources": sources,
            "response_owner": "soc_fabric",
            "byte_enable": writable,
        })

    mmio_sources = ["cpu_unified"] if is_unified else ["cpu_data"]
    mmio_sources = mmio_sources + ["fuzz_mmio"]
    peripheral_targets = [{
        "target_id": record.get("target_id", "%s_win" % record["id"]),
        "component_id": record["id"],
        "port": record["protocol"][0],
        "protocol": list(record["protocol"]),
        "window": copy.deepcopy(record["window"]),
        "request_sources": list(mmio_sources),
        "response_owner": "soc_fabric",
        # The planner's byte_enable flag means "this target really accepts
        # partial byte writes"; an IP with a sel pin but register-specific
        # semantics (ZipCPU wbuart) records partial_write False and keeps the
        # fail-closed adapter rejection.
        "byte_enable": bool(record["capabilities"].get("partial_write", False)),
        "data_width": record["data_width"],
        "width_conversion": {"spanning_write": "reject", "spanning_read": "reject"},
    } for record in records]

    interrupt_routes = []
    irq = 3
    for record in sorted(records, key=lambda item: item["id"]):
        route = record.get("irq")
        if not route:
            continue
        interrupt_routes.append({
            "route_id": "%s_irq" % record["id"],
            "source": {"component_id": record["id"], "signal": route["signal"],
                       "trigger": route["trigger"]},
            "sink": {"master_id": "cpu_unified" if is_unified else "cpu_data",
                     "irq": irq},
            "mask_ack": {"register": "%s.intr_state" % record["id"],
                         "semantics": "write-1-to-clear"},
        })
        irq += 1

    environment_links = []
    for record in sorted(records, key=lambda item: item["id"]):
        link = record.get("environment")
        if not link:
            continue
        environment_links.append({
            "link_id": "%s_pins" % record["id"],
            "component_id": record["id"],
            "protocol": list(link["protocol"]),
            "parameters": copy.deepcopy(link["parameters"]),
        })

    source_locks = sorted({"soc_ram_model", "soc_rom_model", "soc_clock_reset_harness",
                           cpu_lock} | {record["source_lock"] for record in records})
    return {
        "schema_version": "soc_spec.v1",
        "spec_id": config.get("cell_id", cell["cell_id"]),
        "source_locks": source_locks,
        "components": components,
        "memory_regions": [{
            "region_id": region["region_id"],
            "component_id": region["region_id"],
            "base": region["base"],
            "size": region["size"],
            "permissions": copy.deepcopy(region["permissions"]),
            "physical_memory_id": region["physical_memory_id"],
            "initialization_policy": region["initialization_policy"],
        } for region in config["memory_regions"]],
        "masters": masters,
        "targets": memory_targets + peripheral_targets,
        "interrupt_routes": interrupt_routes,
        "environment_links": environment_links,
        "resources": {
            "clock_domains": [{"name": "core", "frequency_hz": 50000000}],
            "resets": [
                {"name": "rst_sys_ni", "domain": "sys_rst", "polarity": "active_low",
                 "synchronous": True},
                {"name": "rst_cpu_ni", "domain": "cpu_rst", "polarity": "active_low",
                 "synchronous": True},
            ],
            "clock_adapters": [],
            "limits": {"build_timeout_s": 600, "run_timeout_s": 120,
                       "rss_limit_mb": 2048, "cycles_per_sample": 100000},
        },
        "assumptions": [{
            "assumption_id": "single_runtime_clock",
            "statement": "Every selected IP runs on the single runtime clock domain.",
            "provenance": records[0]["closure"] if records else cell["config"],
        }],
        "provenance": {
            "render_config": cell["config"],
            "cell": config.get("cell_id", cell["cell_id"]),
            "closures": CLOSURE_DIR,
            "sources": "configs/soc/sources.lock.json",
        },
    }


def build_execution(cpu: dict) -> dict:
    protocol = list(cpu["protocol"])
    width = 64 if cpu["xlen"] == 64 else 32
    is_unified = protocol[0] == "axi4"
    module = "axi4_processor_memory_adapter" if is_unified else "obi_processor_memory_adapter"
    source = "src/myfuzz/protocols/rtl/%s.sv" % module
    route = {
        "source_protocol": protocol,
        "target_protocol": ["processor-memory-beat", "1"],
        "adapter_id": "%s_beat" % protocol[0],
        "rtl_module": module,
        "rtl_source": source,
        "parameters": {"ADDRESS_WIDTH": width, "READ_ONLY": 0},
        "widths": {"address": width, "data": width},
        "field_connections": [],
        "extension_policies": [],
        "reset_contract": {"polarity": "active_low", "synchrony": "sync"},
        "backend_contract": {
            "mode": "single_outstanding_request_response",
            "protocol": ["processor-memory-beat", "1"],
            "capabilities": {"max_outstanding": 1, "max_wait_cycles": 64},
        },
    }
    routes = []
    if is_unified:
        routes.append(dict(route, route_id=1, function="memory_master"))
    else:
        routes.append(dict(route, route_id=1, function="instruction_memory_master",
                           parameters={"ADDRESS_WIDTH": width, "READ_ONLY": 1}))
        routes.append(dict(route, route_id=2, function="data_memory_master"))
    return {
        "schema_version": "processor_execution.v1",
        "adapter_sources": [source],
        "classification": None,
        "routes": routes,
        "execution_hash": "sha256:" + "b" * 64,
    }


def build_contracts(records: list, config: dict, width: int) -> list:
    contracts = []
    for region in config["memory_regions"]:
        writable = bool(region["permissions"]["write"])
        model = "riscv_boot_memory_%d" % width
        contracts.append({
            "target_id": "%s_win" % region["region_id"],
            "component_id": region["region_id"],
            "port": "mem",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": model,
            "adapter_source": "src/myfuzz/integration/rtl/riscv_boot_memory.sv",
            "capabilities": {"partial_write": writable, "read": True,
                             "write": writable, "data_width": width},
            "evidence": {"provenance": "src/myfuzz/integration/rtl/riscv_boot_memory.sv"},
        })
    for record in records:
        target_id = record.get("target_id", "%s_win" % record["id"])
        try:
            resolved = resolve_target_adapter(
                {"protocol": "processor-memory-beat", "version": "1",
                 "address_width": width, "data_width": 32},
                {
                    "component_id": record["id"], "target_id": target_id,
                    "protocol": list(record["protocol"]),
                    "version": record["protocol"][1],
                    "data_width": record["data_width"],
                    "window": copy.deepcopy(record["window"]),
                    "capabilities": copy.deepcopy(record["capabilities"]),
                    "evidence": _evidence(record),
                },
            )
        except ValueError:
            # The plan is still buildable; render_soc must reject it fail-closed
            # with a SocRenderError naming the cell and the peripheral.
            resolved = {"rtl_module": "unresolved_target_adapter",
                        "rtl_source": record["closure"]}
        contracts.append({
            "target_id": target_id,
            "component_id": record["id"],
            "port": record["protocol"][0],
            "protocol": list(record["protocol"]),
            "adapter_module": resolved["rtl_module"],
            "adapter_source": resolved["rtl_source"],
            # data_width stays a declared target fact (soc_spec target), not a
            # capability fact: the P5 resolver reads it from the target record.
            "capabilities": copy.deepcopy(record["capabilities"]),
            "evidence": _evidence(record),
        })
    return contracts


def cell_documents(cell: dict, *, config_path=None) -> tuple:
    """Build (plan, stimulus, config) for one matrix cell."""
    config = load_cell_config(cell)
    if config_path is not None:
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    records = peripheral_records(config)
    spec = build_spec(cell, config, records)
    if config_path is not None:
        spec["provenance"]["render_config"] = str(config_path)
    width = 64 if config["cpu"]["xlen"] == 64 else 32
    plan = build_soc_plan(spec, build_execution(config["cpu"]),
                          build_contracts(records, config, width))
    stimulus = compile_soc_stimulus(plan, {"mode": "mixed", "address_strategy": "biased"})
    return plan, stimulus, config


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


class SocRendererCellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cells = cell_entries()

    def documents(self, cell: dict) -> tuple:
        return cell_documents(cell)

    def test_every_cell_renders_real_source_backed_peripherals(self):
        for cell in self.cells:
            with self.subTest(cell=cell["cell_id"]):
                plan, stimulus, config = self.documents(cell)
                rendered = render_soc(plan, stimulus)
                for name in ("soc_top.sv", "soc_sources.f", "soc_manifest.json",
                             "soc_boot.S", "soc_parameters.json"):
                    self.assertIn(name, rendered)
                manifest = json.loads(rendered["soc_manifest.json"])
                self.assertEqual(manifest["plan_hash"], stimulus["plan_hash"])
                records = peripheral_records(config)
                self.assertEqual(set(manifest["peripherals"]),
                                 {record["id"] for record in records})
                for record in records:
                    entry = manifest["peripherals"][record["id"]]
                    self.assertEqual(entry["source_lock"], record["source_lock"])
                    self.assertTrue(entry["runtime_status"])
                    self.assertIn(record["spot_check"], entry["closure_files"],
                                  "%s closure does not record %s"
                                  % (record["id"], record["spot_check"]))
                    self.assertIn(record["spot_check"], rendered["soc_sources.f"])
                    adapter = adapter_module(record["protocol"][0])
                    self.assertEqual(entry["adapter_module"], adapter)
                    self.assertIn(adapter, rendered["soc_sources.f"])
                    self.assertIn(adapter, rendered["soc_top.sv"])
                    wrapper = wrapper_module(record["source_lock"])
                    self.assertIn(wrapper, rendered["soc_top.sv"])
                    self.assertEqual(record["top_module"], entry["top_module"])
                    self.assertIn(record["spot_check"], entry["ip_source_files"])
                    # The wrapper must instantiate the real IP, never a
                    # behavioural stand-in.
                    wrapper_text = (ROOT / entry["wrapper_source"]).read_text(encoding="utf-8")
                    self.assertRegex(
                        wrapper_text,
                        r"\b%s\s*(?:#\s*\(|u_)" % re.escape(record["top_module"]),
                        "%s does not instantiate the real %s"
                        % (entry["wrapper_source"], record["top_module"]),
                    )
                # Environment peers and the IRQ router exist exactly for the
                # peripherals that declare such a contract.
                contract = manifest["environment_contract"]
                link_protocols = {link["protocol"][0] for link in contract["links"]}
                for protocol, peer in (("uart-serial", "fuzz_uart_peer"),
                                       ("spi-miso", "fuzz_spi_peer")):
                    with self.subTest(cell=cell["cell_id"], peer=peer):
                        self.assertEqual(protocol in link_protocols,
                                         peer in rendered["soc_top.sv"])
                self.assertEqual(bool(contract["interrupt_routes"]),
                                 "soc_irq_router" in rendered["soc_top.sv"])
                for forbidden in ("soc_behavioural_model", "behavioural_peripheral",
                                  "regression_stub"):
                    self.assertNotIn(forbidden, rendered["soc_top.sv"])

    def test_cell_render_is_byte_identical_across_runs(self):
        for cell in self.cells:
            with self.subTest(cell=cell["cell_id"]):
                plan, stimulus, _config = self.documents(cell)
                self.assertEqual(render_soc(plan, stimulus), render_soc(plan, stimulus))

    @staticmethod
    def corrupt(cell: dict, *, protocol=None, closure=None) -> dict:
        """Return a copy of the effective cell config with one field changed.

        The real config file is never touched; the copy is written to a
        temporary directory and referenced by the plan's render_config.
        """
        config = copy.deepcopy(load_cell_config(cell))
        entry = config["peripherals"][0]
        if not isinstance(entry, dict):
            entry = copy.deepcopy(PERIPHERAL_FACTS[entry])
            entry["id"] = config["peripherals"][0]
            config["peripherals"][0] = entry
        if protocol is not None:
            entry["protocol"] = list(protocol)
        if closure is not None:
            entry["closure"] = closure
        return config

    def render_corrupted(self, cell: dict, **changes) -> None:
        corrupted = self.corrupt(cell, **changes)
        entry = corrupted["peripherals"][0]
        peripheral = entry["id"] if isinstance(entry, dict) else entry
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("%s.json" % cell["cell_id"])
            path.write_text(json.dumps(corrupted), encoding="utf-8")
            with self.assertRaises(SocRenderError) as caught:
                plan, stimulus, _config = cell_documents(cell, config_path=path)
                render_soc(plan, stimulus)
            message = str(caught.exception)
            self.assertIn(cell["cell_id"], message)
            self.assertIn(peripheral, message)

    def test_package_collisions_are_resolved_and_recorded_before_their_users(self):
        for cell in self.cells:
            with self.subTest(cell=cell["cell_id"]):
                plan, stimulus, _config = self.documents(cell)
                manifest = json.loads(render_soc(plan, stimulus)["soc_manifest.json"])
                elaboration = manifest["real_elaboration"]
                sources = list(elaboration["source_files"])
                self.assertIn("package_collisions", elaboration)
                for package, record in elaboration["package_collisions"].items():
                    with self.subTest(cell=cell["cell_id"], package=package):
                        self.assertIn(record["winner"], sources)
                        for shadowed in record["shadowed"]:
                            self.assertIn(shadowed, sources)
                        if record["reordered"]:
                            self.assertLess(sources.index(record["winner"]),
                                            sources.index(record["default_first"]))

    def test_a_corrupted_protocol_fails_closed_naming_cell_and_peripheral(self):
        for cell in self.cells:
            with self.subTest(cell=cell["cell_id"]):
                self.render_corrupted(cell, protocol=["usb", "1"])

    def test_a_missing_closure_fails_closed_naming_cell_and_peripheral(self):
        for cell in self.cells:
            with self.subTest(cell=cell["cell_id"]):
                self.render_corrupted(
                    cell, closure="configs/soc/closures/does_not_exist.json")

    def test_rendered_top_elaborates_with_verilator_from_the_manifest_closure(self):
        verilator = shutil.which("verilator")
        self.assertIsNotNone(verilator, "verilator is required for rendered-top elaboration")
        opt_in = os.environ.get("MYFUZZ_SOC_REAL") == "1"
        elaborated = []
        missing = []
        for cell in self.cells:
            with self.subTest(cell=cell["cell_id"]):
                plan, stimulus, _config = self.documents(cell)
                rendered = render_soc(plan, stimulus)
                manifest = json.loads(rendered["soc_manifest.json"])
                closure = manifest["real_elaboration"]
                sources = [ROOT / item for item in closure["source_files"]]
                absent = [str(path) for path in sources if not path.is_file()]
                if absent:
                    if opt_in:
                        self.fail("%s: real sources are missing from third_party: %s"
                                  % (cell["cell_id"], absent[:3]))
                    missing.append(cell["cell_id"])
                    continue
                include_dirs = [ROOT / item for item in closure["include_dirs"]]
                with tempfile.TemporaryDirectory() as directory:
                    top = Path(directory) / "soc_top.sv"
                    top.write_text(rendered["soc_top.sv"], encoding="utf-8")
                    command = [
                        str(verilator), "--lint-only", "--top-module", "myfuzz_soc_top",
                        "-Wno-fatal", "-Wno-PINMISSING", "-Wno-WIDTHEXPAND",
                        "-Wno-WIDTHTRUNC", "-Wno-MULTIDRIVEN", "-Wno-UNSIGNED",
                        "-Wno-CASEINCOMPLETE", "-Wno-LATCH", "-Wno-UNOPTFLAT",
                        # Two pinned checkouts may declare the same package or
                        # module name (for example the OpenTitan prim_secded_pkg
                        # and the HPDcache fork); the manifest records which
                        # definition the ordered closure makes win.
                        "-Wno-MODDUP",
                    ]
                    command.extend("-D" + item for item in closure["defines"])
                    command.extend("-I" + str(item) for item in include_dirs)
                    command.extend(str(path) for path in sources
                                   if path.suffix in (".sv", ".v"))
                    command.append(str(top))
                    result = subprocess.run(command, cwd=ROOT, text=True,
                                            capture_output=True, timeout=900)
                    self.assertEqual(0, result.returncode,
                                     result.stdout[-8000:] + result.stderr[-8000:])
                elaborated.append(cell["cell_id"])
        if not elaborated and missing:
            self.skipTest("no real third_party sources for: %s" % ", ".join(missing))
        if opt_in:
            self.assertEqual(set(elaborated), {cell["cell_id"] for cell in self.cells})


class SocRendererLegacyCompatibilityTests(unittest.TestCase):
    """The P10 Ibex+PULP plan keeps rendering through the frozen profile."""

    def test_plan_without_a_render_config_keeps_the_p10_document(self):
        from tests.composition.test_soc_stimulus import plan_fixture, policy

        plan = plan_fixture()
        rendered = render_soc(plan, compile_soc_stimulus(plan, policy()))
        manifest = json.loads(rendered["soc_manifest.json"])
        self.assertEqual("soc_ibex_pulp_core", manifest["real_elaboration"]["runtime_top"])
        self.assertEqual(["MYFUZZ_ENABLE_REAL_IBEX"], manifest["real_elaboration"]["defines"])
        self.assertIn("fuzz_spi_peer", rendered["soc_top.sv"])


if __name__ == "__main__":
    unittest.main()
