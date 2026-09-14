"""Config-driven real RFuzz build for generated source-backed SoCs (P14).

This module is the production build hook behind
:func:'myfuzz.integration.soc_campaign.run_soc_campaign'.  It performs the
missing real path end to end:

1. load the cell config named by the campaign task config (or the embedded
   'base_cell' document) and build the 'soc_plan.v1' plan plus the
   'soc_stimulus.v1' document for the configured mode,
2. render the cell with :func:'myfuzz.composition.soc_renderer.render_soc' and
   publish every rendered file under 'build_dir',
3. derive the RFuzz input layout from the compiled stimulus raw ABI, build the
   pinned transport with
   :func:'myfuzz.composition.rfuzz_transport.build_rfuzz_transport' and publish
   'rfuzz_input_transport.sv' / 'rfuzz_input_transport.json',
4. generate the persistent harness testbench that speaks the internal simulator
   protocol of :mod:'myfuzz.integration.rfuzz_simulator' (version 2), compile it
   with Verilator through the same supervised command path 'build_simulator'
   uses, and return a :class:'SimulatorArtifact' that 'rfuzz_live.run_live' can
   drive through the official RFuzz FIFO/shared-memory channel.

Every step is fail closed.  A missing Verilator, a missing closure source, an
unsupported cell or a compiler failure raises :class:'SocBuildError'; no
behavioural CPU/peripheral model is ever substituted and no artifact is
returned unless the executable was actually produced.

The peripheral capability facts below are the pinned task P1 closure readings
('configs/soc/closures/*.json'); they are overlaid, when the cell config
declares them, by that config's own protocol/window/parameters so the cell
document stays the source of truth.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.composition.input_layout import (
    InputLayout,
    LayoutField,
    input_layout_document,
)
from myfuzz.composition.rfuzz_transport import build_rfuzz_transport
from myfuzz.composition.soc_plan import build_soc_plan
from myfuzz.composition.soc_renderer import render_soc
from myfuzz.composition.soc_stimulus import compile_soc_stimulus
from myfuzz.composition.target_adapters import resolve_target_adapter

from .campaign import CampaignOptions, run_supervised_command
from .riscv_execution import (
    RiscvExecutionFacts,
    RiscvExecutionProvenance,
    build_minimal_boot_image,
)
from .rfuzz_simulator import (
    MAX_CYCLES,
    SIMULATOR_PROTOCOL_VERSION,
    SimulatorArtifact,
)


ROOT = Path(__file__).resolve().parents[3]
BUILD_SCHEMA = "soc_campaign_build.v1"
CLOSURE_DIR = "configs/soc/closures"
SOURCES_LOCK = "configs/soc/sources.lock.json"
COUNTER_LIMIT = 128
COUNTER_BITS_PER_PORT = 16
PROBE_TIMEOUT_SECONDS = 60
BUILD_TIMEOUT_SECONDS = 600
#: CPUs whose first fetch is not at the reset vector itself.  Ibex documents
#: 'boot_addr_i + 0x80' as the first instruction address; CVA6 starts at
#: 'boot_addr_i'.  A cell config may override this with 'cpu.fetch_offset'.
_CPU_FETCH_OFFSETS = {"ibex": 0x80, "cva6": 0x0}
#: Inputs the harness holds at a defined idle level when the compiled raw ABI
#: does not drive them.
_IDLE_INPUTS = {"spi_cs_i": 1, "spi_cs": 1}

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

#: Capability facts recorded from the pinned task P1 closures.  'spot_check' is
#: the real IP source the closure records; the campaign build test asserts that
#: file is part of the rendered closure.
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
        # Pinned fact; a cell config that declares its own window (the ibex-pulp
        # and cva6-pulp profiles do) overrides this value.
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
        # Pinned fact; overridden by a cell config's own window when declared.
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

_TOP_MODULE_RE = re.compile(r"^module\s+([A-Za-z_]\w*)\b", re.MULTILINE)
_PORT_RE = re.compile(
    r"\b(input|output|inout)\s+(?:wire|logic|reg)?\s*(\[[^\]]*\])?\s*([A-Za-z_]\w*)"
)
_SAFE_WIDTH_RE = re.compile(r"\A[0-9+\-*/() ]+\Z")
_WIDTH_IDENTIFIERS = {"ADDRESS_WIDTH", "DATA_WIDTH"}


class SocBuildError(RuntimeError):
    """A real source-backed campaign artifact could not be built."""


@dataclass(frozen=True)
class SocCampaignArtifact(SimulatorArtifact):
    """A Verilator SoC artifact plus the exact build evidence behind it."""

    build_document: Mapping[str, object] = None
    rendered_files: tuple[tuple[str, str], ...] = ()


class SocRawProjector:
    """Identity projection: one RFuzz record *is* one raw stimulus sample."""

    instruction_mode = "soc-raw-stimulus-abi"

    def __init__(self, layout, constraint_hash):
        self.layout = layout
        self.constraint_hash = constraint_hash

    def project(self, raw):
        if type(raw) is not int or not 0 <= raw < 1 << self.layout.raw_width:
            raise ValueError("raw sample outside the compiled stimulus layout")
        return raw


def _require_mapping(value, label):
    if not isinstance(value, Mapping):
        raise SocBuildError("%s:mapping-required" % label)
    return value


def _read_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SocBuildError("%s-unreadable:%s: %s" % (label, path, error)) from error


def _hash_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _file_hash(path):
    return _hash_bytes(Path(path).read_bytes())


def _mode(config):
    mode = config.get("mode", "mixed")
    if mode not in ("cpu_only", "mmio_only", "mixed"):
        raise SocBuildError("unsupported campaign mode: %r" % (mode,))
    return mode


def _tool_version(tool):
    try:
        result = subprocess.run(
            (str(tool), "--version"), capture_output=True, text=True,
            timeout=30, check=False)
    except OSError as error:
        raise SocBuildError("tool-unavailable:%s: %s" % (tool, error)) from error
    text = (result.stdout or result.stderr or "").strip().splitlines()
    if result.returncode != 0 or not text:
        raise SocBuildError("tool-version-failed:%s" % (tool,))
    return text[0]


def _cell_config(config, root, build):
    """Resolve (config path, effective cell document) for this task."""
    reference = config.get("cell_config", config.get("render_config"))
    if reference is None:
        cell_id = config.get("cell_id") or config.get("config_id")
        candidate = root / "configs/soc" / ("%s.json" % cell_id)
        if cell_id and candidate.is_file():
            reference = candidate
    if reference is not None:
        path = Path(str(reference))
        if not path.is_absolute():
            path = root / path
        path = path.resolve()
        if not path.is_file() or path.is_symlink():
            raise SocBuildError("cell config is missing: %s" % path)
        document = _read_json(path, "cell-config")
    elif isinstance(config.get("base_cell"), Mapping):
        document = copy.deepcopy(dict(config["base_cell"]))
        build.parent.mkdir(parents=True, exist_ok=True)
        path = build.with_name(build.name + "-cell_config.json").absolute()
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    else:
        raise SocBuildError(
            "campaign config must name 'cell_config' or embed 'base_cell'")
    effective = _merge_base_profile(document, path, root)
    if not isinstance(effective.get("cpu"), Mapping):
        raise SocBuildError("cell config must declare a cpu mapping: %s" % path)
    if not isinstance(effective.get("peripherals"), list) or not effective["peripherals"]:
        raise SocBuildError("cell config must declare peripherals: %s" % path)
    if not isinstance(effective.get("memory_regions"), list) or not effective["memory_regions"]:
        raise SocBuildError("cell config must declare memory_regions: %s" % path)
    return path, effective


def _merge_base_profile(document, path, root):
    """Merge a 'base_profile' exactly like the renderer's own profile merge."""
    base_reference = document.get("base_profile")
    if not isinstance(base_reference, str) or not base_reference:
        return document
    base_path = Path(base_reference)
    if not base_path.is_absolute():
        base_path = root / base_path
    base = _read_json(base_path.resolve(), "base-profile")
    if not isinstance(base, Mapping):
        raise SocBuildError("base profile is not an object: %s" % base_path)
    merged = copy.deepcopy(dict(base))
    merged["cell_id"] = document.get("cell_id", merged.get("cell_id"))
    merged["families"] = list(document.get("families", merged.get("families", [])))
    merged["peripherals"] = copy.deepcopy(document["peripherals"])
    merged["matrix_cell"] = copy.deepcopy(dict(document))
    merged["base_profile"] = base_reference
    return merged


def _peripheral_records(cell, root):
    """Normalise the cell config's peripheral declarations into full records."""
    records = []
    for entry in cell["peripherals"]:
        if isinstance(entry, Mapping):
            source_lock = entry.get("source_lock", entry.get("id"))
        elif isinstance(entry, str):
            source_lock = entry
        else:
            raise SocBuildError("peripheral declaration must be a string or object")
        facts = PERIPHERAL_FACTS.get(str(source_lock))
        if facts is None:
            raise SocBuildError(
                "peripheral %r has no pinned capability facts; refusing to invent them"
                % (source_lock,))
        record = copy.deepcopy(facts)
        if isinstance(entry, Mapping):
            record.update(copy.deepcopy(dict(entry)))
        record["source_lock"] = str(source_lock)
        record.setdefault("id", str(source_lock))
        record.setdefault("target_id", "%s_win" % record["id"])
        record.setdefault("closure", "%s/%s.json" % (CLOSURE_DIR, record["source_lock"]))
        record.setdefault("runtime_status", "runtime_unverified")
        closure_path = Path(str(record["closure"]))
        if not closure_path.is_absolute():
            closure_path = root / closure_path
        if not closure_path.is_file() or closure_path.is_symlink():
            raise SocBuildError("peripheral closure is missing: %s" % closure_path)
        closure = _read_json(closure_path, "peripheral-closure")
        if (closure.get("component") != record["source_lock"]
                or closure.get("top_module") != record["top_module"]):
            raise SocBuildError(
                "closure identity mismatch for %s: %s" % (record["id"], closure_path))
        record["closure_document"] = closure
        if not record.get("parameters"):
            # The cell config may name a peripheral by source lock only; the
            # pinned closure then records the parameter values that elaborated.
            record["parameters"] = {
                str(item["name"]): item["value"]
                for item in closure.get("parameters", [])
                if isinstance(item, Mapping) and isinstance(item.get("name"), str)
                and item["name"].isidentifier()
            }
        topics = {item.get("topic") for item in closure.get("capability_findings", [])
                  if isinstance(item, Mapping)}
        record["unverified_evidence_topics"] = sorted(
            topic for topic in set(record["evidence_topics"].values())
            if topic not in topics)
        records.append(record)
    ids = [record["id"] for record in records]
    if len(set(ids)) != len(ids):
        raise SocBuildError("duplicate peripheral ids in the cell config")
    return records


def _cpu_facts(cell, cell_id):
    cpu = cell.get("cpu")
    if not isinstance(cpu, Mapping):
        raise SocBuildError("%s: cpu mapping required" % cell_id)
    protocol = cpu.get("protocol")
    if (not isinstance(protocol, Sequence) or isinstance(protocol, (str, bytes))
            or len(protocol) != 2 or not all(isinstance(item, str) and item
                                             for item in protocol)):
        raise SocBuildError("%s: cpu protocol must be a (name, version) pair" % cell_id)
    xlen = cpu.get("xlen")
    if xlen not in (32, 64):
        raise SocBuildError("%s: cpu xlen must be 32 or 64" % cell_id)
    if not isinstance(cpu.get("source_lock"), str) or not isinstance(cpu.get("top_module"), str):
        raise SocBuildError("%s: cpu source_lock/top_module required" % cell_id)
    return cpu


def _evidence(record):
    """Evidence keyed by capability fact (the shape soc_plan records)."""
    return {
        fact: {"topic": record["evidence_topics"][fact],
               "evidence_path": record["closure"], "provenance": "rtl_read"}
        for fact in sorted(record["capabilities"])
        if fact in record["evidence_topics"]
    }


def _cell_spec(cell, cpu, records, cell_id, config_path, root):
    width = 64 if cpu["xlen"] == 64 else 32
    is_unified = list(cpu["protocol"])[0] == "axi4"

    components = [{
        "component_id": "cpu",
        "kind": "cpu",
        "source_lock": cpu["source_lock"],
        "top_module": cpu["top_module"],
        "clock_domain": "core",
        "reset_domain": "cpu_rst",
        "instances": [{"instance_id": "cpu0",
                       "parameters": dict(cpu.get("parameters", {}))}],
        "capability_evidence": {"isa": "rv%d" % cpu["xlen"],
                                "provenance": cpu.get("source_provenance", str(config_path))},
    }]
    for region in cell["memory_regions"]:
        writable = bool(region["permissions"]["write"])
        components.append({
            "component_id": region["region_id"],
            "kind": "memory",
            "source_lock": "soc_%s_model" % ("ram" if writable else "rom"),
            "top_module": "riscv_boot_memory_%d" % width,
            "clock_domain": "core",
            "reset_domain": "sys_rst",
            "instances": [{"instance_id": region["region_id"],
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
        "instances": [{"instance_id": "harness0", "parameters": {"CYCLES": MAX_CYCLES}}],
        "capability_evidence": {"model": "clock/reset/environment harness",
                                "provenance": "P7"},
    })

    masters = []
    if is_unified:
        masters.append({
            "source_id": "cpu_unified", "kind": "cpu_unified", "component_id": "cpu",
            "port": "noc", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": width, "test_modes": ["cpu_only", "mixed"],
        })
    else:
        masters.append({
            "source_id": "cpu_ifetch", "kind": "cpu_instruction", "component_id": "cpu",
            "port": "instr", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": width, "test_modes": ["cpu_only", "mixed"],
        })
        masters.append({
            "source_id": "cpu_data", "kind": "cpu_data", "component_id": "cpu",
            "port": "data", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": width, "test_modes": ["cpu_only", "mixed"],
        })
    masters.append({
        "source_id": "fuzz_mmio", "kind": "fuzz_mmio", "component_id": "harness",
        "port": "mmio", "protocol": ["processor-memory-beat", "1"],
        "data_width": width, "address_width": width,
        "test_modes": ["mmio_only", "mixed"],
    })

    memory_targets = []
    for region in cell["memory_regions"]:
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
        "target_id": record["target_id"],
        "component_id": record["id"],
        "port": record["protocol"][0],
        "protocol": list(record["protocol"]),
        "window": copy.deepcopy(record["window"]),
        "request_sources": list(mmio_sources),
        "response_owner": "soc_fabric",
        # The planner's byte_enable flag means "this target really accepts
        # partial byte writes"; an IP with a byte-enable pin but register-specific
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
                           str(cpu["source_lock"])}
                          | {record["source_lock"] for record in records})
    return {
        "schema_version": "soc_spec.v1",
        "spec_id": cell_id,
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
        } for region in cell["memory_regions"]],
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
            "limits": {"build_timeout_s": BUILD_TIMEOUT_SECONDS, "run_timeout_s": 120,
                       "rss_limit_mb": 2048, "cycles_per_sample": MAX_CYCLES},
        },
        "assumptions": [{
            "assumption_id": "single_runtime_clock",
            "statement": "Every selected IP runs on the single runtime clock domain.",
            "provenance": str(config_path),
        }],
        "provenance": {
            "render_config": str(config_path),
            "cell": cell_id,
            "closures": CLOSURE_DIR,
            "sources": SOURCES_LOCK,
            "root": str(root),
        },
    }


def _processor_execution(cpu, cell_id):
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
        "execution_hash": content_hash({"cell": cell_id, "routes": routes,
                                        "module": module}),
    }


def _target_contracts(cell, records, cpu, cell_id):
    width = 64 if cpu["xlen"] == 64 else 32
    contracts = []
    for region in cell["memory_regions"]:
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
        target_record = {
            "component_id": record["id"],
            "target_id": record["target_id"],
            "protocol": list(record["protocol"]),
            "version": record["protocol"][1] if len(record["protocol"]) > 1 else None,
            "data_width": record["data_width"],
            "window": copy.deepcopy(record["window"]),
            "capabilities": copy.deepcopy(record["capabilities"]),
            "evidence": _evidence(record),
        }
        try:
            resolved = resolve_target_adapter(
                {"protocol": "processor-memory-beat", "version": "1",
                 "address_width": width, "data_width": record["data_width"]},
                target_record,
            )
        except ValueError as error:
            raise SocBuildError(
                "%s:%s:target-adapter-unresolved: %s" % (cell_id, record["id"], error)
            ) from error
        contracts.append({
            "target_id": record["target_id"],
            "component_id": record["id"],
            "port": record["protocol"][0],
            "protocol": list(record["protocol"]),
            "adapter_module": resolved["rtl_module"],
            "adapter_source": resolved["rtl_source"],
            # data_width is a declared target fact, not a capability fact: the
            # P5 resolver reads it from the target record, and every recorded
            # capability fact must carry evidence.
            "capabilities": copy.deepcopy(record["capabilities"]),
            "evidence": _evidence(record),
        })
    return contracts


def build_soc_campaign_artifact(config, build_dir):
    """Render, generate the RFuzz transport and compile one real SoC cell.

    'config' is the campaign task config; 'build_dir' must be a new directory.
    The returned artifact is a :class:'SimulatorArtifact' subclass carrying the
    full 'soc_campaign_build.v1' provenance document.
    """
    config = _require_mapping(config, "config")
    build = Path(build_dir).absolute()
    if build.exists() or build.is_symlink():
        raise SocBuildError("campaign build directory must be new")
    root = Path(config.get("root") or ROOT).resolve()
    mode = _mode(config)
    seed = config.get("seed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise SocBuildError("campaign seed must be a nonnegative integer")
    bias_off = config.get("bias_off") is True

    verilator = shutil.which(str(config.get("verilator") or "verilator"))
    if verilator is None:
        raise SocBuildError(
            "verilator-missing: a real campaign build requires Verilator on PATH")

    cell_path, cell = _cell_config(config, root, build)
    cell_id = str(cell.get("cell_id") or config.get("cell_id") or config.get("config_id"))
    cpu = _cpu_facts(cell, cell_id)
    records = _peripheral_records(cell, root)

    spec = _cell_spec(cell, cpu, records, cell_id, cell_path, root)
    execution = _processor_execution(cpu, cell_id)
    contracts = _target_contracts(cell, records, cpu, cell_id)
    plan = build_soc_plan(spec, execution, contracts)
    stimulus = compile_soc_stimulus(
        plan, {"mode": mode, "address_strategy": "bias_off" if bias_off else "biased"})

    rendered = render_soc(plan, stimulus)
    if not isinstance(rendered, Mapping) or "soc_top.sv" not in rendered:
        raise SocBuildError("%s: renderer did not produce soc_top.sv" % cell_id)
    build.mkdir(parents=True, exist_ok=False)
    rendered_records = []
    for name in sorted(rendered):
        if (not isinstance(name, str) or not name or "/" in name or "\\" in name
                or name.startswith(".")):
            raise SocBuildError("%s:unsafe-rendered-filename:%r" % (cell_id, name))
        text = rendered[name]
        if not isinstance(text, str):
            raise SocBuildError("%s:rendered-file-not-text:%s" % (cell_id, name))
        payload = text.encode("utf-8")
        (build / name).write_bytes(payload)
        rendered_records.append({"file": name, "sha256": _hash_bytes(payload),
                                 "bytes": len(payload)})

    manifest = _read_json(build / "soc_manifest.json", "%s:manifest" % cell_id)
    modules = _rendered_modules(rendered)
    top_module, top_name = _top_module(manifest, modules, cell_id)
    ports = _parse_ports(rendered[top_name], rendered, cell_id)
    rendered_boot_address = _rendered_boot_address(rendered[top_name])

    layout, mapping = _input_layout(stimulus, ports, cell_id)
    transport = build_rfuzz_transport(layout)
    (build / "rfuzz_input_transport.json").write_bytes(
        canonical_bytes(transport.document()))
    (build / "rfuzz_input_transport.sv").write_text(
        transport.render_systemverilog(), encoding="utf-8")
    (build / "input_layout.json").write_bytes(
        canonical_bytes(input_layout_document(layout)))

    coverage_ports = _coverage_ports(ports, cell_id)
    source_closure = _source_closure(manifest, root, cell_id)
    simulator_args = ()
    boot_document = None
    preloaded = [region for region in plan["address_map"]["memory_regions"]
                 if str(region.get("initialization_policy", "")) in {"preload", "rom"}]
    source_requires_image = _sources_require_boot_image(source_closure, root)
    if source_requires_image and not preloaded:
        raise SocBuildError(
            "%s: compiled harness preloads a memory image the plan does not declare"
            % cell_id)
    if preloaded:
        reset_vector = int(cpu.get("reset_vector", 0))
        if rendered_boot_address is not None and rendered_boot_address != reset_vector:
            raise SocBuildError(
                "%s: rendered harness boots at 0x%x but the cell config declares "
                "0x%x; the render config and the plan disagree, so no boot image "
                "can be placed safely" % (cell_id, rendered_boot_address, reset_vector))
        boot_document, simulator_args = _boot_image(
            build, plan, cell, cell_path, cpu, cell_id, mode, config, stimulus,
            preloaded)

    (build / "live_tb.sv").write_text(
        _testbench(layout, mapping, ports, top_module, coverage_ports),
        encoding="utf-8")

    command = _compile_command(verilator, build, source_closure, root, top_name)
    result = run_supervised_command(CampaignOptions(
        command=command, output_dir=build / "build",
        duration_seconds=BUILD_TIMEOUT_SECONDS, checkpoint_seconds=1,
        env={"JOBS": "1", "MAKEFLAGS": "-j1"}))
    log_path = build / "compiler.log"
    if result.get("status") != "completed" or result.get("returncode") != 0:
        raise SocBuildError(
            "%s:verilator-build-failed:status=%s:rc=%s: see %s"
            % (cell_id, result.get("status"), result.get("returncode"), log_path))
    executable = build / "obj_dir" / "Vmyfuzz_live_tb"
    if not executable.is_file():
        raise SocBuildError("%s:verilator-did-not-emit:%s" % (cell_id, executable))
    _probe_executable(executable, simulator_args, cell_id)

    constraint_hash = content_hash({
        "schema_version": "soc_campaign_constraints.v1",
        "cell_id": cell_id,
        "mode": mode,
        "bias_off": bias_off,
        "layout_hash": layout.layout_hash,
        "plan_hash": stimulus["plan_hash"],
    })
    coverage_kind = "sampled-output-bit-events-u8-saturating"
    document = {
        "schema_version": BUILD_SCHEMA,
        "cell_id": cell_id,
        "config_id": str(config.get("config_id") or cell_id),
        "mode": mode,
        "seed": seed,
        "bias_off": bias_off,
        "root": str(root),
        "render_config": str(cell_path),
        "plan_hash": stimulus["plan_hash"],
        "stimulus": {
            "schema_version": stimulus.get("schema_version"),
            "mode": stimulus.get("mode"),
            "layout_hash": layout.layout_hash,
            "raw_width": layout.raw_width,
            "total_bits": int(stimulus["raw_layout"]["total_bits"]),
            "masked_segments": list(
                stimulus.get("mode_masking", {}).get("masked_segments", [])),
        },
        "render_hash": (manifest.get("render_hash")
                        if isinstance(manifest, Mapping) else None),
        "rendered_files": rendered_records,
        "input_layout": {
            "raw_width": layout.raw_width,
            "layout_hash": layout.layout_hash,
            "fields": len(layout.fields),
            "mapped_fields": sorted(mapping["mapped"]),
            "unmapped_fields": sorted(mapping["unmapped"]),
            "port_bindings": dict(sorted(mapping["bindings"].items())),
            "unmapped_reason": (
                "the rendered harness exposes no compatible input port for these "
                "declared raw fields; the bits stay part of the ABI and are recorded "
                "here instead of being silently re-mapped"),
        },
        "transport": transport.document(),
        "coverage": {
            "kind": coverage_kind,
            "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
            "counter_count": len(coverage_ports),
            "observations": [list(item) for item in coverage_ports],
        },
        "sources": {
            "runtime_top": source_closure["runtime_top"],
            "harness_top": top_module,
            "defines": list(source_closure["defines"]),
            "include_dirs": list(source_closure["include_dirs"]),
            "source_count": len(source_closure["source_files"]),
            "source_files": [{"path": item, "sha256": _file_hash(root / item)}
                             for item in source_closure["source_files"]],
        },
        "peripherals": [{
            "id": record["id"],
            "source_lock": record["source_lock"],
            "top_module": record["top_module"],
            "protocol": list(record["protocol"]),
            "window": dict(record["window"]),
            "closure": record["closure"],
            "capabilities": dict(record["capabilities"]),
            "spot_check": record["spot_check"],
            "unverified_evidence_topics": list(record["unverified_evidence_topics"]),
        } for record in records],
        "boot_image": boot_document,
        "executable": {"path": str(executable), "sha256": _file_hash(executable)},
        "constraint_hash": constraint_hash,
        "tool": {
            "verilator": _tool_version(verilator),
            "verilator_path": verilator,
            "simulator_protocol_version": SIMULATOR_PROTOCOL_VERSION,
            "max_cycles_per_test": MAX_CYCLES,
        },
        "build_command": list(command),
        "policy": (
            "fail-closed: no behavioural CPU/peripheral fallback; the artifact is "
            "returned only after Verilator produced the executable and the protocol "
            "probe accepted it"),
    }
    document["build_hash"] = content_hash(document)
    (build / "artifact_provenance.json").write_bytes(canonical_bytes(document))
    return SocCampaignArtifact(
        layout=layout,
        transport=transport,
        executable=executable,
        coverage_ports=coverage_ports,
        projector=SocRawProjector(layout, constraint_hash),
        coverage_kind=coverage_kind,
        control_defaults={"mode": mode, "bias_off": bias_off},
        randomized_controls=(),
        simulator_args=simulator_args,
        simulator="verilator",
        isolate_tests=False,
        execution_monitor=None,
        build_document=document,
        rendered_files=tuple((item["file"], item["sha256"]) for item in rendered_records),
    )


def _rendered_boot_address(top_text):
    """The literal BOOT_ADDR the rendered harness passes to the CPU core."""
    match = re.search(r"\.BOOT_ADDR\(\s*[0-9]+'h([0-9a-fA-F]+)\s*\)", top_text)
    return int(match.group(1), 16) if match else None


def _rendered_modules(rendered):
    """Map every module name defined by the rendered document to its file."""
    modules = {}
    for name in sorted(rendered):
        text = rendered[name]
        if not isinstance(text, str):
            continue
        for match in _TOP_MODULE_RE.finditer(text):
            modules.setdefault(match.group(1), name)
    return modules


def _top_module(manifest, modules, cell_id):
    elaboration = manifest.get("real_elaboration") if isinstance(manifest, Mapping) else None
    if not isinstance(elaboration, Mapping):
        raise SocBuildError(
            "%s: rendered manifest has no real_elaboration closure" % cell_id)
    for key in ("wrapper_top", "runtime_top", "harness_top"):
        name = elaboration.get(key)
        if isinstance(name, str) and name in modules:
            return name, modules[name]
    for fallback in ("myfuzz_soc_top",):
        if fallback in modules:
            return fallback, modules[fallback]
    raise SocBuildError("%s: no rendered file defines the harness top" % cell_id)


def _parse_ports(text, rendered, cell_id):
    """Parse the ANSI port list of the generated harness top."""
    match = _TOP_MODULE_RE.search(text)
    if match is None:
        raise SocBuildError("%s: harness top has no module declaration" % cell_id)
    start = text.index("(", match.end()) if "(" in text[match.end():] else -1
    if start < 0:
        raise SocBuildError("%s: harness top has no port list" % cell_id)
    end = text.find("\n);", start)
    if end < 0:
        raise SocBuildError("%s: harness top port list is not terminated" % cell_id)
    header = text[start:end]
    parameters = _render_parameters(rendered, cell_id)
    ports = []
    names = set()
    for port in _PORT_RE.finditer(header):
        direction, packed, name = port.group(1), port.group(2), port.group(3)
        if name in names:
            raise SocBuildError("%s: duplicate harness port: %s" % (cell_id, name))
        names.add(name)
        ports.append({"name": name, "direction": direction,
                      "width": _packed_width(packed, parameters, cell_id, name)})
    if not ports:
        raise SocBuildError("%s: harness top port list is empty" % cell_id)
    inouts = [port["name"] for port in ports if port["direction"] == "inout"]
    if inouts:
        raise SocBuildError("%s: inout harness ports are unsupported: %s"
                            % (cell_id, ", ".join(inouts)))
    return ports


def _render_parameters(rendered, cell_id):
    document = rendered.get("soc_parameters.json")
    if not isinstance(document, str):
        raise SocBuildError("%s: rendered soc_parameters.json is missing" % cell_id)
    try:
        values = json.loads(document)
    except ValueError as error:
        raise SocBuildError("%s: rendered soc_parameters.json is invalid" % cell_id) from error
    parameters = {}
    for key, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise SocBuildError("%s: rendered parameter %s is not an integer"
                                % (cell_id, key))
        parameters[str(key).upper()] = value
    for required in ("ADDRESS_WIDTH", "DATA_WIDTH"):
        if required not in parameters:
            raise SocBuildError("%s: rendered parameter %s is missing"
                                % (cell_id, required))
    return parameters


def _packed_width(packed, parameters, cell_id, port):
    if packed is None:
        return 1
    body = packed.strip()[1:-1].strip()
    if ":" not in body:
        raise SocBuildError("%s: unsupported packed dimension on %s: %s"
                            % (cell_id, port, packed))
    msb, _, lsb = body.rpartition(":")
    return (_width_value(msb, parameters, cell_id, port)
            - _width_value(lsb, parameters, cell_id, port) + 1)


def _width_value(expression, parameters, cell_id, port):
    substituted = expression
    for name, value in parameters.items():
        substituted = re.sub(r"\b%s\b" % re.escape(name), str(int(value)), substituted)
    if not _SAFE_WIDTH_RE.match(substituted):
        raise SocBuildError("%s: unsupported width expression on %s: %s"
                            % (cell_id, port, expression))
    # The substituted text is digits and arithmetic operators only; evaluating it
    # keeps the harness correct for parameterized generated ports.
    return int(eval(substituted, {"__builtins__": {}}, {}))  # noqa: S307


def _field_port(item, name, inputs, taken):
    """Return the harness input port a declared raw field drives, if any."""
    candidates = []
    declared = item.get("port")
    if isinstance(declared, str) and declared:
        candidates.append(declared)
    candidates.append(name)
    for candidate in candidates:
        for suffix in ("", "_i"):
            port = candidate + suffix
            if port in inputs and port not in taken:
                return port
    return None


def _input_layout(stimulus, ports, cell_id):
    """Build the input layout from the compiled 'soc_stimulus.v1' raw ABI."""
    raw_layout = stimulus.get("raw_layout")
    if not isinstance(raw_layout, Mapping):
        raise SocBuildError("%s: stimulus has no raw_layout" % cell_id)
    raw_width = raw_layout.get("total_bits")
    if isinstance(raw_width, bool) or not isinstance(raw_width, int) or raw_width <= 0:
        raise SocBuildError("%s: stimulus raw width is invalid" % cell_id)
    inputs = {port["name"] for port in ports if port["direction"] == "input"}
    taken = set()
    fields = []
    mapped, unmapped, bindings = [], [], {}
    for segment in raw_layout.get("segments", []):
        segment_id = str(segment["segment_id"])
        base_bit = int(segment["base_bit"])
        for item in segment["fields"]:
            name = str(item["name"])
            width = int(item["width"])
            raw_lo = base_bit + int(item["lsb"])
            if width <= 0 or raw_lo < 0 or raw_lo + width > raw_width:
                raise SocBuildError("%s: raw field outside the layout: %s.%s"
                                    % (cell_id, segment_id, name))
            port = None
            if not item.get("padding"):
                port = _field_port(item, name, inputs, taken)
            label = "%s.%s" % (segment_id, name)
            if port is None:
                unmapped.append(label)
            else:
                taken.add(port)
                mapped.append(label)
                bindings[label] = port
            fields.append(LayoutField(
                field_id=label,
                owner=segment_id,
                role=str(item.get("role", "data")),
                width=width,
                raw_lo=raw_lo,
                raw_hi=raw_lo + width - 1,
                encoding=str(item.get("encoding", "uint")),
                constraint={} if item.get("padding") else {"randomizable": True},
                port=port or "",
                direction="input",
                provenance={"segment_id": segment_id, "bit_offset": raw_lo},
            ))
    fields.sort(key=lambda field: field.raw_lo)
    provisional = InputLayout("input_layout.v1", raw_width, tuple(fields), "pending")
    document = input_layout_document(provisional)
    document.pop("layout_hash")
    for entry in document["fields"]:
        entry.pop("provenance", None)
    # Bare sha256 hex, matching myfuzz.composition.input_layout's own layout
    # identity convention.
    layout = replace(provisional,
                     layout_hash=hashlib.sha256(canonical_bytes(document)).hexdigest())
    return layout, {"mapped": mapped, "unmapped": unmapped, "bindings": bindings}


def _coverage_ports(ports, cell_id):
    """Bounded output-bit observations in declaration order."""
    observations = []
    for port in ports:
        if port["direction"] != "output":
            continue
        for bit in range(min(port["width"], COUNTER_BITS_PER_PORT)):
            observations.append((port["name"], bit))
            if len(observations) >= COUNTER_LIMIT:
                return tuple(observations)
    if not observations:
        raise SocBuildError("%s: harness top has no observable output port" % cell_id)
    return tuple(observations)


def _source_closure(manifest, root, cell_id):
    elaboration = manifest.get("real_elaboration") if isinstance(manifest, Mapping) else None
    if not isinstance(elaboration, Mapping):
        raise SocBuildError(
            "%s: rendered manifest has no real_elaboration closure" % cell_id)
    files = elaboration.get("source_files")
    includes = elaboration.get("include_dirs", [])
    defines = elaboration.get("defines", [])
    for label, value in (("source_files", files), ("include_dirs", includes),
                         ("defines", defines)):
        if (not isinstance(value, Sequence) or isinstance(value, (str, bytes))
                or not all(isinstance(item, str) and item for item in value)):
            raise SocBuildError("%s: rendered %s is invalid" % (cell_id, label))
    if not files:
        raise SocBuildError("%s: rendered closure has no source files" % cell_id)
    missing = [item for item in files if not (root / item).is_file()]
    if missing:
        raise SocBuildError(
            "%s: closure source missing: %s" % (cell_id, ", ".join(sorted(missing)[:5])))
    return {
        "runtime_top": elaboration.get("runtime_top"),
        "source_files": [str(item) for item in files],
        "include_dirs": [str(item) for item in includes],
        "defines": [str(item) for item in defines],
    }


def _sources_require_boot_image(closure, root):
    for relative in closure["source_files"]:
        path = root / relative
        if path.suffix not in (".sv", ".v"):
            continue
        if ".LOAD_IMAGE(1)" in path.read_text(encoding="utf-8", errors="replace"):
            return True
    return False


def _boot_image(build, plan, cell, cell_path, cpu, cell_id, mode, config, stimulus,
                preloaded):
    """Build the deterministic campaign boot image for one preloaded region.

    The image places a real RV32I/RV64I pass-and-loop program at the CPU's first
    fetch address inside the preloaded region, so the real CPU executes from the
    pinned memory model.  It is not a behavioural CPU and it never substitutes
    for RFuzz mutation: the mutator still drives the MMIO/environment ABI.
    """
    if len(preloaded) != 1:
        raise SocBuildError(
            "%s: exactly one preloaded memory region is supported, found %d"
            % (cell_id, len(preloaded)))
    region = preloaded[0]
    base = int(region["base"])
    size = int(region["size"])
    reset_vector = int(cpu.get("reset_vector", 0))
    fetch_offset = cpu.get("fetch_offset")
    if fetch_offset is None:
        fetch_offset = config.get("boot_image_fetch_offset")
    if fetch_offset is None:
        fetch_offset = _CPU_FETCH_OFFSETS.get(str(cpu.get("id") or cpu.get("source_lock")))
    if fetch_offset is None:
        raise SocBuildError(
            "%s: unknown first-fetch offset for cpu %s"
            % (cell_id, cpu.get("source_lock")))
    image_offset = reset_vector + int(fetch_offset) - base
    if image_offset < 0 or image_offset % 4 or image_offset + 4 > size:
        raise SocBuildError(
            "%s: boot image offset %d is outside the preloaded region at %d"
            % (cell_id, image_offset, base))
    writable = [item for item in plan["address_map"]["memory_regions"]
                if item.get("permissions", {}).get("write")]
    pass_address = int(writable[0]["base"]) if writable else 0
    xlen = int(cpu["xlen"])
    extensions = "".join(str(item).lower() for item in cpu.get("extensions", [])
                         if str(item).isalnum())
    isa = "rv%d%s" % (xlen, extensions or "i")
    facts = RiscvExecutionFacts(
        isa=isa, xlen=xlen, reset_vector=image_offset,
        pass_address=pass_address, pass_value=0x600DCAFE,
        protocol=tuple(cpu["protocol"]), max_cycles=MAX_CYCLES,
        provenance=RiscvExecutionProvenance(
            source_identity="%s:boot-stub" % cell_id,
            source_hash=content_hash({"cell_config": str(cell_path),
                                      "cell": copy.deepcopy(dict(cell))}),
            profile_identity="%s:%s:campaign-boot-stub" % (cell_id, mode),
            profile_hash=content_hash({"cell": cell_id, "mode": mode,
                                       "image_offset": image_offset,
                                       "isa": isa}),
            interface_identity=str(stimulus["plan_hash"]),
            interface_hash=str(stimulus["plan_hash"]),
            isa=isa, xlen=xlen, reset_vector=image_offset))
    try:
        image = build_minimal_boot_image(facts, build / "boot")
    except (OSError, ValueError, RuntimeError) as error:
        raise SocBuildError("%s:boot-image-build-failed:%s" % (cell_id, error)) from error
    document = {
        "role": ("campaign boot stub: real CPU execution from the pinned memory model; "
                 "RFuzz still mutates the MMIO/environment raw ABI"),
        "region": {"region_id": region["region_id"], "base": base, "size": size,
                   "initialization_policy": region.get("initialization_policy")},
        "image_offset": image_offset,
        "cpu_reset_vector": reset_vector,
        "cpu_fetch_offset": int(fetch_offset),
        "pass_address": pass_address,
        "pass_value": "0x600dcafe",
        "isa": isa,
        "compiler": image.compiler,
        "command": list(image.command),
        "memory_hex": image.memory_hex_path.name,
        "memory_hex_sha256": image.memory_hex_hash,
        "binary_size": image.binary_size,
    }
    return document, ("+riscv_boot_image=%s" % image.memory_hex_path,)


_RESERVED_TB_NAMES = frozenset((
    "raw_bits", "counters", "count", "scan", "i", "j", "request_id",
    "last_request_id", "clk", "reset",
))


def _clock_and_reset(ports, cell_id):
    names = {port["name"] for port in ports}
    clock = next((name for name in ("clk", "clk_i", "clock", "clock_i") if name in names), None)
    reset = next((name for name in ("reset", "reset_i", "rst", "rst_i", "reset_ni",
                                    "rst_ni", "resetn") if name in names), None)
    if clock is None or reset is None:
        raise SocBuildError("%s: harness top must expose a clock and a reset" % cell_id)
    active_low = reset.endswith("_ni") or reset.endswith("_n")
    return clock, reset, ("1'b0" if active_low else "1'b1"), ("1'b1" if active_low else "1'b0")


def _testbench(layout, mapping, ports, top_module, coverage_ports):
    """Generate the persistent harness that speaks simulator protocol 2."""
    clock, reset, reset_active, reset_inactive = _clock_and_reset(ports, top_module)
    driven = {}
    for field in layout.fields:
        if field.port:
            driven[field.port] = (field.raw_lo, field.raw_hi)
    widths = {port["name"]: port["width"] for port in ports}
    lines = []
    add = lines.append
    add("// Generated by myfuzz.integration.soc_builder (%s)." % BUILD_SCHEMA)
    add("// Persistent RFuzz harness: one raw %d-bit stimulus sample per cycle," % layout.raw_width)
    add("// %d saturating 8-bit output-bit event counters." % len(coverage_ports))
    add("module myfuzz_live_tb;")
    add("  localparam integer RAW_WIDTH = %d;" % layout.raw_width)
    add("  localparam integer COUNTER_COUNT = %d;" % len(coverage_ports))
    add("  logic clk = 1'b0;")
    add("  logic reset = %s;" % reset_inactive)
    add("  logic [RAW_WIDTH-1:0] raw_bits = '0;")
    add("  logic [7:0] counters [0:COUNTER_COUNT-1];")
    add("  logic [COUNTER_COUNT*8-1:0] counter_bits = '0;")
    add("  integer count, scan, i, j;")
    add("  logic [63:0] request_id, last_request_id = 64'd0;")
    for port in ports:
        name = port["name"]
        width = port["width"]
        packed = "" if width == 1 else "[%d:0] " % (width - 1)
        if name in (clock, reset):
            continue
        if name in _RESERVED_TB_NAMES:
            raise SocBuildError("harness port collides with the harness internals: %s" % name)
        if port["direction"] == "output":
            add("  wire %s%s;" % (packed, name))
        elif name in driven:
            add("  wire %s%s;" % (packed, name))
        else:
            idle = _IDLE_INPUTS.get(name, 0)
            add("  logic %s%s = %s;" % (packed, name, "1'b1" if idle else "'0"))
    add("  %s dut(" % top_module)
    connections = [".%s(clk)" % clock, ".%s(reset)" % reset]
    connections.extend(".%s(%s)" % (port["name"], port["name"])
                       for port in ports if port["name"] not in (clock, reset))
    add("    " + ",\n    ".join(connections))
    add("  );")
    for name in sorted(driven):
        raw_lo, raw_hi = driven[name]
        if raw_lo == raw_hi:
            add("  assign %s = raw_bits[%d];" % (name, raw_lo))
        else:
            add("  assign %s = raw_bits[%d:%d];" % (name, raw_hi, raw_lo))
    for label in sorted(mapping["unmapped"]):
        add("  // raw field %s has no matching harness input port and stays unmapped." % label)
    add("  task tick; begin #5 clk=1'b1; #5 clk=1'b0; end endtask")
    add("  initial begin")
    add("    clk=1'b0; reset=%s;" % reset_inactive)
    add('    $display("RFUZZ_READY %d"); $fflush();' % SIMULATOR_PROTOCOL_VERSION)
    add("    forever begin")
    add('      scan=$fscanf(32\'h80000000,"%h %d",request_id,count);')
    add("      if (scan == -1) $finish;")
    add('      if (scan != 2 || request_id == 0 || request_id <= last_request_id) $fatal(1,"request id");')
    add("      last_request_id=request_id;")
    add('      if (count < 1 || count > %d) $fatal(1,"cycle count");' % MAX_CYCLES)
    add("      raw_bits='0;")
    # Two reset clocks clear the CPU, fabric, IRQ and coverage state at every
    # sample boundary.  The pinned memory models rewrite their whole array on
    # each clock while reset is asserted, so a longer hold multiplies the
    # per-sample cost without adding reset coverage.
    add("      reset=%s; repeat (2) tick(); reset=%s;" % (reset_active, reset_inactive))
    add("      for (j=0;j<COUNTER_COUNT;j=j+1) counters[j]=8'h00;")
    add("      for (i=0;i<count;i=i+1) begin")
    add('        scan=$fscanf(32\'h80000000,"%h",raw_bits);')
    add('        if (scan != 1) $fatal(1,"raw sample");')
    add("        tick();")
    for index, (name, bit) in enumerate(coverage_ports):
        expression = ("dut.%s" % name if widths[name] == 1
                      else "dut.%s[%d]" % (name, bit))
        add('        if (%s !== 1\'b0 && %s !== 1\'b1) $fatal(1,"unknown observation");'
            % (expression, expression))
        add("        if (%s && counters[%d] != 8'hff) counters[%d] = counters[%d] + 1'b1;"
            % (expression, index, index, index))
    add("      end")
    # Pack the counters into one wide vector: a single %h conversion keeps the
    # reply exactly COUNTER_COUNT*2 lowercase hex digits and avoids one slow
    # $write formatting call per counter, which otherwise dominates runtime.
    add("      counter_bits='0;")
    add("      for (j=0;j<COUNTER_COUNT;j=j+1) counter_bits=(counter_bits<<8)|{56'd0,counters[j]};")
    add('      $write("RFUZZ_COUNTERS %016h %h\\n",request_id,counter_bits);')
    add("      $fflush();")
    add("    end")
    add("  end")
    add("endmodule")
    return "\n".join(lines) + "\n"


def _compile_command(verilator, build, closure, root, top_name):
    warnings = ("-Wno-fatal", "-Wno-PINMISSING", "-Wno-WIDTHEXPAND", "-Wno-WIDTHTRUNC",
                "-Wno-MULTIDRIVEN", "-Wno-UNSIGNED", "-Wno-CASEINCOMPLETE", "-Wno-LATCH",
                "-Wno-UNOPTFLAT")
    command = ("nice", "-n15", str(verilator), "--binary", "--timing",
               "--top-module", "myfuzz_live_tb", "-j", "1",
               "--Mdir", str(build / "obj_dir"), *warnings,
               *("-D" + item for item in closure["defines"]),
               *("-I" + str((root / item).resolve()) for item in closure["include_dirs"]),
               *[str((root / item).resolve()) for item in closure["source_files"]],
               str(build / top_name), str(build / "rfuzz_input_transport.sv"),
               str(build / "live_tb.sv"))
    log_path = build / "compiler.log"
    return (sys.executable, "-c",
            "import subprocess,sys; "
            "log=open(sys.argv[1],'wb'); "
            "result=subprocess.call(sys.argv[2:],stdout=log,stderr=subprocess.STDOUT); "
            "log.close(); sys.exit(result)", str(log_path), *command)


def _probe_executable(executable, simulator_args, cell_id):
    """Refuse to publish an executable that cannot speak protocol 2."""
    try:
        result = subprocess.run((str(executable), *simulator_args),
                                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=PROBE_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SocBuildError("%s:executable-probe-failed:%s" % (cell_id, error)) from error
    output = (result.stdout or "") + (result.stderr or "")
    expected = "RFUZZ_READY %d" % SIMULATOR_PROTOCOL_VERSION
    if result.returncode != 0 or expected not in output:
        raise SocBuildError(
            "%s:executable-protocol-probe-failed:rc=%s:output=%s"
            % (cell_id, result.returncode, output[-2000:].replace("\n", " | ")))


__all__ = [
    "BUILD_SCHEMA",
    "CLOSURE_DIR",
    "PERIPHERAL_FACTS",
    "SocBuildError",
    "SocCampaignArtifact",
    "build_soc_campaign_artifact",
]
