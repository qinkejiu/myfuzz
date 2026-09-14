"""Deterministic source-backed SoC harness rendering.

The renderer is deliberately a small boundary between the validated JSON
contracts and a generated HDL harness.  It does not infer ports from names or
silently replace a missing CPU/peripheral source with a behavioural model.  A
rendered document records the source-lock identities, every generated file,
and whether real elaboration is still pending.

Two render profiles exist.

'cell profile' (the general, data-driven path): a plan whose provenance
records 'render_config' (the cell config the planner used) is rendered from
the validated plan plus that cell config:

* the CPU source closure comes from configs/soc/sources.lock.json (ordered
  'files', or the flattened filelist closure when the lock declares one),
* every peripheral's closure files, include roots, defines and parameters
  come from the closure the cell config declares (by default
  configs/soc/closures/<source_lock>.json),
* the target-side adapter is resolved by resolve_target_adapter from the
  plan's recorded protocol and capability facts,
* the fabric (soc_arbiter, soc_router, mmio_width_adapter) is instantiated
  from the plan's own fabric document,
* the environment peers and the IRQ router are instantiated only for the
  peripherals that declare such a contract,
* each real peripheral is wrapped by the source-backed module
  soc_<source_lock>_target; a missing closure, a missing wrapper, an
  unresolved protocol or a config/plan disagreement is a SocRenderError
  naming the cell and the peripheral.

'legacy P10 profile' (byte-frozen compatibility path): a plan without a
recorded render config keeps the exact P10 Ibex+PULP document
(soc_ibex_pulp_core and its frozen source/include tuples) so previously
rendered plans keep reproducing byte for byte.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.integration.soc_coverage import build_coverage_universe

from .cva6_source_closure import Cva6SourceClosureError, resolve_cva6_source_closure
from .soc_contracts import SocContractError, soc_plan_hash, validate_soc_plan, validate_soc_stimulus
from .target_adapters import TargetAdapterError, resolve_target_adapter


RENDER_SCHEMA = "soc_render.v1"
ROOT = Path(__file__).resolve().parents[3]
CLOSURE_DIR = "configs/soc/closures"
SOURCES_LOCK = "configs/soc/sources.lock.json"
WRAPPER_DIR = "src/myfuzz/composition/rtl"
RTL_DIR = "src/myfuzz/protocols/rtl"
MEMORY_MODEL = "src/myfuzz/integration/rtl/riscv_boot_memory.sv"

#: Harness peers keyed by the environment link protocol.  Only peripherals
#: that declare such a link get a peer instance; a declared link whose
#: protocol has no peer is recorded, never silently substituted.
_ENVIRONMENT_PEERS = {
    "uart-serial": {
        "module": "fuzz_uart_peer",
        "source": RTL_DIR + "/fuzz_uart_peer.sv",
        "parameters": (
            ("DATA_WIDTH", ("DATA_WIDTH", "bits", "width"), 8),
            ("BAUD_DIV", ("BAUD_DIV", "baud_div"), 1),
            ("FRAME_BITS", ("FRAME_BITS", "frame_bits"), 10),
        ),
    },
    "spi-miso": {
        "module": "fuzz_spi_peer",
        "source": RTL_DIR + "/fuzz_spi_peer.sv",
        "parameters": (
            ("BITS", ("BITS", "bits"), 8),
            ("CPOL", ("CPOL", "cpol"), 0),
            ("CPHA", ("CPHA", "cpha"), 0),
        ),
    },
}

_IRQ_ROUTER_SOURCE = RTL_DIR + "/soc_irq_router.sv"
_CPU_LANE_PREFIX = {"cpu_instruction": "instr", "cpu_data": "data", "cpu_unified": "unified"}
_IRQ_MARKER = "// MYFUZZ_IRQ_OUTPUTS:"
_CORE_DEPENDENCY_MARKER = "// MYFUZZ_CORE_DEPENDENCIES:"

#: Frozen P10 Ibex+PULP profile.  A plan without a recorded render config
#: keeps reproducing this document byte for byte.
_LEGACY_RTL_SOURCES = (
    "src/myfuzz/protocols/rtl/fuzz_mmio_master.sv",
    "src/myfuzz/protocols/rtl/fuzz_uart_peer.sv",
    "src/myfuzz/protocols/rtl/fuzz_spi_peer.sv",
    "src/myfuzz/protocols/rtl/soc_irq_router.sv",
    "src/myfuzz/protocols/rtl/soc_arbiter.sv",
    "src/myfuzz/protocols/rtl/soc_router.sv",
    "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
    "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv",
    "src/myfuzz/protocols/rtl/processor_memory_backend.sv",
    "src/myfuzz/protocols/rtl/processor_apb_bridge.sv",
    "src/myfuzz/integration/rtl/riscv_boot_memory.sv",
    "src/myfuzz/composition/rtl/soc_ibex_pulp_core.sv",
)
_LEGACY_SOURCE_BACKED_CLOSURE = (
    "third_party/rfuzz/upstream/ibex/sources.f",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv",
    "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
    "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
    "third_party/soc-pulp-apb-spi/spi_master_apb_if.sv",
    # The APB SPI checkout records these as symlinks to the sibling AXI SPI
    # closure.  Keep the resolved source identities explicit so a clean
    # checkout does not silently omit the real controller/FIFO RTL.
    "third_party/soc-pulp-axi-spi/spi_master_clkgen.sv",
    "third_party/soc-pulp-axi-spi/spi_master_controller.sv",
    "third_party/soc-pulp-axi-spi/spi_master_fifo.sv",
    "third_party/soc-pulp-axi-spi/spi_master_rx.sv",
    "third_party/soc-pulp-axi-spi/spi_master_tx.sv",
)
_LEGACY_IBEX_SOURCE_FILES = (
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_util_pkg.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_count_pkg.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_ram_1p_pkg.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_pkg.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_cheriot_pkg.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_cheriot_ex.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_alu.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_branch_predict.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_compressed_decoder.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_controller.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_cs_registers.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_csr.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_counter.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_decoder.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_ex_block.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_fetch_fifo.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_id_stage.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_if_stage.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_load_store_unit.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_multdiv_fast.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_multdiv_slow.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_prefetch_buffer.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_pmp.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_wb_stage.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_dummy_instr.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_register_file_ff.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_trvk.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_lockstep.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_icache.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv",
    "third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_assert.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_cipher_pkg.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_lfsr.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_mubi_pkg.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_mubi4_dec.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_pkg.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_inv_39_32_enc.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_inv_39_32_dec.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_inv_64_57_enc.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl/prim_secded_inv_64_57_dec.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_buf.sv",
    "third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim_generic/rtl/prim_clock_gating.sv",
)
_LEGACY_REAL_INCLUDE_DIRS = (
    "+incdir+third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim/rtl",
    "+incdir+third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/ip/prim_generic/rtl",
    "+incdir+third_party/rfuzz/upstream/ibex/vendor/lowrisc_ip/dv/sv/dv_utils",
    "+incdir+third_party/rfuzz/upstream/ibex/vendor/pulp_common_cells/rtl",
)


class SocRenderError(ValueError):
    """Raised when a validated SoC cannot be rendered safely."""


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SocRenderError(f"{label}:mapping-required")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SocRenderError(f"{label}:positive-integer-required")
    return value


def _resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _read_json(path: Path, label: str, where: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SocRenderError(f"{where}{label}-unreadable:{path}") from error


def _source_records(plan: Mapping[str, object]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    seen: set[str] = set()

    def add(path: object, *, role: str, source_lock: object = None) -> None:
        if path is None:
            return
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/"):
            raise SocRenderError(f"source-path:{path}")
        if path in seen:
            return
        seen.add(path)
        records.append({"path": path, "role": role, **(
            {"source_lock": source_lock} if isinstance(source_lock, str) else {}
        )})

    execution = _require_mapping(plan.get("processor_execution"), "processor_execution")
    for value in execution.get("adapter_sources", []):
        add(value, role="cpu_adapter")
    for route in execution.get("routes", []):
        if isinstance(route, Mapping):
            add(route.get("rtl_source"), role="cpu_adapter")
    for adapter in plan.get("adapters", []):
        if isinstance(adapter, Mapping):
            add(adapter.get("rtl_source"), role="target_adapter")
    capabilities = _require_mapping(plan.get("target_capabilities"), "target_capabilities")
    for target_id, record in capabilities.items():
        if not isinstance(record, Mapping):
            raise SocRenderError(f"target-capabilities:{target_id}")
        for field in ("adapter", "fabric_adapter"):
            value = record.get(field)
            if isinstance(value, Mapping):
                add(value.get("source"), role=f"{field}:{target_id}")
    for source in _LEGACY_RTL_SOURCES:
        add(source, role="generated_harness")
    for source in _LEGACY_SOURCE_BACKED_CLOSURE:
        add(source, role="source_backed_closure")
    for source in _LEGACY_IBEX_SOURCE_FILES:
        add(source, role="source_backed_cpu_closure", source_lock="ibex")

    # The plan binds source-lock ids on instances.  Preserve those ids even
    # when their concrete checkout is resolved by the campaign runner.
    for instance in plan.get("instances", []):
        if isinstance(instance, Mapping):
            lock = instance.get("source_lock")
            top = instance.get("top_module")
            if isinstance(lock, str) and isinstance(top, str):
                records.append({"source_lock": lock, "top_module": top,
                                "role": str(instance.get("kind", "component")),
                                "instance_id": str(instance.get("instance_id", ""))})
    return records


def _window_parameters(plan: Mapping[str, object]) -> tuple[int, int, int, int, int, str, str]:
    windows = _require_mapping(plan.get("address_map"), "address_map").get("windows")
    if not isinstance(windows, Sequence) or isinstance(windows, (str, bytes)) or not windows:
        raise SocRenderError("address-map:windows-required")
    values = [item for item in windows if isinstance(item, Mapping)]
    if len(values) != len(windows):
        raise SocRenderError("address-map:window-record")
    widths = []
    for item in values:
        window = _require_mapping(item.get("window"), "address-map:window")
        base, size = window.get("base"), window.get("size")
        _positive_int(size, "address-map:size")
        if isinstance(base, bool) or not isinstance(base, int) or base < 0:
            raise SocRenderError("address-map:base")
        widths.extend((base.bit_length(), (base + size - 1).bit_length()))
    address_width = max(1, max(widths, default=32), 32)
    # Keep the generated harness on the frozen 32-bit Ibex/MMIO boundary.
    if address_width > 32:
        raise SocRenderError("address-map:address-width-exceeds-ibex")
    data_widths = [
        int(_require_mapping(value, "target-capability").get("data_width", 32))
        for value in _require_mapping(plan.get("target_capabilities"), "target-capabilities").values()
        if isinstance(value, Mapping)
    ]
    data_width = max(data_widths or [32])
    if data_width not in (32, 64):
        raise SocRenderError("target-capabilities:data-width")
    selector_width = max(1, (len(values)).bit_length())
    invalid = len(values)
    bases = sum(int(_require_mapping(item.get("window"), "window")["base"]) << (index * address_width)
                for index, item in enumerate(values))
    sizes = sum(int(_require_mapping(item.get("window"), "window")["size"]) << (index * address_width)
                for index, item in enumerate(values))
    return address_width, data_width, selector_width, invalid, len(values), f"{bases:x}", f"{sizes:x}"


def _environment_contract(stimulus: Mapping[str, object]) -> Mapping[str, object]:
    value = stimulus.get("environment_contract")
    if not isinstance(value, Mapping):
        raise SocRenderError("environment-contract:missing")
    links = value.get("links")
    routes = value.get("interrupt_routes")
    if not isinstance(links, list) or not isinstance(routes, list):
        raise SocRenderError("environment-contract:links-routes")
    for link in links:
        if not isinstance(link, Mapping) or not isinstance(link.get("link_id"), str):
            raise SocRenderError("environment-contract:link-record")
    for route in routes:
        if not isinstance(route, Mapping) or not isinstance(route.get("route_id"), str):
            raise SocRenderError("environment-contract:route-record")
    return value


def _render_top(plan: Mapping[str, object], stimulus: Mapping[str, object], contract: Mapping[str, object]) -> str:
    address_width, data_width, selector_width, selector_invalid, windows, bases, sizes = _window_parameters(plan)
    priority_literal = "{3{4'd1}}"
    # The generated top intentionally exposes raw environment offers and the
    # driver counters.  CPU/IP source closure is supplied by sources.f and is
    # never replaced by a Python-side response model.
    return f'''// Generated by myfuzz.composition.soc_renderer ({RENDER_SCHEMA}).
// Source-backed CPU binding: ibex_top (configs/soc/sources.lock.json).
// Peripheral bindings: real PULP APB GPIO and APB SPI closures.
// The MYFUZZ_REAL_IBEX define enables the source-backed CPU instance in the
// campaign build; without it this file is a structural preflight harness.
module myfuzz_soc_top #(
  parameter integer ADDRESS_WIDTH = {address_width},
  parameter integer DATA_WIDTH = {data_width}
) (
  input logic clk_i,
  input logic reset_i,
  input logic env_offer_i,
  input logic [DATA_WIDTH-1:0] env_data_i,
  input logic spi_sck_i,
  input logic spi_cs_i,
  input logic [7:0] gpio_in_i,
  input logic irq_claim_i,
  input logic irq_complete_i,
  input logic stim_offer_i,
  input logic [{selector_width-1}:0] stim_target_selector_i,
  input logic [ADDRESS_WIDTH-1:0] stim_offset_i,
  input logic stim_write_i,
  input logic [DATA_WIDTH-1:0] stim_wdata_i,
  input logic [DATA_WIDTH/8-1:0] stim_be_i,
  output logic uart_rx_o,
  output logic spi_miso_o,
  output logic irq_o,
  output logic [31:0] env_drop_count_o,
  output logic cpu_irq_o,
  output logic [31:0] gpio_out_o,
  output logic [31:0] gpio_dir_o,
  output logic gpio_irq_o,
  output logic spi_clk_o,
  output logic spi_cs0_o,
  output logic spi_sdo0_o,
  output logic cpu_mmio_transaction_o,
  output logic fuzz_mmio_transaction_o,
  output logic [31:0] cpu_transaction_count_o,
  output logic [31:0] fuzz_transaction_count_o,
  output logic [31:0] cpu_completion_count_o,
  output logic [31:0] fuzz_completion_count_o,
  output logic fabric_protocol_error_o
);
  logic uart_ready, uart_busy;
  logic spi_ready, spi_busy;
  logic [31:0] uart_drop, uart_sent, spi_drop, spi_sent;
  logic uart_event, spi_event;
  logic [7:0] uart_event_data;
  logic [7:0] spi_event_data;
  logic [2:0] irq_pending;
  logic [2:0] irq_service;
  logic irq_claim_valid;
  logic [1:0] irq_claim_id;
  logic [2:0] irq_sources;
  logic [11:0] irq_priority = {priority_literal};

  fuzz_uart_peer #(.DATA_WIDTH(8), .BAUD_DIV(1), .FRAME_BITS(10)) u_uart_peer (
    .clk_i(clk_i), .reset_i(reset_i), .offer_i(env_offer_i), .data_i(env_data_i[7:0]),
    .rx_o(uart_rx_o), .ready_o(uart_ready), .busy_o(uart_busy),
    .drop_count_o(uart_drop), .sent_count_o(uart_sent),
    .event_valid_o(uart_event), .event_data_o(uart_event_data));
  fuzz_spi_peer #(.BITS(8), .CPOL(0), .CPHA(0)) u_spi_peer (
    .clk_i(clk_i), .reset_i(reset_i), .offer_i(env_offer_i), .data_i(env_data_i[7:0]),
    .sck_i(spi_sck_i), .cs_i(spi_cs_i), .miso_o(spi_miso_o),
    .ready_o(spi_ready), .busy_o(spi_busy), .drop_count_o(spi_drop),
    .sent_count_o(spi_sent), .event_valid_o(spi_event), .event_data_o(spi_event_data));
  assign irq_sources = {{1'b0, spi_event, uart_event}};
  soc_irq_router #(.NUM_SOURCES(3), .SOURCE_ID_WIDTH(2), .PRIORITY_WIDTH(4)) u_irq_router (
    .source_i(irq_sources), .enable_i(3'b111), .edge_mode_i(3'b111),
    .clear_i(3'b000), .claim_i(irq_claim_i), .complete_i(irq_complete_i),
    .priority_i(irq_priority), .clk_i(clk_i), .reset_i(reset_i),
    .irq_o(irq_o), .pending_o(irq_pending), .in_service_o(irq_service),
    .claim_valid_o(irq_claim_valid), .claim_id_o(irq_claim_id));
  assign env_drop_count_o = uart_drop + spi_drop;

`ifdef MYFUZZ_ENABLE_REAL_IBEX
  // The real campaign compiles the pinned Ibex closure and the real PULP
  // closures.  The explicit define is the opt-in boundary; preflight builds
  // below still elaborate without any CPU model or constant response path.
  logic [2:0] real_stim_target_selector_i;
  assign real_stim_target_selector_i = stim_target_selector_i;
  soc_ibex_pulp_core u_ibex_pulp_core (
    .clk_i(clk_i), .reset_i(reset_i), .stim_offer_i(stim_offer_i),
    .stim_target_selector_i(real_stim_target_selector_i), .stim_offset_i(stim_offset_i),
    .stim_write_i(stim_write_i), .stim_wdata_i(stim_wdata_i), .stim_be_i(stim_be_i),
    .gpio_in_i(gpio_in_i), .spi_sck_i(spi_sck_i), .spi_cs_i(spi_cs_i),
    .irq_claim_i(irq_claim_i), .irq_complete_i(irq_complete_i),
    .gpio_out_o(gpio_out_o), .gpio_dir_o(gpio_dir_o), .gpio_irq_o(gpio_irq_o),
    .spi_clk_o(spi_clk_o), .spi_cs0_o(spi_cs0_o), .spi_sdo0_o(spi_sdo0_o),
    .cpu_irq_o(cpu_irq_o), .cpu_mmio_transaction_o(cpu_mmio_transaction_o),
    .fuzz_mmio_transaction_o(fuzz_mmio_transaction_o),
    .cpu_transaction_count_o(cpu_transaction_count_o),
    .fuzz_transaction_count_o(fuzz_transaction_count_o),
    .cpu_completion_count_o(cpu_completion_count_o),
    .fuzz_completion_count_o(fuzz_completion_count_o),
    .fabric_protocol_error_o(fabric_protocol_error_o)
  );
`else
  assign cpu_irq_o = 1'b0;
  assign gpio_out_o = '0;
  assign gpio_dir_o = '0;
  assign gpio_irq_o = 1'b0;
  assign spi_clk_o = 1'b0;
  assign spi_cs0_o = 1'b1;
  assign spi_sdo0_o = 1'b0;
  assign cpu_mmio_transaction_o = 1'b0;
  assign fuzz_mmio_transaction_o = 1'b0;
  assign cpu_transaction_count_o = '0;
  assign fuzz_transaction_count_o = '0;
  assign cpu_completion_count_o = '0;
  assign fuzz_completion_count_o = '0;
  assign fabric_protocol_error_o = 1'b0;
`endif

  // The real branch is intentionally fail-closed: no behavioural CPU or
  // peripheral response is present in this generated preflight source.
endmodule
'''


def _validated_contracts(plan: Mapping[str, object], stimulus: Mapping[str, object]) -> Mapping[str, object]:
    try:
        validate_soc_plan(dict(plan))
        validate_soc_stimulus(dict(stimulus))
    except (SocContractError, TypeError, ValueError) as error:
        raise SocRenderError(f"invalid-contract:{error}") from error
    if not isinstance(plan, Mapping) or not isinstance(stimulus, Mapping):
        raise SocRenderError("contracts:mapping-required")
    try:
        expected_plan_hash = soc_plan_hash(dict(plan))
    except Exception as error:  # pragma: no cover - validator normally catches this
        raise SocRenderError(f"identity:plan-hash:{error}") from error
    if stimulus.get("plan_hash") != expected_plan_hash:
        raise SocRenderError("identity:stimulus-plan-hash-mismatch")
    return _environment_contract(stimulus)


def _render_profile(plan: Mapping[str, object]) -> tuple[dict, str, Path] | None:
    """Return (cell config, cell id, config path) or None for the legacy profile.

    The planner records the cell config it used in the plan provenance.  Its
    absence selects the frozen P10 profile; its presence selects the general,
    data-driven profile.
    """
    provenance = plan.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    reference = provenance.get("render_config")
    if not isinstance(reference, str) or not reference:
        return None
    path = _resolve_path(reference)
    cell = str(provenance.get("cell") or plan.get("spec_id") or "<unknown-cell>")
    document = _read_json(path, "render-config", f"{cell}:")
    if not isinstance(document, Mapping) or not isinstance(document.get("peripherals"), list):
        raise SocRenderError(f"{cell}:render-config-schema:{path}")
    merged = dict(document)
    base_reference = document.get("base_profile")
    if isinstance(base_reference, str) and base_reference:
        base_path = _resolve_path(base_reference)
        base = _read_json(base_path, "base-profile", f"{cell}:")
        if not isinstance(base, Mapping):
            raise SocRenderError(f"{cell}:base-profile-schema:{base_path}")
        merged = dict(base)
        for key, value in document.items():
            if key == "peripherals":
                merged["peripherals"] = list(value)
                continue
            if key == "cpu" and isinstance(value, str) and isinstance(base.get("cpu"), Mapping):
                # A matrix cell names its CPU; the base profile owns the CPU
                # record.  A disagreement is a fail-closed error.
                base_cpu = base["cpu"]
                if value not in (base_cpu.get("id"), base_cpu.get("source_lock")):
                    raise SocRenderError(f"{cell}:cpu-declaration-mismatch:{value}")
                continue
            merged[key] = value
        merged["base_profile"] = base_reference
    merged["cell_id"] = str(document.get("cell_id") or document.get("config_id") or cell)
    return merged, merged["cell_id"], path


def render_soc(plan: Mapping[str, object], stimulus: Mapping[str, object]) -> dict[str, str]:
    """Render deterministic SoC files from validated plan/stimulus documents.

    The return value is a filename-to-text mapping.  The caller decides where
    to publish it, which keeps this function side-effect free and makes replay
    identity independent of temporary build paths.
    """
    contract = _validated_contracts(plan, stimulus)
    profile = _render_profile(plan)
    if profile is None:
        return _legacy_document(plan, stimulus, contract)
    config, cell, config_path = profile
    return _cell_document(plan, stimulus, contract, config, cell, config_path)


def _legacy_document(plan: Mapping[str, object], stimulus: Mapping[str, object],
                     contract: Mapping[str, object]) -> dict[str, str]:
    """The frozen P10 Ibex+PULP document (byte-identical compatibility path)."""
    sources = _source_records(plan)
    top = _render_top(plan, stimulus, contract)
    # The renderer carries the coverage boundary even when no backend report
    # is available yet.  An empty universe is intentional: source-instrumented
    # RTL points are populated by the campaign build, while input samples are
    # never promoted to branch evidence here.
    coverage = build_coverage_universe([], instances=[
        item for item in plan.get("instances", []) if isinstance(item, Mapping)
    ])
    manifest: dict[str, object] = {
        "schema_version": RENDER_SCHEMA,
        "plan_hash": stimulus["plan_hash"],
        "stimulus_layout_hash": stimulus.get("layout_hash"),
        "source_records": sources,
        "environment_contract": _plain(contract),
        "real_cpu": {
            "top_module": "ibex_top",
            "source_lock": "ibex",
            "status": "source_bound_pending_elaboration",
        },
        "peripherals": {
            "gpio": "source_bound_pending_elaboration",
            "spi": "source_bound_pending_elaboration",
        },
        "real_elaboration": {
            "runtime_top": "soc_ibex_pulp_core",
            "wrapper_top": "myfuzz_soc_top",
            "defines": ["MYFUZZ_ENABLE_REAL_IBEX"],
            "include_dirs": [entry.removeprefix("+incdir+") for entry in _LEGACY_REAL_INCLUDE_DIRS],
            # Keep package/dependency order: Ibex's package declarations must
            # precede the modules that import them.  dict.fromkeys gives a
            # deterministic ordered de-duplication without alphabetizing the
            # elaboration-sensitive closure.
            "source_files": list(dict.fromkeys(
                (*_LEGACY_IBEX_SOURCE_FILES, *_LEGACY_SOURCE_BACKED_CLOSURE, *_LEGACY_RTL_SOURCES)
            )),
            "elaboration_status": "source_bound",
            "runtime_status": "runtime_unverified",
        },
        "generated_modules": [
            "myfuzz_soc_top", "soc_ibex_pulp_core", "fuzz_mmio_master",
            "fuzz_uart_peer", "fuzz_spi_peer", "soc_irq_router",
        ],
        "unique_driver_policy": "one declared driver per net; elaboration required",
        "coverage": {
            "schema_version": coverage["schema_version"],
            "backend": coverage["backend"],
            "universe_hash": coverage["universe_hash"],
            "categories": coverage["categories"],
            "branch_feedback_is_rtl_only": coverage["branch_feedback_is_rtl_only"],
            "instrumentation_required": True,
        },
    }
    manifest["render_hash"] = content_hash(manifest)
    manifest_text = json.dumps(_plain(manifest), sort_keys=True, indent=2) + "\n"
    parameters = _window_parameters(plan)
    # Emit a flat, cwd-independent file list.  The APB-SPI checkout contains
    # broken portability symlinks in minimal exports, so the resolved sibling
    # AXI-SPI helper paths above are listed explicitly rather than relying on
    # a simulator to follow a missing nested file list.
    sources_text = "\n".join((*_LEGACY_REAL_INCLUDE_DIRS, *_LEGACY_IBEX_SOURCE_FILES,
                               *_LEGACY_RTL_SOURCES, *_LEGACY_SOURCE_BACKED_CLOSURE[2:])) + "\n"
    boot = (
        "/* Minimal deterministic boot/ISR acceptance image (RV32I).\n"
        " * The campaign replaces this text with a compiled image only after\n"
        " * the selected address map and CPU reset vector are validated.\n"
        " */\n"
        ".section .text.init\n"
        ".globl _start\n_start:\n  j _start\n"
        ".section .text.irq\n.globl irq_handler\nirq_handler:\n  mret\n"
    )
    return {
        "soc_top.sv": top,
        "soc_sources.f": sources_text,
        "soc_manifest.json": manifest_text,
        "soc_boot.S": boot,
        "soc_parameters.json": json.dumps({
            "address_width": parameters[0], "data_width": parameters[1],
            "selector_width": parameters[2], "selector_invalid": parameters[3],
            "num_windows": parameters[4],
        }, sort_keys=True, indent=2) + "\n",
    }



# ---------------------------------------------------------------------------
# cell profile: data-driven resolution
# ---------------------------------------------------------------------------


def _closure_document(path: Path, cell: str, peripheral: str) -> dict:
    where = f"{cell}:{peripheral}:"
    document = _read_json(path, "closure", where)
    if (not isinstance(document, Mapping)
            or document.get("schema_version") != "soc_elaboration_closure.v1"):
        raise SocRenderError(f"{where}closure-schema:{path}")
    return dict(document)


def _closure_ordered_sources(document: Mapping[str, object], cell: str,
                             peripheral: str) -> tuple[list[str], list[str], list[str]]:
    """Return (files, include_dirs, defines) in the proven closure order.

    The closure records the exact verilator command task P1 ran; its file
    arguments are the only order that is proven to elaborate (package
    declarations precede their imports).
    """
    where = f"{cell}:{peripheral}:"
    command = document.get("command")
    if not isinstance(command, Sequence) or isinstance(command, (str, bytes)):
        raise SocRenderError(f"{where}closure-command")
    files: list[str] = []
    include_dirs: list[str] = []
    for token in command:
        if not isinstance(token, str):
            continue
        if token.startswith("-I") and len(token) > 2:
            if token[2:] not in include_dirs:
                include_dirs.append(token[2:])
        elif token.endswith(".sv") or token.endswith(".v"):
            if token not in files:
                files.append(token)
    root = document.get("root")
    include_roots = document.get("include_roots")
    if isinstance(include_roots, list) and isinstance(root, str):
        for item in include_roots:
            if not isinstance(item, str):
                continue
            candidate = f"{root}/{item}"
            if candidate not in include_dirs:
                include_dirs.append(candidate)
    defines = [item for item in document.get("defines", []) if isinstance(item, str)]
    if not files:
        raise SocRenderError(f"{where}closure-files-missing")
    return files, include_dirs, defines


def _closure_recorded_files(document: Mapping[str, object]) -> list[str]:
    records = document.get("closure_files")
    if not isinstance(records, list):
        return []
    result: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        root, path = record.get("root"), record.get("path")
        if isinstance(root, str) and isinstance(path, str):
            entry = f"{root}/{path}"
            if entry not in result:
                result.append(entry)
    return result


def _lock_component(cell: str, source_lock: str) -> Mapping[str, object]:
    document = _read_json(ROOT / SOURCES_LOCK, "source-lock", f"{cell}:")
    components = document.get("components") if isinstance(document, Mapping) else None
    record = next((item for item in components or []
                   if isinstance(item, Mapping) and item.get("id") == source_lock), None)
    if not isinstance(record, Mapping):
        raise SocRenderError(f"{cell}:{source_lock}:source-lock-missing")
    return record


def _cpu_closure(cell: str, source_lock: str) -> dict:
    """Resolve the CPU source closure from the pinned source lock."""
    record = _lock_component(cell, source_lock)
    source = record.get("source")
    if not isinstance(source, Mapping):
        raise SocRenderError(f"{cell}:{source_lock}:source-record-missing")
    if source.get("filelist"):
        try:
            closure = resolve_cva6_source_closure(ROOT)
        except Cva6SourceClosureError as error:
            raise SocRenderError(f"{cell}:{source_lock}:filelist-closure:{error}") from error
        files = [str(item) for item in closure["source_files"]]
        include_dirs = [str(item) for item in closure["include_dirs"]]
        defines = [str(item) for item in closure["defines"]]
    else:
        root = source.get("root")
        raw_files = source.get("files")
        if not isinstance(root, str) or not isinstance(raw_files, list):
            raise SocRenderError(f"{cell}:{source_lock}:source-files-missing")
        files = [f"{root}/{item}" for item in raw_files]
        include_dirs = [f"{root}/{item}" for item in source.get("include_roots", [])
                        if isinstance(item, str)]
        defines = [item for item in record.get("defines", []) if isinstance(item, str)]
    if not files:
        raise SocRenderError(f"{cell}:{source_lock}:cpu-closure-empty")
    return {
        "source_lock": source_lock,
        "top_module": str(source.get("top_module", "")),
        "root": source.get("root"),
        "revision": source.get("revision"),
        "source_files": files,
        "ip_source_files": list(files),
        "include_dirs": include_dirs,
        "defines": defines,
        "source_status": record.get("source_status"),
        "elaboration_status": record.get("elaboration_status"),
        "runtime_status": record.get("runtime_status", "runtime_unverified"),
    }


def _wrapper(cell: str, peripheral: str, source_lock: str) -> dict:
    module = f"soc_{source_lock}_target"
    relative = f"{WRAPPER_DIR}/{module}.sv"
    path = ROOT / relative
    if not path.is_file():
        raise SocRenderError(f"{cell}:{peripheral}:source-backed-wrapper-missing:{relative}")
    text = path.read_text(encoding="utf-8")
    outputs: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(_IRQ_MARKER):
            outputs = stripped[len(_IRQ_MARKER):].split()
            break
    return {"module": module, "source": relative, "irq_outputs": outputs}


def _config_peripheral(config: Mapping[str, object], component_id: str,
                       source_lock: str) -> Mapping[str, object] | None:
    for entry in config.get("peripherals", []):
        if isinstance(entry, Mapping):
            if entry.get("id") == component_id or entry.get("source_lock") == source_lock:
                return entry
        elif isinstance(entry, str) and entry in (component_id, source_lock):
            return {"id": entry, "source_lock": source_lock}
    return None


def _sv_literal(value: object) -> str:
    if isinstance(value, bool):
        return "1'b1" if value else "1'b0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        text = value.strip()
        if text and (text[0].isdigit() or "'" in text):
            return text
        return '"' + text.replace('"', "") + '"'
    raise SocRenderError(f"parameter-literal:{value!r}")


def _packed(values: Sequence[int], width: int, slots: int) -> str:
    items = [f"{width}'h{int(value):x}" for value in values]
    items.extend(f"{width}'h0" for _ in range(slots - len(values)))
    if len(items) == 1:
        return items[0]
    return "{" + ", ".join(reversed(items)) + "}"



def _safe_literal(value: object) -> bool:
    if isinstance(value, bool) or isinstance(value, int):
        return True
    if isinstance(value, str):
        text = value.strip()
        if not text or "{" in text or "}" in text:
            return False
        return text[0].isdigit() or "'" in text
    return False


def _cell_records(plan: Mapping[str, object], stimulus: Mapping[str, object],
                  contract: Mapping[str, object], config: Mapping[str, object],
                  cell: str) -> dict:
    """Resolve every source-backed record the generated top needs."""
    instances = {str(item["component_id"]): item for item in plan["instances"]}
    capabilities = plan["target_capabilities"]
    plan_windows = {str(item["target_id"]): item for item in plan["address_map"]["windows"]}
    regions = {str(item["region_id"]): item for item in plan["address_map"]["memory_regions"]}
    fabric = plan["fabric"]
    fabric_parameters = fabric["rtl"]["parameters"]
    address_width = int(fabric_parameters["ADDRESS_WIDTH"])
    data_width = int(fabric_parameters["DATA_WIDTH"])

    cpu_instances = [item for item in plan["instances"] if item.get("kind") == "cpu"]
    if len(cpu_instances) != 1:
        raise SocRenderError(f"{cell}:cpu-instance-required")
    cpu_instance = cpu_instances[0]
    cpu_lock = str(cpu_instance["source_lock"])
    core_module = f"soc_{cpu_lock}_beat_core"
    core_source = f"{WRAPPER_DIR}/{core_module}.sv"
    if not (ROOT / core_source).is_file():
        raise SocRenderError(f"{cell}:{cpu_lock}:source-backed-cpu-core-missing:{core_source}")
    core_text = (ROOT / core_source).read_text(encoding="utf-8")
    core_dependencies: list[str] = []
    for line in core_text.splitlines():
        stripped = line.strip()
        if stripped.startswith(_CORE_DEPENDENCY_MARKER):
            core_dependencies = stripped[len(_CORE_DEPENDENCY_MARKER):].split()
            break
    for dependency in core_dependencies:
        if not (ROOT / dependency).is_file():
            raise SocRenderError(f"{cell}:{cpu_lock}:cpu-core-dependency-missing:{dependency}")
    cpu_closure = _cpu_closure(cell, cpu_lock)
    cpu_config = config.get("cpu") if isinstance(config.get("cpu"), Mapping) else {}
    reset_vector = cpu_config.get("reset_vector", 0)
    if isinstance(reset_vector, bool) or not isinstance(reset_vector, int) or reset_vector < 0:
        raise SocRenderError(f"{cell}:{cpu_lock}:reset-vector")
    raw_parameters = cpu_instance.get("parameters") or {}
    cpu_parameters = {str(name): value for name, value in raw_parameters.items()
                      if isinstance(name, str) and name.isidentifier() and _safe_literal(value)}
    skipped_parameters = {str(name): value for name, value in raw_parameters.items()
                          if str(name) not in cpu_parameters}

    lanes = []
    for source in fabric["sources"]:
        kind = str(source.get("kind"))
        if kind in _CPU_LANE_PREFIX:
            lanes.append({
                "index": int(source["index"]),
                "source_id": str(source["source_id"]),
                "kind": kind,
                "prefix": _CPU_LANE_PREFIX[kind],
                "instruction": bool(source.get("instruction")),
            })
    if not lanes:
        raise SocRenderError(f"{cell}:cpu-lane-missing")

    peripherals = []
    by_component: dict[str, dict] = {}
    for target in fabric["targets"]:
        if target.get("backing_kind") != "target":
            continue
        index = int(target["index"])
        rows = [row for row in fabric["decode"]["windows"] if int(row["target_index"]) == index]
        if len(rows) != 1:
            raise SocRenderError(f"{cell}:{target['backing_id']}:window-count-unsupported")
        row = rows[0]
        target_id = str(row["target_id"])
        capability = capabilities[target_id]
        component_id = str(capability["component_id"])
        instance = instances.get(component_id)
        if instance is None:
            raise SocRenderError(f"{cell}:{component_id}:instance-missing")
        declared = _config_peripheral(config, component_id, str(instance["source_lock"]))
        if declared is None:
            raise SocRenderError(f"{cell}:{component_id}:not-declared-by-cell-config")
        source_lock = str(instance["source_lock"])
        closure_reference = declared.get("closure") if isinstance(declared, Mapping) else None
        closure_path = (str(closure_reference) if isinstance(closure_reference, str) and closure_reference
                        else f"{CLOSURE_DIR}/{source_lock}.json")
        closure = _closure_document(_resolve_path(closure_path), cell, component_id)
        if (closure.get("component") != source_lock
                or closure.get("top_module") != str(instance["top_module"])):
            raise SocRenderError(f"{cell}:{component_id}:closure-identity:{closure_path}")
        protocol = [str(item) for item in capability["protocol"]]
        declared_protocol = declared.get("protocol") if isinstance(declared, Mapping) else None
        if declared_protocol is not None and [str(item) for item in declared_protocol] != protocol:
            raise SocRenderError(
                f"{cell}:{component_id}:protocol-mismatch:{declared_protocol}!={protocol}")
        target_width = int(capability.get("data_width") or 32)
        target_record = {
            "component_id": component_id,
            "target_id": target_id,
            "protocol": protocol,
            "data_width": target_width,
            "window": {"base": int(row["target_base"]), "size": int(row["size"])},
            "capabilities": dict(capability.get("capabilities") or {}),
            "evidence": dict(capability.get("evidence") or {}),
            "max_wait_cycles": int(fabric["watchdog"]["max_wait_cycles"]),
        }
        if len(protocol) > 1:
            target_record["version"] = protocol[1]
        try:
            adapter = resolve_target_adapter(
                {"protocol": "processor-memory-beat", "version": "1",
                 "address_width": address_width, "data_width": target_width},
                target_record,
            )
        except (TargetAdapterError, ValueError) as error:
            raise SocRenderError(f"{cell}:{component_id}:target-adapter:{error}") from error
        wrapper = _wrapper(cell, component_id, source_lock)
        record_parameters: dict[str, object] = {}
        skipped_record_parameters: dict[str, object] = {}
        for name, value in (instance.get("parameters") or {}).items():
            if isinstance(name, str) and name.isidentifier() and _safe_literal(value):
                record_parameters[name] = value
            else:
                skipped_record_parameters[str(name)] = value
        width_adapter = next((entry for entry in fabric.get("width_adapters", [])
                              if int(entry["target_index"]) == index), None)
        if data_width != target_width and width_adapter is None:
            raise SocRenderError(f"{cell}:{component_id}:width-adapter-missing")
        record = {
            "id": component_id,
            "instance_id": str(instance["instance_id"]),
            "source_lock": source_lock,
            "top_module": str(instance["top_module"]),
            "target_id": target_id,
            "protocol": protocol,
            "window": {"base": int(row["base"]), "size": int(row["size"])},
            "target_index": index,
            "row": row,
            "adapter": adapter,
            "wrapper": wrapper,
            "width_adapter": width_adapter,
            "closure": closure_path,
            "closure_document": closure,
            "parameters": record_parameters,
            "parameters_skipped": skipped_record_parameters,
            "runtime_status": (str(declared.get("runtime_status"))
                               if declared.get("runtime_status")
                               else _runtime_status(cell, source_lock)),
            "elaboration_status": closure.get("status"),
            "environment_links": [],
            "irq_routes": [],
            "irq_outputs": wrapper["irq_outputs"],
        }
        peripherals.append(record)
        by_component[component_id] = record

    links = sorted((link for link in contract.get("links", []) if isinstance(link, Mapping)),
                   key=lambda link: str(link.get("link_id")))
    for link in links:
        component_id = str(link.get("component_id"))
        record = by_component.get(component_id)
        if record is None:
            raise SocRenderError(f"{cell}:{component_id}:environment-link-unknown-peripheral")
        protocol = link.get("protocol")
        protocol_name = str(protocol[0]) if isinstance(protocol, Sequence) and len(protocol) else ""
        peer = _ENVIRONMENT_PEERS.get(protocol_name)
        record["environment_links"].append(str(link.get("link_id")))
        if peer is None:
            continue
        if not (ROOT / peer["source"]).is_file():
            raise SocRenderError(f"{cell}:{component_id}:environment-peer-missing:{peer['source']}")
        if record.get("environment_peer") is not None:
            raise SocRenderError(f"{cell}:{component_id}:duplicate-environment-peer")
        link_parameters = link.get("parameters") if isinstance(link.get("parameters"), Mapping) else {}
        parameters: dict[str, object] = {}
        used: set[str] = set()
        for name, aliases, default in peer["parameters"]:
            for alias in aliases:
                if alias in link_parameters:
                    parameters[name] = link_parameters[alias]
                    used.add(alias)
                    break
            else:
                parameters[name] = default
        record["environment_peer"] = {
            "link_id": str(link.get("link_id")),
            "component_id": component_id,
            "module": peer["module"],
            "source": peer["source"],
            "protocol": protocol_name,
            "parameters": parameters,
            "unmapped_parameters": {str(key): value for key, value in link_parameters.items()
                                    if str(key) not in used},
        }

    peers = [record["environment_peer"] for record in peripherals
             if record.get("environment_peer") is not None]
    if len({peer["module"] for peer in peers}) != len(peers):
        raise SocRenderError(f"{cell}:duplicate-environment-peer-module")

    routes = sorted((route for route in contract.get("interrupt_routes", [])
                     if isinstance(route, Mapping)), key=lambda route: str(route.get("route_id")))
    for route in routes:
        component_id = str(route["source"]["component_id"])
        record = by_component.get(component_id)
        if record is None:
            raise SocRenderError(f"{cell}:{component_id}:interrupt-route-unknown-peripheral")
        signal = str(route["source"]["signal"])
        if signal not in record["irq_outputs"]:
            raise SocRenderError(f"{cell}:{component_id}:irq-signal-not-declared:{signal}")
        record["irq_routes"].append(str(route["route_id"]))

    memory = []
    for target in fabric["targets"]:
        if target.get("backing_kind") != "memory":
            continue
        index = int(target["index"])
        rows = [row for row in fabric["decode"]["windows"] if int(row["target_index"]) == index]
        if len(rows) != 1 or int(rows[0]["target_base"]) != int(rows[0]["base"]):
            raise SocRenderError(f"{cell}:{target['backing_id']}:memory-alias-unsupported")
        row = rows[0]
        region = regions.get(str(row["window_id"]), {})
        policy = str(region.get("initialization_policy", ""))
        memory.append({
            "index": index,
            "target_index": index,
            "backing_id": str(target["backing_id"]),
            "window": {"base": int(row["base"]), "size": int(row["size"])},
            "model": "riscv_boot_memory_32" if data_width == 32 else "riscv_boot_memory_64",
            "load_image": policy in ("preload", "rom"),
            "initialization_policy": policy,
        })

    decode = sorted((dict(row) for row in fabric["decode"]["windows"]),
                    key=lambda row: (int(row["base"]), str(row["window_id"])))
    projection = stimulus.get("rtl_projection")
    if not isinstance(projection, Mapping):
        raise SocRenderError(f"{cell}:stimulus-rtl-projection-missing")
    return {
        "cell": cell,
        "address_width": address_width,
        "data_width": data_width,
        "fabric": fabric,
        "fabric_parameters": fabric_parameters,
        "decode": decode,
        "cpu": {
            "instance": cpu_instance,
            "source_lock": cpu_lock,
            "top_module": str(cpu_instance["top_module"]),
            "core_module": core_module,
            "core_source": core_source,
            "core_dependencies": core_dependencies,
            "closure": cpu_closure,
            "reset_vector": reset_vector,
            "parameters": cpu_parameters,
            "parameters_skipped": skipped_parameters,
            "lanes": lanes,
        },
        "peripherals": peripherals,
        "peers": peers,
        "routes": routes,
        "memory": memory,
        "projection": dict(projection),
        "cpu_held_in_reset": bool(
            stimulus.get("reset_semantics", {}).get("cpu_reset", {}).get("held_in_reset_whole_test")),
    }


def _runtime_status(cell: str, source_lock: str) -> str:
    """The source lock's runtime status for a component this cell renders."""
    record = _lock_component(cell, source_lock)
    return str(record.get("runtime_status", "runtime_unverified"))



# ---------------------------------------------------------------------------
# cell profile: generated top
# ---------------------------------------------------------------------------


def _target_net_widths(adapter: Mapping[str, object]) -> dict[str, int]:
    """Widths of the P5 adapter's target-side port contract.

    These are protocol facts (the same fields every implementation of the
    protocol carries), not peripheral facts.  The wrapper declares the same
    widths; a disagreement is an elaboration error, never a silent truncation.
    """
    parameters = {entry["name"]: entry["value"] for entry in adapter["parameters"]}
    protocol = adapter["target_protocol"]["protocol"]
    data_width = int(parameters["DATA_WIDTH"])
    if protocol == "apb":
        return {"paddr": int(parameters["ADDRESS_WIDTH"]), "psel": 1, "penable": 1,
                "pwrite": 1, "pwdata": data_width, "pstrb": data_width // 8,
                "pready": 1, "prdata": data_width, "pslverr": 1}
    if protocol == "tl-ul":
        return {"a_valid": 1, "a_ready": 1, "a_opcode": 3, "a_param": 3,
                "a_size": int(parameters["SIZE_WIDTH"]),
                "a_source": int(parameters["SOURCE_WIDTH"]),
                "a_address": int(parameters["ADDRESS_WIDTH"]),
                "a_mask": data_width // 8, "a_data": data_width,
                "a_user": int(parameters["USER_WIDTH"]),
                "d_valid": 1, "d_ready": 1, "d_opcode": 3, "d_param": 3,
                "d_size": int(parameters["SIZE_WIDTH"]),
                "d_source": int(parameters["SOURCE_WIDTH"]),
                "d_sink": int(parameters["SINK_WIDTH"]), "d_data": data_width,
                "d_user": int(parameters["DUSER_WIDTH"]), "d_error": 1}
    return {"cyc": 1, "stb": 1, "we": 1,
            "adr": max(1, int(parameters["TARGET_ADDRESS_WIDTH"])),
            "dat_w": data_width, "sel": data_width // 8,
            "ack": 1, "err": 1, "stall": 1, "dat_r": data_width}


def _sv_type(width: int) -> str:
    return "logic" if width <= 1 else f"logic [{width - 1}:0]"


def _cell_top(records: Mapping[str, object], cell: str) -> str:
    address_width = int(records["address_width"])
    data_width = int(records["data_width"])
    be_width = data_width // 8
    fabric_parameters = records["fabric_parameters"]
    num_sources = int(fabric_parameters["NUM_SOURCES"])
    num_targets = int(fabric_parameters["NUM_TARGETS"])
    source_id_width = max(1, (num_sources - 1).bit_length())
    target_id_width = max(1, (num_targets - 1).bit_length())
    projection = records["projection"]
    projection_parameters = projection["parameters"]
    selector_width = int(projection_parameters["SELECTOR_WIDTH"])
    cpu = records["cpu"]
    peripherals = records["peripherals"]
    peers = records["peers"]
    routes = records["routes"]
    topology = records["fabric"]["sources"]
    lines: list[str] = []

    def add(text: str = "") -> None:
        lines.append(text)

    add(f"// Generated by myfuzz.composition.soc_renderer ({RENDER_SCHEMA}).")
    add(f"// Cell: {cell}.  Source-backed CPU: {cpu['top_module']} "
        f"({cpu['source_lock']}, closure {cpu['closure']['source_files'][0]}).")
    for record in peripherals:
        add(f"// Peripheral {record['id']}: {record['top_module']} "
            f"({record['protocol'][0]}) behind {record['adapter']['rtl_module']}, "
            f"closure {record['closure']}.")
    add("// Every peripheral below is the pinned real IP; no behavioural model is")
    add("// instantiated by this harness.  The MYFUZZ_ENABLE_REAL_* define is the")
    add("// opt-in boundary for the source-backed CPU core.")
    add("module myfuzz_soc_top #(")
    add(f"  parameter integer ADDRESS_WIDTH = {address_width},")
    add(f"  parameter integer DATA_WIDTH = {data_width}")
    add(") (")
    add("  input  logic clk_i,")
    add("  input  logic reset_i,")
    add("  input  logic env_offer_i,")
    add("  input  logic [DATA_WIDTH-1:0] env_data_i,")
    add("  input  logic spi_sck_i,")
    add("  input  logic spi_cs_i,")
    add("  input  logic [7:0] gpio_in_i,")
    add("  input  logic irq_claim_i,")
    add("  input  logic irq_complete_i,")
    add("  input  logic stim_offer_i,")
    add(f"  input  logic [{selector_width - 1}:0] stim_target_selector_i,")
    add("  input  logic [ADDRESS_WIDTH-1:0] stim_offset_i,")
    add("  input  logic stim_write_i,")
    add("  input  logic [DATA_WIDTH-1:0] stim_wdata_i,")
    add("  input  logic [DATA_WIDTH/8-1:0] stim_be_i,")
    add("  output logic uart_rx_o,")
    add("  output logic spi_miso_o,")
    add("  output logic irq_o,")
    add("  output logic [31:0] env_drop_count_o,")
    add("  output logic cpu_irq_o,")
    add("  output logic [31:0] gpio_out_o,")
    add("  output logic [31:0] gpio_dir_o,")
    add("  output logic gpio_irq_o,")
    add("  output logic spi_clk_o,")
    add("  output logic spi_cs0_o,")
    add("  output logic spi_sdo0_o,")
    add("  output logic cpu_mmio_transaction_o,")
    add("  output logic fuzz_mmio_transaction_o,")
    add("  output logic [31:0] cpu_transaction_count_o,")
    add("  output logic [31:0] fuzz_transaction_count_o,")
    add("  output logic [31:0] cpu_completion_count_o,")
    add("  output logic [31:0] fuzz_completion_count_o,")
    add("  output logic fabric_protocol_error_o")
    add(");")
    add(f"  localparam bit CPU_HELD_IN_RESET = "
        f"{'1' if records['cpu_held_in_reset'] else '0'};")
    add("  wire reset_n = ~reset_i;")
    add("  wire cpu_reset = reset_i | CPU_HELD_IN_RESET;")
    add("  logic [1:0] cpu_irq_bus;")
    add("  logic [31:0] env_gpio_in_bus;")
    add("  assign env_gpio_in_bus = {24'd0, gpio_in_i};")
    add("  logic cpu_flush;")

    # CPU lane signals.
    for lane in cpu["lanes"]:
        prefix = lane["prefix"]
        add(f"  logic cpu_{prefix}_req_valid, cpu_{prefix}_req_ready, cpu_{prefix}_write;")
        add(f"  logic [ADDRESS_WIDTH-1:0] cpu_{prefix}_addr;")
        add(f"  logic [DATA_WIDTH-1:0] cpu_{prefix}_wdata, cpu_{prefix}_rdata;")
        add(f"  logic [DATA_WIDTH/8-1:0] cpu_{prefix}_be;")
        add(f"  logic cpu_{prefix}_rsp_valid, cpu_{prefix}_rsp_ready, cpu_{prefix}_error;")
    add(f"  logic [{num_sources - 1}:0] src_req_valid, src_req_ready, src_write, src_instr;")
    add(f"  logic [{num_sources - 1}:0] src_rsp_valid, src_rsp_ready, src_error;")
    add(f"  logic [{num_sources - 1}:0][ADDRESS_WIDTH-1:0] src_addr;")
    add(f"  logic [{num_sources - 1}:0][DATA_WIDTH-1:0] src_wdata, src_rdata;")
    add(f"  logic [{num_sources - 1}:0][DATA_WIDTH/8-1:0] src_be;")
    add("  logic fabric_req_valid, fabric_req_ready, fabric_write, fabric_instr;")
    add("  logic [ADDRESS_WIDTH-1:0] fabric_addr;")
    add("  logic [DATA_WIDTH-1:0] fabric_wdata, fabric_rdata;")
    add("  logic [DATA_WIDTH/8-1:0] fabric_be;")
    add("  logic fabric_rsp_valid, fabric_rsp_ready, fabric_error;")
    add(f"  logic [{source_id_width - 1}:0] fabric_source_id, fabric_rsp_source_id;")
    add("  logic [7:0] fabric_transaction_id, fabric_rsp_transaction_id;")
    add("  logic fabric_protocol_error;")
    fuzz_lane = next((int(source["index"]) for source in topology
                      if source.get("kind") == "fuzz_mmio"), None)
    if fuzz_lane is not None:
        add("  logic fuzz_req_valid, fuzz_req_ready, fuzz_write;")
        add("  logic [ADDRESS_WIDTH-1:0] fuzz_addr;")
        add("  logic [DATA_WIDTH-1:0] fuzz_wdata, fuzz_rdata;")
        add("  logic [DATA_WIDTH/8-1:0] fuzz_be;")
        add("  logic fuzz_rsp_valid, fuzz_rsp_ready, fuzz_error;")
        add("  logic [31:0] fuzz_busy_drop, fuzz_error_count, fuzz_completion_count;")
        add("  logic [3:0] fuzz_error_code;")
    add(f"  logic [{num_targets - 1}:0] t_req_valid, t_req_ready, t_write;")
    add(f"  logic [{num_targets - 1}:0] t_rsp_valid, t_rsp_ready, t_error;")
    add(f"  logic [{num_targets - 1}:0][ADDRESS_WIDTH-1:0] t_addr;")
    add(f"  logic [{num_targets - 1}:0][DATA_WIDTH-1:0] t_wdata, t_rdata;")
    add(f"  logic [{num_targets - 1}:0][DATA_WIDTH/8-1:0] t_be;")
    for record in peripherals:
        identifier = record["id"]
        add(f"  logic {identifier}_beat_req_valid, {identifier}_beat_req_ready, "
            f"{identifier}_beat_write;")
        add(f"  logic [ADDRESS_WIDTH-1:0] {identifier}_beat_addr;")
        add(f"  logic [31:0] {identifier}_beat_wdata, {identifier}_beat_rdata;")
        add(f"  logic [3:0] {identifier}_beat_be;")
        add(f"  logic {identifier}_beat_rsp_valid, {identifier}_beat_rsp_ready, "
            f"{identifier}_beat_error;")
        widths = _target_net_widths(record["adapter"])
        for port in record["adapter"]["target_side_ports"]:
            name = str(port["port"])
            width = widths.get(name, 1)
            add(f"  {_sv_type(width)} {identifier}_{name};")
        add(f"  logic [31:0] {identifier}_obs_gpio_out, {identifier}_obs_gpio_dir;")
        add(f"  logic {identifier}_obs_spi_clk, {identifier}_obs_spi_cs0, "
            f"{identifier}_obs_spi_sdo0, {identifier}_obs_uart_tx;")
        add(f"  logic {identifier}_irq, {identifier}_gpio_irq;")
    for peer in peers:
        identifier = peer["link_id"]
        add(f"  logic {identifier}_rx, {identifier}_ready, {identifier}_busy;")
        add(f"  logic [31:0] {identifier}_drop, {identifier}_sent;")
        add(f"  logic {identifier}_event_valid;")
        add(f"  logic [7:0] {identifier}_event_data;")
        if peer["module"] == "fuzz_spi_peer":
            add(f"  logic {identifier}_miso;")

    # CPU core (the only instance behind the opt-in define in this harness).
    define = f"MYFUZZ_ENABLE_REAL_{cpu['source_lock'].upper()}"
    add("")
    add(f"`ifdef {define}")
    add(f"  {cpu['core_module']} #(")
    add(f"    .BOOT_ADDR({address_width}'h{int(cpu['reset_vector']):x})"
        + ("".join(f",\n    .{name}({_sv_literal(value)})"
                   for name, value in sorted(cpu["parameters"].items()))))
    add("  ) u_cpu (")
    add("    .clk_i(clk_i), .reset_i(cpu_reset), .irq_i(cpu_irq_bus),")
    lane_ports = []
    for lane in cpu["lanes"]:
        prefix = lane["prefix"]
        lane_ports.extend((
            f"    .{prefix}_req_valid_o(cpu_{prefix}_req_valid), "
            f".{prefix}_req_ready_i(cpu_{prefix}_req_ready),",
            f"    .{prefix}_write_o(cpu_{prefix}_write), .{prefix}_addr_o(cpu_{prefix}_addr),",
            f"    .{prefix}_wdata_o(cpu_{prefix}_wdata), .{prefix}_be_o(cpu_{prefix}_be),",
            f"    .{prefix}_rsp_valid_i(cpu_{prefix}_rsp_valid), "
            f".{prefix}_rsp_ready_o(cpu_{prefix}_rsp_ready),",
            f"    .{prefix}_rdata_i(cpu_{prefix}_rdata), .{prefix}_error_i(cpu_{prefix}_error),",
        ))
    lane_ports.append("    .flush_o(cpu_flush)")
    add(chr(10).join(lane_ports))
    add("  );")
    add("`else")
    for lane in cpu["lanes"]:
        prefix = lane["prefix"]
        add(f"  assign cpu_{prefix}_req_valid = 1'b0;")
        add(f"  assign cpu_{prefix}_write = 1'b0;")
        add(f"  assign cpu_{prefix}_addr = '0;")
        add(f"  assign cpu_{prefix}_wdata = '0;")
        add(f"  assign cpu_{prefix}_be = '0;")
        add(f"  assign cpu_{prefix}_rsp_ready = 1'b1;")
    add("  assign cpu_flush = 1'b0;")
    add("`endif")

    # Fuzz MMIO master: the independent synthetic source.
    if fuzz_lane is not None:
        add("")
        add(f"  // Synthetic MMIO initiator ({projection.get('module', 'fuzz_mmio_master')}).")
        add(f"  {projection.get('module', 'fuzz_mmio_master')} #(")
        add("    .ADDRESS_WIDTH(ADDRESS_WIDTH), .DATA_WIDTH(DATA_WIDTH),")
        add(f"    .SELECTOR_WIDTH({int(projection_parameters['SELECTOR_WIDTH'])}), "
            f".SELECTOR_INVALID({int(projection_parameters['SELECTOR_INVALID'])}),")
        add(f"    .NUM_WINDOWS({int(projection_parameters['NUM_WINDOWS'])}), "
            f".ADDRESS_STRATEGY({int(projection_parameters['ADDRESS_STRATEGY'])}),")
        add(f"    .WINDOW_BASE({_packed(projection_parameters['WINDOW_BASE'], address_width, int(projection_parameters['NUM_WINDOWS']))}),")
        add(f"    .WINDOW_SIZE({_packed(projection_parameters['WINDOW_SIZE'], address_width, int(projection_parameters['NUM_WINDOWS']))})")
        add("  ) u_fuzz_mmio (")
        add("    .clk(clk_i), .reset(reset_i), .stim_offer(stim_offer_i),")
        add("    .stim_target_selector(stim_target_selector_i), .stim_offset(stim_offset_i),")
        add("    .stim_write(stim_write_i), .stim_wdata(stim_wdata_i), .stim_be(stim_be_i),")
        add("    .req_valid(fuzz_req_valid), .req_ready(fuzz_req_ready), .write(fuzz_write),")
        add("    .addr(fuzz_addr), .wdata(fuzz_wdata), .be(fuzz_be),")
        add("    .rsp_valid(fuzz_rsp_valid), .rsp_ready(fuzz_rsp_ready), .rdata(fuzz_rdata),")
        add("    .error(fuzz_error), .busy_drop_count(fuzz_busy_drop),")
        add("    .error_count(fuzz_error_count), .completion_count(fuzz_completion_count),")
        add("    .error_code(fuzz_error_code)")
        add("  );")

    # Arbiter lane wiring.
    add("")
    add("  // Arbiter lanes: one per declared master, ordered by the plan fabric.")
    for source in topology:
        index = int(source["index"])
        kind = str(source.get("kind"))
        if kind in _CPU_LANE_PREFIX:
            prefix = _CPU_LANE_PREFIX[kind]
            add(f"  assign src_req_valid[{index}] = cpu_{prefix}_req_valid;")
            add(f"  assign cpu_{prefix}_req_ready = src_req_ready[{index}];")
            add(f"  assign src_write[{index}] = cpu_{prefix}_write;")
            add(f"  assign src_addr[{index}] = cpu_{prefix}_addr;")
            add(f"  assign src_wdata[{index}] = cpu_{prefix}_wdata;")
            add(f"  assign src_be[{index}] = cpu_{prefix}_be;")
            add(f"  assign src_instr[{index}] = 1'b{'1' if source.get('instruction') else '0'};")
            add(f"  assign cpu_{prefix}_rsp_valid = src_rsp_valid[{index}];")
            add(f"  assign src_rsp_ready[{index}] = cpu_{prefix}_rsp_ready;")
            add(f"  assign cpu_{prefix}_rdata = src_rdata[{index}];")
            add(f"  assign cpu_{prefix}_error = src_error[{index}];")
        elif kind == "fuzz_mmio":
            add(f"  assign src_req_valid[{index}] = fuzz_req_valid;")
            add(f"  assign fuzz_req_ready = src_req_ready[{index}];")
            add(f"  assign src_write[{index}] = fuzz_write;")
            add(f"  assign src_addr[{index}] = fuzz_addr;")
            add(f"  assign src_wdata[{index}] = fuzz_wdata;")
            add(f"  assign src_be[{index}] = fuzz_be;")
            add(f"  assign src_instr[{index}] = 1'b0;")
            add(f"  assign fuzz_rsp_valid = src_rsp_valid[{index}];")
            add(f"  assign src_rsp_ready[{index}] = fuzz_rsp_ready;")
            add(f"  assign fuzz_rdata = src_rdata[{index}];")
            add(f"  assign fuzz_error = src_error[{index}];")
        else:
            raise SocRenderError(f"{cell}:unsupported-master-kind:{kind}")

    # Arbiter and router.
    add("")
    add(f"  soc_arbiter #(.NUM_SOURCES({num_sources}), .ADDRESS_WIDTH(ADDRESS_WIDTH),")
    add(f"      .DATA_WIDTH(DATA_WIDTH), .SOURCE_ID_WIDTH({source_id_width}),")
    add("      .TRANSACTION_ID_WIDTH(8)) u_soc_arbiter (")
    add("    .clk(clk_i), .reset(reset_i), .s_req_valid(src_req_valid),")
    add("    .s_req_ready(src_req_ready), .s_write(src_write), .s_addr(src_addr),")
    add("    .s_wdata(src_wdata), .s_be(src_be), .s_instr(src_instr),")
    add("    .s_rsp_valid(src_rsp_valid), .s_rsp_ready(src_rsp_ready),")
    add("    .s_rdata(src_rdata), .s_error(src_error), .req_valid(fabric_req_valid),")
    add("    .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),")
    add("    .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),")
    add("    .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),")
    add("    .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),")
    add("    .rdata(fabric_rdata), .error(fabric_error),")
    add("    .rsp_source_id(fabric_rsp_source_id),")
    add("    .rsp_transaction_id(fabric_rsp_transaction_id),")
    add("    .protocol_error(fabric_protocol_error)")
    add("  );")
    decode = records["decode"]
    max_windows = max(1, len(decode))
    executable = sum(1 << position for position, row in enumerate(decode)
                     if row["permissions"]["execute"])
    readable = sum(1 << position for position, row in enumerate(decode)
                   if row["permissions"]["read"])
    writable = sum(1 << position for position, row in enumerate(decode)
                   if row["permissions"]["write"])
    add("")
    add("  // Address router: the plan's own decode windows and permissions.")
    add(f"  soc_router #(.RESET_CLEARS_TARGETS(1'b1), .NUM_TARGETS({num_targets}),")
    add(f"      .ADDRESS_WIDTH(ADDRESS_WIDTH), .DATA_WIDTH(DATA_WIDTH),")
    add(f"      .SOURCE_ID_WIDTH({source_id_width}), .NUM_SOURCES({num_sources}),")
    add(f"      .TRANSACTION_ID_WIDTH(8), .TARGET_ID_WIDTH({target_id_width}),")
    add(f"      .MAX_WINDOWS({max_windows}), .NUM_WINDOWS({len(decode)}),")
    add(f"      .WINDOW_BASE({_packed([int(row['base']) for row in decode], address_width, max_windows)}),")
    add(f"      .WINDOW_TARGET_BASE({_packed([int(row['target_base']) for row in decode], address_width, max_windows)}),")
    add(f"      .WINDOW_SIZE({_packed([int(row['size']) for row in decode], address_width, max_windows)}),")
    add(f"      .WINDOW_TARGET({_packed([int(row['target_index']) for row in decode], target_id_width, max_windows)}),")
    add(f"      .WINDOW_EXECUTABLE({max_windows}'b{executable:0{max_windows}b}),")
    add(f"      .WINDOW_READABLE({max_windows}'b{readable:0{max_windows}b}),")
    add(f"      .WINDOW_WRITABLE({max_windows}'b{writable:0{max_windows}b}),")
    add(f"      .WINDOW_SOURCE_MASK({int(fabric_parameters['WINDOW_SOURCE_MASK'])})")
    add("  ) u_soc_router (")
    add("    .clk(clk_i), .reset(reset_i), .req_valid(fabric_req_valid),")
    add("    .req_ready(fabric_req_ready), .write(fabric_write), .addr(fabric_addr),")
    add("    .wdata(fabric_wdata), .be(fabric_be), .instr(fabric_instr),")
    add("    .source_id(fabric_source_id), .transaction_id(fabric_transaction_id),")
    add("    .rsp_valid(fabric_rsp_valid), .rsp_ready(fabric_rsp_ready),")
    add("    .rdata(fabric_rdata), .error(fabric_error),")
    add("    .rsp_source_id(fabric_rsp_source_id),")
    add("    .rsp_transaction_id(fabric_rsp_transaction_id),")
    add("    .t_req_valid(t_req_valid), .t_req_ready(t_req_ready), .t_write(t_write),")
    add("    .t_addr(t_addr), .t_wdata(t_wdata), .t_be(t_be),")
    add("    .t_rsp_valid(t_rsp_valid), .t_rsp_ready(t_rsp_ready),")
    add("    .t_rdata(t_rdata), .t_error(t_error), .selected_target(),")
    add("    .stale_pending()")
    add("  );")

    # Memory targets.
    for record in records["memory"]:
        index = int(record["index"])
        add("")
        add(f"  // Memory target {record['backing_id']} "
            f"({record['model']}, initialization {record['initialization_policy']}).")
        add(f"  {record['model']} #(.BASE_ADDR({int(record['window']['base'])}), "
            f".BYTES({int(record['window']['size'])}), "
            f".LOAD_IMAGE({1 if record['load_image'] else 0})) u_mem_{index} (")
        add("    .clock(clk_i), .reset(reset_n), .flush(cpu_flush),")
        add(f"    .req_valid(t_req_valid[{index}]), .req_ready(t_req_ready[{index}]),")
        add(f"    .write(t_write[{index}]), .addr(t_addr[{index}]), .wdata(t_wdata[{index}]),")
        add(f"    .be(t_be[{index}]), .rsp_valid(t_rsp_valid[{index}]),")
        add(f"    .rsp_ready(t_rsp_ready[{index}]), .rdata(t_rdata[{index}]),")
        add(f"    .error(t_error[{index}])")
        add("  );")

    # Peripheral targets: width adapter (when the beat side is wider), the P5
    # target adapter and the source-backed real IP wrapper.
    for record in peripherals:
        identifier = record["id"]
        index = int(record["target_index"])
        adapter = record["adapter"]
        add("")
        add(f"  // Real peripheral {identifier}: {record['top_module']} "
            f"({record['protocol'][0]}) behind {adapter['rtl_module']}.")
        if record["width_adapter"] is not None:
            width_adapter = record["width_adapter"]
            width_parameters = {str(name): value
                                for name, value in width_adapter["parameters"].items()}
            add(f"  {width_adapter['module']} #("
                + ", ".join(f".{name}({_sv_literal(value)})"
                            for name, value in sorted(width_parameters.items())))
            add(f"  ) u_{identifier}_width (")
            add("    .clk(clk_i), .reset(reset_i),")
            add(f"    .req_valid(t_req_valid[{index}]), .req_ready(t_req_ready[{index}]),")
            add(f"    .write(t_write[{index}]), .addr(t_addr[{index}]), "
                f".wdata(t_wdata[{index}]), .be(t_be[{index}]),")
            add(f"    .rsp_valid(t_rsp_valid[{index}]), .rsp_ready(t_rsp_ready[{index}]),")
            add(f"    .rdata(t_rdata[{index}]), .error(t_error[{index}]),")
            add(f"    .p_req_valid({identifier}_beat_req_valid), "
                f".p_req_ready({identifier}_beat_req_ready),")
            add(f"    .p_write({identifier}_beat_write), .p_addr({identifier}_beat_addr),")
            add(f"    .p_wdata({identifier}_beat_wdata), .p_be({identifier}_beat_be),")
            add(f"    .p_rsp_valid({identifier}_beat_rsp_valid), "
                f".p_rsp_ready({identifier}_beat_rsp_ready),")
            add(f"    .p_rdata({identifier}_beat_rdata), .p_error({identifier}_beat_error),")
            add("    .stale_pending()")
            add("  );")
        else:
            add(f"  assign {identifier}_beat_req_valid = t_req_valid[{index}];")
            add(f"  assign t_req_ready[{index}] = {identifier}_beat_req_ready;")
            add(f"  assign {identifier}_beat_write = t_write[{index}];")
            add(f"  assign {identifier}_beat_addr = t_addr[{index}];")
            add(f"  assign {identifier}_beat_wdata = t_wdata[{index}];")
            add(f"  assign {identifier}_beat_be = t_be[{index}];")
            add(f"  assign t_rsp_valid[{index}] = {identifier}_beat_rsp_valid;")
            add(f"  assign {identifier}_beat_rsp_ready = t_rsp_ready[{index}];")
            add(f"  assign t_rdata[{index}] = {identifier}_beat_rdata;")
            add(f"  assign t_error[{index}] = {identifier}_beat_error;")
        add("")
        add(f"  {adapter['rtl_module']} #("
            + ", ".join(f".{entry['name']}({_sv_literal(entry['value'])})"
                        for entry in adapter["parameters"]))
        add(f"  ) u_{identifier}_adapter (")
        add("    .clk(clk_i), .reset(reset_i),")
        add(f"    .req_valid({identifier}_beat_req_valid), "
            f".req_ready({identifier}_beat_req_ready), .write({identifier}_beat_write),")
        add(f"    .addr({identifier}_beat_addr), .wdata({identifier}_beat_wdata), "
            f".be({identifier}_beat_be),")
        add(f"    .rsp_valid({identifier}_beat_rsp_valid), "
            f".rsp_ready({identifier}_beat_rsp_ready),")
        add(f"    .rdata({identifier}_beat_rdata), .error({identifier}_beat_error),")
        for position, port in enumerate(adapter["target_side_ports"]):
            name = str(port["port"])
            comma = "," if position + 1 < len(adapter["target_side_ports"]) else ""
            add(f"    .{name}({identifier}_{name}){comma}")
        add("  );")

        peer = record.get("environment_peer")
        uart_peer = peer if peer is not None and peer["module"] == "fuzz_uart_peer" else None
        spi_peer = peer if peer is not None and peer["module"] == "fuzz_spi_peer" else None
        uart_rx_connection = f"{uart_peer['link_id']}_rx" if uart_peer else "1'b1"
        spi_sdi_connection = f"{spi_peer['link_id']}_miso" if spi_peer else "1'b0"
        add("")
        add(f"  {record['wrapper']['module']} #("
            + ", ".join(f".{name}({_sv_literal(value)})"
                        for name, value in sorted(record["parameters"].items()))
            + f") u_{identifier} (")
        add("    .clk_i(clk_i), .rst_ni(reset_n),")
        wrapper_text = (ROOT / record["wrapper"]["source"]).read_text(encoding="utf-8")
        for position, port in enumerate(adapter["target_side_ports"]):
            name = str(port["port"])
            wrapper_port = f"{name}_i" if port["direction"] == "output" else f"{name}_o"
            if wrapper_port not in wrapper_text:
                raise SocRenderError(
                    f"{cell}:{identifier}:wrapper-port-missing:{wrapper_port}")
            add(f"    .{wrapper_port}({identifier}_{name}),")
        add("    .env_gpio_in_i(env_gpio_in_bus),")
        add(f"    .env_uart_rx_i({uart_rx_connection}),")
        add(f"    .env_spi_sck_i({identifier}_obs_spi_clk),")
        add(f"    .env_spi_cs_i({identifier}_obs_spi_cs0),")
        add(f"    .env_spi_sdi_i({spi_sdi_connection}),")
        add(f"    .obs_gpio_out_o({identifier}_obs_gpio_out), "
            f".obs_gpio_dir_o({identifier}_obs_gpio_dir),")
        add(f"    .obs_spi_clk_o({identifier}_obs_spi_clk), "
            f".obs_spi_cs0_o({identifier}_obs_spi_cs0),")
        add(f"    .obs_spi_sdo0_o({identifier}_obs_spi_sdo0), "
            f".obs_uart_tx_o({identifier}_obs_uart_tx),")
        add(f"    .irq_o({identifier}_irq), .gpio_irq_o({identifier}_gpio_irq)")
        add("  );")

    # Environment peers: only for peripherals that declare such a contract.
    for peer in peers:
        link = peer["link_id"]
        parameters = ", ".join(f".{name}({_sv_literal(value)})"
                               for name, value in sorted(peer["parameters"].items()))
        add("")
        add(f"  // Environment peer for {peer['component_id']} ({peer['protocol']}).")
        add(f"  {peer['module']} #({parameters}) u_{link} (")
        add("    .clk_i(clk_i), .reset_i(reset_i), .offer_i(env_offer_i),")
        add("    .data_i(env_data_i[7:0]),")
        if peer["module"] == "fuzz_uart_peer":
            add(f"    .rx_o({link}_rx), .ready_o({link}_ready), .busy_o({link}_busy),")
        else:
            add(f"    .sck_i({peer['component_id']}_obs_spi_clk), "
                f".cs_i({peer['component_id']}_obs_spi_cs0),")
            add(f"    .miso_o({link}_miso), .ready_o({link}_ready), .busy_o({link}_busy),")
        add(f"    .drop_count_o({link}_drop), .sent_count_o({link}_sent),")
        add(f"    .event_valid_o({link}_event_valid), .event_data_o({link}_event_data)")
        add("  );")

    # Interrupt router: only when the plan declares interrupt routes.
    add("")
    if routes:
        count = len(routes)
        route_id_width = max(1, (count - 1).bit_length())
        edge_bits = "".join("1" if str(route["source"]["trigger"]) == "edge" else "0"
                            for route in reversed(routes))
        add(f"  logic [{count - 1}:0] irq_sources;")
        for position, route in enumerate(routes):
            add(f"  assign irq_sources[{position}] = "
                f"{route['source']['component_id']}_irq;")
        add(f"  soc_irq_router #(.NUM_SOURCES({count}), "
            f".SOURCE_ID_WIDTH({route_id_width}), .PRIORITY_WIDTH(4)) u_irq_router (")
        add(f"    .source_i(irq_sources), .enable_i({{{count}{{1'b1}}}}), "
            f".edge_mode_i({count}'b{edge_bits}),")
        add(f"    .claim_i(irq_claim_i), .complete_i(irq_complete_i), "
            f".clear_i({{{count}{{1'b0}}}}),")
        add(f"    .priority_i({{{count}{{4'd1}}}}), .clk_i(clk_i), .reset_i(reset_i),")
        add("    .irq_o(irq_router_irq), .pending_o(), .in_service_o(),")
        add("    .claim_valid_o(), .claim_id_o()")
        add("  );")
        add("  assign irq_o = irq_router_irq;")
        add("  assign cpu_irq_o = irq_router_irq;")
        add("  assign cpu_irq_bus = {1'b0, irq_router_irq};")
    else:
        add("  assign irq_o = 1'b0;")
        add("  assign cpu_irq_o = 1'b0;")
        add("  assign cpu_irq_bus = 2'b00;")

    # Harness observability.
    add("")
    uart_peers = [peer for peer in peers if peer["module"] == "fuzz_uart_peer"]
    spi_peers = [peer for peer in peers if peer["module"] == "fuzz_spi_peer"]
    add("  assign uart_rx_o = "
        + (f"{uart_peers[0]['link_id']}_rx;" if uart_peers else "1'b1;"))
    add("  assign spi_miso_o = "
        + (f"{spi_peers[0]['link_id']}_miso;" if spi_peers else "1'b0;"))
    add("  assign env_drop_count_o = "
        + (" + ".join(f"{peer['link_id']}_drop" for peer in peers) + ";" if peers else "'0;"))
    for port, key in (("gpio_out_o", "obs_gpio_out"), ("gpio_dir_o", "obs_gpio_dir"),
                      ("gpio_irq_o", "gpio_irq"), ("spi_clk_o", "obs_spi_clk"),
                      ("spi_cs0_o", "obs_spi_cs0"), ("spi_sdo0_o", "obs_spi_sdo0")):
        expression = " | ".join(f"{record['id']}_{key}" for record in peripherals)
        add(f"  assign {port} = {expression if expression else chr(39) + '0'};")
    cpu_lane_indexes = [int(lane["index"]) for lane in cpu["lanes"]]
    cpu_transactions = " | ".join(
        f"(src_req_valid[{index}] && src_req_ready[{index}])" for index in cpu_lane_indexes)
    add(f"  assign cpu_mmio_transaction_o = {cpu_transactions};")
    add("  assign fuzz_mmio_transaction_o = "
        + (f"(src_req_valid[{fuzz_lane}] && src_req_ready[{fuzz_lane}]);"
           if fuzz_lane is not None else "1'b0;"))
    add("  assign fabric_protocol_error_o = fabric_protocol_error;")
    cpu_completions = " | ".join(
        f"(src_rsp_valid[{index}] && src_rsp_ready[{index}])" for index in cpu_lane_indexes)
    add("  always_ff @(posedge clk_i or posedge reset_i) begin")
    add("    if (reset_i) begin")
    add("      cpu_transaction_count_o <= 32'd0;")
    add("      fuzz_transaction_count_o <= 32'd0;")
    add("      cpu_completion_count_o <= 32'd0;")
    add("      fuzz_completion_count_o <= 32'd0;")
    add("    end else begin")
    add("      if (cpu_mmio_transaction_o)")
    add("        cpu_transaction_count_o <= cpu_transaction_count_o + 1'b1;")
    add("      if (fuzz_mmio_transaction_o)")
    add("        fuzz_transaction_count_o <= fuzz_transaction_count_o + 1'b1;")
    add(f"      if ({cpu_completions})")
    add("        cpu_completion_count_o <= cpu_completion_count_o + 1'b1;")
    if fuzz_lane is not None:
        add(f"      if (src_rsp_valid[{fuzz_lane}] && src_rsp_ready[{fuzz_lane}])")
        add("        fuzz_completion_count_o <= fuzz_completion_count_o + 1'b1;")
    add("    end")
    add("  end")
    add("endmodule")
    return chr(10).join(lines) + chr(10)



def _cell_source_records(plan: Mapping[str, object], records: Mapping[str, object]) -> list[dict]:
    """Source records in the same shape the P10 manifest used."""
    result: list[dict] = []
    seen: set[str] = set()

    def add(path: object, role: str, source_lock: object = None) -> None:
        if not isinstance(path, str) or not path or path in seen:
            return
        seen.add(path)
        entry: dict[str, object] = {"path": path, "role": role}
        if isinstance(source_lock, str):
            entry["source_lock"] = source_lock
        result.append(entry)

    execution = plan["processor_execution"]
    for value in execution.get("adapter_sources", []):
        add(value, "cpu_adapter")
    for route in execution.get("routes", []):
        if isinstance(route, Mapping):
            add(route.get("rtl_source"), "cpu_adapter")
    for adapter in plan.get("adapters", []):
        if isinstance(adapter, Mapping):
            add(adapter.get("rtl_source"), "target_adapter")
    cpu = records["cpu"]
    add(cpu["core_source"], "source_backed_cpu_core", cpu["source_lock"])
    for path in cpu["closure"]["source_files"]:
        add(path, "source_backed_cpu_closure", cpu["source_lock"])
    for source in records["fabric"]["rtl"]["sources"]:
        add(source, "soc_fabric")
    for record in records["peripherals"]:
        for path in record["closure_recorded_files"]:
            add(path, "source_backed_peripheral_closure", record["source_lock"])
        add(record["adapter"]["rtl_source"], "target_adapter", record["source_lock"])
        add(record["wrapper"]["source"], "source_backed_peripheral_wrapper", record["source_lock"])
        if record["width_adapter"] is not None:
            add(record["width_adapter"]["source"], "fabric_width_adapter", record["source_lock"])
    for record in records["memory"]:
        add(MEMORY_MODEL, "memory_model")
    for peer in records["peers"]:
        add(peer["source"], "environment_peer", peer["component_id"])
    if records["routes"]:
        add(_IRQ_ROUTER_SOURCE, "environment_irq_router")
    for instance in plan.get("instances", []):
        if isinstance(instance, Mapping):
            lock = instance.get("source_lock")
            top_module = instance.get("top_module")
            if isinstance(lock, str) and isinstance(top_module, str):
                result.append({"source_lock": lock, "top_module": top_module,
                               "role": str(instance.get("kind", "component")),
                               "instance_id": str(instance.get("instance_id", ""))})
    return result


def _cell_document(plan: Mapping[str, object], stimulus: Mapping[str, object],
                   contract: Mapping[str, object], config: Mapping[str, object],
                   cell: str, config_path: Path) -> dict[str, str]:
    records = _cell_records(plan, stimulus, contract, config, cell)
    top = _cell_top(records, cell)
    cpu = records["cpu"]

    source_files: list[str] = []
    include_dirs: list[str] = []
    defines: list[str] = []

    def add_sources(items: Sequence[object]) -> None:
        for item in items:
            if isinstance(item, str) and item and item not in source_files:
                source_files.append(item)

    def add_includes(items: Sequence[object]) -> None:
        for item in items:
            if isinstance(item, str) and item and item not in include_dirs:
                include_dirs.append(item)

    def add_defines(items: Sequence[object]) -> None:
        for item in items:
            if isinstance(item, str) and item and item not in defines:
                defines.append(item)

    blocks: list[tuple[str, list[str]]] = []
    cpu_block = list(cpu["closure"]["source_files"]) + [cpu["core_source"]]
    cpu_block += [str(item) for item in cpu["core_dependencies"]]
    cpu_block += [str(item) for item in plan["processor_execution"].get("adapter_sources", [])
                  if isinstance(item, str)]
    for route in plan["processor_execution"].get("routes", []):
        if isinstance(route, Mapping) and isinstance(route.get("rtl_source"), str):
            cpu_block.append(route["rtl_source"])
    blocks.append((f"cpu:{cpu['source_lock']}", cpu_block))
    fabric_block = [str(item) for item in records["fabric"]["rtl"]["sources"]]
    projection_source = records["projection"].get("source")
    if isinstance(projection_source, str) and projection_source:
        fabric_block.append(projection_source)
    blocks.append(("fabric", fabric_block))
    for record in records["peripherals"]:
        closure_files, closure_includes, closure_defines = _closure_ordered_sources(
            record["closure_document"], cell, record["id"])
        record["closure_source_files"] = closure_files
        record["closure_include_dirs"] = closure_includes
        record["closure_defines"] = closure_defines
        record["closure_recorded_files"] = _closure_recorded_files(record["closure_document"])
        lock_record = _lock_component(cell, record["source_lock"])
        lock_source = lock_record.get("source")
        root = lock_source.get("root") if isinstance(lock_source, Mapping) else None
        own_files = lock_source.get("files") if isinstance(lock_source, Mapping) else None
        record["ip_source_files"] = [f"{root}/{item}" for item in own_files or []]
        peripheral_block = list(closure_files)
        if record["width_adapter"] is not None:
            peripheral_block.append(str(record["width_adapter"]["source"]))
        peripheral_block += [str(record["adapter"]["rtl_source"]), str(record["wrapper"]["source"])]
        blocks.append((f"peripheral:{record['id']}", peripheral_block))
    blocks.append(("memory", [MEMORY_MODEL]))
    environment_block = [str(peer["source"]) for peer in records["peers"]]
    if records["routes"]:
        environment_block.append(_IRQ_ROUTER_SOURCE)
    if environment_block:
        blocks.append(("environment", environment_block))

    ordered_blocks, collisions, duplicate_modules = _resolve_package_collisions(blocks, cell)
    for _name, files in ordered_blocks:
        add_sources(files)
    add_includes(cpu["closure"]["include_dirs"])
    add_defines(cpu["closure"]["defines"])
    for record in records["peripherals"]:
        add_includes(record["closure_include_dirs"])
        add_defines(record["closure_defines"])

    peripherals_manifest: dict[str, object] = {}
    for record in records["peripherals"]:
        adapter = record["adapter"]
        peripherals_manifest[record["id"]] = {
            "source_lock": record["source_lock"],
            "top_module": record["top_module"],
            "target_id": record["target_id"],
            "protocol": list(record["protocol"]),
            "window": dict(record["window"]),
            "adapter_module": adapter["rtl_module"],
            "adapter_source": adapter["rtl_source"],
            "adapter_id": adapter["adapter_id"],
            "adapter_parameters": {entry["name"]: entry["value"] for entry in adapter["parameters"]},
            "width_adapter": (None if record["width_adapter"] is None
                              else {"module": record["width_adapter"]["module"],
                                    "source": record["width_adapter"]["source"]}),
            "wrapper_module": record["wrapper"]["module"],
            "wrapper_source": record["wrapper"]["source"],
            "wrapper_parameters": dict(record["parameters"]),
            "package_parameters": dict(record["parameters_skipped"]),
            "closure": record["closure"],
            "closure_files": list(record["closure_recorded_files"]),
            "elaboration_files": list(record["closure_source_files"]),
            "include_dirs": list(record["closure_include_dirs"]),
            "defines": list(record["closure_defines"]),
            "ip_source_files": list(record["ip_source_files"]),
            "environment_links": list(record["environment_links"]),
            "irq_routes": list(record["irq_routes"]),
            "irq_outputs": list(record["irq_outputs"]),
            "runtime_status": record["runtime_status"],
            "elaboration_status": record["elaboration_status"],
            "unsupported": list(adapter.get("unsupported", [])),
        }

    projection_parameters = records["projection"]["parameters"]
    coverage = build_coverage_universe([], instances=[
        item for item in plan.get("instances", []) if isinstance(item, Mapping)
    ])
    define = f"MYFUZZ_ENABLE_REAL_{cpu['source_lock'].upper()}"
    manifest: dict[str, object] = {
        "schema_version": RENDER_SCHEMA,
        "cell_id": cell,
        "render_config": str(config_path),
        "plan_hash": stimulus["plan_hash"],
        "stimulus_layout_hash": stimulus.get("layout_hash"),
        "source_records": _cell_source_records(plan, records),
        "environment_contract": _plain(contract),
        "real_cpu": {
            "top_module": cpu["top_module"],
            "source_lock": cpu["source_lock"],
            "status": "source_bound_pending_elaboration",
            "core_module": cpu["core_module"],
            "core_source": cpu["core_source"],
            "closure_source": SOURCES_LOCK,
            "closure_files": list(cpu["closure"]["source_files"]),
            "include_dirs": list(cpu["closure"]["include_dirs"]),
            "defines": list(cpu["closure"]["defines"]),
            "reset_vector": int(cpu["reset_vector"]),
            "parameters": dict(cpu["parameters"]),
            "package_parameters": dict(cpu["parameters_skipped"]),
            "runtime_status": cpu["closure"]["runtime_status"],
        },
        "peripherals": peripherals_manifest,
        "real_elaboration": {
            "runtime_top": "myfuzz_soc_top",
            "wrapper_top": "myfuzz_soc_top",
            "cpu_core": cpu["core_module"],
            "defines": [define],
            "include_dirs": list(include_dirs),
            "source_files": list(source_files),
            "source_blocks": [name for name, _files in ordered_blocks],
            "package_collisions": _plain(collisions),
            "duplicate_modules": _plain(duplicate_modules),
            "elaboration_status": "source_bound",
            "runtime_status": "runtime_unverified",
        },
        "generated_modules": ["myfuzz_soc_top"],
        "unique_driver_policy": "one declared driver per net; elaboration required",
        "coverage": {
            "schema_version": coverage["schema_version"],
            "backend": coverage["backend"],
            "universe_hash": coverage["universe_hash"],
            "categories": coverage["categories"],
            "branch_feedback_is_rtl_only": coverage["branch_feedback_is_rtl_only"],
            "instrumentation_required": True,
        },
    }
    manifest["render_hash"] = content_hash(manifest)
    manifest_text = json.dumps(_plain(manifest), sort_keys=True, indent=2) + chr(10)
    sources_text = chr(10).join(
        [f"+incdir+{item}" for item in include_dirs] + list(source_files)) + chr(10)
    boot = (
        "/* Minimal deterministic boot/ISR acceptance image (RV32I/RV64I)." + chr(10) +
        " * The campaign replaces this text with a compiled image only after" + chr(10) +
        " * the selected address map and CPU reset vector are validated." + chr(10) +
        " */" + chr(10) +
        ".section .text.init" + chr(10) +
        ".globl _start" + chr(10) + "_start:" + chr(10) + "  j _start" + chr(10) +
        ".section .text.irq" + chr(10) + ".globl irq_handler" + chr(10) +
        "irq_handler:" + chr(10) + "  mret" + chr(10)
    )
    return {
        "soc_top.sv": top,
        "soc_sources.f": sources_text,
        "soc_manifest.json": manifest_text,
        "soc_boot.S": boot,
        "soc_parameters.json": json.dumps({
            "address_width": records["address_width"],
            "data_width": records["data_width"],
            "selector_width": int(projection_parameters["SELECTOR_WIDTH"]),
            "selector_invalid": int(projection_parameters["SELECTOR_INVALID"]),
            "num_windows": int(projection_parameters["NUM_WINDOWS"]),
        }, sort_keys=True, indent=2) + chr(10),
    }



_DECLARATION = re.compile(r"^\s*(module|package|interface|program)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
_QUALIFIED_REFERENCE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)")


def _package_body(text: str, package: str) -> str:
    start = text.find("package " + package)
    if start < 0:
        return ""
    end = text.find("endpackage", start)
    return text[start:end if end >= 0 else len(text)]


def _provides(body: str, symbol: str) -> bool:
    return re.search(r"\b" + re.escape(symbol) + r"\b\s*[=;(,]", body) is not None


def _resolve_package_collisions(blocks: Sequence[tuple[str, Sequence[str]]], cell: str) -> tuple:
    """Order closure blocks so one definition of each package can serve all users.

    Two pinned checkouts can declare the same package name (for example the
    OpenTitan prim_secded_pkg and the HPDcache fork of it).  A single
    compilation has one symbol table per package name, so every
    P::symbol reference in the compiled set resolves to the definition that
    comes first.  The renderer therefore promotes the block whose definition
    provides every referenced symbol; when no definition can, or when the
    choice is ambiguous, it fails closed instead of letting the compiler pick
    silently.  Packages referenced through an import only keep the default
    order, and the decision is recorded in the manifest.
    """
    owner: dict[str, int] = {}
    for index, (_name, files) in enumerate(blocks):
        for path in files:
            owner.setdefault(path, index)
    texts = {path: (ROOT / path).read_text(encoding="utf-8") for path in owner}
    declarations: dict[str, list[str]] = {}
    modules: dict[str, list[str]] = {}
    for path, text in texts.items():
        for kind, name in _DECLARATION.findall(text):
            target = declarations if kind == "package" else modules
            target.setdefault(name, []).append(path)
    references: dict[str, set[str]] = {}
    for text in texts.values():
        for package, symbol in _QUALIFIED_REFERENCE.findall(text):
            references.setdefault(package, set()).add(symbol)

    promote: set[int] = set()
    collisions: dict[str, dict] = {}
    for package, paths in sorted(declarations.items()):
        ordered = sorted(set(paths), key=lambda path: (owner[path], path))
        if len(ordered) < 2:
            continue
        wanted = references.get(package, set())
        complete = [path for path in ordered
                    if all(_provides(_package_body(texts[path], package), symbol)
                           for symbol in wanted)]
        winner = ordered[0]
        reordered = False
        if wanted and winner not in complete:
            if len(complete) != 1:
                raise SocRenderError(
                    f"{cell}:package-collision-unresolved:{package}:"
                    + ",".join(ordered))
            winner = complete[0]
            promote.add(owner[winner])
            reordered = True
        collisions[package] = {
            "winner": winner,
            "default_first": ordered[0],
            "shadowed": [path for path in ordered if path != winner],
            "references": sorted(wanted),
            "reordered": reordered,
        }
    duplicate_modules = {name: sorted(set(paths)) for name, paths in sorted(modules.items())
                         if len(set(paths)) > 1}
    order = ([index for index in range(len(blocks)) if index in promote]
             + [index for index in range(len(blocks)) if index not in promote])
    ordered_blocks = [blocks[index] for index in order]
    return ordered_blocks, collisions, duplicate_modules


__all__ = ["RENDER_SCHEMA", "SocRenderError", "render_soc"]
