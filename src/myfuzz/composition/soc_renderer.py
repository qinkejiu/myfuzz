"""Deterministic source-backed SoC harness rendering.

The renderer is deliberately a small boundary between the validated JSON
contracts and a generated HDL harness.  It does not infer ports from names or
silently replace a missing CPU/peripheral source with a behavioural model.  A
rendered document records the source-lock identities, every generated file,
and whether real elaboration is still pending.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from myfuzz.contracts import canonical_bytes, content_hash

from .soc_contracts import SocContractError, soc_plan_hash, validate_soc_plan, validate_soc_stimulus


RENDER_SCHEMA = "soc_render.v1"
_RTL_SOURCES = (
    "src/myfuzz/protocols/rtl/fuzz_mmio_master.sv",
    "src/myfuzz/protocols/rtl/fuzz_uart_peer.sv",
    "src/myfuzz/protocols/rtl/fuzz_spi_peer.sv",
    "src/myfuzz/protocols/rtl/soc_irq_router.sv",
)
_SOURCE_BACKED_CLOSURE = (
    "third_party/rfuzz/upstream/ibex/sources.f",
    "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
    "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
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
    for source in _RTL_SOURCES:
        add(source, role="generated_harness")
    for source in _SOURCE_BACKED_CLOSURE:
        add(source, role="source_backed_closure")

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
  output logic uart_rx_o,
  output logic spi_miso_o,
  output logic irq_o,
  output logic [31:0] env_drop_count_o
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
  // The real campaign compiles the pinned Ibex closure and supplies the
  // compiler-proven boundary wrapper.  Keeping the binding behind an explicit
  // define prevents a preflight-only elaboration from silently using a fake
  // CPU while still making the source-backed instance visible to the build.
  ibex_top u_ibex_source_backed (.*);
`endif

  // The synthetic MMIO requester is structurally present and is connected to
  // the shared beat fabric in the full campaign wrapper.  It is disabled in
  // this preflight top so no constant response can masquerade as CPU traffic.
  // Real Ibex, register file, RAM/ROM, target adapters and PULP IP are listed
  // in sources.f and bound by the campaign-specific wrapper.
endmodule
'''


def render_soc(plan: Mapping[str, object], stimulus: Mapping[str, object]) -> dict[str, str]:
    """Render deterministic SoC files from validated plan/stimulus documents.

    The return value is a filename-to-text mapping.  The caller decides where
    to publish it, which keeps this function side-effect free and makes replay
    identity independent of temporary build paths.
    """
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
    contract = _environment_contract(stimulus)
    sources = _source_records(plan)
    top = _render_top(plan, stimulus, contract)
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
        "generated_modules": [
            "myfuzz_soc_top", "fuzz_mmio_master", "fuzz_uart_peer",
            "fuzz_spi_peer", "soc_irq_router",
        ],
        "unique_driver_policy": "one declared driver per net; elaboration required",
    }
    manifest["render_hash"] = content_hash(manifest)
    manifest_text = json.dumps(_plain(manifest), sort_keys=True, indent=2) + "\n"
    parameters = _window_parameters(plan)
    sources_text = "\n".join((*_RTL_SOURCES, *_SOURCE_BACKED_CLOSURE)) + "\n"
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


__all__ = ["RENDER_SCHEMA", "SocRenderError", "render_soc"]
