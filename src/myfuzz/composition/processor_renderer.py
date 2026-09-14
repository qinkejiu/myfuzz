"""Processor boundary rendering extracted from protocol_composer.py (P2).

Owns the processor backend/top rendering plus the SystemVerilog emission
primitives that the generic top renderer shares with it. protocol_composer.py
re-imports every name below, so its historical entry points and private
helpers keep their original names and generated output is byte-identical.
"""
from __future__ import annotations
import re
from collections.abc import Mapping
from myfuzz.contracts import content_hash
from .ids import canonical_id


def _generic_port_records(
    plan: object, *, internal_ports: frozenset[str] = frozenset(), require_records: bool = True,
) -> tuple[dict[str, object], ...]:
    annotations = getattr(plan, "annotations", None)
    if not isinstance(annotations, Mapping):
        raise ValueError("generic composition plan annotations are invalid")
    endpoints = annotations.get("endpoints")
    if not isinstance(endpoints, list | tuple):
        raise ValueError("generic composition plan endpoints are invalid")
    records: dict[str, dict[str, object]] = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping) or not isinstance(endpoint.get("endpoint_id"), str):
            raise ValueError("generic composition endpoint is invalid")
        for field in endpoint.get("fields", ()):
            if not isinstance(field, Mapping):
                raise ValueError("generic composition field is invalid")
            port, direction, width = field.get("port"), field.get("direction"), field.get("width")
            if (
                not isinstance(port, str) or not port
                or direction not in {"input", "output"}
                or isinstance(width, bool) or not isinstance(width, int) or width <= 0
            ):
                raise ValueError("generic composition field facts are invalid")
            if port in internal_ports:
                continue
            identity = f"{endpoint['endpoint_id']}:{field.get('role')}:{port}"
            existing = records.get(port)
            # Endpoints describe semantic views of the same source module.
            # Shared physical pins retain their first opaque binding; only
            # contradictory HDL facts constitute a conflict.
            opaque = existing["opaque_port"] if existing is not None else f"p_{canonical_id('generic-top-port', identity):016x}"
            record = {
                "source_port": port,
                "opaque_port": opaque,
                "direction": direction,
                "width": field.get("container_width", width),
                "signed": False if field.get("member_path") else field.get("signed", False),
                "members": (),
            }
            member_path = field.get("member_path")
            if member_path:
                if existing is not None and not existing.get("members"):
                    raise ValueError(f"generic composition mixes whole port and members: {port}")
                member = (tuple(member_path), field.get("raw_lo"), field.get("raw_hi"), width)
                prior = () if existing is None else existing["members"]
                for other in prior:
                    if not (member[2] < other[1] or member[1] > other[2]):
                        raise ValueError(f"generic composition member slices overlap: {port}")
                record["members"] = tuple(prior) + (member,)
            elif existing is not None and existing.get("members"):
                raise ValueError(f"generic composition mixes whole port and members: {port}")
            if existing is not None and any(existing[key] != record[key] for key in ("opaque_port", "direction", "width", "signed")):
                raise ValueError(f"generic composition port facts conflict: {port}")
            records[port] = record
    for port, record in records.items():
        if record["direction"] == "input" and record["members"]:
            if not _complete_ranges([(member[1], member[2]) for member in record["members"]], int(record["width"])):
                raise ValueError(f"generic composition input container is not fully covered: {port}")
    if require_records and not records:
        raise ValueError("generic composition has no source-backed ports")
    return tuple(sorted(records.values(), key=lambda item: str(item["opaque_port"])))


def _generic_source_top(plan: object, *, internal_ports: frozenset[str] = frozenset()) -> tuple[str, dict[str, dict[str, object]]]:
    ports = _generic_port_records(plan, internal_ports=internal_ports, require_records=False)
    description = getattr(plan, "interface_description", None)
    source = getattr(description, "source", None)
    top_module = getattr(source, "top_module", None)
    if not isinstance(top_module, str) or not top_module:
        raise ValueError("generic composition source top module is invalid")
    declarations: list[str] = []
    for record in ports:
        width = int(record["width"])
        shape = "logic" if width == 1 else f"logic {'signed ' if record['signed'] else ''}[{width - 1}:0]"
        signed = " signed" if record["signed"] and width == 1 else ""
        declarations.append(f"    {record['direction']} {shape}{signed} {record['opaque_port']}")
    return top_module, {str(record["source_port"]): record for record in ports}


def _sv_identifier(value: object, *, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", value) is None:
        raise ValueError(f"generic composition {context} is not a SystemVerilog identifier")
    return value


def _sv_logic(name: str, width: int, *, signed: bool = False) -> str:
    if width <= 0:
        raise ValueError("generic composition wire width is invalid")
    if width == 1:
        return f"logic{' signed' if signed else ''} {name}"
    return f"logic {'signed ' if signed else ''}[{width - 1}:0] {name}"


def _sv_literal(width: int, value: int) -> str:
    if width <= 0 or value < 0 or value >= 1 << width:
        raise ValueError("generic composition address literal is invalid")
    return f"{width}'h{value:x}"


def _source_parameter_clause(plan: object) -> str:
    source = getattr(getattr(plan, "interface_description", None), "source", None)
    elaboration = getattr(source, "elaboration", None)
    parameters = getattr(elaboration, "parameters", ()) if elaboration is not None else ()
    if not parameters:
        return ""
    rendered = []
    for name, value in parameters:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None or re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value) is None:
            raise ValueError("generic composition source parameter override is invalid")
        rendered.append(f".{name}({value})")
    return " #(\n        " + ",\n        ".join(rendered) + "\n  )"


def _complete_ranges(ranges: list[tuple[int, int]], width: int) -> bool:
    cursor = 0
    for low, high in sorted(ranges):
        if low != cursor or high < low or high >= width:
            return False
        cursor = high + 1
    return cursor == width


_PROCESSOR_BEAT_FIELDS = (
    "req_valid", "req_ready", "write", "addr", "wdata", "be",
    "rsp_valid", "rsp_ready", "rdata", "error",
)


def _processor_controls(plan: object) -> tuple[str, str, dict[str, str]]:
    """Return the processor clock/reset selected from semantic boundary facts."""
    from .auto import _generic_endpoint_reset_contract
    from .processor_boundary import build_processor_boundary

    catalog = getattr(plan, "protocol_catalog", None)
    if catalog is None:
        raise ValueError("processor composition protocol catalog is missing")
    boundary = build_processor_boundary(
        getattr(plan, "capabilities", ()), protocol_catalog=catalog,
        require_instruction_identity=False,
    )
    if len(boundary.clock.fields) != 1 or len(boundary.reset.fields) != 1:
        raise ValueError("processor composition control binding is incomplete")
    reset_endpoint = next(
        (item for item in getattr(plan, "capabilities", ())
         if item.endpoint_id == boundary.reset.endpoint_id),
        None,
    )
    if reset_endpoint is None:
        raise ValueError("processor composition reset evidence is missing")
    return (
        boundary.clock.fields[0].port,
        boundary.reset.fields[0].port,
        _generic_endpoint_reset_contract(reset_endpoint),
    )


def _processor_physical_signal(
    physical: Mapping[str, object], signals: Mapping[str, str],
) -> str:
    if "port" in physical:
        port = _sv_identifier(physical["port"], context="processor physical port")
        if port not in signals:
            raise ValueError("processor composition physical port is missing")
        return signals[port]
    port = _sv_identifier(
        physical.get("container_port"), context="processor physical container",
    )
    part_select = physical.get("part_select")
    lo, hi, width = (
        physical.get("raw_lo"), physical.get("raw_hi"),
        physical.get("container_width"),
    )
    if (
        port not in signals or not isinstance(part_select, str)
        or type(lo) is not int or type(hi) is not int or type(width) is not int
        or part_select != f"[{hi}:{lo}]" or lo < 0 or hi < lo or hi >= width
    ):
        raise ValueError("processor composition packed mapping is invalid")
    return signals[port] + part_select


def _validate_processor_drivers(routes: tuple[Mapping[str, object], ...]) -> None:
    """Prove that adapter-driven source inputs have pairwise unique ranges."""
    claims: list[tuple[str, int | None, int | None]] = []
    for route in routes:
        connections = route.get("field_connections")
        if not isinstance(connections, list | tuple):
            raise ValueError("processor composition field connections are invalid")
        for connection in connections:
            if not isinstance(connection, Mapping) or connection.get("direction") != "input":
                continue
            physical = connection.get("physical")
            if not isinstance(physical, Mapping):
                raise ValueError("processor composition physical mapping is invalid")
            if "port" in physical:
                claim = (str(physical["port"]), None, None)
            else:
                lo, hi = physical.get("raw_lo"), physical.get("raw_hi")
                if type(lo) is not int or type(hi) is not int:
                    raise ValueError("processor composition packed mapping is invalid")
                claim = (str(physical.get("container_port")), lo, hi)
            for prior in claims:
                if prior[0] != claim[0]:
                    continue
                if prior[1] is None or claim[1] is None or max(prior[1], claim[1]) <= min(prior[2], claim[2]):
                    raise ValueError(f"processor composition duplicate driver: {claim[0]}")
            claims.append(claim)


def _render_processor_backend_module(
    address_width: int, data_width: int, max_wait_cycles: int, synchrony: str,
) -> str:
    if not 1 <= max_wait_cycles <= 65_535:
        raise ValueError("processor composition backend wait bound is invalid")
    if synchrony not in {"synchronous", "asynchronous"}:
        raise ValueError("processor composition backend reset synchrony is invalid")
    reset_event = "" if synchrony == "synchronous" else " or negedge rst_ni"
    return f"""module myfuzz_processor_memory_backend (
    input logic clk_i, input logic rst_ni,
    input logic req_valid_i, output logic req_ready_o,
    input logic req_write_i, input logic [{address_width - 1}:0] req_addr_i,
    input logic [{data_width - 1}:0] req_wdata_i,
    input logic [{data_width // 8 - 1}:0] req_be_i, input logic req_mapped_i,
    output logic rsp_valid_o, input logic rsp_ready_i,
    output logic [{data_width - 1}:0] rsp_rdata_o, output logic rsp_error_o,
    input logic cancel_valid_i, output logic cancel_ready_o,
    output logic target_flush_o,
    output logic target_req_valid_o, input logic target_req_ready_i,
    output logic target_write_o, output logic [{address_width - 1}:0] target_addr_o,
    output logic [{data_width - 1}:0] target_wdata_o,
    output logic [{data_width // 8 - 1}:0] target_be_o,
    input logic target_rsp_valid_i, output logic target_rsp_ready_o,
    input logic [{data_width - 1}:0] target_rdata_i, input logic target_error_i
);
  localparam integer MAX_WAIT_CYCLES = {max_wait_cycles};
  typedef enum logic [2:0] {{IDLE, SEND_TARGET, WAIT_TARGET, RESPOND, FLUSH}} state_t;
  state_t state_q;
  logic [{address_width - 1}:0] addr_q;
  logic [{data_width - 1}:0] wdata_q, rdata_q;
  logic [{data_width // 8 - 1}:0] be_q;
  logic write_q, error_q, flush_after_response_q;
  integer unsigned wait_cycles_q;
  assign req_ready_o = rst_ni && state_q == IDLE && !cancel_valid_i;
  assign target_req_valid_o = state_q == SEND_TARGET && !cancel_valid_i;
  assign target_write_o = write_q;
  assign target_addr_o = addr_q;
  assign target_wdata_o = wdata_q;
  assign target_be_o = be_q;
  assign target_rsp_ready_o = state_q == WAIT_TARGET || state_q == FLUSH ||
                              (state_q == SEND_TARGET && target_req_ready_i);
  assign rsp_valid_o = state_q == RESPOND;
  assign rsp_rdata_o = rdata_q;
  assign rsp_error_o = error_q;
  assign target_flush_o = state_q == FLUSH;
  assign cancel_ready_o = cancel_valid_i &&
                          (state_q == IDLE || state_q == SEND_TARGET ||
                           (state_q == RESPOND && !flush_after_response_q) ||
                           state_q == FLUSH);
  always_ff @(posedge clk_i{reset_event}) begin
    if (!rst_ni) begin
      state_q <= IDLE; addr_q <= '0; wdata_q <= '0; be_q <= '0;
      write_q <= 1'b0; rdata_q <= '0; error_q <= 1'b0;
      flush_after_response_q <= 1'b0; wait_cycles_q <= 0;
    end else begin
      case (state_q)
        IDLE: begin
          wait_cycles_q <= 0; flush_after_response_q <= 1'b0;
          if (req_valid_i && req_ready_o) begin
            addr_q <= req_addr_i; wdata_q <= req_wdata_i; be_q <= req_be_i;
            write_q <= req_write_i;
            if (!req_mapped_i) begin
              rdata_q <= '0; error_q <= 1'b1; state_q <= RESPOND;
            end else state_q <= SEND_TARGET;
          end
        end
        SEND_TARGET: begin
          if (cancel_valid_i) state_q <= IDLE;
          else if (target_req_ready_i) begin
            wait_cycles_q <= 0;
            if (target_rsp_valid_i) begin
              rdata_q <= target_rdata_i; error_q <= target_error_i;
              state_q <= RESPOND;
            end else state_q <= WAIT_TARGET;
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            rdata_q <= '0; error_q <= 1'b1; state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        WAIT_TARGET: begin
          if (cancel_valid_i) begin
            state_q <= FLUSH;
          end
          else if (target_rsp_valid_i) begin
            rdata_q <= target_rdata_i; error_q <= target_error_i;
            state_q <= RESPOND;
          end else if (wait_cycles_q + 1 >= MAX_WAIT_CYCLES) begin
            rdata_q <= '0; error_q <= 1'b1;
            flush_after_response_q <= 1'b1; state_q <= RESPOND;
          end else begin
            wait_cycles_q <= wait_cycles_q + 1;
          end
        end
        RESPOND: begin
          if (cancel_valid_i || rsp_ready_i) begin
            if (flush_after_response_q) state_q <= FLUSH;
            else state_q <= IDLE;
          end
        end
        FLUSH: begin
          flush_after_response_q <= 1'b0; state_q <= IDLE;
        end
        default: state_q <= IDLE;
      endcase
    end
  end
endmodule
"""


def _processor_reset_signal(
    lines: list[str], *, domain: str, clock: str, raw_reset_n: str,
    source_contract: Mapping[str, str], target_contract: Mapping[str, str],
) -> str:
    """Render an explicit reset-domain adapter from normalized CPU reset."""
    if source_contract.get("polarity") not in {"active_low", "active_high"}:
        raise ValueError("processor composition source reset contract is invalid")
    if source_contract.get("synchrony") not in {"synchronous", "asynchronous"}:
        raise ValueError("processor composition source reset contract is invalid")
    polarity = target_contract.get("polarity")
    synchrony = target_contract.get("synchrony")
    if polarity not in {"active_low", "active_high"} or synchrony not in {"synchronous", "asynchronous"}:
        raise ValueError("processor composition target reset contract is invalid")
    active_low = f"{domain}_reset_n"
    lines.append(f"  logic {active_low};")
    if source_contract["synchrony"] == "asynchronous" and synchrony == "synchronous":
        synchronizer = f"{domain}_reset_sync_q"
        lines.extend((
            f"  logic [1:0] {synchronizer};",
            f"  always_ff @(posedge {clock} or negedge {raw_reset_n}) begin",
            f"    if (!{raw_reset_n}) {synchronizer} <= 2'b00;",
            f"    else {synchronizer} <= {{{synchronizer}[0], 1'b1}};",
            "  end",
            f"  assign {active_low} = {synchronizer}[1];",
        ))
    else:
        lines.append(f"  assign {active_low} = {raw_reset_n};")
    if polarity == "active_low":
        return active_low
    active_high = f"{domain}_reset"
    lines.extend((f"  logic {active_high};", f"  assign {active_high} = ~{active_low};"))
    return active_high


def _validate_processor_transducer(plan: object, contract_transducer: object) -> int:
    from .contract_transducer import ContractTransducerPlan
    from .processor_execution import processor_execution_document

    if not isinstance(contract_transducer, ContractTransducerPlan):
        raise ValueError("processor transducer requires a ContractTransducerPlan")
    if getattr(plan, "processor_execution", None) is None:
        raise ValueError("contract transducer requires processor execution")
    execution = processor_execution_document(plan.processor_execution)
    routes = execution["routes"]
    functions = {route["function"] for route in routes}
    split = len(routes) == 2 and functions == {
        "instruction_memory_master", "data_memory_master"
    }
    classification = execution.get("classification")
    unified = (
        len(routes) == 1
        and functions <= {"memory_master", "processor_memory_master"}
        and isinstance(classification, Mapping)
        and classification.get("mode") == "explicit_signal"
        and classification.get("field_role") == "instruction_identity"
        and isinstance(classification.get("physical"), Mapping)
    )
    if not (split or unified):
        raise ValueError("contract transducer requires split memory functions or explicit instruction identity")
    required_domains = {"instruction_memory_master", "data_memory_master"}
    if set(dict(contract_transducer.memory_domains)) != required_domains:
        raise ValueError("contract transducer memory functions do not match processor routes")
    if contract_transducer.protocol != ("processor-memory-beat", "1"):
        raise ValueError("contract transducer backend protocol does not match processor routes")
    for route in routes:
        if (route["widths"]["address"], route["widths"]["data"]) != (
            contract_transducer.address_width, contract_transducer.data_width,
        ):
            raise ValueError("contract transducer width does not match processor routes")
    contract_transducer.cycle_layout.validate()
    wait = contract_transducer.max_wait_cycles
    if type(wait) is not int or wait < 1:
        raise ValueError("contract transducer wait bound is invalid")
    watchdog = max(2 * wait + 16, *(int(route["backend_contract"]["capabilities"]["max_wait_cycles"])
                                  for route in routes))
    if watchdog > 65_535:
        raise ValueError("contract transducer outer wait bound exceeds 65535")
    return watchdog


def _render_processor_top(plan: object, backend: object, *, contract_transducer: object = None) -> str:
    from .processor_backend import processor_backend_document
    from .processor_execution import processor_execution_document

    execution = processor_execution_document(getattr(plan, "processor_execution"))
    routes = tuple(execution.get("routes", ()))
    backend_record = processor_backend_document(backend)
    backend_payload = {key: value for key, value in backend_record.items() if key != "backend_hash"}
    if backend_record.get("backend_hash") != content_hash(backend_payload):
        raise ValueError("processor composition routing evidence hash is invalid")
    if not routes or len(routes) not in (1, 2):
        raise ValueError("processor composition route topology is invalid")
    max_wait_cycles = int(backend_record["recovery"]["max_wait_cycles"])
    if contract_transducer is not None:
        max_wait_cycles = max(max_wait_cycles, _validate_processor_transducer(plan, contract_transducer))
    _validate_processor_drivers(routes)
    clock_port, reset_port, reset_semantics = _processor_controls(plan)
    all_records = {
        str(item["source_port"]): item for item in _generic_port_records(plan)
    }
    internal_ports = frozenset(
        str(physical.get("port", physical.get("container_port")))
        for route in routes
        for connection in route["field_connections"]
        for physical in (connection["physical"],)
    )
    classification = execution.get("classification")
    if isinstance(classification, Mapping):
        physical = classification.get("physical")
        if isinstance(physical, Mapping):
            port = physical.get("port", physical.get("container_port"))
            if isinstance(port, str) and port:
                internal_ports = frozenset((*internal_ports, port))
    source_module, external = _generic_source_top(
        plan, internal_ports=internal_ports,
    )
    source_signals = {
        port: (
            f"source_{canonical_id('generic-render-source-port', port):016x}"
            if port in internal_ports else str(record["opaque_port"])
        )
        for port, record in all_records.items()
    }
    if clock_port not in source_signals or reset_port not in source_signals:
        raise ValueError("processor composition control signal is missing")
    clock_signal = source_signals[clock_port]
    reset_signal = source_signals[reset_port]
    if reset_semantics["polarity"] == "active_low":
        normalized_reset = reset_signal
    elif reset_semantics["polarity"] == "active_high":
        normalized_reset = "processor_reset_n"
    else:
        raise ValueError("processor composition reset polarity is invalid")
    if reset_semantics["synchrony"] not in {"synchronous", "asynchronous"}:
        raise ValueError("processor composition reset synchrony is invalid")
    adapter_reset_contract = {"polarity": "active_low", "synchrony": "synchronous"}
    for route in routes:
        contract = route.get("reset_contract")
        if contract != adapter_reset_contract:
            raise ValueError("processor composition adapter reset contract is incompatible")

    declarations = []
    for record in sorted(external.values(), key=lambda item: str(item["opaque_port"])):
        width = int(record["width"])
        shape = "logic" if width == 1 else f"logic {'signed ' if record['signed'] else ''}[{width - 1}:0]"
        signed = " signed" if record["signed"] and width == 1 else ""
        declarations.append(f"    {record['direction']} {shape}{signed} {record['opaque_port']}")
    if contract_transducer is not None:
        declarations.extend((
            f"    input logic [{contract_transducer.cycle_layout.raw_width - 1}:0] rfuzz_cycle_bits",
            "    input logic test_begin",
            f"    input logic [{contract_transducer.address_width - 1}:0] test_boot_address",
            "    input logic test_illegal_instruction",
        ))
    lines = [
        "// Generated from source-backed interface annotations. Do not edit.",
        "module generic_composition_top (", ",\n".join(declarations), ");",
    ]
    for port in sorted(internal_ports):
        record = all_records.get(port)
        if record is None:
            raise ValueError("processor composition internal source port is missing")
        lines.append("  " + _sv_logic(source_signals[port], int(record["width"]), signed=bool(record["signed"])) + ";")
    if normalized_reset == "processor_reset_n":
        lines.extend(("  logic processor_reset_n;", f"  assign processor_reset_n = ~{reset_signal};"))
    adapter_reset = _processor_reset_signal(
        lines, domain="processor_adapter", clock=clock_signal,
        raw_reset_n=normalized_reset, source_contract=reset_semantics,
        target_contract=adapter_reset_contract,
    )
    source_connections = [
        f"        .{_sv_identifier(port, context='source port')}({source_signals[port]})"
        for port in sorted(all_records)
    ]
    lines.extend((
        f"  {source_module}{_source_parameter_clause(plan)} u_{canonical_id('generic-source-instance', source_module):016x} (",
        ",\n".join(source_connections), "  );",
    ))

    route_wires: list[dict[str, str]] = []
    for route in routes:
        tag = f"r_{int(route['route_id']):016x}"
        widths = route.get("widths")
        parameters = route.get("parameters")
        if not isinstance(widths, Mapping) or not isinstance(parameters, Mapping):
            raise ValueError("processor composition route parameters are invalid")
        address_width, data_width = int(widths["address"]), int(widths["data"])
        wires = {field: f"{tag}_{field}" for field in _PROCESSOR_BEAT_FIELDS}
        wires["mapped"] = f"{tag}_mapped"
        route_wires.append(wires)
        for name, width in (
            ("req_valid", 1), ("req_ready", 1), ("write", 1),
            ("addr", address_width), ("wdata", data_width),
            ("be", data_width // 8), ("rsp_valid", 1),
            ("rsp_ready", 1), ("rdata", data_width), ("error", 1),
            ("mapped", 1),
        ):
            lines.append("  " + _sv_logic(wires[name], width) + ";")
        terms = [
            f"({wires['addr']} >= {_sv_literal(address_width, int(region['base']))} && {wires['addr']} <= {_sv_literal(address_width, int(region['end']) - 1)})"
            for region in backend_record["address_decode"]["regions"]
        ]
        mapped = "1'b1" if contract_transducer is not None else (" || ".join(terms) if terms else "1'b0")
        lines.append(f"  assign {wires['mapped']} = {mapped};")
        adapter_connections = [f"        .clk_i({clock_signal})", f"        .rst_ni({adapter_reset})"]
        for connection in route["field_connections"]:
            physical = connection["physical"]
            adapter_connections.append(
                f"        .{_sv_identifier(connection['adapter_port'], context='processor adapter port')}({_processor_physical_signal(physical, source_signals)})"
            )
        backend_ports = {
            item["field_id"]: item["adapter_port"]
            for item in route["backend_contract"]["fields"]
        }
        for field in _PROCESSOR_BEAT_FIELDS:
            adapter_connections.append(
                f"        .{_sv_identifier(backend_ports[field], context='processor backend adapter port')}({wires[field]})"
            )
        parameter_lines = []
        for name, value in sorted(parameters.items()):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("processor composition adapter parameter is invalid")
            if contract_transducer is not None and name == "MAX_WAIT_CYCLES":
                value = max(value, max_wait_cycles)
            parameter_lines.append(f".{_sv_identifier(name, context='processor adapter parameter')}({value})")
        lines.extend((
            f"  {_sv_identifier(route['rtl_module'], context='processor adapter module')} #(\n        " + ",\n        ".join(parameter_lines) + f"\n  ) u_{tag} (",
            ",\n".join(adapter_connections), "  );",
        ))

    first_widths = routes[0]["widths"]
    address_width, data_width = int(first_widths["address"]), int(first_widths["data"])
    backend_wires = {field: f"backend_{field}" for field in _PROCESSOR_BEAT_FIELDS}
    lines.extend("  " + _sv_logic(backend_wires[name], width) + ";" for name, width in (
        ("req_valid", 1), ("req_ready", 1), ("write", 1),
        ("addr", address_width), ("wdata", data_width), ("be", data_width // 8),
        ("rsp_valid", 1), ("rsp_ready", 1), ("rdata", data_width), ("error", 1),
    ))
    lines.extend(("  logic backend_cancel_valid;", "  logic backend_cancel_ready;"))
    routing = backend_record["routing"]
    backend_reset_contract = routing.get("backend_reset_contract")
    if backend_reset_contract != {"polarity": "active_low", "synchrony": "asynchronous"}:
        raise ValueError("processor composition backend reset contract is malformed")
    backend_reset = _processor_reset_signal(
        lines, domain="processor_backend", clock=clock_signal,
        raw_reset_n=normalized_reset, source_contract=reset_semantics,
        target_contract=backend_reset_contract,
    )
    if len(routes) == 1:
        wires = route_wires[0]
        for field in ("req_valid", "write", "addr", "wdata", "be", "rsp_ready"):
            lines.append(f"  assign {backend_wires[field]} = {wires[field]};")
        for field in ("req_ready", "rsp_valid", "rdata", "error"):
            lines.append(f"  assign {wires[field]} = {backend_wires[field]};")
        lines.append("  assign backend_cancel_valid = 1'b0;")
        backend_mapped = wires["mapped"]
    else:
        arbiter = routing
        expected_source = arbiter.get("rtl_source")
        if (
            set(arbiter) != {"mode", "max_outstanding", "address_width", "data_width", "backend_reset_contract", "rtl_module", "rtl_source", "reset_contract", "fairness"}
            or expected_source not in backend_record.get("rtl_sources", ())
            or arbiter.get("reset_contract") != {"polarity": "active_low", "synchrony": "asynchronous"}
        ):
            raise ValueError("processor composition routing evidence is malformed")
        arbiter_reset = _processor_reset_signal(
            lines, domain="processor_arbiter", clock=clock_signal,
            raw_reset_n=normalized_reset, source_contract=reset_semantics,
            target_contract=arbiter["reset_contract"],
        )
        initiators = backend_record["initiators"]
        by_route = {int(route["route_id"]): wires for route, wires in zip(routes, route_wires)}
        ordered = [by_route[int(item["route_id"])] for item in initiators]
        connections = [f"        .clk_i({clock_signal})", f"        .rst_ni({arbiter_reset})"]
        for index, wires in enumerate(ordered):
            for field, suffix in (
                ("req_valid", "req_valid_i"), ("req_ready", "req_ready_o"),
                ("write", "req_write_i"), ("addr", "req_addr_i"),
                ("wdata", "req_wdata_i"), ("be", "req_be_i"),
                ("mapped", "req_mapped_i"), ("rsp_valid", "rsp_valid_o"),
                ("rsp_ready", "rsp_ready_i"), ("rdata", "rsp_rdata_o"),
                ("error", "rsp_error_o"),
            ):
                connections.append(f"        .i{index}_{suffix}({wires[field]})")
        for field, port in (
            ("req_valid", "req_valid_o"), ("req_ready", "req_ready_i"),
            ("write", "req_write_o"), ("addr", "req_addr_o"),
            ("wdata", "req_wdata_o"), ("be", "req_be_o"),
            ("rsp_valid", "rsp_valid_i"), ("rsp_ready", "rsp_ready_o"),
            ("rdata", "rsp_rdata_i"), ("error", "rsp_error_i"),
        ):
            connections.append(f"        .{port}({backend_wires[field]})")
        connections.extend((
            "        .cancel_valid_o(backend_cancel_valid)",
            "        .cancel_ready_i(backend_cancel_ready)",
        ))
        readonly = [1 if item["access"] == "read_only" else 0 for item in initiators]
        lines.extend((
            f"  {_sv_identifier(arbiter['rtl_module'], context='processor arbiter module')} #(\n"
            f"        .ADDRESS_WIDTH({address_width}), .DATA_WIDTH({data_width}),\n"
            f"        .MAX_WAIT_CYCLES({max_wait_cycles}),\n"
            f"        .INITIATOR0_READ_ONLY({readonly[0]}), .INITIATOR1_READ_ONLY({readonly[1]})\n"
            "  ) u_processor_backend_arbiter (",
            ",\n".join(connections), "  );",
        ))
        terms = [
            f"(backend_addr >= {_sv_literal(address_width, int(region['base']))} && backend_addr <= {_sv_literal(address_width, int(region['end']) - 1)})"
            for region in backend_record["address_decode"]["regions"]
        ]
        backend_mapped = "backend_mapped"
        mapped = "1'b1" if contract_transducer is not None else (" || ".join(terms) if terms else "1'b0")
        lines.extend(("  logic backend_mapped;", f"  assign backend_mapped = {mapped};"))
    backend_connections = [
        f"        .clk_i({clock_signal})", f"        .rst_ni({backend_reset})",
        "        .req_valid_i(backend_req_valid)", "        .req_ready_o(backend_req_ready)",
        "        .req_write_i(backend_write)", "        .req_addr_i(backend_addr)",
        "        .req_wdata_i(backend_wdata)", "        .req_be_i(backend_be)",
        f"        .req_mapped_i({backend_mapped})", "        .rsp_valid_o(backend_rsp_valid)",
        "        .rsp_ready_i(backend_rsp_ready)", "        .rsp_rdata_o(backend_rdata)",
        "        .rsp_error_o(backend_error)", "        .cancel_valid_i(backend_cancel_valid)",
        "        .cancel_ready_o(backend_cancel_ready)",
        "        .target_flush_o(backend_target_flush)",
    ]
    target_wires = {
        field: f"backend_target_{field}" for field in _PROCESSOR_BEAT_FIELDS
    }
    for name, width in (
        ("req_valid", 1), ("req_ready", 1), ("write", 1),
        ("addr", address_width), ("wdata", data_width), ("be", data_width // 8),
        ("rsp_valid", 1), ("rsp_ready", 1), ("rdata", data_width), ("error", 1),
    ):
        lines.append("  " + _sv_logic(target_wires[name], width) + ";")
    lines.append("  logic backend_target_flush;")
    backend_connections.extend((
        "        .target_req_valid_o(backend_target_req_valid)",
        "        .target_req_ready_i(backend_target_req_ready)",
        "        .target_write_o(backend_target_write)",
        "        .target_addr_o(backend_target_addr)",
        "        .target_wdata_o(backend_target_wdata)",
        "        .target_be_o(backend_target_be)",
        "        .target_rsp_valid_i(backend_target_rsp_valid)",
        "        .target_rsp_ready_o(backend_target_rsp_ready)",
        "        .target_rdata_i(backend_target_rdata)",
        "        .target_error_i(backend_target_error)",
    ))
    components = getattr(plan, "components", ()) if contract_transducer is None else ()
    if not isinstance(components, tuple):
        raise ValueError("processor composition component records are invalid")
    response_terms: list[tuple[str, str, str, str]] = []
    for component in components:
        if not isinstance(component, Mapping):
            raise ValueError("processor composition component record is invalid")
        protocol = component.get("protocol")
        if not isinstance(protocol, Mapping) or (protocol.get("id"), protocol.get("version")) != ("processor-memory-beat", "1"):
            raise ValueError("processor composition backend target protocol is invalid")
        binding = component.get("target_binding")
        if not isinstance(binding, Mapping) or not isinstance(binding.get("fields"), list | tuple):
            raise ValueError("processor composition backend target binding is invalid")
        fields = {str(item["role"]): item for item in binding["fields"] if item["role"] not in {"clock", "reset"}}
        if set(fields) != set(_PROCESSOR_BEAT_FIELDS):
            raise ValueError("processor composition backend target fields are incomplete")
        tag = f"c_{canonical_id('processor-backend-component', str(component['component_id'])):016x}"
        region = next(
            (item for item in backend_record["address_decode"]["regions"]
             if item["component_id"] == component["component_id"]), None,
        )
        if region is None:
            raise ValueError("processor composition backend target region is missing")
        select = f"{tag}_select"
        lines.extend((
            f"  logic {select};",
            f"  assign {select} = backend_target_addr >= {_sv_literal(address_width, int(region['base']))} && backend_target_addr <= {_sv_literal(address_width, int(region['end']) - 1)};",
        ))
        component_signals: dict[str, str] = {}
        for role, width in (
            ("req_valid", 1), ("req_ready", 1), ("write", 1),
            ("addr", address_width), ("wdata", data_width), ("be", data_width // 8),
            ("rsp_valid", 1), ("rsp_ready", 1), ("rdata", data_width), ("error", 1),
        ):
            component_signals[role] = f"{tag}_{role}"
            lines.append("  " + _sv_logic(component_signals[role], width) + ";")
        lines.extend((
            f"  assign {component_signals['req_valid']} = backend_target_req_valid && {select};",
            f"  assign {component_signals['write']} = backend_target_write;",
            f"  assign {component_signals['addr']} = backend_target_addr;",
            f"  assign {component_signals['wdata']} = backend_target_wdata;",
            f"  assign {component_signals['be']} = backend_target_be;",
            f"  assign {component_signals['rsp_ready']} = backend_target_rsp_ready && {select};",
        ))
        control = binding.get("control")
        if not isinstance(control, Mapping):
            raise ValueError("processor composition backend target control is invalid")
        recovery = binding.get("recovery")
        if (
            not isinstance(recovery, Mapping)
            or recovery.get("mode") != "reset_flush"
            or recovery.get("acknowledgment") != "one_active_clock_edge"
            or recovery.get("late_response_after_ack") != "forbidden"
            or recovery.get("reset_semantics") != control.get("reset_semantics")
        ):
            raise ValueError("processor composition backend target recovery contract is invalid")
        target_reset_contract = control.get("reset_semantics")
        if not isinstance(target_reset_contract, Mapping):
            raise ValueError("processor composition backend target reset contract is invalid")
        target_reset = _processor_reset_signal(
            lines, domain=tag, clock=clock_signal, raw_reset_n=normalized_reset,
            source_contract=reset_semantics, target_contract=target_reset_contract,
        )
        component_reset = f"{tag}_flush_reset"
        lines.append(f"  logic {component_reset};")
        selected_flush = f"(backend_target_flush && {select})"
        if target_reset_contract["polarity"] == "active_low":
            lines.append(f"  assign {component_reset} = {target_reset} && !{selected_flush};")
        else:
            lines.append(f"  assign {component_reset} = {target_reset} || {selected_flush};")
        component_connections = [
            f"        .{_sv_identifier(fields[role]['port'], context='processor component port')}({component_signals[role]})"
            for role in _PROCESSOR_BEAT_FIELDS
        ]
        component_connections.extend((
            f"        .{_sv_identifier(control['clock']['target_port'], context='processor component clock')}({clock_signal})",
            f"        .{_sv_identifier(control['reset']['target_port'], context='processor component reset')}({component_reset})",
        ))
        parameter_text = []
        parameters = component.get("parameters")
        if not isinstance(parameters, Mapping):
            raise ValueError("processor composition component parameters are invalid")
        for name, value in sorted(parameters.items()):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError("processor composition component parameter is invalid")
            parameter_text.append(f".{_sv_identifier(name, context='processor component parameter')}({value})")
        module_name = _sv_identifier(component["module_name"], context="processor component module")
        parameter_clause = "" if not parameter_text else " #(\n        " + ",\n        ".join(parameter_text) + "\n  )"
        lines.extend((
            f"  {module_name}{parameter_clause} u_{tag} (",
            ",\n".join(component_connections), "  );",
        ))
        response_terms.append((
            f"({select} && {component_signals['req_ready']})",
            f"({select} && {component_signals['rsp_valid']})", component_signals["rdata"],
            component_signals["error"],
        ))
    if contract_transducer is not None:
        lines.extend((
            "  logic backend_req_instruction;",
            "  logic backend_target_req_instruction;",
            f"  always_ff @(posedge {clock_signal} or negedge {backend_reset}) begin",
            f"    if (!{backend_reset}) begin",
            "      backend_req_instruction <= 1'b0;",
            "      backend_target_req_instruction <= 1'b0;",
            "    end else begin",
        ))
        classification_signal = None
        if isinstance(classification, Mapping):
            physical = classification.get("physical")
            if isinstance(physical, Mapping):
                classification_signal = _processor_physical_signal(physical, source_signals)
        for route, wires in zip(routes, route_wires):
            instruction = (
                classification_signal
                if classification_signal is not None
                else ("1'b1" if route["function"] == "instruction_memory_master" else "1'b0")
            )
            lines.append(f"      if ({wires['req_valid']} && {wires['req_ready']}) backend_req_instruction <= {instruction};")
        lines.extend((
            "      if (backend_req_valid && backend_req_ready)",
            "        backend_target_req_instruction <= backend_req_instruction;",
            "    end",
            "  end",
            "  myfuzz_contract_transducer u_contract_transducer (",
            f"    .clock_i({clock_signal}), .reset_i({backend_reset} && !backend_target_flush),",
            "    .test_begin_i(test_begin), .test_boot_address_i(test_boot_address),",
            "    .test_illegal_instruction_i(test_illegal_instruction), .rfuzz_cycle_bits(rfuzz_cycle_bits),",
            "    .req_valid_i(backend_target_req_valid), .req_ready_o(backend_target_req_ready),",
            "    .req_instruction_i(backend_target_req_instruction), .req_addr_i(backend_target_addr),",
            "    .req_write_i(backend_target_write), .req_wdata_i(backend_target_wdata), .req_be_i(backend_target_be),",
            "    .rsp_valid_o(backend_target_rsp_valid), .rsp_data_o(backend_target_rdata),",
            "    .rsp_error_o(backend_target_error)",
            "  );",
        ))
    elif response_terms:
        lines.append("  assign backend_target_req_ready = " + " || ".join(item[0] for item in response_terms) + ";")
        lines.append("  assign backend_target_rsp_valid = " + " || ".join(item[1] for item in response_terms) + ";")
        lines.append("  assign backend_target_rdata = " + " | ".join(f"({item[1]} ? {item[2]} : '0)" for item in response_terms) + ";")
        lines.append("  assign backend_target_error = " + " || ".join(f"({item[1]} && {item[3]})" for item in response_terms) + ";")
    else:
        lines.extend((
            "  assign backend_target_req_ready = 1'b0;",
            "  assign backend_target_rsp_valid = 1'b0;",
            "  assign backend_target_rdata = '0;",
            "  assign backend_target_error = 1'b0;",
        ))
    lines.extend((
        "  myfuzz_processor_memory_backend u_processor_memory_backend (",
        ",\n".join(backend_connections), "  );", "endmodule", "",
        _render_processor_backend_module(
            address_width, data_width,
            max_wait_cycles,
            str(backend_reset_contract["synchrony"]),
        ),
    ))
    return "\n".join(lines)
