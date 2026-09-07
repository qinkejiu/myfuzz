"""Single-target, single-outstanding AXI4-Lite native routing.

AW and W reserve one shared slot in either order; reads cannot overtake a
partial write. The target wait budget starts on downstream request assertion,
not while waiting for the source's other write channel or response READY.
Timeout returns SLVERR and quarantines the route until reset. Already asserted
downstream VALID/payload remain stable until handshake (including in quarantine)
or reset; late responses are never forwarded. Reset must reset both endpoints.
Invalid AW/AR addresses return DECERR locally, without entering quarantine.
"""
from .ids import canonical_id


REQUEST_WIDTHS = {
    "awaddr": "address_width", "awprot": "3", "awvalid": "1",
    "wdata": "data_width", "wstrb": "data_width / 8", "wvalid": "1",
    "bready": "1", "araddr": "address_width", "arprot": "3",
    "arvalid": "1", "rready": "1",
}
RESPONSE_WIDTHS = {
    "awready": "1", "wready": "1", "bresp": "2", "bvalid": "1",
    "arready": "1", "rdata": "data_width", "rresp": "2", "rvalid": "1",
}


def native_axi_lite_contract(plugin):
    """Fail closed on unsupported catalog channels, capabilities and bounds."""
    widths = {**REQUEST_WIDTHS, **RESPONSE_WIDTHS}
    if len(plugin.fields) != len(widths) or {f.field_id for f in plugin.fields} != set(widths):
        raise ValueError("native-fields:unknown-or-missing-channel")
    for field in plugin.fields:
        direction = "host_to_device" if field.field_id in REQUEST_WIDTHS else "device_to_host"
        if field.direction != direction or field.width_expression != widths[field.field_id] or not (field.required or field.runtime_required):
            raise ValueError("native-fields:unsupported-shape")
    limits = dict(plugin.capability_limits)
    expected = {"max_outstanding": 1, "bursts": False, "ids": False, "byte_enable": True, "partial_write": True}
    if len(limits) != len(plugin.capability_limits) or set(limits) != set(expected) | {"max_wait_cycles"} or any(type(limits.get(k)) is not type(v) or limits.get(k) != v for k, v in expected.items()):
        raise ValueError("native-capabilities:unsupported-feature")
    relations = {
        "write_address_and_data_before_response": {"awvalid", "awready", "wvalid", "wready", "bvalid", "bready"},
        "read_address_before_response": {"arvalid", "arready", "rvalid", "rready"},
    }
    if len(plugin.channel_relations) != 2 or {r.kind for r in plugin.channel_relations} != set(relations) or any(set(r.field_ids) != relations[r.kind] or len(r.field_ids) != len(relations[r.kind]) for r in plugin.channel_relations):
        raise ValueError("native-relations:unsupported-channel")
    temporal_shapes = {
        ("handshake", "awvalid", "awready"), ("handshake", "wvalid", "wready"),
        ("write_response", "bready", "bvalid"), ("handshake", "arvalid", "arready"),
        ("read_response", "rready", "rvalid"),
    }
    if len(plugin.temporal_rules) != len(temporal_shapes) or {(r.kind, r.antecedent_field_id, r.consequent_field_id) for r in plugin.temporal_rules} != temporal_shapes:
        raise ValueError("native-temporal:unsupported-channel")
    projection_shapes = {
        ("mask", "address_validity", frozenset({"awaddr", "araddr"})),
        ("gate", "protocol_legality", frozenset({"awvalid", "wvalid", "bready", "arvalid", "rready"})),
        ("fold_xor", "dependency_consistency", frozenset({"wdata"})),
    }
    if len(plugin.projection_actions) != len(projection_shapes) or {(a.kind, a.category, frozenset(a.field_ids)) for a in plugin.projection_actions} != projection_shapes or any(len(a.field_ids) != len(set(a.field_ids)) or a.constant_value is not None or (a.kind != "gate" and a.max_cycles is not None) for a in plugin.projection_actions):
        raise ValueError("native-projection:unsupported-channel")
    bounds = [limits.get("max_wait_cycles")]
    bounds.extend(a.max_cycles for a in plugin.projection_actions if a.kind == "gate")
    bounds.extend(r.max_cycles for r in plugin.temporal_rules)
    if any(type(v) is not int or not 1 <= v <= 65535 for v in bounds):
        raise ValueError("native-bound:invalid")
    return {"mode": "native_axi4_lite", "request_fields": sorted(REQUEST_WIDTHS),
            "response_fields": sorted(RESPONSE_WIDTHS), "address_field_ids": ["awaddr", "araddr"],
            "max_wait_cycles": min(bounds)}


def render_axi_lite_adapter(route):
    """Render registered independent channels with timeout quarantine."""
    contract = route["contract"]
    fields = {f["field_id"]: f for f in route["fields"]}
    widths = {**REQUEST_WIDTHS, **RESPONSE_WIDTHS}
    if set(fields) != set(widths) or len(route["fields"]) != len(widths):
        raise ValueError("native AXI4-Lite requires all semantic fields")
    if tuple(contract.get("request_fields", ())) != tuple(sorted(REQUEST_WIDTHS)) or tuple(contract.get("response_fields", ())) != tuple(sorted(RESPONSE_WIDTHS)) or tuple(contract.get("address_field_ids", ())) != ("awaddr", "araddr"):
        raise ValueError("native AXI4-Lite contract is unsupported")
    address_width, data_width = fields["awaddr"]["width"], fields["wdata"]["width"]
    if type(address_width) is not int or address_width < 1 or type(data_width) is not int or data_width not in (32, 64):
        raise ValueError("native AXI4-Lite address/data width is unsupported")
    for name, field in fields.items():
        width = {"address_width": address_width, "data_width": data_width, "data_width / 8": data_width // 8}.get(widths[name])
        if width is None:
            width = int(widths[name])
        if type(field["width"]) is not int or field["width"] != width or field["signed"] or field["direction"] != ("input" if name in REQUEST_WIDTHS else "output") or field["address"] != (name in {"awaddr", "araddr"}):
            raise ValueError("native AXI4-Lite field shape is unsupported")
    base, size = route["base"], route["size"]
    if type(base) is not int or type(size) is not int or base < 0 or size < 1 or base + size > 1 << address_width:
        raise ValueError("native AXI4-Lite address region is unsupported")
    bound = route["max_wait_cycles"]
    if type(bound) is not int or not 1 <= bound <= 65535 or bound != contract["max_wait_cycles"]:
        raise ValueError("native AXI4-Lite bound is invalid")
    semantics = route["control"]["reset_semantics"]
    if semantics not in ({"polarity": p, "synchrony": sy} for p in ("active_low", "active_high") for sy in ("synchronous", "asynchronous")):
        raise ValueError("native AXI4-Lite reset semantics unsupported")
    low = semantics["polarity"] == "active_low"
    event = (" or negedge reset" if low else " or posedge reset") if semantics["synchrony"] == "asynchronous" else ""
    tag = f"{canonical_id('generic-render-route', str(route['component_id'])):016x}"
    ports = ["input logic clock", "input logic reset", "input logic component_select"]
    # Keep readable local names; only the module boundary uses opaque field IDs.
    aliases = []
    for name, field in fields.items():
        hashed = f"f_{canonical_id('generic-render-field', name):016x}"
        for prefix in (("source", "target") if name in REQUEST_WIDTHS else ("target", "response")):
            incoming = prefix == "source" or (prefix == "target" and name in RESPONSE_WIDTHS)
            shape = f"logic [{field['width']-1}:0]"
            ports.append(f"{'input' if incoming else 'output'} {shape} {prefix}_{hashed}")
            aliases.append(f"{shape} {prefix}_{name};")
            left, right = (f"{prefix}_{name}", f"{prefix}_{hashed}") if incoming else (f"{prefix}_{hashed}", f"{prefix}_{name}")
            aliases.append(f"assign {left} = {right};")
    payloads = ("awaddr", "awprot", "wdata", "wstrb", "araddr", "arprot")
    payload_reset = "\n".join(f"target_{name} <= '0;" for name in payloads)
    return "\n".join([
        f"module myfuzz_generic_adapter_{tag} #(parameter logic [{address_width-1}:0] ADDRESS_BASE = {address_width}'h{base:x})(",
        ",\n".join(ports), ");", *aliases,
        f"localparam logic [{address_width}:0] ADDRESS_SIZE = {address_width+1}'h{size:x};",
        f"localparam integer MAX_WAIT_CYCLES = {bound};",
        f"wire reset_active = {'!reset' if low else 'reset'};",
        """
// component_select is intentionally unused: AW and AR decode independently.
// The extended comparison also permits regions ending at 2**address_width.
wire aw_selected = {1'b0, source_awaddr} >= {1'b0, ADDRESS_BASE} &&
                   {1'b0, source_awaddr} < {1'b0, ADDRESS_BASE} + ADDRESS_SIZE;
wire ar_selected = {1'b0, source_araddr} >= {1'b0, ADDRESS_BASE} &&
                   {1'b0, source_araddr} < {1'b0, ADDRESS_BASE} + ADDRESS_SIZE;
typedef enum logic [2:0] {IDLE, COLLECT, WRITE, READ, B_RESPONSE, R_RESPONSE, QUARANTINE} state_t;
state_t state;
logic aw_have, w_have, aw_selected_q, poisoned;
integer count;
wire expired = count >= MAX_WAIT_CYCLES - 1;
assign response_awready = !reset_active && (state == IDLE || state == COLLECT) && !aw_have;
assign response_wready = !reset_active && (state == IDLE || state == COLLECT) && !w_have;
// Writes win simultaneous arbitration and reserve the sole outstanding slot.
assign response_arready = !reset_active && state == IDLE && !source_awvalid && !source_wvalid;
assign response_bvalid = state == B_RESPONSE;
assign response_rvalid = state == R_RESPONSE;
assign target_bready = state == WRITE && !target_awvalid && !target_wvalid;
assign target_rready = state == READ && !target_arvalid;
""",
        f"always_ff @(posedge clock{event}) begin\nif (reset_active) begin",
        """
state <= IDLE; aw_have <= 0; w_have <= 0; aw_selected_q <= 0; poisoned <= 0; count <= 0;
target_awvalid <= 0; target_wvalid <= 0; target_arvalid <= 0;
response_bresp <= 0; response_rresp <= 0; response_rdata <= 0;
""", payload_reset, """
end else begin
  // These handshake clears remain active in quarantine. A stalled VALID is
  // never withdrawn on timeout; no further transactions can reuse its slot.
  if (target_awvalid && target_awready) target_awvalid <= 0;
  if (target_wvalid && target_wready) target_wvalid <= 0;
  if (target_arvalid && target_arready) target_arvalid <= 0;
  if (source_awvalid && response_awready) begin
    aw_have <= 1; aw_selected_q <= aw_selected;
    target_awaddr <= source_awaddr - ADDRESS_BASE; target_awprot <= source_awprot;
  end
  if (source_wvalid && response_wready) begin
    w_have <= 1; target_wdata <= source_wdata; target_wstrb <= source_wstrb;
  end
  case (state)
    IDLE: begin
      count <= 0;
      if (source_awvalid || source_wvalid) state <= COLLECT;
      else if (source_arvalid && response_arready) begin
        target_araddr <= source_araddr - ADDRESS_BASE; target_arprot <= source_arprot;
        if (ar_selected) begin target_arvalid <= 1; state <= READ; end
        else begin response_rresp <= 2'b11; response_rdata <= 0; state <= R_RESPONSE; end
      end
    end
    COLLECT: if (aw_have && w_have) begin
      count <= 0;
      if (aw_selected_q) begin target_awvalid <= 1; target_wvalid <= 1; state <= WRITE; end
      else begin response_bresp <= 2'b11; state <= B_RESPONSE; end
    end
    WRITE: begin
      if (target_bvalid && target_bready) begin response_bresp <= target_bresp; state <= B_RESPONSE; end
      else if (expired) begin response_bresp <= 2'b10; poisoned <= 1; state <= B_RESPONSE; end
      else count <= count + 1;
    end
    READ: begin
      if (target_rvalid && target_rready) begin response_rresp <= target_rresp; response_rdata <= target_rdata; state <= R_RESPONSE; end
      else if (expired) begin response_rresp <= 2'b10; response_rdata <= 0; poisoned <= 1; state <= R_RESPONSE; end
      else count <= count + 1;
    end
    B_RESPONSE: if (source_bready) begin
      aw_have <= 0; w_have <= 0;
      if (poisoned) state <= QUARANTINE; else state <= IDLE;
    end
    R_RESPONSE: if (source_rready) begin
      if (poisoned) state <= QUARANTINE; else state <= IDLE;
    end
    QUARANTINE: begin end
    default: state <= QUARANTINE;
  endcase
end
end
endmodule
"""])
