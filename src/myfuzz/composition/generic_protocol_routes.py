"""Bounded same-protocol routes, selected only by declared protocol semantics.

APB has a setup and an access phase; Wishbone classic holds a cycle until
ACK/ERR. Neither route supports queues, pipelining, clock crossing or AXI.
"""
from .ids import canonical_id


def native_contract(protocol, plugin):
    if protocol not in {("apb", "3"), ("apb", "4"), ("wishbone", "classic")}:
        return None
    apb = protocol[0] == "apb"
    request = {"paddr", "psel", "penable", "pwrite", "pwdata"} if apb else {"cyc", "stb", "we", "adr", "dat_w", "sel"}
    response = {"pready", "prdata", "pslverr"} if apb else {"ack", "err", "dat_r"}
    if protocol == ("apb", "4"):
        request |= {"pprot", "pstrb"}
    expected = {**{f: "host_to_device" for f in request}, **{f: "device_to_host" for f in response}}
    fields = plugin.fields
    if not apb:
        optional_stall = [f for f in fields if f.field_id == "stall"]
        if optional_stall:
            if len(optional_stall) != 1 or optional_stall[0].required or optional_stall[0].runtime_required or optional_stall[0].direction != "device_to_host" or optional_stall[0].width_expression != "1":
                raise ValueError("native-fields:pipelined-stall-unsupported")
            fields = tuple(f for f in fields if f.field_id != "stall")
    actual = {f.field_id: f.direction for f in fields}
    if actual != expected or len(fields) != len(expected):
        raise ValueError("native-fields:unknown-or-missing-channel")
    limits = dict(plugin.capability_limits)
    expected_limits = {"max_outstanding": 1, "byte_enable": protocol != ("apb", "3"), "partial_write": protocol != ("apb", "3")}
    if not apb:
        expected_limits.update(single_beat_only=True, stall_supported=False, completion="ack_or_err")
    if set(limits) != set(expected_limits) | {"max_wait_cycles"} or any(type(limits.get(k)) is not type(v) or limits.get(k) != v for k, v in expected_limits.items()):
        raise ValueError("native-capabilities:unsupported-feature")
    relation_kind = "setup_access_response" if apb else "cycle_strobe_held_until_completion"
    relation_fields = ({"psel", "penable", "pready"} | ({"pstrb"} if protocol[1] == "4" else set())) if apb else {"cyc", "stb", "ack", "err"}
    if len(plugin.channel_relations) != 1 or plugin.channel_relations[0].kind != relation_kind or set(plugin.channel_relations[0].field_ids) != relation_fields:
        raise ValueError("native-relations:unsupported-channel")
    bounds = [limits.get("max_wait_cycles")]
    bounds.extend(a.max_cycles for a in plugin.projection_actions if a.kind == "gate")
    bounds.extend(r.max_cycles for r in plugin.temporal_rules)
    if any(type(v) is not int or not 1 <= v <= 65535 for v in bounds):
        raise ValueError("native-bound:invalid")
    return {"mode": "native_apb" if apb else "native_wishbone_classic", "request_fields": sorted(request),
            "response_fields": sorted(response), "address_field_id": "paddr" if apb else "adr", "max_wait_cycles": min(bounds)}


def render_native_adapter(route):
    """Latch payload; propagate completion only during the native active phase."""
    contract = route["contract"]
    apb = contract["mode"] == "native_apb"
    if contract["mode"] not in {"native_apb", "native_wishbone_classic"}:
        raise ValueError("unsupported native mode")
    by_id = {f["field_id"]: f for f in route["fields"]}
    request, response = set(contract["request_fields"]), set(contract["response_fields"])
    if set(by_id) != request | response:
        raise ValueError("native route requires all semantic fields including error response")
    scalars = {"psel", "penable", "pwrite", "pready", "pslverr"} if apb else {"cyc", "stb", "we", "ack", "err"}
    for name, f in by_id.items():
        if f["direction"] != ("input" if name in request else "output") or f["signed"] or int(f["width"]) < 1 or (name in scalars and f["width"] != 1):
            raise ValueError("native route field shape is unsupported")
    address = contract["address_field_id"]
    data = "pwdata" if apb else "dat_w"
    read_data = "prdata" if apb else "dat_r"
    if by_id[data]["width"] != by_id[read_data]["width"] or by_id[data]["width"] % 8:
        raise ValueError("native route data width is unsupported")
    for be in ("pstrb", "sel"):
        if be in by_id and by_id[be]["width"] * 8 != by_id[data]["width"]:
            raise ValueError("native route byte enable width is unsupported")
    if "pprot" in by_id and by_id["pprot"]["width"] != 3:
        raise ValueError("native route protection width is unsupported")
    def sig(prefix, name):
        return f"{prefix}_f_{canonical_id('generic-render-field', name):016x}"
    s = lambda name: sig("source", name)
    t = lambda name: sig("target", name)
    r = lambda name: sig("response", name)
    q = lambda name: sig("payload", name)
    tag = f"{canonical_id('generic-render-route', str(route['component_id'])):016x}"
    semantics = route["control"]["reset_semantics"]
    if semantics not in ({"polarity": p, "synchrony": sy} for p in ("active_low", "active_high") for sy in ("synchronous", "asynchronous")):
        raise ValueError("native reset semantics unsupported")
    low = semantics["polarity"] == "active_low"
    event = (" or negedge reset" if low else " or posedge reset") if semantics["synchrony"] == "asynchronous" else ""
    bound = route["max_wait_cycles"]
    if type(bound) is not int or not 1 <= bound <= 65535 or bound != contract["max_wait_cycles"]:
        raise ValueError("native bound invalid")
    ports = ["input logic clock", "input logic reset", "input logic component_select"]
    declarations, assignments, capture, reset = [], [], [], []
    control_fields = {"psel", "penable"} if apb else {"cyc", "stb"}
    live = f"{s('psel')} && {s('penable')}" if apb else f"{s('cyc')} && {s('stb')}"
    for name, f in by_id.items():
        shape = f"logic [{int(f['width'])-1}:0]"
        if name in request:
            ports += [f"input {shape} {s(name)}", f"output {shape} {t(name)}"]
            if name not in control_fields:
                declarations.append(f"{shape} {q(name)};")
                capture.append(f"{q(name)} <= {s(name)}" + (" - ADDRESS_BASE" if name == address else "") + ";")
                reset.append(f"{q(name)} <= '0;")
                assignments.append(f"assign {t(name)} = {q(name)};")
        else:
            ports += [f"input {shape} {t(name)}", f"output {shape} {r(name)}"]
    if apb:
        assignments += [f"assign {t('psel')} = (state == SETUP || state == ACTIVE) && {s('psel')};",
                        f"assign {t('penable')} = active;",
                        f"assign {r('pready')} = active && ({t('pready')} || expired);",
                        f"assign {r('pslverr')} = active && ({t('pready')} ? {t('pslverr')} : expired);",
                        f"assign {r('prdata')} = active && {t('pready')} ? {t('prdata')} : '0;"]
        start = f"{s('psel')} && !{s('penable')}"
        done = f"{t('pready')} || expired"
        phases = [f"SETUP: if (!{s('psel')}) state <= IDLE; else if ({s('penable')}) state <= ACTIVE; else if (expired) state <= DRAIN; else count <= count + 1;",
                  f"ACTIVE: if (!({live})) state <= IDLE; else if ({done}) state <= IDLE; else count <= count + 1;",
                  f"DRAIN: if (!{s('psel')}) state <= IDLE;"]
        # SETUP waiting does not consume the target's access response budget.
        phases[0] = phases[0].replace("state <= ACTIVE;", "begin state <= ACTIVE; count <= 0; end")
    else:
        assignments += [f"assign {t('cyc')} = active;", f"assign {t('stb')} = active;",
                        f"assign {r('err')} = active && ({t('err')} || (!{t('ack')} && expired));",
                        f"assign {r('ack')} = active && {t('ack')} && !{t('err')};",
                        f"assign {r('dat_r')} = active && {t('ack')} && !{t('err')} ? {t('dat_r')} : '0;"]
        start = live
        done = f"{t('ack')} || {t('err')} || expired"
        phases = [f"ACTIVE: if (!({live})) state <= IDLE; else if ({done}) state <= DRAIN; else count <= count + 1;",
                  f"DRAIN: if (!({live})) state <= IDLE;"]
    width = int(by_id[address]["width"])
    return "\n".join([f"module myfuzz_generic_adapter_{tag} #(parameter logic [{width-1}:0] ADDRESS_BASE = {width}'h{int(route['base']):x})(",
        ",\n".join(ports), ");", f"localparam integer MAX_WAIT_CYCLES = {bound};",
        "typedef enum logic [1:0] {IDLE, SETUP, ACTIVE, DRAIN} state_t; state_t state;",
        "integer count; wire expired = count >= MAX_WAIT_CYCLES - 1;",
        f"wire active = state == ACTIVE && ({live});", *declarations, *assignments,
        f"always_ff @(posedge clock{event}) begin if ({'!reset' if low else 'reset'}) begin state <= IDLE; count <= 0;", *reset,
        "end else case(state)", f"IDLE: if ({start}) begin count <= 0; if (component_select) begin", *capture,
        f"state <= {'SETUP' if apb else 'ACTIVE'}; end else state <= DRAIN; end", *phases,
        "default: state <= IDLE; endcase end", "endmodule\n"])
