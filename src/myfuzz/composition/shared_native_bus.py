"""Protocol-only shared native fanout downstream of one transaction latch.

Groups are derived from validated routes, never from cached fabric metadata.
The existing native adapter owns phase, payload, timeout and abort state; this
decoder therefore sees a held address throughout every downstream transaction.
"""
from collections import defaultdict

from .ids import canonical_id


def validate_groups(routes):
    groups = defaultdict(list)
    for route in routes:
        groups[route["source_endpoint_id"]].append(route)
    for group in groups.values():
        if len(group) < 2:
            continue
        first = group[0]
        if first["contract"]["mode"] not in {"native_apb", "native_wishbone_classic"}:
            raise ValueError("shared native protocol unsupported")
        def shape(route):
            return sorted((f["field_id"], f["source_port"], f["source_direction"],
                           f["direction"], f["width"], f["signed"], f["address"])
                          for f in route["fields"])
        end = 0
        for route in sorted(group, key=lambda r: r["base"]):
            if (route["contract"] != first["contract"] or shape(route) != shape(first)
                    or any(f["irq_route"] for f in route["fields"])
                    or route["control"]["reset_semantics"] != first["control"]["reset_semantics"]
                    or any(route["control"][r]["source_port"] != first["control"][r]["source_port"]
                           for r in ("clock", "reset"))):
                raise ValueError("shared native group mismatch/reset")
            width = next(f["width"] for f in route["fields"] if f["address"])
            if route["base"] < end or route["base"] + route["size"] > 1 << width:
                raise ValueError("shared native address region invalid")
            end = route["base"] + route["size"]
    return groups


def collapse_groups(routes):
    result, modules = [], []
    for endpoint, group in sorted(validate_groups(routes).items()):
        if len(group) == 1:
            result.extend(group)
            continue
        first = group[0]
        name = f"myfuzz_shared_{canonical_id('shared-native-endpoint', endpoint):016x}"
        width = next(f["width"] for f in first["fields"] if f["address"])
        virtual = {**first, "component_id": name, "module_name": name, "parameters": {},
                   "base": 0, "size": 1 << width,
                   "fields": tuple({**f, "target_port": f["field_id"]} for f in first["fields"]),
                   "control": {**first["control"], **{r: {**first["control"][r], "target_port": r}
                                                    for r in ("clock", "reset")}}}
        result.append(virtual)
        modules.append(_render_fanout(name, group, width))
    return tuple(result), tuple(modules)


def _render_fanout(name, group, width):
    first = group[0]
    fields = first["fields"]
    apb = first["contract"]["mode"] == "native_apb"
    address = "paddr" if apb else "adr"
    controls = {"psel", "penable"} if apb else {"cyc", "stb"}
    ports = ["input logic clock", "input logic reset"]
    ports += [f"{f['direction']} wire [{f['width']-1}:0] {f['field_id']}" for f in fields]
    lines = [f"module {name}(" + ",\n".join(ports) + ");"]
    for index, route in enumerate(group):
        lines.append(f"wire hit_{index} = {{1'b0, {address}}} >= {width+1}'h{route['base']:x} && "
                     f"{{1'b0, {address}}} < {width+1}'h{route['base']+route['size']:x};")
        connections = [f".{route['control'][r]['target_port']}({r})" for r in ("clock", "reset")]
        for f in route["fields"]:
            field = f["field_id"]
            signal = f"t{index}_{field}"
            lines.append(f"wire [{f['width']-1}:0] {signal};")
            connections.append(f".{f['target_port']}({signal})")
            if f["direction"] == "input":
                value = f"{address} - {width}'h{route['base']:x}" if f["address"] else field
                if field in controls:
                    value = f"{field} && hit_{index}"
                lines.append(f"assign {signal} = {value};")
        params = ", ".join(f".{k}({v})" for k, v in sorted(route["parameters"].items()))
        lines.append(f"{route['module_name']}" + (f" #({params})" if params else "")
                     + f" target_{index}(" + ", ".join(connections) + ");")
    for f in fields:
        if f["direction"] == "output":
            field = f["field_id"]
            default = "1'b1" if field in ({"pready", "pslverr"} if apb else {"err"}) else "'0"
            mux = "".join(f"hit_{i} ? t{i}_{field} : " for i in range(len(group))) + default
            lines.append(f"assign {field} = {mux};")
    return "\n".join([*lines, "endmodule\n"])
