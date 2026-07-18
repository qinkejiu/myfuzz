from myfuzz.builder import (
    DiscoveredModule,
    DiscoveredPort,
    PortDirection,
    SystemSpec,
)


SIGNALS = {
    "request": (1, "req"), "write_enable": (1, "we"), "address": (32, "addr"),
    "write_data": (32, "wdata"), "read_data": (32, "rdata"), "grant": (1, "gnt"),
}


def rtl_module(name, role, extra=()):
    directions = {
        "initiator": {"request": "output", "write_enable": "output", "address": "output", "write_data": "output", "read_data": "input", "grant": "input"},
        "target": {"request": "input", "write_enable": "input", "address": "input", "write_data": "input", "read_data": "output", "grant": "output"},
    }[role]
    ports = [
        DiscoveredPort(f"{prefix}_{'o' if directions[semantic] == 'output' else 'i'}", PortDirection(directions[semantic]), width, None)
        for semantic, (width, prefix) in SIGNALS.items()
    ]
    ports.extend(extra)
    return DiscoveredModule(name, f"/{name}.sv", "rtl", {}, tuple(ports), (), True, "test")


def module_spec(name, kind, role, address=None, unknown_ports=None):
    directions = {
        "initiator": {"request": "output", "write_enable": "output", "address": "output", "write_data": "output", "read_data": "input", "grant": "input"},
        "target": {"request": "input", "write_enable": "input", "address": "input", "write_data": "input", "read_data": "output", "grant": "output"},
    }[role]
    ports = {
        semantic: f"{prefix}_{'o' if directions[semantic] == 'output' else 'i'}"
        for semantic, (_, prefix) in SIGNALS.items()
    }
    result = {
        "name": name, "kind": kind, "source_set": "rtl", "ports": {},
        "interfaces": [{"name": "bus", "protocol": "simple_bus", "role": role, "ports": ports}],
    }
    if address:
        result["address"] = address
    if unknown_ports:
        result["unknown_ports"] = unknown_ports
    return result


def system_spec(modules):
    return SystemSpec.from_dict({
        "schema_version": 1, "name": "planned",
        "sources": [{"name": "rtl", "rtl_files": [f"{module['name']}.sv" for module in modules]}],
        "modules": modules,
    })
