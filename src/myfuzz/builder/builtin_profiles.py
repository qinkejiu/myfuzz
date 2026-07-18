"""Built-in reusable protocol knowledge."""

from __future__ import annotations

from .profiles import ProfileRegistry, ProtocolProfile


def builtin_profile_registry() -> ProfileRegistry:
    profiles = _SIMPLE_BUS_PROFILES + _AXI_LITE_PROFILES + _APB_PROFILES
    return ProfileRegistry(ProtocolProfile.from_dict(item) for item in profiles)


_COMMON_SIGNALS = {
    "request": ["req", "req_i", "req_o", "data_req_o"],
    "write_enable": ["we", "we_i", "we_o", "data_we_o"],
    "address": ["addr", "addr_i", "addr_o", "data_addr_o"],
    "write_data": ["wdata", "wdata_i", "wdata_o", "data_wdata_o"],
    "read_data": ["rdata", "rdata_i", "rdata_o", "data_rdata_i"],
    "grant": ["gnt", "gnt_i", "gnt_o", "data_gnt_i"],
}


def _profile(role: str, directions: dict[str, str]) -> dict:
    protocol = "simple_bus"
    ports = [
        {
            "semantic": f"{protocol}.{semantic}",
            "direction": directions[semantic],
            "aliases": aliases,
            "required": semantic != "grant",
        }
        for semantic, aliases in _COMMON_SIGNALS.items()
    ]
    return {
        "name": f"{protocol}_{role}",
        "protocol": protocol,
        "interface_role": role,
        "priority": 100,
        "ports": ports,
        "channels": [
            {"name": "request", "signals": [
                f"{protocol}.request", f"{protocol}.write_enable",
                f"{protocol}.address", f"{protocol}.write_data",
            ]},
            {"name": "response", "signals": [f"{protocol}.read_data", f"{protocol}.grant"]},
        ],
        "address_rule": {
            "requires_window": role == "target",
            "default_size": 4096 if role == "target" else None,
            "alignment": 4096 if role == "target" else None,
        },
        "constraints": ["request remains asserted until grant when grant is present"],
    }


_SIMPLE_BUS_PROFILES = (
    _profile("initiator", {
        "request": "output", "write_enable": "output", "address": "output",
        "write_data": "output", "read_data": "input", "grant": "input",
    }),
    _profile("target", {
        "request": "input", "write_enable": "input", "address": "input",
        "write_data": "input", "read_data": "output", "grant": "output",
    }),
)


_AXI_LITE_SIGNALS = {
    "awvalid": (("s_axi_awvalid", "m_axi_awvalid", "awvalid"), "initiator"),
    "awready": (("s_axi_awready", "m_axi_awready", "awready"), "target"),
    "awaddr": (("s_axi_awaddr", "m_axi_awaddr", "awaddr"), "initiator"),
    "wvalid": (("s_axi_wvalid", "m_axi_wvalid", "wvalid"), "initiator"),
    "wready": (("s_axi_wready", "m_axi_wready", "wready"), "target"),
    "wdata": (("s_axi_wdata", "m_axi_wdata", "wdata"), "initiator"),
    "wstrb": (("s_axi_wstrb", "m_axi_wstrb", "wstrb"), "initiator"),
    "bvalid": (("s_axi_bvalid", "m_axi_bvalid", "bvalid"), "target"),
    "bready": (("s_axi_bready", "m_axi_bready", "bready"), "initiator"),
    "bresp": (("s_axi_bresp", "m_axi_bresp", "bresp"), "target"),
    "arvalid": (("s_axi_arvalid", "m_axi_arvalid", "arvalid"), "initiator"),
    "arready": (("s_axi_arready", "m_axi_arready", "arready"), "target"),
    "araddr": (("s_axi_araddr", "m_axi_araddr", "araddr"), "initiator"),
    "rvalid": (("s_axi_rvalid", "m_axi_rvalid", "rvalid"), "target"),
    "rready": (("s_axi_rready", "m_axi_rready", "rready"), "initiator"),
    "rdata": (("s_axi_rdata", "m_axi_rdata", "rdata"), "target"),
    "rresp": (("s_axi_rresp", "m_axi_rresp", "rresp"), "target"),
}


def _axi_lite_profile(role: str) -> dict:
    ports = []
    for semantic, (aliases, driven_by) in _AXI_LITE_SIGNALS.items():
        direction = "output" if driven_by == role else "input"
        ports.append({"semantic": f"axi_lite.{semantic}", "direction": direction, "aliases": list(aliases)})
    return {
        "name": f"axi_lite_{role}_v1", "protocol": "axi_lite", "interface_role": role,
        "version": "1.0", "priority": 100, "ports": ports,
        "channels": [
            {"name": "write_address", "signals": ["axi_lite.awvalid", "axi_lite.awready", "axi_lite.awaddr"]},
            {"name": "write_data", "signals": ["axi_lite.wvalid", "axi_lite.wready", "axi_lite.wdata", "axi_lite.wstrb"]},
            {"name": "write_response", "signals": ["axi_lite.bvalid", "axi_lite.bready", "axi_lite.bresp"]},
            {"name": "read_address", "signals": ["axi_lite.arvalid", "axi_lite.arready", "axi_lite.araddr"]},
            {"name": "read_data", "signals": ["axi_lite.rvalid", "axi_lite.rready", "axi_lite.rdata", "axi_lite.rresp"]},
        ],
        "address_rule": {"requires_window": role == "target", "default_size": 4096 if role == "target" else None, "alignment": 4096 if role == "target" else None},
        "capabilities": ["independent_aw_w", "backpressure", "error_response"],
        "width_rules": ["data_width == 32", "wstrb_width == data_width / 8", "bresp_width == 2", "rresp_width == 2"],
        "handshake": ["each channel transfers on valid && ready", "responses persist until accepted"],
        "responses": ["okay=0", "slverr=2", "decerr=3"],
    }


_AXI_LITE_PROFILES = (_axi_lite_profile("initiator"), _axi_lite_profile("target"))


def _apb_profile(protocol: str) -> dict:
    signals = {
        "paddr": ("input", True), "psel": ("input", True), "penable": ("input", True),
        "pwrite": ("input", True), "pwdata": ("input", True), "prdata": ("output", True),
        "pready": ("output", True), "pslverr": ("output", False),
        "pstrb": ("input", protocol == "apb4"), "pprot": ("input", False),
    }
    return {
        "name": f"{protocol}_target_v1", "protocol": protocol, "interface_role": "target",
        "version": "1.0", "priority": 100,
        "ports": [{"semantic": f"{protocol}.{name}", "direction": direction,
                   "aliases": [name, f"s_{protocol}_{name}"], "required": required}
                  for name, (direction, required) in signals.items()],
        "channels": [{"name": "transfer", "signals": [f"{protocol}.{name}" for name in ("paddr", "psel", "penable", "pwrite", "pwdata", "prdata", "pready")]}],
        "address_rule": {"requires_window": True, "default_size": 4096, "alignment": 4096},
        "capabilities": ["setup_access_phases", "wait_states", "error_response"],
        "width_rules": ["data_width == 32", "pstrb_width == data_width / 8"],
        "handshake": ["setup: psel && !penable", "access: psel && penable", "complete: access && pready"],
        "responses": ["pslverr is sampled only on completion"],
    }


_APB_PROFILES = (_apb_profile("apb3"), _apb_profile("apb4"))
