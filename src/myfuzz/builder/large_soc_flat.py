"""Disconnected scheme-A shell over the same CPU and IP component boundaries."""

from __future__ import annotations

from .contracts import SystemIR
from .flat_shell import EmittedFlatShell, emit_flat_shell
from .formal_ip_set import formal_axi_lite_ip_set
from .input_model import InputValidationError


def _port(name: str, direction: str, width: int = 1) -> dict[str, object]:
    return {"name": name, "direction": direction, "width": width}


def _axi_slave(address_width: int, reset_name: str) -> tuple[dict[str, object], ...]:
    return (
        _port("clk", "input"), _port(reset_name, "input"),
        _port("s_awvalid", "input"), _port("s_awready", "output"),
        _port("s_awaddr", "input", address_width), _port("s_wvalid", "input"),
        _port("s_wready", "output"), _port("s_wdata", "input", 32),
        _port("s_wstrb", "input", 4), _port("s_bvalid", "output"),
        _port("s_bready", "input"), _port("s_bresp", "output", 2),
        _port("s_arvalid", "input"), _port("s_arready", "output"),
        _port("s_araddr", "input", address_width), _port("s_rvalid", "output"),
        _port("s_rready", "input"), _port("s_rdata", "output", 32),
        _port("s_rresp", "output", 2),
    )


def _cpu_ports(cpu_id: str) -> tuple[dict[str, object], ...]:
    master = (
        _port("m_awvalid", "output"), _port("m_awready", "input"),
        _port("m_awaddr", "output", 32), _port("m_wvalid", "output"),
        _port("m_wready", "input"), _port("m_wdata", "output", 32),
        _port("m_wstrb", "output", 4), _port("m_bvalid", "input"),
        _port("m_bready", "output"), _port("m_bresp", "input", 2),
        _port("m_arvalid", "output"), _port("m_arready", "input"),
        _port("m_araddr", "output", 32), _port("m_rvalid", "input"),
        _port("m_rready", "output"), _port("m_rdata", "input", 32),
        _port("m_rresp", "input", 2),
    )
    if cpu_id == "picorv32":
        return (_port("clk", "input"), _port("resetn", "input"),
                _port("fuzz_irq", "input", 32), _port("cpu_trap", "output"), *master)
    if cpu_id != "ultra_riscv":
        raise InputValidationError(f"unsupported large flat CPU {cpu_id!r}")
    loader = (
        _port("loader_awvalid", "input"), _port("loader_awready", "output"),
        _port("loader_awaddr", "input", 32), _port("loader_awid", "input", 4),
        _port("loader_awlen", "input", 8), _port("loader_awburst", "input", 2),
        _port("loader_wvalid", "input"), _port("loader_wready", "output"),
        _port("loader_wdata", "input", 32), _port("loader_wstrb", "input", 4),
        _port("loader_wlast", "input"), _port("loader_bvalid", "output"),
        _port("loader_bready", "input"), _port("loader_bresp", "output", 2),
        _port("loader_bid", "output", 4), _port("loader_arvalid", "input"),
        _port("loader_arready", "output"), _port("loader_araddr", "input", 32),
        _port("loader_arid", "input", 4), _port("loader_arlen", "input", 8),
        _port("loader_arburst", "input", 2), _port("loader_rvalid", "output"),
        _port("loader_rready", "input"), _port("loader_rdata", "output", 32),
        _port("loader_rresp", "output", 2), _port("loader_rid", "output", 4),
        _port("loader_rlast", "output"),
    )
    return (_port("clk", "input"), _port("reset", "input"),
            _port("cpu_reset", "input"), _port("fuzz_irq", "input", 32), *master, *loader)


def _ip_boundary(type_id: str) -> tuple[str, tuple[dict[str, object], ...]]:
    if type_id == "verilog_axi.axil_ram":
        return "verilog_axi_ram_wrapper", _axi_slave(16, "reset")
    if type_id == "verilog_axi.axil_dp_ram":
        return "verilog_axi_dp_ram_wrapper", _axi_slave(12, "reset")
    if type_id == "pulp.axi_lite_regs":
        return "pulp_axi_lite_regs_wrapper", _axi_slave(32, "resetn")
    if type_id == "pulp.axi_lite_lfsr":
        return "pulp_axi_lite_lfsr_level1_adapter", _axi_slave(32, "resetn")
    if type_id == "zipcpu.axilgpio":
        return "zipcpu_axilgpio_level1_adapter", (
            *_axi_slave(5, "resetn"), _port("gpio_input", "input", 32),
            _port("gpio_output", "output", 32), _port("gpio_interrupt", "output"),
        )
    if type_id == "zipcpu.axil2apb":
        return "zipcpu_axil2apb_level1_adapter", (
            *_axi_slave(12, "resetn"), _port("apb_ready", "input"),
            _port("apb_read_data", "input", 32), _port("apb_error", "input"),
            _port("apb_select", "output"), _port("apb_enable", "output"),
            _port("apb_write", "output"), _port("apb_address", "output", 12),
            _port("apb_write_data", "output", 32), _port("apb_write_strobe", "output", 4),
        )
    raise InputValidationError(f"unsupported flat IP boundary {type_id!r}")


def emit_large_flat_soc(cpu_id: str, *, module_name: str | None = None) -> EmittedFlatShell:
    cpu_module = {
        "picorv32": "picorv32_level1_adapter",
        "ultra_riscv": "ultra_riscv_level1_adapter",
    }.get(cpu_id)
    if cpu_module is None:
        raise InputValidationError(f"unsupported large flat CPU {cpu_id!r}")
    modules: list[dict[str, object]] = [{
        "name": "cpu", "module_type": cpu_module, "instance": "cpu0",
        "ports": _cpu_ports(cpu_id), "parameters": {},
    }]
    for ip in formal_axi_lite_ip_set():
        boundary, ports = _ip_boundary(ip.type_id)
        modules.append({
            "name": ip.instance_id, "module_type": boundary, "instance": ip.instance_id,
            "ports": ports, "parameters": {},
        })
    ir = SystemIR(f"{cpu_id}_flat", tuple(modules), (), ())
    return emit_flat_shell(ir, module_name or f"myfuzz_{cpu_id}_flat_random")
