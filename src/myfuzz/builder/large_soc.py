"""Emit the locked large generated SoC used by experiment variants B and C."""

from __future__ import annotations

from dataclasses import dataclass

from .axi_lite import AxiLiteFabricConfig, emit_axi_lite_fabric
from .cpu_profiles import builtin_cpu_execution_profile
from .formal_ip_set import QualifiedAxiLiteIP, formal_axi_lite_ip_set
from .input_model import InputValidationError


@dataclass(frozen=True)
class EmittedLargeSoc:
    cpu_id: str
    module_name: str
    rtl: str
    fabric_rtl: str
    slave_ids: tuple[str, ...]
    address_windows: tuple[tuple[str, int, int], ...]


_ADDR_WIDTHS = {
    "verilog_axi.axil_ram": 16,
    "verilog_axi.axil_dp_ram": 12,
    "pulp.axi_lite_regs": 32,
    "pulp.axi_lite_lfsr": 32,
    "zipcpu.axilgpio": 5,
    "zipcpu.axil2apb": 12,
}


def _ip_instance(ip: QualifiedAxiLiteIP, index: int) -> str:
    reset_binding = (".reset(!execution_resetn)" if ip.type_id.startswith("verilog_axi.")
                     else ".resetn(execution_resetn)")
    width = _ADDR_WIDTHS[ip.type_id]
    address = f"s_awaddr[{index}]" if width == 32 else f"s_awaddr[{index}][{width - 1}:0]"
    read_address = f"s_araddr[{index}]" if width == 32 else f"s_araddr[{index}][{width - 1}:0]"
    module = {
        "pulp.axi_lite_lfsr": "pulp_axi_lite_lfsr_level1_adapter",
        "zipcpu.axilgpio": "zipcpu_axilgpio_level1_adapter",
        "zipcpu.axil2apb": "zipcpu_axil2apb_level1_adapter",
    }.get(ip.type_id, ip.module)
    external = {
        "zipcpu.axilgpio": (
            ".gpio_input(gpio_input), .gpio_output(gpio_output), "
            ".gpio_interrupt(gpio_interrupt),\n    "
        ),
        "zipcpu.axil2apb": (
            ".apb_ready(apb_ready), .apb_read_data(apb_read_data), .apb_error(apb_error),\n"
            "    .apb_select(apb_select), .apb_enable(apb_enable), .apb_write(apb_write),\n"
            "    .apb_address(apb_address), .apb_write_data(apb_write_data), "
            ".apb_write_strobe(apb_write_strobe),\n    "
        ),
    }.get(ip.type_id, "")
    return f"""  {module} i_{ip.instance_id}(
    .clk(clk), {reset_binding}, {external}
    .s_awvalid(s_awvalid[{index}]), .s_awready(s_awready[{index}]), .s_awaddr({address}),
    .s_wvalid(s_wvalid[{index}]), .s_wready(s_wready[{index}]), .s_wdata(s_wdata[{index}]),
    .s_wstrb(s_wstrb[{index}]), .s_bvalid(s_bvalid[{index}]), .s_bready(s_bready[{index}]),
    .s_bresp(s_bresp[{index}]), .s_arvalid(s_arvalid[{index}]),
    .s_arready(s_arready[{index}]), .s_araddr({read_address}),
    .s_rvalid(s_rvalid[{index}]), .s_rready(s_rready[{index}]),
    .s_rdata(s_rdata[{index}]), .s_rresp(s_rresp[{index}]));"""


def emit_large_generated_soc(cpu_id: str, *, rom_words: int,
                             module_name: str | None = None) -> EmittedLargeSoc:
    if rom_words <= 0:
        raise InputValidationError("rom_words must be positive")
    profile = builtin_cpu_execution_profile(cpu_id)
    if cpu_id not in {"picorv32", "ultra_riscv"}:
        raise InputValidationError(f"unsupported large-SoC CPU {cpu_id!r}")
    module = module_name or f"myfuzz_{cpu_id}_large_soc"
    if not module.isidentifier():
        raise InputValidationError("large SoC module name must be a Verilog identifier")
    ips = formal_axi_lite_ip_set()
    infrastructure = []
    if cpu_id == "picorv32":
        infrastructure.append(("rom", profile.rom_window["base"], profile.rom_window["size"]))
    infrastructure.extend((
        ("mailbox", profile.mailbox_window["base"], profile.mailbox_window["size"]),
        ("watchdog", profile.watchdog_window["base"], profile.watchdog_window["size"]),
    ))
    windows = tuple(infrastructure) + tuple((ip.instance_id, ip.base, ip.size) for ip in ips)
    fabric_name = f"{module}_fabric"
    config = AxiLiteFabricConfig(32, 32, len(windows),
                                 tuple(base for _name, base, _size in windows),
                                 tuple(size for _name, _base, size in windows))
    fabric = emit_axi_lite_fabric(config, fabric_name)
    index = {name: slot for slot, (name, _base, _size) in enumerate(windows)}
    count = len(windows)
    cases = "\n".join(
        f"      32'd{slot}: expected_address = 32'h{ip.base:08x} + "
        f"((active_offset << 2) & 32'h{ip.size - 4:08x});"
        for slot, ip in enumerate(ips)
    )
    cpu = _pico_cpu() if cpu_id == "picorv32" else _ultra_cpu()
    rom = ""
    if cpu_id == "picorv32":
        slot = index["rom"]
        rom = f"""  myfuzz_level1_external_rom #(.WORDS(ROM_WORDS),.HEX_FILE(ROM_HEX_FILE)) i_rom(
    .clk(clk),.resetn(execution_resetn),.s_awvalid(s_awvalid[{slot}]),.s_awready(s_awready[{slot}]),.s_awaddr(s_awaddr[{slot}]),
    .s_wvalid(s_wvalid[{slot}]),.s_wready(s_wready[{slot}]),.s_wdata(s_wdata[{slot}]),.s_wstrb(s_wstrb[{slot}]),
    .s_bvalid(s_bvalid[{slot}]),.s_bready(s_bready[{slot}]),.s_bresp(s_bresp[{slot}]),
    .s_arvalid(s_arvalid[{slot}]),.s_arready(s_arready[{slot}]),.s_araddr(s_araddr[{slot}]),
    .s_rvalid(s_rvalid[{slot}]),.s_rready(s_rready[{slot}]),.s_rdata(s_rdata[{slot}]),.s_rresp(s_rresp[{slot}]));"""
    mailbox_slot, watchdog_slot = index["mailbox"], index["watchdog"]
    ip_rtl = "\n".join(_ip_instance(ip, index[ip.instance_id]) for ip in ips)
    top = f"""module {module} #(
  parameter integer ROM_WORDS={rom_words}, parameter ROM_HEX_FILE="level1_rom.hex",
  parameter integer MAX_TRANSACTION_CYCLES=1024
) (
  input wire clk, input wire resetn, input wire [31:0] fuzz_irq,
  input wire [31:0] gpio_input,
  output wire [31:0] gpio_output, output wire gpio_interrupt,
  input wire apb_ready, input wire [31:0] apb_read_data, input wire apb_error,
  output wire apb_select, output wire apb_enable, output wire apb_write,
  output wire [11:0] apb_address, output wire [31:0] apb_write_data,
  output wire [3:0] apb_write_strobe,
  input wire record_valid, output wire record_ready, input wire [31:0] record_sequence,
  input wire [31:0] record_ip_select, input wire record_read_write,
  input wire [31:0] record_offset, input wire [31:0] record_data,
  input wire terminal_capture_ack,
  output wire terminal_valid, output wire terminal_timed_out,
  output wire [31:0] terminal_sequence, output wire [7:0] terminal_route,
  output wire terminal_read_write, output wire [31:0] terminal_address,
  output wire [1:0] terminal_response, output wire [31:0] terminal_cycles,
  output wire cpu_fault, output wire loader_busy, output wire loader_done, output wire loader_error,
  output wire recovering, output wire [31:0] restart_count, output wire recovery_error
);
  localparam integer SLAVES={count};
  wire m_awvalid,m_awready,m_wvalid,m_wready,m_bvalid,m_bready;
  wire m_arvalid,m_arready,m_rvalid,m_rready; wire [31:0] m_awaddr,m_wdata,m_araddr,m_rdata;
  wire [3:0] m_wstrb; wire [1:0] m_bresp,m_rresp;
  wire [SLAVES-1:0] s_awvalid,s_awready,s_wvalid,s_wready,s_bvalid,s_bready;
  wire [SLAVES-1:0] s_arvalid,s_arready,s_rvalid,s_rready;
  wire [SLAVES-1:0][31:0] s_awaddr,s_wdata,s_araddr,s_rdata;
  wire [SLAVES-1:0][3:0] s_wstrb; wire [SLAVES-1:0][1:0] s_bresp,s_rresp;
  wire active,active_rw,software_progress,mailbox_error,watchdog_timeout;
  wire execution_resetn,cpu_run,loader_start,accept_enable,bus_quiet,owner_error;
  wire raw_terminal_valid,raw_terminal_timed_out,raw_terminal_rw;
  wire [31:0] raw_terminal_sequence,raw_terminal_address,raw_terminal_cycles;
  wire [7:0] raw_terminal_route; wire [1:0] raw_terminal_response;
  wire [31:0] active_sequence,active_ip_select,active_offset,active_data,software_progress_value,watchdog_cycles;
  reg [31:0] expected_address;
  always @* begin
    case(active_ip_select)
{cases}
      default: expected_address = 32'hf0000000;
    endcase
  end

{cpu}
  assign bus_quiet=!(m_awvalid||m_wvalid||m_bvalid||m_arvalid||m_rvalid||
                     (|s_bvalid)||(|s_rvalid));
  myfuzz_level1_recovery_controller #(.USE_LOADER({1 if cpu_id == "ultra_riscv" else 0})) i_recovery(
    .clk(clk),.resetn(resetn),.terminal_valid(terminal_valid),.terminal_timed_out(terminal_timed_out),
    .terminal_capture_ack(terminal_capture_ack),.bus_quiet(bus_quiet),.loader_done(loader_done),
    .loader_error(loader_error),.execution_resetn(execution_resetn),.cpu_run(cpu_run),
    .loader_start(loader_start),.accept_enable(accept_enable),.recovering(recovering),
    .restart_count(restart_count),.recovery_error(recovery_error));
  myfuzz_level1_record_owner i_owner(.clk(clk),.resetn(resetn),.accept_enable(accept_enable),
    .record_valid(record_valid),.record_ready(record_ready),.record_sequence(record_sequence),
    .record_ip_select(record_ip_select),.record_read_write(record_read_write),
    .record_offset(record_offset),.record_data(record_data),.active(active),
    .active_sequence(active_sequence),.active_ip_select(active_ip_select),
    .active_read_write(active_rw),.active_offset(active_offset),.active_data(active_data),
    .raw_terminal_valid(raw_terminal_valid),.raw_terminal_timed_out(raw_terminal_timed_out),
    .raw_terminal_sequence(raw_terminal_sequence),.raw_terminal_route(raw_terminal_route),
    .raw_terminal_read_write(raw_terminal_rw),.raw_terminal_address(raw_terminal_address),
    .raw_terminal_response(raw_terminal_response),.raw_terminal_cycles(raw_terminal_cycles),
    .terminal_valid(terminal_valid),.terminal_capture_ack(terminal_capture_ack),
    .terminal_timed_out(terminal_timed_out),.terminal_sequence(terminal_sequence),
    .terminal_route(terminal_route),.terminal_read_write(terminal_read_write),
    .terminal_address(terminal_address),.terminal_response(terminal_response),
    .terminal_cycles(terminal_cycles),.protocol_error(owner_error));
  {fabric_name} i_fabric(.aclk(clk),.aresetn(execution_resetn),
    .m_awaddr(m_awaddr),.m_awvalid(m_awvalid),.m_awready(m_awready),
    .m_wdata(m_wdata),.m_wstrb(m_wstrb),.m_wvalid(m_wvalid),.m_wready(m_wready),
    .m_bresp(m_bresp),.m_bvalid(m_bvalid),.m_bready(m_bready),
    .m_araddr(m_araddr),.m_arvalid(m_arvalid),.m_arready(m_arready),
    .m_rdata(m_rdata),.m_rresp(m_rresp),.m_rvalid(m_rvalid),.m_rready(m_rready),
    .s_awvalid(s_awvalid),.s_awaddr(s_awaddr),.s_awready(s_awready),
    .s_wvalid(s_wvalid),.s_wdata(s_wdata),.s_wstrb(s_wstrb),.s_wready(s_wready),
    .s_bvalid(s_bvalid),.s_bresp(s_bresp),.s_bready(s_bready),
    .s_arvalid(s_arvalid),.s_araddr(s_araddr),.s_arready(s_arready),
    .s_rvalid(s_rvalid),.s_rdata(s_rdata),.s_rresp(s_rresp),.s_rready(s_rready));
{rom}
  myfuzz_level1_mailbox i_mailbox(.clk(clk),.resetn(execution_resetn),.active(active),
    .active_sequence(active_sequence),.active_ip_select(active_ip_select),
    .active_read_write(active_rw),.active_offset(active_offset),.active_data(active_data),
    .software_progress(software_progress),.software_progress_value(software_progress_value),
    .protocol_error(mailbox_error),.s_awvalid(s_awvalid[{mailbox_slot}]),.s_awready(s_awready[{mailbox_slot}]),
    .s_awaddr(s_awaddr[{mailbox_slot}]),.s_wvalid(s_wvalid[{mailbox_slot}]),.s_wready(s_wready[{mailbox_slot}]),
    .s_wdata(s_wdata[{mailbox_slot}]),.s_wstrb(s_wstrb[{mailbox_slot}]),.s_bvalid(s_bvalid[{mailbox_slot}]),
    .s_bready(s_bready[{mailbox_slot}]),.s_bresp(s_bresp[{mailbox_slot}]),.s_arvalid(s_arvalid[{mailbox_slot}]),
    .s_arready(s_arready[{mailbox_slot}]),.s_araddr(s_araddr[{mailbox_slot}]),.s_rvalid(s_rvalid[{mailbox_slot}]),
    .s_rready(s_rready[{mailbox_slot}]),.s_rdata(s_rdata[{mailbox_slot}]),.s_rresp(s_rresp[{mailbox_slot}]));
  myfuzz_level1_watchdog #(.MAX_CYCLES(MAX_TRANSACTION_CYCLES)) i_watchdog(.clk(clk),.resetn(execution_resetn),
    .record_active(active),.timeout(watchdog_timeout),.elapsed_cycles(watchdog_cycles),
    .s_awvalid(s_awvalid[{watchdog_slot}]),.s_awready(s_awready[{watchdog_slot}]),.s_awaddr(s_awaddr[{watchdog_slot}]),
    .s_wvalid(s_wvalid[{watchdog_slot}]),.s_wready(s_wready[{watchdog_slot}]),.s_wdata(s_wdata[{watchdog_slot}]),
    .s_wstrb(s_wstrb[{watchdog_slot}]),.s_bvalid(s_bvalid[{watchdog_slot}]),.s_bready(s_bready[{watchdog_slot}]),
    .s_bresp(s_bresp[{watchdog_slot}]),.s_arvalid(s_arvalid[{watchdog_slot}]),.s_arready(s_arready[{watchdog_slot}]),
    .s_araddr(s_araddr[{watchdog_slot}]),.s_rvalid(s_rvalid[{watchdog_slot}]),.s_rready(s_rready[{watchdog_slot}]),
    .s_rdata(s_rdata[{watchdog_slot}]),.s_rresp(s_rresp[{watchdog_slot}]));
  myfuzz_level1_transaction_monitor i_monitor(.clk(clk),.resetn(execution_resetn),
    .record_active(active),.record_sequence(active_sequence),.record_read_write(active_rw),
    .expected_route(active_ip_select[7:0]),.expected_address(expected_address),.watchdog_timeout(watchdog_timeout),
    .m_awvalid(m_awvalid),.m_awready(m_awready),.m_awaddr(m_awaddr),.m_wvalid(m_wvalid),.m_wready(m_wready),
    .m_bvalid(m_bvalid),.m_bready(m_bready),.m_bresp(m_bresp),.m_arvalid(m_arvalid),.m_arready(m_arready),
    .m_araddr(m_araddr),.m_rvalid(m_rvalid),.m_rready(m_rready),.m_rresp(m_rresp),
    .terminal_valid(raw_terminal_valid),.terminal_timed_out(raw_terminal_timed_out),
    .terminal_sequence(raw_terminal_sequence),.terminal_route(raw_terminal_route),
    .terminal_read_write(raw_terminal_rw),.terminal_address(raw_terminal_address),
    .terminal_response(raw_terminal_response),.terminal_cycles(raw_terminal_cycles));
{ip_rtl}
endmodule
"""
    return EmittedLargeSoc(cpu_id, module, top, fabric, tuple(name for name, _base, _size in windows), windows)


def _pico_cpu() -> str:
    return """  assign loader_busy=1'b0; assign loader_done=1'b1; assign loader_error=1'b0;
  picorv32_level1_adapter i_cpu(.clk(clk),.resetn(execution_resetn&&cpu_run),.fuzz_irq(fuzz_irq),.cpu_trap(cpu_fault),
    .m_awvalid(m_awvalid),.m_awready(m_awready),.m_awaddr(m_awaddr),.m_wvalid(m_wvalid),
    .m_wready(m_wready),.m_wdata(m_wdata),.m_wstrb(m_wstrb),.m_bvalid(m_bvalid),
    .m_bready(m_bready),.m_bresp(m_bresp),.m_arvalid(m_arvalid),.m_arready(m_arready),
    .m_araddr(m_araddr),.m_rvalid(m_rvalid),.m_rready(m_rready),.m_rdata(m_rdata),.m_rresp(m_rresp));"""


def _ultra_cpu() -> str:
    return """  wire law,lwv,lbv,lbr,larv,lrr; wire lawr,lwr,larr,lrv;
  wire [31:0] laa,lwd,lra,lrd; wire [3:0] laid,lws,lbid,lraid,lrid;
  wire [7:0] lalen,lrarlen; wire [1:0] laburst,lbresp,lrarburst,lrresp; wire lwlast,lrlast;
  assign cpu_fault=loader_error;
  myfuzz_level1_tcm_loader #(.WORDS(ROM_WORDS),.HEX_FILE(ROM_HEX_FILE)) i_loader(
    .clk(clk),.reset(!execution_resetn),.start(loader_start),.busy(loader_busy),.done(loader_done),.error(loader_error),
    .awvalid(law),.awready(lawr),.awaddr(laa),.awid(laid),.awlen(lalen),.awburst(laburst),
    .wvalid(lwv),.wready(lwr),.wdata(lwd),.wstrb(lws),.wlast(lwlast),.bvalid(lbv),.bready(lbr),
    .bresp(lbresp),.bid(lbid),.arvalid(larv),.arready(larr),.araddr(lra),.arid(lraid),
    .arlen(lrarlen),.arburst(lrarburst),.rvalid(lrv),.rready(lrr),.rdata(lrd),.rresp(lrresp),.rid(lrid),.rlast(lrlast));
  ultra_riscv_level1_adapter i_cpu(.clk(clk),.reset(!execution_resetn),.cpu_reset(!cpu_run),.fuzz_irq(fuzz_irq),
    .m_awvalid(m_awvalid),.m_awready(m_awready),.m_awaddr(m_awaddr),.m_wvalid(m_wvalid),.m_wready(m_wready),
    .m_wdata(m_wdata),.m_wstrb(m_wstrb),.m_bvalid(m_bvalid),.m_bready(m_bready),.m_bresp(m_bresp),
    .m_arvalid(m_arvalid),.m_arready(m_arready),.m_araddr(m_araddr),.m_rvalid(m_rvalid),.m_rready(m_rready),
    .m_rdata(m_rdata),.m_rresp(m_rresp),.loader_awvalid(law),.loader_awready(lawr),.loader_awaddr(laa),
    .loader_awid(laid),.loader_awlen(lalen),.loader_awburst(laburst),.loader_wvalid(lwv),.loader_wready(lwr),
    .loader_wdata(lwd),.loader_wstrb(lws),.loader_wlast(lwlast),.loader_bvalid(lbv),.loader_bready(lbr),
    .loader_bresp(lbresp),.loader_bid(lbid),.loader_arvalid(larv),.loader_arready(larr),.loader_araddr(lra),
    .loader_arid(lraid),.loader_arlen(lrarlen),.loader_arburst(lrarburst),.loader_rvalid(lrv),.loader_rready(lrr),
    .loader_rdata(lrd),.loader_rresp(lrresp),.loader_rid(lrid),.loader_rlast(lrlast));"""
