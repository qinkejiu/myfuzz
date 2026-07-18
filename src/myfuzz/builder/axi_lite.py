"""Small, parameterized AXI-Lite fabric backend and executable reference model."""

from __future__ import annotations

from dataclasses import dataclass
from .input_model import InputValidationError


AXI_LITE_STATE_TABLE = (
    {"state": "write_collect", "accepts": "AW and W independently", "blocks": "second accepted AW or W"},
    {"state": "write_issue", "accepts": "selected slave AW/W independently", "blocks": "new master write"},
    {"state": "write_response", "accepts": "one selected B or internal DECERR", "blocks": "new master write"},
    {"state": "read_issue", "accepts": "one AR", "blocks": "second AR"},
    {"state": "read_response", "accepts": "one selected R or internal DECERR", "blocks": "new master read"},
    {"state": "reset", "accepts": "none", "blocks": "all requests and clears partial transactions"},
)


@dataclass(frozen=True)
class AxiLiteFabricConfig:
    address_width: int
    data_width: int
    slave_count: int
    bases: tuple[int, ...]
    sizes: tuple[int, ...]

    def __post_init__(self) -> None:
        values = (self.address_width, self.data_width, self.slave_count)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in values):
            raise InputValidationError("AXI-Lite widths and slave_count must be positive integers")
        if self.data_width % 8:
            raise InputValidationError("AXI-Lite DATA_WIDTH must be a multiple of 8")
        if self.slave_count != len(self.bases) or self.slave_count != len(self.sizes):
            raise InputValidationError("AXI-Lite window count must equal slave_count")
        limit = 1 << self.address_width
        windows = sorted(zip(self.bases, self.sizes), key=lambda item: item[0])
        for base, size in windows:
            if base < 0 or size <= 0 or base + size > limit:
                raise InputValidationError("AXI-Lite window exceeds the address space")
        for (_, upper), (base, _size) in zip(
            ((base, base + size) for base, size in windows),
            windows[1:],
        ):
            if upper > base:
                raise InputValidationError("AXI-Lite address windows overlap")


@dataclass(frozen=True)
class AxiLiteCycle:
    awvalid: bool = False
    awaddr: int = 0
    wvalid: bool = False
    wdata: int = 0
    wstrb: int = 0
    bready: bool = False
    arvalid: bool = False
    araddr: int = 0
    rready: bool = False


@dataclass(frozen=True)
class AxiLiteResponse:
    awready: bool
    wready: bool
    bvalid: bool
    bresp: int
    arready: bool
    rvalid: bool
    rdata: int
    rresp: int
    target: int | None


class AxiLiteReferenceModel:
    """One logical read or write transaction may be outstanding system-wide."""

    def __init__(self, config: AxiLiteFabricConfig):
        self.config = config
        self._aw: int | None = None
        self._w: tuple[int, int] | None = None
        self._b: tuple[int, int] | None = None
        self._r: tuple[int, int, int] | None = None

    def step(self, cycle: AxiLiteCycle) -> AxiLiteResponse:
        write_locked = self._aw is not None or self._w is not None or self._b is not None
        read_locked = self._r is not None
        idle = not write_locked and not read_locked
        choose_write = idle and (cycle.awvalid or cycle.wvalid)
        response = AxiLiteResponse(
            not read_locked and self._b is None and self._aw is None and (write_locked or choose_write),
            not read_locked and self._b is None and self._w is None and (write_locked or choose_write),
            self._b is not None,
            self._b[1] if self._b else 0,
            idle and not choose_write,
            self._r is not None,
            self._r[1] if self._r else 0,
            self._r[2] if self._r else 0,
            self._r[0] if self._r else (self._b[0] if self._b else None),
        )
        if response.bvalid and cycle.bready:
            self._b = None
        if response.rvalid and cycle.rready:
            self._r = None
        if response.awready and cycle.awvalid:
            self._aw = cycle.awaddr
        if response.wready and cycle.wvalid:
            self._w = cycle.wdata, cycle.wstrb
        if self._b is None and self._aw is not None and self._w is not None:
            target = self._target(self._aw)
            self._b = (target if target is not None else -1, 0 if target is not None else 3)
            self._aw = None
            self._w = None
        if self._r is None and cycle.arvalid and response.arready:
            target = self._target(cycle.araddr)
            self._r = (target if target is not None else -1, 0, 0 if target is not None else 3)
        return response

    def _target(self, address: int) -> int | None:
        for index, (base, size) in enumerate(zip(self.config.bases, self.config.sizes)):
            if base <= address < base + size:
                return index
        return None


def emit_axi_lite_fabric(config: AxiLiteFabricConfig, module_name: str = "myfuzz_axi_lite_fabric") -> str:
    """Emit a single-outstanding, full-width-decoded AXI-Lite master-to-slaves fabric."""
    c = config
    if not module_name.isidentifier():
        raise InputValidationError("fabric module_name must be a Verilog identifier")
    lines = [f"module {module_name} #(parameter integer ADDR_WIDTH={c.address_width}, DATA_WIDTH={c.data_width}, SLAVES={c.slave_count}) (",
        " input logic aclk, input logic aresetn,",
        " input logic [ADDR_WIDTH-1:0] m_awaddr, input logic m_awvalid, output logic m_awready,",
        " input logic [DATA_WIDTH-1:0] m_wdata, input logic [DATA_WIDTH/8-1:0] m_wstrb, input logic m_wvalid, output logic m_wready,",
        " output logic [1:0] m_bresp, output logic m_bvalid, input logic m_bready,",
        " input logic [ADDR_WIDTH-1:0] m_araddr, input logic m_arvalid, output logic m_arready,",
        " output logic [DATA_WIDTH-1:0] m_rdata, output logic [1:0] m_rresp, output logic m_rvalid, input logic m_rready,"]
    lines += [
        " output logic [SLAVES-1:0] s_awvalid, output logic [SLAVES-1:0][ADDR_WIDTH-1:0] s_awaddr, input logic [SLAVES-1:0] s_awready,",
        " output logic [SLAVES-1:0] s_wvalid, output logic [SLAVES-1:0][DATA_WIDTH-1:0] s_wdata, output logic [SLAVES-1:0][DATA_WIDTH/8-1:0] s_wstrb, input logic [SLAVES-1:0] s_wready,",
        " input logic [SLAVES-1:0] s_bvalid, input logic [SLAVES-1:0][1:0] s_bresp, output logic [SLAVES-1:0] s_bready,",
        " output logic [SLAVES-1:0] s_arvalid, output logic [SLAVES-1:0][ADDR_WIDTH-1:0] s_araddr, input logic [SLAVES-1:0] s_arready,",
        " input logic [SLAVES-1:0] s_rvalid, input logic [SLAVES-1:0][DATA_WIDTH-1:0] s_rdata, input logic [SLAVES-1:0][1:0] s_rresp, output logic [SLAVES-1:0] s_rready",
        ");",
        " logic aw_hold, w_hold, ar_hold, b_wait, r_wait, aw_sent, w_sent, ar_sent;",
        " logic [ADDR_WIDTH-1:0] aw_reg, ar_reg; logic [DATA_WIDTH-1:0] wdata_reg;",
        " logic [DATA_WIDTH/8-1:0] wstrb_reg; integer i; integer wtarget, rtarget; logic write_hit, read_hit;",
    ]
    for index, (base, size) in enumerate(zip(c.bases, c.sizes)):
        lines.append(f" localparam logic [ADDR_WIDTH-1:0] BASE_{index} = {c.address_width}'h{base:x};")
        lines.append(f" localparam logic [ADDR_WIDTH-1:0] END_{index} = {c.address_width}'h{base + size:x};")
    lines += [" always_comb begin write_hit = 1'b0; read_hit = 1'b0; wtarget = -1; rtarget = -1;"]
    for index in range(c.slave_count):
        lines.append(f"  if ((aw_reg >= BASE_{index}) && (aw_reg < END_{index})) begin write_hit=1'b1; wtarget={index}; end")
        lines.append(f"  if ((ar_reg >= BASE_{index}) && (ar_reg < END_{index})) begin read_hit=1'b1; rtarget={index}; end")
    lines += [
        "  m_awready = !aw_hold && !b_wait && !ar_hold && !r_wait;",
        "  m_wready = !w_hold && !b_wait && !ar_hold && !r_wait;",
        "  m_arready = !ar_hold && !r_wait && !aw_hold && !w_hold && !b_wait && !(m_awvalid || m_wvalid);",
        "  s_awvalid='0; s_awaddr='0; s_wvalid='0; s_wdata='0; s_wstrb='0; s_bready='0; s_arvalid='0; s_araddr='0; s_rready='0;",
        "  if (aw_hold && w_hold && write_hit && !b_wait) begin s_awvalid[wtarget]=!aw_sent; s_wvalid[wtarget]=!w_sent; s_wdata[wtarget]=wdata_reg; s_wstrb[wtarget]=wstrb_reg; case (wtarget)",
    ]
    for index in range(c.slave_count):
        lines.append(f"    {index}: s_awaddr[wtarget]=aw_reg-BASE_{index};")
    lines += [
        "    default: s_awaddr[wtarget]='0; endcase end",
        "  if (b_wait && write_hit) s_bready[wtarget]=m_bready;",
        "  if (ar_hold && read_hit && !r_wait) begin s_arvalid[rtarget]=!ar_sent; case (rtarget)",
    ]
    for index in range(c.slave_count):
        lines.append(f"    {index}: s_araddr[rtarget]=ar_reg-BASE_{index};")
    lines += [
        "    default: s_araddr[rtarget]='0; endcase end",
        "  if (r_wait && read_hit) s_rready[rtarget]=m_rready;",
        "  m_bvalid = 1'b0; m_bresp = 2'b11; if (b_wait) begin if (write_hit) begin m_bvalid=s_bvalid[wtarget]; m_bresp=s_bresp[wtarget]; end else m_bvalid=1'b1; end",
        "  m_rvalid = 1'b0; m_rdata = '0; m_rresp = 2'b11; if (r_wait) begin if (read_hit) begin m_rvalid=s_rvalid[rtarget]; m_rdata=s_rdata[rtarget]; m_rresp=s_rresp[rtarget]; end else m_rvalid=1'b1; end",
        " end",
        " always_ff @(posedge aclk or negedge aresetn) begin",
        "  if (!aresetn) begin aw_hold<=0; w_hold<=0; ar_hold<=0; b_wait<=0; r_wait<=0; aw_sent<=0; w_sent<=0; ar_sent<=0; end else begin",
        "   if (m_awready && m_awvalid) begin aw_hold<=1; aw_reg<=m_awaddr; end",
        "   if (m_wready && m_wvalid) begin w_hold<=1; wdata_reg<=m_wdata; wstrb_reg<=m_wstrb; end",
        "   if (m_arready && m_arvalid) begin ar_hold<=1; ar_reg<=m_araddr; end",
        "   if (aw_hold && w_hold && write_hit && !b_wait) begin if (!aw_sent && s_awready[wtarget]) aw_sent<=1; if (!w_sent && s_wready[wtarget]) w_sent<=1; if ((aw_sent || s_awready[wtarget]) && (w_sent || s_wready[wtarget])) begin b_wait<=1; aw_hold<=0; w_hold<=0; aw_sent<=0; w_sent<=0; end end",
        "   if (aw_hold && w_hold && !write_hit) begin b_wait<=1; aw_hold<=0; w_hold<=0; end",
        "   if (b_wait && m_bvalid && m_bready) b_wait<=0;",
        "   if (ar_hold && read_hit && !r_wait && s_arready[rtarget]) begin ar_sent<=1; r_wait<=1; ar_hold<=0; ar_sent<=0; end",
        "   if (ar_hold && !read_hit) begin r_wait<=1; ar_hold<=0; end",
        "   if (r_wait && m_rvalid && m_rready) r_wait<=0;",
        "  end",
        " end",
        "endmodule",
    ]
    return "\n".join(lines) + "\n"


def emit_axi_lite_assertions(module_name: str = "myfuzz_axi_lite_fabric_sva") -> str:
    """Emit bindable protocol assertions for response stability and reset cleanup."""
    if not module_name.isidentifier():
        raise InputValidationError("assertion module_name must be a Verilog identifier")
    return f"""module {module_name} #(
 parameter integer DATA_WIDTH=32
) (
 input logic aclk, input logic aresetn,
 input logic m_bvalid, input logic m_bready, input logic [1:0] m_bresp,
 input logic m_rvalid, input logic m_rready, input logic [DATA_WIDTH-1:0] m_rdata,
 input logic [1:0] m_rresp
);
 property p_b_stable; @(posedge aclk) disable iff (!aresetn)
   m_bvalid && !m_bready |=> m_bvalid && $stable(m_bresp);
 endproperty
 property p_r_stable; @(posedge aclk) disable iff (!aresetn)
   m_rvalid && !m_rready |=> m_rvalid && $stable({{m_rdata,m_rresp}});
 endproperty
 property p_reset_quiet; @(posedge aclk) !aresetn |=> !m_bvalid && !m_rvalid;
 endproperty
 assert property (p_b_stable);
 assert property (p_r_stable);
 assert property (p_reset_quiet);
endmodule
"""
