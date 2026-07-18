"""Generic AXI-Lite-to-APB bridge and APB decoder backends."""

from __future__ import annotations

from dataclasses import dataclass

from .input_model import InputValidationError


@dataclass(frozen=True)
class ApbDecoderConfig:
    address_width: int
    data_width: int
    bases: tuple[int, ...]
    sizes: tuple[int, ...]
    apb4: bool = False

    def __post_init__(self) -> None:
        _validate_widths(self.address_width, self.data_width)
        if not self.bases or len(self.bases) != len(self.sizes):
            raise InputValidationError("APB decoder requires equal non-empty base/size arrays")
        _validate_windows(self.address_width, self.bases, self.sizes)


def emit_axi_lite_to_apb_bridge(
    *, address_width: int = 32, data_width: int = 32, apb4: bool = False,
    module_name: str = "myfuzz_axi_lite_to_apb",
) -> str:
    """Emit one single-outstanding AXI-Lite slave to APB master bridge."""
    _validate_widths(address_width, data_width)
    _identifier(module_name, "bridge module_name")
    return f"""module {module_name} #(
  parameter integer ADDR_WIDTH={address_width}, DATA_WIDTH={data_width}
) (
  input logic clk, input logic resetn,
  input logic [ADDR_WIDTH-1:0] s_awaddr, input logic s_awvalid, output logic s_awready,
  input logic [DATA_WIDTH-1:0] s_wdata, input logic [DATA_WIDTH/8-1:0] s_wstrb,
  input logic s_wvalid, output logic s_wready,
  output logic [1:0] s_bresp, output logic s_bvalid, input logic s_bready,
  input logic [ADDR_WIDTH-1:0] s_araddr, input logic s_arvalid, output logic s_arready,
  output logic [DATA_WIDTH-1:0] s_rdata, output logic [1:0] s_rresp,
  output logic s_rvalid, input logic s_rready,
  output logic psel, output logic penable, output logic pwrite,
  output logic [ADDR_WIDTH-1:0] paddr, output logic [DATA_WIDTH-1:0] pwdata,
  output logic [DATA_WIDTH/8-1:0] pstrb,
  input logic pready, input logic [DATA_WIDTH-1:0] prdata, input logic pslverr
);
  localparam [2:0] IDLE=0, WRITE_COLLECT=1, APB_SETUP=2, APB_ACCESS=3,
                   WRITE_RESPONSE=4, READ_RESPONSE=5;
  logic [2:0] state;
  logic have_aw, have_w, request_write;
  logic [ADDR_WIDTH-1:0] address_reg;
  logic [DATA_WIDTH-1:0] data_reg, read_data_reg;
  logic [DATA_WIDTH/8-1:0] strobe_reg;
  logic response_error;

  always_comb begin
    s_awready = 1'b0; s_wready = 1'b0; s_arready = 1'b0;
    s_bvalid = (state == WRITE_RESPONSE); s_bresp = response_error ? 2'b10 : 2'b00;
    s_rvalid = (state == READ_RESPONSE); s_rresp = response_error ? 2'b10 : 2'b00;
    s_rdata = read_data_reg;
    psel = (state == APB_SETUP) || (state == APB_ACCESS);
    penable = (state == APB_ACCESS); pwrite = request_write;
    paddr = address_reg; pwdata = data_reg; pstrb = strobe_reg;
    if (state == IDLE) begin
      if (s_awvalid || s_wvalid) begin s_awready = !have_aw; s_wready = !have_w; end
      else s_arready = 1'b1;
    end else if (state == WRITE_COLLECT) begin
      s_awready = !have_aw; s_wready = !have_w;
    end
  end

  always_ff @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      state<=IDLE; have_aw<=0; have_w<=0; request_write<=0; address_reg<='0;
      data_reg<='0; strobe_reg<='0; read_data_reg<='0; response_error<=0;
    end else begin
      case (state)
        IDLE: begin
          response_error<=0;
          if (s_awvalid || s_wvalid) begin
            request_write<=1; have_aw<=s_awvalid; have_w<=s_wvalid;
            if (s_awvalid) address_reg<=s_awaddr;
            if (s_wvalid) begin data_reg<=s_wdata; strobe_reg<=s_wstrb; end
            if (s_awvalid && s_wvalid) state<=APB_SETUP; else state<=WRITE_COLLECT;
          end else if (s_arvalid) begin
            request_write<=0; address_reg<=s_araddr; strobe_reg<='0; state<=APB_SETUP;
          end
        end
        WRITE_COLLECT: begin
          if (s_awready && s_awvalid) begin have_aw<=1; address_reg<=s_awaddr; end
          if (s_wready && s_wvalid) begin have_w<=1; data_reg<=s_wdata; strobe_reg<=s_wstrb; end
          if ((have_aw || (s_awready && s_awvalid)) &&
              (have_w || (s_wready && s_wvalid))) begin state<=APB_SETUP; end
        end
        APB_SETUP: state<=APB_ACCESS;
        APB_ACCESS: if (pready) begin
          response_error<=pslverr;
          if (request_write) state<=WRITE_RESPONSE;
          else begin read_data_reg<=prdata; state<=READ_RESPONSE; end
        end
        WRITE_RESPONSE: if (s_bready) begin state<=IDLE; have_aw<=0; have_w<=0; end
        READ_RESPONSE: if (s_rready) state<=IDLE;
        default: state<=IDLE;
      endcase
    end
  end
endmodule
"""


def emit_apb_decoder(config: ApbDecoderConfig,
                     module_name: str = "myfuzz_apb_decoder") -> str:
    """Emit an APB decoder with local byte addresses and an error default target."""
    _identifier(module_name, "APB decoder module_name")
    count = len(config.bases); aw = config.address_width; dw = config.data_width
    lines = [f"module {module_name} #(parameter integer ADDR_WIDTH={aw}, DATA_WIDTH={dw}, TARGETS={count}) (",
        "  input logic psel, input logic penable, input logic pwrite,",
        "  input logic [ADDR_WIDTH-1:0] paddr, input logic [DATA_WIDTH-1:0] pwdata,",
        "  input logic [DATA_WIDTH/8-1:0] pstrb, output logic pready,",
        "  output logic [DATA_WIDTH-1:0] prdata, output logic pslverr,",
        "  output logic [TARGETS-1:0] m_psel, output logic [TARGETS-1:0] m_penable,",
        "  output logic [TARGETS-1:0] m_pwrite,",
        "  output logic [TARGETS-1:0][ADDR_WIDTH-1:0] m_paddr,",
        "  output logic [TARGETS-1:0][DATA_WIDTH-1:0] m_pwdata,",
        "  output logic [TARGETS-1:0][DATA_WIDTH/8-1:0] m_pstrb,",
        "  input logic [TARGETS-1:0] m_pready,",
        "  input logic [TARGETS-1:0][DATA_WIDTH-1:0] m_prdata,",
        "  input logic [TARGETS-1:0] m_pslverr",
        ");", "  integer selected;"]
    for index, (base, size) in enumerate(zip(config.bases, config.sizes)):
        lines.append(f"  localparam logic [ADDR_WIDTH-1:0] BASE_{index}={aw}'h{base:x}, END_{index}={aw}'h{base + size:x};")
    lines += ["  always_comb begin", "    selected=-1; m_psel='0; m_penable='0; m_pwrite='0;",
              "    m_paddr='0; m_pwdata='0; m_pstrb='0; pready=1'b0; prdata='0; pslverr=1'b0;"]
    for index in range(count):
        lines.append(f"    if (paddr >= BASE_{index} && paddr < END_{index}) selected={index};")
    lines += ["    if (psel && selected >= 0) begin",
              "      m_psel[selected]=1'b1; m_penable[selected]=penable; m_pwrite[selected]=pwrite;",
              "      m_pwdata[selected]=pwdata; m_pstrb[selected]=pstrb;",
              "      pready=m_pready[selected]; prdata=m_prdata[selected]; pslverr=m_pslverr[selected];",
              "      case (selected)"]
    for index in range(count):
        lines.append(f"        {index}: m_paddr[selected]=paddr-BASE_{index};")
    lines += ["        default: m_paddr[selected]='0; endcase", "    end else if (psel) begin",
              "      pready=1'b1; pslverr=1'b1;", "    end", "  end", "endmodule", ""]
    return "\n".join(lines)


def _validate_widths(address_width: int, data_width: int) -> None:
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
           for value in (address_width, data_width)):
        raise InputValidationError("APB address/data widths must be positive integers")
    if data_width != 32:
        raise InputValidationError("first-stage AXI-Lite/APB backend requires 32-bit data")


def _validate_windows(address_width: int, bases: tuple[int, ...], sizes: tuple[int, ...]) -> None:
    limit = 1 << address_width; windows = sorted(zip(bases, sizes))
    for base, size in windows:
        if base < 0 or size <= 0 or base + size > limit:
            raise InputValidationError("APB window exceeds address space")
    for (base, size), (next_base, _next_size) in zip(windows, windows[1:]):
        if base + size > next_base: raise InputValidationError("APB windows overlap")


def _identifier(value: str, path: str) -> None:
    if not isinstance(value, str) or not value.isidentifier():
        raise InputValidationError(f"{path} must be a Verilog identifier")
