// SPDX-License-Identifier: ISC
// Experiment-only adapter. The qualification wrapper remains frozen.
module picorv32_level1_adapter #(
  parameter [31:0] RESET_VECTOR = 32'h0000_2000
) (
  input  wire        clk,
  input  wire        resetn,
  input  wire [31:0] fuzz_irq,
  output wire        cpu_trap,
  output wire        m_awvalid,
  input  wire        m_awready,
  output wire [31:0] m_awaddr,
  output wire        m_wvalid,
  input  wire        m_wready,
  output wire [31:0] m_wdata,
  output wire [3:0]  m_wstrb,
  input  wire        m_bvalid,
  output wire        m_bready,
  input  wire [1:0]  m_bresp,
  output wire        m_arvalid,
  input  wire        m_arready,
  output wire [31:0] m_araddr,
  input  wire        m_rvalid,
  output wire        m_rready,
  input  wire [31:0] m_rdata,
  input  wire [1:0]  m_rresp
);
  wire mem_valid, mem_instr, mem_ready;
  wire [31:0] mem_addr, mem_native_wdata, mem_native_rdata;
  wire [3:0] mem_native_wstrb;
  wire pcpi_valid;
  wire [31:0] pcpi_insn, pcpi_rs1, pcpi_rs2, eoi;
  wire trace_valid;
  wire [35:0] trace_data;
  wire unused_response = ^{m_bresp, m_rresp, pcpi_valid, pcpi_insn, pcpi_rs1,
                           pcpi_rs2, eoi, trace_valid, trace_data};

  picorv32 #(
    .PROGADDR_RESET(RESET_VECTOR),
    .ENABLE_PCPI(1'b0),
    .ENABLE_IRQ(1'b1),
    .ENABLE_TRACE(1'b0)
  ) i_cpu (
    .clk(clk), .resetn(resetn), .trap(cpu_trap),
    .mem_valid(mem_valid), .mem_instr(mem_instr), .mem_ready(mem_ready),
    .mem_addr(mem_addr), .mem_wdata(mem_native_wdata),
    .mem_wstrb(mem_native_wstrb), .mem_rdata(mem_native_rdata),
    .pcpi_valid(pcpi_valid), .pcpi_insn(pcpi_insn), .pcpi_rs1(pcpi_rs1),
    .pcpi_rs2(pcpi_rs2), .pcpi_wr(1'b0), .pcpi_rd(32'b0), .pcpi_wait(1'b0),
    .pcpi_ready(1'b0), .irq(fuzz_irq), .eoi(eoi),
    .trace_valid(trace_valid), .trace_data(trace_data)
  );

  myfuzz_picorv32_axi_lite_bridge i_axi_bridge (
    .clk(clk), .resetn(resetn),
    .mem_valid(mem_valid), .mem_instr(mem_instr), .mem_ready(mem_ready),
    .mem_addr(mem_addr), .mem_wdata(mem_native_wdata),
    .mem_wstrb(mem_native_wstrb), .mem_rdata(mem_native_rdata),
    .m_awvalid(m_awvalid), .m_awready(m_awready), .m_awaddr(m_awaddr),
    .m_wvalid(m_wvalid), .m_wready(m_wready), .m_wdata(m_wdata), .m_wstrb(m_wstrb),
    .m_bvalid(m_bvalid), .m_bready(m_bready),
    .m_arvalid(m_arvalid), .m_arready(m_arready), .m_araddr(m_araddr),
    .m_rvalid(m_rvalid), .m_rready(m_rready), .m_rdata(m_rdata)
  );
endmodule

// The upstream picorv32_axi_adapter treats either response channel as the
// completion of the current native request. Keep one direction in flight so a
// delayed B response cannot complete a read, and a delayed R response cannot
// complete a write.
module myfuzz_picorv32_axi_lite_bridge (
  input  wire        clk,
  input  wire        resetn,
  input  wire        mem_valid,
  input  wire        mem_instr,
  output wire        mem_ready,
  input  wire [31:0] mem_addr,
  input  wire [31:0] mem_wdata,
  input  wire [3:0]  mem_wstrb,
  output wire [31:0] mem_rdata,
  output wire        m_awvalid,
  input  wire        m_awready,
  output wire [31:0] m_awaddr,
  output wire        m_wvalid,
  input  wire        m_wready,
  output wire [31:0] m_wdata,
  output wire [3:0]  m_wstrb,
  input  wire        m_bvalid,
  output wire        m_bready,
  output wire        m_arvalid,
  input  wire        m_arready,
  output wire [31:0] m_araddr,
  input  wire        m_rvalid,
  output wire        m_rready,
  input  wire [31:0] m_rdata
);
  localparam [2:0] IDLE=3'd0, WRITE_SEND=3'd1, WRITE_RESP=3'd2,
                   READ_SEND=3'd3, READ_RESP=3'd4;
  reg [2:0] state;
  reg [31:0] address_hold, write_data_hold;
  reg [3:0] write_strobe_hold;
  reg aw_pending, w_pending;

  assign m_awvalid = state == WRITE_SEND && aw_pending;
  assign m_awaddr = address_hold;
  assign m_wvalid = state == WRITE_SEND && w_pending;
  assign m_wdata = write_data_hold;
  assign m_wstrb = write_strobe_hold;
  assign m_bready = state == WRITE_RESP && mem_valid && |mem_wstrb;
  assign m_arvalid = state == READ_SEND;
  assign m_araddr = address_hold;
  assign m_rready = state == READ_RESP && mem_valid && !(|mem_wstrb);
  assign mem_ready = (state == WRITE_RESP && m_bvalid && |mem_wstrb) ||
                     (state == READ_RESP && m_rvalid && !(|mem_wstrb));
  assign mem_rdata = m_rdata;

  always @(posedge clk or negedge resetn) begin
    if (!resetn) begin
      state <= IDLE;
      address_hold <= 0;
      write_data_hold <= 0;
      write_strobe_hold <= 0;
      aw_pending <= 0;
      w_pending <= 0;
    end else begin
      case (state)
        IDLE: if (mem_valid) begin
          address_hold <= mem_addr;
          write_data_hold <= mem_wdata;
          write_strobe_hold <= mem_wstrb;
          if (|mem_wstrb) begin
            aw_pending <= 1;
            w_pending <= 1;
            state <= WRITE_SEND;
          end else begin
            state <= READ_SEND;
          end
        end
        WRITE_SEND: begin
          if (m_awvalid && m_awready) aw_pending <= 0;
          if (m_wvalid && m_wready) w_pending <= 0;
          if ((!aw_pending || m_awready) && (!w_pending || m_wready))
            state <= WRITE_RESP;
        end
        WRITE_RESP: if (m_bvalid && m_bready) state <= IDLE;
        READ_SEND: if (m_arvalid && m_arready) state <= READ_RESP;
        READ_RESP: if (m_rvalid && m_rready) state <= IDLE;
        default: state <= IDLE;
      endcase
    end
  end

  wire unused_instruction = mem_instr;
endmodule
