// Self-contained CPU master models for AutoTop material testing.
//
// These are dependency-free bus-master validation models named after well-known
// open CPU families. They provide enough CPU-like traffic diversity to test
// AutoTop composition without requiring generator outputs or native SoC glue.

module famous_cpu_master_model #(
  parameter logic [31:0] BASE_ADDR = 32'h0000_0000,
  parameter logic [31:0] STRIDE    = 32'h0000_0004,
  parameter int unsigned PHASE     = 0
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  logic [31:0] counter_q;
  logic [31:0] mix_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      counter_q <= 32'h0;
      mix_q <= 32'h9e37_79b9 ^ BASE_ADDR;
    end else if (data_gnt_i) begin
      counter_q <= counter_q + 1'b1;
      mix_q <= {mix_q[30:0], mix_q[31]} ^ data_rdata_i ^ (32'h1020_3040 + PHASE);
    end
  end

  assign data_addr_o = BASE_ADDR + ((counter_q + PHASE[31:0]) * STRIDE);
  assign data_wdata_o = mix_q ^ counter_q ^ BASE_ADDR;
  assign data_we_o = counter_q[PHASE % 5];
  assign data_req_o = 1'b1;
endmodule

module serv_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h0000_0000), .STRIDE(32'h0000_0004), .PHASE(1)) u_model (.*);
endmodule

module vexriscv_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000_0000), .STRIDE(32'h0000_0010), .PHASE(2)) u_model (.*);
endmodule

module neorv32_cpu_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000_1000), .STRIDE(32'h0000_0008), .PHASE(3)) u_model (.*);
endmodule

module rocket_rv32_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h0000_0000), .STRIDE(32'h0000_0020), .PHASE(4)) u_model (.*);
endmodule

module boom_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000_2000), .STRIDE(32'h0000_0040), .PHASE(5)) u_model (.*);
endmodule

module blackparrot_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000_3000), .STRIDE(32'h0000_0004), .PHASE(6)) u_model (.*);
endmodule

module lm32_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000_0000), .STRIDE(32'h0000_0004), .PHASE(7)) u_model (.*);
endmodule

module mor1kx_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000_1000), .STRIDE(32'h0000_0010), .PHASE(8)) u_model (.*);
endmodule
