// Auto-generated dependency-free bulk CPU models for AutoTop material testing.

module microwatt_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40009000), .STRIDE(32'h00000008), .PHASE(9)) u_model (.*);
endmodule

module or1200_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000a000), .STRIDE(32'h00000010), .PHASE(10)) u_model (.*);
endmodule

module leon3_sparc_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000b000), .STRIDE(32'h00000020), .PHASE(11)) u_model (.*);
endmodule

module openmips_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000c000), .STRIDE(32'h00000004), .PHASE(12)) u_model (.*);
endmodule

module orca_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000d000), .STRIDE(32'h00000008), .PHASE(13)) u_model (.*);
endmodule

module scr1_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000e000), .STRIDE(32'h00000010), .PHASE(14)) u_model (.*);
endmodule

module sodor5_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h4000f000), .STRIDE(32'h00000020), .PHASE(15)) u_model (.*);
endmodule

module swerv_eh1_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40000000), .STRIDE(32'h00000004), .PHASE(16)) u_model (.*);
endmodule

module swerv_el2_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40001000), .STRIDE(32'h00000008), .PHASE(17)) u_model (.*);
endmodule

module cva6_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40002000), .STRIDE(32'h00000010), .PHASE(18)) u_model (.*);
endmodule

module ariane_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40003000), .STRIDE(32'h00000020), .PHASE(19)) u_model (.*);
endmodule

module minerva_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40004000), .STRIDE(32'h00000004), .PHASE(20)) u_model (.*);
endmodule

module femtorv_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40005000), .STRIDE(32'h00000008), .PHASE(21)) u_model (.*);
endmodule

module darkriscv_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40006000), .STRIDE(32'h00000010), .PHASE(22)) u_model (.*);
endmodule

module ao486_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40007000), .STRIDE(32'h00000020), .PHASE(23)) u_model (.*);
endmodule

module zpu_core_model (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);
  famous_cpu_master_model #(.BASE_ADDR(32'h40008000), .STRIDE(32'h00000004), .PHASE(24)) u_model (.*);
endmodule
