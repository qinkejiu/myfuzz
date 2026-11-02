// Passive observation only: original core and official monitor remain unchanged.
// The monitor has delayed tasks. This unit fixes their real time semantics.
`timescale 1ns/1ps
`define CV32E40P_RVFI
`include "cv32e40p_tb_wrapper.sv"
module cv32e40p_rvfi_local_top
  import cv32e40p_pkg::*;
#(
    parameter COREV_PULP = 0, // PULP ISA Extension (incl. custom CSRs and hardware loop, excl. cv.elw)
    parameter COREV_CLUSTER = 0,  // PULP Cluster interface (incl. cv.elw)
    parameter FPU = 0,  // Floating Point Unit (interfaced via APU interface)
    parameter FPU_ADDMUL_LAT = 0,  // Floating-Point ADDition/MULtiplication computing lane pipeline registers number
    parameter FPU_OTHERS_LAT = 0,  // Floating-Point COMParison/CONVersion computing lanes pipeline registers number
    parameter ZFINX = 0,  // Float-in-General Purpose registers
    parameter NUM_MHPMCOUNTERS = 1
) (
    // Clock and Reset
    input logic clk_i,
    input logic rst_ni,

    input logic pulp_clock_en_i,  // PULP clock enable (only used if COREV_CLUSTER = 1)
    input logic scan_cg_en_i,  // Enable all clock gates for testing

    // Core ID, Cluster ID, debug mode halt address and boot address are considered more or less static
    input logic [31:0] boot_addr_i,
    input logic [31:0] mtvec_addr_i,
    input logic [31:0] dm_halt_addr_i,
    input logic [31:0] hart_id_i,
    input logic [31:0] dm_exception_addr_i,

    // Instruction memory interface
    output logic        instr_req_o,
    input  logic        instr_gnt_i,
    input  logic        instr_rvalid_i,
    output logic [31:0] instr_addr_o,
    input  logic [31:0] instr_rdata_i,

    // Data memory interface
    output logic        data_req_o,
    input  logic        data_gnt_i,
    input  logic        data_rvalid_i,
    output logic        data_we_o,
    output logic [ 3:0] data_be_o,
    output logic [31:0] data_addr_o,
    output logic [31:0] data_wdata_o,
    input  logic [31:0] data_rdata_i,

    // Interrupt inputs
    input  logic [31:0] irq_i,  // CLINT interrupts + CLINT extension interrupts
    output logic        irq_ack_o,
    output logic [ 4:0] irq_id_o,

    // Debug Interface
    input  logic debug_req_i,
    output logic debug_havereset_o,
    output logic debug_running_o,
    output logic debug_halted_o,

    // CPU Control Signals
    input  logic fetch_enable_i,
    output logic core_sleep_o,
    output logic rvfi_valid,
    output logic [63:0] rvfi_order,
    output logic [31:0] rvfi_insn,
    output logic [31:0] rvfi_pc_rdata
);
  cv32e40p_tb_wrapper #(
    .COREV_PULP(COREV_PULP),
    .COREV_CLUSTER(COREV_CLUSTER),
    .FPU(FPU),
    .FPU_ADDMUL_LAT(FPU_ADDMUL_LAT),
    .FPU_OTHERS_LAT(FPU_OTHERS_LAT),
    .ZFINX(ZFINX),
    .NUM_MHPMCOUNTERS(NUM_MHPMCOUNTERS)
  ) u_original (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .pulp_clock_en_i(pulp_clock_en_i),
    .scan_cg_en_i(scan_cg_en_i),
    .boot_addr_i(boot_addr_i),
    .mtvec_addr_i(mtvec_addr_i),
    .dm_halt_addr_i(dm_halt_addr_i),
    .hart_id_i(hart_id_i),
    .dm_exception_addr_i(dm_exception_addr_i),
    .instr_req_o(instr_req_o),
    .instr_gnt_i(instr_gnt_i),
    .instr_rvalid_i(instr_rvalid_i),
    .instr_addr_o(instr_addr_o),
    .instr_rdata_i(instr_rdata_i),
    .data_req_o(data_req_o),
    .data_gnt_i(data_gnt_i),
    .data_rvalid_i(data_rvalid_i),
    .data_we_o(data_we_o),
    .data_be_o(data_be_o),
    .data_addr_o(data_addr_o),
    .data_wdata_o(data_wdata_o),
    .data_rdata_i(data_rdata_i),
    .irq_i(irq_i),
    .irq_ack_o(irq_ack_o),
    .irq_id_o(irq_id_o),
    .debug_req_i(debug_req_i),
    .debug_havereset_o(debug_havereset_o),
    .debug_running_o(debug_running_o),
    .debug_halted_o(debug_halted_o),
    .fetch_enable_i(fetch_enable_i),
    .core_sleep_o(core_sleep_o)
  );
  assign rvfi_valid = u_original.rvfi_i.rvfi_valid;
  assign rvfi_order = u_original.rvfi_i.rvfi_order;
  assign rvfi_insn = u_original.rvfi_i.rvfi_insn;
  assign rvfi_pc_rdata = u_original.rvfi_i.rvfi_pc_rdata;
endmodule
