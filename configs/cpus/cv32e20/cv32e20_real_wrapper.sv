// Thin integration shell for the upstream CVE2/CV32E20 implementation.
// Only the split OBI memory contract is surfaced; extension/debug outputs and
// inputs are deliberately left at deterministic smoke-test defaults.
module real_cv32e20_core (
    input  logic        clock,
    input  logic        reset,
    output logic        instr_req_o,
    input  logic        instr_gnt_i,
    input  logic        instr_rvalid_i,
    output logic [31:0] instr_addr_o,
    input  logic [31:0] instr_rdata_i,
    input  logic        instr_err_i,
    output logic        data_req_o,
    input  logic        data_gnt_i,
    input  logic        data_rvalid_i,
    output logic        data_we_o,
    output logic [3:0]  data_be_o,
    output logic [31:0] data_addr_o,
    output logic [31:0] data_wdata_o,
    input  logic [31:0] data_rdata_i,
    input  logic        data_err_i
);
    logic reset_probe_q;

    always_ff @(posedge clock) begin
        if (!reset) reset_probe_q <= 1'b0;
        else reset_probe_q <= 1'b1;
    end

    cve2_top u_core (
        .clk_i(clock), .rst_ni(reset), .test_en_i(1'b0),
        .hart_id_i(32'h0000_0000), .boot_addr_i(32'h0000_0000),
        .instr_req_o(instr_req_o), .instr_gnt_i(instr_gnt_i),
        .instr_rvalid_i(instr_rvalid_i), .instr_addr_o(instr_addr_o),
        .instr_rdata_i(instr_rdata_i), .instr_err_i(instr_err_i),
        .data_req_o(data_req_o), .data_gnt_i(data_gnt_i),
        .data_rvalid_i(data_rvalid_i), .data_we_o(data_we_o),
        .data_be_o(data_be_o), .data_addr_o(data_addr_o),
        .data_wdata_o(data_wdata_o), .data_rdata_i(data_rdata_i),
        .data_err_i(data_err_i), .irq_software_i(1'b0), .irq_timer_i(1'b0),
        .irq_external_i(1'b0), .irq_fast_i(16'h0), .irq_nm_i(1'b0),
        .debug_req_i(1'b0), .dm_halt_addr_i(32'h0),
        .dm_exception_addr_i(32'h0), .fetch_enable_i(1'b1)
    );
endmodule
