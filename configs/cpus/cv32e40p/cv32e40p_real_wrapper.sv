// Thin, name-independent integration shell for the upstream CV32E40P core.
// The shell exposes only the OBI/clock/reset contract used by the generic
// planner and ties the core's unrelated verification pins to deterministic
// values.  The CPU implementation itself remains the upstream RTL.
module real_cv32e40p_core (
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
    logic [31:0] instr_rdata_core;
    logic [31:0] data_rdata_core;

    // The upstream CV32E40P OBI interface has no explicit error pins.  Keep
    // the common shell contract honest by consuming backend errors: an
    // instruction error becomes an illegal instruction response, while a
    // data error returns zero data.  The core therefore cannot silently use
    // stale response bits even though it has no dedicated error CSR input.
    assign instr_rdata_core = instr_err_i ? 32'h0000_0000 : instr_rdata_i;
    assign data_rdata_core = data_err_i ? 32'h0000_0000 : data_rdata_i;

    // CV32E40P has no architectural OBI error input.  A backend error cannot
    // be represented for a store (and a zero load value would be ambiguous),
    // so the simulation shell terminates instead of claiming a successful
    // transaction.  The matrix therefore proves only the no-error path; a
    // production integration must add a core-specific exception bridge.
    always_ff @(posedge clock) begin
        if (instr_rvalid_i && instr_err_i)
            $fatal(1, "CV32E40P instruction error has no architectural OBI channel");
        if (data_rvalid_i && data_err_i)
            $fatal(1, "CV32E40P data error has no architectural OBI channel");
    end

    always_ff @(posedge clock) begin
        if (!reset) reset_probe_q <= 1'b0;
        else reset_probe_q <= 1'b1;
    end

    cv32e40p_core u_core (
        .clk_i(clock), .rst_ni(reset), .pulp_clock_en_i(1'b1),
        .scan_cg_en_i(1'b0), .boot_addr_i(32'h0000_0000),
        .mtvec_addr_i(32'h0000_0000), .dm_halt_addr_i(32'h0000_0000),
        .hart_id_i(32'h0000_0000), .dm_exception_addr_i(32'h0000_0000),
        .instr_req_o(instr_req_o), .instr_gnt_i(instr_gnt_i),
        .instr_rvalid_i(instr_rvalid_i), .instr_addr_o(instr_addr_o),
        .instr_rdata_i(instr_rdata_core), .data_req_o(data_req_o),
        .data_gnt_i(data_gnt_i), .data_rvalid_i(data_rvalid_i),
        .data_we_o(data_we_o), .data_be_o(data_be_o), .data_addr_o(data_addr_o),
        .data_wdata_o(data_wdata_o), .data_rdata_i(data_rdata_core),
        .apu_gnt_i(1'b0), .apu_rvalid_i(1'b0), .apu_result_i(32'h0),
        .apu_flags_i('0), .irq_i(32'h0), .debug_req_i(1'b0),
        .fetch_enable_i(1'b1)
    );
endmodule
