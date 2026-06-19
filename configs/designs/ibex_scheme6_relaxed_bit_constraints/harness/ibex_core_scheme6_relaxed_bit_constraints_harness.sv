// Ibex scheme6: relaxed input-bit-only constraints.
//
// This harness keeps the same 395-bit rfuzz_input_bits interface as the
// baseline Ibex top-level harness.  It avoids instruction templates, protocol
// state machines, memory models, RF models, and DUT-output feedback.  Compared
// with scheme5, it removes constraints that shrink decode/IRQ diversity too
// aggressively while keeping local input relations that are cheap and useful.

module ibex_core_scheme6_relaxed_bit_constraints_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [394:0] rfuzz_input_bits,
    output logic [1113:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    logic [63:0] raw_ic_data_rdata_i [0:1];
    logic [21:0] raw_ic_tag_rdata_i [0:1];
    logic [31:0] raw_boot_addr_i;
    logic [31:0] raw_data_rdata_i;
    logic [31:0] raw_hart_id_i;
    logic [31:0] raw_instr_rdata_i;
    logic [31:0] raw_rf_rdata_a_ecc_i;
    logic [31:0] raw_rf_rdata_b_ecc_i;
    logic [14:0] raw_irq_fast_i;
    logic [3:0]  raw_fetch_enable_i;
    logic        raw_data_err_i;
    logic        raw_data_gnt_i;
    logic        raw_data_rvalid_i;
    logic        raw_debug_req_i;
    logic        raw_ic_scr_key_valid_i;
    logic        raw_instr_err_i;
    logic        raw_instr_gnt_i;
    logic        raw_instr_rvalid_i;
    logic        raw_irq_external_i;
    logic        raw_irq_nm_i;
    logic        raw_irq_software_i;
    logic        raw_irq_timer_i;

    assign raw_ic_data_rdata_i[0] = rfuzz_input_bits[394 -: 64];
    assign raw_ic_data_rdata_i[1] = rfuzz_input_bits[330 -: 64];
    assign raw_ic_tag_rdata_i[0]  = rfuzz_input_bits[266 -: 22];
    assign raw_ic_tag_rdata_i[1]  = rfuzz_input_bits[244 -: 22];
    assign raw_boot_addr_i        = rfuzz_input_bits[222 -: 32];
    assign raw_data_rdata_i       = rfuzz_input_bits[190 -: 32];
    assign raw_hart_id_i          = rfuzz_input_bits[158 -: 32];
    assign raw_instr_rdata_i      = rfuzz_input_bits[126 -: 32];
    assign raw_rf_rdata_a_ecc_i   = rfuzz_input_bits[94 -: 32];
    assign raw_rf_rdata_b_ecc_i   = rfuzz_input_bits[62 -: 32];
    assign raw_irq_fast_i         = rfuzz_input_bits[30 -: 15];
    assign raw_fetch_enable_i     = rfuzz_input_bits[15 -: 4];
    assign raw_data_err_i         = rfuzz_input_bits[11 -: 1];
    assign raw_data_gnt_i         = rfuzz_input_bits[10 -: 1];
    assign raw_data_rvalid_i      = rfuzz_input_bits[9 -: 1];
    assign raw_debug_req_i        = rfuzz_input_bits[8 -: 1];
    assign raw_ic_scr_key_valid_i = rfuzz_input_bits[7 -: 1];
    assign raw_instr_err_i        = rfuzz_input_bits[6 -: 1];
    assign raw_instr_gnt_i        = rfuzz_input_bits[5 -: 1];
    assign raw_instr_rvalid_i     = rfuzz_input_bits[4 -: 1];
    assign raw_irq_external_i     = rfuzz_input_bits[3 -: 1];
    assign raw_irq_nm_i           = rfuzz_input_bits[2 -: 1];
    assign raw_irq_software_i     = rfuzz_input_bits[1 -: 1];
    assign raw_irq_timer_i        = rfuzz_input_bits[0 -: 1];

    logic [63:0] ic_data_rdata_i [0:1];
    logic [21:0] ic_tag_rdata_i [0:1];
    logic [31:0] boot_addr_i;
    logic [31:0] data_rdata_i;
    logic [31:0] hart_id_i;
    logic [31:0] instr_rdata_i;
    logic [31:0] rf_rdata_a_ecc_i;
    logic [31:0] rf_rdata_b_ecc_i;
    logic [14:0] irq_fast_i;
    logic [3:0]  fetch_enable_i;
    logic        data_err_i;
    logic        data_gnt_i;
    logic        data_rvalid_i;
    logic        debug_req_i;
    logic        ic_scr_key_valid_i;
    logic        instr_err_i;
    logic        instr_gnt_i;
    logic        instr_rvalid_i;
    logic        irq_external_i;
    logic        irq_nm_i;
    logic        irq_software_i;
    logic        irq_timer_i;
    logic        instr_err_gate;
    logic        data_err_gate;
    logic        debug_gate;
    logic        regular_irq_gate;
    logic        fast_irq_gate;
    logic        nmi_gate;

    assign ic_data_rdata_i[0] = raw_ic_data_rdata_i[0];
    assign ic_data_rdata_i[1] = raw_ic_data_rdata_i[1];
    assign ic_tag_rdata_i[0]  = raw_ic_tag_rdata_i[0];
    assign ic_tag_rdata_i[1]  = raw_ic_tag_rdata_i[1];

    // Keep reset/trap targets naturally aligned without collapsing the low byte.
    assign boot_addr_i = {raw_boot_addr_i[31:2], 2'b00};

    assign data_rdata_i     = raw_data_rdata_i;
    assign hart_id_i        = raw_hart_id_i;
    assign instr_rdata_i    = raw_instr_rdata_i;
    assign rf_rdata_a_ecc_i = raw_rf_rdata_a_ecc_i;
    assign rf_rdata_b_ecc_i = raw_rf_rdata_b_ecc_i;

    // Keep fetch mostly enabled while preserving all four controlling bits.
    assign fetch_enable_i = {raw_fetch_enable_i[3:1], |raw_fetch_enable_i};

    // A response valid implies grant.  Valid itself stays raw, so response
    // density is unchanged from baseline.
    assign instr_rvalid_i = raw_instr_rvalid_i;
    assign instr_gnt_i    = raw_instr_gnt_i | instr_rvalid_i;
    assign data_rvalid_i  = raw_data_rvalid_i;
    assign data_gnt_i     = raw_data_gnt_i | data_rvalid_i;

    // Errors are legal only on valid responses, but fire often enough to keep
    // trap/error coverage active during short and long runs.
    assign instr_err_gate = raw_rf_rdata_a_ecc_i[0] | raw_rf_rdata_a_ecc_i[1];
    assign data_err_gate  = raw_rf_rdata_b_ecc_i[0] | raw_rf_rdata_b_ecc_i[1];
    assign instr_err_i    = instr_rvalid_i & raw_instr_err_i & instr_err_gate;
    assign data_err_i     = data_rvalid_i & raw_data_err_i & data_err_gate;

    assign ic_scr_key_valid_i = raw_ic_scr_key_valid_i;

    // Keep asynchronous events fuzz-controlled.  The gates reduce always-hot
    // behavior, but do not onehot fast IRQs or suppress multi-IRQ priority cases.
    assign nmi_gate         = raw_instr_rdata_i[10] | raw_instr_rdata_i[11];
    assign regular_irq_gate = raw_instr_rdata_i[6] | raw_instr_rdata_i[7];
    assign fast_irq_gate    = raw_instr_rdata_i[8] | raw_instr_rdata_i[9];
    assign debug_gate       = raw_data_rdata_i[0] | raw_data_rdata_i[1];

    assign irq_nm_i       = raw_irq_nm_i & nmi_gate;
    assign irq_software_i = raw_irq_software_i & regular_irq_gate & ~irq_nm_i;
    assign irq_timer_i    = raw_irq_timer_i & regular_irq_gate & ~irq_nm_i;
    assign irq_external_i = raw_irq_external_i & regular_irq_gate & ~irq_nm_i;
    assign irq_fast_i     = raw_irq_fast_i & {15{fast_irq_gate & ~irq_nm_i}};
    assign debug_req_i    = raw_debug_req_i & debug_gate & ~irq_nm_i;

    ibex_core #(
        .PMPEnable(1'b0),
        .SecureIbex(1'b0),
        .RV32M(ibex_pkg::RV32MFast),
        .RV32B(ibex_pkg::RV32BNone),
        .WritebackStage(1'b0),
        .ICache(1'b0),
        .RegFileECC(1'b0),
        .MemECC(1'b0)
    ) dut (
        .clk_i(clock),
        .rst_ni(rst_ni),

        .hart_id_i(hart_id_i),
        .boot_addr_i(boot_addr_i),

        .instr_req_o(),
        .instr_gnt_i(instr_gnt_i),
        .instr_rvalid_i(instr_rvalid_i),
        .instr_addr_o(),
        .instr_rdata_i(instr_rdata_i),
        .instr_err_i(instr_err_i),

        .data_req_o(),
        .data_gnt_i(data_gnt_i),
        .data_rvalid_i(data_rvalid_i),
        .data_we_o(),
        .data_be_o(),
        .data_addr_o(),
        .data_wdata_o(),
        .data_rdata_i(data_rdata_i),
        .data_err_i(data_err_i),

        .dummy_instr_id_o(),
        .dummy_instr_wb_o(),
        .rf_raddr_a_o(),
        .rf_raddr_b_o(),
        .rf_waddr_wb_o(),
        .rf_we_wb_o(),
        .rf_wdata_wb_ecc_o(),
        .rf_rdata_a_ecc_i(rf_rdata_a_ecc_i),
        .rf_rdata_b_ecc_i(rf_rdata_b_ecc_i),

        .ic_tag_req_o(),
        .ic_tag_write_o(),
        .ic_tag_addr_o(),
        .ic_tag_wdata_o(),
        .ic_tag_rdata_i(ic_tag_rdata_i),
        .ic_data_req_o(),
        .ic_data_write_o(),
        .ic_data_addr_o(),
        .ic_data_wdata_o(),
        .ic_data_rdata_i(ic_data_rdata_i),
        .ic_scr_key_valid_i(ic_scr_key_valid_i),
        .ic_scr_key_req_o(),

        .irq_software_i(irq_software_i),
        .irq_timer_i(irq_timer_i),
        .irq_external_i(irq_external_i),
        .irq_fast_i(irq_fast_i),
        .irq_nm_i(irq_nm_i),
        .irq_pending_o(),

        .debug_req_i(debug_req_i),
        .crash_dump_o(),
        .double_fault_seen_o(),
        .alert_minor_o(),
        .alert_major_internal_o(),
        .alert_major_bus_o(),
        .core_busy_o(),
        .fetch_enable_i(fetch_enable_i),
        .__vi_coverage(__vi_coverage)
    );

endmodule
