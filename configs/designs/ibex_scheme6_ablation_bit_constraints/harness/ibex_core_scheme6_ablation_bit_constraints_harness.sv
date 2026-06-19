// Ibex scheme6 ablation harness: strict input-bit-only combinational variants.
//
// The module keeps the 395-bit RFuzz input interface and does not use
// instruction templates, scenarios, protocol state machines, memory/RF models,
// or DUT-output feedback.  Different design configs compile this same source
// with one MODE_* define to test which narrow combinational constraint helps.

module ibex_core_scheme6_ablation_bit_constraints_harness (
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
    logic        use_fetch_projection;
    logic        use_handshake_projection;
    logic        use_valid_error_projection;
    logic        use_boot_alignment;
    logic        use_opcode_projection;
    logic        use_opcode_mixed;
    logic        use_opcode_mixed25;
    logic        use_opcode_mixed12;
    logic        use_opcode_mixed75;
    logic        use_low2_projection;
    logic        use_low2_mixed25;
    logic        use_low2_mixed50;
    logic [6:0]  legal_opcode_i;
    logic [6:0]  opcode_i;
    logic        opcode_project_en;
    logic        low2_project_en;
    logic        ls_project_en;
    logic        ls_word_project_en;
    logic        lsu_misalign_project_en;

    assign ic_data_rdata_i[0] = raw_ic_data_rdata_i[0];
    assign ic_data_rdata_i[1] = raw_ic_data_rdata_i[1];
    assign ic_tag_rdata_i[0]  = raw_ic_tag_rdata_i[0];
    assign ic_tag_rdata_i[1]  = raw_ic_tag_rdata_i[1];

`ifdef MODE_FETCH_ONLY
    assign use_fetch_projection     = 1'b1;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_HANDSHAKE_ONLY
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b1;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_FETCH_HANDSHAKE
    assign use_fetch_projection     = 1'b1;
    assign use_handshake_projection = 1'b1;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_MINLEGAL
    assign use_fetch_projection     = 1'b1;
    assign use_handshake_projection = 1'b1;
    assign use_valid_error_projection = 1'b1;
    assign use_boot_alignment       = 1'b1;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_OPCODE_ONLY
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_OPCODE_MIXED
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b1;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_OPCODE_MIXED25
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b1;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_OPCODE_MIXED12
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b1;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_OPCODE_MIXED75
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b1;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_OPCODE_MINLEGAL
    assign use_fetch_projection     = 1'b1;
    assign use_handshake_projection = 1'b1;
    assign use_valid_error_projection = 1'b1;
    assign use_boot_alignment       = 1'b1;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_LOW2_MIXED25
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b1;
    assign use_low2_mixed25         = 1'b1;
    assign use_low2_mixed50         = 1'b0;
`elsif MODE_LOW2_MIXED50
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b1;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b1;
`elsif MODE_LOW2_OPCODE_MIXED25
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b1;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b1;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b1;
    assign use_low2_mixed25         = 1'b1;
    assign use_low2_mixed50         = 1'b0;
`else
    assign use_fetch_projection     = 1'b0;
    assign use_handshake_projection = 1'b0;
    assign use_valid_error_projection = 1'b0;
    assign use_boot_alignment       = 1'b0;
    assign use_opcode_projection    = 1'b0;
    assign use_opcode_mixed         = 1'b0;
    assign use_opcode_mixed25       = 1'b0;
    assign use_opcode_mixed12       = 1'b0;
    assign use_opcode_mixed75       = 1'b0;
    assign use_low2_projection      = 1'b0;
    assign use_low2_mixed25         = 1'b0;
    assign use_low2_mixed50         = 1'b0;
`endif

    assign boot_addr_i = use_boot_alignment ? {raw_boot_addr_i[31:2], 2'b00} : raw_boot_addr_i;
    assign data_rdata_i     = raw_data_rdata_i;
    assign hart_id_i        = raw_hart_id_i;

`ifdef MODE_LS_OPCODE_MIXED50
    assign ls_project_en           = raw_instr_rdata_i[11];
    assign ls_word_project_en      = 1'b0;
    assign lsu_misalign_project_en = 1'b0;
`elsif MODE_LS_OPCODE_MIXED75
    assign ls_project_en           = raw_instr_rdata_i[11] | raw_instr_rdata_i[12];
    assign ls_word_project_en      = 1'b0;
    assign lsu_misalign_project_en = 1'b0;
`elsif MODE_LS_WORD_MIXED50
    assign ls_project_en           = raw_instr_rdata_i[11];
    assign ls_word_project_en      = 1'b1;
    assign lsu_misalign_project_en = 1'b0;
`elsif MODE_LS_MISALIGN_MIXED50
    assign ls_project_en           = raw_instr_rdata_i[11];
    assign ls_word_project_en      = 1'b1;
    assign lsu_misalign_project_en = 1'b1;
`elsif MODE_LS_MISALIGN_MIXED75
    assign ls_project_en           = raw_instr_rdata_i[11] | raw_instr_rdata_i[12];
    assign ls_word_project_en      = 1'b1;
    assign lsu_misalign_project_en = 1'b1;
`else
    assign ls_project_en           = 1'b0;
    assign ls_word_project_en      = 1'b0;
    assign lsu_misalign_project_en = 1'b0;
`endif

    assign legal_opcode_i =
        ls_project_en ? (raw_instr_rdata_i[10] ? 7'b0100011 : 7'b0000011) :
        (raw_instr_rdata_i[10:7] == 4'h0) ? 7'b0010011 :
        (raw_instr_rdata_i[10:7] == 4'h1) ? 7'b0110011 :
        (raw_instr_rdata_i[10:7] == 4'h2) ? 7'b0000011 :
        (raw_instr_rdata_i[10:7] == 4'h3) ? 7'b0100011 :
        (raw_instr_rdata_i[10:7] == 4'h4) ? 7'b1100011 :
        (raw_instr_rdata_i[10:7] == 4'h5) ? 7'b1101111 :
        (raw_instr_rdata_i[10:7] == 4'h6) ? 7'b1100111 :
        (raw_instr_rdata_i[10:7] == 4'h7) ? 7'b0110111 :
        (raw_instr_rdata_i[10:7] == 4'h8) ? 7'b0010111 :
        (raw_instr_rdata_i[10:7] == 4'h9) ? 7'b1110011 :
        (raw_instr_rdata_i[10:7] == 4'ha) ? 7'b0001111 :
        (raw_instr_rdata_i[10:7] == 4'hb) ? 7'b0010011 :
        (raw_instr_rdata_i[10:7] == 4'hc) ? 7'b0110011 :
        (raw_instr_rdata_i[10:7] == 4'hd) ? 7'b0000011 :
        (raw_instr_rdata_i[10:7] == 4'he) ? 7'b0100011 :
                                             7'b1100011;
    assign opcode_project_en =
        use_opcode_projection
        & (
            (~use_opcode_mixed & ~use_opcode_mixed25 & ~use_opcode_mixed12 & ~use_opcode_mixed75)
            | (use_opcode_mixed & raw_instr_rdata_i[11])
            | (use_opcode_mixed25 & raw_instr_rdata_i[11] & raw_instr_rdata_i[12])
            | (use_opcode_mixed12 & raw_instr_rdata_i[11] & raw_instr_rdata_i[12] & raw_instr_rdata_i[13])
            | (use_opcode_mixed75 & (raw_instr_rdata_i[11] | raw_instr_rdata_i[12]))
        );
    assign low2_project_en =
        use_low2_projection
        & (
            (~use_low2_mixed25 & ~use_low2_mixed50)
            | (use_low2_mixed25 & raw_instr_rdata_i[14] & raw_instr_rdata_i[15])
            | (use_low2_mixed50 & raw_instr_rdata_i[14])
        );
    assign opcode_i = (opcode_project_en | ls_project_en) ? legal_opcode_i : raw_instr_rdata_i[6:0];
    assign instr_rdata_i = {
        raw_instr_rdata_i[31:22],
        (lsu_misalign_project_en & ls_project_en) ? 2'b00 : raw_instr_rdata_i[21:20],
        raw_instr_rdata_i[19:15],
        (ls_word_project_en & ls_project_en) ? 3'b010 : raw_instr_rdata_i[14:12],
        raw_instr_rdata_i[11:9],
        (lsu_misalign_project_en & ls_project_en) ? 2'b00 : raw_instr_rdata_i[8:7],
        opcode_i[6:2],
        low2_project_en ? 2'b11 : opcode_i[1:0]
    };
    assign rf_rdata_a_ecc_i = (lsu_misalign_project_en & ls_project_en)
                             ? {
                                   raw_rf_rdata_a_ecc_i[31:2],
                                   (raw_rf_rdata_a_ecc_i[1:0] == 2'b00) ? 2'b01
                                                                        : raw_rf_rdata_a_ecc_i[1:0]
                               }
                             : raw_rf_rdata_a_ecc_i;
    assign rf_rdata_b_ecc_i = raw_rf_rdata_b_ecc_i;

    assign fetch_enable_i = use_fetch_projection ? {raw_fetch_enable_i[3:1], |raw_fetch_enable_i}
                                                 : raw_fetch_enable_i;

    assign instr_rvalid_i = raw_instr_rvalid_i;
    assign data_rvalid_i  = raw_data_rvalid_i;
    assign instr_gnt_i    = use_handshake_projection ? (raw_instr_gnt_i | instr_rvalid_i)
                                                     : raw_instr_gnt_i;
    assign data_gnt_i     = use_handshake_projection ? (raw_data_gnt_i | data_rvalid_i)
                                                     : raw_data_gnt_i;

    assign instr_err_i = use_valid_error_projection ? (raw_instr_err_i & instr_rvalid_i)
                                                    : raw_instr_err_i;
    assign data_err_i  = use_valid_error_projection ? (raw_data_err_i & data_rvalid_i)
                                                    : raw_data_err_i;

    assign ic_scr_key_valid_i = raw_ic_scr_key_valid_i;
    assign irq_nm_i           = raw_irq_nm_i;
    assign irq_software_i     = raw_irq_software_i;
    assign irq_timer_i        = raw_irq_timer_i;
    assign irq_external_i     = raw_irq_external_i;
    assign irq_fast_i         = raw_irq_fast_i;
    assign debug_req_i        = raw_debug_req_i;

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
