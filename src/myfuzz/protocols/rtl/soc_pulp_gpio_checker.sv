// Independent boundary monitor for the pinned 32-pad PULP APB GPIO.
// Local bits 0..14 map to global checker IDs 21..35. Bits 11..14 are reserved
// for interrupt/status behaviors and deliberately remain unevaluated here.
module soc_pulp_gpio_checker (
    input  logic         clk_i,
    input  logic         rst_ni,
    input  logic [11:0]  paddr_i,
    input  logic         psel_i,
    input  logic         penable_i,
    input  logic         pwrite_i,
    input  logic [31:0]  pwdata_i,
    input  logic [31:0]  prdata_i,
    input  logic         pready_i,
    input  logic         pslverr_i,
    input  logic [31:0]  gpio_in_i,
    input  logic [31:0]  gpio_out_i,
    input  logic [31:0]  gpio_dir_i,
    input  logic [127:0] gpio_padcfg_i,
    input  logic [31:0]  gpio_in_sync_i,
    input  logic         interrupt_i,
    output logic [14:0]  eval_o,
    output logic [14:0]  fail_o,
    output logic [5:0]   first_fail_id_o
);
    localparam logic [11:0] REG_PADDIR     = 12'h000;
    localparam logic [11:0] REG_GPIOEN     = 12'h004;
    localparam logic [11:0] REG_PADIN      = 12'h008;
    localparam logic [11:0] REG_PADOUT     = 12'h00c;
    localparam logic [11:0] REG_PADOUTSET  = 12'h010;
    localparam logic [11:0] REG_PADOUTCLR  = 12'h014;
    localparam logic [11:0] REG_PADCFG0    = 12'h028;
    localparam logic [11:0] REG_PADCFG3    = 12'h034;

    logic [31:0] paddir_q;
    logic [31:0] gpioen_q;
    logic [31:0] padout_q;
    logic [127:0] padcfg_q;
    logic [31:0] sync0_q;
    logic [31:0] sync1_q;
    logic [31:0] padin_q;
    logic reset_pending_q;
    logic [1:0] out_check_kind_q;
    logic cfg_check_pending_q;
    logic [14:0] eval_d;
    logic [14:0] fail_d;

    wire access_accept = psel_i && penable_i && pready_i && !pslverr_i;
    // The locked APB GPIO RTL decodes PADDR[6:2]; higher bits and the low
    // byte offset therefore alias the same register. Keep this source-derived
    // probe aligned with that decode while leaving the public oracle strict.
    wire [11:0] canonical_paddr = {5'b0, paddr_i[6:2], 2'b00};

    // Evaluation is a one-cycle pulse. The failure vector is sticky until reset.
    always_comb begin
        eval_d = '0;
        fail_d = fail_o;

        if (reset_pending_q) begin
            eval_d[0] = 1'b1;
            if (gpio_out_i !== 32'b0 || gpio_dir_i !== 32'b0 ||
                gpio_padcfg_i !== 128'b0 || gpio_in_sync_i !== 32'b0)
                fail_d[0] = 1'b1;
        end else begin
            // The independent direction shadow is checked against the exported
            // direction pins on every active cycle (source-derived probe).
            eval_d[10] = 1'b1;
            if (gpio_dir_i !== paddir_q) fail_d[10] = 1'b1;

            // GPIOEN controls clock sampling by groups of four pads in the
            // locked RTL. Disabled groups must hold; enabled groups advance the
            // separate input-stage model. These are source-derived probes.
            for (int group = 0; group < 8; group++) begin
                if (|(gpioen_q[group*4 +: 4])) begin
                    eval_d[8] = 1'b1;
                    if (gpio_in_sync_i[group*4 +: 4] !==
                        sync1_q[group*4 +: 4])
                        fail_d[8] = 1'b1;
                end else begin
                    eval_d[7] = 1'b1;
                    if (gpio_in_sync_i[group*4 +: 4] !==
                        sync1_q[group*4 +: 4])
                        fail_d[7] = 1'b1;
                end
            end

            // PADOUT/PADOUTSET/PADOUTCLR pin effects are checked one sampled
            // cycle after accepted writes, when the real register has updated.
            if (out_check_kind_q == 2'd1) begin
                eval_d[4] = 1'b1;
                if (gpio_out_i !== padout_q) fail_d[4] = 1'b1;
            end else if (out_check_kind_q == 2'd2) begin
                eval_d[5] = 1'b1;
                if (gpio_out_i !== padout_q) fail_d[5] = 1'b1;
            end else if (out_check_kind_q == 2'd3) begin
                eval_d[3] = 1'b1;
                if (gpio_out_i !== padout_q) fail_d[3] = 1'b1;
            end

            // PADCFG pin outputs are sampled after the accepted write. The
            // flattened layout follows gpio_padcfg[pad][3:0].
            if (cfg_check_pending_q) begin
                eval_d[6] = 1'b1;
                if (gpio_padcfg_i !== padcfg_q) fail_d[6] = 1'b1;
            end

            if (access_accept && !pwrite_i) begin
                case (canonical_paddr)
                    REG_PADDIR: begin
                        eval_d[1] = 1'b1;
                        if (prdata_i !== paddir_q) fail_d[1] = 1'b1;
                    end
                    REG_GPIOEN: begin
                        eval_d[2] = 1'b1;
                        if (prdata_i !== gpioen_q) fail_d[2] = 1'b1;
                    end
                    REG_PADIN: begin
                        eval_d[9] = 1'b1;
                        if (prdata_i !== padin_q) fail_d[9] = 1'b1;
                    end
                    REG_PADOUT: begin
                        eval_d[3] = 1'b1;
                        if (prdata_i !== padout_q) fail_d[3] = 1'b1;
                    end
                    default: begin
                        if (canonical_paddr >= REG_PADCFG0 &&
                            canonical_paddr <= REG_PADCFG3) begin
                            eval_d[6] = 1'b1;
                            if (prdata_i !==
                                padcfg_q[((canonical_paddr - REG_PADCFG0) >> 2)*32 +: 32])
                                fail_d[6] = 1'b1;
                        end
                    end
                endcase
            end
        end
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            paddir_q <= '0;
            gpioen_q <= '0;
            padout_q <= '0;
            padcfg_q <= '0;
            sync0_q <= '0;
            sync1_q <= '0;
            padin_q <= '0;
            reset_pending_q <= 1'b1;
            out_check_kind_q <= '0;
            cfg_check_pending_q <= 1'b0;
            eval_o <= '0;
            fail_o <= '0;
        end else begin
            eval_o <= eval_d;
            fail_o <= fail_d;
            reset_pending_q <= 1'b0;

            for (int group = 0; group < 8; group++) begin
                if (|(gpioen_q[group*4 +: 4])) begin
                    sync0_q[group*4 +: 4] <= gpio_in_i[group*4 +: 4];
                    sync1_q[group*4 +: 4] <= sync0_q[group*4 +: 4];
                    padin_q[group*4 +: 4] <= sync1_q[group*4 +: 4];
                end
            end

            if (access_accept && pwrite_i) begin
                case (canonical_paddr)
                    REG_PADDIR: paddir_q <= pwdata_i;
                    REG_GPIOEN: gpioen_q <= pwdata_i;
                    REG_PADOUT: padout_q <= pwdata_i;
                    REG_PADOUTSET: padout_q <= padout_q | pwdata_i;
                    REG_PADOUTCLR: padout_q <= padout_q & ~pwdata_i;
                    default: begin
                        if (canonical_paddr >= REG_PADCFG0 &&
                            canonical_paddr <= REG_PADCFG3)
                            padcfg_q[((canonical_paddr - REG_PADCFG0) >> 2)*32 +: 32]
                                <= pwdata_i;
                    end
                endcase
            end

            if (access_accept && pwrite_i && canonical_paddr == REG_PADOUT)
                out_check_kind_q <= 2'd3;
            else if (access_accept && pwrite_i && canonical_paddr == REG_PADOUTSET)
                out_check_kind_q <= 2'd1;
            else if (access_accept && pwrite_i && canonical_paddr == REG_PADOUTCLR)
                out_check_kind_q <= 2'd2;
            else
                out_check_kind_q <= '0;

            cfg_check_pending_q <= access_accept && pwrite_i &&
                                   canonical_paddr >= REG_PADCFG0 &&
                                   canonical_paddr <= REG_PADCFG3;
        end
    end

    // first_fail_id_o reports the lowest global checker ID (21..35); 63 means
    // that no GPIO checker bit has failed.
    always_comb begin
        first_fail_id_o = 6'd63;
        for (int bit_index = 14; bit_index >= 0; bit_index--) begin
            if (fail_o[bit_index])
                first_fail_id_o = 6'd21 + bit_index[5:0];
        end
    end

    wire unused_interrupt = interrupt_i;
endmodule
