// Boundary checker for the calibrated single-line PULP SPI profile.
//
// Local eval/fail bit 0..13 maps to global SPI property IDs 36..49. Only the
// calibrated pins/protocol properties at local bits 5..10 are implemented and
// enabled by the checker profile; APB/FIFO internal side-effect claims and
// pulse/rearm behavior remain unevaluated.
module soc_pulp_spi_checker (
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
    input  logic         sck_i,
    input  logic         csn0_i,
    input  logic         csn1_i,
    input  logic         csn2_i,
    input  logic         csn3_i,
    input  logic [1:0]   mode_i,
    input  logic         sdo0_i,
    input  logic         sdo1_i,
    input  logic         sdo2_i,
    input  logic         sdo3_i,
    input  logic         sdi0_i,
    input  logic         sdi1_i,
    input  logic         sdi2_i,
    input  logic         sdi3_i,
    output logic [13:0]  eval_o,
    output logic [13:0]  fail_o
);
    localparam logic [11:0] REG_STATUS = 12'h000;
    localparam logic [11:0] REG_SPILEN = 12'h010;
    localparam logic [11:0] REG_TXFIFO = 12'h018;
    localparam logic [11:0] REG_RXFIFO = 12'h020;

    logic [5:0] cmd_len_q;
    logic [5:0] addr_len_q;
    logic [15:0] data_len_q;
    logic [15:0] dummy_rd_q;
    logic [15:0] dummy_wr_q;
    logic [31:0] tx_word_q;
    logic tx_word_valid_q;
    logic transfer_supported_q;
    logic transfer_tx_q;
    logic transfer_rx_q;
    logic frame_active_q;
    logic mode_seen_edge_q;
    logic sck_prev_q;
    logic csn0_prev_q;
    logic [7:0] frame_edge_count_q;
    logic [7:0] frame_rise_count_q;
    logic [7:0] frame_fall_count_q;
    logic [5:0] tx_sample_count_q;
    logic [5:0] rx_sample_count_q;
    logic [31:0] tx_observed_q;
    logic [31:0] rx_observed_q;
    logic [31:0] rx_expected_q;
    logic [5:0] rx_expected_count_q;
    logic rx_expected_valid_q;

    wire access_accept = psel_i && penable_i && pready_i && !pslverr_i;
    wire all_cs_idle = csn0_i && csn1_i && csn2_i && csn3_i;
    wire sck_changed = (sck_i != sck_prev_q);
    wire sck_rising = !sck_prev_q && sck_i;
    wire csn0_start = csn0_prev_q && !csn0_i;
    wire csn0_end = !csn0_prev_q && csn0_i;
    wire [7:0] edge_count_at_close = frame_edge_count_q +
                                     ((sck_changed && csn0_end) ? 8'd1 : 8'd0);
    wire [7:0] rise_count_at_close = frame_rise_count_q +
                                     ((sck_changed && csn0_end && sck_i) ? 8'd1 : 8'd0);
    wire [7:0] fall_count_at_close = frame_fall_count_q +
                                     ((sck_changed && csn0_end && !sck_i) ? 8'd1 : 8'd0);

    // eval_o is a one-cycle observation pulse. fail_o is sticky until reset,
    // so the global checker_fail_o remains suitable for the existing stop path.
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            cmd_len_q <= '0;
            addr_len_q <= '0;
            data_len_q <= '0;
            dummy_rd_q <= '0;
            dummy_wr_q <= '0;
            tx_word_q <= '0;
            tx_word_valid_q <= 1'b0;
            transfer_supported_q <= 1'b0;
            transfer_tx_q <= 1'b0;
            transfer_rx_q <= 1'b0;
            frame_active_q <= 1'b0;
            mode_seen_edge_q <= 1'b0;
            sck_prev_q <= 1'b0;
            csn0_prev_q <= 1'b1;
            frame_edge_count_q <= '0;
            frame_rise_count_q <= '0;
            frame_fall_count_q <= '0;
            tx_sample_count_q <= '0;
            rx_sample_count_q <= '0;
            tx_observed_q <= '0;
            rx_observed_q <= '0;
            rx_expected_q <= '0;
            rx_expected_count_q <= '0;
            rx_expected_valid_q <= 1'b0;
            eval_o <= '0;
            fail_o <= '0;
        end else begin
            eval_o <= '0;
            sck_prev_q <= sck_i;
            csn0_prev_q <= csn0_i;

            // Check idle only while an APB sequence has established this
            // checker's supported 32-bit data-only phase. Other PULP modes
            // and transfers are outside this calibrated checker contract.
            if ((transfer_supported_q || frame_active_q) && all_cs_idle) begin
                eval_o[6] <= 1'b1;
                if (sck_i !== 1'b0) fail_o[6] <= 1'b1;
            end

            // The external setup selects CS0 only; other active chip selects
            // and clock edges outside that window are protocol violations.
            // Gate these checks to transactions this checker can identify.
            if (transfer_supported_q || frame_active_q) begin
                if (!all_cs_idle) begin
                    eval_o[5] <= 1'b1;
                    if ((csn0_i !== 1'b0) || (csn1_i !== 1'b1) ||
                        (csn2_i !== 1'b1) || (csn3_i !== 1'b1))
                        fail_o[5] <= 1'b1;
                end
                if (sck_changed && csn0_i !== 1'b0 && !csn0_end) begin
                    eval_o[5] <= 1'b1;
                    fail_o[5] <= 1'b1;
                end
            end

            // Single-line mode uses SDO0/SDI1. PULP can expose its line-width
            // setup value briefly after CS assertion; mode must be 00 by the
            // first SCK transition and remain there for the frame.
            if ((transfer_supported_q || frame_active_q) && !csn0_i) begin
                eval_o[10] <= 1'b1;
                if (sck_changed) mode_seen_edge_q <= 1'b1;
                if (mode_seen_edge_q || sck_changed) begin
                    if (mode_i !== 2'b00) fail_o[10] <= 1'b1;
                end else if ((mode_i !== 2'b00) && (mode_i !== 2'b10)) begin
                    fail_o[10] <= 1'b1;
                end
            end else if (csn0_end) begin
                mode_seen_edge_q <= 1'b0;
            end

            // Record only the specific 32-bit data-only transaction supported
            // by this checker. Other commands/lengths stay not_assessed.
            if (access_accept && pwrite_i) begin
                case (paddr_i[5:2])
                    (REG_SPILEN >> 2): begin
                        cmd_len_q <= pwdata_i[5:0];
                        addr_len_q <= pwdata_i[13:8];
                        data_len_q <= {pwdata_i[31:24], pwdata_i[23:16]};
                    end
                    (REG_TXFIFO >> 2): begin
                        tx_word_q <= pwdata_i;
                        tx_word_valid_q <= 1'b1;
                    end
                    (REG_STATUS >> 2): begin
                        transfer_supported_q <=
                            ((pwdata_i == 32'h0000_0101) ||
                             (pwdata_i == 32'h0000_0102)) &&
                            (cmd_len_q == 6'd0) &&
                            (addr_len_q == 6'd0) &&
                            (data_len_q == 16'd32) &&
                            (dummy_rd_q == 16'd0) &&
                            (dummy_wr_q == 16'd0) &&
                            ((pwdata_i == 32'h0000_0101) || tx_word_valid_q);
                        transfer_rx_q <= (pwdata_i == 32'h0000_0101);
                        transfer_tx_q <= (pwdata_i == 32'h0000_0102);
                        rx_expected_valid_q <= 1'b0;
                    end
                    4'h5: begin
                        dummy_rd_q <= pwdata_i[15:0];
                        dummy_wr_q <= pwdata_i[31:16];
                    end
                    default: begin end
                endcase
            end

            if (csn0_start && transfer_supported_q) begin
                frame_active_q <= 1'b1;
                frame_edge_count_q <= '0;
                frame_rise_count_q <= '0;
                frame_fall_count_q <= '0;
                tx_sample_count_q <= '0;
                rx_sample_count_q <= '0;
                tx_observed_q <= '0;
                rx_observed_q <= '0;
                mode_seen_edge_q <= 1'b0;
            end else if (frame_active_q && !csn0_i) begin
                if (sck_changed) begin
                    frame_edge_count_q <= frame_edge_count_q + 1'b1;
                    if (sck_rising)
                        frame_rise_count_q <= frame_rise_count_q + 1'b1;
                    else
                        frame_fall_count_q <= frame_fall_count_q + 1'b1;
                end
                if (sck_rising && transfer_supported_q) begin
                    if (transfer_tx_q) begin
                        tx_observed_q <= {tx_observed_q[30:0], sdo0_i};
                        tx_sample_count_q <= tx_sample_count_q + 1'b1;
                    end
                    if (transfer_rx_q && rx_sample_count_q < 6'd32) begin
                        rx_observed_q <= {rx_observed_q[30:0], sdi1_i};
                        rx_sample_count_q <= rx_sample_count_q + 1'b1;
                    end
                end
            end

            if (csn0_end) begin
                frame_active_q <= 1'b0;
                if (transfer_supported_q) begin
                    // Pinned APB PULP TX produces the calibrated 64-edge
                    // frame. Its RX controller has an additional public SCK
                    // transition around completion, so this exact edge-count
                    // property is not assessed for RX-only phases.
                    if (transfer_tx_q) begin
                        eval_o[7] <= 1'b1;
                        if (edge_count_at_close != 8'd64 ||
                            rise_count_at_close != 8'd32 ||
                            fall_count_at_close != 8'd32)
                            fail_o[7] <= 1'b1;
                    end
                    if (transfer_tx_q && edge_count_at_close == 8'd64 &&
                        tx_sample_count_q == 6'd32 && tx_word_valid_q) begin
                        eval_o[8] <= 1'b1;
                        if (tx_observed_q !== tx_word_q) fail_o[8] <= 1'b1;
                    end
                    if (transfer_rx_q && rx_sample_count_q == 6'd32) begin
                        rx_expected_q <= rx_observed_q;
                        rx_expected_count_q <= rx_sample_count_q;
                        rx_expected_valid_q <= 1'b1;
                    end
                end
                transfer_supported_q <= 1'b0;
                transfer_tx_q <= 1'b0;
                transfer_rx_q <= 1'b0;
                tx_word_valid_q <= 1'b0;
                mode_seen_edge_q <= 1'b0;
            end

            // RXFIFO is checked against the independent public SDI1 samples
            // collected on mode-0 rising edges, not a DUT-internal counter.
            if (access_accept && !pwrite_i &&
                paddr_i[5:2] == (REG_RXFIFO >> 2) && rx_expected_valid_q) begin
                eval_o[9] <= 1'b1;
                if ((rx_expected_count_q != 6'd32) ||
                    (prdata_i !== rx_expected_q))
                    fail_o[9] <= 1'b1;
                rx_expected_valid_q <= 1'b0;
            end
        end
    end
endmodule
