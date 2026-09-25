// PULP apb_spi_master's role-compatible, single-line mode-0 slave peer.
//
// The PULP boundary has four CS outputs, a two-bit line-width mode, four MOSI
// lanes, and four MISO lanes.  This peer binds every role, responds only while
// CS0 is selected in mode 2'b00, drives the 32-bit arm word MSB first on the
// mode-0 trailing edge, and ties the inactive MISO lanes low.  It observes only
// public pin roles; it does not inspect PULP internal state.
//
// One arm word may wait for the next CS0 selection.  A selection without an
// armed word shifts deterministic zeros.  An arm request while selected or
// while a word is pending is dropped and counted.  A mode error is sticky
// until reset, and the counter increments once per selected interval that
// contains a non-2'b00 mode value.
module soc_pulp_spi_peer (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic [31:0] arm_word_i,
    input  logic        arm_valid_i,

    input  logic        sck_i,
    input  logic        csn0_i,
    input  logic        csn1_i,
    input  logic        csn2_i,
    input  logic        csn3_i,
    input  logic [1:0]  mode_i,
    input  logic        sdo0_i,
    input  logic        sdo1_i,
    input  logic        sdo2_i,
    input  logic        sdo3_i,

    output logic        sdi0_o,
    output logic        sdi1_o,
    output logic        sdi2_o,
    output logic        sdi3_o,

    output logic        armed_o,
    output logic [31:0] arm_accept_count_o,
    output logic [31:0] arm_drop_count_o,
    output logic        selected_o,
    output logic [31:0] selection_count_o,
    output logic [31:0] clock_count_o,
    output logic [31:0] shift_count_o,
    output logic        mode_error_o,
    output logic [31:0] mode_error_count_o
);
  logic        selected_prev_q;
  logic        sck_q;
  logic        armed_q;
  logic [31:0] armed_word_q;
  logic [31:0] tx_shift_q;
  logic        mode_error_seen_q;
  logic        sck_change_w;
  logic        sck_fall_w;
  logic        mode0_w;

  assign selected_o = !csn0_i;
  assign sck_change_w = sck_i ^ sck_q;
  assign sck_fall_w = sck_q && !sck_i;
  assign mode0_w = (mode_i == 2'b00);

  assign armed_o = armed_q;
  assign sdi0_o = 1'b0;
  assign sdi1_o = (rst_ni && selected_o && mode0_w) ? tx_shift_q[31] : 1'b0;
  assign sdi2_o = 1'b0;
  assign sdi3_o = 1'b0;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      selected_prev_q <= 1'b0;
      sck_q <= 1'b0;
      armed_q <= 1'b0;
      armed_word_q <= 32'b0;
      tx_shift_q <= 32'b0;
      mode_error_seen_q <= 1'b0;
      arm_accept_count_o <= 32'b0;
      arm_drop_count_o <= 32'b0;
      selection_count_o <= 32'b0;
      clock_count_o <= 32'b0;
      shift_count_o <= 32'b0;
      mode_error_o <= 1'b0;
      mode_error_count_o <= 32'b0;
    end else begin
      selected_prev_q <= selected_o;
      sck_q <= sck_i;

      if (!selected_prev_q && selected_o) begin
        selection_count_o <= selection_count_o + 32'd1;
        tx_shift_q <= armed_q ? armed_word_q : 32'b0;
        armed_q <= 1'b0;
        mode_error_seen_q <= 1'b0;
      end

      if (selected_prev_q && !selected_o)
        mode_error_seen_q <= 1'b0;

      if (sck_change_w && selected_o)
        clock_count_o <= clock_count_o + 32'd1;

      // Mode 0 samples MISO on rising SCK and advances to the next bit on the
      // falling edge.  The leading bit is already visible after CS0 assertion.
      if (sck_fall_w && selected_o && mode0_w) begin
        tx_shift_q <= {tx_shift_q[30:0], 1'b0};
        shift_count_o <= shift_count_o + 32'd1;
      end

      if (selected_o && !mode0_w && !mode_error_seen_q) begin
        mode_error_o <= 1'b1;
        mode_error_count_o <= mode_error_count_o + 32'd1;
        mode_error_seen_q <= 1'b1;
      end

      if (arm_valid_i) begin
        if (!selected_o && !armed_q) begin
          armed_q <= 1'b1;
          armed_word_q <= arm_word_i;
          arm_accept_count_o <= arm_accept_count_o + 32'd1;
        end else begin
          arm_drop_count_o <= arm_drop_count_o + 32'd1;
        end
      end
    end
  end
endmodule
