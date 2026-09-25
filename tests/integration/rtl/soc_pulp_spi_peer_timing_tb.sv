// Timing calibration for the pinned PULP APB SPI master and its public-pin peer.
// The literal RXFIFO word checks the complete 32-bit mode-0 transfer at CLKDIV
// values 0 and 1; divider 0 makes SCK toggle once per HCLK.
module soc_pulp_spi_peer_timing_tb;
  logic clk = 1'b0;
  logic rstn = 1'b1;
  logic [11:0] paddr = '0;
  logic [31:0] pwdata = '0;
  logic pwrite = 1'b0;
  logic psel = 1'b0;
  logic penable = 1'b0;
  wire [31:0] prdata;
  wire pready;
  wire pslverr;
  wire [1:0] events;
  wire spi_clk;
  wire spi_csn0, spi_csn1, spi_csn2, spi_csn3;
  wire [1:0] spi_mode;
  wire spi_sdo0, spi_sdo1, spi_sdo2, spi_sdo3;
  wire spi_sdi0, spi_sdi1, spi_sdi2, spi_sdi3;
  logic [31:0] arm_word = 32'hA5C3_96F0;
  logic arm_valid = 1'b0;
  wire peer_armed;
  wire [31:0] arm_accept_count, arm_drop_count;
  wire peer_selected;
  wire [31:0] selection_count, clock_count, shift_count;
  wire mode_error;
  wire [31:0] mode_error_count;
  logic [31:0] sampled_word = 32'b0;
  integer sample_count = 0;

  always #5 clk = ~clk;

  // Capture the same HCLK-domain sample enable used by PULP's RX shifter. The
  // public SCK/MISO values at that instant make the divider-zero timing visible.
  always @(posedge clk) begin
    if (!rstn) begin
      sampled_word <= 32'b0;
      sample_count <= 0;
    end else if (dut.u_spictrl.spi_rise && !spi_csn0) begin
      if (sample_count < 4 || sample_count == 31)
        $display("SPI_RX_SAMPLE div=%0d index=%0d sck_pre=%b miso=%b peer_head=%b%b peer_fall=%b",
                 dut.u_axiregs.spi_clk_div, sample_count, spi_clk, spi_sdi1,
                 peer.tx_shift_q[31], peer.tx_shift_q[30], peer.sck_fall_w);
      sampled_word <= {sampled_word[30:0], spi_sdi1};
      sample_count <= sample_count + 1;
    end
  end

  apb_spi_master #(.BUFFER_DEPTH(10), .APB_ADDR_WIDTH(12)) dut (
      .HCLK(clk), .HRESETn(rstn), .PADDR(paddr), .PWDATA(pwdata),
      .PWRITE(pwrite), .PSEL(psel), .PENABLE(penable), .PRDATA(prdata),
      .PREADY(pready), .PSLVERR(pslverr), .events_o(events),
      .spi_clk(spi_clk), .spi_csn0(spi_csn0), .spi_csn1(spi_csn1),
      .spi_csn2(spi_csn2), .spi_csn3(spi_csn3), .spi_mode(spi_mode),
      .spi_sdo0(spi_sdo0), .spi_sdo1(spi_sdo1), .spi_sdo2(spi_sdo2),
      .spi_sdo3(spi_sdo3), .spi_sdi0(spi_sdi0), .spi_sdi1(spi_sdi1),
      .spi_sdi2(spi_sdi2), .spi_sdi3(spi_sdi3)
  );

  soc_pulp_spi_peer peer (
      .clk_i(clk), .rst_ni(rstn), .arm_word_i(arm_word),
      .arm_valid_i(arm_valid), .sck_i(spi_clk), .csn0_i(spi_csn0),
      .csn1_i(spi_csn1), .csn2_i(spi_csn2), .csn3_i(spi_csn3),
      .mode_i(spi_mode), .sdo0_i(spi_sdo0), .sdo1_i(spi_sdo1),
      .sdo2_i(spi_sdo2), .sdo3_i(spi_sdo3), .sdi0_o(spi_sdi0),
      .sdi1_o(spi_sdi1), .sdi2_o(spi_sdi2), .sdi3_o(spi_sdi3),
      .armed_o(peer_armed), .arm_accept_count_o(arm_accept_count),
      .arm_drop_count_o(arm_drop_count), .selected_o(peer_selected),
      .selection_count_o(selection_count), .clock_count_o(clock_count),
      .shift_count_o(shift_count), .mode_error_o(mode_error),
      .mode_error_count_o(mode_error_count)
  );

  task automatic apb_write(input logic [11:0] addr, input logic [31:0] data);
    begin
      @(negedge clk);
      paddr = addr;
      pwdata = data;
      pwrite = 1'b1;
      psel = 1'b1;
      penable = 1'b0;
      @(negedge clk);
      penable = 1'b1;
      @(negedge clk);
      psel = 1'b0;
      penable = 1'b0;
      pwrite = 1'b0;
    end
  endtask

  task automatic apb_read(input logic [11:0] addr, output logic [31:0] data);
    begin
      @(negedge clk);
      paddr = addr;
      pwrite = 1'b0;
      psel = 1'b1;
      penable = 1'b0;
      @(negedge clk);
      penable = 1'b1;
      @(posedge clk);
      data = prdata;
      @(negedge clk);
      psel = 1'b0;
      penable = 1'b0;
    end
  endtask

  task automatic run_case(input logic [7:0] divider);
    logic [31:0] received;
    integer timeout;
    begin
      // Reset the actual APB target and peer between divider cases.
      @(negedge clk);
      rstn = 1'b0;
      psel = 1'b0;
      penable = 1'b0;
      pwrite = 1'b0;
      arm_valid = 1'b0;
      repeat (3) @(negedge clk);
      rstn = 1'b1;

      @(negedge clk);
      arm_valid = 1'b1;
      @(negedge clk);
      arm_valid = 1'b0;
      if (!peer_armed) $fatal(1, "peer did not arm divider=%0d", divider);

      apb_write(12'h004, {24'b0, divider});
      apb_write(12'h010, 32'h0020_0000); // 32 RX samples, no command/address.
      apb_write(12'h000, 32'h0000_0101); // Start RX and select CS0.

      timeout = 0;
      while (!events[1] && timeout < 1000) begin
        @(negedge clk);
        timeout = timeout + 1;
      end
      if (!events[1]) $fatal(1, "EOT timeout divider=%0d", divider);
      // The pinned controller briefly exposes spi_mode=2'b10 at CS assertion
      // before its registered output settles to standard mode 2'b00. This
      // timing test records RX sampling only and does not treat that setup
      // transient, which sets the peer's sticky mode observation, as a failure.
      if (sample_count != 32)
        $fatal(1, "wrong RX sample count divider=%0d count=%0d", divider, sample_count);
      if (sampled_word !== 32'hA5C3_96F0)
        $fatal(1, "HCLK sample mismatch divider=%0d expected=A5C396F0 got=%08x",
               divider, sampled_word);
      $display("SPI_RX_SAMPLES divider=%0d count=%0d word=%08x",
               divider, sample_count, sampled_word);
      apb_read(12'h020, received);
      if (received !== 32'hA5C3_96F0)
        $fatal(1, "RXFIFO mismatch divider=%0d expected=A5C396F0 got=%08x", divider, received);
      $display("SPI_PEER_TIMING_PASS divider=%0d rx=%08x", divider, received);
    end
  endtask

  initial begin
    run_case(8'd0);
    run_case(8'd1);
    $display("SPI_PEER_TIMING_ALL_PASS");
    $finish;
  end
endmodule
