// Self-checking bench for the LATCH_MASK behaviour of soc_irq_controller.
//
// The bench runs one controller with two sources and a chosen LATCH_MASK, drives
// bounded pulses, and prints one RESULT line.  It is deliberately separate from
// soc_irq_controller_tb.sv: that bench pins the level-only behaviour of the
// original parameterization and must keep passing unchanged, while this one is
// about the difference the mask makes.
//
// Scenarios (NUM_SOURCES = 2):
//   S1  a one-cycle pulse on source 1 sets pending and pending STAYS set after
//       the pulse has ended -- the whole point of the latch;
//   S2  CLAIM returns source id 1 and clears the latched pending bit;
//   S3  COMPLETE retires it and the long-gone pulse does not re-pend;
//   S4  a second pulse re-pends, and a third one after that;
//   S5  an unlatched source in the same controller still follows its level:
//       pending rises with it and falls when it falls;
//   S6  enable masking still gates notification and claiming for a latched
//       source, and the latched pending bit is not lost while masked;
//   S7  reset clears everything, including a latched pending bit.
//
// LATCH_MASK is a parameter, so the same bench proves the default (0) drops the
// pulse -- the negative control that makes S1 meaningful.
`timescale 1ns/1ps

module soc_irq_controller_latch_tb;
  parameter integer LATCH_MASK = 2'b01;

  localparam integer NUM_SOURCES = 2;
  localparam integer AW = 8;
  // 0x00 CLAIM, 0x04 COMPLETE, 0x08 IN_SERVICE, 0x0c SOURCE_COUNT,
  // 0x20 PENDING0, 0x24 ENABLE0.
  localparam [AW-1:0] CLAIM_ADDR = 8'h00;
  localparam [AW-1:0] COMPLETE_ADDR = 8'h04;
  localparam [AW-1:0] IN_SERVICE_ADDR = 8'h08;
  localparam [AW-1:0] SOURCE_COUNT_ADDR = 8'h0c;
  localparam [AW-1:0] PENDING0_ADDR = 8'h20;
  localparam [AW-1:0] ENABLE0_ADDR = 8'h24;

  reg  clk_i = 0;
  reg  rst_ni = 0;
  reg  [NUM_SOURCES-1:0] source_i = 0;

  logic req_valid_i = 0;
  wire  req_ready_o;
  logic req_write_i = 0;
  logic [AW-1:0] req_addr_i = 0;
  logic [31:0] req_wdata_i = 0;
  logic [3:0] req_be_i = 4'hf;
  wire  rsp_valid_o;
  logic rsp_ready_i = 1;
  wire  [31:0] rsp_rdata_o;
  wire  rsp_error_o;

  integer failures = 0;
  logic [31:0] value;
  logic error;

  soc_irq_controller #(
      .NUM_SOURCES(NUM_SOURCES), .ADDRESS_WIDTH(AW), .LATCH_MASK(LATCH_MASK[1:0])
  ) dut (
      .clk_i(clk_i), .rst_ni(rst_ni), .source_i(source_i), .irq_o(),
      .req_valid_i(req_valid_i), .req_ready_o(req_ready_o), .req_write_i(req_write_i),
      .req_addr_i(req_addr_i), .req_wdata_i(req_wdata_i), .req_be_i(req_be_i),
      .rsp_valid_o(rsp_valid_o), .rsp_ready_i(rsp_ready_i), .rsp_rdata_o(rsp_rdata_o),
      .rsp_error_o(rsp_error_o)
  );

  always #5 clk_i = ~clk_i;

  task check(input condition, input [1023:0] label);
    begin
      if (!condition) begin
        failures = failures + 1;
        $display("CHECK-FAIL: %0s (source=%b value=0x%08x error=%b)",
                 label, source_i, value, error);
      end
    end
  endtask

  // One clock, with the request held stable across it.
  task tick;
    begin
      @(posedge clk_i);
      #1;
    end
  endtask

  // One accepted transfer.  Returns the read data in `value` and the response
  // error in `error`; every transfer here is answered on the next clock.
  task xfer(input write, input [AW-1:0] address, input [31:0] wdata);
    begin
      @(negedge clk_i);
      req_valid_i = 1'b1;
      req_write_i = write;
      req_addr_i = address;
      req_wdata_i = wdata;
      tick();
      req_valid_i = 1'b0;
      tick();
      value = rsp_rdata_o;
      error = rsp_error_o;
    end
  endtask

  task read_word(input [AW-1:0] address);
    begin
      xfer(1'b0, address, 32'd0);
    end
  endtask

  task write_word(input [AW-1:0] address, input [31:0] wdata);
    begin
      xfer(1'b1, address, wdata);
    end
  endtask

  // Bitmap bit k is source id k and bit 0 is the reserved id 0, so a source's
  // own bit is exactly its source id (soc_irq_controller.sv: bitmap_id =
  // 32*word + bit, and pending_q[bitmap_id-1] drives it).
  task expect_pending(input integer source_id, input expected, input [1023:0] label);
    begin
      read_word(PENDING0_ADDR);
      check(!error, label);
      check(((value >> source_id) & 32'd1) == expected, label);
    end
  endtask

  // One pulse of exactly `cycles` clocks on the given source bits, then back to
  // zero for `gap` clocks.  Pulses are driven off the falling edge so every
  // asserted clock is a full cycle as seen by the DUT.
  task pulse(input [NUM_SOURCES-1:0] bits, input integer cycles, input integer gap);
    integer i;
    begin
      @(negedge clk_i);
      source_i = bits;
      for (i = 0; i < cycles; i = i + 1)
        tick();
      @(negedge clk_i);
      source_i = {NUM_SOURCES{1'b0}};
      for (i = 0; i < gap; i = i + 1)
        tick();
    end
  endtask

  initial begin
    if (NUM_SOURCES != 2) begin
      $display("RESULT: FAIL bench-expects-two-sources");
      $finish;
    end

    // Reset, then enable both sources.
    rst_ni = 1'b0;
    tick();
    tick();
    rst_ni = 1'b1;
    tick();
    // Bitmap bit s+1 of ENABLE0 enables source id s+1, and bit 0 is the
    // reserved id 0, so enabling both sources is 3'b110.
    write_word(ENABLE0_ADDR, 32'b110);
    check(!error, "S0 both sources can be enabled");

    // --- S1: a one-cycle pulse is captured and held ------------------------
    pulse(2'b01, 1, 16);
    expect_pending(2, 1'b0, "S1 the other source is not pending");
    if (LATCH_MASK[0] == 1'b1)
      expect_pending(1, 1'b1, "S1 a one-cycle pulse is still pending 16 clocks later");

    // --- S2: CLAIM returns the id and clears the latched pending -----------
    read_word(CLAIM_ADDR);
    check(!error, "S2 CLAIM is answered without error");
    check(value == 32'd1 || LATCH_MASK[0] == 1'b0, "S2 CLAIM returns the latched id");
    if (LATCH_MASK[0] == 1'b1) begin
      check(value == 32'd1, "S2 CLAIM returns source id 1");
      expect_pending(1, 1'b0, "S2 CLAIM clears the latched pending bit");
      read_word(IN_SERVICE_ADDR);
      check(value == 32'd1, "S2 IN_SERVICE reports the claimed id");
      write_word(COMPLETE_ADDR, 32'd1);
      check(!error, "S3 COMPLETE with the in-service id succeeds");
      read_word(IN_SERVICE_ADDR);
      check(value == 32'd0, "S3 COMPLETE clears in-service");

      // --- S3: the long-gone pulse does not re-pend ----------------------
      for (integer i = 0; i < 16; i = i + 1)
        tick();
      expect_pending(1, 1'b0, "S3 the finished pulse does not re-pend after COMPLETE");

      // --- S4: a second pulse re-pends -----------------------------------
      pulse(2'b01, 1, 4);
      expect_pending(1, 1'b1, "S4 a second pulse pends again");
      read_word(CLAIM_ADDR);
      check(value == 32'd1, "S4 the second pulse is claimable");
      write_word(COMPLETE_ADDR, 32'd1);
      check(!error, "S4 the second COMPLETE succeeds");
      pulse(2'b01, 3, 4);
      expect_pending(1, 1'b1, "S4 a wider pulse also pends");
      read_word(CLAIM_ADDR);
      check(value == 32'd1, "S4 the wider pulse is claimable");
      write_word(COMPLETE_ADDR, 32'd1);
      check(!error, "S4 the third COMPLETE succeeds");
    end else begin
      // The negative control: with no latch the same pulse is gone by now.
      check(value == 32'd0, "S1-negative an unlatched pulse is not claimable later");
      expect_pending(1, 1'b0, "S1-negative an unlatched pulse is not pending later");
    end

    // --- S5: source 2 follows its own mask bit -----------------------------
    write_word(ENABLE0_ADDR, 32'b110);
    check(!error, "S5 both sources can be enabled again");
    @(negedge clk_i);
    source_i = 2'b10;
    tick();
    tick();
    expect_pending(2, 1'b1, "S5 an asserted source pends");
    @(negedge clk_i);
    source_i = {NUM_SOURCES{1'b0}};
    tick();
    tick();
    if (LATCH_MASK[1] == 1'b0)
      expect_pending(2, 1'b0, "S5 an unlatched source clears when its input falls");
    else
      expect_pending(2, 1'b1, "S5 a latched source survives its input falling");

    // --- S6: masking a latched source keeps the event but blocks the claim --
    if (LATCH_MASK[0] == 1'b1) begin
      write_word(ENABLE0_ADDR, 32'b00);
      check(!error, "S6 masking succeeds");
      pulse(2'b01, 1, 8);
      expect_pending(1, 1'b1, "S6 a masked latched source still records the event");
      read_word(CLAIM_ADDR);
      check(value == 32'd0, "S6 a masked source cannot be claimed");
      expect_pending(1, 1'b1, "S6 a failed CLAIM does not clear the latched event");
      write_word(ENABLE0_ADDR, 32'b010);
      check(!error, "S6 unmasking succeeds");
      read_word(CLAIM_ADDR);
      check(value == 32'd1, "S6 unmasking makes the held event claimable");
      write_word(COMPLETE_ADDR, 32'd1);
      check(!error, "S6 COMPLETE after unmasking succeeds");
    end

    // --- S7: reset clears a latched pending bit ----------------------------
    if (LATCH_MASK[0] == 1'b1) begin
      pulse(2'b01, 1, 2);
      expect_pending(1, 1'b1, "S7 the latched event is pending before reset");
      rst_ni = 1'b0;
      tick();
      tick();
      rst_ni = 1'b1;
      tick();
      expect_pending(1, 1'b0, "S7 reset clears the latched pending bit");
    end

    if (failures == 0)
      $display("RESULT: PASS");
    else
      $display("RESULT: FAIL failures=%0d", failures);
    $finish;
  end

  initial begin
    #400000;
    $display("RESULT: FAIL bench-timeout");
    $finish;
  end
endmodule
