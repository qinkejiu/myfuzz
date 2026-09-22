// Self-checking behavioural testbench for soc_irq_controller (Icarus Verilog).
//
//   iverilog -g2012 -s soc_irq_controller_tb -o tb.vvp \
//       src/myfuzz/protocols/rtl/soc_irq_controller.sv \
//       tests/fixtures/rtl/soc_irq_controller_tb.sv
//   vvp tb.vvp
//
// The bench prints exactly one result line, "RESULT: PASS" or
// "RESULT: FAIL: <reason>", and finishes with $finish. Parameter overrides
// select the configuration under test:
//
//   -P soc_irq_controller_tb.NUM_SOURCES=40 -P soc_irq_controller_tb.ADDRESS_WIDTH=12
//
// The complete register suite needs the PENDING/ENABLE bitmap window to be
// addressable. With NUM_SOURCES=1 and ADDRESS_WIDTH=5 the deepest decodable
// word is word 7 (0x1c), so ENABLE[0] at 0x24 cannot be reached at all: source
// enable is then impossible and the bench says so on a NOTE line and runs the
// header-only checks instead of pretending to cover the claim path.
module soc_irq_controller_tb #(
    parameter integer NUM_SOURCES = 40,
    parameter integer ADDRESS_WIDTH = 12,
    // Compile-time self-test hook used by the Python harness to prove that a
    // deliberately broken expectation is really detected. It is 0 in every real
    // run.
    parameter integer NEGATIVE_CONTROL = 0
) ();
  localparam integer B = (NUM_SOURCES + 1 + 31) / 32;
  localparam integer ID_WIDTH = (NUM_SOURCES + 1 <= 1) ? 1 : $clog2(NUM_SOURCES + 1);
  localparam integer REG_WORDS = 8 + 2*B;
  localparam integer MAX_WORD = (1 << (ADDRESS_WIDTH - 2)) - 1;
  // The full suite needs the last ENABLE word inside the decodable window and at
  // least two sources to exercise priority and in-service exclusion.
  localparam integer BITMAP_REACHABLE = ((8 + 2*B - 1) <= MAX_WORD);
  localparam integer FULL_SUITE = (BITMAP_REACHABLE && (NUM_SOURCES >= 2));
  // Highest word index this window can decode. It is always either above the
  // register window or an in-window reserved header word, so it must error.
  localparam integer OOB_WORD = (REG_WORDS <= MAX_WORD) ? REG_WORDS : MAX_WORD;

  localparam [ADDRESS_WIDTH-1:0] CLAIM_ADDR = 0;
  localparam [ADDRESS_WIDTH-1:0] COMPLETE_ADDR = 4;
  localparam [ADDRESS_WIDTH-1:0] IN_SERVICE_ADDR = 8;
  localparam [ADDRESS_WIDTH-1:0] SOURCE_COUNT_ADDR = 12;
  localparam [ADDRESS_WIDTH-1:0] RESERVED_ADDR = 16;   // header word 4
  localparam [ADDRESS_WIDTH-1:0] OOB_ADDR = OOB_WORD * 4;
  localparam [31:0] ENABLE_LOW_IDS = 32'h0000_0006;    // source IDs 1 and 2

  logic clk_i = 1'b0;
  logic rst_ni = 1'b0;
  logic [NUM_SOURCES-1:0] source_i = {NUM_SOURCES{1'b0}};
  logic irq_o;
  logic req_valid_i = 1'b0;
  logic req_ready_o;
  logic req_write_i = 1'b0;
  logic [ADDRESS_WIDTH-1:0] req_addr_i = {ADDRESS_WIDTH{1'b0}};
  logic [31:0] req_wdata_i = 32'd0;
  logic [3:0] req_be_i = 4'b1111;
  logic rsp_valid_o;
  logic rsp_ready_i = 1'b0;
  logic [31:0] rsp_rdata_o;
  logic rsp_error_o;

  logic [31:0] rd_value;
  logic [31:0] wr_value;
  logic [31:0] scratch_value;
  bit rd_error;
  bit wr_error;
  bit scratch_error;

  soc_irq_controller #(
      .NUM_SOURCES(NUM_SOURCES),
      .ADDRESS_WIDTH(ADDRESS_WIDTH)
  ) dut (
      .clk_i(clk_i),
      .rst_ni(rst_ni),
      .source_i(source_i),
      .irq_o(irq_o),
      .req_valid_i(req_valid_i),
      .req_ready_o(req_ready_o),
      .req_write_i(req_write_i),
      .req_addr_i(req_addr_i),
      .req_wdata_i(req_wdata_i),
      .req_be_i(req_be_i),
      .rsp_valid_o(rsp_valid_o),
      .rsp_ready_i(rsp_ready_i),
      .rsp_rdata_o(rsp_rdata_o),
      .rsp_error_o(rsp_error_o)
  );

  always #5 clk_i = ~clk_i;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  task automatic tick;
    begin
      @(posedge clk_i);
      #1;
    end
  endtask

  task automatic fail(input [8*200-1:0] message);
    begin
      $display("RESULT: FAIL: %0s", message);
      $fatal(1, "soc_irq_controller self-check failed");
    end
  endtask

  task automatic check(input bit condition, input [8*200-1:0] message);
    begin
      if (!condition)
        fail(message);
    end
  endtask

  function automatic [31:0] id_bit_mask(input integer source_id);
    begin
      id_bit_mask = 32'd0;
      id_bit_mask[source_id % 32] = 1'b1;
    end
  endfunction

  // Bitmap bits that a full-ones write to word j may legally set: bit 0 of word 0
  // is the reserved ID 0 and every bit above NUM_SOURCES is unimplemented.
  function automatic [31:0] valid_bitmap_mask(input integer j);
    integer bit_index;
    begin
      valid_bitmap_mask = 32'd0;
      for (bit_index = 0; bit_index < 32; bit_index = bit_index + 1)
        if (((32*j + bit_index) >= 1) && ((32*j + bit_index) <= NUM_SOURCES))
          valid_bitmap_mask[bit_index] = 1'b1;
    end
  endfunction

  function automatic [ADDRESS_WIDTH-1:0] pending_addr(input integer j);
    begin
      pending_addr = 32 + 4*j;
    end
  endfunction

  function automatic [ADDRESS_WIDTH-1:0] enable_addr(input integer j);
    begin
      enable_addr = 32 + 4*B + 4*j;
    end
  endfunction

  // Wait until the DUT can accept a request, then leave the bench sitting on the
  // negedge that precedes the accepting edge.
  task automatic idle_wait;
    begin
      @(negedge clk_i);
      while (!req_ready_o)
        @(negedge clk_i);
    end
  endtask

  task automatic req_drive(input bit write, input [ADDRESS_WIDTH-1:0] addr, input [31:0] wdata, input [3:0] be);
    begin
      req_valid_i = 1'b1;
      req_write_i = write;
      req_addr_i = addr;
      req_wdata_i = wdata;
      req_be_i = be;
    end
  endtask

  // One complete request/response with the response accepted immediately.
  task automatic xfer(input bit write, input [ADDRESS_WIDTH-1:0] addr, input [31:0] wdata, input [3:0] be,
                      output [31:0] rdata, output bit rsp_err);
    begin
      rsp_ready_i = 1'b1;
      idle_wait();
      req_drive(write, addr, wdata, be);
      tick();
      check(rsp_valid_o, "response must be registered by the accepting edge");
      rdata = rsp_rdata_o;
      rsp_err = rsp_error_o;
      req_valid_i = 1'b0;
      tick();
    end
  endtask

  task automatic read_word(input [ADDRESS_WIDTH-1:0] addr, output [31:0] value, output bit rsp_err);
    begin
      xfer(1'b0, addr, 32'd0, 4'b1111, value, rsp_err);
    end
  endtask

  task automatic rd(input [ADDRESS_WIDTH-1:0] addr, input [3:0] be);
    begin
      xfer(1'b0, addr, 32'd0, be, rd_value, rd_error);
    end
  endtask

  task automatic wr(input [ADDRESS_WIDTH-1:0] addr, input [31:0] wdata);
    begin
      xfer(1'b1, addr, wdata, 4'b1111, wr_value, wr_error);
    end
  endtask

  task automatic expect_word(input [ADDRESS_WIDTH-1:0] addr, input [31:0] expected, input [8*200-1:0] message);
    begin
      read_word(addr, scratch_value, scratch_error);
      check(!scratch_error, "read must not report an error");
      check(scratch_value == expected, message);
    end
  endtask

  task automatic expect_pending_bit(input integer source_id, input bit expected, input [8*200-1:0] message);
    begin
      read_word(pending_addr(source_id / 32), scratch_value, scratch_error);
      check(!scratch_error, "PENDING read must not report an error");
      check(scratch_value[source_id % 32] == expected, message);
    end
  endtask

  // Write a word and check irq_o on the accepting edge itself.
  task automatic wr_watch_irq(input [ADDRESS_WIDTH-1:0] addr, input [31:0] wdata, input bit expect_irq,
                              input [8*200-1:0] message);
    begin
      rsp_ready_i = 1'b1;
      idle_wait();
      req_drive(1'b1, addr, wdata, 4'b1111);
      tick();
      check(irq_o == expect_irq, message);
      check(rsp_valid_o && !rsp_error_o, "the watched write must succeed");
      req_valid_i = 1'b0;
      tick();
    end
  endtask

  task automatic dut_reset;
    begin
      rst_ni = 1'b0;
      req_valid_i = 1'b0;
      req_write_i = 1'b0;
      req_addr_i = {ADDRESS_WIDTH{1'b0}};
      req_wdata_i = 32'd0;
      req_be_i = 4'b1111;
      rsp_ready_i = 1'b0;
      source_i = {NUM_SOURCES{1'b0}};
      tick();
      tick();
      rst_ni = 1'b1;
      tick();
    end
  endtask

  // ---------------------------------------------------------------------------
  // Scenarios 1..10 for a configuration whose PENDING/ENABLE window is reachable
  // ---------------------------------------------------------------------------
  task automatic full_suite;
    integer j;
    integer high_source;
    begin
      // 1: reset values ------------------------------------------------------
      dut_reset();
      check(!irq_o, "S1 irq_o must be low after reset");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S1 IN_SERVICE reads 0 after reset");
      expect_word(SOURCE_COUNT_ADDR, NUM_SOURCES + NEGATIVE_CONTROL, "S1 SOURCE_COUNT reads NUM_SOURCES");
      for (j = 0; j < B; j = j + 1) begin
        expect_word(pending_addr(j), 32'd0, "S1 PENDING word reads 0 after reset");
        expect_word(enable_addr(j), 32'd0, "S1 ENABLE word reads 0 after reset");
      end

      // 2: a masked source still pends, ENABLE then raises irq_o --------------
      @(negedge clk_i);
      source_i[0] = 1'b1;                                  // source ID 1
      tick();
      check(!irq_o, "S2 a masked pending source must not notify");
      expect_pending_bit(1, 1'b1, "S2 a masked source is still sampled into pending");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error, "S2 CLAIM without a candidate is not an error");
      check(scratch_value == 32'd0, "S2 CLAIM without a candidate returns 0");
      check(!irq_o, "S2 CLAIM without a candidate claims nothing");
      expect_pending_bit(1, 1'b1, "S2 a claimless CLAIM leaves pending set");
      wr_watch_irq(enable_addr(0), id_bit_mask(1), 1'b1, "S2 irq_o rises when the pending source is enabled");
      expect_pending_bit(1, 1'b1, "S2 ENABLE never clears pending");

      // 6: level semantics ----------------------------------------------------
      @(negedge clk_i);
      source_i[0] = 1'b0;
      tick();
      check(!irq_o, "S6 deasserting the level clears the notification");
      expect_pending_bit(1, 1'b0, "S6 deasserting the level clears pending");
      @(negedge clk_i);
      source_i[0] = 1'b1;
      tick();
      check(irq_o, "S6 an asserted level notifies again");
      expect_pending_bit(1, 1'b1, "S6 an asserted level sets pending again");

      // 3: lowest ID wins, a busy controller claims nothing --------------------
      wr(enable_addr(0), ENABLE_LOW_IDS);
      check(!wr_error, "S3 enabling both sources succeeds");
      @(negedge clk_i);
      source_i[1] = 1'b1;                                  // source ID 2
      tick();
      expect_pending_bit(1, 1'b1, "S3 both asserted sources are pending");
      expect_pending_bit(2, 1'b1, "S3 both asserted sources are pending");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error, "S3 CLAIM must not report an error");
      check(scratch_value == 32'd1, "S3 CLAIM returns the lowest asserted ID");
      check(!irq_o, "S3 no notification while a source is in service");
      expect_pending_bit(1, 1'b0, "S3 the claimed source is no longer pending");
      expect_pending_bit(2, 1'b1, "S3 the other source stays pending");
      expect_word(IN_SERVICE_ADDR, 32'd1, "S3 IN_SERVICE reports the claimed ID");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd0), "S3 a second CLAIM while busy returns 0");
      expect_word(IN_SERVICE_ADDR, 32'd1, "S3 a second CLAIM changes no state");
      expect_pending_bit(2, 1'b1, "S3 a second CLAIM leaves the other source pending");

      // 4: COMPLETE rules -----------------------------------------------------
      wr(COMPLETE_ADDR, 32'd2);
      check(wr_error, "S4 COMPLETE with a wrong nonzero ID errors");
      expect_word(IN_SERVICE_ADDR, 32'd1, "S4 a wrong ID leaves IN_SERVICE unchanged");
      wr(COMPLETE_ADDR, 32'd0);
      check(wr_error, "S4 COMPLETE with ID 0 errors");
      expect_word(IN_SERVICE_ADDR, 32'd1, "S4 ID 0 leaves IN_SERVICE unchanged");
      xfer(1'b1, COMPLETE_ADDR, 32'd1, 4'b0001, wr_value, wr_error);
      check(wr_error, "S4 a partial-byte COMPLETE errors");
      expect_word(IN_SERVICE_ADDR, 32'd1, "S4 a partial-byte COMPLETE changes nothing");
      wr(COMPLETE_ADDR, 32'd1);
      check(!wr_error, "S4 COMPLETE with the in-service ID succeeds");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S4 COMPLETE clears IN_SERVICE");
      expect_pending_bit(2, 1'b1, "S4 COMPLETE never touches the peripheral");

      // 3b: a level that only appears on the accepting edge is not claimable ---
      dut_reset();
      wr(enable_addr(0), id_bit_mask(1));
      check(!wr_error, "S3b enabling source ID 1 succeeds");
      rsp_ready_i = 1'b1;
      idle_wait();
      source_i[0] = 1'b1;                    // the level appears together with the request
      req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
      tick();
      check(rsp_valid_o && !rsp_error_o, "S3b the same-edge CLAIM is answered");
      check(rsp_rdata_o == 32'd0, "S3b a level that first appears on this edge is not claimable");
      req_valid_i = 1'b0;
      tick();
      check(irq_o, "S3b the sampled level notifies from the next edge on");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S3b the same-edge CLAIM claimed nothing");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd1), "S3b the next request claims the level");

      // 5: re-pending is level driven -----------------------------------------
      dut_reset();
      wr(enable_addr(0), ENABLE_LOW_IDS);
      check(!wr_error, "S5 enabling both sources succeeds");
      @(negedge clk_i);
      source_i[0] = 1'b1;
      source_i[1] = 1'b1;
      tick();
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd1), "S5 the first claim takes ID 1");
      @(negedge clk_i);
      source_i[1] = 1'b0;                                  // cleared before COMPLETE
      tick();
      expect_pending_bit(2, 1'b0, "S5 the deasserted source is cleared while ID 1 is in service");
      rsp_ready_i = 1'b1;
      idle_wait();
      req_drive(1'b1, COMPLETE_ADDR, 32'd1, 4'b1111);
      tick();
      check(rsp_valid_o && !rsp_error_o, "S5 COMPLETE succeeds");
      check(!irq_o, "S5 the COMPLETE edge itself does not re-pend the completed source");
      req_valid_i = 1'b0;
      tick();
      check(irq_o, "S5 a still-asserted source notifies again one sampling edge after COMPLETE");
      expect_pending_bit(1, 1'b1, "S5 the still-asserted source re-pends");
      expect_pending_bit(2, 1'b0, "S5 the deasserted source never re-pends");

      // 7: backpressure cannot double-claim -----------------------------------
      dut_reset();
      wr(enable_addr(0), id_bit_mask(1));
      check(!wr_error, "S7 enabling source ID 1 succeeds");
      @(negedge clk_i);
      source_i[0] = 1'b1;
      tick();
      rsp_ready_i = 1'b0;
      idle_wait();
      req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
      tick();
      check(rsp_valid_o && !rsp_error_o && (rsp_rdata_o == 32'd1), "S7 CLAIM returns the source ID");
      req_valid_i = 1'b0;
      check(!irq_o, "S7 the claimed source no longer notifies");
      repeat (3) begin
        tick();
        check(rsp_valid_o && !rsp_error_o && (rsp_rdata_o == 32'd1),
              "S7 the response is held stable under backpressure");
        check(!req_ready_o, "S7 req_ready_o stays low while a response is pending");
      end
      // A fresh CLAIM is presented while the old response is still unaccepted:
      // it must not be accepted and must not claim the source a second time.
      req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
      repeat (2) begin
        tick();
        check(rsp_valid_o && (rsp_rdata_o == 32'd1), "S7 a blocked request cannot replace the response");
        check(!req_ready_o, "S7 a blocked request is not accepted");
      end
      rsp_ready_i = 1'b1;
      tick();
      check(!rsp_valid_o, "S7 the held response retires once accepted");
      tick();
      check(rsp_valid_o && !rsp_error_o, "S7 the waiting request is answered afterwards");
      check(rsp_rdata_o == 32'd0, "S7 the waiting CLAIM answers 0 while a source is in service");
      req_valid_i = 1'b0;
      expect_word(IN_SERVICE_ADDR, 32'd1, "S7 the source was claimed exactly once");

      // 8: access errors and ENABLE masking -----------------------------------
      dut_reset();
      wr(enable_addr(0), id_bit_mask(1));
      check(!wr_error, "S8 enabling source ID 1 succeeds");
      @(negedge clk_i);
      source_i[0] = 1'b1;
      tick();
      check(irq_o, "S8 setup: the enabled pending source notifies");
      rd(IN_SERVICE_ADDR, 4'b0011);
      check(rd_error, "S8 a partial-byte read errors");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S8 a partial-byte read has no side effect");
      rd(CLAIM_ADDR, 4'b0001);
      check(rd_error, "S8 a partial-byte CLAIM errors");
      check(irq_o, "S8 a partial-byte CLAIM must not claim");
      expect_pending_bit(1, 1'b1, "S8 a partial-byte CLAIM leaves pending set");
      rd(COMPLETE_ADDR, 4'b1111);
      check(rd_error, "S8 reading the write-only COMPLETE register errors");
      wr(COMPLETE_ADDR, 32'd1);
      check(wr_error, "S8 completing a source that is not in service errors");
      rd(RESERVED_ADDR, 4'b1111);
      check(rd_error, "S8 reading a reserved header word errors");
      wr(RESERVED_ADDR, 32'hffffffff);
      check(wr_error, "S8 writing a reserved header word errors");
      rd(OOB_ADDR, 4'b1111);
      check(rd_error, "S8 reading outside the register window errors");
      wr(OOB_ADDR, 32'hffffffff);
      check(wr_error, "S8 writing outside the register window errors");
      wr(pending_addr(0), 32'hffffffff);
      check(wr_error, "S8 writing the read-only PENDING bitmap errors");
      expect_pending_bit(1, 1'b1, "S8 a PENDING write cannot clear pending");
      wr(CLAIM_ADDR, 32'hdeadbeef);
      check(wr_error, "S8 writing the read-only CLAIM register errors");
      check(irq_o, "S8 a CLAIM write cannot claim");
      wr(SOURCE_COUNT_ADDR, 32'h1);
      check(wr_error, "S8 writing the read-only SOURCE_COUNT register errors");
      wr(IN_SERVICE_ADDR, 32'h1);
      check(wr_error, "S8 writing the read-only IN_SERVICE register errors");
      rd(pending_addr(0), 4'b0011);
      check(rd_error, "S8 a partial-byte PENDING read errors");
      xfer(1'b1, enable_addr(0), 32'h0, 4'b0011, wr_value, wr_error);
      check(wr_error, "S8 a partial-byte ENABLE write errors");
      expect_word(enable_addr(0), id_bit_mask(1), "S8 a partial-byte ENABLE write changes nothing");
      for (j = 0; j < B; j = j + 1) begin
        wr(enable_addr(j), 32'hffffffff);
        check(!wr_error, "S8 a full-word ENABLE write succeeds");
        expect_word(enable_addr(j), valid_bitmap_mask(j), "S8 ENABLE masks the reserved and unimplemented bits");
      end

      // 10: in-service exclusion and masking ----------------------------------
      dut_reset();
      wr(enable_addr(0), ENABLE_LOW_IDS);
      check(!wr_error, "S10 enabling both sources succeeds");
      @(negedge clk_i);
      source_i[0] = 1'b1;
      source_i[1] = 1'b1;
      tick();
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd1), "S10 the lowest ID is claimed");
      check(!irq_o, "S10 a pending enabled source does not notify while one is in service");
      wr(COMPLETE_ADDR, 32'd1);
      check(!wr_error, "S10 completing the in-service source succeeds");
      check(irq_o, "S10 the other enabled pending source notifies after completion");
      @(negedge clk_i);
      source_i[0] = 1'b0;                                  // ID 1 is no longer a candidate
      tick();
      check(irq_o, "S10 only source ID 2 is still pending");
      wr(enable_addr(0), 32'd0);
      check(!wr_error, "S10 masking the pending source succeeds");
      check(!irq_o, "S10 a masked pending source does not notify");
      expect_pending_bit(2, 1'b1, "S10 masking never clears pending");
      wr(enable_addr(0), ENABLE_LOW_IDS);
      check(!wr_error, "S10 unmasking succeeds");
      check(irq_o, "S10 unmasking a still-pending source notifies again");

      // 10b: wide IDs in the second bitmap word --------------------------------
      if (NUM_SOURCES > 32) begin
        high_source = NUM_SOURCES - 1;                     // source index, ID NUM_SOURCES
        @(negedge clk_i);
        source_i[1] = 1'b0;
        tick();
        check(!irq_o, "S10b the low sources are cleared before the wide-ID check");
        wr(enable_addr(NUM_SOURCES / 32), id_bit_mask(NUM_SOURCES));
        check(!wr_error, "S10b enabling the wide source succeeds");
        @(negedge clk_i);
        source_i[high_source] = 1'b1;
        tick();
        expect_pending_bit(NUM_SOURCES, 1'b1, "S10b the wide source pends in the upper bitmap word");
        expect_word(pending_addr(NUM_SOURCES / 32), id_bit_mask(NUM_SOURCES),
                    "S10b unimplemented pending bits above NUM_SOURCES read 0");
        check(irq_o, "S10b the wide source notifies");
        read_word(CLAIM_ADDR, scratch_value, scratch_error);
        check(!scratch_error && (scratch_value == NUM_SOURCES), "S10b CLAIM returns the wide source ID");
        expect_word(IN_SERVICE_ADDR, NUM_SOURCES, "S10b IN_SERVICE holds the wide ID");
        expect_pending_bit(NUM_SOURCES, 1'b0, "S10b an in-service source is not pending");
        wr(COMPLETE_ADDR, NUM_SOURCES);
        check(!wr_error, "S10b COMPLETE accepts the full-width ID");
        expect_word(IN_SERVICE_ADDR, 32'd0, "S10b the wide ID completes");
        check(irq_o, "S10b the still-asserted wide source notifies again");
      end

      // 9: reset in the middle of a transaction -------------------------------
      dut_reset();
      wr(enable_addr(0), id_bit_mask(1));
      check(!wr_error, "S9 enabling source ID 1 succeeds");
      @(negedge clk_i);
      source_i[0] = 1'b1;
      tick();
      rsp_ready_i = 1'b0;
      idle_wait();
      req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
      tick();
      check(rsp_valid_o && !rsp_error_o && (rsp_rdata_o == 32'd1), "S9 the claim is outstanding");
      req_valid_i = 1'b0;
      tick();
      check(rsp_valid_o && (rsp_rdata_o == 32'd1) && !req_ready_o, "S9 the response is held unaccepted");
      check(!irq_o, "S9 the claimed source is in service and no longer notifies");
      rst_ni = 1'b0;
      #1;
      check(!rsp_valid_o && !req_ready_o && !irq_o, "S9 reset drops the pending response immediately");
      tick();
      check(!rsp_valid_o && !req_ready_o, "S9 no response survives the reset edge");
      rst_ni = 1'b1;
      tick();
      expect_word(IN_SERVICE_ADDR, 32'd0, "S9 reset clears the in-service source");
      check(!irq_o, "S9 reset clears enable, so the asserted level alone does not notify");
      expect_pending_bit(1, 1'b1, "S9 the asserted source is re-observed after reset release");
      // The stale claim must not be replayed: only source ID 2 is enabled and
      // asserted now, so the next CLAIM must answer 2, not the old 1.
      @(negedge clk_i);
      source_i[0] = 1'b0;
      source_i[1] = 1'b1;
      wr(enable_addr(0), id_bit_mask(2));
      check(!wr_error, "S9 re-enabling the other source succeeds");
      tick();
      expect_pending_bit(1, 1'b0, "S9 the cleared source is not pending");
      check(irq_o, "S9 the re-enabled source notifies");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd2), "S9 no stale claim is replayed after reset");
      wr(COMPLETE_ADDR, 32'd2);
      check(!wr_error, "S9 the fresh claim completes");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S9 the fresh claim left nothing in service");

      dut_reset();
      check(!irq_o, "final: no notification without pending sources");
    end
  endtask

  // ---------------------------------------------------------------------------
  // Reduced suite for a configuration whose bitmap window is unreachable
  // ---------------------------------------------------------------------------
  task automatic header_only_suite;
    begin
      if (!BITMAP_REACHABLE)
        $display("NOTE: the PENDING/ENABLE window is not addressable with ADDRESS_WIDTH=%0d; running header-only checks",
                 ADDRESS_WIDTH);
      else
        $display("NOTE: the full register suite needs at least two sources; running header-only checks");
      // 1: reset values ------------------------------------------------------
      dut_reset();
      check(!irq_o, "S1 irq_o must be low after reset");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S1 IN_SERVICE reads 0 after reset");
      expect_word(SOURCE_COUNT_ADDR, NUM_SOURCES + NEGATIVE_CONTROL, "S1 SOURCE_COUNT reads NUM_SOURCES");

      // 2/3/6/10: a source can never be enabled in this window, so CLAIM can
      // never succeed even though the level is sampled into pending.
      @(negedge clk_i);
      source_i[0] = 1'b1;
      tick();
      check(!irq_o, "S2 a source that cannot be enabled must not notify");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd0), "S2 CLAIM without an enabled source returns 0");
      read_word(CLAIM_ADDR, scratch_value, scratch_error);
      check(!scratch_error && (scratch_value == 32'd0), "S3 a repeated CLAIM stays 0");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S3 no source can enter service");
      check(!irq_o, "S10 no notification without an enabled source");
      @(negedge clk_i);
      source_i[0] = 1'b0;
      tick();
      check(!irq_o, "S6 a cleared source does not notify");

      // 4: COMPLETE can never match because no source can be in service.
      wr(COMPLETE_ADDR, 32'd1);
      check(wr_error, "S4 COMPLETE with no source in service errors");
      wr(COMPLETE_ADDR, 32'd0);
      check(wr_error, "S4 COMPLETE with ID 0 errors");
      expect_word(IN_SERVICE_ADDR, 32'd0, "S4 IN_SERVICE stays 0");

      // 8: header access errors -----------------------------------------------
      rd(IN_SERVICE_ADDR, 4'b0011);
      check(rd_error, "S8 a partial-byte read errors");
      rd(COMPLETE_ADDR, 4'b1111);
      check(rd_error, "S8 reading the write-only COMPLETE register errors");
      wr(IN_SERVICE_ADDR, 32'd1);
      check(wr_error, "S8 writing a read-only register errors");
      rd(RESERVED_ADDR, 4'b1111);
      check(rd_error, "S8 reading a reserved header word errors");
      wr(RESERVED_ADDR, 32'hffffffff);
      check(wr_error, "S8 writing a reserved header word errors");
      rd(OOB_ADDR, 4'b1111);
      check(rd_error, "S8 reading the top of the narrow window errors");
      wr(OOB_ADDR, 32'hffffffff);
      check(wr_error, "S8 writing the top of the narrow window errors");

      // 7: backpressure on a CLAIM that answers 0 -----------------------------
      rsp_ready_i = 1'b0;
      idle_wait();
      req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
      tick();
      check(rsp_valid_o && !rsp_error_o && (rsp_rdata_o == 32'd0), "S7 CLAIM answers 0");
      req_valid_i = 1'b0;
      repeat (2) begin
        tick();
        check(rsp_valid_o && !rsp_error_o && (rsp_rdata_o == 32'd0),
              "S7 the response is held stable under backpressure");
        check(!req_ready_o, "S7 req_ready_o stays low while a response is pending");
      end
      rsp_ready_i = 1'b1;
      tick();
      check(!rsp_valid_o, "S7 the held response retires once accepted");

      // 9: reset in the middle of a transaction -------------------------------
      rsp_ready_i = 1'b0;
      idle_wait();
      req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
      tick();
      check(rsp_valid_o, "S9 a response is outstanding");
      req_valid_i = 1'b0;
      rst_ni = 1'b0;
      #1;
      check(!rsp_valid_o && !req_ready_o && !irq_o, "S9 reset drops the pending response immediately");
      tick();
      check(!rsp_valid_o && !req_ready_o, "S9 no response survives the reset edge");
      rst_ni = 1'b1;
      tick();
      expect_word(IN_SERVICE_ADDR, 32'd0, "S9 reset clears the in-service state");
      check(!irq_o, "S9 no notification after reset");
    end
  endtask

  initial begin
    rst_ni = 1'b0;
    req_valid_i = 1'b0;
    req_write_i = 1'b0;
    req_addr_i = {ADDRESS_WIDTH{1'b0}};
    req_wdata_i = 32'd0;
    req_be_i = 4'b1111;
    rsp_ready_i = 1'b0;
    source_i = {NUM_SOURCES{1'b0}};
    $display("NOTE: soc_irq_controller_tb NUM_SOURCES=%0d ADDRESS_WIDTH=%0d B=%0d ID_WIDTH=%0d full_suite=%0d",
             NUM_SOURCES, ADDRESS_WIDTH, B, ID_WIDTH, FULL_SUITE);
    tick();
    check(!irq_o && !rsp_valid_o && !req_ready_o, "reset holds irq_o, rsp_valid_o and req_ready_o low");
    // A request presented while reset is asserted must never be accepted.
    req_drive(1'b0, CLAIM_ADDR, 32'd0, 4'b1111);
    tick();
    check(!rsp_valid_o && !req_ready_o, "no request is accepted while reset is asserted");
    req_valid_i = 1'b0;
    rst_ni = 1'b1;
    tick();
    check(!rsp_valid_o, "the request presented during reset leaves no response");
    if (FULL_SUITE)
      full_suite();
    else
      header_only_suite();
    $display("RESULT: PASS");
    $finish;
  end
endmodule
