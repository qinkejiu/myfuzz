// Real-RTL calibration for the public-boundary SPI checker. Mutants alter only
// checker-visible boundary pins or APB read data; the pinned PULP RTL is intact.
module soc_pulp_spi_checker_tb;
  logic clk = 1'b0;
  logic rstn = 1'b0;
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

  logic [31:0] arm_word = 32'h5A3C_C3A5;
  logic arm_valid = 1'b0;
  wire peer_armed;
  wire [31:0] arm_accept_count, arm_drop_count;
  wire peer_selected;
  wire [31:0] selection_count, clock_count, shift_count;
  wire mode_error;
  wire [31:0] mode_error_count;

  logic force_idle_sck = 1'b0;
  logic force_second_cs = 1'b0;
  logic force_unrecognized_cs = 1'b0;
  logic hide_one_sck_high = 1'b0;
  logic flip_mosi = 1'b0;
  logic flip_miso_observation = 1'b0;
  logic force_standard_mode_error = 1'b0;
  logic [31:0] read_data_xor = '0;
  wire checker_sck = force_idle_sck ? 1'b1 : (spi_clk & ~hide_one_sck_high);
  wire checker_csn0 = force_unrecognized_cs ? 1'b0 : spi_csn0;
  wire checker_csn1 = force_unrecognized_cs ? 1'b0 :
                      (spi_csn1 & ~(force_second_cs & ~spi_csn0));
  wire checker_sdo0 = spi_sdo0 ^ (flip_mosi & ~spi_csn0);
  wire [1:0] checker_mode = (force_standard_mode_error && !spi_csn0 && spi_clk)
                          ? 2'b10 : spi_mode;
  wire checker_sdi1 = spi_sdi1 ^ (flip_miso_observation & ~spi_csn0);
  wire [31:0] checker_prdata = prdata ^ read_data_xor;

  wire [13:0] eval_o, fail_o;
  logic [13:0] eval_seen = '0;
  always #5 clk = ~clk;

  always_ff @(posedge clk) begin
    if (!rstn) eval_seen <= '0;
    else eval_seen <= eval_seen | eval_o;
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

  soc_pulp_spi_checker u_checker (
      .clk_i(clk), .rst_ni(rstn), .paddr_i(paddr), .psel_i(psel),
      .penable_i(penable), .pwrite_i(pwrite), .pwdata_i(pwdata),
      .prdata_i(checker_prdata), .pready_i(pready), .pslverr_i(pslverr),
      .sck_i(checker_sck), .csn0_i(checker_csn0), .csn1_i(checker_csn1),
      .csn2_i(spi_csn2), .csn3_i(spi_csn3), .mode_i(checker_mode),
      .sdo0_i(checker_sdo0), .sdo1_i(spi_sdo1), .sdo2_i(spi_sdo2),
      .sdo3_i(spi_sdo3), .sdi0_i(spi_sdi0), .sdi1_i(checker_sdi1),
      .sdi2_i(spi_sdi2), .sdi3_i(spi_sdi3), .eval_o(eval_o), .fail_o(fail_o)
  );

  task automatic tick;
    @(posedge clk);
    #1;
  endtask

  task automatic idle_bus;
    psel = 1'b0;
    penable = 1'b0;
    pwrite = 1'b0;
    paddr = '0;
    pwdata = '0;
  endtask

  task automatic apb_write(input logic [11:0] address,
                           input logic [31:0] value);
    @(negedge clk);
    paddr = address;
    pwdata = value;
    pwrite = 1'b1;
    psel = 1'b1;
    penable = 1'b0;
    @(negedge clk);
    penable = 1'b1;
    @(posedge clk);
    #1;
    @(negedge clk);
    idle_bus();
  endtask

  task automatic apb_read(input logic [11:0] address,
                          output logic [31:0] value);
    @(negedge clk);
    paddr = address;
    pwrite = 1'b0;
    psel = 1'b1;
    penable = 1'b0;
    @(negedge clk);
    penable = 1'b1;
    @(posedge clk);
    value = prdata;
    @(negedge clk);
    idle_bus();
  endtask

  task automatic reset_case;
    @(negedge clk);
    rstn = 1'b0;
    idle_bus();
    arm_valid = 1'b0;
    force_idle_sck = 1'b0;
    force_second_cs = 1'b0;
    force_unrecognized_cs = 1'b0;
    hide_one_sck_high = 1'b0;
    flip_mosi = 1'b0;
    flip_miso_observation = 1'b0;
    force_standard_mode_error = 1'b0;
    read_data_xor = '0;
    repeat (3) @(negedge clk);
    rstn = 1'b1;
    repeat (2) tick();
  endtask

  task automatic arm_peer;
    @(negedge clk);
    arm_valid = 1'b1;
    @(negedge clk);
    arm_valid = 1'b0;
    if (!peer_armed) $fatal(1, "SPI peer arm did not latch");
  endtask

  task automatic wait_eot;
    integer timeout;
    timeout = 0;
    while (!events[1] && timeout < 1000) begin
      @(negedge clk);
      timeout = timeout + 1;
    end
    if (!events[1]) $fatal(1, "SPI end-of-transfer timeout");
    repeat (3) tick();
  endtask

  task automatic start_tx(input integer mutant);
    begin
      reset_case();
      force_second_cs = (mutant == 1);
      force_idle_sck = (mutant == 5);
      flip_mosi = (mutant == 3);
      force_standard_mode_error = (mutant == 4);
      apb_write(12'h004, 32'h0);              // CLKDIV = 0
      apb_write(12'h010, 32'h0020_0000);       // 32 data bits
      apb_write(12'h018, 32'hA5C3_96F0);       // TXFIFO word
      apb_write(12'h000, 32'h0000_0102);       // TX-only, CS0
      if (mutant == 2) begin
        fork
          begin
            wait (!spi_csn0);
            repeat (6) @(posedge clk);
            wait (spi_clk === 1'b0);
            #1 hide_one_sck_high = 1'b1;
            wait (spi_clk === 1'b1);
            wait (spi_clk === 1'b0);
            #1 hide_one_sck_high = 1'b0;
          end
        join_none
      end
      wait_eot();
      repeat (3) tick();
    end
  endtask

  task automatic check_single_failure(input integer local_bit,
                                      input string label_text);
    logic [13:0] expected;
    expected = 14'b1 << local_bit;
    if ((fail_o & expected) == 0)
      $fatal(1, "%s did not set sticky fail bit %0d: %014b",
             label_text, local_bit, fail_o);
    repeat (2) tick();
    if ((fail_o & expected) == 0)
      $fatal(1, "%s fail bit %0d was not sticky: %014b",
             label_text, local_bit, fail_o);
    $display("SPI_CHECKER_MUTANT_PASS label=%s local_bit=%0d fail=%014b",
             label_text, local_bit, fail_o);
  endtask

  logic [31:0] received;
  initial begin
    idle_bus();

    // TX-only golden: APB TXFIFO -> SDO0, exactly 64 mode-0 edges.
    start_tx(0);
    if (fail_o !== 14'b0) $fatal(1, "TX golden fail: %014b", fail_o);
    if (!eval_seen[5] || !eval_seen[6] || !eval_seen[7] ||
        !eval_seen[8] || !eval_seen[10])
      $fatal(1, "TX properties did not evaluate: %014b", eval_seen);
    $display("SPI_CHECKER_GOLDEN_TX_PASS eval=%014b", eval_seen);

    // The checker snapshots MISO at its own SDI1 boundary and compares it with
    // the accepted RXFIFO APB data. TXFIFO is intentionally absent in this RX
    // phase; the PULP controller selects RX and TX as separate branches.
    reset_case();
    arm_peer();
    apb_write(12'h004, 32'h0);
    apb_write(12'h010, 32'h0020_0000);
    apb_write(12'h000, 32'h0000_0101);
    wait_eot();
    apb_read(12'h020, received);
    $display("SPI_RX_READ value=%08x", received);
    if (received !== 32'h5A3C_C3A5)
      $fatal(1, "RX golden value: %08x", received);
    repeat (2) tick();
    if (fail_o !== 14'b0) $fatal(1, "RX golden fail: %014b", fail_o);
    if (!eval_seen[5] || !eval_seen[6] ||
        !eval_seen[9] || !eval_seen[10])
      $fatal(1, "RX properties did not evaluate: %014b", eval_seen);
    $display("SPI_CHECKER_GOLDEN_RX_PASS eval=%014b", eval_seen);

    // Without the accepted supported APB sequence, even active pins and high
    // SCK are outside this calibration's contract and must remain unassessed.
    reset_case();
    force_unrecognized_cs = 1'b1;
    force_idle_sck = 1'b1;
    repeat (3) tick();
    force_unrecognized_cs = 1'b0;
    force_idle_sck = 1'b0;
    repeat (2) tick();
    if (fail_o !== 14'b0 || eval_seen !== 14'b0)
      $fatal(1, "unsupported pins were assessed: eval=%014b fail=%014b",
             eval_seen, fail_o);
    $display("SPI_CHECKER_UNSUPPORTED_NOT_ASSESSED_PASS");

    // CS0 exclusivity mutant; the checked CS1 pin is corrupted only while the
    // real PULP target has selected CS0.
    start_tx(1);
    check_single_failure(5, "second-CS-active");

    // Hide one observed SCK high phase. The checker must refuse to call the
    // finite 32-bit frame complete and latch the edge-count failure.
    start_tx(2);
    check_single_failure(7, "missing-mode0-edge");

    start_tx(3);
    check_single_failure(8, "MOSI-word-corruption");

    start_tx(4);
    check_single_failure(10, "standard-mode-broken");

    // SCK forced high during the recognized transaction violates the mode-0
    // idle level before CS0 opens.
    start_tx(5);
    check_single_failure(6, "mode0-idle-high");

    // MISO checker input is corrupted while the DUT still receives the
    // unmodified peer line, so the independent sampled value disagrees with
    // the real RXFIFO readback.
    reset_case();
    arm_peer();
    flip_miso_observation = 1'b1;
    apb_write(12'h004, 32'h0);
    apb_write(12'h010, 32'h0020_0000);
    apb_write(12'h000, 32'h0000_0101);
    wait_eot();
    apb_read(12'h020, received);
    check_single_failure(9, "MISO-to-RXFIFO-mismatch");

    $display("PULP_SPI_CHECKER_ALL_PASS");
    $finish;
  end
endmodule
