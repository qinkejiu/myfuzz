module soc_pulp_gpio_checker_tb;
  logic clk_i = 1'b0;
  logic rst_ni = 1'b0;
  always #5 clk_i = ~clk_i;

  logic [11:0] paddr;
  logic psel, penable, pwrite;
  logic [31:0] pwdata;
  wire [31:0] prdata;
  wire pready, pslverr;
  logic [31:0] gpio_in;
  wire [31:0] gpio_out, gpio_dir, gpio_in_sync;
  wire [127:0] gpio_padcfg;
  wire interrupt;

  apb_gpio #(.APB_ADDR_WIDTH(12), .PAD_NUM(32), .NBIT_PADCFG(4)) dut (
    .HCLK(clk_i), .HRESETn(rst_ni), .dft_cg_enable_i(1'b0),
    .PADDR(paddr), .PWDATA(pwdata), .PWRITE(pwrite), .PSEL(psel),
    .PENABLE(penable), .PRDATA(prdata), .PREADY(pready), .PSLVERR(pslverr),
    .gpio_in(gpio_in), .gpio_in_sync(gpio_in_sync), .gpio_out(gpio_out),
    .gpio_dir(gpio_dir), .gpio_padcfg(gpio_padcfg), .interrupt(interrupt)
  );

  // Mutations are applied only at checker inputs. The golden PULP RTL remains
  // untouched, and each case changes one observed boundary value.
  logic [31:0] prdata_xor;
  logic [31:0] gpio_out_xor, gpio_dir_xor, gpio_in_sync_xor;
  logic [127:0] gpio_padcfg_xor;
  wire [31:0] observed_prdata = prdata ^ prdata_xor;
  wire [31:0] observed_gpio_out = gpio_out ^ gpio_out_xor;
  wire [31:0] observed_gpio_dir = gpio_dir ^ gpio_dir_xor;
  wire [31:0] observed_gpio_in_sync = gpio_in_sync ^ gpio_in_sync_xor;
  wire [127:0] observed_gpio_padcfg = gpio_padcfg ^ gpio_padcfg_xor;

  wire [14:0] eval_o, fail_o;
  wire [5:0] first_fail_id_o;
  logic [14:0] eval_seen = '0;
  always_ff @(posedge clk_i) begin
    if (!rst_ni) eval_seen <= '0;
    else eval_seen <= eval_seen | eval_o;
  end

  soc_pulp_gpio_checker u_checker (
    .clk_i(clk_i), .rst_ni(rst_ni),
    .paddr_i(paddr), .psel_i(psel), .penable_i(penable),
    .pwrite_i(pwrite), .pwdata_i(pwdata), .prdata_i(observed_prdata),
    .pready_i(pready), .pslverr_i(pslverr),
    .gpio_in_i(gpio_in), .gpio_out_i(observed_gpio_out),
    .gpio_dir_i(observed_gpio_dir), .gpio_padcfg_i(observed_gpio_padcfg),
    .gpio_in_sync_i(observed_gpio_in_sync), .interrupt_i(interrupt),
    .eval_o(eval_o), .fail_o(fail_o), .first_fail_id_o(first_fail_id_o)
  );

  task automatic tick;
    @(posedge clk_i);
    #1;
  endtask

  task automatic idle_bus;
    psel = 1'b0;
    penable = 1'b0;
    pwrite = 1'b0;
    paddr = '0;
    pwdata = '0;
  endtask

  task automatic reset_case(input logic corrupt_reset_padcfg);
    @(negedge clk_i);
    rst_ni = 1'b0;
    idle_bus();
    gpio_in = '0;
    prdata_xor = '0;
    gpio_out_xor = '0;
    gpio_dir_xor = '0;
    gpio_in_sync_xor = '0;
    gpio_padcfg_xor = '0;
    repeat (2) tick();
    @(negedge clk_i);
    gpio_padcfg_xor = corrupt_reset_padcfg ? 128'h1 : 128'b0;
    rst_ni = 1'b1;
    tick();
  endtask

  task automatic write_reg(input logic [11:0] address,
                           input logic [31:0] value);
    @(negedge clk_i);
    paddr = address;
    pwdata = value;
    pwrite = 1'b1;
    psel = 1'b1;
    penable = 1'b0;
    @(negedge clk_i);
    penable = 1'b1;
    @(posedge clk_i);
    #1;
    @(negedge clk_i);
    idle_bus();
  endtask

  task automatic read_reg(input logic [11:0] address,
                          output logic [31:0] value);
    @(negedge clk_i);
    paddr = address;
    pwdata = '0;
    pwrite = 1'b0;
    psel = 1'b1;
    penable = 1'b0;
    @(negedge clk_i);
    penable = 1'b1;
    @(posedge clk_i);
    #1;
    value = prdata;
    @(negedge clk_i);
    idle_bus();
  endtask

  task automatic expect_failure(input logic [14:0] expected,
                                input integer evaluated_bit,
                                input string label_text);
    if (fail_o !== expected)
      $fatal(1, "%s: expected full fail mask %015b, got %015b",
             label_text, expected, fail_o);
    if (eval_o[evaluated_bit] !== 1'b1)
      $fatal(1, "%s: property bit %0d was not evaluated: %015b",
             label_text, evaluated_bit, eval_o);
    if (first_fail_id_o !== (6'd21 + evaluated_bit[5:0]))
      $fatal(1, "%s: first failure id expected %0d got %0d",
             label_text, 21 + evaluated_bit, first_fail_id_o);
  endtask

  logic [31:0] value;
  initial begin
    idle_bus();
    gpio_in = '0;
    prdata_xor = '0;
    gpio_out_xor = '0;
    gpio_dir_xor = '0;
    gpio_in_sync_xor = '0;
    gpio_padcfg_xor = '0;

    // Golden accepted APB accesses and pin timing cover every enabled local ID.
    reset_case(1'b0);
    if (fail_o !== 15'b0) $fatal(1, "reset golden trace failed: %015b", fail_o);
    // The PULP RTL selects registers only with PADDR[6:2], so bit 7 aliases
    // PADDIR. The independent shadow must apply the same canonical offset.
    write_reg(12'h080, 32'h0000_00a5);
    read_reg(12'h000, value);
    if (value !== 32'h0000_00a5) $fatal(1, "PADDIR readback: %h", value);
    if (gpio_dir !== 32'h0000_00a5 || fail_o !== 15'b0)
      $fatal(1, "golden aliased PADDIR access failed: dir=%h fail=%h",
             gpio_dir, fail_o);
    write_reg(12'h004, 32'h0000_000f);
    read_reg(12'h004, value);
    if (value !== 32'h0000_000f) $fatal(1, "GPIOEN readback: %h", value);
    write_reg(12'h00c, 32'h0000_00a5);
    read_reg(12'h00c, value);
    if (value !== 32'h0000_00a5) $fatal(1, "PADOUT readback: %h", value);
    write_reg(12'h010, 32'h0000_0002);
    tick();
    if (gpio_out !== 32'h0000_00a7) $fatal(1, "PADOUTSET output: %h", gpio_out);
    write_reg(12'h014, 32'h0000_0001);
    tick();
    if (gpio_out !== 32'h0000_00a6) $fatal(1, "PADOUTCLR output: %h", gpio_out);
    write_reg(12'h028, 32'h0000_002f);
    tick();
    read_reg(12'h028, value);
    if (value !== 32'h0000_002f) $fatal(1, "PADCFG readback: %h", value);
    write_reg(12'h02c, 32'h89ab_cdef);
    write_reg(12'h030, 32'h0123_4567);
    write_reg(12'h034, 32'h7654_3210);
    tick();
    read_reg(12'h034, value);
    if (value !== 32'h7654_3210 || gpio_padcfg[127:96] !== 32'h7654_3210)
      $fatal(1, "PADCFG high-bank packing: read=%h pins=%h", value,
             gpio_padcfg[127:96]);

    @(negedge clk_i);
    gpio_in = 32'h0000_0001 | 32'h0000_0100;
    repeat (4) tick();
    if (gpio_in_sync[0] !== 1'b1 || gpio_in_sync[8] !== 1'b0)
      $fatal(1, "input synchronization golden trace: %h", gpio_in_sync);
    read_reg(12'h008, value);
    if (value[0] !== 1'b1 || value[8] !== 1'b0)
      $fatal(1, "PADIN golden trace: %h", value);
    tick();
    if (fail_o !== 15'b0) $fatal(1, "golden GPIO trace failed: %015b", fail_o);
    if ((eval_seen & 15'h07ff) !== 15'h07ff)
      $fatal(1, "enabled properties were not all evaluated: seen=%015b", eval_seen);
    if (eval_seen[14:11] !== 4'b0 || fail_o[14:11] !== 4'b0)
      $fatal(1, "unsupported GPIO property bits must remain low: eval=%b fail=%b",
             eval_seen[14:11], fail_o[14:11]);

    // RESET_STATE: inject only a reset-time PADCFG pin observation.
    reset_case(1'b1);
    expect_failure(15'b000_0000_0000_001, 0, "reset-state mutant");

    // PADDIR readback shadow.
    reset_case(1'b0);
    write_reg(12'h000, 32'h1);
    prdata_xor = 32'h1;
    read_reg(12'h000, value);
    expect_failure(15'h002, 1, "PADDIR readback mutant");

    // GPIOEN readback shadow.
    reset_case(1'b0);
    write_reg(12'h004, 32'h1);
    prdata_xor = 32'h1;
    read_reg(12'h004, value);
    expect_failure(15'h004, 2, "GPIOEN readback mutant");

    // PADOUT register readback shadow.
    reset_case(1'b0);
    write_reg(12'h00c, 32'h1);
    prdata_xor = 32'h1;
    read_reg(12'h00c, value);
    expect_failure(15'h008, 3, "PADOUT readback mutant");

    // A complete PADOUT write must also drive the external output pins.
    reset_case(1'b0);
    write_reg(12'h00c, 32'h1);
    gpio_out_xor = 32'h1;
    tick();
    expect_failure(15'h008, 3, "PADOUT output mutant");

    // PADOUTSET output pin observation.
    reset_case(1'b0);
    write_reg(12'h010, 32'h1);
    gpio_out_xor = 32'h1;
    tick();
    expect_failure(15'h010, 4, "PADOUTSET output mutant");

    // PADOUTCLR output pin observation.
    reset_case(1'b0);
    write_reg(12'h00c, 32'h1);
    write_reg(12'h014, 32'h1);
    gpio_out_xor = 32'h1;
    tick();
    expect_failure(15'h020, 5, "PADOUTCLR output mutant");

    // PADCFG output/readback observation.
    reset_case(1'b0);
    write_reg(12'h028, 32'hf);
    tick();
    prdata_xor = 32'h1;
    read_reg(12'h028, value);
    expect_failure(15'h040, 6, "PADCFG readback mutant");

    reset_case(1'b0);
    write_reg(12'h028, 32'hf);
    gpio_padcfg_xor = 128'h1;
    tick();
    expect_failure(15'h040, 6, "PADCFG pin-output mutant");

    // A disabled four-pad group must hold its synchronizer value.
    reset_case(1'b0);
    @(negedge clk_i);
    gpio_in = 32'h0000_0100;
    repeat (4) tick();
    gpio_in_sync_xor = 32'h0000_0100;
    tick();
    expect_failure(15'h080, 7, "GPIOEN group-sampling mutant");

    // An enabled group exposes the two-stage gpio_in_sync output.
    reset_case(1'b0);
    write_reg(12'h004, 32'hf);
    @(negedge clk_i);
    gpio_in = 32'h1;
    repeat (3) tick();
    gpio_in_sync_xor = 32'h1;
    tick();
    expect_failure(15'h100, 8, "gpio_in_sync mutant");

    // PADIN is compared against the independently sampled third input stage.
    reset_case(1'b0);
    write_reg(12'h004, 32'hf);
    @(negedge clk_i);
    gpio_in = 32'h1;
    repeat (4) tick();
    prdata_xor = 32'h1;
    read_reg(12'h008, value);
    expect_failure(15'h200, 9, "PADIN readback mutant");

    // The external direction pin must follow the accepted PADDIR write.
    reset_case(1'b0);
    write_reg(12'h000, 32'h1);
    gpio_dir_xor = 32'h1;
    tick();
    expect_failure(15'h400, 10, "direction output mutant");

    $display("PULP_GPIO_CHECKER_PASS");
    $finish;
  end
endmodule
