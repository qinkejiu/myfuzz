module soc_protocol_checkers_tb;
  logic clk = 0;
  logic rst_n = 0;
  always #5 clk = ~clk;

  logic req, gnt, rvalid, we, err;
  logic [31:0] addr, wdata, rdata;
  logic [3:0] be;
  wire [2:0] obi_eval, obi_fail;
  soc_obi_checker u_obi (
    .clk_i(clk), .rst_ni(rst_n), .req_i(req), .gnt_i(gnt),
    .addr_i(addr), .wdata_i(wdata), .be_i(be), .we_i(we),
    .rvalid_i(rvalid), .rdata_i(rdata), .err_i(err),
    .eval_o(obi_eval), .fail_o(obi_fail)
  );
  logic data_req, data_gnt, data_rvalid, data_we, data_err;
  logic [31:0] data_addr, data_wdata, data_rdata;
  logic [3:0] data_be;
  wire [2:0] data_obi_eval, data_obi_fail;
  soc_obi_checker u_data_obi (
    .clk_i(clk), .rst_ni(rst_n), .req_i(data_req), .gnt_i(data_gnt),
    .addr_i(data_addr), .wdata_i(data_wdata), .be_i(data_be), .we_i(data_we),
    .rvalid_i(data_rvalid), .rdata_i(data_rdata), .err_i(data_err),
    .eval_o(data_obi_eval), .fail_o(data_obi_fail)
  );

  logic psel, penable, pready, pwrite, pslverr;
  logic [31:0] paddr, pwdata, prdata;
  wire [3:0] apb_eval, apb_fail;
  soc_apb3_checker u_apb (
    .clk_i(clk), .rst_ni(rst_n), .psel_i(psel), .penable_i(penable),
    .pready_i(pready), .paddr_i(paddr), .pwrite_i(pwrite),
    .pwdata_i(pwdata), .prdata_i(prdata), .pslverr_i(pslverr),
    .eval_o(apb_eval), .fail_o(apb_fail)
  );

  logic f_req, f_ready, f_rsp, f_rsp_ready;
  logic [31:0] f_addr;
  logic [1:0] target_select, source_id, response_source_id;
  wire [1:0] fabric_eval, fabric_fail;
  soc_fabric_checker #(.NUM_TARGETS(2), .SOURCE_ID_WIDTH(2)) u_fabric (
    .clk_i(clk), .rst_ni(rst_n), .req_valid_i(f_req),
    .req_ready_i(f_ready), .addr_i(f_addr), .target_select_i(target_select),
    .request_source_id_i(source_id), .response_source_id_i(response_source_id),
    .rsp_valid_i(f_rsp), .rsp_ready_i(f_rsp_ready),
    .eval_o(fabric_eval), .fail_o(fabric_fail)
  );

  task automatic tick;
    @(posedge clk);
    #1;
  endtask
  task automatic expect_fail(input logic [2:0] expected_obi,
                             input logic [2:0] expected_data_obi,
                             input logic [3:0] expected_apb,
                             input logic [1:0] expected_fabric,
                             input string label);
    if ({fabric_fail, apb_fail, data_obi_fail, obi_fail} !==
        {expected_fabric, expected_apb, expected_data_obi, expected_obi})
      $fatal(1, "%s: got fabric=%b apb=%b data_obi=%b instr_obi=%b",
             label, fabric_fail, apb_fail, data_obi_fail, obi_fail);
  endtask
  task automatic clear_all;
    @(negedge clk);
    rst_n = 0;
    req = 0; gnt = 0; rvalid = 0; we = 0; err = 0;
    addr = 0; wdata = 0; rdata = 0; be = 4'hf;
    data_req = 0; data_gnt = 0; data_rvalid = 0; data_we = 0; data_err = 0;
    data_addr = 0; data_wdata = 0; data_rdata = 0; data_be = 4'hf;
    psel = 0; penable = 0; pready = 1; pwrite = 0;
    pslverr = 0; paddr = 0; pwdata = 0; prdata = 0;
    f_req = 0; f_ready = 0; f_rsp = 0; f_rsp_ready = 1;
    f_addr = 0; target_select = 0; source_id = 0;
    response_source_id = 0;
    tick();
    @(negedge clk);
    rst_n = 1;
  endtask

  initial begin
    clear_all();
    req = 1; addr = 32'h100; we = 1; wdata = 32'hfeed; be = 4'hf;
    psel = 1; paddr = 32'h100; pwrite = 1; pwdata = 32'hbeef;
    f_req = 1; f_ready = 1; f_addr = 32'h100; source_id = 2'd1;
    tick();
    @(negedge clk); f_req = 0; psel = 1; penable = 1;
    tick();
    @(negedge clk); gnt = 1; f_rsp = 1; response_source_id = 2'd1;
    psel = 0; penable = 0;
    tick();
    @(negedge clk); req = 0; gnt = 0; rvalid = 1;
    psel = 0; penable = 0; f_rsp = 0;
    target_select = 2'b01;
    tick();
    expect_fail(3'b000, 3'b000, 4'b0000, 2'b00, "golden trace");
    if ((obi_eval & 3'b011) !== 3'b011 ||
        (apb_eval & 4'b1101) !== 4'b1101 ||
        fabric_eval !== 2'b11)
      $fatal(1, "golden property not evaluated obi=%b apb=%b fabric=%b",
             obi_eval, apb_eval, fabric_eval);

    clear_all(); req = 1; addr = 32'h100; tick();
    @(negedge clk); addr = 32'h104; tick();
    expect_fail(3'b001, 3'b000, 4'b0000, 2'b00, "stalled address mutant");

    clear_all(); rvalid = 1; tick();
    expect_fail(3'b010, 3'b000, 4'b0000, 2'b00, "orphan response mutant");

    clear_all(); req = 1; gnt = 1; rvalid = 1;
    data_req = 1; data_gnt = 1; data_rvalid = 1;
    tick();
    expect_fail(3'b010, 3'b010, 4'b0000, 2'b00,
                "same-cycle grant/response without prior grant");
    if (u_obi.outstanding_q !== 16'd1 || u_data_obi.outstanding_q !== 16'd1)
      $fatal(1, "new grant was consumed by orphan response");
    @(negedge clk); req = 0; gnt = 0; rvalid = 0;
    data_req = 0; data_gnt = 0; data_rvalid = 0;
    tick();
    @(negedge clk); rvalid = 1; data_rvalid = 1;
    tick();
    expect_fail(3'b010, 3'b010, 4'b0000, 2'b00,
                "same-cycle mutant retains newly granted outstanding request");
    if (u_obi.outstanding_q !== 16'd0 || u_data_obi.outstanding_q !== 16'd0)
      $fatal(1, "later response did not consume newly granted request");

    clear_all(); psel = 1; penable = 1; tick();
    expect_fail(3'b000, 3'b000, 4'b0001, 2'b00, "missing APB SETUP mutant");

    clear_all(); psel = 1; paddr = 32'h100; tick();
    @(negedge clk); penable = 1; pready = 0; tick();
    @(negedge clk); paddr = 32'h104; tick();
    expect_fail(3'b000, 3'b000, 4'b0110, 2'b00,
                "APB wait payload mutant: wait also violates pinned PREADY=1");

    clear_all(); psel = 1; pready = 0; tick();
    expect_fail(3'b000, 3'b000, 4'b0100, 2'b00, "APB ready mutant");

    clear_all(); psel = 1; pslverr = 1; tick();
    expect_fail(3'b000, 3'b000, 4'b1000, 2'b00, "APB slave error mutant");

    clear_all(); target_select = 2'b11; tick();
    expect_fail(3'b000, 3'b000, 4'b0000, 2'b01, "double target select mutant");

    clear_all(); f_req = 1; f_ready = 1; source_id = 2'd1; tick();
    @(negedge clk); f_req = 0; f_rsp = 1; response_source_id = 2'd0;
    tick();
    expect_fail(3'b000, 3'b000, 4'b0000, 2'b10, "wrong response source mutant");

    $display("PROTOCOL_CHECKERS_PASS");
    $finish;
  end
endmodule
