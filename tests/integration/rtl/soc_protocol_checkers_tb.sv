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
  task automatic clear_all;
    @(negedge clk);
    rst_n = 0;
    req = 0; gnt = 0; rvalid = 0; we = 0; err = 0;
    addr = 0; wdata = 0; rdata = 0; be = 4'hf;
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
    if (obi_fail !== 0 || apb_fail !== 0 || fabric_fail !== 0)
      $fatal(1, "golden protocol trace failed obi=%b apb=%b fabric=%b",
             obi_fail, apb_fail, fabric_fail);
    if ((obi_eval & 3'b011) !== 3'b011 ||
        (apb_eval & 4'b1101) !== 4'b1101 ||
        fabric_eval !== 2'b11)
      $fatal(1, "golden property not evaluated obi=%b apb=%b fabric=%b",
             obi_eval, apb_eval, fabric_eval);

    clear_all(); req = 1; addr = 32'h100; tick();
    @(negedge clk); addr = 32'h104; tick();
    if (!obi_fail[0] || obi_fail[1]) $fatal(1, "stalled address mutant missed");

    clear_all(); rvalid = 1; tick();
    if (!obi_fail[1] || obi_fail[0]) $fatal(1, "orphan response mutant missed");

    clear_all(); psel = 1; penable = 1; tick();
    if (!apb_fail[0]) $fatal(1, "missing APB SETUP mutant missed");

    clear_all(); psel = 1; paddr = 32'h100; tick();
    @(negedge clk); penable = 1; pready = 0; tick();
    @(negedge clk); paddr = 32'h104; tick();
    if (!apb_fail[1]) $fatal(1, "APB wait payload mutant missed");

    clear_all(); psel = 1; pready = 0; tick();
    if (!apb_fail[2]) $fatal(1, "APB ready mutant missed");

    clear_all(); psel = 1; pslverr = 1; tick();
    if (!apb_fail[3]) $fatal(1, "APB slave error mutant missed");

    clear_all(); target_select = 2'b11; tick();
    if (!fabric_fail[0]) $fatal(1, "double target select mutant missed");

    clear_all(); f_req = 1; f_ready = 1; source_id = 2'd1; tick();
    @(negedge clk); f_req = 0; f_rsp = 1; response_source_id = 2'd0;
    tick();
    if (!fabric_fail[1]) $fatal(1, "wrong response source mutant missed");

    $display("PROTOCOL_CHECKERS_PASS");
    $finish;
  end
endmodule
