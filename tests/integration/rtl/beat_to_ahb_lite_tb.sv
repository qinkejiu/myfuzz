// Self-checking testbench for beat_to_ahb_lite.
//
// The adapter converts this system's internal processor-memory-beat face into an
// AHB-Lite manager port (the signal set CORE-V Wally's external bus declares).
// Lint alone cannot show that the phases are right, so this testbench models a
// subordinate and checks the protocol facts that matter:
//
//   1. one-cycle address phase with HTRANS=NONSEQ, HWRITE, HADDR, HSIZE for the
//      requested byte lanes, HBURST=SINGLE and HMASTLOCK=0;
//   2. HWDATA/HWSTRB appear in the cycle AFTER the address phase (AHB-Lite's
//      write data phase), not in the address phase;
//   3. HRDATAEXT is captured on the completion edge (HREADYEXT high) and the
//      HRESPEXT sampled then is what the beat face reports;
//   4. the completion is held until rsp_ready_i accepts it (the beat face is a
//      handshake), and req_ready_o is not offered while one is outstanding;
//   5. a subordinate that never asserts HREADYEXT ends in a timeout completion
//      rather than hanging the harness.
//
// The subordinate model is deliberately minimal: it answers reads with a value
// derived from the address and asserts HREADYEXT after a programmable number of
// cycles.
`timescale 1ns/1ps

module beat_to_ahb_lite_tb;
    localparam integer AW = 34;   // CVW rv32imc PA_BITS
    localparam integer DW = 32;   // CVW rv32imc AHBW
    localparam integer MAX_WAIT = 5;

    logic clk = 1'b0;
    logic rst_ni = 1'b0;
    always #5 clk = ~clk;

    // beat face
    logic                 req_valid;
    logic                 req_write;
    logic [AW-1:0]        req_addr;
    logic [DW-1:0]        req_wdata;
    logic [(DW/8)-1:0]    req_be;
    logic                 req_ready;
    logic                 rsp_valid;
    logic                 rsp_ready;
    logic [DW-1:0]        rsp_rdata;
    logic                 rsp_error;

    // AHB-Lite manager boundary
    logic [1:0]           HTRANS;
    logic [AW-1:0]        HADDR;
    logic                 HWRITE;
    logic [2:0]           HSIZE;
    logic [2:0]           HBURST;
    logic [3:0]           HPROT;
    logic                 HMASTLOCK;
    logic [DW-1:0]        HWDATA;
    logic [(DW/8)-1:0]    HWSTRB;
    logic                 HREADYEXT;
    logic [DW-1:0]        HRDATAEXT;
    logic                 HRESPEXT;

    beat_to_ahb_lite #(.ADDRESS_WIDTH(AW), .DATA_WIDTH(DW),
                       .MAX_WAIT_CYCLES(MAX_WAIT)) dut (
        .clk_i(clk), .rst_ni(rst_ni),
        .req_valid_i(req_valid), .req_write_i(req_write), .req_addr_i(req_addr),
        .req_wdata_i(req_wdata), .req_be_i(req_be), .req_ready_o(req_ready),
        .rsp_valid_o(rsp_valid), .rsp_ready_i(rsp_ready),
        .rsp_rdata_o(rsp_rdata), .rsp_error_o(rsp_error),
        .HTRANS(HTRANS), .HADDR(HADDR), .HWRITE(HWRITE), .HSIZE(HSIZE),
        .HBURST(HBURST), .HPROT(HPROT), .HMASTLOCK(HMASTLOCK),
        .HWDATA(HWDATA), .HWSTRB(HWSTRB),
        .HREADYEXT(HREADYEXT), .HRDATAEXT(HRDATAEXT), .HRESPEXT(HRESPEXT));

    // ---- subordinate model -------------------------------------------------
    integer sub_delay = 0;        // cycles after the address phase before ready
    logic   sub_error = 1'b0;
    logic   sub_hold_ready = 1'b0; // 1 = never assert HREADYEXT
    integer sub_wait = 0;
    logic   sub_active = 1'b0;
    logic [AW-1:0] sub_addr;
    logic          sub_write;
    logic [DW-1:0] sub_wdata;
    logic [(DW/8)-1:0] sub_strb;
    integer        sub_address_phases = 0;
    integer        sub_write_data_phases = 0;

    always @(posedge clk) begin
        if (!rst_ni) begin
            sub_active = 1'b0;
            sub_wait = 0;
            sub_address_phases = 0;
            sub_write_data_phases = 0;
            HREADYEXT = 1'b1;
            HRESPEXT = 1'b0;
            HRDATAEXT = '0;
        end else begin
            HRDATAEXT = sub_addr ^ 32'hA5A5_0000;
            HRESPEXT = sub_error;
            if (!sub_active) begin
                HREADYEXT = 1'b1;
                if (HTRANS == 2'b10) begin
                    sub_active = 1'b1;
                    sub_addr = HADDR;
                    sub_write = HWRITE;
                    sub_wait = sub_delay;
                    sub_address_phases = sub_address_phases + 1;
                    if (sub_hold_ready) HREADYEXT = 1'b0;
                end
            end else begin
                if (sub_write && HWSTRB != '0) begin
                    sub_wdata = HWDATA;
                    sub_strb = HWSTRB;
                    sub_write_data_phases = sub_write_data_phases + 1;
                end
                if (sub_hold_ready) begin
                    HREADYEXT = 1'b0;
                end else if (sub_wait > 0) begin
                    sub_wait = sub_wait - 1;
                    HREADYEXT = 1'b0;
                end else begin
                    HREADYEXT = 1'b1;
                    sub_active = 1'b0;
                end
            end
        end
    end

    // ---- checking ---------------------------------------------------------
    integer failures = 0;
    task automatic check(input logic condition, input string message);
        begin
            if (!condition) begin
                failures = failures + 1;
                $display("FAIL: %s", message);
            end
        end
    endtask

    task automatic tick();
        begin
            @(posedge clk);
            #1;   // sample the settled post-edge values
        end
    endtask

    task automatic idle(input integer cycles);
        integer index;
        begin
            req_valid = 1'b0;
            for (index = 0; index < cycles; index = index + 1) tick();
        end
    endtask

    task automatic accept_response();
        begin
            // The completion is a handshake: it must stay asserted until this
            // accepts it, and drop on the following edge.
            tick();
            check(rsp_valid, "response asserted");
            tick();
            check(rsp_valid, "completion is held until accepted");
            rsp_ready = 1'b1;
            tick();
            rsp_ready = 1'b0;
            tick();
            check(!rsp_valid, "completion released after acceptance");
        end
    endtask

    logic [DW-1:0] captured;
    logic          accepted;

    initial begin
        req_valid = 1'b0; req_write = 1'b0; req_addr = '0; req_wdata = '0;
        req_be = '0; rsp_ready = 1'b0;
        repeat (3) tick();
        rst_ni = 1'b1;
        tick();

        // ---- 1. read: address phase shape and HSIZE from byte lanes ---------
        sub_delay = 1;
        req_addr = 34'h1_0000_0004;
        req_be = 4'b1111;
        req_write = 1'b0;
        req_valid = 1'b1;
        accepted = req_ready;      // combinational handshake, sampled with the request
        tick();
        // This is the address phase.
        check(HTRANS == 2'b10, "read address phase asserts HTRANS=NONSEQ");
        check(HWRITE == 1'b0, "read address phase has HWRITE=0");
        check(HADDR == 34'h1_0000_0004, "address phase drives HADDR");
        check(HSIZE == 3'b010, "four contiguous lanes give HSIZE=32-bit");
        check(HBURST == 3'b000, "HBURST is SINGLE");
        check(HMASTLOCK == 1'b0, "HMASTLOCK is 0");
        check(HPROT == 4'b0011, "HPROT is the documented default");
        check(HWSTRB == '0, "no write strobes during a read address phase");
        check(accepted, $sformatf("request accepted while idle (req_ready=%b)", req_ready));
        req_valid = 1'b0;
        tick();
        check(HTRANS == 2'b00, "HTRANS returns to IDLE after one address phase");
        while (!rsp_valid) tick();
        captured = rsp_rdata;
        check(captured == ((34'h1_0000_0004 ^ 32'hA5A5_0000) & 32'hFFFF_FFFF),
              $sformatf("read data is HRDATAEXT masked to the transfer width (got %h want %h)",
                        captured, ((34'h1_0000_0004 ^ 32'hA5A5_0000) & 32'hFFFF_FFFF)));
        check(!rsp_error, "clean completion reports no error");
        accept_response();
        check(sub_address_phases == 1, "exactly one address phase per beat");

        // ---- 2. write: HWDATA/HWSTRB appear after the address phase ---------
        idle(2);
        sub_delay = 2;
        req_addr = 34'h1_0000_0010;
        req_wdata = 32'hDEAD_BEEF;
        req_be = 4'b0011;      // low two lanes -> 16-bit transfer
        req_write = 1'b1;
        req_valid = 1'b1;
        tick();
        check(HTRANS == 2'b10, "write address phase asserts HTRANS=NONSEQ");
        check(HWRITE == 1'b1, "write address phase has HWRITE=1");
        check(HSIZE == 3'b001, "two contiguous aligned lanes give HSIZE=16-bit");
        check(HWSTRB == '0, "write data is NOT in the address phase");
        check(HWDATA == '0, "HWDATA is NOT driven in the address phase");
        req_valid = 1'b0;
        tick();
        check(HWSTRB == 4'b0011, "HWSTRB follows the address phase");
        check(HWDATA == 32'hDEAD_BEEF, "HWDATA follows the address phase");
        while (!rsp_valid) tick();
        check(!rsp_error, "write completes cleanly");
        accept_response();
        check(sub_write_data_phases >= 1, "subordinate saw a write data phase");

        // ---- 3. error response is observed, not invented --------------------
        idle(2);
        sub_delay = 0;
        sub_error = 1'b1;
        req_addr = 34'h1_0000_0020;
        req_be = 4'b0001;
        req_write = 1'b0;
        req_valid = 1'b1;
        tick();
        req_valid = 1'b0;
        while (!rsp_valid) tick();
        check(rsp_error, "HRESPEXT=1 is reported as rsp_error_o");
        accept_response();
        sub_error = 1'b0;

        // ---- 4. a stuck subordinate times out instead of hanging ------------
        idle(2);
        sub_delay = 0;
        sub_hold_ready = 1'b1;
        req_addr = 34'h1_0000_0030;
        req_be = 4'b0001;
        req_write = 1'b0;
        req_valid = 1'b1;
        tick();
        req_valid = 1'b0;
        while (!rsp_valid) tick();
        check(rsp_error, "held HREADYEXT produces a timeout error completion");
        check(!req_ready, "the adapter is busy while a completion is outstanding");
        accept_response();
        sub_hold_ready = 1'b0;

        // ---- 5. the adapter is reusable after all of the above -------------
        idle(2);
        sub_delay = 0;
        req_addr = 34'h1_0000_0040;
        req_be = 4'b1111;
        req_write = 1'b0;
        req_valid = 1'b1;
        tick();
        req_valid = 1'b0;
        while (!rsp_valid) tick();
        check(!rsp_error, "a later transaction does not inherit the earlier error");
        accept_response();

        if (failures == 0) $display("BEAT_TO_AHB_LITE_TB: PASS");
        else $display("BEAT_TO_AHB_LITE_TB: FAIL (%0d)", failures);
        $finish;
    end

    initial begin
        #20000;
        $display("BEAT_TO_AHB_LITE_TB: FAIL (timeout)");
        $finish;
    end
endmodule
