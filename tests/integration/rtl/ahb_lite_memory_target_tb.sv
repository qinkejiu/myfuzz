// Self-checking testbench for ahb_lite_memory_target (the AHB-Lite subordinate).
//
// CVW is the AHB manager, so the facts that matter are the *subordinate* rules:
// a transfer starts on a real HTRANS, HWDATA/HWSTRB are sampled one cycle AFTER
// the address phase, completion happens on the edge HREADYEXT is high, an idle
// HTRANS is not a transfer, and a service that never answers becomes an error
// completion instead of holding the CPU.
`timescale 1ns/1ps
module ahb_lite_memory_target_tb;
    localparam integer AW = 34, DW = 32, MAX_WAIT = 4;
    logic clk = 0; always #5 clk = ~clk;
    logic rst_ni = 0;

    logic [1:0] HTRANS = 0; logic [AW-1:0] HADDR = 0; logic HWRITE = 0;
    logic [2:0] HSIZE = 3'b010, HBURST = 0; logic [3:0] HPROT = 0;
    logic HMASTLOCK = 0, HSELEXT = 1;
    logic [DW-1:0] HWDATA = 0; logic [3:0] HWSTRB = 0;
    logic HREADYEXT; logic [DW-1:0] HRDATAEXT; logic HRESPEXT;

    logic req_valid, req_ready = 0, req_write;
    logic [AW-1:0] req_addr; logic [DW-1:0] req_wdata; logic [3:0] req_be;
    logic rsp_valid = 0, rsp_ready, rsp_error = 0; logic [DW-1:0] rsp_rdata = 0;

    ahb_lite_memory_target #(.ADDRESS_WIDTH(AW), .DATA_WIDTH(DW),
                             .MAX_WAIT_CYCLES(MAX_WAIT)) dut (
        .clk_i(clk), .rst_ni(rst_ni),
        .HTRANS, .HADDR, .HWRITE, .HSIZE, .HBURST, .HPROT, .HMASTLOCK, .HSELEXT,
        .HWDATA, .HWSTRB, .HREADYEXT, .HRDATAEXT, .HRESPEXT,
        .req_valid_o(req_valid), .req_ready_i(req_ready), .req_write_o(req_write),
        .req_addr_o(req_addr), .req_wdata_o(req_wdata), .req_be_o(req_be),
        .rsp_valid_i(rsp_valid), .rsp_ready_o(rsp_ready),
        .rsp_rdata_i(rsp_rdata), .rsp_error_i(rsp_error));

    integer failures = 0;
    task automatic check(input logic condition, input string message);
        begin
            if (!condition) begin failures = failures + 1; $display("FAIL: %s", message); end
        end
    endtask
    task automatic tick(); begin @(posedge clk); #1; end endtask

    initial begin
        repeat (2) tick();
        rst_ni = 1;
        tick();

        // ---- 1. an IDLE HTRANS is not a transfer -------------------------
        HTRANS = 2'b00; HSELEXT = 1; tick();
        check(!req_valid, "IDLE is not a transfer");
        check(HREADYEXT, "an idle subordinate holds HREADYEXT high so the next address phase completes");

        // ---- 2. a read transfer: address phase then completion ------------
        HTRANS = 2'b10; HADDR = 34'h0000_0004; HWRITE = 0; HWDATA = 32'h0; HWSTRB = 4'b0000;
        check(HREADYEXT, "HREADYEXT is high as the address phase is presented");
        tick();   // the address phase completes on this edge: HADDR is now captured
        check(!HREADYEXT, "the transfer is now outstanding, so HREADYEXT is low");
        // The beat request is a promise that the whole request is valid, so for a
        // write it may only appear once the data phase has been latched.  That
        // makes the request visible one edge after the address phase, once the
        // sequential block has published the captured address.
        check(!req_valid, "the request is not raised from the same edge that captures the address");
        tick();
        check(req_valid, "NONSEQ raises a beat request");
        check(!req_write, "read request is not a write");
        check(req_addr == 34'h0000_0004, "request carries the accepted HADDR");
        check(req_be == 4'b1111, "a read offers full byte lanes");
        check(!HREADYEXT, "a transfer in progress holds HREADYEXT low");
        // The service accepts, then answers.
        // The service accepts the request, then presents the answer on the next
        // edge (non-blocking assignment), which is the edge that completes it.
        req_ready = 1; tick();
        req_ready = 0;
        check(rsp_ready, "the target is ready to take the response");
        rsp_rdata = 32'hDEAD_BEEF; rsp_valid = 1;
        HTRANS = 2'b00;   // no next transfer: HREADYEXT is high on this edge
        tick();
        check(HREADYEXT, "completion asserts HREADYEXT on the answering edge");
        check(HRDATAEXT == 32'hDEAD_BEEF, "read data comes from the service");
        check(!HRESPEXT, "clean read has no error");
        rsp_valid = 0; tick();
        check(!req_valid, "the target returns to idle after completing");

        // ---- 3. a write transfer samples HWDATA one cycle after HADDR ------
        HTRANS = 2'b10; HADDR = 34'h0000_0010; HWRITE = 1;
        HWDATA = 32'hA5A5_1234; HWSTRB = 4'b0011;
        tick();   // the address phase completes here; HWDATA is NOT sampled yet
        check(!req_valid,
              "a write does not surface a request before its data phase is latched");
        tick();   // the data phase is latched on this edge
        check(req_valid && req_write, "write raises a write request");
        check(req_wdata == 32'hA5A5_1234, "write data is presented to the service");
        check(req_be == 4'b0011, "write strobes are presented to the service");
        req_ready = 1; tick(); req_ready = 0;
        rsp_valid = 1; HTRANS = 2'b00;   // no next transfer on the completion edge
        tick();
        check(HREADYEXT, "write completes on the ready edge");
        rsp_valid = 0; tick();

        // ---- 4. an unanswered transfer is held, not falsely completed ------
        // The CPU has no error pin, so the subordinate must not invent an error
        // completion; it extends the transfer by holding HREADYEXT low.
        HTRANS = 2'b10; HADDR = 34'h0000_0020; HWRITE = 0;
        tick();   // the address phase completes here
        check(!req_valid, "the second transfer also raises its request one edge later");
        tick();
        check(req_valid, "second request raised");
        repeat (MAX_WAIT + 2) tick();
        check(!HREADYEXT, "an unanswered transfer is held, not completed");
        check(!HRESPEXT, "no error is invented while the service has not answered");
        // The service answers late; the transfer then completes normally.
        req_ready = 1; tick(); req_ready = 0;
        rsp_rdata = 32'h1234_5678; rsp_valid = 1;
        HTRANS = 2'b00;   // no next transfer on the completing edge
        tick();
        check(HREADYEXT, "the held transfer completes once the service answers");
        check(!HRESPEXT, "a late but clean answer is not an error");
        rsp_valid = 0; tick();

        // ---- 5. pipelined beats: HREADYEXT high means the NEXT address phase
        // is accepted on the completing edge.  A cache line fill depends on this,
        // and dropping it lost every second beat (addresses stepped by 8 instead of
        // 4, scrambling the fetched line).
        HTRANS = 2'b10; HADDR = 34'h0000_0040; HWRITE = 0;
        tick();                       // capture A (address phase completes)
        tick();                       // request for A is visible
        check(req_valid && req_addr == 34'h0000_0040, "first pipelined beat is requested");
        req_ready = 1; tick(); req_ready = 0;
        check(rsp_ready, "the service is taken for the first pipelined beat");
        // The manager presents the SECOND beat's address phase while HREADYEXT is
        // still high, i.e. exactly on the edge that completes the first beat.
        HADDR = 34'h0000_0044; HTRANS = 2'b11;   // SEQ: next beat of the burst
        rsp_rdata = 32'h1111_1111; rsp_valid = 1;
        check(HREADYEXT, "the first pipelined beat is completing on this edge");
        tick();                       // first beat completes; B is captured here
        rsp_valid = 0;
        check(dut.state_q == 1, "the next beat was taken, so the target is in ADDRESS");
        check(req_addr == 34'h0000_0044,
              "the pipelined beat's address was captured, not the completed one");
        tick();
        check(req_valid, "the second pipelined beat is served, not dropped");
        check(req_addr == 34'h0000_0044,
              "the second pipelined beat carries the next address, not the previous one");
        req_ready = 1; tick(); req_ready = 0;
        rsp_rdata = 32'h2222_2222; rsp_valid = 1; HTRANS = 2'b00;
        tick();
        check(HREADYEXT, "the second pipelined beat completes");
        rsp_valid = 0; tick();

        if (failures == 0) $display("AHB_LITE_MEMORY_TARGET_TB: PASS");
        else $display("AHB_LITE_MEMORY_TARGET_TB: FAIL (%0d)", failures);
        $finish;
    end
    initial begin #20000; $display("AHB_LITE_MEMORY_TARGET_TB: FAIL (timeout)"); $finish; end
endmodule
