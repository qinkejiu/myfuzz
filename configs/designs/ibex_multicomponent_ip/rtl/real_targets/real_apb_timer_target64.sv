module real_apb_timer_target64 (
    input  logic        clock,
    input  logic        reset,
    input  logic        req_valid,
    output logic        req_ready,
    input  logic        write,
    input  logic [63:0] addr,
    input  logic [63:0] wdata,
    input  logic [7:0]  be,
    output logic        rsp_valid,
    input  logic        rsp_ready,
    output logic [63:0] rdata,
    output logic        error
);
    logic [63:0] paddr, pwdata, prdata;
    logic [7:0] pstrb;
    logic [2:0] pprot;
    logic psel, penable, pwrite, pready, pslverr;
    logic mmio_valid, mmio_write;
    logic [63:0] mmio_addr, mmio_wdata, mmio_rdata;
    logic [7:0] mmio_be;
    logic [31:0] native_rdata;
    logic native_valid, native_write, lane_error;
    logic [31:0] native_addr, native_wdata;
    logic [3:0] native_be;
    logic reset_probe_q;

    always_ff @(posedge clock) begin
        if (!reset) reset_probe_q <= 1'b0;
        else reset_probe_q <= 1'b1;
    end

    apb4_mmio_bridge #(.ADDRESS_WIDTH(64), .DATA_WIDTH(64)) u_bridge (
        .clk_i(clock), .rst_ni(reset), .req_valid_i(req_valid), .req_write_i(write),
        .req_addr_i(addr), .req_wdata_i(wdata), .req_be_i(be), .req_ready_o(req_ready),
        .rsp_valid_o(rsp_valid), .rsp_ready_i(rsp_ready), .rsp_rdata_o(rdata),
        .rsp_error_o(error), .paddr_o(paddr), .pprot_o(pprot), .psel_o(psel),
        .penable_o(penable), .pwrite_o(pwrite), .pwdata_o(pwdata), .pstrb_o(pstrb),
        .pready_i(pready), .prdata_i(prdata), .pslverr_i(pslverr)
    );

    apb4_mmio_target #(.ADDRESS_WIDTH(64), .DATA_WIDTH(64)) u_target (
        .clk_i(clock), .rst_ni(reset), .paddr_i(paddr), .pprot_i(pprot), .psel_i(psel),
        .penable_i(penable), .pwrite_i(pwrite), .pwdata_i(pwdata), .pstrb_i(pstrb),
        .pready_o(pready), .prdata_o(prdata), .pslverr_o(pslverr),
        .valid_o(mmio_valid), .write_o(mmio_write), .addr_o(mmio_addr),
        .wdata_o(mmio_wdata), .be_o(mmio_be), .rdata_i(mmio_rdata), .ready_i(1'b1),
        .error_i(lane_error)
    );

    real_64_to_32_lane #(.ALLOW_PARTIAL_WRITES(1'b0)) u_lane_guard (
        .mmio_valid(mmio_valid), .mmio_write(mmio_write), .mmio_addr(mmio_addr),
        .mmio_wdata(mmio_wdata), .mmio_be(mmio_be), .mmio_rdata(mmio_rdata),
        .mmio_error(lane_error), .native_valid(native_valid),
        .native_write(native_write), .native_addr(native_addr),
        .native_wdata(native_wdata), .native_be(native_be),
        .native_rdata(native_rdata)
    );

    ibex_mcip_timer u_timer (
        .clk_i(clock), .rst_ni(reset), .valid_i(native_valid), .write_i(native_write),
        .addr_i(native_addr), .wdata_i(native_wdata), .tick_i(1'b0),
        .rdata_o(native_rdata), .irq_o(), .state_o()
    );
endmodule
