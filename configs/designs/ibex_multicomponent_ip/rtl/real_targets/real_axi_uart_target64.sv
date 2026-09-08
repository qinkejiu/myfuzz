module real_axi_uart_target64 (
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
    logic [63:0] awaddr, araddr, wdata_axi, rdata_axi;
    logic [7:0] wstrb;
    logic [2:0] awprot, arprot;
    logic awvalid, awready, wvalid, wready, bvalid, bready;
    logic arvalid, arready, rvalid, rready;
    logic [1:0] bresp, rresp;
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

    axi4_lite_mmio_bridge #(.ADDRESS_WIDTH(64), .DATA_WIDTH(64)) u_bridge (
        .clk_i(clock), .rst_ni(reset), .req_valid_i(req_valid), .req_write_i(write),
        .req_addr_i(addr), .req_wdata_i(wdata), .req_be_i(be), .req_ready_o(req_ready),
        .rsp_valid_o(rsp_valid), .rsp_ready_i(rsp_ready), .rsp_rdata_o(rdata),
        .rsp_error_o(error), .awaddr_o(awaddr), .awprot_o(awprot), .awvalid_o(awvalid),
        .awready_i(awready), .wdata_o(wdata_axi), .wstrb_o(wstrb), .wvalid_o(wvalid),
        .wready_i(wready), .bresp_i(bresp), .bvalid_i(bvalid), .bready_o(bready),
        .araddr_o(araddr), .arprot_o(arprot), .arvalid_o(arvalid), .arready_i(arready),
        .rdata_i(rdata_axi), .rresp_i(rresp), .rvalid_i(rvalid), .rready_o(rready)
    );

    axi4_lite_mmio_target #(.ADDRESS_WIDTH(64), .DATA_WIDTH(64)) u_target (
        .clk_i(clock), .rst_ni(reset), .awaddr_i(awaddr), .awprot_i(awprot),
        .awvalid_i(awvalid), .awready_o(awready), .wdata_i(wdata_axi), .wstrb_i(wstrb),
        .wvalid_i(wvalid), .wready_o(wready), .bresp_o(bresp), .bvalid_o(bvalid),
        .bready_i(bready), .araddr_i(araddr), .arprot_i(arprot), .arvalid_i(arvalid),
        .arready_o(arready), .rdata_o(rdata_axi), .rresp_o(rresp), .rvalid_o(rvalid),
        .rready_i(rready), .valid_o(mmio_valid), .write_o(mmio_write),
        .addr_o(mmio_addr), .wdata_o(mmio_wdata), .be_o(mmio_be), .rdata_i(mmio_rdata),
        .ready_i(1'b1), .error_i(lane_error)
    );

    real_64_to_32_lane #(.ALLOW_PARTIAL_WRITES(1'b0)) u_lane_guard (
        .mmio_valid(mmio_valid), .mmio_write(mmio_write), .mmio_addr(mmio_addr),
        .mmio_wdata(mmio_wdata), .mmio_be(mmio_be), .mmio_rdata(mmio_rdata),
        .mmio_error(lane_error), .native_valid(native_valid),
        .native_write(native_write), .native_addr(native_addr),
        .native_wdata(native_wdata), .native_be(native_be),
        .native_rdata(native_rdata)
    );

    ibex_mcip_uart u_uart (
        .clk_i(clock), .rst_ni(reset), .valid_i(native_valid), .write_i(native_write),
        .addr_i(native_addr), .wdata_i(native_wdata), .rx_valid_i(1'b0),
        .rx_data_i(8'h00), .rdata_o(native_rdata), .irq_o(), .state_o()
    );
endmodule
