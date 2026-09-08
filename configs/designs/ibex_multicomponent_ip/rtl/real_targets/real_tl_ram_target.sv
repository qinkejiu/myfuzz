module real_tl_ram_target #(
    parameter int WORDS = 16384
) (
    input  logic        clock,
    input  logic        reset,
    input  logic        req_valid,
    output logic        req_ready,
    input  logic        write,
    input  logic [31:0] addr,
    input  logic [31:0] wdata,
    input  logic [3:0]  be,
    output logic        rsp_valid,
    input  logic        rsp_ready,
    output logic [31:0] rdata,
    output logic        error
);
    logic a_valid, a_ready, a_corrupt;
    logic [2:0] a_opcode, a_param, a_size;
    logic [0:0] a_source;
    logic [31:0] a_address, a_data;
    logic [3:0] a_mask;
    logic d_valid, d_ready, d_denied, d_corrupt;
    logic [2:0] d_opcode, d_size;
    logic [1:0] d_param;
    logic [0:0] d_source, d_sink;
    logic [31:0] d_data;
    logic mmio_valid, mmio_write;
    logic [31:0] mmio_addr, mmio_wdata, mmio_be, mmio_rdata;
    logic reset_probe_q;

    always_ff @(posedge clock) begin
        if (!reset) reset_probe_q <= 1'b0;
        else reset_probe_q <= 1'b1;
    end

    tl_ul_mmio_bridge #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_bridge (
        .clk_i(clock), .rst_ni(reset),
        .req_valid_i(req_valid), .req_write_i(write), .req_addr_i(addr),
        .req_wdata_i(wdata), .req_be_i(be), .req_ready_o(req_ready),
        .rsp_valid_o(rsp_valid), .rsp_ready_i(rsp_ready),
        .rsp_rdata_o(rdata), .rsp_error_o(error),
        .a_valid_o(a_valid), .a_ready_i(a_ready), .a_opcode_o(a_opcode),
        .a_param_o(a_param), .a_size_o(a_size), .a_source_o(a_source),
        .a_address_o(a_address), .a_mask_o(a_mask), .a_data_o(a_data),
        .a_corrupt_o(a_corrupt), .d_valid_i(d_valid), .d_ready_o(d_ready),
        .d_opcode_i(d_opcode), .d_param_i(d_param), .d_size_i(d_size),
        .d_source_i(d_source), .d_sink_i(d_sink), .d_denied_i(d_denied),
        .d_data_i(d_data), .d_corrupt_i(d_corrupt)
    );

    tl_ul_mmio_target #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_target (
        .clk_i(clock), .rst_ni(reset), .a_valid_i(a_valid), .a_ready_o(a_ready),
        .a_opcode_i(a_opcode), .a_param_i(a_param), .a_size_i(a_size),
        .a_source_i(a_source), .a_address_i(a_address), .a_mask_i(a_mask),
        .a_data_i(a_data), .a_corrupt_i(a_corrupt), .d_valid_o(d_valid),
        .d_ready_i(d_ready), .d_opcode_o(d_opcode), .d_param_o(d_param),
        .d_size_o(d_size), .d_source_o(d_source), .d_sink_o(d_sink),
        .d_denied_o(d_denied), .d_data_o(d_data), .d_corrupt_o(d_corrupt),
        .valid_o(mmio_valid), .write_o(mmio_write), .addr_o(mmio_addr),
        .wdata_o(mmio_wdata), .be_o(mmio_be[3:0]), .rdata_i(mmio_rdata),
        .ready_i(1'b1), .error_i(1'b0)
    );

    ibex_mcip_ram #(.WORDS(WORDS), .COHERENT(1'b1)) u_ram (
        .clk_i(clock), .rst_ni(reset), .valid_i(mmio_valid), .write_i(mmio_write),
        .addr_i(mmio_addr), .wdata_i(mmio_wdata), .be_i(mmio_be[3:0]),
        .seed_i(32'h52414d31), .rdata_o(mmio_rdata), .state_o()
    );
endmodule
