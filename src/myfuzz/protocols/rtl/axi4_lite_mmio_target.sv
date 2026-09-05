module axi4_lite_mmio_target #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,

    input  logic [ADDRESS_WIDTH-1:0]      awaddr_i,
    input  logic [2:0]                    awprot_i,
    input  logic                          awvalid_i,
    output logic                          awready_o,
    input  logic [DATA_WIDTH-1:0]         wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]     wstrb_i,
    input  logic                          wvalid_i,
    output logic                          wready_o,
    output logic [1:0]                    bresp_o,
    output logic                          bvalid_o,
    input  logic                          bready_i,
    input  logic [ADDRESS_WIDTH-1:0]      araddr_i,
    input  logic [2:0]                    arprot_i,
    input  logic                          arvalid_i,
    output logic                          arready_o,
    output logic [DATA_WIDTH-1:0]         rdata_o,
    output logic [1:0]                    rresp_o,
    output logic                          rvalid_o,
    input  logic                          rready_i,

    output logic                          valid_o,
    output logic                          write_o,
    output logic [ADDRESS_WIDTH-1:0]      addr_o,
    output logic [DATA_WIDTH-1:0]         wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     be_o,
    input  logic [DATA_WIDTH-1:0]         rdata_i,
    input  logic                          ready_i,
    input  logic                          error_i
);

    localparam integer EFFECTIVE_MAX_WAIT_CYCLES =
        (MAX_WAIT_CYCLES < 1) ? 1 :
        ((MAX_WAIT_CYCLES > 16) ? 16 : MAX_WAIT_CYCLES);
    localparam integer WAIT_COUNTER_WIDTH =
        (EFFECTIVE_MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(EFFECTIVE_MAX_WAIT_CYCLES);

    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [(DATA_WIDTH/8)-1:0] be_q;
    logic aw_captured_q;
    logic w_captured_q;
    logic write_active_q;
    logic read_active_q;
    logic bvalid_q;
    logic [1:0] bresp_q;
    logic rvalid_q;
    logic [DATA_WIDTH-1:0] rdata_q;
    logic [1:0] rresp_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;

    wire write_busy = aw_captured_q || w_captured_q || write_active_q || bvalid_q;
    wire read_busy = read_active_q || rvalid_q;
    wire aw_take = awvalid_i && awready_o;
    wire w_take = wvalid_i && wready_o;
    wire ar_take = arvalid_i && arready_o;

    assign awready_o = !aw_captured_q && !write_active_q && !bvalid_q && !read_busy;
    assign wready_o = !w_captured_q && !write_active_q && !bvalid_q && !read_busy;
    assign arready_o = !write_busy && !read_busy && !awvalid_i && !wvalid_i;
    assign bvalid_o = bvalid_q;
    assign bresp_o = bresp_q;
    assign rvalid_o = rvalid_q;
    assign rdata_o = rdata_q;
    assign rresp_o = rresp_q;
    assign valid_o = write_active_q || read_active_q;
    assign write_o = write_active_q;
    assign addr_o = (write_active_q || read_active_q) ? addr_q : '0;
    assign wdata_o = write_active_q ? wdata_q : '0;
    assign be_o = write_active_q ? be_q : '0;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            aw_captured_q <= 1'b0;
            w_captured_q <= 1'b0;
            write_active_q <= 1'b0;
            read_active_q <= 1'b0;
            bvalid_q <= 1'b0;
            bresp_q <= 2'b00;
            rvalid_q <= 1'b0;
            rdata_q <= '0;
            rresp_q <= 2'b00;
            wait_count_q <= '0;
        end else begin
            if (bvalid_q && bready_i) begin
                bvalid_q <= 1'b0;
                bresp_q <= 2'b00;
            end
            if (rvalid_q && rready_i) begin
                rvalid_q <= 1'b0;
                rdata_q <= '0;
                rresp_q <= 2'b00;
            end

            if (write_active_q) begin
                if (ready_i) begin
                    write_active_q <= 1'b0;
                    bvalid_q <= 1'b1;
                    bresp_q <= error_i ? 2'b10 : 2'b00;
                    wait_count_q <= '0;
                end else if (wait_count_q == EFFECTIVE_MAX_WAIT_CYCLES - 1) begin
                    write_active_q <= 1'b0;
                    bvalid_q <= 1'b1;
                    bresp_q <= 2'b10;
                    wait_count_q <= '0;
                end else begin
                    wait_count_q <= wait_count_q + 1'b1;
                end
            end else if (read_active_q) begin
                if (ready_i) begin
                    read_active_q <= 1'b0;
                    rvalid_q <= 1'b1;
                    rdata_q <= rdata_i;
                    rresp_q <= error_i ? 2'b10 : 2'b00;
                    wait_count_q <= '0;
                end else if (wait_count_q == EFFECTIVE_MAX_WAIT_CYCLES - 1) begin
                    read_active_q <= 1'b0;
                    rvalid_q <= 1'b1;
                    rdata_q <= '0;
                    rresp_q <= 2'b10;
                    wait_count_q <= '0;
                end else begin
                    wait_count_q <= wait_count_q + 1'b1;
                end
            end else if (!write_busy && !read_busy && ar_take) begin
                addr_q <= araddr_i;
                read_active_q <= 1'b1;
                wait_count_q <= '0;
            end else if (!read_busy) begin
                if (aw_take) begin
                    addr_q <= awaddr_i;
                    aw_captured_q <= 1'b1;
                end
                if (w_take) begin
                    wdata_q <= wdata_i;
                    be_q <= wstrb_i;
                    w_captured_q <= 1'b1;
                end
                if ((aw_captured_q || aw_take) && (w_captured_q || w_take)) begin
                    aw_captured_q <= 1'b0;
                    w_captured_q <= 1'b0;
                    write_active_q <= 1'b1;
                    wait_count_q <= '0;
                end
            end
        end
    end

endmodule
