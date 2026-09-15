// axi4_lite_processor_memory_adapter: CPU-side AXI4-Lite initiator to the
// generic processor-memory-beat backend.
//
// DIRECTION
//   AXI4-Lite MASTER (a real CPU such as the PicoRV32's AXI4-Lite port) -> this
//   adapter -> the generic fabric's beat request/response backend.  The
//   peripheral side of AXI4-Lite already exists as axi4_lite_mmio_bridge /
//   axi4_lite_mmio_target; those drive a target and are not reused backwards.
//
//   The CPU is the AXI4-Lite master, so the ports this adapter samples are the
//   master's outputs (aw*/w*/ar*/bready/rready) and the ports it drives are the
//   master's inputs (awready/wready/b*/arready/r*).  Port names are adapter
//   centric, matching the other *_processor_memory_adapter modules.
//
// WHY THIS IS NOT THE AXI4 ADAPTER
//   AXI4-Lite is a separate AMBA protocol: every transfer is a single beat, there
//   are no IDs, no bursts, no atomics and no cache/qos/region sidebands.  A CPU
//   that only implements the Lite subset therefore cannot declare axi4@1 without
//   claiming channels it does not have.  This adapter publishes exactly the Lite
//   channels and nothing else.
//
// TRANSFER RULES (one outstanding transaction)
//   * AW and W are accepted independently and in either order, as the protocol
//     allows, and are buffered until both have arrived; one beat write is then
//     issued.  The write data and byte enables are the ones captured with W, so
//     B cannot be attributed to a later write.
//   * AR is accepted only when no write is being collected or issued, so
//     simultaneous write and read address activity has a deterministic outcome:
//     the write wins.  A read is never silently dropped, it is simply not
//     accepted in that cycle (ARREADY low is legal backpressure).
//   * B and R are each held until their ready is asserted.  BRESP/RRESP are
//     OKAY, or SLVERR when the backend reports an error; errored read data is
//     forced to zero so it can never be mistaken for a payload.
//   * AWPROT and ARPROT are accepted and ignored, the same policy the AXI4
//     adapter applies to its protection sidebands.  No behaviour is invented.
//
// RESET
//   rst_ni is synchronous and active low, matching the other CPU-side adapters.

module axi4_lite_processor_memory_adapter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,

    input  logic [ADDRESS_WIDTH-1:0]     awaddr_i,
    input  logic [2:0]                   awprot_i,
    input  logic                         awvalid_i,
    output logic                         awready_o,
    input  logic [DATA_WIDTH-1:0]        wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]    wstrb_i,
    input  logic                         wvalid_i,
    output logic                         wready_o,
    output logic [1:0]                   bresp_o,
    output logic                         bvalid_o,
    input  logic                         bready_i,
    input  logic [ADDRESS_WIDTH-1:0]     araddr_i,
    input  logic [2:0]                   arprot_i,
    input  logic                         arvalid_i,
    output logic                         arready_o,
    output logic [DATA_WIDTH-1:0]        rdata_o,
    output logic [1:0]                   rresp_o,
    output logic                         rvalid_o,
    input  logic                         rready_i,

    output logic                         req_valid_o,
    input  logic                         req_ready_i,
    output logic                         req_write_o,
    output logic [ADDRESS_WIDTH-1:0]     req_addr_o,
    output logic [DATA_WIDTH-1:0]        req_wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]    req_be_o,
    input  logic                         rsp_valid_i,
    output logic                         rsp_ready_o,
    input  logic [DATA_WIDTH-1:0]        rsp_rdata_i,
    input  logic                         rsp_error_i
);
    localparam logic [1:0] AXI_OKAY = 2'b00;
    localparam logic [1:0] AXI_SLVERR = 2'b10;

    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH > 1024 ||
            DATA_WIDTH % 8 != 0 || (DATA_WIDTH & (DATA_WIDTH - 1)) != 0)
            $fatal(1, "invalid AXI4-Lite/backend address or data width");
    end

    typedef enum logic [2:0] {
        IDLE,
        WRITE_REQUEST,
        WRITE_RESPONSE,
        B_REPLY,
        READ_REQUEST,
        READ_RESPONSE,
        R_REPLY
    } state_t;
    state_t state_q;

    logic aw_captured_q, w_captured_q;
    logic [ADDRESS_WIDTH-1:0] aw_addr_q, ar_addr_q;
    logic [DATA_WIDTH-1:0] w_data_q, r_data_q;
    logic [(DATA_WIDTH/8)-1:0] w_strb_q;
    logic [1:0] b_resp_q, r_resp_q;

    wire aw_take = awvalid_i && awready_o;
    wire w_take = wvalid_i && wready_o;
    wire ar_take = arvalid_i && arready_o;
    wire write_ready = aw_captured_q || aw_take;
    wire write_has_data = w_captured_q || w_take;
    // A write may still start while we are idle or while its request is being
    // taken by the backend, so both write channels are accepted in either order.
    wire write_open = (state_q == IDLE) || (state_q == WRITE_REQUEST);

    // AW and W are independent channels and may arrive in either order.
    assign awready_o = rst_ni && write_open && !aw_captured_q;
    assign wready_o = rst_ni && write_open && !w_captured_q;
    // A write already in flight owns the adapter, so AR is not accepted while one
    // is being collected or issued: simultaneous write and read address activity
    // resolves deterministically in favour of the write.
    assign arready_o = rst_ni && (state_q == IDLE) && !aw_captured_q && !w_captured_q &&
                       !awvalid_i && !wvalid_i;

    assign req_valid_o = rst_ni &&
                         ((state_q == WRITE_REQUEST) || (state_q == READ_REQUEST));
    assign req_write_o = (state_q == WRITE_REQUEST);
    assign req_addr_o = (state_q == WRITE_REQUEST) ? aw_addr_q :
                        (state_q == READ_REQUEST) ? ar_addr_q : '0;
    assign req_wdata_o = (state_q == WRITE_REQUEST) ? w_data_q : '0;
    assign req_be_o = (state_q == WRITE_REQUEST) ? w_strb_q : '0;
    assign rsp_ready_o = rst_ni &&
                         ((state_q == WRITE_RESPONSE) || (state_q == READ_RESPONSE));

    assign bresp_o = b_resp_q;
    assign bvalid_o = (state_q == B_REPLY);
    assign rdata_o = r_data_q;
    assign rresp_o = r_resp_q;
    assign rvalid_o = (state_q == R_REPLY);

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            aw_captured_q <= 1'b0;
            w_captured_q <= 1'b0;
            aw_addr_q <= '0;
            ar_addr_q <= '0;
            w_data_q <= '0;
            w_strb_q <= '0;
            r_data_q <= '0;
            b_resp_q <= AXI_OKAY;
            r_resp_q <= AXI_OKAY;
        end else begin
            case (state_q)
                IDLE: begin
                    b_resp_q <= AXI_OKAY;
                    r_resp_q <= AXI_OKAY;
                    if (aw_take) begin
                        aw_captured_q <= 1'b1;
                        aw_addr_q <= awaddr_i;
                    end
                    if (w_take) begin
                        w_captured_q <= 1'b1;
                        w_data_q <= wdata_i;
                        w_strb_q <= wstrb_i;
                    end
                    if (ar_take) begin
                        ar_addr_q <= araddr_i;
                        state_q <= READ_REQUEST;
                    end else if (write_ready && write_has_data) begin
                        state_q <= WRITE_REQUEST;
                    end
                end
                WRITE_REQUEST: begin
                    if (aw_take) begin
                        aw_captured_q <= 1'b1;
                        aw_addr_q <= awaddr_i;
                    end
                    if (w_take) begin
                        w_captured_q <= 1'b1;
                        w_data_q <= wdata_i;
                        w_strb_q <= wstrb_i;
                    end
                    if (req_valid_o && req_ready_i) state_q <= WRITE_RESPONSE;
                end
                WRITE_RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        b_resp_q <= rsp_error_i ? AXI_SLVERR : AXI_OKAY;
                        state_q <= B_REPLY;
                    end
                end
                B_REPLY: begin
                    if (bvalid_o && bready_i) begin
                        aw_captured_q <= 1'b0;
                        w_captured_q <= 1'b0;
                        b_resp_q <= AXI_OKAY;
                        state_q <= IDLE;
                    end
                end
                READ_REQUEST: begin
                    if (req_valid_o && req_ready_i) state_q <= READ_RESPONSE;
                end
                READ_RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        r_data_q <= rsp_error_i ? '0 : rsp_rdata_i;
                        r_resp_q <= rsp_error_i ? AXI_SLVERR : AXI_OKAY;
                        state_q <= R_REPLY;
                    end
                end
                R_REPLY: begin
                    if (rvalid_o && rready_i) begin
                        r_data_q <= '0;
                        r_resp_q <= AXI_OKAY;
                        state_q <= IDLE;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    aw_captured_q <= 1'b0;
                    w_captured_q <= 1'b0;
                    b_resp_q <= AXI_SLVERR;
                    r_resp_q <= AXI_SLVERR;
                end
            endcase
        end
    end
endmodule
