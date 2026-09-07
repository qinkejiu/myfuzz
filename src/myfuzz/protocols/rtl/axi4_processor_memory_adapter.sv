module axi4_processor_memory_adapter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer ID_WIDTH = 1,
    parameter integer USER_WIDTH = 1
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,

    input  logic [ID_WIDTH-1:0]          awid_i,
    input  logic [ADDRESS_WIDTH-1:0]     awaddr_i,
    input  logic [7:0]                   awlen_i,
    input  logic [2:0]                   awsize_i,
    input  logic [1:0]                   awburst_i,
    input  logic                         awlock_i,
    input  logic [3:0]                   awcache_i,
    input  logic [2:0]                   awprot_i,
    input  logic [3:0]                   awqos_i,
    input  logic [3:0]                   awregion_i,
    input  logic [5:0]                   awatop_i,
    input  logic [USER_WIDTH-1:0]        awuser_i,
    input  logic                         awvalid_i,
    output logic                         awready_o,

    input  logic [DATA_WIDTH-1:0]        wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]    wstrb_i,
    input  logic                         wlast_i,
    input  logic [USER_WIDTH-1:0]        wuser_i,
    input  logic                         wvalid_i,
    output logic                         wready_o,

    output logic [ID_WIDTH-1:0]          bid_o,
    output logic [1:0]                   bresp_o,
    output logic [USER_WIDTH-1:0]        buser_o,
    output logic                         bvalid_o,
    input  logic                         bready_i,

    input  logic [ID_WIDTH-1:0]          arid_i,
    input  logic [ADDRESS_WIDTH-1:0]     araddr_i,
    input  logic [7:0]                   arlen_i,
    input  logic [2:0]                   arsize_i,
    input  logic [1:0]                   arburst_i,
    input  logic                         arlock_i,
    input  logic [3:0]                   arcache_i,
    input  logic [2:0]                   arprot_i,
    input  logic [3:0]                   arqos_i,
    input  logic [3:0]                   arregion_i,
    input  logic [USER_WIDTH-1:0]        aruser_i,
    input  logic                         arvalid_i,
    output logic                         arready_o,

    output logic [ID_WIDTH-1:0]          rid_o,
    output logic [DATA_WIDTH-1:0]        rdata_o,
    output logic [1:0]                   rresp_o,
    output logic                         rlast_o,
    output logic [USER_WIDTH-1:0]        ruser_o,
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

    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH > 1024 ||
            DATA_WIDTH % 8 != 0 || (DATA_WIDTH & (DATA_WIDTH - 1)) != 0)
            $fatal(1, "invalid AXI/backend address or data width");
        if (ID_WIDTH < 1 || ID_WIDTH > 64 || USER_WIDTH < 1 || USER_WIDTH > 256)
            $fatal(1, "invalid AXI ID or user width");
    end

    localparam logic [1:0] AXI_OKAY   = 2'b00;
    localparam logic [1:0] AXI_SLVERR = 2'b10;
    localparam logic [1:0] AXI_DECERR = 2'b11;
    localparam logic [2:0] MAX_TRANSFER_SIZE = 3'($clog2(DATA_WIDTH / 8));
    localparam logic [(DATA_WIDTH/8)-1:0] FULL_BE = {(DATA_WIDTH/8){1'b1}};

    typedef enum logic [3:0] {
        IDLE,
        WRITE_COLLECT,
        WRITE_DRAIN,
        WRITE_REQUEST,
        WRITE_RESPONSE,
        WRITE_AXI_RESPONSE,
        READ_REQUEST,
        READ_RESPONSE,
        READ_AXI_RESPONSE,
        ATOMIC_AXI_RESPONSE
    } state_t;

    state_t state_q;
    logic aw_captured_q, w_captured_q;
    logic aw_bad_q, w_bad_q;
    logic [ID_WIDTH-1:0] write_id_q, read_id_q;
    logic [ADDRESS_WIDTH-1:0] write_addr_q, read_addr_q;
    logic [DATA_WIDTH-1:0] write_data_q, read_data_q;
    logic [(DATA_WIDTH/8)-1:0] write_be_q;
    logic [1:0] write_resp_q, read_resp_q;
    logic [7:0] write_len_q, write_beats_left_q, read_beats_left_q;
    logic atomic_read_error_q, atomic_compare_q;
    logic atomic_r_pending_q, atomic_b_pending_q;

    wire collecting_write = (state_q == IDLE) || (state_q == WRITE_COLLECT);
    wire aw_take = awvalid_i && awready_o;
    wire w_take = wvalid_i && wready_o;
    wire ar_take = arvalid_i && arready_o;
    wire aw_bad = (awlen_i != 8'd0) || (awsize_i > MAX_TRANSFER_SIZE) ||
                  ((awburst_i != 2'b00) && (awburst_i != 2'b01)) ||
                  awlock_i || (awatop_i != 6'd0);
    wire ar_bad = (arlen_i != 8'd0) || (arsize_i > MAX_TRANSFER_SIZE) ||
                  ((arburst_i != 2'b00) && (arburst_i != 2'b01)) || arlock_i;
    wire completed_write = (aw_captured_q || aw_take) && (w_captured_q || w_take);
    wire completed_write_bad = aw_bad_q || w_bad_q ||
                               (aw_take && aw_bad) || (w_take && !wlast_i);
    wire [7:0] completed_write_len = aw_take ? awlen_i : write_len_q;
    wire completed_atomic_read = aw_take ? awatop_i[5] : atomic_read_error_q;
    wire completed_atomic_compare = aw_take ? (awatop_i == 6'b110001) :
                                               atomic_compare_q;
    // AWLEN is transfers-minus-one. AtomicCompare returns half as many R
    // transfers when its write payload spans multiple transfers.
    wire [7:0] completed_atomic_r_beats_left = completed_atomic_compare ?
                                                       (completed_write_len >> 1) :
                                                       completed_write_len;
    wire atomic_r_done = !atomic_r_pending_q ||
                         (rready_i && (read_beats_left_q == 8'd0));
    wire atomic_b_done = !atomic_b_pending_q || bready_i;

    assign awready_o = rst_ni && collecting_write && !aw_captured_q;
    assign wready_o = rst_ni && ((collecting_write && !w_captured_q) ||
                                 (state_q == WRITE_DRAIN));
    // A partial AW/W transaction owns the adapter.  Simultaneous write input
    // receives deterministic priority over AR rather than depending on names.
    assign arready_o = rst_ni && (state_q == IDLE) &&
                       !awvalid_i && !wvalid_i;

    assign bid_o = write_id_q;
    assign bresp_o = write_resp_q;
    assign buser_o = '0;
    assign bvalid_o = (state_q == WRITE_AXI_RESPONSE) ||
                      ((state_q == ATOMIC_AXI_RESPONSE) && atomic_b_pending_q);
    assign rid_o = read_id_q;
    assign rdata_o = read_data_q;
    assign rresp_o = read_resp_q;
    assign rlast_o = ((state_q == READ_AXI_RESPONSE) ||
                      (state_q == ATOMIC_AXI_RESPONSE)) &&
                     (read_beats_left_q == 8'd0);
    assign ruser_o = '0;
    assign rvalid_o = (state_q == READ_AXI_RESPONSE) ||
                      ((state_q == ATOMIC_AXI_RESPONSE) && atomic_r_pending_q);

    assign req_valid_o = (state_q == WRITE_REQUEST) || (state_q == READ_REQUEST);
    assign req_write_o = (state_q == WRITE_REQUEST);
    assign req_addr_o = (state_q == WRITE_REQUEST) ? write_addr_q :
                        (state_q == READ_REQUEST) ? read_addr_q : '0;
    assign req_wdata_o = (state_q == WRITE_REQUEST) ? write_data_q : '0;
    assign req_be_o = (state_q == WRITE_REQUEST) ? write_be_q :
                      (state_q == READ_REQUEST) ? FULL_BE : '0;
    assign rsp_ready_o = (state_q == WRITE_RESPONSE) || (state_q == READ_RESPONSE);

    // cache/prot/qos/region/user are explicitly accepted metadata with no
    // effect in the non-coherent beat backend.  Unsupported lock and ATOP
    // semantics are rejected above with DECERR.
    wire unused_sideband = ^{awcache_i, awprot_i, awqos_i, awregion_i,
                             awuser_i, wuser_i, arcache_i, arprot_i,
                             arqos_i, arregion_i, aruser_i};

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            aw_captured_q <= 1'b0;
            w_captured_q <= 1'b0;
            aw_bad_q <= 1'b0;
            w_bad_q <= 1'b0;
            write_id_q <= '0;
            read_id_q <= '0;
            write_addr_q <= '0;
            read_addr_q <= '0;
            write_data_q <= '0;
            read_data_q <= '0;
            write_be_q <= '0;
            write_resp_q <= AXI_OKAY;
            read_resp_q <= AXI_OKAY;
            write_len_q <= '0;
            write_beats_left_q <= '0;
            read_beats_left_q <= '0;
            atomic_read_error_q <= 1'b0;
            atomic_compare_q <= 1'b0;
            atomic_r_pending_q <= 1'b0;
            atomic_b_pending_q <= 1'b0;
        end else begin
            case (state_q)
                IDLE, WRITE_COLLECT: begin
                    if (aw_take) begin
                        aw_captured_q <= 1'b1;
                        aw_bad_q <= aw_bad;
                        write_id_q <= awid_i;
                        write_addr_q <= awaddr_i;
                        write_len_q <= awlen_i;
                        atomic_read_error_q <= awatop_i[5];
                        atomic_compare_q <= (awatop_i == 6'b110001);
                    end
                    if (w_take) begin
                        w_captured_q <= 1'b1;
                        w_bad_q <= !wlast_i;
                        write_data_q <= wdata_i;
                        write_be_q <= wstrb_i;
                    end
                    if (completed_write) begin
                        aw_captured_q <= 1'b0;
                        w_captured_q <= 1'b0;
                        aw_bad_q <= 1'b0;
                        w_bad_q <= 1'b0;
                        if (completed_write_bad) begin
                            write_resp_q <= AXI_DECERR;
                            atomic_read_error_q <= completed_atomic_read;
                            if (completed_atomic_read) begin
                                read_id_q <= aw_take ? awid_i : write_id_q;
                                read_data_q <= '0;
                                read_resp_q <= AXI_DECERR;
                                read_beats_left_q <= completed_atomic_r_beats_left;
                                atomic_r_pending_q <= 1'b1;
                                atomic_b_pending_q <= 1'b1;
                            end
                            if (completed_write_len != 8'd0) begin
                                write_beats_left_q <= completed_write_len;
                                state_q <= WRITE_DRAIN;
                            end else if (completed_atomic_read) begin
                                state_q <= ATOMIC_AXI_RESPONSE;
                            end else begin
                                state_q <= WRITE_AXI_RESPONSE;
                            end
                        end else begin
                            state_q <= WRITE_REQUEST;
                        end
                    end else if (aw_take || w_take) begin
                        state_q <= WRITE_COLLECT;
                    end else if (ar_take) begin
                        read_id_q <= arid_i;
                        read_addr_q <= araddr_i;
                        read_data_q <= '0;
                        if (ar_bad) begin
                            read_resp_q <= AXI_DECERR;
                            read_beats_left_q <= arlen_i;
                            state_q <= READ_AXI_RESPONSE;
                        end else begin
                            read_beats_left_q <= 8'd0;
                            state_q <= READ_REQUEST;
                        end
                    end
                end
                WRITE_DRAIN: begin
                    if (wvalid_i && wready_o) begin
                        if (write_beats_left_q == 8'd1) begin
                            write_beats_left_q <= 8'd0;
                            if (atomic_read_error_q)
                                state_q <= ATOMIC_AXI_RESPONSE;
                            else
                                state_q <= WRITE_AXI_RESPONSE;
                        end else begin
                            write_beats_left_q <= write_beats_left_q - 1'b1;
                        end
                    end
                end
                WRITE_REQUEST: begin
                    if (req_valid_o && req_ready_i)
                        state_q <= WRITE_RESPONSE;
                end
                WRITE_RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        write_resp_q <= rsp_error_i ? AXI_SLVERR : AXI_OKAY;
                        state_q <= WRITE_AXI_RESPONSE;
                    end
                end
                WRITE_AXI_RESPONSE: begin
                    if (bvalid_o && bready_i) begin
                        write_resp_q <= AXI_OKAY;
                        state_q <= IDLE;
                    end
                end
                READ_REQUEST: begin
                    if (req_valid_o && req_ready_i)
                        state_q <= READ_RESPONSE;
                end
                READ_RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        read_data_q <= rsp_rdata_i;
                        read_resp_q <= rsp_error_i ? AXI_SLVERR : AXI_OKAY;
                        state_q <= READ_AXI_RESPONSE;
                    end
                end
                READ_AXI_RESPONSE: begin
                    if (rvalid_o && rready_i) begin
                        if (read_beats_left_q != 8'd0) begin
                            read_beats_left_q <= read_beats_left_q - 1'b1;
                        end else begin
                            read_data_q <= '0;
                            read_resp_q <= AXI_OKAY;
                            state_q <= IDLE;
                        end
                    end
                end
                ATOMIC_AXI_RESPONSE: begin
                    if (atomic_r_pending_q && rready_i) begin
                        if (read_beats_left_q != 8'd0)
                            read_beats_left_q <= read_beats_left_q - 1'b1;
                        else
                            atomic_r_pending_q <= 1'b0;
                    end
                    if (atomic_b_pending_q && bready_i)
                        atomic_b_pending_q <= 1'b0;
                    if (atomic_r_done && atomic_b_done) begin
                        atomic_read_error_q <= 1'b0;
                        atomic_compare_q <= 1'b0;
                        atomic_r_pending_q <= 1'b0;
                        atomic_b_pending_q <= 1'b0;
                        read_resp_q <= AXI_OKAY;
                        write_resp_q <= AXI_OKAY;
                        state_q <= IDLE;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    aw_captured_q <= 1'b0;
                    w_captured_q <= 1'b0;
                    aw_bad_q <= 1'b0;
                    w_bad_q <= 1'b0;
                    atomic_read_error_q <= 1'b0;
                    atomic_compare_q <= 1'b0;
                    atomic_r_pending_q <= 1'b0;
                    atomic_b_pending_q <= 1'b0;
                    write_resp_q <= AXI_DECERR;
                    read_resp_q <= AXI_DECERR;
                end
            endcase
        end
    end

endmodule
