module generic_processor_fixture (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic [7:0]  random_i,
    output logic        instruction_identity_o,

    output logic        obi_req_o,
    input  logic        obi_gnt_i,
    output logic [31:0] obi_addr_o,
    output logic        obi_we_o,
    output logic [31:0] obi_wdata_o,
    output logic [3:0]  obi_be_o,
    input  logic        obi_rvalid_i,
    input  logic [31:0] obi_rdata_i,
    input  logic        obi_error_i,

    output logic [3:0]  axi_awid_o,
    output logic [31:0] axi_awaddr_o,
    output logic [7:0]  axi_awlen_o,
    output logic [2:0]  axi_awsize_o,
    output logic [1:0]  axi_awburst_o,
    output logic        axi_awlock_o,
    output logic [3:0]  axi_awcache_o,
    output logic [2:0]  axi_awprot_o,
    output logic [3:0]  axi_awqos_o,
    output logic [3:0]  axi_awregion_o,
    output logic [5:0]  axi_awatop_o,
    output logic [2:0]  axi_awuser_o,
    output logic        axi_awvalid_o,
    input  logic        axi_awready_i,
    output logic [31:0] axi_wdata_o,
    output logic [3:0]  axi_wstrb_o,
    output logic        axi_wlast_o,
    output logic [2:0]  axi_wuser_o,
    output logic        axi_wvalid_o,
    input  logic        axi_wready_i,
    input  logic [3:0]  axi_bid_i,
    input  logic [1:0]  axi_bresp_i,
    input  logic [2:0]  axi_buser_i,
    input  logic        axi_bvalid_i,
    output logic        axi_bready_o,
    output logic [3:0]  axi_arid_o,
    output logic [31:0] axi_araddr_o,
    output logic [7:0]  axi_arlen_o,
    output logic [2:0]  axi_arsize_o,
    output logic [1:0]  axi_arburst_o,
    output logic        axi_arlock_o,
    output logic [3:0]  axi_arcache_o,
    output logic [2:0]  axi_arprot_o,
    output logic [3:0]  axi_arqos_o,
    output logic [3:0]  axi_arregion_o,
    output logic [2:0]  axi_aruser_o,
    output logic        axi_arvalid_o,
    input  logic        axi_arready_i,
    input  logic [3:0]  axi_rid_i,
    input  logic [31:0] axi_rdata_i,
    input  logic [1:0]  axi_rresp_i,
    input  logic        axi_rlast_i,
    input  logic [2:0]  axi_ruser_i,
    input  logic        axi_rvalid_i,
    output logic        axi_rready_o,

    output logic        tl_a_valid_o,
    input  logic        tl_a_ready_i,
    output logic [2:0]  tl_a_opcode_o,
    output logic [2:0]  tl_a_param_o,
    output logic [2:0]  tl_a_size_o,
    output logic        tl_a_source_o,
    output logic [31:0] tl_a_address_o,
    output logic [3:0]  tl_a_mask_o,
    output logic [31:0] tl_a_data_o,
    output logic        tl_a_corrupt_o,
    input  logic        tl_d_valid_i,
    output logic        tl_d_ready_o,
    input  logic [2:0]  tl_d_opcode_i,
    input  logic [2:0]  tl_d_param_i,
    input  logic [2:0]  tl_d_size_i,
    input  logic        tl_d_source_i,
    input  logic        tl_d_sink_i,
    input  logic        tl_d_denied_i,
    input  logic [31:0] tl_d_data_i,
    input  logic        tl_d_corrupt_i,

    output logic        done_o,
    output logic [7:0]  accepted_o,
    output logic [7:0]  completions_o,
    output logic [31:0] readback_o,
    output logic [7:0]  errors_o,
    output logic [15:0] cycles_o
);
    localparam logic [31:0] INSTRUCTION = 32'h13579bdf;
    localparam logic [31:0] INITIAL_DATA = 32'haabbccdd;
    localparam logic [31:0] WRITE_DATA = 32'h11223344;
    localparam logic [31:0] FINAL_DATA = 32'haabb3344;

    logic [2:0] operation_q;
    logic [1:0] protocol_q;
    logic waiting_q;
    logic axi_aw_accepted_q;
    logic axi_w_accepted_q;
    logic accepted;
    logic [1:0] accepted_protocol;
    logic completed;
    logic [31:0] completion_data;
    logic completion_error;
    logic requesting;
    logic writing;
    logic [31:0] address;

    wire axi_aw_take = axi_awvalid_o && (axi_awready_i === 1'b1);
    wire axi_w_take = axi_wvalid_o && (axi_wready_i === 1'b1);
    wire axi_write_accepted = requesting && writing &&
                              (axi_aw_accepted_q || axi_aw_take) &&
                              (axi_w_accepted_q || axi_w_take);

    assign requesting = !done_o && !waiting_q;
    assign writing = operation_q == 3'd2;
    assign instruction_identity_o = !writing;
    assign address = operation_q == 3'd0 ? 32'h0 : 32'h4;

    assign obi_req_o = requesting;
    assign obi_addr_o = address;
    assign obi_we_o = writing;
    assign obi_wdata_o = WRITE_DATA;
    assign obi_be_o = writing ? 4'b0011 : 4'b1111;

    assign axi_awid_o = '0;
    assign axi_awaddr_o = address;
    assign axi_awlen_o = '0;
    assign axi_awsize_o = 3'd2;
    assign axi_awburst_o = 2'b01;
    assign axi_awlock_o = 1'b0;
    assign axi_awcache_o = '0;
    assign axi_awprot_o = '0;
    assign axi_awqos_o = '0;
    assign axi_awregion_o = '0;
    assign axi_awatop_o = '0;
    assign axi_awuser_o = '0;
    assign axi_awvalid_o = requesting && writing && !axi_aw_accepted_q;
    assign axi_wdata_o = WRITE_DATA;
    assign axi_wstrb_o = 4'b0011;
    assign axi_wlast_o = 1'b1;
    assign axi_wuser_o = '0;
    // Deliberately issue W after AW acceptance so the connected test covers
    // independent channel readiness and never relies on a simultaneous take.
    assign axi_wvalid_o = requesting && writing && axi_aw_accepted_q &&
                          !axi_w_accepted_q;
    assign axi_bready_o = 1'b1;
    assign axi_arid_o = '0;
    assign axi_araddr_o = address;
    assign axi_arlen_o = '0;
    assign axi_arsize_o = 3'd2;
    assign axi_arburst_o = 2'b01;
    assign axi_arlock_o = 1'b0;
    assign axi_arcache_o = '0;
    assign axi_arprot_o = '0;
    assign axi_arqos_o = '0;
    assign axi_arregion_o = '0;
    assign axi_aruser_o = '0;
    assign axi_arvalid_o = requesting && !writing;
    assign axi_rready_o = 1'b1;

    assign tl_a_valid_o = requesting;
    assign tl_a_opcode_o = writing ? 3'd1 : 3'd4;
    assign tl_a_param_o = '0;
    assign tl_a_size_o = 3'd2;
    assign tl_a_source_o = 1'b0;
    assign tl_a_address_o = address;
    assign tl_a_mask_o = writing ? 4'b0011 : 4'b1111;
    assign tl_a_data_o = WRITE_DATA;
    assign tl_a_corrupt_o = 1'b0;
    assign tl_d_ready_o = 1'b1;

    always_comb begin
        accepted = 1'b0;
        accepted_protocol = 2'd0;
        if (requesting && (obi_gnt_i === 1'b1)) begin
            accepted = 1'b1;
            accepted_protocol = 2'd1;
        end else if (axi_write_accepted) begin
            accepted = 1'b1;
            accepted_protocol = 2'd2;
        end else if (requesting && !writing && (axi_arready_i === 1'b1)) begin
            accepted = 1'b1;
            accepted_protocol = 2'd2;
        end else if (requesting && (tl_a_ready_i === 1'b1)) begin
            accepted = 1'b1;
            accepted_protocol = 2'd3;
        end
    end

    always_comb begin
        completed = 1'b0;
        completion_data = '0;
        completion_error = 1'b0;
        case (protocol_q)
            2'd1: begin
                completed = obi_rvalid_i === 1'b1;
                completion_data = obi_rdata_i;
                completion_error = obi_error_i;
            end
            2'd2: begin
                completed = writing ? (axi_bvalid_i === 1'b1) :
                                      (axi_rvalid_i === 1'b1);
                completion_data = axi_rdata_i;
                completion_error = writing ? (axi_bresp_i != 2'b00) :
                                             (axi_rresp_i != 2'b00 || !axi_rlast_i);
            end
            2'd3: begin
                completed = tl_d_valid_i === 1'b1;
                completion_data = tl_d_data_i;
                completion_error = tl_d_denied_i || tl_d_corrupt_i;
            end
            default: begin end
        endcase
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            operation_q <= 3'd0;
            protocol_q <= 2'd0;
            waiting_q <= 1'b0;
            axi_aw_accepted_q <= 1'b0;
            axi_w_accepted_q <= 1'b0;
            done_o <= 1'b0;
            accepted_o <= '0;
            completions_o <= '0;
            readback_o <= '0;
            errors_o <= '0;
            cycles_o <= '0;
        end else begin
            cycles_o <= cycles_o + 1'b1;
            if (axi_aw_take)
                axi_aw_accepted_q <= 1'b1;
            if (axi_w_take)
                axi_w_accepted_q <= 1'b1;
            if (accepted) begin
                waiting_q <= 1'b1;
                protocol_q <= accepted_protocol;
                accepted_o <= accepted_o + 1'b1;
                axi_aw_accepted_q <= 1'b0;
                axi_w_accepted_q <= 1'b0;
            end
            if (waiting_q && completed) begin
                waiting_q <= 1'b0;
                completions_o <= completions_o + 1'b1;
                if (completion_error)
                    errors_o <= errors_o + 1'b1;
                if (operation_q == 3'd0 && completion_data != INSTRUCTION)
                    errors_o <= errors_o + 1'b1;
                if (operation_q == 3'd1 && completion_data != INITIAL_DATA)
                    errors_o <= errors_o + 1'b1;
                if (operation_q == 3'd3) begin
                    readback_o <= completion_data;
                    if (completion_data != FINAL_DATA)
                        errors_o <= errors_o + 1'b1;
                    done_o <= 1'b1;
                end else begin
                    operation_q <= operation_q + 1'b1;
                end
            end
        end
    end

    wire unused_inputs = ^{random_i, axi_bid_i, axi_buser_i, axi_rid_i,
                           axi_ruser_i, tl_d_opcode_i, tl_d_param_i,
                           tl_d_size_i, tl_d_source_i, tl_d_sink_i};
endmodule
