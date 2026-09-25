// Check composed router target arbitration and arbiter response ownership.
module soc_fabric_checker #(
    parameter int NUM_TARGETS = 2,
    parameter int SOURCE_ID_WIDTH = 2,
    parameter int ADDRESS_WIDTH = 32
) (
    input logic clk_i, rst_ni,
    input logic req_valid_i, req_ready_i,
    input logic [ADDRESS_WIDTH-1:0] addr_i,
    input logic [NUM_TARGETS-1:0] target_select_i,
    input logic [SOURCE_ID_WIDTH-1:0] request_source_id_i,
    input logic [SOURCE_ID_WIDTH-1:0] response_source_id_i,
    input logic rsp_valid_i, rsp_ready_i,
    output logic [1:0] eval_o, fail_o
);
    logic pending_q;
    logic [SOURCE_ID_WIDTH-1:0] owner_q;
    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            pending_q <= 1'b0;
            owner_q <= '0;
            eval_o <= '0;
            fail_o <= '0;
        end else begin
            if (target_select_i != '0) begin
                eval_o[0] <= 1'b1;
                if (!$onehot(target_select_i)) fail_o[0] <= 1'b1;
            end
            if (req_valid_i && req_ready_i) begin
                owner_q <= request_source_id_i;
                pending_q <= 1'b1;
            end
            if (rsp_valid_i && rsp_ready_i && pending_q) begin
                eval_o[1] <= 1'b1;
                if (response_source_id_i !== owner_q)
                    fail_o[1] <= 1'b1;
                pending_q <= 1'b0;
            end
        end
    end
    wire unused_addr = ^addr_i;
endmodule
