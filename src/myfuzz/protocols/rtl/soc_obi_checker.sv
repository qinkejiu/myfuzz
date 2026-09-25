// Observe one Ibex OBI port at the CPU/adapter boundary. Response ordering
// needs an independent tagged reference and is intentionally not assessed.
module soc_obi_checker #(
    parameter int ADDRESS_WIDTH = 32,
    parameter int DATA_WIDTH = 32
) (
    input  logic clk_i, rst_ni,
    input  logic req_i, gnt_i,
    input  logic [ADDRESS_WIDTH-1:0] addr_i,
    input  logic [DATA_WIDTH-1:0] wdata_i,
    input  logic [DATA_WIDTH/8-1:0] be_i,
    input  logic we_i,
    input  logic rvalid_i,
    input  logic [DATA_WIDTH-1:0] rdata_i,
    input  logic err_i,
    output logic [2:0] eval_o, fail_o
);
    logic stalled_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [DATA_WIDTH/8-1:0] be_q;
    logic we_q;
    logic [15:0] outstanding_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            stalled_q <= 1'b0;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            we_q <= 1'b0;
            outstanding_q <= '0;
            eval_o <= '0;
            fail_o <= '0;
        end else begin
            stalled_q <= req_i && !gnt_i;
            if (req_i && !gnt_i) begin
                addr_q <= addr_i;
                wdata_q <= wdata_i;
                be_q <= be_i;
                we_q <= we_i;
            end
            if (stalled_q) begin
                eval_o[0] <= 1'b1;
                if (req_i !== 1'b1 || addr_i !== addr_q ||
                    we_i !== we_q || be_i !== be_q ||
                    (we_q && wdata_i !== wdata_q))
                    fail_o[0] <= 1'b1;
            end
            if (req_i && gnt_i || rvalid_i) begin
                eval_o[1] <= 1'b1;
                // A grant on this edge cannot justify a response on the same
                // edge: only requests granted on earlier edges are pending.
                if (rvalid_i && outstanding_q == 0)
                    fail_o[1] <= 1'b1;
                case ({req_i && gnt_i, rvalid_i})
                    2'b10: outstanding_q <= outstanding_q + 1'b1;
                    2'b01: if (outstanding_q != 0)
                        outstanding_q <= outstanding_q - 1'b1;
                    2'b11: if (outstanding_q == 0)
                        outstanding_q <= 16'd1;
                    default: ;
                endcase
            end
        end
    end
    // The response data/error are observed at the boundary but have no
    // independent expected value in this protocol checker.
    wire unused_response = ^{rdata_i, err_i};
endmodule
