// Observe APB3 at the real PULP target pins. For these two pinned targets
// PREADY is tied high and PSLVERR low; WAIT_STABLE remains reserved but idle.
module soc_apb3_checker #(
    parameter int ADDRESS_WIDTH = 12,
    parameter int DATA_WIDTH = 32
) (
    input logic clk_i, rst_ni,
    input logic psel_i, penable_i, pready_i,
    input logic [ADDRESS_WIDTH-1:0] paddr_i,
    input logic pwrite_i,
    input logic [DATA_WIDTH-1:0] pwdata_i, prdata_i,
    input logic pslverr_i,
    output logic [3:0] eval_o, fail_o
);
    logic setup_q, waiting_q;
    logic [ADDRESS_WIDTH-1:0] paddr_q;
    logic [DATA_WIDTH-1:0] pwdata_q;
    logic pwrite_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            setup_q <= 0;
            waiting_q <= 0;
            paddr_q <= '0;
            pwdata_q <= '0;
            pwrite_q <= 0;
            eval_o <= '0;
            fail_o <= '0;
        end else begin
            if (psel_i && !penable_i) begin
                setup_q <= 1'b1;
                waiting_q <= 1'b0;
                paddr_q <= paddr_i;
                pwrite_q <= pwrite_i;
                pwdata_q <= pwdata_i;
            end else if (psel_i && penable_i) begin
                eval_o[0] <= 1'b1;
                if ((!setup_q && !waiting_q) ||
                    paddr_i !== paddr_q || pwrite_i !== pwrite_q ||
                    (pwrite_q && pwdata_i !== pwdata_q))
                    fail_o[0] <= 1'b1;
                if (waiting_q) begin
                    eval_o[1] <= 1'b1;
                    if (paddr_i !== paddr_q || pwrite_i !== pwrite_q ||
                        (pwrite_q && pwdata_i !== pwdata_q))
                        fail_o[1] <= 1'b1;
                end
                waiting_q <= !pready_i;
                if (pready_i) setup_q <= 1'b0;
            end else begin
                setup_q <= 1'b0;
                waiting_q <= 1'b0;
            end
            if (psel_i) begin
                eval_o[2] <= 1'b1;
                eval_o[3] <= 1'b1;
                if (pready_i !== 1'b1) fail_o[2] <= 1'b1;
                if (pslverr_i !== 1'b0) fail_o[3] <= 1'b1;
            end
        end
    end
    wire unused_read_data = ^prdata_i;
endmodule
