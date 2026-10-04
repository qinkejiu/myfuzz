// Single outstanding byte-addressed memory completion. No early ready and no
// success response can be synthesized from backend error or timeout.
module native_completion_memory_adapter #(
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input logic clk, reset, valid_i,
    output logic ready_o,
    input logic [31:0] addr_i, wdata_i,
    input logic [3:0] wstrb_i,
    output logic [31:0] rdata_o,
    output logic req_valid_o,
    input logic req_ready_i,
    output logic req_write_o,
    output logic [31:0] req_addr_o, req_wdata_o,
    output logic [3:0] req_be_o,
    input logic rsp_valid_i,
    output logic rsp_ready_o,
    input logic [31:0] rsp_rdata_i,
    input logic rsp_error_i,
    output logic fault_o,
    output logic [1:0] fault_code_o
);
    localparam integer WAIT_WIDTH = $clog2(MAX_WAIT_CYCLES+1);
    typedef enum logic [2:0] {IDLE, REQUEST, RESPONSE, COMPLETE, FAILED} state_t;
    state_t state_q;
    logic [31:0] addr_q, wdata_q, rdata_q;
    logic [3:0] strb_q;
    logic [WAIT_WIDTH-1:0] wait_q;
    wire changed = !valid_i || addr_i != addr_q || wstrb_i != strb_q ||
                   ((|strb_q) && wdata_i != wdata_q);
    initial if (MAX_WAIT_CYCLES < 1 || MAX_WAIT_CYCLES > 1024)
        $fatal(1,"invalid native completion wait bound");
    assign ready_o = !reset && valid_i && state_q == COMPLETE && !changed;
    assign rdata_o = state_q == COMPLETE ? rdata_q : 32'b0;
    assign req_valid_o = !reset && state_q == REQUEST && !changed;
    assign req_write_o = |strb_q;
    assign req_addr_o = addr_q;
    assign req_wdata_o = wdata_q;
    assign req_be_o = (|strb_q) ? strb_q : 4'b1111;
    assign rsp_ready_o = !reset && state_q == RESPONSE && !changed;
    assign fault_o = !reset && state_q == FAILED;
    always_ff @(posedge clk) begin
        if (reset) begin
            state_q <= IDLE; addr_q <= 0; wdata_q <= 0; strb_q <= 0;
            rdata_q <= 0; wait_q <= 0; fault_code_o <= 0;
        end else if (state_q inside {REQUEST, RESPONSE, COMPLETE} && changed) begin
            state_q <= FAILED; fault_code_o <= 3;
        end else case (state_q)
            IDLE: if (valid_i) begin
                addr_q <= addr_i; wdata_q <= wdata_i; strb_q <= wstrb_i;
                wait_q <= 0; state_q <= REQUEST;
            end
            REQUEST: if (req_ready_i) begin
                state_q <= RESPONSE; wait_q <= 0;
            end else if (int'(wait_q)+1 >= MAX_WAIT_CYCLES) begin
                state_q <= FAILED; fault_code_o <= 2;
            end else wait_q <= wait_q + 1'b1;
            RESPONSE: if (rsp_valid_i) begin
                if (rsp_error_i) begin state_q <= FAILED; fault_code_o <= 1; end
                else begin rdata_q <= rsp_rdata_i; state_q <= COMPLETE; end
            end else if (int'(wait_q)+1 >= MAX_WAIT_CYCLES) begin
                state_q <= FAILED; fault_code_o <= 2;
            end else wait_q <= wait_q + 1'b1;
            COMPLETE: state_q <= IDLE;
            FAILED: state_q <= FAILED;
            default: begin state_q <= FAILED; fault_code_o <= 3; end
        endcase
    end
endmodule
