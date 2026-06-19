module toy_cpu (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        fetch_enable_i,
    input  logic        req_valid_i,
    input  logic        req_write_i,
    input  logic [31:0] req_addr_i,
    input  logic [31:0] req_wdata_i,
    input  logic [3:0]  req_be_i,
    input  logic        debug_req_i,
    input  logic        error_i,
    input  logic        timer_irq_i,
    input  logic        external_irq_i,
    input  logic        bus_ready_i,
    input  logic        bus_rvalid_i,
    input  logic [31:0] bus_rdata_i,
    output logic        bus_valid_o,
    output logic        bus_write_o,
    output logic [31:0] bus_addr_o,
    output logic [31:0] bus_wdata_o,
    output logic [3:0]  bus_be_o,
    output logic [7:0]  state_o
);

    typedef enum logic [2:0] {
        S_RESET = 3'd0,
        S_IDLE = 3'd1,
        S_REQ = 3'd2,
        S_WAIT = 3'd3,
        S_IRQ = 3'd4,
        S_DEBUG = 3'd5,
        S_ERROR = 3'd6
    } state_e;

    state_e state_q, state_d;
    logic [7:0] transaction_count_q;
    logic [7:0] irq_count_q;
    logic [31:0] last_rdata_q;

    always_comb begin
        state_d = state_q;
        unique case (state_q)
            S_RESET: begin
                if (fetch_enable_i) begin
                    state_d = S_IDLE;
                end
            end
            S_IDLE: begin
                if (error_i) begin
                    state_d = S_ERROR;
                end else if (debug_req_i) begin
                    state_d = S_DEBUG;
                end else if (timer_irq_i || external_irq_i) begin
                    state_d = S_IRQ;
                end else if (fetch_enable_i && req_valid_i) begin
                    state_d = S_REQ;
                end
            end
            S_REQ: begin
                if (bus_ready_i) begin
                    state_d = S_WAIT;
                end
            end
            S_WAIT: begin
                if (bus_rvalid_i) begin
                    state_d = S_IDLE;
                end
            end
            S_IRQ: begin
                if (!timer_irq_i && !external_irq_i) begin
                    state_d = S_IDLE;
                end
            end
            S_DEBUG: begin
                if (!debug_req_i) begin
                    state_d = S_IDLE;
                end
            end
            S_ERROR: begin
                if (!error_i) begin
                    state_d = S_IDLE;
                end
            end
            default: begin
                state_d = S_RESET;
            end
        endcase
    end

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_q <= S_RESET;
            transaction_count_q <= 8'h00;
            irq_count_q <= 8'h00;
            last_rdata_q <= 32'h0;
        end else begin
            state_q <= state_d;
            if (state_q == S_REQ && bus_ready_i) begin
                transaction_count_q <= transaction_count_q + 8'h1;
            end
            if (state_q == S_IDLE && (timer_irq_i || external_irq_i)) begin
                irq_count_q <= irq_count_q + 8'h1;
            end
            if (bus_rvalid_i) begin
                last_rdata_q <= bus_rdata_i;
            end
        end
    end

    assign bus_valid_o = (state_q == S_REQ);
    assign bus_write_o = req_write_i;
    assign bus_addr_o = req_addr_i;
    assign bus_wdata_o = req_wdata_i ^ last_rdata_q;
    assign bus_be_o = req_be_i;
    assign state_o = {state_q, transaction_count_q[2:0], irq_count_q[1:0]};

endmodule
