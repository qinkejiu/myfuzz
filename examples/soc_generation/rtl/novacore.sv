// novacore: a first-time input CPU used by the automatic-composition example.
//
// It is deliberately *not* a registered model: it appears nowhere in the
// myfuzz component tables, and the generator must compose it purely from its
// profile and the OBI protocol contract.  The implementation is a small
// deterministic OBI master: it fetches one word from its boot address, then
// keeps polling one MMIO word so a peripheral can be observed.
module novacore #(
    parameter integer XLEN = 32,
    parameter logic [31:0] BOOT_ADDR = 32'h0001_0000,
    parameter logic [31:0] POLL_ADDR = 32'h4000_0000
) (
    input  logic                clk_i,
    input  logic                rst_ni,

    // Configuration / special inputs.
    input  logic                fetch_enable_i,
    input  logic [3:0]          event_i,

    // Interrupt entry: same-domain level, active high, machine-external.
    input  logic                irq_external_i,

    // Observation outputs.
    output logic [7:0]          status_o,
    output logic                trap_o,

    // Unified OBI memory master.
    output logic                obi_req_o,
    input  logic                obi_gnt_i,
    output logic [XLEN-1:0]     obi_addr_o,
    output logic                obi_we_o,
    output logic [XLEN-1:0]     obi_wdata_o,
    output logic [XLEN/8-1:0]   obi_be_o,
    input  logic                obi_rvalid_i,
    input  logic [XLEN-1:0]     obi_rdata_i,
    input  logic                obi_err_i
);
    localparam logic [7:0] ST_BOOT = 8'h01;
    localparam logic [7:0] ST_FETCH = 8'h02;
    localparam logic [7:0] ST_POLL = 8'h03;
    localparam logic [7:0] ST_IRQ = 8'h04;
    localparam logic [7:0] ST_TRAP = 8'h05;

    logic [7:0] state_q;
    logic [7:0] status_q;
    logic       trap_q;
    logic [31:0] poll_count_q;
    logic [31:0] irq_count_q;

    assign obi_req_o   = (state_q == ST_FETCH) || (state_q == ST_POLL) || (state_q == ST_IRQ);
    assign obi_addr_o  = (state_q == ST_FETCH) ? BOOT_ADDR : POLL_ADDR;
    assign obi_we_o    = 1'b0;
    assign obi_wdata_o = {XLEN{1'b0}};
    assign obi_be_o    = {(XLEN/8){1'b1}};
    assign status_o    = status_q;
    assign trap_o      = trap_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            state_q      <= ST_BOOT;
            status_q     <= ST_BOOT;
            trap_q       <= 1'b0;
            poll_count_q <= 32'd0;
            irq_count_q  <= 32'd0;
        end else begin
            if (!fetch_enable_i) begin
                state_q  <= ST_BOOT;
                status_q <= ST_BOOT;
            end else begin
                case (state_q)
                    ST_BOOT: begin
                        status_q <= ST_FETCH;
                        state_q  <= ST_FETCH;
                    end
                    ST_FETCH: begin
                        if (obi_req_o && obi_gnt_i) begin
                            status_q <= ST_POLL;
                            state_q  <= ST_POLL;
                        end
                    end
                    ST_POLL: begin
                        if (obi_rvalid_i) begin
                            if (obi_err_i) begin
                                trap_q   <= 1'b1;
                                status_q <= ST_TRAP;
                                state_q  <= ST_TRAP;
                            end else begin
                                poll_count_q <= poll_count_q + 32'd1;
                                if (irq_external_i) begin
                                    irq_count_q <= irq_count_q + 32'd1;
                                    status_q    <= ST_IRQ;
                                    state_q     <= ST_IRQ;
                                end else begin
                                    status_q <= ST_POLL;
                                    state_q  <= ST_POLL;
                                end
                            end
                        end
                    end
                    ST_IRQ: begin
                        // A real ISR would claim, service and complete; the
                        // example only records that the entry was observed.
                        status_q <= ST_POLL;
                        state_q  <= ST_POLL;
                    end
                    default: begin
                        status_q <= ST_TRAP;
                        state_q  <= ST_TRAP;
                    end
                endcase
            end
        end
    end

    logic unused_events;
    assign unused_events = ^event_i;
endmodule
