// soc_arbiter: N beat initiators onto one beat target port.
//
// Beat contract (identical to the P5 target adapters):
//   clk, reset, req_valid, req_ready, write, addr, wdata, be,
//   rsp_valid, rsp_ready, rdata, error
// "reset" is synchronous and active high.
//
// Every source owns one lane of the s_* vectors and speaks exactly that
// contract.  First release: exactly ONE outstanding transaction globally.
// The winning source and every request field (addr, write, wdata, be, instr)
// are latched in the cycle the source handshake completes and never change
// while the response is pending.  Arbitration is round-robin from a rotating
// priority pointer, so an always-requesting source is granted at least once
// every NUM_SOURCES grants.
//
// The request channel to the target carries the accepted source index and a
// transaction id that increments once per accepted transaction; the target
// side (soc_router) echoes both back so the completion can be attributed.

module soc_arbiter #(
    parameter integer NUM_SOURCES = 2,
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer SOURCE_ID_WIDTH = (NUM_SOURCES <= 1) ? 1 : $clog2(NUM_SOURCES),
    parameter integer TRANSACTION_ID_WIDTH = 8
) (
    input  logic clk,
    input  logic reset,

    input  logic [NUM_SOURCES-1:0]                    s_req_valid,
    output logic [NUM_SOURCES-1:0]                    s_req_ready,
    input  logic [NUM_SOURCES-1:0]                    s_write,
    input  logic [NUM_SOURCES-1:0][ADDRESS_WIDTH-1:0] s_addr,
    input  logic [NUM_SOURCES-1:0][DATA_WIDTH-1:0]    s_wdata,
    input  logic [NUM_SOURCES-1:0][(DATA_WIDTH/8)-1:0] s_be,
    input  logic [NUM_SOURCES-1:0]                    s_instr,
    output logic [NUM_SOURCES-1:0]                    s_rsp_valid,
    input  logic [NUM_SOURCES-1:0]                    s_rsp_ready,
    output logic [NUM_SOURCES-1:0][DATA_WIDTH-1:0]    s_rdata,
    output logic [NUM_SOURCES-1:0]                    s_error,

    output logic                                      req_valid,
    input  logic                                      req_ready,
    output logic                                      write,
    output logic [ADDRESS_WIDTH-1:0]                  addr,
    output logic [DATA_WIDTH-1:0]                     wdata,
    output logic [(DATA_WIDTH/8)-1:0]                 be,
    output logic                                      instr,
    output logic [SOURCE_ID_WIDTH-1:0]                source_id,
    output logic [TRANSACTION_ID_WIDTH-1:0]           transaction_id,

    input  logic                                      rsp_valid,
    output logic                                      rsp_ready,
    input  logic [DATA_WIDTH-1:0]                     rdata,
    input  logic                                      error,
    input  logic [SOURCE_ID_WIDTH-1:0]                rsp_source_id,
    input  logic [TRANSACTION_ID_WIDTH-1:0]           rsp_transaction_id,

    output logic                                      protocol_error
);
    localparam integer BE_WIDTH = DATA_WIDTH / 8;

    initial begin
        if (NUM_SOURCES < 1 || ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "invalid soc_arbiter width parameters");
        if (TRANSACTION_ID_WIDTH < 1)
            $fatal(1, "invalid soc_arbiter transaction id width");
        if (SOURCE_ID_WIDTH < 1 || NUM_SOURCES > (1 << SOURCE_ID_WIDTH))
            $fatal(1, "SOURCE_ID_WIDTH cannot index NUM_SOURCES");
    end

    typedef enum logic [1:0] {IDLE, REQUEST, WAIT_RSP, RESPOND} state_t;
    state_t state_q;

    logic [SOURCE_ID_WIDTH-1:0] owner_q, priority_q, grant_index;
    logic grant_valid;
    logic write_q, instr_q, error_q, protocol_error_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q, rdata_q;
    logic [BE_WIDTH-1:0] be_q;
    logic [TRANSACTION_ID_WIDTH-1:0] next_txid_q, active_txid_q;

    // Rotating priority: start from priority_q and take the first requesting
    // source.  priority_q advances past every granted source, which bounds the
    // wait of any continuously requesting source by NUM_SOURCES grants.
    always_comb begin
        grant_valid = 1'b0;
        grant_index = '0;
        for (int unsigned i = 0; i < NUM_SOURCES; i++) begin
            int unsigned candidate;
            candidate = (priority_q + i) % NUM_SOURCES;
            if (!grant_valid && s_req_valid[candidate]) begin
                grant_valid = 1'b1;
                grant_index = candidate[SOURCE_ID_WIDTH-1:0];
            end
        end
    end

    always_comb begin
        s_req_ready = '0;
        if (!reset && (state_q == IDLE) && grant_valid)
            s_req_ready[grant_index] = 1'b1;
    end

    assign req_valid = !reset && (state_q == REQUEST);
    assign write = write_q;
    assign addr = addr_q;
    assign wdata = wdata_q;
    assign be = be_q;
    assign instr = instr_q;
    assign source_id = owner_q;
    assign transaction_id = active_txid_q;

    assign rsp_ready = !reset && (state_q == WAIT_RSP);

    always_comb begin
        s_rsp_valid = '0;
        s_rdata = '0;
        s_error = '0;
        if (!reset && (state_q == RESPOND)) begin
            s_rsp_valid[owner_q] = 1'b1;
            s_rdata[owner_q] = rdata_q;
            s_error[owner_q] = error_q;
        end
    end

    assign protocol_error = protocol_error_q;

    always_ff @(posedge clk) begin
        if (reset) begin
            // A transaction in flight is terminated: no completion is offered
            // and the sources are never required to accept one.  Nothing is
            // replayed, so the aborted transaction cannot create a duplicate
            // side effect.
            state_q <= IDLE;
            owner_q <= '0;
            priority_q <= '0;
            next_txid_q <= '0;
            active_txid_q <= '0;
            write_q <= 1'b0;
            instr_q <= 1'b0;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            rdata_q <= '0;
            error_q <= 1'b0;
            protocol_error_q <= 1'b0;
        end else begin
            protocol_error_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    if (grant_valid && s_req_ready[grant_index]) begin
                        owner_q <= grant_index;
                        priority_q <= (grant_index == (NUM_SOURCES - 1)) ? '0 : (grant_index + 1'b1);
                        write_q <= s_write[grant_index];
                        addr_q <= s_addr[grant_index];
                        wdata_q <= s_wdata[grant_index];
                        be_q <= s_be[grant_index];
                        instr_q <= s_instr[grant_index];
                        active_txid_q <= next_txid_q;
                        next_txid_q <= next_txid_q + 1'b1;
                        state_q <= REQUEST;
                    end
                end
                REQUEST: begin
                    if (req_valid && req_ready) state_q <= WAIT_RSP;
                end
                WAIT_RSP: begin
                    if (rsp_valid) begin
                        if ((rsp_source_id == owner_q) && (rsp_transaction_id == active_txid_q)) begin
                            rdata_q <= rdata;
                            error_q <= error;
                        end else begin
                            rdata_q <= '0;
                            error_q <= 1'b1;
                            protocol_error_q <= 1'b1;
                        end
                        state_q <= RESPOND;
                    end
                end
                RESPOND: begin
                    if (s_rsp_ready[owner_q]) state_q <= IDLE;
                end
                default: state_q <= IDLE;
            endcase
        end
    end
endmodule
