// TileLink coherent memory slave for one CPU client, with a host-owned backend.
//
// The client here is the real A/B/C/D/E coherent boundary of the pinned
// ``BoomTile`` top (39 declared roles, data width 64, 8-byte beats).  This model
// owns the *pin* protocol only.  Every data byte either comes from the backend
// beat face or goes to it, so the host memory - not this module - is the
// authority; no read value is invented and no response is synthesized from a
// timeout or an error.
//
// Scope, named rather than implied:
//   * the harness never probes.  ``b_valid`` is tied low and there is no probe
//     state machine, so a client that needs a probe to make progress stalls
//     instead of being served a fabricated probe;
//   * one A or C message is in flight at a time.  The next request is accepted
//     only after the previous response has been fully delivered, which
//     ready/valid permits (see ``master_backpressure_tolerated`` in
//     src/myfuzz/local_harness/template_contracts.py);
//   * A opcodes Get (4), PutFullData (0), PutPartialData (1), AcquireBlock (6)
//     and AcquirePerm (7) are served, with multi-beat sizes up to 6 (64 bytes);
//   * C opcodes Release (6) and ReleaseData (7) are served without a preceding
//     probe, exactly as the pinned reference model does
//     (configs/cpus/boom/runtime/tl_ram.h);
//   * any other A or C opcode, an oversized transfer, an unallocated GrantAck,
//     an exhausted sink pool, a backend error or a backend timeout raises
//     ``fault_o`` and freezes the bus.  ``d_bits_denied`` is therefore never
//     used to disguise an unsupported request as a legal denial;
//   * Grant (D opcode 4) and GrantData (D opcode 5) hand out a sink from an
//     8-entry pool; the matching GrantAck on E releases it.
module tl_coherent_memory_adapter #(
    parameter integer ADDRESS_WIDTH   = 32,
    parameter integer DATA_WIDTH      = 64,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,
    // A channel: the CPU client issues Get/Put/Acquire here.
    input  logic                          a_valid,
    output logic                          a_ready,
    input  logic [2:0]                    a_bits_opcode,
    input  logic [2:0]                    a_bits_param,
    input  logic [3:0]                    a_bits_size,
    input  logic [2:0]                    a_bits_source,
    input  logic [ADDRESS_WIDTH-1:0]      a_bits_address,
    input  logic [(DATA_WIDTH/8)-1:0]     a_bits_mask,
    input  logic [DATA_WIDTH-1:0]         a_bits_data,
    // B channel: this model never probes.
    output logic                          b_valid,
    input  logic                          b_ready,
    output logic [2:0]                    b_bits_opcode,
    output logic [1:0]                    b_bits_param,
    output logic [3:0]                    b_bits_size,
    output logic [2:0]                    b_bits_source,
    output logic [ADDRESS_WIDTH-1:0]      b_bits_address,
    output logic [(DATA_WIDTH/8)-1:0]     b_bits_mask,
    output logic                          b_bits_corrupt,
    // C channel: Release / ReleaseData without a preceding probe.
    input  logic                          c_valid,
    output logic                          c_ready,
    input  logic [2:0]                    c_bits_opcode,
    input  logic [2:0]                    c_bits_param,
    input  logic [3:0]                    c_bits_size,
    input  logic [2:0]                    c_bits_source,
    input  logic [ADDRESS_WIDTH-1:0]      c_bits_address,
    input  logic [DATA_WIDTH-1:0]         c_bits_data,
    // D channel: AccessAck/AccessAckData/Grant/GrantData/ReleaseAck.
    output logic                          d_valid,
    input  logic                          d_ready,
    output logic [2:0]                    d_bits_opcode,
    output logic [1:0]                    d_bits_param,
    output logic [3:0]                    d_bits_size,
    output logic [2:0]                    d_bits_source,
    output logic [2:0]                    d_bits_sink,
    output logic                          d_bits_denied,
    output logic [DATA_WIDTH-1:0]         d_bits_data,
    output logic                          d_bits_corrupt,
    // E channel: GrantAck for a sink this model handed out.
    input  logic                          e_valid,
    output logic                          e_ready,
    input  logic [2:0]                    e_bits_sink,
    // Backend beat face: the host is the memory authority for every byte.
    output logic                          req_valid_o,
    input  logic                          req_ready_i,
    output logic                          req_write_o,
    output logic [ADDRESS_WIDTH-1:0]      req_addr_o,
    output logic [DATA_WIDTH-1:0]         req_wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     req_be_o,
    input  logic                          rsp_valid_i,
    output logic                          rsp_ready_o,
    input  logic [DATA_WIDTH-1:0]         rsp_rdata_i,
    input  logic                          rsp_error_i,
    output logic                          fault_o,
    output logic [1:0]                    fault_code_o
);
    // TileLink message opcodes used here.  The C channel's Release/ReleaseData
    // share the 6/7 encoding of AcquireBlock/AcquirePerm and the D channel's
    // ReleaseAck is 6, exactly as in the pinned reference model.
    localparam logic [2:0] A_PUT_FULL     = 3'd0;
    localparam logic [2:0] A_PUT_PARTIAL  = 3'd1;
    localparam logic [2:0] A_GET          = 3'd4;
    localparam logic [2:0] A_ACQUIRE_BLK  = 3'd6;
    localparam logic [2:0] A_ACQUIRE_PERM = 3'd7;
    localparam logic [2:0] C_RELEASE      = 3'd6;
    localparam logic [2:0] C_RELEASE_DATA = 3'd7;
    localparam logic [2:0] D_ACCESS_ACK      = 3'd0;
    localparam logic [2:0] D_ACCESS_ACK_DATA = 3'd1;
    localparam logic [2:0] D_GRANT           = 3'd4;
    localparam logic [2:0] D_GRANT_DATA      = 3'd5;
    localparam logic [2:0] D_RELEASE_ACK     = 3'd6;

    localparam integer DB      = DATA_WIDTH / 8;  // bytes per beat
    localparam integer MAXW    = 8;               // beats of a 64-byte line
    localparam integer WAIT_W  = 12;
    localparam logic [WAIT_W-1:0] WAIT_MAX = MAX_WAIT_CYCLES[WAIT_W-1:0];

    initial begin
        if (ADDRESS_WIDTH < 6 || ADDRESS_WIDTH > 64)
            $fatal(1, "invalid TileLink coherent address width");
        if (DATA_WIDTH != 64)
            $fatal(1, "this coherent model implements the declared 64-bit beat only");
        if (MAX_WAIT_CYCLES < 1 || MAX_WAIT_CYCLES > 1024)
            $fatal(1, "invalid TileLink backend wait bound");
    end

    typedef enum logic [2:0] {IDLE, COLLECT, FETCH, WRITE, RESPOND, FAILED} state_t;
    state_t state_q;

    // One latched message, from A or C.
    logic [2:0]               req_opcode_q;
    logic [2:0]               req_source_q;
    logic [2:0]               req_param_q;
    logic [3:0]               req_size_q;
    logic [ADDRESS_WIDTH-1:0] req_base_q;
    logic [3:0]               req_beats_q;
    logic                     collect_c_q;

    // The response currently offered on D.
    logic [2:0]               rsp_opcode_q;
    logic [2:0]               rsp_source_q;
    logic [2:0]               rsp_sink_q;
    logic [1:0]               rsp_param_q;
    logic [3:0]               rsp_size_q;
    logic [3:0]               rsp_beats_q;
    logic [3:0]               rsp_index_q;
    logic                     rsp_has_data_q;

    // Line buffer: one entry per 8-byte word of the 64-byte block.
    logic [DATA_WIDTH-1:0]    line_q [0:MAXW-1];
    logic [DB-1:0]            be_q   [0:MAXW-1];

    // Backend beat index and handshake bookkeeping.
    logic [3:0]               io_index_q;
    logic [3:0]               collect_index_q;
    logic                     req_pending_q;
    logic [WAIT_W-1:0]        wait_q;

    // Grant sink pool: one bit per sink handed out and not yet acknowledged.
    logic [MAXW-1:0]          sink_used_q;

    logic                     fault_q;
    logic [1:0]               fault_code_q;

    function automatic logic [2:0] beats_of(input logic [3:0] size);
        if (size <= 4'd3) return 3'd1;
        return 3'd1 << (size - 4'd3);
    endfunction

    function automatic logic [2:0] lowest_free(input logic [MAXW-1:0] used);
        integer i;
        begin
            lowest_free = 3'd0;
            for (i = MAXW - 1; i >= 0; i--)
                if (!used[i]) lowest_free = i[2:0];
        end
    endfunction

    wire       sink_free = (sink_used_q != {MAXW{1'b1}});
    wire [2:0] sink_next = lowest_free(sink_used_q);
    wire [3:0] io_slot   = {1'b0, req_base_q[5:3]} + io_index_q;
    wire [3:0] rsp_slot  = {1'b0, req_base_q[5:3]} + rsp_index_q;
    wire       io_active = (state_q == FETCH) || (state_q == WRITE);

    // A and C never start together: A always wins the IDLE slot and C waits,
    // which is the only assignment that cannot deadlock two held valids.
    // Every ready/valid output is gated by ``rst_ni``: while reset is asserted
    // the client's pins are meaningless, and accepting a phantom A beat there
    // would invent a request that the host would then have to answer.
    assign a_ready = rst_ni && !fault_q && ((state_q == IDLE) ||
                                            (state_q == COLLECT && !collect_c_q));
    assign c_ready = rst_ni && !fault_q && ((state_q == IDLE && !a_valid) ||
                                            (state_q == COLLECT && collect_c_q));

    assign b_valid        = 1'b0;
    assign b_bits_opcode  = 3'd0;
    assign b_bits_param   = 2'd0;
    assign b_bits_size    = 4'd0;
    assign b_bits_source  = 3'd0;
    assign b_bits_address = '0;
    assign b_bits_mask    = '0;
    assign b_bits_corrupt = 1'b0;

    assign d_valid        = rst_ni && !fault_q && (state_q == RESPOND);
    assign d_bits_opcode  = rsp_opcode_q;
    assign d_bits_param   = rsp_param_q;
    assign d_bits_size    = rsp_size_q;
    assign d_bits_source  = rsp_source_q;
    assign d_bits_sink    = rsp_sink_q;
    assign d_bits_denied  = 1'b0;
    assign d_bits_data    = (rsp_has_data_q && !fault_q)
                            ? line_q[rsp_slot[2:0]] : '0;
    assign d_bits_corrupt = 1'b0;

    assign e_ready = rst_ni && !fault_q;

    assign req_valid_o = rst_ni && !fault_q && io_active && !req_pending_q;
    assign req_write_o = (state_q == WRITE);
    assign req_addr_o  = req_base_q + (io_index_q * (DATA_WIDTH / 8));
    assign req_wdata_o = (state_q == WRITE) ? line_q[io_slot[2:0]] : '0;
    assign req_be_o    = (state_q == WRITE) ? be_q[io_slot[2:0]] : {DB{1'b1}};
    assign rsp_ready_o = rst_ni && !fault_q && io_active && req_pending_q;

    assign fault_o      = fault_q;
    assign fault_code_o = fault_code_q;

    // Inputs this model deliberately does not consume: the B channel is never
    // used (no probes) and C's param is irrelevant to Release/ReleaseData.
    logic unused_inputs;
    assign unused_inputs = &{1'b0, b_ready, c_bits_param};

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q         <= IDLE;
            req_opcode_q    <= 3'd0;
            req_source_q    <= 3'd0;
            req_param_q     <= 3'd0;
            req_size_q      <= 4'd0;
            req_base_q      <= '0;
            req_beats_q     <= 4'd1;
            collect_c_q     <= 1'b0;
            rsp_opcode_q    <= 3'd0;
            rsp_source_q    <= 3'd0;
            rsp_sink_q      <= 3'd0;
            rsp_param_q     <= 2'd0;
            rsp_size_q      <= 4'd0;
            rsp_beats_q     <= 4'd1;
            rsp_index_q     <= 4'd0;
            rsp_has_data_q  <= 1'b0;
            io_index_q      <= 4'd0;
            collect_index_q <= 4'd0;
            req_pending_q   <= 1'b0;
            wait_q          <= '0;
            sink_used_q     <= '0;
            fault_q         <= 1'b0;
            fault_code_q    <= 2'd0;
            for (int i = 0; i < MAXW; i++) begin
                line_q[i] <= '0;
                be_q[i]   <= '0;
            end
        end else if (fault_q) begin
            // A fault is sticky until reset: the bus stays frozen and the host
            // observes fault_o rather than a synthesized completion.
            state_q <= FAILED;
        end else begin
            // GrantAck is independent of the request/response FSM.
            if (e_valid && e_ready) begin
                if (sink_used_q[e_bits_sink])
                    sink_used_q[e_bits_sink] <= 1'b0;
                else begin
                    fault_q      <= 1'b1;
                    fault_code_q <= 2'd2;
                end
            end
            case (state_q)
                IDLE: begin
                    req_pending_q <= 1'b0;
                    wait_q        <= '0;
                    if (a_valid) begin
                        req_opcode_q <= a_bits_opcode;
                        req_source_q <= a_bits_source;
                        req_param_q  <= a_bits_param;
                        req_size_q   <= a_bits_size;
                        req_base_q   <= {a_bits_address[ADDRESS_WIDTH-1:3], 3'b000};
                        collect_c_q  <= 1'b0;
                        if (a_bits_size > 4'd6) begin
                            fault_q      <= 1'b1;
                            fault_code_q <= 2'd1;
                        end else if (a_bits_opcode == A_PUT_FULL ||
                                     a_bits_opcode == A_PUT_PARTIAL) begin
                            req_beats_q     <= {1'b0, beats_of(a_bits_size)};
                            collect_index_q <= 4'd0;
                            io_index_q      <= 4'd0;
                            for (int i = 0; i < MAXW; i++) begin
                                line_q[i] <= '0;
                                be_q[i]   <= '0;
                            end
                            state_q <= COLLECT;
                        end else if (a_bits_opcode == A_GET ||
                                     a_bits_opcode == A_ACQUIRE_BLK) begin
                            req_beats_q    <= {1'b0, beats_of(a_bits_size)};
                            rsp_opcode_q   <= (a_bits_opcode == A_GET) ? D_ACCESS_ACK_DATA
                                                                      : D_GRANT_DATA;
                            rsp_param_q    <= (a_bits_opcode == A_ACQUIRE_BLK)
                                              ? ((a_bits_param == 3'd0) ? 2'd1 : 2'd0)
                                              : 2'd0;
                            rsp_source_q   <= a_bits_source;
                            rsp_size_q     <= a_bits_size;
                            rsp_sink_q     <= '0;
                            rsp_beats_q    <= {1'b0, beats_of(a_bits_size)};
                            rsp_index_q    <= 4'd0;
                            rsp_has_data_q <= 1'b1;
                            io_index_q     <= 4'd0;
                            state_q        <= FETCH;
                        end else if (a_bits_opcode == A_ACQUIRE_PERM) begin
                            if (!sink_free) begin
                                fault_q      <= 1'b1;
                                fault_code_q <= 2'd2;
                            end else begin
                                rsp_opcode_q  <= D_GRANT;
                                rsp_param_q   <= (a_bits_param == 3'd0) ? 2'd1 : 2'd0;
                                rsp_source_q  <= a_bits_source;
                                rsp_size_q    <= a_bits_size;
                                rsp_sink_q    <= sink_next;
                                rsp_beats_q   <= 4'd1;
                                rsp_index_q   <= 4'd0;
                                rsp_has_data_q<= 1'b0;
                                sink_used_q[sink_next] <= 1'b1;
                                state_q       <= RESPOND;
                            end
                        end else begin
                            fault_q      <= 1'b1;
                            fault_code_q <= 2'd1;
                        end
                    end else if (c_valid) begin
                        req_opcode_q <= c_bits_opcode;
                        req_source_q <= c_bits_source;
                        req_param_q  <= 3'd0;
                        req_size_q   <= c_bits_size;
                        req_base_q   <= {c_bits_address[ADDRESS_WIDTH-1:3], 3'b000};
                        collect_c_q  <= 1'b1;
                        if (c_bits_size > 4'd6) begin
                            fault_q      <= 1'b1;
                            fault_code_q <= 2'd1;
                        end else if (c_bits_opcode == C_RELEASE) begin
                            rsp_opcode_q   <= D_RELEASE_ACK;
                            rsp_param_q    <= 2'd0;
                            rsp_source_q   <= c_bits_source;
                            rsp_size_q     <= c_bits_size;
                            rsp_sink_q     <= '0;
                            rsp_beats_q    <= 4'd1;
                            rsp_index_q    <= 4'd0;
                            rsp_has_data_q <= 1'b0;
                            state_q        <= RESPOND;
                        end else if (c_bits_opcode == C_RELEASE_DATA) begin
                            req_beats_q     <= {1'b0, beats_of(c_bits_size)};
                            collect_index_q <= 4'd0;
                            io_index_q      <= 4'd0;
                            for (int i = 0; i < MAXW; i++) begin
                                line_q[i] <= '0;
                                be_q[i]   <= '0;
                            end
                            state_q <= COLLECT;
                        end else begin
                            fault_q      <= 1'b1;
                            fault_code_q <= 2'd1;
                        end
                    end
                end
                COLLECT: begin
                    if (collect_c_q) begin
                        if (c_valid && c_ready) begin
                            line_q[io_slot[2:0]] <= c_bits_data;
                            be_q[io_slot[2:0]]   <= {DB{1'b1}};
                            collect_index_q <= collect_index_q + 4'd1;
                            io_index_q      <= io_index_q + 4'd1;
                            if (collect_index_q + 4'd1 == req_beats_q) begin
                                rsp_opcode_q   <= D_RELEASE_ACK;
                                rsp_param_q    <= 2'd0;
                                rsp_sink_q     <= '0;
                                rsp_beats_q    <= 4'd1;
                                rsp_index_q    <= 4'd0;
                                rsp_has_data_q <= 1'b0;
                                io_index_q     <= 4'd0;
                                state_q        <= WRITE;
                            end
                        end
                    end else begin
                        if (a_valid && a_ready) begin
                            line_q[a_bits_address[5:3]] <= a_bits_data;
                            be_q[a_bits_address[5:3]]   <= a_bits_mask;
                            collect_index_q <= collect_index_q + 4'd1;
                            if (collect_index_q + 4'd1 == req_beats_q) begin
                                rsp_opcode_q   <= D_ACCESS_ACK;
                                rsp_param_q    <= 2'd0;
                                rsp_source_q   <= a_bits_source;
                                rsp_size_q     <= req_size_q;
                                rsp_sink_q     <= '0;
                                rsp_beats_q    <= 4'd1;
                                rsp_index_q    <= 4'd0;
                                rsp_has_data_q <= 1'b0;
                                io_index_q     <= 4'd0;
                                state_q        <= WRITE;
                            end
                        end
                    end
                end
                FETCH, WRITE: begin
                    if (!req_pending_q) begin
                        // The host's *acceptance* is the bounded step: a host
                        // that never takes the request is a stuck environment.
                        if (wait_q + 1'b1 >= WAIT_MAX) begin
                            fault_q      <= 1'b1;
                            fault_code_q <= 2'd2;
                        end else begin
                            wait_q <= wait_q + 1'b1;
                            if (req_ready_i)
                                req_pending_q <= 1'b1;
                        end
                    end else begin
                        // Once accepted, the wait is unbounded on purpose: the
                        // host may legitimately hold the answer (an instruction
                        // word that has not been materialized yet).  Timing out
                        // here would turn the host's own park into a fault.
                        if (rsp_valid_i) begin
                            req_pending_q <= 1'b0;
                            wait_q        <= '0;
                            if (rsp_error_i) begin
                                fault_q      <= 1'b1;
                                fault_code_q <= 2'd3;
                            end else begin
                                if (state_q == FETCH)
                                    line_q[io_slot[2:0]] <= rsp_rdata_i;
                                if (io_index_q + 4'd1 == req_beats_q) begin
                                    rsp_index_q <= 4'd0;
                                    if (req_opcode_q == A_ACQUIRE_BLK) begin
                                        if (!sink_free) begin
                                            fault_q      <= 1'b1;
                                            fault_code_q <= 2'd2;
                                        end else begin
                                            rsp_opcode_q  <= D_GRANT_DATA;
                                            rsp_sink_q    <= sink_next;
                                            rsp_beats_q   <= req_beats_q;
                                            rsp_has_data_q<= 1'b1;
                                            sink_used_q[sink_next] <= 1'b1;
                                            state_q       <= RESPOND;
                                        end
                                    end else begin
                                        rsp_opcode_q   <= D_ACCESS_ACK_DATA;
                                        rsp_sink_q     <= '0;
                                        rsp_beats_q    <= req_beats_q;
                                        rsp_has_data_q <= 1'b1;
                                        state_q        <= RESPOND;
                                    end
                                end else begin
                                    io_index_q <= io_index_q + 4'd1;
                                end
                            end
                        end
                    end
                end
                RESPOND: begin
                    if (d_ready) begin
                        if (rsp_index_q + 4'd1 == rsp_beats_q)
                            state_q <= IDLE;
                        else
                            rsp_index_q <= rsp_index_q + 4'd1;
                    end
                end
                FAILED: begin
                    fault_q      <= 1'b1;
                    fault_code_q <= fault_code_q;
                end
                default: begin
                    fault_q      <= 1'b1;
                    fault_code_q <= 2'd3;
                end
            endcase
        end
    end
endmodule
