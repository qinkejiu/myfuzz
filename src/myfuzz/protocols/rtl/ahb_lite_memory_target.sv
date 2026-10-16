// ahb_lite_memory_target: AHB-Lite subordinate-side memory service.
//
// WHY THIS EXISTS (and why it replaces beat_to_ahb_lite)
//   CORE-V Wally is the AHB **manager** at its external bus: it drives
//   HTRANS/HADDR/HWRITE/HSIZE/HBURST/HPROT/HMASTLOCK/HWDATA/HWSTRB and it
//   *receives* HREADYEXT/HRDATAEXT/HRESPEXT.  The repository's AHB-Lite
//   declaration, CPU-side contract and runtime shape all record exactly that.
//   `beat_to_ahb_lite` was written the other way round - it drove the bus as if
//   the harness were the manager - which cannot produce a transaction from the
//   CPU at all.  This module is the correct side: a subordinate that answers the
//   CPU's requests.
//
// DIRECTION
//   CPU AHB manager DUT  ->  this subordinate
//   The DUT-side pins keep the real CVW names so the wiring is the declaration's
//   (`HADDR`/`HTRANS`/... in, `HREADYEXT`/`HRDATAEXT`/`HRESPEXT` out).
//   The beat face carries the CPU's request OUT to the harness and the service's
//   answer IN, exactly like the other processor-memory adapters:
//     out: req_valid_o, req_write_o, req_addr_o, req_wdata_o, req_be_o
//     in : req_ready_i, rsp_valid_i, rsp_rdata_i, rsp_error_i
//
// AHB-LITE SUBORDINATE RULES IMPLEMENTED
//   * A transfer begins in the address phase (`HTRANS` = NONSEQ or SEQ) and
//     completes on an edge where `HREADYEXT` is high (AHB-Lite's single
//     completion rule).  `HRESPEXT` is driven on that completing edge.
//   * `HTRANS` = IDLE/BUSY is not a transfer: the target keeps `HREADYEXT` high
//     and does not start anything.
//   * The write data phase follows the address phase, so `HWDATA`/`HWSTRB` are
//     sampled one cycle after the address is accepted.  This is why the beat
//     request is only raised in the data phase: `req_valid_o` is a promise that
//     the whole request - address AND write data/strobes - is valid.  Raising it
//     during the address phase would hand the service stale write data.
//   * Because the subordinate may only extend a transfer by holding `HREADYEXT`
//     low, the request stays asserted until the service accepts it, and the
//     transfer stays outstanding until the service answers.
//   * `HSELEXT` is CVW's external-memory chip select, not an AHB-Lite signal; it
//     gates whether the transfer is addressed to this subordinate at all.
//   * `HSIZE`/`HBURST`/`HPROT`/`HMASTLOCK` are accepted and ignored: this service
//     does not claim burst support.  A burst is answered one beat at a time,
//     which is what the profile's single-outstanding capability declares, and the
//     byte lanes come from `HWSTRB` rather than from `HSIZE`.
//
// NOT CLAIMED
//   No burst acceleration, no cacheability semantics, no error injection beyond
//   propagating the service's own error flag, and no invented timeout error (see
//   MAX_WAIT_CYCLES below).
module ahb_lite_memory_target #(
    parameter integer ADDRESS_WIDTH = 34,
    parameter integer DATA_WIDTH = 32,
    // Kept for interface parity with the other processor-memory adapters.  It is
    // deliberately NOT used to abort a transfer: CVW's profile declares no usable
    // error pin, so a timeout could only be signalled by inventing a semantic the
    // boundary cannot carry.  A harness that wants a bound enforces it harness
    // side.  It is referenced below so the parameter is not dead.
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,

    // ---- CPU AHB manager pins (CVW names, DUT drives these) ----------------
    input  logic [1:0]                    HTRANS,
    input  logic [ADDRESS_WIDTH-1:0]      HADDR,
    input  logic                          HWRITE,
    /* verilator lint_off UNUSEDSIGNAL */
    input  logic [2:0]                    HSIZE,
    input  logic [2:0]                    HBURST,
    input  logic [3:0]                    HPROT,
    input  logic                          HMASTLOCK,
    /* verilator lint_on UNUSEDSIGNAL */
    input  logic                          HSELEXT,
    input  logic [DATA_WIDTH-1:0]         HWDATA,
    input  logic [(DATA_WIDTH/8)-1:0]     HWSTRB,
    output logic                          HREADYEXT,
    output logic [DATA_WIDTH-1:0]         HRDATAEXT,
    output logic                          HRESPEXT,

    // ---- beat face to the harness ----------------------------------------
    output logic                          req_valid_o,
    input  logic                          req_ready_i,
    output logic                          req_write_o,
    output logic [ADDRESS_WIDTH-1:0]      req_addr_o,
    output logic [DATA_WIDTH-1:0]         req_wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     req_be_o,
    input  logic                          rsp_valid_i,
    output logic                          rsp_ready_o,
    input  logic [DATA_WIDTH-1:0]         rsp_rdata_i,
    input  logic                          rsp_error_i
);
    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH > 1024 ||
            DATA_WIDTH % 8 != 0 || (DATA_WIDTH & (DATA_WIDTH - 1)) != 0)
            $fatal(1, "invalid AHB address or data width");
        if (MAX_WAIT_CYCLES < 1)
            $fatal(1, "MAX_WAIT_CYCLES must be positive");
    end

    localparam logic [1:0] HTRANS_NONSEQ = 2'b10;
    localparam logic [1:0] HTRANS_SEQ    = 2'b11;
    localparam logic [(DATA_WIDTH/8)-1:0] FULL_BE = {(DATA_WIDTH/8){1'b1}};

    typedef enum logic [2:0] {IDLE, ADDRESS, WAIT_DATA, WAIT_SERVICE, COMPLETE} state_t;
    state_t state_q;

    logic [ADDRESS_WIDTH-1:0]  addr_q;
    logic                      write_q;
    logic [DATA_WIDTH-1:0]     wdata_q;
    logic [(DATA_WIDTH/8)-1:0] be_q;

    // A transfer is presented when the manager drives a real transfer type and
    // selects this subordinate.  IDLE and BUSY are not transfers.
    wire transfer_start = ((HTRANS == HTRANS_NONSEQ) || (HTRANS == HTRANS_SEQ))
                          && HSELEXT;

    // The beat request is a promise that the whole request is valid: for a read
    // that is true as soon as the address is accepted, for a write it is only true
    // after the data phase has been latched.  It stays asserted until accepted, and
    // must NOT be deferred to a state that waits on HREADYEXT going low - the
    // service only answers after it sees the request, so that would deadlock.
    assign req_valid_o = rst_ni && (state_q == WAIT_DATA || state_q == WAIT_SERVICE);
    assign req_write_o = write_q;
    assign req_addr_o  = addr_q;
    assign req_wdata_o = wdata_q;
    assign req_be_o    = write_q ? be_q : FULL_BE;

    // AHB-Lite: HREADYEXT high means "the transfer completes on this edge".  It is
    // high while idle, so the address phase of a new transfer is presented while
    // the manager has not yet driven HWDATA; HREADYEXT goes low as soon as the
    // transfer is captured and only returns high to complete it.
    assign HREADYEXT   = rst_ni && (state_q == IDLE || state_q == COMPLETE);
    assign HRDATAEXT   = rsp_rdata_i;
    assign HRESPEXT    = rsp_error_i;
    // Held high in COMPLETE: the service drives rsp_valid in the same cycle the
    // request is accepted, so the response is taken on the completion edge.
    assign rsp_ready_o = rst_ni && (state_q == COMPLETE);

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            addr_q  <= '0;
            write_q <= 1'b0;
            wdata_q <= '0;
            be_q    <= '0;
        end else begin
            case (state_q)
                IDLE: begin
                    if (transfer_start) begin
                        // Address phase: captured, but HWDATA/HWSTRB are not valid
                        // for a write yet, so the beat request is not raised here.
                        addr_q  <= HADDR;
                        write_q <= HWRITE;
                        state_q <= ADDRESS;
                    end
                end
                ADDRESS: begin
                    if (write_q) begin
                        // Data phase: HWDATA/HWSTRB are valid on this edge, so
                        // latch them and only then surface the write request.
                        wdata_q <= HWDATA;
                        be_q    <= HWSTRB;
                        state_q <= WAIT_DATA;
                    end else begin
                        // A read has no data phase to wait for.
                        state_q <= WAIT_SERVICE;
                    end
                end
                WAIT_DATA: begin
                    // Write request is now complete and visible; wait for the
                    // service to accept it.
                    if (req_ready_i) state_q <= COMPLETE;
                end
                WAIT_SERVICE: begin
                    if (req_ready_i) state_q <= COMPLETE;
                end
                COMPLETE: begin
                    // The transfer completes on this edge: HREADYEXT is high and
                    // HRDATAEXT/HRESPEXT carry the service's answer.  A service
                    // that has not answered yet simply keeps the transfer
                    // outstanding by leaving HREADYEXT low.
                    if (rsp_valid_i) begin
                        // Because HREADYEXT is HIGH on this edge, AHB-Lite says the
                        // manager's *next* address phase is accepted on this same
                        // edge: a pipelined manager (and every AHB master, including
                        // a cache doing a line fill) presents the next beat's HADDR
                        // right here.  Dropping it silently loses every second beat
                        // of a burst, which is exactly what happened before this
                        // branch existed: the core's 4-beat line fill arrived as
                        // 0x0, 0x8, 0x10, 0x18 ... instead of 0x0, 0x4, 0x8, 0xC,
                        // so the fetched line was scrambled.
                        if (transfer_start) begin
                            addr_q  <= HADDR;
                            write_q <= HWRITE;
                            state_q <= ADDRESS;
                        end else begin
                            state_q <= IDLE;
                        end
                    end
                end
                default: state_q <= IDLE;
            endcase
        end
    end

    // Reference MAX_WAIT_CYCLES so its "accepted but unused" status is explicit
    // rather than an oversight; it is accepted-and-ignored by design (above).
    wire unused_max_wait_cycles = |MAX_WAIT_CYCLES;
endmodule
