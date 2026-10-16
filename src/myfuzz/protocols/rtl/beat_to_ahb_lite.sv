// beat_to_ahb_lite: adapter from the internal processor-memory-beat face to an
// AHB-Lite initiator (manager) port.
//
// WHY THIS EXISTS
//   CVW (CORE-V Wally) is the repository's only real AHB-Lite boundary
//   (configs/cpus/cvw/interface_description.json, derived from
//   third_party/cvw_upstream_reference/src/wally/wallypipelinedsoc.sv).  It has
//   a CPU-side contract (cpu.ahb-lite / cvw-external-bus) and its top level
//   elaborates with Verilator, but the runtime renderer had no AHB branch and
//   src/myfuzz/protocols/rtl/ contained no AHB file at all, so no runnable
//   harness could be produced for it.  This module is that missing piece.
//
// DIRECTION
//   processor-memory-beat INITIATOR (our harness) -> this adapter -> AHB-Lite
//   MANAGER port (the DUT's AHB slave-facing boundary).  One outstanding
//   transaction, matching every other adapter in this directory.
//
// BEAT PORT CONTRACT (same names as wishbone_mmio_bridge / beat_to_wishbone):
//   clk_i, rst_ni, req_valid_i, req_write_i, req_addr_i, req_wdata_i, req_be_i,
//   req_ready_o, rsp_valid_o, rsp_ready_i, rsp_rdata_o, rsp_error_o.
//   rst_ni is synchronous and active low.
//
// AHB-LITE SIGNALS, taken verbatim from the CVW boundary:
//   outputs HTRANS HADDR HWRITE HSIZE HBURST HPROT HMASTLOCK HWDATA HWSTRB
//   inputs  HREADYEXT HRDATAEXT HRESPEXT
//   Clock/reset (HCLK/HRESETn) are harness-level signals, exactly as CVW
//   declares them, so this adapter does not drive them.
//   Two facts about that boundary are deliberate and must not be "corrected":
//     * read data arrives as HRDATAEXT, not HRDATA (src/ebu/ebu.sv has no
//       HRDATA port at all: its comment reads "HRDATA is sent to all
//       controllers at the core level");
//     * HSELEXT is a CVW chip-select extension rather than an AHB-Lite signal,
//       so this adapter does not drive it.
//
// AHB-LITE PHASE SEMANTICS IMPLEMENTED
//   * HTRANS = NONSEQ (2'b10) for one address phase; the manager offers the
//     address for exactly one cycle and then returns to IDLE (2'b00).  AHB-Lite
//     permits HTRANS to change every cycle, so this adapter never claims SEQ.
//   * HBURST = SINGLE (3'b000) and HMASTLOCK = 0: no burst, no lock.  Both are
//     driven rather than tied off so the boundary is explicit.
//   * HPROT is derived from nothing the beat face carries, so it is driven to
//     the architectural default 4'b0011 (data access, privileged, non-bufferable,
//     non-cacheable) and that choice is stated here rather than implied.
//   * HSIZE is computed from HWSTRB: a transfer whose byte lanes are contiguous
//     and naturally aligned gets the matching size (8/16/32-bit, and 64-bit when
//     DATA_WIDTH >= 64); anything else falls back to the full data width with
//     byte strobes doing the fine-grained selection.  HSIZE is an output the
//     adapter owns, not something the beat face states, so the rule is explicit.
//   * HWDATA/HWSTRB are registered one cycle after the address phase, which is
//     what AHB-Lite requires (the write data phase follows the address phase).
//   * A transfer completes when the subordinate asserts HREADYEXT: that is the
//     single completion rule in AHB-Lite.  HRESPEXT is sampled on that same edge
//     and reported as rsp_error_o, so an error is observed rather than invented.
//   * A held HREADYEXT is bounded by MAX_WAIT_CYCLES and reported as a timeout
//     error completion, so a stuck subordinate cannot hang a campaign.
//
// DELIBERATELY NOT DONE
//   * No burst support (HBURST is driven SINGLE even when the beat face would
//     allow more) and therefore no SEQ beats.
//   * No HSELEXT drive, no HRDATA/HREADY alias, no HCLK/HRESETn drive.
//   * No attempt to model arbitration: this adapter is one manager.
//   * Untested against real RTL at the time of writing - see the task that added
//     it.  It has no elaborated CVW port to bind to yet; the CPU-side profile and
//     source lock are separate work.
module beat_to_ahb_lite #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,
    // Internal processor-memory-beat face.
    input  logic                          req_valid_i,
    input  logic                          req_write_i,
    input  logic [ADDRESS_WIDTH-1:0]      req_addr_i,
    input  logic [DATA_WIDTH-1:0]         req_wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]     req_be_i,
    output logic                          req_ready_o,
    output logic                          rsp_valid_o,
    input  logic                          rsp_ready_i,
    output logic [DATA_WIDTH-1:0]         rsp_rdata_o,
    output logic                          rsp_error_o,
    // AHB-Lite manager boundary (CVW names).
    output logic [1:0]                    HTRANS,
    output logic [ADDRESS_WIDTH-1:0]      HADDR,
    output logic                          HWRITE,
    output logic [2:0]                    HSIZE,
    output logic [2:0]                    HBURST,
    output logic [3:0]                    HPROT,
    output logic                          HMASTLOCK,
    output logic [DATA_WIDTH-1:0]         HWDATA,
    output logic [(DATA_WIDTH/8)-1:0]     HWSTRB,
    // HSELEXT is CVW's external-memory chip select: a CVW extension rather than
    // an AHB-Lite signal.  The adapter drives it asserted because this harness
    // models exactly one external region; the profile records it as observed.
    output logic                          HSELEXT,
    input  logic                          HREADYEXT,
    input  logic [DATA_WIDTH-1:0]         HRDATAEXT,
    input  logic                          HRESPEXT
);
    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH > 1024 ||
            DATA_WIDTH % 8 != 0 || (DATA_WIDTH & (DATA_WIDTH - 1)) != 0)
            $fatal(1, "invalid beat/AHB address or data width");
        if (MAX_WAIT_CYCLES < 1)
            $fatal(1, "MAX_WAIT_CYCLES must be positive");
    end

    localparam logic [1:0] HTRANS_IDLE   = 2'b00;
    localparam logic [1:0] HTRANS_NONSEQ = 2'b10;
    localparam logic [2:0] HBURST_SINGLE = 3'b000;
    // Architecture default: data access, privileged, non-bufferable, non-cacheable.
    localparam logic [3:0] HPROT_DEFAULT = 4'b0011;

    localparam integer BE_BITS = DATA_WIDTH / 8;

    typedef enum logic [1:0] {IDLE, ADDRESS, DATA} state_t;
    state_t state_q;

    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0]    wdata_q;
    logic [BE_BITS-1:0]       be_q;
    logic                     write_q;
    logic [2:0]               size_q;
    logic [15:0]              wait_q;
    logic                     rsp_valid_q, error_q, timeout_q;
    logic [DATA_WIDTH-1:0]    rdata_q;

    // HSIZE from the byte strobes: a contiguous, naturally aligned lane group.
    localparam integer BE_BITS_LOG2 = $clog2(BE_BITS);
    localparam logic [2:0] SIZE_FULL = (DATA_WIDTH == 8) ? 3'b000 :
                                       (DATA_WIDTH == 16) ? 3'b001 :
                                       (DATA_WIDTH == 32) ? 3'b010 : 3'b011;

    function automatic logic [2:0] size_for(logic [BE_BITS-1:0] be,
                                            logic [BE_BITS_LOG2-1:0] offset);
        integer low, high, count, bit_index;
        begin
            low = -1;
            high = -1;
            count = 0;
            for (bit_index = 0; bit_index < BE_BITS; bit_index = bit_index + 1) begin
                if (be[bit_index]) begin
                    if (low < 0) low = bit_index;
                    high = bit_index;
                    count = count + 1;
                end
            end
            // Contiguous lanes only, and naturally aligned: the lowest lane index
            // must equal the byte offset the address selects.  Anything else keeps
            // the full data width and lets HWSTRB do the fine-grained selection.
            if (count == 0 || count != (high - low + 1) || low != int'(offset))
                size_for = SIZE_FULL;
            else
                size_for = (count == 1) ? 3'b000 :
                           (count == 2) ? 3'b001 :
                           (count == 4) ? 3'b010 : SIZE_FULL;
        end
    endfunction

    assign req_ready_o = rst_ni && (state_q == IDLE) && !rsp_valid_q;
    // The beat face is a handshake: a completion is held until the consumer
    // accepts it, which is what the other adapters in this directory do.
    assign rsp_valid_o = rsp_valid_q;
    assign rsp_rdata_o = rdata_q;
    assign rsp_error_o = error_q || timeout_q;

    assign HTRANS    = (state_q == ADDRESS) ? HTRANS_NONSEQ : HTRANS_IDLE;
    assign HADDR     = (state_q == ADDRESS) ? addr_q : '0;
    assign HWRITE    = (state_q != IDLE) && write_q;
    assign HSIZE     = (state_q == ADDRESS) ? size_q : 3'b010;
    assign HBURST    = HBURST_SINGLE;
    assign HPROT     = HPROT_DEFAULT;
    assign HMASTLOCK = 1'b0;
    assign HWDATA    = (state_q == DATA) ? wdata_q : '0;
    assign HWSTRB    = (state_q == DATA) ? be_q : '0;
    assign HSELEXT   = 1'b1;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q  <= IDLE;
            addr_q   <= '0;
            wdata_q  <= '0;
            be_q     <= '0;
            write_q  <= 1'b0;
            size_q   <= 3'b010;
            wait_q   <= 16'd0;
            rsp_valid_q <= 1'b0;
            error_q  <= 1'b0;
            timeout_q <= 1'b0;
            rdata_q  <= '0;
        end else begin
            if (rsp_valid_q && rsp_ready_i) begin
                // Completion accepted; the error flag is cleared with it so a
                // later transaction cannot inherit it.
                rsp_valid_q <= 1'b0;
                error_q  <= 1'b0;
                timeout_q <= 1'b0;
            end
            case (state_q)
                IDLE: begin
                    wait_q <= 16'd0;
                    if (req_valid_i && !rsp_valid_q) begin
                        addr_q  <= req_addr_i;
                        wdata_q <= req_wdata_i;
                        be_q    <= req_be_i;
                        write_q <= req_write_i;
                        size_q  <= size_for(req_be_i, req_addr_i[BE_BITS_LOG2-1:0]);
                        state_q <= ADDRESS;
                    end
                end
                ADDRESS: begin
                    // One-cycle address phase, then the data phase.
                    state_q <= DATA;
                end
                DATA: begin
                    if (HREADYEXT) begin
                        rsp_valid_q <= 1'b1;
                        rdata_q     <= HRDATAEXT;
                        error_q     <= HRESPEXT;
                        state_q     <= IDLE;
                    end else if (wait_q >= 16'(MAX_WAIT_CYCLES - 1)) begin
                        // A held HREADYEXT is a timeout completion, not a hang.
                        rsp_valid_q <= 1'b1;
                        rdata_q     <= '0;
                        timeout_q   <= 1'b1;
                        state_q     <= IDLE;
                    end else begin
                        wait_q <= wait_q + 16'd1;
                    end
                end
                default: state_q <= IDLE;
            endcase
        end
    end
endmodule
