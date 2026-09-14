// beat_to_wishbone: target-side adapter from a processor-memory-beat initiator
// to a Wishbone peripheral target.
//
// DIRECTION (fixed by task P5):
//   processor-memory-beat INITIATOR (arbiter/router output) -> this adapter ->
//   Wishbone TARGET (ZipCPU wbuart / ziptimer style peripheral).
// This is not wishbone_mmio_bridge reused backwards.  That bridge is CPU side:
// it consumes a Wishbone initiator and produces beat requests.  This module
// consumes beat requests and drives a Wishbone target.
//
// Beat initiator port contract (exactly these names, first release = one
// outstanding transaction):
//   clk, reset, req_valid, req_ready, write, addr[AW-1:0], wdata[DW-1:0],
//   be[DW/8-1:0], rsp_valid, rsp_ready, rdata[DW-1:0], error
// reset is synchronous and active high.  The surrounding *_mmio_bridge.sv
// modules use an active-low rst_ni; the P5 beat contract fixes this port as an
// active-high "reset", so a parent that owns an rst_ni domain must invert it.
//
// request_accepted vs completion:
//   request_accepted : one-cycle pulse in the cycle the adapter asserts the bus
//                      request (CYC/STB) for an accepted beat request.
//   completion       : one-cycle pulse in the cycle the target terminates the
//                      bus cycle (ACK or ERR).  rsp_valid is the beat-side
//                      completion and may wait for rsp_ready.
//
// WB_FLAVOUR selects the recorded target handshake configuration:
//   0 = classic               CYC/STB/ADR/DAT_W/SEL are asserted and held until
//                             ACK or ERR completes the cycle.
//   1 = registered-ack        STB is a ONE-CYCLE pulse and CYC stays asserted
//                             into the following cycle and until ACK/ERR.  This
//                             is the wbuart requirement: o_wb_ack is gated by
//                             CYC in T+1 and appears in T+2, while STB alone
//                             triggers the register action in T (a classic
//                             strobe hold would repeat the side effect).
//   2 = registered-ack, CYC   STB is a ONE-CYCLE pulse, CYC is asserted for the
//       ignored               pulse cycle and one following cycle and is then
//                             released.  This is the ziptimer requirement: CYC
//                             is ignored by the IP and ACK is a registered copy
//                             of STB one cycle later.  The adapter still drives
//                             well-formed CYC while STB is asserted.
//
// stall is deliberately unused: both pinned ZipCPU targets tie o_wb_stall low,
// and Wishbone B4 STALL is pipeline admission rather than response
// backpressure.  Completion is ACK or ERR only.
//
// Reported target capability (from configs/soc/closures/*.json):
//   TARGET_ADDRESS_WIDTH   0 when the IP has no address port (ziptimer).  adr
//                          is then a 1-bit tie-off (leave unconnected) and an
//                          explicit WINDOW_BASE/WINDOW_SIZE window is
//                          mandatory; out-of-window accesses are rejected with
//                          a beat error and no bus cycle.
//   ADDRESS_UNITS          0 = byte address, 1 = word address (wbuart consumes
//                          two word-index bits, no byte-offset bits).
//   SUPPORTS_PARTIAL_WRITE 0 when i_wb_sel is unimplemented (ziptimer) or only
//                          register-specific (wbuart).  Sub-word writes are then
//                          answered with a beat error response and ZERO bus
//                          cycles; no read-modify-write is synthesised.
//   HAS_ERR                1 when the target really has an ERR output.  When 0
//                          (both ZipCPU IPs) the target has no error pin: the
//                          parent fabric must drive err with its own decode
//                          error.  No target pin is invented.

module beat_to_wishbone #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer WB_FLAVOUR = 0,
    parameter integer TARGET_ADDRESS_WIDTH = 0,
    parameter integer ADDRESS_UNITS = 0,
    parameter integer SUPPORTS_PARTIAL_WRITE = 1,
    parameter integer HAS_ERR = 0,
    parameter integer MAX_WAIT_CYCLES = 16,
    parameter logic [ADDRESS_WIDTH-1:0] WINDOW_BASE = '0,
    parameter integer WINDOW_SIZE = 0
) (
    input  logic                          clk,
    input  logic                          reset,

    input  logic                          req_valid,
    output logic                          req_ready,
    input  logic                          write,
    input  logic [ADDRESS_WIDTH-1:0]      addr,
    input  logic [DATA_WIDTH-1:0]         wdata,
    input  logic [(DATA_WIDTH/8)-1:0]     be,

    output logic                          rsp_valid,
    input  logic                          rsp_ready,
    output logic [DATA_WIDTH-1:0]         rdata,
    output logic                          error,

    output logic                          request_accepted,
    output logic                          completion,

    output logic                          cyc,
    output logic                          stb,
    output logic                          we,
    output logic [( (TARGET_ADDRESS_WIDTH > 0) ? TARGET_ADDRESS_WIDTH : 1 )-1:0] adr,
    output logic [DATA_WIDTH-1:0]         dat_w,
    output logic [(DATA_WIDTH/8)-1:0]     sel,
    input  logic                          ack,
    input  logic                          err,
    input  logic                          stall,
    input  logic [DATA_WIDTH-1:0]         dat_r
);

    localparam integer BYTE_ENABLE_WIDTH = DATA_WIDTH / 8;
    localparam integer ADDRESS_PORT_WIDTH =
        (TARGET_ADDRESS_WIDTH > 0) ? TARGET_ADDRESS_WIDTH : 1;
    localparam integer LOG2_BYTE_ENABLE =
        (BYTE_ENABLE_WIDTH <= 1) ? 0 : $clog2(BYTE_ENABLE_WIDTH);
    localparam logic [BYTE_ENABLE_WIDTH-1:0] FULL_BE = {BYTE_ENABLE_WIDTH{1'b1}};
    localparam logic [ADDRESS_WIDTH-1:0] WINDOW_LIMIT = WINDOW_SIZE;
    localparam integer WAIT_COUNTER_WIDTH =
        (MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(MAX_WAIT_CYCLES - 1);

    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "beat_to_wishbone: invalid address or data width");
        if (WB_FLAVOUR < 0 || WB_FLAVOUR > 2)
            $fatal(1, "beat_to_wishbone: WB_FLAVOUR must be 0 (classic), 1 (registered-ack) or 2 (registered-ack, CYC ignored)");
        if (TARGET_ADDRESS_WIDTH < 0 || TARGET_ADDRESS_WIDTH > ADDRESS_WIDTH)
            $fatal(1, "beat_to_wishbone: TARGET_ADDRESS_WIDTH is out of range");
        if ((ADDRESS_UNITS != 0 && ADDRESS_UNITS != 1) ||
            (SUPPORTS_PARTIAL_WRITE != 0 && SUPPORTS_PARTIAL_WRITE != 1) ||
            (HAS_ERR != 0 && HAS_ERR != 1))
            $fatal(1, "beat_to_wishbone: capability parameters must be boolean");
        if (TARGET_ADDRESS_WIDTH == 0 && WINDOW_SIZE <= 0)
            $fatal(1, "beat_to_wishbone: a target without an address port requires an explicit window");
        if (MAX_WAIT_CYCLES < 1)
            $fatal(1, "beat_to_wishbone: MAX_WAIT_CYCLES must be positive");
        if (WINDOW_SIZE < 0 || WINDOW_SIZE % BYTE_ENABLE_WIDTH != 0)
            $fatal(1, "beat_to_wishbone: WINDOW_SIZE must be a multiple of the data width");
        if (WINDOW_SIZE != 0 &&
            (WINDOW_LIMIT == 0 || WINDOW_BASE % BYTE_ENABLE_WIDTH != 0))
            $fatal(1, "beat_to_wishbone: window does not fit the address width or is misaligned");
    end

    typedef enum logic [1:0] {
        IDLE,
        REQUEST,
        WAIT
    } state_t;

    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic write_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [BYTE_ENABLE_WIDTH-1:0] be_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic rsp_valid_q;
    logic [DATA_WIDTH-1:0] rsp_rdata_q;
    logic rsp_error_q;
    logic request_accepted_q;
    logic cyc_q;
    logic [ADDRESS_WIDTH-1:0] offset;
    logic [ADDRESS_WIDTH-1:0] word_offset;
    logic [ADDRESS_PORT_WIDTH-1:0] adr_value;
    logic bus_active;
    logic bus_complete;
    logic in_window;
    logic partial_write_rejected;

    assign in_window = (WINDOW_SIZE <= 0) ||
                       ((addr - WINDOW_BASE) < WINDOW_LIMIT);
    assign partial_write_rejected =
        (SUPPORTS_PARTIAL_WRITE == 0) && write && (be != FULL_BE);
    assign bus_active = (state_q == REQUEST) || (state_q == WAIT);
    assign bus_complete = bus_active && (ack || err);

    always_comb begin
        offset = addr_q - WINDOW_BASE;
        word_offset = offset >> LOG2_BYTE_ENABLE;
        adr_value = ADDRESS_PORT_WIDTH'((ADDRESS_UNITS != 0) ? word_offset : offset);
    end

    assign req_ready = !reset && (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid = rsp_valid_q;
    assign rdata = rsp_rdata_q;
    assign error = rsp_error_q;
    assign request_accepted = request_accepted_q;
    assign completion = bus_complete;

    assign cyc = bus_active && ((state_q == REQUEST) || cyc_q);
    assign stb = (state_q == REQUEST);
    assign we = cyc && write_q;
    assign adr = cyc ? adr_value : '0;
    assign dat_w = cyc ? wdata_q : '0;
    assign sel = cyc ? be_q : '0;

    always_ff @(posedge clk) begin
        if (reset) begin
            state_q <= IDLE;
            addr_q <= '0;
            write_q <= 1'b0;
            wdata_q <= '0;
            be_q <= '0;
            wait_count_q <= '0;
            rsp_valid_q <= 1'b0;
            rsp_rdata_q <= '0;
            rsp_error_q <= 1'b0;
            request_accepted_q <= 1'b0;
            cyc_q <= 1'b0;
        end else begin
            request_accepted_q <= 1'b0;
            if (rsp_valid_q && rsp_ready) rsp_valid_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    wait_count_q <= '0;
                    if (req_valid && !rsp_valid_q) begin
                        if (!in_window || partial_write_rejected) begin
                            // Local rejection: no bus cycle is issued at all.
                            rsp_valid_q <= 1'b1;
                            rsp_rdata_q <= '0;
                            rsp_error_q <= 1'b1;
                        end else begin
                            addr_q <= addr;
                            write_q <= write;
                            wdata_q <= wdata;
                            be_q <= be;
                            state_q <= REQUEST;
                            request_accepted_q <= 1'b1;
                            cyc_q <= 1'b1;
                        end
                    end
                end
                REQUEST: begin
                    if (bus_complete) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        cyc_q <= 1'b0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= (err || write_q) ? '0 : dat_r;
                        rsp_error_q <= err;
                    end else if (WB_FLAVOUR == 0) begin
                        // Classic cycle: hold CYC/STB/ADR/DAT_W/SEL until completion.
                        if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                            state_q <= IDLE;
                            wait_count_q <= '0;
                            cyc_q <= 1'b0;
                            rsp_valid_q <= 1'b1;
                            rsp_rdata_q <= '0;
                            rsp_error_q <= 1'b1;
                        end else begin
                            wait_count_q <= wait_count_q + 1'b1;
                        end
                    end else begin
                        // Registered-ack cycle: exactly one STB cycle, CYC held
                        // into the following cycle.
                        state_q <= WAIT;
                        wait_count_q <= '0;
                        cyc_q <= 1'b1;
                    end
                end
                WAIT: begin
                    if (bus_complete) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        cyc_q <= 1'b0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= (err || write_q) ? '0 : dat_r;
                        rsp_error_q <= err;
                    end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        cyc_q <= 1'b0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0;
                        rsp_error_q <= 1'b1;
                    end else begin
                        wait_count_q <= wait_count_q + 1'b1;
                        // Flavour 2 targets ignore CYC, so it is released after
                        // the pulse cycle and one following cycle.  Flavour 1
                        // targets gate ACK with CYC, so CYC is held.
                        cyc_q <= (WB_FLAVOUR == 1);
                    end
                end
                default: begin
                    state_q <= IDLE;
                    wait_count_q <= '0;
                    cyc_q <= 1'b0;
                    rsp_valid_q <= 1'b1;
                    rsp_rdata_q <= '0;
                    rsp_error_q <= 1'b1;
                end
            endcase
        end
    end

endmodule
