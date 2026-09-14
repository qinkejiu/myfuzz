// beat_to_apb: target-side adapter from a processor-memory-beat initiator to an
// APB peripheral target.
//
// DIRECTION (fixed by task P5):
//   processor-memory-beat INITIATOR (arbiter/router output) -> this adapter ->
//   APB TARGET (PULP apb_gpio / apb_spi_master style peripheral).
// This is not apb3_mmio_bridge/apb4_mmio_bridge reused backwards.  Those
// bridges are CPU side: they consume an APB initiator and produce beat
// requests.  This module consumes beat requests and drives an APB target.
//
// Beat initiator port contract (exactly these names, first release = one
// outstanding transaction):
//   clk, reset, req_valid, req_ready, write, addr[AW-1:0], wdata[DW-1:0],
//   be[DW/8-1:0], rsp_valid, rsp_ready, rdata[DW-1:0], error
// reset is synchronous and active high.  The surrounding *_mmio_bridge.sv
// modules use an active-low rst_ni; the P5 beat contract fixes this port as an
// active-high "reset", so a parent that owns an rst_ni domain must invert it
// when instantiating this adapter.
//
// Reported target capability (from configs/soc/closures/*.json):
//   HAS_PSTRB                 1 for APB4 (PSTRB present), 0 for APB3.
//   SUPPORTS_PARTIAL_WRITE    1 only when the target really implements a
//                             per-byte write mask.  PULP apb_gpio and
//                             apb_spi_master are APB3 with no PSTRB and
//                             hardwired PREADY=1/PSLVERR=0, so they resolve to
//                             0 and every non-all-ones write is answered with a
//                             beat error response and ZERO APB transfers.
//                             No read-modify-write is ever synthesised.
//   HAS_PSLVERR               1 when the IP has a PSLVERR output.  When 0 the
//                             parent must tie pslverr to 1'b0 (no invented
//                             pin); adapter-side rejections still set error.
//
// Phase generation: psel with penable low for at least one SETUP cycle, then
// penable high until PREADY.  paddr/pwrite/pwdata/pstrb are registered and held
// stable through any number of wait states.  PREADY constant 1 completes in the
// first ACCESS cycle.
//
// A target that is not addressed (address outside WINDOW_BASE..+WINDOW_SIZE) is
// rejected locally: beat error response, psel/penable stay low, no APB transfer.

module beat_to_apb #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer HAS_PSTRB = 1,
    parameter integer SUPPORTS_PARTIAL_WRITE = 1,
    parameter integer HAS_PSLVERR = 1,
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

    output logic [ADDRESS_WIDTH-1:0]      paddr,
    output logic                          psel,
    output logic                          penable,
    output logic                          pwrite,
    output logic [DATA_WIDTH-1:0]         pwdata,
    output logic [(DATA_WIDTH/8)-1:0]     pstrb,
    input  logic                          pready,
    input  logic [DATA_WIDTH-1:0]         prdata,
    input  logic                          pslverr
);

    localparam integer BYTE_ENABLE_WIDTH = DATA_WIDTH / 8;
    localparam logic [BYTE_ENABLE_WIDTH-1:0] FULL_BE = {BYTE_ENABLE_WIDTH{1'b1}};
    localparam logic [ADDRESS_WIDTH-1:0] WINDOW_LIMIT = WINDOW_SIZE;
    localparam integer WAIT_COUNTER_WIDTH =
        (MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(MAX_WAIT_CYCLES - 1);

    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "beat_to_apb: invalid address or data width");
        if ((HAS_PSTRB != 0 && HAS_PSTRB != 1) ||
            (SUPPORTS_PARTIAL_WRITE != 0 && SUPPORTS_PARTIAL_WRITE != 1) ||
            (HAS_PSLVERR != 0 && HAS_PSLVERR != 1))
            $fatal(1, "beat_to_apb: feature parameters must be boolean");
        if (SUPPORTS_PARTIAL_WRITE != 0 && HAS_PSTRB == 0)
            $fatal(1, "beat_to_apb: partial writes require the APB4 PSTRB field");
        if (MAX_WAIT_CYCLES < 1)
            $fatal(1, "beat_to_apb: MAX_WAIT_CYCLES must be positive");
        if (WINDOW_SIZE < 0 || WINDOW_SIZE % BYTE_ENABLE_WIDTH != 0)
            $fatal(1, "beat_to_apb: WINDOW_SIZE must be a multiple of the data width");
        if (WINDOW_SIZE != 0 &&
            (WINDOW_LIMIT == 0 || WINDOW_BASE % BYTE_ENABLE_WIDTH != 0))
            $fatal(1, "beat_to_apb: window does not fit the address width or is misaligned");
    end

    typedef enum logic [1:0] {
        IDLE,
        SETUP,
        ACCESS
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

    logic in_window;
    logic partial_write_rejected;
    logic pslverr_effective;

    assign in_window = (WINDOW_SIZE <= 0) ||
                       ((addr - WINDOW_BASE) < WINDOW_LIMIT);
    assign partial_write_rejected =
        (SUPPORTS_PARTIAL_WRITE == 0) && write && (be != FULL_BE);
    assign pslverr_effective = (HAS_PSLVERR != 0) && pslverr;

    assign req_ready = !reset && (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid = rsp_valid_q;
    assign rdata = rsp_rdata_q;
    assign error = rsp_error_q;

    assign paddr = (state_q == IDLE) ? '0 : addr_q;
    assign psel = (state_q == SETUP) || (state_q == ACCESS);
    assign penable = (state_q == ACCESS);
    assign pwrite = psel && write_q;
    assign pwdata = (state_q == IDLE) ? '0 : wdata_q;
    assign pstrb = (HAS_PSTRB != 0 && state_q != IDLE && write_q) ? be_q : '0;

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
        end else begin
            if (rsp_valid_q && rsp_ready) rsp_valid_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    wait_count_q <= '0;
                    if (req_valid && !rsp_valid_q) begin
                        if (!in_window || partial_write_rejected) begin
                            // Local rejection: no APB transfer is issued at all.
                            rsp_valid_q <= 1'b1;
                            rsp_rdata_q <= '0;
                            rsp_error_q <= 1'b1;
                        end else begin
                            addr_q <= addr;
                            write_q <= write;
                            wdata_q <= wdata;
                            be_q <= be;
                            state_q <= SETUP;
                        end
                    end
                end
                SETUP: state_q <= ACCESS;
                ACCESS: begin
                    if (pready) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= (write_q || pslverr_effective) ? '0 : prdata;
                        rsp_error_q <= pslverr_effective;
                    end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0;
                        rsp_error_q <= 1'b1;
                    end else begin
                        wait_count_q <= wait_count_q + 1'b1;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    wait_count_q <= '0;
                    rsp_valid_q <= 1'b1;
                    rsp_rdata_q <= '0;
                    rsp_error_q <= 1'b1;
                end
            endcase
        end
    end

endmodule
