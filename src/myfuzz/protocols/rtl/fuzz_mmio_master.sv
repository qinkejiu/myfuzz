// P7 independent MMIO driver: soc_stimulus.v1 MMIO segment -> beat initiator.
//
// The module consumes exactly the six raw fields the stimulus document records
// (offer, target_selector, offset, write, wdata, be) and drives the frozen
// processor-memory-beat initiator port used by the P5/P6 fabric:
//
//   clk, reset, req_valid, req_ready, write, addr, wdata, be,
//   rsp_valid, rsp_ready, rdata, error
//
// Parameters come from the compiled stimulus document (rtl_projection):
//
//   ADDRESS_WIDTH      mmio offset field width / plan address width
//   DATA_WIDTH         wdata field width
//   SELECTOR_WIDTH     target_selector field width
//   SELECTOR_INVALID   explicit invalid selector value (outside NUM_WINDOWS)
//   NUM_WINDOWS        number of declared address windows
//   ADDRESS_STRATEGY   0 = bias_off (raw address bits), 1 = biased (region+offset)
//   WINDOW_BASE        flat packed window bases, window i at [i*AW +: AW]
//   WINDOW_SIZE        flat packed window sizes, same packing (power of two when
//                      biased addressing is selected)
//
// State machine: idle -> request -> response.
//
//   * An offer is accepted only in idle.  Every payload field is latched then and
//     no raw input is sampled again until the transaction completes, so new raw
//     bits can never change an in-flight transaction.
//   * Every accepted offer completes exactly once: either with the fabric beat
//     response in the response state, or, for an invalid target_selector, with an
//     internal error completion that issues no fabric request.
//   * While busy (request or response) an offer is dropped by a deterministic
//     rule and counted in busy_drop_count.  At most one transaction is pending;
//     there is no queue.
//   * reset terminates an in-flight transaction cleanly and clears the latches,
//     the counters and the recorded error code.  Offers during reset are ignored.
//
// Errors are recorded, never retried: an invalid selector sets
// error_code=ERROR_INVALID_TARGET_SELECTOR and counts in error_count; a fabric
// response with error=1 sets error_code=ERROR_FABRIC_RESPONSE and counts in
// error_count.  Unmapped addresses and unsupported operations are the fabric's
// recorded errors and reach this driver only as that error response.
module fuzz_mmio_master #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer SELECTOR_WIDTH = 1,
    parameter logic [SELECTOR_WIDTH-1:0] SELECTOR_INVALID = {SELECTOR_WIDTH{1'b1}},
    parameter integer NUM_WINDOWS = 1,
    parameter integer ADDRESS_STRATEGY = 0,
    parameter logic [NUM_WINDOWS*ADDRESS_WIDTH-1:0] WINDOW_BASE = '0,
    parameter logic [NUM_WINDOWS*ADDRESS_WIDTH-1:0] WINDOW_SIZE = '0
) (
    input  logic clk,
    input  logic reset,
    input  logic stim_offer,
    input  logic [SELECTOR_WIDTH-1:0] stim_target_selector,
    input  logic [ADDRESS_WIDTH-1:0] stim_offset,
    input  logic stim_write,
    input  logic [DATA_WIDTH-1:0] stim_wdata,
    input  logic [DATA_WIDTH/8-1:0] stim_be,
    output logic req_valid,
    input  logic req_ready,
    output logic write,
    output logic [ADDRESS_WIDTH-1:0] addr,
    output logic [DATA_WIDTH-1:0] wdata,
    output logic [DATA_WIDTH/8-1:0] be,
    input  logic rsp_valid,
    output logic rsp_ready,
    input  logic [DATA_WIDTH-1:0] rdata,
    input  logic error,
    output logic [31:0] busy_drop_count,
    output logic [31:0] error_count,
    output logic [31:0] completion_count,
    output logic [3:0] error_code
);
    localparam integer BYTE_COUNT = DATA_WIDTH / 8;
    localparam integer BIAS_OFF = 0;
    localparam integer BIASED = 1;

    localparam logic [3:0] ERROR_NONE = 4'd0;
    localparam logic [3:0] ERROR_INVALID_TARGET_SELECTOR = 4'd1;
    localparam logic [3:0] ERROR_FABRIC_RESPONSE = 4'd2;

    typedef enum logic [1:0] {IDLE, REQUEST, RESPONSE} state_t;
    state_t state_q;

    logic [SELECTOR_WIDTH-1:0] selector_q;
    logic [ADDRESS_WIDTH-1:0] address_q;
    logic write_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [BYTE_COUNT-1:0] be_q;
    logic [3:0] error_code_q;

    logic [31:0] selector_index;
    logic selector_valid;
    logic [ADDRESS_WIDTH-1:0] selected_base;
    logic [ADDRESS_WIDTH-1:0] selected_size;
    logic [ADDRESS_WIDTH-1:0] resolved_addr;
    logic [ADDRESS_WIDTH-1:0] address_mask;
    logic unused_rdata;

    // The plan address width is exactly the raw offset field width; the mask is
    // recorded in the stimulus document and applied here for bias_off.
    assign address_mask = {ADDRESS_WIDTH{1'b1}};
    assign unused_rdata = ^rdata;

    always_comb begin
        selector_index = 32'(stim_target_selector);
        selector_valid = (selector_index < NUM_WINDOWS) &&
                         (stim_target_selector != SELECTOR_INVALID);
        selected_base = '0;
        selected_size = '0;
        if (selector_index < NUM_WINDOWS) begin
            selected_base = WINDOW_BASE[selector_index*ADDRESS_WIDTH +: ADDRESS_WIDTH];
            selected_size = WINDOW_SIZE[selector_index*ADDRESS_WIDTH +: ADDRESS_WIDTH];
        end
    end

    always_comb begin
        if (ADDRESS_STRATEGY == BIASED) begin
            // region index + offset within the region; sizes are powers of two
            resolved_addr = selected_base + (stim_offset & (selected_size - 1'b1));
        end else begin
            // the raw bits are the address, masked to the plan address width
            resolved_addr = stim_offset & address_mask;
        end
    end

    assign req_valid = !reset && (state_q == REQUEST);
    assign write = (state_q == REQUEST) ? write_q : 1'b0;
    assign addr = (state_q == REQUEST) ? address_q : '0;
    assign wdata = (state_q == REQUEST) ? wdata_q : '0;
    assign be = (state_q == REQUEST) ? be_q : '0;
    assign rsp_ready = !reset && (state_q == RESPONSE);
    assign error_code = error_code_q;

    always_ff @(posedge clk) begin
        if (reset) begin
            state_q <= IDLE;
            selector_q <= '0;
            address_q <= '0;
            write_q <= 1'b0;
            wdata_q <= '0;
            be_q <= '0;
            error_code_q <= ERROR_NONE;
            busy_drop_count <= '0;
            error_count <= '0;
            completion_count <= '0;
        end else begin
            case (state_q)
                IDLE: begin
                    if (stim_offer) begin
                        if (selector_valid) begin
                            selector_q <= stim_target_selector;
                            address_q <= resolved_addr;
                            write_q <= stim_write;
                            wdata_q <= stim_wdata;
                            be_q <= stim_be;
                            state_q <= REQUEST;
                        end else begin
                            // recorded error completion; no fabric request is issued
                            error_count <= error_count + 32'd1;
                            completion_count <= completion_count + 32'd1;
                            error_code_q <= ERROR_INVALID_TARGET_SELECTOR;
                        end
                    end
                end
                REQUEST: begin
                    if (req_ready) state_q <= RESPONSE;
                end
                RESPONSE: begin
                    if (rsp_valid) begin
                        state_q <= IDLE;
                        completion_count <= completion_count + 32'd1;
                        if (error) begin
                            error_count <= error_count + 32'd1;
                            error_code_q <= ERROR_FABRIC_RESPONSE;
                        end else begin
                            error_code_q <= ERROR_NONE;
                        end
                    end
                end
                default: state_q <= IDLE;
            endcase
            // deterministic busy rule: any offer while not idle is dropped and counted
            if ((state_q != IDLE) && stim_offer) begin
                busy_drop_count <= busy_drop_count + 32'd1;
            end
        end
    end

    integer window_index;
    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "invalid MMIO address/data width");
        if (SELECTOR_WIDTH < 1)
            $fatal(1, "SELECTOR_WIDTH must be at least 1");
        if (NUM_WINDOWS < 1)
            $fatal(1, "NUM_WINDOWS must be at least 1");
        if (SELECTOR_INVALID < NUM_WINDOWS)
            $fatal(1, "SELECTOR_INVALID must be outside the declared window range");
        if (ADDRESS_STRATEGY != BIAS_OFF && ADDRESS_STRATEGY != BIASED)
            $fatal(1, "unknown ADDRESS_STRATEGY");
        if (ADDRESS_STRATEGY == BIASED) begin
            for (window_index = 0; window_index < NUM_WINDOWS; window_index = window_index + 1) begin
                if ((WINDOW_SIZE[window_index*ADDRESS_WIDTH +: ADDRESS_WIDTH] == '0) ||
                    ((WINDOW_SIZE[window_index*ADDRESS_WIDTH +: ADDRESS_WIDTH] &
                      (WINDOW_SIZE[window_index*ADDRESS_WIDTH +: ADDRESS_WIDTH] - 1'b1)) != '0))
                    $fatal(1, "biased addressing requires non-zero power-of-two window sizes");
            end
        end
    end
endmodule
