// Level-triggered interrupt controller with a 32-bit MMIO register window.
//
// The controller keeps one pending bit, one enable bit and at most one
// in-service source. Bit k of source_i is source ID k+1, so bitmap bit k of
// PENDING[j] belongs to source ID 32*j+k and bitmap bit 0 is the reserved ID 0.
// Pending is level state by default: every source that is neither in service nor
// claimed on the current edge is sampled straight from its input, so an asserted
// source sets pending and a deasserted source clears it. A source held in
// service is not sampled until COMPLETE retires it, which is exactly what makes
// a still-asserted source re-pend one sampling edge after completion while a
// source that was cleared before COMPLETE stays quiet.
//
// A source whose output is a *moment* rather than a *state* cannot use that
// rule: a bounded pulse is only visible for its own width, so a controller that
// followed it would drop the event long before the CPU could claim it. Such a
// source is declared LATCHED in LATCH_MASK, and its pending bit is then
// set-dominant (``pending | source``) and cleared only by CLAIM. That is what
// lets a same-domain pulse -- a peripheral's one-cycle event output, or the
// output of ``soc_irq_edge_detect`` -- survive until software services it, while
// a level source keeps following its input exactly as before.
//
// The MMIO slave accepts one request while no response is outstanding and holds
// the registered response stable until rsp_ready_i accepts it. Only full 32-bit
// accesses are legal; every illegal address, direction or byte enable answers
// with rsp_error_o and no side effect. reset is synchronous, has priority over
// request acceptance and clears pending, enable, in-service and the response
// state. The handshake outputs are additionally qualified with rst_ni so that
// they read 0 while reset is asserted.
module soc_irq_controller #(
    parameter integer NUM_SOURCES = 1,        // number of physical interrupt sources, >= 1
    parameter integer ADDRESS_WIDTH = 12,     // byte address width of the MMIO window, >= 5
    // Bit i set means source i (controller bit i, source id i+1) is latched: its
    // pending bit is set by any sampled high and cleared only by CLAIM, instead
    // of following the input level. The default of all zeros is the original
    // level-for-every-source behaviour.
    parameter logic [NUM_SOURCES-1:0] LATCH_MASK = {NUM_SOURCES{1'b0}}
) (
    input  logic                        clk_i,
    input  logic                        rst_ni,        // active-low synchronous reset

    // Normalized interrupt sources: active-high level, bit k is source ID k+1.
    input  logic [NUM_SOURCES-1:0]      source_i,
    // Single same-domain active-high notification to the CPU entry point.
    output logic                        irq_o,

    // 32-bit MMIO slave (one outstanding request/response).
    input  logic                        req_valid_i,
    output logic                        req_ready_o,
    input  logic                        req_write_i,
    input  logic [ADDRESS_WIDTH-1:0]    req_addr_i,
    input  logic [31:0]                 req_wdata_i,
    input  logic [3:0]                  req_be_i,
    output logic                        rsp_valid_o,
    input  logic                        rsp_ready_i,
    output logic [31:0]                 rsp_rdata_o,
    output logic                        rsp_error_o
);
  // Number of 32-bit bitmap words covering the reserved ID 0 and IDs 1..NUM_SOURCES.
  localparam integer B = (NUM_SOURCES + 1 + 31) / 32;
  // Encoded source ID width; the encoded value 0 means "no source in service".
  localparam integer ID_WIDTH = (NUM_SOURCES + 1 <= 1) ? 1 : $clog2(NUM_SOURCES + 1);
  // ID_WIDTH never exceeds 32 bits for a realizable source count, so the zero
  // padding below is a legal replication.
  localparam integer ID_PAD = (ID_WIDTH < 32) ? (32 - ID_WIDTH) : 0;
  // 0x00..0x1f is 8 header words, then B PENDING words, then B ENABLE words.
  localparam integer REG_WORDS = 8 + 2*B;
  localparam integer PENDING_BASE_WORD = 8;
  localparam integer ENABLE_BASE_WORD = 8 + B;
  localparam [31:0] SOURCE_COUNT_VALUE = NUM_SOURCES;
  localparam [3:0] FULL_BE = 4'b1111;

  logic [NUM_SOURCES-1:0] pending_q;
  logic [NUM_SOURCES-1:0] enable_q;
  logic [NUM_SOURCES-1:0] service_q;
  logic [ID_WIDTH-1:0]    service_id_q;
  logic                   rsp_valid_q;
  logic [31:0]            rsp_rdata_q;
  logic                   rsp_error_q;

  logic                   claim_valid;
  logic                   busy;
  logic [ID_WIDTH-1:0]    complete_id;
  logic                   complete_id_ok;
  logic                   accept_req;
  logic                   is_claim;
  logic                   is_complete;
  logic                   is_in_service;
  logic                   is_source_count;
  logic                   is_pending_word;
  logic                   is_enable_word;
  logic                   read_legal;
  logic [31:0]            read_data;
  logic [31:0]            op_rdata;
  logic                   op_error;
  logic                   op_claim_read;
  logic                   op_complete_write;
  logic                   op_enable_write;

  integer claim_scan_index;
  integer claim_index;
  integer sample_index;
  integer service_index;
  integer enable_index;
  integer word_index;
  integer address_bit;
  integer bitmap_base;
  integer bitmap_bit;
  integer bitmap_id;
  integer enable_word_select;
  logic [31:0] bitmap_word;

  initial begin
    if ((NUM_SOURCES < 1) || (ADDRESS_WIDTH < 5))
      $fatal(1, "invalid soc_irq_controller parameters");
  end

  assign busy = (service_id_q != {ID_WIDTH{1'b0}});
  assign complete_id = req_wdata_i[ID_WIDTH-1:0];
  assign complete_id_ok = (complete_id != {ID_WIDTH{1'b0}}) && (complete_id == service_id_q);

  // Notification is a level function of the state before the current edge: the
  // pending bit must be enabled, its source must not be in service, and the
  // controller must be idle (a busy controller notifies nothing).
  assign irq_o = rst_ni && !busy && claim_valid;

  // One outstanding response: a new request is accepted only when the previous
  // response has been taken, and never while reset is asserted.
  assign req_ready_o = rst_ni && !rsp_valid_q;
  assign rsp_valid_o = rst_ni && rsp_valid_q;
  assign rsp_rdata_o = rsp_rdata_q;
  assign rsp_error_o = rsp_error_q;

  // Fixed lowest-ID priority over the pre-edge state. A level that first appears
  // on the current edge is still invisible here, so it can only be claimed by a
  // request that arrives afterwards.
  always_comb begin
    claim_index = 0;
    claim_valid = 1'b0;
    for (claim_scan_index = NUM_SOURCES - 1; claim_scan_index >= 0; claim_scan_index = claim_scan_index - 1) begin
      if (pending_q[claim_scan_index] && enable_q[claim_scan_index] && !service_q[claim_scan_index]) begin
        claim_index = claim_scan_index;
        claim_valid = 1'b1;
      end
    end
  end

  // Address decode, read data mux and the access rules of the register map.
  always_comb begin
    word_index = 0;
    bitmap_base = 0;
    bitmap_bit = 0;
    bitmap_id = 0;
    bitmap_word = 32'd0;
    enable_word_select = 0;
    for (address_bit = ADDRESS_WIDTH - 1; address_bit >= 2; address_bit = address_bit - 1)
      word_index = (word_index << 1) | {31'd0, req_addr_i[address_bit]};

    is_claim = (word_index == 0);
    is_complete = (word_index == 1);
    is_in_service = (word_index == 2);
    is_source_count = (word_index == 3);
    is_pending_word = (word_index >= PENDING_BASE_WORD) && (word_index < ENABLE_BASE_WORD);
    is_enable_word = (word_index >= ENABLE_BASE_WORD) && (word_index < REG_WORDS);

    read_legal = 1'b0;
    read_data = 32'd0;
    if (is_claim) begin
      // CLAIM is a read with a side effect: its data is produced from the same
      // pre-edge candidate that the accepting edge commits.
      read_legal = 1'b1;
      if (claim_valid && !busy)
        read_data = claim_index + 1;
    end else if (is_in_service) begin
      read_legal = 1'b1;
      read_data = {{ID_PAD{1'b0}}, service_id_q};
    end else if (is_source_count) begin
      read_legal = 1'b1;
      read_data = SOURCE_COUNT_VALUE;
    end else if (is_pending_word || is_enable_word) begin
      read_legal = 1'b1;
      if (is_pending_word)
        bitmap_base = 32 * (word_index - PENDING_BASE_WORD);
      else
        bitmap_base = 32 * (word_index - ENABLE_BASE_WORD);
      for (bitmap_bit = 0; bitmap_bit < 32; bitmap_bit = bitmap_bit + 1) begin
        bitmap_id = bitmap_base + bitmap_bit;
        // Bitmap bit 0 (the reserved ID 0) and every bit above NUM_SOURCES read 0.
        if ((bitmap_id >= 1) && (bitmap_id <= NUM_SOURCES)) begin
          if (is_pending_word)
            bitmap_word[bitmap_bit] = pending_q[bitmap_id - 1];
          else
            bitmap_word[bitmap_bit] = enable_q[bitmap_id - 1];
        end
      end
      read_data = bitmap_word;
    end

    // Only a full 32-bit access is legal. COMPLETE is write-only; CLAIM,
    // IN_SERVICE, SOURCE_COUNT and PENDING are read-only; ENABLE is read/write;
    // every other offset inside or above the window is an error.
    op_error = 1'b1;
    if (req_be_i == FULL_BE) begin
      if (req_write_i) begin
        if (is_complete)
          op_error = !complete_id_ok;
        else if (is_enable_word)
          op_error = 1'b0;
        else
          op_error = 1'b1;
      end else begin
        op_error = !read_legal;
      end
    end
    // An error response carries no data; a successful write also reads as 0.
    op_rdata = (req_write_i || op_error) ? 32'd0 : read_data;

    // One committed operation per accepted request, taken from pre-edge state.
    accept_req = req_valid_i && req_ready_o;
    op_claim_read = accept_req && !req_write_i && is_claim && (req_be_i == FULL_BE);
    op_complete_write = accept_req && req_write_i && is_complete && (req_be_i == FULL_BE);
    op_enable_write = accept_req && req_write_i && is_enable_word && (req_be_i == FULL_BE);
    if (is_enable_word)
      enable_word_select = word_index - ENABLE_BASE_WORD;
    else
      enable_word_select = 0;
  end

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      pending_q <= {NUM_SOURCES{1'b0}};
      enable_q <= {NUM_SOURCES{1'b0}};
      service_q <= {NUM_SOURCES{1'b0}};
      service_id_q <= {ID_WIDTH{1'b0}};
      rsp_valid_q <= 1'b0;
      rsp_rdata_q <= 32'd0;
      rsp_error_q <= 1'b0;
    end else begin
      if (rsp_valid_q && rsp_ready_i)
        rsp_valid_q <= 1'b0;

      // Sampling: a source that is not in service before this edge either
      // follows its input (level) or accumulates it (latched). A source claimed
      // on this edge is overridden below, so its pending bit stays 0 while it is
      // in service.
      for (sample_index = 0; sample_index < NUM_SOURCES; sample_index = sample_index + 1) begin
        if (!service_q[sample_index]) begin
          if (LATCH_MASK[sample_index])
            pending_q[sample_index] <= pending_q[sample_index] | source_i[sample_index];
          else
            pending_q[sample_index] <= source_i[sample_index];
        end
      end

      if (accept_req) begin
        rsp_valid_q <= 1'b1;
        rsp_rdata_q <= op_rdata;
        rsp_error_q <= op_error;

        if (op_claim_read) begin
          // Exactly one claim per accepted CLAIM read; backpressure can never
          // double-claim because the candidate comes from pre-edge state.
          if (claim_valid && !busy) begin
            pending_q[claim_index] <= 1'b0;
            service_q[claim_index] <= 1'b1;
            service_id_q <= claim_index[ID_WIDTH-1:0] + 1'b1;
          end
        end else if (op_complete_write) begin
          // Pure controller bookkeeping: the peripheral is never touched.
          if (complete_id_ok) begin
            for (service_index = 0; service_index < NUM_SOURCES; service_index = service_index + 1) begin
              if ({{ID_PAD{1'b0}}, service_id_q} == (service_index + 1))
                service_q[service_index] <= 1'b0;
            end
            service_id_q <= {ID_WIDTH{1'b0}};
          end
        end else if (op_enable_write) begin
          // Bitmap bit s+1 of the selected word drives enable bit s, so the
          // reserved bitmap bit 0 and bits above NUM_SOURCES are never written.
          for (enable_index = 0; enable_index < NUM_SOURCES; enable_index = enable_index + 1) begin
            if (((enable_index + 1) / 32) == enable_word_select)
              enable_q[enable_index] <= req_wdata_i[(enable_index + 1) % 32];
          end
        end
      end
    end
  end
endmodule
