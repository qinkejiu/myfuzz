// Bounded interrupt router with explicit edge/level capture and claim state.
//
// The router deliberately keeps one pending bit per declared source. Sources
// are never ORed together, so simultaneous edge events remain observable at
// the sink. A claimed source is held in service until completion_i; level
// sources re-pend after completion while their input remains asserted.
module soc_irq_router #(
    parameter integer NUM_SOURCES = 4,
    parameter integer SOURCE_ID_WIDTH = 2,
    parameter integer PRIORITY_WIDTH = 4
) (
    input  logic [NUM_SOURCES-1:0] source_i,
    input  logic [NUM_SOURCES-1:0] enable_i,
    input  logic [NUM_SOURCES-1:0] edge_mode_i,
    input  logic [NUM_SOURCES-1:0] clear_i,
    input  logic                   claim_i,
    input  logic                   complete_i,
    input  logic [NUM_SOURCES*PRIORITY_WIDTH-1:0] priority_i,
    input  logic                   clk_i,
    input  logic                   reset_i,
    output logic                   irq_o,
    output logic [NUM_SOURCES-1:0] pending_o,
    output logic [NUM_SOURCES-1:0] in_service_o,
    output logic                   claim_valid_o,
    output logic [SOURCE_ID_WIDTH-1:0] claim_id_o
);
  logic [NUM_SOURCES-1:0] pending_q;
  logic [NUM_SOURCES-1:0] service_q;
  logic [NUM_SOURCES-1:0] source_q;
  logic claim_valid_q;
  logic [SOURCE_ID_WIDTH-1:0] claim_id_q;

  integer scan_index;
  integer best_index;
  integer best_priority;

  // Conservative Verilog syntax keeps this usable with older simulators.
  always @* begin
    best_index = -1;
    best_priority = 0;
    irq_o = 1'b0;
    for (scan_index = 0; scan_index < NUM_SOURCES; scan_index = scan_index + 1) begin
      if (pending_q[scan_index] && enable_i[scan_index] && !service_q[scan_index]) begin
        if ((best_index < 0) ||
            (priority_i[(scan_index*PRIORITY_WIDTH) +: PRIORITY_WIDTH] > best_priority)) begin
          best_index = scan_index;
          best_priority = priority_i[(scan_index*PRIORITY_WIDTH) +: PRIORITY_WIDTH];
        end
      end
    end
    if (best_index >= 0)
      irq_o = 1'b1;
  end

  assign pending_o = pending_q;
  assign in_service_o = service_q;
  assign claim_valid_o = claim_valid_q;
  assign claim_id_o = claim_id_q;

  always @(posedge clk_i) begin
    if (reset_i) begin
      pending_q <= {NUM_SOURCES{1'b0}};
      service_q <= {NUM_SOURCES{1'b0}};
      source_q <= {NUM_SOURCES{1'b0}};
      claim_valid_q <= 1'b0;
      claim_id_q <= {SOURCE_ID_WIDTH{1'b0}};
    end else begin
      source_q <= source_i;
      claim_valid_q <= 1'b0;

      for (scan_index = 0; scan_index < NUM_SOURCES; scan_index = scan_index + 1) begin
        if (clear_i[scan_index]) begin
          pending_q[scan_index] <= 1'b0;
        end else if (edge_mode_i[scan_index]) begin
          if (source_i[scan_index] && !source_q[scan_index])
            pending_q[scan_index] <= 1'b1;
        end else if (source_i[scan_index]) begin
          pending_q[scan_index] <= 1'b1;
        end else begin
          pending_q[scan_index] <= 1'b0;
        end

        if (complete_i && service_q[scan_index])
          service_q[scan_index] <= 1'b0;
      end

      if (claim_i && (best_index >= 0)) begin
        claim_valid_q <= 1'b1;
        claim_id_q <= best_index[SOURCE_ID_WIDTH-1:0];
        pending_q[best_index] <= 1'b0;
        service_q[best_index] <= 1'b1;
      end
    end
  end
endmodule
