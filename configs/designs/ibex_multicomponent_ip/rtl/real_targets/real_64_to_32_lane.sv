// Explicitly adapt one 32-bit lane of a 64-bit processor beat to a native
// 32-bit peripheral.  Reads do not carry a byte-enable on AXI-Lite/APB, so
// their lane is recovered from address bit 2; writes use the supplied strobe.
// Requests selecting both lanes, an unaligned word, or an address above 4 GiB
// are rejected before the native IP sees valid_i.
module real_64_to_32_lane #(
    parameter bit ALLOW_PARTIAL_WRITES = 1'b0
) (
    input  logic        mmio_valid,
    input  logic        mmio_write,
    input  logic [63:0] mmio_addr,
    input  logic [63:0] mmio_wdata,
    input  logic [7:0]  mmio_be,
    output logic [63:0] mmio_rdata,
    output logic        mmio_error,
    output logic        native_valid,
    output logic        native_write,
    output logic [31:0] native_addr,
    output logic [31:0] native_wdata,
    output logic [3:0]  native_be,
    input  logic [31:0] native_rdata
);
    logic low_lane_active;
    logic high_lane_active;
    logic high_lane;
    logic lane_valid;
    logic write_lane_alignment_valid;
    logic partial_write;

    assign low_lane_active = mmio_write ? |mmio_be[3:0] :
                             (mmio_addr[2:0] == 3'b000);
    assign high_lane_active = mmio_write ? |mmio_be[7:4] :
                              (mmio_addr[2:0] == 3'b100);
    assign high_lane = !low_lane_active && high_lane_active;
    assign write_lane_alignment_valid = !mmio_write ||
        (low_lane_active && !high_lane_active && (mmio_addr[2:0] == 3'b000)) ||
        (high_lane_active && !low_lane_active &&
         ((mmio_addr[2:0] == 3'b000) || (mmio_addr[2:0] == 3'b100))) ||
        (low_lane_active && high_lane_active && (mmio_addr[2:0] == 3'b000));
    assign lane_valid = (low_lane_active ^ high_lane_active) &&
                        (mmio_addr[1:0] == 2'b00) &&
                        (mmio_addr[63:32] == 32'b0) &&
                        write_lane_alignment_valid;
    assign native_addr = {mmio_addr[31:3], 3'b000} + (high_lane ? 32'd4 : 32'd0);
    assign native_wdata = high_lane ? mmio_wdata[63:32] : mmio_wdata[31:0];
    assign native_be = mmio_write ? (high_lane ? mmio_be[7:4] : mmio_be[3:0]) : 4'hf;
    assign partial_write = mmio_write && (native_be != 4'hf);
    assign mmio_error = mmio_valid && (!lane_valid ||
                      (partial_write && !ALLOW_PARTIAL_WRITES));
    assign native_valid = mmio_valid && lane_valid && !mmio_error;
    assign native_write = mmio_write;
    assign mmio_rdata = high_lane ? {native_rdata, 32'b0} : {32'b0, native_rdata};
endmodule
