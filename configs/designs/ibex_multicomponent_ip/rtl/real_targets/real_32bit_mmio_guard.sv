// Guard a 32-bit register target that has no byte-enable input.  A partial
// write is rejected before the native IP sees valid_i, so it cannot silently
// update an entire register from a narrow or zero-strobe request.
module real_32bit_mmio_guard #(
    parameter bit ALLOW_PARTIAL_WRITES = 1'b0
) (
    input  logic       mmio_valid,
    input  logic       mmio_write,
    input  logic [3:0] mmio_be,
    output logic       native_valid,
    output logic       error
);
    logic partial_write;

    assign partial_write = mmio_write && (mmio_be != 4'hf);
    assign error = mmio_valid && partial_write && !ALLOW_PARTIAL_WRITES;
    assign native_valid = mmio_valid && !error;
endmodule
