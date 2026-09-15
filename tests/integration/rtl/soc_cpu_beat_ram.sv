// Beat-level RAM target for the real-CPU protocol benches.
//
// It implements the target side of myfuzz_processor_memory_backend for both
// soc_picorv32_axilite_tb and soc_picorv32_wishbone_tb, so the two protocol
// runs differ only in the initiator protocol in front of the adapter under
// test.  Behaviour:
//
//   - one outstanding request; a response is held until the backend takes it,
//   - writes apply the byte enables to the lanes of the *word* containing the
//     address.  That is the convention the rest of this project already uses
//     (see beat_to_wishbone.sv, where sel is passed through next to the word
//     address, and PicoRV32 itself, which builds a byte store as
//     "4'b0001 << addr[1:0]"),
//   - a zero byte enable, or an address outside the array, answers with an
//     error instead of silently aliasing to a valid word or widening the
//     access, so a mis-decoded address in an adapter is caught rather than
//     hidden,
//   - reads return the whole word, so a load cannot appear correct merely
//     because the caller ignored the lanes.
//
// The counters are evidence outputs: the testbench compares write_count_q
// against the number of stores the CPU itself reports retiring, which is what
// makes "no invented and no dropped writes" checkable.
module soc_cpu_beat_ram #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MEM_WORDS = 2048
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,
    // target side of myfuzz_processor_memory_backend
    input  logic                          target_req_valid_i,
    output logic                          target_req_ready_o,
    input  logic                          target_req_write_i,
    input  logic [ADDRESS_WIDTH-1:0]      target_req_addr_i,
    input  logic [DATA_WIDTH-1:0]         target_req_wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]     target_req_be_i,
    output logic                          target_rsp_valid_o,
    input  logic                          target_rsp_ready_i,
    output logic [DATA_WIDTH-1:0]         target_rsp_rdata_o,
    output logic                          target_rsp_error_o
);
    localparam integer LANES = DATA_WIDTH / 8;
    localparam integer WORD_BITS = $clog2(MEM_WORDS);
    localparam integer BYTE_BITS = $clog2(LANES);
    localparam integer MEM_BYTES = MEM_WORDS * LANES;

    logic [DATA_WIDTH-1:0] mem [0:MEM_WORDS-1];
    logic [DATA_WIDTH-1:0] rdata_q;
    logic                  error_q;
    integer                write_count_q;
    integer                read_count_q;
    integer                lane;

    logic [WORD_BITS-1:0]  word_index;
    logic                  in_range;
    logic                  request_fire;

    initial begin
        if (DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0 || MEM_WORDS < 1 ||
            (LANES & (LANES - 1)) != 0)
            $fatal(1, "soc_cpu_beat_ram: invalid parameters");
        write_count_q = 0;
        read_count_q = 0;
    end

    assign word_index = target_req_addr_i[BYTE_BITS +: WORD_BITS];
    assign in_range = (target_req_addr_i < MEM_BYTES[ADDRESS_WIDTH-1:0]);
    assign request_fire = target_req_valid_i && target_req_ready_o;

    assign target_req_ready_o = rst_ni && !target_rsp_valid_o;
    assign target_rsp_rdata_o = rdata_q;
    assign target_rsp_error_o = error_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            target_rsp_valid_o <= 1'b0;
            rdata_q <= '0;
            error_q <= 1'b0;
            write_count_q <= 0;
            read_count_q <= 0;
        end else begin
            if (request_fire) begin
                target_rsp_valid_o <= 1'b1;
                // Byte enables are a write-side concept: the AXI4-Lite and
                // Wishbone adapters drive them as zero on reads (see
                // axi4_lite_processor_memory_adapter.sv, "req_be_o = ... : '0"),
                // so only a write with no enabled byte is a violation.
                error_q <= !in_range ||
                           (target_req_write_i && target_req_be_i == '0);
                rdata_q <= in_range ? mem[word_index] : '0;
                if (target_req_write_i) begin
                    write_count_q <= write_count_q + 1;
                    if (in_range)
                        for (lane = 0; lane < LANES; lane = lane + 1)
                            if (target_req_be_i[lane])
                                mem[word_index][lane*8 +: 8] <=
                                    target_req_wdata_i[lane*8 +: 8];
                end else begin
                    read_count_q <= read_count_q + 1;
                end
            end
            if (target_rsp_valid_o && target_rsp_ready_i)
                target_rsp_valid_o <= 1'b0;
        end
    end
endmodule
