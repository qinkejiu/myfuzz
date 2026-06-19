// CVA6 scheme4 plus4 harness.
//
// This version keeps the original 521-bit top-level RFuzz input surface and
// constrains the 0/1 bitstring with small, bit-controlled projections. The
// intent is to retain baseline exploration while making selected inputs less
// likely to leave the core permanently stalled.

module cva6_lightweight_plus4_harness (
    input  logic          clock,
    input  logic          reset,
    input  logic          io_meta_reset,
    input  logic [520:0]  rfuzz_input_bits,
    output logic [3495:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    logic [63:0] cycle_q;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            cycle_q <= 64'h0;
        end else begin
            cycle_q <= cycle_q + 64'h1;
        end
    end

    wire [209:0] raw_noc_resp = rfuzz_input_bits[520 -: 210];
    wire [177:0] raw_cvxif_resp = rfuzz_input_bits[310 -: 178];
    wire [63:0]  raw_boot_addr = rfuzz_input_bits[132 -: 64];
    wire [63:0]  raw_hart_id = rfuzz_input_bits[68 -: 64];
    wire [1:0]   raw_irq = rfuzz_input_bits[4 -: 2];
    wire         raw_debug_req = rfuzz_input_bits[2 -: 1];
    wire         raw_ipi = rfuzz_input_bits[1 -: 1];
    wire         raw_time_irq = rfuzz_input_bits[0 -: 1];

    wire boot_near_mode = raw_noc_resp[11] ^ raw_cvxif_resp[11];
    wire hart_small_mode = raw_noc_resp[12] ^ raw_cvxif_resp[12];
    wire noc_project_mode = raw_noc_resp[13] ^ raw_cvxif_resp[13];
    wire cvx_project_mode = raw_noc_resp[14] ^ raw_cvxif_resp[14];
    wire event_project_mode = raw_noc_resp[15] ^ raw_cvxif_resp[15];

    wire [63:0] boot_addr_aligned = {raw_boot_addr[63:3], 3'b000};
    wire [63:0] boot_addr_near = 64'h0000_0000_8000_0000 + {49'h0, raw_boot_addr[14:3], 3'b000};
    wire [63:0] boot_addr_i_w = boot_near_mode ? boot_addr_near : boot_addr_aligned;
    wire [63:0] hart_id_i_w = hart_small_mode ? {60'h0, raw_hart_id[3:0]} : raw_hart_id;

    wire raw_aw_ready = raw_noc_resp[209];
    wire raw_ar_ready = raw_noc_resp[208];
    wire raw_w_ready = raw_noc_resp[207];
    wire raw_b_valid = raw_noc_resp[206];
    wire [69:0] raw_b_chan = raw_noc_resp[205:136];
    wire raw_r_valid = raw_noc_resp[135];
    wire [134:0] raw_r_chan = raw_noc_resp[134:0];

    wire bus_accept_window = (cycle_q[1:0] != raw_noc_resp[1:0]);
    wire read_return_window = (cycle_q[2:0] == raw_noc_resp[5:3]) ||
                              (cycle_q[3:1] == raw_cvxif_resp[2:0]);
    wire write_return_window = (cycle_q[3:0] == raw_noc_resp[9:6]) ||
                               (cycle_q[4:1] == raw_cvxif_resp[6:3]);

    wire aw_ready_i_w = noc_project_mode ? (raw_aw_ready | bus_accept_window | cycle_q[0]) : raw_aw_ready;
    wire ar_ready_i_w = noc_project_mode ? (raw_ar_ready | bus_accept_window | cycle_q[1]) : raw_ar_ready;
    wire w_ready_i_w = noc_project_mode ? (raw_w_ready | bus_accept_window | cycle_q[2]) : raw_w_ready;
    wire b_valid_i_w = noc_project_mode ? (raw_b_valid | (write_return_window & (raw_aw_ready | raw_w_ready))) : raw_b_valid;
    wire r_valid_i_w = noc_project_mode ? (raw_r_valid | read_return_window) : raw_r_valid;
    wire [69:0] b_chan_i_w = raw_b_chan;
    wire [134:0] r_chan_i_w = {
        raw_r_chan[134:65],
        raw_r_chan[64] | (noc_project_mode & read_return_window),
        raw_r_chan[63:0]
    };

    wire [209:0] noc_resp_i_w = {
        aw_ready_i_w,
        ar_ready_i_w,
        w_ready_i_w,
        b_valid_i_w,
        b_chan_i_w,
        r_valid_i_w,
        r_chan_i_w
    };

    wire raw_x_compressed_ready = raw_cvxif_resp[177];
    wire [32:0] raw_x_compressed_resp = raw_cvxif_resp[176:144];
    wire raw_x_issue_ready = raw_cvxif_resp[143];
    wire [3:0] raw_x_issue_resp = raw_cvxif_resp[142:139];
    wire raw_x_register_ready = raw_cvxif_resp[138];
    wire raw_x_result_valid = raw_cvxif_resp[137];
    wire [136:0] raw_x_result = raw_cvxif_resp[136:0];

    wire x_ready_window = (cycle_q[2:0] != raw_cvxif_resp[9:7]);
    wire x_result_window = (cycle_q[3:0] == raw_cvxif_resp[13:10]);
    wire x_compressed_ready_i_w = cvx_project_mode ? (raw_x_compressed_ready | x_ready_window) : raw_x_compressed_ready;
    wire x_issue_ready_i_w = cvx_project_mode ? (raw_x_issue_ready | x_ready_window) : raw_x_issue_ready;
    wire x_register_ready_i_w = cvx_project_mode ? (raw_x_register_ready | cycle_q[0]) : raw_x_register_ready;
    wire x_result_valid_i_w = cvx_project_mode ? (raw_x_result_valid | (x_result_window & raw_cvxif_resp[16])) : raw_x_result_valid;
    wire [32:0] x_compressed_resp_i_w = cvx_project_mode
                                      ? {raw_x_compressed_resp[32:1], raw_x_compressed_resp[0] | raw_cvxif_resp[17]}
                                      : raw_x_compressed_resp;
    wire [3:0] x_issue_resp_i_w = cvx_project_mode
                                ? {raw_x_issue_resp[3] | raw_cvxif_resp[18],
                                   raw_x_issue_resp[2] | raw_cvxif_resp[19],
                                   raw_x_issue_resp[1:0]}
                                : raw_x_issue_resp;

    wire [177:0] cvxif_resp_i_w = {
        x_compressed_ready_i_w,
        x_compressed_resp_i_w,
        x_issue_ready_i_w,
        x_issue_resp_i_w,
        x_register_ready_i_w,
        x_result_valid_i_w,
        raw_x_result
    };

    wire event_window = (cycle_q[7:0] == (raw_noc_resp[23:16] ^ raw_cvxif_resp[23:16])) ||
                        (cycle_q[5:0] == raw_noc_resp[29:24]);
    wire debug_window = (cycle_q[9:0] == {raw_cvxif_resp[31:24], raw_noc_resp[31:30]});
    wire [1:0] irq_i_w = event_project_mode ? (event_window ? raw_irq : 2'b00) : raw_irq;
    wire ipi_i_w = event_project_mode ? (event_window & raw_ipi) : raw_ipi;
    wire time_irq_i_w = event_project_mode ? ((event_window | cycle_q[8]) & raw_time_irq) : raw_time_irq;
    wire debug_req_i_w = event_project_mode ? (debug_window & raw_debug_req) : raw_debug_req;

    cva6 dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .boot_addr_i(boot_addr_i_w),
        .hart_id_i(hart_id_i_w),
        .irq_i(irq_i_w),
        .ipi_i(ipi_i_w),
        .time_irq_i(time_irq_i_w),
        .debug_req_i(debug_req_i_w),
        .rvfi_probes_o(),
        .cvxif_req_o(),
        .cvxif_resp_i(cvxif_resp_i_w),
        .noc_req_o(),
        .noc_resp_i(noc_resp_i_w),
        .__vi_coverage(__vi_coverage)
    );

endmodule
