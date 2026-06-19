// CVA6 scheme4 plus5 harness.
//
// This keeps the original 521-bit RFuzz input surface. Most fields remain raw
// passthrough; selected mode bits project ready/valid, boot address, events,
// and NoC read data into forms that are more likely to advance the core.

module cva6_lightweight_plus5_harness (
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
    wire instr_project_mode = raw_noc_resp[32] ^ raw_cvxif_resp[32];
    wire instr_mix_mode = raw_noc_resp[33] ^ raw_cvxif_resp[33];

    wire [63:0] boot_addr_aligned = {raw_boot_addr[63:3], 3'b000};
    wire [63:0] boot_addr_near = 64'h0000_0000_8000_0000 + {49'h0, raw_boot_addr[14:3], 3'b000};
    wire [63:0] boot_addr_i_w = boot_near_mode ? boot_addr_near : boot_addr_aligned;
    wire [63:0] hart_id_i_w = hart_small_mode ? {60'h0, raw_hart_id[3:0]} : raw_hart_id;

    function automatic logic [31:0] enc_i(
        input logic [11:0] imm,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3,
        input logic [4:0]  rd,
        input logic [6:0]  opcode
    );
        begin
            enc_i = {imm, rs1, funct3, rd, opcode};
        end
    endfunction

    function automatic logic [31:0] enc_r(
        input logic [6:0] funct7,
        input logic [4:0] rs2,
        input logic [4:0] rs1,
        input logic [2:0] funct3,
        input logic [4:0] rd,
        input logic [6:0] opcode
    );
        begin
            enc_r = {funct7, rs2, rs1, funct3, rd, opcode};
        end
    endfunction

    function automatic logic [31:0] enc_s(
        input logic [11:0] imm,
        input logic [4:0]  rs2,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3
    );
        begin
            enc_s = {imm[11:5], rs2, rs1, funct3, imm[4:0], 7'b0100011};
        end
    endfunction

    function automatic logic [31:0] enc_b(
        input logic [12:0] imm,
        input logic [4:0]  rs2,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3
    );
        begin
            enc_b = {imm[12], imm[10:5], rs2, rs1, funct3, imm[4:1], imm[11], 7'b1100011};
        end
    endfunction

    function automatic logic [31:0] enc_u(
        input logic [19:0] imm,
        input logic [4:0]  rd,
        input logic [6:0]  opcode
    );
        begin
            enc_u = {imm, rd, opcode};
        end
    endfunction

    function automatic logic [31:0] enc_j(
        input logic [20:0] imm,
        input logic [4:0]  rd
    );
        begin
            enc_j = {imm[20], imm[10:1], imm[11], imm[19:12], rd, 7'b1101111};
        end
    endfunction

    function automatic logic [31:0] instr_word(
        input logic [5:0]  idx,
        input logic [31:0] seed
    );
        logic [4:0] rd;
        logic [4:0] rs1;
        logic [4:0] rs2;
        logic [11:0] imm12;
        begin
            rd = (idx[4:0] == 5'h0) ? 5'h1 : idx[4:0];
            rs1 = ((idx[4:0] ^ seed[4:0]) == 5'h0) ? 5'h1 : (idx[4:0] ^ seed[4:0]);
            rs2 = (((idx[4:0] + seed[9:5]) & 5'h1f) == 5'h0) ? 5'h2 : ((idx[4:0] + seed[9:5]) & 5'h1f);
            imm12 = {seed[7:0], idx[3:0]};
            unique case (idx[3:0] ^ seed[13:10])
                4'h0: instr_word = enc_u({seed[31:16], idx[3:0]}, rd, 7'b0110111);
                4'h1: instr_word = enc_u({seed[27:12], idx[3:0]}, rd, 7'b0010111);
                4'h2: instr_word = enc_i(imm12, rs1, 3'b000, rd, 7'b0010011);
                4'h3: instr_word = enc_i({6'h0, seed[5:0]}, rs1, 3'b001, rd, 7'b0010011);
                4'h4: instr_word = enc_i({6'h0, seed[11:6]}, rs1, 3'b101, rd, 7'b0010011);
                4'h5: instr_word = enc_r(7'b0000000, rs2, rs1, 3'b000, rd, 7'b0110011);
                4'h6: instr_word = enc_r(7'b0100000, rs2, rs1, 3'b000, rd, 7'b0110011);
                4'h7: instr_word = enc_r(7'b0000000, rs2, rs1, 3'b100, rd, 7'b0110011);
                4'h8: instr_word = enc_i({8'h00, idx[3:0]}, rs1, 3'b011, rd, 7'b0000011);
                4'h9: instr_word = enc_s({8'h00, idx[3:0]}, rs2, rs1, 3'b011);
                4'ha: instr_word = enc_b(13'h008, rs2, rs1, 3'b000);
                4'hb: instr_word = enc_b(13'h010, rs2, rs1, 3'b001);
                4'hc: instr_word = enc_j(21'h00010, rd);
                4'hd: instr_word = enc_i(12'hb00, 5'h0, 3'b010, rd, 7'b1110011);
                4'he: instr_word = seed[30] ? 32'h0010_0073 : 32'h0000_000f;
                default: instr_word = 32'h0000_0013;
            endcase
        end
    endfunction

    function automatic logic [63:0] instr_pair(
        input logic [63:0] addr,
        input logic [31:0] seed
    );
        logic [5:0] word_idx;
        begin
            word_idx = addr[8:3] ^ seed[5:0];
            instr_pair = {
                instr_word((word_idx << 1) + 6'h1, seed ^ 32'h6a09_e667),
                instr_word((word_idx << 1), seed ^ 32'hbb67_ae85)
            };
        end
    endfunction

    wire [469:0] noc_req_bits = dut.noc_req_o;
    wire [160:0] noc_ar_bits = noc_req_bits[162:2];
    wire [63:0] noc_ar_addr = noc_ar_bits[156:93];

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
    wire [63:0] raw_r_data = raw_r_chan[130:67];
    wire [31:0] instr_seed = raw_noc_resp[63:32] ^ raw_cvxif_resp[63:32] ^ raw_boot_addr[31:0];
    wire [63:0] instr_r_data = instr_pair(noc_ar_addr ^ boot_addr_i_w, instr_seed);
    wire [63:0] projected_r_data = instr_mix_mode ? (instr_r_data ^ raw_r_data) : instr_r_data;
    wire [63:0] r_data_i_w = instr_project_mode ? projected_r_data : raw_r_data;
    wire [134:0] r_chan_i_w = {
        raw_r_chan[134:131],
        r_data_i_w,
        raw_r_chan[66:65],
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
