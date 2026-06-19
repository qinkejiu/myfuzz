// Long-run oriented lightweight-plus2 constrained harness for CVA6.
//
// This keeps CVA6 as a top-level DUT and replaces fully-random environment
// inputs with a stateful NoC/AXI model, an input-bit projected instruction
// stream, CV-X-IF, interrupt, debug, and low-rate error behavior.

module cva6_lightweight_plus2_harness (
    input  logic          clock,
    input  logic          reset,
    input  logic          io_meta_reset,
    input  logic [520:0]  rfuzz_input_bits,
    output logic [3495:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    wire [63:0] base_seed = rfuzz_input_bits[63:0];
    wire [63:0] boot_seed = rfuzz_input_bits[127:64];
    wire [63:0] hart_seed = rfuzz_input_bits[191:128];
    wire [63:0] mem_seed0 = rfuzz_input_bits[255:192];
    wire [63:0] mem_seed1 = rfuzz_input_bits[319:256];
    wire [63:0] cvx_seed0 = rfuzz_input_bits[383:320];
    wire [63:0] cvx_seed1 = rfuzz_input_bits[447:384];
    wire [31:0] event_seed = rfuzz_input_bits[479:448];
    wire [40:0] extra_seed = rfuzz_input_bits[520:480];
    wire [5:0]  scenario_w = base_seed[5:0] ^ extra_seed[5:0];

    logic [63:0] cycle_q;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            cycle_q <= 64'h0;
        end else begin
            cycle_q <= cycle_q + 64'h1;
        end
    end

    logic [63:0] boot_addr_q;
    logic [63:0] hart_id_q;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            boot_addr_q <= base_seed[3]
                         ? (64'h0000_0000_8000_0000 + {48'h0, boot_seed[15:3], 3'b000})
                         : 64'h0000_0000_8000_0000;
            hart_id_q <= {60'h0, hart_seed[3:0]};
        end
    end

    function automatic logic [63:0] mix64(
        input logic [63:0] a,
        input logic [63:0] b,
        input logic [63:0] c
    );
        begin
            mix64 = (a ^ {b[31:0], b[63:32]}) + (c ^ 64'h9e37_79b9_7f4a_7c15);
            mix64 = mix64 ^ {mix64[6:0], mix64[63:7]};
        end
    endfunction

    function automatic logic [2:0] nonzero_delay(input logic [2:0] value);
        begin
            nonzero_delay = (value == 3'h0) ? 3'h1 : value;
        end
    endfunction

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
        input logic [5:0]  scenario,
        input logic [31:0] seed
    );
        logic [4:0] rd;
        logic [4:0] rs1;
        logic [4:0] rs2;
        logic [11:0] imm12;
        begin
            rd = (idx[4:0] == 5'h0) ? 5'h1 : idx[4:0];
            rs1 = ((idx[4:0] ^ scenario[4:0]) == 5'h0) ? 5'h1 : (idx[4:0] ^ scenario[4:0]);
            rs2 = (((idx[4:0] + scenario[4:0]) & 5'h1f) == 5'h0) ? 5'h2 : ((idx[4:0] + scenario[4:0]) & 5'h1f);
            imm12 = {seed[7:0], scenario[3:0]} ^ {idx, idx};
            unique case (idx[3:0] ^ scenario[3:0])
                4'h0: instr_word = enc_u({seed[31:16], idx[3:0]}, rd, 7'b0110111);              // lui
                4'h1: instr_word = enc_u({seed[27:12], scenario[3:0]}, rd, 7'b0010111);         // auipc
                4'h2: instr_word = enc_i(imm12, rs1, 3'b000, rd, 7'b0010011);                  // addi
                4'h3: instr_word = enc_i({6'h0, scenario[5:0]}, rs1, 3'b001, rd, 7'b0010011);  // slli
                4'h4: instr_word = enc_i({6'h0, seed[5:0]}, rs1, 3'b101, rd, 7'b0010011);      // srli/srai
                4'h5: instr_word = enc_r(7'b0000000, rs2, rs1, 3'b000, rd, 7'b0110011);        // add
                4'h6: instr_word = enc_r(7'b0100000, rs2, rs1, 3'b000, rd, 7'b0110011);        // sub
                4'h7: instr_word = enc_r(7'b0000000, rs2, rs1, 3'b100, rd, 7'b0110011);        // xor
                4'h8: instr_word = enc_i({8'h00, idx[3:0]}, rs1, 3'b011, rd, 7'b0000011);      // ld
                4'h9: instr_word = enc_s({8'h00, idx[3:0]}, rs2, rs1, 3'b011);                 // sd
                4'ha: instr_word = enc_b(13'h008, rs2, rs1, 3'b000);                           // beq +8
                4'hb: instr_word = enc_b(13'h010, rs2, rs1, 3'b001);                           // bne +16
                4'hc: instr_word = enc_j(21'h00010, rd);                                       // jal +16
                4'hd: instr_word = enc_i(12'hb00, 5'h0, 3'b010, rd, 7'b1110011);               // csrrs mcycle
                4'he: instr_word = scenario[5] ? 32'h0010_0073 : 32'h0000_000f;                // ebreak/fence
                default: instr_word = 32'h0000_0013;                                           // nop
            endcase
        end
    endfunction

    function automatic logic [63:0] instr_pair(
        input logic [63:0] addr,
        input logic [7:0]  beat,
        input logic [5:0]  scenario,
        input logic [31:0] seed
    );
        logic [5:0] word_idx;
        begin
            word_idx = addr[8:3] + beat[5:0];
            instr_pair = {
                instr_word((word_idx << 1) + 6'h1, scenario, seed ^ 32'h5eed_1001),
                instr_word((word_idx << 1), scenario, seed ^ 32'hc0de_2002)
            };
        end
    endfunction

    logic [63:0] mem_q [0:63];
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            for (int i = 0; i < 64; i++) begin
                mem_q[i] <= mix64(mem_seed0, mem_seed1, 64'(i));
            end
        end else if (wr_pending_q && (wr_delay_q == 3'h0)) begin
            if (wr_strb_q[0]) mem_q[wr_index_q][7:0] <= wr_data_q[7:0];
            if (wr_strb_q[1]) mem_q[wr_index_q][15:8] <= wr_data_q[15:8];
            if (wr_strb_q[2]) mem_q[wr_index_q][23:16] <= wr_data_q[23:16];
            if (wr_strb_q[3]) mem_q[wr_index_q][31:24] <= wr_data_q[31:24];
            if (wr_strb_q[4]) mem_q[wr_index_q][39:32] <= wr_data_q[39:32];
            if (wr_strb_q[5]) mem_q[wr_index_q][47:40] <= wr_data_q[47:40];
            if (wr_strb_q[6]) mem_q[wr_index_q][55:48] <= wr_data_q[55:48];
            if (wr_strb_q[7]) mem_q[wr_index_q][63:56] <= wr_data_q[63:56];
        end
    end

    wire [469:0] noc_req_bits = dut.noc_req_o;

    wire [166:0] noc_aw_bits = noc_req_bits[469:303];
    wire         noc_aw_valid = noc_req_bits[302];
    wire [136:0] noc_w_bits = noc_req_bits[301:165];
    wire         noc_w_valid = noc_req_bits[164];
    wire         noc_b_ready = noc_req_bits[163];
    wire [160:0] noc_ar_bits = noc_req_bits[162:2];
    wire         noc_ar_valid = noc_req_bits[1];
    wire         noc_r_ready = noc_req_bits[0];

    wire [3:0]  noc_aw_id = noc_aw_bits[166:163];
    wire [63:0] noc_aw_addr = noc_aw_bits[162:99];
    wire [7:0]  noc_aw_len = noc_aw_bits[98:91];
    wire [63:0] noc_w_data = noc_w_bits[136:73];
    wire [7:0]  noc_w_strb = noc_w_bits[72:65];
    wire        noc_w_last = noc_w_bits[64];
    wire [3:0]  noc_ar_id = noc_ar_bits[160:157];
    wire [63:0] noc_ar_addr = noc_ar_bits[156:93];
    wire [7:0]  noc_ar_len = noc_ar_bits[92:85];

    logic        aw_seen_q;
    logic        w_seen_q;
    logic        wr_pending_q;
    logic [2:0]  wr_delay_q;
    logic [3:0]  wr_id_q;
    logic [5:0]  wr_index_q;
    logic [63:0] wr_data_q;
    logic [7:0]  wr_strb_q;
    logic        b_valid_q;
    logic [3:0]  b_id_q;
    logic [1:0]  b_resp_q;

    logic        rd_pending_q;
    logic [2:0]  rd_delay_q;
    logic [3:0]  rd_id_q;
    logic [5:0]  rd_index_q;
    logic [63:0] rd_addr_q;
    logic [7:0]  rd_len_q;
    logic [7:0]  rd_beat_q;
    logic        r_valid_q;
    logic [3:0]  r_id_q;
    logic [63:0] r_data_q;
    logic [1:0]  r_resp_q;
    logic        r_last_q;

    wire aw_ready_w = !wr_pending_q && !b_valid_q &&
                      (base_seed[0] || cycle_q[0] || cycle_q[5] || (scenario_w[0] && !cycle_q[3]));
    wire w_ready_w = !wr_pending_q && !b_valid_q &&
                     (base_seed[1] || cycle_q[1] || cycle_q[6] || (scenario_w[1] && !cycle_q[4]));
    wire ar_ready_w = !rd_pending_q && !r_valid_q &&
                      (base_seed[2] || cycle_q[0] || cycle_q[4] || (scenario_w[2] && !cycle_q[5]));
    wire aw_accept = noc_aw_valid && aw_ready_w;
    wire w_accept = noc_w_valid && w_ready_w;
    wire ar_accept = noc_ar_valid && ar_ready_w;
    wire b_fire = b_valid_q && noc_b_ready;
    wire r_fire = r_valid_q && noc_r_ready;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            aw_seen_q <= 1'b0;
            w_seen_q <= 1'b0;
            wr_pending_q <= 1'b0;
            wr_delay_q <= 3'h0;
            wr_id_q <= 4'h0;
            wr_index_q <= 6'h0;
            wr_data_q <= 64'h0;
            wr_strb_q <= 8'h0;
            b_valid_q <= 1'b0;
            b_id_q <= 4'h0;
            b_resp_q <= 2'b00;

            rd_pending_q <= 1'b0;
            rd_delay_q <= 3'h0;
            rd_id_q <= 4'h0;
            rd_index_q <= 6'h0;
            rd_addr_q <= 64'h0;
            rd_len_q <= 8'h0;
            rd_beat_q <= 8'h0;
            r_valid_q <= 1'b0;
            r_id_q <= 4'h0;
            r_data_q <= 64'h0;
            r_resp_q <= 2'b00;
            r_last_q <= 1'b0;
        end else begin
            if (b_fire) begin
                b_valid_q <= 1'b0;
            end

            if (!wr_pending_q && !b_valid_q) begin
                if (aw_accept) begin
                    aw_seen_q <= 1'b1;
                    wr_id_q <= noc_aw_id;
                    wr_index_q <= noc_aw_addr[8:3] ^ base_seed[11:6];
                end
                if (w_accept) begin
                    w_seen_q <= 1'b1;
                    wr_data_q <= noc_w_data ^ {mem_seed0[31:0], mem_seed1[63:32]};
                    wr_strb_q <= (noc_w_strb == 8'h00) ? 8'hff : noc_w_strb;
                end
                if ((aw_seen_q || aw_accept) && (w_seen_q || w_accept || noc_w_last)) begin
                    wr_pending_q <= 1'b1;
                    wr_delay_q <= nonzero_delay(base_seed[14:12] ^ cycle_q[4:2]);
                    aw_seen_q <= 1'b0;
                    w_seen_q <= 1'b0;
                end
            end else if (wr_pending_q) begin
                if (wr_delay_q == 3'h0) begin
                    wr_pending_q <= 1'b0;
                    b_valid_q <= 1'b1;
                    b_id_q <= wr_id_q;
                    b_resp_q <= ((base_seed[18] && (cycle_q[8:0] == {1'b0, event_seed[7:0]})) ||
                                 (scenario_w[5:3] == 3'b101 && cycle_q[9:0] == {2'b10, event_seed[7:0]}))
                              ? 2'b10 : 2'b00;
                end else begin
                    wr_delay_q <= wr_delay_q - 3'h1;
                end
            end

            if (r_fire) begin
                r_valid_q <= 1'b0;
                if (!r_last_q) begin
                    rd_pending_q <= 1'b1;
                    rd_delay_q <= nonzero_delay((base_seed[21:19] ^ rd_beat_q[2:0]) + 3'h1);
                    rd_beat_q <= rd_beat_q + 8'h1;
                    rd_index_q <= rd_index_q + 6'h1;
                end
            end

            if (!rd_pending_q && !r_valid_q && ar_accept) begin
                rd_pending_q <= 1'b1;
                rd_delay_q <= nonzero_delay(base_seed[24:22] ^ cycle_q[5:3]);
                rd_id_q <= noc_ar_id;
                rd_index_q <= noc_ar_addr[8:3] ^ base_seed[30:25];
                rd_addr_q <= noc_ar_addr;
                rd_len_q <= (noc_ar_len > 8'd15) ? 8'd15 : noc_ar_len;
                rd_beat_q <= 8'h0;
            end else if (rd_pending_q) begin
                if (rd_delay_q == 3'h0) begin
                    rd_pending_q <= 1'b0;
                    r_valid_q <= 1'b1;
                    r_id_q <= rd_id_q;
                    if (!base_seed[55] || rd_addr_q[31] || (rd_addr_q[15:12] == boot_addr_q[15:12])) begin
                        r_data_q <= instr_pair(rd_addr_q, rd_beat_q, scenario_w, mem_seed0[31:0] ^ mem_seed1[63:32]);
                    end else begin
                        r_data_q <= mem_q[rd_index_q] ^ mix64(mem_seed0, {56'h0, rd_beat_q}, {56'h0, rd_id_q, 4'h0});
                    end
                    r_resp_q <= ((base_seed[31] && (cycle_q[9:0] == {2'b01, event_seed[15:8]})) ||
                                 (scenario_w[5:3] == 3'b110 && cycle_q[10:0] == {3'b011, event_seed[7:0]}))
                              ? 2'b10 : 2'b00;
                    r_last_q <= (rd_beat_q >= rd_len_q);
                end else begin
                    rd_delay_q <= rd_delay_q - 3'h1;
                end
            end
        end
    end

    wire [69:0] b_chan_bits = {b_id_q, b_resp_q, 64'h0};
    wire [134:0] r_chan_bits = {r_id_q, r_data_q, r_resp_q, r_last_q, 64'h0};
    wire [209:0] noc_resp_bits = {
        aw_ready_w,
        ar_ready_w,
        w_ready_w,
        b_valid_q,
        b_chan_bits,
        r_valid_q,
        r_chan_bits
    };

    wire [448:0] cvx_req_bits = dut.cvxif_req_o;
    wire         x_compressed_valid = cvx_req_bits[448];
    wire [79:0]  x_compressed_req = cvx_req_bits[447:368];
    wire         x_issue_valid = cvx_req_bits[367];
    wire [98:0]  x_issue_req = cvx_req_bits[366:268];
    wire         x_result_ready = cvx_req_bits[0];

    wire [31:0] x_compressed_instr = {16'h0, x_compressed_req[79:64]};
    wire [31:0] x_issue_instr = x_issue_req[98:67];
    wire [63:0] x_issue_hartid = x_issue_req[66:3];
    wire [2:0]  x_issue_id = x_issue_req[2:0];

    logic        x_pending_q;
    logic [2:0]  x_delay_q;
    logic [63:0] x_hartid_q;
    logic [2:0]  x_id_q;
    logic [4:0]  x_rd_q;
    logic [63:0] x_data_q;
    logic        x_we_q;
    logic        x_result_valid_q;

    wire x_accept = x_issue_valid &&
                    (base_seed[33] || x_issue_instr[6:0] == 7'b0001011 || cycle_q[2]) &&
                    !(base_seed[34] && (cycle_q[7:0] == event_seed[23:16]));
    wire x_reject = x_issue_valid && !x_accept &&
                    (base_seed[35] || cycle_q[4:0] == extra_seed[4:0]);

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            x_pending_q <= 1'b0;
            x_delay_q <= 3'h0;
            x_hartid_q <= 64'h0;
            x_id_q <= 3'h0;
            x_rd_q <= 5'h1;
            x_data_q <= 64'h0;
            x_we_q <= 1'b0;
            x_result_valid_q <= 1'b0;
        end else begin
            if (x_result_valid_q && x_result_ready) begin
                x_result_valid_q <= 1'b0;
            end

            if (!x_pending_q && !x_result_valid_q && x_accept) begin
                x_pending_q <= 1'b1;
                x_delay_q <= nonzero_delay(cvx_seed0[2:0] ^ cycle_q[4:2]);
                x_hartid_q <= x_issue_hartid;
                x_id_q <= x_issue_id;
                x_rd_q <= (x_issue_instr[11:7] == 5'h0) ? 5'h1 : x_issue_instr[11:7];
                x_data_q <= mix64(cvx_seed0, cvx_seed1, {32'h0, x_issue_instr});
                x_we_q <= base_seed[36] || (x_issue_instr[11:7] != 5'h0);
            end else if (x_pending_q) begin
                if (x_delay_q == 3'h0) begin
                    x_pending_q <= 1'b0;
                    x_result_valid_q <= 1'b1;
                end else begin
                    x_delay_q <= x_delay_q - 3'h1;
                end
            end
        end
    end

    wire [32:0] x_compressed_resp_bits = {
        base_seed[37] ? {16'h0000, x_compressed_instr[15:0]} : 32'h0000_0013,
        x_compressed_valid && (base_seed[38] || cycle_q[1])
    };
    wire [3:0] x_issue_resp_bits = {
        x_accept && !x_reject,
        x_accept && (base_seed[39] || x_issue_instr[11:7] != 5'h0),
        2'b11
    };
    wire [136:0] x_result_bits = {
        x_hartid_q,
        x_id_q,
        x_data_q,
        x_rd_q,
        x_we_q
    };
    wire [177:0] cvxif_resp_bits = {
        (base_seed[40] || !x_compressed_valid || cycle_q[0]),
        x_compressed_resp_bits,
        (base_seed[41] || !x_issue_valid || cycle_q[0]),
        x_issue_resp_bits,
        (base_seed[42] || !x_issue_valid || cycle_q[1]),
        x_result_valid_q,
        x_result_bits
    };

    logic [7:0] event_counter_q;
    logic [7:0] event_period_q;
    logic [7:0] event_duration_q;
    logic [3:0] event_select_q;
    logic       event_active_q;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            event_counter_q <= 8'h0;
            event_period_q <= 8'd24 + {3'b000, event_seed[4:0]};
            event_duration_q <= {5'h0, event_seed[10:8]} + 8'h1;
            event_select_q <= event_seed[14:11];
            event_active_q <= 1'b0;
        end else begin
            if (event_counter_q >= event_period_q) begin
                event_counter_q <= 8'h0;
                event_period_q <= 8'd24 + {3'b000, (event_seed[20:16] ^ base_seed[4:0])};
                event_duration_q <= {5'h0, (event_seed[18:16] ^ scenario_w[2:0])} + 8'h1;
                event_select_q <= event_seed[30:27] ^ cycle_q[6:3] ^ {1'b0, scenario_w[2:0]};
                event_active_q <= base_seed[43] || event_seed[31] || (cycle_q[5:0] == event_seed[5:0]);
            end else begin
                event_counter_q <= event_counter_q + 8'h1;
                if (event_counter_q >= event_duration_q) begin
                    event_active_q <= 1'b0;
                end
            end
        end
    end

    wire [1:0] irq_i_w = event_active_q ? event_select_q[1:0] : 2'b00;
    wire ipi_i_w = event_active_q && (event_select_q == 4'h2);
    wire time_irq_i_w = event_active_q && (event_select_q == 4'h3);
    wire debug_req_i_w = (base_seed[44] && event_active_q && event_select_q == 4'h4) ||
                         (base_seed[45] && cycle_q[10:0] == {3'b101, event_seed[7:0]}) ||
                         (scenario_w[4] && cycle_q[12:0] == {5'b1_0110, event_seed[7:0]});

    cva6 dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .boot_addr_i(boot_addr_q),
        .hart_id_i(hart_id_q),
        .irq_i(irq_i_w),
        .ipi_i(ipi_i_w),
        .time_irq_i(time_irq_i_w),
        .debug_req_i(debug_req_i_w),
        .rvfi_probes_o(),
        .cvxif_req_o(),
        .cvxif_resp_i(cvxif_resp_bits),
        .noc_req_o(),
        .noc_resp_i(noc_resp_bits),
        .__vi_coverage(__vi_coverage)
    );

endmodule
