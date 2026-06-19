// Input-bit constrained lightweight-plus3 harness for Ibex.
//
// This is an independent scheme4 variant.  It keeps the same 395-bit top-level
// input width as baseline/scheme4, but interprets the 0/1 RFuzz bit string as
// structured fields: scenario/persona, short-program operands, bus latency,
// memory data, and low-frequency trap/debug/error events.  The constraints are
// a projection from raw bits to legal/high-value top-level input behavior.

module ibex_core_lightweight_plus3_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [394:0] rfuzz_input_bits,
    output logic [1113:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    wire [31:0] base_seed      = rfuzz_input_bits[31:0];
    wire [31:0] hart_id_seed   = rfuzz_input_bits[63:32];
    wire [31:0] boot_addr_seed = rfuzz_input_bits[95:64];
    wire [31:0] instr_seed     = rfuzz_input_bits[127:96];
    wire [31:0] data_seed      = rfuzz_input_bits[159:128];
    wire [31:0] rf_seed_a      = rfuzz_input_bits[191:160];
    wire [31:0] rf_seed_b      = rfuzz_input_bits[223:192];
    wire [20:0] irq_seed       = rfuzz_input_bits[244:224];
    wire [3:0]  scenario_sel   = rfuzz_input_bits[248:245] ^ base_seed[3:0];
    wire [2:0]  latency_sel    = rfuzz_input_bits[251:249] ^ base_seed[6:4];
    wire [2:0]  event_sel      = rfuzz_input_bits[254:252] ^ base_seed[9:7];
    wire [4:0]  rd_bias_raw    = rfuzz_input_bits[259:255] ^ instr_seed[11:7];
    wire [4:0]  rd_bias        = (rd_bias_raw == 5'h0) ? 5'h1 : rd_bias_raw;
    wire [4:0]  rs1_bias       = rfuzz_input_bits[264:260] ^ instr_seed[19:15];
    wire [4:0]  rs2_bias       = rfuzz_input_bits[269:265] ^ instr_seed[24:20];
    wire [11:0] imm_bias       = rfuzz_input_bits[281:270] ^ instr_seed[31:20];
    wire [31:0] instr_salt     = rfuzz_input_bits[313:282] ^ instr_seed ^ base_seed;
    wire [31:0] data_salt      = rfuzz_input_bits[345:314] ^ data_seed ^ {base_seed[15:0], base_seed[31:16]};
    wire [31:0] event_salt     = rfuzz_input_bits[377:346] ^ {11'h0, irq_seed} ^ base_seed;
    wire [16:0] extra_salt     = rfuzz_input_bits[394:378];

    logic [31:0] cycle_q;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            cycle_q <= 32'h0;
        end else begin
            cycle_q <= cycle_q + 32'h1;
        end
    end

    function automatic logic [4:0] nz_reg(input logic [4:0] value);
        nz_reg = (value == 5'h0) ? 5'h1 : value;
    endfunction

    function automatic logic [31:0] enc_i(
        input logic [11:0] imm,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3,
        input logic [4:0]  rd,
        input logic [6:0]  opcode
    );
        enc_i = {imm, rs1, funct3, rd, opcode};
    endfunction

    function automatic logic [31:0] enc_r(
        input logic [6:0] funct7,
        input logic [4:0] rs2,
        input logic [4:0] rs1,
        input logic [2:0] funct3,
        input logic [4:0] rd,
        input logic [6:0] opcode
    );
        enc_r = {funct7, rs2, rs1, funct3, rd, opcode};
    endfunction

    function automatic logic [31:0] enc_s(
        input logic [11:0] imm,
        input logic [4:0]  rs2,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3
    );
        enc_s = {imm[11:5], rs2, rs1, funct3, imm[4:0], 7'b0100011};
    endfunction

    function automatic logic [31:0] enc_b(
        input logic [12:0] imm,
        input logic [4:0]  rs2,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3
    );
        enc_b = {imm[12], imm[10:5], rs2, rs1, funct3, imm[4:1], imm[11], 7'b1100011};
    endfunction

    function automatic logic [31:0] enc_u(
        input logic [19:0] imm,
        input logic [4:0]  rd,
        input logic [6:0]  opcode
    );
        enc_u = {imm, rd, opcode};
    endfunction

    function automatic logic [31:0] enc_j(
        input logic [20:0] imm,
        input logic [4:0]  rd
    );
        enc_j = {imm[20], imm[10:1], imm[11], imm[19:12], rd, 7'b1101111};
    endfunction

    function automatic logic [31:0] enc_csr(
        input logic [11:0] csr,
        input logic [4:0]  rs1,
        input logic [2:0]  funct3,
        input logic [4:0]  rd
    );
        enc_csr = {csr, rs1, funct3, rd, 7'b1110011};
    endfunction

    function automatic logic [31:0] special32(
        input logic [3:0] selector,
        input logic [31:0] seed
    );
        begin
            unique case (selector)
                4'h0: special32 = 32'h0000_0000;
                4'h1: special32 = 32'h0000_0001;
                4'h2: special32 = 32'hffff_ffff;
                4'h3: special32 = 32'h8000_0000;
                4'h4: special32 = 32'h7fff_ffff;
                4'h5: special32 = 32'h0000_0fff;
                4'h6: special32 = 32'hffff_f000;
                4'h7: special32 = 32'h0000_8000;
                default: special32 = seed ^ {seed[15:0], seed[31:16]};
            endcase
        end
    endfunction

    function automatic logic [31:0] compressed_pair(input logic [31:0] seed);
        logic [15:0] lo;
        logic [15:0] hi;
        begin
            unique case (seed[3:0])
                4'h0: begin lo = 16'h0001; hi = 16'h0001; end // c.nop; c.nop
                4'h1: begin lo = 16'h9002; hi = 16'h0001; end // c.ebreak; c.nop
                4'h2: begin lo = {seed[15:2], 2'b01}; hi = 16'h0001; end
                4'h3: begin lo = 16'h0001; hi = {seed[31:18], 2'b10}; end
                4'h4: begin lo = {seed[15:2], 2'b00}; hi = {seed[31:18], 2'b01}; end
                default: begin lo = {seed[15:2], 2'b01}; hi = {seed[31:18], 2'b10}; end
            endcase
            compressed_pair = {hi, lo};
        end
    endfunction

    function automatic logic [31:0] legal_instr(input logic [31:0] seed);
        logic [4:0] rd;
        logic [4:0] rs1;
        logic [4:0] rs2;
        logic [11:0] imm12;
        logic [12:0] bimm;
        begin
            rd    = nz_reg(seed[11:7]);
            rs1   = seed[19:15];
            rs2   = seed[24:20];
            imm12 = {seed[31:22], seed[1:0]};
            bimm  = {seed[31], seed[30:25], seed[11:8], 1'b0};

            unique case (seed[4:0])
                5'd0:  legal_instr = enc_i(imm12, rs1, 3'b000, rd, 7'b0010011); // addi
                5'd1:  legal_instr = enc_i(imm12, rs1, 3'b100, rd, 7'b0010011); // xori
                5'd2:  legal_instr = enc_i(imm12, rs1, 3'b110, rd, 7'b0010011); // ori
                5'd3:  legal_instr = enc_i(imm12, rs1, 3'b111, rd, 7'b0010011); // andi
                5'd4:  legal_instr = enc_i({7'b0000000, seed[24:20]}, rs1, 3'b001, rd, 7'b0010011); // slli
                5'd5:  legal_instr = enc_i({1'b0, seed[30], 5'b00000, seed[24:20]}, rs1, 3'b101, rd, 7'b0010011); // srli/srai
                5'd6:  legal_instr = enc_r(7'b0000000, rs2, rs1, 3'b000, rd, 7'b0110011); // add
                5'd7:  legal_instr = enc_r(7'b0100000, rs2, rs1, 3'b000, rd, 7'b0110011); // sub
                5'd8:  legal_instr = enc_r(7'b0000000, rs2, rs1, 3'b100, rd, 7'b0110011); // xor
                5'd9:  legal_instr = enc_r(7'b0000000, rs2, rs1, 3'b110, rd, 7'b0110011); // or
                5'd10: legal_instr = enc_r(7'b0000000, rs2, rs1, 3'b111, rd, 7'b0110011); // and
                5'd11: legal_instr = enc_r(7'b0000000, rs2, rs1, 3'b001, rd, 7'b0110011); // sll
                5'd12: legal_instr = enc_r({1'b0, seed[30], 5'b00000}, rs2, rs1, 3'b101, rd, 7'b0110011); // srl/sra
                5'd13: legal_instr = enc_r(7'b0000001, rs2, rs1, seed[14:12], rd, 7'b0110011); // mul/div/rem family
                5'd14: legal_instr = enc_i({seed[31:22], 2'b00}, rs1, 3'b010, rd, 7'b0000011); // lw
                5'd15: legal_instr = enc_i({seed[31:22], 2'b00}, rs1, seed[14:12], rd, 7'b0000011); // load variants
                5'd16: legal_instr = enc_s({seed[31:22], 2'b00}, rs2, rs1, 3'b010); // sw
                5'd17: legal_instr = enc_s({seed[31:22], 2'b00}, rs2, rs1, seed[14:12]); // store variants
                5'd18: legal_instr = enc_b(bimm, rs2, rs1, 3'b000); // beq
                5'd19: legal_instr = enc_b(bimm, rs2, rs1, 3'b001); // bne
                5'd20: legal_instr = enc_b(bimm, rs2, rs1, 3'b100); // blt
                5'd21: legal_instr = enc_b(bimm, rs2, rs1, 3'b111); // bgeu
                5'd22: legal_instr = enc_j({seed[31:12], 1'b0}, rd); // jal
                5'd23: legal_instr = enc_i({seed[31:22], 2'b00}, rs1, 3'b000, rd, 7'b1100111); // jalr
                5'd24: legal_instr = enc_u(seed[31:12], rd, 7'b0110111); // lui
                5'd25: legal_instr = enc_u(seed[31:12], rd, 7'b0010111); // auipc
                5'd26: legal_instr = enc_csr(12'h300, rs1, 3'b010, rd); // csrrs mstatus
                5'd27: legal_instr = enc_csr(12'h304, rs1, 3'b010, rd); // csrrs mie
                5'd28: legal_instr = enc_csr(12'hb00, 5'h0, 3'b010, rd); // csrrs mcycle
                5'd29: legal_instr = 32'h00000073; // ecall
                5'd30: legal_instr = 32'h00100073; // ebreak
                default: legal_instr = 32'h9002_0001; // c.nop + c.ebreak
            endcase
        end
    endfunction

    function automatic logic [31:0] program_instr(
        input logic [31:0] pc,
        input logic [31:0] seed,
        input logic [31:0] salt,
        input logic [3:0]  scenario,
        input logic [4:0]  rd_base,
        input logic [4:0]  rs1_base,
        input logic [4:0]  rs2_base,
        input logic [11:0] imm_base
    );
        logic [3:0] slot;
        logic [4:0] rd;
        logic [4:0] rs1;
        logic [4:0] rs2;
        logic [11:0] imm12;
        begin
            slot = pc[5:2] ^ seed[3:0] ^ salt[7:4];
            rd = nz_reg(rd_base ^ slot);
            rs1 = rs1_base ^ {1'b0, slot};
            rs2 = rs2_base ^ {slot, 1'b0};
            imm12 = imm_base ^ seed[31:20] ^ {8'h00, slot};

            unique case (scenario[2:0])
                3'd0: begin
                    unique case (slot)
                        4'h0: program_instr = enc_i(12'h001, 5'h0, 3'b000, 5'h1, 7'b0010011);
                        4'h1: program_instr = enc_i(imm12, 5'h1, 3'b000, rd, 7'b0010011);
                        4'h2: program_instr = enc_r(7'b0000000, rs2, rs1, 3'b000, rd, 7'b0110011);
                        4'h3: program_instr = enc_r(7'b0100000, rs2, rs1, 3'b000, rd, 7'b0110011);
                        4'h4: program_instr = enc_r(7'b0000000, rs2, rs1, 3'b100, rd, 7'b0110011);
                        4'h5: program_instr = enc_i({7'b0000000, seed[24:20]}, rs1, 3'b001, rd, 7'b0010011);
                        4'h6: program_instr = enc_i({1'b0, seed[30], 5'b00000, seed[24:20]}, rs1, 3'b101, rd, 7'b0010011);
                        4'h7: program_instr = enc_u(seed[31:12], rd, 7'b0110111);
                        4'h8: program_instr = enc_u(seed[31:12], rd, 7'b0010111);
                        4'h9: program_instr = enc_b(13'd8, rs2, rs1, salt[9] ? 3'b001 : 3'b000);
                        4'ha: program_instr = enc_j(21'd16, rd);
                        4'hb: program_instr = enc_csr(12'hb00, 5'h0, 3'b010, rd);
                        default: program_instr = legal_instr(seed ^ pc ^ salt);
                    endcase
                end
                3'd1: begin
                    unique case (slot)
                        4'h0: program_instr = enc_i({8'h00, salt[3:0]}, 5'h0, 3'b000, 5'h1, 7'b0010011);
                        4'h1: program_instr = enc_i({8'h00, salt[3:0]}, 5'h0, 3'b000, 5'h2, 7'b0010011);
                        4'h2: program_instr = enc_b(13'd8, 5'h2, 5'h1, 3'b000);
                        4'h3: program_instr = enc_b(13'd8, 5'h2, 5'h1, 3'b001);
                        4'h4: program_instr = enc_b(13'd8, 5'h2, 5'h1, 3'b100);
                        4'h5: program_instr = enc_b(13'd8, 5'h2, 5'h1, 3'b101);
                        4'h6: program_instr = enc_j(21'd12, 5'h3);
                        4'h7: program_instr = enc_i(12'h000, 5'h3, 3'b000, 5'h0, 7'b1100111);
                        default: program_instr = legal_instr(seed ^ {pc[15:0], salt[15:0]});
                    endcase
                end
                3'd2: begin
                    unique case (slot)
                        4'h0: program_instr = enc_i({4'h0, seed[7:2], 2'b00}, 5'h0, 3'b000, 5'h3, 7'b0010011);
                        4'h1: program_instr = enc_i(imm12, 5'h0, 3'b000, 5'h4, 7'b0010011);
                        4'h2: program_instr = enc_s({8'h00, salt[3:2], 2'b00}, 5'h4, 5'h3, 3'b000);
                        4'h3: program_instr = enc_s({8'h00, salt[5:4], 2'b00}, 5'h4, 5'h3, 3'b001);
                        4'h4: program_instr = enc_s({8'h00, salt[7:6], 2'b00}, 5'h4, 5'h3, 3'b010);
                        4'h5: program_instr = enc_i({8'h00, salt[3:2], 2'b00}, 5'h3, 3'b000, 5'h5, 7'b0000011);
                        4'h6: program_instr = enc_i({8'h00, salt[5:4], 2'b00}, 5'h3, 3'b001, 5'h6, 7'b0000011);
                        4'h7: program_instr = enc_i({8'h00, salt[7:6], 2'b00}, 5'h3, 3'b010, 5'h7, 7'b0000011);
                        4'h8: program_instr = enc_i({8'h00, salt[9:8], 2'b00}, 5'h3, 3'b100, 5'h8, 7'b0000011);
                        4'h9: program_instr = enc_i({8'h00, salt[11:10], 2'b00}, 5'h3, 3'b101, 5'h9, 7'b0000011);
                        default: program_instr = enc_r(7'b0000000, 5'h7, 5'h8, 3'b000, rd, 7'b0110011);
                    endcase
                end
                3'd3: begin
                    unique case (slot)
                        4'h0: program_instr = enc_i(12'h040, 5'h0, 3'b000, 5'h3, 7'b0010011);
                        4'h1: program_instr = enc_csr(12'h305, 5'h3, 3'b001, 5'h0); // mtvec
                        4'h2: program_instr = enc_i(12'h008, 5'h0, 3'b000, 5'h1, 7'b0010011);
                        4'h3: program_instr = enc_csr(12'h300, 5'h1, 3'b010, 5'h0); // mstatus
                        4'h4: program_instr = enc_i(12'h888, 5'h0, 3'b000, 5'h2, 7'b0010011);
                        4'h5: program_instr = enc_csr(12'h304, 5'h2, 3'b010, 5'h0); // mie
                        4'h6: program_instr = enc_csr(12'h341, 5'h0, 3'b010, rd); // mepc
                        4'h7: program_instr = enc_csr(12'h342, 5'h0, 3'b010, rd); // mcause
                        4'h8: program_instr = enc_csr(12'h344, 5'h0, 3'b010, rd); // mip
                        4'h9: program_instr = enc_csr(12'hb00, 5'h0, 3'b010, rd); // mcycle
                        4'ha: program_instr = enc_csr(12'hb02, 5'h0, 3'b010, rd); // minstret
                        4'hb: program_instr = 32'h00000073; // ecall
                        4'hc: program_instr = 32'h00100073; // ebreak
                        4'hd: program_instr = 32'h30200073; // mret
                        default: program_instr = legal_instr(seed ^ pc ^ salt);
                    endcase
                end
                3'd4: begin
                    unique case (slot)
                        4'h0: program_instr = enc_i(12'h001, 5'h0, 3'b000, 5'h1, 7'b0010011);
                        4'h1: program_instr = enc_i(12'hfff, 5'h0, 3'b000, 5'h2, 7'b0010011);
                        4'h2: program_instr = enc_r(7'b0000001, 5'h2, 5'h1, 3'b000, rd, 7'b0110011); // mul
                        4'h3: program_instr = enc_r(7'b0000001, 5'h2, 5'h1, 3'b001, rd, 7'b0110011); // mulh
                        4'h4: program_instr = enc_r(7'b0000001, 5'h2, 5'h1, 3'b100, rd, 7'b0110011); // div
                        4'h5: program_instr = enc_r(7'b0000001, 5'h2, 5'h1, 3'b101, rd, 7'b0110011); // divu
                        4'h6: program_instr = enc_r(7'b0000001, 5'h2, 5'h1, 3'b110, rd, 7'b0110011); // rem
                        4'h7: program_instr = enc_r(7'b0000001, 5'h2, 5'h1, 3'b111, rd, 7'b0110011); // remu
                        default: program_instr = legal_instr(seed ^ pc ^ salt);
                    endcase
                end
                3'd5: begin
                    program_instr = compressed_pair(seed ^ pc ^ salt);
                end
                3'd6: begin
                    unique case (slot)
                        4'h0: program_instr = 32'h00000073; // ecall
                        4'h1: program_instr = 32'h00100073; // ebreak
                        4'h2: program_instr = 32'h30200073; // mret
                        4'h3: program_instr = 32'h7b200073; // dret-like privileged path
                        4'h4: program_instr = 32'h00000000; // illegal
                        4'h5: program_instr = 32'hffff_ffff; // illegal/compressed-heavy
                        4'h6: program_instr = enc_i(12'h001, 5'h0, 3'b000, rd, 7'b0010011);
                        default: program_instr = legal_instr(seed ^ pc ^ salt);
                    endcase
                end
                default: begin
                    unique case (slot)
                        4'h0: program_instr = enc_u(20'h80000, rd, 7'b0110111);
                        4'h1: program_instr = enc_u(20'h7ffff, rd, 7'b0110111);
                        4'h2: program_instr = enc_i(12'hfff, 5'h0, 3'b000, rd, 7'b0010011);
                        4'h3: program_instr = enc_i(12'h001, rd, 3'b001, rd, 7'b0010011);
                        4'h4: program_instr = enc_i(12'h01f, rd, 3'b101, rd, 7'b0010011);
                        4'h5: program_instr = enc_b(13'd8, rd, 5'h0, 3'b100);
                        4'h6: program_instr = enc_b(13'd8, rd, 5'h0, 3'b111);
                        default: program_instr = legal_instr(seed ^ pc ^ salt);
                    endcase
                end
            endcase
        end
    endfunction

    function automatic logic [31:0] merge_be(
        input logic [31:0] old_word,
        input logic [31:0] new_word,
        input logic [3:0]  be
    );
        begin
            merge_be = old_word;
            if (be[0]) merge_be[7:0]   = new_word[7:0];
            if (be[1]) merge_be[15:8]  = new_word[15:8];
            if (be[2]) merge_be[23:16] = new_word[23:16];
            if (be[3]) merge_be[31:24] = new_word[31:24];
        end
    endfunction

    wire [3:0] fetch_enable = 4'b0001;

    logic [31:0] hart_id_latched;
    logic [31:0] boot_addr_latched;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            hart_id_latched <= hart_id_seed;
            boot_addr_latched <= {20'h0, boot_addr_seed[11:2], 2'b00};
        end
    end

    logic [31:0] rf_model [0:31];
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            for (int i = 0; i < 32; i++) begin
                rf_model[i] <= (i == 0) ? 32'h0 :
                               special32((scenario_sel ^ i[3:0]), rf_seed_a ^ (rf_seed_b + i));
            end
        end else begin
            rf_model[0] <= 32'h0;
            if (dut.rf_we_wb_o && (dut.rf_waddr_wb_o != 5'h0)) begin
                rf_model[dut.rf_waddr_wb_o] <= dut.rf_wdata_wb_ecc_o;
            end
        end
    end

    wire [31:0] rf_rdata_a =
        (dut.rf_raddr_a_o == 5'h0) ? 32'h0 : rf_model[dut.rf_raddr_a_o];
    wire [31:0] rf_rdata_b =
        (dut.rf_raddr_b_o == 5'h0) ? 32'h0 : rf_model[dut.rf_raddr_b_o];

    logic        data_gnt_reg;
    logic        data_rvalid_reg;
    logic        data_pending_q;
    logic        data_pending_we_q;
    logic [1:0]  data_delay_q;
    logic [3:0]  data_pending_be_q;
    logic [4:0]  data_pending_index_q;
    logic [31:0] data_pending_addr_q;
    logic [31:0] data_pending_wdata_q;
    logic [31:0] data_rdata_q;

    logic [31:0] data_mem [0:31];
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            for (int i = 0; i < 32; i++) begin
                data_mem[i] <= special32((scenario_sel ^ i[3:0]), data_seed ^ data_salt ^ (32'h9e37_0000 + i));
            end
        end else if (data_pending_q && (data_delay_q == 2'h0) && data_pending_we_q) begin
            data_mem[data_pending_index_q] <= merge_be(
                data_mem[data_pending_index_q],
                data_pending_wdata_q,
                data_pending_be_q
            );
        end
    end

    logic        instr_gnt_reg;
    logic        instr_rvalid_reg;
    logic        instr_pending_q;
    logic [1:0]  instr_delay_q;
    logic [31:0] instr_rdata_q;
    wire [31:0] instr_pc_mix = dut.instr_addr_o ^ {cycle_q[7:0], cycle_q[15:8], cycle_q[23:16], cycle_q[31:24]};
    wire [31:0] instr_program = program_instr(
        dut.instr_addr_o,
        instr_seed ^ instr_salt,
        base_seed ^ instr_salt,
        scenario_sel,
        rd_bias,
        rs1_bias,
        rs2_bias,
        imm_bias
    );
    wire [31:0] instr_generic = legal_instr(instr_seed ^ instr_pc_mix ^ instr_salt ^ base_seed);
    wire instr_raw_escape = (scenario_sel == 4'hf) && extra_salt[0];
    wire instr_compressed_escape = (scenario_sel[2:0] == 3'd5) || (extra_salt[1] && scenario_sel[3]);
    wire [31:0] instr_candidate =
        instr_raw_escape ? instr_seed :
        instr_compressed_escape ? compressed_pair(instr_seed ^ instr_salt ^ dut.instr_addr_o) :
        (scenario_sel[3] && extra_salt[2]) ? instr_generic :
                                     instr_program;
    wire instr_backpressure =
        (latency_sel[2] && (cycle_q[2:0] == latency_sel)) ||
        (latency_sel == 3'd6 && cycle_q[4:0] == event_salt[4:0]);
    wire [1:0] instr_latency =
        (latency_sel[1:0] == 2'b00) ? 2'h0 :
        (latency_sel[2] ? (cycle_q[1:0] ^ latency_sel[1:0]) : latency_sel[1:0]);

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            instr_gnt_reg <= 1'b0;
            instr_rvalid_reg <= 1'b0;
            instr_pending_q <= 1'b0;
            instr_delay_q <= 2'h0;
            instr_rdata_q <= 32'h00000013;
        end else begin
            instr_gnt_reg <= 1'b0;
            instr_rvalid_reg <= 1'b0;

            if (!instr_pending_q) begin
                if (dut.instr_req_o && !instr_backpressure) begin
                    instr_gnt_reg <= 1'b1;
                    instr_pending_q <= 1'b1;
                    instr_delay_q <= instr_latency;
                    instr_rdata_q <= instr_candidate;
                end
            end else if (instr_delay_q == 2'h0) begin
                instr_rvalid_reg <= 1'b1;
                instr_pending_q <= 1'b0;
            end else begin
                instr_delay_q <= instr_delay_q - 2'h1;
            end
        end
    end

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            data_gnt_reg <= 1'b0;
            data_rvalid_reg <= 1'b0;
            data_pending_q <= 1'b0;
            data_pending_we_q <= 1'b0;
            data_delay_q <= 2'h0;
            data_pending_be_q <= 4'h0;
            data_pending_index_q <= 5'h0;
            data_pending_addr_q <= 32'h0;
            data_pending_wdata_q <= 32'h0;
            data_rdata_q <= 32'h0;
        end else begin
            data_gnt_reg <= 1'b0;
            data_rvalid_reg <= 1'b0;

            if (!data_pending_q) begin
                if (dut.data_req_o &&
                    !(latency_sel[2] && (cycle_q[3:1] == (latency_sel ^ scenario_sel[2:0])))) begin
                    data_gnt_reg <= 1'b1;
                    data_pending_q <= 1'b1;
                    data_pending_we_q <= dut.data_we_o;
                    data_pending_be_q <= (dut.data_be_o == 4'h0) ? 4'hf : dut.data_be_o;
                    data_pending_addr_q <= dut.data_addr_o;
                    data_pending_index_q <= dut.data_addr_o[6:2] ^ data_salt[4:0];
                    data_pending_wdata_q <= dut.data_wdata_o ^ data_salt;
                    data_delay_q <= (latency_sel[1:0] == 2'b00) ? 2'h0 :
                                    ((latency_sel[2] || scenario_sel[2:0] == 3'd2) ?
                                     (cycle_q[1:0] ^ latency_sel[1:0]) : latency_sel[1:0]);
                end
            end else if (data_delay_q == 2'h0) begin
                data_rvalid_reg <= 1'b1;
                data_pending_q <= 1'b0;
                data_rdata_q <= data_mem[data_pending_index_q] ^
                                data_salt ^
                                {data_pending_addr_q[15:0], data_pending_addr_q[31:16]};
            end else begin
                data_delay_q <= data_delay_q - 2'h1;
            end
        end
    end

    wire event_error_en = (event_sel[1] || scenario_sel[2:0] == 3'd6);
    wire event_debug_en = (event_sel[2] || scenario_sel[2:0] == 3'd6);
    wire event_irq_en = (event_sel != 3'd0) || (scenario_sel[2:0] == 3'd3);
    wire instr_err = instr_rvalid_reg &&
                     event_error_en &&
                     (cycle_q[8:0] == {1'b0, event_salt[7:0]});
    wire data_err = data_rvalid_reg &&
                    event_error_en &&
                    (cycle_q[7:0] == (event_salt[15:8] ^ 8'h5a));

    logic [7:0] irq_counter;
    logic [7:0] irq_period;
    logic [7:0] irq_duration;
    logic [4:0] irq_select;
    logic       irq_active;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            irq_counter <= 8'h0;
            irq_period <= 8'd32 + {2'b00, event_salt[21:16]};
            irq_duration <= {5'h0, event_salt[10:8]} + 8'h1;
            irq_select <= irq_seed[4:0];
            irq_active <= 1'b0;
        end else begin
            if (irq_counter >= irq_period) begin
                irq_counter <= 8'h0;
                irq_period <= 8'd32 + (irq_seed[15:8] ^ event_salt[23:16]);
                irq_duration <= {5'h0, event_salt[18:16]} + 8'h1;
                irq_select <= irq_seed[9:5] ^ {1'b0, cycle_q[5:2]} ^ {2'b00, event_sel};
                irq_active <= event_irq_en;
            end else begin
                irq_counter <= irq_counter + 8'h1;
                if (irq_counter >= irq_duration) begin
                    irq_active <= 1'b0;
                end
            end
        end
    end

    wire irq_software = irq_active && (irq_select == 5'd0);
    wire irq_timer    = irq_active && (irq_select == 5'd1);
    wire irq_external = irq_active && (irq_select == 5'd2);
    wire [14:0] irq_fast = irq_active ? (15'h1 << irq_select[3:0]) : 15'h0;
    wire irq_nm = irq_active && ((irq_select == 5'd31) || (event_sel[0] && cycle_q[6:0] == 7'h55));

    wire debug_req = event_debug_en &&
                     ((cycle_q[8:0] == {1'b0, event_salt[7:0]}) ||
                      (cycle_q[9:0] == {2'b10, event_salt[15:8]}));

    wire [20:0] ic_tag_0 = instr_salt[20:0];
    wire [20:0] ic_tag_1 = data_salt[20:0];
    wire [63:0] ic_data_0 = {instr_salt, data_salt};
    wire [63:0] ic_data_1 = {event_salt, instr_seed ^ data_seed};

    ibex_core #(
        .PMPEnable(1'b0),
        .SecureIbex(1'b0),
        .RV32M(ibex_pkg::RV32MFast),
        .RV32B(ibex_pkg::RV32BNone),
        .WritebackStage(1'b0),
        .ICache(1'b0),
        .RegFileECC(1'b0),
        .MemECC(1'b0)
    ) dut (
        .clk_i(clock),
        .rst_ni(rst_ni),

        .hart_id_i(hart_id_latched),
        .boot_addr_i(boot_addr_latched),

        .instr_req_o(),
        .instr_gnt_i(instr_gnt_reg),
        .instr_rvalid_i(instr_rvalid_reg),
        .instr_addr_o(),
        .instr_rdata_i(instr_rdata_q),
        .instr_err_i(instr_err),

        .data_req_o(),
        .data_gnt_i(data_gnt_reg),
        .data_rvalid_i(data_rvalid_reg),
        .data_we_o(),
        .data_be_o(),
        .data_addr_o(),
        .data_wdata_o(),
        .data_rdata_i(data_rdata_q),
        .data_err_i(data_err),

        .rf_raddr_a_o(),
        .rf_raddr_b_o(),
        .rf_waddr_wb_o(),
        .rf_we_wb_o(),
        .rf_wdata_wb_ecc_o(),
        .rf_rdata_a_ecc_i(rf_rdata_a),
        .rf_rdata_b_ecc_i(rf_rdata_b),

        .ic_tag_req_o(),
        .ic_tag_write_o(),
        .ic_tag_addr_o(),
        .ic_tag_wdata_o(),
        .ic_tag_rdata_i({ic_tag_1, ic_tag_0}),
        .ic_data_req_o(),
        .ic_data_write_o(),
        .ic_data_addr_o(),
        .ic_data_wdata_o(),
        .ic_data_rdata_i({ic_data_1, ic_data_0}),
        .ic_scr_key_valid_i(1'b0),
        .ic_scr_key_req_o(),

        .irq_software_i(irq_software),
        .irq_timer_i(irq_timer),
        .irq_external_i(irq_external),
        .irq_fast_i(irq_fast),
        .irq_nm_i(irq_nm),

        .debug_req_i(debug_req),

        .crash_dump_o(),
        .double_fault_seen_o(),
        .alert_minor_o(),
        .alert_major_internal_o(),
        .alert_major_bus_o(),
        .core_busy_o(),
        .fetch_enable_i(fetch_enable),
        .dummy_instr_id_o(),
        .dummy_instr_wb_o(),
        .__vi_coverage(__vi_coverage)
    );

endmodule
