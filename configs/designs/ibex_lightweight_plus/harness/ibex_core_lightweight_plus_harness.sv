// Lightweight-plus constrained harness for Ibex.
// Keeps the baseline 395-bit input width, but adds low-frequency legal
// exploration on top of the original scheme4 protocol constraints.

module ibex_core_lightweight_plus_harness (
    input logic         clock,
    input logic         reset,
    input logic         io_meta_reset,
    input logic [394:0] rfuzz_input_bits,
    output logic [1113:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    wire [31:0] base_seed       = rfuzz_input_bits[31:0];
    wire [31:0] hart_id_seed    = rfuzz_input_bits[63:32];
    wire [31:0] boot_addr_seed  = rfuzz_input_bits[95:64];
    wire [31:0] instr_seed      = rfuzz_input_bits[127:96];
    wire [31:0] data_seed       = rfuzz_input_bits[159:128];
    wire [31:0] rf_seed_a       = rfuzz_input_bits[191:160];
    wire [31:0] rf_seed_b       = rfuzz_input_bits[223:192];
    wire [20:0] irq_seed        = rfuzz_input_bits[244:224];

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

    function automatic logic [31:0] legal_instr(input logic [31:0] seed);
        logic [4:0] rd;
        logic [4:0] rs1;
        logic [4:0] rs2;
        logic [11:0] imm12;
        logic [12:0] bimm;
        logic [20:0] jimm;
        begin
            rd    = nz_reg(seed[11:7]);
            rs1   = seed[19:15];
            rs2   = seed[24:20];
            imm12 = seed[31:20];
            bimm  = {seed[31], seed[30:25], seed[11:8], 1'b0};
            jimm  = {seed[31:12], 1'b0};

            unique case (seed[2:0])
                3'd0: legal_instr = {imm12, rs1, 3'b000, rd, 7'b0010011}; // addi
                3'd1: legal_instr = {7'b0000000, rs2, rs1, 3'b000, rd, 7'b0110011}; // add
                3'd2: legal_instr = {imm12, rs1, 3'b010, rd, 7'b0000011}; // lw
                3'd3: legal_instr = {imm12[11:5], rs2, rs1, 3'b010, imm12[4:0], 7'b0100011}; // sw
                3'd4: legal_instr = {bimm[12], bimm[10:5], rs2, rs1, 3'b000,
                                     bimm[4:1], bimm[11], 7'b1100011}; // beq
                3'd5: legal_instr = {jimm[20], jimm[10:1], jimm[11], jimm[19:12],
                                     rd, 7'b1101111}; // jal
                3'd6: legal_instr = {seed[31:12], rd, 7'b0110111}; // lui
                default: legal_instr = {12'h300, rs1, 3'b010, rd, 7'b1110011}; // csrrs mstatus
            endcase
        end
    endfunction

    wire [3:0] fetch_enable = 4'b0001;

    logic [31:0] hart_id_latched;
    logic [31:0] boot_addr_latched;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            hart_id_latched <= hart_id_seed;
            boot_addr_latched <= {boot_addr_seed[31:2], 2'b00};
        end
    end

    logic        instr_gnt_reg;
    logic        instr_rvalid_reg;
    logic        instr_pending_q;
    logic [1:0]  instr_delay_q;
    logic [31:0] instr_rdata_q;

    wire [31:0] instr_structured = legal_instr(instr_seed ^ cycle_q);
    wire [31:0] instr_candidate =
        (base_seed[5:4] == 2'b10) ? instr_seed :
        (base_seed[5:4] == 2'b11) ? 32'h00000013 :
                                    instr_structured;

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
                if (dut.instr_req_o && (base_seed[0] | cycle_q[0])) begin
                    instr_gnt_reg <= 1'b1;
                    instr_pending_q <= 1'b1;
                    instr_delay_q <= {1'b0, base_seed[2] ^ cycle_q[1]};
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

    logic        data_gnt_reg;
    logic        data_rvalid_reg;
    logic        data_pending_q;
    logic [1:0]  data_delay_q;
    logic [31:0] data_rdata_q;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            data_gnt_reg <= 1'b0;
            data_rvalid_reg <= 1'b0;
            data_pending_q <= 1'b0;
            data_delay_q <= 2'h0;
            data_rdata_q <= 32'h0;
        end else begin
            data_gnt_reg <= 1'b0;
            data_rvalid_reg <= 1'b0;

            if (!data_pending_q) begin
                if (dut.data_req_o && (base_seed[1] | cycle_q[0])) begin
                    data_gnt_reg <= 1'b1;
                    data_pending_q <= 1'b1;
                    data_delay_q <= {1'b0, base_seed[3] ^ cycle_q[2]};
                    data_rdata_q <= data_seed ^ {cycle_q[15:0], cycle_q[31:16]};
                end
            end else if (data_delay_q == 2'h0) begin
                data_rvalid_reg <= 1'b1;
                data_pending_q <= 1'b0;
            end else begin
                data_delay_q <= data_delay_q - 2'h1;
            end
        end
    end

    wire instr_err = instr_rvalid_reg && base_seed[24] && (cycle_q[7:0] == 8'h3d);
    wire data_err  = data_rvalid_reg  && base_seed[25] && (cycle_q[6:0] == 7'h2a);

    logic [7:0] irq_counter;
    logic [7:0] irq_duration;
    logic [4:0] irq_select;
    logic       irq_active;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            irq_counter <= 8'h0;
            irq_duration <= {5'h0, base_seed[10:8]} + 8'h2;
            irq_select <= irq_seed[4:0];
            irq_active <= 1'b0;
        end else begin
            if (irq_counter >= 8'd48) begin
                irq_duration <= {5'h0, base_seed[18:16]} + 8'h2;
                irq_select <= irq_seed[9:5] ^ {1'b0, cycle_q[5:2]};
                irq_active <= irq_seed[10];
                irq_counter <= 8'h0;
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
    wire irq_nm       = irq_active && (irq_select == 5'd31);

    wire [31:0] rf_rdata_a =
        (dut.rf_raddr_a_o == 5'h0) ? 32'h0 : (rf_seed_a ^ {27'h0, dut.rf_raddr_a_o});
    wire [31:0] rf_rdata_b =
        (dut.rf_raddr_b_o == 5'h0) ? 32'h0 : (rf_seed_b ^ {27'h0, dut.rf_raddr_b_o});

    wire debug_req = base_seed[26] && ((cycle_q[7:0] == 8'h40) || (cycle_q[7:0] == 8'h80));

    wire [20:0] ic_tag_0 = rfuzz_input_bits[265:245];
    wire [20:0] ic_tag_1 = rfuzz_input_bits[286:266];
    wire [63:0] ic_data_0 = {rfuzz_input_bits[318:287], rfuzz_input_bits[350:319]};
    wire [63:0] ic_data_1 = {rfuzz_input_bits[382:351], rfuzz_input_bits[394:383], 20'h0};

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
