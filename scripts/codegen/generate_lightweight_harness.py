#!/usr/bin/env python3
"""生成轻量级约束harness - 只约束23个顶层端口间的关系"""

from pathlib import Path


def generate_lightweight_harness() -> str:
    """生成轻量级harness的SystemVerilog代码"""

    code = """// Copyright 2024 - Lightweight Constrained Harness for Ibex
// 只约束顶层23个端口间的关系，输入保持395位

module ibex_core_lightweight_harness (
    input logic        clock,
    input logic        reset,
    input logic        io_meta_reset,
    input logic [394:0] rfuzz_input_bits  // 和baseline一样，395位
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    // ============================================================
    // 从rfuzz提取种子
    // ============================================================
    wire [31:0] base_seed = rfuzz_input_bits[31:0];
    wire [31:0] hart_id_seed = rfuzz_input_bits[63:32];
    wire [31:0] boot_addr_seed = rfuzz_input_bits[95:64];
    wire [31:0] instr_rdata_seed = rfuzz_input_bits[127:96];
    wire [31:0] data_rdata_seed = rfuzz_input_bits[159:128];
    wire [31:0] rf_seed_a = rfuzz_input_bits[191:160];
    wire [31:0] rf_seed_b = rfuzz_input_bits[223:192];
    wire [20:0] irq_seed = rfuzz_input_bits[244:224];

    // ============================================================
    // 约束1: fetch_enable固定
    // ============================================================
    wire [3:0] fetch_enable;
    assign fetch_enable = 4'b0001;

    // ============================================================
    // 约束2: hart_id和boot_addr在reset后固定
    // ============================================================
    logic [31:0] hart_id_latched;
    logic [31:0] boot_addr_latched;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            hart_id_latched <= hart_id_seed;
            boot_addr_latched <= {boot_addr_seed[31:2], 2'b00};
        end
    end

    // ============================================================
    // 约束3: 指令总线协议
    // ============================================================
    logic instr_req_reg;
    logic instr_gnt_reg;
    logic instr_rvalid_reg;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            instr_req_reg <= 1'b0;
            instr_gnt_reg <= 1'b0;
            instr_rvalid_reg <= 1'b0;
        end else begin
            instr_req_reg <= dut.instr_req_o;
            // gnt只在req时可能有效
            instr_gnt_reg <= instr_req_reg && base_seed[0];
            // rvalid在gnt后1周期
            instr_rvalid_reg <= instr_gnt_reg;
        end
    end

    wire [31:0] instr_rdata;
    assign instr_rdata = instr_rvalid_reg ? instr_rdata_seed : 32'h00000013;

    // ============================================================
    // 约束4: 数据总线协议
    // ============================================================
    logic data_req_reg;
    logic data_gnt_reg;
    logic data_rvalid_reg;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            data_req_reg <= 1'b0;
            data_gnt_reg <= 1'b0;
            data_rvalid_reg <= 1'b0;
        end else begin
            data_req_reg <= dut.data_req_o;
            data_gnt_reg <= data_req_reg && base_seed[1];
            data_rvalid_reg <= data_gnt_reg;
        end
    end

    wire [31:0] data_rdata;
    assign data_rdata = data_rvalid_reg ? data_rdata_seed : 32'h0;

    // ============================================================
    // 约束5: 中断burst模式
    // ============================================================
    logic [7:0] irq_counter;
    logic [7:0] irq_duration;
    logic [4:0] irq_select;
    logic       irq_active;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            irq_counter <= 8'h0;
            irq_duration <= base_seed[15:8] | 8'h08;
            irq_select <= irq_seed[4:0];
            irq_active <= 1'b0;
        end else begin
            if (irq_counter >= 8'd200) begin
                irq_duration <= base_seed[23:16] | 8'h08;
                irq_select <= irq_seed[9:5];
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

    // ============================================================
    // 约束6: RF读数据（x0固定为0）
    // ============================================================
    wire [31:0] rf_rdata_a;
    wire [31:0] rf_rdata_b;

    assign rf_rdata_a = (dut.rf_raddr_a_o == 5'h0) ? 32'h0 : rf_seed_a;
    assign rf_rdata_b = (dut.rf_raddr_b_o == 5'h0) ? 32'h0 : rf_seed_b;

    // ============================================================
    // I-cache信号（简化）
    // ============================================================
    wire [20:0] ic_tag_0 = rfuzz_input_bits[265:245];
    wire [20:0] ic_tag_1 = rfuzz_input_bits[286:266];
    wire [63:0] ic_data_0 = {rfuzz_input_bits[318:287], rfuzz_input_bits[350:319]};
    wire [63:0] ic_data_1 = {rfuzz_input_bits[382:351], rfuzz_input_bits[394:383], 20'h0};

    // ============================================================
    // DUT: ibex_core
    // ============================================================
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

        // 指令总线（协议约束）
        .instr_req_o(),
        .instr_gnt_i(instr_gnt_reg),
        .instr_rvalid_i(instr_rvalid_reg),
        .instr_addr_o(),
        .instr_rdata_i(instr_rdata),
        .instr_err_i(1'b0),

        // 数据总线（协议约束）
        .data_req_o(),
        .data_gnt_i(data_gnt_reg),
        .data_rvalid_i(data_rvalid_reg),
        .data_we_o(),
        .data_be_o(),
        .data_addr_o(),
        .data_wdata_o(),
        .data_rdata_i(data_rdata),
        .data_err_i(1'b0),

        // 寄存器文件（约束）
        .rf_raddr_a_o(),
        .rf_raddr_b_o(),
        .rf_waddr_wb_o(),
        .rf_we_wb_o(),
        .rf_wdata_wb_ecc_o(),
        .rf_rdata_a_ecc_i(rf_rdata_a),
        .rf_rdata_b_ecc_i(rf_rdata_b),

        // I-cache接口
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

        // 中断（burst模式）
        .irq_software_i(irq_software),
        .irq_timer_i(irq_timer),
        .irq_external_i(irq_external),
        .irq_fast_i(irq_fast),
        .irq_nm_i(irq_nm),

        // 调试
        .debug_req_i(1'b0),

        // 其他
        .crash_dump_o(),
        .double_fault_seen_o(),
        .alert_minor_o(),
        .alert_major_internal_o(),
        .alert_major_bus_o(),
        .core_sleep_o(),
        .scan_rst_ni(1'b1),
        .fetch_enable_i(fetch_enable),
        .dummy_instr_id_o(),
        .dummy_instr_wb_o()
    );

endmodule
"""
    return code


def main() -> int:
    output_dir = Path("myfuzz/runs/designs/ibex_lightweight/harness")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "ibex_core_lightweight_harness.sv"
    output_file.write_text(generate_lightweight_harness())

    print(f"✓ 生成轻量级harness: {output_file}")
    print(f"  - 输入: 395位（和baseline一样）")
    print(f"  - 约束: 总线协议 + 中断burst + fetch_enable固定")
    print(f"  - 代码: ~200行")

    # 生成配置文件
    config_dir = Path("myfuzz/configs/designs/ibex_lightweight")
    config_dir.mkdir(parents=True, exist_ok=True)

    config_file = config_dir / "config.json"
    config_content = """{
  "top": "ibex_core",
  "project_root": "third_party/rfuzz/upstream/ibex",
  "flist": "third_party/rfuzz/upstream/ibex/sources.f",
  "out_dir": "runs/designs/ibex_lightweight",
  "harness": {
    "manual_harness": "runs/designs/ibex_lightweight/harness/ibex_core_lightweight_harness.sv",
    "manual_harness_module": "ibex_core_lightweight_harness"
  },
  "description": "Ibex core with lightweight port-level constraints"
}
"""
    config_file.write_text(config_content)
    print(f"✓ 生成配置文件: {config_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
