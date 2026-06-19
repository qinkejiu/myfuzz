#!/usr/bin/env python3
"""从约束规则生成带约束的SystemVerilog harness。

读取 extracted_constraints.yaml，生成：
1. constrained_memory_model.sv - 符合协议的memory model
2. ibex_core_constrained_harness.sv - 主harness
3. constraint_generators.sv - 约束输入生成器
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def generate_memory_model(constraints: dict[str, Any]) -> str:
    """生成符合协议约束的memory model"""

    instr_protocol = next(
        (p for p in constraints["protocols"] if p["name"] == "instruction_bus_protocol"),
        None
    )
    data_protocol = next(
        (p for p in constraints["protocols"] if p["name"] == "data_bus_protocol"),
        None
    )

    code = """// Copyright 2024 - Constrained Memory Model for Ibex Fuzzing
// Auto-generated from extracted_constraints.yaml

module constrained_memory_model #(
    parameter int IMEM_SIZE = 1024,  // 指令存储器大小（字）
    parameter int DMEM_SIZE = 1024   // 数据存储器大小（字）
) (
    input  logic        clk_i,
    input  logic        rst_ni,

    // Instruction memory interface
    input  logic        instr_req_i,
    output logic        instr_gnt_o,
    output logic        instr_rvalid_o,
    input  logic [31:0] instr_addr_i,
    output logic [31:0] instr_rdata_o,
    output logic        instr_err_o,

    // Data memory interface
    input  logic        data_req_i,
    output logic        data_gnt_o,
    output logic        data_rvalid_o,
    input  logic        data_we_i,
    input  logic [3:0]  data_be_i,
    input  logic [31:0] data_addr_i,
    input  logic [31:0] data_wdata_i,
    output logic [31:0] data_rdata_o,
    output logic        data_err_o,

    // Initialization interface (from rfuzz)
    input  logic        init_enable_i,
    input  logic [31:0] init_addr_i,
    input  logic [31:0] init_data_i
);

    // ============================================================
    // Instruction Memory
    // ============================================================
    logic [31:0] imem [IMEM_SIZE];
    logic [31:0] imem_addr_latched;
    logic        imem_req_latched;

    // 指令总线协议 FSM
    typedef enum logic [1:0] {
        IMEM_IDLE,
        IMEM_GRANTED,
        IMEM_VALID
    } imem_state_t;

    imem_state_t imem_state, imem_next_state;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            imem_state <= IMEM_IDLE;
        end else begin
            imem_state <= imem_next_state;
        end
    end

    always_comb begin
        imem_next_state = imem_state;
        instr_gnt_o = 1'b0;
        instr_rvalid_o = 1'b0;

        case (imem_state)
            IMEM_IDLE: begin
                if (instr_req_i) begin
                    instr_gnt_o = 1'b1;
                    imem_next_state = IMEM_GRANTED;
                end
            end

            IMEM_GRANTED: begin
                imem_next_state = IMEM_VALID;
            end

            IMEM_VALID: begin
                instr_rvalid_o = 1'b1;
                imem_next_state = IMEM_IDLE;
            end

            default: imem_next_state = IMEM_IDLE;
        endcase
    end

    // Latch address on grant
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            imem_addr_latched <= 32'h0;
        end else if (instr_gnt_o) begin
            imem_addr_latched <= instr_addr_i;
        end
    end

    // Return data on rvalid
    logic [31:0] imem_word_addr;
    assign imem_word_addr = imem_addr_latched[31:2];
    assign instr_rdata_o = (imem_word_addr < IMEM_SIZE) ? imem[imem_word_addr] : 32'h0000_0013; // NOP
    assign instr_err_o = 1'b0;  // 简化：不产生指令总线错误

    // ============================================================
    // Data Memory
    // ============================================================
    logic [31:0] dmem [DMEM_SIZE];
    logic [31:0] dmem_addr_latched;
    logic [31:0] dmem_wdata_latched;
    logic [3:0]  dmem_be_latched;
    logic        dmem_we_latched;

    // 数据总线协议 FSM
    typedef enum logic [1:0] {
        DMEM_IDLE,
        DMEM_GRANTED,
        DMEM_VALID
    } dmem_state_t;

    dmem_state_t dmem_state, dmem_next_state;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            dmem_state <= DMEM_IDLE;
        end else begin
            dmem_state <= dmem_next_state;
        end
    end

    always_comb begin
        dmem_next_state = dmem_state;
        data_gnt_o = 1'b0;
        data_rvalid_o = 1'b0;

        case (dmem_state)
            DMEM_IDLE: begin
                if (data_req_i) begin
                    data_gnt_o = 1'b1;
                    dmem_next_state = DMEM_GRANTED;
                end
            end

            DMEM_GRANTED: begin
                dmem_next_state = DMEM_VALID;
            end

            DMEM_VALID: begin
                data_rvalid_o = 1'b1;
                dmem_next_state = DMEM_IDLE;
            end

            default: dmem_next_state = DMEM_IDLE;
        endcase
    end

    // Latch transaction info on grant
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            dmem_addr_latched <= 32'h0;
            dmem_wdata_latched <= 32'h0;
            dmem_be_latched <= 4'h0;
            dmem_we_latched <= 1'b0;
        end else if (data_gnt_o) begin
            dmem_addr_latched <= data_addr_i;
            dmem_wdata_latched <= data_wdata_i;
            dmem_be_latched <= data_be_i;
            dmem_we_latched <= data_we_i;
        end
    end

    // Perform write on rvalid
    logic [31:0] dmem_word_addr;
    assign dmem_word_addr = dmem_addr_latched[31:2];

    always_ff @(posedge clk_i) begin
        if (data_rvalid_o && dmem_we_latched && (dmem_word_addr < DMEM_SIZE)) begin
            if (dmem_be_latched[0]) dmem[dmem_word_addr][7:0]   <= dmem_wdata_latched[7:0];
            if (dmem_be_latched[1]) dmem[dmem_word_addr][15:8]  <= dmem_wdata_latched[15:8];
            if (dmem_be_latched[2]) dmem[dmem_word_addr][23:16] <= dmem_wdata_latched[23:16];
            if (dmem_be_latched[3]) dmem[dmem_word_addr][31:24] <= dmem_wdata_latched[31:24];
        end
    end

    // Return read data on rvalid
    assign data_rdata_o = (dmem_word_addr < DMEM_SIZE) ? dmem[dmem_word_addr] : 32'h0;
    assign data_err_o = 1'b0;  // 简化：不产生数据总线错误

    // ============================================================
    // Initialization from rfuzz
    // ============================================================
    always_ff @(posedge clk_i) begin
        if (init_enable_i) begin
            if (init_addr_i[31] == 1'b0) begin
                // 指令存储器初始化（地址高位为0）
                if (init_addr_i[15:2] < IMEM_SIZE) begin
                    imem[init_addr_i[15:2]] <= init_data_i;
                end
            end else begin
                // 数据存储器初始化（地址高位为1）
                if (init_addr_i[15:2] < DMEM_SIZE) begin
                    dmem[init_addr_i[15:2]] <= init_data_i;
                end
            end
        end
    end

endmodule
"""
    return code


def generate_constraint_generators(constraints: dict[str, Any]) -> str:
    """生成约束输入生成器"""

    fetch_enable = constraints["metadata"]["special_constraints"]["fetch_enable"]
    interrupts = constraints["metadata"]["special_constraints"]["interrupts"]

    code = """// Copyright 2024 - Constraint Input Generators
// Auto-generated from extracted_constraints.yaml

module constraint_input_generators (
    input  logic        clk_i,
    input  logic        rst_ni,

    // rfuzz seed inputs
    input  logic [255:0] rfuzz_seed_i,

    // Constrained outputs to DUT
    output logic [31:0] hart_id_o,
    output logic [31:0] boot_addr_o,
    output logic [3:0]  fetch_enable_o,
    output logic        irq_software_o,
    output logic        irq_timer_o,
    output logic        irq_external_o,
    output logic [14:0] irq_fast_o,
    output logic        irq_nm_o,
    output logic        debug_req_o
);

    // ============================================================
    // fetch_enable: 固定使能（基于约束）
    // ============================================================
    // 约束: SecureIbex=0时只有bit[0]有效，应保持为1以持续运行
    assign fetch_enable_o = 4'b0001;

    // ============================================================
    // hart_id和boot_addr: 每次reset后固定
    // ============================================================
    logic [31:0] hart_id_latched;
    logic [31:0] boot_addr_latched;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            hart_id_latched <= rfuzz_seed_i[31:0];
            boot_addr_latched <= {rfuzz_seed_i[63:34], 2'b00};  // 4字节对齐
        end
    end

    assign hart_id_o = hart_id_latched;
    assign boot_addr_o = boot_addr_latched;

    // ============================================================
    // 中断: burst模式，避免每周期随机翻转
    // ============================================================
    logic [7:0] irq_counter;
    logic [7:0] irq_duration;
    logic [4:0] irq_select;
    logic       irq_active;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            irq_counter <= 8'h0;
            irq_duration <= rfuzz_seed_i[71:64];  // 持续周期数
            irq_select <= rfuzz_seed_i[76:72];    // 选择哪个中断
            irq_active <= 1'b0;
        end else begin
            if (irq_counter == 8'hFF) begin
                // 重新随机选择
                irq_duration <= rfuzz_seed_i[87:80] | 8'h08;  // 至少8个周期
                irq_select <= rfuzz_seed_i[92:88];
                irq_active <= rfuzz_seed_i[93];
                irq_counter <= 8'h0;
            end else begin
                irq_counter <= irq_counter + 8'h1;
                if (irq_counter >= irq_duration) begin
                    irq_active <= 1'b0;
                end
            end
        end
    end

    // 根据选择生成中断信号
    assign irq_software_o = irq_active && (irq_select == 5'd0);
    assign irq_timer_o    = irq_active && (irq_select == 5'd1);
    assign irq_external_o = irq_active && (irq_select == 5'd2);
    assign irq_fast_o     = irq_active ? (15'h1 << irq_select[3:0]) : 15'h0;
    assign irq_nm_o       = irq_active && (irq_select == 5'd31);

    // debug_req也使用类似的burst模式
    logic [7:0] debug_counter;
    logic       debug_active;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            debug_counter <= 8'h0;
            debug_active <= 1'b0;
        end else begin
            if (debug_counter == 8'hFF) begin
                debug_active <= rfuzz_seed_i[100];
                debug_counter <= 8'h0;
            end else begin
                debug_counter <= debug_counter + 8'h1;
                if (debug_counter >= 8'h10) begin
                    debug_active <= 1'b0;
                end
            end
        end
    end

    assign debug_req_o = debug_active;

endmodule
"""
    return code


def generate_main_harness(constraints: dict[str, Any]) -> str:
    """生成主harness"""

    code = """// Copyright 2024 - Constrained Harness for Ibex Core
// Auto-generated from extracted_constraints.yaml

module ibex_core_constrained_harness (
    input logic        clock,
    input logic        reset,
    input logic        io_meta_reset,

    // rfuzz接口
    input logic [4095:0] rfuzz_input_bits  // 扩展输入空间用于初始化memory
);

    localparam int RFUZZ_INPUT_BITS = 4096;
    localparam int RFUZZ_INPUT_BYTES = RFUZZ_INPUT_BITS / 8;

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    // ============================================================
    // 约束输入生成
    // ============================================================
    logic [31:0] constrained_hart_id;
    logic [31:0] constrained_boot_addr;
    logic [3:0]  constrained_fetch_enable;
    logic        constrained_irq_software;
    logic        constrained_irq_timer;
    logic        constrained_irq_external;
    logic [14:0] constrained_irq_fast;
    logic        constrained_irq_nm;
    logic        constrained_debug_req;

    constraint_input_generators gen_i (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .rfuzz_seed_i(rfuzz_input_bits[255:0]),
        .hart_id_o(constrained_hart_id),
        .boot_addr_o(constrained_boot_addr),
        .fetch_enable_o(constrained_fetch_enable),
        .irq_software_o(constrained_irq_software),
        .irq_timer_o(constrained_irq_timer),
        .irq_external_o(constrained_irq_external),
        .irq_fast_o(constrained_irq_fast),
        .irq_nm_o(constrained_irq_nm),
        .debug_req_o(constrained_debug_req)
    );

    // ============================================================
    // Memory Model (符合协议约束)
    // ============================================================
    logic        instr_req;
    logic        instr_gnt;
    logic        instr_rvalid;
    logic [31:0] instr_addr;
    logic [31:0] instr_rdata;
    logic        instr_err;

    logic        data_req;
    logic        data_gnt;
    logic        data_rvalid;
    logic        data_we;
    logic [3:0]  data_be;
    logic [31:0] data_addr;
    logic [31:0] data_wdata;
    logic [31:0] data_rdata;
    logic        data_err;

    // Memory初始化控制
    logic [7:0]  init_counter;
    logic        init_enable;
    logic [31:0] init_addr;
    logic [31:0] init_data;

    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            init_counter <= 8'h0;
            init_enable <= 1'b1;
        end else if (init_counter < 8'd64) begin
            init_counter <= init_counter + 8'h1;
            init_enable <= 1'b1;
        end else begin
            init_enable <= 1'b0;
        end
    end

    // 从rfuzz输入提取初始化数据
    assign init_addr = {24'h0, init_counter[5:0], 2'b00};
    assign init_data = rfuzz_input_bits[256 + init_counter*32 +: 32];

    constrained_memory_model #(
        .IMEM_SIZE(1024),
        .DMEM_SIZE(1024)
    ) mem_i (
        .clk_i(clock),
        .rst_ni(rst_ni),
        // Instruction interface
        .instr_req_i(instr_req),
        .instr_gnt_o(instr_gnt),
        .instr_rvalid_o(instr_rvalid),
        .instr_addr_i(instr_addr),
        .instr_rdata_o(instr_rdata),
        .instr_err_o(instr_err),
        // Data interface
        .data_req_i(data_req),
        .data_gnt_o(data_gnt),
        .data_rvalid_o(data_rvalid),
        .data_we_i(data_we),
        .data_be_i(data_be),
        .data_addr_i(data_addr),
        .data_wdata_i(data_wdata),
        .data_rdata_o(data_rdata),
        .data_err_o(data_err),
        // Initialization
        .init_enable_i(init_enable),
        .init_addr_i(init_addr),
        .init_data_i(init_data)
    );

    // ============================================================
    // Register File (简化实现)
    // ============================================================
    logic [4:0]  rf_raddr_a;
    logic [4:0]  rf_raddr_b;
    logic [4:0]  rf_waddr_wb;
    logic        rf_we_wb;
    logic [31:0] rf_wdata_wb;
    logic [31:0] rf_rdata_a;
    logic [31:0] rf_rdata_b;

    logic [31:0] rf_regs [32];

    // x0永远为0
    assign rf_regs[0] = 32'h0;

    // 写端口
    always_ff @(posedge clock) begin
        if (rf_we_wb && (rf_waddr_wb != 5'h0)) begin
            rf_regs[rf_waddr_wb] <= rf_wdata_wb;
        end
    end

    // 读端口
    assign rf_rdata_a = rf_regs[rf_raddr_a];
    assign rf_rdata_b = rf_regs[rf_raddr_b];

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

        .hart_id_i(constrained_hart_id),
        .boot_addr_i(constrained_boot_addr),

        // 指令总线 - 连接到memory model
        .instr_req_o(instr_req),
        .instr_gnt_i(instr_gnt),
        .instr_rvalid_i(instr_rvalid),
        .instr_addr_o(instr_addr),
        .instr_rdata_i(instr_rdata),
        .instr_err_i(instr_err),

        // 数据总线 - 连接到memory model
        .data_req_o(data_req),
        .data_gnt_i(data_gnt),
        .data_rvalid_i(data_rvalid),
        .data_we_o(data_we),
        .data_be_o(data_be),
        .data_addr_o(data_addr),
        .data_wdata_o(data_wdata),
        .data_rdata_i(data_rdata),
        .data_err_i(data_err),

        // 寄存器文件 - 连接到RF model
        .rf_raddr_a_o(rf_raddr_a),
        .rf_raddr_b_o(rf_raddr_b),
        .rf_waddr_wb_o(rf_waddr_wb),
        .rf_we_wb_o(rf_we_wb),
        .rf_wdata_wb_ecc_o(rf_wdata_wb),
        .rf_rdata_a_ecc_i(rf_rdata_a),
        .rf_rdata_b_ecc_i(rf_rdata_b),

        // I-cache接口 - 未使用，tieoff
        .ic_tag_req_o(),
        .ic_tag_write_o(),
        .ic_tag_addr_o(),
        .ic_tag_wdata_o(),
        .ic_tag_rdata_i('{default: '0}),
        .ic_data_req_o(),
        .ic_data_write_o(),
        .ic_data_addr_o(),
        .ic_data_wdata_o(),
        .ic_data_rdata_i('{default: '0}),
        .ic_scr_key_valid_i(1'b0),
        .ic_scr_key_req_o(),

        // 中断和调试 - 使用约束生成
        .irq_software_i(constrained_irq_software),
        .irq_timer_i(constrained_irq_timer),
        .irq_external_i(constrained_irq_external),
        .irq_fast_i(constrained_irq_fast),
        .irq_nm_i(constrained_irq_nm),
        .debug_req_i(constrained_debug_req),

        // 其他输出
        .crash_dump_o(),
        .double_fault_seen_o(),
        .alert_minor_o(),
        .alert_major_internal_o(),
        .alert_major_bus_o(),
        .core_sleep_o(),
        .scan_rst_ni(1'b1),
        .fetch_enable_i(constrained_fetch_enable),
        .dummy_instr_id_o(),
        .dummy_instr_wb_o()
    );

endmodule
"""
    return code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--constraints",
                       default="myfuzz/configs/designs/ibex_constrained/extracted_constraints.yaml")
    parser.add_argument("--output-dir",
                       default="myfuzz/runs/designs/ibex_constrained/harness")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    constraints_path = Path(args.constraints)
    if not constraints_path.exists():
        print(f"错误: 约束文件不存在: {constraints_path}")
        return 1

    print(f"读取约束文件: {constraints_path}")
    constraints = yaml.safe_load(constraints_path.read_text())

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 生成文件
    files = {
        "constrained_memory_model.sv": generate_memory_model(constraints),
        "constraint_generators.sv": generate_constraint_generators(constraints),
        "ibex_core_constrained_harness.sv": generate_main_harness(constraints)
    }

    for filename, content in files.items():
        filepath = output_dir / filename
        filepath.write_text(content)
        print(f"✓ 生成: {filepath}")

    print(f"\n代码生成完成！")
    print(f"输出目录: {output_dir}")
    print(f"生成文件数: {len(files)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
