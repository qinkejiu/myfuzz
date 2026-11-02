# 通用化进度（2026-11-02 凌晨，round 1）

本文件只记录当前树、真实命令和已保存证据；不把声明、单元测试或探针结果当作统一循环的通过。

## 已完成并有真实 RTL 证据

### 1. IRQ/F5 通用化

- 触发写与清除写分开计数，F5 判据同时要求两者与声明一致。
- `status_cause_bits` 从 ISR 的真实状态读采样；case 行 `isr_cause` 不再由声明直接生成。
- 单目标多 IRQ 源（v2 `irq_sources`）：PULP timer 的 `irq_o[0]` overflow 与 `irq_o[1]` compare 在同一进程、同一 CPU 上各跑一例，状态字/kind/交付宽度都按 link 变化。
- level 源必须声明 clear 写或 `read_clears` 状态；case 末采样每个 level link 的原始输出，持高则失败并只复位 IP/DMA，不静默屏蔽。
- cause 真实例：PULP GPIO `INTSTATUS` 读清 + `status_cause_bits:[0]`，`isr_cause 0x1`、`status_after_read 0`、`irq_cause_pins 1`。

证据：

- `runs/round1-smoke/multilink/`：7/7 `observations_passed`，两条 F5（link0 count/16，link1 compare/24）。
- `runs/round1-smoke/gpio-cause/`：3/3，F5 cause=1；F4 先写 PADDIR=1。
- I2C level + 写清除：`runs/round1-smoke/i2c-level` 3/3，两条 F5 都 `clear_writes 1`、`irq_level_final 0`、`isr_cause 1`；负控制（故意不清除）已修复：`irq_takes > 4` 且电平仍高时记录 `level_stuck`、停止该 case、只复位设备；stuck 批次 2 例（1 failed + 1 F2 passed），不再 0 例，见 `runs/round1-irq-storm/`。
- 报告：`docs/reports/irq-generalization-20261102.md`。
- 测试：`PYTHONPATH=src:. python3 -m pytest tests/fuzz tests/composition/test_inprocess_behavior.py tests/integration/test_inprocess_f1f6_entry.py -q` → 964 passed；加入多 IP/DMA 模块与入口测试后 required suite 为 1178 passed（见各节）。

### 2. F1 程序空间——地址计算已接入，分支/压缩待接入

- **地址计算已接入**：`f1_allow_address_forms` gate/header/C++ 静态 provenance 已落地；固定 2/2（含 16-word 地址程序）与 fuzz-20 20/20 真实 Ibex 批次；证据 `runs/round1-f1-a/`。
- `src/myfuzz/fuzz/rv32_program.py` 已有前向 B 型分支、PC 解释器/退休 trace、分支感知分析；`rv32_compressed.py` 有 packed compressed 子集、2/4 字节 PC 推进和 reference model。
- **前向分支已接入**：`f1_allow_branches`、C++ B 型目标门、固定 4 字程序真实退休 3 条（跳过一条）、`prog_trace_hash 0xd2403c87` 与 Python 参考一致；fuzz-20 20/20（真实生成 branch 形状，15 例合法少退休）；`apply_correspondence` 现在会把错误 trace 的批次判 failed；required suite 1248 passed；回归 AXI4 3/3、multi-IP 6/6、DMA len8/FIFO 1/1、IRQ multilink 7/7；证据 `runs/round1-f1-b/`。
- **压缩指令已接入**：`f1_allow_compressed`、C++ two-parcel 安全子集（rd/rs2 x12..x15）、PC 2/4 步进、parcel/word 比较与 trace hash；固定 4 record word/8 parcel 真实退休 8 条（不是 4 字），`prog_trace_hash 0xe232c69e` 与 Python 参考一致；fuzz-20 20/20 真实生成 compressed；回归 address/branch/AXI4/multi-IP/DMA/IRQ 全过；required suite 1309 passed；证据 `runs/round1-f1-c/`。压缩 control/memory/FP/SP 仍按名拒绝。
- RV64/特权：仍拒绝/不生成；当前 per-signal RVFI 目标只有 RV32，故没有可验证的真实批次。

### 3. 完整 AXI4（CVA6）接入——已通过 F2–F4

- 真实探针 `runs/round1-axi4/` 与统一入口 `runs/round1-axi4-unified/` 都跑通真实 CVA6 + `axi4_processor_memory_adapter`。
- 固定 F2/F3/F4：3/3 `observations_passed`，`runs/round1-axi4-unified/fixed-f2f4`；boot fetch 0x10000 tick 251（ARID 0），firmware fetch 0x11000 tick 335，77 AR/77 R（68/9 instruction/data）、11 AW/W/B、88/88 beat req/rsp。
- 连续 fuzz 30/30（F2 18/F3 7/F4 5），`runs/round1-axi4-unified/fuzz-30`。
- 无 RVFI：`retirement_evidence missing`，F1 拒绝 `unsupported-f1:no-retirement-observation:cva6_packed_axi4`；F5 拒绝 `unsupported-f5:no-retirement-or-trap-witness:cva6_packed_axi4`。
- 早期停顿根因：adapter beat 的 `req_ready_i` 在捕获 tick 的上升沿前被撤销，适配器停在 READ_REQUEST。修复见 `scripts/inprocess_axi4_host.h`/宿主。
- 限制：单 outstanding、IP beat 必须一个完整 32 位字、64→32 拆分、cached 槽不声称一致性（槽在 0x12000 非 cached 区）。

### 4. 多 IP——已通过两个真实 APB3 IP

- `configs/scenarios/inprocess-obi-apb-two-ip-timer-i2c-f1f6.json`：Ibex OBI 同时按地址访问 PULP timer（0x40001000，唯一 F5 目标）和 PULP I2C（0x40002000，fixed scl/sda=1），ZipDMA 控制 0x40003000，RAM 0x10000..0x30000。
- 固定 6/6：F2/F4 分别命中 target0/target1，F5 只从 timer 交付，F3 为 RAM（target_index -1）；每例另一目标 reads/writes 为 0，F5 `isr_read_addr 0x40001000`。
- 连续 fuzz 30 例（seed 5）：27 通过，3 个 F5 `not_triggered`（随机值未触发 timer），0 finding；F1 7/F2 8/F3 2/F4 4/F5 6/F6 3；无跨目标读写。
- 换 IP：交换 target0/target1 后 5/5，F5 `irq_base`/`isr_read_addr` 变为 0x40002000，CPU×IP 代码未改。
- 回归：AXI4 3/3、IRQ multilink 7/7、GPIO cause 3/3、旧单目标 F1–F4 4/4；required tests 1123 passed。
- 证据：`runs/round1-multi-ip/`（README/fixed/fuzz-30/swapped/regressions）。
- 限制：同一目标协议（当前 APB3 对；混合 APB3+AXI4 按名拒绝）；只允许一个 F5 目标；多目标 pin 模型拒绝；一个 host tick 驱动所有模型。

### 5. DMA——第一增量已通过

- `src/myfuzz/composition/dma_transfer.py`（42 tests）已接入入口；ZipDMA block 1..8 真实搬运（len8 1/1、block 1..8 sweep 8/8、fuzz 30/30）、设备自己的 1-byte size 字节使能（`dma_lane_masks 0x8421`、`dma_sel_partial 16`、guard 不变）、2-tick 背压（`dma_delayed_acks 8`、`dma_wait_min 3`）、wbdmac F6 回归、AXI4 3/3、multi-IP 6/6。
- 证据：`runs/round1-dma-a/`、`docs/reports/round1-dma-a-20261102.md`；required suite 1178 passed；旧单目标 inline F5 被 target 归一化丢弃的 bug 已在本轮修复（zipdma-block4 F5 恢复通过）。
- **DMA→IP FIFO 已跑通（同一轮稍后）**：`configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-fifo-f1f6.json`（timer + PULP SPI at 0x20002000）固定 1/1：`dma_route_enabled 1`、`dma_route_target_index 1`、`dma_route_destination 0x20002018`、`dma_route_writes 8`、`dma_route_acks 8`、`dma_route_target_writes 8`、`dma_ram_writes 0`、`fifo_status_before 0x1` → `fifo_status_after 0x08000001`、`tx_fifo_level 0→8`、`dma_route_expected_level 8`。6 例 flows 全过；fuzz 30 中 26 通过、4 个 F5 正常未触发；负控制把 expected level 写成 4（实际 8）时 F6 失败，证明判据不是只看 ack。证据：`runs/round1-dma-b/`。
- 证据：`runs/round1-dma-b/`（README + fifo-fixed/flows/fuzz-30/negative-depth/refusals/regressions）；required suite 1096（DMA-B 运行时的集合）。
- 仍未实现/未跑：单 outstanding；非递增搬运；主机强制 lane mask；错误注入；FIFO 的读方向/多通道/不同宽度。

## 真实缓存与工具

- `runs/stage2-stepD2-cache`：Ibex + PULP timer + ZipDMA（IRQ 批次使用）。
- `runs/stage2-unified-gpio-20261101/cache`：Ibex + PULP GPIO cause 批次使用。
- `runs/round1-cva6-cache/8f5f…`：当前树重建的 CVA6 模型（artifact `7411ff18…`）；`runs/round1-axi4/build/adapter-cva6`：adapter。
- Verilator 5.051，32 核 / 7 GB RAM。CVA6 模型重建约 16 s（8 job），adapter 约 1 s；整机耗时以准备/链接为主。

## 不声称

- 未跑通 AXI4 统一 F2–F4；未跑多 IP / DMA 扩展 / 新 F1 程序形状的真实 RTL。
- 没有覆盖率、证书、完整 replay；`configs/behaviors` 只描述声明，因果仍以 case 行真实读/边沿/引脚为准。
