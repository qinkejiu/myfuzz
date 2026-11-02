# round 1 通用化总结：CPU/IP/DMA 声明化与真实 RTL 批次（2026-11-02）

本文件按任务顺序汇总实际支持范围、真实运行结果、仍不支持的部分和性能影响。详细命令/逐行日志在各自的 `runs/` 目录和分项报告中；这里不重复长日志，也不把声明、单元测试或取指当作完整 RTL 通过。

## 支持矩阵（本轮之后）

| 轴 | 实际支持 | 真实证据 |
|---|---|---|
| CPU | Ibex OBI（RV32IMC）、PicoRV32 Wishbone、CVW AHB-Lite（F2–F4，无 F1/F5/F6）、CVA6 packed AXI4（F2–F4，无 F1/F5） | `runs/stage2-stepD2-*`、`runs/round1-multi-ip/`、`runs/round1-axi4-unified/` |
| 目标协议 | APB3、AXI4-Lite；同一会话内多个 APB3 目标按地址路由 | `runs/round1-multi-ip/`、`runs/round1-dma-b/` |
| 目标 IP | PULP Timer、GPIO、I2C、SPI（APB3）；ZipCPU AXI UART（AXI4-Lite） | 各分项报告 |
| DMA | ZipDMA Wishbone（block 1..8、字节使能、背压、FIFO 路由）、wbdmac（block 4、无 SEL） | `runs/round1-dma-a/`、`runs/round1-dma-b/` |
| F1 程序 | 直线 RV32IM、子字、计算地址、前向 B 型分支、packed C 安全 ALU 子集 | `runs/round1-f1-a/b/c/`、`runs/stage2-*subword*` |
| IRQ | pulse/level、触发/清除分开、cause 采样、单目标多 link、PULP I2C 真实 level+写清除、电平风暴检测 | `runs/round1-smoke/`、`runs/round1-irq-storm/` |

## 1. IRQ/F5

- 触发写与清除写分开计数；F5 判据同时要求两者等于声明值。
- cause 取自 ISR 的真实状态读（`status_cause_bits`→mask），不是声明直出。
- 单目标多 link：PULP Timer overflow/compare 两条 F5，同一进程 7/7 `observations_passed`；link0 status 0/count/16 tick，link1 status 8/compare/24 tick。
- PULP I2C 真实 level IRQ：`interrupt_o = irq_flag && s_ien`，`CMD[0]` iack；`STATUS[0]` cause。固定 3/3：`clear_writes 1`、`last_clear 0x14=1`、`isr_cause 1`、`irq_level_final 0`，后续 F2 无污染。
- PULP GPIO cause（读清状态）：3/3，`isr_cause 1`、`status_after_read 0`、引脚边沿与中断同 tick。
- 电平风暴：错误 clear 时 `irq_takes > 4` 且电平仍高 → `level_stuck`、停止该 case、只复位设备并等待 handler 清命令字。`runs/round1-irq-storm/stuck` 现在 2 例（case0 failed/level_stuck 1/device_resets 1，case1 F2 passed），不是 0 例；正确 I2C 3/3、multilink 7/7 不变。
- 仍不支持：一个 CPU 只允许一个 F5 目标（一根 IRQ 线）；level 源必须可清除；没有 NMI/PLIC/多 bit 向量/active-low；没有覆盖率/证书/replay。

## 2. 完整 AXI4（CVA6）

- 统一入口新增 `axi4` 分支，复用 `axi4_processor_memory_adapter`；固定 F2/F3/F4 **3/3**、fuzz **30/30**。
- 真实计数：77 AR/77 R（68 取指/9 数据）、11 AW/W/B、88/88 beat req/rsp、0 beat error；boot 0x10000 tick 251、firmware 0x11000 tick 335。
- 退休接口不可用：归档未导出 RVFI/commit，`retirement_evidence missing`；F1 拒绝 `unsupported-f1:no-retirement-observation:cva6_packed_axi4`，F5 拒绝 `unsupported-f5:no-retirement-or-trap-witness:cva6_packed_axi4`。取指没有冒充退休。
- 指令缓存边界：程序槽 0x12000 位于 execute 但非 cached 的 0x10000..0x20000；同槽改写会重取，不声称处理 cached 一致性/fence.i。cached 区只有 0x8000_0000..0xC000_0000。
- 仍不支持：单 outstanding、ARLEN≤1 INCR、IP beat 必须一个完整 32 位字、合并 64 位 IP store 按名拒绝、无 F1/F5/F6、无其他 CVA6 配置。

## 3. 一个 CPU 访问多个 MMIO IP

- `targets[]` 声明 + `declared_targets`/`target_windows`/`route_address`/`target_for_f5`；入口每目标独立 artifact、header `IP_COUNT`/`IpTarget<n>` trait，宿主按窗口路由、每目标计数、所有模型同 tick。
- Ibex + PULP Timer（0x40001000，F5）+ PULP I2C（0x40002000）：固定 **6/6**；每例另一目标 reads/writes 为 0，F5 `isr_read_addr 0x40001000`。
- fuzz 30（seed 5）：27 通过 + 3 个 F5 `not_triggered`，0 finding，无跨目标读写。
- 换 IP：交换 target0/target1 后 5/5，F5 `irq_base`/`isr_read_addr` 变为 0x40002000，宿主源码无 timer/i2c 分支。
- 仍不支持：混合目标协议（APB3+AXI4-Lite 按名拒绝）；一个 F5 目标；多目标 pin 模型；两个 AXI4-Lite 目标未跑。

## 4. DMA

- 第一增量：planner 接入；ZipDMA block **1..8**（len8 1/1、1..8 sweep 8/8、fuzz 30/30）、设备 size-derived 字节使能（1-byte size：`dma_lane_masks 0x8421`、`dma_sel_partial 16`、guard 不变）、2-tick 背压（`dma_delayed_acks 8`、`dma_wait_min 3`/max 4、`dma_delay_evidence observed`）、wbdmac F6 回归。
- 第二增量：ZipDMA 真实写 PULP SPI TXFIFO。固定路由 `0x20002018`、8 字、目的不递增；`dma_route_writes/acks/target_writes 8/8/8`、`dma_ram_writes 0`、`fifo_status 0x1→0x08000001`、`tx_fifo_level 0→8`、`dma_route_expected_level 8`。flows 6/6、fuzz 26/30（4 个 F5 正常未触发）；负控制 expected level 4 时 F6 failed（8/8 ack 仍发生），证明判据是 readback 不是 ack。
- 仍不支持：单 outstanding；固定目的地址、只写路由、APB3+OBI、全字；非递增未跑；错误注入、多通道/不同宽度、DMA 读路由未实现；SPI 串行引擎/外部 peer 未验证，只声称 FIFO occupancy。

## 5. RISC-V 程序变异

- 地址计算：`f1_allow_address_forms`；固定 2/2（含 16 字全模板程序）、fuzz 20/20 真实生成；C++ 静态 provenance 与 Python 一致，越界/未证明/绝对 ANDI 按名拒绝。
- 前向分支：`f1_allow_branches`；4 字程序退休 3 条（跳过 1 条）、`prog_trace_hash 0xd2403c87` 与 Python 一致；fuzz 20/20（15 例合法少退休）；错误 trace 会使批次 failed。
- 压缩：`f1_allow_compressed`；4 record word/8 parcel 退休 8 条（不是 4 字）、`prog_trace_hash 0xe232c69e` 与 Python 一致、PC 步进 2/4；fuzz 20/20 真实生成；mixed 32-bit+parcel 1/1。
- 仍不支持：只允许严格前向 B 型（无 JAL/JALR/循环/backward）；压缩只允许安全 ALU 子集（rd/rs2 x12..x15），compressed memory/control/FP/SP 按名拒绝；RV64/特权/CSR 没有可验证目标，拒绝且未生成。

## 测试、性能、资源

- Required suite：`tests/fuzz` + `test_inprocess_behavior.py` + `test_multi_target.py` + `test_dma_transfer.py` + `test_inprocess_f1f6_entry.py` → **1310 passed**（storm 修复后）。
- 代表性最终回归（本机、真实 RTL）：AXI4 3/3、multi-IP 6/6、DMA FIFO 1/1、F1 compressed 1/1，均 `observations_passed`；见 `runs/final-verify/`。
- 性能：AXI4 host 1–3 ms/case，wall ~18 s（adapter Verilate/link 为主）；multi-IP fixed 6.35 s（host 5.4 ms）、fuzz-30 12.5 s（host 26 ms）；DMA-A/B ~5.6–6.2 s（host 5–33 ms）；F1 fixed ~5.6–12.7 s（host 5 ms）、fuzz-20 ~6.5 s；IRQ 批次 11–13 s。准备/链接仍占主要时间。
- 资源：工作区保留的 CVA6 cache ~474 MB、DMA-B cache ~1.6 GB、I2C cache ~184 MB；本机 7 GB RAM 下未出现 OOM。未做远程测试。
- 没有 reset/clean；其他人的未提交内容保留。临时 `.tmp-hdr*` 已清理；证据目录保留。

## 明确不声称

- 没有 RTL 覆盖率、完整证书、独立 replay、跨 seed 可复现性认证。
- 没有把声明、单元测试或取指当作完整 RTL 通过；每个数字对应 `runs/` 里的 case 行/summary。
- 没有混合协议多目标、DMA 读路由、多 outstanding、RV64/特权、compressed memory/control、任意分支/循环。
