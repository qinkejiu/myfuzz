# round 2：CVA6 RVFI/F1、F1 控制流、DMA 读路由与多 F5 目标（2026-11-02）

本文件汇总本轮四个真实 RTL 增量，以及仍未实现的部分。每个结论都对应
`runs/` 里保存的 case 行和 summary；本文件不把声明、单元测试或取指当作执行
通过，也不声称覆盖率、证书或独立 replay。

## 支持矩阵（本轮之后）

| 轴 | 本轮新增 | 真实证据 |
|---|---|---|
| CVA6 packed AXI4 | 6974 bit RVFI probe bundle 导出 + pinned `cva6_rvfi` scoreboard 并行 Verilate；F1 三例（1/2/4 字）+ F2–F4 三例共 6/6、F1 fuzz 20/20；F2–F4 fuzz 8/8 | `runs/round1-cva6-rvfi/`、`runs/final-verify-round2b/cva6-f1/` |
| RV32 F1 控制流 | JAL/JALR 固定 2/2 + fuzz 20/20；canonical 有界循环固定 1/1 + fuzz 20/20；压缩控制固定 3/3 + fuzz 20/20；压缩访存固定 2/2 + fuzz 20/20 | `runs/round1-f1-controlflow/`、`runs/final-verify-round2b/f1-*` |
| DMA | Wishbone 读 beat → APB3 目标读 → RAM（IP→RAM）；`dma_ram_reads 0`；固定 2/2、flows 5/5、fuzz 10/10 | `runs/round1-dma-read/`、`runs/final-verify-round2b/dma-read/` |
| F5 / IRQ | 同一会话两个 APB3 目标都声明 F5；两路真实 IRQ 相或进 CPU 一根输入；每例按 global link 选择目标；固定 10/10 | `runs/round1-multi-f5/`、`runs/final-verify-round2b/multi-f5/` |

## 1. CVA6：真实退休观察与 F1

**做了什么。** CVA6 profile 的 `rvfi_probes_o` 从 `unconnected` 改为 `observe`，
生成模型导出完整 6974 bit probe bundle。`core/cva6_rvfi.sv` 不在 pinned
`Flist.cva6` 中，因此作为**独立 Verilated 模型**（`scripts/inprocess_cva6_rvfi_build.py`
+ `src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv`）与 CPU 模型并排链接，在 AXI4
link 的同一上升沿采样 probe，输出每拍一条的 RVFI face。host 的
`cpu_retirement` 在 AXI4 构建里指向这个 scoreboard，不是 CPU 的取指或
`instruction[0]`。

**真实结果。**

- 固定 6 例 `runs/final-verify-round2b/cva6-f1`：F1 4 字、F1 2 字、F1 1 字、
  F2、F3、F4 全部 `observations_passed`；`rvfi_retire_dropped 0`，
  `retirement_evidence observed`，summary 为
  `retirement_observation rvfi:cva6_rvfi_probes`、`rvfi_bundle_width 6974`、
  `rvfi_scoreboard cva6_rvfi`、`rvfi_projection low32_of_rv64`。
- 4 字 F1 的 4 条退休：`pc=0x12000 insn=0x2ab00693 rd=13 wdata=0x2ab`、
  `pc=0x12004 insn=0x29d1f0b7 rd=1 wdata=0x29d1f000`、
  `pc=0x12008 insn=0x00b5f5b3 rd=11 wdata=0`、
  `pc=0x1200c insn=0x00192023 rd=0 wdata=0`；`prog_insns_match 1`、
  `prog_pc_ordered 1`、`successor_pc 0x12010`。
- F1 fuzz：20 例全部通过，`retirements 327`、`rvfi_writebacks 178`、
  `rvfi_retire_dropped 0`（`runs/round1-cva6-rvfi/f1-fuzz`）。
- F2–F4 回归：固定 3/3（`runs/final-verify-round2b/axi4-f2f4`），fuzz 8/8
  （`runs/round1-cva6-rvfi/fuzz-f2f4`）。

**边界。** 只执行 RV32IM 编码，CVA6 的 64 bit 记录取低 32 bit 与 RV32 参考
trace 比较；scenario 明确声明 `f1_rv32_projection: true`，没有该声明的 xlen 64
仍被 gate 拒绝。没有 RV64 指令、CSR、特权态、F1 压缩/分支/跳转；F5 仍按名拒绝
（AXI4 host 把 `irq_i` 拉低，没有中断交付）；F6 未接。scoreboard 是 local-harness
新增 RTL，不属于 pinned closure，报告和 summary 明写了这一点。

## 2. RV32 F1 控制流

**做了什么。** `rv32_program.py` 增加 whole-image 控制流解析：JAL/JALR 的静态
目标（JALR base 必须是 x0 或程序可证明的常量）、canonical 有界循环
（`addi xN,x0,K` / body 不写 xN / `addi xN,xN,-1` / `bne xN,x0,head`，K=2..6）、
循环区间互不重叠、不得从循环内部进入。`rv32_compressed.py` 增加
C.J/C.JAL/C.JR/C.JALR/C.BEQZ/C.BNEZ 与 C.LW/C.SW/C.LWSP/C.SWSP（静态 proven
目标/地址）。host 增加 JAL/JALR/循环/压缩控制/压缩访存门禁与 `prog_pc_repeat`；
循环模式不再要求 PC 严格上升，而是把**完整退休 trace**（count + FNV-1a hash）
与 Python 参考比较；`prog_pc_order` 仍如实报告。

**真实结果（`runs/round1-f1-controlflow/` 与 `runs/final-verify-round2b/`）。**

| 形状 | 固定 | fuzz 20 | 关键 case 事实 |
|---|---|---|---|
| JAL/JALR | 2/2 | 20/20 | JAL `prog_trace_hash 0x20cee9b7`、`prog_retires 3`；JALR `0x1bb7b41c`、`prog_retires 4`；link 寄存器 x1 的 pc+4 写回在 trace 里 |
| canonical 循环 | 1/1 | 20/20 | `prog_retires 13`、`prog_trace_hash 0x030a0aaf`、`prog_pc_repeat 2`、`prog_pc_ordered 0`（如实报告） |
| 压缩控制 | 3/3 | 20/20 | 6 个 parcel 退休、trace hash 与 Python 一致；`prog_pc_repeat 0` |
| 压缩访存 | 2/2 | 20/20 | C.LW/C.SW 的地址与数据窗口变化由 host 观察 |

所有 fuzz 批次的 `summary` 都是 `observations_passed`，`failures 0`；每个 case
的 `prog_trace_count`/`prog_trace_hash` 与参考 trace 对齐。

**边界。** 仍不支持任意/数据相关循环、嵌套/交叠循环、backward JAL/JALR、任意
基址 JALR、压缩 FP/SP/system、C.LD/C.SD（RV32 rv32imc 没有 D）、RV64/CSR/特权。
循环必须可静态证明终止；不是“任意程序 fuzz”。

## 3. DMA：IP→RAM 读路由

**做了什么。** ZipDMA 的 Wishbone master 发读 beat（`we=0`）时，host 把声明的
固定源地址送到目标自己的 APB3 读端口（`PWRITE=0`），等 `PREADY`，捕获
`PRDATA` 后在 `mwb_dat_r` 上回 ACK；DMA 再把该字写入递增的 RAM 目的块。RAM
源窗口对该 beat 从未被读取。planner 的 route evidence 改为方向相关；read 需要
固定源、递增 RAM 目的、可读寄存器，证据必须是 routed register 自己的
`register_readback`；FIFO read/aperture 按名拒绝。

**真实结果（`runs/round1-dma-read/`）。**

- 固定链 `read-fixed` 2/2：F4 写 PULP I2C `PRESCALER`（`0x20001000`）为
  `0x00005a5a`；F6 读回同一字，写满 4 个 RAM 目的字。
- case 行：`dma_route_direction read`、`dma_route_source 0x20001000`、
  `dma_route_reads/acks/target_reads 4/4/4`、
  `dma_route_read_value 0x00005a5a`、`stable 4`、`read_matched 4`、
  `cpu_matched 4`、`dma_ram_reads 0`、`dma_ram_writes 4`、
  `dst0..3 0x00005a5a`、`dma_route_cpu_dst0..3 0x00005a5a`。
- `read-twice` 3/3（第二次仍读到 `0x5a5a`）、`read-flows` 5/5（F2/F4/F5/F6/F2）、
  fuzz 10/10（两个 F6 都读 `0x5a5a`）。
- 回归：FIFO 写路由 1/1、RAM→RAM 8 字 1/1、字节使能 1/1、2 tick 延迟 1/1、
  timer+ZipDMA F1–F6 6/6、双 IP F1–F6 6/6。

**为什么 I2C 在 `0x20001000`。** pinned ZipDMA 的 SOURCE/DESTINATION 是 30 bit
byte address，`0x40002000` 会被截断；planner 对 `>=0x40000000` 的 route 按名拒绝
（`dma-route-target-unreachable`），所以该场景把 I2C 映射到 1 GiB 以下。这是设备
事实，不是宿主造值。

**边界。** 单 outstanding；无错误注入（`mwb_err` 拉低）；无 FIFO read、无
aperture/incrementing read、无 AXI4-Lite/非 OBI route、无多通道/不同宽度/
多 outstanding；fuzz 不检查前置 F4 值（generator 可能写 32 bit 被 16 bit
PRESCALER 截断），但 route 自身证据仍检查。

## 4. F5：同会话两个 IRQ 目标

**做了什么。** `targets_for_f5` 返回所有声明完整 F5 事实的目标；entry 把所有
目标的 link 编成一张 global table，每个 link 带 `target_index`/base/status/
trigger/clear。host 对每个声明目标的真实 IRQ 输出逐 tick 采样并**相或**进 CPU
的一根外部 IRQ 输入；F5 record 的第一个字选择 global link，ISR 读/写该 link
自己的目标窗口。原有 `target_for_f5` 保留单目标拒绝语义。

**真实结果（`runs/round1-multi-f5/fixed-multif5/`，10/10）。**

- timer link 0：`irq_link_target 0`、`isr_read_addr 0x40001000`、kind `count`、
  `isr_result 0`、`clear_writes 0`、`irq_takes 1`、另一目标 0/0。
- I2C link 1：`irq_link_target 1`、`isr_read_addr 0x4000200c`、kind `status`、
  `isr_result 0x81`、`isr_cause 0x1`、`clear_writes 1`（`0x14=1`）、
  `irq_takes 1`、另一目标 0/0。
- summary：`ip_count 2`、`irq_sources 3`、`irq_target_links 2`、
  `irq_link_targets 0:0,1:1`、`target0_irq delivered`/`target1_irq delivered`、
  `target0_f5 yes`/`target1_f5 yes`、`level_stuck 0`、`device_resets 0`。
- 回归：单目标 multilink 7/7、I2C level 3/3、双 IP F1–F6 6/6、AXI4 F2–F4 3/3、
  no-F5 拒绝 2/2。

**边界。** 同时两源只证明“相或交付”，不证明归因：一个 F5 record 只选一个 link，
ISR 只有一组 status/result/clear cell；负控制
`runs/round1-multi-f5/negative-unselected-assert2` 里未选中的 I2C 也能把 CPU
拉进 handler（`irq_takes 5`），但 case 如实失败为 `level_stuck 1`，没有冒充
归因。NMI、PLIC、多 bit 向量、更多极性/清除方式仍未实现；多目标 pin 模型、
混合 APB3/AXI4-Lite、link 触发字数不一致仍按名拒绝。

## 测试、性能与资源

- 本轮 required suite（含新增 CVA6 RVFI 与 F1 控制流测试）：**1375 passed**。
- 最终代表回归 `runs/final-verify-round2b/`：CVA6 F1+F2–F4 6/6、F1 JAL/JALR 2/2、
  F1 循环 1/1、F1 压缩控制 3/3、DMA read 2/2、multi-F5 10/10、AXI4 F2–F4 3/3、
  双 IP 6/6、DMA FIFO 写 1/1，全部 `observations_passed`。
- 性能：CVA6 F1+F2–F4 22 s（host 0.019 s，per-case 0.6–6.8 ms）；F1 控制流
  固定/20 例 fuzz 5–13 s；DMA read 固定 2 例 13 s（host 5.5 ms）；multi-F5 10 例
  12 s（host 6.6 ms）。准备/Verilator/link 仍占主导。
- 未做 reset/clean；未删除任何已有 runs/docs；未做远程测试。

## 明确不声称

- 没有 RTL 覆盖率、完整证书、独立 replay、跨 seed 可复现性认证。
- CVA6 的 F1 是 RV32IM 在 RV64 核上的低 32 bit 投影，不是 RV64 指令执行。
- CVW/AHB 仍无 RVFI 退休观察和 IRQ 输入，F5/F6 仍拒绝；Wishbone/TL-UL/AHB
  目标适配仍未并入统一循环；混合 APB3+AXI4-Lite 多目标仍拒绝；DMA
  multi-outstanding/error injection/FIFO read/多通道仍拒绝；F5 的 NMI/PLIC/
  多 bit 向量仍拒绝；RV64/CSR/特权仍拒绝。
