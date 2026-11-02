# 报告与证据导航

这里按专题定位报告；最新状态统一查[当前进度](../CURRENT_PROGRESS.md)，组件与路径边界以[当前能力盘点](../current-system-capabilities-20261101.md)的「2026-11-02 增量」为准。每份报告的结论只适用于其声明的源码、输入和运行范围。

## 常用专题

| 范围 | 入口 |
|---|---|
| 六 CPU / 四 IP 与 DMA | [逐组件状态审计](dma-six-cpu-four-ip-status-20261022.md) |
| **P0-2 CPU-only**：单 Ibex 模型 + RAM，无目标 IP/DMA；固定 5/5、fuzz 16/16；声明 fault 触发 Ibex 真实 `PendingAccessTrackingCorrect`/`NoMemResponseWithoutPendingAccess`，源文件/行/case 留存；超时归 environment | [P0-2 报告](p0-cpu-only-ibex-20261102.md)、[证据](../../runs/p0-cpu-only/README.md) |
| Compiled F2 / F4 | [有界执行与兼容门](f2-f4-current-acceptance-20261023.md)、[F2 RFuzz 入口](compiled-f2-rfuzz-entry-20261023.md) |
| Compiled F6 | [跨组件边及取指证据](f6-cross-component-edges-20261025.md)、[Wishbone DMA checker](f6-wbdmac-dual-endpoint-checker-20261025.md) |
| 同协议接入 | [通用接入缺口](generic-protocol-onboarding-gap-20261025.md)、[G7 新 APB storage source](generic-runtime-g7-gpio-20261026.md)、[G8.1a Wishbone 第一片](generic-runtime-g8_1a-wishbone-20261026.md)、[G8.1c Wishbone routed storage/producer](generic-runtime-g8_1c-wishbone-20261026.md)、[G8.1 Wishbone storage 行真实通过](generic-runtime-g8_1-wishbone-20261026.md) |
| P7 / P8 | [已记录真实门及边界](p7-p8-real-gates-20261018.md)、[P7 I5 候选](p7-i5-candidate-20261018.md) |
| 定向 IRQ 与原生就绪 | [reset/exception/multi-source/cross-protocol 软件门与原生脚本](directed-irq-native-validation-20261030.md) |
| Native source completion | [r11 检查点](codex-progress-status-20261023.md) |
| P1–P5 与旧运行 | [阶段复现手册](../reproduction/first-step-p1-p5-20261008.md)、[历史结果表](../history/experiments/ALL_TEST_RESULTS_MASTER.md) |
| 文件与分支整理 | [2026-10-25/26 处置与验证](source-docs-branch-cleanup-20261025.md)、[目录地图](../WORKSPACE_MAP.md) |

## 2026-10-30 通用化续接

| 范围 | 入口 |
|---|---|
| CV32E40P 六 flow F1–F6（真实 ack/id/entry-PC、pc/insn/order-only F5/F6） | [六 flow 验收](cv32e40p-six-flow-f5-f6-20261030.md) |
| 声明式 IRQ → 完整 F5（Wishbone/APB/AHB 三 target） | [F5 验收](declared-irq-f5-acceptance-20261030.md) |
| 声明式 F5 扩展到 pc/insn/order-only CPU（CV32E40P） | [有限 CPU F5](declared-irq-f5-limited-cpu-20261030.md) |
| 复位屏障、多源 IRQ、异常与跨协议定向原生 | [定向原生用例](directed-irq-native-cases-20261030.md)、[reset 记录](irq-reset-lineage-20261030.md)、[多源记录](irq-group-multisource-20261030.md)、[软件门与脚本](directed-irq-native-validation-20261030.md) |
| 新路径覆盖率与可比性 | [覆盖率](new-path-coverage-20261030.md)、[固定契约](coverage-comparison-contract-20261030.md)、[fresh 前缀与外部契约](coverage-fresh-prefix-and-external-contract-20261030.md) |
| 宿主开销优化与同工作量 A/B | [优化记录](host-overhead-reduction-20261030.md)、[轻量 A/B](journal-cache-campaign-ab-20261030.md)、[开销分解](host-overhead-profile-20261030.md) |

## 2026-11-01 闭环与性能

| 范围 | 入口 |
|---|---|
| 统一入口闭环变异、F1 短程序、超时恢复与行为声明的真实批次 | [闭环证据](../../runs/stage2-fuzz-loop-20261101/README.md)、[使用方法](../inprocess-fuzz-loop.md) |
| 200 例 fuzz 的准备/会话/DUT 分项与事件层 A/B | [闭环性能报告](fuzz-loop-performance-20261101.md) |
| 误报修正、失败分类与超时恢复 | [修正证据](../../runs/stage2-task1-fix-20261101/README.md) |
| 长跑内存边界与 soak | [长跑报告](fuzz-longrun-20261101.md)、[原始证据](../../runs/fuzz-soak-20261101/README.md) |
| 新同协议 IP 接入（PULP I2C） | [I2C 接入](new-ip-onboarding-20261101.md)、[证据](../../runs/stage2-fuzz-newip-20261101/README.md) |
| 输入前缀与失败复现 | [前缀重放证据](../../runs/stage2-prefix-replay-20261101/README.md) |
| Wishbone CPU 连续 F1–F6（预算根因、IRQ/DMA、换 IP） | [Wishbone 报告](wishbone-f1f6-continuous-20261101.md)、[原始证据](../../runs/stage2-wb-six-20261101/README.md) |
| 合并后统一批量验收与分项性能 | [批量验收](../../runs/stage2-acceptance-20261101/README.md) |
| CVW AHB-Lite CPU F2–F4 接入统一入口 | [AHB 接入](inprocess-ahb-unified-20261101.md)、[证据](../../runs/stage2-ahb-unified-20261101/README.md) |
| 完整 AXI4 CPU（CVA6）原生探针、缓存与身份 | [AXI4 分析](inprocess-axi4-cpu-analysis-20261101.md) |
| 第二台同协议 IP（PULP SPI 进入 fuzz） | [SPI 接入](new-ip-2-onboarding-20261101.md) |
| IRQ/F5 可声明范围（timer compare/timer1、CPU ABI） | [IRQ 声明](irq-declaration-expansion-20261101.md) |
| wbdmac F6 行为声明与源事实 | [DMA 声明](dma-declaration-wbdmac-20261101.md) |
| F1 子字/半字访存真实执行 | [子字报告](subword-f1-20261102.md) |
| 设备行为声明 schema、优先级与限制 | [行为声明](../inprocess-behavior-declarations.md) |

## 2026-11-02 通用化：IRQ/F5、多 link、完整 AXI4 与未接入模块

本轮最终汇总（支持矩阵、五项真实结果、限制、性能）：[round 1 总结](round1-final-20261102.md)。

| 范围 | 入口 |
|---|---|
| IRQ 触发/清除分离、cause 采样、多 link F5、PULP I2C level + 单次清除（含已知 level 风暴缺口） | [IRQ 通用化报告](irq-generalization-20261102.md) |
| round 1 通用化进度（IRQ/F5、完整 AXI4、未接入模块、真实缓存与工具） | [进度记录](round1-generalization-progress-20261102.md) |
| p1 IRQ 通用化：三目标/三 link 与一目标双 link 会话、PULP I2C 两写有序 clear（含失败负控制）、CVA6 2-bit `irq_i` 仅 bit0 被驱动并由 `mcause` 回读见证 take（bit1 由 profile 常量 0，报告为 partial vector）；NMI/PLIC/CPU vector/W1C 按名拒绝 | [p1 IRQ 报告](p1-irq-generalization-20261102.md)、[证据](../../runs/p1-irq/README.md) |
| 完整 AXI4（CVA6）接入统一入口：F2/F3/F4 固定 3/3、fuzz 30/30，F1/F5 按名拒绝 | [AXI4 集成报告](round1-axi4-integration-20261102.md)、[已保存证据](../../runs/round1-axi4-unified/README.md) |
| CVA6 真实退休观测：导出 6974-bit RVFI probe bundle，旁挂 pinned `cva6_rvfi` 记分板；F1 三例（1/2/4 词）+ F2–F4 三例共 6/6、F1 fuzz 20/20、F2–F4 回归 3/3；F5 仍按名拒绝；RV32IM 低 32 位投影为声明事实 | [CVA6 RVFI 退休报告](cva6-rvfi-retirement-f1-20261102.md)、[已保存证据](../../runs/round1-cva6-rvfi/README.md) |
| 多 IP 地址路由：Ibex + Timer + I2C 固定 6/6、fuzz 30（27 通过/3 正常未触发）、换 IP 5/5、回归 1123 tests | [多 IP 报告](round1-multi-ip-20261102.md)、[证据](../../runs/round1-multi-ip/README.md) |
| DMA 第一增量：ZipDMA block 1..8、设备字节使能、2-tick 背压、wbdmac 回归；FIFO 仍拒绝 | [DMA-A 报告](round1-dma-a-20261102.md)、[证据](../../runs/round1-dma-a/README.md) |
| DMA 第二增量：ZipDMA 真实写 PULP SPI TXFIFO（8/8 route writes、0 RAM writes、TX level 0→8），flows 6/6、fuzz 26/30（4 正常未触发） | [DMA-B 报告](../../runs/round1-dma-b/README.md) |
| DMA 第三增量：ZipDMA 真实读 PULP I2C PRESCALER 到 RAM（4/4 route reads、0 RAM reads、dst0..3=0x5a5a、CPU 前后回读一致），固定链 2/2、flows 5/5、fuzz 10/10，六项回归通过 | [DMA 读路由报告](round1-dma-read-20261102.md)、[证据](../../runs/round1-dma-read/README.md) |
| F1 地址计算：固定 2/2、fuzz 20/20（真实生成 address 形状） | [F1-A 报告](../../runs/round1-f1-a/README.md) |
| F1 前向分支：4 字程序退休 3 条、trace hash 与 Python 一致、fuzz 20/20；错误 trace 使批次 failed | [F1-B 报告](../../runs/round1-f1-b/README.md) |
| F1 压缩：4 record word/8 parcel 退休 8 条、trace hash 0xe232c69e、fuzz 20/20 | [F1-C 报告](../../runs/round1-f1-c/README.md) |
| IRQ 电平风暴：错误 clear 的负控制在 case 内被转成 `level_stuck` 失败，2 例（1 失败+1 通过）而非整批 0 例 | [IRQ storm 报告](../../runs/round1-irq-storm/README.md) |
| **round 2 汇总**：CVA6 RVFI/F1、F1 JAL/循环/压缩控制与访存、DMA 读路由、多 F5 目标；含最终回归与未实现边界 | [round 2 报告](round2-removed-limits-20261102.md) |
| F1 控制流：JAL/JALR 2/2+fuzz20、canonical 循环 1/1+fuzz20、压缩控制 3/3+fuzz20、压缩访存 2/2+fuzz20；trace hash 与 Python 一致，88/88 saved cases 独立复核 | [F1 控制流报告](f1-controlflow-jumps-loops-compressed-20261102.md)、[证据](../../runs/round1-f1-controlflow/README.md) |
| 多 F5 目标：timer + I2C 两路真实 IRQ 相或进一根 CPU 输入；global link 选目标；固定 10/10、回归通过；同时归因按名拒绝 | [多 F5 报告](round1-multi-f5-20261102.md)、[证据](../../runs/round1-multi-f5/README.md) |
| **IRQ 高级增量**：同用例双源 F5（timer+I2C 同时触发；ISR 在各自地址读两个状态字、双结果单元、I2C CMD=1 清除；CPU 仍只有一个 OR 输入，状态内容归因而非 CPU vector）；GPIO INTSTATUS 读清；双 bit 状态向量；NMI/PLIC/CPU vector/active-low/W1C 按名拒绝 | [round3 IRQ 报告](round3-irq-advanced-20261102.md)、[证据](../../runs/round3-irq/README.md) |
| 最终代表回归：CVA6 F1+F2–F4、F1 JAL/循环/压缩、DMA read、multi-F5、AXI4、双 IP、DMA FIFO 共 9 批全部通过 | [最终回归](../../runs/final-verify-round2b/campaign.log) |
| CVW/AHB 边界证伪：`wallypipelinedsoc` 不导出 IRQ/退休；`rvvisynth` 的输入是 core 内部信号；F1/F5/F6 仍按名拒绝（非运行通过） | [CVW 边界报告](cvw-retirement-irq-boundary-20261102.md) |
| **混合目标协议**：同一 OBI 会话内 APB3 timer + AXI4-Lite axiluart；固定 6/6，每例 `target_protocol`、AXI 五通道计数、另一目标 0/0；同协议 6/6、单 AXI4-Lite 5/5、CVA6 3/3 回归 | [混合目标报告](round3-mixed-protocol-targets-20261102.md)、[证据](../../runs/round3-mixed-targets/README.md) |
| **混合协议多目标（任意 2..4 子集）**：APB3+TL-UL 8/8、APB3+Wishbone classic 8/8、APB3+AXI4-Lite+TL-UL 8/8、APB3+Wishbone+TL-UL（无 AXI4-Lite）8/8；每例各目标自己的 protocol/桥与计数器、非路由目标 0/0；历史 APB3+AXI4-Lite 对与同构构建保持原文 | [p1 混合协议报告](p1-mixed-protocols-any-subset-20261102.md)、[证据](../../runs/p1-mixed-protocols/README.md) |
| **CVA6 高级**：RVFI `cause/intr/mode` + CSR 读回；真实 M-mode ECALL trap/CSR 1/1（重复 2/2）；独立 RV64 模式 10/10（64-bit trace hash；`0x11111111deadbeee` 跨 bit32）；F5 仍拒绝（缺 IRQ 接线/take） | [CVA6 高级报告](cva6-advanced-trap-rv64-20261102.md)、[证据](../../runs/round3-cva6/README.md) |
| **DMA 高级**：SPI RX FIFO 读（8 pop，level 8→0，0 RAM reads，21 例）、4 寄存器 aperture（5/5）、声明式 master 错误注入（2/2，sticky ERR bit30）；multi-outstanding/多通道/wider beat 按 RTL 事实拒绝 | [DMA 高级报告](dma-advanced-round3-20261102.md)、[证据](../../runs/round3-dma/README.md) |
| **Wishbone / TL-UL 目标**：Wishbone classic 5/5（真实 cyc/stb/ack/we/adr/dat_w/sel）；TL-UL 6/6（真实 A/D 通道）；AHB-Lite 目标按名拒绝 | [目标协议报告](round3-target-protocols-20261102.md)、[证据](../../runs/round3-target-protocols/README.md) |
| **P0-1 IRQ/DMA + 新 IP**：TL-UL OpenTitan rv_timer 真实 F5（INTR_STATE0 状态/bit0 cause/compare 更新清除，CPU 取真实 IRQ；mtime=0x132），同会话 F1–F6 9/9；W1C-only 清除按 RTL 事实拒绝；DMA 路由到 TL-UL/Wishbone/AXI4-Lite 按名拒绝；APB3 route 与 multi-F5 回归通过 | [P0-1 报告](p0-1-irq-dma-tlul-timer-20261102.md)、[证据](../../runs/p0-1-ip/README.md) |
| **round 3 最终回归**：混合、Wishbone、TL-UL、CVA6 trap/RV64、DMA FIFO/aperture/error、IRQ both/multibit、multi-F5、AXI4、DMA FIFO 写共 13 批全部通过 | [最终回归](../../runs/final-verify-round3b/campaign.log) |
| **P0-2 IP-only 与统一 `--mode`**：单 target 模型（PULP APB3 Timer）无 CPU/DMA，26/26 真实读写+trace+IRQ；I2C 带捕获批次 14/14 且 0 断言（模型级断言审计与精确可达性原因）；总线超时单列 environment；`combined` 6/6、`cpu-only` 5/5（仅 CPU archive）、`ip-only` 26/26（仅 target archive） | [P0-2 报告](p0-2-ip-only-unified-modes-20261102.md)、[IP-only 证据](../../runs/p0-ip-only/README.md)、[三模式证据](../../runs/p0-unified-modes/README.md) |
| **P0-1/P0-2 验收汇总**：profile 契约、3 APB3 IP 9/9、CV32E40P F1–F6 6/6、TL-UL timer F5+ZipDMA 9/9、三模式（combined 6/6 / cpu-only 5/5 / ip-only 26/26）、真实 Ibex 断言与 environment timeout | [P0 验收报告](p0-1-p0-2-acceptance-20261102.md)、[最终回归](../../runs/final-verify-p0/README.md) |
| **P0-1 组件 profile 契约与多 IP 汇编**：CPU/MMIO IP/DMA 必需字段逐项列名与拒绝名（复用 `component_profile.v1`，无新 schema），26 个定向测试；同一会话三 IP（timer+I2C+SPI）9/9、CV32E40P 三 IP 8/8、混合 APB3+AXI4-Lite 6/6，`combination_specific_branches none`；无 DMA 的 F6 按名拒绝 | [profile 契约](p0-1-component-profile-contract.md)、[P0-1 报告](p0-1-cpu-replacement-and-assembly-20261102.md)、[证据](../../runs/p0-1-cpu/README.md) |
| **P0-1 CPU 替换（CV32E40P）**：pinned `cv32e40p_rvfi_local`（未改 profile）在 Ibex 同一声明中跑 F1–F6 6/6（F1 退休 33、F5 `irq_takes 1`、F6 DMA 4/4 真实搬运）；为 timed 模型新增通用相位调度（host 按声明半周期推进 `VerilatedContext` 并排空事件）+ 链接 `verilated_timing.cpp`、`-fcoroutines`；退休面无 `rvfi_trap` 时如实报 `traps unknown`/`trap_evidence unobservable`，不伪造 0；Ibex 基线 case 行逐字节不变 | [P0-1 报告](p0-1-cpu-replacement-and-assembly-20261102.md)、[证据](../../runs/p0-1-cpu/README.md) |
| **P1 行为表达力 + 三个替换样本**：行为声明新增有序 `clear_sequence`（一条写步即执行器那条清除写；多步/读步按名拒绝）、命名 `pin_groups`/`serial_peer`（单 dir 组可执行并派生 `pins`；多组/串行 peer 按名拒绝）、DMA `capabilities`（channels/beat_bytes/max_outstanding/burst_beats，planner 按 pinned 器件事实拒绝超声明）；替换样本只用 profile/behavior/scenario 改动：`picorv32_wb_irq_rvfi` F1–F6 6/6（custom IRQ bit3 + eoi、RVFI 退休、ZipDMA 4 词）、`opentitan_uart_local` TL-UL F1–F5 5/5（真实 `tx_done` 事件：CTRL/WDATA 真串行发送、INTR_STATE bit2、W1C 清除；F6 按名拒绝）、`shared_profile_dma`（同一 pinned ZipDMA、不同 profile）F6 5/5（F5 按名拒绝）；6 个具名拒绝实录 | [P1 报告](p1-behavior-expressiveness-replacements-20261102.md)、[证据](../../runs/p1-replacements/README.md) |
| **P1 DMA 路由协议**：DMA route 不再只走 APB3；TL-UL（rv_timer `COMPARE_LOWER0_0` 固定读）、Wishbone（wbuart `SETUP` 定长读/写）与 AXI4-Lite（axiluart `SETUP` 读/写）各跑真实批次，case 行给出该 target 自身协议计数（TL-UL A/D 各 4、Wishbone `wb_acks` 4、AXI4-Lite AR/R 4 与 AW/W/B 4）、捕获/回读值与 `dma_ram_reads 0`；APB3 route 行逐字段不变，五条具名拒绝（写只读/读只写/窗口外/30 位地址不可达/无 adapter 的 AHB-Lite），AXI4-Lite 完成判据改为按事务增量（`AxiMark`） | [P1 报告](p1-dma-route-protocol-20261102.md)、[证据](../../runs/p1-dma-route/README.md) |
| **P1 每模型时钟与 CPU 能力矩阵**：声明频率归一成整数半周期比（`phase_clock_plan`，参考 CPU 半周期为一格，全部时钟先低）；50/25/10 MHz 单会话实测 318/159/64 上升沿、两目标真实 APB3 读写；timed CV32E40P + untimed 25 MHz（`grid_ps 10000`，209/105）与 untimed Ibex + timed 10 MHz（半周期 5 格，233/47）两个混合方向；等速率 Ibex/CV32E40P F1–F6 case 行与 P0-1 基线逐字节相同；四条具名拒绝（无退休面、非整数比、快于参考 CPU、AHB+DMA F6）；`docs/cpu-capability-matrix.md` 由 `scripts/cpu_capability_matrix.py` 覆盖 25 个 CPU profile 的退休/trap/IRQ 面与可运行流向 | [P1 时序报告](p1-timing-clocks-capability-20261102.md)、[证据](../../runs/p1-timing/README.md) |
| **P1 验收汇总**：六条要求逐条落点（混合协议多目标、IRQ 任意拓扑、DMA 四种目标协议路由、每模型时钟与 CPU 能力矩阵、行为声明扩展、三个替换样本）+ 最终代表批次 13 批 64 例（全部 `observations_passed`/`matched`，210 s）+ 综合测试 1758 passed；并与 P0 结论对齐两处更正（TL-UL+APB 混合、DMA route 到 TL-UL 不再拒绝） | [P1 验收报告](p1-acceptance-final-20261102.md)、[最终批次](../../runs/final-verify-p1/README.md) |

## 2026-11-03 P2：单组件模式补全与剩余协议/行为

七个并行增量，各自有真实 RTL 批次与独立证据目录。本轮的核心约束仍是「按协议或设备
行为扩展，不写 CPU×IP 组合分支」；新增能力的反面（不支持）一律给具名拒绝。

| 范围 | 入口 |
|---|---|
| **P2 CPU-only 通用指令程序 fuzz**：`--fuzz-mode program`（默认）每例生成并真实执行一条不同 RV32 程序，复用 F1 生成器/门禁/参考模型，逐例报告程序词、反汇编、`retires`、写回、trace 哈希与数据窗口对比；`--fuzz-mode data` 保留旧数据形状且 case 行逐字不变；CPU artifact 由 profile 现场解析并按 `artifact_digest` 命中/构建（如实报 `cache_hit`/`compiled_this_invocation`）；OBI + Wishbone + AXI4-Lite 三种总线各 8 例真实批次，缺 RVFI 的模型 `retires/trap=unknown` 但总线流照跑；断言与 environment 超时语义不变 | [P2 CPU-only 报告](p2-cpu-only-program-fuzz-20261103.md)、[证据](../../runs/p2-cpu-only-20261103/README.md) |
| **P2 IP-only：fuzz、四目标协议、长驻执行**：`--fuzz` 真闭环（写→同偏移回读→**以设备回读值为下一轮变异种子**；APB3 64 例 / TL-UL 48 例，每例输入/依据/观察/结果在 `fuzz.json`）；单 IP 模式扩到 `apb3`/`tl-ul`/`wishbone`/`axi4-lite`（26/15/9/9 例，完成判据与采样地址都来自目标自己的 trace 角色）；默认改**长驻**（同 26 例：1 进程 125 ticks 0.00424 s vs 26 进程 1718 ticks 0.10871 s，325/351 次事务是重放），`--case-isolation prefix-replay` 显式保留；断言命中即中止并保存 source/line/scope/text/tick/事务；P0 四形态 case 行逐字节回归 | [P2 IP-only 报告](p2-ip-only-fuzz-and-protocols-20261103.md)、[证据](../../runs/p2-ip-only-20261103/README.md) |
| **P2 AHB-Lite 目标适配器**：统一入口新增第五种目标协议；由 profile 的 `mmio_slave` 端点派生 `target.ahb-lite/1` 与真实 `ahb_lite_mmio_target` 桥，宿主按十角色采 address/data 两相（`hsel/htrans/haddr/hwrite/hsize/hwdata/hreadyin/hreadyout/hrdata/hresp`）；同构 F2/F4 3/3、Caliptra SHA 已知答案 67/67（abc/abd 摘要与 `hashlib` 逐字节一致、STATUS READY→VALID、BLOCK 写后读 0）、APB3+AHB-Lite+TL-UL 混合 9/9（每例 `target_protocol`、非路由目标 0/0）；F5（无 IRQ 契约）与 F6（路由准入未含 ahb-lite）具名拒绝；其余四种协议既有 case 行除 `seconds` 外逐字节不变 | [AHB 目标报告](p2-ahb-lite-target-adapter-20261103.md)、[证据](../../runs/p2-ahb-target-20261103/README.md) |
| **P2 IRQ 第二轮**：TL-UL OpenTitan GPIO 的**写 1 清除真的执行并保持低**（`INTR_TEST` 自抬中断 → ISR 读 `INTR_STATE` → 真 W1C；`irq_takes 1 clear_writes 1 last_clear_data 0x1 irq_level_final 0 level_stuck 0`，两例之后能再次取中断），PULP GPIO 读清固定（`isr_read_clears 1 clear_writes 0`）；Wishbone/AXI4-Lite 的 F5、NMI、PLIC、CVA6 的 `irq_i[1]` 各自把**卡住的那一层**逐行核实后按名拒绝（NMI 卡在 profile 端口处置层而非 RTL/RVFI；`rv_plic` 是 TL-UL 设备、claim/complete 本就是普通 MMIO，故不缺 CPU 端口）；对 p1 的 IRQ case 行逐字节一致 | [p2 IRQ 报告](p2-irq-round-two-20261103.md)、[证据](../../runs/p2-irq-20261103/README.md) |
| **P2 引脚与串行真执行**：宿主按声明顺序执行最多 4 个 `dir_resolved_pad_word` 组（`direction` 真选线、`hold_ticks` 真窗口、逐组 case 字段、方向以设备 `PADDIR` 为可证伪见证），并按 `serial_peer` 真驱动/采样串行线：8n1/8e1/8o1 三种帧全有真实批次，宿主打进整帧后设备 `FIFO_STATUS` 读回 RXLVL=1 且 `RDATA` 读回同一字节，设备发出的字节由宿主逐 bit 解码且 `tx_done` 真取中断；`HOST_SOURCE_EXECUTION` 升为 4 组 + 1 peer；多停止位、半双工、两 peer、第二 pad 字、缺角色等逐条按名拒绝；单 pad 旧路径与 P1 UART 目标 case 行逐字节不变 | [P2 引脚/串行报告](p2-pins-serial-execution-20261103.md)、[证据](../../runs/p2-pins-serial-20261103/README.md) |
| **P2 DMA：真不同器件与能力边界**：树内只有两颗 DMA RTL，`inprocess_generality_wbdmac` 与 `zipcpu_wbdmac` 经核对是**同一 RTL 的不同 profile**（不算新器件，测试钉住）；`wbdmac` 在统一入口 F6 **真跑通 4 字与 8 字块自主搬运**（控制口 keyed start `0x0fed0004`/`0x0fed0008` → 真实 read/write beat → 器件完成脉冲 → CPU 读回目标块逐字正确）；多通道、8 字节 beat、多 outstanding 按器件事实具名拒绝，其中深度 2 有**实测失败证据**（`wbdmac.v:472-491` 把请求计数当 ack 计数）；F6 case 行新增 `dma_device/dma_channels/dma_beat_bytes/dma_max_outstanding/dma_outstanding_peak`，既有 ZipDMA 47 条 case 行逐字节不变 | [P2 DMA 报告](p2-dma-capabilities-new-device-20261103.md)、[证据](../../runs/p2-dma-20261103/README.md) |
| **P2 时钟：非整数比 / 更快模型 / 异步**：一格 = `1/(2·lcm(声明频率))` 的精确有理网格（50+30 MHz = `C3/R5`、实测 131/218 沿 = 30/50；50+30+60 MHz = `C6/R10/5`、实测 262/218 = 60/50），比 CPU 更快的模型在同一 tick 内多次推进（真子步进，`static_assert` 钉死「一 tick = 一个 CPU 周期」）；32.768 kHz RTC 的异步对与「更快模型的总线流量」按名拒绝（含精确网格与两侧格数，另有真实超时失败存档）；五条 p1 等速率/整数比 case 行去掉 `seconds` 后逐字节不变 | [P2 时序报告](p2-timing-ratios-async-20261103.md)、[证据](../../runs/p2-timing-20261103/README.md) |

## 2026-10-31 阶段一收尾

| 范围 | 入口 |
|---|---|
| 阶段一验收 6 条逐条状态（已完成/部分、证据路径、还缺什么） | [验收矩阵](stage1-acceptance-matrix-20261031.md) |
| 阶段一完成报告（六 CPU / 五条 IP 总线真实结果、profile 派生证据、wall 时间、移出项） | [阶段一完成报告](stage1-completion-20261031.md) |
| F1–F4 最小交互路径与代码体量审计 | [最小路径审计](f1-f4-minimal-path-audit-20261030.md) |
| OBI park 与 Wishbone UART 写策略修复 | [修复记录](f1-f4-fixes-20261030.md) |
| F1–F4 代表组合真实批量（含 CV32E40P/Timer 追加） | [批量结果](f1-f4-batch-20261030.md) |
| TL-UL / AXI4-Lite / AHB-Lite IP 目标适配 | [扩展总线](extended-bus-adapters-20261031.md)、[TL-UL 2 例最小验证](tlul-f2f4-real-run-20261031.md) |
| 完整 AXI4 CPU（Vexii/ZipAXI/CVA6）可行性 | [AXI4 CPU 可行性](full-axi4-cpu-f1-f4-feasibility-20261031.md) |
| RISC-V 指令生成器与 F1 真实执行 | [RISC-V 生成器](riscv-generator-20261030.md) |
| 阶段一全量验收审计（2026-10-31 01:15 快照） | [阶段一审计](stage1-completion-audit-20261031.md) |

## 查找其他报告

- [完整报告目录](CATALOG.md)：按专题和文件日期列出报告，不重复抄写测试数或通过结论。
- [原始证据目录](evidence/)：按报告进入具体 attempt、manifest、日志与 replay 输入。
- [旧报告首页完整快照](../history/2026-10-26-report-index.md)：保留拆分前全部逐次更新，包含较早结论和已覆盖的检查点。
- [已删除产物记录](DELETED_ARTIFACTS_20261009.md)：区分报告仍在与原始运行可复算；部分历史链接的原目标已不存在。

软件、真实 RTL、native、RFuzz、远程 gate 和独立审计各有证明范围。能力查询、目录存在或局部通过不替代系统验收。
