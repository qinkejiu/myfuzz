# P1 验收：混合协议多目标、IRQ 任意拓扑、DMA 路由、每模型时钟、行为扩展与替换样本（2026-11-02）

本文件汇总本轮五个并行增量与最终代表 RTL 批次。每个结论都对应 `runs/` 下保存的
case/summary；不把声明、单元测试或取指当作执行通过，不声称覆盖率、证书或 replay。
最终批次 `runs/final-verify-p1/` 是在**同一棵最终树**上把五个增量各取一条代表组合
重跑一遍，用于确认它们落地后仍能一起运行；增量自己的完整证据仍在各自的
`runs/p1-*/` 目录里。

## 0. 六条要求 → 落点

| 用户要求 | 增量 | 证据 | 结论 |
|---|---|---|---|
| 1 混合协议多 IP 仍不够通用 | 代理 A | [p1 混合协议报告](p1-mixed-protocols-any-subset-20261102.md)、`runs/p1-mixed-protocols/` | 任意 2–4 协议子集均可作为目标；每目标独立协议适配器与完成判据 |
| 2 IRQ 行为仍有适配边界 | 代理 B | [p1 IRQ 报告](p1-irq-generalization-20261102.md)、`runs/p1-irq/` | 任意 link 拓扑、有序多写 clear、CVA6 多位入口真实 take；NMI/PLIC/vector/W1C 按名拒绝 |
| 3 DMA 路由未覆盖所有目标协议 | 代理 C | [p1 DMA 路由报告](p1-dma-route-protocol-20261102.md)、`runs/p1-dma-route/` | TL-UL / Wishbone / AXI4-Lite 目标全部打通真实路由事务 |
| 4 CPU 与模型时序仍有边界 | 代理 D | [p1 时序报告](p1-timing-clocks-capability-20261102.md)、`runs/p1-timing/`、`docs/cpu-capability-matrix.md` | 声明频率归一成整数半周期比；25 个 CPU profile 的退休/trap/IRQ/时序逐项列名 |
| 5 profile 能表达的设备行为有限 | 代理 E | [p1 行为表达力报告](p1-behavior-expressiveness-replacements-20261102.md)、`runs/p1-replacements/` | 有序 `clear_sequence`、`pin_groups`/`serial_peer`、DMA `capabilities`：能执行的执行，不能执行的在声明层按名拒绝 |
| 6 真实组件替换样本要扩大 | 代理 E | 同上 | 新 CPU、新 IP、新 DMA 三个替换样本，只改 profile/config，不改组合代码 |

## 1. 混合协议的多个 IP

**声明轴**：目标集合不再按「一对协议」写死。入口按每个目标自己的 `mmio_slave`
协议选适配器、完成判据和计数器，混合集合本身只要求「每个协议都在已支持集合内」。

**真实运行**（各 8 例，`runs/p1-mixed-protocols/`）：

| 集合 | 用例 | 结果 |
|---|---|---|
| APB3 + TL-UL | F2/F4/F5/F2/F4/F2/F4/F3 | 8/8 `observations_passed`，`correspondence matched` |
| APB3 + Wishbone classic | 同上 | 8/8 |
| APB3 + AXI4-Lite + TL-UL | 同上 | 8/8 |
| APB3 + Wishbone + TL-UL（无 AXI4-Lite） | 同上 | 8/8 |

**最终批次复核**（`runs/final-verify-p1/mixed-apb3-tlul`，8/8）：case 0–2
`target_protocol apb3`（`0x40001000`），case 3–6 `target_protocol tl-ul`
（`0x40003000`，含 F4 写 `COMPARE_LOWER0_0`），case 7 RAM-only F3
`target_protocol none target_transfers 0`——非目标例不许有目标事务。同一份
`target_protocol` 结构里，`transfer_criterion` 逐目标给出
`apb3=sel_enable_ready`、`tl-ul=a_valid_and_a_ready_then_d_valid_and_d_ready`，
`error_response` 逐目标给出（APB3 无 `pslverr` 时是 `unknown`，TL-UL 采样真实
`d_error`）——完成条件是按目标选的，不是按组合猜的。

**仍拒绝**：`unsupported-targets:mixed-protocol:ahb-lite,apb3`（协议不在集合内）、
`unsupported-pins:multiple-targets`（pin 模型是单目标特性）、
`unsupported-f5:target-protocol-not-run:wishbone|axi4-lite:<name>`（F5 目标协议
仍只有 APB3 + TL-UL）、`unsupported-target-protocol:ahb-lite-target:<name>`。

## 2. IRQ 通用化

**任意拓扑**（`runs/p1-irq/`）：三目标三 global link 9/9；三目标四 link（PULP timer
同时拥有 overflow 与 compare 两条 link）9/9，每例点名自己选的 link 与状态字；
「同用例双源」行现在对**任意** ≥2 个单 link 声明目标生成（不再写死两个），
双 light 目标由 `both-needs-one-link-per-target` 按名拒绝。

**新的清除形态**：PULP I2C 的有序两写 ack（`CMD=1` 清 `irq_flag`，`CMD=0` 释放
`iack`），2/2，`clear_writes 2` 且 APB 写顺序被核对；失败负控（清除序列不写 ack）
保留在 `two-step-clear-negative`，状态是 **`failed`**——这是设计内的负控，不是
增量失败（`level_stuck 1`、5 次 take）。

**CPU 侧多位入口**：CVA6 F5 3/3。`cpu_irq driven_bit0_machine_external
cpu_irq_bit1 not_driven`；take 由核心自己的 `mcause` 回读见证
（`clock_cpu_take_witness mcause_readback`），bit1 由 profile 常量 0 →
报告 `cpu-vector-partial`，不冒充向量。增量实测：pinned `cva6_rvfi` scoreboard
上 `rvfi_intr` **不**标记中断进入，因此不作为该 CPU 的 take 见证。

**最终批次复核**（`runs/final-verify-p1/irq-three-ip`，9/9）：case 1
`target_index 0 isr_read_addr 0x40001000 isr_read_register_kind count`；case 2
`target_index 1 isr_read_addr 0x4000200c isr_read_value 0x00000081
isr_cause 0x00000001 clear_writes 1`；case 3 `target_index 2
isr_read_addr 0x20002028`；case 4（双源行）`irq_edges 2 irq_takes 2
trigger_writes 6 clear_writes 1 level_stuck 0`；case 5–7 是三个目标各自的 F2。
`irq-cva6` 3/3，两例 F5 均 `irq_takes 1 level_stuck 0`。

**仍拒绝**：NMI（Ibex `irq_nm_i=constant-0`，CVA6 无端口）、PLIC（树内有真实
`rv_plic.sv` 但没有组合 profile/claim 完成端口）、CPU 多位 vector、
active-low、只靠 W1C 保持低的电平清除。能力上限照旧：一个 CPU 中断输入、
无 per-source vector、双源行恰好两个成员、有序 clear ≤2 写。

## 3. DMA 路由到各目标协议

**协议集合**：`ROUTE_PROTOCOLS = apb3 / tl-ul / wishbone / axi4-lite`。路由事实不再
假设 APB3——它从被路由目标 profile 的 `mmio_slave` endpoint 读该目标**自己的**
协议（`PROFILE_PROTOCOL_NAMES` 做 `apb→apb3` 归一），endpoint 写了未承认的线就
`dma-route-target-protocol-unsupported`。宿主侧新增「只服务路由」的协议 trace
采样器（Wishbone `cyc/stb/ack/we/adr/dat_w/dat_r`、TL-UL A→D、AXI4-Lite
`AW/W/B` 或 `AR/R`），计数写在 case 行里。

**真实运行**（`runs/p1-dma-route/`）：TL-UL rv_timer `COMPARE_LOWER0_0` 固定读 2/2
与六流批次 6/6；Wishbone wbuart `SETUP` 写 1/1、读 2/2；AXI4-Lite axiluart
`SETUP` 读 2/2、写 1/1；APB3 全部回归通过，且 APB3 的 case 行逐字段不变。

**最终批次复核**（`runs/final-verify-p1/dma-route-*`）：

| 目标 | case | 关键字段 |
|---|---|---|
| TL-UL `0x20004118` | F6 | `dma_route_protocol tl-ul dma_route_reads 4 dma_route_acks 4 dma_route_target_reads 4 dma_route_protocol_transfers 4 dma_first_read_value 0x0badc0de dma_ram_reads 0` |
| Wishbone `0x20005000` | F6 | `dma_route_protocol wishbone dma_route_wb_acks 4 dma_route_protocol_transfers 4 dma_first_read_value 0x0000abcd dma_ram_reads 0` |
| AXI4-Lite `0x20006000` | F6 | `dma_route_protocol axi4-lite dma_route_protocol_transfers 4 dma_first_read_value 0x0000abcd dma_ram_reads 0 axi_ar 2 axi_r 2` |

AXI4-Lite 那两行 CPU 读（F4 前的证据读与 F6 后的回读）能同时存在，是因为完成
判据从「整例累计 == 1」改成按事务增量（`AxiMark`）；旧判据会把一次合法的第二次
CPU 读判成错误，这点在增量里有对照复现。

**仍拒绝**：写只读寄存器、读只写寄存器、窗口外偏移、30 位地址不可达、没有适配器
的 AHB-Lite 路由；DMA 多 outstanding / 多通道 / 宽 beat 只在声明层，超 pinned
器件事实即拒。

## 4. 每模型时钟与 CPU 能力

**时钟归一**：`phase_clock_plan` 把每个模型声明的频率化成「参考 CPU 半周期的整数倍」
一格，模型电平 `(step // half) % 2`，全部时钟先低、各自在自己的半周期首次上升。
非整数比、快于参考 CPU、比值 >1024、timed 契约与比值不一致、非整数 ps 网格
全部按名拒绝（`assume_single_clock` 保留为显式回退，并且仍报告 `assumed`）。

**真实运行**（`runs/p1-timing/rows/`）：50/25/10 MHz 单会话（实测上升沿 318/159/64，
两目标真实 APB3 读写）；timed CV32E40P + untimed 25 MHz（`grid_ps 10000`，
209/105）；untimed Ibex + timed 10 MHz（半周期 5 格，233/47）；等速率
Ibex/CV32E40P F1–F6 与 P0-1 基线 case 行逐字节相同。

**最终批次复核**（`runs/final-verify-p1/timing-ratio`，6/6，untimed 比率模式
`timing.timed false`）：`clockcase 0 ticks 83 plan per_model_ratio
cpu_half_ticks 1 cpu_rises 83 target0_half_ticks 2 target0_rises 42
target1_half_ticks 5 target1_rises 17`——实测上升沿就是声明的 1 : 1/2 : 1/5；
两个目标的 F2/F4 分别 41/46 与 48/53 ticks，越慢越晚。

**能力矩阵**：`docs/cpu-capability-matrix.md` 由 `scripts/cpu_capability_matrix.py`
从全部 25 个 `configs/cpus/*/component_profile.json` 生成，逐 profile 给出总线、
xlen、退休面、RVFI 字段、trap 面、IRQ 入口/宽度/语义、时钟与时序模式，以及每个
流向的可运行性/拒绝名。本文件核对：**10 个有退休面、8 个有 trap 面、14 个有 IRQ
入口、2 个是 timed**；4 个 profile 的总线本身按名拒绝。缺信号写 `unknown`/`none`，
不写 0。

**仍拒绝**：参考 CPU 必须最快（更快的按名拒绝，不做子步进）；非整数比拒绝而非
近似；timed-IP 方向只是「timed build 的链接与相位路径」，因为树内没有带
`assign #` 延迟的外设 RTL；`assume_single_clock` 是声明不是测量。

## 5. Profile/behavior 能表达的设备行为

`src/myfuzz/composition/inprocess_behavior.py` 扩展了三处声明（全部是加法，
最小声明产生的 fact 字典与旧版逐字段相同）：

1. **有序 `clear_sequence`**（每个 IRQ link）：步对象或 `[offset, value]` 简写；
   单写步会派生进 `clear_writes` 并**真的执行**，多步 → 
   `unsupported-behavior-execution:multi_step_clear:<n>`，读步 →
   `…:clear_read_step`；同时给 `clear_writes` 用
   `behavior-source-conflict:clear_writes` 拒绝歧义写法。
2. **命名 `pin_groups` / `serial_peer`**：`dir_resolved_pad_word`
   （direction/hold_ticks）与 `serial_peer`（rx/tx/tx_en 角色、idle_level、
   bit_ticks、frame 8n1/8e1/8o1）；单个 dir 组可执行并派生 `pins` fact，
   多组 → `…:pin_groups:<n>`、串行 peer → `…:serial_peer` 按名拒绝。
   `HOST_SOURCE_EXECUTION` 是可审的能力事实，同一批声明在放宽 `limits` 后
   可执行（有测试）。
3. **DMA `capabilities`** `{channels, beat_bytes, max_outstanding, burst_beats}`：
   声明层做形状检查，**planner 按 pinned 器件事实拒绝超声明**
   （`dma-capability-beyond-device:<k>:<d>><dev>`、profile 侧同类名，并在
   `validate_transfer_plan` 复检）。

**这一节的诚实边界**：同协议只解决总线通信，IP 自身功能与引脚行为仍需要必要描述；
能被声明 ≠ 能被执行 —— 上面每条都明确写了哪些形态只声明、哪些真跑。

## 6. 真实组件替换（只改 profile/config）

| 替换对象 | 声明改动 | 真实结果 |
|---|---|---|
| CPU `picorv32_wb_irq_rvfi`（Wishbone，custom IRQ bit3 + 真实 eoi，RVFI） | `cpu_profile`、`cpu_irq_bit`、`cpu_timing`、镜像/等待参数 | F1–F6 6/6 |
| IP `opentitan_uart_local`（TL-UL） | `source_profile` + behavior | F1–F5 5/5，F6 按名拒绝（无 DMA 声明） |
| DMA `shared_profile_dma`（同一 pinned ZipDMA、不同 profile） | `dma_profile` | F6 5/5，F5 按名拒绝 |

**最终批次复核**：`replacement-cpu` 6/6（`retires 29/11/13/15/59/91`，
`rvfi_order_monotonic 1`，F5 `irq_takes 1`，F6 `dma_reads 4 dma_writes 4`）；
`replacement-ip` 5/5（F5 `isr_read_addr 0x40003000 isr_read_value 0x00000105
isr_cause 0x00000004 clear_writes 1 trigger_writes 3`——bit2 `tx_done`，由真实
串行化的一个字节产生，W1C 清除）；`replacement-dma` F1–F4 + F6 5/5
（`ctl_status 0x40`，`dst0..3 = 0x0110c000/0x08000000/0xdeadbeef/0x12345678`
与 F4 写入一致）。

**唯一代码之外的发现**：`opentitan_uart_local` 的 profile 缺 `INTR_STATE` 的
`tx_done` 位（只有 per-port bit0），RTL 寄存器顺序把 `tx_done` 放在 bit2；
先用错位跑出的 `wait_timeout` 失败留在 `runs/p1-replacements/probes/`，没有删。
这是 profile 缺口，不是行为层能补的。

## 7. 最终代表批次（`runs/final-verify-p1/`）

13 批、64 例，**13/13 exit 0，64/64 `observations_passed` 且
`correspondence matched`**，整批 210 s（11–24 s/批）。命令、逐例 case 行、
`summary.json` 都在该目录；README 里逐条注明哪些数字是本次重跑得到的。

| # | 批次 | 例 | 用时 |
|---|---|---|---|
| 1 | `mixed-apb3-tlul` | 8 | 13 s |
| 2 | `irq-three-ip` | 9 | 19 s |
| 3 | `irq-cva6` | 3 | 24 s |
| 4 | `dma-route-tlul` | 2 | 13 s |
| 5 | `dma-route-wb` | 2 | 13 s |
| 6 | `dma-route-axil` | 2 | 16 s |
| 7 | `timing-ratio` | 6 | 16 s |
| 8 | `replacement-cpu` | 6 | 18 s |
| 9 | `replacement-ip` | 5 | 19 s |
| 10 | `replacement-dma` | 5 | 14 s |
| 11 | `regression-axi4` | 3 | 22 s |
| 12 | `regression-mixed-pair` | 6 | 11 s |
| 13 | `regression-wb-tlul` | 7 | 12 s |

该批混有缓存复用与真编译，两者都逐 build 记录：**11 个模型 build 是本次真编译
（`compiled_published`）**，27 个是 `cache_hit`；共享 C++ 宿主每批都重新链接
（`link_cache_hit false`，5.2–6.4 s）。

## 8. 测试

在最终树上重跑本轮综合套：**1758 passed（19.14 s）**，与上个会话末的计数一致；
`tests/test_doc_link_check.py` + `tests/test_repository_audit.py` 81 passed（本轮新增的文档链接
全部有效）。**不声称全仓一律通过**：`tests/examples/test_real_ibex_rfuzz_example.py::
test_root_readme_links_chinese_walkthrough` 在本次工作开始前就已失败（HEAD 与工作区的根
`README.md` 都没有它要的 `examples/real_ibex_rfuzz/README.zh-CN.md` 链接），与本轮改动无关；
`tests/composition/` 的监督式 elaboration 用例在本沙箱按 pgid 被拒（既有记录见
`runs/stage2-ahb-unified-20261101/README.md` 的 `setsid` 要求），本轮未改这些文件。
各增量自己的定向测试数：混合协议 22 条新增（`test_inprocess_mixed_protocols.py`，
连同 `test_inprocess_mixed_targets.py`/`test_inprocess_target_protocols.py` 共 67、
入口 196）；IRQ `test_irq_generalization.py` 18 条（聚焦 422）；DMA 路由
`test_inprocess_dma_route_protocols.py` 24 条；时序 `test_timing_capabilities.py`
22 条（聚焦 289/289）；行为与替换 `test_p1_behavior_extension.py` +
`test_p1_replacement_configs.py` 66 条。

## 9. 仍拒绝 / 未验证（本轮结束时的边界）

| 项 | 状态 |
|---|---|
| AHB-Lite 目标适配器 | 没有；`unsupported-target-protocol:ahb-lite-target` |
| 含 ahb-lite 的混合目标集合 | `unsupported-targets:mixed-protocol:ahb-lite,apb3` |
| F5 目标协议 Wishbone / AXI4-Lite | `unsupported-f5:target-protocol-not-run:…` |
| NMI / PLIC / CPU 多位 vector / active-low / 只 W1C | 按名拒绝（RTL 事实逐条写明） |
| 一个 CPU 多个独立中断输入、per-source vector | 未支持；双源行恰好两个成员 |
| DMA 多通道 / 宽 beat / 多 outstanding | 只声明 + planner 拒绝 |
| 串行 peer / 多 pin 组 | 只声明（可执行的是单 dir 组） |
| 参考 CPU 之外更快的模型、非整数时钟比 | 拒绝，不近似、不子步进 |
| CVW/AHB CPU 的 F1 退休面与 F5/F6 | 继续拒绝（profile 不导出） |
| timed-IP 的事件顺序 | 无带延迟的外设 RTL，只证明 timed build/相位路径 |
| IP-only 的非 APB3 目标（P0-2 遗留） | 本轮未改，仍拒绝 |

## 10. 与 P0 结论的关系

P0 验收（`p0-1-p0-2-acceptance-20261102.md`）末尾列的「仍拒绝：IP-only 非 APB3、
TL-UL+APB 混合、DMA route 到 TL-UL、W1C、多 outstanding、CV32E40P 的
trap/writeback」中，本轮改变了前两条：

- **TL-UL + APB 混合**不再是拒绝项，见第 1 节（任意 2–4 协议子集）。
- **DMA route 到 TL-UL** 不再是拒绝项，Wishbone 与 AXI4-Lite 一并打通，见第 3 节。

其余不变：W1C-only 清除仍拒、DMA 多 outstanding/多通道仍拒、CV32E40P 的
trap/writeback 仍报 `unknown`（不可观测，不是测得 0）、IP-only 非 APB3 仍拒。

## 11. 文件

| 路径 | 内容 |
|---|---|
| `runs/final-verify-p1/{run.sh,campaign.log,case-lines.txt,README.md}` | 最终批次命令、结果、逐例 case 行 |
| `runs/p1-mixed-protocols/` | 4 个混合集合 + 4 条回归 + 拒绝实测 |
| `runs/p1-irq/` | 三目标三 link、四 link、两写 clear（含负控）、CVA6 F5 |
| `runs/p1-dma-route/` | TL-UL / Wishbone / AXI4-Lite 路由 + APB3 回归 + 5 条拒绝 |
| `runs/p1-timing/` | 7 个比率/时序会话 + 4 条拒绝 + `case-lines.txt` |
| `runs/p1-replacements/` | 3 个替换样本 + 6 条具名拒绝 + `probes/` 失败轨迹 |
| `docs/cpu-capability-matrix.md` | 25 个 CPU profile 的能力矩阵（脚本生成） |
