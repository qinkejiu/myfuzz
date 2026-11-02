# 单进程 F1–F6 循环验证报告（2026-11-01）

> 本报告部分广度结论截至 11 月 1 日凌晨；同日晚间 AXI4-Lite 目标、GPIO 引脚与 Wishbone CPU 的统一循环验证见[当前能力盘点](../current-system-capabilities-20261101.md)。

状态：**完成**（2026-11-01）。三部分审计与优化重证均已完成，结论与证据见 §3–§6。本文件是长期目标「验证优化后的单进程 F1–F6 执行循环」的合并报告：§2 事件面静态盘点、§3 事件完善性、§4 通用化档位、§5 广度矩阵、§6 优化前后对照与重证。

口径：只写可复核的事实。每条结论必须能指到 `run.log` 行、`summary.json` 字段或源码行号；`observed` / `partial` / `missing` / `unknown` 四档分开写，不把 directed、单例或主机侧假设说成通用通过。完整证书与 replay 不在本循环内，原型只留紧凑摘要。

## 1. 验证对象

| 项 | 内容 |
|---|---|
| 执行循环 | `scripts/inprocess_obi_apb_f1f4_spike.cpp`（F1–F6 同一进程；`#ifndef HAVE_DMA/HAVE_IRQ_LINKS` 默认关闭，F1–F4 语义不变） |
| 入口 | `scripts/run_inprocess_f1f6.py`（F1–F6）、`scripts/run_inprocess_flow.py`（F5/F6 薄入口）、`scripts/run_inprocess_f1f4.py`（F1–F4 子集） |
| 配置 | `configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json`（Ibex + PULP Timer + ZipDMA） |
| 基线证据 | `runs/stage2-stepD2-f1f6/`（6 例 `observations_passed`、`combination_specific_branches=none`） |
| 测量脚本 | `scripts/measure_inprocess_phases.py`，基线见 `runs/stage2-stepE-measure/REPORT.md` |

## 2. 事件面静态盘点

三个 host 实际打印的事件种类（`grep 'cout <<'` 逐条核对）：

| host | 事件种类 |
|---|---|
| `inprocess_obi_apb_irq_spike.cpp`（F5） | `mmio`、`apb_access`、`ip_read`、`irq_source`、`irq_take`、`mret`、`case`、`summary` |
| `inprocess_obi_wb_dma_spike.cpp`（F6） | `cpu_mmio`、`dma_read`、`dma_write`、`irq_*`、`mret`、`case`、`summary` |
| `inprocess_obi_apb_f1f4_spike.cpp`（F1–F6，当前循环） | `retire`、`cpu_data`、`cpu_mmio`、`cpu_control`、`apb`、`dma_read`、`dma_write`、`dma_control`、`irq_edge`、`irq_take`、`case`、`summary` |

当前循环每条事件的字段（源码行号）：

| 事件 | 字段 | 源码 |
|---|---|---|
| `retire` | `tick pc insn` | `:568` |
| `cpu_data` | `tick write/read addr value be` | `:675` |
| `cpu_mmio` | `tick write/read addr value` | `:634` |
| `cpu_control` | `tick write/read addr value` | `:642` |
| `apb` | `tick write/read paddr pwdata prdata` | `:557` |
| `dma_read` / `dma_write` | `tick addr data` | `:737` |
| `dma_control` | `tick write/read offset value` | `:703/:708` |
| `irq_edge` | `index tick` | `:593/:601` |
| `irq_take` | `tick` | `:539` |
| `case` | 每例状态 + 该 flow 的观察字段（`fetch`/`read_addr`/`write_addr`/`mmio_addr`/`trigger_writes`/`dma_reads`/`dst*`） | `:831-897` |
| `summary` | 汇总（cases/ticks/fetches/ram_reads/ram_writes/apb_*/irq_*/dma_*） | `:935` |

**相对 F5/F6 专用 host 的信息差**（待 §3 逐条判定是否算 `missing`）：
- 没有 `mret` 事件（F5/F6 host 有），中断返回只体现在后续 `retire` 流里；
- 没有 `irq_source` 命名，改用 `irq_edge <index> <tick>`（多源时用 index 区分）；
- 没有独立的 `ip_read`，但 `apb` 行的 `prdata` 覆盖了 ISR 读值；
- `retire` 只有 `pc/insn`，没有 RVFI 写回值、没有 trap 记录（trap 直接抛异常终止），没有压缩指令标志。

## 3. 第一部分：六条数据流事件完善性

来源：`runs/stage2-verify-events-20261101/`（`events_matrix.md`、`events_report.json`、`run.log` 297 行、`analyze_events.py`）。六例 `observations_passed`、`correspondence` 全 `matched`、`summary` 的 `unknown_fields=[]`。

**逐流事件计数**（每格为该流日志中的事件条数；括号为首行行号）：

| 事件族 | F1 | F2 | F3 | F4 | F5 | F6 |
|---|---:|---:|---:|---:|---:|---:|
| `retire` | 22 (1) | 11 (26) | 13 (43) | 15 (62) | 46 (85) | 78 (163) |
| `cpu_data` | 2 (14) | 5 (28) | 5 (45) | 5 (64) | 21 (87) | 33 (165) |
| `cpu_mmio` | 0 | 0 | 0 | 1 (79) | 4 (120) | 0 |
| `cpu_control` | 0 | 0 | 0 | 0 | 0 | 6 (222) |
| `apb` | 0 | 0 | 0 | 1 (81) | 4 (122) | 0 |
| `irq_edge` | 0 | 0 | 0 | 0 | 1 (135) | 1 (261) |
| `irq_take` | 0 | 0 | 0 | 0 | 1 (137) | 1 (264) |
| `dma_read` | 0 | 0 | 0 | 0 | 0 | 4 (245) |
| `dma_write` | 0 | 0 | 0 | 0 | 0 | 4 (254) |
| `dma_control` | 0 | 0 | 0 | 0 | 0 | 6 (224) |

**已确认缺失（`absent`，审计脚本判定日志中完全没有）**：
- `ifetch`：逐拍取指地址/指令字（只有 `retire` 的 pc/insn）；
- `rvfi_extra`：`rvfi_order` / `rd_addr` / `rd_wdata` / `pc_wdata` / `mem_*`；
- `trap`：`rvfi_trap` 作为**被观察事件**（当前 trap 直接抛异常终止，不是记录）；
- `bus_error`：OBI i/d 或 APB 的错误响应；
- `dma_done`：DMA 完成 / busy 撤销（只有 `dma_read`/`dma_write` 与 IRQ）。

**审计结论（`runs/stage2-verify-events-20261101/events-audit-20261101.md`）：最小动作观测完备，事件不完善。**

- 动作层：真实取指、RVFI 退休 185 条、真实 RAM/APB 读写、真实 IRQ 输出 + CPU take、真实 DMA 主设备搬运，均有 RTL 证据；
- 事件层：只有 10 类打印行，缺指令写回、退休序号、trap、逐拍取指地址、cause 语义、错误/负路径与 unknown 三值；
- **模型本来就有、只是没采**（只读探针复制 spike 加 3 处打印即证）：`ifetch` 239 行、`rvfi_order` 1..185 严格递增、101 拍带 `rd_addr/rd_wdata`、`rvfi_intr=1` 两处、`exp_valid` 恒 0（压缩指令未被激励）。

**「看起来有但不足以证明」**（本轮实测）：
1. F5 pulse 是主机按 `config:11` 拉宽到 16 tick，设备本身只高 1 tick（`timer.sv:58-59`）；
2. F5 `isr_result 0x10` 是 timer 的 **count** 寄存器（`timer.sv:13/116-118`），不是 cause；
3. F6 `ctl_status 0x40` 是 CONTROL_STATUS 的 `o_transferlen`（`zipdma_ctrl.v:116-121`），busy=0 未被检查（判据只 `!=0`，`spike:815`）；
4. `summary` 的 `instruction_fetch_evidence/retirement_evidence=observed` 是**无条件常量**（`spike:956-957`），不是测量；
5. 与旧路径对照：新循环退休证据更强，但 `instruction_hops`/`joins`/`memory_read_observation`/RAM 版本全部缺失，两者不可互相替代。

**最重要 5 条补强**：① 采 `rvfi_rd_addr/rd_wdata/order`（`rt_lh_p_85/87/82`，`spike:565-577`）；② 打印逐拍 `ia`（`spike:617-627`）；③ 设备 profile 补 cause/完成位声明，DMA 判据改用 busy/err 并在 start 前后各读一次；④ IRQ 多源 + 设备高/送达高分离（`spike_config.h:55-57`）；⑤ error/trap 改为 case 级 unknown 而非整轮 abort（`spike:566/680/916`）。

### 3.1 事件层补强结果（2026-11-01 已实施并真机验证）

来源：`runs/stage2-events-fix-20261101/README.md`（改动仅 3 个文件：`inprocess_obi_apb_f1f4_spike.cpp`、`run_inprocess_f1f6.py`、`test_inprocess_f1f6_entry.py`）。同输入 before/after 各跑一次，after 与 repeat 逐行一致。

| 补强项 | 状态 | 证据 |
|---|---|---|
| 逐拍取指地址 `ifetch <tick> <ia> <word>` | **observed** | 243 行（F1..F6=31/16/17/19/58/102），`cpp:787-792` |
| 寄存器写回 + 退休序号 `rvfi <tick> <order> <rd_addr> <rd_wdata>` | **observed** | 189 行、其中 104 拍有写回；order 1..189 严格递增；例 `run.log:116 rvfi 88 32 7 0xdeadbeef` |
| trap 作为被观察事件 | **observed（0 次）** | 路径已事件化且失败不再整轮 abort（`cpp:698-707`）；本 run 无 trap |
| 总线错误 | **unknown / 部分** | APB `pslverr` 已接并逐笔采样（0 次置位）；OBI i/d 与 WB 的 error 是宿主输入、模型无输出 → 逐通道标 `unknown`，未硬接 0 |
| DMA 完成 `dma_done <tick>` | **observed（推导）** | 1 条（`run.log:660`），推导=最后一笔主写完成(467)+完成 IRQ 边沿(471)，summary 明示 `dma_done_derivation` |
| unknown 三值 | **已落地** | `instruction_fetch_evidence`/`retirement_evidence` 改由实测计数推导（原为常量）；`expanded_insn_evidence=missing`（压缩指令未激励）、`dma_busy_evidence=missing`（无 busy 输出、未采到 busy=1）、`irq_cause=unknown` |

**4 处反夸大已修**：① F5 `device_high_ticks 1 / delivered_high_ticks 16`、F6 `35/35`（分离计数）；② F5 改 `isr_read_register_kind count` + `isr_cause unknown`（旧 `isr_result` 保留未改名）；③ F6 完成判据改为 `busy(31)==0 && err(30)==0` 且 start 前后各读一次（`ctl_reads 1→2`）；④ 生成 `DMA_CLEAR_DECLARED/DMA_CLEAR_MASK` 宏，host 只按宏决定是否期望 clear。

**回归**：6 条 case 行逐键比较——移除键 0、改名键 0；仅 F6 数值变化（`i_fetches 98→102`、`d_writes 12→13`、`ctl_reads 1→2`、`ticks 214→224`），F1–F5 ticks 不变。单测 `test_inprocess_f1f6_entry.py` **130 passed**。

**仍 unknown/missing（如实）**：OBI/WB 总线错误（模型无 error 输出）、`irq_cause`（timer 无状态位）、`expanded_insn`（`rvfi_ext_expanded_insn_valid` 恒 0）、`dma_busy`（模型只导出 `o_interrupt`）。

## 4. 第二部分：通用化（同协议接入档位）

来源：`runs/stage2-verify-generality-20261101/`。

| 替换 | 结果 | 档位（初判） |
|---|---|---|
| CPU：Ibex → **CV32E20**（OBI） | `cpu-cv32e20/summary.json`：**6 例 `observations_passed`**；`cpu_request.json` 指向 `configs/cpus/cv32e20/component_profile.json` | **config-only**（只改配置里的 cpu_profile） |
| IRQ IP：PULP Timer → **PULP SPI**（APB） | 已准备 `profiles/pulp_spi_irq_declared` 与 `irq-spi-unmodified`/`irq-spi-derived` 两组请求，尚无 `summary.json` | 待定 |
| DMA：ZipDMA → **wbdmac**（Wishbone） | `dma-wbdmac-patched`：`status=failed`、0 例；`analysis/run_f1f6_dma_units_patch.py` 是打过地址单位补丁的入口副本 | 初判 **code-change**（地址单位 `byte_address_shift_right_2`），补丁版仍失败，具体阻断待报告 |

基线对照：`baseline-f1f6` 6 例 `observations_passed`。

**审计结论（`runs/stage2-verify-generality-20261101/README.md` + `refusals.json`）：同协议接入目前是代码级，不是配置级。**

| 替换 | 改动量 | 结果 | 第一处拒绝 | 档位 |
|---|---|---|---|---|
| CPU Ibex→CV32E20（OBI） | 1 个字段 | 6/6 通过 | 无 | **config-only** |
| IRQ Timer→PULP SPI（APB3） | 7 字段 + profile 声明 9 行 + 1 行代码 | 原样拒 → 补声明仍拒 → 放开 `pulp_spi_contract.py:89` 一条谓词后 F5 通过（1 边沿/1 take） | `run_inprocess_f1f6.py:190`；补声明后 `pulp_spi_contract.py:89` | **code-change** |
| DMA ZipDMA→wbdmac（WB） | 2 字段 + ~7 行/2 文件 | 打补丁后 6/6 通过 | `run_inprocess_f1f6.py:218` | **code-change** |

关键事实：
- CPU 是真 config-only（`cpu_request_from_config()` 只透传 `profile_path`，模型名两侧都是 `local_runtime_cpu`）；副作用：`cv32e20` profile 的 description 仍写“no runtime claim”，与实测不符。
- SPI 的 IRQ 声明层可补（需 `interrupt_source` 端点 + 带 `source_id/clock_domain/pulse_width_cycles` 的 `interrupts` 行），但被代码策略挡住；语义缺口须保留：`INTSTA(0x28)` 读回 0（无 read-mux），触发靠 EOT 事件而非状态位。
- wbdmac 的 CSR 语义是 `wbdmac_source_contract.py:15-28` 的代码常量 + `SOURCE_SHA256` 钉死，profile 改不动；最小改动两处（单位谓词 1 行 + clear 期望交给 header 宏）。
- 反例成立：三个不支持组合都在入口抛具名 `ValueError`（exit 1），`test_inprocess_f1f6_entry.py` 94 passed 覆盖；错填记录值时报 `case exceeded its tick budget`，不静默通过。

### 4.1 档位提升结果（2026-11-01 已实施并真机验证）

来源：`runs/stage2-generality-fix-20261101/README.md`。改动只在三个合约文件（`pulp_spi_contract.py` +76/−3、`wbdmac_source_contract.py` +65/−1、`wishbone_dma_fields.py` +15），**`scripts/**` 未改**（事件层与 `DMA_CLEAR_*` 宏由另一代理同期落地）。

| 替换 | 结果 | 档位 |
|---|---|---|
| CPU Ibex→CV32E20 | 1 个字段，6/6 | **config-only**（不变） |
| IRQ Timer→PULP SPI | SPI 声明 pulse 源（强制 `pulse_width_cycles`、禁 latch/clear、禁 level），`spi-f5-eot` **2/2**、`spi-f5-eot-pulse4`（pulse 16→4）**1/1** | **profile+config** |
| DMA ZipDMA→wbdmac | 声明 `source_destination_units=byte_address_shift_right_2`/`master_address_shift=2`/`length_unit=words`/`irq_clear=none`，与 pinned 源交叉校验（漂移报 `wbdmac-declaration-source-drift:<field>`）；`dma-wbdmac-f1f6` **F1–F6 6/6**、`dma-wbdmac-f6-two` **2/2**；基线 ZipDMA 回归 6/6 | **profile+config** |

**未改共享 profile**：`configs/peripherals/zipcpu_wbdmac/component_profile.json` 逐字节未动，声明放在新变体 profile `configs/peripherals/inprocess_generality_wbdmac/` 里，共享 profile 继续走 pinned 默认（同一份被校验的真值）。

**语义缺口仍保留**：SPI 的 `INTSTA(0x28)` 读回 0（无 read-mux）、触发来自 EOT 事件；`irq_cause=unknown`。

## 5. 第三部分：协议与 IP 广度

来源：`runs/stage2-verify-breadth-20261101/breadth-audit-20261101.md` + `inventory.json`（快照 2026-11-01 01:25）。

**结论：架构验证够，广度宣称不够。** 统一循环只覆盖 **1/5 CPU 总线、1/5 IP 总线、1/5 IP 家族**；UART 与 AXI4-Lite 完全缺席；wbdmac 被统一循环拒绝；GPIO/I2C 无入口。

覆盖矩阵（节选；完整表见审计报告）：

| 行 | 仓库 RTL+profile | 阶段一/二 | 单进程统一循环 | 接入缺口 / 量级 |
|---|---|---|---|---|
| AXI4-Lite（CPU） | ✔ picorv32_axi | ✔ F1–F4 | ✖ | host AXI4-Lite master + RVFI；~300–500 行 |
| AHB-Lite（CPU） | ✔ CVW | ✔ F1–F4 | ✖ | host AHB master + RVFI；~400–600 行 |
| Wishbone（CPU） | ✔ picorv32_wb | ✔ F1–F4 | ✖ | host WB master（RVFI profile 已有）；~250–400 行 |
| TL-UL（IP） | ✔ OpenTitan GPIO 等 | ✔ F2/F4（仅 GPIO） | ✖ | TL-UL target + pins；无 TL-UL CPU；~400–600 行 |
| 完整 AXI4（CPU） | ✔ Vexii/CVA6 | ✔ F1–F4 | ✖ | full AXI4 master + RVFI；IP 侧无完整 AXI4 target；~600–900 行 |
| UART | ✔ WB/AXI4-Lite/TL-UL | ✔ WB F1–F4；AXI F2/F4 | ✖ | 先补对应 IP host；rx/cts + IRQ；400–600 行 |
| SPI | ✔ PULP APB3 | ✔ F1–F4 | △ 仅 F5 入口 | 配置 + re-arm |
| I2C | ✔ PULP APB3 | ✔ F1–F4 | ✖ | PULP 无 IRQ 端点 |
| Timer | ✔ PULP/Zip/OT | ✔ F1–F4 | ✔ PULP | — |
| GPIO | ✔ PULP/OT | ✔ OT F2/F4；PULP 仅 E2 证书 | ✖ | 缺 pin 模型；配置级 + 100–200 行 |
| DMA | ✔ ZipDMA/wbdmac | F6 ✔ 两者 | ✔ ZipDMA；✖ wbdmac | 地址单位契约 |

**最值得做的 3 项**：① AXI4-Lite IP target + ZipCPU AXI UART（~400–600 行，一次覆盖 IP 总线与 UART 两个第一优先级）；② 第二颗 CPU（配置级，CV32E20 已验证）+ 第二条 CPU 总线（WB，~250–400 行）；③ PULP GPIO 进统一循环 + pin 模型（配置级 + 100–200 行，补“引脚 I/O”这一完全缺失的维度）。

**不要做**：为没有真实 RTL 的协议写适配器（IP 侧完整 AXI4 target 不存在、无 TL-UL CPU）；塞组合专用分支；在单 IRQ + RAM-only 稳定前扩多 IRQ / DMA→IP FIFO / 部分字节使能；把 profile/elaboration 当覆盖；追求 CPU×IP 笛卡尔积。

### 5.1 广度补强结果（2026-11-01）

**③a AXI4-Lite IP target + ZipCPU AXI UART：已跑通（`observed`，F1/F2/F3/F4 + 跨例读回）**
- 新增 `scripts/inprocess_obi_axi4lite_spike.cpp`(699) + `scripts/run_inprocess_axi4lite.py`(673) + 配置 + 单测(568)，未改 `src/`、既有 host/入口。
- 接线：OBI beat 命中 `0x40001000/16` 时变成 target 事务 → 生成 wrapper 的 `axi4_lite_mmio_bridge` 驱动 axiluart 的 19 根从端口；宿主只读 `trace_*` 被动 tap；`valid&&ready` 同拍判完成；读数据与回填 CPU 的 `rsp_rdata` 强校验。
- 实测（`runs/stage2-breadth-axi4lite-20261101/`）：F2 读 SETUP → AR@40/R@42 `RDATA=0x19`(25=INITIAL_SETUP)；F4 写 0x5a5a → AW/W 同拍 `addr=0, data=0x5a5a, strb=15`、B 次拍 `resp=0`；再 F2 → R@122 `RDATA=0x5a5a`（**跨例保留、未复位**）；F1 fetch/retire 0x12000/0x2ab00693；F3 `0x11111111→0x0badf00d`、be=15。
- summary：`axi_transfers 2`、aw/w/b/ar/r 各 1、`bresp_okay/rresp_okay=1`、**`error_response unknown`**（从设备恒 OKAY，错误路径未激励，如实标注）。
- 未接：F5 IRQ（UART 4 个 level IRQ 未接线）、F6 DMA；只整字（WSTRB 恒 15）；单 outstanding；两模型同 50 MHz；RVFI 仅 valid/trap/insn/pc_rdata（无写回值/退休序号）。
- 合并进统一循环还差：AXI UART 的 IRQ → F5、DMA 落 IP 窗口、host 按 `base_protocol_trace.protocol` 选观测段、协议中立 target 字段替代 `axi_*`/`apb_*`。

**③b PULP GPIO + 真实 pin 模型：已跑通（`observed`，11 例 + 5 例在线）**
- 新增 `scripts/inprocess_obi_apb_gpio_spike.cpp`(835) + `scripts/run_inprocess_gpio.py`(935) + 配置 + 单测(438)，未改 `src/`、既有 host/入口。
- pin 接法：每 tick `eval → 采器件 gpio_out/gpio_dir/gpio_in_sync → pad=(out&dir)|(ext&~dir) → 回驱 gpio_in → 再 eval → 采 interrupt 与 probe_gpio_{rise,fall,padin_latch,inten,status} → 上升沿`；`ext` 是**配置声明的宿主常量**（报告已注明），pad 值不来自常量。
- 实测（`runs/stage2-breadth-gpio-20261101/run1`）：F4 PADOUT=`0x2a` → `out_after=0x2a`、`pad_after=0x2a`、`rise_mask=0x2a`；F2 读 PADIN=`0x2a`（写→pad→同步链→读回的真实回环）；P 流 `ext=0xaaaa→0x5555` → `read_value 0xaaaa→0x5555`、`rise/fall_mask` 对应；causal F5：pin 534 pad `0x2a→0x2b` → pin 536 rise edge → `irq_edge cause 0x1` → take 1 → ISR 读 `INTSTATUS(0x24)=1`、读后 status=0（读即清）。
- 反例：P 地址指向 PADOUT → 具名拒绝；F5 引脚不跳变 → `case exceeded its tick budget`，不静默通过。

**③b Wishbone CPU 总线：已跑通（`observed`，5 例 + 5 例在线）**
- 新增 `scripts/inprocess_wb_cpu_spike.cpp`(566) + `scripts/run_inprocess_wbcpu.py`(596) + 配置 + 单测(262)；CPU `picorv32_wb_irq_rvfi`，IP PULP Timer(APB3)。
- RVFI 无阻断：`valid/order/insn/trap/pc_rdata/rd_addr/rd_wdata/mem_*` 全在 physical_exports。
- 实测（`runs/stage2-breadth-wbcpu-20261101/run1`，`wb_transfers 91`/`wb_retires 62`/435 ticks）：F1 fetch/retire `0x2000`、order 12/12 严格递增、`rd_wdata=0x2ab`；F2 RAM `0xdeadbeef`；F3 存 `0x0badf00d`；F4 APB 写 `0x8=0x123`；在线第二例先使能 timer 读 `0x49`、写 CMP 后读 `0x07`（RTL `write_resets_count`，同进程无复位）。
- **具名阻断**：该 build 的 CPU 32 位 `irq` 输入恒驱 0（`inprocess_wb_cpu_spike.cpp:301`）→ 无 F5/F6；零等待回应 → WB stall 分支未激励；仅整字 beat。

**并入统一循环还差（两份 REPORT.md 已列）**：GPIO 需 `render_bindings` 支持 `apb_gpio` 的 pin/probe 绑定、`case` 行加 pad 字段与 correspondence 分支；WB 需 `cpu.kind` 支持 `picorv32_wb`、RAM 基址跟 boot contract、32 位 IRQ 的 take 判据另立。

## 6. 优化后的重证与前后对照

来源：`runs/stage2-opt-20261101/REPORT.md`、`runs/stage2-opt-20261101-diag/compare_ab.py`、本机复核 `runs/stage2-verify-opt-rerun2/`、`runs/stage2-ab-f5-on2|off/`。

**优化内容（4 项，均不改观察口径）**：① 同一进程内按内容身份 memo 纯数据结果（PhysicalFacts、source-lock 文档、build identity+snapshots）；② `render_local_runtime`/`render_local_driver` 的对象缓存收进 `static_validation` **scope 内**（不跨 preparation 共享活对象）；③ 退出边界按**输入内容身份**复用已接受的校验结果（任一字节变化、含同尺寸回填 mtime 用 ctime 检测，都必须重跑）；④ 入口侧校验一项未删。默认 `MYFUZZ_IDENTITY_REUSE=1`，`=0` 只用于 A/B（只会增加工作）。

**A/B（同一棵树、同一输入、同一缓存；热缓存 2 次中位数，秒）**：

| 类 | 臂 | wall | body | exit | `_elaborate_profile` | `render_local_driver` | DUT |
|---|---|---:|---:|---:|---|---|---|
| F5 | reuse=0 | 13.57 | 4.40 | 7.90 | 12 次 / 4.60–4.85 s | 8 次 / 2.42–2.50 s | 1.77 ms |
| F5 | reuse=1 | **5.30** | 4.50 | **0.51** | **2 次 / 0.79–0.86 s** | **4 次 / 0.07–0.10 s** | 1.79 ms |
| F6 | reuse=0 | 12.94 | 3.17 | 8.09 | 同上 | 同上 | 1.48 ms |
| F6 | reuse=1 | **5.76** | 3.22 | **0.86** | 同上 | 同上 | 1.52 ms |
| F1F4 | reuse=0 | 12.57 | 4.39 | 7.91 | 同上 | 同上 | 1.43 ms |
| F1F4 | reuse=1 | **5.23** | 4.45 | **0.51** | 同上 | 同上 | 1.33 ms |

冷缓存：23.6–23.8 s → **16.0–16.7 s**（其中链接编译 ≈4.5–4.8 s）。以上为最终树上的复测数（`runs/stage2-opt-ab-artifacts/measurements-reuse-{on,off}.json`）。

**本机独立复核**：
- `pytest tests/runtime -q`：优化前 **692 s / 729 passed** → 优化后 **220.87 s / 729 passed**（我自己的运行；代理两次复现 212–214 s）。
- F5 薄入口（`run_inprocess_flow.py --flow F5`，同一输入、同一缓存）：`reuse=1` entry **5.35 s** vs `reuse=0` entry **12.64 s**。
- F1–F6 同进程重跑（`runs/stage2-verify-opt-rerun2/`）：6 例 `observations_passed`、warm total **5.15 s**；`run.log` 与优化前 `runs/stage2-stepD2-f1f6/run.log` **仅 `case … seconds` 行不同**，case/tick/takes/status/观察字段全同；`summary.json` 与另一臂 0 字段差异；`driver.cpp`/`runtime.sv` 与改动前逐字节相同。

**仍存在的地板（非重复，未动）**：热 body ≈4.7 s 中约 **2.6 s** 是每进程一次的 `_discover_host_sources()`（520 文件 / 12.8 MB AST 走查，`host_source_discovery_scope` 按设计每进程一次），≈0.85 s 是每模型一次真实 Verilator elaboration，≈0.35 s 是 3 次 source gate。要压到 ~2 s 量级需要给 host-source 发现加“内容校验的持久缓存”——这是“一次 run 该重算什么”的策略决定。**2026-11-01 决定：先不做**（缓存键漏项即可观测性风险；当前 5.2 s/次、DUT 仅 1.5 ms 已够用；如将来要做，须单独做一次缓存键完备性审计）。

## 7. 不声称

- 不声称 DUT 内部正确性（Verilator 未编译 `--assert`）；
- 不声称退休/RAM 版本/跨例来源已验证（原型里这些多为 `unknown`）；
- 不把 `directed` 或单例运行说成通用支持；
- 三模型同 tick（`assume_single_clock`）、F5 pulse 由主机拉宽、DMA 仅 RAM 全字——这些限制在结论里必须保留。
