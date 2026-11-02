# 当前系统能力与代码整理盘点

日期：2026-11-01；最后更新：2026-11-02。

> **时点约定（2026-11-02）**：本文件保留 2026-11-01 及更早的全部小节，作为 **prior state（当时状态）**。它们仍描述当时的源码与真实批次，但不代表 2026-11-02 的能力；当前状态以「2026-11-02 增量」一节和已保存的 run 证据为准，冲突处在原小节内就地标注「2026-11-02 更正」。本次只改文档，未改脚本、RTL、测试、配置或 run 目录。

下文区分当前源码、历史运行结果和仍未验证的范围；先前 10 月 31 日的原型方案是历史设计，不反映所有最新实现。

## 当前架构和入口

系统使用独立的 CPU、外设和 DMA RTL 模型，宿主模拟 RAM、总线转发及 IRQ 等连接，不要求连接实际 SoC。核心入口分为两条路线：

| 路线 | 代码入口 | 当前用途 |
| --- | --- | --- |
| 既有通用执行 | `scripts/generate_mmio_scenario.py`、`scripts/run_generic_scenario.py`、`src/myfuzz/integration/compiled_mmio.py` | profile 派生场景及旧执行器，F1–F4 有多协议运行记录；较完整的记录和复核能力 |
| 单进程原型 | `scripts/run_inprocess_f1f6.py`、`scripts/inprocess_obi_apb_f1f4_spike.cpp` | 选定组件一次初始化，在同一循环按配置执行可支持的 F1–F6 |
| 专用实验和反馈 | `scripts/run_inprocess_irq.py`、`scripts/run_inprocess_f6.py`、`scripts/inprocess_feedback.py`、`scripts/run_inprocess_flow.py` | 独立 F5/F6 的定向运行和简单反馈；不等同于统一入口已接入通用反馈搜索 |

脚本入口导航见 [scripts/README.md](../scripts/README.md)。选用路径时不要把不同入口的协议范围、性能数字或证据等级混在一起。

## 六条数据流

| 流 | 真实行为 | 当前结论 |
| --- | --- | --- |
| F1 | CPU 从程序内存取指并执行 | 代表性统一循环可观测取指及退休；不是任意 RISC-V 指令支持 |
| F2 | CPU 读 RAM 或 IP | 代表性 APB、AXI4-Lite 目标等有实际读取记录 |
| F3 | CPU 写 RAM | 代表性组合有实际 RAM 写入及读回记录 |
| F4 | CPU 写外设 | 代表性组合有实际 MMIO 接收记录 |
| F5 | IP 产生 IRQ，CPU 接收并运行处理程序 | Timer、SPI、GPIO 等有具体记录；IRQ 路由与设备语义依赖声明和实际能力 |
| F6 | CPU 配置 DMA，DMA 发起真实读写 | ZipDMA、wbdmac 有实际 RAM 搬运及中断记录；未覆盖所有 DMA 行为 |

### 单进程统一入口已记录的组合

| CPU / 目标 / DMA | 已运行 | 重要限制与证据 |
| --- | --- | --- |
| Ibex OBI / PULP Timer APB / ZipDMA Wishbone | F1–F6 | 六条记录在同一次初始化中运行；见 [基线摘要](../runs/stage2-stepD2-f1f6/summary.json) |
| CV32E20 OBI / Timer APB / ZipDMA Wishbone | F1–F6 | 替换 CPU profile 后六例通过；见 [通用化记录](../runs/stage2-generality-fix-20261101/README.md) |
| Ibex OBI / Timer APB / wbdmac Wishbone | F1–F6 | 通过新的 DMA profile/能力声明运行；DMA 寄存器行为仍有专门契约，见 [通用化记录](../runs/stage2-generality-fix-20261101/README.md) |
| Ibex OBI / PULP SPI APB | F5 | 特定 EOT pulse 行为有运行记录；状态读回 0，不能称为已证明中断原因；见 [通用化记录](../runs/stage2-generality-fix-20261101/README.md) |
| Ibex OBI / ZipCPU UART AXI4-Lite / ZipDMA | F1–F4、F6 | F5 因目标 IRQ 行为未接入而拒绝；见 [AXI4-Lite 记录](../runs/stage2-unified-axi4lite-20261101/README.md) |
| Ibex OBI / PULP GPIO APB | F1–F5 | 含引脚激励和因果 IRQ；配置无 DMA，F6 拒绝；见 [GPIO 记录](../runs/stage2-unified-gpio-20261101/README.md) |
| PicoRV32 Wishbone / Timer APB / ZipDMA | F1–F6 | 通过声明 `cpu_irq_bit` 的 PicoRV32 custom IRQ ABI 接入；固定六例 6/6，连续 fuzz 120 例 116 通过、80 例第二 seed 全通过；见 [连续六路径证据](../runs/stage2-wb-six-20261101/README.md) |
| CVW AHB-Lite / Timer APB | F2–F4 | 统一入口新增 `ahb` 分支；固定 14/14、连续 80/80；F1（无 RVFI）、F5（无 IRQ 输入）、F6（无 DMA）按名拒绝；见 [AHB 接入](reports/inprocess-ahb-unified-20261101.md) |
| CVA6 packed AXI4 / PULP Timer APB / 无 DMA | F2–F4 | 统一入口新增 `axi4` 分支；固定 3/3、连续 fuzz 30/30；F1（无 RVFI 退休）与 F5（无退休/trap 见证）按名拒绝；单 outstanding、IP beat 必须一个完整 32 位字；见 [AXI4 集成](reports/round1-axi4-integration-20261102.md) |

上述结果只证明各行实际运行的组合与场景；不能外推所有组合或每个总线支持全部六条路径。统一入口的 `--online` 是逐条交付预先指定的记录；反馈驱动的生成器现在由同一入口的 `--fuzz` 提供（见下节），`--online` 仍保留为固定输入路径。

既有执行器还有 OBI、Wishbone、AHB-Lite、AXI4-Lite 及完整 AXI4 CPU 的代表性 F1–F4 结果；目标侧另有 APB、Wishbone、AXI4-Lite、AHB-Lite、TL-UL 的不同范围记录。协议覆盖不等于所有目标自动生成：`generate_mmio_scenario.py` 目前只自动选择 APB3/Wishbone 读写目标。详见 [阶段一审计](reports/stage1-completion-audit-20261031.md) 和 [总路线](universal-system-roadmap.md)。BOOM 的通用路径已到实际运行，但首个 F4 未观察到 MMIO 事务，不能算通过，见 [BOOM 运行记录](../runs/boom-f2f4-run-20261031/README.md)。

## 2026-11-02 增量：IRQ 触发/清除分离、多 link F5、完整 AXI4 F2–F4 与未接入模块

本节只写有已保存 case 行/summary 支持的事实；不声称覆盖率、证书、完整 replay，也不声称通用设备因果。命令、逐行日志与 JSON 判定在各 run 目录及对应报告中。

### IRQ/F5 通用化：触发与清除分离、cause 采样

- **触发写与清除写分开计数**：一次目标写若在 CPU 接受中断后命中声明的 clear 偏移/值，计入 `clear_writes`，否则计入 `trigger_writes`；F5 通过判据同时要求两者等于声明值。此前 `clear_writes` 与 F5 判据冲突的问题已解决。
- **cause 来自真实状态读**：入口 `irq_declaration.status_cause_bits` → 宿主 `IP_CAUSE_MASK`；case 行 `isr_cause` 取自 ISR 对声明状态字的真实读值（`target_read_data & cause_mask`），不再由声明直接打印。未声明 cause 就是 `unknown`。
- **level 源必须可清除**：声明为 level 的源必须给出 clear 写或 `read_clears` 状态字，否则在入口按名拒绝（避免中断风暴）。
- **case 末电平检测**：每个 level link 在 case 末采样原始输出（`irq_level_final`/`level_stuck`）；失败时只复位 IP/DMA、保留 CPU/RAM，不再把持高电平当作 `not_triggered`。
- **无 link 构建**：F5 的打印与判据按 `IRQ_TARGET_LINK_COUNT` 编译，AXI4 等没有 F5 link 的构建不会引用不存在的表。
- 证据：[IRQ 通用化报告](reports/irq-generalization-20261102.md) §1；判据测试 `tests/fuzz/test_irq_clear_cause.py`。

### 多 link 目标 F5（PULP Timer link0 overflow / link1 compare）

- 行为声明升级到 v2 有序 `irq_sources`（1..8 个 link，每 link 各有端口/位/状态字/cause/clear/触发序列），F5 record 变为「链路号:触发值...」。一例只服务一个 link，不把两个源 OR 进同一次状态读。
- 真实 RTL 批 `runs/round1-smoke/multilink/`（Ibex OBI + PULP Timer APB3 + ZipDMA）：**7/7 `observations_passed`**。两条 F5 分别是 link0 count/交付 16 tick、link1 compare/24 tick，状态读为 `0x40001000=0x0` 与 `0x40001008=0x3`；均 `trigger_writes_observed 3`、`clear_writes 0`、`irq_takes 1`、`irq_level_final 0`；summary `cases 7 failures 0`、`irq_sources 3`、`irq_target_links 2`。
- 两例差异全部来自声明的 link，没有新增 CPU×IP 代码分支；cause 位在这两条声明里未给出，保持 `unknown`。

### PULP I2C level IRQ：一次清除写与跨例干净

- 新增 profile/行为/场景（只声明，不改 RTL）：真实 `interrupt_o` 导出，`irq_flag && s_ien` 为 level、`CMD[0]` 为 iack；`STATUS` 0xc 的 bit0 是 cause，`clear_writes=[[0x14,1]]`。
- 批 `runs/round1-smoke/i2c-level/`：**3/3**。两条 F5 都是真实 level：`trigger_writes 3`、`clear_writes 1`、`last_clear_offset 0x14`/`last_clear_data 0x1`、`isr_cause 0x1`、`apb_read_data 0x81`、`irq_level_final 0x0`；其后的 F2 也通过，没有 `level_stuck`。
- **负控制已修复**：错误 clear（`CMD=0x10`）导致电平稳高时，`irq_takes > 4` 即记录 `level_stuck`、停止该 case、只复位设备并等待 handler 清命令字；`runs/round1-irq-storm/stuck` 为 2 例（case0 failed/level_stuck 1/device_resets 1，case1 F2 passed），不再 0 例；正确 I2C 3/3、multilink 7/7 不变。

### PULP GPIO cause（读清状态）

- 批 `runs/round1-smoke/gpio-cause/`：**3/3**。F5 行 `isr_cause 0x1`、`isr_read_value 0x1`、`status_after_read 0x0`、`irq_cause_pins 0x1`、`first_transition_tick 225 == first_irq_tick 225`、`irq_level_final 0x0`；F4 先写 PADDIR=1 是设备方向寄存器的真实前置条件，不是宿主造值。
- 这只证明该读清状态下 cause 位采样与引脚边沿同 tick；不外推到其他 GPIO 或别的 cause 布局。

### 完整 AXI4（CVA6）统一入口：F2/F3/F4 固定与 fuzz

- 统一入口与共享宿主新增 `axi4` 分支（`scripts/inprocess_axi4_host.h` 的 `CpuLink`），经仓库既有 `axi4_processor_memory_adapter` 驱动 pinned CVA6 packed AXI4。
- **固定批** `runs/round1-axi4-unified/fixed-f2f4/`：`F2:00014000`、`F3:00014004:0badf00d`、`F4:40001008:0fffffff` → **3/3 `observations_passed`**；77 AR / 77 R（68 取指、9 数据）、11 AW/W/B、88/88 beat req/rsp、`cpu_axi_beat_errors 0`；boot fetch `0x10000` @ tick 251（ARID 0），firmware fetch `0x11000` @ tick 335，`poll_reads 3`。
- **连续 fuzz** `runs/round1-axi4-unified/fuzz-30/`：**30/30 通过、0 失败**（F2 18 / F3 7 / F4 5），`correspondence_checked 30`、`mismatched 0`、`findings 0`。
- 根因与修复：适配器 beat 的 `req_ready_i` 在适配器采样用的上升沿之前被撤销，适配器卡在 `READ_REQUEST`，16 字节 boot fetch 只服务了两拍；修复为把 `req_ready_i` 保持过捕获 tick 的上升沿，答案在边沿后提交、下一低相驱动响应。
- 详见 [AXI4 集成报告](reports/round1-axi4-integration-20261102.md)、`runs/round1-axi4-unified/README.md` 与 `summary.md`。

### AXI4 的按名拒绝与限制

- **F1/F5 拒绝**：该归档不导出 RVFI，`retirement_observation none:cva6_no_rvfi_exported`；F1 拒绝 `unsupported-f1:no-retirement-observation:cva6_packed_axi4`，F5 拒绝 `unsupported-f5:no-retirement-or-trap-witness:cva6_packed_axi4`。取指不是退休。
- **单 outstanding**：既有适配器一次只允许一个 beat，ARLEN 0 或合法两拍 INCR 读；更长 burst/LOCK/ATOP 由适配器 DECERR。
- **IP beat 必须是一个完整 32 位字**：合并了 IP store 的 64 位 beat 按名拒绝（消息带 64 位地址与 WSTRB），不拆分也不伪造；已保存批次未出现该合并。
- **uncached 槽**：程序槽 `0x12000` 在配置的非缓存 `0x10000..0x20000` 窗口内，因此不声称 `fence.i`/缓存一致性；CVA6 I$ 仍保留。
- 只声称这一个 pinned CVA6 packed AXI4 配置（ARID 0/RID 0 = I$，其余 = D$）；该构建 CPU IRQ 输入恒零，没有 F5 交付，也没有 F6。

### 已实现但尚未接入/未跑（树内模块）

| 模块 | 现在有什么 | 缺什么（因此不能声称的能力） |
|---|---|---|
| 多 IP 地址路由（**已接入，2026-11-02**） | `targets[]` + `declared_targets`/`target_windows`/`route_address`/`target_for_f5`；入口为每目标建独立 artifact，header 输出 `IP_COUNT`/`IpTarget<n>` trait，宿主按窗口路由并保留每目标计数；Ibex + Timer + I2C 固定 6/6、fuzz 30（27 通过/3 正常未触发）、换 IP 5/5；测试 83 条 | 同一目标协议（混合 APB3+AXI4 按名拒绝）；只允许一个 F5 目标；多目标 pin 模型拒绝；DMA 目标路由只有固定目的写（见下方 DMA 行），读路由/多目标路由没有 |
| DMA 传输扩展（**第一、第二增量已接入**） | `dma_transfer_declaration`/`validate_transfer_plan` 接入入口：ZipDMA block 1..8、设备 size-derived 字节使能、2-tick 背压、wbdmac 回归；**DMA→PULP SPI TXFIFO 固定路由真实跑通**（8/8 route writes、0 RAM writes、STATUS level 0→8、negative depth 4 失败）；证据 `runs/round1-dma-a/`、`runs/round1-dma-b/` | 固定目标地址、只写方向、单 outstanding、单 route、APB3+OBI、全字；非递增/错误注入/多通道/读路由/不同宽度没有；SPI 串行引擎未验证，只声称 FIFO occupancy |
| F1 地址/分支/压缩（**已接入，2026-11-02**） | `f1_allow_address_forms`/`f1_allow_branches`/`f1_allow_compressed` 已接入入口/C++；固定/连续真实 Ibex 批次：地址 2/2 + fuzz 20/20、前向分支 1/1 + fuzz 20/20、压缩 8 parcel 1/1 + fuzz 20/20；trace hash 与 Python 参考一致，错误 trace 会使批次 failed；证据 `runs/round1-f1-a/`、`runs/round1-f1-b/`、`runs/round1-f1-c/` | 受控分支只允许严格前向 B 型；压缩只允许安全 ALU 子集（x12..x15），compressed memory/control/FP/SP 拒绝；RV64/特权/CSR、JAL/JALR/循环/backward 拒绝；没有覆盖率/证书 |

多 IP/DMA 的模块测试是 `pytest tests/composition/test_multi_target.py tests/composition/test_dma_transfer.py` → **125 passed**（83/42）；集成真实证据在 `runs/round1-multi-ip/`、`runs/round1-dma-a/`、`runs/round1-dma-b/`。F1 地址/分支/压缩已接入真实 RTL（`runs/round1-f1-a/b/c/`），required suite 1309 passed；压缩 control/memory、RV64/特权仍未实现。

### 2026-11-02 第二轮：CVA6 RVFI/F1、F1 控制流、DMA 读路由、多 F5 目标

本轮新增并已有真实 RTL case 行的能力；未列出的旧限制仍然有效。汇总见
[round 2 报告](reports/round2-removed-limits-20261102.md)。

| 范围 | 现在有什么 | 仍没有 |
|---|---|---|
| CVA6 packed AXI4 | 6974 bit RVFI probe bundle 导出；pinned `cva6_rvfi` scoreboard 作为独立模型同沿采样；F1 三例（1/2/4 字）+ F2–F4 三例共 6/6、F1 fuzz 20/20、F2–F4 fuzz 8/8；`rvfi_retire_dropped 0`、`retirement_observation rvfi:cva6_rvfi_probes`、低 32 bit 投影（`runs/round1-cva6-rvfi/`、`runs/final-verify-round2b/cva6-f1/`） | 只跑 RV32IM 编码，不是 RV64 指令；无 CSR/特权/压缩/分支/跳转；F5/F6 仍拒绝；scoreboard 是 local-harness 新增 RTL，不属于 pinned closure |
| RV32 F1 控制流 | JAL/JALR 固定 2/2 + fuzz 20/20；canonical 有界循环固定 1/1 + fuzz 20/20（13 条退休、`prog_pc_repeat 2`）；压缩控制 3/3 + fuzz 20/20；压缩访存 2/2 + fuzz 20/20；trace hash 与 Python 参考一致（`runs/round1-f1-controlflow/`） | 任意/数据相关循环、嵌套/交叠循环、backward JAL/JALR、任意基址 JALR、压缩 FP/SP/system 仍拒绝；不是任意程序 fuzz |
| DMA | Wishbone 读 beat → APB3 目标读 → RAM；PULP I2C PRESCALER `0x20001000` 的 `0x5a5a` 写满 4 个 RAM 目的字；`dma_ram_reads 0`；固定 2/2、flows 5/5、fuzz 10/10；`runs/round1-dma-read/` | 单 outstanding；无错误注入、FIFO read、aperture read、AXI4-Lite route、多通道/不同宽度/多 outstanding |
| F5 / IRQ | 同一会话两个 APB3 目标都声明 F5；两路真实 IRQ 相或进 CPU 一根输入；global link 选择目标，timer link0/I2C link1 都通过；固定 10/10；`runs/round1-multi-f5/` | 同时两源的归因未证明（负控制如实失败）；NMI/PLIC/多 bit 向量/更多极性/清除方式、多目标 pin、混合 APB3+AXI4-Lite 仍拒绝 |

required suite 现为 **1375 passed**（含 CVA6 RVFI 与 F1 控制流测试）；最终代表回归
`runs/final-verify-round2b/` 9 个批次全部 `observations_passed`。仍未接入：
CVW/AHB 的退休/IRQ、Wishbone/TL-UL/AHB 目标、混合协议多目标、DMA 多
outstanding/错误注入、RV64/CSR/特权。没有覆盖率/证书/replay。

### 2026-11-02 第三轮：混合目标协议、CVA6 trap/RV64、DMA FIFO/aperture/error、F5 双源

| 范围 | 现在有什么 | 仍没有 |
|---|---|---|
| 混合目标协议 | 同一 Ibex OBI 会话内 APB3 目标（timer）+ AXI4-Lite 目标（ZipCPU axiluart）；固定 6/6；每例带 `target_protocol`、每目标 `reads/writes`、AXI `AW/W/B/AR/R` 通道计数；timer F5 仍交付；同协议 6/6、单 AXI4-Lite 5/5、CVA6 F2–F4 3/3 回归；`runs/round3-mixed-targets/` | 第三种协议混用（Wishbone/TL-UL 目前只做单协议会话）、混合 pin 模型、AXI4-Lite F5、AXI4-Lite 的 DMA route 仍按名拒绝 |
| Wishbone / TL-UL 目标 | Wishbone classic（ZipCPU UART 寄存器目标）5/5，真实 `cyc/stb/ack/we/adr/dat_w/sel`；TL-UL（OpenTitan RV timer）6/6，真实 A/D 通道握手；`runs/round3-target-protocols/` | AHB-Lite 目标按名拒绝（唯一 AHB profile 是 Caliptra SHA，不是寄存器窗口）；新协议与 APB/AXI4-Lite 混用仍未做；F5/F6 对新协议拒绝 |
| CVA6 高级 | RVFI `cause/intr/mode` + `mcause/mepc/mtval/mtvec/mstatus` 读回；真实 M-mode ECALL trap/CSR 1/1（重复 2/2，cause `0xb`、mepc `0x12000/0x12004`、handler 存入 RAM）；独立 **RV64** 模式 10/10（ADDIW/ADDW/SLLIW/SRLIW/SRAIW/LD/SD，64-bit trace hash，`0x11111111deadbeee` 跨 bit32）；`runs/round3-cva6/` | CVA6 F5 仍拒绝（`irq_i[0]` 未接线 + 无 `CPU_IRQ_TAKE`；trap/RVFI witness 已有，但交付路径未接）；无 F6、无 CSR fuzz、无更多异常/压缩/FP/原子 |
| DMA 高级 | PULP SPI **RX FIFO** 读路由（8 次 pop，level 8→0，`dma_ram_reads 0`，21 例）；4 寄存器 aperture/incrementing read（5/5，sequence 4）；master `mwb_err` 声明式错误注入（2/2，device sticky ERR bit 30）；`runs/round3-dma/` | 多 outstanding、多通道、8-byte/wider beat、TX FIFO read、写方向错误注入：按 pinned RTL 事实拒绝，不仿真 |
| F5 / IRQ 高级 | 同时两源 F5：timer + I2C 同时触发，ISR 读两个状态、存两个结果、各自 clear；13/13（含单次 take 对齐例）；PULP GPIO 多位 `INTSTATUS`（`isr_cause 0x3`）+ read-clears 4/4；`runs/round3-irq/` | NMI、PLIC、per-source CPU 向量、active-low 设备输出、write-one-clear 状态：按 CPU/设备边界拒绝；不是 CPU 向量归因 |
| CVW / AHB | 边界证伪报告：`wallypipelinedsoc` 不导出 IRQ/退休；`rvvisynth` 输入是 core 内部信号；F1/F5/F6 仍拒绝 | 需要新的 CVW 组合边界/RVVI monitor，未做 |

required suite 现为 **1502 passed**；最终代表回归 `runs/final-verify-round3b/`
13 个批次全部 `observations_passed`（mixed、Wishbone、TL-UL、CVA6 trap、RV64、
DMA FIFO/aperture/error、IRQ both/multibit、multi-F5、AXI4、DMA FIFO 写）。
仍未完成：Wishbone/TL-UL 与 APB/AXI4-Lite 的混合会话、AHB 目标、CVW 退休/IRQ、
CVA6 F5/F6、DMA 多 outstanding/多通道、
NMI/PLIC/active-low 设备、per-source CPU 向量。没有覆盖率/证书/replay。

### 2026-11-02 P0：通用组件接入 / 单 CPU 单 IP 入口

| 项 | 现在有什么 | 证据/边界 |
|---|---|---|
| Profile 契约 | CPU/IP/DMA 必填字段逐项文档化（复用 `component_profile.v1`，无新 schema）；26 tests，含 15 个缺字段按名拒绝、timing 可选、无 trap 导出、3 目标路由/重叠拒绝 | `docs/reports/p0-1-component-profile-contract.md` |
| 组件装配/地址路由 | 3 个 APB3 IP（timer+I2C+SPI）9/9；APB3+AXI4-Lite 6/6；同一三 IP 换 CV32E40P 8/8；没有 CPU×IP 分支 | `runs/p0-1-cpu/` |
| 新 CPU：CV32E40P | 仅换 `cpu_profile`；F1–F6 6/6，F1 退休 33（无 `rvfi_trap`，报告 `traps unknown`），F5 真实 timer IRQ，F6 4 读/4 写；fuzz 8/8；timed model 需 host phase scheduler/`verilated_timing` | `runs/p0-1-cpu/rows/cv32e40p-timer-f1f6` |
| 新 IP：OpenTitan TL-UL rv_timer | 真实 F5：`INTR_STATE0=1`、cause bit0、compare-update clear、`irq_level_final 0`；带 ZipDMA F1–F6 9/9；`COMPARE_UPPER0_0` 复位 `0xffffffff`，必须写 4 次 trigger；W1C 不能保持低 | `runs/p0-1-ip/batch2/all-six` |
| 统一入口三模式 | `--mode {combined,cpu-only,ip-only}`；combined 6/6（3 archive）、cpu-only 5/5（仅 `Vlocal_cpu__ALL.a`）、ip-only 26/26（仅 target archive，link.log 无 CPU） | `runs/p0-unified-modes/` |
| CPU-only 断言 | 只加载 CPU；真实 Ibex `PendingAccessTrackingCorrect`/`NoMemResponseWithoutPendingAccess`，tick 30、输入 `spurious-data-rvalid`，保存 file/line/scope/text；case timeout 单独 environment | `runs/p0-cpu-only/assertion/`、`environment-bus-timeout/` |
| IP-only | 只加载 IP；APB3 `R/W/WAIT` 26/26，读回 0x55/0x28/0x08，irq_o 采样不投递；总线超时 environment | `runs/p0-ip-only/` |

最终合并测试 **1605 passed**；代表批次 `runs/final-verify-p0/`（strictly：TL-UL/三 IP
两条首跑 records 形态不对，按 owner 精确 records 在 `runs/final-verify-p0b/`
重跑 9/9、9/9，失败尝试保留）。仍拒绝：IP-only 非 APB3、TL-UL+APB 混合、
DMA route 到 TL-UL、W1C、多 outstanding、CV32E40P 的 trap/writeback
（不可观测，不是测得 0）。没有覆盖率/证书/replay。

### 2026-11-02 P1：混合协议多目标、IRQ 任意拓扑、DMA 路由、每模型时钟、行为扩展与替换样本

| 项 | 现在有什么 | 证据/边界 |
|---|---|---|
| 混合协议多目标 | 任意 2–4 协议子集可作为同一会话的目标：APB3+TL-UL、APB3+Wishbone classic、APB3+AXI4-Lite+TL-UL、APB3+Wishbone+TL-UL 各 8/8；每个目标按自己的 `mmio_slave` 协议选适配器、完成判据（`apb3=sel_enable_ready`、`tl-ul=a_valid_and_a_ready_then_d_valid_and_d_ready`）和计数器 | 仍拒绝：协议不在集合内（`ahb-lite`）、多目标 pin 模型、Wishbone/AXI4-Lite 目标的 F5、AHB-Lite target kind。`runs/p1-mixed-protocols/`、[报告](reports/p1-mixed-protocols-any-subset-20261102.md) |
| IRQ 任意拓扑 | 三目标三 global link 9/9；三目标四 link 9/9；双源行对任意 ≥2 单 link 目标生成（不再是写死的两个）；PULP I2C 有序两写 ack 2/2（`clear_writes 2`，失败负控 `level_stuck 1`）；CVA6 `irq_i[0]` 真实 take 3/3，见证为 `mcause` 回读，bit1 由 profile 常量 0 → `cpu-vector-partial` | 仍拒绝 NMI（Ibex `irq_nm_i=constant-0`、CVA6 无端口）、PLIC（有 `rv_plic.sv` 但无组合 profile/claim 端口）、CPU 多位 vector、active-low、只 W1C 的清除；上限：一个 CPU 中断输入、双源两成员、clear ≤2 写。`runs/p1-irq/`、[报告](reports/p1-irq-generalization-20261102.md) |
| DMA 路由协议 | `ROUTE_PROTOCOLS = apb3/tl-ul/wishbone/axi4-lite`；路由协议取自被路由目标 profile 的 `mmio_slave` endpoint；TL-UL rv_timer `COMPARE_LOWER0_0` 固定读、Wishbone wbuart `SETUP` 读/写、AXI4-Lite axiluart `SETUP` 读/写全部真实通过，case 行给出该目标自己的协议计数（A/D、wb_acks、AR/R、AW/W/B）且 `dma_ram_reads 0`；AXI4-Lite 完成判据由「整例累计 == 1」改为按事务增量（`AxiMark`） | 仍拒绝：写只读/读只写寄存器、窗口外偏移、30 位地址不可达、无适配器的 AHB-Lite 路由；DMA 多 outstanding/多通道/宽 beat 仍只声明。APB3 的 case 行逐字段不变。`runs/p1-dma-route/`、[报告](reports/p1-dma-route-protocol-20261102.md) |
| 每模型时钟 | `phase_clock_plan` 把声明频率归一成整数半周期比（一格 = 参考 CPU 半周期），全部时钟先低、各自首次上升在自己的半周期；50/25/10 MHz 单会话实测 318/159/64 上升沿；timed CV32E40P + untimed 25 MHz、untimed Ibex + timed 10 MHz 两个混合方向；等速率 case 行与 P0-1 基线逐字节相同 | 拒绝非整数比、比参考 CPU 快、比值 >1024、timed 契约与比值冲突、非整数 ps；`assume_single_clock` 是显式声明不是测量；timed-IP 方向只是 timed build/相位路径（树内无带 `assign #` 延迟的外设 RTL）。`runs/p1-timing/`、[报告](reports/p1-timing-clocks-capability-20261102.md) |
| CPU 能力矩阵 | `scripts/cpu_capability_matrix.py` 从 25 个 `configs/cpus/*/component_profile.json` 生成 `docs/cpu-capability-matrix.md`：总线、xlen、退休面、RVFI 字段、trap 面、IRQ 入口/宽度/语义、时钟、时序模式、每流向可运行性或拒绝名。当前 10 个有退休面、8 个有 trap 面、14 个有 IRQ 入口、2 个 timed | 缺信号写 `unknown`/`none`，不写 0；4 个 profile 的总线本身按名拒绝 |
| 行为声明扩展 | `inprocess_behavior.py` 新增有序 `clear_sequence`（单写步派生 `clear_writes` 并执行；多步/读步按名拒绝）、命名 `pin_groups`/`serial_peer`（单 dir 组可执行并派生 `pins`；多组/串行 peer 拒绝）、DMA `capabilities{channels,beat_bytes,max_outstanding,burst_beats}`（声明层形状检查 + planner 按 pinned 器件事实拒绝超声明） | 全部为加法，最小声明产生的 fact 字典与旧版逐字段相同；能被声明 ≠ 能被执行，报告逐条标注哪些只声明。`runs/p1-replacements/`、[报告](reports/p1-behavior-expressiveness-replacements-20261102.md) |
| 替换样本 | 只改 profile/config/scenario：新 CPU `picorv32_wb_irq_rvfi` F1–F6 6/6；新 IP `opentitan_uart_local`（TL-UL）F1–F5 5/5（真实 `tx_done`：bit2、`INTR_STATE 0x105`、W1C 清除）；新 DMA profile `shared_profile_dma` F6 5/5 | 例子没有 IRQ 就不要求它跑 F5（F6 按名拒绝），没有 DMA 就不要求 F6；`opentitan_uart_local` profile 缺 `INTR_STATE` 的 `tx_done` 位是 profile 缺口，已记录不代改 |
| 最终代表批次 | `runs/final-verify-p1/`：13 批 64 例全部 `observations_passed` 且 `correspondence matched`，210 s；综合测试 **1758 passed** | 该批混有缓存复用与真编译（11 个模型 build 为本次真编译、27 个 cache hit），宿主每批重新链接 |

跨项汇总与「仍拒绝/未验证」清单见 [P1 验收报告](reports/p1-acceptance-final-20261102.md)。

### 与 2026-11-01 内容的更正关系

原 11-01 及 11-02 凌晨小节中的以下陈述已被本轮证据取代，正文已就地标注，旧文字保留：

1. 「AHB-Lite/完整 AXI4 CPU 的新执行器适配」仍缺 → AHB-Lite 已于 11-01 晚接入，完整 AXI4 CPU 已于 11-02 以 F2/F3/F4 接入；仍未接入的是多 IP 自动路由与 DMA→IP FIFO。
2. 「完整 AXI4 CPU 只到原生探针/分析，未接入统一入口」→ 已接入，见上；原生探针（`runs/round1-axi4/`）仍是独立证据，不是唯一证据。
3. 「AXI4 CPU 统一入口」列在「仍未有」→ 该项只剩 F1/F5 按名拒绝。
4. 「clear_writes 与 F5 通过判据冲突、cause 仍 unknown」→ 冲突已解决；cause 改为从真实状态读采样，并有 GPIO 真实例；I2C 提供了真实 level + 单次清除写的批次（含未解决的 case 内 level 风暴缺口）。
5. P0 小节「仍拒绝：TL-UL+APB 混合」→ 已被 P1 取代：任意 2–4 协议子集（含 TL-UL）可作为同一会话目标。
6. P0 小节「仍拒绝：DMA route 到 TL-UL」→ 已被 P1 取代：TL-UL / Wishbone / AXI4-Lite 目标的路由事务均已真实通过。仍拒绝的是 DMA 多 outstanding/多通道/宽 beat 与无适配器的 AHB-Lite 路由。

---

> 以下 2026-11-01 及 2026-11-02 凌晨各节为 **prior state**：保留原文与当时证据，仅在矛盾处附「2026-11-02 更正」。

## 2026-11-01 增量：统一闭环、短程序与行为声明（已实现）

本节记录本日新增并通过真实运行的部分；上文组合与限制仍然有效，除非这里明确说明。

- **统一闭环已接通**：`scripts/run_inprocess_f1f6.py --fuzz` 在同一进程内按 `NEED_RECORD`/`case` 执行「输入 → 真实观察 → 变异下一输入」，不再需要预先给出 `--records`。输入由声明空间生成/变异，并先通过入口自己的 `parse_record`/`validate_record` 门禁。证据见 [闭环证据](../runs/stage2-fuzz-loop-20261101/README.md)。
- **本批实际覆盖**：Ibex+Timer+ZipDMA（F1–F6，200 例，含 4 字 F1 程序）、GPIO+引脚模型（F1–F5，120 例，含因果引脚 IRQ）、PicoRV32 Wishbone+Timer（F1–F4，80 例）、AXI4-Lite UART+ZipDMA（F1–F4、F6，80 例）、CV32E20（F1–F6，80 例）、wbdmac（F1–F6，80 例）。这些是通过替换声明得到的，没有新增组合分支。
- **F1 短程序**：配置 `f1_program_words` 声明 1–16 条直线指令；固件在跳转前把 x18 指向声明的数据窗口，宿主逐字写入程序并在其后写入返回跳转。只允许 LUI/AUIPC/OP-IMM/OP 和 x18 基址上的全字 LW/SW，禁止控制流、CSR、压缩指令和写 x8/x9/x18。case 行报告真实退休数/顺序/安装字匹配/RVFI 写回掩码/最后写回/trap 和数据窗口变化。F1 仍不是任意 RISC-V 程序 fuzz。
- **等待有界、超时可恢复**：F5/F6 的等待循环有 `handler_wait_iterations` 上界；超时写入标记 `2`，case 行打印 `wait_timeout 1`，宿主只复位 IP/DMA 后继续（不计为通过）。这一条是本批新增的真实恢复行为，不是 F5/F6 支持范围的扩大。
- **协议与行为分层**：`source_behavior`/`dma_behavior` 文件把 IRQ 触发/状态/清除、引脚模型和 DMA 控制状态位从执行器中拆出；Timer/SPI/GPIO/ZipDMA 文件见 `configs/behaviors/`，说明见 [行为声明](inprocess-behavior-declarations.md)。DMA 状态位仍在本批的 ZipDMA 文件里显式声明；wbdmac 未声明时使用并报告 builtin 默认，不能称为设备声明。
- **精简热路径**：fuzz 模式固定 `--quiet`，只输出 case/summary 行；固定记录路径仍可保留逐事件输出。200 例的进程内执行约 0.09–0.10 秒，准备/构建仍占主要时间；本机短批次口径与分项见 [performance report](reports/fuzz-loop-performance-20261101.md)（若已生成）。
- **仍然没有**：RTL 覆盖率、证书、fuzz 批次的独立 replay、跨 testcase 状态消费认证、AHB-Lite/完整 AXI4 CPU 的新执行器适配、多 IP 自动组装、DMA 到 IP FIFO/多通道/不同宽度。`corpus.json` 只是输入集合，不是执行权限。**2026-11-02 更正**：AHB-Lite 已于 11-01 晚接入，完整 AXI4 CPU 已于 11-02 以 F2/F3/F4 接入（见「2026-11-02 增量」）；多 IP 自动组装与 DMA→IP FIFO 仍未接入（只有声明/规划模块）。

### 2026-11-01 晚：六项任务的落地与边界

| 任务 | 结果 | 证据 |
|---|---|---|
| 误报与恢复 | GPIO PADIN 只要求 CPU 读值等于设备同步锁存，瞬时 wire 另记 `pad_settled`，同步器延迟不再算错；F5 引脚因果接受上升/下降。failed case 分 `not_triggered`（正常未触发）、`wait_budget_exceeded`、`protocol_error`、`device_anomaly`、`execution_*`、`state_contamination`、`observation_mismatch`。超时只复位 IP/DMA，CPU/RAM 保留，`summary.recovery` 明写边界。 | [修正证据](../runs/stage2-task1-fix-20261101/README.md)、[说明](inprocess-fuzz-loop.md) |
| 长跑稳定 | 60 s 入口级 96,994 例，1,616.5 例/秒；RSS 峰值 142.4 MiB，预热后斜率 −0.0109 MiB/万例；host 1 PID/0 重启；summary 1.10 MiB、fuzz 0.78 MiB。会话级 200k 例 RSS 斜率约 +0.002 MiB/万例。`--stall-seconds` 防无输出挂死。 | [长跑报告](reports/fuzz-longrun-20261101.md)、[证据](../runs/fuzz-soak-20261101/README.md) |
| 同协议新 IP | PULP I2C 仅以 profile/场景声明接入；Ibex OBI 与 PicoRV32 Wishbone 各跑 F1–F4（80/80、60/60），无代码分支。F5 因 profile 无 IRQ 源被具名拒绝，F6 因无 DMA 拒绝。 | [I2C 接入](reports/new-ip-onboarding-20261101.md)、[证据](../runs/stage2-fuzz-newip-20261101/README.md) |
| 程序变异 | 8/16 字 RV32I/M 直线程序、依赖链、LW/SW 数据流、重复地址；真实 RVFI 退休/写回与参考模型逐条一致（8 字 12/12、16 字 12/12，0 mismatch）。AUIPC 的 Python 门已与 C++ 对齐，真实执行 2 条退休。 | [程序证据](../runs/stage2-fuzz-programs-20261101/README.md)、[AUIPC](../runs/stage2-task4-auipc-20261101b/) |
| 前缀复现 | fuzz 模式流式写 `prefix.txt`/`observations.jsonl`，finding 带 `prefix_lines`；`--replay-prefix/--replay-limit` 在新进程重放并比较关键观察。GPIO 种子 F4→F5 真实 IRQ（2 条）和一次未触发失败（7 条）均 `replay_matched`。 | [前缀证据](../runs/stage2-prefix-replay-20261101/README.md) |
| 合并验收 | 同一入口：Timer F1–F6（194/200，6 个正常未触发）、GPIO F1–F5（111/120，8 个正常未触发 + 1 个跨例状态）、Wishbone CPU F1–F4（80/80）、PULP I2C F1–F4（Ibex 80/80、Wishbone 60/60）、AXI UART+ZipDMA F1–F4/F6（80/80）、固定 F1–F6（6/6）。 | [批量验收](../runs/stage2-acceptance-20261101/README.md) |

仍然没有：RTL 覆盖率、证书、完整 replay、AHB-Lite/完整 AXI4 CPU 的新执行器适配、多 IP 自动组装、DMA→IP FIFO/多通道/不同宽度。**2026-11-02 更正**：AHB-Lite 与完整 AXI4 CPU 已接入统一入口（后者 F2–F4），多 IP 与 DMA→IP 仍未接入；见「2026-11-02 增量」。GPIO 没有声明 EOI/clear 的 level IRQ 会在后续 case 生效，现作为 `state_contamination` 记录而不是屏蔽。`run.log` 和前缀文件随 case 数线性增长（磁盘），尚未做日志轮转。

### 2026-11-01 晚：Wishbone CPU 连续 F1–F6

- **固定六路径**：PicoRV32 Wishbone + Timer APB3 + ZipDMA 的六记录 6/6 `observations_passed`，真实 IRQ、真实 DMA 4 读 4 写、ISR 读到状态并清除。
- **连续 fuzz**：120 例 seed 23 中 116 通过（3 个正常未触发、1 个跨例 level IRQ `state_contamination`），55 次 IRQ 接受、196 次 DMA 读写；80 例 seed 29 全部通过。没有 host 崩溃，超时后下一例继续。
- **第 11 例 tick 超限根因**：F5 无触发时 256 轮等待 × 约 34 tick/轮 ≈ 8,700 tick，超过原先写死的 4,000 tick/case 守卫；不是设备或中断处理错误。现 `handler_wait_iterations` 与 `case_tick_budget` 都可声明（Wishbone six 用 64/12000），summary 的 `handler_wait` 报告两者。
- **换 IP**：同一 Wishbone CPU + PULP I2C 60/60，F1–F4 全部真实，仅改声明，无 CPU×IP 代码。
- **边界**：仅 Pico custom IRQ ABI（配置声明的 bit + 真实 EOI 端口）；没有 EOI/clear 的 level IRQ 会跨 case 再次被接受，按 `state_contamination` 记录；DMA 仍全字对齐单通道；没有 RVFI 的 Wishbone CPU 不能沿用该结论。
- 证据：[Wishbone 六路径](../runs/stage2-wb-six-20261101/README.md)。

### 2026-11-02 凌晨：Wishbone 六路径、AHB F2–F4、AXI4 探针与新声明

- **Wishbone CPU F1–F6**：PicoRV32 + Timer APB3 + ZipDMA 固定六例 6/6；连续 fuzz 120 例 116 通过（3 正常未触发、1 跨例 level IRQ `state_contamination`），80 例第二 seed 全通过；第 11 例 tick 超限根因是 256 轮等待 ×34 tick > 4000 tick 守卫，现 `handler_wait_iterations`/`case_tick_budget` 可声明（64/12000）。换 PULP I2C 60/60。证据 [Wishbone](../runs/stage2-wb-six-20261101/README.md)。
- **AHB-Lite CPU（CVW）**：统一入口新增 `ahb` 分支，F2/F3/F4 固定 14/14、连续 80/80；AHB beats 118、真实取指 47；**F1 按名拒绝**（无 RVFI/commit，取指不是退休），F5 拒绝（无 IRQ 输入），F6 拒绝（无 DMA）。CVW 窗口在 0xC0000000；本机 elaboration 需 `setsid`。证据 [AHB](../runs/stage2-ahb-unified-20261101/README.md)。
- **完整 AXI4 CPU**：只到原生探针/分析，未接入统一入口。CVA6 真实归档 + 既有 AXI4 适配器在同一进程跑出真实取指/行填充/load/store、ARID/RID 身份和 B/R OKAY；**无 RVFI，F1 unknown**；同槽改写无 fence 时 I$ 继续旧代码、fence.i/复位后重取。统一入口仍强制 RVFI，F2–F4 都构建不出，需先改准入。证据 [AXI4 分析](reports/inprocess-axi4-cpu-analysis-20261101.md)。**2026-11-02 更正（superseded）**：同一入口现已驱动 CVA6 packed AXI4，固定 F2/F3/F4 3/3、连续 fuzz 30/30；F1/F5 仍按名拒绝（无 RVFI 退休见证）。见 [AXI4 集成](reports/round1-axi4-integration-20261102.md) 与 `runs/round1-axi4-unified/`。原生探针的缓存/fence.i 发现与单 outstanding 限制仍然成立。
- **同协议 IP**：`configs/peripherals` 没有剩余未接入的 APB3/AXI4-Lite profile（5 个 family 均已被 inprocess 场景选中）；PULP SPI 是“新进入 fuzz 路径”，Ibex 80 例 79 通过（1 正常未触发）、Wishbone 60/60，零代码。其余未用 profile 是 TL-UL/AHB-Lite/Wishbone 目标，缺目标适配器，按名拒绝。证据 [SPI](reports/new-ip-2-onboarding-20261101.md)。
- **IRQ/F5 声明**：新增 timer0 compare（irq_o[1]、status CMP、24 tick）与 timer1 overflow（irq_o[2]、status COUNT、32 tick），Ibex/CV32E20/Wishbone 各自真实运行；同一设备只有单目标源 + DMA link，clear_writes 与 F5 通过判据冲突，cause 仍 unknown，GPIO 是 pulse + 读清状态而非 level。证据 [IRQ 报告](reports/irq-declaration-expansion-20261101.md)。**2026-11-02 更正**：`clear_writes` 与 F5 判据的冲突已在触发/清除分离中解决；cause 已由 `status_cause_bits` 从真实状态读采样（GPIO 实测 `isr_cause 1`）；PULP I2C 新增真实 level 源 + 单次 clear 写，多 link v2 声明也已落地。见「2026-11-02 增量」。
- **DMA/F6 声明**：wbdmac 的 busy/err 位 31/30、脉冲完成中断、字长度、字节地址单位从 pinned RTL 核实并写入 `wbdmac_f6.json`；固定 F6 2/2，fuzz F6 30/30。仍受 block_words 1..4、全字对齐、单通道/单 outstanding、无字节使能/背压/错误注入、无 DMA→IP FIFO 限制。证据 [DMA 报告](reports/dma-declaration-wbdmac-20261101.md)。
- **子字程序**：LB/LH/LW/LBU/LHU/SB/SH/SW 的 Python 权威、C++ make_record 门与 RAM 字节使能路径已接；Ibex 与 Wishbone 上 11 字混合程序各 `observations_passed`（11 退休、7 写回、rd_mask 0x7e、data_changed 2）。证据 `runs/stage2-wb-six-20261101/subword-*`、`docs/patches/subword-host-integration.md`。
- **长跑逐例对应/日志**：每个通过的 case 现在都做对应检查（`correspondence.checked` 覆盖全批，`sampled=false`），失败原因最多留 32 条；`--log-mode summary` 只写 summary/错误，12 s 验证批 18,959 例的 `run.log` 约 1.2 KB（逐例模式约 0.8 KiB/case 线性增长）。
- **F4 自触发 IRQ**：写 Timer COUNT 最大值会立即触发 IRQ；F4 不建立 F5 上下文。现在启动时初始化安全的 handler cell，且 F1–F4 case 行也发布 `irq_edges`/`irq_takes`，该情况归为 `state_contamination`，不再以未映射访问中止批次或误报 `device_anomaly`。
- **仍未有**：多 IP 自动路由/不同目标选择、TL-UL/AHB-Lite/Wishbone 目标适配器、AXI4 CPU 统一入口（2026-11-02 更正：F2–F4 已接入，仅 F1/F5 按名拒绝）、F1 的任意跳转/RV64/CSR/特权级、覆盖率/证书/完整 replay、逐例日志轮转（已可用 summary 模式规避）。

## 指令、反馈与接入限制

- F1 目前使用有限范围的合法指令和可观测退休；不等于任意 RV32/RV64 扩展、特权、异常和所有 CPU 启动方式都支持。现有生成相关代码可从 `scripts/generate_riscv_program.py`、`src/myfuzz/isa/` 和 `src/myfuzz/fuzz/rv32_program.py` 开始查看。F1 短程序只在 RV32 profile 的 fuzz 模式中生成；Wishbone CPU 的 F1 退休来自该 profile 的 RVFI，没有 RVFI 的 Wishbone CPU 不能沿用。
- 独立 F5 入口有 Timer 定向规则，已由结果生成后续输入；独立 F6 入口有根据实际 DMA 数据变化下一条输入的规则。它们是小范围闭环，不是通用覆盖率驱动 fuzz；见 [F5 反馈摘要](../runs/stage2-stepB-f5-feedback/summary.json)、[F6 反馈摘要](../runs/stage2-stepB-f6-feedback/summary.json)。
- CPU/IP/DMA 仍需提供真实端口、总线、启动、寄存器、IRQ 和 DMA 行为。部分行为依赖组件专属契约或 pinned 源事实，不能声称新设备只写协议名就可接入。
- F6 目前的代表路径以对齐、全字的 RAM 搬运为主。DMA 到 IP FIFO、其他宽度、复杂背压、多通道等不能从现有结果推定支持。
- 完整证书和 replay 不是单进程原型的默认输出；原型输出为紧凑实际观察。设备 IRQ 脉冲可能由宿主按声明拉宽，设备输出和 CPU 实际收到的宽度应分别理解。
- fuzz 模式当前只有行为反馈（真实退休、IRQ、DMA、复位/超时等观察），没有在线覆盖率引导；发现 RTL 覆盖率工具对比仍暂缓。

## 性能

[单进程测量报告](../runs/stage2-opt-20261101/REPORT.md)记录 Ryzen 9 7945HX 上各两次的中位数：F5 热缓存约 5.30 秒、F6 约 5.76 秒，DUT 推进约 1.3–1.8 毫秒；冷缓存各约 16 秒。测量包含紧凑结果输出，不包含完整证书或 replay。样本数很小，这些值不是通用的每例稳态吞吐量；不同入口、case 数和证据范围也不可直接比较。

当前明显瓶颈是每次进程的准备、宿主源码扫描和模型 elaboration 等，而不是所测短批次的 DUT 推进。要贴近“初始化后主要时间用于 DUT”的目标，应将已有模型保持运行并增加有效批量，同时量化反馈生成、IPC 和结果写出开销，再针对实测热点优化。

## 代码整理结论

`run_inprocess_f1f6.py` 约 2100 行、对应 C++ 约 1900 行；此前还存在分别针对 GPIO、AXI4-Lite 和 Wishbone CPU 的单用途入口和 host。后续可以按相同输入、事件和失败行为逐项核对，将已被统一入口完整替代的代码收拢；不能因为文件名相似或示例通过就删除，因为支持范围和测试引用可能不同。

本次清除一个未使用导入、修正统一入口帮助说明，更新脚本与文档导航，并给旧方案和凌晨报告添加时点提示。工作区本来就有大量未提交更改、测试产物和证据；未对其做批量删除，避免丢失其他工作的内容。

后续优先级：

1. 用少量真实 RTL 批次确认统一入口的代表组合和不支持路径，列清楚 profile 所需行为。
2. 将独立入口验证过的反馈方式以最小接口接入统一循环，再消除固定记录与短生命周期的吞吐限制。（2026-11-01：闭环 `--fuzz` 已接通；吞吐仍以准备/构建为主，见性能报告。）
3. 比对并收拢功能确实重复的独立 host/入口；按协议拆分重复代码，不新增多层框架。
4. 按 CPU/目标/DMA 逐项扩展协议、IRQ 和数据宽度，并对每项给出真实证据和限制。
5. 把 fuzz 的行为反馈扩展到跨 testcase 状态消费与覆盖率（当前只有 case 级行为反馈）；在此之前不声称覆盖率引导。
