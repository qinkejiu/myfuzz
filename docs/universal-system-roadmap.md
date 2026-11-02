# 通用 CPU/IP 数据流系统：分阶段实施路线

更新日期：2026-10-31

本文记录项目的执行顺序、各阶段范围和完成条件。当前优先完成第一阶段；覆盖率工具对比暂缓。实施过程中应根据真实运行结果更新进度，不以静态预检或代码量代替验收。

## 总目标和共同约束

CPU 和 IP 分别提供 profile；对于框架已经支持的总线及行为，兼容组件由配置自动装配并运行，不编写 CPU×IP 组合专用代码。profile 需要声明实际的 RTL、端口、复位、协议、地址和必要行为；不能只给出协议名称就推断所有组件语义。

CPU 和 IP 都执行各自的真实 RTL。宿主提供 RAM、总线转发、事件交付与环境输入，模拟 SoC 内部的数据流动；本项目不要求连接或构建一颗真实 SoC。CPU 对普通外设的控制通过 MMIO 完成。

目标结构：

```text
CPU profile → CPU 总线适配器 ─┐
                             ├→ 统一事务 / RAM / Router → IP 总线适配器 → IP profile
指令和输入 → 真实 CPU RTL ───┘                               ↓
                                                  真实 IP RTL / 真实事件
```

每种已支持的 CPU 或 IP 总线只实现一次适配器；组件差异通过各自 profile 描述。执行、观察、证据和性能测量共享相同的协议接口。真实发生但证据不足的事实标为 `observed` 或 `unknown`；只有可复核的证据才标为 verified，不为未知来源授奖励。

实施采用小批量实现、批量验证和集中修复。复用已有 CPU、IP、ISA 生成器及适配器，不为推测的边界堆叠大量防御代码。远程验证及产物只放在服务器 `/root/fanzehui` 下；本地和远程及时清理本次产生的临时文件、确认相同的重复产物，保留可复现证据。

## 2026-11-01 进展（本轮，不改变下面的阶段验收）

- **统一闭环已接通**：`scripts/run_inprocess_f1f6.py --fuzz` 在同一进程内执行「输入 → 真实观察 → 变异下一输入」；`--online` 仍保留为预先给定记录的固定路径。输入空间按声明生成，并先过入口自己的 gate。
- **F1 短程序**：`f1_program_words` 声明 1–16 条直线 RV32I/M 指令；宿主按程序写入 trampoline、报告真实退休数/顺序/安装字匹配/RVFI 写回掩码/最后写回/trap 和数据窗口变化。仅 RV32、直线、x18 基址全字 LW/SW；RV64 的 fuzz 模式按名排除 F1。
- **设备行为声明**：`source_behavior`/`dma_behavior` 文件承载 F5 触发/状态/清除、引脚模型和 DMA 控制状态位；Timer/SPI/GPIO/ZipDMA 文件在 `configs/behaviors/`。执行器仍做 profile/源事实交叉校验。
- **超时恢复**：F5/F6 等待循环有界；超时写入标记、case 行报告 `wait_timeout`、只复位 IP/DMA 后继续。这是恢复行为，不是 F5/F6 支持范围扩大。
- **本批真实运行**：Timer+ZipDMA（F1–F6，200 例）、GPIO（F1–F5，120 例，含因果 IRQ）、Wishbone CPU（F1–F4，80 例）、AXI4-Lite UART+ZipDMA（F1–F4、F6，80 例）、CV32E20、wbdmac。证据见 [闭环证据](../runs/stage2-fuzz-loop-20261101/README.md)，用法见 [闭环使用说明](inprocess-fuzz-loop.md)，行为见 [行为声明](inprocess-behavior-declarations.md)。
- **仍未完成**：在线覆盖率、证书、fuzz 批次 replay、跨 testcase 状态消费、AXI/AHB CPU 的新执行器适配、多 IP 自动组装、DMA 到 IP FIFO/多通道/不同宽度；这些不因本轮结果而视为通过。

### 2026-11-01 晚：六项任务的增量

- **误报与恢复**：GPIO PADIN 按同步器实际时序判定，失败分类区分正常未触发/等待预算/协议/设备异常/跨例状态；超时只复位 IP/DMA 并写出状态边界。证据 `runs/stage2-task1-fix-20261101/`。
- **长跑**：入口 60 s 96,994 例，RSS 预热后不随 case 增长（−0.0109 MiB/万例），host 不重启；会话语料/特征/前缀均有界或流式。证据 `runs/fuzz-soak-20261101/`、`docs/reports/fuzz-longrun-20261101.md`。
- **同协议接入**：PULP I2C 仅 profile/配置接入，F1–F4 在 Ibex 与 Wishbone 上真实运行；F5 因无 IRQ 源拒绝，未增加组合代码。证据 `runs/stage2-fuzz-newip-20261101/`。
- **程序变异**：8/16 字 RV32I/M 直线程序、依赖链、LW/SW 数据流，真实退休/写回与参考模型一致；AUIPC 门禁对齐。证据 `runs/stage2-fuzz-programs-20261101/`。
- **前缀复现**：`prefix.txt`/`observations.jsonl` + 新进程 `--replay-prefix`，GPIO F4→F5 与失败前缀均重放匹配。证据 `runs/stage2-prefix-replay-20261101/`。
- **合并验收**：Timer/GPIO/Wishbone/I2C/AXI 与固定 F1–F6 在同一入口批量通过；仍无覆盖率/证书/完整 replay，拓扑仍是一个目标 + 可选 DMA。证据 `runs/stage2-acceptance-20261101/`。
- **Wishbone 六路径**：PicoRV32 + Timer + ZipDMA 固定六例 6/6；连续 fuzz 120 例 116 通过（3 正常未触发、1 跨例 level IRQ），80 例第二 seed 全通过；第 11 例超限根因是 256 轮等待 ×34 tick > 4000 tick 守卫，现声明为 64/12000；换 I2C 60/60。证据 `runs/stage2-wb-six-20261101/`。
- **AHB-Lite CPU**：统一入口新增 `ahb` 分支；CVW F2–F4 固定 14/14、连续 80/80；F1（无 RVFI）、F5（无 IRQ）、F6（无 DMA）按名拒绝。证据 `runs/stage2-ahb-unified-20261101/`。
- **完整 AXI4 CPU**：CVA6 原生探针已跑通取指/行填充/load/store、ARID/RID 身份与 B/R OKAY；无 RVFI、F1 unknown；同槽改写无 fence 时 I$ 旧代码、fence.i/复位后重取；统一入口仍未接入，且当前强制 RVFI 是 F2–F4 的前置阻断。证据 `docs/reports/inprocess-axi4-cpu-analysis-20261101.md`。
- **新 IP/IRQ/DMA/子字**：PULP SPI 进入 fuzz（Ibex 80 例 79 通过、Wishbone 60/60）；timer compare/timer1 overflow 声明在三种 CPU ABI 上真实运行；wbdmac F6 行为声明 30/30；LB/LH/LBU/LHU/SB/SH 在 Ibex/Wishbone 上真实执行。

## 第一阶段：F1–F4 通用化（当前优先）

### 目标

CPU 和普通 MMIO IP 分别提供 profile，使用已支持协议的兼容组合自动生成场景，在同一个会话中执行 F1–F4，不因更换 CPU 或 IP 而新增组合代码。

- F1：CPU 从程序存储器取指并执行；相关场景也包含 CPU 从声明的 RAM 读取数据。
- F2：CPU 经总线读取 IP 或 RAM 数据。
- F3：CPU 经总线写入 RAM。
- F4：CPU 经 MMIO 写入外设寄存器。

### 首批范围

1. CPU 侧复用 OBI、Wishbone、AHB-Lite 和 AXI4-Lite 已有适配，按 profile 声明启动地址、取指/数据通道、握手、字节使能和可用观察。
2. IP 侧先完成 APB3 普通 MMIO，随后接入已有基础的 Wishbone 寄存器目标；其他 IP 总线按协议单独扩展一次，不按 CPU×IP 扩展。
3. 先覆盖 32 位地址和数据、声明的 RAM 窗口以及可测试的 MMIO 寄存器。寄存器掩码、副作用和环境输入以 IP 声明为准；不能从总线协议猜测设备行为。
4. 从 CPU/IP profile 生成各自 request、地址映射和场景；允许用户显式提供地址、时序及能力描述，有歧义时说明缺少什么。
5. 在统一运行时记录真实取指、CPU 总线握手、RAM 读写和 IP 请求/响应；CPU 退休、RAM 版本、IP 内部状态或跨例来源缺失时保留 unknown。

### 验收

- [x] 选定支持的 CPU/IP profile，无组合专用代码，自动生成并运行 F1、F2、F3、F4。本批 6 个主组合（另有 SPI/Timer 追加组合）全部由 `scripts/generate_mmio_scenario.py` **从 profile 派生**、由同一个 `compiled_mmio` 执行器运行，没有新增 CPU×IP 组合代码。2026-10-31 补：`spi-{picorv32-wb-memory,cvw-ahb-memory,picorv32-axi-memory}` 三份配置已从冻结 request 改为 `cpu_profile`/`ip_profile`，实测生成的 descriptor `flow_ids=[F1,F2,F3,F4]`、`executors` 全为 `compiled_mmio`，至此 6 个主组合均为 profile 派生（追加组合中 `timer-picorv32-wb-memory` 仍用冻结 request，不计入该口径）；仓库中旧场景仍保留按**协议对**（如 OBI×APB，不是 CPU×IP）命名的 executor 分支。逐条证据见 [阶段一验收矩阵](reports/stage1-acceptance-matrix-20261031.md)。
- [x] 同一个 IP profile 配至少两种不同 CPU 总线；同一个 CPU profile 配至少两个同协议 IP。APB I2C 分别配 Ibex OBI 与 PicoRV32 Wishbone；PicoRV32 Wishbone 分别配 APB I2C 与 APB SPI。
- [x] OBI、Wishbone、AHB-Lite、AXI4-Lite CPU 的首批代表组合均实际执行 F1–F4；F1 真实取指、F3 RAM 写、F2/F4 MMIO 访问各有实际观察。退休、RAM 读取版本、跨例来源等仍为 unknown。
- [x] 每种纳入本阶段的 IP 侧总线有一次独立适配和至少一个真实 IP 验证：APB3（PULP I2C/SPI/Timer，F1–F4）、Wishbone（ZipCPU UART，F1–F4）、AXI4-Lite（ZipCPU AXI UART，F2/F4）、AHB-Lite（Caliptra SHA，仅 F2，1 例；该 IP 无 32 位 rw 寄存器）与 TL-UL（OpenTitan GPIO，F2/F4，6 例 + fresh，`runs/ibex-obi-tlul-gpio-20261031`）均已真实执行并完成独立新进程 replay。完整 AXI4 的 IP 目标不存在。
- [x] 至少对代表性组合做一次独立新进程 replay：本批 6 个组合各做一次 `--mode fresh` 独立进程 replay，全部 `replay_matches=true`；失败会保留 `failure.json` / 事件。
- [x] 文档给出 profile 最小字段、可运行示例、支持范围、常见缺项和限制；本批临时产物已清理。见 [profile 接入说明](profile-onboarding.md)、[批量结果](reports/f1-f4-batch-20261030.md) 与 [验收矩阵](reports/stage1-acceptance-matrix-20261031.md)（第 6 条：本批临时产物已清理，但仓库根目录旧散落文件与历史 campaign 缓存不在此口径内，仍属遗留）。

### 当前进度和主要缺口

- 2026-10-30：按“只保证多设计交互”的口径收敛后，最小执行链约 **27 个文件 / 2.2 万行**，其余证书、验收门与逐组合场景可跳过，详见 [最小路径审计](reports/f1-f4-minimal-path-audit-20261030.md)。
- 已修复两个阻断 F1–F4 的问题：(1) OBI CPU 在“宿主有意停在下一条未物化指令槽”时被 host 检查器累计成等待超限；现在用例在 `cursor+len(code)` 边界后的小窗口内结束，并记录真实停地址/tick/`settle_advances`，不扩大 `max_wait`、不关闭检查器（`runtime/flows/memory.py::fragment_boundary_park`）。(2) Wishbone UART `SETUP` 的 `full_word_reserved_zero` 写策略不再要求 `side_effect == none`；策略与真实副作用分开校验，mask `0x7fffffff` 和 `write_resets_uart_state` 保留，preflight 直接校验实际 F2/F4 候选记录。
- 真实 RTL 批量（2026-10-30，远程 `/root/fanzehui/myfuzz-profile-batch22-20261030`，Verilator 5.051）：6 个组合各 6 例 F3/F1/F4/F2/F4/F2，original 均 `observed`、exit 0，independent fresh replay 全部匹配；事件层分别观察到 6 个 instruction source、61–97 次 RAM 读（含取指）、5 次 RAM 写、6 次 MMIO delivery/acceptance，无 protocol violation。另在同一快照补跑 CV32E40P OBI × APB I2C（6 例、fresh 匹配），证明 OBI 适配器下第二颗 CPU 可用。详见 [批量结果](reports/f1-f4-batch-20261030.md)。
- 2026-10-31 扩展目标总线：AXI4-Lite（ZipCPU AXI UART，F2/F4）、AHB-Lite（Caliptra SHA，F2）与 TL-UL（OpenTitan GPIO，F2/F4，6 例 + fresh）均已在真实 RTL 执行并完成 fresh replay；TL-UL 的 F4 记录为 18 字节（含声明 pin 切片），A/D 通道由 target session 内部驱动，早期“被阻断”的根因是 A 通道 10 个 pin 的 `source_id` 不在依赖图，已由 `src/myfuzz/scenario/target_bus_pins.py` 入图修复。VexiiRiscv（完整 AXI4 CPU）的 **F1–F4 已真实通过**：F2/F4 见 `runs/vexii-axi4-apb-i2c-20261031`，F1–F4 见 `runs/vexii-f1f4-20261031`（descriptor `configs/scenarios/compiled-f1-f4-axi4-apb-i2c-vexii/`），各 6 例 + fresh 匹配；F3/F1 的证书状态是 `submitted`（以提交记录 + 内存事件为证据，与 Ibex 基线一致，不产生 join）。CVA6/BOOM/ZipAXI 分级见 [阶段一审计](reports/stage1-completion-audit-20261031.md)。详见 [扩展总线适配](reports/extended-bus-adapters-20261031.md)。
- 2026-10-31 本轮收尾：证据目录完成改名与清理（149 项、681 MB，9 个正式证据名，旧 `runs/_local-*`、`runs/_tlul-gpio-full` 已不存在，映射见 `runs/RENAMES-20261031.md`）；远程快照按 16 个组合去重镜像到 `runs/remote-batch22-20261031b/`（每组合只有 `summary/replay/case_sequence`，`prefix/events` 仍在远程）。按 6 条验收口径现为 **5 条已完成、1 条部分（第 6 条仅剩清理项）**：TL-UL 目标真实通过、Vexii F1–F4 真实通过、三份 SPI 配置改回 profile 派生，路线图先前“TL-UL 待复验 / Vexii 待复验”的表述已不成立。逐条状态见 [验收矩阵](reports/stage1-acceptance-matrix-20261031.md)，汇总见 [阶段一完成报告](reports/stage1-completion-20261031.md)。
- 2026-10-31 同日后续（CVA6 / BOOM / 远程复验）：**CVA6 的 F1–F4 已真实通过**（`runs/cva6-f1f4-20261031` 6+6、original 117.09 s / fresh 106.63 s、`replay_matches=true`；`campaign.json` bound adapters = `['apb3.mmio.v1','cva6.axi4.cpu.v1']`，确实走通用 `compiled_mmio`）；取指身份改为 **ARID/RID 声明**（`wt_axi_adapter.sv:116/159/597/638` + `cv64a6_imafdc_sv39_config_pkg.sv:32/:72` ⇒ `instruction_id_map {arid:0,rid:0,granule:8,rsize:3}`，由 `cva6_axi_mmio.py::cva6_instruction_identity()` 现场重读 6 个锚点才声明，缺失即退回 data-only refusal），因此先前“user/prot 钉 0 ⇒ 无法取指”的表述已更正（user/prot 确实钉 0，但身份在 ID 上）。**BOOM 的通用 `compiled_mmio` 仍未准入**：Phase A（harness 半）已完成——`tl_coherent_memory_adapter.sv`(468)、39-role `tilelink-coherent` 契约、runtime/driver renderer、真 RTL `verilator --lint-only` exit 0 无 warning（`runs/boom-tl-harness-lint/`，artifact `source_verification=null`），拒绝点前移到 `component-render-refused` ← `local-source-lock-missing-component:boom`；F2/F4 仍只有 `directed_standard_runner_router` 各 6 例 + fresh，剩余 Phase B 约 850–1120 行。同日 15:00 后远程冷缓存复验落地 `runs/remote-stage1-20261031/`（`ibex-obi-apb-i2c` 85.6/78.6 s、`vexii-f1f4` 67.3/86.8 s、`vexii-f2f4` 72.5/94.5 s、`ibex-obi-tlul-gpio` 102.9/92.9 s，fresh 全 `true`），并把 `_ELABORATION_TIMEOUT_SECONDS` 由 30 调到 300（资源预算，非放宽正确性检查）。
- 仍然缺：DUT 断言当前未编译进 Verilator（无 `--assert`），因此不声称任何 DUT 内部正确性；退休、RAM 版本、跨例来源、IP 内部状态保持 unknown；BOOM 的通用执行器准入（Phase B）、ZipAXI 与 F5/F6 不在本阶段（分级与工作量见审计报告与[可行性报告](reports/full-axi4-cpu-f1-f4-feasibility-20261031.md)）。
- 新 CPU 的取指、复位和协议特性，及新 IP 的寄存器/输入行为仍需真实声明和验证；上述组合不代表任意 CPU/IP 自动支持。

## 第二阶段：F5–F6 通用化

### 目标

在第一阶段统一 CPU/IP 总线和 MMIO 的基础上，按组件 profile 装配中断、DMA 和其他明确的数据流；各组件行为分别适配，兼容组合无需编写专用代码。

- F5：外设 IRQ 真实产生并交付 CPU；CPU 进入对应中断处理过程，并按声明读取或清除状态。
- F6（DMA）：CPU 经 MMIO 配置真实 DMA；DMA 作为主设备读取/写入 RAM 或兼容 IP，并按声明报告完成及中断。

### 工作与验收

- [ ] 为 IRQ、DMA 主端口、触发/清除、目标寄存器与可观测信号建立组件级声明和协议适配，不从 MMIO 协议名推断这些行为。
- [ ] 处理单根 IRQ、向量位和不同 CPU 中断 ABI；实际中断输入、CPU 处理和状态访问分别记录。不能将 EOI、取指推进或某根 IRQ 高电平单独当成完整因果证明。
- [ ] 复用真实 DMA 请求、响应和 RAM 事务，按声明验证搬运方向、地址、数据、使能和完成情况；IP FIFO、背压和不同传输宽度按已支持能力逐步扩展。
- [ ] 支持复位后重新装载并继续运行；分别验证实际支持的 warm/cold reset、状态边界和独立 replay。
- [ ] 对至少两种不同 CPU/中断接口及多个不同 IRQ/DMA 组件进行代表性真实验证；缺失来源或退休证据时明确保留 unknown。
- [ ] 对 F6 完成组件描述、统一接口和实际运行验收。

当前已有 OBI CPU 与 DMA、GPIO/I2C 的 F1–F6 真实执行及重放；PicoRV32 Wishbone 组合已运行六路径并完成观察级重放，但 F5/F6 尚不具备完整退休、来源与消费认证。它们是已验证组合，不代表第二阶段完成。

## 第三阶段：RISC-V 指令扩展

### 目标

按 CPU profile 声明的 ISA、启动方式及实际支持范围生成合法程序，在真实 CPU RTL 上执行，并把真实执行观察接入反馈。优先复用已有指令生成与开源项目，避免重新实现完整工具链。

### 工作与验收

- [ ] 从 CPU profile 读取 XLEN、扩展、对齐、寄存器数量、复位/启动及执行限制；生成器不为不支持的 CPU 生成非法指令。
- [ ] 先扩展 RV32I，逐步覆盖已声明的 M、C 等扩展，再按实际 CPU 能力推进 RV64、特权级、异常和其他扩展；每项明确支持矩阵。
- [ ] 复用现有 riscv-dv 等上游项目和本仓库指令生成器；管理固定版本、随机种子及生成产物，支持重现。
- [ ] 将真实取指、退休、寄存器/内存变化和可用的异常观察关联到输入；缺乏 RVFI 等信号时不推断退休或正确性。
- [ ] 选取不同 CPU 做代表性合法程序执行和独立重放；必要时使用可信参考模型检查结果，区分执行观察与指令正确性验证。

已有有限 RV32I/M/C 指令执行记录及 riscv-dv 小规模验证。PicoRV32 的 RVFI profile 已有单 CPU、单条 ADDI 的真实退休 smoke；这些均不代表完整 ISA 支持。

## 第四阶段：性能优化

### 目标

在前述正确性和可观测范围稳定后，减少宿主调度、事件处理、重复编译、重放及存储开销，使初始化后主要时间尽可能用于真实 DUT 推进。先建立基线，再用相同工作负载比较，不能通过减少实际 DUT 工作或丢弃必须证据制造加速。

### 工作与验收

- [ ] 分别测量初始化/编译、CPU 与 IP 内部推进、宿主调度、IPC、事件与证据处理、重放、写盘和峰值内存；说明计时是否重叠。
- [ ] 按实测热点精简每步事件复制、重复遍历、进程通信及不必要的状态重建，优先复用已构建的组件和长期会话。
- [ ] 为正常搜索和需要完整核验的验收分别提供适当输出与 replay 策略；不牺牲实际路径语义和可复现性。
- [ ] 使用固定 CPU/IP、输入序列与种子做优化前后 A/B：比较墙钟、每例耗时、DUT 推进、事件/结果一致性、吞吐量及峰值内存。
- [ ] 支持安全并行准备与执行，隔离临时输出和缓存；验证后及时清理，保留必要证据与可复现输入。

现有测量显示宿主调度与事件处理占比较高；例如某次 Pico 六路径 8 例含独立重放约 948 秒。具体加速目标应在建立同一配置的基线后确定，不以不同组合或不同证据范围直接比较。

## 相关入口

- 组件接入说明：[profile-onboarding.md](profile-onboarding.md)
- 当前原型证据、运行范围和限制：[profile-prototype-20261030.md](reports/profile-prototype-20261030.md)
- 数据流的现有正式定义：[CURRENT_DESIGN.md](CURRENT_DESIGN.md)
- 输入策略与方法约束：[final-method.md](../research/input-strategy-audit-20261027/final-method.md)
- 远程服务器和目录规则：[agent.md](../agent.md)
