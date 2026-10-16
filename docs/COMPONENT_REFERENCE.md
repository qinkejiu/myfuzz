# myfuzz 组件清单与功能

日期：2026-10-08。本文把**现有系统实际存在的组件**按功能列全，并写明每个组件"负责什么、证据在哪里"。清单直接由源码扫描生成（340 个 Python 模块 / 175,416 行），不是凭印象归纳。

> 结构讲解见 [系统说明](SYSTEM_OVERVIEW.md)；testcase 与数据流见 [testcase 与数据流](TESTCASE_AND_DATAFLOW.md)；状态与边界见 [当前工作进度](CURRENT_PROGRESS.md)。
> 模块清单机器可读版：`runs/current-dataflow-p5-final-20261007-logs/module_inventory.tsv`（路径／主要类／docstring 首行／行数）。

---

## 0. 组件全景（按层）

```text
                     ┌──────────────────────────────────────────────┐
   ①入口层           │ __main__ · capabilities · 57 个 scripts/      │
                     ├──────────────────────────────────────────────┤
   ②组合与规划层      │ composition/（67） · elaboration_probe        │
                     ├──────────────────────────────────────────────┤
   ③单 DUT harness 层 │ local_harness/（64） · protocols/（6） · isa/  │
                     ├──────────────────────────────────────────────┤
   ④场景执行层        │ scenario/（118）                              │
                     ├──────────────────────────────────────────────┤
   ⑤接入与运行层      │ integration/（38） · harness/（8） · experiments│
                     ├──────────────────────────────────────────────┤
   ⑥证据与验收层      │ 各层 *_acceptance* · runs/ · docs/reports/     │
                     └──────────────────────────────────────────────┘
```

各层代码量（本次扫描）：

| 层 | 模块数 | 行数 |
|---|---|---|
| 入口（`__main__`、`capabilities`、`rfuzz_compat`、`original_rfuzz`、`scripts/`） | 9 | ~6.2k |
| 组合与规划 `composition/` | 67 | 49,671 |
| 单 DUT harness `local_harness/` | 64 | 12,518 |
| 协议 `protocols/` ＋ ISA `isa/` ＋ 契约 `contracts/` | 14 | 2,961 |
| 场景执行 `scenario/` | 118 | 66,854 |
| 接入与运行 `integration/` | 38 | 26,857 |
| 其它（`components/`、`dependency/`、`harness/`、`experiments/`、`scenario/scripts/`） | 30 | ~10.6k |
| **合计** | **340** | **175,416** |

---

## 1. 入口层

| 组件 | 文件 | 功能 |
|---|---|---|
| CLI 主入口 | `src/myfuzz/__main__.py` | `python -m myfuzz {capabilities,harness,scenario,compat}`；当前工作流与历史兼容分离 |
| 能力查询 | `src/myfuzz/capabilities.py` | 从 `docs/LOCAL_HARNESS_RUNTIME.md` 解析"已登记的真实能力与限制"，带源文件摘要；**不重跑 RTL 验收**，只报告已登记证据 |
| 历史兼容 | `src/myfuzz/rfuzz_compat.py`、`original_rfuzz.py` | 早期 RFuzz 原生接入（`CandidateSource`/`CoverageBinding`/`RawAbiFragment` 等） |
| 门禁与验收脚本 | `scripts/*.py`（57 个） | 三类：**验收套件**（`run_p{3,4,5}_acceptance_suite.py`、`run_first_step_acceptance.py`）、**在线运行**（`run_ibex_pulp_online.py`、`run_ibex_uart_online.py`、`run_cv32e40p_pulp_online.py`）、**只读分析器**（`report_p5_arm_metrics.py`、`report_uart_chain_certificates.py`、`report_p5_assertion_classes.py`、`report_rtl_branch_coverage.py`、`report_p5_uart_routing_witness.py`、`survey_online_trace_kinds.py`、`check_doc_links.py`、`verify_*` 等） |

---

## 2. 组合与规划层（`composition/`）

职责：从**源码事实**与**声明式 profile** 出发，选出 CPU/IP 组合、分配地址、生成接线与约束；不臆测名字，任何缺口/重叠/未验证源码都拒绝。

### 2.1 源码事实与接口

| 组件 | 文件 | 功能 |
|---|---|---|
| 组件 profile 与请求 | `component_profile.py`（2243 行） | 统一、源钉住的 CPU/IP profile 与组合请求（`soc_spec.v1` 输入） |
| 接口描述 | `interface_description.py` | 语义化、源钉住的接口描述，供后续 HDL 分析 |
| 源码抓取 | `source_crawler.py`（1243 行） | 只读收集被钉住源码的 HDL 接口证据 |
| elaboration 读取 | `source_elaboration.py`（1016 行） | 从 Verilator JSON 语法树读有界物理端口事实 |
| 类型化事实 | `facts.py` | `hdl_facts.v2` 的"标识符不可见"视图（比较结构而非名字） |
| 参数证据 | `local_harness/parameter_evidence.py` | 从已钉源码快照取保守的 parameter 证据 |
| CVA6 源码闭包 | `cva6_source_closure.py` | 只用钉住的文件清单解析，不查浮动源码 |

### 2.2 规划与搜索

| 组件 | 文件 | 功能 |
|---|---|---|
| 通用规划 | `generic_planner.py`（1581 行） | 多组件规划：端点能力 → 协议匹配 → 适配器 → 连接 |
| 自动组合 | `auto.py`（900 行） | catalog 驱动的确定性 CPU/外设组合规划 |
| 候选搜索 | `search.py` | 确定性、有界内存的组合候选搜索 |
| 端点能力 | `endpoint_capabilities.py` | 源支撑的端点能力与协议匹配 |
| 地址分配 | `address.py` | 通用地址提取与确定性区段分配 |
| 连接约束 | `constraints.py`、`constraint_ir.py` | 类型化、确定性的连接约束与小表达式语言 |
| IR 与清单 | `ir.py`、`manifest.py`、`metadata.py`、`declarations.py` | `composition_ir.v1` 序列化、候选清单、可移植 JSON 校验 |
| SoC 计划 | `soc_plan.py`、`soc_fabric.py`、`soc_interrupt_plan.py` | 把 `soc_spec.v1` 绑到实例/适配器/网表；仲裁路由 fabric；中断编号与路由计划 |

### 2.3 生成、约束与适配

| 组件 | 文件 | 功能 |
|---|---|---|
| 输入布局 | `input_layout.py` | 源绑定的确定性 RFuzz 输入布局 |
| 输入约束与归属 | `input_constraints.py`（845 行） | 组合 SoC 的版本化输入约束与 ownership 策略 |
| 契约转导 | `contract_transducer.py` | 把 ISA/总线契约编译成确定性 RFuzz 执行 |
| 处理器边界/适配/执行 | `processor_boundary.py`、`processor_adapters.py`、`processor_execution.py`、`processor_backend.py`、`processor_renderer.py` | 与 CPU 名字无关的执行边界、协议适配器、确定性执行记录与渲染 |
| 目标适配器 | `target_adapters.py` | 把 beat 请求解析成真实外设协议 |
| SoC 渲染 | `soc_renderer.py`（2009）、`soc_profile_renderer.py`（1542）、`soc_runtime.py`（1980） | 确定性渲染可编译 SoC 顶层并构建运行 |
| 结构审计 | `soc_structure_audit.py`（2011） | 对生成 SoC 做独立结构审计 |
| 端口处置台账 | `soc_port_dispositions.py` | 逐端口/逐 bit 段的处置台账 |
| 范围声明 | `soc_scope.py` | 机器可读的协议与适配器范围 |
| 参照模型 | `pulp_gpio_oracle.py`、`pulp_spi_oracle.py`、`soc_peer_oracle.py` | 独立的、fail-closed 的参照实现（不参与被验证路径） |

### 2.4 历史 SoC 路线（P14 一带，当前主线之外的共享实现）

`soc_composition.py`、`soc_contracts.py`、`soc_stimulus.py`、`soc_boot_program.py`、`soc_candidate_program.py`、`soc_image.py`、`soc_failure_evidence.py`、`soc_offline_defect_confirmation.py`、`soc_input_chain_report.py`、`soc_comparison.py`、`soc_matrix_smoke.py` 等：完整的"composed SoC"路线（自举程序、激励编译、失效证据、离线确认）。**当前主线的在线增量路径不依赖它们**，但共享源码事实与 profile 格式。

---

## 3. 单 DUT harness 层（`local_harness/` ＋ `protocols/` ＋ `isa/`）

职责：为**一个** CPU 或 IP 生成可构建、可运行、身份可复现的真实 RTL harness。

### 3.1 生成链（plan → render → build → session）

| 组件 | 文件 | 功能 |
|---|---|---|
| 请求 | `request.py` | 严格声明式请求（完整源 profile、实例 ID、reset/等待界限） |
| 规划 | `plan.py` | 钉住源事实与逐位归属；缺口/重叠/未知信号拒绝 |
| 结构 wrapper | `renderer.py`、`port_rendering.py` | 逐位保持的单 DUT 结构 wrapper 与 ABI/构建文档 |
| 运行时顶层 | `runtime_renderer.py`（963 行） | 源准入的 runtime top；适配器留在结构 wrapper 之外 |
| Driver | `driver_renderer.py`（961 行） | 生成有界 C++ 传输（逐本地时钟采样） |
| 时钟 | `clock_schedule.py` | 组件本地频率调度（正整数、可整除偶数慢时钟比 ≤1024） |
| 构建 | `build.py` | 身份为键的有界构建；缓存键由实际构建输入决定 |
| Session | `session.py`、`wire.py`、`protocol_io.py` | 有界期限的持久传输、严格回执、命令行读取 |
| 源锁 | `source_lock.py` | 显式的钉住源码闸门，与规划/渲染分离 |
| 产物身份 | `runtime_artifact.py`、`identity.py` | 后续阶段消费的冻结身份容器 |
| 声明式微调 | `tuning.py` | 类型化 tuning；执行仍需具体 runtime 准入 |

### 3.2 通用协议模板与服务

| 模板 | 文件 | 功能 |
|---|---|---|
| TL-UL 寄存器 | `tlul_register_template.py`、`tlul_register_session.py`、`tlul_session_factory.py` | 组件中立的持久 TL-UL 寄存器与引脚观察（GPIO/RV Timer/SPI Device 等复用） |
| APB3 寄存器 | `apb3_register_template.py`、`apb3_register_session.py` | 同上，APB3 形态（PULP GPIO/Timer） |
| Wishbone 寄存器 | `wishbone_register_template.py`、`wishbone_register_session.py` | 同上，Wishbone 形态（ZipCPU Timer/wbuart） |
| 串行 peer | `tlul_uart_peer_session.py`、`tlul_spi_mode0_peer_session.py` | 可复用的 8N1 UART peer 与单线 SPI mode-0 master |
| 完成式内存 | `native_session.py`、`native_contract.py` | 通用单笔未完成 completion memory 服务；可选 `DataflowRouter` 把落在已声明设备窗口内的 beat 交给真实目标（无 router 时逐字节不变） |
| 工厂 | `generated_register_factory.py` | 由准入产物创建 register session 与输入归属 |

### 3.3 各 DUT 会话（真实 CPU / IP）

**CPU 适配目标与协议对应**（权威口径，与 [P6 逐协议行适配清单](superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md) §1.4 同源）：

| CPU | 对应协议 | 本仓库会话实现 | 现状 |
|---|---|---|---|
| Ibex | OBI 指令 / 数据 | `cpu_session.py` | 可规划、已有真实 RTL 验收 |
| CVA6 | 打包 64 位 AXI4 单主端口 | `cva6_axi4_session.py`＋`cva6_axi4_fields.py` | 可规划、已有真实 RTL 验收 |
| CV32E40P | 分离 OBI 指令 / 数据 | `cpu_session.py` | 可规划 |
| BOOM | TileLink 1.0 指令 / 数据端点 | —（无 `component_profile.json`） | `skipped_unavailable`：仅有参考用语义描述，缺 Chipyard 生成与真实 profile。**2026-10-13 实测查清阻断链（比"缺 java"更本质）**：构建入口是 sbt／Mill，依赖 **Chisel 6.5.0** 且 `rocketVersion = "1.6-SNAPSHOT"`（快照版本）；该仓库**自身没有任何 Verilog 生成目标**，README 明写 "NOT A SELF-RUNNING repository… use the Chipyard SoC generator"（`CHIPYARD.hash` = `4180463d…`）。故需**完整 Chipyard 工具链＋JVM＋快照依赖解析**；本机 `java`／`javac`／`sbt`／`mill` 全无，且 `sudo` 因 `no new privileges` 被禁、apt 不可用。CPU 侧契约已有（`cpu.tilelink` 两 variant） |
| CVW（CORE-V Wally） | AHB-Lite 外部总线（EBU） | — | `skipped_unavailable`：**2026-10-13 已取得真实源码**（`third_party/cvw_upstream_reference`，顶层 commit `2f2ddfd`，`CVW_v0.9` 可钉定），且是 **SystemVerilog，Verilator 可直接吃、不需要 JVM**。权威端口集取自 `src/wally/wallypipelinedsoc.sv`：输出 `HCLK`/`HRESETn`/`HADDR`/`HWDATA`/`HWSTRB`/`HWRITE`/`HSIZE`/`HBURST`/`HPROT`/`HTRANS`/`HMASTLOCK`/`HREADY`/`HSELEXT`，输入 `HRDATAEXT`/`HREADYEXT`/`HRESPEXT`（读数据在 CPU 边界叫 **`HRDATAEXT`**；`src/ebu/ebu.sv` 故意不含 `HRDATA`，其注释明写 "HRDATA is sent to all controllers at the core level"）。**真实宽度**（读自 CVW 自身配置，rv32imc）：`XLEN=32`、`AHBW=XLEN=32`、**`PA_BITS=34`**——故 `HADDR` 34 位、比数据端口宽。**已做到**：声明 `configs/cpus/cvw/interface_description.json`、插件 `ahb_lite.json`、CPU 侧契约 `cpu.ahb-lite`、**顶层 Verilator elaboration 通过**（226 个 `.sv`，`wallywrapper`）。**2026-10-13 更新：已通过 P7-A 声明核对（`ok cvw 9/9`，supervisor 可用与不可用**两条路径结论一致**）**，端口事实由真实 Verilator elaboration 提取（18 端口、`HADDR`=34）、与声明／契约／渲染器形状三方一致。**不入 `sources.lock.json`**：本仓 local profile（`ibex_rvfi_local`／`opentitan_*_local` 等）的官方约定是 `root:"."` ＋ sha256 pin 且**不登记 lock 记录**，CVW 遵循同一约定（实测移除该记录后 `verify_soc_sources.py` 恢复 29/29 全通；保留则唯一失败项就是它）。**2026-10-14 更新**：AHB 运行期分支此前方向写反（`beat_to_ahb_lite.sv` 把 harness 当主设备），已改为**从属端** `ahb_lite_memory_target.sv`（含自检 testbench：IDLE 非交易／读相位与完成／写在地址相位后一拍才采 `HWDATA`／无人应答保持不伪造完成；首版有真实自握手死锁，已修，testbench PASS ＋ `verilator --Wall` 0 warning），运行期渲染器 `ahb_lite_cpu` 分支已实例化它、beat 地址宽度修正为 **34**（曾静默截成 32），生成的 runtime top 与**真实 CVW 源码**经仓库自己的 `run_verilator_elaboration` 一起通过（`tests/integration/test_cvw_ahb_runtime_generation.py` 2 passed），且这 243 文件内容 pin 覆盖**派生配置**。**上游阻断点（新证据）**：`adrdec.Sel = Match & Supported & AccessValid & SizeValid`，CVW 六个已提交配置的 `EXT_MEM_SUPPORTED` **全为 0**，故 `HSELEXT` 永不选通、外部 AHB 端口在上游不可达（CVW 自己的 testbench:545 因此把 `HREADYEXT` 恒置 1）；且 `EXT_MEM_BASE == UNCORE_RAM_BASE == 0x80000000`。本仓已按 `scripts/derive_cvw_config.py` 生成并钉定派生配置（开 `EXT_MEM_SUPPORTED=1`，外部区移到 `0xC0000000..0xCFFFFFFF`，生成期断言与所有启用区间不相交），并把 `config_extmem` 放在 `include_roots` 首位。**仍缺**：**真实 AHB 交易**（实测 `transactions=0`；外部区取指程序尚未跑通）——**通过 P7-A、能 elaborate、配置已开启、从属端模型正确，四者都不等于可执行** |
| VexiiRiscv | TileLink 内存总线 | — | `skipped_unavailable`：仓库无源码／配置／profile。**2026-10-13 实测**：上游 `SpinalHDL/VexiiRiscv` 的 **releases 为空**（无已生成 Verilog 可下载），SpinalHDL 生成需 JVM（本机无 `java`），故阻断性质与 BOOM 相同——缺工具链而非缺仓库访问 |
| ZipCPU | AXI4（分离指令／数据） | `axi4_cpu_session.py`＋`axi4_fields.py` | 可规划 |
| PicoRV32 | AXI4-Lite ／ Wishbone ／ 原生完成式 | `axi_lite_session.py`、`wishbone_cpu_session.py`、`native_session.py` | 可规划 |
| RVX | 流水完成式内存 | `rvx_memory_session.py` | 可规划 |

**协议能力（不得用别的协议抵消）：** CPU 侧模板契约现有 `cpu.obi`／`cpu.axi4`／`cpu.axi4-lite`／`cpu.wishbone`／`cpu.native-memory`／`cpu.pipelined-memory`／**`cpu.tilelink`（两 variant，依 BOOM 真实声明）**／**`cpu.ahb-lite`（variant `cvw-external-bus`，依 CVW 真实声明，2026-10-13 补齐）**，全表共 **15** 条（CPU 侧 10 ＋ target 侧 5）。AHB-Lite 契约的角色名与两条真实形态事实：读数据在 CPU 边界叫 **`HRDATAEXT`**（`src/ebu/ebu.sv` 故意不含 `HRDATA`，其注释明写 "HRDATA is sent to all controllers at the core level"），**`HSELEXT` 是 CVW 片选扩展而非 AHB-Lite 信号**；`AHBW`/`PA_BITS`/`XLEN` 是 `cvw_t` 字段，故契约只声明参数化宽度并标注 `elaboration_status='not-elaborated'`。**AHB-Lite 仍未 elaboration、未跑任何交易，CVW 行仍为 `skipped_unavailable`——有契约不等于可用。** 注意仓库里的 `target.tl-ul` 是 TileLink-UL **目标（外设）**契约，与 BOOM／VexiiRiscv 的 TileLink 1.0 **CPU 端点**不是同一条目。

**按组件列出的会话文件：**

| 类别 | 组件 |
|---|---|
| CPU 会话文件 | `cpu_session.py`（OBI，598 行）、`cva6_axi4_session.py`＋`cva6_axi4_fields.py`（packed AXI4）、`axi4_cpu_session.py`＋`axi4_fields.py`（ZipCPU AXI4）、`axi_lite_session.py`、`wishbone_cpu_session.py`（PicoRV32）、`rvx_memory_session.py`（RVX） |
| OpenTitan IP | `opentitan_gpio_session.py`（＋`_contract`）、`opentitan_uart_session.py`（710 行，＋`opentitan_uart_contract.py`/`opentitan_uart_fifo_contract.py`）、`opentitan_spi_host_session.py`、`opentitan_spi_device_session.py`、`opentitan_i2c_session.py`、`opentitan_rv_timer_session.py`、`opentitan_sysrst_ctrl_session.py`、`opentitan_pattgen_contract.py` |
| PULP IP | `gpio_session.py`、`spi_session.py`、`i2c_session.py`、`timer_session.py`（＋对应 `_contract`） |
| 其它 IP | `axil_uart_session.py`、`wishbone_uart_session.py`、`zip_timer_session.py` |
| Ibex 专用契约 | `ibex_rvfi_contract.py`、`ibex_irq_receipt_contract.py`、`uart_controlled_irq_contract.py` |
| 契约工具 | `template_contracts.py`（406 行，只读协议契约，共 12 条）、`pulp_gpio_probe_contract.py` 等 |

### 3.4 协议与 ISA

| 组件 | 文件 | 功能 |
|---|---|---|
| 协议模板注册表 | `protocols/`（6 模块） | OBI、AXI4、AXI4-Lite、Wishbone classic、Pico native Ready/Valid、TL-UL、PULP APB3 的目标端变体 |
| ISA | `isa/`（5 模块） | RV32I/RV32E 编码与约束、指令字生成 |
| 契约 | `contracts/`（3 模块） | 版本化契约断言与校验 |

---

## 4. 场景执行层（`scenario/`，118 模块）

这是最大的一层。按功能分十组。

### 4.1 会话与 testcase 骨架

| 组件 | 文件 | 功能 |
|---|---|---|
| 在线会话 | `session_runtime.py`（1158 行） | **`OnlineCase` / `OnlineCaseReceipt` / `ScenarioSession`**：无 reset 的在线 testcase 流；5 阶段提交（先决条件→接纳→注入→推进→判定） |
| 连续 Runner | `runner.py`（2374 行） | 独立步进的本地 harness 的最小连续 runner；事件计数、本地 tick、命令 epoch |
| Scheduler | `scheduler.py` | 公平本地步进与"由因果触发的源动作" |
| Batch 脚本 | `batch.py` | 单例状态化 testcase 的在线命令脚本 |
| Genome | `genome.py`、`mutation.py` | 连续源动作 genome 与"只变异声明源"的选择逻辑 |
| 在线解码 | `online_case_decoder.py`（1486 行） | 纯输入解码；提交发生在准入之后 |
| RFuzz 解码 | `rfuzz_decoder.py` | 把 RFuzz 记录解成一个依赖感知的持久 testcase |
| 事件日志 | `event_journal.py` | 有界内存的有序事件存储（长在线会话） |
| 事件来源 | `event_provenance.py`、`source_provenance.py` | 追加时证据元数据；显式源接纳（不做图或运行时推断） |

### 4.2 输入归属、路径与先决条件

| 组件 | 文件 | 功能 |
|---|---|---|
| 归属 | `ownership.py` | 编译 DUT 输入的排他 bit 归属（`bound_input`/`fixed_input` 拒绝） |
| 依赖 | `dependency.py` | 从目标反向到可变异源的 AND/OR 依赖路径 |
| 路径契约 | `runtime_path_contract.py`、`decode_space.py` | 显式静态路由声明与 decode space 身份闭包 |
| 源动作 | `source_actions.py`（2601 行） | **版本化源动作、显式先决条件、有界跨例效果**（`instruction_slot`/`ram_byte_version`/`transport_idle`） |
| 动态先决条件 | `dynamic_prerequisites.py`、`state_dependency.py` | 由真实内存提交/读取产生的字节版本依赖 |
| 拒绝码 | `rejection_codes.py` | 版本化、机器可读的候选拒绝码（37 个） |
| 运行时边索引 | `runtime_edge_index.py` | 把实际事件归因到显式选中的路由候选 |
| 波形闸门 | `uart_waveform_gate.py` | UART RX 波形并发访问的 fail-closed 接纳闸门 |
| 初始 RAM | `initial_ram_data.py` | 会话启动前决定声明字节（opt-in 操作子） |

### 4.3 内存与事务

| 组件 | 文件 | 功能 |
|---|---|---|
| 字节内存 | `memory.py` | 一个连续 testcase 的权威字节内存 |
| 内存服务 | `memory_service.py` | CPU 请求提交时冻结 RAM 响应 |
| 事务账本 | `ledger.py` | 逻辑事务身份与进程内 at-most-once 交付 |
| 提交/读取权限 | `memory_commit_authority.py`、`memory_read_authority.py` | 已安装回调的有界授权 |
| 路由 | `router.py` | 把被接受的 CPU beat 交付到独立真实 IP RTL |

### 4.4 检查器与断言

| 组件 | 文件 | 功能 |
|---|---|---|
| 离线属性 | `checker.py` | 从被接受事务与真实 RTL 输出求值的属性 |
| 在线检查 | `ibex_pulp_online_checker.py`、`ibex_uart_online_checker.py`、`ibex_uart_gpio_assertions.py` | 增量"只看观察"的检查 |
| 断言分类 | `assertion_classes.py`（1769 行） | 协议/跨组件/CPU-IP 三类分开报告 + 异常记录 fail-closed 普查 |
| 受控故障 | `p5_controlled_irq_fault.py`、`p5_controlled_uart_fault.py`、`p5_fault_family.py`、`p5_fault_quality.py` | 只改 checker 观测副本的校准注入；9 变体族；同条件质量对照 |
| 反馈 | `feedback.py`、`interaction_feedback.py`、`closed_loop_feedback.py` | 只看真实 RTL 输出的语义目标；交互反馈；闭环能量（从链证书只读消费） |

### 4.5 证书（"谁消费了谁"的精确证据）

| 证书 | 文件 | 连接什么 |
|---|---|---|
| 逐边来源 | `edge_provenance.py`（2179 行） | 契约声明边（mmio_route / direct_binding / persistent_state）在真实 trace 上的精确 join |
| 持久状态边 | `persistent_state_provenance.py` | 追加的 RAM 字节版本与寄存器位版本两条边 |
| 链证书 | `chain_certificates.py`（1381 行） | 端到端传播链的逐跳增量证书（GPIO 路径） |
| UART 链证书 | `uart_chain_certificates.py`（1906 行） | UART 16 跳声明 DAG 的证书（只读） |
| 跨例链 | `cross_case_chains.py` | 保存 trace 上的可复算跨例链 |
| 消费证书 | `gpio_consumption.py`、`uart_consumption.py`、`computed_consumer_certificates.py`、`computed_value_certificates.py` | 寄存器/同步器/原生 IRQ 事实；CPU 计算值到设备消费值 |
| pin8 系列 | `pin8_consumption_certificates.py`、`pin8_irq_certificates.py`、`pin8_cpu_irq_certificates.py`、`pin8_trap_retirement_certificates.py` | pin8 源 → 原生 IRQ → CPU 输入/取中断 → trap 退休（强度递减，各自标注） |
| UART 系列 | `uart_irq_consumption.py`、`uart_irq_entry.py`、`uart_retired_read.py`、`uart_operand_seed.py`、`uart_operand_use.py`、`uart_store_memory.py`、`uart_ram_commit_join.py`、`uart_memory_readback.py`、`uart_register_copy.py`、`uart_cross_case_action.py` | UART 的 IRQ 级 join、受控入口、退休 LW、寄存器版本 seed 与实际 SW rs2、写内存 lane0 版本、跨例动作 |
| IRQ serial | `irq_serial_certificates.py`、`irq.py` | 被动 Ibex IRQ serial sideband 的精确 join；单源脉冲映射 |
| 写回端点 | `isr_writeback_certificate.py`（1337 行） | ISR 写 GPIO A 的精确身份端点 |
| 退休/交付 | `cpu_retirement.py`、`retirement_delivery.py` | 保守 RV32I 退休见证；退休到实测目标交付的精确键关联 |
| UART 路由见证 | `uart_routing_witness.py` | 逐 case 的 UART 寄存器访问与目标消费见证（写进 report 的 `source_target_transactions`） |

### 4.6 覆盖与效率

| 组件 | 文件 | 功能 |
|---|---|---|
| RTL 内部分支覆盖 | `rtl_branch_coverage.py`（981 行） | 只报告来自 RTL 插桩的覆盖；`coverage_attestation()` 统一新旧 provenance 形态 |
| slot 不可变性 | `slot_immutability.py`（781 行） | 只读扫描保存 trace 的 slot 是否 immutable |
| 验收指标 | `acceptance_metrics.py`（1722 行） | 单遍扫描一个运行目录得出有效例/s、链/s、覆盖新颖率、无效/超时比例等 |
| 单臂指标 | `p5_arm_metrics.py`（1434 行） | 固定预算对照所需的 12 组声明量（每叶带来源与 null 原因） |
| 配对效率 | `paired_efficiency.py`（1455 行） | 连续会话 vs 逐例冷启动的同预算对照（含 9 项可比性先决条件） |
| 臂等价 | `arm_equivalence.py`（1493 行） | 共享 raw 窗口内两臂的逐字段等价/不等价/未知 |
| 算子收益 | `p4_operator_benefit.py`（1612 行） | 合法操作子的同预算收益对照（只读） |
| 在线诊断 | `scenario/scripts/`（5 模块） | 在线运行的分项计时与诊断 |

### 4.7 验收与阶段判定

| 组件 | 文件 | 功能 |
|---|---|---|
| P2 | `p2_acceptance.py`、`p2_negative_gates.py` | P2 逐条判定；六个声明破坏变体的"零进程预检"负例 |
| P3 | `p3_acceptance.py`、`p3_acceptance_suite.py` | P3 判定与跨 run 联合套件（7 项关键验收） |
| P4 | `p4_operator_benefit.py`＋`scripts/run_p4_acceptance_suite.py` | P4 关键项 8/8 |
| P5 | `p5_acceptance.py`（2464 行）、`p5_arm_metrics.py`、`p5_fault_quality.py` | P5 六项关键项联合判定；单臂指标；故障质量对照 |
| 可复现证据 | `evidence.py`、`evidence_identity.py`、`replay.py`、`host_identity.py`、`identity.py` | 保存一个连续 testcase 并从新 RTL 状态重放；身份容器与 host 源闭包 |

### 4.8 各组合的 wiring 与样例

`ibex_pulp_dual_source.py`（1733 行，Ibex＋双 PULP GPIO 双源 wiring）、`ibex_uart_online.py`、`cv32e40p_pulp_dual_source.py`、`cva6_session.py`、`ibex_session.py`、`uart_session.py`、`gpio_session.py`、以及 `*_example.py`（`uart_example`、`uart_gpio_example`、`ip_cpu_ip_example`、`ibex_i2c_example`、`ibex_spi_*_example`、`ibex_timer_example`、`cva6_gpio_example`、`edge_experiments.py`）。

### 4.9 持久状态与源回声

`state_dependency.py`、`persistent_state_provenance.py`、`window`/`ownership` 相关实现，以及"源回声"检查：`uart_memory_readback.py`、`uart_store_memory.py`、`uart_ram_commit_join.py`。

### 4.10 场景契约与旧入口

`contracts.py`（版本化预检契约）、`campaign.py`、`examples.py`、`batch.py`。

---

## 5. 接入与运行层（`integration/`，38 模块）

| 组件 | 文件 | 功能 |
|---|---|---|
| **在线 RFuzz 适配** | `scenario_rfuzz.py`（2456 行） | 完整持久 testcase 的 RFuzz 共享缓冲适配器；含 `case_witness_recorder` 钩子 |
| **在线 Rust 客户端** | `scenario_rfuzz_live.py`（1504 行） | opt-in 的真实 Rust RFuzz 客户端；写 `report.json`、身份、`source_target_transactions` |
| 重放 | `scenario_rfuzz_replay.py` | 用保存的 raw 语料在全新独立 RTL 上重放 |
| 组合 wiring | `ibex_pulp_online.py`、`ibex_uart_online.py`、`cv32e40p_pulp_online.py` | 各自的"一个无 reset 会话"装配 |
| RFuzz 运输 | `rfuzz_live.py`、`rfuzz_runner.py`、`rfuzz_shmem.py`、`rfuzz_fifo.py`、`rfuzz_wire.py`、`rfuzz_toolchain.py`、`rfuzz_simulator.py` | 共享内存/套接字通道、客户端解析、持久 layout-to-Icarus 边界、采样输出位计数 |
| Campaign 编排 | `scenario_campaign.py`（1321）、`campaign.py`（1783）、`real_cpu_campaign.py`、`generic_rtl_campaign.py`、`cva6_scenario_campaign.py`、`soc_campaign.py`、`experiment_matrix.py` | 低资源进程监督、真实 CPU campaign、矩阵执行与原子发布 |
| 监控与审计 | `rtl_execution_monitor.py`、`interaction_monitor.py`、`semantic_projection.py`、`manifest.py`、`pipeline.py` | 协议无关内存边界观察；交互链匹配；语义视图；跨 manifest 哈希 join |
| 资源 | `memory_lock.py`、`low_resource_smoke.py`、`_reference_supervisor.py`、`reference_adapter.py` | 进程共享内存配额；低资源路径验证；可信参照评估器隔离 |
| 覆盖与构建 | `soc_coverage.py`、`soc_builder.py`（3078 行）、`soc_comparison.py`、`soc_matrix_smoke.py` | 实例映射 RTL 覆盖；配置驱动真实构建（含 elaboration 探针）；三臂对照 |
| RISC-V 执行 | `riscv_execution.py`、`rtl_execution_monitor.py` | 事实驱动的有界真实处理器验收支撑 |

---

## 6. 配置、RTL 与外部依赖

| 类别 | 位置 | 说明 |
|---|---|---|
| CPU profile | `configs/cpus/`（14 个：ibex、ibex_obi_local、ibex_rvfi_local、cv32e40p、cv32e20、cva6、picorv32 系列、rvx_core、zipaxi、boom…） | 源码位置、顶层、时钟/复位、端口 |
| 外设 profile | `configs/peripherals/` | OpenTitan/PULP/ZipCPU 各 IP 的模块、地址宽度、原生总线 |
| 组合闭包 | `configs/soc/{closures,checkers,families}/` | 组合闭包与 checker profile |
| 场景声明 | `configs/scenario/`、`configs/campaigns/`、`configs/designs/`、`configs/experiments/` | 路径、源、预算、矩阵 |
| RTL | `third_party/rfuzz/upstream/ibex/`、`…/pulp_*`、`…/opentitan/`、`…/zipcpu/` 等 | 被钉住的真实 RTL 源码 |
| RFuzz 参考实现 | `third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz` | 运输客户端（Rust，需预先构建） |
| 工具链 | Verilator 5.051（`~/.local/verilator-5.051-e413e67/bin/verilator`） | 真实 RTL 仿真 |

---

## 7. 证据与验收组件

| 组件 | 位置 | 功能 |
|---|---|---|
| 运行目录 | `runs/<run-id>/` | `online_run_identity.json`、`online_plan.json`、`online_session_manifest.json`、`receipts.jsonl`、`online_events.{zlib,json}`、`report.json`、`failures/` |
| 门禁脚本与日志 | `runs/*-logs/` | 真实 RTL 门禁脚本、运行/重放日志、只读分析产物 |
| 验收报告 | `docs/reports/`（563 文件） | 阶段验收、逐特性真实门禁、边界与复算入口；索引在 `reports/README.md` |
| 工作日志 | `.superpowers/sdd/` | 过程记录与独立审查（**不等于**验收） |
| 文档守卫 | `scripts/check_doc_links.py`、`scripts/check_identifier_policy.py` | 链接 0 断链；标识符不可见策略 |

---

## 8. 组件与"已验收范围"的对应关系

| 组件层 | 已验收范围 | 关键边界 |
|---|---|---|
| 入口／组合 | P0、P1 完成 | 组合器覆盖已声明的协议形态；不满足的形状在规划期拒绝 |
| 单 DUT harness | 5 类 CPU 协议 ＋ OpenTitan/PULP/ZipCPU 多 IP 有真实运行证据 | 见 [运行能力表](LOCAL_HARNESS_RUNTIME.md) 的逐条限制 |
| 场景执行 | P2～P5 按声明范围完成 | 十项边界见 [P5 阶段验收](reports/current-dataflow-p5-stage-acceptance-20261008.md) |
| 证书 | 逐边 11/11、GPIO 链 27 条、UART 链 7 条认证 | 证书只证"产物内被见证"，不证 DUT 无其它行为 |
| 接入 | 在线 RFuzz（Ibex＋双 PULP GPIO、Ibex＋OpenTitan UART） | 重 RTL 串行；跑时不可改 `src/` |
| 组合路线（历史） | 多组件 composed SoC 有独立证据 | **不属当前主线验收**，不自动继承 |

---

## 9. 一句话总结

> 组件分六层：**入口（怎么调）→ 组合（怎么连）→ 单 DUT harness（单个组件怎么真跑）→ 场景（多个 testcase 怎么连续跑）→ 接入（fuzzer 怎么驱动）→ 证据（凭什么信）**。
> 每一层都有独立的门禁与边界；**上层能力不能自动继承下层证据**，每一份"已验收"都绑定它自己的源码身份与声明范围。
