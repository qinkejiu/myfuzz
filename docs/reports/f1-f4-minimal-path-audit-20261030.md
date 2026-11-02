# F1–F4 最小交互路径审计（只读）

日期：2026-10-30。范围：`/home/qinkejiu/myfuzz`，只读审计，不改源码/配置。
方法：读入口脚本与调用链、读 `configs/scenarios/*/generic_scenario.json`、读 `runs/**/summary.json` 已有真实数字；未新跑 RTL。
本阶段定位（按用户最新口径）：只保证 CPU ↔ host fabric（RAM/Router）↔ IP 三层之间的交互能跑通；DUT 内部正确性以后由插断言负责，宿主协议检查不作为对错判据。

## 1. 结论

1. 最小“传输 + 解释”链路在代码里确实存在，但被压在同一条通用流水线里：约 **27 个文件、21,928 行** 就够（第 2 节），而 `src/` 总量 **322,097 行 / 685 个 .py 文件**，其余 ~93% 是 F5/F6、证书/证据、验收门、SOC 组合、搜索与历史实验。
2. 每种总线**适配器基本只实现一次**（CPU 侧 4 个、IP 目标侧 2 个），但**执行器入口按协议对枚举**：`compiled_f4_obi_apb`、`compiled_mmio_obi_apb`、`compiled_f2_obi_apb`、`compiled_f4_wishbone`、`compiled_f5_obi_gpio`、`compiled_f6_cpu_dma`（`configs/scenarios/*/generic_scenario.json` 的 `executors` 字段）。这是“换组合就要加代码”的残留点。
3. **DUT 断言目前不会让测试失败**：Verilator 命令行 `local_harness/build.py:626` 为 `--cc --exe --build -j .. -Wno-fatal`，全仓库 `src/` 无 `--assert`；DUT 里确实有断言（`third_party`/`external_designs`/`src` 中 189 个文件含 `assert property`），但没被编译进 harness。子进程非零退出只被记进 `execution_audit.exits`（`integration/compiled_process_audit.py:249,267`），不改变结论。
4. 现在真正让一次运行“失败”的是宿主检查器：`scenario/runner.py:2669-2685` 只要 `IpProtocolChecker` 产出一条 finding 就置 `failure_status='protocol_violation'`、`_status='failed'`，其中包含 OBI park 会触发的 `obi_request_wait_budget_exceeded`（`scenario/ip_protocol_checker.py:955-959`）。**这与“不过问 DUT 内部、宿主只做传输”的口径直接冲突**，是最该先拆的一处。
5. 时间上，“跑一次很久”主要不是 DUT 推进：4 例 AXI4-Lite×APB 的 F2/F4 `execution_seconds=3.6`，`wall_seconds=34.4`（`runs/axil-native-original-20261030i/original/summary.json`）；而 8 例含 F5/F6 的混合运行 `wall=947.6`，其中 `replay_seconds=602.7`（64%）。**默认丢不掉的同进程 replay**（`src/myfuzz/search/workflow.py:7-16`，`execution_mode=None` 时 `legacy_default=True`）是最大单项。

## 2. 最小 F1–F4 执行链（文件级行数）

入口：`scripts/run_generic_scenario.py`（89 行）→ `runtime/generic_campaign.py:645 run_descriptor`（892 行，主体 645–882）。

| 层 | 文件 | 行数 | 关键符号 |
|---|---|---|---|
| 装配/输入 | `runtime/preparation.py` | 650 | `create_preparation:576` |
| 组件准入 | `runtime/admission.py` | 782 | `verify_component` |
| 适配器选择 | `runtime/registry.py` | 419 | `select_adapter` |
| 计划编译 | `runtime/compiler.py` | 2078 | `compile_execution_plan` |
| 计划绑定 | `runtime/binding.py` | 545 | `bind_execution_plan` |
| 用例循环 | `runtime/campaign.py` | 394 | `run_directed_campaign` |
| 流内核 | `runtime/flows/mixed.py` / `memory.py` | 318 / 462 | `MixedStorageKernel` |
| 执行器选择 | `local_harness/generated_execution_admission.py` | 241 | `create_compiled_execution:121` |
| runtime 类 | `integration/compiled_mmio.py` | 312 | `CompiledMmioRuntime:118` |
| CPU 会话 | `local_harness/cpu_session.py` | 796 | `GeneratedCve2Session`（OBI） |
| IP 目标会话 | `local_harness/apb3_register_session.py` | 464 | `GeneratedApb3RegisterSession` |
| IP 目标会话 | `local_harness/wishbone_register_session.py` | 192 | `GeneratedWishboneRegisterSession` |
| 宿主 RAM | `scenario/memory.py` | 584 | `PersistentMemory/MemoryRegion` |
| 宿主路由 | `scenario/router.py` | 332 | `DataflowRouter/DeviceWindow` |
| 调度/事务 | `scenario/session_runtime.py` | 3943 | `ScenarioSession` |
| 调度/事务 | `scenario/runner.py` | 3977 | `ScenarioRunner`、`failure_status:321` |
| 批量推进 | `scenario/batch.py` / `genome.py` | 333 / 300 | `BatchAdvance` |
| 检查器 | `scenario/checker.py` / `ip_protocol_checker.py` | 992 / 1124 | `IpProtocolChecker:38` |
| CPU 适配器 | `runtime/adapters/{obi,wishbone,ahb,axi4lite}_cpu.py` | 653/863/149/297 | 4 族 |
| IP 适配器 | `runtime/adapters/{apb3,wishbone}_mmio.py` | 87/93 | 2 族 |

合计 21,928 行。真正“传输 + 解释”的语义集中在 `cpu_session`+`apb3_register_session`+`memory`+`router`+`runner`（6,153 行）；`session_runtime.py` 3,943 行里有大量 reset/证据守卫，F1–F4 只用其中在线推进部分。

## 3. 可完全跳过的证据/证书/溯源层（具体文件与行数）

第一阶段运行不依赖、可按文件名整体排除的部分（共约 32,000 行）：

- 证书族（10 文件 8,558 行）：`scenario/{chain_certificates,computed_consumer_certificates,computed_value_certificates,irq_serial_certificates,isr_writeback_certificate,pin8_consumption_certificates,pin8_cpu_irq_certificates,pin8_irq_certificates,pin8_trap_retirement_certificates,uart_chain_certificates}.py` —— 全部是 F5/F6 的 IRQ/ISR/UART 链证书。
- 验收门（8 文件 14,511 行）：`scenario/{p2_acceptance,p3_acceptance,p3_acceptance_suite,p5_acceptance,p5_arm_metrics,p5_fault_family,p5_fault_quality,acceptance_metrics}.py`；对应 CLI `scripts/report_*`、`run_p*_acceptance*`。
- 溯源/证据（约 5,400 行）：`scenario/edge_provenance.py:2327`、`event_provenance.py:131`、`source_provenance.py:166`、`runtime/evidence/saved.py:2702`。F1–F4 事件里这些字段固定退化为 `origin_status=unknown`、`proof_scope=observation_only`（见 `runs/cv32e20-i2c-target-native-20261030/original/prefix.json` 的 `actual_events[].provenance`），删掉不改变任何观察。
- 重放族（12 文件 3,881 行）：`scenario/{replay,replay_normalize,native_replay_identity,dma_binding_replay}.py`、`integration/*_replay.py`、`composition/soc_*_replay.py`、`search/failure_replay.py`。注意：**运行内的 replay 只由 `runtime.replay()` 一次实现**（`compiled_mmio.py:300`、`compiled_f4.py:1592`、`compiled_wishbone_f4.py:1707`、`session_runtime.py:3361`），上面这些是额外的证书级重放。
- 其他：`scenario/capability_report.py:2021`、`assertion_classes.py:1769`、`scenario/cpu_retirement.py:555`（退休证据，第一阶段保持 unknown 即可）。

接口上可关：`scripts/run_generic_scenario.py` 只消费 `summary.json`；`--record-local-commands` 只是可选 trace；证书在 `CompiledMmioRuntime.finish` 内写 `flow_records`（`compiled_mmio.py:276-283`），属于“算了但没人判定”。

## 4. 协议适配矩阵与组合专用代码

CPU 侧（4 族，各一次）：`obi.cpu.v1`（`registry.py:28`，`adapters/obi_cpu.py:653`，会话 `cpu_session.py:796`）、`wishbone.cpu.v1`（`registry.py:32`，`adapters/wishbone_cpu.py:863`，会话 `wishbone_cpu_session.py:407`）、`ahb-lite.cpu.v1`（`registry.py:34`，`adapters/ahb_cpu.py:149`，会话 `ahb_lite_session.py:525`+`ahb_manager_domain.py:562`）、`axi4-lite.cpu.v1`（`registry.py:36`，`adapters/axi4lite_cpu.py:297`，会话 `axi_lite_session.py:311`）。

IP 目标侧（2 族）：`apb3.mmio.v1`（`registry.py:156`，`adapters/apb3_mmio.py:87`，会话 `apb3_register_session.py:464`）、`wishbone.mmio.v1`（`registry.py:148`，`adapters/wishbone_mmio.py:93`，`integration/wishbone_mmio_target.py:99`）。另有“存储观察”变体 `apb3_storage.py:1693`、`wishbone_storage.py:2206`（内存映射观察，不是新协议）。**AHB / AXI 的 IP 目标不存在**：`registry.py` 无 `target.ahb*` / `target.axi*` 注册项。

组合专用代码的证据（这是 30 万行的直接来源之一）：

- 执行器按协议对命名，`configs/scenarios/*/generic_scenario.json` 的 `executors`：各执行器在 descriptor 中出现次数：`compiled_f6_cpu_dma` 25、`compiled_f4_obi_apb` 13、`compiled_mmio` 10、`compiled_f2_obi_apb` 7、`compiled_mmio_obi_apb` 6、`compiled_f4_wishbone` 1、`compiled_f5_obi_gpio` 1。选谁在 `generated_execution_admission.py:128-144` 里用 `if executor==...` 硬分支。
- 成对的实现体：`integration/compiled_f4.py:1664`（OBI×APB）与 `integration/compiled_wishbone_f4.py:1793`（WB×WB）是两份独立 F4 字节流；`compiled_mmio.py:312` 又把 F2/F4 组合包一层。
- 场景目录按协议对复制：`compiled-f2-f4-obi-apb-i2c-{ibex,cv32e40p,cv32e40p-rvfi}`、`compiled-f2-f4-wb-apb-i2c-picorv32`、`compiled-f2-f4-ahb-apb-i2c-cvw`、`compiled-f2-f4-axil-apb-*-picorv32` 等 16 个（23 个 descriptor 中）。
- 反向证据（组合“借用”别人的证据文件）：`configs/scenarios/compiled-f2-f4-wb-apb-i2c-picorv32/generic_scenario.json` 的 `supplement`/`capability` 指向 `compiled-f2-f4-obi-apb-i2c-ibex/`。
- 这些 descriptor 的 `flow_ids` 多为 `["F2","F4"]`：**F1/F3 只在 6 个 descriptor 出现，其中 F1–F4 齐备的只有 `compiled-f1-f4-cv32e40p-gpio-shared`**，即“一次会话跑满 F1–F4”目前只有 OBI×GPIO 一路真实跑过。

## 5. 失败/错误判定现状

DUT 断言侧：`build.py:626` 的 Verilator argv 无 `--assert`，且 `-Wno-fatal`；生成的 `runtime.sv`/`driver.cpp` 里没有 SVA 或 `$fatal` 包装（见 `runs/axil-native-original-20261030i/generated-original-archived/cpu/runtime.sv`）。因此 `assert property` 在编译期即被忽略，DUT 内部断言**当前不构成失败来源**。若将来要接：需 `--assert` + 让子进程非零退出或 `vl_fatal` 冒泡为 case 失败（现在只在 `compiled_process_audit.py:249,267` 记录 `returncode`）。

宿主检查器侧（会先于任何 DUT 断言失败）：`runner.py:2663-2687`。触发条件包括：

- `*_wait_budget_exceeded`：OBI `obi_{request,response}_wait_budget_exceeded`（`ip_protocol_checker.py:955-959`）、APB 635、Wishbone 848/908、AHB 323/354、TLUL 481/586、AXI4-Lite 813。**OBI park 正是这一类**：取指被“停放”（`axi_lite_session.py:35-36,196-204,228`；`adapters/axi4lite_cpu.py:46` 明确声明 `declared_fetch_slot_parked_until_the_bound_source_materialises_it`），REQ 无 GNT 超过 `max_wait_cycles` 就判 `protocol_violation`。
- 其他：`*_request_changed_while_waiting`、`*_single_outstanding_overlap`、`*_signal_out_of_range`（`runner.py:2668`）。

建议保留（属于“传输层是否通”的事实）：地址/数据/字节使能位宽与译码落在声明窗口、reset assert/release 时序、REQ 最终被 GNT/响应（**只记录事件，不判失败**）、超时只作为“本 case 未完成”的状态而非 `failed`。

建议不再扩展：所有 `*_wait_budget_exceeded` 升级为失败、outstanding/overlap 互斥检查、`request_changed_while_waiting`、信号越界之外的协议时序断言、以及 `assertion_classes.py` 的自然/非自然 finding 分类。理由：这些都是在替 DUT 判断对错，与本阶段口径相反。

## 6. 一次批量运行的时间构成（真实数字）

| 运行 | 例数 | exec | replay | export | wall | 非执行占比 |
|---|---|---|---|---|---|---|
| `axil-native-original-20261030i`（AXI×APB，F2/F4） | 4 | 3.64 | 未请求 | — | 34.38 | 89% |
| `profile-spi-cvw-ahb-native-20261030`（AHB×APB） | 4 | 4.82 | 未请求 | — | 74.57 | 94% |
| `cv32e20-i2c-target-native-20261030`（F2/F4，含 shared_slots） | 2 | 7.21 | 17.54 | 2.76 | 75.55 | 90% |
| `zipdma-all-flows-20261030`（F1–F6） | 8 | 113.0 | 166.9 | 15.1 | 320.6 | 65% |
| `remote-profile-batch-20261030/pico-all-six`（F1–F6） | 8 | 231.0 | 602.7 | 19.7 | 947.6 | 76%（replay 一项 64%） |

结论：小批量 F1–F4 的固定成本（装配 + 路径编译 + 构建复用/构建 + 计划/绑定/审计导出 + 关闭）约 **25–70 s/次**，与例数几乎无关；DUT 推进本身 2–7 s。**最耗时环节按优先级：F5/F6 的 within-invocation replay > 每次运行的装配/构建/导出固定成本 > DUT 推进**。要变快不需要优化 RTL：把 `execution_mode='search'`（跳过默认 replay）+ 只对 1 个组合做独立进程 replay，上述 AXI 例从 34 s 可望降到 ~10 s 级。

## 7. 第一阶段最小验收清单（不扩证书层）

统一跑法：`scripts/run_generic_scenario.py --descriptor <场景> --flow mixed --mode original --case runs/<id> --rounds 128`；每个组合**一个会话内**跑 F1（取指/执行）、F3（RAM 写）、F2（读 IP）、F4（写 IP）。独立进程 replay 只做一次（E 项）。

| # | 组合 | 现有 descriptor | 观察什么 |
|---|---|---|---|
| A | Ibex OBI × APB I2C | `compiled-f2-f4-obi-apb-i2c-ibex` + `compiled-f1-f4-cv32e40p-gpio-shared` 的 F1/F3 | 取指地址/图像、RAM 读写、APB 请求响应 |
| B | PicoRV32 WB × APB I2C | `compiled-f2-f4-wb-apb-i2c-picorv32` | 同上 + WB 握手 |
| C | CVA6 AHB × APB I2C | `compiled-f2-f4-ahb-apb-i2c-cvw` | 同上 + AHB 地址/数据相位 |
| D | PicoRV32 AXI4-Lite × APB SPI | `compiled-f2-f4-axil-apb-spi-mmio-picorv32` | 同上 + 停放取指 |
| E | 同一 CPU（PicoRV32）配 WB IP | `compiled-f4-obi-wb-uart-setup`（**目前只有 F4**） | 需补 F1–F4，或将此项标为缺口 |
| F | 同一 IP（APB I2C）配两种 CPU 总线 | A + B 已覆盖，无需新代码 | 复用 A/B 记录 |

覆盖判定：A/B 满足“同一 IP 配两种 CPU 总线”；D + `wishbone.mmio.v1` 满足“同一 CPU 配两个同协议 IP”（WB IP 目标尚无 F1–F4 实跑，E 为唯一候选）；AHB/AXI 代表各一由 C/D 覆盖。每项只看原始观察：`events.json` 的事件流、`prefix.json` 的 `actual_events`、`failure_status`；不引用 `flow_records[].certificate`。

独立 replay 范围：只对 **C（AHB）** 做一次 `--mode fresh` 新进程重放，比对 `replay_matches` 与事件序列；A/B/D/E 仅保留同进程 `replay_matches` 或直接不请求。

## 8. 明确保持 unknown

退休/RVFI、RAM 读取版本、跨例来源（`origin_status`）、IP 内部状态与寄存器副作用、F5/F6（IRQ/DMA）、覆盖率、以及任何“DUT 内部正确性”结论。这些在报告与 summary 中一律标 `unknown`，不授奖励、不出证书。

## 9. 可执行的最小裁剪（不改语义）

1. `execution_mode='search'` 关掉默认同进程 replay（`search/workflow.py:7-16`）。
2. F1–F4 主流程不写 `flow_records[].certificate`、不写 `execution_audit.identities`、不产出 bound/plan 的完整文档（`generic_campaign.py:775-842` 的 3 次 JSON 落盘）。
3. 检查器降级为“事件记录”，不设 `failure_status='protocol_violation'`（`runner.py:2669-2685`）。
4. 只用 `run_generic_scenario.py` 一条入口，跳过 `run_shared_*`、`verify_*`、`report_*` 系列。
5. 场景只保留 5 个 descriptor（A–E），删掉 18 个重复协议对目录后仍可复现上述清单。
