# 当前方案的代码组织与入口

更新：2026-10-08。本页描述**实际源码依赖与模块职责**。统一阶段状态、正在执行的门禁和证据入口见 [当前进度](CURRENT_PROGRESS.md)；已记录的组件运行证据与限制见 [运行能力表](LOCAL_HARNESS_RUNTIME.md)，验收顺序见 [实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)。P1–P5 的当前代码核对及目录分类见[第一步代码与文档核对](reproduction/first-step-code-doc-audit-20261008.md)。

P1–P5 已按各阶段报告的声明范围验收，P6–P8 未验收；本次重新检查 P1、P2、P3、P5 的软件／保存证据门禁，P4 完整门禁因内存增长中止，详见[复现手册](reproduction/first-step-p1-p5-20261008.md)。各次真实 RTL 证据仍绑定记录时的源码身份，不因本页更新而自动变成当前源码的新运行。

用户原件 `SoC内部数据流动与去向.docx` 是取指、数据读、数据写、MMIO、中断和 DMA 六类数据流的设计来源，逐类目标与当前状态见[实施计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)。运行时路径应编译自受信组件事实和显式场景声明；该 Word 文件本身不是自动接线配置。

## 2026-10-24 Compiled F2 文件与统一 RFuzz 执行链

显式 compose／capability／supplement／records → D2 artifacts 与同次 D3 → `f2_read_contract.py`／`compiled_f2_runtime_path.py` 严格准入 → 独立地址 layout／reader／decoder → `CompiledF2Runtime` 启动后解析当前 IP register version → 真实 OBI／APB read 与依赖 RAM store → 每个 admitted attempt 的 typed 断言及独立 inventory → 新进程完整 fresh → `compiled_runtime_report.py` 校验能力报告材料 → 文件入口保存并重核初始字节 pin。

共享 `compiled_process_audit.py` 只抽取构建回执、实际进程身份与部分诊断，不把 F2 作为 F4 executor 子类。F2 保持自己的 binding／build join／execution audit schema。文件入口为 `scripts/run_compiled_dataflow.py --executor compiled_f2_obi_apb`；统一 `auto_harness`／RFuzz 已新增显式 `compiled-f2-rfuzz` adapter。运输、反馈、receipt join、live/fresh 生命周期、保存字节与 F2 在线材料校验分别位于 `compiled_rfuzz_transport.py`、`compiled_f2_feedback.py`、`compiled_f2_receipts.py`、`compiled_f2_rfuzz_session.py`、`compiled_f2_saved_outputs.py`、`compiled_f2_online_material.py`；执行异常身份和次级notes由executor及shared finalizer共同保留。第三冻结十门独立接受，统一入口限定验收完成，详见[实施报告](reports/compiled-f2-rfuzz-entry-20261023.md)。此前文件入口的限定验收见[报告](reports/f2-f4-current-acceptance-20261023.md)。

## 2026-10-22 Selected F4 runtime-path 执行链

同次 typed request/D3 → `compiled_f4_runtime_path.py` 严格恢复图、合同和路径/来源映射 → `instruction_image_binding.py` 对实际 RAM region 的精确绑定 → `ScenarioSession.configure_runtime_paths` 在 begin 前配置 → bound instruction case 使用 runtime 路径/source ID → decoder/session/plan 保存交叉关联与 fresh constructor 重新绑定。逻辑 D3 路径 ID 保留给 compiled receipt join。最终门状态见[报告](reports/compiled-f4-runtime-path-admission-20261022.md)。

## 2026-10-22 Reduced AXI 来源导出执行链

显式 `admit_observation_stream` → `reduced_axi_stream_source.py` 稳定 owner/observer/listener 注册 → 真实解析 receipt 与 begin/end 生命周期操作 → `observation_stream.py` 有界不可变发行队列 → Runner 导入及 journal 消费者。消费者、完整全局 journal、持久重载及限定 native first/fresh 已通过；终态保留 instruction-read pending，能力仅为 observation_only。source 封存保留原始 scope/refs，协议违例与捕获完整性错误分别处理。见[报告](reports/reduced-axi-journal-crosswalk-20261022.md)。

## 2026-10-22 CVA6 四字 DMA RAM 执行链

`scenario/dma_ram_firmware.py` 显式逐 SW FENCE → `cva6_dma_example.py`
固定非缓存地址 → `cva6_dma_runner.py` 构造未启动 CPU/DMA、共享内存和
queued Router → 标准 Runner 的 DMA/CPU 调度。`scripts/verify_cva6_dma_ram.py`
从完整原始 64 位 AXI 与 Wishbone 样本独立关联真实响应、lane、
writer/version、结果 stores，并重放两分支的完整动作。
[运行状态与边界](reports/cva6-dma-ram-20261022.md)。

## 2026-10-18 native 显式观测执行链

`verify_picorv32_native_online.py --native-completion-observation` 显式选择V2 raw请求，经 `local_harness/plan.py` 的typed native准入和 `native_contract.py` 的实际ABI绑定，生成被动抽头。实际CPU session每个verified receipt交给 `scenario/native_cpu_events.py`，真实RAM读后绑定不可变快照；Runner保留全部PRE/POST及对应传输事件。

`NativePacketSession`保护原始及fresh提交的物理packet边界。`session_runtime.replay_online_session(native_max_cases=...)`重建该会话，`native_replay_identity.py`只在比较副本中改写已验证的真实process身份；raw事件和原始hash均保留。独立gate reducer与离线审计分别从保存raw重建全部事务。完整证据见[真实门报告](reports/native-completion-directed-independent-20261018.md)；这条路径尚无精确source authority、四反馈或持续RFuzz授予。

## 一次 testcase 的执行链

```text
configs/cpus + configs/peripherals + configs/scenario
  → scripts/generate_local_harness.py / record_scenario.py / run_scenario_campaign.py
  → local_harness：源码事实、协议模板、独立 RTL session
  → scenario：Genome、Runner、持久内存、Router、Scheduler、checker、反馈
  → integration/scenario_*：campaign、RFuzz 运输与回放接入
  → scripts/replay_scenario.py：从初态重建与对照证据
```

| 代码位置 | 当前职责 | 主要输入或输出 |
|---|---|---|
| `src/myfuzz/__main__.py`、`src/myfuzz/capabilities.py` | 当前 CLI 路由、显式历史兼容和文档证据能力查询 | 与脚本共用 parser/handler；等级、限制和证据链接 |
| `src/myfuzz/local_harness/` | 生成并运行单个真实 CPU/IP 的 harness；维护局部协议、时钟和 session | 组件 profile、源码锁、生成 artifact、真实端口观察 |
| `src/myfuzz/scenario/` | 连续 testcase、输入所有权、依赖路径、数据交付、持久 RAM/事务、检查与 replay | Genome、真实观察、证据包 |
| `src/myfuzz/scenario/dma_ram_firmware.py`、`cvw_dma_runner.py`、`vexii_dma_runner.py` | 共享有界四字 RV32I DMA 固件、CPU 配置与标准 Runner 调度的 RAM 数据流组合 | 固定 CPU profile、真实源／控制请求与 master response、按字节 writer/version 和完整 fresh；实际证据分别见 CVW/Vexii DMA 报告，未覆盖 IRQ/ISR／通用 F6 |
| `src/myfuzz/scenario/memory_service.py`、`memory.py`、`ledger.py` | host 模拟 RAM 的交易提交；成功写回调冻结完整交易键、实际窗口位置和启用字节版本，重复交易重用原凭据，失败保持 uncertain | `commit_document()` 是提交事实而非来源授权；受限 UART `sw`→host RAM 低字节与后续退休读回已有冻结源码门禁，仍不代表通用 RTL RAM 来源 |
| `src/myfuzz/scenario/dependency.py`、`runtime_path_contract.py`、`replay.py`、`p2_acceptance.py` | P2 有边身份的 proof-DAG、显式静态拓扑契约、预编译路径及启动前 hook；声明范围的逐边来源和阶段门禁已验收 | 受信 node/edge 声明、所选路径、实际 Binding/MMIO/资源拓扑；超出声明的逐边来源仍需另证 |
| `src/myfuzz/scenario/source_provenance.py`、`event_provenance.py`、`runtime_edge_index.py` | immutable源登记、追加前观察/来源元数据、typed RAM writer与物理边候选；不推断RTL因果 | 原始case/action、资源快照、graph/path/edge候选 |
| `configs/cpus/ibex_rvfi_local/`、`src/myfuzz/local_harness/cpu_session.py`、`src/myfuzz/scenario/cpu_retirement.py` | 认证44字段RVFI、实际响应/退休、受限有界交易匹配；新 v2 POST 凭据门禁见当前进度 | 固定profile、冻结writer/version、完整TransactionKey与退休order |
| `src/myfuzz/local_harness/opentitan_uart_session.py`、`src/myfuzz/scenario/runner.py` | action/frame真实RX采样，追加日志中区分raw transport nonce与稳定逻辑driver scope | 原始 admission、逐 tick 冻结 8N1 波形、实际 receipt sequence；FIFO 来源由显式变体追踪 |
| `src/myfuzz/scenario/retirement_delivery.py`、`gpio_consumption.py` | 精确实际 APB 交付与退休交易关联、有界 GPIO 资源版本及逐 bit 同步来源；已有独立 GPIO RTL 门禁 | 实际请求/响应凭据、认证探针、原始来源与资源版本 |
| `src/myfuzz/local_harness/opentitan_uart_fifo_contract.py`、`src/myfuzz/scenario/uart_consumption.py` | 独立 UART FIFO 变体的 154 个认证被动探针、有界接收/入队/读出追踪与终结资源回收；历史冻结源真实 RTL、在线与完整 replay 已通过 | 实际逐 tick 帧凭据、原生 FIFO 身份、完整路由交易与追加证明 |
| `src/myfuzz/local_harness/ibex_irq_receipt_contract.py`、`cpu_session.py`、`src/myfuzz/scenario/uart_irq_consumption.py` | 显式 Ibex RVFI＋UART FIFO 模式的认证实际外部输入、PRE taken 与 POST 通知；有界原生 cause/version/binding/sample/taken join | 真正编译 index 将逻辑 source 解析为 owner；原 case/role、精确 context/parsed receipt，generic ISR/operand unknown |
| `src/myfuzz/scenario/uart_retired_read.py` | 完整 TransactionKey 的 raw UART/CPU 重构与证书核对；只接受对齐 RV32 LW 的实际 RDATA 消费 | v2 POST/44 RVFI、实际路由窗口与 source owner；指令来源可 unknown，后续 operand/store/ISR unknown |
| `src/myfuzz/scenario/uart_operand_seed.py` | 从原始证据独立重建 UART 退休 `lw`，记录该次目标寄存器的精确版本与低8位来源 | 迟到证明只授予对应历史版本；当前查询遇到覆盖、flush 或 certainty barrier 必须保持保守，后续 copy/store/ISR 尚未证明 |
| `src/myfuzz/scenario/uart_operand_use.py` | 独立重建精确旧寄存器版本被实际退休 `sw` 的 rs2 读取；绑定原生 POST 和受限低8位来源 | 不授予整字 Store 来源、持久 RAM commit、后续读取或通用 ISR 来源 |
| `src/myfuzz/scenario/uart_irq_entry.py`、`src/myfuzz/local_harness/uart_controlled_irq_contract.py` | 受信 bootstrap 安装、固定源码/CSR setup、实际 native take 到首次 handler 退休的有界关联 | 固定 image/version、完整 instruction 流与 POST 凭据；仅受控 bootstrap entry；2048冻结源门禁通过，当前源状态见进度页 |
| `schemas/scenario_runtime_manifest.v1.json`、`src/myfuzz/scenario/contracts.py` | UART v2/v3/v4、FIFO/provenance、GPIO causal、CPU RVFI/native additive 结构分支与严格 Python 身份认证 | Schema 仅结构；canonical 类型、source/build 闭包由 Python 校验，legacy 身份保持原 scope |
| `src/myfuzz/scenario/chain_certificates.py`、`acceptance_metrics.py`、`scripts/run_first_step_acceptance.py` | 有界增量的逐 admission 完整链证书（`runtime_chain_certificate.v1`）与单次流式"首步验收"分析（`first_step_acceptance_report.v1`：严格链/s、覆盖/边/链签名新颖率、逐例 p50/p95、终结成本、replay 核对） | 每条 fuzz_source admission 至多一张 `certified`/`incomplete` 证书；未见证跳只能记 incomplete，无法确定的量写 null 并给原因 |
| `src/myfuzz/scenario/rejection_codes.py`、`rv32i_sources.py`、`online_case_decoder.py` | `candidate_rejection.v1` 的 37 个版本化拒绝码与 `decode_candidate()`/`commit_candidate()` 结构化候选处置 | 声明期配置校验仍可为 `ValueError`；在线拒绝校准的 7 类真实拒绝与 1 类不确定回执见 P4 报告，其他码不视为已在 live 路径实测 |
| `src/myfuzz/composition/rtl/ibex_irq_serial_sideband.sv`、`configs/soc/closures/ibex_rvfi_local.json`、`src/myfuzz/local_harness/ibex_rvfi_contract.py` | 固定 RVFI wrapper 的被动 IRQ serial sideband、其 closure/lint 记录与 profile/contract 身份钉 | host 已采集 `irq_decision_serial`/`irq_retirement_serial` 并由下一行消费者关联；该 token 只证明声明的 IRQ 决策到退休一跳 |
| `scripts/check_doc_links.py`、`tests/test_doc_link_check.py` | 文档本地相对链接与标题锚点校验（`doc_link_check.v1`，零第三方依赖，数秒完成全仓扫描） | 只读；不修改任何文档；纯页内 `#anchor` 默认跳过 |
| `src/myfuzz/scenario/irq_serial_certificates.py`、`local_harness/ibex_irq_receipt_contract.py`、`local_harness/cpu_session.py` | `irq_serial_observation`（`ibex_irq_serial_observation.v1`）把 `irq_decision_serial`/`irq_retirement_serial` 写入退休/中断事件；`IrqSerialCertificates` 做精确 token join | 只证明"IRQ 决策→RVFI 退休"一跳；是否并入完整链以对应运行的链生产者与报告为准，不从 serial 数量直接外推 |
| `src/myfuzz/scenario/source_actions.py`、`session_runtime.py`、`integration/scenario_rfuzz.py` | `source_action.v1` 动作契约、先决条件和跨例 witness tracker；`ScenarioSession` 与在线 executor 均在 RTL 命令前调用 gate | Ibex 在线工厂创建取指槽策略；其他组件／动作的支持边界仍按 P3 报告判断 |
| `src/myfuzz/scenario/p5_fault_family.py`、`tests/scenario/fixtures/p5_fault_family_real_window.json` | `p5_controlled_fault.v1` 受控故障族（4 类 9 变体），只扰动 checker 观测副本，产出 finding ID、来源链与最小重放配置 | 已有真实 RTL 受控校准与新进程复现；全部标注 `calibration_only=true`，不计自然 RTL 缺陷 |
| `src/myfuzz/scenario/uart_chain_certificates.py`、`uart_routing_witness.py` | 后续 UART 16 跳链证书及运行自身 `source_target_transactions` 记录器 | UART 证书与旧 P5 联合验收的 GPIO 链计数不同口径；新运行与历史冻结产物分别解释 |
| `src/myfuzz/scenario/paired_efficiency.py`、`scripts/bench_first_step_paired.py`、`scripts/run_first_step_cold_start_run.py` | 连续会话 vs 逐例冷启动的可比性判定与配对效率报告（`paired_efficiency_report.v1`），以及产出可配对冷启动 run 目录的逐例重启执行器 | 逐例 align + 逐字段一致性；无可流式 trace 的组链/s 记 null；不证明 DUT 等价或加速倍数 |
| `src/myfuzz/scenario/closed_loop_feedback.py`、`src/myfuzz/integration/scenario_rfuzz.py`（闭环段） | certified 链 → `closed_loop` 命中（按 `certificate_id` 去重），`energy_weights` 换算后续选源能量；live 由 `closed_loop_energy`／`MYFUZZ_CLOSED_LOOP_ENERGY` 开关控制，默认关闭时权重与改动前逐值一致 | 命中必须带真实证书身份；未知归因键/伪造证书/非连续 journal 一律 fail-closed；开关不进入 manifest 身份 |
| `src/myfuzz/integration/ibex_pulp_rejection_calibration.py`、`scripts/run_ibex_pulp_rejection_calibration.py` | 受信声明驱动的定向拒绝/不确定校准运行时（7 类拒绝 + 1 类 uncertain），真实回执带精确 `code`/`pointer`，`verify` 可复算 | 只覆盖在线路径可达的码；`decode.unbounded_input` 依赖校准实例收紧的输入上界，属校准声明 |
| `src/myfuzz/scenario/rv32i_sources.py`、`rejection_codes.py` | 合法 RV32I 操作子集合（含本轮新增 `SLLI`/`SRLI`/`SRAI`）与 37 个分层拒绝码 | 编码逐位验证；`cpu_retirement.py` 的移位退休接受能力见对应报告 |
| `src/myfuzz/integration/scenario_campaign.py`、`scenario_rfuzz*.py` | 把场景运行接入 campaign、RFuzz 候选和反馈传输 | 候选输入、结果与语料 |
| `src/myfuzz/protocols/` | 协议描述和当前 harness 可复用的局部协议代码 | OBI、AXI、Wishbone、TL-UL、APB 等受限契约 |
| `configs/cpus/`、`configs/peripherals/` | 每个真实 DUT 的接口、参数、源码与声明式微调 | 单组件 harness 生成输入 |
| `configs/scenario/` | 固定场景、对照输入和可重放种子 | Genome/场景配置 |
| `tests/scenario/`、`tests/local_harness/`、`tests/integration/` | 状态与协议契约、生成器及真实 RTL 传播验收 | 定向检查与证据生成 |

## 共享源码和历史路线

`local_harness` 当前直接导入 `composition/component_profile.py`、`interface_description.py`、`source_crawler.py` 和 `soc_port_dispositions.py`；CVA6 场景还使用 `cva6_source_closure.py`。这些模块提供源码、端口和 profile 事实，属于当前方案的共享依赖。`configs/soc/sources.lock.json` 虽位于旧目录，仍被 harness 构建和 OpenTitan contract 读取。

`integration/soc_*`、`composition/soc_*`、`protocols/rtl/soc_*`、`scripts/generate_soc.py` 和旧 `configs/designs/` 主要属于早期完整 SoC 或方案对照路线。其测试、脚本与报告仍存在引用；逐文件迁移前需更新调用、源码锁和 replay 证据。本轮以索引区分用途，不按目录名删除。

`python -m myfuzz` 提供 `harness generate`、`scenario record|replay|campaign`，与对应独立脚本共用 parser 和 handler。`capabilities` 查询直接读取运行能力表，保留文档的等级、限制、行号与源码摘要；查询不会重新运行 RTL 验收。旧 32 项 SoC 矩阵通过 `compat soc check|preflight|run` 显式访问。

## 整理规则

1. 新的场景逻辑写入 `scenario/`；单 DUT 协议、生成和 session 逻辑写入 `local_harness/`。RFuzz/campaign 运输逻辑写入 `integration/scenario_*`。
2. 同协议新组件首先增加受信 profile 与声明式微调；协议语义确实不同才新增版本化模板。不能把组件名判断散落在 Runner 或 mutator 内。
3. 从 `composition/` 抽离共享 helper 时，先迁移导入者和源码身份，再核对生成产物与 replay；不要把文件改名当作功能验收。
4. 历史代码、配置、报告和证据只有在引用、重放及恢复路径核清后才移出。候选文件无文字引用本身不足以证明可删除。

本轮已移出文件和恢复清单见 [清理审计](reports/current-design-cleanup-source-audit-20261006.md)。

历史 UART 原生外部 taken 的冻结源码门禁、live-resource GC 与完整 saved prefix fresh replay 见 [native IRQ 来源报告](reports/current-dataflow-p2-uart-native-irq-20261006.md)。早期 GPIO/UART/FIFO 门禁按其原 captured source 解释，不自动升级；该冻结源软件总门禁为 166 项／56 子检查通过（150.20 秒），后续源码变更须保留其记录时身份。

当前实施与门禁的持续更新集中在 [当前进度](CURRENT_PROGRESS.md)。本页维护代码入口和职责；运行能力表维护组件能力边界；`reports/` 保留各次通过、失败和重放的源码身份与证据。

## Compiled F4 executable identity chain（2026-10-22）

`local_harness/build.py` validated output receipt → opted `session.py` prepare/live executable/READY → `compiled_f4.py` stable execution binding and original/fresh process audits → `compiled_f4_build_join.py` strict D2/session/prefix/replay association → `compiled_rfuzz.py` saved-output verification → `auto_harness_test.py` checked byte hashes. Build timing/cache-hit diagnostics stay outside stable prefix identity. Status and bounded acceptance: [report](reports/compiled-f4-built-identity-20261022.md).
