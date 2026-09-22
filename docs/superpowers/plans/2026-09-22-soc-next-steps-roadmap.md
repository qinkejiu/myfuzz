# SoC 自动组合后续实施路线图

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each independently approved sub-plan task-by-task. Checkboxes track acceptance, not merely code presence.

**Goal:** 从当前已有的 profile 组合、RFuzz 输入投影、peer、真实中断样例和受控缺陷注入出发，形成可重放、可审计、能力边界明确的 SoC 测试系统。

**Architecture:** 保持现有 `component_profile.v1 → CompositionPlan → 通用互联/适配/中断/peer → RTL 构建 → 输入投影与驱动 → 运行/重放/归因` 主链。后续工作按独立交付物拆开：先关闭离线归因的身份漏洞，再验证 RFuzz 输入两段闭环，随后扩展已准入 peer 与多源中断的行为证据，最后在具备固定依赖的环境中验收官方 campaign。每项只对实际准入的接口和协议子集负责；未支持的行为明确拒绝或记为 `not_assessed`。

**Tech Stack:** Python 3 `unittest`、Verilator、Icarus Verilog、现有 RFuzz raw ABI/持久仿真器、`EvidencePackage`。

## Global Constraints

- 从现有生产代码和回归出发，不重写组合器，不添加按 CPU/外设型号选择接线的分支。
- `component_confirmed` 只用于有独立规范、现场重建和隔离复现的受支持判据；结构或连接故障保持 `composition_defect`，证据不足保持候选/未定位。
- 修复器只能修改尚未提交的环境输入、候选指令/初始镜像及合法事件计划；不得改写 CPU 已发出的请求、DUT 响应或 IRQ 输出。
- 每个输入保留 raw、投影、实际施加值、规则/布局/源码/工具身份和拒绝原因；变异测试与重放使用同一版本的规则。
- peer 的期望不得仅从被测外设或 peer 自己的成功计数推导；未观测性质不得写成通过。
- 中断通知由外设经过控制器进入 CPU；claim、清除和 COMPLETE 必须由 CPU 的实际事务闭环。跨域和非 `machine_external` 入口仍为明确拒绝。
- 官方 RFuzz 客户端和固定 Verilator 版本是 *官方 campaign 验收* 的环境条件，不是开发、测试 RFuzz 输入生成/投影/驱动链的先决条件。
- 保留脏工作树中的既有改动。每个子计划先写失败测试、观察失败、实现、定向真实 RTL 验证、审查，再更新能力矩阵；不以单元测试通过外推所有组件行为。

## 阶段 0：关闭正在进行的离线归因身份缺口

**范围：** `src/myfuzz/composition/soc_offline_defect_confirmation.py`、`soc_failure_evidence.py`、`soc_runtime.py`、`soc_defect_confirmation.py` 与对应的 `tests/integration/test_soc_offline_defect_confirmation.py`、`test_soc_defect_injection_real.py`。此阶段的结论仅适用于已支持的受控 SPI 判据。

**状态（2026-09-22 二次复核）：受控 SPI 归因闭环已通过；通用、不可变的构建输入证明未实现。** 本次独立运行的相关纯测试 47 通过、25 个按真实 RTL 开关跳过，真实 RTL 测试 15 通过、0 跳过。早先“30 个纯测试”是修复前的历史记录，不再作为当前验收数。

- [x] 基线和变异 SoC 从已核验的相同计划、顶层、testbench、boot image、源码闭包，用同一个解析后的 Verilator 工具与选项在新目录重建；差分结论只使用新产物运行。记录工具身份、重建输入与可执行文件哈希，不把原始二进制的自报哈希当作源码证明。→ `_rebuild_pair` 用 `build_profile_runtime` 在两个独立目录重建，记录 `rebuild_tool`（解析路径 + 二进制 sha256）、`rebuilt_*_build_hashes`，并显式把原始可执行文件标为 `unverified-not-used-for-differential`；`_build_metadata_problem` 逐字段比对原始与重建的元数据。
- [x] 将传入的 `plan_hash`、raw layout、两边的 `spi_wire_contracts`、`cpu_data_sources`、peer slots/wires/observations 和普通 observations 绑定到实际重建结果；逐字段篡改均不得确认。→ `_BUILD_METADATA` 比较运行解释元数据；`_derived_plan_problem` 从请求/profile 重新生成并逐字段比较完整 `CompositionPlan`，包括旧 `plan_hash` 未覆盖的审计字段 `target_records`；`_runtime_identity_problem` 比较保存的 `runtime.*`。新建 include 清单在两次编译前后检测声明根目录的内容漂移，但不是不可变快照。
- [x] 只准入已定义的 SPI 单字 MOSI 判据 `spi-mosi-byte`；未知判据、格式错误的 peer oracle、非字符串 source-hash 键等不得抛出未分类异常或确认。→ `criterion_id` 白名单只放行 `spi-mosi-byte`（`unsupported-criterion:<id>`），`spi_wire_verdict` 对缺失/重复/畸形 check 返回 `not_assessed`，`_runtime_identity_problem` 拒绝非字符串 source-hash 键。
- [x] 重跑纯测试，以及 `MYFUZZ_SOC_REAL=1` 的 SPI 注入、多源 latch 故障、SPI 线级判据；独立审查后更新四份状态报告。真实负例应证明连接故障不被误判为组件内部故障。→ 真实负例 `test_latch_fault_replays_and_is_classified_as_composition` 保持 `composition_defect`；现场重建的变异版必须用与 `replay_package` 相同的逐字段比较器与保存证据一致，任一差异均保持 `component_candidate`，不能进入隔离确认。

验证命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_defect_confirmation tests.integration.test_soc_offline_defect_confirmation
MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v tests.integration.test_soc_defect_injection_real tests.integration.test_soc_multi_latch_fault tests.integration.test_soc_spi_wire_oracle
git diff --check
```

**验收：** 新重建产物的基线通过、变异失败、隔离夹具同方向复现；更换计划、解释元数据、工具或非目标源码均不能确认。此结论仍限于受控注入、受信任规范以及声明 include 根目录在检查点可观测稳定的环境；不声称不可变编译快照或自然 bug 自动定位。

## 阶段 1：单独验收 RFuzz 输入的两段闭环（下一项 P0）

现有 `src/myfuzz/integration/soc_builder.py` 的 `ProfileCampaignProjector`/`build_projection_arms`、`src/myfuzz/integration/rfuzz_simulator.py`、`rfuzz_live.py`、`src/myfuzz/composition/soc_image.py` 已实现 raw、约束投影、依赖修复以及持久 testbench 的部分路径。本阶段是端到端核验和补缺，不是重新实现变异器，也不以安装 `kfuzz` 为前提。实施前将本阶段拆成一个独立的细化计划，冻结当前 raw ABI 和需要观察的字段。

**状态（2026-09-22）：已完成。** 细化计划见 [`2026-09-22-soc-rfuzz-input-chain-implementation.md`](2026-09-22-soc-rfuzz-input-chain-implementation.md)（含逐条执行结果与 8 项顺带修复的源码缺陷）。六个新模块共 181 个用例；纯测试 288 通过 / 66 按依赖跳过，`MYFUZZ_SOC_REAL=1` 全量真实套件 0 跳过通过。

- [x] **输入生成/修复段：** 用同一 raw 语料分别走 `direct_input`、`constrained_baseline`、`dependency_repair`。逐类验证 ISA 编码、指令/数据候选、基址加偏移、寄存器定义-使用、分支目标、MMIO 权限、peer pulse 间隔和特殊端口时序；每个修复都记录原始值、修改位、依据、预算及拒绝原因。→ `test_soc_input_arms_projection.py`（39 个）冻结四种真实组合的 ABI 并逐字段 A/B；每个修复都由 `RepairRecord` 记录 before/after/rule，每个拒绝都断言具名 reason。**限制：** 声明式程序通道无法把 `target_policy="strict"` 的跳转拒绝暴露到 arm 级（参考 ISA 层先修正手写 JAL/BRANCH），该层序已被钉住，跳转拒绝仍由 `tests/composition/test_soc_input_repair.py` 覆盖。
- [x] **传输/实际驱动段：** 同一个 raw 记录经投影、序列化、持久仿真器读取、CPU 释放前镜像装载、逐周期顶层/peer 驱动，直到 `RunResult` 与 `EvidencePackage`。→ `test_soc_input_transport_ab.py`（22 个）与 `test_soc_input_real_rtl_gate.py`（28 个）：改一个合法 raw 字段即改变实际镜像、CPU 写入值或外设寄存器读回；被拒字段在驱动前抛出具名错误（`run_sample` 未被调用）。**限制：** `RunResult.requests` 只捕获写事务，读证据走 `responses`。
- [x] **重放与度量：** 保存 raw 与 applied、layout/policy/repair 版本和 build/source identity，重放逐字段比对；报告三臂有效率、修复率、拒绝率、唯一投影输入数、CPU 与外设行为覆盖，且三臂使用同一输入集、同一可执行产物。→ `src/myfuzz/composition/soc_input_chain_report.py` + `test_soc_input_chain_report.py`（39 个）。实测（seed 20260922，6 条 × 400 周期，一个构建）：`shared_corpus_hash` 与 `executable_sha256` 三臂一致；`direct_input` 有效 1.000 / 唯一 6；`constrained_baseline` 有效 0.500，具名拒绝 `profile-dynamic-image-loading-unsupported` ×3；`dependency_repair` 有效 1.000，`address_repair` ×4，唯一 6；重放 5209 个施加字段 0 不匹配。**限制：** seeded 语料每条都是同一个 `addi x0,x0,0`，因此在构造上无法产生三臂不同的 CPU 事务；报告如实记录 `cpu-coverage-gap`，而真实写入 A/B 由上面两个模块用真实候选直接测量。BFM 覆盖只用真实 BFM 计划的布局与投影器在纯夹具上验证，未做真实 BFM 运行。
- [x] **真实 RTL 门槛：** 至少一组 CPU 执行真实 SoC 样本显示不同 instruction/data 候选改变 CPU 实际请求；至少一组 peer raw 事件改变外设真实行为；制造过期 layout/规则、越界地址、pulse 间隔冲突和试图覆盖已提交输入的负例，均稳定拒绝。→ `test_soc_input_real_rtl_gate.py`：指令候选 `0x12300293→0x12C00293` 使 CPU 写入 `0x8000F870` 的数据 `0x123→0x12C`；数据候选使 `0x8000F860` 的写入与 `responses` 中的读回同步改变；`EvidencePackage` + `replay_package` agreement、0 不匹配。peer：raw `uart.tx_byte` 数据/有效位与 `gpio.drive` 值分别改变 RXDATA/STATUS/DATA_IN 寄存器读回，期望来自测试自己写入的 raw 值而非任何计数器（`uart0__tx_sent_count_o` 在两例中同为 1，无法区分）。负例：`test_soc_input_stale_identity_refusals.py`（31 个）与 `test_soc_input_event_refusals.py`（20 个）逐条断言具名 reason，并证明拒绝发生在执行之前、已发出的 `RunResult` 记录逐字节不变。

优先检查和扩展：`tests/integration/test_soc_profile_rfuzz_build.py`、`test_soc_input_repair_runtime.py`、`test_soc_dependency_replay.py`、`test_soc_rfuzz_live.py`、`tests/composition/test_soc_image.py`。先运行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_profile_rfuzz_build tests.integration.test_soc_input_repair_runtime tests.integration.test_soc_dependency_replay tests.integration.test_soc_rfuzz_live
```

**验收：** 有真实 RTL 证据证明“raw → 合法候选 → 真实 CPU/peer 行为 → 可重放记录”，并能证明无效位如何修复或拒绝。通过此阶段不等于完成官方 RFuzz 搜索。**已达成**，但另有两项本轮如实记为未达成（都不属于阶段 1 的通过条件）：seeded 语料无法产生三臂不同的 CPU 事务（已记录为 `cpu-coverage-gap`），`soc_peer_oracle.v1` 的 `uart-tx-sent-count` 期望取自事件计划、对 raw 驱动的帧报 `mismatch`（属阶段 2 独立判据工作）。

## 阶段 2：peer 行为判据与端口边界（P0 的受支持子集）
保持现有 `soc_uart_peer.sv`、`soc_spi_peer.sv`、`soc_gpio_peer.sv`、`soc_peer_oracle.py` 和 `test_soc_peer_models.py`，先冻结首期需要宣称的模式。不要以“连接全面”推导“协议行为全部覆盖”。

**状态（2026-09-22）：已完成。** 细化计划见 [`2026-09-22-soc-peer-criteria-implementation.md`](2026-09-22-soc-peer-criteria-implementation.md)。四个新模块共 131 个用例，全部纯/真实通过。

- [x] UART：为已准入的接收/发送格式增加独立帧、奇偶/停止位及 timeout 或错误处理判据；若 profile 声明了当前 oracle 不支持的模式，标记 `not_assessed` 或在准入阶段拒绝。正例和位翻转/错误波特时序负例均检查线级或总线级证据。→ `test_soc_peer_uart_oracle.py`（25 个）。**并修掉了一个真实判据缺陷**：`audit_peer_run` 的 `uart-tx-sent-count` 期望原先只取自 peer 事件计划，raw 驱动的帧因此被误报 `mismatch`；现在新增 `uart_raw_expectation` 从 raw 记录独立解码（`basis="soc_peer_oracle.v1:raw-decoded"`），plan 为空时用它、两者都为空才 `not_assessed`。新增 `uart-rx-wire`/`uart-framing-wire`/`uart-baud-wire` 帧判据（位翻转、错误停止位、半周期错误波特均 `mismatch`；缺线级轨迹 `not_assessed`；非 8 位/多停止位/奇偶声明按名拒绝）。**限制：** 本运行时**不采样**逐周期 `uart_tx_o`，因此真实运行上帧判据仍为 `not_assessed`（具名环境缺口），正/负帧证据由纯解码器与审计夹具给出。
- [x] SPI：在已覆盖的单字四线判据基础上决定是否准入多字、连续 CS、模式切换；每增加一个模式，提供独立期望、完整轨迹和错误注入。首期不宣称模式外的错误计数有正确性证明。→ `test_soc_peer_spi_modes.py`（51 个，真实部分 4 次真实构建 spi00/01/10/11）。已准入：单字四线、多字连续传输、四种 CPOL/CPHA、两种 CS 极性，各自独立期望（测试自己写入的字面量）+ 完整轨迹 + 错误注入（采样沿位翻转、字序交换、字数错误、字中抬 CS、丢失第二次选择、字间时钟毛刺、未知电平、选择未闭合、模式反相）。**限制：** 连续 CS 多字（一次 CS 内多字）与 CPHA=1 帧被声明为 CPHA=0 两项仍 `not_assessed`/`mismatch` 而非 `pass`——冻结解码器每次选择只解一帧，且 CPHA=1 波形对前沿采样器不可判别；两项都已具名记录，未当作通过。
- [x] GPIO：验证输入、输出、输出使能、默认电平和 contention 两种策略。PULP GPIO 的真实 `inout` 若没有电气解析模型，就在生成阶段明确拒绝，不降级为随机单向线。→ `test_soc_peer_gpio_contract.py`（41 个，真实部分覆盖 4 种 (DEFAULT_INPUT_LEVEL, CONTENTION_IS_ERROR) 组合的真实构建）。**并修掉一个真实参考实现缺陷**：`gpio_resolution` 原先只要有一位 contention 就把整字清零，而 `soc_gpio_peer.sv` 是逐位解析（争用位取声明的 contention 电平 0，其余位保留 agreed 值）；两者在部分争用上不一致。参考实现已按逐位规则修正，并保留正/负判据钉住它。PULP `inout` 边界：生成阶段确有具名拒绝 `inout-port-unsupported:<port>:no-single-unambiguous-direction-is-declared`（在 `build_port_dispositions` 渲染前抛出，已用真实展开绑定断言）；**但**pinned 的 `apb_gpio.sv` 本身不声明 `inout`（pads 已拆成 in/out/dir 等单向角色），所以该拒绝无法从该组件端到端触达——这一点如实记为"边界存在但当前组件不可达"，另有对端附着被具名拒绝（`peer-role-unsupported:...:padcfg:output,in_sync:output`）。
- [x] 对上述已准入性质，把期望依据、peer RTL 内容哈希、实际事件与观测写入 replay；更改 peer 源或删失线级轨迹的负例不得输出 `pass`。→ `test_soc_peer_replay_binding.py`（14 个）：每个 check 带非空 `basis`；每个 model 记 peer RTL 源内容哈希（与真实 `soc_{uart,spi,gpio}_peer.sv` 字节比对）；`replay_package` 比较 `peer_oracle:hash` 与状态；改 peer 源 → `REPLAY_DIVERGENCE` 定位到 `peer_oracle:hash`；删失/截断线级轨迹 → `not_assessed`（并断言 `spi_wire_verdict` 返回 `not_assessed`、离线确认的运行闸门拒绝不完整运行），整包无法 replay 成 agreement。

验证入口：`tests.integration.test_soc_peer_models`、`test_soc_spi_wire_oracle`、`test_soc_boundary_replay` 与含 UART/SPI/GPIO 的 `MYFUZZ_SOC_REAL=1` 样例。**验收：** 至少一个三类 peer 均在场的 SoC 能被 raw 输入改变、运行并重放；每个声称支持的行为都有独立正/负判据，其他行为有明确的 `not_assessed`/拒绝记录。

## 阶段 3：中断多源持续样本与故障注入（P0）
现有真实 Ibex 单源、双 GPIO、UART+GPIO、SPI+GPIO、edge+level latch 注入已是起点。继续复用 `soc_interrupt_plan.py`、`soc_irq_controller.sv`、`soc_irq_edge_detect.sv`、`test_soc_interrupt_lifecycle.py` 与 `test_soc_multi_latch_fault.py`。

**状态（2026-09-22）：已完成。** 细化计划见 [`2026-09-22-soc-interrupt-multisource-implementation.md`](2026-09-22-soc-interrupt-multisource-implementation.md)。三个新模块共 52 个用例，全部纯/真实通过。

- [x] 同一真实 SoC 中以多个不同 raw 样本分别触发同周期、错峰、屏蔽期间、复位边界的多个源；记录每源的外部原因、pending、claim ID、外设清除与 COMPLETE，而非只看 `all_sources_closed` 计数。→ `test_soc_irq_sample_matrix.py`（13 个，一个 Ibex+双 novagpio 构建服务四类样本）。实测逐源记录（entry | 起始周期 | CLAIM id | COMPLETE id | claim 前 pending | 清除前状态→后 | COMPLETE 后 pending）：同周期 `1|3296|1|1|0x6|1→0|0x4`、`2|4390|guard|2|0x4|after=0|0x0`；错峰 `1|2256|2|2|0x4|1→0|0x0`、`2|3366|–|1|0x2|–|0x0`；屏蔽 `1|3296|1|1|0x6|1→0|0x4`（被屏蔽源始终未被 claim，无 COMPLETE=2）；复位边界 `1|478|1|1|0x6|1→0|0x4`、`2|1572|–|2|0x4|–|0x0`。**判别力验证：** 把控制器 `source_i` 向量对调的孪生构建在四类样本上 `all_sources_closed` 全为 1，而逐源断言 4/4 全部识破。
- [x] 对 `pulse`、`rising_edge`、`falling_edge`、`both_edges` 与 level 的已准入组合，逐项做 source-specific latch、掩码和 ID 映射负例；结构故障必须稳定归类为组合缺陷，缺少可观测轨迹时不推断闭环。→ `test_soc_irq_trigger_negatives.py`（44 个 = 8 纯 + 36 真实，5 个触发器 × 7 类负例 + pulse 专属）。每项断言 `composition_defect`（`!= component_candidate`）、`replay_package.status == "agreement"`，ID 置换时结构审计 `interrupt_paths == "fail"` 且 `actual.bits_msb_first == reversed(rendered)`。**并把 `all_sources_closed` 会撒谎这件事测出来**：屏蔽运行读 1（被屏蔽源仍 pending）、置换运行读 1（同一个 id 被重复完成 15 次）。缺轨迹时 `not_assessed`（`REPLAY_NOT_ASSESSED`，明确排除 `"agreement"`/`"pass"`），同一构建的基线仍返回 `pass` 以证明非空断言。**未达成（如实记录）：** pulse 通道上 novagpio 持续保持 `irq_o`，其 latch 位不承载语义（清掉仍闭环，已显式断言）；`falling_edge` 的首个下降沿无法由引脚产生，只能来自程序自身的声明寄存器阶段（机制由 RTL+证据推断，未用波形证明）。
- [x] 将多样本 IRQ 记录放进与 RFuzz 输入同一 `EvidencePackage`/replay 入口；缩减反例时保持导致失败的 source ID、事件先后和已接受事务。→ `test_soc_irq_evidence_package.py`（23 个 = 12 纯 + 11 真实）。三个 IRQ 样本进**一个**包，ledger 分别为 `[1,2]`、`[2,1]`（证明记录跟随运行而非计划顺序）、`[2]`（未服务源为显式记录）。篡改定位到具体字段名：claim ID 伪造 → `sample0:fabric_request[38].0x40002004.wdata`（真实）/`[2]`（纯），`mismatching_fields` 仅该一项；只改文档 → `raw-input-document-mismatch:<path>`；只删某源记录 → `sample0:source1:record-missing`。缩减（6000→3843 词）保持 `claimed_source_ids`、`unserved_source_ids`、`service_transactions`、`event_ordering` 不变，并在独立重跑上复核；缩减后的反例仍可打包并 replay 为 `composition_defect`。**限制：** 缩减在服务边界停止，程序尾部记账被截断，因此失败性质读自 `fabric_requests` 而非 `all_sources_closed`。

**验收：** CPU 真实执行的多样本证据能逐源证明通知→claim→清除→COMPLETE；混合触发负例能定位连接/控制器问题而不误报外设内部 bug。跨域 CDC 和非 `machine_external` CPU 入口继续拒绝，不纳入此阶段。

## 阶段 4：固定依赖环境中的官方 campaign 验收（与阶段 1 分离）
**状态（2026-09-22）：已完成。** 依赖已在本机取得并固定：官方 RFuzz 客户端 `kfuzz 0.1.0`（`runs/rfuzz_client_native_build/target/debug/kfuzz`，由 `third_party/rfuzz/upstream/rfuzz_reference/fuzzer` 构建，来源 <https://github.com/timothytrippel/rfuzz>），bundled Verilator 5.020（从 <https://github.com/verilator/verilator> v5.020 源码构建安装到 `third_party/rfuzz/upstream/.tools/apt-root/usr`，`--version` 报 `Verilator 5.020 2024-01-01 rev UNKNOWN.REV (mod)`），两者均通过 `validate_rfuzz_verilator_version` 与 `resolve_rfuzz_toolchain` 校验。

- [x] 在可获得官方 RFuzz 客户端和项目指定 Verilator 版本的环境里，完成 `soc_campaign.py`/`rfuzz_live.py` 的单臂真实搜索、非空 corpus、receipt、覆盖、清理和 rebuild replay；记录实际工具路径、版本、二进制与构建身份。→ `MYFUZZ_SOC_REAL=1 tests.integration.test_soc_profile_rfuzz_campaign` 通过（197 秒）。实测：`status=completed_with_client_termination`、`final_status=passed_with_client_termination`、`evidence_missing=[]`、`execution_kind=official_rfuzz_source_backed_soc`、`corpus.status=verified`（3 条，manifest 带 sha256）、`replay.status=passed`、`cleanup.status=clean`（`remaining_segments=[]`）、`fifo_reply_receipts` 4096 条、`rtl_execution.tests=26422`、`coverage_records=13153`、`execution_totals={cycles:79266, source_transactions:26422, target_transactions>0}`、`artifact.tool_identity` 非空。**为达成它修了三个真实缺陷**（都是首次真实运暴露的）：镜像投影在 byte-enable 不是整字时直接拒绝而非修复（第一个语料条目就失败）；`execution_monitor` 从未在 profile 路径设置，导致 source/target 事务证据永远缺失；生成的 live testbench 用 `forever` + `$finish` 在 EOF 时不会退出，导致发布探测超时（改为 `while (scan > 0)`）。同一轮还发现 `riscv_boot_memory.sv` 的延迟数组赋值在 for 循环里被 Verilator 5.020 以 `BLKLOOPINIT` 拒绝——即此前的 bundling 从未真正编译过——改为非延迟赋值（`memory` 仍是唯一写入者）。
- [x] 将同一官方 raw corpus 交给三臂投影做严格重放，比较有效率、唯一输入、CPU/IP 覆盖、异常类别和运行成本；不把三臂重放说成三次独立搜索。→ `test_soc_official_corpus_replay`、`test_soc_campaign_arms`、`test_soc_campaign_comparison` 在 `MYFUZZ_SOC_REAL=1` 下 28 个用例通过；`test_soc_campaign_arms`/`test_soc_campaign_comparison` 的 profile-build 用例不再 skip。同时官方运行内建的三臂同语料度量已产出：`input_projection.projected_samples=71163`、`projected_unique=3452`、`projection_rejections=0`、`repair_counts={address_repair:2192, byte_enable_repair:1096}`。
- [x] 核对构建缓存：只改输入时命中，改 profile、布局、规则、源码或工具身份时失效。官方依赖缺失时保留 seeded-corpus-rtl 的真实测试结论，并在报告中标明尚无官方搜索证据。→ `test_soc_profile_rfuzz_build` 的缓存用例（`test_profile_build_cache_reuses_the_compiled_rtl_artifact`）不再 skip 并通过；seeded-corpus-rtl 的三臂结论仍保留在 [`2026-09-22-soc-rfuzz-input-chain-implementation.md`](2026-09-22-soc-rfuzz-input-chain-implementation.md)，两者不再混用。

验证入口：`tests.integration.test_soc_campaign_arms`、`test_soc_campaign_comparison`、`test_soc_rfuzz_live`、`test_soc_official_corpus_replay`，以及项目实际 campaign 命令与生成的 receipt/corpus。**验收：** 可核验的官方运行证据和三臂同语料报告；“RFuzz 输入链可用”不再与“官方 campaign 已验收”混用。

## 阶段 5：留出组件、全量回归与论文结论边界

- [ ] 用未参与前述正例开发的 CPU/外设 profile 做留出组合。首先使用已有 Ibex + 首次输入外设、已有 CPU + OpenTitan TL-UL 外设路径；新增组件必须只补 profile 和语义事实，不改生成器型号分支。CVA6 64-bit AXI4 master 在通用宽度/协议适配前继续稳定拒绝。
- [ ] 运行全量 `unittest discover` 和所有 `MYFUZZ_SOC_REAL=1` 套件；逐项区分通过、失败、跳过、固定依赖缺失，不把历史环境失败计作新实现成功或失败。
- [ ] 同步 `docs/reports/soc-remaining-implementation-20260921.md`、`soc-capability-matrix-20260921.md`、`soc-design-acceptance-20260921.md`、`soc-research-scope-20260921.md`，附命令、工具身份、生成物和可重放证据路径。论文仅对已准入协议/模式、留出组件和已验证样本作结论。

**最终验收：** 对受支持的首次输入组件，生成器无需组件型号专用接线代码便可生成结构审计通过、CPU 经真实总线访问外设、外部 peer 与多源中断实际闭环的 SoC；RFuzz 输入能改变合法行为并精确重放；报告能明确区分输入/连接/环境/软件问题与具有独立依据的组件内部缺陷。未支持模式有稳定、具体的拒绝原因，而非“尽可能连接”造成错误归因。

## 执行顺序与计划拆分

阶段 0 的受控 SPI 路径已完成二次复核，阶段 1–4 的各自记录见对应细化计划；当前剩余路线图待办是阶段 5 的留出组件、全量回归与统一报告。阶段 0 的结论不得外推为任意组件、任意判据或不可变编译环境的证明。每阶段的细化实施计划须列出精确字段、失败测试、源码改动和检查命令；本文是跨子系统路线图，不授权把范围外能力默认为已支持。
