# P5 阶段验收（按声明范围）

日期：2026-10-08。本文按[主实施计划](../superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md) P5 的四条清单项与验收口径，逐项列出**已交付的代码与真实门禁证据**，并给出**声明范围与边界**。验收入口是 `scripts/run_p5_acceptance_suite.py`（`p5_acceptance_suite.v1`，只读串起已交付运行与产物，从不渲染 harness、从不启动 RTL）：

```bash
PYTHONPATH=src python3 scripts/run_p5_acceptance_suite.py \
  --run chain_acceptance=runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --run long_search=runs/current-dataflow-p5-chain-600s-20261007-online \
  --run paired_continuous=runs/current-dataflow-p5-paired-20261007-online \
  --run paired_cold_start=runs/current-dataflow-p5-paired-20261007-cold-start \
  --run fault_calibration=runs/current-dataflow-p5-fault-calibration-20261007-online@runs/current-dataflow-p5-fault-calibration-20261007-reproduce \
  --run fault_family=runs/current-dataflow-p5-fault-family-all-20261007-online \
  --run heterogeneous_uart=runs/p5-uart-waveform-gate-20261008-online \
  --artifact long_search=replay=runs/current-dataflow-p5-final-20261007-logs/chain_600s_replay.log \
  --json-out runs/current-dataflow-p5-final-20261007-logs/p5_suite_final.json \
  --reports-dir runs/current-dataflow-p5-final-20261007-logs/p5_suite_final_reports \
  --markdown-out runs/current-dataflow-p5-final-20261007-logs/p5_suite_final.md     # exit 0
# 联合判定：critical 6/6 成立、unmet=[]、no_proving_run=[]
```

联合表（`runs/current-dataflow-p5-final-20261007-logs/p5_suite_final.md`）：

| 关键项 | measured | met | 证明运行 |
|---|---|---|---|
| `assertion_classes_separated` | true | true | chain_acceptance, fault_calibration |
| `controlled_fault_caught_and_reproduced` | true | true | fault_calibration |
| `normal_control_has_no_finding` | true | true | chain_acceptance, fault_family, long_search, paired_continuous |
| `complete_prefix_saved_and_identity_refused_before_start` | true | true | chain_acceptance, long_search |
| `ten_minute_search_reports_chains_and_replay` | true | true | long_search |
| `same_budget_continuous_beats_per_case_restart` | true | true | paired_cold_start |

**这次跑通的是"声明"而不是"新测量"**：套件本身只读已保存产物，本轮相对上一次探测（exit 2、4/6）只补了两处**缺失的声明**——受控故障需要 `compare_run` 复现根、十分钟搜索的 fresh replay 文档不在运行目录内。补声明时仍逐项校验绑定：`--artifact` 声明的产物必须（若有 `run_dir` 字段）自述为被声明运行；`fault_calibration` 的复现根必须携带 `reproduction_summary.json` 且 `fault_document_sha256` 与最小重放逐字节一致。任何一项对不上，套件仍报 `measured=false` 或 `met=false` 并附原因，绝不静默通过。

## 清单逐项

### 1. 三类断言分开报告；生成约束与检查期望分开；异常真实输出不因路径未就绪被过滤

- 交付：[`myfuzz.scenario.assertion_classes`](../../src/myfuzz/scenario/assertion_classes.py)（协议检查器／跨组件来源与顺序／CPU-IP 行为三类各自成节、`finding_count` 或 `null` + `finding_count_reason`）＋只读 CLI [`scripts/report_p5_assertion_classes.py`](../../scripts/report_p5_assertion_classes.py)。
- 真实证据：[断言类报告](current-dataflow-p5-assertion-classes-20261007.md)（60 例 UART 会话与 3 例受控故障会话各一份 `p5_assertion_classes.v1`）。套件对两份文档都判定 **met=true**，并复核四件事：三节各自自述 `assertion_class` 与被存放的键一致；fail-closed 异常普查闸门 `passed=true/exit_code=0`；`abnormal_record_count == represented_record_count` 且 `unrepresented` 为空；报告引擎 sha256 等于**当前** `myfuzz.scenario.assertion_classes` 的 sha256。
- 过滤边界：`input_invalid` 这类**启动前拒绝**在普查里是"已代表"的异常记录（有 `code`/`evidence`），不是被过滤掉的输出。

### 2. 已保存场景的受控故障注入：checker 给出失败、来源链、最小可重放输入，且独立标注

| 证据 | 真实结果 |
|---|---|
| [受控 IRQ 故障真实校准](current-dataflow-p5-controlled-fault-real-20261007.md) | 真实会话第 3 例被 `gpio_b_irq_source_mismatch` 捕获（2 complete ＋ 1 dut_violation），`session_status=finding`；`minimal_replay.json` 记 `calibration_only=true`、`observation_boundary=checker_input_copy`、钉住 `fault_document_sha256=cd753d41…`；控制/故障两 trace 的 event 4609 逐字段相同，证明只改 checker 观测副本 |
| **新进程复现**（本轮纳入验收） | `runs/current-dataflow-p5-fault-calibration-20261007-reproduce` 由 `fault_replay_reproduce.py` 在新进程从最小重放启动真实 RTL：`violations=['gpio_b_irq_source_mismatch']`、`statuses={complete:2, dut_violation:1}`、`tests=3`，与故障根逐字段一致；套件判定 `fault_document_sha256_matches=true`、`met=true` |
| [9 变体真实 RTL 校准](current-dataflow-p5-fault-family-real-9-variants-20261007.md) | 9/9 变体（错 IRQ 2／错 read data 3 含 1 个 UART／重复提交 2／破坏绑定值 2）命中即停并各写最小重放配置；只读复核器 `ok=true`、0 失败 |
| 独立标注 | `calibration_only=true` ＋ `observation_boundary=checker_input_copy` 进入套件判据；套件边界文字明确"受控故障项里的每个 finding 都是注入校准，不是自然 RTL 缺陷" |

### 3. 失败与新增覆盖候选保存 raw/Genome/源码工具链身份/完整 trace/finding/replay；身份不符在启动前拒绝

- 身份与绑定：`online_run_identity.json`（源文件、decode space、plan、manifest、trace 语义 sha256、host、artifact 摘要）＋ `_verify_online_run_identity` 在**构建 RTL factory 之前**执行。套件对 `chain_acceptance` 判定 raw/plan/trace/manifest 四项身份**全部绑定**且 `report_binding=true`。
- 启动前拒绝的真实证据：[冷组逐例 fresh replay](current-dataflow-p5-cold-group-replay-20261008.md) 里 24 例冷组 replay 因 decode space 源码身份漂移（`src/myfuzz/scenario/ibex_pulp_dual_source.py` 等 4 文件摘要不符）被逐例拒绝，拒绝发生在任何 RTL 启动之前，日志与两条 replay summary 均按 sha256 保存。
- 完整前缀与 fresh replay：[冷组逐例 fresh replay](current-dataflow-p5-cold-group-replay-20261008.md) 冷组**逐例各起独立 RTL 进程** replay，15/15 `matches=true`；连续枝 24 例 replay 一致。十分钟搜索的 fresh replay 见 §4。
- 覆盖候选：`first_seen` 写侧台账（[P4 first_seen 真实台账](current-dataflow-p4-first-seen-real-20261008.md)）把首次点亮的目标位绑到 `event`（协议请求号）与时间，300 秒／54,157 次 RTL 测试／点亮 30/128，独立交叉复核 exit 0。

### 4. 固定输入/种子、同源码同断言比较连续会话与逐 testcase 启动，并报告全套效率分项

全套分项由 [`scripts/report_p5_arm_metrics.py`](../../scripts/report_p5_arm_metrics.py)（`p5_arm_metrics.v1`）聚合，12 个清单分组一一对应计划要求：

| 清单分组 | 600 秒运行（`current-dataflow-p5-chain-600s-20261007-online`） | UART 异构运行（`p5-uart-waveform-gate-20261008-online`） |
|---|---|---|
| 有效例/s | **0.612963**（368 complete／600.362953 有效秒） | **0.662254**（57 complete／86.069676 有效秒） |
| 完整真实链/s | **0.044973**（27 条，跨例 6；CPU→IP→CPU 20／IP→CPU→IP 7） | 0（见边界） |
| 覆盖增量/s | 目标位 **0.006663 位/s**、见证边 0.014991 条/s | 目标位 **0.046474 位/s** |
| 无效/超时比例 | **0.0**（0 invalid／0 timeout／368 complete，`unclassified_statuses=[]`） | **0.05**（3 `input_invalid`／60；改前该比例因 `input_invalid` 未分类而算不出） |
| 真实 RTL 事务 | 368/368 例有 case commit、runner 计时与 local ticks | 57/60 例 case commit（3 例为预 RTL 拒绝） |
| Router/Scheduler | 逐例嵌套计时入回执 | 同 |
| 增量反馈 | 31 次反馈交换、32 次 mutation hint 更新、1 例新特征、1 例源增益；345/368 例 `interaction_deferred` | 2 次交换、3 次 hint、1 例新特征、0 例源增益；54/60 例 `interaction_deferred` |
| 日志/证据 | `online_events.zlib`（`online_trace_zlib_chunks.v1`）172,324,767 字节／声明 570,196 事件、语义 sha256 复算一致（证据足迹 165,832,324 字节） | 同容器（`p5-uart-waveform-gate-20261008-online/online_events.zlib`）274,782,641 字节／76,332 事件、语义 sha256 复算一致（证据足迹 276,791,217 字节） |
| 一次性编译/初始化 | 压缩终结成本见[十分钟分项门禁](current-dataflow-p5-chain-600s-20261007.md)；配对对照给出逐例 18.737 秒初始化 | 同 |
| 每例 admission | 559 次 admission（fuzz_source 368／fixed_support 191）、0 证书缺 admission id | 94 次（fuzz_source 57／fixed_support 36／bootstrap 1） |
| p50/p95 时延 | 全分项逐例（checker p50 2.2 µs、receipt 18 µs、selection 107 µs、interaction_ingest p50 19.7 ms/p95 114.8 ms、rtl_submit p50 1.561 s/p95 2.284 s） | 全分项逐例（rtl_submit p50 1.444 s/p95 1.878 s、interaction_ingest p50 10.9 ms/p95 14.2 ms） |

- 低吞吐定位与消除：[压缩 trace 写入效率](current-dataflow-p5-trace-write-efficiency-20261007.md)（中位写入 4.038→1.973 秒，字节与语义摘要不变）、[同条件 trace 容器对照](current-dataflow-p5-trace-container-same-condition-20261007.md)（zlib 分块容器逐事件等价 JSONL，体积约 1/13.4、终结写入少 11.14 秒，两容器各自 fresh replay 一致）、[热路径剖析](current-dataflow-p5-efficiency-profile-20261006.md)（去掉反馈事件深拷贝）。
- 同预算对照：[配对对照](current-dataflow-p5-paired-continuous-cold-start-20261007.md) 9 项可比性先决条件全满足，24/24 例逐例 status/raw/genome/path/断言一致，墙钟 **31.905 秒对 512.881 秒 ≈ 16.08×**（含 24×18.736 秒逐例初始化）。套件对该项判定 `met=true`，并**如实报告链/s 等价不可测**（冷枝无 trace，故 `chain_per_second_equivalence.measurable=false` 且给出原因）。

## 验收口径对照

| 验收要求 | 证据 |
|---|---|
| 在 Ibex＋双 PULP GPIO 与至少一种不同协议/行为的真实外设上，CPU 侧与 IP 侧变异、真实路由、逐例反馈、断言、完整前缀保存与 fresh replay 均通过 | 异构解锁见 [UART 波形接纳门禁](current-dataflow-p5-uart-waveform-admission-20261008.md)：同 seed/预算下由 7 例（1 次 `uncertain_effect` 停机）变为 **60 例、57 complete、3 例启动前声明式拒绝、0 停机**；CPU 侧 24 例 + UART RX 36 例同会话真实使用，54/60 例命中目标，fresh replay 一致。UART 侧**真实路由见证与完整链证书仍为 0**（见边界） |
| 至少一项受控错误被独立断言捕获并在新进程复现，正常对照无该 finding | §2 全部证据 + 套件 `controlled_fault_caught_and_reproduced` met=true；正常对照由 `normal_control_has_no_finding` 的 5 个干净对照（chain_acceptance／fault_family／long_search／paired_cold_start／paired_continuous）承担，且套件列出**唯一携带 finding 的对照**是故障运行自身（`fault_calibration: ['gpio_b_irq_source_mismatch']`）——注入即报警、未注入即静默 |
| 10 分钟定向或覆盖搜索报告完整链、有效执行时间、语料 replay 和实际 finding；没有自然 RTL bug 时如实记零 | 600.362953 有效秒、368/368 例、27 条认证链＝0.044973 链/s、570,196 事件、完整 fresh replay `matches=true`、**自然 finding = 0 且写明是运行自身报数**；trace 语义 sha256 复算一致；套件 `report_binding=true` |
| 同预算对照证明长会话的有效例/s 或完整链/s 高于逐例重启，且有效性、checker 与 replay 不退化 | 16.08× 墙钟（同预算、9 项先决条件、逐例一致）；有效性：两组 24/24 complete、0 violation；replay：连续枝一致、冷组 15/15 逐例一致；链/s 等价**明确记为不可测**而不是编造比值 |
| 未覆盖的 ISA 子集、外设模式和路径列为范围限制 | 见下节边界 |

## 声明范围（本文主张什么）

在**当前 Ibex＋双 PULP GPIO 在线 wiring 与 OpenTitan UART 异构会话**、**声明式受信 profile/模板**与**已保存的真实 RTL 产物**范围内，P5 四条清单项与验收口径均有真实证据；整阶段入口 `p5_acceptance_suite.v1` 六项关键项**全部有 measured 且 met 的证明运行**（联合 exit 0）。三类断言分节、受控故障捕获＋新进程复现、正常对照静默、启动前身份拒绝、十分钟搜索报告与同预算对照都在真实 RTL 上成立。

## 边界（本文不主张什么）

- **不是单次运行通过**：联合证明的是"每个关键项至少有一个运行 measured 且 met"。同一份联合表里 `heterogeneous_uart` 单跑 **0/6**（UART 侧缺断言类报告、缺 fresh replay 文档声明、有 3 例 `input_invalid` 故不算"全 complete 对照"），它是被完整报告的，不是被丢弃的。
- **UART 侧仍是浅层**：`certified_chains.total=0`（57/57 fuzz 源接纳无证书，链生产者只在 GPIO 路径上；UART 链生产者正在补）、无跨例持久状态、`interaction_deferred` 54/60、CPU 侧 `cpu_retired_transaction_target_delivery.registered_origins=[]`。即"两侧源都被真实使用"，但"UART 路径的完整闭环链"未证。**本轮补充（见[UART 路由见证](current-dataflow-p5-uart-routing-witness-20261008.md)）：**`source_target_transactions=null` 已不再成立——新 `online_source_target_transactions.v1` 记录器已接线（执行器钩子＋门禁决策日志），并已从**已保存运行**只读推导出真实路由见证表：7 个例产生真实 UART 读链（`uart-access:uart:0:4/7/11/13/15/17/19`，offset `0x18`），每例 3 条已 join 见证（`uart_fifo_pop`＋被 pop 的 `uart_consumption_match`＋被接受的 `uart_retired_read_match`，`matched.complete=true`）并可回溯到注入该帧的 origin case/action（7 例中 3 例为 UART 侧源、4 例为 CPU 侧源）；共 77 条消费见证（21 joined／56 unjoined 的 IRQ-cause+retention）、37 例无见证、3 例拒绝按 `null`+原因；门禁 24 例被判定（21 采纳＋3 拒绝 `uart-waveform-idle:1832/4456/6296`，prerequisite kind `transport_idle`）、36 例 UART 侧 `not_judged`（门禁只绑 `cpu` 组件）。**边界：该表是从已保存 receipts/trace 推导的，不是运行自身写的**——旧运行的 `report.json` 没有该键，实时证明需要一个新 UART 会话（受影响的 decode-space 源文件已漂移，旧 bundle 按设计不再可 replay）。**实时证明已完成**：新运行 `runs/p5-uart-routing-gate-20261008-online`（同 cache／同 seed `20261007`／同预算）`session_status=complete`、60 例（57 complete ＋ 3 `input_invalid`，与旧运行逐状态一致）、fresh replay **`matches=true`**，且 `report.json` **首次自带** `source_target_transactions`（schema `online_source_target_transactions.v1`）：记录器 totals 为 `cases_with_register_access=7`／`register_accesses=7`／`target_consumption_witnesses=73`／`matched_consumption_witnesses=21`／`unmatched=52`／`cases_with_target_consumption_witness=20`／`cases_without_any_witness=37`／`event_slices_unavailable=3`，门禁决策日志为 `{count:24, admitted:21, refused:3, omitted:0}`。只读交叉核对脚本对该运行独立推导出 77／21（运行自身 73／20），差异**已逐 case 定位**为角本扫全 trace 多算了 bootstrap 例 `uart-fixed-warmup` 的 4 条**未 join** 保留类见证（记录器只覆盖已提交搜索例）；两侧的 `matched_consumption_witnesses=21` 与 `register_accesses=7` 完全一致，链证据不受影响。因此"真实路由见证"一项现在既有运行自证的落盘产物，也有独立推导与差异说明。
- **ISR→GPIO A 回流不在链内**：链终点止于 ISR 读 `PADIN` 退休与写 GPIO A 退休交付，不含 A→B 回流；不可精确 join 的身份已点名（[ISR 写回端点](current-dataflow-p5-isr-writeback-endpoint-20261008.md)）。
- **受控故障是校准**：所有 finding 均为注入，`calibration_only=true`；**没有自然 RTL 缺陷**，也不以注入缺陷替代自然缺陷结论。
- **故障质量/灵敏度**未验收：现有对照是"命中/未命中"（192 认证／528 拒绝／0 unknown），没有同条件灵敏度曲线。
- **算子收益与本预算无关**：本预算下没有算子显示覆盖或完整链收益（[同预算对照](current-dataflow-p4-operator-benefit-comparison-20261008.md)），P5 因此不主张搜索质量提升。
- **CPU 侧分支覆盖只是可判定**：profile 路径 `--min-cpu-points 1` 8/8 PASS exit 0，`--min-cpu-points 8` 因点亮 6/64 < 8 而 FAIL——这是**搜索质量**不足，不是映射缺陷（[可判定化](current-dataflow-p4-cpu-side-gate-decidability-20261008.md)）。
- **冷组聚合报告无 `session_status`**：`first_step_cold_start_run_report.v1` 暴露 `execution_status='complete'` 而非 `session_status`。**本轮已修（判据侧，不重写冻结产物）：**`p5_acceptance` 新增 `DECLARED_SESSION_STATUS_FIELDS`，只在该报告没有 `session_status` 键时按 schema 声明的 `execution_status` 取值，且**显式 `null` 仍被拒绝**，声明为 `complete` 还要求判据自己流式读到的逐例回执全为 `complete` 且 `report.json:statuses` 与回执一致；`paired_cold_start` 因此成为第 5 个干净对照（`normal_control_has_no_finding` 的 proving runs 由 4 个变为 5 个，联合仍 6/6、exit 0）。这是报告 schema 的已知差异，不是运行失败。
- **链/s 等价不可测**：冷组无 trace，`chain_per_second_equivalence.measurable=false`，不给出比例。
- **角色是声明不是测量**：套件只校验"声明的角色所需产物是否存在"，不能证明一个运行"是为了什么而跑"；角色不匹配会被报为 `role_evidence.matched=false` 而不是静默接受。

## 与 P4 的关系

P4 阶段验收（[报告](current-dataflow-p4-stage-acceptance-20261008.md)）覆盖合法变异与反馈分配；P5 在其上覆盖断言、故障保存与效率。两者共用同一验收入口风格（`p4_acceptance_suite.v1` / `p5_acceptance_suite.v1`），且都坚持"未测即 null ＋原因，绝不编造 0"。
