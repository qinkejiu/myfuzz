# P4 合法算子同预算收益对照：覆盖与完整链结果是否改变（只读）

日期：2026-10-08。P4 清单要求实现合法变异算子（合法指令/操作数、**初始 RAM 数据**、外设环境源、因果序列、**合法路径切换**、按新目标/新传播边/失败证据分配 mutation energy）。这些算子此前都已单独证明**逐例生效**：

- 路径切换：[`current-dataflow-p4-path-switch-live-20261007.md`](current-dataflow-p4-path-switch-live-20261007.md)：ON 对照枝 46/96 例候选身份被重定向，逐例可从该例自己的 raw/权重/声明池复算；
- 初始 RAM 数据：[`current-dataflow-p4-initial-ram-data-operator-20261007.md`](current-dataflow-p4-initial-ram-data-operator-20261007.md)：ON 枝在任何读取之前写入初始镜像 `initial-ram-data.ram.6`（地址 `0x100E6`、值 `0x94`），真实 Ibex 首次读该字节返回变异值，`slot_immutability` 判 `immutable`；该报告明确写下"**不会证明**……算子的搜索收益（本门禁不做同预算覆盖/性能对照）"；
- 闭环能量：[`current-dataflow-p4-closed-loop-live-ab-20261007.md`](current-dataflow-p4-closed-loop-live-ab-20261007.md)：ON 枝报告 `closed_loop_count=7`（由 33 张证书结算），选源分布相对 OFF 向 CPU 指令源偏移。

**缺的正是另一半**：同预算下开启算子是否改变**覆盖/完整链结果**。本报告只读已存在的运行目录，交付该对照。三个算子的结论都是"**本预算、本 seed、本负载下没有可测的收益**"，其中只有闭环能量显示出可测的逐例差异（差异方向也不是收益）。本报告不重跑任何 RTL、不启动 Verilator/RFuzz、不修改任何现有产物。

## 方法

新增只读分析与 CLI（版本化 schema `p4_operator_benefit.v1`）：

- 模块：`src/myfuzz/scenario/p4_operator_benefit.py`（不在在线运行路径上，不被任何 online 代码导入）；
- 脚本：`scripts/compare_p4_operator_benefit.py`。

复用的 shipped 只读分析（不复制其逻辑）：

| 指标 | 来源 | 定义 |
|---|---|---|
| 例数/状态/有效搜索窗 | `acceptance_metrics.analyze_run` + `receipts.jsonl`/`report.json` | 每个臂自己的窗口；`report.json` 的 `tests/statuses` 与 receipt 流不一致时两者都报告 |
| 共享 raw 输入前缀 | 本模块流式对齐 `receipts.jsonl` 的 `raw_sha256`（并用 `online_raw_records_hex` 交叉校验） | 两臂按 receipt 序首个不同的例号之前完全相同的例数；**前缀之外不做逐例配对** |
| 覆盖（每目标命中例数） | 本模块从 `coverage_hex` 推导 + `targets.json` | 见下方"计数器布局（实测，不是假设）" |
| `new_target_bits_per_second` | `acceptance_metrics.analyze_run:local_target_novelty` | `first_seen_target_bits / effective_search_seconds`，与 shipped `paired_efficiency` 的 `coverage_novelty.new_target_bits_per_second` **同一规则** |
| 完整链证书 | `chain_certificates` 生产者（经 `analyze_run` 注入）| certified / incomplete 计数、按方向、same/cross case、链/秒、按 admission 完成率、首个缺失 hop |
| 见证边（每方向） | `edge_provenance.edge_provenance_session` + `edge_provenance_report`（`runtime_edge_provenance_report.v1`）| 每条**声明的运行边**一行，再按该运行自己的 `online_session_manifest.json:runtime_paths.declaration.selections` 方向标签汇总 |

诚实规则（由代码强制，不靠约定）：

- **绝不编造 0**：产物不支持的量一律 `null` + 精确 `reason`；
- **fail-closed**：必需指标族不可测时脚本写文档后以退出码 `2` 拒绝；核心产物（`receipts.jsonl`、`report.json`）缺失时以退出码 `1` 拒绝，理由精确到缺失文件名；
- **不暗示逐例配对**：文档显式给出共享 raw 前缀，前缀之外只做整臂聚合并写明"不构成逐例因果"。

复现命令（只读，未跑任何 RTL）：

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 scripts/compare_p4_operator_benefit.py \
  --pair runs/current-dataflow-p4-path-switch-off-20261007-online runs/current-dataflow-p4-path-switch-on-20261007-online path_switch \
  --pair runs/current-dataflow-p4-initial-ram-off-20261007-online runs/current-dataflow-p4-initial-ram-on-20261007-online initial_ram_data \
  --pair runs/current-dataflow-p4-closed-loop-off-20261007-online runs/current-dataflow-p4-closed-loop-on-20261007-online closed_loop_energy \
  --require all \
  --json-out runs/current-dataflow-p4-operator-benefit-20261008/p4_operator_benefit.json \
  --markdown-out runs/current-dataflow-p4-operator-benefit-20261008/p4_operator_benefit.md
# 退出码 0；evidence_status=measurable；refusals=0；limits=0
```

机器文档：`runs/current-dataflow-p4-operator-benefit-20261008/p4_operator_benefit.json` / `.md`（本次三对全部 4 个指标族可测，无 `null`）。

### 交叉校验（不是自证）

1. `new_target_bits_per_second`：对 path-switch 与 initial-ram 两对分别调用 shipped `paired_efficiency.compare_runs`，其 `groups.*.coverage_novelty.new_target_bits_per_second` 与本模块的值**逐位相同**（0.45542815198579506 / 0.47468264073549565 / 0.4379284899950734 / 0.42082815811833596）。
2. 每方向见证边：对 path-switch-OFF 与 closed-loop-ON 两臂调用 shipped `p2_acceptance_report`，其 `direction_paths.directions[*].counts/runtime_edge_count/declared_edge_count` 与本模块的汇总**完全一致**（4/5/1、4/4/0、5/5/0 等）。
3. 计数器布局：三对 6 臂全部实测为 8 个十六进制字符 = 4 字节 = `targets.json` 的 4 个目标，观测计数值只取 `{0,1}`（见下）。

### 测试（TDD，先写测试）

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_p4_operator_benefit.py -q -p no:randomly
```

- **RED（实现前）**：`ModuleNotFoundError: No module named 'myfuzz.scenario.p4_operator_benefit'`（收集即失败）；
- **RED（首版实现后，真实断言失败）**：`11 failed, 2 passed`（前缀字段名、跨臂宽度不一致时的 null 语义、缺 trace 时的 refusal 列表等）；
- **GREEN（最终）**：`13 passed`（合成但真实形状的成对运行夹具、缺 trace 的 `null`+reason、缺 `receipts.jsonl` 的 fail-closed、共享前缀计算、两次运行 JSON 逐字节相同）。

## 计数器布局（实测，不是假设）

三对运行的 `coverage_hex` 全部是 **8 个十六进制字符 = 4 字节**，而各运行自己的 `targets.json` 恰好声明 **4 个目标**；观测到的计数值只有 `0x00/0x01`。因此布局是：**每个声明目标 1 个计数字节，按 `targets.json` 的声明序**，目标 `i` 占 `coverage_hex[2i:2i+2]`，非零即该例观察到该目标。shipped 生产端（`scenario_rfuzz.py`：`bytes(int(target.target_id in hits) for target in self.targets)`）与消费端（`scenario_campaign.py`：按 `range(len(targets))` 取字节）与实测一致。`analyze_run` 的 `first_seen_target_bits` 按 bit 计数，在本布局下与"被命中的计数器槽数"相等（都是 4）。文档在 `coverage.layout` 中同时给出 `counter_order_rule`、`counter_bytes_per_case`、`declared_target_ids`、`observed_counter_values` 与 `counter_order_confirmed`；无法确认时计数为 `null` + 原因。

## 结果

三对运行的声明预算相同（同 seed `20261007`、同组件身份、同 decoder manifest、同 `targets.json`），冻结源身份三对全部相等（`source_identity_equal=true`）。`genome.plan_sha256` 三对都不同（该摘要覆盖整份 plan，逐运行不同；初始 RAM 算子还会**故意**改 plan 的初始镜像），因此只作报告、不作可比性前提。

| 算子（OFF → ON） | 例数 | complete / input_invalid | `effective_search_seconds` | 共享 raw 前缀 | 命中目标数 | `new_target_bits_per_second` | certified 证书 | incomplete | 链/秒 |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|
| path_switch | 96 / 96 | 94/2 → 91/5 | 8.783 → 8.427 | **1** | 4 / 4 | 0.4554 → 0.4747 | **0 → 0** | 94 → 91 | 0 → 0 |
| initial_ram_data | 96 / 96 | 94/2 → 94/2 | 9.134 → 9.505 | **96（全前缀）** | 4 / 4 | 0.4379 → 0.4208 | **0 → 0** | 94 → 94 | 0 → 0 |
| closed_loop_energy | 41 / 35 | 41/0 → 35/0 | 61.081 → 61.062 | **35（=ON 全部）** | 4 / 4 | 0.06549 → 0.06551 | 12 → 7 | 29 → 28 | 0.1965 → 0.1146 |

`new_target_bits_per_second` 三对的分子都是 4（四个目标都被命中），差异只来自分母（各臂自己的有效搜索秒）。

### 每目标命中例数（receipts 自己的窗口）

| 目标 | path_switch OFF/ON | initial_ram OFF/ON | closed_loop OFF/ON |
|---|---:|---:|---:|
| `gpio_a_output_bit0` | 80 / 68（83.3% / 70.8%） | 80 / 80 | 34 / 24（82.9% / 68.6%） |
| `gpio_b_irq` | 23 / 23 | 23 / 23 | 12 / 7（29.3% / 20.0%） |
| `cpu_external_irq_vector_fetch` | 19 / 19 | 19 / 19 | 9 / 6（22.0% / 17.1%） |
| `cpu_data_write` | 58 / 57（60.4% / 59.4%） | 58 / 58 | 24 / 16（58.5% / 45.7%） |
| 至少命中一次 | **4 / 4** | **4 / 4** | **4 / 4** |
| 每例平均点亮目标数（派生） | 1.875 / 1.740 | 1.875 / 1.875 | 1.927 / 1.514 |

`closed_loop` 的首次命中例号（各臂自己的窗口）：OFF `3 / 2 / 2 / 1`，ON `11 / 10 / 10 / 1`。

### 共享前缀内的逐例字段一致/不同（前缀之外不配对）

| 字段 | path_switch（前缀 1） | initial_ram（前缀 96） | closed_loop（前缀 35） |
|---|---|---|---|
| `status` | 1 同 / 0 异 | **96 同 / 0 异** | 35 同 / 0 异 |
| `coverage_hex` | 1 同 / 0 异 | **96 同 / 0 异** | 12 同 / **23 异** |
| `effective_genome_sha256` | 0 同 / 1 异 | **96 同 / 0 异** | 2 同 / **33 异** |
| `path_id` / `applied_sources` / `direction` / `operator_id` | 0 同 / 1 异 | **96 同 / 0 异** | 16 同 / **19 异** |

### 每方向见证边（`runtime_edge_provenance_report.v1`）

三对运行声明的运行边都是 9 条（`CPU_TO_IP_TO_CPU` 5 条 + `IP_TO_CPU_TO_IP` 4 条，另有 6 条声明 hop 不是运行边）。**三对的 OFF/ON 每方向计数完全相同**：

| 运行对 | CPU→IP→CPU certified/incomplete/unknown | IP→CPU→IP certified/incomplete/unknown |
|---|---|---|
| path_switch | 4 / 1 / 0 → 4 / 1 / 0 | 4 / 0 / 0 → 4 / 0 / 0 |
| initial_ram | 4 / 1 / 0 → 4 / 1 / 0 | 4 / 0 / 0 → 4 / 0 / 0 |
| closed_loop | 5 / 0 / 0 → 5 / 0 / 0 | 4 / 0 / 0 → 4 / 0 / 0 |

（`analyze_run` 的 `unique_edges` 三对也都是 9/9。`path_switch` 的 `candidate_observations` 7000→6796，`closed_loop` 3172→2662，说明轨迹不同但**被见证的声明边集合不变**。）

## 结论

1. **path_switch：本预算无可测的覆盖/完整链收益。** 两枝都命中全部 4 个声明目标；认证链都是 **0**（incomplete 94 vs 91，首个缺失 hop 分布同为 `pin8_injection` 55/53、`instruction_fetch` 39/38）；链/秒都是 0；每方向见证边完全相同。该算子确实生效（46/96 例切换、5 例切换后被 source-action 门拒绝），但生效体现在**候选身份与输入轨迹**上（共享 raw 前缀只有 1 例），不体现在覆盖目标集合或完整链数量上。
2. **initial_ram_data：本预算无可测差异，且这是最强的一对对照。** 两枝 96 例 raw 输入**完全相同**（共享前缀=全前缀），前缀内 7 个逐例字段 **96/96 全部相同**；每目标命中例数、`new_target_bits_per_second` 的分子、认证/不完整链（0/94 对 0/94）、每方向见证边全部相同。算子确实生效（初始镜像 + 首个读返回变异值，见其门禁报告），但在这个 96 例窗口里它没有改变任何被判定的搜索结果。
3. **closed_loop_energy：有可测的逐例差异，但差异方向不是收益。** 共享前缀 35 例（=ON 枝全部）内，19 例选源/path 不同、23 例 `coverage_hex` 不同、33 例 genome 不同；三个目标在 ON 枝的**首次命中例号明显更晚**（3/2/2 → 11/10/10）。聚合上两枝都命中 4/4 目标，`new_target_bits_per_second` 基本持平（0.06549 → 0.06551，差异来自分母），但 ON 枝认证链更少（12 → 7，链/秒 0.1965 → 0.1146）、每例平均点亮目标数更低（1.93 → 1.51）、且同 60 秒预算内完成例数更少（41 → 35，与既有报告的 −15% 一致）。既有报告只声称"闭环反馈进入了选源路径"，本报告进一步说明：**它没有带来覆盖或完整链层面的收益**。
4. **总体**：在本 seed、本负载、本预算、各运行只跑一次的条件下，三个合法算子在**覆盖目标集合（都是 4/4）与完整链认证数**上没有可测的收益；可测到的差异是"搜索轨迹被改变"（闭环能量最明显），而不是"结果更好"。

## 限制（不得外推）

- **每个算子只有一对运行、每枝只跑一次**：没有重复实验，就没有方差、置信区间或显著性；"无可测差异"只说明这个窗口里没看到差异，不是"算子无效"的证明。
- **覆盖目标集合已饱和**：三对运行的目标清单只有 4 个目标，OFF/ON 都全部命中。这个窗口对"新增目标"不敏感；`new_target_bits_per_second` 的差异只是分母（有效搜索秒）差异，不能读成覆盖能力差异。
- **前缀之外不是配对**：path_switch 前缀仅 1 例、closed_loop 前缀 35 例（OFF 还多跑 6 例），它们的整臂合计、百分比、每例均值都受例数与轨迹影响；`closed_loop` 的 OFF 绝对命中数更高，部分只是因为多跑了 6 例。
- **认证链为 0 的两对不能读成"DUT 从未完成链"**：shipped 语义是"产物能认证的完整链数"；`chain_gap_evidence` 给出首个缺失 hop（两对均为 `pin8_injection` / `instruction_fetch` 主导），这是证据/产物能力边界。`closed_loop` 两枝各例恰好对应一张 admission 证书（OFF 12+29=41，ON 7+28=35）。
- **每方向见证边对本类差异不敏感**：三对 OFF/ON 的每方向计数完全相同（9 条声明运行边），说明它度量的是"该臂 trace 里被见证的声明边集合"这一结构性事实；它相同**不能**用来论证算子无效，只能说明算子没有改变被见证的声明边集合。另外该消费者受 `max_event_gap` 限制，存在被丢弃的迟到 hop（path_switch 3288、closed_loop 37592/30808），故它是 shipped 口径下的有界计数。
- **初始 RAM 的差异本身不在覆盖里**：变异字节落在固定固件留空的取指空隙，真实 Ibex 会推测预取它；本对照只说明它没有改变这 96 例的判定结果，不说明它对别的窗口/别的字节没有影响。
- **未纳入的运行**：`current-dataflow-p4-path-switch-long-on-20261007-online`（2400 例 ON 长枝）**没有同预算 OFF 对照**；`runs/p4-shift-{slli,srai,srli,fuzz}-20261007-online` 四个运行的预算互不相同（200/25/25/25 例）且 `report.json` 未声明算子开关状态，**不构成诚实对照**，故都未纳入。本报告不复用其数字。
- **不涉及 P5/P6/P7/P8**；`fresh replay`、DUT 等价性、速度提升均不在本报告结论范围内（脚本自身也不做 replay）。所有数字只来自已保存产物，没有重新执行任何 RTL。
