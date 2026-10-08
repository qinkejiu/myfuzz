# P5 固定预算单臂指标聚合（`p5_arm_metrics.v1`）

日期：2026-10-08。对应 [P5 实现计划](../../docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md) 清单项：

> 用固定输入/种子、同一源码和相同断言比较连续会话与逐 testcase 启动；分别统计一次性编译/初始化、每例 admission、真实 RTL 事务、Router/Scheduler、增量反馈、日志/证据、p50/p95 时延、有效例/s、完整真实链/s、覆盖增量/s 与无效/超时比例。

此前这些量分散在四个互不相通的位置：`myfuzz.scenario.acceptance_metrics.analyze_run`（状态计数、无效比例、证书链、覆盖新颖率、分位时延、finalization）、`myfuzz.scenario.paired_efficiency`（只在**成对**比较里给出每臂速率）、run 自己的 `report.json` 分项计时，以及链证书生产器 `chain_certificates.ChainCertificates`。**没有任何一个文档能同时陈述上面那一整串量**——这正是本次交付补齐的 P5 缺口。

本报告交付一个只读聚合器：**一个文档、每臂一次、涵盖全部 12 项声明量**；每臂 12 组共 **119 个叶子指标**，每个叶子都形如 `{"value", "source", "reason"}`——`source` 指明该数字来自哪个 artifact key，输入缺失时 `value=null` 且 `reason` 非空，**绝不写 0**。

---

## 0. 新增文件（全部为新文件，未修改任何既有源码/配置/RTL/脚本）

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/p5_arm_metrics.py` | 聚合模块，schema `p5_arm_metrics.v1`；只读、流式、有界内存；12 组 / 119 叶 |
| `scripts/report_p5_arm_metrics.py` | CLI；退出码 `0` 成功 / `1` 读取错误 / `3` 用法错误 |
| `tests/scenario/test_p5_arm_metrics.py` | 32 项聚焦测试（含 2 项真实已保存 run 只读测试） |
| `docs/reports/p5-arm-metrics-20261008/arm_metrics.json` | 七臂原始文档（证据附件），sha256 `d91e1a6cbfdc1b103a90d65a903ab81ab52224a12d1fc408e4ee9c4dfa8bdb29` |
| `docs/reports/p5-arm-metrics-20261008/arm_metrics.md` | 同一文档的 markdown 渲染（由 CLI `--markdown-out` 生成） |
| `docs/reports/p5-arm-metrics-20261008/cross_check.json` | 与 `paired_efficiency` / `acceptance_metrics` 的逐字段交叉核对证据 |
| `docs/reports/p5-arm-metrics-20261008/revisions.json` | 产生上述数字时的源码修订 sha256 与聚合起止时间 |
| `docs/reports/current-dataflow-p5-arm-metrics-20261008.md` | 本报告 |

本工具**不启动**任何 RTL/Verilator/cargo/fuzz 作业，**不写入**任何 run 目录：它只读 `report.json`、`receipts.jsonl`（逐行流式）、`online_plan.json`、`online_run_identity.json`、`online_session_manifest.json`、`client.log`、`online_final_trace.meta.json` + `online_events.{jsonl,zlib}` 或 `online_final_trace.json`（流式）、`cold_start.json`。

## 1. 用法

```bash
PYTHONPATH=src python3 scripts/report_p5_arm_metrics.py \
  runs/<arm-a> runs/<arm-b> ... \
  --labels <label-a> <label-b> ... \
  --json-out docs/reports/p5-arm-metrics-20261008/arm_metrics.json \
  --markdown-out docs/reports/p5-arm-metrics-20261008/arm_metrics.md
```

`--labels` 必须**跟在** run 目录之后（argparse 位置参数规则）。全量七臂（含 493 MB JSONL trace）一次用时约 3 分 36 秒（`revisions.json:aggregation_started_utc/finished_utc`）。

## 2. 十二项声明量与它们的 artifact key

| P5 清单项 | 文档中的组 `metrics.<group>` | 主叶子 | 来源 artifact key |
|---|---|---|---|
| 一次性编译/初始化 | `one_time_compile_init` | `finalization_timing_seconds`、`compilation_seconds`、`cold_start_init_seconds_p50/p95`、`per_case_initialization_seconds` | `report.json:finalization_timing_seconds` / `cold_start.json:cases[].init_seconds` |
| 每例 admission | `per_case_admission` | `receipt_rows`、`admissions_total`、`local_ticks_by_component_sum`、`coverage_records` | `receipts.jsonl` 各键、`online_plan.json:source_admissions.admissions` |
| 真实 RTL 事务 | `real_rtl_transactions` | `cases_with_runner_timing`、`cases_with_rtl_case_committed`、`record_semantics` | `receipts.jsonl:online_runner_timing_seconds`、`receipts.jsonl:candidate_disposition_reason`、`report.json:record_semantics` |
| Router/Scheduler | `router_scheduler` | `online_runner_timing_seconds`（每分项 count/p50/p95/sum）、`cases_with_router_transact` | `receipts.jsonl:online_runner_timing_seconds.*` |
| 增量反馈 | `incremental_feedback` | `completed_feedback_exchanges`、`mutation_hint_updates`、`cases_with_interaction_*` | `report.json:completed_feedback_exchanges` 等、`receipts.jsonl:interaction_*` |
| 日志/证据 | `log_evidence` | `trace_format`、`trace_bytes`、`trace_meta_container_split`、`evidence_footprint_bytes` | trace 容器与 meta 文件、`receipts.jsonl`/`client.log`/`online_session_manifest.json` 字节数 |
| p50/p95 时延 | `latency_percentiles` | `online_phase_timing_seconds`（逐分项）、`per_case_total_seconds` | `receipts.jsonl:online_phase_timing_seconds` |
| 有效例/s | `effective_cases_per_second` | `effective_cases_per_second`、`complete_status_count`、`denominator_seconds` | `receipts.jsonl:status` ÷ `report.json:effective_search_seconds` |
| 完整真实链/s | `certified_chains_per_second` | `certified_chains`、`certified_chains_per_second`、`first_missing_hop_histogram` | trace 事件上的 `runtime_chain_certificate.v1` 证书 |
| 覆盖增量/s | `coverage_novelty` | `new_target_bits_per_second`、`new_witnessed_edges_per_second` | `receipts.jsonl:coverage_hex`、trace 事件 `provenance.edge_candidates` |
| 无效/超时比例 | `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` + 精确计数 | `receipts.jsonl:status`（分类集合由 shipped 模块拥有） |
| （精确状态计数） | `status_counts` | `status_counts`、`reports_agree` | `receipts.jsonl:status` 对 `report.json:statuses` |

叶子集合是**静态**的：缺输入只会把某个叶子的 `value` 变成 `null` 并填 `reason`，不会改变文档形状（测试 `test_all_arms_expose_the_same_leaf_paths` 对富臂、空臂、异种 schema 臂断言同一叶子路径集合）。

## 3. 真实七臂结果

命令（只读，可逐字复现）：

```bash
PYTHONPATH=src python3 scripts/report_p5_arm_metrics.py \
  runs/current-dataflow-p5-chain-acceptance-20261007-online \
  runs/current-dataflow-p5-chain-600s-20261007-online \
  runs/current-dataflow-p5-paired-20261007-online \
  runs/p5-paired-frozen-20261008-a-online \
  runs/p5-format2-jsonl-20261007-online \
  runs/p5-format2-zlib-20261007-online \
  runs/p4-cpu-side-first-seen-20261008-online \
  --labels chain-acceptance-31s chain-600s paired-31s paired-frozen-a format2-jsonl format2-zlib p4-cpu-side-foreign \
  --json-out docs/reports/p5-arm-metrics-20261008/arm_metrics.json \
  --markdown-out docs/reports/p5-arm-metrics-20261008/arm_metrics.md
```

### 3.1 主表（有效例/s、完整链/s、覆盖增量/s、无效/超时、p50/p95）

| 臂 | 有效例/s | 完整链 | 完整链/s | 目标位增量/s | 见证边增量/s | 无效+超时比例 | 逐例 p50 (s) | 逐例 p95 (s) | 终结 total_before_report (s) | trace 字节 |
|---|---|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | 0.767422 | 8 | 0.255807 | 0.127904 | 0.287783 | 0/24 = 0 | 1.29653 | 1.72226 | 11.5503 | 163,190,709 |
| chain-600s | 0.612963 | 27 | 0.0449728 | 0.00666264 | 0.0149909 | 0/368 = 0 | 1.64830 | 2.37667 | 67.7868 | 172,324,767 |
| paired-31s | 0.779642 | 8 | 0.259881 | 0.129940 | 0.292366 | 0/24 = 0 | 1.27179 | 1.67116 | 11.2796 | 163,567,647 |
| paired-frozen-a | 0.708553 | 7 | 0.215647 | 0.123227 | 0.277260 | 1/24 = 0.0416667 | 1.42173 | 1.77383 | 11.2131 | 157,053,470 |
| format2-jsonl | 0.621291 | 13 | 0.107690 | 0.0331355 | 0.0745549 | 2/77 = 0.0259740 | 1.62889 | 2.09408 | 24.6109 | 493,194,248 |
| format2-zlib | 0.655778 | 14 | 0.116214 | 0.0332040 | 0.0747089 | 2/81 = 0.0246914 | 1.53075 | 2.01874 | 13.4693 | 36,903,052 |
| p4-cpu-side-foreign | `null` | `null` | `null` | `null` | `null` | `null` | `null` | `null` | `null` | `null` |

每格来源：有效例/s = `receipts.jsonl:status` 的 `complete` ÷ `report.json:effective_search_seconds`；完整链/s = 证书总数 ÷ 同一分母；目标位/见证边增量 = `receipts.jsonl:coverage_hex` / trace `provenance.edge_candidates` ÷ 同一分母；无效+超时 = `receipts.jsonl:status`；逐例 p50/p95 = `receipts.jsonl:online_phase_timing_seconds.total`；终结 = `report.json:finalization_timing_seconds.total_before_report`；trace 字节 = 容器文件大小。

要点与旧报告一致：31 秒全探针臂 **8 条认证链 = 0.255807 链/s**、4/4 目标位、9 条见证边，与[首步端到端验收入口](current-dataflow-p5-chain-acceptance-20261007.md)逐位一致；十分钟臂 **27 条认证链 = 0.044973 链/s**（同案 21、跨例 6），与[十分钟全探针门禁](current-dataflow-p5-chain-600s-20261007.md)逐位一致；`format2` 两臂的覆盖增量落在 0.0332 位/s、0.0746–0.0747 边/s，明显低于 31 秒臂（0.128 / 0.288），因为分母是 120.5 秒而 4 个目标位早已在第一分钟见完——**这是分母效应，不是搜索质量退化**。

`p4-cpu-side-first-seen-20261008-online` 不是 dataflow 会话：其 `report.json` 声明 `schema_version = "soc_result.v1"`，目录里既无 `receipts.jsonl` 也无任何 online trace 容器，因此 `arm_kind = not_a_scenario_online_session`、`analysis_performed = false`，**119 个叶子全部为 `null` 且每个 `reason` 都写明 `soc_result.v1` 与缺失条件**。这是"有意义的 null+reason 例"。

### 3.2 一次性编译/初始化

| 臂 | identity_write | plan_write | session_finish | trace_write | total_before_report | effective (s) | elapsed (s) | elapsed − effective (s) | compilation_seconds |
|---|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | 0.237584 | 0.002080 | 6.244267 | 5.005776 | 11.550271 | 31.273544 | 32.440838 | 1.167294 | `null` |
| chain-600s | 0.300499 | 0.003330 | 19.334471 | 48.051290 | 67.786835 | 600.362953 | 601.543951 | 1.180998 | `null` |
| paired-31s | 0.246032 | 0.001651 | 5.953964 | 5.015456 | 11.279589 | 30.783371 | 31.905327 | 1.121956 | `null` |
| paired-frozen-a | 0.213555 | 0.002563 | 5.818923 | 5.116095 | 11.213116 | 32.460502 | 33.730550 | 1.270047 | `null` |
| format2-jsonl | 0.373986 | 0.002296 | 3.392920 | 20.744583 | 24.610933 | 120.716374 | 122.012278 | 1.295904 | `null` |
| format2-zlib | 0.166120 | 0.002026 | 4.065045 | 9.146172 | 13.469331 | 120.467550 | 121.645055 | 1.177505 | `null` |

- **没有任何 artifact 记录 RTL 编译/elaboration 秒数**：`report.json` 只有搜索结束后的 `finalization_timing_seconds`，RTL 构建在本会话之外预编译。因此 `compilation_seconds` 在所有臂上都是 `null` + 该原因，而不是 0。
- `elapsed − effective` 是**派生量**（两个 `report.json` 字段相减），已声明它不分解为分项：30 秒臂约 1.12–1.27 s、120 秒臂约 1.18–1.30 s，与 `total_before_report`（11.2–24.6 s）不同量级，因为 `effective_search_seconds` 与 finalization 并不保证互斥，本工具不替 artifact 做这个假设。
- 连续会话**不把初始化摊到任何单例**：`per_case_initialization_seconds = null`，原因沿用 `paired_efficiency` 的措辞。
- 两个真实冷启动臂（同预算对照的另一半，按臂聚合，非主表成员）：

| 冷启动臂 | baseline 声明 | 实测 init 例数 | init p50 (s) | init p95 (s) | init 总量 (s) | 占自身 report elapsed | 占 wall_clock_seconds |
|---|---|---|---|---|---|---|---|
| `current-dataflow-p5-paired-20261007-cold-start` | 24 | 24 | 18.736194 | 19.047627 | 449.695218 | 17.589489（>1） | **0.876802**（512.881 s） |
| `p5-paired-frozen-20261008-a-cold-start` | 24 | 15 | 12.446517 | 12.776868 | 185.742759 | 11.622541（>1） | **0.546461**（339.901 s） |

  第一行说明为什么必须同时给出两个占比：冷启动组的 `report.json:elapsed_seconds`（25.57 s）**不是墙钟**，用它做分母会得到 >1 的荒谬值；墙钟口径的 `cold_start_share_of_wall_clock_seconds = 0.8768`（第二臂 0.5465）才是可用的"初始化占墙钟比例"。第二行同时暴露 frozen 冷臂只发布了 24 例中的 15 例，聚合器为此写入显式 limit（见 §4 的口径差异）。

### 3.3 每例 admission

| 臂 | receipt 行 | admissions 总数 | fuzz_source / fixed_support | candidate disposition | submit 计时例数 | local_command 总计 | local_command p50 / p95 | roundtrip p50 (s) | host_remainder p50 (s) |
|---|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | 24 | 39 | 24 / 15 | `admitted`×24 | 24 | 2,324 | 97 / 98 | 0.049731 | 1.18390 |
| chain-600s | 368 | 559 | 368 / 191 | `admitted`×368 | 368 | 35,607 | 97 / 98 | 0.052371 | 1.50954 |
| paired-31s | 24 | 39 | 24 / 15 | `admitted`×24 | 24 | 2,324 | 97 / 98 | 0.049393 | 1.14147 |
| paired-frozen-a | 24 | 39 | 23 / 16 | `admitted`×23, `rejected`×1 | 23 | 2,226 | 97 / 98 | 0.056724 | 1.31096 |
| format2-jsonl | 77 | 117 | 75 / 42 | `admitted`×75, `rejected`×2 | 75 | 7,251 | 96 / 98 | 0.056632 | 1.49504 |
| format2-zlib | 81 | 123 | 79 / 44 | `admitted`×79, `rejected`×2 | 79 | 7,637 | 96 / 98 | 0.054818 | 1.40258 |

| 臂 | 有 local_ticks 例数 | local_ticks 分量合计 (cpu/gpio_a/gpio_b) | total_local_ticks 合计 | coverage records | coverage 宽度 | raw records | 有 violations 例数 |
|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | 24 | 768 / 800 / 816 | 2,384 | 24 | 4 B | 24 | 0 |
| chain-600s | 368 | 11,776 / 12,300 / 12,368 | 36,444 | 368 | 4 B | 368 | 0 |
| paired-31s | 24 | 768 / 800 / 816 | 2,384 | 24 | 4 B | 24 | 0 |
| paired-frozen-a | 23 | 736 / 768 / 776 | 2,280 | 24 | 4 B | 24 | 0 |
| format2-jsonl | 75 | 2,400 / 2,504 / 2,500 | 7,404 | 77 | 4 B | 77 | 0 |
| format2-zlib | 79 | 2,528 / 2,632 / 2,636 | 7,796 | 81 | 4 B | 81 | 0 |

每例提交命令数稳定在 96–98（p95 均为 98），与 24/368/81 例规模无关；`rejected` 例数恰好等于 `input_invalid` 状态例数，且这些例没有 runner 计时/本地 tick（所以 runner 计时例数 23/75/79 < receipt 行数 24/77/81）。**没有任何臂出现 violation**（`cases_with_violations = 0` 是实测 0，不是缺失）。

### 3.4 真实 RTL 事务与 Router/Scheduler

`online_runner_timing_seconds` 六分项（嵌套计时，**不可相加**）：

| 臂 | scheduler_batch p50 / p95 / sum (s) | runner_step p50 / p95 / sum (s) | router_enqueue sum (s) | router_drain sum (s) | router_transact 例数 / sum (s) | observed_output_route sum (s) |
|---|---|---|---|---|---|---|
| chain-acceptance-31s | 1.022502 / 1.381803 / 25.040469 | 1.022315 / 1.381613 / 25.036165 | 0.000373 | 0.034201 | 0 / 0.0 | 0.130253 |
| chain-600s | 1.127333 / 2.046716 / 447.904652 | 1.127098 / 2.046485 / 447.824191 | 0.005796 | 0.442272 | 0 / 0.0 | 1.263490 |
| paired-31s | 1.002155 / 1.322508 / 24.641898 | 1.001959 / 1.322325 / 24.637383 | 0.000361 | 0.029812 | 0 / 0.0 | 0.129554 |
| paired-frozen-a | 1.090870 / 1.340690 / 24.943980 | 1.090650 / 1.340378 / 24.938007 | 0.000423 | 0.029067 | 0 / 0.0 | 0.045653 |
| format2-jsonl | 1.266608 / 1.494195 / 92.465678 | 1.266256 / 1.493910 / 92.443203 | 0.001215 | 0.096499 | 0 / 0.0 | 0.244332 |
| format2-zlib | 1.194244 / 1.406539 / 91.347802 | 1.194001 / 1.406282 / 91.328279 | 0.001220 | 0.088193 | 0 / 0.0 | 0.235236 |

- **所有七臂的同步 Router 事务都是 0 例**：`router_transact` 的 p50/p95 全为 0.0、sum 为 0.0——默认 GPIO 闭环负载不走同步事务路径，与[Runner/Router/Scheduler 短门禁](current-dataflow-p5-runner-router-scheduler-timing-20261007.md)的结论一致。这是一个**实测 0**（receipts 里真的没有非 0 事务），不是缺失。
- `scheduler_batch ≈ runner_step`（相差 <0.1%），因为 runner 步进几乎全部发生在调度批次内；`router_drain` 在 24 例臂有 p50>0（0.00118–0.00146），在 format2 臂 p50=0 而 p95>0，说明排空是少数例的长尾。
- 边界：这些分项**互相包含**（scheduler ⊃ runner ⊃ router），文档同时给出每项 p50/p95/sum 并显式声明"不可相加、不是纯 RTL 时间"；`report.json:record_semantics = mutation_decisions_not_dut_cycles`、`total_local_ticks_semantics = sum_of_independent_local_ticks_cost_only` 也被逐字带出，提醒 tick 数与决策数都不是 DUT 周期。

### 3.5 p50/p95 全分项（`online_phase_timing_seconds`）

| 臂 | selection_decode | rtl_submit | trace_digest | interaction_ingest | checker | feedback_credit | receipt_build | total |
|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | 0.0000986 / 0.0001275 | 1.234273 / 1.595630 | 0.047566 / 0.053960 | 0.014803 / 0.078164 | 0.0000019 / 0.0000031 | 0.000854 / 0.001122 | 0.0000173 / 0.0000210 | 1.296532 / 1.722264 |
| chain-600s | 0.0001066 / 0.0001280 | 1.561018 / 2.283925 | 0.052756 / 0.060513 | 0.019712 / 0.114815 | 0.0000022 / 0.0000029 | 0.001219 / 0.008301 | 0.0000180 / 0.0000220 | 1.648304 / 2.376670 |
| paired-31s | 0.0001005 / 0.0001423 | 1.192224 / 1.594464 | 0.047389 / 0.052664 | 0.015276 / 0.075611 | 0.0000020 / 0.0000028 | 0.000812 / 0.001126 | 0.0000173 / 0.0000225 | 1.271786 / 1.671159 |
| paired-frozen-a | 0.0002102 / 0.0003459 | 1.347088 / 1.642171 | 0.049657 / 0.057339 | 0.015976 / 0.081940 | 0.0000023 / 0.0000040 | 0.000982 / 0.001385 | 0.0000246 / 0.0000312 | 1.421734 / 1.773835 |
| format2-jsonl | 0.0002092 / 0.0003415 | 1.538477 / 1.999973 | 0.051883 / 0.059991 | 0.018258 / 0.090342 | 0.0000026 / 0.0000037 | 0.001182 / 0.001836 | 0.0000210 / 0.0000259 | 1.628892 / 2.094083 |
| format2-zlib | 0.0002104 / 0.0003449 | 1.449252 / 1.943850 | 0.051270 / 0.057543 | 0.017962 / 0.083801 | 0.0000024 / 0.0000031 | 0.001087 / 0.001721 | 0.0000211 / 0.0000253 | 1.530746 / 2.018738 |

逐分项计数等于 receipt 行数（24/368/24/24/77/81），`invalid_timing_values = 0`；**时延的 99% 在 `rtl_submit`**（真实 RTL 提交），`checker` 与 `receipt_build` 是可忽略的簿记。缺分位的语义由 shipped 模块决定：单样本时只给 p50、p95 为 `null`（测试 `test_single_sample_arm_reports_p50_only_and_a_null_p95`），聚合器原样转发。

### 3.6 增量反馈

| 臂 | completed_feedback_exchanges | mutation_hint_updates | 有 interaction_new_features 例数 | 有 feature_deltas 例数 | 有 source_gains 例数 | interaction_deferred | gate enforce / action_ids | path_switch | closed_loop_energy |
|---|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | 2 | 3 | 1 | 1 | 1 | 23 | `null` / `null` | `null` | `null` |
| chain-600s | 31 | 32 | 1 | 23 | 1 | 345 | `null` / `null` | `null` | `null` |
| paired-31s | 2 | 3 | 1 | 1 | 1 | 23 | `null` / `null` | `null` | `null` |
| paired-frozen-a | 2 | 3 | 0 | 0 | 0 | 23 | `true` / 23 | `disabled`, 0 次尝试 | `enabled=false`, 0 证书 |
| format2-jsonl | 2 | 3 | 1 | 3 | 1 | 72 | `true` / 75 | `disabled`, 0 次尝试 | `enabled=false`, 0 证书 |
| format2-zlib | 1 | 1 | 1 | 4 | 1 | 75 | `true` / 79 | `disabled`, 0 次尝试 | `enabled=false`, 0 证书 |

三个 06:44 版 `report.json`（chain-acceptance / chain-600s / paired-31s）**根本没有** `source_action_gate` / `path_switch` / `closed_loop_energy` 键——聚合器对这些格子给 `null` + "`report.json:source_action_gate is absent`"，而不是 0。`format2-zlib` 的 `completed_feedback_exchanges = 1`、`mutation_hint_updates = 1` 是它自己的 artifact 值（其余臂为 2/3），聚合器不做任何补齐或推断。

### 3.7 日志/证据

| 臂 | format | 事件文件 | trace 字节 | meta+容器拆分 | 事件数（实测/声明/一致） | 语义摘要校验 | receipts 字节 | session manifest 字节 | 合计 footprint 字节 |
|---|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | `json.v1` | `online_final_trace.json` | 163,190,709 | 否（单体） | 31,795 / – / – | – | 63,721 | 2,402,112 | 165,832,324 |
| chain-600s | `zlib_chunks.v1` | `online_events.zlib` | 172,324,767 | **是** | 570,196 / 570,196 / `true` | `true` | 975,420 | 2,402,237 | 176,609,081 |
| paired-31s | `json.v1` | `online_final_trace.json` | 163,567,647 | 否 | 31,795 / – / – | – | 63,943 | 2,402,237 | 166,209,352 |
| paired-frozen-a | `json.v1` | `online_final_trace.json` | 157,053,470 | 否 | 30,657 / – / – | – | 99,374 | 2,406,053 | 159,751,779 |
| format2-jsonl | `jsonl.v1` | `online_events.jsonl` | 493,194,248 | **是** | 108,113 / 108,113 / `true` | `true` | 327,735 | 2,405,220 | 496,263,865 |
| format2-zlib | `zlib_chunks.v1` | `online_events.zlib` | 36,903,052 | **是** | 114,309 / 114,309 / `true` | `true` | 345,893 | 2,405,220 | 40,001,802 |

- 同条件容器对照的两臂（format2-jsonl / format2-zlib）事件数不同（108,113 vs 114,309）且**不是同一份输入**，所以两臂的字节数差（493 MB vs 36.9 MB）只说明容器体积量级，不能当作同 trace 压缩比；`arm_equivalence.v1` 已另行给出同条件等价判定。
- 单体 `online_final_trace.json` 臂没有 `online_final_trace.meta.json`，`trace_meta_container_split = false`；分体臂为 `true`。声明事件数与实测不一致时该叶子为 `false`（本表全部一致或无可比声明）。
- 四臂 zlib/jsonl 分体的 `trace_semantic_sha256_verified = true`，即流式读出的规范摘要与 artifact 声明一致。

## 4. 与 shipped 模块的交叉核对

证据：`docs/reports/p5-arm-metrics-20261008/cross_check.json`。

**方法**：

1. `paired_efficiency.compare_runs(runs/current-dataflow-p5-paired-20261007-online, runs/current-dataflow-p5-paired-20261007-cold-start)`（真实、同 seed、可逐例对齐的一对）→ 与 `aggregate_arms` 的同两臂逐字段比对；
2. `acceptance_metrics.analyze_run(runs/current-dataflow-p5-chain-acceptance-20261007-online)` → 与 `aggregate_arms` 的同臂逐字段比对；
3. 另外尝试 `compare_runs` frozen 对，记录其拒绝原文。

**结果（全部逐位相同）**：

| 核对对象 | 字段数 | 结果 |
|---|---|---|
| `paired_efficiency.groups.<arm>.*`（每臂 12 个：目标位/s、边/s、唯一边、证书数、链/s、不完整链、全部 receipt 例/s、有效例/s、无效比例、逐例 p50/p95、finalization、complete 计数） | 24 | 全部 `bit_identical = true` |
| `paired_efficiency.initialization.*`（冷启动 p50/p95/实测例数/init 总量/占 elapsed 比） | 5 | 全部 `bit_identical = true` |
| `acceptance_metrics.analyze_run`（证书总数、链/s、first-missing-hop 直方图、方向分布、目标位/s、边/s、有效例/s、无效比例、逐例 p50/p95、状态计数） | 10 | 全部 `bit_identical = true` |

**逐位复用的量**（不是重新实现，是同一个函数/同一条规则）：

- 状态计数、无效/超时比例与分类集合、证书链计数与 `first_missing_hop` 直方图、目标位与见证边新颖率、`online_phase_timing_seconds` 与 `online_runner_timing_seconds` 的分位、`finalization_timing_seconds`、trace 证据（格式/字节/事件数/摘要校验）——全部来自 `acceptance_metrics.analyze_run`，与 `paired_efficiency` 在 `_group_summary` 里搬运的是**同一批字段**；
- 分位数规则来自 `acceptance_metrics._percentiles`（`paired_efficiency` 也是从同一处 import），所以我自己扫描得到的分位与 shipped 分位同类同算法；
- 冷启动初始化复用 `paired_efficiency.load_cold_baseline` 与同一窗口 `cold_start.json:cases[].init_seconds`；
- 分母与来源字符串直接引用 `paired_efficiency.RECEIPT_TOTAL_SOURCE` / `COLD_INIT_SOURCE` 常量，避免口径字符串漂移。

**我重新推导的量**（shipped 模块未暴露，故在本模块内流式重算，已用合成真实形状 fixture 与限值 pin 住）：

| 量 | 来源 | 为什么必须重算 |
|---|---|---|
| `local_ticks_by_component_sum`、`total_local_ticks_sum`、`cases_with_total_local_ticks` | `receipts.jsonl:local_ticks.*` / `total_local_ticks` | 无 shipped API 暴露逐分量 tick 合计 |
| `local_command_count_*`、`local_command_roundtrip_seconds_*`、`host_remainder_seconds_*`、`cases_with_online_submit_timing_seconds` | `receipts.jsonl:online_submit_timing_seconds` | 同上（`online_submit_timing_seconds` 无 shipped 消费方） |
| `candidate_dispositions` / `candidate_disposition_reasons` / `cases_with_rtl_case_committed` | `receipts.jsonl:candidate_disposition*` | 同上 |
| `cases_with_interaction_*`、`cases_deferred` | `receipts.jsonl:interaction_*` | 同上 |
| `coverage_records`、`coverage_width_bytes`、`raw_record_count`、`cases_with_violations` | `receipts.jsonl` | 逐例 footprint，非新颖率 |
| `router_*_sum` / `cases_with_router_transact` / `cases_with_scheduler_batch` / `cases_with_observed_output_route` | `receipts.jsonl:online_runner_timing_seconds.*` | shipped 只给分位，不给非 0 例数与合计；合计带"嵌套不可相加"声明 |
| `evidence_footprint_bytes` 及逐文件字节 | 目录内 artifact 的 `stat` | billed footprint 无 shipped API |

**一处有意的口径差异（已写进 limit）**：当 `cold_start.json` 只覆盖部分用例时，`paired_efficiency` 要求整个比较窗口都有 `init_seconds`，否则报 `null`；本聚合器改为报告**实测子集**并显式给出 `cold_start_cases_with_init_seconds` 与一条 limit：

> `cold_start.json declares 24 cases but only 15 carry a finite non-negative cases[].init_seconds; the percentiles cover the measured subset and report its count, whereas paired_efficiency requires the whole compared window and reports null for a partial baseline`

当 baseline 完整覆盖（20261007 冷臂 24/24）时两者逐位相同——这正是交叉核对里 5 个冷启动字段全部相同的原因；frozen 冷臂（24 声明 / 15 实测）则走到 limit 分支。测试 `test_partial_cold_baseline_is_measured_with_an_explicit_limit` 固定这条差异。

**`compare_runs` 拒绝 frozen 对的真实原因**（原文，`cross_check.json:frozen_pair_refusal`）：

> `receipt counts differ: continuous=24 cold=15; per-case alignment is undefined`

即 `p5-paired-frozen-20261008-a-online` 与 `p5-paired-frozen-20261008-a-cold-start` **不能做逐例配对比较**（冷组只发布 15/24 例）。这不是本聚合器的缺陷，而正是为什么要按臂聚合：即便配对对齐不存在，两个臂各自的一次性初始化、admission、有效例/s、p50/p95 与证据足迹仍然可读、可核对；`null` 只出现在真正缺失的地方。

**修订漂移（重要）**：本次会话进行中，另一个并发进程修改了 shipped 的 `src/myfuzz/scenario/acceptance_metrics.py`（当前 sha256 `6ff4a576d8136056b08ff4da87398da442ed13034aa559cd9c1095b6cd9fa502`），把 `input_invalid` 纳入 `INVALID_STATUSES`。后果：`paired-frozen-a` / `format2-jsonl` / `format2-zlib` 三臂的 `invalid_or_timeout_ratio` 从旧修订的 `null`（原因 "receipt statuses without a local classification are present: ['input_invalid']"）变为 0.0416667 / 0.0259740 / 0.0246914。本聚合器**只转发、不重分类**，因此同一份 artifact 在不同修订下会给出不同的比例值——这本身就是"口径属于 shipped 模块"的证据。`revisions.json` 固定了产生主表数字的修订：

```
acceptance_metrics.py   6ff4a576d8136056b08ff4da87398da442ed13034aa559cd9c1095b6cd9fa502
paired_efficiency.py    6da581f37a123d6595346d7f3c515e7a746d5ee2b26c610abd4f5e13af2a899a
chain_certificates.py   b0966bb3228b8c3f73f654feadfefe951a500595a821b4a2bf90cc482646b71a
p5_arm_metrics.py       d5521adda37d3cc9839be8521e128e89451b19ba4f2d1d3d7dee63018d9409f0
```

因此测试里那条真实臂断言写成**规则**而非某修订的答案：比例必须等于导入的 `INVALID_STATUSES`/`TIMEOUT_STATUSES` 计数 ÷ 总行数，且仅当 `CLASSIFIED_STATUSES` 之外还有状态时才为 `null`（`test_classified_input_invalid_status_follows_the_shipped_vocabulary`、`test_real_saved_arm_is_aggregated_read_only`）。

**字节级确定性**：同一命令连续两次运行（run5/run6）产出**逐字节相同**的 JSON 与 markdown，sha256 均为 `d91e1a6c...`；运行前后四个源码文件 sha256 不变（`revisions.json`）。测试 `test_document_is_byte_identical_across_repeated_runs` 与 `test_cli_writes_deterministic_document_and_markdown` 在合成臂上固定了同一性质。

## 5. 测试（先 RED，后实现）

聚焦命令（**不跑全量测试套**）：

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_arm_metrics.py -q -p no:randomly
```

| 阶段 | 结果 | 说明 |
|---|---|---|
| RED #1（测试先写、模块尚不存在） | `1 error in 0.31s` | `ModuleNotFoundError: No module named 'myfuzz.scenario.p5_arm_metrics'`（collection error，全部 32 项未收集） |
| RED #2（首版实现后） | `22 failed, 8 passed in 18.29s` | 合成事件 `event_id` 非连续导致默认证书生产器拒绝、CLI 无参被 argparse 以退出码 2 拦下、两处分位数期望写错 |
| GREEN | `30 passed` → `31 passed` → **`32 passed in 14.33s`** | 含 1 项真实 zlib 臂只读测试（流式 36.9 MB / 114,309 事件）与 1 项真实异种 schema 臂测试 |

覆盖点：12 组声明量齐全；**逐叶子不变量**（`{value,source,reason}` 三键、`source` 非空、`value=null ⇒ reason` 非空、有值 ⇒ `reason=null`）；三臂叶子路径集合相同；每个指标的合成真实形状抽取（状态/分位/证书/覆盖/admission/feedback/evidence）；每一类缺输入的 `null`+reason（缺 receipts、缺 trace、缺 plan、缺 finalization、缺 cold baseline、异种 schema、未分类状态）；`null` 不得写成 0；与 `acceptance_metrics` 的分位逐位一致；与 `paired_efficiency` 的覆盖/效率/链/初始化逐位一致；字节级确定性；CLI 退出码 0/1/3；真实 run 只读。

## 6. 边界与限制

1. **只读**：不启动 RTL/Verilator/cargo/fuzz，不写入任何 run 目录；本报告的全部数字来自已保存 artifact。
2. **两遍 receipts、一遍 trace**：`receipts.jsonl` 被 `analyze_run` 与本模块各流式读一次，trace 容器只被 `analyze_run` 流式读一次；不物化整文件，内存有界。计时样本上限 `DEFAULT_MAX_TIMING_SAMPLES = 200000`，触顶会写 limit（本次七臂均未触顶）。
3. **没有 RTL 编译/elaboration 计时**：`compilation_seconds` 恒为 `null` + 原因；不要把它读成 0。
4. **连续会话没有每例初始化归属**：`per_case_initialization_seconds = null` + 原因；它实际承担的一次性成本是 `finalization_timing_seconds`。
5. **冷启动占比必须选对分母**：冷组的 `report.json:elapsed_seconds` 不是墙钟，用它算出的占比 >1（17.59 / 11.62）；可用的是 `cold_start_share_of_wall_clock_seconds`（0.8768 / 0.5465），且仅当 `report.json:wall_clock_seconds` 存在时才有值。
6. **Runner 分项是嵌套的**：`scheduler_batch ⊃ runner_step ⊃ router_*`，文档给出的 sum 不可相加、不是纯 RTL 时间（`nested_phase_semantics` 逐字声明）。
7. **口径属于 shipped 模块**：`record_semantics = mutation_decisions_not_dut_cycles`、`total_local_ticks_semantics = sum_of_independent_local_ticks_cost_only`，tick/决策数都不是 DUT 周期；`invalid_or_timeout_ratio` 的分类集合也归 `acceptance_metrics` 所有，未分类状态一律 `null` + 原因，不为了凑出数字而扩大口径。
8. **链数是 artifact 能力而非 DUT 事实**：`certified_chains` 是冻结生产器对该 artifact 发出的证书计数；`incomplete` 的 first-missing-hop 直方图只说明 artifact 缺哪一跳证据，不证明 DUT 从未完成链。`chain_producer_available = true` 表示默认 `chain_certificates` 生产器可用（本次七臂中六个 dataflow 臂为 `true`）。
9. **速率分母统一是 `report.json:effective_search_seconds`**（不是墙钟、不是 elapsed）；`log_evidence`/`one_time_compile_init` 另行给出 elapsed 以区分。artifact 不含逐例完成时间戳，因此新颖率只有整窗速率、**没有逐秒曲线**（shipped 模块亦以 `novelty_time_series` limit 声明）。
10. **冷启动部分覆盖的口径差异**见 §4（frozen 冷臂 24 声明 / 15 实测）。
11. **修订漂移**：shipped `acceptance_metrics.py` 在会话中被并发修改；本 artifact 固定在 `revisions.json` 列出的修订上。重跑前建议先核对这四个 sha256，否则 `invalid_or_timeout_ratio` 一类数值会与主表不同。
12. **异种 schema 臂**：`p4-cpu-side-first-seen-20261008-online`（`soc_result.v1`，无 receipts、无 online trace）被判定为 `not_a_scenario_online_session`，全部 119 叶 `null` + 同一原因；它**不**进入任何 P5 对照结论。
13. **未覆盖**：本交付只补齐"一个文档陈述全部声明量"这一项。断言质量/灵敏度同条件对照、覆盖等价判定、故障族校准等其它 P5 项仍由各自报告负责；本报告不据此宣称 P5 整阶段验收。
