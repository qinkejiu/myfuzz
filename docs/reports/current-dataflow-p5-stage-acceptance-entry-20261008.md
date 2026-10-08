# P5 阶段验收入口：`p5_acceptance_suite.v1` 的逐项判定与联合表

日期：2026-10-08。本文是 **P5 阶段验收入口本身**的交付说明：新增的只读套件
[`scripts/run_p5_acceptance_suite.py`](../../scripts/run_p5_acceptance_suite.py) 与
[`myfuzz.scenario.p5_acceptance`](../../src/myfuzz/scenario/p5_acceptance.py) 如何**逐运行判定**与**按关键项求并**，
以及它在仓库现有真实运行上得到的**联合结果**与**边界**。阶段结论与四组清单项的证据叙述见
[P5 阶段验收（按声明范围）](current-dataflow-p5-stage-acceptance-20261008.md)；本文只回答"入口判了什么、凭什么判、
哪些还没被任何真实运行证明"。

**一句话结论**：六个关键项在声明的六个真实运行上**全部**由至少一个运行 `measured=true` 且 `met=true` 证明，
`exit_code=0`、`critical 6/6`、`no_proving_run=[]`；但**没有任何单个运行**同时满足六项（单运行上限 3/6），
且 P5 的"异构外设长会话"子主张**仍无真实运行**（详见 §5）。

## 1. 入口形状

- 新模块：`src/myfuzz/scenario/p5_acceptance.py`（每运行报告 `p5_acceptance_report.v1` ＋ 联合文档 `p5_acceptance_suite.v1`）。
- 新 CLI：`scripts/run_p5_acceptance_suite.py`，只接受**声明**、只读**已保存产物**：
  - `--run ROLE=DIR[@COMPARE_DIR]`（可重复）：角色显式声明，绝不从目录名推断；`@` 后是同一对里的另一枝。
  - `--artifact ROLE=KEY=PATH`（可重复）：声明不在运行目录内的证据产物。
  - 退出码：`0` 每个关键项都有证明运行；`2` 某关键项无证明运行（或 `measured=false`）；`1` 命令**根本没能运行**
    （坏声明、目录不存在、不可读路径），并打印 `p5_acceptance_suite_error.v1`。
- 判定纪律：`met=true` 必须伴随 `measured=true`（模块自身拒绝伪造通过）；无法测量时是
  `measured=false` / `met=null` / `value=null` ＋ 精确 `reason`，**从不写 0 充数**。
- 套件从不渲染 harness、从不启动 RTL、从不写入被声明的运行目录；唯一的可选写入是
  `--invoke-assertion-classes` 把只读 CLI 的断言分类报告写进 `--scratch-dir`。

## 2. 真实联合结果

精确命令（工作目录 `/home/qinkejiu/myfuzz`）：

```bash
PYTHONPATH=src python3 scripts/run_p5_acceptance_suite.py \
  --run chain_acceptance=runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --run long_search=runs/current-dataflow-p5-chain-600s-20261007-online \
  --run paired_continuous=runs/current-dataflow-p5-paired-20261007-online@runs/current-dataflow-p5-paired-20261007-cold-start \
  --run fault_calibration=runs/current-dataflow-p5-fault-calibration-20261007-online@runs/current-dataflow-p5-fault-calibration-20261007-reproduce \
  --run fault_family=runs/current-dataflow-p5-fault-family-all-20261007-online@runs/current-dataflow-p5-fault-calibration-20261007-reproduce \
  --run heterogeneous_uart=runs/p5-uart-gate2-20261007-online \
  --artifact long_search=replay=runs/current-dataflow-p5-final-20261007-logs/chain_600s_replay.log \
  --artifact paired_continuous=replay=runs/current-dataflow-p5-final-20261007-logs/paired_continuous_replay.log \
  --artifact heterogeneous_uart=replay=runs/current-dataflow-p5-final-20261007-logs/p5_uart_gate2_replay.log \
  --artifact heterogeneous_uart=assertion_classes=runs/p5-acceptance-suite-20261008-logs/assertion_classes-p5-uart-gate2-20261007-online.json \
  --json-out runs/p5-acceptance-suite-20261008-logs/p5_acceptance_suite.json \
  --markdown-out runs/p5-acceptance-suite-20261008-logs/p5_acceptance_suite.md \
  --reports-dir runs/p5-acceptance-suite-20261008-logs/reports
# stderr: p5 acceptance suite: exit=0 ready=True critical=6/6 no_proving_run=[]
```

运行耗时 0.85 秒（全部为已保存产物的 JSON 解析；断言分类报告调用 CLI 是**一次性**的只读步骤，见 §4）。

### 2.1 联合表（关键项 × 证明运行）

| 关键项 | measured | met | 证明运行（proving_runs） | 测到但未成立 | 未测量 |
|---|---|---|---|---|---|
| `assertion_classes_separated` | true | true | `chain_acceptance`, `fault_calibration`, `heterogeneous_uart` | — | `fault_family`, `long_search`, `paired_continuous` |
| `controlled_fault_caught_and_reproduced` | true | true | `fault_calibration`, `fault_family` | — | `chain_acceptance`, `heterogeneous_uart`, `long_search`, `paired_continuous` |
| `normal_control_has_no_finding` | true | true | `chain_acceptance`, `fault_family`, `long_search`, `paired_continuous` | `fault_calibration`（自身带 `dut_violation`，非控制枝）, `heterogeneous_uart`（带 `uncertain_effect`，非干净控制） | — |
| `complete_prefix_saved_and_identity_refused_before_start` | true | true | `chain_acceptance`, `heterogeneous_uart`, `long_search`, `paired_continuous` | `fault_calibration`（该运行目录内无 fresh replay 文档）, `fault_family`（家族根无身份/重放文档） | — |
| `ten_minute_search_reports_chains_and_replay` | true | true | `long_search` | `chain_acceptance`（31.27 秒 < 600 秒下限） | `fault_calibration`, `fault_family`, `heterogeneous_uart`, `paired_continuous` |
| `same_budget_continuous_beats_per_case_restart` | true | true | `paired_continuous` | — | `chain_acceptance`, `fault_calibration`, `fault_family`, `heterogeneous_uart`, `long_search` |

> 说明：`normal_control_has_no_finding` 的"测到但未成立"行指**该运行自己不是干净控制枝**（故障根带
> `dut_violation`，UART 根带 `uncertain_effect`），不是判据失败被隐藏；它们照常出现在 `not_met_by` 里。

### 2.2 逐运行判定（角色一致性也逐条报告）

| 角色 | 运行目录 | 角色产物匹配 | 关键项 met | `exit_code` |
|---|---|---|---|---|
| `chain_acceptance` | `runs/current-dataflow-p5-chain-acceptance-20261007-online` | true | 3/6 | 2 |
| `long_search` | `runs/current-dataflow-p5-chain-600s-20261007-online` | true | 3/6 | 2 |
| `paired_continuous` | `runs/current-dataflow-p5-paired-20261007-online`（`@` 冷启动枝） | true | 3/6 | 2 |
| `fault_calibration` | `runs/current-dataflow-p5-fault-calibration-20261007-online`（`@` 复现根） | true | 2/6 | 2 |
| `fault_family` | `runs/current-dataflow-p5-fault-family-all-20261007-online`（`@` 复现根） | true | 2/6 | 2 |
| `heterogeneous_uart` | `runs/p5-uart-gate2-20261007-online` | true | 2/6 | 2 |

六个声明的角色**全部**与其产物匹配（`role_evidence.missing=[]`）。若某个声明角色缺少该角色应有的产物，
套件仍会把它列入 `runs`/`role_evidence` 并写明缺哪些键——**报告，不静默跳过**。

## 3. 每个关键项读哪些确切产物键

| 关键项 | 读取的确切产物/键 | 成立条件（摘要） |
|---|---|---|
| `assertion_classes_separated` | `p5_assertion_classes.v1` 的 `assertion_classes.{protocol_checker,cross_component_provenance_and_order,cpu_ip_behaviour}`、`not_silently_filtered.{abnormal_record_count,represented_record_count,unrepresented,gate}`、`engine.module.sha256`、`trace.semantic_sha256`；运行侧 `online_run_identity.json:identity.trace.semantic_sha256` | 三节各自自述且计数为整数或 `null`+`finding_count_reason`；`gate.passed=true` 且 `exit_code=0`；`unrepresented=[]` 且 `represented==abnormal`；`engine.module.sha256` 等于**当前** `myfuzz.scenario.assertion_classes` 的 sha256；报告 trace 语义 sha 与运行身份一致 |
| `controlled_fault_caught_and_reproduced` | `minimal_replay.json:{calibration_only,observation_boundary,findings[].detected_by,fault_document_sha256}`、`fault_run_summary.json:violations`、`report.json:{statuses.dut_violation,session_status}`、`fault_document.json:faults[].expected_finding`；复现根 `reproduction_summary.json:{violations,fault_document_sha256,tests,statuses}`；家族根 `fault_family_calibration{,_verify}.json` | `calibration_only=true` 且 `observation_boundary='checker_input_copy'`；`detected_by` 非空且 ⊆ 运行自身 `violations`；`statuses.dut_violation≥1` 且 `session_status='finding'`；复现根 violations 相同且 `fault_document_sha256` 与最小重放一致；家族路径另需 9/9 校准、`verify.ok=true`、0 失败、逐变体 `control_run_clean` 通过且复现根的 `fault_document_sha256` 属于家族 |
| `normal_control_has_no_finding` | 控制枝 `receipts.jsonl`（逐行 `status`/`violations`）、`report.json:{statuses,session_status}`、`failures/*.json`；家族根走 `fault_family_calibration_verify.json` 的逐变体 `control_run_clean`/`control_trace_unchanged` ＋ `fault_family_calibration.json:variants[].source_run.path` 指向的控制运行 receipts | 无 `dut_violation`、`session_status='complete'`、0 条 failure 记录、receipts 无 violation 字符串，且**注入 finding 不出现**在控制枝（联合层要求先有"前件"finding，见 §5） |
| `complete_prefix_saved_and_identity_refused_before_start` | `online_run_identity.json:identity.{artifacts,genome.plan_sha256,trace.{semantic_sha256,manifest_sha256,genome_sha256},session.manifest_sha256,trace_file}`、`report.json:online_run_identity_sha256`、`online_final_trace.meta.json:{semantic_sha256,manifest_sha256,genome_sha256}`、`online_plan.json`/`online_session_manifest.json`/`receipts.jsonl`/`seed.bin` 的文件 sha256、`replay.json|replay.log:{matches,first_difference}` | raw（receipts＋seed＋`corpus/entry_*`）、plan（`genome.plan_sha256 == artifacts['online_plan.json'] ==` 文件 sha）、trace（`trace.manifest_sha256 == session.manifest_sha256`、meta 三者逐字段相等）、manifest（文件 sha 绑定）四项全绑定；`report.online_run_identity_sha256 == envelope.sha256`；replay `matches=true` 且 `first_difference=null`；并给出启动前拒绝机制的模块 sha256 与引用 |
| `ten_minute_search_reports_chains_and_replay` | `first_step_acceptance_report.v1:{effective_search_seconds,certified_chains.{total,cap_reached,by_direction,incomplete_total},certified_chains_per_second,invalid_or_timeout_detail.findings,trace_evidence.semantic_sha256_verified,limits,run_dir}`、`report.json:effective_search_seconds`、`replay.log:{matches,first_difference}` | `effective_search_seconds≥600`；`certified_chains.total` 为整数且 ≥1、`cap_reached=false`；chain/s 为有限数；`findings` 为整数（本次为 0，如实陈述）；trace 语义 sha 复算通过；replay `matches=true`；接受报告与运行自身 `report.json` 的有效秒数一致 |
| `same_budget_continuous_beats_per_case_restart` | 连续枝 `report.json:{elapsed_seconds,effective_search_seconds,tests,statuses}`＋`receipts.jsonl:case_id`；冷枝 `cold_start.json:{case_count,verified_case_count,elapsed_seconds,init_seconds_total,total_seconds_total,comparison_scope,cases[].case_id}`＋`report.json:{wall_clock_seconds,status_mismatch_count,verification_failure_count,continuous_run_dir,continuous_identity_sha256}`；比较器 `paired_efficiency_report.v1:groups.*.{certified_chains_per_second,certified_chains_per_second_reason},paired.certified_chains_per_second_ratio_cold_over_continuous,comparison_validity.{comparable,prerequisites[]}` | 两枝例数相同且 `verified==case_count`；`case_id` 集合相同；冷枝墙钟大于连续枝墙钟（本次 512.881 秒 vs 31.905 秒 ≈ **16.08×**）；`comparison_scope` 已声明；比较器 `comparable=true`、9 项先决条件全满足；并**显式**给出链/s 等价是否可测 |

## 4. 本次判定用到的真实量

- **断言三类**（`heterogeneous_uart`，由只读 CLI 在本轮真实产物上现算）：协议 checker `0`／跨组件来源与顺序 `6`／
  CPU-IP 行为 `85`（记录 1214），异常记录普查 `92/92`、`unrepresented=0`、`gate.passed=true`、引擎 sha 与当前源码一致。
  同一项在 `chain_acceptance` 上是 `0/22/118`（140/140）、在 `fault_calibration` 上是 `1/7/34`（42/42）。
- **受控故障**：`fault_calibration` 命中 `gpio_b_irq_source_mismatch`（2 complete ＋ 1 `dut_violation`，
  `session_status=finding`），标记 `calibration_only=true`／`observation_boundary=checker_input_copy`，
  复现根 `reproduction_summary.json` 同 finding 且 `fault_document_sha256=cd753d419c2860b9…` 与最小重放一致；
  `fault_family` 9/9 变体校准、`verify.ok=true`、0 失败，复现根命中的 `fault_document_sha256` 属于该家族
  （`observation_irq_level`）。
- **干净控制**：`chain_acceptance` 24/24、`long_search` 368/368、`paired_continuous` 24/24，
  三者 `statuses={complete:*}`、0 violation、0 failure 记录；家族根另由复核器逐变体 `control_run_clean` 证明
  两个控制运行（`current-dataflow-p5-paired-20261007-online` 24 例、`p5-uart-gate2-20261007-online` 7 例）不携带家族 finding。
- **完整前缀与启动前拒绝**：四个运行 raw/plan/trace/manifest 四项身份全绑定、`matches=true`；
  拒绝机制引用 `myfuzz.integration.scenario_rfuzz_live._verify_online_run_identity`
  （在 `ibex_pulp_online.replay_pulp_dual_source_online_files` 第 319 行校验、第 328 行才构建 RTL factory）；
  真实拒绝产物为 `runs/current-dataflow-p5-final-20261007-logs/cold-replay-0000.log`
  （`online decode space source identity mismatch: src/myfuzz/scenario/ibex_pulp_dual_source.py (recorded 11a4b307…, current ee0be2b8…)`）、
  `p5_cold_group_replay.json:matches=0`、`cold_replay_summary.json:{"cold_replay_ok":0,"cold_replay_failed":24}`。
  **主体是配对运行的 24 例冷组 replay（同一冻结 bundle 家族），不是被声明的运行本身**——套件在
  `saved_refusal_artifact.subject` 里逐字写明，不冒充。
- **十分钟搜索**：`long_search` 有效搜索 `600.362953` 秒、**27** 条认证链（CPU→IP→CPU 20／IP→CPU→IP 7，跨例 6，
  341 条 incomplete）、`0.0449727950019806` 链/s、**0** 个自然 finding、`matches=true`、trace 语义 sha 复算通过、
  与运行自身报告的有效秒数一致。
- **同预算配对**：连续枝 31.905 秒（有效 30.783 秒）24 例，冷枝墙钟 512.881 秒（逐例初始化合计 449.695 秒，
  均值 18.737 秒/例）24 例且 24/24 校验通过，**16.075×**；比较器 `comparable=true`、9 项先决条件全满足；
  链/s 等价 **不可测**：`paired.certified_chains_per_second_ratio_cold_over_continuous.value=null`，
  原因 `trace events are unavailable, so no certificate could be derived`（冷枝无聚合 trace）。

## 5. 边界（套件不证明什么）

0. **本轮后续更新（2026-10-08，父级补记）**：边界 1 的两个 UART 运行现已被一个**更新的真实运行**
   `runs/p5-uart-routing-gate-20261008-online` 取代为 `heterogeneous_uart` 角色（同 cache／同 seed
   `20261007`／同预算）：60 例（57 complete ＋ 3 预 RTL `input_invalid`）、79.934 有效秒、
   **fresh replay `matches=true`**，且 `report.json` 首次自带 `source_target_transactions`
   （`online_source_target_transactions.v1`；门禁决策日志 `{count:24, admitted:21, refused:3}`）。
   联合判定仍为 **6/6、exit 0**，`normal_control_has_no_finding` 的证明运行多了 `paired_cold_start`
   （判据侧新增 `DECLARED_SESSION_STATUS_FIELDS`）。**边界 1 的结论不变**：UART 侧仍**没有 ≥600 秒长会话**，
   所以 `ten_minute_search_reports_chains_and_replay` 仍**只由** `long_search`（Ibex＋双 PULP GPIO）证明。
   另外 UART 侧完整链证书已由只读生产者补齐（7 certified／30 incomplete，见
   [UART 链路证书](current-dataflow-p5-uart-chain-certificates-20261008.md)），但它**不在本套件的六项判据里**，
   因为它读的是产物能力而不是运行自己的证书流。

1. **异构外设长会话仍无真实运行（P5 唯一仍缺真实运行的分项）**。联合表里
   `ten_minute_search_reports_chains_and_replay` **只有** `long_search`（Ibex＋双 PULP GPIO）证明；
   异构 UART 一侧有两个运行、都不是长会话：
   - `runs/p5-uart-gate2-20261007-online`：7 例（6 complete ＋ 1 `uncertain_effect`）、有效 9.43 秒，
     第 7 例停在既有能力限制 `RuntimeError: TL-UL access during serial source waveform is unsupported`
     （即 **RX 串行波形进行中 CPU 发起 TL-UL MMIO 访问不被 UART session 支持**）；
   - `runs/p5-uart-waveform-gate-20261008-online`（本轮新产物，套件未声明为 `heterogeneous_uart`，避免两个角色重名）：
     60 例、有效 86.07 秒、57 complete ＋ 3 例预 RTL `input_invalid`、认证链 0——**仍不足 600 秒**。
   因此本文**不声称** P5 的"至少一种不同协议/行为的真实外设"长会话子主张成立；套件也把这条缺口写进
   自身 `boundaries`（"the declared heterogeneous_uart run proves no >=600 effective-second chain run …"）。
2. **联合 ≠ 单运行通过**：六个关键项分散在至少四个运行上，单运行上限 3/6；套件 `boundaries` 明写这一点。
3. **受控故障项全部是注入校准**，不是自然 RTL 缺陷；"捕获"只说明既有 checker 不变量对该注入有效，
   不构成检测灵敏度或覆盖率结论；`verify` 不重跑 RTL。
4. **十分钟链/s 的语义**：27 条是注入生产者按该产物能认证的 `certificate_id` 数，341 条 incomplete 明确点名首个缺口；
   它陈述产物能力，不证明 DUT 在该窗口内确实完成了 27 次传播。
5. **同预算项只证明墙钟/有效用例的对照与"链/s 等价不可测"**：`cold_start.json:comparison_scope`
   自述 `startup_cost_only_not_coverage_equivalence`，比较器明确 `coverage_hex` 22/24、`local_ticks` 15/24 不同，
   故不主张输出等价、覆盖率等价或故障发现等价。
6. **身份拒绝的真实产物属于冷组 replay（同一 bundle 家族）**，不是被声明运行自身；plan/manifest/artifact 摘要
   一类拒绝目前只有代码路径与调用顺序（校验先于 factory 构建），**没有**保存下来的负例回执。
7. **断言分类项只证明"三类分开报告 ＋ 异常普查 fail-closed ＋ 引擎版本一致"**，不证明 finding 是真阳性；
   `long_search`/`paired_continuous`/`fault_family` 三个运行没有 `p5_assertion_classes.v1` 产物，
   套件对它们如实报 `measured=false` 并给出 CLI 复算方式。600 秒运行的断言分类现算**过慢**：
   本轮尝试 `report_p5_assertion_classes.py --run runs/current-dataflow-p5-chain-600s-20261007-online`
   10 分钟未完成被终止（172 MB zlib／570,196 事件需逐块解压并复算语义 sha），故不把它计入本次判定；
   这是一条入口使用边界，不是判据放宽。
8. **`--reports-dir` 的逐运行文档**在判定上与套件内 `runs[]` 逐字段一致（items/exit_code/value/evidence/reason），
   但 `resolution_notes` 可能更少：导出的文档**钉住**套件已解析的产物路径，因此不再产生"跳过别的候选"的检索记录。
9. **套件读不到的东西**：`fault_family` 家族根、`fault_calibration` 故障根的 `normal_control` 分别由复核器/自身
   状态判定；任何运行若既没有控制枝也没有家族复核器，该关键项对它是 `measured=false` ＋ 原因，不会静默算过。

## 6. 复算与测试

```bash
cd /home/qinkejiu/myfuzz
# 定向测试（TDD：先 RED 再 GREEN，48 项）
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_acceptance_suite.py -q -p no:randomly
# RED（同一测试文件、模块尚不存在时）：ModuleNotFoundError: No module named 'myfuzz.scenario.p5_acceptance'
# 日志：runs/p5-acceptance-suite-20261008-logs/pytest-red.log / pytest-green.log
```

覆盖：六个关键项在**合成但真实形状**产物上的逐项判定；`measured=false`＋原因（不写 0）路径；
退出码 0/2/1 语义；两个运行各证明一部分的**联合**逻辑；控制项必须有"前件 finding"才可测；
共享证据库**不得**为无运行绑定的产物（如裸 `replay.log`）提供服务；schema 不符的候选被跳过；
比较运行不得顶替被声明运行自身的产物；家族根的控制证据与复现 sha 归属；`--artifact` 声明与坏声明；
两次运行 **byte-identical JSON**（CLI `--json-out` `cmp` 相同）。

产出物：

- 联合文档 `runs/p5-acceptance-suite-20261008-logs/p5_acceptance_suite.json`（含每个运行的完整
  `p5_acceptance_report.v1`、逐项 `measured/met/value/evidence/reason`、`proving_runs`、`role_evidence`、`boundaries`）；
- 联合表 `runs/p5-acceptance-suite-20261008-logs/p5_acceptance_suite.md`；
- 逐运行报告 `runs/p5-acceptance-suite-20261008-logs/reports/report-<role>.json`；
- 本轮现算的断言分类报告 `runs/p5-acceptance-suite-20261008-logs/assertion_classes-p5-uart-gate2-20261007-online.json`。

**没有证明运行的关键项：无**（`no_proving_run=[]`、`critical_unmet=[]`）。文档自述的引擎版本与命令文件
（可逐字段复算）：`myfuzz.scenario.p5_acceptance` =
`6305b0cb5ecb9e1e85d37c3c596a75c71c5595c45bd5a37f5637f4e0c26a4be7`，
`myfuzz.scenario.assertion_classes` =
`7b2530b104f810b0e6485ea6299acf100cedb4a98e21e6284b704935ec1b6608`，
CLI `scripts/run_p5_acceptance_suite.py` =
`8b44277816c69379b9c1e288fb3d9e965da162329c0745f030f073963a63af62`。
