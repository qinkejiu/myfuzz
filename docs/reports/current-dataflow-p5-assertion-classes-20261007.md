# P5 断言分类报告：协议检查器、跨组件来源/顺序、CPU/IP 行为分别计数

日期：2026-10-07。本报告落实 P5 清单条目「用协议检查器、跨组件来源/顺序不变量及
CPU/IP 行为断言**分别**报告问题；生成约束和检查期望**分开**，异常真实输出不能因
路径未就绪被过滤」（`docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md`）。

**软件产物，本轮不跑 RTL。** 全部数字来自已保存运行目录的只读重算：不渲染 harness、
不启动进程、不执行任何 Verilator/工厂调用。报告中的「真实」只表示「已保存的真实运行
产物」，不表示本轮新跑了 RTL。

## 1. 交付物

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/assertion_classes.py` | 新分析模块，schema `p5_assertion_classes.v1`；一次流式读取一个已保存运行目录 |
| `scripts/report_p5_assertion_classes.py` | 新 CLI：`--run <保存目录> --out <json>`；退出码 `0` 通过 / `2` 门禁失败（报告仍写出）/ `1` 无可流式 trace（不写文件） |
| `tests/scenario/test_p5_assertion_classes.py` | 18 项 TDD 测试（合成工件 + 一条真实运行用例） |
| `runs/current-dataflow-p5-assertion-classes-20261007-logs/*.json` | 三个真实运行的机器可读报告 |

模块只 import 已冻结的消费者，不重新实现任何一条 join：

* `scenario/edge_provenance.py`：`EdgeProvenanceConsumer` / `edge_provenance_session`（`runtime_edge_provenance.v1` / `runtime_edge_provenance_report.v1`）；
* `scenario/chain_certificates.py`：`ChainCertificates`（`runtime_chain_certificate.v1`）；
* `scenario/acceptance_metrics.py`：`TraceEventStream`（压缩/整文件两种 trace 格式）与回执状态词表（只读 import）。

## 2. 三类断言：分别计数、分别列举

文档顶层 `assertion_classes` 恰好三个键，互不合并：

| 类 | 数据来源 | `finding_count` 语义 |
|---|---|---|
| `protocol_checker` | 回执 `receipts.jsonl[].violations` + 清单中的 checker 身份 | 该运行自己的 checker 返回的违规条数；有回执但零违规＝**实测 0** |
| `cross_component_provenance_and_order` | `runtime_edge_provenance_report.v1` 的声明边 + `runtime_chain_certificate.v1` 的链证书 | 非 certified 的边（`incomplete`/`unknown`）、`not_a_runtime_edge` 声明跳、incomplete 证书、消费者拒绝记录之和 |
| `cpu_ip_behaviour` | 同一 trace 中的退休/IRQ/消费记录 | 异常 CPU/IP 行为记录条数；**本运行没有任何此类记录时是 `null` + 明确原因，绝不是 0** |

每条 finding 自带 `assertion_class`、`record_class`、`expectation_id`、`record_id` 与
`evidence`（精确键，不使用事件相邻关系）：

* 协议：`receipt_index`、`case_id`、`violation`、`status`、`candidate_disposition`；
* 跨组件边：`rule_index`、`prerequisite_index`、`relation`、`status`、`missing[]`、`hop_ids[]`、`hop_event_ids[]`、`reason`、`directions[]`、`path_ids[]`；
* 链证书：`certificate_id`、`direction`、`source_admission_id`、`source_case_index`、`missing_hops[]`、`first_missing_hop`、`hop_ids[]`、`hop_event_ids[]`、`serial_token_status`、`reason`；
* CPU/IP：`event_id`、`retirement_event_id`、`insn`、`pc`、`order`、`trigger_id`/`source_event_id`、`observation_event_ids[]`、`acceptance_event_ids[]`、`expected_input`/`actual_post_input`、`mask_observation`。

跨组件类同时给出**声明边的完整状态表**（`edge_status.edges`）：certified 边也逐条列出
状态、有序 hop 与 hop 事件号，incomplete/unknown 边额外给出精确 `missing` 与消费者
`reason`；`chain_certificates.incomplete_certificates` 逐条列出 incomplete 证书的
`missing_hops` 与首个缺口。

## 3. 生成约束 vs 检查期望（分节，键不重叠）

* `declaration_constraints`：运行**被生成**成做什么——`decoder_manifest`（含 sha256、`flow_by_target`、允许的 MMIO 操作、声明图边数）、`runtime_path_contract`（合同身份 sha256、`proof_scope`/`runtime_causality_verified`/`resource_versions_verified`、逐路径 `declared_hop_count`/`runtime_hop_count`/`not_a_runtime_edge_hop_count`、逐声明边）、`declared_targets`、`run_identity`、`plan`。
* `check_expectations`：**检查器断言**什么——运行自己的 checker 身份（module/qualname/源码 path+sha256），以及 9 条 `expectation_id`（协议 1 条、跨组件 2 条、CPU/IP 6 条），每条写明 `asserts` 与 `declared_by`（引用冻结模块中的规则原文，例如 `chain_certificates` 的 `instruction_origin_status == 'typed_writer_refs'`）。

测试断言两节键集合不相交，且每条 finding 的 `expectation_id` 必在期望表中。

## 4. 失败关闭：异常真实输出不会被「路径未就绪」吞掉

`not_silently_filtered` 用一份**普查（census）**驱动，而不是计数器自证：

1. 普查枚举运行中每一条异常记录：`not_a_runtime_edge` 声明跳、`runtime_edge_incomplete`、
   `runtime_edge_unknown`、`edge_provenance_rejection`、`chain_certificate_incomplete`、
   协议违规、`case_refused_before_rtl`（在**任何 RTL 命令之前**被拒的候选，带 `code`/`pointer`/
   `rtl_command_observed`）、`case_uncertain`、`case_unfinished`、环境错误、`case_error`、
   时钟截断，以及全部 CPU/IP 异常记录（退休被拒、退休来源未定型、IRQ 未被接受、IRQ 脉冲
   到期未被接受、期望输入不符、消费断言缺键）。
2. 每条普查记录的 `record_id` 被结构性回查：报告组装完成后，从 `assertion_classes[*].findings`
   与 `cases_refused_before_rtl` 等分桶里实际取出 `record_id` 做集合比对。渲染器掉一条记录，
   门禁就以「记录 id + 期望位置」失败——门禁不可能靠一个与文档不一致的计数通过。
3. 无法归类的异常记录（未知 `candidate_disposition`、词表外 `status`、`finding` 状态却没有违规
   串、`cpu_retirement_match` 的未知状态）直接记为 `unclassified_abnormal_record` 并**使门禁
   失败**（退出码 2），而不是静默丢弃。
4. `--max-findings-per-class N` 截断时，被截掉的记录变成 `truncated_finding` 并同样使门禁失败。

节内同时给出 `not_ready_declared_paths`（`not_a_runtime_edge` / `incomplete` / `unknown` 三个
视图）、`cases_refused_before_rtl` 与声明句：*these were reported, not dropped because a declared
path, edge or hop was not ready*。

## 5. 真实保存运行结果（只读重算）

命令（对每个目录只读执行一次）：

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/report_p5_assertion_classes.py \
  --run runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --out runs/current-dataflow-p5-assertion-classes-20261007-logs/acceptance.json
```

| 运行 | 事件 | `protocol_checker` | `cross_component…` | `cpu_ip_behaviour` | 异常/已表示 | 门禁 |
|---|---:|---:|---:|---:|---:|---|
| `current-dataflow-p5-chain-acceptance-20261007-online` | 31,795 | **0**／24 回执（checker `IbexPulpOnlineChecker`） | **22**（6 `not_a_runtime_edge` + 16 incomplete 证书） | **118**／1308 记录 | 140／140 | 通过 (0) |
| `current-dataflow-p5-fault-calibration-20261007-online` | 5,858 | **1**／3 回执（`ControlledFaultFamily`：`gpio_b_irq_source_mismatch`，`dut_violation`） | **7**（6 + 1 incomplete 证书） | **34**／259 记录 | 42／42 | 通过 (0) |
| `current-dataflow-p4-rejection-calibration-20261007-online` | 2,549 | **0**／14 回执 | **16**（6 + 1 incomplete 边 + 2 unknown 边 + 7 incomplete 证书） | **`null`**／0 记录（原因：无 CPU/IP 行为记录） | 24／24 | 通过 (0) |

分项（验收运行）：

* 边状态：声明 15 跳／合同 9 边；certified 9、incomplete 0、unknown 0、`not_a_runtime_edge` 6
  （CPU 方向 3：规则 1/3/7；IP 方向 3：规则 8/9/14）。链证书 certified 8、incomplete 16，
  首个缺口分别为 `instruction_fetch`（6 条）与 `pin8_injection`（10 条）。
* CPU/IP 记录：退休 194、退休匹配 194、IRQ 采样 821、IRQ 接受 10、IRQ 输入 28、IRQ 到期 7、
  原生 IRQ 观测 14、消费匹配 40。异常 finding 118 = 来源未定型 84 + 退休被拒（
  `unsupported_instruction_observation_only`）30 + 原生 IRQ 观测无同源 CPU 接受 2 +
  IRQ 脉冲到期无接受 2。IRQ 实例 7 个观测、5 个被接受，未接受 2 个 —— 与既有 P2 验收报告的
  `early_irq` 结论（2/7）逐项一致。
* 被拒运行（rejection-calibration）演示「路径未就绪不被过滤」：**7 例在任何 RTL 命令之前被拒**
  （`mmio.bad_width`、`ownership.bound_input`、`ownership.fixed_input`、`mmio.window_denied`、
  `decode.unbounded_input`、`budget.exhausted`、`mmio.no_aligned_address`）＋1 例
  `uncertain_effect`，全部带 `code`/`pointer` 逐条列出，门禁仍通过（无一条被丢弃）。
  该运行还暴露一处**词表分歧**：生产写入方 `integration/scenario_rfuzz.py` 写
  `status="input_invalid"`，而冻结的 `acceptance_metrics.INVALID_STATUSES` 只列
  `invalid_input`；本报告按自己的词表分类并把分歧写进 `limits`，而不是把回执丢掉。

确定性：对 `current-dataflow-p5-fault-calibration-20261007-online` 连续两次 CLI，
输出 sha256 均为 `63261b7a6880b2c3dfcd299d4dcd795c891ccc9618b5ea3be7dc35a440ad59d1`（逐字节相同）。

## 6. 测试（先 RED 后 GREEN）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_assertion_classes.py -q -p no:randomly
```

* RED（先写测试，模块尚不存在）：
  `ImportError … ModuleNotFoundError: No module named 'myfuzz.scenario.assertion_classes'`
  → `1 error in 0.13s`（exit 2）。
* GREEN（实现后）：`18 passed in 23.2s`（约 21 秒来自那一项真实运行用例）。

覆盖：三类分别计数且只带各自的证据键；`null`+原因（协议缺 `receipts.jsonl`、跨组件缺清单、
CPU/IP 无记录）与**实测 0** 的区分；声明/期望分节；fail-closed 负例（未知 `candidate_disposition`
→ 门禁失败并给出回执序号与原因；`--max-findings-per-class` 截断 → 门禁失败）；`uncertain_effect`
不被误报为 refused；CLI 两跑逐字节相同与退出码 0/2/1。相邻模块回归
（`test_edge_provenance.py` + `test_cross_case_chains.py` + `test_chain_certificates.py`）：107 passed。

## 7. 边界：本门禁**不**证明什么

* **不证明 RTL 正确性**。所有结论都来自已保存产物；没有本轮新 RTL、没有 harness、没有进程。
* **不证明链终点回流**。跨组件类只复算已冻结的边/证书语义；ISR 写 GPIO A 之后的回流仍不在
  证书终点内（与既有 P5 报告一致）。
* **`cpu_ip_behaviour` 不是 DUT 断言通过率**。「退休来源未定型 84／退休被拒 30」是**该运行
  真实写下的记录分类**，其中 `unsupported_instruction_observation_only` 是观测合同无法解码的
  退休，不等于 DUT 出错；本门禁只保证它们被如实报出，不给出 pass/fail 判定。
* **`not_a_runtime_edge` 不是缺证据**。这 6 跳在编译后的运行时合同里本来就没有可观测关系
  （`EVENT_ORDER`/`ENV_PRECONDITION`/因果序），报告只声明「该跳没有运行时 join」，不声称链断。
* **缺失工件 ≠ 记录被丢弃**。`receipts.jsonl` 或清单缺失时对应类报 `null`+原因，门禁仍按
  「运行中存在的记录是否被表示」判定；此时普查范围本身不完整，报告在 `limits` 里写明——
  这是本门禁的**已知盲区**，不能读成「该运行没有异常」。
* **一次只读一个运行目录**。不做跨运行配对、不做覆盖率/吞吐/链率比较；这些属于 P5 其他条目。
* **十分钟运行未完成**：`runs/current-dataflow-p5-chain-600s-20261007-online`（570,196 事件）
  的 CLI 重算在两个冻结消费者上超过本次时间盒被中止，**本报告不为它给出任何数字**；
  它需要的是一次更长的只读窗口（或更小的 `--max-pending`/`--edge-max-event-gap` 预算下的
  有界重算），而不是新的 RTL。
* 验收运行的 `semantic_sha256_verified = true` 只说明 trace 字节与声明摘要一致，不说明事件
  语义正确。
