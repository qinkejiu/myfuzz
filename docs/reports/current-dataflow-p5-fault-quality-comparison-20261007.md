# P5 受控故障**同条件质量对照**（`p5_fault_quality.v1`）

- 日期：2026-10-07
- 对象：`runs/current-dataflow-p5-fault-family-20261007-online`（单变体完成根）与
  `runs/current-dataflow-p5-fault-family-all-20261007-online`（9 变体全量根）
- 对应清单项：P5「对已保存场景做受控故障注入 … checker 应给出失败、来源链、
  最小可重放输入。注入仅校准检测链，报告中独立标注」以及仍未闭合的
  「同条件故障**质量**对照」
- 性质：**只读、calibration-only**。不跑 RTL/Verilator/fuzz，不重放，不写任何
  校准根目录；注入 finding 一律不是自然 DUT 缺陷。

## 1. 交付物

| 文件 | 作用 |
| --- | --- |
| `src/myfuzz/scenario/p5_fault_quality.py` | 新模块（`p5_fault_quality.v1`）：只读分析一个已完成校准根，逐变体产出检测 / 注入边界 / 可重放材料 / 同条件，并按四个故障类汇总 |
| `scripts/compare_p5_fault_quality.py` | 新 CLI（薄封装；默认把文档打印到 stdout，`--output` 落盘，两次运行逐字节相同） |
| `tests/scenario/test_p5_fault_quality.py` | 新测试（27 条，先写后实现，含合成校准根、拒绝路径、确定性） |
| `docs/reports/current-dataflow-p5-fault-quality-comparison-20261007.md` | 本报告 |

在线运行路径没有任何文件被修改（`git status --short` 只显示上述新文件为 `??`）。

## 2. 运行方式与退出码

```bash
# 单变体根
PYTHONPATH=src python3 scripts/compare_p5_fault_quality.py \
  --calibration-root runs/current-dataflow-p5-fault-family-20261007-online --quiet \
  --output /tmp/q-single.json
# 9 变体全量根
PYTHONPATH=src python3 scripts/compare_p5_fault_quality.py \
  --calibration-root runs/current-dataflow-p5-fault-family-all-20261007-online --quiet \
  --output /tmp/q-all.json
```

退出码：`0` 全部已分析变体 calibrated 且完整性检查全过；`1` 参数/路径/必需输入
缺失或不可解析（拒绝，stderr 精确原因）；`3` 完整性通过但有变体从未校准；
`4` 测量到不一致（锚点数据流字段、摘要连接等）。

实测：

| 根 | 退出码 | 文档字节 | 文档 sha256 | 两次运行逐字节相同 |
| --- | --- | --- | --- | --- |
| `…-fault-family-20261007-online` | 0 | 31532 | `2ada5c9c5e098a4b0dab48b3c17322a9399ffce919db90fa7170de4083aae2ff` | 是 |
| `…-fault-family-all-20261007-online` | 0 | 233353 | `0f8d5eadaeb4da109559da9871b71dbd0b351064ca14ef0e5c5ea913497e6696` | 是 |

拒绝路径实测：`--variant no_such_variant` → `exit=1`，
stderr `p5-fault-quality-error: unknown variant 'no_such_variant'; known variants: …`。

输入现状（用于钉住本次读数）：

| 根 | 汇总 `fault_family_calibration.json` sha256 |
| --- | --- |
| 单变体根 | `bc43ada75225c4bf229e6e7807dcf1ec3556a6036f494088bb59d270c8443eeb` |
| 全量根 | `7f388cc1a5592ac0ba8454b30df39ccbf9eebe31e4d49518fee608777a636bb4` |

## 3. 测试证据（RED → GREEN）

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_p5_fault_quality.py -q -p no:randomly
```

- **RED（实现前）**：`ImportError: cannot import name 'p5_fault_quality' from
  'myfuzz.scenario'`（收集阶段 1 error）。
- **GREEN**：`27 passed`；与既有校准运行器测试同跑：
  `PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_fault_quality.py
  tests/scenario/test_p5_fault_family_calibration.py -q -p no:randomly`
  → `52 passed, 18 subtests passed in 5.85s`。
- **非空测试证明（变异检查）**：临时把 `classify_path()` 改成恒返回 `dataflow`、
  并把 `digest_equal` 短路为 `True` 后，同一套测试出现 5 条失败
  （锚点身份分类、摘要不匹配、汇总与退出码），恢复后 `27 passed`——测试确实
  压在实现行为上，不是空断言。

测试覆盖：合成但同形的校准根逐变体提取；控制/故障锚点逐字段相等（含身份字段
分类）与其数据流字段不一致时的失败；缺失锚点事件 / 缺失 `receipts.jsonl` /
缺失 `minimal_replay.json` / 缺失汇总 / schema 漂移 / `expected_finding` 契约漂移
的**拒绝**；摘要连接与其不匹配；四个故障类的计数；窗口级差异分解；source_files
差异清单；`calibration_only` 标记与声明；两次运行逐字节相同；CLI 退出码 0/1/3/4。

## 4. 真实读数

### 4.1 全量根（9/9 calibrated）

汇总（`rollup`）：`total=9, calibrated=9, not_fired=0, error=0,
no_witness_window=0, selected=0, detected=9, boundary_ok=9,
reproducibility_ok=9, same_condition_degraded=9`，`never_calibrated=[]`，
`ok=true`，退出码 0。

| 变体 | 故障类 | 状态 | 检测（期望 finding / 命中 case / 收据状态 / family finding_id） | 注入边界（锚点事件 / 数据流差异 / 身份差异 / tick / 被扰动字段测量） | minimal replay 摘要连接 | 窗口差异（事件 / 原始 / 仅身份 / 身份摘要叶 / 其它数据流叶） |
| --- | --- | --- | --- | --- | --- | --- |
| `observation_irq_level` | wrong_irq | calibrated | `gpio_b_irq_source_mismatch` / `online-2-604caae5c07e4c776cb357d1` / `dut_violation` / `…wrong_irq_811af21cfe464eab` | `[4609,4610]` / 0 / 4 / `source_tick 131=131=131` / `outputs.irq` 原值 1，注入 0，控制 1，故障 1 | `true`，`cd753d419c2860b94f302a672c90a17f8da3fbdef5ea5d1f1158419db03304d6` | 80 / 149 / 69 / 372 / 67 |
| `cpu_irq_input_bit` | wrong_irq | calibrated | `cpu_irq_pulse_input_mismatch` / 同上 case / `dut_violation` / `…wrong_irq_71b6ab341cafc3d0` | `[4611,4612]` / 0 / 4 / `local_tick 120=120=120` / `inputs.irq` 原值 1，注入 0，控制 1，故障 1 | `true`，`0556ad7bf7558be2bf82af66acacba7f5037ef21740690770c0b9910239a1475` | 80 / 149 / 69 / 372 / 67 |
| `cpu_response_data` | wrong_read_data | calibrated | `cpu_gpio_b_padin_response_mismatch` / 同上 case / `dut_violation` / `…wrong_read_data_8e4e1afb10a759ad` | `[5560,5569]` / 0 / 8 / — / `outputs.data_rsp_rdata` 原值 262，注入 263，控制 262，故障 262 | `true`，`d7f368fa1b43a63264ac40da2b10c712b1c10ff3aeb625d0d84b7a887c2aa10b` | 80 / 149 / 69 / 372 / 67 |
| `delivery_read_data` | wrong_read_data | calibrated | `cpu_gpio_b_padin_response_mismatch`（另有 `gpio_b_padin_read_mismatch`、`cpu_gpio_b_padin_store_mismatch`）/ 同上 case / `dut_violation` / `…wrong_read_data_6f20049281563513` | `[5560,5569]` / 0 / 8 / — / `read_value` 原值 262，注入 263，控制 262，故障 262 | `true`，`0f0430572ea5659655bc494e246e863d4425d8e457aeb4e734e4fbc4f529d61b` | 80 / 149 / 69 / 372 / 67 |
| `uart_cpu_response_data` | wrong_read_data | calibrated | `cpu_uart_rxdata_response_mismatch` / `online-1-819b265ed890cbfc934efd3e` / `dut_violation` / `…wrong_read_data_52714906e3f41ba7` | `[13712,13737]` / 0 / 0 / — / `outputs.data_rsp_rdata` 原值 90，注入 91，控制 90，故障 90 | `true`，`f81cbadadef085a36f768a87c90a1e05d97dad9848ce68fbebddc65d6faa6a8f` | 0 / 0 / 0 / 0 / 0（整窗逐字节相同） |
| `irq_pulse_resubmission` | duplicate_submission | calibrated | `cpu_irq_pulse_input_mismatch` / `online-2-…` / `dut_violation` / `…duplicate_submission_53a6d1201bbf42ec` | `[4611,4779]` / 0 / 4 / `local_tick 124=124=124` / 声明计数语义：`pulse_start` 计数 1=1 | `true`，`dff747d341172f79ab0958d97e639b42dfadcb181e049dee6f2327d6d905f3f6` | 80 / 149 / 69 / 372 / 67 |
| `mmio_delivery_replay` | duplicate_submission | calibrated | `cpu_gpio_b_padin_response_mismatch`（另有 2 条）/ `online-2-…` / `dut_violation` / `…duplicate_submission_77666841aae31fc1` | `[5560,5569]` / 0 / 8 / — / `read_value` 原值 262，注入 263，控制 262，故障 262；`mmio_delivery` 计数 1=1 | `true`，`7ac2b3005a2171a58adc17ac0d3ddc886a9e4420ee1357bf82f91c161f4c9106` | 80 / 149 / 69 / 372 / 67 |
| `delivery_value` | broken_binding_value | calibrated | `gpio_a_to_b_delivery_mismatch` / `online-0-af5570f5a1810b7af78caf4b` / `dut_violation` / `…broken_binding_value_b7ed472b5bbe557d` | `[2225,2226]` / 0 / 2 / — / `value` 原值 0，注入 1，控制 0，故障 0 | `true`，`966256bc7e393ff2e63feca89552e89f832b7403d239d0a05ce41c58f3755b54` | 76 / 140 / 64 / 266 / 0 |
| `bound_input_value` | broken_binding_value | calibrated | `gpio_b_bound_input_mismatch` / `online-0-…` / `dut_violation` / `…broken_binding_value_c6f8d9ea8348e75e` | `[2226,2229]` / 0 / 2 / — / `inputs.gpio_in` 原值 0，注入 1，控制 0，故障 0 | `true`，`ddb9f48243d7694a56b84bb8c77e27d9eb567705fd59288a00693aa155d6a16a` | 76 / 140 / 64 / 266 / 0 |

按故障类汇总（`fault_class_rollup`）：

| 故障类 | 声明数 | 已分析 | calibrated | not_fired | error | no_witness_window | selected | 从未校准 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `wrong_irq` | 2 | 2 | 2 | 0 | 0 | 0 | 0 | — |
| `wrong_read_data` | 3 | 3 | 3 | 0 | 0 | 0 | 0 | — |
| `duplicate_submission` | 2 | 2 | 2 | 0 | 0 | 0 | 0 | — |
| `broken_binding_value` | 2 | 2 | 2 | 0 | 0 | 0 | 0 | — |

> 这里的 0 是**真实计数**：9 个声明变体全部出现在该根里且全部 calibrated。
> `not_fired`/`error`/`no_witness_window` 的计数路径由合成根的测试覆盖
> （`RollupTest`），不会因为本根没有这些状态就退化成常数。

### 4.2 单变体根

`observation_irq_level` 一行与上表完全一致（同一 fixture）；`rollup.total=1`、
`calibrated=1`、`detected=1`、`boundary_ok=1`、`reproducibility_ok=1`、
`same_condition_degraded=1`、`never_calibrated=[]`、`ok=true`、退出码 0。
其余三个故障类的 `analyzed=0` 与 `not_analyzed_variants`（8 个）在同一文档里
明确列出，不会被读成「0 个失败」。

### 4.3 每个变体文档里"建立了什么 / 没建立什么"

以 `observation_irq_level` 为例（`conclusions`，其余变体同构）：

建立：

1. `gpio_b_irq_source_mismatch` 在故障会话 case `online-2-…` 的收据里触发，
   收据状态 `dut_violation`，且故障族自身观测给出
   `finding_ids=['p5_controlled_fault_wrong_irq_811af21cfe464eab']`；
2. 选择器钉住的 2 个锚点事件对照/故障逐字段相等（数据流差异 0，身份字段差异 4
   逐个列出）；记录的故障 trace 在锚点上**仍是原值 1**，注入值 0 未出现；
3. `minimal_replay.json` 存在且 `fault_document_sha256 == fault_document.json`
   的 canonical 摘要 `cd753d41…`。

未建立（逐条写进文档）：

1. **同条件降级**：两次会话的 `runtime_path graph_sha256` 不同
   （`58471d1e…` → `3bfd62f4…`），`runtime path declaration` 有 **78** 个字段不同；
   两次会话钉住的 `source_files` 清单不同（6 个文件，见 4.4）；同一 case 的
   **事件窗口并非逐字段相同**（80 个事件在掩掉逐会话身份字段后仍不同，其中
   **67** 个"其它数据流"叶在同一个事件里，见 4.5）；
2. 不构成对 `wrong_irq` 的检测灵敏度/覆盖率结论（单点见证）；
3. 注入 finding 不是自然 DUT 缺陷，不得并入自然缺陷统计；
4. 本对照不运行 RTL、不重放 `minimal_replay.json`，因此不证明新进程可复现。

### 4.4 「同条件」实测：两次会话的身份与源码清单

| 项 | 8 个 PULP 变体（对照 `runs/current-dataflow-p5-paired-20261007-online`） | `uart_cpu_response_data`（对照 `runs/p5-uart-gate2-20261007-online`） |
| --- | --- | --- |
| `run_id` 相同 | 否（`current-dataflow-p5-paired-20261007` vs `p5-fault-calibration-<variant>`） | 否 |
| `topology_sha256` 相同 | 是（`2f6e0248…`） | 是 |
| `graph_sha256` 相同 | **否**（`58471d1e…` vs `3bfd62f4…`） | 是 |
| `dependency_graph.sha256` 相同 | 否 | 是 |
| `runtime path declaration` 相同 | **否**（78 个扁平字段不同，例如新增 `PERSISTENT_STATE_RULE` 边） | 是（0 个字段不同） |
| `source_files` 清单相同 | **否**：`src/myfuzz/integration/scenario_rfuzz.py`、`src/myfuzz/integration/scenario_rfuzz_live.py`、`src/myfuzz/local_harness/opentitan_uart_session.py`、`src/myfuzz/scenario/cpu_retirement.py`、`src/myfuzz/scenario/ibex_uart_online.py`、`src/myfuzz/scenario/interaction_feedback.py` | **否**：仅前两个文件 |
| 控制 trace 字节未变（对照选择时刻记录的 sha256） | 是 | 是 |
| 同一 case 窗口逐字节相同 | 否 | **是** |

结论（写进文档，而不是靠读者推断）：这 9 个变体的「同条件」只到
**case_id + 事件 ID / tick / 原值 + 锚点事件逐字段** 这一层；控制枝是更早保存的
运行，其源码清单与运行时路径声明都已经和现在的故障会话不同。这不影响
「注入只改 checker 输入副本」的测量（锚点逐字段相等 + 故障 trace 保留原值），
但**不能**把它读成「逐图、逐源码的严格同条件对照」。

### 4.5 窗口级差异分解（`case_window_diff`）

掩掉 `provenance.edge_candidates[*].graph_sha256/path_ids[*]` 后仍不同的事件数
（`differing_event_count`）、原始 canonical 就不同的事件数
（`differing_event_count_raw`）、两者之差（只在身份字段上不同的事件数）、以及差异
叶子的分类计数：

| case | 窗口事件数 | 原始不同 | 掩码后不同 | 仅身份字段不同 | 身份摘要叶（`admission_id`/`path_id`/`origin_admission_ids`） | 其它数据流叶 |
| --- | --- | --- | --- | --- | --- | --- |
| `online-2-604caae5c07e4c776cb357d1` | 1341 | 149 | 80 | 69 | 372 | **67** |
| `online-0-af5570f5a1810b7af78caf4b` | 1140 | 140 | 76 | 64 | 266 | 0 |
| `online-1-819b265ed890cbfc934efd3e` | 1477 | 0 | 0 | 0 | 0 | 0 |

- 身份摘要叶的因果链有据：`admission_id` 是 source admission 材料（含
  `path_id`）的 canonical 摘要（`src/myfuzz/scenario/source_provenance.py`
  的 `_admission_digest`），`path_id` 是每次会话编译出的运行时路径摘要；本次
  `path_id` 从 `3285a03d…` 变成 `7943a650…`，与 78 字段的声明漂移一致。
  该分类只用于**信息性分解**；锚点 gating 仍按严格分类（这些叶子算 dataflow）。
  其材料字段（`action_id`/`case_id`/`component`/`direction`/`input_kind`/
  `input_sha256`/`source_id`/`role`）仍逐字段对照，真实输入变化藏不住。
- 「其它数据流叶 67」全部落在**同一个事件**（逐事件核对：80 个差异事件里只有 1 个
  带非摘要数据流差异）：case `online-2-…` 的
  `event_id=5826`（`cpu_retirement_match`），差异形如
  `byte_cells[0].versions[*]`（控制 `None` vs 故障 `0`）、
  `byte_cells[0].writer_event_ids[*]`、`instruction_responses[0].*`。也就是说：
  同 seed 的两次真实会话在这个 case 上**并非逐字节复现**，锚点之外还存在一处
  内存快照内容差异。这正是「同条件质量对照」需要显式标注、而此前没有文档记录
  的事实。

## 5. 边界与限制

- **只读**：本工具只读校准根；未修改 `src/myfuzz/scenario/`、`src/myfuzz/integration/`、
  `src/myfuzz/local_harness/`、`configs/`、`rtl/`、既有 `scripts/` 与任何 `runs/**`
  （`git status --short` 仅显示 3 个新文件为未跟踪）。
- 未运行 Verilator / RTL / fuzz；未重放 `minimal_replay.json`，因此**不证明新进程
  复现**；重放属于已保存产物之外的独立动作。
- 「检测建立」是**单点见证**：一个变体一次会话一个 case，不构成对故障类的
  灵敏度或覆盖率结论；阴性对照（同 case 未注入不报）由运行器自己的
  `control_run_clean` / `control_window_baseline` 提供，本工具只引用控制 trace
  的字节未变与收据清洁（如果未来要更严格，应把该检查也纳入本文档）。
- 窗口级差异是**信息性**的，不参与 `ok`；`ok` 只由锚点事件（选择器钉住的）与
  摘要连接决定。若某变体的锚点事件本身携带 `admission_id`/`path_id`，当前严格
  分类会把它计成 dataflow 差异并让该变体 `ok=false`（fail-closed）；本次 9 个
  变体都没有这种锚点。
- 本工具不做 RTL、不做统计显著性推断；「质量」在本文件里的含义是
  **逐项可测量的建立/未建立清单**，不是检测率。

## 6. 运行器产物缺陷复核（未改运行器）

**已修复的旧缺陷（记录在案）**：2026-10-07 约 23:39，我用当时的
`scripts/run_p5_fault_calibration_family.py` 在进程内调用 `verify_calibration()`
（只读），得到 `ok=false`，唯一失败检查是 `anchored_events_identical`：

```
observation_irq_level: 锚点事件 event_id=4610 在控制与故障 trace 中不一致
（字段 outputs.irq: 控制=None 故障=None）
```

- 事实：控制 trace `runs/current-dataflow-p5-paired-20261007-online/online_final_trace.json`
  与故障 trace `runs/current-dataflow-p5-fault-family-20261007-online/observation_irq_level/session/online_final_trace.json`
  的 `event_id=4610` 只在 4 个叶子上不同，全部是逐会话的图身份字段：
  `provenance.edge_candidates[0].graph_sha256`、`provenance.edge_candidates[0].path_ids[0]`、
  `provenance.edge_candidates[1].graph_sha256`、`provenance.edge_candidates[1].path_ids[0]`
  （`58471d1e…`→`3bfd62f4…`、`8c5173cf…`→`542b422a…` 等）。
- 证据（同一份产物即可证明这是会话身份而非数据流）：两侧
  `online_run_identity.json` 的 `.identity.runtime_paths.compiled.session.topology_sha256`
  完全相同（`2f6e02486d3d61c51effd28b84cae89c056ecd309cc5a9df77fbd52242ede26a`），
  而 `.identity.runtime_paths.declaration.contract.graph_sha256` 不同
  （`58471d1e…` vs `3bfd62f4…`）；各个 `templates[*].contract_sha256` 也相同。
  即：两次独立会话的整事件 canonical 相等在该字段上**不可能成立**。
- 附带问题：失败文案打印的是**被扰动字段**（`outputs.irq`）的值，而两侧都是
  `None`，与实际差异字段无关，属于误导性诊断。
- **当前状态（无需动作）**：root 已在 2026-10-07 23:42:17 修改该脚本，新增
  `_declaration_drift()`（`scripts/run_p5_fault_calibration_family.py:1067`）与
  `_diff_paths()`，把
  `provenance.edge_candidates*` / `*.graph_sha256` / `*.path_ids` 记为
  `declaration_drift` 并原样写入检查原因。两个根的
  `fault_family_calibration_verify.json` 现在都是 `ok=true, failures=0`
  （例如全量根 `observation_irq_level` 的 `anchored_events_identical` 通过，
  reason 里带 `declaration_drift` 记录）。我**没有**编辑该脚本。
- 与本文档的差异（非缺陷，仅说明口径）：运行器的漂移豁免是「路径以
  `provenance.edge_candidates` 开头或以 `.graph_sha256`/`.path_ids` 结尾」；
  本工具的锚点 gating 只豁免
  `provenance.edge_candidates[N].graph_sha256|path_ids[M]` 两条精确路径模式，并把
  `admission_id`/`path_id`/`origin_admission_ids` 的漂移**只放进信息性分解**、
  仍按 dataflow 计入 gating——更严格，且把两类的差异叶子都逐条列出。

## 7. 复现命令

```bash
# 测试（先 RED 后 GREEN；实现前该文件导入即失败）
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_fault_quality.py -q -p no:randomly

# 真实读数（只读；文档默认打印到 stdout）
PYTHONPATH=src python3 scripts/compare_p5_fault_quality.py \
  --calibration-root runs/current-dataflow-p5-fault-family-all-20261007-online \
  --output /tmp/q-all.json --quiet && sha256sum /tmp/q-all.json
```
