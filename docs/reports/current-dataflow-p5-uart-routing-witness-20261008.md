# P5 异构 UART 真实路由见证（Gap A）与冷组状态判定（Gap B）

日期：2026-10-08。本文对应 [P5 阶段验收报告](current-dataflow-p5-stage-acceptance-20261008.md) 边界节点名的两处差距，两条都以 TDD 完成（先 RED、后 GREEN），并给出**已保存运行**上确实可读出的数字，而不是"应该会有"的数字：

1. **Gap A**：异构 UART 运行 `runs/p5-uart-waveform-gate-20261008-online` 把真实路由/消费见证记成 `null`（`report.json` 里连键都没有），而证据其实一直在运行自己的 trace 里。
2. **Gap B**：冷组聚合报告 `first_step_cold_start_run_report.v1` 只暴露 `execution_status`，P5 判定的 `_judge_normal_control` 因此报 `session_status is None, not 'complete'`，该运行无法作为干净对照。

本文的推导与测试部分只读已保存产物，**没有启动任何 RTL/fuzz 进程**；A1 的在线证明由父级在同一 cache／seed／预算下补跑（新运行 `runs/p5-uart-routing-gate-20261008-online`，见 §3）。

## 1. Gap A：把"真实路由/消费见证"写进 `report.json`

### 1.1 交付内容

| 文件 | 性质 | 作用 |
|---|---|---|
| `src/myfuzz/scenario/uart_routing_witness.py` | 新增模块 | 逐 case 从**该 case 自己的事件切片**读出 UART 寄存器访问与目标消费见证；有界记录器；产出 `online_source_target_transactions.v1` |
| `src/myfuzz/scenario/uart_waveform_gate.py` | 定点修改 | 门自己记录**逐候选决策**（admitted／refused＋精确证据＋前置类型＋候选片段声明的窗口内访问），`decisions()` 有界返回 |
| `src/myfuzz/integration/scenario_rfuzz.py` | 定点修改 | 新增可选 `case_witness_recorder=`；在线路径把 `result.events`（该 case 的切片）交给记录器；**预 RTL 拒绝**记 `events=None`（显式 `null`＋原因） |
| `src/myfuzz/integration/scenario_rfuzz_live.py` | 定点修改 | 仅当会话确实声明了记录器时，写 `report.json:source_target_transactions`（没有记录器的运行 report 字节不变） |
| `src/myfuzz/integration/ibex_uart_online.py` | 定点修改 | 异构 UART wiring 接上记录器 |
| `scripts/report_p5_uart_routing_witness.py` | 新增脚本（只读） | 对**已保存**运行推导同一张见证表；流式读 trace，**从不物化 274 MB JSON**，从不写运行目录 |
| `tests/scenario/test_uart_routing_witness.py` | 新增测试 | A1 的推导规则、join 规则、上限/截断、`null`＋原因、门决策、executor 钩子、report 键 |
| `tests/scenario/test_p5_uart_routing_witness_report.py` | 新增测试 | A2 只读脚本：`not_judged` 作用域、拒绝行 kind 回退、不写运行目录、带键运行的逐字比对 |
| `tests/scenario/test_p5_normal_control_session_status.py` | 新增测试 | Gap B 的判定与全部拒绝路径 |

设计要点：

- **键名归属**：`report.json:source_target_transactions` 是**场景在线写入器**（`myfuzz.integration.scenario_rfuzz_live`）的新键，schema 为 `online_source_target_transactions.v1`；它与 SoC campaign 那条同名但形状不同（`{"status": "observed"…}`）的键互不影响——两者 schema 不同、由不同写入器产出、读不同运行目录。
- **见证来自 case 自己**：执行器在提交后已经持有该 case 的 `result.events`（回执、checker、digest 都用它），记录器拿到的就是这一个切片，因此不会把前一个 case 的事件算到后一个 case 头上，也不需要重新读全局 journal。
- **join 用真实键、并写进记录**：`uart_fifo_pop.observation_event_id == uart_rdata_access.actual_request_event_id`、`uart_retired_read_match.uart_access_event_id == uart_rdata_access.event_id`、`uart_consumption_match.observation_event_id == uart_rdata_access.event_id`、以及按 `entry_id`（pop 带 `frame_id` 时一并比较）join 到已匹配 pop 的帧。每条见证都带 `match_basis`；**join 不上的见证仍然记录**并标 `matched=false`，绝不丢弃。
- **路由起点也记下来**：见证携带 `origin_admission`（`source_admission` 的有界子集），即"这一帧是哪个 case 的哪次注入源送进来的"——它常常**不是**产生访问的那个 case（见 §1.3 的表）。
- **有界**：case 表 `cases.limit`（默认 256）、每个 case 的访问/见证列表各 16 条、门决策日志 256 条，每处都带 `truncated`／`omitted`；totals 对**所有观测到的 case** 累加（`scope=all_observed_cases`、`case_records_omitted`），所以截断表格不会变成截断总数。
- **null＋原因**：`events=None`（预 RTL 拒绝）时访问/见证计数是 `null` 而不是 0，并给出原因；门未接或未暴露 `decisions()` 时同理。

### 1.2 TDD 证据（RED → GREEN）

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_uart_routing_witness.py -q -p no:randomly
# RED（实现前）：ERROR ... ModuleNotFoundError: No module named
#   'myfuzz.scenario.uart_routing_witness'  （1 error during collection）
# RED（模块落地、修 join 前）：3 failed, 9 passed
# GREEN：16 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_uart_waveform_gate.py -q -p no:randomly   # 6 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_uart_routing_witness_report.py -q -p no:randomly
# RED（A2 首版）：4 failed, 3 passed  —— 门把 UART 侧候选也算成自己判的、拒绝行缺 kind、
#                                      join 夹具与真实键不一致
# GREEN：7 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_normal_control_session_status.py -q -p no:randomly
# RED：6 failed, 5 passed      GREEN：11 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_acceptance_suite.py -q -p no:randomly   # 46 passed
```

RED 里被固定住的三条真实失败：见证 join 用错索引（`uart_fifo_pop` 比的是访问的 `actual_request_event_id` 而不是 `event_id`）、`_bounded` 把"总数"算成"保留数"、以及判分器只认 `session_status`。

### 1.3 已保存运行的**确切**见证数字（A2，只读推导）

脚本与产物：

```bash
PYTHONPATH=src python3 scripts/report_p5_uart_routing_witness.py \
  --run-dir runs/p5-uart-waveform-gate-20261008-online \
  --json-out runs/p5-uart-routing-witness-20261008-logs/uart_routing_witness.json \
  --markdown-out runs/p5-uart-routing-witness-20261008-logs/uart_routing_witness.md   # exit 0
```

trace 身份：`online_final_trace.json`（`json.v1`，274,782,641 字节）流式读完 **76,332 事件**，语义 sha256 `0bd295025f9f7740093c4a8ee9ff47b55812d41d9692911e02198f03eb35d528` 与声明**一致**（`semantic_sha256_verified=true`）；只保留 84 条见证类事件在内存中。

| 量 | 数字 | 来源 |
|---|---|---|
| `report.json` 是否带 A1 键 | **否**（`carries_source_target_transactions=false`） | 已保存 `report.json`（sha256 `5737aefc…`） |
| receipts 行数／状态 | 60 行＝57 `complete`＋3 `input_invalid` | 已保存 `receipts.jsonl`（sha256 `cfe903b5…`） |
| 逐候选门的决策（60 行＝门实际判定的 24 ＋ 未判定 36） | **judged 24**（admitted 21／refused 3）＋**not_judged 36**（UART 侧候选不在门声明的 `component=cpu` 内） | receipts 的 `candidate_disposition`＋`source_action`＋门文档的 `component` |
| 产生 UART 寄存器访问的 case | **7**，访问总数 **7** | trace（`uart_rdata_access`） |
| 产生目标消费见证的 case | **21**，见证总数 **77** | trace（`uart_fifo_pop`／`uart_consumption_match`／`uart_retired_read_match`） |
| 已 join 的消费见证 | **21**（7 pop＋7 popped 消费＋7 退休读匹配） | trace join |
| 未 join 的消费见证 | **56**（同 case 内的 IRQ-cause／retention 帧证明，与本次读的 entry 不同） | trace join |
| 无任何见证的 case | **37** | trace |
| 无事件切片（预 RTL 拒绝，`null`＋原因） | **3** | receipts（`input_invalid`） |
| 见证点名的来源 case 去重数 | **7**（来源动作 7） | 见证的 `source_admission` |

**7 条真实路由链**（每条都自带 3 条已 join 见证：pop＋popped 消费＋退休读；`matched.complete=true`）：

| 产生访问的 case | 源 | `access_id` | offset | 读出值 | 源事务 seq | 帧的来源 case（注入源） |
|---|---|---|---|---|---|---|
| `online-1-819b265e…` | instruction | `uart-access:uart:0:4` | 0x18 | 90 | 5 | `uart-fixed-warmup`（bootstrap） |
| `online-10-1b3d5e41…` | UART 源 | `uart-access:uart:0:7` | 0x18 | 0 | 11 | `online-0-af5570f5…` |
| `online-19-06307986…` | instruction | `uart-access:uart:0:11` | 0x18 | 197 | 18 | `online-4-c68c57dc…` |
| `online-28-dccf07a0…` | UART 源 | `uart-access:uart:0:13` | 0x18 | 198 | 23 | `online-5-732ae168…` |
| `online-37-286bb83e…` | UART 源 | `uart-access:uart:0:15` | 0x18 | 200 | 28 | `online-6-c64442bf…` |
| `online-46-bd1099df…` | instruction | `uart-access:uart:0:17` | 0x18 | 202 | 33 | `online-8-8db67a41…` |
| `online-55-3fc20bf6…` | instruction | `uart-access:uart:0:19` | 0x18 | 204 | 38 | `online-10-1b3d5e41…` |

即：**7 个 case 各有一条"来源帧→真实 TL-UL 读→FIFO pop→消费证明→CPU 退休"的闭环**，其中 **3 条是 UART 侧候选**（`online-10`／`online-28`／`online-37`）在自己 case 内被消费，另外 4 条由 CPU 侧候选产生；7 个读里 6 个读到的正是被注入字节（90/197/198/200/202/204），`online-10` 读到 0（时序上该 case 的读早于帧到达），这是**实测值**，不做修饰。

**门的 3 次拒绝**（`reason=uart_rx_waveform_conflict`，前置类型都是 `transport_idle`，证据是精确 tick）：

| case | 证据串 | 主体 | 声明的窗口内访问 |
|---|---|---|---|
| `online-6-1a052124…` | `uart-waveform-idle:1832` | `{transport: uart_rx_waveform, local_tick: 1832, horizon_tick: 1870}` | `SB @ 0x4000001c (word_offset 12)` |
| `online-33-5d1979bd…` | `uart-waveform-idle:4456` | `{… 4456 … 4494}` | `SB @ 0x4000001c` |
| `online-52-56998419…` | `uart-waveform-idle:6296` | `{… 6296 … 6334}` | `SB @ 0x4000001c` |

另 21 个 CPU 侧候选被门判定 admitted：其中 **4 个**（`online-2`／`online-9`／`online-13`／`online-55`）的片段本身含窗口内访问（与 3 次拒绝同样的 `SB @ 0x4000001c`），另外 17 个片段不含窗口内访问；36 个 UART 侧候选**没有被门判定**（门只绑定 `component=cpu`），A2 对它们如实记 `not_judged` 并写明原因，而不是借用 receipt 自己的处置冒充门的决策。

**一个必须点名的错位**：候选"声明的窗口内访问"与 case"真实产生的寄存器访问"**不是同一批**（只有 `online-55` 同时出现在两边）。表里 7 条读链的访问来自 case 自己执行的代码（ISR／support 片段），其中 3 个候选（`online-2`／`online-9`／`online-13`）做的是**窗口内写**（`SB`），而 A1 的见证词汇是读侧的（`uart_rdata_access`＋pop＋消费＋退休），因此它们在本表里如实记 0，而不是编造写侧见证。

**7 条读链与注入字节的对应（§3.3 复核后的口径）**：**7/7** 的读出值都等于本表来源列所指那一帧的注入字节（`online-10` 读到的 `0x00` 正是 `online-0` 注入的那一帧，帧准入/push/pop/消费/退休逐跳都是 0）。但要分清：**值为 0 的相等不构成消费证据**——构成证据的是 entry／pop 的精确 join（`matched.complete=true`）。

### 1.4 哪些数字来自已保存产物、哪些只会在未来运行里出现

- **来自已保存产物（本文可主张）**：receipts 的逐 case 身份/状态/候选处置与门决策；trace 的访问、消费见证、join、来源 `source_admission`、以及 trace 语义 sha256 复算一致；report 的状态、schema 与门的构造文档。JSON 里每个来源都带文件 sha256，`provenance` 与 `save_semantics` 两节逐项写明。
- **只会在未来运行里出现（针对 §1.3 的旧运行；新运行已由 §3 落实）**：①运行自己写的 `report.json:source_target_transactions`（**旧**运行的 report 里没有这个键，所以 §1.3 的表是**推导**，脚本把 `witness_source` 明确写成 `derived_by_this_script`，并把该运行**没有**这个键记成 `carries_source_target_transactions=false`；新运行 `runs/p5-uart-routing-gate-20261008-online` 已写出这个键）；②门在 RTL 之前自己记下的声明式窗口访问（旧运行由脚本用 `fragment_mmio_accesses` 从候选自己的 `words_hex` **重新推导**，并在 `declared_accesses_basis` 里点名"re-derived"；新运行由门自己记录，见 §3.2；**该解码器的 S-type 缺陷已按 §3.3 第 1 条修复并重新生成 JSON**）；③解码器当时选中的 `source_id`／`source_kind`（旧运行从 receipt 读取，新运行由 executor 直接交给记录器）。

## 2. Gap B：冷组聚合报告的状态判定

**选择：实现形状 (ii)——判定器学会读"该 report schema 自己声明的状态字段"——并在同一条路径上加严。**

理由：冷组运行的 `report.json` 是**已冻结的产物**，而重新生成它必须跑 24 次真实 RTL 会话（本轮明确不允许）；形状 (i) 只能让**未来**的冷组报告带上 `session_status`，对已经存在的那份报告无任何作用，差距会原样留着。真正错的地方在判定器：它把"某种字段名"当成了跨 schema 的契约，而 `first_step_cold_start_run_report.v1` 从未声称自己带 `session_status`——它暴露的是 `execution_status`。所以修判定器，而不是要求重跑。同时保留收紧：fallback **只**在 report 完全没有 `session_status` 键时生效（显式 `null` 视为"该报告声明自己没有会话状态"，照样拒绝），且声明的 `complete` **必须**被判定器自己流式读到的逐 case receipts 证实。

实现（`src/myfuzz/scenario/p5_acceptance.py`）：

- `DECLARED_SESSION_STATUS_FIELDS = {"first_step_cold_start_run_report.v1": "execution_status"}`；`_resolved_session_status()` 返回 `(状态, 来源, 原因)`，`value.session_status_source` 把来源写进证据（例如 `report.json:execution_status (declared by schema first_step_cold_start_run_report.v1)`）。
- `_receipt_session_status()` 从 receipts 推导：空 receipts 或任一状态非 `complete` → 不是 complete。
- 拒绝路径（都有测试）：声明的 `complete` ＋ receipts 非全 complete；report 的 `statuses` 与 receipts 计数矛盾；非 `complete` 的 `execution_status`；既无 `session_status` 又无 schema 声明字段；显式 `session_status: null`；非字符串状态；空 receipts。**故障运行仍被拒**（`session_status=finding` ＋ `dut_violation` ＋ injection finding），UART 运行仍被拒（3 例 `input_invalid`），现有 46 个套件测试全绿。

### 2.1 复跑验收套件（同一命令、同一 7 个运行）

| | 改前 | 改后 |
|---|---|---|
| `critical_met` | **6/6** | **6/6** |
| `exit_code` | **0** | **0** |
| `no_proving_run` | `[]` | `[]` |
| `normal_control_has_no_finding` 的 `proving_runs` | `[chain_acceptance, fault_family, long_search, paired_continuous]`（4 个） | `[chain_acceptance, fault_family, long_search, `**`paired_cold_start`**`, paired_continuous]`（5 个） |
| 冷组 run 的这一项 | `measured=true, met=false`，原因 `session_status is None, not 'complete'` | `measured=true, met=true`，`session_status_source=report.json:execution_status (declared by schema first_step_cold_start_run_report.v1)`、`receipt_derived_session_status=complete`、`receipts=24` |
| `paired_cold_start` 单跑 | 2/6 | 3/6（其余仍是本运行不承担的项） |

即：冷组运行现在能作为**干净对照**进入联合证明（此前它 `met=false` 只是被其它对照盖过去），而"不是全 complete 就不算干净对照"的判据没有被放松——反而多了 receipts 一致性与 `statuses` 一致性两道交叉检查（UART 运行的理由串现在会多出一句"声明的 complete 与逐 case receipts 不符"）。

## 3. 实时 RTL 证明（父级补跑，2026-10-08）

本文原本把 A1 的在线证明留给父级；该运行已完成，脚本 `runs/current-dataflow-p5-final-20261007-logs/p5_uart_routing_gate.sh`（同一 cache 目录、同 seed `20261007`、同预算）产出新运行 `runs/p5-uart-routing-gate-20261008-online`：

| 量 | 真实结果 |
|---|---|
| 会话 | `session_status=complete`、60 例（**57 complete ＋ 3 `input_invalid`**）、79.934 有效秒；与旧运行 57/3 逐状态一致 |
| fresh replay | **`matches=true`**、`first_difference=null`（新源码 + 新运行目录，独立 replay cache） |
| `report.json:source_target_transactions` | **存在**，schema `online_source_target_transactions.v1`（旧运行没有这个键） |
| 记录器 totals | 60 例、`cases_with_register_access=7`、`register_accesses=7`、`target_consumption_witnesses=73`、`matched_consumption_witnesses=21`、`unmatched_consumption_witnesses=52`、`cases_with_target_consumption_witness=20`、`cases_without_any_witness=37`、`event_slices_unavailable=3`、`case_records_omitted=0` |
| 门禁决策日志 | `report.json:source_action_gate.gate.decisions = {count:24, admitted:21, refused:3, retained:24, truncated:false}`（21 采纳＋3 拒绝 `uart-waveform-idle:1832/4456/6296`）；`source_target_transactions.source_action_gate.decisions` 另有逐候选记录（含 `declared_window_accesses` 并标注这是**声明**而非实测） |
| 交叉核对 | `scripts/report_p5_uart_routing_witness.py` 对**新运行**给出 `witness_source=report.json:source_target_transactions`，并把运行自己写的量放进 `recorded_by_the_run` |

### 3.1 交叉核对发现的一处真实差异（已定位，已归类）

脚本对同一运行的独立推导给出 `target_consumption_witnesses=77`、`cases_with_target_consumption_witness=21`，运行自身写的是 **73／20**，`agreement_with_recorded.agrees=false`，`differences` 精确列出这两项。逐 case 定位后差异只有一个来源：

- 多出来的 **4 条见证全部属于 `uart-fixed-warmup`**（bootstrap 源，`source_admission.role="bootstrap"`、`case_index=0`），4 条都是 `uart_consumption_match`（`frame_id="uart-frame:0:1"`、`entry_id=["uart",0,0,2]`、`proof_scope="uart_fifo_retention"`），且**全部 `matched=false`**；
- 记录器不给 bootstrap 建立 case 记录（它只覆盖已提交的搜索例 60 个），脚本扫全 trace 故把它算成第 61 个 case；
- 因此差异**只落在"未 join 的保留类见证"上**：两侧的 `matched_consumption_witnesses` 都是 **21**，`cases_with_register_access`／`register_accesses` 都是 **7**，链的证据不受影响。

这是**作用域差异，不是错误计数**：运行自身的计数是"已提交搜索例的作用域"，脚本是"全 trace 作用域"。两处口径都已写明；本文不把运行自己的 73 说成 77，也不把脚本的 61 说成 60。

### 3.2 本轮独立复核（Gap A 交付方自己跑的两项只读检查）

- **同一份交叉核对**：`PYTHONPATH=src python3 scripts/report_p5_uart_routing_witness.py --run-dir runs/p5-uart-routing-gate-20261008-online` 给出 `witness_source=report.json:source_target_transactions`、`recorded_by_the_run` 存在、`agreement_with_recorded.agrees=false` 且 `differences` **只有** `target_consumption_witnesses 73→77` 与 `cases_with_target_consumption_witness 20→21` 两项——与 §3.1 的定位逐字一致；两边 `register_accesses=7`、`cases_with_register_access=7`、`matched_consumption_witnesses=21` 全等。
- **7 条链在新旧运行上逐条同形**：新运行自身写的 7 条链与本文 §1.3 对**旧**运行的独立推导**逐字段一致**（`uart-access:uart:0:4/7/11/13/15/17/19`、offset 全 `0x18`、读出值 `90/0/197/198/200/202/204`、每条 3 条已 join 见证、`matched.complete=true`、来源 case 分别为 `uart-fixed-warmup`／`online-0`／`online-4`／`online-5`／`online-6`／`online-8`／`online-10`）。即：**同一 seed/预算下，A1 的在线记录与 A2 对旧产物的推导互相印证**，而不是各自编一套。
- **门决策日志在线可用**：新运行 `report.json:source_action_gate.gate.decisions={count:24, admitted:21, refused:3, retained:24, truncated:false}`，3 个拒绝各自的 `evidence_ref`（`uart-waveform-idle:1832/4456/6296`）、`prerequisite_kind=transport_idle`、`subject` 与 `declared_window_accesses`（`SB @0x4000001c`，并标注"声明而非实测"）都落在 `report.json` 里，不再是"只有一个计数"。

### 3.3 对抗式独立复核（另一个独立子代理，父级指派）

一个**独立**子代理按对抗口径复核了本文的数字（自己解析 `receipts.jsonl`、自己用 `TraceEventStream` 流式读 76,332 事件的 274,782,641 字节 trace、自己实现 join 与 RV32I 解码；只在标注处导入生产模块做交叉比对）。产物：`scripts/verify_p5_uart_routing_witness.py`、`tests/scenario/test_verify_p5_uart_routing_witness.py`（RED 1 error → 11 failed/6 passed → **GREEN 18 passed**）、`runs/p5-uart-routing-witness-20261008-logs/uart_routing_witness_verify.json`（29 条 claim，`ok=false`、exit 4）。

**结论：29 条里 27 条一致、0 条无法核对，2 条不一致——两条都已处理：**

1. **（实质缺陷，已修）** `declared_address_is_riscv_correct`：表里把 7 条声明式窗口访问记成 `SB @ 0x40000002`，而按真正的 RV32I **S-type** 语义（`imm[11:5]<<5 | imm[4:0]`，rs2=2、rs1=1）同一个字 `0x00208e23` 是 `SB @ 0x4000001C`，正是 UART **TXDATA**（`ibex_uart_online.py` 就是为 `UART_BASE + 0x1c` 造这些片段的）。根因在**出货代码**：`uart_waveform_gate.fragment_mmio_accesses` 对**存储**也按 I-type（bits 31:20）取立即数，把 rs2 折进地址低位并丢掉 `imm[4:0]`。**已按 TDD 修复**（`tests/scenario/test_uart_waveform_gate.py::test_a_store_offset_uses_the_s_type_immediate_not_the_i_type_one`：先临时回退修复得到 `1 failed, 6 passed` 的 RED 证据，恢复后 **7 passed**），并**重新生成了 §1.3 的见证 JSON**（sha256 由 `086ed820…` 变为 `006a5a52…`，7 条声明访问现在全部解出 `0x4000001c`）。对本运行的判定**无影响**（两种读法都落在 `0x40000000+0x1000` 内，故 21 采纳／3 拒绝不变）；但对**非页对齐窗口或别的 rs2** 会改变窗口判定，所以这是必须修的真缺陷，而不是措辞问题。
2. **（叙述错误，已修）** 报告 §1.3 原写"7 条读里 6 条等于注入字节"，复核独立解得 **7/7**：`online-10` 的 `:7` 链消费的是 `online-0` 注入的 `0x00` 帧（帧准入字节 0、push 0、pop 0、消费/退休 0），与本文来源列自洽。原文那句"该读早于帧到达"的注解已删除。复核同时提醒：**值为 0 的相等不构成消费证据**，构成证据的是 join（entry／pop），这一点已按它的口径写在下面。
3. **（§3.1 细节更正）** §3.1 原写 bootstrap 的 4 条见证"都是 `uart_fifo_retention`"是不准确的：只有 event 7375 是 retention（`frame_id=uart-frame:0:1`、`entry_id=["uart",0,0,2]`），另 3 条（7376／7377／7885）分别是 `native_irq_cause` 与 `cpu_external_irq_taken`，`frame_id`/`entry_id` 为 `null`——它们**全部 `matched=false`** 这一点不变，差异仍只落在未 join 的保留/IRQ 类见证上。
4. 对抗检查里**没有发现**的问题（复核原文）：7 条链各自 3 条已 join 记录是**同一次 TL-UL 读**的线性证据链（`retired_read_match.uart_read_proof_event_id` 指向被 pop 的消费见证），不是 3 次独立读；trace 里只有 7 个 `uart_rdata_access`，不存在"有访问无退休"或"有 pop 无访问"的第 8 条半链；3 条拒绝行的 `null` 是**实测空事件切片**（预 RTL 拒绝、0 条 trace 事件），不是装饰性 null；"56 条未 join"是**按 case 作用域**的口径（其中 7 条 retention 见证的 entry 在**另一个** case 才被 pop），属于口径选择而不是无据推断。

## 4. 边界（本文不主张什么）

- ~~**A1 没有在线证明**~~ **已由 §3 的实时运行补齐**：`report.json:source_target_transactions` 已在真实会话中落盘并随 fresh replay 一起验证。已保存旧运行的那张表仍是**只读推导**，不是该运行自己的结论（它的 report 里没有这个键）。
- **记录器只覆盖已提交搜索例**：bootstrap（`uart-fixed-warmup`）的 4 条保留类见证只在脚本的全 trace 推导里出现，运行自身的 `totals` 不含它；两者作用域不同，见 §3.1。若要让运行自身也覆盖 bootstrap，需要把 warmup 的 `submit_case` 结果也交给记录器——本轮不改（父级运行期间源文件冻结），列为后续小改动。
- **A2 的推导不是运行结论**：`witness_source=derived_by_this_script`；被重新推导的量（门的声明式窗口访问）在 `declared_accesses_basis` 里点名；如果未来运行写出了 A1 键，脚本会把它原样放在 `recorded_by_the_run` 并与推导做交叉比对（`agreement_with_recorded`，见 §3.2）。
- **没有门文档的运行**：那时 A2 表里的 `decision=admitted` 来自 receipt 的 `candidate_disposition`（executor 的准入处置），不是门做的决策；脚本把 `gate_report`／`gate_component` 记成 `null`，让这一点可判定。UART 运行有门文档，本文表格不受影响。
- **7/36 不是全覆盖**：36 个 UART 侧候选里只有 3 个在自己 case 内完成了"帧→读→消费→退休"；其余 UART 侧候选的字节没有被读（trace 里 `uart_frame_validation`／`uart_fifo_pop` 各只有 7 次）。本文不主张 UART 侧"高覆盖"，只主张"这 7 条链是真实的，且逐条可点名"。
- **未 join 见证不是失败**：它们是同 case 内的 IRQ-cause／FIFO-retention 证明，帧/entry 与本次读不同；它们被完整保留并标 `matched=false`，不参与"覆盖"计数。口径要分清：旧运行的只读推导是 **56/77**，新运行自身写的是 **52/73**（差的就是 §3.1 的 bootstrap 保留类 4 条）。
- **写侧不在见证词汇里**：A1 只读读侧四类事件（`uart_rdata_access`／`uart_fifo_pop`／`uart_consumption_match`／`uart_retired_read_match`）。3 个 admitted 的窗口内 `SB` 候选（`online-2`／`online-9`／`online-13`）因此记 0 条访问——这是"该类见证不存在"，不是"目标没有被写"。若需要写侧路由见证，必须新增写侧事件词汇，本文不主张已有。
- **跨 case 的帧会分属两个 case**：一帧的 retention 证明常出现在注入它的 case 里，读却发生在后面的 case 里，所以逐 case 表会把 retention 记为未 join；链的闭环由 `matched.complete=true` 的三个读侧见证（pop／popped 消费／退休）承担。
- **链证书仍为 0**：本文只补路由/消费见证，不产生 `certified_chains`；UART 侧完整链证书是另一条工作线（`src/myfuzz/scenario/uart_chain_certificates.py`，本轮未触碰）。
- **旧的 UART bundle 会按设计被身份守卫拒绝**：本次改动落在 `src/myfuzz/integration/scenario_rfuzz.py`、`scenario_rfuzz_live.py`、`ibex_uart_online.py` 三个已登记进该运行 decode-space 源文件清单的文件里（记录的 sha256 分别是 `01bebe23…`／`6eb09003…`／`b31d6dcd…`，当前为 `c7aa4c82…`／`05c8ad02…`／`cb99a709…`）。这是**已声明的机制**：旧 bundle 的 fresh replay 会被 `_verify_online_run_identity` 在任何 RTL 启动之前拒绝，本文不主张旧运行在新源码下可重放。
- **门仍是声明式拒绝**：底层"波形中访问 UART"依然不被支持，A1 只把门自己的决策与路由见证写清楚，不主张长会话稳定性、不主张覆盖等价。

## 5. 测试与验证（本轮实跑，含失败归属）
```bash
# 新增测试（三个新文件）
PYTHONPATH=src python3 -m pytest tests/scenario/test_uart_routing_witness.py \
  tests/scenario/test_p5_uart_routing_witness_report.py \
  tests/scenario/test_p5_normal_control_session_status.py -q -p no:randomly
#   16 + 7 + 11 = 34 passed
# 既有套件（整目录实跑）
PYTHONPATH=src python3 -m pytest tests/scenario -q -p no:randomly
#   10 failed, 2855 passed, 2512 subtests passed（650.44s）
PYTHONPATH=src python3 -m pytest tests/integration -q -p no:randomly
#   125 failed, 1632 passed, 587 skipped, 18 errors, 1157 subtests passed（504.36s）
# 覆盖本次改动的集成测试（定向复跑）
PYTHONPATH=src python3 -m pytest tests/integration/test_first_step_cold_start_run.py \
  tests/integration/test_scenario_rfuzz_terminal_identity.py \
  tests/integration/test_scenario_rfuzz_live_client.py \
  tests/integration/test_online_run_identity.py tests/integration/test_fresh_run_identity.py \
  tests/integration/test_online_decode_space_identity.py -q -p no:randomly
#   89 passed, 5 skipped, 10 subtests passed
# 父级在全冻结源码树上跑的两目录整体回归（2026-10-08，1687.79s）
PYTHONPATH=src python3 -m pytest tests/scenario tests/integration -q -p no:randomly
#   8 failed, 4627 passed, 587 skipped, 3734 subtests passed
# 8 条失败逐条归类（无一条来自本轮交付）：
#   * tests/integration/test_soc_ibex_rvfi_coverage.py（需 Verilator 前端）
#   * tests/integration/test_soc_protocol_checkers.py（profile-verilator-build-failed）
#   * tests/integration/test_soc_source_locks.py ×3（组件 id 集合漂移，configs/ 被本会话外的工作改过）
#   * tests/integration/test_generic_cpu_targets.py（picorv32 清单缺 instruction_identity，配置漂移）
#   * tests/integration/test_rfuzz_live.py ×2（断言正则写的是旧文案 "no RTL tests"，实际为
#     "RFuzz client produced no accepted RTL tests"，属既有文案不一致）
# 定向复跑本文件涉及的模块：tests/scenario/test_uart_waveform_gate.py 7 passed（含新增 S-type 回归用例，
# 先回退修复得 RED 1 failed/6 passed），五个新测试文件合计 73 passed。
```

失败归属（逐条可核对，**没有一条来自本次改动**）：

- `tests/scenario` 的 10 个失败：9 个在**并发 agent 正在 TDD 的** `tests/scenario/test_uart_chain_certificates.py`（其 `src/myfuzz/scenario/uart_chain_certificates.py` 同一分钟仍在写）；1 个是 `tests/scenario/test_p5_acceptance_suite.py::test_a_compare_run_never_stands_in_for_the_declared_run` 在整轮运行途中因**另一个 agent 07:23:06 正在补 import** 而 NameError，现行文件已含 `ARTIFACT_PLAN`／`ARTIFACT_RECEIPTS` 导入，单跑与整文件复跑均 **57 passed**。
- `tests/integration` 的 125 failed＋18 errors：全部集中在 RTL/Verilator 依赖文件（`generic composition lint failed: status=startup-error` 54 处、`ElaborationError: verilator frontend failed: startup-error` 45 处、`profile-verilator-build-failed` 等；本环境按约定不启动 Verilator），另 2 处是 `configs/` 漂移导致的旧期望（`test_generic_cpu_targets.py` 的 picorv32 `instruction_identity`、`test_soc_source_locks.py` 的组件 id 集合——`configs/soc/sources.lock.json` 已被其它工作改动）。对失败 traceback 逐个 grep 本次改动的 6 个模块名，**命中 0 次**。
- 定向复跑覆盖本次改动路径的 6 个集成文件：**89 passed, 5 skipped**。
- **最终树上再跑一次验收套件**（同一条命令，含并发 agent 已落地的改动）：`critical_met=6/6`、`exit_code=0`、`no_proving_run=[]`、`normal_control_has_no_finding.proving_runs = [chain_acceptance, fault_family, long_search, paired_cold_start, paired_continuous]`（5 个，与 §2.1 的"改后"一致），冷组项 `met=true`、`session_status_source=report.json:execution_status (declared by schema first_step_cold_start_run_report.v1)`。

## 6. 文件摘要（sha256）

| 文件 | sha256 |
|---|---|
| `src/myfuzz/scenario/uart_routing_witness.py`（新） | `4d9ad84eb1ac5e0ca66e387ad71c266cda3637fb49a60d5ece9d6e93fad47c8f` |
| `src/myfuzz/scenario/uart_waveform_gate.py` | `3209127f47d5346f7c534d1e921908f6971a47562c156bebc8918d8f24b12ab2`（S-type 修复前）→ **`84e058ee6017e124c8530b9b9f28b137b5a46bf4bba95486a856df413ee5f091`**（§3.3 第 1 条修复后） |
| `src/myfuzz/integration/scenario_rfuzz.py` | `c7aa4c82e5377f00a227889d9724d0e430ee04a586da09893cd0926378df4d8b` |
| `src/myfuzz/integration/scenario_rfuzz_live.py` | `05c8ad02ae73439a0082ed90a3df276a494fa8b3d53810f14119fdfb65c8ecc0` |
| `src/myfuzz/integration/ibex_uart_online.py` | `cb99a709ebbd150aa8ba4f25714c36ba715439bb4081a1e35a1cf4e4e217213b` |
| `src/myfuzz/scenario/p5_acceptance.py` | `6305b0cb5ecb9e1e85d37c3c596a75c71c5595c45bd5a37f5637f4e0c26a4be7` |
| `scripts/report_p5_uart_routing_witness.py`（新） | `81133e50f778f5c9cf1520ffb047bdf60134a801535b15dd4ded7ba272bc2336` |
| `tests/scenario/test_uart_routing_witness.py`（新） | `27cc7cccc12aad3ab094b10fc57cf67dbf431075173b6dddf5caf1f496f177b4` |
| `tests/scenario/test_p5_normal_control_session_status.py`（新） | `f7f3ccdf6f7707614c01cdb6851e1da07120b880592bbf399358d833337a02ce` |
| `tests/scenario/test_p5_uart_routing_witness_report.py`（新） | `878f262dfeb61462f573b8026d76b00f99e2ebc0f0aaed8ff0b2437cc67c79dc` |
| `runs/p5-uart-routing-witness-20261008-logs/uart_routing_witness.json`（推导产物） | **`006a5a52ef5bebc43642be714909e6eee0ebcb6991fcc10f61a3ae01e2c324c5`**（§3.3 修复后重新生成；修复前为 `086ed820ad6f1e9cb0a964e1155c9d17c288a7300a37b56bad5e9d9b61ff246b`） |
| `scripts/verify_p5_uart_routing_witness.py`（新，独立复核器） | 见 §3.3；`runs/p5-uart-routing-witness-20261008-logs/uart_routing_witness_verify.json` 为 29 条 claim 的逐条结论 |
| `tests/scenario/test_verify_p5_uart_routing_witness.py`（新） | 18 passed（RED 1 error → 11 failed/6 passed → GREEN） |
| `tests/scenario/test_uart_waveform_gate.py`（新增 S-type 回归用例） | 7 passed（含先回退修复得到的 RED：1 failed, 6 passed） |
