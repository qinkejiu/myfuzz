# P5 链终点之外：ISR 写 GPIO A 的精确身份连通性判定与回流端点证书

日期：2026-10-08。本报告回答 [`current-dataflow-p5-chain-600s-20261007.md`](current-dataflow-p5-chain-600s-20261007.md) 与 [`../CURRENT_PROGRESS.md`](../CURRENT_PROGRESS.md) 里明确写下的那条边界——"证书终点分别是 ISR 读 GPIO B `PADIN` 的退休与写 GPIO A 的退休交付，**不含** ISR 写 GPIO A 之后、A→B 回流与第二次中断"——并给出由真实保存产物支撑的证书扩展。

分析只读真实 run（`runs/current-dataflow-p5-chain-600s-20261007-online`，570,196 事件、zlib 分块 trace；`runs/current-dataflow-p5-chain-acceptance-20261007-online`，31,795 事件、单文件 JSON），全部经 `myfuzz.scenario.acceptance_metrics.TraceEventStream` 流式读取，`max_pending`/`max_event_gap` 有界。**未启动任何 Verilator/RTL/fuzz 进程**，未修改任何既有 producer、配置或 verdict。

## 0. 结论

| 问题 | 判定 | 依据 |
|---|---|---|
| 把"ISR 写 GPIO A"接成 P5 已认证链的下一跳（上游连接） | **不可按精确身份连接**：acceptance run **0/8**、600s run **0/27** 条证书可扩展 | §2.3、§3 |
| 边界原文中"ISR 写 GPIO A **之后**"的 A→B 回流与第二次中断（下游连接） | **可按精确身份连接，并已出具新证书** `isr_writeback_certificate.v1`：acceptance run 5 个 ISR 写中 **2** 个 10 跳全认证；600s run 68 个中 **3** 个全认证 | §2.2、§4 |
| 是否使用了相邻/顺序回退 | **0 次**（`adjacency_fallbacks_used = 0`，两个 run） | §4 |
| 唯一最重要的缺失身份 | `cpu_retired_transaction_target_delivery.registered_origins` / `registered_origin_status`（handler 写那条记录上为 `[]` / `"unknown"`） | §3 |

一句话：**"ISR 写 GPIO A 之后"这段是精确可连的，而且今天就能出证书；"某条已认证链 → 这次 ISR 写"这段不是，缺的是 handler 执行的来源身份。**

## 1. 判据

*精确身份*＝同一身份字段取值相等。本报告只承认以下几类：六字段事务键 `(channel_id, execution_id, source_component, source_epoch, source_sequence, testcase_id)` 全等、目标侧 `access_id` 全等、寄存器位身份 `(component, register, bit, version, observation_event_id)` 全等、`trigger_id` 全等、事件 id 引用（`producer_event_id` / `retirement_event_id` / `delivery_event_id` / `observation_event_id` / `trigger_event_id`）全等，以及 `cpu_retire` 的 `mem_addr`/`mem_wmask`/`mem_wdata` 与验收侧 `address`/`byte_enable`/`write_value` 全等。

以下一律**不作为**连接依据，只在证书里显式记录：事件相邻与顺序（`relation = adjacency_only`）、程序计数器落在声明的 handler 镜像区间（`relation = classification_only`）、等计数、架构预期。

## 2. 证据

### 2.1 ISR 确实写了 GPIO A：指令与事件证据

`initial_image: cpu.stream.isr` 在 acceptance run 与 600s run 中都是 `address = 66048`、`data_hex` 68 字节，即区间 `[0x10200, 0x10244)`，共 17 条指令。逐字解码（只列与本判定相关的）：

| pc | 指令字 | 解码 | run 中观测到的 `mem_addr` / `mem_wmask` / `mem_wdata` |
|---|---|---|---|
| `0x10214` | `0x0080a103` | `lw x2, 8(x1)`（x1 = `0x40000000`，读 GPIO B `PADIN`） | `0x40000008` / 0 / —（`mem_rmask=0xF`） |
| `0x10220` | `0x00815113` | `srli x2, x2, 8`（取 pin-8 位） | — |
| `0x10224` | `0x400011b7` | `lui x3, 0x40001`（x3 = `0x40001000`，GPIO A 基址） | — |
| **`0x10228`** | `0x0021a623` | **`sw x2, 12(x3)`（写 GPIO A `PADOUT`）** | **`0x4000100C` / `0xF` / `0` 或 `1`** |
| `0x1022c` | `0x0240a103` | `lw x2, 36(x1)`（读回 GPIO B 状态） | `0x40000024` / 0 / — |
| `0x10240` | `0x30200073` | `mret` | — |

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/report_isr_writeback_certificates.py \
  --run-dir runs/current-dataflow-p5-chain-acceptance-20261007-online
```

因此"ISR 写 GPIO A"在真实 trace 中是一整套本地记录，而不是推断：`mmio_acceptance`（cpu、`gpio_a`、offset 12、write）、`gpio_apb_access`、`gpio_register_commit`（register `out`）、`mmio_delivery`、`cpu_retire`（pc `0x10228`）、`cpu_retirement_match`、`cpu_retired_transaction_target_delivery`。

### 2.2 候选身份逐条判定（exact 还是仅相邻/分类）

| 候选证据 | 精确 join key | 判定 |
|---|---|---|
| `mmio_acceptance.source_transaction` ↔ `gpio_apb_access` / `gpio_register_commit.bit_resources[].transaction` / `mmio_delivery.source_transaction` / `data_accept` / `data_response` / `cpu_retirement_match.transaction_keys[0]` | 六字段事务键全等 | **exact** |
| `gpio_register_commit.access_id` ↔ `gpio_apb_access.access_id` ↔ `mmio_delivery.target_access_id` ↔ `cpu_retired_transaction_target_delivery.consumer_resource.target_access_id` | `access_id` 全等 | **exact** |
| `gpio_register_commit.observation_event_id` ↔ `gpio_apb_access.event_id` | 事件 id 全等 | **exact** |
| `gpio_input_applied.segments[].origin.producer_resource_refs[]` ↔ 提交位身份 | `(component, register, bit, version, observation_event_id)` 全等 | **exact**（A→B 绑定跳） |
| `gpio_input_applied_resource.bit_resources[].origin_refs[]` ↔ 提交位身份，且 `origin_status == "known"` | 同上 | **exact** |
| `gpio_irq_trigger` / `gpio_irq_observation` 的 `causes[].current_sample.origin_refs[]` ↔ 提交位身份 | 同上 | **exact** |
| `gpio_irq_observation.trigger_id` / `cpu_irq_input.source_trigger.trigger_id` ↔ `gpio_irq_trigger.trigger_id`；`source_trigger.trigger_event_id` ↔ trigger 事件 id | `trigger_id`、事件 id 全等 | **exact** |
| `cpu_retire.mem_addr/mem_wmask/mem_wdata` ↔ 验收 `address`/`byte_enable`/`write_value`；`cpu_retirement_match.producer_event_id` ↔ retire 事件 id；delivery `retirement_event_id` ↔ match 事件 id | 字段全等 / 事件 id 全等 | **exact** |
| 链证书的 `retired_target_delivery` / `isr_padin_retirement` 跳身份 ↔ ISR 写 | `registered_origins[0]` 文档 + `source_refs[0]`（既有 producer 唯一承认的来源规则） | **absent**：handler 写该记录为 `registered_origin_status="unknown"`、`registered_origins=[]`、`source_refs=[]` |
| 链证书的 `cpu_irq_taken` 跳身份 ↔ ISR 写 | `cpu_step_event_id` / `take_event_id` / `source_trigger.trigger_id` 出现在 ISR 写侧任一事件上 | **absent**：handler 侧没有任何字段引用 take |
| `isr_padin_retirement`（ISR 的 `PADIN` 读退休）↔ ISR 的 `PADOUT` 写退休 | handler 侧存在 `handler_read_retirement_event_id` 之类的字段 | **absent**（字段本身不存在） |
| ISR 写 ↔ 链终点 | `target_access_id` / 事务键 / `retirement_event_id` / `delivery_event_id` | **mismatch**：是两次不同的物理 MMIO 事务（例如 acceptance run 链终点 `gpio-access:gpio_a:0:4`/seq 7 ↔ ISR 写 `gpio-access:gpio_a:0:5`/seq 13） |
| ISR 写 ↔ 链终点的时间关系 | 事件 id 先后 | **adjacency_only**（例如 600s run 某条 IP 链 `isr_padin_retirement` = 5618 与 ISR 写 retire = 6023 相隔 405 事件；仅顺序） |
| ISR 写自身的归属 | retire `pc_rdata ∈ [66048, 66116)` | **classification_only**（`initial_image` 区间观测，非身份） |

链证书自己的跳身份在审计里可见：`CPU_TO_IP_TO_CPU` 的锚点是 `retired_target_delivery`（600s run 例：事件 3770），`IP_TO_CPU_TO_IP` 的锚点是 `isr_padin_retirement`（例：事件 5618）；IP 方向的 take 身份可从证书跳里取出：`take_event_id=4701`、`step_event_id=4696`、`source_event_id=1`、`trigger_id=gpio_b:0:trigger:1`。ISR 写侧没有任何字段等于其中任何一个。

### 2.3 逐跳事件 id：acceptance run 中两个全认证的 ISR 写回

新证书 `isr_writeback_certificate.v1` 的 10 跳声明序列（**journal 顺序**；同一 trigger 的 CPU 输入通知先于 GPIO IRQ 观测，90/90 个真实 trigger 一致）：

`handler_mmio_acceptance → handler_register_commit → binding_segment → binding_input_resource → bound_irq_trigger → handler_retirement → handler_retirement_match → handler_target_delivery → bound_cpu_irq_input → bound_irq_observation`

| 跳 | ISR 写回 #1（access `gpio-access:gpio_a:0:5`） | ISR 写回 #2（access `gpio-access:gpio_a:0:7`） |
|---|---:|---:|
| `handler_mmio_acceptance` | 5908 | 13219 |
| `handler_register_commit` | 5925 | 13236 |
| `binding_segment` | 5951 | 13262 |
| `binding_input_resource` | 5953 | 13264 |
| `bound_irq_trigger` | 6007（`gpio_b:0:trigger:2`） | 13318（`gpio_b:0:trigger:4`） |
| `handler_retirement`（`cpu_retire`，pc `0x10228`） | 6023 | 13334 |
| `handler_retirement_match` | 6024 | 13335 |
| `handler_target_delivery` | 6025 | 13336 |
| `bound_cpu_irq_input` | 6027 | 13338 |
| `bound_irq_observation` | 6058 | 13369 |
| 事务键 `source_sequence` | 13 | 24 |
| `cpu_step_event_id`（第二次中断所在步） | 6012 | 13323 |
| `registered_origin_status` | `unknown` | `unknown` |

即：ISR 的 `sw x2, 12(x3)` 提交 `gpio_a.out` 位版本 → `gpio_input_applied` 段起点重复同一 `(gpio_a, out, bit, version, observation_event_id)` → `gpio_input_applied_resource` 目标侧 `origin_status="known"` → `gpio_irq_trigger` `gpio_b:0:trigger:N` → `cpu_irq_input`，全程精确身份，**无一处相邻回退**。

### 2.4 边界敏感性

同一 acceptance run 在 `max_event_gap=16384` 下结果不变（2 certified / 3 incomplete，首个缺口均为 `bound_irq_trigger`）；600s run 在 `max_event_gap=4096` 与 `32768`（`max_pending` 128↔512）两种有界设置下，`handler_writes_observed=68`、`certified=3`、`incomplete=65`、首个缺口分布 `binding_input_resource 62 / bound_irq_trigger 3` **完全相同**，只有结算原因分布随界变化（`journal_end` 1→4、`max_event_gap` 64→61）。身份缓存淘汰计数 `identity_cache_evictions = 0`：缺失的跳不是被有界缓存挤掉的。在 570,196 事件的 journal 里，一个候选要到出生后 32,768 个事件才过期，而 A→B 绑定跳在物理上只跟在该次写之后几十个事件内——因此 62 条 `binding_input_resource` 缺失是结构性的（那次写没有改变 `out` 位，没有产生新的绑定资源），不是界的问题。

### 2.5 唯一可用的硬件侧带在这条写上是 0

600s run 使用 `--native-irq-receipts`，`cpu_retire` 上带 `irq_serial_observation`。68 个 pc `0x10228` 的写退休**全部** `decision.value = 0`、`retirement.value = 0`（语义 `no_provable_source_lineage`），ISR 区间内其余退休（`0x10200`..`0x1020C` 抽样）同样为 0；唯一非零只出现在 `intr=1` 的 `0x1012C` 退休（退休序号 1..68）。也就是说，即使使用仓库里最严格的硬件 token，也**无法**把 handler 的写绑定到某次外部 IRQ 决策。

## 3. 缺失身份（精确到文件、记录、字段）

**文件**：`runs/current-dataflow-p5-chain-600s-20261007-online/online_events.zlib`（zlib 分块，570,196 事件）与 `runs/current-dataflow-p5-chain-acceptance-20261007-online/online_final_trace.json`（31,795 事件）。

**记录**：ISR 写那条 `cpu_retired_transaction_target_delivery`
：600s run 与 acceptance run 的第一次 ISR 写回都是 `retire_event_id=6023`、`retirement_event_id=6024`、`delivery_event_id=6025`、`consumer_resource.target_access_id=gpio-access:gpio_a:0:5`、事务键 `source_sequence=13`；600s run 的 68 条同类记录字段取值一致。

**字段与实际取值**：

| 字段 | 实际值 | 需要什么才能连上链 |
|---|---|---|
| `registered_origin_status` | `"unknown"`（600s run：全部 68 条 handler 记录；`gpio_a` 的 3,488 个 `out` 位资源同样全为 `origin_status="unknown"`, `origin_refs=[]`） | `"known"` |
| `registered_origins` | `[]` | 恰好一个 origin 文档，等于目标的链 admission 文档 |
| `source_refs` | `[]` | 该 admission 的 `action_id` |
| `cpu_retire` / `cpu_retirement_match` 上的 `irq_take_event_id`（或任何 handler 实例身份） | 字段不存在 | 等于该链 `cpu_irq_taken` 跳的事件 id（例：4701）或 `cpu_irq_taken.cpu_step_event_id`（例：4696）或 `source_trigger.trigger_id`（例：`gpio_b:0:trigger:1`） |
| handler 写记录上的 `handler_read_retirement_event_id` | 字段不存在 | 该次 ISR 的 `PADIN` 读退休事件 id（例：5618） |

**为什么是结构性缺失**：两个 run 的 `online_plan.json` 都只有唯一指令槽 `[["cpu", 69632, 31616]]`（≈`0x11000..0x17B80`），而 ISR 镜像在 `66048`（`0x10200`）；`source_admission` 只有三类 `(role, direction, input_kind)`：`(fixed_support, IP_TO_CPU_TO_IP, instruction)`、`(fuzz_source, CPU_TO_IP_TO_CPU, instruction)`、`(fuzz_source, IP_TO_CPU_TO_IP, source_event)`。**handler 的指令既不在任何指令槽内，也不在任何 admission 里**，所以按现有 schema 它根本没有 `admission_id`/`action_id` 可写进 `registered_origins`；而 `cpu_irq_taken` 的 take 身份从未被任何 handler 侧事件引用。

**harness 要做的最小 journal 改动**（任一条即可让上游连接变成 exact，交叉验证见 §5 的 `test_journaled_handler_origin_would_flip_the_same_audit_to_joinable`）：

1. 为 handler 执行的退休指令在 `cpu_retired_transaction_target_delivery` 上写 `registered_origins`（例如 `source_id="cpu.isr_instruction"` + 由 take 派生的 `admission_id`/`action_id`）并把 `registered_origin_status` 置 `known`；或
2. 在 `cpu_retire` / `cpu_retirement_match` 上增加 `irq_take_event_id`（= `cpu_irq_taken.event_id`）与 `handler_instance_id`（= `cpu_irq_taken.source_trigger.trigger_id`）；或
3. 为 ISR 镜像指令补 `source_admission`（`role=fixed_support`/`bootstrap`，把 pc 或镜像代号纳入 `input_sha256`/`path_id`），使现有 `retired_target_delivery` 规则可以直接命中。

在这之前，任何"ISR 写属于某条链"的说法都只能是 pc 区间分类 + 事件顺序，本报告的新证书显式拒绝这一外推。

## 4. 真实计数

### 4.1 十分钟 run（570,196 事件，zlib）

```bash
PYTHONPATH=src python3 scripts/report_isr_writeback_certificates.py \
  --run-dir runs/current-dataflow-p5-chain-600s-20261007-online \
  --output runs/current-dataflow-p5-isr-writeback-20261008-logs/isr_writeback_600s.json
```

| 指标 | 实测 |
|---|---:|
| trace | `zlib_chunks.v1`，570,196 事件，`semantic_sha256_verified=true` |
| P5 链证书 | 368 张；**27 certified**（`CPU_TO_IP_TO_CPU` 20、`IP_TO_CPU_TO_IP` 7），341 incomplete |
| **链可扩展数** | **0 / 27**（`not_joinable` 27、`no_anchor` 0） |
| GPIO A `PADOUT` 写验收 | 109（读 35 另计） |
| handler 区间内的 ISR `PADOUT` 写 | **68**（全部 pc `0x10228`；67 次写 1、1 次写 0） |
| 区间外（非 handler）`PADOUT` 写 | 41（计数，不出证书） |
| **ISR 写回全认证到第二次 `cpu_irq_input`** | **3**（access `gpio-access:gpio_a:0:5` / `0:7` / `0:14`；例：accept 33212 / commit 33229 / retire 33327 / match 33328 / delivery 33329 / input 33331 / observation 33362 / `gpio_b:0:trigger:9`） |
| ISR 写回 incomplete | 65（首个缺口：`binding_input_resource` 62、`bound_irq_trigger` 3；结算原因：`complete` 3 / `journal_end` 1 / `max_event_gap` 64） |
| 相邻/顺序回退 | **0** |
| 身份缓存淘汰 | **0** |
| 保留的 writeback 身份样本 | 68/68（上限 256，`writeback_records_dropped=0`，未截断） |

31 秒有界 run 上的同一结论：`isr_padin_retirement`（5618）与 ISR 写（6023/6024/6025）只相隔 405 个事件，顺序存在，身份不存在。

`binding_input_resource` 缺失 62 条的物理含义（不是缓存/界的问题，见 §2.4）：68 次 ISR 写里只有 6 次之后出现了新的 `gpio_input_applied_resource`，其余 62 次 `gpio_a.out` 位在本次写前后**没有变化**，A→B 绑定因此不产生任何新资源，也就不存在可连的第二次中断。这 6 次里 3 次产生了上升沿 trigger 并全认证，另 3 次有绑定资源但没有 trigger（首个缺口即 `bound_irq_trigger`）。

### 4.2 31 秒有界 run（31,795 事件，单文件 JSON）

| 指标 | 实测 |
|---|---:|
| P5 链证书 | 24 张；**8 certified**（CPU→IP→CPU 3、IP→CPU→IP 5） |
| **链可扩展数** | **0 / 8** |
| ISR `PADOUT` 写（pc `0x10228`） | 5（写 1 两次、写 0 三次） |
| 区间外 `PADOUT` 写 | 4 |
| **ISR 写回全认证** | **2**（access `gpio-access:gpio_a:0:5`、`gpio-access:gpio_a:0:7`） |
| ISR 写回 incomplete | 3（首个缺口均为 `bound_irq_trigger`：ISR 写 0，无上升沿；结算原因 `journal_end` 1 / `max_event_gap` 2） |
| 相邻/顺序回退 | 0 |
| 身份缓存淘汰 | 0 |

## 5. 交付物（全部新增，只读、附加）

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/isr_writeback_certificate.py` | 新模块：`IsrWritebackCertificates`（`isr_writeback_certificate.v1`，10 跳精确身份、一次结算、`max_pending`/`max_event_gap`/`max_writebacks`/`max_identities` 有界）＋ `audit_chain_extension`（`isr_writeback_chain_extension_audit.v1`，逐条候选身份给出 `exact`/`mismatch`/`absent`/`adjacency_only`/`classification_only` 与 `missing_identity`）。显式字段：`proof_scope = exact_handler_gpio_a_padout_commit_to_bound_second_irq_input`，`not_proof_of = (p5_chain_extension, chain_completion, handler_execution_attribution_to_the_certified_irq_take, isr_entry_or_trap_identity, event_adjacency_or_ordering, operand_taint_beyond_committed_register_versions)`；每张证书的 `chain_extension` 带 `decided_by="audit_chain_extension"`、`handler_origin_identity_present`（handler 写的来源身份是否存在）与 `missing_identity`，因此片段证书自己从不对链归属下结论。 |
| `scripts/report_isr_writeback_certificates.py` | 新 CLI：单次流式复算 P5 链证书（只读复用 `ChainCertificates`，报告中 `mutated=false`）＋ 新证书，输出 `isr_writeback_run_report.v1`（per-run 计数、逐链审计、ISR/越界写身份、`missing_identity`）。 |
| `tests/scenario/test_isr_writeback_certificate.py` | 18 个测试：合成 journal 的正/负例、无相邻回退、有界与一次性结算、链审计负例与"补上身份即翻转"的正例、无锚点链、片段证书不自行判定链归属、两个真实 run 的逐跳断言、CLI 报告契约。 |
| `runs/current-dataflow-p5-isr-writeback-20261008-logs/*.json` | 三个 run 报告产物（600s 默认界、600s `gap32768` 对照、acceptance）与对应 `.summary.txt`。 |

TDD：先写测试 → **RED**（`ModuleNotFoundError: No module named 'myfuzz.scenario.isr_writeback_certificate'`，1 error during collection）→ 实现 → **GREEN**：

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_isr_writeback_certificate.py -q -p no:randomly
# 18 passed
```

既有 `src/myfuzz/**`、`configs/**`、`rtl/**`、`third_party/**` 与既有脚本零改动；新模块不在任何在线路径的 import 链上（`grep -rn isr_writeback_certificate src/myfuzz/ --include=*.py` 只命中 `src/myfuzz/scenario/isr_writeback_certificate.py` 自身；引用者只有新 CLI 与新测试）。

## 6. 边界（不得外推）

- 新证书只证明：**handler 写的 GPIO A `PADOUT` 提交经 A→B 绑定形成了同一 trigger 的第二次 CPU IRQ 输入**。它不证明该 handler 写属于哪条 P5 链、不证明 handler 由哪次 `cpu_irq_taken` 进入、不证明操作数污点、不证明 mret 之后或第三次中断。
- `writer.classification` 里的 handler 区间来自 `initial_image: cpu.stream.isr` 的地址跨度，是**观测分类**，不是身份；证书用 `basis = declared_initial_image_span_observation_not_identity` 与 `not_proof_of` 显式标注。
- incomplete 证书是"第一个未见证跳及其后全部必需跳"，一次结算后不再被后续事件恢复；`settled_reason` 区分 `complete`/`journal_end`/`max_event_gap`/`max_pending`/`outside_declared_handler_span`。
- 本报告的两个 run 都是负载特定门禁（默认 Ibex＋双 PULP GPIO、seed `20261007`）；换外设或换 RFuzz 负载需重跑本 CLI。
- 分析器只统计 producer 发出的证书与它自己按精确身份复算的跳；它不独立重推既有 P5 链的 hop 级正确性（那由冻结 fixture 的逐字段断言保证）。
- 本次未发现自然 RTL 缺陷；"62 条 ISR 写不产生第二次中断"是 GPIO 值未变化的正常行为，不是缺陷。

## 7. 复现材料

- 十分钟 run：`runs/current-dataflow-p5-chain-600s-20261007-online/`（`online_events.zlib`、`online_final_trace.meta.json`、`online_plan.json`、`report.json`）。
- 有界 run：`runs/current-dataflow-p5-chain-acceptance-20261007-online/`（`online_final_trace.json`、`online_plan.json`）。
- 本次分析产物：`runs/current-dataflow-p5-isr-writeback-20261008-logs/isr_writeback_600s.json`（十分钟 run，默认界）、`.../isr_writeback_600s_gap32768.json`（`max_event_gap=32768`、`max_pending=512` 的边界敏感性对照）、`.../isr_writeback_acceptance.json`（31 秒 run），以及三份同名 `.summary.txt`。
- 上游边界原文：`docs/reports/current-dataflow-p5-chain-600s-20261007.md` §"证书语义（不得外推）"、`docs/CURRENT_PROGRESS.md` P5 段落。
- 既有终端跳 producer：`src/myfuzz/scenario/chain_certificates.py`（`CPU_TO_IP_TO_CPU` 13 跳、`IP_TO_CPU_TO_IP` 17 跳），本报告未改动它。
