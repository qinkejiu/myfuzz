# P4 通用消费端证书：声明式设备内部见证登记表

日期：2026-10-08。此前 shipped 的 `computed_value_certificate.v1`（[报告](current-dataflow-p4-computed-value-certificates-20261007.md)）把消费终点硬编码为 4 种外设形状；[UART `0x0c` 字节审计](current-dataflow-p4-computed-uart-store-audit-20261007.md)另用固定指令片段复现了一个字节。本报告补上剩余缺口：**通用消费端**——终点由**声明的见证登记表**驱动，证书只在每一跳都按**精确身份**连接成功时发出；否则给出**点名第一处缺失跳与第一个缺失身份键**的显式拒绝；设备在本 artifact 中完全没有声明见证证据时给出带原因的 `unknown`，而不是一个伪造的 0。

本轮**未运行任何 Verilator/RTL/fuzz 作业**：全部数字来自既有冻结 artifact 经 shipped 有界视图 `TraceEventStream` 的只读流式复算（8 份 run 的 `semantic_sha256` 全部复核为 True）。

## 交付

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/computed_consumer_certificates.py`（新增） | `ComputedConsumerCertificates`，输出 `computed_consumer_certificate.v1`；声明式 `WITNESS_REGISTRY`。**不在在线运行路径上**：`grep -rn computed_consumer_certificates src scripts` 除自身外无任何引用 |
| `scripts/report_computed_consumer_certificates.py`（新增） | 只读 CLI；缺 artifact / 摘要不符 / 无 RVFI 退休 → `unknown` + 原因 + **退出码 3**，绝不输出伪造 0 |
| `tests/scenario/test_computed_consumer_certificates.py`（新增） | 43 项 TDD（先 RED 后 GREEN），含每种见证的精确身份链、拒绝/未知路径、有界淘汰、确定性、真实 run 只读 |
| `docs/reports/current-dataflow-p4-computed-consumer-generic-20261008/*.json`（新增） | 8 份真实 run 的 CLI 原始输出（`gpio-runs.json`、`uart-runs.json`、`p3-lane-selectivity2.json`、`p5-chain-600s.json`）与 `witness-registry.json` |

## 判定管线（三跳，全部 fail-closed）

1. **`rvfi_compute`（起点）**：`cpu_retire` 且 `trap==0`、`valid==1`、`phase=='post'`、`rd != x0`，且 **`rd_wdata` 必须等于用 `insn + rs1_rdata` 重算的值**（LUI/OP-IMM 算术与 SLLI/SRLI/SRAI；保留 `funct7` 一律拒绝，`rd_addr`/`rs1_addr` 必须与编码一致）。
2. **`mmio_store_route`（传播）**：`mmio_acceptance`/`mmio_delivery`/`gpio_target_receipt` 锚点与 `data_accept`/`data_response` 延伸，必须同属**一个 6 字段 `TransactionKey`**（`execution_id`/`source_epoch` 与退休一致），逐跳要求 byte-enable 相同、**被使能 lane 的字节**相同、offset/address 相同、`event_id` 严格递增且相邻 ≤ `max_event_gap`。
3. **`device_consumption`（终点，声明式）**：见下表。每个见证 kind 声明：事件 kind（或原始观测形状）、承载值的字段路径（`word` / 32 位 `bit_list` 重组 / `lane_byte`）、可连接的**精确身份键**、允许的 `status`、能否连接、优先级。

只有**所有**声明的身份键都命中、值在被使能 lane 上一致，才发出证书；一条链可以命中多个见证，结算时（到期 / 容量淘汰 / `flush`）取**声明优先级最高**的那个作为证书终点，并把全部命中见证列在 `witnesses` 里。任何缺失/不匹配都会在链上记录**流序中的第一处**缺失：

* 见证 kind 不可连接（声明 `joinable=False`）→ 拒绝，入 `witness_unjoinable_rejections`；
* `status` 不在声明白名单 → 拒绝，入 `witness_status_rejections`；
* 门控字段/探针不符（如 APB `psel/penable/pwrite/pwdata/pready/pslverr/apb_addr`）→ `witness_gate_rejections`；
* 身份键缺失/不等、lane 值不等 → `witness_join_failures`（按身份键分别计数）；
* 设备**没有任何声明见证 kind** → `unknown` + `no_declared_witness_kind_for_device:<comp>`，`missing_hop=null`，计入 `unknown` 而**不是** 0。

有界保留与逐项计数：`max_pending=64`、`max_event_gap=4096`、`max_value_history=256`、`max_records=256`、`max_witnesses=8`；计数器含 `value_history_evicted`、`chain_capacity_expired`、`chains_expired_by_event_gap`、`refusal_records_evicted`、`unknown_records_evicted`、`witness_history_evicted`、`witness_join_failures`、`witness_status_rejections`、`witness_gate_rejections`、`witness_unjoinable_rejections`、`witness_events_without_pending_chain` 等。日志必须 `event_id` 连续：gap / 回退 / reset barrier 取消全部候选，证书永不跨 gap 或 reset。

## 见证登记表（`WITNESS_REGISTRY`，声明即事实）

| 见证 kind | 事件 kind / 形状 | 组件 | 值字段（语义） | 精确身份键 | 可连接 | 优先级 | 允许 status |
|---|---|---|---|---|---|---|---|
| `gpio_register_commit` | `gpio_register_commit` | gpio_a, gpio_b | `write_value`(word); `post_value`(word); `bit_resources.[].value`(bit_list，逐位 `transaction` 必须等于存储事务) | `fullkey`→store_transaction_key; `component`→routed_device; `raw_offset`→store_offset; `observation_event_id`→已认证设备总线跳（可选，`device_access_hop_present`） | 是 | 40 | observed |
| `gpio_consumption_match` | `gpio_consumption_match` | gpio_a, gpio_b | `proof_resource.[].value`(bit_list，逐位 `transaction`) | `fullkey`→store_transaction_key; `component`→routed_device; `raw_offset`→store_offset（可选，该形状常无 offset） | 是 | 35 | accepted, unknown（rejected/incomplete 永不连接；origin 血统不属于本证明） |
| `gpio_apb_access` | `gpio_apb_access` | gpio_a, gpio_b | `wdata`(word) | `source_transaction`→store_transaction_key; `component`→routed_device; `raw_offset`→store_offset | 是 | 20 | observed |
| `gpio_register_read` | `gpio_register_read` | gpio_a, gpio_b | `read_value`(word); `post_value`(word) | `fullkey`→store_transaction_key（这是**读**事务键）; `component`→routed_device | 是 | 25 | observed |
| `uart_tick_observation_access` | `uart_tick_observation`（必须带 `access` 且 `access.write`） | uart | `access.delivery_context.value`(word) | `access.source_transaction`→store_transaction_key; `access.delivery_context.source_transaction`→store_transaction_key; `component`→routed_device; `access.raw_offset`→store_offset; `access.delivery_context.be`→store_byte_enable | 是 | 30 | — |
| `uart_serial_observation` | 原始外设观测（无 `kind`，`outputs.serial_tx_count/serial_tx_last`） | uart | `outputs.serial_tx_last`(lane_byte，必须是地址 lane 上的字节) | `component`→routed_device; `outputs.serial_tx_count`→serial_counter_increment（需投递前已观测 baseline，且计数恰好 +1、前一采样计数等于 baseline） | 是 | 50 | — |
| `uart_rdata_access` | `uart_rdata_access` | uart | `read_value`(word); `read_capture.post.probe_uart_fifo_data`(word) | `delivery_context.source_transaction`→store_transaction_key（**读**事务键）; `component`→routed_device; `raw_offset`→store_offset | 是 | 22 | — |
| `uart_fifo_pop` | `uart_fifo_pop` | uart | `value`(word) | `access.source_transaction`→store_transaction_key（`pop` 只带**读**访问事务）; `component`→routed_device; `access.raw_offset`→store_offset | 是 | 15 | — |
| `uart_fifo_push` | `uart_fifo_push` | uart | `value`(word) | `source_transaction`→store_transaction_key（**该形状不携带此字段**）; `component`→routed_device | **否**：`device_internal_fifo_entry_token_carries_no_store_transaction_key` | 15 | — |
| `gpio_pad_observation` | 原始外设观测（`outputs.gpio_out/rdata`） | gpio_a, gpio_b | `outputs.gpio_out`(word); `outputs.rdata`(word) | `source_transaction`→store_transaction_key（**该形状不携带**）; `component`→routed_device | **否**：`raw_pad_sample_has_no_transaction_key_adjacency_only` | 10 | — |
| `spi_transfer` | `spi_transfer` | spi0, spi, spi_host, spi_device | `value`(word) | `source_transaction`→store_transaction_key; `component`→routed_device; `raw_offset`→store_offset | 是 | 30 | — |
| `timer_tick` | `timer_tick` | timer, rv_timer, timer_interrupt | `value`(word) | 同上 | 是 | 30 | — |

`spi_transfer`、`timer_tick` 属于 `ABSENT_WITNESS_KINDS`：框架支持但**所研究的 8 份 artifact 里没有任何 producer**。落在这类设备上的链会被拒绝并点名 `device_consumption:spi_transfer`，reason 为 `declared_witness_kind_absent_from_artifact`，**不会**因为“没见过”而伪造 0 证书或 `unknown`（见下文实测）。

## 真实实测（8 份冻结 run，只读流式）

| run | 设备族 | 事件 | RVFI 退休 | certified | refused | unknown | 证书 kind |
|---|---|---:|---:|---:|---:|---:|---|
| `runs/p4-shift-fuzz-20261007-online` | GPIO | 118,963 | 583 | **33** | 105 | 0 | gpio_register_commit 32、gpio_apb_access 1 |
| `runs/p3-lane-selectivity2-20261007-online` | GPIO | 168,917 | 718 | **30** | 145 | 0 | gpio_register_commit 29、gpio_apb_access 1 |
| `runs/current-dataflow-p5-chain-600s-20261007-online` | GPIO | 570,196 | 2,357 | **113** | 206 | 0 | gpio_register_commit 112、gpio_apb_access 1 |
| `runs/current-dataflow-p5-fault-calibration-20261007-online` | GPIO | 5,858 | 43 | **6** | 16 | 0 | gpio_register_commit 5、gpio_apb_access 1 |
| `runs/p5-uart-gate2-20261007-online` | UART | 18,620 | 106 | **3** | 15 | 0 | uart_tick_observation_access 2、**uart_serial_observation 1** |
| `runs/p3-capacity-probe-paired-20261007` | UART | 16,492 | 88 | **2** | 9 | 0 | uart_tick_observation_access 2 |
| `runs/current-dataflow-p4-sb-final-online-20261007` | UART | 63,830 | 389 | **3** | 16 | 0 | uart_tick_observation_access 2、**uart_serial_observation 1** |
| `runs/current-dataflow-p4-uart-sb-real-online`（被 `harness_failure` 截断） | UART | 39,677 | 240 | **2** | 16 | 0 | uart_tick_observation_access 2 |

合计：**certified 192 / refused 528 / unknown 0**（8 份 run 全部 `status="ok"`，`semantic_sha256` 全 True）。与 v1 对照：`p4-shift-fuzz` 33 vs 33、`p3-lane-selectivity2` 30 vs 30、`p4-sb-final` 3 vs 3（含 1 条串口字节）、`p4-uart-sb-real` 2 vs 2——通用消费者**独立复现**了 v1 的计数，但终点构成更细（见下）。

### 按见证 kind 汇总（8 份 run 合计）

| 见证 kind | 出现 run | 事件数 | 证书 | 命中(joined) | 被拒绝 | 身份不符 | status 拒绝 | 门控拒绝 | 不可连接拒绝 | 无挂起链 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `gpio_register_commit` | 4 | 186 | **178** | 178 | 0 | 102 | 0 | 0 | 0 | 0 |
| `gpio_apb_access` | 4 | 437 | **4** | 182 | 0 | 98 | 0 | 26 | 0 | 225 |
| `gpio_consumption_match` | 4 | 166,564 | **0** | 126 | 0 | 83 | 9,948 | 0 | 0 | 157,627 |
| `gpio_register_read` | 4 | 251 | **0** | 0 | 0 | 26 | 0 | 0 | 0 | 225 |
| `gpio_pad_observation` | 4 | 36,968 | **0** | 0 | 0 | 0 | 0 | 0 | 16,855 | 23,592 |
| `uart_tick_observation_access` | 4 | 14,340 | **8** | 40 | 0 | 16 | 0 | 4,989 | 0 | 11,168 |
| `uart_serial_observation` | 4 | 14,220 | **2** | 2 | 2 | 573 | 0 | 0 | 0 | 11,088 |
| `uart_fifo_pop` | 4 | 10 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 10 |
| `uart_fifo_push` | 4 | 10 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 10（声明不可连接） |
| `uart_rdata_access` | 4 | 10 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 10 |
| `spi_transfer` | **0** | 0 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0（`absent_from_artifact`） |
| `timer_tick` | **0** | 0 | **0** | 0 | 0 | 0 | 0 | 0 | 0 | 0（`absent_from_artifact`） |

### 拒绝：第一处缺失跳 / 第一个缺失身份

| 缺失跳 | 次数 | 第一个缺失身份 | 次数 | 含义 |
|---|---:|---|---:|---|
| `mmio_store_route` | 522 | `store_transaction_key` | 522 | 已算出值但**从未到达任何存储事务**（`computed_value_never_reached_a_store`） |
| `rvfi_compute` | 4 | `computed_value_history` | 4 | 有存储事务但窗口内没有 lane 值匹配的 RVFI 计算退休（`no_matching_computed_value_within_max_event_gap`） |
| `device_consumption:uart_serial_observation` | 2 | `serial_counter_increment` | 2 | 已投递但串口采样没有“投递前 baseline + 恰好 +1”（`no_observed_serial_baseline` 等） |
| 合计 | **528** | | **528** | |

### 代表链（真实事件 id 与键）

* **GPIO 寄存器提交**（`p4-shift-fuzz`，第 1 条）：`cpu_retire 194`（`addi x2,x0,0x101`，pc 0x10084）→ `mmio_acceptance 267` → `data_accept 269` → `gpio_target_receipt 300` → `gpio_apb_access 304` → **`gpio_register_commit 306`** → `mmio_delivery 313` → `data_response 332` → `gpio_consumption_match 368`（该 match 行也精确命中并入 `witnesses`，但优先级 35 < 40，证书终点仍是 commit）；`store_value=0x101`，`enabled_lanes=[0,1,2,3]`，`lane_values={0:0x01,1:0x01,2:0x00,3:0x00}`，身份键全部 `matched`（含 `certified_upstream_hop_event_id=304`）。除多出的 368 外与 v1 报告代表链逐事件一致。
* **UART 串口字节**（`p4-sb-final`，独立复现既有审计）：`cpu_retire 25068`（`ADDI x2,x2,12` → `0x0c`，pc 69656）→ `mmio_acceptance 25121` → `data_accept 25122` → `uart_tick_observation_access 25132/25133/25141/25149`（off 28）→ `mmio_delivery 25150` → `data_response 25176` → **`uart_serial_observation 28002`**（`serial_tx_count 0→1`、`serial_tx_last=0x0c`、lane 0）。事件号与字节和[审计文档](current-dataflow-p4-computed-uart-store-audit-20261007.md)完全一致；通用消费者把它记为 `witness_kind=uart_serial_observation`（声明优先级 50 高于 access 的 30），并把 5 个命中见证列入 `witnesses`。
* **UART 串口字节（新）**（`p5-uart-gate2`）：`cpu_retire 14496` → … → `uart_serial_observation 18060`，`store_value=0x0cc3b006`，lane 0 字节 `0x06`，`serial_tx_count 0→1`。
* **GPIO APB 访问终点**：每份 GPIO run 恰有 1 条链的最强见证是 `gpio_apb_access`（该事务没有等到 `gpio_register_commit`），例如 `p4-shift-fuzz` 的 `cpu_retire 584` → … → `gpio_apb_access 654`（PASS 探针 `psel/penable/pwrite/pwdata/pready/pslverr/apb_addr` 全等）。

### 拒绝与未知的“精确点名”示例

* FIFO 内部 token 不能连接：`p4-sb-final` 观测到 5 次 `uart_fifo_push`、5 次 `uart_fifo_pop`、5 次 `uart_rdata_access`，全部发生在**没有挂起链**的时刻（`events_without_pending_chain`），因此 0 证书、0 拒绝；一旦链挂起，`uart_fifo_push` 会以声明理由 `device_internal_fifo_entry_token_carries_no_store_transaction_key` 被拒绝，`uart_fifo_pop`/`uart_rdata_access` 会以 `store_transaction_key` 不等被拒绝（读事务 ≠ 存储事务）。
* 原始 pad 采样永不“邻接连接”：`p4-shift-fuzz` 5,418 次 `gpio_pad_observation`，3,259 次在有挂起链时被拒绝（`witness_unjoinable_rejections`），即使 `gpio_out` 与存储值相同也不产生证书。
* 寄存器回读不是提交：`gpio_register_read` 共 251 次，身份不符 26 次（读事务键 ≠ 存储事务键），0 证书。
* `gpio_consumption_match` 共 166,564 次：**126 次真正命中**（shift-fuzz 32、lane-selectivity2 29、chain-600s 60、fault-calibration 5；均因优先级低于 commit/apb 而未成为证书终点），9,948 次因 `status` 为 `rejected`/`incomplete` 被声明白名单（accepted/unknown）拒绝，其余无挂起链。
* **未知路径**：若链落在没有任何声明见证 kind 的设备上（如 `i2c0`），结果为 `status="unknown"`、`reason="no_declared_witness_kind_for_device:i2c0"`、`missing_hop=null`，计入 `unknown`；**run 级**缺 artifact / 摘要不符 / 无 RVFI 退休时 CLI 输出 `certified/refused/unknown` 全为 `null` 并以**退出码 3** 失败关闭，例如：
  `PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py runs/no-such-run` → `unknown evidence for runs/no-such-run: artifact_unavailable:run directory does not exist`，exit 3。

## 诚实边界：本证书**没有**证明什么

每条记录（certified / refused / unknown）都强制携带 `proof_scope` 与 `not_proof_of`：

* **不是寄存器堆内部来源 token**：没有证明该值来自哪个物理寄存器版本，只证明 RVFI 退休值 = 设备见证值。
* **不是设备内部寄存器/FIFO 血统**：`gpio_register_commit`/`uart_tick_observation` 的值同一性不代表设备内部 FIFO/序列化路径的逐位因果；`uart_fifo_push/pop` 正因为只有 `entry_id`/`frame_id` 而没有存储事务键，被声明为**不可连接**并拒绝。
* **不是跨指令数据依赖 / 控制流依赖**：没有证明算出的寄存器随后确被那条 `SB`/`SW` 当作 rs2 读取（v1 的“该值确被后续指令使用”同样不在此证明内）。
* **不是消费逻辑正确性**：不证明外设行为、寄存器映射或固件逻辑正确。
* **不是地址路由归属**：不证明 MMIO 解码/路由归属，只使用 trace 里已记录的路由结果。
* **串口字节并非 FIFO 内部证明**：`uart_serial_observation` 依赖“投递前观测到的 baseline + 计数恰好 +1 + 该 lane 字节相等 + 事件顺序”，属于观测关联，不含 UART TX FIFO 内部 token；计数未推进的采样被记为 `deferred`，既不连接也不消耗一次性归属。
* **原始 pad 采样无身份键**：`gpio_pad_observation` 只计数（16,855 次拒绝），永不产生证书。
* **SPI / timer 无 producer**：8 份 artifact 中 0 次出现，登记为 `absent_from_artifact`；落在这类设备的链给出 `declared_witness_kind_absent_from_artifact` 拒绝并点名 hop，绝不用 0 冒充“已验证没有”。
* 未覆盖：宽度 > 4B 的多 beat 存储、压缩指令、向量/浮点、跨 testcase 的 CPU scope；证书只覆盖**被使能 lane 的字节**。
* 该消费者**尚未接入** `acceptance_metrics` 的在线通路（本轮交付的是只读复算工具 + 离线模块）。

## 复现命令

```bash
# TDD（先 RED：ModuleNotFoundError: myfuzz.scenario.computed_consumer_certificates；后 GREEN：43 passed）
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
  tests/scenario/test_computed_consumer_certificates.py -q -p no:randomly

# 只读 CLI（8 份 run 的完整 JSON 见 docs/reports/current-dataflow-p4-computed-consumer-generic-20261008/）
#   gpio-runs.json       = p4-shift-fuzz + p5-fault-calibration
#   p3-lane-selectivity2.json / p5-chain-600s.json = 另外两份 GPIO run
#   uart-runs.json       = 四份 UART run
PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py \
  runs/p4-shift-fuzz-20261007-online \
  runs/current-dataflow-p5-fault-calibration-20261007-online \
  --sample 3 --output docs/reports/current-dataflow-p4-computed-consumer-generic-20261008/gpio-runs.json

PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py \
  runs/p3-lane-selectivity2-20261007-online \
  --sample 2 --output docs/reports/current-dataflow-p4-computed-consumer-generic-20261008/p3-lane-selectivity2.json

PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py \
  runs/current-dataflow-p5-chain-600s-20261007-online \
  --sample 3 --output docs/reports/current-dataflow-p4-computed-consumer-generic-20261008/p5-chain-600s.json

PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py \
  runs/p5-uart-gate2-20261007-online runs/p3-capacity-probe-paired-20261007 \
  runs/current-dataflow-p4-sb-final-online-20261007 \
  runs/current-dataflow-p4-uart-sb-real-online \
  --sample 3 --output docs/reports/current-dataflow-p4-computed-consumer-generic-20261008/uart-runs.json

# 登记表本身（确定性 JSON，可 diff）
PYTHONPATH=src python3 scripts/report_computed_consumer_certificates.py --registry-only
```

## 声明

本轮全部结论来自既有保存 artifact 的只读流式复算（`TraceEventStream`，有界内存），`semantic_sha256_verified` 在 8 份 run 上均为 True；**未启动任何 Verilator/RTL/fuzz 作业**，未修改任何既有 `src/myfuzz/**`、`configs/**`、`rtl/**`、`third_party/**` 或既有脚本。
