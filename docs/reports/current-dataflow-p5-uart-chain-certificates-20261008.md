# P5 UART 链路证书（只读生产者）

日期：2026-10-08。本文交付一个**只读**的 UART 链路证书生产者：给定已保存的在线运行目录，流式读取 trace，为异构 OpenTitan UART 通路发出 `runtime_uart_chain_certificate.v1` 证书，并给出**每个候选的 incomplete 直方图**（首缺跳永远具名）。它补齐的是这样一个缺口：既有 [`myfuzz.scenario.chain_certificates`](../../src/myfuzz/scenario/chain_certificates.py) 只认 `gpio_b.external_pin8` 与 `cpu.online_instruction` 两类源，UART 运行既报 `certified=0` 也报 `incomplete=0`——**根本没有候选被跟踪**。

复现命令（只读；从不渲染 harness、从不启动 RTL／fuzz／Verilator，也从不写运行目录）：

```bash
PYTHONPATH=src python3 scripts/report_uart_chain_certificates.py \
  --run runs/p5-uart-waveform-gate-20261008-online \
  --json-out runs/current-dataflow-p5-final-20261007-logs/uart_chain_certificates.json   # exit 0
```

交付物：生产者 [`src/myfuzz/scenario/uart_chain_certificates.py`](../../src/myfuzz/scenario/uart_chain_certificates.py)、只读 CLI [`scripts/report_uart_chain_certificates.py`](../../scripts/report_uart_chain_certificates.py)、测试 [`tests/scenario/test_uart_chain_certificates.py`](../../tests/scenario/test_uart_chain_certificates.py)、产物 `runs/current-dataflow-p5-final-20261007-logs/uart_chain_certificates.json`（sha256 `1469849c9318d178dd42fa92970c13f75e5e3d36cad2f18bc9fb7e064ddd55aa`）。**未改动任何既有文件**（`chain_certificates.py` mtime 2026-10-07 13:52、`acceptance_metrics.py` mtime 2026-10-08 06:49，均早于本次会话的首次写入）。

## 真实数字（`runs/p5-uart-waveform-gate-20261008-online`）

trace 为单片 `online_final_trace.json`（274,782,641 字节，76,332 个事件，逐事件流式读取，峰值内存只保留有界缓存）。文档自述语义摘要**自校验通过**：`declared_semantic_sha256 == semantic_sha256_recomputed == 0bd295025f9f7740093c4a8ee9ff47b55812d41d9692911e02198f03eb35d528`，`semantic_sha256_verified=true`。

| 量 | 实测值 |
|---|---|
| `candidates_total` | 37（36 个 `fuzz_source` ＋ 1 个 `bootstrap` 走同一跳序列） |
| `certificates_total` | 37 |
| `certified_total` / `incomplete_total` | 7 / 30 |
| `first_missing_hop_histogram` | `{"uart_source_frame_begin": 30}` |
| `irq_mode_histogram` | `{"irq_taken": 7, "no_irq_witness": 30}` |
| `refusals_total` / `refused_hops` | **0** / `[]`（诚实 0：整条 trace 读完，没有一条 join 键被自相矛盾地触发） |
| `unresolved_total` | 0 |
| `duplicates_total` | 28（全部 `duplicate_uart_irq_assertion`：同一条目仍是队首时的后续水位断言，只记一次跳） |
| `skipped_total` | 240（全部 `non_watermark_uart_irq_update`：`rx_overflow/rx_frame_err/...` 等其它 IRQ 类别，不属本通路） |
| `expired_total` / `evicted_total` / `contradicted_total` / `late_events_after_settlement` | 0 / 0 / 0 / 0 |
| `self_consistent` | true（8 项自检全 ok） |

每跳证书级见证数（`witness_counts`，即携带该跳的证书数）：`uart_source_admission`/`uart_source_injection`/`uart_frame_admission` 各 37；其余 13 跳各 7。事件级计数（`hop_event_counts`）：`source_admission=37`、`source_injection=37`、`uart_source_frame_admission=37`、`uart_source_frame_begin=7`、`uart_rx_receiver_start=7`、`uart_rx_receiver_complete=7`、`uart_fifo_push=7`、`uart_irq_update=62`（全部 302 条 `uart_irq_update` 中的 `rx_watermark` 类）、`uart_source_frame_end=7`、`uart_frame_validation=7`、`native_irq_binding_delivery=13576`、`cpu_external_irq_sample=5888`、`cpu_external_irq_taken=7`、`uart_fifo_pop=7`、`uart_rdata_access=7`、`uart_retired_read_match=7`。代码**没有任何期望常数**：7 与 30 都是数出来的。

7 张 certified 证书（`certificate_id = sha256(["IP_TO_CPU", admission_id, frame_id])`）：

| frame | source case / role | endpoint case（消费侧） | entry_id | byte | irq_update | irq_taken | fifo_pop | rdata_access | retired_read_match | source_output_key |
|---|---|---|---|---|---|---|---|---|---|---|
| `uart-frame:0:1` | `uart-fixed-warmup` / bootstrap | `online-1-…`（case 2） | `["uart",0,0,2]` | 90 | 7276 | 7884 | 13698 | 13710 | 13762 | `["uart",0,"rx_watermark",7]` |
| `uart-frame:0:2` | `online-0-…` / fuzz_source | `online-10-…`（case 11） | `["uart",0,0,4]` | 0 | 21244 | 21271 | 23835 | 23847 | 23899 | `["uart",0,"rx_watermark",16]` |
| `uart-frame:0:3` | `online-4-…` | `online-19-…` | `["uart",0,0,6]` | 197 | 31354 | 31381 | 34099 | 34111 | 34163 | v27 |
| `uart-frame:0:4` | `online-5-…` | `online-28-…` | `["uart",0,0,8]` | 198 | 41335 | 41362 | 44171 | 44183 | 44235 | v34 |
| `uart-frame:0:5` | `online-6-…` | `online-37-…` | `["uart",0,0,10]` | 200 | 51344 | 51371 | 54246 | 54258 | 54310 | v41 |
| `uart-frame:0:6` | `online-8-…` | `online-46-…` | `["uart",0,0,12]` | 202 | 61378 | 61405 | 64365 | 64377 | 64429 | v48 |
| `uart-frame:0:7` | `online-10-…` | `online-55-…` | `["uart",0,0,14]` | 204 | 71518 | 71545 | 74571 | 74583 | 74635 | v55 |

30 张 incomplete 的证书都停在同一步：`uart_source_admission → uart_source_injection → uart_frame_admission` 三跳有精确见证，第 4 跳 `uart_source_frame_begin` 从未出现，因此 `first_missing_hop=uart_source_frame_begin`、`settled_reason=journal_end`；它们的 `endpoint_case_id=null` 且 `endpoint_case_reason="endpoint_case_not_witnessed"`、`cross_case=null` 且 `cross_case_reason="endpoint_case_unknown"`、`polling_consistent=null` 且原因是 `read_chain_not_witnessed`——**未知一律 null＋原因，绝不写 0**。

## 跳序列与偏序（已冻结在模块里）

`UART_HOPS`（声明顺序，也是 `hops` 的排列顺序）：

```
uart_source_admission → uart_source_injection → uart_frame_admission →
uart_source_frame_begin → uart_rx_receiver_start → uart_rx_receiver_complete →
uart_fifo_push → uart_irq_update → uart_source_frame_end → uart_frame_validation →
uart_irq_binding_delivery → uart_cpu_irq_sample → uart_cpu_irq_taken →
uart_fifo_pop → uart_rdata_access → uart_retired_read_match
```

**顺序不是"严格按事件号线性递增"，而是声明 DAG（`UART_HOP_ORDER`，17 条边＋传递闭包）**：只有写入 DAG 的边才被强制（违者按 `hop_out_of_order` 拒绝并计数），未写边的跳对不比较事件号。这是实测逼出来的，不是设计偏好：

- `uart_irq_update` 的见证事件在 `uart_source_frame_end` 之前（frame 1：7276 < 7372；frame 2：21244 < 21372），因为水位 IRQ 在字节入队后立刻拉高，而 frame_end 在整帧结束时才记账；同时该跳**只能**在 `cpu_external_irq_taken` 给出 `source_output_key` 后才可识别（`input_context.source_output_key` → `uart_irq_output_definition` → `irq_update_event_id`），所以它是**回填插入**到已记录跳之间，插入合法性由邻跳事件号边界检查保证。
- 反过来，CPU IRQ 确认腿可以**早于**同一帧的 frame_end/validation：frame 2 的 `delivery=21268 / sample=21270 / take=21271` < `frame_end=21372 / validation=21374`，而 frame 1 是 `validation=7374` < `delivery=7881`。两种交错都真实存在，所以这四对关系**故意不约束**。

每跳的 join 全部是字面身份，无邻接、无计数、无架构学推测：

| 跳 | 精确 join 键 |
|---|---|
| `uart_source_admission` | `admission.admission_id/action_id/component=uart/direction=IP_TO_CPU/source_id=uart.external_rx_byte/input_kind=source_event`，`role ∈ {fuzz_source, bootstrap}`，`provenance.origin_status=known` 且 `origin_admission_ids==[admission_id]`，`observed_case` 与 admission 一致 |
| `uart_source_injection` | `action_id` ＋ `port=uart_rx_byte` ＋ `direction=IP_TO_CPU` ＋ `bit_offset=0` ＋ `origin_admission_ids==[admission_id]`；`value` 与后续 byte 互校 |
| `uart_frame_admission` | `frame_id` ＋ `action_id` ＋ `origin_admission_ids==[admission_id]` ＋ `byte` |
| `uart_source_frame_begin/end` | `frame_id` ＋ `port` ＋（end）`byte` ＋ `waveform_matched is True` |
| `uart_rx_receiver_start` | `input_ref.frame_id/action_id/admission_id` ＋ `receiver_id` |
| `uart_rx_receiver_complete` | `receiver_id` ＋ `frame_error==0` ＋ `parity_error==0` ＋ `value` |
| `uart_fifo_push` | `entry_id`（`[uart,epoch,generation,sequence]`）＋ `frame_id` ＋ `receiver_id` ＋ `completion_event == complete.observation_event_id` ＋ `value` ＋ `retained is True` |
| `uart_irq_update` | take 的 `source_output_key` → definition 的 `source_output_key`；definition 的 `irq_update_event_id` 必须命中已见的 `uart_irq_update`（`post_output` 与 `pre_entry_ids` 逐字相等）；该条目的 entry_id 必须是 `pre_entry_ids[0]`（队首） |
| `uart_source_frame_end` / `uart_frame_validation` | `frame_id` ＋ `action_id` ＋ `admission_id`（validation 独有）＋ `byte == push.value` |
| `uart_irq_binding_delivery` | take 的 `binding_delivery_event_id` → delivery，且 `source_output_key` 相等、`value==1`、`source_port=uart_rx_watermark`、`target_port=irq`、`width=1`、两个 bit offset 为 0、`target_component/target_epoch` 与 CPU 一致 |
| `uart_cpu_irq_sample` | take 的 `sample_event_id` → sample，且 `component/reset_epoch/local_tick/command_scope/receipt_id` 与 take 逐字相等，`expected_input=actual_pre_input=actual_post_input=1`、`irq_masked_pre=0`、`irq_taken_pre=1`、`binding_delivery_event_id` 与 `source_output_key` 相等 |
| `uart_cpu_irq_taken` | `input_context` 六字段自洽（schema/`binding_delivery_event_id`/`expected_input`/`source_output_key`/`target_component`/`target_epoch`）＋ `take_key` |
| `uart_fifo_pop` | `entry_id` → push；`value == push.value`；`access.access_id/source_transaction` 合法且 `raw_offset=24`、`write=False`、`byte_enable=15` |
| `uart_rdata_access` | `actual_request_event_id == pop.observation_event_id`；`access_id`、六字段 `source_transaction`、`address`、`read_value` 与 pop 逐字相等；`address == window_base+24`、`error=0` |
| `uart_retired_read_match` | `status=accepted`＋`proof_scope=cpu_retired_uart_rdata_read`；`entry_id`/`frame_id`/`read_value` 与 push/access 相等；`uart_access_event_id`/`uart_request_event_id`/`uart_response_event_id` 命中该 access；`fullkey == access.source_transaction`；`source_admission.admission_id` 命中该 admission；`cpu_scope.source_component/source_epoch` 与该证书的 CPU take 一致 |

## IRQ→CPU：只报证据，不报因果

`irq_mode` 三态由证据决定：`irq_taken`（四跳全见证，7 例）、`irq_asserted_no_take`（水位已断言且该条目为队首，但没有 join 上的 take）、`no_irq_witness`（无任何断言把该条目列为队首，30 例）。`polling_consistent` 只在"读链完整但无 join 上的 take"时为 `true`，且 `not_proof_of` 明写"**不证明 CPU 取过中断**"。take 归因只走一条路径：`input_context.source_output_key` → definition → `pre_entry_ids[0]`（队首）→ `entry_id` → 候选；也就是说，只有当这次外部中断交付的水位输出**确实把这一条目排在队首**时才归因，绝不因为"IRQ 在附近"而归因。帧 2 的 `irq_assertion_keys` 显示版本 v15→v18（`irq_assertion_key_count=6`），证书记录的是 CPU 实际观测到的那一版（take 的 `source_output_key=v16`），跳证据里的 `source_output_key`（v15，首次断言）与 take 版本并存但都具名。

## 边界（本产物**不**证明什么）

- **不证明 DUT 没有其它行为**：证书只覆盖已保存 trace 内的见证链；每个证书的 `proof_scope=saved_artifact_uart_witness_chain`，`not_proof_of` 7 条逐项列出。
- **不证明字节本身的因果**：水位中断的 join 是"该条目在 `pre_entry_ids` 中位列队首"，不等于"这一字节单独造成了中断"（阈值可能由多个队内条目共同满足）。
- **不证明没有发生的 IRQ**：30 张 incomplete 只说明"该 frame 的 `uart_source_frame_begin` 及之后没有出现"，不说明运行中不存在其它中断；`cpu_external_irq_sample` 有 5,888 条、`native_irq_binding_delivery` 有 13,576 条，其中只有 7 条被 take 精确归因到本通路的队首条目。
- **不证明轮询**：`polling_consistent=true` 只是"读链完整且没有 join 上的 take"这一证据状态，不是"CPU 轮询"的证明（本产物里 30 张 incomplete 的该字段是 `null`，7 张 certified 是 `false`）。
- **不证明跨例因果**：7 张 certified 的 `cross_case=true` 只说明 `source_case_id != endpoint_case_id`（源 admission 例与消费例确实不同）；`cross_case=false` 只在两侧 case 逐字相同时给出，缺一侧则 `null`＋原因。
- **不证明 ISR/操作数/写回语义**：只到 `uart_retired_read_match` 指名的那条已退休加载（本运行 `insn=25207171`、`pc=66096`、`destination_register=3`）。
- **有界保留的边界**：证书文档最多保留 `max_certificates=2048` 份（`certificates_truncated` 会置位，计数不受影响）；身份索引每条最多 `max_identities=4096`，因此对已结算身份的"迟到矛盾"识别只在该保留窗口内有效（本运行窗口未溢出，`late_events_after_settlement=0`）。
- **不覆盖非 UART 通路**：`gpio_b.external_pin8` 与 CPU 指令链仍由既有 `chain_certificates` 负责；本模块不读取、不修改它的任何语义。

## 自检、确定性与测试

CLI 只有在"扫描完成且每张证书自洽"时 exit 0：`self_consistency_checks` 覆盖候选记账、状态域、certified 跳完整、incomplete 必有 `missing_hops`、`first_missing_hop == missing_hops[0]`、enforced 边事件号严格递增、首缺直方图与证书一致、拒绝计数与保留样本一致。读错误（无 trace／契约不符／自检失败）exit 1，用法错误 exit 3。同一产物连跑两次输出**逐字节相同**（两次 sha256 均 `1469849c…`）；文档正文不含任何墙钟或运行 id。

`limit` 全部显式声明在文档 `limits` 里：`max_pending=128`（最老候选以 `settled_reason=evicted_by_max_pending` 结算）、`max_event_gap=65536`（进度窗口，超窗以 `event_gap_exceeded` 结算）、`max_identities=4096`、`max_certificates=2048`、`max_refusal_samples=64`。

测试（TDD：先写测试看到 RED，再实现看到 GREEN）：

- RED（模块缺失）：`ModuleNotFoundError: No module named 'myfuzz.scenario.uart_chain_certificates'`（collection error）；随后断言级 RED 依次暴露 11 项失败（例如把 frame_validation 的 byte 改掉时期望"拒绝而非接受"、`missing_hops` 的冻结截断语义、淘汰时误 pop 候选导致证书丢失）。
- GREEN：`tests/scenario/test_uart_chain_certificates.py` **32 passed**；回归 `tests/scenario/test_chain_certificates.py` **50 passed**。仓库中不存在 `tests/scenario/test_acceptance_metrics.py`（该文件名在本仓库没有对应文件），因此以直接使用 `myfuzz.scenario.acceptance_metrics` 的 `tests/scenario/test_p5_arm_metrics.py` 作为替代回归：**32 passed**。
- 单测全部使用测试内构造的合成 UART trace（可同时写成 `online_events.jsonl` 与单片 `online_final_trace.json`，两者产出相同证书），不依赖本文的真实运行目录；覆盖满链发出、缺跳→incomplete＋首缺具名、矛盾 join→拒绝（不是接受）、两次运行逐字节一致、`max_pending`/`max_event_gap` 有界、`null`＋reason（而非 0）、CLI 三种退出码。
