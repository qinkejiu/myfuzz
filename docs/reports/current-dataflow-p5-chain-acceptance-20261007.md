# P5 首步端到端验收入口与严格完整链/s 门禁

日期：2026-10-07。目标是补上 P5 长期缺失的量：**严格完整真实传播链/s**。此前[600 秒链审计](current-dataflow-p5-chain-audit-20261007.md)判定该指标"无法确定"，因为旧回执没有逐 admission 的完成证书，且旧运行未启用链接所需探针。本轮新增两个软件交付并做一次带全部探针的有界真实 RTL 门禁：

1. `src/myfuzz/scenario/chain_certificates.py`：有界、增量、fail-closed 的端到端链证书生产者（每条 `fuzz_source` admission 至多一张证书，`certified` 或 `incomplete`）。
2. `src/myfuzz/scenario/acceptance_metrics.py` + `scripts/run_first_step_acceptance.py`：单次流式扫描的"首步验收"分析入口，输出 `first_step_acceptance_report.v1`（链/s、覆盖新颖率、p50/p95 分项耗时、终结成本、replay 核对），无法确定的量写 `null` 并给原因，**绝不写 0**。

两者均为软件门禁：证书 50 项测试、分析器 36 项测试（含手算精确断言、负例、流式内存断言）。本报告只解释下方这条真实 RTL 运行。

## 运行与结论

运行命令（源码为当时工作区，含本报告的证书/分析模块；`--cpu-retirement --native-irq-receipts --gpio-consumption` 同时启用 RVFI 退休、原生 IRQ 回执与被动 GPIO 消费探针）：

```bash
cd /home/qinkejiu/myfuzz
python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/current-dataflow-p5-chain-acceptance-20261007-cache \
  --output runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --seconds 30 --max-tests 40 --seed 20261007 \
  --run-id current-dataflow-p5-chain-acceptance-20261007 \
  --cpu-retirement --native-irq-receipts --gpio-consumption
```

退出码 0，`{"tests": 24, "statuses": {"complete": 24}, "effective_search_seconds": 31.273544041999997, "elapsed_seconds": 32.362159227999996}`。运行身份 `online_run_identity_sha256 = ba3e57b210e92515c2b0169d33ec716eff28e9009b6d46005f7e1db15cf74e79`，decoder manifest `b68042f0a0cbd76918d4066108a93b987a4d6de37261af50fa2d4941908fff84`，`client_returncode = 0`，`execution_status = complete`。

分析命令：

```bash
python3 scripts/run_first_step_acceptance.py analyze \
  --run-dir runs/current-dataflow-p5-chain-acceptance-20261007-online \
  --json-out runs/current-dataflow-p5-chain-acceptance-20261007-logs/acceptance.json \
  --markdown-out runs/current-dataflow-p5-chain-acceptance-20261007-logs/acceptance.md
```

退出码 0，wall 3.45 秒、峰值 RSS 60.1 MB（输入是 163,190,709 字节的单体 `online_final_trace.json`，用 `JSONDecoder().raw_decode` + 滑动缓冲解析，**从不整文件 `json.load`**）。31,795 条事件全部读入，重算 `semantic_sha256 = 6c998e5d894173655e3b94ceaa9d68796f1e22ee424354feffe454a712f79bc5`，与运行声明一致（`semantic_sha256_verified = true`）。

| 指标 | 实测值 |
|---|---:|
| complete 例 | 24/24 |
| 有效搜索秒 | 31.273544 |
| 例/s | 0.7674 |
| **认证链总数** | **8**（IP→CPU→IP 5；CPU→IP→CPU 3） |
| **严格认证链/s** | **0.255807** |
| 同例完成／跨例完成 | 7 / 1 |
| incomplete 证书 | 16（首个缺口：`instruction_fetch` 6、`pin8_injection` 10） |
| 唯一链签名（direction + 有序 hop） | 2（0.063952/s） |
| 本地目标位首次命中 | 4/4（0.127904 位/s） |
| 见证运行时边（唯一/观测） | 9 / 1,940（0.287783 边/s） |
| 无效/超时例比例 | 0.0 |
| 证据终结（含 trace 写入） | 11.550271 秒 |

逐例分项耗时（`receipts.jsonl` 内嵌，24/24 例齐全，单位秒）：

| 分项 | p50 | p95 |
|---|---:|---:|
| selection_decode | 0.0000986 | 0.0001275 |
| rtl_submit | 1.234273 | 1.595630 |
| trace_digest | 0.047566 | 0.053960 |
| interaction_ingest | 0.014803 | 0.078164 |
| checker | 0.0000019 | 0.0000031 |
| feedback_credit | 0.000854 | 0.001122 |
| receipt_build | 0.0000173 | 0.0000210 |
| total | 1.296532 | 1.722264 |
| scheduler_batch＝runner_step | 1.022501 | 1.381803 |
| router_enqueue | 0.0000173 | 0.0000333 |
| router_drain | 0.001464 | 0.003489 |
| observed_output_route | 0.001759 | 0.038275 |

终结分项：`session_finish` 6.244267 秒、`trace_write` 5.005776 秒、`identity_write` 0.237584 秒、`plan_write` 0.002080 秒，`total_before_report` 11.550271 秒。上表各分项包含子调用，不可相加解释为纯 RTL 时间。

独立缓存 fresh replay：

```bash
python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir runs/current-dataflow-p5-chain-acceptance-20261007-replay-cache \
  --plan runs/current-dataflow-p5-chain-acceptance-20261007-online/online_plan.json \
  --trace runs/current-dataflow-p5-chain-acceptance-20261007-online/online_final_trace.json
```

退出码 0，`matches = true`、`first_difference = null`、`difference_context = null`；新进程重建真实 Ibex＋双 GPIO RTL 后逐事件与 local ticks 一致。

## 证书语义（不得外推）

证书 `certificate_id = sha256(canonical_json([direction, source_admission_id]))`，因此每条 `fuzz_source` admission 恰有一张证书、计数不会重复。`hops` 是已认证前缀，`missing_hops` 是第一个未见证跳及其后全部必需跳；`hops` 之外不得推断任何因果。

**`IP_TO_CPU_TO_IP`（17 跳，本轮 5 条）**：`pin8_admission → pin8_injection → pin8_segment_applied → pin8_input_resource → pin8_sync0_sample → pin8_sync1_sample → gpio_b_native_irq_trigger → gpio_b_native_irq_observation → cpu_irq_input → cpu_irq_taken → isr_padin_mmio_acceptance → isr_padin_target_receipt → isr_padin_target_access → isr_padin_register_read → isr_padin_mmio_delivery → isr_padin_data_response → isr_padin_retirement`。
即：真实外部 pin 输入 → GPIO B 真实同步/原生 IRQ → CPU 实际接受中断 → 真实 ISR 对 GPIO B `PADIN` 的 MMIO 读被 RVFI 退休确认。**终点是 ISR 读回寄存器并退休**；ISR 随后对 GPIO A 的写、A→B 绑定回流与第二次中断都不在证书内。

**`CPU_TO_IP_TO_CPU`（13 跳，本轮 3 条）**：`instruction_admission → instruction_source → instruction_fetch → mmio_write_acceptance → mmio_write_data_acceptance → gpio_a_target_receipt → gpio_a_target_access → gpio_a_register_commit → mmio_write_delivery → mmio_write_data_response → instruction_retirement → instruction_retirement_match → retired_target_delivery`。
即：在线指令 admission → 真实取指 → 真实 MMIO 写被 GPIO A 寄存器提交 → 投递/响应 → 该指令 RVFI 退休与目标交付确认。**终点是 CPU 退休确认，"回到 CPU"不是新的 IP→CPU 事件。**

16 条 incomplete 的首个缺口只有两类：`instruction_fetch`（当选源指令是 NOP 或只产生读拍，没有可精确连接的 GPIO A 写拍）与 `pin8_injection`（该 pin8 admission 从未成为任何原生 GPIO IRQ cause 的来源）。这表示**该运行缺少相应跳的证据**，不表示 DUT 没有发生传播。

## 限制与未覆盖

- 这是 31 秒有界运行，**不是 P5 的十分钟门禁**；上表的链/s、覆盖/s 只属于本次运行，不能外推到其他负载、种子或时长。
- 本轮启用全部现有探针，但**尚未消费** wrapper 新增的 RVFI IRQ serial sideband（`irq_decision_serial`/`irq_retirement_serial`）；证书仍依靠既有 `cpu_irq_input.source_trigger.trigger_id` 与 MMIO/退休事务键的精确相等，不是硬件 serial token。serial 的采集与精确 join 另有独立工作项。
- 新颖率覆盖整个扫描窗口：回执与证书没有逐例完成时间戳，无法重建按秒的新颖曲线（分析器在 `limits` 中显式记录）。
- 分析器只统计注入 producer 发出的证书，**不自行重推 hop 证据**；hop 级正确性由 `tests/scenario/test_chain_certificates.py` 的冻结 fixture 逐字段断言保证。
- 本次未发现自然 RTL 缺陷；正常运行不产生 checker finding 属于预期。
- `IP_TO_CPU_TO_IP` 的第三条腿是"CPU 读 IP 寄存器"，不是"CPU 写 IP 输出"；跨例链 1 条（case 21 的指令 admission 在 case 22 退休交付）已计入 `cross_case`，但同样是上表口径。

## 复现与材料

- 运行材料：`runs/current-dataflow-p5-chain-acceptance-20261007-online/`（plan、trace、identity、receipts、session manifest），构建缓存 `runs/current-dataflow-p5-chain-acceptance-20261007-cache`，重放缓存 `runs/current-dataflow-p5-chain-acceptance-20261007-replay-cache`。
- 命令与真实输出：`runs/current-dataflow-p5-chain-acceptance-20261007-logs/`（`run.log`、`acceptance.json`、`acceptance.md`、`acceptance.stdout`、`acceptance.time`、`replay.log`；另有旧探针 fixture 的 `pin8_fixture_acceptance.json` 供交叉核对）。
- 证书与分析器测试：`PYTHONPATH=src python3 -m pytest tests/scenario/test_chain_certificates.py tests/integration/test_first_step_acceptance.py -q -p no:randomly` → 86 passed。
