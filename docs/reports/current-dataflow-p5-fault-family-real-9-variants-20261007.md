# P5 受控故障族 9/9 变体真实 RTL 校准与独立复核

日期：2026-10-08。P5 要求"至少一项受控错误被独立断言捕获并在新进程复现，正常对照无该 finding"，并列出可选注入形态（错 IRQ、错 read data、重复提交、破坏 GPIO A→B 值）。此前真实 RTL 只校准了 **1/9** 变体（`wrong_irq`/`observation_irq_level`）。本报告把真实校准扩到**全部 9 个变体**，并用独立的只读复核器逐变体复核。

## 运行方式

软件侧先由[通用校准运行器与复核器](current-dataflow-p5-fault-family-calibration-20261007.md)在保存事件上选出 9/9 见证窗口（`--select-only`，6.4 秒，未启动 RTL）。真实会话：

```bash
PYTHONPATH=src python3 scripts/run_p5_fault_calibration_family.py run \
  --continuous-run runs/current-dataflow-p5-paired-20261007-online \
  --continuous-run runs/p5-uart-gate2-20261007-online \
  --output-root runs/current-dataflow-p5-fault-family-all-20261007-online \
  --cache-dir runs/current-dataflow-p5-fault-family-20261007-cache \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz   # exit 0
PYTHONPATH=src python3 scripts/run_p5_fault_calibration_family.py verify \
  --calibration-root runs/current-dataflow-p5-fault-family-all-20261007-online           # exit 0
```

每个变体一次**全新真实会话**（`ibex_pulp_online` 带 `cpu_retirement`/`gpio_consumption`/`native_irq_receipts`；UART 变体走 `ibex_uart_online` 运行时），预算 120 秒 / 24 例 / seed 20261007 / `max_runs_per_batch=1`；会话在 finding 命中后即停止，因此实际只跑到第 1～3 例（见下表）。

## 9/9 变体真实校准结果

| 变体（kind） | checker | 见证 case | 例数（statuses） | 命中 finding | 有效秒 |
|---|---|---|---|---:|---:|
| `observation_irq_level`（wrong_irq） | pulp | `online-2-604caae5c07e4c776cb357d1` | 3（2 complete + 1 dut_violation） | `gpio_b_irq_source_mismatch` | 4.874 |
| `cpu_irq_input_bit`（wrong_irq） | pulp | `online-2-…` | 3（2+1） | `cpu_irq_pulse_input_mismatch` | 4.498 |
| `cpu_response_data`（wrong_read_data） | pulp | `online-2-…` | 3（2+1） | `cpu_gpio_b_padin_response_mismatch` | 4.530 |
| `delivery_read_data`（wrong_read_data） | pulp | `online-2-…` | 3（2+1） | 3 条：`gpio_b_padin_read_mismatch`／`cpu_gpio_b_padin_response_mismatch`／`cpu_gpio_b_padin_store_mismatch` | 4.722 |
| `uart_cpu_response_data`（wrong_read_data） | **uart** | `online-1-819b265ed890cbfc934efd3e` | 2（1+1） | `cpu_uart_rxdata_response_mismatch` | 4.127 |
| `irq_pulse_resubmission`（duplicate_submission） | pulp | `online-2-…` | 3（2+1） | `cpu_irq_pulse_input_mismatch` | 4.340 |
| `mmio_delivery_replay`（duplicate_submission） | pulp | `online-2-…` | 3（2+1） | 3 条（同上） | 4.487 |
| `delivery_value`（broken_binding_value） | pulp | `online-0-af5570f5a1810b7af78caf4b` | 1（1 dut_violation） | `gpio_a_to_b_delivery_mismatch` | 0.001 |
| `bound_input_value`（broken_binding_value） | pulp | `online-0-…` | 1（1 dut_violation） | `gpio_b_bound_input_mismatch` | 0.002 |

九个变体的 `fault_run_summary.json` 都记 `observed_findings == family_findings ==` 期望 finding，并各自写出 `minimal_replay.json`（9/9 存在，`p5_controlled_fault_replay.v1`）。**四类故障形态全部有真实捕获**：错 IRQ 2 个、错 read data 3 个（含 1 个 UART）、重复提交 2 个、破坏绑定值 2 个。

## 独立复核（`verify`，只读，exit 0）

复核器不信任汇总字段，直接重读：`fault_document.json` 是否 canonical（重算内容摘要）、`minimal_replay.json` 是否存在且 `fault_document_sha256` 等于该变体文档的 canonical 摘要、故障会话 `receipts.jsonl` 是否含期望 finding、控制运行是否**不含**该 finding、控制/故障两份真实 trace 的锚点事件是否逐字段相同、控制 trace 文件 SHA-256/字节数是否与选择时刻记录一致。结果：

- `ok=true`、`failures=0`，9/9 变体 `ok=true`；
- 8 个 PULP 变体各记 **1 条 `declaration_drift`**（控制运行 `runs/current-dataflow-p5-paired-20261007-online` 是更早保存的运行，其 `provenance.edge_candidates` 记的是**当时**的运行时路径声明摘要 `58471d1e…`，而本次故障会话记的是当前声明 `3bfd62f4…`），差异路径被逐条列出且仅限该声明字段——**注入只改 checker 观测副本、真实 trace 未被改写**这一结论因此仍逐字段成立，同时漂移本身被显式记录而不是被忽略；UART 变体漂移 0 条（两侧同一声明）。

## 修复的两个复核器缺陷（软件）

复核器在真实产物上首次运行暴露两处自身缺陷，均已修复并加回归测试（`tests/scenario/test_p5_fault_family_calibration.py`，25 项）：

1. 锚点事件比对把"控制枝与故障枝是两次独立会话"误当成注入越界：它用整段 canonical JSON 比较，任何声明漂移都报成"不一致"，且诊断只打印**被注入字段**的值（于是出现"控制=None 故障=None 却说不一样"的自相矛盾信息）。改为递归差异路径：只允许 `provenance.edge_candidates` 类声明路径不同且必须原样记录，其余任何差异都列出精确键路径。
2. 校验"tick 来自同一事件"时，对**该变体根本没钉住**的另一对 (tick, 事件键) 也去查事件，导致 `cpu_irq_input_bit` 与 `irq_pulse_resubmission` 被误判失败。改为只比对选择器同时钉住的那一对。

## 同条件故障质量对照（`p5_fault_quality.v1`）

[故障质量对照工具](current-dataflow-p5-fault-quality-comparison-20261007.md)（`scripts/compare_p5_fault_quality.py`，27 项软件测试）只读复核同一个校准根，退出码 0：

- rollup：`total=9 calibrated=9 detected=9 boundary_ok=9 reproducibility_ok=9 not_fired=0 error=0 no_witness_window=0 never_calibrated=[]`；按类 2/2、3/3、2/2、2/2。
- 每变体：期望 finding 在钉住 case 上以 `dut_violation` 命中且 family `finding_ids` 一致；锚点事件逐字段数据流差异 **0**；故障 trace 锚点上仍是被扰动字段的**原值**、注入值不出现（例 `outputs.irq 1→0 ctl=1 flt=1`、`read_value 262→263`、`value 0→1`）；重复提交类以"记录 trace 里同身份事件计数 1=1"度量；9/9 的 `minimal_replay.fault_document_sha256` 等于该变体 `fault_document.json` 的 canonical 摘要。
- **同条件降级（该工具新暴露，必须一起读）**：9/9 变体 `same_condition_degraded=true`。8 个 PULP 变体的控制运行与故障会话 `topology_sha256` 相同（`2f6e0248…`）但 `graph_sha256` 不同（`58471d1e…` → `3bfd62f4…`），运行时路径声明有 78 个扁平字段不同，`source_files` 有 6 个文件不同（`scenario_rfuzz.py`、`scenario_rfuzz_live.py`、`opentitan_uart_session.py`、`cpu_retirement.py`、`ibex_uart_online.py`、`interaction_feedback.py`）；UART 变体 graph/声明相同但仍有 2 个文件不同。此外 case `online-2` 的窗口在两次会话间并非逐字节相同：掩码后仍有 80 个事件不同，其中 372 个是身份摘要叶（`admission_id`/`path_id`/`origin_admission_ids`），另有 67 个真实内容叶全部落在同一个事件 `event_id=5826`（`cpu_retirement_match` 的 `byte_cells[0].versions[*]`）；UART 变体的窗口逐字节相同。
- 因此本报告的"同条件"只到 **case_id + 事件 ID/tick/原值 + 锚点逐字段** 这一层；不得读成逐图、逐源码严格同条件。

## 结论与限制

**结论**：P5 的受控故障检测链在**四类九变体**上都有真实 RTL 证据——每个变体在被见证的真实 case 上由既有 checker 不变量捕获、会话随即停止接纳后续例、保存可重放的最小配置，并且这些产物通过一个只读、fail-closed 的独立复核器（9/9，0 失败）。

**限制（不得外推）**：

- 全部 finding 都是**注入校准**（`calibration_only=true`、`observation_boundary=checker_input_copy`），不得计入自然 RTL 缺陷；控制运行在同一窗口不含该 finding。
- 单变体 `calibrated` 只表示"该断言在本窗口确实会响"，不表示该类故障的检测灵敏度或漏检率；本报告**不做**故障质量/灵敏度对照。
- 会话在 finding 命中后即停止，故例数只有 1～3；这不证明长会话下的稳定性。
- `verify` 只读已保存产物，它不重跑 RTL，也不证明"新进程复现"；后者的既有证据见[受控故障真实校准与新进程复现](current-dataflow-p5-controlled-fault-real-20261007.md)（`wrong_irq`/`observation_irq_level`，含最小重放输入在新进程复现同一 finding）。
- 8 个 PULP 变体的控制运行是更早保存的会话，其运行时路径声明与当前不同（已记为 `declaration_drift`）；因此"锚点事件逐字段相同"的结论在该漂移字段之外成立。
