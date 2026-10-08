# P5 受控故障真实校准与新进程复现

日期：2026-10-07。P5 要求"至少一项受控错误被独立断言捕获并在新进程复现，正常对照无该 finding"。软件侧已有 [`p5_controlled_fault.v1` 四类九变体](current-dataflow-p5-controlled-fault-family-20261007.md)与[受控 IRQ 校准](current-dataflow-p5-controlled-irq-fault-20261007.md)；本报告用该故障族做**真实 RTL**校准，并从保存的最小重放输入在**新进程**复现同一 finding。

## 目标选择（来自已保存真实运行）

从 `runs/current-dataflow-p5-paired-20261007-online`（24 例、31,795 事件、含全部探针）流式选出首个"同一 case 内、gpio_b 在 `source_tick` 处 `interrupt=1`、随后出现 gpio_b.irq→cpu.irq `source_start`"的见证：

```json
{"case_id": "online-2-604caae5c07e4c776cb357d1",
 "source_start_event_id": 4610, "observation_event_id": 4609,
 "source_tick": 131, "original_value": 1}
```

故障文档（`p5_controlled_fault_wrong_irq_4993dbdde44c56d1`）为 `wrong_irq` / `observation_irq_level`，`operation="rewrite"`、`mutation={"field": "outputs.irq", "replacement": 0}`、`expected_finding="gpio_b_irq_source_mismatch"`。

## 真实运行与捕获

```bash
PYTHONPATH=src python3 runs/current-dataflow-p5-final-20261007-logs/fault_calibration_gate.py \
  runs/current-dataflow-p5-paired-20261007-online \
  runs/current-dataflow-p5-fault-calibration-20261007-online \
  runs/current-dataflow-p5-final-20261007-cache \
  third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
```

退出码 0：`{"tests": 3, "statuses": {"complete": 2, "dut_violation": 1}, "effective_search_seconds": 4.242610220999268, "violations": ["gpio_b_irq_source_mismatch"]}`。真实会话在**第 3 例**（case `online-2-604caae5c07e4c776cb357d1`）被独立断言捕获并停止接纳后续例；`receipts.jsonl` 中该例 `status="dut_violation"`、`violations=["gpio_b_irq_source_mismatch"]`，前两例 `complete`。

保存产物：`fault_document.json`、`fault_run_summary.json`、`minimal_replay.json`（`p5_controlled_fault_replay.v1`，带 `calibration_only: true`、`observation_boundary: "checker_input_copy"`、`fault_document_sha256 = cd753d419c2860b94f302a672c90a17f8da3fbdef5ea5d1f1158419db03304d6`）。**该运行属于故障注入校准，不计入自然 RTL 缺陷统计。**

## 新进程复现

```bash
PYTHONPATH=src python3 runs/current-dataflow-p5-final-20261007-logs/fault_replay_reproduce.py \
  runs/current-dataflow-p5-fault-calibration-20261007-online/minimal_replay.json \
  runs/current-dataflow-p5-fault-calibration-20261007-reproduce \
  runs/current-dataflow-p5-final-20261007-cache \
  third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
```

退出码 0：`{"fault_document_sha256": "cd753d41…", "tests": 3, "statuses": {"complete": 2, "dut_violation": 1}, "violations": ["gpio_b_irq_source_mismatch"]}`——**从保存的最小重放输入出发，在新进程、新 RTL 会话中复现同一 finding，且同一 case 身份**。

## 原始 RTL 观测未被修改（独立核对）

逐个流式读取两份 trace 的 `event_id = 4609`：控制运行 `runs/current-dataflow-p5-paired-20261007-online` 与故障运行 `runs/current-dataflow-p5-fault-calibration-20261007-online` 的该事件都是 `local_tick_sample`、`outputs = {"interrupt": 1, …}`、`local_tick = 131`，**逐字段相同**。即注入只改写交给 checker 的观测副本（`irq 1 → 0`），真实 RTL trace 字节不变。

## 意义与限制

- 意义：P5 的"受控错误被独立断言捕获 → 保存最小可重放输入 → 新进程复现"闭环在真实 RTL 上成立；正常对照（同 seed、同例数的常规运行）在 368 例与 24 例两次运行中均为 0 finding。
- 只校准了 9 个变体中的 1 个（`wrong_irq`/`observation_irq_level`）真实运行；其余变体的真实校准未做（软件侧另有 6/9 在真实保存窗口上校准）。
- 故障注入仅作用于 checker 输入副本，**不能**用于声称 DUT 缺陷；本次未发现自然 RTL 缺陷。
- 校验范围是"该断言在真实运行中确实会响"，不是"检测能力对所有故障类型的灵敏度"。
