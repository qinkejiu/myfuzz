# P5 异构外设长会话：UART RX 波形互斥改为**接纳前声明式拒绝**

日期：2026-10-08。P5 验收要求"在 Ibex＋双 PULP GPIO 与至少一种不同协议/行为的真实外设上"跑通第一步的多例会话。此前的异构门禁（[Ibex＋OpenTitan UART 多例门禁](current-dataflow-p5-uart-heterogeneous-gate-20261007.md)）在第 7 例因 `RuntimeError: TL-UL access during serial source waveform is unsupported` 停机（`uncertain_effect`），异构长会话因此有界。本报告把这条限制从"提交后崩溃"改成"**任何 RTL 命令之前的声明式拒绝**"，并给出真实运行结果。

## 问题定位

`src/myfuzz/local_harness/opentitan_uart_session.py::_access` 在发起 TL-UL 寄存器访问前检查

```python
if self.peer.source_overlaps(self.local_ticks,
        self.local_ticks + self.max_local_ticks_per_register_access + 1):
    raise RuntimeError('TL-UL access during serial source waveform is unsupported')
```

在线路径上这个 `RuntimeError` 发生在**已提交的 case 内部**，于是 `run_scenario_rfuzz_live` 把该例记成 `uncertain_effect` 并停止整个会话——搜索无法继续。

## 修复：把同一谓词提前到接纳之前

| 层 | 改动 |
|---|---|
| 会话 | `opentitan_uart_session.py` 新增只读查询 `register_access_conflict()`：用**完全相同的** `peer.source_overlaps` 与相同视界返回 `{local_tick, horizon_tick, source_start_tick, source_end_tick, ...}` 而不是抛错；`_access` 的原有守卫一行未改 |
| 声明词汇 | `source_actions.PREREQUISITE_KINDS` 增加 `transport_idle`（subject 恰为 `transport`/`local_tick`/`horizon_tick`，带校验），用于"某条传输资源必须空闲"的声明式前置 |
| 门 | 新模块 `src/myfuzz/scenario/uart_waveform_gate.py`：`UartWaveformAdmissionGate` 实现 shipped 的 `register`/`require_case`/`evaluate` 接口；只对**组件匹配、片段自身字节里确实含落入声明 UART 窗口的 LW/SW/SB**（`fragment_mmio_accesses` 从 `LUI`+load/store 逐字解码）的候选，去问会话是否冲突 |
| 接线 | `make_ibex_uart_online_runtime` 把它作为 `source_action_gate` 注入；组件会话按"**恰好一个**声明了该查询的组件"定位，0 个或多个立即抛错（不猜） |

拒绝沿既有路径：`SourceActionPrerequisiteError` → executor 记为 `source_action.refusal = source_action_prerequisite_unsatisfied`、`candidate_disposition = rejected`、该例**不消耗任何东西**（在任何 RTL 命令之前，decoder 的 commit 不被调用）。

## 真实运行（同一 wiring、同 seed、同预算）

```bash
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/p5-uart-waveform-gate-20261008-cache \
  --output runs/p5-uart-waveform-gate-20261008-online \
  --seconds 120 --max-tests 60 --seed 20261007 --run-id p5-uart-waveform-gate-20261008 \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback --uart-wdata-byte-store
# 随后 replay（独立 cache）→ matches=true
```

| 量 | 修复前（`runs/p5-uart-gate2-20261007-online`） | 修复后（本次） |
|---|---:|---:|
| 例数 | 7（第 7 例停机） | **60（跑满预算）** |
| complete | 6 | **57** |
| `uncertain_effect`（停机） | **1** | **0** |
| 声明式拒绝（`input_invalid`） | 0 | **3**（全部 `uart_rx_waveform_conflict`） |
| 源覆盖 | — | **CPU 指令源 24 例 + UART RX 外部源 36 例** |
| 命中至少一个目标位 | — | 54/60 |
| fresh replay | 一致 | **`matches=true`** |

3 次拒绝的精确证据（每例一条，时标即冲突发生的 local tick）：

```
slot 5  cpu.online_instruction  input_invalid  evaluation_reason=uart_rx_waveform_conflict
        missing_kinds=["transport_idle"]  missing_evidence_refs=["uart-waveform-idle:1832"]
slot 33 cpu.online_instruction  input_invalid  同上  ["uart-waveform-idle:4456"]
slot 53 cpu.online_instruction  input_invalid  同上  ["uart-waveform-idle:6296"]
```

`report.json` 的运行态门记录：`uart_waveform_admission_gate.v1`、`window={base:1073741824,size:4096}`、`enforce=true`、`refusals=3`、basis 写明"用会话自己的 `peer.source_overlaps` 查询、在 RTL 命令之前拒绝"。

## 结论与边界

**结论**：异构（OpenTitan UART）长会话不再因 RX 波形互斥而停机——同一 seed/预算下由 7 例（1 次 `uncertain_effect`）变为 **60 例、57 complete、0 停机**，3 次冲突候选在**任何 RTL 命令之前**被声明式拒绝并带精确 tick 证据，CPU 侧与 IP 侧源在同一会话内都被真实使用，fresh replay 一致。

## 同一运行上**已证**与**未证**（逐项口径）

| P5 异构验收子项 | 本次运行的实际证据 |
|---|---|
| 多例异构会话不再停机 | ✅ 60 例、57 complete、3 次声明式拒绝、0 `uncertain_effect` |
| CPU 侧与 IP 侧变异 | ✅ 同一会话内 CPU 指令源 24 例 + UART RX 外部源 36 例 |
| 逐例覆盖反馈 | ✅ 逐例 `online_weights` 有 22 种不同取值，54/60 例命中至少一个目标位；`report.json` 记录 checker 身份 |
| 断言 | ✅ 运行内 checker 违规 0（如实记零，不当作"断言通过"的正面证据；checker 身份在 manifest 中） |
| 完整前缀保存 + fresh replay | ✅ plan/trace/manifest 身份齐全，独立 cache 的 fresh replay `matches=true` |
| 声明式拒绝（新） | ✅ 3 次 `uart_rx_waveform_conflict`，各带 `transport_idle` 前置与 `uart-waveform-idle:<tick>` 证据 |
| 无效/超时比例 | ✅ 分析入口现可计算：complete 57 / invalid 3 / findings 0（本轮同时修掉 `input_invalid` 未被 `acceptance_metrics.INVALID_STATUSES` 分类的盲点） |
| **UART 侧真实路由见证** | ❌ 本次产物 `source_target_transactions=null`，未做逐边见证分析；**未证** |
| **UART 侧完整链证书** | ❌ 分析入口报 `certified_chains.total=0`，并注明"57/57 声明 fuzz source 一个证书都没产出"；**未证** |
| **跨例持久状态（UART 侧）** | ❌ 本次回执无 memory commit 证据；**未证** |
| **逐例交互反馈（interaction）** | ❌ 54/60 例 `interaction_deferred=true`（选源权重由覆盖目标驱动）；**未证** |

因此本报告只主张"异构长会话的**停机阻塞**已解除、CPU/IP 双侧变异与覆盖反馈、断言、前缀保存与 replay 成立"，**不主张** UART 实例的完整 P5 验收（路由见证、链证书、跨例持久状态、交互反馈仍待补齐或显式列为范围限制）。

**边界（不得外推）**：

- 这**不是**让"波形进行中的 TL-UL 访问"变成支持：底层互斥**依然不被支持**，只是从"提交后崩溃"变成"接纳前拒绝"。真正的支持需要 harness/RTL 层的调度改动，本报告未做也未主张。
- 拒绝只针对**确实会访问声明 UART 窗口**的指令片段；不触达该窗口的 CPU 候选在波形进行中照常接纳（`test_the_session_predicate_is_only_asked_for_an_in_window_access` 钉住窗口外/非 CPU/无访问三种情形都不触碰会话谓词）。
- 本次是 120 秒 / 60 例预算的单次运行；**不**主张长会话稳定性、完整链/s 或异构侧覆盖等价。
- 该改动触及在线解码空间（`integration/ibex_uart_online.py`、`scenario/source_actions.py`、`local_harness/opentitan_uart_session.py`），因此**此前保存的 UART bundle 的 fresh replay 会按设计被身份守卫拒绝**；旧报告的结论仍属其记录时的产物，不因此重算。
- 门的判定依赖会话当前 tick 状态，属运行态查询；它不做预测、不做排队，也不改变波形本身的推进方式。
