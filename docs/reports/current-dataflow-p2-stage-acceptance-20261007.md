# P2 阶段验收：路径、逐边来源与绑定门禁

日期：2026-10-07。本报告按主实施计划 P2 的**验收条文逐条**汇总证据，并给出明示边界。所有结论绑定各自保存 artifact 与引擎 sha256；未运行新的真实 RTL（除既列运行外）。

## 验收条文 → 证据

### 1. 两条路径由版本化声明实例化，均有逐边交付/消费记录

`scripts/run_p2_acceptance_gate.py analyze --run-dir runs/current-dataflow-p5-chain-acceptance-20261007-online` → **退出码 0**：

| 方向 | 状态 | 声明边数 |
|---|---|---:|
| `CPU_TO_IP_TO_CPU` | certified | 8 |
| `IP_TO_CPU_TO_IP` | certified | 7 |

逐边状态由[通用逐边来源](current-dataflow-p2-edge-provenance-20261007.md)给出，并在三条真实 run 上复算为 **9 certified / 0 incomplete / 0 unknown**（含此前唯一的 incomplete 边 `gpio_a.gpio_out→gpio_b.gpio_in`）：

| run | 事件 | certified | incomplete | unknown |
|---|---:|---:|---:|---:|
| `runs/p4-shift-fuzz-20261007-online` | 118,963 | **9** | 0 | 0 |
| `runs/current-dataflow-p5-paired-20261007-online` | 31,795 | **9** | 0 | 0 |
| `runs/p3-slot-policy-20261007-online` | 42,519 | **9** | 0 | 0 |
| `runs/current-dataflow-p5-streamed-short-20261007-online`（无目标侧观测） | 10,418 | 8 | 1 | 0 |

A→B 数据绑定的消费跳由目标组件自身的输入观测（`gpio_tick_observation.active_input_context.segments[]` / `gpio_input_applied*`）给出，且必须满足：`origin.kind=="binding"`、源端点与相对位一致、**恰好一次覆盖声明窗**（无重叠/空洞/越界位宽）、`origin.delivery_event_id` 命中**自身声明本条边**的 `dataflow_delivery`、该 delivery 的 `producer_event_id` 命中 driver 且既有精确切片值 == delivery 值 == 目标测量窗切片（三方相等）。仅时间相邻**完全不能**进入该边（无引用连 key 都拿不到）。

持久状态边同样有实测证据：[在线契约追加两条 `persistent_state` 边](current-dataflow-p2-persistent-state-edges-20261007.md)（RAM 字节版本、GPIO 寄存器位版本），既有 9 条边逐字段不变；扩展后为 **11 条边、11 certified / 0 incomplete / 0 unknown**（RAM 边按写 `version=[generation,seq]`＋`byte_enable` 覆盖与读 lane `versions/writer_kinds` 精确引用连接，寄存器边按位行 `version`/`observation_event_id` 全等连接）。

### 2. 切断 A→B 或删除 IRQ 绑定给出可定位失败

六个**纯声明**破坏变体（`cut_binding`／`drop_irq_binding`／`wrong_mmio_base`／`wrong_target_window`／`edge_identity_swap`／`producer_drift`）全部在 `contract_compile` 阶段被拒并定位到具体边与字段（例如 `direct edge (2, 0) Binding matches=0`、`MMIO edge (0, 0) window aperture/target mismatch`、`selected cross-component edge (0, 0) lacks contract`）。

`LaunchProbe` 证明拒绝**先于任何 harness 渲染/构建/会话构造与任何进程启动**：八个计数器（`rtl_process_launches`、`rtl_begin_attempts`、`tool_process_invocations`、`harness_renders`、`harness_builds`、`harness_session_constructions`、`filesystem_writes`、`factory_calls`）在六次拒绝中全为 **0**；对照组（未破坏声明）不被拒绝。

### 3. 真实 IP 提前 IRQ 仍写入 trace

验收门禁的 `early_irq` 段按 `trigger_id`（缺则 `source_event_id+component`）聚合原生 IRQ trigger/high 观测并与 CPU 接受精确比对，结论：`decision = early_irq_recorded`、`decision_value = true`，**2 个未被接受的实例**：

| instance | 事件 ID |
|---|---|
| `gpio_b:0:trigger:2` | 6007, 6058 |
| `gpio_b:0:trigger:4` | 13318, 13369 |

即：原生 IRQ 已触发/置高但该实例没有同源 CPU 接受记录时，事件仍完整保留在 trace 中并被显式统计（未观察到时该字段为 `null` + 原因，绝不写成通过）。

### 4. 相同 graph 与不同 edge identity 的 fresh replay 不得互认

API 级真实门禁（`authority=genome`，真实 `GenomeRecordDecoder` + 真实 `ScenarioRfuzzExecutor._install_runtime_replay_identity`，零 RTL 零 factory）：同 graph、`path_id` 相同、`contract_sha256` 不同 → **A↮B 与 B↮A 双向拒绝**（`fresh replay runtime path declaration mismatch`），A↔A 互认成功。

### 5. 新增同协议组件时路径声明可复用

同一套 ownership／MMIO 窗口／绑定／IRQ 脉冲策略／boot+ISR 固件体／在线 decoder（F4/F5 路径）／checker 被 CV32E40P（OBI，另一 CPU）复用，仅两处显式 CPU 差异（首取指 0x10000 的 JAL trampoline、`mtvec=0x10101` 选 vectored）；该组合真实运行 **42/42 complete** 且完整 fresh replay 一致（见 P6 交付与 `runs/cv32e40p-pulp-online-20261007`）。

## 引擎版本钉

验收门禁把消费引擎的字节绑进报告：`edge_provenance = 33af477f4acd1c06…`、`chain_certificates = b0966bb3228b8c3f…`、`p2_negative_gates = 5570ad779e3d0ce7…`、`acceptance_metrics = 242b35ef5c4a6ce6…`、`p2_acceptance = e48e2585ae7511d7…`。**结论只对这些字节成立**；任何引擎改动都需要重跑门禁。

## 明示边界

1. "不同 edge identity 的真实 run 对"在 `runs/` 中**不存在**：48 个 `graph 58471d1e` 的 run 共用同一 declaration 身份。因此第 4 条的真实证据是 **API 级**（合成 swap 声明），`--compare-run` 对现有 run 会如实报 `criterion_applicable=false`；要给出 run 对级证据需先产出一个合法但 edge identity 不同的声明/run。
2. `memory_read.writer_event_ids` 仍从不含**整数写事件 id**（734 条读、0 个），RAM 边的精确引用形式是写记录自身**事务键的规范 repr**；这是 host 写入器侧的字段缺口（软件），不需要新 RTL 探针。本 run 亦无 `memory_write_commit`/`commit_id`，`memory_initialization` 无跨度字段。
3. 消费跳依赖目标侧观测事件的 `segments[].origin.delivery_event_id`：某 run 若不写目标侧观测（如 `p5-streamed-short`），该边仍如实为 incomplete。
4. driver 精确切片规则未放宽：若源 `gpio_out` 一直带声明窗以上的位，A→B 边会停在 `missing=[producer,delivery,consumer]`。
5. 本报告不重推 hop 证据、不跑 RTL；链证书计数由 `analyze_run` 给出并与 P5 报告一致（`cross_check = agree`）。

---

## 2026-10-09 产物重建说明

本报告引用的 `runs/cv32e40p-pulp-online-20261007` 曾在 2026-10-09 的 `runs/` 清理中被误删。**原始参数在文档中没有完整记录**，因此按 Ibex 对照的预算重建（`--seconds 180 --max-tests 200 --seed 20261007 --run-id cv32e40p-pulp-online-20261007 --gpio-consumption`，CV32E40P 无 RVFI 探针）：**133/133 `complete`、180.161 有效秒**，与本文"CV32E40P 复用同一 wiring"的结论一致，但**例数与原始 42/42 不同**（原运行的预算未记录）——本文只主张"该 CPU 复用同一 ownership／窗口／绑定／IRQ 策略／固件／decoder／checker 且真实运行全部 complete"，不主张例数可复现。
