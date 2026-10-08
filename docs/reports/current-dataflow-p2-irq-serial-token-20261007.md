# P2 RVFI IRQ serial token：真实 RTL 精确来源连接门禁

日期：2026-10-07。P2 长期缺口是"Ibex RVFI 退休事件没有与 IRQ 决策同流水级推进的硬件来源 serial"，因此 pin8 原生 trigger 到 CPU 退休只能给出**弱架构关联**（见[trap 退休关联](current-dataflow-p2-pin8-native-trap-relation-20261007.md)与[来源归属审计](current-dataflow-p2-native-trap-attribution-audit-20261007.md)）。本报告收口该缺口：wrapper 侧的被动 IRQ serial sideband（RTL 与身份见 [sideband 身份门禁](current-dataflow-p2-rvfi-sideband-identity-20261007.md)）现在被 host 侧采集，并在真实运行上给出**精确硬件 token 相等**的证书。

## 交付

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/irq_serial_certificates.py`（新增） | `IrqSerialCertificates`：有界、增量、fail-closed 的 serial 连接消费者；证书 `irq_serial_certificate.v1`，`proof_scope = exact_nonzero_irq_serial_token_equality`，并显式列出 `not_proof_of`（事件相邻、指令来源、操作数/FIFO 污点、完整传播链、handler 入口或 ISR 效果） |
| `src/myfuzz/local_harness/ibex_irq_receipt_contract.py` | 追加 serial 观测契约/构造/校验（`ibex_irq_serial_observation.v1`）；既有 `ibex_irq_receipt_contract()` 字节未改 |
| `src/myfuzz/local_harness/cpu_session.py` | 新增 `_serial_observation()` 与两个调用点，把 `irq_decision_serial`/`irq_retirement_serial` 物理导出值写入观测 |

落点：事件键 `irq_serial_observation`，出现在 `cpu_retire`、`cpu_external_irq_sample`、`cpu_external_irq_taken`、`cpu_irq_notification`。字段含 `sampling`、`width_bits=64`、`zero_semantics="no_provable_source_lineage"`，以及 `decision`/`retirement` 各自的 `physical_port`、`phase`、`value`、`status`。**决策 token 取 pre 边沿、退休 token 取 post 边沿**；旧 artifact 缺这两个导出时写 `status="unobservable"`、`value=null`，不报错、不猜测。

## 精确 join 判定（全部满足才发证书）

1. journal 连续（`event_id == last+1`，否则 `ValueError`）。
2. 决策 token 已观测且**非 0**（0 = 无可证明来源，记 `zero_decision_serial`，不给 credit）。
3. 退休事件 `valid==1`、`intr==1`，退休 token 已观测且非 0。
4. 两个 token **精确相等**（不等 → `unmatched_retirement_serial`）。
5. 两侧同 `execution_id`、`reset_epoch`、`component`（`source_epoch` 存在时必须一致）。
6. `decision_event_id < retirement_event_id` 且间隔 ≤ `max_event_gap`（超龄即作废，迟到退休仍为 0）。
7. 一次决策只认证一次退休（credit 消费后不重复使用）。
8. take 身份精确：原生 `take_key = [component, reset_epoch, sequence]` 必须匹配 scope 且在该 scope 内严格新增；重用/回退/scope 不符一律拒绝。
9. pin8 `source_trigger`（`trigger_id`/`trigger_event_id`/`observation_event_id`/`sample_event_id`）必须被 journal 自身的 `cpu_irq_input` + `cpu_irq_taken` 逐字段佐证；缺伙伴记 `take_identity_uncorroborated`，不一致记 `trigger_identity_mismatch`。
10. 伪造/畸形观测（错误 schema/sampling/port/phase/status，bool、越界整数、字符串、浮点 value）→ 拒绝，并封锁该 `(execution, epoch, component)` scope 直到真实 reset。

## 真实 RTL 结果

两次真实 Ibex＋双 PULP GPIO 运行（`--cpu-retirement --native-irq-receipts --gpio-consumption`，当前冻结源码）都由本消费者在保存的 `online_events` 上复算：

| 运行 | 事件数 | 证书 | 说明 |
|---|---:|---:|---|
| `runs/current-dataflow-p5-paired-20261007-online`（24 例，30.783 s） | 31,795 | **5 条 certified** | 全部 `decision_serial == retirement_serial`（1…5） |
| `runs/current-dataflow-p5-chain-600s-20261007-online`（368 例，600.363 s） | 570,196 | **68 条 certified** | 全部精确相等且非 0，见 `chain_600s_serial_certificates.json` |

复算方式为逐行流式（`TraceEventStream` + 分批 `ingest`），未整文件加载 trace。证书同时携带 `execution_id`、`reset_epoch`、`decision_event_id`、`decision_producer_event_id`、`decision_phase`、`take_identity`、`retirement_event_id`、`event_gap` 等可复算字段。

## 门禁

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_irq_serial_certificates.py -q -p no:randomly
# 35 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_irq_serial_certificates.py \
  tests/scenario/test_cpu_retirement.py tests/local_harness/test_cpu_native_irq_receipt.py \
  tests/local_harness/test_cpu_native_retirement_receipt.py tests/local_harness/test_ibex_rvfi_probe.py \
  -q -p no:randomly
# 137 passed, 1 skipped（真实 RTL 门控）, 400 subtests passed
```

负例（每条都有可复现拒绝原因）：serial 不等、任一为 0、跨 reset epoch、超 `max_event_gap`、缺 take 身份、`trigger_id`/ref 不符、伪造 bool 观测、旧 artifact 无 serial（静默不认证且不抛错）、reset 后 credit 清零。其中 9 条配有"最小修复 → 恰好 1 张证书"的对照，证明每个守卫都是承重的。

## 限制

- 证书只到 **IRQ 决策 → RVFI 退休**这一跳；不断言指令来源、操作数/FIFO 污点、handler 入口或 ISR 效果，也不替代 `pin8_*` 家族证书。
- 该证书**尚未**接入 `chain_certificates.py` 的完整链，也尚未写入 live 回执；本轮是保存 trace 上的独立消费者复算。
- 真实运行证明 serial 在真实 RTL 上推进并对齐，但本消费者不做端到端链/s 统计（由[600 秒门禁](current-dataflow-p5-chain-600s-20261007.md)给出）。
- 旧冻结源码的 RVFI 证据仍只按其自身身份成立。
