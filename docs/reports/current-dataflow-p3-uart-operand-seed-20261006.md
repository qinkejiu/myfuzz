# 受限 UART 退休 load → 寄存器版本 seed

日期：2026-10-06。P3 的一个受限子阶段，尚不代表 P3 完成。当前冻结源码的软件验证、实际在线记录，以及本次完整 fixture／fresh replay 门禁已通过。fixture 验证既有 FIFO／原生 IRQ／受控入口／退休读取路径与完整trace重放一致性；seed语义由另外的原始证据独立审计验证。

## 设计与真实性边界

`UartOperandSeedTracker` 独立重建 `UartRetiredReadLinker` 的原始 UART FIFO/RDATA 与 CPU load 证据。它要求真实 AdmissionRegistry、OwnershipMap、RuntimeEdgeIndex，完整 TransactionKey，实际 RVFI v2 POST receipt，以及 raw CPU 接收、响应、退休和对应派生证书一致。调用者自签的 accepted 标签不能授予来源证书。

允许的 seed 仅为普通 RV32 LW 对编译认证 UART RDATA 窗口的读取，且目标为非零的5位寄存器，写回值为32位；trap、RF 写抑制和 capability 标志必须严格为0。Pinned Ibex 的 `ext_rf_wr_suppress` 表示 load integrity error 导致 RF 写入被抑制，不能仅凭退休load就宣称寄存器获得来源。

寄存器版本由 component、reset epoch、retirement order、rd 组成。即使新写入值相同，也创建新的 unknown 版本。迟到的来源证明只追加历史版本证书；只有当前版本仍完全相同时才更新当前来源。flush、观测冲突及容量丢失引入 certainty barrier；屏障后的当前查询返回 None。实际同CPU域且epoch推进的reset可清除对应状态，UART reset不能代替CPU寄存器reset。

证书限定 UART 影响低8位；高位来源、后续 operand/copy/store 与一般 ISR 来源均未知。它不建立通用寄存器污点传播，也不改变 mutation/checker/corpus 策略。

## 已通过的软件证据

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| owner 的最终 seed 软件套件 | 41 passed，3.69s；compile exit0 | `.superpowers/sdd/current-dataflow-p3-uart-operand-seed-software-report.md` |
| Runner 接线与 seed 的独立组合检查 | 43 passed，3.57s，exit0 | `.superpowers/sdd/current-dataflow-p3-uart-operand-seed-runner-review.md` |

负例涵盖缺失原始证据、完整key更改、x0/trap/suppression/capability、类型与位宽、POST验证、同值覆盖后的旧proof迟到、malformed JSON、flush后current查询、过期event ID、1100条有界已消费numeric IDs、pending溢出和实际reset。软件fixture是模拟的实际形状receipt，不等同于真实RTL证据。

冻结模块 SHA256：`894eef6e9817976691ece96f4762a9bebeba05ac8dbac172a0ea52a6be278213`。Runner host、online session和fresh runtime三个source identity列表均纳入模块。现配置保持有限预算：seed pending256、CPU组件16、instruction witnesses2048；有限历史预算不能保证任意长度会话，真正取指历史GC仍需另行实现。

## 新实际 online 保存记录

保存目录：[finalfreeze-online](../../runs/current-dataflow-p2-controlled-entry-read-20261006-finalfreeze-online/)。`report.json` 记录 client_returncode0、execution_status complete、4个测试全部complete，seed43。该记录含48319个事件，**4条 accepted UART retired-read 与4条 accepted register seed**；本次fixture/fresh结果见下节；在线seed计数与seed语义审计仍分别说明。

| seed event ID | raw retirement event ID | 寄存器版本 |
| --- | --- | --- |
| 22126 | 22123 | cpu / epoch0 / order81 / x3 |
| 24612 | 24609 | cpu / epoch0 / order151 / x3 |
| 34786 | 34783 | cpu / epoch0 / order226 / x3 |
| 46408 | 46405 | cpu / epoch0 / order300 / x3 |

身份与保存文件：

- `online_run_identity.json` identity SHA256：`c5b858d07532d8f1b060f8545da5bd70eeba5bac5b66fc6ff9997b4643dd3ae4`。
- `online_final_trace.json` semantic SHA256：`b1a2f4b47846102e41b7cc2579192f816cf54e3f1f5ba60202082c7c2c2a7ff3`；文件 SHA256：`4e78b0d5eb52929ddb24820d876c45f766799cd4b3fdf09ab89a487ecc84f37a`。
- `online_session_manifest.json` 文件 SHA256：`235c326d72872b5bc60d30650573a5d3daed5939bab320a8021da72fe894f048`。其online source、Runner host与CPU/UART build身份均记录上述冻结模块SHA。
- trace内manifest语义SHA：`b2bc63049ad17453fe67fc3675f09ddbcb3a960e8e6744a5ebc505bfd366d473`；不要与manifest文件hash混用。

## 本次 fixture／fresh 与独立审计通过

本次冻结源实际门禁：**8 passed、8 subtests，250.72s，exit0**。使用上述finalfreeze-online与独立的`runs/current-dataflow-p2-controlled-entry-read-20261006-finalfreeze-replay-cache/`。同一保存运行另有一次独立 fixture 执行耗时 263.20 秒，记录于 P2 报告；两个耗时对应两次通过的执行。门禁前保存manifest中的35项online source与当前文件SHA全部一致，0 mismatch。

[实际fixture门禁日志](../../.superpowers/sdd/current-dataflow-p3-uart-operand-seed-finalfreeze-fixture-gate.md)记录raw saved/reconstructed范围检查、完整fresh wire-prefix与local ticks相等、删除／自签证据负例及typed-core检查。该fixture验证已建立的UART FIFO、native IRQ、controlled entry与retired read路径，并验证包含seed记录的整体trace fresh一致；它**不独立验证seed语义**。

seed语义由[原始证据独立审计](../../.superpowers/sdd/current-dataflow-p2-uart-operand-finalfreeze-audit.md)重建验证；[冻结身份审计](../../.superpowers/sdd/current-dataflow-p3-uart-seed-finalfreeze-identity-audit.md)另外确认source/build/binary一致性与4条seed、零UART incomplete/barrier。这些不同范围的检查合起来认证本次记录，不能据此宣称通用copy、operand/store传播或一般ISR来源已完成。历史旧源码门禁也不能代替本次源闭包验收。
