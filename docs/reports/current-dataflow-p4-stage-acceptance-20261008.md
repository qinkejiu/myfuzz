# P4 阶段验收（按声明范围）

日期：2026-10-08。本文按[主实施计划](../superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md) P4 的四条清单项与验收口径，逐项列出**已交付的代码与真实门禁证据**，并给出**声明范围与边界**。验收入口是 `scripts/run_p4_acceptance_suite.py`（`p4_acceptance_suite.v1`，只读串起已交付门禁）：

```bash
PYTHONPATH=src python3 scripts/run_p4_acceptance_suite.py --skip-heavy \
  --write runs/current-dataflow-p4-acceptance-20261008.json     # exit 0
# 关键项 8/8 成立、ready=True、unmet=[]；唯一非关键 partial = cpu_side_gate_verdict
```

## 清单逐项

### 1. 先按 F1～F6 目标与反馈选可执行路径，再选最上游 Fuzzable Source；方向/flow/路径/源/操作子写入候选身份；已绑定输入与持久字节不在可写集合

- 证据：[在线路径先选与 flow 身份](current-dataflow-p4-online-path-selection-20261007.md)、[候选身份真实门禁](current-dataflow-p4-candidate-identity-real-gate-20261007.md)、[路径选择熵真实门禁](current-dataflow-p4-path-entropy-real-gate-20261007.md)、[路径切换 live 门禁](current-dataflow-p4-path-switch-live-20261007.md)。
- 真实结果：25 例短门禁逐例 `candidate_id` 独立复算一致；1000 例路径分布 491/509；路径切换 live 对照枝 46/96、长枝 1199/2400 例候选被重定向，三枝 96/96、96/96、2400/2400 逐例复算一致且 fresh replay 一致；`ownership.bound_input`/`fixed_input` 在真实拒绝校准与算子门禁中均有拒绝例。

### 2. 合法操作子：指令替换/插入/删除/操作数/立即数、初始 RAM 数据、外设环境源、因果序列、路径切换；每种操作子保存采用/拒绝原因

| 操作子 | 真实证据 |
|---|---|
| CPU 指令立即数/操作数（XORI） | [XORI 真实退休门禁](current-dataflow-p4-xori-retirement-real-gate-20261007.md)：25/25 例、3 条 XORI 真实取指来源 + RVFI 退休 |
| 移位立即数 SLLI/SRLI/SRAI | [移位操作子真实退休](current-dataflow-p4-shift-operators-real-20261007.md)：83/83 例、7 条移位全部 `matcher=accepted` |
| **指令插入/删除（序列编辑）** | [序列编辑真实门禁](current-dataflow-p4-sequence-edit-real-gate-plan-20261008.md)：种子 raw 直投两枝各 8/8，六项判据全 proven（含 RVFI 逐字退休与保留区走查） |
| **初始 RAM 数据** | [初始 RAM 数据算子](current-dataflow-p4-initial-ram-data-operator-20261007.md)：真实 Ibex 首次读回 `0x94`、writer kind `INITIAL_IMAGE`、slot 判 `immutable` |
| 外设环境源（GPIO pin8 / UART RX） | 路径熵/候选身份门禁与 UART 侧运行，实际消费由链证书与消费证书证明 |
| **路径切换** | [路径切换 live 门禁](current-dataflow-p4-path-switch-live-20261007.md)（同上） |
| MMIO 字节写（`SB` lane 0） | [UART `SB` 真实短门禁](current-dataflow-p4-sb-uart-byte-real-gate-20261007.md) |
| 采用/拒绝原因 | [37 个分层拒绝码](current-dataflow-p4-rejection-codes-20261007.md) + [真实 7 类拒绝＋1 类不确定](current-dataflow-p4-rejection-calibration-real-20261007.md)（每条带精确 `code`/`pointer`） |

### 3. 真实事件分别建立路径阶段/依赖边/状态转移/完整闭环反馈；区分端口语义命中与真实 RTL 内部分支覆盖

- 路径阶段与依赖边：[P2 逐边来源（通用消费者）](current-dataflow-p2-edge-provenance-20261007.md)（9/9 声明边认证）与[链证书](current-dataflow-p5-chain-600s-20261007.md)（600 秒 27 条认证链）。
- 状态转移与闭环：[闭环反馈 A/B](current-dataflow-p4-closed-loop-live-ab-20261007.md)（ON 结算 7 条闭环命中）。
- 分离计数：[RTL 内部分支覆盖](current-dataflow-p4-rtl-branch-coverage-20261007.md)（插桩身份 28/28 校验）+ **本轮修复**：[CPU 侧映射修复真实生效](current-dataflow-p4-cpu-side-branch-coverage-real-20261008.md) —— CPU `elaborated-lit=12`/64、`unelaborated-bound=0`；[可判定化](current-dataflow-p4-cpu-side-gate-decidability-20261008.md)后 profile 路径 `--min-cpu-points 1` **8/8 判据 PASS**；[first_seen 真实台账](current-dataflow-p4-first-seen-real-20261008.md)（30 点、`event` 为协议请求号、独立交叉复核 exit 0）。

### 4. 依新目标/新边/失败证据分配 energy，并保留同 seed 基线

- [同前缀反馈因果分支](current-dataflow-p4-feedback-causal-branch-20261007.md)：相同 raw 下仅扣除当例增益即改选并实际消费不同源。
- [算子收益同预算对照](current-dataflow-p4-operator-benefit-comparison-20261008.md)：三对同 seed/同预算真实 A/B，**结论是本预算下没有算子显示覆盖或完整链收益**（初始 RAM 96/96 判定一致、路径切换不改目标位与链数、闭环能量改选源但证书更少）。
- [臂等价判定](current-dataflow-p5-arm-equivalence-20261008.md)：5 对臂逐字段等价/不等价/未知，无一对 `claimed=true`。

## 验收口径对照

| 验收要求 | 证据 |
|---|---|
| 指定 F5/CPU IRQ 目标时实际变异上游 GPIO pin/程序源，不能直接覆写 CPU IRQ | 在线候选池按路径反向选最上游源；`ownership.bound_input`/`fixed_input` 拒绝直接覆写已绑定输入（真实拒绝例） |
| 受信字段描述拒绝协议保留位、错误宽度、已绑定输入 | 37 码 + 真实 7 类拒绝（含 `mmio.bad_width`、`ownership.bound_input`） |
| 真实 Store/取指后的程序字节不能被后例变异 | [slot 不可变性全扫描](current-dataflow-p4-slot-immutability-sweep-20261008.md)：10 个运行 **36,985 个 slot 全 immutable、0 violated/0 insufficient**；1 个无 manifest/trace 的运行记 `unavailable` |
| 候选 trace 显示流类别/path/源/前状态/真实中间输出与下游消费 | 候选身份与接纳原因门禁（`direction/flow_id/path_id/source_id/operator_id/candidate_id` + `online_weights` 前状态 + 选源原因）；[通用消费端证书](current-dataflow-p4-computed-consumer-generic-20261008.md) 192 认证（GPIO 178 + UART 串口字节等） |
| 同一条跨例链的增量反馈至少一次改变后续选源/能量 | 同前缀反馈因果分支 + 闭环 A/B |
| 固定预算对照分别报告有效执行数、完整链数、各类覆盖与 replay 成功数 | 算子收益对照（例数/有效秒/目标位/链证书）+ 各算子门禁的 fresh replay `matches=true` + 臂等价判定的窗口与字段表 |

## 声明范围（本文主张什么）

在**当前 Ibex＋双 PULP GPIO 在线 wiring**、**声明式受信 profile/模板**与**已保存/新录的真实 RTL 产物**范围内，P4 四条清单项与验收口径均有真实证据；整阶段入口 `p4_acceptance_suite.v1` 关键项 **8/8 成立**（含 `first_seen_ledger` 与 `cpu_side_gate_decidable`）。

## 边界（本文不主张什么）

- **F4/SPI transfer 实例未覆盖**：当前 wiring 没有 SPI 目标，该条属 P6 的多协议实例范围；P4 只证明"按目标反向选择上游源"这一机制在 F5/CPU IRQ 上真实成立。
- **算子在固定预算下的收益未被证明**：三对对照与臂等价判定都显示本预算/seed/负载下没有可测的覆盖或完整链增益；这不等于"算子无效"，但也不构成收益证据。
- **CPU 侧 8 点阈值是搜索质量问题**：`--min-cpu-points 8` 在 600 秒运行上 FAIL（点亮 6/64），门禁把该失败与映射问题分开报告；本阶段不主张"CPU 侧点亮度达标"。
- **消费端证书的边界**：只证被使能 lane 上的值同一性沿声明键成立，不证寄存器堆/设备内部 FIFO 溯源、跨指令依赖、消费逻辑正确性与路由归属。
- **`first_seen` 只在 soc_* 插桩路径产生**，且粒度是"每次测试回读"，不是 RTL 内部分支求值时刻；在线数据流会话不写该字段。
- **slot 不可变性只覆盖被事件触及的字节**（每个运行还有 99,076～126,372 个声明字节未被触及，只计数不主张）；序列编辑两枝覆盖率约 0.27%。
- **拒绝码 37 个中其余分支在在线路径不可达**，未授予证据。
- 本阶段验收不涉及 P5 的异构外设长会话、故障灵敏度与链终点回流（见 P5 相关报告与边界）。
