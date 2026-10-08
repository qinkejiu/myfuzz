# 第一步 P1–P5 逐文件审阅记录

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
本记录针对当前工作树，区别于已经制作的归档快照。范围是 P1–P5 入口、验收判据、会话执行、来源证据和相关文档。本轮没有修改生产逻辑。

**状态：审阅进行中，尚未完成全范围逐文件审阅。** 下表是实际发现，不是待验证猜测；逐文件进度、源码 SHA256 与已读区间见 [`file-review-ledger.partial.json`](../../runs/individual-review-20261008/file-review-ledger.partial.json)（**部分重建**：原始台账已随 2026-10-09 清理删除且无法重建；本文件只记录本文引用位置与当前 SHA256，不代表原始进度）。台账中的候选集合还包含共享、历史模块和测试，`pending` 不代表已确认属于第一步，也不代表没有问题。`reviewed_full_text` 仅表示全文读过，不保证代码无缺陷；`reviewed_sections` 表示只核对了指定部分。

## 新发现与复现

| 编号／优先级 | 文件与位置 | 根因、观察结果与影响 |
|---|---|---|
| R1／高 | [`p5_acceptance.py:1509`](../../src/myfuzz/scenario/p5_acceptance.py#L1509)，`_judge_complete_prefix` | corpus 只检查身份清单中的文件名；trace 检查存在性、声明摘要和 meta 字段，未核实实际文件 SHA。小样例先通过，再删除 corpus、替换 trace 字节，仍 `met=true`。判据不能据此证明当前磁盘上的输入／trace 完整。历史真实运行是否损坏需单独核验，复现没有改动历史运行。|
| R2／高 | [`p5_acceptance.py:1847`](../../src/myfuzz/scenario/p5_acceptance.py#L1847)，`_judge_paired_budget` | `if continuous_seconds and cold_wall` 让零耗时跳过正值与加速比检查；缺少 `verified_case_count` 也不拒绝。两种变体各自仍 `met=true, reason=null`。效率结论与完整验证数量缺少必要前提。|
| R3／中 | [`session_runtime.py:745`](../../src/myfuzz/scenario/session_runtime.py#L745)，`submit_case`；bootstrap 观察也有相同异常保护缺口 | `_execute_case` 已缓存回执，再调用 gate 的 `observe`；观察异常未使会话终止。重试从缓存返回，不重做 `observe`。复现得到 `halted=false`、重试后观察调用仍为 1、下一例继续接纳。调用方若捕获异常继续使用，会在未更新前置状态下执行。|
| R4／中 | [`session_runtime.py:980`](../../src/myfuzz/scenario/session_runtime.py#L980)，`replay_online_session` | 启动后没有覆盖整段回放的 `try/finally`；非预期 step 异常跳过 `finish`。模拟 transport 故障后 `end_case` 调用次数为 0；复现最后显式清理。真实多组件会话存在残留资源风险；本轮没有启动真实进程，也不把此前 crash 直接归因于它。|
| R5／中 | [`edge_provenance.py:1936`](../../src/myfuzz/scenario/edge_provenance.py#L1936)，`report` 及末尾 wrapper | ingest 已生成的证书没有收入报告；flush 调用 `_settle` 已存储证书，report 又重复 extend。完整 journal：4 条 certified edge、ingest 4 条证书、report 0 条；部分 journal：flush report 1 条、内部存储 2 条。影响证书列表的完整性和内部计数一致性；边状态表本身在这个完整样例上仍为 4 条 certified。|
| R6／高 | [`closed_loop_feedback.py:136`](../../src/myfuzz/scenario/closed_loop_feedback.py#L136)，`certificate_hit` 与 ingest 去重 | 校验 hop 顺序和 `missing_hops` 声明，却不要求 certified 证书包含全部必需 hop。完整生产者证书删至首个 hop 后仍输出 `kind=closed_loop`、`reached_terminal_hop=false`。另一次只改同 ID 证书的 evidence 内容，投影后的 hit 相同，静默去重而非拒绝冲突。不能依赖这个消费接口阻止不完整／变更证据进入反馈。此处没有证明真实生产者会自然生成这种坏证书。|
| R7／中 | [`closed_loop_feedback.py:409`](../../src/myfuzz/scenario/closed_loop_feedback.py#L409)，`ClosedLoopFeedback.ingest` | 文档承诺整批验证后记录，但 ID 冲突检查发生在逐条写入循环。将同 ID、不同 action 的两条证书放在一个新 batch 中，第二条报错后 `certificate_count=1`。失败 batch 已部分改变状态，重试和增量反馈边界可能不一致。|

以上 7 组问题共 10 个观察场景，保存在 [`findings.json`](../../runs/individual-review-20261008/findings.json)（**重跑重建**：由下方脚本在当前源码上重跑得到，只含该脚本可复现的观察项）。复现脚本复用仓库已有单元样例，临时目录自动删除，不构建 RTL，不写原始运行：

```bash
ulimit -v 524288
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 scripts/reproduce_stage1_review_findings.py
```

本轮运行退出 0，表示脚本完成并输出观察；**不表示问题已修复或验收通过**。证据对当前台账所记源码有效，源码变化后应重做复现。

## 既有问题与文档核对

本轮全文读完 13 个代码文件，另有 14 个文件完成部分核对；相关区间逐一记入台账。新问题还沿调用链核对了 `ScenarioRfuzzExecutor._closed_loop_observe`：它创建 `ClosedLoopFeedback` 来消费证书，因此 R6 的漏检位于实际反馈接口。R7 的部分写入在这个调用点发生于临时 consumer 内，发生异常时 caller 不采用该批结果；不能把 R7 的公共 API 状态问题直接外推为该 caller 已部分更新权重。

此前确认的 CLI replay JSON 格式不匹配、配对身份缺字段仍可比、P4 `--skip-heavy` 仍运行高内存对照，以及“保存材料相同”被称作 `replay.verified` 的证明边界，继续列在[代码与文档核对](first-step-code-doc-audit-20261008.md)。本记录增加新发现，不重复计数。

- [P5 阶段报告](../reports/current-dataflow-p5-stage-acceptance-20261008.md)中“任何一项对不上…绝不静默通过”与 R1/R2 的负例冲突。此前保存产物的联合 6/6 是判据输出，不能替代缺失文件和零耗时负例的验证。
- [主实施计划](../superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)顶部同一状态段同时写“P2–P5 已通过”与“P5 未验收”，后续补充又写“仍未整阶段验收”。这些历史追加内容缺少明确的时点区分；目前只记录冲突，不擅自扩大或撤销历史验收范围。
- 此前链接检查证明的是引用可解析。内容核对需要将每个能力主张对应到判据、实现与冻结证据；尚未完成的文档保留在台账的待审范围。

## 继续审阅顺序

1. 读完 P1 身份与 replay 调用链，核实缺失／变更身份能否在启动前拒绝。
2. 读完 P2 逐边证据消费、淘汰和最终报告，核实事件排序、重复与容量边界。
3. 读完 P3 source action 与 executor，核实重试、前置状态、异常结束和跨例资源一致性。
4. 读完 P4 变异／反馈和对照分析，检查合法性、指标前提及内存保留结构。
5. 读完 P5 所有 judge 与 union，逐项核对主实施计划和报告中的能力主张。

修复建议应分别处理上述根因，并在修复前保留负例。本轮的交付是审阅发现与进度记录，生产代码尚未修复。
