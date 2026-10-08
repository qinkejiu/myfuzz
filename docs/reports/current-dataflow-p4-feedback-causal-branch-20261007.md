# P4 同前缀、同输入下反馈增益改变后续选源

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。本门禁从既有[100 例真实反馈运行](current-dataflow-p4-feedback-real-gate-20261007.md)的冻结源码 `/home/qinkejiu/myfuzz_snapshot_p4_receipts_20261007` 重演前 16 例。该源码的 1,800 文件 [SHA-256 清单](../../runs/current-dataflow-p4-receipts-snapshot-20261007.sha256)哈希 `973505059a8a03b2e00d55dd9e6c8dab16893f2c2d4de46792dcb0424271e842`，本次重核 0 差异。重演 16/16 个已保存的选择、权重和状态均吻合，两个分支前缀每例 `semantic_sha256` 完全相同。

第 16 例（索引 15）的真实事件给 CPU 指令源和 GPIO B pin8 源分别记 **3** 与 **4** 个有来源见证的交互增益。它使下一例权重为 CPU/GPIO **19/24**。仅在对照分支中扣除这一例刚产生的两个增益，保留同一 RTL 前缀、decoder 游标、源使用次数、此前全部增益和目标命中状态，下一例权重为 **14/16**。对两支提交相同的合法 8 字节输入 `000701d10d0106b0`，只改变本次反馈增益是否参加路径选择。

| 分支 | CPU/GPIO 权重 | 实际选中路径／源 | 真实消费 | 本例状态 | 完整 trace 事件 |
|---|---|---|---|---|---:|
| 保留本次增益 | 19/24 | CPU→IP→CPU／`cpu.online_instruction` | 源 ID 在实际消费列表 | complete | 6,915 |
| 仅扣除本次增益 | 14/16 | IP→CPU→IP／`gpio_b.external_pin8` | 源 ID 在实际消费列表 | complete | 7,063 |

两次真实 Ibex＋双 PULP GPIO RTL 运行各保存独立[保留增益 plan/trace](../../runs/current-dataflow-p4-feedback-causal-20261007-actual_gain/)与[扣除增益 plan/trace](../../runs/current-dataflow-p4-feedback-causal-20261007-without_case15_gain/)；[摘要](../../runs/current-dataflow-p4-feedback-causal-20261007-summary.json)记录相同前缀的 16 个语义摘要、增益、权重、路径、源、实际消费和文件哈希。在原运行结束后的新 Python 进程中，两支分别用新建 RTL Runner 对完整 17 例前缀执行 `replay_online_session`；两支均 `matches=true`、`first_difference=null`、`difference_context=null`，结果文件在各自目录内。

这证明此受控输入下，**该次真实反馈增益足以使下一例选源和真实 RTL 消费方向改变**。原 100 例 RFuzz 自然下一输入不同；直接用它的第 17 例输入对比 15/16 与 19/24 虽也会改选，但单独扣除新增益后的 14/16 仍选 GPIO，因此自然第 17 例的改选不能只归因于新增益。本门禁特意构造了可区分两种权重的下一例 raw，证明调度机制的因果作用；它不是独立 RFuzz 预算的覆盖优势，也不证明完整传播链、RTL 内部分支覆盖或 P4 整阶段验收。
