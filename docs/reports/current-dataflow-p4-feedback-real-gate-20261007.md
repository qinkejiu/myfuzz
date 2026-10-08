# P4 路径反馈到后续选源：真实 GPIO 短门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。此报告绑定独立快照 `/home/qinkejiu/myfuzz_snapshot_p4_receipts_20261007`。快照 1,800 个源、配置、脚本、schema 和测试文件的[清单](../../runs/current-dataflow-p4-receipts-snapshot-20261007.sha256) SHA-256 是 `973505059a8a03b2e00d55dd9e6c8dab16893f2c2d4de46792dcb0424271e842`；运行及 replay 后重核 0 不符。在线身份列出的 34 个 source file 与快照逐一匹配。

在快照根目录运行 Ibex＋双 PULP GPIO 在线入口，RFuzz seed `20261007`、`--seconds 20 --max-tests 100`，缓存及输出分别为 `runs/current-dataflow-p4-receipts-20261007-cache`、[online 材料](../../runs/current-dataflow-p4-receipts-20261007-online/)。命令退出 0；100/100 例 complete，真实搜索 8.398 秒，38,625 条事件。v3 decoder manifest 声明 F4/F5 主要目标，receipt 中有 47 次 CPU 指令源/F4、53 次 GPIO B 外部 pin 源/F5。新进程使用独立 `runs/current-dataflow-p4-receipts-20261007-replay-cache` 对保存 plan 和完整 trace 执行 `scripts/run_ibex_pulp_online.py replay`，退出 0，`matches=true`，`first_difference=null`。

普通 `receipts.jsonl` 现在逐例持久化 `case_id/direction/flow_id/target_id/source_id/path_id/interaction_source_gains`。第 16 条 receipt（索引 15）的真实交互摘要含 `bound_delivered:gpio_a:gpio_b`、`irq_taken:gpio_b:cpu`、`mmio_write_delivered:cpu:gpio_a` 等新特征；有来源见证的增益分别记给 CPU 指令源 3 和 GPIO pin 源 4。该例接纳前权重为 CPU/GPIO `15/16`，下一例变为 `19/24`，并选择 GPIO 路径。不同例的 raw 输入也不同，因此这组在线记录证明真实新边进入下一例权重，不单独证明固定 raw 下的改选因果；后者由[同输入确定性语义测试](current-dataflow-p4-online-path-selection-20261007.md)隔离验证。

该 100 例 trace 的证据终结为 2.815 秒，其中 session finish 1.347 秒、JSON trace 写入 1.267 秒、identity 写入 0.150 秒。这是短跑数据。当前尚未证明 F1～F5 所有声明路径的合法变异、真实 RTL 内部分支覆盖、同预算独立驱动基线或十分钟完整链效率；P4、P5 均保持未验收。
