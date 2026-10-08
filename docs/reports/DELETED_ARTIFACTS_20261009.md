# 已删除的原始产物（2026-10-09 清理）

本仓库在 2026-10-09 做过一次 `runs/` 瘦身（114.75 GB → 19 GB，保留 72 个被引用目录 ＋ 5 个重建目录），删除了未被代码/测试/脚本引用的历史运行目录。
结果：**83 条指向这些目录的文档链接现在指向不存在的路径**（全部为本次清理所致，涉及 45 个运行目录、30 份文档）。
报告里的结论、数字与边界仍然有效（它们记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。

## 删除策略

| 类别 | 处理 |
|---|---|
| 被代码/测试/脚本引用（68 个目录） | 保留 |
| 当前 P5 验收证据（4 个目录） | 保留 |
| 无任何引用（99 个目录） | 删除 |
| 仅被文档引用（104 个目录） | 删除（含本清单中的目录） |
| 备份 tar 快照（36 GB）与构建缓存 `.gch/.o/.a`（31.7 GB） | 删除 |

## 已重建的（证据恢复）

| 运行 | 结果 |
|---|---|
| `runs/p3-ip-cross-case-20261007-online` | 已按原命令重建；60 例（57/2/1）、`IP_TO_CPU_TO_IP` 跨例 3、`case_gap` p50=max=1，与报告判据一致 |
| `runs/p3-ram-prereq-20261007-online` | 已重建；40/40 complete、`policy_matched=1`/`not_matched=39` 一致，但报告所述 `dynamic_binding` 字段未复现 |
| `runs/first-step-reproduction-20261008/` | 五项复现产物全部重建（P1 236 tests OK、P2 exit 0 ready、P3 exit 0 ready、P4 48 passed、P5 6/6） |

## 仍未恢复

| 项 | 说明 |
|---|---|
| `runs/cv32e40p-pulp-online-20261007` | P2 阶段报告的 CV32E40P 复用证据；可用 `scripts/run_cv32e40p_pulp_online.py` 重跑同预算恢复 |
| `runs/individual-review-20261008/` | 独立审核的两份产物；可按该文档方法重跑（不跑 RTL） |
| 其余历史 P2/P3 中间产物 | 不可恢复 |

## 断链明细（按文档）

| 文档 | 断链数 |
|---|---:|
| `docs/reports/current-dataflow-p2-gpio-consumption-20261006.md` | 12 |
| `docs/reports/ibex-pulp-online-rfuzz-smoke-20261006.md` | 8 |
| `docs/reports/current-dataflow-p3-read-issuance-capacity-20261007.md` | 7 |
| `docs/reports/current-dataflow-p2-controlled-entry-read-20261006.md` | 6 |
| `docs/reports/ibex-opentitan-uart-online-rfuzz-20261006.md` | 6 |
| `docs/reports/README.md` | 5 |
| `docs/reports/current-dataflow-p3-directed-writer-capacity-20261007.md` | 5 |
| `.superpowers/sdd/current-dataflow-p2-uart-fifo-saved-independent-audit.md` | 4 |
| `docs/reports/current-dataflow-p3-late-readback-capacity-20261007.md` | 4 |
| `docs/reports/current-dataflow-p2-retirement-frames-20261006.md` | 2 |
| `docs/reports/current-dataflow-p3-uart-operand-use-20261006.md` | 2 |
| `docs/reports/current-dataflow-p4-feedback-causal-branch-20261007.md` | 2 |
| `docs/reports/current-dataflow-p5-trace-write-efficiency-20261007.md` | 2 |
| `docs/reproduction/first-step-individual-review-20261008.md` | 2 |
| `docs/reports/current-dataflow-p2-uart-native-irq-20261006.md` | 1 |
| `docs/reports/current-dataflow-p3-current-tree-readback-20261007.md` | 1 |
| `docs/reports/current-dataflow-p3-host-ram-readback-real-gate-20261007.md` | 1 |
| `docs/reports/current-dataflow-p3-live-duration-buffer-20261007.md` | 1 |
| `docs/reports/current-dataflow-p3-readback-history-20261007.md` | 1 |
| `docs/reports/current-dataflow-p3-store-real-gate-20261007.md` | 1 |
| `docs/reports/current-dataflow-p3-uart-operand-seed-20261006.md` | 1 |
| `docs/reports/current-dataflow-p3-uart-ram-join-software-20261007.md` | 1 |
| `docs/reports/current-dataflow-p4-candidate-disposition-real-gate-20261007.md` | 1 |
| `docs/reports/current-dataflow-p4-candidate-identity-real-gate-20261007.md` | 1 |
| `docs/reports/current-dataflow-p4-feedback-real-gate-20261007.md` | 1 |
| `docs/reports/current-dataflow-p4-sb-uart-byte-real-gate-20261007.md` | 1 |
| `docs/reports/current-dataflow-p5-online-phase-timing-20261007.md` | 1 |
| `docs/reports/current-dataflow-p5-runner-router-scheduler-timing-20261007.md` | 1 |
| `docs/reports/current-dataflow-p5-trace-volume-audit-20261007.md` | 1 |
| `docs/reports/current-dataflow-p5-zlib-chunk-trace-20261007.md` | 1 |

## 涉及被删运行的清单

```
current-dataflow-p2-controlled-entry-read-20261006-capacity2048-frozen-online
current-dataflow-p2-controlled-entry-read-20261006-capacity2048-online
current-dataflow-p2-controlled-entry-read-20261006-current-p5lookup-online
current-dataflow-p2-controlled-entry-read-20261006-finalfreeze-online
current-dataflow-p2-controlled-entry-read-20261006-online
current-dataflow-p2-controlled-entry-read-20261006-snapshotp5-online
current-dataflow-p2-gpio-consumption-20261006-directed-final
current-dataflow-p2-gpio-consumption-20261006-directed-source-alias
current-dataflow-p2-gpio-consumption-20261006-online
current-dataflow-p2-gpio-consumption-20261006-online-bounded
current-dataflow-p2-gpio-consumption-20261006-online-source-alias
current-dataflow-p2-retirement-20261006-pulp-event-contract
current-dataflow-p2-retirement-20261006-uart-event-contract
current-dataflow-p2-uart-fifo-20261006-directed
current-dataflow-p2-uart-fifo-20261006-online
current-dataflow-p2-uart-native-irq-20261006-online-alias-fixed
current-dataflow-p3-efficiency-4-online
current-dataflow-p3-efficiency-review-100-online
current-dataflow-p3-efficiency-review-4-online
current-dataflow-p3-long-20261007-online
current-dataflow-p3-readback-final-20261007-online
current-dataflow-p3-readback-gc-20261007-online
current-dataflow-p3-store-20261007-online
current-dataflow-p3-uart-operand-use-20261006-freeze-online
current-dataflow-p3-uart-release-4-online
current-dataflow-p4-candidate-20261007-online
current-dataflow-p4-disposition-20261007-online
current-dataflow-p4-feedback-causal-20261007-actual_gain
current-dataflow-p4-feedback-causal-20261007-without_case15_gain
current-dataflow-p4-receipts-20261007-online
current-dataflow-p4-sb-online-20261007
current-dataflow-p5-timing-20261007-online
current-dataflow-p5-zlib-chunks-4-online
current-progress-p3-current-online
ibex-pulp-online-20261006-1k-ack
ibex-pulp-online-20261006-1k-journal
ibex-pulp-online-20261006-calibration2
ibex-pulp-online-20261006-final4
ibex-uart-online-20261006-12case
ibex-uart-online-20261006-directed2
individual-review-20261008
p3-capacity-directed-270-20261007
p3-late-readback-v2-270-20261007
p5-runner-timing-20261007-online
p5-writer-short-20261007
```

机器可读版：`docs/reports/deleted-artifacts-20261009.json`（83 条逐条 file/line/target）。
