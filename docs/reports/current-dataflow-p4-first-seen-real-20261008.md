# P4 `first_seen` 写侧补齐与真实台账

日期：2026-10-08。P4 分支覆盖报告长期记着一条边界：**`first_seen` 不可用**——检查器 `myfuzz.scenario.rtl_branch_coverage` 早已支持该字段，但产物里从不记录 per-point 首次命中证据（永远 `available=false` + 原因）。本报告给出写侧实现与真实运行结果。

## 证据来源（可证明、最便宜）

soc_* 仿真器**本来就**在每个 RTL 测试后回读整条插桩计数器向量（`RtlSimulator.run_test`，模拟器协议 v2 的 `RFUZZ_COUNTERS <request id>`）。某个点第一次在回读里非零的那次测试，就是它的首次命中：协议请求号是事件身份，回读的单调时钟偏移是时间。**因此不需要改 Rust 客户端、不需要改 harness 渲染、不需要改协议**——台账由已有的回读路径写出。

被明确否决的方案（都写进报告）：Rust 客户端每测试计数器（客户端从不把计数器送回主机，`report.json` 只留 `coverage_maxima`，且 Rust 属禁改范围）；`live/checkpoints.jsonl`（30 秒分桶，只能给上界，会把某个分桶错当成首次命中）；语料 `trace_bits`（运行后幸存者快照）；新增 harness 锁存端口（需要客户端读回，属协议改动）。

## 交付物（全部在 soc_* 路径，在线路径零改动）

| 文件 | 作用 |
|---|---|
| `src/myfuzz/integration/soc_coverage.py` | 台账 schema/常量：`soc_coverage_first_seen.v1`、`FIRST_SEEN_EVIDENCE="per-test-counter-readback"`、`MAX_FIRST_SEEN_ENTRIES=65536`（等于检查器上界）、16 MiB 读取上界 |
| `src/myfuzz/integration/rfuzz_simulator.py` | `CoverageFirstSeenLedger`（条目身份绑定、失败关闭、每会话只写一次、原子写、写失败只返回不抛）、`first_seen_ledger_for_artifact()`、`run_test` 记录点、`close()` 落盘；带一个"在线路径默认不声明该字段、因此什么都不写"的测试 |
| `src/myfuzz/integration/soc_builder.py` | `coverage_first_seen_evidence()` 声明 + `first_seen_ledger_path()`；写进**两种** provenance 形态（嵌套 `coverage.first_seen` 与扁平 `coverage_instrumentation.first_seen`）；旧缓存条目什么都不声明 |
| `scripts/report_rtl_branch_coverage.py` | 把台账按**运行自己的 plan** 逐位 join（schema／counter_count／points 逐元素相等、每个非空条目必须命名自己的点、`truncated` 直接拒绝、点亮的计数器必须有条目），通过才交给 shipped 检查器；输出 `first_seen_source` |
| `tests/scenario/test_rtl_branch_coverage_first_seen.py` | 39 项测试（先写后实现：RED 33 失败／1 通过 → GREEN 39 通过） |

## 真实运行结果

```bash
MYFUZZ_SOC_REAL=1 python3 runs/current-dataflow-p4-cpu-side-20261008-logs/run_single_cell.py \
  --output runs/p4-cpu-side-first-seen-20261008-online --seconds 300 --seed 20260926 \
  --cell ibex-pulp --mode cpu_only
```

- 运行：300 秒、**54,157 次 RTL 测试**（`readbacks` 与 `actual_rtl_execution.tests` 相等）、128 个观测点、点亮 **30/128**。
- 报告 CLI：`status=verified`、`observed_branches.first_seen.available=**true**`、`points=30`、`earliest={"bit":21,"event":1,"port":"__vi_coverage","time":0.016486}`；条目形如 `{"bit":21,"event":1,"port":"__vi_coverage","time":0.016486}`——**事件是那次回读的协议请求号，时间是该回读的实测偏移**，没有编造时间戳。
- 独立交叉复核（脚本内的断言，exit 0）：`OK points=128 lit=30 readbacks=54157`——台账 `points` 与 plan 的暴露端口逐位相等、`counter_count == len(coverage_maxima)`、**台账"已命中"集合与计数器非零集合完全相等**、每个条目命名自己的点、`readbacks == actual_rtl_execution.tests`。
- 诊断（只读）：CPU 侧 `elaborated-lit=12`/64、IP 18/64、`unelaborated-bound=0`。
- 该 campaign 自身的 `final_status=failed-acceptance`（`evidence_missing=[source_transactions,target_transactions]`，与上一次 legacy 单 cell 运行同一现象），与本报告的覆盖证据无关；本报告不主张该 campaign 的验收状态。

**兼容性**：没有台账的旧产物仍然 `available=false` + 精确原因（在真实的 `runs/p4-cpu-side-coverage-20261008-online` 上只读复核：`first_seen=no reason=the artifact preserves no per-point first-seen evidence`，exit 0），**绝不写成 0**。

## 边界

- 台账只覆盖**这些运行自己的**计数器；`first_seen` 证明"哪一次回读第一次看见该点非零"，不证明 RTL 内部该分支在更细粒度上第一次被求值（回读是每测试一次）。
- 首次命中的**事件/时间**不期望在重跑中复现（时间预算 fuzzing）；可复现的是台账与 plan/计数器的身份一致性和文档判定。
- 该证据只在 soc_* 插桩路径产生；在线数据流会话（`scenario_rfuzz`）不写该字段。
- `--min-cpu-points` 之类的搜索质量问题不在本报告范围（见[CPU 侧覆盖真实报告](current-dataflow-p4-cpu-side-branch-coverage-real-20261008.md)）。
