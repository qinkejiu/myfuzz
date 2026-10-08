# P5 在线 Runner、Router、Scheduler 内部分项计时短门禁

> **⚠ 复算可用性（2026-10-09 更新）**：本文引用的部分原始产物目录在 2026-10-09 的 `runs/` 清理中被删除，因此文中指向 `runs/` 的链接可能失效。**报告的结论、数字与边界仍然有效**（记录的是当时真实执行的结果），但"从原始产物复算"的能力已不存在。删除范围、已重建项与逐条断链清单见 [已删除的原始产物](DELETED_ARTIFACTS_20261009.md)。
日期：2026-10-07。本轮在在线 `submit_case` 作用域内记录同步调用的单调时钟耗时。逐例 `receipts.jsonl` 新增 `online_runner_timing_seconds`，包含 `scheduler_batch`、`runner_step`、`router_enqueue`、`router_drain`、`router_transact` 和 `observed_output_route`。观察器通过 `ContextVar` 仅在当前例启用，成功和异常都在 `finally` 中结算；作用域外不记录。每个计时点只更新一个小计数表，没有扫描历史事件或复制 trace。字段只属于诊断回执，不进入事件或语义哈希。

这些计时是**包含子调用的壁钟时间**：`scheduler_batch` 包含 `runner_step`，`runner_step` 包含 Router 与本地命令，`router_drain` 可以包含真实目标的命令往返，`observed_output_route` 是 Runner 对已观察输出的传播处理。它们不能相加，也不能直接从任一项推得纯 RTL 求值时间。已有 `online_submit_timing_seconds.local_command_roundtrip` 也可能落在上述区间内。

## 定向测试和真实短跑

测试先因缺少 `observe_runtime_timings` 导入失败；接线后运行：

```bash
PYTHONPATH=src:. python3 -m pytest \
  tests/integration/test_scenario_rfuzz_terminal_identity.py \
  tests/scenario/test_dataflow_router.py \
  tests/scenario/test_runner_continuity.py \
  tests/scenario/test_online_session_partial_replay.py \
  tests/integration/test_p5_runtime_timing_receipts.py \
  tests/scenario/test_runtime_timing_observer.py -q
```

结果为 **53 passed、4 subtests passed**。新增测试检查计时观察器作用域、异常保留、回执字段、非零 Runner/Scheduler 时间及语义事件中不出现计时字段。`git diff --check` 对本轮文件退出 0。

真实门禁用 `/home/qinkejiu/myfuzz_snapshot_p5_runner_timing_20261007` 独立源码快照；运行与 replay 使用不同的 harness 缓存：

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_runner_timing_20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-runner-timing-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/p5-runner-timing-20261007-online \
  --seconds 8 --max-tests 16 --seed 20261007 --run-id p5-runner-timing-20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-runner-timing-20261007-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/p5-runner-timing-20261007-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/p5-runner-timing-20261007-online/online_final_trace.json
```

运行退出 0、16/16 `complete`，有效搜索 1.203980 秒；完整 trace 有 6,996 事件，语义 SHA-256 为 `695fa8ee588d3d8941024b2725569377f321b54c517a7ef1053031eb0b6303c4`。replay 退出 0，`matches=true`、`first_difference=null`、`difference_context=null`。回执及完整 trace 位于 [短跑目录](../../runs/p5-runner-timing-20261007-online)。与先前 16 例命令往返短跑的语义哈希相同，但两次运行的计时不能当作严格性能对照。

| 逐例分项，秒 | p50 | p95 | 16 例累计 |
|---|---:|---:|---:|
| Scheduler 批次调用 | 0.059736 | 0.076641 | 1.005968 |
| Runner step | 0.059629 | 0.076544 | 1.004345 |
| Runner 已观察输出传播 | 0.001546 | 0.004076 | 0.032078 |
| Router 排队接收 | 0.000014 | 0.000024 | 0.000177 |
| Router 排队交付 | 0.000349 | 0.000978 | 0.005774 |
| Router 同步事务 | 0 | 0 | 0 |

分位数对 16 例排序后作线性插值。16 例 Scheduler、Runner 和输出传播均有非零观测；10 例进入 Router 排队接收及交付，默认 GPIO 场景未调用同步 `transact`。累计 `rtl_submit` 1.194531 秒，其中 `scheduler_batch` 1.005968 秒；两者差额仍含输入准入、case 回执构造、证据处理和计时开销，不能简单归属给 Scheduler。Router 的排队交付计时可能包含目标 RTL 命令。

本轮是 16 例真实 RTL 短门禁。它没有十分钟同条件冷启动对照、完整传播链/s 或纯 RTL 进程内部计时，不构成 P5 整阶段验收。
