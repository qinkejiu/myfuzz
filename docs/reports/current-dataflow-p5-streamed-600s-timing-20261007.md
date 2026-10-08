# P5 流式终结后的 600 秒真实 GPIO 计时门禁

日期：2026-10-07。此门禁把逐例在线分项计时、证据终结耗时和独立 fresh replay 放在同一次冻结源码运行中核对。`scripts/runs/summarize_p5_online_timing.py` 逐行读取回执，不加载约 2.28 GB 的事件 JSONL；它要求全部案例 `complete`、没有 checker violation、全部案例具有合法分项计时、有效搜索至少 600 秒、终结分项完整、trace/plan/在线身份存在且 fresh replay 全量一致。脚本对不满足项返回退出码 2 并列出 `failed_checks`。

## 源码、运行与初步结果

源码快照：`/home/qinkejiu/myfuzz_snapshot_p5_stream_20261007`，从独立快照复制后同步当时的 `src/`、`configs/`、`scripts/`、`schemas/`、`tests/`。2,742 文件 SHA-256 清单位于 `runs/current-dataflow-p5-stream-600s-20261007/snapshot.sha256`，清单自身 SHA-256 为 `ca0129492610f098fa8c006ed770569f4d3b9f0eadfeeba6d197e4fca84f2b9d`。运行后 `sha256sum -c --quiet` 退出 0，零差异。快照中包含流式 JSONL 终结和在线逐例分项计时。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_stream_20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/online \
  --seconds 600 --max-tests 20000 --seed 20261007 \
  --run-id current-dataflow-p5-stream-600s-20261007
```

命令退出 0。`report.json`：6,276/6,276 `complete`，有效搜索 600.105372 秒，吞吐 10.458 例/秒，767 次反馈交换。完整 trace 含 2,112,036 个事件，`online_events.jsonl` 2,276,752,852 字节；语义 SHA-256 为 `cf840b1cb2ceaed43a0061fdb36a5981e12ec53b911e0048af0f0f80b077664b`，在线运行身份 SHA-256 为 `7844afd9724223485715e431a0a20ebeeb9cb7374c95561cdda6eadb5cc56ed9`。

终结计时来自同一 `report.json`：`session_finish=11.269s`、`plan_write=0.033s`、`trace_write=79.981s`、`identity_write=2.581s`、报告发布前合计 `93.915s`。这些是搜索后的证据成本；有效搜索分母不含这 93.915 秒。JSONL 写入阶段吞吐约 28.5 MB/s（十进制 MB），包含 JSON 编码、语义 SHA、写盘和 `fsync`，并非磁盘纯写速度。

## 重放和逐例统计

独立缓存的完整 fresh replay 命令：

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_stream_20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/time \
  -f 'replay_wall_seconds=%e\nreplay_peak_kb=%M' \
  -o /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/replay-time.txt \
  /usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/online/online_final_trace.meta.json \
  > /home/qinkejiu/myfuzz/runs/current-dataflow-p5-stream-600s-20261007/replay.json
```

fresh replay 退出 0，`matches=true`、`first_difference=null`、`difference_context=null`，独立壁钟耗时 695.10 秒，`/usr/bin/time` 峰值常驻内存记录为 415,332 KB。重放后再次执行 `sha256sum -c --quiet`，快照清单仍为零差异。统计命令：

```bash
cd /home/qinkejiu/myfuzz
python3 scripts/runs/summarize_p5_online_timing.py \
  --output runs/current-dataflow-p5-stream-600s-20261007/online \
  --replay-result runs/current-dataflow-p5-stream-600s-20261007/replay.json \
  > runs/current-dataflow-p5-stream-600s-20261007/timing-summary.json
```

命令退出 0，保存的 `timing-summary.json` 给出 `gate_passed=true`、`failed_checks=[]`、6,276/6,276 例有完整计时及 checker 字段、0 个 checker violation。分位数按 6,276 例排序后线性插值，单位秒；累计值为所有案例该分项之和。

| 分项 | p50 | p95 | 累计 |
|---|---:|---:|---:|
| 选择/解码 | 0.000081 | 0.000108 | 0.519 |
| 真实 RTL submit | 0.070737 | 0.103567 | 557.795 |
| trace 摘要 | 0.002399 | 0.003342 | 15.737 |
| 交互事件摄入 | 0.001780 | 0.002442 | 11.686 |
| checker | 0.000001 | 0.000002 | 0.006 |
| 反馈/来源计分 | 0.000166 | 0.006177 | 7.549 |
| 回执构造 | 0.000012 | 0.000017 | 0.076 |
| 每例总处理 | 0.075683 | 0.110623 | 593.370 |

`rtl_submit` 占逐例总处理累计时间约 94.0%；逐例总处理累计 593.370 秒与有效搜索 600.105 秒的测量边界不同，差额包含传输、调度和循环开销，不应分配给某个已记录的分项。终结 93.915 秒约为有效搜索时长的 15.6%，fresh replay 另需 695.10 秒；验收时应分别预算搜索、证据终结和重放。

定向验证：`PYTHONPATH=src:. python3 -m pytest tests/integration/test_p5_online_timing_gate.py tests/integration/test_scenario_rfuzz_terminal_identity.py -q`，**30 passed、2 subtests passed**。新增测试先因汇总模块缺失失败，再因缺少可诊断 `failed_checks` 和缺失 checker 字段未被拒绝而失败，随后通过；覆盖分位数、证据字段、失败状态、重放不匹配、搜索预算不足及缺失分项计时。`git diff --check` 对新增脚本、测试和报告退出 0。

## 解释边界

这一轮启用默认 Ibex＋两个 PULP GPIO 场景与默认 checker；没有添加新的 GPIO 消费或 CPU retirement 探针，因此 `complete` 和路径标签不能算作完整的源→IRQ→CPU→输出传播链。逐例 `rtl_submit` 仍是 Runner、Router/Scheduler 和 RTL 进程的合并耗时；分项表不能把这些内部成本拆开。与 2026-10-06 的 5,563 例冻结快照长跑不是同一源码及负载，吞吐差值不能归因于流式写入。流式写入的固定事件集旧/新路径对照见[既有报告](current-dataflow-p5-streamed-final-trace-20261007.md)，本轮提供新路径的真实 600 秒终结实测。
