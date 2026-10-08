# P5 在线例分项耗时：冻结源码真实 GPIO 短门禁

日期：2026-10-07。为提高最终 fuzz 门禁的可解释性，在线执行器在每例回执中记录单调时钟分项：选择/解码、真实 RTL `submit_case`、trace 摘要、交互事件摄入、checker、反馈/来源计分、回执构造及总耗时。计时仅作为回执诊断，不进入 SoC 语义 trace。失败例保留已完成分项，未完成分项为 0；因此失败例的全分项时间不能据此分摊。本次聚焦测试先因回执缺字段而失败，接入后 `tests/integration/test_scenario_rfuzz_terminal_identity.py`、`test_rfuzz_runtime_path_preflight.py` 与 `test_scenario_online_credit.py` 合计 **50 passed、7 subtests passed**。

运行绑定独立源码快照 `/home/qinkejiu/myfuzz_snapshot_p5_timing_20261007`。`src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 的 1,805 文件 [SHA-256 清单](../../runs/current-dataflow-p5-timing-snapshot-20261007.sha256) 哈希为 `9e13fc5ed731d7242b2cd2c982a08221c7b66102be8f77f2f47f4778f112af0f`；在线身份 36 个源码文件逐一与快照相同，清单 0 个差异。命令在快照目录执行：

```text
/usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/current-dataflow-p5-timing-20261007-cache \
  --output /home/qinkejiu/myfuzz/runs/current-dataflow-p5-timing-20261007-online \
  --seconds 30 --max-tests 100 --seed 20261007 \
  --run-id current-dataflow-p5-timing-20261007
```

运行退出码 0、100/100 `complete`、真实搜索 8.508 秒，保存 [逐例回执](../../runs/current-dataflow-p5-timing-20261007-online/receipts.jsonl)与完整 trace（38,625 事件）。100 例计时如下，单位秒；p95 采用排序后的线性插值。各分项是外层观测时间，`rtl_submit` 内部还包含 Runner、Router/Scheduler 与 RTL 进程，不能据此拆分它们。

| 分项 | p50 | p95 | 累计 |
|---|---:|---:|---:|
| 选择/解码 | 0.000073 | 0.000104 | 0.0075 |
| 真实 RTL submit | 0.077347 | 0.111055 | 7.9343 |
| trace 摘要 | 0.002590 | 0.003385 | 0.2702 |
| 交互事件摄入 | 0.001704 | 0.002347 | 0.2063 |
| checker | 0.000001 | 0.000001 | 0.0001 |
| 反馈/来源计分 | 0.000204 | 0.005917 | 0.1458 |
| 回执构造 | 0.000013 | 0.000017 | 0.0013 |
| 每例总处理 | 0.083295 | 0.118953 | 8.5655 |

证据终结另测得 `session_finish=1.342s`、`trace_write=1.205s`、`identity_write=0.151s`、终结至报告发布总计 2.748 秒。有效搜索时长定义与逐例总处理时长的测量边界不同，不应强求两者累计完全相等。

新进程使用独立 replay cache 和保存的 `online_plan.json`、`online_final_trace.json` 完整重放，退出码 0，`matches=true`、`first_difference=null`、`difference_context=null`。该短跑证明计时不改变此固定场景的保存语义。它没有对十分钟运行测 p50/p95，也不能独立证明完整传播链/s、逐例 Router/Scheduler 或 RTL 内部成本、故障保存质量和等覆盖冷启动对照，P5 仍未整阶段验收。
