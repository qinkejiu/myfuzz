# P5 在线 submit 的本地命令往返计时

日期：2026-10-07。此轮把既有逐例 `rtl_submit` 窗口分为本地驱动命令往返与其余主机时间，保持案例、事件、trace 和 fresh replay 语义。它测量可无损观测的调用边界，不宣称已测得纯 RTL 求值时间。

## 测量边界

`GeneratedLocalSession.command()` 在启用观察器时测量进入命令到取得完整驱动回执或抛出异常的壁钟时间。它包括主机验证/编码、管道写入、等待独立驱动进程、真实 RTL 执行、回执读取/解析和可能的 ACK；这些成本无法从该调用再无损分离。在线 `submit_case()` 期间用 `ContextVar` 启用观察器，逐例记录 `local_command_roundtrip` 累计秒数和 `local_command_count`。`host_remainder = rtl_submit - local_command_roundtrip`，覆盖 Session/Runner/Router 路径、来源注入、事件及证据处理、局部驱动在 `command()` 外的工作，也包含少量计时开销。逐次命令同步且不相互嵌套，两个时间段在同一 submit 窗口内不重叠。计时作为回执元数据保存，不进入语义事件或 trace 哈希。

异常路径也在 `finally` 中保存已执行命令的测量；观察器作用域结束即复位。现有 `online_phase_timing_seconds.rtl_submit` 保持原定义，新增 `online_submit_timing_seconds` 存在 `receipts.jsonl` 中。

## 冻结源码真实 RTL 短门禁

源码快照：`/home/qinkejiu/myfuzz_snapshot_p5_command_timing_20261007`。`src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 共 2,749 个文件的 SHA-256 清单为 `runs/p5-command-timing-snapshot.sha256`，清单 SHA-256 是 `0147c2403b0331fc44a59aac59c562612ae51d1b3797eebe5b396dab07472176`。运行与 replay 后，快照内 `sha256sum -c --quiet` 退出 0。独立缓存构建的命令如下：

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_command_timing_20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-command-timing-cache \
  --output /home/qinkejiu/myfuzz/runs/p5-command-timing-online \
  --seconds 8 --max-tests 16 --seed 20261007 --run-id p5-command-timing-20261007

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-command-timing-replay-cache \
  --plan /home/qinkejiu/myfuzz/runs/p5-command-timing-online/online_plan.json \
  --trace /home/qinkejiu/myfuzz/runs/p5-command-timing-online/online_final_trace.json \
  > /home/qinkejiu/myfuzz/runs/p5-command-timing-replay.json
```

运行 16/16 `complete`，有效搜索 1.466229 秒，trace 6,996 个事件，语义 SHA-256 `695fa8ee588d3d8941024b2725569377f321b54c517a7ef1053031eb0b6303c4`。fresh replay 退出 0，`matches=true`、`first_difference=null`、`difference_context=null`。所有 16 例本地命令数均非零，总计 1,549 次。分位数按案例线性插值，单位秒：

| 逐例分项 | p50 | p95 | 累计 |
|---|---:|---:|---:|
| 原 `rtl_submit` 总窗口 | 0.087162 | 0.118851 | 1.453906 |
| 本地命令往返 | 0.028604 | 0.032945 | 0.463751 |
| submit 内其余主机时间 | 0.057904 | 0.089230 | 0.990156 |

命令往返占本次累计 submit 窗口约 31.9%，其余部分约 68.1%。这是这 16 例的调用边界分解，不能与旧 600 秒运行直接比较占比；两者不是同一源码、运行时间或负载。尤其不能由 `local_command_roundtrip` 推出纯 RTL eval、进程 IPC 或 JSON 解析各自成本，也不能由 `host_remainder` 推出 Runner、Router 和 Scheduler 各自成本。

定向测试：`PYTHONPATH=src:. python3 -m pytest tests/local_harness/test_command_timing_observer.py tests/integration/test_scenario_rfuzz_terminal_identity.py -q`，24 passed、2 subtests passed。`git diff --check` 对本轮文件退出 0。短门禁验证了字段、加和、作用域复位及异常不吞没，不能代替完整 600 秒效率门禁或完整传播链吞吐门禁。
