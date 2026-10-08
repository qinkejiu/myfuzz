# P5 Runner/Router/Scheduler 十分钟在线计时与压缩终结实测

日期：2026-10-07。本轮把已有的在线逐例外层计时、Runner/Router/Scheduler 嵌套计时和可选分块 zlib 终态事件格式放进同一次冻结源码真实 Ibex＋双 PULP GPIO 搜索。它测量此默认 GPIO 负载的吞吐、逐例延迟、压缩证据终结和完整 fresh replay 成本。P5 整阶段仍未验收。

## 冻结身份与执行

源码快照为 `/home/qinkejiu/myfuzz_snapshot_p5_runner_zlib_600s_20261007`。`src/`、`configs/`、`scripts/`、`schemas/`、`tests/` 的 2,766 文件 SHA-256 清单保存在 `runs/p5-runner-zlib-600s-20261007/snapshot.sha256`，清单 SHA-256 为 `ee6191e8f5344f260d2ce17a51f5e6cd2f711bd3562decfe7d657eede49100bd`。快照内 `kfuzz` SHA-256 为 `d10256615cc9e35beeee75d40c75b1b5c8b30471fc6041f493a89043f1f52bf9`；运行 CLI SHA-256 为 `91f15293b27ee7316823d834b7fcbbca22a8e2085cae527c30228ba9e612b91b`。在线运行后与首轮重放后，清单检查均退出 0。

```bash
cd /home/qinkejiu/myfuzz_snapshot_p5_runner_zlib_600s_20261007
PYTHONDONTWRITEBYTECODE=1 /usr/bin/time \
  -f 'run_wall_seconds=%e\nrun_peak_kb=%M' \
  -o /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/run-time.txt \
  /usr/bin/python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/cache \
  --output /home/qinkejiu/myfuzz/runs/p5-runner-zlib-600s-20261007/online \
  --seconds 600 --max-tests 20000 --seed 20261007 \
  --run-id p5-runner-zlib-600s-20261007 --compressed-trace
```

命令退出 0，6,272/6,272 例 `complete`，`effective_search_seconds=600.066509`，吞吐 **10.452 例/有效搜索秒**，768 次反馈交换。`report.json` 的 `elapsed_seconds=600.511329`；独立 `/usr/bin/time` 记录整条进程命令 800.52 秒、峰值 RSS 1,163,324 KB。后者包含启动、构建缓存与搜索后终结，不能当作有效搜索时长。

## 在线逐例耗时

下面分位数来自这 6,272 条真实 `receipts.jsonl`，按排序后线性插值，单位秒；累计列为各例该字段之和。全部逐例计时通过正值、有限数和嵌套边界检查。外层 `rtl_submit` 包含在线执行器、Runner/Router/Scheduler 与本地 RTL 命令。

| 外层阶段 | p50 | p95 | 累计 |
|---|---:|---:|---:|
| 选择/解码 | 0.000083 | 0.000107 | 0.536 |
| RTL submit | 0.071461 | 0.102207 | 555.428 |
| trace 摘要 | 0.002425 | 0.003281 | 15.925 |
| 交互摄入 | 0.001701 | 0.002489 | 11.978 |
| checker | 0.000000808 | 0.000001469 | 0.00565 |
| 反馈计分 | 0.000201 | 0.005772 | 8.746 |
| 回执构造 | 0.0000122 | 0.0000158 | 0.0793 |
| 每例总处理 | 0.076619 | 0.109468 | 592.703 |

| submit 内嵌套阶段 | p50 | p95 | 累计 |
|---|---:|---:|---:|
| Scheduler 批次调用 | 0.060053 | 0.086742 | 458.646 |
| Runner step | 0.059947 | 0.086632 | 458.003 |
| Runner 已观察输出传播 | 0.001495 | 0.002605 | 12.446 |
| Router 排队接收 | 0.0000132 | 0.0000334 | 0.0683 |
| Router 排队交付 | 0.000312 | 0.000917 | 1.837 |
| Router 同步事务 | 0 | 0 | 0 |

嵌套阶段**不能相加**：Scheduler 包含 Runner step，Runner 又包含部分 Router 和本地命令。默认 GPIO 场景没有调用 Router 同步事务。外层 `rtl_submit` 与 Scheduler 的差额包含其他主机步骤，不能直接解释为纯 RTL 时间。逐例处理累计与有效搜索时间的测量边界不同。

## 压缩证据与终结

终态 trace 有 2,355,748 个事件，语义 SHA-256 为 `11c7acaee27e17a4aeb72050b5b89aa371cd61694f4f0dbf5128ddce56c533d7`，在线运行身份 SHA-256 为 `ae38b9f5c690115c07cfb52c986158d1378e9d135a286b04b5ff3693437247b3`。`online_events.zlib` 139,902,175 字节、9,203 个块；块头声明原始事件字节合计 2,471,806,961，故本次原始事件字节/压缩文件体积为 **17.668×**。这些都是同一条压缩 trace 的量，完整性另由分块读取器逐块校验并重算语义 SHA。

`finalization_timing_seconds`：`session_finish=12.647s`、`plan_write=0.025s`、`trace_write=79.783s`、`identity_write=0.203s`、发布报告前总计 **92.702s**。压缩写入时间包含编码、压缩、语义哈希和持久化，不是纯磁盘带宽。它约为有效搜索时间的 15.4%，另于搜索预算之外。相同预算的旧 JSONL 600 秒运行不是同一源码/负载，不能由两个总耗时归因出压缩速度收益。

## 重放、门禁与边界

第一轮独立 cache 的完整 fresh replay 使用上述冻结快照的 `scripts/run_ibex_pulp_online.py replay`，`matches=true`、`first_difference=null`、`difference_context=null`；`/usr/bin/time` 壁钟 848.23 秒、峰值 RSS 475,500 KB。初始 CLI 输出没有输入文件哈希，因此它独立证明语义比较结果，却不足以单独满足加严的绑定门禁。

随后从另一独立 replay cache 再跑一次完整 RTL replay。`scripts/runs/replay_p5_online_verified.py` 仅接受本快照的 CLI SHA-256 和前述清单 SHA-256，调用前后分别核对清单内 2,766 个文件及 plan、trace 元数据、压缩事件、在线身份、report、`run-time.txt` 和清单本身的 SHA-256；这些哈希和原始 replay 退出码进入 `replay-verified.json`。本次前后哈希相同，冻结清单检查均为零差异，CLI 返回 `matches=true`、`first_difference=null`、退出 0。绑定重放的壁钟为 **838.44 秒**、峰值 RSS **475,044 KB**。两次 replay 的时间不同，不能仅凭这两次不同缓存运行判断优化收益。

```bash
cd /home/qinkejiu/myfuzz
/usr/bin/time -f 'verified_replay_wall_seconds=%e\nverified_replay_peak_kb=%M' \
  -o runs/p5-runner-zlib-600s-20261007/verified-replay-time.txt \
  python3 scripts/runs/replay_p5_online_verified.py \
  --snapshot-cli /home/qinkejiu/myfuzz_snapshot_p5_runner_zlib_600s_20261007/scripts/run_ibex_pulp_online.py \
  --cache-dir runs/p5-runner-zlib-600s-20261007/verified-replay-cache \
  --plan runs/p5-runner-zlib-600s-20261007/online/online_plan.json \
  --trace runs/p5-runner-zlib-600s-20261007/online/online_final_trace.meta.json \
  --result runs/p5-runner-zlib-600s-20261007/replay-verified.json
python3 scripts/runs/summarize_p5_online_timing.py \
  --output runs/p5-runner-zlib-600s-20261007/online \
  --replay-result runs/p5-runner-zlib-600s-20261007/replay-verified.json \
  > runs/p5-runner-zlib-600s-20261007/timing-summary.json
```

最终汇总退出 0，`gate_passed=true`、`failed_checks=[]`。6,272/6,272 例有完整外层和嵌套计时、计时边界一致、checker 字段齐全，0 个 checker violation；压缩读取器解码全部 9,203 块并重算 2,355,748 事件的语义 SHA。汇总本身另耗 39.56 秒、峰值 RSS 34,208 KB，这是额外的验收成本，不算入搜索、终结或 replay。定向负例覆盖损坏压缩流、错误元数据哈希、布尔事件数、旧 replay 对错 plan、运行报告后替换、零/矛盾计时、终结合计小于分项、假 CLI 被拒绝。`PYTHONPATH=src:. python3 -m pytest tests/integration/test_p5_online_timing_gate.py tests/integration/test_p5_verified_replay.py tests/integration/test_p5_runtime_timing_receipts.py -q` 为 **16 passed**。

当前默认运行未启用 GPIO 实际消费、CPU retirement 或原生 IRQ 探针。完整来源→IRQ→CPU→输出传播链/秒在此证据中**无法确定**，不能写成零，也不能以 `complete`、路径数或目标位新颖率替代。压缩体积比不代表同条件性能优势；本轮未做同源码、同预算、同探针和断言条件的 JSONL 对照，亦未证明故障发现质量。P5 整阶段保持未验收。
