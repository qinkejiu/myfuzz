# 闭环长跑稳定性与内存边界（2026-11-01）

状态：完成一轮 60 s 入口级、200k case 会话级浸泡测量。只针对一个组合（Ibex RVFI OBI + PULP Timer APB3 + ZipDMA Wishbone）、一台机器、一个 seed；不是多组合结论，也不是覆盖率/证书/replay。

## 短答

- 入口级 60 s：执行 **96,994 case**，会话 60.00 s，1,616.5 例/秒；入口 RSS 峰值 142.4 MiB，预热后斜率 **−0.0109 MiB/万例**（不随 case 增长）；host 1 个 PID、0 次重启。
- 会话级 200,000 case：7,483 例/秒；RSS 43.49→43.95 MiB，斜率约 **+0.002 MiB/万例**；会话文档 41 KB 不增长。
- `summary.json` 1.10 MiB、`fuzz.json` 0.78 MiB（保留 128/96,994 例）；旧版同口径曾达 12.52 MiB，主要来自逐例 F6 `dst_hash` 特征和无界 feedback 列表。
- 时间预算到点退出；host 不重启；`--stall-seconds` 负责无输出挂死。

## 做法

1. `session.py` 只保留 `max_cases_recorded`/`max_submitted_recorded` 的首尾样本，滚动 totals 精确；findings 有上限。
2. `FeedbackState` 词汇表硬上限 8192；达到后新特征只计数不保留；`document()` 只嵌入 2048 条样本，保留精确 `distinct`/`by_family`。
3. corpus 上限 256；case 文档只在 `--retain-cases` 内；`--no-prefix` 关闭前缀文件。
4. host stdout 由读线程 + 队列消费，`--stall-seconds` 到期终止；正常 case 不重启 CPU/IP/DMA。
5. 入口集成：`summary.json` 的 `cases`/`fuzz.cases`/`feedback` 均有界；批次计数用 `cases_total`/`submitted_total`，correspondence 标记为 sampled。

## 实测

| 指标 | 入口 60 s | 会话级 200k |
|---|---:|---:|
| case | 96,994 | 200,000 |
| 吞吐 | 1,616.5 例/秒 | 7,483 例/秒 |
| RSS 峰值 | 142.4 MiB | 43.95 MiB |
| 预热后斜率 | −0.0109 MiB/万例 | +0.002 MiB/万例 |
| host 重启 | 0 | 0 |
| 文档大小 | summary 1.10 MiB / fuzz 0.78 MiB | 41 KB |

## 输出与内存的剩余边界

- `run.log` 逐例记录时仍线性增长（本次 77.3 MiB）；新增 `--log-mode summary` 只保留 summary/错误行，长跑可显著减小日志，代价是没有逐例原始行（case 级观察仍在有界样本/finding 中）。
- 每个通过的 case 都做对应检查（`correspondence.checked` 覆盖全批，`sampled=false`），不再只检查抽样行；失败样本最多保留 32 条。
- 12 s 验证批（`runs/fuzz-soak-20261101/complete-correspondence-12s-c/`）：18,959 例、18,772 个通过 case 全部检查、0 mismatch；`--log-mode summary` 的 `run.log` 只有约 1.2 KB，而逐例日志按约 0.8 KiB/case 线性增长。该批 6 个 `state_contamination` 都是 `F4:40001000:ffffffff`：写 Timer COUNT 最大值立即触发 IRQ，F4 不建立 F5 上下文，现由启动时初始化的安全 handler cell + CASE 行的 `irq_takes` 归类为 IRQ 干扰，不再以未映射访问中止批次或误报设备缺陷。
- `prefix.txt`/`observations.jsonl` 默认开启时也线性增长；长跑不需要复现用 `--no-prefix`。
- `FeedbackState` 达到 8192 后不再保留新特征；超过上限的新观察不会进入 corpus 的新特征判定，这是有意的内存/探索折中，需在长跑报告中如实说明。
- 只测了 60 s；没有小时级泄漏、峰值瞬时抖动或不同组合的对比。

## 入口与复现

- 浸泡工具：`scripts/run_fuzz_soak.py`（入口模式与 `--session-only`，写 `soak.json`/`REPORT.md`）。
- 原始结果：`runs/fuzz-soak-20261101/entry-final/`、`runs/fuzz-soak-20261101/session-only-200000/`、`runs/fuzz-soak-20261101/README.md`。
- 入口：`scripts/run_inprocess_f1f6.py --fuzz`。用法见[闭环使用说明](../inprocess-fuzz-loop.md)。
