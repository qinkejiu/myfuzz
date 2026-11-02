# Journal 缓存与 prefix 单次渲染的同工作量 A/B（2026-10-30）

范围：`EventJournal` 读 chunk 缓存（单槽 → 有界 LRU，默认 4）与 `prefix.json`/`compiled_f6_prefix.json` 单次渲染的同源、同工作量 A/B。所有运行都是真实 RTL 会话（同一 shared descriptor、同一 cache、同一输入），仅 `MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE` 不同（1 = 旧单槽策略，4 = 新策略）。

## 1. 完整八例 A/B 的内存边界（未完成，原产物保留）

先按原计划运行完整八例 shared benchmark（`scripts/benchmark_shared_all_flows.py --native --dut-eval`，含 within-invocation replay）。warm-up 完成 campaign 与 prefix 导出（`$B/perf/warmup/workload/original/prefix.json`，211,435,731 bytes），在 replay 阶段主机内存不足并重启（2026-10-30 00:10，7 GB 主机）。该次没有 `performance.json`，**不计为结果**；原目录保留。完整八例 wall A/B 需要更大内存或分阶段 replay，本报告不以任何推算替代。

## 2. 轻量同工作量 A/B（实际执行）

为避免 replay 的整份 prefix/replay 双份内存，使用 `scripts/bench_journal_cache_campaign.py`：同一 `configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json`、同一 `runs/config-driven-20261028/cache`，固定两个 F6 用例（历史事件读取最重的路径），`execution_mode='search'`（真实 campaign + 证据导出，不做 within-invocation replay）。两侧工作量完全相同，仅缓存容量不同。

顺序：先 `legacy`（capacity 1）后 `lru`（capacity 4），再反序 `lru2` 后 `legacy2`，用于检查顺序效应。证据：`$B/perf-lite/{legacy,lru,legacy2,lru2}/performance.json`。

| 运行 | wall (s) | campaign (s) | finish/export (s) | peak RSS (MB) |
|---|---:|---:|---:|---:|
| legacy（1 槽） | 85.371 | 42.442 | 17.882 | 1,027.7 |
| lru（4 槽） | 75.937 | 35.176 | 16.805 | 1,065.6 |
| lru2（反序） | 76.527 | 34.514 | 16.962 | 1,065.4 |
| legacy2（反序） | 82.608 | 40.378 | 17.786 | 1,027.6 |

配对结果（`$B/perf-lite/comparison-legacy-lru.json`、`comparison-legacy2-lru2.json`）：

| 配对 | wall 比（lru/legacy） | campaign 变化 | 等价性 |
|---|---:|---:|---|
| legacy → lru | 0.8895 | 42.442 → 35.176（−17.1%） | 全部检查 true |
| lru2 → legacy2 | 0.9264 | 40.378 → 34.514（−14.5%） | 全部检查 true |

两对均值：wall 83.99 → 76.24 s（−9.2%），campaign 41.41 → 34.85 s（−15.8%）。反序配对仍保留 −7.4% wall，说明顺序/缓存热度不能解释全部差异；但这仍是**两次配对、单主机、单 workload 子集**，不是多 seed 统计，也不外推到完整八例（见第 3 节：规范八例只有约 2% campaign 收益）。

### 等价性（同一工作量，不是减少工作）

四个运行的实际工作量完全一致：

- 2 个主 case / 2 个 session case；事件 **14,921**；local ticks CPU **385** / DMA **424** / peripheral **408**。
- native eval 次数（`--dut-eval` 实际计数器）：CPU **1540** runtime / 51 startup，DMA **1696** / 51，peripheral **1632** / 18。
- 完整 normalized prefix SHA256 相同：`f9907e6632366c89…`（两侧逐字节规范化相等）。
- `executed_work`、`native_eval_counts`、`complete_campaign_without_replay`、`full_normalized_prefix` 四项检查均为 true。

因此 campaign 的缩短不能来自少执行 case、少推进 tick 或少 eval。

### DUT eval 占比（仍然很低）

同一 `--dut-eval` 计数器的实际 eval 时间：legacy 约 5.33 ms、lru 约 4.51 ms（三组件 runtime+startup 合计），分别占 wall 的约 0.0062%/0.0059%。也就是说，**即使宿主开销下降约 9–16%，初始化后时间仍由宿主编排/证据处理主导，远未达到 DUT 推进主导**。这是结构性的（每 tick 一次 IPC 往返、逐事件主机处理），不是本缓存改动能关闭的目标；后续需要批量化 IPC、减少逐事件复制/导出，才能继续接近该目标。

## 3. 规范八例 campaign-only A/B（实际执行）

同一 driver 改跑规范的八例序列（`F3,F1,F4,F5,F2,F6,F5,F6`），仍为 campaign-only（无 replay），capacity 1 vs 4。证据：`$B/perf-8/{legacy,lru}/performance.json`、`comparison.json`。

| 运行 | wall (s) | campaign (s) | peak RSS (MB) |
|---|---:|---:|---:|
| legacy（1 槽） | 192.212 | 127.703 | 1,905.6 |
| lru（4 槽） | 191.062 | 125.314 | 1,953.1 |

wall 比 **0.9940**（−0.6%），campaign **−1.9%**。等价性四项检查全部 true：事件 **38,421**、ticks CPU **977**/DMA **1010**/peripheral **1023**、8 主 case；native eval 次数 CPU **3908**/51、DMA **4040**/51、GPIO **4092**/18（与参考 workload 完全一致）；完整 normalized prefix 相等。

结论必须按 workload 分开看：**密集历史读取的 2-F6 子集**（第 2 节）收益明显（wall −9.2%、campaign −15.8%），但**规范八例 campaign** 只有 wall −0.6%、campaign −1.9%。也就是说，缓存修复的是被 profile 命名的病理访问模式，但规范八例的宿主成本分散在多个站点（整份 journal 复制、逐事件证据、导出、IPC 往返），缓存不是该 workload 的主导成本。不能把 2-F6 的百分比外推到八例。

## 4. 机制证据（同一进程内的微基准）

`scripts/bench_event_journal_cache.py` 在真实 38,421 事件 journal 上测同一访问模式（tail + 每步 3 次历史 `event_id` 读取）：单槽 **71.50 ms/step、2.83 次 chunk unpickle/step**；LRU 4 **0.83 ms/step、0.008 次/step**（2,727 步折算 194.97 s → 2.27 s）。tail-only 模式两者相同（1.15 → 0.75 ms/step，噪声级）。`prefix` 双写渲染从 2×3.919 s 降为 1×3.919 s（实测 `_json` 8.263 → 4.087 s，两文件仍逐字节相同，`sha256 1efc599e…`）。缓存内存有界：capacity 4 在参考 journal 上常驻约 62.3 MB（+47 MB 相对单槽），不随 journal 增长。

## 5. 未声明

- 不把本次结果外推为完整八例或任意 workload 的提速；完整八例（含 replay）A/B 因主机内存未完成，规范八例 campaign-only 的实测收益只有约 0.6% wall / 1.9% campaign。
- 不计 replay/导出总成本的收益；本 A/B 明确排除 within-invocation replay，finish/export 的约 1 s 差异与单次渲染一致但未单独归因。
- 不作策略优越性、覆盖率或漏洞收益结论。
- 不把 peak RSS 约 1.03–1.07 GB 当作所有配置的上界；完整八例的峰值未记录。

## 6. 复现

```bash
B=research/input-strategy-audit-20261027/runs/native-batch-20261030
MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=1 PYTHONPATH=src:. python3 scripts/bench_journal_cache_campaign.py \
  --native --dut-eval --output $B/perf-lite/legacy --cache runs/config-driven-20261028/cache
MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=4 PYTHONPATH=src:. python3 scripts/bench_journal_cache_campaign.py \
  --native --dut-eval --output $B/perf-lite/lru --cache runs/config-driven-20261028/cache
MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=4 PYTHONPATH=src:. python3 scripts/bench_journal_cache_campaign.py \
  --native --dut-eval --output $B/perf-lite/lru2 --cache runs/config-driven-20261028/cache
MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE=1 PYTHONPATH=src:. python3 scripts/bench_journal_cache_campaign.py \
  --native --dut-eval --output $B/perf-lite/legacy2 --cache runs/config-driven-20261028/cache
PYTHONPATH=src:. python3 scripts/compare_workload_ab.py --baseline $B/perf-lite/legacy \
  --candidate $B/perf-lite/lru --axis journal_cache --baseline-option single-chunk \
  --candidate-option lru-4 --replay-skipped --output $B/perf-lite/comparison-legacy-lru.json
```
