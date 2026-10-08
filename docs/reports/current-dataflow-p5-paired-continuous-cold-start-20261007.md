# P5 同预算配对对照：连续会话 vs 逐例冷启动（真实 RTL）

日期：2026-10-07。P5 要求"用固定输入/种子、同一源码和相同断言比较连续会话与逐 testcase 启动"，并证明长会话的有效例/s 或完整真实链/s 更高、且有效性、checker 与 replay 不退化。本报告用同一冻结源码、同一 seed `20261007`、同 24 例输入做真实 RTL 配对对照。

## 两组如何产生

**连续组**（一次初始化，24 例共享同一 Ibex＋双 PULP GPIO 会话）：

```bash
python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/current-dataflow-p5-final-20261007-cache \
  --output runs/current-dataflow-p5-paired-20261007-online \
  --seconds 30 --max-tests 24 --seed 20261007 \
  --run-id current-dataflow-p5-paired-20261007 \
  --cpu-retirement --native-irq-receipts --gpio-consumption
```

**冷启动组**（逐例独立进程、新 runtime、新 RTL 会话，输入与连续组逐例相同）：

```bash
PYTHONPATH=src python3 scripts/run_first_step_cold_start_run.py run \
  --continuous-run-dir runs/current-dataflow-p5-paired-20261007-online \
  --output runs/current-dataflow-p5-paired-20261007-cold-start \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/current-dataflow-p5-final-20261007-cache --max-cases 24
# exit 0；{"case_count": 24, "case_failure_count": 0, "verification_failure_count": 0,
#  "status_mismatch_count": 0, "init_seconds_total": 449.6952181739962,
#  "wall_clock_seconds": 512.8813625590001}
```

配对分析：`python3 scripts/bench_first_step_paired.py compare --continuous <连续目录> --cold <冷目录>`，退出码 0，报告 `paired_efficiency_report.v1`。

## 可比性（先决条件全部满足）

`comparison_validity.status = "comparable"`，`failed_prerequisites = []`、`unverified_prerequisites = []`：

| 先决条件 | 证据 |
|---|---|
| 例数相等 | 24 / 24 |
| 源码身份相等 | `source_files_sha256 = bc21120107db3504c3b1779f060e61d5e87814d8354e30798d1d4d6367ec7da2`（两组相同）；decoder manifest `b68042f0…`、plan `23a43de7…`、component identity 与 targets 摘要均相同 |
| 种子相等 | `search_seed = global_mutation_seed = 20261007` |
| 预算相等 | `max_tests = 24`、`duration_seconds = 30.0`、`feedback_interval = 16` |
| 输入序列对齐 | 24 例按 receipt 序号对齐，raw 24/24 相同，无缺例 |

逐例字段一致性（24 例）：

| 字段 | 相同 | 不同 | 缺失 |
|---|---:|---:|---:|
| `status` | 24 | 0 | 0 |
| `raw_identity`（`raw_sha256`） | 24 | 0 | 0 |
| `effective_genome_sha256` | 24 | 0 | 0 |
| `path_id` | 24 | 0 | 0 |
| `applied_sources` | 24 | 0 | 0 |
| `violations`（checker） | 24 | 0 | 0 |
| `coverage_hex` | 2 | 22 | 0 |
| `local_ticks` | 9 | 15 | 0 |

两组都是 24/24 `complete`、0 checker violation。因此**有效性、断言与路径选择不退化**；但 `coverage_hex` 与 `local_ticks` 大量不同 → 报告 `output_equivalence.claimed = false`。这是诚实结论：连续会话把前例的外设/RAM 状态带入后例，逐例冷启动每例都从初态开始，两者**不是**输出等价。

## 效率

| 量 | 连续组 | 冷启动组 |
|---|---:|---:|
| 例数 | 24 | 24 |
| 墙钟总耗时 | 31.905 s（`elapsed_seconds`，另加一次性构建） | **512.881 s** |
| 逐例 runtime 初始化 | 一次性，未摊到任何一例（`continuous_init_seconds = null`，绝不写 0） | 合计 **449.695 s**，p50 18.736 s、p95 19.048 s |
| 逐例处理 `total` p50 / p95 | 1.2718 s / 1.6712 s | 1.0314 s / 1.0696 s |
| 有效例/s（按各自声明窗口） | 0.7796 | 170.10（分母是各例冻结窗口之和 0.141 s，**与连续组不同口径**） |
| 认证链 | 8（0.259880 链/s） | 不可得（聚合目录无单会话 trace，报告写 `null` + 原因，不是 0） |

**同预算墙钟对比：512.881 / 31.905 ≈ 16.08×**，即同样 24 例输入，连续会话的墙钟成本约为逐例冷启动的 1/16，节省完全来自**避免 24 次 runtime 初始化（每例约 18.7 s）**。必须同时说明：连续组的**逐例处理** p50 比冷启动组高约 0.24 s（1.2718 对 1.0314），因此本对照**不**声称"每例处理更快"，只声称"同预算下有效例/s 更高，且有效性/断言不退化"。

`paired` 段里 `cases_per_second_ratio_cold_over_continuous = 218.17`：两组速率分母不同（冷组分母是各例冻结窗口之和），报告已在 `interpretation` 中标明这不是加速倍数；`certified_chains_per_second_ratio_cold_over_continuous` 因冷组为 null 而保持 null。

## 明令禁止的外推（报告内已写入 `boundaries`）

1. 连续组把前例组件状态带入后例，冷启动组每例从初态开始；逐例状态/raw/path/覆盖相同**不**证明两组前置硬件状态相同。
2. 两组总成本边界不同：连续组逐例 `total` 不含一次性构建/启动与会话终结，冷启动组逐例 `total` 含该例初始化。
3. 连续组前 N 例 `total` 与冷组初始化秒数**不得相减**当作节省。
4. 覆盖数字只做逐例相等性检查，不外推覆盖新颖率差异。
5. 所有速率的分母按组命名，不可互换。

## replay

本轮连续组自身的完整 fresh replay 已执行，退出码 0、`matches = true`、`first_difference = null`、`difference_context = null`（`runs/current-dataflow-p5-final-20261007-logs/paired_continuous_replay.log`，独立缓存 `runs/current-dataflow-p5-paired-20261007-replay-cache`）；同配置的另一独立运行（`runs/current-dataflow-p5-chain-acceptance-20261007-online`）亦有完整 replay 一致记录。**冷启动组的逐例 replay 未执行**：其聚合目录不含单会话 trace，逐例 trace 保存在 `cases/<i>/`，这是本报告的未覆盖项。

## 结论与限制

结论：在同一冻结源码、同一 seed、同一 24 例输入下，**连续会话的墙钟有效例/s 显著高于逐例冷启动（约 16×），且 status/raw/genome/path/断言逐例一致**；覆盖与 tick 的差异被如实记录并禁止据此声称输出等价。

限制：单次 24 例有界对照，不是十分钟门禁；冷启动组链证书不可得（写 null）；冷启动逐例 replay 未跑；两组前置状态不同；本报告不含自然 RTL 缺陷结论。
