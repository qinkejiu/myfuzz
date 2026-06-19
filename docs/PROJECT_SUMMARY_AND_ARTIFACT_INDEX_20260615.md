# Project Summary and Artifact Index

生成时间：2026-06-15

本文件是当前 Ibex/CVA6 RFuzz 方案实现、测试结果和产物位置的索引。远端所有操作只应发生在：

```text
/root/fanzehui/myfuzz
```

本地工程根目录：

```text
/home/qinkejiu/test/myfuzz
```

## 1. 总览

当前做过的主线工作：

1. 实现并运行 Ibex 四方案 10h 对比。
2. 在 Ibex 上连续增强方案4：`scheme4_plus`、`scheme4_plus2`、`scheme4_plus3`。
3. 实现 CVA6 的方案1/方案4对比，并完成 CVA6 10h 可续跑测试。
4. 为长跑补过断续重启脚本和每小时采样 CSV/JSON。
5. 最新有效增强结果是 Ibex `scheme4_plus3` 1000s，对 baseline 提升明显。
6. 针对 CVA6 新增 `scheme4_lightweight_plus4/plus5`，把方案4改回“521-bit 输入串轻量投影”方向，并启动 plus5 4h 可续跑测试。

## 2. 关键文档

| 文档 | 内容 |
|---|---|
| `/home/qinkejiu/test/agent.md` | 远程连接、操作边界、四方案大致思路 |
| `myfuzz/docs/ALL_TEST_RESULTS_MASTER.md` | 所有长测、短测、失败尝试的统一测试结果总表；后续测试也必须追加到这里 |
| `myfuzz/docs/IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md` | Ibex baseline harness、pre/post 变异定义和 41 路实验结果 |
| `myfuzz/docs/IBEX_SCHEME5_BIT_CONSTRAINTS.md` | Ibex scheme5 bit-string 约束实现说明 |
| `myfuzz/docs/CPU_IP_MULTICOMPONENT_EXPERIMENT_PLAN.md` | Ibex + 多 IP target 新实验计划、baseline/depaware 对照、依赖 manifest 和远端运行口径 |
| `myfuzz/docs/PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md` | 本索引文件 |

旧的阶段性结果文档已合并到 `ALL_TEST_RESULTS_MASTER.md` 后删除，后续不要再分散新增结果报告。

## 3. Ibex 实现索引

### 3.1 原始四方案

| 方案 | label | 本地配置/实现 | 远端构建产物 |
|---|---|---|---|
| 方案1 | `scheme1_baseline` | `configs/designs/ibex/config.json` | `/root/fanzehui/myfuzz/runs/designs/ibex/` |
| 方案2 | `scheme2_naive_decomposed` | `configs/designs/ibex_naive/config.json` | `/root/fanzehui/myfuzz/runs/designs/ibex_naive/` |
| 方案3 | `scheme3_constrained_decomposed` | `configs/designs/ibex_constrained/config.json` | `/root/fanzehui/myfuzz/runs/designs/ibex_constrained/` |
| 方案4 | `scheme4_lightweight` | `configs/designs/ibex_lightweight/config.json` | `/root/fanzehui/myfuzz/runs/designs/ibex_lightweight/` |

原始四方案脚本：

```text
myfuzz/scripts/runs/run_four_schemes_10h_hourly_common.py
myfuzz/scripts/runs/run_four_schemes_1000s.py
```

### 3.2 Ibex 方案4增强变体

| 变体 | 说明 | 本地文件 |
|---|---|---|
| `scheme4_plus` | 在原始方案4基础上加入合法指令、可变总线延迟、低频 debug/error/IRQ | `configs/designs/ibex_lightweight_plus/config.json`, `configs/designs/ibex_lightweight_plus/harness/ibex_core_lightweight_plus_harness.sv`, `scripts/runs/run_ibex_baseline_vs_lightweight_plus_1000s.py` |
| `scheme4_plus2` | 加稳定短程序流、轻量 RF model、相关 data memory；6h 尝试中异常退出 | `configs/designs/ibex_lightweight_plus2/config.json`, `configs/designs/ibex_lightweight_plus2/harness/ibex_core_lightweight_plus2_harness.sv`, `scripts/runs/run_ibex_scheme1_vs_scheme4_plus2_10h_resume.py` |
| `scheme4_plus3` | 保持 395-bit 0/1 输入串，把 bit 字段投影为场景、指令模板、寄存器 bias、总线延迟和低频事件 | `configs/designs/ibex_lightweight_plus3/config.json`, `configs/designs/ibex_lightweight_plus3/harness/ibex_core_lightweight_plus3_harness.sv`, `scripts/runs/run_ibex_baseline_vs_lightweight_plus3_1000s.py` |

## 4. CVA6 实现索引

| 方案 | label | 本地配置/实现 | 远端构建产物 |
|---|---|---|---|
| 方案1 | `scheme1_baseline` | `configs/designs/cva6/config.json` | `/root/fanzehui/myfuzz/runs/designs/cva6/` |
| 方案4 | `scheme4_lightweight_plus` | `configs/designs/cva6_lightweight_plus/config.json`, `configs/designs/cva6_lightweight_plus/harness/cva6_lightweight_plus_harness.sv` | `/root/fanzehui/myfuzz/runs/designs/cva6_lightweight_plus/` |
| 方案4增强 | `scheme4_lightweight_plus4` | `configs/designs/cva6_lightweight_plus4/config.json`, `configs/designs/cva6_lightweight_plus4/harness/cva6_lightweight_plus4_harness.sv`, `scripts/runs/run_cva6_scheme1_vs_scheme4_plus4_4h_resume.py` | `/root/fanzehui/myfuzz/runs/designs/cva6_lightweight_plus4/` |
| 方案4增强 | `scheme4_lightweight_plus5` | `configs/designs/cva6_lightweight_plus5/config.json`, `configs/designs/cva6_lightweight_plus5/harness/cva6_lightweight_plus5_harness.sv`, `scripts/runs/run_cva6_scheme1_vs_scheme4_plus5_4h_resume.py` | `/root/fanzehui/myfuzz/runs/designs/cva6_lightweight_plus5/` |

CVA6 可续跑脚本：

```text
myfuzz/scripts/runs/run_cva6_scheme1_vs_scheme4_10h_resume.py
myfuzz/scripts/runs/run_cva6_scheme1_vs_scheme4_plus4_4h_resume.py
myfuzz/scripts/runs/run_cva6_scheme1_vs_scheme4_plus5_4h_resume.py
```

## 5. 已完成测试与结果

### 5.1 Ibex 原始四方案 10h

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002
```

统计口径：

```text
common_total = 1058
统计 __vi_coverage[1057:0]
排除顶层 ibex_core 的 56 个 MSB bit: __vi_coverage[1113:1058]
```

最终结果：

| 方案 | tests_total | tests/s | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---:|---|
| `scheme1_baseline` | 8,096,032 | 224.90 | 376/1058 = 35.54% | 119 | returncode=0 |
| `scheme2_naive_decomposed` | 951,355 | 26.43 | 227/1058 = 21.46% | 76 | returncode=0 |
| `scheme3_constrained_decomposed` | 955,130 | 26.53 | 183/1058 = 17.30% | 35 | returncode=0 |
| `scheme4_lightweight` | 8,096,608 | 224.91 | 350/1058 = 33.08% | 103 | returncode=0 |

本地曲线产物：

```text
/home/qinkejiu/test/ibex_four_schemes_common_coverage_curve.csv
/home/qinkejiu/test/ibex_four_schemes_common_coverage_curve.png
```

远端结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002/hourly_common_coverage.jsonl
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002/summary.json
```

### 5.2 Ibex `scheme4_plus` 1000s

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus_try1_1000s_20260615_011659
```

结果：

| 方案 | tests_total | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---|
| `scheme1_baseline` | 254,096 | 181/1058 = 17.11% | 29 | returncode=0 |
| `scheme4_plus` | 254,096 | 199/1058 = 18.81% | 17 | returncode=0 |

结论：`scheme4_plus` 在同测试次数下比 baseline 多 18 个 common bit。

### 5.3 CVA6 方案1/方案4 10h

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626
```

统计口径：

```text
common_total = 3496
exclude_top_bits = 0
支持断续重启和每小时采样
```

最终结果：

| 方案 | tests_total | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---|
| `scheme1_baseline` | 584,056 | 404/3496 = 11.56% | 7 | returncode=0 |
| `scheme4_lightweight_plus` | 641,076 | 371/3496 = 10.61% | 0 | returncode=0 |

远端结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/latest_sample.json
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/summary.json
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/manifest.json
```

结论：CVA6 当前方案4没有超过 baseline，且 discoveries 为 0，后续需要 CVA6 专用的更强覆盖探索约束。

### 5.4 Ibex `scheme4_plus2` 6h 尝试

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_scheme1_vs_scheme4_plus2_6h_resume_20260615_151324
```

状态：无效双方案长跑结果。第 1 小时采样显示：

| 方案 | alive | returncode | tests_total | common coverage |
|---|---:|---:|---:|---:|
| `scheme1_baseline` | 1 |  | 72,980 | 443/1058 |
| `scheme4_plus2` | 0 | 1 | 256 | 239/1058 |

结论：`scheme4_plus2` 已异常退出，不应引用为有效 6h 对比结果。

### 5.5 Ibex `scheme4_plus3` 1000s

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915
```

结果：

| 方案 | tests_total | tests/s | common coverage | queue union coverage | discoveries | 状态 |
|---|---:|---:|---:|---:|---:|---|
| `scheme1_baseline` | 4,116 | 5.13 | 341/1058 = 32.23% | 366/1058 | 95 | returncode=0 |
| `scheme4_plus3` | 4,116 | 5.11 | 440/1058 = 41.59% | 463/1058 | 121 | returncode=0 |

结论：

- `scheme4_plus3` 比 baseline 多 99 个 common bit。
- 两者 tests_total 相同，差异来自 395-bit 输入串约束映射。
- 这是当前最有效的 Ibex 新方案4短跑结果。

远端结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/latest_sample.json
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/manifest.json
```

## 6. 如何查看远端结果

Ibex 四方案 10h：

```bash
ssh inner70
RUN=/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002
cat $RUN/hourly_common_coverage.csv
cat $RUN/summary.json
```

CVA6 10h：

```bash
ssh inner70
RUN=/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626
cat $RUN/hourly_common_coverage.csv
cat $RUN/latest_sample.json
cat $RUN/summary.json
```

Ibex plus3 1000s：

```bash
ssh inner70
RUN=/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915
cat $RUN/hourly_common_coverage.csv
cat $RUN/latest_sample.json
cat $RUN/manifest.json
```

CVA6 plus5 4h 当前运行：

```bash
ssh inner70
RUN=/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501
cat $RUN/hourly_common_coverage.csv
cat $RUN/latest_sample.json
cat $RUN/manifest.json
tail -80 $RUN/logs/slice_0000_scheme1_baseline.log
tail -80 $RUN/logs/slice_0000_scheme4_lightweight_plus5.log
```

查看进程：

```bash
ssh inner70
RUN=/root/fanzehui/myfuzz/runs/managed_runs/<run_id>
ps -fp $(cat $RUN/runner.pid)
```

## 7. 下一步建议

1. 如果要证明新方案4长时间最高，优先把 `scheme4_plus3` 做成 6h/10h 可续跑脚本，并和 `scheme1_baseline` 同口径对比。
2. `scheme4_plus3` 的覆盖高但运行慢，需要继续压低 harness 复杂度，特别是程序模板/RF model/总线事件逻辑。
3. CVA6 方案4目前没有超过 baseline，应单独优化 CVA6 的约束，不要直接照搬 Ibex plus3。
4. `scheme4_plus2` 6h run 已异常，不应继续作为正式结果引用。
5. CVA6 plus4/plus5 短测已经修复旧方案4 discovery 为 0 的问题；等待 plus5 4h 每小时采样判断是否能长期超过 baseline。

## 8. 最新远程任务

### 8.1 Ibex all bit-only variants pre/post 6h

最新已完成远程任务：

```text
host: inner70
repo: /root/fanzehui/myfuzz
runner pid: 3136817
run root: /root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
launch log: /root/fanzehui/myfuzz/runs/managed_runs/tools/ibex_all_variants_pre_post_6h_launch_20260616_032453.log
script: /root/fanzehui/myfuzz/scripts/runs/run_ibex_all_bit_constraint_variants_pre_post_6h_resume.py
```

任务内容：

- baseline + 20 个 bit-only 约束变体的 `_pre` 版本 + 20 个对应 `_post` 版本，共 41 路。
- `_pre` 表示 RFuzz 变异修正前 raw 输入，再由 harness 投影修正。
- `_post` 表示 RFuzz 直接变异修正后的 DUT 输入向量，作为 after-correction control。
- 6h，1h 采样一次，common coverage 分母为 1058。
- 支持断续重启。

远程 smoke 已通过：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_remote_smoke_5s_5s_20260616_032233
summary rows: 41
bad rows: 0
```

启动后内存：

```text
Mem: 125Gi total, 6.1Gi used, 119Gi available
Swap: 0B used
new run RSS: about 1028 MiB
```

最终摘要：

```text
scheme1_baseline: 63,508 tests, 453/1058, 148 discoveries
scheme5_pre: 63,508 tests, 506/1058, 178 discoveries
scheme6_relaxed_pre: 63,508 tests, 487/1058, 165 discoveries
best: scheme5_pre, +53 common bits vs baseline
all final rows: returncode=0
completion memory: 125Gi total, 4.5Gi used, 121Gi available, swap 0B used
```

结果已追加到：

```text
/home/qinkejiu/test/myfuzz/docs/ALL_TEST_RESULTS_MASTER.md
```

## 9. CPU + 多 IP 多组件实验框架

新实验方向已整理为文档和本地/远端目录骨架：

```text
myfuzz/docs/CPU_IP_MULTICOMPONENT_EXPERIMENT_PLAN.md
myfuzz/configs/designs/ibex_multicomponent_ip/
```

初步 target 已明确为 `ibex_core + RAM + timer + GPIO + UART + SPI`。CPU 使用远端
`third_party/rfuzz/upstream/ibex` 中的真实 Ibex，第一版 IP 是本目录轻量 common-IP
行为模型。两条路径对比：

```text
baseline_direct_slice:
  RFuzz bit 串直接固定切片到各组件输入，不做 bit 间依赖约束。

depaware_projection:
  RFuzz bit 串先经过 dependency manifest/scenario decoder，根据源码和文档得到的
  address decode、request/response、ready/valid、IRQ/status 等关系投影到同一个 target。
```

本地只做轻量结构检查；frontend/instrument/harness/server/fuzz 均按 agent 约定放到
远端 `inner70:/root/fanzehui/myfuzz` 运行，并追加到 `ALL_TEST_RESULTS_MASTER.md`。
