# All Test Results Master

生成时间：2026-06-15

本文件是当前项目所有 Ibex/CVA6 相关 fuzz 测试结果的统一汇总。后续任何新的长测、短测、smoke、失败尝试、断续重启结果，都必须追加到本文件，避免结果散落在多个文档中。

远端统一操作边界：

```text
/root/fanzehui/myfuzz
```

本地工程目录：

```text
/home/qinkejiu/test/myfuzz
```

## 0. 后续追加规范

后续每次测试完成后，在本文件末尾追加一个新小节，至少包含：

- 测试日期、设计对象、方案名称。
- 运行时长，是短测还是长测，是否支持断续重启。
- run root 和结果文件路径。
- 运行策略：串行还是并行、是否断续重启、采样间隔、是否复用上一轮 queue。
- 输入约束策略：RFuzz 原始 bit 串如何进入 DUT，是否拆子模块，是否映射为合法指令/总线握手/IRQ/debug/error/内存/RF model。
- 覆盖率口径：coverage total、common coverage 分母、是否排除顶层 bit。
- 每个方案的 `tests_total`、coverage、discoveries、returncode。
- 如果失败或中断，写明失败原因、停止状态、是否能作为有效结果引用。

不同口径不能直接比较。例如：

- 早期 branch coverage 使用 `1118` 分母。
- Ibex 正式 common coverage 使用 `1058` 分母。
- CVA6 common coverage 使用 `3496` 分母。

## 1. 总览表

| 日期 | 设计 | 测试 | 时长 | 口径 | 结果状态 | 主要结论 |
|---|---|---|---:|---|---|---|
| 2026-06-12 | Ibex | 早期 3/4 方案 100s | 100s | branch coverage, 1118 | 成功，历史参考 | 各方案均为 134/1118，时间太短未分化 |
| 2026-06-13 | Ibex | 四方案真实实现 100s | 100s | branch coverage, 1118 | 成功，历史参考 | 四方案仍均为 134/1118 |
| 2026-06-13 | Ibex | 四方案 1000s 串行短测 | 1000s | branch coverage, 1118 | 成功，旧口径 | lightweight 206/1118 最高，baseline 181/1118 |
| 2026-06-14 | Ibex | 四方案 10h common coverage 正式长测 | 10h | common coverage, 1058 | 成功，正式可引用 | baseline 376/1058 最高，原始方案4 350/1058 |
| 2026-06-15 | Ibex | `scheme4_plus` vs baseline 1000s | 1000s | common coverage, 1058 | 成功 | plus 比 baseline 多 18 个 common bit |
| 2026-06-15 | CVA6 | 方案1/方案4 10h 可续跑 | 10h | common coverage, 3496 | 成功，正式可引用 | baseline 404/3496，高于 CVA6 方案4 的 371/3496 |
| 2026-06-15 | Ibex | `scheme4_plus2` vs baseline 6h 尝试 | 6h 目标 | common coverage, 1058 | 失败/无效 | plus2 第 1 小时前异常退出，不能作为有效双方案结果 |
| 2026-06-15 | Ibex | `scheme4_plus3` vs baseline 1000s | 1000s | common coverage, 1058 | 成功，当前最佳短测 | plus3 440/1058，高于 baseline 341/1058 |
| 2026-06-15 | CVA6 | `scheme4_lightweight_plus4/plus5` vs baseline 300s | 300s | common coverage, 3496 | 成功，短测 | plus4/plus5 均恢复到 baseline 的 403/3496、6 discoveries |
| 2026-06-15 | CVA6 | `scheme4_lightweight_plus5` vs baseline 4h | 4h 目标 | common coverage, 3496 | 运行中，可续跑 | 已启动，等待每小时采样 |
| 2026-06-16 | Ibex | `scheme4_plus3` vs baseline 12h continuation | 4h 已完成 + 8h 续跑 | common coverage, 1058 | 运行中，可续跑 | 历史性能增强版，从已完成 4h run 的 queue 继续，目标凑满 12h |
| 2026-06-16 | Ibex | `scheme5_bit_constraints` 实现 | 尚未运行 | common coverage, 1058 | 已实现，待测试 | 当前符合“只约束 0/1 输入 bit 串”的 Ibex 方案5；无模板、无模型、无 DUT 输出反馈 |
| 2026-06-16 | Ibex | `scheme5_bit_constraints` vs baseline 100s | 100s | common coverage, 1058 | 成功，短测 | baseline 132/1058，高于 scheme5 107/1058；queue union 均为 135 |
| 2026-06-16 | Ibex | baseline vs `scheme5_bit_constraints` vs `scheme6_relaxed_bit_constraints` 100s | 100s | common coverage, 1058 | 成功，短测 | baseline 132/1058；scheme5 107/1058；scheme6 118/1058。scheme6 比 scheme5 好，但仍低于 baseline |
| 2026-06-16 | Ibex | baseline + scheme5/6 bit-only pre/post variants 6h | 6h | common coverage, 1058 | 成功，正式可引用 | `scheme5_pre` 506/1058、`scheme6_relaxed_pre` 487/1058，均高于 baseline 453/1058；41 路全部 returncode=0 |

## 2. 运行策略与输入约束总览

### 2.1 通用 RFuzz 流程

通用流程：

1. `run_design_flow.py` 根据 design config 准备 frontend、instrumented RTL、RFuzz harness、TOML 和 Verilator server。
2. `kfuzz` 生成或变异 0/1 输入 bit 串，通过 TOML 写入 server。
3. server 驱动 DUT 执行若干 cycles，并返回 `__vi_coverage`/trace bitmap。
4. runner 从 queue/latest stats 中采样 `tests_total`、coverage、discoveries。
5. 长测脚本按固定间隔写 `hourly_common_coverage.csv`、`latest_sample.json`、`manifest.json`。

覆盖率记录原则：

- 早期短测主要使用 branch coverage，分母为 `1118`。
- Ibex 正式对比使用 common coverage，分母为 `1058`。
- CVA6 正式对比使用 common coverage，分母为 `3496`。

### 2.2 方案1：baseline 顶层 fuzz

运行策略：

- 保留完整设计顶层。
- 使用 RFuzz 自动生成的顶层 harness。
- 不拆子模块。
- 通常作为所有方案的对照组。

输入约束：

- RFuzz 输入 bit 直接驱动顶层输入端口。
- 不主动维护总线握手、内存响应、RF read data、IRQ/debug/error 的真实关系。
- 优点是随机空间最大，可能偶然进入异常、debug、错误和边界状态。
- 缺点是很多组合不真实，可能降低有效执行比例。

Ibex：

```text
input width = 395 bit
config = configs/designs/ibex/config.json
```

CVA6：

```text
input width = 521 bit
config = configs/designs/cva6/config.json
```

### 2.3 方案2：naive decomposed

运行策略：

- 只用于 Ibex 原始四方案实验。
- 拆开 Ibex 一级子模块，例如 IF、ID、EX、LSU、WB、CSR。
- 子模块独立 fuzz，覆盖拼接后再和其他方案按 common bit 对比。

输入约束：

- 输入宽度约为 `15870` bit。
- RFuzz bit 串按端口/子模块切片后直接喂给各子模块。
- 基本不维护跨模块 pipeline 因果。
- 目标是直接触达内部输入组合，但输入空间大、无效状态多。

关键影响：

- tests/s 明显低于顶层方案。
- 在正式 10h 中覆盖率低于 baseline 和原始方案4。

### 2.4 方案3：constrained decomposed

运行策略：

- 只用于 Ibex 原始四方案实验。
- 仍然拆子模块，但在进入子模块前先把 raw input 改写为更像合法协议/枚举的 `constrained_bits`。

输入约束：

- 指令 seed 映射到少量合法 RISC-V 指令。
- PC、branch target、trap address、LSU address 等做 4 字节对齐。
- IF/LSU handshake 更一致。
- ALU/CSR/写回等内部枚举限制到合法范围。
- IRQ/debug 使用低频事件。

关键影响：

- 比 naive 更少无意义组合。
- 但约束太强会压掉异常、错误、边界路径。
- 因为仍然是拆分式 harness，不具备完整 pipeline 自然状态流。

### 2.5 方案4：lightweight 顶层约束

运行策略：

- 保留完整设计顶层，不拆模块。
- 使用手写 harness，把顶层外部环境约束成更接近真实 SoC/总线环境。
- 和 baseline 保持相同输入宽度，方便判断差异是否来自约束而不是输入规模。

Ibex 原始方案4输入约束：

- `fetch_enable_i` 固定打开。
- boot address、hart id reset 后锁存，boot address 对齐。
- instruction/data bus 的 request、grant、valid 有相关关系。
- 无 valid 时指令返回 NOP，数据返回 0。
- IRQ 使用低频 burst。
- RF 读 x0 返回 0。
- 原始方案4中 debug 和 bus error 大多关闭。

效果：

- 前期有效执行比例高。
- 长时间可能因为 debug/error/异常路径受限而低于 baseline。

CVA6 方案4输入约束：

- NoC/AXI-like request/ready/response 建立相关关系。
- read/write response 带可变延迟。
- 小型 memory model 支持 store 后 load。
- CV-X-IF response 按 ready/valid 关系响应。
- IRQ/debug 使用低频事件。
- boot address/hart id reset 后锁存并对齐。

效果：

- 当前 10h 中没有超过 CVA6 baseline，主要问题是 discovery 很少、覆盖进入平台期。

CVA6 方案4增强 plus4/plus5：

- plus4 保持 CVA6 顶层 `521-bit` RFuzz 输入，不拆模块。
- plus4 先按 baseline 原始映射取得 `noc_resp_i`、`cvxif_resp_i`、`boot_addr_i`、`hart_id_i`、IRQ/debug/ipi/time_irq。
- 再由 bit 字段选择是否做轻量投影：boot address 对齐或靠近 `0x8000_0000`，hart id 小范围化，NoC ready/valid 更容易响应，CV-X-IF ready 更容易接受，IRQ/debug/ipi/time_irq 改为低频事件。
- plus5 在 plus4 基础上增加 NoC read-data 投影模式：由输入 bit 控制是否把 read data 映射成合法 RV64 指令对，或与 raw read data 混合。
- plus4/plus5 的重点是约束 0/1 输入 bit 串，而不是固定程序或外部 workload；每个模式、指令字段和事件仍由 `rfuzz_input_bits` 决定。

### 2.6 Ibex 方案4增强：plus / plus2 / plus3 / plus4

`scheme4_plus`：

- 保持 Ibex 顶层 395-bit 输入。
- 在原始方案4基础上打开低频 debug、低频 instr/data error、IRQ burst。
- 增加 1-2 拍可变 instruction/data bus delay。
- 指令数据中混入合法 RISC-V 指令。
- RF read data 按读地址扰动。

`scheme4_plus2`：

- 保持 Ibex 顶层 395-bit 输入。
- 增加稳定 PC 相关短程序流。
- 增加轻量 RF model，让写回后续读可见。
- 增加相关 data memory，保留 store/load 联动。
- 该版本 6h 尝试中异常退出，不能作为有效结果。

`scheme4_plus3`：

- 保持 Ibex 顶层 395-bit 输入。
- 把 `rfuzz_input_bits` 切分为 `base_seed`、`instr_seed`、`data_seed`、`irq_seed`、`scenario_sel`、`latency_sel`、`event_sel` 等字段。
- `scenario_sel` 选择 ALU/branch、LSU、CSR/IRQ、mul/div、compressed、trap/debug/illegal 等场景。
- bit 字段选择 rd/rs1/rs2、立即数边界值、总线延迟、backpressure、IRQ/debug/error 事件。
- 使用小型 RF model，x0 固定为 0。

关键点：

- plus3 是历史性能增强版；1000s 覆盖率高，但包含指令模板、场景选择、总线/RF/内存行为和 DUT 输出相关逻辑。
- 因此 plus3 不再作为“只约束 0/1 输入 bit 串”的当前实现引用。

`scheme5_bit_constraints`：

- 保持 Ibex 顶层 395-bit 输入。
- 不做场景执行、指令模板、协议状态机、memory model、RF model 或 directed generation。
- 不使用 `dut.instr_req_o`、`dut.data_req_o`、`dut.rf_raddr_*` 等 DUT 输出反向决定输入。
- 只做组合/局部输入投影：
  - `boot_addr_i = {raw_boot_addr_i[31:8], 8'h00}`。
  - `instr_rdata_i[1:0]` 大概率投影为 `2'b11`，提高 32-bit 指令路径概率，但不生成具体指令模板。
  - `fetch_enable_i = {raw_fetch_enable_i[3:1], |raw_fetch_enable_i}`。
  - `instr_rvalid_i = raw_instr_rvalid_i`，`instr_gnt_i = raw_instr_gnt_i | instr_rvalid_i`。
  - `data_rvalid_i = raw_data_rvalid_i`，`data_gnt_i = raw_data_gnt_i | data_rvalid_i`。
  - `instr_err_i`/`data_err_i` 只在 valid response 时低频触发。
  - IRQ/NMI/debug 均由 raw bit 控制但低频 gate；NMI 屏蔽普通 IRQ，debug 不与 NMI 同周期触发。
  - `irq_fast_i` 投影为最低编号 raw fast IRQ 的 onehot。
- `grant requires request` 不在方案5中实现，因为 Ibex 的 request 是 DUT 输出；用 request gate grant 会引入环境模型。

方案5文件：

```text
myfuzz/configs/designs/ibex_scheme5_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme5_bit_constraints/harness/ibex_core_scheme5_bit_constraints_harness.sv
myfuzz/scripts/runs/run_ibex_baseline_vs_scheme5_bit_constraints_1000s.py
myfuzz/docs/IBEX_SCHEME5_BIT_CONSTRAINTS.md
```

### 2.7 长测和断续重启策略

普通短测：

- 通常直接运行固定 `--seconds 1000`。
- 结果写 `latest_sample.json`、`hourly_common_coverage.csv`、`manifest.json`。
- 适合快速判断某个约束方向是否有效。

10h/6h 长测：

- 使用可续跑脚本。
- 按 `sample_interval` 每小时采样。
- 停止后用同一个 `--run-root` 重启。
- 重启时创建新 slice，并可把上一 slice 的 queue 作为输入继续。

注意：

- 长测必须记录每小时 coverage 和 tests_total。
- 如果某个方案提前退出，即使 baseline 继续跑，也不能把该 run 当作有效双方案长测。

## 3. Ibex 早期 100s 短测

历史来源文档已合并到本节，旧文件清理时可删除：

```text
INITIAL_TEST_RESULTS.md
FOUR_SCHEMES_TEST_RESULTS.md
REAL_IMPLEMENTATION_TEST_RESULTS.md
```

测试对象：Ibex 早期方案实现。

运行时长：每个方案 100s。

口径：branch coverage，分母 `1118`。

最终稳定记录以 2026-06-13 真实实现 100s 为准：

| 方案 | 输入位数 | Queue 条目 | Coverage | 状态 |
|---|---:|---:|---:|---|
| Baseline | 395 | 15 | 134/1118 = 11.99% | 成功 |
| Naive Decomposition | 15870 | 15 | 134/1118 = 11.99% | 成功 |
| Full Constrained | 4096 | 15 | 134/1118 = 11.99% | 成功 |
| Lightweight | 395 | 15 | 134/1118 = 11.99% | 成功 |

结论：100s 太短，覆盖率完全相同，只能作为历史参考。

## 4. Ibex 四方案 1000s 串行短测

历史来源文档已合并到本节，旧文件清理时可删除：

```text
FOUR_SCHEMES_1000S_RESULTS.md
```

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_1000s_20260613_222523
```

运行方式：四个方案串行，每个方案 1000s。

口径：branch coverage，分母 `1118`。这是旧口径，不等同于后续正式 common coverage。

| 排名 | 方案 | 输入位数 | Queue 条目 | Coverage | 状态 |
|---:|---|---:|---:|---:|---|
| 1 | Lightweight | 395 | 32 | 206/1118 = 18.43% | returncode=0 |
| 2 | Baseline | 395 | 30 | 181/1118 = 16.19% | returncode=0 |
| 3 | Full Constrained | 4096 | 9 | 150/1118 = 13.42% | returncode=0 |
| 4 | Naive | 15870 | 10 | 117/1118 = 10.47% | returncode=0 |

结论：旧口径下 lightweight 最高，1000s 开始能观察到方案差异。

注意：这里的 `Full Constrained` 是早期 4096-bit Memory/RF 版本，不等同于后续正式 10h 中的 `scheme3_constrained_decomposed`。

## 5. Ibex 四方案 10h 正式长测

来源说明：

```text
旧阶段性文档已合并到本节后删除。
轻量结果快照保留在 myfuzz/archives/ibex_schemes_archive_20260616/remote_results/four_schemes_10h_common_10h_20260614_021002/
```

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002
```

结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002/hourly_common_coverage.jsonl
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002/summary.json
```

口径：

```text
common_total = 1058
统计 __vi_coverage[1057:0]
排除顶层 ibex_core 的 56 个 bit: __vi_coverage[1113:1058]
```

最终结果：

| 方案 | tests_total | tests/s | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---:|---|
| `scheme1_baseline` | 8,096,032 | 224.90 | 376/1058 = 35.54% | 119 | returncode=0 |
| `scheme2_naive_decomposed` | 951,355 | 26.43 | 227/1058 = 21.46% | 76 | returncode=0 |
| `scheme3_constrained_decomposed` | 955,130 | 26.53 | 183/1058 = 17.30% | 35 | returncode=0 |
| `scheme4_lightweight` | 8,096,608 | 224.91 | 350/1058 = 33.08% | 103 | returncode=0 |

每小时覆盖率：

| 小时 | 方案1 baseline | 方案2 naive | 方案3 constrained | 方案4 lightweight |
|---:|---:|---:|---:|---:|
| 1 | 209/1058 | 218/1058 | 166/1058 | 207/1058 |
| 2 | 223/1058 | 221/1058 | 177/1058 | 268/1058 |
| 3 | 265/1058 | 221/1058 | 177/1058 | 286/1058 |
| 4 | 265/1058 | 221/1058 | 178/1058 | 291/1058 |
| 5 | 272/1058 | 227/1058 | 179/1058 | 291/1058 |
| 6 | 310/1058 | 227/1058 | 181/1058 | 301/1058 |
| 7 | 314/1058 | 227/1058 | 181/1058 | 328/1058 |
| 8 | 365/1058 | 227/1058 | 183/1058 | 332/1058 |
| 9 | 374/1058 | 227/1058 | 183/1058 | 347/1058 |
| 10 | 376/1058 | 227/1058 | 183/1058 | 350/1058 |

每小时累计测试次数：

| 小时 | 方案1 baseline | 方案2 naive | 方案3 constrained | 方案4 lightweight |
|---:|---:|---:|---:|---:|
| 1 | 788,848 | 92,288 | 92,480 | 787,696 |
| 2 | 1,594,016 | 186,559 | 186,943 | 1,593,312 |
| 3 | 2,402,276 | 280,639 | 281,279 | 2,402,084 |
| 4 | 3,230,116 | 378,366 | 379,518 | 3,230,116 |
| 5 | 4,079,204 | 477,181 | 478,717 | 4,079,204 |
| 6 | 4,886,864 | 573,181 | 575,165 | 4,886,864 |
| 7 | 5,686,144 | 668,732 | 671,228 | 5,686,144 |
| 8 | 6,469,936 | 763,004 | 765,948 | 6,470,000 |
| 9 | 7,284,976 | 857,723 | 861,051 | 7,286,512 |
| 10 | 8,096,032 | 951,355 | 955,130 | 8,096,608 |

本地产物：

```text
/home/qinkejiu/test/ibex_four_schemes_common_coverage_curve.csv
/home/qinkejiu/test/ibex_four_schemes_common_coverage_curve.png
```

结论：正式 10h 中方案1最高，原始方案4接近但最终低 26 个 common bit。方案2/3速度显著慢，方案3覆盖最低。

## 6. Ibex `scheme4_plus` 1000s 短测

来源说明：

```text
旧阶段性文档已合并到本节后删除。
```

其中 `IBEX1000S_CVA610H_CURRENT_RESULTS_20260615.md` 的内容已合并到本文件，旧文件清理时可删除。

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus_try1_1000s_20260615_011659
```

口径：

```text
common_total = 1058
输入宽度均为 395 bit
```

结果：

| 方案 | tests_total | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---|
| `scheme1_baseline` | 254,096 | 181/1058 = 17.11% | 29 | returncode=0 |
| `scheme4_plus` | 254,096 | 199/1058 = 18.81% | 17 | returncode=0 |

结论：`scheme4_plus` 比 baseline 多 18 个 common bit，短测有效。

## 7. CVA6 方案1/方案4 10h 长测

来源说明：

```text
myfuzz/docs/PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md
```

其中 `IBEX1000S_CVA610H_CURRENT_RESULTS_20260615.md` 的内容已合并到本文件，旧文件清理时可删除。

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626
```

结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/latest_sample.json
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/summary.json
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626/manifest.json
```

口径：

```text
common_total = 3496
exclude_top_bits = 0
支持断续重启
```

最终结果：

| 方案 | tests_total | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---|
| `scheme1_baseline` | 584,056 | 404/3496 = 11.56% | 7 | returncode=0 |
| `scheme4_lightweight_plus` | 641,076 | 371/3496 = 10.61% | 0 | returncode=0 |

每小时结果：

| 小时 | baseline coverage | baseline tests | scheme4 coverage | scheme4 tests |
|---:|---:|---:|---:|---:|
| 1 | 404/3496 | 54,836 | 371/3496 | 55,092 |
| 2 | 404/3496 | 112,296 | 371/3496 | 123,444 |
| 3 | 404/3496 | 178,088 | 371/3496 | 190,004 |
| 4 | 404/3496 | 233,436 | 371/3496 | 256,052 |
| 5 | 404/3496 | 297,692 | 371/3496 | 321,076 |
| 6 | 404/3496 | 352,272 | 371/3496 | 386,356 |
| 7 | 404/3496 | 404,292 | 371/3496 | 449,076 |
| 8 | 404/3496 | 464,708 | 371/3496 | 510,260 |
| 9 | 404/3496 | 518,520 | 371/3496 | 574,772 |
| 10 | 404/3496 | 584,056 | 371/3496 | 641,076 |

结论：CVA6 当前方案4没有超过 baseline，第 1 小时后两个方案都进入平台期。

## 8. Ibex `scheme4_plus2` 6h 尝试

来源说明：

```text
旧阶段性工作记录已合并到本节后删除。
轻量结果快照保留在 myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_scheme1_vs_scheme4_plus2_6h_resume_20260615_151324/
```

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_scheme1_vs_scheme4_plus2_6h_resume_20260615_151324
```

状态：无效双方案长跑结果。

第 1 小时采样：

| 方案 | alive | returncode | tests_total | common coverage |
|---|---:|---:|---:|---:|
| `scheme1_baseline` | 1 |  | 72,980 | 443/1058 |
| `scheme4_plus2` | 0 | 1 | 256 | 239/1058 |

结论：`scheme4_plus2` 已异常退出，只剩 baseline 进程继续跑，因此不能作为有效 6h 对比结果引用。

## 9. Ibex `scheme4_plus3` 1000s 短测

来源说明：

```text
旧阶段性文档已合并到本节后删除。
轻量结果快照保留在 myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/
```

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915
```

结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/latest_sample.json
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_lightweight_plus3_bitconstrained_fix1_1000s_20260615_161915/manifest.json
```

口径：

```text
common_total = 1058
RFuzz input width = 395 bit
```

结果：

| 方案 | tests_total | tests/s | common coverage | queue union coverage | discoveries | 状态 |
|---|---:|---:|---:|---:|---:|---|
| `scheme1_baseline` | 4,116 | 5.13 | 341/1058 = 32.23% | 366/1058 | 95 | returncode=0 |
| `scheme4_plus3` | 4,116 | 5.11 | 440/1058 = 41.59% | 463/1058 | 121 | returncode=0 |

直接对比：

| 指标 | plus3 - baseline |
|---|---:|
| common covered | +99 bit |
| common pct | +9.36 percentage points |
| queue union common covered | +97 bit |
| discoveries | +26 |
| tests_total | 0 |

结论：`scheme4_plus3` 是历史上最有效的 Ibex 方案4短测增强，但它不满足当前“只做轻量输入 bit 约束”的边界。当前符合原始意图的新实现改名为方案5：`scheme5_bit_constraints`，尚待短测/长测。

## 10. 当前有效结论

1. Ibex 正式 10h 原始四方案中，baseline 最高，原始方案4接近但没有超过 baseline。
2. Ibex 历史性能增强方向有效：`scheme4_plus` 和 `scheme4_plus3` 在 1000s 短测里均超过 baseline。
3. `scheme4_plus3` 的短测提升最明显，但它包含模板/model/反馈逻辑；当前已新增方案5 `scheme5_bit_constraints` 作为符合原始意图的 bit-only 约束实现。
4. CVA6 当前方案4没有超过 baseline，需要单独优化 CVA6 的约束策略。
5. `scheme4_plus2` 6h 尝试失败，不能作为有效结果引用。

## 10.1 Ibex 方案5 `scheme5_bit_constraints` 当前实现状态

实现日期：2026-06-16。

本节记录当前 Ibex 方案5的方向：只约束 RFuzz 0/1 输入 bit 串，不把 harness 改成协议模拟器或 directed generator。

本地文件：

```text
/home/qinkejiu/test/myfuzz/configs/designs/ibex_scheme5_bit_constraints/config.json
/home/qinkejiu/test/myfuzz/configs/designs/ibex_scheme5_bit_constraints/harness/ibex_core_scheme5_bit_constraints_harness.sv
/home/qinkejiu/test/myfuzz/scripts/runs/run_ibex_baseline_vs_scheme5_bit_constraints_1000s.py
/home/qinkejiu/test/myfuzz/docs/IBEX_SCHEME5_BIT_CONSTRAINTS.md
```

约束策略：

- `rfuzz_input_bits` 接口保持 395 bit，与 baseline 相同。
- 所有 DUT 输入最终都来自 `rfuzz_input_bits`。
- 没有 instruction template、scenario、协议状态机、memory/RF model。
- 没有 `dut.*` 输出反馈到输入生成逻辑。
- 当前是推进优先版：boot 256B 对齐、轻微 32-bit 指令低位偏置、fetch enable 投影、`rvalid=>gnt` 且提高 response 概率、`err=>rvalid` 且低频化、IRQ/NMI/debug 低频互斥、fast IRQ onehot。

当前状态：

- 已完成本地实现。
- 已通过 JSON/Python 解析检查。
- 已静态检查 harness 中没有 `always_*`、函数模板、`dut.*` 反馈引用。
- 已通过本地 1s smoke：能够生成 RFuzz TOML、Verilator server，并执行 1s fuzz。
- 尚未运行正式 1000s/长测覆盖率对比。

## 11. CVA6 `scheme4_lightweight_plus4/plus5` 300s 短测与 plus5 4h 当前运行

测试日期：2026-06-15。

目标：优化 CVA6 的方案4，使其回到“约束 RFuzz 0/1 输入 bit 串”的原始目标，并尽量提高覆盖率。

新增实现：

```text
myfuzz/configs/designs/cva6_lightweight_plus4/config.json
myfuzz/configs/designs/cva6_lightweight_plus4/harness/cva6_lightweight_plus4_harness.sv
myfuzz/scripts/runs/run_cva6_scheme1_vs_scheme4_plus4_4h_resume.py

myfuzz/configs/designs/cva6_lightweight_plus5/config.json
myfuzz/configs/designs/cva6_lightweight_plus5/harness/cva6_lightweight_plus5_harness.sv
myfuzz/scripts/runs/run_cva6_scheme1_vs_scheme4_plus5_4h_resume.py
```

远端构建产物：

```text
/root/fanzehui/myfuzz/runs/designs/cva6_lightweight_plus4/
/root/fanzehui/myfuzz/runs/designs/cva6_lightweight_plus5/
```

运行策略：

- baseline 和新方案4并行运行。
- `common_total = 3496`，不排除 CVA6 顶层 bit。
- 300s 短测用于判断约束方向。
- 4h 测试使用可续跑 runner，`sample_interval = 3600s`，每小时写 `hourly_common_coverage.csv`。

输入约束策略：

- `scheme1_baseline`：CVA6 顶层 521-bit 输入完全随机驱动。
- `scheme4_lightweight_plus4`：保留原始 521-bit 顶层输入映射，以 raw passthrough 为主；由 bit 字段控制 boot/hart、NoC ready/valid、CV-X-IF ready、IRQ/debug/ipi/time_irq 的轻量投影。
- `scheme4_lightweight_plus5`：继承 plus4，并增加可选 NoC read-data 指令投影模式，把部分 read data 映射为合法 RV64 指令对，或与 raw data 混合。

短测结果 1：plus4 300s。

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus4_probe_300s_20260615_214736
```

| 方案 | tests_total | common coverage | discoveries | queue entries | 状态 |
|---|---:|---:|---:|---:|---|
| `scheme1_baseline` | 352 | 403/3496 = 11.53% | 6 | 7 | returncode=0 |
| `scheme4_lightweight_plus4` | 352 | 403/3496 = 11.53% | 6 | 7 | returncode=0 |

短测结果 2：plus5 300s。

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_probe_300s_20260615_221252
```

| 方案 | tests_total | common coverage | discoveries | queue entries | 状态 |
|---|---:|---:|---:|---:|---|
| `scheme1_baseline` | 352 | 403/3496 = 11.53% | 6 | 7 | returncode=0 |
| `scheme4_lightweight_plus5` | 352 | 403/3496 = 11.53% | 6 | 7 | returncode=0 |

短测结论：

- plus4/plus5 均把旧 CVA6 方案4的 `371/3496`、`0 discoveries` 修复到 baseline 水平。
- plus5 的合法指令投影在 300s 内没有表现出超过 plus4/baseline 的增益，但它保留 plus4 passthrough 并增加一个 RFuzz bit 可选择的指令数据投影模式，因此选 plus5 做 4h 长测。

当前 4h 测试：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501
```

启动状态：

```text
launcher PID: 3125512
scheme1 run_design_flow PIDs: 3125523, 3125524
scheme4 plus5 run_design_flow PIDs: 3125525, 3125526
scheme4 plus5 server PID: 3125527
scheme1 server PID: 3125528
scheme4 plus5 kfuzz PID: 3125529
scheme1 kfuzz PID: 3125531
```

结果文件：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501/hourly_common_coverage.csv
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501/latest_sample.json
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501/manifest.json
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501/logs/slice_0000_scheme1_baseline.log
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501/logs/slice_0000_scheme4_lightweight_plus5.log
```

查看命令：

```bash
ssh inner70
cd /root/fanzehui/myfuzz
RUN=/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_plus5_4h_4h_20260615_223501
cat $RUN/hourly_common_coverage.csv
cat $RUN/latest_sample.json
cat $RUN/manifest.json
tail -80 $RUN/logs/slice_0000_scheme1_baseline.log
tail -80 $RUN/logs/slice_0000_scheme4_lightweight_plus5.log
```

## 12. Ibex `scheme4_plus3` 12h continuation 当前运行

测试日期：2026-06-16。

目标：把已经完成的 Ibex baseline vs `scheme4_plus3` 4h 结果继续运行 8h，形成同一口径的 12h 曲线。

新增本地脚本：

```text
myfuzz/scripts/runs/run_ibex_scheme1_vs_scheme4_plus3_12h_resume.py
```

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_scheme1_vs_scheme4_plus3_12h_cont_from_4h_20260616_0018
```

种子来源，也就是已经完成的 4h run：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_scheme4_plus3_4h_common_14400s_20260615_194845
```

运行策略：

- `slice_0000`：引用已完成 4h run 的两个 queue，并把原 0h/1h/2h/3h/4h 采样转换进新的 `hourly_common_coverage.csv`。
- `slice_0001`：从 `slice_0000` 的 queue 继续 fuzz，计划 28800 秒，也就是额外 8h。
- 总目标 `--seconds 43200`，采样间隔 `3600s`。
- 两个方案并行运行，CPU pin：baseline 用 CPU 0，`scheme4_plus3` 用 CPU 1。
- common coverage 分母仍为 `1058`，排除 Ibex 顶层 MSB 56 bit。

启动状态：

```text
launcher PID: 3126994
scheme1 run_design_flow PIDs: 3126997, 3126998
scheme4_plus3 run_design_flow PIDs: 3126999, 3127000
scheme4_plus3 server PID: 3127001
scheme1 server PID: 3127002
scheme4_plus3 kfuzz PID: 3127003
scheme1 kfuzz PID: 3127005
```

续跑确认：

```text
scheme1 input queue:
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_scheme4_plus3_4h_common_14400s_20260615_194845/designs/scheme1_baseline/queue

scheme4_plus3 input queue:
/root/fanzehui/myfuzz/runs/managed_runs/ibex_baseline_vs_scheme4_plus3_4h_common_14400s_20260615_194845/designs/scheme4_plus3/queue
```

4h 起点结果：

| 方案 | tests_total | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---|
| `scheme1_baseline` | 200104 | 491/1058 = 46.41% | 172 | 作为 `slice_0000` 种子 |
| `scheme4_plus3` | 200104 | 552/1058 = 52.17% | 205 | 作为 `slice_0000` 种子 |

查看命令：

```bash
ssh inner70
cd /root/fanzehui/myfuzz
RUN=/root/fanzehui/myfuzz/runs/managed_runs/ibex_scheme1_vs_scheme4_plus3_12h_cont_from_4h_20260616_0018
cat $RUN/hourly_common_coverage.csv
cat $RUN/latest_sample.json
cat $RUN/manifest.json
tail -80 $RUN/runner.nohup.log
tail -80 $RUN/logs/slice_0001_scheme1_baseline.log
tail -80 $RUN/logs/slice_0001_scheme4_plus3.log
ps -fp $(cat $RUN/runner.pid)
```

当前状态：`slice_0001` 正在运行。完成后需要在本节追加 5h 到 12h 的每小时覆盖率和测试次数，并在总览表中把状态改为成功或失败。

## 13. Ibex `scheme6_relaxed_bit_constraints` 实现与 100s 三方案短测

测试日期：2026-06-16。

目标：在保持“只约束 0/1 输入 bit 串”的边界下，尝试一个比方案5更放松的方案6，并与 baseline、方案5 同时运行 100s。

新增实现文件：

```text
myfuzz/configs/designs/ibex_scheme6_relaxed_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_relaxed_bit_constraints/harness/ibex_core_scheme6_relaxed_bit_constraints_harness.sv
myfuzz/scripts/runs/run_ibex_baseline_vs_scheme5_vs_scheme6_1000s.py
```

方案6约束策略：

- 保持 Ibex 顶层 395-bit `rfuzz_input_bits`，不拆模块。
- 不使用指令模板、场景选择、状态机、memory model、RF model 或 `dut.*` 输出反馈。
- `boot_addr_i` 只做 4-byte 对齐：`{raw_boot_addr_i[31:2], 2'b00}`，不再像方案5一样清零低 8 bit。
- `instr_rdata_i` 完全保留 raw instruction bits，不再把 `instr_rdata_i[1:0]` 偏向 `2'b11`。
- `fetch_enable_i = {raw_fetch_enable_i[3:1], |raw_fetch_enable_i}`，避免 all-zero 关闭 fetch。
- instruction/data bus 保留推进优先局部关系：`rvalid = raw_rvalid`，`gnt = raw_gnt | rvalid`。
- `instr_err_i`/`data_err_i` 只在 valid response 时触发，但 gate 从方案5的 4-bit all-one 放松为 2-bit OR，提高 trap/error 频率。
- IRQ/debug 仍由 raw bit 控制，但 gate 从低频 all-one 改成 2-bit OR。
- `irq_fast_i` 不再 onehot，保留 raw multi-fast-IRQ 组合，避免压掉 fast IRQ priority 相关覆盖。

和方案5的关键差异：

| 点 | 方案5 | 方案6 |
|---|---|---|
| boot address | 256-byte 对齐 | 4-byte 对齐 |
| instruction data | 低两位大概率改为 `2'b11` | 完全 raw |
| error gate | 4-bit all-one，低频 | 2-bit OR，中高频 |
| regular/fast IRQ gate | 4-bit all-one，低频 | 2-bit OR，中高频 |
| fast IRQ | lowest onehot | 保留 raw 15-bit 组合 |

本地 smoke：

```bash
cd /home/qinkejiu/test/myfuzz
python3 src/myfuzz/scripts/run_design_flow.py --config configs/designs/ibex_scheme6_relaxed_bit_constraints/config.json --stage all --force --jobs 2 --fuzz-seconds 1
```

结果：通过，server 能构建并完成 1s fuzz。

100s run root：

```text
/home/qinkejiu/test/myfuzz/runs/managed_runs/ibex_baseline_vs_scheme5_vs_scheme6_100s_100s_20260616_013953
```

运行命令：

```bash
cd /home/qinkejiu/test/myfuzz
python3 scripts/runs/run_ibex_baseline_vs_scheme5_vs_scheme6_1000s.py \
  --seconds 100 \
  --sample-interval 100 \
  --label ibex_baseline_vs_scheme5_vs_scheme6_100s \
  --final-grace-seconds 60
```

运行策略：

- 三个方案并行运行。
- CPU pin：baseline 用 CPU 0，scheme5 用 CPU 1，scheme6 用 CPU 2。
- 每个方案 `jobs=1`、`server_count=1`。
- `seed_cycles=5`，`max_cycles=200`，`max_runs=64`。
- common coverage 分母为 `1058`，排除 Ibex 顶层 MSB 56 bit。

最终结果：

| 方案 | tests_total | cycles_total | common coverage | queue union common | discoveries | returncode |
|---|---:|---:|---:|---:|---:|---:|
| `scheme1_baseline` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme5_bit_constraints` | 4479 | 635 | 107/1058 = 10.11% | 135/1058 = 12.76% | 3 | 0 |
| `scheme6_relaxed_bit_constraints` | 4479 | 635 | 118/1058 = 11.15% | 162/1058 = 15.31% | 8 | 0 |

结论：

- 方案6比方案5更好：common coverage 从 107 提高到 118，discoveries 从 3 提高到 8。
- 方案6仍低于 baseline：118 vs 132，说明当前纯组合 bit 约束还没有在 100s 内带来覆盖优势。
- 三个方案的 `tests_total` 和 `cycles_total` 完全一致，因此这次差异主要来自输入投影/约束本身，不是运行量不同。
- 方案6的 `queue_union_common_covered` 最高，为 162，高于 baseline 的 135；这说明方案6能产生更多队列级候选覆盖，但最终 cumulative bitmap 里的 common coverage 没有转化成最高值。后续优化应围绕“保留 queue union 优势，同时提高 latest bitmap 覆盖”继续调约束。

查看结果：

```bash
cd /home/qinkejiu/test/myfuzz
RUN=runs/managed_runs/ibex_baseline_vs_scheme5_vs_scheme6_100s_100s_20260616_013953
cat $RUN/hourly_common_coverage.csv
cat $RUN/latest_sample.json
cat $RUN/manifest.json
tail -80 $RUN/logs/scheme1_baseline.log
tail -80 $RUN/logs/scheme5_bit_constraints.log
tail -80 $RUN/logs/scheme6_relaxed_bit_constraints.log
```

## 14. Ibex strict bit-only ablation: minimal constraints and opcode projection

测试日期：2026-06-16。

目标：继续只处理 Ibex，并严格保持“方案五/六模式”：Ibex 顶层 395-bit `rfuzz_input_bits`，所有 DUT 输入只由输入 bit 串组合投影得到；不加入方案四/plus3 那类场景、指令程序、memory/RF model、协议状态机或 `dut.*` 输出反馈。

新增共享 ablation harness：

```text
myfuzz/configs/designs/ibex_scheme6_ablation_bit_constraints/harness/ibex_core_scheme6_ablation_bit_constraints_harness.sv
```

新增/复用配置：

```text
myfuzz/configs/designs/ibex_scheme6_fetch_only_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_handshake_only_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_fetch_handshake_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_minlegal_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_opcode_only_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_opcode_mixed_bit_constraints/config.json
myfuzz/configs/designs/ibex_scheme6_opcode_minlegal_bit_constraints/config.json
myfuzz/scripts/runs/run_ibex_bit_constraints_ablation_1000s.py
myfuzz/scripts/runs/run_ibex_opcode_bit_constraints_ablation_1000s.py
```

### 14.1 最小约束 ablation 100s

run root：

```text
/home/qinkejiu/test/myfuzz/runs/managed_runs/ibex_bit_constraints_ablation_100s_100s_20260616_015516
```

结果：

| 方案 | tests_total | cycles_total | common coverage | queue union common | discoveries | returncode |
|---|---:|---:|---:|---:|---:|---:|
| `scheme1_baseline` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_fetch_only` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_handshake_only` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_fetch_handshake` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_minlegal` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_relaxed_bit_constraints` | 4479 | 635 | 118/1058 = 11.15% | 162/1058 = 15.31% | 8 | 0 |
| `scheme5_bit_constraints` | 4479 | 635 | 107/1058 = 10.11% | 135/1058 = 12.76% | 3 | 0 |

结论：

- `fetch_enable` 非零投影、`rvalid=>gnt`、boot 4-byte 对齐、error 只在 valid response 时触发，这些最小约束在 100s 内没有提高覆盖率，但也没有伤害覆盖率。
- 方案5/6之前掉覆盖的主要风险不在这些最小协议约束，而在更强的 instruction/IRQ/debug/error 频率塑形。

### 14.2 opcode 投影 ablation 100s

run root：

```text
/home/qinkejiu/test/myfuzz/runs/managed_runs/ibex_opcode_bit_constraints_ablation_100s_100s_20260616_020256
```

结果：

| 方案 | tests_total | cycles_total | common coverage | queue union common | discoveries | returncode |
|---|---:|---:|---:|---:|---:|---:|
| `scheme6_opcode_mixed` | 4479 | 635 | 133/1058 = 12.57% | 135/1058 = 12.76% | 13 | 0 |
| `scheme1_baseline` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_minlegal` | 4479 | 635 | 132/1058 = 12.48% | 135/1058 = 12.76% | 12 | 0 |
| `scheme6_opcode_only` | 4479 | 635 | 121/1058 = 11.44% | 122/1058 = 11.53% | 7 | 0 |
| `scheme6_opcode_minlegal` | 4479 | 635 | 121/1058 = 11.44% | 122/1058 = 11.53% | 7 | 0 |

约束策略：

- `scheme6_opcode_only`：只把 `instr_rdata_i[6:0]` opcode 位组合映射到常见 RV32 opcode class，指令其它位保持 raw。
- `scheme6_opcode_mixed`：由 `raw_instr_rdata_i[11]` 这个输入 bit 选择 raw opcode 或合法 opcode 投影，大约一半测试保持 baseline raw opcode，一半测试走合法 opcode class。
- `scheme6_opcode_minlegal`：opcode 投影再叠加 minlegal 的 boot/fetch/handshake/error-valid 投影。

结论：

- `scheme6_opcode_mixed` 是当前第一个严格 bit-only 方案五/六模式下短测超过 baseline 的变体：133 vs 132。
- 完全 opcode 合法化明显伤覆盖：121 vs 132，说明把 opcode 一直压到合法集合会丢掉 Ibex illegal instruction、trap、decode 边界路径。
- 后续优化方向应该是“少量、可透传的 opcode/low-bit 投影”，不是全量合法化，也不是回到方案四那类状态机/模板驱动。

## 15. Ibex all bit-only variants pre/post 6h remote run: completed

启动时间：2026-06-16 03:24:53 CST。

完成时间：2026-06-16 09:25 CST 左右。

状态：已完成。41 路方案全部 `returncode=0`，没有异常退出。

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
```

启动日志：

```text
/root/fanzehui/myfuzz/runs/managed_runs/tools/ibex_all_variants_pre_post_6h_launch_20260616_032453.log
```

运行脚本：

```text
/root/fanzehui/myfuzz/scripts/runs/run_ibex_all_bit_constraint_variants_pre_post_6h_resume.py
```

运行策略：

- 只在远程服务器 `inner70` 的 `/root/fanzehui/myfuzz` 下运行。
- `--hours 6`，每 3600s 采样一次。
- 支持断续重启：后续可用同一个 `--run-root` 继续运行。
- 使用 common coverage 口径，`common_total=1058`。
- CPU 绑定到 `2..42`，避开旧的 CPU0/1 plus3 12h continuation run。
- 共 41 路并行：baseline 1 路，20 个 bit-only 约束变体的 `_pre` 版本，20 个对应 `_post` 版本。

pre/post 定义：

- `_pre`：RFuzz 变异修正前 raw 395-bit `rfuzz_input_bits`；手写 harness 再把 raw bits 组合投影到 Ibex 顶层输入。
- `_post`：RFuzz 直接变异修正后的 DUT 输入向量；作为 after-correction control，复用 baseline direct top-level harness。

启动前远程 5s smoke：

```text
run root: /root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_remote_smoke_5s_5s_20260616_032233
summary rows: 41
bad rows: 0
```

启动后内存快照：

```text
Mem: 125Gi total, 6.1Gi used, 101Gi free, 119Gi available
Swap: 8.0Gi total, 0B used
new run processes: 41 server + 41 kfuzz
new run RSS: about 1028 MiB
```

完成后远程状态：

```text
runner: exited
server processes: 0
kfuzz processes: 0
Mem: 125Gi total, 4.5Gi used, 121Gi available
Swap: 8.0Gi total, 0B used
```

最终结果排名：

| rank | scheme | tests_total | cycles_total | common coverage | discoveries | returncode |
|---:|---|---:|---:|---:|---:|---:|
| 1 | `scheme5_pre` | 63,508 | 211,543 | 506/1058 = 47.83% | 178 | 0 |
| 2 | `scheme6_relaxed_pre` | 63,508 | 210,920 | 487/1058 = 46.03% | 165 | 0 |
| 3 | `scheme6_low2_mixed25_pre` | 63,508 | 212,004 | 462/1058 = 43.67% | 162 | 0 |
| 4 | `scheme6_handshake_only_pre` | 63,508 | 211,658 | 460/1058 = 43.48% | 158 | 0 |
| 5 | `scheme6_opcode_mixed_post` | 63,508 | 211,232 | 459/1058 = 43.38% | 153 | 0 |
| 6 | `scheme6_low2_opcode_mixed25_post` | 63,508 | 211,844 | 459/1058 = 43.38% | 151 | 0 |
| 7 | `scheme6_minlegal_pre` | 63,508 | 211,222 | 458/1058 = 43.29% | 154 | 0 |
| 8 | `scheme6_low2_mixed50_post` | 63,508 | 211,143 | 458/1058 = 43.29% | 147 | 0 |
| 9 | `scheme6_fetch_only_post` | 63,508 | 211,415 | 457/1058 = 43.19% | 148 | 0 |
| 10 | `scheme6_opcode_only_post` | 63,508 | 211,029 | 457/1058 = 43.19% | 147 | 0 |
| 11 | `scheme6_handshake_only_post` | 63,508 | 210,227 | 455/1058 = 43.01% | 156 | 0 |
| 12 | `scheme5_post` | 63,508 | 210,684 | 455/1058 = 43.01% | 149 | 0 |
| 13 | `scheme6_opcode_mixed75_post` | 63,508 | 211,244 | 454/1058 = 42.91% | 153 | 0 |
| 14 | `scheme6_fetch_handshake_pre` | 63,508 | 211,747 | 454/1058 = 42.91% | 152 | 0 |
| 15 | `scheme1_baseline` | 63,508 | 212,658 | 453/1058 = 42.82% | 148 | 0 |

超过 baseline 的 `_pre` 变体：

| scheme | tests_total | cycles_total | common coverage | delta vs baseline | discoveries |
|---|---:|---:|---:|---:|---:|
| `scheme5_pre` | 63,508 | 211,543 | 506/1058 = 47.83% | +53 | 178 |
| `scheme6_relaxed_pre` | 63,508 | 210,920 | 487/1058 = 46.03% | +34 | 165 |
| `scheme6_low2_mixed25_pre` | 63,508 | 212,004 | 462/1058 = 43.67% | +9 | 162 |
| `scheme6_handshake_only_pre` | 63,508 | 211,658 | 460/1058 = 43.48% | +7 | 158 |
| `scheme6_minlegal_pre` | 63,508 | 211,222 | 458/1058 = 43.29% | +5 | 154 |
| `scheme6_fetch_handshake_pre` | 63,508 | 211,747 | 454/1058 = 42.91% | +1 | 152 |

关键方案每小时覆盖率和测试次数：

| hour | `scheme1_baseline` | `scheme5_pre` | `scheme6_relaxed_pre` | `scheme6_low2_mixed25_pre` | `scheme6_handshake_only_pre` |
|---:|---:|---:|---:|---:|---:|
| 1 | 366/1058, 5,396 tests | 433/1058, 5,396 tests | 408/1058, 5,396 tests | 385/1058, 5,396 tests | 369/1058, 5,396 tests |
| 2 | 406/1058, 16,916 tests | 467/1058, 16,916 tests | 447/1058, 16,916 tests | 412/1058, 16,916 tests | 413/1058, 16,916 tests |
| 3 | 428/1058, 28,692 tests | 484/1058, 28,692 tests | 459/1058, 28,692 tests | 423/1058, 28,692 tests | 437/1058, 28,692 tests |
| 4 | 438/1058, 40,212 tests | 496/1058, 40,212 tests | 467/1058, 39,956 tests | 448/1058, 39,956 tests | 445/1058, 40,212 tests |
| 5 | 442/1058, 51,732 tests | 499/1058, 51,732 tests | 477/1058, 51,732 tests | 457/1058, 51,732 tests | 453/1058, 51,732 tests |
| 6 | 453/1058, 63,508 tests | 506/1058, 63,508 tests | 487/1058, 63,508 tests | 462/1058, 63,508 tests | 460/1058, 63,508 tests |

结论：

- 这次 6h 长测证明严格 bit-only 的方案五/六模式可以超过 baseline。
- `scheme5_pre` 是当前最强结果：比 baseline 多 53 个 common bit，discoveries 多 30 次，且测试次数完全相同。
- `scheme6_relaxed_pre` 是第二强结果：比 baseline 多 34 个 common bit。
- `_pre` 明显比 `_post` 更有意义：`_pre` 保持“fuzzer 变异 raw bit 串，再由 harness 修正/投影”的原始研究目标；`_post` 主要是 direct-harness 对照。
- 后续优化应以 `scheme5_pre` 的约束为基线，小幅调 gate、IRQ/debug/error 和指令低位扰动；本轮强 opcode/LSU 投影多数低于 baseline，说明过度合法化或过度定向 LSU 会压掉覆盖空间。

查看结果：

```bash
ssh inner70
cd /root/fanzehui/myfuzz
RUN=/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
cat $RUN/latest_sample.json
cat $RUN/hourly_common_coverage.csv
cat $RUN/summary.json
cat $RUN/manifest.json
tail -80 runs/managed_runs/tools/ibex_all_variants_pre_post_6h_launch_20260616_032453.log
ps -fp $(cat $RUN/runner.pid)
free -h
```

### 15.1 为什么这轮 6h 的 `tests_total` 完全相同

这轮 `ibex_all_variants_pre_post_6h` 中，baseline、scheme5/6 的多个 `_pre/_post` 变体最终都显示 `tests_total = 63,508`。这个现象需要解释清楚，避免误以为结果被复制。

`tests_total` 的来源不是 coverage，也不是手工填表，而是 runner 从 RFuzz stats 中读取：

```text
tests_per_second.global_numerator
```

对应本地脚本：

```text
/home/qinkejiu/test/myfuzz/scripts/runs/run_ibex_scheme1_vs_scheme4_plus2_10h_resume.py
```

关键实现位置：

- `cumulative_slice_stats()` 读取 `tests_per_second.global_numerator` 并累加为 `tests_total`。
- `sample_scheme()` 把这个累计值写入 `hourly_common_coverage.csv`、`latest_sample.json`、`summary.json`。
- 每个方案都用同样的 `run_design_flow.py --stage fuzz --jobs 1 --fuzz-seconds <slice_seconds>` 方式启动。

这轮 6h 实验里，所有有效方案有几个共同点：

- 都是 Ibex 顶层 395-bit 输入规模，没有方案2/3那种拆子模块后的大输入和慢仿真。
- 都在同一 runner 中按相同 wall-clock 时长、相同采样间隔、相同 job 数运行。
- 都正常结束，`returncode=0`，没有某一路提前崩溃或卡死。
- RFuzz 的 test 计数在这个配置下主要跟执行批次数/调度节奏绑定，而不是跟发现了多少覆盖绑定。

因此，`tests_total` 完全相同并不表示 coverage 被复制；它反而说明这轮对比把“运行量”控制住了。可以用 `cycles_total` 和 coverage 的差异验证这一点：

| 方案 | tests_total | cycles_total | common coverage | discoveries |
|---|---:|---:|---:|---:|
| `scheme1_baseline` | 63,508 | 212,658 | 453/1058 = 42.82% | 148 |
| `scheme5_pre` | 63,508 | 211,543 | 506/1058 = 47.83% | 178 |
| `scheme6_relaxed_pre` | 63,508 | 210,920 | 487/1058 = 46.03% | 165 |

如果只是结果被复制，`cycles_total`、coverage、discoveries 不应该同时不同。这里真正相同的是 RFuzz 执行的 test 数量，不同的是这些 test 经过不同 harness 投影后进入 Ibex 的实际输入分布。

对照历史也能说明计数不是固定死的：原始 Ibex 四方案 10h 中，方案1/4 是顶层 harness，约 8.09M tests；方案2/3 是分解式大输入，只有约 0.95M tests。也就是说，当仿真结构和吞吐差异很大时，`tests_total` 会明显不同。本轮 6h 之所以相同，是因为所有方案都是同类顶层 Ibex harness，运行配置也一致。

### 15.2 Ibex 方案5 `scheme5_bit_constraints` 的全部约束和来源

方案5的文件位置：

```text
/home/qinkejiu/test/myfuzz/configs/designs/ibex_scheme5_bit_constraints/harness/ibex_core_scheme5_bit_constraints_harness.sv
```

方案5的边界：

- 保持 Ibex 顶层 fuzz，不拆子模块。
- 保持和 baseline 一样的 395-bit `rfuzz_input_bits`。
- fuzzer 变异的是修正前 raw 0/1 bit 串。
- harness 只做组合逻辑投影，把 raw bit 串映射成更合理的 Ibex 顶层输入。
- 不使用指令模板程序、不使用 memory/RF model、不读取 DUT 输出反馈、不做协议状态机。

约束来源主要有三类：

1. Ibex 顶层端口和总线语义：`fetch_enable_i`、`instr_gnt_i/rvalid_i`、`data_gnt_i/rvalid_i`、`instr_err_i/data_err_i`、IRQ/debug 这些信号不是彼此独立的完全随机位。
2. RISC-V/Ibex 执行语义：32-bit 指令编码低两位通常为 `2'b11`，启动/取指地址需要对齐，NMI 和普通中断有优先级关系。
3. 前面 baseline/方案4/方案5/方案6 短测和长测的经验：过度合法化会压掉 illegal/trap/decode 边界路径；完全随机又会让大量周期停在低质量状态。因此方案5采用“少量低频门控 + 保留大部分 raw 随机性”的策略。

方案5全部约束如下。

| 编号 | 约束 | 实现 | 作用 |
|---:|---|---|---|
| 1 | `boot_addr_i` 256-byte 对齐 | `boot_addr_i = {raw_boot_addr_i[31:8], 8'h00}` | 减少随机低地址位造成的无意义起始/跳转状态，让取指入口更稳定。 |
| 2 | 指令低位偏向 32-bit 编码 | 大多数情况下 `instr_rdata_i[1:0] = 2'b11`，少数由 raw bits 透传 | 让 core 更常进入正常 32-bit decode/execute，同时保留少量 compressed/illegal 边界。 |
| 3 | `fetch_enable_i` 大概率开启 | `fetch_enable_i = {raw_fetch_enable_i[3:1], |raw_fetch_enable_i}` | 避免 fetch 长时间关闭，增加有效执行周期；仍然由 raw bits 决定，不是常量 4'b0001。 |
| 4 | 指令/数据握手局部一致 | `rvalid` 保持 raw，`gnt = raw_gnt | rvalid` | 避免出现 response valid 但 grant 不成立的低质量组合；不依赖 DUT 的 `req_o`，所以仍是纯输入 bit 投影。 |
| 5 | bus error 低频且必须伴随 valid | `err = rvalid & raw_err & gate`，gate 来自 raw ECC 低 4 位全 1 | 保留异常/错误路径，但避免每周期高概率 error 把 core 长期打进 trap/flush。 |
| 6 | NMI/普通 IRQ 低频触发 | gate 来自 `raw_instr_rdata_i` 的若干位；普通 IRQ 在 NMI 时关闭 | 让中断像事件而不是每周期噪声；保留 NMI 优先级关系。 |
| 7 | fast IRQ onehot 化 | lower-index raw bit 优先，最多保留一个 `irq_fast_i[n]` | 对应 Ibex fast IRQ 优先级，避免密集多 IRQ 互相遮蔽。 |
| 8 | debug 低频且不与 NMI 同周期 | `debug_req_i = raw_debug_req_i & debug_gate & ~irq_nm_i` | 保留 debug 入口路径，但避免 debug 每周期随机拉高，也避免和 NMI 同周期冲突。 |

未约束、保持 raw passthrough 的输入：

- `ic_data_rdata_i[0/1]`
- `ic_tag_rdata_i[0/1]`
- `data_rdata_i`
- `hart_id_i`
- `rf_rdata_a_ecc_i`
- `rf_rdata_b_ecc_i`
- `ic_scr_key_valid_i`

这点很重要：方案5不是把输入改造成小型 directed testbench，而是把最破坏执行质量的少数端口关系修正掉。最终 6h 结果中，`scheme5_pre` 在相同 `tests_total` 下比 baseline 多覆盖 53 个 common bit，说明这种 raw-bit-before-correction 的约束方向有效。

## 16. 远端 Ibex/CVA6 baseline vs 方案4历史对比汇总

本节只汇总“远程服务器上已经完成的 baseline vs 方案4”结果，方便后续查阅。这里不把 Ibex 和 CVA6 互相比，只记录各自设计内的 baseline 与方案4对比。

### 16.1 Ibex 原始方案1/方案4 10h

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/four_schemes_10h_common_10h_20260614_021002
```

本地归档副本：

```text
/home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/four_schemes_10h_common_10h_20260614_021002
```

覆盖率口径：

- `common_total = 1058`
- 统计 `__vi_coverage[1057:0]`
- 排除 Ibex 顶层额外 56 个 bit：`__vi_coverage[1113:1058]`

最终对比：

| 方案 | tests_total | tests/s | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---:|---|
| `scheme1_baseline` | 8,096,032 | 224.90 | 376/1058 = 35.54% | 119 | returncode=0 |
| `scheme4_lightweight` | 8,096,608 | 224.91 | 350/1058 = 33.08% | 103 | returncode=0 |

结论：Ibex 原始方案4前期一度领先 baseline，但 10h 结束时 baseline 覆盖更高。主要原因是原始方案4关闭/压低了 debug、bus error、异常类路径，前期更稳，后期覆盖空间受限。

### 16.2 CVA6 方案1/方案4 10h

远端 run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/cva6_scheme1_vs_scheme4_10h_resume_20260615_035626
```

覆盖率口径：

- `common_total = 3496`

最终对比：

| 方案 | tests_total | common coverage | discoveries | 状态 |
|---|---:|---:|---:|---|
| `scheme1_baseline` | 584,056 | 404/3496 = 11.56% | 7 | returncode=0 |
| `scheme4_lightweight_plus` | 641,076 | 371/3496 = 10.61% | 0 | returncode=0 |

结论：CVA6 旧方案4没有超过 baseline，且 discoveries 为 0。后续 plus4/plus5 短测把 CVA6 方案4恢复到 baseline 水平，但还没有证明能稳定超过 baseline。

## 17. Ibex baseline vs scheme5_pre 6h 覆盖点集合分析

分析时间：2026-06-16。

分析对象：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
```

本地分析产物：

```text
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616
```

统计口径：

- 比较 `scheme1_baseline` 与 `scheme5_pre`。
- 使用 common coverage indices `0..1057`。
- 读取两个方案各自 queue 中 `latest.json` 和 `entry_*.json` 的 bitmap。
- 判定规则与 runner 一致：`bitmap[index] != 255` 视为 covered。

集合结果：

| 集合 | 覆盖点数 |
|---|---:|
| baseline covered | 453 |
| scheme5_pre covered | 506 |
| overlap | 426 |
| baseline only | 27 |
| scheme5_pre only | 80 |
| union | 533 |
| uncovered by both | 525 |

区域分布：

| area | overlap | baseline_only | scheme5_only | baseline_total | scheme5_total |
|---|---:|---:|---:|---:|---:|
| ID/decode | 178 | 7 | 53 | 185 | 231 |
| controller/trap/irq/debug | 35 | 0 | 10 | 35 | 45 |
| IF/fetch | 22 | 2 | 8 | 24 | 30 |
| CSR/priv/counters | 52 | 0 | 6 | 52 | 58 |
| EX/ALU/multdiv | 67 | 1 | 3 | 68 | 70 |
| LSU/memory | 59 | 17 | 0 | 76 | 59 |

区域功能说明：

| area | 主要功能 | 本轮覆盖差异说明 |
|---|---|---|
| ID/decode | 指令解压缩、主 decoder、立即数/寄存器/控制信号生成、非法指令识别 | `scheme5_pre` 独有 53 点，是最大增益来源。说明指令低位偏向 32-bit、fetch 维持开启、握手更一致后，core 更容易持续进入有效 decode 路径，同时还能保留一部分 illegal/default decode 分支。 |
| controller/trap/irq/debug | pipeline 控制、异常/trap、interrupt/debug 入口、flush/redirect、控制状态机 | `scheme5_pre` 独有 10 点，baseline 独有 0 点。说明低频 IRQ/NMI/debug/error 比完全随机更容易触发可持续的控制流状态，而不是把 core 打散到噪声状态。 |
| IF/fetch | 取指请求、fetch valid、prefetch/fetch FIFO、取指侧 stall/flush 交互 | `scheme5_pre` 独有 8 点。说明 `fetch_enable_i` 大概率开启、`instr_rvalid => instr_gnt` 的局部握手约束提高了取指推进能力。 |
| CSR/priv/counters | CSR 读写、特权状态、异常原因/中断相关寄存器、性能计数器 | `scheme5_pre` 独有 6 点，baseline 独有 0 点。说明低频异常/中断/debug 事件让 CSR/privileged 状态更容易被真实触发。 |
| EX/ALU/multdiv | ALU 运算、分支比较、移位、乘除法执行路径 | `scheme5_pre` 小幅多 3 点。说明更多有效 decode 会带来更多执行单元路径，但当前约束没有专门定向 EX。 |
| LSU/memory | load/store 状态机、data bus grant/valid/error、地址/字节使能、memory stall/response | baseline 独有 17 点，而 `scheme5_pre` 独有 0 点。说明完全随机输入仍能碰到一些 LSU raw 边界；后续方案五不能继续收紧 LSU，应该保留或增强 LSU 随机边界探索。 |
| WB | 写回阶段、寄存器写回路径 | 两边都只覆盖 2 点，没有差异。本配置下 writeback stage 参数关闭或路径较少，不是本轮差异来源。 |
| top ibex_core excluded | 顶层 ibex_core 额外覆盖位；正式 common 口径主要排除顶层额外 MSB 56 bit | 两边在 common 低位中各 5 点，无差异；不是方案五增益来源。 |
| unknown | TOML/bitmap 中未能映射到具体模块的 padding/辅助覆盖点 | 两边各 6 点，无差异，不作为功能结论依据。 |

主要结论：

- 两个方案共有 426 个重合点，说明基本执行路径和容易触达路径基本一致。
- `scheme5_pre` 独有 80 点，远多于 baseline 独有 27 点；净增覆盖就是 `506 - 453 = 53`。
- `scheme5_pre` 的独有点主要集中在 decode、controller/trap/irq/debug、IF/fetch、CSR 区域，说明 bit-only 约束确实让 core 更常进入“能持续取指、解码、控制流推进、异常/中断可达”的状态。
- baseline 独有点主要集中在 LSU/memory，说明完全随机输入仍然能偶然打到一些 scheme5 没触达的 raw/memory 边界路径。后续优化不能把 LSU 过度规整，否则会丢掉这部分探索能力。

明细文件：

```text
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/README.md
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/overlap_points.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/baseline_only_points.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/scheme5_only_points.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/missing_points.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/module_distribution.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/area_distribution.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_scheme5_vs_baseline_coverage_6h_20260616/kind_distribution.csv
```

## 18. Ibex baseline / scheme5_pre / scheme6_relaxed_pre 三方案覆盖集合分析

分析时间：2026-06-16。

分析对象：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
```

本地分析产物：

```text
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616
```

统计口径：

- 比较 `scheme1_baseline`、`scheme5_pre`、`scheme6_relaxed_pre` 三个方案。
- 使用 common coverage indices `0..1057`。
- 读取各自 queue 中 `latest.json` 和 `entry_*.json` 的 bitmap。
- 判定规则与 runner 一致：`bitmap[index] != 255` 视为 covered。

三方案集合结果：

| 集合 | 覆盖点数 |
|---|---:|
| baseline covered | 453 |
| scheme5_pre covered | 506 |
| scheme6_relaxed_pre covered | 487 |
| all three overlap | 416 |
| baseline only | 6 |
| scheme5 only | 38 |
| scheme6 only | 8 |
| baseline + scheme5 only, not scheme6 | 10 |
| baseline + scheme6 only, not scheme5 | 21 |
| scheme5 + scheme6 only, not baseline | 42 |
| union | 541 |
| uncovered by all three | 517 |

两两对比：

| 对比 | overlap | 左侧独有 | 右侧独有 | union | 结论 |
|---|---:|---:|---:|---:|---|
| baseline vs scheme5_pre | 426 | 27 | 80 | 533 | `scheme5_pre` 净多 53 点，是当前最强方案。 |
| baseline vs scheme6_relaxed_pre | 437 | 16 | 50 | 503 | `scheme6_relaxed_pre` 净多 34 点，也明显强于 baseline。 |
| scheme5_pre vs scheme6_relaxed_pre | 458 | 48 | 29 | 535 | `scheme5_pre` 总覆盖更高；`scheme6` 保留了部分 `scheme5` 丢掉的 LSU/memory 点。 |

功能区域分布：

| area | 主要功能 | baseline_total | scheme5_total | scheme6_total | all_three | baseline_only | scheme5_only | scheme6_only | scheme5+scheme6 only |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ID/decode | 指令解压缩、主 decoder、立即数/寄存器/控制信号生成、非法指令识别 | 185 | 231 | 201 | 168 | 4 | 29 | 6 | 24 |
| controller/trap/irq/debug | pipeline 控制、异常/trap、interrupt/debug 入口、flush/redirect 控制状态机 | 35 | 45 | 45 | 35 | 0 | 1 | 1 | 9 |
| IF/fetch | 取指 request/valid、prefetch/fetch FIFO、取指侧 stall/flush 交互 | 24 | 30 | 28 | 22 | 0 | 4 | 0 | 4 |
| CSR/priv/counters | CSR 访问、特权状态、trap/interrupt cause、计数器 | 52 | 58 | 56 | 52 | 0 | 2 | 0 | 4 |
| EX/ALU/multdiv | ALU、branch compare、shift、乘除法执行路径 | 68 | 70 | 69 | 67 | 0 | 2 | 0 | 1 |
| LSU/memory | load/store 状态机、data grant/valid/error、地址/byte-enable、memory stall/response | 76 | 59 | 75 | 59 | 2 | 0 | 1 | 0 |
| WB | 寄存器写回路径 | 2 | 2 | 2 | 2 | 0 | 0 | 0 | 0 |
| top ibex_core excluded | 顶层 ibex_core 额外覆盖位；正式 common 口径主要排除顶层额外 MSB 56 bit | 5 | 5 | 5 | 5 | 0 | 0 | 0 | 0 |
| unknown | TOML/bitmap 中未能映射到具体模块的 padding/辅助覆盖点 | 6 | 6 | 6 | 6 | 0 | 0 | 0 | 0 |

两两差异的区域解释：

| 对比 | 左侧独有主要分布 | 右侧独有主要分布 | 说明 |
|---|---|---|---|
| baseline vs scheme5_pre | LSU/memory 17、ID/decode 7、IF/fetch 2、EX 1 | ID/decode 53、controller/trap/irq/debug 10、IF/fetch 8、CSR 6、EX 3 | `scheme5_pre` 的收益主要来自更稳定的取指/解码推进和低频控制流事件；baseline 的残留优势主要是随机 data bus 打到的 LSU 边界。 |
| baseline vs scheme6_relaxed_pre | ID/decode 14、LSU/memory 2 | ID/decode 30、controller/trap/irq/debug 10、IF/fetch 4、CSR 4、EX 1、LSU/memory 1 | `scheme6` 仍能扩大 decode/control/CSR 覆盖，同时比 `scheme5` 更少牺牲 LSU。 |
| scheme5_pre vs scheme6_relaxed_pre | ID/decode 39、IF/fetch 4、CSR 2、EX 2、controller 1 | LSU/memory 16、ID/decode 9、IF/fetch 2、controller 1、EX 1 | `scheme5` 更偏向 decode/control 覆盖最大化；`scheme6` 是放松版本，牺牲一部分 decode 增益，换回更多 memory/LSU 边界探索。 |

主要结论：

- 当前 6h 结果中，总覆盖排序是 `scheme5_pre` 506 > `scheme6_relaxed_pre` 487 > `scheme1_baseline` 453。
- 三者共同覆盖 416 点，说明基础执行路径高度重合。
- `scheme5_pre` 相对 baseline 多出来的覆盖点主要集中在 ID/decode、controller/trap/irq/debug、IF/fetch、CSR，符合“01 输入 bit 串约束让 core 更常进入正确状态并持续推进”的预期。
- `scheme6_relaxed_pre` 相对 `scheme5_pre` 少 19 个总覆盖点，但它在 LSU/memory 上有 16 个相对 `scheme5` 的独有点，说明放松约束确实恢复了一部分随机 memory 边界探索能力。
- 后续如果继续优化方案五/六，方向应该是保留 `scheme5` 的 fetch/decode/control 约束收益，同时把 LSU/memory 的随机边界能力从 `scheme6` 合回去。

明细文件：

```text
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/README.md
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/summary.json
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/three_way_area_distribution.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/three_way_module_distribution.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/baseline_only_vs_scheme5_pre.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/scheme5_pre_only_vs_baseline.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/baseline_only_vs_scheme6_relaxed_pre.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/scheme6_relaxed_pre_only_vs_baseline.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/scheme5_pre_only_vs_scheme6_relaxed_pre.csv
/home/qinkejiu/test/myfuzz/analysis/ibex_baseline_scheme5_scheme6_coverage_6h_20260616/scheme6_relaxed_pre_only_vs_scheme5_pre.csv
```

## 2026-06-19 Ibex + common IP multi-component target smoke

设计对象：

```text
configs/designs/ibex_multicomponent_ip/
```

远端运行位置：

```text
host: inner70
repo: /root/fanzehui/myfuzz
baseline run root: /root/fanzehui/myfuzz/runs/designs/ibex_multicomponent_ip_baseline_direct_slice
depaware run root: /root/fanzehui/myfuzz/runs/designs/ibex_multicomponent_ip_depaware_projection
```

target 组成：

```text
real ibex_core from third_party/rfuzz/upstream/ibex
+ instruction RAM model
+ data RAM model
+ timer
+ GPIO
+ UART
+ SPI
```

对照策略：

| scheme | 输入策略 | DUT feedback |
|---|---|---|
| `baseline_direct_slice` | 512-bit `rfuzz_input_bits` 固定切片直连到 wrapper 输入 | no |
| `depaware_projection` | 同一 512-bit raw input，经 manifest/source-derived CPU/bus/IP 依赖关系做组合投影 | no |

已完成阶段：

| stage | baseline | depaware |
|---|---|---|
| frontend | pass | pass |
| instrument | pass | pass |
| toml | pass | pass |
| harness | pass | pass |
| server build | pass | pass |
| 10s fuzz smoke | pass | pass |

覆盖口径：

| item | value |
|---|---:|
| instrumented HDL files | 36 |
| instrumentation coverage points | 1123 |
| generated harness coverage width | 1194 |
| macro | `IBEX_MCIP_COVERAGE_MSB=1193` |

10 秒 fuzz smoke 结果：

| scheme | queue_entries | crashes | first interesting input newly covered |
|---|---:|---:|---:|
| `baseline_direct_slice` | 1 | 0 | 122 |
| `depaware_projection` | 1 | 0 | 158 |

结论：

- 这次测试确认 Ibex + RAM/timer/GPIO/UART/SPI 的 multi-component target 可以在远端完成 RFuzz frontend 到 server/fuzz 的最小闭环。
- 两个方案使用同一 top、同一 instrumentation 设置、同一 coverage width、同一 512-bit input width。
- 10 秒 fuzz 只作为 smoke，不作为正式覆盖率结论；后续需要跑更长时间并按 common coverage bitmap 做稳定对比。
