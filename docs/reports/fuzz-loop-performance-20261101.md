# 单进程 fuzz 闭环性能报告（2026-11-01）

状态：**完成**（2026-11-01）。本报告只写本次实测的数字，全部来自
`runs/fuzz-opt-20261101/measurements.json`（schema `inprocess_fuzz_measurement.v1`）和同目录
`REPORT.md`（由 `scripts/measure_fuzz_phases.py` 渲染）。测量脚本、入口、C++ host、配置和
`src/` 都没有改动；新增的只有测量脚本、本报告和 `runs/fuzz-opt-20261101/` 下的运行产物。

口径：`total_seconds` 是入口自己的计时（含准备/构建/link）；`run_seconds` 是入口包住 host
进程的那一段；`preparation = total_seconds − run_seconds`；`fuzz.wall_seconds` 是闭环会话本身；
`fuzz.stats.dut_seconds`（= 每例 `case.seconds` 之和）是 host 自己量的 DUT 循环段，不含模型
构造/复位与用例间空隙；下面的"准备/会话/DUT"都按这个定义读。

## 1. 短答

- 这批 200 例 fuzz 的 **wall 中位数 6.552 s**，拆开是：解释器启动/退出 0.917 s +
  `total_seconds` 5.646 s；后者再拆成**准备 5.558 s**（其中 link 0.022 s）与
  **host 进程段 `run_seconds` 0.093 s**。也就是说，短批次里 **84.8% 的 wall 是准备**，
  DUT 推进只占 0.6%。
- 闭环本身很快：会话 wall 0.093 s，DUT 合计 0.036 s（占会话 39.6%），
  **2160 例/秒（会话口径）**；摊到整个进程 wall 只有 35.4 例/秒。
- **单例 DUT 中位数 0.166 ms，p95 0.394 ms**（host 侧每例 `case.seconds`，最慢 2.69 ms）；
  F1–F4 约 0.04–0.05 ms，F5/F6 约 0.16/0.19 ms。
- 固定输入（100 条记录、每臂 3 次、同一 cache）的事件层 A/B：`--quiet` 把 run.log 从
  **200 487 字节 / 5 017 行**降到 **44 030 字节 / 305 行**（−78% / −94%），100 个 case 的状态和
  两臂 ticks 合计（3 604）相同；host 进程段由 40.9 ms 降到 16.6 ms（差 24.3 ms，超过臂内极差
  2.2 ms）；但 **wall 差 −72 ms 小于臂内极差 280 ms，样本内分辨不出，不能叫 wall 加速**。
- 200 例全部执行，196 通过、4 失败（全部 F5 的观察判失败），状态
  `fuzz_completed_with_findings`；4 个失败是闭环的 finding，不是测量失败。9 次测量运行全部
  成功，没有被排除的 run。

## 2. 测量对象

| 项 | 内容 |
|---|---|
| 入口 | `scripts/run_inprocess_f1f6.py`（单进程 CPU+IP+DMA，`--fuzz` 闭环） |
| fuzz 配置 | `configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json`（4 字 F1 program 槽） |
| A/B 配置 | `configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json`（单字 F1 旧配置） |
| 组合 | Ibex RVFI（OBI） + PULP Timer（APB） + ZipDMA（Wishbone），一个 host tick 驱动 |
| cache | `runs/_probe/cache`，9 次运行全部 `link_cache_hit=true`；该目录是构建缓存，已随本轮临时产物清理，按 §7 命令重建后首次为冷缓存，数字按当时的热缓存口径读 |
| 机器 | AMD Ryzen 9 7945HX / 32 CPUs / Python 3.12.3 / WSL2 Linux 6.18.33.2；9 次运行的 1 分钟 load average 1.28–1.60 |
| 批次 | fuzz `--cases 200 --seed 20261101`，重复 3 次；A/B 100 条固定记录，每臂 3 次，`--max-ticks 200000` |
| 源码指纹 | 9 次运行记录相同：`c10cdd1617c7…`（campaign 时点的工作树；当时其它 agent 的改动已在树内） |
| 测量脚本 | 新增 `scripts/measure_fuzz_phases.py`（CLI，无 pytest） |

fuzz 的第 1 次重复和稳态（第 2–3 次）分开报：

| 重复 | wall (s) | total (s) | run (s) | link (s) | 准备 (s) | 会话 wall (s) | 用例（过/败） | ticks | DUT 合计 (s) | 例/秒（会话） | 例/秒（total） | DUT/会话 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|
| r1 | 6.547 | 5.646 | 0.087 | 0.022 | 5.558 | 0.087 | 200（196/4） | 39 152 | 0.034585 | 2299.7 | 35.4 | 39.8% |
| r2 | 6.552 | 5.631 | 0.093 | 0.021 | 5.537 | 0.093 | 200（196/4） | 39 152 | 0.036177 | 2160.3 | 35.5 | 39.1% |
| r3 | 6.705 | 5.788 | 0.096 | 0.022 | 5.692 | 0.095 | 200（196/4） | 39 152 | 0.037756 | 2100.0 | 34.6 | 39.6% |
| 稳态中位数（r2–r3） | 6.628 | 5.709 | 0.094 | 0.022 | 5.615 | 0.094 | 200（196/4） | 39 152 | 0.036967 | 2130.2 | 35.0 | 39.4% |

**首轮并不慢**：r1 的 wall 比稳态中位数低 0.082 s，三次都命中 link 缓存；本批没有"冷缓存
首轮"，0.16 s 的波动与构建无关（三次 link 都是缓存命中），只能归到进程启动/加载与机器负载。

## 3. 准备 vs DUT 推进（这批短批次的分法）

| 阶段 | 秒（3 次中位数） | 占 wall |
|---|---:|---:|
| 解释器启动 + 退出（`wall − total_seconds`） | 0.917 | 14.0% |
| 准备（`total_seconds − run_seconds`） | 5.558 | 84.8% |
| 　其中 link / cache 查找 | 0.022 | 0.3% |
| 　其中其余准备（导入、scope、模型请求、固件/绑定渲染、summary 写出） | 5.537 | 84.5% |
| host 进程段 `run_seconds` | 0.093 | 1.4% |
| 　其中闭环会话 | 0.093 | 1.4% |
| 　其中 DUT 循环（`dut_seconds`） | 0.036 | 0.6% |

- 准备是 wall 的主导项，且**不是** link：link 已全部命中缓存（0.022 s）。按入口代码，剩下
  5.54 s 覆盖进程启动、profile/artifact 请求、固件与绑定渲染、执行 scope 的进出和 summary
  写出（这些项目前没有逐项拆分，只作为准备的整体报告）。
- DUT 合计 0.036 s 只占 wall 的 0.6%；即使把 host 进程段全算上（0.093 s）也只有 1.4%。
- 200 例的 DUT 合计只有 0.036 s，所以在这批规模上多跑 case 对 wall 的贡献是毫秒级；
  这批的 35.4 例/秒（total 口径）主要不是闭环节奏，而是准备摊薄。

## 4. 每例 DUT 与闭环吞吐

| 重复 | DUT ms 中位数 | p95 | 最小 | 最大 | 每例 ticks 中位数 | host `runtime` (s) |
|---|---:|---:|---:|---:|---:|---:|
| r1 | 0.164 | 0.379 | 0.028 | 2.723 | 161 | 0.0801 |
| r2 | 0.166 | 0.394 | 0.029 | 2.274 | 161 | 0.0864 |
| r3 | 0.170 | 0.487 | 0.029 | 2.693 | 161 | 0.0898 |
| 中位数 | **0.166** | **0.394** | 0.029 | 2.693 | 161 | 0.0864 |

- 每例 DUT 毫秒 = `fuzz.json` 的 `cases[].case.seconds`（host 在 install 之后、打印 case 行
  之前计时），p95 用最近秩。
- `runtime − Σcase.seconds = 0.0864 − 0.0362 ≈ 0.050 s` 是模型构造/复位与用例间空隙的**上界**，
  不能算进 DUT。
- 按 flow（第 1 次重复；同一 seed 下三次重复的输入逐条相同）：

| flow | 用例数 | DUT ms 中位数 | p95 | 每例 ticks 中位数 |
|---|---:|---:|---:|---:|
| F1 | 23 | 0.041 | 0.082 | 39 |
| F2 | 22 | 0.038 | 0.078 | 34 |
| F3 | 29 | 0.039 | 0.117 | 38 |
| F4 | 20 | 0.045 | 0.112 | 45 |
| F5 | 11 | 0.160 | 2.723 | 148 |
| F6 | 95 | 0.185 | 0.464 | 231 |

- 闭环会话内部（3 次中位数）：generation 0.0115 s（12.4%）、parse 0.0043 s（4.7%）、
  feedback 0.0082 s（8.9%）、round-trip 0.0672 s（72.6%，含 DUT）、DUT 0.0362 s（39.6%）、
  会话内未归因 0.0014 s（1.5%）。round-trip 包含 DUT，不能和前三项相加。
- 语料/特征：corpus 151 条，distinct features 233；findings 4 条（全部 F5，见 §5 末）。
- 吞吐：**2160 例/秒**（会话口径，即闭环内每例约 0.46 ms 端到端）；**35.4 例/秒**（`total_seconds`
  口径）。

## 5. 事件层 A/B（固定输入）

固定 100 条记录（`F1:2ab00693`、`F2:00014000`、`F3:00014004:0badf00d`、`F4:40001008:0fffffff`
重复 25 次），同一 cache、同一 `--max-ticks 200000`；一臂默认事件层，另一臂加 `--quiet`；
两臂交替各跑 3 次。

| 臂 | 样本 | wall 中位 (s) | wall 范围 (s) | `run_seconds` 中位 (s) | CPU 中位 (s) | log 字节 | log 行 | ticks | DUT 合计 (s) | 100 个 case 状态 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `--online`（默认事件层） | 3 | 6.631 | 6.453–6.733 | 0.0409 | 6.348 | 200 487 | 5 017 | 3 604 | 0.027295 | 全部 `observations_passed` |
| `--online --quiet` | 3 | 6.559 | 6.546–6.696 | 0.0166 | 6.261 | 44 030 | 305 | 3 604 | 0.004213 | 全部 `observations_passed` |

run.log 行前缀计数（每臂第 1 次；`irq_*` 与声明前导行归入 other）：

| 臂 | case | ifetch | rvfi | retire | apb | cpu_* | dma_* | other |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| online | 100 | 1 715 | 1 261 | 1 261 | 25 | 450 | 0 | 205 |
| quiet | 100 | 0 | 0 | 0 | 0 | 0 | 0 | 205 |

对照（quiet − online，中位数；噪声带 = 两臂各自 wall/CPU/`run_seconds` 的极差取大）：

| 量 | 差 | 臂内极差 | 是否超过噪声 |
|---|---:|---:|---|
| wall | −0.072 s（−1.1%） | 0.280 s | 否 |
| CPU | −0.086 s | 0.242 s | 否 |
| `run_seconds` | −0.0243 s（−59%） | 0.0022 s | 是 |
| DUT 合计（`case.seconds`） | −0.0231 s | — | — |
| run.log 字节 | −156 457（−78%） | — | — |
| run.log 行 | −4 712（−94%） | — | — |

结论：

- **wall 上没有可主张的加速。** −72 ms 小于臂内 280 ms 的极差（每臂 3 次样本）；wall 的
  5.5 s 准备把 24 ms 的事件层差异淹没了。
- **可分辨的是日志体积与 host 进程段。** run.log 缩小 78%（行数 94%），`run_seconds` 从
  40.9 ms 降到 16.6 ms；两臂 ticks 合计相同（3 604），case 状态逐条一致，说明两臂做的是同一批
  工作，差的只是 4 712 行逐拍/逐传输事件的打印与转发。
- **DUT 合计的 23 ms 差不能读成 RTL 变快。** online 臂的 `case.seconds` 覆盖该例 tick 循环
  *连同*逐拍事件打印；quiet 臂关掉了这些行。fuzz 模式由入口固定加 `--quiet`，所以 §3/§4 的
  DUT 秒数不含逐拍打印。
- 噪声带只是 2–3 次样本的经验范围，不是置信区间；"没超过极差"只说明这批样本分辨不出。

失败用例：4 个失败全部是 F5（IRQ 观察判失败，`fuzz_completed_with_findings`），是闭环的
finding；200 例全部执行完，没有 host error、tick 预算截断或对应用例错配。

## 6. 这些数字说明什么、不说明什么

**说明**（本机、本组合、本 cache 状态、本批输入）：

1. 短批次 fuzz 的 wall 由每次进程的准备决定（5.558 s / 6.552 s = 84.8%），DUT 推进只有
   0.036 s；要评估闭环吞吐应按会话口径（2160 例/秒），按总 wall 会把准备算进"每例成本"。
2. 单例 DUT 中位 0.166 ms、p95 0.394 ms；F5/F6 明显更贵（0.16/0.19 ms、148/231 ticks），
   F1–F4 在 0.04–0.05 ms 量级。200 例中 95 例是 F6，这也是整体中位数高于 F1–F4 的原因。
3. 会话内部 generation/parse/feedback 合计约 0.024 s，远小于 round-trip 0.067 s；round-trip
   里 DUT 占 0.036 s，其余是 IPC/调度/写日志等未逐项分解的开销。
4. 事件层在固定输入上的代价是**可测的**：3 604 ticks、4 712 行日志、host 进程段 24 ms；
   在 wall 上不是可分辨的收益。
5. 第 1 次重复不比稳态慢（反而低 0.082 s），三次 link 缓存全命中；首轮差异在本批是负载波动。

**不说明**：

- 只有一个 CPU/IP/DMA 组合（Ibex RVFI OBI + PULP Timer APB + ZipDMA Wishbone）、一台机器
  （Ryzen 9 7945HX / WSL2）、一个 seed、200 例短批次、100 条固定输入；不能外推到别的组合、
  别的 seed 或长批次。
- 没有长跑内存/泄漏测量：只记录每次进程的 `maxrss`（中位数 138 312 KiB ≈ 135 MiB），没有随时间重复采样。
- 没有覆盖率结论：fuzz 只按观察到的 case 事实做反馈，`distinct_features=233` 是反馈特征数，
  不是 RTL 覆盖率。
- fuzz 模式没有 replay、没有 certificate（入口明示 `certificate=none`、
  `replay=not_performed`）；本报告也不评它们。
- 没有与其它入口（`run_inprocess_flow.py`、`run_inprocess_f1f4.py` 等）的横比。
- 测量期间机器 1 分钟 load average 在 1.28–1.60（其它 agent 也在跑），wall 的绝对值包含这份负载；
  事件层 A/B 的 wall 判定已按噪声带处理，但绝对秒数不应拿去做机器间对比。

## 7. 复现命令

在仓库根目录、同一时间只跑一个 RTL 运行：

```bash
python3 scripts/measure_fuzz_phases.py --cases 200 --repetitions 3
```

默认值即本次口径：`--config configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json`、
`--cache runs/_probe/cache`、`--output runs/fuzz-opt-20261101`、`--seed 20261101`、
`--ab-config configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json`、
`--ab-repetitions 3`、`--ab-max-ticks 200000`、`--fixed-records` 为 100 条记录。100 条记录可这样
原样生成：

```bash
python3 - <<'PY'
print(','.join(['F1:2ab00693,F2:00014000,F3:00014004:0badf00d,F4:40001008:0fffffff'] * 25))
PY
```

脚本内部对每次运行新建输出目录并调用现有入口；等价的单次命令（argv 也逐条记录在
`measurements.json` 的 `runs.*[].argv`）：

```bash
python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6-program.json \
  --cache runs/_probe/cache --output runs/fuzz-opt-20261101/fuzz-r1 \
  --fuzz --cases 200 --seed 20261101

python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json \
  --cache runs/_probe/cache --output runs/fuzz-opt-20261101/ab-online-r1 \
  --records '<100 条记录>' --online --max-ticks 200000

python3 scripts/run_inprocess_f1f6.py \
  --config configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json \
  --cache runs/_probe/cache --output runs/fuzz-opt-20261101/ab-quiet-r1 \
  --records '<100 条记录>' --online --max-ticks 200000 --quiet
```

只重渲染报告（不跑 RTL）：

```bash
python3 scripts/measure_fuzz_phases.py --report-only
```

产物：`runs/fuzz-opt-20261101/{fuzz-r1..r3,ab-online-r1..r3,ab-quiet-r1..r3}/`（每目录一份
`summary.json`、`fuzz.json`/`run.log`）、`runs/fuzz-opt-20261101/measurements.json`、
`runs/fuzz-opt-20261101/REPORT.md`。失败或被排除的 run：**无**（9 次运行状态均为
`fuzz_completed_with_findings` 或 `observations_passed`）。
