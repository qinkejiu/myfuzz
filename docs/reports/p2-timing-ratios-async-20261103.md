# P2 时钟：非整数比、更快模型、异步（2026-11-03）

本轮只改时钟轴（入口 `phase_clock_plan`/`clock_plan_*`/`CLOCK_*`、
`scripts/inprocess_phase_clock.h`、宿主相位调度与 per-model gate 区），不触碰
IRQ/F5、DMA、目标协议、cpu-only、ip-only 区域。证据目录
[`runs/p2-timing-20261103`](../../runs/p2-timing-20261103/README.md)（精确命令、
逐字 case/clockcase 行、非整数比会话、更快模型、异步结论、拒绝实录、与 p1 的
case 行 diff）。

## 1. 结论（四条，各有真实运行）

1. **非整数比按有理网格精确支持。** 一格 = `1 / (2 · lcm(声明频率))` 秒，于是
   每个声明半周期都是整数格：参考 CPU 半周期是 `C = L / cpu_hz` 格，声明 `f` Hz
   的模型恰好 `L / f` 格。50 MHz + 30 MHz 是 `C = 3`、`R = 5`（恰好 5/3 个 CPU
   半周期），一 tick = `2C = 6` 格。整除数会话 `C = 1`，数值与 p1 完全一致，这是
   回归逐字节不变的原因。
2. **比 CPU 更快的模型真的子步进。** `R < C` 时该模型自己的一整个半周期短于一
   tick，于是它在同一个 tick 内发生多次上升沿——仍是 `level (step // R) % 2`
   同一套调度，不是第二套机制，也不做任何取整。50 MHz + 60 MHz 在 300 MHz 网格上
   `C = 6`、`R = 5`：实测一个 F1 会话 119 次目标上升沿对 99 次 CPU 上升沿
   （1.202 ≈ 60/50）。
3. **无可用公共网格的异步对按名拒绝。** 32.768 kHz RTC 晶体配 50 MHz CPU，精确
   网格 12.8 GHz（RTC 半周期 390 625 格），远超 1024 格上限。拒绝文本给出精确
   网格、两侧格数，并写明本宿主没有回退：只用一张同步网格、未实现相位无关采样。
4. **对子步进更快模型的「总线流量」按名拒绝**（不是时钟）：宿主每 tick 只采样
   一次模型协议输出，而该模型整个 APB 访问窗口（`psel/penable` 两个自身周期 +
   下一沿清零的 `rsp_valid`）比一个 tick 还短（60 MHz 时 10 格 vs 12 格 tick），
   窗口可能整个落在两次采样之间。时钟照旧子步进并实测上升沿计数，传输不做任何
   声称。

## 2. 机制（自解释字段）

`clock_plan.json` 新增/改写的字段与宿主宏一一对应，plan、宏、宿主调度是同一份
归一化的三种渲染：

| 位置 | 内容 |
|---|---|
| `grid_lcm_hz` / `CLOCK_GRID_LCM_HZ` | `lcm(声明频率)`，一格 = `1/(2·它)` 秒 |
| `grid_steps_per_cpu_half` / `CLOCK_CPU_HALF_TICKS` | `C`，参考 CPU 半周期格数（p1 恒为 1，现在可为 3/6…） |
| `grid_steps_per_tick` / `CLOCK_GRID_STEPS_PER_TICK` | `2C`，一 tick 格数 = 恰好一个 CPU 周期 |
| 每行 `half_period_ticks` / `CLOCK_IP_HALF_TICKS` | `R`，该模型半周期格数 |
| 每行 `half_period_of_cpu_half` | `R/C` 的既约精确分式（`5/3`、`5/6`） |
| 每行 `first_rising_grid_step` | `R`，首次上升沿仍恰在自己半周期 |
| `contract` | 上述事实的一句话陈述（含 `level (step // R) % 2`） |

宿主侧 `static_assert(CLOCK_GRID_STEPS_PER_TICK == 2 * CLOCK_CPU_HALF_TICKS)` 把
「一 tick = 一个 CPU 周期」钉成编译期契约；`summary.clock_assumption` 逐字复述
网格、CPU 半周期格数、tick 格数、每模型格数与精确分式。

## 3. 精确 hunk 清单

`scripts/run_inprocess_f1f6.py`

| 函数/位置 | 行为变化 |
|---|---|
| import 区 | 新增 `import math`（`lcm`/`gcd` 用） |
| `_exact_ratio()`（新，3837） | `R/C` 既约分式 |
| `common_grid_hz()`（新，3843） | 声明频率的 lcm |
| `phase_clock_plan()`（3856） | 删除整数半周期比分支（含 `not an integer divider`、`faster than the reference CPU` 两条拒绝），改为精确 lcm 网格；每行新增 `half_period_of_cpu_half`；plan 新增 `grid_lcm_hz`/`grid_steps_per_cpu_half`/`grid_steps_per_tick`；网格越界（任一侧 > `MAX_PHASE_RATIO`）改为一条统一具名拒绝（保留 `phase-grid bound` 字样与两侧格数）；timed 检查改为「网格步必须是整数皮秒」+「各模型半周期 = 自己格数 × 网格步」；`equal_rates`/`assumed_single_clock` 两个分支保持原样，只补三个网格字段 |
| `clock_plan_header()`（4041） | 新增 `CLOCK_GRID_LCM_HZ`、`CLOCK_GRID_STEPS_PER_TICK`，`CLOCK_CPU_HALF_TICKS` 由常量 1 改为 `grid_steps_per_cpu_half` |
| `clock_assumption_text()`（4072） | 陈述改为「精确公共网格 … 每模型格数 … 精确分式 … 一格是什么」 |
| `faster_model_traffic_refusal()`（新，4133） | 见第 1 节第 4 条：记录路由到「快于参考 CPU」的目标/DMA 时给出具名拒绝（含两侧格数） |
| `render_bindings()`（4321、4329） | 两处新守卫：packed-AXI4 上 `C != 1` 按名拒绝；pin 组目标在 `C != 1` 按名拒绝（pin 跃变探针只在 tick 首个边界采样） |
| `main()`（8770 附近、9060 附近） | 固定记录路径与 fuzz 路径各一行调用 `faster_model_traffic_refusal` |

`scripts/inprocess_phase_clock.h`

| 成员 | 行为变化 |
|---|---|
| `phase_sample_gates(step, half, pending, window = 2u)` | 新增 `window` 参数（一 tick 的边界数 = `2C`），`trace` 改为「本 tick 窗口内任一边界有上升沿」；默认 2 与历史逐字等价；`probe` 保持「上一 tick 末边界或本 tick 首边界」（pin 采样点不变）；文档改为 lcm 网格与 `C > 1` 的语义 |

`scripts/inprocess_obi_apb_f1f4_spike.cpp`

| 位置 | 行为变化 |
|---|---|
| 相位常量块（4842-4844） | 新增 `kGridStepsPerTick = CLOCK_GRID_STEPS_PER_TICK` 与两条 `static_assert`；注释由「一格 = CPU 半周期」改为 lcm 网格 |
| `edge()` 非 AXI4 分支（5069） | 两次固定边界改为 `kGridStepsPerTick` 次循环（含 time advance）；`C == 1` 时逐字等价 |
| `device_tick()`（5357） | 同上两边界 → 循环 |
| tick 起始 gate（5715、5723） | IP/DMA 的 `phase_sample_gates` 传入 `kGridStepsPerTick` |
| 主 tick 体低/高半（6928、6940） | 低半插入 `C-1` 个子步（边界+eval+time advance），CPU 上升沿仍是低半最后一个边界；高半插入 `C-1` 个子步后再做既有的 `time advance`，本 tick 的寄存输出采样点不变；`C == 1` 时两个循环为空，case 行逐字节不变 |
| `clockcase` 行（9859） | 追加 `grid_steps_per_tick`、`grid_lcm_hz`（行尾追加，不改既有字段顺序） |
| `summary` 时钟块（10142） | 追加 `clock_grid_steps_per_tick`、`clock_grid_lcm_hz` |

配置（新文件/描述更正，均未改 pinned profile）

| 文件 | 变更 |
|---|---|
| `configs/peripherals/pulp_timer_32768hz_rtc/{component_profile.json,README.md}` | 新：32.768 kHz RTC 变体（同 RTL/修订/复位/引脚，只有声明频率不同），异步拒绝用 |
| `configs/peripherals/pulp_timer_30mhz/{component_profile.json,README.md}` | 描述由「永不运行」改为「P2 起在 150 MHz 精确网格上运行」，附证据路径 |
| `configs/peripherals/pulp_timer_60mhz/{component_profile.json,README.md}` | 同上，并写明「更快模型子步进可用、总线流量按名拒绝」 |
| `configs/scenarios/inprocess-obi-apb-rational-pair-f1f4.json` | 新：50 + 30 MHz（`C = 3`、`R = 5`） |
| `configs/scenarios/inprocess-obi-apb-rational-rate-timers-f1f4.json` | 新：50 + 30 + 60 MHz（`C = 6`，`R = 10/5`，含更快模型） |
| `configs/scenarios/inprocess-obi-apb-timer-async-grid-refusal.json` | 新：异步具名拒绝 |
| `configs/scenarios/inprocess-obi-apb-timer-timed-rational-refusal.json` | 新：timed 模型 + 非整数皮秒网格拒绝 |

## 4. 真实结果

| 行 | 内容 | 结果 |
|---|---|---|
| `pair-50-30-rational` | 50 + 30 MHz（`C=3`、`R=5`），F1/F2/F4/F3 | 4/4 passed；`clock_cpu_cycles 218`、`clock_target0_cycles 131`（131/218 = 0.601 vs 30/50） |
| `p1-fixture-nondivisor-now-runs` | p1 的 30 MHz 拒绝 fixture | 3/3 passed（原本按名拒绝） |
| `rational-two-targets-30-60` | 50 + 30 + 60 MHz（`C=6`、`R=10/5`） | 4/4 passed；`clock_cpu_cycles 218`、`target0 131`、`target1 262`（1.202 vs 60/50） |
| `p1-fixture-faster-now-substepped` | p1 的 60 MHz 拒绝 fixture | 1/1 passed；`cpu_cycles 99`、`target0_cycles 119` |
| 五条 p1 回归行 | 等速率 Ibex/CV32E40P、50/25/10、timed CPU、timed IP | 全部 `IDENTICAL`（见下） |
| `refusals/faster-target-traffic` | 记录路由到更快目标 | 非零退出，具名拒绝 |
| `refusals/async-grid` | 32.768 kHz RTC | 非零退出，具名拒绝 |
| `refusals/timed-rational-grid` | timed CV32E40P + 30 MHz | 非零退出，具名拒绝 |

30 MHz 目标的真实传输逐字（`case-lines.txt` 有全批）：

```
case 1 observations_passed flow F2 record F2:40001000 ticks 40 ... apb_reads 1 ... target0_reads 1 target0_ready 1 ... read_from apb apb_rdata 0x00000000
case 2 observations_passed flow F4 record F4:40001004:00000001 ticks 46 ... apb_offset 0x00000004 apb_pwdata 0x00000001 apb_pready 1 ... target0_last_data 0x00000001
```

## 5. 回归证明

`run.sh` 最后一步调用 `compare-p1.sh`，输出 `p1-case-line-diff.txt`：五条 p1 行
全部 `IDENTICAL`。判据是两条独立断言：每个 `case` 行去掉 `seconds` 后逐字节
相同；`clockcase`/`summary` 行去掉时间字段与本轮**新增**的两个网格字段后完全
相同（对不存在的字段做剥离是 no-op，因此也证明没有别的时钟字段漂移）。

## 6. 拒绝名变化表（改名的只有被能力取代的两条）

| 旧拒绝（p1） | 现状 | 处理 |
|---|---|---|
| `unsupported: declared clock rates differ (...); ... is not an integer divider ...` | 50:30、50:60 等有理比已支持 | **退役**；改为精确网格（`tests/integration/test_timing_capabilities.py::test_a_non_integer_ratio_is_placed_on_the_exact_common_grid` 重写） |
| `unsupported: <name> declares ... faster than the reference CPU ...; cannot sub-step` | 更快模型已子步进 | **退役**；改为 `test_a_model_faster_than_the_reference_cpu_is_sub_stepped` 重写 |
| `unsupported: ... above the 1024-step phase-grid bound`（半周期比） | 保留名称与 `phase-grid bound` 字样 | 文本改为「精确网格 + 两侧格数」，因为新的格数与「参考半周期」不再是同一个量 |
| `unsupported: timed phase grid: the reference CPU half period ... not a whole number of picoseconds` | 语义扩大 | 仍叫 `timed phase grid`，文本改为「公共网格步不是整数皮秒」，并附两侧格数 |
| （新）`unsupported-target-traffic:<name>:faster-than-reference-cpu: ...` | 新增 | 更快模型的流量拒绝 |
| （新）`unsupported: rational phase grid on the packed-axi4-clock-path` | 新增 | packed AXI4 上 `C != 1` |
| （新）`unsupported: pin-group target on a rational phase grid` | 新增 | pin 组 + `C != 1` |
| `unsupported: timed model on the packed-axi4-clock-path`、`unsupported: timed models declare different half periods`、`unsupported: timed contract disagrees ...` | 未改 | 保留原文 |

## 7. 测试

```sh
PYTHONPATH=src:. python3 -m pytest tests/integration/test_p2_timing_ratios.py -q   # 13 passed
PYTHONPATH=src:. python3 -m pytest tests/integration/test_timing_capabilities.py -q # 22 passed
PYTHONPATH=src:. python3 -m pytest tests/integration/test_inprocess_f1f6_entry.py -q # 196 passed
```

`test_p2_timing_ratios.py`（13 个）：lcm 网格与整除数不回归、有理比精确分式、
更快模型子步进、`faster_model_traffic_refusal` 的两类记录、异步拒绝（两个方向）、
timed 网格拒绝、不取整/不半驱动、头文件三宏、`clock_assumption_text` 分式、
编译 `inprocess_phase_clock.h` 走真实调度算术（10 tick 内 10/15/6/12 个上升沿，
以及 1..40 tick 的计数恒等式）、tick 窗口对慢模型「每周期一次采样」、以及读取
`runs/p2-timing-20261103` 的实测计数（缺证据时 skip）。

改写/更新的既有测试：`test_timing_capabilities.py` 两条（退役拒绝 → 新能力）、
`test_inprocess_f1f6_entry.py::test_a_clock_rate_mismatch_is_normalized_or_refused_by_name`
（不再拒绝，改为断言 `CLOCK_GRID_LCM_HZ 150` / `CLOCK_CPU_HALF_TICKS 3` /
`CLOCK_IP_HALF_TICKS 5` / `CLOCK_DMA_HALF_TICKS 150`）、
`tests/fuzz/test_new_ip_2_onboarding.py` 的 inventory 计数 19 → 20（新增 RTC 变体；
该文件另有一条 `caliptra_sha256/ahb-lite` 失败是 C 代理 AHB 能力变化造成的陈旧
期望，与本轮无关）。

## 8. 仍需别人配合（未越界的部分）

1. **更快模型的协议观测**：要把 `unsupported-target-traffic` 变成能力，需要把
   `scripts/inprocess_obi_apb_f1f4_spike.cpp` 里四个协议 trace 采样块（APB3 约
   6900 行前、AXI4-Lite、Wishbone、TL-UL，均由 `ip_trace_now`/`ip_response_now`
   门控）抽成可从 tick 子步循环内调用的 lambda，即「每个模型上升沿采一次」。这些
   块正被 C（AHB 目标）与 D（IRQ 采样）同时扩展，本轮不动。
2. **p1 证据脚本**：`configs/scenarios/inprocess-obi-apb-timer-nondivisor-ratio-refusal.json`
   与 `...-faster-model-refusal.json` 我**未改动**（文件名与内部 name 仍带
   "refusal"），所以 `bash runs/p1-timing/run.sh` 现在会把这两行记为 unexpected
   pass。是否重命名/退役这两个 fixture 与 p1 run.sh 的期望，由父代理统一决定
   （`runs/p1-timing/README.md` 的两条拒绝为历史记录）。
3. **pin 组 + 有理网格**：E1 若把 pin 探针改成「每模型周期采样」，可以撤掉
   `render_bindings` 里那条守卫。
4. **DMA 更快模型**：若 E2 的 DMA 路由声明的目标快于参考 CPU，`F6` 记录会被
   `faster_model_traffic_refusal` 拒绝；要放开同样需要第 1 条的按沿采样。
5. **索引行**：按并发纪律我没有编辑 `docs/reports/README.md`，行文本见回给父
   代理的消息。

## 9. 限制（本轮不声称）

- 无覆盖率/证书/replay 声称；取指不是退休，APB 完成不是 CPU 提交。
- 更快模型的**时钟**子步进是真实能力并有实测；其**协议流量**不声称。
- timed 模型不能进入非整数皮秒网格；30 MHz 模型若自身声明 `timing` 会更早在
  artifact 构建阶段被 `timed-clock-half-period-not-integral-picoseconds` 拒绝。
- pinned RTL 不调度延迟事件（`grep 'assign #'` 为空），timed 运行只声称 timed
  构建/链接与 `TIMED_GRID_PS` 推进，不声称事件次序。
- `clockcase`/summary 的时钟字段是宿主实际施加的沿计数，不是对 RTL 内部时钟的
  独立测量。
