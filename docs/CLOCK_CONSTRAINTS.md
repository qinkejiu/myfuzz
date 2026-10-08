# 时钟约束是怎么得到的

日期：2026-10-08。本文只回答一个问题：**一个 DUT 的时钟/复位约束从哪里来、长什么样、谁校验、怎么变成仿真行为、怎么被验证。** 每一步都指到具体文件与行号，并用本仓库真实 profile 与实际运行产物举例。

> 时序的整体处理见 [四个问题的实证回答](FOUR_QUESTIONS_EVIDENCE.md) 第四节；单组件多时钟的概述见 [系统说明](SYSTEM_OVERVIEW.md) §3.2。

---

## 0. 一句话回答

> **时钟约束不是被测 RTL 自己报出来的，也不是系统猜的**：它由**人写的 profile 声明**（端口 → 域 → 频率、复位端口 → 极性/同步性），加上**请求里显式给出的复位 tick 数**，一起交给规划阶段的校验器；校验器把它编译成一份 `local_clock_schedule.v1` 文档，这份文档既生成 driver 的时钟翻转代码，又成为运行身份的一部分。

```text
配置（人写）                请求（人写）                  校验与编译                    执行与验证
configs/**/component_profile.json    local_harness.v1 请求      clock_schedule.py           driver_renderer.py
  clocks[]: port/domain/frequency     reset_assert_ticks         （5 类拒绝）                 → C++ 时钟翻转
  resets[]: port/domain/polarity      reset_release_ticks        local_clock_schedule.v1     wire.py（边沿数核对）
                                      max_wait_cycles            → 进 runtime artifact 身份   report.json（口径声明）
```

---

## 1. 第一步：人写配置 —— 频率从哪里来

`configs/**/component_profile.json` 里两个字段：

```json
// configs/cpus/ibex_obi_local/component_profile.json
"clocks": [{"port": "clk_i", "domain": "core", "frequency_hz": 50000000}],
"resets": [{"port": "rst_ni", "domain": "sys_rst", "polarity": "active_low",
            "synchronous": false,
            "release": "rst_ni is the single active-low asynchronously asserted reset of ibex_top (rtl/ibex_top.sv:318,632,642); ..."}]
```

```json
// configs/peripherals/pulp_gpio_causal_local/component_profile.json
"clocks": [{"port": "HCLK", "domain": "core", "frequency_hz": 50000000}],
"resets": [{"port": "HRESETn", "domain": "sys_rst", "polarity": "active_low",
            "synchronous": false,
            "release": "RTL asynchronously asserts active-low reset; release must satisfy HCLK recovery/removal timing."}]
```

字段定义在 `src/myfuzz/composition/component_profile.py`：

| 记录 | 字段（`:276`、`:283`） |
|---|---|
| `ClockBinding` | `port`、`domain`、`frequency_hz` |
| `ResetBinding` | `port`、`domain`、`polarity`（`active_high`/`active_low`）、`synchronous`、`release`（**人写的文字依据，指到 RTL 行号**）、`sequence_after`（有序复位依赖） |

**三个关键点**：

1. **频率是声明值，不是实测值**。当前没有任何"从 RTL 或波形反推频率"的机制；频率来自 profile，profile 由人对着真实 RTL 写，`release` 字段要求写清依据（如上面引到 `ibex_top.sv:318,632,642`）。
2. **域（domain）是名字，不是端口**。同一个域可以有多个端口；但规划器**要求域唯一**（`duplicate_clock_domain`）。
3. **复位也按时钟域组织**：`synchronous` 标明同步/异步，`polarity` 标极性；`sequence_after` 一旦声明就**拒绝运行**（见 §3 第 5 条）。

**当前仓库的真实分布**（本次扫描 38 个带 clocks 的 profile）：

| 频率比组合 | profile 数 | 例子 |
|---|---|---|
| 单域（ratio=1） | 35 | ibex（50 MHz）、PULP GPIO（50 MHz）、多数 OpenTitan IP |
| `(1, 120)` | 2 | OpenTitan `sysrst_ctrl`（core 24 MHz + aon 200 kHz） |
| `(1, 5)` | 1 | OpenTitan `spi_device`（core 50 MHz + spi 10 MHz） |

---

## 2. 第二步：人写请求 —— 复位 tick 数从哪里来

时钟频率不够，还需要"复位拉多久、放开后等多久"。这些是**请求里的显式数字**（`local_harness.v1`，字段见 `src/myfuzz/local_harness/request.py:14`）：

```python
# src/myfuzz/scenario/ibex_pulp_dual_source.py:246-253  —— 真实 wiring 的写法
request = load_local_harness_request({
    "schema_version": "local_harness.v1",
    "profile_path": profile_path,
    "instance_id": instance_id,
    "reset_assert_ticks": 8,
    "reset_release_ticks": 8,
    "max_wait_cycles": 16,
})
plan = plan_local_harness(request, base_dir=ROOT)
```

这三个数的含义（`clock_schedule.py:24` 与 `driver_renderer.py`）：

| 字段 | 含义 | 单位 |
|---|---|---|
| `reset_assert_ticks` | 复位保持多少个 tick | **最快域** tick |
| `reset_release_ticks` | 释放后再等多少个 tick 才 READY | **最快域** tick |
| `max_wait_cycles` | 一条命令最多等多少个周期（命令期限） | 最快域 tick |

真实运行产物里能看到它们落在身份里（`runs/p5-uart-routing-gate-20261008-online/online_session_manifest.json`）：

```json
"plan": {"timing": {"max_wait_cycles": 16, "reset_assert_ticks": 8, "reset_release_ticks": 8}},
"driver_reset": {"reset_assert_ticks": 8, "reset_release_ticks": 8, "schema_version": "generated_local_reset.v1"},
"clock_schedule": {"startup_fast_ticks": 16, "fast_frequency_hz": 50000000,
                   "primary_clock_domain": "core", "primary_reset_domain": "sys_rst",
                   "phase_policy": "all_low_then_half_period_toggle",
                   "clock_edges_observed": "rising_edges_since_ready",
                   "clocks": [{"domain":"core","signal":"clk","frequency_hz":50000000,
                               "ratio":1,"half_period_fast_ticks":1,"first_rising_fast_tick":1}],
                   "resets": [{"domain":"sys_rst","port":"rst_ni","signal":"reset",
                               "polarity":"active_low","synchronous":false}]}
```

`startup_fast_ticks = reset_assert_ticks + reset_release_ticks = 8 + 8 = 16`（`clock_schedule.py:118`）。

---

## 3. 第三步：校验与编译 —— 五类拒绝

`build_local_clock_schedule()`（`src/myfuzz/local_harness/clock_schedule.py:14`）在**规划阶段**（`plan.py:126`）执行，规则是硬的，违反即在任何 RTL 之前失败：

| # | 规则 | 违反时的错误 | 代码行 |
|---|---|---|---|
| 1 | clock 与 reset 都必须声明 | `...:clock-reset-required` | `:28` |
| 2 | 频率必须是正整数；端口/域必须是合法标识符 | `frequency_must_be_positive` / `invalid_clock_identity` | `:39-43` |
| 3 | 端口与域都不得重复 | `duplicate_clock_port` / `duplicate_clock_domain` | `:44-49` |
| 4 | 同一域的频率必须一致 | `conflicting_domain_frequency` | `:50-52` |
| 5 | **最慢域必须整除最快域，且比值要么是 1 要么是偶数，且 ≤1024** | `non_integral_ratio` / `odd_ratio` / `ratio_exceeds_limit` | `:61-67` |
| 6 | `reset_assert_ticks` 必须 ≥ 最慢域的半个周期（否则慢域采不到复位边沿） | `reset_edge_not_sampled` | `:69-70` |
| 7 | 声明了有序复位依赖（`sequence_after`）直接拒绝 | `local-reset-sequence-unsupported` | `:94-95` |

**编译结果**（`local_clock_schedule.v1`，`:111-121`）里每个域得到四个数：

```text
ratio                  = fast_frequency_hz // frequency           （本域多少最快 tick 一个周期）
half_period_fast_ticks = ratio（ratio=1）或 ratio//2（否则）        （每隔多少 tick 翻转一次）
first_rising_fast_tick = half_period_fast_ticks                   （首个上升沿位置）
signal                 = "clk"（最快域）或 "clk_<domain>"          （渲染出的信号名）
```

外加四条全局声明：`fast_frequency_hz`、`primary_clock_domain`（最快域字典序第一个）、`phase_policy="all_low_then_half_period_toggle"`（所有时钟从低电平开始）、`clock_edges_observed="rising_edges_since_ready"`。

### 3.1 真实例子：`sysrst_ctrl` 的 24 MHz + 200 kHz

```text
profile: core 24 MHz, aon 200 kHz        →  fast=24 MHz, ratio_aon = 24000000/200000 = 120 ✔ 偶数且 ≤1024
half_period_aon = 60                     →  aon 每 60 个最快 tick 翻转一次
reset_assert_ticks 必须 ≥ 60             →  否则报 reset_edge_not_sampled（慢域采不到复位）
```

`docs/LOCAL_HARNESS_RUNTIME.md` 对该场景的记录正是这样：*"RTL 的 24 MHz core 与 200 kHz AON 各自推进，比例为 120；只用 DUT 本地 tick 表达延迟，不模拟全局 SoC cycle"*。

### 3.2 真实例子：`spi_device` 的 10 MHz 被拒绝（诚实点名的限制）

我对 `configs/peripherals/opentitan_spi_device/component_profile.json`（core 50 MHz + spi 10 MHz）实际跑了一遍规划器：

```text
$ plan_local_harness(request, ...)
REFUSED: ValueError local-clock-schedule-unsupported:odd_ratio
```

**原因**：`ratio = 50/10 = 5` 是奇数，被规则 5 拒绝（偶数比是"每个最快 tick 内恰好一个完整低-高循环、慢域边沿落在固定相位"这一实现的硬前提）。

**但 SPI Device 的真实运行是存在的**——它走的是**专用 session**（`src/myfuzz/scenario/spi_device_session.py`，自建二进制、自己在命令里驱动 `sck_i/csb_i/sd_i` 并在 local tick 里更新），**不经过** `plan_local_harness → build_local_clock_schedule` 这条通用生成链，因此这个 1:5 声明从未被规划器校验。

**这是一条应当点明的边界**：`clocks[]` 里写进一个"外部引脚被当作时钟域"的条目，在通用生成路径上会导致该 profile 不可用；当前没有通用的"外部时钟源旁路"机制，只能改 profile（如去掉该域，或用专用 session）。

---

## 4. 第四步：约束怎么变成仿真行为

校验后的 schedule 被交给 driver 渲染器（`driver_renderer.py:627` 读入并校验 schema；`:670-693` 生成代码）：

```cpp
// 生成的 C++（示意，来自 driver_renderer.py 的模板）
static std::uint64_t fast_schedule_ticks = 0;
// 最快域：每个本地 tick 恰好一个完整低→高→低周期
if (next_fast_tick % <half_period>ULL == 0) { dut.clk_<domain> = !dut.clk_<domain>;
                                             if (dut.clk_<domain>) ++<domain>_edges; }
```

| 情形 | 生成的行为 | 代码 |
|---|---|---|
| 最快域 | 每个 tick 一个完整低/高循环，恰有一个上升沿 | `:670-676` |
| 同频异域（ratio=1） | 各自是独立 wire，每个 tick 各一次完整循环，并**分别计数** | `:677-684` |
| 慢域（ratio>1，偶数） | 每 `half_period_fast_ticks` 个 tick 翻转一次，上升沿计数 | `:685-693` |
| 复位 | 按 `reset_assert_ticks`/`reset_release_ticks` 同时断言与释放；每域必须已收到上升沿才 READY | `:937`、`:953` |

**关键语义**：一次宿主命令（`STEP_*`）只推进**最快域一个 tick**；慢域在该 tick 内**只在固定相位翻转**，不插入额外求值。这就是"没有全局周期"的实现层含义。

---

## 5. 第五步：约束怎么被验证（两层）

**第一层：宿主侧形状与边沿数核对**（`src/myfuzz/local_harness/wire.py`）

```python
rows, startup = _clock_rows(schedule)        # :100-118 —— 逐条检查 schema、域唯一、ratio≥1、首个上升沿≥1
def _clock_edges_through(row, fast_tick):    # :121-127
    return 0 if fast_tick < row['first_rising_fast_tick'] else \
           1 + (fast_tick - row['first_rising_fast_tick']) // row['ratio']
```

即：**宿主用声明的频率算出"到第 t 个最快 tick 时该域应有多少个上升沿"，再与 DUT 实际报告的值比较**（driver 每个样本都附带 `clock_edges`）。这是"声明"与"真实信号"之间唯一的对照点。

**第二层：身份绑定**

`clock_schedule` 整份文档（含 `ratio`/`half_period`/`first_rising`/`startup_fast_ticks`/`phase_policy`）进入 runtime artifact，进而进入：

- `online_session_manifest.json`（per-component 身份）
- `online_run_identity.json`（运行身份；`decode_space` 里含相关源码文件）

**改一个频率或一个 tick 数，就是一次身份变更**——旧 bundle 的 replay 会被拒绝，这与"变异依据被记录"是同一套机制。

**第三层：口径声明**（`report.json`）

```json
{"clock_model": "independent_local_ticks_and_causal_order",
 "record_semantics": "mutation_decisions_not_dut_cycles",
 "total_local_ticks_semantics": "sum_of_independent_local_ticks_cost_only"}
```

即：报告里所有 tick 数都是**成本量**，不是 DUT 周期数，也不是仿真时间。

---

## 6. 时钟约束会影响什么（下游可见后果）

| 影响 | 说明 |
|---|---|
| 搜索预算 | 每例的 `advances` × 部件数 = 本地命令数（GPIO 96、UART 192），而**每条命令只推进一个最快 tick**；所以 tick 数直接决定耗时与吞吐 |
| 路由开销 | `_step_tick_bounds` 会把**路由目标侧要走的 tick** 也计入资源预算，所以 MMIO 不是"零时间" |
| 空闲等待 | "等 64 个 tick 再访问 UART"这类等待必须显式声明轮数（无法用真实时间等待） |
| 慢域采样 | 慢域上的信号只能在其上升沿被采样；`reset_assert_ticks` 不足会在规划期就被拒绝 |
| 证据粒度 | 事件带 `local_tick`（该组件自己的），跨组件对齐**不用时间戳**，只用事件号与身份 |
| 旧 bundle | 频率/复位/tick 任一改动 → 运行身份变化 → 旧 replay 按设计被拒 |

---

## 7. 常见误解对照

| 误解 | 实际 |
|---|---|
| "系统会从 RTL 或波形量出时钟频率" | ❌ 频率是 profile 里的声明值，人对着 RTL 写，没有反推机制 |
| "所有 DUT 共享一个时钟" | ❌ 每个 DUT 独立时钟域；只有因果顺序（`event_id`）被保证 |
| "慢时钟会被插值求值" | ❌ 慢域只在固定相位翻转，不做子周期求值 |
| "复位是全局同时释放" | ✅ 同时断言/释放，但每域必须自己采到上升沿；声明了有序释放依赖则直接拒绝运行 |
| "tick 数可以当周期数比较" | ❌ 报告明确是 `sum_of_independent_local_ticks_cost_only` |
| "任意频率比都行" | ❌ 必须整除、比值 1 或偶数、≤1024；违反在规划期拒绝 |

---

## 8. 一句话总结

> **时钟约束 = profile 里人写的 `clocks[]`/`resets[]`（端口→域→频率、极性、同步性、释放依据）＋ 请求里人写的三个 tick 数（assert/release/max_wait）**；`clock_schedule.py` 在规划阶段做 7 类校验并编译成 `local_clock_schedule.v1`，`driver_renderer.py` 把它变成真实的时钟翻转代码，`wire.py` 用声明的频率去核对 DUT 报告的边沿数，整份 schedule 进运行身份。
> 没有任何一步在"猜"——**要么配置里写明，要么在规划阶段被拒绝**。

---

### 附：本文的取证位置

| 结论 | 位置 |
|---|---|
| 声明字段 | `src/myfuzz/composition/component_profile.py:276,283`（`ClockBinding`/`ResetBinding`）、`configs/**/component_profile.json` |
| 请求字段 | `src/myfuzz/local_harness/request.py:14`；真实 wiring `src/myfuzz/scenario/ibex_pulp_dual_source.py:246-253` |
| 校验与编译 | `src/myfuzz/local_harness/clock_schedule.py:14-121`（7 类拒绝、`ratio`/`half_period`/`first_rising` 的算法） |
| 规划期调用 | `plan.py:126`、`port_rendering.py:59`、`runtime_renderer.py:138,241` |
| 生成时钟行为 | `driver_renderer.py:627`（读入校验）、`:670-693`（翻转与边沿计数）、`:937,953`（复位） |
| 边沿核对 | `wire.py:100-127` |
| 真实身份产物 | `runs/p5-uart-routing-gate-20261008-online/online_session_manifest.json`（`clock_schedule`、`plan.timing`、`driver_reset`） |
| 多域真实例子 | `configs/peripherals/opentitan_sysrst_ctrl_local/component_profile.json`（1:120）；`docs/LOCAL_HARNESS_RUNTIME.md` 的 sysrst_ctrl 场景说明 |
| 奇数比被拒 | 本次实测：对 `configs/peripherals/opentitan_spi_device/component_profile.json` 调 `plan_local_harness` → `local-clock-schedule-unsupported:odd_ratio` |
