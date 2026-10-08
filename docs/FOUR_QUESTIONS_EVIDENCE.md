# 四个问题的实证回答

日期：2026-10-08。本文回答四个具体问题：① 外设 IP 有没有"通用事件 01 串"的说明；② 为什么代码量这么大；③ 吞吐量为什么低、怎么提高；④ 时序怎么处理。所有数字都来自本仓库的源码扫描与真实运行产物，测量方法随文标注。

---

## 一、外设 IP 有没有通用的"事件 01 串"说明？

**结论：有协议层的契约，但没有 CPU ISA 那样的"通用事件语义层"。** CPU 与外设的抽象层级是不对称的，这一点在整个工程里是一致的。

### 1.1 CPU 侧：有 ISA 目录 + 约束 + 转导（声明式，可跨 CPU 复用）

| 组件 | 位置 | 内容 |
|---|---|---|
| CPU/ISA 目录 | `src/myfuzz/isa/profiles/*.json`（7 个：ibex、cv32e40p、cva6、boom、picorv32、rocket…） | `cpu_id`、`xlen`、`extensions`、原生/集成协议、源码状态、顶层模块 |
| 冻结记录 | `isa/model.py`（`CpuProfile`） | 不可变、可传递稳定的元数据 |
| 约束 | `isa/constraints.py`（`IsaContract`） | 合法指令/字段范围的契约 |
| 转导 | `isa/transducer.py` | 把契约编译成确定性 RFuzz 执行 |
| 指令解码 | `scenario/rv32i_sources.py` `decode_instruction_fragment()` | **12 字节熵 → 合法 RV32I 片段**（含 SLLI/SRLI/SRAI 与 MMIO 模板） |

所以"CPU 用 RISC-V 指令集"不是类比，而是**一份可被目录、约束和转导共同引用的声明**。

### 1.2 外设侧：两层声明，都不是"01 串语义"

**第一层：总线协议契约**（`src/myfuzz/protocols/plugins/*.json`，11 个）

| 文件 | protocol_id | 字段数 |
|---|---|---|
| `apb3.json` / `apb4.json` | `apb` | 8 / 10（`paddr`/`psel`/`penable`/`pwrite`/`pwdata`/`pready`/`prdata`…） |
| `axi4.json` / `axi4_lite.json` | `axi4` / `axi4-lite` | 29 / 19 |
| `obi.json` | `obi` | 7 |
| `tl_ul.json` | `tl-ul` | 23 |
| `wishbone.json` | `wishbone` | 10 |
| `ready_valid_memory.json` / `ready_valid_mmio.json` | — | 6 / 6 |
| `pipelined_completion_memory.json` / `processor_memory_beat.json` | — | 8 / 10 |

每个字段都声明 `field_id`、`direction`（host_to_device / device_to_host）、`width`（可用符号如 `address_width`）、`required`、`reset_value`。这一层确实是**通用的位级契约**——但它描述的是**总线信号**，不是"外设事件的 01 串"。

**第二层：每个外设自己的寄存器/事件契约**（`local_harness/*_contract.py` + `*_session.py`）

真实存在的契约：`opentitan_gpio_contract`、`opentitan_uart_contract`、`opentitan_uart_fifo_contract`（306 行）、`opentitan_spi_host_contract`、`opentitan_spi_device_contract`、`opentitan_i2c_contract`、`opentitan_rv_timer_contract`、`opentitan_sysrst_ctrl_contract`、`opentitan_pattgen_contract`、`pulp_gpio_probe_contract`、`pulp_spi_contract`、`ibex_rvfi_contract`、`ibex_irq_receipt_contract`、`uart_controlled_irq_contract`。每个都钉住：上游源码、实例 id、逐位端口边界、tuning、以及**该 IP 的观察语义**（例如 PULP GPIO 的 `raw_offset 8 = PADIN / 12 = PADOUT("out")`、UART 的 `offset 0x18 = RDATA`、RX watermark IRQ 类）。

**Fuzzer 看到的事件对象则是统一的**（`scenario/batch.py` 的 `BatchSourceEvent`）:

```text
component + port + bit_offset + width + value     ← 一个"源切片"
```

也就是说：**统一的是"源切片"这个概念，不统一的是"每个 IP 的切片语义"**。

### 1.3 真实证据：当前只有 4 个在线源声明

全仓库 `OnlineSource(...)` 只出现在两处 wiring（`grep -rn "OnlineSource(" src/myfuzz/scenario/*.py`）：

| wiring | 源 | kind | 切片 | 方向 |
|---|---|---|---|---|
| `ibex_pulp_dual_source.py:1712` | `cpu.online_instruction` | `instruction` | 指令槽 | `CPU_TO_IP_TO_CPU` |
| 同上 `:1714` | `gpio_b.external_pin8` | `source` | `gpio_in[8]`，1 位 | `IP_TO_CPU_TO_IP` |
| `ibex_uart_online.py:481` | `cpu.online_instruction` | `instruction` | 指令槽 | `CPU_TO_IP` |
| 同上 `:483` | `uart.external_rx_byte` | `source` | `uart_rx_byte`，8 位 | `IP_TO_CPU` |

每个源的声明里还带 `coverage_target_ids`（如 pin8 → `("gpio_b_irq", "cpu_external_irq_vector_fetch")`；UART RX → `("uart_rx_irq", "cpu_uart_vector_fetch")`），这就是"这个事件源能推进哪些目标"的显式依据。

### 1.4 为什么会这样（设计取舍）

| 若做成"通用 01 串语义" | 本工程的取舍 |
|---|---|
| 需要为一类外设约定统一的位含义（"bit0=FIFO 满"…），而真实 IP 的寄存器映射各不相同 | 改为**每个 IP 一个契约 + 一个 session**，契约里写死该 IP 的真实边界与语义 |
| 抽象层会掩盖真实 RTL 行为（例如"波形进行中不接受 TL-UL 访问"） | 保留真实约束，并把它变成**声明式拒绝**（`uart_waveform_gate`，`transport_idle`） |
| 新增外设只需填表 | 新增外设需要：源码契约 + session + 源声明 + 目标（约 100–400 行） |

**代价是诚实的**：新增一个外设比"填一张表"贵；**收益**是每个证据都能指到具体位与具体事件，不会被通用抽象悄悄近似。

---

## 二、为什么代码量这么大

先摆事实（本次扫描）：

| 类别 | 文件数 | 行数 |
|---|---|---|
| Python 源码 `src/myfuzz/` | 340 | **175,416** |
| 测试 `tests/`（671 个 test 文件） | 671 | **200,222** |
| 文档 `docs/`（含 221 份报告） | 364 | **50,122** |
| 门禁/分析脚本 `scripts/*.py` | 58 | **24,317** |

`scenario/` 层 118 模块的内部构成（按功能拆）：

| 功能 | 行数 | 说明 |
|---|---|---|
| 核心（会话/调度/内存/身份/决策） | 20,981 | `session_runtime` 1158、`runner` 2374、`source_actions` 2601、`online_case_decoder` 1486… |
| 证书与逐边证据 | 12,565 | 链证书 1381、UART 链 1906、逐边来源 2179、ISR 写回 1337… |
| 验收/阶段判定/对照 | 13,420 | P3 套件 1082+2897、P5 判定 2464、单臂 1434… |
| 各 IP 适配/wiring/样例 | 19,888 | 每个 IP 的 session、契约、示例 |

**为什么会长成这样（四个真实原因）：**

1. **验证代码量 ≈ 生产代码量**：`tests/` 200k 行 > `src/` 175k 行。每个判据都要有测试，而本工程的判据包括"身份不符必须拒绝""缺失必须是 `null` 不能是 0""拒绝码必须精确"——这些都要逐个断言。
2. **两条互斥的路线共存**：`composition/`（49.7k 行，历史 composed-SoC 路线：`soc_*.py` 一套自举程序/激励编译/结构审计）与 `scenario/`＋`integration/`（当前在线增量路线）。当前主线**不使用**前者，但两者共享源码事实与 profile 格式。这是最大的单块"看似冗余"。
3. **每个 IP 一套适配**：`local_harness` 64 个模块里，光契约类就有 14 个；`scenario` 里有 UART 系列 10 个模块、pin8 系列 4 个模块——因为每个 IP 的真实边界不同（见第一部分 1.4）。
4. **证据要能独立复算**：221 份报告 + 每份的复算脚本 + 只读分析器（`acceptance_metrics` 1722、`p5_arm_metrics` 1434、`report_*` 系列）。这些不是"业务逻辑"，但它们是本工程的核心产物。

**如果目标是缩小代码量，可控的削法是**（按收益排序，都需要先确认无引用）：
① 把历史 `composition/soc_*` 迁出主包或标记归档 → 最大一块；② 把"验收/对照"类模块合并成一个套件框架（P3/P4/P5 三套判定逻辑高度同构）；③ 把 14 个 `*_contract.py` 收敛成"契约描述 + 校验器"两个文件；④ 顶层 `harness/`、`experiments/` 若已无入口引用可删。

---

## 三、吞吐量为什么低、怎么提高

### 3.1 实测瓶颈：**`rtl_submit` 占 94.6%（GPIO）／96.8%（UART）**

用保存运行的逐例分项计时（`receipts.jsonl:online_phase_timing_seconds`），按"逐例求和"口径：

| 运行 | 例数 | `rtl_submit` p50 | `rtl_submit` 总和 | 每例总时长总和 | **占比** | `trace_digest` p50 | `interaction_ingest` p50 | checker/feedback/receipt |
|---|---|---|---|---|---|---|---|---|
| Ibex＋双 PULP GPIO | 24 | **1.234 s** | 30.572 s | 32.324 s | **94.6%** | 0.048 s | 0.015 s | < 1 ms |
| Ibex＋OpenTitan UART | 60 | **1.305 s** | 78.919 s | 81.567 s | **96.8%** | 0.024 s | 0.011 s | < 1 ms |

`rtl_submit` 不随例号增长（GPIO 前 10 例均值 1.218 s、后 10 例 1.324 s；UART 前后都是 1.238 s），说明**不是累积状态变慢，而是每命令固定成本 × 命令数**。

### 3.2 结构性原因：**每一条命令只推进一个本地 tick**

| 量 | GPIO | UART |
|---|---|---|
| 每例 `advances` | 32 | 96 |
| 每次调度的部件数 | 3 | 2 |
| **每例本地命令数** | **96** | **192** |
| 每例 `rtl_submit`（p50） | 1.234 s | 1.305 s |
| **折算每条命令**（`rtl_submit` 总和 ÷ 例数 ÷ 命令数） | **13.27 ms** | **6.85 ms** |

这个"每条命令的固定成本"是**文本行协议 + JSON 十六进制载荷 + 一次阻塞往返**（`local_harness/rtl/local_driver_v1.h`：`local_driver.v1`，命令上限 1,024 字节、载荷 JSON 上限 1 MiB、`STEP_*` 命令各推进一个 tick；宿主侧 `wire.py` 逐行解析并校验）。

**独立验证**：我另跑了一次最小探针（同 cache 的 RTL 会话，`scripts/profile_online_step_breakup.py`），测得

| 阶段 | 实测 |
|---|---|
| RTL 会话构造（prepare） | 9.92 s |
| 运行时契约声明 + `begin()` | 25.71 s |
| **bootstrap 例（1236 advances × 2 部件 = 2472 条命令）** | **1.299 s → ≈ 0.53 ms/命令** |
| **一个普通例（96 advances × 2 部件 = 192 条命令）** | **0.140 s → ≈ 0.73 ms/命令** |

两者都落在 **0.5–0.7 ms/命令**，与保存运行折算出的 6.8–12.9 ms/命令同量级（探针缺少 CLI 与部分记录器开销）。**结论：吞吐量低不是"仿真慢"，而是"每条 tick 都要一次主机往返"。**

### 3.3 怎么提高（按预期收益排序，含代价）

| # | 措施 | 预期收益 | 代价 / 风险 |
|---|---|---|---|
| 1 | **批量 tick**：驱动新增 `STEP_MANY n`（一次命令推进 n 个本地 tick，只回末态 + 需要的采样） | 命令数 ÷ n；按 n=32 估算，`rtl_submit` 可降一个数量级（1.23 s → ~0.1 s 级） | 需要改 C++ 驱动 + `driver_renderer` + 每个 session 的"哪些中间采样必须保留"声明；会改变 decode space 身份（旧 bundle 按设计不可 replay） |
| 2 | **二进制载荷替代 JSON 文本**：命令/回执改定长二进制帧 | 单命令成本降 2–5×（解析与 hex 展开消失） | 协议版本升级，所有 session 的解析层同步改 |
| 3 | **减少命令数本身**：把 `advances` 从 96 降到必要步数（用真实因果点而不是固定轮数） | 线性降低；UART 场景 96 轮里有大量空轮 | 需要证明"少步不影响观察"，属搜索语义变更 |
| 4 | **主机侧零拷贝**：`interaction_ingest` 与 `trace_digest` 已经是小头（各 < 5%），但仍可把 digest 移出热路径 | ~3–5% | 低风险 |
| 5 | **`session_declare_and_begin` 25.7 s 与 prepare 9.9 s 只在启动付一次** | 长跑时摊薄；短门禁里占大头 | 已有缓存（cache_dir）可用；短跑应复用 cache |

**注意**：措施 1–3 都会改动 decode space 或驱动协议，因此**会让已有 bundle 不可 replay**——按本工程的机制这是"如实的身份变化"，必须同时重录基线，而不是偷偷兼容。

---

## 四、时序是怎么处理的

四个要点，全部可在运行身份与报告口径里查到：

### 4.1 没有全局时钟，只有组件本地时钟

```text
每个 DUT 有自己的 clock_schedule（如 cpu: domain=core, frequency_hz=50_000_000, ratio=1）
一次 step() 只推进该 DUT 最快时钟一个完整周期
慢时钟按整数比 ratio 在 ratio//2 边界翻转；ratio 必须可整除且为偶数（≤1024），否则规划期拒绝
所有时钟从低电平开始；同一时刻的边沿在同一次 DUT 求值中观察
```

报告口径写明：`clock_model = independent_local_ticks_and_causal_order`、`record_semantics = mutation_decisions_not_dut_cycles`、`total_local_ticks_semantics = sum_of_independent_local_ticks_cost_only`——**tick 数是成本量，不是 DUT 周期数**。

### 4.2 跨组件时序靠"声明绑定 + 交付策略"，不靠共享周期

| 机制 | 谁决定 | 例子 |
|---|---|---|
| 物理绑定 | 声明（`bindings`） | `gpio_a.gpio_out → gpio_b.gpio_in`（宽 8） |
| IRQ 交付 | Runner 策略（`irq_pulses`） | `gpio_b.irq → cpu.irq`，`width_cpu_ticks: 4`、`overrun_policy: terminate_unsupported` |
| 交付时刻 | **每步按目标自己的下一个本地 tick 求值** | `_effective_inputs`: `value = policy.input_at(local_ticks[target] + 1)` |
| 顺序 | 声明调度序列 | `["cpu","gpio_a","gpio_b"]` / `["uart","cpu"]` |
| 因果顺序 | 事件序号（`event_id` 单调） | 所有 `join` 都按事件号/身份，不按时间戳 |

**含义**：中断不是"抢占"，而是在 CPU **下一次步进之前**按声明策略改变它的输入电平。

### 4.3 空闲等待必须显式声明并计入预算

"等 64 个 tick 再访问 UART"这类等待，是靠**声明轮数**实现的（`advances` / `max_steps`），不是靠轮询或真实时间。每多声明一个 tick 就多一条命令、多占预算（见第三部分：命令数直接决定耗时），所以"等多久"是被定价的。

### 4.4 时序相关的量都进身份或明确标注

| 量 | 去处 |
|---|---|
| 时钟比、初相位、复位映射、启动 tick 数 | 进 runtime artifact 身份（改了就换身份） |
| 每例 `local_ticks_before/after`、`total_local_ticks` | 进回执 |
| 分项耗时（`selection_decode`/`rtl_submit`/…） | 进回执（p50/p95 由套件聚合） |
| 墙钟预算 | `_ensure_wall_capacity` + 每步 deadline |
| 时钟推进的**副作用** | `_step_tick_bounds`：路由目标侧要走的 tick 也计入预算，所以 MMIO 路由不是免费的 |

---

## 一句话总结四个问题

1. **外设**：有 11 个总线协议契约（字段级、含方向/宽度/复位值）+ 每个 IP 一份寄存器/事件契约；fuzzer 侧统一的是"源切片（component+port+bit_offset+width+value）"，**没有**跨 IP 的通用事件语义层，这是刻意的取舍。
2. **代码量**：Python 175k + 测试 200k + 文档 50k；最大的"看似冗余"是历史 `composition/soc_*` 路线（≈50k）与"每个 IP 一套适配"，其次是验收/证书类模块——它们对应的是"证据要能独立复算"这条硬要求。
3. **吞吐量**：瓶颈是 `rtl_submit` 占 94.6%（GPIO）/96.8%（UART），根因是**每条命令只推进一个本地 tick**（每例 96/192 条命令，6.85/13.27 ms 每条命令）；先做的改进是**批量 tick（`STEP_MANY`）**，其次二进制协议、其次减少轮数——代价是 decode space 变更、旧 bundle 不可 replay。
4. **时序**：组件本地时钟（整数比、偶数、≤1024）+ 声明式绑定/IRQ 交付策略 + 事件号因果顺序；tick 明确是成本量；每步的输入电平按目标自己的下一个 tick 计算；空闲等待显式声明并计入预算。

---

### 附：本文的测量方法与原始产物

| 结论 | 测量方式 | 产物 |
|---|---|---|
| `rtl_submit` 占 95% | 读保存回执的 `online_phase_timing_seconds` 求 p50/p95/和 | `runs/current-dataflow-p5-chain-acceptance-20261007-online/receipts.jsonl`、`runs/p5-uart-routing-gate-20261008-online/receipts.jsonl` |
| 每命令 0.5–0.7 ms（探针） | 同 cache 起一次最小在线会话，分别计时 bootstrap 例与普通例 | `scripts/profile_online_step_breakup.py`；摘要 `runs/current-dataflow-p5-final-20261007-logs/step_breakup.json` |
| 命令数 96/192 | 读回执 `online_submit_timing_seconds.local_command_count` 与 `local_ticks` | 同上 |
| 代码量构成 | AST 扫描全部 `src/myfuzz/**.py` + `tests/` + `docs/` + `scripts/` | `runs/current-dataflow-p5-final-20261007-logs/module_inventory.tsv` |
| 协议/ISA 声明 | 读 `protocols/plugins/*.json`、`isa/profiles/*.json`、`*_contract.py` | 源码 |

> 诚实标注：第三节的"命令数 ÷ n 可降一个数量级"是**基于实测每命令成本的推算**，不是已实现的优化；本仓库目前**没有** `STEP_MANY` 之类的批量命令。探针运行只提交了 1 个成功用例（其余 raw 被解码器拒绝），因此"普通例 0.140 s"是单次观测，不是分布。
