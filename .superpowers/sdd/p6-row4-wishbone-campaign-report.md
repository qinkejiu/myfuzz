# P6 行 4（classic Wishbone）真实 campaign 实现报告

日期：2026-10-17。范围：`docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md` 行 4
（**classic Wishbone ｜ 首选 CPU：PicoRV32 Wishbone ｜ 首选 IP：OpenTitan GPIO**），
以及 `docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md` P6 段。

> **状态口径（不得越过）：** 本轮交付的是**可运行实现 + 真实 RTL 单例/单格证据**。
> **18 格 campaign 尚未运行**——协调方决定等所有源码代理停写、根代理冻结源码后，
> 由根代理在 heavy lock 下串行执行（原因：任何 host-source 变更都会让 18 格 campaign 的
> build identity 失效）。因此本报告**不宣称** P6 行 4 通过、**不宣称**整个 P6 通过。
> 单格 smoke 不是 18 格 campaign 证据；定向测试也不是。

---

## 1. 交付物（本次提交）

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/picorv32_wb_two_gpio_example.py` | 真实 RTL 场景夹具：pinned `picorv32_wb_irq` + **两个** pinned `opentitan_gpio_local` 实例；双向两轮程序（含 Pico custom0 IRQ handler）、ownership、bindings、per-case runner 对 |
| `src/myfuzz/integration/picorv32_wb_scenario_campaign.py` | `PicoWbGpioBoundProvider`（三策略共用同一真实 pipeline）、闭环 checker `assess_pico_wb_closed_chain`、独立 saved-run 审计 `audit_campaign_run`/`audit_campaign_cell` |
| `configs/scenario/pico_wb_two_gpio_campaign_seed.json` | CPU 方向 bound seed Genome（image + 一个外部 pin 源） |
| `configs/scenario/pico_wb_two_gpio_reverse_seed.json` | IP 方向反向 seed Genome（4 个真实引脚动作） |
| `configs/scenario/pico_wb_two_gpio_independent_cpu_seed.json` | independent baseline（CPU 方向）seed |
| `configs/scenario/pico_wb_two_gpio_independent_ip_seed.json` | independent baseline（IP 方向）seed |
| `configs/scenario/pico_wb_two_gpio_campaign_baseline.json` | independent baseline manifest（shadow 窗口、无跨组件绑定、`cpu_irq=constant_zero`） |
| `tests/integration/test_scenario_picorv32_wb_campaign.py` | 程序/源形状、checker 逐阶段负例、旧组件负例、provider 守卫、saved-run 审计（合成 bundle + 真实 bundle 可选） |
| 本报告 | 命令、结果、证据、未覆盖范围 |

**没有修改** Runner / Router / mutator / scheduler / `scenario_campaign.py` / gate；
provider 仅继承 `IbexTwoGpioBoundProvider` 的 `search`/`replay` 外形。

本地未提交（`/.superpowers/*` 按仓库约定忽略，除 `.superpowers/sdd`）的运行证据：

- `.superpowers/p6-row4/probe-*.json`：单例 checker 复算结果（两方向）
- `.superpowers/p6-row4/smoke/smoke__*__seed_20260927/`：**单格 campaign 原始产物**
  （`live/receipts.jsonl`、`live/corpus/`、`chain_checks.jsonl`、`live/run_identity.json`、`seed_genome.json`）
- `.superpowers/p6-row4/smoke/smoke-*.json`：单格汇总

---

## 2. 夹具：真实双 GPIO + Pico Wishbone + custom0 IRQ

### 2.1 组件与接线

- CPU：`configs/cpus/picorv32_wb_irq/component_profile.json`（`ENABLE_IRQ=1`），
  经 `GeneratedWishboneCpuSession`；`defer_mmio=False`（与行 3 的 AXI4-Lite 夹具同口径：
  被路由的 beat 在同一 step 内联应答，tick 成本由会话自身声明）。
- IP：`configs/peripherals/opentitan_gpio_local/component_profile.json` ×2，
  经 `GeneratedOpentitanGpioSession`；`gpio_a` @ 0x4000_1000、`gpio_b` @ 0x4000_0000。
- 路由：`gpio_a.gpio_out[0:8]` → `gpio_b.gpio_in[0:8]`（真实输出引脚 → 真实输入引脚；
  不是 Python 侧赋值）。
- 中断：`gpio_b.irq` 的 **4 个不同 pending 位**分别绑定到 CPU 32 位 custom IRQ 输入的
  bit 3/4/5/6。**为什么不是同一位两轮**：pinned 核的 `LATCHED_IRQ` 默认为全 1，
  被 mask 的 pending 位只在 deassert 的 state 里按 mask 清除；同一引脚再"unmask"会
  **没有新物理边沿就重入 handler**（定向夹具因此 maskirq 后从不 unmask）。所以第二轮
  使用**第二个真实 GPIO 引脚 + 第二个 CPU IRQ 位**，而不是伪造同一引脚的第二条边沿。
- 启动寄存器：host 在 `begin_case` 通过真实 `ACCESS_TLUL_GPIO` 写 `INTR_ENABLE` /
  `INTR_CTRL_EN_RISING`（pins 0/4/8/12）。IRQ 本身只来自 GPIO RTL 对真实引脚的采样，
  没有任何 scheduler 合成脉冲。
- 结果块：RAM 0x200 起的 24 字节（status/data/q1/after/counter/marker），
  由 ISR 与 main 真实写入。

### 2.2 两个方向与两轮

`CPU_TO_IP_TO_CPU`（CPU 发起）：
CPU store `gpio_a.DIRECT_OUT=V`（bit0 恒 1、bit4 恒 0）→ 真实 `gpio_a` 引脚 →
`gpio_b` 输入 → 真实 pin0 上升沿 → CPU IRQ bit3 → **真实 custom0 trap**（`q1=8`）→
handler `getq`/读 `INTR_STATE`/读 `DATA_IN`/写 RAM/W1C/读回/计数/`maskirq`/`retirq` →
`gpio_b.irq` 与 CPU IRQ 输入回落。第二轮 `DIRECT_OUT = V | 0x10`：pin0 与 pin4 同时
上升，bit3 已 mask，所以 trap 是 **pin4 的真实边沿**（`q1=16`，`INTR_STATE=0x11`）。

`IP_TO_CPU_TO_IP`（IP 发起）：外部源在 START 拉起 `gpio_b.gpio_in` pin8 → 真实 pin8
上升沿 → CPU IRQ bit5 → `q1=32` → handler 读状态/数据、把程序常量写 `gpio_a.DIRECT_OUT`、
写 RAM、W1C、读回、计数、`maskirq`/`retirq`。第二轮由 **CPU 自己的真实 store 地址**
（`data_addr == RESULT+12`，即 handler 写"清后状态"的那条 store）触发：pin8 落下、
pin12 在 8 个 `gpio_b` tick 后拉起 → CPU IRQ bit6 → `q1=64`。
触发点选在 store 地址而不是 IRQ 下降，是为了让第二轮的外部边沿**晚于**第一轮
"清除后状态"的读取；否则那一读合法地会看到下一轮的 pending 位（本实现第一版正是如此，
已修）。

### 2.3 每方向的两个可变异源（这是本行的硬要求）

| 源 | kind | 位置 | 说明 |
|---|---|---|---|
| `cpu.program` | memory_image | 指令字 37 的 image bits [21,24)（`addi x9,x0,X` 立即数 bits 1..3） | 每例真实取指读回该字节（`initial-image` writer），值决定 CPU 侧 payload |
| `b.pin9` | source | `gpio_b.gpio_in` bit 9（真实外部输入引脚） | 真实被采样进 `DATA_IN`，每例被 CPU 读回 |

- 源宽 3 bit：value bit 0（字 bit 20）与 value bit 4（字 bit 24）都在源**之外**，
  所以 8 个变异基因型都保持"第一轮必有 pin0 上升沿"、且不会误触 pin4。
- 两个方向都声明这两个源；saved-run 审计还核对 `applied_source_uses` 两侧都 >0。

---

## 3. 闭环 checker（保留 Pico custom0 IRQ ABI）

`assess_pico_wb_closed_chain(direction, events, final_state)` 每轮要求以下**观测**按序出现
（每个阶段都带自己的 event identity，不从调度推导）：

1. 方向发起侧：CPU 的真实 `DIRECT_OUT` store（值 = 程序 image 立即数）或真实外部引脚
   `source_injection`；
2. `gpio_a` 真实输出观测 → 真实 output→input 路由（CPU 方向）；
3. 该轮**那个引脚**的真实上升沿（按位、不是整向量相等：GPIO 的输入同步会让多个使能
   引脚跨 tick 生效）+ `inputs.gpio_in` 等于期望读值；
4. `gpio_b.irq → cpu.irq` 的位级绑定（`source_bit_offset`/`target_bit_offset` 精确）；
5. CPU 真实 IRQ 输入置位 → **`eoi` 等于该轮真实向量**（8/16/32/64）；
6. ISR 的 `INTR_STATE` 读 = 期望状态、`DATA_IN` 读 = 期望数据（期望值由
   *观测到的 CPU store*、*声明的源注入值*、*运行期自己的 `initial_image` 事件中的程序 image*
   推出，不假设 DUT 返回值）；
7. CPU `data_rsp_consumed` 携带同一 read 的 epoch/sequence；
8. RAM 写：`RESULT+0/4/8` = status/data/q1（IP 方向还有 ISR 驱动 `gpio_a` 的真输出）；
9. W1C 写 = 观测到的 status；
10. `gpio_b` 该引脚真实下降沿 → `RESULT+12 = 0`（清后状态）→ CPU IRQ 输入回 0；
11. 每轮的 MMIO delivery 事务身份唯一（重复使用 → `transaction_reused`）；
12. 全程无 `reset_barrier`；轮次不得互相吞并（`rounds_overlap`）；结束
    `pending_responses` 全 0、CPU IRQ 与 GPIO 向量都回 0。

期望 IRQ 位/引脚/向量（按轮）：

| 方向 | 轮 | GPIO pin | CPU IRQ bit | q1/eoi | `INTR_STATE` | `DATA_IN` |
|---|---|---|---|---|---|---|
| CPU | 1 | 0 | 3 | 8 | 0x1 | `V \| (P<<9)` |
| CPU | 2 | 4 | 4 | 16 | 0x11 | `(V\|0x10) \| (P<<9)` |
| IP | 1 | 8 | 5 | 32 | 0x100 | `0x100 \| (P<<9)` |
| IP | 2 | 12 | 6 | 64 | 0x1000 | `0x1000 \| (P<<9) \| K` |

（`V`/`K` 为 image 立即数，`P` 为外部 pin 9 源值。）

---

## 4. 本轮真实运行（命令、退出、观察）

环境：Linux x86_64，Python 3.12，Verilator 5.051 devel，
预构建客户端 `third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz`
sha256 `d10256615cc9e35beeee75d40c75b1b5c8b30471fc6041f493a89043f1f52bf9`（与行 3 相同）。
所有真实 RTL 运行都用
`flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock` 串行。

### 4.1 定向回归（现有单 GPIO custom0 链）

```
flock -w 3600 .superpowers/heavy-worker.lock \
  env MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m pytest \
  tests/integration/test_scenario_picorv32_wb_opentitan_gpio_irq_real.py -x -q
```
→ **1 passed, 2 subtests passed in 91.80 s，EXIT=0**。证明本机 pinned Pico WB + OpenTitan
GPIO 真实 RTL、真实 custom0 handler 与 fresh replay 仍可用（本行夹具的语义基线）。

### 4.2 新测试（无 RTL 部分）

```
PYTHONPATH=src python3 -m pytest tests/integration/test_scenario_picorv32_wb_campaign.py -q
```
→ **20 passed, 3 skipped in 0.49 s，EXIT=0**。3 个 skip：2 个真实 RTL 单例（需
`MYFUZZ_SCENARIO_REAL=1`）与 1 个真实 18 格 bundle 审计（bundle 尚不存在）。

### 4.3 单例真实 RTL（checker 直接复算）

```
flock -w 3600 .superpowers/heavy-worker.lock \
  env PYTHONPATH=src python3 .superpowers/p6-row4/probe.py CPU_TO_IP_TO_CPU
```
CPU 方向完整 trace（`max_steps=1800`）：**status=complete，checker complete，rounds=2，
findings=[]**；RAM 结果块实测
`[status=1, data=517, q1=8, after=0, counter=1, status=0x11, data=533, q1=16, after=0,
counter=2, marker=0x66]`；`eoi∈{8,16}`、`trap=0`、CPU IRQ 输入取值 `{0,8,24}`、
外部源 `b.pin9=1`、最终 pending 全 0。

```
flock -w 3600 .superpowers/heavy-worker.lock \
  env PYTHONPATH=src python3 .superpowers/p6-row4/probe.py IP_TO_CPU_TO_IP
```
IP 方向（`max_steps=2400`）：**status=complete，checker complete，rounds=2，findings=[]**；
RAM 结果块实测
`[256, 768, 32, 0, 1, 4096, 4618, 64, 0, 2, 0x66]`；`eoi∈{32,64}`；两轮外部边沿
`first-rise@pin8`、`second-rise@pin12`（由 `cpu.data_addr == 0x20C` 触发，delay 8 gpio ticks）；
最终 pending 全 0、CPU IRQ 回 0。

**步预算标定**（真实 RTL sweep，`quiesce=8`）：

| 方向 | 完成 | 未完成 | 采用 | 单例墙钟（含夹具） |
|---|---|---|---|---|
| CPU | 1800 / 1500 | 1200 | **1800** | 4.6 s |
| IP | 2700 / 2400 / 2100 | — | **2400** | 5.4 s |

单格 smoke 实测实际吞吐：CPU 方向 **2.7 s/例**（1800 步/例，25 例/67.2 s）。

### 4.4 单格 campaign smoke（真实 provider.search + provider.replay）

```
flock -w 3600 .superpowers/heavy-worker.lock \
  env PYTHONPATH=src python3 .superpowers/p6-row4/smoke_cell.py CPU_TO_IP_TO_CPU 45
```
→ 证据目录 `.superpowers/p6-row4/smoke/smoke__CPU_TO_IP_TO_CPU__seed_20260927/`：
`testcases=25`、`valid=25`、**`completed_chains=25`（全部 `rounds=2`）**、
`applied_source_uses={'cpu.program': 14, 'b.pin9': 8}`（**两侧源都被真实消费**）、
`post_seed_mutation_batches=3`、`post_seed_effective_genotypes=5`、
`post_seed_completed_chains=22`、`corpus=3`、
`replay={total 3, matched 3, failure_entries 0, error: null}`、
`effective_search_seconds=67.24`、`seed_status=supported`、`failures={'complete':25}`。

```
... smoke_cell.py IP_TO_CPU_TO_IP 45
```
→ 证据目录 `.superpowers/p6-row4/smoke/smoke__IP_TO_CPU_TO_IP__seed_20260927/`：
`testcases=17`、**`completed_chains=17`（全部两轮）**、
`applied_source_uses={'cpu.program': 7, 'b.pin9': 8}`、
`post_seed_mutation_batches=2`、`post_seed_effective_genotypes=5`、
`post_seed_completed_chains=15`、`corpus=2`、
`replay={total 2, matched 2, failure_entries 0, error: null}`、
`effective_search_seconds=52.56`、`failures={'complete':17}`。

**注意（必须如实记录）**：IP 单格只请求 45 s 时有效搜索时间测得 **52.56 s**，
低于 gate 的最小 60 s（`search_budget_short`）。因此**不能**用 45 s 请求跑 18 格；
按协调口径用 `--seconds 200`（每格有效时间 ≥200 s，约 40–70 例），
且 CPU/IP 两个方向的单格证据都已证明 `testcases>9`、两条 mutation batch、
≥2 个有效基因型、seed 后 ≥1 条完整链与 corpus 全覆盖可达。

---

## 5. 负例（全部已跑或已由测试固定）

1. **旧组件不得冒充本行 seed**（任务硬要求）：把 `ibex_two_gpio_closed_two_rounds.json`
   或 `cva6_cpu_two_gpio_campaign_seed.json` 喂给 `PicoWbGpioBoundProvider._fixture`
   的两个方向 → **`CampaignBlocked`，且在任何 RTL 构建之前拒绝**（形状/方向 pin 不同）。
2. seed 形状被改（`max_steps+2`）→ 拒绝；program image 任一字节被改（源字段之外）→ 拒绝；
   reverse seed 的 action 表被裁短 → 拒绝。
3. independent baseline：`gpio_local_windows` 尺寸被改、`cpu_irq` 从 `constant_zero` 改成
   `bound` → 都在构建前拒绝。
4. checker 逐阶段负例（每项都断言**该阶段自己的 finding**）：删 CPU store、删
   output→input 路由、删 GPIO 上升沿、删 IRQ 绑定、删 `INTR_STATE` 读、删 `DATA_IN` 读、
   删 consume、删 q1 RAM 写、删 W1C、删清后状态写、删 GPIO 下降沿；另有：
   - program 不在 pinned image 内（源字段之外被改）→ `cpu_program_image_differs`；
   - 立即数 bit0 被清 → `cpu_program_immediate_outside_source`；
   - 注入 `reset_barrier` → `unexpected_reset`；
   - 结束 pending ≠ 0 → `pending_responses_at_end`；
   - 只有一轮 → `too_few_closed_rounds`；
   - 两轮复用同一事务身份 → `round_2:transaction_reused`；
   - 未知方向 → 不评估（`None`）。
5. saved-run 审计负例（合成 18 格 bundle，测试中明确标注"验证审计逻辑，不是真实 RTL 战役"）：
   `gate_status` 改坏、coverage `executed≠declared`、chain check `rounds=1`、
   多出未记账 corpus 条目、保存的 seed action 表被换、run identity envelope 被篡改 →
   审计全部拒绝；未篡改的 bundle 复算通过（18 格、54 例、24 条链、18 条 corpus）。

---

## 6. 未完成 / 未覆盖（不得略去）

- **18 格 campaign 未运行**。当前没有 `campaign_report.json`、没有
  `gate_status=complete`、没有 18/18 格逐格证据。**这不是行 4 通过。**
  根代理冻结源码后请执行（唯一待补步骤）：

  ```
  flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock \
    env PYTHONPATH=src python3 scripts/run_scenario_campaign.py \
    --manifest configs/scenario/pico_wb_two_gpio_campaign_seed.json \
    --baseline-manifest configs/scenario/pico_wb_two_gpio_campaign_baseline.json \
    --seconds 200 --seed 20260927 \
    --output runs/scenario/campaign-pico-wb-g4-18cell-p6-row4 \
    --provider myfuzz.integration.picorv32_wb_scenario_campaign:PicoWbGpioBoundProvider
  ```

  预期：18 格 × 3 策略 × 2 方向 × 3 seed；每格 `testcases` 约 40–70；`gate_status=complete`；
  总有效搜索约 3600 s（要求 18×200=3600）。跑完用审计复核：

  ```
  env MYFUZZ_PICO_WB_CAMPAIGN_RUN=runs/scenario/campaign-pico-wb-g4-18cell-p6-row4 \
    PYTHONPATH=src python3 -m pytest tests/integration/test_scenario_picorv32_wb_campaign.py -q
  ```
  （审计测试会逐格从 `receipts.jsonl`/`chain_checks.jsonl`/`corpus`/`seed_genome.json`/
  `run_identity.json` 复算并与 report 交叉核对；不通过会直接失败。）
- **execution_mode=fresh_genomes**：每例新建 RTL harness，无跨例持久 DUT 状态；
  若"多例持续会话"须为单一 harness 跨例，本行仍未满足（与行 2/3 同口径）。
- **independent_drive 基线**只用真实 RTL 观察一个本地点（CPU 本地应答/GPIO IRQ），
  corpus 只有 1 条，`completed_chains=0`（gate 也禁止其声明链）。
- 本 provider 继承 `IbexTwoGpioBoundProvider.replay` 的失败计数口径：若出现
  `dut_violation` 且失败 trace 数 > corpus 数，`_validated_replay` 会以
  `replay counts are inconsistent` 让该格报错（保守失败，不会假绿）；行 3 为此改写过口径，
  本行未改（本轮 0 个 dut_violation / 0 个 uncertain_effect）。
- 未做行 4 的受控错误负例（P6 额外要求"至少一个非 Ibex＋非 GPIO 组合的受控错误"，
  本行范围未包含；现有受控故障校准仍只覆盖 Ibex＋PULP GPIO）。
- 仅覆盖 OpenTitan GPIO；未覆盖 ZipCPU `wbuart`/`timer`（行 4 的备选 IP）。
- `runtime_path_status=legacy_unchecked`（继承）；`closed_loop_energy`/`path_switch`
  同样未启用，故反馈通道是 mutation-hint，不含四类命名命中族。
- 未修改共享能力表/总计划状态（§5 要求等真实 18 格通过后再更新；本行尚未通过）。

---

## 7. 结论

已交付行 4 缺失的三件具体东西（scenario 夹具、`CampaignProvider`、保留 custom0 ABI 的
闭环 checker + 两份 manifest），并有：
① 两方向单例真实 RTL 两轮闭环（checker 复算 `findings=[]`）；
② 两方向**单格真实 campaign**（provider 搜索 + 完整前缀 replay）——CPU 25/25、IP 17/17
条完整两轮链，两侧源都被真实消费，corpus 全覆盖 replay 无差异；
③ 旧组件（Ibex/CVA6）seed 拒绝、逐阶段负例与审计负例。

**未交付**：18 格 campaign 运行与 `gate_status=complete`。按协调决定，这一步由根代理在
源码冻结后用 heavy lock 串行执行；在它通过并由审计复核之前，本行**仍记未通过**，
不得以本报告的单例/单格证据替代 18 格 campaign。
