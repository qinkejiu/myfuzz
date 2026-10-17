# P6 行 5（PicoRV32 native Ready/Valid Memory × 真实 PULP APB3 GPIO）campaign 实施报告

日期：2026-10-17。范围：`docs/superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md` 行 5
（`ready-valid-memory/1`）的"第二步完整框架复用"证据。当前 HEAD `0a4a81b`。

> **状态：源码／测试／seed／checker 已实现并提交；18 格 campaign 尚未运行。**
> 这是协调决定：P7/P8 代理仍在修改 `src/myfuzz`，任何 host-source 变更都会让 campaign 的
> build identity 漂移（本轮 `host-source-content-drift:src/myfuzz/scenario/compiled_paths.py`
> 实测发生于 15:46:38，是该文件被其它代理并发编辑所致，不是本行代码缺陷）。root 将在源码
> 冻结后统一用 heavy lock 跑 18 格。本报告只声称已真实发生的证据，不把定向/directed 当 campaign。

---

## 1. 交付物

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/picorv32_native_cpu_example.py` | 真实 PicoRV32 native CPU（`configs/cpus/picorv32`，`git:ef203c2b…`）＋真实 PULP APB3 GPIO（`configs/peripherals/pulp_gpio`，`git:f82caeb7…`）的 scenario fixture：双向两轮程序、两个可变异源、ownership、runner pair、`DeferredNativeMemorySession` |
| `src/myfuzz/integration/picorv32_native_scenario_campaign.py` | `PicoNativeGpioBoundProvider`（三策略 × 两方向 × 三 seed）、`assess_native_gpio_closed_chain` 双轮闭环 checker、independent baseline fixture、source identity/run record CLI |
| `configs/scenario/pico_native_gpio_campaign_seed.json` | bound CPU 方向 seed Genome（`AFTER_OUTPUT` 触发，shape `(1200,16)`） |
| `configs/scenario/pico_native_gpio_reverse_seed.json` | bound IP 方向 seed Genome（`START` 触发，同 shape） |
| `configs/scenario/pico_native_gpio_independent_ip_seed.json` | independent IP 方向 seed Genome |
| `configs/scenario/pico_native_gpio_campaign_baseline.json` | independent baseline manifest（local shadow、`cross_component_bindings=[]`、`cpu_irq=constant_zero`） |
| `tests/integration/test_scenario_picorv32_native_campaign.py` | 程序/seed/ownership 守卫、checker 每个篡改点的定向 finding、旧组件负例（Ibex/CVA6 seed 喂本 provider 必须拒绝）、`MYFUZZ_SCENARIO_REAL=1` 双向 directed 真 RTL |
| `tests/integration/test_picorv32_native_campaign_saved_run_audit.py` | 18 格保存产物的独立审计（逐 cell 重算 gate、源选择/消费、post-seed 多样性、双轮排队链、corpus replay、provider/fixture/输入/RTL build identity） |

共享框架**零改动**：Runner/Router/mutator/`GeneratedNativeMemorySession`/contracts/host identity
均未改。排队 MMIO 由 fixture 内的 `DeferredNativeMemorySession` 子类实现（`defer_mmio` 构造参数），
既有 inline 行为逐字节不变。`native_session.py` 也没有改（它在 generated harness 的 host-source
闭包内，改它会改变每一份已保存 runner manifest 的 build identity）。

## 2. 真实 RTL 定向证据（fresh cache，双向）

命令（定向，不依赖 campaign 框架）：

```
R5_CACHE=.superpowers/r5-cache-h PYTHONPATH=src python3 .superpowers/r5-smoke/smoke.py CPU_TO_IP_TO_CPU
R5_CACHE=.superpowers/r5-cache-h PYTHONPATH=src python3 .superpowers/r5-smoke/smoke.py IP_TO_CPU_TO_IP
```

日志：`.superpowers/r5-smoke/directed-cpu.log`、`.superpowers/r5-smoke/directed-ip.log`（本地、
未入库）。两个方向都是 `STATUS complete`、`ASSESS complete:true / rounds:2 / findings:[]`、
`REPLAY True`，且：

* `ticks = {cpu: 601, gpio0: 624}`；`mmio_acceptance = 6`、`mmio_delivery = 6`；
* 真实引脚：`gpio_out` 依次出现 `0 → 0x5a(A=90) → 0x66(C1=102)`，
  `gpio_in_sync = 0x3c(B=60)`；`gpio_dir` 由 CPU 的 `PADDIR` 写变为 `0xffffffff`；
* 6 个 delivery 的 `producer_event_id` 全部指向 `gpio0` 自己的 step（acceptance 在 CPU step），
  即真正排队：device 未 step 之前 CPU 拿不到应答；
* RAM：`0x100 = 0x66 = A^B`、`0x104 = 0xa2 = (A^B)+B`、`0x108 = 1`（完成 marker）；
* `pending_responses = {cpu:0, gpio0:0}`；无 `reset_barrier`；输入终态 `gpio_in=0x3c`；
* fresh replay 与记录逐事件一致。

CPU 方向触发链（真实事件序）：`mmio_acceptance(PADOUT=A)` → `source_injection(gpio_in=B)` →
`mmio_delivery(PADOUT=A, producer=gpio0 step)` → `gpio_out=A` → `mmio_delivery(PADIN)` →
`data_rsp_consumed(rdata=B)` → `memory_write(0x100,A^B)` → 第二轮同构。IP 方向仅把
`source_injection` 提前到 `START`（首个 CPU device 访问之前），checker 强制该序。

## 3. 单格 gate 预演（20s）与一个真实缺陷

在旧树、20s、全新 build 的 `dependency_guided` 单格预演中（`.superpowers/r5-smoke/cell-cpu.log`、
`cell-ip.log`）：

* `testcases=9`、`valid=9`、`completed_chains=9`、`post_seed_completed_chains=7`、
  `post_seed_effective_genotypes=7`、corpus 2 条、replay `matched=2/2`、`error=null`；
* **发现并修复的真实缺陷**：`applied_source_uses` 只有 `cpu.padout_byte`，`gpio0.pin_byte`
  为 **0**。根因不是 RTL，而是搜索：`scenario_rfuzz.mutation_hint` 把同一条 path 的两个源
  评分打平时按 `source_index` 破平，恒选 index 0；CPU 源又因 `gpio_out` 位覆盖获得增益，
  而 pin 源从未被选、增益为 0，于是被长期饿死。gate 的 per-direction 源覆盖（
  `dependency_guided__*` 的 `declared == executed`）会因此失败。
* **修法（不碰共享代码）**：把 graph 改成"每个 coverage target 一条诚实单源规则"：
  `gpio0.pin_sync_bit_*`/`cpu.device_answer_bit_*` 只依赖 pin 源，
  `gpio0.padout_pin_bit_*` 只依赖 CPU 源（第一轮固定写 A），anchor 双源。
  这样 hint 在 seed 后第一步先选 pin 源（template 序号更小且 target 未命中），
  第二步选 CPU 源，两个源在最早两例内都被真实选中/消费；不是靠频度交替或按名分支。

20s 的 9 例口径：effective 20.0s（wall 43.6s）→ 每例有效约 2.2s，因此 `--seconds 60`
预期约 27 例（远大于 gate 的 `testcases > 9`）。50/150s 只是更大余量，不是 gate 变更。

## 4. 18 格 campaign：尚未运行（等源码冻结）

在 15:44–15:46 的 fresh-cache 60s 单格预演中，`compiled_paths.py` 于 15:46:38 被其它代理
并发修改，`host_source_discovery_scope` 以 `host-source-content-drift` fail-closed 中止
（`.superpowers/r5-smoke/cell60-cpu.log`、`cell60-ip.log`）。这是正确的失败：同一 cell 内
build identity 不得漂移。协调结论是 root 在所有源码代理提交、树静止后统一跑。以下命令/审计
已备好；**本报告不声称 18 格已通过**。

```
# 1) 18 格（heavy lock 串行；--seconds 150 为余量，60 按 2.2s/例也 >9 例）
flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock \
  env PYTHONPATH=src python3 scripts/run_scenario_campaign.py \
    --manifest configs/scenario/pico_native_gpio_campaign_seed.json \
    --baseline-manifest configs/scenario/pico_native_gpio_campaign_baseline.json \
    --seconds 150 --seed 20260927 \
    --output runs/scenario/campaign-pico-native-g4-18cell-p6-row5-20261017-v1 \
    --provider myfuzz.integration.picorv32_native_scenario_campaign:PicoNativeGpioBoundProvider

# 2) 记录 provider/fixture/输入/client 身份并写 run record
PYTHONPATH=src python3 -m myfuzz.integration.picorv32_native_scenario_campaign \
  runs/scenario/campaign-pico-native-g4-18cell-p6-row5-20261017-v1

# 3) 独立审计（逐 cell 重算，不读摘要）
PYTHONPATH=src python3 -m pytest \
  tests/integration/test_picorv32_native_campaign_saved_run_audit.py -q
```

要求的 gate 结果：`gate_status=complete`、18/18 `complete`、每格 `gate_failures=[]`、
每格 `chain_checks.jsonl` 非空且每条 credited `rounds=2/findings=[]`、corpus 有增长且
`replay.error=null/matched=total`、`campaign_source_identity_stable=true`、
`originals_stable/snapshots_stable=true`。若任一不成立，保留原跑并修真实原因，不放宽 gate。

默认审计目录即上面的 `runs/scenario/campaign-pico-native-g4-18cell-p6-row5-20261017-v1`；
可用 `MYFUZZ_PICO_NATIVE_CAMPAIGN_RUN` 指向另一份同口径 run。

## 5. 设计要点与"为什么不伪造"

* **CPU 侧**：`configs/cpus/picorv32` 只有一个 `processor.memory`（`ready-valid-memory/1`）、
  没有中断端点；`ENABLE_IRQ=0`。因此本 fixture 不声明、不合成任何 IRQ，checker 也没有 IRQ 项。
* **MMIO 目标**：CPU profile 自己**没有**地址窗口；窗口（`0x40000000/0x1000`）、寄存器偏移
  （`PADDIR/GPIOEN/PADIN/PADOUT = 0/4/8/12`）来自 fixture + device profile，窗口外仍走 RAM。
* **排队语义**：`DeferredNativeMemorySession` 对窗口内 beat 调 `DataflowRouter.enqueue`，
  CPU 保持单 outstanding、无应答，直到 device harness 被 step、router 在 device step 回来执行
  并回调；checker 用 source-transaction identity 把 acceptance/delivery/CPU consume 三方 join，
  并要求 delivery 的 producer 是 `gpio0` step。不是同步直写，也不是"Python 算一个应答"。
* **两个源、两轮**：
  - CPU 源 `cpu.padout_byte`：程序第 4 条 `addi` 的立即数低字节（绝对 bit 148..155）；
  - IP 源 `gpio0.pin_byte`：`gpio_in` 的 bit 0..7（bit 8..31 fixed 0，reserved/mask 负例在测试里）。
  - 程序：写 A 到 PADOUT → 读 PADIN(B) → RAM 存 A^B → 写 A^B 到 PADOUT → 再读 PADIN(仍 B，
    设备无 output→input loopback) → RAM 存 (A^B)+B → marker。checker 断言真实 `gpio_out`
    依次为 A、A^B，`gpio_in_sync=B`，两次 PADIN 回读都是 B，RAM 两个 joint 值，且第二次写
    的值必须等于 A^B。
* **独立基线**：同一对真实 RTL，但 CPU 窗口由声明的 local shadow 应答、`bindings=[]`、
  `independent_baseline=True`、inline（非排队）模式；gate 要求它 claim 0 条因果链。
* **checker 负例**：delivery 在 CPU step（非 device step）执行、方向序反、PADIN 答案错、
  第二次写非 joint、缺 RAM commit、事务身份复用、reset_barrier、末尾 pending response——
  每条都有定向 finding 测试（`TestClosedChainChecker`，24 passed / 2 real-RTL skipped）。

## 6. 已记录的外部缓存失效

`cell-ind.log` 与 `cell60-cpu/ip.log` 的 `host-source-content-drift:src/myfuzz/scenario/compiled_paths.py`
是外部源码变更（root 的 `987eada` 及后续代理编辑）导致的 build identity 漂移；按协调决定
本报告把它记录为"旧 cache 失效、需在冻结树上重建"，不作为行 5 的失败。fresh-cache 的
directed 双向 smoke 已在 `.superpowers/r5-cache-h` 上重建并通过。

## 7. 明确未声称

* 18 格 campaign **尚未运行**；本报告只声称 directed 双向真 RTL、单格 20s 预演（旧树）和
  checker/守卫测试。
* 无跨例持续 RTL/RAM 状态（campaign 是 `fresh_genomes`：每例新进程、RAM 从 genome 重建；
  共享的是 search/decoder/corpus/feedback）。
* 无受控错误负例；无 `RuntimePathContract` 逐边预检（`legacy_unchecked`）；
  反馈只有 mutation-hint 通道，未声称 stage/edge/state/closed-loop 四类命中。
* 无 IRQ/handler 链（profile 无中断端点，`ENABLE_IRQ=0`）。
* corpus 增长受 25 个 coverage target 限制；不是广泛变异档案。
* 没有把定向用例或 20s 预演当作 18 格 campaign 证据。
