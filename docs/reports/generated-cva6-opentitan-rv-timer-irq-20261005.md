# CVA6 + OpenTitan RV Timer 原生 M_TIMER 验收

日期：2026-10-05

## 验收范围

本场景使用真实 CVA6 packed AXI4 RTL 和真实 OpenTitan RV Timer TL-UL RTL。两者运行在各自独立的 generated harness 中；`ScenarioRunner` 只通过 DataflowRouter 交付 MMIO 事务，并将 Timer RTL 的真实 IRQ 绑定到 CVA6 的独立 `irq_timer` 运行时输入（物理端口 `time_irq_i`）。CVA6 的 `irq_external` 保持为 0，因此该场景验证的是 native machine timer 中断 M_TIMER，不是 M_EXT。

CVA6 执行 testcase RAM 中的 RV64 程序，配置 `mtvec`、`mie.MTIE`、`mstatus.MIE` 和 Timer compare。Timer 到期后，真实 Timer RTL IRQ 经 binding 到达 `time_irq_i`，CVA6 进入 ISR。ISR 从 Timer RTL 读取真实 `INTR_STATE` 和计数器，把它们及完整 `mcause` 写入持久 RAM，停止 Timer 后通过 W1C 清除中断状态，并把清零结果和完成标记写入 RAM。

## 验收结果

- trace 状态：`complete`；独立 CPU 和 Timer harness 均完成运行。
- Timer 真实 IRQ 高电平经 `timer.irq → cpu.irq_timer` 绑定交付，且 CVA6 样本观察到 `irq_timer=1`。
- ISR 读到 Timer `INTR_STATE=1`，计数值不小于 compare 值 128。
- RAM 保存完整 `mcause=0x8000000000000007`，确认 trap cause 为 machine timer interrupt 7。
- Timer 的真实 W1C 操作后，ISR 读回 `INTR_STATE=0`；完成标记为 `0x55`。
- fresh replay 创建新的 CPU/Timer session，完整语义比对通过：`matches=true`。
- 首轮 trace 有 5961 条语义事件；本地 tick 为 CVA6 700、Timer 740。两者 tick 独立计数，不定义统一 SoC cycle。

## Evidence 与复现

持久 evidence bundle：`/tmp/myfuzz-cva6-timer-debug/evidence/`。其中 `trace.json`、`transactions.jsonl`、`observations.jsonl`、`manifest.json` 和 `replay_report.json` 保存了事务、样本、构建身份及 replay 结果。`result.json` 报告 `status=complete`、`event_count=5961`，`replay_report.json` 报告 `matches=true`。

定向验收测试入口：

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_scenario_cva6_generated_opentitan_rv_timer_irq_real \
  -v
```

成功的诊断运行由 wrapper 调用上述 integration test 的完整场景，并将其内容寻址构建缓存重定向到 `/tmp/myfuzz-cva6-timer-debug/cache/`，以保留构建产物供复查。首轮执行和 fresh replay 均通过：1 项通过，进程退出码 0，约 50 秒。另将同一场景保存为上面的持久 evidence bundle。证据 bundle 的 manifest SHA-256 为 `25a8de20f42d340d9c538f8097bb58d3d1597e7ee39b8e16c8a752e2f95535ee`，语义 SHA-256 为 `21bdb1c3ab119995bfc1d0e2b90e419d1ffedb4da9a3efe424e6a3676759b53b`。

## 能力边界

此验收证明当前 CVA6 harness 的独立 native `time_irq_i` 输入可绑定真实 Timer IRQ，并能由真实 CVA6 执行 M_TIMER handler；它不覆盖 M_EXT/PLIC 路由、其他中断源、具体 SoC 总线拓扑、global cycle-accurate 时序、突发 MMIO 或通用 AXI4 CPU 复用。Timer 与 CPU 分别按各自 harness 的局部时序推进。
