# CVA6 + OpenTitan GPIO M_EXT ISR 验收

日期：2026-10-05

## 验收范围

本场景使用固定源码生成的 CVA6 packed AXI4 harness 与 OpenTitan GPIO TL-UL harness。CPU 和 GPIO RTL 独立运行，由 `ScenarioRunner` 通过 `DataflowRouter` 转交真实 MMIO 事务，并将真实 GPIO IRQ 输出绑定到 CVA6 的 `irq_external`。Timer 输入 `irq_timer` 固定为零。

唯一可变的 Genome source 是 GPIO 外部输入 `gpio_in[7:0]`。依赖图选择 `external_gpio_pins`，bit 7 变异将输入从 `0x01` 改为 `0x81`；`gpio_in[31:8]` 和 `strap_en` 固定为零。两个值都使已使能的 pin 0 从低变高，同时 `DATA_IN` 保留不同的真实 pin payload。

CVA6 固件配置直接模式 `mtvec=0x10100`、`mie.MEIE` 与 `mstatus.MIE`，再通过 AXI4→Router→TL-UL 向 GPIO 写入 `INTR_ENABLE=1` 和 `INTR_CTRL_EN_RISING=1`。Genome 的输入动作以 CVA6 接受地址 `0x4000002c` 的 AXI AW 握手为触发，并等待 32 个 CPU 本地 tick。测试另外检查两笔 GPIO 配置写的 `mmio_delivery` 都早于输入注入，因此 AW 地址仅决定安排时机，不被当作写提交证据。

GPIO RTL 产生的真实 IRQ 经 `gpio.irq → cpu.irq_external` 进入 CVA6。ISR 从真实 GPIO RTL 读取 `INTR_STATE`、`DATA_IN` 和 CSR `mcause`，把结果写入持久 RAM；对 `INTR_STATE` 执行 W1C 并读取清零结果。IRQ 随后拉低。ISR 写入 `0x55` 完成标记并执行 MRET；主程序轮询该标记并在返回后写入 `0x66`，作为主程序恢复执行的可观察证据。

## 验收结果

- 两个源值 `gpio_in=0x01` 和 `gpio_in=0x81` 均各注入一次，注入范围为 bit `[7:0]`。
- `INTR_ENABLE=1` 与 pin 0 上升沿使能 `INTR_CTRL_EN_RISING=1` 的真实 GPIO TL-UL 事务均在 source injection 之前完成。
- 真实 GPIO IRQ 到达 CVA6 `irq_external`，CVA6 采样到 IRQ 高电平；`irq_timer` 始终为零。
- ISR 读取 `INTR_STATE=1`，`DATA_IN` 分别为 `0x01` 和 `0x81`，并保存 `mcause=0x800000000000000b`，对应 machine-external interrupt cause 11。
- GPIO `INTR_STATE` W1C 后，ISR 读回零，且绑定 IRQ 后续拉低。
- RAM 保存 ISR 标记 `0x55` 及 MRET 后主程序标记 `0x66`。AXI 写入按真实 64 位数据通道和 WSTRB lane 检查。
- 两个场景均在 command epoch 0 完成，无 testcase 内 reset barrier；路由事务 source sequence 唯一。
- 每个源值都生成预算化 evidence bundle，并在全新的 CVA6/GPIO harness 上完整 replay，`matches=true`；replay 的 RAM 结果相同，两个新 session 的 reset epoch 均为零。
- 实现代理运行 `1 passed in 95.08s`；主代理独立重跑 `1 passed in 94.03s`。每条测试覆盖两个源值及各自的完整 fresh replay。

测试限制为每个 Genome 最多 3000 runner steps；`ResourceBudget` 上限为 2048 transactions、每组件 8192 local cycles、12000 scheduler steps、300000 ms、每个 memory 0x40000 bytes 和 64 MiB evidence。trace 以 `complete` 结束，未达到所设预算上限。evidence bundle 在测试临时目录中生成并用于 replay；测试结束后目录会清理，复现命令会重新生成证据。

## 复现

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 pytest -q tests/integration/test_scenario_cva6_generated_opentitan_gpio_mext_irq_real.py
```

## 能力边界

此验收证明当前固定 CVA6/OpenTitan GPIO profile 的一个 pin 0 上升沿→M_EXT ISR 闭环。它不证明其他 pin、边沿或电平模式，不包含 PLIC、具体 SoC 总线拓扑、协议桥、全局 cycle-accurate 时序、其他 CVA6 IRQ 类别或其他 CVA6 配置。两个 RTL 各自在独立 harness 和本地时钟下执行，跨组件只交付真实事务和 IRQ。该定向验收没有声称发现 RTL 缺陷，也不构成 coverage-guided bug search 结果。
