# OpenTitan SPI Device 生成式本地 harness 验收

## 源码与完整边界

固定上游源码为 `third_party/soc-opentitan` 的 `fca045df919a26c47e71616b9dac917b1ea4fd07`。`opentitan_spi_device_local` profile 引用锁定闭包中的 93 个上游源文件与一个标量 wrapper，使用 Verilator 全顶层端口事实（35 个端口）和内容哈希验收。边界包含 20 个 TL-UL 字段、SCK/CSb/TPM CSb/SD 引脚、8 个真实 IRQ，以及原生诊断输出。只声明系统 `clk_i` 为本地时钟；外部 SCK 是 SPI 主设备控制的引脚，在测试场景中产生局部边沿，不建立全局 SoC cycle-accurate 时钟。

## 两级能力与输入归属

| 路径 | 输入归属 | 已验证的真实 RTL 行为 | 未覆盖范围 |
|---|---|---|---|
| `local_harness.v2` 通用 `tlul_register_observe` | 四个 SPI 输入均由 `fixed_inputs` 声明：`sck_i=0`、`csb_i=1`、`tpm_csb_i=1`、`sd_i=0`；未声明则拒绝生成 | 同一进程连续 TL-UL 写 CONTROL 与 JEDEC_CC、读回 JEDEC_CC、观测引脚/IRQ，并在新进程 fresh replay | 外部 SCK 保持静止，所以**只验收寄存器和输出观测，不验收串行收发** |
| `local_harness.v1` SPI Device 串行 session | SPI 主设备只控制四个外部输入；`sd_o`、`sd_en_o`、`irq_o`、TL-UL RDATA 只能取真实 RTL 输出 | mode-0 单线 JEDEC 响应 `A1 34 12`，改写 CSR 后变为 `B2 78 56`；外部上传帧触发真实 IRQ，命令/地址 FIFO 与 SRAM 内容来自 RTL；独立场景有 fresh replay | TPM、双线/四线、passthrough、其他 SPI 模式及任意外部主设备行为未验收 |

SPI Device 有独立 SCK 域，生成式串行驱动在 CSb 高期间给 SCK 两个启动脉冲，再从 testcase 的本地 tick 0 开始。这个动作只满足 DUT 的局部复位/时钟恢复；每个 testcase 内仍使用同一 RTL 实例，CS 配置和 SRAM 状态保持到结束或显式 reset。

## 运行证据

```bash
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.integration.test_local_opentitan_spi_device_generated_real -v
PYTHONPATH=src MYFUZZ_SCENARIO_REAL=1 python3 -m unittest \
  tests.local_harness.test_generic_tlul_register_real.GenericTlulContractTests.test_spi_device_requires_all_four_fixed_external_inputs \
  tests.local_harness.test_generic_tlul_register_real.GenericTlulRealTests.test_spi_device_profile_only_registers_and_fresh_replay -v
```

前一组证明专用串行 session 的真实 RTL 收发和外部源 replay；后一组证明同一 SPI Device profile 能在通用 v2 模板中按声明式固定输入完成寄存器级验收，且未增加新的组件专用通用驱动分支。两组的能力不得混称。

## 跨组件边界

这里验收的是 SPI Device 独立 harness 的真实局部行为，以及外部 SPI 主设备源到 SPI Device RTL 的传播。尚未建立 `CPU → SPI Device → CPU` 或 `SPI Device → CPU → 其他 IP` 的场景路由、Dependency Path、CPU 指令执行和 Bound Input 回送；不能将本地寄存器/串行通过解释为 CPU 多组件闭环通过。后续跨组件验收必须让 CPU 的真实 MMIO 输出配置 SPI Device，并把 SPI Device 的真实 RDATA/IRQ 交给 CPU harness，再核对 CPU RTL 的后续行为与 fresh replay。
