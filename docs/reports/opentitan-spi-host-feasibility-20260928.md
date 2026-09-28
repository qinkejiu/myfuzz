# OpenTitan SPI Host 独立场景接入评估

日期：2026-09-28。此项为本地源码只读审计与下一阶段实施范围，**尚无 SPI Host RTL 构建或运行结果**。

## 选择与当前缺口

下一项异构外设建议采用 OpenTitan `spi_host`。本地源码位于 `third_party/soc-opentitan/hw/ip/spi_host/`，但当前 `configs/soc/sources.lock.json` 没有 OpenTitan SPI Host/Device 的锁定条目，项目也没有相应 component profile、独立 scenario harness 或真实端到端证据。`spi_device` 涉及外部 SCK/CS 时钟域、TPM/SRAM/DFT 等更多接口，先接入 Host 的范围更明确。

Host 顶层提供 TL-UL 寄存器接口、真实 `cio_sck_o`/`cio_csb_o`/`cio_sd_o[3:0]`/输出使能、外部 `cio_sd_i[3:0]`，以及 `intr_spi_event_o`/`intr_error_o`。首批 harness 可复用 UART 的 TL-UL adapter、持久本地进程与 `ScenarioRunner` 事务路由模式，但必须从 `spi_host.core` 和相关 package/prim 解析完整的本地 Verilator 编译闭包，不能直接复制 UART filelist。

## 输入约束和传播路径

建议首个场景为：

```text
Fuzzer 变异 CPU 程序/初始数据
→ CPU RTL 真实写 SPI Host CONTROL/CONFIGOPTS/COMMAND
→ SPI Host RTL 真实产生 SCK/CS
→ Fuzzer 控制的外部 SPI peer 依据真实 SCK/CS 和配置提供 cio_sd_i
→ SPI Host RTL 真实产生 RXDATA/状态型 IRQ
→ CPU 真实接收 IRQ、读取 RXDATA、写持久 RAM
```

`cio_sd_i` 是可变的外部 source；CPU MMIO 响应、SPI Host RXDATA/IRQ 是 bound input/真实输出，不得由 Fuzzer 再随机覆盖。外部 peer 的位相和数据变化必须服从 SPI Host 实际输出的局部握手与 CPOL/CPHA 设置，不以跨组件全局 cycle 数预置数据。保持各 RTL 自身局部 tick，并在 testcase 内保存 FIFO、寄存器、待处理事件和 RAM 状态。

OpenTitan SPI Host 的 `INTR_STATE.spi_event` bit1 为只读状态型中断；仅 `INTR_STATE.error` bit0 为 W1C。闭环应通过 CPU 真实读取 RXDATA 或调整事件使条件解除，再观察 IRQ 真实下降，不能对 `spi_event` 使用 W1C 假清除。首次接收用标准单线 4 字节命令较稳妥：`COMMAND.LEN=3`、`DIRECTION=1`、`SPEED=0`，然后核对 RTL 的 32 位 RXDATA 打包。

## 分步验收

1. 锁定源码与完整编译闭包，独立 top 经 Verilator elaboration；记录版本、参数、全部输入文件哈希及本地协议断言。
2. 独立 Host harness 以合法 TL-UL 写 CONTROL/CONFIGOPTS/EVENT_ENABLE/COMMAND；观察真实 SCK/CS、合法外部输入被采样、RXDATA/IRQ 与寄存器读回。测试 byte-enable、局部延迟、状态型 IRQ 解除和超预算 pending。
3. Ibex＋Host 独立 harness 在一个连续 testcase 中完成两轮 CPU→Host→CPU；CPU 程序与外部 peer payload 分别可变，真实中间值逐事务绑定，CPU 读回与持久 RAM 对应；无隐式 reset。
4. 做切断 Host→CPU IRQ/RDATA 绑定的负例、完整初态 replay、源码身份校验；再考虑 SPI Device 与更多错误路径。

本评估不构造 SoC Bus/Crossbar/PLIC，也不把不同 harness 的局部 tick 当作真实 SoC 总线延迟。
