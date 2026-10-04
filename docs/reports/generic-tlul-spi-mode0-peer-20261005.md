# 通用 TL-UL 模板上的 SPI mode-0 外部 master 验收

本阶段在 `local_harness.v2` 的 `tlul_register_observe` 产物上叠加一个可配置的单线 SPI mode-0 master session。生成器、TL-UL 适配器和 C++ 驱动没有按 SPI Device 加新分支。外设的固定源码、完整端口 profile、TL-UL 协议合同和逐字段输入归属仍由现有模板校验。

OpenTitan SPI Device 的 `sck_i`、`csb_i`、`sd_i` 由 `environment_bindings` 声明为同一个外部 frame 源，`tpm_csb_i=1` 由 `fixed_inputs` 拥有。peer 参数指定三根输入引脚、MISO 输出与输出使能、bit lane、半周期长度、可选前缀与读取字节数。Scenario Genome 只变异一个 `spi_master_frame`；session 将它转换为逐周期 SCK/CS/MOSI 波形。未拥有的引脚、重叠固定归属、错误的 source identity、超宽或第二个不同 frame 均拒绝。相同 frame 再次提交只运行一个普通 step，不重复串行事务。

MISO 只在真实 `sd_en_o` 使能时从真实 `sd_o` 采样；IRQ、上传状态和 SRAM 值均读取真实 RTL。peer 不生成预期的 MISO、IRQ 或 DUT 寄存器结果。一次 testcase 中进程与配置寄存器保持状态，CS 在配置前置为不选中。fresh replay 使用相同 artifact、frame、局部时序和事务顺序。

真实 RTL 验收：

| 场景 | 真实结果 | replay |
|---|---|---|
| JEDEC opcode `0x9F`，预设 JEDEC 寄存器 | `sd_o/sd_en_o` 返回 `A1 34 12` | 匹配 |
| upload opcode `0x02` 加 32 位 frame `0x0012345A` | `irq_o[0]` 置位，状态寄存器读到 opcode/address，SRAM 读到 `0x5A` | 匹配 |

该 peer 只覆盖单线 mode-0、单次 frame、一个局部时钟域和最多 32 位可变 payload。它是独立 harness 的外部环境模型，没有生成 SoC bus、仲裁或全局 cycle-accurate 连接；多线 SPI、其他模式、连续多帧和 CPU 中断处理程序仍需扩展与单独验收。专用 `tlul_spi_device` session 的既有验收保持独立。
