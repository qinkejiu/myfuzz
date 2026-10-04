# 自动生成独立 Harness：2026-10-04 能力状态

本报告只统计固定源码、生成式本地 harness、真实 RTL 行为和新进程回放共同支持的能力。协议目录中的候选不自动取得运行等级。详细输入归属、运行方式和限制见 `docs/LOCAL_HARNESS_RUNTIME.md`。

| 方向 | 协议 / 组件 | 已验收的真实 RTL 行为 | 主要边界 |
|---|---|---|---|
| CPU | OBI：CV32E20/CVE2、Ibex | 两种真实 CPU 复用同一 OBI 生成器；取指、Store/Load、byte enable、持久 RAM、回放 | 已验证的 OBI 形态；新 CPU 须重新核对全部端口和握手变体 |
| CPU | AXI4：ZipCPU | 五通道、八拍取指突发、RAM 写入和回放 | 只验收当前 RAM 路径，不接受 exclusive 或非 RAM 地址 |
| CPU | AXI4-Lite：PicoRV32 | 真实取指及两轮 Store/Load、持久 RAM、回放 | 当前 CPU 路径仅 RAM/ROM，无 MMIO/IRQ |
| CPU | Wishbone classic：PicoRV32 | 真实取指、RAM、deferred GPIO MMIO、reset 和回放 | 单 outstanding，尚无 CPU IRQ |
| CPU | Pico 原生 Ready/Valid Memory | 真实程序两轮 Store/Load、持久 RAM、回放 | 当前仅 RAM/ROM，无 MMIO/IRQ |
| IP | PULP APB3：GPIO、SPI master、Timer、I2C master | 各自独立生成的本地协议执行器及真实 GPIO pin、SPI 串行、Timer IRQ、I2C 开漏 ACK/数据与回放 | SPI 只验收 CLKDIV=1；I2C peer 当前固定一个从地址和一个字节 |
| IP | OpenTitan TL-UL：GPIO | 真实 TL-UL 寄存器与 pin/IRQ、读写错误响应和回放 | 其他 OpenTitan IP 仍待接入 |
| IP | ZipCPU Wishbone target：ziptimer | 无地址注册 ACK、计数、单周期 IRQ 与回放 | 不支持部分写；CPU IRQ 尚未绑定 |
| IP | ZipCPU AXI4-Lite target：axiluart | 独立 AW/W/B 与 AR/R 握手、TX pin 解码、RX 串行回读与回放 | 固定 8N1/波特，当前 peer 仅单字节 |

跨组件验收包括 CVE2↔PULP GPIO A↔GPIO B 双向多轮中断链，以及 CVE2→PULP SPI/OpenTitan GPIO/PULP Timer/ZipCPU Timer/PULP I2C→CVE2 RAM 数据链。I2C 原生 IRQ 已绑定 CPU 输入。每条链在独立 CPU/IP harness 中运行，Router 只转交真实 RTL 输出，不组合 Bus/Crossbar。testcase 内进程、RAM、事务和 pending 状态连续保存；显式 reset 才按策略清理。

生成器可处理已声明的协议形态和局部变体，尚不能凭协议名称无检查地接入任意同协议 RTL。UART RX 当前在构造会话时选择，I2C 从设备字节当前固定为 `0xA5`；这两个实例证明真实外部 peer 与数据回流，尚未证明 Genome 对其外部字节的自动变异。其他 OpenTitan IP、更多串行模式及 CPU 中断链仍需分别验收。
