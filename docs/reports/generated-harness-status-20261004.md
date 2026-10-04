# 自动生成独立 Harness：2026-10-04 能力状态

本报告只统计固定源码、生成式本地 harness、真实 RTL 行为和新进程回放共同支持的能力。协议目录中的候选不自动取得运行等级。详细输入归属、运行方式和限制见 `docs/LOCAL_HARNESS_RUNTIME.md`。

| 方向 | 协议 / 组件 | 已验收的真实 RTL 行为 | 主要边界 |
|---|---|---|---|
| CPU | OBI：CV32E20/CVE2、Ibex | 两种真实 CPU 复用同一 OBI 生成器；取指、Store/Load、byte enable、持久 RAM、回放 | 已验证的 OBI 形态；新 CPU 须重新核对全部端口和握手变体 |
| CPU | OBI：CVE2 RV32E 参数变体 | 仅新增 profile/源码锁/闭包，复用生成器并通过真实 Store/Load、byte enable 与 fresh replay | 证明同 CPU 参数复用；不等于新 CPU 型号的 profile-only 验收 |
| CPU | AXI4：ZipCPU | 五通道、八拍取指突发、RAM 写入和回放 | 只验收当前 RAM 路径，不接受 exclusive 或非 RAM 地址 |
| CPU | AXI4-Lite：PicoRV32 | 真实取指及两轮 Store/Load、持久 RAM、回放 | 当前 CPU 路径仅 RAM/ROM，无 MMIO/IRQ |
| CPU | Wishbone classic：PicoRV32 | 真实取指、RAM、deferred GPIO MMIO、reset 和回放 | 单 outstanding，尚无 CPU IRQ |
| CPU | Pico 原生 Ready/Valid Memory | 真实程序两轮 Store/Load、持久 RAM、回放 | 当前仅 RAM/ROM，无 MMIO/IRQ |
| IP | PULP APB3：GPIO、SPI master、Timer、I2C master | 各自独立生成的本地协议执行器及真实 GPIO pin、SPI 串行、Timer IRQ、I2C 开漏 ACK/数据与回放 | SPI 只验收 CLKDIV=1；I2C 限固定从地址和单字节响应，字节值可变异 |
| IP | OpenTitan TL-UL：GPIO、RV Timer、SPI Host、I2C、UART、SPI Device | GPIO pin/IRQ、Timer 计数/IRQ、SPI Host 受限 4 字节 mode-0 RX、I2C 开漏单字节、UART 串行，以及 SPI Device 单线 JEDEC/上传均来自真实 RTL 并可 replay | SPI Device 的 CPU 轮询数据链已验收，ISR 尚未验收；各串行模式仅按已验收子集计；Timer 与 I2C 的 CPU 中断入口未验收 |
| IP | ZipCPU Wishbone target：ziptimer | 无地址注册 ACK、计数、单周期 IRQ 与回放 | 不支持部分写；CPU IRQ 尚未绑定 |
| IP | ZipCPU Wishbone target：wbuart | 19/19 端口、word 地址、byte select、注册 ACK；真实串行 TX/RX、原生 RX IRQ 和两种源值回放 | 固定 8N1、单字节；CPU 数据链已验收，CPU ISR 未验收 |
| IP | ZipCPU AXI4-Lite target：axiluart | 独立 AW/W/B 与 AR/R 握手、TX pin 解码、RX 串行回读与回放 | 固定 8N1/波特，当前 peer 仅单字节 |

跨组件验收包括 CVE2↔PULP GPIO A↔GPIO B 双向多轮中断链、CVE2↔OpenTitan UART/ZipCPU wbuart↔CVE2 RAM 双向数据链，以及 CVE2→PULP SPI/OpenTitan GPIO/OpenTitan RV Timer/OpenTitan I2C/OpenTitan SPI Host/OpenTitan SPI Device/PULP Timer/ZipCPU Timer/PULP I2C/ZipCPU AXI4-Lite UART→CVE2 RAM 数据链。I2C 与 ZipCPU wbuart 原生 IRQ 已转交 CPU 输入；这两个程序仍轮询状态，尚未验收 CPU 的中断处理程序。SPI Device 当前 CPU 轮询设备真实 IRQ_STATE 并读取 FIFO/SRAM，未交付 CPU ISR。OpenTitan RV Timer 当前由 CPU 读取真实中断状态，尚未将 IRQ 交付 CPU。每条链在独立 CPU/IP harness 中运行，Router 只转交真实 RTL 输出，不组合 Bus/Crossbar。testcase 内进程、RAM、事务和 pending 状态连续保存；显式 reset 才按策略清理。

通用 `local_harness.v2` 已有三类寄存器观察模板：TL-UL 的 GPIO、RV Timer、SPI Device，APB3 的 PULP GPIO、Timer，以及 Wishbone 的 ZipCPU Timer、wbuart。各组 profile-only 请求都通过真实寄存器交易与 fresh replay；APB3 还验收动态 GPIO pin→真实 IRQ，并有两个独立 GPIO 的 A 真实输出→B Bound Input→B 真实 IRQ 与 fresh replay。逐字段输入归属严格区分 `fixed_inputs`、`environment_bindings` 和 `bound_bindings`。APB3 当前限 12 位地址、4096 字节窗口和 32 位数据；Wishbone 通用模板要求真实 `stall` 输出，且目前只接收固定物理输入。超出运行时形状的请求在规划阶段拒绝。TL-UL 通用 artifact 上的 UART 8N1 与 SPI mode-0 单线 peer 均由 v2 tuning 声明引脚、环境源、节拍和启动寄存器写入，进入 artifact 身份并由通用 factory 创建 session。UART 已在 OpenTitan UART 验收真实 RX/TX、IRQ 与 fresh replay；SPI 已在 OpenTitan SPI Device 验收真实 JEDEC MISO、上传 IRQ/SRAM 与 fresh replay。当前分别限单字节和单帧；原专用串行 session 继续保留。

生成器可处理已声明的协议形态和局部变体，尚不能凭协议名称无检查地接入任意同协议 RTL。ZipCPU UART 和 OpenTitan UART RX 已支持 DependencyGraph 引导的 Genome 变异；`0x35→0xA6` 两种源值经真实串行接收、CPU MMIO 回读和 RAM 写入，均匹配 fresh replay。CPU 写入 `0x41` 也经真实 UART TX 引脚解码。PULP I2C 的 `peer_response` 也由 8 位 Genome 源选择；`0x5A` 和 `0xA6` 分别经真实串行传输、CPU MMIO 回读并存入 RAM，两份证据可重放。I2C 仍限固定地址 `0x42` 的单字节响应。OpenTitan SPI Device 的本地寄存器、单线串行和 CPU 轮询读取真实上传 FIFO/SRAM 的多组件链已验收；更多串行模式及 CPU 中断处理程序仍需分别验收。OpenTitan I2C 的 CPU 程序轮询 IRQ 状态，CPU IRQ 固定为 0。

v2 寄存器观察 artifact 现可按协议类型自动创建 TL-UL、APB3 或 Wishbone session，并从多个 artifact 的物理输入声明编译 OwnershipMap 和精确等宽的真实输出 Binding。固定值、环境源、Bound Input 各有唯一归属；ScenarioRunner 仍核对绑定的真实输出路由。该入口的合同用例 4/4、PULP APB3 双 GPIO 真实绑定用例 2/2 通过：A 的真实 `gpio_out` 持续转交 B 输入，B 的真实 IRQ 随后产生，fresh replay 一致。串行抽象帧和 CPU 协议 session 的自动场景装配尚未纳入此入口。

声明式 SPI peer 的主线焦点验收 5/5 通过，其中两项使用真实 OpenTitan SPI Device：一项从 artifact 选择 JEDEC peer 并观察真实 MISO，一项由 artifact 指定上传帧前缀、32 位 Fuzzable Source、启动配置和节拍，观察真实 IRQ、状态和 SRAM。两项均完成 fresh replay。外部 master 仍限 mode-0 单线及已验收的单帧形态。

用户特别关注的三个 CPU 中，Ibex 已有生成式 OBI 真实运行与回放；CVA6 的固定源码与 232 文件 Verilator 读取闭包已通过 elaboration 和全库源码锁校验，现可从经验证 filelist 展开生成单个打包 64 位/ID4 AXI4 顶层 wrapper 与 runtime top，顶层 lint 无错误。CVA6 生成式 driver 已编译运行并观察到真实 ARVALID 取指请求；AXI 数据响应、程序执行和回放尚未验收，不能列为 RTL operational，详见 `docs/reports/cva6-generated-axi4-feasibility-20261005.md` 和 `docs/superpowers/plans/2026-10-05-cva6-packed-axi4-local-runtime.md`；BOOM 当前只有接口描述候选，缺少已验收的完整本地生成式运行路径，按不可执行 CPU 跳过真实验收并记录缺口。五类协议的 AXI4 首个真实生成式实例使用 ZipCPU，和早期设计计划中的 CVA6 不同。
