# OpenTitan 独立外设扩展设计

日期：2026-09-28。授权来源：用户要求继续接入 OpenTitan 系列其他部件。本设计沿用现有多组件独立 harness、Fuzzable Source / Bound Input、Dependency Path、Dataflow Router、Dependency Scheduler 和 testcase 内持续状态；不构造具体 SoC。

## 范围与顺序

本地已有真实 OpenTitan GPIO、UART harness。新增顺序为 SPI Host、I2C、RV Timer；SPI Device 在前述阶段稳定后单独设计，因其外部时钟域、异步 RAM、TPM、DFT 与 passthrough 端口需要独立边界。当前 vendor 树无 PWM RTL，记录为 `skipped_unavailable`。每一种 IP 都须分别交付可运行 RTL、本地协议测试、跨组件链和可回放证据；不能用结构编译替代行为验收。

## SPI Host 边界

`spi_host` 在自己的持久进程中运行。Wrapper 只把测试系统的合法单笔 MMIO 请求转为 TL-UL，并固定未纳入首期场景的 alert、RACL、passthrough 输入；不产生 Host 的 SCK、CS、RXDATA 或 IRQ。Host 原生 `cio_sck_o`、`cio_csb_o`、`cio_sd_o[3:0]` 与 `cio_sd_en_o[3:0]` 均从真实 RTL 观察，`cio_sd_i[1]` 由可变外部 SPI peer 驱动。标准单线模式中 Host MOSI 为 SD0，MISO 为 SD1。

SPI peer 持续保存帧、位索引、CS 状态和上一次实际 SCK。CPOL=0、CPHA=0 首期中，只有真实 CS 有效且真实 SCK 采样边沿到来时才推进位索引；下一位在采样前稳定。peer 的可变源为每轮 4 字节 payload，可变逻辑延迟必须仍满足局部 SPI 时序。它不得直接赋值 Host 的 FIFO、RXDATA、状态或 IRQ。

CPU MMIO write → Router → SPI Host TL-UL 寄存器事务。首轮通过 CONTROL、CONFIGOPTS、EVENT_ENABLE、INTR_ENABLE 配置，等待 STATUS.READY 后写 COMMAND，四字节只读命令 `LEN=3,DIRECTION=1,SPEED=0`。Host 真实 SCK/CS 驱动 peer 送入数据，RXDATA 的 32 位字节序应为 `b0 | b1<<8 | b2<<16 | b3<<24`。`spi_event` 为状态型 IRQ，读取 RXDATA 或实际改变事件条件后观察其下降；不得用虚构的 W1C 清除。第二轮在同一个 testcase、同一 Host RTL 实例中进行，不能 reset，FIFO 与寄存器状态持续。

Host RXDATA 的真实 MMIO response 通过 Router 绑定 CPU rdata；真实 `intr_spi_event_o` 通过声明的中断绑定进入 CPU。Scheduler 只决定何时能注入外部 peer 位和何时运行下一个局部 step，不预测 DONE、RXDATA 或 IRQ。任何 Host 异常时刻产生的 IRQ 与协议错误原样记录，checker 再判定性质；不能被 generation constraint 过滤。

## 后续 IP

I2C 首期采用 Controller 模式、单 master、外部从机 peer。peer 只在真实开漏 SCL/SDA 线与协议允许的 ACK/data 时隙驱动低电平；上拉为环境约束，clock stretch 作为有界可变事件。I2C 需另行锁定 FIFO/RAM 依赖并完成协议验收后，才进入 CPU 跨组件链。

RV Timer 仅有 TL-UL 与 `intr_timer_expired_hart0_timer0_o`，首期链为 CPU 真实写 CFG/COMPARE/CTRL → Timer 持续计数 → 真实 IRQ → CPU ISR 读状态、更新比较值 → IRQ 清除，再重复一轮。Timer 没有外部 source，因此不用于证明 IP 外部输入→CPU 方向。

## 源码身份与失败边界

各 IP 需记录 vendor revision、完整 Verilator 文件闭包、include 路径、wrapper 和本地进程源码哈希；`configs/soc/sources.lock.json` 与 component profile 必须与实际编译一致。每个 testcase 从新 RTL 初态开始，testcase 内不重复 reset。源输入与 Bound Input 的 ownership 声明在 RTL 启动前编译，已由真实输出或持久状态决定的值不可再随机。输运命令复用 execution ID/sequence 幂等语义；失去确认的效果标为 `uncertain_effect`。物理 wall cut 只要求已记录的确定语义前缀可重放。

## 验收

1. SPI Host 独立 harness 真正编译和运行，合法 TL-UL byte-enable、等待、错误响应、局部时序受检查；可观察真实 SCK/CS、32 个采样位、RXDATA、IRQ 上升和下降。
2. Ibex＋SPI Host 两份独立 RTL 在同一 testcase 中连续完成两轮；CPU 写入的配置与 COMMAND、外部 peer payload、Host RXDATA、CPU 消费的 rdata、ISR 和持久 RAM 写入逐事务对应。
3. 变异 CPU 程序和外部 peer payload 都能改变真实下游观察；切断 IRQ 或 RXDATA 绑定、伪造 response 身份时 checker 拒绝完整链。
4. 保存完整 Genome、source 选择/实际采样、源码身份、事件轨迹和状态演化；独立进程从初态全量回放匹配。物理超时仅验证语义前缀。
5. RV Timer 与 I2C 各自按相同的“独立运行、真实输出绑定、双轮持续状态、切边负例、完整回放”门槛验收；未完成的 IP 明确标为 `not_run`，不能从 SPI Host 通过外推。
