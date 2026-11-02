# 多组件方案五：候选设计对比与测试案例

生成时间：2026-06-17

本文单独整理两部分内容：

```text
1. 用户列出的 RFUZZ / DirectFuzz / HW-Fuzz / SymbFuzz 相关设计，与 XiangShan XSTop 类系统级顶层的相似性和差异；
2. 方案五在多组件场景下如何运行，以及值得优先测试的案例。
```

## 1. 设计与 XSTop 的关系

### 1.1 判断标准

一个设计是否接近 XiangShan `XSTop`，主要看：

```text
1. 是否有真实 DUT system top；
2. system top 下是否集成 core、cache、bus、debug、interrupt、memory/peripheral interface；
3. 是否存在多个组件之间的协议连接；
4. top 输入是否主要代表系统级外部环境；
5. 是否需要 TestHarness、memory model、peripheral model 才能运行。
```

### 1.2 总体分类

| 类别 | 代表设计 | 和 XSTop 相似度 | 适合方案五的方式 |
|---|---|---:|---|
| 系统级 top / generator | Rocket-Chip、OpenTitan top-level | 高 | 用方案五做协议感知环境模型 |
| CPU core | Ibex、CVA6、Sodor、Mor1kx | 中 | 约束 memory/debug/interrupt/bus 输入 |
| 多个分列 IP | OpenTitan `hw/ip/*` | 中 | 自己搭 multi-IP harness，同时驱动多个组件 |
| 单外设 IP | SPI、I2C、UART、PWM | 低 | 做单 IP 协议/寄存器/状态机约束 |
| 加密/安全 IP | AES、HMAC、KMAC、Alert Handler、Timer | 低到中 | 单 IP 或 multi-IP 组合 |
| DSP datapath | FFT | 低 | 做 streaming/datapath 约束 |

### 1.3 逐项说明

#### Rocket-Chip

Rocket-Chip 最接近 XiangShan `XSTop`。

它不是简单单个 core，而是 generator，可以生成包含：

```text
Rocket core / tile
cache
TileLink bus
debug
interrupt
memory / MMIO interface
TestHarness
```

的系统级 RTL。

它适合做：

```text
raw bits
  -> memory/cache/TileLink/debug/interrupt environment model
  -> Rocket system top
```

优点：

```text
系统层级完整
适合多核/cache/bus/memory 强耦合场景
研究说服力强
```

缺点：

```text
构建和生成流程重
RFuzz 接入难度高
覆盖率口径和 instrument 成本高
```

#### OpenTitan top-level

OpenTitan top-level 与 `XSTop` 相似，但它更像安全 MCU SoC，而不是高性能 CPU subsystem。

它包含：

```text
Ibex core
TL-UL bus
AES/HMAC/KMAC 等 crypto IP
Timer/PLIC/Alert Handler
UART/SPI/I2C/GPIO 等外设
SRAM/ROM/flash controller
debug/reset/power/security subsystem
```

适合做：

```text
raw bits
  -> TL-UL / interrupt / alert / peripheral environment model
  -> OpenTitan top-level
```

优点：

```text
真实 SoC
IP 多，协议清晰
比 Rocket-Chip 更适合多 IP 组合实验
```

缺点：

```text
完整 top 构建仍然较重
不是多核 CPU/cache coherence 场景
```

#### OpenTitan IP 层

OpenTitan `hw/ip/*` 不是一个天然的 `XSTop` 式统一 fuzz top，而是多个真实 IP 分列。

这反而很适合用户当前的想法：

```text
不要直接使用已有大 top；
自己构造一个 scheme5_multi_ip_harness；
把多个 IP 接起来；
由统一 harness 协调驱动多个组件。
```

可选组件包括：

```text
aes
hmac
kmac
uart
i2c
spi_host
spi_device
rv_timer
rv_plic
alert_handler
sram_ctrl
dma
tlul
```

适合做：

```text
raw bits
  -> multi-IP scenario decoder
  -> bus transaction + IP config + data stream + interrupt + alert
  -> multiple OpenTitan IPs
```

优点：

```text
工程可控
多组件关系明确
可以逐步增加组件数量
```

缺点：

```text
组件关系主要是控制级/事务级，不是多核 cache coherence 那种强耦合。
```

#### Ibex / CVA6 / Sodor / Mor1kx

这些更接近 CPU core 级 target。

适合做：

```text
raw bits
  -> instruction/data memory response
  -> interrupt/debug/error/reset
  -> CPU core top
```

它们与 `XSTop` 的区别是：

```text
没有完整 SoC 层级
没有大量独立 peripheral
通常没有复杂系统级 bus fabric
```

其中：

```text
Ibex：小型 RISC-V core，最适合快速验证；
CVA6：更复杂 core，工程成本高于 Ibex；
Sodor：教学 core，适合 sanity check；
Mor1kx：OpenRISC core，可作为非 RISC-V CPU 对照。
```

#### SPI / I2C / UART / PWM

这些是单外设 IP。

适合做：

```text
raw bits
  -> 合法寄存器配置
  -> 合法协议帧
  -> 状态机输入
  -> 单 IP
```

例如：

```text
UART: start/data/parity/stop bit
SPI: CS/CLK/MOSI/MISO transaction
I2C: start/address/ack/data/stop
PWM: period/duty/enable/change-duty
```

它们适合证明“协议约束比随机 pin 更有效”，但不足以证明多组件协调。

#### AES / HMAC / KMAC / Timer / Alert Handler

这些是 OpenTitan 里的真实 IP。

单独测试时，它们是单 IP target；组合起来时，可以形成多组件方案五实验。

典型关系：

```text
bus 写配置
IP start
IP busy/done
status/interrupt
alert/error
bus read/clear
```

适合做 multi-IP 组合。

#### FFT

FFT 是 DSP datapath，不是 CPU/SoC。

适合做：

```text
raw bits
  -> 合法 streaming frame
  -> valid/ready/sync/data pattern
  -> FFT datapath
```

它更适合验证 streaming 输入约束，不适合作为系统级多组件案例。

## 2. 多组件方案五如何运行

### 2.1 Baseline 的问题

baseline 如果直接把 raw bits 打到多个组件输入上，通常是：

```text
raw bits
  -> component A pins
  -> component B pins
  -> component C pins
  -> bus pins
  -> interrupt pins
```

这些输入彼此独立随机，容易出现：

```text
response 没有对应 request
valid/ready 没有因果关系
interrupt 没有 pending source
alert 没有 sender
IP 没有配置就 start/done
DMA/CPU/memory 访问顺序不一致
```

因此大量测试停留在无效状态或不可达路径。

### 2.2 方案五的多组件结构

方案五改成：

```text
RFuzz raw 0/1 bit string
  -> scenario decoder
  -> protocol/state coordinator
  -> component drivers
  -> multi-component DUT
```

也就是：

```text
raw bits 决定想探索什么场景；
harness 根据当前系统状态把它投影为合法输入；
多个组件收到的是同一个系统场景下相互协调的信号。
```

### 2.3 harness 维护的状态

多组件 harness 至少应该维护：

```text
pending bus request table
memory model
IP register shadow state
interrupt pending/clear state
alert source/ack/escalation state
DMA active/done/error state
response latency counters
reset/boot phase
```

如果是多核/cache 场景，还需要：

```text
core/hart id
shared memory state
cache line ownership 或简化的 line state
outstanding transaction id
load/store ordering state
```

### 2.4 fuzzer 变异什么

fuzzer 仍然变异原始 0/1 bit 串。

但 bit 串不直接等于 DUT pins，而是解释成：

```text
scenario_id
target_component
operation_type
address_region
data_pattern
burst_length
response_latency
backpressure_pattern
interrupt_timing
alert_injection
error_injection
```

因此方案五不是取消随机性，而是把随机性从低层 pin 提升到高层 scenario。

### 2.5 怎么保证约束成立

harness 使用状态机和投影规则保证：

```text
只有存在 request 时才生成 response
只有 handshake 成立后才推进 transaction
只有 IP configured 后才允许 start
只有 done/pending 后才允许 read result 或 clear interrupt
只有 alert source 活跃后才允许 alert ack/escalation
memory response 的 id/data/last 对应之前的 request
```

简短地说：

```text
raw bits 决定“想做什么”；
harness 决定“在当前状态下怎样合法地做”。
```

### 2.6 多组件方案五希望提高的覆盖区域

主要包括：

```text
bus arbitration
request-response state machine
IP configuration sequence
start/busy/done/status machine
interrupt pending/clear path
alert classification/escalation path
DMA/shared memory contention
memory latency/backpressure/timeout path
error injection/recovery path
cross-component ordering path
```

## 3. 值得测试的案例

### 3.1 OpenTitan: AES + Timer + Alert Handler + bus

目标：

```text
验证多 IP 配置、状态机、interrupt、alert 之间的控制级协调。
```

组件：

```text
AES
rv_timer 或 aon_timer
alert_handler
simple TL-UL-like bus driver
small memory/data buffer
```

scenario：

```text
1. 配置 AES key/data/mode；
2. start AES；
3. timer 在 AES busy/done 附近触发 interrupt；
4. 低频注入 alert；
5. bus 读取 AES status/result；
6. clear interrupt/alert；
7. 重复不同 mode、data pattern、delay。
```

适合覆盖：

```text
AES control/status
bus register access
timer compare/interrupt
alert receive/classify/clear
cross-IP event ordering
```

优点：

```text
工程可控，适合作为第一个 multi-component scheme5 实验。
```

### 3.2 OpenTitan: DMA + SRAM + Timer/PLIC + CPU-like master

目标：

```text
构造更强的共享资源竞争关系。
```

组件：

```text
DMA
SRAM controller 或 memory model
rv_timer
rv_plic
CPU-like bus master
TL-UL/simple bus
```

scenario：

```text
1. CPU-like master 配置 DMA descriptor；
2. DMA 对 SRAM 发起 read/write；
3. CPU-like master 同时访问相同或相邻地址；
4. bus 产生 backpressure；
5. timer/PLIC 在 DMA active 时触发 interrupt；
6. 检查 DMA done/status/interrupt clear。
```

适合覆盖：

```text
shared memory contention
bus arbitration
DMA active/done/error
interrupt pending/clear
address boundary/alignment/burst
```

这个案例比 AES/Timer/Alert 更接近“多个组件互相影响”。

### 3.3 OpenTitan top-level: Ibex + TL-UL + peripheral + interrupt

目标：

```text
从自定义 multi-IP harness 过渡到真实 SoC top。
```

组件：

```text
top_earlgrey 或裁剪 top/subsystem
Ibex
TL-UL xbar
timer/PLIC
AES/HMAC/KMAC/UART/SPI 等 peripheral
memory/ROM/SRAM model
```

scenario：

```text
1. raw bits 生成程序/指令或 MMIO transaction；
2. Ibex 通过 bus 配置 peripheral；
3. peripheral 完成后触发 interrupt/alert；
4. harness 提供合法 memory/peripheral response；
5. 低频注入 bus error/debug/interrupt。
```

适合覆盖：

```text
CPU-to-peripheral path
TL-UL bus path
interrupt delivery
software-visible status path
SoC-level reset/clock/error path
```

### 3.4 Rocket-Chip: DualCore + cache + TileLink + memory

目标：

```text
验证多核/cache/bus/memory 的强耦合场景。
```

组件：

```text
two Rocket cores
L1 I/D cache
coherent bus / TileLink
memory model
interrupt/debug
```

scenario：

```text
1. core0 store addr X；
2. core1 load addr X；
3. 两个 core 访问同一 cache line；
4. 触发 cache miss/refill；
5. memory model 插入延迟/backpressure；
6. 低频 interrupt/debug；
7. 观察 coherence/refill/arbitration/replay 路径。
```

适合覆盖：

```text
cache miss/refill
coherence transaction
load/store ordering
bus arbitration
memory response latency
multicore interrupt/debug
```

这是最接近“多个 CPU core 同时驱动并协调”的案例，但工程成本最高。

### 3.5 Sodor: two cores + shared memory + arbiter

目标：

```text
用简单 CPU core 快速验证多 core/shared memory 方案五思想。
```

组件：

```text
two Sodor cores
shared memory model
simple arbiter
timer/interrupt model
```

scenario：

```text
1. core0/core1 执行短指令序列；
2. 两个 core 访问共享地址；
3. arbiter 插入 stall；
4. memory model 返回有因果关系的数据；
5. timer interrupt 打断其中一个 core。
```

适合覆盖：

```text
basic pipeline stall
load/store
branch/flush
shared memory arbitration
simple interrupt
```

这个案例工程成本低，但研究说服力弱于 OpenTitan/Rocket-Chip。

## 4. 推荐顺序

按“工程可控 + 能体现多组件关系”的平衡：

```text
1. OpenTitan: AES + Timer + Alert Handler + bus
2. OpenTitan: DMA + SRAM + Timer/PLIC + CPU-like master
3. Sodor: two cores + shared memory + arbiter
4. OpenTitan top-level/subsystem
5. Rocket-Chip: DualCore + cache + TileLink + memory
```

按“最接近用户多 core 理想场景”：

```text
1. Rocket-Chip DualCore/cache/TileLink
2. Sodor two-core 自组实验
3. OpenTitan DMA/SRAM/Timer 组合
```

按“最快做出可运行结果”：

```text
1. OpenTitan AES/Timer/Alert 组合
2. OpenTitan 单 IP 到 multi-IP 逐步扩展
3. Sodor two-core shared memory
```

最终建议：

```text
先用 OpenTitan IP 组合证明 multi-component scheme5 的可行性；
再用 Sodor/Rocket-Chip 扩展到 multi-core/shared-memory 强耦合场景。
```
