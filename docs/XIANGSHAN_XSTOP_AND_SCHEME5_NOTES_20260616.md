# XiangShan XSTop 层级与方案五思路记录

生成时间：2026-06-16

本文整理关于 XiangShan `XSTop`、大型 CPU/SoC RTL 层级、系统级接口，以及方案五如何用于完整 top 与子模块级 fuzz 的讨论。

## 0. 文档主线

本文要回答四个问题：

```text
1. XiangShan 的 XSTop 是什么层级；
2. XSTop、CPU core、SoC top、TestHarness 之间有什么区别；
3. 用户列出的 RFUZZ/DirectFuzz/HW-Fuzz/SymbFuzz target 和 XSTop 类设计有什么相同和不同；
4. 方案五在多组件场景下应该怎样定义、怎样驱动、哪些案例值得测试。
```

最终结论先写在前面：

```text
XSTop/Rocket-Chip 这类设计适合做系统级方案五：
  raw bits -> 协议感知环境模型 -> system top

OpenTitan IP 层适合做自定义多组件方案五：
  raw bits -> 统一 multi-IP harness -> 多个 IP 同时协同运行

Ibex/CVA6/Sodor 适合做 CPU core 级方案五：
  raw bits -> memory/debug/interrupt/bus 约束 -> core top

SPI/I2C/UART/PWM/AES/HMAC/KMAC/FFT 适合做单 IP 协议约束：
  raw bits -> 合法协议/寄存器/streaming 序列 -> IP block
```

方案五在多组件场景下的核心不是“随机驱动更多模块”，而是：

```text
用一个统一 harness 维护跨组件状态、协议因果关系和时序关系；
由 fuzzer 的 0/1 bit 串选择场景、地址、延迟、冲突、错误、interrupt/alert；
再同时生成多个组件的输入，使系统进入更真实的交互路径。
```

## 1. XSTop 到底是什么

`XSTop` 是 XiangShan 生成 RTL 的系统级顶层模块。

它不是裸 CPU core top，也不是完整仿真环境 `TestHarness`。更准确地说：

```text
XSCore / core pipeline
  = CPU 核心微架构级别

XSTile
  = core + L1 cache + core-local wrapper

XSTop
  = tile/core + cache/bus/debug/interrupt/reset/memory/peripheral 接口的系统级封装

TestHarness / 板级环境
  = XSTop + memory model + 外设模型 + clock/reset/debug/interrupt 仿真环境
```

所以 `XSTop` 高于 CPU core 级别，低于完整仿真 `TestHarness`/板级环境级别。

## 2. 真实 XiangShan RTL 与 XSTop 的关系

可以这样理解：

```text
XSTop 是 XiangShan 生成 RTL 的真实顶层模块；
真实 CPU 核心微架构主要位于 XSTop 例化的子模块中；
XSTop 的作用是集成 core/tile、cache、bus、debug、interrupt、reset、memory/peripheral 接口等系统级逻辑，并协调它们之间的连接关系。
```

因此，不能说 `XSTop` 只是假的壳或 testbench。它是 DUT 层级的一部分。

但如果关心真正执行指令的流水线逻辑，主体通常在 `XSTop` 下面更深的 `tile/core/frontend/backend/LSU/CSR` 等子模块中。

## 3. 为什么 SoC/系统级 top 仍然有输入输出

“完整系统”不等于“没有输入输出”。系统级 top 仍然需要连接外部世界：

```text
clock/reset
external interrupt
debug/JTAG
boot mode / boot address
memory response
peripheral response
trace/difftest/status
```

例如 CPU 执行一次 load：

```text
core 执行 load
  -> DCache miss
  -> L2 / bus 发 read request
  -> XSTop 输出 AXI/TileLink read request
  -> 外部 memory model 接收请求
  -> 几拍后 memory model 输入 read data response
  -> XSTop 把 response 送回 cache/core
  -> load 指令完成
```

所以 `XSTop` 自己通常不包含真实 DRAM、真实外设、真实 debugger 和完整板级环境。这些由更外层的 `TestHarness` 或自定义 harness 提供。

## 4. XSTop 协调的系统级结构

一个大型 CPU RTL top 通常组织如下：

```text
XSTop / TestHarness / ChipTop
  |
  +-- CPU core / tile
  |     +-- frontend
  |     +-- decode
  |     +-- rename / issue / execute
  |     +-- load-store unit
  |     +-- csr / interrupt / debug
  |
  +-- L1 ICache / DCache
  +-- L2 cache / cache adapter
  +-- bus fabric, e.g. TileLink / AXI
  +-- memory model or memory port
  +-- interrupt/debug/reset/clock wrapper
  +-- difftest / trace / performance monitor
```

`XSTop` 的职责是把这些设计部件接成一个系统：

```text
reset 信号分发给 core/cache/debug/bus
interrupt controller 输出接到 core interrupt input
core/cache memory request 接到 bus
bus 决定访问 memory 还是 peripheral
debug module 接到 core debug interface
外部 AXI/TileLink 端口暴露给外部世界
trace/difftest 信号从 core 导出
```

## 5. cache、bus 等是否有自己的模块

通常有。

例如 cache 可能有：

```text
ICache
DCache
L2Cache
CacheWrapper
CacheBridge
```

bus 可能有：

```text
TileLink crossbar
AXI bridge
TLToAXI
AXI4Xbar
BusWrapper
```

debug/interrupt/reset 也通常有自己的模块或子系统。

但它们一般是 `XSTop` 下面的子模块，不是整个项目的唯一 top。一次具体仿真/综合/fuzz 任务通常指定一个 top，但真实 RTL 项目可以有多个候选 top：

```text
CoreTop
TileTop
ChipTop
XSTop
TestHarness
FPGATop
FormalTop
```

哪个模块是 top，取决于实验目标。

## 6. 协调关系是通用的还是设计特定的

两者都有。

RISC-V ISA 只规定指令语义、异常/中断架构行为、CSR/特权级等，不规定 cache、bus、frontend/backend、debug module、memory system 怎样实现。

通用部分包括：

```text
reset 后进入稳定启动流程
boot address / reset vector 稳定
memory request 之后才有 response
AXI/TileLink valid-ready 等协议规则
interrupt/debug 不应每拍随机乱跳
合法 RISC-V 指令流更容易推进 pipeline
```

设计特定部分包括：

```text
top 端口名
bus 类型
信号宽度
reset 极性
debug/interrupt 接法
cache/MMIO 地址空间
具体握手 channel
哪些输入是外部环境，哪些是 DUT 输出
```

因此方案五应该抽象成：

```text
通用 scenario 生成 + 每个设计专用 signal/protocol adapter
```

## 7. 方案五在 XSTop 上的位置

方案五不应该简单随机 `XSTop` 的所有 input pin。

更合理结构是：

```text
RFuzz raw 0/1 bit string
  -> scheme5 protocol-aware harness / environment model
  -> XSTop 外部端口
  -> XSTop 内部 core/cache/bus/debug/interrupt
```

harness 根据 raw bit 生成：

```text
memory latency
bus grant/ready
read/write response
interrupt timing
debug request
reset phase
instruction/memory data pattern
cache miss/hit pattern
exception/error injection
```

也就是说，fuzzer 仍然探索 bit 串，但 bit 串不是直接等于 DUT pins，而是控制环境模型的策略。

## 8. 方案五的两种粒度

方案五可以分成两条线。

### 8.1 系统级方案五

目标是完整 `XSTop`：

```text
scheme5_xstop_harness
  |
  +-- XSTop
       |
       +-- core
       +-- cache
       +-- bus
       +-- debug
       +-- interrupt
```

这个方向能说明方案五可以协调完整 CPU/SoC wrapper 的外部环境，覆盖完整层级。

约束重点：

```text
memory/bus response
interrupt/debug/reset 时序
外部环境模型
cache/memory/peripheral 访问响应
```

缺点是复杂度高，需要理解 `XSTop` 的端口和协议。

### 8.2 子模块级方案五

目标是拆开测试 `XSTop` 下的模块，例如：

```text
scheme5_xscore_harness -> XSCore
scheme5_dcache_harness -> DCache
scheme5_icache_harness -> ICache
scheme5_bus_harness    -> TL/AXI bridge
```

这个方向适合先验证方案五思想，因为局部接口更清晰，输入空间更小，约束更容易写。

推荐优先顺序：

```text
1. DCache 或 ICache
2. TileLink/AXI bridge
3. LSU 或 frontend
4. XSCore
5. XSTop
```

原因是 cache/bus 有清晰协议、状态机覆盖点多、约束关系明确，比直接 fuzz out-of-order core 简单。

## 9. 子模块级测试的优缺点

优点：

```text
输入空间更小
约束关系更局部
更容易覆盖 cache/bus 等状态机
更容易做短测验证方案五收益
```

缺点：

```text
需要自己模拟上游和下游环境
可能脱离完整系统上下文
局部覆盖率提升不一定代表完整 XSTop 执行路径提升
```

因此结果表述要清楚：

```text
XiangShan 子模块级方案五测试
```

不要把它直接说成完整 XiangShan 系统级测试。

## 10. 最终研究表述

方案五可以表述为：

```text
bit-string guided protocol-aware environment modeling
```

也就是：

```text
fuzzer 仍然探索原始 0/1 bit 串；
但 bit 串不直接打到 RTL pin；
而是控制一个协议感知、有状态、有时序的环境模型；
环境模型生成合法、相关、可变化的 DUT 输入；
从而减少无效输入空间，提高进入真实执行路径的概率。
```

在小 core 上，例如 Ibex：

```text
raw bits -> signal-level projection -> ibex_core
```

在大型项目上，例如 XiangShan：

```text
raw bits -> transaction-level environment model -> XSTop 或子模块
```

这两个方向本质一致，只是约束粒度不同。

## 11. 候选 benchmark/target 分类

下面整理用户列出的 RFUZZ、DirectFuzz、HW-Fuzz、SymbFuzz 相关 target，并判断它们和 XiangShan/XSTop 这类系统级设计的关系。

核心判断标准不是“模块大不大”，而是：

```text
1. 它是单个 IP block，还是 CPU core，还是 SoC/system top；
2. 它的输入是否有明显协议/时序/状态关系；
3. 它是否能体现多个模块、多个接口、多个 agent 之间的协调；
4. 方案五能否把 raw 0/1 bit string 投影成更真实的环境激励。
```

### 11.1 总体分类

| 类别 | 代表设计 | 和 XiangShan/XSTop 的相似度 | 对方案五的价值 |
|---|---|---:|---|
| 单 IP / 外设模块 | SPI、I2C、UART、PWM、AES、HMAC、KMAC、Timer、Alert Handler、FFT | 低 | 适合做单模块协议约束，不适合体现多个组件协调 |
| CPU core 级 | Sodor、Ibex、CVA6、Mor1kx | 中低 | 适合验证 core 顶层输入约束、memory/debug/interrupt 约束 |
| SoC / generator / system top | Rocket-Chip、OpenTitan top-level | 高 | 最接近方案五的“多组件协调输入约束”目标 |

### 11.2 RFUZZ 原始 target

#### SiFive blocks: SPI / I2C

`sifive-blocks` 是 SiFive 项目中复用的 common RTL blocks。SPI、I2C 这类模块属于外设 IP block。

它们的特点：

```text
寄存器配置接口
串行协议状态机
ready/valid 或寄存器读写时序
中断/状态输出
```

适合方案五做：

```text
raw bits -> 合法寄存器访问序列 -> SPI/I2C 状态机
raw bits -> 合法传输节奏 -> start/stop/ack/data phase
raw bits -> interrupt/status 触发组合
```

但它们不是 XiangShan/XSTop 那种系统级 top。它们更适合作为“小而清晰的协议约束 benchmark”。

#### FFT

`ucb-art/fft` 是 DSP 数据通路密集型模块，不是 CPU/SoC。

它的特点：

```text
streaming input/output
valid/ready 或类似流式时序
数据窗口、同步、流水线延迟
乘法器、加法器、蝶形计算网络
```

适合方案五做：

```text
raw bits -> 合法 streaming transaction
raw bits -> input frame / sync / sample pattern
raw bits -> backpressure / latency pattern
```

它的价值是验证“约束流式输入能否比随机 pin 更快推进 datapath”，但不适合证明多组件 SoC 协调。

#### Sodor 1-stage / 3-stage / 5-stage

Sodor 是 UC Berkeley 的教学型 RISC-V microarchitecture 集合，包含不同流水线深度的简单 core。

它的特点：

```text
结构小
流水线层级清晰
memory 接口简单
适合快速实验
```

适合方案五做：

```text
raw bits -> 合法指令流
raw bits -> memory response
raw bits -> stall/flush/branch/exception 场景
```

但它太小，不能代表 XiangShan/Rocket 这种系统级复杂结构。它适合做方案五的最小 CPU sanity check。

#### Rocket Core / Rocket-Chip

Rocket-Chip 不是单纯一个 core RTL 文件，而是 SoC generator。它可以生成包含 Rocket core、tile、cache、bus、debug、interrupt、peripheral、TileLink/AXI 适配等结构的完整 RTL。

它和 XiangShan/XSTop 很接近：

```text
Rocket/BOOM tile
L1/L2 cache
TileLink bus fabric
debug/interrupt/reset
外部 memory/peripheral interface
TestHarness / ChipTop / System top
```

适合方案五做：

```text
raw bits -> TileLink/AXI memory model
raw bits -> interrupt/debug/reset scenario
raw bits -> cache miss/refill/backpressure
raw bits -> peripheral/MMIO transaction
```

在用户当前研究目标里，Rocket-Chip 是最值得关注的 target 之一，因为它可以体现“不是随机打 pin，而是用协议感知环境模型驱动系统 top”。

### 11.3 DirectFuzz 新增 target

#### UART

UART 是串行通信 IP，内部通常包括：

```text
TX/RX 状态机
baud-rate 计数器
FIFO 或 holding register
start/data/parity/stop bit 时序
interrupt/status register
```

适合方案五做：

```text
raw bits -> 合法 UART frame
raw bits -> baud / parity / stop 配置
raw bits -> RX/TX FIFO 压力
raw bits -> interrupt/status 组合
```

它是非常好的单 IP 协议 benchmark，但不是系统级多模块 benchmark。

#### PWM

PWM 是寄存器控制型时序模块，内部通常包括：

```text
period counter
duty compare
enable/config register
output waveform state
```

适合方案五做：

```text
raw bits -> 合法 period/duty 配置
raw bits -> enable/disable/change-duty 时序
raw bits -> 边界 duty：0%、50%、100%
```

PWM 适合验证“配置空间约束”和“时序状态覆盖”，但规模较小。

### 11.4 HW-Fuzz 新增 OpenTitan IP

OpenTitan 的 IP 比普通外设更适合作为方案五中间层 target，因为它们属于一个真实 SoC 项目的 IP block，并且很多 IP 都有明确的寄存器接口、alert/interrupt、bus、状态机。

#### AES

AES 是加密计算和控制状态机结合的 IP。

适合方案五做：

```text
raw bits -> 合法寄存器写序列
raw bits -> key/plaintext/data_valid 流程
raw bits -> mode/operation 配置
raw bits -> start/done/interrupt/alert 场景
```

#### HMAC / KMAC

HMAC/KMAC 是 hash/authentication 相关 IP，通常包含消息输入、key 配置、吸收/压缩/完成状态。

适合方案五做：

```text
raw bits -> 合法 message stream
raw bits -> key/config/start/done sequence
raw bits -> backpressure / partial block / final block
```

#### RISC-V Timer

Timer 是典型时序/中断模块。

适合方案五做：

```text
raw bits -> compare value / counter value
raw bits -> enable/disable
raw bits -> interrupt pending/clear sequence
```

#### Alert Handler

Alert Handler 是安全/异常处理相关 IP，状态机和中断/alert 路径丰富。

适合方案五做：

```text
raw bits -> alert source pattern
raw bits -> escalation phase
raw bits -> interrupt/clear/ack sequence
```

这些 OpenTitan IP 本身仍是单 IP 或子系统级 target；如果把 OpenTitan top-level 作为 DUT，则更接近方案五理想场景：

```text
raw bits -> TL-UL bus transaction
raw bits -> CPU/peripheral/interrupt/alert coordinated scenario
raw bits -> 多 IP 之间的交互路径
```

### 11.5 SymbFuzz processor target

#### Ibex

Ibex 是小型 32-bit RISC-V CPU core，也是当前本项目已经重点做过 scheme5 的对象。

适合方案五做：

```text
instruction memory response
data memory response
interrupt timing
debug request
bus error injection
reset/fetch-enable phase
```

Ibex 的优点是 top-level 端口清晰，构建和短测成本低。缺点是它不是完整 SoC，不能充分体现多组件协调。

#### CVA6

CVA6 是更复杂的 6-stage RISC-V core，可配置性强，能用于 application-class 场景。

适合方案五做：

```text
memory/bus response model
instruction stream / exception / interrupt / debug
cache/memory latency
branch/CSR/load-store 场景
```

它比 Ibex 更接近复杂 CPU core，但仍偏 core 级。要体现系统级协调，需要额外 harness 或 SoC wrapper。

#### Rocket-Chip

Rocket-Chip 在这一组里最接近 XiangShan/XSTop，因为它不是单个裸 core，而是 generator + system top 生态。

如果用户要找“多个模块共同工作、约束它们的输入关系从而提升 fuzz 效率”的对象，Rocket-Chip 比单独 Ibex/CVA6 更合适。

#### Mor1kx

Mor1kx 是 OpenRISC 1000 processor IP core。

适合做 core-level 约束：

```text
instruction/data bus response
interrupt/debug/reset
stall/error/exception
```

但它不是 RISC-V，也不是完整 SoC。作为 CPU core benchmark 可以用，作为 XiangShan/Rocket 类系统级 benchmark 不如 Rocket-Chip/OpenTitan。

## 12. 推荐实验路线

如果目标是证明方案五的核心 insight：

```text
随机 bit 串先被投影成协议正确、状态相关、跨模块协调的激励，
从而让 DUT 更常进入真实执行路径。
```

推荐路线如下。

### 12.1 最容易产出有效结果

```text
Ibex / Sodor / UART / SPI / AES
```

原因：

```text
规模小
接口清晰
约束关系容易写
短测可以快速看到趋势
```

适合用来证明“raw pin random”和“bit-string guided projection”之间的区别。

### 12.2 最适合多组件协调 proof-of-concept

```text
OpenTitan top-level 或 OpenTitan 子系统
```

原因：

```text
真实 SoC 项目
有 Ibex core
有 TL-UL bus
有 crypto/timer/alert/interrupt/peripheral
多个 IP 之间存在真实交互
```

方案五可以生成：

```text
CPU 发起 MMIO
AES/HMAC/KMAC 接收配置和数据
timer 产生 interrupt
alert handler 响应异常
bus 返回合法 response
```

这比单独 fuzz AES 或 UART 更能体现方案五的价值。

### 12.3 最接近 XiangShan/XSTop 的复杂 CPU 系统 target

```text
Rocket-Chip
```

原因：

```text
generator 生成 system top
core/tile/cache/bus/debug/interrupt 结构齐全
TileLink/AXI 协议明确
和 XiangShan/XSTop 的层级思想接近
```

缺点是工程成本更高，构建、生成 RTL、instrument、coverage 对齐都更复杂。

### 12.4 多核/多组件协调方向

如果用户的理想场景是：

```text
多个 CPU core 或多个硬件组件同时运行；
原始 RFuzz 向多个输入随机打 bit；
方案五通过统一 harness 协调这些输入；
让多个 core/component 进入更真实的交互状态。
```

那么更合适的 target 类型是：

```text
multicore / multitile CPU
cache-coherent system
NoC / bus fabric + memory subsystem
SoC with CPU + DMA + peripheral + interrupt controller
```

候选方向：

```text
OpenTitan：多 IP SoC，适合先做多组件协调
Rocket-Chip：接近 XiangShan 的 system top/generator
BlackParrot / OpenPiton / PULP：更偏 multicore/multitile，需要额外评估工程成本
```

方案五在这类系统里的目标应写成：

```text
raw bit string
  -> coordinated multi-agent scenario
  -> protocol-correct signals
  -> multicore / multi-component DUT
```

而不是：

```text
raw bit string
  -> 每个 core/component 的 input pin 独立随机
```

## 13. 最终判断

用户列出的 target 里：

```text
最像 XiangShan/XSTop：Rocket-Chip
最适合多组件协调 proof-of-concept：OpenTitan top-level/subsystem
最适合快速验证方案五：Ibex、Sodor、UART、SPI、AES
最适合 DSP 数据流约束：FFT
最适合作为复杂 core-level 对照：CVA6、Mor1kx
```

因此，后续如果只想快速获得方案五优于 baseline 的证据，应优先选 Ibex/Sodor/IP block。

如果想证明方案五在“系统级多组件协调”上的研究价值，应优先选 OpenTitan 或 Rocket-Chip，而不是只选单个 SPI/UART/AES IP。

## 14. 用户列出设计与 XSTop 的系统化对比

本节专门回答：这些设计是和 XiangShan `XSTop` 差不多，还是更接近单 IP / core / 自定义多组件 harness。

### 14.1 对比维度

判断一个设计是否“像 XSTop”，主要看下面几项：

```text
1. 是否有一个真实 DUT system top；
2. system top 下是否集成 core、cache、bus、interrupt、debug、memory/peripheral interface；
3. 是否存在多个组件之间的协议连接；
4. top 的输入是否主要是系统级外部环境，而不是单个 IP 的普通 pins；
5. 是否需要 TestHarness/memory model/peripheral model 才能跑起来。
```

### 14.2 对比表

| 设计 | 类型 | 是否类似 XSTop | 与 XSTop 的主要差异 | 方案五使用方式 |
|---|---|---:|---|---|
| XiangShan `XSTop` | CPU subsystem/system top | 是 | 高性能 CPU 系统顶层，包含 core/tile/cache/bus/debug/interrupt 等连接 | system top 环境模型 |
| Rocket-Chip | SoC generator/system top | 很像 | 由 Chisel/generator 生成，常通过 `TestHarness`/config 选择系统形态 | system top 或 multicore/cache/bus 方案五 |
| OpenTitan `top_earlgrey` | microcontroller SoC top | 像，但不是 CPU 性能核系统 | 偏安全 MCU SoC，包含 Ibex、TL-UL bus、大量 IP、alert/interrupt | SoC top 方案五 |
| OpenTitan `hw/ip/*` | 多个分列 IP | 不像单个 XSTop，但很适合自组 | IP 分列，天然没有只服务方案五的统一 fuzz top | 自定义 multi-IP harness |
| Ibex | CPU core | 中等 | 只有 core 顶层，没有完整 SoC/cache/bus fabric | core-level memory/debug/interrupt harness |
| CVA6 | CPU core | 中等 | 比 Ibex 更复杂，但仍偏 core/subsystem，不是完整 SoC top | core-level bus/memory/interrupt harness |
| Sodor | 教学 CPU core | 低到中 | 小型教学流水线，系统层级简单 | 快速 sanity / core-level 方案五 |
| Mor1kx | OpenRISC CPU core | 中等 | CPU IP core，不是 RISC-V，不是完整 SoC | core-level 方案五 |
| SPI/I2C/UART/PWM | 外设 IP | 低 | 单 IP 状态机/寄存器控制，没有多组件系统层级 | 单 IP 协议约束 |
| AES/HMAC/KMAC/Timer/Alert Handler | OpenTitan IP | 低到中 | 单 IP 或子系统 IP，但属于真实 SoC 的组件 | 单 IP 或 multi-IP 组合 |
| FFT | DSP datapath | 低 | 数据流/流水线计算模块，不是 CPU/SoC | streaming/datapath 约束 |

### 14.3 关键区别

#### XSTop / Rocket-Chip 这类

它们已经有系统级顶层：

```text
system top
  +-- core/tile
  +-- cache
  +-- bus
  +-- debug
  +-- interrupt
  +-- memory/peripheral interface
```

方案五在这里更像“替换或增强外部环境”：

```text
raw bits
  -> protocol-aware environment model
  -> memory/bus/debug/interrupt/peripheral response
  -> existing system top
```

优点是研究说服力强，因为 DUT 本身就是复杂系统。

缺点是工程成本高，因为要理解已有 top 的生成、接口、依赖、仿真环境和覆盖率口径。

#### OpenTitan IP 层这类

它们不是一个天然的 XSTop 式统一 fuzz top，而是多个真实 IP 分列：

```text
aes
hmac
kmac
uart
i2c
spi_host
rv_timer
rv_plic
alert_handler
sram_ctrl
tlul
```

方案五在这里更像“自己搭一个多组件实验系统”：

```text
raw bits
  -> scheme5_multi_ip_harness
  -> bus transaction + IP config + data stream + interrupt + alert
  -> several IPs running together
```

这比单 IP 更能体现“多组件同时驱动”，但又比完整 Rocket-Chip/XiangShan 更容易落地。

#### 单 IP 这类

SPI/I2C/UART/PWM/AES/HMAC/KMAC/FFT 都可以做方案五，但它们主要验证的是：

```text
约束单个模块输入是否比随机 pin 更有效
```

而不是：

```text
多个组件之间的协调关系是否提升系统级覆盖率
```

所以它们适合作为小实验或 ablation，不适合作为最终多组件论证的唯一 target。

## 15. 多组件方案五如何运行

本节专门按用户当前定义重新阐述方案五：多个组件同时驱动，而不是单模块 pin 约束。

### 15.1 Baseline 的问题

如果直接把 RFuzz raw bits 打到多个组件输入上，结构通常是：

```text
raw bits
  -> component A input pins
  -> component B input pins
  -> component C input pins
  -> bus input pins
  -> interrupt input pins
```

问题是这些输入彼此独立随机，容易出现系统语义无效组合：

```text
memory response 没有对应 request
bus valid/ready 没有因果关系
IP 还没配置就 start/done 随机跳变
interrupt 没有对应 pending source
alert 没有对应 alert sender
DMA/CPU/cache 访问顺序没有一致状态
```

这种随机性虽然覆盖输入 bit 空间，但大量时间消耗在不可达或无意义状态。

### 15.2 方案五的多组件结构

方案五改成：

```text
RFuzz raw 0/1 bit string
  -> scenario decoder
  -> protocol/state coordinator
  -> component drivers
  -> multi-component DUT
```

更展开：

```text
raw bits
  -> 选择场景类型
  -> 选择参与组件
  -> 选择地址/数据/延迟/错误/interrupt/alert
  -> harness 维护 pending transaction 和组件状态
  -> 同时驱动多个组件的合法输入
```

其中 harness 维护：

```text
pending bus request table
memory model
IP register shadow state
interrupt pending/clear state
alert source/ack/escalation state
DMA active state
cache line or address ownership state
response latency counters
reset/boot phase
```

### 15.3 fuzzer 变异什么

fuzzer 仍然变异原始 0/1 bit 串。

区别是 bit 串不再直接等于 DUT pins，而是被解释成更高层的控制变量：

```text
scenario_id
target_component
address_region
operation_type
burst_length
response_latency
backpressure_pattern
interrupt_timing
alert_injection
error_injection
data_pattern
```

因此随机性没有消失，而是从低层 pin 随机变成高层场景随机。

### 15.4 harness 怎么保证满足约束

harness 通过组合逻辑和时序状态机投影输入：

```text
raw bits 是候选决策；
harness 根据当前状态修正非法选择；
只有存在 request 时才生成 response；
只有 IP configured 后才允许 start；
只有 done/pending 后才允许 interrupt/status clear；
只有 alert source 活跃后才允许 alert handler ack/escalate；
只有 bus ready/valid 握手成立后才推进 transaction。
```

也就是说：

```text
raw bits 决定“想做什么”；
harness 决定“在当前系统状态下怎样合法地做”。
```

### 15.5 多组件方案五的收益点

它主要提高这些覆盖区域：

```text
bus arbitration / request-response state
IP configuration sequence
start/busy/done status machine
interrupt pending/clear path
alert classification/escalation path
DMA/CPU/shared memory contention
memory latency / backpressure / timeout path
error injection / recovery path
cross-component ordering path
```

它不只是减少输入空间，而是让随机探索更集中到真实系统路径。

## 16. 值得测试的多组件案例

本节给出后续真正值得做的实验案例，按工程难度从低到高排列。

### 16.1 OpenTitan IP 组合：AES + Timer + Alert Handler + TL-UL/simple bus

目标：

```text
验证多 IP 寄存器配置、状态机、interrupt、alert 之间的协调能否提升覆盖率。
```

组件：

```text
AES
rv_timer 或 aon_timer
alert_handler
simple TL-UL-like bus driver
small memory/data buffer
```

方案五 scenario：

```text
1. 配置 AES key/data/mode；
2. start AES；
3. 让 timer 在 AES busy/done 附近触发 interrupt；
4. 随机低频注入 alert；
5. 通过 bus 读取 AES status/result；
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
工程可控
IP 关系清晰
比单 AES/UART 更有多组件意义
```

缺点：

```text
关系主要是控制级/事件级，不是强耦合数据一致性。
```

### 16.2 OpenTitan IP 组合：DMA + SRAM + Timer/PLIC + CPU-like master

目标：

```text
构造更强的共享资源竞争关系。
```

组件：

```text
DMA
SRAM controller or memory model
rv_timer
rv_plic
CPU-like bus master model
TL-UL/simple bus
```

方案五 scenario：

```text
1. CPU-like master 配置 DMA descriptor；
2. DMA 对 SRAM 发起 read/write；
3. CPU-like master 同时访问同一地址或相邻地址；
4. bus 产生 backpressure；
5. timer/PLIC 在 DMA active 时触发 interrupt；
6. harness 检查 DMA done/status/interrupt clear。
```

适合覆盖：

```text
shared memory contention
bus arbitration
DMA active/done/error
interrupt pending/clear
address boundary / alignment / burst
```

优点：

```text
比 AES/Timer/Alert 更接近“多个组件互相影响”。
```

缺点：

```text
需要确认 OpenTitan 当前 DMA/相关 IP 的依赖和接口，工程量中等。
```

### 16.3 OpenTitan top-level：Ibex + TL-UL + peripheral + interrupt

目标：

```text
从自定义 multi-IP harness 过渡到真实 SoC top。
```

组件：

```text
top_earlgrey 或裁剪后的 top/subsystem
Ibex
TL-UL xbar
timer/PLIC
AES/HMAC/KMAC/UART/SPI 等 peripheral
memory/ROM/SRAM model
```

方案五 scenario：

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

优点：

```text
研究说服力强，是真实 SoC 交互。
```

缺点：

```text
完整 top 构建和 instrument 成本高，需要更多工程准备。
```

### 16.4 Rocket-Chip：DualCore + cache + TileLink + memory

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

方案五 scenario：

```text
1. core0 store addr X；
2. core1 load addr X；
3. 两个 core 访问同一 cache line；
4. 触发 cache miss/refill；
5. memory model 插入延迟/backpressure；
6. 低频 interrupt/debug；
7. 观察 coherence / refill / arbitration / replay 路径。
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

优点：

```text
最接近用户最初设想的“多个 CPU core 同时驱动并协调”。
```

缺点：

```text
工程成本最高。Rocket-Chip 依赖 generator、config、submodule 和生成流程，RFuzz 接入难度明显高于 OpenTitan IP 组合。
```

### 16.5 Sodor 多 core 自组实验

目标：

```text
用简单 CPU core 低成本模拟多 core + shared memory 场景。
```

组件：

```text
两个或多个 Sodor core
shared memory model
simple arbiter
timer/interrupt model
```

方案五 scenario：

```text
1. core0/core1 执行短指令序列；
2. 两个 core 访问共享地址；
3. simple arbiter 插入 stall；
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

优点：

```text
工程成本低，适合先验证多组件方案五思想。
```

缺点：

```text
不是真实复杂系统，说服力弱于 OpenTitan/Rocket-Chip。
```

## 17. 推荐优先级

按“能尽快落地 + 能体现多组件关系”的平衡，推荐顺序是：

```text
1. OpenTitan: AES + Timer + Alert Handler + bus
2. OpenTitan: DMA + SRAM + Timer/PLIC + CPU-like master
3. Sodor: two cores + shared memory + arbiter
4. OpenTitan top-level/subsystem
5. Rocket-Chip: DualCore + cache + TileLink + memory
```

如果只追求最强研究说服力：

```text
Rocket-Chip DualCore/cache/TileLink
```

如果追求最快得到一个可运行的多组件方案五实验：

```text
OpenTitan AES/Timer/Alert 或 DMA/SRAM/Timer 组合
```

如果追求最贴近用户最初“多个 core 同时输入协调”的理想场景：

```text
Rocket-Chip DualCore 或 Sodor two-core 自组实验
```

最终建议：

```text
先用 OpenTitan IP 组合证明 multi-component scheme5 的方法有效；
再用 Rocket-Chip/Sodor 扩展到 multi-core/shared-memory 场景。
```
