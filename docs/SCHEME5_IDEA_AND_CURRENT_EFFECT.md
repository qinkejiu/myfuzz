# Dependency-Aware Multi-Harness Fuzzing

## 0. 一句话定义

方案可以表述为：

```text
Dependency-aware multi-harness fuzzing:
use one or more semantic/protocol-aware harnesses to project raw fuzzer bit strings
into dependency-consistent DUT inputs, so that fuzzing explores valid and coordinated
hardware execution paths instead of independent random pin toggles.
```

中文表述：

```text
依赖感知的多 harness fuzzing：
保留 fuzzer 对原始 0/1 bit 串的随机变异能力，
但在 harness 层根据模块间、信号间、协议间、时序间的依赖关系做投影和协调，
让 DUT 更容易进入真实、可推进、跨组件一致的执行路径。
```

这里的 dependency 包括：

- 单个 top module 内部不同 input pin 之间的协议依赖；
- request/response、valid/ready、grant/rvalid 之间的时序依赖；
- interrupt/debug/error 与正常执行路径之间的优先级依赖；
- CPU、bus、memory、timer、interrupt controller、UART/SPI/GPIO 等多个组件之间的系统级依赖；
- 多个 harness 之间共享同一个高层 scenario 或 coordinator 的跨接口依赖。

因此，方案不是简单地“加约束”，而是把随机 bit 串解释为有依赖关系的硬件环境行为。

## 1. 方案的 idea

### 1.1 原始问题

RFuzz baseline 的典型做法是：

```text
raw 0/1 bit string
  -> 直接切片
  -> DUT top-level input pins
```

这种方式保留了最大的随机性，但也有一个明显问题：很多输入组合在硬件语义上是不真实或低价值的。

以 CPU core 为例，完全随机顶层输入可能出现：

- `rvalid=1` 但没有合理的 `grant`；
- 指令返回数据大概率是非法编码；
- reset/boot/trap 地址未对齐；
- interrupt、debug、NMI、bus error 同时高频乱跳；
- fetch 没有持续打开，core 很难进入稳定执行路径；
- 外部 memory/bus 行为和 core 请求之间没有时序关系。

这些随机组合不是“不允许”，但会让 fuzz 大量时间花在无意义状态、浅层错误状态、重复 trap/debug 状态或不推进的 pipeline 状态上。

### 1.2 核心想法

不是取消 fuzz，也不是写定向 test。

核心是：

```text
raw 0/1 bit string
  -> semantic/protocol-aware harness
  -> projected legal/coordinated DUT inputs
```

也就是说，fuzzer 仍然变异原始 bit 串；harness 把这些 bit 串解释成更有硬件语义的输入。

希望把随机性从“低层 pin 乱跳”提升到“高层场景和合法关系随机”：

- raw bit 决定是否 fetch、是否 valid、是否 interrupt、是否 debug；
- raw bit 决定指令数据的大部分字段；
- raw bit 决定地址、数据、event、delay、priority；
- harness 只负责去掉明显无效或低价值组合，保留探索能力。

### 1.3 单模块 top 的方案

对于 Ibex/CVA6 这类单个 CPU top，方案主要约束同一个 top module 的不同输入端口关系。

例子：

- boot address 对齐；
- fetch enable 更容易打开；
- `rvalid` 和 `grant` 不产生明显矛盾；
- error 只在 valid response 时低频出现；
- IRQ/NMI/debug 不高频同时乱跳；
- 指令编码低位偏向合法 32-bit 指令路径。

这类方案仍然是 top-level fuzz，只是输入不再完全独立随机。

### 1.4 多组件系统的方案

对于多个组件同时工作的系统，方案更像一个自定义环境模型：

```text
RFuzz raw bits
  -> scheme5 coordinator
      -> CPU instruction/data/memory inputs
      -> bus ready/valid/response
      -> interrupt controller input
      -> timer event
      -> UART/SPI/GPIO/I2C external behavior
      -> memory/peripheral register responses
  -> multiple DUT components
```

目标不是“同时随机驱动更多模块”，而是让多个模块之间的输入满足可执行的协调关系。

例如：

- CPU 发起 MMIO 访问时，总线和外设给出合理响应；
- timer 到期后 interrupt controller 再触发中断；
- UART/SPI/I2C 的状态机按协议节奏推进；
- DMA、memory、bus、interrupt 之间有因果关系；
- 多核/shared memory 场景里，不同 core 的请求和 memory arbitration 有一致语义。

这才是方案相对普通 top-level random fuzz 的研究价值。

### 1.5 方案与baseline的区别

Ibex baseline 使用 RFuzz 自动生成 harness。

baseline 行为：

- RFuzz 输入宽度为 395 bit；
- 输入 bit 直接映射到 `ibex_core` 顶层 input；
- 不做协议修正；
- 不做指令合法化；
- 不做 IRQ/debug/error 低频化；
- 不做 memory/RF model；
- 不根据 DUT 输出构造外部环境。

优点：

- 随机空间最大；
- 有机会偶然进入一些异常、debug、错误和边界状态；
- 是最干净的对照组。

缺点：

- 大量输入组合语义低效；
- 容易浪费在不推进或不真实状态；
- 对复杂系统的跨接口关系探索很弱。

## 3. 当前语义建模内容

当前 Ibex 方案的建模强度是“轻量语义投影”，不是完整环境模型。

主要约束如下。

| 约束                              | 目的                                    | 是否保留随机性                    |
| --------------------------------- | --------------------------------------- | --------------------------------- |
| boot address 低 8 bit 清零        | 避免 reset/trap 入口落到噪声低地址偏移  | 高 24 bit 仍由 raw bit 控制       |
| instruction low bits 偏向 `2'b11` | 提高 32-bit 合法指令路径概率            | 指令高 30 bit 仍原始随机          |
| fetch enable 投影                 | 避免 core 长时间不 fetch                | raw fetch bits 仍控制结果         |
| `instr_rvalid -> instr_gnt`       | 减少 response valid 与 grant 的明显矛盾 | valid 仍由 raw bit 直接控制       |
| `data_rvalid -> data_gnt`         | 减少 LSU response 低价值组合            | valid 仍由 raw bit 直接控制       |
| instr/data error valid-gated      | error 只在有效响应时低频出现            | error 仍由多个 raw bit 共同控制   |
| IRQ 低频 gate                     | 避免中断每周期乱跳                      | 每个 IRQ source 仍由 raw bit 控制 |
| fast IRQ onehot                   | 避免多个 fast IRQ 同时高导致优先级噪声  | 哪个 IRQ 被选中仍由 raw bit 决定  |
| NMI/debug 低频且互斥              | 避免异步入口长期主导执行                | NMI/debug 仍由 raw bit 决定       |

刻意没有做的约束：

- 没有 `grant requires request`，因为 `instr_req_o`/`data_req_o` 是 DUT 输出；
- 没有 RF x0 read zero 修正，因为需要看 `dut.rf_raddr_*`；
- 没有 store/load memory model；
- 没有基于 scenario 的指令模板；
- 没有按 DUT 状态机反馈生成输入。

这些限制是为了保持“fuzzer 变异修正前 bit 串”的实验语义干净。

## 4. 当前实验效果

### 4.1 100s 早期短测

测试：

结果：

| 方案                    | common coverage |
| ----------------------- | --------------: |
| baseline                |        132/1058 |
| scheme5_bit_constraints |        107/1058 |

短测结论：

- 100s 内方案没有超过 baseline；
- 很短时间内，baseline 的完全随机输入可能更快碰到浅层 coverage；
- 这不能直接否定方案，因为方案目标是让更长时间探索进入更有效路径。

### 4.2 6h baseline vs scheme5_pre 长测

结果：

| scheme             | tests_total | cycles_total |   common coverage | discoveries |
| ------------------ | ----------: | -----------: | ----------------: | ----------: |
| `scheme1_baseline` |      63,508 |      212,658 | 453/1058 = 42.82% |         148 |
| `scheme5_pre`      |      63,508 |      211,543 | 506/1058 = 47.83% |         178 |

直接对比：

| 指标            | baseline | scheme5_pre |   差异 |
| --------------- | -------: | ----------: | -----: |
| tests_total     |   63,508 |      63,508 |      0 |
| cycles_total    |  212,658 |     211,543 | -1,115 |
| common coverage |      453 |         506 |    +53 |
| discoveries     |      148 |         178 |    +30 |

这组结果里测试次数完全相同，所以覆盖率差异不是因为 scheme5 跑了更多 test，而是因为同样数量的 raw bit 输入经过 harness 投影后，触达了更多有效覆盖点。

### 4.3 覆盖点集合差异

集合结果：

| 集合                | 覆盖点数 |
| ------------------- | -------: |
| baseline covered    |      453 |
| scheme5_pre covered |      506 |
| overlap             |      426 |
| baseline only       |       27 |
| scheme5_pre only    |       80 |
| union               |      533 |
| uncovered by both   |      525 |

解释：

- 两个方案共有 426 个重合点，说明基础执行路径和容易触达路径大体一致。
- baseline 独有 27 个点，说明完全随机输入仍有一部分边界探索能力。
- scheme5_pre 独有 80 个点，远多于 baseline only。
- 净增覆盖为 `506 - 453 = 53` 个 common coverage 点。

### 4.4 覆盖点位置与功能区域

区域分布：

| area                      | overlap | baseline_only | scheme5_only | baseline_total | scheme5_total |
| ------------------------- | ------: | ------------: | -----------: | -------------: | ------------: |
| ID/decode                 |     178 |             7 |           53 |            185 |           231 |
| controller/trap/irq/debug |      35 |             0 |           10 |             35 |            45 |
| IF/fetch                  |      22 |             2 |            8 |             24 |            30 |
| CSR/priv/counters         |      52 |             0 |            6 |             52 |            58 |
| EX/ALU/multdiv            |      67 |             1 |            3 |             68 |            70 |
| LSU/memory                |      59 |            17 |            0 |             76 |            59 |

区域功能说明：

| area                      | 主要功能                                                     | 本轮覆盖差异说明                                             |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| ID/decode                 | 指令解压缩、主 decoder、立即数生成、寄存器字段解析、控制信号生成、非法指令识别 | `scheme5_pre` 独有 53 点，是最大增益来源。说明指令低位偏向 32-bit、fetch 持续打开、握手更一致后，core 更容易持续进入有效 decode 路径，同时仍保留一部分 illegal/default decode 分支。 |
| controller/trap/irq/debug | pipeline 控制、异常/trap、interrupt/debug 入口、flush/redirect、控制状态机 | `scheme5_pre` 独有 10 点，baseline 独有 0 点。说明低频 IRQ/NMI/debug/error 比完全随机更容易触发可持续的控制流状态。 |
| IF/fetch                  | 取指请求、fetch valid、prefetch/fetch FIFO、取指侧 stall/flush 交互 | `scheme5_pre` 独有 8 点。说明 `fetch_enable_i` 大概率开启、`instr_rvalid => instr_gnt` 的局部握手约束提高了取指推进能力。 |
| CSR/priv/counters         | CSR 读写、特权状态、异常原因/中断相关寄存器、性能计数器      | `scheme5_pre` 独有 6 点，baseline 独有 0 点。说明低频异常/中断/debug 事件让 CSR/privileged 状态更容易被真实触发。 |
| EX/ALU/multdiv            | ALU 运算、分支比较、移位、乘除法执行路径                     | `scheme5_pre` 小幅多 3 点。说明更多有效 decode 会带来更多执行单元路径，但当前方案没有专门定向 EX。 |
| LSU/memory                | load/store 状态机、data bus grant/valid/error、地址/字节使能、memory stall/response | baseline 独有 17 点，而 `scheme5_pre` 独有 0 点。说明完全随机输入仍能碰到一些 LSU raw 边界；后续方案不能继续收紧 LSU，应该保留或增强 LSU 随机边界探索。 |

覆盖点功能结论：

- 方案的主要收益集中在 `ID/decode`、`controller/trap/irq/debug`、`IF/fetch`、`CSR/priv/counters`。
- 这些区域正好对应方案想提升的路径：持续取指、有效解码、控制流推进、低频异常/中断/debug 进入。
- baseline 的主要独有点集中在 `LSU/memory`，说明完全随机输入对 memory 边界仍有价值。
- 下一步优化方案时，不能把 LSU/data bus 约束得更死；应该保留 raw 边界扰动，同时给 load/store response 更合理的时序。

### 4.5 区域功能与两个方案的探索能力特点

从功能上看，这些覆盖区域可以分成三类。

第一类是“让 CPU 真正跑起来”的前端和译码区域：

- `IF/fetch` 负责向指令侧发起取指请求、接收指令响应、处理 fetch stall/flush。
- `ID/decode` 负责把取回来的指令解释成内部控制信号，包括 opcode、寄存器、立即数、分支/load-store/CSR/ALU 类型，以及非法指令判断。

这两个区域决定了 fuzz 输入是否能把 core 推进到“持续取指、持续解码、持续产生有效控制流”的状态。`scheme5_pre` 在这里明显更强，尤其是 `ID/decode` 独有 53 点，说明它不是简单减少随机性，而是让随机输入更常进入有效指令流附近，从而打开更多 decode 分支。

第二类是“控制流和架构状态变化”的区域：

- `controller/trap/irq/debug` 负责 pipeline 控制、异常入口、中断入口、debug 入口、flush/redirect 等控制状态机行为。
- `CSR/priv/counters` 负责特权态寄存器、异常原因、中断状态、性能计数器等架构状态。

这些区域通常需要正常执行路径和异步事件之间有合理配合。如果 interrupt/debug/error 完全随机高频乱跳，core 可能反而无法稳定进入深层状态。`scheme5_pre` 在 controller 和 CSR 区域都有独有覆盖点，说明低频且互斥的 IRQ/NMI/debug/error 建模更容易触发“可持续的异常/中断/debug 路径”，而不是制造噪声。

第三类是“执行和访存边界”的后端区域：

- `EX/ALU/multdiv` 负责 ALU、分支比较、移位、乘除法等执行单元路径。
- `LSU/memory` 负责 load/store、data bus grant/valid/error、地址/字节使能、memory stall/response。

`scheme5_pre` 在 EX 区域小幅领先，主要是因为更好的 fetch/decode 推进间接带来了更多执行路径；但在 `LSU/memory` 上，baseline 独有 17 点，而 scheme5 独有 0 点。这说明 baseline 的完全随机输入虽然整体效率较低，但仍擅长偶然打到一些 data bus、load/store、memory response 的边界组合。

因此两个方案的探索能力特点可以总结为：

| 方案        | 探索能力特点                                                 | 从覆盖区域看到的证据                                         |
| ----------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| baseline    | 更像无约束随机搜索，探索面发散，能偶然触达一些 LSU/memory 边界，但大量输入可能不形成稳定执行流 | baseline only 主要集中在 `LSU/memory`，有 17 个独有点；但在 control/CSR 上没有独有优势 |
| scheme5_pre | 更像依赖感知搜索，把随机 bit 投影成更容易推进的取指、译码、控制流和低频事件组合，适合打开 CPU 正常执行和控制状态路径 | scheme5 only 主要集中在 `ID/decode` 53、controller 10、IF 8、CSR 6，净增 53 个 common coverage 点 |

一句话概括：

```text
baseline 的强项是随机边界碰撞；
scheme5_pre 的强项是依赖一致的执行路径推进。
```

这正好符合方案的预期：它不是要在所有局部边界上压过 baseline，而是让 fuzzer 更高比例地探索“真实、可推进、跨信号关系一致”的状态空间。

## todo

1.扩展长时间测试 

2.增加测试设计范围


