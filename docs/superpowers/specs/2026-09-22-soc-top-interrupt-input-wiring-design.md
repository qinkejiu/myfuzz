# SoC 顶层的中断连接与输入控制：当前实现说明

日期：2026-09-22。性质：基于现有生产代码的架构与接线契约，不是从零设计，也不把未验收的组件或协议写成已支持。

本文回答两个问题：生成器如何把 CPU、MMIO 外设和通用中断控制器接成一个 SoC；RFuzz 的输入究竟在哪里进入、何时生效、可以改变什么。完整能力状态以[后续路线图](../plans/2026-09-22-soc-next-steps-roadmap.md)为准。本文中的“自动”仅指已准入的 profile、协议和运行模式；它不意味着从端口名字猜出未知 RTL 的语义。

## 1. 顶层架构与两种不同的通路

```text
                              同一时钟/复位域
  测试环境 ── raw / event ──> 特殊输入、外部引脚、UART/SPI/GPIO peer
                                  │                    │
                                  │                    └──> 外设外部接口
                                  ▼
  ROM/RAM <──取指/数据── CPU ──CPU 主接口──> 协议适配器 ──> beat 互联
                          ▲                                      │
                          │ machine_external                      ├──> ROM/RAM
                          │                                      ├──> MMIO 外设桥 ──> 外设
                          │                                      └──> 中断控制器 MMIO 窗口
                          │                                                   ▲
                          └──────── 控制器 irq_o <── source_i <── 归一化后的外设 IRQ
```

必须区分两条路径：

- **CPU—外设事务路径**：CPU 自己发请求，经适配器、互联、地址译码到达 MMIO 外设或中断控制器；响应沿原路径返回。RFuzz 不直接篡改已发出的 CPU 请求或 DUT 响应。
- **中断通知路径**：外设 IRQ 经极性/触发方式归一化，进入控制器；控制器只用一根通知信号驱动 CPU 声明的 `machine_external` 入口。CPU 仍通过上述总线读取 `CLAIM`、清除外设状态、写入 `COMPLETE`。

这两条路径一起闭环。把多个外设 IRQ 直接 OR 到 CPU 入口、或让测试环境直接驱动控制器 `source_i`，都不是当前生产组合机制。

## 2. 构建时必须提供的事实

用户提交 CPU RTL、外设 RTL、各自的 `component_profile.v1` 和组合 request。profile 是**声明式事实与证据**，不是按组件型号执行的 Python 接线代码。

CPU profile 至少要使生成器能够确定：源码闭包和顶层；时钟/复位；CPU 主接口的协议、角色、方向、宽度及已准入能力；启动地址与存储需求；中断入口 endpoint、端口角色、极性和 `machine_external` 语义。外设 profile 至少要确定：MMIO 从接口及寄存器/地址窗口；IRQ 输出 endpoint、端口或向量位、极性、触发类型、同域时钟；中断保持与清除条件；可选的外部引脚、peer 角色和特殊输入策略。

request 决定实际 CPU/外设实例、地址策略、存储器和运行模式。生成器把 profile 声明与 RTL 展开的真实端口事实逐项核对。端口不存在、方向/位宽不符、向量位不明确、地址冲突或必要语义缺失时，应拒绝组合，不得按相似名字猜线。可参看[Ibex CPU profile](../../../configs/cpus/ibex/component_profile.json)和[novagpio 外设 profile](../../../examples/soc_generation/profiles/novagpio.json)。

## 3. 中断从声明到顶层连线

### 3.1 源解析、编号与控制器窗口

[`build_interrupt_plan`](../../../src/myfuzz/composition/soc_interrupt_plan.py)读取每个外设的 `interrupt_source` 绑定，检查它真的是输出源、极性合法、向量位明确、没有重复物理源，且与 CPU 位于受支持的同一域。声明的源按稳定键排序后获得 ID `1..N`，不按 request 中的书写顺序编号；ID `0` 保留为“没有可 claim 的源”。目前准入上限为 40 个已验证源。

计划记录 `source ID → 实例/端口/位 → 控制器 bit`、触发方式、转换器、`LATCH_MASK`、控制器窗口和 CPU 入口。控制器被作为一个普通 MMIO target 分配非重叠地址窗口；自身只解码窗口内偏移，顶层传入经证明不会截断的低地址位。若没有声明任何中断源，不实例化控制器，CPU 入口按计划固定为无效电平，并且不声称中断覆盖。

### 3.2 极性与触发方式归一化

控制器的 `source_i[k]` 对应 ID `k+1`，统一按高有效采样。外设若声明低有效，先反相；若 CPU 的已准入入口声明低有效，则在控制器通知到 CPU 时反相。外设自己的状态寄存器和 IRQ 输出不被生成器改写。

- `level`：归一化后直接接控制器。非服务状态下 pending 每拍跟随该电平；外设必须保持请求，直到软件执行 profile 声明的清除操作。
- `pulse`：归一化后直接接控制器，但该源的 `LATCH_MASK` 位置 1。profile 必须声明至少一个本域时钟周期的可采样脉宽；控制器把采到的脉冲保存在 pending，直到 `CLAIM`。
- `rising_edge`、`falling_edge`、`both_edges`：插入 [`soc_irq_edge_detect`](../../../src/myfuzz/protocols/rtl/soc_irq_edge_detect.sv)，先按极性归一化，再检测声明的边沿并产生有界脉冲；对应 `LATCH_MASK` 也置 1。边沿检测器不是 CDC 同步器或毛刺滤波器。

`LATCH_MASK` 由源的捕获契约推导，不由用户给控制器随意传入。若脉冲/边沿源误用纯电平 pending，脉冲可能在 CPU `CLAIM` 前消失；真实负例已覆盖这种连接缺陷。

### 3.3 控制器状态与总线寄存器

[`soc_irq_controller`](../../../src/myfuzz/protocols/rtl/soc_irq_controller.sv)为每个源维护 pending、enable；全控制器同一时间最多一个 in-service 源。可 claim 的源是“pending 且 enabled 且不在服务中”的源；多个源同时满足时，最低 ID 优先。控制器忙时不继续通知 CPU。复位清除 pending、enable、in-service 和响应状态。

控制器使用 32 位完整字访问，非法地址、方向或字节使能返回错误且无副作用。寄存器 ABI 的重要部分是：`CLAIM` 位于窗口偏移 `0x00`，读取返回获选 ID（无源时为 0）并执行认领；`COMPLETE` 位于 `0x04`，只接受当前 in-service 的同一个 ID；`IN_SERVICE` 位于 `0x08`；`SOURCE_COUNT` 位于 `0x0c`。`PENDING` 位图从 `0x20` 开始，`ENABLE` 位图接在全部 `PENDING` 字之后，故其精确偏移要从计划中的 `register_map` 读取，不应对所有源数量硬编码为 `0x24`。位图的 ID 0 位保留。

`COMPLETE` 只清除控制器的服务状态，**不清除外设自己的中断原因**。电平源在外设原因仍有效时会再次 pending；这不是控制器替外设修复故障。

### 3.4 CPU 软件的服务闭环

在受支持的 RISC-V/boot 模板内，生成程序设置中断入口和使能，CPU 实际进入 ISR 后：读取 pending 留证；通过总线读取 `CLAIM`；按 ID 分派到相应外设；读取外设状态并按 profile 声明的 `write_1_to_clear` 或 `read_clears` 操作清除；可观测时再读回状态；最后把同一 ID 写入 `COMPLETE` 并读回 `IN_SERVICE`。若 `CLAIM=0`，不伪造一次完成；若返回计划外 ID，记录错误，不乱写 `COMPLETE`。[程序生成入口](../../../src/myfuzz/composition/soc_boot_program.py)只使用已声明且可解析的寄存器语义；缺少清除操作时拒绝，而不是猜组件型号。

因此，IRQ 线接通不等于闭环成立。闭环要求外部原因、外设状态、pending、正确 ID、外设清除和 COMPLETE 都由真实运行证据对应起来。

## 4. 输入控制：谁拥有哪一类信号

### 4.1 一次构建固定布局，一条样本是一串周期字

SoC 生成时，组合计划建立 `raw_layout`；带镜像/peer 的运行路径把它扩成 `combined_input_layout`。布局逐字段冻结 `owner`、位段、宽度、顶层端口、约束和身份哈希。**不存在跨所有 SoC 固定的 raw 位号。** 一个 `RuntimeSample` 带请求 ID、非空的逐周期 `raw` 字序列，以及可选的外部引脚事件与 peer 事件计划；序列化后交给持久仿真器。具体位段必须查看本次生成的布局，不应照抄其他组件的位号。

当前主要所有权如下：

- `soc_image`：CPU 释放前的指令与数据候选。典型字段为 `<slot>_offer/address/data/be` 或数据值字段。它们控制存储模型的初始镜像，不是 CPU 正在运行时的总线请求。
- `soc_stimulus`：仅在声明合成 BFM 主接口的隔离/竞争模式中存在，字段如 `stim_offer/target_selector/offset/write/wdata/be`。这是**另一位总线主设备**的请求，不能计作 CPU 请求；当前官方 RFuzz 语料还未携带 BFM 主接口槽位。
- `soc_peer`：附着的 UART/SPI/GPIO 对端模型的有效位、数据、驱动等请求端口。peer 再通过外设真实外部接口影响 DUT；不能直接替外设设置状态寄存器或 IRQ 输出。
- profile 声明的特殊输入和外部引脚：仅环境拥有的输入端口可以驱动，按策略投影/定时；组件输出、CPU 主接口输出、外设响应、中断输出均为观察对象，不能被 raw 覆盖。

布局的实际拼接和保留位以 [`combined_input_layout`](../../../src/myfuzz/composition/soc_image.py)为准：profile 特殊输入在基础段；如有 BFM，其请求段按计划占位；指令/数据镜像段随后；peer 请求字段附加在镜像段之后。读取者必须按生成布局解码，而不是自己重算偏移。

### 4.2 一个样本的严格时间顺序

```text
构建一次 SoC 与输入布局
  → RFuzz 给出一串 raw 周期字
  → 选择 direct_input / constrained_baseline / dependency_repair 投影
  → 拒绝或记录修复，得到 projected
  → 缓存整条样本；在 CPU 释放前把已准入候选写入初始镜像并读回
  → 复位刷新镜像、释放 CPU
  → 每周期施加对应 raw/projected 外部字段与事件
  → CPU 自己取指、执行并经总线访问外设/中断控制器
  → 保存实际 applied、CPU 请求/响应、peer 与中断证据
```

镜像候选虽写在某个 raw 周期字中，**不是等执行到该周期才改写正在运行的 CPU 指令**。运行时先缓存整条记录、放置候选、复位刷新，再重放同一串字的逐周期外部部分。[持久 testbench 生成](../../../src/myfuzz/composition/soc_runtime.py)显式实现此顺序。时钟和复位按构建契约产生，不让随机位任意破坏启动；没有候选镜像时按对应 boot image 运行。

### 4.3 raw、projected、applied 与事件优先级

`raw` 是 RFuzz 原始提议；`projected` 是规则允许的候选；`applied` 是顶层驱动器/peer 在仿真中实际施加的值。三者必须分别保存和重放。`direct_input` 保持原样作为对照；`constrained_baseline` 只投影环境拥有的受约束位；`dependency_repair` 可进一步修复尚未提交的镜像/程序候选，例如地址、完整指令字节使能和已声明依赖。无法安全修复时以具名原因拒绝。修复器不能修改 CPU 已发出的请求、DUT 响应或 IRQ。

对 peer 请求端口，逐周期 raw 是默认电平；若该端口的显式 peer event 在指定周期触发，**该周期 event 覆盖 raw**，随后恢复 raw 来源。事件 slot、周期、payload 和 pulse 最小间隔都受计划约束。外部引脚 event 由单独计划施加；没有声明的端口不能借 event plan 取得驱动权。

### 4.4 输入如何导致中断，又有哪些输入绝不能直连

例如测试环境改变 GPIO 引脚或 UART peer 发送请求，外设 RTL 依其自身寄存器状态决定是否拉起 IRQ；生成连接把这个真实 IRQ 送进控制器；CPU 再按 ISR 流程服务。另一些中断需要 CPU 先经 MMIO 设置外设 enable、状态或发送寄存器，生成引导程序只执行 profile 声明的前置动作。输入不能直接伪造“外设 IRQ 已经发生”或“CPU 已完成 CLAIM”。这样才能把外设内部行为与接线、输入策略、软件行为分开归因。

## 5. 一个完整的接线与输入例子

下面是**示意**，ID 与地址必须以实际生成的 `interrupt_plan.json`、`address_map.json` 和 `raw_layout.json` 为准：CPU 是带 `irq_external_i` 的 Ibex，`gpio0` 声明高有效 `level` 源，`uart0` 声明同域 `pulse` 源，且两者都提供可解析的外设清除操作。若稳定排序后 GPIO 为 ID 1、UART 为 ID 2，顶层连接相当于：

```systemverilog
// 说明性伪码，不是可复制到生成顶层的组件专用实现。
source_i[0] = gpio0_irq_o;       // ID 1：电平 pending
source_i[1] = uart0_irq_pulse;   // ID 2：脉冲 pending，LATCH_MASK[1]=1
cpu0.irq_external_i = irq_controller0.irq_o;
// irq_controller0 同时是 beat 互联上的一个 MMIO target。
```

测试样本先使 CPU 执行的初始化程序设置 GPIO/UART 和控制器使能；输入计划随后改变 GPIO 外部引脚或使 UART peer 收到发送请求。IRQ 必须由外设 RTL 自己产生。若两个源同拍到达，控制器 pending 含 ID 1、2；CPU 先读到优先级较高的 ID 1，读/清 GPIO 的声明寄存器并写 `COMPLETE=1`；控制器空闲后再通知 CPU 服务 ID 2。UART 脉冲虽已结束，ID 2 的 latch pending 仍应保留到 `CLAIM`。每一步都要从 CPU 总线事务与外设状态证据核对，而不是只看 ISR 进入次数。

若测试环境直接把控制器 `source_i[1]` 拉高、或在 CPU 已发出 MMIO 请求后修改请求数据，这会绕过被测外设或 CPU，**不是**上述实验。若 UART 实际 IRQ 需要先由 CPU 写 `TXDATA/CTRL` 才能产生，这些前置写入必须来自 profile 声明并由 CPU 程序执行，不能由生成器根据“UART”名称猜测。

## 6. 审计、运行证据与失败分类

生成物应包含 `myfuzz_soc_top.sv`、`sources.f`、`soc_composition.json`、`interrupt_plan.json`、`raw_layout.json`、`port_dispositions.json` 和 `structure_audit.json`。独立[结构审计](../../../src/myfuzz/composition/soc_structure_audit.py)复核实际展开网表中的 IRQ 源位、极性路径、边沿转换器参数、`LATCH_MASK`、控制器窗口、CPU 入口以及端口处置；计划有线而实物接错时判为组合问题。

运行证据保存 raw/projected/applied、布局和规则版本、源与工具身份、外设/peer 事件、CPU 总线事务、逐源 pending/claim/清除/COMPLETE。重放必须用同一身份和字段逐项比较；缺轨迹时为 `not_assessed`，不能写成 `pass`。`all_sources_closed` 等软件汇总计数不是 ID↔物理源映射的独立证明；真实负例中它可能显示成功而接线仍错误。只有结构审计、边界重放和受信任独立判据共同排除连接/软件/环境问题后，才考虑组件内部缺陷。

推荐分别验证结构、输入和中断行为：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.composition.test_soc_interrupt_plan \
  tests.composition.test_soc_structure_audit \
  tests.integration.test_soc_input_arms_projection \
  tests.integration.test_soc_input_transport_ab

MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_interrupt_lifecycle \
  tests.integration.test_soc_irq_sample_matrix
```

真实套件需要相应 RTL 和 Verilator 环境；测试被跳过不等于验收通过。官方 RFuzz campaign 与三臂同语料重放的环境和证据另见[路线图阶段 4](../plans/2026-09-22-soc-next-steps-roadmap.md)。

## 7. 明确边界

当前生产路径仅对已准入的协议/宽度和单时钟域负责；CPU 中断入口仅接受一位 `machine_external`。跨域/CDC、timer/software/supervisor/user/NMI/debug/local 入口、未声明向量位、不可靠脉宽、任意电气 `inout`、多核、DMA、多 outstanding/乱序和完整 burst 语义不由此机制补线。BFM 合成主接口尚未进入官方 RFuzz 语料。任意 ISA 的完整程序生成、所有外设的独立行为判据及自然未知 bug 的自动确认也不属于当前已证明范围。

验收口径是：在**受支持且真实展开核验**的 CPU/外设 profile 上，无组件型号专用接线分支地生成结构审计通过的 SoC；输入确实改变 CPU 或 peer 的合法行为；CPU 经真实总线读取 `CLAIM`、清除外设并写 `COMPLETE`；证据可重放且能把输入/连接问题与已有独立依据的组件问题区分。未满足前置事实时应明确拒绝，不以“尽可能连接”代替正确性。
