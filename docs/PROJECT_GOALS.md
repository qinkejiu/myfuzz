# 自动组合 SoC 与 RFuzz 输入约束：当前项目目标

日期：2026-09-14。状态：目标与实施基线；本文件不代表新目标已经实现。

实际开发目录为 `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`，核对基线为 `029840a`。
本文件和 [实施计划](superpowers/plans/2026-09-14-soc-composition-and-fuzz.md) 是新工作的入口。
7 月和 9 月上旬的计划、报告保留为历史证据；其完成比例不能沿用到本目标。

## 1. 最终目标

用户提供 CPU、外设源码和显式接口声明，系统自动生成一个包含真实 CPU、多个真实 MMIO 外设、总线和 RAM/ROM 模型的可运行仿真 SoC。RFuzz 变异原始 bit，生成的 harness 根据 ISA、协议、地址映射及有界状态修正输入，支持：

1. 随机指令进入 CPU，CPU 执行后发起实际 MMIO 请求。
2. 合成主设备不依赖 CPU 执行，独立发起 MMIO 请求。
3. 外设环境驱动器产生真实引脚输入。
4. CPU 和合成主设备经仲裁访问同一组外设，外设真实响应和 IRQ 反馈给 CPU。
5. 对跨组件交互收集 RTL 覆盖、事务记录及可重放证据。

“运行成功”必须包含真实 CPU 执行、真实外设副作用、官方 RFuzz 闭环和重建重放；编译成功、合成 CPU、同一寄存器模型的不同 personality 都不能代替。

## 2. 两层架构

结构层：源码事实 + 显式语义 → 实例化 → CPU 协议适配 → 通用请求后端 → 仲裁/译码 → 目标协议适配 → RAM/ROM 或真实外设。另有时钟、复位、IRQ 和外部引脚路由。

输入层：RFuzz raw bits → 固定版本输入布局 → 字段/ISA 投影 → 有状态驱动器 → 结构层允许控制的入口。投影放在生成的 harness；Python 可作参考模型和编译器，但运行时不得以 Python 合成行为代替 RTL 外设执行。

```text
RFuzz bits -> harness
                |-- instruction/data initialization -> memory model -> CPU
                |-- synthetic MMIO initiator -------------------------|
                |-- GPIO/UART/SPI environment                         |
                                                                      v
CPU memory interfaces -> CPU adapters -> arbitration/decode -> target adapters
                                                        |-- RAM/ROM
                                                        |-- real IP A/B/C
real IP IRQ -> declared interrupt routing -> CPU
```

## 3. 约束与状态语义

- RFuzz 原始语料不覆盖写回；保存 raw/layout/constraint/source/tool/binary/config 的身份。
- 指令候选在首次初始化时修正并保存。相同物理内存区域共享字节状态，不能因为取指端与数据端不同就生成不一致内容；跨字读取、压缩指令和部分写必须一致。
- 按需生成只适用于声明的程序存储区域；MMIO 的读返回始终来自真实外设。未映射地址有明确错误行为，不能被 transducer 当作任意可用内存。
- ROM 允许测试开始装载，执行期间写入返回错误且无副作用；RAM 的有效写更新状态。CPU cache 行为来自真实 CPU；自修改代码验收遵守所选 ISA 的同步要求。
- 驱动器空闲时接纳新候选；忙时不接纳的新候选按确定性规则丢弃并计数。已接纳字段锁存到完成，禁止随新 raw bits 变化。首版每驱动器最多一笔 pending，不使用无限队列。
- 基础结构/协议约束与探索偏置分开。ISA 合法化、MMIO 命中偏置、事件频率可切换；不承诺任意随机测试都正常退出 trap 或产生进展。
- CPU 输出、真实外设 read data/status/IRQ 不能被投影器改写。只允许根据公开协议握手和已接受事务维护环境状态，不读取内部寄存器来强迫结果。
- 超时不能撤销已发生的外设副作用。无安全取消机制时记录失败并结束该测试；测试边界复位恢复。禁止把局部外设复位冒充无副作用的事务取消。
- CPU-only、MMIO-only、mixed 在测试边界选择。MMIO-only 的 CPU 从测试开始保持独立复位；外设正常释放复位。mixed 不在事务中途切换驱动权。

## 4. CPU 与外设矩阵

CPU：真实 Ibex（现有 OBI 边界）和真实 CVA6（现有 compiler-proven packed AXI4 边界）。沿用已保存的源码 pin 作为候选，重新验证源码闭包、CPU 参数和实际接口后冻结。CVA6 的 AXI burst、ID、原子操作和 64→32 位 MMIO 行为需要独立能力检查，不能声称自动支持全部 AXI4。

三个系列定义为不同上游项目生态，首选以下真实模块；每系列至少两个不同外设：

| 系列 | 首批模块 | 外设协议 | 接入重点 |
|---|---|---|---|
| OpenTitan | UART、GPIO | TL-UL | packed 字段、integrity、alert、生成依赖及复位配置 |
| PULP | apb_gpio、apb_spi_master | APB，按固定版本确认 APB3/APB4 能力 | PREADY/PSLVERR/字节选通是否存在，SPI 外部时序 |
| ZipCPU | wbuart32 的 wbuart、zipcpu 的 ziptimer | Wishbone，按固定版本确认 classic/pipelined 子集 | CYC/STB/STALL/ACK、地址单位、无地址单寄存器窗口、写掩码能力 |

协议存在并不代表适配已完成。单 outstanding 的实现也必须遵守所选目标的实际握手。ziptimer 等目标的 byte-enable 语义不能凭端口存在推断；不支持部分写时明确拒绝或采用声明且验证的策略，不对有副作用 MMIO 自动做 read-modify-write。

最终必测六格：Ibex × 三系列、CVA6 × 三系列。每格同时实例化本系列两个真实外设；此外两个 CPU 各有一个混合三系列 top，每 top 至少一个来自每系列的真实外设。合计八个配置。BOOM 暂不作为本轮完成门槛。

## 5. 验收与证据

每个配置均须通过自动生成、编译、CPU-only、MMIO-only、mixed 三模式确定性 smoke。CPU 模式需要 CPU 发起 MMIO 并观察实际副作用；独立模式需要合成主设备完成同等操作；mixed 需要两个来源都有接受和完成记录。

每格至少一条 A 事件/IRQ → CPU 服务 → B 访问的定向可重放链；对其做固定其他输入、只改变 A 事件的差分重放。定向验收用地址图生成最小初始化/中断服务代码，标明 directed，不作为随机 fuzz 覆盖提升证据。

正式 RFuzz：八配置分别进行三种激励模式，每模式至少 300 秒有效 fuzz 时间、不计编译，固定并记录 seed；共 24 个任务、至少 120 分钟有效时间。300 秒是首轮功能验收门槛，不是统计显著性声明。各配置再有一次 mixed/bias-off 300 秒对照，总计至少 160 分钟。共享相同 SoC、raw ABI、模型和时钟预算，只关闭探索偏置；flat pin baseline 独立标为结构对照。

每任务保存实际 tests、completed feedback receipts、RTL coverage 类型/映射、CPU/各外设进展、协议错误、projection/consumption 计数、语料和失败输入。必须有多次真实执行和非零反馈，保存并重建重放所有保留语料；新增语料数如实记录，不以随机运行必然增长作为硬性保证。

内部 CPU/IP branch 或 toggle coverage 应接入反馈并分别报告；总线、模型、harness 覆盖单列。输入 bit 变化、首取指地址初始化数、backend completion 只能作为事件/进展指标，不能命名为 CPU 内部覆盖率。

资源：默认单构建、单运行 worker，nice 15，默认无波形；配置显式给出 build/run 超时、RSS 上限、每样本周期和停止排空时限。按环境预检给出可运行预算，不能以未生效的配置字段声称资源限制已生效。

## 6. 现有基础与缺口

已有源码：source_crawler / source_elaboration / interface_description / endpoint_capabilities；processor_boundary / processor_adapters / processor_execution / processor_backend；input_layout / runtime_projection / contract_transducer / coherent_memory / transducer_rtl；rfuzz_wire / shmem / fifo / live / simulator，以及 source-level 插桩链路。

本次静态核对发现：`protocol_composer.py` 的 contract 模式把 components 置为空；`real_cpu_campaign.py` 明确报告 fixed targets disabled。必须把 memory transducer 限定为内存目标，使真实外设与受约束指令并存。当前 processor routes 限一或两个 CPU memory endpoint，不含额外 fuzz master；`auto.py`、`protocol_composer.py` 均超过两千行，需按职责逐步拆分。

历史 Ibex/CVA6 执行报告保留，但本轮没有重新跑实核，也没有证据证明上述八配置已通过。

## 7. 上游依据（2026-09-14 核对）

- [OpenTitan TL-UL](https://opentitan.org/book/hw/ip/tlul/index.html) 与 [UART 接口](https://opentitan.org/book/hw/ip/uart/data/uart.html)。
- [PULP APB GPIO](https://github.com/pulp-platform/apb_gpio) 与 [APB SPI master](https://github.com/pulp-platform/apb_spi_master)。
- [ZipCPU wbuart](https://github.com/ZipCPU/wbuart32/blob/master/rtl/wbuart.v) 与 [ziptimer](https://github.com/ZipCPU/zipcpu/blob/master/rtl/peripherals/ziptimer.v)。

以上为选型依据，不是冻结 revision。任务 P1 必须记录实际 commit、嵌套依赖、参数、源码闭包和生成步骤；任何候选无法实现时保留阻塞证据，不能用 toy 外设填补验收矩阵。
