# SoC 线级判据、多源 latch 与组件缺陷归因设计

日期：2026-09-21。基于现有 profile 组合、`soc_runtime`、`soc_peer_oracle.v1`、中断控制器与 `EvidencePackage` 增量实现；不另建 SoC 生成器，也不把 seeded-corpus 说成官方 RFuzz 搜索。

## 范围与取舍

本轮完成三个独立但串联的验收场景：SPI+GPIO 真实运行的 SPI 线级独立判据；同一控制器下多个源的 latch 故障注入；一个已知组件 RTL 注入缺陷与一个已知接线/profile 错误的可重放归因对照。用户已确认：归因机制用已知注入缺陷证明，不以发现自然存在的未知 bug 为交付条件。

考虑过三种路线。只比较 peer/组件计数成本低，但同源实现可能一起错，不能作为线级独立判据。全量 VCD 加离线解析覆盖广，但日志、工具差异和重放成本过高。本轮选用生成 testbench 中的紧凑、只读边沿记录：按已验证的 peer 角色绑定采样连接线，独立 Python 参考模型处理波形；后续可以增补 VCD，但不是准入条件。

## 一、SPI 线级证据和独立判据

生成 testbench 从 `CompositionPlan.peers` 的实际角色绑定找到 SCK、CS、MOSI、MISO 网线，不根据组件实例名或 RTL 端口名猜测。运行时在稳定采样点记录四线变化及周期，包含模型参数、记录数和截断标志；记录进入 `RunResult`、证据包和 replay 的逐字段比较。采样只观察 DUT/peer 网线，不回写 DUT 输入。无绑定、出现 X/Z、时序采样歧义或轨迹截断时，线级检查为 `not_assessed` 或 `observation_insufficient`，不得报 `pass`。

独立 Python 判据按声明的 `BITS`、`CPOL`、`CPHA`、`CS_ACTIVE_LOW` 分割片选窗口，检查片选前后空闲电平、只在选中窗口出现有效时钟、每次完整传输的采样边沿数、MOSI 字序和 MISO 与已接受的 `spi.arm_byte` payload 的关系。MOSI 期望字节来自实际观测的 CPU→SPI TXDATA 总线写入及独立冻结的寄存器契约，不能由生成软件的意图或 peer 的 RX 计数反推；MISO 期望来自 raw peer 事件。判据输入是总线写入、raw peer 事件、线级轨迹及冻结的接口契约；peer RTL 的 `rx_count`、`clock_count` 等计数只作为交叉观测，不生成期望值。实际总线写入或规范来源缺失时不判通过。必须有正例以及 MOSI 错位、选中外时钟、缺失/截断轨迹负例。首期只承诺单片选、单字、一个未完成传输、已准入的 SPI 模式；超出范围显式拒绝或不评估。

## 二、多源 latch 故障注入

复用真实 Ibex + 至少两个中断源的组合和通用控制器。正例覆盖同周期与错开触发、source ID、pending、CPU CLAIM、profile 清除和 COMPLETE。负例只在测试构建的生成顶层中按 source ID 清除一个应 latch 的位，并证明另一源仍能闭环、被破坏源的 pending/claim 消失或不闭环；再覆盖屏蔽错误和 source ID 置换。变异必须记录原始/变异顶层哈希及改动位置，不能覆盖生产生成器或原始 RTL。期望分类是 `composition_defect`，不是任一外设内部 bug。若没有足够的事件、pending 和服务证据，只能标记未定位。

## 三、组件缺陷归因

保留现有 `component_candidate` 作为初筛，不因一个 assertion 或同源 profile 自检就升级。新增一条单独的“已确认组件内部缺陷”评估路径：要求 (1) 完整的原始/变异组件源码、profile、连接、软件、工具和输入身份；(2) 独立于组件 RTL 与生成软件的规范依据和实际边界轨迹；(3) 合法输入及复位/握手/权限前置检查；(4) 同输入可重放；(5) 隔离复现，或在保留交互的最小 SoC 中做替换/差分实验，证明失效随组件 RTL 而非接线、profile、软件、peer 或 checker 移动。任何一项缺失，保持 `component_candidate` 或 `undiagnosed`。

验收夹具复制一个已有外设 RTL 源并注入明确的内部行为错误；对照夹具只改变一个连接或 profile 语义。两者运行同一合法激励、保存证据包和 replay 结果。组件注入应达到“已确认组件内部缺陷”，连接/profile 注入必须分别进入组合/profile 分类；改变运行身份、删去独立依据、删去合法性证据、让 replay 不一致或让隔离不复现，都必须阻止确认。确认结论只针对该注入实验，不自动外推到真实未知缺陷。

## 实施顺序与验收

1. 先补线级记录及独立 SPI 参考测试，再跑 SPI+GPIO 真实正例和负例；保持旧无 peer 构建和证据包兼容。
2. 补多源 latch 故障注入及边界证据；验证故障归类为组合层。
3. 补确认门槛、已知组件/连接或 profile 注入夹具和差分重放；更新能力矩阵及验收报告。

每步先写失败测试再改实现。定向 Python/RTL 测试和 `MYFUZZ_SOC_REAL=1` 真实运行均需通过；官方 `kfuzz`/bundled Verilator 5.020 缺失仍如实列为环境缺口，不属于这三项的虚构证据。线级判据未覆盖的 UART framing、GPIO 电气双向以及跨域中断仍保持 `not_assessed`/拒绝。
