# CVA6 campaign 与 OpenTitan UART RX 三组件扩展

日期：2026-09-28。此报告记录 Ibex＋双 OpenTitan GPIO 首期验收之后的扩展，不将固定场景或短跑结果当作正式 G4 通过。

## 执行边界

- CVA6、Ibex、GPIO、UART 均在各自独立的真实 RTL harness 中运行。场景层只路由事务、数据和事件，不构造 Bus/Crossbar/PLIC，也不把不同组件的本地 tick 解释为全局 SoC 时延。
- Fuzzer 只能变异有权变异的上游 source。CPU 程序镜像或 GPIO/UART 外部输入改变后，中间状态、MMIO 响应、IRQ 与 GPIO 输出必须由真实 RTL 和持久状态决定。
- 一个 testcase 在连续多步中保留 RTL、内存、事务和待处理事件状态；除显式 reset 外不重新初始化。

### 输入如何约束

当前 G4 为验证 source 选择，CPU 程序镜像与 GPIO 外部引脚各只开放两个 1-bit 位置；因此该评测的候选常表现为 0/1 翻转。RFuzz 的原始 8 字节记录先选 target/path/source，再由受信 `SourceBindings` 指向允许改动的 Genome action 或初始镜像。更一般的外部 UART RX 则由有序 8N1 位事件组成，不能每周期独立随机。

`ownership` 将 DUT 输入逐位标成 source、bound 或 fixed。只允许 source 接收 Fuzzer 值；bound 值由 `DataflowRouter` 引用真实上游输出或冻结的 MMIO 响应，fixed 值按配置保持。`DependencyScheduler` 检查事件触发、局部延迟与前置条件，决定何时递送；它不计算 IP 本应输出什么。持久 RAM 先读未知字节时可物化并保存，真实写入后由写者状态决定，后续读不可重新随机。比如 GPIO B 的 IRQ 若已绑定 CPU IRQ，Fuzzer 改的是 B 外部引脚或更早的 CPU 程序，不能直接再改 CPU IRQ。

## CVA6 双 GPIO 搜索

[CVA6 provider](../../src/myfuzz/integration/cva6_scenario_campaign.py)复用三策略 campaign 执行器，同时提供 CVA6 专属的两轮因果链检查。CPU 源路径为 CVA6 程序变异→真实 MMIO 写 GPIO A→A 输出绑定 B 输入→B 真实 IRQ→CVA6 读取 B 与写持久 RAM。外设源路径为 B 外部引脚变异→B 真实 IRQ→CVA6 读取 B→真实 MMIO 写 A 与持久 RAM。检查器按事件顺序、事务身份、真实读响应消费、W1C 和 IRQ 回落核对至少两轮，不根据预期配置合成 DUT 输出。

guided 与 uniform 使用相同真实绑定、seed、变异 energy 和 RTL；差异是上游 source 选择。独立基线仍运行三份真实 RTL，但没有跨组件绑定，CPU IRQ 固定为零，CPU MMIO 使用本地持久影子寄存器；基线的完成链计数必须为零。三组配置位于 [configs/scenario](../../configs/scenario/)。

campaign 身份现在包括 provider、执行器、Rust 客户端、宿主源码、直接 manifest、反方向 bound seed，以及基线 manifest 间接引用的两个 seed。间接 seed 路径不能逃出其 manifest 目录。正式评测必须在开始、结束及报告发布后核对身份一致。

当前受信 source 仅开放每方向两个 1-bit 变异位置，用于证明 source selection 会使真实 RTL 下游改变；候选空间小，Rust 搜索循环的运行秒数不等于同样长的 RTL 执行秒数。评测必须同时列出每格实际 testcase 数、有效搜索秒数和覆盖/闭环数量，不能单凭 60 秒预算声称广泛探索。

软件回归 `tests.integration.test_scenario_campaign tests.integration.test_scenario_cva6_campaign` 为 28/28 通过，其中 4 项真实 opt-in 按默认设置跳过。真实定向检查确认两方向新 seed 各有两轮完成链，切断 B→CPU IRQ 后拒绝完整链；CPU ISR 位和 B pin9 的变异分别改变真实下游 A 输出。修复前 18 单元[短跑报告](../../runs/scenario/campaign-cva6-18cell-smoke-20260928-v1/campaign_report.json)的 23/23 保存语料回放匹配、无搜索错误；guided/uniform 分别记录 33/49 条完成链，独立基线 0。其 bound 单元存在首批后停滞，且链计数含 seed 与重复候选，故这些链数只作故障诊断，不计正式 G4 或搜索收益。

首次正式 CVA6 尝试输出目录为 [campaign-cva6-g4-18cell-20260928-v1](../../runs/scenario/campaign-cva6-g4-18cell-20260928-v1/)，但在运行中发现 Rust 场景队列把已完成变异的 corpus entry 反复轮转，长时间不再触发真实 RTL testcase；该尝试已中断，不能计作 G4。随后按红灯→绿灯修复两级停滞：新反馈 hint 可使 parent 产生下一批变异，且每次队列访问只执行一批，返回队列后新发现的 entry 可获得调度。真实 Ibex＋双 GPIO 短跑证明旧实现 seed 后只有一批，而修复后会持续执行多批；另有真实回归先复现“新子 entry 永不选中”，修复后实际选中。Rust Cargo 单测 4/4、release 构建和该真实队列公平性回归均通过。

Host 证据现在从真实 receipt 记录提交的 source selector，并统计包含 RTL 本地周期的后续 mutation batch；`applied_hint_sequence` 仅在选择器唯一匹配时推断，不能当作严格的 Rust sideband 消费证明。G4 bound 单格进一步要求两个不同于 seed 的有效 Genome 变体、至少一条变异后真实闭环；有效 Genome 哈希排除 testcase ID/path 标签，避免把重复 raw 包装成不同场景。每种策略与方向的三个 seed 合计必须提交过全部声明的上游 source。CPU 方向若两轮值不同，campaign 检查器按每轮真实 MMIO 写值分别核对 A→B→IRQ→CPU 回读/RAM 写，不沿用“所有轮值相同”的限制；切边和伪响应序号负例均拒绝。

当前源码的正式 CVA6 尝试目录为 [post-fairness v2](../../runs/scenario/campaign-cva6-g4-18cell-post-fairness-20260928-v2/)。前 12 个有绑定单元完成搜索；进入独立 CPU 基线后，第 4 批候选长时间没有新的回执，运行已中断，因此没有完整的 `campaign_report.json`，不能计作正式 G4 通过。该停滞正在定位。通过标准仍为 18/18 单元 `complete`、每格有效搜索至少 60 秒、上述真实探索门槛、所有保存 corpus 从初态回放匹配，以及报告起止身份与运行后当前身份相同。

后续定位发现 host 原先只有整批结束才持久化回执，且 30 秒排空超时把一批 64 个真实 RTL testcase 的正常执行时间算作空闲。改为每条回执立即落盘，并从最近完成的 testcase/反馈起算空闲时间；campaign 为每个 testcase 安装 5 秒局部执行预算，首次 RTL 构建不计入该预算。修复后的 CVA6 独立 CPU 定向实跑分别达到 65/65（有效搜索 65.03 秒）和 257/257（有效搜索 264.12 秒）`complete`；长跑跨过旧停点，四批各 64 条全部完成，两个保存 corpus 都是 1/1 回放匹配。这些只是单格诊断，不能替代 18 单元正式 G4。独立审查促成两项加固：源使用须由最终 Genome 的净变化和真实 RTL 采样证明；物理截断回放须用事件前缀区分同一局部 tick 内的多次操作。Runner 身份变化后，当前 21 份固定证据已重新录制，状态、事件数、局部周期和语义哈希均与前版 21/21 相同；独立新进程回放 20 份完整轨迹、1 份语义前缀均匹配。

当前源码的 CVA6 18 单元正式重跑报告为 [post-budget-source-use v3](../../runs/scenario/campaign-cva6-g4-18cell-post-budget-source-use-20260928-v3/campaign_report.json)：18/18 单元 `complete`，门禁失败项为空，实测有效搜索 1235.043 秒，报告起止源码身份一致。Guided、uniform、独立基线分别运行 414、414、582 个 testcase；有效 testcase 为 377、376、582，严格闭环数为 246、232、0。保存 corpus 分别 12/12、12/12、6/6 从初态回放匹配。两个有绑定策略在两个方向上均实际采样到全部声明的上游源。此报告证明所锁定 CVA6＋双 OpenTitan GPIO 场景的 G4 门禁；不外推到 SPI 或 BOOM。Ibex 的当前源码 G4 结果见下文正式报告。

## OpenTitan UART RX → Ibex → GPIO

[三组件工厂](../../src/myfuzz/scenario/uart_gpio_example.py)把 UART RX 设为外部可变 source，把 CPU IRQ bit0 绑定到 UART RTL 的真实 IRQ；CPU 的 MMIO 读写由 router 交付给 UART/GPIO 真实 harness。GPIO 外部输入固定为零，不能随机覆盖 UART→CPU 或 CPU→GPIO 已绑定的数据。

[两帧 Genome](../../configs/scenario/ibex_uart_rx_gpio_two_rounds.json)在同一 testcase 中发送 8N1 的 `0xA5` 和 `0x3C`；UART 当前配置的 NCO=0x4000，位间隔用 UART 自身 64 个本地 tick 表达。第二帧在第一轮真实 GPIO 写之后触发。定向 [真实测试](../../tests/integration/test_scenario_uart_rx_gpio_real.py)检查两次 RX watermark IRQ、Ibex 实际进入中断、两笔真实 UART RDATA 消费及响应身份、CPU 对 GPIO 的两笔 MMIO 写、GPIO RTL 输出、持久 RAM 写入顺序与无隐式 reset。

[固定证据包](../../runs/scenario/acceptance/case-ibex-uart-rx-gpio-two-rounds-v1/manifest.json)为 `complete`；CPU/UART/GPIO 分别执行 1800/1820/1815 个本地周期，15342 条语义事件；独立新进程回放为 `matches=true, verification_scope=full`。这些 tick 只表述各 harness 的局部工作量。

## 固定证据身份与范围

将 UART 三组件工厂纳入显式宿主源码闭包后，旧身份 20 份包归档于 [旧目录](../../runs/scenario/acceptance-prior-uart-rx-20260928/)。同 tick 物理截断定位修复后，上一版 21 份包又归档于 [上一版目录](../../runs/scenario/acceptance-prior-wall-cut-20260928/)。[当前验收目录](../../runs/scenario/acceptance/)按新 Runner 身份重录 21 份，逐包与上一版比较状态、本地周期、事件数和语义 SHA，21/21 完全一致。21/21 都经新进程回放匹配：20 份完整轨迹，一份物理回复超时包只验证已确认语义前缀。当前宿主闭包摘要为 `6acd04d66ed306994f7bd57f8b04e5d39e5dcdd8c95c53ce2e68e3362ccb091b`。

Ibex 当前源码的[正式 G4 报告](../../runs/scenario/campaign-ibex-g4-18cell-post-budget-source-use-20260928-v2/campaign_report.json)同样为 18/18 单元 `complete`，门禁失败项为空，总有效搜索 1103.873 秒，报告起止及运行后当前源码身份一致。Guided、uniform、独立基线分别运行 1678、1750、1926 个 testcase；有效 testcase 为 1535、1573、1926，严格闭环数为 878、894、0。保存 corpus 分别 12/12、12/12、6/6 从初态回放匹配，四个有绑定策略/方向组合都实际采样到各自两个上游源。旧 v9 报告只供历史追溯，不能替代本报告。

BOOM 依照本地不可执行规则跳过，依据见[探查记录](boom-local-availability-20260928.md)。OpenTitan SPI 和更多 UART 异常/错误路径尚未由这些结果证明。
