# 当前数据流 Fuzz 实施计划

> **当前进度入口：** [docs/CURRENT_PROGRESS.md](../../CURRENT_PROGRESS.md)。本页保留目标、阶段门槛和实施顺序；最新任务状态以该入口及对应验收报告为准。
>
> **2026-10-08 状态：** P0 文件／入口整理完成，P1 在声明的身份范围完成；P2、P3、P4、P5 **已按各自声明范围通过整阶段验收**；P6～P8 尚未通过阶段验收。固定场景、既有代码或短跑证据不等于后续阶段通过。[P2 受控 UART 子路径](../../reports/current-dataflow-p2-controlled-entry-read-20261006.md)在隔离源码快照中通过 4/4/4 关联、零容量屏障及 48,323 事件完整 fresh replay；旧 256 容量和身份漂移失败均保留。P3 slot 重传回执已修复，另有[受限 UART→host RAM→后续退休 Load 真实短门禁](../../reports/current-dataflow-p3-host-ram-readback-real-gate-20261007.md)通过，未推广为通用路径。[P5 热路径剖析与优化](../../reports/current-dataflow-p5-efficiency-profile-20261006.md)减少反馈事件深拷贝；同一快照完成 600.979 秒、5,563 例真实在线搜索及 2,236,544 事件完整 fresh replay，又完成约 599 秒、30/30 例的同源码逐例冷启动对照。后续十分钟运行已补外层和 Runner/Router/Scheduler 逐例耗时；完整链/s、同等状态覆盖和同条件故障质量／性能对照仍缺，P5 未验收。Generic ISR、完整反馈搜索及 DMA 仍未验收。

> **后续证据：** [pin8→CPU IRQ 接受身份门禁](../../reports/current-dataflow-p2-pin8-cpu-irq-identity-20261007.md)在新冻结源码中得到 5 条精确连接和完整 replay；[当前代码时期 UART 读回短回归](../../reports/current-dataflow-p3-current-tree-readback-20261007.md)重新验证受限低字节跨例链；[P5 600 秒分项门禁](../../reports/current-dataflow-p5-streamed-600s-timing-20261007.md)补齐逐例 p50/p95、93.915 秒证据终结成本及全量 replay；[Runner/Router/Scheduler 十分钟压缩门禁](../../reports/current-dataflow-p5-runner-zlib-600s-20261007.md)又在 6,272 例中记录嵌套耗时、92.702 秒证据终结及输入哈希绑定的完整 replay。P5 仍缺完整链/s、同条件 JSONL 与故障质量对照，P2/P3/P4/P5 阶段状态不变。

> **新增推进：** [P4 路径熵门禁](../../reports/current-dataflow-p4-path-entropy-real-gate-20261007.md)对固定传输字节的选路偏置做修正，1,000 例真实运行的 F4/F5 分别为 491/509，并完整重放；[pin8 trap 退休关联](../../reports/current-dataflow-p2-pin8-trap-retirement-architectural-20261007.md)只提供弱架构证据；[P5 submit 分解](../../reports/current-dataflow-p5-command-roundtrip-split-20261007.md)区分命令往返与其余主机时间。三项均不替代整阶段验收。

> **长会话预算与容量：** [P3 多 slot 截止报告](../../reports/current-dataflow-p3-live-duration-buffer-20261007.md)记录旧 180 秒运行因整批处理达到 652.118 秒后中断，以及逐 slot 截止的新冻结源码 3 例真实短门禁与完整 replay。[定向真实 writer 容量门禁](../../reports/current-dataflow-p3-directed-writer-capacity-20261007.md)使一个持续会话产生 271 个不同的受限低字节 writer 证书；[后续退休 `lw` 读回门禁](../../reports/current-dataflow-p3-late-readback-capacity-20261007.md)在另一冻结源码中认证最后版本 `[0,282]` 经真实 RAM read/response 到 RVFI 退休，二者各有完整 fresh replay。通用跨例路径仍未验收。

> **后续同例数与 CPU 采样证据：** [P4 新旧选择器对照](../../reports/current-dataflow-p4-path-selector-paired-1000-20261007.md)在同源码基底各跑 1,000 例，选路更均衡但目标位和交互新特征种类未增长；[P2 原生 CPU IRQ 回执](../../reports/current-dataflow-p2-native-irq-sampled-receipt-20261007.md)新增显式 opt-in 的真实 pre-edge take 身份，RVFI 退休仍晚 5 tick、缺硬件来源 token。两者均不提升整阶段验收状态。

> **严格完整链/s 首次可测：** [P5 首步端到端验收门禁](../../reports/current-dataflow-p5-chain-acceptance-20261007.md)新增增量链证书生产者与 `scripts/run_first_step_acceptance.py` 流式分析入口；带全部现有探针的真实 Ibex＋双 PULP GPIO 有界运行 24/24 complete、31.273544 有效搜索秒，认证 8 条链＝0.255807 链/s（IP→CPU→IP 5／CPU→IP→CPU 3），16 条 incomplete 明确点名首个缺口，并给出全分项 p50/p95 与 11.550 秒终结成本，独立缓存 fresh replay 一致。链终点仅到 ISR 读 `PADIN` 退休与写 GPIO A 退休交付，不含 A→B 回流；该 31 秒有界运行**不能替代** P5 要求的十分钟同条件门禁。同轮[RVFI IRQ serial sideband 身份门禁](../../reports/current-dataflow-p2-rvfi-sideband-identity-20261007.md)重录在建 sideband 的 profile/contract 身份并修复其构建输入物化缺陷；host 侧尚未消费 serial，P2 的精确来源 token 仍未闭合。

> **十分钟与同预算门禁：** [P5 十分钟全探针门禁](../../reports/current-dataflow-p5-chain-600s-20261007.md)在真实 Ibex＋双 PULP GPIO 单会话中完成 368/368 例、600.362953 有效搜索秒与 570,196 事件，认证 **27 条链＝0.044973 链/s**（跨例 6），并在同一 trace 上复算 **68 条** `decision_serial == retirement_serial != 0` 的 IRQ serial 精确证书，独立缓存完整 fresh replay 一致；[同预算配对对照](../../reports/current-dataflow-p5-paired-continuous-cold-start-20261007.md)证明连续会话墙钟约为逐例冷启动的 1/16（31.905 秒对 512.881 秒，含 24×18.736 秒逐例初始化），且 status/raw/genome/path/断言逐例一致，覆盖与 tick 差异如实记录、不声称输出等价。二者都未做同条件 JSONL/故障质量对照，P5 仍未整阶段验收。

> 供后续实施者按 A1～A8、P6～P8 逐项执行并在每项后核对证据；本文中的未勾选任务和计划命令均不代表已经实现或运行。

**目标：** 先让 Ibex＋若干真实外设具备双侧输入变异、持续多例、真实数据流反馈和断言发现能力，再复用到多协议固定实例，最后对已支持协议子集实现自动接入与测试。

**架构：** CPU/IP 分别在独立 harness 中真实执行；总控只编译输入归属、跨组件 Router/Scheduler、持续状态、反馈、检查和重放。RFuzz 原始字节先经合法源解码，不能直接改写 Bound Input 或 DUT 输出。

**技术与边界：** Python 场景层、SystemVerilog/Verilator 本地 RTL、RFuzz Rust 运输、JSON 证据；不构造具体 SoC Bus/Bridge/PLIC，不声称全局 cycle-accurate 时序。工作区原有未提交修改和第三方 RTL 保持原样；真实验收只按固定源码/profile/工具链身份归档。

日期：2026-10-06。本文件按**最终功能**和**逐阶段实现情况**两部分组织。实际能力以[运行能力表](../../LOCAL_HARNESS_RUNTIME.md)及[验收报告](../../reports/README.md)为准；计划中的验收条件不代表已经通过。代码位置见[代码组织图](../../CODE_ORGANIZATION.md)。

## 一、系统的最终实现目标功能

### 总控环境与真实组件

总控环境根据受信源码、组件 profile、协议模板及声明式微调，为所选 CPU/IP 分别生成独立 harness，并在一个**长期运行的测试会话**中协调它们。会话开始时构建、初始化并启动 CPU/IP 一次；之后可以持续输入 testcase，直到发现 bug、达到显式预算或用户结束会话。每个 DUT 的 RTL、原生接口、局部握手、局部时序、内部状态和输出都真实执行。跨组件只交换事务、数据与事件，不生成具体总线矩阵、桥、仲裁器、PLIC 或全局 cycle-accurate SoC。

新 CPU/IP 应优先复用同协议模板并微调 harness；协议语义确有差别时新增版本化模板。支持程度逐级记录，不能凭协议名称声称任意同协议组件即插即用。

### 三步交付目标

1. **Ibex＋若干真实外设的功能完整初版。** 以 Ibex＋双 PULP GPIO 的双向链为最小基线，再接入至少一种不同协议/行为的真实外设（优先已固定源码且有运行证据的 OpenTitan TL-UL UART 或 SPI Host）。这一阶段就应完成系统的大部分核心功能：一次初始化后多例持续输入、CPU 指令与 IP 外部源两端变异、按 F1～F5 数据流/依赖路径选源、ISA/协议/字段输入约束、真实跨组件/跨周期传播、持久 RAM/事务/事件、增量覆盖引导、独立断言、故障证据和完整前缀 replay。允许首版的组件 profile、路径和断言针对选定 Ibex/IP 手工声明，覆盖的 ISA 子集、外设模式及路径较窄；不能把“缺少通用接入”解释为可以缺少核心搜索或检测闭环。通过受控错误校准“能发现并复现故障”，正常 RTL 搜索结果如实记录，不要求凭空发现自然 bug。
2. **基于同一框架扩展 CPU 与外设协议实例。** 对五类已登记 CPU 边界 OBI、AXI4、AXI4-Lite、Wishbone 和 PicoRV32 Ready/Valid Memory，以及 OpenTitan TL-UL、PULP APB3、ZipCPU Wishbone 等 IP 系列，逐个固定真实 CPU/IP 实例与协议子集，复用第一步完整的输入变异、持续会话、Router、Scheduler、覆盖反馈、checker、故障证据与 replay。每个实例只按实际通过的局部交易和跨组件路径登记能力。
3. **从已验证实例提炼自动测试入口。** 给出已支持协议子集内的 CPU/IP 源码与 profile，系统自动校验端口/协议事实、选择模板并生成可微调 harness，编译 F1～F6 中该组合实际可用的路径、输入约束和初始种子，随后自动运行持续 testcase、反馈搜索、断言与 replay。组件特有的寄存器语义、IRQ 接法和外部环境模型仍由受信声明提供；不能把同名协议直接等同于任意 RTL 自动可测。

第三步的“自动”以第二步已验收的协议**形态与组件能力**为边界。原 Word 的 F6 DMA 路径仍是最终数据流范围，需在真实 DMA master 接入后单独验收；不能用 CPU 搬运或合成 DMA 输出填补。

第一步的完成门槛按**功能**检查，第二步按**可适配的固定实例与协议范围**检查，第三步按**新组件自动接入**检查。F6 需要真实 DMA 主设备，单列 P8；第一步不以没有 DMA 为由降格为“只跑演示场景”。

### 一次初始化、连续 testcase 与持久状态

每次输入的 **testcase** 是一个有身份的上游源动作及其观察过程，例如在未来合法取指位置提供一条 RISC-V 指令，或给 IP 一个外部输入事件。取指必须由 CPU 真实发起；内存 harness 只按地址和局部协议返回已保存的指令。对声明为“待 Fuzzer 提供指令”的地址，若 CPU 提前发出取指请求，指令服务须按局部协议暂缓**响应**并保留请求，直到合法指令提交或 case/会话预算结束；不能先用未知 RAM 的随机物化值回复，再尝试改写该字。其他允许首次物化的数据 RAM 仍按原持久规则处理。**已完成取指响应**、已由真实写操作决定或已物化的字节不能被后续 testcase 偷偷改写；仅有尚未回复的取指请求不算已消费指令。一个 testcase 可经历等待、响应消费与检查所需的多个局部周期；尚未完成的传播不因例边界截断。testcase 依序进入同一会话，其反馈可立即用于生成下一例。

**testcase 边界不 reset、不重新构建 harness、不重装初始镜像。** CPU/IP RTL、RAM、事务账本、pending event、局部 tick 与场景事实跨 testcase 持续保存。只有显式 reset 或会话结束才按 policy 清理。真实 Store 以 byte-enable 更新对应 RAM 字节，后续 testcase 的 Load 复用已写值；未初始化字节首次读取可由 Fuzzer 物化一次并保存，冻结后的读响应保持不变。允许尚未完成的中断或外设事件跨 testcase 继续传播，下一例须遵守其输入所有权和因果前置条件。

会话证据按 `session_id → case_index/testcase_id → 输入与反馈 → 状态摘要` 追加记录。第 N 例的 replay 必须先从会话初态重放第 1～N−1 例，或使用经过验证且与前缀身份绑定的快照；不能把后续单例当作独立初态运行。发现断言失败后立即停止接纳新 testcase，保存触发失败时的完整前缀、真实 RTL 观察和未完成事务状态，再在新进程重放到同一失败点。

### 输入约束和 SoC 数据流语义

Fuzzer 只变异没有真实上游绑定的 **Fuzzable Source**，例如程序镜像、初始数据、GPIO 自由 pin、UART RX 和 SPI/I2C peer。**Bound Input** 来自真实 RTL 输出或持久状态，例如 IP 的 IRQ、GPIO A 输出到 B 输入、IP read data 到 CPU rdata、已经写入的 RAM 字节；这些输入不能再次随机覆盖。

以原件 `SoC内部数据流动与去向.docx` 的数据流类别为清单，建立版本化、可执行的路径声明。每条路径明确上游源、实际 Binding/MMIO Router、事件先决条件、状态版本、下游消费和完成条件。**数据流类别是变异目标和传播路径的分类，不是 testcase 边界，也不要求一次输入预先写死整条链。** Dataflow Router 交付带来源的真实结果，Dependency Scheduler 选择下一步允许的输入与局部执行顺序，checker 独立检查所有真实输出。系统应支持 CPU→IP→CPU、IP→CPU→IP 和 CPU→IP A→IP B→CPU 等跨周期、跨 testcase 路径；不能从自然语言或端口名猜测 RTL 语义。

### 数据流目标选择与输入变异

每例按顺序执行三步：① 按尚未覆盖的行为或断言目标选择 F1～F6 中的主要数据流类别及可执行 Dependency Path；② 沿路径反向寻找当前状态下可控的 Fuzzable Source，按 CPU 已启用的 RISC-V ISA 扩展、目标 IP 原生协议和经源码/接口核对的机器可读字段描述选择合法操作子与可变位；③ 用局部协议握手、跨周期数据来源、跨组件因果、当前寄存器/事务状态和持久资源版本检查何时可接纳输入。外设文档用于提取语义候选，不能单凭文档文字或同名端口自动推断可变位。可变 mask、范围、对齐、握手和源归属进入受信 profile/路径契约并在运行时核对。

第一步的 CPU 指令白名单限定 RV32I 的 `LUI`、`ADDI`、`LW`、`SW`、`SB` 与 `NOP`，固定引导/ISR 可保留已验收的 CSR 和返回指令，但不把任意 CSR 编码列为可变源。`LUI+ADDI` 构造数据或地址，`LW/SW/SB` 让 Ibex 真实访问 RAM 或已声明 MMIO 窗口；寄存器号、带符号立即数、字节使能、对齐和外设可写寄存器位置必须合法。生成器只能对**可静态证明地址**的片段预检 MMIO 窗口/权限；寄存器运行后才决定的实际地址，须等 CPU 真实发出请求再由 Router 在接纳前检查，不改写 CPU 输出。CPU 侧操作子可在白名单中选指令、操作数、立即数、地址、未来取指位置及片段顺序；插入/替换/删除只作用于尚未完成取指响应、未物化且未由真实写决定的可写程序区域。IP 侧操作子只作用于外部 pin、UART RX、SPI/I2C peer 数据和合法事件时机等未绑定环境源。若 IP 寄存器应由 CPU 配置，就变异上游 CPU 指令/操作数，让 CPU 真实发出 MMIO；不能同时直接随机该 IP 寄存器。若目标是 F5 中断，Fuzzer 选择可能引出 IRQ 的 CPU 配置或 IP 外部源；CPU IRQ 本身必须来自真实 IP 输出。

**双侧主动变异**是同一搜索会话中 CPU 和 IP 均保留各自的 Fuzzable Source。Fuzzer 根据未覆盖路径阶段、依赖边、状态转移与真实闭环，选择当前有能力推动目标的 CPU 或 IP 上游源；不限制只能选一侧，也不按固定次数机械轮换。`Mutation Direction` 描述目标传播路径，不授予写入 Bound Input 的权限。某一例可由 CPU 指令驱动，下一例也可继续由 CPU 驱动或改由 IP 外部源驱动，实际决定取决于当前会话状态和反馈。

一个 testcase 默认接纳一个主要上游源动作；确需关联的环境输入要单独声明来源、触发条件和身份。运行后记录 `session_id`、`case_index`、`flow_id`、`path_id`、`source_id`、操作子、合法字段约束、前后状态摘要、真实交付链及增量反馈。单例可以跨多个本地周期；一条 F4→F5→F2 链可以由多例在同一持续会话中自然接续。例边界只用于输入和反馈记账，不隐式 reset 或强制 quiesce。

首版 `SourceDecision` 的规范字段为 `case_id`、`flow_id`、`path_id`、`source_id`、`operator`、`payload`、`trigger/prerequisite`、`local_step_budget`；RFuzz raw bytes 只用于选择并变异这些字段，经 ISA/协议/所有权解码后才提交。`CaseReceipt` 至少包含原始输入 hash、规范化输入、接纳/拒绝原因、事件起止 ID、实际局部 tick 差、前后状态摘要、阶段/边/状态/闭环增量反馈和 checker finding。无副作用的非法输入只返回拒绝回执；RTL 命令已发出而回执丢失则记录 `uncertain_effect` 并结束该会话，不能重试造成重复事务。状态未达目标时返回 `incomplete` 并保留待处理事实，后例可继续推进；只有受控预算/显式 reset/会话结束执行清理 policy。

原件的总体结构图用于确定参与者和数据去向；其中 Bus/Interconnect、Interrupt Controller 是文档对典型 SoC 的描述。在本系统中，各条流按以下六类实现，跨组件只保留事务、数据来源、持久状态与事件因果：

| 流 ID | 原件数据流 | 本系统的实际传播与约束 |
|---|---|---|
| F1 指令流 | 程序存储器 → CPU | Fuzzer 变异程序/初始镜像；CPU 真实 PC 和取指请求决定地址，持久 ROM/RAM 按局部协议返回已保存的指令；CPU 真实译码执行并更新 PC/寄存器。 |
| F2 数据读流 | RAM 或外设 → CPU | CPU Load 真实发出地址/读请求；RAM 使用提交时冻结的持久字节，MMIO 使用目标 IP RTL 的真实读响应；CPU 真实消费 rdata。已绑定 rdata 不随机覆盖。 |
| F3 数据写流 | CPU → RAM | CPU Store 真实给出地址、wdata 和 byte-enable；Memory Service 一次提交并逐字节更新；后续 F1/F2 读取同一资源版本，不能重新装载初值。 |
| F4 MMIO 控制流 | CPU → 外设 | CPU 真实 Load/Store 经声明的地址窗口转换为 IP 原生局部协议事务；寄存器配置、TX、状态读和 W1C 清除均由真实 IP RTL 执行/响应。 |
| F5 中断事件流 | 外设 → CPU → ISR → MMIO | IP 真实状态/IRQ 经声明的电平或脉冲交付规则送至 CPU 中断输入；CPU 真实 trap/ISR 后再读取 IP 真实状态。IRQ 只通知事件，不代替 F2 的数据返回；不模拟 PLIC 汇聚/优先级。 |
| F6 DMA 搬运流 | CPU 配置 DMA → DMA 主设备 → RAM/IP → 完成 IRQ → CPU | CPU 真实配置 DMA；**真实 DMA RTL** 在独立 harness 中发出读写主设备请求，Router 将已接受事务交给持久 RAM 或真实 IP FIFO/寄存器；数据和完成 IRQ 均追溯到真实组件输出。并发访问按声明的事务提交顺序处理，不声称覆盖物理总线仲裁。 |

F1～F6 可连接为一段持续场景，例如 F1 执行配置指令→F4 配置 IP→F5 等待 IRQ→F2 读取状态→F3 保存 RAM；或者 F4 配置 DMA→F6 搬运→F5 通知 CPU。每一步必须保留真实生产者、消费者和跨周期状态来源。

**第一步跨例示例：** Case 1～3 分别提交合法 `LUI`、`ADDI`、`SW` 指令，让 Ibex 经真实取指/执行配置 GPIO B；Case 4 变异 B 的未绑定外部 pin；B RTL 若真实产生 IRQ，Router 才交付 CPU；固定 ISR 或后续合法 `LW/SW` 指令让 CPU 读取 B 的真实状态并写 RAM；Case 5 提交 `LW` 读取该 RAM 字节，必须得到此前真实 Store 的值。Case 1～5 共用同一 Ibex/GPIO RTL 进程与 RAM。若某一步没有产生预期结果，记录 `incomplete` 或 checker finding，不让 Scheduler 合成 GPIO IRQ 或 CPU 读值。下一轮也可以继续选 CPU 指令，而不必机械切到 IP 输入。

### Fuzzer、覆盖、断言与重放

Fuzzer 先选目标和 Dependency Path，再反向选最上游可变源；CPU 与 IP 源进入同一候选池，均能主动驱动本侧真实 RTL。操作子覆盖 CPU 白名单指令及操作数、IP 外部环境、合法因果序列和路径切换。跨组件交互反馈分别记录：真实输入被本地 RTL 消费的路径阶段、带生产者/消费者身份的依赖边、RAM/IRQ/寄存器状态转移，以及有完整真实证据的闭环。另将端口语义命中和有明确 CPU/IP RTL 插桩来源的内部分支覆盖分别计数；所有反馈可用于下一轮目标、源、路径和 mutation energy 分配，不能以两个组件先后出现就推断因果命中。

协议检查器、跨组件来源/顺序不变量和 CPU/IP 行为断言要保存异常真实输出、失败来源链、raw 输入、Genome、源码/工具链身份和完整 trace。每个 testcase 完成后生成增量反馈供下一例变异；新增覆盖与失败语料保存其会话前缀，并从初态 fresh replay。受控故障注入用于校准检测能力，与自然 RTL 缺陷分别统计。性能报告区分一次性编译/初始化、每例真实事务和 host 调度时间；连续 testcase 不重复预热。

### Fuzz 吞吐与执行开销

速度是第一步就要验收的系统能力。构建/缓存 Verilator 产物、加载 profile、编译 Dependency Path/Ownership、初始化 harness 和 reset 均在会话开始时完成一次；普通 testcase 只做源选择、合法性接纳、必要的局部 RTL 步进、增量反馈与回执。连续多例共用相同 CPU/IP 进程、RAM 和预编译路径，不调用 `record_scenario(..., factory)` 逐例启动。不同会话可作为独立 worker 并行搜索，但同一会话内保持确定的提交顺序、状态和前缀身份。

热路径不应每例重扫整个事件历史、重建依赖图、重复解析 profile，或逐周期序列化完整 JSON。Runner 以新事件游标增量更新反馈/Checker，复用预编译源字段及路径索引；普通例返回紧凑计数和状态摘要。完整会话仍以追加式日志记录**足以重放的全部输入、调度、首次物化值、事务次序与来源事件**；finding/新增覆盖时才从该日志整理详细证据包和 fresh replay。轻量化不能丢弃 Checker 所需真实输出、事件来源或失败前缀，也不能把 DUT 尚未执行的结果当作覆盖。对不需要继续推进的 harness 可按 Scheduler 的真实 pending/依赖状态减少空转，但仍须满足各 DUT 局部握手、超时和事件可见性。

性能报告用同一源码/profile、相同输入预算和确定种子比较“逐例重新启动”与“长会话连续输入”。分别记录构建缓存命中、一次性初始化/reset、每例 admission、真实 RTL 局部 tick/事务、Router/Scheduler、反馈/Checker、日志写入、每例总时延的 p50/p95、有效 testcase/s、**完整真实传播链/s**、覆盖增量/s、finding 到可重放证据的时间，以及无效/超时例比例。首阶段 10 分钟门禁必须证明长会话在相同有效性和断言条件下提高有用吞吐；若没有提高，先定位瓶颈并优化，不能只报告原始 RFuzz slot 数。任何性能优化都不得跳过真实 RTL、Bound Input 校验、异常输出记录或完整前缀 replay。

### 系统不变量与能力分级

- 基准需求见 [当前设计](../../CURRENT_DESIGN.md)、[持续场景设计](../specs/2026-09-27-persistent-multicomponent-fuzz-design.md)和[生成式 harness 设计](../specs/2026-10-04-generated-local-harness-five-protocol-design.md)。后者扩展了前者最初“仅 OpenTitan 外设”的范围；持久状态、事务和 replay 不变量继续适用。
- 一个测试会话内 CPU/IP RTL、RAM、事务账本、pending event 和场景状态持续；普通 action、RFuzz chunk 与 testcase 边界不触发隐式 reset。会话前缀或经过验证的状态快照是后续 testcase 的 replay 前提。
- Fuzzer 只能改 Fuzzable Source。真实 RTL 输出、Bound Input、已经物化的 RAM 字节和冻结响应不重新随机化；合法 byte-enable 写按真实请求更新对应字节。
- Router 交付带来源的真实数据；Scheduler 决定下一步可生成的输入和执行顺序；checker 独立评价所有真实输出，包括提前或异常 IRQ。
- 保留每个 DUT 的原生接口、局部握手和局部周期。跨组件事件先后不解释为某个具体 SoC 的全局周期或总线时延。
- 能力等级分别记录 `Catalog`、`Generated`、`RTL operational`、`Cross-component accepted`、`Coverage-guided searched`、`Bug confirmed`。一级不能自动推出下一级；故障注入可以校准 checker，但不能作为自然 RTL 缺陷计数。
- BOOM 或其他本地不可执行 CPU 记录 `skipped_unavailable` 和缺少的源码/工具条件，不以静态扫描冒充运行通过。
- 现有工作区有未提交 CPU/IP 适配改动和验收材料。修改前记录文件身份；不要清除 `runs/scenario/acceptance/`、源码锁、用户原件或第三方 RTL。

## 二、逐个阶段的实现情况

本节每个阶段均写明当前状态、已证明能力、剩余工作和完成判据。**完成**指该阶段自身门禁已核对；**部分完成**指有固定场景证据但通用门禁未过；**待实施**指核心交付尚未实现。状态以 2026-10-06 工作区为准，源码变化后需重新核对受影响证据。


### 2026-10-06 初期短跑的代码状态（历史口径）

以下条目记录当天初期短跑。随后 IRQ taken 探针、600 秒长跑、冷启动对照及 UART RFuzz 已有进一步证据，最新范围以运行报告和下方阶段表为准。初期新增代码已落入工作区，并完成一次固定组合的真实 RTL/RFuzz 短跑及 fresh replay，详见[2026-10-06 在线短跑记录](../../reports/ibex-pulp-online-rfuzz-smoke-20261006.md)。状态仍为**实施中**：短跑证明了当前固定组合的启动、双侧取源、持续输入、部分真实传播和重放；不改变 A1～A8 或 P1～P8 的完整验收判据，也不把有序路径当成已证明的因果闭环。

- `memory.py` 与生成式 CPU session 增加在线 instruction slots 预约与指令接纳接口：待提供指令的取指地址可暂缓响应，已接纳或已物化字节禁止覆写。固定 Ibex 组合已在 120 例长会话中真实取走 CPU 指令源；预取、写后再取和跨协议适配仍需更广覆盖。
- `session_runtime.py` 增加 `ScenarioSession`、`OnlineCase` 与逐例 receipt，复用同一 Runner、持久 RAM 和事件前缀；一次性 warmup 的局部推进、预约槽及完整会话输入均进入 replay plan。正常 120 例和受控 finding 的完整前缀 fresh replay 已匹配；部分命令异常另有版本化终止边界和聚焦测试。
- `online_case_decoder.py` 增加 `OnlineCaseDecoder`：根据 RFuzz 源选择字节、coverage hint 和已声明 Dependency Path 选择 CPU 合法 RV32I 片段或 IP 外部 source；CPU 指令检查 cursor 与预约范围，IP 输入检查 source ownership。IP case 可附带固定且不可变异的 NOP 支撑指令，避免 CPU 停在未填取指槽；该支撑动作不计为 Fuzzable Source，并写入完整计划。调用者成功接纳后才提交 decoder cursor，decode 自身不推进 RTL。
- `ibex_pulp_dual_source.py` 增加双源模板和独立 stream bootstrap：固定 Ibex 启动片段配置双 GPIO/IRQ，随后跳到默认 `[0x11000, 0x20000)` 的未初始化在线指令区；初始化镜像、真实 ISR 和 GPIO Bound 接线独立保留。每例 32 轮、96 个局部调度步，不重置三个 RTL；PULP GPIO 在线 MMIO 生成只用 full-word `LW/SW`，当前 CPU 变异目标限 GPIO A PADOUT，以保留 GPIO B 中断前提。真实取指与 IRQ 输入采样已观察；可关联的 IRQ taken/retire 仍未证明。
- `interaction_feedback.py` 已提供事件阶段、消费边、状态变化、闭环证据及 feature delta/novelty weight 接口。真实 trace 中有双 GPIO/CPU 有序读回路径和 IRQ 采样→CPU 读→GPIO A 写路径；`closed_loops=0`，因为尚无 IRQ taken 证据。在线接口已按新增事件/边/路径返回增量见证，reset 边界和 MMIO 字段一致性进入边判定；10 分钟长跑仍待验收。
- `scenario_rfuzz.py` 已新增独立 online decoder 分支：同一 session 逐 slot 接收一条 8-byte RFuzz record（当前 Rust mutator 的 source selector 位于该 record 的 byte 2），记录原始选择权重、规范化 case、真实指令读取/端口消费证据及终止时的完整输入前缀；成功 slot 记为 `complete`，整段会话继续运行。多 record 在线模式在对齐 Rust selector 语义前显式拒绝。live 入口保存完整 plan/trace 和逐例源/反馈记录；`max-tests` 为硬上限，finding 后不再执行剩余批次 slot。固定组合完成 120 例双侧短跑、fresh replay，以及受控断言 finding/replay；尚需长跑和跨 IP/协议扩展。
- OpenTitan UART 的独立 RTL harness 已支持连续 RX 帧，ScenarioRunner 在每个 source action 接纳时只排入一帧；在线计划记录本地调度 tick 并在 fresh replay 比较。Ibex＋OpenTitan UART 同一 Runner 中两个连续 case 分别输入 `0x5a` 与 `0xa6`，真实 RTL 产生接收事件且重放匹配。该定向验收尚未接入 RFuzz 在线双侧变异。

**本轮已做固定组合短时真实 RTL 运行、速度测量与 fresh replay；随后 1000 例连续搜索全部完成并 fresh replay，约 16.50 例/秒，详见[运行记录](../../reports/ibex-pulp-online-rfuzz-smoke-20261006.md)。尚未证明 IRQ taken 意义上的完整闭环，也没有十分钟长跑或连续会话与逐例重启的性能对比。** 受控断言校准证明检测链路，不算真实 DUT bug；扩展组合与自动接入仍按后续阶段验收。

### 原件六类数据流的当前实现情况

| 流 ID | 当前状态 | 现有证据及边界 | 完成该类流还需要什么 |
|---|---|---|---|
| F1 指令流 | 固定 CPU profile 已验收 | Ibex、CV32E40P 等真实取指/程序镜像见[运行能力表](../../LOCAL_HARNESS_RUNTIME.md) | 通用“单条目标指令”动作编译归 P3 |
| F2 数据读流 | 固定 RAM/IP 路径已验收 | 真实 Load/RAM 状态与 IP read data→CPU 的固定组合见[阶段验收](../../reports/persistent-scenario-acceptance-20260927.md)及[运行能力表](../../LOCAL_HARNESS_RUNTIME.md) | 任意选中路径的来源/消费预检归 P2 |
| F3 数据写流 | 固定 CPU/RAM 路径已验收 | byte-enable、写后读和持久状态有固定真实 RTL 证据 | 跨连续 testcase 的通用编译及 RFuzz 长会话归 P3 |
| F4 MMIO 控制流 | 固定 CPU/IP 组合已验收 | CPU 真 MMIO 到 GPIO、UART、I2C、SPI、Timer 等受限 profile 见[运行能力表](../../LOCAL_HARNESS_RUNTIME.md) | 从声明自动选择目标 IP 与局部合法事务归 P2/P6 |
| F5 中断事件流 | 固定 CPU/IP IRQ 链已验收 | GPIO、UART、Timer、I2C 等真实 IRQ→CPU ISR→MMIO/RAM 的定向报告见[报告索引](../../reports/README.md)；未验收通用 PLIC | 路径预检、脉冲/电平交付复用与异常 IRQ 检查归 P2/P5 |
| F6 DMA 搬运流 | 未实现/未验收 | 当前没有真实 DMA master harness、DMA 事务路由或 DMA 完成 IRQ 的闭环证据 | 源码固定的真实 DMA RTL、独立 master session、资源提交与 replay 归 P8 |

“固定路径已验收”只表示该具体源码、profile、协议子集和场景成立，不表示任意同协议组件或原件中全部 SoC 拓扑自动可用。

### 阶段状态总览

| 用户要求的交付步 | 对应阶段 | 当前结论 | 完成门槛 |
|---|---|---|---|
| 第一步：Ibex＋若干 IP 的功能完整初版 | P1～P5 | 部分基础已通过；完整框架未完成 | F1～F5 中选定路径的双向合法变异、同会话多例、持久依赖、覆盖引导、受控故障断言、完整前缀 fresh replay 与效率报告全部通过 |
| 第二步：扩展若干协议的 CPU/IP | P6 | 多个固定实例已有真实 RTL 证据；统一框架复用未完成 | 五类 CPU 协议各有至少一个 CPU＋真实 IP 组合复用第一步完整变异/搜索/断言/replay 流程，目标 IP 系列逐实例定级 |
| 第三步：已支持协议范围内自动测试 | P7 | 未完成通用端到端自动入口 | 新同协议 CPU 和 IP 仅用受信 profile/允许的微调完成生成、路径/输入编译、搜索、断言和 replay |

“框架能检测 bug”以独立断言在受控错误下报警并可重放为能力门槛；自然 RTL bug 的发现数单独统计，不能用注入故障冒充。

| 阶段 | 状态 | 已证明的范围 | 尚缺的门禁 |
|---|---|---|---|
| P0 代码和文档入口 | 完成，仅文件整理 | 当前/共享/历史路径和计划索引已明确 | 不提升 RTL 能力等级 |
| P1 统一 CLI 和能力身份 | 完成，按声明的身份验证范围 | CLI/能力查询、标准 evidence v2、fresh/live/continuous 身份、异常终结、模板声明及 campaign 门禁已验证 | continuous 不重算搜索策略或累计 verdict；后续功能门禁仍归 P2～P8 |
| P2 路径与真实绑定 | **完成（按声明范围）** | RuntimePathContract/启动前预检、源登记/typed快照、认证 RVFI 退休、GPIO 原生消费链与 UART FIFO 留存/路由读取、原生 external IRQ taken、有界受控入口／退休 UART read／host RAM 低字节读回子路径；本轮补齐[通用逐边来源](../../reports/current-dataflow-p2-edge-provenance-20261007.md)（真实 run **9/9 声明边 certified**，含 `gpio_a→gpio_b` 目标侧消费跳）、[持久状态逐边来源](../../reports/current-dataflow-p2-persistent-state-edges-20261007.md)（追加 RAM 字节版本与 GPIO 寄存器位版本两条边，叠加后 **11/11 certified**）、[六个声明破坏变体的零进程预检负例](../../reports/README.md)，并由[P2 阶段验收门禁](../../reports/current-dataflow-p2-stage-acceptance-20261007.md) **exit 0** 汇总（两方向 certified、提前 IRQ 2 个未接受实例仍写入 trace、同 graph 不同 edge identity 的 replay 双向拒绝） | 明示边界：`runs/` 中不存在"不同 edge identity"的真实 run 对（该条为 API 级真实门禁）；`memory_read.writer_event_ids` 仍无整数写事件 id（精确引用形式为写事务键规范 repr）；消费跳依赖目标侧观测的 `segments[].origin.delivery_event_id`；一般寄存器复制仍只到受限 UART 子路径。见[受控路径](../../reports/current-dataflow-p2-controlled-entry-read-20261006.md)、[GPIO 消费](../../reports/current-dataflow-p2-gpio-consumption-20261006.md)和[读回短门禁](../../reports/current-dataflow-p3-host-ram-readback-real-gate-20261007.md) |
| P3 目标动作与长会话 | **完成（按声明范围）** | 固定连续场景、受限在线源、RFuzz 多例共用 Runner、UART 低字节跨逻辑例读回与完整前缀 replay；`source_action.v1` 接入在线 executor（Ibex 取指槽先决条件默认生效）。本轮补齐正向 RAM 跨例消费、byte-enable lane 选择性、IP→CPU→IP 跨例链，并由[P3 阶段验收套件](../../reports/current-dataflow-p3-stage-acceptance-20261007.md) exit 0（7 项关键验收各由至少一个声明 run 证明） | 明示边界：无单 run 全项（最高 5/7）；finding 项为注入校准；`chunk_split_invariance.rtl_event_level` 恒 null；IP 跨例 opt-in 模式曾出现 1 次 `unsupported_irq_overrun`，未做长跑稳定性验收 |
| P4 依赖变异与覆盖 | **完成（按声明范围）** | 路径先选与候选身份、九类合法操作子、反馈与 CPU 侧内部分支覆盖（含 `first_seen`）、energy 与同 seed 基线、整阶段入口 `p4_acceptance_suite.v1` 关键项 8/8 成立（[P4 阶段验收](../../reports/current-dataflow-p4-stage-acceptance-20261008.md)） | 明示边界：F4/SPI 实例属 P6；本预算下无算子显示可测收益；CPU 8 点阈值是搜索质量而非映射缺陷；消费端证书不证内部溯源 |
| P5 断言与效率 | **完成（按声明范围）** | 三类断言分节＋fail-closed 普查、受控故障捕获＋新进程复现、正常对照静默、完整前缀＋启动前身份拒绝、十分钟 600.362953 秒／27 条认证链／自然 finding 0、同预算 16.08×；整阶段入口 `p5_acceptance_suite.v1` 六项关键项全部有证明运行（[P5 阶段验收](../../reports/current-dataflow-p5-stage-acceptance-20261008.md)）；验收后收尾：[UART 链路证书](../../reports/current-dataflow-p5-uart-chain-certificates-20261008.md) 7 certified／30 incomplete（首缺跳具名）与 [UART 路由见证实时证明](../../reports/current-dataflow-p5-uart-routing-witness-20261008.md)（60 例、fresh replay 一致、`report.json` 自带 `source_target_transactions`） | 明示边界：异构外设的**十分钟**长会话未做（十分钟项目前只由 Ibex＋双 PULP GPIO 证明）、UART 侧跨例持久状态未做、故障灵敏度对照未做、链终点不含 ISR→GPIO A 回流、非单 run 全项（单 run 最高 3/6） |
| P6 多协议固定实例扩展 | 未验收，已有实例证据 | 多个固定 profile 的局部及跨组件 RTL 证据 | 非 Ibex 组合复用第一步完整搜索、断言和 replay；五类 CPU 协议及 IP 系列逐项定级 |
| P7 已支持协议自动测试 | 未验收 | 源锁、模板和声明式微调有局部能力 | 新同协议 CPU/IP 不加组件专用代码，自动生成/编译路径/连续搜索/断言/replay |
| P8 真实 DMA 数据流 | 未验收，核心未实现 | 尚无真实 DMA master harness 或闭环证据 | CPU 配置→DMA 真实读写→RAM/IP→IRQ→CPU 与 fresh replay |

状态口径：P4～P6 的“已有基础／实例证据”描述局部实现，不等于阶段通过。新受控入口和退休 read 软件、manifest／安装 hook 已实现并独立审查；首次 v2 运行有取指容量失败，修正版本待新真实 gate。只有新运行实际退出状态、完整 fresh prefix replay 和相应审计完成后才能更新其范围。历史失败、中断和旧 captured-source 结果保留，不重算旧证明为新版本成功。

### 阶段与顺序

```text
第一步：Ibex＋若干真实 IP 的缺陷检测框架
  P0 文档入口 → P1 CLI/身份 → P2 路径绑定 → P3 长会话
  → P4 合法变异/反馈 → P5 断言、故障证据和效率
第二步：P6 将同一框架扩展到多协议固定 CPU/IP 实例
第三步：P7 从已验收协议子集提炼自动生成与自动测试
完整数据流扩展：P8 真实 DMA 主设备路径
```

P2 的路由契约和 P3 的动作 schema 可以分别设计；在 RFuzz 接入点合并前，必须以同一版本化 `path_id`、`source_id` 和 execution identity 对齐。P6 的源码/profile 收集和单组件运行可与 P2～P5 并行，但第二步的完整框架复用须等第一步验收。P7 的自动入口须基于 P6 的已验收协议子集。P8 的 DMA 源码与主设备协议适配可提前准备，其跨组件验收依赖 P2/P3 的路径与持续状态契约。

### 第一步的可执行任务与接口顺序（Ibex＋双 PULP GPIO＋一种异构 IP）

以下任务共同构成第一步，任何一个定向样例单独通过都不等于第一步完成。先固定已有真实 RTL 组合的源码身份，再在同一 Runner 上实现双侧输入与持续会话，最后接 RFuzz/反馈和缺陷检测。接口名称是本计划的目标契约；现有代码中尚未出现的名称不能记作已实现。

| 任务 | 依赖 | 主要文件 | 应交付的可核对接口/行为 | 最小验收 |
|---|---|---|---|---|
| A1 固定双侧试点 | P0 | `src/myfuzz/scenario/ibex_pulp_dual_source.py`、`configs/scenario/`、`configs/cpus/ibex_obi_local/`、`configs/peripherals/pulp_gpio/` | **同一个** Ibex＋GPIO A＋GPIO B Runner：CPU 程序是启动源；B 的独立外部 pin 位是 IP 源；A 真实输出绑定 B 的另一些 pin 位；B 真实 IRQ 绑定 CPU。两套合法 seed 能分别触发 CPU→A→B→CPU 和 B 外源→CPU→A，且不能以两个单向 factory 的结果冒充同一 Runner。 | 源归属逐位无重叠；CPU、IP 各能独立改变真实上游 RTL 输出；B 已绑定 pin、CPU IRQ、CPU rdata 的随机输入均被拒绝。 |
| A2 RV32I 小指令与初始数据源 | A1 | `src/myfuzz/scenario/rv32i_sources.py`、`src/myfuzz/scenario/{genome,mutation,memory}.py`、CPU profile 的 ISA/地址字段 | 版本化 `instruction`/`program_fragment` 源只接受 `LUI/ADDI/LW/SW/SB/NOP`；按寄存器、立即数、字节宽度和**可静态证明**的 MMIO 地址窗口/权限生成或变异；运行时地址仍由 CPU 真请求和 Router 核对。会话开始前的初始 RAM 数据可作为 seed 源；会话内只有未物化数据字节在首次读取时可选值并冻结，已有字节不得重填。固定 ISR/CSR 不列为随机指令。 | 变异前后均解码为允许指令；可证明的 MMIO 越界/错位/只读寄存器写在进入 RTL 前拒绝；动态地址的真实 CPU 请求在 Router 接纳前合法校验；真实 Ibex Fetch→MMIO→IP 输出存在；首次未知读值复用、真实 Store 覆盖后读取新值。 |
| A3 在线 CPU 指令接纳 | A2 | `src/myfuzz/scenario/{memory,memory_service,runner,batch}.py`、`src/myfuzz/local_harness/cpu_session.py` | 目标 `admit_instruction(case_id, address, word)` 只向**尚未完成取指响应、未物化、未被真实 Store 决定**的合法程序槽提交一次指令。指令取指请求先到、输入尚未到时按 OBI 局部握手保留请求/等待，不走普通数据 RAM 的首次随机物化；提交后才返回已保存的 word。CPU 仍经原生 Fetch 取指；记录 slot/admission/fetch 及 writer 来源，禁止直接随机 `instr_rdata`。启动前 `MemoryImage` 继续可用于固定引导程序。 | 插入指令后等待中的真实取指读到该字；在程序槽等待时 DUT 不被重置、RAM/IRQ 仍保持；已回复的取指、Store 写过或重复不同值的地址均拒绝且内存无副作用；超时留下可重放的待决请求，同 ID 重试只返回原回执。 |
| A4 长会话与逐例反馈边界 | A1～A3 | `src/myfuzz/scenario/{runner,batch,genome,evidence,replay}.py`、`src/myfuzz/integration/scenario_rfuzz.py` | 目标 `ScenarioSession.begin()` 一次、`submit_case(SourceDecision)` 多次、`finish()` 一次。每例有 `session_id/case_index/case_id`、输入 hash、前后状态摘要、事件范围与局部 tick 差值；只划反馈边界，不调用 DUT reset/finalize/quiesce。pending 事务/IRQ 能进入后例。完整前缀记录首次未知 RAM 字节/来源、合法调度与等待选择、事务接纳顺序、RFuzz 原始输入及解码版本。 | 三例连续运行只启动/reset 一次；第 1 例 Store 后第 3 例 Load 返回原字节，byte-enable 与首次未知读保持；更改任一物化字节/调度选择/事务顺序的 replay 被拒绝；失败例后不接纳新例。 |
| A5 路径与输入接纳契约 | A1～A4 | `src/myfuzz/scenario/{dependency,ownership,contracts,router,scheduler}.py`、`configs/scenario/` | 把 F1～F5 的选中路径编译为 `RuntimePathContract`：真实生产者、真实消费者、绑定宽度、协议前置条件、持久版本与终止观察。每次 case admission 重查当前 Ownership 与状态；Router 传值，Scheduler 安排允许动作，checker 评价真实输出。 | CPU/IP 两侧都有 Fuzzable Source；对已绑定 rdata/IRQ/GPIO pin、已提交 RAM 字节和错误协议阶段的随机输入，拒绝且不推进 DUT。提前 IRQ 原样记录。 |
| A6 真实交互反馈 | A4、A5 | `src/myfuzz/scenario/{interaction_feedback,feedback,state_dependency}.py`、`src/myfuzz/integration/scenario_rfuzz.py` | 从事件 trace 提取 `stage_hits`、`edge_hits`、`state_transition_hits`、`closed_loop_hits`；每条命中带路径、源、真实生产事件、交付事件、消费事件或事务 ID。跨例来源仍指向原始 case；仅有注入、没有本地消费时不能算有效传播。 | 单向源变异可分别获得 CPU→IP 与 IP→CPU 的真实阶段命中；删除任一交付/消费证据后对应边与闭环命中消失；RAM RAW/WAW 与 IRQ taken 分开计数。 |
| A7 双侧覆盖引导搜索 | A2～A6 | `src/myfuzz/scenario/{mutation,rfuzz_decoder}.py`、`src/myfuzz/integration/{scenario_rfuzz,scenario_rfuzz_live}.py`、`third_party/rfuzz/` 的必要 mutation sideband | 每轮先选 flow/target/path，再按**当前状态和交互反馈**从 CPU 指令源或 IP 外部源选择 mutation；合法值生成后交给同一长会话。目标/路径/源/操作子及能量写入 receipt。不能用 direction 标签硬限制源，也不能机械 CPU/IP 交替。运输会话显式 `open → submit slot → receipt/feedback → next slot`，finding 或预算结束时停止接纳并关闭；限制 outstanding slot 或明确背压。按 `(session_id, buffer_id, slot, raw_hash)` 幂等处理 chunk/slot 重传，不逐 slot 新建 Runner。热路径复用预编译路径/源约束，按事件游标更新反馈。 | 固定种子下至少有一次 CPU 侧和一次 IP 侧变异均引出真实下游差异；反馈变化能改变后续选择；连续 slots 共享同一 RTL/RAM 状态，下一例拿到上一例反馈；重复 chunk 只返回原 receipt，finding 后的 slot 被拒绝；Bound Input 在解码、接纳和运行三层均不可写；逐例无 harness 重建或完整历史重扫。 |
| A8 断言、证据与首版门禁 | A1～A7 | `src/myfuzz/scenario/{checker,evidence,replay}.py`、`tests/integration/`、`docs/reports/` | 对协议、来源、值一致性、事件先后、事务至多一次和真实异常 IRQ 建立独立断言；finding 停止继续输入，原子保存**截至触发例的完整会话前缀**、首次未知字节、调度/等待选择、事务接纳序、raw RFuzz 输入/解码版本及 pending 状态；新 harness 从初态按原命令边界重放。再将相同框架接到一个不同协议/行为的 Ibex＋OpenTitan TL-UL UART 或 SPI Host 场景。 | 受控错误可报警且 fresh replay 同一 finding，正常对照不报；改动任何前缀输入/身份后 replay 不互认；两种外设类型均有双侧源、完整链与重放证据；10 分钟运行报告编译/初始化一次成本、每例时间、有效链、各类反馈和真实 finding 数。 |

任务 A1、A2、A6 已有固定组合的真实短跑证据：同一 Ibex＋双 PULP GPIO Runner 在连续 120 例中选出 CPU 在线指令源和 GPIO B 外部 pin 源，并观察到真实 MMIO、绑定输入、IRQ 采样、IP 读回与 fresh replay。`scripts/run_ibex_pulp_online.py run` 是试点入口；live 入口保存完整前缀 `online_plan.json` 和 `online_final_trace.json`，`scripts/run_ibex_pulp_online.py replay` 新建 RTL 会话比较完整事件序列。路径反馈目前只证明**有序且带数值见证的传播路径**，未证明 IRQ taken 意义上的完整闭环；A1～A8 的完成标记须等各自全部验收证据齐备后再更新。在线模式每 slot 限一条 8-byte RFuzz record，并为 IP 源 case 提供固定 NOP 支撑指令；这些限制应在后续扩展中明示。

第一步的执行证据至少保存：固定源码/profile/toolchain 摘要，case 输入原始字节与解码结果，`flow_id/path_id/source_id/operator`，case 前后状态摘要，真实 Fetch/MMIO/IRQ/Binding/Memory 事件及关联 ID，增量交互反馈，checker 结果，完整前缀 fresh replay 对比，以及每例/整个会话的时间与资源统计。`case_index` 只表示输入/反馈记账；前例引起、后例才消费的事件必须保留最初来源，不得强行归为后例的新输入。

**建议的逐门禁验证命令（实施对应任务时创建并执行，不代表当前已运行）：**

```bash
PYTHONPATH=src python3 -m unittest tests.scenario.test_rv32i_sources -v
PYTHONPATH=src python3 -m unittest tests.scenario.test_interaction_feedback -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_dual_source_long_session_real -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_uart_long_session_real -v
MYFUZZ_SCENARIO_RFUZZ_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_rfuzz_live_session_real -v
```

第一条检查 RV32I 编码、MMIO 地址/权限和非法变异拒绝；第二条用真实 trace 摘要与删边/删消费负例检查交互反馈；后三条依次核对同 Runner 双侧源、异构 UART 场景和 RFuzz 多 slot 长会话。所有真实 RTL 命令必须保存退出码、源锁与证据包。10 分钟效率/搜索门禁另用固定 seed、同一组件身份与明确预算运行，并同时报告自然 finding=0 的情况；不能用单元检查或历史定向报告代替这些门禁。

### P0：整理当前代码与文档入口——完成（仅文件整理）

**文件：** `README.md`、`QUICKSTART.md`、`docs/README.md`、`docs/CODE_ORGANIZATION.md`、`docs/superpowers/plans/README.md`、`docs/reports/README.md`、`scripts/README.md`。

- [x] 标明当前执行链及旧完整 SoC 路线的共享源码，不按 `soc` 文件名批量移动。
- [x] 保留旧报告和计划的原路径，建立唯一当前实施计划、专题计划索引和当前报告入口。
- [x] 更正旧文档中仍自称当前目标的文字；已移出文件有仓库外恢复清单。

**验收：** 当前入口能从目标→代码→运行能力→报告→下一项任务连续导航；当前 Markdown 本地链接无断链；工作区原有修改和用户材料保持原样。文件整理本身不提升 RTL 能力等级。

**已有证据：** [代码组织图](../../CODE_ORGANIZATION.md)、[计划索引](README.md)、[报告索引](../../reports/README.md)及[清理审计](../../reports/current-design-cleanup-source-audit-20261006.md)；2026-10-06 静态检查的 242 份 Markdown 本地链接无断链，未运行 RTL 功能测试。

### P1：统一当前命令入口和能力身份——完成（身份与入口范围）

**当前情况：** 当前 harness/scenario 命令与脚本共用 parser 和 handler，旧矩阵位于 `compat soc`。`capabilities` 查询运行能力表的实际等级、限制和证据，明确 `runtime_revalidated=false`。标准 evidence v2、fresh/live RFuzz 及外层 campaign 已保存版本化身份；campaign 先快照 provider 明确声明的输入闭包，各 cell 使用快照运行。运输异常后保存实际 report/identity，无法生成完整身份时明确保存 incomplete；旧 continuous decoder 保存完整接纳前缀及两层 checker 身份。23 个已接纳 runtime kind 均声明版本化 `selected_template.executor`，不提升协议或 source-lock 等级。

**前置：** P0。**主要文件：** `src/myfuzz/__main__.py`、`scripts/{generate_local_harness,record_scenario,replay_scenario,run_scenario_campaign}.py`、`src/myfuzz/scenario/identity.py`、`src/myfuzz/local_harness/runtime_artifact.py`、`docs/LOCAL_HARNESS_RUNTIME.md`。

- [x] 给 `python -m myfuzz` 增加明确的 `harness generate`、`scenario record`、`scenario replay`、`scenario campaign` 子命令；旧 SoC 矩阵转为 `compat soc check|preflight|run`，保留原参数语义及真实运行环境门禁。
- [x] 标准 evidence v2 将组件/source/profile/build、Genome、checker、反馈和工具链关联为不可变 run identity，并计入启动前预算和最终字节数；固定 Genome 执行没有 decoder graph，明确记录 `not_applicable`，不从路径名构造图。
- [x] fresh/live RFuzz 保存真实 Runner 身份、完整 decoder graph/templates、targets、checker、源与工具链、输入/回执及实际 trace/corpus/failure artifacts；新证据 replay 在 factory 前校验保存材料、源码及声明身份，在实际 Runner 构造后、begin 前比较运行身份。
- [x] campaign 快照内置 provider 明确声明的主输入和间接 seed，按实际 cell 关联运行身份与辅助证据；原输入、快照或快照符号链接发生变化时 gate incomplete，custom provider 未提供的闭包/执行证据明确记录限制。
- [x] `capabilities [--match TEXT]` 与独立脚本共用实现，直接返回运行能力文档的等级、限制、行号、摘要和证据链接；不自动提升 source-lock 或组件等级。
- [x] fresh RFuzz 运输异常后原子保存实际 report/identity，保留主异常；终态身份生成失败时保存 incomplete 并拒绝 campaign complete。continuous 路径保存实际接纳前缀、session/decoder checker 身份及声明范围的 fresh replay；所有已接纳模板均有显式版本身份。
- [x] 让脚本入口与统一入口调用相同 parser 和 handler，避免两套解析和身份规则。

**已验证：** 稳定源码整合回归 219 项通过、5 项按环境门禁跳过；campaign 身份与全部实际 Rust client 运输检查 16 项通过。真实 Ibex＋双 PULP GPIO 的标准 evidence v2 保存 1,061 个事件，准确字节数 1,707,617，模板状态为 declared，完整 fresh replay 匹配（40.540 秒）。P1 收尾版本的 UART live RFuzz 完成 1 例，完整前缀 fresh replay 匹配。后续 P2 修改身份闭包时须按新源码重新记录证据。脚本与 module 入口生成材料/证据的字节一致性有定向检查。新扫描仍在初始化或终结阶段，online slot 不新增 Runner 身份扫描。详见[本阶段报告](../../reports/current-dataflow-p1-cli-identity-20261006.md)。

**验证范围：** continuous replay 重放完整已接纳前缀、执行 session checker 并核对 decoder checker 身份；不重算 RFuzz 策略、候选反馈或累计 decoder checker verdict。cleanup 失败时保存实际 running/失败前缀，不保证正常终结 replay API 自动匹配它；磁盘写入失败可能阻止证据保存。P1 完成仅指入口与身份门禁；吞吐、路径契约及整体缺陷搜索仍按 P2～P8 验收。UART 吞吐终止语义尚待定义。

### P2：把依赖路径绑定到实际运行数据流——部分完成

**后续受限关联：** [原生 STEP_CPU 回执约束的 pin8→trap 退休审计](../../reports/current-dataflow-p2-pin8-native-trap-relation-20261007.md)在已保存真实 trace 中得到 4 条逐 tick 连续关联；[后续来源归属审计](../../reports/current-dataflow-p2-native-trap-attribution-audit-20261007.md)修复了中间 native post notification 伪造可误通过的问题，并明确了 Ibex RVFI 流水级 serial 所需的硬件侧接线。RVFI 退休仍无硬件来源 token，不升级为精确逐边来源证书。

2026-10-06 接续：三个子代理与 root 并行完成 GPIO 消费和 UART FIFO 来源子任务。GPIO 最终别名修正版本通过 637 项软件、5 项真实 RTL、16 例在线及完整 fresh replay；旧容量/来源别名不足的证据保留。UART 独立 `--uart-fifo` 变体通过 738 项软件、2 项真实 RTL、4 例 Ibex 在线及完整 fresh replay，实际追加 4 条 FIFO 留存、4 条路由读取证明；其中每类 bootstrap 1、fuzz_source 3。原生 IRQ/CPU taken/ISR 来源及 CPU 操作数消费仍待闭合，P2 保持部分完成。范围见 [GPIO 报告](../../reports/current-dataflow-p2-gpio-consumption-20261006.md)、[UART FIFO 报告](../../reports/current-dataflow-p2-uart-fifo-consumption-20261006.md)和[UART 并行进度](../../../.superpowers/sdd/current-dataflow-p2-task4-uart-fifo-parallel-progress.md)。这些结果各按记录时冻结源码身份解释，不升级旧证据。

2026-10-06 下一轮实际闭合：认证 CPU 原生 IRQ 输入 PRE/POST 与决策凭据、有界 UART native cause／交付／sample／taken join 通过 4 项真实门禁＋7 个删除子检查，48,378 个完整 wire 事件与 local ticks 新进程 replay 一致。4 个实际 taken 与原始 bootstrap 1／fuzz_source 3 来源关联，20 个因果输出版本明确区分。FIFO 与 join 历史安全回收经过 260／1100 周转验证；实际来源 alias、reset role、上下文删除及原始 JSON 比较缺陷已修复。旧失败证据保留，受控 ISR 入口、实际退休读取与反馈闭环仍在后续工作中，P2 保持部分完成。详见[原生 IRQ 实施报告](../../reports/current-dataflow-p2-uart-native-irq-20261006.md)。

**当前情况：** 固定场景已能用 Router、Binding 和 Scheduler 传播真实值。已完成入口审计：逻辑图节点不等于物理端口，须显式受信声明；同源 OR 路径须保留 edge 身份和旧 corpus 映射。edge-aware 路径、显式静态 compiler 和通用 fresh 可选 hook 已通过基础接口验收（275 项整合回归、5 项环境跳过；新模块 34 项）。新 decoder 的 edge-aware 缓存、fresh/live/continuous/online 接纳及运行身份/replay 接入已落地；接续独立审查发现的启动前 expected source ownership、uncertain_effect 分类和 replay-only 搜索限制已修复。root整合317项、5环境跳过、零失败；当前源GPIO在线120例完整前缀fresh replay匹配，属于Task3接纳/身份门禁。Task4已新增跨例来源登记、typed RAM writer快照、逐边候选与schema10/11 replay，397项整合（5环境跳过）、当前源GPIO120/UART2完整replay通过，见[来源进度](../../reports/current-dataflow-p2-source-provenance-20261006.md)。MMIO/IRQ源因果仍未知，逐边完整来源尚未验收，因此P2仍部分完成。接口/剩余任务见[专题计划](2026-10-06-runtime-path-contract-implementation.md)及[阶段报告](../../reports/current-dataflow-p2-path-contract-20261006.md)。设计细化见[运行路径设计](../specs/2026-10-05-rfuzz-runtime-dependency-route-validation-design.md)。

**前置：** P1 的身份字段。**主要文件：** `src/myfuzz/scenario/{dependency,ownership,router,scheduler,contracts}.py`、`src/myfuzz/integration/scenario_rfuzz.py`、`configs/scenario/`，新增版本化路径契约 schema 与编译器。

- [x] 新 edge-aware API 给每条 rule/prerequisite edge 稳定身份，同源 OR 路径保持不同 path digest，不被 source_ids 合并；旧 paths_to 保留 decoder v1/v2 映射。新搜索 Genome v3/online v2 的 schema、编译缓存、身份与启动前接纳已落地；Task3软件/真实门禁见阶段报告。
- [ ] 以用户的 `SoC内部数据流动与去向.docx` 的 F1～F6 为完整数据流类别清单，建立版本化、可执行的场景路径声明：取指、RAM/IP 读、RAM 写、MMIO、IRQ 和 DMA master 搬运。端点、先决条件和输入所有权由受信 profile/声明填写；运行时不能从自然语言或端口名猜测 RTL 语义。F6 的真实 RTL 运行在 P8 验收。
- [ ] 由受信组件 profile/场景配置声明每条跨组件边的实际实现：物理 Binding、CPU MMIO→IP 事务 Router、纯因果条件或持久资源版本。记录生产端、消费端、宽度、协议窗口和来源证据。
- [ ] 在长期会话启动前编译基础 `RuntimePathContract`，每次接纳 testcase 前核对选中路径与当前状态；选中边缺绑定、宽度不符、来源身份不符、重复驱动或把真实输出列为随机源时，拒绝该输入，且不推进 RTL。
- [ ] 运行中把每条交付附上来源事件、事务 ID、状态版本和 `path_id`；未就绪时等待或报告 incomplete，不合成 DONE、IRQ 或 read data。

**验收：** Ibex→GPIO A→GPIO B→Ibex 与 GPIO B 外部源→Ibex→GPIO A 两条路径由版本化声明实例化，均有逐边交付/消费记录；切断 A→B 或删除 IRQ 绑定在预检或 checker 中给出可定位失败；真实 IP 提前 IRQ 仍写入 trace。相同 graph 与不同 edge identity 的 fresh replay 不得互认。新增同协议组件时路径声明可复用，端点映射按其 profile 微调。

### P3：目标动作 testcase 与持续测试会话——部分完成

**当前情况：** [持续场景阶段验收](../../reports/persistent-scenario-acceptance-20260927.md)证明固定场景内的 RAM、byte-enable、事务和 replay；早期 [online batch](../../reports/generated-ibex-pulp-gpio-online-batch-20261005.md)把三轮 source 事件记为单个 testcase。当前 Ibex＋PULP/UART 的 `online_decoder` 分支已通过 `ScenarioSession` 在同一 Runner 上接纳独立 case 并返回增量反馈，见在线 RFuzz 报告。[Store 真实短门禁](../../reports/current-dataflow-p3-store-real-gate-20261007.md)证明受限 UART 来源经退休 Store 到 host RAM 低字节 writer 的两次连接；后续[读回短门禁](../../reports/current-dataflow-p3-host-ram-readback-real-gate-20261007.md)在另一冻结快照中证明一次到后续例退休 `lw` 的读回，均完整 fresh replay。它们不证明通用动作或通用跨例状态。标准 fresh decoder 分支仍逐 slot 创建 Runner，属于单独执行模式；通用路径动作契约、逐例终止观察和各项长会话门禁尚未全部完成。

**前置：** P2 的路径/所有权契约。**主要文件：** `src/myfuzz/scenario/{genome,batch,runner,memory,ledger,replay}.py`、`src/myfuzz/integration/{scenario_rfuzz,scenario_rfuzz_live,scenario_rfuzz_replay}.py`、`configs/scenario/`。

- [ ] 定义版本化源动作 `instruction`（未来合法取指地址和目标指令）与 `external_event`（未绑定 IP 源），并把 `interrupt_flow` 作为观察目标/完成条件而非可直接注入的 CPU IRQ。每个动作有前置条件、源归属、终止观察和预算；设置指令需真实 CPU 取指，不直接驱动 CPU 内部执行结果。
- [ ] 将 `session_id` 与 `case_index/testcase_id` 分开：会话只初始化一次并持有 Runner、RTL 进程、Memory Service、ledger、pending event 和覆盖累计状态；每次 `submit_case` 仅接纳新的合法上游输入，在目标消费/终止观察后返回本例反馈，再接纳下一例。
- [ ] 将 `scenario/batch.py` 的在线输入与 RFuzz live 对齐：RFuzz 显式打开长会话，多个 slot 依次得到 admission、receipt 与反馈后才继续供给下一例；finding/预算/用户结束时关闭。去掉正常路径中的逐 slot `record_scenario(..., factory)`；按会话、buffer、slot 和 raw hash 缓存回执，重复 chunk/slot 只返回原 receipt，不重复执行。限制 outstanding slot 或显式背压；若传输允许并发，先按确定性提交顺序串行接纳并记录，不根据到达时刻猜测 SoC 时序。
- [ ] 每例保存输入哈希、前状态摘要、真实事件范围、后状态摘要、增量覆盖与 checker 结果；完整前缀另保存首次未知内存物化值、合法调度/等待决策、事务接纳顺序、raw RFuzz 输入与解码版本。内存首次物化、byte-enable 写、读快照、pending IRQ 和局部 tick 跨例持续。CPU 指令只能在尚未完成取指响应的合法程序槽进入内存，不能覆盖已回复取指或真实 Store 决定的字节。
- [ ] 一旦 checker 给出 DUT finding，停止接纳后续 testcase，原子保存包含触发例在内的完整会话前缀、未完成事务与失败点；新进程从初态按序重放该前缀。显式 reset/预算结束另有独立结束原因，不清除已保存故障。

**验收：** 一个真实 RTL 会话顺序执行至少三个有独立 ID、独立反馈的 testcase，只初始化、启动、初始 reset 一次，期间无 harness 重建。第 1 例 `Store M[A]=X`，第 3 例 `Load M[A]` 必须返回 X；byte-enable 只覆盖相应 lane，首次未知读后复用，真实 IRQ/pending event 可跨例由 CPU 消费。CPU→IP→CPU 和 IP→CPU→IP 能跨例完成。逐例反馈改变下一例输入；注入一个断言失败后后续例不再执行，保存的前缀在 fresh harness 中重现同一失败。RFuzz chunk 切分不改变规范化事件/末态；换 execution ID 不接受旧回执。

### P4：按路径选源变异并用覆盖反馈调度——未验收（已有基础）

**补充证据：** [CPU `ADDI` 结果到 UART `SB` 的受限架构审计](../../reports/current-dataflow-p4-computed-uart-store-audit-20261007.md)从既有真实 trace 复核连续 RVFI 退休、实际 rs2 值、同键 MMIO 事务及串口输出。没有寄存器文件／UART FIFO 内部来源 token，不作为通用计算到 IP 的完整链证书。此后 [35 个版本化拒绝码](../../reports/current-dataflow-p4-rejection-codes-20261007.md)接入 live 回执键，并由[定向校准运行](../../reports/current-dataflow-p4-rejection-calibration-real-20261007.md)在真实 RTL 上产出 7 类结构化拒绝（decode/budget/mmio/ownership 四层，各带精确 `code`/`pointer`）与 1 类 `uncertain_effect`；[闭环反馈消费](../../reports/current-dataflow-p5-chain-acceptance-20261007.md)已能把 certified 链计为 `closed_loop` 命中并换算 `energy_weights`（默认不接线）。仍未验收：把该能量真正接入 live 选源的 A/B 真实对照、更多合法操作子、以及"计算结果到外设"的通用传播证书。

**补充证据：** 声明式路径／源切换算子的软件门（[算子与 slot 不可变性](../../reports/current-dataflow-p4-path-switch-operators-20261007.md)：真实 profile F4/F5 互切、bound/fixed 切片按 ownership 拒绝、伪造记录摘要拒绝、有界保留淘汰；真实运行只读判定 p3 1716/1716、p4 1296/1296 slot `immutable`）与它的 [live 真实门禁](../../reports/current-dataflow-p4-path-switch-live-20261007.md)（`MYFUZZ_PATH_SWITCH` 默认关闭，对照枝 46/96、2,400 例长枝 1199/2400 例候选被重定向到声明池内另一路径；三枝 96/96、96/96、2400/2400 例的 `candidate_id` 与算子内容摘要逐例独立复算一致，report 计数零不一致，两枝 fresh replay `matches=true`）已补上本条里的"合法路径切换操作子"与"每种操作子保存采用/拒绝原因"。0 拒绝是**窗口未到预留边界**的实测结果（长枝余量 99,076 字节），真实声明下的拒绝由同报告的软件门证 `budget.exhausted@switch.source_id`。仍未验收：switched 路径下的"计算结果到外设"通用传播证书、路径切换对覆盖/完整链收益的同预算对照。**本轮补充：**CPU 侧内部分支覆盖的映射缺陷已修复并在真实 RTL 上验证（[CPU 侧覆盖映射修复真实生效](../../reports/current-dataflow-p4-cpu-side-branch-coverage-real-20261008.md)：CPU `elaborated-lit=12`/64、`unelaborated-bound=0`、覆盖身份 verified 30/128；门禁 8 条判据 7 条通过，唯一 FAIL 是 legacy 单 cell 不声明 RVFI opcode 前置，故 verdict=INCONCLUSIVE）；"合法初始 RAM 数据操作子"也已完成真实门禁。**本轮再补三项：**`first_seen` 写侧记录已实现（soc_* 每测试计数器回读 → 有界身份绑定台账，39 项测试，无需改 Rust/harness/协议）；[通用计算→外设消费证书](../../reports/current-dataflow-p4-computed-consumer-generic-20261008.md)已落地（12 类声明式见证、192 认证／528 拒绝／0 unknown）；[CPU 侧门禁可判定化](../../reports/current-dataflow-p4-cpu-side-gate-decidability-20261008.md)路线已证明并备好驱动（profile 路径声明 RVFI opcode 窗口 `[228,239]`），并新增整阶段验收入口 `scripts/run_p4_acceptance_suite.py`（当前关键项 6/6 成立）。**本轮真实结果：**first-seen 台账已在真实运行上落地（300 秒／54,157 次 RTL 测试／点亮 30/128，`first_seen.available=true`，独立交叉复核 exit 0）；profile 路径 CPU 侧门禁已可判定——`--min-cpu-points 1` 下 8/8 判据全过、exit 0，`--min-cpu-points 8` 仅因 CPU 点亮 6/64<8 而 FAIL（搜索质量，不是映射）；slot 不可变性全扫描 36,985 slot 全 immutable、0 violated；臂等价判定 5 对无一对 `claimed=true`。**P4 阶段验收已授予（按声明范围）：**first-seen 与可判定 CPU 门禁已并入验收套件关键项，`p4_acceptance_suite.v1` 关键项 **8/8 成立**；四条清单项与验收口径逐项证据及边界见 [P4 阶段验收报告](../../reports/current-dataflow-p4-stage-acceptance-20261008.md)。仍未覆盖（属 P5/P6 或后续工作）：F4/SPI 与异构外设实例、更长预算/非饱和目标集下的操作子收益、故障灵敏度对照、链终点回流。**本轮再补两项：**指令插入/删除的[真实门禁](../../reports/current-dataflow-p4-sequence-edit-real-gate-plan-20261008.md)两枝各 8/8、六项判据全部 proven（种子直投 + 指令通道取指 + RVFI 逐字退休 + 保留区走查 + fresh replay）；算子收益的[同预算对照](../../reports/current-dataflow-p4-operator-benefit-comparison-20261008.md)给出诚实结论（本预算下无覆盖/链收益：初始 RAM 96/96 判定一致、路径切换不改目标位与链数、闭环能量改选源但证书更少）。

**当前情况：** `scenario/mutation.py` 有固定 target/path/source 选源与 Genome bit 变异，`feedback.py` 有端口 mask/value 语义目标；[在线路径先选与 flow 身份](../../reports/current-dataflow-p4-online-path-selection-20261007.md)已通过软件门禁并接入真实 GPIO/UART 工厂的 F4/F5 主要目标声明。[在线 XORI 真实退休短门禁](../../reports/current-dataflow-p4-xori-retirement-real-gate-20261007.md)证明 3 条精确指令来源与 RVFI 退休；[UART WDATA lane 0 `SB` 短门禁](../../reports/current-dataflow-p4-sb-uart-byte-real-gate-20261007.md)又证明单条 RVFI 退休经 `be=1` MMIO 投递到实际串口字节。[候选身份真实短门禁](../../reports/current-dataflow-p4-candidate-identity-real-gate-20261007.md)将路径、源与操作子身份写入回执并完成 25 例 replay。[选择与接纳原因门禁](../../reports/current-dataflow-p4-candidate-disposition-real-gate-20261007.md)进一步区分直接/权重回退选源及提交、拒绝、不确定阶段。[同前缀反馈因果分支](../../reports/current-dataflow-p4-feedback-causal-branch-20261007.md)证明一条真实交互增益可在受控同 raw 输入下改变后续实际源。[同源码基底 1,000 例路径选择器对照](../../reports/current-dataflow-p4-path-selector-paired-1000-20261007.md)证明 F4/F5 分布均衡化、IRQ 观测增多，但目标位和交互新特征种类未增加。更多操作子、细粒度约束拒绝码和到 IP 的广泛传播仍缺。本轮新增 `candidate_rejection.v1` 的 35 个分层拒绝码（ISA／字段／片段／MMIO／解码／所有权／槽位／预算／路径，含失败指针与冻结目录摘要）及 `decode_candidate()`/`commit_candidate()` 结构化处置接口，66 项定向测试与兼容性回归通过；但 live 回执尚未改用该接口，且真实拒绝／不确定例与完整 P4 搜索仍未验收。[Ibex＋双 PULP GPIO 的 600 秒记录](../../reports/generated-ibex-two-pulp-gpio-acceptance-20261005.md)是定向搜索，不是通用 RFuzz coverage-guided 搜索。

**前置：** P2、P3。**主要文件：** `src/myfuzz/scenario/{rv32i_sources,mutation,opentitan_mutation,interaction_feedback,feedback,dependency,genome}.py`、`src/myfuzz/integration/{scenario_campaign,scenario_rfuzz,scenario_rfuzz_live}.py`。

- [ ] 先按 F1～F6 的主要数据流目标和反馈选可执行路径，再从目标的反向依赖路径选择当前可控的最上游 Fuzzable Source；CPU 和 IP 源同时参加候选排序，不将 `Mutation Direction` 当成单侧输入禁令，也不按固定频率交替。把方向、`flow_id`、路径、源与操作子写入候选身份。已绑定输入和持久字节不出现在可写字段集合。
- [ ] 加入合法 CPU 指令替换/插入/删除/操作数/立即数、初始 RAM 数据、外设环境源、因果序列、合法路径切换操作子；指令序列操作仅触及尚未完成取指响应、未物化且未由真实 Store 决定的程序区域。初始数据在会话启动前变异；会话内仅未知数据字节的首次读取可物化一次。每种操作子保存采用/拒绝原因；ISA、外设寄存器和协议字段的可变 mask/范围由受信 profile/模板核对。
- [ ] 从真实事件分别建立路径阶段、依赖边、状态转移、完整闭环反馈；每条反馈附生产、交付、消费或事务身份，缺少下游消费时只算阶段到达，不算完整传播。另区分端口语义目标与真实 RTL branch 覆盖的来源；只有插桩并证明来自 CPU/IP RTL 的数据才报告为内部 branch coverage。
- [ ] 根据新目标、新传播边和失败证据分配后续 mutation energy；保留同 seed、同时间、同组件身份的独立驱动基线。

**验收：** 指定 F5/CPU IRQ 目标时实际变异上游 GPIO pin/程序源，不能直接覆写 CPU IRQ；指定 F4/SPI transfer 时实际变异上游 CPU 程序或 SPI peer。受信字段描述拒绝协议保留位、错误宽度和已绑定输入；真实 Store/取指后的程序字节不能被后例变异。候选 trace 能显示所选流类别、path、变异 source、前状态、真实中间输出和下游消费；同一条跨例链的增量反馈至少一次改变后续选源/能量。固定预算对照分别报告有效执行数、完整链数、各类覆盖与 replay 成功数，不把值变化当 RTL 内部覆盖。

### P5：断言发现、故障保存与效率门禁——已完成（按声明范围）

**整阶段验收已授予：** [P5 阶段验收报告](../../reports/current-dataflow-p5-stage-acceptance-20261008.md)。入口 `scripts/run_p5_acceptance_suite.py`（`p5_acceptance_suite.v1`）在 7 个声明运行上**联合判定六项关键项 6/6 成立、exit 0、unmet=[]、no_proving_run=[]**：三类断言分节＋fail-closed 普查、受控故障真实捕获＋新进程复现、正常对照静默、完整前缀＋启动前身份拒绝、十分钟 600.362953 秒／368 例／27 条认证链＝0.044973 链/s／自然 finding 0 如实记零＋fresh replay、同预算 16.08×（链/s 等价如实记不可测）。效率清单的 12 个分组由 `scripts/report_p5_arm_metrics.py`（`p5_arm_metrics.v1`）逐项落到三个真实臂。**该完成明确不主张**：自然 RTL 缺陷（如实记 0）、故障质量/灵敏度对照、ISR→GPIO A 回流链终点、单 run 全项（`heterogeneous_uart` 单跑 0/6 被完整报告）。**验收后的两条 UART 收尾：**①[UART 链路证书](../../reports/current-dataflow-p5-uart-chain-certificates-20261008.md)把"UART 侧完整链证书为 0"补成 **7 certified／30 incomplete**（16 跳声明 DAG；7 条各带 16 条已见证跳、`irq_mode=irq_taken`、`cross_case=true`（帧在某例注入、读发生在后面的另一例，两个 case id 都点名）；30 条 incomplete 首缺跳一律 `uart_source_frame_begin`）——它只证**保存产物内**的见证链，不证 IRQ→CPU 因果、不证 polling；②[UART 路由见证实时证明](../../reports/current-dataflow-p5-uart-routing-witness-20261008.md)在真实新会话上让 `report.json` 首次自带 `source_target_transactions` 并与 fresh replay 一起验证。

**后续局部效率证据：** [压缩终态写入优化](../../reports/current-dataflow-p5-trace-write-efficiency-20261007.md)在同一已保存 trace 的 131,072 事件前缀上，使压缩输出逐字节及语义摘要不变，配对中位写入耗时从 4.038 秒降到 1.973 秒。完整 600 秒新源码运行、同条件覆盖/断言对照及完整链/s 尚未因此通过。

**当前情况：** [Ibex＋双 PULP GPIO 验收](../../reports/generated-ibex-two-pulp-gpio-acceptance-20261005.md)已有双向真实闭环、checker 和 fresh replay，旧 600 秒定向搜索记录 420/420 完整链、26/26 抽样重放；报告未发现自然 RTL 缺陷。新 600 秒在线 RFuzz 冻结运行完成 5,563 例及完整重放，同源码冷启动约 599 秒完成 30 例；[原始事件审计](../../reports/current-dataflow-p5-chain-audit-20261007.md)表明新运行的严格完整链率无法确定。[100 例在线分项计时短门禁](../../reports/current-dataflow-p5-online-phase-timing-20261007.md)已给出 p50/p95；[Runner/Router/Scheduler 十分钟压缩门禁](../../reports/current-dataflow-p5-runner-zlib-600s-20261007.md)在 6,272 例真实运行中记录嵌套耗时、压缩终结成本并通过严格完整重放，但没有完整链探针。[同冻结源码的十例逐例冷启动对照](../../reports/current-dataflow-p5-same-snapshot-cold-start-20261007.md)测得十次初始化累计 194.220 秒、source/path 各 10/10 相同；它只证明重复启动成本。[pin8 原生 IRQ 证书](../../reports/current-dataflow-p2-p5-pin8-native-irq-certificate-20261007.md)只连接来源到 GPIO B 原生高电平。[受控 IRQ checker 校准](../../reports/current-dataflow-p5-controlled-irq-fault-20261007.md)证明扰动观测可报警和 fresh RTL 重放。新的[首步端到端验收入口](../../reports/current-dataflow-p5-chain-acceptance-20261007.md)以增量链证书在带全部现有探针的 31.273544 秒真实运行中测得 **8 条认证链＝0.255807 链/s**、4/4 目标位、9 条见证边与全分项 p50/p95，完整 fresh replay 一致。此后[十分钟全探针门禁](../../reports/current-dataflow-p5-chain-600s-20261007.md)把该指标升级到 600.362953 秒、368/368 例、570,196 事件：**27 条认证链＝0.044973 链/s**（跨例 6），同 trace 复算 **68 条 IRQ serial 精确证书**；[同预算配对对照](../../reports/current-dataflow-p5-paired-continuous-cold-start-20261007.md)证明连续会话墙钟约为逐例冷启动的 1/16 且逐例 status/raw/genome/path/断言一致；[受控故障真实校准](../../reports/current-dataflow-p5-controlled-fault-real-20261007.md)在真实 RTL 上捕获并新进程复现受控 finding。链终点仍不含 ISR 写 GPIO A 后的回流（不可精确 join 的身份已点名，见 [ISR 写回端点](../../reports/current-dataflow-p5-isr-writeback-endpoint-20261008.md)）。**异构外设阻塞已解锁：**UART RX 波形互斥改为接纳前声明式拒绝（[报告](../../reports/current-dataflow-p5-uart-waveform-admission-20261008.md)），同 seed/预算下由 7 例（1 次 `uncertain_effect` 停机）变为 **60 例、57 complete、0 停机**，CPU 与 UART 两侧源在同一会话内都被真实使用，fresh replay 一致；底层互斥仍不支持，只是不再崩溃。**本轮补充：**受控故障族已由[通用校准运行器](../../reports/current-dataflow-p5-fault-family-calibration-20261007.md)扩到[四类九变体全部真实 RTL 校准](../../reports/current-dataflow-p5-fault-family-real-9-variants-20261007.md)（错 IRQ 2／错 read data 3 含 1 个 UART／重复提交 2／破坏绑定值 2，命中即停并各写最小重放配置；只读复核器 exit 0、0 失败，并显式记录声明漂移）；[同条件 trace 容器对照](../../reports/current-dataflow-p5-trace-container-same-condition-20261007.md)证明 zlib 分块容器逐事件等价于 JSONL（较短枝完整事件前缀、77/77 例字段相同、两种容器各自 fresh replay 一致）且体积约 1/13.4、终结写入少 11.14 秒。故障**质量/灵敏度**对照、覆盖等价与同类搜索质量比较尚未验收。

**前置：** P3、P4。**主要文件：** `src/myfuzz/scenario/{checker,evidence,replay,feedback}.py`、`src/myfuzz/integration/scenario_campaign.py`、`tests/integration/`、`docs/reports/`。

- [x] 用协议检查器、跨组件来源/顺序不变量及 CPU/IP 行为断言分别报告问题；生成约束和检查期望分开，异常真实输出不能因路径未就绪被过滤。**证据：**`p5_assertion_classes.v1` 三类各自成节并自述类别，fail-closed 异常普查 `abnormal == represented`、`unrepresented=[]`，报告引擎 sha256 必须等于当前模块 sha256（[P5 阶段验收](../../reports/current-dataflow-p5-stage-acceptance-20261008.md) §1）。
- [x] 对已保存场景做受控故障注入：错 IRQ、错 read data、重复提交或破坏 GPIO A→B 值；checker 应给出失败、来源链、最小可重放输入。注入仅校准检测链，报告中独立标注。**证据：**9/9 变体真实校准＋`calibration_only=true`／`observation_boundary=checker_input_copy` 标记＋新进程复现根（`statuses={complete:2,dut_violation:1}`、`fault_document_sha256` 与最小重放一致）。
- [x] 失败与新增覆盖候选保存 raw 输入、Genome、源码/工具链身份、完整 trace、checker finding 和 fresh replay 结果；重放身份不符在启动前拒绝。**证据：**`online_run_identity.json` 四项身份绑定＋`_verify_online_run_identity` 在 RTL factory 之前执行；冷组 24 例 decode-space 漂移被逐例启动前拒绝，冷组 15/15 例 fresh replay `matches=true`；`first_seen` 台账把首次点亮绑到 event／时间。
- [x] 用固定输入/种子、同一源码和相同断言比较连续会话与逐 testcase 启动；分别统计一次性编译/初始化、每例 admission、真实 RTL 事务、Router/Scheduler、增量反馈、日志/证据、p50/p95 时延、有效例/s、完整真实链/s、覆盖增量/s 与无效/超时比例。定位低吞吐路径，消除每例重建、全量事件重扫和逐周期 JSON 序列化；仍保留完整可重放日志。**证据：**`p5_arm_metrics.v1` 12 个分组逐项落到三个真实臂（600 秒臂 0.612963 有效例/s、0.044973 链/s、无效/超时 0.0；UART 臂 0.662254 有效例/s、0.05）＋配对对照 16.08×；低吞吐修复见压缩写、容器等价与热路径剖析；边界：单例初始化的 RTL 编译秒数与 p95 尾部如实记 `null`／仅记录而不消除。

**验收：** 在 Ibex＋双 PULP GPIO 与至少一种不同协议/行为的真实外设上，F1～F5 中已声明路径的 CPU 侧和 IP 侧变异、跨例持久状态、真实路由、逐例反馈、断言、完整前缀保存与 fresh replay 均通过；未覆盖的 ISA 子集、外设模式和路径列为范围限制。至少一项受控错误被独立断言捕获并在新进程复现，正常对照无该 finding。10 分钟定向或覆盖搜索报告完整链、有效执行时间、语料 replay 和实际 finding；同预算对照证明长会话的有效例/s 或完整真实链/s 高于逐例重启，且有效性、checker 与 replay 不退化。没有自然 RTL bug 时如实记零，不以注入缺陷替代。

**验收结果（2026-10-08）：通过（按声明范围）。** 六项判据各有 measured＋met 的证明运行（联合 exit 0）。异构外设侧的收尾也已落地：UART 链路证书 **7 certified／30 incomplete（首缺跳具名）**，UART 路由见证由新真实会话自证（60 例、57 complete＋3 声明式拒绝、fresh replay `matches=true`、`report.json` 自带 `source_target_transactions`）。仍未被证明的部分逐条点名：**异构外设的十分钟长会话**（十分钟项目前只由 Ibex＋双 PULP GPIO 证明；UART 运行是 79.934 有效秒）、**UART 侧跨例持久状态**、**故障灵敏度对照**、**链终点不含 ISR→GPIO A 回流**。这些都是边界而不是隐藏项，见[阶段验收报告](../../reports/current-dataflow-p5-stage-acceptance-20261008.md)的边界节。

### P6：把第一步框架扩展到多协议固定 CPU/IP——未验收（已有实例证据）

**当前情况：** [运行能力表](../../LOCAL_HARNESS_RUNTIME.md)列有五类 CPU 边界与 OpenTitan/PULP/ZipCPU 多个固定 profile 的真实 RTL 证据。这些分散的定向验收还不是第一步框架在多协议实例上的统一持续搜索、断言和 replay；本地不可执行 CPU 按 `skipped_unavailable` 处理。

**前置：** P2～P5 的稳定接口。**主要文件：** `src/myfuzz/local_harness/{request,plan,template_contracts,runtime_renderer,session,source_lock}.py`、`src/myfuzz/protocols/plugins/`、`configs/cpus/`、`configs/peripherals/`、`docs/LOCAL_HARNESS_RUNTIME.md`。

- [ ] 对 OBI、AXI4、AXI4-Lite、Wishbone 和 PicoRV32 Ready/Valid Memory 五个 CPU 边界逐一登记真实模板子集与已通过 CPU；对 OpenTitan TL-UL、PULP APB3、ZipCPU Wishbone 常见 GPIO/UART/SPI/I2C/Timer 按各自真实等级登记。
- [ ] 按固定源码/profile 选择实际可运行的非 Ibex CPU 与至少两类外设协议实例，复用第一步相同的长会话 testcase、F1～F5 路径、源约束、覆盖、断言、故障保存及完整前缀 replay。起初只声明该实例验证过的协议子集和数据流。
- [ ] 对同协议但端口/握手/IRQ/寄存器语义不同的实例，记录声明式微调与模板版本差异；不能只凭协议名称或端口名认定可复用。
- [ ] 每个组合产生 Catalog→Generated→RTL operational→Cross-component accepted→Coverage-guided searched 的逐级证据；若不可执行则记录 `skipped_unavailable`，不得提升等级。
- [ ] 新协议适配沿用第一步的长会话、预编译路径与增量反馈热路径；分别报告新增适配器的局部 tick/事务、每例 host 开销和完整链/s，若明显退化先定位协议执行器或日志瓶颈再计入可搜索能力。

**验收：** 五类 CPU 协议各有固定 RTL 实例及真实局部交易证据；每一类均须以至少一个真实 IP 组合跑通第一步的多例持续会话、CPU/IP 双侧源选择、真实下游消费、交互反馈、断言及前缀 fresh replay。目标 IP 系列按实际 profile/协议子集逐项定级，至少覆盖 OpenTitan TL-UL、PULP APB3 与 ZipCPU Wishbone/AXI4-Lite 中的真实可运行实例。至少一个非 Ibex＋非 GPIO 组合还须证明受控错误由 checker 捕获。源码不可执行的 CPU 明确 `skipped_unavailable`，则第二步相关协议行不能标为完成；该阶段不要求对任意新组件自动生成全部测试。

第二步按下面顺序推进。先把已有定向证据迁入第一步的持续会话/反馈接口，再补齐缺少 MMIO/IRQ 路由的协议形态；表中的组合是首选验收对象，任何替换都要记录真实源码、协议形态和替换原因。

| CPU 侧协议形态 | 首选真实 CPU | 首选 IP 协议/类型 | 当前基础 | 第二步仍需证明 |
|---|---|---|---|---|
| OBI | Ibex、CV32E40P | PULP APB3 GPIO；OpenTitan TL-UL UART/Timer | 固定闭环已有 | CV32E40P 复用第一步逐例双侧搜索，而非只跑旧定向场景 |
| 完整 AXI4 | CVA6 | OpenTitan TL-UL GPIO/SPI Host；PULP APB3 I2C | 固定 MMIO/IRQ 数据链已有 | 长会话多例、两侧变异、交互反馈和前缀 replay |
| AXI4-Lite | PicoRV32 AXI4-Lite | ZipCPU AXI4-Lite UART | CPU RAM 与 IP 本地 RTL 各自已验收 | CPU 请求到真实 UART 的 MMIO 路由、RX/TX 数据链、持续会话和断言 |
| classic Wishbone | PicoRV32 Wishbone | ZipCPU Wishbone wbuart/Timer；OpenTitan GPIO | 固定 IRQ/ISR 闭环已有 | 复用逐例搜索与依赖边反馈，保留 Pico 的自定义 IRQ ABI |
| Pico 原生 Ready/Valid Memory | PicoRV32 native | PULP APB3 GPIO 或 OpenTitan TL-UL GPIO | CPU RAM/ROM 本地 RTL 已验收 | 新增受约束 MMIO 目标和真实 IP 消费链，再接双侧源、会话和 replay |

每行须先分别通过取指/数据访存/字节使能的本地协议验收，再证明至少一条 CPU→IP 和一条 IP→CPU 真实传播路径；需要 ISR 的组合另证明真实 IRQ→CPU handler。只有达到第一步相同的逐例输入、交互反馈、断言和前缀 replay 门槛，才能在“第二步完整框架复用”列标通过。某 CPU 本地不可执行时记 `skipped_unavailable` 并保留缺口，不能用另一协议的 CPU 抵消。

### P7：对已支持协议 CPU/IP 自动生成与测试——未验收／待实施

**当前情况：** 源锁、端口事实、协议模板、生成式 harness 和部分声明式微调已有实例；尚无一个入口能对新同协议 CPU/IP 自动完成 harness 生成、路径及可变源编译、多例持续搜索、断言和 replay 的全部步骤。自动化范围只包括 P6 已证明可运行的协议形态和受信组件能力。

**前置：** P1～P6 的稳定会话、路径、变异和验收接口。**主要文件：** `src/myfuzz/local_harness/{request,plan,template_contracts,runtime_renderer,session,source_lock}.py`、`src/myfuzz/scenario/{contracts,dependency,ownership,genome,mutation,runner,checker,replay}.py`、`src/myfuzz/integration/scenario_rfuzz.py`、`configs/cpus/`、`configs/peripherals/`、统一 CLI 与报告生成器。

- [ ] 对受信 CPU/IP 源码和 profile 自动核对端口、时钟/reset、协议形态、地址窗口、输入字段归属、IRQ 电平/脉冲和外部环境模型；缺信息时给出可定位的声明式微调需求，不猜测 RTL 语义。
- [ ] 在已验收的协议子集内选择版本化模板并分别生成独立 harness；从组件能力与数据流契约编译该组合真正可走的 F1～F6 路径、Fuzzable Source/Bound Input、合法字段 mask/range、前置状态、初始种子和断言集合。没有真实生产者的边不能标为已支持路径。
- [ ] 自动运行一次初始化后的逐例输入、按反馈变异、真实 Router/Scheduler 传播、checker、故障保存及完整前缀 fresh replay；输出每条路径及组件的能力等级与不支持原因。
- [ ] 自动生成入口复用可缓存构建产物与已编译协议/路径契约；普通例沿用紧凑回执和增量反馈，详细证据按 finding/新增覆盖保存。对新组件报告构建成本与稳定后有用吞吐，不以“自动生成成功”代替可实际 fuzz 的性能门槛。
- [ ] 选一个已有受支持协议形态、但未被 Runner/Router/mutator 以组件名分支处理的新 CPU 和新 IP，仅用受信 profile 与允许的声明式微调完成端到端验收。协议语义确不兼容时新增模板版本，并从旧等级重新验收。

**验收：** 新组件接入的 diff 中没有组件名硬编码进 Runner、Router、mutator 或既有协议模板；生成入口自动得到正确的局部 harness、路径、输入约束、持续 testcase 与 checker，并在真实 RTL 上跑出双向传播、受控错误捕获及 fresh replay。故意提供缺失来源、保留位随机源或错误握手时，系统在执行前拒绝或明确降级。自动报告只对已证明的协议子集和可执行路径给出通过等级；不能宣称任意同协议 RTL 即插即测。

第三步的端到端入口按 `受信源码/profile → 端口及协议事实核对 → 选择已验收模板及声明式微调 → 分别生成 CPU/IP harness → 编译可用路径/输入归属/ISA 与外设约束 → 初始化一次会话 → 逐例双侧变异与反馈 → 断言/保存 → fresh replay` 执行。自动编译的输出必须列出每条可执行路径、每个可变源及被拒绝的路径理由；例如缺少 IP peer 模型时，相关 IP→CPU 路径标为不可用而非由 Fuzzer 随机制造 IP 结果。验收使用新增的同协议 CPU 和新增 IP 各一个，同时保留一个旧组件负例，确认生成器没有因名称相似错误套用模板。

### P8：真实 DMA 主设备搬运流——未验收／核心未实现

**当前情况：** 现有场景可测试 CPU Store/Load 与 IP MMIO/IRQ，但没有受信 DMA master RTL、独立 DMA 主设备 harness、由 DMA 真实请求触发的 RAM/IP 搬运或 DMA 完成 IRQ 闭环。原件第 7 节描述的 F6 因而尚未实现；已有 CPU 模拟搬运不能替代 DMA 验收。

**前置：** P2 的逐边路径契约、P3 的持续资源/事务身份；DMA 源码与主设备协议 profile 可并行准备。**主要文件：** 新增 `configs/peripherals/<dma>/` profile、`src/myfuzz/local_harness/` 的 DMA master session/协议模板，以及 `src/myfuzz/scenario/{router,scheduler,memory_service,ledger,irq,evidence,replay}.py` 的多主事务来源、提交顺序和证据接口。具体 DMA 候选先固定真实源码和其读写/IRQ 端口，再登记能力；源码不可执行时记录 `skipped_unavailable`。

- [ ] CPU 经 F4 的真实 MMIO 配置 DMA 源、目的、长度和启动；DMA RTL 真实发出每笔读写请求，Router 按地址和声明绑定选择 RAM 或真实 IP 目标。
- [ ] 用源事务 ID、读响应快照、目标写提交和 byte-enable 形成 F6 的完整来源链；CPU 与 DMA 同时访问持久 RAM 时，由 Scheduler/Memory Service 记录确定的事务提交顺序，不把此顺序称为物理 Bus 仲裁时序。
- [ ] 真实 DMA 完成/错误输出和原生 IRQ 经 F5 交付 CPU；CPU 真实 ISR 读取 DMA/IP 状态。异常或过早 IRQ 原样进入 trace 和 checker。
- [ ] 证据与 fresh replay 覆盖 RAM→RAM、RAM→IP、IP FIFO→RAM，以及候选 RTL/目标 IP 支持时的 IP→IP；未支持的组合逐项标明，不以合成 DMA 响应填补。

**验收：** 至少一个源码固定的真实 DMA master 在独立 harness 内完成 CPU 配置→真实请求→源读取→目标写入→真实完成 IRQ→CPU ISR 的完整多周期链，RAM→RAM 与含真实 IP FIFO 的方向分别有成功/非法输入对照；所有已提交数据可由源版本或 IP RTL 输出追踪，事务不重复执行，fresh replay 复现局部 tick、数据和 IRQ。F6 的能力表按实际 RAM/IP 方向逐项列出；未验证的物理总线仲裁、全局周期和 PLIC 不计通过。

### 交付与状态更新规则

每阶段的验收记录必须列出命令、退出状态、源码/配置/生成物身份、真实 RTL 观察、负例、证据路径、replay 结论和未覆盖范围。更新 [运行能力表](../../LOCAL_HARNESS_RUNTIME.md) 的对应组合行，再更新本页状态；不能仅靠计划复选框宣布通过。

当前按三步推进：先执行 P1～P5，在 Ibex＋双 PULP GPIO 及至少一种不同外设上完成真正可报警、可重放的持续搜索框架；再以 P6 让多协议固定 CPU/IP 实例复用同一框架；最后以 P7 提炼已支持协议范围内的自动生成与测试。P8 补齐原件 F6 的真实 DMA 主设备路径。原 [2026-09-27 实施计划](2026-09-27-persistent-multicomponent-fuzz-implementation.md)中的 G0～G4 编号和详细不变量留作基线证据，其旧日期的完成状态不得自动用于本页新门禁。
