# 依赖感知的多模块并行 Fuzz 系统设计

日期：2026-07-22

状态：设计已口头确认，等待书面规格审阅

## 1. 目标

本项目构建一个通用的 RTL 组合与 fuzz 输入投影系统。用户提供：

- CPU 和 IP 模块的 RTL 源文件及编译参数；
- 每个模块的角色，例如 CPU、UART、GPIO、timer、memory；
- 每个端口的语义角色，例如 clock、reset、request、address、data、valid、ready、interrupt；
- 端口所使用的常见协议类型；
- 可选的协议参数和必须满足的用户约束。

系统在不读取参考 SoC 顶层的前提下完成：

1. 使用项目内现有的 Verilator 前端解析 RTL；
2. 自动推断模块连接关系和地址映射；
3. 输出多个可解释、可编译的候选 top；
4. 为每个候选输出 baseline 和 dependency-aware harness；
5. 使用相同资源预算执行 RFuzz，并分别报告每个候选的覆盖率；
6. 在 RVX 和 Ibex + OpenTitan IP 两类目标上验证系统的通用性。

系统禁止依赖模块名、设计名或目标目录名的硬编码规则。RVX 的原始 SoC 顶层只能由评测流程使用，生成流程不得读取、解析、评分或间接恢复其中的连接及地址信息。

## 2. 非目标

首期不追求：

- 恢复唯一且与人工 SoC 完全相同的连接图；
- 支持任意私有或未声明协议；
- 自动生成完整固件、驱动程序或定向寄存器测试序列；
- 自动插入未经声明的跨时钟域桥；
- 完整的全芯片动态 taint；
- 同时常驻所有候选的 Verilator AST 或仿真进程；
- 将 RVX 原始 top 的覆盖率差异全部归因于 harness。

目标是生成一组满足已知约束、协议一致、可运行并具有证据链的合理候选，而不是声称从局部 RTL 唯一恢复原设计意图。

## 3. 设计原则

### 3.1 通用化而非目标打表

源码中的推断逻辑只能依赖以下信息：

- Verilator 提取的 RTL 结构和数据流事实；
- 用户声明的模块角色、端口角色和协议；
- 协议插件中的通用约束；
- 与目标无关的宽度、方向、时钟域、地址冲突等约束。

目标相关信息只能存在于输入配置中。核心源码中不得出现类似 `if design == "rvx"`、模块名白名单、固定 RVX 地址或固定 OpenTitan 实例组合。

### 3.2 事实、推断和假设分离

每条信息必须带来源：

- `declared`：用户显式提供；
- `rtl`：从 RTL AST 或数据流中确定提取；
- `protocol`：由协议定义必然推出；
- `inferred`：由多个证据评分得到；
- `assumed`：为形成可执行候选而引入，但无法从已有信息证明。

候选 top 的输出必须列出所有 `inferred` 和 `assumed` 项。评测报告不得把假设描述为 RTL 事实。

### 3.3 确定性与可复现性

相同的输入文件内容、配置、协议插件版本和工具版本必须生成相同的候选顺序、地址映射、名称及稳定哈希。所有并列评分使用稳定的规范化 ID 排序，不依赖文件系统遍历顺序或线程调度顺序。

### 3.4 低内存优先

当前执行环境约 7.3 GiB RAM 和 2 GiB swap。系统默认采用流式候选生成、单 AST 构建、有限 worker、无波形长驻和按 RSS 分配任务的策略。CPU 核心数量不作为并发度的直接依据。

## 4. 总体架构

系统分为九个边界清晰的组件。

### 4.1 输入规范化器

读取 filelist、include 路径、宏、top 候选模块、模块角色、端口角色、协议声明和用户约束。它只负责语法与引用检查，不执行目标专用推断。

输出规范化输入摘要和内容哈希，供缓存和复现使用。

### 4.2 Verilator RTL 事实提取器

复用当前项目中剥离的 Verilator 前端，而不是引入第二套 RTL parser。它在现有 module、port、instance 和 branch manifest 基础上扩展：

- 端口方向、位宽、signedness 和数据类型；
- instance 到 module 的解析关系；
- pin 与 net/expression 的实际绑定；
- continuous assignment、过程赋值和条件控制的数据依赖；
- clock/reset 候选及其极性证据；
- 参数化后可确定的宽度和常量；
- 可识别的寄存器局部 offset、range 和 decode 条件；
- 无法解析或因条件生成而不确定的诊断。

输出 `hdl_facts.v2`，不在该阶段决定最终连接图。

### 4.3 协议 DSL 与插件编译器

协议采用声明式 DSL 表示，而不是把协议语义写入连接算法。插件定义：

- initiator/target 两侧的 channel 和 field；
- field 的方向、宽度约束、可选性和多路关系；
- handshake、request/response 和稳定性规则；
- 地址、数据、byte-enable、error、ID 等语义；
- 合法的无状态适配和明确禁止的适配；
- harness 使用的有界状态机规则；
- 协议产生的静态依赖边。

首期插件范围固定为：

- generic ready/valid MMIO；
- APB3/APB4；
- AXI4-Lite；
- OBI；
- TL-UL host/device 子集。

首期 TL-UL 只覆盖 Ibex 与所选 OpenTitan 外设实验需要的单 outstanding、无 source-ID 重排路径。完整 TileLink、一致性协议和 AXI4 burst 不属于首期范围。插件能力不足时必须显式拒绝或将未连接端口暴露为外部端口，不能静默生成看似成功的连接。

### 4.4 连接与地址推断核心

推断核心构建带类型的约束图。节点包括 component、port、protocol endpoint、clock domain、reset domain 和 address region；边表示兼容性、依赖、候选连接或禁止连接。

连接推断结合两类证据：

1. 类型和协议约束：方向、位宽、channel、initiator/target、时钟复位域及协议规则；
2. RTL 数据流证据：地址参与 decode、valid/ready 控制关系、response 对 request 的依赖、interrupt/status 来源等。

硬约束先删除不可能连接，再对剩余候选执行确定性评分和约束搜索。搜索允许产生多个合法连接图，但不允许通过模块名查表决定连接。

地址推断分两步：

1. 从 RTL 中提取外设内部寄存器 offset、decode mask、窗口大小和对齐要求；
2. 使用通用约束分配器为候选实例分配互不重叠的绝对 base address。

分配器优先满足已声明的固定地址、可表示范围、自然对齐、CPU 地址宽度和协议窗口约束。没有固定地址时，按规范化 component ID 和候选图顺序进行确定性分配。不同合理布局可以形成不同候选；绝对 base 必须标记为 `inferred` 或 `assumed`，不得标记为 RTL 提取事实。

### 4.5 Top-K 候选管理器

候选使用分层的字典序质量指标，而不是目标专用权重表：

1. 硬约束是否全部满足；
2. 未连接的 required endpoint 数量；
3. 非安全宽度适配数量；
4. 未经证明的 clock/reset 假设数量；
5. 地址空间浪费和冲突修复数量；
6. 协议证据完整度；
7. RTL 数据流支持度；
8. 规范化连接图哈希。

只有硬约束全部满足的候选可以进入 Top-K。管理器使用有界堆流式保留 K 个候选，立即释放落选候选的搜索状态。默认 K 是配置项，不写死在算法中；实验配置首期使用 `K=3`。

### 4.6 Composition IR 与 Verilator AST 生成器

推断结果先写入与 Verilator 内部节点解耦的 `composition_ir.v1`。IR 描述 component instance、net、endpoint binding、adapter、address map、clock/reset、external port、证据和假设。

Top 生成采用 Verilator 原生 AST 节点和输出逻辑：

1. 参考 `V3LinkLevel::wrapTop()` 和 `wrapTopCell()` 的构造方式；
2. 新建项目内 `MyFuzzCompositionAstBuilder`；
3. 创建全新的 source-like `AstModule`、`AstCell`、`AstVar`、`AstPin`、`AstVarRef` 和必要赋值节点；
4. 运行 Verilator link、pin、width 和 dtype 校验；
5. 接入与当前 vendored Verilator 版本完全匹配的 `V3EmitV.cpp`；
6. 使用 `V3EmitV` 输出 SystemVerilog；
7. 对输出文件重新 parse/elaborate，作为候选有效性的最终门禁。

不得直接修改并重新输出经过优化的 DUT AST。`V3ParseGrammar` 中 parser 状态相关的 builder 只能作为实现参考，不能作为组合器公共接口。

### 4.7 静态依赖图与动态收缩器

静态阶段生成保守过近似依赖图。依赖来源包括：

- RTL expression 和控制依赖；
- 跨 module 的候选连接；
- 协议 handshake 与 request/response 规则；
- 地址 decode 到目标外设；
- status、interrupt、error 与其来源状态；
- clock/reset 对状态推进的控制关系。

图以 32-bit 稳定 ID 和 CSR 邻接结构保存，不保存重复字符串或整棵 AST。

动态阶段使用协议 field 级别的分组 taint 与抽样差分 replay 收缩无效边：

- 每个批次最多处理 64 个 field group；
- 对相同初始状态和 stimulus，仅改变一个 group；
- 观察 branch coverage、状态摘要和协议事件摘要的差异；
- 只有多次观测均不支持的边才降低置信度；
- 静态图始终保留为 fallback，不做不可逆删除；
- reset 不稳定、超时或 replay 不可重复的样本不参与负证据统计。

该策略避免全信号逐 bit taint 的内存成本，并降低一次偶然观测造成错误剪枝的风险。

### 4.8 Harness 编译器

系统为每个候选生成两种 harness。

`direct` harness 是候选内的公平 baseline：RFuzz 原始 bit 串按固定 ABI 直接映射到候选的外部输入，不执行协议修正、优先级修正或状态相关投影。

`depaware` harness 使用完全相同的候选 top、原始 bit 宽度、seed 和周期预算。它执行：

1. 将 raw bits 解码为协议 field；
2. 根据静态依赖图选择本周期相关 field；
3. 应用协议插件的有界状态规则；
4. 使用动态收缩后的 active view 减少无关投影；
5. 把无效组合确定性地映射到合法或可推进组合；
6. 将投影后的值驱动到同一组 top 输入。

投影不得丢弃一个完整样本或无限等待 DUT。所有 raw bits 必须有确定用途；对于因候选接口缩小而剩余的 entropy，使用稳定的分组折叠进入同类数据、延迟或事件选择字段，并记录映射。

为忠实保留用户提出的原始对照，系统还生成 `flat-direct` 聚合 top：每个 CPU/IP 都是独立子模块，所有子模块输入直接拼接为顶层输入，输出仅作为观测。该组用于回答“自动组合系统相对完全无连接随机驱动的总体效果”。由于其拓扑与输入维度不同，它是结构性对照，不能单独用于归因 harness 效果。

因此实验包含三个必要组：

- `flat-direct`：无推断连接，全部模块输入直接随机驱动；
- `candidate-direct`：候选连接图 + direct harness；
- `candidate-depaware`：同一候选连接图 + dependency-aware harness。

`candidate-direct` 与 `candidate-depaware` 的差异用于归因 harness；`flat-direct` 与候选组的差异用于衡量组合与投影的整体效果。

### 4.9 执行与评测调度器

任务单位为：

```text
target x candidate x harness x seed x time-budget
```

调度器按预计和实测 RSS 申请内存令牌。默认规则：

- 同一台低内存机器同时只进行一个完整 Verilator build；
- fuzz worker 数由最近一次相同 build 的峰值 RSS 决定；
- 达到软内存上限时不启动新任务；
- 达到硬内存上限或持续 swap 增长时停止最低优先级任务并保存检查点；
- 默认不生成 VCD/FST；
- event、replay 和诊断使用有界 ring buffer；
- 相同 instrumented RTL、候选哈希和编译参数复用 build cache。

候选结果独立保存，禁止把多个候选的覆盖点先求并集再宣称为单个候选效果。

## 5. 端到端数据流

```text
RTL + roles + port roles + protocol declarations + constraints
  -> input normalizer
  -> Verilator RTL fact extractor
  -> hdl_facts.v2
  -> protocol compiler
  -> typed constraint graph
  -> connection search + address allocation
  -> streaming Top-K composition_ir.v1
  -> MyFuzzCompositionAstBuilder
  -> Verilator link/width validation
  -> V3EmitV
  -> generated_top.sv
  -> reparse/elaborate gate
  -> candidate_manifest.v1
  -> static dependency graph
  -> direct and depaware harnesses
  -> RFuzz jobs
  -> sampled differential replay
  -> dependency confidence update
  -> per-candidate coverage reports
```

动态收缩结果只改变后续 harness 的 active dependency view，不修改已生成的连接事实或掩盖原始静态图。

## 6. 四个冻结接口契约

两个并行开发终端只通过以下四个版本化 JSON 契约协作。实现开始后，兼容性变更必须提升 minor 版本；破坏性变更必须提升 major 版本并同时更新生产者、fixture 和消费者。

### 6.1 `hdl_facts.v2`

必须包含：

- `schema_version`；
- frontend、Verilator 和输入内容版本；
- modules、parameters、ports、instances；
- pin bindings 及规范化 expression；
- clock/reset candidates；
- dataflow/control edges；
- local address decode facts；
- source locations；
- 每项事实的 provenance 和 confidence；
- errors、warnings 和 unsupported constructs。

所有实体使用稳定整数 ID，同时保留可读名称。消费者不得依赖数组原始顺序。

### 6.2 `protocol.v1`

必须包含：

- protocol/plugin ID 和版本；
- endpoint role；
- channels 和 fields；
- 相对 initiator 的方向；
- width/type constraints；
- required/optional 条件；
- handshake 和 bounded temporal rules；
- dependency edges；
- legal adapters；
- harness projection actions；
- capability limits。

协议实例只引用 field role，不依赖具体 RTL 信号名。信号名到 field role 的绑定来自用户输入和结构推断证据。

### 6.3 `composition_ir.v1`

必须包含：

- candidate ID、parent input hash 和稳定 graph hash；
- component instances；
- typed nets 和 endpoint bindings；
- adapters；
- address regions；
- clock/reset domains；
- external ports；
- unresolved optional endpoints；
- evidence、assumptions 和 rejected alternatives；
- 字典序评分向量。

IR 不能包含 Verilator AST 指针、进程内地址或不可复现的临时路径。

### 6.4 `candidate_manifest.v1`

必须包含：

- candidate 和 Composition IR 哈希；
- emitted top/harness 文件及内容哈希；
- top-level port ABI；
- final address map；
- direct/depaware raw-bit mapping；
- parse/link/width/compile/smoke 状态；
- diagnostics；
- coverage point universe 和 source mapping；
- build cache key；
- 峰值 RSS 和运行时统计；
- 完整 assumptions/evidence 摘要。

只有 reparse/elaborate 成功的候选可以标记为 `valid`。

## 7. 候选推断细节

### 7.1 端口角色解析

角色来源优先级为：

1. 用户声明；
2. 协议实例显式绑定；
3. RTL 结构和数据流推断；
4. 通用命名提示。

命名只能作为低置信度提示，不能覆盖方向、位宽或用户声明。任何由名称推断的 clock、reset 或 protocol field 都必须出现在候选假设中。

### 7.2 连接硬约束

至少包括：

- producer/consumer 方向兼容；
- 位宽相等或存在协议声明允许的安全适配；
- protocol/channel/field 兼容；
- required endpoint 满足连接基数；
- 单驱动规则；
- clock/reset domain 一致；
- address window 无重叠；
- initiator 可达 target；
- 禁止形成纯组合 ready/valid 环；
- 未声明 CDC 不自动连接。

### 7.3 候选多样性

Top-K 不能仅由同一图的实例命名差异组成。两个候选只有在连接边、adapter、address region 或 external endpoint 至少一项不同才视为不同。候选生成器按图哈希去重。

### 7.4 无解处理

若完整约束无解，系统输出最小冲突诊断，包括冲突 endpoint、协议、宽度、domain 和用户约束。系统可以生成降级候选，但必须满足以下条件：

- 仅断开 optional endpoint 或将其暴露为 external；
- 不违反 required protocol 规则；
- manifest 明确记录降级原因；
- 降级候选与完整候选分组报告。

不得用常量绑死 required input 来伪造一个可编译候选。

## 8. Harness 语义与公平性

### 8.1 固定周期模型

两种候选 harness 都使用固定最大周期数。depaware harness 的协议状态机只能执行常数上界内的组合和状态更新，不能因为输入无效而跳过整个样本、重新取随机数或延长测试预算。

### 8.2 Raw-bit 可追踪性

manifest 记录每一段 raw bits 在 direct 和 depaware 中的用途。depaware 可以重排、gate、mask 或折叠 bits，但不得引入未记录的随机源。相同 seed 和样本序号必须重现相同投影结果。

### 8.3 防止过度约束

每条投影规则必须归入以下一类：

- protocol legality；
- progress；
- dependency consistency；
- bounded event rarity；
- address validity。

不得加入“为了覆盖某条已知分支”的目标专用条件。系统报告 projection rate、修正类型分布和 direct-only coverage，防止覆盖提升来自把输入空间收缩成单一正常路径。

## 9. 实验目标

### 9.1 RVX

生成器输入只包含 CPU/IP RTL、角色、端口角色、协议和通用约束。RVX 原始 SoC top 不进入生成器输入目录，也不参与缓存键、推断、候选评分或地址分配。

生成实验对每个有效候选执行：

- flat-direct；
- candidate-direct；
- candidate-depaware。

RVX 原始 SoC 由隔离的评测适配器执行，作为额外的 `reference-original` 组。它与生成候选只比较共享 CPU/IP 源文件中的稳定 branch coverage ID。由于 topology、地址和环境不同，该比较仅描述系统级结果，不用于单独证明 harness 优势。

### 9.2 Ibex + OpenTitan IP

该目标没有参考 top。首期固定组件集合为：

- Ibex core；
- OpenTitan UART；
- OpenTitan GPIO；
- OpenTitan RV timer；
- 支撑这些模块所需的通用 OBI/TL-UL adapter、interconnect 和 memory endpoint。

adapter 和 interconnect 必须由协议及 Composition IR 生成，不允许针对上述实例名写专用 wiring。SPI device 及更重的 OpenTitan IP 属于后续扩展，不进入首期验收，避免扩大内存和依赖范围。

每个有效候选执行 flat-direct、candidate-direct 和 candidate-depaware。候选之间分别报告，不存在 reference-original 组。

## 10. 覆盖率与统计口径

主要指标为项目当前的 branch coverage，并保留现有插装模块作为唯一 coverage source。报告至少包含：

- 固定时间点的 covered/common-total；
- coverage-over-time 曲线及面积；
- 首次发现时间和 discovery 数；
- direct-only、depaware-only 和 overlap 集合；
- 按 CPU、bus、UART、GPIO、timer 等源码模块分组的覆盖；
- 每秒测试数、每秒周期数和峰值 RSS；
- projection rate、协议事件数和无进展周期数；
- 候选生成数、验证通过率和失败原因。

同一候选的 direct 与 depaware 使用：

- 相同 instrumented RTL；
- 相同 coverage universe；
- 相同 seed 集合；
- 相同 wall-clock 或 cycle budget；
- 相同 RFuzz 版本和变异参数；
- 随机化并交错的运行顺序。

flat-direct 因 topology 不同，单独报告 coverage universe，并通过共享源码位置 ID 比较公共模块，不使用不同分母的百分比直接相减。

## 11. 错误处理

### 11.1 输入和解析错误

filelist 缺失、module 重定义、required role 缺失或 Verilator parse 失败时立即停止该 target，并输出包含源位置的结构化错误。

### 11.2 协议和推断错误

不支持的 required 协议、无法安全适配的宽度、非法方向或未声明 CDC 为候选级硬失败。optional endpoint 可以 externalize，但必须降低候选质量并记录原因。

### 11.3 地址错误

固定地址冲突或地址宽度无法容纳所有 required region 时输出冲突集合，不允许自动覆盖用户固定地址。纯推断地址无解时可生成不同布局候选。

### 11.4 AST 和生成错误

任何 link、pin、width、dtype 或 reparse 错误都使当前候选失效。生成器继续验证下一候选，最终返回已通过候选和完整失败清单。少于请求的 K 个有效候选时返回实际数量并以非成功完整度标记任务。

### 11.5 运行时错误

harness 内部维护协议违规、投影次数、超时和无进展计数器。仿真崩溃、assert、超时与资源终止必须区分保存。内存保护触发属于可重试资源错误，不记为 DUT crash。

## 12. 缓存和内存边界

缓存键由输入内容、工具版本、schema 版本、Composition IR 哈希、instrumentation 配置和编译参数组成。路径和时间戳不进入语义哈希。

内存策略为：

- facts 和 IR 使用紧凑 JSON 作为持久交换格式；
- 进程内使用整数 ID 和字符串驻留；
- 每次只构造和验证一个候选 AST；
- Top-K 搜索只保留有界 frontier；
- 静态图使用 CSR；
- 动态 taint 每批最多 64 个 field group；
- replay queue 和 event log 有固定上限；
- coverage bitmap 使用共享只读映射或紧凑位图；
- 默认禁用长波形；
- 构建和 fuzz 任务受全局内存令牌约束。

## 13. 测试策略

### 13.1 契约测试

为四个 schema 提供：

- valid fixture；
- 缺字段 fixture；
- 未知兼容字段 fixture；
- 版本不兼容 fixture；
- 稳定排序和哈希测试；
- producer/consumer round-trip 测试。

### 13.2 前端事实测试

使用小型参数化 RTL fixture 覆盖：

- module/instance/pin binding；
- generate 和参数宽度；
- continuous/procedural dependency；
- clock/reset 候选；
- local address decode；
- 不支持结构的诊断。

### 13.3 推断测试

构造不含目标名称的合成 CPU、bus 和 IP fixture，验证：

- 方向和协议不兼容连接被拒绝；
- 多个合法拓扑产生稳定 Top-K；
- 地址分配不重叠且可复现；
- hard constraint 无解时给出最小冲突；
- 修改实例名不改变规范化结构结果。

### 13.4 AST 与 emitter 测试

每个生成 top 必须通过：

- AST 结构检查；
- Verilator link/pin/width 检查；
- `V3EmitV` 输出；
- 输出文件 reparse/elaborate；
- 小周期 smoke simulation。

### 13.5 Harness 属性测试

验证：

- direct 映射无协议修正；
- depaware 投影满足已声明的 bounded protocol invariant；
- 相同 raw input 可重放；
- 每个 raw bit 均可追踪；
- 无样本被丢弃；
- 固定周期预算不被延长；
- 动态负证据不能删除静态 fallback；
- direct-only 路径仍被单独统计。

### 13.6 集成与实验测试

先运行无参考 top 的合成 fixture，再运行 Ibex + OpenTitan 短 smoke，最后运行 RVX。正式长测按内存令牌顺序执行，避免两个并行 Codex 终端同时启动重型构建或 fuzz。

## 14. 验收标准

首期完成必须同时满足：

1. 同一套核心代码能够处理 RVX 和 Ibex + OpenTitan，仅更换声明式输入配置；
2. 生成流程无法访问 RVX reference top；
3. 至少输出一个通过 reparse/elaborate 和 smoke 的候选，并支持配置的 Top-K；
4. 每个候选都有完整 evidence、assumption、address map 和稳定哈希；
5. flat-direct、candidate-direct 和 candidate-depaware 都可由统一 runner 执行；
6. candidate-direct 与 candidate-depaware 使用相同 DUT、coverage universe、raw width、seed 和预算；
7. dependency graph 实现静态过近似和可回退的动态收缩；
8. 核心源码不存在 RVX、Ibex、OpenTitan module-name 或地址专用分支；
9. 默认配置在当前低内存机器上不会并发启动两个完整 Verilator build；
10. 结果按候选分别报告，并正确区分结构差异与 harness 差异。

覆盖率提升不是软件功能验收的硬门槛，因为它是待验证的研究假设。实验成功标准是比较过程公平、可复现、可解释，并能够判断 dependency-aware 方案在哪些模块和时间区间有效或无效。

## 15. 两个 Codex 终端的并行边界

设计规格和四个契约先在共同基线提交中冻结。之后创建两个独立 Git worktree。

### 15.1 终端 A：composition core

分支和工作树：

```text
feature/composition-core
.worktrees/composition-core
```

负责：

- Verilator facts 扩展和 `hdl_facts.v2` producer；
- typed constraint graph；
- 连接搜索和地址分配；
- Composition IR producer；
- Top-K；
- `MyFuzzCompositionAstBuilder`；
- `V3EmitV` 接入；
- top 验证和 candidate manifest 的生成部分。

主要文件所有权：

```text
src/myfuzz/frontend/**
src/myfuzz/composition/**
tests/frontend/**
tests/composition/**
```

### 15.2 终端 B：protocol, harness and experiments

分支和工作树：

```text
feature/harness-runtime
.worktrees/harness-runtime
```

负责：

- protocol DSL compiler 和首期插件；
- `protocol.v1` consumer/producer；
- 静态依赖图和动态收缩；
- direct、depaware 和 flat-direct harness；
- 内存感知调度器；
- RVX 与 Ibex + OpenTitan 实验配置；
- 覆盖率统计和报告。

主要文件所有权：

```text
src/myfuzz/protocols/**
src/myfuzz/harness/**
src/myfuzz/experiments/**
configs/experiments/**
tests/protocols/**
tests/harness/**
tests/experiments/**
```

终端 B 在终端 A 完成前使用冻结的 JSON fixtures，不复制或模拟 A 的内部算法。

### 15.3 同步规则

- 两个终端不得在同一个 working tree 工作；
- schema 文件由共同基线拥有，任一终端不得单方面修改；
- 共享接口变更先在集成分支形成单独契约提交并推送，再由双方 merge；
- 终端 A 先集成，终端 B 在 A 的真实 producer 输出上运行 contract tests 后再集成；
- 同机运行时，两个终端共享一个文件锁和内存令牌服务；
- 轻量单元测试可并行，Verilator 完整构建、集成仿真和正式 fuzz 串行；
- 每个终端的提交只包含自己的文件所有权范围，避免合并时覆盖对方工作。

### 15.4 GitHub 节点提交规则

实施计划中的每个可验收节点都分配稳定 ID：终端 A 使用 `A<n>`，终端 B 使用 `B<n>`，联合集成使用 `I<n>`。一个节点只有同时满足“验证通过、本地提交成功、推送到 GitHub 成功”才可以标记为完成。

每个节点严格执行：

1. 只暂存该节点及该终端所有权范围内的文件；
2. 运行计划为该节点指定的最小充分验证；
3. 运行 `git diff --check` 并检查 staged diff；
4. 创建一个原子提交，不把两个独立节点混在同一提交中；
5. 首次使用 `git push -u origin <branch>`，后续使用普通 `git push origin <branch>`；
6. 在 GitHub 能看到该提交后，才更新节点状态并开始依赖它的后续节点。

提交消息采用：

```text
<type>(<area>): [<node-id>] <result>

Node: <node-id>
Tests: <commands or checks actually run>
```

例如：

```text
feat(composition): [A3] emit validated candidate top

Node: A3
Tests: pytest tests/composition/test_emit_top.py
```

GitHub 分支规则为：

- 终端 A 只推送 `feature/composition-core`；
- 终端 B 只推送 `feature/harness-runtime`；
- 联合节点推送到 `integration/dependency-aware-fuzz`；
- 只有联合 contract tests 和 smoke 通过后，集成分支才可以合入 `main`；
- 禁止 `git push --force` 和 `--force-with-lease`；
- 分支首次发布后不改写历史，使用 merge commit 吸收新的共同基线；
- 禁止提交密钥、访问令牌、机器专用绝对路径和私有环境配置；
- 禁止提交 build 目录、可执行文件、VCD/FST、完整 fuzz corpus 或大体积原始日志；
- 允许提交小型 deterministic fixture、schema、manifest、覆盖率摘要和复现实验所需脚本；
- push 失败时保留本地提交并记录为 `pending-push`，不得宣称节点完成，也不得开始依赖该节点的联合工作；
- 任一终端发现对方分支有意外修改时停止合并，先通过契约提交解决，不覆盖或回退对方工作。

设计规格、schema 冻结和 worktree 基线本身也是节点，必须先推送到 GitHub，两个终端才从该提交创建工作树。这样每个阶段都有远端可恢复检查点，而不是只存在于本机 worktree。

## 16. 实施顺序

实现按以下依赖顺序推进。详细 implementation plan 会把每一项拆成带 `A<n>`、`B<n>` 或 `I<n>` 的 GitHub 提交节点：

1. 冻结 schema 和最小无目标名称 fixtures；
2. 两个终端并行实现 facts/composition 与 protocol/harness；
3. A 完成小型 RTL 到有效 generated top 的垂直路径；
4. B 完成 fixture 到两种 harness 和本地 runner 的垂直路径；
5. 合并 A，并让 B 对接真实 manifests；
6. 完成无参考合成 fixture 的联合 smoke；
7. 完成 Ibex + OpenTitan smoke；
8. 完成 RVX generated candidate smoke；
9. 在隔离评测阶段运行 RVX reference-original；
10. 按内存预算执行短测和长测并生成最终对比报告。

该顺序使两个终端在最初阶段真正并行，同时把最容易发生冲突的 schema 和重型集成步骤集中到明确的同步点。
