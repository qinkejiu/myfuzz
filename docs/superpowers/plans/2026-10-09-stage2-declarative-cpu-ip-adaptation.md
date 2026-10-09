# 第二阶段：通用 CPU 与 IP 声明式适配实施清单

日期：2026-10-09。状态：实施中，M0 基线门禁已通过，M1 正在执行。本文落实用户关于保留架构、基础／功能事件分层、L1–L3 能力、三类依赖、新 IP 验收和 CPU 通用契约的要求，替代此前聊天中以五类功能插件作为 IP 接入前提的方案。

**目标：**保留现有通用 CPU Session、协议适配器、独立 harness、Scenario／Router／Scheduler、持久状态和反馈机制，使有受信接口描述的未知 IP 能按实际能力参与基础测试，再通过寄存器描述和功能族插件增强测试深度。

**实施方式：**各工作包顺序执行；采用 executing-plans 工作流及逐检查点核对。构建和真实运行串行，不默认派生多个实现 agent。功能或缺陷改动先有行为负例，再实现、复核、提交；单项文档编辑不增设镜像测试。

**技术基础：**Python 场景／描述层、现有协议模板与生成式 harness、SystemVerilog／Verilator、本地持续 RTL 会话、RFuzz 输入及反馈、版本化 JSON 证据。

## 1. 已确定的范围与不变量

| 项目 | 本阶段决定 |
|---|---|
| CPU | CVA6、BOOM、CVW（CORE-V Wally）、VexiiRiscv；每核一个固定单核配置 |
| CPU 条件不足 | 允许 `skipped_unavailable`；必须列具体原因及受影响组合，不能声称四核全部支持 |
| BOOM | 优先经验证的 Chipyard 转换链导出 AXI；原生边界、内部缓存及转换链均进入身份 |
| 功能增强 IP | GPIO、UART、SPI、I2C、Timer；每个可运行 CPU 覆盖全部五类，最多 20 个组合 |
| 未知 IP | 新增一个此前未接入的真实 IP，必须在关闭功能插件时通过基础接入门禁 |
| DMA、多核 | 留到后续阶段，不加入本轮完成分母 |
| 输入 | CPU 侧变异程序，IP 侧变异声明的环境输入；CPU 发出的事务与 bound 输入不可主机改写 |
| 时间 | 独立 harness 的局部 tick／时钟域及显式交付；不引入全局周期准确 SoC 模拟 |
| 资源 | RTL 构建／生成／运行串行；复用身份缓存，不复制整个仓库 |
| 兼容 | 保留第一阶段有效入口和身份语义，旧证据不自动升级 |

普适性表示在**已验证协议子集、真实端口事实和受信描述**内复用框架。未知功能可降级；未知协议、缺失握手、无法确定 reset、必需输入无合法来源等不能降级成可执行。

CPU 架构观察保持统一 ISA 能力、Session 契约及事务／退休观察。组件专用代码允许存在于边界适配器和探针，核心不得按 CPU／IP 名称分支。不把指令发射、总线请求或推测执行当作架构退休。

## 2. 经代码核对的复用起点

- `src/myfuzz/local_harness/` 已有通用 APB3、TL-UL、Wishbone 寄存器／端口观察模板、生成策略和独立 session，扩展这些实现，不重新建立 harness 系统。
- `src/myfuzz/scenario/` 已有 runtime path contract、逐边来源、交互反馈、来源登记和持久会话；新增分级和基础消费者接到既有事件／证据接口。
- 当前通用模板仍有显式宽度、对齐、输入类型、peer 和启动写入限制。任务首先登记真实子集，不能把“存在通用模板”等同于全部同协议 IP 都可执行。
- 当前 CPU 程序与支持指令部分仍明确限制 RV32I、32-bit word／NOP，需要在能力接口下扩展；不更换既有 ISA 与 Session 抽象。
- 本地已有 OpenTitan HMAC 原生 TL-UL RTL 与寄存器资料；现有 peripheral profile 和运行能力索引没有 HMAC 条目，作为未知 IP 接入门禁的固定对象。其源码存在不等于已完成依赖闭包、harness 或测试。

## 3. 必须实现的接口语义

### 3.1 L1／L2／L3 是本系统测试能力，不是 IP 厂商的成熟度等级

| 级别 | 必需输入 | 可执行测试／检查 | 不授予的能力 |
|---|---|---|---|
| L1 接口级 | 源锁、原生协议／端口事实、reset／clock、地址 aperture、输入归属与合法接口范围 | 接纳／响应／错误／等待、实际端口采样与变化、显式交付、事务身份与基础依赖核对、协议及基础覆盖反馈 | 寄存器读写副作用、内部功能状态、算法正确性、完整功能链 |
| L2 寄存器级 | L1 加经过核对的寄存器／字段描述及可写 mask、访问权限／宽度、明确副作用规则 | 合法寄存器程序、字段边界、reset 值、声明的读写语义、可观察寄存器状态及版本依赖 | 未描述的 FIFO／功能状态、按名称猜测的完成条件 |
| L3 功能级 | L2 加可选功能族插件、环境 peer、真实观察映射与功能规则 | 功能动作、传输、IRQ 原因、操作完成、深层持久状态、完整功能链及语义反馈 | 未观察的内部原因、未验证配置／模式 |

实现 `declared_level`、`effective_level` 和 `verified_level`：分别表示描述请求、启动前可执行能力、已通过证据的最高等级。能力按具体操作／端点登记，不因一个字段缺失整体撤销已有能力。

默认自动选择实际可执行的最高等级，并报告缺口。显式要求最低 L2／L3 时，达不到就启动前拒绝；不能静默降级。缺功能插件可运行 L1/L2；无寄存器描述可运行 L1，但不推断所有 aperture 地址都具有相同寄存器语义。

L1 集成时由 CPU 程序产生访问；独立协议门禁可由既有 BFM 发起事务，必须标记 `standalone_protocol_test`，不得冒充 CPU→IP 证据。声明的保留地址、访问上限和必需前提始终生效；未实现地址返回的真实协议错误单独记录，不凭错误响应判定 IP 功能失败。

### 3.2 基础事件独立于功能族插件

新增版本化 `ip_base_event.v1`，由协议／端口边界产生以下公共事件：

- `transaction_request`、`transaction_accept`、`transaction_response`、`protocol_error`、`wait_observation`。
- `port_sample`、`signal_change`、`binding_delivery`；只有目标实际采样并可关联时记录 `input_sample`。
- `reset_observation`、`clock_domain_progress`；记录实际局部状态，不虚构全局先后。

公共字段：组件／端点、原始事件引用、局部 event ID 和时钟域／tick、reset epoch、原生 transaction key、动作／来源引用、payload、观察映射身份和观察性质。没有原生身份时保留缺口，不能用数组位置假造事务 key。

派生层分两类：L2 的 `register_access`／可观察字段版本；L3 的功能 `transfer`、`interrupt`、`state_transition`、`completion`。普通总线收发仍是基础事务事件；串行帧、FIFO 消费和算法完成才是功能事件。IRQ 引脚变化在 L1 是 `signal_change`；具备声明的 IRQ 交付角色可检查交付；功能原因、CPU 接受及 ISR 退休另需对应证据。

新增 `ip_register_event.v1`、`ip_function_event.v1`；派生事件保留 `base_event_refs`、规则版本和证明范围。观测映射只允许端口／字段选择、位切片、端序转换和证据引用，不允许承载计算功能结果的任意脚本或隐式功能模型。

插件可消费基础／寄存器事件并追加功能事件、动作及语义检查，不改变基础事件，不改变主机数据交付，不提供它唯一知道的基础 coverage，不能成为基础归属检查或协议检查的必需依赖。

### 3.3 依赖分级及证据要求

新增 `dependency_evidence.v1`，使用 `declared`、`candidate`、`verified` 三种类型，并保存关系、范围、证据引用、规则、epoch 和有效性。

| 类型 | 来源 | 允许用途 |
|---|---|---|
| declared 声明依赖 | Profile／路径／输入归属契约 | 路径规划、绑定约束；不证明一次执行已经发生传播 |
| candidate 候选依赖 | 运行时事件相关性、时序、值匹配、覆盖变化 | 探索目标建议；不满足来源前置条件，不产生认证闭环 |
| verified 真实依赖 | 精确请求／交付／消费身份、byte mask／版本或相应真实观察 | 已验证依赖反馈、状态前置 witness、逐边证书；范围不能超出证据 |

不是自动的三个状态晋级：声明存在而运行未验证时，声明继续存在；有证据的运行依赖另行记录并引用声明。声明外候选必须先通过 ownership、路由及协议合法性核对，再产生运行证明；候选不能自动修改执行拓扑。

仅时序相邻、相同数据或一次覆盖变化不能晋级 verified。反事实／变异对照可加强 candidate，但缺少精确身份的关系仍不认证。协议身份只能证明接纳／响应；不能据此宣称寄存器副作用、功能完成或 CPU 已退休。

reset、覆盖写、证据淘汰或身份冲突使相应实时 witness 失效；历史已验证观察保留，当前 prerequisite 不得复用失效 witness。跨例来源保留起始 action／case，不强行归属于消费例。

反馈分别报告 `base_coverage`、`candidate_novelty`、`verified_dependency`、`functional_coverage`。基础事务和真实信号覆盖可在 L1 获得探索权重。候选探索通道默认关闭，显式开启时按 session 去重、每 case 最多一个候选 novelty 单位且最多占该例新增能量的 10%；不得计入认证链收益，配置进入 replay identity。候选过期和淘汰不制造新 novelty。

## 4. 工作包与逐项验收

### A. 基线、已有问题与资源

- [x] A1：冻结实施起点的 Git／第三方／工具链身份及 CPU/IP 能力；核对其他 agent 的已实现部分，按接口兼容增量实施。
- [x] A2：重核首步 replay 输出、证据摘要、缺失身份、零耗时／验证数、异常清理、证书完整性和 batch 状态问题。公共路径负例已修复，最新并行回归覆盖首步／P5、真实事件 fixture 证书身份、serial token、batch 重放身份与失败清理；详见 M0 进度报告和机器摘要。
- [x] A3：把 4 CPU×5 功能族登记为单独验收行，并新增 HMAC 基础接入行；L1/L2/L3、可执行／已验证分别报告。
- [x] A4：构建／运行采用单 worker；进程树 RSS 上限默认 `min(4 GiB, 启动可用内存－2 GiB)`，可用预算不足 1 GiB 时不启动重型任务。生成 JVM 使用显式 heap；预算终止单列，不记 DUT finding。首步 smoke、启动拒绝回执、Java/SBT heap 预检和 Mill fail-closed 均有验证证据。
- [x] A5：单一按身份索引的构建缓存；新 run 使用新目录；不复制整仓库，不覆盖第一阶段材料。启动、运行、replay 任一失败须清理全部组件进程。真实 Verilator cache identity／损坏拒绝测试、fresh output 目录和进程树失败清理均有证据。

**交付与门槛：**起点与能力表、受影响负例结果、资源终止／清理证据、输出规则。基线未达到门槛，不开始长跑。

### B. 公共 IP 描述与等级预检

- [x] B1：沿用现有 component profile／request／tuning，增加可选的版本化测试能力、寄存器语义和观察映射描述；旧 schema 不接受新字段，新字段采用明确的 sidecar／新版本契约。新增 `ip_test_capability.v1` sidecar loader，要求并核对完整 profile 文档的规范化 SHA-256 指纹，再核对端点、字段、寄存器、权限／mask、观察映射及证据引用；现有 `component_profile.v1` 对未知顶层键 fail closed。
- [ ] B2：实现等级解析和缺口报告，输出 declared／effective／verified level 与 endpoint／operation 支持矩阵，并单列调用方请求的最低等级。
- [ ] B3：核对所有必需端口、方向、宽度、clock／reset、aperture、输出映射、输入 ownership 和协议子集；功能未知与接口非法分别处理。
- [ ] B4：L1 无 register map／无插件可运行；L2 应用实际字段权限／mask／副作用规则；L3 插件必须自述需要的观察能力。
- [ ] B5：去掉基础路径依赖 `gpio`／`uart`／`spi` 等名称才能选择 executor 的规则；保留旧专用执行器和已验证功能路径。
- [ ] B6：增加负例：缺功能描述只降级、最低等级不满足拒绝、未知协议拒绝、bound 输入不可 fuzz、端口缺失拒绝、寄存器名称不得推断功能。

**交付与门槛：**等级接口、描述契约、同一匿名 IP 在 L1/L2/L3 的能力差异测试；L1 启动不导入或调用功能插件。

### C. 基础事件与通用协议／端口检查

- [ ] C1：在既有协议 adapter 和 raw event 出口添加组件中立的规范化层；原始 trace 保留，不对旧事件重新编号或改值。
- [ ] C2：先覆盖现有通用 APB3、TL-UL、Wishbone 目标模板；其他协议复用已实现子集，未验证形态保持 unsupported。
- [ ] C3：基础记录请求／接纳／响应／错误／等待；各 channel 的未完成、重复、取消和 timeout 依原生协议保留身份。
- [ ] C4：按 profile 导出任意名称的合法物理输入／输出；记录实际采样、变化、绑定值和 reset epoch，不根据名字推断功能。
- [ ] C5：共用协议 Checker 验证握手、请求稳定、响应关联、mask、至多一次交付和超预算；不要求未知 IP 写后读相等。
- [ ] C6：基础覆盖记录事务类型、响应、延迟 bucket、端口切片变化和声明的实际目标覆盖位，有限集合／饱和计数，按游标增量消费。
- [ ] C7：以无功能插件的 fixture 验证合法／非法事务、stall、error、重复 ID、reset、迟到响应和跨例消费。

**交付与门槛：**不依赖功能族的真实基础事件、Checker、覆盖；去掉插件后同一 raw trace 的基础事件及基础覆盖不变。

### D. 三类依赖及运行证据消费

- [ ] D1：把声明图／执行候选／已验证证据在 API、报告和存储中分开；既有 RuntimePathContract 继续承担拓扑和前置契约。
- [ ] D2：候选发现依据实际事件及覆盖变化，限制 pending、窗口、详情数和候选特征数；不回写 topology，不执行候选指定的输入。
- [ ] D3：复用既有 runtime edge／source provenance 消费者，认证显式 binding 的 producer→delivery→真实 input sample，以及精确事务请求→接纳→响应。
- [ ] D4：L2／L3 用额外版本／消费证明扩展关系；功能族无证据时保持 incomplete／unknown；协议接纳不等于内部操作成功。
- [ ] D5：RAM writer／byte-enable／读 snapshot、IRQ 交付／接受／退休各自保持证明范围；真实 persistent witness 才可满足前置状态。
- [ ] D6：实现 history 与 active witness 分离；reset、覆盖写、证据淘汰和冲突不得使旧 witness 重新满足 prerequisites。
- [ ] D7：负例覆盖仅事件相邻、值相同但事务不同、不同 epoch、消费先于接纳、删 delivery、删 sample、重传、同 ID 变内容。
- [ ] D8：候选探索默认关闭；启用后按第 3.3 节限制，只改变合法目标的探索排序。反馈逐类别可审计，不能用 candidate 提升 verified 计数。

**交付与门槛：**基础依赖在 L1 可被验证；未知 IP 可产生协议／交付级证据但不能取得未观察功能的认证。候选伪证样例必须全部拒绝晋级。

### E. 寄存器规则与可选功能族增强

- [ ] E1：L2 描述地址／字段／权限／mask／reset／访问宽度，W1C、read-clear、FIFO 等规则只在真实行为已核对且有观察依据时启用。
- [ ] E2：寄存器生成仍通过 CPU 程序；独立 BFM 模式显式单列。未声明副作用不设置写后读 oracle。
- [ ] E3：功能族插件只追加功能动作、derived event、语义 Checker 和功能覆盖；使用有界、版本化规则，不改变基础交付及 raw trace。
- [ ] E4：GPIO 增强方向／mask／外部输入／输出及 IRQ 原因；UART 增强帧、FIFO／发送及中断；SPI 增强 CS／串行事务；I2C 增强地址／ACK／NACK／STOP；Timer 增强启停／到期／清除。
- [ ] E5：peer 产生实际合法环境输入；约束状态由协议／RTL 观察获取，不能用主机功能模拟器替代 DUT。
- [ ] E6：同一 IP 分别运行 L1、L2、L3；关闭插件后仍产生基础事件／事务及反馈；功能证据不足只降低对应语义能力。
- [ ] E7：为各族增加 busy、非法字段、缺观察、错误 IRQ 和未完成操作负例；异常实际输出不能因路径未就绪而过滤。

**交付与门槛：**五族增强可独立启停；每族有至少一个真实功能验收。新增未知功能族无需实现 E3–E7 即可执行 L1。

### F. CPU 侧的增量通用化与四核接入

- [ ] F1：保留现有 CPU Session，统一能力查询、begin、程序片段接纳、step、事务／退休观察、带来源 IRQ 交付和幂等 finalize；以已有方法建立能力委托，不替换全部执行体系。
- [ ] F2：按 ISA 能力支持 XLEN、实际 register 集、合法指令子集、地址及访存宽度；固定引导／ISR／NOP 与可变片段分开。初期不 fuzz 浮点、向量及未验证原子指令。
- [ ] F3：缓存／预取涉及的程序字节一经物化不可覆盖；接纳位置及 fence 行为依能力规则。未准备的未来代码不能被普通未初始化 RAM 随机物化后再次提交。
- [ ] F4：事务与退休统一观察，多退休 slot／取消请求与架构顺序分开；不假定总线请求与退休一一对应。
- [ ] F5：CVA6 复用已有 AXI4 harness／source closure，先迁移到公共接口，再逐五类 IP 验收。
- [ ] F6：CVW 固定官方单核可仿真配置；优先 RV64，若官方可运行配置只有 RV32 则记录选择原因。核实实际 AHB 边界，缺协议子集时在 adapter 层实现并验证，不在 Runner 加 CPU 名称分支。
- [ ] F7：VexiiRiscv 固定生成配置、工具链与 RTL，优先已有合法 AXI 导出方式；接口／退休／IRQ 不具备的条件明确记录，不能伪造边界。
- [ ] F8：BOOM 固定受支持最小单核配置和 Chipyard 转换链；验证 AXI 导出、MMIO 属性、内部缓存／一致性与真实 commit 观察。工具链／资源／合法边界缺失则记录 skipped_unavailable。
- [ ] F9：每核先独立 Fetch、RAM Load／Store／byte mask／MMIO／IRQ 门禁，再进入长期组合。缺 IRQ 的 CPU 可以执行基础行，不能把该功能行判为通过；缺退休证据不能授予退休链认证。

**交付与门槛：**统一 CPU 契约与四核逐项状态，核心无 CPU 名称分支；跨核不要求 tick 或微架构 trace 相同。

### G. 新未知 IP 的强制接入门禁

固定对象为本地已有真实 RTL、尚未有本系统 profile 的 **OpenTitan HMAC**。本轮不实现 HMAC 功能族插件，也不验收密码算法。厂商文档里的生命周期 L1/L2 与本系统等级完全无关。

- [ ] G1：在基础框架冻结后检查 profile／report 仍没有 HMAC；记录 baseline 和全部 protected core 路径的 blob SHA。
- [ ] G2：固定现有 OpenTitan revision 及 HMAC 依赖闭包，新增 Profile、接口说明、合法 clock／reset／固定输入及观察映射。需要结构体 scalar wrapper 时只做连线／位映射，进入组件描述包，不写 HMAC Session 或新 executor。
- [ ] G3：使用现有 generic TL-UL 目标适配执行 L1；功能插件列表为空，register map 可省略；测试真实请求／响应、合法错误、输出采样、协议身份和基础覆盖。
- [ ] G4：提供核实的寄存器描述后执行 L2：至少一个无副作用稳定寄存器的受约束写／读、reset 及权限边界；不将任何输出命名成 hash／算法完成结论。
- [ ] G5：与 CVA6 组合，由真实 CPU 程序产生事务，连续至少 3 个 case、一次初始化；产生至少一条协议／交付级 verified dependency，保留 candidate 与未知项。
- [ ] G6：60 秒基础持续搜索及 fresh 完整 replay；改接口／映射／输入摘要时启动前拒绝；缺功能语义显示 L1/L2、L3 未验证，而非 unavailable。
- [ ] G7：改组件 ID 和实例 ID，保持同一 RTL／描述内容，仍可运行；检查基础路径没有名称特判。
- [ ] G8：接入 diff 只允许组件 Profile／接口及观察描述、声明式场景、测试／报告和该组件的透明接线 wrapper。Runner、Router、Scheduler、Mutator、公共 Checker、公共 factory／registry、协议执行器及功能插件不得改动；逐文件 SHA 和 diff 由只读 verifier 核对。

**强制通过条件：**G1–G8 全部成立。若接入暴露通用框架缺陷，回到 B/C 修复、冻结新 baseline 后重新接入；不能一边新增组件专用公共代码一边称门禁通过。HMAC 门禁不得以 skipped_unavailable 抵消；资源或闭包未解决时，该阶段仍缺未知 IP 接入证据。

### H. 20 个组合的功能及分级验收

| CPU | GPIO | UART | SPI | I2C | Timer |
|---|---|---|---|---|---|
| CVA6 | PULP GPIO | OpenTitan UART | OpenTitan SPI Host | PULP I2C | OpenTitan RV Timer |
| BOOM | 同上 | 同上 | 同上 | 同上 | 同上 |
| CVW | 同上 | 同上 | 同上 | 同上 | 同上 |
| VexiiRiscv | 同上 | 同上 | 同上 | 同上 | 同上 |

- [ ] H1：每行依次独立交易、8-case smoke、60 秒连续搜索／replay、600 秒功能门禁／replay；失败不进入后一级。
- [ ] H2：每个可运行 CPU 的五行均验证真实 CPU→IP 消费及 IP→CPU read／IRQ 路径、持续状态、两侧可用上游输入、实际反馈、正常对照、受控错误捕获与完整前缀。
- [ ] H3：非功能插件提供的 L1 基础覆盖／依赖独立报告；L3 功能链单列，不能用基础事务完成抵消缺功能证据。
- [ ] H4：当 IP 没有合法外部数据输入时，按描述登记可探索源，不为满足双侧指标虚构输入；该矩阵默认对象具有外部／时间输入的实际角色，Timer 本地时间推进属于固定调度，只有可合法选择的等待／调度才可作为独立探索动作。
- [ ] H5：每行使用相同预算的反馈启用／关闭短对照，证明选择受影响；不要求覆盖收益必然为正。
- [ ] H6：统计初始化、有效搜索、终结、逐例耗时、资源峰值、覆盖、candidate／verified／functional 指标及来源缺口。零耗时和缺验证数不能通过。
- [ ] H7：增加功能族替换：GPIO PULP→OpenTitan、UART OpenTitan→ZipCPU、SPI OpenTitan→PULP、I2C PULP→OpenTitan、Timer OpenTitan→PULP；在 CVA6 上各 60 秒及 replay，核心不增加名称分支。

**完成口径：**每个可运行 CPU 的五行均达到声明的功能门槛；若某行只能 L1/L2，该行基础能力可登记通过，但功能矩阵仍未完成。跳过 CPU 的整列附原因，不能用其他 CPU 的组合抵消。

### I. 兼容、证据、文档与交付

- [ ] I1：恢复／保留 Ibex 第一阶段有效入口；旧 schema 原样解释，规范化及分级语义进入新 run identity，历史证据不补字段后冒充新版本。
- [ ] I2：完整保存 raw／生成程序／源动作／接纳顺序／等待选择／首次物化／case 前缀／所有身份；实际核验文件 hash，而非仅声明摘要。
- [ ] I3：fresh replay 从新进程初态复现 raw 与规范化事件、证据类别及 finding；候选发现和插件配置冻结。跨 epoch active witness 状态按事件重建。
- [ ] I4：只读验收器验证分级、插件禁用、依赖负例、SHA 冻结、新 IP protected diff、20 行、可用 CPU、完整 replay 和资源边界。
- [ ] I5：能力查询和报告支持按 operation／endpoint 的 L1–L3，显示 declared／effective／verified、candidate／verified 与 skipped 原因，不按插件安装情况推断运行可用性。
- [ ] I6：更新系统说明、能力矩阵及总计划 P6/P7 的声明范围；新 IP 基础接入是本阶段强制子门禁，不等于 P7 任意组件全功能自动测试完成。
- [ ] I7：提交源码、配置、单测、真实门禁、只读复算命令与最小恢复材料；cache 集中保留，临时副本清理依据身份清单。

## 5. 测试清单与完成证据

| 测试组 | 必须覆盖 |
|---|---|
| 分级 | 无插件运行 L1；无 register map 仍 L1；合法 map→L2；缺功能观察只禁对应功能；最低等级请求不满足拒绝 |
| 基础事件 | APB3／TL-UL／Wishbone 的 request／accept／response、wait/error；任意端口名与切片；raw 不变；插件关闭基础流不变 |
| 寄存器 | mask／权限／宽度／reset；已核实副作用；无描述不推断写后读相等；CPU 与 BFM 来源明确 |
| 依赖 | 声明不等于真实；时间和值相同只有候选；删精确 hop 撤销认证；epoch／版本／容量／冲突／重试／迟到消费 |
| 反馈 | 基础覆盖独立可用；候选默认关闭且预算有界；候选不认证；功能 novelty 单列；当前 witness 与历史计数分开 |
| CPU | ISA／XLEN、缓存物化、burst／ID、推测／退休、实际 IRQ、未知能力拒绝；核心无 CPU 名称分支 |
| 新组件 | 真实 HMAC 无插件 L1、寄存器描述 L2、CVA6 组合、60 秒及 replay、核心文件 SHA 不变 |
| 资源与清理 | 单 worker；进程树预算；异常释放；新日志不覆盖旧证据；候选和观察详情不能无界保留 |
| 兼容 | 第一阶段轻量回归及短真实 Ibex smoke；旧 replay 明确版本；不重解释历史结论 |

长跑不作为开发阶段反复调试方法。真实结果按构建／独立／smoke／短跑／长跑递进；每项结论绑定当前配置，禁止把多份短跑 union 宣称为一份持续会话。

## 6. 实施顺序、检查点和最终交付

| 检查点 | 任务 | 进入下一步条件 |
|---|---|---|
| M0 | A | 公共证据风险重核，资源控制及基线有效 |
| M1 | B、C | 匿名／未知功能 IP 可按已支持协议运行 L1，基础事件不需功能插件 |
| M2 | D、E1–E2 | 三类依赖隔离，基础反馈及 L2 已验证，不发生候选伪认证 |
| M3 | F1–F5、G | CVA6 接入保留架构，真实新 HMAC 仅描述接入门禁通过 |
| M4 | E3–E7、H7 | 五类功能插件可选，基础测试仍可运行，替换证明复用 |
| M5 | F6–F9、H1–H6 | 四核逐项可用状态明确；全部可运行 CPU 的五行完成 |
| M6 | I | 分级及依赖验收器、兼容、文档、恢复材料齐全 |

CPU 实施顺序 CVA6→CVW→VexiiRiscv→BOOM；后三核工具链／来源条件在 A 同时核清，但重型生成仍串行。若原有第二阶段任务已经完成，按同一 gate 补证／复用，不重复实现。

最终交付：保留既有架构的增量 patch；四核能力／配置；L1–L3 描述及预检；基础／寄存器／功能事件；三类依赖和分离反馈；五族增强及替换证据；HMAC 未知 IP 强制门禁；最多 20 个组合的逐行结果；完整身份／replay／资源报告；缺口清单和最小恢复资料。

**当前状态：**A1–A5 已完成，M0 基线门禁通过；B1 已完成，M1 正在执行。A2 修复首步 replay 日志消费和配对验收伪通过，并审计 fresh RTL trace counts／identity、证书精确身份、serial token、batch replay identity 与异常清理。A4/A5 的单 worker／进程树 RSS、启动拒绝、heap fail-closed、身份缓存、fresh run 目录与失败清理均有测试或真实 smoke／Verilator 证据。当前尚无 Stage 2 CPU/IP 生产命令消费者；B–I 建立具体重型命令时必须接入同一 worker 与身份缓存，这属于后续工作包的执行约束。Java/SBT/Mill 不可用，直接 Mill 命令 fail closed；不声称真实 JVM generator 已运行。B1 sidecar 有独立版本、闭集字段校验、完整 profile 指纹绑定、引用核对和深度不可变身份。Ibex retry1 的 3/3 legacy cases 与 fresh replay 不能授予 Stage 2 矩阵等级。见 [M0/B1 进度报告](../../reports/stage2-m0-baseline-progress-20261009.md)、[起点身份](../../reports/stage2-baseline-20261009.json)和[逐行矩阵](../../STAGE2_ACCEPTANCE_MATRIX.md)。
