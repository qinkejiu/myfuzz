# 多组件持续场景模糊测试：目标系统详细设计

> 历史设计基线：本文件保留当时的持续状态、输入所有权和因果传播契约，但其中“一个 testcase 是整段场景、下一 testcase 获得新状态”的生命周期已被[当前设计](../../CURRENT_DESIGN.md)和[当前实施计划](../plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)取代。当前要求是**会话初始化一次、多个 testcase 共享真实 RTL/RAM/待处理事件、每例有独立反馈、从会话前缀重放**。最初仅列 OpenTitan 外设、Ibex＋双 OpenTitan GPIO 的范围也已扩展；实测边界见[运行能力表](../../LOCAL_HARNESS_RUNTIME.md)。

版本：1.1｜日期：2026-09-27｜状态：设计与验收契约；部分基础模块实施中

配套文件：`docs/superpowers/plans/2026-09-27-persistent-multicomponent-fuzz-implementation.md`。

本文件规定目标行为。配套实施文件说明现状、文件修改、阶段任务、测试入口和验收证据。已完成的基础模块和真实 RTL 局部里程碑以实施文件记录为准；其余接口和测试仍是设计要求，不能视为已经通过端到端验收。

核心原则：局部 RTL 执行真实，跨组件数据流抽象，testcase 内状态持续，真实结果不能被随机覆盖。

## 1. 目标、范围与成功条件

### 1.1 系统要完成的工作

系统同时管理真实 CPU 与 OpenTitan 系列 GPIO、SPI、UART 等 IP 的独立 harness。Fuzzer 选择目标、传播方向和 Dependency Path，从上游 Fuzzable Source 变异程序、初始数据、外部输入或合法调度决策。各组件真实执行后，其真实输出通过 Dataflow Router 转化为其他组件后续输入；Dependency Scheduler 维护局部执行与事件先后。

一次 testcase 是一个持续场景。CPU/IP 的寄存器、局部流水线、FIFO、内存、未完成事务、待投递事件和场景事实在多个周期及多次交互之间保留。普通 step、输入 chunk、一次读写完成、一次 IRQ 或一次 ISR 返回均不是新的 testcase。

目标传播包括 CPU→IP、IP→CPU、IP→IP，以及 CPU→IP→CPU、IP→CPU→IP、CPU→IP_A→IP_B→CPU。每条已完成传播必须有真实请求、真实目标执行、实际数据交付及消费证据。

### 1.2 抽象边界

保留各 DUT 原生接口、局部协议、局部时序、真实内部状态与真实输出。跨组件使用统一事务、事件、数据来源和状态版本描述关系。

不生成完整 SoC 顶层，不实现 Bus、Crossbar、Bridge、Arbiter、PLIC 或全局周期对齐。局部 harness 中的总线驱动器/响应器负责各自端口协议，不是连接两个 DUT 的桥接 RTL。host 调度顺序不等价于硬件仲裁，逻辑等待也不等价于实际 SoC 延迟。

外设范围限定为项目中有固定源码身份的 OpenTitan 系列 IP。首个端到端场景采用一个 Ibex 与两个独立 OpenTitan GPIO 实例；随后用同一场景契约接入 CVA6，BOOM 仅在本地具备可执行生成 RTL、完整依赖和受支持接口时进入运行验收。本地无法执行的 CPU 记录具体阻碍并跳过，不将静态源码检查算作运行通过。数据模型允许多个 CPU，但首版不验收多核共享缓存、一致性、原子操作、弱内存模型、CDC 或任意 AXI burst。

### 1.3 成功条件

必须同时证明：源变异确实改变真实上游行为；下游输入来自真实上游或明确的持久环境状态；同 testcase 内状态不会被逐周期重新随机化；跨多周期链能够继续；异常不会被约束器隐藏；从初始状态重新执行能够复现完整状态演化。

覆盖增长、无崩溃、多个组件同时运行或最终结果非零，均不能单独作为上述条件的证明。

## 2. 术语与时间模型

### 2.1 四种边界

| 名称 | 定义 | 状态行为 |
|---|---|---|
| campaign | 包含多个候选 testcase 的搜索任务 | 保留 corpus、统计和构建缓存，不继承前一 testcase 的 DUT 状态 |
| testcase | 从声明初始条件开始的一次持续运行 | 持有自己的运行状态、随机材料、事务与事件历史 |
| chunk | 同 testcase 的输入运输或 host 工作分块 | 不 reset、不重灌镜像、不重播已执行动作 |
| reset barrier | genome 或错误策略显式要求的复位边界 | 按具名资源策略处理 RTL、内存、事务和事件 |

### 2.2 身份与时钟

`campaign_id` 标识搜索，`testcase_id` 标识一份场景输入，`execution_id` 区分相同输入的重复执行。日志中的逻辑身份与 execution_id 分离，重放比较时对宿主执行身份进行显式规范化。

每个组件具有 `component_id`、`reset_epoch`、单调 `lifetime_tick` 与本 epoch 内的 `epoch_tick`。普通 chunk 不改变 epoch，不把 tick 归零。跨组件事件具有单调 `event_seq`；它表示执行记录顺序，不表示全局硬件时钟。

每个环境内存具有独立 `memory_id` 与 `memory_generation`。warm reset 可以增加组件 epoch，同时保留内存 generation。不能将 CPU epoch 隐式用作物理内存身份。

### 2.3 Chunk 等价的精确定义

相同 genome、初始状态和有序调度，仅改变 host 分块边界时，语义事件、逐组件输入/输出、读返回及最终状态必须相同。不同组件交错顺序或不同 IRQ 时机是不同实验，不要求结果相同。

## 3. 保留的总体架构

```text
组件描述 / 固定绑定 / 持久资源策略
                  ↓
          Scenario Compiler
                  ↓
Fuzzer → Genome → ScenarioRunner
                  ├─ Persistent Runtime State
                  ├─ Dependency Scheduler
                  ├─ Dataflow Router
                  ├─ Memory Service + Transaction Ledger
                  └─ 多个独立 Local Harness → 真实 RTL
                                          ↓
                           原始观察 / 状态版本 / 因果记录
                                          ↓
                           独立 Checker / Coverage / Replay
```

组件内部功能由真实 RTL 产生。环境拥有的 RAM/ROM、外部设备输入和事件递送可建模；若某存储本身就是被测真实 RAM/IP，其响应仍来自该 RTL，不能以环境 Memory Model 替代。

## 4. 输入所有权与持久绑定

### 4.1 Fuzzable Source

Fuzzable Source 是明确声明为环境所有、未绑定其他真实输出、允许在当前阶段改变的决策源，例如 CPU 初始程序/数据、GPIO 自由引脚、SPI peer 数据、UART 帧、合法事件延迟及未初始化 RAM 的首次取值材料。

CPU 内部寄存器操作数通过程序和初始数据产生。时钟、协议握手状态和固定值不能仅因没有上游连接就变成任意随机输入。

### 4.2 Bound Input

Bound Input 保持现有定义：其值有唯一声明来源，Fuzzer 不直接写该字段。`producer_ref` 可以指向真实 RTL 输出，也可以指向本方案新增的持久环境资源版本。例如 CPU 读 RAM 的 rdata 绑定 Memory Service 的已冻结响应；CPU 读 GPIO 的 rdata 绑定该 GPIO 的真实响应。

这不是第三种可随机端口。Fuzzer 可以选择首次初始化材料；一旦字节物化，后续输入由该持久状态决定。绑定字段没有独立随机 payload。

### 4.3 不变量

- OWN-01：同一场景、阶段和位区段只能有一个驱动来源，Fuzzable Source 与 Bound Input 不重叠。
- OWN-02：切换 mutation direction 只能改变选源和操作子，不能解除绑定。
- OWN-03：DUT 输出、已提交内存字节、已冻结响应和已发生事件不在 mutator 的可写集合中。
- OWN-04：没有上游结果时应等待、报告能力问题或未完成，不填零、不随机补值、不使用预期成功结果。
- OWN-05：初始镜像只在创建对应 memory generation 时应用；不能在每个周期或 chunk 重新覆盖 CPU Store。

## 5. ScenarioRunner 连续生命周期

### 5.1 状态机

```text
CREATED → INITIALIZING → RUNNING → QUIESCING → FINALIZED
                            │           │
                            ├→ RESETTING → RUNNING
                            └→ FAILED / INCOMPLETE → FINALIZED
```

`INITIALIZING` 验证构建和 genome 身份，创建全部持久资源，加载一次初始镜像，按局部要求施加初始 reset，释放后进入 RUNNING。后续不能以处理一条 action 为由重新调用 begin_test。

### 5.2 建议接口

```python
class ScenarioRunner:
    def begin_test(self, manifest, genome) -> None: ...
    def step(self, max_scheduler_steps: int) -> object: ...
    def request_reset(self, reset_action) -> None: ...
    def quiesce(self, max_scheduler_steps: int) -> object: ...
    def finalize(self) -> object: ...
```

这些是接口契约，不是现有实现。`step` 只能推进当前上下文，不能重建 MemoryState 或 harness。收包由独立 `ChunkAssembler.append(ChunkEnvelope)` 完成；envelope 包含 execution_id、testcase_id、genome 身份、chunk_id、长度、hash 和 final。Assembler 不推进仿真、不消费随机材料、不改变初始化状态。首版完整接收并校验有界 genome 后才 begin_test；begin 后追加返回 unsupported_streaming_input。真正边收边执行属于后续扩展，避免输入到达时间影响仿真。

### 5.3 单次调度步骤

1. 依据稳定规则选择可推进组件，公平轮转并限制连续服务上限。
2. 在目标组件允许改变输入的局部边界施加已就绪动作，已接受的协议载荷按要求保持。
3. 推进该组件一个局部周期，采集真实请求、响应、引脚、IRQ 和覆盖增量。
4. 将新观察追加到不可变日志；更新事务状态和观察事实。
5. 对已被内存服务接受的操作执行一次提交，产生冻结响应和状态版本。
6. Router 生成带来源的后续交付；Scheduler 更新就绪队列、动作游标与局部等待。
7. 独立检查器处理全部观察，包括提前 IRQ、错误返回和协议违例。

### 5.4 结束与排空

没有下一条 genome action 不意味着每周期输入补零或自动 reset。RTL 可以继续执行并消费已排队结果，直到结束条件或预算达到。

进入 QUIESCING 时冻结已接受事务和待交付事件集合，停止生成新外部根事件，以合法背压停止接受新的源事务；继续处理冻结集合及完成它们所必需的派生动作。此时 IRQ 排空仅表示既定脉冲已交付并到期，不表示 CPU 完成 ISR；需要两轮 ISR 完成的成功条件必须在进入 quiesce 前达到。不能一边阻止取指一边等待新的 ISR 完成。首版排空上限为 4,096 个调度步骤，数值进入 manifest。若不能排空，保存最后可靠事实，报告 incomplete 或 uncertain_effect，不能伪造成功或静默清队列。

finalize 必须先写证据与最终摘要，再按 testcase 结束策略 reset/释放资源。再次 finalize 不得产生第二次 DUT 执行。进程可复用，但下一 testcase 必须获得新的状态上下文和正确初始条件。

## 6. Persistent Runtime State

### 6.1 状态组成

| 对象 | 主要内容 | 权威来源 |
|---|---|---|
| Identity | testcase、execution、manifest、genome、policy 身份 | 固定输入材料 |
| Component State | RTL 实例、epoch、局部 tick、reset 记录 | 各真实 RTL/harness |
| Memory State | 逐字节内容、初始化标记、版本、writer | 环境 Memory Service |
| Transaction Ledger | 接受、入队、目标提交、响应快照、交付、取消 | 真实握手与环境提交记录 |
| Pending Events | 尚未交付的绑定、IRQ、外部动作与到期规则 | 已发生事件和 genome |
| Scenario Facts | 已观察事实、持久配置访问证据、资源引用 | 有来源的原始观察 |
| Scheduler State | 就绪队列、稳定排序、动作游标、公平性计数 | 已声明调度策略 |
| Evidence State | append-only 日志、初始化材料、依赖边、检查结果 | 实际执行与独立判据 |

观察事实、环境资源和检查期望分开存放。成功配置写只证明访问已完成，不自动证明 IP 内部处于 configured 状态。期望结果不得写回观察事实。

### 6.2 资源上限

首版默认每 testcase：每组件最多 65,536 个运行局部周期；最多 262,144 个 scheduler step；每环境 RAM 最多 65,536 个已物化字节；最多 4,096 个源动作、16,384 笔事务、1,000,000 条语义记录和 256 MiB 证据；wall time 上限 60 秒。reset 周期另计并报告。

达到上限必须给出独立 budget_exhausted 结果，并保留已发生效果。256 MiB 证据上限中预留 8 MiB 给终止记录和摘要；正常事件达到剩余容量即停止接纳。不得为继续运行而清空内存、淘汰 pending 响应或覆写去重记录。host watchdog 与存储失败属于宿主终止，不是 genome 语义事件：重放比较保存完整的语义前缀，不要求再次恰好在相同 wall time 截断；缺失后缀必须标明。上述值是首版配置默认值，不是已测性能，也不是物理 SoC 时序限制。

## 7. Persistent Memory Model

### 7.1 规范化地址与字节单元

所有入口先映射到 `(memory_id, memory_generation, byte_offset)`。同物理资源的取指、数据访问和合法地址别名必须共享同一个存储对象。不同 memory_id 隔离；未声明别名不得通过随意屏蔽地址位产生。

```text
ByteCell:
    initialized: bool
    value: uint8
    version: (generation, commit_seq)
    writer_kind: INITIAL_IMAGE / FIRST_READ / STORE
    writer_event_id
    source_transaction_id
```

32 位读、16 位写和 8 位读均由同一组字节构成，禁止按访问宽度分别建 shadow map。首版按小端实现；地址、位宽、byte-enable 与端序的对应关系写入 profile。

每个独立 testcase 的初始 memory_generation 固定为 0；testcase 内每次 cold reset 对该资源递增，不继承进程历史。初始镜像字节使用版本 (generation, 0)；每次成功首次物化或有效 Store 按资源内提交顺序分配新 commit_seq，单次操作覆盖的字节共享该版本。没有新物化的普通读、失败操作和 BE=0 写不分配字节版本。状态图节点身份同时包含 memory_id、generation、byte_offset 和 version，不能仅按 commit_seq 合并不同字节。

### 7.2 一次性初始化

初始程序镜像和显式初始数据在 generation 创建时写入一次。尚未初始化的环境 RAM 在首次成功读服务提交时，仅对缺失字节生成值并保存。

建议首次字节初始化使用版本化 SHA-256 派生：

```text
byte_value = SHA256(canonical_encode([
  "memory-init-v1", initialization_seed,
  memory_id, generation, byte_offset
]))[0]
```

`canonical_encode` 的字段类型、UTF-8 编码和整数表示必须固定。输入不包含执行时钟、访问顺序、chunk ID 或 execution_id，因此同一字节的初值不随访问顺序或宽度变化。保存 seed、算法身份及实际物化字节。

已写入的字节不再调用初始化器；部分写未覆盖的字节保持未知，直到未来读提交才生成。Fuzzer 对 seed 的变异只作用于新 testcase 或明确的新 generation，不能反向修改已物化内容。

程序区域首版使用预装镜像。对可写执行区域发生真实 Store 后，新发生的 MemoryService 取指读提交取得修改后的字节；此前已经冻结的取指快照保持原值。CPU 已预取指令的执行由真实 RTL 和声明的指令同步契约决定，不据此声称通用自修改代码正确性。返回字节不能再次做 ISA 合法化。未来若增加按需合法指令生成，只允许填充完全未初始化且满足约束的区域，不能覆盖已确定字节。

### 7.3 byte-enable 写提交

内存服务在一个明确、原子的 `MEMORY_SERVICE_COMMIT` 点接受操作。提交前完整检查权限、宽度、范围、对齐和资源预算；首版不支持的跨界访问整体失败，不发生部分提交。

对被使能 lane i，写入 `wdata` 的对应字节，并标记 initialized、版本和真实 Store 来源。BE 为零的 lane 不改变 value、initialized、version 或 writer；全零 BE 是有事务记录的无数据效果操作，不生成新字节版本。

已有值即使被相同值再次写入，也要记录新的有效 writer，以保持真实写历史。只读区域写返回声明的访问错误。环境内存校验失败无副作用；不能把这一保证泛化为真实 IP 报错也无副作用。

### 7.4 读快照与延迟响应

源 CPU 请求接受、Memory Service 提交、CPU 接收响应是三个不同点。本设计的读值在 MEMORY_SERVICE_COMMIT 冻结；这个点是模型的串行化点，不是 CPU 源握手点，也不声明实际 SoC 的全局内存顺序。

读提交生成不可变 `ReadSnapshot`，包含字节值、逐字节版本、writer、事务 ID 和 commit event。随后写操作不会改变该快照。响应背压期间始终使用快照，交付时禁止重新读取当前内存。

多个入口访问同一环境内存时，首版按记录的服务提交序列串行化。不同合法调度可能改变交错结果；重放必须保存服务顺序。此策略不等价于多核缓存一致性或硬件原子语义。

### 7.5 数值示例

地址 A 起始 word 为 `0x11223344`，小端字节为 `44 33 22 11`。提交 `wdata=0xAABBCCDD`、`BE=0101` 后，字节必须为 `DD 33 BB 11`，word 为 `0x11BB33DD`。

先提交读 R1，随后在 R1 尚未交付时，用 BE=0010 的对齐 word 写将 A+1 改为 `0x77`。当前 word 变为 `0x11BB77DD`；R1 仍返回 `0x11BB33DD`，新读 R2 返回 `0x11BB77DD`。

若初始区域全未知，先执行 BE=0101 写，则 lane 0/2 为 DD/BB，首次整字读只生成 lane 1/3。后续任意合法重叠读必须复用相同字节。

### 7.6 MMIO 严格隔离

GPIO、SPI、UART 的寄存器、FIFO、状态、中断与读清除行为由真实 IP 产生。未知 MMIO、未映射地址、IP 暂无响应均不能走 RAM 首次读取初始化逻辑。Router 只转交真实响应及声明的能力错误。

## 8. 事务生命周期与防重复执行

### 8.1 身份与状态

事务逻辑键为 `(testcase_id, source_component, source_epoch, channel_id, source_sequence)`，运行时再用 execution_id 隔离整个命名空间。命令、回复、去重缓存和 pending 消息都必须携带 execution_id，防止相同 genome 重放时误用上一执行的 receipt。重放比对时才规范化该字段。source_sequence 在真实源握手接受时分配；同内容的第二次真实访问必须得到新序号。

```text
OBSERVED → SOURCE_ACCEPTED → TARGET_QUEUED → TARGET_ACCEPTED
          → TARGET_COMPLETED → RESPONSE_READY → SOURCE_DELIVERED
```

每一步还记录目标 epoch。取消、协议错误、预算终止和副作用未知使用独立终态。`TARGET_COMPLETED` 表示观察到访问完成，不自动证明所有内部功能正确。

### 8.2 去重规则

首次入账时保存规范化载荷 digest，入账发生在目标副作用之前。同键同载荷的运输重发只返回当前状态或已有 receipt，不再执行目标访问；同键不同载荷立即报告 identity_conflict。不能用 payload hash 代替事务键，否则两次合法相同 FIFO pop 会被错误合并。

MMIO 读清除和 FIFO pop 在真实目标执行时产生效果。CPU 尚未收到返回不构成重试理由。MVP 不自动重试不确定事务。

### 8.3 进程故障边界

在运行中的去重保证目标访问至多一次。若模拟器在可能接受请求后崩溃，日志无法确定副作用，结果必须是 `uncertain_effect`。不能宣称跨任意崩溃自动“恰好一次”，也不能重新发请求碰运气。

恢复方式是从可靠初始状态重跑整个 testcase 并比对前缀；首版不支持仅恢复 Python 状态后继续使用丢失的 RTL 状态。

## 9. 持久状态依赖图

### 9.1 静态规则与动态实例

静态 Dependency Graph 描述 DATA_BINDING、EVENT_ORDER、ENV_PRECONDITION、PERSISTENT_STATE_RULE。允许反馈环；AND/OR 依赖用于反向寻找 focus/support source 集合。

动态图记录具体事件、状态版本和读快照。每次循环产生新的节点；边指向已经发生的前因。同一个地址和组件在多个周期反复出现，不应被合并成一个无时间身份的节点。

### 9.2 长期状态边

- RAW：读快照的每个字节指向实际读取的最近 writer/version。一个 word 可同时依赖初始镜像、首次物化和多次不同 Store。
- WAW：新 Store 对覆盖字节记录前 writer 到当前 writer 的版本覆盖关系。
- WAR：记录旧读快照已经捕获后，后续 Store 覆盖相同字节的顺序约束；这是反依赖，不是数据值来源。
- PERSIST：当前 ByteCell 版本保留到覆盖或 generation 重建；读提交时产生的不可变 ReadSnapshot 拥有独立寿命，后续 Store 不切断快照到 CPU 交付的来源链。快照保留关系只在交付或明确取消时结束。
- INVALIDATE：冷复位或明确资源重建终止旧 generation 的可见性；warm reset 保留 RAM 时，旧 epoch writer 仍可成为新读的来源。

GPIO 的配置访问可以作为后续环境动作的观察前提，但不能由 SharedState 假定设备一定工作正常。真实 IP 状态不建立可替代读返回的 shadow register；依赖证据来自实际访问、输出和检查结果。

### 9.3 历史裁剪

首版使用有界完整日志，达到上限结束 testcase。后续可以引入保留当前 writer 与不可变摘要的压缩，但不能删除 pending snapshot 依赖或静默丢失持久值。压缩后的证据必须明确粒度，不能继续声称拥有完整逐事件历史。

## 10. 连续 Scenario Genome

### 10.1 数据结构

```text
ScenarioGenome:
  encoding_version, scenario_id, direction, path_id
  initial_program, initial_memory_material
  source_decisions[]
  actions[]
  schedule_choices[]
  explicit_resets[]
  termination_condition, resource_budget

Action:
  action_id, source_id
  trigger: START / AFTER_EVENT / OBSERVED_PREDICATE
  event_selector, occurrence_selector
  delay: {component_id, local_ticks}
  payload_or_material_ref
  repeat_bound, expiry_policy
```

事件触发默认匹配动作激活之后的新事件；引用历史事件必须指定 event_id 或明确的版本选择器。每动作保存匹配游标与消费集合，旧 IRQ 不能在每个 step 重新触发同一动作。

### 10.2 持续输入与动作

GPIO level、UART frame 和 SPI peer 数据遵守各自持续驱动契约。无新动作时保持契约规定的电平或 idle，不每周期重新随机采样。开始发送的帧、已接受请求和已提交内存不允许被后续 genome 决策追溯覆盖。

逻辑 delay 以指定组件的局部 tick 计量，不以 host chunk 次数、wall time 或其他组件周期计量。所有来源和调度选择由 genome 材料及已记录的真实事实确定。

### 10.3 Chunk 协议

每个 chunk 带 execution/testcase/genome 身份、递增 chunk_id、长度、payload hash 和 final 标记。同 ID 同内容重发无效果；同 ID 不同内容、缺块或乱序明确拒绝。chunk 不能隐式调用 reset_test 或重置 decoder cursor。

首版完整收齐再执行，因此分块只改变运输。若以后支持在线追加，材料缺失时暂停 host 推进、保持全部虚拟局部时间和信号，不把宿主等待时间换成 DUT 周期；该模式须另验收。

## 11. 变异选择与持久状态

保持六类 direction：CPU_TO_IP、IP_TO_CPU、IP_TO_IP、CPU_TO_IP_TO_CPU、IP_TO_CPU_TO_IP、MULTI_COMPONENT_CHAIN。direction 约束主路径、focus source 和操作子，不改所有权。

反向求源包含状态建立动作和后续消费动作。例如目标为第二次 ISR 输出，应回溯当前外部输入、前一次 ISR 的真实 Store、初始累积值和使能配置，而不是只变异最后一个读返回。

CPU 操作子修改程序/初始数据；IP 操作子修改自由环境输入；causal 操作子修改未来合法动作；path 操作子切换已声明路径。状态相关操作子可以插入无关延迟、保留某次 Store 并改变稍后消费者、改变有效 byte-enable、重复状态消费或变异初始材料。它们都通过真实访问修改状态，不能直接覆写 RuntimeState。

读后覆盖、部分覆盖和跨多轮 ISR 的状态链可作为有界语义反馈。事件 ID、地址任意新值和周期数增长不能直接当作新覆盖，避免无意义奖励。

在线 coverage 只影响下一份 genome 的选择与 energy。同一 genome 的 decode、初始化字节和 reset policy 不随历史覆盖变化。

## 12. Dataflow Router 与 Dependency Scheduler

Router 决定“真实值来自哪里、映射到哪里”，维护 transaction_id、地址域、字节 lane、位区段与状态版本。Scheduler 决定“何时允许环境动作发生、推进哪个局部周期、何时交付”。

两者都不能制造 DUT 的 DONE、IRQ、成功读值或预期内部状态。真实输出持续采集；generation constraints 与 checking properties 分开。

提前 IRQ 立即记录并按声明递送，不等待期望 DONE。没有配置时环境可以选择不注入某个场景动作，但已经真实出现的 DUT 请求/输出仍必须保留。对不支持的请求形状，按局部协议返回声明的能力错误或终止该场景，不能悄悄修正 CPU 地址或字节使能。

## 13. 中断的持续状态

首版不用 PLIC。OpenTitan GPIO 的真实 IRQ 电平通过声明的路线交付到 CPU 原生 external IRQ 输入；Router 保留源电平、上升沿事件、递送状态和消费证据。若 CPU harness 只支持脉冲输入，脉冲宽度 N 以 CPU 局部 tick 计量并进入 manifest，且须报告与源电平的映射；不能把持续为高的真实 IRQ 擅自解释成已清除。未受理按实际结果记录，不自动重试。

接收槽保存源 event_id、递送开始点、剩余 tick 和状态；普通 step/chunk 不丢失。首版通过 genome 约束每轮事件间隔，验收连续两个事件。若出现重叠事件，不静默合并：记录全部源事件并按具名 overrun 策略终止或报告不支持，不能据此宣称一般多源中断能力。

OpenTitan GPIO `INTR_STATE` 由真实 RTL 管理，其写 1 清除动作、GPIO IRQ 源电平变化、CPU 输入递送与 CPU 进入/退出 ISR 是不同事实。环境不能因为 CPU 已受理就自动清除真实 GPIO 状态，也不能因为一次读完成就推断没有并发新事件。

## 14. Reset 与结束清理策略

### 14.1 首版策略矩阵

首版支持全场景 warm 与 cold 显式 reset；组件局部 reset 在契约中保留范围字段，但准入时拒绝，直至完成专项验收。

| 资源 | testcase 开始 / cold reset | warm reset |
|---|---|---|
| CPU/IP RTL | 按局部要求 reset；组件 epoch 增加 | 同样 reset；组件 epoch 增加 |
| 环境 RAM | generation 增加；恢复显式镜像；其他字节未知 | 内容、generation、版本、writer 保留 |
| 程序/ROM | 恢复声明初始镜像；只读属性保留 | 内容保留 |
| 未交付响应 | 取消并记录；旧 epoch 结果隔离 | 同样取消；不回滚已提交 RAM 写 |
| pending 外部/IRQ 动作 | 清除并逐项记录原因 | 清除并逐项记录原因 |
| 调度/条件游标 | 建立新 epoch 游标，按显式 reset 后动作继续 | 同样处理；不从 action 0 重播全部前缀 |
| 历史日志/coverage | testcase 内保留并分 epoch 标记 | testcase 内保留并分 epoch 标记 |

### 14.2 Reset barrier

停止接受新根动作，标记复位范围，采集复位前最后可靠握手和已知提交。取消旧响应不撤销已发生副作用。可能已执行但缺证据的事务标记 uncertain_effect。按策略 reset RTL、处理资源、增加 epoch，完成本地释放后才运行显式的 reset 后动作。

冷复位清除 RAM 是明确资源操作，而不是取消事务时的回滚。warm reset 后旧 Store 仍是后续 Load 的合法来源。真实 IP 被 reset 后的变化由真实 reset 行为产生；host 不修补内部状态。

### 14.3 Testcase 之间隔离

新 genome 不得从上一 testcase 的最终状态继续。首版所有独立 testcase 从声明初态开始。持久进程复用必须通过隔离验收。首版 checkpoint 仅保存 host 摘要用于核对，不支持从该摘要恢复真实 RTL；完整重放从初态重新运行。

## 15. 完整状态演化重放

### 15.1 保存材料

保存 RTL/source/tool/harness 身份、genome bytes、decoder 与初始化算法版本、CPU 实际镜像、初始资源清单、绑定图、reset policy、全部随机材料、首次读物化字节、实际动作选择、逐组件局部步进、事务提交/快照/交付、IRQ 区间和状态版本。

日志每条含 testcase 逻辑身份、event_seq、组件 epoch/tick、事务或动作 ID、原始 payload、父事件、前后状态摘要。完整事件日志追加写入；周期性摘要用于定位，不替代原始记录。

### 15.2 两种重放用途

完整闭环重放从初态启动全部真实 RTL，按保存的输入与调度执行，重新采集实际输出并逐条比较。录制输出只能作为期望，不能灌入 Router 替代本次真实输出。

固定录制输入的下游独立重放仅用于归因对照，必须标为 isolated replay，不计作完整跨组件因果重现。

### 15.3 比较与首个分歧

比较物化字节、真实源握手、目标完成、读快照、交付数据、持久版本、IRQ 与 CPU 响应，以及最终摘要。首先报告第一个语义分歧的字段、组件局部周期、事务/事件和相关 writer 链。coverage 相同而中间 Store 丢失仍必须失败。

若源/规则/固件身份不一致，在执行前拒绝。若重新执行的输出不同，报告差异而不是强迫其使用原轨迹结果。分块元数据和宿主时间不参与语义相等比较。

## 16. 双 GPIO 连续场景

### 16.1 固定绑定

CPU 使用一个独立 Ibex harness，GPIO A/B 各用一个独立 OpenTitan GPIO RTL + TL-UL 局部协议 harness。A.out[7:0] 固定绑定 B.in[7:0]；B.in[15:8] 为自由外部输入；A.out[15:8] 为结果观察出口，不回接 B。其他输入显式固定。B 的绑定区段不能由 Fuzzer 再随机覆盖。

每输入 bank 使用七位 payload 与一位 strobe。B[7] 与 B[15] 在 OpenTitan GPIO 的 `INTR_ENABLE`、`INTR_CTRL_EN_RISING` 中配置上升沿。A 的 `DIRECT_OUT` 和 `DIRECT_OE`、B 的 `DATA_IN` 和 `INTR_STATE` 均按 OpenTitan 固定源码寄存器语义访问。配置动作由 CPU 真实程序完成，不能由场景编译器直接写入 GPIO 寄存器；仅局部 harness 的协议验收可使用定向 MMIO 驱动。

### 16.2 CPU→IP→CPU 多轮

CPU 配置一次 A/B 和中断入口；计算 x1 并真实写 A 低 bank；A 的真实输出影响 B；B IRQ 递送 CPU；ISR 读取 B 的真实 `DATA_IN`/`INTR_STATE`，按 OpenTitan 的写 1 清除语义确认该中断，并把结果 Store 到环境 RAM。经过多个局部周期后，CPU 拉低 strobe 再产生 x2，重复第二轮；两轮之间不 reset、不重新灌镜像。

第二轮验收同时检查第一轮保存的 RAM 数据仍可读、GPIO 配置仍持续、IRQ 状态按真实访问更新。strobe 回落与同步等待是连续运行的一部分，不能靠 reset 准备下一轮。

### 16.3 IP→CPU→IP 与累积状态

初始化 RAM 中 `S=5`。环境在 B 高 bank 连续提供 x1=3、x2=9 两次合法事件；ISR 每次真实读取 B 的数据，再读取 S、计算 `S=(S+x) mod 2^32`、Store 回 RAM 并真实写 A 高 bank。

期望两轮累积值为 8 和 17；A 的结果 payload 应对应 8、17，且后续 CPU Load S 为 17。这样能区分持续状态与两次分别从 5 开始的孤立测试。值来自实际 GPIO 响应；独立 checker 只计算期望，不驱动结果。

### 16.4 首版与后续能力

首版支持 OpenTitan GPIO TL-UL 的合法寄存器访问、32 位环境 RAM 的 byte-enable、有限 RV32 程序模板变异、两个连续事件、单源 IRQ 递送和固定公平调度。CPU load/store 子字节行为通过受支持的原生接口映射验证；不以 RAM 的 byte-enable 能力推断所有 GPIO 寄存器都允许任意部分写。

后续仅从 OpenTitan 系列加入 SPI/UART 等异构 IP、更多状态消费轮次、程序插删、并发事件和多源组合。每项均需新的明确准入与证据。

## 17. 反馈、失败分类与研究边界

分别反馈组件 RTL 覆盖、真实依赖前缀、长期状态消费、检查器评估/失败、执行成本。`input_invalid`、`dut_violation_candidate`、`environment_failure`、`path_incomplete`、`budget_exhausted`、`uncertain_effect` 与 `replay_mismatch` 独立记录。

合法输入触发 DUT 违例必须保存，即使没有新覆盖。状态模型错误、Router 串配和局部 driver 违例属于测试系统问题。超时本身不能证明 DUT 死锁。源码导出的行为 probe 与独立规范 checker 在报告中分别标注。

研究对照使用同一 RTL/harness/预算下的均匀 source 变异与依赖引导变异；另外设置独立驱动、切边和固定下游输入对照。故障注入用于校准检查能力，不计为真实组件 bug。

## 18. 必须保持的设计不变量

- LIFE-01：step、chunk、事务完成、ISR 返回不产生隐式 reset。
- MEM-INV-01：同一 memory_id/generation/address 只有一个权威字节。
- MEM-INV-02：BE=0 的字节及其初始化、版本、writer 不变。
- MEM-INV-03：已初始化字节仅由已提交写或显式资源策略改变。
- MEM-INV-04：读快照建立后至交付/取消保持不变。
- TX-INV-01：同键同载荷运输不重复目标副作用；同键异载荷拒绝。
- TX-INV-02：不同真实握手即使内容相同也不得合并。
- DEP-INV-01：每个读取字节引用实际消费版本，长期依赖不因 chunk 丢失。
- RST-INV-01：epoch 变化不隐式改变 memory_generation。
- REP-INV-01：完整 replay 重新执行真实 RTL，不用录制输出替代本次观察。
- OWN-INV-01：direction 和持久状态消费均不能把 Bound Input 重新变成随机输入。

配套实施文档为这些不变量提供验收 ID、具体刺激、判定、证据及反例校准。设计完成与系统实现完成必须分开报告。
