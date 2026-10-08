# RFuzz 依赖路径与运行时路由一致性校验设计

日期：2026-10-05  
状态：设计草案，待用户审阅  
范围：RFuzz testcase 启动前的依赖路径、真实绑定和 MMIO 路由一致性校验

## 1. 目标

RFuzz 当前可以依赖 `DependencyGraph` 选择目标、传播路径和 Fuzzable Source，也可以通过 `ScenarioRunner` 验证实际 Binding 的输入所有权、位范围，以及 Router 中已声明的 MMIO window 是否指向已注册的真实 harness。但 RFuzz 还没有在运行候选 testcase 前，检查所选依赖路径要求的跨组件连接是否真的存在于该 Runner。

本设计增加一个只读的 **Runtime Dependency Preflight**：在所选 Genome 开始执行前，对照所选依赖路径与该候选使用的 `ScenarioRunner` 拓扑。校验失败时不启动 testcase、不推进 RTL、不运行 DUT checker，也不产生 DUT coverage；将其报告为环境配置错误。

核心规则：

> 依赖图说明哪些关系应当存在；Runner 的 Binding 和 Router 说明本次运行实际配置了哪些关系。两者不一致时，先拒绝运行，不能靠 Scheduler 补线或靠随机输入掩盖差异。

## 2. 保留的边界

- CPU/IP 仍运行在各自独立的真实 RTL harness 中。
- 本工作不生成 SoC，不加入 Bus、Crossbar、Bridge、Arbiter、PLIC，也不增加全局 cycle-accurate 时序。
- Fuzzable Source、Bound Input、Dependency Path、Dataflow Router、Dependency Scheduler 和 testcase 内持久状态的既有职责不变。
- Router 继续转送实际交易和真实 RTL 输出；Preflight 只校验配置，不生成数据、IRQ、完成状态或读响应。
- Scheduler 仍只决定下一步何时允许生成或递送输入；真实 RTL 输出即使违反预期因果顺序，也必须保留给 checker。

## 3. 校验对象与匹配规则

Preflight 接收：

1. 已信任的 `DependencyGraph`；
2. 解码后 Genome 的 target、direction 和 path；
3. 本次新建但尚未 `begin_case` 的 `ScenarioRunner`；
4. 与 RFuzz target/path 一起登记的 `RuntimePathContract`，说明选中路径上的跨组件依赖通过真实 Binding、MMIO Router、纯因果顺序或持久状态关系中的哪一种成立。不能通过组件名或端口字符串猜测传输类型。

`DependencyPath` 目前只保存 target 与 source IDs，无法区分“source 相同但中间 Rule 不同”的两条路径。为使本校验精确，路径解析必须同时返回被选中的 Rule-edge identity（Rule 在 graph 中的稳定索引及 prerequisite 索引）；`path_id` 与 Genome/decoder identity 纳入这些 edge identity。不能为了预检而把同源的 OR 路径合并。

### 3.1 只检查本次所选路径

由 `target + direction + path_id` 解析出唯一的 `DependencyPath`。仅取该路径中参与传播的 DependencyRule，不因图中其他未选分支而拒绝该 testcase。若路径不存在、`path_id` 不属于当前 graph，或解析结果不唯一，按环境配置错误拒绝。

Rule 的 `prerequisites` 到 `target` 保持现有含义：同一 Rule 的先决节点共同构成 AND 依赖；同一 target 的多个 Rule 是 OR 路径选择。Preflight 不改变路径语义。

跨组件 edge 定义为：prerequisite 与 target 各自归属于不同的已注册 component。FuzzableSource 节点使用 source profile 的 component 字段；其他 component-scoped graph 节点使用 `<component_id>.<node>` 命名约定。component ID 后第一个点之后的完整余串是 port/node 名，允许其自身再包含点。若路径节点无法唯一归属，且该 edge 声称跨组件传输，则拒绝而不是猜测。

`RuntimePathContract` 按所选 graph rule 与 prerequisite edge identity 记录一种关系类型及该关系所需的端点或资源：

| 关系类型 | 校验方式 |
|---|---|
| `direct_binding` | 对照一个真实 `ScenarioRunner.Binding` |
| `mmio_route` | 对照一个 initiator Router 到真实 IP session 的 `DeviceWindow` |
| `causal_order` | 声明该 edge 是 Scheduler 的逻辑先后关系，不代表物理线；仅适用于 `EVENT_ORDER`，实际因果仍看 trace/checker |
| `persistent_state` | 声明该 edge 由现有持久状态机制表达；本 Preflight 不验证数据版本关系，仍由既有状态依赖与运行时证据负责 |

选中路径上所有跨组件 edge 必须有且仅有一个合约。`DATA_BINDING` 只能分类为 `direct_binding` 或 `mmio_route`；`PERSISTENT_STATE_RULE` 可分类为 `mmio_route` 或 `persistent_state`；`EVENT_ORDER` 可分类为 `direct_binding`、`mmio_route` 或 `causal_order`。不允许类型与 Rule kind 不相容，也不允许重复/遗漏合约。`ENV_PRECONDITION` 与 `BASELINE_GROUPING` 不作为跨组件传输 edge。

### 3.2 跨组件直接绑定

对合约类型 `direct_binding`，合约中的 source/target 端点必须与其所引用 Rule edge 的 prerequisite/target 节点完全一致，并且两者必须是具体端口端点。Runner 必须恰有一个匹配 Binding：

```text
prerequisite component.port
  == Binding.source_component.source_port
target component.port
  == Binding.target_component.target_port
```

零个匹配代表图要求的跨组件关系没有接入；多个匹配代表运行拓扑不唯一；两种情况都拒绝。端点 component 不在 Runner 中也拒绝。纯逻辑状态、持久状态和事件标记不是物理 Binding，不能标为 `direct_binding`，也不得仅凭字符串相似度推断为 Binding。

`ScenarioRunner` 现有的 ownership / binding 校验仍负责确认目标输入由正确 producer 拥有，并检查实际 Binding 的 bit offset 与 width 不越界。当前 `DependencyRule` 不包含 bit offset/width，因此本阶段只比对端点，不声称证明了依赖边自身的位段精确相等，也不添加虚构的位段精度。

### 3.3 Router / MMIO 目标

对合约类型 `mmio_route`，必须显式登记 `(initiator_component, device_id)`，不从 `DependencyGraph` 节点名猜测 MMIO 拓扑。逻辑数据依赖箭头可以与 MMIO 请求方向相反；`initiator_component` 表示发出真实寄存器读写的 harness，`device_id` 表示 Router 实际调用的目标 IP。对每个期望项：

- `initiator_component` 必须是 Runner 中带 Router 的 session；
- 该 Router 必须恰有一个 `DeviceWindow` 使用指定 `device_id`；
- 该 window 的 `target` 必须是 `runner.sessions[device_id]` 的同一个 session 实例；
- 目标 component 必须属于所选依赖路径涉及的组件，且该 MMIO 合约必须引用当前检查的 graph edge。

缺失、重复、目标 session 不一致或目标不在路径中时，拒绝该 testcase。Runner 对 Router 中其他已声明 window 的既有检查继续生效。

## 4. 执行与错误处理

RFuzz 对每个新候选按如下顺序执行：

```text
解码 genome / 选择 target 与 path
        ↓
创建 fresh ScenarioRunner（不调用 begin_case）
        ↓
Runtime Dependency Preflight
   ┌────┴─────┐
  通过       失败
   ↓           ↓
正常 record  environment_error
scenario     coverage 全零；不 begin、不 step、不调用 checker
```

失败诊断至少包含 testcase slot、target、direction、path ID、失败 Rule 或路由期望、期望端点、实际匹配数量/目标。其状态不得标成 `dut_violation`、`uncertain_effect` 或覆盖命中。当前进程内相同 Runner topology identity 与相同校验输入可以缓存通过结果；不能跨不同 manifest、Binding、Router window、graph 或路径复用缓存。

Mismatch 是静态环境/配置错误。首个候选发现后应将错误显式保留并停止将该配置下后续候选送入 RTL；修正 topology 或 profile 后再启动 campaign。不能为了继续搜索而跳过该约束。

## 5. Replay 和证据

- Preflight 版本、DependencyGraph 身份、包含 edge identity 的 target/path 选择以及完整 RuntimePathContract 需进入 RFuzz 配置/证据身份。
- Fresh replay 必须用同一 graph、路径解析规则、RuntimePathContract 和 Runner manifest 重新执行 Preflight；任何身份变化在 RTL 启动前拒绝。
- 路径 edge identity 改变 RFuzz decoder 的路径选择身份；需递增 decoder/schema 版本。旧 corpus 不能静默按新 path ID 解释，应保留旧版 replay 解码或明确标记为旧版不可搜索。
- Preflight 通过只证明图与声明拓扑相符，不证明传播值正确，也不证明 RTL 满足功能预期。真实输入/输出、事务、事件顺序及最终状态仍由 trace、checker 和 replay 验证。
- 对既有 `record_scenario` 通用 API 的改动应保持可选；非 RFuzz 场景继续原行为。RFuzz 必须显式传入该校验，避免遗漏。

## 6. 验收标准

1. Ibex + 双 PULP GPIO RFuzz 所选真实路径通过 Preflight；现有实际 Binding 与 CPU Router windows 能逐项对应。
2. 删除 GPIO A → GPIO B 或 GPIO B IRQ → CPU IRQ Binding 后，对应路径在 `begin_case` 和任一 RTL step 前失败，状态为环境错误，checker 未调用，coverage 全零。
3. 将 Binding source/target 端点改错、增加歧义匹配或令 ownership producer 不符时，按环境错误拒绝；不得放宽 Bound Input，也不得随机填值。
4. 删除所选 CPU Router 的 GPIO MMIO window，或令其目标对象不是 Runner 注册的同一 GPIO session 时，在 RTL 启动前拒绝。
5. 非所选的 OR 分支缺少绑定，不影响当前候选；选择到该分支时必须拒绝。即使两条 OR 分支的 source IDs 相同，也必须由不同 path/edge identity 选择，不能合并或误校验另一条分支。
6. Preflight 通过后，既有真实 RTL 端到端候选仍通过，并能从初态 fresh replay；真实 GPIO 输出、IRQ 和 CPU 响应来源保持可追溯。
7. 对故障注入得到的提前/错误 IRQ，Preflight 不过滤、不修正；执行后仍由独立 checker 根据真实 trace 报告。
8. 自动单元验收覆盖路径筛选、精确/缺失/重复 Binding、路由缺失/错对象、错误分类、未启动 harness、checker 未调用及 coverage 为零；真实 RTL 验收覆盖有效路径与 fresh replay。

## 7. 明确不做与风险

- 不证明 DependencyGraph 完整描述了所有硬件行为，也不从 graph 自动推断遗漏的边。
- 不验证跨组件数据值的 bit-level 变换；`DependencyRule` 当前没有 edge-level 位段 schema。
- 本 Preflight 不自行证明 `causal_order` 与 `persistent_state` 的真实语义；它只确保这些跨组件 edge 有明确类型，实际事件顺序和持久读写版本由 Scheduler、StateDependencyTracker、trace 与 checker 负责。
- 不证明合法配置下真实 RTL 按预期工作；这是 trace/checker/replay 的责任。
- 不用 dependency 期望覆盖异常 RTL 输出，不把配置错误记成 DUT bug。
- RuntimePathContract 必须由场景/target 配置明确提供；省略跨组件 edge 的关系分类会使 Preflight 无法发现缺线或缺 window，因此路径上有未分类跨组件 edge 时应拒绝搜索。
- Preflight 创建 Runner 可能带来 session 构造成本；其检查必须发生在 `begin_case`/RTL step 前，并可基于完整 topology identity 安全缓存，不能复用已运行的 DUT 状态来省成本。


## 2026-10-06 实施细化：显式节点与版本兼容

当前总计划已授权实施 P2。入口审计发现现有图包含 `online.*`、`pin0`、`irq_from_*` 等逻辑别名，不能按首个点猜 component 或端口。因此实施使用显式受信 `RuntimeNode` 声明 node_id/component/kind；physical 节点声明具体 port/bit_offset/width，logical/state 节点不伪装物理线。此声明优先于第 3 节旧命名约定，遗漏所选节点时拒绝。direct_binding 只匹配 physical endpoint，并比较声明位段与实际 Binding；逻辑事件用明确的 EVENT_ORDER/causal_order，持久状态关系必须声明资源。MMIO 明确 initiator/device/base/size，并核对目标 session 对象。

新增 edge-aware proof-DAG：规则使用构造时的全局有序 index，每个 prerequisite 有独立 index。同一 node 在单条路径中选择一个一致 OR rule，AND 保留全部 prerequisite，共享子图只保存一次 edge。同源 OR 路径按不同 edges 保留；path 身份绑定版本化完整 graph、方向、目标、来源和 edges。`edge_paths_to` 与 `path_identity` 提供此语义；旧 `paths_to` 继续保留 decoder v1/v2 的 source-set 映射。新搜索入口将使用新 decoder schema 与初始化编译的路径表，旧 corpus 不能按新序号重解释。

静态 compiler 只读取实际 Runner 的 sessions/bindings/ownership/router，不调用 identity_document、factory、begin、step 或 checker。仅校验选中路径，未选 OR 分支不阻止当前输入。编译结果绑定 graph/contract/topology；后续 admission 检查相关对象和 tuple 是否仍与冻结拓扑一致，不扫描源码/工具链。全局冻结和当前资源前置状态在接入阶段完成；compiler 成功不证明真实传播或状态版本正确。

在线 fixed runtime 必须在 session.begin 和 warmup 前调用 compiler；fresh 在既有单次 factory 创建后、begin 前调用可选 preflight。运行后的提前 IRQ 保留给独立 checker，preflight 不能过滤真实异常。P2 仍需接入新 decoder 身份、两方向真实逐边交付/消费及负例、fresh replay，并非新增静态模块即可完成。
