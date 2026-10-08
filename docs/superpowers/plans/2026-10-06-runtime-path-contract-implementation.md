# P2 Runtime Path Contract 实施计划

> 执行当前已授权总计划 P2；按独立文件并行实现，遵守 TDD 和完成前验证。工作区原有修改保留，不暂存、不提交。

**Goal:** 将选中依赖路径绑定实际 Runner 的端点、MMIO 路由与持久资源声明，在 RTL begin 前拒绝拓扑不一致，并保留旧 corpus 映射。

**Architecture:** edge-aware proof-DAG 与静态 contract compiler 分离。新 decoder 初始化编译路径表，运行接入只使用已编译路径和当前资源事实。Router 与 checker 继续处理真实输出。

**Tech Stack:** Python dataclasses、现有 ScenarioRunner/OwnershipMap/DataflowRouter、unittest、真实 Ibex/PULP RTL 与 fresh replay。

## 全局约束

- 不从逻辑 node 名称猜接线；受信声明填写 component/physical endpoint/位段。
- 不调用额外 factory，不扫描每例源码/工具链，不逐例重新编译图。
- 旧 decoder v1/v2 保留旧 paths_to 映射；新 path schema 不与旧 raw corpus 静默互认。
- 所选路径缺少/重复/错误连接报 environment_error，RTL 不推进、checker不调用、coverage 为零。
- 静态预检不证明传播、IRQ taken 或 CPU/IP 内部覆盖；异常真实 IRQ 原样保留。
- F6 可声明类别，DMA master 的真实运行仍归 P8。

## Task 1：有边身份的依赖路径

**Files:** dependency.py；新增 tests/scenario/test_dependency_edge_paths.py。

**Interfaces:**

```python
@dataclass(frozen=True)
class DependencyEdge:
    rule_index: int
    prerequisite_index: int
    prerequisite: str
    target: str
    kind: str

# DependencyPath 保留 target/source_ids，新增 edges=()。
graph.edge_paths_to(target, direction=direction, max_depth=16, max_paths=64)
graph.edge_document()
graph.path_identity(path, direction=direction)
```

- [x] 写同源 OR 负例：旧 paths_to 为一条，新 edge_paths_to 为两条，path identity 不同。
- [x] 运行新测试看到缺 API/OR 合并的 RED。
- [x] 保存构造时全局 rule 顺序，版本化 graph document；有界展开 AND/OR，单路径共享 node 的 OR 选择一致。
- [x] path identity 验证选中边属于 graph、AND完整、root可达、source方向一致、无选中循环。
- [x] 检查共享子图、重复 prerequisite、循环、深度/路径/work上限、跨序列化顺序、伪造路径及旧 mutation/decoder 回归。

运行：

```bash
PYTHONPATH=src python3 -m unittest tests.scenario.test_dependency_edge_paths tests.scenario.test_dependency_mutation tests.scenario.test_rfuzz_genome_decoder -v
```

## Task 2：显式运行时路径契约与静态 compiler

**Files:** 新增 src/myfuzz/scenario/runtime_path_contract.py；tests/scenario/test_runtime_path_contract.py。

**Interfaces:**

```python
RuntimeNode(node_id, component, kind, port=None, bit_offset=0, width=None)
RuntimeEdgeContract(rule_index, prerequisite_index, relation,
                    initiator_component=None, device_id=None, base=None,
                    size=None, resource_component=None, resource_id=None)
RuntimePathContract(graph_sha256, nodes=tuple(), edges=tuple())
compile_runtime_path_contract(graph, contract, runner,
                              paths=tuple[(direction, path), ...])
# 编译结果 document()/identity_sha256/topology_sha256/path_ids
# 及 validate_topology()；contract document/from_document 严格版本往返。
```

physical node 必须有 port/width；logical/state 不带虚构端口。persistent_state 只引用实际 session.memory 声明的 memory_id，不把寄存器标签当 RAM。相邻任务使用上述版本化文档和 compiled.validate_topology。

```python
paths = graph.edge_paths_to(target, direction="CPU_TO_IP")
compiled = compile_runtime_path_contract(
    graph, contract, runner, paths=(("CPU_TO_IP", paths[0]),))
compiled.validate_topology()  # 不 begin、不 step、不 checker、不 source scan
```

- [x] 新测试先 RED：明确 physical alias 正确匹配；删 Binding、改 producer、重复匹配拒绝；未选 OR 缺连接允许。
- [x] 编译所选跨组件 edge 的唯一契约，拒绝未知 node/edge、错误 relation/rule kind、graph digest漂移；ENV/BASELINE不作为传输。
- [x] direct 比较 endpoint/位段/ownership producer；MMIO比较唯一window、base/size、initiator与实际注册session对象。
- [x] causal仅EVENT_ORDER；persistent必须引用真实声明资源，声明不作为运行时版本正确证明。
- [x] 冻结轻量拓扑，validate_topology 拒绝相关session/Binding/router/ownership替换，不查询工具链或RTL源码。
- [x] 负例覆盖所有拒绝类型、contract序列化、selected-only branch、无启动/checker、热路径无graph编译与身份扫描。

运行：

```bash
PYTHONPATH=src python3 -m unittest tests.scenario.test_runtime_path_contract -v
```

## Task 3：新 decoder 与执行/replay 接入

**Files:** rfuzz_decoder.py、online_case_decoder.py、replay.py、scenario_rfuzz.py、session_runtime.py、Ibex/PULP factory与online runtime；相应测试。

- [x] 新schema保存有序graph/RuntimePathContract及edge-aware选择；初始化预编译路径表，legacy document保留原mapping且禁止误用为新搜索。
- [x] 通用 fresh record/replay 已提供可选 `runner_preflight`，在单次 factory 创建实际 Runner 后、源码身份扫描/begin 前调用；新 4 项 RED→GREEN，与 replay/fresh身份/异常终结合计 32 项通过。
- [x] RFuzz 显式传入并绑定 RuntimePathContract；online 在 begin/warmup 前编译，逐例接纳前检查所选路径/拓扑/相关资源事实。
- [x] mismatch固定environment_error、zero coverage、无checker；finding与uncertain_effect保留原分类。
- [x] 将graph/contract/path/compiled topology纳入run identity与replay，比对在begin前完成。
- [x] 真实PULP正反两方向声明实际gpio_out→gpio_in、irq→irq和CPU MMIO windows；不凭逻辑别名作假Binding。
- [x] 测实际begin_test无调用、没有额外factory/source scan/graph编译；改edge identity replay拒绝。

## Task 4：逐边真实证据与完整验收

**Files:** Runner/feedback/trace相关模块、tests/integration、报告与总计划。

- [ ] delivery/consume关联path/edge、origin source/case、transaction和资源版本；后例观察保留前例来源。
- [ ] 当前真实Ibex/PULP两个方向完整record/replay，切断A→B及IRQ在RTL前定位，提前IRQ仍可见。
- [ ] 明确静态契约、运行时消费/因果、coverage各自验证范围；P2全项齐备才更新完成状态。
- [ ] 更新总计划、能力表、报告索引和progress，执行git diff --check及文档链接核对。

Task 1/2可按独立文件并行；Task 3/4依赖其接口，依次集成。所有测试退出码和实际计数进入对应报告；不能用软件contract检查替代真实RTL。

## 2026-10-06 基础接口验证

Task1/Task2 与通用 fresh hook 已落地并经独立review；root整合回归275项、5环境门禁跳过，零失败（6.204秒），三个新模块34项零失败。位段disjoint/overlap、MMIO对象身份、实际RAM lookup漂移及physical input范围负例已验证。这里的完成只针对基础接口；Task3 RFuzz显式接入、新decoder schema、执行身份与replay接入、Task4真实逐边来源和RTL门禁仍未完成。详见[进度报告](../../reports/current-dataflow-p2-path-contract-20261006.md)。

## 2026-10-06 Task3 接续整合与审查

Task3 已完成上述声明、接纳和身份接口范围。Genome decoder v3/online decoder v2 缓存有边路径；fresh、live、continuous、online 显式使用契约；legacy 保留旧映射并标记 unchecked。非 replay 会话存在外部源时，configure 必须传入受信 source_ownership，实际 producer_ref 在 begin/warmup 前核对；begin 再检查冻结拓扑。通用 executor 对所有缓存路径的源核对，文档重建 decoder 不获搜索授权。RTL 命令回执丢失保留 uncertain_effect，typed 协议环境错误保留 environment_error。

修复均有 RED→GREEN 负例，独立审查 spec/quality 通过。root 整合 317 项、5 项环境跳过、零失败（25.649秒）；实际 Rust 运输检查16项全过（1.578秒）。当前源 GPIO 真实会话120例 complete，CPU 指令源16例、IP pin源104例，完整前缀 fresh replay匹配。此处不证明逐边原始 source/case 归属或资源版本，compiled 的 runtime_causality_verified 仍为 false；Task4 保持未完成。详细记录见[阶段报告](../../reports/current-dataflow-p2-path-contract-20261006.md)。

## Task4 来源基础设施接续（部分完成）

SourceAdmission/Registry、RuntimeEdgeIndex、append前深分离事件元数据、typed RAM writer快照、schema10/11 pre-factory来源重建和feedback见证引用已落地，见[来源实施](2026-10-06-source-provenance-task4.md)与[验收报告](../../reports/current-dataflow-p2-source-provenance-20261006.md)。397项整合、5环境跳过、零失败；当前源GPIO120/UART2完整replay通过。STORE同名action碰撞已用真实冻结writer_kind拒绝；来源未知的MMIO/IRQ不贴当前case或最近fetch。原Task4复选框仍不勾选：退休/外设FIFO因果来源未贯通，尚不能证明完整闭环或逐边资源因果。
