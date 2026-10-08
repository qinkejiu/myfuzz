# P2 剩余缺口：追加 `persistent_state` 边（RAM 字节版本 / GPIO 寄存器位版本）

日期：2026-10-07。上一份报告（[通用逐边来源](current-dataflow-p2-edge-provenance-20261007.md)）把 P2 的剩余缺口写成"契约未声明任何 `persistent_state` 关系，`memory_read.writer_event_ids` 全是字符串占位"。本轮把该缺口**声明出来并实测**：

* Ibex + 双 PULP GPIO 的在线契约**追加**两条 `persistent_state` 声明（rule 15/16），既有 9 条边逐字段不变、既有路径选择集不变；
* `edge_provenance.py` 追加 strict 判定：写侧必须给出精确版本（`version`/`generation`/`byte_offset`/`byte_enable`/`width_bytes`，commit 记录再要 `commit_id`+`commit_document`），读侧必须**逐字段引用同一版本**；
* 两条真实 run（p4-shift 118,963 事件；p5-paired 31,795 事件）流式复算：**两类新边都 certified**（extended 11 条边 10 certified / 1 incomplete / 0 unknown；唯一 incomplete 仍是既有的 `gpio_a.gpio_out→gpio_b.gpio_in` 绑定）；
* RAM 边的证书由**写侧事务键 + 精确版本**连接（读侧 `writer_event_ids` 依旧不含整数事件 id：p4 734 条读、0 个整数引用）；寄存器边的证书由 `gpio_register_commit.bit_resources[].version`+`observation_event_id` 与后续 `gpio_register_read` 同名位行**全等**连接；
* **未运行任何真实 RTL / 在线 fuzz**：全部统计来自既有保存 trace 的流式复算。

## 交付物

| 文件 | 内容 |
|---|---|
| `src/myfuzz/scenario/ibex_pulp_dual_source.py`（追加） | rule 15/16 两条 `persistent_state` 声明 + 两个声明节点 + 资源坐标常量；既有行、既有字段、既有路径枚举不变 |
| `src/myfuzz/scenario/edge_provenance.py`（追加/收紧 `persistent_state`） | 严格版本引用判定（memory 版 + register 版）、有界写记录历史、`candidate_resolver` 只增不改的候选钩子、`persistent_state` 报告块；`mmio_route`/`direct_binding` 判定未改动 |
| `src/myfuzz/scenario/persistent_state_provenance.py`（新增） | 把"追加声明"与"追加前的 run"显式、可校验地连接起来（声明前缀校验 + 端点解析 + 事件归因），单次流式同时产出 run 自身报告与扩展报告 |
| `scripts/persistent_state_provenance_report.py`（新增） | 只读保存 trace 的实测驱动（`--run DIR [--run DIR] --out FILE`） |
| `tests/scenario/test_persistent_state_edges.py`（新增，32 tests） | 声明/路径回归、合成 certified 正例与 6 类负例、真实 trace 钉住、有界性 |

## 1. 追加声明（逐条）

| rule | kind | relation | prerequisite → target | resource |
|---:|---|---|---|---|
| 15 | `PERSISTENT_STATE_RULE` | `persistent_state` | `cpu.online_instruction` → `online.cpu.persistent_ram_byte` | `cpu` / `ram` |
| 16 | `PERSISTENT_STATE_RULE` | `persistent_state` | `online.gpio_a.isr_padout` → `online.gpio_a.persistent_register_bit` | `gpio_a` / `out` |

资源坐标不是自造的，全部取自**真实事件字段**：

* `memory_write`/`memory_read` 的 `component="cpu"`、`memory_id="ram"`（host `PersistentMemory` 区域名，`PersistentMemory.memory_ids`）；
* `gpio_register_commit`/`gpio_register_read` 的 `component="gpio_a"`、`register="out"`（PADOUT，`scenario/gpio_consumption.py` 的 `_WRITE[12]=('out','overwrite')`）。

追加不改动既有交付（逐条实测，见 `test_appended_rows_leave_every_legacy_rule_and_edge_byte_identical`）：

* `recorded_graph.sources` 与当前图完全相同；当前图的 `rules`/`edges` 前 15/15 行与冻结 run 的记录**逐字段相等**（追加行位于最后）；
* 既有 9 条 `RuntimeEdgeContract` 与冻结 run manifest 里的声明逐字段相等（key 0/2/4/5/6/10/11/12/13）；
* 两条声明路径（`cpu_to_ip_to_cpu.closed_loop`、`ip_to_cpu_to_ip.closed_loop`）选中的 edge 集合恰为 rule 0..14，**不含** 15/16（`test_appended_edges_are_off_every_declared_path`）。因此新边不会被任何声明路径选中：既有的 driver 行为、路径枚举与端点解析不变（`path_id` 是整图摘要的函数，追加声明后新 run 的 `path_id` 必然变化——这是声明变更的必然结果，报告如实记录，既有 run 的 manifest 不受影响）。

## 2. 判定条件（逐条）

`persistent_state` 的 hop 仍是 `producer`（写记录）、`delivery`（同一记录的版本，`shared_event`）、`consumer`（后续读取）。

**certified（memory 版）** 需要同时成立：

1. 写侧 kind ∈ {`memory_write`, `memory_write_commit`, `memory_initialization`}，`component`/`memory_id` 等于声明资源；`generation` 为非负整数；`version` 为 `[generation, commit_sequence]` 且 `commit_sequence != 0` 且 `version[0] == generation`；`byte_offset`/`width_bytes` 为非负整数且 `width_bytes ≥ 1`；`byte_enable` 非零且不超出 `width_bytes`；`producer_event_id` 为已观测记录 id。`memory_write_commit` 额外要求 `commit_id` 非空且 `commit_document` 的 `memory_id`/`generation`/`byte_offset`/`width_bytes`/`byte_enable`/`version`/`commit_status` 与该记录一致；
2. 读侧是后续的 `memory_read`（`event_id > 写记录`），`component`/`memory_id` 相等，`generation` 等于写侧 `generation`，`versions`/`writer_event_ids`/`writer_kinds` 三者与 `width_bytes` **等长**；
3. 读窗口的**每一个字节**都落在该写记录的 `byte_enable` 覆盖范围内，且该字节的 `versions[lane]` 等于写侧 `version`；
4. 该字节的 `writer_event_ids[lane]` 必须**解析到这条写记录本身**，形式仅限三种精确键：该写事件自身的整数 `event_id`、该写记录自身 `transaction` 六字段的规范 `TransactionKey(...)` 串（host commit 写入字节的 writer 标识）、该写记录自身声明的 `writer_event_id` 串；`writer_kinds[lane]` 必须是非空的非 `INITIAL_IMAGE` 种类；
5. `initial-image` 之类的**占位串**解析不到任何写记录 → 不 certified（计入 `missing_fields`），也不会因为"四个字节的版本都等于写版本"而放行。

**certified（register 版）** 需要同时成立：

1. 写侧是 `gpio_register_commit`（`status="observed"`），`component`/`register` 等于声明资源，且 `bit_resources[]` 中至少一位给出整数 `bit`、整数 `version ≥ 1`、整数 `observation_event_id`（指向**已观测**的更早事件，且 `< commit event_id`）；缺任一字段的位行不构成证据；
2. 读侧是后续的 `gpio_register_read`/`gpio_target_receipt`（`event_id > commit event_id`，`status` 为 `observed`），在其 `bit_resources[]`/`post_bit_resources[]`（以及这两者内部嵌套的 `dependencies[]`/`origin_refs[]`，或平铺的同名字段）中，存在一行与写侧某一位行 **`component`/`register`/`bit`/`version`/`observation_event_id` 全等**（若双方都给 `value` 还必须相等）；
3. 缺 `observation_event_id`、版本不同、观测事件不同 → 不 certified。

**incomplete**：写侧有据（producer+delivery 已见）但读侧没有可用引用 → `missing=["consumer"]`，并在 `persistent_state.missing_fields` 中给出精确字段名（例如 `memory_read.writer_event_ids names no write record (placeholder)`、`memory_read.versions != memory_write.version`、`gpio_register_read.bit_resources[].version+observation_event_id`）。

**unknown**：该 run 完全没有该资源的观测形状 → 保留既有 `no_observable_hop`，并在 `persistent_state.unsupported_shape_reason` 写出 `no observed writer/reader record names resource (component, resource_id) in this journal`。端点未解析（未传编译文档）时仍按既有语义 `unknown` + `no resolved physical endpoints for this declared edge`（fail-closed，不放宽）。

**有界性**：每条声明边保留**最多 256 条**写记录历史（`_ANCHOR_LIMIT`），超出丢弃最旧并计入 `dropped_anchors` 与一条 `missing_fields` 说明；`missing_fields` 至多 8 条；观测账本每个声明边一行；`max_pending`/`max_event_gap`/`max_record_references` 语义不变，既不新增无界结构也不放宽既有 mmio/binding 判定。

**为什么需要写记录历史**：真实 run 里同一资源会被写多次（p4：68 次 `memory_write`），而"某一次写的版本被后续读到"才是这条边的语义。单锚点（只认第一条写）会把"读引用了第 k 条写"误判为 incomplete；因此保留一个有界历史，读取引用哪条写，证书的三跳就整体落到那条写上（三跳始终描述同一个版本，不会出现"生产者是 A、消费者引用 B"的拼接）。

## 3. 合成负例（RED→GREEN，`tests/scenario/test_persistent_state_edges.py`）

| 用例 | 期望 |
|---|---|
| RAM：写→读，读按整数写事件 id 引用 | `certified`，`writer_reference_forms=["event_id"]` |
| RAM：读按写记录自己的 `TransactionKey(...)` 引用 | `certified`，hop key `writer_version+transaction_key` |
| RAM：`writer_event_ids=["initial-image"]*4`（版本却相等） | `incomplete`，`missing=["consumer"]`，`missing_fields` 记占位 |
| RAM：`versions` 不等于写版本 | `incomplete` |
| RAM：`byte_enable=0b0011` 覆盖不到整个读窗口 | `incomplete` |
| RAM：`generation` 不同 | `incomplete`（`missing_fields=["memory_read.generation"]`） |
| RAM：写记录缺精确 `version` | `incomplete`，`missing=[producer, delivery, consumer]` |
| RAM：读引用被保留的更早一次写 | `certified`，三跳都落在该写记录上 |
| register：commit→read 同名位同版本同观测 | `certified` |
| register：read 缺 `observation_event_id` | `incomplete` |
| register：read 版本不同 / 观测事件不同 | `incomplete` |
| register：commit 的位行缺 `version`/`observation_event_id` | `incomplete`（producer 缺失） |
| register：该 run 无任何寄存器记录 | `unknown` + `unsupported_shape_reason` 点名 `(gpio_a, out)` |
| 未解析端点 | `unknown`，reason 固定 `no resolved physical endpoints for this declared edge` |
| 有界性 | 写入 `256+40` 次后 `dropped_anchors==40`、`missing_fields ≤ 8`、`pending ≤ max_pending`；淘汰/事件间隙重置后永不恢复信用 |

## 4. 真实 trace 实测

复算命令（只读保存 trace，未启动任何进程/渲染）：

```bash
PYTHONPATH=src python3 scripts/persistent_state_provenance_report.py \
  --run runs/p4-shift-fuzz-20261007-online \
  --run runs/current-dataflow-p5-paired-20261007-online \
  --out docs/reports/evidence/current-dataflow-p2-persistent-state-edges-20261007.json
```

产物：[evidence/current-dataflow-p2-persistent-state-edges-20261007.json](evidence/current-dataflow-p2-persistent-state-edges-20261007.json)（含 join 校验项、逐边 hops/references、观测账本、被判拒的候选字段）。

| run | 事件 | run 自身 9 条边 | 扩展 11 条边 | 既有 9 边是否逐字段不变 |
|---|---:|---|---|---|
| `runs/p4-shift-fuzz-20261007-online` | 118,963 | 8 certified / 1 incomplete / 0 unknown | **10 certified / 1 incomplete / 0 unknown** | 是 |
| `runs/current-dataflow-p5-paired-20261007-online` | 31,795 | 8 certified / 1 incomplete / 0 unknown | **10 certified / 1 incomplete / 0 unknown** | 是 |

两类新边的逐边状态与见证：

| run | 边 | 状态 | 三跳（producer / delivery / consumer） | 连接键 |
|---|---|---|---|---|
| p4 | 15 `cpu/ram` | **certified** | 4967 / 4967 / 6054 | 写 `version=[0,7]`、`byte_offset=130816`、`byte_enable=15`、`generation=0`、事务键 `…source_sequence=8`；读 6054 的 4 个 lane `versions=[[0,7]]*4`、`writer_kinds=["STORE"]*4`、`writer_event_ids` 为该写记录自身事务键的规范 repr |
| p4 | 16 `gpio_a/out` | **certified** | 12882 / 12882 / 14433 | commit 12882 的 `bit_resources[bit].version=8545..`、`observation_event_id=12880`；read 14433 的同名位行 `version`/`observation_event_id` 全等 |
| p5-paired | 15 `cpu/ram` | **certified** | 5104 / 5104 / 6216 | 同上形状（`version=[0,7]`、`source_sequence=8`） |
| p5-paired | 16 `gpio_a/out` | **certified** | 13236 / 13236 / 14825 | 同上形状（`version=8545..`、`observation_event_id=13234`） |

观测账本（该 run 里点名该资源的记录数，与证书是否已结算无关）：

| run | 边 15 writer/reader | 边 15 读侧引用形式 | 边 16 writer/reader |
|---|---|---|---|
| p4 | 92 / 734（68 `memory_write` + 24 `memory_initialization`；读为该 run 全部 `memory_read`） | event_id 0、transaction_key 4 lane、placeholder 0 | 29 / 5（gpio_a `out` 的 commit 与 read） |
| p5-paired | 44 / 241（20 + 24） | event_id 0、transaction_key 4 lane、placeholder 0 | 9 / 2 |

`0 rejected`、`0 evicted`、`0 dropped_anchors`：两条 run 都在 256 条写历史内。certified 的边上 `missing_fields` 为空，同一批"被拒候选"的原因记在 `rejected_candidates` 里——两条 run 的边 15 都是 `["memory_initialization.byte_offset/width_bytes", "memory_read byte window exceeds memory_write.byte_enable"]`（初始化记录没有跨度字段；其余读的字节窗口不在所匹配写记录的 `byte_enable` 内），边 16 为 `[]`。这是"哪些候选没被采纳"的记录，不是缺口。

**为什么 RAM 边能 certified、而不是像上一份报告预期的那样停在 incomplete**：真实读记录的 `writer_event_ids[lane]` 不是"什么都没有"，而是**写侧自己的身份**——host commit 把字节的 writer 记为 `str(TransactionKey(...))`（`memory_service.py` 的 `writer_event_id=str(key)`）。该串可与写事件自身 `transaction` 六字段解析后**逐字段相等**，且 p4 的 68 条 `memory_write` 事务键两两不同（68 events / 68 distinct keys，`execute_once` 语义），因此"这条读读到的就是这个版本"是可判定的精确键连接，而不是猜测。判定不接受任何解析不到写记录的串（`initial-image`、`init:ram:N` 在没有对应初始化记录字段时、`online-…:fixed-support`），所以严格性没有被放宽。

## 5. 还缺什么事件字段（决定是否只能在 RTL/探针侧补齐）

**寄存器边：不缺字段**。`gpio_register_commit.bit_resources[].version`+`observation_event_id` 与后续 `gpio_register_read` 的同名位行已经构成版本级精确引用；这条边在两条真实 run 上都 certified。

**RAM 边：已 certified，但仍有两处字段级缺口（都不影响本轮的证书，因为证书用的是事务键形式）**：

1. `memory_read.writer_event_ids[lane]` **从不携带整数写事件 id**（p4：734 条读、0 个整数引用；全部是字符串：`initial-image` / `init:ram:N` / `online-…:fixed-support` / 写事务键 repr）。要让证书直接点名写**事件**，需要 host 侧在写字节时把**事件 id** 也存进 cell（`scenario/memory.py` 的 `writer_event_id`，现在只有 `memory_service.py` 的 `str(key)`），属于**软件侧**改动，不需要 RTL；
2. 本轮 run 里**没有 `memory_write_commit` 事件**（p4/p5-paired 计数为 0），所以写侧没有 `commit_id` 可用；判定已支持该形状（要求 `commit_id` + `commit_document` 自洽），但需要在开启 commit 流（`memory_commit_receipts`）的 run 上复算才能实测；
3. `memory_initialization` 记录**没有 `width_bytes`/`byte_enable`**，因此初始化字节的跨度无法从事件自身确定（这也是 `FIRST_READ` 形式写者引用无法构成字节级精确证书的原因）；要覆盖"初始化版本→首读"这条关系，需要初始化记录补充跨度字段。

结论：**RAM/寄存器版本级逐边来源的缺口不需要新的 RTL 探针**——现有 RTL 观测（`gpio_register_commit` 的位版本、`memory_write` 的版本）已经足够；剩下的字段缺口在 host/合规写入器一侧（补 `writer_event_ids` 的整数事件 id、可选 `commit_id`、初始化跨度）。RTL/探针侧唯一仍然需要的是：把"这条读确实消费了该寄存器/该字节"的**消费**观测（例如目标侧消费记录）做成事件——本轮寄存器边只用"读侧携带同一版本记录"来判定，不能被外推为"读出的值被后续计算使用"。

## 6. 既有门禁的精确化（不改语义，只把代理断言换成真断言）

`tests/integration/test_runtime_fixture_contracts.py::test_register_state_is_never_declared_as_persistent_memory`
原来用"在线契约里根本不存在 `persistent_state`"作为"寄存器状态不会被当成持久内存"的**代理断言**。追加声明后该代理不再成立，因此把它改写为同名规则的**直接断言**（不是放宽）：

* PULP 在线契约里所有在 legacy 模板契约中已存在的 edge key，其 `relation` 必须与模板契约相同（既有 9 条边没有被重新分类）；
* 每条 `persistent_state` 声明的 `resource_component` 必须属于它自己的 edge；且该组件要么真的声明了含该 `resource_id` 的 host `PersistentMemory`，要么**根本没有** host `PersistentMemory`（寄存器标签永远不是 RAM）。

同一文件新增 `test_appended_persistent_edge_compiles_only_with_a_real_resource`，把规则做成**真断言**：把追加 rule 选进一条真实路径后编译——
RAM 边（`cpu`/`ram`）对着真实 runner **编译通过**；寄存器边（`gpio_a`/`out`）被编译期拒绝（`persistent edge … lacks real declared memory resource`），因为 PULP GPIO session 没有 `PersistentMemory`。

## 7. 门禁

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_persistent_state_edges.py -q -p no:randomly
# 32 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_edge_provenance.py -q -p no:randomly
# 38 passed（既有 9 条边语义回归）
PYTHONPATH=src python3 -m pytest tests/integration/test_runtime_fixture_contracts.py -q -p no:randomly
# 9 passed（含改写后的寄存器/持久资源规则与新的编译期拒绝用例）
PYTHONPATH=src python3 -m pytest tests/scenario -q -p no:randomly
# 2009 passed, 2476 subtests passed
```

## 8. 限制与未覆盖

* **未运行真实 RTL、未启动任何 harness/进程**：全部结论来自既有保存 trace 的流式复算；两条新边的**声明**是静态声明，其"实现"只由保存事件判定，不能替代 root 串行进行的在线验收。
* 追加声明后，**新 run** 的 `graph_sha256`/`contract_sha256`/`path_id` 与追加前不同（图是声明的一部分）；既有 run 的 manifest 与报告完全不受影响（报告读 run 自己的声明）。
* `persistent_state` 的端点解析：追加前的 run 编译文档里没有这两条边的选择项，因此实测时端点由**声明 + 该 run 自己记录拓扑的组件集合**解析（`legacy_prefix_join` 的 4 项校验全部通过才允许），并在报告里标为 `declaration_endpoints`；这不是"从 run 编译文档解析的端点"，报告明确区分。
* 证书只断言**声明边的身份连接**（写记录的版本被后续读记录逐字段引用），不断言 RTL 因果、不断言该值随后被计算使用，也不把 `origin_status` 之类的弱字段洗成证据。
* 未覆盖：其他 CPU（CV32E40P 等）的同名声明、`memory_write_commit` 形状的实测、跨组件的寄存器版本边（`origin_refs` 已支持但本轮声明为同组件）。
