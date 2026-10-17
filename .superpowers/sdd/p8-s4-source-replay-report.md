# P8 S4 实现报告：UART FIFO 来源认证 + typed normalizer + 统一前缀 replay

- 增量：P8 S4（只做来源/证明与 replay；不改 RTL、不改固件字节、不改 `fifo_origin` 原始帧字段）
- 日期：2026-10-19
- 状态：源码 + 纯软件测试已实现并提交。**真实 RTL 门未由本增量运行**（主会话在冻结快照上运行）。代码全部 fail-closed：证明缺失时 case 保持 `unknown`/`incomplete` 并记录缺失项，绝不把 equal byte/waveform/pop 当成 authority。
- 基线：父提交 `f3dc20d`（P7 I3，其他 agent 并发推进；本会话开始时工作树 HEAD 为 `a43e3fa`）。本增量只叠加自己的文件；S2/S3 真实门基线仍是 `dbebc4d` 系列。
- 未修改：`agent.md`、`third_party/`、root-owned evidence、RTL、固件镜像字节、`contracts.py` 身份期望。

## 1. 结论摘要

1. **来源图已声明并可编译**：新 `scenario/dma_runtime_paths.py` 声明 `uart.external_rx_byte → uart.rx_frame → uart.fifo_entry → cpu.fifo_pop → dma.fifo_pop → dma.ram_write → ram.destination_commit → dma.completion_irq → cpu.dma_irq → cpu.isr` 的 9 条边，编译复用 `PreparedRuntimePathContract` + `RuntimeEdgeIndex`。缺边、错 relation、错 graph digest、缺节点、错误 ownership、缺少 DMA master window / `master_target_access` 能力全部在第一条 RTL 命令前失败。
2. **admission 是真实字节 admission，不是 host token**：`SourceAdmission.source_id` 用图节点 id（不是 `producer_ref`），`input_sha256` 用 `UartConsumptionTracker._validate_frame` 完全相同的 canonical 文档（`{action_id, component:'uart', port:'uart_rx_byte', value, bit_offset:0, width:8, kind:'source_event'}`）。`producer_ref` 冒充 `source_id` 时 `source_owner_ref` 返回 `None` → 永远不通过。
3. **DMA master 读现在带事务身份**：`GeneratedOpentitanUartSession.master_target_access` 用真实 TL-UL `ACCESS_TLUL_UART` 进行读，上下文为 `route_context_mode='dma_master'`、channel `dma-memory`；`wishbone_dma_session._deliver_target` 在**启用 source provenance 时**才走该能力（其余既有 direct fixture 保持原 `read_register` 行为与证据字节不变）。`UartConsumptionTracker` 只对 `router`/`dma_master` 证明 `graph_path_certified`，并要求 dma_master 的声明窗口、offset、be、delivery context 逐字段相等。
4. **case 证据只在两证齐备时翻为 accepted**：新 `scenario/uart_fifo_authority.py` 把 tracker 的 accepted `uart_fifo_retention` / `uart_fifo_read_consumption` 行 join 到本 case 已认证的真实 FIFO entry 与真实 pop 行；每个被 admission 的字节恰有一条 retention，每个真实 pop 恰有一条 read，entry_id/access_id/value/route/channel/admission/path 全部一致才输出 `fifo_origin='accepted_uart_fifo_entry'`、`source_authority='accepted_uart_fifo_entry'`、`proof_grade='accepted_uart_fifo_chain'`。缺失 → 保持 `unknown` 并写 `missing`/`incomplete_reasons`；**矛盾**（foreign frame/access、错误 admission、错误 entry、重复 accepted）→ 直接 `RuntimeError`，不降级、不洗白。
5. **原始 `fifo_origin` 未改写**：`uart_source_frame_*`/`uart_frame_validation.fifo_origin` 仍为 `unknown`；accepted 只出现在 case 证据与 `source_authority_evidence` 文档中。
6. **typed normalizer 已共享**：新 `scenario/replay_normalize.py` 用显式规则表（`NORMALIZER_RULES`/`FIELD_RULES`/`RETAINED_FIELDS`）替代 `dma_uart_rx_runtime._normalize` 的实现，`_normalize` 改为委托，旧行为逐字节保持（S1b/S2/S3 测试全绿）。整 JSON `str.replace` 不是声明规则；`first_difference` 报第一差异路径。
7. **统一前缀 replay**：新 `integration/dma_prefix_replay.py`（`DmaPrefixReference`/`prefix_reference`/`compare_dma_prefix`/`replay_dma_prefix`）对每个前缀比较 plan 命令、每个真实 event、tick 边界与逐 case 证据；任一差异抛 `PrefixDivergence` 并携带第一差异。
8. **测试计数（本机，实际运行）**：新增 S4 纯软件 **159 passed**；既有 S2/S3 focused **162 passed, 6 skipped**；S1b 搜索 focused **32 passed**；设计 6.2 基线 **20 passed, 3 skipped**；合并 focused 门 **421 passed, 7 skipped, 14 subtests passed / 70.78s**。真实门未运行。

## 2. 变更文件

| 文件 | 类型 | 内容 |
| --- | --- | --- |
| `src/myfuzz/scenario/dma_runtime_paths.py` | 新增 | UART RX FIFO 来源图/契约；`compile_dma_runtime_paths`、`compile_dma_source_provenance`、`declared_dma_master_route`、`source_input_sha256`、`register_case_admissions` |
| `src/myfuzz/scenario/replay_normalize.py` | 新增 | typed replay normalizer 规则表、`normalize_execution_identities`、`first_difference`/`first_replay_difference`/`first_difference_normalized`、`PrefixDivergence`、`compare_prefix_events` |
| `src/myfuzz/scenario/uart_fifo_authority.py` | 新增 | accepted retention/read 证明与真实 entry/pop 的精确 join；缺失/矛盾分类 |
| `src/myfuzz/integration/dma_prefix_replay.py` | 新增 | 统一 typed 前缀 replay（整 plan fresh 重放 + 逐前缀比较） |
| `src/myfuzz/integration/dma_uart_descriptor_runtime.py` | 修改 | boot 安装 provenance/admissions；case 证据 join accepted 证明；replay 重建 admissions 并用 typed first-difference 比较 |
| `src/myfuzz/integration/dma_uart_rx_runtime.py` | 修改 | `_normalize` 委托共享 typed normalizer（行为不变） |
| `src/myfuzz/local_harness/opentitan_uart_session.py` | 修改 | `master_target_access`（dma_master route context）、`source_provenance_enabled` |
| `src/myfuzz/local_harness/wishbone_dma_session.py` | 修改 | 启用 provenance 时 DMA master 读走 `master_target_access`；`target_route_context_mode` |
| `src/myfuzz/scenario/uart_consumption.py` | 修改 | 接受 `dma_master` 事务 key/窗口证明；`_promote` 只在 `router`/`dma_master` 证明 graph path |
| `tests/scenario/test_dma_runtime_paths.py` | 新增 | 图/契约负例：缺边/错 relation/错 digest/缺节点/非 source ownership/缺 master 能力/wrong window |
| `tests/scenario/test_replay_normalize.py` | 新增 | 规则表、retained 字段、整 JSON 替换负例、tick/byte/IRQ 第一差异 |
| `tests/scenario/test_uart_consumption_dma_master.py` | 新增 | dma_master 接受/拒绝、missing admission/edge_index、producer_ref 冒充、tampered waveform |
| `tests/local_harness/test_opentitan_uart_master_target_access.py` | 新增 | endpoint 读事务身份、wrong window/be/offset/context 拒绝、DMA bridge 能力选择 |
| `tests/integration/test_dma_source_authority.py` | 新增 | accepted/缺失/篡改/foreign/duplicate join 与 case 级翻旗 |
| `tests/integration/test_dma_prefix_replay.py` | 新增 | 统一前缀 replay 与第一差异（plan/event/tick/case、整 JSON 负例） |
| `tests/integration/test_dma_prefix_replay_real.py` | 新增 | opt-in S4 真实门（2 valid + 2 ILLEGAL、accepted、全前缀 fresh） |
| `tests/integration/test_dma_uart_descriptor_real.py` | 修改 | S2 门改为断言 accepted + 每前缀 typed 比较 |
| `tests/integration/test_dma_error_isr_real.py` | 修改 | S3 门改为断言 accepted + 每前缀 typed 比较 |
| `.superpowers/sdd/p8-s4-source-replay-report.md` | 新增 | 本报告 |

## 3. 来源图（声明与实际拓扑绑定）

节点（`dma_runtime_paths.NODES`）：

| node | component | kind |
| --- | --- | --- |
| `uart.external_rx_byte` | uart | physical `uart_rx_byte` 0..8（**唯一 source**） |
| `uart.rx_frame` | uart | logical |
| `uart.fifo_entry` | uart | state |
| `cpu.fifo_pop` | cpu | logical |
| `dma.fifo_pop` | dma | logical |
| `dma.ram_write` | dma | logical |
| `ram.destination_commit` | cpu | state（RAM resource 由 CPU 侧同一个 `PersistentMemory` 持有） |
| `dma.completion_irq` | dma | physical `irq` 0..1 |
| `cpu.dma_irq` | cpu | physical `irq` 0..1 |
| `cpu.isr` | cpu | logical |

边（规则 → relation）：

1. source → `uart.rx_frame`：`EVENT_ORDER/causal_order`
2. `uart.rx_frame` → `uart.fifo_entry`：`EVENT_ORDER/causal_order`
3. `uart.fifo_entry` → `cpu.fifo_pop`：`EVENT_ORDER/mmio_route`（initiator `cpu`, device `uart`, base `0x50000000`, size `0x1000`；与真实 CPU `DataflowRouter` 的 `DeviceWindow('uart', ...)` 逐字段一致）
4. `cpu.fifo_pop` → `dma.fifo_pop`：`EVENT_ORDER/causal_order`（RX case 先由 CPU pop 描述符，再由配置后的 DMA pop payload）
5. `dma.fifo_pop` → `dma.ram_write`：`EVENT_ORDER/causal_order`
6. `dma.ram_write` → `ram.destination_commit`：`PERSISTENT_STATE_RULE/persistent_state`（resource `cpu`/`ram`）
7. `ram.destination_commit` → `dma.completion_irq`：`EVENT_ORDER/causal_order`
8. `dma.completion_irq` → `cpu.dma_irq`：`DATA_BINDING/direct_binding`（与真实 `Binding('dma','irq','cpu','irq',1)` + ownership `bound/dma.irq` 一致）
9. `cpu.dma_irq` → `cpu.isr`：`EVENT_ORDER/causal_order`

`RuntimeEdgeIndex` 从真实 topology 的 ownership inputs 生成 `_source_owners`，因此 `source_owner_ref('uart.external_rx_byte', path_id, 'IP_TO_CPU', 'uart','uart_rx_byte',0,8) == 'external-serial-byte'`（真实 ownership producer）；`source_owner_ref('external-serial-byte', ...)` 为 `None`。

**诚实限制（必须保留）**：共享 `RuntimePathContract` 只有 4 种 relation，DMA master 目标窗口不是 `DataflowRouter` 窗口，因此第 4 条边用 `causal_order` 表达；真正的 master 路由由 `declared_dma_master_route` 对 DMA session 的真实 `MasterTargetWindow`（component/base/size/readable offset/endpoint 实例）独立校验。要把它升级为一等 `master_route` relation 需要改共享 `runtime_path_contract.py`（本增量不做，避免改动所有方向的编译语义）。

## 4. admission 与 source authority 算法

- 每个 case 的每个 serial byte 在**第一条 source command 之前**注册一条 `SourceAdmission`：
  - `case_id='descriptor-case-<case_index>'`，`case_index=case_index-1`，`action_id='descriptor-<case>-<slot>'`；
  - `source_id='uart.external_rx_byte'`（图节点 id），`path_id`=编译 path id，`component='uart'`，`direction='IP_TO_CPU'`，`role='fuzz_source'`，`input_kind='source_event'`；
  - `input_sha256 = sha256(canonical({action_id, component:'uart', port:'uart_rx_byte', value, bit_offset:0, width:8, kind:'source_event'}))`，与 tracker 的帧字节校验逐字节一致。
- 注册顺序 = 串行顺序；fresh replay 在相同 case 边界重算同一 admission，因此 journal 前缀逐字节可复现。
- tracker 的 accepted 证明只有在 `AdmissionRegistry + OwnershipMap + RuntimeEdgeIndex` 齐备且 `mutation_source == source_owner_ref` 时才产生；本仓库没有 host 自签 token 的入口。

## 5. DMA master 读与 tracker

- `GeneratedOpentitanUartSession.master_target_access(source_transaction, ...)`：
  - 只接受 `TransactionKey(channel_id='dma-memory')`，offset 固定 `0x18`、`write=False`、`be=15`、`value=0`；
  - `delivery_context` 必须与该 master 请求逐字段一致（source_transaction/device/address/offset/write/value/be/window_base/window_size）；`window_base == address-0x18`、`window_base % 0x1000 == 0`、`window_size % 4 == 0`、`offset+4 <= window_size`；
  - 仍执行真实 `ACCESS_TLUL_UART` 读并把 `uart_rdata_access` 原样返回（`route_context_mode='dma_master'`）。未观察到真实 access 时 `RuntimeError`。
  - 只有 `source_provenance_enabled`（`configure_provenance → enable_source_provenance`）为真时 `_deliver_target` 才走该路径；否则保持旧 `read_register` 行为（既有 direct fixture 的 `source_transaction is None` 基线不变）。
- `UartConsumptionTracker`：
  - `dma_master` key 用独立校验（channel `dma-memory`、非空 source_component、uint64 epoch/sequence>0），不复用 CPU `data` channel；
  - dma_master 的窗口证明是 `delivery_context` 与声明窗口/offset/be 的精确相等（`unproven_uart_dma_master_window`）；
  - `_promote` 仅在 mode ∈ {router, dma_master} 且 `edge_index` 存在时把 `graph_path_certified=True` 并把 admission 的 `path_id` 写入 read 证明。

## 6. case 证据的接受/拒绝规则

`source_authority_evidence(rows, entries, admissions, reads, authority)`：

- 输入 entries = 本 case 串行顺序的真实 frame/action/admission/value；reads = 已认证真实 `fifo.pops`（CPU → `router`，DMA → `dma_master`）。
- 接受条件（全部精确）：
  1. 每个 entry 恰一条 accepted retention（同 frame_id、同 entry_id、同 admission_id/source_id/path_id、`graph_path_certified=True`、`retained_at_push=True`、真实 push/observation event id）；
  2. 每个真实 pop 恰一条 accepted read（同 access_id、同 entry_id、同 read_value、route/channel 匹配、真实 request/response tick & event id、同 path/admission、`graph_path_certified=True`）；
  3. 任何 accepted 行不得指向 foreign frame/access；重复 accepted 直接失败。
- 拒绝（保持 `unknown`/`incomplete`）+ 命名原因：`source_provenance_not_installed`、`missing_uart_fifo_retention:<action>`、`missing_uart_fifo_read_consumption:<access>`，并保留 tracker 的 `unproven_uart_source_authority`/`unrouted_uart_access`/`uart_empty_read`/`uart_unknown_entry_origin`/`uart_source_action_bytes_mismatch` 等原因。
- 矛盾（篡改）→ `RuntimeError`：错误 admission/path/source、foreign entry/frame/access、错误 value/route/channel、重复 accepted、request>response、非法 disposition。
- 原始 `uart_frame_validation.fifo_origin` 不改写（仍是 `unknown`）；case 级 `fifo_origin`/`source_authority`/`proof_grade` 只在接受时翻转。

## 7. typed normalizer 与统一前缀 replay

- 规则表（`NORMALIZER_RULES`）：
  - `field` 规则：`execution`, `execution_id` → 已发放 UUID 映射为 `execution:<role>`；
  - `state_edge_endpoint`：仅 journal 根记录且恰含 `event_id,producer_event_id,edge_kind,memory_id,generation,byte_offset,version,source,target` 的 `state_dependency` 的 `source`/`target`；
  - `ledger_reference`：`writer_event_id(s)`、`pending_before/after_finalize`、`uncertain_transactions` 中前导 `TransactionKey(execution_id='<uuid>', ...)` token，保留整个后缀；
  - 无 catch-all、无整文档替换；`RETAINED_FIELDS` 声明数据/tick/frame/admission/access/FIFO 探针/ISR 等必须逐字节保留的字段。unknown UUID 与任意其它字符串保持原样。
- `first_difference`/`first_replay_difference` 返回 `{path, reason, reference, actual, ...}`；`replay_descriptor_cases` 与 `compare_dma_prefix` 都报第一差异。
- `integration/dma_prefix_replay.py`：以完整 fresh 重放（最严形式）执行同一 `ScenarioBatchPlan`，再按请求前缀比较 plan 命令、真实 event 前缀（各侧用自己的 execution UUID 归一化）、每个 case 证据与边界 tick。任何差异抛 `PrefixDivergence`。

## 8. 测试（实际运行，非声称）

```sh
cd /home/qinkejiu/myfuzz
# 新增 S4 纯软件测试（六个文件）
PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_replay_normalize.py \
  tests/scenario/test_dma_runtime_paths.py \
  tests/scenario/test_uart_consumption_dma_master.py \
  tests/local_harness/test_opentitan_uart_master_target_access.py \
  tests/integration/test_dma_source_authority.py \
  tests/integration/test_dma_prefix_replay.py
# 159 passed in 0.76s
```

```sh
# 设计 6.2 基线（9 个文件）
# 20 passed, 3 skipped in 3.67s
```

```sh
# S2/S3 focused（S3 报告 15 文件）
# 162 passed, 6 skipped in 4.89s
```

```sh
# S1b 搜索 focused（3 文件）
# 32 passed in 7.98s
```

```sh
# 合并 focused（设计 6.2 + S2/S3 + S1b + S4 新增 + uart_consumption/identity 回归）
# 421 passed, 7 skipped, 14 subtests passed in 70.78s
```

说明：合并运行第一次曾在 `test_dma_uart_rx_discovery_scope.py` 失败，原因是**另一个 agent 并发修改** `src/myfuzz/local_harness/apb_storage_probe_verification.py` 触发 host-source content drift；该文件不在本增量范围内，重跑后该用例通过。冻结快照上不会出现该问题。

## 9. 真实 RTL 门（未由本增量运行）

主会话应在冻结快照上按序运行：

```sh
MYFUZZ_DMA_DESCRIPTOR_REAL=1 MYFUZZ_DMA_DESCRIPTOR_CACHE=<cache> \
MYFUZZ_DMA_DESCRIPTOR_EVIDENCE=<evidence> PYTHONPATH=src timeout 1800 \
python3 -m pytest -xq tests/integration/test_dma_uart_descriptor_real.py
# 6 例三方向；现在额外要求每例 accepted + 全前缀 typed 比较

MYFUZZ_DMA_ERROR_ISR_REAL=1 MYFUZZ_DMA_ERROR_ISR_CACHE=<cache> \
MYFUZZ_DMA_ERROR_ISR_EVIDENCE=<evidence> PYTHONPATH=src timeout 1800 \
python3 -m pytest -xq tests/integration/test_dma_error_isr_real.py
# 3 valid + 3 invalid；现在额外要求每例 accepted + 全前缀 typed 比较

MYFUZZ_DMA_PREFIX_REAL=1 MYFUZZ_DMA_PREFIX_CACHE=<cache> \
MYFUZZ_DMA_PREFIX_EVIDENCE=<evidence> PYTHONPATH=src timeout 1800 \
python3 -m pytest -xq tests/integration/test_dma_prefix_replay_real.py
# 2 valid RX（含 len=2）+ 2 ILLEGAL；accepted 证据 + 每个前缀 typed replay
```

真实门要验证的**新增字段**：

- 每个 case：`fifo_origin='accepted_uart_fifo_entry'`、`source_authority='accepted_uart_fifo_entry'`、`proof_grade='accepted_uart_fifo_chain'`；`source_authority_evidence.missing == []`；`retention/reads` 数 = `len(source_bytes)`；所有 retention/read 的 `entry_id` 集合相同；RX 例有 `len` 条 `route_context_mode='dma_master'` 且 channel `dma-memory` 的 read；非 RX 例全部 `router`。
- fresh replay：`fresh.cases == result.cases`、`fresh.local_ticks == result.local_ticks`、`fresh.plan.commands == result.plan.commands`、`fresh.identities == result.identities`、`fresh.execution_ids != result.execution_ids`；每个前缀 `compare_dma_prefix` 通过。
- 新增证据文件：`prefix-digests.json`（S4 门）、`cases.json`/`descriptor.json.gz`/`fresh.json.gz`/`manifest.json`。

**若真实门失败**：case 会保持 `unknown` 并记录 `missing`/`incomplete_reasons`，或直接在矛盾处失败；不会出现“accepted 但缺证明”的路径。真实门失败时应先读取 `source_authority_evidence.reason/missing/incomplete_reasons`，不要放宽断言。

## 10. 诚实边界与剩余缺口

1. **DMA master 路由还不是 `RuntimePathContract` 的一等 relation**：第 4 条边声明为 `causal_order`，master 窗口由 `declared_dma_master_route` 对真实 `MasterTargetWindow` 单独校验，tracker 再用 `dma_master` 窗口证明消费。升级为一等 `master_route` 需要改共享契约（影响所有方向），建议 S5/后续增量单独做。
2. **连续 RX runtime（`run_continuous_uart_rx`）仍未安装 provenance**：其 S1b 真实门依旧输出 `fifo_origin='unknown'`。共享 join/authority 代码已经存在，但给 `_ContinuousRxBoot` 接 admission 会改变 S1b 搜索门的事件/基线，需单独增量在其真实门上重新建立基线。本增量没有声称连续 RX 已认证。
3. **真实门未运行**：本报告的所有 accepted 结论是“代码在证明齐备时才允许”，不是已观测的 RTL 事实。S4 的 accepted 证据必须由主会话在冻结快照上实测；`error-status-measured.json` 的 S3 测量基线仍以真实门为准。
4. **额外 provenance tracker 的副作用**：`configure_provenance` 会在 descriptor runner 上同时安装 `UartNativeIrqJoin`、`UartRetiredReadLinker`、operand seed/use 等 tracker，journal 会新增这些历史证据行；S4 的 baseline 与旧 attempt6 不可互换（设计要求如此）。若真实门显示这些行与 descriptor 证据冲突，应在新增量中显式关闭或验证，而不是过滤事件。
5. **不是新 RTL**：IRQ 仍是 host latch/16-tick 展宽，波形期间只走 UART，无 PLIC、无共享时钟、无物理总线仲裁；`dma_master` 只是同一真实 TL-UL UART 访问的声明路由上下文，不是 DMA 侧新增 RTL。
6. **范围外**：CPU 程序字节变异（S5）、多主并发、任意 CPU+IP 通用接入、`ScenarioRfuzzExecutor` 通用复用。

## 11. 提交

- 提交信息以 `P8 S4:` 开头，只包含 §2 列出的 S4 源/测试/报告文件；不包含 `agent.md`、`third_party/`、root-owned evidence。
- P8 状态：**源码与纯软件门满足 S4 的“认证 + typed normalizer + 前缀 replay”实现要求；真实门与独立审计仍由主会话执行，P8 整体不自动通过。**
