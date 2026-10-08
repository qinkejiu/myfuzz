# P2 通用逐边来源：真实声明边的 certified/incomplete 统计

> **2026-10-07 更新：** 唯一 incomplete 边 `gpio_a.gpio_out→gpio_b.gpio_in` 已闭环。目标侧消费由 `gpio_tick_observation.active_input_context.segments[]`（过 `is_authenticated_gpio_tick`）或 `gpio_input_applied*` 提供，`origin.kind="binding"` + `origin.delivery_event_id` 精确引用声明本条边的 `dataflow_delivery`，且要求行恰好覆盖声明窗、driver 切片值 == delivery 值 == 目标测量窗切片（三方相等）；仅时间相邻进不了该边。三条真实 run 复算均为 **9/0/0**；在 `p4-shift-fuzz` 上叠加追加的两条 `persistent_state` 边后为 **11 certified / 0 incomplete / 0 unknown**。阶段级汇总见[P2 阶段验收](current-dataflow-p2-stage-acceptance-20261007.md)。

日期：2026-10-07。P2 的长期缺口是"**通用逐边来源与消费**"：此前只有 pin8 GPIO 与 GPIO A 写等**固定子路径**有精确证书，任意"声明边"的统一生产者/交付/消费者身份没有建立，真实 trace 里大量 MMIO/Store/IRQ 事件是 `origin_status="unknown"`。本报告交付一个通用的、按**契约声明边**统计证明状态的消费者，并在真实运行上给出每条边的实测状态。

## 交付

| 文件 | 内容 |
|---|---|
| `src/myfuzz/scenario/edge_provenance.py`（新增） | `runtime_edge_provenance.v1` 消费者与 `runtime_edge_provenance_report.v1` 报告；`edge_endpoints_from_compiled()` 从编译会话文档解析物理端点；`edge_provenance_session(run_dir)` 一步取回 contract 与 endpoints；`edge_provenance_report(contract, events, endpoints=...)` |
| `tests/scenario/test_edge_provenance.py`（新增，38 tests） | 合成 certified/incomplete/unknown 正负例、真实 trace 钉住用例、逐事件流式等价、有界性 |

边状态定义：
- **`certified`**：生产者、交付、消费者（或事务/资源版本）由**精确 ID/键**连接（事务键逐字段相等、`source_event_id` 相等、端点/位宽/值相等、`address` 落在声明 aperture）。
- **`incomplete`**：只观测到部分跳，给出 `missing`（第一个缺失跳）与已见跳的 `event_id`。
- **`unknown`**：该边没有任何可用观测形状（例如端点无法解析），显式记 unknown 并给 `unsupported_shape_reason`——**不是** 0，也不是"边未发生"。
- 严格 fail-closed：事件 id 非连续/重复/非整数、同 id 冲突、伪造成本跳、事务键错型 → 计入 `rejections`。

## 真实运行结果

调用方式（新增的一行 API 避免"只传 contract 导致 9/9 unknown"的脚坑）：

```python
from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.edge_provenance import edge_provenance_session, edge_provenance_report
contract, endpoints = edge_provenance_session("runs/current-dataflow-p5-paired-20261007-online")
report = edge_provenance_report(contract, TraceEventStream(run).events(), endpoints=endpoints)
```

两条真实 run（`contract_sha256` 均与 manifest 内 `851b74bc…` 一致、`graph_sha256 = 58471d1e…`）：

| run | 事件 | certified | incomplete | unknown | rejected |
|---|---:|---:|---:|---:|---:|
| `runs/current-dataflow-p5-streamed-short-20261007-online` | 10,418 | **8** | **1** | 0 | 0 |
| `runs/current-dataflow-p5-paired-20261007-online` | 31,795 | **9** | **0** | 0 | 0 |

共 9 条声明边的逐条状态（已由 root 独立复算，结果一致）：

| relation | rule | 状态 | 见证 |
|---|---:|---|---|
| `mmio_route` | 0/5/6/11/12/13 | certified | acceptance 与 delivery 的 `source_transaction` **六字段全等**、`device_id` 相等、`address` 落在声明 aperture（paired：275/322、888/913） |
| `direct_binding`（`gpio_b.irq → cpu.irq`） | 4/10 | certified | producer@4610(`source_event_id`) → delivery@4611 → consumer@4617，三者共享精确 `source_event_id=1`，value/端点/位宽逐字段相等 |
| `direct_binding`（`gpio_a.gpio_out → gpio_b.gpio_in`） | 2 | certified | driver@24 → delivery@25 → **consumer@27**（目标自身输入观测 `segments[].origin.delivery_event_id` 精确引用该 delivery；行恰好覆盖声明窗；driver 切片值 == delivery 值 == 目标测量窗切片，三方相等） |

## 与已知事实的对照（不夸大）

- 该 run 的 `dataflow_delivery` 全部 `origin_status="unknown"`（origin 属 source-admission 概念），因此**不能**用 `origin_status` 当边证书；反过来，本次 certified 的 MMIO/IRQ 跳也**不携带** admission，未把 unknown 洗成已知。
- IRQ binding 的 certified 口径与既有 pin8 链证书一致（同一 `source_event_id` 精确连接），但本消费者**不复用**其 17 跳语义，只声明边身份与三跳连接。
- 4 条 mmio_route 共享同一对 router window，本 trace 只实测到两对事务；6 条 mmio 边按各自 `rule_index` 身份各自持证，未外推。
- **没有任何 RAM/寄存器版本边被认证**：该契约本身没有声明 `persistent_state` 关系，且 233 条 `memory_read.writer_event_ids` 全是字符串（`initial-image` 等），无一条点名写事件 id。这正是 P2 剩余的"寄存器/RAM 版本逐边来源"缺口，报告把它写成 incomplete/unknown，而不是 0。
- 修复了一个真实缺陷：采样 tick 记录（`local_tick_sample`，自身不带 `edge_candidates`）只能靠后续事件的 `producer_event_id` 反查归因，旧实现只对整段切片做预扫描，传惰性生成器时反链建立不起来；现改为逐事件注册 + 延迟引用回填（同一记录对同一边只 attach 一次）。

## 门禁

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_edge_provenance.py -q -p no:randomly
# 38 passed
# 相关回归（含 runtime_path_contract/edge_index/chain_certificates/source_provenance）：128 passed, 130 subtests
```

钉住用例：`test_real_trace_without_resolved_endpoints_is_pinned_unknown`（只传 contract 时 certified==0、unknown==9 且 reason 固定，同时断言事件候选的 `graph_sha256` 与 contract 相等）、`test_real_trace_streamed_one_event_at_a_time_is_attributed`（逐事件流式与批量结果逐跳相等）。有界性：5 万事件后 pending ≤ `max_pending`、引用表 ≤ `max_record_references`，`tracemalloc` 峰值约 0.4 MB。

## 限制

- 只覆盖该契约实际声明的 9 条边；`persistent_state`（RAM/寄存器版本）边尚未声明，因此没有 RAM 版本级逐边证据。
- `gpio_a→gpio_b` 数据绑定只到 incomplete：目标侧消费在该 trace 中没有可用的精确记录（这是可定位缺口，不是 unknown）。
- 状态是**该 run 的观测结论**；不同 run 的边覆盖可能不同，须按各自 bundle 重算（`edge_provenance_session` 会校验 `contract_sha256`）。
- 未运行新的真实 RTL：本报告的全部统计来自既有保存 trace 的流式复算。
