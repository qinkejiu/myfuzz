# P5 统一受控故障族（软件实现与软件测试，未跑真实 RTL）2026-10-07

> **后续真实门禁（2026-10-07）：** 本报告的 `wrong_irq`/`observation_irq_level` 变体已在真实 RTL 上完成校准——真实会话第 3 例被 `gpio_b_irq_source_mismatch` 捕获并停止，并由保存的最小重放输入在新进程复现同一 finding；控制/故障两份 trace 的目标事件逐字段相同。详见[受控故障真实校准与新进程复现](current-dataflow-p5-controlled-fault-real-20261007.md)。本报告其余变体仍只有软件/真实窗口校准。

## 结论与边界

本轮交付一个**统一的受控故障族** `p5_controlled_fault.v1`，覆盖 P5 要求的四类故障（错 IRQ、错 read data、重复提交/重复交付、破坏 GPIO A→B 绑定值），
共 **9 个变体**。所有故障只作用于**交给 checker 的 deepcopy 观测副本**；原始事件对象、保存的真实 RTL trace 字节、DUT 状态与在线 journal 均不变。

本轮**只做软件实现与软件测试**：没有运行 Verilator，没有启动任何真实 RTL 会话，没有跑在线 fuzz，也没有重放真实 RTL。
因此本文的全部证据都是**分析保存事件**与**合成观测**级别的，**不构成** P5 阶段验收，也不能替代真实门禁。

三条硬边界（与既有 `p5_controlled_irq_fault.py`／`p5_controlled_uart_fault.py` 先例一致并更严格）：

1. **不触碰真实输出**：故障只改 checker 输入副本；原始 trace 文件 SHA-256 前后一致（有测试）。
2. **不作为自然缺陷统计**：每条 finding 带 `calibration_only: true`、`observation_boundary: "checker_input_copy"`；未扰动的 baseline finding 与故障 finding 分别返回（`baseline_findings` / `injected_findings`），
   若未扰动观测本身已经报告了目标 finding，默认配置**跳过注入**，钉住配置（pinned）则**直接拒绝**。
3. **fail-closed**：见证锚点不存在 → 不注入；改动是空操作 → 报错；扰动后既有 checker 不变量未触发 → 报错；配置试图指向真实 DUT/引脚/波形写入 → 直接拒绝。绝不伪造"校准成功"。

## 模块与 API

新增 [p5_fault_family.py](../../src/myfuzz/scenario/p5_fault_family.py)（1554 行），schema 常量：

| 常量 | 值 |
| --- | --- |
| `FAULT_SCHEMA_VERSION` | `p5_controlled_fault.v1` |
| `FINDING_SCHEMA_VERSION` | `p5_controlled_fault_finding.v1` |
| `REPLAY_SCHEMA_VERSION` | `p5_controlled_fault_replay.v1` |

主要接口：

- `ControlledFaultFamily.from_document(document)` / `.from_faults(entries)` / `.document()`：严格校验 + 规范化 + 往返。
- `family(receipt) -> tuple[str, ...]`：与在线 checker 调用点同签名（`OnlineCaseReceipt -> tuple[str, ...]`），返回 `baseline ∪ 注入` 的去重 violation 元组。
- `family.inject(receipt) -> ControlledFaultRun`：额外给出 `baseline_findings`、`injected_findings`、`observations`、`skipped`。
- `family.finding_documents`：累计的 finding 文档（来源链 + 双子哈希 + 重放锚点）。
- `family.minimal_replay_document()`：**最小可重放输入**导出（见下）。
- `family.trace_checker()`：适配离线 `ScenarioTrace` 调用点。
- `controlled_fault_checker(document)`：显式包装函数。

配置文档样例：

```json
{"schema_version":"p5_controlled_fault.v1",
 "faults":[{"kind":"wrong_irq","variant":"observation_irq_level",
            "checker":"ibex_pulp_online","expected_finding":"gpio_b_irq_source_mismatch",
            "operation":"rewrite","selector":{},
            "mutation":{"field":"outputs.irq","replacement":0},
            "fault_id":"p5_controlled_fault_wrong_irq_d339f86b05cc4e24"}]}
```

校验规则（全部 fail-closed，未知字段即拒绝）：`kind` / `variant` / `checker` / `expected_finding` / `operation` 必须与该变体的声明完全一致（不能把注入说成别的 finding）；
`replacement` 类型、范围、IRQ 位约束逐变体校验；`selector` 只允许该变体的锚点键，且**只要钉住任何事件就必须同时钉住 `case_id`**；
任何层级出现指向真实 DUT/引脚/硬件的键（`dut_*`、`*_to_dut`、`rtl_write`、`hardware`、`apply_to_dut`、`force`、`trace_write` …）都拒绝；`fault_id` 由配置内容派生，显式给出时必须一致。

## 四类故障、finding ID 与来源链

finding ID 规则：`p5_controlled_fault_<kind>_<sha256(canonical(身份))[:16]>`，身份 = 变体 + checker + 预期不变量 + 被扰动字段 + case/事件 ID + 原值/扰动值（**不含**配置 `fault_id`），
因此同一故障配置对同一观测稳定、对不同注入点唯一；键名沿用既有 checker violation 的 snake_case 风格。

| 类别 | 变体 | 被扰动字段 | 既有 checker 不变量（`detected_by`） |
| --- | --- | --- | --- |
| `wrong_irq` | `observation_irq_level` | `outputs.irq`（含 `interrupt` 别名） | `gpio_b_irq_source_mismatch` |
| `wrong_irq` | `cpu_irq_input_bit` | `inputs.irq`（清 bit0，脉冲挂起时） | `cpu_irq_pulse_input_mismatch` |
| `wrong_read_data` | `cpu_response_data` | `outputs.data_rsp_rdata`（GPIO B PADIN） | `cpu_gpio_b_padin_response_mismatch` |
| `wrong_read_data` | `delivery_read_data` | `read_value`（GPIO B PADIN 交付） | `cpu_gpio_b_padin_response_mismatch` |
| `wrong_read_data` | `uart_cpu_response_data` | `outputs.data_rsp_rdata`（UART 0x18） | `cpu_uart_rxdata_response_mismatch` |
| `duplicate_submission` | `irq_pulse_resubmission` | 复制一条 `pulse_start` | `cpu_irq_pulse_input_mismatch` |
| `duplicate_submission` | `mmio_delivery_replay` | 复制交付并改冲突载荷 | `cpu_gpio_b_padin_response_mismatch` |
| `broken_binding_value` | `delivery_value` | A→B `dataflow_delivery.value` | `gpio_a_to_b_delivery_mismatch` |
| `broken_binding_value` | `bound_input_value` | GPIO B `inputs.gpio_in` 低字节 | `gpio_b_bound_input_mismatch` |

"错 IRQ 时机"以**选择锚点**落实：IRQ 观测必须与 `source_start.source_tick` 同 tick，且脉冲消费/矛盾观测必须在同一 case 内被见证；锚点不成立就不注入。
"重复提交"需要多一条事件，因此插入 1 条合成副本并把其后 `event_id`（及其 `producer_event_id` 引用）整体 +1，使既有 checker 的严格单调约束成立；
纯重复（脉冲重提交）记 `value_semantics: "claim_count"`（1→2），带冲突载荷的重复记 `"payload"`。

来源链字段（`finding["source_chain"]`）：`case_id`、`observation_event_id` / `observation_event_kind` / `observation_component` / `observed_local_tick`、`mutated_field`、`original_value`、`injected_value`、`related_event_ids`（如 `source_start_event_id`、`read_event_id`、`response_event_id`、`delivery_event_id`、`producer_event_id`、`insert_before_event_id`）、`source_tick`、`transaction`（epoch/sequence）、`case_admission_ids`、`origin_status`、`origin_admission_ids`、`event_id_shift`、`inserted_checker_input_event_id`、`value_semantics`。
finding 顶层另有 `raw_observation_sha256`（原始观测）与 `checker_input_sha256`（扰动副本），两者可直接对比取证。

## 真实保存事件窗口上的四类样例

夹具 [p5_fault_family_real_window.json](../../tests/scenario/fixtures/p5_fault_family_real_window.json)（88,521 字节，SHA-256 `272b57e682e1513f5b7576f491ada08462ab8ad39b34d49db43cd190572c7c1e`）
逐字节取自保存运行 [online_final_trace.json](../../runs/current-dataflow-p4-xori-certified-20261007-online/online_final_trace.json)
（SHA-256 `f8ae9a898b2916521feab45591da4138f493a4eae221909232beaaf9f9da9d18`，与同目录 `online_run_identity.json` 记录一致；注意该值与该目录 2026-10-07 受控 IRQ 报告里写的 `c6d542d1…` 不同，说明该 trace 文件在报告之后被重写过），
两个窗口 `irq_binding_6436_6452`（17 事件）与 `padin_read_7356_7365`（10 事件），case 均为 `online-4-f13d49307cfb514a7489f1b1`。
两个窗口的未扰动 baseline 均为 `()`。

| 类别 | `finding_id` | 来源链关键字段 | 最小重放 `selector` |
| --- | --- | --- | --- |
| `wrong_irq` | `p5_controlled_fault_wrong_irq_0de498262918caeb` | 观测事件 6437（`local_tick_sample`，tick 195，`interrupt` 1→0），关联 `source_start` 6438，`source_tick` 195 | `case_id`、`observation_event_id=6437`、`source_start_event_id=6438`、`source_tick=195`、`original_value=1` |
| `wrong_read_data` | `p5_controlled_fault_wrong_read_data_db49ea1aac6d63a3` | 观测事件 7365（CPU 响应，`data_rsp_rdata` 262→263），关联读交付 7356，`transaction={epoch 0, sequence 11}` | `case_id`、`read_event_id=7356`、`response_event_id=7365`、`original_value=262` |
| `duplicate_submission` | `p5_controlled_fault_duplicate_submission_56dfb498dbb36cf2` | 复制交付 7356（`read_value` 262→263），插入在 7365 之前，`inserted_checker_input_event_id=7365`、`event_id_shift=1` | `case_id`、`read_event_id=7356`、`insert_before_event_id=7365`、`original_value=262` |
| `broken_binding_value` | `p5_controlled_fault_broken_binding_value_c2eb07640decb8aa` | 观测事件 6452（GPIO B `inputs.gpio_in` 低字节 6→7），关联交付 6449 | `case_id`、`delivery_event_id=6449`、`observation_event_id=6452`、`original_value=6` |

最小重放配置样例（`wrong_irq`，取自 `family.minimal_replay_document()["fault_document"]`）：

```json
{"schema_version":"p5_controlled_fault.v1",
 "faults":[{"checker":"ibex_pulp_online","expected_finding":"gpio_b_irq_source_mismatch",
   "fault_id":"p5_controlled_fault_wrong_irq_ab5107fcb116c53e","kind":"wrong_irq",
   "mutation":{"field":"outputs.irq","replacement":0},"operation":"rewrite",
   "selector":{"case_id":"online-4-f13d49307cfb514a7489f1b1","observation_event_id":6437,
               "original_value":1,"source_start_event_id":6438,"source_tick":195},
   "variant":"observation_irq_level"}]}
```

真实保存事件窗口覆盖 6/9 变体（`observation_irq_level`、`cpu_response_data`、`delivery_read_data`、`mmio_delivery_replay`、`delivery_value`、`bound_input_value`）；
其余 3 个变体（`cpu_irq_input_bit`、`uart_cpu_response_data`、`irq_pulse_resubmission`）用形状相同的合成观测校准（合成观测字段取自同一份保存 trace 的事件形状）。

## 最小可重放输入

`family.minimal_replay_document()` 返回 `p5_controlled_fault_replay.v1`：`calibration_only: true`、`fault_document`（把每个真正触发的故障**钉到观测锚点**的合法 `p5_controlled_fault.v1` 文档）、
`fault_document_sha256`、以及每个 finding 的 `{finding_id, fault_id, case_id, expected_finding, detected_by, observation_event_id}`。

- 与先例一致且更强：先例只重跑"同一静态 fault_mode + 同一保存场景"；这里导出的文档本身就是**可再次校验的配置**，并且在钉住锚点上额外钉住**观测到的原值**。
- 稳定性：同一配置对同一观测两次运行产出**逐字节相同**的 finding 文档（测试断言 canonical JSON 相等）；未扰动观测已含目标 finding、或钉住的见证不再成立时**拒绝**而不是静默空跑。
- 注意：新进程做**真实 RTL fresh replay** 时必须使用与保存 manifest 相同的**原始配置文档**（checker 身份含 `fault_document`）；钉住版本用于从同一保存观测复现同一 finding。

## 测试与 RED/GREEN

命令：`cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_fault_family.py -q -p no:randomly`

- **RED**（实现前）：`ImportError while importing test module … ModuleNotFoundError: No module named 'myfuzz.scenario.p5_fault_family'` → `1 error in 0.12s`。
- **GREEN**（实现后）：`23 passed, 39 subtests passed in 0.63s`。
- 相关回归（不改动任何既有文件，仅确认无影响）：`tests/scenario/test_p5_controlled_irq_fault.py`、`test_p5_controlled_uart_fault.py`、`test_ibex_pulp_online_checker_retention.py`、`test_online_session_partial_replay.py`、`test_online_source_provenance.py`、`test_event_journal.py`、`test_session_runtime_paths.py`、`test_online_candidate_rejection_receipt.py`、`test_online_uart_source_events.py`、`test_chain_certificates.py`、`tests/integration/test_online_run_identity.py`、`tests/test_repository_audit.py`、`tests/test_doc_link_check.py` → **205 passed, 50 subtests passed in 8.24s**。

测试覆盖：9 个变体各 1 正例（finding ID + 来源链 + 期望不变量）与 1 负例（无见证不注入且不产生 finding）；
四类原生缺陷单独统计（`baseline_findings` vs `injected_findings`）；配置往返与 checker 身份稳定；非法配置（未知类型/缺字段/非法值/DUT 写入键）拒绝；
最小重放配置往返与稳定性；钉住配置对变更观测拒绝；空操作与未触发不变量的拒绝；离线 `ScenarioTrace` 适配；真实保存窗口校准；原始 trace 字节与原始事件对象不变。

## "原始观测未被修改"的证明方式

1. **对象图不变**：测试记录扰动前事件结构里每个 dict/list 的 `id()` 序列，调用后逐一相等 → 不存在原地改写或被替换的嵌套容器。
2. **逐字段/逐字节不变**：扰动前后 `json.dumps(events, sort_keys=True, separators=(",", ":"))` 的 SHA-256 相等，且与调用前的 `deepcopy` 深度相等。
3. **实现方式**：只对待扰动的那一条事件 `deepcopy`（重复类再 `deepcopy` 一条副本），其余事件按引用复用且从不写入；来源链记录 `raw_observation_sha256` 与 `checker_input_sha256` 供独立复核。
4. **真实文件不变**：测试对保存的真实 trace 计算 SHA-256，跑完全部注入后再算一次，要求等于 `f8ae9a898b2916521feab45591da4138f493a4eae221909232beaaf9f9da9d18`（文件不存在时 skip）。

## 接线状态

**已接线（API 级，未改任何既有集成/入口文件）**——两处既有 checker 调用点都直接接受本故障族，无需新代码路径：

- 在线（live session）：`make_ibex_pulp_online_runtime(checker=family)`／`make_ibex_uart_online_runtime(checker=family)`；`ScenarioSession` 以 `checker(receipt)` 调用，本族的 `__call__` 同签名。
- 离线（trace 级）：`ScenarioRfuzzExecutor(checker=family.trace_checker())`；`trace_checker()` 用真实 `ScenarioTrace` 单测过。
- 新进程 replay：`replay_scenario_rfuzz_continuous(output_dir, factory, session_checker=family)` 在启动 RTL 前强制比对保存 manifest 的 checker 身份（身份含 `fault_document` 与本模块源码 SHA-256），不一致即拒绝。

**未接线**：没有任何生产入口/脚本默认构造本故障族（`grep` 只有测试引用）。本轮**没有新增 run 脚本**，因此真实 RTL 门禁与 fresh replay **尚未执行**；`src/myfuzz/integration/*`、`scripts/`、`session_runtime.py`、两个先例模块均未被修改。

真实门禁所需命令（root 串行执行，本轮未运行）：

```bash
# 1) 在线校准（同一文档即 checker 身份；输出目录必须不存在）
#    以 root 既有 run 脚本方式构造 runtime，并把 checker=ControlledFaultFamily.from_document(doc) 传入
#    make_ibex_pulp_online_runtime(cache_dir=..., run_id=..., checker=<family>, cpu_retirement=True, gpio_consumption=True)
#    run_scenario_rfuzz_live(executor=runtime.executor, client_binary=..., output_dir=..., duration_seconds=..., max_tests=..., search_seed=...)
# 2) 新进程 fresh replay（同一文档）
PYTHONPATH=src python3 -m pytest tests/scenario/test_p5_fault_family.py -q -p no:randomly
# 3) 全量/相关回归
PYTHONPATH=src python3 -m pytest tests/scenario tests/integration/test_online_run_identity.py -q -p no:randomly
```

## 已知限制

- 未运行真实 RTL：本族的在线行为（多 case 链式状态）只在合成 receipt 与保存事件上验证。
- 开销：注入点为每条故障各维护一条独立 checker 链，另有每个 checker 一条 baseline 链；每个 receipt 会跑 `1 + N` 次 checker，适合**短校准跑**，不适合长时在线搜索。
- 重复类故障会对其自身的 checker 链做 `+1` id 重编号（每个注入 +1），跨 receipt 的 `producer_event_id` 引用可能失效，只会**抑制**该链上无关 finding，不会制造 finding；保存 trace 与 baseline 链保持原编号。
- 锚点必须与矛盾见证落在**同一 receipt**内；跨 case 边界的见证不会被利用（不注入，不会伪造）。
- `case_admission_ids` 取自该 receipt 内的 `source_admission`；本族的两个真实窗口样本内没有 admission 事件，因此为空列表。
