# P3 通用源动作契约与跨例依赖泛化（软件门禁）

日期：2026-10-07。主实施计划 P3 要求把源动作定义成**版本化契约**（`instruction` 与 `external_event`，各自带前置条件、源归属、终止观察与预算），并让**跨例依赖**以显式见证泛化，而不是只靠固定 ISR 脚本。本报告记录该契约的软件交付与它已接线/未接线的边界。

## 交付

| 文件 | 内容 |
|---|---|
| `src/myfuzz/scenario/source_actions.py`（新增） | `source_action.v1` 动作契约、`source_prerequisite.v1` 先决条件（6 种）、`cross_case_effect_witness.v1` 见证、`prerequisite_evaluation.v1` 评估、`cross_case_effect_tracker.v1` 有界跨例跟踪 |
| `src/myfuzz/scenario/session_runtime.py` | 极小接线：`ScenarioSession(..., prerequisite_gate=None)`；`submit_case` 在**任何 RTL 命令之前**查询先决条件；成功后把该例真实事件喂入 tracker |
| `tests/scenario/test_source_actions.py`（新增） | 36 tests / 7 subtests |
| `tests/scenario/test_source_action_session_gate.py`（新增） | 8 tests |

契约字段：`action_id`、`kind`（`instruction` / `external_event`）、`component`、`source_id`、`ownership`（`fuzzable` / `bound` / `fixed`）、`flow_id`（F1–F6）、`payload`、`prerequisites`、`termination_observation`（`consumption` / `retirement` / `delivery` / `incomplete`）、`local_step_budget`、`action_sha256`。

先决条件六种：RAM 字节版本（`memory_id`/`generation`/`byte_offset`）、IP 寄存器版本（`component`/`register`/`reset_epoch`）、未决 IRQ（pending / delivered / taken，三者必须带 `flow_id="interrupt_flow"`）、指令槽尚未物化（`component`/`address`）。`satisfied(action)` **只在证据精确匹配时为真**，否则返回带序 `.missing` 的 `PrerequisiteEvaluation`；证据必须逐字段相等（换 commit_id、generation、memory_id、cpu_tick 均不满足）。

## 严格拒绝（fail-closed）

未知 `kind`、缺 `ownership`、`bound`/`fixed` 携带可变 payload（构造与 `from_document` 两条路径）、把 CPU IRQ 当可变源（`flow_id`、`endpoint_class`、payload 内 `interrupt_flow` token 三路拒绝）、非法 subject、缺 `evidence_ref`、重复 prerequisite、预算越界、空串内容摘要、文档篡改——全部拒绝。后到的 RAM/寄存器版本覆盖旧证据后旧 prerequisite 失效；`instruction_slot_unmaterialized` 在真实 `instruction_source` 或 Store 材料化后失效；未登记槽位 fail-closed 不满足；同 `event_id` 不同内容的冲突事件保留首证据并 bar 该 subject，只有 reset 可解除。容量/超龄淘汰后 floor 单调，旧事件重放被拒且计数（`restored_attempts`），不恢复 credit。

有界：`max_effects=4096`、`max_age_events=131072`、`max_slots=512`、`max_components=64`，`max_pending = max_effects + 2*max_slots`；注入 55,000 个混合事件后仍在上限内。

## 门禁

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_source_actions.py -q -p no:randomly
# 36 passed, 7 subtests passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_source_action_session_gate.py -q -p no:randomly
# 8 passed
# 定向回归（含 session_runtime/在线来源/回执/CLI）：117 passed, 49 subtests passed
# 全量 tests/scenario（本报告冻结源码）：1697 passed, 799 subtests passed in 431.78s
```

接线测试断言：先决条件缺失时抛异常且 `runner` 事件数、`local_ticks`、`session.cases` **完全不变**（即拒绝发生在任何 RTL 命令之前）。

## 已接线 / 仅 API（不夸大）

- **已接线**：`ScenarioSession(prerequisite_gate=...)` 的接纳前门禁与成功后的事件喂入；`source_actions.py` 已纳入 online manifest 身份闭包（因此**新记录**的 online 身份会变化，replay 两侧同码重算）。
- **仅 API、未接线**：`DependencyScheduler.run`、`online_case_decoder`、`scenario_rfuzz` / `scenario_rfuzz_live` 都不构造 `SourceAction` 或 gate；**live RFuzz 与真实 RTL 路径目前仍是原行为**，`prerequisite_gate` 只能由调用方显式传入。

## 限制

- 纯软件门禁：未运行任何真实 RTL；跨例见证只识别已声明的真实事件形状（`memory_write_commit.v1`、legacy `memory_write` 逐 lane、`gpio_register_commit(status="observed")`、`pulse_start`/过期类、`cpu_irq_input(value==1)`、`cpu_irq_taken`、`instruction_source`），其它事件一律不产生 witness。
- 因此 P3 的"整阶段长会话验收"（通用跨例 CPU→IP→CPU 与 IP→CPU→IP、finding 后停止并重放）**仍未完成**：契约就绪不等于 live 路径已使用它。
