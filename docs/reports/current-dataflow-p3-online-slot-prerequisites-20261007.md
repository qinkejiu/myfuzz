# P3 在线取指槽先决条件：shipped 策略与跨例见证（软件门禁）

日期：2026-10-07。P3 要求跨例依赖以**显式见证**泛化，而不是只靠固定 ISR 脚本。上一轮报告（`current-dataflow-p3-source-actions-20261007.md`）交付了 `source_action.v1` 契约、六种先决条件、有界 tracker 与 `ScenarioSession(prerequisite_gate=)` 的极小接线；本轮补齐**shipped 集成声明**：Ibex＋双 PULP GPIO 在线场景现在真的构造 `SourceActionGate` 并接到 session/executor，门禁在真实在线会话中**每例被查询**，且跨例见证真的生效。

## 交付

| 文件 | 内容 |
|---|---|
| `src/myfuzz/scenario/source_actions.py` | 新增 `instruction_slot_reservation_gate.v1` 策略门禁 `InstructionSlotReservationGate`（声明式按例绑定 + 惰性登记 + 越界 fail-closed）、`SourceActionSlotWindowError`；修正门禁输入比对的字段词表（`words_hex` ↔ `data_hex`，两种拼写一致才通过） |
| `src/myfuzz/scenario/ibex_pulp_dual_source.py` | 新增声明常量 `ONLINE_INSTRUCTION_START/END`、`ONLINE_SLOT_RESERVATION_PREFIX` 与 `make_pulp_dual_source_source_action_gate(...)`；`make_pulp_dual_source_factory(..., source_actions=False)`（共享，第二颗 CPU 保持原行为）与 `make_ibex_pulp_dual_source_factory(..., source_actions=True)`（Ibex shipped 默认开启）在返回的 factory 上暴露 `new_source_action_gate()`（每 session 新建一个 gate） |
| `src/myfuzz/integration/ibex_pulp_online.py` | `make_pulp_dual_source_online_runtime(..., prerequisite_gate=None, source_actions=False)` 构造并挂到 `ScenarioSession(prerequisite_gate=)`；`make_ibex_pulp_online_runtime(..., source_actions=True)`（shipped 默认开启）；`IbexPulpOnlineRuntime.source_action_gate` 属性 |
| `src/myfuzz/integration/scenario_rfuzz.py` | `_bind_online_source_action` 记录并评估 **gate 实际登记的动作**（策略门禁绑定的 per-case 先决条件因此出现在回执里）；校验 register 返回值 |
| `src/myfuzz/scenario/online_case_decoder.py` | 仅文档：说明静态 `OnlineSourceActionDeclaration` 与按例槽位策略的分工（无代码改动） |
| `tests/scenario/test_ibex_pulp_source_action_prerequisites.py`（新增） | 16 tests：声明/上限、按例绑定与物化、跨例满足与跨例拒绝、静态声明对移动游标不可满足、越界 fail-closed、工厂/运行时默认开启与 legacy 显式关闭、live 回执/report 键 |
| `tests/scenario/test_gpio_profile_selection.py` | 既有“精确转发 kwargs”断言补上 `source_actions`（并追加显式 `source_actions=False` 的 legacy 断言，未放宽生产默认） |

## 声明的先决条件、登记范围与上限依据

- **种类**：`instruction_slot_unmaterialized`（负向先决条件），subject = `{component: "cpu", address: <32 位字地址>}`，`evidence_ref = "online-instruction-slot.v1:<address:#010x>"`。
- **为什么地址必须按例**：在线指令游标单调前进，每条早先被填过的槽位保持已物化。静态声明一个固定地址只能对**一条**用例可满足，第二条必被 `materialized_instruction_slot` 拒绝（测试 `test_a_static_declared_slot_cannot_follow_the_moving_cursor` 用真实事件形状证明了这一点）。因此策略门禁绑定**该 action 自己声明的 payload 地址**（`address .. address+len(words_hex)/2`，逐 32 位字），地址来自用例输入而不是猜测。
- **登记范围**：`instruction_start .. instruction_end`，即 stream bootstrap 声明的同一段在线指令保留区（默认 `0x11000..0x2fe00`）；策略门禁的 `component` 取自 `wiring.memory_component`（声明字段），不是字面量。
- **上限依据**：`(instruction_end - instruction_start) // 4 = 31616` 字，是“一次运行可能命中的不重复字地址”的**真上界**。**不预先登记整段**（整段 31616 字一次性登记会在 512 容量的 tracker 上立刻淘汰最早槽位）。实际登记是**惰性的**：每个被接纳的指令用例只登记它自己写的那 1–2 个字。tracker 以 `max_slots = 31616` 构造，使得任何登记都不会在“声明它的那条用例”被接纳之前被淘汰，物化也不会把 tracker 打到 degraded；构造时若 tracker 容量小于声明字数则直接 fail-closed 拒绝（`exceeds the tracker slot capacity`）。
- **保留位置语义**：登记使用 `event_id = max(tracker.cursor, 上次声明位置) + 1`，即“紧接最后一条已观测日志事件之后的会话位置”，严格新于任何被淘汰证据的 floor，因此有界淘汰不会把新声明误判为 stale。

## 跨例语义（如实说明）

- **可做到的**：某例真实执行产生的 `instruction_source` 事件（由 `ScenarioRunner._append_external_events` 从 CPU memory service 排入日志，带 `component/address/data_hex`）被 tracker 记为 `instruction_slot_materialized`；此后**任何**再次声明同一槽位的用例都在**任何 RTL 命令之前**被拒绝，reason 为 `materialized_instruction_slot`（部分命中时 `matched_evidence_refs` 只列仍新鲜的其余字）。
- **做不到的（如实）**：本在线场景的指令源**没有** RAM 字节效果——decoder 的 MMIO 窗口只有 `0x4000100c`（GPIO A PADOUT），固定 ISR 的 RESULT 写入只发生在 pin8 中断被取走时，且其 `memory_write` 的精确 `event_id`/`commit_id` 跑前不可知，无法在 manifest 里诚实声明。因此本轮**没有**“前一例 Store 的 `ram_byte_version` 成为后一例被满足的先决条件”这种正向 RAM 跨例消费。最强形态就是上面的槽位跨例语义：**第 N 例写过的槽位在第 M 例必须被拒绝**，以及每条后续指令例的“本槽仍未物化”要求由 tracker 中累积的跨例状态回答。

## 已接线 / 未接线

- **已接线**：`make_ibex_pulp_online_runtime(...)`（`source_actions=True` 默认）→ 构造 `InstructionSlotReservationGate` → `ScenarioSession(prerequisite_gate=)` → `ScenarioRfuzzExecutor` 自动发现同一对象 → 每个候选在 `_bind_online_source_action` 里 `register`（绑定+登记）并 `require_case`（查询），`Session.submit_case` 在任何 RTL 命令前**再次**查询；接纳后 session 把回执事件喂入 tracker。
- **未接线**：`make_pulp_dual_source_online_runtime` 的共享默认仍是 `source_actions=False`，因此 CV32E40P 在线路径与 `ibex_pulp_rejection_calibration` 仍是原行为（calibration 用 Ibex factory 但显式不挂 gate）；`ibex_uart_online` 未声明策略；自行构造 `ScenarioSession` 的调用方（例如 `tests/integration/test_ibex_pulp_online_stream_boundary_real.py`）若要用策略必须显式使用 `factory.new_source_action_gate()`。支持型 NOP 槽（pin8 例的 `support_words`）不在策略门禁内，只由 decoder 自己的保留区约束。
- **身份**：gate 与其 tracker 是**运行态**，不进入 `_online_manifest` / plan；策略声明与计数只出现在 `report.json` 的运行态记录里。fresh replay 由 plan 重建用例、不构造 gate，因此既有 replay 语义不变（回归含 `test_scenario_rfuzz_*`、`test_retirement_replay_selection_review`）。

## 结果（真实输出）

```bash
# GREEN：新测试
PYTHONPATH=src python3 -m pytest tests/scenario/test_ibex_pulp_source_action_prerequisites.py -q -p no:randomly
# 16 passed in 41.53s

# 回归（默认开启策略）：在线/源动作/门禁/工厂/运行时/replay 选择
PYTHONPATH=src python3 -m pytest tests/scenario/test_online_source_action_gate.py \
  tests/scenario/test_source_action_session_gate.py tests/scenario/test_source_actions.py \
  tests/scenario/test_ibex_pulp_source_action_prerequisites.py \
  tests/scenario/test_online_source_provenance.py tests/scenario/test_online_real_flow_mapping.py \
  tests/scenario/test_online_session_partial_replay.py tests/scenario/test_online_path_first_selection.py \
  tests/scenario/test_online_candidate_rejection_receipt.py tests/scenario/test_online_uart_source_events.py \
  tests/scenario/test_pin8_native_irq_optin.py tests/integration/test_runtime_fixture_contracts.py \
  tests/integration/test_cv32e40p_pulp_online_factory.py tests/integration/test_ibex_pulp_rejection_calibration.py \
  tests/integration/test_scenario_rfuzz_acceptance.py tests/integration/test_scenario_rfuzz_transport.py \
  tests/integration/test_scenario_rfuzz_terminal_identity.py -q -p no:randomly
# 261 passed, 97 subtests passed in 104.46s

# 全量 tests/scenario（同一工作树）
PYTHONPATH=src python3 -m pytest tests/scenario -q -p no:randomly
# 1945 passed, 2476 subtests passed in 513.17s
```

RED 证据（用临时 pytest 插件把三个 shipped 开关还原成改动前行为：无 provider、无 session gate、旧输入词表、旧回执动作；插件位于 `runs/p3-slot-policy-red/legacy_full_red.py`）：

```bash
PYTHONPATH=src:runs/p3-slot-policy-red python3 -m pytest \
  tests/scenario/test_ibex_pulp_source_action_prerequisites.py -q -p no:randomly -p legacy_full_red
# 9 failed, 7 passed in 42.65s
# 失败覆盖：按例绑定/物化、跨例满足、跨例拒绝、静态槽位对照、越界 fail-closed、
# register 返回值校验、工厂 provider、运行时挂 gate、live 回执/report 键、输入词表
```

## 改动文件 sha256（本报告写作时）

| 文件 | sha256 |
|---|---|
| `src/myfuzz/scenario/source_actions.py` | `5756f5cc3fc8cc7543dd7267e898336d86a740584e033a0bf744596238e48f8f` |
| `src/myfuzz/scenario/ibex_pulp_dual_source.py` | `ee0be2b8a900fd63f06d97484dc790f207f00d6092fb4d2668b3aad968ab6bbe` |
| `src/myfuzz/integration/ibex_pulp_online.py` | `a7819d08d2dd69c7d41d9c67035f912476369d4e9d92a3c198f7cc8f27b1c40a` |
| `src/myfuzz/integration/scenario_rfuzz.py` | `92d7d9310f059ddec8fb71867260ad528129debb4f7c39ab14411e81a07b9f32` |
| `src/myfuzz/scenario/online_case_decoder.py` | `c4725878231b672f3b58344fc3e67665b906b2f124578e5815d40dca3cde1d3a` |
| `tests/scenario/test_ibex_pulp_source_action_prerequisites.py` | `492eb1466f5eeffe12f7c2f46bdc617570594c7066a76b7d9b4759ab68e3939e` |
| `tests/scenario/test_gpio_profile_selection.py` | `110388bd46cd2a4a42811c8746a8b823c94d2e0e83bf8377f6f67eb8dc4d8c80` |

`src/myfuzz/scenario/ibex_pulp_dual_source.py` 同时包含另一个并行任务的声明化重构（`PulpDualSourceWiring` / `dual_source_ownership_declaration` / `dual_source_wiring`）：本轮的加法改动只新增常量、`make_pulp_dual_source_source_action_gate`、factory 的 `source_actions` 开关与 `new_source_action_gate` 属性，并复用 `wiring.memory_component` 作为策略 component，未重写既有函数体。

## root 真实门禁命令与判定键

```bash
# 本仓库 root 的真实门禁命令（本轮未执行；--seconds/--max-tests/--run-id 由 root 决定）
python3 scripts/run_ibex_pulp_online.py run \
  --client-binary <rfuzz-client> --cache-dir <cache> --output <new-dir> \
  --cpu-retirement --gpio-consumption
```

从真实产物核对（键路径按 `report.json` / `receipts.jsonl` 现状）：

- `report.json["source_action_gate"]["enforce"] is True`：门禁处于强制模式。
- `report.json["source_action_gate"]["gate"]["schema_version"] == "instruction_slot_reservation_gate.v1"` 且 `["declaration"] == {"component":"cpu","first_address":69632,"last_address":196096,"word_bytes":4,"declared_words":31616,"reservation_ref_prefix":"online-instruction-slot.v1","registration":"lazy_per_admitted_case","prerequisite_kind":"instruction_slot_unmaterialized"}`：策略真的被构造且声明与 bootstrap 的在线保留区一致。
- `report.json["source_action_gate"]["gate"]["counters"]["reservations"] > 0`、`["queries"] > 0`、`["bound_actions"] > 0`：门禁**真的被查询**并按例登记（queries ≈ 2×已接纳例数；refusals 一般为 0）。
- `report.json["source_action_gate"]["gate"]["gate"]["tracker"]["materialized_count"] > 0` 且 `["slot_count"] > 0`：某例的真实 `instruction_source` 事件已把它的槽位物化。
- `report.json["source_action_gate"]["action_ids"]`：每个被接纳用例的 `case_id:source_id`。
- `receipts.jsonl` 中 `status == "complete"` 的行：`source_action.action.prerequisites[*].kind == "instruction_slot_unmaterialized"`，`evidence_ref` 形如 `online-instruction-slot.v1:0x00011000`，且 `source_action.evaluation.matched_evidence_refs` 与之逐项相等（失败时 `refusal.reason == "source_action_prerequisite_unsatisfied"`、`detail.evaluation_reason == "materialized_instruction_slot"`、`rejection is None`、`status == "input_invalid"`，且 runner 事件数/ticks/cases 不变）。
- 跨例判定（软件证据已固定）：同一槽位被两条用例声明时第二条被拒；`tracker["counters"]["refused"]` 与 `gate["counters"]["redeclared_reservations"]` 增加。真实在线运行中游标单调前进，正常路径只出现“满足”分支；拒绝分支由测试与 `runs/p3-slot-policy-red/` 证据覆盖。

## 未运行的部分

- **未跑真实 RTL**：本文所有结果均为软件测试（离线 CPU stub 产生与真实 CPU memory service 相同形状的 `instruction_source` 事件）；未运行 Verilator、未启动真实 Ibex/GPIO 进程、未跑在线 fuzz。上表 root 命令与判定键是给 root 串行执行的真实门禁，本轮未执行。
- 真实运行中“槽位重用被拒”的分支无法自然出现（游标只前进），因此该分支的**真实验证**只能在软件测试或人为重放同一用例时获得。
