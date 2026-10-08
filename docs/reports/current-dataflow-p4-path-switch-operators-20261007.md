# P4 声明式路径/源切换算子与 slot 不可变性（软件门）

日期：2026-10-07。P4 要求"实现合法变异算子（含路径切换）"。本文记录解码器侧算子的声明、拒绝语义与两条真实 profile 断言，以及"真实 Store/取指后的程序字节不能被后例变异"这条不变量的只读检查器。算子进入在线搜索主循环后的真实 RTL 逐例证据见[P4 声明式 live 路径切换算子在真实 RTL 上生效](current-dataflow-p4-path-switch-live-20261007.md)；本文不声称 RTL 行为。

## 算子：声明池内的重定向

`OnlineCaseDecoder` 新增只读声明池与切换请求，全部走已有的声明与拒绝通道：

| 入口 | 作用 |
|---|---|
| `path_switch_targets(flow_id=None)` | 按声明序列出池：`path_id/target_id/direction/flow_id/source_ids/eligible_source_ids/switchable`，让"为什么这条路径不可切"可见，而不是无理由拒绝 |
| `PathSwitchRequest(path_id, flow_id, source_id, input_slice)` | 至少给出一个声明字段；不解析、不推断，未命中即按 shipped 码拒绝 |
| `switch_proposal(request)` | 返回 `(case, CandidateDisposition)`：授予时给出 `online_path_switch.v1` 记录，拒绝时不消耗任何状态 |
| `PathSwitchRecord` | `families/from_path_id/from_source_id/path_id/source_id/flow_id/changed/ownership_producer/request` + 自内容摘要 `operator_id`；`from_document` 会重算摘要，篡改的记录无法载入 |

要点：

- **身份改变才进 candidate 身份**：只有 `changed=true` 的候选把 `switch_operator_id` 写进 `candidate_id`；未切换候选的身份键与摘要逐字节不变。保留的切换记录有界（`MAX_RETAINED_SWITCHES`），被淘汰的旧例只能回到未切换身份，不会错标。
- **拒绝只复用 shipped 码**：`path.undeclared`（未知路径/未知 flow）、`path.source_mismatch`（源不在该路径上）、五个 `ownership.*`（由编译后的 ownership map 裁决，拒绝指针改指请求字段）、`budget.exhausted`（切到指令源但预留已耗尽）、`slot.proposal_mismatch`（没有当前提案/拿别例请求冒充）。
- **拒绝不消耗**：当前提案、指令游标与例计数保持原样，原来的提案仍可提交。
- **切换后的前置条件跟着切换后的源**：声明了跨例前置的源切换后，shipped `SourceActionGate` 会在任何 RTL 命令之前拒绝该例，而不是把前置条件算到旧源头上。

## 测试（软件，无 RTL）

`tests/scenario/test_online_path_switch_operators.py`（20 项）覆盖：合法路径切换写入算子身份与 `candidate_id`、同路径内源切换（含 CPU 指令源 ↔ 外部源）、由 ownership map 裁决的输入切片切换、`changed=false` 的原地切换保持身份、上表全部拒绝码、原地拒绝后原提案仍可提交、请求/记录往返与伪造摘要拒绝、切换后有界保留与淘汰、切换后前置条件由 gate 拒绝、默认解码分布与 `candidate_id` 对"算子之前"的黄金值逐值不变。

真实 profile（`make_ibex_pulp_dual_source_online_decoder()`，无 RTL）断言：F4/F5 两条声明路径可互相切换（`families=("path_switch",)`、`ownership_producer=external_b.pin8`、flow 随路径更新），而 GPIO B 的 bound/fixed 输入切片被 ownership 直接拒绝（`ownership.bound_input`、`ownership.fixed_input`、`ownership.range_exceeds_field`）。

`tests/scenario/test_slot_immutability.py`（25 项）覆盖：只读 slot 不可变性检查器 `myfuzz.scenario.slot_immutability` 的判定与 CLI 退出码。

```bash
PYTHONPATH=src python3 -m pytest -q tests/scenario/test_online_path_switch_operators.py tests/scenario/test_slot_immutability.py
# 45 passed in 23.22s
```

## slot 不可变性：真实运行只读结论

检查器只读一个已保存运行目录：程序区取 `decoder_manifest.json` 声明的在线指令预留与声明的 `initial_image` 区，slot 全集是该区域内**至少被一个事件物化或读取过**的字节；`instruction_source`、`initial_image`、`memory_initialization`、带完整 `memory_write_commit` 回执且 `performed_effect` 为真的真实 Store 才算物化（未被使能的 lane 不算），`memory_read` 与非写非错的 `instr_response` 才算读取证据。读取先于物化、读取但从未物化、Store 缺完整回执、记录畸形一律记为 `insufficient_evidence`，绝不记为通过。结论按运行给出且显式限定作用域（`rtl_executed_by_checker=false`）。

```bash
PYTHONPATH=src python3 -m myfuzz.scenario.slot_immutability \
  runs/p3-lane-selectivity2-20261007-online runs/p4-shift-fuzz-20261007-online \
  --json-out runs/current-dataflow-p4-path-switch-20261007-logs/slot_immutability_two_runs.json
# slot_immutability_report.v1 runs/p3-lane-selectivity2-...: conclusion=immutable slots=1716 immutable=1716 violated=0 insufficient_evidence=0 reads=1714
#   (scope: this run only; 124984 untouched declared program byte(s) are outside the slot universe)
# slot_immutability_report.v1 runs/p4-shift-fuzz-...:        conclusion=immutable slots=1296 immutable=1296 violated=0 insufficient_evidence=0 reads=1420
#   (scope: this run only; 125404 untouched declared program byte(s) are outside the slot universe)
```

退出码即判定：`immutable=0`、`violated=1`、`insufficient_evidence=2`，参数错误另有码；因此"没证据"不能被当成"通过"（`test_cli_gate_exit_codes_follow_the_recorded_verdict` 钉住）。

## 限制

- 本文全部为软件断言：没有编译、渲染或启动任何 RTL，不声称 CPU 真的执行了切换后的路径，也不声称 slot 不可变性由 RTL 保证（它只是对已保存事件流的只读判定）。
- slot 判定只覆盖它读到的**这一个 trace 的 slot 全集**；未被任何事件触及的声明字节只报计数，不报通过。
- 算子池由声明决定：本文不讨论声明之外的路径、自动发现路径或跨 wiring 的泛化。
- live 主循环接线（`MYFUZZ_PATH_SWITCH`、运行态 `path_switch` 记录）与真实 RTL 逐例复算见 live 报告；真实声明下"请求已耗尽预留的目标被 `budget.exhausted` 拒绝"由 live 报告里的软件门证明，非本文。
