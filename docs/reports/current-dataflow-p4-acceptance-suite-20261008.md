# P4 验收套件 `run_p4_acceptance_suite.py`：合取判据、缺陷修复与 `--skip-heavy` 实测

日期：2026-10-08。承接 [P4 操作符收益比较报告](current-dataflow-p4-operator-benefit-comparison-20261008.md) 与 [P4 CPU 侧门禁可判定化报告](current-dataflow-p4-cpu-side-gate-decidability-20261008.md)。本报告只回答四件事：**这套件把哪些东西并成了一份文档、每一项的判据到底是什么、这套判据里原本有哪些"能通过但门禁其实失败了"的漏洞（已修 + 已用测试钉住）、以及本次真实 `--skip-heavy` 运行的逐项结果**。

> **诚实声明（先写在最前面）**
>
> 1. 本报告**不主张任何新的 RTL 结果**。本次任务**没有**运行任何 Verilator / RTL / fuzz 作业，也没有渲染任何 harness。所有结论来自：(a) 源码与已保存产物的只读阅读；(b) 只读 CLI 的复算；(c) 纯软件测试（48 个，零子进程）。
> 2. 真实实测只跑了 **`--skip-heavy`**（跳过 `path_switch` 与 `initial_ram` 两个长门禁）。因此 **本次实测未覆盖这两项**，报告不会声称它们被本次跑过；套件自己的 `limits` 字段也照实写着这一点。
> 3. 新增测试全部是**密闭（hermetic）**的：门禁调用被 `monkeypatch` 掉、产物路径被重定向到 `tmp_path`，不依赖 `runs/` 的当前状态，也不会因为真实运行被删/被改而变红或变绿。

---

## 1. 这套件"并"的是什么

`p4_acceptance_suite.v1` 文档 = 8 个**关键项** + 1 个**非关键 partial 项**。每一项只由一条**已存在的只读命令**（或一份已保存产物）判定，套件自己**不重算**任何指标：

| # | item key | 关键 | 判据来源（只读调用） | 判据（满足条件） |
|---|---|---|---|---|
| 1 | `legal_operator_sequence_edit_insert` | 是 | `scripts/run_p4_sequence_edit_gate.py verify --run runs/p4-sequence-edit-insert-20261008-online --replay-log <log>` | 本次 `exit == 0` **且** `gate-document-json:` 之后 JSON 的 `verdict == "PASS"` |
| 2 | `legal_operator_sequence_edit_delete` | 是 | 同上（delete 运行与 replay log） | 同上 |
| 3 | `legal_operator_path_switch` | 是 | `runs/current-dataflow-p4-path-switch-20261007-logs/path_switch_gate.py --off/--on/--long --write <json>` | 本次 `exit == 0` **且** 写出的 `checks` 非空 **且** 全为 `true` |
| 4 | `legal_operator_initial_ram_data` | 是 | `runs/current-dataflow-p4-initial-ram-20261007-logs/initial_ram_gate.py --off/--on --write <json>` | 本次 `exit == 0` **且** `ok is true` |
| 5 | `cpu_side_coverage_identity` | 是 | `scripts/report_rtl_branch_coverage.py --run runs/p4-cpu-side-coverage-20261008-online --json --quiet` | 本次 `exit == 0` **且** `status == "verified"` **且** `external_binding.passed is true`（即该 CLI 自己的 `_accepted` 规则） |
| 6 | `cpu_side_gate_verdict` | **否（partial）** | `scripts/run_p4_cpu_side_branch_gate.py verify --run <同上> --min-cpu-points 8` | `verdict == "PASS"`；当前为 `INCONCLUSIVE`（缺 RVFI opcode 窗口），照实记为 partial + 精确理由 |
| 7 | `fixed_budget_comparison` | 是 | `scripts/compare_p4_operator_benefit.py --pair ×3（path_switch / initial_ram_data / closed_loop_energy）--require all --json-out <json> --quiet` | 本次 `exit == 0` **且** `evidence_status == "measurable"` **且** `refusals` 为空 **且** `pairs` 非空 |
| 8 | `slot_immutability` | 是 | `python3 -m myfuzz.scenario.slot_immutability runs/p3-lane-selectivity2-20261007-online runs/p4-shift-fuzz-20261007-online --json-out <json>` | 本次 `exit == 0` **且** 每个 run 的 `run_conclusion == "immutable"` |
| 9 | `adoption_and_refusal_reasons` | 是 | 直接读 `runs/current-dataflow-p4-rejection-calibration-20261007-online/receipts.jsonl`（**不**调子进程） | 可完整解析 **且** 不同 `rejection.code` ≥ 3 |

退出码语义（`main` 的 `exit_code` 与进程退出码一致）：

| 退出码 | 含义 |
|---|---|
| `0` | 每个关键项都 `measured is True` **且** `met is True` |
| `2` | 至少一个关键项未测量或未满足（包括门禁超时、没写产物、产物不可读） |
| `1` | 套件自身无法产出文档（例如某个 check 抛异常）——此时只打印 `schema_version/ready/exit_code/error`，**不伪造 items** |

关键不变式：**一项只有在 `measured` 与 `met` 同时为真时才算通过**；无法测量的项一律 `met=null` + 精确 `reason`（`value` 保留该次调用能给出的诊断，如退出码或空 `checks`），绝不把"没测到"写成 0——收据项尤其如此：`value` 为 `null` 而不是 `distinct_codes: 0`。

---

## 2. 本次在套件里找到并修好的缺陷（判据过弱 = 可以"通过"但门禁其实失败了）

这些都先在测试里写成期望行为、跑出 RED，再改脚本让测试变绿。逐条如下（`check_*` 名称指改后文件 `scripts/run_p4_acceptance_suite.py`）：

| # | 缺陷（修复前） | 为什么危险 | 修复 | 钉住它的测试 |
|---|---|---|---|---|
| 1 | `check_path_switch`：`met = code == 0 and all(checks.values())` | `all({}.values())` 空集为**真**：门禁 `exit 0` 但没写 `checks` 文档时得到 `measured=false, met=true`，旧聚合只看 `met` ⇒ **整份套件可以 exit 0** | `measured = bool(checks)`；`met = measured and code == 0 and all(...)` | `test_path_switch_a_missing_artifact_with_exit_zero_is_not_met` |
| 2 | `check_initial_ram`：只看产物 `ok is True`，不看本次退出码 | 上一次运行留下的 `ok:true` 产物能让**本次失败**的门禁通过 | 追加 `code == 0` | `test_initial_ram_a_stale_ok_document_with_a_failing_gate_is_not_met` |
| 3 | `check_slot_immutability`：只看产物结论，不看本次退出码；且 `measured=false` 时 `reason` 可能是 `null` | 陈旧产物可让失败的 CLI 通过；未测量却没有理由 | 追加 `code == 0`，并保证 `met is not True` 时必有 `reason` | `test_slot_immutability_a_stale_document_with_a_failing_exit_is_not_met`、`test_slot_immutability_a_non_list_document_is_unmeasured` |
| 4 | `check_benefit`：拒绝行取 `row.get("family")` | comparator 自己的 schema 用的是 **`metric_family`**（`src/myfuzz/scenario/p4_operator_benefit.py:1183`），于是拒绝时报告出 `refused_families: [null]`，root 拿不到任何可行动信息 | 取 `metric_family → family → "unnamed"`，并把 `met` 改为要求 `refusals` 为空（不再依赖集合真假） | `test_benefit_a_refused_document_names_the_refused_families`、`test_benefit_a_refusal_row_without_a_family_key_still_refuses` |
| 5 | `check_adoption_and_refusals`：`json.loads(line)` 无保护 | 一条畸形收据行 ⇒ `JSONDecodeError` 冒到 `main` ⇒ **exit 1、丢掉全部 item 表**；空文件同样炸 | 畸形/非对象行、不可读文件、空文件全部走 **`null` + reason**（`receipts.jsonl line N is not JSON (...)`），绝不"部分解析后报 0 个码" | `test_receipts_a_malformed_line_is_the_null_path_not_a_fabricated_zero`、`test_receipts_an_empty_file_is_the_null_path` |
| 6 | `_run` 未捕获 `subprocess.TimeoutExpired` | 任何一条门禁超时 ⇒ 整个套件 exit 1、**已经收集到的所有结论全部作废**（长门禁 7200s 上限，最容易触发） | `_run` 捕获并返回 `124` + `timeout: the gate did not finish within <N>s and was killed`；该项记为未测量，套件 exit 2 且 item 表完整 | `test_a_timeout_in_every_gate_keeps_the_item_table_and_exits_two`、`test_a_timeout_is_reported_per_item_with_its_own_reason` |
| 7 | `_json_after`：`json.loads(tail[start:])` 要求 JSON 一直延伸到 stdout 末尾 | 门禁在 JSON 之后多打一行人类可读总结，真实 verdict 就变成 `None` ⇒ **假阴性 exit 2** | 改用 `json.JSONDecoder().raw_decode`，取 marker 之后**第一个完整** JSON 文档；畸形输入仍返回 `None` | `test_json_after_keeps_reading_past_a_trailing_summary_line`、`test_json_after_reads_the_first_marker_delimited_document` |
| 8 | `main` 聚合：`unmet = [row for row in critical if row["met"] is not True]` | 只信 `met`，任何"声称 met 但没测量"的行都能进通过集合 | `unmet = [row for row in critical if not (row["measured"] is True and row["met"] is True)]`，把不变式放到聚合层 | `test_a_critical_item_that_claims_met_without_measurement_exits_two` |
| 9 | 产物型 check 在 `met=False` 且 `exit==0` 时 `reason=None`（如 `checks` 里有 `false`） | 未满足项没有理由，root 无法行动 | 统一 `reason=None if met is True else ...`（门禁 stderr 优先，其次自述回退） | `test_path_switch_one_failed_check_is_unmet` |
| 10 | `check_sequence_edit`：只看 stdout 里的 `verdict == "PASS"`，不看本次退出码 | "文档说 PASS、进程说失败"这种自相矛盾会被当成通过 | 追加 `code == 0`（文档 verdict 与退出码必须同时说通过） | `test_sequence_edit_a_pass_verdict_with_a_failing_exit_is_not_met` |
| 11 | `check_cpu_side_coverage` 的 identity 项：只看 `status == "verified"` | 该 CLI 的接受规则 `_accepted`（`scripts/report_rtl_branch_coverage.py:342`）还要求 **`external_binding.passed`**：一份 `status: verified` 但外部绑定未通过的文档会被 CLI 判为 REJECTED（exit 1），旧判据却记 `met=true` | 追加 `code == 0` **且** `external_binding.passed is true`，并把该字段写进 `value` 供 root 复核 | `test_cpu_side_identity_a_verified_document_rejected_by_its_own_exit_is_unmet`、`test_cpu_side_identity_needs_the_external_binding_attestation` |

另外两处非缺陷但同向收紧的改动：

* 新增 `_json_file(path)`：产物**缺失或不可读**统一返回 `None`（原先 `path_switch` 遇到被截断的 JSON 会直接抛 `JSONDecodeError` ⇒ exit 1 丢表）；现在它是"该项未测量 + 理由"。
* 未测量项的 `met` 统一为 `null`（`check_sequence_edit`、`check_cpu_side_coverage` 的 identity 项原本写 `False`），与收据项的 `null` 约定对齐。

**没有改动**的部分：`PATHS`/`LOGS` 声明、每条门禁的 argv 与超时、item key 与顺序、`--skip-heavy` 行为、`--write` 行为、partial 项的判定与理由文本、汇总行文本。

---

## 3. 怎么跑

```bash
# 1) 纯软件测试（密闭，无子进程、无 RTL；本次交付的回归网）
cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
    tests/scenario/test_p4_acceptance_suite.py -q -p no:randomly

# 2) 真实套件：跳过两个长门禁（本次实测用的就是这条）
PYTHONPATH=src python3 scripts/run_p4_acceptance_suite.py --skip-heavy

# 3) 真实套件：完整（会调用 path_switch / initial_ram 两个上限 7200s 的门禁，只在有时间预算时跑）
PYTHONPATH=src python3 scripts/run_p4_acceptance_suite.py --write <某个新路径>.json
```

* 套件只做**只读复算**：不渲染 harness、不启动 RTL/Verilator、不写进任何已保存运行目录。
* 它自己会（重新）生成两个既有产物路径：`runs/current-dataflow-p4-operator-benefit-20261008/p4_operator_benefit.json`（comparator 的 `--json-out`）与 `runs/current-dataflow-p5-final-20261007-logs/p4_suite_slot_immutability.json`（immutability CLI 的 `--json-out`）。本次运行后两者仍可解析（`evidence_status=measurable`、`["immutable","immutable"]`）。
* `--write` 是可选的：**本报告没有**用它，以免在 `runs/` 下新增文件；实测文档只打印到 stdout。

---

## 4. 本次真实 `--skip-heavy` 实测

命令与结果：

```text
$ PYTHONPATH=src python3 scripts/run_p4_acceptance_suite.py --skip-heavy
...
p4 acceptance suite: exit=0 ready=True critical=6/6 unmet=[]
$ echo $?
0
```

stderr 为空。逐项表（原样取自本次 stdout 的 JSON）：

| item key | 关键 | measured | met | value | reason |
|---|---|---|---|---|---|
| `legal_operator_sequence_edit_insert` | 是 | true | true | `"PASS"` | — |
| `legal_operator_sequence_edit_delete` | 是 | true | true | `"PASS"` | — |
| `cpu_side_coverage_identity` | 是 | true | true | `{"status":"verified","external_binding_passed":true,"observed_points":30,"total_points":128}` | — |
| `cpu_side_gate_verdict` | 否 | true | **false** | `{"verdict":"INCONCLUSIVE","passed":7,"total":8,"failed":["[FAIL] cpu-stimulus (precondition): run declares no RVFI opcode counter window"]}` | 该门禁的 `cpu-stimulus` 前置判据需要本 campaign 路径未声明的 RVFI opcode 窗口；三条映射判据（no-dead-counters / cpu-side-observable / elaboration-attested）全部通过 |
| `fixed_budget_comparison` | 是 | true | true | `{"exit":0,"pairs":3,"evidence_status":"measurable","operators":["path_switch","initial_ram_data","closed_loop_energy"],"refusal_count":0,"refused_families":[]}` | — |
| `slot_immutability` | 是 | true | true | `{"runs":2,"immutable":2,"violated":0}` | — |
| `adoption_and_refusal_reasons` | 是 | true | true | `{"receipts":14,"distinct_codes":7,"codes":{"budget.exhausted":1,"decode.unbounded_input":1,"mmio.bad_width":1,"mmio.no_aligned_address":1,"mmio.window_denied":1,"ownership.bound_input":1,"ownership.fixed_input":1}}` | — |
| `limits` | — | — | — | `["path_switch and initial_ram gates skipped by --skip-heavy"]` | 套件自己声明了这两项本次**没跑** |

与修复前保存的同套件文档 `runs/current-dataflow-p4-acceptance-20261008.json`（同一 `--skip-heavy` 流程）对比：结论完全一致（`exit 0`、`critical=6/6`、唯一 partial 仍是 `cpu_side_gate_verdict`）。差异只在两处 `value`：`fixed_budget_comparison.value` 新增 `refusal_count: 0`（修复 #4 带来），`cpu_side_coverage_identity.value` 新增 `external_binding_passed: true`（修复 #11 带来）——这条同时是收紧后的判据在**真实产物**上不产生假阴性的实测：真实的 `runs/p4-cpu-side-coverage-20261008-online` 确实满足 `external_binding.passed`。

---

## 5. 测试：RED → GREEN

```text
# RED-1（第一轮，任何修复之前）
$ PYTHONPATH=src python3 -m pytest tests/scenario/test_p4_acceptance_suite.py -q -p no:randomly
17 failed, 28 passed in 0.33s

# RED-2（第二轮，第 2 节 10–11 号判据先写成测试时：3 条新测试失败）
$ ... -q -p no:randomly
3 failed, 45 passed in 0.15s

# GREEN（全部修复后，最终状态）
$ ... -q -p no:randomly
48 passed in 0.07s
```

RED-1 的 17 条失败正是第 2 节里 1–9 号缺陷的直接后果，逐组为：`_json_after` 尾部总结与多文档（2）、聚合只信 `met`（1）、硬错误路径断言口径（1，测试自身修正）、`path_switch` 空 checks / checks 有 false 却无理由 / 畸形产物（3）、`initial_ram` 陈旧产物（1）、`slot_immutability` 陈旧产物与非列表文档（2）、`benefit` 拒绝家族名 / 无 family 键 / 畸形产物（3）、超时不保留 item 表与逐项理由（2）、收据畸形行与空文件（2）。RED-2 的 3 条是 10–11 号：sequence-edit 的"verdict PASS 但退出码 2"、coverage identity 的"CLI 拒绝但文档自称 verified"、"退出码 0 却缺 external binding"。

测试覆盖（48 条）分十组：`_json_after` 解析（7）、文档 schema 与退出码语义（8）、sequence-edit 门禁（4）、path-switch 门禁（5）、initial-RAM 门禁（3）、slot-immutability（4）、benefit comparator（5）、CPU 侧报告（5）、超时（2）、收据扫描（5）。其中"确定性"一条用真实的 check 函数（只 stub `_run`）+ 预置产物跑两遍 `main --write`，断言两份写出的文档**逐字节相同**。

---

## 6. 边界：这套件**不**证明什么

1. **不重跑 RTL**。它只对已保存产物做只读复算；门禁自己的判据是否足够强，套件只继承、不独立复核。若某条门禁判据本身过弱，套件会跟着弱（这正是第 2 节修掉的那类问题，只不过修的是**套件这一层**）。
2. **`--skip-heavy` 未覆盖 `path_switch` 与 `initial_ram` 两项**。本次 `critical=6/6` 是"6 个**被跑到的**关键项满足"，不是 8 个。完整判据要跑不带 `--skip-heavy` 的命令。
3. **`cpu_side_gate_verdict` 永远是非关键 partial**：它的 `INCONCLUSIVE` 不会被折成通过，也不会改变退出码；它证明的是"该 CPU 侧门禁在本 campaign 路径上不可判定"，不是"CPU 侧映射已被证明"。
4. **收据项只证明"≥3 个不同拒绝码存在"**：它不证明拒绝码语义正确、不证明它们来自哪条路径、也不证明三条以上之外的比例。
5. **slot immutability 只对声明的两个运行成立**（`p3-lane-selectivity2`、`p4-shift-fuzz`），不是对所有历史运行的全称结论。
6. **benefit 项的 `measurable` 是 comparator 的判定**，套件不重算覆盖率/链证书/边见证；套件只保证"拒绝就绝不通过"。
7. **时间预算**：完整运行会调用两个上限 7200s 的长门禁；`--skip-heavy` 是为快速复现准备的，因此它天然弱于完整运行。
8. **本次交付的 48 个测试不启动任何子进程**：它们证明的是**套件的判据与退出码语义**，不是任何门禁的真实结论。
9. **判据仍以"门禁自己的话"为基础**：套件现在要求文档字段与进程退出码一致（第 2 节 10–11 号），但它不重算门禁内部的判据。若某条门禁把两件事同时说错，套件仍会跟着错——这只是把"单点信任"降为"两点一致"，不是独立复核。

---

## 7. 本次交付的文件

| 文件 | 说明 |
|---|---|
| `tests/scenario/test_p4_acceptance_suite.py` | **新增**：48 个密闭测试（门禁 stub + 产物重定向），覆盖 schema/退出码/解析/收据/benefit/确定性 |
| `scripts/run_p4_acceptance_suite.py` | **修改**（该脚本今日新增、无其它导入方）：第 2 节列出的 11 处判据收紧 + 2 处同向改动；`PATHS/LOGS`、门禁 argv、item key 与顺序、`--skip-heavy`/`--write` 行为全部不变 |
| `docs/reports/current-dataflow-p4-acceptance-suite-20261008.md` | **新增**：本报告 |


## 补记（2026-10-08，新增两项关键项后的真实运行）

`first_seen` 真实台账与可判定 CPU 门禁落地后，本套件新增两个关键项，并补上对应 hermetic 测试：

| 新增关键项 | 判据 | 真实值 |
|---|---|---|
| `first_seen_ledger` | `runs/p4-cpu-side-first-seen-20261008-online` 的覆盖报告 exit 0、`status=verified`、`observed_branches.first_seen.available=true`、`first_seen_source.available=true`、`points>0` | available=true，points=30，earliest `bit:21@event:1` |
| `cpu_side_gate_decidable` | profile 路径运行 `runs/p4-cpu-side-profile-rvfi-20261008-online` 上的门禁 `--min-cpu-points 1` exit 0、verdict=PASS（映射问题可判定） | verdict=PASS（8/8 判据，含 RVFI opcode 前置） |

`--skip-heavy` 下的真实结果是 **关键项 8/8 成立、exit 0**（新增两项后关键项总数由 6 变 8），`cpu_side_gate_verdict` 仍是唯一的非关键 `partial`（legacy 单 cell 运行不带 RVFI opcode 窗口，故 INCONCLUSIVE 7/8，且不影响退出码）。`tests/scenario/test_p4_acceptance_suite.py` 48 项全绿。
