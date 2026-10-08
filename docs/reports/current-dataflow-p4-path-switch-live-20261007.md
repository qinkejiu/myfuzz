# P4 声明式 live 路径切换算子在真实 RTL 上生效

日期：2026-10-07。P4 要求"实现合法变异算子（含路径切换）"并给出真实证据。声明式切换算子此前已在解码器侧完成（[路径/源切换算子](current-dataflow-p4-path-switch-operators-20261007.md) 的候选池、请求/记录 schema 与拒绝码），本报告补齐它在**在线搜索主循环**里的接线、运行态记录，以及真实 Ibex + 双 PULP GPIO RTL 上的逐例可复算证明。

## 算子规则与开关

- 开关：`MYFUZZ_PATH_SWITCH`（构造参数 `path_switch`）。默认关闭，且仅在在线解码器路径上读环境变量；关闭时行为与改动前逐字节一致（选源分布、`candidate_id` 不变）。
- 目标抽取：`sha256(b"myfuzz.online.path_switch.v1\0" + raw)`，前 8 字节对**声明序**的切换池取模选行，次 8 字节在该行的可用源里选源；请求 `PathSwitchRequest(path_id=行, source_id=源)` 交给解码器 `switch_proposal`。抽取只依赖该例 raw 记录与声明池，不看时钟或任何回放不可复现的搜索状态。
- 一次尝试三态：
  - `changed`：解码器授予且候选身份改变 → `decision["path_switch"]=online_path_switch.v1 记录`，`source_selection_reason=declared_path_switch`；
  - `no_op`：授予但身份未变 → 仍写记录（`changed=false`），保留原本的选源原因；
  - 拒绝：解码器用**自己的 shipped 拒绝码**拒绝（请求声明的目标但当前不可用），`decision["path_switch_refusal"]` 记录请求、目标、声明池与拒绝码；**该例不消耗任何东西**，未切换的候选照常提交。
- 切换不是额外一次提交：`switch_proposal` 不推进 `_sequence`、不消耗指令预留，重定向后的 case 只替换同一 slot 的候选（`case_id` 两枝一致）。
- 运行态：`report.json` 恒有 `path_switch`（`online_path_switch_state.v1`，含 `attempts/granted/changed/refusals/rejection_codes/operator_ids`），`run_config` 恒有 `path_switch`/`path_switch_source`，关闭时也写明"本次没有运行该算子"。

被切到的目标行若当前不可用（例如 CPU 指令预留耗尽后的 F4 路径），算子**不做本地猜测**：请求照发，由解码器的 shipped 码（`budget.exhausted@switch.source_id`）拒绝并逐字记录。

## 真实运行

同一 client、同 seed、同预算、各自全新 cache；ON 枝只多一个环境变量（脚本 `runs/current-dataflow-p4-path-switch-20261007-logs/path_switch_arms.sh`、`path_switch_long_arm.sh`）：

```bash
BIN=third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz
python3 scripts/run_ibex_pulp_online.py run --client-binary $BIN \
  --cache-dir runs/p4-path-switch-off-20261007-cache \
  --output runs/current-dataflow-p4-path-switch-off-20261007-online \
  --seconds 150 --max-tests 96 --seed 20261007 --run-id current-dataflow-p4-path-switch-off-20261007   # OFF
# 同命令 + MYFUZZ_PATH_SWITCH=1 + 各自 output/cache/run-id                          # ON（96 例对照枝）
# 同 ON 命令，--max-tests 2400 --seconds 900                                        # ON 长枝
```

| 运行 | 例数 | 状态 | 墙钟 | attempts | granted | changed | no_op | 拒绝 |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| OFF（默认） | 96 | 94 complete / 2 input_invalid | 8.88 s | 0 | 0 | 0 | — | 0 |
| ON（对照枝） | 96 | 91 complete / 5 input_invalid | 8.52 s | 96 | 96 | **46** | 50 | 0 |
| ON（长枝） | 2400 | 2275 complete / 125 input_invalid | 252.58 s | 2400 | 2400 | **1199** | 1201 | 0 |

声明池（两枝都只有这两个声明路径，`flow_id` 分别 F4/F5）：

| 路径 | flow | 声明源 | OFF 落点 | ON 落点 | ON 未切换解码落点 |
|---|---|---:|---:|---:|---:|
| `cpu_to_ip_to_cpu.closed_loop` | F4 | `cpu.online_instruction` | 41 | 43 | 43 |
| `ip_to_cpu_to_ip.closed_loop` | F5 | `gpio_b.external_pin8` | 55 | 53 | 53 |

长枝的四个 `operator_id`（46/50 与 1199/1201 两两成对：CPU→PIN 改变、PIN→CPU 改变、CPU 原地、PIN 原地）分别出现 613/586/615/586 次。

## 逐例可复算证明（`path_switch_gate.py`）

`runs/current-dataflow-p4-path-switch-20261007-logs/path_switch_gate.py` 只读三枝产物，退出码 0（`path_switch_gate.json`、`.stdout`）：

1. **身份门**：三枝 `decoder_manifest.json` 的内容都等于现构建的 shipped 在线声明（内容比较，不看字节排版）。
2. **对照枝复算**：OFF 枝 96/96 例——用该例自己的 `online_raw_records_hex` + 记录的 `online_weights` 重跑 shipped 解码，得到未切换的 path/source，并按 shipped 身份公式重算 `candidate_id`，与记录逐例一致；`attempts=0`。这条既是控制组，也证明复算方法本身成立。
3. **ON 枝复算**：96/96（对照枝）与 **2400/2400**（长枝）例中，记录的 `candidate_id` 恰好被**唯一一个**声明身份复现——要么是未切换身份（未变或被拒），要么是另一声明行加上**重算出的** `online_path_switch.v1` 内容摘要（改变）。改变例必须等于 raw 抽取规则点名的行、且必须带 `declared_path_switch`；未变例必须保留 shipped 选源原因。逐例 `path_id/source_id/flow_id/direction/target_id` 与复算一致。
4. **计数门**：三枝 `report.json` 的 `path_switch` 计数与逐例分类完全相等（`attempts/granted/changed/operator_ids/refusals/rejection_codes`），0 处不一致。
5. **fresh replay**：对照枝与长枝都用 `scripts/run_ibex_pulp_online.py replay` 对新 RTL 进程重放，`matches=true`（长枝 2275 个完整例、JSONL 事件流）。

## 结论与限制

**结论**：声明式路径切换算子已进入真实在线搜索主循环：ON 对照枝 46/96、长枝 1199/2400 例的**提交候选身份**被重定向到声明池内的另一条路径，且每个 `candidate_id` 与算子的内容摘要都能从该例自己的 raw、权重与声明池独立复算；关闭时算子完全不运行（0 次尝试）。切换与 shipped 源动作门可组合：ON 对照枝 5 例在切换之后被 `source_action_not_constructible` 拒绝（其候选身份仍可从记录复算）。

**限制（不得外推）**：

- 两枝 raw 输入只在第 1 例相同（切换立刻改变反馈，RFuzz 随之分叉），因此跨枝只是同 seed 的搜索过程对照；逐例因果由**枝内复算**给出，不是跨枝配对。
- 长枝 0 次拒绝不是"拒绝路径不可达"的证明，而是**本窗口够不到预留边界**的实测结果：长枝 admitted 指令字节 27,388 / 声明预留 126,464，余量 99,076 字节（≈24,769 个 4 字节 CPU 例）。真实声明下的拒绝路径由软件门 `tests/scenario/test_path_switch_live_wiring.py::test_real_ibex_profile_refuses_its_spent_cpu_target` 证明：用该解码器自己的 decode/commit 把预留推进到下界，算子请求 F4 声明目标，shipped 码 `budget.exhausted@switch.source_id` 拒绝，`switchable_paths` 只剩 F5，且未切换的候选仍在。
- 算子开销未测：本报告不声称吞吐变化（两个 96 例枝的墙钟差异仅 0.36 秒，且负载不同）。
- 切换只发生在**声明池**内（此 wiring 只有 2 条路径、每路径 1 个源），所以"改变"必然是 CPU↔PIN 的整条路径互换；更宽池下的行为由算子单测覆盖，不在本报告范围。
- 已知记录边界（未修改 shipped 产物 schema）：预 RTL 的 source-action 拒绝例在 `receipts.jsonl` 里 `path_id` 为 `null`（该分支的回执未填 receipt 自身字段），但 `candidate_id/source_id/flow_id/direction/target_id` 仍在，故本门仍能逐例复算切换身份。
- 本报告不涉及 P6/P7/P8；不改动任何默认身份，关闭开关的运行产物与改动前一致。
