# P3 正向 RAM 跨例消费真实门禁：Store M[A]=X → 后例 Load M[A]

日期：2026-10-07。P3 验收要求"第 1 例 `Store M[A]=X`，第 3 例 `Load M[A]` 必须返回 X"。此前该形态只有 UART 受限低字节版；本轮把**动态 RAM 版本先决条件**接进 Ibex＋双 PULP GPIO 在线路径，并在真实 RTL 上得到一次被精确绑定的跨例消费。

## 两个 enabler（默认关闭，既有身份逐字节不变）

| enabler | 内容 | 默认 |
|---|---|---|
| 结果槽读窗口 | `make_ibex_pulp_dual_source_online_decoder(..., result_slot_readback=False)`；仅 `make_ibex_pulp_online_runtime` 传 `True`，窗口追加 `MmioWindow(0x10000, 4)`，使"读结果槽的 `LW`"可被生成 | 共享 builder 与 CV32E40P 保持单窗口 |
| commit receipts 流 | `memory_commit_receipts: bool = False` 透传到 `GeneratedCve2Session`，并新增 `HostRamCommitJournal`（复用仓库通用 `MemoryCommitAuthority`，仅在开关打开时安装到既有扩展点）使 journal 真实产生 `memory_write_commit` 且不会撞上有界 FIFO 容量 | False（身份与行为逐字节不变） |

`scripts/run_ibex_pulp_online.py` 新增 `--memory-commit`（`action="store_true"`，仅在显式打开时转发 kwarg）。软件侧另有 26 项定向测试：默认关闭时 `identity_document` 与 `_online_manifest` 双重相等；打开时只多出 `memory_commit_stream` 一键；端到端桩测试（真实 `MemoryService`/`MemoryCommitAuthority`/runner 落盘路径，仅 CPU 执行体为桩）证明 commit 出现、被 ack、并被下一例绑定。

## 真实 RTL 结果

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/p3-ram-prereq-20261007-cache \
  --output runs/p3-ram-prereq-20261007-online \
  --seconds 60 --max-tests 40 --seed 20261007 --run-id p3-ram-prereq-20261007 \
  --cpu-retirement --gpio-consumption --memory-commit
```

退出码 0：40/40 `complete`，有效搜索 54.422 秒。门禁计数（`report.json → source_action_gate.gate`）：

| 量 | 值 |
|---|---|
| `counters.policy_matched` / `policy_not_matched` | **1** / 39 |
| `counters.registered` / `reservations` / `queries` | 40 / 33 / 80 |
| `counters.refusals` / `unbound` / `refused_evidence` | 0 / 0 / 0 |
| `ram_prerequisite.rule` | `statically_materialized_lw_base_equals_result_address` |
| `dynamic_binding.counters` | requests **1**、bound **1**、unbound 0、refused 0、provenance_records 132 |

**被绑定的真实 case**：`online-15-6dcf6e04a509a6f017fa8a62`（`status=complete`），其 `source_action.action.prerequisites[0]` 为：

```json
{"kind": "ram_byte_version",
 "subject": {"memory_id": "ram", "generation": 0, "byte_offset": 0},
 "evidence_ref": "41fb2ef445b775df524f2764d72cd9cb002859e13def50a8eaf8880da6156d9a"}
```

`evaluation.satisfied = true`、`matched_evidence_refs` 与该 `evidence_ref` 相等、`refusal = null`。

**精确交叉核对**（流式读同一 run 的事件）：该 `evidence_ref` **恰好等于**更早的真实提交事件 `memory_write_commit`（event_id **17567**）的 `commit_id`，其 `commit_document.memory_id = "ram"`、`byte_offset = 0`、`enabled_byte_cells[*].writer_kind = "STORE"`、单元值 `[1, 1, 0, 0]`。即：前例 ISR 的真实 `sw` 经 host MemoryService 提交产生该版本，后例的 `LW`（读 `RESULT_ADDRESS`）被静态识别并在**任何 RTL 命令之前**以该精确版本为先决条件接纳。

操作子分布（40 例）：`external_event` 24、`LUI+ADDI+LUI+SW` 5、`LUI` 4、**`LUI+LW` 2**、`SRAI` 2、`SLLI`/`SRLI`/`NOP` 各 1 —— 说明新窗口确实让"读结果槽"的候选进入了真实解码空间。

## 语义与边界

- 绑定只**证明"读之前该已提交版本被见证并 pin 住"**；"Load 真的返回 X"仍须由既有读/退休证据证明，本报告不外推。门禁的 fail-closed 形态也已被软件测试覆盖：无前例提交时读取用例 `input_invalid` + `source_action_not_constructible` + `DynamicBindingUnbound`（`untrusted_source_provenance`），且零 RTL 副作用。
- 该 run 的**运行身份与既有 bundle 不同**（decoder `mmio_windows` 与 commit stream 身份变化）——旧 bundle 仍按其自身身份 replay，不受影响。
- 单次 40 例短跑，不是长会话；只观察到 **1** 个"读结果槽"候选被绑定（`policy_matched=1`），样本量小。
- 本轮未发现自然 RTL 缺陷；0 拒绝、0 unbound。

---

## 2026-10-09 产物重建说明

本报告的原始产物目录曾在 2026-10-09 的 `runs/` 瘦身中被误删，随后**按原命令重建**（`--seconds 60 --max-tests 40 --seed 20261007 --run-id p3-ram-prereq-20261007 --cpu-retirement --gpio-consumption --memory-commit`）。

重建结果与本文全部判据一致：40/40 `complete`；门禁 `policy_matched=1`／`policy_not_matched=39`；`source_action_gate.gate.dynamic_binding.counters` = requests 1／bound 1／unbound 0／refused 0／provenance_records 132；绑定回执仍是 case `online-15-6dcf6e04…`，其 `matched_evidence_refs` 含 `41fb2ef445b775df524f2764d72cd9cb002859e13def50a8eaf8880da6156d9a`，该值精确等于更早 `memory_write_commit`（event **17567**）的 `commit_id`，其 `memory_id=ram`、`byte_offset=0`、`writer_kinds=STORE`、单元值 `[1,1,0,0]`。
