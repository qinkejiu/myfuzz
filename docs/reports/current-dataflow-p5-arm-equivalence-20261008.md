# P5 同条件双臂等价判定（`arm_equivalence.v1`）

本报告交付 **一个** 只读比较器：给定两个已保存 run 目录，回答"这两条臂是否等价、在哪一个窗口内、在哪几个确切字段上等价"，并且当窗口不可比较时**失败关闭**（fail-closed）。它补齐了 P5 剩余项"覆盖等价与同类搜索质量比较"中此前缺失的部分：已有工具分别回答"同等预算下 operator 收益"（`scripts/compare_p4_operator_benefit.py`）、"continuous vs cold 的效率"（`scripts/bench_first_step_paired.py` / `myfuzz.scenario.paired_efficiency`）和"断言分类"（`scripts/report_p5_assertion_classes.py`），但没有任何一个给出**带明确等价定义、逐字段计数、以及无法比较时拒绝**的等价声明。

新增文件（全部为新文件，未修改任何既有源码、配置、RTL 或脚本）：

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/arm_equivalence.py` | 比较器模块，schema `arm_equivalence.v1`；单次流式扫描，有界内存 |
| `scripts/compare_arm_equivalence.py` | CLI；退出码 `0` 已比较 / `2` 拒绝 / `1` 读取错误 / `3` 用法错误 |
| `tests/scenario/test_arm_equivalence.py` | 26 个聚焦测试（含 1 个真实已保存配对只读测试） |
| `docs/reports/arm-equivalence-20261008/*.json` / `*.md` | 五对真实配对的原始判定文档（证据附件） |
| `docs/reports/current-dataflow-p5-arm-equivalence-20261008.md` | 本报告 |

本工具不启动任何 RTL/Verilator/cargo/fuzz 作业；只读取 `receipts.jsonl`（逐行流式）、`report.json`、`online_run_identity.json`、`decoder_manifest.json`，**从不打开** trace 容器。

---

## 1. 等价定义

### 1.1 可比较窗口（比较窗口）

> **共享原始输入前缀**：按 receipt 顺序逐例比较 `raw_sha256`，取两臂完全相同的最长前导段。

搜索本身因变异决策而必然分叉，所以这个前缀是**唯一**可做逐例比较的区域。窗口之外不做过任何逐例断言。

- 窗口长度同时受两臂用例数上限与 `--max-window-cases` 上限约束（默认 200000，触顶则 `truncated_by_window_case_cap=true`，claim 直接为假）。
- 窗口仅仅是**字节级**输入同一性，不是 source/plan 同一性：同一个 `raw_sha256` 可能由不同 source 产生（见 §3.2 path-switch 的实证）。
- `online_raw_records_hex` 作为交叉校验字段一并比较，用于确认逐例字节内容（而不仅是哈希）一致。

### 1.2 声明字段集（projection）

| 族 | 判定字段（verdict-role） | 上下文字段（context-role，只报告不参与族判定） |
|---|---|---|
| `status` | `status` | — |
| `effective_genome` | `effective_genome_sha256`, `genome_sha256` | — |
| `path` | `path_id`, `applied_path` | — |
| `direction` | `direction` | — |
| `applied_sources` | `applied_sources`, `applied_source_ids`, `source_id` | — |
| `checker_violations` | `violations` | `rejection`, `error` |
| `coverage` | `coverage_hex` | — |
| `local_ticks` | `local_ticks`, `total_local_ticks` | — |

`context` 字段（按契约在多数用例里为 null 的诊断字段）**不能**定义族判定：否则每个族都会因条件性 null 而变成 `unknown`，判定失去信息量。但它们的逐字段计数、缺失计数与 case 下标仍然完整报告。

### 1.3 逐例逐字段判定

每例每个声明字段落到五种状态之一，计数保存在 JSON 中（绝不是单一布尔）：

| 状态 | 含义 |
|---|---|
| `equal` | 两侧都非 null，且规范化 JSON 字节完全相同 |
| `unequal` | 两侧都非 null，但规范化字节不同 |
| `missing_left` / `missing_right` / `missing_both` | 任一侧（或两侧）为 null / 键缺失 |

**缺失永远不等于相等**：显式 JSON `null` 与键缺失都算缺失。字段判定规则：

- `unequal > 0` ⇒ `not_equivalent`；
- `unequal = 0` 且有任一侧缺失 ⇒ `unknown`（无法证明）；
- 某字段在窗口内两臂全部缺失 ⇒ `not_applicable`（无信息，明确列出，不计入相等）；
- 其余（全部 `equal`）⇒ `equivalent`。

族判定取该族所有 in-scope 判定字段中最差的一个（`not_equivalent > unknown > equivalent`），并给出驱动字段名。若某族的声明语义字段（`record_semantics`、`total_local_ticks_semantics`、`clock_model`）在两臂被声明且不同，该族强制为 `unknown`（量纲不同，不可比）。

### 1.4 输出等价声明 `output_equivalence.claimed`

`claimed=true` 当且仅当下列条件**全部**成立（逐条列出 `satisfied`）：

1. `window_computable`：窗口可计算；
2. `same_receipt_case_count`：两臂 receipt 用例数相同；
3. `window_covers_left_arm` / `window_covers_right_arm`：窗口覆盖两臂全部用例；
4. `window_not_truncated`：未触发窗口上限；
5. `every_inscope_field_equivalent`：所有 in-scope 声明字段全部相等；
6. `every_family_equivalent`：没有 `not_equivalent`，也没有 `unknown` 族。

`claimed` 由 `evidence_status="compared"` **绝不**自动成立；未声明的原因逐条写入 `not_claimed_reasons`。

### 1.5 失败关闭的拒绝（非零退出 + 精确原因）

| 拒绝码 | 触发条件 |
|---|---|
| `no_receipts` | 任一臂缺少 `receipts.jsonl` |
| `empty_receipts` | 任一臂 0 条可解码用例 |
| `decoder_manifest_undecodable` | 无法解出 decoder 身份（report 与 manifest 都没有） |
| `decoder_manifest_inconsistent` | 同一臂内 `report.json:decoder_manifest_sha256` 与 `decoder_manifest.json` 规范化摘要互相矛盾 |
| `decoder_manifest_mismatch` | 两臂 decoder manifest 不同 |
| `source_identity_undecodable` | 无法解出 source 身份（`source_files_sha256` / `component_identity_sha256`） |
| `source_identity_mismatch` | 两臂 source 身份不同 |
| `zero_shared_prefix` | 共享前缀长度为 0 |

拒绝时仍会写出完整诊断（两臂用例数/状态分布、身份、预算、首个分叉用例的下标与两侧 `raw_sha256`），只是不做任何等价断言。

预算（`max_tests`、`duration_seconds`、`feedback_interval`、`search_seed`、`global_mutation_seed`）只报告不拒绝：不同预算的两臂仍可在共享窗口内比较，但不能声明输出等价。

---

## 2. 五对真实运行的结果

命令（对每一对；`--json-out/--markdown-out` 指向 `docs/reports/arm-equivalence-20261008/`）：

```bash
PYTHONPATH=src python3 scripts/compare_arm_equivalence.py <LEFT_DIR> <RIGHT_DIR> \
  --left-label <L> --right-label <R> --json-out ... --markdown-out ... --quiet
```

| 配对（左 vs 右） | 用例 左/右 | 共享窗口 | 窗口覆盖 | `equivalent` | `not_equivalent` | `unknown` | `claimed` | 退出码 |
|---|---|---|---|---|---|---|---|---|
| sequence-edit insert vs delete | 8 / 8 | **0** | 无 | — | — | 8（窗口空） | false | **2（拒绝）** |
| path-switch OFF vs ON | 96 / 96 | 1 | 1/96 与 1/96 | status, checker_violations, coverage, local_ticks | effective_genome, path, direction, applied_sources | — | false | 0 |
| initial-RAM OFF vs ON | 96 / 96 | **96（全覆盖）** | 96/96 与 96/96 | status, direction, applied_sources, checker_violations, coverage | — | effective_genome, path, local_ticks | false | 0 |
| format2 JSONL vs zlib | 77 / 81 | 77 | 77/77 与 77/81 | status, direction, applied_sources, checker_violations, coverage | — | effective_genome, path, local_ticks | false | 0 |
| paired continuous vs cold | 24 / 24 | **24（全覆盖）** | 24/24 与 24/24 | status, effective_genome, path, direction, checker_violations | applied_sources, coverage, local_ticks | — | false | 0 |

五对的身份与预算前置条件全部成立：`decoder_manifest_sha256`、`source_files_sha256`、`component_identity_sha256`、`targets_sha256` 两两相同；`max_tests` / `duration_seconds` / `feedback_interval` / `search_seed` / `global_mutation_seed` 也两两相同。**没有任何一对可以声明输出等价**——原因是逐对不同，下面逐对说明。

### 2.1 sequence-edit insert vs delete：拒绝（`zero_shared_prefix`）

两臂身份与预算完全相同（同 seed 20261008、同 8 例、同 decoder），但**第 0 例的原始输入就已不同**：

- 左（insert）`raw_sha256=0e82fe6fcf188adfd352dce52b6a0c53cca9418b2d05c1d5ee4c7cba781425d3`
- 右（delete）`raw_sha256=d99079771646e93f615fe282946be2a95dd8d971082e070aa2612170aa311361`

因此共享窗口长度为 0，逐例等价**无法定义**，退出码 2。这是诚实答案而不是缺陷：insert/delete 两种编辑算子从第 0 例起就产生不同输入序列，任何"逐例等价"的说法都是伪造的。整臂聚合层面的比较仍可由 `scripts/compare_p4_operator_benefit.py` 给出（它显式声明 `per_case_pairing_scope="none"`）。

### 2.2 path-switch OFF vs ON：窗口只有 1 例，且该例已有 8 个字段不等价

两臂 96 例，但 `raw_sha256` 从第 1 例起就分叉 ⇒ 窗口 = 第 0 例。这是很有价值的一对，因为它同时暴露了"窗口是字节级同一性"的边界：

| 字段 | 左（OFF） | 右（ON） | 判定 |
|---|---|---|---|
| `raw_sha256` | `af5570f5…83dfc` | `af5570f5…83dfc` | 相同（窗口成立） |
| `online_raw_records_hex` | `["0000000000000000"]` | `["0000000000000000"]` | 相同（字节交叉校验 1/1 一致） |
| `online_source` | `gpio_b.external_pin8`，`kind=source_event` | `cpu.online_instruction`，`kind=instruction` | **不同** |
| `operator_id` | `external_event` | `rv32i:NOP` | **不同** |
| `path_id` / `applied_path` | `7943a650…975b8` / 1 | `542b422a…2ed8` / 0 | **不同** |
| `direction` | `IP_TO_CPU_TO_IP` | `CPU_TO_IP_TO_CPU` | **不同** |
| `applied_sources`（含 `applied_source_ids`、`source_id`） | `["gpio_b.external_pin8"]` | `["cpu.online_instruction"]` | **不同** |
| `status` / `violations` / `coverage_hex` / `local_ticks` | `complete` / `[]` / `00000000` / 96 tick | 同左 | 相同 |

即：**相同的 8 字节原始输入在两臂被不同的 source 解释、走不同的 path/direction**；族判定 `effective_genome`、`path`、`direction`、`applied_sources` 为 `not_equivalent`（各自给出不等例下标 `[0]`），其余 4 族在 1/96 的窗口内 `equivalent`。窗口覆盖率条件为假，`claimed=false`（"4 个族等价"只对 1 例成立，几乎是空声明，报告显式写出 `window 1 of left 96`）。

### 2.3 initial-RAM OFF vs ON：96 例全窗口，5 族等价、3 族 `unknown`（不是不等价）

关键事实：两臂 **96/96 例的 `raw_sha256` 完全相同**，逐例字节交叉校验 96/96 一致；总预算、seed、身份全部一致（右臂 `report.json:initial_ram_data.adopted=1`）。逐族结果：

- `equivalent`：`status` 96/96、`direction` 96/96、`applied_sources`（3 字段各 96/96）、`checker_violations.violations` 96/96、`coverage.coverage_hex` 96/96。
- `unknown`（无任何不等，只是读不到）：`effective_genome`、`path`、`local_ticks`——第 15、30 例是 `input_invalid`，两臂都记录 `path_id=null`、`effective_genome_sha256=null`、`local_ticks=null`。94 例可读且全部相等，2 例不可读。
- `not_equivalent`：无。
- `claimed=false`：唯一原因是 `every_inscope_field_equivalent`/`every_family_equivalent` 为假。

这正是"缺失即 `unknown`、绝不静默判等"的实证：即使两臂在同样的 2 例上**对称地**不可读，我们也不把它算作相等。对初始 RAM 数据这一因素而言，本比较器能说的最强结论是"在 94 个可观测用例上，声明的逐例投影完全一致"；更强的话需要让 `input_invalid` 用例也带上 path/genome 记录（当前记录契约不提供）。

### 2.4 format2 JSONL vs zlib：共享窗口内字段级一致，但两臂用例数不同（77 vs 81）

两臂同为 120 秒 / `max_tests=120` / seed 20261007，身份全同（同 decoder、同 source、同 targets）。结果：

- 共享窗口 = 77 例（等于 JSONL 臂全部用例，即 zlib 臂的前 77 例）；第 77 例处 `divergence_reason="left_arm_ended"`（JSONL 臂先结束）。
- 窗口内 5 族 `equivalent`，3 族 `unknown`（同 §2.3 的 2 例 `input_invalid` 不可读），**0 族 `not_equivalent`**。
- 臂级差异：`report.json:tests` = 77 vs 81；`same_declared_case_count=false`，`same_declared_budget=true`。
- `claimed=false`，原因三条：`same_receipt_case_count`、`window_covers_right_arm`、`every_inscope_field_equivalent`。

**可以说的**：在共同完成的 77 例上，两种 trace 容器的逐例声明投影一致（同一预算、同一 seed、同一身份），容器格式本身没有改变这 8 个族的记录值。**不可以说的**：两臂"等价"——它们连用例数都不同（77 vs 81），窗口没有覆盖 zlib 臂；这两条运行在 120 秒内完成的搜索工作量不同，而**原因无法从这些 artifact 判定**（可能是容器写入开销改变了有效搜索时间，但本比较器不做这种因果推断）。

### 2.5 paired continuous vs cold：24 例全窗口，3 族 `not_equivalent`，差异字段精确到例

两臂 24/24 例原始输入相同、身份与预算相同（`decoder_manifest_matches_continuous=true`，冷启动臂自带核验 `raw/status/genome/path/source` 各 24/24 兼容）。本比较器在**声明的完整投影**上给出：

| 族 | 判定 | 驱动字段与确切差异 |
|---|---|---|
| `status` | equivalent | `status` 24/24 |
| `effective_genome` | equivalent | `effective_genome_sha256`、`genome_sha256` 各 24/24 |
| `path` | equivalent | `path_id`、`applied_path` 各 24/24 |
| `direction` | equivalent | `direction` 24/24 |
| `checker_violations` | equivalent | `violations` 24/24 |
| `applied_sources` | **not_equivalent** | `applied_sources` 24/24 相等、`source_id` 24/24 相等，但 `applied_source_ids` 15 相等 / **9 不等**：例 `[1,3,6,10,14,15,17,18,22]`（cold 臂这 9 例为 `[]`，其中 8 例 `applied_sources` 与 `source_id` 都表明 source 已施加，第 22 例 cold 为 `["gpio_b.external_pin8"]` 而 continuous 为 `["cpu.online_instruction","gpio_b.external_pin8"]`） |
| `coverage` | **not_equivalent** | `coverage_hex` 2 相等 / **22 不等**（不等例很多，报告只列前 20 个下标 `[1..20]`，`case_indexes_truncated=true`；如例 2：continuous `00010101` vs cold `00010000`） |
| `local_ticks` | **not_equivalent** | `local_ticks` 与 `total_local_ticks` 各 9 相等 / **15 不等**，例 `[1,2,3,6,8,9,10,12,13,15,16,17,20,21,22]`（如例 1：`{"gpio_a":36}`,100 vs `{"gpio_a":32}`,96） |

`claimed=false`（`every_inscope_field_equivalent` 与 `every_family_equivalent` 为假，且逐字段不等例下表列出）。

与冻结 bundle 自身声明的关系：`cold_start.json:comparison_scope = "startup_cost_only_not_coverage_equivalence"`，它只核验 selection 兼容性（raw/status/genome/path/source 各 24/24）。本比较器的结论与之**不矛盾且互补**：selection 维度确实兼容，而 `coverage`、`local_ticks`、`applied_source_ids` 这三个族在这 24 例上并不等价。这一对是"给出不等价 + 精确差异字段比给出等价更有价值"的直接例证。

---

## 3. 声明投影之外的字段（`outside_declared_projection`）

声明投影之外的 receipt 字段同样被逐例比较（有界：默认最多跟踪 64 个字段），按 `timing` / `run_bookkeeping` / `other` 分类报告，但**不参与族判定、也不参与 claim**：

| 配对 | 差异类计数（timing / run_bookkeeping / other） | 差异字段 |
|---|---|---|
| seq-edit（拒绝，窗口 0） | 0 / 0 / 0 | 无 |
| initial-RAM | 3 / 1 / **0** | 3 个 timing map + `run_id` |
| format2 | 3 / 1 / **0** | 3 个 timing map + `run_id` |
| path-switch | 3 / 2 / **7** | 另有 `online_source`、`operator_id`、`target_id`、`flow_id`、`source_action`、`source_selection_reason`、`semantic_sha256` 在唯一窗口例上不同 |
| paired continuous vs cold | 3 / 3 / **5** | 另有 `semantic_sha256`（23/24）、`interaction_deferred`/`interaction_feature_deltas`/`interaction_new_features`/`interaction_source_gains`（各 1/24，例 15） |

解读：initial-RAM 与 format2 两对在窗口内**没有任何** `other` 类字段差异，说明"5 族等价"不是投影选得巧；而 path-switch 与 paired 两对存在 `other` 差异，与它们 `not_equivalent` 的族判定一致。

---

## 4. 边界：`equivalent` 不声明什么

1. **不声明搜索质量**。`equivalent` 只覆盖共享窗口内的 8 个声明字段，对目标命中数、覆盖新颖度、链证书产出、闭环收益、每秒新覆盖等**完全不作断言**；这些量的同条件比较属于 `compare_p4_operator_benefit.py` / `acceptance_metrics` / `chain_certificates` 的职责。
2. **不覆盖 trace 容器**。三条 trace 容器（`online_final_trace.json`、`online_events.jsonl`、`online_events.zlib`）从未被打开；本工具不说"事件流相同"。
3. **`claimed=true` 是强条件**。它要求窗口覆盖两臂全部用例、用例数相同、未触窗口上限、且全部 in-scope 声明字段逐例相等；`evidence_status="compared"` 绝不蕴含它。
4. **窗口是字节级同一性，不是 source/plan 同一性**。§2.2 已给出反例：同一 `raw_sha256` 与同一原始记录字节可以来自不同 source 与不同 path。因此窗口长度必须与逐字段表、`outside_declared_projection` 一起读。
5. **`not_equivalent` 的驱动字段必须看清**。例如 paired 对的 `applied_sources` 族：真正的不等在重复 id 字段 `applied_source_ids` 上，而 `applied_sources`/`source_id` 完全一致（且 cold 臂内部自相矛盾）。这类差异可能是记录路径差异而非 DUT 行为差异——本工具只报告"记录不等价"，不做 DUT 因果判定。
6. **`unknown` 是"证据不足"而不是"相等"**。任一臂或两臂缺失/为 null 的字段永不判等，即使两侧对称缺失。
7. **窗口是顺序前缀，不是集合交集**。后段偶然相同的用例不在窗口内，也不做任何断言。
8. **只读已保存 artifact**。不启动 RTL/Verilator/cargo/fuzz client；不修改任何 run 目录。
9. **声明投影是固定的**。当前投影不含 `semantic_sha256`、`slot`、`buffer_id`、交互增量等字段；它们被 §3 显式报告，但改变 claim 需要先改变投影定义。

---

## 5. 复现证据

### 5.1 TDD（先红后绿）

```bash
# RED：模块尚不存在
PYTHONPATH=src python3 -m pytest tests/scenario/test_arm_equivalence.py -q
#   ERROR ... ModuleNotFoundError: No module named 'myfuzz.scenario.arm_equivalence'

# 补充"投影外字段"用例后的 RED（实现前）
PYTHONPATH=src python3 -m pytest tests/scenario/test_arm_equivalence.py -q -k "undeclared"
#   2 failed（TypeError: compare_arms() got an unexpected keyword argument 'max_undeclared_fields'）

# GREEN
PYTHONPATH=src python3 -m pytest tests/scenario/test_arm_equivalence.py -q
#   26 passed
```

覆盖点：完全相同的两臂 ⇒ `claimed=true`；单字段不同 ⇒ 该族 `not_equivalent` 且 claim 为假（并给出不等 case 下标）；窗口外差异不计入 tally；单侧缺失 ⇒ `unknown`（不是相等）；两侧对称缺失 ⇒ `unknown`（不是相等）；条件性 context 字段不能翻转族判定；无共享前缀 / decoder manifest 不同 / source 身份缺失或不同 / 无 receipts / 空 receipts ⇒ 各自拒绝码；窗口计算与首分叉；用例数不同阻断 claim；窗口上限阻断 claim；投影外字段报告及其跟踪上限；连续两次比较字节相同；真实已保存配对只读比较。

### 5.2 确定性

五对真实配对各自重复运行（相同参数），输出 JSON **逐字节相同**（`diff -q` 全部一致）。文档不含时间戳、不含比较耗时、所有列表按声明顺序或字典序构造。

### 5.3 有界读取

| 证据 | 数值 |
|---|---|
| 最坏 trace 环境（`p5-format2-jsonl` 的 `online_events.jsonl` = 493 MB；`p5-format2-zlib` 的 `online_events.zlib` = 37 MB） | 比较峰值 RSS **23 440 KiB ≈ 22.9 MiB**、wall 0.09 s |
| 38 MB `online_final_trace.json`（path-switch） | 峰值 RSS **23 184 KiB ≈ 22.6 MiB**、wall 0.09 s |
| 文档自证的读取集合 | 每臂仅 `receipts.jsonl`、`report.json`、`online_run_identity.json`、`decoder_manifest.json` |
| `read_scope.full_trace_loaded` | `false`（`online_final_trace.json` / `online_events.jsonl` / `online_events.zlib` 均不在读取列表内） |

内存上界来自：单次 lockstep 流式扫描（不保留任何 receipt 行）、每字段不等的 case 下标列表上限 20、窗口用例上限 200000、投影外字段跟踪上限 64。

---

## 6. 限制与未覆盖范围

1. **只有一种窗口定义**：共享 `raw_sha256` 前缀。不做集合交集、不做按 `case_id` 对齐、不做"后段重同步"。序列编辑类算子（insert/delete）因此必然被拒绝（§2.1）——这是设计选择，不是遗漏。
2. **身份要求严格**：source/decoder 身份不可解码即拒绝。若将来出现没有 `online_run_identity.json` 的 run 目录，本工具会拒绝而不是猜测（可用 `compare_p4_operator_benefit.py` 做整臂聚合）。
3. **`applied_source_ids` 这类重复字段的语义未在 artifact 中声明**，因此"记录不等价"未必等于"行为不等价"；报告已逐字段标出驱动字段，但不做因果解释。
4. **没有对五对之外的配对跑过**：本报告只覆盖 §2 的五对；其它 run 目录（如 `p5-format-zlib-20261007-online`、`current-dataflow-p5-zlib-chunks-4-online`、`p3-ram-prereq-*` 等）未纳入，未做任何声明。
5. **claim 只针对声明投影**：`semantic_sha256`、`slot`、`buffer_id`、交互增量等不在投影内（§3 已逐例报告其差异）。若要提升为 claim 条件，需要先扩展 `FAMILY_FIELDS` 并重新跑测试。
6. **不判定"同类搜索质量"本身**：本工具回答的是"两条臂在窗口内是否字段等价"，而不是"哪条臂搜得更好"。P5 的搜索质量比较仍需 `acceptance_metrics` / `chain_certificates` / `edge_provenance` 等既有度量配合使用；本工具的价值是为这些比较提供**前置的同条件检查**：如果两条臂连声明投影都不等价，把它们当作"同条件重复"来对比质量就是不成立的。
7. **本报告未运行任何 RTL/Verilator/fuzz 作业**，全部数字来自上表所列已保存 run 目录的只读读取；并发进行的真实 RTL 窗口不受影响。
