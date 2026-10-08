# P4 在线指令序列编辑（插入 XORI / 删除 ADDI）：真实门禁计划与软件证明

日期：2026-10-08。对象：`src/myfuzz/scenario/rv32i_sources.py::decode_instruction_fragment` 的在线序列编辑算子（choice 2 且熵字节 6 的高两位 `edit = entropy[6] & 0xC0`）：`0x40` 保持两字基序列 `LUI rd; ADDI rd,rd,imm12`，`0x80` 删除可选 `ADDI`（4 字节），`0xC0` 在两字之间插入 `XORI rd,rd,imm12`（12 字节）。软件语义已由 [序列编辑软件门禁](current-dataflow-p4-sequence-edit-software-20261007.md) 证明；本文件交付**真实门禁的准备件**（新脚本 `scripts/run_p4_sequence_edit_gate.py`，只读、不运行 RTL）、**raw 选择的软件证明**与**诚实的状态声明**。

**本文件不声称任何真实 RTL 结果。** 本文所有结论来自冻结源码、已保存的运行产物与软件证据；真实门禁尚未运行。

---

## 1. 门禁要证明什么

真实门禁要补的缺口是：**没有任何证据表明真实在线会话曾按确定性的原始输入提出并退休过一个插入（12 字节）或删除（4 字节）的片段**。门禁把它拆成六条可复算的判据：

| 判据 | 要证明的内容 | 证据位置（运行自身产物） |
| --- | --- | --- |
| `deterministic_seed_injection` | `seed.bin` 是本门禁声明的某个 8 字节 raw，且该 raw 作为一例的 `online_raw_records_hex` 出现在 `receipts.jsonl`：声明输入确实经 shipped seed 机制到达在线解码器 | `<run>/seed.bin`、`receipts.jsonl` |
| `operator_case_admitted` | 至少一例被接纳的指令 case，其 `online_source.data_hex` 正是用**该例自己的 raw** 经 shipped `decode_instruction_fragment` 复算出的 insert(12B)/delete(4B) 片段，并给出 `case_id`/`action_id`/`candidate_id` | `receipts.jsonl`、`online_plan.json` |
| `fragment_fetch_evidence` | 该 case 的**每个 4 字节片段字**都出现在运行自身的真实取指证据中：`memory_read`（`transaction.channel_id == "instr"`）或 `instr_response`，地址等于片段字地址、字节等于该字、writer 身份等于该 case 的 `action_id`；另有 trace 的 `instruction_source` 物化事件 | trace 事件 |
| `fragment_retirement_evidence` | 在 RVFI 退休观测下，**每个片段字**都有 `cpu_retirement_match`：`status="accepted"`、`instruction_origin_status="typed_writer_refs"`、`source_refs == [该 case 的 action_id]`、`pc`/`insn` 等于该字 | trace 事件 |
| `reservation_boundary` | plan 自身的 `instruction_slots` 与逐例游标走查证明没有片段越过声明的 `instruction_end`，累计接纳字节不超过保留区 | `online_plan.json`、`decoder_manifest.json` |
| `fresh_replay_matches` | 若运行旁存在 fresh replay 日志，其 `matches` 必须为 `true`（不存在时记 `not_applicable`，不据此判失败） | 运行旁的 replay 日志 |

判据只使用运行**自己**的产物：不信任报告结论，不引入外部数值。`verify` 还会用 shipped `SourceAdmission` 校验计划接纳行自身的 `admission_id`，并用 `OnlineInstruction` 的规范化摘要复算 `input_sha256`（规则见 `src/myfuzz/scenario/session_runtime.py::_case_admissions`），把「回执片段」与「计划接纳」按字节绑定；`decoder_manifest.json` 若与当前 shipped Ibex 在线声明（`make_ibex_pulp_dual_source_online_decoder(bootstrap=..., result_slot_readback=True).document()`，规范 JSON sha256 `625710f477121c08abdae046710efe5e168948f50b073aba6f0e95fd051a0e64`）不同，则片段无法归因到冻结算子，判据只能记 `unproven`。

---

## 2. raw 选择的软件证明（真实解码器）

三个声明 raw 均满足：字节 2 = 0（直接选源字节指向指令源 `cpu.online_instruction`，索引 0）；字节 3 mod 5 = 2（choice 2 = 算术/序列编辑分支）；字节 4 的高两位即分支选择位；寄存器 `rd = 1 + entropy[1] % 31 = x7`（t2，非 x1/x2）。`entropy` 按在线解码器的既有布局取 `(raw[3:] * k)[:12]`（`online_case_decoder._case_entropy`）。

| arm | raw（8B hex） | entropy[6]&0xC0 | 片段（hex） | 长度 | `instruction_operator_id` | 逐字读数 |
| --- | --- | --- | --- | --- | --- | --- |
| insert | `00000007c00200fc` | `0xC0` | `b72300c093c3c37f93832300` | 12 B | `rv32i:LUI+XORI+ADDI` | `LUI x7,0xfc0002` / `XORI x7,x7,-0x804` / `ADDI x7,x7,2` |
| delete | `00000011a10100aa` | `0x80` | `b71300a0` | 4 B | `rv32i:LUI` | `LUI x7,0xaa0001` |
| base（对照） | `0000003e63010106` | `0x40` | `b713106093831310` | 8 B | `rv32i:LUI+ADDI` | `LUI x7,0x60101` / `ADDI x7,x7,0x101` |

软件证明（`tests/scenario/test_p4_sequence_edit_gate.py` 全部通过）：

1. **分支选择位**：同一 raw 只改字节 4 的高两位，片段长度依次为 `0x00→4`、`0x40→8`、`0x80→4`、`0xC0→12`；在**操作数完全相同**的三条变体（`r4 = 0x44/0x82/0xC0`，均给出 `rd = x7`）上，插入片段 `[0]`、`[2]` 等于基序列的两个字，删除片段等于基序列 `[:1]` —— 即插入是把 `XORI` 加到两字之间、删除是去掉可选的 `ADDI`，不搬移既有字。
2. **真实解码器一致**：`make_ibex_pulp_dual_source_online_decoder()` 与 shipped Ibex 在线入口点所用的 `... (bootstrap=..., result_slot_readback=True)` 两个声明对三个 raw 给出**相同**片段；重复解码与重复构造解码器结果逐字段相同（确定性）。
3. **路径抽签有裕度**：指令路径与 pin8 路径在首例权重下同为 `104`（`_online_baseline_weights`：`weight * (8 + 64 + 32)`），抽签域 = 208，指令路径占下半区；三个 raw 的 `selector` 为 52 / 56 / 52，`margin` 为 51 / 47 / 51，即使首例权重发生小幅变化仍落在指令路径。
4. **客户端变异字节像**：三个 raw 的字节 3..7 与 shipped Rust 客户端 `mutation/scenario.rs::ScenarioDecisionMutator::apply` 的单记录写入规则一致（`[0]=template`、`[1]=path`、`[2]=source`，`[3..7]` 由同一个 decision word 导出），即本门禁声明的 raw 不是自造形状，而是该客户端在指令源上会写出的字节布局。

---

## 3. raw 如何到达客户端（shipped 机制，逐条源码复核）

`plan` 每次调用都重新读取下列源码并逐条报告 `[OK]`，因此「raw 注入」不是本文的发明：

```text
scripts/run_ibex_pulp_online.py        --initial-ram-record <hex>
scripts/run_ibex_pulp_online.py        seed_records=(initial_ram_record,)
src/.../scenario_rfuzz_live.py         "seed must contain complete eight byte records"
src/.../scenario_rfuzz_live.py         (output / "seed.bin").write_bytes(b"".join(seed_records))
src/.../scenario_rfuzz_live.py         "--seed-input"
third_party/.../fuzzer/src/main.rs     mutation::identity(input)
third_party/.../fuzzer/src/main.rs     let expected = test_size.input * start_cycles;
third_party/.../fuzzer/src/mutation/scenario.rs  output[record + 3] = (decision & 255) as u8;
```

链路：`--initial-ram-record <16 hex>` → `seed_records=(record,)` → `<run>/seed.bin`（8 字节）→ 客户端命令 `--seed-cycles 1 --seed-input <run>/seed.bin` → `fuzz_one(server, &starting_seed)` 用 `mutation::identity` 把**这 8 字节原样**作为第一例提交 → 宿主 `_execute_online_batch` 取 `raw = b"".join(records)` 解码，并把 `online_raw_records_hex[0]` 写进回执。已保存运行中 `seed.bin == 第一例 online_raw_records_hex[0]`（例如 `runs/current-dataflow-p4-candidate-20261007-online`：`seed.bin=0000000000000000` 且首例 raw 相同），与该链路一致。

注意（诚实边界）：seed 机制保证**第一例**的 8 字节是声明的 raw；随后客户端继续变异，其变异结果的字节 0..2 由 hint 的 `template/path/source` 决定、字节 3..7 由 decision 导出 —— 本门禁不声称任意变异都会再次命中该分支，这不是本门禁的证明目标。

---

## 4. 精确命令序列（准备件，未运行）

### 4.1 只读计划（可随时重跑）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_p4_sequence_edit_gate.py plan \
  > runs/p4-sequence-edit-plan-20261008.txt
```

`plan` 打印：三个 raw 与其片段/读数/路径抽签、seed 机制的逐条源码证据（含文件 sha256）、两条真实运行命令与两条 replay 命令、要读回的字段、六条判据与退出码。它**不写任何文件、不运行任何 RTL**（`--write` 可选地落盘计划 JSON）。

### 4.2 insert arm（12 字节片段）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/p4-sequence-edit-insert-20261008-cache \
  --output runs/p4-sequence-edit-insert-20261008-online \
  --seconds 25 --max-tests 8 --seed 20261008 \
  --cpu-retirement \
  --run-id p4-sequence-edit-insert-20261008 \
  --initial-ram-record 00000007c00200fc
```

### 4.3 delete arm（4 字节片段）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py run \
  --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz \
  --cache-dir runs/p4-sequence-edit-delete-20261008-cache \
  --output runs/p4-sequence-edit-delete-20261008-online \
  --seconds 25 --max-tests 8 --seed 20261008 \
  --cpu-retirement \
  --run-id p4-sequence-edit-delete-20261008 \
  --initial-ram-record 00000011a10100aa
```

### 4.4 fresh replay（每个 arm 用独立 cache）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_ibex_pulp_online.py replay \
  --cache-dir runs/p4-sequence-edit-insert-20261008-replay-cache \
  --plan runs/p4-sequence-edit-insert-20261008-online/online_plan.json \
  --trace runs/p4-sequence-edit-insert-20261008-online/online_final_trace.json \
  | tee runs/p4-sequence-edit-insert-20261008-online-replay.log
```

（delete arm 同理，替换名称与 raw。若某次运行因事件数 ≥ 100000 或使用 `--compressed-trace` 而保存为 `online_final_trace.meta.json`，`--trace` 应指向该 meta 文件；最终以运行自己的 `online_run_identity.json` 的 `identity.trace_file` 为准，shipped replay 也从它解析。）

### 4.5 验证（只读）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/run_p4_sequence_edit_gate.py verify \
  --run runs/p4-sequence-edit-insert-20261008-online \
  --replay-log runs/p4-sequence-edit-insert-20261008-online-replay.log
PYTHONPATH=src python3 scripts/run_p4_sequence_edit_gate.py verify \
  --run runs/p4-sequence-edit-delete-20261008-online \
  --replay-log runs/p4-sequence-edit-delete-20261008-online-replay.log
```

### 4.6 可选对照臂（base，8 字节，不是 PASS 条件）

`plan` 同时给出 `control_arm.run_command`（`--initial-ram-record 0000003e63010106`）。控制臂的作用是用同一 raw 形状证明 `edit=0x40` 仍产生 8 字节 `LUI+ADDI`，因此 insert/delete 不是无条件发生的；`verify` 只接受 insert/delete，所以控制臂按设计应判 `INCONCLUSIVE`，其价值在与 `raw_selection` 和回执片段字节对照。

---

## 5. 通过／失败判据与退出码

`verify` 的判据状态为 `proven` / `refuted` / `unproven` / `missing` / `not_applicable`，总判定：

| 退出码 | 判定 | 触发条件 |
| --- | --- | --- |
| 0 | `PASS` | 六条判据全部 `proven`（`fresh_replay_matches` 无日志时 `not_applicable`） |
| 1 | `FAIL` | 任一判据被运行自身证据**反驳**：声称的片段无法用该例 raw 复算；取指字节与该字不符；该字退休观测是别的 insn；片段越过 `instruction_end` 或游标不连续；接纳行 `input_sha256`/`case_id` 与回执不符；该例未接纳；replay 日志 `matches=false` 或其 `matches` 不可解析 |
| 3 | `BLOCKED` | 必需产物缺失或不可解析：`receipts.jsonl`、`online_plan.json`、`decoder_manifest.json`、`report.json`、`seed.bin`、trace（含显式指定的 replay 日志不存在） |
| 4 | `INCONCLUSIVE` | 产物可读但不足以证明：没有 insert/delete 例；`seed.bin` 不是声明的 raw；片段未被取指；运行未开启 RVFI 退休观测（`--cpu-retirement`）；解码声明不是 shipped 声明；运行未正常结束 |

`--allow-unseeded` 把「必须由声明 raw 触发」这一条从 `unproven` 改为 `not_applicable`（只放宽这一条，其余判据不变），用于事后审计由搜索命中的运行；若 seed 是声明 raw 却从未作为任何一例的 raw 出现，仍判 `FAIL`。

实现细节（可复核）：`verify` 只用 shipped 代码做身份判据 —— `SourceAdmission.from_document` 校验接纳行自哈希，`OnlineInstruction` + 规范化 JSON 摘要复算 `input_sha256`，`decode_instruction_fragment` 复算片段；trace 通过 shipped `JsonlEventView` / `ZlibChunkEventView` 惰性读取（897 MB 的真实 JSONL 运行可在数分钟内完成一次扫描），不支持的事件流按 `BLOCKED` 处理。`--allow-unseeded` 可放宽「必须由声明 raw 触发」这一条，用于事后审计非播种运行。

---

## 6. 软件证据（TDD，RED → GREEN）

先写测试、后写实现（`scripts/run_p4_sequence_edit_gate.py` 当时不存在）：

```text
$ cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest tests/scenario/test_p4_sequence_edit_gate.py -q -p no:randomly
29 failed in 0.57s          # RED：脚本尚未实现（load_script 明确报出缺失路径）
```

实现后同一定向组合（含相邻的序列编辑/XORI/在线首选路径测试）：

```text
$ cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
    tests/scenario/test_p4_sequence_edit_gate.py \
    tests/scenario/test_rv32i_sequence_edit.py \
    tests/scenario/test_rv32i_xori_mutation.py \
    tests/scenario/test_online_path_first_selection.py -q -p no:randomly
63 passed                   # GREEN（其中新门禁测试 32 项；复跑一致）
```

新测试覆盖：三个 raw 的真实解码证明、分支选择位与「插入在两字之间／删除可选 ADDI」的结构关系、客户端变异字节像、路径抽签裕度、解码确定性、seed 机制的源码复核（含被篡改源码必须报 `verified=false`）、六条判据在「真实形状」合成产物上的通过路径（JSON / JSONL+meta / zlib 三种 trace 格式、`memory_read` 与 `instr_response` 两种取指证据）、以及每一条 fail-closed 路径（缺产物 `BLOCKED`、未触及算子／未取指／无 RVFI／未播种／异声明 `INCONCLUSIVE`、取指字节不符／退休字不符／越界／被拒／未复算／replay 不一致 `FAIL`）、`verify` 的确定性与只读性、`plan` 的只读性与命令内容。

---

## 7. 诚实状态声明（重要）

1. **本门禁尚未产生任何真实 RTL 结论。** 本文不含 `PASS`；`verify` 在真实运行出现前没有可判定的 insert/delete 证据。
2. **已保存运行里最强的真实证据只到「提出 + 取指」，未到「退休」。** 用 `--allow-unseeded` 事后审计它时，六条判据里五条已满足（`operator_case_admitted`/`fragment_fetch_evidence`/`reservation_boundary`/`fresh_replay_matches` 为 `proven`，`deterministic_seed_injection` 为 `not_applicable`），唯一 `unproven` 的是 `fragment_retirement_evidence`。 用本门禁对 `runs/current-dataflow-p4-path-switch-long-on-20261007-online`（其 `decoder_manifest.json` 与当前 shipped 声明逐字节一致）实测：1103/1103 指令回执可由冻结算子复算，其中 **72 例 insert（12B）**、**58 例 delete（4B）**、72 例 base；被判据选中的 insert 例 `online-149-72fd583f7be5f51c19f946c8`（raw `00010148f4010a6f`，片段 `371ea0f0134efe86130e1ea0`，地址 `0x11720`）的**三个字全部**出现在真实指令通道取指证据中，writer 身份为该例自己的 `action_id`；保留区走查（27388 字节 < 126464 字节）无越界；旁置 replay 日志（需显式 `--replay-log runs/current-dataflow-p4-path-switch-20261007-logs/path_switch_long_replay.log`）报 `matches=true`。但该 trace 中 `cpu_retirement_match`、`instr_response`、`cpu_retire` 事件数均为 **0**（运行时未开 `--cpu-retirement`），且 `seed.bin` 是 8 个零字节：默认判定为 `INCONCLUSIVE`（exit 4），理由为「不是声明的播种实验」+「无 RVFI 退休观测」；加 `--allow-unseeded` 后只剩「无 RVFI 退休观测」一条 `unproven`（其余 `proven`/`not_applicable`），判定仍为 `INCONCLUSIVE`（exit 4）。换言之：**「提出并取指」已有真实证据，「退休」与「确定性原始输入」仍缺；本门禁给出的最短补证路径就是第 4.2/4.3 节两条带 `--cpu-retirement` 的播种运行**。
3. **注入机制是 seed，不是变异可达性。** `--initial-ram-record` 保证第一例就是声明的 8 字节；它不保证后续变异再次命中该分支。若 `verify` 发现 seed 被提交但没有产生携带声明片段的指令例（例如路径抽签落到 pin8 路径），会按 `FAIL` 精确报出，而不是含糊通过。
4. **已知风险（计划中已量化）**：(a) `--cpu-retirement` 需要 RVFI 认证包装器，`runs/p4-sequence-edit-*-20261008-cache` 首次会触发一次 Verilator 构建（时间成本在计划外，可改用已有 RVFI cache 目录）；(b) 删除臂只有 1 个字，其后紧跟尚未接纳的保留区字节，CPU 会进入既有设计里的取指/陷入等待路径（已保存的 p2-native RVFI 运行中 4 字节片段未出现 trap，风险低但不为零）；(c) 每条判据都要求**整段**片段（12B 的 3 个字或 4B 的 1 个字）都有取指与退休观测，窗口过短会得到 `INCONCLUSIVE` 而非 `PASS`。
5. **不在本门禁范围内的量**：本门禁不证明操作子对覆盖/闭环有效，不证明跨例数据流，不替代 P4 阶段验收；它只证明「真实在线会话确实提出、取指并退休了一个插入或删除的片段」这一条。

## 8. 交付物

- 脚本：`scripts/run_p4_sequence_edit_gate.py`（`plan` / `verify`，两者只读、不运行 RTL/Verilator/Rust/fuzz）
- 测试：`tests/scenario/test_p4_sequence_edit_gate.py`（32 项，RED→GREEN 见第 6 节）
- 本文件：`docs/reports/current-dataflow-p4-sequence-edit-real-gate-plan-20261008.md`
