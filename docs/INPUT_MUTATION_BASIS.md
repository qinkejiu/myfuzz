# 输入的变异依据

日期：2026-10-08。本文回答：**一次 testcase 的输入是怎么被变异出来的、每一步的依据是什么、不允许依据什么**。所有规则都指到具体代码位置，所有例子都取自真实运行的回执与 trace。

> testcase 的种类见 [testcase 的种类与数据流](TESTCASE_TYPES.md)；逐事件号的例子见 [testcase 与数据流](TESTCASE_AND_DATAFLOW.md)。

---

## 0. 一页结论

| 问题 | 答案 |
|---|---|
| 随机性从哪来 | **只有一处**：Rust fuzzer 客户端给出的原始 bit 串（每例 1～8 字节 raw record） |
| 随机串怎么变成输入 | 由**在线解码器**按声明解码：路径 → 源 → 载荷；解码是纯函数，不碰 harness、不碰内存 |
| 变异"应该"往哪走 | 由 **feedback 权重**决定（覆盖缺口 ＋ 使用次数 ＋ 历史增益，闭环开启时再加链证书能量） |
| 什么**不许**变 | 已绑定输入、固定输入、真实 Store/取指决定过的程序字节、真实 RTL 输出、会话内已物化的指令槽、非声明窗口 |
| 越界了怎么办 | 37 个版本化拒绝码，带精确 `code`/`pointer`；拒绝发生在**任何 RTL 命令之前**，且消耗为 0 |
| 依据本身算不算身份 | 算。**decode space**（解码器＋ISA 算子空间＋ownership＋依赖声明＋genome 方向…）被哈希进运行身份，改了它旧 bundle 就不能 replay |

一句话：**变异依据 ＝ 一处随机源 × 六道声明式约束闸门 × 一层反馈权重**；随机只决定"在允许集合里选哪个"，不决定"允许集合是什么"。

---

## 1. 随机源：raw record

| 项 | 说明 |
|---|---|
| 产生者 | 上游 Rust fuzzer 客户端（`third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz`） |
| 形态 | 每例一条 raw record，1～8 字节；上界由声明 `max_input_bytes=8` 决定 |
| 入口 | `scenario_rfuzz.py` 把 record 交给 `online_decoder.decode_candidate(raw, coverage_hints=weights)`（`:2029`） |
| 记录 | 回执里存 `online_raw_records_hex`、`raw_sha256`、`online_weights`、`source_selection_reason`、`path_id`、`source_id`、`candidate_id` |
| 边界 | 空或超长 → `decode.unbounded_input`；hint 非法 → `decode.bad_coverage_hint` |

**变异本身不做任何"智能"动作**：客户端只是给出字节，语义全部由下面的解码器赋予。

---

## 2. 六道约束闸门（"允许集合"是怎么定的）

顺序固定，**每一道都在 RTL 之前**：

```text
raw bytes
  │
  ├─① 路径闸门        选哪条声明路径（F4/F5…）
  ├─② 源闸门          选这条路径上的哪个声明源
  ├─③ 归属闸门        这些 bit 是否"可变异"（bound/fixed 直接拒绝）
  ├─④ ISA/算子闸门    指令必须是合法 RV32I，且只允许声明的算子与 MMIO 操作
  ├─⑤ 窗口/预算闸门   地址必须落在声明 MMIO 窗口；指令槽必须尚未物化且未耗尽
  └─⑥ 切换闸门（可选）声明式路径/源切换算子
  ▼
OnlineCase（一个源输入 ＋ advances）
```

| 闸门 | 依据（声明的来源） | 实现位置 | 违反时的拒绝码（节选） |
|---|---|---|---|
| ① 路径 | `OnlineDependencySource` 的 direction ＋ 依赖规则 `rules`；目标到源的 AND/OR 路径 | `dependency.py`、`online_case_decoder._decode_case` 路径选择 | `path.undeclared` |
| ② 源 | decoder 自己的 `sources` 声明（`OnlineSource`：`source_id`/`component`/`port`/`bit_offset`/`width`/`direction`/`path_id`/`weight`/`coverage_target_ids`） | `online_case_decoder` 源选择 | `path.source_mismatch` |
| ③ 归属 | 编译后的 ownership map（`source` / `bound` / `fixed`） | `ownership.py`、`online_case_decoder._mutation_source` | `ownership.bound_input`、`ownership.fixed_input`、`ownership.undeclared_field`、`ownership.range_exceeds_field`、`ownership.ambiguous_producer` |
| ④ ISA/算子 | `decode_instruction_fragment` 的合法算子空间 ＋ `allowed_mmio_operations`（默认 `LW`/`SW`/`SB`，本 wiring 加 `SLLI/SRLI/SRAI` 与结果槽 `SB`） | `rv32i_sources.py`、`online_case_decoder._materialize_case` | `isa.disallowed_operation`、`isa.unexpected_operand`、`isa.reserved_imm_bit`、`field.bad_register`、`field.bad_immediate`、`field.bad_shamt`、`field.bad_alignment`、`field.bad_address`、`fragment.invalid_sequence`、`fragment.exceeds_address_space` |
| ⑤ 窗口/预算 | 声明 MMIO `windows`（base/size/读写权限/宽度）＋ 指令槽区间 `[instruction_start, instruction_end)` ＋ `advance_rounds` | `online_case_decoder`、`source_actions.py`、`CrossCaseEffectTracker` | `mmio.bad_window`、`mmio.bad_permission`、`mmio.bad_width`、`mmio.out_of_window`、`mmio.read_only`、`mmio.write_only`、`mmio.window_denied`、`mmio.no_aligned_address`、`slot.out_of_reservation`、`slot.materialized`、`slot.already_consumed`、`slot.proposal_mismatch`、`budget.exhausted` |
| ⑥ 切换 | 同 decoder 的声明候选池 `path_switch_targets()` | `online_case_decoder` 的 `switch_proposal` | 复用上述既有码（如 `ownership.*`、`budget.exhausted`、`path.undeclared`、`path.source_mismatch`）——**不为切换新造码** |

**37 个拒绝码**都定义在 `src/myfuzz/scenario/rejection_codes.py`，每条带 `code` ＋ `pointer`（如 `mmio.bad_width@mmio.width`），并且**拒绝不消耗任何东西**：当前 proposal、指令游标、case 计数都不动，调用方仍可提交未切换的那一例。

---

## 3. raw 的 8 字节怎么被使用（真实 layout）

以 `raw = 00 00 00 c2 0c 01 06 b0`（真实回执 `online-1-…`）为例：

| 字节 | 用途 | 本例取值 | 结果 |
|---|---|---|---|
| 0..1 | 路径加权选择（域分隔 sha256：`sha256("myfuzz.online.path.v1\0" + raw)` 前 8 字节 mod 权重和） | `00 00` | 选中 `cpu_to_ip_to_cpu.closed_loop`（GPIO 运行）或对应 UART 路径 |
| 2 | **直接命名源**（若该源属于所选路径且合法） | `00` | 源数组中 index 0 → `cpu.online_instruction`，故 `source_selection_reason=direct_source_byte` |
| 3.. | **变异熵**（`_case_entropy`：长度 ≥8 时取 `raw[3:]` 补齐 12 字节） | `00 c2 0c 01 06 b0` | 决定指令片段/外部事件取值 |
| 0..7 | 源的**加权回退选择**（byte 2 未直接命中时）：`int.from_bytes(raw[:8],"little") % Σweights` | — | 落在哪个源的权重区间就选哪个 |

两个关键设计（都在 docstring 里写明）：

1. **载荷熵从 byte 3 起**（`_case_entropy`），所以客户端固定 template/path/source 字节**不能冻结**操作与取值；
2. **路径选择用整条 raw 的域分隔摘要**，所以固定低位路径字节也不能冻结探索。

### 真实例子：CPU 指令源

`raw = 000000c20c0106b0` → `cpu.online_instruction` → 熵 12 字节 → `decode_instruction_fragment` 解出指令片段（本例 4 个字，见 TESTCASE_AND_DATAFLOW 例子 A 的 `LUI/ADDI/LUI/SW`）。

### 真实例子：外部事件源

`raw = 0000000000000000` → `uart.external_rx_byte` → `value = int.from_bytes(entropy,"little") & ((1<<width)-1)` = `0x00`。

**注意**：外部事件取值**只取源切片的位宽**（GPIO pin8 取 1 位、UART RX 取 8 位），所以被绑定/未声明的位不会被顺手改掉。

---

## 4. 反馈权重：变异"应该往哪走"

### 4.1 权重公式（`scenario_rfuzz._online_baseline_weights`, `:1255`）

```text
weight(source) = max(1, min(65536, round(
      source.weight                       # 声明的基础权重（OnlineSource.weight，默认 1）
    * ( 8                                  # 基础项
      + (64 if 该源的 coverage_target_ids 里有目标尚未命中 else 0)   # 覆盖缺口
      + 32 / (selection_uses + 1)                                   # 少用优先
      + 16 * selection_gains / (selection_uses + 1)                  # 历史增益产出率
      ) )))
```

| 项 | 依据 | 目的 |
|---|---|---|
| `source.weight` | wiring 里的显式声明 | 人工先验（例如想让某条路径多一些） |
| `+64` | 该源声明的 `coverage_target_ids` 与实际 `_target_hits` 的差 | **覆盖缺口优先** |
| `+32/(uses+1)` | 该源被选中次数 | 防止一直压在同一个源上 |
| `+16*gains/(uses+1)` | 该源历史上带来的新特征/增益 | 有产出者加权 |
| 闭环开启时再加 `energy[source]` | 真实链证书结算出的能量（`closed_loop_feedback.py`，只读消费证书） | 让"真的走通了链"的源获得下一次机会 |

### 4.2 真实证据：同一运行里的权重序列（哪些能复算、哪些不能）

60 例 UART 运行的回执逐例记录 `online_weights`。真实序列的前几对是：

```text
(104,104) → (104,40) → (88,40) → (83,40) → (80,40) → (80,29) → (16,24) → … → (10,10)
```

**我能逐一核对通过的**（把 `uses`/`gains`/是否还有未命中目标代进公式，数值完全吻合）：

| 权重 | 对应的状态 | 公式 |
|---|---|---|
| **104** | 该源仍有未命中目标，`uses=0`、`gains=0` | `1×(8 + 64 + 32/1 + 0) = 104` |
| **40** | 该源目标已全部命中，`uses=0`、`gains=0` | `1×(8 + 0 + 32/1 + 0) = 40` |
| **88** | 仍有未命中目标，`uses=1`、`gains=0` | `1×(8 + 64 + 32/2 + 0) = 88` |

**我不能逐一复算的**：`83`、`80`、`29`、`24`… 这些值对应"两个未命中目标先后被覆盖 ＋ `uses`/`gains` 同时增长"的组合（例如 `80` 可以来自 `uses=1,gains=7`，也可以来自 `uses=3,且仍有未命中目标`）。回执里只给出**权重本身**，没有单独给出每一例的 `uses`/`gains` 计数，所以我只能确认"这些值都落在公式的取值集合内、且衰减形状与公式一致"，**不声称逐例反解出唯一的状态**。要让这条完全可复算，需要把 `selection_uses`/`selection_gains` 也逐例写进回执——目前没有。

实测**下界是 10**（出现 17 次），它是观测结果，不是公式推导出的下界（公式在 `gains=0` 时随 `uses` 单调降到 8 附近）。

`selection_gains` 的语义可在源码确认：只有当该源**被消费**、且该例带来了新的目标命中或新的交互特征时才累加（`scenario_rfuzz.py:1197-1203` 的 `gains += coverage_gain + interaction_gain`），所以它衡量的是"这个源最近还有没有产出"，而不是"用了多少次"。

### 4.3 闭环能量的边界（实测）

闭环开启时，`_online_weights` 把证书能量加/减到权重上；实测 60 秒 A/B（P4 报告）：ON 相比 OFF 改变了逐例选源与覆盖（前缀内 23/35 例 `coverage_hex` 不同），但**证书更少**（7 对 12 条、0.115 对 0.196 链/s）。所以"反馈有效"与"反馈更好"是两件事，报告只主张前者。

---

## 5. 路径与源选择的三条真实路径

| 情况 | 触发条件 | 记录 |
|---|---|---|
| 直接命名源 | `raw[2]` 落在源数组范围内，且该源属于已选路径 | `source_selection_reason=direct_source_byte` |
| 加权回退 | 上面不成立 | `source_selection_reason=feedback_weighted_legal_source` |
| 声明式切换 | 调用方提交 `switch_proposal` 且被采纳并**确实改变了**候选 | `source_selection_reason=declared_path_switch`，并把 `online_path_switch.v1` 记录写进候选决策与 `candidate_id` |

三条都写进**候选身份**：`candidate_id` 由该例自己的 `raw ＋ 权重 ＋ 声明池` 独立复算；实测路径切换长枝 2,400/2,400 例逐例复算一致。

---

## 6. 不依据什么（负向清单）

| 不允许的依据 | 机制 | 实证 |
|---|---|---|
| 已绑定输入（如 GPIO A 输出 → GPIO B 输入） | ownership 编译成 `bound`，`_mutation_source` 直接拒绝 | `ownership.bound_input@source.port` |
| 固定输入（如 CPU IRQ 输入） | ownership 编译成 `fixed` | `ownership.fixed_input@source.port` |
| 真实 RTL 输出（地址、写值、byte enable） | 运行期事实不是可写目标 | `mutate_genome` 对 `committed_ram`/`read_snapshot`/`real_response`/`ip_output` 抛 `runtime mutation target is immutable` |
| 真实 Store/取指决定过的程序字节 | slot 不可变性 | 全扫描 **36,985 slot 全 `immutable`、0 violated** |
| 会话内已物化的指令槽 | `CrossCaseEffectTracker` | `slot.materialized`、`slot.already_consumed` |
| 未声明窗口内的地址 | MMIO 窗口声明 | `mmio.out_of_window`、`mmio.window_denied` |
| 名字推断（"看起来像 GPIO 就接 GPIO"） | 组合与解码都走声明；`composition` 层同样拒绝未验证源码 | 见"标识符不可见"回归门禁（`semantic_projection.py`） |
| 把拒绝当 0 或当通过 | 拒绝 = `input_invalid` ＋ 精确码，绝不折算 | UART 臂无效/超时比例 **0.05 = 3/60**，3 例各带 `uart-waveform-idle:*` 证据 |

---

## 7. "依据"本身是运行身份的一部分（decode space）

同一串 raw 在不同解码器下会解出**不同 case**，所以"依据"必须被钉住：

```text
online_run_identity.json
  └─ identity.decode_space  ← 46 个源文件的 sha256 清单
       online_case_decoder.py    （解码算法：路径/源选择、载荷熵、case 身份）
       rv32i_sources.py          （合法指令与算子空间）
       ibex_pulp_dual_source.py / ibex_uart_online.py （具体源、ownership、窗口、预算）
       ownership.py              （哪些 bit 可变异）
       dependency.py / genome.py （路径与方向声明）
       …
```

**实证效力**：改动 `src/myfuzz/scenario/{ibex_pulp_dual_source,online_case_decoder,rv32i_sources,source_actions}.py` 后，旧 bundle 的 24 例冷组 replay 被 `_verify_online_run_identity` **在任何 RTL 启动之前**逐例拒绝（记录 `recorded 11a4b307… vs current ee0be2b8a900…`）。这不是缺陷，而是"变异依据被改动"被如实检测出来。

---

## 8. 附加依据：初始 RAM 数据与受控故障（都不走 raw 解码）

| 机制 | 依据 | 与 raw 变异的关系 |
|---|---|---|
| 初始 RAM 数据操作子 | 受信声明窗口/mask 内抽地址与取值，写进**会话启动前**的初始镜像 | 不是 case 输入；实测 `0x100E6=0x94`、event 6 `initial_image`、CPU 首次读回 `0x94`、slot `immutable` |
| 受控故障注入 | 声明 selector（`case_id` ＋ 事件号 ＋ 原值）＋ 改写规则（只改 checker 观测副本） | **完全不改 raw、不改程序、不改源**；标 `calibration_only=true`、`observation_boundary=checker_input_copy`；控制/故障 trace 锚点事件逐字段相同 |

---

## 9. 在哪能看到"这一例为什么这么变"

| 想查什么 | 看哪个字段／文件 |
|---|---|
| 随机输入本身 | 回执 `online_raw_records_hex`、`raw_sha256` |
| 这一例为什么选这个源 | 回执 `source_selection_reason`、`online_weights`、`path_id`、`source_id` |
| 候选身份怎么复算 | `candidate_id`（由 raw ＋ 权重 ＋ 声明池复算；路径切换报告里有 2,400 例逐例复算） |
| 用了哪些算子 | `operator_id`（如 `rv32i:SLLI`、`switch` 记录） |
| 解码依据的源码身份 | `online_run_identity.json:identity.decode_space` |
| 被拒绝了什么、为什么 | 回执 `status=input_invalid` ＋ `rejection.code`/`pointer`；套件的无效/超时统计 |
| 权重怎么来的 | `_online_baseline_weights` 的四个输入：声明权重、目标命中、`selection_uses`、`selection_gains`；**注意**：`online_weights` 只记录权重结果，`uses`/`gains` 目前**不逐例入回执**，所以只有部分取值能逐例反解（见 §4.2） |

### 9.1 一条具体的改进建议（可验证的后续工作）

要让"权重怎么来的"完全可复算，最小改动是把 `selection_uses` 与 `selection_gains` 也写进每例回执（或写进 `report.json` 的一个有界快照）。目前它们只存在于 runner 进程内，运行结束后无法从产物恢复；这是本文明确点出的**证据缺口**，不是已实现能力。

---

## 10. 一句话总结

> **随机性只有一处（fuzzer 的 raw bytes），变异依据却有三层**：声明式的允许集合（路径/源/归属/ISA/窗口/预算，六道闸门 37 个拒绝码）、可复算的反馈权重（覆盖缺口＋使用次数＋历史增益＋闭环能量）、以及被哈希进运行身份的 decode space。
> 系统从不"凭名字猜"、从不改真实 RTL 的输出、也从不把拒绝说成 0——**能变什么、该往哪变、变了凭什么算数**，三件事各自有独立可查的证据。
