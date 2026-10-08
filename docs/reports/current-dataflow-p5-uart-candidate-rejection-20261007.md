# P5 UART 在线候选：按真实 lane 语义判定寄存器写（RTL 前结构化拒绝）

日期：2026-10-07。范围：Ibex RVFI + OpenTitan UART 在线会话（`runs/p5-uart-gate-20261007-online` 的真实停机）。
本报告只包含软件实现与软件测试；**未运行 Verilator，未运行任何真实 RTL／在线 fuzz**（真实门禁命令见末节，由 root 串行执行）。

## 1. 结论摘要

1. **判定口径 = session 的真实按 lane 写入语义**：pinned 目标只写 `a_mask` 使能的字节 lane，因此 `WDATA` 的 8 位声明字段只约束**被使能 lane 的字节值**；
   `be=1`（`SB`）只看 lane 0，`be=15`（`SW`）才要求整字落在 0..255。运行时 `write_register` 与在线门禁**共用同一谓词**，不会漂移。
2. 真实失败候选（`x2=0x0CC3B006`、`SB x2,0x1c(x1)`、`be=1`）因此**被接纳**：它写入的真实字节是 lane 0 的 `0x06`，与 P4 SB 门禁测得的
   "`be=1` → 真实串口字节" 行为一致；不再出现 `unsupported UART register write`，也不再有 `uncertain_effect` 停机。
3. 真正超出声明字段的写（`be=15` 整字 > 255，即未开启 `--uart-wdata-byte-store` 的 SW 形状）仍在**任何 RTL 命令之前**被拒绝，
   回执为 `status="input_invalid"`、`candidate_disposition="rejected"`、`candidate_disposition_reason="decode_rejected"`，
   `rejection` 为 `candidate_rejection.v1`，码沿用既有 **`field.bad_immediate@mmio.value`**（未新增码）。
4. 拒绝时 runner 事件数、`local_ticks`、`session.cases` 零变化（runner 完全未被触碰），会话继续接受下一个 slot。
5. 运行时 `write_register` 对**原本已接受**的写，其投递给目标的 beat（value、be）逐字段不变，实际字节效果不变。

## 2. 真实证据链

- 运行目录 `runs/p5-uart-gate-20261007-online`，`receipts.jsonl` 共 3 条：
  `complete/admitted/rtl_case_committed`、`complete/admitted/rtl_case_committed`、
  `uncertain_effect/uncertain/rtl_submit_failed_or_partial`，`error = "ValueError: unsupported UART register write"`，`rejection=null`。
- 失败产物 `failures/online_uncertain_effect_7b098af9_1_1_604caae5c07e4c77.json`：
  - `raw_records_hex = ["000000c30c0106b0"]`，`source_id = cpu.online_instruction`，`operator_id = rv32i:LUI+ADDI+LUI+SB`；
  - `online_case.source.data_hex = 37b1c30c13016100b7000040238e2000`，即
    `LUI x2,0x0cc3b`、`ADDI x2,x2,6`、`LUI x1,0x40000`、`SB x2,0x1c(x1)`；
  - 真实 store 数据 `x2 = 0x0CC3B006`，地址 `0x4000001c`（WDATA），funct3=0 → `be=1`。
- 值的高位来自熵布局：`_decode_case` 对 8 字节记录取 `entropy = (raw[3:] * 3)[:12]`，`decode_instruction_fragment` 取
  `value = int.from_bytes(raw[8:12]) = raw[6] | raw[7]<<8 | raw[3]<<16 | raw[4]<<24`，故 `value = 0x0CC3B006`（与产物逐字节一致）。
  因为选择 MMIO 类要求 `raw[3] % 4 == 3`，所以 `raw[3] >= 3` 必然进入 bit16..23：**该类的字永远是"高位有值、lane 0 有真实字节"**。
- 该字由 Router 以完整 32 位 + lane 使能投递：`DataflowRouter._prepare` 得 `data32 = wdata`、`lane_be = 1`；
  `_access` 调 `GeneratedOpentitanUartSession.write_register(0x1c, 0x0CC3B006, be=1)`。
- **lane 语义的静态 RTL 证据**（只读源码，不跑仿真）：
  - `src/myfuzz/composition/rtl/soc_opentitan_uart_local_target.sv`：`tl_h2d.a_mask = a_mask_i`、`tl_h2d.a_data = a_data_i`（wrapper 原样透传）；
  - `third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_adapter_reg.sv:154-161`：`wr_req` 只看 opcode（`PutFullData`/`PutPartialData`），
    `we_o = wr_req & ~err_internal`、`wdata_o = tl_i.a_data`、`be_o = tl_i.a_mask`；
  - `third_party/soc-opentitan/hw/ip/uart/rtl/uart_reg_top.sv:1264-1285, 1745-1746`：`u_wdata` 是 `prim_subreg #(.DW(8), .SwAccess(WO))`，
    `wdata_wd = reg_wdata[7:0]`，`wdata_we = racl_addr_hit_write[7] & reg_we & !reg_error`；
  - P4 真实门禁 `docs/reports/current-dataflow-p4-sb-uart-byte-real-gate-20261007.md`：`be=1`、`mem_wdata=0x0c` 实测得到真实串口字节 `0x0c`。
  即：`be=1` 时 lane 0 写入 `value[7:0]`，lane 1..3 不参与寄存器内容；用整字比较会把该真实写误判为非法。
- 同一 raw record 在 P4 SB 门禁中对应 `online-2-604caae5c07e4c776cb357d1:cpu.online_instruction`（`mem_wdata=0x0c`）：
  旧栈的 UART 感知生成把 `raw[4]` 当字节值，新栈通用生成给出 4 字节寄存器字；本次修正后新栈的 `SB` 候选同样被接纳，真实写字节为 `value & 0xFF`。

## 3. 改动文件与 sha256

| 文件 | sha256 | 说明 |
| --- | --- | --- |
| `src/myfuzz/local_harness/opentitan_uart_session.py` | `011dbc2cff5a89b9aca41892f34848d41251daed3084b77febd8acb7d5470c27` | 新增 `enabled_write_mask()`（lane 使能→数据字节掩码）、`UartRegisterWrite.written_value()`；声明 `UART_REGISTER_WRITES`／`UART_REGISTER_WRITES_BY_OFFSET`、`uart_register_write_supported()`、`uart_register_write_denial()`；`write_register` 调用同一谓词（错误消息不变，投递 beat 不变） |
| `src/myfuzz/scenario/ibex_uart_online.py` | `05d60cd9eb0238e863b646a01ff9149ad8cb8a08221781ce4864747d546c0e3a` | 新增 `UartTargetWrite`、`instruction_mmio_writes()`（从片段自身字节解析真实 store，含显式 `byte_enable`）、`uart_write_rejection()`、`uart_fragment_rejection()`、`uart_case_rejection()`；`UartOnlineCaseDecoder.decode_candidate()` 提交前判定；`decode()` 直调路径同样加门 |
| `tests/scenario/test_ibex_uart_candidate_rejection.py` | `c4e36b360690a0cd22a5cf9ab318648b3526d7b09b2d6c68aabec8603417ee04` | 新增 15 项测试（真实产物正例、运行时 beat 复核、整字负例、lane 网格、分类分支、会话继续、RX 路径） |
| `tests/integration/test_uart_fifo_replay_selector.py` | `7e5b4841687af22b52159c9f596123ef3e4594f05231cfe757ba08bcb19553da` | 仅为修复**既有失效测试**的单行补丁（见 7.2），不属于本次功能改动 |

未改动任务禁改清单中的任何模块；`integration/ibex_uart_online.py`、`scenario/uart_session.py`、`local_harness/uart_controlled_irq_contract.py` 无需改动。

## 4. 判定依据与所用码

单一声明（`UART_REGISTER_WRITES`，依据现有实现与 pinned RTL 语义，而非新造语义）：

| offset | 寄存器 | 声明的字节使能 | 声明的寄存器字段 |
| --- | --- | --- | --- |
| 0x04 | INTR_ENABLE | 15 | 精确 `{0x6, 0x2}` |
| 0x10 | CTRL | 15 | 精确 `{0x80000003}` |
| 0x1C | WDATA | 1、15 | `0..255`（8 位发送字段） |

判定规则：`written = value & enabled_write_mask(be)`（`be=1→0xFF`、`be=3→0xFFFF`、`be=15→0xFFFFFFFF`），
仅当 `written` 落在声明字段内才接受。`write_register` 与该声明共用同一谓词，`uart_register_write_denial()` 把拒绝分成三个声明字段：

| 真实分支 | 码 | pointer | detail 关键字段 |
| --- | --- | --- | --- |
| offset 不在已声明写寄存器表内 | `mmio.window_denied` | `mmio.address` | `address/offset/operation/declared_offsets` |
| 字节使能未被该寄存器声明 | `mmio.bad_width` | `mmio.width` | `register/byte_enable/declared_byte_enables` |
| **被使能 lane 的寄存器字**超出声明字段 | `field.bad_immediate` | `mmio.value` | `register/value/byte_enable/enabled_value/declared_values` |
| 片段未物化 store 的地址或数据（无法证明合法） | `mmio.window_denied` | `mmio.address` | `reason="store_target_unresolved"`, `fragment` |
| 片段不是完整字 / store 宽度不在 RV32I 子集 | `decode.malformed_record` / `isa.disallowed_operation` | `instruction.fragment` | — |

第三行的真实形状（`be=15`、`x2=0x0CC3B006`）给出的回执：

```json
{"schema_version": "candidate_rejection.v1", "code": "field.bad_immediate", "pointer": "mmio.value",
 "detail": {"address": 1073741852, "byte_enable": 15, "declared_values": [0, 255],
            "enabled_value": 214151174, "offset": 28, "operation": "SW",
            "register": "WDATA", "value": 214151174}}
```

选择理由：该三元组里 offset 已声明、`be` 已声明，唯一不合声明的是"真正写进寄存器的字不落在其 8 位字段"；`enabled_value` 让回执自证判的是哪个字。
`rv32i_sources.mmio_write_fragment` 已有 `field.bad_immediate@mmio.value` 先例；`mmio.window_denied` 语义更粗，用于 offset 级与"无法证明"级。未新增码。

## 5. "是否可在接纳前判定"的结论与证据

结论：**可以**。证据：

1. 判定输入全部来自候选自身：`decode_candidate` → `_decode_case` 生成的片段是 `LUI/ADDI/LUI/SW|SB` 模板，基址寄存器、store 宽度（funct3）、
   数据寄存器值都由该片段内的 `LUI`/`ADDI` 静态物化；`instruction_mmio_writes()` 直接从**即将被 CPU 取指的字节**解析，并显式带出 `byte_enable`。
2. 判定规则是纯谓词且与运行时同源：`test_runtime_write_register_and_the_gate_agree_on_the_same_grid` 对
   offset×byte_enable×value = 9×6×9 = 486 组，逐点比较**真实 `write_register`**（在裸实例上仅替换 `_access`，记录投递 beat）与门禁
   `uart_write_rejection()`，两者接受/拒绝完全一致。
3. 真实 raw 的映射可复算：`test_refused_candidate_is_the_fragment_the_real_run_submitted` 用同一声明复现
   `raw 000000c30c0106b0 → data_hex 37b1c30c13016100b7000040238e2000 → (SB, 0x4000001c, 0x0CC3B006, be=1)`，与保存产物逐字段一致。
4. 无法解析的 store 一律 fail-closed 拒绝（含"基址寄存器被 SLLI 等非物化指令覆盖后仍被当作地址"的形状），不会猜成合法。

因此不存在"只有提交时才知道寄存器是否支持"的情况，任务的次优降级方案（把提交期失败降级为可继续的结构化拒绝）**未启用**。

## 6. RED → GREEN

RED A（新 API 缺席，收集期即失败）：

```text
$ PYTHONPATH=src python3 -m pytest tests/scenario/test_ibex_uart_candidate_rejection.py -q -p no:randomly
E   ImportError: cannot import name 'enabled_write_mask' from 'myfuzz.local_harness.opentitan_uart_session'
ERROR tests/scenario/test_ibex_uart_candidate_rejection.py
```

RED B（行为 RED：临时把 `written_value()` 退回"整字比较"，即修正前的口径，再跑同一测试文件；实验后已还原，源文件 sha256 与上表一致）：

```text
4 failed, 11 passed in 0.30s
tests/.../test_ibex_uart_candidate_rejection.py:181: AssertionError: assert 'input_invalid' == 'complete'
FAILED test_real_failure_candidate_is_admitted_as_a_lane_zero_byte_write
FAILED test_real_write_register_accepts_the_lane_zero_word_and_keeps_its_byte
FAILED test_wdata_byte_writes_are_judged_by_their_enabled_lane
FAILED test_refused_candidate_is_the_fragment_the_real_run_submitted
```

即：整字比较会把真实产物形状（`be=1`、lane 0 字节 `0x06`）误判为非法——正是 root 指出的错向。

GREEN：

```text
$ PYTHONPATH=src python3 -m pytest tests/scenario/test_ibex_uart_candidate_rejection.py -q -p no:randomly
15 passed in 0.28s
```

测试覆盖（15 项）：

- 正例：真实失败产物形状在 `--uart-wdata-byte-store` 解码器上 **complete/admitted/rtl_case_committed**，提交路径收到原片段，
  `operator_id=rv32i:LUI+ADDI+LUI+SB`，且该写被声明接受、lane 0 字节 = `0x06`；
- 正例：真实 `write_register` 对 `(0x1C, 0x0CC3B006, be=1)` 接受并把 `(value=0x0CC3B006, be=1)` 原样交给目标（lane 0 → `0x06`）；
  旧已接受写（`0x1C/0x0C/be=1`、`0x1C/0x0C/be=15`、`0x10/0x80000003/be=15`）投递 beat 逐字段不变；
- 正例：`SB` 值低字节 0..255 全范围（含 `0x00/0x7F/0x80/0xFF/0x100/0x203B006/0x0CC3B006/0xFFFFFFFF`）不被拒；`SW` 值 0..255 不被拒；
- 负例：`be=15` 整字 > 255 → `field.bad_immediate@mmio.value`（`enabled_value == value`）；未声明 be → `mmio.bad_width`；
  未声明 offset → `mmio.window_denied`；不可物化 → `mmio.window_denied(store_target_unresolved)`；
- 等价：运行时 `write_register` 与门禁 486 组网格一致；被拒 slot 后同批下一 slot 仍被接纳并提交；UART RX 源路径不受影响。

## 7. 兼容性回归（全部软件测试，无 RTL）

| 命令 | 结果 |
| --- | --- |
| `pytest tests/scenario/test_ibex_uart_candidate_rejection.py tests/scenario/test_uart_*.py -q -p no:randomly` | **486 passed, 14 subtests passed**（170.11 s） |
| `pytest tests/local_harness/test_opentitan_uart_{byte_write_gate,fifo_probe,rearm,routed_identity,source_provenance}.py tests/integration/test_ibex_uart_online_pilot.py tests/integration/test_ibex_uart_memory_commit_mode.py tests/integration/test_uart_fifo_replay_selector.py tests/integration/test_runtime_fixture_contracts.py tests/scenario/test_rv32i_rejection_codes.py tests/scenario/test_online_candidate_rejection_receipt.py tests/scenario/test_ibex_pulp_source_action_prerequisites.py -q -p no:randomly` | **166 passed, 33 subtests passed**（44.25 s；码表摘要未变、GPIO 双源路径行为未变） |
| `pytest tests/integration/test_opentitan_uart_source_frames_real.py --collect-only -q` | 可收集（1 test）；**未执行**，它需要真实 Verilator/RTL 后端 |

7.1 既有构建身份不稳定（与本改动无关）：把 31 个 UART 场景测试文件一次性跑时，曾出现一次
`ValueError: generated build identity mismatch`（`scenario/contracts.py:418`），且**在两次运行中落在不同测试**
（一次 `test_uart_fifo_identity_optin.py`，一次 `test_uart_controlled_manifest.py`）；两者单独运行、以及较小的批次均通过，
同一批次随后完整重跑 486 项全绿。`docs/CURRENT_PROGRESS`／`.superpowers/sdd/progress.md` 已记录同类现象
（"并行编辑期间先前一次构建身份不匹配，原测试单独重跑通过"）。本改动不涉及 `local_harness/build.py`、`scenario/contracts.py`
或任何构建输入字节，失败断言与本次读路径无交集。

7.2 既有失效测试的修复：`tests/integration/test_uart_fifo_replay_selector.py::test_replay_profile_selector_runs_after_envelope_and_before_factory`
原先只 patch 了 3 个 selector，漏掉后加入 `integration/ibex_uart_online.py` 的 `_saved_memory_readback_mode`，因此在临时目录上抛
`ValueError: saved memory readback manifest path mismatch`（先于本次改动的既有缺口）。补上该 selector 的 patch 并把顺序断言
升级为 `['envelope','fifo','commit','readback','factory']`、追加 `memory_readback=False` 断言后通过。这是测试侧最小修补，不改变任何交付模块。

## 8. 边界

- 开启 `--uart-wdata-byte-store`（`SB`、`be=1`，P5 门禁使用的模式）时：CPU→UART TX 字节写候选按 lane 0 判定，**会被接纳**，
  真实写字节 = `value & 0xFF`（真实产物的 `x2=0x0CC3B006` → `0x06`），TX 覆盖恢复；未开启时解码器声明的是 `SW`（`be=15`），
  4 字节整字超 8 位字段的候选仍被 RTL 前结构化拒绝（`field.bad_immediate@mmio.value`），不会升级为不确定副作用。
- 未做：真实 RTL 复核（`mem_wdata`/`be`/串口字节）与 P5 长会话验收；本报告不声称这些已通过，必须由 root 用同一冻结源码实跑判定。
- 本改动不改变任何已接受写的投递 beat 或实际字节效果，也不改变 `write_register` 对非法输入的拒绝消息。

## 9. root 真实门禁命令与判定键

```bash
cd /home/qinkejiu/myfuzz && PYTHONPATH=src:. /usr/bin/python3 scripts/run_ibex_uart_online.py run \
  --cpu-retirement --uart-fifo --memory-commit --memory-readback --uart-wdata-byte-store \
  --seconds 60 --max-tests 60 --seed 20261007
```

预期观察点（`receipts.jsonl` / `failures/`）：

1. `complete` 至少 10 例（TX 字节写候选、非 MMIO 指令候选与 UART RX 源候选均可被接纳），不再出现第 3 例即停；
2. 不再出现 `status="uncertain_effect"` 且 `candidate_disposition_reason="rtl_submit_failed_or_partial"` 的停机
   （`failures/` 下不应再生成 `online_uncertain_effect_*` 文件）；
3. TX 字节类候选出现在回执并被接纳：`source_id="cpu.online_instruction"`、
   `operator_id` 含 `LUI+ADDI+LUI+SB`、`candidate_disposition="admitted"`、`candidate_disposition_reason="rtl_case_committed"`、
   `rejection=null`，且 `online_case.source.action_id` 指向该在线指令动作（离线复算得到
   `online-0-604caae5c07e4c776cb357d1:cpu.online_instruction`）；`applied_source_ids` 视该例是否产生消费证据而定，不作为判定键；
4. 若出现拒绝，必须是 `status="input_invalid"`、`candidate_disposition="rejected"`、
   `candidate_disposition_reason="decode_rejected"`、`rejection` 为 `candidate_rejection.v1` 文档（本模式预期为未声明的 offset/be 或
   不可物化 store；`field.bad_immediate@mmio.value` 只在被使能 lane 的字真的越界时出现）。
