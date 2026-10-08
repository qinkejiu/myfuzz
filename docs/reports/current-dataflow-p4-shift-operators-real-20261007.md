# P4 合法操作子扩展：RV32I 移位立即数与真实退休门禁

日期：2026-10-07。P4 要求"加入合法 CPU 指令替换/插入/删除/操作数/立即数……操作子，每种操作子保存采用/拒绝原因"。本报告记录把 RV32I 移位立即数 `SLLI`/`SRLI`/`SRAI` 加入合法操作子集合，并在真实 RTL 上验证它们被真实取指、退休、被退休匹配器接受，且来源指向该例的在线指令 admission。

## 编码（逐位金标准，已写入测试）

`opcode = 0x13`；`SLLI` funct3=1、`SRLI`/`SRAI` funct3=5；`shamt = insn[24:20]`；`insn[31:25]` 为 RV32I 保留位：`SLLI`/`SRLI` 必须为 0、`SRAI` 必须为 `0b0100000`。示例（测试内同时按字段拼装与字面值双重钉死）：`slli x5,x6,7 = 0x00731293`、`srli x7,x8,31 = 0x01F45393`、`srai x9,x10,3 = 0x40355493`；`SRAI ^ SRLI == 1<<30`（仅 bit30 区分）。

## 实现与拒绝码

- `src/myfuzz/scenario/rv32i_sources.py`：合法集、`word()` 编码、字节校验、`instruction_operator_id`、在线变异空间（`byte4 & 0x20` 且无编辑位时按 `byte6 % 3` 选 SLLI/SRLI/SRAI）、操作数与 shamt 变异。既有操作子（`LUI/ADDI/XORI/ORI/ANDI/LW/SW/SB/NOP`）语义与结果逐例不变。
- `src/myfuzz/scenario/rejection_codes.py`：**新增** `field.bad_shamt`（指针 `instruction.shamt`，shamt 非 0..31）与 `isa.reserved_imm_bit`（指针 `fragment[i].immediate`，置位 RV32I 保留位；detail 带 `immediate/shamt/funct3/opcode`）。无既有码改名或删除，目录由 35 码变为 **37 码**，冻结摘要 `f8181f5c…996464` → `86d03337fa3955b18ea05429a1c0eaa8c3c5bb21a56332d02a6a390d7e560577`，两个摘要测试已显式更新。
- `src/myfuzz/scenario/cpu_retirement.py`：退休匹配器新增移位解码与结果校验（`rd_wdata == f(rs1_rdata, shamt)`，SRAI 为算术右移），保留位不符/trap/编码不符一律保持既有拒绝语义。

## 软件门禁

```bash
PYTHONPATH=src python3 -m pytest tests/scenario/test_rv32i_shift_operators.py -q -p no:randomly
# 实现前 67 failed, 7 passed；实现后 74 passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_cpu_retirement_shift.py tests/scenario/test_cpu_retirement.py -q -p no:randomly
# 89 passed, 427 subtests passed
PYTHONPATH=src python3 -m pytest tests/scenario/test_rv32i_*.py tests/scenario/test_online_*.py -q -p no:randomly
# 272 passed, 35 subtests passed
```

兼容性硬证据（与冻结旧模块逐例 diff）：`decode_instruction_fragment` 36,960 例一致、3,360 例差异**全部**落在新移位空间（非预期差异 0）；`Rv32iInstruction` 构造与 `word()` 1,701 例一致；`mutate_instruction` 旧操作 108 例一致；20,088 个字中"由合法变非法" 0 个。

## 真实 RTL 门禁

**（A）120 秒覆盖运行**（`--cpu-retirement --gpio-consumption --seconds 120 --max-tests 200 --seed 20261007`，`runs/p4-shift-fuzz-20261007-online`，83/83 complete）在自然变异下命中三种移位共 7 条：`SRAI`×3、`SLLI`×2、`SRLI`×2。逐条核对（`runs/current-dataflow-p5-final-20261007-logs/shift_trace_check.py`，流式读取）全部通过：

```
== runs/p4-shift-fuzz-20261007-online: proposed=7 verified=7    # 退出码 0
   OK SLLI pc=0x110cc insn=0x00281693 matcher=accepted writer_kinds=['INSTRUCTION_SOURCE']
   OK SRLI pc=0x11184 insn=0x00185713 matcher=accepted
   OK SRAI pc=0x111c8 insn=0x40185793 matcher=accepted
   OK SRAI pc=0x11200 insn=0x40185793 matcher=accepted
   OK SRAI pc=0x1122c insn=0x40185793 matcher=accepted
   OK SLLI pc=0x1125c insn=0x00181813 matcher=accepted
   OK SRLI pc=0x1137c insn=0x0028d893 rs1=x17=0x10801000 rd=x17=0x04200400 want=0x04200400 matcher=accepted
```

其中 `online-70` 的例子**rs1 非零**：`0x10801000 >> 2 == 0x04200400`，与观测 `rd_wdata` 逐位一致——即真实运行不仅证明"取指+退休+被接受"，还证明了一次带真实数据的移位结果语义。

**（B）三次定向 seed 运行**（`0001000203050027`/`0000000204050027`/`0000000205050027`，各 30 秒）中 SLLI 与 SRLI 各出现 1 条同样通过；SRAI 的定向 seed 未在该窗口稳定选中（其真实证据由 (A) 提供）。

三份运行身份都与当前 `cpu_retirement.py`（sha256 `eaf795a55f66be4bf4e70de246bdb1681ba62ba33504ea8656ff153e08abe1ed`）绑定（已在 `online_run_identity.json` 中逐字节核对相等）。

## 限制

- 真实运行共核对 7 条移位候选（SRAI 3／SLLI 2／SRLI 2），全部通过；其中 6 条 `rs1=0`（结果为 0），仅 1 条（`online-70` 的 SRLI）带非零操作数并验证了值语义。其余值语义（尤其 SRAI 的算术右移符号行为）由 `tests/scenario/test_cpu_retirement_shift.py` 的合成帧负例覆盖。
- 三次定向 seed 运行只稳定命中 SLLI/SRLI；SRAI 的真实证据来自 120 秒自然变异运行。
- 每个运行窗口内移位候选占比很小（83 例中 7 条），不声称命中率或覆盖率。
- 退休证书只证明"指令字节被真实取指并退休 + 观测寄存器结果与 ISA 一致"；移位无 data beat，因此不会形成数据流 hop，也不证明结果传播到外设。
- 未加入 `SLTI`/`SLTIU`（保持 OP-IMM funct3=2/3 的拒绝分支可达，且与 ADDI 同形无新编码结构）。
