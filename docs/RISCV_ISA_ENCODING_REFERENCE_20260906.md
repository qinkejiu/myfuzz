# RISC-V CPU 指令集合与 0/1 编码参考

版本：`2026-09-06`
用途：为 CPU 指令合法化、指令级输入投影、依赖感知组合和后续 decoder/fuzzer 生成提供统一参考。
基准：RISC-V Ratified Specifications Library `v20260120`；具体 RTL 若采用旧版或自定义扩展，必须在 CPU manifest 中注明版本和差异。

## 0. 重要边界

“所有指令”必须先定义范围。RISC-V 的标准扩展持续增加，不能把某一颗 CPU 的配置集合误写成全 ISA。本文件把可直接用于当前项目的集合定义为：

```text
完整基线：RV32I / RV64I + Zicsr + Zifencei + M + A + F + D + C
常用可选：B = Zba + Zbb + Zbc + Zbs，以及 Zicond、Zca/Zcb/Zcd/Zcf/Zcmp/Zcmt
明确排除：没有证据时不声称 V、Q、H、P、Crypto、厂商 custom 扩展已被某 CPU 实现
```

下文对 `I/M/A/F/D/C` 给出指令级清单和可重建的字段 0/1 含义；对 `B/Z*` 给出常用指令全集目录和 profile 选择规则。压缩指令是 16 bit，其他基础/标准标量指令通常是 32 bit。汇编伪指令（例如 `nop`、`mv`、`ret`）不另计为硬件 opcode，除非明确标为 alias。

## 1. 之前提到的 CPU 指令集合 profile

| CPU | 本文件对应的默认 profile | 备注 |
|---|---|---|
| Ibex | `RV32I`；按配置增加 `M`、`C`、`B`；常见 `RV32EC`、`RV32IMC`、`RV32IMCB` | `RV32M` 有 None/Fast/SingleCycle 等实现选项；B 也可能是子集。 |
| CVA6 | `RV64I/M/A`；可选 `F/D/C/B/Zicond/Zcb` 等，亦有 RV32 配置 | 以生成配置/commit 为准，不能只按仓库名决定。 |
| BOOM | 文档化常见 `RV64GC`，即 `RV64IMAFDC` 加 privileged | BOOM 文档版本未把 V 当成默认能力；Rocket Chip 配置可改变细节。 |
| Rocket | 常见 `RV64GC` 或配置化 RV32/RV64 | 由 Rocket Chip config 选择扩展。 |
| PicoRV32 | `RV32I`，可选 PCPI/M | `picorv32_axi`/`picorv32_wb` 是总线包装，不改变 ISA。 |
| VexRiscv | 插件决定的 RV32/RV64 集合 | Mul/Div、C、F/D、CSR、MMU 等都必须读取 plugin 配置。 |
| CV32E40P | `RV32IMC` 常见，APU/custom hardware loop 可选 | APU 不是标准 RISC-V 基础指令。 |
| CV32E40S | RV32 profile，安全配置/扩展随版本 | 使用官方 user manual 和构建参数确认。 |
| NEORV32 | `RV32I`，M/C/自定义扩展依配置 | 外部 Wishbone/AXI bridge 与 ISA 独立。 |
| SweRV/VeeR EH1 | RV32 profile，具体扩展依版本 | 可有自定义指令或安全配置。 |
| XiangShan | 高性能 RV64 profile，随版本演进 | 需要从目标 commit 的 ISA/config 生成清单。 |

后续组合器的规则：CPU 只声明自己支持的 `extensions`、`xlen`、`privilege_modes` 和 `custom_extensions`；指令生成器只从该集合取编码。遇到 `mask/match` 重叠、版本不一致或 custom 指令未声明，必须拒绝样本或 candidate。

## 2. 0/1 编码的统一表示

### 2.1 位编号和模式字符串

32-bit 指令采用 `inst[31:0]`，模式字符串从 bit 31 写到 bit 0：

```text
31                                      0
| fixed bits / variable fields           |

0/1 : 固定为该值
x   : 由寄存器、立即数、rm、source 等字段填充
-   : 与 x 同义，仅用于显示“未参与该条指令固定匹配”的位
```

例如 `JALR`：

```text
imm[11:0] | rs1 | 000 | rd | 1100111
31:20       19:15 14:12 11:7 6:0
```

机器解码统一定义为：

```text
matches(inst, mask, match) := (inst & mask) == match
```

`mask` 的固定字段为 1，变量字段为 0；`match` 只在 mask=1 的位置保存固定 0/1。建议实现直接采用官方 `riscv-opcodes` 生成的 `encoding/mask/match/variable_fields`，而不是手工维护十六进制常数。

### 2.2 通用字段

| 字段 | 位 | 宽度 | 0/1 含义 |
|---|---:|---:|---|
| `opcode` | `[6:0]` | 7 | major opcode，决定大类。 |
| `rd` | `[11:7]` | 5 | 整数/浮点目的寄存器编号；整数 `00000` 为 x0。 |
| `funct3` | `[14:12]` | 3 | 子操作、访问宽度、或 rounding mode。 |
| `rs1` | `[19:15]` | 5 | 第一源寄存器。 |
| `rs2` | `[24:20]` | 5 | 第二源寄存器或扩展子编码。 |
| `funct7` | `[31:25]` | 7 | R-type 子操作；部分 FP/A 扩展再拆分。 |
| `imm` | 多个片段 | 依格式 | 立即数，按规范拼接、符号扩展、缩放。 |
| `csr` | `[31:20]` | 12 | CSR 地址。 |
| `zimm` | `[19:15]` | 5 | CSR immediate 形式的无符号立即数。 |
| `aq` | bit `[26]` | 1 | A 扩展 acquire ordering。 |
| `rl` | bit `[25]` | 1 | A 扩展 release ordering。 |
| `fmt` | `[26:25]` | 2 | FP 格式：S=`00`、D=`01`、H=`10`、Q=`11`。 |
| `rm` | `[14:12]` | 3 | FP rounding mode；`111` 选择动态 `frm`。 |
| `rs3` | `[31:27]` | 5 | FMA 第三个 FP 源寄存器。 |

### 2.3 指令格式与立即数重排

| 格式 | bit 31 到 bit 0 的布局 | 立即数重建 |
|---|---|---|
| R | `funct7 rs2 rs1 funct3 rd opcode` | 无 immediate。 |
| I | `imm[11:0] rs1 funct3 rd opcode` | `sext(inst[31:20])`。 |
| S | `imm[11:5] rs2 rs1 funct3 imm[4:0] opcode` | `sext({inst[31:25],inst[11:7]})`。 |
| B | `imm[12] imm[10:5] rs2 rs1 funct3 imm[4:1] imm[11] opcode` | `sext({inst[31],inst[7],inst[30:25],inst[11:8],1'b0})`。 |
| U | `imm[31:12] rd opcode` | `sext(imm20 << 12)` 写入 rd，低 12 bit 为 0。 |
| J | `imm[20] imm[10:1] imm[11] imm[19:12] rd opcode` | `sext({inst[31],inst[19:12],inst[20],inst[30:21],1'b0})`。 |
| R4 | `rs3 rs2 rs1 rm rd opcode`，另含 `fmt` | 用于 FMADD/FMSUB/FNMSUB/FNMADD。 |

共同规则：所有有符号 immediate 的 sign bit 为 `inst[31]`；B/J 目标按 2 byte 对齐，U immediate 左移 12；I/S 不是地址乘法单位。`C` 存在时 `IALIGN=16`，32-bit 指令可从 16-bit 边界开始。

## 3. RV32I：完整 40 条基础指令

下表的 `fixed` 给出固定字段，未列出的寄存器/立即数字段都是 `x`。每一行都可直接组合成 32-bit 0/1 字符串，并由第 2 节的 `mask/match` 规则解码。

### 3.1 U、跳转和分支

| 指令 | 格式 | fixed（字段=值） | 语义 |
|---|---|---|---|
| `LUI` | U | `opcode=0110111` | `rd <- imm20 << 12`。 |
| `AUIPC` | U | `opcode=0010111` | `rd <- pc + (imm20 << 12)`。 |
| `JAL` | J | `opcode=1101111` | `rd <- pc+4`，`pc <- pc + sext(jimm20)`。 |
| `JALR` | I | `opcode=1100111, funct3=000` | `t=pc+4; pc=(rs1+sext(imm)) & ~1; rd<-t`。 |
| `BEQ` | B | `opcode=1100011, funct3=000` | `rs1 == rs2` 时 PC 相对分支。 |
| `BNE` | B | `opcode=1100011, funct3=001` | `rs1 != rs2` 时分支。 |
| `BLT` | B | `opcode=1100011, funct3=100` | 有符号 `<` 时分支。 |
| `BGE` | B | `opcode=1100011, funct3=101` | 有符号 `>=` 时分支。 |
| `BLTU` | B | `opcode=1100011, funct3=110` | 无符号 `<` 时分支。 |
| `BGEU` | B | `opcode=1100011, funct3=111` | 无符号 `>=` 时分支。 |

二进制布局示例：

```text
BEQ = imm[12] imm[10:5] rs2 rs1 000 imm[4:1] imm[11] 1100011
JAL = imm[20] imm[10:1] imm[11] imm[19:12] rd 1101111
```

### 3.2 Load/store

| 指令 | 格式 | fixed（`funct3`） | 语义/约束 |
|---|---|---|---|
| `LB` | I | `opcode=0000011, funct3=000` | byte load，符号扩展。 |
| `LH` | I | `opcode=0000011, funct3=001` | halfword load，符号扩展。 |
| `LW` | I | `opcode=0000011, funct3=010` | 32-bit word load。 |
| `LBU` | I | `opcode=0000011, funct3=100` | byte load，零扩展。 |
| `LHU` | I | `opcode=0000011, funct3=101` | halfword load，零扩展。 |
| `SB` | S | `opcode=0100011, funct3=000` | 保存低 8 bit。 |
| `SH` | S | `opcode=0100011, funct3=001` | 保存低 16 bit。 |
| `SW` | S | `opcode=0100011, funct3=010` | 保存 32 bit。 |

有效地址均为 `rs1 + sext(imm12)`；自然对齐、非对齐和 access fault 由执行环境/CPU 配置定义。模糊测试器不能把设备寄存器的 byte enable 当作普通 RAM 行为，需由组件副作用定义覆盖。

### 3.3 OP-IMM

| 指令 | `opcode` | `funct3` | 额外固定位 | 语义 |
|---|---|---|---|---|
| `ADDI` | `0010011` | `000` | 无 | `rd <- rs1 + sext(imm12)`。 |
| `SLTI` | `0010011` | `010` | 无 | 有符号小于，写 0/1。 |
| `SLTIU` | `0010011` | `011` | 无 | 无符号小于，写 0/1。 |
| `XORI` | `0010011` | `100` | 无 | XOR immediate。 |
| `ORI` | `0010011` | `110` | 无 | OR immediate。 |
| `ANDI` | `0010011` | `111` | 无 | AND immediate。 |
| `SLLI` | `0010011` | `001` | RV32 `imm[11:5]=0000000` | 逻辑左移，shamt=5 bit。 |
| `SRLI` | `0010011` | `101` | `imm[11:5]=0000000` | 逻辑右移。 |
| `SRAI` | `0010011` | `101` | `imm[11:5]=0100000` | 算术右移。 |

通用布局：`imm[11:0] rs1 funct3 rd 0010011`。`SLLI/SRLI/SRAI` 的 imm 高位不是任意立即数，而是把 shift 变体写入固定字段；RV64 的 shamt 宽度和 W 变体见第 4 节。

### 3.4 OP

| 指令 | `opcode` | `funct3` | `funct7` | 语义 |
|---|---|---|---|---|
| `ADD` | `0110011` | `000` | `0000000` | 加法。 |
| `SUB` | `0110011` | `000` | `0100000` | 减法。 |
| `SLL` | `0110011` | `001` | `0000000` | 逻辑左移。 |
| `SLT` | `0110011` | `010` | `0000000` | 有符号小于。 |
| `SLTU` | `0110011` | `011` | `0000000` | 无符号小于。 |
| `XOR` | `0110011` | `100` | `0000000` | 异或。 |
| `SRL` | `0110011` | `101` | `0000000` | 逻辑右移。 |
| `SRA` | `0110011` | `101` | `0100000` | 算术右移。 |
| `OR` | `0110011` | `110` | `0000000` | 或。 |
| `AND` | `0110011` | `111` | `0000000` | 与。 |

通用布局：`funct7 rs2 rs1 funct3 rd 0110011`。`SUB/SRA` 仅改变 `funct7[6:0]`；其余固定 `0000000`。

### 3.5 Fence 与环境调用

| 指令 | 布局/固定字段 | 语义 |
|---|---|---|
| `FENCE` | `fm pred succ rs1=00000 rd=00000 funct3=000 opcode=0001111` | 对指定 predecessor/successor 内存/IO 类别建立顺序。 |
| `ECALL` | `imm12=000000000000, rs1=00000, funct3=000, rd=00000, opcode=1110011` | 环境调用异常。完整 32 bit 为 `0x00000073`。 |
| `EBREAK` | `imm12=000000000001`，其他同 `ECALL` | breakpoint 异常。完整 32 bit 为 `0x00100073`。 |

RV32I 共 40 条：2 U + 2 jump + 6 branch + 5 load + 3 store + 9 OP-IMM + 10 OP + 1 FENCE + 2 environment/system。

## 4. RV64I 增量指令

RV64I 复用 RV32I，大多数 32-bit 指令结果按 RV64 规则符号扩展；新增 12 条主要指令：

| 指令 | 格式/fixed | 语义 |
|---|---|---|
| `LWU` | I，`opcode=0000011, funct3=110` | 32-bit load，零扩展到 XLEN。 |
| `LD` | I，`opcode=0000011, funct3=011` | 64-bit load。 |
| `SD` | S，`opcode=0100011, funct3=011` | 64-bit store。 |
| `ADDIW` | I，`opcode=0011011, funct3=000` | 低 32 bit 加法，再 sign-extend。 |
| `SLLIW` | I，`opcode=0011011, funct3=001, imm[11:5]=0000000` | 32-bit 左移。 |
| `SRLIW` | I，`opcode=0011011, funct3=101, imm[11:5]=0000000` | 32-bit 逻辑右移。 |
| `SRAIW` | I，`opcode=0011011, funct3=101, imm[11:5]=0100000` | 32-bit 算术右移。 |
| `ADDW` | R，`opcode=0111011, funct3=000, funct7=0000000` | 32-bit 加法后 sign-extend。 |
| `SUBW` | R，`opcode=0111011, funct3=000, funct7=0100000` | 32-bit 减法后 sign-extend。 |
| `SLLW` | R，`opcode=0111011, funct3=001, funct7=0000000` | 32-bit 左移。 |
| `SRLW` | R，`opcode=0111011, funct3=101, funct7=0000000` | 32-bit 逻辑右移。 |
| `SRAW` | R，`opcode=0111011, funct3=101, funct7=0100000` | 32-bit 算术右移。 |

## 5. Zicsr、Zifencei 与 privileged 指令

### 5.1 Zicsr 六条 CSR 指令

所有 CSR 指令的 `opcode=1110011`，`csr=inst[31:20]`，`rd=inst[11:7]`。寄存器形式使用 `rs1=inst[19:15]`，立即数形式把这 5 bit 当作 `zimm`。

| 指令 | `funct3` | 读/写效果 |
|---|---|---|
| `CSRRW` | `001` | 读旧 CSR 到 rd，并用 rs1 写 CSR。 |
| `CSRRS` | `010` | 读 CSR；按 rs1 置位。rs1=x0 时只读。 |
| `CSRRC` | `011` | 读 CSR；按 rs1 清位。rs1=x0 时只读。 |
| `CSRRWI` | `101` | 用 zimm 写 CSR。 |
| `CSRRSI` | `110` | 用 zimm 置位；zimm=0 时只读。 |
| `CSRRCI` | `111` | 用 zimm 清位；zimm=0 时只读。 |

通用布局：`csr[11:0] rs1/zimm[4:0] funct3 rd 1110011`。CSR 是否存在、可读写和特权级权限由 privileged spec 与具体 CPU 实现决定；随机器必须避免把未声明 CSR 当成合法 CSR。

### 5.2 Zifencei

```text
FENCE.I = imm[11:0] rs1=00000 funct3=001 rd=00000 opcode=0001111
```

`FENCE.I` 保证后续 instruction fetch 能看到此前数据写入；实现可能把 `imm`/`rs1` 作为保留值。不能将其等同普通 `FENCE`。

### 5.3 常见 privileged 编码

| 指令 | 32-bit hex | 0/1 固定含义 |
|---|---:|---|
| `URET` | `0x00200073`（若实现） | SYSTEM，`funct7/rs2/rs1/funct3/rd` 为特定固定模式。 |
| `SRET` | `0x10200073` | 从 S-mode trap 返回。 |
| `MRET` | `0x30200073` | 从 M-mode trap 返回。 |
| `WFI` | `0x10500073` | 等待中断；实现可按特权规则处理。 |
| `SFENCE.VMA` | 基础 `0x12000073`，`rs1/rs2` 为地址/ASID | 刷新地址转换缓存；不是所有 CPU 都实现 MMU。 |
| `HFENCE.VVMA` | `0x22000073` 基础模式 | H 扩展，只有 hypervisor profile。 |
| `HFENCE.GVMA` | `0x62000073` 基础模式 | H 扩展，只有 hypervisor profile。 |

这里的 hex 是固定字段组合；对带 `rs1/rs2` 的 fence，只有所示固定字段参与 mask，寄存器字段仍是变量。`DRET` 属于 debug 规范，不能仅凭 privileged ISA 清单假定 CPU 支持。

### 5.4 常见 CSR 地址

| CSR | 地址 | 典型用途 |
|---|---:|---|
| `fflags` | `0x001` | FP 累计异常标志。 |
| `frm` | `0x002` | FP 动态舍入模式。 |
| `fcsr` | `0x003` | FP 状态合并寄存器。 |
| `mstatus` | `0x300` | M-mode 状态/中断使能。 |
| `misa` | `0x301` | XLEN 和扩展存在性。 |
| `medeleg` | `0x302` | 异常委托。 |
| `mideleg` | `0x303` | 中断委托。 |
| `mie` | `0x304` | 中断使能。 |
| `mtvec` | `0x305` | M-mode trap vector。 |
| `mscratch` | `0x340` | M-mode scratch。 |
| `mepc` | `0x341` | 异常 PC。 |
| `mcause` | `0x342` | 异常/中断原因。 |
| `mtval` | `0x343` | trap 附加值。 |
| `mip` | `0x344` | 中断 pending。 |
| `cycle` | `0xC00` | cycle counter。 |
| `time` | `0xC01` | time counter。 |
| `instret` | `0xC02` | retired instruction counter。 |

`mstatus` 等寄存器的具体位、只读位和实现选项必须从 CPU 文档生成，不能只用地址表生成写事务。

## 6. M：整数乘除法（完整清单）

### 6.1 RV32M

统一格式：`funct7=0000001, opcode=0110011`，`funct3` 选择操作，其他为 `rs2/rs1/rd`。

| 指令 | `funct3` | 语义 |
|---|---|---|
| `MUL` | `000` | XLEN 位乘法低 XLEN 位。 |
| `MULH` | `001` | 有符号 × 有符号高半。 |
| `MULHSU` | `010` | 有符号 × 无符号高半。 |
| `MULHU` | `011` | 无符号 × 无符号高半。 |
| `DIV` | `100` | 有符号除法。 |
| `DIVU` | `101` | 无符号除法。 |
| `REM` | `110` | 有符号余数。 |
| `REMU` | `111` | 无符号余数。 |

除零和有符号最小值除以 `-1` 的结果按 M 规范定义，不能让模糊测试器使用语言运行时的异常行为替代硬件语义。

### 6.2 RV64M 增量

格式：`funct7=0000001, opcode=0111011`。

| 指令 | `funct3` | 语义 |
|---|---|---|
| `MULW` | `000` | 32-bit 乘法低位，结果 sign-extend。 |
| `DIVW` | `100` | 32-bit 有符号除法，结果 sign-extend。 |
| `DIVUW` | `101` | 32-bit 无符号除法，结果 sign-extend。 |
| `REMW` | `110` | 32-bit 有符号余数，结果 sign-extend。 |
| `REMUW` | `111` | 32-bit 无符号余数，结果 sign-extend。 |

`Zmmul` 只保留乘法类 `MUL/MULH/MULHSU/MULHU`（及 RV64 的 `MULW`），CPU manifest 若只声明 Zmmul，不能生成除法指令。

## 7. A：原子指令（完整基础清单）

### 7.1 通用编码

```text
funct5 = inst[31:27]
aq     = inst[26]
rl     = inst[25]
rs2    = inst[24:20]
rs1    = inst[19:15]
funct3 = inst[14:12]       // W=010, D=011
rd     = inst[11:7]
opcode = 0101111
```

`aq=1` 表示 acquire，`rl=1` 表示 release；两位可组合为 relaxed/acquire/release/aq+rl。地址必须满足自然对齐，具体执行环境决定异常行为。

### 7.2 RV32A/RV64A

| `funct5` | `.W`/`.D` 指令 | 语义/固定约束 |
|---|---|---|
| `00010` | `LR.W` / `LR.D` | load-reserved；`rs2` 必须为 `00000`。 |
| `00011` | `SC.W` / `SC.D` | store-conditional；rd=0 成功，1 失败。 |
| `00001` | `AMOSWAP.W` / `.D` | 原子交换。 |
| `00000` | `AMOADD.W` / `.D` | 原子加。 |
| `00100` | `AMOXOR.W` / `.D` | 原子异或。 |
| `01100` | `AMOAND.W` / `.D` | 原子与。 |
| `01000` | `AMOOR.W` / `.D` | 原子或。 |
| `10000` | `AMOMIN.W` / `.D` | 有符号最小值。 |
| `10100` | `AMOMAX.W` / `.D` | 有符号最大值。 |
| `11000` | `AMOMINU.W` / `.D` | 无符号最小值。 |
| `11100` | `AMOMAXU.W` / `.D` | 无符号最大值。 |

`.D` 和 `LD/SD` 是 RV64 可用；RV32 只生成 `.W`。A 指令的 memory ordering 与依赖图有关：LR/SC 有 reservation 依赖，AMO 有 read-modify-write 原子依赖，不能被拆成两个独立普通 load/store 事务。

## 8. F：单精度浮点（完整指令组与字段）

F 依赖 Zicsr，增加 `f0..f31` 和 `fcsr`；`fmt=00` 表示 S，`rm` 编码为 `RNE=000, RTZ=001, RDN=010, RUP=011, RMM=100, DYN=111`，`101/110` 保留。

OP-FP 通用布局：

```text
op5[31:27] fmt[26:25] rs2[24:20] rs1[19:15] rm/funct3[14:12] rd[11:7] 1010011
```

以下表中的 `op5`、`fmt` 和 `funct3/rs2` 共同构成固定 0/1 位；未标字段为变量。

### 8.1 Load/store 和 FMA

| 指令 | 格式/固定字段 | 语义 |
|---|---|---|
| `FLW` | I，`opcode=0000111, funct3=010` | `rd` 为 f 寄存器，加载 32 bit。 |
| `FSW` | S，`opcode=0100111, funct3=010` | `rs2` 为 f 寄存器，保存 32 bit。 |
| `FMADD.S` | R4，`opcode=1000011, fmt=00` | `(rs1*rs2)+rs3`。 |
| `FMSUB.S` | R4，`opcode=1000111, fmt=00` | `(rs1*rs2)-rs3`。 |
| `FNMSUB.S` | R4，`opcode=1001011, fmt=00` | `-(rs1*rs2)+rs3`。 |
| `FNMADD.S` | R4，`opcode=1001111, fmt=00` | `-(rs1*rs2)-rs3`。 |

FMA 的 `rm` 在 `[14:12]`，`rs3` 在 `[31:27]`，所以不能按普通 R-type 把 `[31:27]` 当作固定 funct7。

### 8.2 OP-FP 算术、比较和分类

| 指令 | `op5` | `fmt` | `funct3`/`rs2` 固定 | 语义 |
|---|---|---|---|---|
| `FADD.S` | `00000` | `00` | `rm` | 加。 |
| `FSUB.S` | `00001` | `00` | `rm` | 减。 |
| `FMUL.S` | `00010` | `00` | `rm` | 乘。 |
| `FDIV.S` | `00011` | `00` | `rm` | 除。 |
| `FSQRT.S` | `01011` | `00` | `rs2=00000, rm` | 平方根。 |
| `FSGNJ.S` | `00100` | `00` | `funct3=000` | 取 rs1 数值位、rs2 符号位。 |
| `FSGNJN.S` | `00100` | `00` | `funct3=001` | 符号位取反后注入。 |
| `FSGNJX.S` | `00100` | `00` | `funct3=010` | 符号位 XOR 后注入。 |
| `FMIN.S` | `00101` | `00` | `funct3=000` | 最小值，按 NaN/±0 规则。 |
| `FMAX.S` | `00101` | `00` | `funct3=001` | 最大值，按 NaN/±0 规则。 |
| `FLE.S` | `10100` | `00` | `funct3=000` | `rs1 <= rs2`，结果写整数 rd。 |
| `FLT.S` | `10100` | `00` | `funct3=001` | `rs1 < rs2`。 |
| `FEQ.S` | `10100` | `00` | `funct3=010` | `rs1 == rs2`。 |
| `FCLASS.S` | `11100` | `00` | `rs2=00000, funct3=001` | 写 10-bit 分类 mask。 |
| `FMV.X.W` | `11100` | `00` | `rs2=00000, funct3=000` | f bit pattern -> integer rd。RV64 高位复制符号位。 |
| `FMV.W.X` | `11110` | `00` | `rs2=00000, funct3=000` | integer rs1 低 32 bit -> f rd。 |

`FLE/FLT/FEQ` 的结果目标是整数寄存器；`FSGNJ`、`FMV` 是 bit-level 操作，不应被测试器按浮点数值归一化。FCLASS 的 rd 低 10 bit 依次表示负无穷、负正规、负次正规、负零、正零、正次正规、正正规、正无穷、signaling NaN、quiet NaN，且恰有一位为 1。

### 8.3 F 转整数与整数转 F

布局仍为 OP-FP，`fmt=00`；`op5=11000` 表示 float -> integer，`op5=11010` 表示 integer -> float。`rs2` 选择整数格式：`00000=W`、`00001=WU`、`00010=L`、`00011=LU`。

| 指令 | 固定字段 | 可用 XLEN | 语义 |
|---|---|---|---|
| `FCVT.W.S` | `op5=11000, fmt=00, rs2=00000, rm` | RV32/RV64 | S -> signed W。RV64 sign-extend。 |
| `FCVT.WU.S` | `op5=11000, rs2=00001` | RV32/RV64 | S -> unsigned W。 |
| `FCVT.L.S` | `op5=11000, rs2=00010` | RV64 | S -> signed L。 |
| `FCVT.LU.S` | `op5=11000, rs2=00011` | RV64 | S -> unsigned L。 |
| `FCVT.S.W` | `op5=11010, rs2=00000` | RV32/RV64 | signed W -> S。 |
| `FCVT.S.WU` | `op5=11010, rs2=00001` | RV32/RV64 | unsigned W -> S。 |
| `FCVT.S.L` | `op5=11010, rs2=00010` | RV64 | signed L -> S。 |
| `FCVT.S.LU` | `op5=11010, rs2=00011` | RV64 | unsigned L -> S。 |

## 9. D：双精度浮点（完整增量指令组）

D 依赖 F，`fmt=01`，`FLEN=64`；D 包含 F 的单精度指令语义，同时增加以下双精度/交叉精度指令。OP-FP 的 0/1 规则与 F 完全相同，唯一变化是 `fmt=01` 和相应的 load/store opcode。

| 指令组 | 指令清单 | 字段规则 |
|---|---|---|
| 访存 | `FLD`, `FSD` | `FLD`: I，`opcode=0000111, funct3=011`；`FSD`: S，`opcode=0100111, funct3=011`。 |
| FMA | `FMADD.D`, `FMSUB.D`, `FNMSUB.D`, `FNMADD.D` | FMA opcode 依次为 `1000011/1000111/1001011/1001111`，`fmt=01`，`rm`/`rs3`/寄存器字段同 F。 |
| 算术 | `FADD.D`, `FSUB.D`, `FMUL.D`, `FDIV.D`, `FSQRT.D` | `op5` 依次 `00000/00001/00010/00011/01011`，`fmt=01`；平方根 `rs2=00000`。 |
| 符号 | `FSGNJ.D`, `FSGNJN.D`, `FSGNJX.D` | `op5=00100, fmt=01`，`funct3=000/001/010`。 |
| 最值 | `FMIN.D`, `FMAX.D` | `op5=00101, fmt=01`，`funct3=000/001`。 |
| 比较 | `FLE.D`, `FLT.D`, `FEQ.D` | `op5=10100, fmt=01`，`funct3=000/001/010`。 |
| 分类/搬运 | `FCLASS.D`, `FMV.X.D`, `FMV.D.X` | `FCLASS.D`/`FMV.X.D`: `op5=11100, fmt=01`，`rs2=00000`，`funct3=001/000`；`FMV.D.X`: `op5=11110, fmt=01`，`rs2=00000, funct3=000`；`FMV.X.D/FMV.D.X` 主要为 RV64。 |

### 9.1 D 的转换指令

float/int 转换的固定字段用 `rs2` 标识源格式，`fmt` 标识目标/操作格式。为了避免把交叉格式字段手工写错，decoder 生成阶段必须从官方 opcode 表的 `mask/match` 读取；以下列出完整名称集合和可变字段含义：

| 指令 | 源 -> 目标 | 额外字段 |
|---|---|---|
| `FCVT.W.D`, `FCVT.WU.D` | D -> signed/unsigned W | `op5=11000, fmt=01, rs2=00000/00001, rm`。 |
| `FCVT.L.D`, `FCVT.LU.D` | D -> signed/unsigned L | `rs2=00010/00011`，RV64。 |
| `FCVT.D.W`, `FCVT.D.WU` | signed/unsigned W -> D | `op5=11010, fmt=01, rs2=00000/00001, rm`。 |
| `FCVT.D.L`, `FCVT.D.LU` | signed/unsigned L -> D | `rs2=00010/00011`，RV64。 |
| `FCVT.S.D` | D -> S | `op5=01000, fmt=00, rs2=00001, rm, opcode=1010011`。 |
| `FCVT.D.S` | S -> D | `op5=01000, fmt=01, rs2=00000, rm, opcode=1010011`。 |

不同官方版本对表格展示（`funct7`/`op5+fmt`）有所不同，但字段语义一致；将 `fmt`、源格式 `rs2`、`rm` 和 `mask/match` 一起保存，不能只保存 mnemonic。

## 10. C：压缩指令（16-bit 完整目录）

C 不是独立 ISA，必须与 RV32I/RV64I 或 F/D 共同启用。`inst[1:0]` 为 quadrant，`inst[15:13]` 为 funct3；`x8..x15` 用三位压缩寄存器字段 `rd' / rs1' / rs2'` 表示。

### 10.1 压缩格式字段

| 格式 | `inst[15:0]` 从高到低 | 典型用途 |
|---|---|---|
| CR | `funct4 rd/rs1 rs2 op` | JR、MV、ADD、EBREAK。 |
| CI | `funct3 imm rd/rs1 imm op` | ADDI、LI、LUI、SLLI、SP load。 |
| CSS | `funct3 imm rs2 op` | SP-relative store。 |
| CIW | `funct3 imm rd' op` | ADDI4SPN。 |
| CL | `funct3 imm rs1' rd' op` | register-based load。 |
| CS | `funct3 imm rs1' rs2' op` | register-based store。 |
| CA | `funct6 rd'/rs1' funct2 rs2' op` | SUB/XOR/OR/AND。 |
| CB | `funct3 offset rs1' offset op` | BEQZ/BNEZ、shift/ANDI。 |
| CJ | `funct3 jump_target op` | J/JAL。 |

其中 `op=00/01/10` 分别为 quadrant 0/1/2；`op=11` 不是普通 C 指令而是 32-bit/更长指令前缀。立即数同样采用重排，且压缩分支/跳转 offset 以 2 byte 为单位。

### 10.2 Quadrant 0：`inst[1:0]=00`

| `funct3` | 指令 | 依赖/变体 |
|---|---|---|
| `000` | `C.ADDI4SPN` | CIW；`nzuimm != 0`，`rd' <- x2 + nzuimm`，立即数按 4 对齐。 |
| `001` | `C.FLD` | D，CL；RV32/RV64 的浮点寄存器变体。 |
| `010` | `C.LW` | CL，32-bit integer load。 |
| `011` | `C.FLW`（RV32）/`C.LD`（RV64） | 同一主编码按 XLEN/profile 解释。 |
| `100` | reserved | 不生成。 |
| `101` | `C.FSD` | D，CS。 |
| `110` | `C.SW` | CS，32-bit store。 |
| `111` | `C.FSW`（RV32）/`C.SD`（RV64） | 按 profile 选择。 |

### 10.3 Quadrant 1：`inst[1:0]=01`

| `funct3` | 子字段/指令 | 约束 |
|---|---|---|
| `000` | `C.ADDI`；RV64 为 `C.ADDIW` | `rd != x0` 时为自加立即数；rd=x0/imm=0 的编码包含 NOP/HINT 规则。 |
| `001` | RV32 `C.JAL`；RV64 `C.ADDIW` | XLEN 决定同一 funct3 的解释。 |
| `010` | `C.LI` | `rd != x0` 是正常指令，rd=x0 为 HINT。 |
| `011` | `C.ADDI16SP` 或 `C.LUI` | `rd=x2` 选择 ADDI16SP；nzimm 不得为 0；其他 rd 用 LUI，rd=x0 或 imm=0 受保留/HINT 规则限制。 |
| `100` | `C.SRLI`, `C.SRAI`, `C.ANDI`, `C.SUB`, `C.XOR`, `C.OR`, `C.AND` | bits `[11:10]` 选择 shift/ANDI；bits `[6:5]` 选择 SUB/XOR/OR/AND；RV64 另有 `C.SUBW/C.ADDW`。 |
| `101` | `C.J` | CJ；符号扩展的跳转 offset。 |
| `110` | `C.BEQZ` | CB；`rs1' == 0` 时分支。 |
| `111` | `C.BNEZ` | CB；`rs1' != 0` 时分支。 |

### 10.4 Quadrant 2：`inst[1:0]=10`

| `funct3` | 指令族 | 约束 |
|---|---|---|
| `000` | `C.SLLI` | CI；`rd != x0`，RV32/RV64 shamt 宽度按 XLEN。 |
| `001` | `C.FLDSP` | D；CI，SP-relative double load。 |
| `010` | `C.LWSP` | CI，SP-relative 32-bit integer load。 |
| `011` | `C.FLWSP`（RV32F）/`C.LDSP`（RV64） | 按 F/XLEN profile。 |
| `100` | `C.JR`, `C.MV`, `C.EBREAK`, `C.JALR`, `C.ADD` | `funct4`、rd/rs2 是否为 0 决定子指令；JR/JALR 的 rs1 不能为 x0。 |
| `101` | `C.FSWSP`（RV32F）/`C.FSDSP`（D） | CSS；SP-relative FP store。 |
| `110` | `C.SWSP` | CSS；32-bit store。 |
| `111` | `C.FSWSP`（RV32F）/`C.SDSP`（RV64） | CSS；按 F/XLEN profile 选择。 |

不同 XLEN/F/D profile 会复用 C 的主编码，因此 C decoder 必须以 `xlen + extensions` 作为输入。零值编码、rd=x0、nzimm=0、保留位和 HINT 不能随机填成普通合法指令。

### 10.5 C 指令完整名称索引

```text
C.ADDI4SPN C.FLD C.LW C.FLW C.LD C.FSD C.SW C.FSW C.SD
C.ADDI C.ADDIW C.JAL C.J C.LI C.LUI C.ADDI16SP
C.SRLI C.SRAI C.ANDI C.SUB C.XOR C.OR C.AND
C.SUBW C.ADDW C.BEQZ C.BNEZ
C.SLLI C.LWSP C.LDSP C.FLWSP C.FLDSP
C.JR C.MV C.EBREAK C.JALR C.ADD
C.SWSP C.SDSP C.FSWSP C.FSDSP
```

上面的索引包含按 profile 复用的名称；生成器在没有 `RV64`、`F` 或 `D` 时删除对应变体。`C.NOP` 是 `C.ADDI x0, 0` 的语义 alias，不是额外编码。

## 11. B 与常用 Z 扩展目录

这些指令不能无条件加入 Ibex/CVA6/BOOM。下表是常用、适合 fuzz 的已分组名称；精确 `mask/match` 应由官方 opcode 数据生成并按 `RV32/RV64` 过滤。

| 子扩展 | 指令目录 | 主要字段/语义 |
|---|---|---|
| Zba | `ADD.UW`, `SH1ADD`, `SH2ADD`, `SH3ADD`, `SH1ADD.UW`, `SH2ADD.UW`, `SH3ADD.UW`, `SLLI.UW`；`ZEXT.W` 为常见 alias | shift-and-add 地址生成；`.UW` 使用低 32 bit 并零扩展；RV64 变体。 |
| Zbb | `ANDN`, `ORN`, `XNOR`, `CLZ`, `CTZ`, `CPOP`, `CLZW`, `CTZW`, `CPOPW`, `MIN`, `MINU`, `MAX`, `MAXU`, `SEXT.B`, `SEXT.H`, `ZEXT.H`, `ROL`, `ROR`, `ROLW`, `RORW`, `RORI`, `RORIW`, `ORC.B`, `REV8` | 位逻辑、计数、最值、旋转、字节反转/合并；W 变体为 RV64。 |
| Zbc | `CLMUL`, `CLMULH`, `CLMULR` | carry-less multiplication。 |
| Zbs | `BCLR`, `BCLRI`, `BEXT`, `BEXTI`, `BINV`, `BINVI`, `BSET`, `BSETI` | bit index 来自寄存器或立即数；索引超范围按 XLEN 规则。 |
| Zicond | `CZERO.EQZ`, `CZERO.NEZ` | 条件为零/非零时选择零或 rs1；依赖 profile。 |
| Zca | 主要非浮点 C 指令 | C 的 integer 子集。 |
| Zcb | `C.ZEXT.B`, `C.SEXT.B`, `C.ZEXT.H`, `C.SEXT.H`, `C.ZEXT.W`, `C.NOT`, `C.MUL`, `C.LBU`, `C.LHU`, `C.LH`, `C.SB`, `C.SH` 等 | 代码尺寸扩展；必须按 RV32/RV64 和 Zcb 版本读取。 |
| Zcmp/Zcmt | push/pop、table jump 等 | 组合/函数序言和表跳转，不能当成普通 C。 |

`B` 的 canonical shorthand 不是“所有 bit 指令的无条件开关”；推荐 manifest 写成 `Zba/Zbb/Zbc/Zbs`，这样可以精确表达 Ibex 的 `RV32B` 子集和 CVA6/BOOM 配置差异。

## 12. 指令机器可读记录

指令数据库建议使用下列最小记录；它可以直接被 decoder、合法化器、coverage 分类器和指令序列发生器共享：

```json
{
  "mnemonic": "beq",
  "extension": "I",
  "xlen": [32, 64],
  "length": 32,
  "format": "B",
  "mask": "0x707f",
  "match": "0x63",
  "fixed_fields": {
    "opcode": "1100011",
    "funct3": "000"
  },
  "variable_fields": ["bimm12", "rs1", "rs2"],
  "semantic_tags": ["control_flow", "signed_compare"],
  "requires": ["RV32I"],
  "profiles": ["ibex.rv32i", "cva6.rv64i", "boom.rv64i"]
}
```

### 12.1 生成/验证规则

1. 从官方 opcode 表解析每一条 regular instruction；保留 `encoding`、`mask`、`match`、variable fields 和 extension。
2. 将 pseudo-op 单独存为 alias，不能把 alias 当作独立 coverage point 或重复 decoder case。
3. 检查同一 profile 内 `mask/match` 是否产生不可消解重叠；有 overlap 时用 extension/XLEN/privilege 条件分层，仍不能静默选一条。
4. 检查保留编码：立即数的 `0`/非零、寄存器 x0 禁止、`rs2=0`、`rm` 保留值、对齐和特权级。
5. 生成指令时先选合法 record，再填寄存器/立即数；不要从 32 个随机 bit 直接希望命中合法指令。
6. 将 `instruction_id`、`extension`、`encoding_hash` 写入 sample metadata，便于跨 CPU 比较。

### 12.2 对 RFuzz 的映射建议

当前 Ibex RFuzz ABI 仍是顶层 395-bit / 56-byte 输入，不能把指令表强行替换成变长软件指令流。推荐增加一个固定宽度的“指令投影层”：

```text
raw bits -> fixed instruction template fields
         -> profile-aware mask/match check
         -> legal instruction or bounded fallback
         -> instr_rdata_i / memory response / protocol projection
```

该层必须：

```text
保持原 raw_width 和 RFuzz byte 输入结构
记录每个 raw bit 的 destination/action/category
使用固定宽度切片、XOR fold、mask、bounded event select
不丢 sample、不额外抽随机数、不无限等待、不读取反馈改变输入宽度
同一比较组的 CPU/harness 使用相同 raw_width、seed 和预算
```

指令内部字段的依赖应显式登记，例如：

```text
opcode -> instruction_record
instruction_record -> required_extension / operand_format
format -> immediate_fields / alignment
load_store -> address_region / byte_enable / response
CSR -> privilege_mode / csr_access_policy
AMO/LRSC -> reservation_state / memory_order
compressed_quadrant -> xlen + C + F/D profile
```

## 13. CPU 指令集与实现的对照原则

| 对照项 | Ibex | CVA6 | BOOM |
|---|---|---|---|
| XLEN | RV32 | RV32/RV64 配置 | 常见 RV64 |
| 最小整数基线 | RV32I/E 配置 | RV32I 或 RV64I | RV64I |
| M/A | M 可选；A 通常不作为 Ibex 基线 | M/A 常见 | M/A 属于常见 G profile |
| F/D | 通常不在微控制器 Ibex 默认配置 | 可选 | `GC` 文档 profile 包含 F/D |
| C | 常见 | 可选/常见 | G profile 中常见 |
| B/Z* | Ibex 可有 B 子集；以参数为准 | 可选 | 以 Rocket/BOOM config 为准 |
| privileged/CSR | 实现部分 M-mode CSR | 依平台/MMU/特权配置 | privileged + 高性能平台状态 |
| custom | Ibex 参数和安全扩展 | 具体配置/平台 | BOOM/Rocket Chip custom 需单独登记 |

因此，后续系统应分别生成 `isa_profile_id`，例如 `ibex.rv32imc`、`cva6.rv64imafdc`、`boom.rv64imafdc`，而不是只生成 `cpu=ibex/cva6/boom`。协议组合和指令生成分别引用这个 profile，二者在 composition IR 中通过 `cpu_endpoint` 和 `isa_profile` 关联。

## 14. 参考资料

### RISC-V 官方规范

- [RISC-V Ratified Specifications Library](https://docs.riscv.org/)
- [RV32I/RV64I base integer instructions](https://docs.riscv.org/reference/isa/v20260120/unpriv/rv32.html)
- [M extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/m-st-ext.html)
- [A extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/a-st-ext.html)
- [F extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/f-st-ext.html)
- [D extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/d-st-ext.html)
- [C extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/c-st-ext.html)
- [Zicsr](https://docs.riscv.org/reference/isa/unpriv/zicsr.html)
- [Zifencei](https://docs.riscv.org/reference/isa/unpriv/zifencei.html)
- [Privileged Architecture](https://docs.riscv.org/reference/isa/v20260120/priv/priv-index.html)
- [B extension](https://docs.riscv.org/reference/isa/v20260120/unpriv/b-st-ext.html)
- [RISC-V official opcode database and mask/match generator](https://github.com/riscv/riscv-opcodes)

### CPU 官方资料

- [Ibex repository and supported configurations](https://github.com/lowRISC/ibex)
- [Ibex integration parameters](https://github.com/lowRISC/ibex/blob/master/doc/02_user/integration.rst)
- [CVA6 programmer view](https://cva6.readthedocs.io/en/stable/01_cva6_user/Programmer_View.html)
- [CVA6 requirements](https://cva6.readthedocs.io/en/stable/02_cva6_requirements/cva6_requirements_specification.html)
- [BOOM RISC-V ISA](https://docs.boom-core.org/en/latest/sections/intro-overview/riscv-isa.html)
- [PicoRV32 README](https://github.com/YosysHQ/picorv32/blob/main/README.md)
- [VexRiscv project](https://github.com/SpinalHDL/VexRiscv)
- [CV32E40P user manual](https://cv32e40p.readthedocs.io/en/latest/intro.html)
- [NEORV32 project](https://github.com/stnolting/neorv32)

### 本地 RFuzz/组合约束

- [Ibex RFuzz baseline harness 与 395-bit mapping](IBEX_41_PRE_POST_AND_BASELINE_HARNESS_20260616.md)
- [Ibex scheme5 bit constraints](IBEX_SCHEME5_BIT_CONSTRAINTS.md)
- [CPU/IP 多组件实验计划](CPU_IP_MULTICOMPONENT_EXPERIMENT_PLAN.md)
- [composition IR schema](../schemas/composition_ir.v1.schema.json)
- [candidate manifest schema](../schemas/candidate_manifest.v1.schema.json)
