# 子字（LB/LBU/LH/LHU/SB/SH）主机接入补丁计划

日期：2026-11-01。状态：**待应用**。本文件只描述补丁，不修改执行器、C++ host、既有测试/配置/文档，也不产生 RTL 结果。应用后由父 agent 在真实 CPU 上跑固定记录与 fuzz 批次，证据写入新的 `runs/` 目录。

## 0. 结论与范围

Python 侧的唯一权威已经是 `src/myfuzz/fuzz/rv32_subword.py`（本次修复完成）：`validate_subword_program`、`generate_subword_program`、`mutate_subword_program`、`reference_run_subword`、`subword_access`。它现在能正确接受/拒绝 LB/LH/LW/LBU/LHU/SB/SH/SW，并给出带指令下标的拒绝消息。

当前树里入口已经有一条**可用的 opt-in 分支**：`scripts/run_inprocess_f1f6.py:811-817` 在 `f1_subword=True` 时直接调用 `validate_subword_program`，因此 Python 侧不需要再改也能接受子字程序；`_validate_f1_program`（同文件 `823-885`）仍保持 legacy 的 `funct3 == 2`（`850-852`），只在 `f1_subword=False` 时使用。**本补丁的最小工作集中在 C++ host 的两处门禁和 RAM 地址/字节使能路径**；Python 侧只建议做文档/一致性收尾，或在父 agent 决定把分支合并进 `_validate_f1_program` 时按 §2.2 改。

应用本补丁后，一条 F1 记录里的 LB/LH/LW/LBU/LHU/SB/SH/SW 会真正进入 trampoline 执行，`data_changed`、`prog_rd_mask`、`prog_last_wdata` 和 `data_hash_after` 都由真实 CPU 退休/RVFI 产生，而不是从指令流推断。

## 1. 当前锚点（本树）

| 文件:行 | 现状 | 补丁 |
|---|---|---|
| `scripts/run_inprocess_f1f6.py:797-820` | `validate_record` 已有 `f1_subword` 分支（811-817），直接调用 `validate_subword_program` | 保留；补 docstring（§2.1） |
| `scripts/run_inprocess_f1f6.py:823-885` | `_validate_f1_program` 只接受 `funct3 == 2`（850-852） | 仅当合并分支时按 §2.2 改 |
| `scripts/run_inprocess_f1f6.py:2661-2664` | 读取 `f1_subword`，要求 bool 且 `f1_program_words > 1` | 保留；这就是建议的配置名 |
| `scripts/run_inprocess_f1f6.py:1404` | 生成 `#define F1_ALLOW_SUBWORD <0/1>` | 保留；C++ 侧开始使用它 |
| `scripts/run_inprocess_f1f6.py:2436-2464` | fuzz gate/strategy 已传 `f1_subword` | 保留 |
| `scripts/run_inprocess_f1f6.py:2962-2974` | `f1_program.limit` 文案仍写 “LW/SW only” | 子字开启时更新文案（§5） |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp:240-253` | `F1_MAX_WORDS`、`PROGRAM_DATA_WORDS` 默认值 | 新增 `F1_ALLOW_SUBWORD` 默认 0（§3.1） |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp:586-639` | `make_record` 的 F1 门，619-632 只认 `funct3 == 2` | 按 §3.2 替换 619-632 |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp:1452-1453` | Wishbone 全局拒绝 `req_sel != 15` | 移到 `in_ip` 分支内（§4.1） |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp:1471-1473` | Wishbone RAM 分支已把 `req_sel` 传给 `memory.write` | 只补地址对齐（§4.1） |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp:1149-1150` | OBI 数据口 `da = CPU_D_REQ_ADDR`、`dbe = CPU_D_REQ_BE` | OBI 是**字节地址**；RAM 访问前必须 `da & ~3u`（§4.2） |
| `scripts/inprocess_obi_apb_f1f4_spike.cpp:1540-1582` | OBI `in_ip`/`in_dma` 的 `dbe != 15` 只挡目标/控制；RAM 只检查 `dbe > 15`，但 `memory.read/write(da)` 直接用了字节地址 | 保留目标/控制守卫；RAM 的 `in_ram`、`memory.read`、`memory.write`、`dat.value` 全部用 `da & ~3u`（§4.2） |
| `scripts/inprocess_memory.h:27-30` | `Memory::write(address, value, be)` 已按 `be` 写字节 | 不改 |
| `src/myfuzz/fuzz/strategy.py:52,65-67,91-107` | `f1_subword` 生成/变异 opt-in 已接好 | 不改（见 §5 的兼容性说明） |

> 行号以本树当前内容为准；父 agent 应用时按“文件 + 代码片段”匹配，不要只按行号。
>
> 统一入口只编译 `scripts/inprocess_obi_apb_f1f4_spike.cpp`（`run_inprocess_f1f6.py:2855`）；`scripts/inprocess_wb_cpu_spike.cpp`、`scripts/inprocess_obi_apb_gpio_spike.cpp` 等旧单用途 host 不在本补丁范围，不要顺手改它们。

## 2. Python 入口门

### 2.1 推荐：保留现有分支，只收尾（最小改动）

`validate_record` 的 811-817 已经是正确行为：

```python
    if f1_subword:
        from myfuzz.fuzz.rv32_subword import validate_subword_program
        from myfuzz.riscv.profile import RiscvProfile
        profile = RiscvProfile(isa.xlen, frozenset(isa.extensions),
                               isa.instruction_alignment, 32, 0)
        validate_subword_program(profile, record['fields'],
                                 window_size=PROGRAM_DATA_WORDS * 4)
    else:
        _validate_f1_program(record['fields'], isa=isa, windows=windows)
```

建议只改 `validate_record` 的 docstring（797-805）：把“its only memory words LW/SW”改成“默认只允许 LW/SW；`f1_subword=True` 时允许 LB/LH/LW/LBU/LHU/SB/SH/SW，规则由 `rv32_subword` 单点定义”。功能不变。

**不要**在 `f1_subword=True` 分支里再调用 `validate_instruction_bytes`：它当前拒绝 LB/LH/LBU/LHU/SH（实测：LW/SW/SB 通过，LB/LH/LBU/LHU/SH 报 `unsupported first-stage RV32I instruction encoding`）。`validate_subword_program` 已用 `validate_program_words` 覆盖非内存字的 profile/扩展/保留寄存器规则，内存字由模块自己检查；再叠一层 legacy ISA 门会错误拒绝子字。

### 2.2 可选：把子字规则合并进 `_validate_f1_program`

如果父 agent 希望 `_validate_f1_program` 自己成为唯一入口（而不是在 `validate_record` 里分支），按下面改；否则**不要**动它。

1. 签名加参数（`823`）：

```python
def _validate_f1_program(words, *, isa, windows, f1_subword=False):
```

2. 把 849-862 的内存块替换为：

```python
        if memory:
            load_funct3 = {0, 1, 2, 4, 5}
            store_funct3 = {0, 1, 2}
            allowed = load_funct3 if opcode == 0x03 else store_funct3
            if f1_subword:
                if funct3 not in allowed:
                    raise ValueError(
                        'F1 program memory word ' + str(index) +
                        ' memory funct3 ' + str(funct3) + ' is not ' +
                        ('LB/LH/LW/LBU/LHU' if opcode == 0x03
                         else 'SB/SH/SW'))
                size = {0: 1, 1: 2, 2: 4, 4: 1, 5: 2}[funct3]
            else:
                if funct3 != 2:
                    raise ValueError('F1 program memory word ' + str(index) +
                                     ' is not LW or SW')
                size = 4
            if rs1 != 18:
                raise ValueError('F1 program memory word ' + str(index) +
                                 ' must use x18 as its base')
            if offset % size:
                raise ValueError('F1 program memory word ' + str(index) +
                                 ' offset ' + str(offset) + ' is not ' +
                                 str(size) + '-byte aligned')
            if not 0 <= offset <= window_bytes - size:
                raise ValueError('F1 program memory word ' + str(index) +
                                 ' memory access leaves the declared data window '
                                 '(offset ' + str(offset) + ', size ' + str(size) + ')')
            if opcode == 0x03 and rd in (8, 9, 18):
                raise ValueError('F1 program load ' + str(index) +
                                 ' may not overwrite x8, x9 or x18')
```

3. 末尾 872-884 的 ISA 门对子字内存字要跳过：

```python
        if opcode == 0x17 or (f1_subword and memory):
            pass
        else:
            try:
                validate_instruction_bytes(word.to_bytes(4, 'little'), isa=isa)
            except Exception as error:
                raise ValueError(...)
```

4. `validate_record` 调用处（819）改为：

```python
        _validate_f1_program(record['fields'], isa=isa, windows=windows,
                             f1_subword=f1_subword)
```

并在 811-817 删除/保留分支二选一：**要么**保留分支并让 `_validate_f1_program` 不再被 subword 调用，**要么**删除分支、统一走 `_validate_f1_program(..., f1_subword=f1_subword)`。不要两处都做规则判断，避免消息漂移。

### 2.3 配置名与 profile

- 配置键就用现有的 **`f1_subword`**（bool），与 `f1_program_words > 1` 绑定（2661-2664 已有校验）。C++ 头文件宏名是 **`F1_ALLOW_SUBWORD`**（1404 已生成），两者一一对应。
- profile 由 `RiscvProfile(isa.xlen, ..., 32, 0)` 构造。注意：模块支持 `register_count == 16` 的 RV32E 并会拒绝内存字（没有 x18），但入口这里硬编码 32；当前 `f1_isa_from_profile` 要求 `I`，RV32E 不会走到 F1 程序模式，所以不是现实问题。若将来允许 E，必须传真实 `register_count`，否则 Python 会放行 x18（见 §7 决策 6）。

## 3. C++ `make_record`

### 3.1 默认宏

在 `scripts/inprocess_obi_apb_f1f4_spike.cpp:240-253` 的 `F1_MAX_WORDS` 附近加：

```cpp
// Whether an F1 program may use byte/halfword loads and stores.  The generated
// spike_config.h sets this from the scenario's f1_subword flag; a hand-built
// host keeps the legacy LW/SW-only gate.
#ifndef F1_ALLOW_SUBWORD
#define F1_ALLOW_SUBWORD 0
#endif
```

`spike_config.h` 在源文件第 28 行被 `#include`，生成器已在 `run_inprocess_f1f6.py:1404` 写入该宏，所以不需要再改编译命令行。

### 3.2 替换 619-632 的内存门

把：

```cpp
      if (memory) {
        if (funct3 != 2u)
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " is not LW or SW");
        if (rs1 != 18u)
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " must use x18, the declared data-window base");
        if (offset % 4 || offset < 0
            || offset > int(PROGRAM_DATA_WORDS * 4 - 4))
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " leaves the declared data window");
        if (opcode == 0x03u && (rd == 8u || rd == 9u || rd == 18u))
          throw std::runtime_error("F1 program load " + std::to_string(index) +
                                   " may not overwrite x8, x9 or x18");
      } else if (rd == 8u) {
```

换成：

```cpp
      if (memory) {
        // F1_ALLOW_SUBWORD is a compile-time fact from spike_config.h: a host
        // built for a scenario without the opt-in keeps the legacy LW/SW gate.
#if F1_ALLOW_SUBWORD
        const bool is_load = opcode == 0x03u;
        const bool width_ok =
            is_load ? (funct3 == 0u || funct3 == 1u || funct3 == 2u
                       || funct3 == 4u || funct3 == 5u)
                    : (funct3 == 0u || funct3 == 1u || funct3 == 2u);
        if (!width_ok)
          throw std::runtime_error(
              "F1 program memory word " + std::to_string(index) +
              (is_load ? " is not LB/LH/LW/LBU/LHU" : " is not SB/SH/SW"));
        const unsigned size = (funct3 == 0u || funct3 == 4u) ? 1u
                            : (funct3 == 1u || funct3 == 5u) ? 2u : 4u;
#else
        if (funct3 != 2u)
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " is not LW or SW");
        const unsigned size = 4u;
#endif
        if (rs1 != 18u)
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " must use x18, the declared data-window base");
        if (offset % int(size) || offset < 0
            || offset > int(PROGRAM_DATA_WORDS * 4) - int(size))
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " leaves the declared data window");
        if (opcode == 0x03u && (rd == 8u || rd == 9u || rd == 18u))
          throw std::runtime_error("F1 program load " + std::to_string(index) +
                                   " may not overwrite x8, x9 or x18");
      } else if (rd == 8u) {
```

要点：

- 载入宽度表与 Python `_LOADS` 一致：`0/1/2/4/5`；存储：`0/1/2`。`funct3 == 3`（LD）和 `6/7` 在 RV32 上仍拒绝。
- 对齐按自然宽度：LB/SB 任意字节，LH/SH 2 字节，LW/SW 4 字节。
- 窗口上界是 `PROGRAM_DATA_WORDS * 4 - size`；LB 可以到 63，LH 到 62，LW 到 60。
- 保留寄存器规则不变：载入的 `rd` 不得是 8/9/18；存储的 `rs2` 可以是 8/9/18（数据来源），不要误拒。
- `offset < 0` 必须保留：12 位有符号立即数可以是负数，Python 与 reference 都会拒绝，host 也要拒绝。

### 3.3 观察字段不需要改

- `data_changed`（`inprocess_obi_apb_f1f4_spike.cpp:1722-1725`）按 16 个字采样，子字写只改一个字，仍然计 1；两个子字写落在同一字只计 1。这是**字粒度**语义，不要改成字节粒度。
- `data_hash_after`（571-581、1722）是逐字节 FNV-1a，能区分同一字内不同 lane，是字节级证据。
- `prog_rd_mask` / `prog_last_wdata`（1330-1336）来自 RVFI `rd_addr`/`rd_wdata`；LB/LH 的写回由 CPU 做符号扩展，LBU/LHU 零扩展，host 不需要再处理。
- 可选证据行（建议加，便于直接断言真实字节使能）：在 F1 的 `case` 行（1981-1989）追加

```cpp
                  << " data_write_accepted " << int(observation.write_accepted)
                  << " data_write_addr " << hex32(observation.write_address)
                  << " data_write_be " << observation.write_be
```

`observation.write_be` 记录的是**最后一次**进入数据窗口的写（F1 程序里就是最后一条 store 的 `req_sel`/`dbe`）。如果程序没有 store，`write_accepted == 0`，不要把它当成 `be == 0` 的证据。

## 4. RAM 字节使能路径

### 4.1 Wishbone（`CPU_BUS_WISHBONE`）

当前 1452-1453 在任何地址解码之前就拒绝 `req_sel != 15`。改为只拒绝**目标/控制**的 partial 写，RAM 放行：

```cpp
        if (req_wide > UINT32_MAX)
          throw std::runtime_error("Wishbone address out of range");
        if (in_ip(req_addr)) {
          if (req_write && req_sel != 15)
            throw std::runtime_error("partial Wishbone store is outside this spike");
          ...
        } else if (in_dma(req_addr)) {
          // 1464 已有自己的 req_sel != 15 守卫，保持不变
          ...
        } else if (in_ram(req_addr & ~3u)) {
          const uint32_t ram_addr = req_addr & ~3u;
          if (req_write) {
            memory.write(ram_addr, req_wdata, req_sel);
            ...
            if (ram_addr == kCommand && req_sel == 15 && req_wdata == 0)
              ack_pending = true;
            if (ram_addr == kEcho && req_sel == 15) {
              observation.echo_stored = true;
              observation.echo_value = req_wdata;
            }
            if (ram_addr >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = req_addr;  // 真实字节地址，保留证据
              observation.write_value = req_wdata;
              observation.write_be = req_sel;
            }
          } else {
            ...
            dat.value = memory.read(ram_addr);
            ...
          }
```

- `Memory::write`（`scripts/inprocess_memory.h:27-30`）已经按 `be` 逐字节写；`Memory::offset`（13-18）要求 4 字节对齐，所以 `ram_addr` 必须 `& ~3u`。
- `in_ram` 的边界是 `address - base <= size - 4`（531-533）。对字节地址做 `& ~3u` 后再判断，避免数据窗口最后 3 个字节被误拒。
- `kCommand`/`kEcho` 的比较要用对齐后的 `ram_addr`；`observation.write_address` 保留 CPU 给出的原始地址（字节地址）作为证据。
- DMA 分支（1462-1464）保持 full-word 守卫：partial DMA control write 仍拒绝。

### 4.2 OBI

OBI 数据口的 `da` 是**字节地址**（`inprocess_obi_apb_f1f4_spike.cpp:1149`；本地 harness 的同一约定见 `src/myfuzz/local_harness/cpu_session.py:311-315`：“OBI CPU ports expose byte addresses ... address backing memory ... by the beat”）。因此 1557-1560 必须先把地址对齐：

```cpp
        } else if (in_ram(da & ~3u)) {
          if (dbe > 15) throw std::runtime_error("invalid RAM byte enable");
          const uint32_t ram_addr = da & ~3u;
          if (dw) {
            memory.write(ram_addr, dv, dbe);
            ++observation.d_writes;
            if (ram_addr == kCommand && dbe == 15 && dv == 0)
              ack_pending = true;
            if (ram_addr == kEcho && dbe == 15) {
              observation.echo_stored = true;
              observation.echo_value = dv;
            }
            if (da >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = da;
              observation.write_value = dv;
              observation.write_be = dbe;
            }
          } else {
            ++observation.d_reads;
            if (da >= kDataBase && !in_ip(da)) {
              observation.read_accepted = true;
              observation.read_address = da;
              observation.read_from_ip = false;
              observation.read_value = memory.read(ram_addr);
            }
          }
          dat.value = dw ? 0 : memory.read(ram_addr);  // 原 1582 行也要改
          dat.valid = true;
```

- `dbe` 是相对 4 字节 beat 的 lane 掩码；`SB` 在 offset 1 时 `dbe == 0b0010`，`SH` 在 offset 2 时 `dbe == 0b1100`。`Memory::write(ram_addr, dv, dbe)` 直接可用。
- 载入不需要在 host 侧提取 lane：host 返回对齐后的整字，CPU 的 load 单元自己选字节并做符号/零扩展。
- `in_ip`/`in_dma` 的 `dbe != 15` 守卫（1541-1551）**不要**删：partial MMIO/控制访问仍然拒绝；它们只挡目标/控制，不挡 RAM。
- RAM 分支只有 `dbe > 15` 检查（1558），这是合法性检查，不是 partial 拒绝，保留。
- `in_ram(da & ~3u)` 的边界理由同 §4.1。

### 4.3 `Memory` 与 `data_changed`

`Memory::write(address, value, be)`（`scripts/inprocess_memory.h:27-30`）已经支持任意 `be`；`window_hash`（571-581）逐字节哈希；`data_changed`（1722-1725）按字计数。**不要**改 `Memory` 或 `data_changed` 的粒度。

## 5. Strategy / entry / corpus

- 配置：`f1_subword: true` 必须与 `f1_program_words > 1` 同时出现（`run_inprocess_f1f6.py:2661-2664`）。建议的键名就是 **`f1_subword`**；C++ 宏名 `F1_ALLOW_SUBWORD`。
- 生成：`strategy.py:91-95` 在 `f1_subword` 时调用 `generate_subword_program`；宽度按 seed 循环，保证一批 seed 覆盖 LB/SB、LH/SH、LW/SW（`tests/fuzz/test_rv32_subword.py` 已覆盖 300 个 seed）。
- 变异：`strategy.py:103-107` 只在程序里已有内存字时调用 `mutate_subword_program`；它只改一个内存字，保留 base 和 rd/rs2，宽度必变。
- 入口 gate：`run_inprocess_f1f6.py:2436-2441` 已把 `config.get('f1_subword', False)` 传给 `validate_record`；`2460-2464` 已传给 `FuzzStrategy`。补丁不需要再改这两处。
- 种子/corpus 兼容性：`corpus.json` 只存 `fields`（字），不存子字标记。用 `f1_subword=True` 重放旧 corpus 的 LW/SW 条目仍然合法；用 `f1_subword=False` 重放含子字的条目会被 legacy gate 拒绝，`FuzzStrategy._attempt`（`strategy.py:134-152`）会捕获 `ValueError` 并重试，不会把非法输入交给 host。因此 corpus 不需要新元数据；只需要保证同一次运行的 config 与 host 编译宏一致。
- 运行文档：`run_inprocess_f1f6.py:2962-2974` 的 `f1_program.limit` 文案在 `f1_subword` 为真时应改为“LB/LH/LW/LBU/LHU/SB/SH/SW ...”，并把 `subword=True` 写进 `f1_program` 字典，避免证据文档与实际能力不符。`input_channel` 文案可选更新。
- `docs/inprocess-fuzz-loop.md` 第 4 节仍写“多字模式下的 LW/SW”；该文件不在本补丁所有权内，父 agent 可另开文档改动，或在运行报告里注明本补丁扩展了它。

## 6. 真实 CPU 验证（补丁应用后由父 agent 执行）

### 6.1 纯 Python 回归（无 RTL）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. python3 -m pytest \
  tests/fuzz/test_rv32_subword.py \
  tests/fuzz/test_entry_f1_subword.py \
  tests/fuzz/test_entry_f1_program.py -q
```

当前期望：`204 passed`（120 + 54 + 30）。`test_rv32_subword.py` 包含生成/变异/门/reference/策略/合成 byte-RAM 端到端；`test_entry_f1_subword.py` 是入口 gate 的契约测试，不 import 入口。

### 6.2 用现有入口验证 Python opt-in（不跑 host）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. python3 - <<'PY'
import json
from pathlib import Path
from myfuzz.fuzz.rv32_subword import generate_subword_program
from myfuzz.riscv.profile import RiscvProfile
from myfuzz.isa.constraints import IsaContract
from scripts.run_inprocess_f1f6 import (declared_windows, parse_record,
                                       validate_record, PROGRAM_DATA_WORDS)
config = json.loads(Path('configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
windows = declared_windows(config, 16)
isa = IsaContract(32, ('I', 'M'), instruction_alignment=4)
arity = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
profile = RiscvProfile(32, frozenset(('I', 'M')), 4, 32, 0)
for seed in range(8):
    words = generate_subword_program(profile, seed=seed, max_words=8,
                                     window_size=PROGRAM_DATA_WORDS * 4)
    text = 'F1:' + ':'.join(f'{w:08x}' for w in words)
    record = parse_record(text, windows=windows, arity=arity, f1_words=8)
    validate_record(record, isa=isa, windows=windows, f1_words=8, f1_subword=True)
print('python opt-in path accepted 8 generated subword programs')
PY
```

### 6.3 固定记录（真实 CPU，建议 11 字混合程序）

用一个**新的临时 config**（不要改既有 config）打开 opt-in。选 `f1_program_words` 至少 11 的现有配置，例如 16 字：

```bash
cd /home/qinkejiu/myfuzz
cp configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-16w-fuzz.json /tmp/f1-subword-16w.json
python3 - <<'PY'
import json
path = '/tmp/f1-subword-16w.json'
data = json.load(open(path))
data['f1_subword'] = True
json.dump(data, open(path, 'w'), indent=2)
PY

PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config /tmp/f1-subword-16w.json \
  --cache runs/_subword-cache-20261101 \
  --output runs/subword-f1-fixed-20261101 \
  --records 'F1:112230b7:34408093:001900a3:00191123:00192223:00190103:00594183:00291203:00695283:00492303:00191323' \
  --max-ticks 20000
```

程序（11 字）：

| # | 汇编 | 作用 |
|---|---|---|
| 0 | `LUI x1, 0x11223` | x1 = 0x11223000 |
| 1 | `ADDI x1, x1, 0x344` | x1 = 0x11223344 |
| 2 | `SB x1, 1(x18)` | 字节写 lane 1 |
| 3 | `SH x1, 2(x18)` | 半字写 lane 2-3 |
| 4 | `SW x1, 4(x18)` | 全字写第二字 |
| 5 | `LB x2, 1(x18)` | 符号扩展字节 |
| 6 | `LBU x3, 5(x18)` | 零扩展字节 |
| 7 | `LH x4, 2(x18)` | 符号扩展半字 |
| 8 | `LHU x5, 6(x18)` | 零扩展半字 |
| 9 | `LW x6, 4(x18)` | 全字 |
| 10 | `SH x1, 6(x18)` | 最后一次写，`be = 0b1100` |

初始数据窗口是 `DATA_WORDS = (0xDEADBEEF, 0x11111111, 0, ...)`（`run_inprocess_f1f6.py:102`），16 字窗口。最终：

- word0 = `0x334444EF`，word1 = `0x33443344`，其余为 0；
- 字节序列：`EF 44 44 33 44 33 44 33 00 ...`；
- `data_hash_before = 0xf870121f`，`data_hash_after = 0x82c26777`；
- `data_changed = 2`（word0、word1 各变一次；word1 的 `SW` 和最后 `SH` 落在同一字，只计 1）。

期望的 `case` 行关键字段（地址/PC 取决于 layout，不要硬编码 `data_base`/`slot`）。前提：该 CPU 模型暴露 RVFI writeback（`HAVE_RVFI_WRITEBACK=1`，生成的 `spike_config.h` 已声明）；否则 `prog_rd_mask`/`prog_last_wdata`/`prog_writebacks` 会保持 0，不能作为证据，此时用 `prog_retires`、`prog_insns_match`、`data_changed`、`data_hash_after` 判断：

```
case 1 observations_passed flow F1 record F1:... ticks ... 
  prog_words 11 prog_retires 11 prog_pc_ordered 1 prog_insns_match 1
  prog_writebacks 7 prog_rd_mask 0000007e prog_last_rd 6
  prog_last_wdata 11223344 prog_last_pc <slot+40> prog_last_insn 00191323
  prog_traps 0 data_hash_before f870121f data_hash_after 82c26777 data_changed 2
```

- `prog_rd_mask 0000007e`：x1..x6 都写过；x1 写两次仍只占一位。
- `prog_writebacks 7`：LUI、ADDI、LB、LBU、LH、LHU、LW 共 7 次非 x0 写回。
- `prog_last_wdata 11223344`：最后一条**写回**是 LW x6（第 9 字）；第 10 字是 store，不产生写回。
- `prog_last_insn 00191323`：最后一条程序字是 `SH x1, 6(x18)`。
- 若加了 §3.3 的可选证据行，还应看到 `data_write_accepted 1`、`data_write_addr <data_base+6>`、`data_write_be 12`（0b1100）。
- `data_hash_after` 是字节级 FNV；它等于 `0x82c26777` 就证明 lane 1/2-3/6-7 的写和 word1 的全字写都按字节生效，而不只是“字变了”。

**反例**（同一记录，`f1_subword` 未开）：Python 在 `validate_record` 阶段就拒绝：

```
F1 program memory word 2 is not LW or SW
```

（`run_inprocess_f1f6.py:850-852` 的 legacy 消息）。C++ host 在 `F1_ALLOW_SUBWORD=0` 时同样在 `make_record` 拒绝（§3.2 的 `#else` 分支）。

### 6.4 Fuzz 批次（真实 CPU）

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src:. python3 scripts/run_inprocess_f1f6.py \
  --config /tmp/f1-subword-16w.json \
  --cache runs/_subword-cache-20261101 \
  --output runs/subword-f1-fuzz-20261101 \
  --fuzz --cases 64 --seed 20261101
```

检查：

- `prefix.txt` 中至少有一条 F1 记录含 `funct3` 不为 2 的内存字（`LB/LH/LBU/LHU/SB/SH`）；
- `observations.jsonl` / `summary.json` 的 F1 行里，至少一条 `data_changed >= 1`（程序含 store），至少一条 `prog_rd_mask != 0`（程序含 load）；
- `prog_traps == 0`、`prog_insns_match == 1`、`prog_pc_ordered == 1`；
- 若某条程序只有 ALU 字或没有内存字，`data_changed`/`prog_rd_mask` 为 0 是正常的，按整批统计，不要按单条硬断言；
- 若该 CPU 模型没有 RVFI writeback（`HAVE_RVFI_WRITEBACK=0`），`prog_rd_mask`/`prog_last_wdata`/`prog_writebacks` 不可用；以 `data_changed`/`data_hash_after` 和 `prog_retires` 为准；
- `corpus.json` 不需要新字段；同一 config/宏下重放 `--corpus` 应继续通过。

### 6.5 固定记录里的 RAM 字节

host 目前不在 F1 `case` 行打印 16 字 RAM，只打印 `data_hash_after`。两种验证方式：

1. **不改进 host**（最小补丁）：用 §6.3 的期望 `data_hash_after` 验证；`0x82c26777` 是逐字节 FNV，等价于断言上述 8 个字节 + 56 个零字节。
2. **加可选证据行**（§3.3）：直接看 `data_write_addr`/`data_write_be`，并可在 `case` 行后追加 16 字 RAM（例如 `for i: std::cout << " data_word " << hex32(memory.read(kDataBase + 4*i))`）。如果父 agent 选择这一项，建议只加在 `F1` 分支，避免改变其他流的字段集合。

## 7. 需要父 agent 决策的规则

1. **字节偏移与 host 地址语义（必须决定）**：程序里的 `offset` 是 `x18` 的字节偏移（0..63），CPU 计算 `x18+offset`。OBI 数据口把这个字节地址直接给 host，host 的 `Memory` 是字寻址且要求 4 字节对齐，所以 **RAM 访问前必须 `address & ~3u`**；`dbe`/`sel` 保持 lane 语义。Wishbone 当前核的 `req_addr` 看起来是字地址，但仍建议同样 `& ~3u`，这样两种总线语义一致。不要在 Python gate 或程序生成里把 offset 改成“字内 lane + 字偏移”的双字段；那会改变 reference 模型和 host 的契约。
2. **Wishbone partial store（必须决定）**：只在 `in_ram` 分支放行 `req_sel != 15`；`in_ip`（APB 目标寄存器）和 `in_dma`（DMA 控制）保持 full-word 守卫。不要为了子字把 MMIO 也放开：F1 程序只允许 x18 数据窗口，MMIO partial 写没有声明。
3. **`data_changed` 粒度（建议保持）**：保持字粒度，不要改成字节粒度；字节级证据用 `data_hash_after`。否则既有 case 字段语义和父 agent 的比对脚本都会变。
4. **`write_be` 证据（建议加）**：F1 `case` 行目前不打印 `write_be`；若需要“真实字节使能”的直接证据，按 §3.3 加 3 个字段。若不想改 host 输出，`data_hash_after` 已经能证明 lane 生效，但证据链不如 `write_be` 直接。
5. **ISA gate（必须决定）**：`validate_instruction_bytes` 目前拒绝 LB/LH/LBU/LHU/SH（只接受 LW/SW/SB）。子字分支**不要**调用它；非内存字继续由 `validate_program_words` 检查。如果父 agent 想扩 `validate_instruction_bytes` 本身，那是另一个入口侧改动，不属于本最小补丁。
6. **RV32E / register_count（低优先级）**：模块支持 16 寄存器 profile 并会拒绝 x18；入口 `validate_record` 硬编码 `RiscvProfile(..., 32, 0)`。当前 F1 程序模式要求 `I`，E 不会到达；若将来开放 E，传真实 `register_count` 或直接拒绝子字。
7. **宏名/配置名（建议保持）**：配置 `f1_subword`，C++ `F1_ALLOW_SUBWORD`；两者已经在树里，不要改名，避免与既有测试/报告不一致。
8. **corpus 元数据（建议不加）**：corpus 只存字；同一次运行的 config 和 host 宏必须一致。子字 corpus 在 `f1_subword=False` 下会被 gate 拒绝并由策略重试，不会误送 host。

## 8. 风险与回滚

- 风险最高的不是 `make_record`，而是 **RAM 地址未对齐**：OBI 的 `da` 是字节地址，直接 `memory.read(da)`/`memory.write(da, ...)` 会在 `Memory::offset` 抛 `RAM access out of bounds or unaligned`。按 §4.2 先 `& ~3u` 即可。
- 第二个风险是 **Wishbone 全局 partial 守卫**：只删 1452-1453 而不把它移进 `in_ip`，会让 partial MMIO 写进入 APB 模型；按 §4.1 移动，不要直接删除。
- 回滚：把 `f1_subword` 设回 false（或删掉临时 config 的该键），C++ 重新生成 `spike_config.h` 后 `F1_ALLOW_SUBWORD` 为 0，host 回到 legacy LW/SW gate；Python 侧不需要回滚（模块是 opt-in，不改变默认路径）。
- 本补丁不改变 F2–F6 的任何字段或行为；`data_changed`/`data_hash_*` 的语义对 F1 之外不变。
