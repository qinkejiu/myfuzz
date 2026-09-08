# 真实 Ibex 契约转导与 RFuzz 示例

本示例把真实 Ibex 的 OBI 接口连接到由 ISA 和总线契约生成的
`contract_transducer`。每个尚未初始化、可生成指令的地址，其首次指令内容都来自
RFuzz 周期记录；数据读取的首次内容、握手时机、中断和 debug request 也由记录驱动。

入口是 `run_example.py`，输入是 `input/ibex-scratch.json`，生产实现位于
`src/myfuzz/`。系统概览见[《系统能力与工作原理》](系统能力与工作原理.md)。

## 1. 自动组合与执行结构

组合器验证固定源码 revision、源码闭包和 elaborated 物理端口，然后按 endpoint
的协议、功能、方向和宽度选择适配器。Ibex 名称用于标识样例，接线选择依赖接口事实。

```text
真实 Ibex instruction/data OBI
  → OBI adapter
  → 请求仲裁与 processor-memory-beat 后端
  → contract_transducer：协议状态 + 指令修复 + main 共享字节内存
         ↑
RFuzz 周期记录：selector、payload、response_choice、response_data

RFuzz 周期记录：外部输入
  → 已验证的物理端口
  → IRQ / nonmaskable_interrupt / debug request
```

输入中的 `personality` 保留组件来源和组合元数据。此 constrained 执行路径禁用固定
target，由转导器处理内存请求，因此本例不能证明 scratch、GPIO 或 timer 外设的
实际功能执行。旧固定启动内存路径已从本示例移除。

核心调用链是 `load_example → build_candidate → plan_generic_composition →
compile_contract_transducer → build_simulator → RtlSimulator`。协议归一化仍使用
`processor-memory-beat@1`，最终执行的处理器是 Verilator 编译的真实 RTL。

## 2. 输入配置与固定测试头

当前配置的关键值如下；完整配置以 [ibex-scratch.json](input/ibex-scratch.json) 为准。

```json
{
  "input_mode": "contract_transducer",
  "isa_contract": {
    "xlen": 32,
    "extensions": ["I", "M", "C"],
    "privilege_modes": ["M"],
    "instruction_alignment": 2
  },
  "protocol": ["obi", "1"],
  "memory_domains": {
    "instruction_memory_master": "main",
    "data_memory_master": "main"
  },
  "test_header": {
    "reset_cycles": 2,
    "execution_cycles": 200,
    "boot_address": 128,
    "hart_id": 0,
    "illegal_instruction": false
  },
  "probe_cycles": 80
}
```

编译后的测试头采用 `cycle_test.v1`，另包含生成的 `layout_hash` 和
`contract_hash`。它固定复位周期、执行上限、boot address、hart ID 和非法指令模式，
不占 RFuzz 周期输入位。`execution_cycles=200` 是每个测试的执行上限，不要求每份
输入都具有 200 个完整记录。

转导器参数为 `max_wait_cycles=16`、`memory_capacity_entries=256`、
`allow_error=false`。容量按不同 domain/对齐 beat 计数。

`control_defaults` 声明 fetch enable、scan reset、完整性和其他固定控制；boot/hart
绑定必须与测试头一致。时钟和复位由仿真调度。六类可变外部字段为：

| 配置字段 | 物理端口 | 宽度 |
| --- | --- | --- |
| `processor.interrupts:software_interrupt` | `irq_software_i` | 1 |
| `processor.interrupts:timer_interrupt` | `irq_timer_i` | 1 |
| `processor.interrupts:external_interrupt` | `irq_external_i` | 1 |
| `processor.interrupts:fast_interrupt` | `irq_fast_i` | 15 |
| `processor.execution_controls:nonmaskable_interrupt` | `irq_nm_i` | 1 |
| `processor.debug:request` | `debug_req_i` | 1 |

`randomizable_fields` 声明这些外部字段；指令和响应字段由契约编译器添加。
外部字段须具有已验证的物理绑定，并满足 runtime control policy。

## 3. 输入约束与精确位布局

`CycleInputLayout.build()` 按字段声明顺序从 bit 0 连续分配区间。
`compile_contract_transducer()` 先分配指令 selector，再分配 payload、压缩标记、
响应选择和数据，最后按完整字段名排序分配外部输入。

本例 selector 宽度为 8。启用 C 扩展且指令对齐为 2 字节时，32 位 beat 预留两个
selector；即使该周期选择 32 位指令，第二个 selector 的位仍在布局中。

| 字段 | raw bits | 宽度 |
| --- | --- | --- |
| `instruction_selector` | `[7:0]` | 8 |
| `instruction_selector_1` | `[15:8]` | 8 |
| `instruction_payload` | `[47:16]` | 32 |
| `instruction_compressed` | `[48]` | 1 |
| `response_choice` | `[51:49]` | 3 |
| `response_data` | `[83:52]` | 32 |
| `external.processor.debug:request` | `[84]` | 1 |
| `external.processor.execution_controls:nonmaskable_interrupt` | `[85]` | 1 |
| `external.processor.interrupts:external_interrupt` | `[86]` | 1 |
| `external.processor.interrupts:fast_interrupt` | `[101:87]` | 15 |
| `external.processor.interrupts:software_interrupt` | `[102]` | 1 |
| `external.processor.interrupts:timer_interrupt` | `[103]` | 1 |

总宽度是 `8 + 8 + 32 + 1 + 3 + 32 + 20 = 104` 位。字段提取公式为：

```text
value = (raw_cycle >> raw_lo) & ((1 << width) - 1)
```

RFuzz transport 使用 64 位倍数的记录长度：
`byte_count = ceil(raw_width / 64) × 8 = 16` 字节。大端字节序中，104 位 payload
位于记录高位，末尾 24 位是 padding；编码时置零，输入时忽略。每个完整记录代表一个
执行周期。底层 decode API 可报告 `truncated_bytes`；本例 live/语料接口只接受完整记录，
每测试记录数不得超过测试头上限。

这里的 `CycleIdentityProjector` 保留周期 entropy，状态化约束在生成的转导器 RTL
中执行。布局、契约和测试头都有独立身份，运行产物是核对位宽和哈希的权威来源。

### 指令 selector 与最小修复

在本例 `illegal_instruction=false` 下，32 位共有 50 个模板，16 位共有 26 个模板。
模板数来自当前 ISA 契约，选择公式为：

```text
template_index = floor(selector × template_count / 256)
word = ((payload & ~fixed_mask) | fixed_value) & width_mask
```

模板固定 opcode、funct 等必须满足的编码位，保留可自由变化的寄存器和立即数位。
压缩指令还按需修复非零寄存器、非零立即数等保留编码限制。
`C.ANDI` 的 6 位立即数均自由，包括 bit 12；合法 `0x9805`、`0x9855` 在 RV32/RV64
下都原样保留。当前公开契约只实现 I/M/C，六种 Zicsr CSR 操作不属于 I 模板。

| 输入 | 选择与修复结果 |
| --- | --- |
| 32 位 selector=0，payload=`0xffffffff` | ADDI，mask=`0x0000707f`，结果 `0xffff8f93`，即 `addi x31,x31,-1` |
| 32 位 selector=220，payload=`0xffffffff` | MUL，结果 `0x03ff8fb3` |
| 16 位 selector=0，payload=0 | C.ADDI4SPN，补非零立即数位，结果 `0x0020` |
| 16 位 selector=207，payload=0 | C.MV，补非零 rd 和 rs2，结果 `0x8086` |

`instruction_compressed=0` 时用 selector0 修复完整 32 位 payload；为 1 时，两个
selector 分别修复 payload 的低、高 16 位，再拼接成一个 32 位 beat。半字请求地址，
或同一 boot beat 内 `boot_address % 4 == 2` 的入口，会强制使用压缩指令槽。

首次生成指令使用的是**响应完成周期**的 selector/payload，不是接受请求周期的值。
这些规则保证已实现 ISA 契约范围内的编码合法性；执行是否发生 trap 还取决于寄存器、
地址、CSR 和当前处理器状态。

### OBI 握手 repair

`response_choice` 的 bit 0、1、2 分别请求接受请求、完成响应、注入响应错误，
对应全局 raw bit 49、50、51。这些位经过 pending 状态约束：

- 没有请求时不 grant，没有已接受请求时不产生 response。
- grant 与同一请求的 response 分开；响应总是绑定保存的请求。
- 在响应周期不接受替代请求，当前后端保持单 outstanding、按序完成。
- 连续 request 的第 16 个等待周期强制接受，随后 pending 的第 16 个等待周期
  强制响应；计数针对转导器边界，外层 adapter/backend 还会增加流水延迟。
- 本例关闭随机 error 注入；容量和内存 provenance 错误仍会返回。

例如仅为解释计数，令等待上限为 3、choice 始终为 0：周期 0、1 等待，周期 2 grant，
周期 3、4 等待，周期 5 response。OBI adapter 将 backend completion 注册成
`rvalid/rdata/error` 后交给 CPU。

### 重复地址、共享域与 test_begin

`memory_domains` 把 instruction/data 都绑定到 `main`。32 位 beat 的键为
`(domain, address & ~3)`，byte enable 选择小端字节 lane，地址低位不会把 beat
再次偏移。

首次指令读取生成的字节会保存；同址重复读取忽略新的 selector/payload，data read
也能看到相同内容。首次 data read 使用当个响应周期的 `response_data` 初始化字节。

例如首次在 `0x80` 生成 `0xffff8f93`，之后改变 selector 仍读取相同值；CPU 使用
`write_data=0x11223344, byte_enable=0b0011` 写该地址后，读取结果为 `0xffff3344`。
CPU 写入的指令字节按原样返回，不会再次做指令合法化。

如果一个 beat 先由随机 data read 初始化，随后被当作指令读取，会返回
`provenance_error`。零 byte enable 写入不分配内存，也不改变 provenance。
容量耗尽返回 `capacity_error`，不会驱逐已保存的地址。

每个测试的 `test_begin` 清空字节、容量记录、provenance 和协议状态，并锁存测试头；
测试内 DUT reset 只清协议 pending/等待状态，保留内存。相同测试头和周期记录因此具有
可重放的初始化过程。

## 4. 前置依赖与命令

从仓库根目录执行。需要 Python 3、Verilator、C++ 编译器、配置中固定的 Ibex
源码以及已构建的官方 RFuzz 客户端。

```bash
bash examples/real_ibex_rfuzz/commands.sh check
```

脚本设置 `PYTHONDONTWRITEBYTECODE=1`、`PYTHONPATH=src:.`、`JOBS=1`，通过
`nice -n15` 限制构建优先级。客户端路径默认是
`runs/rfuzz_client_native_build/target/debug/kfuzz`；直接调用 CLI 时可用 `--client` 指定。
计划中的 `runs/rfuzz_client_native_build/release/rfuzz-client` 在当前环境不存在，
本例改用已确认可执行且动态库依赖齐全的 native debug `kfuzz`。

### 自动组合与真实 CPU probe

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 examples/real_ibex_rfuzz/run_example.py compose \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --output runs/examples/contract-rfuzz-new-compose
```

组合命令编译真实 RTL，并两次执行 80 周期的全零 RFuzz 格式记录。由这些记录导出的
selector=0、payload=0 会生成 ADDI 编码 `0x00000013`。这是确定性 probe；官方 live
阶段会变异输入，不能把全零 probe 当成变异测试结果。

probe 验收检查 instruction request/response、至少两个不同地址的首次指令初始化、
零转导器/协议错误，以及重复执行的反馈和执行结果一致。主要产物是
`build/execution.json`、`build/interface.json`、`build/sim/` 和 `summary.json`。

### 5 秒官方 RFuzz 测试

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 examples/real_ibex_rfuzz/run_example.py test \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --client runs/rfuzz_client_native_build/target/debug/kfuzz \
  --output runs/examples/contract-rfuzz-new-5s \
  --seconds 5
```

该命令重新组合和编译，通过 SysV shared memory 执行官方客户端输入，保存有反馈增益的
语料，并用本次 artifact 重放语料。`--seconds 5` 表示第 5 秒请求客户端停止；上游
客户端会先完成当前批次，另有最多 60 秒排空窗口。`live/report.json` 分别记录
请求时长、发出中断时间、排空时间和实际总时长，不能把它描述成严格 5 秒墙钟上限。
检查结果：

```bash
PYTHONPATH=src:. python3 examples/real_ibex_rfuzz/run_example.py inspect \
  --output runs/examples/contract-rfuzz-new-5s
python3 -m json.tool runs/examples/contract-rfuzz-new-5s/live/corpus_manifest.json
```

`completed_feedback_exchanges` 只统计完整提交并收到对应回复的共享内存交换。
测试数、receipt 数、语料数含义不同，不能互相替代。结果还需核对客户端退出码、
重放条数、执行统计以及 `remaining_segments`。

### 独立重建与语料重放

合法的指令编码仍可能因地址或处理器状态触发硬件 trap；显式 illegal 模式还可测试非法指令。
上游 RTL 的普通 stdout 诊断
会有界保存到 `simulator_diagnostics`（总行数及最多 32 条样本）；它们不属于覆盖反馈。
仿真接口只接受明确的完整 `RFUZZ_COUNTERS` 帧，协议错误、超限输出和异常退出仍失败。
Python 与生成仿真程序使用内部协议 `RFUZZ_READY 2`：每次请求附带单调 64 位编号，
按固定 16 位小写十六进制编码（例如 `0000000000000001`），
响应必须回显同一个编号，延迟到下一请求之后的旧帧也会被拒绝。编号不进入 DUT 输入。
旧版仿真二进制需要重新构建；官方 RFuzz 客户端的共享内存接口保持不变。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 examples/real_ibex_rfuzz/run_example.py replay \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --output runs/examples/contract-rfuzz-new-5s \
  --build-output runs/examples/contract-rfuzz-new-replay
```

这里 `--output` 指向保留的测试目录，`--build-output` 必须是新目录。命令独立重建
simulator，再核对保留的 corpus manifest、执行身份和每条语料的 coverage。语料身份
包含 raw、layout、contract/transducer、implementation、header、固定控制、simulator input 和 binary
的哈希。独立重建允许 binary hash 随构建路径改变，但必须保持 composition、输入契约、
测试头、固定控制与输入内容一致，且每条覆盖反馈相同；每份新二进制的身份另行记录。
实际重放计数器的 SHA-256 必须等于原 manifest 的 `coverage_sha256`；读取到的保留
trace 全部字节（含传输 padding）的哈希必须等于原 `trace_sha256`，缺失或篡改都会失败。

`implementation_hash` 从实际生成 RTL 去除注释、归一化空白后的 token 文本计算，
包含已编译的 ISA 选择/修复、协议等待和内存逻辑。它不含输出路径、自引用哈希注释或
native binary 字节，并参与 `contract_hash`；同配置独立构建保持一致，逻辑变化必须改变。
该身份显式保存在契约、artifact provenance、execution proof、manifest 和 replay 中。
低层 replay 也读取语料旁的 `corpus_manifest.json`，按完整稳定身份及 raw/trace/coverage
逐条核对。缺少新实现身份的旧 constrained 语料不能作为当前实现的兼容性证据。
entry 若也带 inline 身份，其 binary/replay key 必须匹配原 manifest；独立构建不要求
这些原构建字段等于新二进制身份，但仍必须逐项匹配所有稳定语义身份。

命令脚本提供对应快捷入口：

```bash
bash examples/real_ibex_rfuzz/commands.sh compose runs/examples/contract-rfuzz-new-compose
bash examples/real_ibex_rfuzz/commands.sh test runs/examples/contract-rfuzz-new-5s 5
bash examples/real_ibex_rfuzz/commands.sh inspect runs/examples/contract-rfuzz-new-5s
bash examples/real_ibex_rfuzz/commands.sh replay \
  runs/examples/contract-rfuzz-new-5s runs/examples/contract-rfuzz-new-replay
```

以上 `new-*` 是供重新运行使用的新目录示例；如果已存在，须改用另一个新目录。

## 5. 当前测试结果

最终保留运行是 `runs/examples/contract-rfuzz-final-5s`，对应最终复审修复提交 `6d4ef8a`。
兼容后续修复 `dba09b1` 处理 inline/manifest 的重复构建身份校验和非 UTF-8 源码闭包
附件，不改变本例的指令规则、生成 RTL 或契约身份。
以下数值来自该目录的 `summary.json`、`live/report.json`
及语料重放产物；重新运行会产生新的实测结果。

| 实测项目 | 结果 |
| --- | --- |
| RTL 测试 / 完成 feedback receipt | 124153 / 98557 |
| 保存语料 / 同构建重放 | 23 / 23 |
| instruction request / response / 首次初始化 | 249246 / 248306 / 248306 |
| protocol / transducer / 总 errors | 0 / 0 / 0 |
| 客户端退出码 / 遗留共享内存段 | 0 / 0 |
| 请求停止时长 / 实际发出中断 | 5 秒 / 5.000071473001299 秒 |
| 排空时长 / 实际总时长 | 23.32143781099876 秒 / 28.32273579500179 秒 |
| 采样进程组 RSS 峰值 / 普通 RTL 诊断 | 108556288 bytes / 0 行 |

本次 23 条语料的独立重建证据是
`runs/examples/contract-rfuzz-final-replay/rebuild_replay.json`，逐条核对原输入、trace、
coverage 和执行身份。独立 compose 证据在 `runs/examples/contract-rfuzz-final-compose/`。
旧 `contract-rfuzz-review-5s` 和 `contract-rfuzz-5s` 的 23 条语料仍保留为历史证据，
其旧契约缺少实现身份且含错误 ISA 模板，不能重归属到当前实现；此前的旧语料兼容性
结论仅适用于修复前构建，不计入本次验收。

[expected/bounded-result.json](expected/bounded-result.json) 保存完整 composition、
layout、constraint/transducer、implementation、header、二进制、配置文件和证据文件 SHA-256，并列出
`entry_0000.json` 的代表性 raw/input、coverage、trace 与 replay key；其他条目的
完整身份在其绑定的 corpus manifest 和 replay 文件中。`replay_key` 包含 binary hash，
因此独立构建的 key 会改变；原始输入和覆盖反馈仍须相同。证据文件哈希按磁盘全部
字节计算，不能把重排 JSON 后的文件直接视作同一文件。

只读查看这次保留结果：

```bash
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py inspect \
  --output runs/examples/contract-rfuzz-final-5s
python3 -m json.tool examples/real_ibex_rfuzz/expected/bounded-result.json
```

`runs/` 是本地忽略的运行产物，不随 Git 提交分发；在另一机器上需按第 4 节重新构建、
测试和重放，或先恢复完整证据目录。已有输出目录不能覆盖。全项目接续事项见
[《项目目标与后续任务交接》](../../项目目标与后续任务交接.md)。

当前反馈类型为 `sampled-dut-signal-bit-events-u8-saturating`：记录所选真实 RTL
信号位和 backend 事件的采样计数，不能解读为源码行覆盖率或分支覆盖率。只有带来新
反馈的输入才会保留，因此执行次数通常大于语料条数。

## 6. 回归与尚未完成的验收

运行示例测试：

```bash
bash examples/real_ibex_rfuzz/commands.sh focused-tests
```

具备 Verilator 和真实 Ibex 源码时，该测试集合包含真实 CPU 构建与执行测试。
全量项目回归可使用 `commands.sh full-tests`，即 `python3 -m pytest tests -q`。
显式限定项目的 `tests/`，避免把第三方 checkout 中的生成脚本当成 pytest 测试收集。

5 秒有界测试是功能预检，不等同于正式的 3×300 秒验收。正式三组长测尚未执行；
BOOM 处理器验收仍暂缓。本例的 personality 元数据不构成 scratch/GPIO/timer 外设
验收证据，也不能把旧固定 target campaign 的结果计入新转导器路径。

常见失败应按产物定位：输出目录已存在时换用新目录；接口或客户端缺失时核对配置路径；
probe 的 instruction request/response 或初始化不足时检查执行证明；重放 identity/
coverage 不匹配时保留原始语料与构建证据。资源检查可用 `pgrep -af 'kfuzz|verilator|Vgenerated'`
和 `ipcs -m`，清理范围仅限本次运行拥有的资源。
