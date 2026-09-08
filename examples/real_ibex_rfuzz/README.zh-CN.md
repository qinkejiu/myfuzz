# 真实 Ibex 自动组合与 RFuzz 示例

这个目录给出一套可以从仓库根目录直接运行的真实处理器示例。它使用固定的 Ibex
源码、OBI 总线、启动内存和寄存器外设，展示从接口事实到自动组合、输入约束、
Verilator 仿真、官方 RFuzz 客户端、反馈语料和重放验证的完整链路。

从整体上看，这个系统是一个“面向真实 RTL 处理器的自动组合与反馈驱动测试平台”。
它解决的核心问题是：给定处理器 RTL、接口描述、ISA 约束和外设后，不再为每款 CPU
手工编写测试顶层，而是自动识别总线、选择协议适配器、分配地址、生成接线，再由
RFuzz 产生受约束输入并运行真实 RTL。

示例入口是 `run_example.py`，输入是 `input/ibex-scratch.json`。生产逻辑仍位于
`src/myfuzz/`；示例程序只是调用已有 API，不维护另一份组合器或测试器。

如果希望先理解整体架构和工作原理，请阅读独立文档：
[《系统能力与工作原理》](系统能力与工作原理.md)。

## 1. 当前能力与边界

| 能力 | 已实现 | 夹具执行 | 真实 CPU | 5 秒 RFuzz | 3×300 秒验收 |
| --- | --- | --- | --- | --- | --- |
| OBI → 通用 memory-beat | 是 | 是 | Ibex 已通过 | 已通过 | 未执行 |
| AXI4 → 通用 memory-beat | 是 | 是 | CVA6 已通过 | 本示例不使用 | 未执行 |
| TL-UL → 通用 memory-beat | 是 | 是 | 尚无真实 CPU 样本 | 本示例不使用 | 未执行 |
| 启动 RAM + scratch 外设 | 是 | 是 | Ibex 已通过 | 已通过 | 未执行 |
| GPIO/timer personality | 是 | 是 | 本检查点未跑真实 CPU | 未执行 | 未执行 |
| BOOM 处理器验收 | 否 | 否 | 按要求暂缓 | 否 | 否 |

这里的“5 秒已通过”指已有保留证据中的短时预检。它证明真实链路能够正确工作，
但 **5 秒短测不等同于正式的 3×300 秒验收**。

## 2. 整体工作流

```text
固定源码 + 接口描述 + 本示例输入
  ↓ 校验 source revision、源码闭包和 elaborated port facts
语义处理器边界
  ↓ 根据 protocol/capability 事实选择，不按 CPU 名称分支
OBI adapter + 启动 RAM + scratch 外设
  ↓ 自动分配地址并生成 CPU/adapter/arbiter/backend/peripheral 接线
组合 IR 与 SystemVerilog 顶层
  ↓ ISA 契约和字段约束投影
RFuzz 逻辑输入布局 → 物理 DUT 端口
  ↓ 单 worker Verilator 编译
真实 Ibex 取指、访存和外设写入
  ↓ 官方客户端通过 SysV shared memory 发送测试并读取反馈
覆盖反馈 → 新语料保存 → 逐条 RTL 重放与身份核对
```

自动组合阶段会完成以下决策：

1. 从 `interface` 指向的 source-backed 描述加载真实端口和端点。
2. 把 instruction/data memory endpoint 归一为处理器边界。
3. 从端点的 `obi@1` 协议事实选择 OBI adapter。
4. 为启动 RAM 和 scratch 外设分配互不重叠的地址区间。
5. 生成 CPU、adapter、仲裁器、通用 backend 和外设之间的唯一驱动连接。
6. 生成 Verilator 模型，并用最小 RISC-V 启动程序检查首取指、地址进展、
   completion、外设 pass 和协议错误。

任何接口宽度、方向、协议字段、源码身份、地址范围或连接唯一性不满足契约时，
组合会失败关闭，不会猜测端口含义或生成“尽量能编译”的接线。

### 系统分层

| 层次 | 主要职责 | 主要产物 |
| --- | --- | --- |
| 源码事实层 | 校验源码版本、源码闭包、模块、端口及 packed member 坐标 | source/elaboration evidence |
| 接口语义层 | 把物理端口标注为 clock、reset、interrupt、memory endpoint 等角色 | interface description |
| 处理器边界层 | 把不同 CPU 的 instruction/data 总线归一为统一边界 | processor boundary |
| 协议层 | 根据协议事实选择 OBI、AXI4 或 TL-UL adapter | processor-memory-beat 请求与响应 |
| 组合层 | 选择组件、分配地址、生成仲裁与唯一驱动接线 | composition IR、SystemVerilog top |
| 约束层 | 把可随机化逻辑字段映射为有约束的 RFuzz 输入布局 | layout、constraint hash |
| 执行层 | 编译 Verilator，启动真实 CPU，检查取指、进展和 completion | simulator artifact、execution proof |
| 反馈层 | 执行官方 RFuzz IPC，保存有反馈增益的输入 | report、feedback receipts、corpus |
| 重放层 | 对保存语料重新执行并核对完整身份 | corpus manifest、replay evidence |

生产路径不使用 `if cpu == "ibex"` 或 `if cpu == "cva6"` 选择接线。处理器名称可以
出现在示例配置和报告中，但 adapter 与组件选择只取决于 endpoint protocol、字段
role、方向、位宽、capability 和 compiler-proven physical port。

### 协议归一化

不同处理器可以暴露不同的总线接口，系统通过 adapter 把它们归一到统一后端：

```text
Ibex OBI  ─────► OBI adapter  ───┐
CVA6 AXI4 ─────► AXI4 adapter ───┼──► processor-memory-beat
TL-UL endpoint ► TL-UL adapter ──┘
```

统一的 `processor-memory-beat` 后端表示地址、读写类型、写数据、byte enable、返回
数据、error、request acceptance 和 response completion。当前模型限制为单
outstanding、按序完成和有界等待，使错误、超时与背压具有明确语义。

本示例自动生成的主要结构是：

```text
                  ┌──────────────┐
RFuzz inputs ────►│  Real Ibex   │
                  └──────┬───────┘
                         │ OBI
                  ┌──────▼───────┐
                  │ OBI Adapter  │
                  └──────┬───────┘
                         │ processor-memory-beat
                  ┌──────▼───────┐
                  │   Arbiter    │
                  └───┬──────┬───┘
                      │      │
              ┌───────▼─┐  ┌─▼────────────────┐
              │ Boot RAM│  │ Scratch Registers│
              └─────────┘  └──────────────────┘
```

### 自动组合的内部调用链

示例命令不会使用预先写好的 Ibex 专用顶层。`run_example.py compose` 最终进入
`src/myfuzz/integration/real_cpu_campaign.py::build_candidate()`，内部依次执行：

```text
load_example(input JSON)
  │
  ├─ 严格检查 schema、字段类型和仓库内相对路径
  └─ 生成 production config + peripheral personality
        │
        ▼
load_interface_description(interface JSON)
  │
  ├─ 加载 source pin、module、port、endpoint 和 field role
  └─ 把 randomizable_fields 标记到对应接口字段
        │
        ▼
ComponentCatalog(
  boot-memory profile,
  scratch-register profile
)
        │
        ▼
IsaContract(rv32imc)
        │
        ▼
GenericCompositionRequest(
  processor interface,
  requested component types,
  ISA contract,
  deterministic seed
)
        │
        ▼
plan_generic_composition(...)
  │
  ├─ build_processor_boundary
  ├─ resolve protocol adapter
  ├─ allocate address regions
  ├─ plan backend routing and arbitration
  ├─ build constrained RFuzz input layout
  └─ emit composition IR and generated RTL
        │
        ▼
build_minimal_boot_image(...)
        │
        ▼
build_simulator(..., simulator="verilator")
        │
        ▼
RtlSimulator.run_test(...)
  ├─ first fetch
  ├─ address progress
  ├─ completion
  ├─ peripheral pass
  └─ error/replay checks
```

其中几个关键边界是：

- `load_interface_description` 只接受通过来源和物理端口验证的接口事实。
- `GenericCompositionRequest` 只声明“需要什么能力”，不声明某个 CPU 名称对应哪个
  adapter。
- `plan_generic_composition` 根据协议和 capability 匹配组件，同时生成稳定哈希。
- `plan.ir["address_regions"]` 是启动 RAM 和外设地址的权威结果；boot image 使用这里
  分配的外设地址生成 pass 写入指令。
- `plan.layout.fields` 是可随机化输入的权威集合；只有出现在
  `randomizable_fields` 中的字段才进入 coverage/input projection。
- `build_simulator` 消费生成的组合计划和布局，渲染真实顶层并编译，而不是切换到
  CPU 的行为模型。

### 一个具体的 Ibex 组合示例

本目录的输入文件 `input/ibex-scratch.json` 核心内容如下：

```json
{
  "interface": "configs/cpus/ibex/official_core_interface_description.json",
  "isa": "rv32imc",
  "isa_contract": {
    "xlen": 32,
    "extensions": ["I", "M", "C"],
    "privilege_modes": ["M"],
    "instruction_alignment": 2
  },
  "protocol": ["obi", "1"],
  "memory_module": "riscv_boot_memory_32",
  "reset_vector": 128,
  "probe_cycles": 80,
  "composition_seed": 20260908,
  "randomizable_fields": [
    "processor.interrupts:software_interrupt",
    "processor.interrupts:timer_interrupt",
    "processor.interrupts:external_interrupt",
    "processor.interrupts:fast_interrupt"
  ],
  "personality": {
    "name": "scratch-registers",
    "module": "processor_register_target",
    "source": "src/myfuzz/integration/rtl/processor_register_target.sv",
    "mode": 0
  }
}
```

完整输入还包含 `control_defaults`，用于固定 boot address、hart ID、fetch enable、
scan reset、test enable 和完整性相关控制。

执行组合：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 examples/real_ibex_rfuzz/run_example.py compose \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --output runs/examples/real-ibex-compose
```

该输入经过事实匹配后得到如下选择，而不是由命令硬编码：

```text
processor boundary : Ibex instruction OBI + data OBI
selected adapter   : obi-to-processor-memory-beat
boot target        : riscv_boot_memory_32
peripheral target  : processor_register_target(MODE=0)
backend policy     : single outstanding, in order, bounded completion
randomized inputs  : four declared interrupt field groups
fixed controls     : boot/hart/fetch/reset/integrity controls
```

一次已验证的组合输出为：

```text
composition hash   sha256:d7c35e7dcdc0c5b92b90c39a5e411d5fe8791db9a702b9c8ff08ab2c9969c4e6
layout hash        256f048e229cfcc1c582a861ec14afe29929a2aceb6d77f6741e1769bc44e0f1
constraint hash    sha256:3ddb7186ce5ce304658fcd263ae30926bf979164116fe5938f6004c55f47c1f3
first fetch match  1
requests           11
completions        11
successful reads   10
progress events    10
peripheral pass    1
protocol errors    0
```

当替换为其他 CPU 时，接口描述必须完整提供同类语义事实。如果协议仍是当前支持的
OBI、AXI4 或 TL-UL，现有 adapter 可以直接参与组合；如果是未知协议、缺少字段 role、
缺少 packed-member elaboration 证据或需要特殊启动序列，系统会失败关闭，需要先补充
通用协议契约或 adapter，不能只改 CPU 名称。

## 3. 输入约束如何生效

输入文件的 `randomizable_fields` 只声明四组中断：软件中断、定时器中断、外部
中断和 fast interrupt。组合器先根据字段宽度与约束生成逻辑输入布局，运行时再由
projection 把 RFuzz 字节解包、规范化并映射到真实 DUT 端口。

```text
RFuzz raw bytes
  → transport.unpack
  → ISA/enum/range/mask constraint projection
  → logical field values
  → compiler-proven packed/scalar physical coordinates
  → real Ibex interrupt ports
```

时钟、复位、boot address、hart ID、fetch enable 等字段在 `control_defaults` 中固定，
不进入可变输入布局。原始 fuzzer 字节不能绕过约束直接覆盖这些控制端口。布局哈希、
约束哈希、物理控制哈希、仿真输入哈希和二进制哈希都会进入保存/重放证据，用来防止
配置或构建变化被误认为同一测试。

### RFuzz 输入约束的来源

约束不是在 RFuzz 客户端里临时修改输入，而是在 simulator 建立之前汇总成一个不可变
的 runtime constraint snapshot。它有四类来源：

1. **接口事实**：端点字段的 `width`、`signed`、方向、物理端口及 packed member
   坐标决定字段能否进入布局、占多少位以及最后驱动哪里。
2. **字段约束**：组件或接口可以为 `(owner, role)` 声明 `range`、`alignment`、
   `enum`、`mask`、`gated_by` 和 `randomizable`。
3. **字段依赖**：握手 gate、byte enable/data 宽度和需要上游求解的
   `dependency_group` 描述字段之间的关系。
4. **ISA 契约**：`IsaContract` 的 XLEN、扩展、特权级和指令对齐决定 instruction
   字段能否使用合法 RISC-V 编码投影。

```text
interface fields ─────────────┐
component_constraints ────────┼─► build_input_layout
IsaContract ──────────────────┘         │
                                       ▼
                              immutable InputLayout
                              ├─ raw bit ranges
                              ├─ field constraints
                              ├─ dependency metadata
                              ├─ physical bindings
                              └─ layout_hash
                                       │
control_defaults ─────────────┐         ▼
randomized_controls ──────────┼─► runtime boundary filtering
field.randomizable ───────────┘         │
                                       ▼
                               RuntimeProjector
                               ├─ constraint validation
                               ├─ constraint_hash
                               └─ project/project_ports
```

### 从接口字段生成 InputLayout

`build_input_layout()` 只收集 DUT 的 `input`/`inout` 字段，并使用
`owner + role` 作为字段身份。字段按 owner、optional、role 和物理端口稳定排序，然后
连续分配 RFuzz raw bit 区间：

```text
LayoutField
├── field_id       = owner:role
├── width
├── raw_lo/raw_hi  = 在 RFuzz 输入 word 中的位置
├── encoding       = bits / raw_instruction / riscv_imc
├── constraint
├── dependency_group
├── port
├── signed
└── member_path + port_raw_lo/raw_hi/port_width
```

最终布局必须完整使用 raw bits，不能出现 hole、overlap、重复字段或重复物理端口。
packed 输入还必须满足所有 member slice 无重叠地覆盖完整容器，并具有
`compiler_elaboration` 证据。

### 支持的字段约束

| 约束 | 语义 | 验证规则 |
| --- | --- | --- |
| `range: [lo, hi]` | 把任意 raw value 映射到闭区间 | 边界必须适合字段 signed/width |
| `alignment: N` | 输出必须按 N 对齐 | N 必须是正的 2 次幂且不超过字段空间 |
| `enum: [...]` | 输出只能从有限集合中选择 | 非空、无重复、适合位宽，并满足 range/mask/alignment |
| `mask: M` | 禁止 mask 外的位为 1 | mask 必须非负且适合字段位宽 |
| `gated_by: owner:valid` | gate 为 0 时本字段强制为 0 | 必须引用同 owner 的 1 位 valid 字段 |
| `randomizable: true` | 允许字段进入选定的 runtime fuzz 边界 | 必须是布尔值，并同时通过 control policy |
| `byte_enable_width: N` | byte enable 与同 owner data 建立宽度依赖 | data width 必须可整除 8，N 必须等于 data width/8 |

约束可以组合，但组合必须有非空交集。例如 `range + alignment + mask` 会在构建
projector 时预计算有限候选集合；候选空间超过 1,000,000 或交集为空会被拒绝。

### 字段依赖怎样处理

当前运行时支持三种已经具体绑定的依赖关系：

1. **Gate 依赖**：`gated_by` 引用同一 owner 的一位 `valid`。先分别约束两个字段，
   再检查 gate；gate 为 0 时，被依赖字段最终强制归零。`ready` 与同 owner `valid`
   同时存在时，layout builder 默认建立这个依赖。
2. **宽度依赖**：`byte_enable` 的位数必须严格等于同 owner `data.width / 8`。例如
   32 位 data 只能配 4 位 byte enable。
3. **ISA 依赖**：`riscv_imc` instruction 字段依赖完整 `IsaContract`。16 位指令还
   要求包含 C 扩展并声明 2 字节对齐。

`dependency_group` 用于声明两个或更多字段属于同一个需要联合求解的关系组。layout
阶段要求每个 group 至少有两个成员，但当前 `RuntimeProjector` 不会擅自推断组内
关系；如果一个 `dependency_group` 到运行时仍未被上游求解并消除，会以
`unbound runtime dependency group` 失败关闭。也就是说，它是“必须在投影前解析”的
依赖标记，不是当前运行时可以忽略的注释。

### 精确投影顺序

`RuntimeProjector` 把最终顺序固化在 constraint document 的 `projection_order`：

```text
1. mask
2. finite_selection_or_range_alignment
3. instruction_legality
4. inactive_gate_zero
5. raw_reconstruction
```

具体过程是：

1. 从 `raw_lo:raw_hi` 提取字段原始值。
2. 如果存在 `mask`，先执行 `source &= mask`。
3. 如果存在 `enum`，用 `source % len(enum)` 选择合法枚举项。
4. 如果存在 `range + mask`，从预计算的合法交集候选集中取值。
5. 否则处理 signed，并按 `range/alignment` 做模映射和对齐。
6. 对 `riscv_imc` 检查指令合法性；非法 32 位指令替换为 `0x00000013`，非法 16 位
   压缩指令替换为 `0x0001`，两者都是相应宽度的合法 NOP。
7. 执行 `inactive_gate_zero`。这一步故意晚于 enum/range；gate 为 0 时，0 会覆盖
   其他字段约束，即使 enum 的活动值列表没有 0。
8. 执行 `raw_reconstruction`，把每个约束后的字段放回其 layout raw slice。
9. `project_ports()` 再根据 scalar/packed 物理坐标重建实际 DUT 输入端口。

约束快照记录 `gating_semantics=inactive_zero_overrides_field_constraints`。调用者之后
修改原始 Python list/dict 不会改变已经运行的 projector。

### 数值示例一：range、alignment、signed 和 gate

假设布局是：

```text
bit 0       e:valid    width=1
bits 1..8   e:address  width=8, range=[16,28], alignment=4
bit 9       e:ready    width=1, gated_by=e:valid
bits 10..17 e:data     width=8, signed, range=[-8,7]
```

输入取：`valid=0`、raw address=`255`、raw ready=`1`、raw data=`255`。投影结果为：

```text
address: 255 → [16,20,24,28] 中的 28
ready:   1 → 因 valid=0，最终被 gate 强制为 0
data:    255 → 8 位 signed 的 -1 → raw slice 中为 0xff
```

### 数值示例二：enum 和 mask

```text
enum field: width=4, enum=[1,4,7]
mask field: width=4, mask=0b1010
raw input : 0xf1
```

低 4 位原始值是 1，因此枚举选择 `enum[1 % 3] = 4`；高 4 位原始值是 `0xf`，
mask 后得到 `0xf & 0xa = 0xa`。最终投影 word 是 `0xa4`。

### 真实 Ibex 示例的约束依赖

真实示例的接口描述先包含所有 Ibex 输入。`build_candidate()` 只给配置中的四组中断
字段添加 `randomizable=true`。`build_simulator()` 同时传入：

```text
randomized_controls = ("interrupt",)
control_defaults     = boot/hart/debug/fetch/reset/integrity 等固定值
```

runtime boundary 同时要求：字段属于 canonical `interrupt` control，并且字段上确实有
`randomizable=true`，两者缺一不可。修正后的真实 runtime layout 正好是 18 位：

```text
raw bit 0       → irq_external_i[0]
raw bits 1..15  → irq_fast_i[14:0]
raw bit 16      → irq_software_i[0]
raw bit 17      → irq_timer_i[0]
```

其他输入通过 `control_defaults` 生成固定 binding，不占用这 18 个 fuzz bits。coverage
再观察这 18 个输入位以及 backend request/response 两个内部事件，因此当前反馈向量共
20 个计数器。

可以直接检查运行产物：

```bash
jq . runs/examples/real-ibex-compose/build/sim/runtime_layout.json
jq '{layout_hash, constraint_hash, runtime_controls}' \
  runs/examples/real-ibex-compose/build/sim/artifact_provenance.json
```

`constraint_hash` 绑定完整 layout、每个字段的约束和物理坐标、精确
`projection_order`、gating semantics、instruction mode 以及完整 ISA contract。
保存和重放语料时必须再次匹配该哈希；约束变化后，旧语料不会被误认为同一执行身份。

## 4. 目录内容

```text
examples/real_ibex_rfuzz/
├── README.zh-CN.md
├── commands.sh
├── run_example.py
├── input/ibex-scratch.json
└── expected/bounded-result.json
```

- `run_example.py`：`compose`、`test`、`inspect` 三个命令。
- `input/ibex-scratch.json`：真实 Ibex 示例输入。
- `commands.sh`：带环境设置的可执行命令集合。
- `expected/bounded-result.json`：此前 5 秒运行的参考结果，不是伪造的新运行输出。

## 5. 前置依赖

需要 Python 3、Verilator、C++ 编译器、固定 Ibex checkout 和已编译的官方 RFuzz
客户端。先检查：

```bash
verilator --version
test -f third_party/rfuzz/upstream/ibex/rtl/ibex_core.sv
test -x runs/task14_client_cancel_build/debug/kfuzz
```

RFuzz checkout 需要仓库中的有界取消补丁。未应用时执行：

```bash
git -C third_party/rfuzz/upstream/rfuzz_reference apply --check \
  --ignore-space-change \
  ../../../../patches/rfuzz/0001-bounded-cancel-after-ipc-batch.patch
git -C third_party/rfuzz/upstream/rfuzz_reference apply \
  --ignore-space-change \
  ../../../../patches/rfuzz/0001-bounded-cancel-after-ipc-batch.patch
```

如果第一条正向检查失败，先用 `apply --check --reverse` 判断补丁是否已经应用，
不要重复应用。客户端的完整固定工具链构建命令见
`docs/reports/task16_processor_rfuzz_regression_20260908.md`。

## 6. 输入文件字段

`input/ibex-scratch.json` 中各字段的作用如下：

| 字段 | 含义 |
| --- | --- |
| `schema_version` | 示例输入契约版本，必须为 `real_ibex_rfuzz_example.v1` |
| `id` | 本次 CPU/ISA/外设配置身份 |
| `interface` | 固定 Ibex 的 source-backed 接口描述 |
| `isa` / `isa_contract` | RV32IMC、扩展集合、特权级和指令对齐约束 |
| `protocol` | 期望从接口事实解析出的 `obi@1` |
| `memory_module` | 通用 backend 后的启动 RAM 模块 |
| `reset_vector` | Ibex 首取指地址，本例为 `0x80` |
| `probe_cycles` | 构建后确定性执行探测的周期数 |
| `composition_seed` | 地址分配和组合决策的固定种子 |
| `randomizable_fields` | 唯一允许进入 RFuzz 输入布局的逻辑字段 |
| `control_defaults` | 不受 fuzz 输入影响的固定物理控制值 |
| `personality` | scratch 寄存器外设的模块、源码和 `MODE=0` 参数 |

示例加载器拒绝未知字段、缺失字段、错误版本、绝对/越界源码路径、缺失源码以及非法
字段类型。

## 7. 自动组合命令

从仓库根目录运行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 examples/real_ibex_rfuzz/run_example.py compose \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --output runs/examples/real-ibex-compose
```

输出目录必须事先不存在。主要输出包括：

- `build/execution.json`：首取指、进展、completion、pass 和 error 证明。
- `build/interface.json`：实际送入组合器的接口描述。
- `build/sim/`：生成的顶层、输入 transport、布局和 Verilator artifact。
- `summary.json`：面向使用者的组合哈希、布局哈希、执行和覆盖摘要。

组合命令本身会运行两次相同的确定性 RTL probe；两次结果不同会直接失败。

## 8. 5 秒官方 RFuzz 测试

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 examples/real_ibex_rfuzz/run_example.py test \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --client runs/task14_client_cancel_build/debug/kfuzz \
  --output runs/examples/real-ibex-rfuzz-5s \
  --seconds 5
```

该命令会重新组合和编译，随后启动官方客户端，通过共享内存对真实 RTL 执行测试，
保存有反馈增益的语料，再逐条重放。重点检查：

```bash
PYTHONPATH=src:. python3 examples/real_ibex_rfuzz/run_example.py inspect \
  --output runs/examples/real-ibex-rfuzz-5s
jq . runs/examples/real-ibex-rfuzz-5s/summary.json
jq . runs/examples/real-ibex-rfuzz-5s/live/corpus_manifest.json
```

成功摘要应包含非零 `tests`、`corpus_entries`、
`completed_feedback_exchanges` 和 `replay_entries`，`returncode` 为 0，且
`remaining_segments` 为空。

## 9. 当前简单测试结果

`expected/bounded-result.json` 记录了修正控制约束后重新执行的 5 秒真实 Ibex 预检：

- 33,657 次 RTL 测试；
- 27,758 个完成的 feedback receipt；
- 19 条保存并重放的语料；
- 370,227 次 request 和 completion；
- 336,570 次成功读取与地址进展；
- 33,657 次外设 pass completion；
- 零协议错误、客户端返回码 0、零遗留共享内存。

覆盖类型是 `sampled-dut-signal-bit-events-u8-saturating`，表示显式中断输入位和
内部 backend request/response 事件的采样计数，不应表述为源码行覆盖率或分支覆盖率。

## 10. 新反馈为什么产生新语料

RFuzz 为每次输入得到一组反馈计数，并维护整个运行到目前为止已经观察到的反馈状态。
如果一个输入使至少一个反馈位置出现此前没有观察过的状态，这个输入就具有反馈增益，
会被保留到 corpus；没有增益的输入不会保留。

```text
输入 A → 没有新反馈       → 不保存
输入 B → 新反馈位置 5     → 保存为语料
输入 C → 与 B 的反馈相同  → 不保存
输入 D → 新反馈位置 8     → 保存为语料
```

因此，“执行一次测试”和“产生一条新语料”不是一回事。33,657 次执行最终只有 19 条
语料是正常现象，表示绝大多数变异没有扩展已知反馈状态，而这 19 条输入分别贡献了
可保留的反馈增益。

`completed_feedback_exchanges` 也不等同于进程内部简单地调用过一次 simulator。
它只统计经过共享内存 FIFO 完整提交，并收到对应回复的交换。只有具有这类 receipt 的
输入，才能被标记为 `shared_memory_exchange_verified=true`。

## 11. 语料重放和身份一致性

保存语料以后，系统把每条 raw input 重新拆成周期记录，再送入真实 Verilator RTL。
重放得到的反馈计数必须与保存时一致，否则立即报告 coverage mismatch。

重放同时核对：

- 原始输入 SHA-256；
- input layout hash；
- constraint hash；
- simulator binary SHA-256；
- 固定物理控制输入 SHA-256；
- simulator input SHA-256；
- 由上述身份组成的 replay key。

正式 campaign 还会从保留的源码重新构建一份 simulator，然后用新构建产物重放全部
语料。这用来排除残留进程状态、临时生成文件或某一次二进制偶然行为对结果的影响。

## 12. 回归和正式长测

只验证示例契约与文档，不启动真实 CPU：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v \
  tests.examples.test_real_ibex_rfuzz_example
```

全量 Python 回归：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 \
  python3 -m unittest discover -s tests -p 'test_*.py'
```

正式三组长测使用生产 runner，而不是示例短测入口：

```bash
PYTHONPATH=src:. JOBS=1 nice -n15 python3 scripts/run_real_cpu_campaigns.py \
  --config configs/campaigns/ibex-real-rfuzz.json \
  --client runs/task14_client_cancel_build/debug/kfuzz \
  --output runs/task15-real-cpu-3x300 \
  --seconds 300 --seed 20260908
```

runner 串行运行 scratch/GPIO/timer 三种不同组合，每组至少 300 秒，并执行独立重建
和全语料重放。该门槛目前未执行，不能从 5 秒结果推断为通过。

## 13. 常见问题

- `output already exists`：为新运行换一个输出目录；不要删除需要保留的旧证据。
- `interface does not exist`：固定 Ibex checkout 或接口描述不完整。
- `RFuzz client does not exist/is not executable`：重新构建客户端或修正 `--client`。
- Verilator 编译内存不足：保留 `JOBS=1`，不要并行启动多个真实 CPU 构建。
- 中断后检查进程：`pgrep -af 'kfuzz|verilator|Vgenerated'`。
- 检查 SysV 共享内存：`ipcs -m`。生产 runner 只清理由本次客户端拥有的 segment。
- `first_fetch_matched=0`、无地址进展、无 pass 或出现 error：该次运行失败，不能只看
  客户端是否启动。

所有详细能力与历史证据见
`docs/reports/task16_processor_rfuzz_regression_20260908.md`。

## 14. 当前结论

当前已经跑通并验证的主链路是：

```text
自动组合
→ OBI 协议适配
→ 地址分配和 RTL 接线
→ 输入约束投影
→ Verilator 编译
→ 真实 Ibex 启动和执行
→ 官方 RFuzz 共享内存反馈
→ 新语料保存
→ 全语料真实 RTL 重放
```

尚未完成的是覆盖范围和长时间稳定性门槛：BOOM 真实处理器验收按要求暂缓，GPIO 和
timer personality 尚未完成本轮真实 CPU 长测，三组各 300 秒的 Task 15 campaign
尚未执行。因此可以确认系统主链路能够正确运行，但不能据此宣称整个长期验收计划完成。
