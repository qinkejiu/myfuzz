# 真实 Ibex 自动组合与 RFuzz 示例

这个目录给出一套可以从仓库根目录直接运行的真实处理器示例。它使用固定的 Ibex
源码、OBI 总线、启动内存和寄存器外设，展示从接口事实到自动组合、输入约束、
Verilator 仿真、官方 RFuzz 客户端、反馈语料和重放验证的完整链路。

示例入口是 `run_example.py`，输入是 `input/ibex-scratch.json`。生产逻辑仍位于
`src/myfuzz/`；示例程序只是调用已有 API，不维护另一份组合器或测试器。

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

`expected/bounded-result.json` 记录了此前保留的 5 秒真实 Ibex 预检：

- 15,357 次 RTL 测试；
- 13,440 个完成的 feedback receipt；
- 19 条保存并重放的语料；
- 168,927 次 request 和 completion；
- 153,570 次成功读取与地址进展；
- 15,357 次外设 pass completion；
- 零协议错误、客户端返回码 0、零遗留共享内存。

覆盖类型是 `sampled-dut-signal-bit-events-u8-saturating`，表示显式中断输入位和
内部 backend request/response 事件的采样计数，不应表述为源码行覆盖率或分支覆盖率。

## 10. 回归和正式长测

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

## 11. 常见问题

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
