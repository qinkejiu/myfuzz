# 通用 RISC-V CPU 直接接入示例

这份说明描述不依赖 CPU 名称的接入方式。输入是一份带源码定位的
`interface_description.v1`，输出是可交给 Verilator/RFuzz 的组合目录。组合器不会把
随机位串替换成固定指令序列：RFuzz 仍提供每周期的原始位串，ISA 和协议契约只对这些位
做合法化、布尔修复和握手状态约束。

## 1. 输入文件

PicoRV32 类统一端点的最小描述如下（CV32E40P 类 CPU 则用两个
`instruction_memory_master`/`data_memory_master` OBI endpoint）：

```json
{
  "schema_version": "interface_description.v1",
  "source": {
    "root": "third_party/picorv32_upstream_reference",
    "revision": "git:0000000000000000000000000000000000000000",
    "top_module": "picorv32",
    "files": ["picorv32.v"],
    "elaboration": {"frontend": "verilator-json"}
  },
  "endpoints": [
    {"endpoint_id": "processor.clock", "function": "clock", "module": "picorv32",
     "fields": [{"role": "clock", "aliases": ["clk"]}]},
    {"endpoint_id": "processor.reset", "function": "reset", "module": "picorv32",
     "fields": [{"role": "reset", "aliases": ["resetn"]}]},
    {"endpoint_id": "processor.memory.unified", "function": "memory_master",
     "module": "picorv32", "protocol": ["ready-valid-memory", "1"],
     "clock": "clk", "reset": "resetn", "fields": [
       {"role": "valid", "aliases": ["mem_valid"]},
       {"role": "ready", "aliases": ["mem_ready"]},
       {"role": "addr", "aliases": ["mem_addr"]},
       {"role": "wdata", "aliases": ["mem_wdata"]},
       {"role": "wstrb", "aliases": ["mem_wstrb"]},
       {"role": "rdata", "aliases": ["mem_rdata"]},
       {"role": "instruction_identity", "aliases": ["mem_instr"]}
     ]}
  ]
}
```

`instruction_identity` 是 CPU 源码产生的单 bit 输出：1 表示取指，0 表示数据访问。
它必须有源文件和端口方向/宽度证据，且不会被加入 RFuzz 输入布局。分离端点不需要这个
字段，因为端点函数本身已经表达请求类别。

仓库中可直接复用的模板是：

- `configs/cpus/cv32e40p/official_core_interface_description.json`：分离 OBI；
- `configs/cpus/picorv32/official_core_interface_description.json`：统一 valid/ready + `mem_instr`。

模板的 `third_party/*_upstream_reference` 是外部 pinned checkout 的位置；接入真实源码时，
先将 `revision`、文件列表、include roots 和端口别名改成真实值，再运行组合命令。

## 2. 自动组合的内部流程

Python API 的调用顺序是：

```text
load_interface_description
  → plan_generic_composition
      → source crawler / EndpointCapability
      → ProcessorBoundary（split_function 或 explicit_signal）
      → ProcessorExecution（按 protocol_id@version 选 adapter）
      → processor-memory-beat@1 backend
  → compile_contract_transducer（约束模式）
  → write_generic_composition
      → generic_composition_top.sv + sources.f + JSON evidence
```

`plan_generic_composition` 固定源码 revision、验证时钟/复位和字段方向；统一端点会拒绝
缺失身份字段。`ProcessorExecution` 对 `ready-valid-memory@1` 使用
`ready-valid-to-processor-memory-beat`，由 `wstrb != 0` 得到写操作，并保持单 outstanding
和 bounded completion。顶层在请求握手时采样 `mem_instr`，再锁存到转导器的
`req_instruction_i`；因此 CPU 改变下一个周期的身份不会污染当前响应。

`compile_contract_transducer` 将 RISC-V ISA 模板、响应选择、测试内一致内存和原始周期布局
编译到同一个契约。随机输入位先选择合法操作，再只修复 ISA/协议要求的固定位；寄存器、
立即数、地址、响应数据等自由位仍保持随机。指令和数据两个逻辑域可以映射到同一物理
`main` 域，首次读取之后按地址/字节使能保存并可重放。

## 3. 标准组合命令

从仓库根目录执行：

```bash
PYTHONPATH=src python3 scripts/generate_composition.py \
  --interface-description configs/cpus/picorv32/official_core_interface_description.json \
  --base-dir . \
  --out-dir runs/examples/generic-picorv32-composition \
  --isa-xlen 32 \
  --isa-extension I --isa-extension M --isa-extension C \
  --constrained \
  --max-wait-cycles 16 \
  --memory-capacity-entries 256 \
  --no-allow-error
```

命令输出一行 JSON。`complete=true` 表示计划、源码证据、顶层 lint 和原子发布全部通过；
约束模式还会输出：

```json
{
  "top_path": ".../generic_composition_top.sv",
  "processor_execution_path": ".../processor_execution.v1.json",
  "contract_transducer_path": ".../contract_transducer.json",
  "complete": true
}
```

组合目录中还包括 `processor_backend.v1.json`、`rfuzz_input_transport.json`、
`rfuzz_input_transport.sv`、`input_layout.json` 和 `sources.f`。不需要约束转导器时，
省略 `--constrained` 以及 ISA 参数即可生成接线检查产物；三个调优参数必须和
`--constrained` 一起使用。

## 4. 后续测试命令

先检查生成的 RTL：

```bash
PYTHONPATH=src pytest -q tests/integration/test_generic_cpu_targets.py
iverilog -g2012 -s generic_composition_top \
  -o runs/examples/generic-picorv32-composition/composition.vvp \
  -f runs/examples/generic-picorv32-composition/sources.f
```

真实 RFuzz 运行沿用现有示例入口；组合目录作为其输入，完成短时随机激励后再重放语料：

```bash
PYTHONPATH=src python3 examples/real_ibex_rfuzz/run_example.py test \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --client runs/rfuzz_client_native_build/target/debug/kfuzz \
  --output runs/examples/generic-picorv32-rfuzz --seconds 5
```

上面的 `run_example.py` 命令是现有真实 Ibex RFuzz runner 的示例；接入其他 CPU 时，
应使用该 CPU 自己的 simulator/test harness，同时复用组合目录中的
`processor_execution.v1.json`、`contract_transducer.json` 和 `sources.f`。测试结果至少
应记录 compose、编译、随机激励、feedback receipt、corpus、同构建重放和独立重建重放。

## 5. 真实 CPU × 真实外设矩阵

仓库中的 `scripts/run_real_cpu_peripheral_matrix.py` 用同一套 generic planner 验证多个
真实 CPU 与多个真实外设的重复组合：

```bash
PYTHONPATH=src python3 scripts/run_real_cpu_peripheral_matrix.py \
  --seed 20260909 \
  --out-dir examples/real_cpu_peripheral_matrix/results
```

每个组合执行以下闭环：

```text
上游 CPU checkout + revision
  → interface_description（split OBI instruction/data）
  → ProcessorExecution OBI adapter
  → processor-memory-beat@1
  → profile/source closure/address allocation
  → real target wrapper
  → TL-UL、AXI4-Lite 或 APB4 bridge
  → 真实 RAM/UART/SPI/Timer/GPIO
  → plan/publication → Verilator lint → 有界时钟 smoke（2048 边沿）
```

CPU wrapper 只补充上游顶层没有的通用错误字段，不替换 CPU 的 OBI 行为。CV32E40P
没有架构化 OBI error 输入，因此有效 error 响应会在仿真 shell 中 `$fatal`；本矩阵只验收
无 error 路径，生产接入需要 CPU 专用异常桥。Ibex、CV32E40P、CV32E20 使用 32 位
目标；CVA6 使用 64 位 wrapper。`real_ram64` 由两个一致性 32 位 bank 组成，保留完整
beat；64 位 UART/SPI/Timer/GPIO 只转换一个对齐 lane，双 lane、未对齐访问和禁止的部分
写会 fail-closed 地产生 `error`，不会静默截断或写入真实模块；TL 桥会保留 `+4` 高 lane
的 32 位读写语义。真实目标的 profile 源码
闭包位于 `configs/designs/ibex_multicomponent_ip/rtl/real_targets/`，其内部桥接分别为
TL-UL（RAM）、AXI4-Lite（UART/SPI）和 APB4（Timer/GPIO）。IRQ 在本轮 smoke 中固定为零，
因此不能把该结果解读为中断覆盖；smoke 检查的是公共 backend 的请求/响应活动，并未逐个
访问每个外设寄存器；CVA6 的 smoke 周期额外覆盖了其复位 I-cache 清空。

种子 `20260909` 产生 9 个组合，9/9 同时通过 planner、publication、Verilator lint 和
smoke；四种 CPU 出现次数为 Ibex 2、CV32E40P 2、CV32E20 2、CVA6 3。每个 32 位真实
外设在兼容 CPU 组合中至少复用两次。JSON/text 报告分别记录组合顺序、桥接协议、位宽、
复用计数和失败诊断。CV32 上游仓库只放在运行时临时的已提交 source root 中，默认不会
写入或清理用户的 `third_party/`；需要检查中间产物时使用 `--keep-artifacts`。

## 6. Fail-closed 诊断

约束发布没有 `instruction_identity` 时，转导器校验返回
`missing-instruction-identity`；方向错误、宽度错误、重复字段、无源证据或交错 split/unified
拓扑也会在发布前失败。组合器不会根据 CPU 名称、RTL 路径或地址范围猜测请求类别。省略
`--constrained` 时可以生成协议接线检查产物，但该产物不宣称统一端点的取指/数据分类已证明。

因此同一 ISA 和协议描述可以跨实现复用，但每个 CPU 仍必须提供真实的协议端口和身份信号
证据。替换端口别名只会改变物理连接和来源哈希，不会改变 ISA/协议约束的语义。
