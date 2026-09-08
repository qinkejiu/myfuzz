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

## 5. Fail-closed 诊断

约束发布没有 `instruction_identity` 时，转导器校验返回
`missing-instruction-identity`；方向错误、宽度错误、重复字段、无源证据或交错 split/unified
拓扑也会在发布前失败。组合器不会根据 CPU 名称、RTL 路径或地址范围猜测请求类别。省略
`--constrained` 时可以生成协议接线检查产物，但该产物不宣称统一端点的取指/数据分类已证明。

因此同一 ISA 和协议描述可以跨实现复用，但每个 CPU 仍必须提供真实的协议端口和身份信号
证据。替换端口别名只会改变物理连接和来源哈希，不会改变 ISA/协议约束的语义。
