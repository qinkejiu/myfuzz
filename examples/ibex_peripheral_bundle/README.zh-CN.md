# Ibex + 五种真实外设组合包

这个目录把一次完整的 Ibex 组合拆成两部分：

```text
ibex_peripheral_bundle/
├── input/      # 组合器读取的五类输入
└── output/     # 由这些输入生成的全部组合文件
```

## input 中的五类输入

| 目录 | 内容 | 本例对应 |
| --- | --- | --- |
| `01_cpu_interface/` | CPU 顶层模块、时钟/复位、取指/数据端口和源码版本说明 | Ibex `ibex_top`，OBI 取指和数据端口 |
| `02_hdl_source/` | 完整 HDL 源码集合、include 目录、宏定义和版本清单 | 43 个 Ibex HDL 文件，源码根为 `third_party/rfuzz/upstream/ibex` |
| `03_protocol_rules/` | CPU 和外设握手字段、方向、宽度和时序规则 | OBI、统一内存访问、TL-UL、AXI4-Lite、APB4 |
| `04_peripheral_descriptions/` | 外设模块、地址大小、原生协议和外设 RTL 来源 | RAM、UART、SPI、Timer、GPIO |
| `05_isa_test/` | ISA、共享内存、启动地址、等待上限、短测周期和组合顺序 | RV32IMC、2048 周期 smoke |

这些输入文件中的链接指向仓库已有的权威说明；Ibex 上游源码本身不复制到这个示例目录，
避免产生第二份 59 MB 的源码副本。组合器仍会从源码根目录读取全部文件，并在输出中保存
源码清单和校验值。

## 生成 output

在仓库根目录执行（这个小脚本显式加载真实外设说明，而普通通用 CLI 默认不自动加载
`real_*.json`）：

```bash
PYTHONPATH=src python3 examples/ibex_peripheral_bundle/compose.py
```

`output/` 必须是一个新的目录；生成器不会覆盖旧输出。这个命令故意不使用
`--constrained`：本次输出要展示真实 Ibex 同时连接五种真实外设。受约束 CPU-only
输出会由约束转导器提供内存响应，不会把这五个外设实例一起接入。

## output 中会看到什么

```text
output/
├── composition_ir.json
├── input_layout.json
├── processor_execution.v1.json
├── processor_backend.v1.json
├── rfuzz_input_transport.json
├── rfuzz_input_transport.sv
├── generic_composition_top.sv
└── sources.f
```

- `composition_ir.json`：CPU、五个外设、适配器、地址区间、中断和来源校验值；
- `processor_execution.v1.json`：Ibex 两个 OBI 端口如何变成统一内存访问；
- `processor_backend.v1.json`：取指/数据仲裁、地址解码、超时、未映射地址错误和复位恢复；
- `generic_composition_top.sv`：真正实例化 Ibex、适配器、仲裁器、五个外设桥和目标模块；
- `sources.f`：Verilator 实际编译的完整 CPU、桥、外设和生成顶层文件清单；
- `input_layout.json` 与 `rfuzz_input_transport.*`：RFuzz 周期输入的位布局和字节打包方式。

生成器会先在临时目录中写入这些文件，核对地址不能重叠、源码校验值和顶层结构，并执行
Verilator lint；全部通过后才把临时目录一次性发布到 `output/`。发布后的有界外设 smoke
由真实 CPU × 外设矩阵命令执行：

```bash
PYTHONPATH=src python3 scripts/run_real_cpu_peripheral_matrix.py \
  --seed 20260909 \
  --out-dir examples/ibex_peripheral_bundle/output/matrix-smoke
```

如果要查看最终连线，先打开 `output/generic_composition_top.sv`；如果要查看实际使用了
哪些源码，打开 `output/sources.f`；如果要核对五个外设的地址，打开
`output/composition_ir.json`。
