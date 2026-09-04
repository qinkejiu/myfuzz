# Ibex 协议组合与长时间测试设计

**日期：** 2026-09-04
**状态：** 已确认设计，待编写实施计划

## 1. 目标

在不改变现有默认实验配置的前提下，为 MyFuzz 增加一条可复用的真实 Ibex 组合流程：

1. 实现 APB4、AXI4-Lite、TileLink-UL 的可执行单拍协议桥；
2. 通过声明式组件清单自动组合 Ibex、RAM、Timer、GPIO、UART 和 SPI；
3. 将组合结果接入现有 RTL 插桩、Verilator 和 RFuzz 流程；
4. 在低资源策略下提供可恢复的小时级长时间测试入口。

首轮交付的是一个可验证、可重复的 Ibex 组合目标，不承诺本阶段覆盖协议的所有高级特性，也不把结构生成成功等同于 RTL 功能正确。

## 2. 当前基线

当前 `main` 已具备：

- 本地 Verilator 前端组件和源级 RTL 插桩流程；
- `src/myfuzz/protocols` 协议 Catalog、字段宽度编译和依赖投影声明；
- `src/myfuzz/composition` 组合声明、候选搜索和 `composition_ir.v1`；
- Ibex 多组件 IP 实验脚手架，包含 RAM、Timer、GPIO、UART、SPI；
- `run_design_flow.py` 的 frontend、instrument、toml、harness、server、fuzz 阶段；
- 低资源 profile 和确定性的低资源 Smoke；
- 现有协议插件声明：APB3、APB4、AXI4-Lite、OBI、Ready/Valid MMIO、TileLink-UL。

现有 Ibex 多组件目标的组件状态逻辑可以复用，但当前数据请求仍直接连接到统一的 `valid/write/address/data` 端口，协议插件也主要承担声明和投影元数据职责。因此，本设计新增的是运行时协议桥和组合生成边界，不重写现有组件内部状态机。

## 3. 范围与非目标

### 3.1 本阶段范围

- 真实 Ibex `ibex_core` 作为组合目标中的 CPU；
- 一个统一时钟域和一个低有效同步复位边界；
- RAM、Timer、GPIO、UART、SPI 五类组件，其中 RAM 同时服务指令和数据访问；
- APB4、AXI4-Lite、TileLink-UL 三种运行时协议；
- 一个默认的、确定性的组件清单和一个自动生成的 Harness；
- 单构建槽、单 RFuzz worker、无波形的低资源长跑；
- checkpoint、日志、覆盖率、事务统计、协议错误和崩溃归档。

### 3.2 非目标

- 本阶段不接入 CVA6；
- 不实现 AXI4/AXI Stream、AHB-Lite 或其他第四种协议；
- 不实现 AXI Burst、多个未完成事务、TL 多拍事务或多 Source 并发；
- 不实现多时钟域、异步 FIFO、CDC 自动综合；
- 不在现有默认 Ibex、CVA6、BOOM 配置上修改字段；
- 不在首轮实现 Top-K 组合搜索；
- 不把 Python 事务模型替代 HDL 协议桥的实际仿真验证；
- 不在没有短跑证据时直接宣称小时级长跑通过。

## 4. 系统架构

总体流程如下：

```text
protocol_composition.v1 清单
        │
        ▼
协议 Catalog + 组件注册表 + Ibex 端口事实
        │
        ▼
组合校验器
  协议版本 / 字段位宽 / 地址范围 / 中断 / 时钟复位
        │
        ▼
稳定的 composition_ir.v1 和生成元数据
        │
        ▼
SystemVerilog 组合 Wrapper + RFuzz Harness
        │
        ▼
RTL 插桩 → Verilator Server → RFuzz
        │
        ▼
checkpoint、覆盖率、吞吐量、协议错误和崩溃报告
```

组合目标内部的数据路径为：

```text
Ibex native instruction/data request
              │
              ▼
       Ibex 协议路由器
       ┌──────┼──────┐
       ▼      ▼      ▼
    TL-UL   APB4  AXI4-Lite
       │      │      │
      RAM  Timer   UART
           GPIO    SPI
```

Ibex 的原生请求接口作为主端。每个协议桥把原生请求转换为标准协议时序，再把协议从端响应还原为 `ready/rdata/error`。组件内部继续使用统一的 MMIO 端口，协议差异被限制在桥和组件适配层。

协议路由使用现有地址规划：

| 地址范围 | 组件 | 运行时协议 |
| --- | --- | --- |
| `0x0000_0000`–`0x0000_FFFF` | 指令/数据 RAM | TileLink-UL |
| `0x8001_0000`–`0x8001_0FFF` | Timer | APB4 |
| `0x8002_0000`–`0x8002_0FFF` | GPIO | APB4 |
| `0x8003_0000`–`0x8003_0FFF` | UART | AXI4-Lite |
| `0x8004_0000`–`0x8004_0FFF` | SPI | AXI4-Lite |

同一地址范围只能有一个有效组件；未命中地址返回确定的错误响应，不允许随机传播 X 状态。

## 5. 协议运行时边界

### 5.1 APB4

运行时桥必须处理以下字段：

```text
PADDR、PPROT、PSEL、PENABLE、PWRITE、PWDATA、PSTRB
PREADY、PRDATA、PSLVERR
```

约束如下：

- 每次只允许一个传输；
- 必须先进入 Setup，再进入 Access；
- `PADDR/PWRITE/PWDATA/PSTRB/PPROT` 在 Access 阶段保持稳定；
- 只有 `PSEL && PENABLE && PREADY` 时才完成传输；
- `PSLVERR` 转换为 Ibex 数据错误；
- 等待周期由受限 RFuzz 参数控制，最大等待不超过协议策略声明的 16 个周期。

当前 Catalog 中已有 APB4 的抽象字段。为保持旧绑定兼容，新增运行时字段可以作为“运行时必需、抽象绑定可选”的字段；只有组合运行时编译路径才要求完整 APB4 字段。

### 5.2 AXI4-Lite

运行时桥必须处理完整的 Lite 事务字段：

```text
AWADDR、AWPROT、AWVALID、AWREADY
WDATA、WSTRB、WVALID、WREADY
BRESP、BVALID、BREADY
ARADDR、ARPROT、ARVALID、ARREADY
RDATA、RRESP、RVALID、RREADY
```

约束如下：

- 不支持 Burst；
- 写地址和写数据可独立握手，但必须同时收齐后才向组件提交一次写事务；
- 每个方向最多保留一个未完成事务；
- `AWVALID/WVALID/ARVALID` 在未握手前保持地址、控制和数据稳定；
- `BRESP/RRESP` 映射为成功、从端错误或解码错误；
- `WSTRB` 转换为统一 MMIO 的 byte enable；
- 背压和响应延迟必须在 16 个周期的边界内完成。

### 5.3 TileLink-UL

首版支持单拍的 `Get`、`PutFullData` 和 `PutPartialData`，运行时字段包括：

```text
A：valid、ready、opcode、param、size、source、address、mask、data、corrupt
D：valid、ready、opcode、param、size、source、sink、denied、data、corrupt
```

约束如下：

- 不支持多拍传输；
- 不支持多个并发 Source；
- `PutPartialData` 使用 `mask` 生成 byte enable；
- `denied`、A/D 通道 `corrupt` 和不支持的 opcode 转换为统一 MMIO 错误；
- 只有 A 通道握手后才能产生对应 D 响应；
- 响应延迟受 16 个周期边界限制。

当前 `tl-ul@1` 插件的抽象字段少于运行时完整字段。运行时协议绑定需要增加兼容的运行时字段元数据，并由运行时编译器检查完整字段；既有抽象协议测试不得因为新增可选元数据而失效。

## 6. 组件契约与自动组合

### 6.1 组件注册表

组件注册表是受控的静态映射，清单只能选择已注册的组件类型，不能通过清单注入任意 Verilog 文件或编译参数。每个注册项提供：

- 组件类型和稳定组件 ID；
- HDL 模块名及受控源文件列表；
- 统一 MMIO 请求/响应端口；
- 参数白名单和默认值；
- 中断端口及状态观测字段；
- 支持的协议 ID、版本和运行时 profile。

首轮注册项为 `ram`、`timer`、`gpio`、`uart`、`spi`。它们复用 `configs/designs/ibex_multicomponent_ip/rtl/` 下已有的状态逻辑，并由适配器连接到协议桥。

### 6.2 组合清单

清单采用新的 `protocol_composition.v1` 契约，包含：

- `target.kind` 和 Ibex 基础设计配置；
- 组件 ID、注册类型、协议 ID/版本、地址基址、窗口大小；
- 可选数据位宽、地址位宽和组件参数；
- 中断编号和是否暴露外部输入；
- 运行 profile、随机种子、持续时间和 checkpoint 周期。

清单中组件按 ID 排序后参与哈希。地址必须按 4 KiB 窗口对齐，窗口不得重叠，所有 IRQ 编号必须唯一且落在 Ibex 可用范围内。

### 6.3 组合编译结果

组合器复用现有 `composition_ir.v1` 的语义字段，不建立第二套候选 IR。输出至少包含：

- `components` 和 `instances`；
- `endpoint_bindings`，含协议 ID、版本、方向和字段绑定；
- `adapters`，含桥类型和证据；
- `address_regions`、`clock_domains`、`reset_domains`；
- 生成 Wrapper 的源文件列表、顶层模块和内容哈希；
- `assumptions`、`diagnostics` 和校验结果。

生成过程必须是确定性的：同一清单、同一协议 Catalog、同一组件注册表和同一工具版本得到相同的排序、源文本哈希和组合计划哈希。生成文件只能写入 `runs/` 或明确的临时输出目录，原始 RTL 不得被改写。

## 7. Ibex 激励与 RFuzz 映射

首轮组合目标使用固定的、合法的 RV32I 访问程序，以保证长跑中五类组件都能被访问。程序循环执行：

```text
RAM 读写 → Timer 读写 → GPIO 读写
→ UART 读写 → SPI 读写 → 返回 RAM
```

程序代码不由随机位直接生成，避免随机非法指令使协议路径无法覆盖。RFuzz 输入映射到以下受限场景：

- 每个协议的地址偏移、读写选择和合法 byte enable；
- APB4 等待周期和 `PSLVERR`；
- AXI4-Lite 的 AW/W/AR/R/B 背压和响应错误；
- TileLink A/D 通道的合法延迟、Mask 和错误响应；
- GPIO 输入变化、UART RX、SPI MISO 和 Timer Tick；
- 外设状态、IRQ 组合和有限错误场景。

RFuzz 不直接随机写入 `valid/ready` 的任意组合。协议桥负责维持握手稳定性，协议策略负责把输入裁剪到有限时序窗口。每个样本都带有确定性 seed，报告中保存 seed 和映射版本。

## 8. 长时间测试控制器

新增一个面向组合清单的 campaign 入口，默认使用低资源 profile。它依次执行：

1. 清单、协议和组件注册表预检；
2. 生成组合 IR、Wrapper、Harness 和源文件列表；
3. 执行现有 RTL 插桩和 Harness/TOML 生成；
4. 单次构建 Verilator Server；
5. 以单 worker 启动 RFuzz；
6. 按时间周期写 checkpoint 和中间统计；
7. 到期、收到中断或发生错误时安全结束并发布报告。

首轮小时级运行默认持续 3600 秒，命令行可以显式缩短或延长，但默认不能自动增加并发。首轮开发验证使用 10～60 秒短跑，短跑通过后才执行小时级命令。

报告至少包含：

- 清单和组合计划哈希；
- Ibex、协议桥和组件版本；
- 实际运行时长、seed、迭代数和吞吐量；
- 每种协议及每个组件的事务计数；
- 覆盖率摘要和新增覆盖点；
- 协议错误、Ibex 错误、子进程退出状态；
- 峰值 RSS、软/硬资源策略和 checkpoint 列表；
- 崩溃样本、输入 seed 和可复现命令。

报告写入采用现有原子发布边界；长跑中断不能留下半份成功报告。

## 9. 低资源与恢复策略

首轮默认策略为：

- 构建和运行串行；
- 一个 Verilator 构建槽和一个 RFuzz worker；
- 关闭 VCD/波形；
- 使用现有保守 profile：512 MiB soft、768 MiB hard、64 MiB token 上限；
- 限制 replay queue、event ring 和 field batch；
- 由运行时 supervisor 监控实际子进程 RSS，而不仅依赖 planner 配置；
- 超过硬上限时终止当前进程组，保存 seed、日志、已收集样本和 checkpoint；
- 资源终止最多按配置次数恢复，连续超限后报告为 resource-terminated；
- 不因单个协议样本非法而终止整个 campaign，非法样本进入协议错误计数。

如果当前平台无法可靠获得子进程 RSS 或无法安全终止进程组，campaign 必须在启动前失败，并明确报告资源监督不可用；不能将仅有配置约束标记为实际硬内存保护。

## 10. 错误处理

错误按阶段处理：

| 阶段 | 错误 | 处理 |
| --- | --- | --- |
| 预检 | 清单格式、协议版本、位宽、地址或 IRQ 非法 | 立即失败，不生成可运行产物 |
| 协议编译 | 必需字段缺失、宽度不一致、桥不支持 | 立即失败，报告字段路径 |
| 生成 | 模块、端口或源文件无法解析 | 立即失败，保留诊断，不启动 RFuzz |
| Verilator | 编译错误或协议断言错误 | 保存完整编译日志，退出 campaign |
| RFuzz 样本 | 协议输入违反桥边界 | 丢弃样本并增加协议错误计数 |
| 运行时 | 子进程崩溃、超时或硬资源终止 | 保存 checkpoint 和日志，按策略恢复或结束 |
| 报告发布 | 目标文件被替换、写入失败或大小超限 | 原子回滚并报告可恢复文件位置 |

任何未识别的 runner 返回、缺失样本或不一致的观测数据都必须 fail closed。

## 11. 验证计划

### 11.1 单元测试

- Catalog 测试检查 APB4、AXI4-Lite、TL-UL 的运行时必需字段和版本；
- 协议桥模型测试覆盖握手、保持、背压、错误和超时边界；
- 组件清单测试覆盖合法清单、地址重叠、IRQ 冲突、未知组件和未知协议；
- 组合器测试检查 IR 字段、稳定排序和重复生成哈希；
- campaign 测试检查参数校验、checkpoint、RSS 超限、崩溃归档和原子报告。

### 11.2 HDL 与真实设计集成测试

- 生成的 Ibex Wrapper 必须通过现有前端和 Verilator 编译；
- 每种协议至少完成一次读和一次写；
- 每个组件至少收到一次有效事务；
- Timer、GPIO、UART、SPI 的 IRQ 可以返回 Ibex；
- 协议错误能映射到报告而不是静默吞掉；
- 10～60 秒真实 RFuzz 短跑产生非零迭代和事务统计。

### 11.3 小时级验收

短跑通过后，执行默认 3600 秒、单 worker 的 Ibex campaign。验收条件为：

- 进程持续到期或按资源策略有记录地结束；
- 报告可解析且包含组合哈希、事务数、覆盖率和 RSS；
- 没有未归档的崩溃或半写入报告；
- 通过 checkpoint 能复现最近一次中断前的 seed 和组合配置；
- 根工作区其他分支和默认配置不受影响。

## 12. 预期变更边界

实现集中在以下区域：

- `src/myfuzz/protocols/`：运行时协议字段、绑定和桥契约；
- `src/myfuzz/composition/`：Ibex 组合清单校验、IR 扩展和确定性生成；
- `src/myfuzz/integration/`：campaign 监督、checkpoint 和报告接入；
- `src/myfuzz/protocols/rtl/` 或等价受控 RTL 目录：三类协议桥；
- `schemas/`：`protocol_composition.v1` 清单契约；
- `configs/designs/ibex_protocol_composition/`：首个真实 Ibex 组合清单和 Harness 边界；
- `scripts/`：组合生成和长跑入口；
- `tests/`：协议、组合、HDL 集成和 campaign 测试。

现有默认设计配置、已有 baseline/depaware 配置和根工作区的其他未提交内容不属于本次修改范围。
