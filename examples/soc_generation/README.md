# 自动 SoC 组合示例：首次输入的 CPU 与两个外设

本目录是 `scripts/generate_soc.py` 的输入样例，也是阶段 A（生成与独立结构验证）的验收对象。

`novacore`、`novauart`、`novagpio` **不在任何 myfuzz 型号表里**：它们不出现在
`configs/soc/matrix.json`、`configs/soc/families/`、`src/myfuzz/components/profiles/`，
也不出现在 `soc_matrix_smoke.py` 的任何事实表中。生成器只依据 profile 声明、协议/能力表
和 verilator 展开得到的真实端口事实完成组合。

## 目录内容

| 路径 | 内容 |
| --- | --- |
| `rtl/novacore.sv` | 首次输入的 32 位 RISC-V CPU，统一 OBI 访存主接口、一个中断入口、4 位特殊随机输入、两个观测输出 |
| `rtl/novauart.sv` | 首次输入的 MMIO UART，APB4 从接口、一个同域电平中断源、一对 UART 引脚 |
| `rtl/novagpio.sv` | 首次输入的 MMIO GPIO，APB4 从接口、一个同域电平中断源、8 位引脚、3 位特殊随机输入 |
| `profiles/novacore.json` | CPU profile：源码闭包与哈希、时钟复位、接口角色绑定、能力、CPU 执行/中断入口契约、port_actions |
| `profiles/novauart.json` | 外设 profile：APB4 总线、中断源保持与清除、地址窗口与寄存器表、外部引脚 |
| `profiles/novagpio.json` | 外设 profile：同上，另有一个标记为 fuzz 的特殊输入 |
| `request.json` | 组合请求：实例、参数覆盖、固定地址、ROM/RAM、地址策略、时钟复位、测试模式 |

`request.json` 里 `uart0` 与 `uart1` **引用同一份 profile**：系统为它们分别分配地址和中断源，
不需要复制或修改组件描述；`uart1` 还固定了 `0x40001000`，自动分配会绕开它。

## 运行

```bash
PYTHONPATH=src:. python3 scripts/generate_soc.py \
  --request examples/soc_generation/request.json \
  --profile examples/soc_generation/profiles/novacore.json \
  --profile examples/soc_generation/profiles/novauart.json \
  --profile examples/soc_generation/profiles/novagpio.json \
  --output runs/soc-generation/novacore-demo
```

退出码：`0` 生成并通过独立结构审计；`1` 输入或组合被拒绝；`2` 生成 RTL 未通过审计。

重新计算某个 profile 的源码 pin：

```bash
PYTHONPATH=src:. python3 scripts/generate_soc.py --request examples/soc_generation/request.json \
  --profile examples/soc_generation/profiles/novacore.json --print-pin
```

## 产物

| 文件 | 内容 |
| --- | --- |
| `myfuzz_soc_top.sv` | 生成的 SoC 顶层：CPU + 处理器适配器 + beat 互联 + ROM/RAM + 外设桥 + 中断控制器 + 顶层导出端口 |
| `sources.f` | 生成顶层需要的全部源文件（含角色与归属） |
| `soc_composition.json` | 完整生成记录：实例、profile 绑定、端口台账、原始输入布局、中断计划、spec/plan |
| `port_dispositions.json` | 每个端口与位段的处理方式、去向、依据与覆盖损失 |
| `interrupt_plan.json` | 源编号、控制器参数与窗口、寄存器映射、三条物理路径、服务契约 |
| `address_map.json` / `raw_layout.json` | 地址分配与特殊输入位段布局 |
| `structure_audit.json` | 独立结构审计结果，含无法证明的项（标记为 `unknown`，不算通过） |
| `inputs.json` | 请求、profile、pin 与计划身份 |

## 本例的地址与中断分配

```text
rom0   0x0001_0000 + 0x8000   只读只执行，镜像由外部 +riscv_boot_image 提供
ram0   0x8000_0000 + 0x10000  可读写执行
gpio0  0x4000_0000 + 0x1000   自动分配
uart1  0x4000_1000 + 0x1000   请求固定
uart0  0x4000_2000 + 0x1000   自动分配
irq    0x4000_3000 + 0x0040   通用中断控制器
```

中断源按稳定实例 ID 排序编号（与本例中 `peripherals` 的书写顺序无关）：

```text
source id 1 = gpio0.irq_o -> 控制器 bit 0
source id 2 = uart0.irq_o -> 控制器 bit 1
source id 3 = uart1.irq_o -> 控制器 bit 2
控制器 irq_o -> cpu0.irq_external_i（machine external，高有效同域电平）
```

## 本次示例能证明什么、不能证明什么

能证明（有自动化证据）：

- 三个陌生组件的 profile 声明与 verilator 展开的真实端口方向/宽度/成员一致；
- 每个端口和位段都有唯一处理方式，输入不悬空、输出不被随机驱动；
- 地址不重叠、用户固定地址原样保留、自动分配确定性且与请求书写顺序无关；
- 同一 profile 的多实例各自获得独立地址、独立桥和独立中断源；
- 12 位地址缩窄有窗口证明（`base % 2**12 == 0` 且 `size <= 2**12`），不是静默截断；
- 生成 RTL 可编译/展开，且重新展开后的实际连接与计划一致（含六类故障注入全部被检出）。

不能证明（本阶段明确不声称）：

- CPU 实际执行、程序语义、中断处理闭环：本阶段的例子 CPU 是组合用的骨架，不含可运行软件；
- 协议时序行为：审计只证明结构，行为仍由协议级仿真证据负责；
- 互联的单未完成事务限制之外的并发/乱序行为；
- 复位释放时序、跨时钟域、多核等首期范围外能力。
