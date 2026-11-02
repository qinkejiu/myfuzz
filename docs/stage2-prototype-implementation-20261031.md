# 通用数据流原型实施方案

日期：2026-10-31

> 时点说明：本文保留 10 月 31 日方案。11 月 1 日后已新增 F1–F6 单进程入口和独立 F5/F6 反馈闭环；本文后续关于两者尚未实现的状态已过时。当前能力和限制见[系统能力盘点](current-system-capabilities-20261101.md)。

**目标：** CPU、IP 和 DMA 分别提供 profile，同一协议的兼容组件复用适配器，不为 CPU×IP 组合编写专用执行代码；先跑通真实 RTL 的 F1–F6，再逐步扩大协议与组件范围。

**设计：** 每个组件仍是独立的 Verilator 模型，由一个 C++ 宿主进程模拟 RAM、总线路由和 IRQ，推进真实 CPU/IP/DMA。正常运行只输出必要结果，详细事件和独立重放按需开启。

**技术栈：** Python 负责读取配置、准备模型和输入；Verilator/C++ 负责执行；复用现有组件 profile、固件生成和构建缓存。

## 1. 原则与范围

- 不连接实际 SoC，也不要求把多个组件 RTL 合并成一个 SoC；数据流由宿主模拟。
- CPU 真实执行 RISC-V 指令；CPU 和 DMA 的事务、IP 和 DMA 的 IRQ 必须来自真实 RTL 信号。
- 总线握手按协议处理；profile 只描述真实端口和行为，不凭声明推断事件已发生。
- 每种 CPU 总线、IP 总线、DMA 主总线分别适配一次；设备的寄存器、IRQ 等差异由 profile 和行为描述提供。
- 初版优先支持已验证的 OBI CPU、APB IP、Wishbone DMA、32 位对齐 RAM 访问、单 IRQ。其他协议与多 IRQ 后续按同一接口扩展。
- 正常 fuzz 不要求完整证书、逐周期日志或每例 replay。失败可保存输入和必要诊断；需要复核时手动重放。没有观测到的事实记为 unknown。
- 不重做已有 F1–F4 执行器、不新建复杂调度框架；先以现有 F5/F6 原型为基础，逐步统一入口和循环。

## 2. 六条数据流

| 路径 | 原型需要完成的真实动作 | 最小观察 |
| --- | --- | --- |
| F1 | CPU 从程序 RAM 取指并执行 | 实际取指；有退休接口时记录退休 |
| F2 | CPU 读取 IP 或 RAM | CPU 请求、目标响应和读值 |
| F3 | CPU 写 RAM | 实际写入及地址、数据 |
| F4 | CPU 经 MMIO 写 IP | 实际目标握手及地址、数据 |
| F5 | IP 输出 IRQ，CPU 接收并执行中断处理 | IRQ、CPU 接收；可观察时记录 ISR 状态访问和返回 |
| F6 | CPU 配置 DMA，DMA 作为主设备搬运数据 | DMA 读写、目的数据；有完成 IRQ 时观察 IRQ 和处理 |

F1–F4 已有 `compiled_mmio` 路径及多协议验证，但**尚未并入本文的新单进程循环**。F5、F6 目前是两个独立原型入口，不是现成的 F1–F6 统一执行器。

## 3. 最小结构

```text
CPU profile ── CPU 模型 + 总线适配 ──┐
                                     │
IP profile ─── IP 模型 + 总线适配 ───┼── 单进程 C++ 执行循环 ── RAM
                                     │          │
DMA profile ── DMA 模型 + 总线适配 ──┘          ├── 地址路由 / IRQ 交付
                                                └── 少量结果 / 可选诊断
```

Python 进程只在启动时读取 profile、复用或生成模型与绑定、编译链接，并启动执行进程。执行进程在一次初始化后连续接收输入、驱动真实模型、返回结果；循环中不进行逐周期跨进程调用，也不为每个 case 重新编译或初始化。

一次最小循环的逻辑：

```text
读取下一条输入，放入 RAM mailbox 或尚未应答的指令槽
重复推进各组件：
    将 CPU 事务送到 RAM 或目标 IP/DMA 控制端口
    将 DMA 主设备事务送到 RAM 或兼容目标
    将实际 IRQ 输出送到 CPU 的声明输入
    更新必要的事务与完成观察
case 完成且上一次事务和 IRQ 已处理完毕后，输出结果并接收下一条
```

这描述的是执行次序和职责，不规定所有协议共享相同握手或时钟。初版只接受明确支持的时钟及复位组合；不能支持的配置直接报告原因，不伪造完成结果。是否保留组件状态、何时清理 IRQ、如何判断可以开始下一例，都由设备行为和实际观察决定。

## 4. profile 需要提供什么

沿用现有配置格式和组件 artifact，下面是需要表达的语义，**不是可直接运行的新 JSON schema**。

| 对象 | 必要信息 | 作用 |
| --- | --- | --- |
| CPU | RTL 来源、总线协议及端口映射、启动/复位、ISA、IRQ 输入、可用退休或异常观察 | 准备真实 CPU 并生成能运行的指令 |
| 普通 IP | RTL 来源、目标总线及端口映射、MMIO 地址范围、必要寄存器的宽度和访问行为 | 路由 CPU 的 MMIO |
| IRQ IP | 普通 IP 信息，加 IRQ 输出、极性、触发、状态读取和清除操作 | 触发、传递和消费真实 IRQ |
| DMA | 控制端口、主设备总线及端口、源/目的/长度/启动寄存器、数据宽度、完成和 IRQ 行为 | CPU 配置 DMA；路由 DMA 实际读写 |

同协议并不意味着所有设备只声明协议名即可自动运行：启动、寄存器语义、可用地址、IRQ 和 DMA 行为仍必须由组件提供。复用的是协议驱动及执行循环，组件描述不包含 CPU×IP 的组合专用逻辑。

## 5. 当前已有的原型

| 入口 | 真实验证 | 目前边界 |
| --- | --- | --- |
| `scripts/run_inprocess_irq.py` | Ibex + PULP Timer、Ibex + PULP SPI、CV32E20 + PULP Timer；Timer 在线两例 | OBI + APB；在线验证限单源 pulse、无需软件清除的 Timer 场景；其他组合不能据此推定 |
| `scripts/run_inprocess_f6.py` | Ibex + ZipDMA 在线两例；替换 DMA profile 后 Ibex + wbdmac 单例 | OBI + Wishbone、对齐 32 位 RAM；在线方式依赖 RVFI、最多八个指令槽；两种 DMA 在线互换未验证 |

两条在线结果都实际观察了 CPU、设备和相应 IRQ 行为，输入预先送入管道；**尚未接入反馈驱动生成器**。F6 的 ZipDMA 测试显式使用 `--assume-lockstep`，这只是仿真推进假设，不代表硬件真实同频。两者均未要求完整证书或独立 replay。

运行结果示例在 [F5 在线结果](../runs/stage2-oneclick-20261031/f5-online-two/summary.json)、[F6 在线结果](../runs/stage2-oneclick-20261031/f6-online-two/summary.json) 和 [wbdmac 结果](../runs/stage2-oneclick-20261031/f6-wbdmac/summary.json)。观察与用时范围见后面的探索记录；原型模型执行时间不包含完整准备、构建或 replay，不能与旧系统全流程时间直接相除计算加速比。

## 6. 实施步骤

### A. 把现有 F5/F6 跑通到一个简单入口

涉及 `scripts/run_inprocess_irq.py`、`scripts/run_inprocess_f6.py`、`scripts/inprocess_build.py`、`scripts/inprocess_memory.h`。

1. 保留两个经过真实验证的 C++ 执行循环；先提供一个薄入口按 profile 和所选路径调用现有实现，复用已有构建缓存。
2. 统一输入、结果及失败输出的基本格式：包含路径、输入、实际观察和耗时；无法观察的字段标为 unknown。不要为此再建立证书生成器。
3. 分批运行现有 Timer F5 和 ZipDMA F6 两例，确认入口调用的是实际 RTL、输入各不相同、各自结果正确。单次运行结束清理临时目录，保留少量摘要和失败输入。

交付：一个调用入口能运行现有 F5、F6；此时底层仍是两个循环，不能称为 F1–F6 统一循环。

### B. 接入实际在线输入与反馈

涉及 `scripts/run_inprocess_irq.py`、`scripts/run_inprocess_f6.py`、`scripts/inprocess_f6_firmware.py`，以及实际选定的现有生成器入口。

1. 利用现有 `NEED_RECORD` 交互，将上一条的最小反馈传给生成器，由生成器再提供下一条输入；避免每个 case 重新启动模型或构建。
2. F5 继续复用已验证的 RAM mailbox。F6 优先评估能否用固定 CPU 程序和 mailbox 驱动 DMA，去掉每例生成指令和八槽限制；在替代方式通过真实验证前保留现有槽方式。
3. 用至少两条由前一结果决定的输入验证真实闭环；分别检查两次实际 DMA 数据/IRQ，不能用预先输入两条来冒充反馈闭环。

交付：真实反馈决定下一条输入，并在一个 CPU/IP/DMA 生命周期中持续运行；明确支持的 IRQ 清除和复位范围。

### C. 按协议复用并验证组件替换

涉及 `scripts/prepare_inprocess_irq_bindings.py`、`scripts/inprocess_f6_firmware.py`、`scripts/inprocess_obi_apb_irq_spike.cpp`、`scripts/inprocess_obi_wb_dma_spike.cpp` 和 `configs/scenarios/` 下的现有 profile。

1. 整理 F5/F6 中确实重复的 RAM、事务路由和 IRQ 处理，保留最少的协议适配函数；不提前建立插件注册、通用调度框架或虚接口层。
2. 用第二颗已适配的 OBI CPU 跑 F6，用第二个 DMA 跑在线 F6；F5 选择另一颗已声明行为的 IRQ IP 运行在线多例。更换时只改对应组件 profile/行为描述；若需要改组合专用代码，记录为未达标。
3. 校验真实 MMIO、IRQ、DMA 数据及连续 case 的边界；批量验证这些代表组合，再集中修正问题。

交付：至少两颗 CPU、两个 IRQ IP、两个 DMA 在各自适用的路径上有真实验证；结果须列出精确组合，不把未运行的笛卡尔积宣称为已通过。

### D. 把 F1–F4 接入同一执行过程

参考现有 `compiled_mmio` 的协议和固件生成实现，复用 F5/F6 的宿主 RAM、路由和模型生命周期；先支持 OBI + APB 代表组合，再逐协议扩展。

1. 让同一已初始化的 CPU、IP、RAM 接收 F1–F4 输入并观察真实取指、读写；F5、F6 继续按组件能力启用。
2. 对一个支持全部所需能力的 CPU + IRQ IP + DMA 组合执行 F1–F6，确认数据来自真实组件且没有组合专用分支；先用固定输入，再用在线输入。
3. 对同一协议替换 CPU 和 IP 分别验证；支持情况按组件、协议、实际路径列明。清理明确被替代且不再使用的旧原型代码，保留仍有用户或复核价值的旧执行入口。

交付：同一进程提供 F1–F6，组件通过独立 profile 接入；不支持的协议、ISA 或设备行为有明确结果。

### E. 测量并优化

分别记录准备/构建、模型初始化、稳定运行、输出写盘的时间、内存和产物大小；比较时固定 CPU/IP、输入数量、缓存状态及观察范围。优先优化启动、生成和事件记录中测出的热点，让长时间运行主要花在 DUT 推进；不以省略真实握手为代价。完整证书和 replay 只在需要离线复核时单独运行。

## 7. 当前命令与批量验证

下列命令使用仓库中现有接口；实际首次运行需要对应 RTL、Verilator 和现有组件准备依赖。`--output` 应指向新的运行目录。F5 的三个数字是 Timer 示例所需的触发值，F6 是 8 字节十六进制输入；`END` 结束在线会话。

```bash
printf '0,0,0xffffffff\n1,0,0xfffffffe\nEND\n' | \
  python3 scripts/run_inprocess_irq.py \
    --config configs/scenarios/inprocess-irq-pulp-timer-profile.json \
    --cache runs/prototype-cache-f5 --output runs/prototype-f5-online --online

printf '0110c00008000000\n0530c00110000000\nEND\n' | \
  python3 scripts/run_inprocess_f6.py \
    --config configs/scenarios/shared-dma-profile-examples/ibex-zipdma-profile-only.json \
    --cache runs/prototype-cache-f6 --output runs/prototype-f6-online \
    --online --assume-lockstep
```

检查 `summary.json` 和 `run.log` 中各 case 的真实观察与退出状态；这两条命令本身不证明反馈闭环或完整通用性。快速回归：

```bash
PYTHONPATH=src:. python3 -m pytest -q \
  tests/integration/test_inprocess_irq_online.py \
  tests/integration/test_inprocess_irq_entry.py \
  tests/integration/test_inprocess_irq_bindings.py \
  tests/integration/test_inprocess_f6_direct.py \
  tests/integration/test_inprocess_f6_binding.py \
  tests/integration/test_inprocess_build.py
```

远程测试遵守 [agent.md](../agent.md)：跳转机只转发；目标机文件操作限定 `/root/fanzehui`，临时目录也放在该范围内，结束后核对路径并清理本次临时产物。模型缓存和有用的少量结果按需保留。

## 8. 参考材料

- [精简设计和当前原型状态](stage2-lean-design-20261031.md)：F5/F6 的背景、约束和后续顺序。
- [F5 单进程探索记录](reports/inprocess-irq-spike-20261031.md)：真实信号、模型及单次实验口径。
- [F6 单进程探索记录](reports/inprocess-f6-spike-20261031.md)：DMA 事务、在线与批量实验及其限制。
- [整体分阶段路线图](universal-system-roadmap.md)：F1–F6 定义、第一阶段已有协议和验证矩阵。
- [宿主开销分析](reports/host-overhead-profile-20261030.md)：旧路径性能瓶颈。
- [F5 Timer 配置](../configs/scenarios/inprocess-irq-pulp-timer-profile.json)、[F5 SPI 配置](../configs/scenarios/inprocess-irq-pulp-spi-profile.json)、[F5 CV32E20 配置](../configs/scenarios/inprocess-irq-cv32e20-pulp-timer-profile.json)：组件替换示例。
- [F6 ZipDMA 配置](../configs/scenarios/shared-dma-profile-examples/ibex-zipdma-profile-only.json)、[F6 wbdmac 配置](../configs/scenarios/shared-dma-profile-examples/ibex-wbdmac-profile-only.json)：不同 DMA 行为的示例。
- [F5 执行入口](../scripts/run_inprocess_irq.py)、[F6 执行入口](../scripts/run_inprocess_f6.py)、[共享构建缓存](../scripts/inprocess_build.py)、[共享 RAM](../scripts/inprocess_memory.h)：当前实现入口。
