# 第二阶段 F5/F6：精简执行方案与原型

日期：2026-10-31。状态：原型验证中；本文件不是第二阶段完成声明。

> 时点说明：本文记录 10 月 31 日状态；后续已新增统一 F1–F6 循环及独立 F5/F6 的有限反馈。当前证据与适配边界见[系统能力盘点](current-system-capabilities-20261101.md)。

## 要解决的问题

当前 F5/F6 已有部分真实 RTL 运行，但路径装配、设备组合、事件收集、完整证据导出和 replay 交织。单次执行即可能反复扫描大量事件或生成数百 MB 产物，CPU/IP 行为和特定运行模式也容易耦合。历史测量见 [宿主开销报告](reports/host-overhead-profile-20261030.md)，不得将不同组合或不同证据范围的耗时直接比较。

目标是 CPU、IP、DMA 分别提供 profile，适配过的总线和 IRQ 机制可复用；CPU 和 IP 真实运行，宿主只模拟 RAM、总线事务路由与信号交付。初始化后尽量把时间留给 DUT 推进，同时不以压缩记录代替实际握手。

## 建议结构

```text
CPU profile ─ CPU 适配器 ─┐
IP profile  ─ IP 适配器  ─┼─ 统一执行循环 ─ RAM / MMIO / DMA Router
DMA profile ─ DMA 适配器 ─┘          │
                                    ├─ IRQ 交付（位、触发与极性来自声明）
                                    └─ 观察器：按需记录实际事件
```

1. **组件适配一次：** CPU profile 描述总线、启动、IRQ 输入和可用执行观察；IP profile 描述 MMIO、IRQ 输出和触发/清除方式；DMA profile 描述控制寄存器、主设备协议、地址/长度和完成信号。协议适配器处理真实的 valid/ready、请求/响应与错误，行为差异放在 profile，不写 CPU×IP 组合分支。
2. **同进程执行核心：** 将每个组件各自生成的 Verilator model 链接到同一宿主进程，由 C++ 执行循环持有这些独立 model、RAM 和协议适配器；不是把 RTL 接成一颗 SoC。真实总线请求仍由宿主 Router 分发，实际 IRQ 输出按声明交付 CPU。每种协议的握手、时钟和复位各实现一次；跨组件握手、IRQ、外部输入或可观测完成条件不能因批处理而跳过。不同组件仍保持独立来源和身份，但不能伪称它们是独立进程。
3. **按需要观察：** 运行时只索引对应 case 的实际关键信号、事务和完成条件，不为每个判断反复扫描所有历史；跨 case 依赖需要时保留必要上下文。分别记录事实、可复核的关联和未知项，不能从 profile 的声明直接推断设备内部因果或指令退休。
4. **两种输出成本：** 常规探索默认一次执行、少量观察与失败诊断；验收按需输出完整事件及独立新进程 replay。两者使用相同 DUT、输入和握手，不改变行为。常规结果不是离线完整证书，完整验收是否复现必须实际比较。

## F5 最小路径

从一个 CPU 和一个有实际 IRQ 的 IP 开始：CPU 通过 MMIO 执行 profile 声明的触发操作；采样 IP 真实 IRQ，按声明位/极性交付 CPU；观察真实 CPU 接受、ISR 状态读/清除以及可用的返回/退休。没有真实退休或来源证据时显示 unknown。多源组合由多个同样的声明组成，不应强制为单源再启动闲置 IP。

`scripts/run_inprocess_irq.py` 现可从 CPU/IP profile 和所声明的 IRQ/寄存器行为准备并运行真实 Ibex + Timer；CPU 写 Timer、IRQ、CPU take、ISR 读、RAM 写、MRET 和后继均有观察。同一 CPU 更换为 PULP SPI profile 和 IRQ 行为描述也已实际运行，记录到真实的两次源脉冲和一次 CPU 接受；只换 CPU profile 的 CV32E20 + Timer 也已实际运行。入口见 `configs/scenarios/inprocess-irq-pulp-timer-profile.json`、`configs/scenarios/inprocess-irq-pulp-spi-profile.json` 和 `configs/scenarios/inprocess-irq-cv32e20-pulp-timer-profile.json`，运行与构建口径见[探索记录](reports/inprocess-irq-spike-20261031.md)。当前只验证 OBI + APB 的有限组合，尚不是任意 profile 通用引擎或完整证书。

`--online` 使用固定指令轮询 RAM mailbox；CPU 自己读取输入并发起 MMIO，不修改已取指代码。目标机 `/root/fanzehui/myfuzz-stage2-f5online-20261031/runs/f5-online-two/` 的 Ibex + Timer 测试在同一进程连续处理两组触发值，各自观察到一次 IRQ、CPU take、ISR 读取及 MRET 后继续；CPU/IP 未在两例间复位。输入预先送入管道，未接反馈驱动生成器；当前只支持单源 pulse、无需软件 clear 的路径，不是完整 F5 证书或独立 replay。

现有多进程入口 `scripts/run_declared_irq_f5.py` 也增加了 `single_source` 和 `--evidence summary`；full 为原始证据模式，summary 不保存逐边沿日志，不能独立进行完整离线审计。单源原始/fresh 的语义摘要匹配，但此入口仍继承 OBI CPU 与声明式 IRQ 的限制，不能解决逐步跨进程调度。

## F6 最小路径

CPU 按 DMA profile 经 MMIO 配置源、目的和长度；DMA 真实 RTL 发起主设备读写，由现有协议适配和 Router 到达 RAM/IP；实际观察读写请求、响应、数据、完成与 IRQ。四字对齐 RAM 搬运只是原型；支持 IP FIFO、背压、其他宽度/协议和多通道时分别通过声明与真实验证扩展。

此前试验过省略大文件导出的 F6 包装入口，但热缓存下与现有搜索入口耗时都约 129 秒，没有解决调度瓶颈；该额外入口已移除。后续直接在简化的同进程执行循环中接入 DMA，而不是维护第二套包装层。

`scripts/run_inprocess_f6.py` 可从 CPU/DMA profile 配置直接准备并运行 Ibex + ZipDMA，只创建这两个组件，不再准备 GPIO 或完整 D3。示例 `configs/scenarios/shared-dma-profile-examples/ibex-zipdma-profile-only.json` 仍引用 DMA capability 文件；结果和边界见 [DMA 探索记录](reports/inprocess-f6-spike-20261031.md)。真实运行中，同一个 CPU、DMA 和 RAM 初始化一次，连续执行两组输入，分别观察到四次读写、IRQ 接收/清除和 MRET 后继续。`--online` 已在真实 RTL 上验证：未物化指令槽的取指等待期间逐条接收输入，CPU/DMA/RAM 不重置；该次输入预先送入管道，尚未连接反馈驱动生成器，且受限于八个固件槽、RVFI 和所声明时钟假设。只更换 DMA profile 和能力声明的 wbdmac 单例也已真实执行四字搬运及中断返回；这两种 DMA 有不同的中断处理方式。完整证书与 replay 均未验证。

## 性能验证和后续顺序

先对同一 CPU/IP、输入、case 数和构建缓存进行对照，记录准备/编译、执行循环、证据整理、写盘、重放、总时间、峰值内存和产物大小；记录组件步数、事务/IRQ 事件及是否 fresh，不能把冷编译与热缓存混比。真实执行结果、事务和输入相同才比较运行模式；完整 replay 不得因省略日志而改变判定。

1. 用同一程序和适用时序对照现有执行，检查实际事务及 IRQ；单次实验未包含完整证据或 replay，不直接计算加速比。
2. 继续将 F5/F6 使用的固件生成从旧大型模块中整理出来，并把在线输入接到反馈驱动生成器；不要重复构建或重新初始化模型。
3. 换一颗已适配的 CPU 和另一颗 DMA，仅修改组件声明做实际运行；先覆盖明确支持的协议、时钟和复位，不引入组合专用代码。
4. 再按真实需要扩展不同总线、多源 IRQ、DMA IP FIFO 与复位；测量准备、编译、推进和内存，删除被替代的旧路径。

流式 JSON 写出尝试和同字节 A/B 记录见 [流式证据导出报告](reports/stream-pinned-json-20261031.md)。其内存变化只针对导出分配，并非完整 F5/F6 吞吐量结果。
