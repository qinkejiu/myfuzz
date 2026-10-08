# P2 Task4.4 真实退休、UART帧与交易见证

日期：2026-10-06。P2/Task4仍部分完成；本轮接入真实Ibex RVFI、冻结响应与退休交易匹配，以及UART action/frame和实际RX采样。完整寄存器/FIFO/IRQ双向因果闭环仍待验收。没有暂存或提交。

## 实现与边界

- 新 `ibex_rvfi_local` profile 使用固定官方RVFI宏，版本化wrapper完整认证并flatten全部44字段，包括cap类型与两个320bit计数数组。旧profile/default保留；在线run可显式 `--cpu-retirement`，replay从已验证保存身份选同profile。没有修改第三方RTL。
- CPU `cpu_events` 保存真实post-rising valid/order/PC/insn/寄存器及内存观察、真正消费的instruction response与冻结ByteCell版本/kind、数据accept/response完整TransactionKey和raw/aligned地址。response先于同沿retire进入匹配；reset/restart真实推进epoch，已取消MMIO不当作执行。
- `CpuRetirementMatcher` 按execution/component/epoch和连续order/分通道sequence有界匹配；case标签不清状态。匹配RV32I LUI/ADDI/NOP/LW/SW/SB、CPU实际数据交易队列head、response完整key与enabled lanes；支持非对齐两beats。真实pinned Ibex的非memory rmask残留结合opcode解释。C/JAL/CSR/trap仍明确observation。有效bootstrap冻结响应可匹配交易且保持unknown来源；只有四字节实际INSTRUCTION_SOURCE才输出可登记action refs。同PC不同writer/kind/version、漏响应/order/sequence与容量驱逐保留ambiguous。缺失字段/错误channel/地址或快照不一致、unsupported或unresolved退休memory和trap会形成certainty barrier；advanced真实reset才能恢复自身scope，flush不擦除序列/历史屏障。默认256容量驱逐后的降级未消除，不宣称长程完整归因。
- Runner逐项排出原始CPU/source流并追加accepted-only来源见证，保留原始source/case和实际transaction。scope明确只证明退休指令字节来源，不能把rs1/rs2操作数、返回数据或IRQ归为相同源。原始retire和普通MMIO/localoutput仍不从最新fetch推断来源。
- UART保留独立action/frame、被冻结byte和clocks的8N1位边界、真实cio_rx pre/post样本与parsed receipt sequence，缺tick/错误level/peer schedule改动都不能报告matched。reset取消未完成帧并保留旧prefix。frame完成只证明物理驱动，FIFO origin保持unknown。
- UART原session证据保留真实parsed transport UUID；Runner在detached语义日志中按每component首次遇见顺序映射逻辑driver进程scope，保持sequence和跨case/重启区分，避免随机nonce导致fresh replay不同。完成与取消记录均转换；不更改实际transport nonce或协议。

## RED/GREEN 与独立审查

先复现再修复了：缺失stream排出/配置hook、frame与instruction action冒认、跨component scope误配、snapshot bytes不能JSON、无界order去重、freshprocess/reset epoch重复增加、同PC未知response被跳过、bootstrap未知来源污染其他PC、未配对bootstrap交易阻塞FIFO、instruction/data/order缺口、非法标量遮蔽失败、UART冻结byte/clock/缺tick、receipt随机UUID及cancel前缀。

独立replay审查另复现historical无manifest回放被破坏，以及真实manifest末尾换行使raw/canonical哈希错比。已保留初次失败材料，修复用envelope artifact的raw文件哈希绑定再读取，legacy只在原verified identity=None路径使用旧profile。没有跳过身份检查。

## 验证

最终当前源码整合 **503项/112.015秒，OK(skipped=6)，退出0**；实际Rust运输 **16项/1.688秒，退出0**。完整命令见[最终整合转录](../../.superpowers/sdd/current-dataflow-p2-task4-retirement-root-event-contract-regression.txt)。跳过项不计实际RTL证据。

| 门禁 | 受限在线RFuzz | 原始证据与匹配 | 完整前缀fresh replay |
|---|---|---|---|
| [Ibex＋双PULP GPIO](../../runs/current-dataflow-p2-retirement-20261006-pulp-event-contract/gate_commands.json) | 120 complete，CPU16/IP104；实际搜索20.416676482秒达到120例上限 | 63,756事件，224admission，565跨例来源观察；1,407退休逐项44RVFI核对、2,254实际响应；164accepted，其中50有typed instruction引用、114来源unknown；1条fuzz SW关联实际GPIO A MMIO完整key | run/replay退出0，matches=true |
| [Ibex＋OpenTitan UART](../../runs/current-dataflow-p2-retirement-20261006-uart-event-contract/gate_commands.json) | 2 complete，CPU1/RX1，另含已记录bootstrap；实际搜索2.188566719秒 | 15,879事件，4admission，3跨例观察；160退休、181实际响应；154accepted，其中typed5、unknown149；2帧各320真实pre/post样本，FIFOunknown，typed MMIO0 | run/replay退出0，matches=true |

GPIO最早容量barrier在event9093；256容量后的1,662条显式不完整记录、978 ambiguous没有被提升为known消费。80条accepted memory关联均在barrier前；typed SW是event1057，PC0x1100c，TransactionKey data/source_sequence7，对应GPIO A acceptance1016/delivery1023及实际目标请求/响应。它只证明指令字节与真实执行效果，不证明rs2数据taint或后续IRQ因果。UART没有capacitybarrier；两帧分别是bootstrap5a与fuzz4e，logical driver scope跨case保持local-driver:uart:1。

最终envelope：GPIO `337797ae50b34eed27dfe7542aaaade325159b93a487f61f5b23afa0eb1dfd6b`；UART `3ac7540f2e8d402c6c10b1540cdcc1235a29143b839573ca938065c669957901`。独立原始证据审计零错误：[审计报告](../../.superpowers/sdd/current-dataflow-p2-task4-retirement-final-audit.md)、[机器摘要](../../.superpowers/sdd/current-dataflow-p2-task4-retirement-final-audit-summary.json)。GPIO339/UART387捕获source各自符合当前文件；335共同路径摘要一致，组件独有文件分别保留，不能要求所有文件相同。

早期 `-pulp`、`-pulp-final`、`-receipt-scopes`、`-pulp-memory-barrier` 保留各自原closure/摘要，最后两目录 `-event-contract` 才是最终字段/取消/重归属屏障修复后的门禁。审计使用各原保存trace，不用新算法重算提升旧证据。两个当前短跑不是25/8秒持续门禁或10分钟性能验收。

CPU独立真实RTL：分支冲刷/跨word32bit/压缩观察、非对齐双beat/load、explicit reset/freshprocess epoch、pending MMIO取消通过。UART独立真实RTL：相同byte两action帧、逐bit真实采样和13tick后reset取消、新epoch帧通过。单worker/-j1，源变化时build guard拒绝的中间运行未算门禁。

模块报告：[CPU探针](../../.superpowers/sdd/current-dataflow-p2-task4-ibex-retire-probe-report.md)、[退休匹配](../../.superpowers/sdd/current-dataflow-p2-task4-cpu-retirement-report.md)、[UART帧](../../.superpowers/sdd/current-dataflow-p2-task4-uart-frame-report.md)。

## 后续验收

尚须显式GPIO寄存器语义、写提交到输出/绑定接收和IRQ状态的实际证据；UART实际RX/FIFO push/pop、错误/清除、RDATA ACCESS关联与nativeIRQ sampled/taken；producer/delivery/consumer的完整资源链反馈和定向断线/错epoch/版本负例。单条源指令到MMIO或帧驱动不能替代完整双向闭环。10分钟、校准、持续搜索和P3～P8仍未完成。
