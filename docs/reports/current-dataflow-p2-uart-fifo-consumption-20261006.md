# P2 UART FIFO 实际消费链（2026-10-06）

状态：UART 的物理接收、FIFO 留存、实际路由读出子任务通过软件、真实 RTL、在线及完整前缀 fresh replay。整体 P2 仍部分完成。

## 实现与身份

独立 `configs/peripherals/opentitan_uart_fifo_local/` profile 和 `--uart-fifo` 选择认证的 154 个被动探针；原 UART profile 和历史帧的 `fifo_origin=unknown` 保持原含义。官方 OpenTitan 固定版本 `fca045df919a26c47e71616b9dac917b1ea4fd07` 与本地 wrapper 未改写。实际逐 tick 引脚、接收器状态、FIFO 指针、TL-UL 请求和响应构成消费凭据；后续来源证明追加，不改写旧证据。可独立配合 `--cpu-retirement`。

Runner 传入真实 SourceAdmission Registry、编译后的 ownership 与 RuntimeEdgeIndex，绑定完整 TransactionKey、实际设备窗口和 command/tick/event ID。缓存及消费模型严格拒绝 bool/int/float 身份替换；旧 v1 host 清单恢复历史 34 项，新语义由 v2 来源闭包认证。新变体认证编译参数不包含 `SIMULATION` CDC 随机化。

## 冻结源码门禁

| 门禁 | 结果与证据 |
|---|---|
| 软件回归 | 738 passed，13 skipped，759 subtests，263.78 s；[日志](../../.superpowers/sdd/current-dataflow-p2-uart-fifo-software-gate.txt) |
| 真实 RTL | 2 passed，182.24 s，exit 0；[日志](../../.superpowers/sdd/current-dataflow-p2-uart-fifo-real-final-gate.txt) |
| 同字节独立来源 | 两个 `0x5a` 帧保留不同 FIFO entry、action 和 admission；2 条留存、2 条读出证明，最后空读取为 0；新进程全部记录相等 |
| 满 FIFO | 65 个实际接收完成，64 项留存及读出证明；第 65 帧产生深度 64 的溢出且无留存；最后空读取为 0 |
| Ibex 在线 | 4/4 complete，CPU 源 1、RX 源 3；搜索 19.598802747001173 s，完整前缀 fresh replay 匹配；[日志](../../.superpowers/sdd/current-dataflow-p2-uart-fifo-online-gate.txt) |

在线完整日志为 `runs/current-dataflow-p2-uart-fifo-20261006-online/online_final_trace.json`，SHA-256 `b28b95a3c215425abc2abaeb28598e9029dd7f6f688480db2628ec926e79a555`。36,258 个事件包括 5,080 个实际 UART tick、4 次接收完成、4 次入队和出队，以及 4 次真实 RDATA ACCESS；追加 4 条 FIFO 留存和 4 条读出证明，其中每种证明分别包含 1 个 bootstrap、3 个 fuzz_source。来源路径由实际 index/owner 认证，尚不表示整条 CPU ISR 路径已实现。未观察到 UART 消费不完整或容量 barrier。

定向文件 `runs/current-dataflow-p2-uart-fifo-20261006-directed/uart-fifo-equal-cross-case.json` 的 SHA-256 为 `64261624f5281d7c8022d23680eae09bf647b09e5fa8c46caf1d39598a607c59`，归一化完整原始前缀哈希为 `224a313f845c4818569528de72c5f05f58e09bcf63ec01b17c309b9342965d25`。[独立审计](../../.superpowers/sdd/current-dataflow-p2-uart-fifo-actual-independent-audit.md)确认 canonical 来源字节、320 个逐 tick 驱动凭据、10 个实际位采样、独立 FIFO 身份与精确请求/响应。定向 fixture 使用真实 Registry/ownership，未编造 RuntimeEdgeIndex，所以该 fixture 的 path_id=None、graph_path_certified=False；在线门禁使用实际 index。

首次真实门禁因 fixture 跳过 RDATA 结束事件而失败，导致下一读取作用域未关闭。只修 fixture 的事件投递后重跑通过；[首轮失败日志](../../.superpowers/sdd/current-dataflow-p2-uart-fifo-real-gate.txt)保留。正确验证 unknown 来源不会污染 FIFO 状态，也不能事后登记回溯升级。

## 范围与剩余工作

公开 driver 策略实际验证固定 8N1、无 filter/loopback/parity 的模式。clear、错误帧、同 tick push/pop 等角落有软件模型测试，本轮没有新增这些模式的真实 RTL 门禁。65 帧的完整证明在实际测试中断言，未单独保存 64 条证明文件；定向保存文件包含筛选后的原始记录及完整前缀摘要，不能仅用筛选文件重算完整摘要。

默认有限模型保留最多 256 项帧/来源历史，累计超过该范围会保守降级；该门禁不证明无限长 campaign 或十分钟性能。generic runtime JSON schema 当前没有 UART session 分支，该在线路径实际由严格 Python 身份与 replay 合同校验。

实际 UART 读出证明绑定 CPU 路由交易，但尚未贯通 CPU 操作数或退休指令消费来源；原生 IRQ cause 记录仍是观察，CPU taken 与通用 ISR 来源闭合待实现。P3 反馈、P4 效率、P5 受控错误、第二/第三阶段和 DMA 不能据此标记完成。
