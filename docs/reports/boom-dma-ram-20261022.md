# BOOM uncached shared-memory CPU-programmed DMA

## 当前状态

BOOM 本地固定场景原生门 **exit 0，正例和 stale-key 两条分支均完成 first/fresh**；独立原生数据流审计与输入归档审计通过。结论只覆盖本报告定义的 uncached 四字 DMA cell；六 CPU／四 IP、P6/P7/P8 和通用同协议接入仍开放。

[原生 attempt 终态和完整保存记录](evidence/boom-dma-ram-20261022-task5-attempt2/attempt-be77b5eef02548dbb28676a6ff4ce510/verification.json.gz)、[worker 收据](evidence/boom-dma-ram-20261022-task5-attempt2/attempt-be77b5eef02548dbb28676a6ff4ce510/worker.json.gz)、[独立完整数据流审计](../../.superpowers/sdd/task-5-boom-native-independent-audit.md)、[独立输入归档审计](../../.superpowers/sdd/task-5-boom-archive-audit.md)。执行 verifier SHA-256 为 `bdb8bd3a7fa71ba8f8a70c05c2f256545da080f3e073914c980d6c9e0d3a9c36`。

| 分支（first/fresh 各自相同） | CPU/DMA 配对轮次＋quiesce | CPU/DMA ticks | CPU 外部请求 | 结果 |
| --- | ---: | ---: | ---: | --- |
| positive | 515＋1 | 515/535 | 23 | status 3；源和目标 `[135,246,357,468]`；marker 1 |
| stale-key | 376＋1 | 376/396 | 14 | status 3；目标全零；marker `0xffffffff` |

正例实际 DMA 四次读、四次写，均按完整 transaction key 连接 Wishbone STB/ACK、共享内存效果、byte writer/version 与响应。stale-key 在 DMA master beat 前拒绝：没有 DMA 接受、响应或内存效果。两分支 first/fresh 均重放完整动作，完整保存记录逐字段比对一致；12 个 CPU/DMA 子进程全都以 exit 0 结束，所有 CPU/DMA/Router pending 归零。`0x4110` hole refusal 在 native 启动和任何效果前失败，前后状态相同。

## 实现边界

本门把 `0x4000..0x4fff` 的 uncached TileLink A/D 接到真实共享 `MemoryService`，并将 `0x4400/16` 控制窗接到 ZipCPU Wishbone DMA。CPU 自己写源字和 DMA 配置；host 只预置代码与清零后的目标／结果。CPU/DMA 使用同一 `PersistentMemory`。门要求 marker 的真实 D 完成、无部分 A 事务后才记录 no-edge quiesce，并保持指令/缓存 traffic 与共享数据服务分开。

实现规格与计划：[设计规格](../superpowers/specs/2026-10-22-boom-shared-memory-dma-design.md)、[实施计划](../superpowers/plans/2026-10-22-boom-shared-memory-dma.md)。构建产物有[独立 22 项 artifact audit](../../.superpowers/sdd/task-5-boom-cpu-artifact-audit.md)。

## 执行输入与保留的失败

[执行输入归档](evidence/boom-dma-ram-20261022-task5-attempt2/attempt-be77b5eef02548dbb28676a6ff4ce510/executed-inputs.tar.gz) SHA-256 为 `e38cec088333b62d6da817048cbe5aac223b85025d2fb2adfd1cd76e05dbc143`，含 1,777 个文件成员、未压缩 273,585,807 字节；成员 hash 与 freeze、worker、verdict 一致。独立审计确认 CPU binary 和所选 DMA harness 与归档身份一致。外部工具 executable bytes 未 pin；归档不声称认证外部工具。归档的两份临时 executed-program image 已不存在于当前工作区；计划文档也在 gate 后更新，故归档记录的是执行时 freeze，而非当前工作区镜像。

此前失败均独立保留：[attempt1 wrong cache path](evidence/boom-dma-ram-20261022-task5-attempt1/attempt-21a2c266d7794302a9628a6260a08e9b/verification.json.gz) 在启动任何子进程前拒绝；[attempt1 tuple/list assertion](evidence/boom-dma-ram-20261022-task5-attempt1/attempt-b6fc66305cca48f48c0c41ffae44d0ec/verification.json.gz) 已运行 positive first，但在 fresh/stale 分支前于 quiesce marker 表示比较失败。fix5 只将 marker snapshot 规范化为 `plain()` 形式，没有放宽断言；该 SHA 经过两份独立静态审查后才执行最终门。

本切片不证明 coherent C/E DMA、TileLink B/probe、任意部分传输 quiesce、物理 SRAM/总线桥、IRQ/ISR、CPU retirement、通用 F6/D4 或 P6/P7/P8 完成。
