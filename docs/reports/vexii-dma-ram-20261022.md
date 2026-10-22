# Vexii CPU-programmed DMA RAM

## 当前状态

本地原生 attempt3 **实际 exit0／52.51秒**，正例与错误key各自完整独立fresh
通过门内全部断言。独立原生证据审计PASS，六CPU／四IP与P6/P7/P8仍开放。

[实际命令／终态](evidence/vexii-dma-ram-20261022/native-attempt3/process.json)、
[原始日志](evidence/vexii-dma-ram-20261022/native-attempt3/native.log)、
[完整原生记录](evidence/vexii-dma-ram-20261022/native-attempt3/gate/attempt-3a1b13c3ed9944219a79acd5e9661a0a/)。

| 每次运行（first/fresh相同） | steps＋quiesce | events | CPU/DMA ticks | 结果 |
| --- | ---: | ---: | --- | --- |
| positive | 354＋1 | 1927 | 177/201 | status3，四字正确，marker1 |
| wrong-key | 260＋1 | 1343 | 130/150 | status3，目标全零，markerFFFFFFFF |

正例四次DMA读、四次写；两分支各自完整fresh前缀一致。八个DUT进程均exit0，
CPU/DMA pending及Router队列全空。每次显式quiesce在真实marker写入后发生，
所有排空边仍在完整动作列表中。MMIO接纳关联CPUstep，delivery和真实控制
STB/ACK关联实际调度DMAstep，非host未记录的手动drain。

执行脚本SHA256为
`1ef936b0fde9f0ec9b4fce2f8dd9dce7eeff969680913b7d7c9918de6a5e59c1`。
[输入归档核验](evidence/vexii-dma-ram-20261022/native-attempt3/executed-inputs-verification.json)
确认896个成员与本次freeze逐一匹配，包含实际脚本、生产代码、选定RTL与
source-lock校验器／中央lock／closure／认证输入；归档SHA256为
`b00ca19343bce20364cb7f267810c53c8142f1c26d419403c389416919fd9640`。
该范围不等于完整elaborated closure或外部工具字节认证。

## 实现范围

- pinned cacheless32 reduced-dual-AXI Vexii（非 IRQ profile）与 ZipCPU DMA，
  标准 ScenarioRunner；`router` 只读属性暴露同一个 `mmio_router`，旧 API
  和身份文档保持原样，Runner 无 CPU 名称分支。
- 共享 host RAM `0x80000000..0x8000ffff`；MMIO `0x40000000..0x4000000f`。
  Host 仅预装 512 代码＋16 零目标＋24 零结果字节，CPU 写源和配置。
- RV32I 四字 DMA 固件生成器按地址布局参数化；CVW 四种 key 镜像独立
  对照之前执行归档逐字节相等，Vexii 只改变四个地址 LUI。显式拒绝
  非页对齐、越界、重叠布局和超出该四字固件编码范围的参数。
- 源／目标／结果为 `0x80001000/0x80002000/0x80003000`，源字
  `0x135,0x246,0x357,0x468`，valid key `0xfed`，负例 `0x3db`。

## 软件接口检查

[检查记录](evidence/vexii-dma-ram-20261022/software-fixture.json)确认未启动、
源区未初始化、552 字节预装、精确注册窗口、共享内存和空 IRQ bindings；
注入 Runner 构造失败后逆序 cpu→dma 清理并保留原始异常。排队后 Runner
发现一个 DMA target request，目标步计时上界由 1 变为 33；取消该 ledger
请求后回到 1，未执行 callback 或原生命令。这不是 RTL 证据。

## 原生验收入口

`scripts/verify_vexii_dma_ram.py` 记录完整 dma/cpu actions，真实 marker 后
必要时显式 CPU begin_quiesce，再记录所有排空边；总上界 4000 轮。检查
AXI 分离 AW/W、B 与 AR/R 的完整 transaction key、控制 STB/ACK、DMA
master response 和 RAM writer/version；两分支各有完整独立 fresh。
执行时使用唯一 heavy-worker 锁、独立 attempt、精确输入字节归档和失败收据。

[设计](../superpowers/specs/2026-10-22-vexii-dma-ram-design.md)、
[实施计划](../superpowers/plans/2026-10-22-vexii-dma-ram.md)。六 CPU／四 IP
和 P6/P7/P8 总门仍开放；物理桥/SRAM/全局时钟、IRQ/ISR、retirement、
通用 D4/F6 或持续搜索均不在该切片结论内。

## 保留的原生 attempt1 失败

[worker 终态](evidence/vexii-dma-ram-20261022/native-attempt1/process.json)为
exit1／36.92 秒。CPU 与 DMA 各4000ticks、8000steps，CPU实际写完四个
sourcewords，但没有 MMIO 接纳或 DMA master 事务；result与destination
保持零，两进程各exit0、无capture/cleanup错误，未计为通过。

根因是初始 DMA 地址0x40002000不在已生成 CPU 的 PMA 中。实际 pinned
`VexiiRiscv.v:4557` 只允许 RAM0x80000000/1MiB 和 MMIO0x40000000/4KiB；
`generated/manifest.json` 的 generation_command 同样声明该页。故 CPU
在首条 MMIO store 之前拒绝访问；记录仅能证明没有外部请求，不声称
此处测到了内部 trap 语义。将布局纠正为0x40000000的16字节窗口后重跑；
不修改 CPU RTL/profile，不扩大4000轮，不改变通过断言。旧输入归档保留。

## 保留的原生 attempt2：硬件正例完成，脚本退出1

[终态](evidence/vexii-dma-ram-20261022/native-attempt2/process.json)为 exit1／25.45秒。
校正PMA地址后，positive first/fresh 均实际完成：354steps＋一次显式quiesce，
1927events，CPU177／DMA201ticks，result=`[3,309,582,855,1128,1]`，
pending/Router队列为空，四个DUT均exit0。保存的身份文档精确一致，完整
规范化前缀独立比较一致。但 worker 在正例断言处失败，没有执行 wrong-key，
因此仍不计为完整原生门通过。

失败位于 writer_event_ids 比较：实际 MemoryService 保留 tuple，旧门将其
直接与 list 比较；JSON 落盘转换为 list，故保存JSON重读可以通过。已使用
实际 first/fresh 恢复 live tuple 重现旧门拒绝，再以 tuple 序列比较修复
两处断言；仍要求四条完整 writer key 逐项相等，未放宽来源条件。
上述attempt2失败状态随后由独立attempt3的完整门结果取代；旧档案保持不变。

## 最终独立审计

[保存证据独立审计PASS](evidence/vexii-dma-ram-20261022/native-attempt3/independent-review.md)
逐项重算所有实际队列／调度／AXI／Wishbone／writer/version／结果提交联结，
两组完整fresh前缀一致，896个归档成员与freeze无路径或hash差异。
正例每次77个完整CPU AXI事务；status写accepted/completed ticks为111/112，
四个数据保存128/129、140/141、152/153、164/165，marker为176/177，
均在所需实际读响应之后。没有剩余所审范围内的Critical/Important/Minor问题。

后续CVA6不能只替换本固件地址：已核对其实际RV64/64bitAXI、低地址
非缓存PMA与WT合并写缓冲；需单独保持字节lane，并通过FENCE顺序及
实测阻止相邻控制写合并。BOOM仍需coherent backing RAM与DMA共享
内存的契约及真实证据。上述缺口不被本次Vexii通过抵消。
