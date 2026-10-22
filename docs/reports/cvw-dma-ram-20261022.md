# CVW CPU-programmed DMA RAM：本地有界原生门

## 当前结论

本地原生 attempt1 已实际终态 exit 0：正例、错误 key 及各自独立完整 fresh
全部通过门内断言。六 CPU／四 IP 与 P6/P7/P8 总目标保持开放。

证据：[worker 命令与终态](evidence/cvw-dma-ram-20261022/native-attempt1/process.json)、
[原始日志](evidence/cvw-dma-ram-20261022/native-attempt1/native.log)、
[原生记录目录](evidence/cvw-dma-ram-20261022/native-attempt1/gate/attempt-f84d3e8899f14fbaa00411bdf581f01a/)。
实际时间 139.83 秒；本机单 heavy-worker、单任务编译，没有远端操作。

| 分支（first / fresh 相同） | schedule steps | Runner events | CPU / DMA ticks | 结果 |
| --- | ---: | ---: | --- | --- |
| positive | 618 | 2652 | 309 / 333 | status=3，四字回读正确，marker=1 |
| wrong-key | 588 | 2608 | 294 / 314 | 目标四字为零，marker=0xffffffff |

正例恰好四次 DMA master read、四次 write；CPU 源字为
`0x135,0x246,0x357,0x468`。负例 master 事务为零。各分支均检查原生
CPU 控制请求、Wishbone STB/ACK 与 master response、writer/version 来源、
目标回读和完整规范化事件前缀。每次终态 CPU/DMA pending=0，八个原生
进程各自 exit 0；fresh 使用不同进程与 execution IDs。

保留 [1113 个实际输入文件的字节归档清单](evidence/cvw-dma-ram-20261022/native-attempt1/executed-inputs.json)，
所有成员逐一对照本次 input-freeze 摘要核验；归档 SHA256
`63afe91226303e843d55f736955015ffbd6b2d89cd6d6daaf4aec48e91907bfe`。
这不是完整 elaborated source closure 或外部工具字节认证。

## 实现

- 固件：`src/myfuzz/scenario/cvw_dma_example.py`。CPU 写四个源字，配置真实
  ZipCPU DMA 的 source/destination/length/start，轮询 busy/error，比较目标和源，
  将状态、目标数据和成功／失败 marker 写回 RAM。错误 key 为 `0x3db`。
- 组合：`src/myfuzz/scenario/cvw_dma_runner.py`。使用既有 AHB CPU session、
  Wishbone DMA session、Router 与 ScenarioRunner；没有修改通用协议层。
- RAM 固定为 `0xc0000000..0xc000ffff`，DMA 控制窗口为
  `0xcfff1000..0xcfff100f`。Host 仅预装 512 字节代码、零目标与零结果；
  源区由 CPU 写入。没有为 CVW 添加 IRQ 输入或绑定。
- 构造失败时按相反顺序清理已创建的 session，并保留原始异常。
- 原生证据入口：`scripts/verify_cvw_dma_ram.py`。使用仓库既有 heavy-worker
  互斥锁与独立 attempt 目录，准备正例和错误 key 各自的完整 fresh 调度，
  保存原始事件、身份、进程退出码与失败诊断。该入口已按本报告 attempt1 执行。

## 实现阶段的检查记录（原生运行之前）

固件子任务此前报告的软件解释器检查为 13 passed；解释器中的 DMA 是软件模型，
不能用来证明真实 DMA。该结果不是当前组合运行器或 native 链路的验收结果。

运行器独立静态审查未发现构造范围内的问题；实际启动、调度与来源联结仍待
native 证据。内部交接记录在 `.superpowers/sdd/cvw-dma-*-report.md` 与
`.superpowers/sdd/cvw-dma-*-review.md`。本轮没有执行 RTL、构建或远端操作。

验收入口审查期间已补齐无条件进程清理、失败落盘、非空进程终态检查、
DMA master response 联结、控制 STB 实际地址／数据与 ACK、完整 CPU transaction
key 和 writer/version。AHB 读事务可能保留先前写数据；控制读 STB 使用实际
control receipt 的值比较，不假设其写数据为零。身份文档在 UUID 规范化前
精确比较。输入摘要只覆盖列出的声明文件，不声称完整 elaborated source closure
或外部工具字节认证。AST 解析完成，未运行该入口或新增运行验收。

## 原生验收依据

按照[设计](../superpowers/specs/2026-10-22-cvw-dma-ram-design.md)和
[计划](../superpowers/plans/2026-10-22-cvw-dma-ram.md)保存正例、错误 key 与
各自独立 fresh 的完整调度、原始事件、精确 artifact 身份和进程终态。
必须联结 CPU 源写入、DMA 读快照 writer/version、四次控制写的 STB/ACK、
四次 DMA 目标写与 CPU 目标回读，且终态响应全部排空。

本切片是独立真实 RTL 进程通过软件内存服务进行的事务级组合；即使后续门通过，
也不证明物理总线桥、物理共享 SRAM、全局 SoC 时钟、CPU retirement、IRQ/ISR、
通用 D4/F6 或持续反馈 fuzz。

## 最终静态复审

原生入口运行前经独立静态复审，所审范围无剩余 Critical/Important 问题；脚本 SHA256
为 `345823cc98a51ffc1b8034ce9df5c476be6cfba205c5c874daeedd2e83a5ed9d`。
这只支持代码审查结论，不支持 RTL 或 fresh gate 通过。固件和运行器也已各自
获得独立静态审查。上述静态审查之后已执行本文 attempt1，实际终态见首节。

## 独立原生证据审计

[独立审计 PASS](evidence/cvw-dma-ram-20261022/native-attempt1/independent-review.md)：
逐项重算事务、响应、全字节 writer/version、1113 个输入与归档成员哈希，
两组完整规范化前缀一致。额外检查各正例 72 条、负例 78 条物理 AHB
completion observation；均 HRESP=0，实际源与控制写匹配。物理 AHB 观察
仍为 observation-only／native_transaction_key=null，不授予新的通用事务凭据。

[未启动 fixture 检查](evidence/cvw-dma-ram-20261022/native-attempt1/fixture-check.json)
确认进程未创建、tick=0、源区未初始化、仅 552 个预装字节、精确控制窗口与
共享内存；注入 Runner 构造失败后按 cpu→dma 清理，未执行原生命令。

下一项 CPU DMA 缺口优先 VexiiRiscv：先让已有 reduced-AXI queued MMIO
通过标准 Runner 发现并消费同一个 Router，再复用 CPU 编程／轮询／多字
RAM 回读链。CVA6 的 64 位 lanes／cache visibility 和 BOOM 的 coherent
backing memory 共享契约分别需要额外实证；现有 CPU/IP/IRQ 报告不能补足 DMA 格。
