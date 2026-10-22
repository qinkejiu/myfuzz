# P8 S1c：DMA UART RX 标量实测与保存数据独立审计

2026-10-18 在远端新工作集上完成一次标量测量；本报告记录这次运行及其保存数据审计。测量未重跑，旧失败尝试和原始产物均保留。

## 结果

- 远端测量操作记录为 `completed`、exit 0，使用测量脚本 SHA256 `91eb4652ce81aa2dbddc4da200f9b90f26dd2bebdd2d4ffd5bc98cf9d793f8ee`，输入字节为 `[0x5a, 0x00, 0xa5, 0xa5]`。四例均完成，诊断 `phase=complete`、`error=null`。
- 复制映射对应 root HEAD `269717b7e9cc7c92da5e427ac950bc82446b3ac6`；计划与实际 copy receipt 的固定 SHA 均匹配，项目映射为 28,302 文件/3,242 目录，采集期 before/after 映射一致。此处验证的是保存映射关联，不是本地独立重散列全部项目文件字节。
- 本地纯标准库保存数据审计 exit 0，状态为 `partial_scope_verified_open_checks_remain`；审计器 SHA256 `c45915ffd3852eaa9eeed2e36e46236a7cd5273ef4ac0470c183414149a196c8`，其八进制 tar 字段及偏移边界实现经另一审阅者静态复核。它解析了 SHA256 为 `e79cc4163e3a3a556af81945cea9486771ac81dce7f6d85d5d990bfccb41ad41` 的只读归档，共 771 个成员，并关联本地采集收据、远端进程链、固定计划/复制收据、来源映射及原始结果。
- 独立重算得到 29,636 个事件、4 个已完成 case、4,776 条逻辑计划命令；CPU/DMA/UART 本地 tick 分别为 1,316/1,396/3,496，UART raw tick samples 为 pre/post 各 3,496，UART tick observations 为 3,488。四个 case 的事件区间为 `[185,7557)`、`[7557,14922)`、`[14922,22279)`、`[22279,29636)`。审计器逐例关联 UART 帧、FIFO 读、DMA 写、CPU 读、IRQ、状态轮询及完成写，并重算 case 前缀摘要。
- 保存的 timing 报告给出 whole-runtime wall `213.607s`、import `2.244s`。wall 包含运行时启动、构建、执行与收尾。命令观察回调合计 6,181 次／15.232 秒；这不是线上的命令数、ACK 数、字节数或独立传输耗时。CPU delta 也不能作为 native-only CPU 成本，因为 waited-descendant 可能包括编译子进程。

## 未关闭的验收项

- 此实测没有 fresh 对比、失败重放或独立原 DUT exit 收据；FIFO 来源仍为 `unknown`，证明级别仍为 `bounded_historical_chain`。
- 保存事件无法重建命令回调次数/耗时的语义；没有 wire command、ACK、wire byte、steady-state-only wall 或 native-only CPU 指标。没有测得 5×，也没有证明 UART 批处理正确性。
- 远端 project/cache 仅保存映射，未归档主体字节，故不能离线重新散列全部文件；保存映射也未包含 `nlink`。完整 generated build identity 与原始 DUT 独立退出状态未能从本证据重建。FAN 目录外工具的可执行文件字节未采集，只保留历史 manifest/映射和明确的排除边界。
- 因此本次只确认“一次有界标量运行及其保存结果结构和链路”，不关闭 batching plan Task1，不授 P8 S1c 5× 或 P8 整体验收。Task1 的 fresh/失败重放、steady-state/build 分离和传输归因仍待完成。

## 证据索引

- [远端只读采集归档](evidence/p8-scalar-measurement-attempt1-20261018/actual-remote.tar.gz)，SHA256 `e79cc416…41ad41`。
- [本地采集终态](evidence/p8-scalar-measurement-attempt1-20261018/capture-terminal.json)、[采集输入前后核对](evidence/p8-scalar-measurement-attempt1-20261018/capture-local-inputs.json)。本地采集脚本 SHA256 `725a1d5783a29c32bcebe50b6430efcbcfde949c573911f95128432604b29449`；远端只读采集脚本 SHA256 `6b7b9ba61bc785b78784b00f9be486218369cc96f403731073f4fc69820dc722`。
- [独立审计 JSON 输出](evidence/p8-scalar-measurement-attempt1-20261018/saved-audit.stdout)、[审计终态与 argv/stream pins](evidence/p8-scalar-measurement-attempt1-20261018/saved-audit-terminal.json)、[审计 stderr](evidence/p8-scalar-measurement-attempt1-20261018/saved-audit.stderr)（空）。本地保存审计器源码位于 `.superpowers/sdd/p8-scalar-20261018/attempt1-control/audit_scalar_run_saved.py`；其执行包装器及 SHA 记录在证据目录。
- [标量测量源码审查](p8-s1c-scalar-measurement-review-20261018.md)、[原始脚本与依赖准备记录](p8-scalar-remote-dependency-20261018.md)。
