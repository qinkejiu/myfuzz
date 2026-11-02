# 交给 DS：myfuzz 通用化框架执行任务

日期：2026-10-26。本文是执行交接，不是实现完成报告。DS在这里指后续负责代码执行的模型/开发者；需要能读写本仓库并运行命令。若使用纯聊天版本，必须由操作者实际应用补丁、运行命令后回传输出，DS不能把生成命令当成执行结果。

## 1. 先读这三份材料

1. [框架设计与接口合同](../superpowers/specs/2026-10-26-generic-runtime-framework-design.md)。
2. [逐任务实施计划](../superpowers/plans/2026-10-26-generic-runtime-ds-implementation-plan.md)。
3. [当前验收状态](../CURRENT_PROGRESS.md)及仓库根 `agent.md`。

不要先通读500份报告，也不要从项目名猜当前进度。按每个任务列出的现有模块和真实fixture定位即可。

## 2. 给 DS 的首轮提示词（可直接复制）

```text
你负责实现 /home/qinkejiu/myfuzz 的通用CPU/IP数据流运行框架。
架构和验收合同已写在：
- docs/superpowers/specs/2026-10-26-generic-runtime-framework-design.md
- docs/superpowers/plans/2026-10-26-generic-runtime-ds-implementation-plan.md
- docs/handover/DS_GENERIC_RUNTIME_TASK.md

先读这些文件、agent.md、CURRENT_PROGRESS.md，然后按计划执行G0到G6。
G0–G6是本次实现范围；G7–G10是后续扩展，不要在首轮顺便实现全部协议。

核心要求：
1. 复用已有Runner/Router/Scheduler/PersistentMemory/MemoryService/ledger/native issuer，
   不另造内存、调度器或第二套证据权威。
2. 新generic执行由经验证的协议+语义+证据能力选择，不由组件名或exact session class选择。
   适配器内部现有native ABI/issuer认证不能改为hasattr，也不能删除旧检查。
3. 第一纵向切片为OBI CPU + 两个已登记APB3 storage源合同。
   必须完成同次D2/D3→typed plan→真实provider→持久多例→完整fresh；
   在shared core中增加timer/SPI/CPU名称分支、fallback具名工厂或每例新harness均不合格。
4. 只修改当前任务允许的文件。保留当前dirty和untracked的F2/F6源码、第三方pin、
   所有失败attempt和另一个未合并native worktree。不要git reset/clean、stage-all或提交前驱工作。
5. 先写能暴露具体缺陷的测试，再实现并跑本任务门。只有实际执行的结果才能标PASS。
   软件mock不授native；缺关键依赖或native未执行时不得把skip记成通过。
6. 通过一个任务的门就按依赖继续下一任务，不反复询问是否继续。
   发生真实阻塞时记录具体缺失、命令/错误和可继续的独立工作；不降低验收标准。
7. 每任务写 runs/generic-runtime/Gx/task-report.json，保留命令、exit、日志、修改路径、hash。
   每轮回复只写完成的任务、实际结果、剩余问题和下一任务，不能靠大段旧进度宣称完成。

现在开始G0。先输出实际基线，再执行G1；不要只给“可以实现”的方案。
```

## 3. 当前工作树的事实

- 活动分支为 `codex/system-completion-20261016`，HEAD为 `4186ff565280d7d6729b010981f2741cea1d3b4c`。**大量关键F2/F6代码尚未提交**，HEAD本身不是完整输入。
- `main`与另一个 `codex/native-exact-source-completion-20261018` 分支保留。后者有独立提交和dirty工作树 `/home/qinkejiu/.codex/worktrees/7c57/myfuzz`；不要替其合并、删除或清理。
- 第一方实现/工具约34.2万物理行，测试约31.8万行；通用化重点是抽取共享接缝和减少复制，不按每个CPU/IP复制一套执行器。
- 最近整理已删除7个无调用旧代码文件，14个历史scheme脚本迁到 `scripts/legacy/`；不要按旧计划把它们补回当前入口。
- 当前报告导航为 `docs/reports/README.md`，全目录为 `CATALOG.md`；历史进度和旧报告首页在 `docs/history/`，不再向首页追加数百行流水。
- F6仍未通过完整真实门，Freeze15为4 passed/5 failed；Task8 attempt16也失败，source closure修复的软件结果不替代真实重验。
- 2026-10-26扩展整理回归为95 passed、10 failed、54 subtests passed。十项static-campaign失败在原脚本路径下同样复现，缺失 `runs/designs/ibex_opentitan_real_ip_static_projection/instrumented/sources.f`；不能以删除测试或放宽身份检查解决。
- 文档检查有121个历史失效目标；新任务要求不新增断链。不要为修链创建假的原始trace、summary或来源证明。
- 远端访问受 `agent.md` 限定：跳转机只连接，目标机所有操作限 `/root/fanzehui`。本次设计没有探测远端可用性。

以上是设计时快照；G0必须重新读取实际工作树和外部工具状态，不把本文当成实时过程句柄。

## 4. 每个任务交回什么

| 项目 | 具体内容 |
|---|---|
| 修改 | 精确文件列表和修改理由；新增模块与现有模块职责如何分开 |
| 软件检查 | 原命令、环境开关、exit、实际passed/failed/skipped；失败原栈 |
| 真实运行 | 原始CPU/IP PID/nonce、初始化次数、case/transaction数量、局部时序和退出状态 |
| 证据 | source/tool/build/binary/plan与输入摘要、raw/native/semantic refs、完整prefix及fresh |
| 负例 | 错误source/template/语义/地址/类型/身份分别在哪一层拒绝，是否已产生effect |
| 能力边界 | 本任务实际支持的protocol/semantic/ISA/IRQ/证据scope，unsupported/missing和pending |
| 后续 | 下一任务ID；不能用代码行数或测试总数代替验收项 |

源码和原始证据请留在工作区，不只在聊天里贴概括结果。每次实现任务要有可独立审阅的diff，别把无关dirty修改一起stage。

## 5. 架构审阅时的拒收条件

出现任一项，当前任务不能PASS：

- 注册表按 `ibex/pulp/zipcpu/caliptra` 或实例名直接选择工厂；仅把if搬进registry。
- 通用层通过caller传入的class/import-string/callback创建可信provider。
- 把APB3等协议当成寄存器/FIFO/IRQ语义，把storage适配器用于有副作用的未登记寄存器。
- 声称同次D2/D3绑定，实际重新构造了另一个图、另一份RAM或legacy family。
- mock/序列化receipt/最终RAM相等被当成native token、逐边来源或retirement。
- 持久会话的每例换PID、重置RAM、清空pending或隐式fresh_genomes。
- fresh只比最后结果，或正常化真实payload、版本和缺失事件以求相等。
- source/工具包未闭合、native门没执行或关键skip，却把里程碑勾成完成。
- 为跑通新组件而复制旧kernel并加入新名称分支，或者提前删除仍被旧schema/replay使用的生产路径。

## 6. 分工

框架设计由本交接及配套规格固定；DS实现、运行并交回可核查产物。发生设计冲突时列出具体接口/证据和最小调整方案，由架构审阅决定；在兼容边界内的日常实现选择自行处理。

首切片通过后，G7证明真正新增source无需改core；再逐协议/语义推进G8、F6推进G9、系统矩阵和P7/P8推进G10。不要把首切片完成说成全部系统完成。
