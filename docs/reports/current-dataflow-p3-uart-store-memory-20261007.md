# UART SW operand → modeled host RAM byte（实施草稿）

日期：2026-10-07。**新StoreMemoryJoin冻结源码的软件门禁已通过；actual online与fresh尚未完成。** 此报告记录已确认的前置证据、旧路径修复、软件结果和待验范围；不能作为新阶段实际RTL通过证据。P2/P3整体仍部分完成。

## 目标与证明范围

目标是关联三项独立事实：此前具体UART LW产生的寄存器版本；真实退休SW以rs2读取该版本；实际安装的MemoryService callback提交的同一完整TransactionKey及host RAM低byte STORE版本。commit先到/后到、原始source proof迟到均须按exactkey/version保留有界候选，不按值相等、latest事件或时间邻近关联。

授证范围计划限定为host `PersistentMemory`低byte writer。BE15四字节写入不意味着四字节都受UART影响；其他written lanes仍unknown。RTL RAM、whole-word来源、后续RAM load、通用复制、generic ISR与P2/P3整阶段均不由本子任务认证。

## 已确认前置与旧缺口

[受限SW rs2 use阶段](current-dataflow-p3-uart-operand-use-20261006.md)有保存的4条use、48,323事件和完整fresh证据；该旧源闭包不包含本次StoreMemoryJoin，不能自动升级到新阶段。

实际callback receipt与live安装authority已在软件中验证。冻结producer stream快照`f8ed028c0db293856fba1745623be0d26f26209190adb7152437b6a4dbf5ec9c`和authority`b3f54173314c5fe038fca3dcfb78a83d14743747c4c7137cf25ada17a83b0f52`的组合为144 passed、11 subtests、0.36s；仅属于前置生产者/authority/legacy门禁，**不是StoreMemoryJoin通过**。证据：[authority软件记录](../../.superpowers/sdd/current-dataflow-p3-memory-commit-authority-software-report.md)、[callback生产者软件记录](../../.superpowers/sdd/current-dataflow-p3-uart-store-commit-software-report.md)。

旧`UartRamCommitJoin`不是纯status关联，已使用真实installed callback与raw重构，但只读审查复现生命周期缺口：raw SW/use先完成时，即使commit尚未到，候选也被pop；随后真实stage成功却不产proof，并残留commit。晚到unrelated commit也缺终结回收路径。旧Runner曾要求BE0也stage成功，且用Python值等价比较actual/drain记录；新接线需区分noneffect与错误、严格canonical类型、stage后安全log/join再ack。详见[最小迁移审查](../../.superpowers/sdd/current-dataflow-p3-store-join-migration-review.md)。

## 真实性与接口验收要求

下游必须调用同一installed `MemoryCommitAuthority.resolve(token)`取得actual callback证据，不能信自签`memory_commit_authority`字典/hash/status。Root通过实际installed service pendinglookup取receipt，按发行sequence顺序stage，交exactissued event和live token给consumer，安全记录后prefixack。BE0无byte来源但仍需安全unknown/noneffect记录和ack；callback失败/uncertain不得重执行。

stage之后log/join失败时，队列未ack不代表可以重新stage同sequence。会话必须明确terminaluncertain，或通过有界exactcommit→token机制处理重试；不能静默丢token后恢复来源。CPU/UART stream整理顺序可能让commit先于data_accept进入journal，因此必须完整key有界pending，不能邻近匹配。

## 新join最终软件快照

源码SHA256：`abde3a9874c67de4a27d2b3f673801922575680ec54f3d869b50128e56c8f072`。独立fresh own＋Runner suite为**40 passed、3.66s、exit0**（37项join＋3项Runner）。late commit/late seed、六key变动、自签字典/无live token、严格低lane、unknown global屏障不能单CPUreset修复、34逻辑case floor、真实pending容量与correctreset均通过。

独立allocator-only1000逻辑case close循环保持1个scopefloor、1个CPU epoch和1个旧pin；旧pin晚close后pending0、旧replay拒绝。这只验证有界资源管理，不是1000条完整真实来源proof。Runner严格canonical比较actual/drain记录，publicstep及session将中途异常标terminaluncertain并停止新输入。详见[最终独立审查](../../.superpowers/sdd/current-dataflow-p3-store-join-migration-review.md)。

## 本阶段待验记录

| 检查 | 当前状态 | 所需证据 |
| --- | --- | --- |
| 新StoreMemoryJoin与Runner纯软件 | 40 passed、3.66s，冻结源软件通过 | raw删除／自签、fullkey／低lane、late commit／late seed、duplicate／capacity／reset全部门禁 |
| 新冻结源actual online | 未运行或未取得完整记录 | 新run/cache、source/build/binary/manifest、完整raw commit/ref、accepted与barrier计数 |
| 独立raw重构 | 未验 | live service callback重构与原始SW交易key、寄存器版本、RAM字节版本严格一致 |
| 完整fresh | 未验 | 每条canonical wire事件及local ticks一致、最终退出码与日志 |

后续结果仅在取得证据后补入；本稿不使用旧seed/use fixture耗时代替新门禁，不预先填写新actual accepted数或声称新online/fresh通过。当前CURRENT_PROGRESS由Root维护。
