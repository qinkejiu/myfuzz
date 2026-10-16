# D5 RAM prerequisite 校验进度（2026-10-11）

D5 实施中，未勾选完成。首步修复现有 `CrossCaseEffectTracker._commit_witness` 对 RAM callback snapshot 的消费校验；不新增拓扑或替代 MemoryService。

原实现逐个接纳 `enabled_byte_cells`，没有核对完整 span、byte-enable 和统一提交版本；末尾单元异常时还可能留下前面单元的 prerequisite。新实现先验证整份快照，再发布任何字节 witness：实际 MemoryService 支持的 1／2／4／8 字节宽度、范围内且启用的唯一 lane、完整启用单元集合、generation 与非零提交版本一致、所有单元版本一致、字节值类型合法。失败时整份记录不产生 witness。

测试驱动记录：新增 10 个不一致 commit 负例，修改前全部失败；合法部分写正例原本通过。修复后，加上实际 MemoryService callback 在四种宽度下的部分写检查，共 **18 passed**。这些是软件执行，不是 RTL 或 fresh replay。

证明边界：这一步只加强已记录 commit 的字节范围一致性。内容摘要、complete 标签和合成 fixture 本身不能证明真实回调来源；既有 `MemoryCommitAuthority` 的 installed-service issuance 校验仍负责实际回调身份。尚未完成 D5 的统一 RAM writer／read snapshot 证据分类和 IRQ delivery／acceptance／retirement 分类，也未完成 D6 的 active witness 生命周期。

下一步核对 read snapshot 的实际发行与 writer 身份引用，复用现有 read authority 和精确消费者；IRQ 三种证据分别保留其自身 scope，不把交付视为接受或退休。

只读复核发现 generation／version 缺 uint64 上界；另补三项负例，修改前 3 failed，修复后扩大软件回归 **110 passed、7 subtests passed（0.97 秒）**，含全部 18 项新增检查。span 末端也必须在 uint64 内。首版修复的扩大兼容回归 **145 passed、7 subtests passed（114.96 秒）**，含 Ibex RAM／source-action prerequisites 的旧冻结 trace 检查；该进程在最后三项 uint64 负例与边界修复前启动，最终边界由上述 110 项回归覆盖。未启动 RTL。

待办：复核指出既有 malformed 后续 overwrite 被拒绝后，旧 byte witness 仍可查询；当前修复只保证不产生部分新 witness，不能据此声称旧 active 状态已失效。须在 D5／D6 的前置状态与 active 生命周期衔接时处理并补负例。

最终只读复核：34 项针对性检查通过，uint64 问题已解决；本修复未发现其他新增边界问题。`git diff --check` 通过。D5 保持未完成，下一步仍为 read snapshot 与 IRQ 证据范围衔接。
