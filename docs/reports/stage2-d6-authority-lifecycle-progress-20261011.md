# D6 authority 身份与淘汰失效进度

## GPIO register／sync 的通用 reset barrier

本轮发现两个历史 provider 失效边界：L2 register 和 L3 sync0→sync1 只处理带 component 的原生 `gpio_reset`，忽略 Runner 的无 component `reset_barrier`。旧 writer/read 或 stage producer/consumer 跨 warm／cold barrier 仍各生成一张证书；四项负例观察到 RED（verified=1，预期 0）。通用 barrier 现清除当前 writer、stage sources、上一实际 edge、transaction 集合及 native tracker，保留历史证书原文。没有本轮原生 reset 时进入 incomplete 并报告 `awaiting_native_reset=True`；合法 epoch 推进的原生 reset 允许建立新资源。寄存器和同步器证书仍仅历史范围，不授 active prerequisites。

原生 reset 回执可以在 barrier 前或后 drain，但只能确认一个 barrier。只读复核发现的 `barrier1→native reset(epoch1)→barrier2` 双重确认 P1 已补 L2／L3 两项 RED（awaiting=False，预期 True）修复：已用于确认待处理 barrier 的 reset 不再保留 pending ack。第二次 barrier 须有新的原生 reset；旧 epoch 不续证，epoch2 实际观察可重新建立历史证书。journal 身份冲突后 barrier/reset 不恢复完整性。新增 17 项软件检查覆盖失效、两种回执顺序、重复确认、冲突及统一 ingest 的整批／分块 fresh 重建；九模块最终回归 231 passed（1.25 秒），只读复核独立 97 passed（0.56 秒），无新增重要问题。

资源监督下的原生 GPIO RTL 定向 reset 与新进程重建已执行通过：两类 policy 各运行一次原始序列和一次新 native GPIO 进程，完整 50 个原始事件及全部 checkpoint／final 报告相同。实际 host router 写 GPIOEN、PADOUT 再读 PADOUT，reset 前 L2 register=1／L3 sync=8；调用实际 `gpio.reset_local()` 后先消费 global barrier、再 drain 原生 reset 回执。barrier 后历史数量不变、两 provider incomplete／awaiting；原生 epoch1 reset 到达后才允许新版本，后续实际写／读使 L2=2／L3=16，旧证书前缀原文保留，所有新增证书 epoch1。单 worker 资源 complete，10.33 秒、峰值进程树 RSS 427,962,368 bytes，RSS 上限 3,609,878,528 bytes，DUT finding=false。保存原始 native journal 的 fresh 软件 ingest 与 final 报告精确匹配，源摘要当前一致；见产物 [verification.json](../../runs/stage2-d6-gpio-reset-rtl-20261011/verification.json)。

产物目录 `runs/stage2-d6-gpio-reset-rtl-20261011`。该 worker 直接使用 pinned causal GPIO profile／native session，手工标注 global barrier 来核验两种回执顺序中的生产 reset 后 drain 顺序；warm／cold 是 barrier 的 policy 标签，两组都执行相同的原生 GPIO reset，不证明 Runner 两种策略的差异。空的 synthetic RuntimePathContract 未配置 CPU edges。此门禁不覆盖实际 CPU、Runner／Session reset、RFuzz 或生产 online verified 文件入口，也不授寄存器／sync active prerequisite。独立产物复核通过：保存源摘要及 271 个非生成 build inputs、artifact／build digest 和 GPIO contract 与当前文件一致；两组 event25 为标注 barrier、event26 为实际 epoch1 reset，历史前缀、新 epoch 证书及资源回执一致；保存 journal 的 fresh 软件 ingest 精确匹配 final，未发现重要问题。当前其他 provider 的实时 active 资格仍待实现，D5／D6 未勾选。

## 统一查询接口的首步

Runner 新增 `active_prerequisite_status(Prerequisite)` 和 `dependency_lifecycle_report()`，由 `DependencyWitnessLifecycle` 分开返回历史观察数量与当前、逐 subject 的资格。历史报告不授 prerequisites；当前查询每次调用实际安装的 `LiveMemoryEffectTracker`，不缓存正向结果，不接受保存证书、普通 dict 或先前返回的 answer。报告不枚举所有实时 subject，`active.counts=None` 明确标注 `query_subject_required`，不能把历史 verified 数量当作 active 数量。

当前原生 active provider 仅覆盖 RAM，以及显式配置后的 instruction slot。RAM 仍核对实际 token 认证的 retained writer 和当前物理 cell；slot 仍核对当前 generation、实际 declaration、未物化状态及保留 reservation。`satisfied` 只表示该精确当前 prerequisite 有匹配；`unsatisfied` 表示有 provider 但当前无匹配；身份或 journal 完整性失败返回 `incomplete`；无 active provider 的 register、IRQ、transport 范围返回 `unknown`。协议证书也不能转成当前状态资格。本接口是查询与诊断契约，不增加其他 provider 的 admission，也不替代既有 Session 命令前 gate。

19 项实际软件 service／callback 定向检查通过（0.25 秒）：实际 writer 的无读／无 journal 副作用查询；四条历史证书存在但缺 active provider；register／IRQ unknown；reset、等值覆盖、writer 淘汰、journal 冲突后拒绝，历史原文保留；slot 实际物化失效；返回值 detached、runtime identity 不变；provider 与 consumer 漂移不能恢复。启动失败负例曾 RED：不兼容 tracker 留下已发布 gate，或 policy property 异常留下半绑定 lifecycle；现在 Runner 用局部 gate 完成绑定再发布，lifecycle 在读取／验证全部局部状态后一次性绑定，失败后默认配置可重试。consumer 被替换为 None／object 的四项 RED 原先崩溃或丢失历史诊断，现身份冲突直接锁存 incomplete，不再解引用替代对象，历史从启动时固定 consumer 查询。恢复原对象不续授权。

修复后七模块最终兼容回归 120 passed（45.24 秒）：lifecycle、live RAM prerequisites、slot、binding、RAM Runner、IRQ Runner、online reset replay。只读复核独立 lifecycle／RAM Runner／IRQ Runner 46 passed（1.05 秒），无新增重要问题；git diff --check 通过，本轮未启动新 RTL。D5／D6 仍未勾选；其他 provider 的 active 生命周期、后续实际门禁仍待执行。

当前authority登记快照修复后的正常实际运行已补验：两类reset verified文件链均通过，保存非空RAM binding＋schema14reset顺序，1,455／1,587events新建RTLmatches true。生产verifier／selector及独立产物复核通过；仅证明正常固定admission路径，不把软件登记故障注入提升为DUT冲突实测。见 [实际文件重放](stage2-d5-live-memory-replay-progress-20261011.md)。

后续登记冲突修复：即使authority实例未变，内部installed服务登记删除、ledger指针替换或额外组件加入也须撤销旧writer。两authority乘三变异共6项真实MemoryService callback负例均RED（旧prerequisite仍satisfied）。tracker现保存启动登记快照，统一检查dict键集合、记录类型／长度、service／ledger／memory对象身份及commit region IDs；漂移永久degraded，恢复原登记或reset不能恢复。三模块64 passed（45.74秒），只读复核独立16 passed（12.60秒）、无新增重要问题，无新RTL；属于软件身份故障注入，不授DUT冲突实测或通用lifecycle完成。

本轮修复可信 RAM／instruction-slot tracker 的 authority 实例漂移。原实现核对实际 service、ledger 和 memory，但从 consumer 动态取得 commit/read authority；替换成同服务的新实际 authority 后，旧 retained writer 仍满足 RAM prerequisite。两类替换负例均观察到 RED（satisfied=True）。

tracker 现在在创建时固定实际 commit/read authority 实例。RAM 查询、instruction-slot 查询及诊断报告共用身份检查；实例漂移或原 authority degraded 永久锁存 tracker 的 degraded 状态。恢复原实例、重置 tracker 均不能续旧授权，保存 receipt 不加入 authority。历史证书保持原文不变。该限制是实际运行身份冲突的失效行为，不把 document 格式合法当作认证。

新增五项实际软件 callback／service 检查：两类 authority 替换撤销 RAM 且不能恢复、两类替换撤销合法 instruction slot、writer 淘汰撤销旧 RAM。淘汰用 max_writer_versions=4：首个实际 STORE 的四 lane 可授权并经实际 read 生成四条历史证书；第二个不同地址 STORE 淘汰首 writer，首地址当前 cell 的值与版本完全未变，旧 prerequisite 仍拒绝。重新观察保存历史不能恢复 writer，四条历史证书保持不变。

六模块联合软件回归 93 passed（51.66 秒）；首轮四模块 59 passed（5.57 秒），git diff --check 通过。只读复核通过：独立58 passed（46.27秒），无新增重要问题。本轮未启动新 RTL，不能将软件 authority 故障注入称为 DUT 冲突实测；此前覆盖写与 warm/cold reset 的真实证据按各自源身份保留，见 [保存／reset 进度](stage2-d5-live-memory-replay-progress-20261011.md)。

reset schema14/15 上轮复核已收尾：独立 28 passed／2 subtests，实际 warm/cold 时间线、trace 摘要和历史证书吻合。D5／D6 仍未勾选；通用 provider 的 history／active 生命周期、其他冲突及后续 Stage 2 真实门禁尚待完成。
