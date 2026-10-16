# D5 可信 RAM 前置状态接入

## 实际前置条件入口

Runner 提供默认关闭的 configure_persistent_memory_prerequisites。必须先配置实际 RAM 历史消费者，启动时安装 PersistentMemoryPrerequisiteGate；最多注册 256 个动作，容量可显式配置并进入启动身份。ScenarioSession 的提交与观察每次解析 Runner 当前 gate，拒绝替代 gate；主源与 support instruction 的已注册输入和前置条件均在实际命令之前查询。

LiveMemoryEffectTracker 使用实际 authority token 已认证的 writer 缓存。查询必须同时满足：writer 未被淘汰／过期／reset floor 禁用、journal 未发生冲突、实际服务及 ledger／memory 对象未替换、read/write authority 未降级，以及当前 RAM cell 的 generation、version、value、STORE writer kind 和 writer transaction reference 精确匹配。只有启用的实际写 lane 可满足 ram_byte_version。inspect_byte 是单 cell 的 detached 查询，不初始化未知字节，不调用 read，不改变内存。

历史 snapshot 证书继续保持 historical，查询 active 字节不改变历史 verified 计数。receipt observe 不接受保存事件作为认证入口；同值覆盖的新版本在尚未排出 commit 前就阻止旧前置条件。reset 后旧 writer 不恢复；真实新提交可以提供新前置条件。journal 冲突、authority 降级和实际服务替换构成持续不确定性，不由 reset 清除。本 gate 仅提供 RAM 范围，其他前置类型保留拒绝，不能借旧 reservation 数据授新范围。

## 验证与复核

新增 **21 项软件检查**：实际部分字节写、无读取副作用、保存 receipt、同值覆盖、历史／active reset 分离、淘汰／过期、journal 冲突、对象替换／恢复、冷 generation、精确动作输入、未知 cell 查询、启动身份与动作容量、非 RAM scope、authority 降级、显式年龄单调、跨实际服务 memory id 歧义、实际 Session 提交前拒绝、Session 后安装 gate、support instruction 前置条件。

Session 后安装 gate 的缓存旁路由只读复核发现，RED 复现后改为动态查询；复核 live＋旧 session gate **28 passed**。最后辅助指令遗漏由新增负例复现，修复后独立 live 模块 **21 passed**，未发现新重要缺陷。最终扩大兼容回归 **324 passed、25 subtests passed（9.07 秒）**，涵盖实际 memory／service／authority、RAM／IRQ Runner、旧 source actions／session gate、在线 gate、runtime paths、日志与 replay 预检。

使用实际 MemoryService／GeneratedCve2Session._serve 软件回调和实际 ScenarioSession.submit_case 方法。未运行新 RTL 或 fresh replay，不授真实 CPU/IP 等级。

## 剩余工作

D5 仍保持未勾选：当前 Runner／Session 可信入口已具备，现有在线 factory 的 gate 选择与默认 instruction-slot 策略组合仍需衔接／审计。D6 已开始 RAM history／active 失效，但通用生命周期接口与其他 provider 的 active 资格尚未完成。完整 Stage 2 生产命令、CPU/IP／HMAC 门禁仍按原计划推进。
