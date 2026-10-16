# D5 当前实际 RAM 动态绑定进度

新增 `LiveMemoryDynamicPrerequisiteBinder`，复用既有不可变 DynamicEffectBinding／BoundWitness 与 payload 不变校验。只接受实际 LiveMemoryEffectTracker，声明限制为实际 memory region 内的至多 256 个 byte offsets，writer whitelist 固定为 STORE，provenance 缓存显式预算至多 65536。

绑定与 claim 验证从 tracker 的当前 retained live writer 重算 STORE writer kind：此前的实际 token 认证、实际 memory generation／cell version／writer ref／value、journal integrity、reset floor 和保留预算均必须仍然成立。保存 receipt 的 observe 或 writer_kind 标签不能加入或替换 provenance。STORE 仅是 host memory writer kind，不授 CPU 指令退休、UART 来源或其他上游源身份。

10 项新增测试通过实际 CPU `_serve` 软件 callback 和 Runner drain 验证：无需 receipt observation 即绑定；pending commit／saved receipt 不授证；等值覆盖在 drain 前拒绝旧 binding；新 binder 可凭仍有效的实际 authority 重算保存 claim；cold reset、淘汰和超龄拒绝；actual region 外声明启动拒绝且不初始化 memory；保存 writer_kind 不能改实际 STORE。

已观察缺失 API 和 actual region 越界负例的 RED。首轮扩大兼容回归 99 passed（68.56 秒），包含旧 Ibex RAM 策略。只读复核发现重算 digest 后错误 version／action_id 仍被 legacy verifier 接受的 P2；新增两项 RED 并在 live verifier 精确核对 actual writer version 与 consumer action_id，修复后联合回归 75 passed（0.43 秒）。修复只读复核独立 75 passed，无新增重要问题。未启动新 RTL／fresh replay。

D5 尚未完成。此轮交付当前实际 RAM 动态 binder 基础，factory 的结果槽读策略仍需把它连接到 admission，并保存策略身份和绑定决策供 replay 重算。D6 通用生命周期及完整 Stage 2 CPU/IP／HMAC 门禁保留原计划范围。

后续 factory admission 衔接：共享 PULP adapter 的 `PulpLiveMemoryPrerequisiteGate` 从实际 memory resolve 取得结果槽 region／offset，复用既有静态 LW base 规则；被规则确认的 load 必须绑定当前 actual STORE witness，再叠加自己的 instruction-slot prerequisite。缺 witness 时拒绝且不注册 action；非该类读保持原 slot 路径。固定辅助指令入口继续沿用。

Runner 通过显式可信 gate subclass 配置此 adapter，公共 Runner 不按 CPU／外设标签挑选策略。策略 schema、规则、component、实际结果地址、STORE byte declaration、proof scope 与 max_bindings 进入启动身份。binding 记录按已注册 action 数量限界，并由 executor 写入决策中的 dynamic_binding，payload 保持原值。

新增两项真实 factory／实际 CPU host callback 软件检查，RED 分别复现缺 witness 仍注册与决策缺 binding；修复后 slot／factory／live binder／旧 gate／RAM Runner 联合回归 96 passed（41.14 秒）。只读复核独立 28 passed、未发现重要缺陷。未启动 RTL；CPU `_case_id` 为测试显式设置，以便调用实际 `_serve`，不表示真实程序运行。

当前剩余：保存 plan 中每例 action／辅助 action 及策略声明，verified bundle 重选 factory 配置，并在 replay 每例 admission 前依据新进程实际 witness 重算／核对 binding。现有 replay 缺动作注册，不宣称可信 gate replay 已可运行；完整在线执行与真实 Stage 2 门禁仍未验收。
