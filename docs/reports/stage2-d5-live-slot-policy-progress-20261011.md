# D5 可信 instruction-slot 与在线 factory 衔接进度

本轮工作区实现将实际 RAM 前置状态与 instruction-slot reservation 放在同一可信 gate 中。槽必须落在声明窗口内，属于实际 memory 的同一线性 region span，且四个字节均实际声明、未 materialize；注册信息不能替代实际 memory 状态。写入任意 lane 后即拒绝，独立 RAM prerequisite 仍需实际 token 认证的当前 cell。

只读复核发现的 cold_reset 旧槽授权恢复问题已用实际 PersistentMemory 负例复现并修复。新 reservation 的 witness 绑定实际 generation，canonical witness_id 重算；重复注册不刷新旧 reservation。实际 generation 改变立即拒绝旧授权；消费 reset 后明确注册可重新授权。该修复联合回归 183 passed／15 subtests（20.69 秒），独立复核 39 passed，无新增重要问题。

共享 PULP factory 和 Ibex wrapper 新增默认关闭的 `persistent_memory_runtime_contract_sha256`。非空时必须显式启用 source actions 和 commit receipts、提供 64 位 hex contract identity；不完整配置在渲染前拒绝。每个实际 Runner 安装独立 read/write authority、历史 RAM consumer 和可信 slot/RAM gate，同时保留旧 commit journal。CPU 启用实际 readback receipts，不启动 RTL 进程即可检查配置。

Ibex 在线入口新增默认关闭的 `persistent_memory_prerequisites`，开启时从实际 decoder 的 runtime contract identity 传给 factory。共享在线启动优先使用 Runner 安装的可信 gate；不会调用旧 gate builder 替换它。

factory 定向初次验证 5 passed；slot／factory／在线启动、旧在线策略、live RAM 与 RAM Runner 联合回归 66 passed（41.71 秒）。只读复核独立 6 passed，未发现重要问题；另在真实 factory CPU 的 `_serve` 软件写／读上取得 4 个 byte-version 证书，两个 authority 和 service pending 均归零。复核未启动 RTL，结论仅覆盖配置与分发。所有检查仅软件配置、实际 host memory/callback 和渲染范围，未新增 RTL 或 fresh replay。

D5 保持未勾选。完整在线执行仍需衔接辅助 instruction SourceAction 注册、可信动态 RAM prerequisite binding、保存身份及 replay 消费；D6 通用 lifecycle、其他 provider active 资格与 Stage 2 真实 CPU/IP／HMAC 门禁继续按原计划执行。

后续辅助指令衔接：可信 gate 新增固定 NOP fragment 注册入口，借用现有 slot window／逐字绑定，最终 SourceAction 的 ownership 为 fixed、payload 为空；完整 fragment 另行保留并在 require_case 前核对，不能凭固定动作的空 payload 替换实际片段。容量受 max_actions 限制。executor 在主动作注册之后、require_case 之前注册 decoder 当前 proposal 的辅助片段，并在决策记录中保留 support_actions。旧 gate 没有该入口时沿用原行为。

已观察 executor→真实 decoder／factory gate 链的 RED（辅助 action 未注册）；实现后联合软件回归 83 passed（45.64 秒）；新增拒绝路径独立定向 4 passed，只读复核独立 6 passed，未发现重要问题。实际 memory 定向 4 passed：完整片段地址篡改、槽已填充、非 NOP、错误 component、越窗均拒绝。未启动 RTL，完整在线 execution／可信动态 RAM binding／保存及 replay 仍未验收。
