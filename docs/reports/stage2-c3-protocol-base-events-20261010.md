# Stage 2 C3：通用协议基础事件与事务身份

日期：2026-10-10。C3 为新生成的 `local_harness.v2` 通用 APB3、TL-UL、Wishbone 目标 artifact 增加协议边界采样，并由 `ScenarioRunner` 在保留原始 `local_tick_sample` 的同时投影 `ip_base_event.v1` 事务事件。协议 trace 的端点、时钟域、等待上限和信号名映射进入 runtime artifact identity；采样 tap 直接连接到已经由 profile／ABI 绑定的协议线，不按组件名选信号。

投影记录 `transaction_request`、`transaction_accept`、`transaction_response`、`protocol_error`、`wait_observation`、`transaction_duplicate`、`transaction_cancel` 和 `transaction_timeout`。握手只由原始 `pre` 样本判定，因为它是活动时钟边沿前呈现的值；`post` 仍保留在 raw event 和 C1 端口事件中，避免同一边沿被记两次。

TL-UL 请求／响应保留 A/D channel 的原生 source 值。事务 key 由协议、profile endpoint、reset epoch 和 source 组成；等待中的重复 source、A 或 D 超时、reset 取消及迟到／未关联 D 响应都记录相同的原生 source 身份。A 请求接受后会独立开始 D 等待预算。D 超时不会释放 source：该 source 暂时隔离，迟到响应仍关联原超时请求并标记 `matched_timed_out`；只有响应或 reset 才允许复用，避免迟到 D 被归到新请求。reset 也分别取消同 source 的 outstanding 请求和未接受 offer。

APB3 和已接纳的通用 Wishbone 子集没有原生事务 ID。对应事件明确保留 `transaction_key=null`、`native_identity=null` 和 `identity_gap=protocol_has_no_transaction_id`；接受／响应事件以原始请求 event 引用关联，不从数组位置构造 key。APB3 以 SETUP 作为请求、`PSEL && PENABLE && PREADY` 作为接受／响应，并记录 `PSLVERR`、等待、超时及 reset 取消。Wishbone 以 `CYC && STB` 作为请求、`!STALL` 的 strobe 作为接受、`ACK` 作为响应，并记录等待、超时及 reset 取消。当前 generic Wishbone admission 不提供 IP error pin，trace 不虚构 `ERR` 信号。

回归分成独立 pytest 子进程并行执行：

- 协议／基础事件、journal、Runner 连续性与来源回归：62 passed，86 subtests passed；包含 A/D 等待预算分离、超时 source 隔离／迟到响应关联、reset 双取消的负例。
- 通用 TL-UL artifact/factory：3 passed，2 个真实 RTL 测试按默认配置跳过。
- 通用 APB3 artifact/factory：3 passed，2 个真实 RTL 测试跳过。
- 通用 Wishbone artifact/factory：2 passed，2 subtests passed，1 个真实 RTL 测试跳过。
- runtime renderer/lint、driver renderer、template contracts：39 passed，59 subtests passed。
- `compileall` 与 `git diff --check` 均通过。
- 文档链接扫描：592 Markdown 文件、1,314 个本地链接、83 条既有缺失引用、150 个 HTTPS 跳过项；C3 新增链接均解析成功。

边界：这些结果证明合约、事件投影和生成产物，不证明 generic target 的真实 DUT 运行；真实 RTL 场景测试未启用。C3 不实现跨协议 Checker、输入采样／绑定交付事件或覆盖消费者；这些由 C4–C7 继续验收。Stage 2 生产 Runner、HMAC DUT admission 和 DUT 级别结果仍未声称完成。C1–C2 的端口事件范围见 [C1–C2 报告](stage2-c1-base-events-20261010.md)，完整工作项见[主计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)。
