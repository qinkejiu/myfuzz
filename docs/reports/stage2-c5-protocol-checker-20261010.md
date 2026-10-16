# Stage 2 C5：通用协议 Checker

日期：2026-10-10。C5 在 C3 的声明式协议 trace 和 Runner raw tick 消费路径上加入不依赖功能插件的共用 Checker。Checker 只消费声明 tap 的 pre-edge 样本，保留违规事件的 raw sample 引用；发现违反协议合同时把本次 Runner 状态标为 `failed`，并继续把已采样事件写入日志。

Checker 校验 trace 字段宽度和值域，并针对三种协议记录握手约束、请求 payload 稳定性、响应关联和等待预算。APB3 要求 setup 后进入 access，access 等待时保持 payload；Wishbone 检查 `SEL` 位宽及写入非零、stall 期间请求稳定、接纳请求与 ACK 的 FIFO 关联和等待预算；TL-UL 检查 A/D payload 在 backpressure 下稳定、source 至多一次 outstanding、响应与已接纳 source 关联、请求／响应 opcode 与 size 一致、等待预算和 `a_size`／地址／mask 合法性。Get mask 可为零；非零时须连续、处于对应 transfer lane 范围且字节数不超过 `2**a_size`。PutFullData 必须覆盖该 size/address 的全部 lane；PutPartialData mask 可为零或任意限于对应 lane 的子集。未支持 opcode 会产生违规事件。TL-UL 允许 A 接纳与对应 D offer 在同一周期出现，因此该周期按 source 绑定新请求；其余 D offer 首次出现时绑定当时已有的 outstanding 请求。无对应请求的 stalled D offer 会立即报错，之后不能被新接纳请求补绑。一个 D 响应完成时，其余 outstanding source 仍按周期累计等待。

Checker 不比较未知 IP 的写后读值，不按寄存器名猜功能，也不证明 target RTL 的寄存器语义。对无原生事务 ID 的 Wishbone，队列只表达协议上可观察的接纳顺序关联。真实目标 RTL 测试仍按默认配置跳过；本报告只覆盖软件 Checker、生成 trace contract 与 Runner 事件接线。

定向用例覆盖合法的零 Get/PutPartial mask、PutFull 零或不完整 mask、mask 越出 transfer lane、Get mask 超出 size 或不连续、有效 PutPartial 子集、未支持 opcode、请求／响应 stall payload 改变、重复 TL source、无匹配响应、无匹配的 stalled D offer 不能绑定后续请求、同周期 A/D 接纳、错配 D opcode/size、多个 outstanding source 在另一个响应握手时仍累积等待、APB setup/access 与 reset、Wishbone `SEL`/stall/响应一次性和等待预算。Runner 集成测试确认违规事件保留引用并令 run 失败。

并行回归结果：

- 协议 Checker、协议事务事件与基础事件：33 passed。
- 通用 APB3／TL-UL／Wishbone artifact/factory 加 runtime/driver renderer：36 passed，5 个真实 RTL 测试按默认配置跳过，55 个 subtests passed。
- `compileall` 与 `git diff --check` 通过。
- 文档链接扫描覆盖 594 个 Markdown 文件和 1,332 个本地链接；83 条缺失链接均为既有历史产物引用，改动文档中的新增 C5 链接全部解析成功，150 个 HTTPS 链接跳过。

一轮更广的 `tests/scenario` 长跑在测试夹具改动前启动，结果为 2,917 passed、2,512 subtests passed、9 failed：7 项失败使用了当时尚未增加 `a_size` 的旧 TL-UL fixture；当前 fixture 更新后，相关 Checker/事件/基础事件定向套件为 33 passed。另一项并发 build-identity 比较在独立重跑中通过；一项 P5 UART 地址见证测试独立重跑仍失败，与 C5 无关，未在本工作包修改。该长跑不能作为全量场景套件通过的证据。

同周期响应关联和 response opcode/size 规则也与仓库 vendored OpenTitan 的 [`tlul_assert.sv`](../../third_party/soc-opentitan/hw/ip/tlul/rtl/tlul_assert.sv) 对照；该 checker 明确支持 combinational response，并比较响应 opcode 与原请求及响应 size 与 request size。

详见[主计划 C5](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)、[C3 报告](stage2-c3-protocol-base-events-20261010.md)和[C4 报告](stage2-c4-input-sampling-20261010.md)。C6 基础覆盖与 C7 跨例 fixture 仍待完成；无 Stage 2 生产运行器、真实 DUT 结果或能力授级结论。
