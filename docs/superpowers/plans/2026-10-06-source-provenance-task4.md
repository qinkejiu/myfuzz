# P2 Task4 来源与逐边证据接入

> 执行已授权总计划 P2 Task4。使用 subagent-driven-development 与并行独立模块、TDD、独立审查和完成前验证；保留原有修改，不暂存、不提交。

**目标：** 将合法源动作的原始 case/source、持久 RAM writer/version 与选中物理边候选接入真实追加日志和完整前缀 replay，随后用真实退休与外设消费证据贯通完整链。

**架构：** 输入登记、事件观察上下文和真实来源分别保存。物理边索引初始化缓存，只识别精确 Binding 或已声明 MMIO window；索引候选不证明寄存器语义或 RTL 因果。事件在 journal append 前完成 detached 元数据，后续消费引用旧事件，不修改旧前缀。

**技术：** Python immutable dataclass、现有 Runner/MemoryService/EventJournal、版本化 session plan、真实 Ibex/PULP/UART 与 fresh replay。

## 不变量

- case B 观察到 case A 的指令/RAM，origin 保留 A，observed_case 可以是 B。
- 来源只能来自明确 action 注册或真实 RAM writer；不能用最近 fetch/current case 给 MMIO 或 IRQ 指定 origin。
- fixed_support、bootstrap 与 fuzz_source 分开；登记或注入本身不计真实消费。
- 所有 Binding 候选保留 graph/rule/prerequisite/path 身份；多路径歧义保留。MMIO 只标 route_window，不能猜 PADOUT/PADIN offset。
- 新 schema 身份包括登记、edge index 和配置；从 plan 重建来源并逐项比较后再创建 RTL。legacy plan 保留其事件语义，不自动升级为有 origin 的 trace。
- 热路径不重编译图，不查询工具链/源码，不完整重扫历史。未知来源保留 unknown；缺失真实探针不得宣称完整闭环。

## T4.1：独立来源登记与边索引（并行）

- [x] `source_provenance.py`：SourceAdmission.create/document/from_document，字段 admission_id、case_id/index、source_id/path_id/direction、component/action_id、role、input_kind/input_sha256。canonical digest 防伪造；Registry 的 action ID 重用必须完全相同。
- [x] `runtime_edge_index.py`：RuntimeEdgeIndex(session.runtime_path_document, contract.document())，初始化校验版本及所有声明身份；match_event 只查缓存，返回全部候选，不产生因果或资源版本证明。
- [x] 两模块先 RED 后 GREEN；独立检查未知来源、伪造 ID、同源多路径、位段/端点、错窗口/身份、热路径无 graph 遍历。

## T4.2：Runner 的追加日志元数据

**接口：** configure_provenance(edge_index)、register_source_admission(admission)、set_observation_case(case_id, case_index)、clear_observation_case()、provenance_configuration、source_admissions。

- [x] 新测试先验证跨例 instruction/RAM writer 保留原 admission，当前 observed_case 不替换 origin；非来源的 MMIO 保持 unknown。
- [x] _EventLog.append/append_unchecked 在落日志前 detached 注入元数据；源事件按 action_id/source_event_id 查询 registry，memory_read 根据 writer_event_ids 保存逐字节版本、writer 和已知/未知来源。精确物理 edge 候选只与事件实际端点/window匹配。
- [x] 不给任意 local output 推断 origin；不改 DUT 输入/输出、event ID、握手或 IRQ 规则；registration 是元数据，consumption 另看真实事件。
- [x] journal 分块、重复 STEP 与 old suffix 查找保持一致，非法登记与非法输入不产生消费证据。

## T4.3：session/admission 与 replay

- [x] 新契约 session 启用来源配置；_validate_runtime_case 唯一解析 source_id。submit_case 注册主源和 fixed_support，明确 source_role 参数用于受信 bootstrap，绝不解析 action_id 猜来源。
- [x] 注册内容绑定规范化动作 SHA-256；一个 case 的原始登记可跨后续 case 使用。case 观察上下文在执行完成/失败后清理，后续最终化不硬归到最后 case。
- [x] 新 plan schema 10/11 包含 source_role 和 provenance registry/configuration；严格重建规范输入、support 与来源表，身份/前缀篡改在 factory 前拒绝；schema4～9仍按旧语义重放。
- [x] 新模块纳入 host/online/live source identity；UART fixed RX warmup 明确 bootstrap，普通 slot 仍 fuzz_source。
- [x] 回归 existing replay、preflight、异常前缀、Rust 运输；真实 GPIO/UART 当前源码 record/replay，检查 event writer/version 与来源登记/路径身份。

## T4.4：完整真实因果与门禁（仍须完成）

- [ ] 官方 Ibex RVFI 或经固定认证的退休探针：退休 PC/order/insn/内存访问与实际交易匹配；非对齐双 beat、trap/被取消指令不误归。新RVFI profile及RV32I子集交易匹配已接入；默认旧profile仍未启用。完整链验收未完成，Fetch不替代退休。
- [ ] UART peer action/frame身份和实际RX驱动已接入；实际FIFO push/pop和MMIO返回关系仍须完成，同值重复帧不互认。native IRQ 的 sampled/taken 与 pulse IRQ 分开建证据。
- [ ] feedback 消费边携带 producer/delivery/consumer、transaction/resource、原始 source/case 和明确 proof_scope。删任一见证、错 epoch/sequence/版本、只采样无 taken 不提升。
- [ ] 完整双向 real trace、提前 IRQ、跨例来源、断线/错 window/绑定源拒绝及 fresh replay；Task4 全部成立才标 P2 完成。

## 来源基础设施原轮状态记录（397项/原bundle）

上一轮判定为 progress：Task3 修改、317项整合及真实GPIO120/UART2例完整replay已有当前材料。本轮不重复实现Task3。T4.1～T4.3来源/见证基础设施已整合并独立复审；追加真实字节 writer kind 防Store/action字符串同名误归属。该轮root397项、5环境跳过、零失败；实际Rust16项全过。修复后GPIO120/UART2例完整前缀replay匹配，旧preliminary证据保留。该原closure的RVFI及UART frame/FIFO尚缺，不标Task4/P2完成。

### T4.4 退休/帧续作

认证RVFI新profile和44字段全量wrapper、实际post-rising退休/response/accept、真实复位/取消probe已接入；UART action/frame与冻结波形真实pre/post验证、legacy原语义和raw/logicalreceipt区分已接入。受限有界matcher区分bootstrap unknown与typed instruction源，保留case/epoch/完整key和同PC版本歧义。独立审查持续用RED反例修复unsupported memory/trap/非法或无法配对memory不能将旧CPU数据交易队列head重归后续指令；集中必需事件字段矩阵已RED→GREEN，最终当前源码503项/6skip与GPIO120/UART2例完整prefix门禁通过；完整寄存器/FIFO/IRQ链仍缺。

完整T4.4复选框仍不勾选：尚需真实GPIO寄存器→输出/IRQ及UART FIFO/原生IRQ消费。当前证据及各closure状态见[退休/帧报告](../../reports/current-dataflow-p2-retirement-frames-20261006.md)，下一个GPIO探针细化见[实施准备](../../../.superpowers/sdd/current-dataflow-p2-task4-gpio-consumption-next.md)。不使用最近fetch或字节相等/时间接近猜完整因果。

两项后续探针分别准备：[GPIO寄存器/IRQ](../../../.superpowers/sdd/current-dataflow-p2-task4-gpio-consumption-next.md)、[UART接收/FIFO/nativeIRQ](../../../.superpowers/sdd/current-dataflow-p2-task4-uart-fifo-next.md)。均为只读设计准备，未计入完整门禁。
