# P2 UART 原生外部 IRQ taken 来源验收

日期：2026-10-06。本轮在冻结源码下完成 **实际 UART RX 来源→FIFO 留存→原生 watermark cause 版本→实际 CPU 输入交付→Ibex 外部 IRQ taken** 的受限闭环。真实 fixture 4 项及 7 个负例子检查通过，完整 fresh replay 的 48,378 个 wire JSON 事件和局部 tick 一致。通用 ISR 入口与操作数／load 来源仍为 unknown；整体 P2 尚未完成。

## 实现范围

显式 `cpu_retirement=True, uart_fifo=True` 使用 `ibex_rvfi_local` 与 `opentitan_uart_fifo_local`；两者同时开启时 CPU factory 才启用 exact-boolean `native_irq_receipts`。默认 UART/CPU profile 与旧身份保留。原始 UART 帧记录继续携带 `fifo_origin=unknown`，追加的消费证明独立保存来源，不改写历史 raw 事实。

CPU 的 `ibex_native_irq_receipts.v1` contract 认证固定官方 Ibex 源码、实际 `irq_external_i` 输入、真实 PRE masked/taken 表达式和 POST RVFI 扩展通知。完整 parsed receipt 的 execution、command sequence、tick 和实际 PRE/POST 输入必须精确符合已提交命令。`set_next_irq_input_context` 只携带脱离原对象的计划引用，一次消费并在异常路径清理；None 清除旧上下文并保持 unknown。实际 `irq_taken_pre=1` 才产生 `cpu_external_irq_taken`，`rvfi_ext_irq_valid=1` 的 POST 通知即使 `rvfi_valid=0` 也单独记录，不能把通知或 PC 当作外部 IRQ taken 来源。

Runner 在实际 CPU step 前使用最后实际应用的 binding；同值新版本也替换旧引用。原生 join 验证 source PRE/POST／epoch／版本、完整 binding／input context、实际 CPU sample/taken 及 journal ID。逻辑 graph source `uart.external_rx_byte` 必须经真实编译 `RuntimeEdgeIndex` 解析为输入 owner `external_uart_rx_byte`，不能直接比较不同命名空间，也不能凭字节值猜来源。

FIFO 与 native join 的 GC 只释放无 live 引用的已完成历史。队列、同步器／接收器、未完成 pop/read、当前输入／sample 与未证明 take 保留精确资源；超过真实未完成容量形成 certainty barrier，不能静默丢弃或升级。软件检查覆盖超过 256 个 frame/read、超过 1024 个 version/take、延迟 proof、重复、旧 epoch、source-case 与初始 unknown。reset kind 必须对应真实声明的 UART source 或 CPU IRQ binding 角色，失败 reset 不生成成功事实。

`scenario_runtime_manifest.v1.json` 新增 UART v2/v3/v4 结构分支及 FIFO/provenance、GPIO causal、CPU RVFI/native additive 字段限制。结构校验不等于源码／build 认证，也不声称 JSON Schema 可认证整数与 integral-float 的词法区别；严格 canonical Python 身份验证仍负责精确类型和重新生成的源／build 闭包。

## 冻结源码真实门禁

运行目录：[新 native 在线材料](../../runs/current-dataflow-p2-uart-native-irq-20261006-online-alias-fixed/)。缓存：`runs/current-dataflow-p2-uart-native-irq-20261006-cache-alias-fixed`。Root 使用唯一 build worker；在线 RFuzz 完成 4 例、返回 0。真实 fixture 4 项及 7 个子检查通过（123.22 秒），fresh marker 为 `verification_scope=full_wire_prefix`、`first_difference=null`，逐事件 canonical JSON 与局部 tick 全部相等。

| 已保存实际证据 | 数量与范围 |
|---|---|
| 完整事件前缀 | 48,378；没有只比较选择事件或摘要代替完整 prefix |
| 接受的 native cause 版本证明 | 20；多版本不代表额外 source frame |
| FIFO 留存／读取证明 | 各 4 |
| 实际外部 IRQ taken 来源证明 | 4，全部 `graph_path_certified=true` |
| 原始来源角色 | 1 bootstrap、3 fuzz_source，保留各自原 case ID |
| 不完整消费记录 | 0 |

负例逐项删除 cause、entry、binding、sample、context、taken、observer schema，均不能 promotion；无实际 reset witness 的 epoch 跳变也不能 promotion。这是 reset-free 捕获及软件负例，不认证实际 reset 波形。Generic ISR/operand origin 均为 unknown。

独立只读审计退出 0，验证 12 个 envelope artifact、444 次 source hash 对照、CPU 317／UART 295 个 captured input、strict cache identity／binary bytes、真实 index／registry／RX admission、frame/retention、context 与 exact parsed sample/taken 链。审计没有执行 binary 或 RTL。官方 HEAD 与 pinned 源一致：OpenTitan `fca045df919a26c47e71616b9dac917b1ea4fd07`，Ibex `34b0705760ef3dfa00e99637432473d2be8f22f3`。

- Envelope identity：`036f6f103cfc9ef6ea8ca5ac2e898338c1e46190153632121f3d556eca7312f5`
- Raw manifest：`860f8064c5d1358a0c4d5058f80421ab38be5e4f9c31f8283e6bdef5018c6a8d`
- Trace：`3ba09738833eda8c275f69476e983ca05fe7d8fab29b6ff7a12c89eb0a55345e`
- CPU build：`4425ced88676f9882628cf57fcf87c4a7ebd35b9ef860fd3f605da474df1a141`
- UART build：`bc6e6b79d5f6ed62f5f0c59ada35997f9fe5042ab57d9483d073a71ac14c98ac`

最终 alias-corrected 冻结源码 source-focused 软件总门禁：**166 passed、56 subtests，150.20 秒，exit=0**。此前 broader native 软件 `817 passed、17 skipped、774 subtests，332.59 秒` 发生于 alias 修正前，仅作为当时软件范围记录，不代替当前源总门禁或最终真实结果。独立最终 native review 38 项通过，最终 helper/index/wire 测试 4 项通过、4 个 real fixture 在软件模式下正确 skip。

## 保留的失败与边界

首次 native 在线运行完成四例，但真实 positive fixture 失败：逻辑 source ID 与 owner 名称直接比较错误，产生 4 条 `untrusted_uart_irq_entry_certificate`。记录保留，不升级为成功：[首次 failure 审计](../../.superpowers/sdd/current-dataflow-p2-native-real-first-gate-failure-audit.md)。修正后使用新 output/cache 重跑源码门禁。

随后 positive native 链通过，但 fixture 将 fresh Python tuple 与 saved JSON list 作 raw equality，产生巨大 difflib 诊断；Root SIGINT 停止，保留中断日志。仅修改测试为逐事件严格 canonical wire JSON 比较，再对同一生产源/output/cache fresh replay；没有虚构另一次 online run。最终日志明确引用并复制原 actual run prefix。

本轮不认证 first-handler／generic ISR、通用 CPU taint、任意 IRQ class、overflow/error 并发角落、PLIC／完整 SoC／全局 cycle-accurate 时序、十分钟吞吐或 RTL bug-found。旧 GPIO 637 软件／5 RTL／16 例、旧 UART FIFO 与 P1 gate 均按原 captured source identity 保留，不能在新源码下自动升级。

证据：[最终 fixture 日志](../../.superpowers/sdd/current-dataflow-p2-uart-native-irq-real-wire-prefix-final-gate.txt)、[独立最终审计](../../.superpowers/sdd/current-dataflow-p2-native-saved-final-audit.md)、[审计 JSON](../../.superpowers/sdd/current-dataflow-p2-native-saved-final-audit.json)、[GC review](../../.superpowers/sdd/current-dataflow-p2-native-gc-independent-review.md)、[schema 报告](../../.superpowers/sdd/current-dataflow-p2-native-runtime-schema-report.md)。所有工作未 stage 或 commit。
