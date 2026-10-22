## 2026-10-22 Compiled F4 built executable identity

[执行计划](2026-10-22-compiled-f4-built-identity.md)：D2 artifact／稳定构建回执／live executable／原始和 fresh process 关联。最终验收状态见[报告](../../reports/compiled-f4-built-identity-20261022.md)。

# 实施计划索引

- [Selected compiled F4 runtime-path admission](2026-10-22-compiled-f4-runtime-path-admission.md)：同次 D3 路径、显式 image source、实际 session 与 fresh 连接；代码审查通过，最终门状态见[报告](../../reports/compiled-f4-runtime-path-admission-20261022.md)。

- [CVA6 CPU-programmed DMA RAM](2026-10-22-cva6-dma-ram.md)：有序单字读写、64 位 lane／来源链和正负例完整 fresh；实际状态见报告。

- [Compiled F4 second APB3 source: PULP SPI SPICMD](2026-10-22-compiled-f4-apb3-second-source.md)：将现有 source-reviewed APB3 storage executor 从 PULP Timer 扩展到 PULP SPI 的 SPICMD full-word 存储/读回；Attempt5 的四条 native first/fresh RAM-witness 记录及独立审计通过；不启动串行 SPI、不扩为任意 APB3 或 F6，P7-E overall 仍须独立验收。见[结果报告](../../reports/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022.md)。

- [Vexii CPU-programmed DMA RAM](2026-10-22-vexii-dma-ram.md)：标准Runner queued reduced-AXI CPU→DMA→RAM→CPU；attempt3实际exit0、正负例各完整fresh，独立证据审计PASS。六CPU／四IP与P6/P7/P8总门仍开放。

- [CVW CPU-programmed DMA RAM](2026-10-22-cvw-dma-ram.md)：本地原生 attempt1 exit 0／139.83 秒；正例和错误 key 各自完整 fresh，八个原生进程 exit 0；独立证据审计 PASS。物理桥、IRQ/ISR、通用 D4/F6 与整体系统门仍开放。

- [BOOM uncached shared-memory CPU-programmed DMA](2026-10-22-boom-shared-memory-dma.md)：positive/stale-key first/fresh 原生门通过，独立数据流与输入归档审计通过；仅覆盖 uncached shared-memory 四字 DMA cell，整体 CPU/IP 与阶段门仍开放。

- [Live AHB-Lite target protocol evidence](2026-10-22-live-ahb-target-protocol-evidence.md)：把生成式 AHB-Lite target 的现有 raw/projection journal 接入通用协议证据与 L1 coverage report；CPU OBI 多端点投影保持原样，协议报告不授予功能或因果反馈。

## 当前唯一总计划

[当前数据流 Fuzz 实施计划](2026-10-06-current-dataflow-fuzz-implementation-plan.md)分为“最终目标功能”和“逐阶段实现情况”两部分，并逐项覆盖原始 Word 文档的取指、数据读、数据写、MMIO、中断和 DMA 六类流。需求口径以 [当前设计](../../CURRENT_DESIGN.md) 为准；具体组合的实际能力以 [运行能力表](../../LOCAL_HARNESS_RUNTIME.md) 与 [报告索引](../../reports/README.md) 为准。

## 仍适用的专题契约

- [Native exact-source completion r11 controller](2026-10-22-native-completion-r11-controller.md)：one-shot controller、post-gate runner 与版本化合同已有实现。可执行软件验收修复嵌套身份副本和数字伪布尔；九文件 **266 passed、3 skipped、32 subtests passed**，Task 4 仍仅部分覆盖。Stage 1 清单 SHA-256 `a944ef09f414642541854d36955a81b906f213b4705b2e09cc96372de7f84059`，两位独立精确摘要复核均接受该版本，回执已更新；Stage 2 快照、上传与真实 gate 尚未执行。

- [P6 逐协议行适配清单](2026-10-13-p6-per-protocol-row-checklist.md)：把 P6 五行验收句落成逐行可执行清单，含**实测**的模板契约口径（**12 个**：新增从机侧 `target.axi4-lite`）、每个 CPU profile 声明的协议端点、可规划的目标端 profile 清单，以及逐行的"已有什么/缺什么"。结论：行 1/2/4 主要是"接线已有能力"，**行 3（AXI4-Lite）是最短路径**（CPU 与 IP 两侧均可规划、IP 已有独立证据），**行 5（Pico 原生 Ready/Valid）缺口最大**（需新增 MMIO 目标与路由）。**行 3（AXI4-Lite）已闭合**（通用事件层第四种协议、通用寄存器观测 kind、声明式 8N1 peer、多例持久会话与受控错误负例，均有真实 RTL 证据），行 1/2/4/5 仍开放；另新增 **§1.4 CPU 适配目标与协议对应（权威口径，六核）**。

- [P7 已支持协议范围内自动接入与自动测试实现文档](2026-10-13-p7-automatic-onboarding-implementation.md)：把 P7 验收句拆成 D1–D4 可判定交付与 A–E 五阶段路线（声明核对器 → 组合级生成 → 路径/输入编译 → 自动跑通与分级报告 → 端到端验收），含真实入口清单、目标产物、逐阶段验证命令、六项实测陷阱与边界。**P7-A/D1 与 P7-B/D2 已有实现**；P7-C/D3 已支持若干静态编译和 bounded execution slices；P7-D/D4 已有具名在线家族、D4-A/B DMA topology software binding、PULP GPIO APB3 target admission 与编译 F4 executor 等分片证据；P7-E 的广泛同协议新组件自动接入验收仍开放。各门的真实范围见该文档 §10、本 README 下方专题计划和报告索引。P7 可自动接入的形态上限仍由 P6 已验收协议子集决定。

- [第二阶段通用 CPU／IP 声明式适配](2026-10-09-stage2-declarative-cpu-ip-adaptation.md)：保留既有架构，细化 L1–L3、基础／功能事件、三类依赖、四核五类 IP 与未知 HMAC 基础接入门禁；M0 实施中，A1/A3 已登记，真实短门禁被启动内存预算拒绝；不提升能力等级。

- [P2 Task4来源与逐边证据](2026-10-06-source-provenance-task4.md)：来源/见证、真实RVFI退休和UART帧已接入；完整寄存器/FIFO/IRQ因果仍待验收。

- [P2 运行路径契约实施](2026-10-06-runtime-path-contract-implementation.md)：有边身份的路径、显式节点映射、静态预检、新 decoder 与真实逐边证据；实施中，不替代总计划验收。

- [持续状态与多组件场景实施基线](2026-09-27-persistent-multicomponent-fuzz-implementation.md)：内存、事务、reset、IRQ、replay 的详细验收编号；其中早期外设范围与完成状态按当前总计划重新解释。
- [生成式本地运行时](2026-10-04-generated-local-runtime.md)、[生成式本地模板契约](2026-10-04-local-template-contract-registry.md)、[源码锁门禁](2026-10-04-local-source-lock-gate.md)：生成单组件 harness 的分项实施记录。
- [在线持续批次](2026-10-05-online-stateful-scenario-batches.md)：同一 testcase 连续输入的已有实现与受限范围。
- [仓库清理记录](2026-10-06-current-design-repository-cleanup.md)：已移出文件和保留引用的依据。

## 定向组合计划

- [Ibex → ZipCPU DMA → Caliptra SHA256 → Ibex ISR](2026-10-21-ibex-caliptra-sha-dma-isr.md)：补齐 fresh replay schedule heartbeat 后，attempt15 positive/fresh **1 passed／98.59s**、attempt3 wrong-offset refusal **1 passed／46.15s**；first/fresh heartbeat 各19个检查点。报告见[切片报告](../../reports/ibex-caliptra-sha-dma-isr-20261021.md)。单字 DMA 只触发 `CTRL=5`，SHA 输入由 host AHB 预装；F6 仍 unsupported，remote/generic/multiword/aggregate gates 未关闭。
- [CV32E40P → ZipCPU DMA → PULP GPIO → CV32E40P ISR](2026-10-21-cv32e40p-zipcpu-pulp-dma-isr.md)：assertion-strengthened positive/fresh attempt8 **1 passed／69.28s**，309 steps；三个 ISR 读取均按 OBI source sequence 5/8/10 关联 receipt 与 consumed response，normalized comparison `equal=true`，CPU/DMA/GPIO 退出码均为零。focused software gate **5 passed／54.96s**，并覆盖同组件 profile-fingerprint 漂移在 D4/native 启动前拒绝。attempt7 因 tuple/list 比较断言退出 1，原始证据保留且不计通过；attempt6 `PADOUT+4` 拒绝门 **1 passed／32.44s**，`uncertain_effect` 边界如切片报告所述。报告、总体进度与运行能力文档已同步。
- [P7 post-live compiled F6 runtime path](2026-10-21-p7-compiled-f6-runtime-path.md)：补齐 Task 2 回归覆盖后的六文件软件门 **201 passed／378.04s**；隔离本地 native first-positive/refusal/fresh-positive gate **1 passed／73.87s**，独立证据审计 APPROVED。远程 target SSH exit 255（`No route to host`），故本门在本地独立 cache/evidence 路径运行。静态 F6 仍 unsupported；P7-E、P6/P7/P8 与六 CPU／四 IP 总目标仍开放，见[状态报告](../../reports/p7-f6-runtime-path-caliptra-20261021.md)。
- [P7-D4 protocol-neutral DMA route admission](2026-10-21-protocol-neutral-dma-route-admission.md)：统一 D4 exact route-consumption gate 的原始 PULP APB3／ZipCPU Wishbone slice 有 software gate **68 passed**、PULP native **2 passed**、ZipCPU native **1 passed**；后续 Caliptra AHB-Lite 消费见[独立计划](2026-10-21-caliptra-protocol-neutral-dma-route-consumption.md)，focused software gate **41 passed**、native/fresh/refusal gate **1 passed／92.11s**。
- [P7-D4 Caliptra protocol-neutral DMA route consumption](2026-10-21-caliptra-protocol-neutral-dma-route-consumption.md)：generated Caliptra SHA256 AHB-Lite 以单次 D4 bind 消费 RAM-read 与 CTRL-write routes，native 正例、独立 fresh replay 和 `CTRL+4` 拒绝均通过。F6、P7-E 与 P6/P7/P8 总验收仍开放。
- [P7 compiled F6 DMA handoff](2026-10-21-p7-compiled-f6-dma-handoff.md)：有界实现已通过 software/native/fresh/refusal 门，报告与证据见[P7 F6 handoff](../../reports/p7-f6-compiled-dma-handoff-20261021.md)。完整 P7-C `compiled_paths.v1` 进入 Caliptra D4 单次 live bind；F6 仍 `unsupported`，不生成静态 DMA runtime edge，也不关闭 P7-E 或整体目标。
- [P7-D4 PULP native route consumption](2026-10-20-p7-d4-pulp-native-route-consumption.md)：D4 single bind 与真实 native RAM→PULP PADOUT transaction join 已完成；原生/fresh 门 2 passed，联合软件门 236 passed、61 subtests。D2/D3 F6 仍 unsupported，P7-E 与总体验收仍开放。
- [P7-B/P7-C 静态 DMA route intent v2](2026-10-20-p7-d2-d3-dma-route-intents.md)：静态 route 声明与 profile/template/resource bindings 穿过 D2 生成和 D3 路径编译；F6 继续等待 live topology binding 与真实 runtime transaction。
- [P7-D DMA intent topology binding](2026-10-20-p7-dma-intent-topology-binding.md)：D4-A、D4-B Tasks 2–5 已有软件实现与审查；required save/replay envelope 维持历史 inner bytes，D2/D3 route/binding rows 复用已有 typed graph，联合门 166 passed、30 subtests。F6 仍 unsupported，且无 native DMA transaction / native replay 声明。
- [P7-D4 PULP GPIO APB3 admission](2026-10-20-p7-d4-pulp-gpio-apb3-admission.md)：第二个 peripheral target 正例限于 sealed generated PULP GPIO `gpio.bus` APB3 与 PADOUT full-word 写；guarded route-fit lookup 复用原 prepared graph，并拒绝缓存/provider/topology 漂移。联合软件门 209 passed、61 subtests（250.50 秒）。F6 与 runtime DMA transfer edge 仍关闭；本切片未运行 native/remote gate。
- [P7-D4 ZipCPU UART Wishbone admission](2026-10-20-p7-d4-zipcpu-uart-wishbone-admission.md)：generated `GeneratedWishboneUartSession` / `uart.bus` Wishbone classic 的 D4 正例只接入 TXREG offset 12 full-word 写；七类 provider/static/template 负例在 bind 前拒绝，topology guard 继续复核 provider 方法和身份，live target window 由原 prepared binder 验证。联合软件门 186 passed、30 subtests；F6 与 runtime DMA transfer edge 仍关闭，无 native/remote gate。
- [P7-D4 Caliptra SHA256 AHB-Lite admission](2026-10-20-p7-d4-caliptra-ahb-admission.md)：exact generated `GeneratedAhbLiteRegisterSession` / `sha256.bus` 的 D4 正例只接入 CTRL@0x10=5 full-word 写；guard 复核 MRO-resolved provider methods、code objects、identity、stable config 与 trace signal mapping。联合软件门 200 passed、30 subtests；F6 与 runtime DMA transfer edge 仍关闭，无 native/remote gate。
- [编译 F4 的 APB3 执行身份绑定](2026-10-20-compiled-apb3-f4-execution-binding.md)：给不按 CPU/IP 名称分支的 compiled-F4 executor 加入可复核的 D3/artifact-bytes/layout/OBI/producer/window/assertion identity；以 CV32E40P OBI + 已注册 PULP `TIMER0_CTRL` APB3 作为同 CPU 协议 sibling 实测。此计划只复用既有 timer 源合同，不扩成任意 APB3，也不关闭整体 P7。

- [P7 I5 CV32E20 + PULP Timer current-source supplement](../../reports/p7-i5-candidate-20261018.md)及[独立验收审计](../../reports/P7_I5_ATTEMPT1_INDEPENDENT_AUDIT_20261022.md)：5/5 selected compiled-F4 cases certified、full fresh replay matched，并保存 original/fresh process exit audits 与 wrong-CPU CLI refusal。普通 online session 仍为 `runtime_path_status=legacy_unchecked`，D2 harness binary/build identity 与有效吞吐门缺失；P7-E/P6/P8 仍 OPEN。

2026-10-05 的 `ibex-*`、`cv32e40p-*`、`cva6-*` 和 `picorv32-*` 计划只描述各自锁定的 CPU/IP 组合与源码身份。它们是当前能力的实施历史，不能合并成“任意同协议组件自动接入”的验收。

## 历史目标计划

2026-07 至 2026-09 的 `*soc*`、`*composition*`、`*scheme*` 计划，以及 [2026-09-14 SoC 生成总计划](2026-09-14-soc-composition-and-fuzz.md)，记录完整总线/互连生成和早期 RFuzz 对照路线。这些文件留在原路径以维持交叉引用和证据检索，不再决定当前工作的完成标准。

判定某任务是否完成时，先找当前总计划的验收门禁，再查看对应源码身份的真实 RTL 报告；计划中的“通过”文字本身不是当前工作树的运行证据。
