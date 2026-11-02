# 当前工作进度与证据入口

更新：2026-11-02 深夜（P0 收尾 + P1 五路增量）。本轮把 P0 之后剩下的五个边界一起推进，并在同一棵最终树上重跑代表批次：**混合协议多目标**不再只支持「一对协议」——APB3+TL-UL、APB3+Wishbone、APB3+AXI4-Lite+TL-UL、APB3+Wishbone+TL-UL 各 8/8，每个目标自己选适配器/完成判据/计数器（`runs/p1-mixed-protocols/`）；**IRQ 拓扑任意化**——三目标三 link 9/9、三目标四 link 9/9、PULP I2C 有序两写 ack 2/2（含失败负控 `level_stuck 1`）、CVA6 `irq_i[0]` 真实 take 3/3 且以 `mcause` 回读为见证（bit1 由 profile 常量 0，报 `cpu-vector-partial`，不冒充向量），NMI/PLIC/vector/W1C 按名拒绝（`runs/p1-irq/`）；**DMA 路由覆盖四种目标协议**——TL-UL/Wishbone/AXI4-Lite 目标各跑真实固定读/写，case 行给出该目标自己的协议计数，AXI4-Lite 完成判据改成按事务增量（`runs/p1-dma-route/`）；**每模型时钟**按声明频率归一成整数半周期比（50/25/10 MHz 单会话实测 318/159/64 上升沿），非整数比/快于参考 CPU/超界/契约冲突按名拒绝，并生成 25 个 CPU profile 的能力矩阵（`runs/p1-timing/`、`docs/cpu-capability-matrix.md`）；**行为声明**扩展有序 `clear_sequence`、命名 `pin_groups`/`serial_peer` 与 DMA `capabilities`（能执行的真执行，不能的在声明层按名拒绝）；**替换样本**只改 profile/config 就接入新 CPU（`picorv32_wb_irq_rvfi` F1–F6 6/6）、新 IP（`opentitan_uart_local` TL-UL F1–F5 5/5）与新 DMA profile（F6 5/5），见 `runs/p1-replacements/`。最终代表批次 `runs/final-verify-p1/` 13 批 64 例全部 `observations_passed`/`matched`（210 s），综合测试 **1758 passed**。汇总见[P1 验收报告](reports/p1-acceptance-final-20261102.md)。仍拒绝：AHB-Lite 目标适配器、Wishbone/AXI4-Lite 目标的 F5、NMI/PLIC/多位 vector、只 W1C 的清除、DMA 多通道/宽 beat/多 outstanding、串行 peer、非整数时钟比、快于参考 CPU 的模型、CVW/AHB CPU 的 F1 退休面与 F5/F6、IP-only 的非 APB3 目标。

更新：2026-11-02。IRQ/F5 完成触发/清除分离、声明的 cause 采样、单目标多 link（PULP Timer overflow/compare 真实 F5）与 PULP I2C level IRQ + 一次清除写；GPIO cause 读清有真实批次。完整 AXI4（CVA6）已接入统一入口并跑通 F2/F3/F4 固定 3/3、连续 fuzz 30/30；F1/F5 因归档未导出 RVFI/commit 按名拒绝。多 IP、DMA 扩展与 F1 地址/分支/压缩当时只有声明/模块/测试（**2026-11-02 深夜更正：混合协议多目标、DMA 路由到四种目标协议、F1 地址/分支/压缩均已接入并跑真实 RTL，见本文件上方条目与 [P1 验收报告](reports/p1-acceptance-final-20261102.md)**）；跨例电平风暴的 case 内检测仍未完成。证据见 `docs/reports/irq-generalization-20261102.md`、`docs/reports/round1-axi4-integration-20261102.md`、`docs/reports/round1-generalization-progress-20261102.md` 和 `runs/round1-axi4-unified/`。

更新：2026-11-01。统一单进程入口新增闭环 `--fuzz`：同一进程按真实 case 观察生成/变异下一输入，不再要求预先给出 `--records`；F1 可声明 1–16 条直线 RV32 短程序并回报真实退休/写回/数据窗口变化；F5/F6 的等待有界，超时按 finding 记录并只复位设备。设备行为（IRQ 触发/状态/清除、引脚、DMA 控制状态位）可用 `source_behavior`/`dma_behavior` 文件声明。真实批次覆盖 Ibex/Timer/ZipDMA、GPIO 引脚、PicoRV32 Wishbone、AXI4-Lite UART+ZipDMA、CV32E20 与 wbdmac，证据见[闭环证据](../runs/stage2-fuzz-loop-20261101/README.md)，用法见[闭环使用说明](inprocess-fuzz-loop.md)，分项计时见[性能报告](reports/fuzz-loop-performance-20261101.md)。仍未完成：在线 RTL 覆盖率、证书、完整 replay、跨 testcase 状态消费认证、AHB-Lite/完整 AXI4 CPU 的新执行器适配、多 IP 自动组装和 DMA 到 IP FIFO/多宽度。2026-11-01 晚的六项任务已落地并复验：GPIO 同步器误报修正/失败分类/超时恢复（`runs/stage2-task1-fix-20261101/`）、60 s/200k 长跑内存边界（`docs/reports/fuzz-longrun-20261101.md`）、PULP I2C 仅声明接入（`docs/reports/new-ip-onboarding-20261101.md`）、8/16 字程序与 AUIPC 真实退休（`runs/stage2-fuzz-programs-20261101/`）、输入前缀重放（`runs/stage2-prefix-replay-20261101/`）、统一批量验收（`runs/stage2-acceptance-20261101/`）；2026-11-02 凌晨又完成 Wishbone 连续 F1–F6（`runs/stage2-wb-six-20261101/`）、CVW AHB F2–F4（`runs/stage2-ahb-unified-20261101/`）、PULP SPI 进入 fuzz（`runs/stage2-newip2-20261101/`）、IRQ/F5 声明扩展（`runs/stage2-irq-decl-20261101/`）、wbdmac F6 声明（`runs/stage2-dma-decl-20261101/`）和子字程序真实执行（`runs/stage2-wb-six-20261101/subword-*`）；AXI4 CPU 仍只有原生探针/分析，未进统一入口。当前组合与限制以[能力盘点](current-system-capabilities-20261101.md)为准。

更新：2026-10-30。最新状态与逐项范围以[通用化系统完成审计](reports/universal-system-completion-audit-20261028.md)顶部“2026-10-30 末，冻结窗口原生批次”为准：CV32E40P 声明式 F5、复位/多源/异常/跨协议定向原生、新路径覆盖率与轻量同工作量 A/B 已完成；完整八例 A/B 受主机内存限制。

更新：2026-10-28。以下证据按各自源码快照和范围解释；历史矩阵、远程门及研究实验不因新功能基线通过而自动关闭。

## 配置驱动搜索、重放与比较（2026-10-28）

现有组件范围内的 F1–F6 功能基线已通过验收：生产入口统一使用 `run_dependency_search.py --scenario`，CPU/IP 组合由配置选择并复用现有独立 RTL 执行器。联合软件门 **336 passed / 26.57s**；Timer + Ibex、SPI + CV32E40P、F1/F3 mixed、F5、F6 均有原生执行及严格 fresh 证据。F6 已修复生成目录污染身份和 raw nonce hash 跨调用误比较。

真实比较入口验证了 Timer 两策略 primary comparable、F5 两策略执行及 fresh 成功但未知指标保持 unavailable；当前比较器导入已有真实 DUT 测量后 coverage_comparable=true。缺少 provider 的路径保留 unknown，不声称已获得状态引导收益或效率提升。功能基线不代表完整通用化：当前主要任务仍是 F1–F6 共享运行、实际消费反馈和组件适配复用验收，同时削减运行开销。

使用方式见[配置驱动搜索](CONFIG_DRIVEN_SEARCH.md)，逐项范围、版本边界和原始证据见[本轮验收报告](../research/input-strategy-audit-20261027/config-driven-system-acceptance-20261028.md)。

第一轮提速已落地：prepared cache 命中时合并重复源码读取，冷准备前后检查保留。Timer 单组相同输入测量，搜索区间 **26.14 → 22.28s（−14.75%）**，总耗时 **105.06 → 98.62s（−6.14%）**；输入、语义哈希一致，独立 fresh 与实际 binary/source/nonce 复核通过。相关 root 软件门为 **53 passed + 3 subtests**。单组结果不代替多负载统计或覆盖率实验，见[提速报告](reports/native-validation-speed-20261028.md)。

第二轮流程提速已落地：CLI 默认 search，静态认证移到会话边界，普通搜索跳过无条件重放，真实新关系选择重放。Timer 最新单例搜索 **2.48s**，整条命令 **39.59s**；GPIO 自动独立 fresh 已通过。失败材料导出与有超时的独立复现已接入，真实 DUT bug 复现仍缺原生样本验证。见[流程验证报告](reports/execution-workflows-20261028.md)，请勿将热循环时间当作整条命令耗时。

按用户要求继续精简防御逻辑：本地 search/develop original 默认静态依赖首次检查一次，省去终态全量复核；acceptance/fresh 保留完整检查。Timer 同参数单样本整条命令 **39.59 → 33.03s**，相关软件门 **185 passed**。策略假设、版本证据见[本地搜索精简报告](reports/trusted-search-20261028.md)。

启动复用第一步已实现：同输入 RTL 展开会话内复用，Git blob 跨读取器复用。Timer 实际展开 **22 → 2次**、逐文件 Git 子进程 **3202 → 242次**；重复运行约 **15.1–15.4s**，严格 fresh 通过。相关软件门 **256 passed + 47 subtests**。测量环境和剩余成本见[启动复用报告](reports/startup-reuse-20261028.md)。

源码锁会话复用和依赖扫描去重后，Timer 缓存命中单次 **11.25s**，严格 fresh 通过。搜索及相关测试 **219 passed + 18 subtests**，依赖扫描 **7 passed**；扩展 BOOM fixture 有7项无关失败，见[报告](reports/startup-reuse-20261028.md)。

通用化增量：F1/F3 支持独立 scenario，复用 mixed 执行器并通过原生 original/fresh；逐 case adapter 已接入 live storage，Timer 真实消费关系与选择性重放通过。GPIO live 已接入同一逐例接口，F5/F6 已改为执行后再选择并通过部分前缀 fresh；有限记录反馈依然 unknown。证据见[通用化记录](reports/generalization-step-20261028.md)。

最新通用化增量：F1/F3 与 mixed 的有限候选也按真实执行逐例选择，预算中止可回滚未提交决策；F1/F3/mixed 原生 original/fresh 已通过。F5/F6 分别复用自身持续 runtime，仍未实现同一 session 混跑 F1–F6 或全部路径的 live 反馈；证据见[通用化记录](reports/generalization-step-20261028.md)。

最新共享运行证据：RAM 当前版本与实际 writer/consumer 奖励已接通；共享 GPIO 的 F1/F3/F4/F5 和显式 F2 入口已有 original/strict fresh 证据。六例 GPIO 序列实际读取 PADIN 为 0/256/0，并产生相应 dependent RAM 写入；GPIO pin 消费关系向搜索奖励的接线也已原生通过，IRQ 消费仍 unknown。F6 公共装配已有双组件 original/fresh 证据，三组件真实 storage 操作与 F6 交错尚未验收。详见[完成审计](reports/universal-system-completion-audit-20261028.md)。

GPIO live 反馈新增原生证据：`research/input-strategy-audit-20261027/runs/pin-live-20261028/state`，实际六例 F4/F2/F4/F5-low/F5-low/F2。首次 F2 保持 unattributed，最后 F2 认证最后一次 F5 的实际 PADIN→OBI→dependent RAM 消费，前一次同值 F5 不获该关系奖励；original 和独立 strict fresh 的一条语义关系集合相等，所有 fresh verification 均 verified。original 在 cProfile 下执行 163.08s，超过120s预算43.08s；fresh 未加 profiler，执行65.42s。两次耗时不能当作优化前后比较。完整性能目标仍未达到。

F6 三组件首次原生失败原因已定位并保留：`runs/three-component-20261028/f6-storage-debug-1/first_failure_diagnostic.json`（位于研究 runs 目录），CPU/DMA 分别推进44/43周期，storage仅1周期；固定两组件 bootstrap 调度遗漏 storage，造成真实 CPU OBI response 等待16周期后协议违例。正在修复调度，不放宽 checker；该次不计通过。

调度修复后的 F6 三组件 original 已 complete：`research/input-strategy-audit-20261027/runs/three-component-20261028/f6-storage-support-schedulefix/prefix.json` 中 before/after 分别为85/170，各有8条真实取指、2条CPU MMIO及dependent RAM证据。strict fresh 在语义比较前被 build join 的旧双组件限定拒绝，当前仍未通过；正在将声明的 storage companion 纳入全部构建凭据核对。固定 boot/tail support 仍不代表动态 F4/F6 selector 已实现。

GPIO 两策略同预算原生比较已通过：`research/input-strategy-audit-20261027/runs/pin-live-20261028/optimized-compare/comparison.json`，state/uniform 各8例、预算120s，original执行69.73/54.38s，独立strict fresh执行64.60/52.73s，各一条真实消费关系。两策略覆盖率均48/189，回放分别1034/1031条结果且原始/插桩/录制回复一致；primary、execution及coverage均comparable。仅seed7，不作策略优劣结论。后续事件借阅优化尚待原生验收，以上数据不代表其性能。

最新长前缀覆盖率验收：`research/input-strategy-audit-20261027/runs/long-coverage-20261028/shared-f2/comparison.json` 中共享 GPIO F2 搜索 4 例和 strict fresh 均成功；实际回放 518 条结果、530 ticks，显式命令预算 2048，plain/instrumented/录制回复一致，DUT 覆盖 48/189。这是离线完整前缀覆盖率，不代表在线固定时间覆盖率。该次搜索执行阶段 23.04s、整条 original 命令 47.30s，性能目标尚未达到。

完整 F5 的剩余要求：共享 pin 提交当前使用固定 NOP support，尚未配置中断 CSR/bootstrap/ISR，也未启用 CPU native IRQ 消费回执。GPIO→PADIN→dependent RAM 的数据消费证明不能替代 IRQ acceptance/ISR 证明；需要补实际中断接受、handler 执行及其 MMIO 消费验收后，才能关闭完整 F5。

回执复制精简：`ScenarioRunner.events_since` 支持独占 stop，旧例查询/重试只复制本例事件区间，不再先复制全部后续事件；metadata 单独复制，保留返回值隔离。journal/session 专项门 **27 passed + 3 subtests / 0.40s**，独立审阅通过。尚未测量原生性能增益。纯编译 cProfile 的 10 次测量合计 0.057s，不能将重复编译认定为 23s 执行阶段的主要瓶颈；待共享路径冻结后测完整执行。

逐 tick 复制精简：调度器内部 `step` 复用原命令状态机，只复制返回的 outputs，避免复制随后丢弃的完整 StepReceipt/events；公开 `execute_step` 首次与重试仍返回完整独立回执。STEP 重试、未知效果、epoch、GPIO tick、partial replay、journal/session 联合门 **51 passed + 5 subtests / 0.58s**，独立审阅通过。原生耗时收益待冻结后测量；仓库没有依赖重写 `execute_step` 的调度器子类，外部此类重写不再作为 `step` 钩子。

## 2026-10-25 起的历史检查点

## 系统验收状态

| 范围 | 最近记录的结论 | 证据与待办 |
|---|---|---|
| 六 CPU / 四系列 IP | 各有分开的固定实例、有界运行证据；6×4 联合验收 OPEN | [DMA 状态审计](reports/dma-six-cpu-four-ip-status-20261022.md)；CPU 为 Ibex、CVA6、CV32E40P、BOOM、CVW、VexiiRiscv，IP 系列为 OpenTitan、PULP、ZipCPU、Caliptra |
| F2 / F4 | 有界编译执行、F2 RFuzz 入口与 F4 兼容门已有独立审计通过记录 | [F2/F4 汇总](reports/f2-f4-current-acceptance-20261023.md)、[F2 RFuzz](reports/compiled-f2-rfuzz-entry-20261023.md)；限已登记 RV32I OBI/APB3 storage 合同 |
| F6 | 软件证据链继续补齐；完整真实 original/fresh 正例及预期错误归档、独立 raw audit OPEN | [跨组件边及取指凭据](reports/f6-cross-component-edges-20261025.md)、[Wishbone 双端 checker](reports/f6-wbdmac-dual-endpoint-checker-20261025.md)；Freeze15 为 **4 passed / 5 failed，FAIL_PRESERVE** |
| 同协议通用接入 | 固定 provider/session 的有界接入已有证据；无名称分支的任意同协议接入 OPEN | [缺口审计](reports/generic-protocol-onboarding-gap-20261025.md) |
| P6 | 固定实例 campaign 的证据不等于字面要求的持久单 harness、多 case 和闭环四次命中 | [逐协议清单](superpowers/plans/2026-10-13-p6-per-protocol-row-checklist.md)；P6 总门 OPEN |
| P7-E | 有界实例、D1–D4 和补充审计已有记录；自动接入正式总门 OPEN | [P7 计划](superpowers/plans/2026-10-13-p7-automatic-onboarding-implementation.md) |
| P8 | S2/S3/S4 有真实门；S1c 5× 未达到，历史测量为 **1.37×** | [P7/P8 真实门](reports/p7-p8-real-gates-20261018.md)、[总计划](superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md)；P8 总门 OPEN |

## 最近 F6 检查点

Task9 在 Ibex/CVE2 原生 OBI 响应路径签发 source-bound completion，并在 `instruction_source` 发布 F6-only acceptance anchor。记录的最终 source closure 为 `67221f53…0703d3`：producer **57 passed / 536.09s**，anchor focused **5 passed**；Task10 saved semantics **324 passed**、saved verifier **87 passed**、saved outputs **15 passed**，live edge-3 正例及边界 **9 passed / 176 deselected**。这些软件检查不等于真实 DUT/F6 原始归档验收。精确哈希与证据见[跨组件报告](reports/f6-cross-component-edges-20261025.md)。

Task8 远程 attempt16 已失败并保留：**744 passed、106 failed、868 errors、12 skipped、10 subtests passed，exit 1**。运行包缺少 `runs/task4-ibex-retire/rvfi-export-manifest.json` 以及 profile pin 所需 Git 对象/身份元数据。见[终态记录](../.superpowers/sdd/compiled-f6-20261024/tasks/task-8-software.md#2026-10-25-attempt16-terminal-source-closure-failure)。

source-closure 修复已在本地接线：清单包含 RVFI manifest 与 **16** 个 exact Git repositories 元数据包；记录的输入清点为 **22,939 files**。metadata **21 passed**、监督器 **45 passed**，合计 **66 passed**。freeze04 只完成独立审查，未执行；freeze05 被拒后已修复相关元数据问题。**最后文档检查点中，最终候选尚未重新冻结/审查，attempt17 尚未执行。** 本轮整理未通过 SSH 查询远端状态。下一步见[冻结源码闭包计划](superpowers/plans/2026-10-25-f6-frozen-source-closure.md)。

## Native exact-source completion / r11

本地 Task5 三分支有真实门记录；远端 Stage2 包已准备、审查并上传，但控制器在 claim 前拒绝自己的 preflight 文件；后续 SSH 超时。远端 one-shot gate 和独立 post-gate auditor 未通过。记录见[2026-10-23 检查点](reports/codex-progress-status-20261023.md)。本轮没有远端探测，本地结果不替代远端验收。

## 通用运行框架 G0–G6（2026-10-26）

按 `docs/superpowers/plans/2026-10-26-generic-runtime-ds-implementation-plan.md` 执行：
G0 基线冻结、G1–G5 软件门通过（合同/受信认证/唯一选择/APB3 provider/同次 D2/D3
计划与 prepare CLI/持久引擎）。**G6 首切片 PASS**：两个已登记 APB storage 源
（PULP timer `TIMER0_CTRL`、PULP SPI `SPICMD`）各跑真实 3 例持久 F4（CPU 写 +
读回 + 跨例 prerequisite 读取，证据全部 certified）与跨进程 fresh（plan 字节一致、
PID 不同、replay 匹配）；改名实例、真实非 alias 地址 effect 前拒绝、真实
`generic_runtime_bundle.v1` original/fresh 验证与 8 类篡改拒绝均通过。设计 §5.2 的
**混合 F2+F4 单 session directed 序列**也已真实通过（一条 session：F4 写 0x55 →
F2 CPU 读取该前例值并 XOR 存 RAM → F4 写 0xaa；三例证据 certified，跨进程 fresh
plan 字节一致、PID 不同、replay 匹配）。真实门
`tests/integration/test_generic_storage_native.py` 9 passed（需
`MYFUZZ_RUN_GENERIC_NATIVE=1`，未设时不计通过）。剩余：混合 RFuzz wire、混合
saved bundle、改名实例 fresh，以及 G8–G10 尚未开始。详见
`docs/reports/generic-runtime-g0-g6-20261026.md`、`runs/generic-runtime/G6/task-report.json`
与 `runs/generic-runtime/G5/mixed-addendum.json`。

**G7 PASS（声明式接入范围，2026-10-26）**：新增真正不同的 PULP `apb_gpio`
`PADDIR`（offset 0）APB3 storage source。只新增 source-contract 登记、storage
profile/capability、scenario/矩阵 fixture 与测试；未改 registry 匹配算法、APB3
adapter、storage kernel、compiler 或 engine。真实 GPIO 3 例持久 F4（CPU 写 +
读回）original/fresh 均 certified、plan `ba1f5ee0…` 字节一致、PID 不同、replay
匹配；改名 `gpio0` 真实 3 例；混合 F4+F2+F4 单 session 真实 original/fresh
（F2 读前例 `0x55`，RAM `1520=0x55^0x5a5`，plan `7982dd61…` 一致）；真实非 alias
`window_base+4` effect 前拒绝；14 项错误语义/相似名/模板负例全部拒绝；saved pair
52 checks verified、8 类篡改拒绝。共享功能源码 SHA 除
`runtime/semantics/storage.py` 一处 docstring 外不变。armed G7+G6 原生证据门
8+9 passed。详见 `docs/reports/generic-runtime-g7-gpio-20261026.md`、
`runs/generic-runtime/G7/task-report.json` 与 `runs/generic-runtime/G7/mixed-addendum.json`。

**G8.1a 进行中（PARTIAL，2026-10-26）**：Wishbone 迁移先落第一片。选定 WBUART
`SETUP` @ word index 0 作为 scoped Wishbone storage source（只声明该 32 位字稳定；
UART RX/TX/FIFO/IRQ/serial 明确不声明）。新增
`zipcpu-wbuart.setup.storage.v1`（digest `3dc8b5e2…`）、storage profile/capability、
`compiled-f4-obi-wb-uart-setup` 场景；真实 target-only 测试 1 passed（SETUP 写
0x55 读回 0x55，fresh replay 匹配），Wishbone 软件门 77 passed/2 skipped/26
subtests。D3 已产出 executable Wishbone F4/F2（artifact
`wishbone_register_observe` + `wishbone_cpu`），但 D4 仍拒绝
`compiled-F4-CPU-protocol-unsupported`/`register-word-shape:`；尚无 Wishbone
adapter/probe/consumer/executor 与 CPU→target native。**G8.1 未 PASS**，也不关闭
G8.2–G8.10。详见 `docs/reports/generic-runtime-g8_1a-wishbone-20261026.md`、
`runs/generic-runtime/G8/G8.1a-report.json` 与 `G8.1-SCOPE.md`。真实
PicoRV32 Wishbone master→WBUART SETUP 的单例和 3 次持久写/读回 + 新 session
复现均已通过（各 1 test），但仍是 transport 证据，不是 generic F4 计划/consumer。
并行子代理已落地 Wishbone probe/verification/authority/consumer、target/CPU
adapter、renderer 11-port probe；lead 已接 registry 4 rows、binding factories、
admission verifiers 与 `(role,protocol)` compiler expectation。软件门待汇总；
native 仍缺 Wishbone F4 producer/executor、reset/issuer dispatch 和 3 例
persistent/fresh，**G8.1 仍 NOT_PASS**。

**G8.1c 进行中（PARTIAL，2026-10-26）**：Wishbone target 侧真实 routed storage 与
producer row 已落地，F4 executor 仍未完成。真实测量出 WBUART `SETUP` 每 tick 的
`pre`/`post` + `storage_probes` 波形（请求首现于 `post`、唯一 `pre` 请求、寄存 ACK
在 T+2 且 CYC 保持、`stall=0`），据此实现
`GeneratedWishboneRegisterSession.routed_register_access` 与
`WishboneStorageRegisterVersionAuthority` 的 `_actual_begin`/`_actual_command`
（绑定真实 built receipt build digest、全样本状态机、单一 opaque token）；真实
routed 写 0x55 读回 0x55，唯一 commit `before 0x19 / after 0x55`，token 单次消费。
新增封闭 producer row `generic_wishbone_storage_abi` 与 `declare_wishbone_writer`
（`SETUP` 为 masked 行 `0x7fffffff`，新增按行限定的 `declared_masked_full_word_write`
声明策略，原有 `declare_writer` 拒绝未被放宽）。软件门 398 passed，真实
routed/target 2 passed，CPU→target 2 passed，G6+G7 归档证据 17 passed。仍缺
`compiled_f4_wishbone` executor、3 例 persistent/fresh 与 saved bundle，
**G8.1 仍 NOT_PASS**。详见
`docs/reports/generic-runtime-g8_1c-wishbone-20261026.md`、
`runs/generic-runtime/G8/G8.1c-native-sample-shape.md`、
`G8.1d-F4-RUNTIME-CONTRACT.md`。

**G8.1 PASS（2026-10-26，声明式接入范围）**：Wishbone classic storage 行真实通过。
新增 `compiled_f4_wishbone` executor（`admit_wishbone_f4`、`wishbone_cpu_traces`、
`wishbone_native_beats`、`check_wishbone_f4_exact_hops`、
`wishbone_normalized_semantic_sha256`、`WishboneF4Runtime`）、
`assess_compiled_f4_support` Wishbone 分支、`create_compiled_execution` dispatch 与
`WISHBONE_FLOW_EXECUTORS`；`GeneratedWishboneCpuSession` 增加与 OBI 同构的在线指令
源（`declare_instruction_slots`/`accept_instructions`）。真实 3 例持久 F4
（0x55→0x2a→0x12345678，write_count 1→2→3）与跨进程 fresh：plan 字节一致
`74f7166e…`、PID 不相交（2329999/2330057 vs 2331995/2332038）、每例 8 条指令 hop +
2 条 data hop + 结果 RAM 写、四态证据全部 certified、replay matches；bundle pair
52 checks verified（`bfacec06…`/`82e44f92…`），8 类篡改全部拒绝；armed G8.1 gate
5 passed（未 armed 为 5 skipped，不算通过），软件门 628 passed，真实 Wishbone 测试
5 passed，G6+G7 归档证据 17 passed。APB/OBI 共享文件由
`runs/generic-runtime/G8/G8.1-shared-core-freeze.json` 冻结且未变。**G8.1 仅覆盖
本报告列出的支持项**；Wishbone F2、混合 flow、native reset、probe 层次证明、
G8.2–G8.10、P7-E 仍未完成。详见
`docs/reports/generic-runtime-g8_1-wishbone-20261026.md` 与
`runs/generic-runtime/G8/G8.1-final-report.json`。

## 当前整理工作

本轮正在减少无调用的旧代码、迁移历史文档和整理本地分支。恢复清单、原文与 branch bundle 位于 `runs/repository-organization/20261025-deep/`；详细处置见[整理台账](REPOSITORY_ORGANIZATION.md)和[工作区地图](WORKSPACE_MAP.md)。整理改变了工作树，旧 frozen source map 继续仅证明其当时归档，不能代表当前源码。

## 历史记录与其他入口

- [完整进度流水快照](history/2026-10-25-progress-log.md)：拆分前全部内容，包含更早的阶段、失败、修复、测试数和被覆盖的状态；不作为当前进行中任务清单。
- [运行能力表](LOCAL_HARNESS_RUNTIME.md)：逐组件与协议的有界能力。
- [报告索引](reports/README.md)：按专题找原始运行记录。
- [计划索引](superpowers/plans/README.md)：按阶段查验收要求。
- [历史文档](history/README.md)、[技术参考](reference/README.md)、[源码导航](../src/myfuzz/README.md)。
