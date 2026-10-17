# P6 下一步实施与证据边界（2026-10-18）

盘点基线：本地 `50510545767b1caa7b6e3957b062478b9dbd5f0b`。本报告只读源码、已有文档和证据；未启动测试、工具前端、原生模型或远程操作。远程新工作集是用户声明的 `42a9ce9` 快照，不能直接视为本地 HEAD 联合验收环境。

## 1. 实际缺口

P6 固定实例 campaign 已有真实证据。行1 CV32E40P 为 online_cases；行2 CVA6、行3 AXIL、行4 Wishbone、行5 native 的归档 campaign 为 fresh_genomes。后四行缺跨例同一进程/RAM/Router 状态；每个 genome 内多轮传播不能代替持久会话。

最新汇总“持久会话、RuntimePathContract、closed-loop 未实现”应限于上述协议行接入和验收，不能作为整个仓库源码判断：

| 实际文件/入口 | 已有职责与限制 |
|---|---|
| `scenario/session_runtime.py:ScenarioSession` | begin、declare_instruction_slots、submit_case、configure_runtime_paths、encode_plan 已有。循环 record_scenario 不是此持久路径。 |
| `scenario/online_case_decoder.py:OnlineCaseDecoder` | 权重选源、指令槽、路径预检、proposal/commit、path switch 已有。指令槽采用 RV32 地址约束，support words 固定 RV32I；不能直接声明覆盖 RV64 CVA6。 |
| `scenario/runtime_path_contract.py:compile_runtime_path_contract` | 绑定实际 runner、端点、路由和资源；声明本身不证明实际消费。 |
| `scenario/runner.py:ScenarioRunner.configure_provenance`、`scenario/edge_provenance.py:EdgeProvenance` | 启动前安装逐边 producer/delivery/consumer 关联，支持 direct_binding/mmio_route/persistent_state。 |
| `integration/ibex_pulp_online.py:make_pulp_dual_source_online_runtime` | 已接 decoder、ScenarioSession、warmup、runtime contract、RFuzz executor；固定 GPIO/bootstrap/IRQ 检查点仍须适用性审查。 |
| `integration/cv32e40p_pulp_online.py:make_cv32e40p_pulp_online_runtime` | 已有 reset-free 在线入口，明确拒绝 cpu_retirement/native_irq_receipts。 |
| `integration/scenario_rfuzz.py:ScenarioRfuzzExecutor` | online_decoder/session、path_switch、closed_loop_energy、反馈权重及保存已实现。 |
| `scenario/chain_certificates.py:ChainCertificates`、`scenario/closed_loop_feedback.py:ClosedLoopFeedback` | 具名逐跳认证和 closed_loop/partial_propagation/stage_reached 已有；默认 producer 依赖 Ibex retirement/native IRQ，不能换 CPU 名就复用认证。 |

以上相对路径均位于 `src/myfuzz/`。下一步应接入各协议真实生产者和持久会话，不必重写通用反馈框架。

## 2. 最小实施序列

### A：先封闭行1的反馈能力边界

在 `integration/cv32e40p_pulp_online.py:make_cv32e40p_pulp_online_runtime` 与共享 `integration/ibex_pulp_online.py:make_pulp_dual_source_online_runtime` 明确各 CPU 可用 producer 和证据级别；不支持的 required-hop 请求在启动前拒绝。CV32 缺真实 retirement/native IRQ 合同，必须补真实 profile/driver/消费证明或保留 partial/stage；不能将最终 RAM 值改称退休证据。

先做软件负例，证明不适用的 producer/required-hop 不会静默降级；此步不授完整行1。

### B：在行2–5先增加一个持久最小样本

建议先行5 native/PULP GPIO：已有真实 queued MMIO，RV32 与现有指令模型接近，profile 无 IRQ，可先验收非 IRQ 数据路径。这是源码复用判断，不是实测性能排名。

现有落点为 `integration/picorv32_native_scenario_campaign.py` provider、`scenario/picorv32_native_cpu_example.py` fixture，以及实际 GeneratedNativeMemorySession/DeferredNativeMemorySession。新增独立 `integration/picorv32_native_online.py` 装配和 `scenario/picorv32_native_online.py` bootstrap/decoder/契约，保留旧18格的原证据解释。

1. 审查真实 CPU session 是否能在不 reset 下等待未交付取指并向预留 RAM 槽提交指令；缺接口时只补实际 session，保留缺字节等待、byte-enable 和 deferred MMIO 语义。不得用主机目标 ACCESS 替代 CPU 执行。
2. 一个 factory、一组 CPU/GPIO 进程、一份 PersistentMemory/Router/ledger，初始化一次。不可覆盖 bootstrap 的指令窗；至少3例，两侧源均真实选择/消费，不按方向标签强制轮换。
3. 用 ScenarioSession.configure_runtime_paths 编译实际端点、CPU→Router→GPIO、返回与真实持久资源边。每边保留具名 producer/delivery/consumer；没有 CPU 消费证据保持 partial。
4. 通过 submit_case 运行，保存初始化→第N例完整计划/事件；最后一次 finish/quiesce，不按例重建。
5. 如需新 certificate producer，先审查真实可观察逐跳合同与实际 receipt；不能借 injected producer 伪造证书或绕过 frozen hop/schema 检查。

首个 native 门只验收同一 PID/nonce/epoch 连续、两侧真实源、pending 排空、新进程完整 fresh 一致，并加受控响应扰动由独立 checker 检出。此门不等于18格搜索、吞吐达标或整行通过。

### C：四类反馈与其余行

在最小样本之后分别验收 stage、edge、state transition、closed-loop。保留现有 schema，通过报告映射到计划 stage_hits/edge_hits/state_transition_hits/closed_loop_hits。每个 hit 带 path/source/admission/事件引用；删除下游消费后不得继续计 closed-loop，重复证据不能重复奖励。

将实际反馈接入 ScenarioRfuzzExecutor 下一例权重，保存分配前后状态和 attribution；最后接 run_scenario_campaign/campaign_matrix 的18格和 uniform/independent 基线重新测量。旧 fresh_genomes 吞吐不能继承。

行4保留 Pico getq/maskirq/retirq custom0 ABI；行3保留 AXIL OKAY-only/error 字段限制；行2 CVA6 独立解决 RV64 地址、64位/ID4 AXI 单拍边界与实际消费观察。各行均需 full fresh、负例、源码/工具/构建身份后再升级能力等级。

## 3. BOOM与历史六CPU证据的矛盾

本地确有 `configs/cpus/boom/component_profile.json`、`interface_description.json`、`generated/source_manifest.json`、`generated/rtl.tar.gz` 和四份 materialized RTL。profile source revision 为 `sha256:4f960fdd6c96dccfe1bb7788fd628e368304b7280e5449cf3ae5463e982f2c30`；archive SHA 为 `9621a416043c15fa47d421f1623d2e190f081755e3c49fbd5d88b1baedb73219`；physical_ports SHA 为 `80878201d383247fc8eba54d7b4caa710c6b9e96bd62b346fe322ed5e7559310`。

README 记录 Chipyard `4180463d52bc0a6b4c004530601ccdabebf0ab7d` 和 BOOM gitlink `1ad28828673f2fce7a18f7255facd4705f04a58a`；派生 dependencies/IO patch 属于身份。冻结 `8a3fed3` 的持久 CPU/GPIO、后续 coherent/RAM 和 IRQ attempt3 均有独立历史报告。六 CPU 定向链只证明各自冻结实例，不授当前 P6 全协议在线能力，也不证明新远程副本有对应工具和可执行构建。

`docs/reports/p7-p8-real-gates-20261018.md` 写 BOOM “no generated profile/RTL/toolchain”，其中 profile/RTL 与本地具名资产冲突；toolchain 须按执行环境另查。只读 `runs/p7-i4-real-5051054/capability-report.json` 可见 `skipped_unavailable=[]`、summary 对应0，没有 BOOM unavailable 声明。因此该 I4 报告不能证明 BOOM 实测 skipped；历史资产存在也不能证明当前 BOOM 可运行。要记 skipped 须给出具体 run、unavailable 声明及本环境缺项；复用 BOOM 则必须匹配 source/profile/RTL/build executable/tool closure 并实际运行目标门。

CVW 最新 directed session 与 Vexii 固定 CPU/IP/IRQ 报告同样应覆盖旧“完全无能力”的描述，但不授持久在线或 P6 整行通过。

## 4. 后续验收产物

- 冻结源码/配置/第三方源与工具输入；远程按新 README、agent.md 建独立工作副本，遵守共享 heavy lock，保留旧证据。
- 软件控制与 native 分列；保留进程身份、构建身份、逐命令 receipt、完整原始边沿、事件引用、终态/回收记录。
- first/fresh 仅规范化声明身份；语义、时钟和逐边消费差异不可抹平。失败不覆盖、不自动重试后伪装首轮通过。
- 每行同步 LOCAL_HARNESS_RUNTIME、报告索引与 P6 checklist 后再改总计划。P6/P7/P8 整体继续开放。
