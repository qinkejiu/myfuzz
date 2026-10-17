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

## 5. Stage A 最小 admission 修正（源码增量）

只读追踪确认原缺口：CV32 入口只验证 retirement/native IRQ 参数；共享 online builder 先 session.begin/warmup，随后 ScenarioRfuzzExecutor 才通过 `_closed_loop_switch` 读取 `MYFUZZ_CLOSED_LOOP_ENERGY`。真值会实例化默认 Ibex ChainCertificates，而不是在 CPU 能力边界提前拒绝。没有请求时默认关闭，不影响历史 partial/阶段能力。

修正仅限 `src/myfuzz/integration/cv32e40p_pulp_online.py:make_cv32e40p_pulp_online_runtime`：增加可选 `closed_loop_energy`，复用原 `_closed_loop_switch` 的布尔/环境解析及参数优先级，在 generated-artifact admission、bootstrap、factory、begin 之前拒绝真值。将解析后的 false 显式传给共享 builder，避免后续再次读取环境。非法环境仍使用原 resolver 错误，显式 false 按原规则覆盖环境 true。共享 Ibex builder/executor/producer 均未改动，也没有新增 producer 注入入口。

行为边界：CV32 默认在线及已有 partial/交互反馈路径保留；该 wrapper 的关闭状态现在明确作为 constructor 参数传递，因此 executor 决策来源字段会标 constructor，不再区分 default/environment 关闭来源。拒绝能力不授任何新的认证、退休/IRQ观察或 P6通过。按本次任务限制未新增/运行测试、原生模型或远程命令；本节是源码追踪和差异说明，尚无执行验证结论。

## 6. Stage B bounded native online 源码增量（未执行）

本轮新增 `scenario/picorv32_native_online.py` 和 `integration/picorv32_native_online.py`，并只在实际 `local_harness/native_session.py` 与 `scenario/picorv32_native_cpu_example.py` 增加共享 opt-in 取指门。未新增/运行测试，未启动 frontend/build/native/remote；不是 P6 运行验收。

### 实际请求和等待合同

- 物理来源是 profile 的 `capabilities.instruction_identity_port=mem_instr`，由 runtime_renderer 验证唯一1bit observed output 后生成 `instruction_identity_observation`。不按地址猜测取指，也不把 read 当 retirement。
- declare_instruction_slots 必须在进程/测试启动前且有该认证 marker；调用 PersistentMemory 的原始 reserve。accept_instructions 使用 MemoryService 原始一次写入/指令白名单/不覆盖规则，保留 instruction_source 事件，不推进时钟。
- waiting_instruction_address 只来自上一真实 receipt 的 POST backend `m_req_valid/m_req_write/m_req_addr` 与同相 physical marker；未填满的声明字返回地址。该地址是 offered/unaccepted fetch，不是已消费指令。
- 原生下一次 STEP_MEMORY readiness 对该请求置0，既不 MemoryService.read 也不随机 materialize；真实 ticks 照常，adapter 的请求稳定性和 REQUEST/RESPONSE 有限超时全部保留。实际数据 read 不因地址相同被当作取指；未填声明区域仍由原内存权限/InstructionNotReady 路径拒绝，数据 write 保留原真实 STORE 权限并会使后续 instruction admission 因已确定字节拒绝。
- 来源可在 CPU 尚未到达槽时先提交。若首次启动就已出现未观察 POST 的未填请求，该通用 hook 不声称能预知它；新在线 bootstrap 的起始取指0已有初始映像，在线槽起始0x200须经实际 bootstrap 后到达。其他使用者须独立验收其启动窗口。
- 原 `native_completion_memory_adapter.sv` 在 IDLE 锁存请求并在 REQUEST 等 backend ready，期间检查 valid/address/strobes/写数据稳定；Pico mem_state1在 mem_xfer 前保持 mem_instr，profile 禁压缩且单 outstanding。hook 不修改这些 RTL。host 采用 POST 决定下一次输入，而非预先合成 PRE。

### 新构建与跨例对象合同

在线 CPU 请求显式 max_wait_cycles=1024，GPIO请求仍16；原 fixture 的16和已有请求字节不改。新 artifact/build identity 必须独立构建；不能借旧 binary 授新等待能力。新 case 固定128 CPU +128 GPIO实际 ticks，初始化最多512个CPU/GPIO轮次；这些是前瞻声明边界，尚无实测证明足够或性能通过，失败必须如实保留，不自动加额。adapter1024是本地时钟界限，不是主机无限等待许可。

factory 每次创建独立的 CPU/GPIO/Router/PersistentMemory/MemoryService/ledger；一个 runtime 仅调用一次 factory 并创建一个 ScenarioSession，所有 submit 共用它，不调用旧 PicoNativeGpioPair.runner、不重置/替换内存或 Router。fresh replay 才调用同 factory 建新实例。declare槽范围0x200..0xe00，RAM0..0x1000/seed7；bootstrap 在0由实际 CPU store 配置 PADDIR/GPIOEN，随后实际 JAL 到槽。固定 end 自环仅在槽末0xe00，未给新 IP 注入 readback、reset、状态或 IRQ。

runtime.begin 才 begin/start/build 并有界 warmup，真实 POST 出现首个等待槽后停止 warmup。submit 解码一个 source，在同 session.submit_case 执行后 commit decoder；执行中任何异常使 runtime 永久 terminal并尝试原 runner.finalize，保留尝试计划/原始事件。无自动重试、标量替代或换进程继续。finish_export 保存原始完整计划/trace；replay 使用原 replay_online_session。最终化使用原 Runner，已接受 queuedMMIO/pending 仍按既有规则排空或失败，不将未接受的等待请求计作已交付响应。

### 声明与证据上限

decoder 声明 CPU instruction 与 GPIO低8bit source 两种来源，按原 weighted decoder 选择，不强制方向轮换；GPIO高24bit固定0。CPU可产生合法算术/NOP或仅 PADOUT4字节/PADIN只读窗口的 LW/SW；SB被拒绝。IP源只有一个固定NOP support，不自动塞入一条为“命中”准备的读取。选择/接受字节不证明 fetch/CPU消费；未观察下游消费仅 stage/partial。

显式 RuntimePathContract 绑定实际cpu↔gpio0窗口0x40000000/4KiB与原ownership，在begin前安装原provenance；此静态路由不授 terminal证明。入口不创建默认 Ibex ChainCertificates，不授 IRQ/retirement/source权威、四类反馈认证、RFuzz搜索或P6整行能力。真实3例、两侧实际消费、全fresh、受控负例和source/tool/build联合验收均待审查后另行运行。

### Stage B 最终 packet 补充（覆盖§6中间稿的连续槽/NOP消费限制）

`79d85e8` 是中间源码，最新版本把输入改为明确的32字节 packet：首4字节是唯一可提交 source槽，随后28字节为immutable实际CPU代码。0x200..0xe00共有96 packets；单独预留0xe00未填 guard槽，不再初始安装末尾自环，不会在最后 packet 后落入随机RAM。原始plan逐条记录97个 reserve（96 source+guard）及所有固定tail映像，fresh使用实际声明重建；不能用旧 contiguous384词 reservation 替代。

CPU source仅一条 `ADDI x10,x0,u8`；IP source只提交一个NOP支持字。每个实际CPU tail均为 `LUI x1,GPIO_BASE; SW x10,PADOUT; LW x11,PADIN; SW x11,RAM[0x100]; XORI x10,x11,1; SW x10,PADOUT; NOP`。因此IP输入有具体的实际 pin→PADIN→CPU load→RAM store→派生PADOUT store消费路径，而非永久被NOP丢弃。bootstrap实际CPU指令将x10初始化0，不依赖初始寄存器猜值。此代码存在不等于该路径已经运行或事件认证；真实source/receipt/CPU消费关联仍待native门。

NativePacketDecoder沿用weighted选源、proposal/commit和runtime路径校验，但显式固定单词输入及32字节stride。仅在原commit成功且恰好提交4字节后跨过immutable尾部；所有decode入口在reservation耗尽/错位前拒绝，不允许IP输入继续接受却没有支持代码。decoder.document标明 native_online_packet.v1、自定义stride和不支持generic contiguous重建；不把它冒充通用decoder/RFuzz接入。runtime最多96例。

每例是128次CPU操作（实际每次1tick）与128次GPIO调度操作；GPIO queued ACCESS仍有真实多tick且使用原Runner间接边界记账，不能宣称每例恰好128GPIO物理tick。没有新增/跳过/虚构这些访问的时钟。CPU128预算未增加；不足则保留实际失败，不据静态指令数宣布通过。IP方向的声明图也补齐 CPU read→GPIO state 的真实MMIO route，仍只是声明，不是closed-loop hit。
