# Plan: 通用 AXI-Lite/APB SoC 生成与有状态 bit-level 约束

_Locked via grill-me-codex - Codex + 用户，2026-07-14_

## Goal

在保留现有 RFUZZ 数据流、Verilog 分支覆盖率 ABI、历史 A 方案和实验材料的前提下，把当前面向固定 CPU/固定 8 个 AXI-Lite IP 的原型升级为协议驱动的系统生成器。第一阶段交付应能从叶子 RTL、声明式 manifest、协议 profile 和可选寄存器元数据生成一个可复现的单 CPU master SoC，自动完成 AXI-Lite IP 规范化、地址映射、AXI-Lite fabric、AXI-Lite-to-APB 子系统、中断、单时钟多复位域、CPU 启动 ROM、bit-level 控制面、harness 和有状态时序约束。

系统必须支持未见过的模块名、实例数、地址布局、端口命名和复位极性；未知协议不猜测，关键事实不完整时 fail closed。约束输入始终是 RFUZZ bit stream，而不是外部事务对象；约束器可以跨 cycle 保存状态并读取 DUT 反馈。最终以 A/B/C/D 四方案进行至少 10 个配对 seed 的分支覆盖率实验，但覆盖率提升是研究假设，不是工程验收条件。

## Deliverable Boundary

当前完整交付范围是：AXI-Lite 主干、真实 AXI-Lite-to-APB bridge/decoder、CPU 唯一 master、单 clock、多独立 reset domain、内部存储器与 MMIO 设备、内部/外部中断、RAW/PROTOCOL_SAFE/SCENARIO_CONSTRAINED 三种生成模式，以及 A/B/C/D 实验。

AXI4、AHB、Wishbone、多 master、DMA 发起器、多 clock/CDC、任意既有集成顶层的逆向恢复不在本阶段实现，但核心 IR 和 backend 接口必须为其保留扩展位置，不能把 AXI-Lite 特例写进通用 planner。

## Architecture Invariants

1. 用户提供的 filelist、端口类型、协议标注、时钟/复位、地址和外部边界是权威事实；自动分析只能补充候选，不能静默覆盖用户事实。
2. 通用 planner 只消费结构化 contract/IR，不按模块名、当前 8 个 IP 或测试集路径分支。
3. Protocol Profile 描述协议语义；CPU Execution Profile 描述一次性的 CPU 启动、异常、中断和执行 ABI；模块专用 adapter 只处理真正的非标准扩展，并在报告中显式记录。
4. emitter 只把已验证 IR 序列化为 RTL、ROM、harness 和报告，不在模板中重新推断连接或地址。
5. 未解析的关键 clock/reset/protocol/address/boot 事实必须报错；未知 input 必须有显式策略，output 默认观察，未知 inout 必须拒绝或使用显式 adapter。
6. RawBits v2 和历史结果只读保存。B/C/D 使用 RawBits v3 和 ConstraintIR v2；所有结构、布局、profile、ROM 和模式均带 canonical digest，禁止静默迁移。
7. A_FLAT_RAW 的历史生成器、RFUZZ v2 几何、payload 解释、replay bytes 和运行入口永久保留。统一实验编排器如需承载 A，只能使用 v3 opaque envelope 原样封装 v2 bytes，解封后必须 byte-for-byte 进入旧 runner；B/C/D 使用同一个生成 SoC、ROM、RawBits v3 schema 和编译产物，只通过运行时 mode 选择行为。
8. 第一阶段只以分支覆盖率作为覆盖率指标；编译、协议错误、timeout 和 replay 信息只是正确性诊断，不能包装成新的覆盖率分数。

## Core Data Contracts

### SoCIR v2

SoCIR 是唯一的结构真相源，至少包含：逻辑 module/instance ID、source digest、参数、typed endpoint、port binding、protocol role、地址窗口与 `AddressView`、clock domain、reset domain、中断边、外部边界、生成服务节点、adapter、未知端口决策和 provenance。`AddressView` 明确定义 global base/size、byte-address unit、local address width、`local = global - base` 变换、保留 offset bits、alignment 和 alias rejection。SoCIR 不保存任意 RTL/Python 片段。

### Profile Contracts

- `ProtocolProfile`: endpoint 所需/可选 signal、方向、宽度关系、handshake、response、合法连接和 profile capability。
- `CpuExecutionProfile`: boot memory、data memory、mailbox/control-plane ABI、ISA/编译选项、trap/IRQ entry、可用 fence 和 reset 行为。
- `AdapterContract`: 非标准 endpoint 到标准 profile 的显式映射、能力变化和证据。
- `BackendCapabilities`: backend 支持的 role、拓扑、宽度、reset/clock 要求和生成版本。

### RegisterModelIR v1

统一表示 register/block/field 的 offset、width、access、reset、side effect、volatile、IRQ/ack/clear 和枚举信息。首阶段提供严格 JSON schema 和 CMSIS-SVD importer；SystemRDL/IP-XACT 提供 adapter 接口、最小 fixture 和明确的后续实现阶段。没有寄存器元数据时，IP 仍作为普通 MMIO target 使用，只失去设备级场景约束。

### RawBits v3 / ControlPlaneIR v1

RawBits v3 是版本化 bit 布局容器。ControlPlaneIR 从 SoCIR、profile 和 RegisterModelIR 生成字段，不固定为旧的四字段 AccessRecord。字段包括 opcode、target/region、address bits、write data、strobe、wait/timeout、sequence control、IRQ/external/reset/fault 参数及 profile 扩展位。运行 mode 不属于 RawBits，也不计入 fuzz entropy；它由 runner 在 testcase 开始前设置并锁存。每一 fuzz bit 都有 source、consumer、范围、默认值和布局 digest。

### TemporalConstraintIR v2

TemporalConstraintIR 是声明式、可解释、可重放的 bit/cycle 约束，不允许注入任意 Python/Verilog。基础 primitive 包括 `STABLE_UNTIL`、`VALID_READY`、`PULSE_WIDTH`、`HOLD_WHEN`、`UPDATE_ON`、`DEPENDENCY`、`SEQUENCE`、`WAIT_UNTIL`、`TIMEOUT`、`CHOICE_WEIGHT`、`FAULT_INJECT` 和 `RESET_SEQUENCE`。同一 IR 由软件 reference evaluator 和 RTL emitter 消费，并做逐 cycle 等价测试。

### Temporal Execution Semantics

- DUT time 每个 rising edge 前进一次；timeout、pulse width 和 sequence wait 均以 DUT cycle 计数。RawBits record index 只在 `raw_bits_valid && raw_bits_ready` 的 acceptance edge 前进。
- producer 在 `valid && !ready` 时保持整条 RawBits vector 稳定；constraint engine 只在 acceptance edge 锁存新 record，stall 期间继续使用锁存值并按 DUT cycle 更新 temporal state。
- 每个 edge 的顺序固定为：采样 edge 前已注册输出与 accept，DUT 完成 edge/NBA 更新，采样 settled feedback，然后计算并注册下一 cycle 的 constrained output/state。Coverage ABI 也在同一 `after_rising_edge_nba_settle` phase 采样。
- entropy 只统计 acceptance 时被该 variant 的 used-mask 实际消费的 raw bits；stall 中重复保持不增加 entropy。Replay bundle 同时记录 DUT cycle index、accept index 和 used-mask digest。
- IR signal 是定宽 bit-vector/boolean/enum，算术为显式宽度的无符号模运算或显式 saturating counter；禁止隐式扩宽、X-dependent 语义和组合 feedback loop。
- primitive 按 dependency DAG 拓扑顺序执行；hard rule 冲突、多个 writer、环、越界或不可综合状态均 fail closed。hard rule 优先于 weighted choice；同层规则必须声明唯一 priority，不能靠文件顺序决定。
- 所有 state、counter、queue 深度必须静态有界并定义 global/domain reset 值。`WAIT_UNTIL` 必须带有限 timeout 和 timeout transition；无 progress 的 cycle 必须仍允许 watchdog 前进。
- `CHOICE_WEIGHT` 每次 record acceptance 消费预分配的固定 bit slice，经规范化整数映射作选择；不读取宿主 PRNG，也不因分支路径改变后续 bit 消费。
- B/C/D 对同一 seed 必须使用完全相同且顺序一致的 v3 bytes/layout；constraint mode 是 testcase 外不可变的 experiment parameter。各 mode 可因 readiness/latency 产生不同 acceptance cycle/count，必须分别记录 acceptance trace。producer 不跳过 stalled record；到固定 DUT-cycle budget 时记录 consumed prefix count 与 unconsumed-tail digest。只有 A 的 legacy v2 generator 使用独立的 `A` RNG domain。

### Normative Primitive Contract

TemporalConstraintIR v2 必须同时提供 machine-readable operand schema、下面的权威 transition semantics、非法组合规则和独立手写 golden vectors。任何 emitter/evaluator 都以该版本化规范 digest 为准，而不是互相作为正确性来源。

- `STABLE_UNTIL(dst, sample, activate, release)`: idle 时 `activate && !release` 才锁存 sample；idle 的 release 被忽略；active 时 release 优先于 activate，release edge 的输出仍为旧值、下一 cycle 回 idle；active 时单独 activate 被忽略且不重锁存。
- `VALID_READY(valid, payload, activate, ready)`: activate 时锁存 payload 并从下一 cycle assert valid；在 sampled `valid && ready` edge 完成，该 edge 后 deassert。active 时再次 activate 非法。
- `PULSE_WIDTH(dst, start, cycles)`: start 后下一 cycle 起输出 1 恰好 `cycles` 个 DUT cycle；`cycles=0` 不产生 pulse；active 时 start 非法。
- `HOLD_WHEN(dst, sample, hold)`: hold=1 时保持上一注册值，否则在 edge 后更新为 sampled sample。
- `UPDATE_ON(dst, sample, event)`: 仅在 sampled event=1 的 edge 后更新，否则保持。
- `DEPENDENCY(dst, predicate, true_value, false_value)`: 对已排定的本 cycle typed value 做无状态选择；不能读取自身或形成 DAG cycle。
- `SEQUENCE(state, initial, transitions, terminal)`: reset 进入 initial；每个 DUT cycle 至多选择一条按显式 priority 排序且 guard 为真的 transition；priority 重复非法；terminal 无隐式退出。
- `WAIT_UNTIL(activate, predicate, limit, success, expired)`: idle 时 activate 才进入 active 并把 count 置 0；active 时再次 activate 被忽略；每 edge 先判 predicate，再判 `count == limit-1`，因此同 edge success 优先；limit 必须大于 0，二者均产生显式 transition，idle 时 success/expired 为 0。
- `TIMEOUT(active, clear, limit, fired)`: clear 最高优先并把 counter/fired 清零；否则 active=0 也把 counter/fired 清零；active=1 时 saturating 计数，达到 limit 的 edge 后 fired 恰好 1 cycle并保持 counter saturated，下一 active cycle fired 回 0；limit 必须大于 0。
- `CHOICE_WEIGHT(dst, raw_slice, choices, integer_weights)`: 仅在 record acceptance 映射固定且非空 raw slice；令 `R=raw unsigned`、`S=sum(weights)`、`N=2^slice_width`、`bucket=floor(R*S/N)`，选择首个累计权重上界大于 bucket 的 choice，不作 rejection sampling；choice 数与正整数 weight 数相等。
- `FAULT_INJECT(dst, enable, kind, value, cycles)`: 只允许写入 SoCIR 标注为 external/fault-capable 的 sink；idle 时 enable 后下一 cycle 按 kind 驱动固定 value/响应恰好有界 cycles；active 时 enable 被忽略且不延长/替换 fault；cycles 必须大于 0；禁止直接写内部 AXI-Lite/APB wire。
- `RESET_SEQUENCE(domain, start, drain_limit, isolate_limit, assert_cycles, complete_limit, drained, isolated, reset_done, error -> request, force_isolate, success, failed)` 是 canonical macro，validation 时必须展开为 `SEQUENCE + TIMEOUT`，不得由 backend 自定义。所有 limit/cycles 大于 0；它只驱动 reset controller 的 request/force_isolate 和参数，不直接驱动 reset pin。
- 展开状态固定为 `IDLE -> DRAIN -> (RESET | ISOLATE) -> RESET -> DONE` 或 `FAILED`。IDLE 输出全 0，edge 上 `start=1` 后下一 cycle 进入 DRAIN；active/DONE/FAILED 时再次 start 被忽略。DRAIN 输出 request=1/force_isolate=0，并以 `error > drained > drain timeout` 为优先级：error 到 FAILED，drained 到 RESET，timeout 到 ISOLATE。ISOLATE 输出 request=1/force_isolate=1，以 `error > isolated > isolate timeout` 为优先级：isolated 到 RESET，timeout/error 到 FAILED。RESET 保持 request=1，并保持是否经过 ISOLATE 的 force_isolate 值；controller 必须至少 assert `assert_cycles`，本状态以 `error > reset_done > complete timeout` 为优先级进入 FAILED/DONE。各 timeout 在进入状态时从 0 初始化并按 `TIMEOUT` 规则计数。
- DONE 仅输出 success=1 一个 cycle，FAILED 仅输出 failed=1 一个 cycle，随后无条件回 IDLE；其他状态 success/failed=0。非当前状态的 feedback 被忽略；global/domain reset 立即回 IDLE。每个 coincident feedback/timeout、retrigger 和 success/failure pulse 都有 golden vector。

所有 primitive 的 activate/start/request 在 active 时的行为必须由上面定义；静态未定义组合是 validation error，运行期状态按上述 priority 唯一解释，不能由 backend 自选。对于仍标为非法的动态事件（如 active `VALID_READY` 再 activate、active `PULSE_WIDTH` 再 start），统一设置 sticky `constraint_runtime_error`，保持当前注册输出、不再接受 RawBits，并进入 bounded abort/teardown；该 testcase 标为 constraint-invalid，不进入实验统计。global reset 最高优先级并把 output/state 恢复到 schema 声明值，domain reset 只重置显式归属该 domain 的 state。每个 simultaneous/retrigger case 都必须有独立 golden vector。

## Implementation Plan

### 1. 冻结基线、fixture 和 holdout

- 保存现有 A_FLAT_RAW runner/generator、RawBits v2、历史 coverage 结果和固定 8-IP topology；生成 byte-level inventory，覆盖 source/filelist、manifest、wrapper/ROM、license、输入、结果和报告的 path/size/SHA-256，不修改其语义。
- 将当前固定 topology 转为 migration fixture，但禁止新 planner/backend import 旧固定表。
- fixture manifest 可显式引用隔离的 `LegacyAddressAliasAdapter` 以重现旧 GPIO 等“窗口大于 local address space”的可见 alias 行为；adapter 参数写入 manifest/SoCIR/digest，不在 planner 按 module name 触发，也不得用于 holdout 泛化证明。
- 建立 dev/holdout 清单并冻结 source digest。holdout 至少包含 3 个不同来源家族：其他 ZipCPU AXI-Lite IP、PULP mailbox，以及 APB GPIO/timer。
- 添加静态检查，扫描通用目录中的 holdout module name、当前 8-IP module name 和测试集路径特判。

验收：历史 A 可重放；fixture digest 固定；holdout 名称不出现在 profile alias、planner/backend 分支或专用测试逻辑中。

### 2. 版本化 schema、canonical serialization 和迁移工具

- 在 contracts 层加入 SoCIR v2、ControlPlaneIR v1、RegisterModelIR v1、TemporalConstraintIR v2、RawBits v3 和 ExperimentManifest v2。
- 每个 schema 实现严格解析、未知字段策略、canonical JSON、内容 digest、版本兼容矩阵和 provenance。
- 提供显式 `v2 -> v3 opaque envelope` 命令；它只封装原始 bytes 和 legacy digest，round-trip 必须 byte-for-byte。原始 v2 artifact 永不原地改写，不能被重排字段或自动并入原生 v3 corpus。
- 为缺字段、版本错配、非确定序列化和 digest 不一致添加失败测试。

验收命令：`python3 -m unittest tests.builder.test_contract_versions tests.builder.test_canonical_digest tests.builder.test_rawbits_migration`。

### 3. 扩展 manifest 与证据分级 discovery

- manifest 支持 filelist、top/leaf module、实例、参数、interface annotation、clock/reset、地址请求、中断、外部端口、register metadata、adapter 和 unknown-port policy。
- elaboration/discovery 提取端口、参数、宽度和层级事实；按“用户声明 > profile 规则 > elaborated RTL fact > 静态候选”合并，并保存 provenance/conflict。
- 未知协议不自动猜测。仅当端口满足已注册 Profile 或用户标注时建立 endpoint。
- 输出 discovery report：采用事实、被覆盖候选、冲突、强制值和拒绝原因。

验收：同一设计对 manifest/filelist 顺序不敏感；关键冲突报错；未知 input 的 tieoff/fuzz/reject 策略可追踪；未知 inout 默认拒绝。

### 4. Profile registry 与 protocol backend registry

- 将现有 AXI-Lite 逻辑重构为可版本化 `ProtocolProfile`，新增 APB3/APB4 target profile。
- backend registry 根据 SoCIR protocol graph 和 capability 选择实现；选择失败时给出 capability mismatch，不回退到模块名特例。
- 注册 AXI-Lite fabric backend、AXI-Lite-to-APB bridge backend、APB decoder backend 和默认 error target。
- backend API 预留多 initiator、不同协议和 CDC capability，但本阶段 capability 明确拒绝这些组合。

验收：用合成的未见 module name 测试 registry；通用代码对实例名重命名保持同构输出；不支持的协议/多 master/多 clock 给出结构化错误。

### 5. AXI-Lite endpoint 自动规范化 wrapper

- 从已解析的 logical endpoint/binding 生成 wrapper，处理端口命名、address width、reset polarity、可选 signal、参数传递和标准 response 默认值。
- wrapper 只做接口规范化，不修改设备行为，不按 IP 名称判断。
- 地址宽度通过 SoCIR `AddressView` 做 window base subtraction 后传递 local byte offset；要求 window size 可由 local address width 唯一表示、alignment 合法且 window 外访问不能 alias。禁止把 global address 直接静默截断。
- 第一阶段 AXI-Lite/APB data width 固定为 CPU profile 的 32 bit。不同 data width 必须 capability mismatch；未来只有显式 width-adapter contract 定义拆分/合并、strobe 和 error 语义后才能开放。含糊 optional signal 必须拒绝。
- 真正非标准扩展使用显式 adapter contract，并在 topology/report 中标记。

验收矩阵：不同命名、不同 address width、active-high/low reset、可选 signal 缺失、参数化实例；global-to-local alias、非法地址变换、非 32-bit data endpoint 和方向错误必须失败。

### 6. 通用 planner 生成 SoCIR

- planner 输入为规范化 module contracts、manifest、profiles 和 backend capabilities。
- 规划单 CPU master、多个 AXI-Lite target、内部 ROM/RAM/mailbox/watchdog/error target、地址窗口、单 clock、多 reset domain、中断图、APB 子图和外部边界。
- 地址规划支持用户固定、约束范围和自动分配；检查 overlap、alignment、CPU 可达性、bridge window 与下级 decode 完整性。
- 默认 `AddressView` 拒绝 alias；只有 manifest 显式声明且 adapter capability 验证的 alias policy 才可接受。migration fixture 的 legacy alias 不改变通用默认值。
- 中断图区分内部 IP IRQ source、harness external IRQ source、强制生成的 pending/claim mapper 和 CPU IRQ sink。若 CPU profile 提供等价且可验证的 controller，可由 adapter 替代，但 claim contract 不可省略。
- reset graph 明确 controller owner、依赖顺序、isolation、quiescence、保持域和 replay epoch；不做隐式 CDC。每个可独立 reset target 必须有 outstanding tracker 和 reset isolation capability，否则该 domain 不得独立 reset。

验收：相同输入产生 byte-for-byte 相同 SoCIR；module/instance 重命名不改变除 logical ID 外的规划；地址重叠/alias、无 boot path、IRQ 宽度不匹配、无 claim path 和无 isolation 的独立 reset 均 fail closed。

### 7. 生成真实 AXI-Lite/APB 结构

- AXI-Lite backend 从 SoCIR 生成单 master、多 target 的 decoder/interconnect，正确处理独立 AW/W、B、AR/R channel、backpressure、error response 和 unmapped access。
- 第一阶段 fabric capability 固定为全系统最多 1 个逻辑 transaction outstanding。idle 时若读和写同时出现，固定 write priority；任一 AW/W half 被捕获后即锁定 write、阻止 AR，并用独立单槽补齐另一 half；AR 被接受后则阻止 AW/W，直到 R handshake 完成。只有完整 write 被 upstream 捕获后才转发，直到 B handshake 才释放。reset/timeout fence 后拒绝新 transaction，但若已有半个 upstream write，仍只接受其缺失 half，随后只需完成与当前 transaction 类型对应的 synthetic R 或 B，或升级 reset。
- APB backend 生成真实 AXI-Lite-to-APB bridge 与 APB decoder；内部 APB target 的 `PREADY/PRDATA/PSLVERR` 来自真实 target，不由 harness 伪造。
- 只有 manifest 明确声明的外部 APB device 才由 harness responder 模型提供响应，且 responder 同样受 bit-level temporal constraints 控制。
- emitter 输出稳定的 instance/wire 命名和 source map，模板不得重新做 endpoint inference。

验收：协议 reference model/SVA 检查 channel stability、response matching 和 APB setup/access phase；2 个 APB IP 经 bridge 可由 CPU 访问；unmapped 和 slave error 可到达 CPU trap/record 路径。

### 8. CPU Execution Profile 与系统服务模块

- 第一阶段 CPU 明确为 PicoRV32 与 UltraEmbedded（仓库 ID `picorv32`、`ultra_riscv`），各实现一个 CPU Execution Profile，封装 boot、memory、IRQ/trap 和工具链差异，不把 Ibex 计入本交付，也不创建 CPU x IP adapter。
- UltraEmbedded 的 `pre_reset_tcm_loader` 是 CpuExecutionProfile 内部的 boot-time 私有 loader：只在 CPU 保持 reset 时运行，不进入 SoCIR system protocol graph，不接受 RFUZZ 输入，不参与 coverage scope，也不算系统 master。它现有的 AXI4 loader 端口作为 opaque CPU 安装细节保留，不代表本阶段实现 AXI4 backend。
- 生成/连接 boot ROM、data RAM、stack、mailbox/control plane、operation status、watchdog、reset controller 和 epoch register。
- ROM/RAM 的地址和大小来自 SoCIR；CPU profile 负责把相同 ControlPlaneIR 映射到各自执行环境。
- 新 CPU 的准入要求是新增一次 CPU Execution Profile，并通过公共 CPU conformance suite。

验收：两个现有 CPU 在最小 SoC 和混合 AXI-Lite/APB SoC 中均能 boot、读写 RAM、执行 MMIO、进入 trap/ISR 并写回状态。

### 9. RegisterModelIR 与设备语义来源

- 实现严格项目 JSON importer 和 CMSIS-SVD importer；字段语义转换失败时保留证据并拒绝设备级规则，而不是猜测。
- 从 RTL 提取的地址比较、write enable、IRQ 条件只作为候选；除非由 metadata/profile/用户注释确认，否则不能升级为 hard constraint。
- 将 access、side effect、volatile、IRQ clear/ack 等信息编译为 ControlPlaneIR 可选字段和 TemporalConstraintIR 场景模板。
- 没有 metadata 的 AXI-Lite/APB IP 仍可完成自动 SoC 生成和 RAW/PROTOCOL_SAFE 测试。

验收：JSON/SVD 同义模型生成相同 canonical RegisterModelIR；无 metadata holdout IP 可运行；错误 metadata 不改变协议级连接。

### 10. 生成 bit-level Control Plane 和 RawBits v3 布局

- 根据 SoCIR 的地址空间、CPU profile、register model、IRQ/reset/external graph 自动确定字段宽度和消费者。
- 支持操作：`MMIO_READ`、`MMIO_WRITE`、`MMIO_RMW`、`POLL`、`WAIT_CYCLES`、`WAIT_IRQ`、`IRQ_ACK`、`MEM_READ`、`MEM_WRITE`、`FENCE`、`SET_EXTERNAL`、`PULSE_EXTERNAL`、`FAULT_ACCESS`、`RESET_DOMAIN`、`SEQUENCE_CONTINUE`、`SEQUENCE_END`。
- CPU-executed 操作由 ROM 解释器执行；`SET/PULSE_EXTERNAL`、非 CPU reset domain 控制和显式外部 fault response 由 harness 执行。两者都只消费布局中的 bit fields，不接受事务对象。
- DMA 操作不生成，因为本阶段 CPU 是唯一 master。
- A 保留原生 v2 flat payload 和旧 runner；统一编排时 v3 envelope 仅携带原始 v2 bytes、v2 layout digest 和 legacy runner digest，不能重新布局或重新解释。B/C/D 使用原生 v3 control-plane layout。

验收：随机 layout round-trip、字段无重叠、每 bit 有 consumer、同一 IR 布局确定；旧四字段 AccessRecord 不再是新路径的生成依据。

### 11. 生成 ROM 执行器、ISR/trap 和恢复协议

- ROM 从 CpuExecutionProfile、SoCIR、RegisterModelIR 和 ControlPlaneIR 生成，不写死 IP 地址或寄存器。
- 执行器支持上述 CPU 操作、多步 sequence、poll/wait、memory 与 MMIO、fence、故障地址和状态回写。
- 生成 mapper 为每个 internal/external IRQ source 锁存 pending bit，提供确定性 priority claim/complete 寄存器；同时到达的 source 均保留。ISR 读取 claim 后记录 source；只有 metadata/profile 描述设备 ack/clear 时才执行对应 bit-level 选择的 ack/clear，不猜设备寄存器。
- level IRQ 有 metadata 时，complete 后仍为高可按 profile bounded retry 再 pending；无 ack metadata 时默认 `mask_until_deassert`：首次 claim/complete 后屏蔽该 source，直到观测到 low 再重新 arm，并记录 persistent-level diagnostic。这样无 metadata 的设备不会形成无限 ISR loop。
- 四级恢复：operation timeout 只有在对应 request 已获得真实或 synthetic terminal response 后才能记录并继续；scenario timeout 也必须先 unwind 当前 operation；可恢复 trap 记录后返回；永久 CPU/bus stall 触发 execution reset。AXI-Lite 不支持 cancellation，epoch 只隔离逻辑记录，不能替代物理总线排空。
- domain reset 和普通 timeout 共用 unwind 流程：fence 新请求，完成 upstream 半写配对，等待唯一 outstanding 归零；若超时，由 isolation wrapper 在已捕获完整 request 后按当前类型生成唯一 `RRESP=SLVERR` 或 `BRESP=SLVERR`，完成对应 handshake，清空 route/bridge state并按 epoch 丢弃 late target response；无法安全合成 terminal response 时升级为 CPU+fabric+target execution reset。
- reset 随后按 profile 异步/同步 assert，并用单 clock 两级同步 deassert。APB downstream reset 时 bridge 必须隔离并终止当前 transfer。retention state、pending/masked IRQ 和 mapper reset 行为由 domain contract 明确列出。
- 每 testcase 先做确定性 global reset，清空 constraint/ROM/mailbox/IRQ/peripheral 状态；仅 manifest 显式 retention domain 可跨 reset 保留，并写入 replay metadata。

验收：每种 opcode 的 CPU-level test、timeout/trap/reset/epoch test、simultaneous/level IRQ claim test、ISR 有/无 metadata test，以及 AW-only、W-only、完整 write、read、APB setup/access 各阶段发生 timeout/domain reset 的排空/isolation test；证明读写不会同时 outstanding；相同 RawBits 与初始状态逐 cycle replay 一致。

### 12. TemporalConstraintIR 软件 evaluator 与 RTL emitter

- 约束流水线为 `raw bits + constraint state + sampled DUT feedback -> constrained bits + next state + reason trace`。
- `RAW` 只施加结构必需约束；`PROTOCOL_SAFE` 对 fuzz-controlled 的外部边界信号增加 protocol electrical/handshake hard invariants；`SCENARIO_CONSTRAINED` 再约束 control-plane bit fields、external pins/IRQ/reset/fault bits，增加设备/多步 sequence 的 weighted rules。
- CPU、内部 fabric、bridge 和内部 target 的 AXI-Lite/APB 信号从不由 RFUZZ 直接驱动，因此其协议合法性是结构实现属性，不是 C 模式制造的刺激差异。对没有 external protocol responder 的全内部 SoC，B 与 C 允许行为等价，报告必须标记 `protocol_safe_degenerate=true`；禁止为拉开覆盖率而旁路 CPU 或注入内部 malformed transaction。
- 协议 hard rule 不能被随机关闭；边界、异常、raw-invalid 和 fault 行为通过显式 mode/primitive 保留。设备场景规则使用冻结于 manifest 的权重，不根据本轮 coverage 自适应，从而保证 replay。
- 软件 evaluator 用于 reference/replay/debug；RTL emitter 用于 fuzz 性能。两者消费完全相同的 canonical IR。
- reason trace 仅用于正确性诊断和最小反例，不计入 coverage 指标。

验收：对规范中的 evaluation phase、每个 primitive、冲突/环/越界/无 timeout 拒绝、组合 sequence、stall、reset 和反馈依赖做 golden-vector 加逐 cycle differential test；随机至少 10,000 条短 trace，软件与 RTL 输出/state/reason code 一致。

### 13. Harness、模式切换与 testcase 生命周期

- harness 只实现 SoCIR 声明的外部环境：clock/reset、external IRQ/GPIO、显式 external APB responder、coverage 收集和 testcase watchdog。
- B/C/D 编译同一 target，通过 testcase 外的运行时 2-bit mode 选择 `RAW`、`PROTOCOL_SAFE`、`SCENARIO_CONSTRAINED`；mode 在 `start` 前设置、start edge 锁存、testcase 内不可改变，不占 RawBits layout，也不计 entropy。模式值与 artifact digest 一同记录。
- testcase 开始/结束、reset、timeout、seed、RawBits digest、SoCIR/profile/ROM/constraint digest 形成 replay bundle。
- harness 不模拟内部 IP 的 response，也不绕过 CPU 直接发起 AXI-Lite/APB transaction。
- runner 提供 out-of-band `abort` 生命周期控制。到预注册的最终 DUT edge 后，不再允许新的 RawBits acceptance；下一 edge 进入 bounded teardown，丢弃当前 stalled-but-unaccepted record，按 timeout unwind/reset 清理唯一 outstanding，并在全局 testcase reset 完成后才允许下一个 testcase。

验收：B/C/D binary、v3 layout 和每 seed ordered input bytes 相同；只改变 out-of-band latched mode；允许并记录不同 acceptance cycle/count 和 consumed-prefix/unconsumed-tail；运行中改变 mode 触发 format error；final-edge stalled record 被一致 abort；testcase 间无状态泄漏；external model 未声明时相关输入必须被拒绝或按显式 unknown policy 处理。

### 14. Coverage ABI 和 A/B/C/D 实验编排

- 冻结现有 Coverage ABI v2 的精确定义：只纳入 `_PRIMARY_KINDS={if,case,loop,control}` 且 process kind 为 `always_ff/edge_always` 的点；以 stable component ID/path + node/kind/subtype 形成 point identity；采样 phase 固定为 `after_rising_edge_nba_settle`。primary scope 只含 CPU/IP/研究目标逻辑，排除生成 fabric、ROM、harness 和诊断逻辑。
- `A_FLAT_RAW` 保持历史 flat/raw 语义；`B_GENERATED_RAW` 使用通用 SoC 但仅结构约束；`C_PROTOCOL_SAFE` 只对实际由 fuzz 控制的 external protocol boundary 增加 hard constraints，全内部 SoC 可与 B 退化等价；`D_SCENARIO_CONSTRAINED` 增加有状态 bit-level 场景约束。
- 实验唯一 stopping axis 是固定 DUT cycle budget，checkpoint axis 也是 DUT cycle；stall、reset 和 timeout 全部消耗预算，wall-clock 仅作性能诊断。B/C/D 对同一 seed 共用完全相同的 v3 byte stream；A 使用同一 seed 编号但以 `A`/`GENERATED` 两个 domain 分离的固定 RNG-to-field mapping，这不是相同刺激，只用于降低 seed 间方差。
- checkpoint/final snapshot 均在对应 rising edge 的 NBA settle 后读取。最终 edge `M` 的 branch bitmap 立即锁存并冻结；edge `M+1` 起的 abort/unwind/reset teardown 不得修改已锁存 bitmap，也不进入 curve、AUC 或 first-hit。旧 A runner 通过只影响测量边界外的 orchestration wrapper 获得相同 freeze 语义，原生历史 runner 仍保留用于旧 replay。
- teardown 有独立固定上限且不计测量 budget；成功条件是无 outstanding、coverage frozen、global reset 完成。teardown 超时或 snapshot/abort 协议错误将该 seed 标为 infrastructure-invalid 并排除统计，不能保留一个经过额外 drain 的 coverage 值。replay 必须复现 measured snapshot、consumed prefix、abort phase 和 teardown result。
- 配对统计以 `(design, cpu, seed)` 的完整 A/B/C/D tuple 为原子单位；任一 variant 为 infrastructure-invalid 或 constraint-invalid，整个 tuple 从配对统计移除并单独报告原因，禁止只删除失败 variant 后继续声称配对。预注册最小有效 tuple 数；不足时补跑新 seed，不复用或挑选已有结果。
- entropy 定义为 acceptance edge 上按 variant used-mask 实际消费的 raw bit 数，不作为 stopping axis。必须报告 accept count、stall cycles、有效 bit、执行操作数和输入吞吐。A/B/C/D 结果只作描述性/配对统计比较，不声称 payload 等价或严格受控因果效应。
- 每个组合至少 10 个 seed，按固定 checkpoint 保存 branch curve。报告 final coverage、curve AUC、first-hit 分布和预先固定窗口定义的 plateau；这些均由同一 branch bitmap 派生，不引入新 coverage 指标。
- 不以 D 胜出作为通过条件，负结果和无显著差异必须原样报告。

验收：instrumentation smoke、inclusion/exclusion policy/sampling/point/scope digest 稳定、final snapshot 后额外 teardown activity 不改变 bitmap、同一 replay bundle 重放得到相同 measured branch bitmap/abort result；参与 coverage 统计的每个 CPU/IP 组合必须有冻结且非零的 primary denominator。实验预注册每个 variant 允许的 digest tuple：A 使用冻结的 legacy SoC/v2-layout/runner tuple，B/C/D 必须共享 generated SoC/v3-layout/ROM/compiled-target tuple；四者必须共享同一 coverage point catalog/scope digest。只有偏离预注册 tuple 或公共 catalog 才拒绝，不能因 A 预期不同的 SoC/layout 而拒绝。

### 15. 报告、可解释性和失败分类

- 生成 machine-readable 与 human-readable 报告：输入证据、port binding、wrapper、地址、中断/reset graph、backend capability、adapter、unknown policy、ControlPlane bit map、constraint source、artifact digest 和 coverage scope。
- 对失败分类：manifest/schema、elaboration、profile match、binding、address、backend capability、compile、boot、protocol、timeout、replay 和 experiment comparability。
- 每个 generated RTL node 可回溯到 SoCIR node，每个 constraint 可回溯到 protocol/profile/register/user bit annotation。
- 报告中自动检查并标记 module-specific adapter；通用 holdout 成功时应为零。

验收：失败 fixture 的分类稳定；同一输入报告 canonical 部分一致；报告中不存在未说明的 forced connection、tieoff 或 inferred register semantic。

### 16. 泛化、holdout 和回归门

- 用 manifest 在新路径重建当前 8-IP topology，证明未 import 固定表，并与旧 topology/地址/可见 CPU 行为做差分。
- 在冻结的 3 个来源家族 holdout 上运行：至少 3 个未见 AXI-Lite IP，至少 2 个 APB IP；测试不同命名、参数、address width、reset polarity 和 optional signal。第一阶段 data width 均为 32 bit。
- holdout 的功能生成门与 coverage 门分离：可正确生成/访问但当前 instrumenter 得到零 primary point 的 IP 仍可通过功能门，但不得进入覆盖率统计；用于实验的组合必须另行满足非零 frozen denominator。
- 对 protocol-incompatible 设计允许拒绝，但必须提供 profile/capability 证据；不能以 module name unknown 作为理由。
- 两 CPU、8-IP fixture、holdout、APB、错误 fixture、replay 和 coverage smoke 组成合并门。

建议回归入口：`python3 -m unittest discover -s tests/builder`、`python3 -m unittest discover -s tests/integration`、`make builder-regression`、`make fuzz-abcd-smoke`。实现时将这些入口固化到仓库，而不是依赖手工命令。

### 17. 迁移、兼容与清理

- 新旧路径并行存在，直到当前 topology、两 CPU、holdout 和 A/B/C/D smoke 全部通过。
- legacy `large_soc.py` 和固定表只允许 fixture、历史 A 生成/运行与重放使用；新 manifest/profile/backend 禁止引用它们。
- 历史 A 的 fixed generator、v2 decoder 和 runner 永久保留在隔离的 legacy namespace，并进入回归。达到迁移门后只标记其他旧生成入口 deprecated；独立清理变更可删除已证明无消费者的旧 AutoTop/过渡代码，但不得删除或改写 baseline 依赖和 byte inventory。
- 更新架构文档、schema 文档、profile/adapter 编写指南、错误目录和实验复现说明。

验收：新路径静态证明不 import legacy baseline namespace；历史 v2/A generator、runner 和 artifact 可运行/可读；新生成 artifact 均带完整版本与 digest。

### 18. 后续协议与寄存器生态路线

- 第二阶段：完整 SystemRDL importer/compiler integration 与 IP-XACT importer，在 RegisterModelIR 边界收敛，不改变 ROM/constraint consumer。
- 后续协议：分别新增 AXI4、AHB、Wishbone ProtocolProfile/backend/conformance suite；通用 planner/SoCIR 不增加协议名分支。
- 多 master/DMA 需要 arbitration、coherence/ownership、发起器操作模型和新的公平性定义，单独设计后再开放 capability。
- 多 clock 需要显式 CDC bridge、clock/reset crossing contract 和验证，不允许自动直连。

## Acceptance Matrix

工程完成需要同时满足以下条件：

1. SoCIR/address/binding/control-plane/constraint serialization 确定性测试通过。
2. TemporalConstraintIR 软件 evaluator 与 RTL emitter 逐 cycle 等价。
3. 两个现有 CPU 均可在新生成器下 boot、MMIO、IRQ、trap、timeout 和 reset/replay。
4. 当前 8-IP topology 由 manifest 重建，通用路径不 import 固定表。
5. 3 个来源家族的未见 AXI-Lite IP 通过，且无 module-name 特判。
6. 至少 2 个 APB IP 经真实 bridge/decoder 通过。
7. naming、address width、reset polarity、optional signal 和参数组合通过；非 32-bit data endpoint 在第一阶段明确 capability mismatch；默认拒绝 alias，只有显式 legacy adapter 可重现 baseline alias。
8. overlap、关键 unknown、inout、协议不完整、多 master、多 clock 均按合同失败。
9. 历史 A generator/runner、RFUZZ v2 几何、payload bytes、语义与 replay 保持；v3 envelope round-trip 不改变任何 v2 byte。
10. B/C/D 共享 SoC、ROM、v3 schema/layout、每 seed input bytes 和 compiled target；out-of-band immutable mode 是唯一行为开关。
11. replay bundle 可按 DUT cycle/accept index 确定性恢复 constrained bits、CPU 状态结果和 branch bitmap。
12. 至少 10 个配对 seed 的 A/B/C/D branch curves 完成；D 不需要优于其他方案。

## Key Decisions And Tradeoffs

- 选择“已知协议/显式标注下的未知模块与拓扑泛化”，而不是猜测未知协议。这样牺牲零配置幻觉，换取可验证连接。
- 约束保持 bit/cycle 级；opcode 只是 ROM/harness 内部解释的 bit vocabulary，不暴露事务级 fuzz API。
- protocol invariants 是 hard constraints，device sequence 是 weighted constraints，并保留 raw/异常/fault 路径，避免过度合法化导致覆盖率早早平台。
- C 只约束 fuzz-controlled external protocol bits；内部总线合法性由真实 CPU/fabric/target 保证。全内部 SoC 的 B/C 退化是合法结果，不能人为制造 malformed 内部流量。
- CPU 是唯一 master，降低第一阶段的仲裁和可比性风险；新 CPU 通过一次性 Execution Profile 接入，新 IP 不需要 CPU x IP 代码。
- 单 clock、多 reset domain，允许研究 reset 行为但暂不承担隐式 CDC 风险。
- APB 内部设备使用真实 bridge/target response；harness 只建模明确的外部边界。
- 自动 register inference 不作为 hard truth；无 metadata 时系统仍能工作，只减少设备级指导。
- 约束权重在实验前冻结，不在运行中按 coverage 自适应，以保证严格 replay 和 A/B/C/D 可解释性。
- 覆盖率结果不作为生成器正确性的替代；功能验收和研究结论分离。

## Risks And Mitigations

- AXI-Lite AW/W 独立握手和 backpressure 容易生成错误 fabric：使用协议 reference model、SVA 和随机 differential tests。
- CPU profile 可能把 CPU 特性泄漏到通用 planner：通过 conformance suite 和禁止 CPU/module name 分支的静态检查隔离。
- Register metadata 质量不一致：严格 importer、provenance、候选/确认分级，无 metadata graceful fallback。
- Scenario constraints 仍可能过严：保留 RAW/PROTOCOL_SAFE 对照、显式 fault primitive、冻结权重并报告每条规则的 bit 影响。
- A 与生成方案 layout 不同带来实验偏差：A 的 v2 bytes 只放入 opaque v3 envelope，采用固定 DUT-cycle stopping/checkpoint 和 domain-separated RNG，报告 entropy、有效 bit 和吞吐，只作描述性/配对统计，不作不受支持的因果结论。
- reset/timeout 可能留下旧响应：epoch、确定性 testcase reset 和逐层恢复测试。
- reset/timeout isolation 可能在 AW/W 半事务上出错：第一阶段固定单槽、单 outstanding，fence 后只完成已开始的 pairing，所有 synthetic/late response 路径用 reference model 和 SVA 验证。
- holdout 被测试代码间接泄漏：冻结 digest，扫描名字/路径，按来源家族分离开发与验收材料。
- 长期兼容包袱：新旧并行有明确退出门，清理作为独立变更，不在功能迁移中删除历史材料。

## Out Of Scope For This Delivery

- 任意未知总线协议的自动语义推断。
- 任意既有集成 SoC top 的逆向拆解和重建。
- 多 CPU/master、DMA initiator、coherence 或复杂仲裁。
- 多 clock 自动 CDC。
- AXI4、AHB、Wishbone 的完整 backend。
- 完整 SystemRDL/IP-XACT 生态集成；本阶段只建立稳定 adapter 边界和 fixture。
- 覆盖率驱动的在线自适应约束学习。
- 除分支覆盖率之外的研究覆盖指标。
- 以特定 IP 名称、当前 8-IP 清单或测试集路径为依据的生成逻辑。
