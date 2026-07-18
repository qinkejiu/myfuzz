# Plan: compose-v5 无名称 SoC、bit 级约束与覆盖率对比

_Locked via grill - by Codex + 用户，2026-07-17_

## Goal

在保留现有 materials、RFUZZ、源码级分支插装和 v2/v3/v4 兼容路径的前提下，新增独立的 `compose-v5`。用户只提供可 elaboration 的 CPU、RAM、IP 源码入口和模块角色；系统不使用模块名或端口名推断，正式 v5 实验不要求或使用逐端口、地址或约束声明，而是从 elaborated RTL 的结构和可观测行为中发现接口契约，自动生成地址图、fabric、必要的 bridge、SoC top、逐仿真步纯 0/1 bitstream decoder 和覆盖率实验。A 是所有原始模块并排实例化、所有端口扁平暴露的 direct-bit baseline；B/C/D 使用同一个自动生成 SoC，CPU 是唯一功能 master，依次比较 raw、固定 bit 级约束和覆盖停滞自适应变异。约束必须通过 `RAW_ESCAPE` 保留 manifest 上限内所有 fuzz-owned 外部注入点轨迹的 bit-exact 表达能力，不声称能直接驱动 SoC 内部连线。第一阶段优先完成协议波形层和扰动层，最后再从 CPU RTL 自动提取译码布尔谓词，不使用固定 ROM、程序对象、指令列表或事务列表。

## Approach

### 1. 冻结边界并建立 compose-v5

1. 归档当前计划和日志为 `PLAN.previous-v4-20260717.md` 与 `PLAN-REVIEW-LOG.previous-v4-20260717.md`。
2. 新增版本化 `compose-v5` manifest、IR、artifact schema、runner 和 CLI；不得原地改变 v2/v3/v4 testcase、replay 或 runner 语义。
3. 保留并复用 `materials/`、`src/myfuzz/rfuzz/`、`src/myfuzz/instrumentation/` 和 `src/myfuzz/targets/`，不恢复 `autotop`、`flow` 或旧 AutoTop 命令。
4. 正式 `compose-v5-auto` 实验输入只包含：源码/filelist、CPU/RAM/IP 模块角色、必要的 elaboration 参数和 top/module 标识。用户不提供端口角色、协议类型、地址窗口、约束或 bridge RTL。仓库已有可选注解能力保持兼容且在其他模式中仍具权威性，但使用任何注解的 artifact 不得计入本计划的无注解实验。
5. 用户输入中的源码和模块角色是物理事实；若角色与 elaborated RTL 不相容则报错。对于端口语义歧义，v5 不请求用户补注释、不按名称猜测，直接拒绝生成并输出证据。
6. 第一阶段只接受 Verilator 能完整 elaboration 的可综合 Verilog/SystemVerilog。Chisel/SpinalHDL 等必须先生成 RTL；VHDL、SystemC、blackbox、DPI 行为模型、加密 RTL和无法建模的 vendor primitive 不在范围内。

验收：旧 runner 的 replay digest 和行为不变；新入口不导入已删除 AutoTop；schema 版本、artifact digest 和失败分类稳定；drift check 通过。

### 2. 定义四个方案和唯一主覆盖口径

1. A `flat-raw`：实例化同一组、同参数的 CPU、RAM、IP，但不建立模块间功能连接。每个模块的 input（包括时钟和复位）独立暴露并拼接为顶层输入；output 拼接为观察输出；未知 `inout` 第一阶段拒绝。每个仿真步的 raw bits 直接驱动全部输入。
2. B `soc-raw`：使用自动 discovery/planner/bridge 生成的功能 SoC，CPU 是唯一功能 master。公共时钟、复位、外部环境和 boot response 均由 raw bits 驱动；boot memory 固定选择 raw 通道，不保证重复地址一致性。
3. C `soc-fixed`：与 B 使用 byte-identical compiled SoC binary 和 decoder。campaign 固定提高 `VALID` 的采样概率，较少采样 `PERTURB`，保留 `RAW_ESCAPE`；boot memory 高概率 persistent、较低概率 streaming/raw。
4. D `soc-adaptive`：与 C 使用完全相同的 binary、selector 解码和 bit-to-wire 语义；仅根据覆盖停滞改变下一输入的 mutation 位置、强度和长度。
5. A/B/C/D 使用同一份原始模块源码、参数和源码级分支 ID catalog。主覆盖只统计用户列出的 CPU、RAM、IP；生成 top、decoder、fabric、bridge、lazy boot memory 和控制逻辑只记录 diagnostic coverage，不进入主分母。
6. 分别报告 CPU、RAM、每个 IP 和全体原始 RTL 的 hit/total；任何原始模块参数、插装源码或 catalog digest 不一致都拒绝比较。
7. A 的结构与 B/C/D 不同，因此 A 只作 direct-bit baseline 描述性参照。科学主比较是同 DUT 的 C-B 和 D-C。
8. Ibex、RVX、CVA6 运行 A/B/C/D。冻结生成器后揭示的 holdout 只运行 B/C/D，不为 holdout 人工补 A top。

验收：catalog digest 在四方案间一致；generated infrastructure 的 branch ID 不出现在 primary bitmap；报告明确标记 A 的拓扑差异。

### 3. 定义纯 bit、变长、逐仿真步输入 ABI

1. testcase 只是扁平 0/1 bitstream，不包含指令、程序、操作或事务对象。布局为 `step_0 || step_1 || ... || step_n`。
2. 每个 record 是一个仿真步，不承诺产生 CPU cycle。record 包含该方案全部可控输入和 selector bits；bit 顺序固定为 LSB0，layout 由机器可读 manifest 给出并带 SHA-256。
3. 每步先同时设置全部 fuzz-owned 输入电平，再调用组合求值直到达到稳定点或冻结的 settle 上限；输入时钟电平变化产生真实边沿。超过 settle 上限的 testcase 标记为无有效覆盖的执行失败。
4. A 的每个模块时钟/复位独立占 bit；B/C/D 的公共功能时钟/复位占 bit。C 的 VALID 可投影为稳定高低交替和合理复位保持/释放；PERTURB 可停钟、插入额外边沿、短复位或异步释放；RAW_ESCAPE 逐步直通。
5. 协议状态、lazy memory 和事件窗口只在实际检测到的相应时钟边沿更新，不按 record 数更新。
6. testcase 开始时创建全新 Verilated model，或恢复经 bit-exact 验证的无 DUT edge 初始快照；不得用隐藏时钟/复位边沿初始化 DUT。所有 simulator randomization 初值固定并写入 replay metadata。
7. bitstream 用尽后立即结束测量，不 drain DUT；末尾不足一个 record 时补零。墙钟 deadline 到达后不再派发新 testcase，已开始 testcase允许完成并记录 overshoot。
8. 单 testcase 上限为 `1 MiB` raw bytes 和 `65,536` steps，实际 step 上限取二者较小值；若一个完整 record 超过 `1 MiB`，artifact 在构建期拒绝，而不是破例运行。所有长度运算使用 checked arithmetic。
9. B/C/D record layout 相同。A 因端口更多可具有更宽 record 和更少最大 steps；报告实际 bytes、steps、有效上升沿和 DUT eval 次数。

验收：layout round-trip、padding、截断、checked-length、fresh-state replay、clock-edge trace 和 deadline 测试通过；同一 replay bundle 产生相同 wire digest 与 primary coverage。

### 4. 实现无名称的结构与行为 discovery

1. 先扩展并版本化现有 Verilator frontend schema；它必须导出 elaborated sensitivity tree、同步/异步 reset 极性、完整 guard/control predicate、位选择/切片、比较/case、state transition 和跨层 driver/load 关系，而不只是粗粒度 LHS/RHS 依赖。Schema feasibility fixture 未证明这些事实可稳定取得前，不开始 contract 归纳。
2. 基于上述 elaborated AST/netlist 事实收集，不使用正则表达式、模块名、实例名或端口名进行接口决策；从 sequential sensitivity、异步控制和 state-update 关系识别时钟、复位及其极性，第一阶段所有功能通信必须属于一个时钟域。
3. 构建 bit-precise port/state/control 依赖图，记录位宽、方向、唯一 driver、寄存器更新条件、比较、case、切片、数组索引和可观测输出影响。
4. 在任何 target discovery 前冻结 versioned contract hypothesis grammar：允许的端口分组、状态变量、guard、accept/complete/error、payload stability、ordering、reset 和 trace observation 构造均有有限规范；同时冻结 alpha-renaming/state-bisimulation 等价关系和 canonical form。
5. 按共同控制依赖和状态转移关系形成候选端口组。单 bit/小组合受控探测、bounded SAT/SMT 和支持/反驳 trace 只用于提出和淘汰候选解释，不得据此宣称唯一协议意图。ambiguity checker 必须穷举冻结 grammar 在 manifest width/state bound 内的全部 canonical hypotheses，证明只有一个等价类存活；grammar/bound 之外不作唯一性声明。
6. 候选 contract 必须进一步对实际端点 RTL 的相关 transition relation 做归纳/refinement 检查，证明请求接受、payload 稳定、完成、等待、错误、顺序和复位谓词；只有 ambiguity checker 得到一个等价类且该类完成证明，才归纳为与协议名称无关的局部 interface contract automaton。
7. 已知协议 profile 只能在发现和证明后分类、补充独立校验和生成报告，不能参与首次绑定，也不能按模块名选择。
8. 若多个 canonical 等价类仍可满足实际 RTL、存在未知关键 input/inout、不可分析构造、grammar bound 不足或归纳证明无法完成，fail closed；正式 v5 实验不得要求用户补逐端口注释继续。
9. 每个 contract 输出 evidence bundle：frontend schema、hypothesis grammar/bound/equivalence 版本，结构/控制依赖、canonical hypotheses、支持/反驳 trace、穷举 ambiguity 结果、归纳/refinement 证明、RTL/tool digest 和歧义说明。

验收：frontend feasibility fixture 覆盖 sensitivity/reset/guard/slice/state transition；端口和模块批量重命名、随机前缀、端口重排后得到同构 contract；删除关键行为证据后必须拒绝；通用源码静态扫描不得包含实验模块名或端口名特判。

### 5. 自动推导地址窗口和启动区域

1. RAM 容量从存储数组深度、索引表达式和数据宽度计算。
2. 寄存器型 IP 的 aperture 从地址参与的比较、case、切片和数组索引推导精确 predicate、offset、稀疏区域、洞、别名、对齐和权限条件；bridge 两侧的地址截断/变换进入 contract。
3. 保留端点的精确 decode predicate。只有等价证明通过才可化简或取整窗口；允许为 fabric 分配外层对齐窗口，但内部必须继续执行精确 predicate，洞和不可访问区域路由到已证明的错误响应，不套用常见 4 KiB 或二次幂默认值。
4. planner 在 CPU 可寻址空间内确定性分配：启动/RAM 优先，其余按 elaborated 结构指纹排序。相同输入必须得到 byte-identical address map；重叠、截断、不可达或空间不足直接失败。
5. 生成后探测窗口起点、终点、相邻未映射地址和每个可识别 offset，验证 decode 与原 contract 一致。
6. 不使用固定 ROM。discovery 可用临时响应环境和 bounded trace 提出 reset-fetch 候选，再对候选请求及其 state cone 做归纳证明，确认响应数据会驱动持续取指/译码状态且不会把 trap、共享数据口或内部 fetch 错认成唯一启动接口。
7. 正式 SoC 删除临时全地址响应器。在 CPU 取指区域加入无预置内容的 bit-backed lazy boot memory；用户 RAM 仍作为真实地址映射组件并计入覆盖。若用户 RAM 有经验证 loader，可直接作为 backing store。
8. shared/trap/internal fetch 无法消歧、无法唯一证明取指区域、只能从内部不可写 ROM 启动或无法在单时钟域形成可达地址图时拒绝生成。

验收：地址图确定性、边界/alias、无重叠、reset-fetch 重放和“正式 artifact 不含临时 responder/固定内容”测试通过。

### 6. 自动规划 SoC、fabric 和 bridge

1. planner 以发现的 interface contracts、时钟域和地址窗口为唯一连接依据，生成有序连接图；CPU 是唯一功能 master。每个原始 RTL input 必须在 ownership manifest 中恰有一个 owner：原始 RTL output、generated target output，或 manifest 中的 fuzz-owned 外部注入点。
2. CPU request/output 永远拥有内部请求边，decoder 的 VALID/PERTURB/RAW_ESCAPE 不得成为内部 CPU-to-IP wire 的第二 driver。可选内部 fault transform 只能对 CPU 已产生的 active request 做延迟、丢弃或 bit 破坏，CPU idle 时不得凭空创建请求，因此不构成第二 master。
3. 同构契约直接连接；多 target 时生成通用地址 decode/fabric。fabric 的队列深度、顺序、backpressure、reset 和错误目标语义来自 contract，不从协议名或模块名选择。
4. 不兼容接口进入 bridge synthesizer。synthesizer 在通用 primitive 空间中搜索组合连接、寄存切片、FIFO、位宽拆合、地址/byte-enable变换、backpressure、outstanding 限制、顺序恢复和错误映射；primitive 描述状态转换，不描述具体协议/IP 名称。
5. 通用 primitive library 具有独立于 discovery 输出的手写数学语义和归纳证明。只有存在保持两侧可表达语义的 contract mapping 才生成 bridge；不能表达的原子性、顺序、错误或并发语义导致失败，不允许静默降级。
6. 独立定义 endpoint observable trace semantics：request/response accept event、payload、error、ordering tag 和 reset epoch；同时为每端冻结 environment assumptions、fairness、initial/reset state correspondence 和允许的 stutter。bridge proof obligation 是在这些 assumptions 下，两侧实际 endpoint RTL + bridge 的 observable traces 双向满足声明的 trace refinement/映射。
7. 自动生成 bridge assertions：不丢失/重复请求和响应、正确配对、保持 payload、遵守两侧 reset/ordering/backpressure 合同。这些 assertions 只作诊断；正式 gate 是 endpoint RTL miter 的 assume-guarantee induction。每个 assumption 必须有 satisfiability witness，每类 accept/complete/error/backpressure mapping 必须有 mandatory cover，禁止靠不可满足 assumption 或永不发生请求的 vacuous proof 通过。
8. 组合映射、位宽、地址和 byte-enable 转换要求完整形式等价；带状态 bridge 必须完成归纳证明。32 次请求/响应边界 BMC 和 10,000 条 raw-bit 差分轨迹作为补充回归，不能以 `32-bound verified` 身份进入正式实验。
9. 第一阶段拒绝跨功能时钟域连接；异步外部输入可生成同步器，但其物理输入仍可由 RAW_ESCAPE 驱动。

验收：连接图可重放；每条 edge 有 contract/evidence；形式和差分门槛通过；故意删除必要 bridge primitive 时必须给出不可连接报告而非生成错误 RTL。

### 7. 定义 BitConstraintIR 和三通道 decoder

1. `BitConstraintIR v5` 是约束生成的唯一中间表示。来源仅为 verified contracts、地址图、时钟/reset contract、结构行为证据和 post-discovery profile validation；不接受模块专用表或用户逐端口规则。
2. IR 记录 bit offset、消费时机、state update、依赖谓词、selector 解码、RAW right-inverse映射、来源证据、适用方案和 digest。emitter 只序列化 IR，不再次推断策略。
3. 每个 fuzz-owned 外部注入点生成三种 selector 通道；内部 functional edge 不接受 raw 第二驱动：
   - `VALID`：保持握手、payload稳定、响应关联、地址对齐、时钟和 reset 合同。
   - `PERTURB`：由 bit 选择只破坏一条已发现关系，例如外部响应延迟、提前撤销、等待期 payload 变化、乱序或边界脉冲，其余声明关系保持；若启用内部 fault transform，只能变换 CPU 已有请求。
   - `RAW_ESCAPE`：所有 fuzz-owned 外部物理输入逐 bit 直通。
4. C 使用固定 selector 编码分布，大多数编码落入 VALID，较少落入 PERTURB，至少一个编码落入 RAW_ESCAPE。比例从统一 selector-width算法产生，不针对协议/IP 调参。
5. D 使用同一 selector 解码，不得依据全局覆盖改变同一 bitstream 的含义。
6. bit-backed boot memory 三种模式：persistent 首次访问消费 bits 并按地址保存、写入按 byte-enable更新；streaming 每次读消费新 bits；raw 直接驱动 data/response/latency/error。C/D 高概率 persistent，B campaign 固定选择 raw。
7. lazy memory 最多 65,536 地址条目或 16 MiB 数据；达到上限后使用 manifest 固定的 deterministic alias/eviction，不允许宿主容器顺序决定行为。
8. 对每条自动发现 contract，VALID trace 必须满足原 RTL 接受谓词；PERTURB 必须证明目标关系被破坏且其他声明关系保持；证据不足则不生成该通道。

验收：IR schema round-trip、emitter purity、VALID property、单关系 PERTURB、mode replay、memory consistency/byte-enable/eviction 和无模块名分支测试通过。

### 8. 证明 bounded bit-level 完整性

1. 完整性只声明于冻结 ownership manifest 的 fuzz-owned 外部注入点集合、最大 1 MiB 和最大 65,536 steps 内，不包含 CPU-to-IP 内部 functional edge，也不声称无界完整。
2. 自动生成 `encode_raw_trace(trace)`：每步选择 RAW_ESCAPE，并把目标 fuzz-owned 外部输入值写入 payload；正式 decoder 必须满足 `decode(encode_raw_trace(trace)) == trace`。
3. 小位宽/小 step fixture 做穷举；真实 target 做属性测试和形式等价。right-inverse 只检查 ownership manifest 中实际可控的时钟、复位、异步外部 pin、generated boot target response 等 fuzz-owned bit。非法协议或未映射请求只有在某 fuzz-owned 注入点能直接表达时才纳入；CPU 自己产生的地址/request 不属于该证明。
4. 同步器之后的内部值、CPU request wires、生成 bridge 状态和其他不可直接控制状态不属于完整性定义域，必须在 ownership/completeness manifest 中明确排除。
5. RAW_ESCAPE 的存在只证明表达能力，不要求 C/D 在有限时间内均匀访问所有 raw trace。

验收：每个 B/C/D artifact 都携带 completeness manifest、构造器和证明结果；任何 used-mask、截断、钳位或未贯通 bit 使构建失败。

### 9. 实现 controller-owned mutation 和 D 停滞升级

1. v5 controller 自己管理 corpus、parent selection、变长 insertion/deletion/splice/bit-flip 和 per-test coverage delta；不修改 upstream kfuzz。旧 RFUZZ 仅作为 bit/byte mutation能力复用。
2. campaign 内部随机初值固定并记录，但不作为多次实验维度；所有整数选择使用版本化确定性 RNG，避免浮点和容器迭代差异。
3. C 使用固定 mutation 权重。D 按连续无新增 primary branch 的 testcase 数升级：
   - 0-1023：正常，偏向 VALID；
   - 1024-4095：提高 selector、握手时序、时钟/reset和事件窗口 bit；
   - 4096-16383：提高 PERTURB、长度插删和片段 splice；
   - >=16384：提高 RAW_ESCAPE、多点翻转和跨 corpus splice，但保留 VALID。
4. 发现新分支后 D 立即回到第 0 级并保存新 corpus entry。升级只改变 mutation，不改变 decoder。
5. 初始 corpus 使用相同的长度集合和规范 raw patterns；B 将 selector规范为 raw，C/D共享 byte-identical起始 corpus。A 因 layout 不同只共享长度和基础 bit pattern规则。
6. corpus 上限 2 GiB。达到 90% worker RSS预算后停止扩展；淘汰无独占覆盖且长期未选的条目，策略和 tie-break固定并记录。

验收：固定初值完整 replay、checkpoint/resume、阈值边界、coverage-reset、C/D decoder digest相同、长度 mutation边界和 corpus eviction确定性测试通过。

### 10. 延后实现无指令表的 CPU bit 谓词层

1. 第一阶段 C/D 只依赖时钟/reset、协议波形、boot memory一致性和扰动，不以 CPU 语义层为前置条件。
2. 后续从取指数据到译码/合法/异常/控制状态建立依赖，提取 case、比较和掩码形成布尔谓词。
3. 使用 SAT/SMT 求出进入不同译码分支的原始 bit模式，不读取 ISA 指令表，不给模式命名，不生成 ProgramImage、指令对象或操作序列。
4. C/D 高概率选择一个可满足谓词，其他自由 bit仍由 bitstream决定；RAW_ESCAPE保留非法、保留和未建模编码。
5. 通过总线可观测行为关联会引起内存访问、控制流变化或异常的谓词，仅调整 mutation权重，不改变编码语义。
6. 最终追加 CPU predicate disabled/enabled 消融；这不是第一阶段四方案验收的阻塞条件。

验收：提取结果只由 RTL逻辑和 solver证据产生；重命名不变；每个生成编码满足对应 decode谓词；RAW right-inverse继续成立。

### 11. 资源安全和串行实验

1. 同时只运行一个 build 或 fuzz worker。先读取进程所在 cgroup 的 effective memory limit 和宿主可用资源，硬上限为 `min(8 GiB, effective limit 的 25%)`；启动前可用内存必须至少为上限的 1.5 倍。
2. build/fuzz 的整个 process tree 必须放入专用 cgroup 并设置 `memory.max`/`memory.swap.max` 和 PID 限制；只有在经过自测证明可覆盖整个子进程树时才允许 RLIMIT 作为 fallback。无法建立硬限制则不启动正式任务。
3. 每10秒记录 RSS、cgroup current/peak/events、可用内存和 swap delta。达到预算90%停止 corpus/lazy-memory扩展；轮询只负责 telemetry 和 soft throttle，不承担 OOM 防护。硬限制终止可能来不及 checkpoint，必须标记资源截断且不作为成功覆盖结果。
4. 所有方案使用相同 CPU affinity、线程、RSS、corpus和 testcase上限。编译时间不计入 fuzz墙钟；每个任务结束后确认进程释放再开始下一个。
5. 仅统计源码级分支覆盖率。编译失败、仿真失败、超时和资源截断只用于判定数据无效，不分析、不保存或报告 DUT bug candidate。
6. 分阶段运行：每 tuple 30秒 build/run smoke；每 tuple 5分钟初测；最终每 tuple 1小时。单一固定随机初值，不做多 seed重复。
7. 三个复现 target运行4方案，holdout运行3方案，最终串行 fuzz预算为15 worker-hours。每5分钟记录累计 hit/total、testcases、steps、有效上升沿、eval次数、throughput、corpus和RSS。
8. B 的 raw boot 与 C 的高概率 persistent boot 是固定约束 package 的有意差异，因此主 `C-B` 不能解释为单独的协议时序因果。每个 target 额外运行一次5分钟、非主排名的 `C-rawmem` 诊断：保持 C 的 clock/reset/protocol selector 和 mutation，仅把 boot mode 固定为 B 的 raw，用来分离 boot consistency 贡献；它不增加最终1小时四方案预算。
9. 结果定位为固定轨迹下的初步覆盖率证据，不作统计显著性或因果推广。

验收：preflight、RSS cutoff、无并发worker、deadline、checkpoint和CSV schema测试通过；资源失败不被静默重跑或从报告删除。

### 12. 冻结后 holdout 和覆盖率验收

1. Slice 0冻结候选源码池的清单、许可、文件哈希和确定性选择算法；开发与review allowlist排除候选RTL内容。完成三复现 target后冻结 generator源码、toolchain和artifact schema digest，再由独立 reveal步骤按哈希顺序选择首个可编译的 CPU + RAM + 至少2 IP组合。
2. holdout只得到与正常compose相同的源码入口和模块角色，不得添加端口/协议/地址声明。失败只记录原因；不允许针对已揭示设计修改语义规则后重跑同一 holdout。
3. 若失败仅因已声明支持范围内的frontend语法缺陷，可以修复通用parser，但必须重新冻结并选择下一个holdout；原失败仍保留。
4. 静态扫描生成器源码，禁止 holdout模块名、端口名、路径或结构指纹条件分支。
5. 主验收只看 primary branch hits：三个复现target和holdout中，C相对B的分支数中位值（这里只有单轨迹，等同最终值）均必须为正；四个target至少3个达到相对 `C-B >= 3%`；任何target的C-B回退不得超过1%。
6. D相对C至少3个target为正，其余回退不得超过1%。同时报告绝对新增分支、百分点差、相对提升和吞吐，不能只报百分比。
7. A单独展示，但不参与同DUT验收。旧6小时数据只作背景，不与v5新catalog百分比混合。

验收：freeze/reveal日志、禁止特判扫描、generation evidence、B/C/D catalog digest和最终 hourly/5-minute CSV齐全；未满足阈值则如实判定实验假设未被当前实现支持。

### 13. 实施切片和验证命令

1. Slice 0（资格与信任边界）：定位并哈希实际 Ibex/RVX/CVA6 target filelist，逐个用当前 toolchain elaboration；任一真实 target 不可用就停止复现实验，不用 surrogate 冒充。同步冻结 v5 schema、artifact inventory、coverage catalog、holdout pool 和资源 manifest。
2. Slice 1（最小执行与前端可行性）：先实现共同 time-step runner ABI、fresh-state/raw replay fixture，再扩展 frontend v5 schema并用 sensitivity/reset/guard/slice/state transition fixture 证明所需事实可取得。
3. Slice 2：无名称 dependency graph、behavior candidate probing、actual-RTL refinement/induction、contract automata、精确地址 aperture 和歧义拒绝。
4. Slice 3：A flat-aggregate emitter、完整 layout、raw round-trip 和 ownership manifest。
5. Slice 4：planner、fabric、bridge synthesis、独立 primitive proof、endpoint miter gates 和 lazy boot qualification。
6. Slice 5：B raw campaign、BitConstraintIR、RAW right-inverse证明。
7. Slice 6：C三通道投影、persistent/streaming memory和约束证据。
8. Slice 7：D adaptive controller、corpus、checkpoint和资源保护。
9. Slice 8：Ibex/RVX/CVA6串行smoke、5分钟和1小时覆盖实验。
10. Slice 9：freeze/reveal holdout、B/C/D实验和最终报告。
11. Slice 10：CPU decode predicate提取和消融。
12. 每个slice先跑最小fixture，再跑相关builder/RFUZZ/instrumentation回归，最后只跑一个真实target。计划中的CLI路径在实现slice创建后才加入active runbook。

### 14. 输入源码与工具执行信任边界

1. compose filelist/RTL 视为不可信输入：所有路径先 canonicalize，必须位于 manifest 明确列出的只读 allowed roots；拒绝逃逸 root 的 `..`、绝对路径和 symlink，生成目录与临时目录不得反向进入源码树。
2. 所有 Verilator、solver、编译器和 runner 调用使用 argv array，不经 shell 拼接；环境变量采用 allowlist 并清除 preload、语言包和用户级工具注入，正式构建禁用网络。
3. 源码以只读方式提供给隔离子进程，输出只写专用临时目录；沿用并扩展现有 `ElaborationManifest` containment，记录 tool path/digest、argv、scrubbed env digest 和 source-root digest。
4. 解析 filelist/RTL 时拒绝未经 allowlist 的 nested option、插件、DPI、动态库、任意输出路径、`$system`/`$shell`、宿主文件读写 system task 和其他外部副作用构造；允许的 memory initialization 只能读取 canonicalized、只读 allowed-root 内的 manifest 文件。
5. 编译和生成 executable 均在无网络的 user+mount+PID namespace 中运行，只挂载只读 source/tool roots 和专用可写 tmp/output；生成 executable 使用 syscall allowlist/seccomp，禁止 exec、网络、任意 mount、ptrace 和 allowed dirs 外文件访问。超时、PID、CPU、文件大小和 cgroup 内存限制覆盖完整 process tree。

验收：路径穿越、escaping symlink、恶意 filelist option、`$system`、宿主文件 IO、环境注入、网络访问、syscall 和子进程逃逸 fixture 均 fail closed；合法只读 source root 可重放生成相同 digest。

计划实现后的核心验证命令口径：

```sh
python3 -m unittest discover -s tests -p 'test_compose_v5_*.py'
python3 src/myfuzz/scripts/compose_v5.py --manifest <fixture.json> --output /tmp/compose-v5
python3 src/myfuzz/scripts/compose_v5_campaign.py --artifact /tmp/compose-v5 --scheme B --seconds 30
python3 src/myfuzz/instrumentation/source_branch_instrumenter.py --help
/home/qinkejiu/.codex/skills/myfuzz-dev-rigor/scripts/check_drift.sh /home/qinkejiu/myfuzz/myfuzz
```

## Key decisions & tradeoffs

1. 输入始终是可变长度、逐仿真步的纯bitstream；更复杂的约束只改变bit到wire的公开映射或mutation分布，不引入事务/指令对象。
2. 时钟和复位也被fuzz。代价是record不再等于cycle，必须统计真实边沿并使用fresh model隔离testcase。
3. 正式 `compose-v5-auto` 实验不接受或使用逐端口用户声明，也不做名称推断。仓库既有注解能力不删除，但使用注解的 artifact 不属于该实验；歧义设计直接失败。
4. 协议profile不是首次识别表，只能对已由结构/行为证明的contract分类和校验。
5. bridge由contract自动综合而不是用户提供，但必须以独立定义的 primitive 语义和实际 endpoint RTL 的 refinement/induction 证明，不能让推断 contract 自证。
6. A保留传统RFuzz“所有模块端口直接随机”的能力；B/C/D才是CPU唯一master的功能SoC。A与B/C/D结构不同，因此不作严格因果比较。
7. 无固定ROM。lazy boot内容由实际访问时的原始bits产生；用户RAM仍是真实被测模块。
8. 完整性由 fuzz-owned 外部注入点上的 RAW_ESCAPE 右逆证明，不包含 CPU 驱动的内部 functional edge，不以 VALID/PERTURB 覆盖所有行为为依据，也不声称有限时间探索均匀。
9. 第一阶段优先协议有效波形和自适应扰动；CPU语义层延后，并从RTL布尔谓词自动提取。
10. 单轨迹、1小时结果减少成本，但只能作为初步证据；计划不声称统计显著性。

## Risks / open questions

1. 无名称行为归纳和自动bridge synthesis是主要技术风险。有界 probing 只能提出候选；无法相对实际 RTL 完成唯一解释和归纳证明时，实验应失败而不是产生错误SoC。
2. 全新model per testcase可能降低吞吐。只有通过bit-exact验证的无边沿初始快照才可优化，不能用隐藏reset改变实验语义。
3. raw随机取指在CPU谓词层完成前可能仍使CPU覆盖较浅。第一阶段依靠时钟/reset、boot响应和协议一致性验证方法方向；若C不超过B，应如实报告，不能加入手写指令模板补救。
4. 旧三target源码在当前工作树中可能已被用户删除或迁移，且现有 materials 可能没有真实 Ibex/RVX filelist、CVA6 也可能只有不合格模型。Slice 0必须先解析实际可用filelist并逐个 elaboration；不得恢复用户删除内容，也不得用简化模型代替目标后声称复现成功。
5. 单随机轨迹可能受偶然性影响。用户已明确接受该成本/证据权衡；最终报告必须保留此限制。
6. route-lock允许且要求既有 builder 路径保留可选端口注释的权威性；本计划通过新增严格的 `compose-v5-auto` 实验 profile 排除注解，而不是删除或削弱原能力。遇到unknown input/inout时采用更严格的拒绝策略。
7. B/C 的 boot mode 差异使 `C-B` 衡量整套固定约束而非单一协议层。`C-rawmem` 只提供诊断性分解，不改变用户锁定的四方案。

## Out of scope

1. 恢复旧AutoTop或按模块/IP名称维护连接表。
2. 正式 `compose-v5-auto` 实验中的用户逐端口语义、地址、约束或bridge声明；现有非实验模式的兼容能力不在删除范围。
3. 固定ROM、ProgramImage、指令/操作/事务列表和事务级fuzz输入。
4. 多功能master、并发verification master或多功能时钟域/CDC bridge。
5. VHDL、SystemC、高层HDL直接输入、不可分析blackbox和加密RTL。
6. 任意两个接口必然可转换、无界输入完整性或自动恢复任意RTL设计意图。
7. DUT bug、安全漏洞或安全属性评估。
8. 多seed统计显著性结论、与旧6小时不同catalog百分比直接混合比较。
