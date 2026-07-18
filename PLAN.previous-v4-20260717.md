# Plan: 无损三层 bit-level 输入与自适应 AXI-Lite 探索

_Locked via grill - by Codex + 用户，2026-07-15_

## Goal

在保留历史 A direct-bit baseline、RawBits v2、当前 RawBits v3、RFUZZ、分支覆盖插桩和已有实验材料的前提下，把现有会在 harness 中覆盖 opcode、地址、target、wait/timeout 等字段的约束方案，替换为可验证的无损三层输入系统。系统必须高概率生成有意义输入，但不能删除任何属于已声明有效输入集合的 bit-level 编码路径。三层分别是 CPU 语义有效输入、AXI-Lite master 侧协议有效逐周期输入，以及允许乱序、协议违规和 raw bit 变异的受控探索输入。第一阶段优先交付协议层与受控扰动层；第二阶段补齐 CPU 语义层和可变程序片段；最终使用相同墙钟预算和相同硬件资源运行 A/B/C/D 分支覆盖率实验。

## Approach

### 1. 冻结历史能力并建立不可变边界

1. 保存并继续运行历史 A 方案，包括其 direct-bit 拓扑、RawBits v2 几何、生成器、runner、replay bytes 和历史结果，不改变任何输入解释。
2. 保存当前 RawBits v3、B/C/D runner、ControlPlaneIR、TemporalConstraintIR、ROM、harness 和实验结果，作为只读兼容路径；新实现不得原地改变 v3 schema 或旧 testcase 语义。
3. 为 A/v2 和当前 v3 生成 path、size、SHA-256 inventory。任何迁移都生成新 artifact，不覆盖源 artifact。
4. 保留并复用 `materials/`、`src/myfuzz/rfuzz/`、`src/myfuzz/instrumentation/` 和 `src/myfuzz/targets/`。禁止恢复旧 AutoTop 目录、入口或模块名驱动的固定拓扑生成器。
5. 将当前计划和评审日志归档为 `PLAN.previous-v3-20260715.md` 与 `PLAN-REVIEW-LOG.previous-v3-20260715.md`。

验收：历史 A/v2 和当前 v3 的 replay digest、coverage catalog 和 runner 行为不变；新代码不被旧 runner 导入；仓库 drift check 不报告 AutoTop 或模块名特判回归。

### 2. 定义三层有效输入集合和完整性边界

1. `CPU_SEMANTIC`：最终覆盖冻结 `CpuStateDomain` 和当前 CPU profile 实际启用 ISA 下的全部合法有界程序片段、可实现初始状态、异常入口，以及高效率的语义操作序列。第一阶段仅保留现有 CPU/ROM 兼容路径，不宣称 CPU 语义完备；第二阶段实现本集合。
2. `PROTOCOL_WAVEFORM`：覆盖 AXI-Lite master 控制的全部合法有限逐周期驱动轨迹。该定义只包含 master 输出，例如 AW/AR 地址和保护位、W data/strobe、各通道 VALID 与 BREADY/RREADY；slave 的 READY、RESP 和 RDATA 是运行反馈，不是 fuzz 输入。完整性不承诺 fabric 接受任意数量的 outstanding transaction。
3. 协议完整性限定为 manifest-bounded response-compatible stimulus completeness：对冻结 manifest 声明的最大 logical records/chunks/bytes 范围内，任意满足 AXI-Lite master 规则且与实际观察到的 slave/fabric 响应相容的 master 驱动轨迹，都存在一个 v4 逻辑 testcase 编码可逐 bit、逐周期重放。单个 transport chunk 有长度上限，逻辑 testcase 可由多个 continuation chunk 组成；执行前必须收齐并验证整个逻辑 testcase，chunk 边界不执行 infrastructure reset、不切换 lane/epoch、不清空 DUT/front-end state。默认生成 artifact 为 64 DUT cycles。fabric 实际接受的 outstanding 深度是独立、显式报告的 backend capability，不能混入输入编码完整性结论。
4. `ADVERSARIAL_MUTATION`：允许语义乱序、协议乱序、局部协议违规、非法指令和受限 raw bit 变异。它用于探索容错、死锁、异常和恢复路径，不属于“有效输入完整性”的证明集合。
5. 协议合法性只由总线协议决定。未映射地址、权限错误、读写不合适寄存器、全部合法 WSTRB 组合和错误响应仍是协议有效输入，不得被地址表或寄存器模型过滤。
6. 时钟属于实验基础设施并固定。reset 时机/宽度/域、IRQ、GPIO、外部响应和 fault 输入在 manifest 声明后全部可 fuzz；未声明输入按 unknown-port policy fail closed。

验收：文档、schema 和报告分别标识 declared lane、observed classification、合法性规则及首次违规点；任何覆盖率结论不得把第三层输入称为协议有效输入。

### 3. 引入 RawBits v4 无损 tagged union

1. 新增版本化 `RawBits v4` testcase envelope。每个 testcase 带固定 lane tag，lane 只能在 testcase reset 边界切换：`RAW_ESCAPE`、`PROTOCOL_WAVEFORM`、`ADVERSARIAL_MUTATION`，以及第二阶段启用的 `CPU_SEMANTIC`。
2. 每个 lane 有独立、规范化、带 digest 的 payload schema。字段必须记录 offset、width、source、consumer、used-mask 规则、默认解释和 provenance。
3. harness 只按 lane 解码，不允许无条件覆盖地址、opcode、target、wait、timeout 或 raw payload。`LITERAL_TRACE` 与 `RAW_ESCAPE` 的声明 wire bits 必须逐 bit 原样到达验证前端输出。
4. “无损”定义为每个有效值 `x` 至少存在一个编码 `e`，满足 `decode(e) == x`。对于可编码对象提供 canonical `encode(x)`，强制验证 `decode(encode(x)) == x`。
5. 枚举、地址、长度、时间和 ISA 字段使用显式宽度、rank/unrank 或 escape code。禁止用钳位、低位清零、静默截断或 `% N` 作为唯一映射，从而删除合法值。
6. `RAW_ESCAPE` 是字节保留的最终回退：其 payload 不进行合法化或字段修复。它保证新抽象遗漏的输入仍有明确入口，但不等于将所有 raw 输入归类为有效。
7. 提供 v2/v3 到 v4 的 opaque wrapper。wrapper 只携带原始 schema、digest 和 bytes，解封后 byte-for-byte 交给旧 runner；不自动提升成 v4 原生语义 corpus。

#### RawBits v4 transport ABI

1. v4 不复用旧 RFUZZ “每 cycle 一个无头固定 record”作为 testcase framing。定义独立的 `myfuzz.rawbits-transport/v4`：固定 64-byte little-endian header，加固定 record width 的 body。
2. header 至少包含 magic、transport version、header bytes、lane、submode、flags、logical-testcase ID、32-bit unsigned chunk index、continuation/final 标志、record width bits/bytes、record count、payload bytes、layout digest prefix、header CRC32 和 reserved-zero bytes。完整 SHA-256 放在 sidecar manifest/replay bundle；固定 64-byte layout 必须由机器可读 schema 逐 offset 定义，并有编译期/单元 size assertion。
3. 一个编译 target 的 record width 固定为所有启用 lane layout 的最大宽度；较窄 lane 的未使用高位和 record 尾 padding 必须为零。bit 顺序固定为 LSB0，record 按 8-byte 边界排列。
4. 每个 chunk 的 `record_count` 范围为 1..65535；chunk count 不超过 manifest 上限且绝不超过 32-bit index 可表示范围；`record_width_bytes`、单 chunk payload 和单逻辑 testcase累计 records/bytes 均有 manifest 资源上限，并使用 checked add/multiply 验证。插入/删除 mutation 只能改变有界 record sequence 并同步更新 count/length。continuation chunk 必须 ID 相同、index 从零连续、lane/layout digest 相同且恰有一个 final chunk。controller/target 在任何 DUT edge 前完整缓冲并校验所有 chunk；缺块、重复、越序、早 final、final 后数据或超上限统一返回 `format_invalid`，不会产生 DUT 状态或 coverage。完整性只针对该冻结 manifest 可表示的有限集合，不声称无界长度。
5. lane/tag/header 由 controller 生成，不属于 fuzz entropy，也不允许 mutation。payload mutation 不能越过 header/body 边界。
6. magic、版本、CRC、digest prefix、长度、零 padding 或 reserved 字段错误时，在第一个 DUT edge 前返回 `format_invalid`，不产生 primary coverage，也不进入 corpus；格式错误是 controller/transport 缺陷，不是 DUT adversarial 输入。
7. 旧 shared-memory RFUZZ ABI、padding 规则和 kfuzz conformance runner保持不变，仅服务 A/v2、v3 兼容与回归。v4 使用自己的 versioned controller/target transport，不让旧 parser 猜测新 framing。

验收：schema round-trip、canonical digest、unknown-field、version mismatch、opaque byte round-trip 和每个 lane 的 used-mask 测试全部通过。

### 4. 将约束从字段改写改为采样分布

1. 删除新路径中“生成 raw bits 后在 harness 内强制改地址/opcode/等待时间”的设计。旧 v3 实现保留但不被 v4 调用。
2. v4 约束只决定软件生成器更常产生哪些编码，例如 mapped address、短等待、常见 WSTRB 或常见握手序列；每个罕见但有效值仍至少有一个可达编码。
3. 权重和选择使用确定性整数算法，配置写入 manifest 并带 digest。禁止宿主浮点差异、隐式随机数或依赖运行时字典顺序。
4. harness 中允许有状态“语义解码”，例如 `GUARDED_INTENT` 在 AWVALID 等待 READY 时保持已锁存 AWADDR。这不是修复 literal bits，而是该子编码的公开语义；原始逐周期要求由 `LITERAL_TRACE` 表达。
5. 每条输入记录 reason trace：lane、子编码、消费 bit、父输入、变异算子和输出 wire digest。reason trace 不进入 branch coverage。

验收：静态扫描和单元测试证明 v4 harness 不包含 v3 式强制字段覆盖；分布权重变化不能改变可编码值集合。

### 5. 建立协议驱动且可泛化的 AXI-Lite profile

1. 核心 planner、profile 和 emitter 不得按 IP 模块名、实例名、当前八个 IP 或测试路径分支。
2. `ProtocolProfile` 声明 AXI-Lite 信号组、方向、可选项、位宽关系、通道独立性、稳定性、握手、response 顺序和 reset 合同。`AWPROT`、`ARPROT` 作为标准可选 master 信号由结构发现；RTL 存在时必须在 RawBits layout、front-end、fabric、target adapter、monitor、replay 和 round-trip 中逐 bit 贯通，RTL 不存在时 capability manifest 明确标记 absent，不能由通用代码假装存在或静默丢弃。
3. discovery 从 RTL AST/elaboration、端口方向、位宽、参数和用户 manifest 收集事实。elaboration 得到的端口存在性、方向和可证明位宽是不可覆盖的物理事实；用户声明或 profile 与其冲突必须报错。仅对物理事实不能决定的语义角色、接口分组、可选能力和 policy 使用优先级：用户声明 > profile 唯一匹配 > 静态候选。
4. 仅在结构匹配唯一时自动绑定。多个候选、未知关键 input、未知 inout、时钟/复位歧义或能力不匹配必须 fail closed，并输出最小补充 manifest 所需字段。
5. 每次生成输出可审计 manifest：端口角色、连接、地址窗口、时钟域、复位极性、unknown-port 决策、证据来源、置信度和 profile digest。
6. 同协议新 IP 只能通过结构匹配或显式 adapter 接入。adapter 必须声明真实非标准语义，不能成为模块名打表的隐藏入口。
7. 本轮完整实现并证明 AXI-Lite。APB、AXI4、Wishbone 等使用同一 profile/backend 接口扩展，但不要求本轮完成；已有 APB 能力不得回归。

验收：全部现有 AXI-Lite case，以及至少三个在通用实现冻结后才揭示的 holdout IP。holdout 覆盖非标准前缀、宽度变化、多个 AXI-Lite interface、复位极性和额外外部端口；holdout 名称不得出现在通用代码或专用测试分支中。

### 6. 同步生成验证 master front-end 和 SoC 结构

1. 正常功能 SoC 中 CPU 仍是唯一 master。CPU、地址映射、fabric、IP 和系统服务继续由 SoCIR/profile/planner 生成。
2. 现有 fabric 的单 outstanding/读写串行化能力必须在 v4 前显式版本化。第一阶段将其替换或新增为 profile-driven、可配置有界深度的 AXI-Lite fabric：AW、W、AR 分别 FIFO 接收；第 n 个已接收 AW 只能与第 n 个已接收 W 配成写请求。写请求只分配 write sequence，B 只按 write acceptance 顺序经 write reorder buffer 返回；读请求只分配 read sequence，R 只按 read acceptance 顺序经 read reorder buffer 返回。读写 sequence、buffer、READY/backpressure 和前进条件完全独立，较早 B 绝不能阻塞 R，较早 R 也绝不能阻塞 B。跨 target 仍保持各自 channel 内顺序；超出任一 queue/reorder depth 时只通过对应 READY backpressure，绝不丢弃、重配或越序响应；默认 error target 也遵守对应 channel 顺序。depth、counter width、wrap prevention 和 reset 时 queue/sequence/reorder 清空规则写入 SoCIR/backend capability。
3. CPU 和 fabric 之间新增仅用于验证的互斥 master front-end。它不是可并发系统 master，只能在 testcase 开始前选择 CPU 或 trace injector，选择后锁存到 infrastructure testcase reset。
4. `PROTOCOL_WAVEFORM`、`ADVERSARIAL_MUTATION` 和 `RAW_ESCAPE` 运行时 CPU 保持 reset 或被安全 clock-gate；trace injector 独占同一个 master 端口。CPU 不允许在后台积累未观察状态。
5. 第二阶段 `CPU_SEMANTIC` testcase 选择真实 CPU 路径，trace injector 隔离。
6. 明确区分 `infrastructure_reset` 和 fuzz-visible `dut_reset_event`。只有 infrastructure reset 可以切换 lane、coverage epoch、controller/testcase state；testcase 内的 DUT reset 只是 payload 动作，lane 不变、record index 按公开规则继续，guarded pending state按 protocol reset 规则清空，literal bits 继续由 monitor 判断。
7. testcase 生命周期使用至少三个 epoch：setup epoch 覆盖 infrastructure reset/startup但不计分；在第一 measured rising edge 前、无 DUT edge 的安全 phase 切换到全新的 measurement epoch；最终 measured edge NBA settle 后立即 snapshot；drain/teardown 使用另一 epoch或 coverage gate。primary bitmap只取 measurement epoch。v4 coverage ABI 使用至少 64-bit、进程内严格单调且永不复用的 epoch ID；分配前检查剩余空间，任何可能回绕都先完成 checkpoint 并启动全新 target process，禁止同一进程复用历史 epoch 值。旧 v2/v3 epoch ABI 不原地修改。
8. testcase 结束后停止接收新输入，snapshot coverage，执行有界 outstanding drain；必要时隔离 master 并 infrastructure reset。只有 reset/quarantine 完成后才能开始下一 testcase。
9. mode switch、reset、drain、watchdog 和 teardown 周期不进入 primary coverage；它们仍消耗实际机器墙钟时间，防止通过暂停计时获得不公平预算。
10. CPU、front-end、decoder、harness、coverage collector 和生成 fabric 不进入 A/B/C/D primary branch catalog。primary catalog 只包含 A 与生成 SoC 都存在的目标 DUT component，使用 variant-independent component IDs。

验收：互斥驱动形式属性、CPU reset 隔离、AW/W FIFO ordinal pairing、跨 target 的独立 write/B 与 read/R channel ordering、读写互不阻塞、queue/reorder backpressure、reset 清空、outstanding drain、final-cycle coverage snapshot、epoch 临界值拒绝/进程轮换、跨 testcase epoch 清零和无状态泄漏测试通过。

### 7. 实现协议层的两种无损子编码

1. `GUARDED_INTENT` 是高概率默认编码。每周期 input 描述通道动作和新 payload 意图；front-end 根据实际 READY 锁存并保持已经发出的 payload，同时允许其他独立通道继续消费自己的逐周期意图。
2. 单个通道 stall 不得冻结整条 RawBits record。协议 waveform testcase 每个 DUT cycle 消费一条逐周期 record；各 AXI-Lite 通道使用独立 pending state。
3. `LITERAL_TRACE` 逐周期携带全部 master wire bits。front-end 不修复、不延迟、不改写这些 bits，只同步输出并由 monitor 判断它与实际 slave 响应是否仍合法。
4. monitor 覆盖 AW、W、B、AR、R 通道的稳定性、握手、response ordering 和 reset 行为，并输出首次违规 cycle、rule ID 和相关 wire snapshot。
5. literal trace 在运行中第一次违规后继续执行，但只把 `observed_classification` 改为 adversarial。配额永远按 testcase 开始前的 `declared_lane` 计算，不追溯改账、不补偿；报告同时给出 declared mix、observed valid/invalid mix 和每个 DUT 的 response-incompatible 比率。
6. 默认 protocol-only artifact 长度为 64 cycles，可配置到冻结 manifest 的 logical records/chunks/bytes 上限。完整性结论针对该 manifest 可表示的全部 response-compatible 轨迹，不把默认 64 写进协议定义，也不声称无界长度。

验收：手写 golden traces 覆盖 AW/W 不同顺序、长 stall、B/R backpressure、同时读写、全部 strobe、unmapped address、reset 中断和多 pending 合法组合；每个规则都有正反例。

### 8. 实现第三层受控扰动和确定性温度状态机

1. 第三层可从协议 corpus 取父输入；第二阶段再允许从 CPU semantic/program corpus 取父输入。每个子输入记录父 digest、mutation operator、位置、旧值、新值和代数深度。
2. 默认三个扰动等级：
   - `L0`：单点或单段轻度变异，优先合法操作重排、等待抖动和协议保持型变化。
   - `L1`：1 至 4 个 mutation site，允许一次局部顺序/稳定性/握手规则违规。
   - `L2`：1 至 16 个 mutation site，可跨字段和跨周期进行 raw bit、删除、重复、插入和通道乱序；仍受 testcase 长度和内存上限约束。
3. D 初始为 L0。连续 32 个完成 testcase 没有新增 primary branch 时升一级；出现至少一个新 branch 时降一级；L0/L2 为上下限。降级后有 8 个 testcase cooldown，期间不再次升级。阈值和上限可配置，但正式实验前冻结并写入 manifest。
4. C 使用相同 mutation operator 和初始 corpus，但固定在 L0，不读取 coverage feedback。D 与 C 的唯一机制差异是反馈状态机、探索池接受和由此产生的后续 corpus。
5. 主 corpus 永久保存产生新 branch 的 testcase。另设容量 128 的有界探索池，允许暂时保存无新 branch 的中间输入以跨越平台。
6. 探索池默认非新覆盖接受率由整数抽样决定：L0 为 1/32、L1 为 1/8、L2 为 1/2。候选还必须具有尚未存在的结构签名，签名只由 lane、父 digest、mutation operator/位置和 payload digest 构成，不引入新的覆盖指标。
7. 探索池满时按 `(temperature, last_selected_index, insertion_index, digest)` 的冻结确定性顺序淘汰；新 branch 输入及其必要祖先链转入主 corpus。内存中仅保留定长 metadata 和压缩/内容寻址 payload，禁止无界祖先复制。
8. 所有调度、抽样、接受、淘汰和降温决定使用 campaign seed 与明确的 counter-based integer RNG；replay 不依赖当前 coverage 或运行时随机状态。

验收：固定 seed 的逐 testcase lane、温度、父选择、mutation 和 corpus 状态完全一致；平台升级、覆盖降级、cooldown、池满淘汰和祖先保存有 golden log。

### 9. 使用 controller-owned v4 testcase producer

1. 明确选择 controller-owned producer：v4 B/C/D 不把 testcase 生成和 mutation 委托给 upstream kfuzz。controller 自己选择 lane、父 corpus、mutation 和 transport bytes，并调用 v4 target server；旧 kfuzz shared-memory 路径完全保留用于 A/v2、v3 和 conformance regression。
2. B/C/D 共用同一个 v4 controller/server implementation。B policy 生成均匀 raw payload；C policy 固定三层/温度；D policy读取 per-test primary branch delta。这样差异是版本化 policy，不是三个不同 transport 或 target。
3. 当前 server 的 per-test bitmap/new-point 逻辑迁移为可复用 coverage-union component，但 v4 controller 拥有 pre-test union、test dispatch 和 next-test decision，因此可以实现配额、温度和确定性 resume。
4. harness、SoC 和 DUT 不读取 coverage bitmap，也不能根据覆盖率改变输入。它们只执行 v4 testcase 并返回 coverage/diagnostic result。
5. replay 分为两个合同：
   - `wire replay bundle`：包含最终 v4 transport bytes、初始 DUT/SoC/profile/target digests、toolchain/runtime version、完整 invocation options、所有 simulator/randomization seeds、初始化寄存器/内存镜像、外部环境状态与逐周期非 DUT 响应输入，以及预期 wire/coverage snapshot。未列入 bundle 的状态必须由版本化 deterministic-initialization contract 固定；任何不可序列化或未声明随机源都 fail closed。该 bundle 可独立重放 wire/coverage，但不声称重算其 parent choice 或 coverage delta。
   - `campaign decision checkpoint`：包含 pre-test coverage union bitmap、完整 canonical controller state、quota counters、temperature/cooldown、RNG counter、主/探索 corpus 索引和所有内容寻址 payload digests；用于精确重算 coverage delta、接受/淘汰和下一 testcase。
6. campaign resume 只能从完整 decision checkpoint 开始；缺失 corpus object、bitmap或digest mismatch 必须 fail closed。持久化采用版本化 two-phase/WAL commit：先将所有新 payload、bitmap 和 controller objects 写入临时内容寻址对象，执行 flush/fsync、digest/size 验证并原子发布；确认所有引用对象 durable 后，才 fsync 并原子替换 checkpoint root。启动恢复忽略未被已提交 root 引用的孤立对象，并验证 root 的完整引用闭包；不得出现已提交 checkpoint 指向未持久化对象。
7. 预留独立 assertion-event result 字段，但本轮不以安全属性判断 bug，也不让 assertion 事件参与搜索或覆盖统计。

验收：停止/恢复 campaign 后与连续运行产生相同后续决策；单 testcase replay 的 wire trace、违规点和 coverage digest 一致；旧 RFUZZ conformance smoke 继续通过。

### 10. 第一阶段 protocol-only 调度和实验

1. 第一阶段只对第二、第三层作开发与实验验证，不声称完成三层系统。
2. protocol-only C/D 的目标配额为 80% `PROTOCOL_WAVEFORM`、20% `ADVERSARIAL_MUTATION`。调度器按已经 dispatch 的 declared lane 计数，并选择相对目标比例缺口最大的 lane；runtime-invalid literal 只改变 observed classification，不产生配额债务。
3. 第一阶段的 A/B/C/D 标记为 `protocol-only`：
   - A：历史 direct-bit baseline，完全不改。
   - B：生成 SoC/验证 front-end，由 controller-owned v4 policy 使用与 C/D 相同的 counter-based integer RNG 生成均匀 `RAW_ESCAPE`。对当前 target 的 RAW_ESCAPE used-mask 中每个 payload bit 独立均匀采样 0/1；record count/测试长度使用预注册的独立整数分布；header、lane tag、reserved 和 padding bits 不采样并按 transport 合同生成。campaign seed 到 RNG counter/domain 的映射写入 manifest。B 不调用 kfuzz producer。
   - C：固定 80/20 调度，协议采样权重固定，第三层固定 L0，无 coverage feedback。
   - D：与 C 使用相同生成 SoC、v4 schema、初始 corpus、campaign seed 和初始权重，加入 32-testcase 停滞反馈、温度升级和有界探索池。
4. A 与 B/C/D 使用共同的 ordered primary coverage catalog。B/C/D 使用同一编译 target；variant 仅由软件 campaign policy 和 testcase envelope 决定。
5. 不再声称 B/C/D 消费 byte-identical stream，因为三种方案的输入语言和 D 的反馈分叉本来不同。共同初始 mutation corpus 只要求 C/D byte-identical；B 不使用该 corpus。公平性由同一 v4 controller/transport/target、配对 campaign seed 到各 policy 独立 RNG domain 的冻结映射、同一 RAW_ESCAPE layout domain、同一 binary/catalog、相同资源和相同墙钟预算保证；报告必须公开各自实际 bytes、testcase 数和 DUT cycles。

验收：2 分钟 smoke 中四方案均完成、资源门有效、配额误差可解释、D 的反馈状态至少有可人工触发的测试；protocol-only 报告不能被最终三层报告读取为同一实验版本。

### 11. 第二阶段补齐 CPU 语义层

1. 保留高效率 `SEMANTIC_OPS`，但不把固定 16 类操作宣称为 CPU 完备。操作语言继续覆盖 MMIO/memory read-write、RMW、poll、wait、IRQ/ack、fence、external control、fault、reset 和 sequence。
2. 新增 `PROGRAM_FRAGMENT`：payload 包含可变程序片段、初始寄存器、数据内存、入口地址、异常向量和执行边界。固定 ROM 只负责校验、装载、跳转、结果/timeout 上报，不写死 IP 名称或交互流程。
3. PicoRV32 与 UltraRISC-V 都使用共同 ProgramFragmentIR。每个 `CpuExecutionProfile` 声明实际配置启用的 ISA、扩展、内存布局、装载方式、trap/IRQ ABI 和 reset 行为。
4. 合法 CPU 语义以 profile 声明的实际 ISA 为准。合法指令必须有无损编码；非法指令、未对齐、越权和故障行为仍可通过 adversarial/raw escape 表达并单独分类。
5. 两个 CPU 跑共同 RV32 可移植 fragment corpus；扩展指令和特殊异常使用 profile 专属 fixture。不得在通用 program IR 中写 CPU 名称分支。
6. CPU 语义层完成后，正式固定三层配额为 40% CPU semantic、40% protocol waveform、20% adversarial。配额算法和 runtime reclassification 规则与第一阶段一致。
7. 新增版本化 `CpuStateDomain`，逐 profile 冻结：通用 GPR 域及 `x0` 固定规则、可设置 CSR/privilege 列表与合法值 mask、PC/入口/异常向量约束、有限 memory regions 的 base/size/permissions/default-fill/显式 byte overlay、设备初始状态、loader 可实现性、未声明状态的确定性 reset 值和最大执行边界。encoder、ROM/loader、oracle、replay 和完整性测试必须消费同一 domain digest；无法由 loader 建立的状态不属于 declared valid set，不能被文档称为已覆盖。

验收：两个 CPU 的装载、启动、异常、timeout 和 replay；小型 ISA 子集穷举；`decode(encode(fragment))`；同一可移植 fragment 在两个 profile 上达到声明的一致可观察效果。

### 12. 完整性证明与验证证据

1. 构造性 round-trip：每个有效对象类型实现 canonical encoder，验证 `decode(encode(x)) == x`。解码器不是证明来源的唯一实现；测试向量包含独立手写 golden。
2. 小规模穷举：参数化缩小地址/数据宽度、轨迹长度、寄存器和指令集合，枚举全部合法对象，确认每个对象至少有一个编码且无字段丢失。
3. 有界形式属性：
   - `LITERAL_TRACE` 和 `RAW_ESCAPE` payload bits 原样传递；
   - lane 固定且互斥，无 CPU/injector 双驱动；
   - guarded pending payload 在 stall 中稳定，独立通道仍可前进；
   - mode switch 只发生在 reset 边界；
   - coverage epoch、snapshot 和 teardown 不泄漏到下一 testcase。
4. AXI-Lite monitor 使用独立 golden traces 和必要时的第三方/标准规则 fixture 交叉验证，避免 generator 与 monitor 共享同一错误。
5. 泛化验证：全部现有 AXI-Lite case加至少三个冻结 holdout；运行 holdout 前执行静态特判扫描。
6. 回归验证：v2/v3 contract、RFUZZ conformance、instrumentation ABI、existing generated SoC、旧 replay 和 current campaign tests 保持通过。

验收门：上述三类完整性证据任一失败，都不得发布“完整有效输入未被删除”的结论，也不得开始正式 30 分钟实验。

### 13. 资源公平和串行运行规则

1. 主预算是 fuzz-active 墙钟时间，从 server/corpus 就绪后的第一 testcase dispatch 到预注册 deadline。编译、一次性启动和最终报告生成不计入；每个 testcase 内的执行、timeout、reset、watchdog 和 teardown会消耗该墙钟预算，但对应 setup/teardown 周期不进入 coverage。
2. 截止规则固定为 completion-before-deadline：仅当 testcase 的完整结果在 monotonic deadline 前返回，coverage 才并入 endpoint；deadline 后不再 dispatch，新到或仍在运行的 testcase coverage 全部丢弃并标记 `censored_inflight`。in-flight 允许在固定 shutdown grace 内清理，超出则终止；报告 deadline、dispatch/completion 时间和 cleanup overshoot。所有 variant 使用同一规则。
3. 固定单进程、单 case、A -> B -> C -> D 串行执行。Verilator/controller job 数固定为 1，禁止方案间并行。
4. 每个配对 tuple 使用相同 CPU affinity、线程数、内存/cgroup 上限、编译优化、coverage 插桩、runner priority 和机器。编译产物可复用，但 B/C/D 必须使用同一 binary digest。
5. 运行前资源 preflight：记录 CPU 型号/核、负载、可用内存、swap、磁盘和 thermal/frequency 状态；可用内存必须高于冻结的 target peak-RSS 安全倍数。运行中采样 RSS、swap delta、CPU time、load 和 throttling。
6. 预注册 external infrastructure failure 与 variant-caused feasibility failure。整机掉线、无关进程抢占、外部磁盘错误等可证明外部失败允许每 tuple 最多重试一次；再次失败记为 infrastructure-invalid。controller corpus 超限、variant 自身 OOM、内部死循环或持续超时属于该 variant 的 feasibility failure，不重跑、不排除，也不能用其他 seed 替代来宣称成功。
7. 正式实验若出现 variant-caused feasibility failure，保留该 tuple 和失败时间/资源证据，停止该 variant 的覆盖优越性结论；实现验收要求正式配置下无此类失败。不得用 last-observation-carried-forward 构造成功 endpoint。
8. DUT/协议 timeout、CPU trap、非法指令、总线错误和设计死锁属于有效测试结果；在 snapshot coverage 后清理，不归类为基础设施失败。
9. smoke：每方案 2 分钟。正式实验：每方案 30 分钟，至少 10 个有效配对 seed。按用户锁定的 A -> B -> C -> D 顺序逐方案串行运行，不做方案间并行或按 seed 轮换；必须记录并检查系统负载、温度和频率漂移，并在预注册阈值超限时按 external infrastructure failure 规则处理。

验收：资源 manifest 相同；external infrastructure failure 按一次重试和 infrastructure-invalid 规则处理；variant-caused feasibility failure 必须保留并报告，且阻止该方案的覆盖优越性结论。报告同时给出墙钟、CPU time、RSS、DUT cycles、testcase、有效协议轨迹、操作/握手、timeout 和每千秒新增 branch。

### 14. 四方案正式实验和预注册统计

1. 完整 CPU 语义层通过验收后才运行正式三层 A/B/C/D；第一阶段 protocol-only 结果使用不同 schema/experiment ID，不能混入正式统计。
2. 正式方案：
   - A：历史 direct-bit baseline。
   - B：生成 SoC + uniform `RAW_ESCAPE`。
   - C：固定 40/40/20 三层调度，固定 protocol 权重和 L0 adversarial，无 coverage feedback。
   - D：同 C 的初始 corpus/权重/配额，启用 branch feedback、温度和探索池。
3. 唯一覆盖指标是 common primary branch coverage。握手、timeout、异常和吞吐仅为诊断，不构造复合覆盖分数。
4. 30 分钟 endpoint 的配对 `D - A` branch coverage fraction 是预注册主描述性比较，机制描述为 `C - B` 和 `D - C`。同时报告固定时间 checkpoints 的 curve、AUC、最终差值、中位数、逐 seed 胜负和预注册 paired bootstrap confidence interval。由于用户锁定固定 A -> B -> C -> D 串行顺序，方案与运行次序存在混杂：结果只能作为探索性、描述性证据，禁止表述为 D 相对 A/B/C 的无偏因果优越性；若未来要做因果比较，必须另开实验版本并预注册 Latin-square/counterbalanced 顺序。
5. 实现验收不要求 D 必然提高覆盖率。若 D 不提升，完整保存并报告，不能事后改主 endpoint、seed、预算、覆盖 catalog 或排除规则。
6. assertion event ABI 仅预留；安全属性是否判定 bug 属于后续阶段，不参与本轮实验成功标准。

验收：实验 manifest 在运行前冻结比较、seed pool、时间、资源、coverage catalog、统计方法和失败处理；至少十个有效配对 tuple；完整 replay/inventory 可审计。

### 15. 报告、迁移和交付顺序

1. 每个 slice 输出结构化 JSON 和人类可读摘要，至少包含 discovery、profile matching、SoCIR、port binding、unknown-port、address map、v4 layout、lane/constraint、mutation/corpus、coverage、resource 和 replay digests。
2. 交付按顺序执行，任一门失败不得跳到后续正式实验：
   1. 历史冻结与 v4 contracts。
   2. AXI-Lite profile/monitor 和验证 master front-end。
   3. protocol guarded/literal 与完整性证据。
   4. adversarial mutation、探索池和 RFUZZ controller。
   5. protocol-only smoke/正式开发实验。
   6. CPU ProgramFragmentIR 与两个 CPU profile。
   7. 完整三层验证与最终 A/B/C/D。
3. 每个 build slice先跑最窄单元测试，再跑相关 builder/RFUZZ/instrumentation 回归，最后单 case 串行 smoke。禁止一次性并行构建全部 target。
4. 实现完成前不删除 v3 代码。只有显式 cleanup 阶段、全部兼容测试通过且用户再次批准后，才可将旧活动入口降级为 archival；A/v2 永久保留。

验收：所有报告路径存在、digest 一致、命令可运行；drift check、文档命令检查和完整测试清单写入最终交付报告。

## Key decisions & tradeoffs

1. 完整性采用两类有效集合加一类探索集合，而不是声称所有 raw bit 都有效。CPU 和协议有效输入必须有无损编码；adversarial 可以非法但必须可追踪。
2. 约束只改变采样概率，不在 harness 中钳位字段。这会保留较大的理论空间，但通过权重、guarded intent 和 coverage-guided corpus 提高短时间有效探索率。
3. 协议层同时保留 `GUARDED_INTENT` 和 `LITERAL_TRACE`。前者高效适应未知 READY，后者承担逐周期完整性；不能用一个隐式修复器同时满足两种目标。
4. 正常 SoC 仍只有 CPU 一个功能 master；验证 front-end 在 testcase 级互斥接管同一端口。这牺牲了“所有模式都必须由 CPU 发起”的形式纯粹性，换取冻结 manifest 范围内全部协议合法、response-compatible 轨迹可表达。
5. 自适应逻辑放在软件 runner/server，而不是 SoC/harness。这样避免 coverage 反馈污染 DUT、减少硬件面积并保持 replay，但要求 campaign bundle 完整保存控制器状态。
6. 第三层采用有界探索池并允许保留少量无新 branch 输入，以跨越覆盖平台；容量、接受率和变异规模全部有界以控制内存。
7. 第一阶段优先协议与扰动，使用 80/20 protocol-only 配额。CPU 语义延后，因此第一阶段不得发布完整三层结论。
8. 新行为使用 RawBits v4，旧 v2/v3 只读保留。版本数量增加，但避免旧 testcase 被新解释器静默改变。
9. 实验以相同 fuzz-active 墙钟和相同资源为主，而非相同 input 数或 DUT cycle；吞吐差异作为结果的一部分公开。
10. 覆盖率提升是研究假设，不是实现正确性的验收门。主覆盖指标当前只使用 common branch coverage，安全属性断言留待后续。

## Risks / open questions

1. `LITERAL_TRACE` 合法性依赖实际 slave 响应，同一输入在不同 DUT 状态可能被分类不同。缓解：保存初始状态、完整反馈摘要、首次违规点和 replay artifact；完整性结论只针对 response-compatible 轨迹。
2. AXI-Lite 的多 pending 和通道独立性容易被简化成单 outstanding。缓解：profile 与 monitor 不写死 CPU 的单 outstanding 限制，golden/formal 测试覆盖多次 handshake 和独立 channel pending。
3. controller-owned v4 producer不再继承 upstream kfuzz 的成熟 mutation/corpus 行为，可能降低 B 的代表性。缓解：A/v2 和 v3 继续保留真实 kfuzz 路径；B/C/D 共用同一 controller；对 uniform raw 生成、mutation 和 corpus policy 建立独立 conformance/golden 测试，并在报告中明确两条路径。
4. 墙钟实验容易受机器热状态和后台负载影响。缓解：资源 preflight、固定 affinity、串行执行、持续资源采样和 external-failure tuple invalidation；由于固定 A -> B -> C -> D 顺序不做轮换，本实验只发布探索性描述结论。
5. Program fragment 的“全部合法 CPU 行为”只可能相对于冻结的 CPU 配置、`CpuStateDomain` 和 manifest 有界 testcase 表达。缓解：profile 明确 ISA/状态/长度边界，只对该声明集合证明无损编码，不声称覆盖无限程序执行。
6. 探索池即使有界，payload/祖先链仍可能放大磁盘使用。缓解：内容寻址、去重、祖先引用、campaign 磁盘上限和可重复的淘汰策略。
7. 自动接口识别无法可靠解决所有非标准 RTL。缓解：唯一匹配才自动生成，歧义 fail closed，并要求最小用户 manifest；“需要声明”是正确结果，不是泛化失败。
8. 目前没有安全属性来区分新覆盖是否对应 bug。该问题已明确留给后续 assertion 阶段，本轮不作 bug 数量结论。

## Out of scope

1. 本轮不同时实现 AXI4、AHB、Wishbone、多 master、DMA 发起、异步多时钟/CDC 或任意旧集成顶层逆向恢复。
2. 第一阶段不实现完整 CPU `PROGRAM_FRAGMENT`，只保留兼容路径；CPU 语义完整性属于第二阶段。
3. 不使用状态覆盖、toggle coverage、FSM coverage 或安全属性作为本轮反馈/主指标。
4. 不让 fuzz 控制基础时钟频率、占空比或任意模拟时序。
5. 不自动猜测未知协议、未知 inout、含糊时钟/复位或不唯一接口绑定。
6. 不删除或重解释 A/v2、当前 v3、历史结果和材料。
7. 不保证 D 必然优于 A/B/C；只保证实验公平、可复现并如实报告。
