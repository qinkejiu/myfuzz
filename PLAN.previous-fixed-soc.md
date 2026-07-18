# 计划：CPU + 多 AXI-Lite IP 的 RFUZZ 系统生成与三方案对比
_Act 1 已与用户锁定；Act 2 经同一只读 Codex 线程 6 轮评审后 APPROVED_

## 目标

在现有 protocol-driven builder、Verilator RTL 分析、源码插装和 RFUZZ 流程上，生成包含真实 CPU、Level 1 ROM、邮箱、AXI-Lite fabric 和多个 IP 的可执行 SoC，并证明系统拓扑及外部 0/1 bit 约束是否比“模块互不连接、全部端口直接暴露”的基线更有利于 RFUZZ 获得 CPU/IP 公共覆盖率。

对每个 CPU 使用同一组 IP，独立比较三个方案：

| 方案 | 结构 | RFUZZ 输入处理 |
| --- | --- | --- |
| A `Flat Random` | 仅实例化 CPU 和全部 IP，子模块之间不连接，所有非时钟/复位输入直接暴露 | 直接驱动各子模块输入 |
| B `Generated Raw` | CPU + Level 1 ROM + 邮箱 + watchdog + 地址图 + AXI-Lite fabric + IP | 访问记录和外部输入均不加关系约束 |
| C `Generated Constrained` | 与 B 完全相同的生成 SoC | 仅对 SoC 外部输入应用有证据的 0/1 bit 关系约束 |

主结论是同一 CPU SoC 内的 C 对 A；B 是必要消融，用于区分“系统连接/ROM”的收益和“外部 bit 约束”的额外收益。NanoRV32/PicoRV32 系列和 UltraEmbedded RISC-V 是两个独立验证后端，不把两个 CPU 之间的绝对覆盖率作为主比较。

## 已锁定的设计

### 1. 公平的三个实验目标

- A/B/C 使用相同 CPU/IP RTL、参数和预包装插装结果。
- 公共时钟与启动复位由实验驱动器确定地产生，三个方案使用完全相同的波形；A 顶层仍可列出这些端口，但 RFUZZ 不随机控制它们。
- `coverage_epoch_i` 同样由实验驱动器控制并在每个 testcase 开始对 A/B/C 一致推进，不属于 RFUZZ 可变输入。
- A 的空壳顶层只做实例化和端口一一展开，端口名必须包含实例限定，禁止子模块互连、ROM、地址图或协议适配。CPU 的 AXI 响应输入在 A 中也是普通直接 fuzz 输入。
- B/C 共用同一份生成 SoC RTL和执行基础设施，优先做成同一编译目标的运行模式选择；C 不得改变 CPU 内部 AXI-Lite 请求，也不得改变访问记录。
- 不恢复或复用已删除的 AutoTop 路线；继续沿用现有 protocol-driven builder 分层。

### 2. Level 1 ROM 与访问记录

Level 1 ROM 只依赖 CPU execution profile 和生成系统的结构信息：reset vector、ROM/mailbox/watchdog 地址、IP 地址窗口、数据宽度及对齐。它不能包含 GPIO、timer 等 IP 寄存器语义、初始化序列或命令知识。

RFUZZ 访问记录固定为：

```text
ip_select   选择目标 IP；无效编码访问默认错误从设备
read_write  选择 32-bit 读或 32-bit 写
offset      目标窗口内的 word offset
data        32-bit 写数据
```

- 不让 RFUZZ 控制 `WSTRB` 或访问大小。所有写都是 CPU 自然执行的 32-bit word store，合法写掩码由 CPU 产生；所有读都是 32-bit word load。
- `offset` 按目标窗口的 word 数取模并保持 4-byte 对齐，不引入 IP 寄存器语义。
- `ip_select` 不做 modulo；当实例数不是二次幂时，多余编码进入 unmapped/default error 路径。
- 一条记录在 CPU 完成目标访问前保持稳定；完成或 watchdog 超时后才接受下一条记录。
- ROM 通过邮箱取记录、计算地址并执行访问。事务监视器先匹配活动 sequence 预期的目标 route、规范化地址和方向：读必须观察完整 AR handshake，写必须观察同一事务的 AW/W 都完成；只有此后才 arm，并只接受该 route 对应的一个 R/B response。取指、ROM、mailbox、watchdog 或其他地址的响应不能终止记录。不能假设 CPU 软件可见 response code；这兼容当前会丢弃 `RRESP/BRESP` 的 PicoRV32 wrapper。
- CPU profile 可提供最小启动、trap、返回片段和 ROM 安装后端，但公共访问循环的语义一致。PicoRV32 从 fabric 上 reset-vector ROM 取指；UltraEmbedded 在 CPU reset 保持期间通过现有 AXI target loader 将同一生成映像写入内部 TCM，校验后才释放 CPU reset。B/C 使用相同映像、loader trace 和安装摘要；A 不安装生成 ROM，loader 相关子模块输入按 Flat Random 规则直接暴露。
- ROM 生成器输出 RV32I assembly、linker script、ELF、BIN/HEX、反汇编、工具版本和内容哈希；使用已安装的 `riscv64-unknown-elf-gcc -march=rv32i -mabi=ilp32 -nostdlib`，不维护自制机器码编码器。

### 3. 地址图与故障恢复

- CPU profile 保留 reset/ROM 窗口；生成器保留 mailbox 和 watchdog/status 窗口，再确定性放置未指定地址的 IP。
- 用户或 profile 给出的固定地址发生冲突时立即失败，不能静默搬移。
- 一个实验的地址图、timeout 和预算在正式运行前写入冻结 manifest。
- 资格运行先测量 ROM 启动和各 IP 的基本读写延迟，然后冻结：

```text
MAX_TRANSACTION_CYCLES = max(预设下限, 最慢基本事务延迟 * 4)
CYCLE_BUDGET = ROM 启动预算 + 1024 * MAX_TRANSACTION_CYCLES
```

- sequence-numbered 输入槽及其所有权由 harness-owned、reset-exempt controller 保存。每个 sequence 只能收到一个终止确认：`completed` 或 `timed_out`；终止确认锁存后才精确推进一次，断言禁止丢失、重复和永久重放。
- 目标访问超时后记录 sequence、目标 IP、方向和周期数，再复位 CPU/SoC 执行域；reset-exempt controller、当前 testcase 的公共 coverage OR 累加器和结果计数器不随 watchdog reset 清零。ROM 重新安装/启动并通过 quarantine 后才提交下一条记录。
- 禁止 watchdog 伪造 AXI 响应；否则迟到的真实响应可能污染后续事务。
- reset-domain contract 覆盖 CPU、ROM/TCM 执行侧、fabric、mailbox 执行侧、watchdog 和全部 IP。CPU profile 规定极性适配、同步/异步语义和资格化脉冲长度。CPU reset 保持有效时，先释放/检查其余执行组件并进行 stale-response quarantine；只有 fabric/slave 的 outstanding state 为空且 response channels 连续静止规定周期后才释放 CPU。CPU 释放后的正常取指不属于 quarantine；清空超限则目标失败。

### 4. IP 规模与资格门

- 两个 CPU 使用完全相同的 IP 集合和地址窗口。
- 正式 SoC 至少包含 6 种不同 AXI-Lite IP、8 个总实例，优先增加类型多样性而非重复实例。
- 每个计入正式比较的 IP 必须具有非零内部 branch/control-flow 插装点；零点模块只能作为辅助模块，不能计入 6 种或公共覆盖率分母。
- 最终 IP 清单由资格门选择并在实验前冻结。候选可来自当前 materials、verilog-axi、PULP 和 ZipCPU 生态，但不得因知名度绕过资格检查。
- 每个正式 IP 必须通过：许可与来源冻结、编译/elaboration、AXI-Lite profile 完整识别、复位退出、对齐 word read/write 有界响应、插装后 RTL 再编译、非零内部插装点和最小行为一致性检查。
- 小型生成器矩阵覆盖 1/2/4/8 个 IP、实例重排、混合固定/自动地址、非二次幂实例数；不运行全部 IP 子集的笛卡尔积。

### 5. 约束来源和边界

C 只约束生成 SoC 的外部/未知输入，不约束访问记录，也不修改 CPU 产生的 AXI-Lite 信号。约束必须是信号级 0/1 bit 关系，而不是指令或 IP 命令级语义。

证据优先级固定为：

1. 用户端口标注：最高优先级，可自动应用。
2. 已资格化的协议/CPU/外设 profile：只应用已证明的协议事实。
3. Verilator AST 静态分析证明的结构事实：可自动应用。
4. 行为模式启发式推断：仅生成候选，未经用户确认不得应用。

第一版静态证明范围包括方向/位宽、时钟边沿、复位极性与同步性、完整协议 bundle、层次绑定、常量及显式 mask。由行为模式推测的 `ONEHOT`、`PULSE`、`HOLD`、`DEPENDENCY` 默认都是候选。

- 复用现有 Verilator frontend，不增加 regex 语义解析器。
- 未知普通 input 使用显式 `DIRECT` policy 并报告；output 只观察；未知物理 `inout` 拒绝，除非 profile、用户标注或已验证 wrapper 将其安全拆为 input/output/output-enable。
- 正式 SoC 至少包含三类真实外部关系，例如 CPU interrupt、GPIO 输入与更新/使能、valid/data 或 request/ack；每类必须有 profile、用户标注或静态证明证据。
- 每条约束报告 primitive、source、confidence、evidence、applied 状态、影响的 raw bit 数，以及 B/C 实际输出差异。

### 6. 输入 ABI 与消费语义

- A/B/C 每个 CPU SoC 使用同一份 superset RawBits testcase：相同 seed、字节数、输入槽数和 SHA。SHA 只证明原始输入配对，不代表三个方案执行了相同数量的仿真周期或协议事务。
- superset layout 包含访问记录字段、所有 CPU/IP flat input bank、公共外部输入和保留位。
- A 使用 flat input bank；B/C 使用访问记录与公共外部输入，明确忽略 flat-only bit。
- 每个方案报告总 bit、已使用 bit、忽略 bit和利用率。A 直接使用更多熵，视为对基线的保守优势。
- 保持 `RFUZZ RawBits v2` 的 byte/bit 编码不被静默重定义；新增有版本的 `AccessRecord v1` 布局及 ready/consume 元数据，loader、harness 和报告都校验 digest。
- 每个 superset slot 在 A 映射成一个 flat-input cycle，在 B/C 映射成一个 sequence-numbered AccessRecord 加同槽外部输入；manifest 给出逐槽、逐字段映射和 ignored mask。
- B/C 的记录消费由 reset-exempt owner 与 mailbox terminal acknowledgement 控制；一条记录可以跨多个仿真周期保持。A 可逐周期消费输入。因此主实验明确是“相同接受输入槽数”，补充实验才是“相同仿真周期数”。

### 7. 覆盖率 ABI

- 对 CPU 和正式 IP 的共同 RTL 先插装一次，再包装进 A/B/C，保证 point ID、宽度、catalog 和 digest 相同。
- 主指标只统计 CPU/IP 内部公共 branch/control-flow 点。生成 ROM、mailbox、watchdog、fabric、flat shell 和 harness 不进入主分母。
- 生成基础设施可以使用独立 auxiliary coverage ABI，必须与主结果分开展示。
- 每个实验组件在 variant-independent component manifest 中具有固定 `component_instance_id`；A/B/C 的不同实际层次只能作为辅助字段，不能进入公共身份。
- point ID 基于 `component_instance_id`、插装前 source identity、逻辑 AST node identity 和 coverage type；公共 catalog/offset/digest 按这些字段确定排序，不依赖临时路径、改写后行号或方案顶层名称。
- 每次运行必须验证 `common_coverage_abi_digest` 相同；不相同则实验无效而不是尝试换算。
- 公共插装使用 `CoverageABI v2` epoch semantics，不给已有点增加第二个 procedural writer。主 ABI 只包含 Verilator AST 可证明属于 `always_ff` 或 edge-triggered `always` 的 branch/control-flow 点；每点使用 epoch tag，只在原过程命中位置以过程兼容的赋值形式写当前 `coverage_epoch_i`，输出命中条件是 tag 等于当前 epoch。
- `always_comb`、combinational `always`、`always_latch`、expression、`initial` 和 `final` 点不进入主 ABI，避免 delta-cycle 采样和不可重入语义影响实验；它们保留稳定 point catalog、原因和数量，可在 fresh-process 辅助报告中单独展示，不能混入成功门槛。无法可靠分类过程种类的点也排除。每个正式 CPU/IP 必须在这个更严格的主 ABI 中仍有非零点。
- epoch 固定 64 bit，point tag 声明初始化为保留值 0，第一个 testcase 使用 epoch 1；每个 testcase 开始在设计 reset 期间单调递增，watchdog reset 不改变 epoch，正式运行前证明 testcase 总数不会 wrap。testcase N 不得继承 N-1 的覆盖。
- toggle coverage 不在本阶段范围；辅助指标包含事务完成、目标选择、读写、默认错误、timeout、restart 和吞吐率。

## 实现步骤

### Slice 0：冻结 RFUZZ 依赖与服务器合同

- 当前 checkout 缺少 `third_party/rfuzz`，因此在任何“真实 campaign”声明前，固定 RFUZZ/kfuzz 上游 revision、获取方式、文件哈希、license、patch、构建工具版本和可离线复现步骤；依赖缺失时明确失败。
- 定义 transaction-paced `ready/valid/consume` server contract，覆盖 fixed replay、coverage-guided mutation、corpus replay、minimization、可变运行长度、end-of-input、目标 timeout、进程 crash 和重新连接。
- 验收：固定小目标通过 server conformance suite；同 testcase replay 的消费 sequence 和结果可复现；连续运行两个互斥覆盖 testcase 时各自只报告自身点，minimization 重放不继承前一个 testcase；epoch wrap 预算在运行前校验；缺失/错误 revision、ABI 或 layout digest 均在 campaign 前拒绝。

### Slice 1：冻结合同和现状基线

- 盘点现有 builder、RawBits、ConstraintIR、CoverageABI、instrumentation、qualification 和 kfuzz/RFUZZ 入口；记录可复用 API，禁止建立第二套平行 flow。
- 定义并 schema-test：`CpuExecutionProfile v1`、`RomInstallBackend v1`、`AccessRecord v1`、`RecordTerminalAck v1`、`ExperimentVariant v1`、`ExperimentManifest v1`、带 epoch-tag single-writer 语义的 `CoverageABI v2` 和结果 schema。
- 明确 A/B/C 的端口、bit layout、消费握手、复位、结束和排空时序。
- 验收：schema round-trip、未知字段/version 拒绝、稳定排序与逐字节复现、现有 builder 与 instrumentation 回归通过。

### Slice 2：Flat Random 空壳和公共插装 ABI

- 新增只负责实例展开的 flat-shell emitter；生成限定名端口和直接 fuzz 映射，不复用 SoC connection planner。
- 从共同 CPU/IP 输入生成一次插装产物和 point catalog，A/B/C 只消费该产物。
- 验收：A netlist 中不存在子模块间边；所有普通 input 恰有一个顶层来源、所有 output 可观察；variant-independent component ID 和公共 ABI 在 A/B/C 三个最小 fixture 中 digest 一致，实际 hierarchy 不同不改变 point ID/offset；sequential epoch-tag fixture 插装后 lint/compile 无多驱动并通过两 epoch 隔离测试，`combinational/latch/expression/initial/final/unknown-process` exclusion 稳定且不进入主 digest。

### Slice 3：执行基础设施和地址图

- 在现有 SystemIR/AXI-Lite backend 上加入 ROM、mailbox、watchdog/status 的保留窗口和确定性 IP placement。
- 实现 reset-exempt record owner、sequence/terminal-ack 状态机、AXI response monitor、超时统计、host-side epoch coverage OR/snapshot 控制和执行域 reset recovery。
- B/C 使用同一 RTL；约束模式只位于外部输入映射层。
- 每个 A/B/C DUT rising edge 都采用相同采样顺序：驱动时钟边沿、运行 Verilator `eval()` 直到 NBA/settle 完成、由 host 将公共 coverage vector OR 入当前 testcase bitmap。terminal ack 所在边沿完成同一次 settle 后做最后采样，不再增加 DUT clock；host 返回 `coverage_capture_ack` 后才允许提交 checkpoint、复位或取下一条记录。
- 验收：定向测试覆盖成功读写、无效 `ip_select`、地址冲突、offset 归一化、慢响应、永久不响应、迟到响应、取指/邮箱响应不得误完成记录、response code 捕获、复位重启和 CPU-held-reset quarantine；exactly-once、无跨 sequence 响应、同 epoch coverage 不因执行域 reset 丢失、跨 epoch 隔离、terminal edge 上唯一命中的点不丢失，以及 AXI assertions 均通过。

### Slice 4：通用 Level 1 ROM 生成器

- 由 CPU profile 提供 ABI、reset vector、最小 startup/trap 模板、总线访问适配和 `external_rom`/`pre_reset_tcm_loader` 安装后端；公共生成器发出访问循环与 linker script。
- 每个 ROM 产物包含源码、二进制、反汇编、工具链指纹和输入/输出 digest。
- 验收：同 manifest 字节级复现；Pico 的外部 ROM 和 Ultra 的 pre-reset TCM loader 均能安装同一语义的映像并校验 digest；两者可启动、取记录、完成 word read/write，由外部 monitor 上报 response/timeout，并在 watchdog reset、重新安装和 quarantine 后重入循环。

### Slice 5：外部约束与静态证据

- 扩展现有 Verilator AST 分析结果和 ConstraintIR provenance，不复制解析逻辑。
- 自动应用范围仅限锁定的可证明事实；启发式关系进入 candidate report。
- 实现 B `RAW` 与 C `CONSTRAINED` 的同输入差分 trace。
- 验收：每个 applied constraint 能追溯证据；unknown input/inout policy 完整；至少三类外部关系 fixture 有参考解释器和周期级 golden trace；访问记录在 B/C 完全一致。

### Slice 6：双 CPU 与大规模 IP 资格矩阵

- 为 NanoRV32/PicoRV32 和 UltraEmbedded 建立薄 CPU execution profile/adapter，通用策略不得硬编码模块名或单一 CPU 端口。
- 运行候选 IP 资格门，冻结至少 6 种、8 实例的共同清单、来源、license、参数、地址、插装点数和失败清单。
- 验收：两个大 SoC 均能生成 A/B/C，未插装和插装后全部 compile/elaborate；B/C ROM 完成每个 IP 的最小读写；公共 coverage ABI 在每个 CPU 的 A/B/C 内一致。

### Slice 7：确定性 replay 对比

- 先做独立 calibration，冻结 timeout、cycle budget、工具版本、IP 清单、地址图和全部实验参数；正式结果后不得调参。
- 每个 CPU、每个方案使用预先冻结的同一组 20 个独立 seed，每个 seed 1024 条记录；额外探索 seed 不进入正式统计。
- 主实验固定接受 1024 个 superset input slot；补充实验固定冻结的 simulation-cycle budget。二者分别解释，不把同 SHA 当作相同执行工作量。
- 记录 powers-of-two 的 record checkpoint `1..1024` 与 powers-of-two cycle checkpoint，输出 JSON、CSV、Markdown。
- 每个 checkpoint 包含 CPU/各 IP 点数、公共覆盖、事务、每 IP 选择、读写、timeout/restart、输入字节和运行时间。
- replay 主终点固定为第 1024 个已终止 input slot 的公共覆盖率；seed 在 A/B/C 间配对。统计检验和区间使用两套明确算法，共用固定统计 PRNG seed 和 10,000 次 resample。
- 单侧 p-value：从 paired differences 减去观测均值得到 null-centered sample，bootstrap 后计算 studentized mean；每个 bootstrap replicate 若标准误为零，一律作为上尾极端值计入 `p` 的分子，这是保守处理。观测标准误为零时直接固定 `p=1`。
- 95% effect CI：直接对未中心化 paired differences 做独立的 percentile bootstrap，取 2.5%/97.5% quantile，不复用 null-centered test resample。观测标准误为零时 inferential CI 改用完整参数范围 `[-100 pp,+100 pp]`，不得宣称显著。算法版本、quantile 规则和统计 seed 写入 manifest。
- transaction timeout 是正常观测结果，不算 run failure。可在干净进程中用同 testcase 连续 3 次复现的 assertion/非法状态/目标崩溃分类为 DUT failure，该 scheme/seed 的主终点按 `0%` 公共覆盖计并保留 crash artifact；每个 scheme 最多允许 `1/20` 个 DUT failure，超过即整体失败。
- 编译、loader、server、OS/resource、ABI/layout 不匹配或不能稳定复现为 DUT 的错误分类为 infrastructure failure；该 seed 的 A/B/C 整个 paired triplet 作废并在相同冻结 manifest 下全部重跑。若同一 triplet 再次 infrastructure failure，则正式实验无效并停止成功声明，不能继续补跑或保留部分结果。
- 验收：同 seed 输入 SHA 一致；无 seed 删除；统计 mean/median/min/max/stddev、paired 95% CI、逐 seed 结果及 coverage-per-byte/cycle/second。

### Slice 8：真实 RFUZZ campaign 与最终报告

- 复用实际 kfuzz/RFUZZ coverage-guided 路径，不用 replay 模拟 coverage guidance。
- 每 CPU × 每方案运行 5 次独立 campaign；smoke 每次 60 秒，full 每次 10 分钟。相同初始 corpus、superset layout、core 数、wall time 和 fuzzer 参数。
- 在 `1,2,5,10,30,60,120,300,600` 秒采样公共覆盖、time-to-threshold、exec/s、事务、corpus size、crash/timeout；campaign 主终点固定为第 600 秒公共覆盖率，5 次 repeat 仅作独立 campaign 统计，不与 20-seed replay 混合。
- 每个 campaign repeat 使用同一 campaign seed 配对 A/B/C。普通 crash-producing testcase 是 RFUZZ 结果：server 重启目标但 600 秒 wall-clock 不暂停，只有 crash 前已收到有效 coverage snapshot 的点进入 union，重连/最小化时间计入预算。
- unrecoverable 且可 3 次复现的 DUT failure 不重跑：该 scheme/repeat 的 600 秒 endpoint 记为 `0%`，保留 artifact，并使该 CPU 的 campaign success gate 失败。编译、server、loader、OS/resource 或不能复现为 DUT 的错误属于 infrastructure failure：整组 A/B/C campaign triplet 作废并从零完整重跑一次，原失败尝试仍报告；同一 triplet 再次 infrastructure failure 则整个 CPU campaign 无效，不能宣称成功。
- 有效 campaign 不因 downtime 延长，600 秒按单调 wall clock 截止；没有合法 600 秒 endpoint 的运行不得用最后观测值补齐。
- 输出同一 SoC 三方案的曲线、表格、manifest 和原始结果索引；CPU 和每个 IP 分开展示，并给出总公共覆盖。
- 验收：30 次 full campaign 均有合法 600 秒 endpoint，或按上述规则使对应 CPU campaign 明确失败/无效；每个 paired rerun 和失败 attempt 均可追溯，报告可从原始 JSON/CSV 确定性重建。

## 预注册成功标准

对两个 CPU SoC 分别判断，不选择性展示：

- 所有 replay 判定使用第 1024 个已终止 input slot；campaign 判定使用第 600 秒。A/B/C 使用相同 seed 配对。
- C 对 A：平均公共覆盖率至少提高 10 个百分点，至少 `16/20` 个 paired seed 满足严格 `C-A > 0 pp`，paired difference 95% CI 下界大于 0；tie 不算获胜，DUT failure 使用其保守 0% endpoint。
- B 对 A：平均公共覆盖差值大于 0，用来证明系统拓扑与 ROM 的结构收益。
- C 对 B：平均公共覆盖至少提高 1 个百分点，并且至少 `14/20` 个 paired seed 满足 `C-B >= 0 pp`；tie 计作 non-inferior，DUT failure 使用其保守 0% endpoint。事务完成率和 timeout 只作为预注册 secondary outcomes，不再替代覆盖主终点。
- 每个 CPU 的 C-A、B-A、C-B 构成 6 个预注册 replay hypotheses。每项统计 null 都是 paired mean difference `<= 0 pp`，使用同一个 null-centered studentized paired bootstrap 产生一侧 p-value，再以 Holm-Bonferroni 控制 family-wise `alpha=0.05`；原始和校正 p-value 同时报告。
- 显著性门与实际收益门分开：C-A 的 `+10 pp`、80% seed 获胜和 CI 下界大于 0，B-A 的正均值，C-B 的 `+1 pp` 与 70% seed 非劣都是 practical gates；Holm-adjusted `p<0.05` 是额外 statistical gate，不能用一个替代另一个。campaign 的 5 次 repeat 只报告效应量和不确定性，不用低样本显著性替代 replay 结论。
- 正式 RFUZZ campaign 同时报告最终覆盖、覆盖随时间变化、time-to-threshold 和吞吐，不能只挑一个有利指标。
- 若门槛未达到，结果必须按失败保留并解释。更换 IP、约束、timeout、预算或参数都产生新 experiment ID，并重新运行全部 A/B/C 组。

## 风险与待资格化事项

- 最终 6 种/8 实例 IP 清单尚未由资格门冻结；部分 ZipCPU 传统 Verilog 模块此前可能没有内部 branch 点，不能预先计入正式集合。
- UltraEmbedded 与 Nano 的原生总线/启动差异可能需要 CPU-specific adapter 和 startup fragment；这些差异必须局限在 profile/adapter，不能污染公共 ROM 策略。
- transaction-paced AccessRecord 与现有逐周期 RawBits/RFUZZ server 的接口兼容性必须在 Slice 0 用现有代码和端到端 smoke 证明；必要时增加版本化 ready/consume adapter，不能静默改变 RawBits v2。
- A 使用更多直接随机输入而 B/C 忽略 flat-only bit，会降低 B/C 的 entropy utilization；报告必须显式显示，不能隐藏这一保守偏差。
- whole-SoC reset 会影响覆盖与吞吐；所有方案必须使用同一覆盖累计规则，并分别报告 reset/restart 次数。

## 明确不做

- 不让 RFUZZ 搜索或生成任意 RISC-V 程序。
- 不实现 Level 2/3 ROM，不编码 IP 寄存器语义、驱动程序或命令序列。
- 不让 RFUZZ 任意控制 `WSTRB`，不在 CPU 后方篡改 AXI 请求。
- 不约束访问记录字段，不把 CPU 指令语义称为 harness 约束。
- 不比较不同 CPU 的绝对覆盖率高低作为系统有效性结论。
- 不把 generated fabric/harness 的覆盖混入 CPU/IP 主覆盖率。
- 不恢复旧 AutoTop，不新建平行 RTL parser、instrumenter 或 fuzzer engine。
- 不做 toggle coverage、多个 CPU master、完整 IP 子集笛卡尔实验或未经证据的端口名猜测。
