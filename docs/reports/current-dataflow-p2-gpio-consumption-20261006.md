# P2 GPIO 寄存器、同步器与原生 IRQ 消费证据（2026-10-06）

当前已完成的 **来源别名修正＋8192 项有界追踪版本**下，真实被动探针与双 GPIO 定向消费链共 **5 项通过，22.33s**；完整软件回归 **637 passed、11 skipped、691 subtests passed，134.16s**。CPU＋GPIO 在线 **16 例 complete**，run 与整个前缀 fresh replay 均 exit 0、matches=true，有效搜索时间 **23.370535706999362s**。独立 raw audit 已确认当前 341 个源码文件 hash 匹配：1 条已登记 fuzz 指令退休→实际 GPIO 提交证明、1617 个已知 pin8 同步/锁存版本，以及 8 个已知 pin8 原生触发和 1 个已知 Binding pin0 触发。CPU 操作数来源仍未知。

原 256 项容量阶段的证据单独保留：其在线 replay 同样匹配，但 bootstrap 已耗尽缓存，accepted GPIO consumption match 为 0。新源码重录结果不修改这份历史负结果。

这次定向门禁覆盖 `GPIO A PADOUT 提交 → 低字节 Binding 的实际输入凭据 → GPIO B 同步器 → 原生 IRQ → PADIN/INTSTATUS 的实际 APB 读取`。它没有 CPU RTL，事务发起者是 host，指令与操作数来源均为 `unknown`。P2 仍部分完成，完整 CPU 控制/操作数返回链与 UART FIFO 消费验收继续待办。

## 证据与源码边界

| 内容 | 固定身份或材料 |
|---|---|
| 原始 RTL | `third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv`，官方 top `apb_gpio` |
| Git pin | `f82caeb7f7d89427f05e9af5ed31e0675efe0d83` |
| RTL SHA-256 | `1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef` |
| 参数 | APB_ADDR_WIDTH=12、PAD_NUM=32、NBIT_PADCFG=4 |
| 显式新配置 | [pulp_gpio_causal_local](../../configs/peripherals/pulp_gpio_causal_local/component_profile.json) |
| 观测身份 | `pulp.gpio.causal` / 字符串版本 `1` / `pulp_gpio_causal_v1` |
| 采样与 IRQ | `pre_post_rising`；`native_transition_pulse` |
| 寄存器语义摘要 SHA-256 | `45967a98f4999682786fbb1a9e2fc3f67e8a33b725c0a70073b034e64d6efd0d` |
| 探针契约 SHA-256 | `27638467f0680d37899f64a866dfdb823b680581d6dd9239ba5b68c2c4718800` |
| 当前定向材料 | [directed-source-alias](../../runs/current-dataflow-p2-gpio-consumption-20261006-directed-source-alias/) |
| 完整双次消费证据 | [gpio-consumption-chain.json](../../runs/current-dataflow-p2-gpio-consumption-20261006-directed-source-alias/gpio-consumption-chain.json) |

28 个内部观测量使用 `u_component.u_dut` 的固定表达式，包含完整 APB 端口、64 位写掩码、逐位寄存器、三级输入采样、时钟使能组、触发位图和状态。原始 GPIO top 的全部端口与参数保留，第三方 RTL 未修改。探针仅增加输出观察，不增加 DUT 输入赋值、时钟或 APB 访问。

驱动保存原始 runtime 名称快照；会话通过冻结的认证端口映射规范化事实。原始凭据仍保留。原 IRQ 只从官方 `interrupt` 输出选取，内部一位探针不能成为替代 IRQ。原 `pulp_gpio` 仍为默认；只有显式 `gpio_consumption=True` 或 CLI `--gpio-consumption` 才选择两个新 GPIO profile，CPU RVFI 选项独立。

## 当前真实探针门禁（来源别名修正版本）

[被动探针测试](../../tests/integration/test_local_pulp_gpio_causal_probe_real.py) 4 项与下述双 GPIO 消费链 1 项在当前源码下共同 exit 0，**5 passed in 22.33s**；完整日志为 [source-alias RTL gate](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-real-source-alias-gate.txt)。每次实际 ACCESS 校验唯一请求接纳、pre ACCESS 与响应消费，并要求同一命令内严格 `request tick < ACCESS tick < response tick`。全部 28 个 pre/post 量检查精确宽度与原导出交叉一致性。

已观察的内容包括：

- PADOUT 覆盖、PADOUTSET、PADOUTCLR、等值但不同提交身份、128 字节地址别名；上半 32 位写掩码保持导出，上 bank 不产生物理 pad 更新。
- reset epoch、跨进程重置后的 lifetime local tick、实际命令序号和先前 journal 前缀保留。
- PADIN 返回 ACCESS **pre 的 r_gpio_in**。定向输入使该 pre 值为 0，而 pre sync1 为 1；下一阶段实际更新后才读到 1。
- INTSTATUS 与新触发并发：ACCESS pre status=2、trigger mask=1、native IRQ=1，返回 PRDATA=2；post status=3。新事件优先于清除。普通后续读取返回 3 并将状态清至 0，再次读取返回 0。
- 新进程执行相同命令时，完整语义事件一致；随机 transport nonce 不被用作来源或资源身份。

此前首轮真实门禁为 2 passed / 2 failed，原因是测试把 raw `gpio_in` 当作顶层别名；修正后通过认证 export 的 runtime 名称读取输入。初次失败日志保留在 [原始门禁记录](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-real-probe-gate.txt)，不被最终通过记录覆盖。

## 双 GPIO 的实际物理消费链

[定向测试](../../tests/integration/test_gpio_consumption_chain_real.py) 是当前合并 5 项真实门禁中的 1 项；[source-alias 日志](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-real-source-alias-gate.txt) 与当前完整双次 JSON 一起保存。该测试直接建立两颗实际 GPIO 的低字节输入绑定，手动记录逻辑交付后，另行要求真实 STEP 输入及采样凭据。逻辑 Binding 声明和实际输入应用是两条记录。

每次运行包含 **63 条 journal、42 条资源记录、32 个成对 tick、7 个路由访问凭据**。两次运行各启动两颗新的 GPIO 进程；整个 `first` 与 `second` 对象相等，比较包括所有 journal、资源和 router deliveries，而非一个后缀或汇总计数。

下表的 event ID 是定向 JSON 的 journal 身份，version 是对应组件/epoch/寄存器/位的资源版本；A、B 各自的 local tick 不能当作全局同一时钟比较。

| 物理环节 | 可复查的实际引用 |
|---|---|
| A PADOUT 写提交 | APB observation 28，A tick 3，`gpio-access:gpio_a:0:1`，out bit0 version 193，0→1 |
| 完整事务身份 | `{execution_id:gpio-chain, testcase_id:gpio-physical-chain, source_component:host, source_epoch:0, channel_id:data, source_sequence:4}` |
| 低字节逻辑交付 | journal 33，A gpio_out[7:0]→B gpio_in[7:0]，value=1，携带 A out 的精确资源 refs |
| 实际输入应用 | B paired tick 34、input_applied 35、binding_actual_receipt 36；B tick 13、epoch 0、实际 command sequence 4、whole input=1 |
| 同步器逐阶段 | B sync0 bit0：observation 34/version 505/value 1；sync1：observation 37/version 518/value 1；padin_latch：observation 38/version 531/value 1 |
| 原生 IRQ | 唯一 `gpio_b:0:trigger:1`，observation 37、B tick 14 post、mask=1、pin0；包含 prior/current sample 及 GPIOEN/INTEN/INTTYPE 的版本 |
| 状态积累 | 后续 observation 38、B tick 15 pre 的同一触发；status bit0 version 541 包含 native_trigger ID、sync1 version 518 和旧 status 依赖 |
| PADIN 读取 | ACCESS observation 43、B tick 19，返回 1；pre padin_latch bit0 version 568，origin ref 指向 A out bit0 version 193 |
| INTSTATUS 读取 | ACCESS observation 51、B tick 23，返回 pre 1、post 0；消费 status bit0 version 541，记录 `cleared` |
| 清除后再读 | ACCESS observation 59、B tick 27，返回 0；不产生第二个原生 trigger |

IRQ 首次出现于 tick 14 post；状态在 tick 15 rising edge 积累。连续 post/pre 高脉冲被识别为同一原生 trigger，而非重复 IRQ。STATUS 的依赖记录明确指向该触发，不能只凭返回数值相同或事件相邻认定消费。

资源事实记录的 `proof_scope` 为 `gpio_native_resource_observation`，定向整组材料范围为 `gpio_native_physical_binding_consumption`。这里 `origin_status=known` 表示具体输入/采样资源可以追溯到精确 A out 版本；该 out 版本本身的指令和操作数来源仍未知。JSON 显式保留 `instruction_origin=unknown`、`operand_origin=unknown`，没有伪造 CPU 退休来源，也没有产生 accepted 的指令来源消费匹配。

## 当前软件验证与身份封口

当前 root 软件回归 exit 0：**637 passed、11 skipped、691 subtests passed，134.16s**。完整输出在 [root source-alias regression](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-root-source-alias-regression.txt)。skip 项是显式 opt-in 的真实 RTL 等测试；上述 4+1 项真实门禁另行执行并记录。

独立审查与负例覆盖包括：未知/缺失/改动的观测契约、profile/source/参数/表达式/宽度、legacy identity 伪装为新变体、重复等值事务、完整事务键不匹配、实际 ACCESS 缺失、lost receipt/回调异常、重入回调的精确访问 ID、一次性 drain、source/Binding 分段的实际 receipt ID、缺失/改动的 paired tick、旧 epoch 与 reset、未知与混合逐位来源，以及 STATUS 新事件优先级。

输入标记先与已记录的真实 paired tick 校验，再进入同步器资源追踪。无效标记被明确拒绝，不能凭自填 event ID 变成实际输入资源；segment 不能覆盖父记录的 component/epoch/whole input。旧 journal 不因较晚的 CPU 退休确认而重写，较晚来源证明另行追加。

## 首轮 CPU＋GPIO 在线短跑：重放通过，消费追踪容量不足

[online 运行目录](../../runs/current-dataflow-p2-gpio-consumption-20261006-online/) 以 `cpu_retirement=True、gpio_consumption=True` 启用官方 RVFI 与两个被动 GPIO 变体。实际 run exit 0，**16 cases complete**，有效搜索时间 **22.508099908001896s**，总用时 **23.662358588000643s**。种子 `20261006`，2 个完成反馈交换。精确命令、固定 seed record 与源码运行材料见 [gate_commands.json](../../runs/current-dataflow-p2-gpio-consumption-20261006-online/gate_commands.json)。

保存的完整 trace 为 115,319,117 字节，SHA-256 `62d3fd65c0da6eeb7881fff413949a11d6af0a9143c9f230d2d0a477f0e20f56`。plan SHA-256 为 `fe18d0b1638c1b4b1a5dd4be8a1c840aed16c9f8814718eacec704b3432f0096`，raw manifest SHA-256 为 `4b42dbee103e90a5fa410a9a5c0a01ca0c44236d4c2dd1d16defdeace4daa453`。

Root 已确认该首轮完整前缀 fresh replay **exit 0、matches=true**。精确运行与重放结果保留于原目录，不改写 bundle。replay 从经过原始字节 hash 验证的 saved manifest 选择配置，要求两颗 GPIO 的身份一致，并在 RTL 启动前重新核验 source/runtime/build identity。

但独立审计发现：初始默认容量 256 在 bootstrap 阶段已经耗尽，追踪器随后按设计保留 incomplete/unknown 状态，因此该 bundle 的 **accepted GPIO consumption match 为 0**。它有 **28 条 raw-linked retired transaction**，包含 typed fuzz source 的交易；这些原始完整事务关联不构成已接受的 GPIO 消费链。成功 replay 证明这个含容量不足状态的完整前缀可复现，不能提升其消费来源结论。

原 bundle 标记为容量修正前的受限基线。其记录、hash 和成功 replay 都属于当时源码身份；不把新容量配置的结果追记到旧 journal，也不宣称改动源码后仍可用旧 bundle 代表当前代码。

16 例短跑目前只用于集成与重放门禁，不据此宣称全部物理链有 CPU 来源，也不据此评估十分钟持续性能。

## 上一有界版本的在线重录与完整前缀 replay（别名修正前）

Root 为初始化和在线前缀配置显式容量 **8192**；每个缓存 map 仍独立有界。该变化仅调整追踪器构造配置，不扩展来源或物理语义。300 个 paired tick 的行为回归经历 RED→GREEN；极小容量的 fail-closed 测试保留。

| 别名修正前的有界源码门禁 | 实测结果 |
|---|---|
| 完整软件回归 | 618 passed、11 skipped、691 subtests passed；131.28s |
| 被动探针 4 项＋双 GPIO 消费链 1 项 | 5 passed；21.67s |
| 显式有界配置在线重录 | 16 complete；run exit 0；有效搜索 22.10000649200083s，总用时 23.247701981003047s |
| 整个已接纳前缀 fresh replay | replay exit 0；matches=true；first_difference=null |
| 在线来源/消费审计 | 1 条 accepted 寄存器提交来源证明、13 条 unknown、28 条 raw-linked retired transaction；0 次容量屏障；pin8 已知采样版本为 0 |

新材料在 [online-bounded](../../runs/current-dataflow-p2-gpio-consumption-20261006-online-bounded/)；精确命令及退出码见 [gate_commands.json](../../runs/current-dataflow-p2-gpio-consumption-20261006-online-bounded/gate_commands.json)，重放结论见 [replay.log](../../runs/current-dataflow-p2-gpio-consumption-20261006-online-bounded/replay.log)，门禁输出见 [online bounded gate](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-online-bounded-gate.txt)。新源码身份与旧 bundle 分开保存。

该历史有界版本的完整 trace 112,746,094 字节，SHA-256 `9d3f64acd2169ad9cab3cc508cb660f7c4aecdda2b7e0e362e34ca18b104ef22`；raw manifest SHA-256 `055441ae36f123f44d8a94443fe3da8a85f84a6ed99206f0aef7691ab15eb507`；plan SHA-256 `fe18d0b1638c1b4b1a5dd4be8a1c840aed16c9f8814718eacec704b3432f0096`。该 plan 恰与旧短跑相同，并不使两个源码/manifest 身份相同。

该历史有界版本的定向 `gpio-consumption-chain.json` 的 SHA-256 为 `0b052db0d110461e9aeeb0506db3ac73279d6128a832e4f4e19f74984c8e57f1`，仍有 63 条 journal、42 条资源、32 个 paired tick、7 个路由访问，两个新进程运行前缀完全一致；物理链引用在最新 source-alias 定向材料中也逐项核验相同。较短的定向证据与容量调整前恰好相等，不被用来改写旧在线容量不足结果。

### 历史有界 bundle 的独立来源审计

[独立审计 JSON](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-online-bounded-audit.json) 检查实际完整事务、request/ACCESS/response 三类凭据、全部 probe、RVFI 与数据响应引用、来源 registry、保存 hash 和 source closure。结果 errors=[]：14 条 GPIO 提交来源匹配中 1 条 accepted、13 条 unknown，无 capacity barrier；28 条退休/交付 raw links 中仅 1 条带已登记 fuzz 指令来源。

该已知 SW 为 PC `0x1100c`、指令 `0x0020a623`，真实写值 `0x00040101`。完整键为 `{execution_id:local-execution, testcase_id:ibex-dual-source-stream, source_component:cpu, source_epoch:0, channel_id:data, source_sequence:7}`。实际 APB event 2462、GPIO commit 2464、delivery 2471、RVFI 2546、retirement match 2547、raw link 2548 由同一键和 `gpio-access:gpio_a:0:4` 连接；对应指令 admission ID 为 `3a45bc1a1426b8e156a7f0f9ebb580c2219f52a0e3a62252c5073ad22ff7cef8`。

accepted 记录的理由是 `exact_retired_register_commit`，资源范围仍为 `gpio_native_resource_observation`；退休交付链接的范围为 `retired_instruction_transaction_delivery`。它证明已退休的已知指令字节对应实际目标提交，操作数的来源仍未知。这里没有把 LW/SRLI/SW 变换或完整 IRQ/ISR 控制链标为已证明。

该 bundle 另有 9 个实际 native trigger：pin0 的低字节 Binding 原生触发具有精确输出资源来源，8 个 pin8 trigger 的 origin 为 unknown。已知 pin8 stage version 数量为 0。原因是 logical admission 的 `source_id=gpio_b.external_pin8` 与 physical ownership 的 `producer_ref=external_b.pin8` 是受信编译图中的不同名称，旧追踪器直接字符串比较不能识别这个已声明别名。它保持 unknown，而非猜测最近一次输入。

### 来源别名修正实现与当前门禁

已增加基于已验证 `RuntimeEdgeIndex` 的不可变来源归属查询，按 admitted source ID、path、direction、component、port 和实际 bit range 解析 physical producer。查询只能位于已选物理 source 的声明范围内；存在 compiled authority 时，即使名字相等也不能绕过 path/direction 检查。当前 OwnershipMap producer 仍必须与编译结果相同。

实际输入仍必须有认证 paired tick/receipt；声明别名本身不构成物理消费。独立软件审查通过，相关证据见 [别名 authority review](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-source-alias-review.md)。上述历史有界 bundle 的 pin8 unknown 结果不会被新代码追溯提升。

容量调整前另有 4 项探针/10.27s、1 项消费链/13.33s、617 passed/11 skipped/691 subtests/133.85s 的记录，分别保留在 [初轮探针日志](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-real-probe-final-gate.txt)、[初轮消费链日志](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-real-chain-final-gate.txt)、[初轮软件日志](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-root-regression.txt) 和 [初轮定向目录](../../runs/current-dataflow-p2-gpio-consumption-20261006-directed-final/)。当前门禁使用上述新结果，而非沿用这些旧源码阶段计数。

## 最新来源别名修正版本：门禁与独立来源审计通过

| 当前源码门禁 | 实测结果 |
|---|---|
| 完整软件回归 | 637 passed、11 skipped、691 subtests passed；134.16s |
| 被动探针 4 项＋双 GPIO 消费链 1 项 | 5 passed；22.33s |
| 在线 record | 16 complete；run exit 0；有效搜索 23.370535706999362s，总用时 24.619288410998706s |
| 整个前缀 fresh replay | replay exit 0；matches=true；first_difference=null |
| GPIO 指令提交来源 | 1 accepted、13 unknown；28 条 raw retirement links；0 次 GPIO 容量屏障 |
| 已登记 pin8 stage version | sync0 540、sync1 539、padin_latch 538；合计 1617 |
| 已知原生触发 | pin8 8 个＋Binding pin0 1 个；全部 9 个具有局部物理来源 |
| 已知 bit8 读取 | PADIN 8 次、STATUS 7 次 |
| 实际输入审计 | 5000 个 applied segment，其中 pin8 精确 receipt 480 个、Binding 4520 个 |

新材料为 [online-source-alias](../../runs/current-dataflow-p2-gpio-consumption-20261006-online-source-alias/) 和 [directed-source-alias](../../runs/current-dataflow-p2-gpio-consumption-20261006-directed-source-alias/)。精确命令/退出码见 [gate_commands.json](../../runs/current-dataflow-p2-gpio-consumption-20261006-online-source-alias/gate_commands.json)，完整前缀匹配见 [replay.log](../../runs/current-dataflow-p2-gpio-consumption-20261006-online-source-alias/replay.log)，门禁输出见 [online source-alias gate](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-online-source-alias-gate.txt)。

当前 trace 114,089,538 字节，SHA-256 `1a21789e57652f1875e4441239e7c599f14fcf35a2ac110e93269e24f91579a7`；plan SHA-256 `0412f0c3e444a72eb4f2542c37b4d999248b1627ffdff147497ba8f7dc505a7e`；raw manifest SHA-256 `d73cc2073329e96473af49ddb44963fa5c5aca3b8c1fb7945686c82615ca4e6d`。它与先前有界/256 容量 bundle 使用分开的身份与目录。

当前定向两次全量记录相等，仍为 63 条 journal、42 条资源、32 个 paired tick、7 个路由访问；JSON SHA-256 `0b052db0d110461e9aeeb0506db3ac73279d6128a832e4f4e19f74984c8e57f1`。这项小规模 host 物理测试保持相同，不替代在线 source-origin raw audit。

独立审计材料见 [最终审计报告](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-source-alias-independent-audit.md)、[在线审计 JSON](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-online-source-alias-audit.json)、[逐资源审计 JSON](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-source-alias-resource-audit.json) 和 [来源 authority 审计 JSON](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-source-alias-authority-audit.json)。所有结果 pass、errors=[]；12 个 raw artifact hash 与 341 个当前源码文件 hash 均吻合保存的运行身份。

480 个 pin8 segment 分别与实际输入 receipt、paired tick、reset epoch、command scope 和完整 pre/post drive 相符。已知 stage origin 均对应登记的 canonical admission，保留 `fuzz_source`/`source_event` 类型；8 个 pin8 trigger 逐条解析到 sync1→sync0→输入资源→实际 tick。全部 5000 个 segment 和 4520 个 Binding segment 也进行了精确引用检查；早期未知 Binding 版本继续保留 unknown。

1 条 accepted 指令提交证明仍是 PC `0x1100c`、指令 `0x0020a623` 的同一完整事务键，连接物理 APB 2462、commit 2464、delivery 2471、RVFI 2546、retirement 2547、raw link 2548 和 source proof 2549。该证明范围是实际已退休指令对应目标提交；它没有证明写入操作数的数据变换来源。CPU 退休侧另保留 4 条 ambiguous、4 条 capacity-incomplete 和 43 条 rejected；GPIO 容量屏障为 0 不消除这些 CPU 不确定性。

真实 Rust client 验证另有 [16 tests、1.788s、OK](../../.superpowers/sdd/current-dataflow-p2-task4-gpio-rust-client-gate.txt)。它发生于别名源码调整前，但 Rust source 未改动；报告将其作为独立 transport 验证，不把它记为别名修正后的 GPIO 来源计数。

## 仍然缺少的证明

本报告不覆盖通用 `GPIO native IRQ → host pulse mapping → CPU taken → authenticated entry → ISR RVFI → ISR read` 全链。定向 GPIO 测试没有 CPU，真实 STATUS/PADIN 读取由 host 发起。在线 trace 中各条接受边的来源、proof_scope 和负例矩阵仍须单独审计。

`LW → SRLI → SW` 的操作数变换来源尚未经过独立数据依赖证明。受控 ISR 执行、一次真实退休、相等的 PADOUT 数值或 fresh replay exit 0 都不能把这条返回链标成 source-derived。UART FIFO/寄存器消费、完整 CPU 操作数/IRQ 控制链以及后续性能/校准门禁仍未完成。

第一步 [P1～P5 总体目标](../superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md) 仍未完整验收。P1 的声明身份/入口范围完成，不等于 P2～P5 的来源消费、长会话、合法反馈与故障/效率目标全部完成；P2 明确保持部分完成。

总体阶段状态保持：P1 已完成，P2～P5 部分完成；P6 部分完成，P7 未完成，P8 尚未实现。本次 GPIO 局部来源验证不提升这些整体阶段状态。
