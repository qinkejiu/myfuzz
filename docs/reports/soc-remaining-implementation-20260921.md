# 自动组合 SoC：剩余实现任务清单

2026-09-22 阶段 0 二次复核：当前代码的相关纯测试为 `47 passed, 25 skipped`（真实 RTL 开关未启用），SPI 注入/多源 latch/SPI 线级真实套件为 `15 passed, 0 skipped`，独立代码复审通过。离线确认现要求重建完整计划、对比重建变异版与保存证据的完整 replay 字段，并检查声明 include 根目录在编译前后的可观测漂移。确认仍限于受信任规范/夹具下的受控 SPI 注入；不证明不可变编译快照或任意未知组件缺陷。下方较早的测试数字与工具缺失记载均为历史记录；阶段 4 的工具状态以其最新记录为准。

2026-09-22 阶段 2+3+4 复核验证：阶段 2 四个模块 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_peer_uart_oracle tests.integration.test_soc_peer_spi_modes tests.integration.test_soc_peer_gpio_contract tests.integration.test_soc_peer_replay_binding` 纯 197 通过 / 90 按依赖跳过，`MYFUZZ_SOC_REAL=1` 0 跳过通过；阶段 3 三个模块 `test_soc_irq_sample_matrix`(13) `test_soc_irq_trigger_negatives`(44) `test_soc_irq_evidence_package`(23) 全部真实通过；阶段 4 `MYFUZZ_SOC_REAL=1 tests.integration.test_soc_profile_rfuzz_campaign` 通过（197 秒，`status=completed_with_client_termination`、`evidence_missing=[]`、`corpus.status=verified` 3 条、`replay.status=passed`、`cleanup.status=clean`、4096 条 receipt、26422 次测试、13153 条覆盖记录、`source_transactions=26422`、`target_transactions>0`），`test_soc_official_corpus_replay`/`test_soc_campaign_arms`/`test_soc_campaign_comparison` 28 个真实用例通过。工具身份：官方 RFuzz 客户端 `kfuzz 0.1.0`（`runs/rfuzz_client_native_build/target/debug/kfuzz`，源码 <https://github.com/timothytrippel/rfuzz>）、bundled Verilator `Verilator 5.020 2024-01-01 rev UNKNOWN.REV (mod)`（`third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator`，由 <https://github.com/verilator/verilator> v5.020 源码构建）。阶段 0+1 的结论保持：30 纯 + 288 纯 / 66 跳过 + 全量真实套件 0 跳过通过。`git diff --check` 干净。
2026-09-22 阶段 0+1 复核验证：纯测试 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_input_arms_projection tests.integration.test_soc_input_transport_ab tests.integration.test_soc_input_chain_report tests.integration.test_soc_input_real_rtl_gate tests.integration.test_soc_input_stale_identity_refusals tests.integration.test_soc_input_event_refusals tests.integration.test_soc_input_repair_runtime tests.integration.test_soc_dependency_replay tests.composition.test_soc_input_repair tests.composition.test_soc_image tests.integration.test_soc_campaign_arms tests.integration.test_soc_campaign_comparison` 共 288 个通过、66 个按依赖跳过；`MYFUZZ_SOC_REAL=1` 全量真实套件（同前八项）0 跳过通过；阶段 0 的 `test_soc_defect_confirmation` + `test_soc_offline_defect_confirmation` 30 个通过；`git diff --check` 干净。工具身份：Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67（`~/.local/bin/verilator`，sha256 `fb2cc573…fcdf`）、Icarus Verilog 14.0 devel f493076（`~/.local/bin/iverilog`，sha256 `9b3f0a69…be6a`）。bundled RFuzz Verilator 5.020 仍缺失，因此 `test_soc_profile_rfuzz_build`/`test_soc_campaign_arms` 的 profile-build 用例保持 skip，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。
2026-09-22 阶段 0 复核验证：`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_defect_confirmation tests.integration.test_soc_offline_defect_confirmation` 共 30 个通过、0 跳过、1.882 秒；`MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v tests.integration.test_soc_defect_injection_real tests.integration.test_soc_multi_latch_fault tests.integration.test_soc_spi_wire_oracle` 共 15 个通过、0 跳过（SPI 注入 2、多源 latch 5、线级判据 8，304.851 秒）；`git diff --check` 干净。工具身份：Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67（`~/.local/bin/verilator`，sha256 `fb2cc573…fcdf`）、Icarus Verilog 14.0 devel f493076（`~/.local/bin/iverilog`，sha256 `9b3f0a69…be6a`）。本次定向验证没有工具阻塞。bundled RFuzz Verilator 5.020 仍缺失，因此 `test_soc_profile_rfuzz_build` 的 17 个 profile-build 用例保持 skip，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。

2026-09-21 离线复核迁移验证：`PYTHONPATH=src python3 -m unittest -q tests.integration.test_soc_defect_confirmation tests.integration.test_soc_offline_defect_confirmation` 共 25 个通过、0 跳过；`MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest -v tests.integration.test_soc_defect_injection_real tests.integration.test_soc_multi_latch_fault tests.integration.test_soc_spi_wire_oracle` 共 15 个通过、0 跳过（SPI 注入 2、多源 latch 5、线级判据 8，76.264 秒）。本次定向 Verilator/Icarus 验证没有工具阻塞；官方 RFuzz 的固定工具依赖缺口仍然存在，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。

更新日期：2026-09-21。本文是当前工作树的执行清单，配合
[`soc-capability-matrix-20260921.md`](soc-capability-matrix-20260921.md)、
[`soc-design-acceptance-20260921.md`](soc-design-acceptance-20260921.md) 和
[`2026-09-20-soc-composition-assurance-plan.md`](../superpowers/plans/2026-09-20-soc-composition-assurance-plan.md)
阅读。它只列出尚未完成的实现、环境闭环和验收工作；已经通过的测试不重复写成待办。

这里的“完成”有严格含义：代码接入生产路径，生成物包含可审计的身份和连接，正例与负例通过，真实 RTL 路径至少有一次可重放运行。只有单元测试、静态渲染或文档声明的能力仍标记为“部分完成”。

## 一、完成目标所必需的任务

### P0. 把 profile 组合路径接入真实 RFuzz campaign

当前状态：RFuzz 生产接入代码已完成：resolver/config normalization、固定 5.020 工具准入、profile builder 的 tool/env/provenance/cache 身份、`run_soc_campaign` 的默认 build/live wiring、失败分类和清理报告均已接通；`replay_official_corpus_arms` 只接受带官方 execution/receipt/verified manifest 的单臂 raw corpus，并在三个 projector 间强制共享 executable/layout/source/tool identity。本机没有官方 `kfuzz` 和 bundled Verilator 5.020，因此尚未形成真实变异器搜索的生产证据。BFM 合成主接口仍不进入 RFuzz 语料。

仍需完成的是依赖环境中的实跑和证据，而不是再写一套接线代码：

1. 准备并验证官方 RFuzz 客户端、bundled Verilator 5.020 和客户端运行目录；缺失时当前实现会在构建前明确失败，不能用本机其他版本冒充。
2. 在固定依赖环境中完成一次 profile 单臂真实 campaign，保存 receipt、非空 corpus、覆盖、清理和 rebuild replay；再调用 `replay_official_corpus_arms` 生成“官方语料 + 三臂重放”报告。
3. 用真实报告验证 direct、constraint-only、dependency-repair 的 raw/projection/repair/rejection/coverage/anomaly 指标；三臂重放不能重新运行三个独立变异器搜索。
4. 完成内容寻址构建缓存的命中/失效实跑，证明仅改变样本不会重编译 RTL，而改变 profile、规则、布局或工具身份会失效缓存。
5. BFM isolated/contention 的合成主接口继续保持范围外；若纳入 RFuzz，另行定义输入槽位、来源、背压、归属和 CPU 覆盖排除的契约，不能把 seeded 输入当作已接通。

完成判据：在具备依赖的环境中，真实 `kfuzz` 至少完成一个 production 单臂并留下可重放 corpus；三个 projector 使用该同一 corpus 完成严格重放，报告有效输入率、唯一语料、CPU/IP 覆盖、构建缓存命中率及三臂成本。没有这些数据时只能称 seeded-corpus 机制和 official-replay 契约已实现，不能称真实 RFuzz campaign 已完成。

建议验证入口：`tests.integration.test_soc_campaign_arms`、`test_soc_campaign_comparison`、`test_soc_rfuzz_live`、`test_soc_profile_rfuzz_build`，以及完整 `MYFUZZ_SOC_REAL=1` 回归。

### P0. 接通 UART/SPI/GPIO peer 的生产 ABI、事件和重放

本轮（2026-09-22，路线图阶段 1）补上了这一项的 raw ABI 半边：`render_profile_testbench`/`build_profile_runtime` 现在真正消费合并 ABI——对端请求端口由 raw 字驱动（`assign <port> = <port>__event_active ? <port>__event : raw_bits[hi:lo];`，事件计划在事件触发的那一拍覆盖 raw 电平），且该端口不再带任何初值（否则 Verilator `CONTASSINIT` 拒绝，此前所有对端组合根本无法编译）。声明式候选程序也不再以 `image.raw_width` 约束记录宽度，因此带对端字段的合法记录能通过 `dependency_repair`。真实证据：`test_soc_input_real_rtl_gate.py` 改单个 raw 字段即改变 RXDATA/STATUS/DATA_IN 寄存器读回；`MYFUZZ_SOC_REAL=1 tests.integration.test_soc_peer_models` 50 个用例全绿（此前 6 个 setUpClass 因编译失败报错）。仍未做：UART framing/timeout、SPI 多字与复杂错误时序、GPIO 运行时 contention 的线级判据（见下条）。


当前状态：`soc_uart_peer.sv`、`soc_spi_peer.sv`、`soc_gpio_peer.sv` 已有独立 RTL 回归；profile renderer 和 profile RFuzz artifact 已把 peer 请求端口接入 per-cycle raw ABI，生成的 layout、persistent testbench、source closure 和 pulse 最小间隔拒绝已有验证。raw ABI 事件证据进入 RFuzz 语料和边界重放。`soc_peer_oracle.v1` 保存 peer 参数/协议/源内容哈希、事件传输及可观测 UART 发送计数。新增的 SPI 线级监视器按已解析角色绑定采样 SCK/CS/MOSI/MISO，独立 Python 判据把实际 CPU TXDATA 总线写入与 peer arm 字节分别作为 MOSI/MISO 期望；已在 Ibex+SPI+GPIO 真实运行和注入 MOSI 错位的真实运行中给出 pass/mismatch，线级轨迹、总线请求与 oracle 哈希都进入 EvidencePackage replay。该判据只覆盖已准入模式的单字传输；缺独立寄存器规范、总线写入、完整波形或发生截断时保持 `not_assessed`。UART 接收/framing/timeout、GPIO 电气解析以及 PULP GPIO 的真实 `inout` 行为仍未评估。

还需要实现：

1. [已完成] 为每个 peer slot 将 valid、payload、mask、时钟/片选等可驱动信号纳入 `combined_input_layout`，记录顶层 port、宽度、来源、最小间隔和所有权；旧的无 peer layout 保持兼容。
2. [部分完成] persistent testbench 已按 layout 驱动字段，并检查 pulse slot 最小间隔；UART 发送计数、GPIO 真值表和 SPI 单字四线传输有独立 Python 判据。UART framing/timeout、SPI 多字/复杂错误时序及 GPIO 运行时 contention 仍缺少足够线级证据，只能标记为 `not_assessed`。
3. [已完成/范围受限] raw ABI 事件已序列化到 RFuzz 语料，并在 replay 中检查 slot、周期、payload、间隔、模型/协议字段和 peer 源内容哈希；运行结果中的 `soc_peer_oracle.v1` 会随完整 `EvidencePackage` 保存，边界 replay 比较 oracle 状态与哈希。缺失或哈希不一致的事件证据仍会拒绝。
4. [部分完成] peer 连接已有独立参考模型和运行审计；SPI 单字判据已用线级波形及 CPU 实际写入闭环，不能由 peer RTL 自身计数生成唯一期望。未观测的行为仍须保持 `not_assessed`。
5. 明确 PULP GPIO 双向接口的支持边界。若暂不实现电气解析，必须在生成阶段拒绝 `inout`/驱动冲突配置，而不是退回随机输入。

完成判据：一个含 UART、SPI、GPIO 的未知 profile 组合能生成含 peer 的 top、layout、transport、live TB 和 replay package；改变 peer raw 字段能改变对应模型行为，未声明端口、非法间隔和 contention 负例均在边界被拒绝。

建议新增或扩展：`tests.integration.test_soc_peer_models`、`test_soc_profile_rfuzz_build`、`test_soc_boundary_replay`、`tests.composition.test_soc_image`。

### P0. 建立真实 CPU 多源中断闭环

当前状态：同域 level/pulse/edge、`soc_irq_edge_detect`、`LATCH_MASK` 和真实 Ibex 单源 lifecycle 已有证据；通用生成器现在把外部 GPIO 事件、附加 peer 事件和 profile 声明的有序 MMIO `write_value` 动作合并为统一 trigger plan，由所有 source ID 逐个执行 claim/按 profile 清除/COMPLETE，并保存 `interrupt_completions` 与 `all_sources_closed`。中断 source 还可以声明通用的 MMIO `set_bits` 前置条件；生成器只执行这些封闭操作，不猜测组件型号语义。`MYFUZZ_SOC_REAL=1` 的双 `novagpio` 实例正例已覆盖同周期触发、固定优先级、source ID、两次 ISR 进入和闭环；真实 Ibex + UART peer + GPIO 以及 Ibex + SPI peer + GPIO 均已完成异构闭环。SPI 的 `TXDATA`/`CTRL` 写入由 profile 声明，并在 peer arm 后执行，不是生成器的专用分支；去掉这些软件触发写入的负例不会完成 SPI source。屏蔽负例验证两源均不被 claim；额外的 staggered 运行覆盖不同到达窗口。跨域和非 `machine_external` 入口仍按设计拒绝。

本轮复核记录：双 GPIO、UART+GPIO 与 SPI+GPIO 的定向真实运行均通过；SPI+GPIO 正例完成两源 claim/clear/COMPLETE，并以实际线级轨迹通过独立单字 SPI 判据和 EvidencePackage replay。双源 edge+level 注入运行仅清除 edge 源的 latch 位后，level 源仍服务一次，edge 源 pending/claim 不闭环；保留原始/变异顶层哈希的证据包可重放并分类为 `composition_defect`。这不等同于持续多源 campaign 或对所有 edge/pulse 组合的证明。

源 ID 置换负例还暴露了软件汇总字段的范围：两源同周期到达时，`all_sources_closed` 可能仅因完成次数达到 2 而为 1，它本身不证明 ID↔物理源映射正确。错开事件的真实运行未闭环，独立结构审计也拒绝置换后的 `interrupt_paths`。因此组件归因门槛要求结构审计通过并绑定实际顶层哈希，不能只引用软件汇总字段。

还需要实现：

1. 将 UART+GPIO 和 SPI+GPIO 的真实运行扩展到持续 campaign 和多样本日志/EvidencePackage；目前两者均只有单样本闭环及重放证据，不能推断协议的全部行为已覆盖。
2. [部分完成] 已在真实 edge+level 双源 SoC 注入一个 source-specific latch 位缺失并归类为组合缺陷；仍需对 pulse、falling/both edge 的多源组合以及屏蔽错误、source ID 错位逐项做真实负例。
3. 将多源运行接入持续 campaign，确保每个 source 的实际输入、pending、claim、清除和 COMPLETE 轨迹均进入统一 EvidencePackage；目前异构单样本和 edge+level latch 注入均可重放，持续生产入口仍待验证。
4. 仍明确拒绝 CDC；如果未来实现 CDC，必须另建同步器/FIFO 能力和独立验证，不能把 edge detector 当同步器。

完成判据：真实 CPU 程序在同一生成 SoC 中完成至少两个异构源的通知、识别、清除和 `COMPLETE`，并具有同周期、不同周期、屏蔽和 latch 负例；运行日志与独立 peer oracle 一起进入可重放 EvidencePackage。UART+GPIO、SPI+GPIO 单样本闭环、SPI 单字线级判据及 edge+level latch 注入已达成；持续多样本 campaign 和其他 trigger 的多源注入仍待完成。

### P0. 完成组件内部 bug 的独立归因闭环

当前状态：结构审计、边界重放、失败证据及保守的 `component_candidate` 初筛已实现。受控 SPI 注入实验中，原始 RTL 在 SoC/独立 APB 夹具均发送 `0x5A`，仅改组件 TXDATA 内部赋值后两处均发送 `0x5B`；另一个仅删去多源 latch 位的实验归为组合缺陷。新 `confirm_component_offline` 显式重跑两套 SoC、变异 replay、两份结构审计和独立 APB 夹具，并绑定规范、构建及源码内容。旧 `confirm_component_defect` 对候选一律返回 `offline-verification-required`，调用方自报映射不再确认。`component_confirmed` 仅表示支持的 SPI 注入样例在受信任规范和夹具前提下通过此次复核，不表示发现自然存在的未知组件 bug。

还需要实现：

1. [部分完成] RuntimeBuild/证据包现已记录源文件内容哈希、profile、工具与生成物身份，SPI 注入实验记录原始/变异源码和独立规范哈希；CPU、适配器、控制器及其他 peer 的逐类归因规范与隔离夹具仍待扩展。
2. 为每类可疑失败记录组件拥有的请求/响应、握手合法性、地址权限、复位阶段、中断前置和软件状态；先排除生成器、adapter、profile、软件、peer、harness 和环境错误。
3. SPI 单字样例的离线复核和旧映射入口关闭已实现；后续需扩展独立规范与隔离夹具到其他组件。`record_offline_confirmation` 保存审计、重放、隔离、构建哈希及报告哈希；保存 JSON 的验证仅为 `record-integrity-only`，重新取得确认必须重跑离线入口，旧 v1 记录与反序列化对象均不构成新证明。
4. [已完成/范围受限] 一个 SPI 组件 RTL 注入与一个多源 latch 连接错误均已真实运行和重放，前者在受控夹具中有隔离对照；尚未覆盖其他组件种类或自然 bug。
5. 缩减时保留失败前置状态和同一失败性质；原始 RTL、插桩 RTL 和重放环境的差异必须显式报告。

完成判据：缺身份、规范依据或合法性证据的报告只能标为“候选/未定位”；只有独立规范违例、可重复反例和边界排除链同时满足时，才允许标为“组件内部 bug”。

## 二、需要补齐但可在首期边界内分阶段完成的任务

### P1. 扩大输入依赖修复的有效范围

当前只承诺有限单指令/单数据镜像、ISA 合法性、地址/权限和部分寄存器前置修复。后续要实现多候选程序、跨记录寄存器定义/使用、基址加立即数、控制流目标、压缩指令以及更多受支持 ISA 扩展；每项都必须有预算、拒绝原因和重放身份。不能用“随机位”代替未实现的依赖。

完成判据：改变 instruction/data 候选确实改变 CPU 释放前镜像和执行轨迹；非法依赖被拒绝或修复并计数；修复器不修改 CPU 已提交输出和 DUT 响应。

### P1. 完成首期 RISC-V 软件与 MMIO 行为覆盖

当前有有限 boot/ISR、ROM/RAM、未映射/权限/写 ROM 等行为证据。仍需把 profile 声明的寄存器初始化、状态轮询、清除、副作用和错误响应组合成通用软件模板，并覆盖等待、背压、异常返回和多个外设协同；软件不能按组件型号写专用分支。

完成判据：未知但满足已支持 ISA/ABI 和协议契约的 CPU/外设组合能使用同一后端生成启动和测试程序；缺失语义明确拒绝，不能静默访问猜测的寄存器。

### P1. 完成 OpenTitan 外设的组合留出验证，并保持 CVA6 边界诚实

OpenTitan TL-UL profile 的结构体成员和 sideband 已绑定，但 Ibex + OpenTitan 的新组合、MMIO 错误行为和中断闭环还需一次独立实跑。CVA6 的 64-bit AXI4 master 目前是明确拒绝项；除非先实现并验证通用 64→32 适配、字节使能、burst/响应语义，否则不得把 CVA6 结构审计写成 CVA6 SoC 支持。

完成判据：OpenTitan 组合有独立 request/profile、生成物、运行轨迹和负例；CVA6 若仍未扩展则在能力矩阵和命令输出中保持稳定拒绝。

### P1. 统一能力矩阵、验收报告和 CI 状态（本轮已完成文档同步，持续维护）

计划、能力矩阵和验收报告必须引用本清单，且“已实现”“部分实现”“环境阻塞”“明确拒绝”四种状态保持一致。完成每项后同时更新代码入口、测试名、证据路径和环境要求，避免旧结论（例如 peer 尚未接通或脉冲中断未闭环）残留。

完成判据：从干净环境按文档命令可定位每一项证据；测试跳过原因与真正失败分开；全量回归结果带日期、工具身份和依赖缺口。本轮已同步能力矩阵、验收报告、研究范围和本清单；固定依赖实跑后只需补写真实结果，不得改写范围口径。

## 三、明确不作为本轮完成门槛的范围外能力

以下内容是未来研究扩展，不应通过临时常量或随机端口伪造支持，也不阻塞首期“单核、单时钟域、单未完成事务、非 DMA”的论文原型：

- CDC、复杂时钟切换和跨域中断；
- 多核一致性、外设 DMA、多主并发；
- AXI4/TileLink 完整 burst、乱序、多 outstanding、exclusive 和完整 sideband 语义；
- 真实 `inout` 电气强度、上拉、漏电和亚稳态；
- 非 RISC-V 自动软件后端；
- STA、功耗、面积和版图后功能验证。

如果论文把这些扩展列为最终系统能力，必须先新增通用契约、适配器和独立验收，不得沿用本轮“明确拒绝”的证据冒充实现。

## 四、推荐执行顺序

1. 先准备固定工具和真实 RFuzz 客户端，完成 P0.1 的环境验收。
2. 在已接通的 peer raw ABI 上补独立行为判据和源内容身份，先用 seeded-corpus 验证，再接 `kfuzz`。
3. 把已验证的 UART+GPIO、SPI+GPIO 单样本证据扩展为持续 campaign，补多源混合 trigger、latch 负例和线级独立判据。
4. 建立独立参考/故障注入归因，再进行三臂 campaign 对照；没有归因链的覆盖增长不能作为论文 bug 结论。
5. 最后做多候选输入依赖、OpenTitan 留出组合和全量回归；P2 范围另开研究任务。

当前最终验收仍以本文件 P0 全部完成为最低门槛；P1 用于扩大首期覆盖，P2 不属于本轮完成承诺。
