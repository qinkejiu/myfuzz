# 研究范围与后续工作（2026-09-21）

2026-09-22 阶段 0 二次复核：当前代码的相关纯测试为 `47 passed, 25 skipped`（真实 RTL 开关未启用），SPI 注入/多源 latch/SPI 线级真实套件为 `15 passed, 0 skipped`，独立代码复审通过。离线确认现要求重建完整计划、对比重建变异版与保存证据的完整 replay 字段，并检查声明 include 根目录在编译前后的可观测漂移。确认仍限于受信任规范/夹具下的受控 SPI 注入；不证明不可变编译快照或任意未知组件缺陷。下方较早的测试数字与工具缺失记载均为历史记录；阶段 4 的工具状态以其最新记录为准。

2026-09-22 阶段 2+3+4 复核验证：阶段 2 四个模块 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_peer_uart_oracle tests.integration.test_soc_peer_spi_modes tests.integration.test_soc_peer_gpio_contract tests.integration.test_soc_peer_replay_binding` 纯 197 通过 / 90 按依赖跳过，`MYFUZZ_SOC_REAL=1` 0 跳过通过；阶段 3 三个模块 `test_soc_irq_sample_matrix`(13) `test_soc_irq_trigger_negatives`(44) `test_soc_irq_evidence_package`(23) 全部真实通过；阶段 4 `MYFUZZ_SOC_REAL=1 tests.integration.test_soc_profile_rfuzz_campaign` 通过（197 秒，`status=completed_with_client_termination`、`evidence_missing=[]`、`corpus.status=verified` 3 条、`replay.status=passed`、`cleanup.status=clean`、4096 条 receipt、26422 次测试、13153 条覆盖记录、`source_transactions=26422`、`target_transactions>0`），`test_soc_official_corpus_replay`/`test_soc_campaign_arms`/`test_soc_campaign_comparison` 28 个真实用例通过。工具身份：官方 RFuzz 客户端 `kfuzz 0.1.0`（`runs/rfuzz_client_native_build/target/debug/kfuzz`，源码 <https://github.com/timothytrippel/rfuzz>）、bundled Verilator `Verilator 5.020 2024-01-01 rev UNKNOWN.REV (mod)`（`third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator`，由 <https://github.com/verilator/verilator> v5.020 源码构建）。阶段 0+1 的结论保持：30 纯 + 288 纯 / 66 跳过 + 全量真实套件 0 跳过通过。`git diff --check` 干净。
2026-09-22 阶段 0+1 复核验证：纯测试 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_input_arms_projection tests.integration.test_soc_input_transport_ab tests.integration.test_soc_input_chain_report tests.integration.test_soc_input_real_rtl_gate tests.integration.test_soc_input_stale_identity_refusals tests.integration.test_soc_input_event_refusals tests.integration.test_soc_input_repair_runtime tests.integration.test_soc_dependency_replay tests.composition.test_soc_input_repair tests.composition.test_soc_image tests.integration.test_soc_campaign_arms tests.integration.test_soc_campaign_comparison` 共 288 个通过、66 个按依赖跳过；`MYFUZZ_SOC_REAL=1` 全量真实套件（同前八项）0 跳过通过；阶段 0 的 `test_soc_defect_confirmation` + `test_soc_offline_defect_confirmation` 30 个通过；`git diff --check` 干净。工具身份：Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67（`~/.local/bin/verilator`，sha256 `fb2cc573…fcdf`）、Icarus Verilog 14.0 devel f493076（`~/.local/bin/iverilog`，sha256 `9b3f0a69…be6a`）。bundled RFuzz Verilator 5.020 仍缺失，因此 `test_soc_profile_rfuzz_build`/`test_soc_campaign_arms` 的 profile-build 用例保持 skip，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。
2026-09-22 阶段 0 复核验证：`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_defect_confirmation tests.integration.test_soc_offline_defect_confirmation` 共 30 个通过、0 跳过、1.882 秒；`MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v tests.integration.test_soc_defect_injection_real tests.integration.test_soc_multi_latch_fault tests.integration.test_soc_spi_wire_oracle` 共 15 个通过、0 跳过（SPI 注入 2、多源 latch 5、线级判据 8，304.851 秒）；`git diff --check` 干净。工具身份：Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67（`~/.local/bin/verilator`，sha256 `fb2cc573…fcdf`）、Icarus Verilog 14.0 devel f493076（`~/.local/bin/iverilog`，sha256 `9b3f0a69…be6a`）。本次定向验证没有工具阻塞。bundled RFuzz Verilator 5.020 仍缺失，因此 `test_soc_profile_rfuzz_build` 的 17 个 profile-build 用例保持 skip，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。

对应 14 项要求的第 14 项。目的：把"本轮是什么、不是什么"写死，避免用"自动组合已完成"覆盖仍属后续工作的能力。

具体的 P0/P1/P2 实现顺序和逐项验收条件见 [`soc-remaining-implementation-20260921.md`](soc-remaining-implementation-20260921.md)；本文件继续负责论文范围和结论口径。

## 1. 本轮的结论口径

本轮可以说出口的结论只有三种，每种都必须绑定证据：

| 结论 | 需要的证据 | 本轮达到的范围 |
| --- | --- | --- |
| **能组合** | profile 与真实 elaboration 事实一致；端口台账完整；连接计划通过校验；生成 RTL 重新展开后由独立审计核对 | 达到（首次输入 CPU/外设、已有 Ibex CPU + 首次输入外设、同 profile 多实例、BFM/竞争模式）；CVA6 只达到 profile/结构审计，64-bit master 仍按声明范围拒绝 |
| **能运行** | 真实构建 + 真实仿真，且有待测对象的行为证据（CPU 执行、MMIO 副作用、中断闭环） | 达到的范围：Nova 示例、真实 Ibex + novagpio，以及真实 Ibex + UART peer + GPIO 的引导→中断→pending→CLAIM→ISR→清除→COMPLETE 闭环；BFM 单独与竞争模式；三方 campaign 的 seeded-corpus-real-rtl 执行。官方 RFuzz 单臂及官方语料三臂重放的生产入口已实现，但本机依赖缺失，尚无真实官方运行证据 |
| **能判错** | 有明确判据（规范/断言/参考模型）+ 可复现反例 + 边界归因证据 | 达到的范围：未映射地址错误响应、控制器契约（单元级参考模型对照）、五类故障注入的边界分类、重放与缩减，以及一个受控 SPI 注入样例的隔离对照。**未达到**：通用自动化组件缺陷确认和自然存在的未知组件 bug 确认 |

**本轮不声称**：整份 profile 的语义正确性、"能运行"结论可外推到其他配置、组件内部缺陷已被发现或排除。

## 2. 明确的范围外（列为后续工作）

以下能力**不在本轮范围**，也不以任何形式被当前结论覆盖。它们是扩大覆盖的下一步，不是"已完成"的暗含部分。

| 范围外项 | 为什么不在本轮 | 扩大范围需要什么 |
| --- | --- | --- |
| 多核与缓存一致性 | 首期边界为单核单域；仲裁与响应归属只按单未完成事务设计 | 多主并发互联、每核一致性契约、跨核中断路由，并独立验证 |
| DMA / 外设主动总线主接口 | 首期外设只作为 MMIO 从设备；没有外设主导的地址生成与响应归属 | 外设主接口的能力声明、第二类主的仲裁公平性与归属、与 CPU 的竞争语义 |
| 跨时钟域连接与复杂时钟切换 | 首期单时钟域；profile 与请求校验直接拒绝非同域输入 | 通用同步器/异步 FIFO 能力、CDC 约束声明与独立验证、跨域复位释放顺序 |
| 非 RISC-V ISA 的自动软件生成 | 软件后端只覆盖 RISC-V 家族；其他 ISA 明确报能力缺口 | 对应 ISA 的后端、ABI/启动契约、指令合法性与依赖修复规则 |
| TileLink / AXI4 的完整语义 | 目前是子集适配：边带按 accept-ignore/reject 策略，不承载完整语义 | 多通道并发、exclusive、完整性字段传播、乱序与多 outstanding 的端到端语义 |
| burst / 多 outstanding / 乱序响应 | 全局单未完成事务；串行化会减少组件经历的并发状态 | 支持并发的互联与适配链，并把"并发覆盖"作为独立判据 |
| inout / 真实双向端口与电气行为 | profile 只表达 input/output；对端模型不含强度、亚稳态、上拉/漏电 | 双向解析与驱动使能的通用建模、电气层验证边界 |
| 物理实现后验证（时序/功耗/面积） | 本轮是行为级 RTL 仿真与结构审计 | STA、形式验证、版图后仿真，并说明与功能覆盖的关系 |

## 3. 覆盖损失必须随结论一起出现

首期边界的代价已经在生成清单与实验报告里逐项记录，引用时必须带上，不能只给"通过"：

- **单未完成事务**：串行化减少了组件经历的并发状态，因此不承诺发现依赖多事务并发或乱序响应的缺陷。
- **单核单域**：不覆盖多核一致性、跨域中断、复杂时钟切换。
- **非 DMA 模式**：若外设只在 DMA 模式下工作，明确拒绝；若可独立工作，报告必须记录 DMA 功能未测试。
- **中断**：单上下文、固定最低 ID 优先；同域 level 直接采样，pulse/edge 通过显式 latch/edge normalizer 验证；真实 Ibex + 双 GPIO、Ibex + UART peer + GPIO 与 Ibex + SPI peer + GPIO 已覆盖多源 claim/clear/COMPLETE。另有 edge+level 双源运行：仅删除 edge 源 latch 位时该源不闭环、level 源仍服务，归类为组合缺陷。UART 接收使能和 SPI 软件触发写入均由 profile 的通用 MMIO 动作设置；不覆盖嵌套领取、CDC、跨域源、持续多源 campaign 或所有 trigger 类型的多源故障注入。
- **BFM 竞争**：交替归属成立，但不声称并发；归属证据来自仲裁器自身的 `rsp_source_id`。
- **三方 campaign**：本机没有官方 RFuzz 客户端（`kfuzz` 未构建）和固定 Verilator 5.020；已执行的是 `seeded-corpus-real-rtl`——真实构建、真实 RTL、真实覆盖、真实重放，但语料来自确定性种子调度而非变异器搜索。代码已增加 `official-rfuzz-corpus-replay-3arm`，它只消费一次官方单臂留下的 raw corpus，禁止把三次独立搜索冒充同输入对照；该模式目前只有契约级正/负例。

- **边沿与脉冲中断**：`soc_irq_edge_detect` 只做同域、已归一化输入的 rising/falling/both transition→单周期 pulse；它不是 CDC 同步器、毛刺滤波器或最小脉宽保证。pulse/edge source 必须在计划中设置相应 `LATCH_MASK`，控制器按“置位优先、仅 CLAIM 清除”保存事件；默认纯电平 source 仍按输入电平清除 pending。去掉 latch 的负例证明了连接策略错误会丢事件，因此不能把该路径写成“控制器自动兼容所有脉冲”。
- **CPU 入口拒绝**：当前只支持 `machine_external`。`machine_timer`、`machine_software`、supervisor/user external、NMI、debug、machine-local 以及任何 cross-domain source 都以稳定拒绝原因退出；不能把它们绑到 machine external 或随机端口来制造支持。
- **CVA6/OpenTitan**：CVA6 的 packed AXI4 结构体多角色绑定和 OpenTitan TL-UL `a_user/d_user/d_error` profile 事实已闭环，但 CVA6 64-bit 组合和 Ibex + OpenTitan 新路径仍是留出验证；结构诊断绕过不算生产能力。
- **peer raw ABI**：UART/SPI/GPIO 请求端口已进入 profile RFuzz 的 per-cycle raw layout、persistent testbench 和 corpus 事件重放。`soc_peer_oracle.v1` 检查事件传输与可观测 UART 计数；SPI 增加按角色绑定的四线监视与单字独立判据，以实际 CPU 总线写入及 peer arm 而非组件计数形成期望。已准入 SPI 模式的真实正例和 MOSI 注入错位分别通过/失败；缺规范、写入或完整轨迹时不评估。UART 接收/framing/timeout、GPIO 电气解析及 PULP GPIO 双向仍不在该结论内。

## 4. 从"通过"到"论文结论"还缺什么

按 1.10.3 的门槛，本轮结束时仍缺的、属于后续工作的：

1. **自然存在的组件内部缺陷与通用确认门槛**：人为注入的 SPI RTL MOSI 错位现由 `confirm_component_offline` 重跑基线/变异 SoC、变异 replay、两份结构审计与独立 APB 夹具，并绑定规范、源码差分及构建内容哈希；latch 接线错误保持组合缺陷。旧调用方自报映射入口不再确认，结果持久化后只可检查 `record-integrity-only`；旧记录和反序列化对象都不能代替实际重跑。该验证仍以受信任独立规范和夹具为前提，不等于发现自然存在的未知 bug，也不自动证明其他组件类别；后续工作是扩展规范与夹具覆盖。
2. **真实变异器搜索的对照**：需要在完整环境（`kfuzz` 可用）重跑三臂，报告有效率、唯一有效语料、DUT 覆盖与可重放异常，而不是种子语料。
3. **跨组件的"能运行"外推**：目前真实运行只覆盖有限的组件组合；把结论外推到"任意已支持协议的组件"需要更多独立设计的留出验证。
4. **profile 语义的独立依据**：软件、激励与检查器若由同一份 profile 生成，其一致结果不能证明 profile 正确；需要逐项对照规范或设计说明。
