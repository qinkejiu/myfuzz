# 自动组合设计验收记录

2026-09-22 阶段 0 二次复核：当前代码的相关纯测试为 `47 passed, 25 skipped`（真实 RTL 开关未启用），SPI 注入/多源 latch/SPI 线级真实套件为 `15 passed, 0 skipped`，独立代码复审通过。离线确认现要求重建完整计划、对比重建变异版与保存证据的完整 replay 字段，并检查声明 include 根目录在编译前后的可观测漂移。确认仍限于受信任规范/夹具下的受控 SPI 注入；不证明不可变编译快照或任意未知组件缺陷。下方较早的测试数字与工具缺失记载均为历史记录；阶段 4 的工具状态以其最新记录为准。

2026-09-22 阶段 2+3+4 复核验证：阶段 2 四个模块 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_peer_uart_oracle tests.integration.test_soc_peer_spi_modes tests.integration.test_soc_peer_gpio_contract tests.integration.test_soc_peer_replay_binding` 纯 197 通过 / 90 按依赖跳过，`MYFUZZ_SOC_REAL=1` 0 跳过通过；阶段 3 三个模块 `test_soc_irq_sample_matrix`(13) `test_soc_irq_trigger_negatives`(44) `test_soc_irq_evidence_package`(23) 全部真实通过；阶段 4 `MYFUZZ_SOC_REAL=1 tests.integration.test_soc_profile_rfuzz_campaign` 通过（197 秒，`status=completed_with_client_termination`、`evidence_missing=[]`、`corpus.status=verified` 3 条、`replay.status=passed`、`cleanup.status=clean`、4096 条 receipt、26422 次测试、13153 条覆盖记录、`source_transactions=26422`、`target_transactions>0`），`test_soc_official_corpus_replay`/`test_soc_campaign_arms`/`test_soc_campaign_comparison` 28 个真实用例通过。工具身份：官方 RFuzz 客户端 `kfuzz 0.1.0`（`runs/rfuzz_client_native_build/target/debug/kfuzz`，源码 <https://github.com/timothytrippel/rfuzz>）、bundled Verilator `Verilator 5.020 2024-01-01 rev UNKNOWN.REV (mod)`（`third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator`，由 <https://github.com/verilator/verilator> v5.020 源码构建）。阶段 0+1 的结论保持：30 纯 + 288 纯 / 66 跳过 + 全量真实套件 0 跳过通过。`git diff --check` 干净。
2026-09-22 阶段 0+1 复核验证：纯测试 `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_input_arms_projection tests.integration.test_soc_input_transport_ab tests.integration.test_soc_input_chain_report tests.integration.test_soc_input_real_rtl_gate tests.integration.test_soc_input_stale_identity_refusals tests.integration.test_soc_input_event_refusals tests.integration.test_soc_input_repair_runtime tests.integration.test_soc_dependency_replay tests.composition.test_soc_input_repair tests.composition.test_soc_image tests.integration.test_soc_campaign_arms tests.integration.test_soc_campaign_comparison` 共 288 个通过、66 个按依赖跳过；`MYFUZZ_SOC_REAL=1` 全量真实套件（同前八项）0 跳过通过；阶段 0 的 `test_soc_defect_confirmation` + `test_soc_offline_defect_confirmation` 30 个通过；`git diff --check` 干净。工具身份：Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67（`~/.local/bin/verilator`，sha256 `fb2cc573…fcdf`）、Icarus Verilog 14.0 devel f493076（`~/.local/bin/iverilog`，sha256 `9b3f0a69…be6a`）。bundled RFuzz Verilator 5.020 仍缺失，因此 `test_soc_profile_rfuzz_build`/`test_soc_campaign_arms` 的 profile-build 用例保持 skip，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。
2026-09-22 阶段 0 复核验证：`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_defect_confirmation tests.integration.test_soc_offline_defect_confirmation` 共 30 个通过、0 跳过、1.882 秒；`MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v tests.integration.test_soc_defect_injection_real tests.integration.test_soc_multi_latch_fault tests.integration.test_soc_spi_wire_oracle` 共 15 个通过、0 跳过（SPI 注入 2、多源 latch 5、线级判据 8，304.851 秒）；`git diff --check` 干净。工具身份：Verilator 5.051 devel rev vUNKNOWN-built20260806-e413e67（`~/.local/bin/verilator`，sha256 `fb2cc573…fcdf`）、Icarus Verilog 14.0 devel f493076（`~/.local/bin/iverilog`，sha256 `9b3f0a69…be6a`）。本次定向验证没有工具阻塞。bundled RFuzz Verilator 5.020 仍缺失，因此 `test_soc_profile_rfuzz_build` 的 17 个 profile-build 用例保持 skip，这些结果不构成官方 campaign 验收。保存结果的哈希仅验证记录完整性。

验收对象是“现有项目接入用户 RTL/profile 后生成 SoC”的生产路径，不是固定型号表的演示。以下状态以 2026-09-22 工作树和实际回归为准。

剩余实现任务按优先级、完成判据和验证入口记录在 [`soc-remaining-implementation-20260921.md`](soc-remaining-implementation-20260921.md)。本报告只记录当前证据，不把待办当作验收通过。

已通过的生成/结构门槛：

1. profile、request、端口 disposition、协议适配、地址 map、时钟复位和中断 source ID 都写入生成计划，并由实际 RTL 展开结果复核。
2. 生成 top 可重新展开；独立结构审计覆盖端口、结构体成员、复位、适配器参数、窗口、未接端口和 source wiring。APB3 窗口/`HAS_PSTRB`、CVA6 结构成员、CPU adapter 和中断连接的故障注入均能拒绝。
3. 跨域、未声明 CPU 入口、unsupported trigger、非法边沿参数、缺失 TL-UL 必要 sideband、重复/遗漏端口和不支持的 64-bit master 都以明确原因拒绝，不退回随机驱动或常量拼接。
4. 输入约束会在样本边界投影环境拥有的 special bits；有限 ISA/地址/权限/寄存器前置修复会记录修复、拒绝和预算，不修改已提交的 CPU 输出或 DUT 响应。
5. `soc_irq_controller` 默认保持旧的纯电平 pending；pulse 和 edge source 仅在声明时设置 `LATCH_MASK`，其语义为置位优先、仅 CLAIM 清除。edge converter、latch controller、触发拒绝和真实 Ibex lifecycle 均有证据。
6. profile artifact 返回前经过独立 `soc_structure_audit.v1`；缓存命中重新校验审计 hash。边界重放入口核对 identity、事件完整性和逐字段比较，拒绝 stale build。
7. 单指令/单数据候选可在 CPU 释放前装载 memory model；生成的软件/引导程序和 MMIO 错误行为已有定向测试，但不把这等同于完整软件或组件功能覆盖。
8. BFM isolated/contention 有独立生成和真实 RTL 证据；BFM 不进入 CPU 主模式，也未被伪装成 RFuzz 语料输入。
9. RFuzz 接入边界已实现并有契约回归：工具链在构建前 fail-closed，客户端/Verilator/环境身份进入构建和报告，官方 live runner 使用 resolver 选出的客户端和有效环境；已实现的 `replay_official_corpus_arms` 只接受带 receipt、verified manifest 的官方 raw corpus，并对三 projector 共享身份做严格检查。

尚未通过或明确不声称的项目：

- 官方 `kfuzz` 客户端和 bundled Verilator 5.020 尚未在本机准备好，因此尚无真实持续 RFuzz 变异/客户端传输证据；实现已经具备单臂 production wiring 和“官方 raw corpus + 三臂重放”入口，目前只有 seeded-corpus-real-rtl 对照和契约级 official-replay 测试。
- UART/SPI/GPIO peer 已接入新 profile 生成顶层、per-cycle raw layout、persistent testbench 和事件重放。`soc_peer_oracle.v1` 除事件与 UART 发送计数外，现可在外部提供独立 TXDATA 规范时按角色绑定观测 SPI SCK/CS/MOSI/MISO，并将实际 CPU 写数据、peer arm 字节与四线时序作独立比较；真实 Ibex+SPI+GPIO 正例和注入错误分别得到 pass/mismatch。UART 接收/framing/timeout、GPIO 电气解析仍为 `not_assessed`。Ibex+双 GPIO、UART+GPIO、SPI+GPIO 已有单样本多源闭环；双源 edge+level 的 latch 位删除注入可重放并归为组合缺陷。持续多源 campaign、其他 trigger 组合、PULP GPIO 电气双向仍未完成。
- CVA6 profile/结构体审计完成，但生产组合明确拒绝 64-bit AXI4 master；OpenTitan TL-UL profile/成员绑定完成，Ibex + OpenTitan 新组合留作下一轮留出验证。
- CDC、DMA、多核、复杂时钟切换、多 outstanding/乱序/burst 完整语义和完整软件行为不在首期验收。
- 一个**人为注入的** SPI 组件 RTL 行为缺陷由离线入口重新执行基线/变异 SoC、变异 replay、两份结构审计与 APB 隔离复现，绑定独立规范、源码差分和构建内容哈希后支持该样例的组件内部归因；latch 接线错误保持组合缺陷分类。旧自报映射入口保持候选，不能输出确认。持久化结果仅提供 `record-integrity-only` 校验；记录哈希及反序列化对象不替代实际重跑。该结论依赖受信任的独立规范和夹具，未发现或确认自然存在的未知组件 bug。
- 软件的 `all_sources_closed` 只计完成次数：源 ID 置换后同周期输入仍可能报 1。错开事件的负例与独立结构审计会拒绝该接线；确认门槛不能只使用这个软件标志，还要求结构审计结果和顶层哈希绑定。

本轮定向回归命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_rfuzz_live \
  tests.integration.test_soc_rfuzz_live \
  tests.integration.test_soc_rfuzz_toolchain \
  tests.integration.test_soc_profile_rfuzz_build \
  tests.integration.test_soc_campaign_arms \
  tests.integration.test_soc_campaign_comparison \
  tests.integration.test_soc_campaign_matrix \
  tests.integration.test_soc_official_corpus_replay \
  tests.integration.test_soc_profile_rfuzz_campaign
```

结果：本轮该定向集合共 104 个用例通过、22 个环境条件跳过（本机缺少固定 RFuzz Verilator/client；未设置 `MYFUZZ_SOC_REAL=1` 的真实验收也只跳过）。显式运行 `MYFUZZ_SOC_REAL=1` 的 profile campaign 会失败并保留“缺少 bundled RFuzz Verilator 5.020、kfuzz”的证据，不会伪造通过。随后执行的全量 `unittest discover` 共 2641 个用例，155 个环境条件跳过，剩余 2 个失败和 10 个错误均落在既有静态 RFuzz/工具链用例，原因是同一个 bundled Verilator 5.020 缺失；没有新的 profile RFuzz 路径失败。当前结果仍不能外推为真实 RFuzz campaign 已完成。
