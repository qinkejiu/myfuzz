# P2 路径身份与静态契约基础接口进度

日期：2026-10-06。P2 **部分完成**。基础接口及新 decoder、RFuzz 接纳、会话身份和 replay 接入已落地；接续审查发现的启动前源归属、异常分类和 replay-only 搜索限制已修复并独立复核。固定 GPIO/UART 的当前源码运行与完整前缀 replay 已通过；逐边真实来源及 P2 完整门禁尚未齐备。

## 已实现

- DependencyEdge 保存构造时全局 rule/prerequisite index；edge_paths_to 保留同源 OR 路径、AND 全部边和共享子图，单路径采用一致 OR proof-DAG。path_identity 防止未知/缺失/断开边、错误来源/方向和选中循环，绑定完整 graph 与目标。旧 paths_to 保持 decoder v1/v2 的 source-set 映射。
- 新图文档 dependency_edge_graph.v1 保存全局规则顺序，严格往返；online instruction source 必须显式使用其类型，不能当作初始 memory_image。枚举有深度、数量和工作预算，上界耗尽明确拒绝；初始化索引一次遍历，不能每例重编译这些材料。
- RuntimePathContract 明确 node/component/physical endpoint/位段及 edge relation。编译只检查所选路径，不从 online.* 等逻辑名称猜接线。direct 按完整端点/位段匹配，核对唯一性、ownership 和重叠驱动；MMIO 核对 aperture、唯一 window 和实际注册 session 对象；persistent 只允许实际 RAM 资源，核对真实 lookup 映射。
- compiled.validate_topology 保存轻量拓扑并检测相关 session、Binding、ownership、Router/window 及 RAM 映射变化；不执行 factory/begin/step/checker、源码扫描、工具链查询或图重编译。检查成本按声明拓扑大小计，不声称 O(1)。
- record_scenario/_record_with_runner/replay_scenario 新增可选 runner_preflight，在既有 factory 创建的单个真实 Runner 上、源码身份扫描与 begin 前执行。错误 callback 在 factory 前拒绝；通过时不增加既有 identity scan。新版 RFuzz 契约模式已显式接入，legacy 明确标为 legacy_unchecked。
- Genome decoder v3、online decoder v2 保存有序图、RuntimePathContract 和 path_mapping；路径与变异授权初始化缓存。新 schema 严格往返，旧 corpus 保留旧映射，重建文档只允许 replay。
- PreparedRuntimePathContract 在 fresh 的实际 Runner 上绑定选中路径；长会话预先配置并在每次输入前检查。身份保存声明及实际 compiled topology，replay 对保存材料和新 Runner 重新核对。PULP 两方向与 UART 已有显式真实端点、MMIO window 和配置先于 begin/warmup 的接入。

## 验证

三个新模块：

```bash
PYTHONPATH=src:. python3 -m unittest tests.scenario.test_dependency_edge_paths tests.scenario.test_runtime_path_contract tests.scenario.test_replay_preflight -q
```

root结果：34 项通过，无跳过。分别13项edge、17项contract、4项hook。新API先RED缺接口，再GREEN；独立review发现的disjoint Binding误拒绝、RAM实际lookup漂移漏检、MMIO/causal physical input越界漏检均新增负例并修复。legacy同源映射、decoder和mutation回归通过。

root整合命令为[P1报告](current-dataflow-p1-cli-identity-20261006.md)列出的219项焦点命令，再加入上述三个新模块及 tests.scenario.test_replay、tests.scenario.test_dependency_mutation、tests.scenario.test_rfuzz_genome_decoder。实际返回0，`Ran 275 tests in 6.204s ... OK (skipped=5)`；5个真实环境门禁保持跳过。独立review三模块31项通过早于最终增加3项contract检查，不把它计为最终34项。

Task1/Task2软件检查不包含新的真实RTL运行。P1收尾时真实GPIO预算化evidence及UART完整前缀replay按当时固定源身份保存；本轮P2修改dependency/replay身份闭包后，旧材料保持历史证据，不能当作当前P2真实路径验证。

## 仍需实施和验收

1. 新 decoder 已有版本化 edge-aware 路径、契约和初始化缓存；接续独立审查已复跑既有 98 项执行/身份检查及 60 项契约/fixture 检查。修复后的 root 整合回归为 317 项，5 项环境跳过、零失败。
2. fresh/live/continuous/online 已显式接入所选路径预检。非 replay 会话存在外部源时，配置必须传可信 ownership；启动前对照 decoder 的 producer_ref，begin 再核冻结拓扑；general continuous 构造也对照所有缓存源，文档重建的 online decoder 禁止用于搜索。
3. graph/contract/path/topology 已进入运行身份和 replay。在线命令已发出后的 uncertain_effect 分类已保留；typed 协议环境错误仍为 environment_error。四项修复均有失败测试和通过证据，独立 review 的 spec/quality 均通过。
4. 真实PULP正反路径逐边记录producer/delivery/consumer、origin case/source、transaction及资源版本；断A→B或IRQ得到启动前定位，提前IRQ保持可见。
5. 当前 GPIO 双源与 UART 异构入口的完整前缀 record/replay 已重新归档；Task4 仍须补逐边原始来源、资源版本、跨例消费及提前 IRQ 的完整验收，静态连接配置不替代这些证据。

源码/接口细节见[边身份报告](../../.superpowers/sdd/current-dataflow-p2-edge-path-report.md)、[契约报告](../../.superpowers/sdd/current-dataflow-p2-runtime-contract-report.md)和[专题计划](../superpowers/plans/2026-10-06-runtime-path-contract-implementation.md)。资源版本与运行时因果仍明确为未证明；本阶段未暂存或提交。

## Task3 接续验收（当前源码）

完整命令及 root 工具结果转录见[整合记录](../../.superpowers/sdd/current-dataflow-p2-root-regression-resume.txt)。软件整合命令在 P1 的 219 项焦点命令基础上，加入基础接口及 replay/dependency/Genome 模块，再加入 tests.scenario.test_edge_aware_decoders、test_prepared_runtime_paths、test_session_runtime_paths 和 tests.integration.test_rfuzz_runtime_path_preflight、test_runtime_fixture_contracts。实际退出0：317项 /25.649秒 /OK(skipped=5)，跳过不计真实RTL证据。独立修复review定向38项 /19.312秒 /OK，零跳过；executor实现者最终120项 /18.386秒 /OK。root另执行持久内存/状态依赖/事件journal子集39项全过；第一次误引用尚未创建的 test_interaction_feedback/test_state_dependency 产生2个loader error，改用现有模块后通过，未当作产品故障或通过证据。

实际 Rust 运输检查命令：

```bash
MYFUZZ_SCENARIO_RFUZZ_LIVE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_campaign_run_identity tests.integration.test_scenario_rfuzz_live_client -q
```

退出0，16项 /1.578秒 /OK，零跳过。

当前版 GPIO 真实命令：

```bash
python3 scripts/run_ibex_pulp_online.py run --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --cache-dir /tmp/myfuzz-online-cache-20261006 --output runs/current-dataflow-p2-contract-20261006-resume-pulp --seconds 15 --max-tests 120 --seed 20261006 --run-id current-dataflow-p2-contract-20261006-resume-pulp
python3 scripts/run_ibex_pulp_online.py replay --cache-dir /tmp/myfuzz-online-cache-20261006 --plan runs/current-dataflow-p2-contract-20261006-resume-pulp/online_plan.json --trace runs/current-dataflow-p2-contract-20261006-resume-pulp/online_final_trace.json
```

run/replay均退出0，完整前缀matches=true。120 receipt全部complete，CPU指令源16、GPIO B pin8源104，固定seed20261006；搜索8.023752秒先达到case预算，**不是10分钟效率门禁**。56,224事件，真实Binding交付8,274次、MMIO接纳/交付各168次；52个cpu_irq_taken事件来自真实irq_taken_pre观察。CPU/GPIO A/GPIO B local ticks分别3893/4137/4321。run identity为60aa6b58546dcd2345154553598042859de5b276908bd550fe07791da44523af；decoder/graph/contract/compiled topology和完整前缀存于上述runs目录。4个CPU receipt的applied_source_ids为空，不能把所有complete slot都视为有效传播。

对该完整 trace 重新计算交互反馈，irq_sample_read_then_write、irq_taken_read_then_write、write_bound_then_read 各52；closed_loops=0，这些有序见证计数不冒充完整闭环覆盖。静态编译文档仍明确 runtime_causality_verified=false。真实taken计数不能单独证明每条图边的origin source/case、资源版本和完整闭环；Task4仍缺这些贯通与负例，P2保持部分完成。自然finding与受控错误校准、首版10分钟门禁、P3～P8不得用本次短跑替代。全部工作未暂存或提交。

当前版 UART 入口命令（顺序运行，不与 GPIO 并发）：

```bash
python3 scripts/run_ibex_uart_online.py run --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --cache-dir /tmp/myfuzz-ibex-uart-online-cache --output runs/current-dataflow-p2-contract-20261006-resume-uart --seconds 8 --max-tests 2 --seed 123 --run-id current-dataflow-p2-contract-20261006-resume-uart
python3 scripts/run_ibex_uart_online.py replay --cache-dir /tmp/myfuzz-ibex-uart-online-cache --plan runs/current-dataflow-p2-contract-20261006-resume-uart/online_plan.json --trace runs/current-dataflow-p2-contract-20261006-resume-uart/online_final_trace.json
```

run/replay均退出0，matches=true。CPU指令源1例、UART RX源1例，全部complete，搜索1.132028秒即达到例数预算。完整plan另保留固定warmup RX 0x5a，随后在线RX 0x4e，两次注入均在真实trace中。15,358事件，6次MMIO接纳/交付、CPU/UART ticks 832/2592。identity为d2ee02e2355cb4448ad56e0baa87b8d81d32032cec8b81fabc5e0f3f55951af2。此次未观察IRQ taken，不声明RX→IRQ→ISR完整闭环。两个bundle的artifact摘要、envelope身份、receipt path/session和runtime材料独立核验均通过。两个runs目录保存gate_commands.json及run/replay日志和退出码。

真实工厂的五项启动前负例分别切断A→B、切断IRQ、改MMIO base、改target session、改source producer。实际Runner/session对象经真实builder预检全部拒绝，begin/step/identity调用均为0，实际RTL进程均未启动；这是静态拒绝边界，不是执行错误拓扑的RTL campaign。详细摘要与负例见[当前RTL门禁记录](../../.superpowers/sdd/current-dataflow-p2-real-gate-resume.md)，逐边缺口及接续接口见[独立审查](../../.superpowers/sdd/current-dataflow-p2-fixture-audit-resume.md)。

## 后续Task4来源版本

本文上述Task3的源身份及短跑保留为当时材料。后续source/admission/typed writer/journal/feedback修改及修复后当前源门禁见[来源实施与验收](current-dataflow-p2-source-provenance-20261006.md)；不要将本文60aa6b/d2ee02旧bundle与后续新closure互认。Task4完整退休/MMIO/FIFO因果仍缺，不据来源基础设施标P2完成。
