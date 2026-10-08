# 多组件持续场景模糊测试实施与验收计划

> 历史实施基线：本文件保留 2026-09-27 的详细 RUN/RST/IRQ/REP/FUZ/G0～G4 门禁和当时进度。其中 Runner 属于单个 testcase、下一例重新建立状态的旧生命周期不再适用。当前要求是一个长期会话连续接纳多个 testcase，共享真实 RTL/RAM/待处理事件并逐例反馈；数据流目标可跨例继续。当前跨 OpenTitan/PULP/ZipCPU、生成式独立 harness、变异与路径绑定工作，以 [2026-10-06 当前实施计划](2026-10-06-current-dataflow-fuzz-implementation-plan.md) 为唯一总进度；具体能力查 [运行能力表](../../LOCAL_HARNESS_RUNTIME.md)。

> 下列复选框是完整目标的验收门槛；已完成的局部里程碑以“当前实测边界”和具体测试记录为准。未完成的复选框不能用局部通过代替。

**Goal:** 在现有 myfuzz 基础上建立多个独立真实 RTL harness 的连续 testcase，保持内存、事务、事件和长期依赖，并以 source/path-aware mutation 与完整 replay 验收。

**Architecture:** 新增 scenario 路径复用接口描述、源身份、部分局部协议适配、插装和 RFuzz 运输。ScenarioRunner 拥有一次 testcase 的持久上下文；Memory Service 以逐字节版本提供权威环境状态，Router 与 Scheduler 在线传播真实输出。旧单目标和 SoC 生成路径保留为独立兼容流程，不将其历史结果外推为新机制完成。

**Tech Stack:** Python 3、现有 unittest、SystemVerilog 独立 harness、项目固定 Verilator 工具链、项目内 RFuzz Rust 客户端及 FIFO/shared-memory 协议、JSON/JSONL 证据。

版本：2.1｜日期：2026-09-27｜状态：实施中；持续 Genome、Ibex/OpenTitan GPIO 双向因果场景、三实例完整事件 replay 与本地参考反馈循环已有定向实测。RFuzz 定宽 record→完整 Genome 解码、SysV/FIFO、host target/source energy 提示与 Rust 客户端→真实 Ibex＋双 GPIO 短跑及保存 corpus 全量重放已通过；长跑与完整验收矩阵仍未完成。逐项状态见 `docs/reports/persistent-scenario-acceptance-20260927.md`。

配套目标规格：`docs/superpowers/specs/2026-09-27-persistent-multicomponent-fuzz-design.md`。

### 当前实测边界（2026-09-27）

| 对象 | 已实测 | 不能据此声称 |
|---|---|---|
| 新 scenario 基础 | 本轮 `tests/scenario/` 59/59 通过，覆盖显式 warm/cold reset、Genome v3 reset/quiesce、首次未知字节物化事件、重放 manifest 预检、GPIO 输出检查器校准。真实 RTL 合并回归 27/27 通过；真实 Ibex＋GPIO reset/quiesce 与含 reset 的重新执行 replay 已验收为局部里程碑。Rust 离线单测通过，轻量与真实 RTL RFuzz 客户端短跑及 corpus 回放通过 | 完整 RUN/RST/IRQ/REP/FUZ 逐项注入、证据包、资源上限和长跑门禁未完成 |
| OpenTitan GPIO 独立 harness | 两个真实 RTL 进程在同一 testcase 内连续运行；A 真实输出绑定 B 输入，B 真实产生 IRQ，状态和寄存器读值持续 | 完整 CPU＋双 GPIO 多轮 genome 场景尚未验收 |
| Ibex 独立 harness | 真实 OBI 请求接持久 RAM 和独立 OpenTitan GPIO；CPU 程序镜像属于 Genome。CPU→GPIO A→GPIO B→CPU 与 GPIO B 外部输入→CPU→GPIO A 均在三实例持续场景中完成至少两轮真实交互；CPU 程序和第二次 GPIO 环境事件的上游变异均改变真实下游结果；两个三实例方向均可从新 RTL 重放一致 | 尚未完成两方向各两份成功 genome 的完整门禁和独立 checker；当前定向变异不等于发现 DUT bug |
| CVA6 独立 harness | 固定源码闭包独立编译；真实 AXI 适配器请求接持久 RAM，64 位 beat 按地址/byte-enable 映射到独立 OpenTitan GPIO 的 32 位寄存器；定向读写通过 | 尚未完成 CVA6 的 IRQ、两方向多轮程序和统一 Scheduler |
| RFuzz 新模式 | 八字节 record 被解码为 template/direction/path/source/bit/action/delay 决策；同一 RFuzz test 的全部 record 生成一个持续 Genome，真实 Ibex＋双 GPIO 定向测试命中新下游 coverage；SysV 帧往返、Rust 离线构建、轻量 harness FIFO 短跑及 Rust 客户端直接驱动真实 Ibex＋双 GPIO 的短跑通过（至少两条不同原始输入，无环境错误）；host 根据未覆盖目标选择模板/路径/上游源并分配 64/8 mutation energy，Rust scenario mutator 消费原子更新且带 run_id 的提示；checker 违例单独保存完整 Genome/轨迹；轻量和真实 RTL 短跑的 Rust 保存 corpus 均能从 manifest 重建并重放匹配语义轨迹摘要，篡改输入可被拒绝 | 尚未完成多固定 seed 长跑、完整 DUT checker、性能对照与所有错误恢复门禁，不声称完整 T10 |
| Ibex、CVA6 | 旧 OpenTitan SoC 诊断路径的 `cpu_only` 与 GPIO directed 运行均有 `status=ok`，观察文件位于 `runs/open-titan-three-cpu/` | 旧路径有生成的 fabric，不能代替新独立 harness 的跨组件验收 |
| BOOM | 本地仅有 Scala/reference 源，缺生成 Chipyard RTL/filelist 且缺构建工具；按用户要求跳过本地执行 | 不能记为通过或将参考源码当作可运行 RTL |

前序执行证据：真实 RTL 套件（`tests.integration.test_scenario_cva6_local_cpu`、`test_scenario_gpio_live_session`、`test_scenario_ibex_opentitan_cpu`、`test_scenario_opentitan_gpio_session`、`test_scenario_runner_ibex_gpio`、`test_scenario_genome_ibex_irq`、`test_scenario_real_replay`、`test_scenario_three_component_genome`、`test_scenario_ip_cpu_ip_genome`）合并执行通过 18/18（约 60 秒）。

续实施证据：`tests/scenario/` 增至 45/45；原有 RFuzz wire/shmem 加新 SysV scenario 运输测试 9/9；`cargo test --offline -q` 通过新 Rust mutator 单测，`cargo build --offline --release -q` 通过；`tests.integration.test_scenario_rfuzz_real` 的新真实 RTL record 输入测试通过；`MYFUZZ_SCENARIO_RFUZZ_LIVE=1 PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_rfuzz_live_client -v` 通过 Rust 客户端与轻量 harness 的 1 秒短跑及完整 corpus 重放；`MYFUZZ_SCENARIO_RFUZZ_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_rfuzz_real_client.ScenarioRfuzzRealClientTests.test_rust_rfuzz_drives_ibex_and_two_gpio_processes -v` 通过 Rust→真实 RTL 的短跑及该次完整 corpus 重放。旧 18 个真实 RTL 套件在前序轮次通过，续实施没有更改旧场景执行模块。

下一关键路径：完成 E2E 切边/固定下游/提前 IRQ、扩展独立 checker 与故障注入 → 完整证据包、资源上限和故障恢复 → 多固定 seed 长跑、对照和完整 G0～G4 门禁。两方向各两份固定 genome 已留存，仍须进入正式门禁。当前 RFuzz record 解码、运输、mutation sideband、真实 RTL 短跑与保存 corpus 的全量重放已接通，但尚未完成 T10 全部门禁。

本轮显式 reset 实现边界：`ScenarioGenome` v2 的规范化编码保持原有字节格式；v3 增加 `reset_actions`，每个 reset 只支持 `warm_all` 或 `cold_all`，可由 `START` 或真实 `AFTER_OUTPUT` 触发并按一个组件的局部 tick 延迟。Scheduler 先执行到期的 reset，再注入同一调度点的源动作。Runner 对全部独立 harness 形成 reset barrier，清空待驱动输入；warm 保留 RAM generation 与字节，cold 建立新 generation 并记录旧版本的 `INVALIDATE` 边。CPU 未交付响应被取消，但先前真实提交的写入不回滚；事务键通过 CPU reset_epoch 避免与旧请求碰撞。当前仅通过语法编译，以上行为尚未列入实测通过清单。

本轮 quiesce 实现边界：v3 `quiesce_steps` 为显式局部步进预算；值为 0 时不进入收束。进入收束后 Runner 拒绝新 Fuzzable Source 注入，Ibex/CVA6 端口不再 grant 新请求，但可以交付已经保存的响应。仅对有 pending 响应的组件继续局部 step；到预算仍有 pending 报 `incomplete`，事务账本存在未确认效果报 `uncertain_effect`。quiesce 起止、失败以及启动/重置/执行异常写入事件轨迹。当前这只覆盖本地 CPU 响应的排空；对未来异步 UART/SPI 设备事件和全量故障注入还没有行为验收，不应称为完整 RUN-04。

续实施验证：`PYTHONPATH=src python3 -m unittest discover -s tests/scenario -p 'test_*.py' -q` → 59/59；`MYFUZZ_SCENARIO_REAL=1` 下合并运行 Ibex、CVA6、GPIO、双向 Genome、完整 replay、reset/quiesce、独立 GPIO checker 和 RFuzz record 真实输入模块 → 27/27；`MYFUZZ_SCENARIO_RFUZZ_LIVE=1` 与 `MYFUZZ_SCENARIO_RFUZZ_REAL=1` 两种 Rust 客户端短跑与保存 corpus 回放各通过；`cargo test --offline -q` 通过。新 trace 保存 ownership/router/memory/source/toolchain manifest hash；RFuzz receipts 也保存并在 corpus replay 核对。首次未知内存读逐字节记录物化值和 writer；GPIO checker 对完整 DIRECT_OUT 写后的真实输出做独立校准。以上仅证明对应局部能力，不替代报告中未完成的验收 ID。

TX-05 进程层续实施：三个真实 local RTL 进程现在接受 `CMD execution_token sequence payload`，返回带相同 sequence 的完整观察结果，并缓存已完成命令。相同身份/载荷重发返回原回复且不增加 GPIO/CPU 局部 tick；同 ID 改载荷、乱序命令和旧 execution token 被拒绝。GPIO 状态性 MMIO 写也在重复命令校准中执行。Python Ibex/CVA6/GPIO 会话每次进程启动产生新 token，reset 后命令序号从 1 重新开始，校验回复序号与 CPU wire tick。`tests.integration.test_scenario_command_replay_real` 三个真实进程校准 3/3；受影响真实 RTL 合并回归 30/30。

TX-05 Runner 续实施：`ScenarioRunner.execute_step` 使用 `(execution_id, reset_epoch, command_sequence)` 和当前输入快照缓存完整 step receipt；`DependencyScheduler` 的普通 `runner.step` 也调用同一接口。重复运输不会再次推进 RTL 或重新执行 MMIO/内存提交；同 ID 异载荷、乱序和旧 execution 被拒绝。失败后效果不确定的命令保留占位，重发报告 `uncertain_effect`。`runner.events` 返回独立快照，调用方不能修改权威轨迹。新增 `test_step_command_receipt` 5/5，软件场景 64/64；真实 RTL 合并回归 30/30，事件快照改动后的真实 replay 定向回归 2/2。进程崩溃时的实际握手边界、资源有界日志和迟到回复故障注入仍需单列验收，不能据此将 TX-05/RUN-04 全部记为通过。

RST-05 续实施：本地 step 已发出后如失去完整回复，Runner 保留失败前可确认的服务事件和局部 tick，记录 `harness_failure`、`uncertain_transactions` 并把场景标为 `uncertain_effect`；返回的输出在主机绑定/路由阶段失败时也按同一原则记录，不把已推进 RTL 的情况误报为普通环境错误。Scheduler 结束该 testcase，`record_scenario` 和 RFuzz receipt 保留部分轨迹及语义哈希，RFuzz 将不确定轨迹单独落盘并跳过针对未完成执行的 DUT checker。新的初态 replay 可重现这一状态；同一步命令重传仍禁止再次执行。内存服务在事务账本接收前预检访问合法性和初始化容量，明确的无副作用拒绝不再污染未决账本。软件场景 68/68、真实 RTL 定向回归 12/12；提取失败前服务事件后真实 replay/reset 追加定向回归 4/4。真实 OpenTitan GPIO 故障钩子在 RTL 写事务完成后、C++ 命令回执前直接终止进程；GPIO 进程级试验 4/4，整段 ScenarioRunner 故障分类/初态 replay 1/1；合并真实 RTL 回归 32/32。Ibex/CVA6 增加真实 tick 后、回执前退出的进程级注入，命令级合并用例 6/6；Ibex＋GPIO 完整场景分类和初态 replay 1/1。迟到回复隔离和故障覆盖矩阵仍需单列验收，不能据此将 RST-05/TX-05 全部记为通过。

## Global Constraints

- 一个 testcase 连续运行；step、chunk、事务完成和 ISR 返回不隐含 reset。
- 不生成完整 SoC，不实现 Bus/Crossbar/Bridge/Arbiter/PLIC 或全局 cycle-accurate 调度。
- 保持 Fuzzable Source / Bound Input、Dependency Path、Dataflow Router、Dependency Scheduler 与独立 harness 边界。
- Bound Input、真实 DUT 输出、已提交内存和已冻结响应不得由变异器覆盖。
- 内存键为 memory_id/generation/byte_offset；组件 reset_epoch 独立。
- RAM 首次读只初始化缺失字节；MMIO 绝不使用随机初始化兜底。
- 内存读在 MEMORY_SERVICE_COMMIT 冻结快照；CPU 交付阶段不重新取当前值。
- 去重按完整事务身份和载荷 digest；未知副作用不自动重试、不回滚。
- 首版全场景 warm/cold reset 可执行；组件局部 reset 明确拒绝，列为扩展验收。
- 未标明“已执行”的入口、命令与测试仍为未来交付物；验收状态以实际运行证据为准。
- 外设候选仅来自 OpenTitan 系列；每个候选须有固定源码身份、可运行 RTL、合法本地接口驱动及真实输出证据。Ibex/CVA6 本地可在旧 OpenTitan 诊断路径执行；BOOM 缺生成 RTL 时按“本地不可执行”记录并跳过，不能据此声称新场景 CPU 链通过。
- 构建默认单 worker，固定源码/工具身份，无默认波形；测试开启时按声明预算记录实际资源。
- 现有工作区有未提交改动，实施前记录 diff 身份；只修改本任务文件，不覆盖其他工作，不执行批量清理。

## 1. 当前系统实际状态与差距

### 1.1 生命周期已经具备的基础

当前系统并非每周期 reset。`src/myfuzz/integration/rfuzz_simulator.py` 的 `_bench` 在一份请求开始时 reset，随后循环执行 count 个周期；`RtlSimulator.run_test` 的 isolate_tests 只在不同 test 之间重启进程。差距是多实例在线协作、显式 session API、跨 step 状态和长期事件关系。

| 文件 / 位置 | 已核实事实 | 迁移决定 |
|---|---|---|
| integration/rfuzz_simulator.py:416、823 | 每 test 一次开始/reset，test 内连续 tick；输入整体投影并一次发送 | 新建会话式 executor；不得反复调用 run_test 模拟同一 testcase 的 chunks |
| integration/soc_builder.py:1163、2690 | projector 执行前物化整份输入；bench 连续执行 | 保留编译和身份方法；不把预投影当在线 Router |
| integration/soc_builder.py:2751 | checker sticky failure 后可能停止 tick，但继续消费 records | record_count 与 actual_cycles 分开报告 |
| composition/coherent_memory.py:17 | 缺失字节初始化、逐 byte-enable 写、test reset 清空 | 复用字节算法，增加 generation/version/writer/提交与快照 |
| composition/contract_transducer.py:445、472 | begin_test 清 memory；reset_dut 保留 memory、清协议状态 | 借鉴生命周期分离，不能直接充当新 RuntimeState |
| composition/contract_transducer.py:496 | 响应路径读写 memory；部分模式锁初始化 entropy | 新服务统一定义提交点与读快照，不声称旧模式都接受时取值 |
| composition/transducer_rtl.py:467、485 | test_begin 清 store，DUT reset 清 pending | 保留旧语义；新模式单独声明资源 policy |
| integration/rtl/riscv_boot_memory.sv:50、64 | reset 重新装载初值；请求握手即抓读值/写数据 | 与前一模型 reset/commit 不同，禁止全局替换假设 |
| composition/soc_runtime.py:1576、1884 | 每 sample 新进程，sample 内连续执行 | 可参考采集方式，不能直接复用为多实例 session |

### 1.2 变异与反馈的实际差距

RFuzz `queue.rs:98` 轮转选种子；`mutation/mod.rs:51` 执行 deterministic/havoc；host 的 TOML 只暴露 raw_bits。没有按 direction/path/source 分配操作子和 energy。`analysis.rs:79` 主要返回覆盖新颖性与 invalid 分类。

`rfuzz_live.py:505` 把 checker_fail 标成 fail；客户端会据此标为 invalid。新模式必须将合法输入触发的 DUT 违例保存为有效失败样本，不能靠 invalid 过滤。

`dependency/dynamic.py` 是静态依赖组缩减；`harness/depaware.py` 是 raw 输入投影；它们不是新方案所需的事件/持久状态引擎。

`soc_candidate_program.py:1423` 包含静态 MMIO 写后读值推导；不得成为真实 IP 响应来源。当前 GPIO profile 的 IRQ 仅 observe，GPIO oracle 的 IRQ 寄存器尚未评估；新场景需补足对应事实和判据。

### 1.3 旧代码处理原则

不整体重写旧项目。不全局更改旧 reset 行为来迁就新方案。新建 scenario 模式，抽取与单 top 无关的进程/身份/传输接口；只在必要接口处修改旧文件。首次读字节派生算法与旧 initializer API 可以不同，但版本必须分开并有回归保护。

## 2. 文件与接口蓝图

下列 create 路径均为计划新增，当前不存在不代表实施错误。modify 路径需先确认实际工作区差异。

### 2.1 新增模块

| 路径（src/myfuzz/ 下） | 单一职责 | 主要交付接口 |
|---|---|---|
| scenario/contracts.py | 生命周期、事件、身份与结果契约 | ScenarioManifest、Action、ResetAction、RunResult |
| scenario/ownership.py | source/binding 位区段校验 | compile_ownership |
| scenario/state.py | 一次 testcase 的上下文 | PersistentRuntimeState |
| scenario/memory.py | 稀疏字节、一次初始化、版本 | PersistentMemory |
| scenario/memory_service.py | 真实请求到一次提交/快照 | MemoryService.commit |
| scenario/ledger.py | 事务状态与运输去重 | TransactionLedger.accept/transition |
| scenario/session.py | 独立 RTL 会话协议 | LocalHarnessSession |
| scenario/harness_builder.py | 独立 CPU/GPIO harness 构建 | build_local_harness |
| scenario/router.py | 真实来源到目标交付 | DataflowRouter.route |
| scenario/scheduler.py | 局部步进与稳定动作调度 | DependencyScheduler.next_step |
| scenario/runner.py | testcase 生命周期与资源处理 | ScenarioRunner |
| scenario/dependency.py | 规则图、事件图、版本依赖 | DependencyGraph.record |
| scenario/genome.py | 连续场景 codec 与分块验证 | GenomeCodec、ChunkAssembler |
| scenario/mutation.py | typed source mutator 参考实现 | MutationPlan、mutate_genome |
| scenario/path_planner.py | direction 与 AND/OR 求源 | plan_mutation_sources |
| scenario/feedback.py | 覆盖、路径、持久状态反馈 | ScenarioFeedback |
| scenario/evidence.py | 日志、身份、摘要和物化材料 | EvidenceWriter |
| scenario/replay.py | 全轨迹复现和首个差异 | replay_scenario |
| integration/scenario_campaign.py | RFuzz 与新 executor 接入 | run_scenario_campaign |

### 2.2 协议与数据契约

`ScenarioManifest` 固定源码/工具/profile/binding/调度/reset/初始化算法身份、地址映射、内存上限和 testcase 预算。`Action` 字段与目标规格第 10 节一致；`ResetAction` 包含 action_id、policy_id、scope、触发条件和保持/释放周期。

`ReadSnapshot` 固定 transaction_id、commit_event、memory_id/generation、addresses、bytes、versions、writers。`CommitResult` 包含 snapshot 或 write receipt、错误、是否有状态效果及版本。`Observation` 包含实例、epoch、局部 tick、事件类型、原始 payload 与来源。

`RunResult` 包含 status、input_legality、dut_violations、environment_errors、uncertain_effects、各实例周期、reset 次数、pending 总账、coverage、因果链、最终资源摘要及证据路径。状态不得合并成单一 pass/fail。

### 2.3 Local Harness API

建议会话命令：`BEGIN_CASE`、`APPLY_ACTION`、`STEP_LOCAL`、`RESET_BARRIER`、`READ_COVERAGE`、`END_CASE`。每命令和回复带 protocol_version、execution_id、testcase_id、command_sequence 和 digest；缓存按 execution 隔离。同键同内容重发返回原命令的完整 Observation/receipt，不重复推进周期；不能仅回一个 ACK 而丢失首轮捕获的 IRQ 或握手。旧 execution 的迟到回复不得匹配新执行。

BEGIN_CASE 只在 testcase 初始执行一次；STEP_LOCAL 推进现有 RTL，默认一步一个完整局部周期；APPLY_ACTION 只在声明驱动边界改变输入；END_CASE 返回最后状态与关闭结果。旧 RFUZZ 请求头协议继续用于旧 executor，不能把每个 STEP 编成一次旧 run_test。

## 3. 实施顺序与里程碑

```text
T0 契约与基线
  ├→ T1 持久内存 → T2 事务服务
  ├→ T3 独立Harness会话
  └→ T7 Genome基础
T1+T2+T3 → T4 Runner与reset
T4 → T5 Router/Scheduler → T6 持久依赖
T5+T6+T7 → T8 双GPIO连续RTL场景
T0起持续记录证据；T4+T7 → T9a 软件与单session Replay
T5+T6+T7+T9a → T8 → T9b 多实例完整Replay
T7+T8+T9b → T10 RFuzz搜索接入
全部阶段 → T11 对照、回归与最终证据
```

每任务按“增加有判别力的失败用例 → 实现最小职责 → 定向验证 → 检查契约与证据 → 独立提交”的顺序执行。文档不要求当前运行这些步骤。fixture、纯软件和真实 RTL 的证据分别报告。

## 4. T0：冻结契约与记录基线

**文件：**新增 scenario/contracts.py、ownership.py、state.py 的数据契约；新增 tests/scenario/__init__.py、test_contracts.py；新增 schemas/scenario_manifest.v1.json、scenario_genome.v1.json、scenario_result.v1.json。

**输入：**本设计的所有权、生命周期、资源与结果定义。**输出：**后续任务共同使用的不可变 manifest/身份规则及 RuntimeState 容器。

- [ ] 记录当前 HEAD、dirty diff hash、工具版本和源码 pin；保存到新 campaign 的 baseline.json，不覆盖旧证据。
- [ ] 实现字段与位区段单一 owner 校验；绑定和 source 重叠、方向抢占绑定、未知 reset policy 必须拒绝。
- [ ] 固定 testcase/execution/component_epoch/memory_generation 的关系及规范化序列化格式。
- [ ] 明确首版 warm_all/cold_all 策略；partial reset 以 unsupported_reset_scope 拒绝。
- [ ] 建立纯契约测试与字段级错误信息；验收 OWN-01、OWN-02、RST-06。

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_contracts -v`。预期所有用例实际运行通过，无假环境跳过。

## 5. T1：实现持久字节存储与初始化

**文件：**新增 scenario/memory.py；参考 composition/coherent_memory.py；新增 tests/scenario/test_persistent_memory.py。

**输入：**规范化内存 profile、初始镜像、初始化 seed、generation。**输出：**按字节查询/物化/写入、version/writer 和快照组成能力。

- [ ] 先写 Store→等待→Load、首次读重复、不同宽度重叠、别名与 byte-enable 测试。
- [ ] 实现 canonical address mapping，访问校验必须先于任何物化或写入。
- [ ] 一次性 preload；first-read 对缺失 byte 按 memory-init-v1 派生并保存，已有 byte 不再生成。
- [ ] 写入仅更新使能 lane；保留未使能字节的 initialized/version/writer。
- [ ] 加入资源上限，超限返回 budget_exhausted，不清空存储腾空间。
- [ ] 加入 warm retain / cold new generation；通过 MEM-01～MEM-08。

算法契约：

```text
validate_complete_access(request)
for each requested byte:
    if read and byte absent:
        materialize deterministic initial byte once
    if write and corresponding BE bit is 1:
        store actual requested byte with new writer/version
never initialize MMIO
never reapply preload during step or chunk
```

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_persistent_memory -v`。

## 6. T2：事务总账、提交点与不可变响应

**文件：**新增 scenario/ledger.py、memory_service.py；新增 tests/scenario/test_transaction_delivery.py、test_memory_service.py。

**输入：**真实源请求或测试夹具请求、事务键、载荷、memory profile。**输出：**一次提交、持久 receipt、冻结 ReadSnapshot 和明确的未知效果状态。

- [ ] 测试同键重发、同键异载荷、同内容不同键三种情况，防止错误去重。
- [ ] 入账必须先于目标驱动；真实 source handshake 才分配新事务序号。
- [ ] MemoryService.commit 一次性完成校验、读快照或掩码写；delivery 只消费保存的结果。
- [ ] 实现事务 phase 的单调转换、源/目标 epoch 校验和旧响应隔离。
- [ ] 测试读快照后写、FIFO fixture pop 运输重发、响应丢失后不自动重试。
- [ ] 通过 MEM-09、TX-01～TX-05；fixture 结果不计作真实 GPIO FIFO 能力。

```text
entry = ledger.accept(key, canonical_payload_digest)
if entry already exists:
    return existing phase or receipt
entry = mark_target_pending_before_delivery(entry)
result = execute_target_once(entry)
freeze result and observed effect status
deliver frozen result; never execute target again for delivery retry
```

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_transaction_delivery tests.scenario.test_memory_service -v`。

## 7. T3：独立 RTL 持续会话

**文件：**新增 scenario/session.py、harness_builder.py；新增 scenario/rtl/local_gpio_harness.sv、local_ibex_harness.sv；新增 tests/scenario/test_session_protocol.py、tests/integration/test_local_harness_sessions.py。可抽取 rfuzz_simulator.py 的进程管理，但不修改旧 bench 的 testcase reset 语义。

**输入：**单个 source-backed profile 和本地动作。**输出：**可多次 step 的真实实例、逐周期观察与覆盖。

- [ ] 实现带 testcase/command identity 的会话命令与重复命令防重。
- [ ] Ibex harness 提供 OBI 响应端与存储器服务连接；CVA6 另按其 AXI 局部协议接入。OpenTitan GPIO harness 提供合法 TL-UL A/D 握手，并记录实际请求接受与响应；不能将本地 beat-to-TL-UL 适配器算作 SoC bridge。
- [ ] 检查 BEGIN_CASE 一次 reset，STEP_LOCAL 从不 reset 或重载镜像。
- [ ] 每步采集真实 pin、IRQ、请求/响应；CPU 增加被动 RVFI 访存/中断证据，不能以 RVFI 自证 ISA 正确。
- [ ] 一个真实 GPIO 连续配置→等待→读回；一个真实 Ibex 连续 Store→Load。用局部 monitor 核对握手。
- [ ] 通过 RUN-01、TX-05 和局部协议验收 ABS-01；缺少真实工具时标 blocked，不用 fixture 填充真实通过数。

未来命令：`MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_local_harness_sessions -v`。保留此已有真实执行 opt-in，后续可新增更准确的别名但不能静默启用真实长跑。

## 8. T4：Runner 生命周期、收束与 reset

**文件：**新增 scenario/runner.py；扩展 state.py；新增 tests/scenario/test_continuous_execution.py、test_reset_epochs.py。

**输入：**固定 manifest、完整 genome、session 集合、memory/ledger。**输出：**begin/step/reset/quiesce/finalize 的一个持续 testcase。

- [ ] 验证同一 testcase 多次 step 使用同一 RTL 实例和同一状态上下文。
- [ ] begin 建立初态；step 保存所有资源；quiesce 停新根动作、完成已接受事务；finalize 先保存证据后清理。
- [ ] 实现 warm_all RAM 保留、cold_all generation 更新，严格区分 epoch 与 generation。
- [ ] reset barrier 记录取消和未知效果；已提交 RAM 写不会因 CPU 尚未收到响应而回滚。
- [ ] 检查新 testcase 不继承上一条末态；同 genome 重跑重新建立初态。
- [ ] 达到资源上限保留 ledger 并报告 incomplete/budget_exhausted；不得补响应完成。
- [ ] 本任务使用固定 fixture scheduler 验证 RUN-01、04、05 与 RST-01～06。RUN-02 的 ChunkAssembler 集成在 T7 完成，RUN-03 的真实 Scheduler 集成在 T5 完成；不提前记为通过。

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_continuous_execution tests.scenario.test_reset_epochs -v`。

## 9. T5：Router、Scheduler 与持续 Pending Event

**文件：**新增 scenario/router.py、scheduler.py；新增 tests/scenario/test_router.py、test_scheduler.py、test_irq_delivery.py。

**输入：**固定绑定、真实 Observation、未来环境 Action、事务状态。**输出：**有来源的交付、稳定局部步进和不会跨 chunk 丢失的 pending。

- [ ] Router 只进行声明的地址、位区段和数据格式转换；保存原始值与 transform identity。
- [ ] Scheduler 按固定公平轮转推进本地周期，ready queue 使用稳定排序键。
- [ ] 未交付响应和 IRQ 区间跨 step 保留，倒计时使用目标局部 tick。
- [ ] 真实异常事件不受预期 DONE guard 过滤；generation constraints 仅限制环境动作。
- [ ] 首版单 IRQ 源采用真实 IP `irq` 电平绑定：IP 实际拉高时 CPU 输入保持高，IP 实际清除后才变低；本地调度可改变何时采样，但不能凭超时合成拉低。两个事件按真实清除与再次产生分隔。通过 IRQ-01～03 后才能声称中断契约完整。
- [ ] 完成真实 CPU 请求到 GPIO 接受、GPIO 响应到 CPU 的身份核对；通过 TX-04、RUN-03、ABS-01。提前 IRQ 先用 fixture 校准，真实 E2E-07 在 T8 销号。

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_router tests.scenario.test_scheduler tests.scenario.test_irq_delivery -v`。

## 10. T6：Persistent State Dependency

**文件：**新增 scenario/dependency.py、path_planner.py；新增 tests/scenario/test_persistent_dependencies.py、test_direction_paths.py。

**输入：**静态 AND/OR 规则、真实事件和 MemoryService 提交/快照。**输出：**数据/事件/状态版本边以及 direction 合法的 focus/support 集合。

- [ ] 加入逐字节 RAW、WAW、WAR、PERSIST 和 generation INVALIDATE 关系。
- [ ] word read 可以引用多个 writer；禁用写 lane 不生成新来源。
- [ ] 静态反馈环按事件实例展开，不强迫组件节点构成无环图。
- [ ] 反向选源包含长期状态建立与消费；有界展开 AND/OR source sets，保留路径来源。
- [ ] 覆盖反馈只奖励实际发生的有界语义特征，不奖励任意 event_id 增长。
- [ ] 通过 DEP-01～DEP-03 与 OWN-03。

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_persistent_dependencies tests.scenario.test_direction_paths -v`。

## 11. T7：连续 Genome 与 Source Mutation

**文件：**新增 scenario/genome.py、mutation.py；新增 tests/scenario/test_genome_stream.py、test_source_mutation.py。

**输入：**版本化 bytes、不可变场景/绑定/路径及允许操作子。**输出：**整个 testcase 的一次性初态和连续动作计划。

- [ ] codec 将完整 testcase 解码为初始化材料、动作、trigger、局部 delay、重复上限、reset 与终止条件。
- [ ] ChunkAssembler 接收完整材料，校验顺序与重复；分块不调用 begin、step、reset 或 RNG。
- [ ] action 按新事件发生次数/明确 event_id 消费，旧事件不能每周期重复触发。
- [ ] 首版实现 CPU 立即数/初始数据、GPIO payload/strobe、有限 delay 和 path 切换；受保护代码区保持启动和 ISR 可执行。
- [ ] source mutation 不直接改 RuntimeState；改变 seed 后创建新的 testcase，不沿用旧末态。
- [ ] 同 raw 在不同 corpus 历史下 decode 相同；通过 GEN-01～GEN-04、OWN-01～OWN-03，并与 T4 联合完成 RUN-02 分块等价。

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_genome_stream tests.scenario.test_source_mutation -v`。

## 12. T8：CPU＋双 GPIO 真实多轮场景

**文件：**新增 configs/scenario/ibex_opentitan_gpio_pair.json、configs/scenario/opentitan_gpio_semantics.v1.json；新增 scenario/examples/gpio_pair_program.py；新增 tests/integration/test_independent_cpu_gpio_scenarios.py。复用锁定的 Ibex/OpenTitan GPIO RTL，不改 DUT 功能。已有 `scenario/gpio_session.py`、两个本地 GPIO Verilator 进程与 `test_scenario_gpio_live_session.py` 只构成此任务的 IP→IP 局部里程碑。

**输入：**三个独立 harness、固定 bank 绑定、continuous genome、环境 RAM。**输出：**两方向、同 testcase 至少两轮完整真实交互与状态证据。

- [ ] 建立 A.out[7:0]→B.in[7:0]；B.in[15:8] 为自由 source；A.out[15:8] 为不回接的结果。
- [ ] 由 CPU 固定序言实际配置 A/B；正确处理 OpenTitan GPIO `DIRECT_OE`、`INTR_ENABLE`、`INTR_CTRL_EN_RISING` 与 `INTR_STATE` 写 1 清除。
- [ ] Ibex 程序按实际 reset vector 和 mtvec 布局生成，配置机器外部中断使能并保存 ISR 使用寄存器。
- [ ] CPU 源 testcase 连续触发两轮 A→B→IRQ→CPU；strobe 回落、等待、再上升均靠真实持续执行。
- [x] 外部源 testcase：RAM S=5，x1=3、x2=9；CPU ISR 从真实 B 读值，累积写回 S，输出 A=8、17。证据为 `case-external-gpio-persistent-accumulation-v2`，后继 CPU Load 读到17。
- [x] 两方向至少各两个不同 genome；每个至少两轮交互、总计至少 1,024 个 CPU 运行局部周期且无中间 reset。四份 `*-1024ticks-v1` 包各有两轮真实闭环和 1,040 个 CPU 局部周期，之后的观察循环不计作新交互。
- [ ] 完成上游扰动、切边和固定下游输入对照；通过 E2E-01～E2E-07。

未来命令：`MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_independent_cpu_gpio_scenarios -v`。已执行的局部里程碑命令为 `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_gpio_live_session -v`，其通过不等价于本节的 CPU 双向链验收。

## 13. T9：完整证据与状态演化 Replay

T9a 证据包续实施（2026-09-27）：`scenario/evidence.py` 已将一个完整 testcase 的 manifest、工厂源码身份、canonical Genome、显式镜像、原始观察、事务、初始化、状态依赖、reset、checker、coverage、末态资源摘要、结果与 trace 分文件保存，并以 `bundle_index.json` 逐文件哈希做重放前校验。即使索引随 `result.json` 一起改动，事件数/摘要与原始 trace 的交叉校验也会在 DUT 启动前拒绝矛盾材料。`scripts/record_scenario.py` 和 `scripts/replay_scenario.py --evidence <dir> --factory <module:function> --rebuild --compare-trace` 分别负责保存和从初态重放；`--resume` 显式拒绝纯 host checkpoint 恢复 RTL。当前 CPU 源四份证据包括短闭环包和对应 `*-1024ticks-v1` 扩展包，各有两轮真实闭环、IRQ 清除、CPU 消费的 MMIO 响应和末态 pending=0，均由独立 CLI 从初态重放匹配。证据目录通过暂存后发布，写入失败不会暴露半包；单步内部预算、运输分块等价及 reset/首次未知读/部分写/延迟响应/双 IRQ 组合仍待完整验收，不能据此勾选 T9 整体通过。

T9b 双方向样例续实施：`configs/scenario/external_gpio_ibex_gpio_closed_two_rounds.json` 与 `scenario/ip_cpu_ip_example.py` 固定 IP_TO_CPU_TO_IP 真实环境；两份短包的两轮输入分别为 0x100/0x300 和 0x100/0x100，对应两份长包的 CPU 各运行 1,040 个局部周期。真实 CPU 消费 B 状态读响应，驱动 A 输出和 RAM 写，IRQ 最终清除。两方向四份短包、四份长包均有事件级闭环检查并经独立 CLI 重放。E2E-05/06 的切边与固定下游对照另有三份真实包，同样重放匹配。`case-external-gpio-persistent-accumulation-v2` 展示 S=5→8→17 的同 testcase 状态依赖。`case-rep01-combined-ibex-two-gpio-v1` 在单一真实 testcase 内组合首次未知读、部分写、冻结延迟消费、每 epoch 两轮 IRQ、warm/cold reset，独立 CLI 完整重放匹配。GPIO 没有 DONE，因此 E2E-07 只有 IRQ 先于后继 Store 的局部证据；跨 reset 旧 pending 回执和 REP-02～05 的多实例故障矩阵仍缺，不能据此勾选 T9b 整体通过。

**文件：**新增 scenario/evidence.py、replay.py；新增 tests/scenario/test_full_trace_replay.py；新增 scripts/replay_scenario.py。

**输入：**真实运行产生的完整材料。**输出：**重建运行、逐事件比较、首个差异和独立下游对照模式。

本任务分两次验收：T9a 在 T4/T7 后完成纯软件和一个真实 session 的 replay core，支撑 G2；T9b 在 T8 后对多实例完整因果链重复全部适用验收，支撑 G3。不能用 T9a 的软件结果代替 T9b 的真实多组件结果。

- [ ] T0 起就使用稳定事件格式；此阶段补齐所有身份与资源摘要，避免事后重建缺失日志。
- [ ] 保存物化字节与算法身份、CPU 镜像、所有 action/scheduler decision、reset 和事务快照。
- [ ] replay 从初态重新运行真实 RTL；录制输出仅作比较，不能作为 Router 数据源。
- [ ] 检查点首版只用于比对和定位，不从纯 Python 摘要恢复 RTL。
- [ ] 故意修改字节、固件、规则、局部响应与中间 Store，验证能拒绝或定位第一处语义分歧。
- [ ] 保留不同 host chunk 划分结果的等价比较；通过 REP-01～REP-05。

未来命令：`PYTHONPATH=src python3 -m unittest tests.scenario.test_full_trace_replay -v`。未来 CLI：`PYTHONPATH=src python3 scripts/replay_scenario.py --evidence runs/scenario/acceptance/case-001 --rebuild --compare-trace`；路径代表该阶段应生成的证据，不表示当前存在。

## 14. T10：RFuzz Genome 模式与反馈闭环

**文件：**新增 integration/scenario_campaign.py、scenario/feedback.py；修改 integration/rfuzz_live.py、rfuzz_shmem.py 的 executor/身份接口；修改 RFuzz fuzzer/src/queue.rs、mutation/mod.rs、main.rs、analysis.rs；新增 mutation/scenario.rs；新增 scripts/run_scenario_campaign.py 和 tests/integration/test_scenario_rfuzz_campaign.py。

**输入：**已验收的 Runner、codec、mutation schema 和真实反馈。**输出：**path/source-aware 搜索、有效失败保留、同 testcase 连续执行和完整 corpus replay。

- [ ] 新输入编码声明 scenario_genome.v1；一份 test payload 是整个连续 genome，record 仅是运输分块。
- [ ] 保留 FIFO/shmem framing，新增 host 执行关联 `(run_id, buffer_id, slot, genome_hash)`，与 Rust TestId 对应。
- [ ] coverage counter 使用 scale=false；真实每组件周期/成本由结构化反馈报告，不拿 record_count 代替。
- [ ] Rust mutator 获取 source 类型、字段 mask、direction/path 和 energy；只修改所选 focus/support 字段。
- [ ] 分开 input_invalid、DUT violation、environment failure 和 path_incomplete；所有 DUT failure 独立保存，不依赖新覆盖。
- [ ] 延迟或丢失 sideband 时不得套用另一个 testcase 的 energy/结果；失败须可诊断。
- [ ] 先用少量定向 corpus 检查真实传输，再做短时搜索，所有保留语料重建 replay；通过 FUZ-01～FUZ-04。

未来命令：`MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_rfuzz_campaign -v`。

未来 CLI：`MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 scripts/run_scenario_campaign.py --manifest configs/scenario/ibex_gpio_pair.json --seconds 60 --seed 20260927 --output runs/scenario/acceptance/search`。CLI 和全局确定性 seed 需在本任务实现；不能沿用旧客户端没有全局 seed 的事实却声称已可复现整个搜索历史。

## 15. T11：回归、对照与交付

**文件：**新增 tests/scenario/test_abstraction_boundaries.py；更新 docs/README.md 的新路径入口时保留已有用户改动；新增 docs/reports/persistent-scenario-acceptance-YYYYMMDD.md，实际文件名使用运行日期。

- [ ] 运行所有新纯软件与真实 RTL 套件，分别记录 pass/fail/skip/blocked，不将未执行或工具缺失记为通过。
- [ ] 按改动文件选择旧 coherent_memory、contract_transducer、rfuzz_simulator 和 RFuzz wire 回归；旧行为不得因新模式默认配置改变。
- [ ] 比较均匀 source 变异与依赖引导变异：相同 RTL、绑定、初始 corpus、预算和工具身份。
- [ ] 增加独立驱动诊断基线：使用单独命名的 baseline manifest，禁用跨 DUT 的真实交付，各 harness 使用声明的本地环境输入/响应模型；持续状态要求不变。此基线不能计完整因果链，也不能偷偷修改正式场景的绑定。通过 BASE-01。
- [ ] 三种策略、每方向至少三个固定 seed、每 seed 至少 60 秒有效搜索，不计编译；独立基线的方向仅表示预算分组，不声称存在该因果路径。报告实际次数/周期/链完成率/覆盖/成本，不预设提升阈值。
- [ ] 失败 corpus 全部重放；普通 corpus 全部重放至门禁规模，超预算时门禁不完成而不是只挑成功条目。
- [ ] 给出改变文件、未完成能力、失败归因和重放命令。不得将注入校准计为自然发现组件 bug。

最终通过要求见第 18 节。该任务不要求性能一定优于基线；负结果也必须完整报告。

## 16. 验收目录与测试归属

所有下列入口均为计划新增，当前未运行。

| 验收组 | 未来测试文件 | 核心判据 |
|---|---|---|
| MEM | tests/scenario/test_persistent_memory.py、test_memory_service.py | 字节持续、初始化一次、掩码写、读快照 |
| TX | tests/scenario/test_transaction_delivery.py、test_session_protocol.py | 目标至多一次、真实相同新事务不合并 |
| RUN/RST/IRQ | tests/scenario/test_continuous_execution.py、test_reset_epochs.py、test_irq_delivery.py | 持续生命周期、epoch/generation、IRQ区间和收束 |
| DEP/GEN/OWN | tests/scenario/test_persistent_dependencies.py、test_genome_stream.py、test_source_mutation.py | 长期版本来源与变异所有权 |
| REP | tests/scenario/test_full_trace_replay.py | 从初态重建完整状态演化 |
| E2E | tests/integration/test_independent_cpu_gpio_scenarios.py | 真实双向、多轮、持续状态 |
| FUZ/ABS | tests/integration/test_scenario_rfuzz_campaign.py、tests/scenario/test_abstraction_boundaries.py | 真实搜索和抽象边界 |

### 16.1 Memory 验收

**MEM-01 Store—等待—Load。** 在同 testcase 真实或服务级提交 A=0x11223344，推进至少 64 个无关合法步骤并跨至少三个 host step 调用，再读 A。必须仍为原值，期间无 reset、preload overlay。证据包含 writer、提交事件、读快照与 reset trace。校准：chunk 边界重建存储必须被检测。

**MEM-02 首次读只物化一次。** 全未知 A 首次读取、等待、重复读取并重叠读取。每个字节只出现一次初始化事件，后续值一致。校准：每读重新 RNG 必须失败。

**MEM-03 初始化不依赖访问顺序。** 同 seed/generation 分别先读 A 后 B、先 B 后 A、先 byte 后 word。每个地址初值一致。保存算法版本和物化映射，禁止隐式全局 RNG 消耗序列改变内容。

**MEM-04 byte-enable。** A 初值 0x11223344；写 0xAABBCCDD、BE=0101；word 必须为 0x11BB33DD。BE=0000 不改变任何字节版本，其他 mask 逐一覆盖。端序、mask 移位和整字覆盖注入必须被检测。

**MEM-05 部分未知写。** 全未知区域先 BE=0101 写 DD/BB，再整字读；已写 lane 保留，只有另外两个 lane 物化。必须展示逐字节 initialized/writer。

**MEM-06 别名与取指/数据一致。** 合法 alias 写读共享 canonical byte；非 alias 不串值；同一可写执行区域经 data Store 修改后，新发生的 MemoryService 取指读提交返回修改字节，不再次 ISA 投影。此前已冻结取指响应保持旧值，不把真实 CPU 预取行为误判成内存错误。

**MEM-07 无非法部分提交。** 跨界、只读写、非法宽度、预算不足时先完整拒绝；错误读的 initializer 调用数、ByteCell 集合、物化事件数和 writer 均不变。未映射地址、未知 MMIO 和真实 IP 无响应时 RAM initializer 调用数必须为零，不产生合成 rdata。真实 MMIO 错误不套用环境内存无副作用保证。

**MEM-08 长期保留。** 建立状态后插入至少 4,096 次无关合法调度/操作，再消费旧字节。值与 writer 必须保留，不能靠 LRU 淘汰重初始化。超过声明预算应明确结束。

**MEM-09 响应快照。** A=V1；R1 在 MEMORY_SERVICE_COMMIT 抓 V1，延迟交付；另一个允许的服务入口提交 A=V2；交付 R1 得 V1，新 R2 得 V2。首版单 CPU 单端口不强造并发，此项可由 MemoryService 夹具验证。交付时重读注入必须失败。

### 16.2 事务与运行验收

**TX-01 重发无重复副作用。** 同键同载荷在目标接受前、完成后重复运输；FIFO fixture pop/push 只执行一次，返回原 receipt。夹具只证明运输层，不计真实 IP 证据。

**TX-02 同键异载荷冲突。** 第二次载荷不同必须 identity_conflict，目标无第二次动作，原 receipt 不被覆盖。

**TX-03 同值新请求执行两次。** 两个真实接受点、两个 ID、相同地址数据均应执行，不能按 payload 去重。

**TX-04 通道顺序。** 控制运输乱序，保持声明的同通道顺序和目标排队规则；日志能区分源序号和调度顺序，不声称全局总线仲裁。

**TX-05 会话命令防重。** 模拟第一次 STEP 回复丢失，重发同 execution/command_id 必须返回原完整 Observation/receipt 且不多推进一周期；相同 ID 异 payload 拒绝。相同 genome 连续执行时注入前一 execution 延迟回复，必须隔离且新 BEGIN/STEP 正常执行。持有 valid 的观察不能在没有新握手时重复分配事务。

**RUN-01 无隐式 reset。** 一个 testcase 至少三次状态相关访问，跨多次 step，逐组件 reset 次数仅为初始和显式计划；epoch/tick/pending 持续。

**RUN-02 Chunk 等价。** 同 genome 用整块、每块 1 byte、固定块和不规则块收齐；再采用相同调度但不同 step 批量运行。语义日志、局部周期、响应及终态一致，仅运输日志不同。不得把此项宣传为在线流式执行已经实现。

**RUN-03 稳定调度。** 改变 dict/组件注册顺序，声明排序键相同时仍得到同一轨迹。host wall time 不参与调度。

**RUN-04 有界收束。** pending 请求或 IRQ 存在时进入 quiesce，冻结集合并停止新源事务；已接受事务按契约排空或报告 incomplete/uncertain。IRQ排空只表示已交付/到期，不等待停止取指后的ISR；需要ISR完成的成功条件须先达成。预留终止日志容量；watchdog截断只验收已保存语义前缀，不要求重现宿主超时时刻。finalize二次调用无新副作用。

**RUN-05 Testcase 隔离。** case A 改写 RAM/IP；case B 同进程开始时回到其声明初态。进程先执行其他 testcase 再重放同 genome，其初始 generation=0，未知 RAM 初值与新进程一致。相反，同一 case 的 step/chunk 必须保留状态。每个方向都要用状态差异证明，不只检查对象引用。

### 16.3 Reset 验收

**RST-01 旧响应隔离。** epoch E 请求后显式 reset，E+1 使用相同数字序号；旧响应不得完成新请求。完整键必须包含 epoch。

**RST-02 Warm 保留矩阵。** 写 RAM、配置 IP、挂起事件后 warm_all：RAM generation/内容/writer 保留；RTL 实际 reset；旧响应与事件取消并留痕；日志保留。不能把 RTL reset 后的真实寄存器变化当 host 回滚。

**RST-03 Cold 新代次。** 修改持久对象后 cold_all：RAM generation 增加，显式镜像恢复，未指定 byte 重新未知，IRQ/pending 按策略清理；初始化 seed/generation 派生可重放。

**RST-04 已提交写不因未交付回滚。** RAM Store 已 service_commit、CPU 尚未收到响应时 warm_all；RAM 值继续保留，旧响应取消。组件局部 reset 保留其他 IP 效果属于扩展项，不用未实现模式完成此验收。

**RST-05 副作用未知。** 目标可能接受后丢失完成证据，结果必须 uncertain_effect；不得自动重发、成功或恢复写前值。复现实验从初态重跑。

**RST-06 不支持范围明确拒绝。** 首版请求 CPU-only/IP-only reset 在执行前拒绝 unsupported_reset_scope，不偷偷扩大到全场景 reset。

**IRQ-01 真实电平递送。** OpenTitan GPIO `irq_o` 的高低变化必须来自真实 RTL，并经声明的映射交付 CPU；不同 step/chunk 划分不得改变源事件、交付顺序和 CPU 看到的局部输入轨迹。若 CPU harness 使用脉冲映射，须验证声明宽度 N、到期点及源电平仍高时的后续策略。CPU 是否进入 ISR 不得让 Router 擅自清除 GPIO 状态。保存源电平、起止 tick、`INTR_STATE` 写 1 清除与实际 CPU 输入轨迹。

**IRQ-02 遮罩到期不重试。** CPU中断屏蔽期间脉冲到期，记录未受理，不自动补发；下一独立源事件仍可正常递送。host暂停不能消耗虚拟CPU tick。

**IRQ-03 Overrun有证据。** 递送槽占用时出现第二个真实源事件，两者均保留；执行声明的overrun终止/不支持策略，不能覆盖、合并或延长旧脉冲。纯软件注入与真实源校准分别报告。

### 16.4 依赖、Genome 与所有权验收

**DEP-01 混合 writer。** 运行 S1→R1.snapshot→部分覆盖S2→R1.delivery→R2，验证 R1→S2 的WAR、S1→S2的WAW、R1仍引用旧writer、R2逐字节引用S1/S2。另做S1(V)→S2(V)→R：值相同但writer必须为S2。BE=0 lane不换writer，节点身份不能合并不同memory/address。

**DEP-02 长期依赖跨 epoch。** warm_all 后的新 Load 引用 reset 前保留 RAM 的 writer；cold_all 后不能引用旧 generation 值。无关周期与 step 不移除关系。

**DEP-03 图与事实分离。** 规则预期 DONE/IRQ 未发生时不生成事件。静态循环可展开两轮不同事件，事件 ID、状态版本和消费游标保持区分。

**GEN-01 一次解码持续动作。** 同一事件只触发相应 occurrence，一段 level/frame 按契约持续，不按每周期重新抽样。

**GEN-02 Chunk 完整性。** 重复块无效果；缺块、乱序、同 ID 异数据、final 后追加均明确拒绝。不足材料不隐式补零。

**GEN-03 确定性解释。** 相同 bytes/manifest 在不同 corpus 历史下产生相同程序、初始化材料和动作；覆盖只改变下一份候选。

**GEN-04 变异不继承旧末态。** 修改初始化 seed 或早期 Store 程序后从初态运行；不能复用旧最终 memory 或未经验证的 checkpoint。

**OWN-01 双 owner 拒绝。** B 绑定低 bank 同时出现在 source write_set 时执行前失败，自由高 bank 保持可变异。

**OWN-02 Direction 不改绑定。** CPU 与外部源两个方向的 binding hash 一致，只修改各自合法 root 字段。

**OWN-03 持久值不可直接改。** 尝试修改已提交 RAM、快照、真实响应或 IP 输出的操作子被拒绝；合法改变必须通过后续真实 Store 或新 testcase 初值。

### 16.5 Replay 与真实场景验收

**REP-01 全状态轨迹。** 保存首次读、部分写、延迟响应、两轮 IRQ 和显式 reset 的 testcase；从初态重放，语义事件与最终状态一致。纯软件长轨迹与真实 RTL 轨迹分别列出。

**REP-02 材料篡改拒绝。** 修改 genome、固件、规则、初始字节或 harness identity 却保留旧声明时，执行前指出不匹配字段。

**REP-03 首个语义分歧。** 在第 K 个响应或状态提交处注入错误，报告 K、组件 tick、tx/event、预期/实际与 writer；不能只给最终 hash mismatch。

**REP-04 不灌录制输出。** 本次真实 RTL 输出与录制不同，必须失败；禁用 live capture 不能继续得到 replay pass。

**REP-05 Checkpoint 边界。** 纯 host 摘要不能用于恢复真实 RTL；首版请求 resume 必须拒绝。证据摘要可以用于完整重跑后的定位比较。

**E2E-01 CPU 源多轮。** 同 testcase CPU 发出 x1/x2 两次真实写，A→B→IRQ→CPU 完成两轮；第二轮沿用持续配置和内存，过程中没有 reset。捕获源请求、A 输出、B 输入、B 读响应和 CPU 接收。对真实 `INTR_STATE` 的读取和写 1 清除必须分别形成新的 TL-UL 事务及真实响应，不能回用前一次缓存或通用 RAM。

**E2E-02 外部源累积。** S=5、x1=3、x2=9，两轮真实 ISR 后 S=8、17，A 高 bank 输出对应结果，后续 Load S=17。每轮从5重建的注入应被发现。

**E2E-03 跨阶段 pending。** 源接受、目标完成、CPU 接收分别跨不同 step 调用，身份与 payload 不变，协议等待稳定。

**E2E-04 上游扰动。** 只变 root payload，真实中间输出与最终结果按声明函数变化；不能由下游直接读取 mutation 参数。

**E2E-05 切边。** 禁止指定 A→B 或 IRQ→CPU 交付后，不能仍得到原完整链；若有其他合法路径，须给出独立真实前因。

**E2E-06 固定下游输入。** 用录制合法输入固定下游，再变上游；下游不能偷偷读取共享变量继续跟随上游。该模式标 isolated replay。

**E2E-07 提前 IRQ。** 完成标志之前真实出现 IRQ，仍记录并按声明递送；受理与否由 CPU 实际状态决定。waiting-for-DONE 过滤注入必须被检测。

### 16.6 Fuzzer 与边界验收

**FUZ-01 源选择有效。** mutation 日志实际显示两个 direction 选择不同 focus 字段；Bound Input 无直接变异；direction/path/source-set 与实际 mutation diff 一致。

**FUZ-02 连续执行语义。** 一个 RFuzz testcase 对应一个完整 genome/session 生命周期，运输 records 不导致多次 reset，反馈给出实际每组件周期。

**FUZ-03 失败不被 invalid 吞掉。** 合法输入触发 checker 违例，无新覆盖也进入 failure corpus；环境非法输入与环境运行错误分别记录。

**FUZ-04 反馈身份。** 多次相同 genome 与批量输入的 coverage/sideband 使用完整执行关联键；乱序结果不能记到另一种子或路径。

**ABS-01 环境错误归因。** 注入非法 TL-UL A/D 握手或 CPU 响应规则，必须归环境/driver 失败，不能计真实 IP bug。

**ABS-02 不虚构全局时序。** 报告只使用局部周期与因果顺序；不把不同组件 tick 相减称作 SoC 延迟，不把 host timeout 直接称 DUT deadlock。

**BASE-01 独立驱动基线。** 单独baseline manifest无真实跨DUT绑定，组件源/响应由其声明的本地环境提供；明确标记independent，不产生完整链计数。RTL、工具、组件集合、预算和持久状态要求与正式场景可比，报告模型与输入自由度差异。主要算法收益仍由同绑定的uniform-source与dependency-guided对照判断。

## 17. 证据包结构与报告模板

```text
case-<id>/
  manifest.json             # source/tool/profile/binding/policy identities
  genome.bin
  genome.json
  images/                  # 实际CPU镜像与初始数据
  initialization.jsonl     # 首次物化byte与来源
  schedule.jsonl           # 实际局部推进和动作选择
  observations.jsonl       # 实时采集原始边界输出
  transactions.jsonl      # 接受、提交、snapshot、交付与取消
  state_versions.jsonl     # writer/version与依赖边
  resets.jsonl
  checks.jsonl
  coverage.json
  result.json
  replay_report.json
```

报告每个验收 ID 必须列出：源代码/构建 hash、测试入口与完整命令、运行日期、实际 pass/fail/skip/blocked、刺激输入、观察值、独立判据、证据路径和限制。没有运行的项目明确写 not_run。

校准注入另外记录 injection_id 和预期检测点。所有失败证据先落盘再清理进程。最终 testcase 清理包含子进程、共享内存、会话锁和临时文件；清理失败独立报告，不能用正常覆盖掩盖。

## 18. 阶段门禁与完成判定

| 门禁 | 必须满足 | 允许宣称 |
|---|---|---|
| G0 设计冻结 | 契约、接口、reset矩阵、预算和所有验收归属完整；无待定字段 | 设计可实施，不代表功能可用 |
| G1 软件持久核心 | MEM/TX/DEP/GEN/OWN 全部适用项通过，校准注入被识别 | 软件状态与事务核心满足契约 |
| G2 持续执行与重放 | T4/T5/T7/T9a联合完成RUN/RST/IRQ与软件、单session REP；至少一个真实session连续状态通过 | 软件及单session持续生命周期与重放成立 |
| G3 真实多组件闭环 | T8/T9b完成E2E和多实例REP；两方向各两个genome、各至少两轮；局部协议无未解释违例 | 指定Ibex/双GPIO场景有真实持续因果和完整重放 |
| G4 Fuzz闭环与评测 | FUZ/ABS/BASE通过；三策略、两方向分组、各三seed、每组60秒有效搜索；保留corpus全部重放 | 可评价依赖变异效果；不预设优于基线 |

G4 最低搜索预算为 3策略×2方向分组×3seed×60秒=1,080秒有效搜索，不计编译、预检和重放。其中720秒属于两个保持真实绑定的主要策略，360秒属于独立驱动诊断基线。它是功能评测门槛，不是统计显著性或缺陷发现保证。指标必须包括实际 testcases、每实例局部 cycles、valid率、真实完成链、coverage、失败类别及运行成本。

任何硬门禁 skip、blocked、not_run 或证据缺失，均不能记为该阶段完成。早期阶段可以单独交付，明确剩余门禁。旧 SoC、旧 RFuzz 或旧单组件测试通过不替代新路径证据。

## 19. 要求到任务和验收的追踪

| 用户要求 | 实施任务 | 验收 |
|---|---|---|
| 同 testcase 持续多周期、不重复reset | T3、T4 | RUN-01～05、E2E-01～03 |
| memory/事务/pending/场景状态保留 | T1、T2、T4、T5 | MEM、TX、RUN、RST |
| Store后延迟Load仍得原值 | T1、T2 | MEM-01、08、09 |
| 首次未知读生成后复用 | T1、T7 | MEM-02、03、05、GEN-03 |
| byte-enable与重叠访问一致 | T1、T2、T6 | MEM-04～07、DEP-01 |
| 真实或持久确定值不被随机覆盖 | T0、T5、T7 | OWN-01～03、REP-04 |
| Genome是连续场景 | T4、T7、T10 | GEN-01～04、FUZ-02 |
| 跨周期双向CPU/IP交互 | T5、T8 | E2E-01～07 |
| persistent state dependency | T6 | DEP-01～03、MEM-08 |
| 保留局部时序、无全局SoC | T3、T5 | ABS-01、02、RUN-03 |
| 结束或显式reset才清理 | T4、T9 | RUN-04、05、RST、REP |
| 从当前代码迁移且可验收 | T0～T11 | G0～G4与baseline对照 |

## 20. 首版之外的明确扩展

组件局部 reset、在线边收chunk边执行、恢复真实 RTL checkpoint、一般多源IRQ、任意 AXI burst/atomic、多CPU一致性、SPI/UART异构链和长时间性能优化均独立立项。首版数据结构保留必要身份字段，但接口占位、schema接受或文档描述不等于能力已实现。

实施交付时先提交 G0～G3 的真实证据，再评价 G4 搜索效果。是否扩大 operator、场景和组件范围，应由实际覆盖缺口、失败分类与运行成本决定。
