# 通用化系统完成审计

目标：CPU/IP 各适配一次，兼容组合主要靠配置；独立执行真实 RTL 并模拟数据流，覆盖 F1–F6；遵循 final-method 的当前版本状态、实际消费关系和逐例决策。完整效率目标仍 active。下面的当前结论取代历史流水中的旧状态；历史失败保留。

## 当前结论（2026-10-30 深夜，本轮通用化/覆盖率/性能）

本轮在保持真实 DUT 行为、有效工作量与证据语义的前提下，做了三件事：补公共能力缺口、补齐可复现覆盖率、实现并实测宿主开销削减。**所有原生运行都是在源码冻结后串行执行的**；并行子代理只做软件实现与测试，唯一例外是一处已披露的 97 s 软件 pytest 与首轮 A/B 前 1.5 min 重叠（已按保守口径改用以反序干净配对为结论）。

### 一、性能：同工作量 A/B 与首次完整八例（含 replay）

同 descriptor、同 8 records（`F3,F1,F4,F5,F2,F6,F5,F6`）、同 13 GB 内容寻址缓存、同 `--dut-eval`，仅源码版本不同：baseline 为 `/tmp/myfuzz-baseline-0101`（本轮改动前字节副本），candidate 为 `/tmp/myfuzz-candidate-0149`。顺序 `base-a → cand-a → cand-b → base-b`，证据在 `runs/host-ab-20261030/timed/{base-a,cand-a,cand-b,base-b}/performance.json`。

| 配对 | wall | campaign | finish/export | peak RSS |
|---|---:|---:|---:|---:|
| base-a → cand-a | 241.00 → 192.69 s（−20.1 %) | 166.87 → 139.24 s（−16.6 %) | 47.62 → 28.39 s（−40.4 %) | 1952 → 1703 MB |
| cand-b → base-b（反序、干净） | **198.06 vs 222.93 s（−11.2 %）** | 143.16 vs 154.28 s（−7.2 %) | 29.15 vs 43.41 s（−32.8 %) | 1703 vs 1942 MB |

同工作量证据：四次运行均 38 421 events、per-kind 计数相同、ticks CPU 977/DMA 1010/peripheral 1023、native eval 次数 3908/4040/4092（eval 时间 CPU 8.4–8.8 ms、DMA 2.5–2.7 ms、GPIO 2.2–2.8 ms）。经运行时自身进程归一化后，四次运行的完整 journal 只差 64 行里的 `execution_binding_sha256`（计划摘要，随宿主源码版本必然变化）；仅掩蔽该摘要后 journal SHA256 四次完全相同 `da01e418…`。因此这是**源码版本 A/B**（`plan_identity_sha256` 按设计变化），不是同二进制开关 A/B；不要跨版本引用 plan identity。

**完整八例含 within-invocation replay 首次在本机完成**：`runs/host-ab-20261030/timed/cand-replay`，wall 415.66 s（campaign 140.69 / finish+export 29.15 / replay 214.18），`replay_matches=true`、scope `within_invocation`，**peak RSS 3 077 MB**。上一轮同工作量在 7 GB 主机内存耗尽而中断；本轮没有 paired baseline replay，不构成 replay 的 A/B。

**剩余成本归属（本轮新 profile，`cProfile` 2-F6 campaign，相对值有效）**：F6 证据路径仍主导——8 例中两个 F6 case 占 141.3 s campaign 的 33.0 + 75.4 s，第二个 F6 明显更贵（journal 更长）。热点：`compiled_f6_consumer.declared_edges`（每 F6 case 一次整 journal `read(0)`，2 × 5.8 s profiled）、`capture_f6_case`（2 × 12.8 s profiled）、`protocol`/`_index_cpu_tick_samples`/checker report 各一次整 journal 读取、`f6_instruction_fetch_receipt._state` 的每次调用都做 `_canonical(artifact)`（两次同值）。本轮已把 finish 阶段的 trace-snapshot 读取改为借用迭代（3 次整 trace detach → 1 次（比较）且不再物化 `trace_events`），但**没有**改上述 F6 证据路径：`declared_edges` 的借用化需要先适配以 `SimpleNamespace(events_since=…)` stub runner 的既有测试，属于下一轮明确的最大单点。

**IPC 与解析不是主因（实测）**：在真实录制回复上（`adapter-matrix-20261029/cv32-gpio-v1` 2 062 条命令），已收到回复的宿主阶段合计 **0.292 s**（hex 0.005、`json.loads` 0.055、`wire._payload` 校验 0.164、samples deepcopy 0.067），约 0.14 ms/命令；同次运行记录的命令往返为 13.2–13.8 s，即 ≥95 % 在管道往返与驱动自身逐命令开销。故单纯批量化 IPC 或不改驱动都无法回收这 13 s（证据 `runs/host-ab-20261030/wire-reply-cost.json`，工具 `scripts/measure_wire_reply_cost.py`）。**DUT eval 仍只占 wall 的约 0.007 %**；“初始化后主要时间用于 DUT”这一效率目标仍未达到，且不是本轮可关闭项。

详细方法与复现见 [宿主开销第二轮 A/B](host-overhead-round2-ab-20261030.md)。

### 二、覆盖率：CPU 侧可测量 + 可比对契约

- **wb-timer CPU 侧已测量**：Ibex DUT line/block **616/1782**（Verilator line 245/812、branch 371/970），105 命令/105 ticks，`status=measured`、exit 0。旧拒绝根因是 artifact 的 `structural_build.source_files` 带 `./` 前缀而缓存输入路径不带，verifier 要求精确路径；加入严格归一化（绝对路径/`.`/`..`/空段仍拒绝）后，从 pinned cache 全新构建并重放。该运行自带的旧 `coverage.dat` 与本次重放解码出**相同 1826 点身份与相同 650 命中点**（`corroboration.json`），数字不是从旧产物反推。命令与 SHA 见 `runs/declared-irq-f5-cpu-20261030/`。
- 三个 target 数字不变并可由保存文件字节级重算：wb-timer 37/39、apb-spi 85/271、ahb-sha 359/614。
- **CV32E40P 六 flow 缺 per-component 命令 trace 已修**：`scripts/run_shared_all_flows.py`/`run_shared_slot_subset.py` 新增 `--record-local-commands`（`shared_slots.py` 已有导出接线，未改）。既有 `shared-six-v6` 仍为 `missing-per-component-command-trace`（历史产物不回填）。
- **可比对契约**（`docs/reports/coverage-comparison-contract-20261030.md` + JSON）：契约 `dut-line-block/offline-recorded-prefix.v1` 要求同一 DUT 源集/点集/分母、nonce 归一化后的同一命令序列与 tick 数、同一重放预算、显式离线模式、两侧均插桩。当前 6/6 配对 `not_comparable`、2 项 `unavailable`，不发布汇总数字。**与其它工具同预算比较仍 unavailable**：缺少外部工具对同一 DUT 源集/点集的测量、同一录制命令序列的重放、预算执行证据与 instrumented fresh prefix。

### 三、通用化：第四个 CPU 总线协议与 reset 恢复

- **AXI4-Lite 成为第 4 个通用 CPU 总线协议（配置复用，无 CPU×IP 专用执行器）**：新增 `runtime/adapters/axi4lite_cpu.py`（薄适配器，复用既有 `GeneratedAxiLiteMemorySession`）、registry/compiler/binding/admission 各一行声明、`configs/scenarios/compiled-f2-f4-axil-apb-i2c-picorv32/` 与 `configs/search/i2c-picorv32-axil.json`。真实 pinned RTL 证据：`create_preparation` 从真实 artifact 得到 F1–F4 `executable`、F5/F6 `unsupported`，`select_adapter → axi4-lite.cpu.v1`（pin `ce563a92…`，semantic `cpu.axi4-lite.v1`），真实 `GeneratedAxiLiteMemorySession` 绑定成功（`drives_cpu=false`），41 项软件测试通过。随后按 review 过的 patch 让渲染器导出该 endpoint 的 17 个 AR/AW pin tap 与显式 `fetch_observation{arprot,bit 2}`（artifact `68f06eaf…`、harness `3a02b9c6…`、build `18bcb312…`，runtime_ports 20→37、protocol_tap_ports 0→17），即**真实引脚已可逐 tick 观测**。**仍未原生执行**：F2/F4 executor 仍以 `generic-plan-mismatch` / `MMIO-CPU-adapter-unsupported:axi4-lite:witness_reader_not_admitted` 拒绝（`process_started=false`、无 cache、无二进制、无 case），且另有一个协议策略缺口——AXI4-Lite 无读选通，PicoRV32 读时 `wstrb=0`，而 `native_mmio_hops`/`native_obi_hops` 对读也硬编码 `byte_enable==15`；两者都必须先做经评审的改动，不能用 `be=15` 冒充采样值。缺口、经验证的 patch 与停点证据见 `runs/axil-picorv32-config-only-20261029/GO-results.md`。
- **reset 后恢复（新能力，代码+软件测试，native 结果为声明的 blocker）**：`scenario/native_reset_recovery.py` 实现“屏障前声明 → 校验真实 reset 屏障/新 epoch/新进程/命令 epoch → 按新 epoch 重装 source/provider/authority → lineage 围栏（旧 epoch credit 拒绝、旧 identity 拒绝、同数值 token 新 epoch 记 `lineage:false`）→ 一次 continuation 尝试”。53 项新测试通过，邻居套件 354 passed/1 skipped。原生 `runs/reset-recovery-20261030/warm-ram-v1`（exit 0，期望 `unavailable`）：真实屏障 `event_id=7576`、`epochs_advanced=true`、`no_old_epoch_credit=true`，continuation 以 typing 拒绝并复现声明的 carrier blocker `compiled-F6-built-process-launch-missing`。即：**复位后重装已可执行，跨复位继续 slot 执行在当前 carrier 架构上不可行**（固件每次从 slot0 启动、launch identity 一次性 pin），需要的 owner diff 已在 `docs/reports/reset-recovery-20261030.md` §4 写明，未应用。

### 四、仍未完成 / 不得推断

- 性能：F6 证据路径仍按 journal 规模增长（`declared_edges`/`capture_f6_case`/protocol/checker 每例整 journal 读取）；下一轮应先做 case-scoped 证据与该 `declared_edges` 借用化，再用同工作量 A/B 验证。完整 replay 的 paired A/B 仍缺（baseline 侧在本机仍可能 OOM）。
- 覆盖率：仅 target 三例 + wb-timer CPU 侧为离线 line/block；无在线/固定时间覆盖，fresh prefix 未插桩；与外部工具的同预算比较 unavailable。
- 通用化：AXI4-Lite 只有 F1–F4 声明与真实会话绑定，**没有**原生执行、F5/F6、IRQ、retirement 或 storage-version 权威；其他新 CPU/IP 组合仍需各自提供真实观测。reset 后继续 slot 执行仍不可行。
- 已知**非本轮**软件测试失败（如实登记，未代修；均在基线副本上复现同样失败）：
  - `tests/runtime/test_generic_wall_budget.py` 13 failed / 20 passed：baseline 副本同样 13 failed（`shared_f5_descriptor` 对 `SimpleNamespace` descriptor 取 `.executors`，是前序未提交改动的缺口）。
  - `tests/runtime/test_registry.py` 3 failed / 25 passed：冻结基线仍写 `len(registrations())==5`、index0 为旧 `apb3.storage.v1`（当前 8 行、index0 为 `apb3.mmio.v1`，均为本轮之前加入）。
  - `tests/integration/test_shared_f5_support_binding.py` + `test_shared_f5_runtime.py` 4 failed / 153 passed：`runtime-physical-facts-mismatch` / build admission（`runtime_renderer.py:163`），在**未打本轮 AXI patch** 的候选副本上同样失败。
  - `register_reset_default_*`/`resume_terminal` 20 failed：`register_reset_default_verifier._PROBE_SHA` 仍 pin 旧 probe 摘要（`52c5a3eb…`，实际 `413cdbad…`），probe 文件在前序会话被改（只改 `_PROFILE_SHA256`）后未同步。
- 本轮冻结树上通过的软件门（摘要）：`test_compiled_f6_consumer.py` **191 passed**；新增/相关的 prefix 等价、trace 借用迭代、replay projection、event journal/journal cache 共 40 passed；AXI 41 passed；覆盖率契约 18 passed + 相邻 167 passed/2 skipped；reset-recovery 53 passed + 邻居 354 passed/1 skipped；文档/仓库审计 81 passed + 12 subtests。

## 当前结论（2026-10-30 末，冻结窗口原生批次）

源码/配置/脚本冻结后集中执行原生批次，原始材料根目录 `runs/native-batch-20261030`（相对研究 runs 根，下称 `$B`）。以下全部是本轮新原生运行；失败原产物保留。

**CV32E40P 声明式 IRQ → 完整 F5（两个 target 协议，跨 CLI）**：`$B/e40-f5/{wb-timer,apb-spi}`，每 target 两次独立 CLI 调用。四份 summary 均 `status=verified`、`irq_consumption=verified`；original/fresh 语义摘要相等（wb-timer `9818d5b5…`、apb-spi `124ebff2…`），fresh `fresh_matches=true`，两阶段 3 组件 PID/nonce 独立、全部 exit0。E40 真实 `irq_ack_pre=1`/`irq_id_pre=11`/`irq_entry_pc=66092`；向量入口退休 order 20/18、PC 66092；ISR 读 offset 0/40 值 0；MRET PC 66624；返回 PC 69652；`retirement_joins=by_documented_order`、`decision_serial=unavailable`、10 个未观测字段显式登记，`raw_mret_pc_wdata` 不存在。独立 `scripts/verify_declared_irq_f5.py` 对两份产物重算 semantic digest、真实 target 输出位、OR frame/take、三层同值、MRET/后继与进程独立，均 `verified`（`$B/e40-f5/*/independent-audit.json`）。这把声明式 F5 链从 Ibex/CV32E20 扩展到 pc/insn/order-only CPU，且没有新增 CPU×IP 执行器。

**复位屏障定向原生**：`$B/reset/ibex-wb-timer`，真实 `warm_all` 屏障位于一次 native take 与 handler 退休之间。`status=verified`、`fresh_matches=true`、`barrier_observed=true`、`epochs_advanced=true`、`post_reset_take_count=2`、`no_lineage_after_reset=true`、`post_reset_serial_distinct=true`；两阶段各 6 个进程（3 组件×2 次启动）全部 reaped/exit0。独立只读复核：barrier event 1738、pre take epoch 0/token 1、post take epoch 1/take_key `["cpu",1,1]`/`["cpu",1,2]`，跨 epoch join 为 0；同数值 token 在新 epoch 重复不算 lineage。不证明 reset 后重新安装 provider 并继续 slot execution。

**多源 IRQ group 定向原生**：`$B/irq-group-v2/{joint-two-targets-ibex,unique-wb-timer-ibex,unique-apb-spi-ibex}` 均 `verified`、`fresh_matches=true`。joint 例真实 frame `attribution_status=joint`、`active_sources=[wb_timer.o_int, spi.events_o]`、单 take；观察文档 `status=ambiguous`、`irq_consumption=unknown`、refusal `declared-F5-OR-attribution-not-unique`、零 credit。两个 unique 例分别唯一归属 `wb_timer.o_int`/`spi.events_o`，完整消费链 `verified`。首次执行的三例在派生阶段因 mapping 键名错误 exit1（原 journal 保留在 `$B/irq-group/`），修正脚本后重跑通过；失败不计通过。

**跨协议 directed 矩阵**：`$B/directed/*` 四个 native-ready case（APB SPI×CV32E20、APB SPI×Ibex、Wishbone Timer×Ibex、AHB SHA×CV32E20）全部 `verified`，7 个声明层由真实 journal 重算，serial 均为 1。

**异常定向与 cross-CLI**：`$B/exception/{ibex-crosscli,ibex-crosscli-v2,cv32e40p-crosscli}` 均 `verified`、`fresh_matches=true`；Ibex 两次当前脚本 CLI 摘要相等 `bc97ec83…`，E40 与旧运行相等 `5c127046…`。全程 `irq_take_count=0`、handler order 11、真实 trap PC；debug/NMI 改道未测。

**覆盖率**：wb-timer CPU 侧离线插桩重放被拒绝（`coverage-dut-source-list-invalid`，缓存无有效 DUT source list），保持 unavailable；target 侧 37/39、85/271、359/614 已测，见 `new-path-coverage-20261030.md`；E40 六 flow 无保存的 per-component command trace，覆盖率 unavailable。

**性能（同工作量 A/B，分 workload 报告）**：完整八例（含 replay）A/B 的 warm-up 完成 campaign/prefix 导出后在 replay 阶段触发 7 GB 主机内存不足并重启（00:10），该次无 performance.json，不计结果、原产物保留。改用 campaign-only 同工作量 A/B（同 descriptor/cache，仅缓存容量 1 vs 4）：(a) 密集历史读取的 2-F6 子集两对 wall 比 0.8895/0.9264，均值 wall 83.99→76.24 s（−9.2%）、campaign 41.41→34.85 s（−15.8%），事件 14,921、eval 次数一致、normalized prefix 相同、peak RSS 1.03–1.07 GB；(b) 规范八例 campaign-only（`$B/perf-8/{legacy,lru}`）wall 192.21→191.06 s（−0.6%）、campaign 127.70→125.31 s（−1.9%），事件 38,421、ticks 977/1010/1023、eval 次数 CPU3908/DMA4040/GPIO4092 与参考 workload 完全一致、normalized prefix 相等。微基准同访问模式 71.50→0.83 ms/step。**规范八例的实测收益只有约 2% campaign**，说明缓存修复的是病理访问模式而非该 workload 的主导成本；实际 DUT eval 仅约 4.5–5.3 ms（wall 的约 0.006%），宿主仍主导。不作策略结论，也不外推。

**仍未完成**：完整八例（含 replay）性能 A/B 需更大内存或分阶段 replay；E40 六 flow 覆盖率缺保存命令 trace；debug/NMI 改道、cold reset 恢复、更多 CPU×target F5/F6 仍属后续能力扩展。性能上，实际 DUT eval 仅约 4.5–5.3 ms（wall 的约 0.006%），宿主编排/证据处理仍主导，尚未达到“初始化后时间主要用于 DUT 推进”；缓存与单次渲染降低了宿主开销，但批量化 IPC、逐事件复制/导出才是后续方向。

## 当前结论（2026-10-30，续接 2026-10-29 末）

本轮先独立复核 2026-10-30 已保存的原生产物，不重复运行已完成的实验；随后继续补齐 reset/多源 IRQ/E40 声明式 F5/覆盖率/性能。以下每项都注明是**本轮新原生运行**还是**对既有原生档案的独立离线重算**。

**CV32E40P 六 flow F1–F6 原生验收（既有档案，本轮独立重算 verified）**：`runs/cv32e40p-irq-20261030/shared-six-v6`（相对研究 runs 根）。同一 CPU/RAM/DMA/GPIO 会话八例 `F1/F2/F3/F4/F5高/F6/F5低/F6` 全部 `passed`；original/fresh 各 8 case、`replay_matches=true`，两份 normalized prefix 相等，raw trace semantic hash 各自精确重算，CPU/DMA/peripheral 三组件 PID 与 execution nonce 两阶段独立。实际 4 次 `cpu_external_irq_taken` 都携带真实 `irq_ack_pre=1`、`irq_id_pre=11`（机器外部）、4 字节对齐 `irq_entry_pc=66092`；两 F5 的 `irq_isr=verified`，retirement authority 明确为 `pc_insn_order_only`，entry retirement order 133/302、MRET event 13737/28710、实际后继 PC 70404/71172；两 F6 五项义务（`declared_edge_hops`/`cpu_configuration`/`irq_isr_completion`/`word_transfer_join`/`receipt_violations`）全部 passed。事件 37,629，ticks CPU 955/DMA 988/peripheral 1001。本轮用 `scripts/verify_cv32e40p_irq_acceptance.py --case-root …/shared-six-v6` 重新独立重算，`status=verified`（`authority=false`、`grants_F5/F6=false`）。该结果**不**把未驱动的 `rvfi_intr`/`rvfi_pc_wdata` 补零，也不外推到其他 CPU。

**声明式 IRQ → 完整 F5 消费链（既有原生 original/fresh，跨 CLI；本轮独立重算 verified）**：`runs/declared-irq-f5-20261030/{wb-timer,apb-spi,ahb-sha}`。三者是**两次独立 CLI 调用**（original 与 fresh 各自新进程，fresh 只按配置重建、不读 original 证据），语义摘要两侧相等。本轮新增 `scripts/verify_declared_irq_f5.py`，只读保存产物并逐项重算：两阶段 semantic digest、真实 target 输出样本位、OR frame 唯一归属与 take 连接、CPU 输入样本、ISR 声明状态读的 delivery/OBI/RAM 写三层同值、MRET 字与后继 order、三组件进程独立且 exit0。三例均 `status=verified`：Wishbone ZipTimer+Ibex（读值 0）、APB PULP SPI+Ibex（INTSTA 按 RTL 设计读 0）、AHB Caliptra SHA+CV32E20（STATUS 读 1）；MRET PC 均 66624，返回 PC 69652/69652/69700。内部 cause/version、跨例来源、ISR-MMIO authority 仍 unknown，`grants_F5/F6=false`、`reward_eligible=false`；读值只证明真实值传播，不证明内部中断原因。

**定向同步异常负控（既有原生，本轮复核）**：`runs/cv32e40p-irq-20261030/exception-{ibex-v4,cv32e40p-v2}`。真实 ECALL 进入异常向量，两次独立原生会话 `fresh_matches=true`；全程 `cpu_external_irq_taken=0`、无 IRQ serial lineage，handler 在 order 11 退休（PC 69632）。E40 侧由真实 `cpu_native_exception_redirect` 探针记录（cause 保持 unknown，不冒充已保存 cause）；Ibex 侧以 `rvfi_trap_retirement` 为证据。

**覆盖率与性能（进行中）**：三个声明式 F5 目录已有 `coverage-target` 离线 line/block 覆盖产物（wb-timer `dut_points=39`），但 `apb-spi/comparability` 因拿外来 baseline 比对返回 `unavailable`，本轮正改为同配置 original/fresh 可比对；性能侧 `docs/reports/host-overhead-profile-20261030.md` 已定位历史事件 chunk 缓存与证据写放大，优化与同工作量 A/B 正在进行，尚不构成提速结论。

**仍未完成**：reset 后 IRQ lineage 定向原生、多源 IRQ joint attribution 原生、CV32E40P 声明式 F5（pc_insn_order_only）原生、新路径覆盖率与可比性、同工作量性能 A/B。上述各项完成前不声称系统完成或效率提升。（2026-10-30 末冻结窗口已补齐前四项并完成轻量 A/B；见上方新章节，完整八例 A/B 仍受主机内存限制。）

## 当前结论（2026-10-29）

用户进一步明确：MMIO执行以CPU协议和target协议分别适配，不增加CPU×IP执行器。已新增协议级APB MMIO通路，将真实总线执行与可选内部storage证据分离。新增I2C仅配置，Ibex、CV32E40P（OBI）、PicoRV32（Wishbone）、CVW（AHB）各4例 original/fresh及独立完整前缀/原生收据核验通过，全部使用同一MMIO runtime。实际值85/85/170/170；OBI/WB各9012事件，AHB9858事件，原/fresh各自完全一致。内部版本及跨例归属unknown、不奖励。详见 `runs/generic-mmio-20261029/{i2c-ibex-v2,i2c-cv32-v1,i2c-wishbone-v1,i2c-ahb-v1}`（相对研究runs根）；generic summary的cross pending保留，独立核验报告verified。此为三种CPU协议→APB32 full-word/static-input范围，不代表所有target协议或F5/F6已经通用。

AHB专门保留实际HPROT及memory事务序号，支持真实deferred target回调与错误位，不冒充OBI；当前case按source-backed64B取指行供给实际NOP padding，不预供下一case。CVW仅本地memory adapter的HREADYEXT等待rsp_valid修正及对应已审查pin更新，上游字节未变；direct展开补实际include闭包候选核验，未跳过sha验证。AHB actual prep/plan/constructor/binding/kernel门1passed；原生original65.05s、fresh60.91s，均包含内部重放，非稳态单例或性能A/B；独立raw checker已exit0 verified。I2C本身PSLVERR恒0，不能据成功原生案例声称已native验证错误响应。

CV32E40P补入总审计（2026-10-29末，`runs/cv32e40p-rvfi-20261029/i2c-v1`）：本地官方RVFI观测器只实际驱动 `rvfi_valid/rvfi_order/rvfi_insn/rvfi_pc_rdata` 四字段；公共I2C四例 original/fresh 各4 case、exit0，within replay `matches=true`，实际wall 55.23s/41.42s，execution 3.877s/3.829s，事件13045103 bytes×2，双方46条退休逐项相等（order 1–46，PC 65536–65716，tick 6–410），两阶段CPU/peripheral PID与execution nonce均独立。独立[retirement-audit.json](../../research/input-strategy-audit-20261027/runs/cv32e40p-rvfi-20261029/i2c-v1/retirement-audit.json)为 `verified`（`authority=false`，`grants_F5=false`，`grants_F6=false`），明确登记 `unavailable_fields=[rvfi_intr,rvfi_pc_wdata]`；`summary.json` 的 cross pending 原样保留，独立重算才报告cross verified。该结果只证明该被动四字段观察与MMIO执行复用，**不**构成IRQ接受、ISR返回或F5/F6能力，也不把未驱动字段补零。当前工作据此补齐E40真实 `irq_ack_o/irq_id_o/entry-PC/redirect` 观测及其F5/F6接入。

CV32E20主profile的通用RVFI/启动/ISA固件/nativeIRQ观测已实现，独立两进程原生CPU adapter smoke通过，见 [CPU验收](cv32e20-cpu-adapter-20261029.md)。随后 `shared-all-flows-20261029/cv32e20-v2` 同一CPU/RAM/DMA/GPIO会话八例全部通过，两F5完整ISR与两F6五义务/四字证据完整，独立新进程full fresh匹配；详见 [E20六路径验收](cv32e20-six-flow-acceptance-20261029.md)。不外推RV32E/E40 IRQ。先前性能边界校验简化已有这些后续功能回归，仍无独立同源性能A/B，不能把旧性能数字归为该改动收益。

E20公共 `shared-search-20261029/cv32e20-state-v1` original/fresh各8次在线决策完成，fresh内部/跨调用/会话边界均verified。完整selection/transitions、归一化prefix身份与实际source/进程证据已独立核验；该轨迹为F3/F4/F3/F1/F1/F5高/F6/F3，RAM关系1条，未选中F2或F5低，IRQ反馈unknown、RTL coverage unavailable。公共跨调用identity使用完整归一化投影；原始trace哈希包含真实进程nonce，不要求其字面相等。

Timer新增可选IRQ声明与公共vector-bit路由后，Ibex和CV32E20仅更换CPU配置，均原生通过CPU实际MMIO三写→Timer真实overflow pulse→host OR→native take→非零serial首handler退休，独立fresh匹配。详见 [Timer验收](timer-native-irq-adaptation-20261029.md)。范围仅该传输链，不授内部版本、完整F5/ISR消费或奖励。通用declared-output IRQ适配与SPI仅配置验证正在实现，尚不计原生通过。

- 代表性通用化适配验证已通过：Ibex/CV32E40P/CV32E20 × SPI/Timer 六个配置组合，以及 CV32E40P＋causal GPIO 独立数据流路径。未增加 CPU×IP 专用执行器；新 CPU 不因此获得尚未适配的 F5/F6 能力。详见 [支持矩阵](configuration-support-matrix-20261029.md)。
- 同一 CPU/RAM/DMA/GPIO 会话八例 F1–F6 执行及完整 fresh 重放通过，两例 F5 的真实 IRQ/ISR 证明通过。RAM/PIN 实际消费、writer 归属、覆盖与奖励去重、warm reset 后旧安装失效和 fresh 重算均有定向原生证据；范围见 [消费验收](shared-consumption-acceptance-20261029.md)，不包括 reset 后继续旧会话。
- 公共搜索入口 `shared-search-20261029/state-v4` 的 state/seed7/cases8 original/fresh 均 exit0。fresh 的内部、跨调用和会话边界检查全部 verified；实际选择 F1×2/F3×3/F4/F5/F6，认证 RAM 关系1条。未选中 F2，不能称这一随机轨迹已验证 PIN 消费；该路径 RTL coverage unavailable，IRQ 奖励 unknown。
- F6 取指完成的七次 journal 遍历合为一次同步快照，全部原校验保留。15项定向回归通过。同源码串行八例 A/B 的完整规范化前缀、38421事件、8 main/9 Session、CPU/DMA/GPIO ticks 977/1010/1023 和 eval 次数3908/4040/4092均一致；两轮完整 fresh 都匹配。
- 单次 A/B 总 wall 724.701→493.848s（下降31.85%）；campaign loop 248.372→155.593s（下降37.35%）。存在初始化缓存/顺序影响，不能将全部 wall 差归于这一修改。新方式 original＋fresh 的 DUT eval 计时仅约0.0257s；仍由宿主开销主导，**未达到初始化后主要耗时在 DUT 的效率要求**。原始证据位于 `research/input-strategy-audit-20261027/runs/shared-performance-20261029/`。
- 随后将3处“读取全部 journal 后截尾”改为已有 pinned tail API；7项定向门通过，独立 review 无阻断。新源码 `shared-performance-20261029/tail-v1` 完整八例和 full fresh exit0，实际工作字段与前轮一致；wall481.956s、campaign149.976s。该轮是集成回归，不与旧源码直接作新的因果性能比较。

详细计时与公共入口独立核验见 [本轮性能验收](shared-performance-public-entry-acceptance-20261029.md)。后续主任务是消除剩余全历史读取/复制，并继续按相同有效工作量测量稳态收益；不通过增加空转周期改善占比。更多 CPU 的 IRQ/F6、cold reset 后重装继续执行，以及更多协议属于后续能力扩展。策略优越性仍需同预算、多 seed 对照；当前单条轨迹不作该结论。

## 已有证据

- 统一配置入口和逐例选择已覆盖现有 F1/F3/mixed/F5/F6；storage/GPIO live 有实际反馈。目录见 generalization-step-20261028.md。
- F1/F3/mixed、F5、F6 原生 original/fresh 有限定场景证据；F6 两例见 online3-dma-f6。
- 模拟调度与预算回滚、实际前缀重放软件门273项通过。

## 初始未完成要求（历史，当前状态见上）

- 同一持续会话组合 F1–F6，消除独立 F5/F6 路由对跨路径状态消费的隔离。
- 将更多现有组件接入公共 protocol/flow 适配，验证组件重用而非增加CPU×IP专用实现。
- 缺失路径的当前版本/真实消费 provider；不能以提交成功或历史事件替代。
- 各策略共享实际动作目录、同预算比较、真实覆盖率测量和可重放结果的端到端验证。
- 新组件接入文档、支持矩阵和完整系统验收，应逐项以当前源码执行结果证明。
- 用户要求的稳态效率：初始化后时间主要用于真实 DUT 推进。必须在相同有效工作量下分别测量 DUT eval、调度/传输、策略和证据处理，不能靠增加空转周期改善占比。现有逐例秒级结果不满足该要求，功能接通不能关闭此项。

## 本轮推进

完整共享路径原生检查点（`runs/shared-full-20261028`，相对于研究 runs 根目录）：

- `dynamic-f4-f6-v1`：首例动态 F4(85) 已有真实取指、MMIO、RAM 证明；随后 F6 未通过。consumer/saved projector 尚将 F6 逻辑序号当作全局 testcase/物理 slot 序号，必须补齐映射校验后重新原生验收。静态退出另有 frontend/facts 漂移，已发现两真实展开器的 content_hash/modules 不同，但未复现本次运行的具体切换，不能将推测记成已证原因。
- `gpio-irq-v1`：原生 GPIO 高/低刺激获得2次 CPU IRQ acceptance 和2条精确 serial 退休关联；完整 ISR 消费/返回检查未通过。旧门错误地把该 Ibex 的 MRET RVFI pc_wdata 当架构返回目标，现按已有 F6 规则改为后继实际退休+取指响应+源字节版本，尚待新原生验收。不得将 acceptance/serial 或软件门等同完整 F5。

上述两次均保留失败，不计完整系统通过。后续运行只在全部源码冻结后启动；新的共享索引、返回证明和展开模式修复须重新验证 original/fresh。

后续真实通过检查点（不覆盖 v1 失败）：

- `shared-full-20261028/dynamic-f4-f6-v2`：公共 descriptor 在线执行 F4(85)→F6→F4(170)→F6，四例均 passed；全量 fresh matches/completed，三组件 build join complete，静态退出复核通过。F6 子账仅2例，物理/全局 slot 为0–3。旧 summary 的 execution_seconds 包含 replay，不能用141.83s计算单例性能。
- `shared-full-20261028/gpio-irq-v3`：两个真实F5高/低源分别取得完整 GPIO IRQ→CPU acceptance→serial→ISR PADIN/INTSTATUS读→RAM写→MRET真实后继取指证书；返回 PC 为69636/69652。full fresh 语义哈希匹配，irq_consumption=verified，未接策略奖励。此证据限定已适配的 Ibex RVFI 与 causal GPIO，不能推广为所有CPU已支持IRQ。
- `shared-full-20261028/mixed-cli-v1`：统一搜索入口实际选择 F4→F6→F6→F4，original/cross-invocation strict fresh 都完成4例，所有fresh verification verified。新口径 campaign 51.691s/fresh 50.062s；peripheral真实覆盖22/30，425条回复、437 ticks，plain/instrumented/录制回复一致。该路径没有认证交互计时provider，metrics仍unknown/unavailable，不虚构收益。

完整目标仍未达到：正在将F1/F2/F3与GPIO F5接入同一shared-slot执行器，并明确实现DMA/GPIO共用CPU IRQ输入的host OR组及唯一源/多源归属规则；当前通过的是两个共享切片，不能计为六flow已在一个会话汇合。稳态DUT占比目标也仍未达到。

并行审查并实施共享会话组件和有真实证据支持的反馈适配；原生运行仅由主代理在所有源码写入停止后执行。冻结后发现问题必须先通知主代理，禁止自行修改，以避免前几轮的证据失效。

本轮核查发现：mixed requirements 对同 endpoint 的操作/证据要求存在覆盖，已由子任务修复并通过限定软件回归；根定向 requirements+record feedback 10项通过。内存审计桥已实际接入，但当前 generic provider 未配置、没有合法下游 RAM read，不能作为消费闭环。正在新增受限 typed RAM-read 动作并接通原生回执；配置示例 memory-consumption-ibex.json 尚待实现及原生核验，不计入已支持路径。F5 live crosswalk 提取已进入测试，共会话接线仍未完成。

实际原生增量（shared-runtime-20261028）：新增受限 RAM read token F1:03200000，与 F3:55000000 同一持续会话执行。original campaign 明确 F3→F1，memory_read=observed，四条字节证书共享读 transaction 且各 write_event_id<read_event_id；provider=verified，reward_eligible=False。original/strict fresh 均通过。F5 通用 live crosswalk 已实际接入固定包装，原生 original/fresh 通过。根定向 memory read/record feedback/mixed requirements 门22项通过；子任务26个crosswalk用例有独立通过证据（首次联合含一项测试自身空操作，修正后单独通过），不是一次联合全绿。

RAM 证据范围仍是 modeled host RAM 经真实 DUT OBI 端口消费，尚无 live 当前版本前沿/写者 testcase 归属奖励。F5 共享会话尚未实现；通用 crosswalk 提取不是其完成证据。后续分别继续接当前版本provider及共享会话真实IRQ binding。完整目标保持active。

RAM live进一步原生证据：`runs/ram-live-20261028/state`，cases4/seed7 original 与 strict fresh 均 exit0，实际 F3/F3/F1/F1。四字节当前版本与实际writer case可查询；同值覆盖后旧writer censored；首次实际读取只结算当前writer+consumer，两参与者奖励合计2；重复读取零新奖励。根逐项断言已验证。证据范围仍是 current_installed_host_memory_bytes 与 DUT OBI 消费，不声称retirement/source指令因果。软件回归125项通过。

当前尚有输出缺口：selection记录 live-ram/transitions，但search-summary统一metrics仍为空，需要接实际事件计时和关系指标供比较。该接线已继续实施。F5共享session仍在实现，未达到系统完成条件。

RAM 统一metrics接线验收：`runs/ram-metrics-20261028/compare`，state/uniform、seed7、cases4、seconds30，两个策略original和strictfresh均exit0；primary/execution comparable，RTL coverage仍 unavailable。两者原生认证关系数均1，state首个事件6.5444s/search9.0857s，uniform首个事件6.4762s/search8.8750s。fresh独立测时分别6.5064s/6.4637s首事件，语义关系集合与各original一致。该单seed不证明效率提升。根相关软件门86项通过；代理完整门176项通过。

比较指标来自actual campaign clock，policy回放成本不当作事件时刻；无固定秒数预算的计数保留，AUC/rates不计算。当前真实缺口转向F5共享CPU/runner/IRQ/slot执行与F6公共装配；目标仍active。

F6公共装配增量：默认构造已实际使用 shared_f6_assembly.build_f6_assembly，公开F6Assembly可接受预启动同合同RAM/CPU/DMA/runner并验证对象同一性与保留区；默认路径原生 original/strict fresh 均exit0，见 `runs/f6-assembly-20261028/default`。该证据只覆盖默认factory，并不证明外部装配注入或F1–F6共会话；后两项继续实施。F5原精确CPU类物理IRQ映射与共享构造已落盘，仍待软件/原生验收；GPIO F2 consumer尚未适配，先验证F1/F4/F5合法flow。Wishbone单F4 live适配已启动，未声称F2可用。

共享装配原生进展：`runs/shared-assembly-20261028`。共享 F1/F3/F4/F5 runtime 的 F4→F5→F4（3例）和 F1→F5（2例）实际执行，full fresh 均matches且语义hash一致。该GPIO组合F2/F6仍unsupported，IRQ消费unknown；因此只证明实际共享进程/会话下的所列flow执行与回放，不是F1–F6完整统一。

同轮Wishbone单F4 live原生2例original/strictfresh exit0，authority当前值85、版本1→2，同例readback certified；重复前沿零新增奖励，relation_features为空，跨例消费unsupported。外部F6Assembly脚本真实注入外部分配RAM/service与assembly对象，original complete+fresh matches，确认接缝实际被消费；仍受F6双组件typed binding约束。

后续继续：共享F5接统一descriptor/search和kernel；GPIO F2真实read consumer；共享GPIO下复用RAM current provider及版本消费策略；F6公共多组件装配、区域/IRQ合并。目标active，不能标记完成。

当前实现中的集成缺口（尚未验收）：共享F5统一descriptor入口需要真实causal GPIO verifier/registry/bound target adapter，而不是将apb_gpio伪装成generic APB。GPIO F2默认读取PADIN(offset8,ro)，已有GPIOEN authority不能授权此字段，正在增加连续原生采样的PADIN current issuer。共享F5搜索入口、GPIO adapter和GPIO F2分别并行实现，任何源码冻结前不运行原生。

统一共享GPIO入口当前进展（尚未原生）：新增真实GPIOEN verifier/registry/bound adapter，不授予PADIN权限；GPIO/registry软件32项，最终专项4项通过。共享完整F1/F3/F4/F5 plan已从真实preparation和注册组件编译通过2项门，剩余bound kernel/统一CLI验收。配置 gpio-shared.json 和 gpio-shared-ram.json 已增加，未计为已支持直到实际运行。

GPIO F2 PADIN issuer/consumer已完成48项软件测试、2项跳过，无原生。仍待shared runtime实际启用及完整F2链原生验收；不能将软件门冒充原生数据消费。PADIN与GPIOEN字段authority保持分离。当前所有其它代理冻结，等待统一入口代理最后门完成后由root集中原生。

共享统一入口集成验收中发现并修复：GPIO bound adapter错误要求prep artifact与runtime私有snapshot为同一Python对象（改为完整内容一致并固定实际live对象）；静态退出callback访问已经close的prep（改为仅核对bind时sealed静态字节）；GPIO legacy F4 joins无write/tick字段（按实际commit tx唯一join、通过真实native sample/delivery投影）。前两修复GPIO软件6项及archive回归通过，join/effect软件79项通过。

重跑 v3-gpio-shared-ram 原生original已成功：F3/F3/F1，当前版本observed且writer可归属，第三例获1条真实消费关系，fresh仍待完成。v3-gpio-shared交错已越过kernel join但被RecordConsumptionFeedback旧F1–F4白名单拒绝F5，尚未完成；已定位，待源码冻结窗口结束后扩F5审计（不推断IRQ奖励）。不得将该失败计入通过。

共享RAM统一CLI v3 original/strictfresh均exit0（`runs/shared-entry-20261028/v3-gpio-shared-ram`），3例F3/F3/F1，当前writer可归属、真实同版本消费产生一条关系；完整replay语义一致，静态退出复核通过。交错入口v3在F5审计旧白名单拒绝后新增明确F5内存审计支持，55项测试通过，不推断IRQ消费/奖励。v4-gpio-shared original已成功，F4/F1/F1/F5，fresh待完成。

GPIO F2 已完成真实共享执行验收：`runs/gpio-f2-20261028/sequence`，F2→F4→F5→F2→F5→F2 六例同会话，full fresh matches且语义hash相同。root核查native_read.value为0/256/0，dependent RAM为1445/1189/1445，后两read的pin_origins[8]为native_pin_sample。仍不声称CPU IRQ消费/retirement，summary保持irq_consumption unknown。

自动RTL覆盖率已对当前两策略实际执行并测量：`runs/automatic-coverage-20261028/compare`，Timer state/uniform各一例，instrumented/plain完整回复相等、均35结果/41ticks，同一DUT点全集30，覆盖22/21；coverage_comparable=true。测量开销分别2.9021s/2.5926s，在搜索预算外明确记录。这是离线完整录制prefix的line/block coverage，包括启动/复位，非在线固定时间RTL AUC，也非策略优越性结论。

F6三组件软件阶段15项通过，但template schedule_order遗漏storage，原生尚未运行；修复中。完整系统仍未完成，目标active。

补记 v4-gpio-shared strictfresh 已exit0，full prefix/source/plan通过；无F2交错目录的统一CLI验收已完成。GPIOF2脚本通过后，下一步将验证统一CLI含F2目录，随后接实际F5 pin→PADIN→OBI→dependentRAM关系反馈；当前已有native pin8 action来源可证，但保存JSON本身不授予策略收益，初始first_measured_state保持unattributed，IRQ消费仍unknown。

独立复核长prefix自动覆盖率（2026-10-28）：`research/input-strategy-audit-20261027/runs/long-coverage-20261028/shared-f2/comparison.json` 的original/fresh均exit0，四例F4/F2/F2/F5。实际518回复/530ticks超过默认512命令，显式2048命令预算完整执行，无截断；recorded/plain/instrumented回复相等。保存产物验证器以可信2048预算重新核验缓存与完整测量，得到DUT点48/189，denominator SHA256 `1a236264855ee52666a676d704db207e689f84411e161878b940f1d275a6ae17`，automatic_coverage=measured。仪器化与回放3.453905s、附加验证0.173023s，总成本3.626928s，明确在搜索预算外；这是peripheral完整录制prefix离线line/block覆盖，不表示在线覆盖AUC或策略优越性。本次独立核查未运行native。详见 `docs/reports/automatic-rtl-coverage-20261028.md`。

共享入口能力扩展：generic_campaign 不再硬编码共享执行器只有 F4/F6 两条，允许包含 F4/F6 的已声明 F1–F6 子集并要求同一 compiled_f6_cpu_dma executor；各已声明 flow 可单独或混合选择。新增五flow/六flow descriptor 回归先失败于旧白名单，修复后与入口/搜索相关105项通过（3.89s）。这仅证明配置与选择入口可用，实际 lowerer/consumer/IRQ 仍须各自 typed 注册及原生证据，不计为六flow运行已完成。

共同中断保存校验增量：project_saved_irq_isr 对可选 irq_dispatch 从真实 entry 开始，逐条重建 DMA 分发路径与首条子处理器指令的 PC/字节/退休序号/回执；保存的 stage hash、子入口地址、退休列表只能与这些 raw 事实相等。默认路径不变，MRET 仍仅允许 DMA 两处，GPIO MRET 不取得 F6 权。新增纯路径7门及保存链正向/4类负控，与既有 saved 回归合计407项通过（39.13s），独立审阅通过。这是软件证据，不代替三组件共同 IRQ 的原生验收。

新增实际三组件配置目录 configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared：复用已有 Ibex RVFI、DMA、causal GPIO 请求，真实 create_preparation 已成功展开 cpu/dma/peripheral。当前 descriptor 故意仍仅声明 F1/F2/F3/F4/F6；F5 必须等 typed fixed-support binding/slot 执行接通再启用。GPIOEN 使用0x100/0x101保持 pin8 开启。尚未原生，不算六flow已通过。

共享GPIO新配置进一步软件验收：tests/integration/test_shared_gpio_dma_config.py 从checked-in配置真实展开三个artifact并通过F6能力接纳，重建共同IRQ固件，确认DMA/GPIO MRET站点隔离；与GPIO分发视图门合计2项通过（25.81s）。新增shared_gpio_irq_isr观察模块首先要求原live fixed-support凭据，再使用同一CPU/session/runner复用旧native GPIO ISR链；共同分发路径的参数化检查尚在并行接入，未原生验收，不计为完整F5。

六flow声明与验收脚本已启用：checked-in shared GPIO/DMA descriptor、supplement现在明确F1–F6；新增scripts/run_shared_all_flows.py定向在线8例F3→F1→F4→F5高→F2→F6→F5低→F6，每次选择依赖此前真实sealed完成，两F5另须irq_isr=verified。脚本控制门与全部搜索配置计划门2项通过（0.42s），未启动native。实际all6 preparation门已暴露失败：extend_shared_pin_path没有可执行F5 D3路径（shared-F5-real-path-required）；对应编译器多中断源接点在修复。前述五flow prep通过不能覆盖此六flow失败，当前不得记六flow完成。

六flow编译缺口已修并软件验收：F5评估仅在显式gpio_irq.component选择该实际GPIO producer，再保留原IRQ shape/status/externalpin校验，避免把DMA producer的缺项累计到F5；DMA合同和路由仍完整保留。代理实测test_f6_gpio_companion.py 3项通过（63.19s）：实际all6 preparation→admit→完整prepared paths回读、F5显式OR组路径与F1固定支持，以及同CPU/RAM/DMA/GPIO原类/authority/owner。该代理已冻结，尚需其余代理完成OR来源资格保存校验才能全局冻结并native。

root另对旧gpio-irq-v3保存的原生raw trace独立重建OBI beats，抽查前三条实际data memory_read，其producer_event_id均精确等于native acceptance event，value/width字段存在；确认新共同ISR逐scratch读取检查所用的实际事件边界，不以测试fixture假定代替。新facade保存字典不授live证据反例及脚本控制门3项通过（0.37s）。

新逐内存退休检查的真实档案复核：root从gpio-irq-v3原trace.json.gz独立重建native OBI beats，按原prefix中的handler_retire_events取实际退休，再把两例各14条LW/SW（含scratch保存/恢复、counter）交给当前_verify_irq_retired_memory_path；两例全部实际RAM/MMIO/OBI/RVFI joins通过。该结果是既有原生运行档案对新检查函数的离线验证，不表示共同DMA/GPIO分发器已原生运行。

F5核心软件接点已验收（代理）：真实all6 prep/group assembly/full constructor下，ScenarioSession实际fixed support接受回调与MemoryService原acceptance绑定，query明确role=fixed_support、F6_authority=false；等值外部DTO不能调用该回调授予权。该门1项通过（44.90s），全union重建/实际pin+NOP声明2项通过（13.17s）；F5加入union后前面memoryflow path_id重算已修。未跑native。

性能后续的体积证据（非时间profile）：root核查mixed-cli-v1/seed-7-state-none/original/compiled_f6_prefix.json，4例文件68,078,231 bytes；compact actual_events约17.20 MB、attempts约7.84 MB、assertion_material约7.83 MB。actual_events主类compact体积local_tick_sample约4.15 MB、step约4.01 MB、cpu_external_irq_sample约1.66 MB、fetch_completion约1.38 MB、state_dependency约1.36 MB。这些数据定位可精简的证明/事件体积，不证明各类耗时；必须结合稳态实际计时决定引用化/去重与延后导出，不能直接声称性能已改善。

集中原生验收（所有源冻结，三个handle均已terminal后才解除）：
- shared-all-flows-20261028/v1（55952，exit1）：首F3原source admission/acceptance绑定拒绝，尚未进入后续flow。真实source/map/admission均F3.program_image，而fetch binder仍仅F4取共享source，其余硬套shared_ram.image；另旧F4-only提前返回也需扩到所有非F6，防止错误发放F6 fetch凭据。失败原产物保留，不算六flow通过。
- reverse-pairs-20261028/spi-ibex-v1（69942，exit0）：同公共代码实际F4/F4/F2/F4，original与strict cross-invocation fresh各4例、所有fresh verification verified/matches。search循环8.276s/fresh7.985s；实际认证write-read关系1条。自动peripheral DUT line/block覆盖72/271，136回复/157ticks，recorded/plain/instrumented完整回复一致，覆盖附加成本3.237s在搜索预算外。
- reverse-pairs-20261028/timer-cv32-v1（21975，exit0）：同公共代码实际F4/F4/F2/F4，original/fresh各4例且全部严格验证通过。search循环6.228s/fresh6.311s；认证write-read关系1条。DUT覆盖22/30，同136回复/157ticks且完整回复一致，覆盖附加成本3.590s在预算外。
这两项是当前源码下配置换CPU/IP的真实复用证据，不借用旧历史通过；单策略单seed不证明策略优越性，也不代表稳态时间已主要用于DUT。

v2后续接线：实际GPIO F4布局由D3明确32bit寄存器值+1bit辅助引脚，必须5bytes；新验收script/catalog/descriptor已更正为GPIOEN0x100/pin0=0001000000、0x101/pin0=0101000000，真实layout编码/声明门1项通过。另发现shared execute_fragment尚未应用decoded辅助pin，正在补真实typed输入/会话映射，不能忽略尾位当作完整通用执行。

共享搜索计时已接通start_search_clock/finish_search_clock生命周期，terminal credit清算纳入campaign_loop，finish/export/replay仍独立。受控计时先暴露缺少clock回调，再修复；含在线/固定序列、零预算、记录开关、acceptance/search范围检查共15项通过、1跳过（0.41s）。RAM/PIN全目录provider仍在实现，尚不宣称统一搜索live反馈完成。

集中三项任务实际推进（全局冻结后all6v3，handle75108已exit1）：前三例F3→F1→F4全部真实passed，F4辅助pin现已实际接纳/执行；第四F5在canonical声明对比拒绝，根因compiled_f6.submit的declare_slot仍取len(session._cases)而非physical flow ledger长度，辅助case使声明slot4与实际slot3不等。必须修调用者索引，不能放宽F5地址比较。失败原产物保留；partial online_plan导出同时暴露aux序列兼容项，已交core owner修。

原生终态后已解除冻结并实作统一反馈：PIN provider纯门10通过，PinCredit显式新authenticator与共享pin_view已接、旧默认保留，新旧联合22项通过；RAMowner负责单Policy/全目录catalog、RAM+PIN合取目标与union状态，按F1/F3和F2/F5互斥归属避免双结算，F4/F6无真实关系不奖励。尚未完整接入口和原生重放，不记方法完成。

统一搜索入口已实际选用新SharedSlotSelector：显式shared_slots+typed全目录命中live-shared-ram-pin，使用同一Policy/目录/clock，RAM与PIN合取目标、family互斥credit。新增独立shared-measurements保存、原测量SHA绑定、fresh语义关系集合核验，并保持实际fresh计时与用于policy replay的原成本分开。旧RAM/PIN路径保留。preflight新门先因record-catalog失败，接线后与搜索相关44项通过（3.71s）。这仍是软件入口证据；实际安装与原生消费/重放尚待完成，不提前计闭环。

v4与统一搜索v1集中原生（两个均terminal exit1后解除freeze）：前三例均已真正执行，F5已进入真实GPIO中断/MRET。首错是native_f6_isr_return的无active-F6 guard误拒typed GPIO handler MRET，清理阶段又因fetch revoked抛unregistered issuer遮盖首错。后者已修为cleanup异常附note、保留原异常，正常drain校验不变，7项通过；MRET必须按真实共享F5来源/固定GPIO站点修分工，不可放开任意MRET或授F6凭据。v4 partial plan已不再报shape错误。

统一搜索PIN当前版本条件已修：历史完成值仅用于语义去重，不能证明current consumed；需要与已认证relation的真实writer资源/epoch等匹配。定向85项通过，尚待新原生重放。

当前实际driver计时：v4 CPU1432 eval/3.354ms，DMA1420/0.992ms，GPIO1552/0.909ms，合计5.255ms；统一search-v1同eval次数合计5.228ms。失败搜索命令94.667s含prepare/init/失败导出，不能当campaign稳态时间；这些数据仅确定native eval不是该失败流程的主要量级，不证明完整系统性能或优化收益。完整成功后须同工作量分解IPC、scheduler、proof/复制，保留tick/event/eval计数以防空转改善占比。

2026-10-29 PIN原生消费验收里程碑（pin-v1 handle81967 terminal exit0）：original/fresh各8例、两份full replay matches=True/first_difference=None，原/fresh selection.json与diagnostic-prefix-identity.json逐项相等。root独立读original_execution_audit：CPU/DMA/GPIO三组件两次PID与execution_nonce全部不同，确认独立实际进程。high/low消费各认证1条新语义关系，writer与reader各奖励1；同值新writer归属更新但语义重复零奖；重复low read亦零新奖。原execution186.613s/export42.170s/replay160.568s/wall435.632s；fresh execution186.746s/export37.159s/replay177.674s/wall429.199s。这证明PIN版本消费/归属/去重与fresh重算，不证明reset或跨DMA的GPIO跟踪不受污染。

所有native均terminal后解除全局冻结：RAM write2912/commit2913精确关联修复已apply，含真实档案与诊断回归79项通过；原生RAM修复仍待v2验收。GPIOconsumer将已注册DMA delivery误作missing target污染GPIO的问题交独立修复。性能collector在/tmp纯门5项通过；缓存微基准仅热调用下降，端到端含strict exit仍波动，尚不计提速，暂不集成候选以免混淆完整baseline。

2026-10-29 主链里程碑：v8-benchmark handle74199 terminal exit0。root核original八例complete（F1/F2/F3/F4各1、F5/F6各2），两F5 IRQ/ISR verified；full fresh replay matches/completed true、first_difference None、verification_scope full。原/fresh各8 main、9 session（含F4aux），CPU977/DMA1010/GPIO1023 ticks、38421 events及record身份一致，六个实际native进程PID与eval记录匹配。原循环311.832s、replay477.430s、整体888.703s；并发负载不同，不能当孤立提速比较。此处是within-invocation的独立新process fullfresh，不冒充cross-CLI验证。

用户改为通用化适配优先、性能后置。当前源新矩阵SPI+CV32E40P原/fresh各4case真实通过，cross-invocation/session/within verification均verified，真实DUT line/block覆盖72/271；Timer+Ibex新运行也exit0，详细关系/coverage由matrix审计继续核。现已解除freeze，正式补CV32E20+SPI/Timer以及CV32E40P+causalGPIO配置复用验证；不得添加CPU×IP专用执行器，缺IRQ/source-backed native provider的CPU明确不宣称F5/F6支持。
