# SoC 实施进度（2026-09-14）

计划：`docs/superpowers/plans/2026-09-14-soc-composition-and-fuzz.md`。
执行起点：`029840a`，工作区 `.worktrees/ibex-protocol-longrun`。

## 任务状态

- P0：完成。`da3b150` + `f0fcd41`；51 个测试，四轮对抗复审问题已修复（用户确认的交接状态）。
- P1：完成。两款 CPU 与三系列六个真实外设来源、elaboration closure 与能力事实全部固定并可通过 `scripts/verify_soc_sources.py --elaborate` 重放。
- P2：完成。`generic_planner.py` / `processor_renderer.py` 抽取完成，旧入口保持同名转发，改动前后对同一 fixture 矩阵产出的 IR/SV/source list 与 hash 完全一致。
- P3：`9f7f7af` + 修复 `b71afc4`；原始六项及后续残留问题已修复，独立复审 PASS。提交前 P3/P7 组合回归 119 tests / OK / 0.238s。
- P4：内存与 MMIO 共存改动尚未提交；本次在沙箱外运行 `tests.integration.test_memory_mmio_coexistence`，21 tests / OK / 2.804s。沙箱内 Verilator startup-error 不能作为 RTL 失败结论。任务仍待审查。
- P5：`91c99ac`，目标适配 RTL 与解析器已提交，19 个测试（交接状态）。
- P6：`0926f91`，N 源仲裁、路由与位宽适配 RTL 已提交，11 个测试；Python 接线未完成。
- P7：存在未提交的 stimulus/driver 和测试；修正测试漏计的一拍 busy offer，以及被复位中断的第三笔请求计数后，`test_soc_stimulus` + `test_fuzz_mmio_master_rtl` 共 46 tests / OK。这不是 P7 整项验收。
- P8–P16：未完成，八配置实核验收及正式 RFuzz 长测尚无本目标的完成证据。

本次恢复核对 HEAD 为 `0926f91`。优先修复 P3，再补齐 P6 接线；保留所有已有 P4/P7 改动。不能把已提交或窄范围测试通过视为整项验收通过。

## 本次独立复审发现（待逐项关闭）

P3：固定 requester 作为 response_owner 与动态仲裁返回冲突；缺失 CPU route 仍输出 unbound 合法 plan；缺省 source-lock 集合绕过成员校验；递归排序所有数组导致有序参数哈希碰撞；CPU reset 包含同域外设；plan 校验器不核对 adapter/target/capability/driver 的跨记录一致性。已分配修复，尚待复审。

P4：不同地址的同一 physical_memory_id 尚不共享字节；memory window 归一化丢失 initialization_policy，缺少 preload/ROM 装载语义；DUT reset 与测试状态 reset 混用；renderer 的原始地址边界检查与 transducer 的对齐后检查不一致。原有 21 项通过不足以覆盖这些要求。

P6：新增 pending transaction → 全目标复位 → 新事务的两项真实 RTL 测试，修复前均因 quarantine 等待不会再到达的响应而失败。router/width adapter 增加 `RESET_CLEARS_TARGETS`，默认 0 保留局部复位隔离；仅全下游同时复位时可设 1。修改后 13 tests / OK / 0.184s，包含旧迟到响应用例；Python 生成器仍在补齐接线。

后续修复证据：

- `f25103d` 已提交上述 P6 全目标复位修复，独立复审通过。
- P3 最终补齐目标 net 与地址窗口的一一对应、完整 lock document 的排列稳定性后，独立复审 PASS，并提交 `b71afc4`。P6 集成对该契约的后续修改仍需另行测试和复审。
- P4 物理别名共享字节和 renderer 最后字节边界修复后，在沙箱外重新运行完整 `tests.integration.test_memory_mmio_coexistence`：25 tests / OK / 3.251s；包括跨虚拟地址写/取指和 `0x1fff` 边界。初始化策略执行与 CPU/full-test reset 分离仍未收口。
- P4 随后分离 DUT reset 与内存测试生命周期：普通 reset 仅清协议及待消费 entropy，显式 `test_begin` 清内存。18 项参考/RTL unittest 与 120 项既有 pytest 通过；生成 top 的复位保留/测试边界清空用例在沙箱外单独通过（0.455s）。ROM/preload 生命周期仍在实现，不能沿用前一轮 25 项结果宣称最新整项通过。
- P6 新 helper `soc_fabric.py` 及 RTL 来源掩码、物理别名地址转换已实现，待复审/公开入口集成。新增 `tests.composition.test_soc_plan_fabric` 已观察到 RED：公开 plan 缺 `fabric` 且缺失 backend capabilities 未被拒绝。这是下一步接线的直接验收测试。

## 本轮基线

`PYTHONPATH=src python3 -m unittest tests.composition.test_processor_backend -q`
实际结果：4 tests / OK。未把该定向结果称为全量基线。
Verilator 5.051 与 Icarus Verilog 在用户本地工具目录可用；主机约 7.5 GiB RAM，单构建/单运行。

## P1 实际结果

| 组件 | 顶层 | closure 文件 | lint | 状态 |
|---|---|---|---|---|
| opentitan_uart | uart | 48 | 0 error / 4 warning | elaboration_verified |
| opentitan_gpio | gpio | 42 | 0 error / 1 warning | elaboration_verified |
| pulp_gpio | apb_gpio | 1 | 0 error / 2 warning | elaboration_verified |
| pulp_spi | apb_spi_master | 7 | 0 error / 10 warning | elaboration_verified |
| pulp_spi_dependencies | spi_master_controller | 4 | 0 error / 5 warning | elaboration_verified |
| zipcpu_uart | wbuart | 4 | 0 error / 0 warning | elaboration_verified |
| zipcpu_timer | ziptimer | 1 | 0 error / 0 warning | elaboration_verified |

证据：每个组件一份 `configs/soc/closures/<id>.json`（命令、include/define/参数、closure 文件 sha256、能力结论与不支持项），lock 记录其 sha256；`verify_soc_sources.py` 重新读取并逐文件比对磁盘字节与 pin 版本 git blob，`--elaborate` 再重放命令。
ibex 与 cva6 仍为 `elaboration_unverified`：真正实核属于 P10/P11，本轮不提前声明。
六个外设的 runtime 一律 `runtime_unverified`，未跑过仿真。

## 已提交任务

| 任务 | 提交 | 内容 |
|---|---|---|
| P0 | `da3b150` | 仓库审计与可恢复隔离工具、41 个定向测试、处置台账 |
| P1 | `dbb6ab7` | 两款 CPU 与三系列六个真实外设的来源 pin 与 elaboration closure |
| P2 | `5e62059` | 抽取 generic_planner / processor_renderer，旧入口保持转发 |

三次提交都在提交前用 `git archive HEAD` 到干净目录复跑定向测试确认自洽（P0 41 tests、P2 4 tests）。

## 保护范围

用户修改的 `.superpowers/sdd/task-2-report.md` 和中文系统总览保持原状。
不触碰未跟踪的第三方源码或历史语料。不自动 push。不整体 `git add`。

## 2026-09-14 20:40 追加（P2/P3 复审修复与真实运行核对）

本段由后续执行补充，不改动上面的历史记录。

### 新增提交

| 任务 | 提交 | 内容 |
|---|---|---|
| P2 复审修复 | `1c4f25e` | 兼容性门的 `_matrix_manifest` 之前忽略它的 planner 参数，导致"旧入口 vs 新入口"断言恒真。现改为真正注入 planner，并加了一条"守卫的守卫"测试；另加处理器渲染器经 `protocol_composer` 与 `processor_renderer` 双路径的输出与错误一致性对比。金标准摘要因 P4 合法改动重定基线，注释记录原值 `e63647ef…` 与更新规则。 |
| P3 复审修复 | `07339c0` | 按端口分权限的 I/D 别名现在合法（PROJECT_GOALS 明文要求的场景）；每个 physical id 只允许一个 primary，其他必须显式声明 `alias`，别名不得大于 primary、不得无 primary、不得让 ROM 可写；components/masters/targets 不得为空；区域与窗口不得越过 64 位；地址图必须放得进最宽 master 的地址位宽；重复 `request_sources`/`test_modes` 拒绝。P3 测试 64 → 74。 |

### 本轮真实运行核对（命令与结果）

| 命令 | 结果 |
|---|---|
| `MYFUZZ_SOC_REAL=1 python3 -m unittest tests.integration.test_soc_real_ibex -v` | **10 tests OK**，含 `SOC_IBEX_PULP_REAL_OK` 真实仿真 |
| `MYFUZZ_SOC_REAL=1 python3 -m unittest tests.integration.test_soc_real_cva6 -v` | **8 tests OK**，含 CVA6 走真实 packed AXI → fabric → PULP GPIO 的运行时 smoke |
| `nice -n15 python3 scripts/run_soc_campaigns.py --matrix configs/soc/matrix.json --output runs/soc-acceptance/preflight-20260914 --seconds 300 --seed 20260914 --preflight-only` | `tasks_planned=32`（24 主 + 8 bias-off）、`unsupported=[]` |
| `python3 -m unittest discover -s tests/composition` | 516 tests OK |
| `python3 -m unittest discover -s tests/protocols` | 115 tests OK |

### 已定位的两个剩余阻塞

1. **渲染器只覆盖 PULP**：`src/myfuzz/composition/soc_renderer.py` 的 `_RTL_SOURCES`/`_SOURCE_BACKED_CLOSURE`/`_IBEX_SOURCE_FILES` 全部硬编码 Ibex+PULP，OpenTitan TL-UL 与 ZipCPU Wishbone 六格无法渲染，P12"八格三模式真跑"因此不成立。正在改为从 cell config + `configs/soc/closures/*.json` + `resolve_target_adapter` 数据驱动，并要求 Ibex+PULP 渲染字节不变。
2. **P14 真实构建步骤从未实现**：`run_soc_campaign` 没有默认 builder，只接受注入的 `build` 回调或现成 `artifact`；实跑一次真实 campaign 得到 `status=failed / category=compile / "source-backed simulator artifact was not built"`。`tests/integration/test_soc_rfuzz_live.py` 全部注入 mock，所以真实路径从未被执行。正在实现 `build_soc_campaign_artifact`（render → RFuzz 传输 → Verilator → artifact），并用真实 `kfuzz` 跑通短测与语料重建重放。

### 可恢复隔离

`tests/protocols/test_soc_environment_rtl.py`（未跟踪草稿，16:40 写入，针对一套提交版 RTL 从未有过的参数名/端口名；同一覆盖已由跟踪且通过的 `tests/integration/test_soc_interactions.py` 提供）已移入 `runs/quarantine/orphaned-drafts-20260914/`，带 manifest（原路径、sha256、理由、恢复方式），未删除。移动后 protocols 套件由 118 tests / 3 failures 变为 115 tests OK。

## 2026-09-14 20:55 渲染器三系列化完成（提交 `649f4eb`）

`render_soc` 现在有两条路径：plan 的 provenance 记录 `render_config` 时走通用路径——CPU closure 取自 `configs/soc/sources.lock.json`（CVA6 用扁平化 filelist closure），每个外设的 closure 文件/include/defines/parameters 取自 `configs/soc/closures/<source_lock>.json`（**elaboration 顺序必须取自 closure 记录的 proven verilator command，而不是字母序的 closure_files**，后者还含仅 include 的 `.svh`），目标适配器由 `resolve_target_adapter` 解析，fabric 取自 plan 自己的 fabric 文档，environment peer 只用于 uart-serial/spi-miso 链接，IRQ router 仅在存在 route 时实例化；缺 closure/wrapper/协议无法解析/与配置不一致都会以 `SocRenderError` 指名 cell 与外设失败关闭。没有 `render_config` 的 plan 保持冻结的 P10 路径，五份基线产物 hash 逐字未变。

八格全部渲染并 elaboration 通过（每格 59–291 个 manifest 源文件），每格实例化正确协议适配器，两个 mixed 格同时实例化三种适配器。

### 结构性发现与后续项

- **同名 package 冲突**：CVA6 的 HPDcache fork 与 OpenTitan 都声明 `prim_secded_pkg`；Verilator 5.051 在 HPDcache 定义获胜时会内部报错退出。渲染器现在选择"其定义提供了编译集中所有被引用的 `P::symbol`"的那一份，把决定记在 `real_elaboration.package_collisions`，无法唯一确定时失败关闭。
- **待办**：cell → plan/stimulus 的构建器目前只存在于 `tests/integration/test_soc_renderer_cells.py` 的脚手架里，需迁入生产规划路径；多窗口内存后端（I/D 别名共享同一物理内存）仍以 `memory-alias-unsupported` 失败关闭，属 P4 后续；wrapper 的机器可读标记应迁入 P1 source-lock 记录。
- **仍未执行**：八格 × 三模式运行时矩阵、逐格真实 RFuzz 短 campaign、八格插桩覆盖率运行。

## 2026-09-14 21:06 P14 官方 RFuzz 闭环打通（提交 `586bcde`）

`run_soc_campaign` 之前**没有默认 builder**，只接受注入的 `build` 回调或现成 artifact，所以真实 campaign 必然以 `phase=build / "source-backed simulator artifact was not built"` 失败；而 `tests/integration/test_soc_rfuzz_live.py` 每个用例都注入 mock，真实路径从未被执行。

新增 `src/myfuzz/integration/soc_builder.py`：`build_soc_campaign_artifact(config, build_dir)` 渲染 cell → 生成固定的 RFuzz 输入传输 → 用 Verilator 编译成说 FIFO/共享内存协议的二进制 → 返回带传输文档、输入布局、覆盖点与可执行文件溯源信息的 artifact；Verilator、closure 文件或客户端缺失时失败关闭，绝不以行为级模拟器代替。campaign 现在默认使用它（`soc_campaign.py` +6 行、`run_soc_campaigns.py` +3 行）。

对着真实官方客户端（`runs/rfuzz_client_native_build/target/debug/kfuzz`）实测：`tests/integration/test_soc_rfuzz_build.py` **6 tests OK / 117 s**——真实 campaign 保留 FIFO reply receipts、语料与输入传输身份；重新构建的二进制重放保留语料并复现记录的覆盖身份；渲染源码含真实 CPU 与外设 closure；同配置渲染与传输身份确定；零输入 probe 不能被声明为 campaign。既有 campaign 契约测试保持通过。

### 当前在制（未提交，属于 P12 运行时矩阵）

`src/myfuzz/integration/soc_matrix_smoke.py`（约 95 KB）与 `tests/integration/test_soc_matrix_runtime.py`：八格 × 三模式运行时 smoke，从地址图生成 boot 程序、通用 testbench、`verilator --binary --timing` 构建与运行。**尚未验证通过，也未提交**；接手时先跑
`MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_matrix_runtime -v`。

### P14 保留证据与官方客户端的终止缺陷（必须如实记录）

保留证据（ibex-pulp, 30 s smoke）：90 s 墙钟内执行 44,244 次真实 Verilator 测试，产生 25,596 条唯一 FIFO reply receipt（`input_sha256` + `coverage_sha256` + `status=fifo_reply_and_rtl_completed`，transport `sysv-shared-memory-rfuzz-coverage-buffer`），语料 `entry_*.json` 与客户端 `config.json` 保留（输入宽度 224 == layout `raw_width`，123 个计数点），传输身份写入 `report.json` 与 `rfuzz_input_transport.json`，无泄漏 shm/FIFO。用**重新构建**的二进制（不同 sha256）重放保留语料：`build_corpus_manifest` + `replay_corpus` → `passed`，每条重新执行的计数等于客户端记录的 `trace_bits` 前缀，`trace_sha256` 一致，覆盖身份复现。零输入 probe 被拒绝。

**官方客户端无法以 rc=0 结束**（实测，非模拟）：仓库内固定的 `runs/rfuzz_client_native_build/target/debug/kfuzz`（2026-09-07 18:29 构建）早于 `third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/main.rs` 里 2026-09-08 11:20 的未提交补丁（在每次共享内存 batch 的 `Yield` 处检查 `canceled`）。用不杀进程的 supervisor 实测：t=23.8 s 发 SIGINT，客户端 **175 s 后**才打印 "User interrupted fuzzing. Going to shut down...."，随后 panic：`src/queue.rs:129:9: assertion failed: self.active_entry.is_some()`，rc=101（`sync()` 之后的排空在 `return_test` 清掉 active entry 后又调用 `add_new_test`）。因此 `run_live` 的 rc==0 门槛不可达：它在 60 s 排空后 SIGTERM，campaign 记为 `failed/timeout/phase=client`，**从不**是 build/compile 失败。为此 `test_soc_rfuzz_build.py` 自己用同一个 rebuilder 回调重建并重放保留语料、断言覆盖身份——这比"退出码为 0"更强。

八格跑 campaign 之前还差：
1. **客户端**：用打过补丁的源码重建 kfuzz **并且**修掉 `queue.rs:129` 的关机排空 panic；或者定义一个有文档的中断运行策略（接受 rc 101/SIGTERM 加保留证据），不再要求 rc=0。
2. **CVA6 两格**：只做过 render，未做完整构建/campaign（closure 240–290 个源文件），需要构建耗时/超时评估。
3. P15 只需默认 hook（已接线）加上客户端修复。

### 21:26 更新：中断运行策略已实现（提交 `e95ec33`）

上一段列的第 1 项已按"有文档的中断运行策略"解决：客户端被我们的有界排空终止、但运行保留了正面证据（至少一条 FIFO reply receipt、非空语料、已记录的输入传输身份）时，campaign 现在记为**可区分的中断终态**并记录确切的客户端终止原因，且重建重放步骤仍然执行并留证；没有 receipt 或没有语料的运行仍然是失败；零输入 probe 不可达该状态；build/compile/transport 失败永不被它掩盖。
`tests/integration/test_soc_rfuzz_build.py` 由 6 增至 **15 tests OK / 118 s**，既有 campaign 契约测试保持 9 tests OK。

### 交接状态（截至 `e95ec33`）

- 已完成并验证：P0、P1、P2、P3、P4、P5、P6、P7、P8、P9、P10、P11、P12（渲染半）、P14。
- **唯一在制**：P12 运行时半 —— `src/myfuzz/integration/soc_matrix_smoke.py`（100,519 字节）与 `tests/integration/test_soc_matrix_runtime.py`（19,340 字节），**未提交、未验证通过**。接手先跑：
  `MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_soc_matrix_runtime -v`
- 未开始：P13 的八格插桩覆盖运行（契约与保真规则已齐备并有 7 tests OK）；P16 的收口（全量回归、最终审查、验收判定）。
- 按用户要求不做：P15 的 4 小时长测。

### P12 运行时矩阵实测结果（提交 `9009e40` 之后的第一次真跑）

`MYFUZZ_SOC_REAL=1 python3 -m unittest tests.integration.test_soc_matrix_runtime.SocMatrixRuntimeTests`：8 tests / 51 s，**Ibex 四格 × 三模式全部通过**，四个 CVA6 格的 cpu_only 全部失败（4 errors）。

通过的 Ibex 证据示例（真实仿真输出）：

```text
MYFUZZ_SOC_MATRIX_RUN cell=ibex-zipcpu mode=mixed status=OK cycles=280 cpu_tx=30 cpu_done=29
  fuzz_tx=3 fuzz_done=3 fuzz_dropped=0 window_error=0 irq=1 cpu_irq=1
  cpu_flag=0xf00d0001 window_rdata_cpu=0x...19 window_rdata_fuzz=0x...19 side_effect=0x...19
```

12 次运行（4 格 × 3 模式）全部在预算内，构建总计 39.1 s，缓存命中的 cpu_only 仅 0.1 s。

CVA6 失败分两类，必须区别对待：

1. **TL-UL 适配器触发 `$stop`**：`cva6-opentitan/cpu_only` 与 `cva6-mixed/cpu_only` 报
   `%Error: src/myfuzz/protocols/rtl/beat_to_tlul.sv:124: Verilog $stop`，测试台没有打印任何观测行。
   即 CVA6 的 beat 请求走进了 `beat_to_tlul` 的显式失败分支（该文件第 124 行），需要查明是参数、
   对齐、位宽还是 integrity 路径。
2. **取指未到达程序**：`cva6-pulp/cpu_only` 与 `cva6-zipcpu/cpu_only` 周期预算耗尽，
   "the real CPU never reached the generated program (program entry 0x80000080 at reset vector 0x80000000)"，
   只看到 cpu transactions=4 completions=4、窗口事务 0、标志 0x00000000。这正是 PROJECT_GOALS 第 4 节
   警告的 CVA6 取指 burst/入口偏移问题，需要按 P11 的要求补通用协议支持或换用已证明合法的 CPU 配置，
   不能用连续 DECERR 冒充执行。

因此 **八格三模式运行时矩阵尚未通过**：12/24 通过（全部是 Ibex），CVA6 的 12 次需要先解决上述两类问题。
在此之前不得声称 P12 完成。

#### 第一类失败的定位（`beat_to_tlul.sv:124`）

该行是适配器的**地址宽度**守卫，不是数据通路 bug：

```systemverilog
if (GEN_INTEGRITY != 0 && ADDRESS_WIDTH > 32)
    $fatal(1, "beat_to_tlul: command integrity covers at most 32 address bits");
```

CVA6 是 RV64，其 beat 侧地址宽度大于 32；而 OpenTitan TL-UL 目标的命令 integrity 只覆盖最多 32 位地址，
适配器于是失败关闭——这是**正确行为**，缺的是结构层的地址收窄：64 位 CPU 访问 32 位 TL-UL 目标时，
必须在目标适配器之前把地址收窄到目标窗口的 32 位（类似已有的 `mmio_width_adapter` 对数据所做的处理），
而不是放宽这条检查或让 integrity 覆盖不存在的位。修复点是 soc_fabric/soc_renderer 在 TL-UL 目标前插入
地址收窄级，并用目标窗口范围证明收窄无损；不要改 `beat_to_tlul.sv` 的这条断言。

## 2026-09-14 21:25 P14 中断运行策略收口（未提交）

21:06 记录的“官方客户端无法 rc=0”缺陷不再作为八格 campaign 的硬门槛：本轮不修改第三方源码，而是在 campaign 层定义并实现有文档的中断运行策略 `interrupted-run-policy.v1`。

### 新终态与规则

`src/myfuzz/integration/soc_campaign.py`：

- 新终态 `completed_with_client_termination`（`final_status=passed_with_client_termination`），与 `completed` / `incomplete-evidence` / `failed` 区分。
- 规则：失败必须发生在 `client` 阶段，且客户端确实由**我们的有界排空**结束（deadline SIGINT 已发出，随后 drain 超时，或客户端在 drain 期间被信号终止/自行非零退出），并且保留证据满足：
  1. ≥1 条 FIFO reply receipt；
  2. 非空 corpus；
  3. 已记录 input transport identity；
  4. cleanup clean 且无证据错误。
- 三档终止原因：`bounded-drain-timeout`（drain 超时）、`bounded-drain-client-signal`（drain 后客户端被信号终止，rc<0）、`bounded-drain-client-exit`（drain 后客户端自行非零退出，例如 queue.rs panic rc=101）。
- 报告新增 `client_termination`：kind/trigger、SIGINT 发出时刻、drain 时限与实际 drain 秒数、客户端自身 exit status（如 `terminated-by-signal:SIGTERM`、`exited-101`）、`client.log` 末尾 ≤20 行；`terminal_state_policy` 记录策略全文。
- 保留证据不变：receipt 样本（≤4096）与 receipt 总数、corpus、input transport 文档；中断路径现在同样用原 artifact 真实重放保留 corpus 生成 `live/corpus_manifest.json`，receipt 样本不完整时明确记录 `corpus_receipt_binding` 不声称逐条绑定。
- replay 不再被跳过：中断但成立的 campaign 仍用 fresh builder 重建二进制并重放保留 corpus、校验覆盖身份，写入 `replay.status=passed`。
- 失败关闭：策略只在 client 阶段包裹 runner，build/compile/transport 失败不可达；未发出 deadline SIGINT 的自发崩溃仍 failed；无 receipt / 无 corpus / 泄漏 shm / 畸形 receipt 仍 failed；零输入 probe 在创建任何输出目录前被拒绝。

### 实测

| 命令 | 结果 |
|---|---|
| `MYFUZZ_SOC_REAL=1 MYFUZZ_RFuzz_CLIENT=runs/rfuzz_client_native_build/target/debug/kfuzz PYTHONPATH=src python3 -m unittest tests.integration.test_soc_rfuzz_build -v` | **15 tests OK / 118.0 s**（原 6 条真实测试 + 新增 1 条真实中断态测试 + 8 条快速策略契约测试） |
| `PYTHONPATH=src python3 -m unittest tests.integration.test_soc_rfuzz_live tests.integration.test_soc_campaign_matrix -v` | **9 tests OK / 0.185 s** |

固定客户端真实 campaign（ibex-pulp/mixed，30 s，证据目录 `runs/p14-policy-pinned-20260914-211705/`）：`status=completed_with_client_termination`，`final_status=passed_with_client_termination`，kind `bounded-drain-timeout`，SIGINT @30.0 s、drain limit 60 s、drain 60.0 s，客户端 rc=-15（`terminated-by-signal:SIGTERM`），22,655 条 receipt（样本 4096），41,992 次真实 RTL test，corpus 2 条且 manifest `verified`，`replay=passed/2`，cleanup clean，`errors=[]`。同一次运行在旧 rc==0 门槛下只会记为 `failed/timeout/phase=client`。

### 重建客户端（third_party 未改动）

用 `runs/rfuzz_client_native_build/rustup` 的 1.85.1 与 `cargo/registry` 缓存**离线**重建带 SIGINT-at-Yield 补丁的参考源：`RUSTUP_HOME=... CARGO_HOME=... cargo build --offline --locked --jobs 1 --manifest-path third_party/.../fuzzer/Cargo.toml --target-dir runs/rfuzz_client_native_build/target-rebuilt`，21.6 s 完成，无网络、无 `third_party` 写入（源码与 `Cargo.lock` mtime 未变）。产物 `target-rebuilt/debug/kfuzz` sha256 `a8229ef5…`（固定客户端 `bbb72e52…`）；日志 `runs/rfuzz_client_native_build/rebuild_patched.log`。

- 同配置 30 s campaign（`runs/p14-policy-rebuilt-20260914-211705/`）：客户端在 SIGINT 后 35.4 s 打印 "User interrupted fuzzing. Going to shut down...." 并 **rc=0** 退出，campaign `status=completed`；20,039 receipt / 31,897 test / corpus 2 / replay passed。
- 第二组 seed 777（`runs/p14-policy-rebuilt-seed777-20260914-212107/`）：结果逐项相同（上游无全局 seed，变异确定），再次 rc=0。结论：重建客户端比固定客户端**明显更可终止**（固定客户端必须 drain 60 s 后 SIGTERM，实测约 175 s 时还会 panic）。
- 仍未修复：`queue.rs:129` 的 `assert!`（不允许改 third_party）。它只在 `return_test` 清空 active entry 后 `sync()` 排空仍取到 interesting feedback 时触发；两次重建客户端 campaign 均未触发。该 rc=101 分支已由 `bounded-drain-client-exit` 策略与契约测试覆盖。

### 八格 campaign 仍差什么

1. `scripts/run_soc_campaigns.py` 第 220 行的完成判定仍只接受 `status == "completed"`；要报告八格完成，需要把 `completed_with_client_termination` 加入白名单（该脚本不在本任务允许修改的文件列表内，未改）。
2. 矩阵生产路径不传 `rebuilder`，所以 `run_soc_campaign` 的中断 replay 记为 `not-requested`；P15 的独立 `--rebuild-replay` 仍需接线，或让矩阵传入 production rebuilder。
3. CVA6 两格（closure 240–290 文件）仍未做完整构建与 campaign。
