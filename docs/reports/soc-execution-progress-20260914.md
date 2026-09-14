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
