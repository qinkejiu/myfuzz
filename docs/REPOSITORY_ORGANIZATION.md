# 项目代码与文件整理台账

## 2026-10-08 第一步 P1–P5 归档

代码、文档、配置／测试和复核输出分别保存至 `archive/development/first-step-p1-p5/20261008/` 的四个压缩包；逐文件原路径、职责分类、内容 SHA-256 和 Git 状态随包保存。归档说明见[第一步归档入口](reproduction/first-step-archive-20261008.md)。当前代码、冻结运行与第三方源码保留原位；源文件快照包括未提交内容，构建缓存按清单规则排除。恢复到新空目录并核对清单，避免覆盖当前工作。

## 2026-10-06 当前方案清理边界

当前主方案见 [`CURRENT_DESIGN.md`](CURRENT_DESIGN.md)：总控环境在独立 CPU/IP harness 中运行连续 testcase，输入以程序内存、外部环境源或中断场景表达；Router/Scheduler 传递真实输出并保持跨周期状态。当前实现状态见 [`LOCAL_HARNESS_RUNTIME.md`](LOCAL_HARNESS_RUNTIME.md)。

### 当前保留范围

- `src/myfuzz/scenario/`：Genome、依赖图、Router、Scheduler、持久状态、checker、反馈和 replay。
- `src/myfuzz/local_harness/`：真实 CPU/IP 的独立 session、协议适配和 harness 生成。
- `src/myfuzz/protocols/`：协议模板、局部协议适配器和可复用 peer/checker。
- `configs/cpus/`、`configs/peripherals/`、`third_party/`：当前已登记的真实 CPU/IP profile、源码闭包与构建依赖。
- 相关 tests、accepted evidence、replay factories 和报告：用于证明组合能力与源码身份，不能因为日期较早或未被当前导航列出就删除。

### 隔离与待审范围

- `configs/soc/`、`scripts/generate_soc.py`、`scripts/run_soc_campaigns.py`、`integration/soc_builder.py` 和 `composition/soc_*` 属于完整 SoC 生成路线；它不定义当前独立 harness 方案。清理前需审计其测试、配置、报告和导入边界。
- `composition/` 目录包含被独立 harness 复用的源码抓取、profile、接口事实、端口 disposition 和协议资料。文件名含 `soc` 或目录名含 `composition` 不能作为删除依据。
- `docs/PROJECT_GOALS.md`、旧 SoC 组合计划和报告保留为历史证据，不再作为当前目标入口；当前入口为 [`docs/README.md`](README.md) 与 [`CURRENT_DESIGN.md`](CURRENT_DESIGN.md)。
- `runs/`、`.downloads/`、`.worktrees/`、`third_party/` 不做目录级清空。它们分别包含验收证据、下载依赖、未登记工作副本或真实 RTL。
- 删除或移动候选项必须记录路径、Git 状态、用途、引用扫描、SHA-256、恢复目标；有未提交内容或无法证明无依赖时保留原位。

### 当前工作区快照

清理开始前对 tracked diff、untracked 文件和 Git 状态做了外部快照：`/home/qinkejiu/myfuzz-cleanup-backup-20261006.MjDhe4/`。本工作区原有修改和新增文件均属于保留范围，后续清理不得覆盖它们。

本轮已将下列与 RTL fuzz 主线无关且无代码/测试/配置调用点的脚本移出项目；原始内容、执行权限和 SHA-256 保存在外部快照的 `excluded-files/` 与 `excluded-files-manifest.json` 中：三个早期 `scripts/codegen/generate_*_harness.py` 原型，以及 `scripts/delete_codex_conversations_for_workspace.py`、`scripts/maintenance/clear_codex_history.py`。恢复时按 manifest 中的 `source` 和 `backup` 字段还原。root trace 与 Word sidecar 按先前保留规则继续留在工作区。

## 2026-09-28 根目录与验收目录整理

本轮仅调整三个已核对文件的位置；移动前后内容哈希一致，原路径、目标路径、大小与哈希见 `runs/quarantine/folder-organize-20260928/manifest.json`。根目录新生成的 `trace_hart_0.dasm` 移入该批次的 `files/`，可按 README 恢复。OpenTitan source-lock 补丁和 Git 准备清单从 `runs/scenario/acceptance/` 移入 `patches/opentitan/`；清单中的补丁路径以及相关报告引用同步更新。临时索引门禁结果继续放在验收目录，Git 索引和提交留待后续处理。

根目录交接文档仍有示例和测试按原路径引用，且与 `docs/handover/` 版本内容不同；`SoC内部数据流动与去向.docx` 是用户提供的原件。本轮保留这些入口，不合并、不删除。`configs/`、`src/`、`tests/`、`third_party/` 和已有场景验收包均未移动。

## 2026-09-14 历史整理记录

以下工作区、分支、目录状态和 P0/P2 编号是当日快照；2026-10-06 的实际工作区状态与清理边界以上文为准。

日期：2026-09-14。当轮已执行文档入口整理；代码迁移在当时实施计划 P0/P2 中按验证门禁逐项执行。

## 工作区与所有权

- 根目录 `/home/qinkejiu/myfuzz`：当前活动 checkout，分支 `fix/soc-production-path`；SoC 自动组合、RFuzz 输入链和中断说明均在此工作树。
- `.worktrees/`：目录当前为空；`git worktree list` 仅登记根目录这一棵工作树。保留目录本身，不把未登记的内容自动视作可删除文件。
- `third_party/rfuzz/upstream/ibex` 有未跟踪状态；保留，不在本轮清理。
- 当前已知用户修改：`.superpowers/sdd/task-2-report.md`、`docs/系统总览与RFuzz约束组合示例_20260909.md`。本轮不覆盖。
- 未跟踪 `third_party/` 含上游源码及实核证据；不因 untracked 就视为缓存。

## 路径处置表

| 路径 | 职责/现状 | 处置 |
|---|---|---|
| src/myfuzz/frontend、scripts/source_branch_instrumenter.py | 前端、插桩 | 保留，接入新 top 的 CPU/IP 内部覆盖 |
| src/myfuzz/composition/source_*、interface_description.py、endpoint_capabilities.py | 来源与接口事实 | 保留复用 |
| composition/auto.py | 老 catalog 与 generic planning 混合 | P2 抽取 generic planner，旧入口兼容委托 |
| composition/protocol_composer.py | 老 wrapper、generic、processor renderer 混合 | P2 抽取 renderer，再改动新行为 |
| composition/contract_transducer.py、coherent_memory.py、transducer_rtl.py | 指令/内存与总线语义 | P4 限定为内存目标，保留版本化旧模式 |
| composition/processor_*、protocols/rtl | CPU 边界和协议后端 | 保留；新增 target-side adapter 与 N 源仲裁 |
| integration/real_cpu_campaign.py | 旧单 personality 契约模式 | 保留旧复现入口；新 campaign 单独实现 |
| integration/rfuzz_*.py | 官方 RFuzz 传输与执行 | 复用，新增 harness 接入及覆盖证据 |
| configs/designs/*scheme*、toy/common IP | 历史实验、fixture | 标为 legacy/fixture；不得计入真实系列验收 |
| configs/cpus | 既有 profile 混有 reference-only 模板 | P1 检查 source-backed 可用性；状态来自验证结果 |
| docs/reports、ALL_TEST_RESULTS_MASTER.md | 历史证据 | 保留、追加；新结论注明源码 hash |
| docs/superpowers/plans/2026-07-*、2026-09-0* | 旧计划 | 历史参考；当前目标由 CURRENT_DESIGN.md 与 2026-10-06 当前实施计划定义 |
| runs、artifacts | 可再生产物和保留证据 | 逐目录分类；语料、pin、报告、失败记录先归档 |
| projects、根目录 PPTX、Zone.Identifier | 用户素材 | 保留；不属于 fuzz 运行代码候选 |
| Codex workspace-management scripts | 独立工具；2026-10-06 用户要求仅保留当前系统相关文件 | 原件可恢复副本已移至仓库外清理快照 |

## 清理执行规则

1. 先建立精确路径清单：tracked/untracked、大小、用途、引用、所属任务、可重建命令与处置理由。
2. 检查 Python import、CLI、配置 source/filelist、文档命令和保留语料重建依赖。无引用不是删除充分证据。
3. 优先更新入口、抽取职责和保留兼容 wrapper。每次迁移一个职责，不混入协议行为变更。
4. 可移除产物先移入 `runs/quarantine/<batch>/`，记录原路径、目标、内容 hash 与恢复方式；默认不永久删除。
5. 第三方源码、脏文件、用户素材和未合并工作树不自动隔离。依赖失效、回归失败则停止本批迁移并按映射恢复。
6. 完成时列出实际迁移/删除清单。P0 之前本轮实际迁移与删除数量均为零；P0 第一批隔离见下节。

## P0 第一批可恢复整理（2026-09-14）

工具：`scripts/audit_repository.py`（只读审计 + 可恢复隔离），定向测试 `tests/test_repository_audit.py`（20 tests）。
批次清单：`runs/repository-audit/<批次>/inventory.json`、`.../quarantine-candidates.json`（`runs/` 不跟踪）。

审计口径（全部满足才标记 eligible）：

1. 命中启用的可重建规则：cache 目录下的编译字节码（`__pycache__/*.pyc|pyo` 等），本批只启用这一条；
2. git 未跟踪；
3. 路径没有任何一段是 symlink，且真实解析后仍在工作区内；
4. 没有任何 tracked/untracked 文本文件引用该路径或所在 cache 目录（本工具自己的清单文件除外）；
5. 其源文件已跟踪、在磁盘上存在且无未提交改动（dirty/staged 都保留）；
6. 字节码头部记录的时间戳与大小仍与源文件一致，且不使用 checked-hash 失效模式（无法在不重编译的前提下确认，一律保留）。

执行 `--apply` 时会重新跑一次审计：审计之后才变脏、才被引用、才过期或失去 pin 的路径会被拒绝，不会按旧结论移动。
目标目录在移动前一次性建好，移动中途失败会把整批回滚，清单在每个文件移动后即时更新，因此恢复依据始终存在。

实际结果：

| 阶段 | 清单 | 结果 |
|---|---|---|
| 首次审计 | 2969 条（2766 keep / 203 eligible） | 见 `runs/repository-audit/P0-20260914/` |
| 批次 `P0-20260914` | 隔离 203 | 往返验证用，已全部恢复，清单状态 `restored` |
| 批次 `P0-20260914-applied` | 再次隔离同一 203 | 203 `moved` |
| 复核后审计 | 2869 条（2771 keep / 98 eligible） | 见 `runs/repository-audit/P0-20260914-final/` |
| 批次 `P0-20260914-applied-2` | 隔离 98（P2 重构与测试运行重新生成的缓存） | 98 `moved` |
| 加固后审计 | 3318 条（3209 keep / 109 eligible） | 见 `runs/repository-audit/P0-final-20260914/` |
| 批次 `P0-20260914-applied-3` | 隔离 109 | 109 `moved`；之后审计 eligible 为 0 |

恢复方式：`PYTHONPATH=src python3 scripts/audit_repository.py --restore runs/quarantine/<批次>/manifest.json`。

## 根目录临时文件整理与 Verilog 插装核查（2026-09-25）

清理遵循“重要记录可恢复、可重建缓存才删除”。既有 `third_party/rfuzz/upstream/ibex` 未跟踪内容保留，不纳入本轮提交。插装核查发现的代码问题已修复，具体修改与验证边界见审计报告。

- `tmp/` 整体移入 `archive/development/rtl-composition-probes-20260925/`；脚本、规格、生成 SoC、探针输出与日志均保留，目录内 README 说明内容。
- 根目录七个 `camp-*` 失败试验报告、`.scratch` 日志和 7 个过期 `.myfuzz-elaboration-*` 快照移入 `runs/quarantine/folder-organize-20260925/`；该目录 README 与 `manifest.json` 记录来源、恢复路径和逐文件哈希，可核对并恢复。
- 删除了 2 个 `.myfuzz-driver-*` 测试构建目录、2 个含纯 test-double 身份和 `exit 0` 假模拟器的泄漏 `.myfuzz-irq-evidence-*` 测试目录、工作区 Python `__pycache__`、`.pytest_cache`、空 `.vlog-*` 目录及 `trace_hart_0.dasm`。这些内容均被忽略且未跟踪；保留 `.downloads/`、`runs/` 既有结果、`archive/`、`deliverables/`、`.superpowers/`、第三方源码/工具链和 frontend 已构建库。
- 插装核查结论见[Verilog/SystemVerilog 插装审计](reports/verilog-instrumenter-audit-20260925.md)：输出目录覆盖保护、legacy testcase 隔离、多个 coverage top 的拒绝策略及插装缓存身份绑定均已修复。当前仍只支持有验证证据的 RTL 子集，不宣称完整 SystemVerilog 支持。
- 定向验证：80 项插装、仿真器、SoC coverage 与 profile 构建测试通过；另有两项真实 profile Verilator 5.020 测试通过。legacy `ibex-pulp` artifact 的真实编译仍被 `prim_secded_pkg` 源码闭包/可见顺序问题阻挡；默认 `test_soc_coverage_run` 有 4 项因未设置 `MYFUZZ_SOC_REAL=1` 跳过。详见审计报告。

清单每条含精确相对路径、恢复路径、stored_path、sha256、大小、理由与状态。恢复前整体校验：工作区不匹配、stored_path 不在本批次目录内、内容被改写、目标已存在或目标已被 git 跟踪都会拒绝，且不移动任何文件。

往返证据：隔离 203 → 恢复 203（逐文件 sha256 与大小比对，0 处不一致）→ 重新审计再次得到 203 eligible → 重新隔离。
实际删除数量为零。编译缓存在每次 import 后会重新生成，因此这一步是可重复的日常清理，不是一次性删除。

独立复审记录（每轮都用一次性 /tmp 仓库复现，未修改工作区）：

- 第 1 轮 FAIL：symlink 父目录逃逸、`runs/` 为 symlink 导致不可恢复、cache 形状 symlink 被标 eligible、源文件未验证是否 tracked、`--apply` 不复核审计结论、移动失败可能无清单、restore 可改写 tracked 文件。
- 第 2 轮 FAIL：store 内更深一层 symlink 逃逸、restore 非原子、git pathspec 少了 `:` 前缀、manifest 自引用、marker 文本遮蔽真实引用、裸文件名与 `.pyo` 检测缺失、in-tree 选择文件自锁、`--apply` 缺 `--batch` 报错误导、`--restore` 忽略其他参数、`planned` 状态不可恢复、移动期 TOCTOU、双重失败抛裸 OSError。
- 第 3 轮 FAIL：悬空 manifest symlink 与 `runs/repository-audit` symlink 仍可写出工作区、restore 崩溃窗口死锁、`rollback-failed` 对 restore 不可见、合法 JSON 的 `schema_version` 为列表时抛未捕获 TypeError、manifest 写入非原子、引用扫描的后缀白名单与 4 MiB 上限漏检、裸 `__pycache__` 字符串过度绑定、pre-move OSError 未包装、失败 `--apply` 烧掉批次名、`--apply` 时 `--output` 被忽略、.pyc 头部检查读整文件、移动时未复核源文件状态。

上述三批问题全部修复。加固要点：工具自有的每条写入路径都经过逐层 symlink 检查并使用临时文件 + `os.replace` 原子替换；`restore` 只在移动成功后改状态，并对"已回到原位但清单未更新"做对账，`rollback-failed` 与崩溃残留都仍可恢复；引用扫描改为遍历全部 tracked/untracked 文件（二进制探测 + 32 MiB 上限，不再依赖扩展名白名单），目录引用改为整 token 匹配，工具自身产物用 schema 加条目结构双重判定；审计结论在真正移动前再取一次，逐文件移动时重新解析并重新哈希。

定向测试 `tests/test_repository_audit.py` 由 9 个增至 52 个，覆盖上述全部拒绝与恢复路径。

## P16 第二批可恢复整理（2026-09-14）

按 P0 的同一口径再次只读审计并处理可证明可重建、未被引用的缓存：

| 阶段 | 清单 | 结果 |
|---|---|---|
| 第二批审计 | 3467 条（3269 keep / 198 eligible） | 见 `runs/repository-audit/P16-batch2/` |
| 批次 `P16-batch2` | 隔离 198 | 198 `moved` |
| 隔离后审计 | 3269 条，eligible 为 0 | `runs/repository-audit/P16-batch2-post/inventory.json` |

隔离总账（全部可逐条恢复，实际删除数量为零）：

| 批次 | 条目 | 状态 |
|---|---|---|
| `P0-20260914-roundtrip-evidence` | 203 | 往返验证后已全部 `restored` |
| `P0-20260914-applied` | 203 | `moved` |
| `P0-20260914-applied-2` | 98 | `moved` |
| `P0-20260914-applied-3` | 109 | `moved` |
| `P16-batch2` | 198 | `moved` |
| `orphaned-drafts-20260914` | 1 | `moved`（见下） |

恢复方式：`PYTHONPATH=src python3 scripts/audit_repository.py --restore runs/quarantine/<批次>/manifest.json`。

批次写入约定：`--quarantine-list` 写到批次目录之外（例如 `runs/repository-audit/selections/<name>.json`），再由 `--apply <selection> --batch <name>` 生成该批次的 `inventory.json`、`quarantine-candidates.json` 与 manifest；工具自有的写入路径受保护，不会覆盖已存在的批次产物或隔离清单。

### 孤儿草稿隔离

`tests/protocols/test_soc_environment_rtl.py`：未跟踪草稿（16:40 写入），针对一套提交版 RTL 从未有过的参数名与端口名（`CLOCKS_PER_BIT`/`DATA_BITS`/`MSB_FIRST`/`ID_WIDTH`/`SOURCE_PRIORITY`、无前缀端口）。同一覆盖已由跟踪且通过的 `tests/integration/test_soc_interactions.py`（真实 Icarus 仿真，三个 peer 模块 + 交互监控）提供。已按"精确清单 + 可恢复隔离"移入 `runs/quarantine/orphaned-drafts-20260914/`，manifest 记录原路径、sha256、大小、理由与恢复方式，未删除。移动后 `tests/protocols` 由 118 tests / 3 failures 变为 115 tests OK。
