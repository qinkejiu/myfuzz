# 项目代码与文件整理台账

日期：2026-09-14。本轮已执行文档入口整理；代码迁移在实施计划 P0/P2 中按验证门禁逐项执行。

## 工作区与所有权

- 根目录 `/home/qinkejiu/myfuzz`：旧 composition-core 分支与用户交接入口。
- 当前开发 `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`：已有 CPU 自动接线、协议运行时和 RFuzz 实现。不得在根目录复制一套新实现。
- 其他 integration/harness-runtime worktree：保留，清理前核对未合并提交和被引用路径。
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
| docs/superpowers/plans/2026-07-*、2026-09-0* | 旧计划 | 历史参考；新目标由 PROJECT_GOALS.md 统领 |
| runs、artifacts | 可再生产物和保留证据 | 逐目录分类；语料、pin、报告、失败记录先归档 |
| projects、根目录 PPTX、Zone.Identifier、clear_codex_history.py | 用户素材/独立工具 | 不纳入代码清理删除集合 |

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
清单每条含精确相对路径、恢复路径、stored_path、sha256、大小、理由与状态。恢复前整体校验：工作区不匹配、stored_path 不在本批次目录内、内容被改写、目标已存在或目标已被 git 跟踪都会拒绝，且不移动任何文件。

往返证据：隔离 203 → 恢复 203（逐文件 sha256 与大小比对，0 处不一致）→ 重新审计再次得到 203 eligible → 重新隔离。
实际删除数量为零。编译缓存在每次 import 后会重新生成，因此这一步是可重复的日常清理，不是一次性删除。

独立复审记录（每轮都用一次性 /tmp 仓库复现，未修改工作区）：

- 第 1 轮 FAIL：symlink 父目录逃逸、`runs/` 为 symlink 导致不可恢复、cache 形状 symlink 被标 eligible、源文件未验证是否 tracked、`--apply` 不复核审计结论、移动失败可能无清单、restore 可改写 tracked 文件。
- 第 2 轮 FAIL：store 内更深一层 symlink 逃逸、restore 非原子、git pathspec 少了 `:` 前缀、manifest 自引用、marker 文本遮蔽真实引用、裸文件名与 `.pyo` 检测缺失、in-tree 选择文件自锁、`--apply` 缺 `--batch` 报错误导、`--restore` 忽略其他参数、`planned` 状态不可恢复、移动期 TOCTOU、双重失败抛裸 OSError。
- 第 3 轮 FAIL：悬空 manifest symlink 与 `runs/repository-audit` symlink 仍可写出工作区、restore 崩溃窗口死锁、`rollback-failed` 对 restore 不可见、合法 JSON 的 `schema_version` 为列表时抛未捕获 TypeError、manifest 写入非原子、引用扫描的后缀白名单与 4 MiB 上限漏检、裸 `__pycache__` 字符串过度绑定、pre-move OSError 未包装、失败 `--apply` 烧掉批次名、`--apply` 时 `--output` 被忽略、.pyc 头部检查读整文件、移动时未复核源文件状态。

上述三批问题全部修复。加固要点：工具自有的每条写入路径都经过逐层 symlink 检查并使用临时文件 + `os.replace` 原子替换；`restore` 只在移动成功后改状态，并对"已回到原位但清单未更新"做对账，`rollback-failed` 与崩溃残留都仍可恢复；引用扫描改为遍历全部 tracked/untracked 文件（二进制探测 + 32 MiB 上限，不再依赖扩展名白名单），目录引用改为整 token 匹配，工具自身产物用 schema 加条目结构双重判定；审计结论在真正移动前再取一次，逐文件移动时重新解析并重新哈希。

定向测试 `tests/test_repository_audit.py` 由 9 个增至 41 个，覆盖上述全部拒绝与恢复路径。
