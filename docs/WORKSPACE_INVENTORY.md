# 工作区目录归类与清理记录

日期：2026-10-09。本文是**当前工作区的一份目录地图**：每个顶层条目的性质（当前主线／历史冻结／构建缓存／可再生物）、是否被代码或文档引用、以及本次清理删掉了什么、重建了什么。

> 阶段状态与验收边界见 [当前工作进度](CURRENT_PROGRESS.md)；组件与 testcase 说明见 [系统说明](SYSTEM_OVERVIEW.md)。

---

## 1. 顶层目录归类

| 目录 | 性质 | 大小 | 处理 |
|---|---|---|---|
| `src/` | **当前主线代码**（340 模块） | 77 MB | 保留 |
| `tests/` | **当前主线测试**（671 个 test 文件） | 36 MB | 保留 |
| `docs/` | 设计／计划／报告／复现文档（364 份 md） | 6.5 MB | 保留 |
| `configs/` | CPU/IP profile、组合闭包、场景与 campaign 声明 | 3.3 MB | 保留 |
| `scripts/` | 门禁、在线运行、只读分析器（58 个 py） | 2.8 MB | 保留 |
| `examples/` | 可运行示例 | 592 KB | 保留 |
| `schemas/` | JSON schema（14 个被跟踪） | 116 KB | 保留 |
| `third_party/` | 被钉住的真实 RTL 源码（118 个被跟踪 + 子模块） | 1.2 GB | **保留**（文档策略：不做目录级清空） |
| `external_designs/` | 外部子模块设计（8 个被跟踪） | 16 MB | **保留**（同上） |
| `runs/` | 运行证据与门禁日志 | 清理后 ≈ 1.4 GB | 本次大幅清理，见 §2 |
| `.downloads/` | 下载依赖：rustup 1.5 G、verilator-5.020 1.2 G、rfuzz 50 M、cargo 38 M | 2.8 GB | **保留**（文档策略；当前实际用的是 `~/.local/verilator-5.051-*`） |
| `.superpowers/sdd/` | 工作日志、审查记录与 fixtures（326 文件；其中 `fixtures/pin8-cpu-irq-events.jsonl` 156 MB **被 `tests/scenario/test_chain_certificates.py` 使用**） | 161 MB | **保留** |
| `archive/` | 历史归档（`development/`、`presentations/`、`releases/20261009`，3012 文件） | 97 MB | **保留**（`REPOSITORY_ORGANIZATION.md`、`first-step-archive-20261008.md`、归档设计 spec 都引用它） |
| `deliverables/` | 汇报材料与设计交付（被归档 spec／计划引用） | 1.9 MB | 保留 |
| `patches/` | 外部补丁（opentitan／rfuzz，4 个被跟踪） | 296 KB | 保留 |
| `README.md`、`QUICKSTART.md`、`agent.md`、`项目目标与后续任务交接.md`、`SoC内部数据流动与去向.docx` | 被跟踪的入口与原始需求文档 | — | 保留 |
| `.git/` | 仓库（只有 `main`，与 `origin/main` 同步） | 269 MB | 保留 |

**本次删除**：`.myfuzz-elaboration-*`（4 个）、`.myfuzz-multicandidate-*`、`.pytest_cache/`、根目录散落的 `trace_hart_0.dasm`、`SoC内部数据流动与去向.docx:Zone.Identifier`，以及若干 `__pycache__`——全部是被忽略的临时/构建产物，且与 `REPOSITORY_ORGANIZATION.md` §历史上已删除项 的既有策略一致。

---

## 2. `runs/` 的清理（本轮最大动作）

清理前 114.75 GB / 275 个目录，清理后 **19 GB / 77 个目录**（72 个被代码/测试/脚本引用的保留目录 ＋ 5 个本次重建的运行/缓存目录）。

| 类别 | 内容 | 释放 |
|---|---|---|
| 备份快照 | `runs/backups/20260928/myfuzz-full-20260928.tar`（36 GB 全量副本；其内容今天都在工作区/git 里，同目录保留了 `sha256`、`.contents` 清单与 `myfuzz-git-history-20260928.bundle`） | 35.53 GB |
| 构建缓存产物 | `.gch`（30.7 GB，Verilator 预编译头）＋ `.o/.a/.rlib/.rmeta`，共 5546 个文件 | 31.65 GB |
| 无引用运行目录 | 99 个目录，名称在代码/测试/脚本/文档里都搜不到 | 7.58 GB |
| 仅报告引用的历史运行 | 104 个目录（旧 SoC 路线、P4/P5 中间变体等） | 22.52 GB |
| **合计释放** | | **97.28 GB**（114.75 → 19 GB，差额为保留目录中体量最大的 `runs/scenario` 6.3 GB、`ibex-pulp-online-20261006-600s` 3.6 GB 等） |

保留的 72 个目录：**68 个被代码/测试/脚本引用**（例如 `runs/p4-shift-fuzz-20261007-online` 被 3 个测试引用、`runs/soc-*` 被一批 `tests/integration/test_soc_*.py` 引用）＋ **4 个当前 P5 证据**（`p5-fault-family-all`、`p5-paired-cold-start`、`p5-uart-routing-gate`、`p5-fault-calibration-reproduce`），它们是 `p5_acceptance_suite.v1` 6/6 的证明运行。

清单与日志：`runs/current-dataflow-p5-final-20261007-logs/runs_cleanup_plan.json`（冻结的删除计划）、`runs_cleanup_executed.log`（逐项结果）、`runs_cleanup_result.json`（汇总）、`runs_cleanup_manifest.txt`（dry-run 全清单）。

---

## 3. 清理的副作用与恢复情况（如实记录）

### 3.1 我的分类错误

最终分类用"目录名是否出现在 `docs/` 的 Markdown 里"判断，但**阶段验收报告里的路径名是折行写的**（`--run cross_case=runs/<换行>p3-ip-cross-case-…`），因此漏判了 3 个被**当前阶段报告**引用的运行目录，把它们当成"仅历史报告引用"删除了：

| 目录 | 依赖它的文档 | 现状 |
|---|---|---|
| `runs/p3-ip-cross-case-20261007-online` | [P3 阶段验收](reports/current-dataflow-p3-stage-acceptance-20261007.md)、复现手册 | **已按原命令重建**，判据一致（见 §3.2） |
| `runs/p3-ram-prereq-20261007-online` | [P3 阶段验收](reports/current-dataflow-p3-stage-acceptance-20261007.md) | **已重建**，运行指标一致，但见 §3.3 的字段差异 |
| `runs/cv32e40p-pulp-online-20261007` | [P2 阶段验收](reports/current-dataflow-p2-stage-acceptance-20261007.md) | **未恢复**（命令见 §3.4） |

另有 104 个被删目录仍被文档按名字引用（完整清单：`runs_cleanup_doc_refs_lost.json`），其中绝大多数是早期 P2/P3 的中间产物，报告结论保留但原始产物已不存在。

### 3.2 `p3-ip-cross-case-20261007-online`：重建结果与报告判据一致

按报告原命令重建（`MYFUZZ_IP_CROSS_CASE=1`，180 秒 / 200 例预算 / seed 20261007）：

| 量 | 报告（原运行） | 重建（2026-10-09） |
|---|---|---|
| 例数 | 60（57 complete、2 `input_invalid`、1 `unsupported_irq_overrun`） | **60（57 / 2 / 1）** |
| 有效搜索秒 | 49.87 | 47.261 |
| `IP_TO_CPU_TO_IP` 跨例链 | certified 3、**cross_case 3**、`case_gap` p50=max=1 | **certified 3、cross_case 3、p50=max=1** |
| `CPU_TO_IP_TO_CPU` 跨例链 | certified 3、cross_case 1 | **certified 3、cross_case 1** |
| 复算命令 | `scripts/report_cross_case_chains.py` | exit 0，结果见 `runs/current-dataflow-p5-final-20261007-logs/p3_ip_cross_case_chains_regen.json` |

### 3.3 `p3-ram-prereq-20261007-online`：运行级与字段级证据均已复现

| 量 | 报告 | 重建（2026-10-09） |
|---|---|---|
| 例数／状态 | 40/40 `complete` | **40/40 `complete`** |
| 有效搜索秒 | 54.422 | 50.121 |
| 门禁计数 `policy_matched`／`policy_not_matched` | 1／39 | **1／39** |
| `source_action_gate.gate.dynamic_binding.counters` | requests 1／bound 1／unbound 0／refused 0／provenance_records 132 | **完全相同** |
| 绑定回执 | case 15 的 `matched_evidence_refs` 含 `41fb2ef4…`，且该值等于更早 `memory_write_commit`（event **17567**）的 `commit_id` | **case 15、同一 `evidence_ref`、同一 event 17567**；`memory_id=ram`、`byte_offset=0`、`writer_kinds=STORE`、cell 值 `[1,1,0,0]` |

> 说明：本文档早先一版曾写"`dynamic_binding` 字段未复现"，那是**我的检查错误**——该字段位于 `report.json` 的 `source_action_gate.gate`（不是逐例回执），重建运行与报告逐字段一致。

### 3.4 逐文件审阅产物的恢复情况

| 产物 | 处理 |
|---|---|
| `runs/individual-review-20261008/findings.json` | **已重跑重建**：由 `scripts/reproduce_stage1_review_findings.py` 在当前源码上重跑（exit 0），含该脚本可复现的观察项；**不是**原始 10 个观察场景的全量重建 |
| `runs/individual-review-20261008/file-review-ledger.partial.json` | **部分重建**：原始台账（13 全文＋14 部分、含 SHA256 与已读区间）无法重建；此文件只记录审阅文档引用位置与当前 SHA256，不代表原始进度 |
| 审阅文档 R1–R7 的文字记录 | 完整保留（7 组判据缺陷，含 `p5_acceptance.py:1509` corpus 未校验、`p5_acceptance.py:1847` 零耗时跳过、`closed_loop_feedback.py:136` 不完整证书通过等） |

### 3.5 仍未恢复的项

| 项 | 恢复方式 | 代价 |
|---|---|---|
| `runs/cv32e40p-pulp-online-20261007`（P2 阶段报告的 CV32E40P 复用证据，42/42） | 按 P2 报告命令用 `scripts/run_cv32e40p_pulp_online.py` 重跑同预算 | 一次真实 RTL 运行（CPU＋GPIO 构建，约 20–30 分钟） |
| `runs/individual-review-20261008/`（`file-review-ledger.json`、`findings.json`） | 按 [独立审核文档](reproduction/first-step-individual-review-20261008.md) 的方法重跑一次逐文件审核 | 受控生成，不跑 RTL |
| 其余 101 个被文档按名字引用的历史运行 | 不可恢复（P2/P3 中间产物） | 报告结论保留，原始产物不再可得 |

### 3.5 清理后的门禁状态

| 门禁 | 结果 |
|---|---|
| `scripts/run_p4_acceptance_suite.py --skip-heavy` | **exit 0，critical 8/8** |
| `scripts/run_p5_acceptance_suite.py`（7 个声明运行） | **exit 0，critical 6/6，no_proving_run=[]** |
| `scripts/check_doc_links.py` | 修复中（见 §4） |

---

## 4. 文档链接修复

清理后 `check_doc_links.py` 报出 8 条断链，全部指向被删的 `runs/first-step-reproduction-20261008/` 与 `runs/individual-review-20261008/`（[复现手册](reproduction/first-step-p1-p5-20261008.md) 与 [独立审核](reproduction/first-step-individual-review-20261008.md) 里的产物链接）。

处理（2026-10-09 已完成大部分）：
- `runs/first-step-reproduction-20261008/` **已按复现手册的命令重建全部五项**：`p1-unittest.txt`（Ran 236 tests，OK，skipped=5）、`p2-report.json`（P2 门禁 exit 0 / ready=true）、`p3-suite.json`（**exit 0 / ready=true，每个关键 P3 项都有声明运行证明**——先重建 `p3-ip-cross-case` 才跑通）、`p4-tests.txt`（48 passed）、`p5-suite.json`（P5 套件 exit 0 / critical 6/6）。
- `runs/individual-review-20261008/` 尚未重建，其两条链接仍是断链。

---

## 5. 结论与建议

**归类结论**：工作区的"当前主线"是 `src/`＋`tests/`＋`docs/`＋`configs/`＋`scripts/`＋`examples/`＋`schemas/`；"被钉住的依赖"是 `third_party/`＋`external_designs/`＋`.downloads/`；"证据"是 `runs/`（已瘦身到只留被引用与当前验收相关的部分）＋`.superpowers/sdd/`；"历史归档"是 `archive/`＋`deliverables/`。这五类在仓库里已经有明确边界，本次没有搬动任何被跟踪文件。

**建议的后续（按优先级）**：
1. 重跑 `scripts/run_p3_acceptance_suite.py`（现在四个运行齐全）并把结果写回 `runs/first-step-reproduction-20261008/p3-suite.json`；
2. 重建 `runs/cv32e40p-pulp-online-20261007`（P2 报告证据）；
3. 定位 RAM 绑定字段的当前位置（§3.3），或在报告里补一句"该字段级证据未随重建复现"；
4. 重建或改链 `runs/individual-review-20261008/` 的两条链接；
5. `.downloads/verilator-5.020`（1.2 GB）+ `rustup`（1.5 GB）如需进一步瘦身可评估，但当前文档策略是不做目录级清空。

---

## 6. 断链声明（清理的可见后果）

清理共造成 **83 条文档断链，100% 来自本次删除**（涉及 45 个已删运行目录、30 份文档）；机器可读明细见 `docs/reports/deleted-artifacts-20261009.json`，人读版见 [已删除的原始产物](reports/DELETED_ARTIFACTS_20261009.md)。

`scripts/check_doc_links.py` **仍会如实报错**——这里没有给检查器加豁免，因为"链接指向不存在的证据"正是应当被看见的事实。
