# P4 内部 RTL 分支覆盖与端口语义命中的分离计数

日期：2026-10-07。计划 P4 要求"另将**端口语义命中**和**有明确 CPU/IP RTL 插桩来源的内部分支覆盖**分别计数；只有插桩并证明来自 CPU/IP RTL 的数据才报告为内部 branch coverage"。本报告交付该分离消费者，并给出既有真实插桩 artifact 的实测——**工作区确实存在真实插桩证据**（不是"无 artifact"情形）。

## 交付

| 文件 | 作用 |
|---|---|
| `src/myfuzz/scenario/rtl_branch_coverage.py`（新增，905 行） | `RtlBranchCoverage`，`rtl_branch_coverage.v1` |
| `tests/scenario/test_rtl_branch_coverage.py`（新增，41 tests） | 合成正负例 + 真实 artifact 钉住 |
| `scripts/report_rtl_branch_coverage.py`（新增） | 只读复算 CLI |

身份校验（任一不符 → `rejected`，`branch_points`/`observed_branches` 一律 `None`，**绝不降级为端口语义命中**）：插桩器版本与源摘要（必须等于 `scripts/source_branch_instrumenter.py` 的实际字节）；每个 RTL 文件 sha256 与树内字节一致且**覆盖运行时编译输入闭包**；聚合树摘要用生产枚举器（`soc_builder._instrumented_output_sha256`）复算；`instrumentation.json` manifest 摘要与**磁盘字节**复算一致；harness 身份与传入 run 绑定；端口清单与位宽一致；位索引范围；位种类来自 manifest 且 ∈ {`if`,`case`}；`bit` 编码下严格 0/1；把指向 `__vi_coverage` 的 `CoverageTarget` 当分支覆盖 → 拒绝。

`separation` 段：`branch_coverage`、`port_semantic_hits`、`non_branch_lit_ports` 三者**分别计数**，`combined: null`、`sum_forbidden: true`。

## 真实 artifact 实测（只读复算，未跑 RTL）

扫描全部 303 个 run：**28 个带插桩分支证据，28/28 校验通过**（`scanned=28 verified=28 rejected=0`）。样例 `runs/ibex-pulp-gpio-spi-cpu-retry7`：`branch_points = 18/128`（ratio 0.1406），IP 侧点亮 18、端口语义命中 0、非分支点亮端口 11、RTL 文件 262（聚合摘要 byte-exact 命中 `build/` 与 `rebuild/` 两棵树）。覆盖最好的 run：`runs/ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926` = **50/128（0.3906）**。

**端到端链条闭合**（人工核对）：RTL 源 `spi_master_rx.sv:123` 的 `if (rstn == 0)` → 插桩文本 L185/L193 `__vi_branch_cov_2077/2078 = 1'b1; // spi_master_rx if true/false line 123` → manifest `coverage_bits[163/162]`（kind=if, subtype=true/false）→ 真实运行 `coverage_maxima` 均为 64。

**伪造来源 fail-closed 已在真实 artifact 上演示**：篡改聚合摘要后 `rejected`、`branch_coverage=None`，而端口语义命中仍单独报出（两者不互相替代）。

## 关键边界（必须如实记录）

- 128 个受监控插桩点 = **64 个 `u_cpu0`（Ibex CPU）+ 64 个 `u_spi0`（IP）**，但在**全部 28 个 run 中 CPU 侧点亮数恒为 0/64**；所有点亮的分支点都在 IP（`soc-pulp-axi-spi` 的 clockgen/rx/tx/controller）。因此当前真实证据只支持**IP 侧**内部分支覆盖；"CPU 分支覆盖"尚无可观测点亮。
- `first_seen` **不可用**：`live/checkpoints.jsonl` 只有一条全零快照；`live/corpus/entry_*.json` 的 `trace_bits` 是赛后优胜样本快照（entry_0000 已点亮全部 18 位），**不是按时间序的首次命中**，不能当 first_seen。模块要求显式事件序列，缺失即如实报 `unavailable`。
- 需要在真实运行中扩大证据时无需新开关：SoC campaign 经 `soc_builder` 自动插桩并落盘（`runs/<cell>/build/instrumentation/instrumented/` + `report.json` 的 `artifact_provenance.coverage_instrumentation` 与 `client_result.coverage_maxima`）。
- 建议的 provenance 增强（未实施，属既有文件改动）：把 manifest 摘要纳入签名闭包、持久化逐文件 `rtl_files: [{path, sha256}]`、`harness_top`、`build_hash`、`coverage_vector_width` 与按时间序的首次命中，即可把当前 `level="aggregate-and-tree"` 升级为 `full` 并启用 `first_seen`。
- 本轮未运行 Verilator 或任何真实 RTL；全部数字来自既有 artifact 的只读复算。
