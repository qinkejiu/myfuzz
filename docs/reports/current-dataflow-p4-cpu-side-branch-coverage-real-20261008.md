# P4 CPU 侧内部分支覆盖：映射修复已在真实 RTL 上点亮（12/64），门禁判 INCONCLUSIVE 的唯一原因已定位

日期：2026-10-08。承接[CPU 侧 0/64 根因诊断](current-dataflow-p4-cpu-side-branch-coverage-diagnosis-20261007.md)：根因是观测配额取**最低**的 64 个覆盖位，而它们全落在两个未 elaborate 的 `generate` 分支（`u_ibex_lockstep`、`i_ibex_trvk`）上。本报告给出修复后的**真实 instrumented 运行**结果。

## 运行与命令

```bash
# 单 cell（ibex-pulp / cpu_only），300 秒，两次编译预算（重规划后重建 harness 一次）
MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 \
  runs/current-dataflow-p4-cpu-side-20261008-logs/run_single_cell.py \
  --output runs/p4-cpu-side-coverage-20261008-online --seconds 300 --seed 20260926 \
  --cell ibex-pulp --mode cpu_only \
  --client runs/rfuzz_client_bounded_build/target/debug/kfuzz
```

`scripts/run_p4_cpu_side_branch_gate.py verify --run runs/p4-cpu-side-coverage-20261008-online --min-cpu-points 8` → **7/8 通过，verdict=INCONCLUSIVE（exit 4）**。

| 判据 | 结果 |
|---|---|
| run-artifact | PASS：128 个观测点，cpu=64 |
| coverage-identity | PASS：`report_rtl_branch_coverage.py` status=**verified**、`external_binding.passed=true`、**30/128** 分支点被点亮 |
| **cpu-stimulus（前置）** | **FAIL**：该运行没有声明 RVFI opcode 计数窗口 |
| elaboration-attested | PASS：status=replanned、模型摘要 `8e974602a02b…`、128/128 观测点 `elaborated`、模型头与磁盘一致 |
| exclusions-reported | PASS：696 个被拒候选点、65 个被排除实例、1716 个候选位，逐条带分类与理由 |
| **no-dead-counters** | **PASS：`unelaborated-bound=0`**（旧 28/28 运行为 64/64 死计数器） |
| **cpu-side-observable** | **PASS：CPU `elaborated-lit=12`（阈值 8）/64** |
| readback-integrity | PASS：probe-unreadable=0、elaboration-unknown=0、contradictions=0 |

独立诊断（`scripts/rtl_cpu_side_observation_diagnosis.py`，只读）：

| 运行 | CPU 侧 | IP 侧 |
|---|---|---|
| 本次（修复后） | **lit 12** / unexercised 52 / dead 0 | lit 18 / unexercised 46 / dead 0 |
| 旧参考运行（修复前） | lit 0 / unexercised 0 / **dead 64** | lit 18 / unexercised 46 / dead 0 |

运行本身：300.002 有效秒、**59,753** 个 RTL 测试、33,173 条覆盖记录；两次编译（重规划后重建 harness 一次）均成功。

## 唯一 FAIL 的原因与含义

`cpu-stimulus (precondition)` 要求运行声明 RVFI opcode 计数窗口（用于独立证明"CPU 真的退休了指令"）。该窗口由 **profile 构建路径**在 checker profile 含 `bit == 16` 属性时生成（`soc_builder.py` 中 `opcode_coverage_ports`），而本次运行走的是 **legacy 单 cell 路径**，其渲染的 `soc_top.sv` 里没有任何 `rvfi_*` 端口（实测 0 处匹配），因此该运行**无法**提供这一前置证据——这是前置条件的声明缺口，不是映射或搜索结果的失败。

因此本报告的口径是：**映射问题已在真实 RTL 上被证伪**（0 死计数器、CPU 侧 12 个内部分支点真实计数），而"CPU 确实退休"这一独立前置仍缺声明。两个可选下一步（都需改动，本轮未做）：

1. 让 legacy 单 cell 路径在 CPU profile 声明 RVFI 时也渲染 `rvfi_opcode_coverage_o`（12 位）并纳入观测端口；
2. 或改走 profile 路径（`composition_request` + 含 `bit == 16` 的 checker profile）跑同一 cell。

## 兼容性修复（本轮顺带交付，必要前置）

修复后的产物用**新的 provenance 形态**（嵌套 `coverage` 文档）记录覆盖证据，而 `report_rtl_branch_coverage.py`/诊断工具此前只认旧的扁平键（`coverage_instrumentation` / `coverage_ports` / `branch_coverage_ports`），因此**任何新运行都无法通过覆盖身份校验**。本轮把两种形态的读取统一到 `myfuzz.scenario.rtl_branch_coverage.coverage_attestation()`（新形态的分支端口由该运行自己的 `build/soc_coverage_plan.json` 逐位重导，并要求与暴露的计数器列表逐位一致，否则拒绝而不是猜测），两个 CLI 共用；旧的 28 个运行仍按扁平形态验证通过（参考运行：verified、18/128、external binding passed）。

## 结论与限制

**结论**：P4 的"CPU 侧内部分支覆盖恒为 0"不再是映射问题——修复后真实运行给出 **CPU 12/64、IP 18/64、0 死计数器**，覆盖身份 `verified`（30/128），并且 elaboration 探针的排除集、模型摘要、读回完整性全部通过。

**限制**：

- 门禁整体判 **INCONCLUSIVE**（7/8），唯一原因是缺少 RVFI opcode 前置声明；不得把 INCONCLUSIVE 读成 PASS，也不得读成映射仍损坏。
- 本运行是 300 秒单 cell（`--seconds 300`、seed 20260926），不是 600 秒参考配置；12/64 是**本窗口**的点亮数，不是该 CPU 的上限或覆盖率结论。
- 98/128 观测点属于"已 elaborate 但本窗口未被触发"（armed but unexercised），这是搜索质量问题，与映射无关。
- 修复改变的是"观测哪些点"：新运行的观测集与旧运行不同，历史 28 个运行的报告仍是各自旧观测集的结论（本轮未重跑它们）。

## 补记（2026-10-08，可判定化路线真实运行结果）

按[可判定化报告](current-dataflow-p4-cpu-side-gate-decidability-20261008.md)的路线改走 **profile 路径**后，真实运行 `runs/p4-cpu-side-profile-rvfi-20261008-online`（600 秒）让门禁**变成可判定的**：

| 判据 | `--min-cpu-points 8` | `--min-cpu-points 1` |
|---|---|---|
| coverage-identity | PASS：`verified`，24/128 | PASS |
| **cpu-stimulus（前置）** | **PASS：RVFI opcode 窗口 `[228,239]` 最大值 `[3,0,4,0,0,0,0,8,1,0,0,0]`（和 16）** | PASS |
| elaboration-attested / exclusions-reported | PASS（status=replanned、模型 `3879dc9cff6f`、912 个被拒点／65 实例／1716 候选位） | PASS |
| no-dead-counters | PASS：`unelaborated-bound=0` | PASS |
| **cpu-side-observable** | **FAIL：CPU `elaborated-lit=6` < 8** | **PASS（6 ≥ 1）** |
| readback-integrity | PASS：0/0/0 | PASS |
| **verdict** | **FAIL（exit 1）** | **PASS（exit 0，8/8）** |

结论分两层，不再混为一谈：**映射问题已经解决且可判定**（8 条判据在 `--min-cpu-points 1` 下全部通过，死计数器 0，elaboration 探针与模型摘要一致）；**`--min-cpu-points 8` 的 FAIL 是搜索质量不足**（600 秒、seed 20260926 下 CPU 侧只点亮 6 个内部分支点，IP 侧 18 个）——门禁自己把这两类问题分开报告，故该 FAIL 不得读成映射仍损坏，反之亦然。
