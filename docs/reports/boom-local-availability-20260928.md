# BOOM 本地执行条件核查

核查日期：2026-09-28。结果：`skipped_unavailable`。这是本地可运行性判定，不是 BOOM RTL 通过或失败。

| 核查项 | 本地命令 | 观察 |
|---|---|---|
| 生成的 BOOM 源清单 | `test -f third_party/boom/sources.f` | 返回码 1；文件不存在 |
| Chipyard 生成清单 | `test -f third_party/chipyard/sims/verilator/generated-src/chipyard.harness.TestHarness.SmallBoomV3Config/boom_small_v3.rfuzz.f` | 返回码 1；文件不存在 |
| 参考仓库 RTL | `find third_party/boom_upstream_reference -type f \( -name '*.sv' -o -name '*.v' \) \| wc -l` | 仅 2 个辅助 Verilog harness 文件，不是可执行的 BOOM tile |
| 本地构建工具 | `for tool in sbt mill verilator java scala; do command -v "$tool" \|\| true; done` | 只有 Verilator 可执行；SBT、Mill、Java、Scala 未找到 |
| 目标接口 | `rg -n 'tilelink@1' configs/cpus/boom/README.md` | 配置明确要求尚未实现的 `tilelink@1` 协议边界 |

[BOOM 语义接口说明](../../configs/cpus/boom/README.md)当前是 reference-only；生成完整 BOOM tile、提供依赖清单和本地 TileLink 适配前，不能建立真实独立 harness。按用户允许“本地不能执行就跳过该 CPU”的规则，BOOM 不进入当前真实 RTL 验收分母。没有下载依赖或用辅助 harness 冒充 BOOM。
