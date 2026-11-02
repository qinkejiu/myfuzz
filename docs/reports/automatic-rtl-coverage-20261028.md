# 当前执行前缀的自动RTL覆盖率

2026-10-28，独立读取long-coverage产物并用现有保存产物验证器复核，未重新运行DUT。入口为 `scripts/run_search_comparison.py --measure-coverage COMPONENT`，复用 `measure_local_coverage.py` 与 attach/比较器；测量当前执行录制的完整component命令前缀，原始搜索summary保持不变。

## 实际证据

产物：`research/input-strategy-audit-20261027/runs/long-coverage-20261028/shared-f2/comparison.json`，详细测量在其 `seed-7-state-none/coverage-measurement/measurement`。四例为F4/F2/F2/F5，original与strictfresh进程均exit0。automatic_coverage为measured；主interaction状态observed不被RTL测量改写。

- peripheral实际518条结果、530个local ticks；显式max_commands=2048，突破默认512而完整测量，无截断。
- 原录制、plain replay与instrumented replay完整回复一致。
- DUT命中48/189；全部仪器化点220，避免将harness点混入DUT分母。denominator SHA256为 `1a236264855ee52666a676d704db207e689f84411e161878b940f1d275a6ae17`。
- original build digest为 `d45aa1d5afbd6adb15761c985559fae108f4064bb782a08a1d8b8bf5217d4fba`；source-selection SHA256为 `850b27b357a8082ce768e73157bb8bfee8d68235706120ed16bfa2565fe7abcd`。
- 仪器化与回放合计3.453905s，attachment验证0.173023s，总3.626928s，在搜索预算外。细分plain replay0.076307s、instrumented replay0.080328s；没有独立build秒数时保持null。

验证调用现有 `scripts.compare_local_harness_coverage.load_run(..., max_commands=2048)`，确认cache_verified、518命令、530ticks及48/189。此步骤只检查保存文件，不执行native。

## 预算与范围

默认512命令、64MiB输入、64MiB输出、每次回放60秒；可显式传 `--coverage-max-commands`、`--coverage-max-input-bytes`、`--coverage-max-output-bytes`、`--coverage-max-wall-seconds`。独立measure工具对应 `--max-*`。硬上界为65536命令、输入/输出各512MiB、3600秒。metadata只能保留/收紧可信调用预算，不能自行扩权；超预算拒绝而非截断。输入包含ACK/END，回复总字节受限。

测量是完整component录制prefix的离线Verilator line/block覆盖，含启动/复位与已发生的预算超时尾部；不是在线固定搜索时间覆盖，也不提供coverage AUC。不同运行仅在真实source/denominator身份一致时可比较。此次只有一个策略结果，不产生策略优越性结论。关系计数与RTL覆盖始终是不同指标。
