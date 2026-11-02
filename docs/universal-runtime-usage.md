# 通用持续 RTL 系统使用

系统在宿主机调度独立 CPU/IP harness，模拟请求、响应、内存与事件传播；不生成或连接 SoC。CPU/IP 原始 RTL、protocol adapter、声明式 source/ownership 和原 admission gate 继续负责真实执行。增加组合优先修改描述与绑定，不复制 CPU×IP 执行器。

统一配置驱动搜索现使用 `run_dependency_search.py --scenario CONFIG`，可配置 Timer + Ibex、SPI + CV32E40P、F1/F3 mixed、F5 与 F6。配置、严格 fresh、预算及反馈能力边界见 [配置驱动搜索](CONFIG_DRIVEN_SEARCH.md)。下文无 `--scenario` 的搜索示例继续表示原 GPIO 专用默认范围。

现有 F1–F6 通过 descriptor 入口运行；新增 GPIO 配置/事件搜索使用同一个可导出、可重放的 typed runtime。当前混合输入支持已有 RV32I CPU 与单 bit 外部事件，不声称任意 ISA、任意外围协议均已支持。新组件仍需要一次 protocol/profile/source adapter。

CLI 默认 `--execution-mode search`；单例调试可用 develop，完整验收可用 acceptance。显式 `--mode fresh` 始终执行严格跨运行验证。普通搜索假设本地代码不变，静态依赖首次检查一次；fresh 与 acceptance 结束重新验证；发现真实新关系选择重放。策略与实测限制见[流程验证报告](reports/execution-workflows-20261028.md)。

所有输出目录必须尚不存在。以下命令从项目根目录运行。

## F1–F6 执行与真实重放

F1 指令、F3 RAM 写、F4 外设写和 F2 外设读可放入同一持续会话：

```bash
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json \
  --flow mixed --mode original --case /tmp/myfuzz-memory-register \
  --record F1:13000000 --record F3:55000000 \
  --record F4:55000000 --record F2:04100040 --rounds 32

python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json \
  --flow mixed --mode fresh --case /tmp/myfuzz-memory-register
```

F5 外部事件路径和 F6 DMA 路径复用原独立执行器与证据：

```bash
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f5-ibex-pulp-gpio/generic_scenario.json \
  --flow F5 --mode original --case /tmp/myfuzz-f5 --record-limit 2
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f5-ibex-pulp-gpio/generic_scenario.json \
  --flow F5 --mode fresh --case /tmp/myfuzz-f5

python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json \
  --flow F6 --mode original --case /tmp/myfuzz-f6 --record-limit 2
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json \
  --flow F6 --mode fresh --case /tmp/myfuzz-f6
```

外部工具生成的同域有序输入可以通过 `--records-file` 导入 JSON 字符串数组，例如 `["F4:55000000","F2:04100040"]`。原始数据仍经过相同 lowerer 和 gate，不因导入而获得权限。

## 状态驱动混合输入搜索

当前共同目录为 GPIOEN CPU 写/读与 pin8 事件。CPU 程序、外部事件和固定支持指令由正式 opt-in mixed runtime 重新生成并 admission；普通 register-only 模式不放行任意字节。

```bash
python3 scripts/run_dependency_search.py --mode original --policy state \
  --cases 6 --seconds 60 --seed 7 --record-local-commands \
  --output /tmp/myfuzz-search-original --cache /tmp/myfuzz-search-cache

python3 scripts/run_dependency_search.py --mode fresh --policy state \
  --cases 6 --seconds 60 --seed 7 --record-local-commands \
  --output /tmp/myfuzz-search-fresh --cache /tmp/myfuzz-search-cache \
  --original /tmp/myfuzz-search-original
```

`state`、`uniform`、`legacy` 使用同一动作目录和执行器；`legacy` 是已有权重公式在共同 typed 域上的适配。`--ablation frontier|state|credit|cost` 分别去掉相应策略机制。GPIOEN→APB 读及 GPIOEN→原生 GPIO IRQ 是不同消费 scope；后者不表示 CPU 中断送达或 ISR 消费已经认证。

状态必须从同一 live authority 查询；版本覆盖或 reset 会使相应当前关系失效。bootstrap 没有本轮实际 testcase writer 时不算已建立 producer。只有确切版本、实际消费者和真实 testcase 归属匹配时才奖励；预算结束的 pending 保持 censored。相同版本后续的新消费 scope 可以增量结算，已有动作不重复增加 trial 或成本。

墙钟预算包含状态查询、选择、生成、RTL、checker 和主要证据写入；build/init 单列，完整 batch 的预算越界量和尾部清理另记。fresh 使用新原生进程实际重跑保存的精确前缀，并用原始策略成本重算决策和结算。保存的 JSON 只能比较，不能恢复执行权限。

## 策略及其他工具比较

先查看矩阵，命令不会运行 RTL 或创建输出：

```bash
python3 scripts/run_search_comparison.py --plan-only \
  --variants state,uniform,legacy --seeds 7 --cases 4 --seconds 30 \
  --output /tmp/myfuzz-comparison-preview
```

移除 `--plan-only` 并增加 `--fresh` 即执行该开发矩阵；增加 `--record-local-commands` 可保存每次实际命令。默认矩阵包含三策略、四消融和 20 个 seed，正式执行前需冻结目标、参数与指标。输出 `comparison.json` 保留每个 seed 的认证交互 AUC、first-hit、预算内 useful cases/s、开销、fresh、拒绝/失败及可比性原因。

其他工具通过 `--import-result` 导入相同 schema 的结果，具体格式见 [比较入口说明](../research/input-strategy-audit-20261027/search-comparison-usage.md)。目标 RTL/source/profile、动作域、metric、seed 和预算不同会明确标为不可比；失败摘要不会成为成功样本。B2/B3/B4 未接通时保持 unavailable，不推断超过完整原策略。

## 实际 RTL 覆盖率

搜索摘要中的认证交互指标不是 RTL 覆盖率。`--record-local-commands` 导出按实际 binary/build/PID/nonce 对齐的 `local-commands.json`，但在运行原生 instrumentation 前覆盖率保持 unavailable。

对选定组件进行一次显式离线重建和命令重放：

```bash
python3 scripts/measure_local_coverage.py \
  --trace /tmp/myfuzz-search-original/local-commands.json --component gpio_b \
  --cache /absolute/path/from/trace/to/content-addressed-build \
  --output /tmp/myfuzz-coverage-gpio-b
```

`--cache` 使用 trace 中该组件 `identity.binary_path` 的父目录，并核对目录名与 `build_digest` 一致。工具检查原 binary、完整命令及回复，输出真实 Verilator line/block 数据和 DUT source 归属。它包含启动/复位和实际已执行命令，不是 source-branch 覆盖率；超过录制容量的轨迹不能伪称完整。

使用 `scripts/compare_local_harness_coverage.py --help` 比较两份已测 artifact。它检查来源与精确 point universe；不能把不同分母、whole-harness 点、DUT 点或语义命中混成同一覆盖率。覆盖率重建成本单列，缺测不当作零。开发 smoke 只证明系统接线，不能据此宣称统计显著的性能提升。

将已校验的真实测量附加到新摘要，并只比较已有结果（不会再启动搜索矩阵）：

```bash
python3 scripts/attach_search_coverage.py \
  --search /tmp/myfuzz-search-original --component gpio_b \
  --measurement /tmp/myfuzz-coverage-gpio-b \
  --cache /absolute/path/from/trace/to/content-addressed-build \
  --output /tmp/myfuzz-search-with-coverage.json

python3 scripts/run_search_comparison.py --import-only \
  --import-result /tmp/myfuzz-search-with-coverage.json \
  --import-result /tmp/other-tool-with-coverage.json \
  --output /tmp/myfuzz-imported-comparison
```

附加器逐项检查 measurement 与原 trace 的 component、build、binary、完整命令、nonce、序号及 RESULT 回复，并从实际 DUT point universe 计算分母。它保留原摘要，新建带 coverage 的摘要；不把离线覆盖率变成在线证书，也不把其他工具自报摘要当作原生执行权限。
