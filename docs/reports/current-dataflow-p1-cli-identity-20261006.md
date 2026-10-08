# 当前数据流方案 P1 进度：统一 CLI、能力查询与运行身份

日期：2026-10-06。P1 **完成（统一入口与声明的身份门禁范围）**。已覆盖标准 evidence、fresh/live/continuous RFuzz、运输异常终结、显式模板身份、campaign 输入快照及文档能力查询。整体 P2～P8 门禁仍未完成。

## 已实现

- `python -m myfuzz` 提供 `harness generate`、`scenario record`、`scenario replay`、`scenario campaign`。四个脚本和 module 命令共享同一 parser 配置与 handler；旧矩阵流程位于 `compat soc check|preflight|run`，原参数语义和 `MYFUZZ_SOC_REAL=1` 环境门禁保留。
- 在线会话 manifest 固定 runner/source 身份、checker 源码和配置；确定性 deque 配置规范化为 JSON 数组。源码清单包含 live RFuzz FIFO transport。
- live RFuzz 输出保存 session manifest 与 versioned run identity。身份覆盖 saved plan、依赖图、targets、运行配置、checker、feedback schema、templates（若运行身份声明）、trace 文件字节及语义摘要、RFuzz client binary；仓库内 RFuzz build 也记录 Cargo/build 配置、Rust 源码和 rustc/cargo 可执行文件哈希。工具链可执行文件缺失时明确标记为 partial。
- 新 bundle replay 在 factory 前核对保存材料、源码、checker、identity sidecar、trace 路径与准确 artifact 清单；实际 Runner 构造后、begin 前比较运行身份。新 bundle 缺 sidecar、trace 内容被改、传入旁路 trace 或 plan 不匹配都会拒绝；没有身份标记的历史 bundle 保留旧 replay 路径。
- UART live trace reader 可读取 JSON array 和 JSONL event 文件。
- `capabilities [--match TEXT]` 与 `scripts/query_capabilities.py` 共用实现，直接读取运行能力表全部 61 行，保留原始等级、限制、行号、文档 SHA 与证据链接；`basis=documented_evidence`、`runtime_revalidated=false`。DMA 未实现的边界已补入权威文档，查询不会生成 DMA 能力行。
- 标准 evidence v2 保存 `run_identity.json`，以引用及摘要绑定已有 manifest/Genome/checker/coverage/source/build 身份；固定 Genome 执行没有 decoder graph，记录 `not_applicable`。身份文件进入启动前材料预算、终止 index reserve 和最终准确字节计量；legacy 格式继续使用原始预算计算。
- fresh RFuzz 在现有实际 Runner 扫描处观察并冻结 manifest，每例不增加 factory/身份扫描。新 sidecar 保存完整 decoder graph/templates、targets、checker 的稳定配置与实际源码、工具链、回执、corpus/failure artifacts；replay 在 factory 前校验材料，并在 begin 前比较实际 Runner 身份。
- 外层 campaign 保存 provider 明确声明的主输入及间接 seed 快照，并对各 cell 的身份和辅助材料作关联。内置 provider 使用快照执行，原输入、快照或快照 symlink 变化都会使 gate incomplete。内置 provider 必须提供执行身份，缺 sidecar、错误 marker、非法 artifact 或 incomplete envelope 均不能通过完成门禁；custom provider 缺少的输入闭包/执行证据明确记为限制。
- 运输初始化冻结源码/client/checker；取得新输出目录所有权后，运输异常仍终结实际 report/identity。清理错误不替换主异常，session finish 最多一次；未执行过 Runner 时记录 no_runner_observed，不制造 trace。身份序列化失败时保存显式 incomplete envelope，不能作为完整可重放证据。
- continuous decoder 使用真实 ScenarioSession.record，保存完整接纳计划和 trace，分别绑定 session checker 与 decoder checker。完整前缀 replay 执行 session checker并核对 decoder checker 身份，不重算 RFuzz 策略、候选反馈或累计 verdict。独立单例 corpus replay 明确拒绝 continuous 证据。
- 23 个已接纳 runtime kind 均保存版本化 selected_template.executor，已有 protocol contract 保留。仅对已匹配的协议子集嵌入相应声明；其他 executor 明确 scope=generated_executor_only、protocol_capability_claim=false。五种代表性 RTL 生成字节在身份更新前后不变，未提升 source-lock 登记等级。

## 验证

焦点回归命令：

```bash
PYTHONPATH=src python3 -m unittest tests.test_capabilities tests.test_current_cli tests.test_cli tests.local_harness.test_generation_cli tests.scenario.test_evidence_bundle tests.scenario.test_evidence_run_identity tests.scenario.test_evidence_budget tests.scenario.test_generated_evidence_host_identity tests.scenario.test_host_source_identity tests.integration.test_scenario_campaign tests.integration.test_scenario_cva6_campaign tests.integration.test_campaign_run_identity tests.integration.test_fresh_run_identity tests.integration.test_online_run_identity tests.integration.test_scenario_rfuzz_terminal_identity tests.scenario.test_online_session_partial_replay tests.scenario.test_online_uart_source_events tests.scenario.test_rfuzz_scenario_executor tests.integration.test_ibex_uart_online_pilot tests.integration.test_scenario_rfuzz_wall_cut_replay -q
```

结果：`Ran 219 tests in 6.005s ... OK (skipped=5)`。需要单独启用的 RTL 项保持跳过。另执行 `MYFUZZ_SCENARIO_RFUZZ_LIVE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_campaign_run_identity tests.integration.test_scenario_rfuzz_live_client -v`，16 项全部通过（1.548 秒），包含全部实际 Rust client 运输检查。异常终结新模块有 12 项检查，覆盖运输前/后失败、主异常保留、最多一次 finish、缺 sidecar、材料篡改、失败接纳前缀及两层 checker；模板身份新增 3 项检查覆盖 21 个不同 profile，注册表 18 项通过。脚本/module 入口对生成材料与标准 evidence/campaign 身份文件作字节一致性对照。

稳定模板源码下真实标准证据命令：

```bash
MYFUZZ_SCENARIO_REAL=1 MYFUZZ_IBEX_GPIO_CACHE=/tmp/myfuzz-ibex-pulp-online-cache MYFUZZ_IBEX_GPIO_EVIDENCE=/tmp/myfuzz-p1-template-evidence-20261006 PYTHONPATH=src:. python3 -m unittest tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real -v
```

结果：1 项通过（40.540 秒），真实双 PULP GPIO IRQ 数据链有 1,061 个事件、准确 evidence 字节数 1,707,617；模板身份 `status=declared`，完整 fresh replay `matches=true`、`verification_scope=full`。run identity SHA：`8891d6df7fff76e38f5c8262cb04a210f4bdab18b251166a0e3257a0581f3e81`。预算明确匹配 factory 的 128 KiB RAM 服务 cap。

最终稳定运输源码下 UART live 与 fresh replay 命令：

```bash
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py run --client-binary third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz --cache-dir /tmp/myfuzz-ibex-uart-online-cache --output /tmp/myfuzz-p1-finalized-uart-20261006 --seconds 3 --max-tests 1 --seed 123 --run-id p1-finalized-uart
PYTHONPATH=src python3 scripts/run_ibex_uart_online.py replay --cache-dir /tmp/myfuzz-ibex-uart-online-cache --plan /tmp/myfuzz-p1-finalized-uart-20261006/online_plan.json --trace /tmp/myfuzz-p1-finalized-uart-20261006/online_final_trace.json
```

两个命令均返回 0；live 完成 1 个 CPU 在线指令 case，另有记录在 plan 中的固定 UART RX warmup。完整 trace 7,383 个事件，CPU 512/UART 1,340 个独立局部 tick，fresh replay `matches=true`、`first_difference=null`。run identity SHA：`20d663c30b65b6d4fcae95daea715e0743c05b32f243029396b413261d267c33`。单例是身份/重放 smoke，不证明双源搜索或吞吐；receipt 的局部 tick 差与完整 plan/trace推进范围也不能混用为性能口径。

此前 `/tmp/myfuzz-p1-standard-evidence-20261006` 与 `/tmp/myfuzz-p1-unified-identity-uart-20261006` 保留为旧版本证据。新增模板及运输身份改变源码摘要，不能要求它们被当前源码 replay 接受。

## 验证限制与后续门禁

- continuous replay 核对完整接纳前缀及两层 checker 的声明范围，不重新执行搜索策略、每候选反馈或累计 decoder verdict。P1 身份完整不等于 P3～P5 搜索验收完整。
- cleanup 失败保留实际 running/失败 trace；正常终结的 replay API 不保证自动重现未完成 cleanup。磁盘写入失败可能使终态证据不可保存，incomplete 不能冒充完成。
- UART 调度吞吐优化仍需 source-associated RX 完成及 pending-event 终止语义；发送波形结束不等于 RTL 接收完成，未读 FIFO/pending IRQ 也不能随意清空。详见 [UART 吞吐审计](../../.superpowers/sdd/current-dataflow-uart-throughput-report.md)。
- P2 需显式 RuntimePathContract、同源 OR 分支 edge 身份和启动前预检；P3～P8 仍按总计划验收。

实现细节及独立检查见 [模板身份报告](../../.superpowers/sdd/current-dataflow-p1-template-identity-report.md)、[运输终结报告](../../.superpowers/sdd/current-dataflow-p1-transport-finalize-report.md)。本阶段工作未暂存或提交文件；工作区原有暂存项保持原样。

P1 验证命令针对上述保存时的源身份。后续 P2 会修改 dependency/decoder 等身份闭包，旧材料仍按其保存源码解释；新源码拒绝旧 bundle 不表示当时 replay 失败。P2 接入稳定后须重新保存真实 RTL 证据并 fresh replay。
