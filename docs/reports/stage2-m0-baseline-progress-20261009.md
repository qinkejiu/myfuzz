# 第二阶段 M0 基线进度（未完成）

日期：2026-10-09。范围：[第二阶段计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)的 A 工作包。A1、A3 已登记；A2 的公共问题复核与修复完成，A4/A5 的监督入口和短 smoke 已运行，工作包尚待全路径审计。B–I 尚未执行，未取得新 L1–L3 或 HMAC 能力。

[机器可读验证摘要](stage2-m0-verification-summary-20261009.json)保存测试结果、基线与日志摘要，以及真实启动拒绝的完整回执。

实施起点为 Git `4095793d74e0fb516417888cc76e8b8ec35d4897`，本轮使用分支 `stage2-declarative-cpu-ip-adaptation`。原有计划／索引修改与第三方未跟踪内容保留。没有复制仓库、覆盖第一阶段材料或修改第三方源码。

## 基线与逐行登记

[身份快照](stage2-baseline-20261009.json)保存起点 HEAD 的 290 个核心文件 blob SHA、第三方 HEAD／dirty 状态、工具可执行文件 SHA／版本、76 份 profile／closure 摘要及 21 个独立验收对象。[矩阵](../STAGE2_ACCEPTANCE_MATRIX.md)将 4 CPU×5 功能族与 CVA6＋HMAC 基础门禁分别登记；所有门禁仍 pending，declared/effective/verified level 未确定。

CVA6 有现有固定 profile／AXI4 closure。BOOM 有本地源码与 Chipyard pin，但对应 Chipyard checkout、生成 RTL 与合法导出闭包缺失；Java、SBT、Mill、firtool 不在当前 PATH。CVW、VexiiRiscv 在仓库没有 CPU source checkout、固定配置或 profile。这是起点条件，最终 `skipped_unavailable` 必须在 F 阶段重新核对并关联受影响的五行。

HMAC 原生 RTL 存在，起点没有 peripheral profile。本快照不是 G1 的 protected core freeze；必须在基础框架完成后重新采集，不得拿起点 HEAD SHA 代替最终接入 SHA。

## 已复现并修复的公共问题

- 首步真实 `--replay` 成功结果被保存为含 `stdout` 的执行日志，分析器却要求顶层 bool `matches`；旧编排测试替换分析器而漏检。新测试使用真实分析器，先复现有效 replay 后分析失败，再修复。[入口](../../scripts/run_first_step_acceptance.py)解析真实比较输出，严格核对 exit 0/2 和 bool verdict；同时保留命令、原始 stdout/stderr、资源回执。比较日志仍不等同于独立 artifact equality，`replay.verified` 保持 false。
- [P5 配对验收](../../src/myfuzz/scenario/p5_acceptance.py)曾允许缺失验证数、零连续时间、零冷时间、零验证数被另一文档的 24 覆盖、零 case_count 被另一文档覆盖，以及两臂零案例／空回执伪通过。六个负例均先观察到 `met=True`，再修复：时间、案例数、验证数必须为正；明确的零和非法数据不能用另一文件兜底；跨文档案例／验证计数矛盾拒绝。
- 首步日志改为逐阶段持久化。replay 启动拒绝、输出非法或后续分析异常，不会再丢失已完成 online run 的资源回执。

原第一阶段 schema／事件未改写，旧报告不回填新字段；本轮修复只改变当前入口和当前只读验收判断，不重新宣称历史证据通过。

## 资源与清理的已实现范围

[资源策略](../../src/myfuzz/experiments/resource_policy.py)新增共用 heavy process supervisor；首步 `run`/`replay` 和通用[第二阶段重型任务入口](../../scripts/run_stage2_heavy_task.py)都能使用相同预算、锁和回执：

- 启动可用内存使用 Linux `MemAvailable`，存在 cgroup v2 上限时再取约束后的剩余额度。默认树 RSS 阈值为 `min(4 GiB, available − 2 GiB)`；预算不足 1 GiB 时不创建 worker。
- 同一仓库锁 `.superpowers/sdd/stage2-heavy-worker.lock` 只允许一个重型 worker。采样间隔 50 ms，记录进程树 RSS 峰值和实际耗时；这是采样后的终止阈值，不是内核分配硬限额。
- Linux subreaper 收养脱离原 process group 的后代；SIGTERM/HUP/INT 进入清理；任务失败、超预算、超时和正常结束均清理并 reap。恢复调用前信号 handler 与 subreaper 状态。为保证归属，调用者必须是单线程 main process 且没有既有直接子进程；否则启动前拒绝。
- `budget_terminated`／`startup_refused`／`wall_timeout`／`interrupted` 单列，`dut_finding=false`；不把资源错误记成 RTL finding。未执行时 RSS／耗时为 null，不伪造零性能指标。
- 首步默认 run/replay 共用 `.superpowers/cache/local-harness`，实际构建仍按现有 build digest 存储、校验 bytes；显式 cache 参数仍可指定，输出目录必须为新目录。通用入口把 `{run_dir}`/`{cache_dir}` 参数展开，记录完整 stdout/stderr 和哈希，供各 Stage 2 构建／搜索／replay 任务复用。
- 直接 `java`、SBT heavy command 必须具有唯一且不超过 RSS 阈值的 heap 上限（`-Xmx`／`-XX:MaxHeapSize`，SBT 为 `-J-` 形式）。Java 解析接受十进制前导零、十六进制及 `t` 单位，畸形值拒绝启动；环境注入、`@argfile` 和 `-XX:VMOptionsFile` 在创建 worker 前拒绝。SBT 扫描 task 名之后的所有参数，并拒绝 `-mem`／`--mem`、环境覆写，以及项目 `.jvmopts`／`.sbtopts` 和 `/etc/sbt/sbtopts` 中的隐藏配置；裸 `sbt -Xmx` 不算 JVM 限额。Mill 直接命令暂时 fail closed：官方 launcher 的 JVM 设置还可来自 `JAVA_OPTS`、`.mill-jvm-opts`、`MILL_JVM_OPTS_PATH` 和 build header，当前没有版本锁定且覆盖这些来源的 adapter。孩子进程输出中的非法 UTF-8 字节会转义为可保存、可哈希的日志。此机器没有 Java/SBT/Mill，所以实际 JVM 启动仍未验证。

代码审查发现并通过真实子进程负例修复：默认 SIGTERM 不进入 finally；两次采样之间创建的 setsid 后代逃逸；已有子进程的后代误归属（现改为拒绝这种调用环境）；replay 拒绝丢 run log；零案例验收。最终复审为 Ready，无新增阻挡项。

A4/A5 仍不勾选：通用入口现已提供串行 worker、共享默认身份缓存、新 run 目录、Java/SBT heap 预检及异常清理；但所有各阶段实际执行命令尚未迁移至该入口，也没有 JVM 工具可做真实生成校验。直接 Mill 命令在版本锁定 adapter 完成前会拒绝启动。首步与通用入口的 CLI／资源负例已验证，不能据此写成所有生产路径已覆盖。

## 本轮验证与真实启动拒绝

最初 M0 回归 **245 passed、12 subtests passed，30.00 秒，exit 0**。最新三组互不依赖的 pytest 子进程并行运行：资源／wrapper 74 passed、首步／P5 100 passed、场景／生命周期 127 passed，另有 12 subtests passed；共 **301 passed、12 subtests passed，均 exit 0**。资源组包括 SBT 参数顺序／隐藏配置、Java heap 数值格式、非法字节输出和 Mill fail-closed 的回归。分组日志及 SHA-256 由[机器可读验证摘要](stage2-m0-verification-summary-20261009.json)维护。

文档全库检查为 585 个 Markdown／1,273 条链接／83 条断链，exit 1；对本轮变更的文档逐项核对，新增断链为 0。这些历史路径主要指向已删除 runs 材料，既有删除说明中已登记；本轮不将全库检查写成通过。先前 HEAD 内容复核也得到相同的 83 条断链，增量复核保存在 `.superpowers/sdd/stage2-m0-doc-link-delta-20261009.json`。

```bash
PYTHONPATH=src python3 -m pytest -q \
  tests/integration/test_first_step_acceptance.py \
  tests/experiments/test_process_budget.py tests/experiments/test_resource_policy.py \
  tests/scenario/test_p5_acceptance_suite.py tests/scenario/test_replay_preflight.py \
  tests/scenario/test_replay_wall_cut_locator.py tests/scenario/test_begin_failure_evidence.py \
  tests/scenario/test_reset_quiesce_lifecycle.py tests/scenario/test_stateful_batch.py \
  tests/scenario/test_online_session_partial_replay.py tests/scenario/test_chain_certificates.py \
  tests/scenario/test_chain_certificate_serial_token.py tests/local_harness/test_session.py \
  tests/local_harness/test_generated_replay_identity.py
```

真实 Ibex smoke 尝试使用 2 秒／最多 3 例，启用退休、GPIO 消费及 native IRQ 回执，要求 compressed trace 和完整 fresh replay。启动时可用内存 **3,049,791,488 bytes**，扣除 2 GiB 后阈值 **902,307,840 bytes**，低于 1 GiB；监督器在创建 worker 前拒绝。保存的回执是 `runs/stage2-m0-ibex-smoke-20261009-resource-receipt/first_step_acceptance_run.json`：`command_exit_codes=[]`、`status=startup_refused`、`analysis=null`、`replay=null`。没有 RTL case、构建或 replay 通过，不能登记为 DUT failure 或 smoke success。

随后可用内存恢复到 5,978,308,608 bytes 后，`retry1` 在同一首步入口完成了 3/3 `complete` case，完整 trace 含 5,586 个事件，`effective_search_seconds=2.489692`，fresh replay exit 0 且 `matches=true`。运行树 peak RSS 510,930,944 bytes／额度 3,830,824,960 bytes；replay peak 220,811,264 bytes／额度 3,884,466,176 bytes。计划、运行 identity、session manifest、压缩 events、meta、逐例 receipts、report 和 run/replay logs 的 SHA-256 已保存于 [短 smoke 证据](stage2-m0-ibex-short-smoke-20261009.json)。这只是历史 Ibex＋双 PULP GPIO 首步兼容 smoke，不能给 20 行 Stage 2 矩阵任何一行授级。分析器把 3/3 来源 admissions 都标记为 incomplete，0 条完整认证链（缺口 `instruction_fetch=1`、`pin8_injection=2`）；因此不声称端到端链/s 或已验证功能链。replay 命令的 `matches=true` 代表其固定 replay 比较通过；first-step wrapper 分析仍把比较 JSON 标为 `verified=false`、缺少独立 trace 差分字段，证据边界如实保留。

## 下一检查点

将每项 Stage 2 重型构建／搜索／replay 命令通过 [stage2 heavy-task 入口](../../scripts/run_stage2_heavy_task.py)启动，并让各自声明的输出与 identity cache 路径接入；复核 A2 对 certificate identity、batch 和 failure cleanup 的剩余证据。legacy Ibex 首步 smoke 已有有效 fresh replay，今后用其作为第一阶段兼容回归。M0 门槛通过后进入 B/C 的声明契约、能力预检与基础事件。

```bash
PYTHONPATH=src python3 scripts/run_first_step_acceptance.py run \
  --seconds 2 --max-tests 3 \
  --output-dir runs/stage2-m0-ibex-smoke-20261009-retry1 \
  --cpu-retirement --gpio-consumption --native-irq-receipts \
  --compressed-trace --replay \
  --json-out .superpowers/sdd/stage2-m0-ibex-smoke-20261009-retry1-analysis.json
```

阶段目标保持完整：公共 L1–L3、基础／寄存器／功能事件、三类依赖、四核逐项条件、全部可运行 CPU 的五行功能验收、CVA6 五族替换、真实 HMAC 强制基础接入与完整 replay，均仍需后续门禁。
