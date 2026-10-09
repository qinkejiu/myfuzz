# 第二阶段 M0 基线进度（未完成）

日期：2026-10-09。范围：[第二阶段计划](../superpowers/plans/2026-10-09-stage2-declarative-cpu-ip-adaptation.md)的 A 工作包。A1、A3 已登记；A2、A4、A5 增量实施中。B–I 尚未执行，未取得新 L1–L3 或 HMAC 能力。

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

[资源策略](../../src/myfuzz/experiments/resource_policy.py)新增共用 heavy process supervisor，已接入首步 `run` 和 `replay`：

- 启动可用内存使用 Linux `MemAvailable`，存在 cgroup v2 上限时再取约束后的剩余额度。默认树 RSS 阈值为 `min(4 GiB, available − 2 GiB)`；预算不足 1 GiB 时不创建 worker。
- 同一仓库锁 `.superpowers/sdd/stage2-heavy-worker.lock` 只允许一个重型 worker。采样间隔 50 ms，记录进程树 RSS 峰值和实际耗时；这是采样后的终止阈值，不是内核分配硬限额。
- Linux subreaper 收养脱离原 process group 的后代；SIGTERM/HUP/INT 进入清理；任务失败、超预算、超时和正常结束均清理并 reap。恢复调用前信号 handler 与 subreaper 状态。为保证归属，调用者必须是单线程 main process 且没有既有直接子进程；否则启动前拒绝。
- `budget_terminated`／`startup_refused`／`wall_timeout`／`interrupted` 单列，`dut_finding=false`；不把资源错误记成 RTL finding。未执行时 RSS／耗时为 null，不伪造零性能指标。
- 首步默认 run/replay 共用 `.superpowers/cache/local-harness`，实际构建仍按现有 build digest 存储、校验 bytes；显式 cache 参数仍可指定，输出目录必须为新目录。

代码审查发现并通过真实子进程负例修复：默认 SIGTERM 不进入 finally；两次采样之间创建的 setsid 后代逃逸；已有子进程的后代误归属（现改为拒绝这种调用环境）；replay 拒绝丢 run log；零案例验收。最终复审为 Ready，无新增阻挡项。

A4/A5 仍不勾选：全部第二阶段构建／生成／持续运行／replay 入口尚未建立并统一接入 supervisor；JVM 显式 heap 门禁尚未实现，当前也没有可执行 Java 生成工具。不能把首步入口覆盖写成所有入口覆盖。

## 本轮验证与真实启动拒绝

最终软件回归 **245 passed、12 subtests passed，30.00 秒，exit 0**。涵盖首步真实分析器编排、配对验收、11 项真实子进程资源测试、replay identity／preflight／wall cut、begin 失败、reset 生命周期、stateful batch、partial replay、链证书与 generated session。日志为 `.superpowers/sdd/stage2-m0-regression-20261009.log`。

文档全库检查为 585 个 Markdown／1,267 条链接／83 条断链，exit 1；以 HEAD 的旧 Markdown 内容在相同当前文件集合上重核，断链仍为同一组 83 条，本轮新增断链为 0。这些历史路径主要指向已删除 runs 材料，既有删除说明中已登记；本轮不将全库检查写成通过。增量复核保存在 `.superpowers/sdd/stage2-m0-doc-link-delta-20261009.json`。

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

## 下一检查点

先把第二阶段重型入口统一接入资源监督并增加显式 JVM heap，再完成 A2 的证据摘要／文件 hash 与证书完整性重核。资源符合计划后，用全新目录执行首步短真实门禁；失败时保留回执并清理，不能调低 2 GiB 主机保留量或伪造可用内存以绕过门禁。通过 M0 后再进入 B/C 的描述、预检和基础事件。

```bash
PYTHONPATH=src python3 scripts/run_first_step_acceptance.py run \
  --seconds 2 --max-tests 3 \
  --output-dir runs/stage2-m0-ibex-smoke-20261009-retry1 \
  --cpu-retirement --gpio-consumption --native-irq-receipts \
  --compressed-trace --replay \
  --json-out .superpowers/sdd/stage2-m0-ibex-smoke-20261009-retry1-analysis.json
```

阶段目标保持完整：公共 L1–L3、基础／寄存器／功能事件、三类依赖、四核逐项条件、全部可运行 CPU 的五行功能验收、CVA6 五族替换、真实 HMAC 强制基础接入与完整 replay，均仍需后续门禁。
