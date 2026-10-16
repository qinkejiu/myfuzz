# Compiled F4 Ibex 实际验证 — 2026-10-17

实验性 F4 的生产文件入口已在冻结源码上完成：**3 个连续真实 RTL candidate，2 次完整 fresh prefix replay 均 `matches=true`，真实进程退出码 0**。这只验证固定 RV32I writer + native OBI/APB + live GPIOEN 链；不代表任意指令搜索、覆盖引导搜索、CV32E40P 接入或完整 P7/D4 已完成。

## 证据与源码

- [证据归档](evidence/compiled-f4-ibex-20261017/evidence.tar.gz)、[归档 SHA256](evidence/compiled-f4-ibex-20261017/evidence.tar.gz.sha256)、[源码 pin 摘要](evidence/compiled-f4-ibex-20261017/source-pins.json)。归档包含原始 native events、完整 prefix、真实 replay 返回、生成 RTL/driver、输入/source hashes、真实命令、软件测试日志及失败 attempt 报告。
- 冻结源码基点 `bdeee0b957a104b9e66abab52e219e15d0fee62e`；完整 32608 文件 manifest 的 SHA256 为 `eb5d2bc471900de9143bfb31fbf8d7bd287f1afa962367861cd0138a542e3788`。运行前后远端逐文件验证均无差异。完整 source snapshot 独立复制，无源文件硬链接共享。
- 本地完整 snapshot：`/home/qinkejiu/myfuzz/.superpowers/f4-verification-20261017/snapshot-attempt3`；远端：`/root/fanzehui/f4-verification-20261017/project-attempt3`。后续源码变化须另行冻结验证，本报告不自动覆盖后续布局等实现。

## 真实命令与结果

在远端 snapshot 中加载 `/root/fanzehui/system-20261016/environment.sh`，并将 snapshot 的 `src`/根目录及 `/root/fanzehui/system-20261016/pythonlib` 放入 PYTHONPATH，执行：

```bash
python3 scripts/run_compiled_dataflow.py \
  --compose configs/scenarios/compiled-f4-obi-apb-ibex/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-ibex/execution_supplement.json \
  --records configs/scenarios/compiled-f4-obi-apb-ibex/example_records.json \
  --executor compiled_f4_obi_apb \
  --output /root/fanzehui/f4-verification-20261017/evidence-attempt3 \
  --cache-dir /root/fanzehui/system-20261016/f4-ibex-cache \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock \
  --run-id compiled-f4-ibex-real --max-cases 4 --rounds-per-case 128 --replays 2
```

Wrapper PID 159073、Python PID 159074；初始真实 harness PID 为 163380/163519，第二次 fresh 的现场 PID 为 175538/175677。进程结束后已确认 Python PID 不存在且 canonical heavy lock 无 holder。**真实退出文件位于 `/root/fanzehui/f4-verification-20261017/logs/entry-attempt3.exit`，值为 0**；stdout 位于同目录 `entry-attempt3.log`，不是目录外同名文件。

| 项目 | 实测结果 |
| --- | --- |
| 原始 candidate 值 | `0x55`、`0xaa`、`0x12345678` |
| 实际首取指 | `0x10080`，native event 17；未把配置 boot base `0x10000` 当作首取指 |
| 连续 instruction slot | `0x10080`、`0x100b0`、`0x100e0` |
| 每 case | 8 个 functional instruction native 消费 hops；GPIOEN prerequisite/commit/postcondition；声明 edge `[5,0]`、`[6,0]` |
| 初始 target 进程 | 3 个 case 的 live witness PID 均为 163380 |
| case wall 时间 | 68.49 / 67.81 / 68.92 秒 |
| fresh replay | `matches=true` 两次；234.42 / 237.13 秒 |
| generation / startup / 总时间 | 39.37 / 73.75 / 795.37 秒 |

初始及两个 fresh 完整 semantic hash 均为：

`568802e698c6fa86675b67e0cc8610af78b09d3c0253d54efd92b197dd09d7fa`

比较保留完整 online plan/semantic identity，仅剥离 prerequisite/postcondition 中声明的进程 scope；没有扩大模糊 normalization。上述耗时属于 directed 执行，不据此宣称可用搜索吞吐。

## 软件控制与实际发现

当前实现的 focused suites：`PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_f4.py tests/integration/test_compiled_execution_files.py`，**40 passed、1 skipped，127.66 秒，真实 pytest exit 0**。被跳过的是另一条 opt-in native pytest；本报告的真实 native 证据来自上述生产入口，没有把 skip 计成 native pass。

控制覆盖 source symlink retarget、依赖集合变化、unsupported executor/锁/失败报告、native instruction/data acceptance/response/error/value/version、router 身份、target commit 缺失/错 tick/错 context/错值，以及 caller/private ownership、physical map、request、compiled document、artifact 的启动后变更。这些软件事件/authority mock 控制证明拒绝路径，不是硬件负向故障注入。

Attempt1 在 native 构造前因同机 DMA 持 canonical lock 拒绝，真实 exit 2。Attempt2 暴露真实 constructor 缺陷：通用 deepcopy 无法复制 admitted graph 的 MappingProxyType，真实 exit 2，`startup_partial_trace_available=false`。修复 `bdeee0b` 私有复制 immutable proxies、核对 exact issued identity 并重新 admission；实际 profile 回归禁止复制期间任何 Popen，1 passed，16.27 秒。失败证据与 `.incomplete` 均保留，未归为 DUT 语义失败。

## 保留的能力缺口

CV32E40P 的合法 ABI 没有 native error role，当前 executor 仍拒绝它。Ibex 的通过不能替代 CV32；[no-error variant 设计](compiled-f4-no-error-variant-design-20261017.md) 只给出后续合同/门控方案，尚未实现或验证。声明驱动 candidate layout、通用受信 witness/assertion 调度、真实覆盖反馈及完整失败 prefix replay 仍需分别集成和验收。
