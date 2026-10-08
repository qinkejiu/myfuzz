# 吞吐量是多少（实测）

日期：2026-10-08。本文给出**实测吞吐量**：先是直接答案（几组真实运行的每秒例数），再是分项拆解，最后回答"为什么比 2026-10-06 的同配置运行慢了约 24 倍"，并给出可做的改进。

> 测量方法：读保存运行自己的 `report.json` / `receipts.jsonl` / `online_final_trace.meta.json`；另用两个只读探针脚本（`scripts/profile_online_step_breakup.py`、`scripts/profile_online_host_cost.py`）在**同 cache 的真实 RTL 会话**上单独计时。全部命令与产物见文末。

---

## 1. 直接答案：三个口径

| 运行 | 例数 | 事件数 | 有效搜索秒 | 墙钟秒 | **有效例/s** | **墙钟例/s** | **毫秒/例** | 事件/例 |
|---|---|---|---|---|---|---|---|---|
| Ibex＋双 PULP GPIO（600 s 长跑） | 368 | 570,196 | 600.363 | 601.544 | **0.6130** | **0.6118** | **1,634.6** | 1,549.4 |
| Ibex＋双 PULP GPIO（31 s 短门禁） | 24 | 31,795 | 31.274 | 32.441 | **0.7674** | 0.7398 | 1,351.7 | 1,324.8 |
| Ibex＋OpenTitan UART（异构） | 60 | 76,332 | 79.934 | 81.683 | **0.7506** | 0.7346 | 1,361.4 | 1,272.2 |

**也就是说：当前主线（在线 RFuzz + 全部探针）的吞吐量约为 0.61–0.77 例/秒，即每例 1.35–1.63 秒。**

其余派生量（来自 `p5_arm_metrics.v1`）：

| 派生量 | 600 s GPIO | UART |
|---|---|---|
| 认证完整链/s | **0.044973**（27 条） | 0（UART 链证书是离线只读生产者算的，不在运行内） |
| 覆盖增量 | 目标位 0.006663 位/s、见证边 0.014991 条/s | 0.046474 位/s |
| 无效/超时比例 | 0.0（0/368） | 0.05（3/60） |
| 逐例 p50 / p95 | 1.648 s / 2.377 s | 1.479 s / 1.919 s |

### 1.1 对照：同配置的历史运行快约 24 倍

| 运行（同机、同配置：32 advances × `[cpu,gpio_a,gpio_b]`、每例 100 local tick） | 例数 | 墙钟秒 | 墙钟例/s | 毫秒/例 | 事件/例 |
|---|---|---|---|---|---|
| `ibex-pulp-online-20261006-balanced-600s`（2026-10-06） | **8,723** | 600.201 | **14.5335** | **68.8** | 428.5 |
| `current-dataflow-p5-chain-600s-20261007-online`（当前） | **368** | 601.544 | **0.6118** | **1,634.6** | 1,549.4 |

结构（advances、调度顺序、local tick 数）完全相同，**差的是每例的事件量（428.5 → 1,549.4，3.6×）与每命令的开销**（见 §3）。这就是"吞吐量低"的真实来源，不是仿真变慢。

---

## 2. 分项拆解：时间花在哪

用保存运行自己的逐例分项计时（`receipts.jsonl:online_phase_timing_seconds`），按"逐例求和"口径：

| 分项 | GPIO 600 s（p50） | 占每例 | UART（p50） | 占每例 |
|---|---|---|---|---|
| **`rtl_submit`** | **1.305 s** | **≈96%** | **1.305 s** | **≈94%** |
| `trace_digest` | 0.048 s | 3.5% | 0.024 s | 1.8% |
| `interaction_ingest` | 0.015 s | 1.1% | 0.011 s | 0.8% |
| `selection_decode` | 0.0001 s | — | 0.0002 s | — |
| `feedback_credit` / `receipt_build` / `checker` | < 1 ms | — | < 1 ms | — |

（30 秒短门禁的占比：GPIO `rtl_submit` 30.572/32.324 = **94.6%**；UART 78.919/81.567 = **96.8%**。）

**触发次数 × 单次成本**：

| 量 | GPIO | UART |
|---|---|---|
| 每例 `advances` | 32 | 96 |
| 每次调度的部件数 | 3 | 2 |
| **每例本地命令（STEP）数** | **96**（实测 96–98） | **192**（实测 192–195） |
| 每例 `rtl_submit` | 1.305 s | 1.305 s |
| **折算每条命令** | **13.27 ms** | **6.85 ms** |
| 命令往返（`local_command_roundtrip`） | p50 0.0497 s / 例 | p50 0.2088 s / 例 |
| 其余主机时间（`host_remainder`） | p50 1.1839 s / 例 | p50 1.1163 s / 例 |

**结构性结论**：**一条宿主命令只推进最快域一个 tick**（driver 协议 `local_driver.v1`，`STEP_*` 各推进一个周期），所以每例的耗时 ≈ 命令数 × 单命令固定成本。命令数由 `advances × 部件数` 决定，与"搜索是否有进展"无关。

---

## 3. 单命令成本到底花在哪（两次独立探针）

### 3.1 探针 A：同 cache 起真实会话，分别计时

`scripts/profile_online_step_breakup.py`（复用 `runs/p5-uart-waveform-gate-20261008-cache`）：

| 阶段 | 实测 |
|---|---|
| RTL 会话构造（prepare） | 9.92 s |
| 运行时契约声明 + `begin()` | 25.71 s |
| bootstrap 例（1236 advances × 2 = 2472 命令） | **1.299 s → 0.53 ms/命令** |
| 一个普通例（96 advances × 2 = 192 命令） | **0.140 s → 0.73 ms/命令** |

两者同量级，且与保存运行折算出的 6.85–13.27 ms/命令 相差约一个数量级——说明**发布运行里每条命令还背着 CLI/记录器/事件记账等额外开销**。

### 3.2 探针 B：cProfile 一次真实会话，看主机侧热点

`scripts/profile_online_host_cost.py`：

```text
cases=1 steps=192 elapsed=0.847s => 4.414 ms/step
4,270,475 function calls in 0.820 s          ← 192 步产生 427 万次 Python 调用
  deepcopy                501,609 次   tottime 0.246s  cumtime 0.450s  ← 主机侧最大单项
  dict.get              1,051,386 次
  select.select               600 次   0.027s
```

`deepcopy` 的调用者（cProfile callers）：

| 调用者 | 次数 | 累计 |
|---|---|---|
| `runner.py:2001 execute_step`（命令账本缓存路径） | 768 | 0.257 s |
| `event_provenance.py:21 decorate`（每个事件盖来源戳） | 2,491 | 0.067 s |
| `local_harness/cpu_session.py:528 _step_local`（采样回执） | 288 | 0.036 s |
| `runner.py:442 events_since` | 1 | 0.084 s |

**注意**：cProfile 会放大嵌套小调用的成本，所以"0.847 s/192 步"不能直接当作发布运行的单命令成本；但它明确指认了**主机侧 Python 的第一热点是 `deepcopy`（约占主机 CPU 的一半）**，而其余是子进程往返与 JSON 编解码。

---

## 4. 怎么提高（按预期收益排序）

| # | 措施 | 预期收益 | 代价 |
|---|---|---|---|
| 1 | **批量 tick**：驱动新增 `STEP_MANY n`（一次命令推进 n 个本地 tick，只回末态 + 必须保留的采样） | 命令数 ÷ n。以 n=32 估算，`rtl_submit` 可从 1.3 s 降到 ~0.05–0.1 s 级 → **吞吐量提升 10× 量级** | 需改 C++ 驱动 + `driver_renderer` + 每个 session 声明"哪些中间采样必须保留"；改驱动协议 = decode space 变更，旧 bundle 不可 replay |
| 2 | **去掉热路径 `deepcopy`**：`execute_step` 账本缓存、`event_provenance.decorate`、`_step_local` 采样改为不可变共享或浅拷贝 | 主机侧约 30–50%（对应总时长几个百分点到十几个百分点；探针 A 显示发布运行的单命令成本远高于纯主机成本，故这项单独做收益有限） | 需要论证不可变性边界（这是"回执不可被改"的安全机制，不能简单删） |
| 3 | **二进制命令/回执帧**替代文本行 + 十六进制 JSON | 单命令成本降 2–5× | 协议版本升级，所有 session 解析层同步改 |
| 4 | **减少 `advances` 轮数**（用真实因果点替代固定 96/32 轮） | 线性降低命令数 | 属搜索语义变更，需要证明"少步不丢观察" |
| 5 | **复用会话启动**：prepare 9.9 s + `declare/begin` 25.7 s 只付一次 | 长跑已摊薄；短门禁受益明显（复用 `--cache-dir`） | 低风险 |

**诚实标注**：措施 1–4 我都**没有实现**，上表是"基于实测每命令成本的推算"。当前仓库里**不存在** `STEP_MANY` 之类的批量命令；`deepcopy` 也仍在热路径上。

---

## 5. 一句话总结

> **当前吞吐量：约 0.61–0.77 例/秒（每例 1.35–1.63 秒）**，其中约 95% 花在 `rtl_submit`；根因是**每条命令只推进一个本地 tick**，而每例要 96（GPIO）或 192（UART）条命令，单命令 6.85–13.27 ms。
> 同配置的 2026-10-06 运行是 **14.53 例/秒（68.8 ms/例）**——慢的不是仿真，而是**每例事件量涨了 3.6 倍 + 单命令固定成本没优化**。把命令批量化的收益最大（估算 10× 量级），代价是驱动协议与运行身份同步变更。

---

### 附：本文的原始产物与复算命令

| 数字 | 来源 |
|---|---|
| §1 三个口径 | `runs/<run>/report.json`（`tests`/`effective_search_seconds`/`wall_clock_seconds`/`elapsed_seconds`）+ `online_final_trace.meta.json`（`event_count`） |
| §1 派生量 | `runs/current-dataflow-p5-final-20261007-logs/p5_arm_metrics.json`（`p5_arm_metrics.v1`） |
| §2 分项占比 | 各运行的 `receipts.jsonl:online_phase_timing_seconds` / `online_submit_timing_seconds` |
| §3.1 探针 A | `scripts/profile_online_step_breakup.py`；摘要 `runs/current-dataflow-p5-final-20261007-logs/step_breakup.json` |
| §3.2 探针 B | `scripts/profile_online_host_cost.py`；输出 `runs/current-dataflow-p5-final-20261007-logs/host_cost_profile.txt`、`host_cost_callers.txt` |
| 命令数结构 | `runs/<run>/online_plan.json`（`cases[].advances`）、回执 `local_ticks` |
| 驱动协议 | `src/myfuzz/local_harness/rtl/local_driver_v1.h`（`STEP_*` 各推进一个 tick）、`src/myfuzz/local_harness/wire.py` |
| §1.1 对照运行 | `runs/ibex-pulp-online-20261006-balanced-600s`（同结构、无逐例分项计时字段） |
