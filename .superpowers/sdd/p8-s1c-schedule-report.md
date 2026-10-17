# P8 S1c 实现报告：ISR 轮询调度抽稀（UART 只在需要时推进）

> 范围：只做设计 `.superpowers/sdd/p8-dma-continuous-design.md` §2.9 / §5 S1c：把
> `_ContinuousRxBoot.run_case` 的 ISR/轮询 schedule 从“每轮都推进 UART”改成“只有
> UART 有真实工作（`router.ready_targets` 或波形/访问冲突需要真实 UART 时钟）时
> 才在回合末尾推进 UART”。
>
> 不做：S2（描述符/三方向/多字）、S3（非法 + error ISR）、S4（认证/统一 replay）、S5。
> 不改 `fifo_origin`、`contracts.py`、DMA/UART RTL、`third_party/`、`agent.md`、未跟踪
> DMA 证据、P6/P7 文件；不放宽任何断言；不改 S1b 的搜索判据。
>
> **本文件不宣称 P8 通过**（S2–S4 未做）。S1c 的真实连续门/搜索门均已通过；但
> **UART ticks/case 的 5× 吞吐门未达到**（实测 1.37×），本报告按任务要求明确写
> “未达吞吐门”，并把原因归到被 §2.9 明确排除在 S1c 之外的“有界多 tick harness
> 命令”，不虚报、不换口径。

## 0. 交付摘要

| 项 | 状态 |
| --- | --- |
| 源码 `_poll_schedule` + `run_case` 轮询调用点 | 已实现（`c00642c`） |
| `_fifo_depth_after` 保持真实 post-pop depth（S1c 连带修正） | 已实现（`b721a9d`） |
| 新测试 `tests/integration/test_dma_uart_rx_uart_schedule.py`（5 项） | 已实现，纯软件全绿 |
| 纯软件 focused 门 | **71 passed, 3 skipped in 13.80s**（基线 66+3，新增 5 项） |
| 真实连续门（live tree + `flock -w 14400`） | **1 passed / 133.85s**（before 1 passed / 173.26s） |
| 真实 guided 搜索门（120s 预算） | **1 passed, 1 skipped / 199.43s**（before 237.00s）；`search_status=ok` |
| 连续门 UART ticks/case | **1,197.5 → 874.0（1.37×）**；轮询阶段 UART 步 **1,294 → 4（324.5×）** |
| 连续门 commands | **4,774 → 4,776（+2，基本不变）** |
| 5× 吞吐门 | **未达到**（见 §5.4；不虚报） |
| 证据 | `docs/reports/evidence/dma-s1c-20261018/`（before/after bundle、manifest、离线审计） |

## 1. 变更文件

源码：

- `src/myfuzz/integration/dma_uart_rx_runtime.py`
  - 新增模块级 `_poll_schedule(runner)`；`_ContinuousRxBoot._execute_case` 的
    ISR/轮询循环由 `recorder.advance(('dma', 'cpu', 'uart'))` 改为
    `recorder.advance(_poll_schedule(runner))`；
  - `_fifo_depth_after` 扩展为读取该例所有已保存的真实 FIFO depth probe
    （UART tick sample + CPU/DMA UART access 的 `read_capture.pre/post`），保持
    “本例最后一次真实 depth 观测”语义（S1c 抽稀后最后一条 tick 观测可能早于 DMA
    pop，否则会误报 stale depth=1）。

测试：

- `tests/integration/test_dma_uart_rx_uart_schedule.py`（新，fake runner，纯软件，5 项）。

未改：`_case_evidence`、`_prefix_digest`、boot/波形阶段、command/event/tick/prefix
边界、`replay_continuous_uart_rx`、`dma_uart_rx_search`、
`ibex_dma_uart_rx_continuous.py`、contracts/RTL。

## 2. 实现

### 2.1 `_poll_schedule(runner)`

```python
def _poll_schedule(runner):
    router = runner.sessions['cpu'].router
    uart = runner.sessions['uart']
    needs_uart = 'uart' in getattr(router, 'ready_targets', ())
    if not needs_uart:
        conflict = getattr(uart, 'register_access_conflict', None)
        needs_uart = callable(conflict) and conflict() is not None
    return ('dma', 'cpu', 'uart') if needs_uart else ('dma', 'cpu')
```

判定规则（与任务/设计 §2.9 一致）：

1. **无 UART 待服务、无波形/冲突**：只推进 `('dma','cpu')`。此时 UART 若被推进，
   只会产生一个空转 native tick 和一条空转命令，不改变任何真实因果。
2. **`uart` 在 `router.ready_targets`**：`('dma','cpu','uart')`，UART 放**末尾**。
   本回合 CPU/DMA 步骤新排的 UART MMIO 因 schedule 已在回合开始时确定，会在**下一
   回合**末尾被服务；本回合已就绪的请求仍在本回合被服务。这样保持“真实生产者
   CPU/DMA 步骤 → 目标 UART 步骤”的顺序，不会把请求排到其生产者之前。
3. **`uart.register_access_conflict()` 非 `None`**（序列波形仍在进行 / 真实 UART
   时钟是唯一合法推进）：同样追加末尾 `uart`，不跳过必要 tick。

`ready_targets` 只取“最老请求已 `target_pending` 且在该通道下一条”的目标；没有用
`pending_targets` 里“尚不可执行”的请求去做空转 UART tick。

### 2.2 `_fifo_depth_after`（保持逐例 evidence 语义）

S1c 抽稀后，一个已完成例可能不再有 DMA pop 之后的空转 UART tick，原来的“最后一条
`uart_tick_observation.post.probe_uart_fifo_depth`”会停在 push 后的 1（stale
pre-pop 采样），而真实 post-pop depth 0 仍保存在同一例的 DMA UART read 的
`target_uart_access.read_capture`（以及 CPU UART access 的 `read_capture`）里。
实现改为按 journal 顺序取所有真实 depth probe 的最后一个：

- `uart_tick_observation.post.probe_uart_fifo_depth`；
- `uart_rdata_access.read_capture.{pre,post}.probe_uart_fifo_depth`；
- `dma_edge.target_delivery.target_uart_access.read_capture.{pre,post}.probe_uart_fifo_depth`。

该 helper 不属于 `_case_evidence`，也不参与 `prefix_sha256` 计算；修正后 after 的
`fifo_depth_after` 回到 0，与 S1a before 及真实 post-pop 深度一致（详见 §5.4）。
第一次 after 运行（`c00642c`）的 bundle 中该字段为 1；该次运行的 bundle/日志仅保留
在本地 `.superpowers/p8-s1c-20261018/pre-fix-continuous/`，不作为最终证据，最终证据
是用 `b721a9d` 重跑的 bundle。

### 2.3 未改变的部分（逐例 evidence / IRQ / tick / prefix 边界）

- 波形阶段仍是 `advance(('uart',))`，直到 `uart_source_frame_end` 且
  `register_access_conflict() is None`；逐 tick 真实推进不变。
- `boot()` 仍是 `advance(('dma','cpu'))` 直到真实 UART CTRL 请求排队。
- 每例完成仍由真实 CPU `COMPLETED` store 判定；`_case_evidence` 的全部 join
  （frame→DMA UART read→RAM write→native IRQ→CPU take→ISR stores）未改。
- `command_start/end`、`event_start/end`、`ticks_before/after`、`prefix_sha256`、
  失败尝试边界均未改；`prefix_sha256` 因 schedule/事件减少而合法变化。
- 每个实际需要的 UART 命令都保留：UART queue pop 只发生在真实 uart 步骤里；
  波形期间首个 UART tick 仍会 drain boot 阶段排队的真实 CTRL 访问；STATUS 读、
  DMA master RDATA 读（同步在 DMA 步骤内）等真实访问不经过 schedule 删减。
- `replay_continuous_uart_rx` 不感知 schedule 来源，仍逐命令重放同一 plan；fresh
  replay 的逐字段比较全部相等（§5.4）。

## 3. RED（先失败）

### 3.1 schedule 抽稀 RED

测试文件：`tests/integration/test_dma_uart_rx_uart_schedule.py`（前 4 项）。改动源码前：

```
$ PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_uart_rx_uart_schedule.py
3 failed, 1 passed in 0.50s
```

- `test_poll_round_advances_uart_only_when_a_request_is_ready`：

  ```
  AssertionError: assert ('dma', 'cpu', 'uart') == ('dma', 'cpu')
    Left contains one more item: 'uart'
  ```

  即现实现每个轮询回合都带 `uart`，即使 `pending_at_start=False`。
- `test_before_after_only_removes_idle_uart_ticks`：before/after 相同（都每轮带
  `uart`），`new_uart == POLL_ROUNDS` 而非“只保留真实服务”的 1。
- `test_schedule_helper_keeps_uart_last_for_ready_or_conflicting_uart`：
  `AttributeError: module 'myfuzz.integration.dma_uart_rx_runtime' has no attribute
  '_poll_schedule'`。
- 第 4 项 `test_thinner_schedule_keeps_every_real_uart_service` 在 RED 阶段通过：
  它断言“抽稀后真实服务仍在”，是抽稀不得删真实服务的守护不变量。

### 3.2 FIFO depth evidence RED

在连续门完成后发现 after bundle 的 `fifo_depth_after=1`（stale），先加测试再修：

```
$ PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_uart_rx_uart_schedule.py
1 failed, 4 passed
AssertionError: assert 1 == 0
  where 1 = _fifo_depth_after(rows)
```

测试 `test_fifo_depth_after_reads_the_latest_real_probe` 要求：同一例中后面的
`uart_rdata_access`/`dma_edge` 捕获 post depth 0 时，`_fifo_depth_after` 必须返回 0；
无任何 probe 时返回 `None`。

RED 的 fake runner 只实现 boot 对象真正使用的 runner/recorder 表面
（`ready_targets`、`register_access_conflict()`、`events_since`、`local_ticks`、
fake journal），不启动 native RTL，不产生 native 证据。

## 4. GREEN（纯软件）

```
$ PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_uart_rx_uart_schedule.py
5 passed in 0.46s
```

5 项断言：

1. 无 UART 请求时轮询 schedule 恰为 `('dma','cpu')`；有请求时恰为
   `('dma','cpu','uart')` 且 uart 最后；整例只有真实 STATUS 服务那 1 轮带 uart；
   idle uart 回合数为 0。
2. 抽稀后真实服务序列仍为 `['ctrl_write', 'status_read', 'dma_rdata_read']`；
   波形阶段仍是 3 个 UART-only tick（fake 口径）。
3. before/after 对比（before 用测试内 monkeypatch 恢复“每轮 uart”的旧 schedule）：
   - 每回合 CPU/DMA 前缀都等于 `('dma','cpu')`，未被删/重排；
   - 真实服务序列完全相同（不丢服务）；
   - before 的 uart 步数 = 回合数，after 的 uart 步数 = 真实 uart 服务数；
   - 被删除的 uart 步数 == before 的 idle uart 步数；
   - after 的每个 uart 步都对应真实服务（`idle_uart is False`）；
   - 命令总数不变；CPU/DMA 的 local ticks 不变；只有 UART ticks 减少，减幅恰为
     删除的 idle 步数；逐例 counter/source_byte 不变。
4. `_poll_schedule` 单元：ready/conflict 四种组合，且 uart 永远最后。
5. `_fifo_depth_after`：tick / CPU access / DMA access 的 probe 顺序与 None 边界。

focused 纯软件门（设计 §6.2 列表 + S1a/S1b 新增文件 + 本测试）：

```
$ PYTHONPATH=src python3 -m pytest -q \
  tests/scenario/test_ibex_dma_example.py \
  tests/local_harness/test_wishbone_dma_scenario_session.py \
  tests/local_harness/test_wishbone_dma_session.py \
  tests/local_harness/test_wishbone_dma_error_recovery.py \
  tests/integration/test_dma_uart_rx_runtime.py \
  tests/integration/test_dma_uart_rx_boot_contract.py \
  tests/integration/test_dma_uart_rx_cursor.py \
  tests/integration/test_dma_uart_rx_failure_document.py \
  tests/integration/test_dma_uart_rx_replay_state_edges.py \
  tests/integration/test_dma_uart_rx_discovery_scope.py \
  tests/integration/test_dma_uart_rx_boot_object.py \
  tests/scenario/test_dma_chain_feedback.py \
  tests/integration/test_dma_uart_rx_search.py \
  tests/integration/test_dma_uart_rx_uart_schedule.py
71 passed, 3 skipped in 13.80s
```

基线：S1a/S1b 报告为 66 passed / 3 skipped；本增量新增 5 项，数量只增不减，既有
断言未改写。

## 5. 真实门与吞吐

### 5.1 门命令与结果（live tree + `flock -w 14400`）

连续门（`b721a9d`，heavy lock，`timeout 900`）：

```sh
flock -w 14400 .superpowers/heavy-worker.lock env \
  MYFUZZ_DMA_CONTINUOUS_REAL=1 \
  MYFUZZ_DMA_CONTINUOUS_CACHE=.superpowers/cache/local-harness \
  MYFUZZ_DMA_CONTINUOUS_EVIDENCE=docs/reports/evidence/dma-s1c-20261018/after/continuous \
  PYTHONPATH=src timeout 900 python3 -m pytest -xq \
  tests/integration/test_dma_uart_rx_runtime.py::test_continuous_native_uart_dma_prefix_and_failure
```

```
1 passed in 133.85s (0:02:13)   exit=0
start 2026-10-17T11:36:19Z / end 2026-10-17T11:38:39Z
```

搜索门（guided，120s，与 S1b before 同一 seed/预算；`timeout 1800`）：

```sh
flock -w 14400 .superpowers/heavy-worker.lock env \
  MYFUZZ_DMA_SEARCH_REAL=1 \
  MYFUZZ_DMA_SEARCH_CACHE=.superpowers/cache/local-harness \
  MYFUZZ_DMA_SEARCH_EVIDENCE=docs/reports/evidence/dma-s1c-20261018/after/search \
  MYFUZZ_DMA_SEARCH_SECONDS=120 \
  MYFUZZ_DMA_SEARCH_SEED=5a17c0de0badf00d0e0d010203040506 \
  PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
  tests/integration/test_dma_uart_rx_search_real.py
```

```
1 passed, 1 skipped in 199.43s (0:03:19)   exit=0
start 2026-10-17T11:38:57Z / end 2026-10-17T11:42:26Z
```

（skipped 的是需要 `MYFUZZ_DMA_SEARCH_UNIFORM=1` 的 uniform 对照臂；本增量的搜索门
要求是 guided 至少 1 passed，已满足。S1b 的 uniform 证据未重跑。）

### 5.2 连续门前后的逐字段对比（从保存 bundle 直接数）

before：`docs/reports/evidence/dma-s1c-20261018/before/continuous-{positive,fresh}.json.gz`
（S1a，HEAD `7e08913`）。after：`.../after/continuous/{positive,fresh}.json.gz`
（S1c，HEAD `b721a9d`）。两次运行的 source pins 均为 453 个
`src/myfuzz/**/*.py`，**唯一差异**是
`src/myfuzz/integration/dma_uart_rx_runtime.py`（before
`7b9379ab…`，after 当前 `6e494331…`）。

| 项 | before | after | 判据 |
| --- | --- | --- | --- |
| 连续门结果 | 1 passed / 173.26s | **1 passed / 133.85s**（−22.7% 墙钟） | 通过 |
| plan commands | 4,774 | 4,776（+2） | 命令流保留；每轮仍一条 advance |
| events | 34,794 | 29,636（−5,158） | 减少的是空转 UART tick 事件 |
| `local_ticks` | 1314 / 1394 / **4790** | 1316 / 1396 / **3496** | UART −1,294；CPU/DMA +2（MMIO 延后一回合） |
| UART `local_tick_sample`（pre/post） | 9580 / 9580 | 6992 / 6992 | post = UART ticks |
| UART `uart_tick_observation` | 4,790 | 3,488 | 权威 UART tick 数用 `local_tick_sample` post（=`local_ticks.uart`）；观测计数略少是少数寄存器访问 tick 不产生独立观测，口径与 before 相同 |
| 逐例 commands | 1188 / 1190 / 1190 / 1190 | 1190 / 1190 / 1190 / 1190 | 首例 +2 |
| 逐例 events | 8654 / 8657 / 8649 / 8649 | 7372 / 7365 / 7357 / 7357 | 减少空转 |
| 逐例 UART ticks | 1199 / 1197 / 1197 / 1197 | 874 / 874 / 874 / 874 | **1.3701×** |
| 逐例 CPU ticks | 326 / 324 / 324 / 324 | 328 / 324 / 324 / 324 | 首例 +2 |
| 逐例 DMA ticks | 346 / 344 / 344 / 344 | 348 / 344 / 344 / 344 | 首例 +2 |
| 逐例 UART 波形-only 命令 | 861 / 865 / 865 / 865 | 861 / 865 / 865 / 865 | **完全不变** |
| 逐例轮询 UART 步 | 326 / 324 / 324 / 324 | 1 / 1 / 1 / 1 | **1,294 → 4（324.5×）** |
| 逐例 UART 寄存器访问 tick | 12 / 8 / 8 / 8 | 12 / 8 / 8 / 8 | **完全不变** |
| `fifo_depth_after` | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 修正后与真实 post-pop 深度一致 |
| positive↔fresh | 全等 | **全等** | `cases`、`plan.commands`、`local_ticks`、`identities`、归一 events 全相等；4 个 execution UUID 互异 |
| 逐例 semantic 字段 | — | 与 before 全等 | `counter/source_byte/action_id/fifo_origin/proof_grade/status_register_flow/fifo_depth_after` |
| 逐例 `_case_evidence` join | — | 0 problems | frame→DMA UART read→RAM write→native IRQ→CPU take→ISR stores 全部重算通过（§5.3） |
| 事件索引字段 | — | 每例 11 个全部变化 | 事件总量减少导致索引合法平移，非因果差异 |
| `prefix_sha256` | 4 个互异 | 4 个互异且全部变化 | 命令/tick 前缀确实改变；positive==fresh |
| 受控失败 | phase=source、18 commands、200 events、ticks 16/16/5 | **相同**（failure/failure-fresh） | 失败前缀与 fresh 失败重放相等 |

逐例边界链（after）：commands `16→1206→2396→3586→4776`、events
`185→7557→14922→22279→29636`；before 为 commands
`16→1204→2394→3584→4774`、events `185→8839→17496→26145→34794`。链式
`case[i+1].command_start == case[i].command_end`、
`case[i+1].event_start == case[i].event_end`、
`case[i+1].ticks_before == case[i].ticks_after` 均成立。

**关于 CPU/DMA +2**：首例的 STATUS 读/DMA 读由“本回合末尾服务”改为“下一回合末尾
服务”，CPU 多停 1 tick/次，因此 CPU/DMA 各 +2、commands +2；cases 2–4 的时序没有
变化（0 增量）。这不是跳过必要 tick，也不是删命令，而是设计要求的“UART 放末尾、
本回合新排 MMIO 下一回合被服务”的合法代价。

### 5.3 因果字段重算（离线，只读 after bundle）

`audit_s1c_throughput.py` 对 after positive 逐例重算：

- 所有 `_case_evidence` 引用的事件都存在、kind 正确、位于该例 `event_start..end`；
- `fifo_read < dma_write < irq < cpu_load < completed` 严格递增；
- `bound_source_event_id` 是 `source_start`，`bound_take_event_id` 是
  `cpu_irq_taken`，两者 `source_event_id` 相等；`cpu_tick == 外部 IRQ local_tick`；
- `dma_irq_edge_event_id` 的 `native_local_tick == source_start.source_tick`；
- status delivery → CPU load → CPU store 顺序成立；
- DMA RAM write 值 == source byte；DMA UART read 值 == source byte；
- `fifo_origin='unknown'`、`proof_grade='bounded_historical_chain'` 未变。

结果：`case_joins=[]`，`ok=true`（`audit-throughput.json`）。

### 5.4 搜索门 before/after

| 项 | before（S1b，HEAD `7e08913`） | after（S1c，HEAD `b721a9d`） |
| --- | --- | --- |
| guided 结果 | 1 passed, 1 skipped / 237.00s | **1 passed, 1 skipped / 199.43s** |
| `search_status` | ok | **ok**（findings=[]，hard=[]） |
| `case_count` / `executed_cases` | 8 / 8 | 8 / 8 |
| `completed_chains` | 8 | 8 |
| `post_seed_cases` / `distinct_effective_specs` | 7 / 7 | 7 / 7 |
| `feedback_influenced` | true | true |
| `effective_search_seconds` | 52.233 | **41.105（−21.3%）** |
| `search_wall_seconds` | 72.352 | **58.919（−18.6%）** |
| search bundle commands / events | 9,534 / 69,390 | 9,536 / 59,064 |
| search bundle UART ticks/case | 1,197.25 | **874.0（1.37×）** |
| search bundle 轮询 UART 步 | 326 / 324×7（2,594） | 1×8（8） |
| 重算判据（离线 `_evaluate_search`） | ok | **ok，findings=[]** |
| fresh 全前缀 replay / 失败重放 | 通过（S1b 门） | **通过**（门内断言 `fresh.cases == cases`、ticks/plan 相等、失败 error/budget 相等） |

### 5.5 5× 吞吐门：**未达到（未达吞吐门）**

- 连续门总 UART ticks/case：**1,197.5 → 874.0，1.3701×**；搜索 bundle 同样
  **1.37×**。距离 5× 很远。
- 被删除的 1,294 个 UART tick **全部是轮询阶段的空转步**（1,294→4，324.5×）；
  真实波形-only UART tick（3,456）与 UART 寄存器访问 tick（12/8/8/8）**一个都没少**。
- commands 没有下降（4,774→4,776），因为“一轮询回合一条 advance 命令”的粒度没变；
  §2.9 的“commands/例显著下降”同样依赖把 545-tick 起始空闲边距 + 320-tick 8N1 帧
  压成**有界多 tick harness 命令**，而该改动被 §2.9 明确要求**不能与 S1c 混在一起**
  （会改 artifact/build 身份，必须重跑逐 bit 波形证明与 fresh replay）。
- 因此本增量**不宣称 5× 通过**：S1c 的实测收益是 −22.7% 连续门墙钟、−21.3% 搜索
  effective 时间、UART ticks −27%、轮询空转 UART 步 −99.7%；要达到 5× 需要后续
  的 harness 多 tick 增量并重建基线。

## 6. 明确未做 / 限制

1. **未达 5× 吞吐门**：S1c 只抽稀轮询空转；真实波形 tick 必须保留。5× 需要被
   §2.9 排除在 S1c 之外的多 tick harness 命令增量（改 build 身份、重跑逐 bit 证明）。
2. 未改 `fifo_origin`（仍 `unknown`）、`proof_grade`、contracts/RTL、S1b 搜索判据。
3. 未做 S2–S4：描述符、三方向、多字、非法/error ISR、认证、统一 typed normalizer/
   前缀 replay 均未做，**P8 仍不通过**。
4. schedule 只对 `_ContinuousRxBoot.run_case` 的 ISR/轮询阶段生效；boot 与波形阶段
   行为不变。
5. uniform 对照臂未在 S1c 重跑（门要求 guided；S1b 的 uniform 证据保留原处）。
6. 未 `git add` 其它代理的改动/证据；只提交本增量的源码、测试、报告、证据。

## 7. 复现命令

见 §4（纯软件）、§5.1（真实门）。离线审计：

```sh
PYTHONPATH=src python3 docs/reports/evidence/dma-s1c-20261018/audit_s1c_throughput.py \
  docs/reports/evidence/dma-s1c-20261018 \
  docs/reports/evidence/dma-s1c-20261018/audit-throughput.json
```

证据清单与文件哈希见
`docs/reports/evidence/dma-s1c-20261018/manifest.json`；本地原始日志见
`.superpowers/p8-s1c-20261018/live-{continuous,search}.log`（不提交）。
