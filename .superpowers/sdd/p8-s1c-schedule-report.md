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
> **本文件不宣称 P8 通过**（S2–S4 未做），也不宣称 5× 吞吐门通过。
> 本提交先冻结源码/测试与报告的非门部分；真实连续门/搜索门的原始日志、bundle、
> before/after 数字在紧随其后的证据提交中追加（§5 的 “pending” 会被实测替换）。

## 0. 交付摘要

| 项 | 状态 |
| --- | --- |
| 源码 `_poll_schedule` + `run_case` 轮询调用点 | 已实现（单文件、最小 diff） |
| 新测试 `tests/integration/test_dma_uart_rx_uart_schedule.py`（4 项） | 已实现，纯软件全绿 |
| 纯软件 focused 门 | **70 passed, 3 skipped in 12.88s**（基线 66+3，新增 4 项） |
| 真实连续门（live tree + `flock -w 14400`） | pending（§5） |
| 真实 guided 搜索门（120s 预算） | pending（§5） |
| before/after UART ticks/commands 实测与 5× 判据 | pending（§5）；预期诚实结论见 §5.3 |

## 1. 变更文件

源码：

- `src/myfuzz/integration/dma_uart_rx_runtime.py`
  - 新增模块级 `_poll_schedule(runner)`；
  - `_ContinuousRxBoot._execute_case` 的 ISR/轮询循环由
    `recorder.advance(('dma', 'cpu', 'uart'))` 改为
    `recorder.advance(_poll_schedule(runner))`。

测试：

- `tests/integration/test_dma_uart_rx_uart_schedule.py`（新，fake runner，纯软件）。

未改：`_case_evidence`、`_case_boundaries`、`_prefix_digest`、boot/波形阶段、
`replay_continuous_uart_rx`、`dma_uart_rx_search`、`ibex_dma_uart_rx_continuous.py`、
contracts/RTL。

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

`ready_targets` 只取“最老请求已 `target_pending` 且在本通道下一条”的目标；对
CPU data 通道，队列顺序与 UART 服务顺序一致。没有用 `pending_targets` 里“尚不可
执行”的请求去做空转 UART tick。

### 2.2 未改变的部分（逐例 evidence / IRQ / tick / prefix 边界）

- 波形阶段仍是 `advance(('uart',))`，直到 `uart_source_frame_end` 且
  `register_access_conflict() is None`；波形逐 tick 真实推进不变。
- `boot()` 仍是 `advance(('dma','cpu'))` 直到真实 UART CTRL 请求排队。
- 每例完成仍由真实 CPU `COMPLETED` store 判定；`_case_evidence` 的全部 join
  （frame→DMA UART read→RAM write→native IRQ→CPU take→ISR stores）未改。
- `_case_boundaries`（`command_start/end`、`event_start/end`、`ticks_before/after`、
  `prefix_sha256`、`fifo_depth_after`）未改；失败尝试边界未改。
- 每个实际需要的 UART 命令都保留：UART 的 queue pop 只发生在真实 uart 步骤里；
  波形期间首个 UART tick 仍会 drain boot 阶段排队的真实 CTRL 访问；STATUS 读、
  DMA master RDATA 读（同步在 DMA 步骤内）等真实访问不经过 schedule 删减。
- `replay_continuous_uart_rx` 不感知 schedule 来源，仍逐命令重放同一 plan；因此
  fresh replay 语义不变（同一 plan 在新进程重新执行，命令/事件/tick 逐字段比较）。

## 3. RED（先失败）

测试文件：`tests/integration/test_dma_uart_rx_uart_schedule.py`（4 项）。在改动源码前：

```
$ PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_uart_rx_uart_schedule.py
3 failed, 1 passed in 0.50s
```

失败原因：

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
  它断言“抽稀后真实服务仍在”，是抽稀不得删真实服务的守护不变量，不要求先失败。

RED 的 fake runner 只实现 boot 对象真正使用的 runner/recorder 表面
（`ready_targets`、`register_access_conflict()`、`events_since`、`local_ticks`、
fake journal），不启动 native RTL，不产生 native 证据。

## 4. GREEN（纯软件）

```
$ PYTHONPATH=src python3 -m pytest -q tests/integration/test_dma_uart_rx_uart_schedule.py
4 passed in 0.47s
```

4 项断言：

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
   - 命令总数不变（每回合仍一条 advance 命令）；CPU/DMA 的 local ticks 不变；
     只有 UART ticks 减少，减幅恰为删除的 idle 步数；逐例 counter/source_byte 不变。
4. `_poll_schedule` 单元：ready/conflict 四种组合，且 uart 永远最后。

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
70 passed, 3 skipped in 12.88s
```

基线：S1a/S1b 报告为 66 passed / 3 skipped；本增量新增 4 项，数量只增不减，既有
断言未改写。

## 5. 真实门与吞吐（pending → 实测后替换）

### 5.1 门命令（与 §6.3/§6.4 一致；live tree + heavy lock）

连续门：

```sh
MYFUZZ_DMA_CONTINUOUS_REAL=1 \
MYFUZZ_DMA_CONTINUOUS_CACHE=.superpowers/cache/local-harness \
MYFUZZ_DMA_CONTINUOUS_EVIDENCE=docs/reports/evidence/dma-s1c-20261018/after/continuous \
PYTHONPATH=src timeout 900 python3 -m pytest -xq \
  tests/integration/test_dma_uart_rx_runtime.py::test_continuous_native_uart_dma_prefix_and_failure
```

搜索门（guided，120s，与 S1b before 同一 seed/预算）：

```sh
MYFUZZ_DMA_SEARCH_REAL=1 \
MYFUZZ_DMA_SEARCH_CACHE=.superpowers/cache/local-harness \
MYFUZZ_DMA_SEARCH_EVIDENCE=docs/reports/evidence/dma-s1c-20261018/after/search \
MYFUZZ_DMA_SEARCH_SECONDS=120 \
MYFUZZ_DMA_SEARCH_SEED=5a17c0de0badf00d0e0d010203040506 \
PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
  tests/integration/test_dma_uart_rx_search_real.py
```

两条命令都在 `flock -w 14400 .superpowers/heavy-worker.lock` 下执行；内部
`ResourceBudget` 不被外层 `timeout` 替代。

### 5.2 before 基线（只读 S1a/S1b 保存数据）

`docs/reports/evidence/dma-continuous-s1-20261018/continuous/{positive,fresh}.json.gz`
（HEAD `7e08913`，连续门 1 passed / 173.26s）：

| 项 | positive | fresh |
| --- | --- | --- |
| plan commands | 4,774 | 4,774 |
| `local_ticks` | 1314 / 1394 / **4790** | 相同 |
| UART `local_tick_sample`（pre/post） | 9,580 / 9,580 | 相同 |
| UART `local_tick_sample`（phase=post，即 UART ticks） | 4,790 | 4,790 |
| `uart_tick_observation` | 4,790 | 4,790 |
| 逐例 commands | 1188 / 1190 / 1190 / 1190 | 相同 |
| 逐例 UART ticks | 1199 / 1197 / 1197 / 1197 | 相同 |

搜索 before：`docs/reports/evidence/dma-continuous-s1-20261018/search/stats.json`
（guided，1 passed / 237.00s）：`case_count=8`、`executed_cases=8`、
`effective_search_seconds=52.23`、`search_wall_seconds=72.35`、`completed_chains=8`、
`distinct_effective_specs=7`、`feedback_influenced=true`、`search_status=ok`。

### 5.3 审计口径与对 5× 判据的诚实结论（重要）

- 从保存 bundle 直接数：`local_tick_sample` 中 `component='uart'` 且
  `phase='post'` 的事件数（= UART ticks，每 tick 一个 post 样本，另有一个 pre 样本）、
  `uart_tick_observation` 条数、`plan.commands` 条数、逐例
  `ticks_after.uart - ticks_before.uart`。
- 设计 §2.9 的 5× 目标（“UART ticks/例从 ~1,198 降到 ~20–50”）只在同时引入
  “有界多 tick harness 命令、把 320-tick 波形/545-tick 空闲边距压成 1 条命令”时
  成立；该改动**被 §2.9 明确排除在 S1c 之外**（会改 artifact/build 身份，必须
  单独增量重跑逐 bit 证明）。
- 只抽稀 ISR 轮询阶段时：每例 still 需要真实波形阶段约 861 个 UART tick
  （545 tick 起始空闲边距 + 320 tick 8N1 帧）+ 少量真实寄存器访问 tick。轮询阶段
  空转约 324 tick/例；删除后总 UART ticks/例预计约 1,197 → ~870（≈1.4×），
  commands/例基本不变（每轮询回合仍是一条 advance 命令，且下一回合服务可能让 CPU
  多停 1 个 tick）。
- 因此**不能把 5× 当作可通过的门**：若实测 <5×，本报告将明确写“未达吞吐门”，
  并指出需要后续 harness 多 tick 命令增量；不虚报、不用其它计数（如只算轮询阶段
  空转）替代总 UART ticks。
- 逐例证据/IRQ/tick 关联的“不变”指**因果结构不变**（`_case_evidence` 全部 join、
  IRQ bound source tick、event 顺序、fresh 前缀 replay 逐字段相等），不是 UART tick
  的数值与 S1a 相同——抽稀本来就会改变 UART tick 数量。CPU/DMA 的 tick/命令数可能
  因 UART MMIO 延后一回合而出现 +1/例 级别的合法变化，将在 §5.4 逐项列出。

### 5.4 真实门结果

pending（第二提交追加原始日志、bundle、逐字段 before/after 对比与审计 JSON）。

## 6. 明确未做 / 限制

1. **未达（或未证）5×**：S1c 只抽稀轮询空转；真实波形 tick 必须保留。5× 需要被
   §2.9 排除在 S1c 之外的多 tick harness 命令增量。
2. 未改 `fifo_origin`（仍 `unknown`）、`proof_grade`、contracts/RTL、S1b 搜索判据。
3. 未做 S2–S4：描述符、三方向、多字、非法/error ISR、认证、统一 typed normalizer/
   前缀 replay 均未做，P8 仍不通过。
4. schedule 只对 `_ContinuousRxBoot.run_case` 的 ISR/轮询阶段生效；boot 与波形阶段
   行为不变。
5. 未 `git add` 其它代理的改动/证据；只提交本增量的源码、测试、报告、证据。

## 7. 复现命令

见 §4（纯软件）、§5.1（真实门）。离线审计：

```sh
PYTHONPATH=src python3 docs/reports/evidence/dma-s1c-20261018/audit_s1c_throughput.py \
  docs/reports/evidence/dma-s1c-20261018 before-after.json
```
