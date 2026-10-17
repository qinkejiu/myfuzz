# P8 S1a + S1b 实现报告：连续 RX boot 对象与单 boot 搜索骨架

> 范围：只做设计 `.superpowers/sdd/p8-dma-continuous-design.md` 的 **S1a**（连续 runtime 抽成 boot 对象，行为不变）与 **S1b**（单 boot、串行字节、反馈/语料/失败/拒绝的搜索骨架）。
> 不做：S1c（调度抽稀/吞吐门）、S2（描述符固件/三方向/多字 FIFO）、S3（非法描述符/CPU error ISR）、S4（来源认证/统一 normalizer/前缀 replay）、S5（CPU 程序变异）。不改 `fifo_origin`、`contracts.py` 身份期望、DMA/UART RTL、`third_party/`。
> 本文件不宣称 P8 通过，也不宣称任何来源权威：`fifo_origin` 仍为 `unknown`，`_case_evidence` 仍是唯一完成链证书。

## 0. 交付摘要

| 项 | 状态 |
| --- | --- |
| S1a 源码（`_ContinuousRxBoot` + 每例前缀边界字段 + 薄封装 + replay 重建边界） | 已实现，纯软件全绿 |
| S1b 源码（`dma_chain_feedback` + `dma_uart_rx_search`：spec/feedback/corpus/mutator/decision/guided+uniform/§2.8 判据） | 已实现，纯软件全绿 |
| 纯软件门 | **66 passed, 3 skipped**（原 9 文件基线 20 passed/3 skipped；新增 4 个测试文件） |
| S1a 真实连续门 | 见 §3（状态与结果） |
| S1b 真实搜索门 | 见 §4（状态与结果） |
| 证据审计脚本（离线、只读保存数据） | `docs/reports/evidence/dma-continuous-s1-20261018/audit_attempt6_comparison.py`、`audit_search_bundle.py` |

## 1. 变更文件

源码：
- `src/myfuzz/integration/dma_uart_rx_runtime.py`（S1a 重构）
- `src/myfuzz/scenario/dma_chain_feedback.py`（新，纯软件事件级反馈）
- `src/myfuzz/integration/dma_uart_rx_search.py`（新，搜索骨架）

测试：
- `tests/integration/test_dma_uart_rx_boot_object.py`（新，S1a RED/GREEN）
- `tests/scenario/test_dma_chain_feedback.py`（新，反馈）
- `tests/integration/test_dma_uart_rx_search.py`（新，搜索纯软件）
- `tests/integration/test_dma_uart_rx_search_real.py`（新，搜索真实门，opt-in）
- `tests/integration/test_dma_uart_rx_cursor.py`（既有测试的 fake runner 补齐真实 runner 的执行身份/`local_ticks`/`commands` 表面；断言不变）

审计脚本：`docs/reports/evidence/dma-continuous-s1-20261018/audit_attempt6_comparison.py`、`audit_search_bundle.py`。

## 2. S1a：`_ContinuousRxBoot`（行为不变）

### 2.1 实现

- 新增私有 `_ContinuousRxBoot(runner, *, budget, template, source_pins)`：
  - `boot()`：原 512 轮 `advance(('dma','cpu'))` 等待真实 UART CTRL 请求排队；
  - `run_case(source_bytes, *, case_index, action_prefix='continuous-rx', max_source_ticks=2048, max_rounds_per_case=4096, expected=None)`：只接受**一个** 8-bit 串行字节；波形阶段只推进 UART；之后 `advance(('dma','cpu','uart'))` 直到出现真实 CPU `COMPLETED` store；返回 `_case_evidence` + 前缀边界；
  - `finish(*, phase, case_index, error)`：原 `_capture`；`close()`：原 `_close`。
- `run_continuous_uart_rx` 改为薄封装：校验/基因组模板/预算与原来完全一致，逐例 `boot.run_case`，失败诊断字段（`type/message/command_count/case_start/max_rounds_per_case/max_source_ticks/requested_source_bytes`）保持不变。
- `replay_continuous_uart_rx` 拆成 `@host_source_discovery_scope()` 薄封装 + 未装饰核心 `_replay_continuous_uart_rx`（搜索入口整场只 discovery 一次）。replay 在**重放命令时**记录每个 source 命令的 `(command_index, event_index, local_ticks)` 起点，用它与下一个 source 起点重建每例 `command_end/event_end/ticks_after`，因此逐例边界也进入 fresh 比较。

### 2.2 每例 evidence 新增字段（唯一的行为增量，其余语义不变）

`command_start, command_end, event_start, event_end, ticks_before, ticks_after, prefix_sha256, fifo_depth_after`

- `event_start/event_end`：0 基 journal 索引（与 `ScenarioRunner.events_since` 同单位）；`command_start/command_end`：`ScenarioBatchPlan.commands` 索引。
- `prefix_sha256 = sha256(canonical({schema_version, commands[start:end] 的 codec 同字段文档, _normalize(events[start:end], execution_ids), ticks_before, ticks_after}))`（设计 §3.5）。**不含 genome 模板**，因此同一案例在不同 max_steps 模板下仍可比较；执行 UUID 经既有 typed `_normalize` 归一，随前缀（命令/事件/tick）变化。
- 失败用例：`boot.case_failure` 保留尝试边界（`complete=False`，含 `phase/command_*/event_*/ticks_*`、`prefix_sha256` 尽力计算、`fifo_depth_after`），不进入 `ContinuousRxResult.cases`（保持原语义）。

### 2.3 RED（先失败）

1. `tests/integration/test_dma_uart_rx_boot_object.py` 全部因 `ImportError: cannot import name '_ContinuousRxBoot'` 在收集期失败。
2. 旧实现与 attempt6 保存案例都**没有**新字段：

```
baseline case keys: [... 'action_id','bound_source_event_id',... 'source_byte', ...]
missing new fields: ['command_end','command_start','event_end','event_start','fifo_depth_after','prefix_sha256','ticks_after','ticks_before']
has _ContinuousRxBoot: False
```

### 2.4 GREEN（纯软件）

- 新增 `test_dma_uart_rx_boot_object.py`（16 项）：薄封装与直接 `boot.run_case` 命令序列逐条相等；新字段存在且边界链一致（`case[i+1].command_start == case[i].command_end` 等）；`prefix_sha256` 与执行身份无关、随前缀（字节）变化；多字节/越界/布尔/非 int 字节在消费 RTL 前被拒；非 `complete` 期望被拒；失败保留尝试边界；wrapper 失败诊断的 `case_start/command_count` 与尝试边界一致；已封存 boot 拒绝继续。
- 既有 `tests/integration/test_dma_uart_rx_*` 全部保持通过（`test_dma_uart_rx_cursor.py` 的 fake runner 只补齐真实 runner 的执行身份/`local_ticks`/`commands` 表面）。

## 3. S1a 真实连续门

命令（与设计 §6.3 相同）：

```sh
MYFUZZ_DMA_CONTINUOUS_REAL=1 \
MYFUZZ_DMA_CONTINUOUS_CACHE=<cache> \
MYFUZZ_DMA_CONTINUOUS_EVIDENCE=<evidence> \
PYTHONPATH=src timeout 900 python3 -m pytest -xq \
  tests/integration/test_dma_uart_rx_runtime.py::test_continuous_native_uart_dma_prefix_and_failure
```

结果：**待源码冻结后由 root 排队执行**（本代理已排队但被并发源码变更与快照完整性阻塞，见下）。

已完成的真实观察（不是门禁通过）：
- 重构**前**在 live tree 跑同一命令（attempt A），4 例全部完成：`commands=4774`、`events=34794`、`ticks={cpu:1314,dma:1394,uart:4790}`，与 attempt6 逐字段相等；失败原因只是 `SourceDrift`（并发代理在运行中新增/修改了 `src/myfuzz/integration/picorv32_wb_scenario_campaign.py`、`src/myfuzz/scenario/picorv32_wb_two_gpio_example.py`，与本增量无关）。
- attempt A 与 attempt6 的归一事件逐事件比较：**34794 条中只有 1 条不同**，差异路径只有 `artifact_digest` / `reset_outcome/artifact_digest`（CPU harness 构建输入自 attempt6 后被其它增量改动，属构建身份，不是 tick/data/IRQ/事务差异）；`plan.commands`、`local_ticks`、逐例 case（baseline 18 字段）全部相等。
- 重构**后**尝试在 frozen snapshot（`src/configs/tests/third_party/scripts/schemas` 字节复制）中跑同一门：在 1.31s 内失败于 `scripts/verify_soc_sources.py` 的 source closure（`git cat-file` 在 `.git` 元数据不完整的子模块副本上失败），**不是** S1a 逻辑失败；日志保留在 `.superpowers/p8-s1-20261018/after-native.log`，该快照已废弃、不再重试。

结论：S1a 的真实门**尚未**在本增量上取得 1 passed；在冻结树上重跑前，本报告不宣称 S1a 真实回归通过。

## 4. S1b：搜索骨架

### 4.1 `myfuzz.scenario.dma_chain_feedback`（纯软件）

- `DMA_FEATURES` 为设计 §2.6 的 18 个结构特征；额外声明**有界桶**：`fifo_push_depth_0..4`、`dma_target_{uart_rdata,uart_window,ram,other}`、`payload_*`（见下）与诊断桶 `fifo_pop_unattributed`。`is_declared_feature()` 冻结词表，外来键无法混入。
- `dma_chain_features(events, *, start, end, destination, uart_base)`：只读 `[start,end)` 事件切片；`start/end` 越界/负值/逆序直接 `ValueError`。
  - 结构证据：`uart_frame_validation.waveform_matched`、`uart_tick_observation.post.probe_uart_fifo_wvalid&wready`、`mmio_delivery` UART STATUS `0x14` 非空、`dma_edge.accepted` 的 `dma-memory` 读/写与地址桶、DMA master UART RDATA 读 + `read_capture.pre.probe_uart_fifo_rdata_re` 的 `fifo_dma_pop`、CPU `channel_id='data'` 的 `fifo_cpu_pop`、原生 IRQ 物理脉冲、`source_start`↔`cpu_irq_taken` 的 `source_event_id` join、ISR 四连 store（`mcause/status/payload/counter`）、`memory_write` 的 `ram_commit_cpu/dma`、`env_error`/`no_target_effect`、`tx_capture`。
  - **无 routed 事务身份的 RDATA 读**（当前 DMA master 直通路径，设计 §1.4/§3.3(c)）计为 `fifo_pop_unattributed`，不冒充 CPU/DMA pop、不冒充认证。
  - `payloads` 记录观测到的数据值（帧字节、DMA master 读值、DMA 目的写值、TX 捕获），并派生**值覆盖桶**：`payload_<hex>`、`payload_hi_nibble_*`、`payload_lo_nibble_*`、`payload_popcount_*`、`payload_zero/all_ones/high_bit/ascii`。这是 S1 单字节搜索唯一可用的真实新颖性信号（**明确声明为值覆盖，不是因果证明**）。
  - `completed_chain`：恰 1 帧 + 1 DMA pop + 1 目的 RAM 写（值相等）+ 1 原生脉冲 + 1 CPU take（join 到 `source_start`）+ mcause store + payload store，且事件顺序严格递增。它只是链级 witness；`_case_evidence` 仍是证书（还要求 DMA status MMIO→data_response→RVFI load/store、版本一致）。
- `new_features(seen, current)`：相对本 run 已见集合的排序增量。

### 4.2 `myfuzz.integration.dma_uart_rx_search`

- `DmaCaseSpec(direction='RX_TO_RAM', source_bytes=(byte,), descriptor={'byte':v}, expect='complete')`：构造期拒绝多字节/非 int/描述符不一致；`validate(windows)` 纯 pre-RTL 窗口校验（`uart_rx_byte` 0..255、描述符=实字节、`expect` 只允许 `complete`）；`identity(firmware_sha256)` 绑定固件镜像摘要。
- `DmaCaseFeedback`：`case_index/spec_id/status/features/new_features/completed_chain/target_error/ticks_before/ticks_after/command_start/command_end/event_start/event_end/prefix_sha256/evidence/error/spec`（`spec` 字段为审计复算所需，属对设计建议类型的补充）。
- `DmaCorpus`：`energy = 1 + len(new_features) + (2 if completed_chain)`；`select(rng)` 用**一次** `rng.random()` 做能量加权；`max_entries/max_bytes` FIFO 淘汰并记录 `evictions`；仅接受 `status='complete'`。
- `DmaMutator`：`OPERATORS` 8 个（设计原样），S1 只实现串行字节算子 `byte_bitflip/byte_interesting/byte_addsub/byte_splice/descriptor_field`；`length/direction/payload` 显式拒绝（`requires the S2 descriptor firmware`）。所有算子先做窗口检查，越界立刻 `ValueError`，绝不发出 >8-bit 值。
- `_DecisionPlanner`（guided/uniform 共用，搜索与离线复算共用同一代码）：
  - seed 固定为 `seed[0]`（记录 `seed_hex`/`seed_byte`）；
  - guided：`parent = corpus.select(rng)`（能量加权），operator 按 corpus 的累计 yield 加权；uniform：父代从**已执行** spec 中均匀抽取、operator 均匀，忽略反馈；
  - 每个 decision 记录 `parent_id/parent_kind/energy/operator/draws/draw_offset/duplicate_attempts/spec/spec_id` 并在记录反馈后合并 `status/observed_features/new_features/completed_chain/target_error`（拒绝类另记 `rejected` 原因）；
  - 已尝试 spec 去重（同一 boot 内不再重复消费 RTL），重试次数记入 `duplicate_attempts`，无法脱出时 `DmaSearchRejected('mutation_cannot_escape_executed_specs')`。
- 搜索循环：`boot.boot()` → 逐例 `next_case` → pre-RTL `validate`（不满足即 `rejected_prertl`，**不消费 RTL**）→ `boot.run_case` → `dma_chain_features(runner.events, event_start, event_end, ...)` → `new_features` → 入语料/记录 decision。`seconds` 只约束例循环（`effective_search_seconds`），`min_cases` 保证能诚实评估结构判据；`case_limit` 由 `budget.max_scheduler_steps` 推出。
- 失败：post-RTL 失败立即 `boot.finish(phase=..., case_index=..., error=...)` 保存原始前缀，并调用未装饰的 `_replay_continuous_uart_rx` 做一次 fresh 失败重放；重放不一致 → `DmaSearchRejected('failure_replay_mismatch')`；一致 → `stats['failure_replay']='reproduced'`、`DmaSearchFailed`。S1b 的 boot 一旦 capture 即封存，因此**没有可继续的 case 级失败隔离**（设计 §2.2 第 4 点留给 S2）。
- `_assert_real_search(result)` / `_evaluate_search(result)`（判据全部由保存数据复算）：
  - 硬拒绝（直接 raise）：`plan_decision_mismatch`（plan 的 source 值/action_id 序列 == 已消费 spec 序列）、`host_wrote_data`（非 cpu/dma 的 `memory_write` 落到被测地址）、`expected_from_host`（每例 evidence `source_byte`/`action_id` 必须来自 spec，且 runner 由 factory 在 spec 之前构造）；
  - 结构判据（不满足 → `DmaSearchNotARealSearch`，`stats['search_status']='not_a_search'`）：`post_seed_cases>=2` 且每例 `ticks_after != ticks_before`、`distinct_effective_specs>=2`（已执行且字节 ≠ seed）、`feedback_influenced`（guided：语料父代 + energy>1 + 该例有 new_features）、`no_post_seed_completed_chain`、`corpus_not_replayable`（每个语料项都有 `prefix_sha256`）、`search_time_unsubstantiated`（`effective_search_seconds <= search_wall_seconds`）；
  - 有保存失败 → `search_status='failed'` + `DmaSearchFailed`。
- `recompute_decisions(seed, strategy, cases)`：**完全离线**用同一 `_DecisionPlanner` 从保存的逐例反馈重放决策流（重放校验每例 spec 与顺序），供门禁与独立审计复算。
- 入口 `search_continuous_dma` 带 `@host_source_discovery_scope()`，整场只 discovery 一次（失败重放使用未装饰核心）。

### 4.3 纯软件测试覆盖（`tests/scenario/test_dma_chain_feedback.py` 11 项、`tests/integration/test_dma_uart_rx_search.py` 17 项）

反馈：完整链 18 特征/目标词表；`tx_capture` 仅在观测时存在；unmatched/write 值/顺序/missing mcause 四类不完整链都不是 `completed_chain`；`env_error`/`no_target_effect`；切片边界与隔离；`new_features` 相对已见集合；CPU pop 需要 `channel_id='data'`；冻结词表。

搜索：guided 满足全部结构判据且 seed/决策/语料形状正确；uniform 对照 `feedback_influenced=False` 且决策序列不同；固定 rng 两次运行决策完全相同且 `recompute_decisions` 复算相等（guided/uniform 各自）；`not_a_search`（min_cases=2 与篡改 new_features 两种）；`plan_decision_mismatch`；`host_wrote_data`；`expected_from_host`；mutator 8-bit 窗口 + 越界拒绝 + S2 算子拒绝；spec pre-RTL 校验/固件绑定/身份；语料能量加权选择（Stub rng 固定 draw 0.05/0.5/0.95）与 FIFO 淘汰；`rejected_prertl` 不消费 RTL；session 失败保存 + fresh 失败重放；bundle JSON 往返 + 重载后复算判据。

### 4.4 真实搜索门

命令（设计 §6.4）：

```sh
MYFUZZ_DMA_SEARCH_REAL=1 \
MYFUZZ_DMA_SEARCH_CACHE=<cache> \
MYFUZZ_DMA_SEARCH_EVIDENCE=<evidence> \
MYFUZZ_DMA_SEARCH_SECONDS=120 \
MYFUZZ_DMA_SEARCH_SEED=<32 hex> \
PYTHONPATH=src timeout 1800 python3 -m pytest -xq \
  tests/integration/test_dma_uart_rx_search_real.py
```

结果：**待源码冻结后由 root 排队执行**（同一并发源码变更/快照完整性问题阻塞，同 §3）。

门禁测试本身要求（`test_dma_uart_rx_search_real.py`）：`search_status='ok'`、`post_seed_cases>=2`、`distinct_effective_specs>=2`、`post_seed_completed_chains>=1`、`feedback_influenced=True`、`effective_search_seconds<=search_wall_seconds`、全部 case `completed_chain` 且有 `prefix_sha256`、plan 与逐例 spec 一致、`recompute_decisions` 与保存决策相等、重载 bundle 后 `_assert_real_search` 通过、完整 fresh 前缀 replay（`fresh.cases == positive.cases`、ticks/plan 相等）、真实受控失败保存 + fresh 失败重放（`error/budget` 相等）。uniform 对照臂在 `MYFUZZ_DMA_SEARCH_UNIFORM=1` 时保存到 `.../uniform/`。

## 5. 明确未做 / 限制

1. **未做 S1c**：轮询 schedule 未抽稀，约 1.2k commands/例、~1.2k UART ticks/例的吞吐未改善；`seconds` 预算内的真实用例数仍受此限制。
2. **未做 S2/S3/S4**：没有外部串行描述符固件、没有多字/多 beat、没有 RAM→RAM/RAM→TX 统一 boot、没有非法描述符与真实 CPU error ISR、没有 `configure_provenance`/admission/`UartConsumptionTracker` accepted、没有统一 typed normalizer/统一前缀 replay、TX 捕获未进 journal。
3. **不改 `fifo_origin`**：case evidence 仍输出 `fifo_origin='unknown'`、`proof_grade='bounded_historical_chain'`；本文任何"特征/语料/决策"都不是来源权威。
4. **只变异串行 8-bit 字节**：不读固件期望值，不改 DMA 配置/程序；host 不写数据（硬判据 `host_wrote_data`）。
5. **单 boot 内的失败隔离有限**：post-RTL 失败即封存并 fresh 重放，不能在同一 boot 继续下一例。
6. **值覆盖桶**（`payload_*`）是 S1b 唯一的新颖性来源之一，报告与代码都声明它是值覆盖，不是因果/覆盖证明；`feedback_influenced` 因此可复算但不等于"搜索有效"。
7. **真实门未通过**（§3/§4）：在冻结树上重跑前，S1a/S1b 只能声明"纯软件通过、真实门待跑"。
8. 未改 `third_party/`、`agent.md`、未跟踪 DMA 证据、`contracts.py`、DMA/UART RTL。

## 6. 复现命令

```sh
# 纯软件门（本报告 §2.4/§4.3；66 passed, 3 skipped）
PYTHONPATH=src python3 -m pytest -q \
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
  tests/integration/test_dma_uart_rx_search.py

# 离线审计（只读保存数据）
PYTHONPATH=src python3 docs/reports/evidence/dma-continuous-s1-20261018/audit_attempt6_comparison.py <evidence> <out.json>
PYTHONPATH=src python3 docs/reports/evidence/dma-continuous-s1-20261018/audit_search_bundle.py <search-evidence> <out.json>
```

所有长 RTL 运行必须 `flock -w 3600 /home/qinkejiu/myfuzz/.superpowers/heavy-worker.lock <command>`，且不许把外层 `timeout` 当内部 `ResourceBudget`。
