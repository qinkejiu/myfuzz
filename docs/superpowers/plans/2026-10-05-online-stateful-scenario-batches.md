# Online Stateful Scenario Batches Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow a running multi-component testcase to accept sequential Fuzzable Source events, preserve CPU/IP/RAM state between them, and replay the complete event-and-step history from a fresh runtime.

**Architecture:** Add an immutable batch plan containing a reset-free template Genome and an ordered stream of source-injection and local-step commands. A live batch recorder applies each command to one `ScenarioRunner`; the saved plan reproduces the same command boundaries in fresh replay. Existing one-Genome `DependencyScheduler`, `record_scenario`, and `replay_scenario` behavior stays intact.

**Tech Stack:** Python dataclasses and strict JSON codec; existing `ScenarioRunner`, `ScenarioTrace`, `ReplayComparison`, `PersistentMemory`, generated local harnesses, and `unittest`.

## Global Constraints

- “同一 testcase 内，CPU/IP RTL 不重复 reset；Memory、事务状态、Pending Event、场景状态持续保存。”
- “已由真实 RTL 或持久状态决定的输入，后续不能重新被 Fuzzer 随机覆盖。”
- “Dependency 不仅包含数据依赖、事件依赖，还要加入 persistent state dependency。”
- “保留各 DUT 自身局部时序，但不要引入全局 cycle-accurate SoC 时序。”
- “testcase 结束或显式 reset 时才按 policy 清理状态。”
- “局部 RTL 执行真实，跨组件数据流抽象，testcase 内状态持续，真实结果不能被随机覆盖。”

---

### Task 1: Stateful online batch recording and replay

**Files:**
- Create: `src/myfuzz/scenario/batch.py`
- Modify: `src/myfuzz/scenario/__init__.py`
- Modify: `src/myfuzz/scenario/replay.py`
- Test: `tests/scenario/test_stateful_batch.py`
- Test: `tests/integration/test_scenario_ibex_pulp_gpio_online_batch_real.py`
- Modify: `docs/LOCAL_HARNESS_RUNTIME.md`
- Create: `docs/reports/generated-ibex-pulp-gpio-online-batch-20261005.md`

**Interfaces:**
- `BatchSourceEvent(action_id, component, port, value, bit_offset=0, width=None)` describes one direct Fuzzable Source admission. Its direction is the template Genome direction.
- `BatchAdvance(schedule)` describes an ordered tuple of local harness steps. Each tuple entry advances that named local harness once.
- `ScenarioBatchPlan(template, commands)` contains a `ScenarioGenome` with `actions == ()`, `reset_actions == ()`, and `quiesce_steps == 0`; commands are an immutable tuple of unique source events and advances. Their order is execution order.
- `ScenarioBatchCodec.encode(plan) -> bytes` and `ScenarioBatchCodec.decode(raw) -> ScenarioBatchPlan` use strict versioned JSON and reject unknown/missing fields, duplicate action IDs, invalid widths, or malformed schedules.
- `ScenarioBatchRecorder(template, runner)` owns one supplied fresh runner. `begin()` loads images and starts one testcase; `submit_source_event(event)` validates unbound source ownership then injects; `advance(schedule)` advances exact local steps without reset and respects `template.max_steps`; `finish() -> ScenarioTrace` finalizes once and hashes the complete plan as testcase identity. `recorder.plan` exists only after finish.
- `record_scenario_batch(plan, factory) -> ScenarioTrace` executes a script in one fresh runtime.
- `replay_scenario_batch(plan, factory, reference) -> ReplayComparison` replays every admission and local-step boundary in a fresh runtime and compares the full event trace.

- [ ] **Step 1: Write failing tests**

Test codec equality/strict rejection, one begin and one finish, source injection after a prior advance, unique event identity, bound-input rejection, max-step enforcement, and full fresh replay. Add a real generated Ibex plus dual PULP GPIO test: inject `0x49`, `0x81`, and `0xff` after real output boundaries in one running testcase, then require three real IRQ deliveries, PADIN responses, GPIO A writes, RAM write history, unchanged memory generation, and fresh replay.

- [ ] **Step 2: Run focused tests and confirm they fail for absent batch interfaces**

Run: `PYTHONPATH=src:. python3 -m unittest tests.scenario.test_stateful_batch -v`

Run: `PYTHONPATH=src:. MYFUZZ_SCENARIO_REAL=1 python3 -m unittest tests.integration.test_scenario_ibex_pulp_gpio_online_batch_real -v`

Expected: focused tests fail at imports of the absent batch API before any implementation exists.

- [ ] **Step 3: Implement immutable plan, live recorder, and replay**

Keep ownership validation, router delivery, RAM persistence, IRQ handling, and per-component clocks in existing classes. The batch recorder only admits declared unbound source inputs; it must never set Bound Input fields or predict DUT outputs. Do not add a global cycle model or any automatic reset. Record each call boundary so replay repeats online source admissions at the same local-step offset.

- [ ] **Step 4: Verify unit and generated RTL acceptance**

Run: `PYTHONPATH=src:. python3 -m unittest tests.scenario.test_stateful_batch tests.scenario.test_replay tests.scenario.test_genome_scheduler tests.scenario.test_runner_continuity -v`

Run: `PYTHONPATH=src:. MYFUZZ_SCENARIO_REAL=1 python3 -m unittest tests.integration.test_scenario_ibex_pulp_gpio_online_batch_real -v`

Expected: one real continuous runtime captures three post-start source admissions; a new runtime replays the exact command stream and matches the full trace.

- [ ] **Step 5: Document, check, and commit**

Document the online batch API and distinguish it from pre-encoded multi-Action Genomes. Do not claim RFuzz live FIFO slots use this interface unless `ScenarioRfuzzExecutor` has a concrete tested integration. Run `git diff --check` and commit only the batch module, tests, and their documentation.
