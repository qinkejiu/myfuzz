# SoC Wire Oracle, Multi-Source Latch, and Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the three approved evidence gates: independent SPI wire checking, real multi-source latch fault injection, and controlled component-versus-connection attribution.

**Architecture:** Extend the existing profile runtime with bounded, role-derived SPI wire observations; evaluate them in a pure Python oracle using observed CPU writes and peer raw events. Reuse the real Ibex interrupt harness for mutated-top latch tests. Build a separate confirmed-defect gate above the existing boundary candidate classifier, requiring differential and isolation evidence.

**Tech Stack:** Python 3 `unittest`, generated SystemVerilog testbench, Verilator real runs, existing `EvidencePackage` and `soc_peer_oracle.v1`.

**执行记录（2026-09-21）：** 已实现 Task 1–5 的首期验收子集并更新 Task 6 文档：SPI 单字四线判据、edge+level 多源 latch 缺失及 source-ID 置换/屏蔽负例、已知 SPI RTL 注入与隔离归因。源 ID 置换揭示 `all_sources_closed` 只是完成次数汇总；独立结构审计可拒绝错接，确认门槛现要求审计通过且顶层哈希相符。纯测试 121 项通过，最新真实联合回归 11 项通过，既有证据/结构/boot 定向回归 111 项通过（7 项按环境跳过）。未执行官方 RFuzz 变异器搜索、UART/GPIO 线级行为、其他 trigger 的完整多源注入；这些仍以剩余任务清单为准。由于共享工作树含大量非本轮未提交内容，本轮没有按下方模板提交代码，避免把用户的其他改动一并纳入提交。

## Global Constraints

- Use only the approved design in [`../specs/2026-09-21-soc-wire-latch-attribution-design.md`](../specs/2026-09-21-soc-wire-latch-attribution-design.md); do not claim official RFuzz execution.
- Never derive a SPI expectation from peer or component counters. Missing, truncated or ambiguous wire evidence is not a pass.
- A mutated generated top is a composition fault; an injected peripheral RTL fault is a component fault only after independent criterion, legal input, replay and isolation/differential proof.
- Preserve the dirty shared worktree and all unrelated user changes. Stage only task-owned files for commits.

---

### Task 1: Role-Derived SPI Wire Capture

**Files:** Modify `src/myfuzz/composition/soc_runtime.py`; test `tests/composition/test_soc_peer_wire_capture.py`.

**Interfaces:** `RuntimeBuild.peer_wires: tuple[dict[str, object], ...]`; `RunResult.peer_wire_trace: tuple[dict[str, object], ...]`. Records use `instance_id`, `cycle`, `sck`, `cs`, `mosi`, `miso`; metadata contains the plan's `role→dut.<instance>__<component_port>` mapping and trace cap/truncation.

- [ ] Write a generation test composing the existing Ibex+novaspi+GPIO fixture. Assert all four SPI roles map to actual peer bindings, not to guessed component port names. Assert a plan without attached SPI peer emits no SPI wire monitor.
- [ ] Run `PYTHONPATH=src:. python3 -m unittest -q tests.composition.test_soc_peer_wire_capture`; expect failure because `peer_wires` and monitor records are absent.
- [ ] Implement `_spi_wire_records(plan)` from `peer.bindings`, persist it in the runtime build manifest, emit bounded change records in the generated testbench after signals settle, parse them into `RunResult.peer_wire_trace`, and include cap/truncation status. Required record shape:

```python
{"instance_id": "spi0", "cycle": 2081, "sck": 0, "cs": 0,
 "mosi": 1, "miso": 0}
```

- [ ] Re-run the generation test and the existing `tests.integration.test_soc_peer_oracle` and `tests.integration.test_soc_boundary_replay`; expect pass. Commit only the capture code and test.

### Task 2: Independent SPI Protocol Oracle and Replay

**Files:** Modify `src/myfuzz/composition/soc_peer_oracle.py`, `src/myfuzz/composition/soc_runtime.py`, `src/myfuzz/composition/soc_failure_evidence.py`; test `tests/integration/test_soc_spi_wire_oracle.py` and `tests/composition/test_soc_peer_interrupt_plan.py`.

**Interfaces:** `spi_wire_expectation(trace, *, bits, cpol, cpha, cs_active_low, mosi_words, miso_words) -> dict`; `RunResult.responses` gains captured `wdata`/`be` for accepted CPU writes without changing existing fields. Oracle check ID `spi-transfer-wire`; wire trace and verdict are replay-compared.

- [ ] Write pure Python tests for CPOL/CPHA modes, 8-bit MSB-first transfer, MOSI bit flip, deselected clock, incomplete frame, absent bus write, X/Z or truncated trace. A legal full trace passes; each malformed/unsupported record is `mismatch` or `not_assessed`, never `pass`.
- [ ] Run `PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_spi_wire_oracle`; expect failure before the oracle exists.
- [ ] Implement a pure edge/state decoder; obtain MOSI expectation from accepted CPU TXDATA write data and an independent frozen register contract, MISO expectation from `spi.arm_byte`. Preserve `not_assessed` when the norm, write, payload or wire trace is unavailable. Capture write data/byte enables in the response trace, hash the new evidence, and compare it in `replay_package`.
- [ ] Add `MYFUZZ_SOC_REAL=1` SPI+GPIO positive and one deliberately corrupted trace negative; assert `spi-transfer-wire` pass/mismatch and evidence replay agreement. Run both pure and real tests, then commit task-owned files.

### Task 3: Multi-Source Latch Fault Injection

**Files:** Modify `tests/integration/test_soc_interrupt_lifecycle.py` or create `tests/integration/test_soc_multi_latch_fault.py`; optionally modify `src/myfuzz/composition/soc_failure_evidence.py` only for missing evidence fields.

**Interfaces:** Test-local `mutate_latch_mask(top_text: str, source_id: int) -> str` rewrites exactly one controller bit after matching the generated literal. Evidence records original/mutated top hashes and source ID.

- [ ] Write real tests with two sources: baseline simultaneous/staggered run closes both; source-specific latch mutation makes that source unclaimable while the other closes; mask/source-ID mutation is classified as `composition_defect`.
- [ ] Run `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_multi_latch_fault`; expect failure before the test-local mutation/evidence path is implemented.
- [ ] Add only test-local mutation and the minimum evidence plumbing needed to preserve pending/claim/complete and top hashes. Do not modify the production controller semantics. Re-run the test and existing `test_soc_irq_edge_lifecycle`, then commit task-owned files.

### Task 4: Confirmed Component Defect Gate

**Files:** Create `src/myfuzz/composition/soc_defect_confirmation.py`; test `tests/integration/test_soc_defect_confirmation.py`.

**Interfaces:** `confirm_component_defect(package: EvidencePackage, *, isolation: Mapping[str, object], criterion: Mapping[str, object]) -> tuple[str, str]` returns `component_confirmed`, existing boundary class, or `undiagnosed`, with an explicit reason. It never changes `classify_boundary`'s conservative candidate semantics.

- [ ] Write table tests showing that missing source identity, independent norm, legal input, matching replay, isolation/differential evidence, or a positive composition/profile/software finding prevents confirmation. Confirmed status requires every field.
- [ ] Run `PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_defect_confirmation`; expect import failure.
- [ ] Implement the small gate on top of `classify_boundary`, checking criterion source hash, original/mutant source hashes, boundary legality, replay status and isolation counterfactual. Preserve the exact failed gate in the reason. Re-run unit tests and commit.

### Task 5: Real Defect-versus-Connection Experiment

**Files:** Create `tests/integration/test_soc_defect_injection_real.py`; use temporary copies of existing fixture peripheral RTL and rendered top, never modify tracked source in place.

**Interfaces:** Two experiments use the same saved legal sample and isolated peripheral fixture: one mutates a component-owned observable behavior; the other mutates one generated connection/profile fact. Both produce EvidencePackage/replay and call `confirm_component_defect`.

- [ ] Write assertions for both known-fault controls: the component mutation is confirmed only after isolated reproduction and clean baseline, while the connection/profile mutation is never confirmed as component-internal. Add identity-mismatch and replay-divergence negatives.
- [ ] Run real-mode test to see the missing experiment, then implement test-local source copying/mutation, builds, replay and independent oracle criterion. Re-run targeted tests and commit.

### Task 6: Regression and Documentation

**Files:** Modify `docs/reports/soc-remaining-implementation-20260921.md`, `docs/reports/soc-capability-matrix-20260921.md`, `docs/reports/soc-design-acceptance-20260921.md`, `docs/reports/soc-research-scope-20260921.md`.

- [ ] Run all new pure tests, prior peer/boundary tests, and `MYFUZZ_SOC_REAL=1` SPI, multi-source and injection suites. Record exact commands, exit codes, skips and dependency gaps.
- [ ] Update the four reports to distinguish verified SPI wire subset, verified injected-component attribution, unassessed UART/GPIO line behavior and absence of official RFuzz campaign. Do not mark the whole SoC complete.
- [ ] Run `git diff --check` and re-run the tests affected by final edits. Commit only the four report files if they are tracked; otherwise report their untracked state without sweeping in unrelated files.
