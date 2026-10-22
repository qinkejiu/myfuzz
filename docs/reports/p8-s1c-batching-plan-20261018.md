# P8 S1c UART transport batching implementation plan

> **For agentic workers:** Use subagent-driven-development or executing-plans task by task after design review. This remains a source-only batching design: no batching behavior, test or batching build has been implemented. Task 1's separate scalar measurement script has since run once; see the actual result below.

**Goal:** Reduce pipe command overhead during the isolated UART RX waveform while retaining every actual clock edge and source/IRQ receipt.

**Architecture:** Add a bounded generated UART command that applies an explicitly supplied RX bit vector and invokes the existing `tick()` once per bit. A dedicated Runner path commits every returned edge through the existing source, observation and binding consumers in order. CPU/DMA polling remains interleaved as today. Batch policy and the relation between wire command and logical edge become explicit versioned replay inputs.

**Tech Stack:** Python session/Runner, generated C++, existing line protocol/replay cache, Verilator RTL. I used the writing-plans skill; the requested report location overrides its default plan directory.

## Evidence and limits

Read `agent.md`, `docs/CURRENT_PROGRESS.md`, `docs/reports/p7-p8-real-gates-20261018.md`, saved `docs/reports/evidence/dma-s1c-20261018/audit-throughput.json`, and the sources below. Saved JSON was read as data, without importing project modules.

The audit records four positive cases after S1c:

| Quantity | Before | After |
| --- | ---: | ---: |
| UART ticks | 4790 | 3496 |
| UART waveform-only logical advance commands | 3456 | 3456 |
| ISR poll UART steps | 1294 | 4 |
| Plan commands | 4774 | 4776 |
| Events | 34794 | 29636 |

The audit's **1.3699 ratio is UART ticks per case** (1197.25/874). It is not a measured wall-clock speedup. Saved eight-case search wall time is 72.352168349→58.919375622 seconds (~1.228×); effective search time is 52.233201008→41.105283515 (~1.271×). Neither proves 5×. The prior continuous gate durations 173.26→133.85 seconds also do not imply 1.37× wall speedup.

Current source `_ContinuousRxBoot._execute_case()` calls `recorder.advance(('uart',))` once per waveform tick (861 first case, 865 later). `GeneratedOpenTitanUartSession.step_local()` sends one `STEP_TLUL_UART`; `GeneratedLocalSession._command_impl()` writes, reads, parses and validates a pipe reply. The driver constructs snapshot JSON and hex encodes each reply. These are concrete repeated operations, **not measured attribution**. Per-edge JSON snapshots and Runner/source consumers remain necessary after batching. `observe_local_command_timings()` already exists in `session.py` and can measure aggregate command time with no receipt substitution.

At block32, the 3456 isolated calls could fit in about112 wire requests before mandatory boundary splits. This is an operation-count opportunity, not a speed estimate. Even eliminating all isolated-waveform cost cannot yield 5× unless measured eligible cost exceeds80% of total; batching alone must not be promised to meet5×.

## Global constraints and acceptance invariants

- No extra/skipped RTL ticks, reset, startup write, register access, FIFO pop, injected output or inferred IRQ. Use the existing generated `tick(Model&, samples*)` including its PRE/POST and low/high evaluation order.
- Batch only an already started, admitted UART waveform in the current continuous RX path, with `read_rx_after_source=false`; first startup step and register accesses stay scalar. CPU and DMA do not advance within a block.
- Reject pending routed UART service, active register-access work, bound RX inputs, unresolved input/source decisions, observer callbacks capable of scheduling inter-edge actions, or insufficient capacity/budget **before** transmitting. End a block before the next source/end/conflict decision boundary.
- RX input for every edge is computed from the existing admitted `Uart8N1Peer.drive_rx()` schedule; never derive a source byte from FIFO/readback. Verify returned physical RX PRE/POST against that schedule and actual tick identity.
- Preserve all real per-edge TX, IRQ, FIFO/probe and bus samples. Apply source authority, frame validation, FIFO retention/read consumption, IRQ latch and binding delivery in original order. UART IRQ may change while CPU is stationary: binding state/events still update per edge, with no invented CPU take.
- The current scalar `_step_once()` performs substantial capacity, authority, budget and routing checks. Do not call `session.command()` from `_ContinuousRxBoot` to bypass it. Extract/share the actual post-edge commit path, with a dedicated, closed UART isolation preflight. Do not fake multiple scalar `DriverReceipt`s from one native command.
- Reserve logical steps, event/sample capacity, serialized reply and replay cache bytes for the whole block before execution. Tick budget counts edges; command budget counts real commands separately. If admission fails, nothing executes. If transport/consumer validation fails after effects, poison/abort/reap once; no retry or scalar fallback after sending a command, no ordinary continuation from an uncommitted physical suffix.
- A block is atomic only for transport. Successful evidence retains per-edge raw references and explicit block/edge joins; failures retain the raw complete/partial receipt plus physical tick range and committed semantic prefix. Never label the full block semantically committed on consumer failure.
- Build/driver schema, operation admission, artifact hash, implementation source pins, native evidence and replay policy must change together. Existing binaries and saved scalar runs cannot inherit batching capability.
- `agent.md`: remote work only `/root/fanzehui` via jumpserver. This design does not authorize any remote/native operation; root coordinates the nonblocking heavy-worker lock, frozen independent copy and exact operation.

## Task 1: Bound and measure the scalar baseline

### 2026-10-18 actual scalar attempt 1

The reviewed measurement script was run once on the pinned remote project copy. The remote operation completed with exit 0 for source bytes `[0x5a, 0x00, 0xa5, 0xa5]`. A separate local saved-byte audit exited 0 with status `partial_scope_verified_open_checks_remain`: 29,636 events, four complete cases, 4,776 logical plan commands, 213.607 seconds whole-runtime wall and 2.244 seconds import. The run and evidence boundaries are documented in [the measurement report](p8-s1c-scalar-measurement-attempt1-independent-20261018.md).

This is partial Task 1 evidence only. Timing includes build/startup/finalization; there is no fresh or failure replay, no independent original DUT exit receipt, no wire command/ACK/byte count, and no steady-state-only or native-only CPU measurement. It does not establish transport dominance or justify batching as a 5× optimization. Keep the acceptance checklist below open until its full cost, correctness and fresh-reference items are met.

**Files:** extend `tests/integration/test_dma_prefix_replay_real.py` measurement harness or add `scripts/measure_dma_uart_transport.py`; consume `src/myfuzz/local_harness/session.py:observe_local_command_timings` without changing commands.

- [ ] Add bounded timing aggregation by operation (count/sum/max), wall and effective duration, build/startup excluded and separately reported; do not append timing to semantic events/prefixes.
- [ ] Count actual wire commands/ACKs/bytes and actual sample count separately from `ScenarioBatchPlan.commands`; current4776 is a logical plan count, not an audited total wire count.
- [ ] Freeze scalar source/tool/build inputs, firmware, values, resource budgets, seeds, source schedule and evidence schema. Save a complete scalar descriptor plus full fresh typed prefix and S3 failure replay as the correctness reference.
- [ ] Record Python process CPU and native process CPU time without version/build commands in measurement. If transport is not dominant, stop and report attribution before broader optimization.

**Deliverable:** auditable cost breakdown; no performance gate passes from timers alone.

## Task 2: New bounded UART command and strict receipt parser

**Files:** `src/myfuzz/local_harness/rtl/local_driver_v1.h` parser/CommandSet; `driver_renderer.py:render_local_driver` UART dispatch; `session.py:_OPERATIONS`, `_expected_ready`, `_command_impl`; `wire.py` receipt validation; runtime generation/build manifest identity where the opt-in is declared. Tests: `tests/local_harness/test_driver_protocol.py`, `test_driver_renderer.py`, new `test_uart_tick_block.py`.

Proposed exact API: `STEP_TLUL_UART_BLOCK(count, rx_bits)`; integer `count∈[1,32]`, unsigned32 `rx_bits`, reject all bits above count, bit0 drives first tick. `count=0`,33, negative/bool host fields, wrong kind and wrong driver schema reject before effects. Fixed two-field admission uses the existing closed parser plus explicit count/tail-bit validation; merely adding maxima is insufficient.

For each `i∈[0,count)`, assign actual RX `(rx_bits>>i)&1`, execute original `tick(dut,&samples)` exactly once. No MMIO or host-selected stop predicate inside this command. Result uses a new closed UART block payload schema with count/rx_bits and all original samples; the real outer receipt retains nonce, sequence, before_tick and after_tick. Require `after-before=count`, contiguous sample ticks and exact sample count. Reserve the worst-case32 complete snapshots (including source/FIFO/clock exports and hex expansion) before executing; if the current replay byte cap cannot reserve it, lower the block bound for this source contract, never truncate samples.

- [ ] Write rejected count/tail/schema/identity tests and mechanical parser replay tests first, then run only the authorized software controls.
- [ ] Implement opt-in command dispatch/schema and strict host parser with scalar default byte stability where promised. Header digest changes legitimately change all affected build identities.
- [ ] Cover duplicate command cached byte equality/no second execution, ACK retirement, wrong nonce/sequence, lost/truncated reply and overflow before tick. Preserve existing uncertain-effect fail-stop.
- [ ] Independently review producer/consumer bounds and new binary admission before any build.

## Task 3: Session and Runner isolated waveform integration

**Files:** `opentitan_uart_session.py:_take`, `step_local`, source/IRQ sample consumers; `scenario/runner.py:_step_once`, `_drain_tick_samples`, binding/IRQ bookkeeping; `scenario/batch.py:ScenarioBatchRecorder`; `integration/dma_uart_rx_runtime.py:_ContinuousRxBoot._execute_case`. New tests `tests/scenario/test_uart_isolated_block.py`; existing UART source/provenance/FIFO fixtures.

Proposed session method: `step_waveform_block(rx_bits: int, count: int)` returns the **real block receipt plus ordered edge results**, not a scalar observation. Proposed Runner method: `step_uart_waveform_block(component: str, count: int)` is available only under the closed isolation preflight above. No generic multi-component fast path is added.

- [ ] Extract the existing post-step sample/source/IRQ/event commit logic into a shared helper; scalar behavior remains the reference. Enumerate every guard from `_step_once()` and either retain it per edge or prove a conservative whole-block preflight; any unhandled guard forces scalar before transmission.
- [ ] Materialize32-or-fewer known RX values from current admitted schedule without mutating peer progress; choose `count` no larger than remaining logical budget and next source/conflict boundary. Run startup/setup through the existing scalar path first.
- [ ] After receiving a validated actual block, process edges strictly in order with sample-local tick, preserving source action, receipt sequence and edge index. Distinguish physical session end tick from semantic committed tick during processing; consumers may not read the block's final tick as the current edge tick. Expose final session tick only after ordered commit; retain actual receipt bounds for failure evidence.
- [ ] Record the original logical `BatchAdvance(('uart',))` sequence for semantic scheduling plus a separate bounded transport grouping ledger. All current `('dma','cpu')` polling and routed MMIO stay scalar and in the same order.
- [ ] Require software cases for block1/2/31/32, repeated same byte, bit changes at block boundaries, frame end/conflict stop, IRQ rise/fall within block, source rejection, capacity refusal before send, and consumer failure at edgek with retained physical suffix. No fabricated native-positive source token is admitted as evidence.

**Deliverable:** a gated waveform-only optimization. If source/IRQ consumers cannot be safely committed through the extracted helper, this task remains open; no deferred or coalesced IRQ delivery is acceptable.

## Task 4: Typed replay and raw receipt joins

**Files:** `src/myfuzz/integration/dma_prefix_replay.py:DmaPrefixReference`, `compare_dma_prefix`; DMA result descriptor codec in `dma_uart_rx_runtime.py`; exact typed identity/reference normalizer used there; `tests/integration/test_dma_prefix_replay.py` and `test_dma_prefix_replay_real.py`.

- [ ] Add an explicit versioned transport grouping ledger: component, semantic command range, native operation/fields, actual receipt scope/sequence and edge count. Freeze block size/splits in the descriptor; fresh uses those recorded splits, not elapsed time or adaptive host scheduling.
- [ ] Preserve original receipt identity in every raw sample reference with an explicit edge index. Bind every logical edge to exactly one actual sample and prohibit gaps/duplicates/out-of-block references.
- [ ] Same-policy full/failure fresh replay must compare all plan commands, raw receipts after existing typed execution-identity normalization, groups, source certificates, events, case boundaries and ticks. Do not suppress all command sequences, raw references, IRQ events or build hashes to make equality pass.
- [ ] Scalar-vs-block validation is a **separate versioned equivalence check**, not a rewrite of old S4 evidence: it compares unchanged source/firmware/logical schedule and per-edge physical/semantic data, while independently validating each run's different wire grouping/receipt sequence. Enumerate each transport-only field in that checker; retain both unmodified documents. It does not assert that scalar and block artifact identities are equal.
- [ ] Tamper one RX bit, sample tick, FIFO sample, IRQ edge, receipt sequence, source action or block split; each must fail its corresponding strict validator/replay comparison.

## Task 5: New actual gates and honest throughput decision

After source review, root schedules a new build because generated C++/header/schema identity changes. Use the new `/root/fanzehui/myfuzz` workspace only after reading its README and verifying actual source/tool maps against the chosen frozen local commit; the user reports its current source snapshot42a9ce9. Do not relabel it current HEAD or modify original `system-20261016`.

- [ ] New actual block1/32 isolated UART pin/FIFO/IRQ gate with every PRE/POST edge retained, plus controlled malformed reply/no-duplicate execution controls.
- [ ] Identical four-byte continuous RX scalar/block runs, full fresh and source-bound failure fresh; each independently validated and all child processes reaped. No budget increase to manufacture completion.
- [ ] Re-run current S2 three-direction multiword, S3 real error ISR and S4 typed prefix gates on the new source. Even though only RX waveform is accelerated, shared parser/header/Runner changes require regression evidence. Any unaffected-direction skip is stated, not counted as pass.
- [ ] Compare scalar and block variants from one reviewed source with explicit transport selector, identical RTL/tools/firmware/inputs/seeds and no other tuning; warm build separately, interleave repeated measurements under the exclusive worker, report median and all individual search wall/effective times and counts. Include end-to-end cold duration separately.
- [ ] Report cases/sec and completed accepted chains/sec, not tick ratio as speedup. State whether5× is relative to frozen original S1 baseline or immediate scalar control and report both with exact source pins. If the criterion remains unmet, keep P8 S1c open and publish the measured limit and residual attribution.

## Review decision requested from root

Approve tasks1–2 first; tasks3–4 require explicit review of per-edge Runner commit and receipt-reference identity before behavior edits. Broader CPU/DMA batching is excluded: CPU requests and DMA responses need host routing between real edges, so their safe design is a separate dependency. The plan does not promise5× and does not upgrade P8 acceptance.
