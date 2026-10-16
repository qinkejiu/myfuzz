# BOOM IRQ runtime gate independent source review

2026-10-17. Reviewed frozen implementation commit `c6e7994` only; no native/build/constructor/describe/tool invocation or test execution performed. Actual test path confirmed from git show: `tests/local_harness/test_boom_irq_verification.py`.

Frozen SHA256:

- `src/myfuzz/scenario/boom_gpio_irq_verification.py`: `3ec9ba1602fd46b0611008ce49fc7d4c3bd20e43526dc86122b0608636227a12`
- `tests/local_harness/test_boom_irq_verification.py`: `3e47de3ae56634b8ef7bc2cd4b401956735b3441c672ec7ed5666f9de0cdb6f2`

Also inspected the plan and implementation report, real factory/program, BOOM native/scenario session, GPIO/local session, IRQ policy and runner teardown. Software GREEN23 is the author's saved receipt, not independently rerun here.

## Verdict: two medium blockers before native authorization

### M1 — trap/ISR/MRET observations are not causally ordered

`validate_run` lines193–222 checks status read values `[0,1,0]`, existence of ROB/CSR cause, one qualified MRET, and a resumed store after MRET. It does not require the initial status clear before the source edge, ISR read1/read-clear0 and cause/mepc/status/clear/done stores after actual trap and before MRET, or MRET after the observed trap/ISR completion.

A concrete source-only counterexample follows directly from the existing `software_chain` fixture: its sole MRET is at tick80, while **all** result stores, including cause/MEPC/status/clear/done, are assigned tick82. The positive checker explicitly accepts this fixture despite claiming ISR work followed by return. The initial read0 is assigned tick11, after the fixture's IRQ pulse starts tick3 and trap tick5, so the advertised initial pre-edge clear also lacks ordering. Moving the qualified MRET from tick80 to tick2 (preserving its actual mepc/evec, then updating transport/passive mirrors as existing `_sync_transport` does) still satisfies all current branch conditions: ROB/CSR tick5, foreground PCs later than2, resumed store82. This reasoning was not executed as a test.

Required fix: retain actual CPU tick and request/response identity for the selected status accesses and accepted RAM stores. Verify the initial clear response precedes injection/source, actual ROB→CSR trap precedes ISR access/results, relevant responses/results precede qualified MRET, and foreground/resumed observation follows MRET. Account explicitly for pre/post edge phase and posted-store/coherent acceptance ordering rather than guessing an instruction-retirement boundary. Add pure RED controls for early MRET, late initial clear, ISR access before trap and result stores after return; fix the synthetic positive fixture to represent the admitted causal chain. Do not enlarge pulse duration, change firmware, weaken qualified MRET or normalize payloads to achieve this.

### M2 — physical source is not joined to the selected pulse identity

Lines165–169 require one physical GPIO IRQ rise and one source_start with the same local GPIO tick. `validate_pulse` independently requires one64-tick pulse, but no check binds `pulse_start.source_event_id` to `source_start.source_event_id` or validates their `source_trigger`/component/port/producer provenance against that physical GPIO sample and binding. A pulse with a changed source ID/trigger therefore retains all currently checked values and passes. The existing positive fixture omits these identity fields entirely and is accepted, documenting the missing consumer.

Required fix: consume the real policy/Runner source and pulse identifiers plus their declared GPIO irq→CPU irq provenance; match the producer native sample/event/tick/phase and expected destination. Require exact shared source_event_id/trigger and ordering, with pure negative controls for swapped pulse source, wrong binding/component/port and mismatched producer sample. Keep the physical edge and64 requested/delivered samples in suppression control.

## Reviewed strengths / remaining evidence boundary

- Actual CPU STEP command/response, passive samples and coherent accepted raw are compared. External A/D, transaction execution, target access identity and routed read value are joined. Actual manager RAM observations supplement accepted stores.
- Pulse policy remains fixed64 with requested and delivered values separately captured; suppression changes the actual adapter input to0 and requires all measured IRQ/MEIP0 while retaining the real GPIO edge and requested64. It is correctly labelled an environment fault, not DUT failure.
- Native capture records constructor temporary CPU and measured CPU process on first actual read, actual raw/READY/unknown lines and partial buffers, commands and real close/poll status. GPIO capture is installed before begin_case, so startup wire lines and abort lifecycle are retained. Normal finalization attempts every peer; failure prefixes retain errors and available raw data.
- Fresh comparison retains full CPU samples/outputs, GPIO samples/wire, source/router/Runner/coherent/commands; typed identity replacements touch explicit documentary slots and do not recurse into arbitrary payloads. It requires all declared execution identities and per-role PIDs to differ. Field/index diagnostics and originals remain available on mismatch.
- Explicit native flag, new confined output, nonblocking canonical lock, exact source/artifact/session-file pins, whole-gate host-source scope, and final audit preserve the metadata-only BOOM origin without rewriting old metadata. No BOOM build path is introduced. Input audits run even when a runtime/validation error occurs.
- Source/retirement/fullP6 authority remains false. Actual native timing, fresh determinism and physical chain remain unverified until blockers are resolved, independently reviewed and separately authorized native receipts exist.
