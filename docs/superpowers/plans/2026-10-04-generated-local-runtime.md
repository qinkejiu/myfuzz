# Generated Local CVE2 and PULP GPIO Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn validated local CVE2 and PULP GPIO plans into persistent real RTL sessions, then accept both specified CVE2/two-GPIO propagation directions for two rounds with complete fresh replay.

**Architecture:** Consume the structural renderer output without changing its one-DUT wrapper or ABI; generate a separate runtime top and C++ driver around that wrapper. Reuse existing OBI/APB transactors and scenario process, memory, transaction, scheduler, and replay infrastructure. Each testcase owns one RTL process per component; target register state persists until an explicit component reset or testcase end.

**Tech Stack:** Python 3, unittest, SystemVerilog, C++17, Verilator, existing myfuzz scenario APIs.

## Global Constraints

- Original pinned `cve2_top` and `apb_gpio` are the only DUT implementations; no behavioral register or CPU substitute.
- First runtime scope: CVE2 OBI instruction/data endpoints and PULP GPIO APB3, one outstanding transaction per endpoint, one clock/reset domain per process.
- Profile parameters, constants, source closure, and every physical top bit remain authoritative. Unsupported ownership or protocol shapes fail before build.
- Preserve `local_harness.v1` request and `local_harness_plan.v1`; add separately versioned runtime artifact and wire ABI.
- CVE2 boot is `0x10000`. PULP register window is 4096 bytes; writes require all four byte enables.
- Observe native GPIO interrupt pulses. No implicit level conversion or CPU interrupt servicing claim.
- Preserve legacy `scenario_host_sources.v1` fixed 34-file identity validation; generated packages use a separately versioned per-harness host closure including generator/templates/session dependencies.
- Builds use one worker, no waveforms by default, bounded execution, no network fetch, and no push.
- A lost receipt never authorizes repeating uncertain RTL side effects.

---

## File map and interfaces

Reuse `src/myfuzz/local_harness/renderer.py` and `render_local_harness(plan) -> RenderedLocalHarness` (`wrapper_sv`, `abi_document`, `build_document`). Create `src/myfuzz/local_harness/runtime_artifact.py` for immutable runtime identity; `runtime_renderer.py` for separate runtime-top SV and C++ generation; `build.py` for identity-keyed builds; `session.py` for process and wire transport; `cpu_session.py` for host memory/OBI service; `gpio_session.py` for environmental pins and register accesses. Create `src/myfuzz/local_harness/rtl/local_driver_v1.h` for bounded wire parsing and per-tick receipts. Modify `local_harness/__init__.py` to expose public APIs. Reuse, without copying DUT semantics, `scenario/protocol_io.py`, `scenario/rtl/local_command_replay.h`, `scenario/identity.py`, `scenario/ledger.py`, `scenario/memory_service.py`, `scenario/router.py`, `scenario/runner.py`, and `scenario/replay.py`.

Public contracts introduced by the stages:

```python
@dataclass(frozen=True)
class LocalRuntimeArtifact:
    plan: LocalHarnessPlan
    structural: RenderedLocalHarness
    source_verification: dict[str, object]
    runtime_sv: str
    cpp_text: str
    runtime_document: dict

def render_local_runtime(plan: LocalHarnessPlan, structural: RenderedLocalHarness,
                         source_verification: dict[str, object]) -> LocalRuntimeArtifact: ...
def build_local_harness(artifact: LocalRuntimeArtifact, *, base_dir: Path,
                        cache_dir: Path) -> Path: ...

class GeneratedLocalSession:
    def __init__(self, artifact: LocalRuntimeArtifact, *, base_dir: Path,
                 cache_dir: Path): ...
    def prepare_local(self) -> None: ...
    def identity_document(self) -> dict: ...
    def begin_case(self, testcase_id: str) -> None: ...
    def command(self, operation: str, fields: tuple[int, ...]) -> dict: ...
    def end_case(self) -> None: ...

class GeneratedCve2Session(GeneratedLocalSession):
    def __init__(self, artifact, *, base_dir, cache_dir,
                 memory: PersistentMemory, router: DataflowRouter,
                 defer_mmio: bool = True): ...
    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]: ...

class GeneratedPulpGpioSession(GeneratedLocalSession):
    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]: ...
    def write_register(self, offset: int, value: int, *, be: int = 15) -> None: ...
    def read_register(self, offset: int) -> int: ...
```

Both specialized sessions provide `local_ticks`, pending counts, quiesce, reset, and bounded tick cost properties required by `ScenarioRunner`. Use `source_lock.py::verify_local_source_lock(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]` at runtime artifact/build acceptance and before cache reuse. Require its `local_source_lock_verification.v1` result; source identity failure prevents runtime admission. Structural rendering remains independent of this operational gate. The immutable runtime artifact is consumed by all later tasks; do not reread an unrelated profile and build different RTL.

## Wire ABI: local_driver.v1

All commands are ASCII lines, lowercase hexadecimal integers, exact arity, no trailing fields. Startup is `READY local_driver.v1 <artifact_digest> <assert_ticks> <release_ticks>`. Execution IDs are 32 lowercase hex characters; command sequences start at 1. END closes the process.

```text
CMD <execution> <sequence> STEP_CPU <irq_external> <iready> <ivalid> <idata> <ierr> <dready> <dvalid> <ddata> <derr>
CMD <execution> <sequence> STEP_GPIO <gpio_in>
CMD <execution> <sequence> ACCESS_GPIO <gpio_in> <write> <offset> <data> <be>
RESULT <execution> <sequence> <tick_before> <tick_after> <payload_hex>
ERROR <execution> <sequence> <tick_after> <code> <detail_token>
```

`payload_hex` is hex-encoded canonical UTF-8 JSON, bounded to 1 MiB before decoding. Integer fields are JSON integers; wide physical observations use fixed-width lowercase hex strings with explicit bit width. CPU payload contains pre-edge instruction/data request fields, response-ready, request acceptance booleans, and post-edge observations. GPIO payload contains `gpio_out`, `gpio_dir`, `gpio_in_sync`, `gpio_padcfg`, `interrupt`, `rdata`, `error`, and a `samples` array with one record per advanced tick, including pre-edge and post-edge interrupt values. All payload schemas have `schema_version: local_driver_result.v1`.

Use `LocalCommandReplay.accept(execution, sequence, original_line, reply)` before driving inputs. Cache the entire terminal RESULT or ERROR with `finish`. Cached commands advance zero ticks. Identity conflicts, stale execution, invalid fields, and out-of-order commands are rejected before an RTL edge. Runtime timeout after possible acceptance is `uncertain_effect`, not a permission to retry. Include execution/sequence/tick identity even in protocol environment failures.

### Task 1: Layer runtime tops over the structural renderer

**Files:** Create `runtime_artifact.py`, `runtime_renderer.py`; modify `__init__.py`; create `tests/local_harness/test_runtime_renderer.py`.

**Interfaces:** Consume the validated plan, `renderer.py::render_local_harness(plan) -> RenderedLocalHarness`, and successful source verification; produce `LocalRuntimeArtifact` and `render_local_runtime()` defined above. Preserve structural wrapper bytes and ABI; do not redefine or modify the structural public API.

- [ ] Write failing renderer tests for CVE2 and GPIO: deterministic output, every physical port connected exactly once, parameters preserved, external pins exported, constants matched, no behavioral DUT substitute, and unsupported protocol rejected.

```python
def test_gpio_render_preserves_native_source(self):
    structural = render_local_harness(self.gpio_plan)
    verified = verify_local_source_lock(self.gpio_plan.profile, base_dir=ROOT)
    artifact = render_local_runtime(self.gpio_plan, structural, verified)
    self.assertEqual(structural.wrapper_sv, artifact.structural.wrapper_sv)
    self.assertEqual(structural.abi_document, artifact.structural.abi_document)
    self.assertIn('beat_to_apb #(', artifact.runtime_sv)
    self.assertEqual('local_runtime_artifact.v1',
                     artifact.runtime_document['schema_version'])
    self.assertEqual(self.gpio_plan.document(),
                     artifact.runtime_document['plan'])
```

- [ ] Run `PYTHONPATH=src python -m unittest discover -s tests/local_harness -p test_runtime_renderer.py -v`; expect import failure before implementation.
- [ ] Implement runtime generation by connecting the structural ABI ports to runtime-owned transactors and driver fields. Validate the full physical bit ledger against facts/dispositions; do not alter the one-DUT wrapper or silently truncate. Packed structs become packed vectors with the exact elaborated width at the wrapper boundary. Export all observe outputs, including CVE2 RVFI and crash status, with wide serialization.

```python
for port in plan.facts.ports:
    entries = tuple(item for item in plan.dispositions if item.port == port.name)
    spans = [(item.bit_lo, item.bit_hi) for item in entries]
    covered = [bit for lo, hi in spans for bit in range(lo, hi + 1)]
    if sorted(covered) != list(range(port.width)):
        raise ValueError('incomplete-local-port:' + port.name)
```

- [ ] Instantiate adapters only in the new runtime top outside the structural wrapper. Instantiate `obi_processor_memory_adapter.sv` twice with instruction read-only/full byte mask and data byte enables. Instantiate `beat_to_apb.sv` for GPIO with no PSTRB/partial writes and profile wait bound; connect only resolved physical APB3 fields. Use local offsets and `WINDOW_BASE=0`, `WINDOW_SIZE=4096`.
- [ ] Run renderer tests; expect all pass. Inspect generated top text against the full bit ledger. Commit renderer/artifact/tests with `git commit -m 'feat: render source-backed local runtime tops'`.

**Evidence gate:** generated tops preserve all physical port ownership and use original source top modules; no structural-only claim of operational status.

### Task 2: Build and versioned persistent driver transport

**Files:** Create `build.py`, `session.py`, `rtl/local_driver_v1.h`; extend `runtime_renderer.py`; create `tests/local_harness/test_driver_protocol.py`, `test_build_identity.py`, `test_session.py`.

**Interfaces:** Consume artifacts; produce `build_local_harness()` and `GeneratedLocalSession.command()` with the ABI above.

- [ ] Add transport tests asserting duplicate command cached reply/zero ticks, conflicting payload rejection, wrong sequence rejection, malformed/wide/overflow values rejected, bounded payloads, EOF and timeout failure, and monotonic actual ticks. Test command 1, command 2, then a cached command 1: the historical receipt must not add ticks, samples, or side effects again. Add build tests asserting changing an included source, generated driver, parameters, or build flags changes cache identity.

```python
def test_receipt_cannot_move_ticks_backwards(self):
    session = self.session_with_reply(tick_before=4, tick_after=3)
    with self.assertRaisesRegex(RuntimeError, 'tick'):
        session.command('STEP_GPIO', (0,))
```

- [ ] Run the three new unittest modules; expect missing API failures.
- [ ] Generate driver tick code with a per-tick sample before and after the edge. Force inactive-reset evaluation, active reset evaluation, configured assertion clocks, then release and configured release clocks. Startup echoes measured reset counts; exclude startup clocks from runtime counter.

```cpp
static void tick(Model &dut, Samples &samples) {
  dut.clk = 0; dut.eval();
  const auto before = snapshot(dut);
  dut.clk = 1; dut.eval();
  ++local_ticks;
  const auto after = snapshot(dut);
  dut.clk = 0; dut.eval();
  samples.append(local_ticks, before, after);
}
```

- [ ] Build from original profile file order/include roots/defines/parameters plus generated top/driver and transactors. Use subprocess argument arrays, `--build -j 1`, finite timeout, cleanup failed build, and atomic publication of successful cache entries. Bundle original closure/includes, profile, request/plan, generated text, transactors, replay header, ABI header, tool versions and flags into canonical identity; verify selected source bytes still match before cache reuse. Retain generated artifact bytes for review.
- [ ] Implement persistent launch and bounded IO with existing `BoundedLineReader`, startup/deadline helpers, `end_local_process`, and replay header. Define 1 MiB as the **decoded JSON** payload limit; a hex-encoded line therefore needs a bound of at least `2 * 1 MiB + envelope + newline`, while also checking decoded length. Test at the limit and one byte over. Every generated `command()` establishes a finite deadline even outside `ScenarioRunner`, intersecting any enclosing testcase deadline; a partial line that stalls must time out. `prepare_local()` builds before testcase wall accounting. Verify READY version, digest, and reset measurements against the artifact.
- [ ] Validate lowercase hexadecimal identity and integer tokens, exact arity, and overflow before `LocalCommandReplay.accept()`. Wrap its short rejection into the versioned `ERROR <execution> <sequence> <tick> <code> <detail>` envelope; use a separate parse-error form when execution/sequence cannot be parsed. Return cached terminal replies verbatim. Bound cumulative cached-reply bytes before any fresh command, without evicting an old receipt that could permit a repeated physical transaction.
- [ ] Run the three modules; expect pass. Commit only staged runtime transport files/tests with `git commit -m 'feat: build persistent versioned local RTL drivers'`.

**Evidence gate:** driver identity pins bytes actually compiled; commands cannot cause duplicated or unacknowledged silent side effects.

### Task 3: Make PULP GPIO operational through native APB3

**Files:** Create `gpio_session.py`, `tests/integration/test_local_pulp_gpio_generated_real.py`; extend driver generation in `runtime_renderer.py`.

**Interfaces:** Consume generated transport; produce `GeneratedPulpGpioSession` and register-target methods consumed by `DeviceWindow`.

- [ ] Write real RTL tests guarded by `MYFUZZ_SCENARIO_REAL=1`: PADDIR/PADOUT readback, SET/CLR, independent two-process state, synchronized PADIN with GPIOEN, read-clearing INTSTATUS, full-word requirement, pulse capture during register transaction clocks, and reset with monotonic lifetime ticks.

```python
gpio.write_register(0x0c, 0xa5)
gpio.write_register(0x10, 0x02)
self.assertEqual(0xa7, gpio.read_register(0x0c))
gpio.write_register(0x14, 0x04)
self.assertEqual(0xa3, gpio.read_register(0x0c))
with self.assertRaises(ValueError):
    gpio.write_register(0x0c, 0xffff, be=1)
self.assertEqual(0xa3, gpio.read_register(0x0c))
```

- [ ] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p test_local_pulp_gpio_generated_real.py -v`; expect missing session failure.
- [ ] Drive a beat until acceptance, deassert valid, await response within declared bound, capture response before consumption, then consume exactly once. Count every actual edge. APB transactor creates SETUP then ACCESS; read capture precedes read-clear edge. Driver returns all tick samples, including transaction ticks, without an extra unrequested settle clock.
- [ ] Retain environmental `gpio_in` across accesses; expose native pulse samples as receipts for evidence. `pending_events` drains a documented bounded synchronizer pipeline after pin changes; readiness derives from clocks, never a predicted interrupt. Do not turn `r_status` into IRQ. Test event-over-clear priority with a concurrent transition.
- [ ] Run real GPIO module; require all cases executed rather than skipped. Commit with `git commit -m 'feat: run generated PULP GPIO sessions on real APB RTL'`.

**Evidence gate:** observed reads originate in actual APB response, rejected partial writes cause no physical access, and interrupt pulses survive multi-clock commands.

### Task 4: Make CVE2 operational with host-owned memory

**Files:** Create `cpu_session.py`, `tests/integration/test_local_cve2_generated_real.py`; extend `runtime_renderer.py` CPU payload generation.

**Interfaces:** Consume generated transport and existing `PersistentMemory`, `MemoryService`, `TransactionLedger`, `DataflowRouter`; produce `GeneratedCve2Session`.

- [ ] Write real tests for first instruction fetch at 0x10000, machine-mode startup observation where available, arithmetic/store into RAM, host response held until ready, no unsolicited response, separate instruction/data transactions, and quiesce/reset cancellation.

```python
program = (0x000201b7, 0x02a00113, 0x0021a023, 0x0000006f)
memory.preload(0x10000, b''.join(word.to_bytes(4, 'little') for word in program))
# RAM includes 0x20000; drive until actual CPU store is accepted.
for _ in range(20000):
    cpu.step_local({'irq': 0})
    if cpu.memory_write_count:
        break
self.assertEqual(1, cpu.memory_write_count)
```

- [ ] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p test_local_cve2_generated_real.py -v`; expect missing session failure.
- [ ] Reuse the flow of `IbexCpuSession._serve()`/`step_local()`, with artifact instance ID as transaction source, one pending response per channel, and grants only when no prior response/MMIO is pending. Accept only pre-edge actual handshakes; serve host memory after the edge. In deferred mode enqueue MMIO and respond only after target completion. External IRQ input is one physical bit; other IRQs stay profile constants.
- [ ] Maintain `reset_epoch` and per-channel source sequences. On explicit reset, cancel router entries/ledger acceptances and pending responses, restart only this component, preserve host memory, and retain monotonic lifetime tick accounting. Declare max transaction events per tick as 2 and deferred MMIO accesses as 0.
- [ ] Run real CVE2 module; require actual fetch and store receipts. Commit with `git commit -m 'feat: serve generated CVE2 OBI sessions from persistent memory'`.

**Evidence gate:** CPU requests are actual RTL handshakes, memory retains accepted stores, and delayed target responses cannot create repeated CPU acceptances.

### Task 5: Scenario identity, reset evidence, and pulse receipts

**Files:** Modify `src/myfuzz/scenario/contracts.py`, `host_identity.py`, `runner.py` only where needed for generated reset/pulse receipts; create `tests/scenario/test_generated_local_contract.py`, `tests/local_harness/test_generated_replay_identity.py`.

**Interfaces:** Consume artifact runtime identity and READY measurements; produce a generated reset evidence variant accepted by scenario preflight and complete event records for command-internal ticks.

- [ ] Add failing tests proving generated reset evidence is admitted only with matching artifact/driver hashes and READY counts; tampered reset counts/source/ABI fail. Preserve all legacy wrapper verification cases. Add replay tests for profile/include/driver/ABI changes causing manifest mismatch before execution.
- [ ] Run new modules; expect generated variant rejection in current `_verify_local_reset_timing()`.
- [ ] Add an explicit `generated_local_reset.v1` record containing artifact digest, generated driver digest and declared asserted/released counts. Validate the reset program and artifact bytes during manifest preflight, before RTL startup; validate measured READY counts after the process starts. Keep legacy literal-loop validation for existing wrapper records; do not weaken the old regex globally. The transient READY receipt is runtime evidence, not a stable manifest identity field.
- [ ] Add `scenario_harness_host_sources.v2` identity validation for generated packages using each artifact's actual Python/C++/template dependency closure. Leave legacy `scenario_host_sources.v1` 34-file enumeration and validation intact; test both variants and ensure changing a v2-only generator dependency does not invalidate unaffected v1 packages.
- [ ] Record every driver tick sample with component ID, command sequence, local tick, pre/post phase, native interrupt, and physical observations. Budget these records before issuing an access; reconcile actual edges after response. Wire execution UUID is receipt transport identity, excluded from semantic replay records; distinct fresh-run UUIDs must replay to the same semantic trace. Keep explicit pulse-to-CPU binding outside this milestone.
- [ ] Run new modules and existing scenario contract tests; expect pass. Commit with `git commit -m 'feat: validate generated reset identity and retain internal tick evidence'`.

**Evidence gate:** generated sessions are accepted by strict scenario contracts, complete tick observations are budgeted, and changed runtime bytes invalidate replay.

### Task 6: Intermediate persistent CPU-to-GPIO gate and fresh replay

**Files:** Create `tests/integration/test_scenario_cve2_two_pulp_gpio_real.py`, `examples/local_harness/cve2-two-pulp-gpio.json`; update `docs/LOCAL_HARNESS_RUNTIME.md`.

**Interfaces:** Consume both sessions and existing `ScenarioRunner`, `DependencyScheduler`, `record_scenario()`, `replay_scenario()`; produce acceptance evidence and a reproducible example.

- [ ] Write a fresh factory using three artifacts with IDs `cpu_0`, `gpio_a`, `gpio_b`. Use windows 0x40000000 and 0x50000000, each size 0x1000; fixed zero external CPU IRQ; declared source-owned GPIO pins. Share one `DataflowRouter` and host `PersistentMemory` with CPU deferred MMIO.

```python
program = (
    0x400000b7, 0x0a500113, 0x0020a623, 0x0020a623,
    0x500000b7, 0x05a00113, 0x0020a623, 0x0000006f,
)
memory.preload(0x10000, b''.join(w.to_bytes(4, 'little') for w in program))
router = DataflowRouter((
    DeviceWindow('gpio_a', 0x40000000, 0x1000, gpio_a),
    DeviceWindow('gpio_b', 0x50000000, 0x1000, gpio_b),
))
```

- [ ] Schedule CPU until the next target request appears, step only that target, then allow CPU response completion. Assert three acceptances and deliveries, targets `[gpio_a, gpio_a, gpio_b]`, values `[0xa5, 0xa5, 0x5a]`, distinct same-value source transaction keys, final PADOUTs 0xa5/0x5a, and unchanged GPIO-A state during GPIO-B access. Add pin transition/status-read actions to exercise persistent synchronization and pulse evidence without resetting the testcase.
- [ ] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p test_scenario_cve2_two_pulp_gpio_real.py -v`; initially expect missing acceptance fixture or behavioral assertion failures.
- [ ] Express the actions as a bounded `ScenarioGenome`; run through `DependencyScheduler` and record with `record_scenario(genome, factory)`. Replay using a fresh factory and assert `matches`, equal event list, ticks, terminal status, semantic digest, and manifest digest. Verify all processes close after completion/failure. Document exact commands and native pulse semantics.
- [ ] Run the acceptance module twice only if the first reveals nondeterminism or new fixes; otherwise retain the first passing evidence. Commit with `git commit -m 'test: accept CVE2 with two persistent generated GPIO sessions'`.

**Evidence gate:** all three original RTL models execute, both GPIO states persist independently, repeated equal-value stores remain distinct, and fresh replay matches complete evidence. Fixed-zero IRQ and CPU writes establish only persistent CPU→IP operation; this intermediate gate cannot establish Cross-component accepted or complete approved stage A.

### Task 7: Explicit pulse delivery and both persistent propagation directions

**Files:** Create `tests/fixtures/scenario_cve2_pulp_gpio_roundtrip.S`, `tests/fixtures/scenario_cve2_pulp_gpio_roundtrip.ld`, `tests/integration/test_scenario_cve2_pulp_gpio_bidirectional_real.py`; extend `examples/local_harness/cve2-two-pulp-gpio.json` and `docs/LOCAL_HARNESS_RUNTIME.md`. Modify `src/myfuzz/scenario/irq.py` or `runner.py` only if existing `IrqPulseDelivery` cannot consume all native pulse receipts from command-internal ticks.

**Interfaces:** Consume native tick samples, `Binding`, `ScenarioRunner(irq_pulses=...)`, bound-input ownership, both generated sessions, and full trace replay. Produce approved stage-A evidence for CPU→GPIO A→GPIO B→CPU and GPIO B external input→CPU→GPIO A, at least two rounds each in a single testcase.

- [ ] Write failing ownership/IRQ tests: A.out[7:0] exclusively owns B.in[7:0]; B.in[15:8] is the only free external bank; direct mutation of B low bank is rejected. Declare one explicit B.native_interrupt→CPU.external_irq binding with delivery width 4 CPU ticks in the manifest. Record native pulse, enqueue, CPU input rise/fall, and expiry separately. Multiple observed pulses during one MMIO command must retain separate causal events rather than collapse into one level snapshot.
- [ ] Run `MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p test_scenario_cve2_pulp_gpio_bidirectional_real.py -v`; expect missing fixture/API or acceptance failures.
- [ ] Implement the assembly fixture at reset PC 0x10000, direct `mtvec`, `mie.MEIE=1`, and `mstatus.MIE=1`. All GPIO setup and status access must come from accepted CPU OBI requests. A.PADDIR enables output banks. B.GPIOEN enables both input banks; B.INTEN enables strobes bits 7/15; B.INTTYPE_LOW sets bits 7/15 and B.INTTYPE_HIGH clears them for rising-edge mode. ISR reads B.PADIN and B.INTSTATUS via real APB, records status/data in persistent RAM, and finishes with `mret`. PULP status acknowledgement is read-clear at 0x24, never OpenTitan write-one-clear. Keep no other IRQ source active.

```asm
# Fixture constants: A=0x40000000, B=0x50000000, S=0x00020000.
# Native setup offsets: PADDIR=0x00, GPIOEN=0x04, PADIN=0x08,
# PADOUT=0x0c, INTEN=0x18, INTTYPE_LOW=0x1c,
# INTTYPE_HIGH=0x20, INTSTATUS=0x24.
# Payload/strobe: low bank bits[6:0]/bit7, high bank bits[14:8]/bit15.
# Main roundtrip publications, with a real low-strobe write between rounds:
li t0, 0x40000000
li t1, 0x81
sw t1, 12(t0)       # low payload 1, strobe rises
# wait on persistent ISR completion counter == 1
li t1, 1
sw t1, 12(t0)       # strobe falls; allow B synchronization clocks
li t1, 0x82
sw t1, 12(t0)       # low payload 2, second rising strobe
# ISR load sequence; handler saves/restores every register it uses:
li t0, 0x50000000
lw t1, 8(t0)
lw t2, 36(t0)      # real read-clear acknowledgement
```

ISR dispatch uses observed status bit7 for roundtrip input and bit15 for external input. Both update persistent S initialized to 5; independent checker derives expected updates from real CPU-consumed PADIN, never supplies read data. External rounds use payloads 3 then 4 and explicit low→high strobe transitions after the CPU has configured B. ISR writes the resulting S into A high bank while preserving A low bank, then a main-program CPU load verifies the persistent RAM value. The four ordered updates 1,2,3,4 produce S values 6,8,11,15; final S is 15. Execute both directions twice without restarting any process, resetting, or reloading the image.

- [ ] Add a checked linker placement for reset code, ISR, and RAM; generate the fixture image with the repository's existing RV32 assembler path and record image bytes/tool identity in the manifest. Verify CPU instruction acceptance/retirement reaches the real handler and returns; an delivered IRQ alone is not ISR evidence. Wait for each ISR completion before entering quiesce, since quiesce halts new instruction requests.
- [ ] Trace each round from originating source action/CPU transaction to actual A output, bound B input, B synchronized PADIN/status/native pulse, explicit CPU IRQ delivery, accepted CPU loads, ISR RAM store, and result output. Negative tests cover bound-input mutation, wrong-direction binding, missing dependency, false level declaration for PULP, repeated command identity conflict, and a driver crash after a write: reject or classify checker finding/uncertain effect with last reliable receipts.
- [ ] Run the real acceptance module; require four ISR completions, two rounds per direction, actual CPU external IRQ evidence, expected RAM 15 and A high payload 15, no pending targets/IRQ deliveries, and no implicit resets. Record the bounded genome with `record_scenario`; replay through a fresh factory with `replay_scenario` and compare full events/ticks, persistent RAM version/writer facts, IRQ final state, and ledger receipts. Commit with `git commit -m 'test: accept bidirectional CVE2 PULP GPIO rounds and replay'`.

**Evidence gate:** only after this task passes may these generated harnesses be labeled Cross-component accepted for approved stage A. Task 6 alone remains intermediate persistence evidence.

## Final acceptance commands and retained evidence

```bash
PYTHONPATH=src python -m unittest discover -s tests/local_harness -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p 'test_local_*_generated_real.py' -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p test_scenario_cve2_two_pulp_gpio_real.py -v
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python -m unittest discover -s tests/integration -p test_scenario_cve2_pulp_gpio_bidirectional_real.py -v
PYTHONPATH=src python -m unittest discover -s tests/scenario -p test_generated_local_contract.py -v
```

Retain generated SV/C++, canonical identity and build arguments, Verilator/compiler versions, READY reset receipts, per-command tick counts, accepted source transactions, target deliveries, complete native pulse observations, record/replay traces, and command exit status. A skipped real RTL test is not evidence of operational support. Review each stage before its next dependency executes; report structural, operational, persistent-composition, and replay evidence separately according to the gates above.

## Plan self-review

- [x] Full facts/dispositions, generated driver/session, both protocols, and source-backed execution have explicit tasks.
- [x] Timing, async reset edge, APB read-clear, partial write rejection, and pulse capture are specified.
- [x] Exact artifact/session API names and wire versions are consistent across tasks.
- [x] Identity includes original and generated bytes, build configuration and toolchain; fresh replay and mismatch rejection are acceptance requirements.
- [x] The structural renderer API/one-DUT wrapper are preserved; runtime adapters and source admission use separate files/interfaces.
- [x] Intermediate persistence is distinct from full two-direction/two-round acceptance with IRQ delivery, ISR reads, bound propagation, and replay.
- [x] Plan only; no runtime code or RTL tests executed while preparing this document.
