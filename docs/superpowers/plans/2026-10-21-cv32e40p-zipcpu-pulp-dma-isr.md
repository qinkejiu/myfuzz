# CV32E40P → ZipCPU DMA → PULP GPIO → CV32E40P ISR Implementation Plan

> **For agentic workers:** Use task-scoped implementation and review. Steps use checkbox syntax. Preserve the shared dirty worktree; do not clean, reset, stage, or commit.

**Goal:** Add and independently verify a local one-word CPU-configured DMA path on CV32E40P, including PULP GPIO effect, DMA IRQ/ISR, fresh replay, and a pre-provider wrong-offset refusal.

**Architecture:** Build a CV32E40P RV32I firmware image and an isolated generated CPU/DMA/GPIO Runner. Compile a CV32E40P-pinned D2/D3 route declaration, keep static D3 F6 unsupported, and bind the exact one-word RAM→PADOUT live route through the existing D4 admission. The native gate records first/fresh typed evidence and a separate refused target request.

**Tech Stack:** Python 3, pytest, generated Verilator CPU/DMA/IP sessions, `ScenarioRunner`, `DataflowRouter`, `PersistentMemory`, `PreparedRuntimePathContract`, D2/D3 DMA route intent, D4 topology binding.

## Global Constraints

- Follow `agent.md`: project and evidence stay local for this slice; if remote access becomes necessary, all target filesystem operations remain under `/root/fanzehui/**`.
- Preserve all existing dirty worktree state; do not clean, reset, stage, or commit.
- Use `configs/cpus/cv32e40p/component_profile.json`; the real boot address is `0x10000`, and the direct-mode `mtvec` base is 256-byte aligned at `0x10200`. Match D3 memory geometry: the D3 declaration marks `rom0` at `0x10000..0x17fff` executable and `ram` at `0x20000..0x3ffff` non-executable. One shared `PersistentMemory` represents both regions and enforces their read/write policy; it has no execute permission field, so runtime instruction/data separation is not claimed.
- Admit only one full-word RAM read and one full-word PULP PADOUT write at offset `0x0c`; source is `0x22000`, selected target is `0x4000100c`, the target window accepts only `0x5aa55aa5`, and DMA length is one word.
- Program the DMA control window at `0x40002000`, matching the existing D2 declaration.
- Keep static D3 F6 `unsupported`; consume one selected live route by one D4 bind. Missing and wrong routes refuse before target provider dispatch.
- Do not claim RVFI instruction retirement for CV32E40P, a physical Wishbone-to-APB bridge, physical shared SRAM, a global SoC clock, generic F6, remote validation, continuous fuzz, or aggregate P6/P7/P8 acceptance.
- Preserve the existing Ibex and PULP evidence directories unchanged.

---

Spec: [CV32E40P DMA PULP GPIO ISR design](../specs/2026-10-21-cv32e40p-zipcpu-pulp-dma-isr-design.md)

### Task 1: CV32E40P DMA firmware and instruction tests

**Files:**

- Create: `src/myfuzz/scenario/cv32e40p_dma_pulp_gpio_example.py`
- Create: `tests/scenario/test_cv32e40p_dma_pulp_gpio_example.py`
- Reuse: `src/myfuzz/scenario/ibex_dma_example.py` RV32 encoders; define the CV32 DMA-control base locally as `0x40002000` to match D2.
- Reuse as behavioral reference only: `src/myfuzz/scenario/ibex_dma_pulp_gpio_example.py`

**Interface:**

```python
MAIN = 0x10000
ISR = 0x10200
SOURCE = 0x22000
RESULT = 0x24000

def cv32e40p_dma_pulp_gpio_images(
    *, destination_address: int, start_key: int = 0xFED,
) -> dict[int, bytes]: ...
```

The returned image keys are `MAIN`, `ISR`, `SOURCE`, and `RESULT`. `MAIN`
sets `mtvec=ISR` in direct mode, enables MEIE/MIE, and writes the DMA
source, destination, one-word length, and keyed start in that order. `ISR`
stores `mcause`, DMA status, PADOUT, and source readback; only zero status and
equal readbacks lead to success marker `1`; failures write `0xffffffff`.
The source payload is fixed at `0x5aa55aa5`, matching the D3 accepted-value
declaration used by the native route gate.

- [x] Write a failing decoder test for aligned direct `mtvec`, DMA write order,
  exact one-word start, ISR loads/stores, branch targets, and marker placement.
- [x] Run only that test and confirm failure is the absent CV32 image builder.
- [x] Implement the minimal image builder using existing RV32 encoders; add a
  local JAL encoder only if the image requires it.
- [x] Run the focused test and confirm expected pass, including a wrong-offset
  image whose destination is `PADOUT+4`.

### Task 2: CV32E40P CPU/DMA/PULP fixture

**Files:**

- Create: `src/myfuzz/scenario/cv32e40p_dma_pulp_gpio_runner.py`
- Create: `tests/scenario/test_cv32e40p_dma_pulp_gpio_runner.py`
- Reuse: `src/myfuzz/scenario/ibex_dma_pulp_gpio_runner.py` assembly structure
- Reuse: `src/myfuzz/scenario/pulp_gpio_dma_paths.py` exact PADOUT constants
- Reuse: `src/myfuzz/scenario/runner.py` `Binding` and pulse delivery

**Interface:**

```python
@dataclass(frozen=True)
class Cv32e40pPulpDmaFixture:
    runner: ScenarioRunner
    dma_endpoint_links: dict

def make_cv32e40p_dma_pulp_gpio_runner(
    *, cache_dir: Path, destination_address: int = PADOUT_ADDRESS,
) -> Cv32e40pPulpDmaFixture: ...
```

The fixture uses a single `PersistentMemory` object for CPU and DMA, with exact
`rom0` and `ram` regions matching the D3 declaration, a generated
`cv32e40p` CPU artifact, generated `zipcpu_wbdmac` and PULP causal GPIO
artifacts, the exact full-word PADOUT master target window (only value
`0x5aa55aa5`), DMA control and GPIO
CPU router windows, one `dma.irq`→`cpu.irq` binding, 16 CPU-tick IRQ hold, and
the exact linked DMA endpoint identity required by D4.

- [x] Write failing fixture tests for actual CV32 profile, same CPU/DMA RAM
  object, exact control/target windows, endpoint links, IRQ owner, and pulse.
- [x] Run the focused fixture tests and confirm failure is due to the missing
  fixture.
- [x] Implement the fixture without copying implementation helpers from test
  modules and without enabling `native_irq_receipts` or RVFI claims.
- [x] Run both Task 2 tests and confirm they pass and clean up partially created
  sessions on fixture construction errors.

### Task 3: D4-bound native first/fresh/refusal gate

**Files:**

- Create: `tests/integration/test_cv32e40p_dma_pulp_gpio_real.py`
- Reuse: `tests/integration/test_ibex_dma_pulp_gpio_real.py` event joins and
  exact schedule replay structure
- Reuse: `tests/integration/test_dma_pulp_gpio_real.py` D4 route declaration
  and pre-provider refusal assertions
- Reuse and parameterize: `tests/integration/test_p7b_p7c_dma_route_intent.py`
  `_generate_pulp_gpio_dma_route_d2_d3` for CPU profile and ROM aperture, plus
  `_pulp_d4_declaration`; keep the helper's existing defaults unchanged.
- Reuse: `tests/integration/test_scenario_cv32e40p_opentitan_uart_irq_real.py`
  actual CV32 `irq_ack_o`, `irq_id_o`, and direct trap entry evidence

#### Native attempt1 diagnosis (2026-10-21)

The first native attempt is preserved under
[`attempt1`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt1/).
It failed before the DMA started: CV32's instruction port requested `0x1005c`,
the word after the terminal JAL at `0x10058`, and `PersistentMemory` rejected
that uninitialized byte in read-only `rom0`. The fresh replay was then refused
because the failed first schedule had an incomplete number of rounds; it is not
a fresh execution result. Neither attempt satisfies the native acceptance gate.
The bounded repair initializes otherwise-unused ROM bytes to RISC-V NOPs before
the test case starts, while retaining the D3 ROM/RAM geometry and ROM read-only
permission. Keep this failed attempt intact alongside all later attempts.

Attempt2 is also a failed run and is preserved separately. It completed the DMA
RAM read, the selected PADOUT write, the GPIO APB access/response, and CV32 ISR
stores for `mcause=0x8000000b` and DMA status `0`. DMA IRQ was acknowledged
(`irq_ack_o=1`, `irq_id_o=11`) and CV32 fetched the direct ISR at `0x10200`.
The ISR then requested a PADOUT readback and remained pending because the test
observer treated `ScenarioRunner.step()`'s returned mapping as an object with
`.outputs`; that `AttributeError` happened outside its failure capture, so the
`gpio` schedule step was skipped. The recorded schedule contains only DMA/CPU
steps, and fresh replay correctly rejected that incomplete schedule. This was
a test observer defect, not evidence of a DMA or APB write failure. The fix is
to capture the mapping returned directly, then rerun positive/fresh under a new
attempt directory. See
[`attempt2`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt2/).

The separate wrong-offset native gate passed in attempt3 (**1 passed / 55.96s**).
Its evidence records the Wishbone write to `PADOUT+4`, D4 refusal before any
GPIO provider/APB event, no DMA IRQ delivery, zero success marker, and clean
CPU/DMA/GPIO child exits. The refusal is recorded as Runner `harness_failure`
with status `uncertain_effect` and no uncertain transaction IDs; at the sampled
Wishbone request, `mwb_ack=0` and `mwb_err=0`. This is a host D4 admission
refusal, not an RTL bus-error response. See
[`attempt3`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt3/).

Attempt4 reached the complete native schedule in both first and fresh runs
(103 rounds / 309 steps each), with results
`[0x8000000b, 0, 0x5aa55aa5, 0x5aa55aa5, 1]`, completed D4 admission, and all
child processes exiting zero. Pytest still failed because the assertion expected
a `dataflow_delivery` event that `ScenarioRunner` does not emit; the measured IRQ
evidence is `source_start` plus `cpu_irq_input`, followed by CV32
`irq_ack_o=1`, `irq_id_o=11`, and direct ISR fetch at `0x10200`. Preserve this
attempt as raw evidence, but do not count it as a passing gate: typed-join and
normalized comparison artifacts were not emitted because pytest stopped at the
first assertion. The IRQ assertions now join the actual source/pulse/input
events; attempt5 below is the passing rerun. Keep attempt4 as raw evidence. See
[`attempt4`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt4/).

Attempt5 passed the first/fresh native gate (**1 passed / 65.33s**). Both runs
completed 103 rounds / 309 schedule steps with result
`[0x8000000b, 0, 0x5aa55aa5, 0x5aa55aa5, 1]`; the typed first/fresh comparison
reports `equal=true` with no difference, and all CPU/DMA/GPIO processes exited
zero. The passing run, typed joins, heartbeats, and comparison are preserved in
[`attempt5`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt5/).
Independent evidence review approved the positive/fresh result, with the
heartbeat CPU event-count limitation documented above.

Attempt6 reran the corrected wrong-offset gate (**1 passed / 32.44s**). It
captured the Wishbone write to `0x40001010` (`PADOUT+4`) with data
`0x5aa55aa5`; D4 refused it before provider/APB dispatch, with no observed GPIO
effect, IRQ, or success-marker store, and all child processes exited zero. The
failure status remains `uncertain_effect`, with no uncertain transaction IDs;
the failure heartbeat has one pending CPU response and no pending target
request. Therefore the evidence supports “no downstream effect observed and
refused before provider dispatch,” but not “all transactions drained” or an RTL
bus-error response. See
[`attempt6`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt6/).

Attempt7 added consumed CPU ISR read joins and a same-component CV32 profile
fingerprint drift negative. Its first/fresh native schedules reached the
expected results, but pytest reported `1 failed in 64.52s` (command elapsed
64.75s) because a test-only assertion compared tuple driver samples directly
with JSON-normalized list samples. Preserve attempt7 as a failed assertion gate,
not a pass.

Attempt8 retains the narrowed `_plain` comparison repair and passes the
five-test software gate (**5 passed / 54.96s**) and positive/fresh native gate
(**1 passed / 69.28s**). It adds typed OBI request/receipt/consumed-response
joins for the three ISR reads (sequences 5, 8 and 10) and the D4 refusal for a
mutated profile fingerprint with the same `cv32e40p` component ID. All first
and fresh CPU/DMA/GPIO processes exit zero, all final responses/target requests
are drained, and normalized comparison is equal. The preserved cache
preflight, source snapshot, prior attempt7 inventory, raw evidence and
postflight audit are in
[`attempt8`](../../reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/attempt8/).
Independent evidence review approved that bounded refusal claim.

- [x] Parameterize the D2/D3 route generator for CPU profile and ROM aperture
  while preserving defaults; prove CV32 ROM/RAM/control geometry and rerun the
  existing default PULP route test.
- [x] Add tests that prove the D2 CPU control window is `0x40002000`, the
  generated D3 pins the CV32 profile and `rom0=0x10000` / `ram=0x20000..0x3ffff`,
  and static F6 still says `unsupported`.
- [x] Prepare the exact shared-memory/GPIO `PreparedRuntimePathContract`, bind
  it once with D4, and install `PulpGpioD4RouteAdmission`; assert it selects
  only the RAM-read/PADOUT-write pair and refuses a changed offset before
  provider dispatch.
- [x] Run those software tests and check that a mutated CV32 profile or PADOUT
  offset is rejected before native execution.
- [x] Add an opt-in first/fresh native gate. Capture OBI setup/ISR transactions,
  both DMA typed keys and responses, APB target request/effect/response,
  delivered DMA IRQ, CV32 direct trap fetch at `0x10200`, exact `mcause=0x8000000b`,
  `irq_ack_o` with `irq_id_o=11`, ISR RAM results, full schedule heartbeat,
  identities, and process exit codes.
- [x] Add an opt-in `PADOUT+4` run. Capture the native Wishbone request and
  require refusal before GPIO provider/APB dispatch, no completion IRQ, and no
  success marker.
- [x] Run focused software tests and native gates with evidence isolated per
  attempt. Reuse a content-addressed native build cache only after verifying
  CPU/DMA/GPIO build and runtime artifact identities are unchanged. Preserve
  every run; do not replace earlier evidence on failure.
- [x] Run the positive/fresh native gate and preserve every run, including
  failures, under a distinct attempt evidence directory.
- [x] Rerun the wrong-offset gate with the corrected native IRQ event assertions
  and preserve it under a new attempt directory.
- [x] Independently audit the saved positive/fresh/refusal evidence and correct
  any unsupported claim before documenting acceptance.

### Task 4: Evidence report and status synchronization

**Files:**

- Create: `docs/reports/cv32e40p-zipcpu-pulp-dma-isr-20261021.md`
- Create: `docs/reports/evidence/cv32e40p-zipcpu-pulp-dma-isr-20261021/`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/LOCAL_HARNESS_RUNTIME.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`
- Modify: this implementation plan

- [x] Record exact gate commands, statuses, native child exits, profile/source/
  artifact identities, IRQ ordering, D4 bind identity, typed transaction joins,
  heartbeat results, replay comparison, and audit reference.
- [x] State that CV32 has no RVFI retirement evidence in this profile and that
  this is one bounded CV32/PULP DMA composition only.
- [x] Record the `uncertain_effect` refusal label accurately if present and
  distinguish it from an observed downstream effect or RTL bus error.
- [x] Keep remote validation, static F6, generic CPU onboarding, continuous
  fuzz, six-CPU/four-IP matrix, and aggregate P6/P7/P8 gates explicitly open.
- [x] Run `py_compile`, scoped `git diff --check`, whitespace checks, and links
  for all new report/evidence references; do not stage or commit.
