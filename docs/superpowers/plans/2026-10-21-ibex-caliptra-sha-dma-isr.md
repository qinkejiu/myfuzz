# Ibex Caliptra SHA DMA ISR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real Ibex-configured ZipCPU DMA path into Caliptra SHA256 with a DMA completion IRQ, ISR readback, and fresh replay.

**Architecture:** Build an isolated firmware and Runner using the existing Ibex CPU, ZipCPU DMA, shared persistent RAM, keyed Caliptra AHB provider, and ScenarioRunner IRQ pulse delivery. The integration gate prepares the existing static route, performs exactly one D4 bind, records native positive/refusal evidence, and compares an independent fresh execution.

**Tech Stack:** Python 3, pytest, generated Verilator sessions, `ScenarioRunner`, `DataflowRouter`, `PersistentMemory`, `GeneratedWishboneDmaScenarioSession`, `GeneratedAhbLiteRegisterSession`.

## Global Constraints

- Follow `agent.md`; all implementation and evidence for this slice stay in the local project. Any later remote operation must remain within `/root/fanzehui/**`.
- Preserve the shared dirty worktree; do not clean, reset, stage, or commit.
- Preserve prior Caliptra and PULP evidence by adding new fixture, gate, and evidence paths.
- Keep the DMA target window limited to full-word `CTRL@0x10 = 5`; keep the source to the declared RAM word.
- Keep independent generated sessions connected through declared transaction-level providers; do not claim a physical Wishbone-to-AHB bridge or shared physical SRAM.
- Keep static D3 F6 `unsupported`; only the live route is consumed through one D4 binding.
- Keep remote validation, generic F6, multiword SHA, and overall P8 acceptance open.

---

Spec: [Ibex Caliptra SHA DMA ISR design](../specs/2026-10-21-ibex-caliptra-sha-dma-isr-design.md)

### Task 1: Add the CPU firmware image and instruction tests

**Files:**

- Create: `src/myfuzz/scenario/ibex_dma_caliptra_sha_example.py`
- Create: `tests/scenario/test_ibex_dma_caliptra_sha_example.py`
- Reuse: `src/myfuzz/scenario/ibex_dma_example.py`

**Interface:**

```python
def ibex_dma_caliptra_sha_images(
    *, source_value: int, destination_address: int, start_key: int = 0xFED
) -> dict[int, bytes]: ...
```

The image keys are `MAIN`, `ISR`, `SOURCE`, and `RESULT` from
`ibex_dma_example.py`. `MAIN` configures machine external interrupts, then
writes `SOURCE`, `destination_address`, word length `1`, and the keyed start
word to `DMA_BASE + {8, 12, 4, 0}` in that order. The fixed source address
contains `source_value`.

`ISR` stores `mcause` and DMA status, refuses a nonzero DMA status, polls SHA
`STATUS@0x18` until bit 1 is set or the fixed poll limit expires, reads SHA
`DIGEST0..DIGEST7` at offsets `0x100..0x11c`, stores each word in result RAM,
and stores marker `1` only after the status checks and all digest loads.
Timeout or nonzero status stores marker `0xffffffff`. The test decodes the
fixed image and checks access order, addresses, values, status branches, digest
loads/stores, and marker branch placement.

- [x] Write a failing firmware test for configuration order, exact one-word
  length/start, bounded SHA-status polling, eight digest reads/stores, and
  success-only marker.
- [x] Run the focused test and verify failure is due to the missing image
  builder.
- [x] Implement the image using the existing RV32 encoders, adding only the
  encoder helpers needed by this image.
- [x] Run the focused test and confirm it passes, including the follow-up
  exact poll back-edge and source-lineage regression assertions.

### Task 2: Assemble an isolated Ibex/DMA/Caliptra Runner

**Files:**

- Create: `src/myfuzz/scenario/ibex_dma_caliptra_sha_runner.py`
- Create: `tests/scenario/test_ibex_dma_caliptra_sha_runner.py`
- Reuse: `src/myfuzz/scenario/ibex_dma_caliptra_sha_example.py`
- Reuse: `src/myfuzz/scenario/ibex_dma_pulp_gpio_runner.py` as the assembly pattern
- Reuse: `src/myfuzz/local_harness/ahb_lite_register_session.py`

**Interface:**

```python
@dataclass(frozen=True)
class IbexCaliptraShaDmaFixture:
    runner: ScenarioRunner
    dma_endpoint_links: dict

def make_ibex_dma_caliptra_sha_runner(
    *, cache_dir: Path, source_value: int = 5,
    destination_address: int = SHA_START_ADDRESS,
) -> IbexCaliptraShaDmaFixture: ...
```

The fixture exposes sessions as `runner.sessions['cpu'|'dma'|'sha']`. It uses
one `PersistentMemory` shared by CPU and DMA, registers CPU router windows for
DMA controls and the Caliptra AHB register aperture, and configures the DMA
master window for only `CTRL@0x10 = 5`. It declares exactly
`Binding('dma','irq','cpu','irq',1)`, matching ownership, and
`irq_pulses={binding: 16}`. The function returns an unstarted fixture and the
DMA artifact's exact endpoint links for the D4 handoff. Build the DMA session
with `render_dma_linked_runtime(..., provider_id=PROVIDER_ID)` and return the
linked wrapper's `endpoint_links_document()`; an ordinary DMA artifact does
not carry the endpoint-link identity required by D4.

- [x] Write failing tests for session roles, shared memory identity, exact CPU
  windows, restricted DMA target policy, IRQ ownership/fixed-pulse settings,
  and returned linked DMA endpoint links.
- [x] Run the focused tests and verify failure is due to the missing fixture.
- [x] Implement the factory by following the existing PULP Runner assembly and
  Caliptra session construction; do not import implementation helpers from
  another test module.
- [x] Run both new scenario test files and confirm they pass: 7 passed.

### Task 3: Add native positive, fresh replay, and wrong-offset gates

**Files:**

- Create: `tests/integration/test_ibex_dma_caliptra_sha_real.py`
- Reuse: `tests/integration/test_dma_caliptra_sha256_real.py` for D3/D4
  handoff construction and Caliptra block initialization patterns
- Reuse: `tests/integration/test_ibex_dma_pulp_gpio_real.py` for bounded
  ScenarioRunner scheduling, IRQ result checks, and fresh-prefix structure

The native positive gate generates a D3 route-intent fixture pinned to the
`ibex_rvfi_local` CPU profile and requires static F6 to remain `unsupported`.
The existing Caliptra D3 fixture is pinned to `ibex_obi_local`, whose profile
fingerprint differs from the live CPU artifact required for Ibex retirement
and IRQ-take receipts; reusing it unchanged cannot pass the D4 RAM-owner
identity check. Keep the same route geometry, source word, and target policy
while recording the RVFI-pinned D3 artifact as this gate's own evidence.
Then build an Ibex fixture, prepare the `compiled_f6_runtime_path.v1`
handoff, call the D4 binder exactly once, and install route admission before
starting any native process. It writes the
padded `abc` block through the real AHB session, then runs a fixed
`('dma', 'cpu', 'sha')` component schedule until the ISR marker is terminal.
Drain and retain the host AHB setup tick samples immediately after those writes
and before the first Runner step; otherwise Runner attributes the queued setup
frames to the first scheduled component. Record each setup offset/value and
receipt as a separate prelude stream because direct AHB register writes do not
populate `sha.local_transactions`.
It joins the ordered CPU OBI DMA-register writes and their retire receipts,
DMA read/write transactions and responses, AHB phase/provider witnesses,
native DMA IRQ and actual CPU IRQ take, CPU STATUS/digest reads, and ISR result
writes. The saved digest words must equal SHA-256(`abc`).

The fresh run constructs independent memory, Runner, RVFI-pinned D3 route
intent, runtime path, D4 bind, and native processes, then consumes the exact
positive schedule and repeats the same separately captured AHB setup prelude.
Typed replay comparison may normalize only the execution identities for `cpu`,
`dma`, `sha`, and `runner`. It must use a SHA-specific
typed normalizer: Caliptra AHB access IDs embed the SHA execution UUID, while
the existing GPIO normalizer preserves those IDs literally. Normalize only
the typed execution UUID portion after validating the AHB access-ID structure;
compare raw artifact identity documents exactly before projection.

The negative run uses real Ibex firmware configured for `SHA_START_ADDRESS+4`.
It captures the native pre-backend Wishbone request and requires route refusal
before the AHB provider, no AHB side effect, no completion IRQ/ISR success,
and a retained typed transaction. All sessions must return cleanly.

- [x] Add the opt-in positive/fresh and wrong-offset tests and their precise
  evidence joins.
- [x] Run the scoped test module once without the native opt-in and confirm
  only the intended native tests are skipped.
- [x] Run the native positive/fresh gate with operation-local cache and evidence
  paths; retain compressed inputs, event streams, run receipts, and comparison.
- [x] Run the native wrong-offset gate and confirm the provider call count and
  Caliptra AHB tick/effect counts remain zero for the refused DMA write.

### Task 4: Review evidence and update project status

**Files:**

- Create: `docs/reports/ibex-caliptra-sha-dma-isr-20261021.md`
- Create: `docs/reports/evidence/ibex-caliptra-sha-dma-isr-20261021/`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/LOCAL_HARNESS_RUNTIME.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`
- Modify: this implementation plan

- [x] Record exact scoped commands, exit codes, source/artifact identities,
  run/fresh/refusal results, IRQ ordering, evidence paths, and uncovered scope.
- [x] Update the Caliptra runtime capability row without changing static F6
  support or claiming P8 completion.
- [x] Mark only verified tasks complete; leave remote validation explicitly
  open because the target is currently unreachable.
- [x] Run a scoped `git diff --check`, resolve links touched by this slice, and
  preserve all other dirty worktree state.
