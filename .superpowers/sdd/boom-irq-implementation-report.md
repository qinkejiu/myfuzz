# BOOM opt-in IRQ source implementation — 2026-10-17

## Scope and status

Source preparation only. No IRQ native build, simulator launch, remote job or
heavy lock acquisition occurred. Previous GPIO and cached coherent native
passes belong to their frozen baseline artifacts, not this variant. Generic
Runner and F4/DMA files were not edited. This work does not complete P6/F5.

The approved design is `.superpowers/sdd/boom-irq-next-design.md` (1f406b9).
Independent review correction is implemented: aggregate CSR `insn_ret` does not
prove MRET; actual command4/address0x302/return must coincide. SRET0x102 and
DRET0x7b2 controls reject.

## Implemented source

- Independent `configs/cpus/boom_irq` profile/interface: exact baseline delta,
  preserves all39 coherent fields and original four RTL source pins/47 ports;
  releases only physical MEIP `auto_int_local_in_2_0` into the second endpoint.
- New generation, C++ driver, Python session and read-only VPI helper. Probes are
  explicit source-derived candidate paths, not confirmed generated symbols.
  Actual build queries each VPI handle's full name/size, records the inventory
  and generated Syms source, and refuses missing/wrong probes without fallback.
  The runtime rechecks source/profile/manager/driver/session/auxiliary closure,
  descriptor crosslink and actual startup inventory. Executable hash is local
  build integrity evidence, not signed provenance.
- Independent standard Runner adapter preserves queued A→GPIO→deferred D and
  transaction execution/epoch identity, coherent checker aborts, reset barrier,
  teardown cancellation and bounded one-edge stepping. Actual pre/post passive
  values are journaled observation-only; exact MRET decode is not retirement
  authority.
- New real PULP GPIO factory uses generic `Binding`, `IrqPulseDelivery(64)` and
  DataflowRouter without component-name changes to Runner. Only pin0 is source
  owned; MEIP is binding owned. The real IRQ source edge starts fixed64 CPU
  ticks, never predicted/extended based on ISR; overrun is unsupported.
- Static RV64 image initializes machine CSRs and real GPIO, zero-extends mtvec
  address, waits in foreground while ISR reads actual mcause/mepc/status twice,
  stores results and returns through MRET. MEIE is disabled in ISR to prevent
  retrapping from the remaining declared pulse. Foreground writes its own
  resumed marker. Expected handler results are never preloaded.

## Software verification

Initial eight contract tests failed with missing module, then passed after
implementation. Two added tests failed (boolean probe width accepted; firmware
module absent), then passed after strict width checking and firmware creation.
Final command:

`PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_boom_irq_contracts.py tests/local_harness/test_boom_session_regressions.py`

Actual exit0: **31 passed in11.05s**. IRQ-only final run before this combined
run:15 passed0.40s. The source-generation regression mocks only
`subprocess.check_output` for the Verilator version query; no compilation or
native execution is performed. It authenticates current real source/physical
port metadata and verifies distinct profile identity and required auxiliary
closure. Tests cover exact second endpoint/bus retention, bad irq input before
transport, names/widths/duplicate probes, SRET/DRET rejection, stale epoch and
duplicate D refusal, fixed64 pulse/reset/overrun, static firmware structure and
profile parsing. They do not establish execution of any ISR.

## Prepared build and remaining gate

`.superpowers/boom-irq-verification-20261017/build.sh` and `source-pins.json`
are source-only preparation; not copied/launched remotely. Parent must allocate
an exact heavy window and arrange an independent complete snapshot under
`/root/fanzehui`. Script uses prescribed environment and canonical nonblocking
lock. Builder requires new/empty output and writes actual
`build.exit`, `probe-describe.exit`, stdout/stderr. Its first real build may
reject a generated scope/name/width or Verilator configuration: resolve using
actual generated registry/source, never guessed members or constant values.

Remaining acceptance work: actual build/probe confirmation; full fresh measured
prefixes with raw identities retained; actual physical GPIO edge→MEIP→ROB trap→
CSR cause/mepc→ISR status1/clear0→exact MRET→actual return PC/foreground resumed;
normal coherent checker; missing IRQ, changed status, SRET/DRET and reset/epoch
controls rejected. No IRQ gate result or runtime admission is claimed. Native
verification harness and detailed negative runtime controls still need assembly
when the new generated probe contract has been confirmed.

## Review correction: historical output preservation

Independent source review identified that d326c5c only rejected the persistent
`session-artifact.json` marker; one-shot `artifact.json`, existing IRQ artifacts
and other historical contents could still be overwritten by generation.

The builder now rejects every nonempty output directory, ordinary file and
directory symlink before resolving the output or opening a lock. It checks
again under the canonical lock, and refuses a lock path inside the output.
No cleanup, overwrite, or reuse is attempted. New or empty directories remain
allowed. This changes new IRQ source identity only; baseline BOOM files remain
unchanged. Prepared source pins were regenerated, so d326c5c pins are superseded.

Six precise filesystem tests initially failed, then passed after the fix.
Native/build and generation entry points are instrumented to fail if reached
for invalid outputs. Missing lock parents prove rejection occurs before lock
opening; historical bytes remain unchanged. Additional tests confirm new/empty
directories reach only mocked generation and that content appearing at lock
acquisition is rejected. No actual native/build or canonical lock was used.

Final combined software command above: actual exit0, **40 passed in10.93s**.
Independent reviewer inspected the correction and reported no new substantive
issue before the final freeze. Native IRQ acceptance remains unverified.
