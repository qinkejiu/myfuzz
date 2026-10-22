# VexiiRiscv CPU → PULP GPIO APB3 → real external IRQ → ISR → RAM

This chain closes the specific gap left by the previous Vexii evidence: the
pinned baseline profile held the core's real `int_m_external` input at constant
zero, so a CPU→IP chain could not also carry an interrupt, and there was no
fixed-instance row or cross-process replay for an interrupt path. The baseline
profile, its closure and its earlier CPU/RAM and CPU→GPIO evidence are
untouched; a derived, exactly validated profile adds the interrupt entry over
the *same* generated RTL bytes.

Source commits: `f454962` (implementation) and `ad4eb9e` (gate-test key fix).
The evidence was produced from a detached worktree snapshot of `ad4eb9e` under
`flock -w 14400 .superpowers/heavy-worker.lock`; other agents' uncommitted
changes were excluded from that snapshot.

## What is actually connected

| Stage | Real artifact | How the chain uses it |
| --- | --- | --- |
| CPU | pinned generated `VexiiRiscv.v` (sha256 source revision `5e73d052…`), 48 physical ports, reduced single-beat AXI4 fetch AR/R and LSU AW/W/B/AR/R | real instruction fetches and real LSU loads/stores |
| CPU profile | `configs/cpus/vexiiriscv_irq` — the authenticated baseline plus one exact declared delta | removes the `constant 0` action for `PrivilegedPlugin_logic_harts_0_int_m_external`, declares it `processor.interrupts` / `machine_external` / `active_high`; `rdtime`, machine-timer and machine-software inputs stay constant 0 exactly as the baseline says |
| AXI4→APB3 | the repository's transaction-level `DataflowRouter` (accepted single-beat LSU transfer → one APB3 access, ordinary APB actual receipts) | no AXI4-to-APB RTL bridge exists in this chain and the router is not bypassed; the conversion is the router's truthful transaction adapter, one target window `0x40000000`/`0x1000` |
| Target IP | pinned PULP `apb_gpio` (git `f82caeb7…`), real register file, real synchronized GPIO input sampling and real `interrupt` pulse | APB offsets 4/12/16/20/24/28/36 only, all declared by the profile address map |
| IRQ wire | host-side declared pulse-to-level adapter | set on the GPIO's actual `interrupt` pulse as observed on a GPIO edge; dropped only after the ISR's actual `PADOUTCLR` APB delivery and a GPIO edge observing `gpio_out[0] == 0` |
| CPU IRQ entry | the core's real `int_m_external` pin | the core samples it, takes its own trap, and fetches the vector the program installed |
| ISR | real RV32I instructions at `0x80000200` | real APB reads of `PADOUT` and `INTSTATUS`, real APB write of `PADOUTCLR`, real RAM stores, `mret` |
| Result | real CPU stores into `PersistentMemory` | the host reads back only words the CPU wrote (`result`, `status`, `check`, `done`) |

Per round the CPU writes `PADOUTSET`; the GPIO input is the declared loopback of
its own real `gpio_out` output, so the GPIO's real synchronizer and edge logic
produce the real `interrupt` pulse. The host converts that transition pulse to
the level the core requires and never injects a trap, cause or vector. The ISR
reads the GPIO's readback register (`PADOUT`) and its latched status
(`INTSTATUS`, read-clears), writes `PADOUTCLR`, stores both observations and a
completion flag to RAM, then returns with `mret`; the main program reads the ISR
result from RAM, XORs it with the value it wrote, stores the zero check, and
advances to the next case. The two RTL processes advance on their own real
clocks: one host round is one CPU edge, then any APB transaction the CPU
accepted, then one GPIO edge. Component ticks are never presented as one shared
cycle.

The derived profile is validated byte-for-byte as the exact baseline delta by
`vexii_irq_contract.py`, which re-authenticates the baseline closure (generated
RTL revision, manifest, lint/generation evidence) first. There is no second
source selector, so this variant cannot diverge from its baseline pin.

## Measured acceptance

Two independent operating-system processes ran the same 8-case row, each with
one native CPU process and one native GPIO process:

* CPU ticks 1,567; GPIO ticks 1,711; 8 IRQ rises and 8 falls; 8 `mtvec` vector
  fetches at `0x80000200`; 36 APB deliveries (4 one-time program configuration
  writes + 8 cases × 4 accesses).
* Every case's per-round record contains exactly one `PADOUTSET` write with the
  driven value, one `PADOUT` read equal to that value, one `INTSTATUS` read with
  bit 0 set, and one `PADOUTCLR` write of `0xffffffff`.
* RAM, read only from words the CPU wrote:
  `result = [17, 35, 51, 91, 165, 291, 1023, 127]` (exactly the case values
  with pad 0 forced set), `status = [1]*8`, `check = [0]*8`, `done = 0x600d`.
* Both runs produced identical raw CPU samples (1,567 edges) and identical raw
  GPIO samples (1,711 ticks), identical artifact/build identities and identical
  per-case evidence; the native execution UUIDs differ
  (`5b849cb6…`/`1be5e0d7…` CPU, `75464baf…`/`e095531b…` GPIO). All 77 row
  checks are `ok` in both runs, and the fresh-replay comparison is `matches:
  true`.
* Evidence identity: CPU runtime artifact digest
  `ee91caefef7c253ff7d733c8cfa31705670b4eea5ab336337fd829a0c7acc778`, GPIO
  runtime artifact digest
  `ac5c4224c6d88ac1777de81515eea022bbb1de019d33036bf1ccaf9fa0afeb8f`, CPU
  harness binary sha256
  `d9a986e6a3e134e3937ed66f0443182f9af86220285b6008082a0d2fce267aa8`, GPIO
  harness binary sha256
  `1fb4696cb2b5849cda3eb53b6be2bb373f22626c8b220d22f8156222a781c5ff`, program
  image sha256
  `e4fb014dbfcae1920261bec4ffb078b4340c8a33d3d0cc6274fc784632a69c86` (4,384
  bytes; 52 main words, 21 ISR words).

Evidence files (under `docs/reports/evidence/vexi-irq-fixed-20261018/`):

| File | SHA-256 |
| --- | --- |
| `first.json.gz` | `05363adb0260d68de452e6ef0917937441f6ecdc5a559d80c5f46d713b6b78a7` |
| `fresh.json.gz` | `71aca53ab76ae51c3adcc93c1722b1bc99f04f72dd700b1cbe7e89f7e32ef53f` |
| `summary.json` | `83ec540efee075f9b2278c81bc5986b1002f4ea41f8092300133c8ad3f787948` |
| `gate.log` | `ea8539be6cde745aa17b726d9ca5ffbeee7e444d863e94a8060463814312d34f` |

`summary.json` also pins the uncompressed SHA-256 and byte length of each
document (`first`: `ff6b49ce…`, 6,598,806 bytes; `fresh`: `0eaffe7c…`,
6,598,805 bytes), so the compressed files can be verified after decompression.
The two documents differ by one measurement byte (wall time/pid), not in any
evidence field.

Test gates run on the same snapshot:

* `MYFUZZ_VEXII_IRQ_REAL=1` real gate in
  `tests/scenario/test_vexii_pulp_gpio_fixed.py`, which itself spawns the
  two-process script: **36 passed, 2 skipped in 31.42 s** for the combined
  focused selection.
* Official evidence command:
  `python3 scripts/run_vexiiriscv_irq_fixed_row.py --base-dir <snapshot> --output docs/reports/evidence/vexi-irq-fixed-20261018`
  under the shared heavy-worker lock: exit 0, `status: verified`,
  `replay.matches: true`.
* Pure selection (previous commit, same code):
  `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_vexii_generated_cpu.py tests/local_harness/test_vexii_irq_contracts.py tests/scenario/test_vexii_pulp_gpio_fixed.py tests/local_harness/test_driver_protocol.py tests/local_harness/test_template_contracts.py tests/local_harness/test_runtime_template_identity.py tests/local_harness/test_source_lock.py tests/local_harness/test_generated_session_registration.py`
  → **98 passed, 3 skipped, 64 subtests passed**.
* Declaration review: both `vexiiriscv` and `vexiiriscv_irq` pass 9/9 checks
  (`scripts/review_component_declarations.py`).

## What this is not

* **Not P6.** This is the largest real fixed-instance chain available in this
  change, not the P6 campaign framework. The program image is fixed per row and
  case data comes from a preloaded RAM table; there is no online genome
  mutation, coverage-guided case selection, cross-case arbitrary harness reuse,
  saved-failure reproduction or the P5/P6 authenticated prefix-replay
  certificate machinery. The fresh replay here compares a 16-key stable
  projection plus raw CPU/GPIO samples, not whole-document equality modulo run
  identity (measurement/PID/wall/implementation/error/profile_paths/schema are
  not compared), and is weaker than an authenticated prefix replay.
* **No interrupt-controller RTL.** The pulse-to-level wire and the GPIO
  `gpio_out → gpio_in` loopback are declared host composition wires, not RTL.
  The loopback uses the previous edge's `gpio_out` (one-edge delay), which the
  shorter report wording omits.
  There is no PLIC/CLINT/SoC IRQ controller, no masking, priority, claim or
  wakeup path, and no multi-source arbitration. The GPIO `interrupt` output is a
  transition pulse, not a held pending bit; the level is held by the host until
  the ISR's real `PADOUTCLR` delivery, which is a declared adapter semantic, not
  an RTL ack.
* **One target IP, one direction pair.** The router still has one APB target;
  there is no second IP, DMA, arbiter, bus bridge or multi-device composition,
  and the IP never becomes a bus master. The AXI4→APB3 conversion is the
  transaction-level router, not an RTL adapter with its own protocol state.
* **Two processes, not one SoC top.** CPU and GPIO are independent Verilator
  processes stepped by the host, so the evidence has per-component ticks and no
  single cycle-accurate combined timing, cross-domain clock ratio or integrated
  reset topology.
* **One fixed Vexii configuration.** Only the pinned cacheless reduced
  single-beat AXI4 configuration is exercised; no other Vexii parameters,
  protocols (for example TileLink), caches or burst modes are claimed.
* **No protocol-consumer authority.** The `PADOUT`/`INTSTATUS` values are real
  GPIO RTL responses carried through the real APB handshakes and the router's
  actual receipts, but this row does not add a generic protocol event/coverage
  consumer or runtime protocol authority for the AXI chain.

The exact pieces a full P6 fixed-instance row would still need: the P6 campaign
driver and persistent harness/genome path, online case selection with coverage
targets, arbitrary per-case program-image admission under the instruction-slot
policy, the P5/P6 authenticated prefix replay certificates, a real interrupt
controller (or a declared RTL level-latch target) with claim/mask semantics, and
a second real target or direction to exercise arbitration.

## Reproduce

```sh
# pure tests
PYTHONPATH=src python3 -m pytest -q \
  tests/local_harness/test_vexii_irq_contracts.py \
  tests/scenario/test_vexii_pulp_gpio_fixed.py

# real gate (two fresh OS processes; builds from the identity-keyed cache)
MYFUZZ_VEXII_IRQ_REAL=1 PYTHONPATH=src \
  python3 -m pytest -q tests/scenario/test_vexii_pulp_gpio_fixed.py

# publish evidence
PYTHONPATH=src python3 scripts/run_vexiiriscv_irq_fixed_row.py \
  --output docs/reports/evidence/vexi-irq-fixed-20261018
```

The gate logs the full child stdout/stderr in `summary.json` and the combined
pytest+gate output in `gate.log`. A failing child produces a failed summary, not
a partial pass.
