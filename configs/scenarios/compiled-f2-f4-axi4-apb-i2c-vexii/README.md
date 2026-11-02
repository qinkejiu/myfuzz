# VexiiRiscv full AXI4 CPU + PULP I2C through the generic MMIO executor

This is a configuration-only F2/F4 combination. It uses the pinned
`configs/cpus/vexiiriscv` processor (full AXI4, not AXI4-Lite: separate fetch
`AR/R` and LSU `AW/W/B/AR/R`, 32-bit address/data, 1-bit ID, no
LEN/BURST/LOCK/QOS pins), the pinned `configs/peripherals/pulp_i2c` APB target
and the protocol executor `compiled_mmio` for both flows. It adds no IP
executor, no internal-state probe and no storage-version source contract.

## Why this row is now selectable

`cpu_axi4.cpu_adapter` admits `reduced_dual_axi_cpu` through
`local_harness/vexii_axi_mmio_session.GeneratedVexiiAxiMmioSession`, a subclass
of the shipped `GeneratedReducedAxiCpuSession` that adds only the three pieces
the generic executor needs and the generated session does not have:

| executor need | wrapper answer |
| --- | --- |
| constructs every CPU with `router=` | `router=` is accepted and handed to the shared session's `mmio_router=` |
| `declare_instruction_slots` / `accept_instructions` | declared slots are reserved in `PersistentMemory`; an accepted word is admitted through `MemoryService` |
| `waiting_instruction_address` (case boundary) | the accepted fetch whose declared word does not exist yet is parked and reported |

The measured single-beat AXI4 service itself is unchanged: the wrapper does not
re-implement a beat parser, a hold check, the observer or the response rules.
A fetch is accepted on the real pins first (this core offers `ARVALID` and waits
for `R`), so a word that does not exist yet is parked *after* acceptance: `R`
stays low, the same `MemoryService` read is repeated once the word arrives, and
one accepted `AR` still yields exactly one ledger entry under that AR's own
transaction key.

`reduced_dual_axi_irq_cpu`, `axi4_cpu` (ZipAXI) and `cva6_packed_axi4_cpu` remain
refused by name in `cpu_axi4.cpu_adapter`, with their own gap lists in
`AXI4_KIND_GAPS`; nothing here advertises them.

## Declared transfer

The declared transfer is a 32-bit APB word at **`0x40000000`** (1073741824),
PRESCALER offset 0. The window sits at the start of the core's own declared I/O
region: the pinned RTL was generated with exactly two address regions
(`configs/cpus/vexiiriscv/generated/manifest.json`:

`--region base=80000000,size=00100000,main=1,exe=1
--region base=40000000,size=00001000,main=0,exe=0`)

so a peripheral anywhere outside `0x40000000..0x40000FFF` is refused *inside the
core* before any AXI beat is issued (the core faults with no trap handler and
the LSU simply stops offering requests). `0x40001000` — the window several other
CPU scenarios use — is outside that map and was measured to wedge this core, so
this descriptor routes at `0x40000000`. The real `apb_i2c.sv` stores `PWDATA[15:0]` in `r_pre`,
reads `{16'h0,r_pre}` and resets it to zero, so the capability uses a 32-bit
word with read/write mask `0xffff`; `0x55`, `0xaa` and `0x1234` all fit that
mask. CTRL stays at reset zero, so no serial transfer starts and no interrupt is
requested. CMD is self-clearing, RX/STATUS are read-only; none of them is
declared as stable writable storage.

The CPU memory is one RAM resource at `0x80000000` (the pinned `reset_vector`)
of 256 KiB, read/write/execute, preloaded. It is the instruction image resource
*and* the LSU backing store, which is exactly the single-address-space layout
the reduced AXI service already implements.

`max_wait_cycles` is 16 (the wrapper's fragment-boundary park stops a case 12
advances after the first unmaterialized fetch, below that bound). `rounds` is
256 per case: one 32-byte fragment is eight single-beat fetches plus the routed
MMIO beat, its read-back and the dependent RAM store, on a core that takes two
measured ticks per fetch and one extra tick when the wrapper resumes a parked
fetch (the resumed read has to be a real edge, and its `R` one edge later, so
the executor can authenticate acceptance → read → response). A smaller budget
risks ending a case before its boundary park, which is why this scenario states
256 rather than the 128 the OBI rows use.

## Records

`generic_scenario.json` declares the corpus and `acceptance_sequence.json` the
ordered six-case smoke (three F4/F2 rounds, which is what the `--mode fresh`
comparison below uses):

| record | flow | meaning |
| --- | --- | --- |
| `00000040` | F2 | read the APB register at `0x40000000` (little-endian address) and store `value ^ 0x5a5` to the result word |
| `55000000` | F4 | write `0x55` to the register, read it back and store the same value |
| `aa000000` | F4 | write `0xaa` |
| `34120000` | F4 | write `0x1234` (catalog only; the six-case smoke repeats 0x55) |

The ordered smoke is `F4:55000000, F2:00000040` three times; every case must
reach `status=observed` with the real CPU AXI4 fetch/LSU beats, the APB
write/read completion, the actual read value `0x55` and the return-dependent RAM
store. The public MMIO result is `compiled_mmio_case.v1` with status `observed`.
Internal storage version, instruction operand origin and cross-case consumption
authority stay unknown; MMIO completion alone justifies no reward.

## Run

```sh
# original: six cases, then the within-invocation replay
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/generic_scenario.json \
  --flow mixed --mode original --case NEW_OUTPUT --cache CACHE --rounds 256 \
  --records-file configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/acceptance_sequence.json
# fresh: the same six cases in a fresh runtime, compared against the prefix
TMPDIR=/tmp/myfuzz-tmp PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/generic_scenario.json \
  --flow mixed --mode fresh --case NEW_OUTPUT --cache CACHE --rounds 256 \
  --records-file configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii/acceptance_sequence.json
```

`summary.json` reports `replay_matches`; both modes must report `true`.

### Replay normalization of the observation stream

The runner admits the reduced-AXI observation stream for any reduced-AXI session,
so every F2/F4 prefix contains `reduced_axi_*` events. Their `scope.execution_id`
is the per-launch execution nonce (a fresh UUID) and the exporter derives
`content_digest` / `observation_sha256` / `prior_operation_chain_sha256` from
envelopes that contain it. `compiled_f6._normalized_f6_prefix` therefore replaces
*only* those process-local values on `reduced_axi*` rows: the nonce itself (also
inside `wire_command`/`wire_reply` text), every `*_sha256`/`*_digest` derived from
it, while artifact/contract identity digests (`artifact_digest`,
`binding_digest`, `contract_sha256`, `source_sha256`, `profile_sha256`) keep
comparing. Every other field of the operation, its payload, `raw_sample` and the
resolved journal references is still compared field by field, so a real
difference in address, data, length, tick or record count is still detected
(`tests/integration/test_cpu_axi4.py`).

## Measured locally (original, two cases)

`--record F4:55000000 --record F2:00000040` completes both cases on the pinned
RTL: F4 reports `status=observed`, `read_value=0x55`, two routed joins and eight
authenticated instruction hops; F2 reports `read_value=0x55`,
`result_value=0x55^0x5a5`, one join and seven hops; both end with
`instruction_boundary_park.reason=fragment_end_instruction_fetch`. The remaining
replay mismatch is not a row-semantic failure: the runner admits the reduced-AXI
observation stream unconditionally and its `begin_scope` operation hashes the
per-run execution nonce, so the shared prefix normalizer must treat
`reduced_axi_source_operation.content_digest` as process-local before a `fresh`
comparison can match.

## Not declared here, and why

* **F1/F3 are not declared.** `CompiledMmioRuntime` enables the online memory
  flows by passing `memory_commit_receipts=True`,
  `memory_readback_receipts=True` and `physical_tick_samples=True` to the CPU
  session. `GeneratedVexiiAxiMmioSession` has no memory commit stream, no
  readback authority and no per-tick physical stream, so it refuses those three
  options **by name** (`ValueError: reduced AXI MMIO session does not implement
  memory_commit_receipts`, ...) instead of accepting and ignoring them. Adding
  F1/F3 therefore needs a real commit/readback stream on this session, which is
  separate work, not a descriptor change.
* **RAM size.** 256 KiB is far more than the corpus needs (16 cases of 32
  bytes) and keeps the executor's declared instruction-slot set small; every
  case's result word stays inside the region.
* **No timing/electrical model.** The PULP I2C pins `SCL/SDA` are held at 1
  (idle high) for this MMIO-only scope; no I2C transaction is synthesized.
* **Native acceptance is pending.** No run of this scenario is claimed here.
  The wrapper and the row selection are software-verified only
  (`tests/integration/test_cpu_axi4.py`, synthetic wire, no RTL and no
  Verilator build); a new original/fresh run on this configuration is the only
  thing that accepts it. Results from another CPU, another target or the
  standalone Vexii RAM smoke do not supply that run.
