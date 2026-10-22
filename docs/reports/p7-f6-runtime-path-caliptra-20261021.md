# P7 post-live F6 runtime path: Caliptra bounded native result

Date: 2026-10-21
Status: Task 2 regression coverage follow-up, Task 3 software gate and bounded local native gate PASSED; independent code/evidence and final test reviews APPROVED. The final six-file software gate passed **201 tests, 0 skipped／378.04s**. Task 4 report/index/link checks are complete. Static/general F6 and overall P6/P7/P8 acceptance remain OPEN.

## Result and boundary

The local implementation prepares `compiled_f6_runtime_path.v1` from the exact
D3 static refusal, an explicit source/route pair, and live endpoint topology.
The opt-in gate passed once with a first positive run, a separate `CTRL+4`
refusal run, and an independently rebuilt fresh positive run. An independent
read-only audit approved the saved evidence joins and scope. The fresh run is
positive replay; a second refusal on the fresh Runner was not run.

Static `compiled_paths.v1` F6 remains `unsupported`, with
`dma-route-live-topology-binding-required` and null runtime identity. It has
no static `DMA_MASTER_TRANSFER` rule/edge or runtime DMA route. The separate
post-live artifact is bounded to one RAM word read and Caliptra SHA256
`CTRL=5` write; it does not make static or general F6 supported.

The design and acceptance requirements remain in the
[spec](../superpowers/specs/2026-10-21-p7-compiled-f6-runtime-path-design.md)
and [implementation plan](../superpowers/plans/2026-10-21-p7-compiled-f6-runtime-path.md).

## Reviewed local gate

The final read-only Task 3 review returned **APPROVED** for the local code
path. The retained [reviewed diff](evidence/p7-f6-runtime-path-caliptra-20261021/task3-final.diff)
has SHA256 `696de1fbf27a91285b7507e7354f272c0723b3cea892666b941fb64b9c87f47d`.
This identifies the reviewed source snapshot, not a native result artifact.

The gate declares source `cpu/ram`, image `sha_ctrl_start`, address `0x10100`,
word width 4 and byte enable 15 in the shared RAM aperture
`0x10000/0x20000`. The explicit route IDs are `route.ram-read` at edge `(0,0)`
and `route.caliptra-ctrl` at edge `(2,0)`; the selected target is Caliptra
`sha256.bus`, `CTRL@0x10`, absolute address `0x40002010`, value `5`.
These values describe the reviewed gate configuration, not observed beats.

The reviewed code requires:

- First and fresh D3 compilation, runtime artifact construction, handoff and
  D4 binding from each run's own inputs; bind count 1 and exact prepared-object
  identity are checked per run.
- Typed `TransactionKey` joins from the RAM read through its completion and
  response, and from the CTRL write through its route match, provider AHB
  receipt/effect and response; the SHA256(`abc`) known answer is asserted.
- Raw canonical D3/runtime-path/handoff/bound-wrapper identity comparison
  before a separate event-only semantic projection. Projection normalizes
  typed transaction execution IDs and validated named AHB access IDs.
- Distinct Runner/session/memory/prepared-path/handoff owners, native PIDs and
  execution IDs while first and fresh runs are both alive, outside semantic
  equality.
- An in-window `CTRL+4` request refused before provider dispatch, preserving
  only the completed RAM read. The final evidence change requires zero
  provider events and empty rejected-key memory service/ledger, DMA event,
  route-match, completion and provider-effect observations.

The evidence is local to this source snapshot and bounded gate. Earlier
[static handoff native evidence](p7-f6-compiled-dma-handoff-20261021.md)
belongs to its earlier source and acceptance scope.

## Software verification chronology

The implementer reported the focused software command:

```bash
PYTHONPATH=src pytest -q \
  tests/scenario/test_compiled_f6_runtime_path.py \
  tests/scenario/test_compiled_f6_dma_handoff.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_dma_route_admission.py \
  tests/scenario/test_caliptra_sha256_dma_paths.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py
```

Initial result: **196 passed in 338.11s**, before the last evidence-contract-only
change tightening rejected-key observations.

After that final change, the focused software command was rerun:

```bash
PYTHONPATH=src pytest -q \
  tests/scenario/test_compiled_f6_runtime_path.py \
  tests/scenario/test_compiled_f6_dma_handoff.py \
  tests/scenario/test_dma_intent_topology_binding.py \
  tests/scenario/test_dma_route_admission.py \
  tests/scenario/test_caliptra_sha256_dma_paths.py \
  tests/integration/test_p7b_p7c_dma_route_intent.py
```

Result: **196 passed, 0 skipped, 0 failed in 336.08s** (exit 0). The earlier
`py_compile` and scoped `git diff --check` also exited 0. A prior default
opt-in invocation skipped because `MYFUZZ_DMA_CALIPTRA_REAL` was unset; it is
not counted as native evidence.

After adding the remaining Task 2 regression cases, the same six-file command
was run again against the final test sources. Result: **201 passed, 0 skipped,
0 failed in 378.04s** (exit 0). The additional coverage exercises real D3
multi-mover ambiguity and a separate multi-target route refusal before graph
construction, independent write-operation and in-aperture source/address drift,
compiler-artifact JSON round-trip with
refusal before both D4 binder spies, and both compatibility APIs invoking the
single shared graph builder. These additions changed tests only; no production
source changed after the previously reviewed native run. Initial local test
construction failures came from invalid fixtures and duplicate synthetic
ports; corrected fixtures passed without reproducing a production defect.

An independent read-only review approved the final regression cases. The
multiple-mover input is rejected by D3 with `dma-route-mover-ambiguous`; the
multi-target input retains D3's general live-topology-unsupported result, then
the runtime-path compiler rejects its extra `rom0` route before graph building.
The synthetic `dma2` session map points to the existing DMA session, so this
test covers D3 mover ambiguity rather than claiming two independently running
DMA owners. In-aperture route/source drift reaches the expected route-mismatch
check; a changed Caliptra write operation is rejected earlier by D3's static
register-permission validation.

After that change, the implementer reported:

```bash
python3 -m py_compile tests/integration/test_dma_caliptra_sha256_real.py
git diff --check -- tests/integration/test_dma_caliptra_sha256_real.py
PYTHONPATH=src pytest -q tests/integration/test_dma_caliptra_sha256_real.py
```

The first two commands exited **0**. The default-disabled last command
returned **1 skipped in 0.24s** with the native opt-in unset. This preceded
the real invocation documented below and is not counted as native evidence.

## Remote readiness and local native execution

The first two SSH readiness attempts to `jumpserver` timed out after 10 seconds
(exit 255) at `166.111.80.238:2249`, before target access. The latest
read-only preflight reached `jumpserver` (0.44s), but the inner SSH to
`root@192.168.5.70` failed after 3.44s with **exit 255**, `No route to host`
for port 22. No target command ran; `/root/fanzehui`, `.copy-done`, target
project version, tools and caches remain unverified. No target file was
uploaded or changed.

Because the target route was unavailable, the bounded Caliptra gate ran locally
after a read-only feasibility check found Verilator 5.051 devel, GCC 13.3,
make 4.3, ar 2.42, Python 3.12.3, pytest 9.1.1, 5.1 GiB available RAM and
729 GiB free disk. The new attempt directory was absent before the run and
keeps its cache/evidence separate from prior files:
[`task3-local-attempt1/`](evidence/p7-f6-runtime-path-caliptra-20261021/task3-local-attempt1/).

Exact command:

```bash
PYTHONPATH=src \
MYFUZZ_DMA_CALIPTRA_REAL=1 \
MYFUZZ_DMA_CALIPTRA_CACHE=/home/qinkejiu/myfuzz/docs/reports/evidence/p7-f6-runtime-path-caliptra-20261021/task3-local-attempt1/cache \
MYFUZZ_DMA_CALIPTRA_EVIDENCE=/home/qinkejiu/myfuzz/docs/reports/evidence/p7-f6-runtime-path-caliptra-20261021/task3-local-attempt1/evidence \
python3 -m pytest -xq tests/integration/test_dma_caliptra_sha256_real.py
```

Result: **exit 0, 1 passed in 73.87s**. The attempt contains 60 evidence
files and 766 cache/build files. The integration source SHA256 is
`8b6a474ff63a2f6639e7ea2b6fc7da0159e9fbe9ed747b358efa23a1b4e838c1`.
An independent read-only evidence review returned **APPROVED** after reading
all 27 compressed evidence documents, recomputing artifact digests and
validating closed readers and transaction joins.

The first positive run and independently rebuilt fresh positive run each
recorded bind count 1 and `same_prepared_object=true`. Their canonical D3,
runtime-path, handoff and bound-wrapper documents match before event
projection; the event-only projections also match. The first/fresh Runner,
CPU/DMA/SHA sessions, memory, prepared runtime paths, runtime path, handoff and
bound wrappers are distinct objects. Both DMA and SHA native processes were
live when sampled; PIDs and execution IDs differ.

| Identity | SHA256 |
|---|---|
| D3 compiled paths | `b9881fb035fbda767c4833f45c7e42b16b78bea159a375df92f13ba58f351143` |
| `compiled_f6_runtime_path.v1` | `3136a389d9e715c91367d95e4816a8fb6684b3c6e7102d33340d53b3423a81f8` |
| `compiled_f6_dma_handoff.v1` | `6852ed1df2aa361c3f560a9d7a19a0d03b039b20e60b372a954c44375c2c066e` |
| Bound wrapper | `4815ea7369a6e126f86f08756ef8cfc96c9565a6a08c346b1fd351d3705dc3db` |

Both runs joined `route.ram-read` at `(0,0)` to the RAM read at `0x10100`
(value `5`, transaction sequence 1), then `route.caliptra-ctrl` at `(2,0)`
to the full-word write of value `5` at Caliptra `CTRL@0x10` (`0x40002010`,
transaction sequence 2). The DMA route match, typed `TransactionKey`, memory
read/completion/response, AHB request/response/effect and SHA status join.
Both digest results equal the SHA256 `abc` known answer
`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.

The separate negative run issued an observed native write to `CTRL+4`
(`0x40002014`) carrying value `5`. D4 refused it before Caliptra provider
dispatch; provider receipts/events were zero, AHB local ticks stayed `68`,
and rejected-key memory service events, ledger entry, DMA events, route
matches, completions and provider effects were absent. The completed RAM
read remains in the evidence. This gate demonstrates first positive + one
refusal + fresh positive; it does not repeat the refusal on the fresh Runner.

| Saved evidence file | SHA256 |
|---|---|
| `first-run.json.gz` | `000a30ba54e6627bd6c90a6735ab9e2405e44c151e13836ecd3d0b2ebb263562` |
| `fresh-run.json.gz` | `caa032285a2751a875d0853e6f1a1b8a5ed0137e2e087cc70f10833d2e7c1bee` |
| `native-refusal.json.gz` | `6a0f69796426721990652c335423e10a9aa3c44cb5ae482a0b618625041b8a7b` |
| `fresh-artifact-comparison.json.gz` | `6c8435aa03fa2435a45cbb1945f041ef6975a30eb9993f74dbd6170c9d0a3179` |
| `fresh-event-semantic-comparison.json.gz` | `0aea540ee8fe8d0549296f33b94a550977c2b44bcdb5fa82800c5093fae2e085` |
| `owner-distinctness.json.gz` | `342f2e631ac55021e4838b14e4616a0151aaab63edcbaac0a225aaf0e46d6660` |

Local transfer package remains available at
[`.superpowers/sdd/task3-overlay-prep-20261021/`](../../.superpowers/sdd/task3-overlay-prep-20261021/): 979 files, 10 declared directories,
4,798,776 bytes, SHA256
`0120498b86c85bff214e82c9b3de6828a48493886458fd39edde18fce8c06d16`. An
independent offline audit verified all 989 tar members (979 regular files and
10 directories), safe paths, file hash/size/mode matches, all 85 pinned
third-party files, and byte equality between the archived integration test
and reviewed worktree source. The package excludes `.git`; target-side base
project and pinned Git-object checks remain pending because target access is
unavailable. These checks are not needed to reproduce the local native run.

## Limits

This local slice concerns one transaction-level ZipCPU Wishbone DMA to
Caliptra AHB-Lite path. It does not establish a physical Wishbone-to-AHB
bridge, CPU DMA programming/consumption/retirement, completion IRQ/ISR,
multiword DMA, arbitrary F6, or P7-E acceptance. F6, P6/P7/P8 and the
six-CPU/four-IP aggregate objective remain open.
