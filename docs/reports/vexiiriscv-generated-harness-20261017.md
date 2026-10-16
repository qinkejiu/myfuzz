# VexiiRiscv generated dual AXI RAM harness — 2026-10-17

## Scope

This slice implements the repository's structural → runtime → native driver →
local Session pipeline for the pinned generated VexiiRiscv.v. It does not use
the direct C++ smoke bench as generated-harness evidence. There are 48 physical
ports: LSU29, fetch13, privileged4, clock/reset2; 42 actual AXI backend ports.
Fetch has only AR/R. Both endpoints omit LEN/BURST/LOCK/QOS. Their single-beat
semantics require explicit capabilities and exact shapes; the complete AXI4
contract remains intact. The source/profile/manifest/port inventory are pinned
independently of runtime acceptance.

The RAM session advances one actual measured edge per step, buffers AW/W
independently, returns the accepted ID, preserves R/B response state while
stalled, and cancels pending local state on reset. Quiesce permits the matching
half of an already accepted AW or W to drain. Oversize/misaligned accesses,
missing WLAST and strobes outside addressed lanes refuse. IRQ/rdtime remain
fixed0. CACHE/PROT metadata are not modeled as memory protection/cache state.

## Acceptance

The generated driver executes this actual CPU program from reset 0x80000000:
store53 at0x80000100, load it through LSU, add1, store54 at0x80000104, then loop.
The gate checks actual accepted AW addresses, WDATA/WSTRB/WLAST, LSU AR/R,
instruction fetches, RAM bytes and both completed B handshakes independently
of the service's counters. A test-only RAM read substitution returns0 for the
LSU load and must change the second store to1. Production session code has no
fault mode. Two fresh native processes compare complete raw physical samples
and runtime/build identities while requiring different execution IDs.

The first frozen snapshot run passed2 tests in57.72s. Its host-source identity
subsequently differed in generated_execution_admission.py due to parallel P6
work, so it is not current-HEAD evidence. A final run after P6 freeze and the
AW/W quiesce correction passed **9 tests in52.75s**. Each native process
completed55 measured steps,11 accepted fetch addresses,1 LSU read and2 B
responses. Normal stores were53 and54; the read substitution changed the
second store to1. Fresh samples and complete identities matched; execution IDs
differed. All304 recorded host-source SHA256 values matched the current local
tree after the final run (zero stale files).

```sh
cd /root/fanzehui/system-20261016/project
. /root/fanzehui/system-20261016/environment.sh
flock -n /root/fanzehui/system-20261016/heavy-worker.lock env \
 MYFUZZ_VEXII_REAL=1 \
 MYFUZZ_VEXII_CACHE=/root/fanzehui/system-20261016/cache/vexii-generated \
 MYFUZZ_VEXII_EVIDENCE=/root/fanzehui/system-20261016/evidence/vexii-generated-current-20261017 \
 python3 -m pytest -q tests/local_harness/test_vexii_generated_cpu.py --tb=short
```

Raw final artifact/first/fresh/fault JSON is committed as deterministic gzip
under `configs/cpus/vexiiriscv/evidence/`; `runtime-20261017.json` pins compressed
and uncompressed hashes and independently recomputed results. Remote originals
remain under `/root/fanzehui/system-20261016/evidence/vexii-generated-current-20261017/`
and the adjacent `.log`. The final build digest is
`9a0b8084724e6e83f546aa1dc9399a4b76a0dc4a512fbd70032685a894ca70fb`;
artifact digest is
`5a0f1ed438dd5da9a6350c38ab34f2d8b6ee25c96756528c249287f33f17f241`.
Future host changes require new current-source execution evidence.

## Local regression and limits

Focused reduced-shape/admission, independent AW/W plus quiesce, response hold,
invalid transfer, template registry and native parser regression: **47 passed,
1 skipped, 12 subtests passed in4.40s**. The skip is the separately enabled
remote real gate. The existing full AXI CPU tests also passed during the initial
combined run; that run had one stale inventory assertion (20 versus22), fixed
and rerun in the focused regression above.

The accepted level is scoped generated CPU/RAM directed RTL operation. No
MMIO/IP chain, IRQ delivery, bursts/exclusives/atomics, online testcase mutation,
protocol evidence consumer/coverage, authenticated prefix replay or performance
acceptance is inferred. The fresh test repeats a directed case, not a saved
scenario evidence bundle. Independent CPU reset/power experiments are pending.
