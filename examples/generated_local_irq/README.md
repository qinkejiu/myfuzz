# Generated CVE2 and two PULP GPIO: persistent bidirectional IRQ

Run from a checkout containing the pinned CVE2 and PULP GPIO source trees:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_scenario_cve2_two_pulp_gpio_irq_real -v
```

Requires Verilator, a C++ toolchain, and clang/lld with RV32 support. The test
compiles `bidirectional.S` using `link.ld`, builds all three generated local
harnesses through the authenticated builder, and starts new real RTL processes
for both recording and replay. The firmware bytes are part of the genome;
source locks, runtime artifacts and host source bytes participate in replay
identity. No handwritten CPU/GPIO harness or mock peripheral is used.

## Ownership and persistent state

| Endpoint | Owner |
| --- | --- |
| A GPIO input | fixed zero |
| A output bits 7:0 → B input bits 7:0 | binding |
| B input bits 15:8 | external source actions |
| B input bits 31:16 | fixed zero |
| B native interrupt → CPU external interrupt | binding, explicit four-CPU-tick pulse delivery |

A occupies `0x40001000`; B occupies `0x40000000`. Boot/vector firmware lives at
`0x10000`; persistent RAM starts at `0x20000`. CPU firmware performs all GPIO
configuration and MMIO. No resets or image reloads occur within the testcase.
Each bank has seven payload bits and its highest bit is a rising-edge strobe.

The CPU emits payloads 1 and 2 on A's low bank. The real binding propagates each
into B's low bank; B produces a native rising IRQ. Then causal external source
actions emit payloads 3 and 4 on B's high bank. Each actual ISR reads B.PADIN and
B.INTSTATUS, adds the selected payload to the shared RAM accumulator (initial
5), and writes the result onto A's high bank. RAM logs status, PADIN and the
accumulated result for each ISR: results must be `6, 8, 11, 15` and status must
be `0x80, 0x80, 0x8000, 0x8000`.

PULP `INTTYPE` at `0x1c` packs **two bits per pad** for pads 0–15; rising types
for pads 7 and 15 require `0x40004000`. `0x20` configures pads 16–31. INTEN is
`0x8080`; GPIOEN is `0xffff`. These are facts from the admitted RTL's register
write cases. INTSTATUS is read-clear; the IRQ remains the native edge pulse.

The first external edge waits 40 CPU ticks after observing A's result 8;
that output is written before the ISR returns. The external second edge waits
80 CPU ticks after result 11; the bank is explicitly lowered first. This
schedule avoids delivering a short pulse while the preceding ISR is running.
Neither the runner nor the test infers an interrupt mask state.

The test checks every native pulse against a real GPIO tick sample, every
four-tick CPU delivery, four real `rvfi_valid && rvfi_intr` observations at
`0x1012c` (CVE2 external vector slot 11), four MMIO status reads, RAM history,
and final A output `0x0f82`. Fresh replay must match the entire event stream,
component ticks and final state. The schedule has 1,860 component steps
(620 CPU ticks); it retains all native receipts.

## Evidence and resource admission

The integration uses `save_evidence_bundle` / `replay_evidence_bundle`, checks
published images/index/result/final-state material through the replay API, and
validates a `scenario_runtime_manifest.v1` document against the published JSON
Schema. The reset declarations come from each actual generated artifact.

The first unbudgeted verification on `300d349` passed both tests in 101.865
seconds. The compiled firmware SHA-256 was
`99daa25de1fb0335007ad9f7f2b89a1608da9fa6522aec2bcc4e748f7099cac0`.

The integration now publishes with `ResourceBudget(max_wall_time_ms=180000,
max_materialized_bytes_per_memory=0x20000)`. The memory cap matches the
fixture's declared persistent RAM service cap; the default 64 KiB cap correctly
rejects that fixture before RTL starts. A separate budgeted real RTL run
completed with 8,924 events and fresh replay matched. The generated-session
per-operation evidence bounds derive from the generated driver's reply
reservation, with additional room for host transaction identities and state.
