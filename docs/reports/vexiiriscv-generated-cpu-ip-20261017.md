# VexiiRiscv generated CPU → PULP GPIO → CPU → RAM

The opt-in `mmio_router` on `GeneratedReducedAxiCpuSession` now queues actual
accepted LSU transfers into the generic `DataflowRouter`. Independent target
scheduling drains the queue. CPU B/R responses become available only after
that target call completes. AW/W remain independently buffered, queued writes
cannot execute twice, read data remains held until acceptance, and reset cancels
undelivered requests. Transaction keys now use the native execution UUID,
reset epoch and monotonically increasing instruction/data sequence.
No changes to the complete AXI4 session or a shared AXI helper were needed.

The directed native acceptance passed **9 tests, 1 skipped in97.42s**. The skip
is the separately enabled CPU/RAM gate. Two fresh CPU and GPIO native processes
ran the same eight-instruction RV32 program within a strict500 CPU tick bound.
Both completed in52ticks with identical CPU raw samples, GPIO raw samples,
CPU build/runtime identity and GPIO identity; native execution UUIDs differed.
The selected GPIO aperture is0x40000000/0x1000, within the generated CPU's
pinned PMA declaration. Physical accepted transfers independently show:

| Native interface | Accepted transfers |
| --- | --- |
| CPU LSU AW/W |0x4000000c /53;0x80000104 /54 |
| GPIO APB pre-edge PSEL/PENABLE/PREADY | offset12 write53; offset12 read53; PSLVERR0 |
| CPU LSU R |53 |
| CPU RAM result |0x80000104 =54 |

The router ledger's data keys1,2,3 cover MMIO write, MMIO read and RAM write.
Their execution UUID and epoch match the actual CPU session; every positive
ledger entry is complete. Target receipts retain the actual GPIO APB access
identity, source transaction and delivery context.

A third fresh native run performs the real target read and then substitutes
its returned value53 with52 while preserving its native receipt. The generic
router rejects `ordinary APB actual receipt binding mismatch` at CPU tick40.
The CPU does not accept the substituted read or issue the RAM result store;
the target read ledger entry remains `uncertain_effect`. This is an explicit
test environment wrapper, with no production CPU fault mode or fabricated CPU
beats. It demonstrates refusal of a response that disagrees with its target
receipt; it does not claim detection of every possible target failure.

Evidence files and compressed/uncompressed SHA256 pins are in
`configs/cpus/vexiiriscv/evidence/mmio-runtime-20261017.json` with four adjacent
`mmio-*-20261017.json.gz` artifacts. The independent summary recomputed physical
AXI/APB handshakes, UUID distinction, raw sample equality and ledger completion.
The CPU build digest is
`0045ba468f1091e8884b68644810b94eb6690a0caf5bc9957ecc92eed8d7b7f6`;
artifact digest is
`c3b9cf4ba00b840d61d040879127ba97492c733ac8b33d76298088fd831057d9`.

This is **frozen snapshot evidence**. The308-entry host source manifest matches
the Vexii implementation; concurrent local changes subsequently changed
`src/myfuzz/local_harness/build.py` and `src/myfuzz/scenario/runner.py`.
It therefore does not certify the final combined working tree. The durable
local snapshot, runner, summary script and recovery state are under
`.superpowers/vexii-mmio-20261017/`; the remote snapshot is
`/root/fanzehui/system-20261016/vexii-mmio-snapshot`, originals are under
`/root/fanzehui/system-20261016/evidence/vexii-mmio-20261017`, and the adjacent
`vexii-mmio-20261017.log` records the gate. It ran under the shared project
`.superpowers/heavy-worker.lock` after existing BOOM/OBI workers completed.
Trusted source verification scripts were copied into the frozen snapshot;
an initial missing-script setup failure and a PYTHONPATH setup failure produced
no acceptance evidence. Remote operations remained under `/root/fanzehui`.

```sh
bash /root/fanzehui/system-20261016/vexii-mmio-snapshot/run.sh
```

Local regression: `PYTHONPATH=src python3 -m pytest -q
 tests/local_harness/test_vexii_generated_cpu.py --tb=short` passed8 tests with
2 explicit real-gate skips in2.74s.

This closes the directed generated Vexii CPU/IP prerequisite only. It does not
establish the complete six-CPU/four-IP/DMA matrix, full P6, IRQ delivery,
continuous instruction search, same-protocol no-adaptation events, authenticated
prefix replay, or runtime protocol-consumer authority for this AXI chain.
