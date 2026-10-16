# P8 directed DMA to real UART TX FIFO

## Result

The pinned Ibex process writes `0xA5` to RAM `0x22000`, enables the pinned OpenTitan UART, and programs the pinned ZipCPU wbdmac with source `0x22000`, destination `0x5000001c`, length one, and start `0x0fed0001`. The real DMA master reads the CPU-written RAM word and issues one write of `0xA5` to the UART WDATA register. An explicit DMA master window routes that accepted write to the real UART TL-UL session. The UART serial peer captures `0xA5`. The DMA's physical native interrupt drives Ibex's external IRQ input; Ibex takes the interrupt, executes its ISR, reads DMA status, and writes the branch-dependent success marker to RAM.

Two fresh CPU/DMA/UART process triples produced equal complete traces after replacing only their fresh process UUIDs. The corrected-code real gate passed both the positive chain and two target rejection controls: **3 passed in 264.00s**. The four raw traces are committed as gzip files under [`evidence/ibex-dma-uart-20261017`](evidence/ibex-dma-uart-20261017).

This is a bounded transaction-level fixture with three independent RTL processes and declared host scheduling. The DMA master write and UART serial output are observed effects of those real processes. The router is an explicit simulation address service; this result does not establish a synthesizable Ibex/ZipCPU/TileLink bus fabric.

## Source and generation identity

The final run used `/root/fanzehui/system-20261016/dma-uart-project`, an isolated source snapshot with pinned third-party source and the frozen current host files. The snapshot's seven task-relevant host files matched the local tree byte for byte at launch; SHA256 values are in remote `evidence/dma-uart-final-source-files.sha256`. This seven-file list records the task's edited/frozen host files, not the full repository or build-input closure. The full captured build inputs and source lock are inside the raw identity documents. Later concurrent changes to unrelated host files were outside this snapshot.

Each raw trace embeds the full generated artifact, build inputs, host sources, Verilator argv/toolchain identity, and source lock. The three final build digests are:

| Real process | Build digest | Artifact digest |
| --- | --- | --- |
| Ibex | `575eb88408969edf3a56da225b3f8b36828c628231dfca4e73d892d66faf7dd0` | `377fe57b8f70b090517994b472ecdb5a11411807aafea0706a18781267f5ebd7` |
| wbdmac | `ed451992da748efb4b490bd4098a22329de9128e7e06ec1e7ffdaafc5d41ebab` | `bf4e47346c890aec2b35c8588152002ecc2489ec2b8cabaf5762f7350ca4022c` |
| UART | `391013bdb222b2657d03647a2d09216500aa33d38edcda4a5661c5bfbf58c3c1` | `0d493963cfaf4e0545324e8e8e222562e940c94bed490aa600d582f59087c0e8` |

The remote gate used Verilator 5.051 and the shared heavy lock `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`. Its exact invocation was:

```sh
cd /root/fanzehui/system-20261016/dma-uart-project
exec 9>/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
flock -x 9
export PATH=/root/fanzehui/system-20261016/tools/verilator-5.051/bin:$PATH
export VERILATOR_ROOT=/root/fanzehui/system-20261016/tools/verilator-5.051/share/verilator
export MYFUZZ_DMA_UART_REAL=1
export MYFUZZ_DMA_UART_CACHE=/root/fanzehui/system-20261016/cache/dma-uart-real
export MYFUZZ_DMA_UART_EVIDENCE=/root/fanzehui/system-20261016/evidence/dma-uart-real
export PYTHONPATH=/root/fanzehui/system-20261016/dma-uart-project/src:/root/fanzehui/system-20261016/pythonlib
timeout 900 python3 -m pytest -xq tests/integration/test_ibex_dma_uart_fifo_real.py \
  > /root/fanzehui/system-20261016/evidence/dma-uart-real.log 2>&1
```

## Measured positive chain

- CPU RAM event writes `0xA5` to `0x22000`. CPU accepted MMIO deliveries write UART CTRL `0x80000003`, then DMA source/destination/length/start. There is no host call that starts DMA or writes WDATA.
- DMA master accepts exactly two beats: RAM read `0x22000` and UART write `0x5000001c`, WDATA `0xA5`, BE `15`. The RAM read response ACK occurs at DMA edge 71. The UART write's target receipt spans UART ticks 61–65, and its DMA response ACK occurs at edge 75. Both have ERR=0. No DMA RAM commit is made at the UART address.
- The UART serial peer captures `[0xA5]`. The physical DMA native IRQ pulses at edge 75. The scheduler passes that pulse to Ibex; actual external IRQ take is CPU tick 60. The ISR stores `mcause=0x8000000b`, real DMA offset-0 readback `0`, then success `1`. The UART TX capture is an external observation; the CPU success marker checks the DMA interrupt and its own status read, without reading back UART serial output.
- A one-word wbdmac transfer's offset-0 readback is `0`: idle=0, error=0, `nread=0`, and `blocklen_sub_one=0` in the pinned RTL's concatenation. The older four-word RAM chain reads `3` because its block-length-minus-one field is 3. The final ISR compares against the one-word value and preserves the actual CPU-visible word in RAM.
- Both fresh valid traces have 385 declared scheduler iterations, 405 measured DMA edges, and 393 UART tick samples. Full normalized traces match, including CPU physical/retirement/IRQ observations, DMA bus edges, memory events, router deliveries, UART events, serial samples, and order.

## Negative controls

The CPU still writes the source RAM and configures real DMA in each control. For destination `0x50000020`, the real DMA master issues the write but the declared target window rejects that register offset. For source word `0x1ff`, the real DMA master issues the WDATA write but the target window rejects the value outside the UART's 8-bit WDATA field. The host service returns Wishbone `mwb_err=1` at DMA edge 75; the real DMA consumes that response and produces its native interrupt pulse. Neither case calls the UART target write, commits a DMA RAM write at the target address, or produces serial TX. These controls stop after the error response, before a CPU error ISR result is observed. The ERR is an environment response, not an error generated by the UART DUT.

## Raw evidence

The remote complete evidence directory is `/root/fanzehui/system-20261016/evidence/dma-uart-real`; the committed compressed copies have these SHA256 values:

| Trace | Raw JSON SHA256 | Compressed SHA256 |
| --- | --- | --- |
| `valid-0` | `286be79411d57b2fa22f5c5e063ed9963f97c03bb30a91fe24593166cde24e1f` | `92eadcd2507857e4925f31814ed54d238e88a3e39a98c1d881bbda166a8969b8` |
| `valid-1` | `41753ad8a833f03feee86560ec49977ee9309af32abf05d5bd2dc40ee8920ebe` | `a7b1e40a50787a7db63f0838502c5265f31699e471324eae80e7b9b916b7587b` |
| `invalid-a5-50000020-0` | `460143314b17724004f1b61ce374c5b3c5e12b6903be298f52c65b2041a82170` | `248e1c06d888ab541082e63cdce4f4f19fca6663a2444c2584f4af1a1ee83eef` |
| `invalid-1ff-5000001c-0` | `144ad4ebf75875c85fcfe6be8a7dd0996b03bd08e1587c46ed63ef3fbde95ec5` | `e6e57baeaab46ce2320854e5bfe6db787f9cedda2885f73f167dfccf72171037` |

Final log: `/root/fanzehui/system-20261016/evidence/dma-uart-real.log`, SHA256 `e0ab1a88670d04a7bec27ec7b68d02ccd5bf9e68535dcab9e3649fce81f0b8de`, exit file `0`. The seven-file source manifest SHA256 is `80a8b3941addcaf1436ef14fe67e6ff0b0203248ea25b54016d1fcee790f64fb`; both are committed with the traces.

Earlier failed attempts remain separately: `dma-uart-blocklen4.log` (SHA256 `1c4a5def...`) shows the initial length-4 start command stalled after one read; `dma-uart-status3.log` (SHA256 `44e460eb...`) shows the real one-word transfer and serial TX with an incorrect ISR expectation of status 3. Their traces are under the remote evidence tree and do not count as successful runs.

The first passing gate exposed a DMA session return-value error on its target path: it returned the target delivery summary in place of the native `STEP_WB_DMA` command receipt. The code now preserves the native receipt, and a focused software contract test asserts the exact returned object, status, pre-backend payload, and one new tick. That earlier passing gate is retained as `dma-uart-pre-return-fix.*` for audit; the final hashes above refer to the corrected-code rerun. Local focused session/firmware checks: `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_wishbone_dma_session.py tests/scenario/test_ibex_dma_example.py` → **6 passed, 1 skipped** (the independent real DMA unit gate requires its own opt-in environment variable).

## P8 boundary

This proves one directed RAM-to-IP TX FIFO path and native completion ISR. P8 still needs IP FIFO-to-RAM transfer, sustained testcase search, a generic Runner/Router/ledger source chain, and authenticated-prefix replay. Multi-beat DMA-to-IP behavior, other UART register accesses, arbitration, error ISR behavior, and a shared hardware bus fabric are also outside this evidence.
