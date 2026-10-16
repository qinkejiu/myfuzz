# Standard Runner native UART RX → DMA → RAM → CPU ISR

The directed native acceptance passed: **1 passed in 80.79s**, with the corrected synchronous CPU MMIO downstream tick bound present in the frozen Runner source. This demonstrates the deferred routing factory and its directed schedule; it does not establish full P8 completion or compiled F4 execution.

## Implementation and causal path

`make_ibex_dma_uart_rx_runner` assembles actual CPU, DMA and UART sessions, shared persistent RAM, deferred CPU MMIO routing, UART serial input ownership and a DMA IRQ binding. DMA master reads are restricted to the UART RDATA window. The scenario DMA session declares bounded indirect UART ticks, including control edges. Runner validates target instance identity and rejects aliases, reserves these indirect ticks, and includes downstream declarations when a synchronous CPU MMIO access can clock DMA. The regression also checks the existing shared-router restriction.

The source byte is **0x5a**. Serial waveform injection enters the native UART RX FIFO; DMA reads **0x50000018**, with an actual native FIFO read/pop capture, and its accepted master write puts the value in RAM at **0x23000**. The native bound interrupt is taken by CPU; the program executes its ISR and publishes success. The test checks destination data, external interrupt mcause **0x8000000b**, the DMA memory write and the native UART read capture. It never seeds a DMA result or fabricates FIFO return data.

## Evidence and source correspondence

Evidence is in [the archived gate log](evidence/dma-rx-runner-20261017/gate.log), [initial journal](evidence/dma-rx-runner-20261017/rx-runner.json.gz), [fresh journal](evidence/dma-rx-runner-20261017/rx-fresh.json.gz), [task source pins](evidence/dma-rx-runner-20261017/task-source-files.sha256) and [frozen host manifest](evidence/dma-rx-runner-20261017/frozen-host-sources.json.gz).

Both journals contain **4,836 events**, **1,097 scheduled steps**, and final ticks **CPU 84 / DMA 104 / UART 937**. Every DMA and UART tick has a raw local sample. The fresh run reconstructs all three native sessions, requires new native execution identifiers, checks identical identity documents and compares the complete event journals after replacing only the three declared native execution UUIDs and Runner UUID. Read-only archive inspection independently confirms complete equality; only one execution UUID is actually serialized differently in these journals.

All four task-source SHA256 pins match the final files: Runner, DMA scenario session, factory and real integration test. The 415-file frozen host manifest matches current files except `src/myfuzz/integration/compiled_f4.py`, concurrently owned by the separate F4 task. That file is outside this RX factory's execution path; this report grants it no acceptance. The manifest records the original frozen bytes' hashes, not copies of the complete source tree.

The final gate supersedes the archived **82.42s** pre-bound-fix gate for source correspondence. Earlier single-run and pre-bound-fix logs remain historical evidence only. The owner supplied focused regression result was **57 passed / 4 subtests passed**; no raw focused log is included here, so this is reported separately from the archived native acceptance. No heavy gate was repeated during finalization.

## Limits

This acceptance covers one byte, this concrete CPU/DMA/UART configuration, the recorded schedule, actual FIFO reception and transfer, native IRQ/ISR, and fresh journal equality. Generic recursive device graphs, arbitrary peripheral compositions, arbitrary UART traffic and full P8 remain outside the claim. The positive synchronous downstream bound is covered by a focused declarative regression, while the native factory uses deferred CPU MMIO.
