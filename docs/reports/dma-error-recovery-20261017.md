# DMA environment ERR followed by a valid transfer

A rejected master request now completes an explicit no-target-effect entry in the same DMA TransactionLedger as successful RAM and IP requests. Previously the session incremented its source sequence without enrolling ERR requests, so the next legal request failed with `out_of_order_transaction: source channel sequence 2 expected 1`. The regression reproduced that failure before the fix. The ledger ordering checks remain in force.

## Real execution

In one generated ZipCPU wbdmac process, a one-word read at unmapped address `0x3000` receives an environment Wishbone ERR. The native DMA error/completion output pulses at edge 18. Reprogramming that same process then reads RAM `0x1000` and writes actual `0x76543210` to RAM `0x2000`; native completion pulses at edge 40. Accepted master sequences are exactly `[1, 2, 3]`. The rejected request has no target effect and no RAM service event; the valid transfer has one actual RAM read and one RAM write. No ledger keys or bus responses remain unresolved at the end. The test checks that process PID and execution UUID stay unchanged across the error and successful transfer.

The isolated snapshot is `/tmp/myfuzz-dma-error-snapshot`; its two modified files match the committed hashes below. Other generator/build inputs and source locks are embedded in the raw identity document. Under the local shared heavy lock:

```sh
cd /tmp/myfuzz-dma-error-snapshot
MYFUZZ_DMA_ERROR_RECOVERY_REAL=1 \
MYFUZZ_DMA_ERROR_RECOVERY_CACHE=/tmp/myfuzz-dma-error-cache \
MYFUZZ_DMA_ERROR_RECOVERY_EVIDENCE=/tmp/myfuzz-dma-error-evidence \
PYTHONPATH=src python3 -m pytest -xq tests/local_harness/test_wishbone_dma_error_recovery.py
```

Result: **2 passed in 11.67s**, covering the failing software contract and actual error/reprogram/transfer path. Focused session/firmware checks: `PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_wishbone_dma_error_recovery.py tests/local_harness/test_wishbone_dma_session.py tests/scenario/test_ibex_dma_example.py` → **8 passed, 1 skipped** before the opt-in real test was added (the skipped existing real DMA gate requires a separate opt-in).

This is a single DMA process recovery check. It does not prove CPU error-ISR handling, a sustained search session, generic Runner DMA admission, or authenticated-prefix replay. Previous RX/TX CPU-combination traces retain their own recorded source identities; they are not new runs of this change.

## Saved evidence

[Evidence directory](evidence/dma-error-recovery-20261017) contains the complete raw trace compressed deterministically, gate output, and the two task source hashes.

| File | SHA-256 |
| --- | --- |
| `error-then-valid.json.gz` | `e541de1a66e1dfa057bef16026e33f0eaa6addb1b98c51eba48877c3730cc0c9` |
| `gate.log` | `1e0c8a6176aabc4369c7f0fbe2670e617b01f0b7975aaf98325690e03c9d72a8` |
| `source-files.sha256` | `cc7bf826bfcef895216b57673f32001db869fbcb4ba34ec30b906beb2c84de2e` |
