# CVA6 bounded full AXI native gate — independent source review

Read-only review 2026-10-17. No tests, subprocess tool commands, artifact construction, compiler or model executed by reviewer.

Frozen scope:
- scripts/verify_cva6_full_axi_observer.py SHA256 4a60dd527ab412472d9d866ded9d492a870875130bd7d0fdccce9040fdd16a49
- tests/local_harness/test_cva6_full_axi_gate.py SHA256 0278d6a5e448b3f02f6672503c8ff02ceb6ced89c8b8ea4bf48fd22d58691b3c

No high/medium source finding in this bounded gate preparation. Default and write-freeze paths only read source bytes; artifact imports/construction occur behind explicit --run-native, confined new output, exact freeze validation and nonblocking canonical lock. The source freeze includes discovered host closure plus gate/program/source-lock inputs. Output preserves actual driver, structural/runtime wrappers, program, manifest raw bytes, complete first/fresh receipts/raw/observer/Runner records and pending state.

The positive validator binds each parsed RESULT to actual issued process nonce, sequence, before/after tick, input fields, raw sample and backend. Observer and Runner scopes require the fixed component/case/epoch and issued execution before typed normalization. It independently reproduces the full observer stream from saved raw samples and requires exact once-only Runner import. Fresh comparison retains full samples, accepted/pending and identity/build manifest, and only replaces declared driver execution and observation scope execution fields; unrelated nested payloads are preserved. Distinct PID/nonce and unique close0/reaped lifecycle are required. Actual Popen argv, ready-time binary/manifest hashes, final actual binary, cache raw manifest SHA and identity crosslinks are checked.

Failure paths retain failed-step receipts/raw and readback collection errors before durable gzip publication. Startup/transport abort captures actual handle and close status. Constructor failure before a process exists is outside per-run evidence collection, but outer summary retains the error and does not claim a native prefix. Byte budget retains the first offending receipt then refuses later commands; it is a stopping threshold, not a strict allocation cap. This matches prior observer limitation and does not grant completion.

Owner reports25 source-only controls passed5.68s, including canonical RESULT parsing, source-only no-subprocess fixture, nonce/scope mutation, ready/bin/manifest, startup abort, readback failure and command budget controls. Reviewer inspected these controls without rerunning. This review grants no native pass, instruction retirement, source authority, global protocol completion or IRQ evidence. Partial pending observation remains explicitly partial; the future actual native run must still be separately authorized and evaluated.
