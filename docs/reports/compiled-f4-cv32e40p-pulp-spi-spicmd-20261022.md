# CV32E40P + PULP SPI SPICMD compiled-F4 evidence

- **Date:** 2026-10-22
- **Status:** bounded F4 first/fresh gate accepted for this registered source row.
- **Evidence root:** [`attempt-5`](evidence/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022/attempt-5/)

## Scope

This slice adds a second source-reviewed PULP APB3 storage row to the existing
compiled-F4 executor: CV32E40P OBI accesses PULP SPI `SPICMD` at
`0x40001008`, reads the stored value back, then stores that value to result RAM.
Four first-run candidates (`0`, `1`, `2`, `4`) have exact APB, register-version,
CPU readback, native OBI store, and RAM-writer joins. A distinct fresh process
reproduced the complete four-record prefix.

This is a CPU MMIO F4 storage/readback result. It is not a DMA/F6 transfer and
does not exercise serial SPI pins, STATUS strobes, SPI FIFO behavior, IRQ/ISR,
arbitrary APB3 targets, physical interconnect, retirement semantics, P6,
P7-E, P8, or aggregate six-CPU/four-IP acceptance.

## Source and generated identity

- Registered contract: `pulp-apb-spi.spicmd.source.v1`, register `SPICMD`.
- Pinned PULP source revision: `sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230`; exact seven-file closure and hashes are in the [hierarchy proof](evidence/verilog-probe-pulp-apb-spi/proof.json).
- Probe proof file SHA-256: `900146781e6226c67f05f9b10702036fcbf3f7d276805e202db9e936fedd349e`; embedded proof digest: `5f7ff0702c8e2452d77891d2c9451f95a3a732b97e35aafa6986ab8ee3361268`. It records reset-zero, SPICMD write commit, readback equal to storage, all ten probe ports sampled, and negative expression controls.
- Compiled CPU profile fingerprint: `sha256:0c2b7ad47948dc2dc0feb750fc4b35973b5e3000fff1bf8db424334c2506d1dd`.
- Compiled peripheral profile fingerprint: `sha256:d2cdcd865c77cd8e85ea5843694a9a86fc035d8a6d03a75fa7bd9cee3af2fddf`; capability sidecar fingerprint: `sha256:de6d706e9a41dcd5552da907529b46037fbe1ebc020138d3fa990373187043cf`.
- Generated processor artifact digest: `1169e7c79ae1fa9b9c7c01e6ad61876b506f73d7c2758236eac75a0262f4ad47`; peripheral artifact digest: `e2c0242a32d03392711161e0b156f054f26e5f04a91c202df06569b6ab54d9f4`.
- `compiled_paths.v1.json` SHA-256: `0d25b6bbbda8217534a4e0a1e99d0f98855c7fc46b6a9b86e18a29e71fc88763`; `harness_set.json` SHA-256: `be9683a6bf7ec28f2faf6b7aa54f6cb6fc01279d95e1893d5c95327517b7fc46`.
- The CPU profile has no error pins; its error behavior is `fail_stop_no_error_pin`. No bus error-pin observation is claimed.

## Certificate change

Attempt 4 had four certified cases and a matching fresh semantic hash, but its
saved per-case certificate did not type the result RAM write. Attempt 4 remains
preserved and is not accepted for this strict gate.

The exact-hop checker now binds the consumer-selected RAM event to the next
native OBI data store. The typed `ram_write_hop` includes the exact address,
value, byte-enable, width, memory ID, generation/version, byte offset,
transaction scope and sequence, producer event, OBI acceptance, and completed
response. The result address must lie inside the admitted image range and its
offset must equal `address - range_start`. Fresh prefix comparison includes the
entire RAM witness. The nested schemas are now
`compiled_F4_exact_hops.v2` and `compiled_F4_chain.v3`; the outer
`compiled_F4_prefix.v2` remains unchanged. No CPU/IP-name branch was added.

Recorded software gates:

- `test_compiled_execution_files.py` plus `test_compiled_f4_no_error.py`: **63 passed** after range and offset checks were added.
- `test_compiled_f4_spi_source_real.py` plus `test_compiled_f4.py`: **31 passed, 1 skipped**.
- The independent code review recorded PASS in
  [`task-4-attempt5-ram-hop-review.txt`](../../.superpowers/sdd/compiled-f4-apb3-second-source/task-4-attempt5-ram-hop-review.txt).

## Native invocation and preserved attempts

The accepted invocation is saved at
[`command2.json`](evidence/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022/attempt-5/invocation/command2.json):

```sh
PYTHONPATH=src /usr/bin/python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e40p/component_profile.json \
  --ip configs/peripherals/pulp_spi/local_component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p/compose.json \
  --output docs/reports/evidence/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022/attempt-5/run-native \
  --executor compiled-f4-rfuzz \
  --client-binary runs/rfuzz_client_native_build/target/debug/kfuzz \
  --cache-dir .superpowers/compiled-f4/cache \
  --budget-seconds 60 --max-tests 8 --max-runs-per-batch 1 --rounds-per-case 32
```

There was no `--runtime` or `--skip-session`. The valid command exited 0 after
261.912 seconds; `run-summary.json` reports `complete`, four receipts, four
certified cases, and a full fresh replay match. The earlier attempt-5 output
directory preflight refusal is preserved separately. The similarly named
`cv32e20` override negative exited 1 before native startup with
`composition-profile-not-reviewed` at `/cpu/request`; its command and output
are preserved in the same attempt directory.

## First/fresh joins

The [saved receipt audit](evidence/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022/attempt-5/invocation/receipt-audit.json)
reports PASS. An [independent read-only raw-evidence review](../../.superpowers/sdd/compiled-f4-apb3-second-source/task-4-attempt5-evidence-review.txt)
also returned PASS with no discrepancies. The reviews checked the four
first-run APB readback/RAM joins, fresh certificate equality, process
identities/termination, input manifest, and run-summary document hashes.

| Candidate | APB write/read source sequence | RAM OBI accept / RAM event / response | Result address / byte offset | Version | RAM source sequence |
|---:|---:|---:|---|---|---:|
| `0` | 1 / 2 | 950 / 951 / 1024 | `0x3fffc` / `0x2fffc` | `[0,2]` | 3 |
| `1` | 4 / 5 | 2334 / 2335 / 2412 | `0x3fffc` / `0x2fffc` | `[0,4]` | 6 |
| `2` | 7 / 8 | 3722 / 3723 / 3800 | `0x3fffc` / `0x2fffc` | `[0,6]` | 9 |
| `4` | 10 / 11 | 5110 / 5111 / 5188 | `0x3fffc` / `0x2fffc` | `[0,8]` | 12 |

Every result store uses full-word `BE=15`, width 4, and the candidate value.
The RAM event's producer is the matching native OBI store acceptance; the store
response completes after the RAM event. APB write/read and result-store
transactions share the case scope, with the result store following the APB read
in source sequence.

- Receipt join: `ok`, **4 certified**.
- First/fresh canonical prefix-comparison digest: `09e0c1d54f07eaa9422053a96ff3c54e84554f36bb840533353dd43f764cc6cb` for both. The serialized first and fresh prefix JSON files are byte-equal; each file SHA-256 is `40770acaf0a9300a6257270986c26cc5e3fe0d89e400409a1a8cf42ca4ec7cc7`.
- First and fresh normalized semantic SHA-256: `9942ffacda50240994b84371a246aeb55bd9b3fac2394fe572dc7720c2b2cf31` for both; each trace contains 5,580 events.
- Fresh scope: `full`, `matches=true`, no first difference.
- First CPU/peripheral PIDs: `352308` / `352265`; fresh PIDs: `356249` / `356206`. Execution nonces differ across first and fresh; all four processes were reaped with exit code 0.
- Frozen input manifest: 591 files; SHA-256 `f9272d90bfe728877c4b1112f8a9669c504e691305f9de8172100df7334d044d`. The independent run-time audit matched all entries. After Task 5 documentation updates, a fresh current-tree comparison found all paths present, 588 entries unchanged, and three expected post-run documentation changes; see the [manifest drift note](../../.superpowers/sdd/compiled-f4-apb3-second-source/task-4-attempt5-postdoc-manifest-drift.txt).
- Run summary SHA-256: `1f7e18f0707d2e31d763f9f274d039015050a27ff586c8d14edcd923bebafd08`.

## Acceptance boundary

This closes only the registered PULP SPI `SPICMD` compiled-F4 storage/readback
slice on the CV32E40P OBI profile. It adds one more protocol-specific target
instance to the executor. It does not establish arbitrary APB3 onboarding,
same-protocol sibling acceptance, serial SPI operation, DMA/F6, or any of the
project-wide CPU/IP, P6, P7-E, or P8 acceptance gates.
