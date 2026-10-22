# Selected compiled F4 runtime path admission

The user selected route A and continued after reviewing the [specification](../superpowers/specs/2026-10-22-compiled-f4-runtime-path-admission-design.md).
The [implementation plan](../superpowers/plans/2026-10-22-compiled-f4-runtime-path-admission.md)
adds the selected D3 F4 contract to the real ScenarioSession and fresh replay.
The final frozen software gate and two native first/fresh gates passed.
Independent raw-evidence auditing passed for both Timer and the sibling SPI. The report does not close P7-E.

## Implemented boundary

The pure same-call admission re-runs D3 compilation, restores the original
graph and contract, and verifies the complete selected runtime path identity.
It explicitly joins the logical D3 image source to the graph memory-image
source and the exact declared RAM resource/range/permissions. A versioned
BoundOnlineInstruction carries its graph source ID; the generic session checks
the selected path, actual RAM region, instruction range and reserved slots
before input writes or native case commands. Existing plain instruction
records retain their serialized form.

CompiledF4Runtime configures the actual ScenarioSession before begin. The
decoder, execution binding, certificate and saved plan retain logical and
runtime path IDs and source identity; the executor derives contract_preflight
from matching real session material. Fresh construction repeats admission and
topology binding on the new Runner.

The saved identity verifier reissues the candidate layout from the selected
D3 row and compares its complete structure, logical image/MMIO sources,
register/address, runtime selection, target node/component, session declaration
and every bound case. Rehashed wrong-source/layout/selected-path controls refuse.
The source/helper D3 digest now uses the existing shared ASCII canonical
compiled_document_sha256; graph/contract digests keep their existing UTF-8 form.

## Compiler correction

The first integration run correctly refused the preexisting F4 contract:
device_register_response was placed on the CPU despite the declared CPU-to-IP
MMIO route. D3 now emits both that runtime node and its target metadata on the
declared target peripheral. The runtime never rewrites the admitted graph or
contract. Historical artifacts retain their original identities and do not
gain runtime preflight from this correction.

## Development verification and reviews

Task1 initially passed 103 tests and 43 subtests. Independent review found a
schema24/25 scheduled-source replay allowlist omission; meaningful successful
and terminal mixed-source RED controls reproduced it. The fix passed 107 tests
and 43 subtests, and independent Task1/2-scoped Spec/Quality review passed.
Task2's initial pure admission gate passed18 tests. Task3's final focused wiring
gate passed16 tests, including actual pre-begin configuration and saved evidence
tamper controls. Independent Task3 review is clear after the logical-source,
layout and row-to-prepared joins were strengthened.

Final executed-input archives, commands and terminal receipts are saved under
[evidence](evidence/compiled-f4-runtime-path-20261022/). Development RED/GREEN
logs are evidence of these implementation checks; only a completed frozen gate
and a new real native run establish final acceptance for this slice.

## Frozen software gate

The actual sixteen-module command completed with **399 passed, 48 subtests
passed**, exit0 in269.26s. Supervisor wall time was269.58s and max child RSS
178388KiB. All2051 archived project Python/config inputs matched before and
after execution; the supervisor PID517119 was reaped. Commands, raw output,
input archive and terminal receipt are in
[software-attempt1](evidence/compiled-f4-runtime-path-20261022/software-attempt1/).
Archive SHA256: `8104d59e67fa3c9cc7771a2ed17bd5fdb88af15a2014f85abf2e390f7a9e8420`.
This is project Python/config freeze evidence; external RTL/toolchain closure
is not claimed by this software archive.

## Native first/fresh gates

Both invocations use `--executor compiled-f4-rfuzz`, no runtime-family fallback,
`--max-tests 2 --budget-seconds 30 --max-runs-per-batch 1 --rounds-per-case 32`,
the existing RFuzz client, and a shared native build cache. Exact argv, stdout,
stderr, source archives and supervisor terminal receipts are retained in each
attempt's `invocation/` directory. All 2051 project Python/config inputs matched
before/after each invocation. The same executor consumes the declared profiles
and selected contract for both combinations.

| Combination | Certified receipts | Full first/fresh events / records | Supervisor wall / exit |
| --- | --- | --- | --- |
| CV32E20 + PULP Timer | 2/2 | 538 / 2 | 121.81s / 0 |
| CV32E40P + PULP SPI SPICMD | 2/2 | 2806 / 2 | 141.65s / 0 |

Both actual sessions report `runtime_path_status=contract_preflight`; both saved
plans are schema24 with explicit `bound_instruction` source identity. The
helper, decoder, session declaration, plan and certificates carry the same
logical/runtime path and instruction-source mapping. Each original/fresh CPU
and IP process has a distinct PID and nonce; all eight recorded native exits
are reaped/returncode0. Full first/fresh prefix files match byte-for-byte in
each attempt. This is selected-F4 certification, not a generic closed-loop
runtime-chain throughput award.

- [Timer evidence](evidence/compiled-f4-runtime-path-20261022/native-attempt1/),
  [independent audit](evidence/compiled-f4-runtime-path-20261022/native-attempt1/independent-audit.md).
  Archive SHA256 `46983678cc8ba5b14989cf0a8d42341ceec8c8c1fa84284417e3d198c073ba89`;
  normalized prefix SHA256 `c08f337faa7d4925101e570cf307468e311caef6adffeddc49fd77e78275d673`.
- [SPI sibling evidence](evidence/compiled-f4-runtime-path-20261022/native-sibling-attempt1/).
  Archive SHA256 `30c1e4475ba769acaf8736fa127b0569663a7c3c8e290c357d02a52f5e46ac22`;
  normalized prefix SHA256 `903b35f94cd8890f86b9ab12fb43d2452e8708d760f1f8c0e2504f1721d9f8f8`.
  [Independent sibling audit](evidence/compiled-f4-runtime-path-20261022/native-sibling-attempt1/independent-audit.md) passed.

The independent auditor checked both attempts: all archive members, the complete
selected D3 row, graph/contract/source joins, schema24 cases, receipts, process
records, source closure, identity/bundle/summary hashes and cached build inputs.
This is a saved-evidence audit, not another independent RTL execution. The
software archive also has an independent
[input audit](evidence/compiled-f4-runtime-path-20261022/software-attempt1/reviews/independent-input-audit.md).

## Next bounded implementation

Join each exact D2 artifact and source/toolchain-bound build identity to a
validated output executable digest and the actual launched PID/nonce. Existing
cache validation already checks binary bytes, but that output identity is not
yet carried through the compiled execution binding and process audit. Record
compile versus cache-validation time separately; a cache hit does not measure
cold-build cost. Keep the structural D2 generation record truthful and add a
run-level build join after preparation, with fresh validation before launch.

## Subsequent executable-identity follow-up

The later [built-identity slice](compiled-f4-built-identity-20261022.md) adds
validated output receipts and live process associations in two independently
audited native runs. Its final software status is tracked separately. The
original runs in this report retain their own frozen identities and do not
retroactively gain those receipts.

## Remaining system gates

This adapter accepts one instruction image and one CPU MMIO stream. An
unrepresented selected external-pin or other source refuses before startup.
General F1-F6 execution, arbitrary same-protocol CPU/IP onboarding, generated
D2 harness binary/build-cost identity, useful throughput, P6 persistent-harness
and per-edge/four-hit gates, and P8's5x target remain open. This source/path
preflight grants no retirement, semantic consumption, DMA or ISR authority.
