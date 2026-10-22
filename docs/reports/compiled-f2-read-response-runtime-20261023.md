# Compiled F2 CPU load and IP read-response runtime slice

Status: bounded software implementation and pure gates passed. This slice did
not run a native process. The follow-on native first/fresh gates subsequently
passed for both registered instances: [native gate report](compiled-f2-native-gate-20261023.md).
No CPU-retirement, F3/F5/F6, P6/P7-E/P8 or system completion is claimed. The preceding selected F4 slice remains accepted only against its
own frozen inputs: [report](compiled-f4-built-identity-20261022.md).

Design: [approved specification](../superpowers/specs/2026-10-23-compiled-f2-read-response-design.md).
Execution plan: [implementation plan](../superpowers/plans/2026-10-23-compiled-f2-read-response.md).
Development evidence: `.superpowers/sdd/compiled-f2/runtime-read-response/`.

## Implemented path

`CompiledF2Runtime` executes the registered, side-effect-free full-word Timer/SPI
APB3 storage register admitted by the D3 F2 row:

1. Startup capture and the IP's normal idle step run with empty inputs; only
   then does the existing pinned `ApbStorageRegisterVersionAuthority` issue and
   consume a current pre-read version token.
2. The candidate supplies exactly the singleton load address. The generated
   RV32I fragment is `LUI/ADDI/LW/XORI 0x5a5/LUI/ADDI/SW` plus four trailing
   NOPs; only SW writes the declared result word inside the image RAM resource.
   No PRDATA, hidden setup write, extra source or diagnostic access is added.
3. `check_f2_read_observation` joins one routed read delivery with the physical
   APB PRE/POST samples, the contiguous idle/read command sequence and the real
   post-read version token; a state/history/version change refuses.
4. `check_f2_exact_hops` joins the seven functional instruction fetches and
   their byte versions, the native OBI data acceptance/response, the dependent
   `PRDATA XOR 0x5a5` RAM store, its installed-memory snapshot and the declared
   three-edge order. A read response alone is not consumption.
5. The certificate resolves the declared prerequisite to an actual
   `ip_register_prerequisite` (`kind=ip_register_version`, live epoch, native
   observation event and field version). Two typed assertion rows are emitted
   through `compiled_assertion_results.v1`; the dependent-RAM checks remain
   named executor checks, not invented D3 expectations.
6. `finish`/`replay` compare the full normalized original/fresh prefix with the
   established process-local projection only; raw PID/nonce evidence is retained
   separately.

## The two known issues

- **An IP version is not a RAM version.** The D3 prerequisite is the IP register
  version selector. Runtime resolution records an `ip_register_version`
  prerequisite (component/register/live epoch/observation event/field version)
  and projects the live witness onto `apb_storage_register_version.v1` stable
  facts. No `ram_byte_version`, `memory_id`, generation or byte offset is
  fabricated for an IP register. A legacy RAM-shaped F2 version document is
  refused before any constructor or native tick by the strict whole-document
  recompile, and the specific `version-prerequisite` guard remains as
  defense-in-depth behind it.
- **No CPU-to-CPU MMIO edge.** `edge_endpoints_from_compiled` now derives each
  MMIO leg's endpoints from the graph's own node ownership: the outbound leg is
  initiator -> device and the return leg is device -> initiator. A route whose
  declared nodes do not equal the declared initiator/device pair (including both
  ends on the CPU) fails closed instead of reusing the declaration as both
  endpoints. `_f2_edges` independently requires the three declared F2 edges,
  refuses a CPU-to-CPU response/consumed node, and labels the legs
  `read_request`/`read_request`/`read_return` from node ownership, not names.
  A read return is never certified by reusing the outbound request as its
  consumer.

## Implemented files

- `src/myfuzz/integration/compiled_f2.py`: typed in-memory F2 admission fix,
  `_f2_edges` role/endpoint resolution, `CompiledF2Runtime` execution, typed
  assertion rows, original/fresh replay.
- `src/myfuzz/scenario/edge_provenance.py`: node-ownership MMIO route endpoint
  resolution (operation/role-scoped; no name dispatch).
- `tests/integration/test_compiled_f2_read_response.py`: new pure controls.

The slice reuses the existing compiled paths, read layout/reader, read producer
selection, native register authority, exact-hop verifier, build-join primitives
and assertion-results module. It does not add a second framework or a name-based
target selector, and it does not inherit the F4 executor's write semantics.

## Pure controls and exact counts

New file `tests/integration/test_compiled_f2_read_response.py`: **13 passed, 0
failed** (`new-tests-green.txt`), covering:

- the positive selected-path shape (three real CPU/IP edges, IP version
  selector, bound `ip_read_response`, exact 11-word reader with the dependent
  store) and a full synthetic exact-hop journal whose seven instruction
  versions, native OBI data read, IP response and XOR-dependent RAM store all
  certify;
- missing IP read response, missing join, wrong response data, borrowed
  response, missing dependent store and wrong dependent store value;
- wrong registered register, RAM-version masquerade, CPU-to-CPU MMIO edge,
  missing response edge, and unsupported flow/read-write/partial-mask shapes.

First `_f2_edges`/admission run before the fixes: **41 passed, 10 failed**
(`baseline-red.txt`), including the edge-ownership test and the missing
`CompiledF2Runtime`. Focused F2 tests plus the generic edge-provenance suite and
the F4 runtime-path regression: **128 passed, 0 failed** (final rerun log
`focused-green-final.txt`). That focused set also contains the existing
source-backed SPI/CV32E40P F2 recompile, marker and full admission test, and the
renamed-instance edge test: neither F2 selection nor edge role resolution
depends on instance names. No native gate was run and no skip was treated as
native evidence.

Commands (from the workspace root):

```
PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_read_response.py
PYTHONPATH=src:. python3 -m pytest -q -ra tests/integration/test_compiled_f2_read_response.py \
  tests/integration/test_compiled_f2.py tests/integration/test_compiled_f2_layout.py \
  tests/integration/test_compiled_f2_consumer.py tests/integration/test_compiled_f2_decoder.py \
  tests/integration/test_compiled_f2_build_join.py tests/integration/test_compiled_f2_runtime_path.py \
  tests/scenario/test_f2_read_contract.py tests/scenario/test_edge_provenance_f2_read.py \
  tests/scenario/test_edge_provenance.py tests/integration/test_compiled_f4_runtime_path.py
```

## Remaining boundaries

- The native Timer/CV32E20 and SPI/CV32E40P original/fresh gates were run in the
  follow-on slice and passed ([report](compiled-f2-native-gate-20261023.md)); the
  renamed-instance native control and independent audit remain main-session work.
- CLI/executor registration, capability-report wiring, saved-file byte pinning
  and the run-level F2 build join are not part of this bounded slice.
- `cross_component.declared_edge_hops` evidence comes from the read-specific
  exact-hop verifier's own edge hops (role-labelled and joined per transaction).
  The generic `edge_provenance` read-route reporter is not widened here; write
  matching is untouched.
- Timer and SPI remain the only registered instances; no other APB3 IP,
  partial-field/lane read, side-effecting read, F1/F3/F5/F6, AXI/AHB/TileLink,
  mutation diversity or throughput claim is made.
