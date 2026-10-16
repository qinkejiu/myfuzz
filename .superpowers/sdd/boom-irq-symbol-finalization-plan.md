# IRQ actual registry layout correction and finalize-only recovery proposal

## Observed outcome, not an IRQ runtime gate

Attempt2 launcher200937, builder200950 and Verilator200958 all terminated.
Actual build.exit0; Verilator54.712s (elab3.324/cvt8.802/build38.913).
Actual probe-describe.exit0; all16 executed VPI full names/widths match required
contract. No measured edge/IRQ firmware run occurred. Actual final stage exit1
is FileNotFoundError for presumed `obj/VBoomTile__Syms.cpp`; no final IRQ session
artifact was emitted. Actual generated unit is `VBoomTile__Syms__Slow.cpp`.
Parent was immediately notified of terminal state and actual canonical lock
probe exit0; DMA6 now owns the next window. No automatic rebuild/retry/recovery.

Original attempt2 snapshot, output and exact old sources remain untouched.
Archive `attempt2-evidence.tar.gz` SHA256:
`559b5faf59607120ffabb59dc1ada694da9cf365b263e967d3cac154d3fee58a`.
Supplement `attempt2-build-closure.tar.gz` SHA256:
`e9a019a75fa4518cd620dc0519ce680b70d9c8c5ab5ba9c12ef1fbcc39082577`.
Both are under `.superpowers/boom-irq-verification-20261017/` locally and the
corresponding remote base. They retain actual logs/exits, binary,16inventory,
original Python generation/session source, driver/probe auxiliary, registry
source/header, make membership and compiled object dependency; supplement also
retains all four copied RTL inputs, original owned pins and interface copy.
Archive hashes were verified after download.

Actual unchanged binary SHA256:
`6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90`.
Actual registry source SHA256:
`bb8f5de56b07e2bd7faab6f96061486c45c16582f2373fd7a5b62c92a3febd21`.
Actual registry header SHA256:
`dc3bb6f677e641cb0b5aaaa42e8e96a2bee1bee579831c1925cf3becd5b9d32b`.

## Prepared source correction

`generated_symbol_files(output)` accepts exactly one of
VBoomTile__Syms.cpp / VBoomTile__Syms__Slow.cpp. No arbitrary glob selection:
unknown Syms CPP units, ambiguity, absent files, symlinks or oversized metadata
fail. The selected stem must occur exactly once in generated make
VM_SUPPORT_FAST/SLOW, and matching object.d must name that CPP source.
Header, CPP, classes.mk and object.d are all recorded in the exact session file
closure. Python constructor independently repeats layout selection and checks
manifest crosslink; actual executed descriptor/startup name/width checks remain.
This is generated file/build integrity, not signed provenance or ISA authority.

Precise software tests first failed3 (missing helper), then passed3; added
negative closure cases cover unknown CPP/header/dependency/duplicate make/link.
Saved actual archives are also checked as data: actual Slow layout, actual
make/object dependency, actual16descriptor and actual build/probe exits0.
Nothing invokes a compiler, executable or source generator in that saved-data
test. Final combined test result is recorded below after execution.

## Proposed recovery — requires source review and exact parent GO

No recovery has been executed or implemented as an automatic builder fallback.
Do not rerun build_boom_irq_session on original nonempty output. Do not modify
original artifact, sources, descriptor, executable or historical ready/pins.

1. Create independent cp-a copies to new `project-finalize-attempt2` and
   `artifact-finalized-attempt2`. No hard-link copies and no overwrite. Overlay
   only reviewed Python metadata correction into the new project; original
   build snapshot remains a historical source identity.
2. Freeze and check a complete recovery-input hash receipt against downloaded
   attempt2 archives and original source manifest. Require actual binary hash
   above, driver, RAM manager, four RTL inputs, IRQ profile/interface, passive
   configuration/probe helper/specs/contract, original generated-probes JSON,
   executed descriptor stdout/stderr/exits, actual build log/exit and generated
   header/Slow CPP/classes.mk/object.d all unchanged. Confirm no final artifact
   was previously present. Recheck copies byte-for-byte, no execution.
3. Recompute canonical expected effective build inputs in a separate temporary
   directory using the reviewed generator's source authentication only (no
   elaboration/build/model launch). Compare every generated C++/RTL/profile/
   probeconfig/manager input hash against original actual build copy. Tool
   version must match recorded build tool identity; version query is not a DUT
   execution. Reject any changed effective compiled input instead of adopting
   the old binary.
4. Read the preserved executed descriptor; require exit0 and strict exact16
   inventory, generated-probes crosslink and unchanged binary. Verify explicit
   unique actual registry layout + make/object closure with the corrected
   helper. No --describe-probes rerun is needed for metadata recovery; a later
   runtime session startup will independently query its actual inventory.
5. Assemble a new final manifest in the *new* output only, recording new Python
   runtime/generator hashes and an explicit `build_origin` carrying original
   source manifest/hash identities, original executable/tool/build/probe receipt
   hashes and original exit0 values. Record `metadata_finalization` separately,
   with original failure1 and reviewed correction identity. Do not claim new
   Python was compiled into original C++, or assign a new build exit to reuse.
   Write once atomically; never overwrite original or existing final manifest.
6. Pure readback audit checks exact closure and all crosslinks without session
   construction. A new artifact identity results even though effective compiled
   C++/RTL/probe config and actual binary hashes remain unchanged. Runtime
   verification stays false. First session/IRQ gate is a subsequent separately
   scheduled step against that identity and actual confirmed probe symbols.

Recovery helper/API and its negative software tests still require assembly
before execution; proposal is intentionally not an implicit repair command.
Potential negative recovery controls: changed driver/RTL/profile/probeconfig/
binary/inventory or nonzero build/probe receipt, duplicate/missing registry,
changed make/object source, overwritten destination, old source/new host identity
conflation. Each must refuse before final manifest emission. No relaxation of
probe or coherent protocol checking is proposed.

## Final source-only regression result

`PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_boom_irq_contracts.py tests/local_harness/test_boom_session_regressions.py .superpowers/boom-irq-verification-20261017/test_launcher.py`

Actual exit0: **50 passed in11.06s**. This tests corrected metadata selection and
reads the saved real build evidence; it does not finalize an artifact or run RTL.
New correction pins are separate `symbol-fix-source-pins.json`; original
attempt2 build ready/source pins are preserved as historical identities.
