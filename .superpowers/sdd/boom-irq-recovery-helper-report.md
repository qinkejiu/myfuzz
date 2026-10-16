# BOOM IRQ finalize-only helper source freeze — 2026-10-17

## Scope

Implements the recovery proposal following independent review. No operational or
remote metadata recovery, build, model invocation, probe describe, IRQ firmware
execution or heavy-lock acquisition occurred in this increment. Root's DMA6/F4
windows were not used. Local tests do invoke the helper on temporary software
fixtures; tool path/version authentication is mocked in those fixtures and they
are not operational restored artifacts or runtime acceptance evidence.

New `boom_irq_recovery.py` is deliberately limited to the three code-pinned
actual attempt2 archives. It cannot import an arbitrary old executable through
caller-supplied hashes. Source/provenance statements remain local integrity,
not signed builds/source authority or ISA/IRQ evidence.

## Historical receipts

Old build0, executed probe0/16 exact rows, failed final stage1 remain separate.
The prior two archives and their original Python/source/driver/executable remain
unchanged. Added readonly command/tool receipt archive:
`attempt2-command-tool.tar.gz`, SHA256
`0fa6d68c4e70195e382a01e255a84952a5e200aea29c20c96cebe2e47a1133ec`.
It contains the actual generated __verFiles.dat C command record and hashes of
the actual wrapper/bin under `/root/fanzehui/myfuzz/.tools/...`; no tool paths
outside agent.md scope were read. Its recorded version comes from actual prior
build metadata, not a new model or tool run.

## Helper contract

- Ancestor and final symlinks rejected before canonical resolution; destinations
  must not exist, overlap originals, or overlap each other. Original captured
  input/receipt bytes must match pinned archives. Existing outputs are untouched.
- Copies source scopes src/configs/tests/PULP GPIO and complete original output
  through copy2. Every copied file must have one link, different inode and equal
  bytes. Source tree links are refused. No cp-al or cleanup of old artifacts.
- Exclusive new output records incomplete state before validating/copying;
  failures retain a failed marker and never overwrite old history. Unsafe path
  or existing-destination refusal happens before claiming the destination.
- Current source/physical ports/profile are authenticated by canonical generator
  into a temporary directory beside new project (thus inside fanzehui when run
  at the prepared remote location). This permits only a version query; never
  elaborates/builds/runs a model. Every driver/manager/four RTL/profile/interface/
  VLT/helper/specs/contract byte must equal the actual prior build input.
- Exact code-owned argv template fixes flags/tool token and every argument.
  Only declared new output paths differ. Actual original __verFiles.dat C record
  must equal that exact old-output template. Actual wrapper/bin path, resolved
  path, hashes and version must still match. No arbitrary payload normalization.
- Actual binary/16 descriptor/build+probe exits/failedstage/raw logs/registry/
  make/object dependency and all captured artifact file hashes are verified
  before and after copying. Explicit two-layout registry helper is reused.
- Three pinned archives are copied into recovery-receipts. Manifest records exact
  source/runtime closure and full captured historical file hashes. build_origin
  and metadata_finalization are separate code-owned schemas: old Python hashes
  are preserved, current hashes must differ, reused_binary=true,
  new_cpp_build=false/runtime_verified=false/source_authority=false.
- Pending manifest is fsynced and atomically published with exclusive hard-link
  insertion, then pending link is removed (one final inode link remains). This
  temporary publication link does not share any historical/source inode.
  Collision refuses to overwrite and retains incomplete state. Readback origin
  checks run before incomplete marker removal.

## Constructor crosslinks

IRQ constructor now invokes the same strict origin contract when either origin
field is present. It reparses pinned receipts and checks exact schema fields,
old/new identities, executable and every historical output hash, actual inventory,
argv/tool and receipt/session-file hashes. Exact expected manifest set includes
those origin receipts/files. Incomplete marker always refuses startup. Canonical
implementation closure includes the recovery helper's current hash. It cannot
silently accept an unknown build_origin claim merely because JSON can open.
Baseline BOOM one-shot/persistent sources and generic Runner are unchanged.
IRQ constructor temporary authentication files are confined to output.parent.

## Software evidence

Initial two recovery tests failed with missing helper, then passed. Full command:

`PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_boom_irq_recovery.py tests/local_harness/test_boom_irq_contracts.py tests/local_harness/test_boom_session_regressions.py .superpowers/boom-irq-verification-20261017/test_launcher.py`

Actual exit0: **86 passed in22.39s**; recovery-only36 passed9.08s before final
path/link strictness additions. Tests forbid compiler/model subprocess.run.
Most positives use actual pinned receipts with mocked canonical/source-tool
fixture; one copies/authenticates actual current source/ports/profile and every
effective input, mocking only tool path/version because no local Verilator is
installed. The actual constructor is then shown refusing changed origin before
Popen. This does not prove a valid operational constructor/session or IRQ gate.

Negatives cover changed original driver/RTL/profile/VLT/binary/inventory/exits/
registry/make/object dependency; changed current effective inputs/flags/version;
wrong wrapper path; archive tamper; stale old-Python identity/new-build/runtime
claims; receipt hash and rehashed binary; existing outputs/ancestor symlink;
linked copies and atomic publication collision. Failed metadata attempts retain
incomplete markers in local fixtures. Operational helper has not been run.

## Next authorization boundary

Review this source freeze first. Only after exact root GO may the helper run on
independent new remote project/output destinations using unchanged attempt2
inputs. No implicit builder retry/fallback, describe-probes rerun or model clock.
After metadata readback audit, runtime state still unverified. New identity needs
its actual session/startup, GPIO→MEIP→ROB/CSR→ISR→exactMRET/return/foreground,
fresh prefixes and missing/changed controls in a later scheduled native window.

## Independent review correction — origin stripping

Reviewer found that removing both origin fields and trimming session_files to
the ordinary manifest could bypass the JSON-key-only provenance check while
physical recovery-receipts remained. The physical output now independently
triggers mandatory complete origin: recovery-receipts directory, incomplete
marker or pending-manifest marker. Either declared origin field also triggers
the full contract. Missing/incomplete origin refuses before native launch.

Three targeted filesystem cases first failed, then passed after the minimal
guard. The real constructor software test additionally strips origin/runtime/
source claims and trims session_files to normal, while retaining actual saved
receipts; it now refuses before Popen. Final combined command above: actual
exit0, **89 passed in20.83s**. Source pins refreshed. No operational recovery,
remote source overlay, model/describe/build or heavy lock was used. This is
still local integrity and explicit recovery provenance, not signed immutable
filesystem history or source authority. Reverse reviewer receives this freeze.

## Required copied-project script dependency

Preparation identified that generic GPIO host discovery explicitly seeds
`scripts/verify_soc_sources.py`, while original copy SCOPES omitted scripts.
Root approved the narrow BOOM helper correction: add scripts to copy scopes.
A precise temporary-fixture test first failed because the new project lacked
the file, then passed after the one-line scope addition. Final combined command
actual exit0: **90 passed in21.27s** (software-green.log under new metadata
preparation directory). Real current source authentication still matches every
original effective compiled input; no C++/RTL/profile/probeconfig change.

The original2460-file local-only preparation is preserved under
`boom-irq-metadata-recovery-20261017/superseded-first`, explicitly superseded,
never uploaded or operationally run. New snapshot will include scripts and
PULP's actual independent.git objects. Operational recovery remains unauthorized
until exact parent GO and reviewed controls.
