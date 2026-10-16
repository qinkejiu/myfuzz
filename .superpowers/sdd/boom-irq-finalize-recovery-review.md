# BOOM finalize-only metadata recovery — independent source review

Reviewed freeze `56bbfc9e5d2ca4c9add05fde28b29f4f544b42fe` and the four source/test SHA values in `recovery-helper-source-pins.json`. Recomputed file hashes match that freeze. Read the helper, generator/session deltas, complete recovery tests, report, and actual pinned command/tool and build-closure archive contents. No tests, build, model, operational recovery or remote operation were executed by this review.

## Medium finding: removing mutable JSON origin fields bypasses recovery validation

`boom_irq_recovery.py:114` returns immediately when both `build_origin` and `metadata_finalization` are absent. `GeneratedBoomIrqCpuSession` calls this validator but does not independently require origin based on the physical recovery directory. Consequently, a recovered artifact can have both origin fields removed and `session_files` reduced to the ordinary canonical set. The physical `recovery-receipts` and captured historical outputs remain, yet the constructor does not check those extras and takes the ordinary artifact path. Its other checks bind current Python/source metadata, the unchanged driver and locally hashed executable, but do not restore the old-build/new-metadata distinction. This defeats the explicit recovered-output origin contract even though it does not create cryptographically signed provenance.

Require the complete origin contract whenever physical recovery receipts/markers or any recovery metadata/manifest entry identifies this output as recovered. A missing field, removed pair, receipt-directory symlink or malformed recovery namespace must refuse before `Popen`. Add a real-constructor control that strips both JSON fields and trims `session_files`, keeping physical receipts, and confirms refusal before launch. The owner agrees this is a medium finding and will coordinate a RED→GREEN follow-up.

## Other reviewed boundaries

- Three code-pinned archives bind historical build0/probe0/failed final stage1 separately, the binary SHA, actual executed 16-row descriptor, old Python/source manifest, driver/manager/RTL/profile/interface/probe helpers, make-selected registry and object dependency. The command/tool archive SHA is `0fa6d68c4e70195e382a01e255a84952a5e200aea29c20c96cebe2e47a1133ec` and the actual recorded C argv matches the narrow old-output template.
- Current canonical generation compares every effective compiled input byte and exact flags; only a Verilator version query is permitted, with actual wrapper/bin paths and hashes constrained to `/root/fanzehui`. This reuses the pinned binary; it does not rerun elaboration/build/model/describe-probes or claim a runtime pass.
- Old build origin and current metadata finalization are separate exact schemas. Old Python hashes are retained, current implementation hashes differ, and `new_cpp_build=false`, `runtime_verified=false`, `source_authority=false` are checked.
- Destinations must be absent, disjoint from originals and each other. Source/destination symlinks are rejected before resolution, copies have distinct inode and one link, byte hashes are checked, originals are not overwritten, and publication is exclusive. Failure retains an incomplete marker; the constructor refuses an incomplete output.
- Constructor reauthenticates source/profile/ports/auxiliary/implementation identity and expected file set before launch. The remaining finding concerns selecting the recovery validation path, rather than the checks within that path.

This is source review of local integrity/provenance checks. It is not signed build provenance, source authority, instruction/IRQ evidence, a valid operational restored-session proof or permission to run recovery/native work. The owner's reported software result is 86 passed; this reviewer did not rerun it. Operational recovery remains gated on the agreed independent new paths and root scheduling.

## Status

One open medium finding; no additional high or medium issue identified within the scoped immutable archive/metadata recovery design. No operational recovery recommendation until the origin-stripping control passes and the updated freeze receives source review.

## Resolution review: `d486513a328eb849a4fcb8aea01ef6b213740a1f`

Re-read the minimal fix and constructor control, without executing tests or recovery. `validate_recovery_origin` now detects physical `recovery-receipts`, incomplete or pending markers, including broken symlinks, independently of mutable JSON fields. Any such physical state or declared origin requires both complete origin dictionaries before parsing the same pinned origin contract. The actual constructor test removes origin/runtime/source claims and trims the manifest to the ordinary set while retaining physical receipts; `Popen` is forbidden and the expected complete-origin rejection is asserted. Three physical-state controls cover receipt directory, incomplete marker and pending manifest.

Recomputed updated helper SHA `dcf7c096058053cea959e9dd08f9c350cad994dba07df1536bd13c80a0d6f22e` and test SHA `f1a0b6de468015ed502d90e71277dea97bb08a6758ab4be8e85dd1aeefd97c1b` match the updated freeze pins. Generator and session source hashes remain the previous reviewed values. The owner reports 89 software tests passed; this reviewer did not rerun them.

The medium origin-stripping finding is resolved for the stated local integrity contract. No remaining high or medium finding within this review scope. Removing every provenance field and every physical recovery trace cannot be cryptographically distinguished from an ordinary unsigned local artifact; this design continues to make no signed build or source authority claim. This review grants no operational recovery/native permission or runtime acceptance.

## Dependency follow-up: `3e9c07bdda1fef4aa972f625c19255ac40033819`

Read the one-line addition of `scripts` to the copied source scopes and its exact `scripts/verify_soc_sources.py` preservation control. The existing host source discovery explicitly seeds that script, so retaining it is necessary for the independent project's later GPIO identity scan. The same symlink rejection, distinct-file copy and byte comparison applies to the added scope. This changes copied Python/script dependencies and current metadata identity; it does not change effective compiled CPU inputs or grant a new C++ build.

Recomputed helper SHA `a6bbd17117a0973e4e67bc599b0e4cd7daa277449d4be9de3dfea0db294db3a8` and test SHA `c9d7dbbd0cb072586e405e46ee3aece3348e213e9bfb08ef65e32b6f88941a83` identify this follow-up. No additional high/medium finding. Owner reports 90 software tests passed; no tests or operational action were performed by this re-review. Earlier preparation paths remain superseded, not operationally accepted.
