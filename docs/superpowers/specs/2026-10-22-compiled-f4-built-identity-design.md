# Compiled F4 built executable identity

Status: bounded implementation and frozen software/native acceptance completed
on2026-10-22; see [acceptance report](../../reports/compiled-f4-built-identity-20261022.md).
The user continued after written-spec review. P6/P7-E/P8 and system acceptance
remain open.

## Goal

Join each selected compiled-F4 CPU/target D2 artifact to a currently validated
native build output and the native process actually started for that component.
Keep the existing full first/fresh prefix comparison strict. Preserve the
meaning of structural-only D2 generation and existing ordinary sessions.

Predecessor: [selected-F4 acceptance](../../reports/compiled-f4-runtime-path-admission-20261022.md).
Both predecessor runs have source-bound artifacts/build inputs and native
process receipts. Neither carries an admitted output binary digest through the
compiled execution binding to those processes.

## Alternatives

1. **Validated build receipt plus run-level join (recommended).** Capture the
   existing cache validator's exact output identity before the compiled binding
   and session manifest are frozen. Revalidate before launch. Keep timing/cache
   diagnostics separate from the stable receipt. This addresses the missing
   association without changing what D2 generation itself produced.
2. **Record a binary path or copy a saved manifest.** Small change, but a path or
   saved JSON does not show that the current executable matches the current
   admitted inputs. It cannot authorize a launch and is rejected as a solution.
3. **Build during all D2 generation and rewrite harness_set as built.** Broadens
   generation behavior and build cost for all callers. It also obscures that
   the existing CLI's D2 step generated structural artifacts while the runtime
   prepared executables later. Defer this separate generation feature.

## Existing ordering and compatibility

`ScenarioSession.begin()` captures the runner identity before
`ScenarioRunner.begin_test()` invokes each session's `prepare_local()`. The
compiled runtime must therefore opt in and prepare its two sessions before
constructing the final execution binding and before `ScenarioSession.begin()`.
The runner's later preparation call must revalidate and reuse the original
receipt; it must not replace it or overwrite compile observations with a cache
hit. No native process starts during this preparation phase.

The ordinary `build_local_harness(...) -> Path` API and non-opted session
identity/launch behavior remain compatible. New behavior is opt-in at the
session boundary and mandatory for the actual compiled-F4 runtime. Generic
`derive_f4_execution_binding()` can retain its prebuild declaration semantics;
its result must not be presented as a started, build-bound runtime credential.
Existing native-reset observation checks continue to apply independently.

## Build result and stable receipt

Add a build API returning a validated result while preserving the old Path API:

- `build_local_harness_with_receipt(artifact, *, base_dir, cache_dir)` returns a
  frozen result containing the validated binary Path, stable receipt and
  preparation observation.
- Stable receipt schema: `local_harness_built_receipt.v1`.
- Stable fields: exact `artifact_digest`, `build_digest`, complete current
  `local_harness_build_identity.v1` document, and `binary_sha256`.
- A canonical UTF-8 sorted-key compact JSON digest identifies the stable
  receipt; returned documents are detached copies. Do not accept a caller's
  deserialized receipt as proof of current preparation.
- Component identity belongs to the runtime join. The join requires the exact
  component key and admitted artifact; a receipt for another component cannot
  substitute even if its build shape or name is similar.

Issue only after the existing validator has checked the current executable's
bytes, executable/non-symlink status, materialized inputs and current canonical
build identity. Check the expected cache schema and receipt/document shape as
part of the new receipt path. Also retain the raw manifest byte digest as
session-local validation state, outside stable first/fresh identity. Repeated
prepare/prelaunch requires those raw bytes unchanged, even if a reformat or
additional field would preserve the stable projection. Preserve fail-closed
cache corruption handling;
a malformed existing cache is refused, not silently repaired by this slice.

Do not include cache paths, stage paths, actual invocation argv, durations or
cache-hit outcomes in the stable receipt digest. The canonical build identity
retains its existing source/toolchain/recipe identities and any paths already
part of that contract; this change does not redefine it.

## Preparation observations

Separate diagnostic schema: `local_harness_build_preparation.v1`.

Record monotonic elapsed preparation seconds and compile seconds when a
compile was actually attempted; record the invocation's actual argv only when
it compiled. Cache-hit compile seconds is null with an explicit
`not_compiled_this_invocation` reason, never a measured zero compile cost.

Classify outcomes at the actual builder branch:

- `cache_hit`: preexisting final cache entry validated, no compile performed.
- `compiled_published`: this invocation compiled and published the selected output.
- `compiled_race_reused`: this invocation compiled, but publication lost a race
  and the selected output came from the independently validated winning entry.

Build failure/timeout raises a structured `LocalHarnessBuildError` with a
detached optional `preparation_observation` containing the phases/argv/elapsed
time already observed and the failure stage. No receipt is issued on failure.
Missing measurements remain explicitly absent with a reason.

Track `compiled_this_invocation` explicitly. Never infer a cache hit solely
from checking directory existence before calling the builder. A race result
must report the selected winning binary's receipt and this invocation's
compile diagnostics separately. Save the selected raw cache manifest digest
and path as diagnostic observations; neither becomes portable stable identity.

## Opt-in session lifecycle

Add `configure_built_executable_receipt()` before preparation/start and expose
`built_executable_receipt_document()` plus
`build_preparation_observation_document()` after successful opted preparation.
The methods return detached documents; receipt access before preparation refuses.
Implementation clarification: an available failed-build preparation observation
and retained launch/cleanup diagnostic rows may be exported after refusal or pin
damage; these diagnostics grant no receipt or launch authority.
Track preparation-attempted independently of `_binary`, including a failed
prepare attempt. Configuration after any preparation attempt or process start
refuses; opting in is irreversible for that session. An opted session
cannot silently downgrade by removing its receipt/configuration.

First opted `prepare_local()` calls the receipt-capable build path and fixes
the exact artifact, binary, build identity and stable receipt. Later prepare
calls validate those same bytes/inputs/cache identity and retain the original
observation. A changed artifact, tool/input, cache manifest, selected output
or internal binary path is refused rather than issuing a replacement receipt.
The path must be the exact selected cache root/build-digest/harness output;
reject symlink/path escapes and unexpected manifest schema. Compare canonical
documents so bool/int/float coercions do not pass identity checks.

Immediately before `Popen`, revalidate the fixed receipt against the current
artifact/build identity, cache and executable bytes. Identity checks and
configuration checks must occur before native launch. The opted
`identity_document()` includes only the stable receipt; preparation diagnostics
remain outside the runner identity and prefix. Non-opted identities retain
their current fields.

This combines a prelaunch validation with a live executable observation; it
does not attest continuous file immutability or future process behavior.
Immediately after `Popen` returns, retain the PID/nonce/argv in a session-local
lifecycle record before any subsequent operation can fail.
For this Linux compiled-F4 slice, after `Popen` and before accepting READY or
issuing case commands, read and hash `/proc/<pid>/exe` through the live process
executable reference. Its bytes must match the admitted `binary_sha256`; an
unavailable process reference, exited process or mismatch refuses and aborts/
reaps the process. A fake script/interpreter cannot substitute for the native
harness executable in this opted launch path. Existing native READY artifact
validation remains required. Record a detached launch observation containing
PID/nonce, actual argv, receipt digest, observed executable digest and matching
READY artifact digest. Only successful executable and READY checks authorize
startup acceptance; observations before this point remain partial failures.
Retain these lifecycle records after abort/`end_case`, even when `_process` is
cleared. Record the failure stage and actual termination/reap result.

## Compiled runtime and process joins

After pure D2/D3/source/topology admission and session construction, opt in and
prepare both selected sessions. Only then construct the final
`CompiledF4ExecutionBinding` and freeze the session manifest. Include the
component-keyed stable receipts plus their digests in the execution binding.
Require exactly the declared CPU and selected target component set.

`_stable()` validates the live receipt set and its association to admitted
artifacts in addition to existing source/layout/path checks. Receipt/cache/
output drift refuses before further candidate commands. Avoid rerunning a
compiler or replacing receipts during stability checks.

Each original/fresh process identity retains component, role, PID, execution
nonce and artifact digest, and adds `build_digest`, `binary_sha256` and
`built_receipt_sha256` and the observed live executable digest/READY artifact
digest. The process row must match one exact component receipt;
missing/duplicate/swapped joins refuse. Original/fresh exit and reap evidence
remains separate and mandatory at successful finalization.

## Fresh replay

Fresh construction repeats pure admission, preparation/cache validation,
receipt creation and native startup. It does not import original receipts as
current launch authority. Pass the original stable receipt map to fresh
construction as expected identity constraints only; compare it with the fresh
validated receipt map before launching either fresh process. A mismatch refuses
before fresh native effects. Current cache/executable validation is still
mandatory and cannot be satisfied by those expected documents.
Timing, cache outcome, actual argv, PID and nonce
are observed independently outside the semantic prefix.

Stable receipts are included in the execution binding and thus in the strict
prefix comparison. **This bounded slice requires identical output binary
hashes between first and fresh.** A rebuilt different binary cannot receive a
full matching-prefix result by dropping or normalizing its digest. The
shared-cache first/fresh acceptance demonstrates exact output reuse, not
reproducible cold builds or deterministic output across independent toolchains.

## Saved run-level output

Write `compiled_f4_build_join.v1.json` with schema
`compiled_F4_build_join.v1` during finalization. After successful fresh cleanup
it can be complete; any prepare/startup/fresh/cleanup failure instead produces
a refused/partial join containing the observations actually available. Include:

- execution binding digest, D3 digest and selected logical/runtime path IDs;
- exact admitted D2 component/artifact keys and stable receipts/digests;
- original/fresh preparation observations outside stable identity;
- original/fresh component process joins and recorded exits/reap status;
- complete/refused status with explicit scope and no inferred cold-build cost.

The CLI records this output's byte digest in `run-summary.json`. The consumer
crosschecks it against the same invocation's D2 harness_set/artifact objects,
execution binding, session manifest, prefix and both execution audits. Saved
JSON is audit material, never a substitute for live preparation authority.
Persist available failure diagnostics without converting a partial join into
success or masking the primary error. The orchestration creates an audit sink
before constructing the original runtime and passes it into original/fresh
construction. A constructor failure must publish available per-session build
observations and lifecycle records through that sink before reraising; it
cannot depend on assigning a successfully constructed runtime variable.

Leave generated `harness_set.json` structural-only/binary-null when that D2
invocation did not build. Keep source-lock and generated-file reconstruction
checks. The run-level join explains the later runtime preparation explicitly.
Do not mark generic throughput tiers accepted from these specialized receipts.

## Acceptance and rejection cases

The design preparation changed no production source and ran no tests. The
following checks define the subsequent implementation acceptance gate:

- Existing ordinary session/build identity APIs retain behavior and plain
  identities. Opted identities include only stable output identity.
- Real artifact and validated cache fixtures cover receipt issuance, detached
  documents, repeated prepare, compiled/cache-hit/race outcomes and timing
  classification. Unsupported schemas/malformed documents refuse.
- Modified artifact, build input/tool identity, binary bytes, cache manifest or
  component association refuse before a mocked launch records any start. A
  mismatch introduced between preflight and launch is caught by the live
  executable check before READY acceptance; retain abort/reap evidence.
- Rehashed saved receipt or process swaps still fail cross-artifact/component
  verification. Timing/cache-hit changes do not affect stable prefix identity;
  binary-digest changes do.
- Actual CLI selected-F4 Timer and sibling SPI runs retain certified receipts,
  exact full first/fresh prefixes, contract_preflight, all process exits, and
  the complete build join. Retain commands, failed attempts, frozen input
  archives and independent source/evidence reviews. Follow `agent.md` for any
  remote operations; current design preparation is local/read-only on sources.

## Scope exclusions

No arbitrary CPU/IP dispatch, new bus support, F1-F3/F5-F6 execution, retirement,
semantic consumption, DMA/ISR authority, P6 persistence/per-edge/four-hit
acceptance, P8 5x performance, clean-room client provenance or full P7-E grant.
A cache validation duration does not establish cold-build time. This feature
closes an executable-identity association only when implementation and real
evidence satisfy the gates above.
