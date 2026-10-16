# D: protocol-selected F4 with a registered APB storage producer

2026-10-17. Read-only design. Inputs: existing GPIO F4 runtime, source contract2dbcc2d, generation60d692f, producer/reset mechanics4b3be10, C issuer cadaa75+clock fix053ff9c, A2 generation4c6822d and host brief135a06a. No constructor/frontend/build/model/native or new test executed. No session/APB/issuer implementation changed for this brief.

## Actual current boundary

`compiled_f4.admit_f4` explicitly requires apb_gpio/GPIOEN and the causal GPIO contract, even though `generated_register_writer` already diagnoses generic APB traces. Runtime directly constructs GeneratedPulpGpioSession/GpioRegisterVersionAuthority; its commit consumer expects GPIO epoch/command_scope fields. Generic source-registered timer declaration exists, has a four-byte candidate and no external pin source, but remains live unsupported. Passing both CPUs against GPIO did not remove this target restriction.

C can establish current storage from actual initial command pre/post, with actual private native build/process/frame/source eligibility and complete measured continuity. It does not establish pre-READY reset waveform or unobserved initial zero. A2 generates bounded measured reset pages, but host constructor/schema/page callbacks and C handoff are explicitly unsupported until the separate reviewed host integration. READY cannot supply those facts.

## Minimum closed producer dispatch

Introduce one code-owned producer selector keyed by **admitted target protocol/template + canonical generated observation contract**. Two closed rows: existing GPIO causal ABI and source-registered generic APB storage ABI. Rows name exact session/issuer classes and exact consumer functions in code; user JSON cannot supply factories, methods, expressions or an authority descriptor. Generic registration is the reviewed source identity/register contract, never component_id/profile name. Unknown APB sources/variants/registers refuse; a registered timer row is not arbitrary same-protocol IP inference.

Selector returns an immutable admitted producer binding: target/component/endpoint identity, template/variant, selected register/offset/width/masks/decode/source/probe/producer digests, source closure and allowed prerequisite kinds. Reconstruct it from trusted source inputs during initial admission, every stability/readmission check and every fresh prefix. Do not accept caller-supplied metadata as that binding. Public executor remains explicit compiled_f4_obi_apb, with a limited capability report, not a default family fallback.

GPIO row preserves its existing concrete construction, observation contract, before/commit/after consumers and named evidence payload. Generic row uses exact GeneratedApb3RegisterSession with setup_writes=()/probe_offsets=(), no dynamic/bound producer, and ApbStorageRegisterVersionAuthority. No named timer or CPU factory. Existing OBI CPU selection and native_error/success_only_no_error ABI policy remain exact artifact/profile selections; do not fabricate CPU error0 on CV32.

## Prerequisite and chain consumers

- Match D3 `ip_register_version` subject to the selected producer's exact register/component/reset_epoch. Do not weaken seed/constraint/source-kind/termination/rule admission or any of the three required F4 assertions. Unknown/reset-dependent prerequisite kinds stay unsupported until an actual eligible consumer exists.
- Current-value-only paths may consume C's opaque before token only after the live target has produced initial actual samples; no assumed reset0, setup write or readback substitute. Require witness source/probe/artifact/build/PID/nonce/epoch/tick-base/sequence and observed current value. Keep unobserved-startup history and grants_reset_prerequisite=false in certificate/report.
- If D3 requires a reset precondition, reject until A2 host retrieval, actual startup provenance and a separately reviewed reset-prerequisite issuer/consumer exist. Existing Runner NativeResetEvidence remains GPIO-specific; do not broaden it by adding isinstance or treating B READY facts as measured waveform. A2 startup levels alone also do not grant F4 reset rights.
- Generic commit consumer requires exactly one new measured CTRL alias write for the candidate. Before field_version/write_count v → after v+1 even when old==new. Bind history digest to prior journal + actual commit; before/after state values, actual raw address/mask0x1c alias, command sequence, execution/epoch/tick and candidate value must agree. Every other command/direct/nonrouted alias write still revokes old tokens; never filter the writer journal by routed context.
- Context is correlation only: join typed TransactionKey/address/offset/value/be/device/window to the **actual Router delivery**, actual native APB pre acceptance and actual C receipt/sample reference in the same process scope. Check context is write, component/epoch/sequence match, actual APB PWDATA equals candidate, source-owned storage transition equals before→after, and CPU readback/RAM equals actual candidate. A caller context or serialized write record cannot certify source delivery.
- Retain complete exact-hop instruction byte-version → physical CPU fetch → actual CPU data beat → Router → physical APB → live storage commit/readback → RAM chain. Generic protocol events and raw storage_probes are different evidence groups; preserve both and join explicit producer references. Existing generic diagnostic check remains runtime_admitted=false unless the live opaque witness consumer supplies authority.

### Raw-reference seam to inspect before implementing

C journal references actual receipt execution/sequence/sample_index/pre; generic `_take` retains storage_probes but does not yet add an explicit transport-reference envelope to each Runner sample. D must either prove the existing unique component/process/epoch/global-tick join reaches the same private parsed receipt, or add an exact code-owned command reference (and receipt digest if needed) during actual `_take`, then consume it with the opaque witness. Do not silently join only equal values or invent a producer event. Any added sample metadata is documentary without the actual original producer/Runner receipt path. Preserve raw payload, actual event IDs and first-difference failures.

## Candidate, prefix and file entry

Reuse D3 compiled_candidate_layout slices without format shortcuts. Timer records are four bytes, not GPIO's eight; no dummy pins, shared high word, implicit seed or expected output. Decode the entire record and all masks/padding before any pin/CPU action. Explicit declared external source slices continue independently for GPIO only.

Include admitted producer/source/probe/layout/reset-policy identity in checker/prefix/fresh identity. File entry reconstructs from source inputs and source pins, loads exact generated artifacts, ownership/map and declarations; JSON output never rehydrates tokens. Preserve lexical source identity checks, selected heavy lock, new output paths, primary and every fresh complete plan/events/process-role→PID/nonce/actual-close receipts, and real exit. Fresh PID/nonce must differ; do not expand normalization beyond existing explicit typed process fields or erase storage payload/command clocks. Keep reported directionality: directed candidate execution, not coverage-guided search throughput.

## Proposed atomic ownership / ordering

| Increment | Exact intended ownership |
|---|---|
| A2 host, separate owner review first | session/APBsession/startup helper/registry+observer/C receipt-mode seams per135a06a; source-only then actual startup gate. No simultaneous shared-file edits |
| D1 closed producer selection | new integration/compiled_storage_producer.py; compiled_f4 admission/construction/checker/stability/prefix; new isolated producer-selection controls and existing F4 tests |
| D2 generic commit/raw join | same dispatcher+compiled_f4; generated_register_writer only if diagnostic/authority separation needs an exact consumer hook; APB `_take` transport-reference metadata only after explicit ownership. Do not touch GPIO authority implementation |
| D3 public entry/config | compiled_execution_files/CLI/limited capability report; registered timer supplement/request/README and current fixture controls. No hand-written artifact authority or change to D2 compose proof boundary |
| actual gates, separate exact GO | frozen snapshots/launch controls/output archives; shared canonical heavy lock, no implicit network or concurrent source mutation |

D1/D2 source controls may be implemented with exact source/profile fixtures and isolated reducer/selector tests; no fake native eligibility positive. Live token/certificate positive remains a real gate. Preserve existing GPIO behavior/certificate semantics via the old producer row, rather than broad shape normalization.

## Later acceptance plan (not authorization)

1. Pure RED→GREEN and independent review: unsupported source/register/template/producer/ownership/method/source/probe/layout/context/clock/alias/serialized/stale/foreign tokens refuse; required assertion consumers remain real. Constructor cannot tick before all input/declaration admission. Read-only instruction/result-resource shapes retain current explicit refusal.
2. Actual standalone registered storage gate: build real complete hierarchy, measured raw storage vs APB/reset, ordinary+high alias writes (host misalignment remains a distinct controlled refusal), readback, held-state continuity, stale token/unknown producer rejection, source/process/epoch/close identities. If reset acceptance is claimed, require actual A2 startup pages and measured release→first-command handoff, not READY.
3. Same compiled public file entry: actual timer four-byte three distinct original records, two full fresh prefixes; all three required assertions, exact write/version count and instruction/OBI/router/APB/storage/readback/RAM joins; full primary/fresh artifacts, source pins, actual plan/events/PID/nonce/exit and failures retained.
4. Preserve GPIO three records/two fresh for Ibex native-error and CV32 legitimate no-error ABI under the new exact source closure. Historical GPIO/CPU evidence remains pinned to old snapshots; do not relabel it as a new-code regression pass.
5. No arbitrary-IP/P7 grant: timer is genuinely different RTL and new to supported F4, not a newly imported repository IP. Other CPU/protocol/DMA/event/search requirements remain separate. No interrupt/serial/error-generation behavior follows from APB CTRL success.
