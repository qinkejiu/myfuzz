# C: generic APB live storage versions — proposed exact scope

Basis e3790c1/spec, source contract2dbcc2d, generation60d692f and closed producer/reset mechanics4b3be10 (root review c0dc8b7). Design only; no C implementation or new test/native execution.

## Interfaces and ownership

| File | Proposed change |
|---|---|
| new `scenario/apb_storage_register_version.py` | Exact-class/source/probe-bound process-local issuer; private weak registries, immutable code pins, bounded sample/write/token journals; direct `_actual_command`, `issue(register, reset_epoch)`, single-use `consume(token)`, documentary `writes()` |
| `local_harness/session.py` | Additional direct callback to new private authority registry inside original `_command_impl`, before sequence/tick commit; preserve existing GPIO dispatch order/frame. Explicit revoke on actual command uncertainty/reset/abort/close, with direct producer-frame authentication. No wrapper dispatcher around command callback |
| `local_harness/apb3_register_session.py` | Registered-storage-only opt-in `routed_register_access_enabled` and `routed_register_access` using existing router seam; exact typed TransactionKey + address/offset/write/value/be/device context, pending command/process/epoch binding, finally-clear private active context; transport fallback remains nonauthoritative |
| `local_harness/native_reset_producer_contract.py` | Pin new exact APB routed methods/context declaration shape and issuer direct producer functions; retain B closed origins/old GPIO row |
| new `tests/scenario/test_apb_storage_register_version.py` | RED/GREEN equation/alias/continuity/token/provenance negatives, explicit noneligible software fixtures; actual production trust guards remain exercised |
| owned report/receipts | Exact source/test pins, bounded pure receipts and limits |

No source-contract extension, renderer/driver/build/Runner/F4 admission change in this atomic C scope. If actual reset-wave capture is required before any version can exist, that is a separate generation increment identified below rather than a fabricated B receipt.

## Issuer admission and raw equations

Fresh exact GeneratedApb3RegisterSession only, B canonical contract and strict empty setup/probe/input policy; exact identity reconstruction and actual native build/private issuance required before issuing any version. Attaching an observer/issuer on a software artifact may establish refusal controls but cannot produce an eligible witness. Descriptor/READY/readback values/expected data/serialized reports never establish authority.

Every actual command revokes pending versions before any send (including no-return/lost reply), consumes only its actual parsed receipt from the base `_command_impl` frame, and checks contiguous execution/epoch/sequence/global local ticks. Each pre/post dedicated storage_probes group must be exact code-owned port set, typed bounded integers, matched reset and physical APB widths. Canonical source/probe/build identity is revalidated on every producer/issue/consume operation. Any missing/duplicate/skipped sample, uncertain effect, source/process/epoch change, callback/frame drift, untracked command or budget overflow permanently poisons that scope; process replacement requires explicit fresh scope, never healing from an arbitrary later sample.

For the reviewed CTRL field: actual reset assertion wins and value must satisfy measured reset equation; otherwise a completed write (`psel && penable && pready && pwrite`, error0) whose raw paddr satisfies `(paddr & 0x1c)==4` updates value to actual pwdata, and all other sampled transitions hold. Preserve actual raw address, ignored bits, accepted tick, before/after, command sequence and independent physical sample references. Count every raw alias, including ignored high/low bits in the pure reducer; host misalignment remains a separate adapter refusal. Count nonrouted direct accepted writes too (context absent), so no stale version survives an alias merely because it has no router delivery context. Readback/rdata cannot substitute storage.

Routed context is correlation input, not authority: typed transaction/address/offset/byte-enable fields must match actual access command and sampled bus acceptance. Deep copy/finally-clear context; reject reentrancy/mismatched lifecycle. No GPIO observation schema imitation. The eventual witness binds source/probe/producer/build/artifact digest, actual PID+execution nonce/epoch/sequence/tick/register/version and actual raw write joins. Returned documentary fields cannot deserialize into a token. Tokens are opaque process-local objects, bounded, single-use and invalidated by the next actual command/reset/close/uncertainty.

## Reset evidence gap to keep explicit

Standard generated APB reset ticks occur before READY and are not currently exported as raw command samples. B authenticates actual reset process lifecycle and driver reset identity; it explicitly does not turn READY into a reset waveform. C must not manufacture sampled asserted reset or claim `reset_value==0` was observed from this metadata.

Recommended atomic C policy: establish first field state from actual initial command's measured pre/post storage samples (no assumed initial zero), then prove only subsequent sampled transitions/continuity. Check the source reset equation whenever actual reset is in the raw sample, but keep `reset_waveform_observed=false` and reset prerequisite unsupported if none was observed. A current-value version witness is distinct from native reset evidence and grants no reset prerequisite. If root requires an actually sampled reset prefix for C eligibility, first authorize an A2 Standard reset-buffer/probe receipt generation increment; do not add it silently to C or infer from READY.

## RED sequence and regression controls

1. Existing generic target cannot issue any live version; absent/unregistered probes, foreign/subclass/monkeypatched producer, forged build/receipt/frame and JSON token all refuse before issuance.
2. Separate pure equation reducer fixtures cover reset priority, stable hold, exact overwrite, every address alias, error response, wrong widths/bool, missing/prepost/different reset, unexpected storage transition and budget limits. These fixtures have no live issuance path.
3. Real command callback controls prove receipt identity/sequence/tick/process closure; serialized/stale/foreign/reused tokens, skipped command/alias write, active-context mismatch and uncertain exception paths refuse. Do not monkeypatch native eligibility to call a software witness native-positive.
4. Existing GPIO version + mechanical reset and both generic identity/probe suites remain unchanged regressions; explicit typed equality, no broad payload normalization. No remote/frontend/model/build/native.

D separately connects a reviewed generic storage witness consumer to F4 prerequisites and exact-hop joins, then executes actual storage/alias/reset and CPU→timer gates. Neither C software fixtures nor generation strings grant P7/new-IP completion.
