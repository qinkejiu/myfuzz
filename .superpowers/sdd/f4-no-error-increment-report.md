# Legal no-error OBI ABI policy increment

Scope: restore the original CV32E40P fixture as a legal success-only ABI candidate without fabricating an error pin. No native build or simulation was launched. Prior frozen source/evidence remains unchanged. This increment does not establish full P7/D4 or new native pass evidence.

## Source decisions

`_cpu_error_policy` derives an explicit policy only from the exact admitted generated artifact: code-owned selected endpoint contracts, explicit boolean profile fact, matching selected executor facts, authenticated physical ABI taps, generated HAS_ERROR values and reviewed adapter source SHA. The known adapter (`59730c6742a85351d6e2cbf284d88185c874080274f323f2364268f2da3440df`) synchronously fatals on an accepted backend ERR when HAS_ERROR=0. Future adapter edits require renewed code-owned review/pin; merely changing an artifact digest cannot authorize different fail-stop logic.

Inspection discovered that renderer metadata recorded endpoint contracts only for error-capable OBI. Parent authorized a minimal renderer branch extension: both explicit boolean variants now record actual existing selected contracts. No empty contract list is interpreted as implicit no-error authority.

Native-error paths still require and sample physical error==0 on every consumed response. No-error paths record `error:null` and policy `fail_stop_no_error_pin`. Public exact-hop omission of policy stays strict native-error; missing taps never auto-downgrade. Runtime re-derives policy at stability boundaries; checker/prefix/certificate identities include it. No component-name branch or new CPU factory was introduced.

## Required assertion audit

| Required assertion | Evidence retained on no-error ABI | Error capability claim |
| --- | --- | --- |
| protocol_checker.receipt_violations | Actual runtime protocol receipt violations must remain empty, target APB failures rejected | Does not claim CPU error pin/trap observation |
| cross_component.declared_edge_hops | Every declared edge retains exact authoritative image versions, accepted native OBI requests/responses, router and APB transaction joins | CPU response error explicitly null |
| cross_component.chain_certificate_hops | Exact fetch/data transactions and live authoritative GPIOEN before/commit/after witnesses remain required | Successful chain only |

An explicit `protocol_checker.native_error_response` requirement is unsupported on no-error ABI. It is not passed or silently removed. All other pre-existing assertion restrictions remain intact.

## Software controls and receipts

`.superpowers/f4-no-error-increment/red.log`/`red.exit`: nine expected RED failures before implementation. First focused GREEN: nine passed in 10.81s, true exit0. Controls cover original fixture positive, wrong selected variant, executor/profile fact contradiction, fake native tap, missing/mismatched adapter closure, wrong generated HAS_ERROR, explicit native-error requirement refusal, null evidence, and strict default consumer refusal.

Final focused adds direct unreviewed adapter bytes refusal. Broader software results appended below. All native tests remain opt-in; no native gate launched.

## Unrun controlled native gate

`scripts/check_compiled_obi_no_error_boundary.py` requires explicit compose, capabilities, supplement, new output/cache and canonical heavy lock. It regenerates/admit exact artifacts, builds actual CPU boundary only when explicitly invoked, observes the real first request acceptance at native and backend boundaries, sends one real instruction backend ERR and requires native fatal text plus actual nonzero exit. Complete raw commands/replies, physical acceptance, PID/nonce, stderr, source hashes and close returncode are saved; failures keep `.incomplete`. It does not synthesize expected successful DUT output or count host read success as child exit.

Syntax compilation and `--help` inspection do not execute this native gate. Future authorized verification must run both the existing adapter RTL fail-stop test and generated-boundary gate, followed by identical three-candidate/two-fresh F4 gates for native-error Ibex and no-error CV32 source snapshots. No previous evidence is borrowed for this new closure.

## Final generic observation boundary correction

Independent review confirmed an existing normalized OBI event path used `bool(signals.get('error',0))`, fabricating false when no role exists. Parent authorized these minimal additional files:

- `scenario/ip_protocol_events.py`: actual role 0/1 remains its actual sample; missing role becomes `None`. Contradictory OBI role/width metadata refuses.
- `scenario/ip_protocol_evidence.py`: completion without a role has `outcome=completed_error_unobserved`, never observed `ok` or `error`. Raw-to-projection verification and handshake certification remain required.
- `scenario/ip_base_coverage.py`: unknown error observation contributes only the distinct bounded `response:...:error_unobserved` completion feature, never observed ok/error coverage.
- `tests/scenario/test_obi_no_error_observation.py`: explicit missing/0/1 role and contradictory width controls.

Checker inspected: it already validates protocol handshake/order independently, with exact role widths, and needs no compatibility change. Backend service receipt `error` fields describe the backend response; they are not physical CPU error pin observations. The physical OBI normalized event and exact-hop evidence now both preserve absence.

Software receipts: initial ABI broad gate **69 passed, 2 skipped in 175.32s**, true exit0; skipped gates require explicit native opt-in. Final ABI focused **10 passed in 11.01s**, exit0. Observation RED **2 failed,2 passed**, exit1; first implementation surfaced a syntax typo and then a missing finite coverage universe entry (both preserved). Corrected focused protocol GREEN **21 passed in 0.11s**, exit0. Extended final protocol/ABI regression result below after completion.

Extended final software regression: **238 passed, 67 subtests passed in 11.21s**, true exit **0** (`observation-regression.log`/`.exit`). Command: `PYTHONPATH=src python3 -m pytest -q tests/scenario/test_obi_no_error_observation.py tests/scenario/test_ip_protocol_obi.py tests/scenario/test_ip_protocol_evidence.py tests/scenario/test_ip_protocol_checker.py tests/scenario/test_ip_base_coverage.py tests/scenario/test_ip_protocol_events.py tests/scenario/test_ip_protocol_events_axi4_lite.py tests/scenario/test_ip_protocol_checker_axi4_lite.py tests/scenario/test_ip_protocol_evidence_ahb_lite.py tests/scenario/test_ip_protocol_events_ahb_lite.py tests/integration/test_compiled_f4_no_error.py`.

All implementation files pinned in `.superpowers/f4-no-error-increment/source-files.sha256`. Source whitespace and syntax checks run separately from preserved raw pytest logs. Native generated-boundary ERR, adapter RTL, and new continuous/fresh CPU gates remain **unrun**.

Independent review `.superpowers/sdd/f4-no-error-variant-source-review.md` verified the generic correction resolves its sole medium blocker. A final defensive review regression found explicit no-error policy passed directly to the standalone exact-hop helper could ignore a still-exposed physical error role; helper now rejects that contradictory combination. Also made OBI error width require actual int1, rejecting boolTrue. These two controls first failed (review-red: 2 failed,1 passed,13 deselected), then implemented without changing runtime authority or relaxing any required assertion. Final regression receipt appended after terminal.

Final frozen software regression: **240 passed, 67 subtests passed in 11.25s**, true exit **0**, `final-green.log`/`final-green.exit`, using the same extended command above. Independent final reviewer verified all12 source manifest entries and the two defensive fixes; no remaining high/medium blockers. No native pass, adapter simulation, generated ERR gate, full D4/P7 or search capability is claimed.
