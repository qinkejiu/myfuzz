# GPIOEN live register version authority — 2026-10-17

Implementation commit: `d368c9e` (`Add source-pinned live GPIOEN register version authority`). The authority issues process-local, one-use GPIOEN version tokens from actual parsed native driver receipts. It is a prerequisite producer for the registered causal GPIO source contract; this gate alone does not establish complete compiled F4 execution.

## Admission and lifetime

The constructor requires an actual fresh `GeneratedPulpGpioSession`, the exact registered `pulp_gpio_causal_local` profile, canonical regenerated D2 artifact/build identity, and verified official PULP source. The source is pinned to upstream revision `f82caeb7f7d89427f05e9af5ed31e0675efe0d83`, file `rtl/apb_gpio.sv`, SHA-256 `1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef`. The profile SHA-256 is `ebda4798cc5e3874957e3b4aad8aa3fe3131c94f01537e90759fbd2f1bbfead0`; the reviewed local closure SHA-256 is `bcf42dc3b40aa2e61a115c8a3fc874c2ec28a1a4aebe2b6c85f64d331c1563c7`.

Actual receipt production is checked against import-time producer methods, native build issuance, binary/cache identity, and the registered physical probe mapping. Each measured tick checks GPIOEN continuity and its declared overwrite/hold transition. Tokens are revoked by the next command, process replacement, reset epoch change, or uncertain state. Token and write capacities fail closed. Authority state and issuances live in private registries; serialized witnesses and reports cannot recreate authority.

Only GPIOEN/decoded word 1 is implemented. Other registers and profiles without the registered source contract remain unsupported. CPU transaction causality must additionally be checked by the compiled executor against actual CPU acceptance, routed delivery and target observations. A context supplied to a standalone Router is not itself proof that a CPU produced the transaction.

## Real gate

The saved [pytest log](evidence/gpioen-live-register-version-20261017/real-gate.log) reports **4 passed in 125.46 seconds**. The exact [transport, command and exit accounting](evidence/gpioen-live-register-version-20261017/gate-command.json) are retained. The remote shell returned 0. Its final command was `cat`, so the pytest process exit code was not separately captured; the saved pytest summary records all four tests passing. No gate was rerun solely to produce this report.

The tests exercised:

1. Rejection of an unregistered target, unsupported ordinary GPIO artifact, unobserved state, duplicate installation and direct fabricated receipt injection; injection permanently invalidates the authority.
2. Rejection of a replaced command producer before authority installation.
3. Actual GPIOEN state observation, real native APB writes `0x55` and `0xaa` through `DataflowRouter`, preservation of routed transaction context, one-use token consumption, command revocation, reset/epoch revocation, rejection of instance `_tokens` injection and token-capacity failure.
4. A second actual write beyond `max_writes=1` rejects further authority, aborts the native process and prevents consumption of a previously issued token.

The final [five-file commit hashes](evidence/gpioen-live-register-version-20261017/commit-source-pins.json) cover the authority, session receipt hook, GPIO probe method pin, directed CPU writer and authority tests. The directed writer is included in the implementation commit; the four-test real gate above directly exercises the authority and GPIO native path, not execution of the CPU writer.

## Retained build evidence and limits

Execution used an independent frozen tree under `/root/fanzehui/system-20261016/project/.superpowers/gpio-version-frozen`, serialized with `/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock`. [Cache identities](evidence/gpioen-live-register-version-20261017/cache-identities.json) retain the available cache manifests, actual build arguments, artifact/input/toolchain fingerprints and executable SHA-256 values captured after the gate. Four cache entries reflect development iterations. The gate log does not identify which entry each individual test selected; these manifests therefore document available build identities and are not presented as an exact per-test binary join.

The authority gate did not save an independent raw receipt/event archive or each consumed witness. Its evidence is the saved pytest result, checked source commit and cache manifests; assertions inspected actual live RTL receipts during execution. Full compiled candidate → CPU → Router → IP → checker causality, continuous feedback and complete fresh-prefix replay require the separate compiled F4 executor gate, which is expected to retain its raw journal. This report makes no such end-to-end claim.

Additional local checks recorded during implementation: native reset regression `26 passed`; final isolated authority unit run `2 passed, 2 skipped`. A concurrent local combined run observed build-identity drift while other agents edited host source; an isolated rerun passed without relaxing source authentication.
