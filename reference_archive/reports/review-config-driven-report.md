# Configuration-driven increment review (2026-10-28)

Read-only source review; no source changes, native builds, simulations, or expensive tests. Reviewed the plan and four requested implementation reports, production search/config/CLI/native routing, generic campaign budget changes, F6 file budget route, compatibility aliases and shipped scenarios. Comparison/metrics are excluded as assigned.

## Resolved Important: empty mixed fresh changes the execution backend

Follow-up read-only review of the frozen source: the finding is resolved. `descriptor_search.py:278` computes `preparation_memory_flows` from the complete deterministic selection before fresh truncation, then passes that unchanged together with the requested `execution_case_capacity` at `:311`. `generic_campaign.py:608-609` honors the explicit preparation profile; `:650` and `:667` preserve requested capacity for shared runtime and engine. F6 forwards the same capacity to its standalone file executor. The inspected regression tests cover empty and nonempty truncated prefixes with both memory and storage preparation. No native or expensive tests were run for this follow-up.

The following describes the earlier defect, retained for traceability:

Location: `src/myfuzz/runtime/generic_campaign.py:586-592`, also runtime construction at `:620-626`; fresh prefix truncation is `src/myfuzz/search/descriptor_search.py:162-167`.

`memory_flows` is inferred from the planned records during original execution, but an empty mixed fresh sequence unconditionally enables memory. An original mixed record-catalog request containing only F2/F4 therefore prepares the descriptor's F2/F4 plan and ordinary mixed runtime. If the deadline prevents its first submit, fresh truncates the same requested sequence to zero, then prepares F1/F2/F3/F4 and enables the memory runtime. It can fail admission or replay a different initialization/plan. It does not preserve the original complete zero-input prefix. This also affects requests whose originally planned memory cases are removed by prefix truncation: preparation is derived from the shortened sequence instead of the original execution configuration.

Suggested lightweight regression: mock preparation/runtime construction in `run_descriptor`; call mixed original with explicit F4/F2 records and an expired-before-submit fake clock, then mixed fresh with `sequence=[]`, `allow_empty_sequence=True`. Assert identical preparation flow_ids, memory_flows option, execution-plan identity and complete initialization/finish semantics. Also cover a nonzero budget prefix with the first F1/F3 record outside the executed prefix. Preserve the original preparation/runtime profile in fresh metadata (or pass the original planned records separately) instead of inferring it from the executed prefix.

## Other inspected requirements

- No Critical finding identified in this review.
- Live fresh validates the full requested seed/policy/rounds/time/case bound before using actual count; zero count retains positive engine capacity. Descriptor manifests additionally bind the original raw summary hash.
- Updated catalog fresh now validates request/selection/source identity and original summary, execution identities and semantic prefix bindings. It repeats the actual count including zero, compares complete semantic/plan identity, requires cleanly reaped successful native processes with consistent build/binary/artifact/manifest bindings, and rejects nonce reuse across invocations. Strict cross-invocation support is now disclosed in capability and result fields. This supersedes the earlier within-invocation-only limitation.
- Shared campaign only converts a RUNNING `generic-budget-refused` with a recorded budget-stage refusal into a budget terminal; other errors propagate. F5/F6 check real case boundaries and disclose first-case admission and measured overrun.
- Unknown catalog state is explicit; trials are censored and gain no evidence-derived reward. Sidecars do not grant certification authority.
- Production ROOT and source hashing no longer require research implementation files. Legacy modules alias the production module objects, including native helpers. The public descriptor driver additionally hashes the Python runtime closure.
- Timer+Ibex and SPI+CV32E40P select the same registered mixed F2/F4 executor and `native.execute`; CPU/IP choice is descriptor data. Native completion for these two combinations remains an integration evidence requirement: the reviewed reports explicitly state software-only verification.
- F1/F3 remain available through explicit mixed records; F5/F6 retain standalone executors and packed eight-byte records. No new combination-specific factory was found.

## Verification limits

One attempted lightweight Python command used unavailable `python`; retried with `python3` successfully. The successful command loaded the Timer descriptor and exercised finite record selection only; it launched no native tools. The finding above is based on directly traced original/fresh control flow, not a claimed native reproduction. Existing zero-prefix tests cover the live driver and shared campaign seam, but the inspected tests do not establish preservation of the generic driver's mixed preparation profile across a truncated fresh prefix.

Follow-up qualification: the new tests at `tests/runtime/test_generic_wall_budget.py:124` and `tests/search/test_descriptor_search.py:252` now cover preservation of preparation and requested capacity across generic fresh truncation. Static review found no remaining Critical or Important issue in the requested preparation/capacity/strict-fresh contract. One stale implementation comment at `descriptor_search.py:335` still says no cross-invocation nonce claim, despite the immediately preceding strict validation and following strict scope field; this is documentation-only and was not changed while source is frozen.
