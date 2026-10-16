# Caliptra SHA256 generated AHB target — 2026-10-17

The fourth peripheral series now has a generated local AHB-Lite register target
that runs unmodified pinned Caliptra SHA256 RTL. Local real acceptance reached
**RTL operational** for the scoped aligned full-word register/hash path. CPU
integration, IRQ delivery and coverage-guided persistent search remain pending.

## Implementation

`target.ahb-lite@1/full-word-single` drives a distinct address phase followed by
a data phase, one outstanding access, and samples real target HRDATA/HRESP on
completion. HREADYIN and HREADYOUT have separate declared directions and passive
taps. The target's pinned wrapper ties error/hold low; internal register errors
are not bus errors. Transport timeout remains a host failure, not a DUT finding.

The generated reset schedule drives both active-low asynchronous reset_n and
cptra_pwrgood low/high for eight edges each; power-good is not held high from
initialization. Independent warm/power sequencing is outside this scope.
Debug/scan is fixed zero by its explicit port action. Configuration constant
ownership is resolved once, avoiding a second driver from the profile endpoint.

The real test exposed an incorrect static profile assumption: CTRL/BLOCK are
software **write-only** in pinned RDL/generated RTL. Their profile access was
corrected from rw to wo and the capability fingerprint refreshed. Their reads
return zero; correct writes are proven by the real resulting digest.

Shared generation/parser implementation commits: `78cc077`, `0647586`.
Generic AHB passive events/checker/base coverage were independently added in
`8caa1a2`. This real gate consumes its normalizer and checker only. It does
not invoke IpProtocolEvidenceConsumer, Runner or base coverage; full evidence
consumer/coverage integration remains pending.

An additional **offline audit of the saved real physical samples** now runs
`scripts/verify_caliptra_ahb_protocol_evidence.py` against the hashed first,
fresh and artifact files. It rebuilds the interleaved raw/event journal and
passes it through `IpProtocolEvidenceConsumer`: each run yields **91 verified
AHB transaction certificates**, zero pending and zero diagnostics. Flipping
the first projected response value yields zero certificates and one
`projection_mismatch`. The compact audit result is
`configs/peripherals/caliptra_sha256/evidence/protocol-audit-20261017.json`.
This retrospective proof does not mean the live Runner or coverage path was
exercised.

## Actual evidence

```bash
flock -n .superpowers/heavy-worker.lock env PYTHONPATH=src \
  MYFUZZ_CALIPTRA_REAL=1 \
  MYFUZZ_CALIPTRA_CACHE=.superpowers/cache/caliptra-target \
  MYFUZZ_CALIPTRA_EVIDENCE=runs/caliptra-ahb-target-20261017 \
  python3 -m pytest -q tests/local_harness/test_ahb_register_target.py --tb=short
```

Result: **2 passed in 19.95s**, local Verilator real RTL. Each process performed
91 real register accesses with exactly one physical AHB address acceptance per
access and a separate checked data phase. The generic normalizer produced
91 requests, 91 accepts and 91 responses; the generic protocol checker reported
zero violations.

Both padded abc and abd blocks execute in the same persistent local session.
Actual digest bytes match independent hashlib reference values and differ:

- abc: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
- abd: `a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9`

A fresh independent process repeats the full directed sequence: raw access
samples, normalized events, digest bytes and session identities match exactly;
process execution IDs differ. Partial/unaligned requests are rejected before
advancing local ticks. This is deterministic fresh directed re-execution, not
an authenticated saved-prefix replay claim.

Raw evidence is `runs/caliptra-ahb-target-20261017/{first,fresh,artifact}.json`.
The committed compact index
`configs/peripherals/caliptra_sha256/evidence/runtime-20261017.json` pins their
hashes and independently recomputed counts. Artifact digest is
`928f9356429ba3a8edbee75a55f408527417b01ff0abaa05a7e3c7564f603f51`.
All recorded host-source file hashes matched the current tree after execution;
future host edits require new current-source evidence.

## Regression and limits

Focused generation, template inventory, port ownership, profile/capability,
native command parser, generic register factory, APB3 construction and generic
AHB events/checker regression: **69 passed, 3 skipped, 23 subtests passed in
34.03s**. The skips are separately gated real Caliptra/APB tests; Caliptra's real
gate above was explicitly enabled and passed. No upstream RTL was changed.

The source lock still records source/elaboration status separately, as existing
peripheral entries do. This report does not promote multi-block/Winternitz,
CPU/IRQ consumption, sustained online fuzzing, fault confirmation or performance
acceptance from local generation or these directed transactions.
