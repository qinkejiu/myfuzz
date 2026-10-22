# CV32E40P + PULP Timer APB3 compiled F4 sibling

Date: 2026-10-20

## Result

The compiled F4 executor runs on a second RV32I/OBI CPU instance: CV32E40P
with the registered PULP Timer `TIMER0_CTRL` APB3 source contract. The
archived native run selected `compiled-f4-rfuzz` without requesting a
runtime family. It completed with exit code 0, no absences or refusals, four
certified cases, RFuzz client return code 0, and a full fresh prefix replay
with `matches=true`.

The D1–D3 projection contains six paths: four declared executable and two
unsupported. The selected path was `F4:ram.image`; this slice does not claim
that every executable D3 path has a runtime executor.

## Bound identity

The archived run used `compiled_F4_execution_binding.v1` with binding
SHA-256 `a2577e082c5941b010c283e9056f854fc507fa4e4598d10feb265113dcf844d7`,
compiled document SHA-256
`69085f226e845b7ef01562a3af23073045f7d4ed03cc1f1cfbf816f63eb96e0d`, and
candidate layout SHA-256
`931640d4fecbdca3ddc29c9d1cc8b534df9c0e569dee8135dd96d0ab693317b5`. The
binding includes per-file hashes for both generated artifacts' wrapper,
runtime, driver, ABI, artifact document and source verification, along with the
selected F4 path, CPU OBI/error trace contract, target window, source producer,
prerequisite and assertion identities.

The registered producer row is `generic_apb_storage_abi` for source contract
`pulp-apb-timer.ctrl0.source.v1`: APB3 full-word access to `TIMER0_CTRL` at
`0x40001004`, inside the `0x40001000` / 4096-byte window. The emitted exact-hop
proof scope is
`selected_F4_image_consumption_native_OBI_route_native_APB_generic_apb_storage_abi_live_TIMER0_CTRL`.

## Fresh replay and refusal controls

The primary and fresh CPU and target processes have distinct PIDs and execution
nonces; all four DUT processes were reaped with return code 0. The full fresh
replay matched all four records and 1,072 events. Both prefixes carry the same
execution-binding SHA and normalized semantic SHA. The run records a 478-file
Python source closure, including `replay_normalize.py`; this is the source
snapshot used for that native run. Later software changes are not covered by
that closure and have not been validated by another native run.

Focused negatives now construct the real `CompiledF4Runtime` entry point for a
similarly named component identity, changed assertion/window, and a half-word
APB template. Each refuses before `subprocess.Popen` is called. The storage
consumer also rejects a changed `build_identity_sha256` between before and
after witnesses from the same live target process. This comparison does not
pin process PID or execution nonce across fresh replay. Existing negatives
retain wrong protocol, register, address, offset, width and mask refusals.

The independent test review identified two medium verification gaps; the
software follow-up addresses them. A further negative combines a similarly
named profile with a wrong APB template and requires the template-specific
refusal before `subprocess.Popen`. The latest scoped command
`PYTHONPATH=src python3 -m pytest -q tests/integration/test_compiled_f4_execution_binding.py tests/integration/test_compiled_f4_storage_producer.py`
returned **83 passed in 54.94s**. The earlier scoped run returned 82 passed in
53.93s, and the broader regression was **112 passed, 1 skipped in 221.83s**
on the source tree used for the archived native run. The latest software tests
did not rerun native execution; the native evidence remains the separately
archived run with binding
`a2577e082c5941b010c283e9056f854fc507fa4e4598d10feb265113dcf844d7`. Its
copied prefix and fresh-verification files match the `current` run directory
and are listed in the current evidence manifest below. The older `final`
evidence bundle remains unchanged and has a different binding. A read-only
follow-up review confirmed the original findings and combined negative are
closed. The build-identity mismatch negative uses the consumer test's
synthetic authority token path; the real authority's token issuance remains
tied to its native-eligible build digest.

## Scope limits

This proves a second OBI CPU instance can use the existing registered PULP
Timer APB3 F4 contract through the compiled executor. It does not add another
APB3 source contract or infer arbitrary register semantics from a protocol
label. It does not close P7 D1–D4/E overall, P6, P8, DMA F6, the four IP-series
goal, or six-CPU adaptation as a whole.

## Reproduction and evidence

```bash
PYTHONPATH=src python3 scripts/auto_harness_test.py \
  --cpu configs/cpus/cv32e40p/component_profile.json \
  --ip configs/peripherals/pulp_timer/component_profile.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/test_capability.json \
  --compose configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/compose.json \
  --executor compiled-f4-rfuzz \
  --client-binary runs/rfuzz_client_native_build/target/debug/kfuzz \
  --budget-seconds 60 --max-tests 8 --rounds-per-case 32 \
  --output runs/p7-f4-cv32e40p-apb3-sibling-current-20261020 \
  --cache-dir .superpowers/compiled-f4/cache
```

The archived run returned exit code 0. Its full output is preserved at
`runs/p7-f4-cv32e40p-apb3-sibling-current-20261020/`; selected evidence and a
SHA-256 manifest are in
[`evidence/p7-f4-cv32e40p-apb3-sibling-current-20261020/`](evidence/p7-f4-cv32e40p-apb3-sibling-current-20261020/).
The earlier run remains preserved at
`runs/p7-f4-cv32e40p-apb3-sibling-final-20261020/` and its older evidence
bundle remains unchanged; the archived claim uses the rerun above.
