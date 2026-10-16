# B: closed generated producer/reset integration

## Scope correction recorded during C (2026-10-17)

The original full B158/35 regression receipt remains real test output, but the blanket no-frontend description above/below was inaccurate for its existing mechanical fixture: native_factory invokes ibex_pulp_dual_source._artifact→plan_local_harness→real elaborate_profile. New B selected-generic focused controls used explicit saved facts, but the whole original scope was not proven frontend-free. No DUT build/model/native claim follows. This historical scope error is preserved rather than retroactively called pure. C's explicit saved-ABI/tool fixture/Popen-guard wrapper now reruns the same existing mechanical controls without frontend/tool/model launch; see apb-storage-version-implementation-report.md and recorded argv/exit receipts.


2026-10-17. Implements the approved B brief, following A60d692f/root dc14fa3 review. CPU owner completed independent local source copy/fullhostfreeze c02134412a742eccde99746af5487f81c2f77f09a7cf20250ce37f2077762e8f before session edits. No remote/frontend/elaboration/DUT compilation/model/native operation. No storage-version, Runner reset-evidence, generic F4 admission or prerequisite issuance changes.

## Implementation

New `native_reset_producer_contract.py` holds a closed two-module class registry. GPIO and generic APB module bodies seal original class, immutable declaration table, and all resolved function/code references once at definition completion. Origins are kept in an independent lexical closure, not learned at first observer request. Sealing rejects foreign execution/resealing: actual module globals and complete Python module-code equality are checked against its current source bytes. This is Python source inspection, not RTL frontend execution. There is no user registration interface or JSON eligibility path. Both mutable module aliases and their apparent `_PIN` aliases must still equal the independent sealed originals. Session independently pins registry module/function/code/origin-checker/table/dependency references.

Generic APB requires exact class, registered canonical storage probes, empty tuple setup/probe lists and exact empty dict dynamic/bound input registries. Canonical whole-wrapper/runtime/probe reconstruction rereads the registered source bytes every observer operation. In-memory canonical-projection dependencies are module/function/code-pinned, and their files join observer source closure. Generic subclass, alternative class, instance shadow, method/class declaration/table/registry drift refuse. GPIO retains all previous specific pin-table checks plus sealed origin checks; its command/timing behavior is unchanged.

Common base/build/wire/Popen/operation-domain/private issuance checks remain. Real `_command_impl` calls observer methods directly, with the original callback frame checks. APB `_take` now mirrors GPIO's finally-safe revocation on postparse consumer failure. Artifact/source/process/epoch/command uncertainty poisons observation through existing guards. Exact AST equality against60d692f for prepare/begin/command/abort/reset/end/native-eligibility and both frame/origin helpers is recorded in `unchanged-producer-functions.json`.

## Evidence and limits

- Intended initial RED: canonical selected generic APB denied by old exact-GPIO observer (1 failed,15 passed,16 timer-only fixture skips).
- Root review attention reproduced: replacing public/private class and declaration/resolved tables *and both apparent pin sides* admitted alternate class. `both-sides-red.log`:1 failed1skip. Independent module-execution origin seal closes that specific counterexample; checker+checker-pin replacement and foreign sealing calls also refuse.
- Additional strict input-map RED: replacing empty maps by `None` was accepted, four actual failures in `input-shape-red.log`; now exact empty dicts are required.
- Existing GPIO tests use real bounded Python Popen/wire peers, explicitly mechanical and native-ineligible. New generic Python peer exercises actual begin→base command→reset/reap→fresh process→close frames, remains native-ineligible, and does not provide any RTL storage or waveform proof. Its first fixture attempt omitted canonical JSON sorting and failed wire parsing; fixed canonical sorting only, no parser weakening.
- No fake build issuance: selected generated fixture and Python peer return native eligibility false; a public build-like tuple is refused by the existing private weak registry. Authority flags `grants_storage`, `grants_version_dependency`, prerequisites and functional grants remain false.
- Pure saved frontend facts are generation fixtures only. New fixture restores real Python producer functions before observer admission; it does not substitute build eligibility, producer/frame logic or observer checkers.
- Final command/results recorded below. Skips are parameterized generic tests on GPIO fixture variants, for which registered timer-only storage is inapplicable; separate actual GPIO mechanical suites execute. Skips do not count as passes or native gates.

Actual timer hierarchy/native reset waveform, storage reset/write/hold equation, alias version tracking and native source/version authority remain pending. READY and a parsed command are only mechanical evidence. This increment does not accept full F4 new-IP or P7.

## Owned files

New registry + focused test; `session.py`, `gpio_session.py`, `apb3_register_session.py`, `native_reset_observation.py`; approved brief, report and source-only receipts. No renderer/driver/build/F4 source edited in B. Exact source/test SHA freeze in `.superpowers/apb-storage-producer-reset/freeze.json`.

## Final frozen receipt

`PYTHONPATH=src python3 -m pytest -q tests/local_harness/test_native_reset_observation.py tests/local_harness/test_native_reset_observation_boundaries.py tests/local_harness/test_native_reset_producer_contract.py tests/local_harness/test_apb_storage_probe_generation.py tests/local_harness/test_generic_apb_identity.py tests/local_harness/test_generic_apb_trace_verification.py`: **158 passed,35 skipped,35.75s; actual pytest process returncode0**. Exact argv/exit in `pytest-exit.json`, output in `green-final.log`. An identical preceding frozen run also passed158/35 in35.30s. No implementation bytes changed between these final two runs. `git diff --check` clean.
