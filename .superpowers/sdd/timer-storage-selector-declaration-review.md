# Independent timer storage-selector declaration review

Reviewed commit: `d9ccc0f9493031cd85634d5a2e05c17bd6ced132`.
Reviewer: CPU AXI/AHB event owner. Read-only source review; no tests, tools, model, build, elaboration, remote operation or native run executed for this review.

## Specification

The request adds exactly one registered passive `apb_storage_observations` selector: endpoint `timer.bus`, contract `pulp-apb-timer.ctrl0.source.v1`, register `TIMER0_CTRL`. This matches the registered source contract and canonical offset4/32-bit CTRL declaration. Existing endpoint policy, request profile, candidate bytes, source ownership and execution supplements are unchanged. It does not substitute passive readback for the outstanding live register-version prerequisite.

The README distinguishes passive generated taps from register probe accesses and leaves actual hierarchy/build/sample admission and F4 runtime acceptance open. It grants no native execution, source authority or P7 acceptance. The test asserts the exact selector document and retains empty request supplements, ownership and physical port map, as well as existing missing-sidecar/wrong-profile/source-writer controls.

## Quality and evidence

No high or medium finding. No requested correction.

Owner receipts show the added exact selector assertion RED (1 failed, 4 passed) before the declaration update, then GREEN (5 passed in 0.27s). Those are owner software results, not independently rerun evidence. Scope remains declaration-only; source generation and later producer/runtime/native gates are separate increments.
