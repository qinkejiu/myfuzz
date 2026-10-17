# Independent source review: CV32 closed-loop admission

Reviewed commit `74119a6f8155704608b3d5e26eb5281974fca79c`, specifically `src/myfuzz/integration/cv32e40p_pulp_online.py`, against the actual `_closed_loop_switch`, shared `make_pulp_dual_source_online_runtime`, `ScenarioRfuzzExecutor` initialization and default `ChainCertificates` implementation. This was source inspection only: no tests, imports, model, build or remote commands were executed. The reviewer did not modify implementation.

## Result

**No blocking finding identified within this admission change.** The new guard rejects unsupported CV32 certificate energy before generated-artifact selection, bootstrap/decoder construction, factory construction, shared-builder `factory()` and `session.begin()`. The shared producer/consumer contract is unchanged. This is an early refusal, not implementation of a CV32 certificate producer or completion of P6.

## Exact switch behavior

The wrapper calls the existing `_closed_loop_switch(closed_loop_energy, online=True)` at the first executable statement, then rejects a resolved true value. The resolver uses `type(requested) is bool`, not truthiness; constructor values take precedence over the environment. `None` reads `MYFUZZ_CLOSED_LOOP_ENERGY`, strips whitespace and lowercases its value.

| Caller | Environment | Source-inspected outcome |
| --- | --- | --- |
| `True` | any | Explicit capability refusal before admission/factory |
| `False` | true, false, invalid or absent | Accepted as explicit off; environment not consulted |
| `None` | `1`, `true`, `yes`, `on` (case/whitespace normalized) | Capability refusal before admission/factory |
| `None` | `0`, `false`, `no`, `off`, empty string | Resolved false, existing scalar online path |
| `None` | absent | Default false, existing scalar online path |
| `None` | any other string | Existing resolver ValueError before admission/factory |
| Integer0/1, string or other non-bool non-None | any | Existing resolver type ValueError before admission/factory |

These are deductions from the exact resolver branches, not executed test results. Explicit false bypassing an invalid environment is consistent with the original resolver's constructor precedence.

The wrapper forwards the resolved false as `closed_loop_energy=resolved_closed_loop_energy`, rather than leaving `None`. The shared builder therefore passes an explicit false to its final `ScenarioRfuzzExecutor`; that executor calls the same resolver and does not re-read a changed environment. Its conditional `_closed_loop_initialize()` is not entered. The shared builder's separate preflight executor used for classified-feedback/candidate options also explicitly disables closed-loop energy and path switching. The wrapper does not expose a producer-injection escape hatch.

## Why refusal matches the actual producer

`_resolve_closed_loop_producer(None, ...)` instantiates `ChainCertificates` with its default `require_native_receipts=True`. That class composes `Pin8IrqCertificates`, `Pin8CpuIrqCertificates` and retirement/target-delivery joins. Its documented and implemented hop sequences include CPU IRQ input/taken, ISR PADIN retirement, fetched/admitted instruction retirement and retired target delivery. Reusing generic local coverage milestones does not supply those authenticated joins.

`_validate_cv32e40p_retirement_flags()` explicitly refuses this CPU's `cpu_retirement=True` and the native IRQ receipt mode; the wrapper has no authenticated replacement producer. Allowing energy mode to instantiate the default producer after a real warm-up would misstate supported capability. The early refusal is consistent with this source limitation and leaves the default producer's strictness intact.

## Compatibility and bounded scope

- The added parameter is keyword-only and defaults to `None`; positional argument binding does not change. Existing calls with no energy environment still resolve off and reach the original factory with unchanged retirement/GPIO/native-receipt arguments.
- Existing observation-flag validation remains after the energy guard. When multiple options are invalid, the first reported error can now be energy refusal/type/environment instead of generated-artifact or retirement validation. This is consistent with early admission and has no DUT side effect before the guard.
- **Documented metadata difference:** disabled mode's executor `closed_loop_energy_source` becomes `constructor` even when the wrapper resolved an absent or false environment. The implementation report discloses this. It does not change disabled execution, but current reports must not be asserted byte-identical to historical reports for that field.
- Replay function `replay_cv32e40p_pulp_online_files` and the shared Ibex builder/executor are untouched. Existing CV32 retirement/native-receipt refusal remains; no historical source/build/proof identity is upgraded.
- The guard covers this CV32 wrapper. Direct callers of the generic shared builder can supply other factories and remain responsible for their capability contract; this change does not claim global CPU capability enforcement.
- Environment path-switch behavior and every unrelated opt-in remain outside this narrow patch. No four-hit feedback, persistent harness, source authority, native IRQ or retirement capability is awarded by the review.

## Remaining verification

No runtime validation was authorized for this review. A future scoped software gate should exercise the table above with generated-artifact selection, bootstrap, decoder, factory and shared builder instrumented as forbidden calls on refusal; accepted false cases should capture the exact forwarded boolean. A separate compatibility control should confirm the disclosed source-label change. Actual CV32 RTL execution is unnecessary to demonstrate these early refusal branches and would not prove the missing certificate producer.
