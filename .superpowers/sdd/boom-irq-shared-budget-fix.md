# BOOM IRQ explicit shared total step budget

Parent approved explicit shared6512 actual local-step cap. Source-only change in boom_gpio_irq_verification.py factors ResourceBudget into shared_resource_budget: max_scheduler_steps=STEPS+QUIESCE. Genome main outer scheduling remains6000; maximum quiesce remains512. Nested router target steps consume the same total cap, leaving no unconditional512-step quiesce reservation. Wall300000ms, IRQ64ticks, firmware and genericRunner remain unchanged. No measured24/488 constant is introduced.

step_accounting reports successful main direct events, indirect local steps, quiesce direct events, per-component and total physical steps, requested limits and explicit reservation=false. Failed-before-effect steps are not counted as actual local steps. It does not make a completion/retirement claim.

## RED/GREEN

Focused actualScenarioRunner/DependencyScheduler/DataflowRouter software fixture performs one real routed synchronous register access, adding3 target steps to6000 outer calls. The old6000 globalcap fails; shared6512 completes at6003. Separate actualRouter nearcap cases:6507 target steps +CPU1+indirect3+quiesce1=6512 drains;6508+CPU1+indirect3=6512 refuses the next quiesce step before effects and remains6512. Test fixture's3 is declared software target latency, independent of observed native24.

Original-cap precise regression:4failed1.35s. Final gate+factory suite:51passed5.50s. Earlier missing-helper RED is preserved separately. These tests invoke no native/model/constructor/build/tool query.

## Saved actual diagnostics (not gate admission)

Read-only diagnose-saved-consumers.py directly runs validate_transport, validate_pulse, source_witness and temporal_witness against the immutable actual attempt2 first.json.gz. All four observation checks match. Originalstatus remains budget_exhausted; original SHA unchanged; gate_pass=false. temporal references retain actual source, native A/D raw IDs, trap/CSR phases, status/clear result stores, MRET429 and foreground acceptance. No saved status is rewritten and validate_run continues to reject the saved run.

Actual accounting: main5976, indirect24, quiesce0, total6000. Full native evidence eb695cb stays immutable; later source control cannot reclassify its failure.

## Identity and future operation

shared-budget-identity-proof.json hashes all8 implementation files against actual manifest3f405a...f89d: all unchanged. Factory pin also unchanged. Verification module is not one of8 implementation hashes, generated C++ INPUTS or top-level factory field; no builder/session/helper/profile/firmware changes occur. Therefore this host gate-only change requires a new copied runtime project and source-freeze/ready identity, but does not require metadata re-finalization or a C++ rebuild. The original artifact and failed attempt2 must remain read-only; any future constructor still performs its ordinary source authentication. This statement is source-based, not an executed constructor claim.

Current gateSHA d199fb5d49a52e978990a4b963ae877d159548ec2f42cf7765bbdaf1662bfd9b; testsSHA8a14e7a9653ec7a8d55d608d2e080251ba192efb658bc30ea44edfdb051f3d20. Independent source review is requested before any next preparation. No remote preparation, metadata operation, model, constructor, describe, build or new native gate was run for this fix.
