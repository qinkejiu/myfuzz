# Closed APB storage source contract implementation

2026-10-17. Approved design: bd1c3b8 plus `.superpowers/sdd/f4-genuine-new-ip-readonly-design.md`. Scope is only new `src/myfuzz/local_harness/apb_storage_source_contract.py`, new pure tests and this report/receipts. Renderer/session/build/authority/compiled F4 admission are unchanged. No frontend, elaboration, DUT build, model, metadata operation or native was executed.

## Design and self-review

The selected design is one code-owned registered source/parameter/register contract, not arbitrary RTL inference, caller hierarchy callbacks or readback prerequisites. Selection accepts only contract_id/register. Registry ID `pulp-apb-timer.ctrl0.source.v1` requires the complete two-file closure, exact SHA/revision/top and APB_ADDR_WIDTH12/TIMER_CNT2 with no defines/include/filelist/repository expansion. It reads actual source bytes on every selection and validation, rejecting symlink components and missing/changed files. Declared revision plus known file bytes is not advertised as a new Git/elaboration proof.

Typed profile facts must agree: HCLK; asynchronous active-low HRESETn; declared12/32 bus widths;4096-byte window/alignment; exactly one TIMER0_CTRL at4/32/rw/ordinary selected-register storage behavior, with no contradictory reset/mask declaration. Frequency/domain labels do not select the contract, nor does component_id. A renamed real timer matches by source; GPIO renamed pulp_timer still refuses. Only the selected field is registered: COUNT's autonomous behavior and TIMER1_CTRL are not implicitly admitted.

The descriptor records all reviewed CTRL writers: bank reset, regs_n=regs_q hold, selected APB overwrite and sequential commit; source review spans include other COUNT/CMP writers and control effects. Raw physical decode is PADDR[4:2]==1, mask0x1c/value4. Both ignored high bits5..11 and low bits0..1 alias, giving512 raw addresses/128 aligned words. Host4-byte alignment is a separate transport rule and never suppresses an actual alias writer. The pure address predicate implies no transfer acceptance or live-source check.

The complete source expression `u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1]` is explicitly prospective, not codegen/native hierarchy verified. Every descriptor carries scope=source_reviewed_contract and authority/native/hierarchy/reset/version/source authority false. Strict canonical JSON comparison includes bool/int distinctions, complete fixed writer/decode/expression facts and descriptor digest; serialized caller alterations cannot define a new contract. Returning JSON does not issue a token, admit a producer or bless a future generated probe. Later source/build/process/reset/command eligibility must independently recheck all pins and actual hierarchy/probe wiring.

## Implementation plan executed

1. Inspect actual source/profile/spec and write pure selection/alias/negative controls.
2. Observe valid missing-module RED, implement minimal closed descriptor and revalidation.
3. Add real-profile width contradiction RED, implement strict widths; rerun all controls.
4. Inspect source boundary, source-mutated revalidation, typed JSON and all4096 raw aliases; save receipts and freeze for independent root review.

## Actual software receipts

Command throughout: `PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q tests/local_harness/test_apb_storage_source_contract.py`.

The first attempted RED was **invalid**: the no-tool fixture replaced Popen before package import-time producer pins initialized, causing an unrelated AttributeError. That fixture failure and an attempted prototype GREEN remain in `.superpowers/apb-storage-source-contract/{invalid-initial-red,import-guard-failure,prototype-green}.log`. They are not feature RED evidence. The prototype module was deleted; package pins were initialized before the no-tool fixture, then actual missing-module RED was rerun before the final implementation was written.

- Valid `red.log`: actual pytest exit1,47 failed0.53s, missing module/feature.
- `green.log`: exit0,47 passed0.41s.
- `width-red.log`: exit1,3 failed48 passed0.44s, wrong address/data width and bool-as-address-width declarations accepted before the targeted fix.
- `green-final.log`: exit0,**51 passed0.42s**; all subprocess construction/run forbidden by fixture after import initialization. The tests perform only file reads/copies, profile loading and Python source-contract logic.

Coverage includes actual pinned timer, GPIO/name spoof, closure/revision/top/parameter mismatches, arbitrary selector evidence/expr, all4096 raw aliases, actual writer/reset/read/decode/top-wire byte mutations, wrong profile register/reset/clock/width declarations, unknown serialized facts, typed false≠0, source changed after selection, missing/symlink inputs and independent returned containers. No passing software result is relabelled native evidence.

## Remaining work

Independent source review is required before generation integration. Later codegen must verify actual hierarchy and read-only probe connectivity; common build/process/reset/command producer eligibility and live single-use version authority are not implemented. Generic timer F4 runtime remains refused. Continuous/fresh native gates and full P7 remain open.

## Frozen source/evidence

- src/myfuzz/local_harness/apb_storage_source_contract.py: `218bfff13fa4b8d793b7fce7d196e5ffe9492a9a26bb2eeb6061cb33e6c68eac`
- tests/local_harness/test_apb_storage_source_contract.py: `b7cebec1b6b34f1059ec0291073728817503d34caf03898aeffbed17622717c6`
- Raw software receipts archive `.superpowers/apb-storage-source-contract/receipts.tar.gz`: `6efce3364644da613aae1b1c8c038731c37b4d0b60b9bae1258234e57225bd48`
