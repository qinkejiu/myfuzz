# BOOM IRQ factory-fix metadata-only plan/control independent review

2026-10-17. Initial source freeze15bc4cb. Read plan `.superpowers/sdd/boom-irq-factory-fix-metadata-plan.md`, new metadata control/launcher/tests, pure input-proof and prior immutable-recovery helper boundary. No metadata recovery, native, constructor, generator, model, build, elaboration, version query or remote preparation executed by this review.

## Medium M1 — state symlink can write historical input before audit

The new controller's `claim()` follows BASE/state without rejecting symlink components. `save`, PID and stage writes similarly follow paths. A state symlink redirected to a historical directory with no conflicting PID/claim lets the controller write operation.claim/PID/stage before protected-before inventory, unlike the previously reviewed runtime controller's check_path(state). Source inventory does not cover state, so this does not fail before the historical write.

Independent pure control loaded exact15bc4cb control bytes through git show, used only TemporaryDirectory paths, redirected operation/state to a mock historical directory and invoked claim. Observed claim_rejected=false and protected_directory_modified=true (new operation.claim). No operational metadata/native action occurred. Owner was notified to reject symlink target/parents before claim and every write; add old-tree unchanged RED→GREEN controls. Initial verdict M1 pending.

## Plan/source boundary otherwise reviewed

The actual prior failure265026/265033 is kept as Python pre-native Runner ownership rejection, with zero CPU/GPIO lifecycles/commands; it is not IRQ semantic failure or timeout. Minimal factory correction gpio_irq→gpio.irq preserves64 delivery/6000+512 limits, program, generic Runner, CPU session/generator/helper/probes/driver and hardware. The source-only input-proof separates new top-level factory identity from unchanged8 implementation hashes and12 actual compiled INPUTS (not an invented13th), unchanged program/binary and original0/0/1 origin receipts.

The plan uses a new source/project-finalized/artifact-finalized base. Existing recover_metadata is reused unchanged, including its actual archive/effective-input/recovery-origin checks; no hand-edited manifest or constructor bypass is proposed. New factory and manifest/path identity are honest new metadata, while runtime_verified/source_authority/new_cpp_build remainfalse. The old metadata cannot authenticate the corrected factory and is never silently reused.

Control checks exclusive use, prepared source hashes, imported helper origins/hashes, exact factory byte delta, unchanged helper and implementation map, archives, effective compiled inputs, independent copied source/artifact inodes and final recovery origin. Before/after audits cover original build, old finalized source/artifact, failed runtime source/first and current source/tools. Post-audit failure forces worker failure and marks only the new output incomplete. These checks should remain intact when fixing M1. Future metadata operation and native gate require separate exact authorization and new final ready pins; this review is neither.

## Corrected controller source re-review

M1 resolved in the following owner-frozen bytes (final remote-ready/operation is not yet reviewed):

- control.py `2d1879526d53d7159dc9001491a6f2a2742cdd75ad12a9968a13d63b1c57824b`
- run-control.sh `b3d43ecfbae4480fbe960e4d5ff7f7fb89386bd1ad8313d4ab77248f7f9ac2df`
- test_control.py `312147217716b4cd29b6053ca5bcc5ee91d7f60f27dcab2bfdc70bca7a9c0141`

All three SHA values independently matched the reviewed local bytes. Claim now rejects state/BASE/all-parent symlinks before any write. Fresh receipt/PID/claim/exit paths reject symlinks and shared file inodes and use exclusive creation. Relative receipt names reject traversal. Only the controller-owned stage and new-output incomplete marker permit checked updates; prior stage/import/result/failure state refuses operation reuse. Preparation imports will be stored separately so operational imports remain a fresh receipt.

Independent command: `PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q .superpowers/boom-irq-factory-fix-20261017/test_control.py` —actual exit0, **13 passed in0.06s**. New controls directly require state-symlink refusal before historical writes and existing/symlink receipt preservation. Owner's separate RED2 is preserved. No operational recovery, tool/version query, constructor, model or remote action ran.

Corrected **source-plan/control** verdict: no remaining high/medium blocker. This does not approve an unreviewed new preparation script or claim actual metadata recovery/remote ready. Final new-source/ready/control manifests, protected before/after receipt and exact operation authorization must still be checked independently before any metadata invocation; later native execution requires a further distinct frozen gate/GO. Old failure and old metadata/source/binary remain historical unchanged inputs.
