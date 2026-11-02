# F6 cross-invocation replay failure: read-only root cause

No production/test source was changed and no native execution or test run was started. Evidence is the existing `runs/config-driven-20261028/dma-f6/{original,fresh}` tree under the input-strategy audit directory. The failed external fresh must remain failed evidence; the findings below do not retroactively certify it.

## Two independent equality mistakes

Both invocations have a complete one-case native prefix and a successful full within-invocation native replay. They have identical records and online_plan, 2,843 actual events each, and identical final clocks (`cpu=154`, `dma=173`). The original and fresh input_declarations and generated wiring_contract files are byte-identical.

The path compile request has exactly one difference: `/wiring/source` is the absolute generated wiring filename under `original/generated` versus `fresh/generated`. Their `compiled_paths.json` documents have exactly one difference: `/identity/request_sha256`. This directory-name difference propagates through the full request hash, compiled document hash, runtime-path admission and execution binding. It also enters the checker/manifest identity. This is an identity-generation defect at the request input boundary, not evidence that the hardware dataflow changed.

Separately, F6 semantic_hash is the hash of its raw actual event journal. That journal deliberately includes actual CPU/DMA execution nonces, structured and repr-form transaction keys, and nonce-derived authenticated memory commit IDs. Raw semantic hashes are therefore unequal even for the already-successful internal replay within each single invocation. Driver `_prefix_identity` incorrectly requires raw semantic_hash equality across processes instead of using F6's existing audited native replay projection.

| Field | Original | Separate fresh |
|---|---|---|
| raw semantic_hash | aeb44a044a072cd6c0b1cd52fc419236f4dec11059b32a0709ca1fab604c1607 | 79e5f0a06a3e4b832dac4fa8693b0a8b068f95bf2683d9917c3e7f6fe5aaf181 |
| trace_genome_sha256 | c49469a61d0cba32502762f870a03004929686520bbf100831da87378b728632 | same |
| compiled_document_sha256 | 35fe8adca77962026951e295bef6c6503df09382135bbbb02ed9920b4bdd71e3 | 46a88ab65a0428cc974182967aa1a35bfbce13d1d0c333b7b1b73c101ddf7f5a |
| request_sha256 | 57e1f35c755eab09ee22b8d32442990715ec49a67ee96b9daedcaf5ed19772cd | c141be60c99910f661481bcfe788b738c2352c625053b19865d17e4e26372851 |
| execution_binding_sha256 | 2d57b3dff5e2fe848258fbc5d6128f20f5441388dff4ad5ef9cfb5d5907743da | 1ef79bb66976005b2d346323fa40bcf594f2313647d45f85d241b92bfd460e4b |

The original's own successful internal replay has raw semantic hash `4896850dca490905dd8e525a51866abd85a46334df2095b2ed9e83e8ec9495c5`, differing from the original while retaining its compiled/genome identity. This directly demonstrates that a raw semantic hash inequality is not itself an F6 behavior inequality.

## Exact residual comparison

Both saved raw semantic hashes recompute correctly from their own actual_events, trace_status and trace_local_ticks. No raw trace/hash corruption was detected.

Applying the existing `CompiledF6Runtime` `_normalized_f6_prefix` to the complete saved prefixes leaves 220 scalar differences:

- execution binding digest: 197 occurrences;
- compiled document digest: 16;
- request digest: 3;
- runtime admission digest: 3;
- trace manifest digest: 1.

The first four identity chains are explained by the single request wiring path difference. Manifest configuration also includes the execution binding, so its change is consistent with that propagation; retaining strict manifest equality after the source fix will reveal any additional unexported manifest difference.

For diagnosis only, replacing each side's five corresponding identity values with the same five typed labels after the existing normalization makes the entire complete-prefix documents equal. This was not written to saved evidence and must not become the production fix. No signal/data/address/ordering/clock/record difference remains under that bounded diagnostic. Production must continue comparing actual compiled/admission/binding/manifest values once their request source is stable.

## Strict repair after all native work stops

1. At F6 preparation, embed this run's generated wiring contract document in the path compile request using the loader's existing closed inline-wiring support. The worker has prepared `/tmp/f6-inline-wiring.patch`. This binds request identity to the full actual wiring content rather than an output directory name. It does not delete request/compiled/admission/binding hash fields or bypass generated/provider/source validation.
2. Before projecting a completed F6 prefix, recompute its raw semantic hash from the entire actual journal/status/clocks and reject any mismatch. Recompute its canonical online-plan SHA and require equality with trace_genome_sha256.
3. Reuse the existing `_normalized_f6_prefix` on the complete prefix, and compare a SHA-256 of its full canonical result. That existing function authenticates memory commit documents before rewriting references, normalizes only known owned process nonces/transaction keys, and retains behavior and binding fields. Keep strict genome, plan, compiled-document and manifest comparisons.
4. Keep the independent `_execution_index`/cross-invocation execution comparison: actual current launches, clean reaped exits, unchanged build/binary/artifact/manifest, and globally disjoint nonces. Saved canonicalized evidence grants no live authority.

Prepared driver patch: `/tmp/f6-cross-invocation-driver.patch`. Prepared existing fake-prefix fixture adaptation: `/tmp/f6-cross-invocation-fixture.patch`. Neither patch has been applied. The source freeze remains intact.

## Proposed software RED/GREEN and acceptance checks

`/tmp/test_f6_cross_invocation_regressions.py` contains five proposed, unexecuted software tests: owned nonce changes raw hash but not full normalized prefix; changed actual data remains different; wrong raw hash is rejected; online-plan/genome mismatch is rejected; and a forged memory commit digest is rejected by the existing canonicalizer. Existing driver fixture tests need the companion fixture patch because their old fake F6 prefix did not include a real internally consistent trace/genome.

Additional integration regressions should check two new generation directories produce the same inline wiring request/compiled identity, while a changed real wiring field produces a different identity or an admission refusal; same prefix with new valid launches passes external comparison; changed data/address/event order/ticks/binding/source/plan fails; and actual nonce reuse/build drift/unclean exit still fail.

After source/test changes are validated and frozen, run a new original/separate-fresh pair into new output directories. Existing original/fresh evidence must remain preserved, and must not be edited or relabeled to pass under a new implementation/source manifest.

## Repair applied after explicit unfreeze

After all active native work stopped, the root explicitly authorized the driver repair and worker-owned inline-wiring change. The five proposed driver regressions were added first; four failed for the expected raw-nonce/hash/integrity reasons before the code change. The existing real-data-change negative case already rejected changed behavior. The driver and its internally consistent fixture patch were then applied: 26 driver tests passed, 41 driver/existing replay-projection tests passed, and the broader search/runtime-budget/package/research gate passed 122 tests. No native test was run by this agent. The preparation worker reports its inline identity/provider checks separately. The original failed pair remains unchanged. Driver/test source is frozen for new native acceptance.
