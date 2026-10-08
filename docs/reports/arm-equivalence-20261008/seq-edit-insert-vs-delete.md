# Arm equivalence (arm_equivalence.v1)

- left arm: `runs/p4-sequence-edit-insert-20261008-online` (label `seq_edit_insert`, run_id `p4-sequence-edit-insert-20261008`)
- right arm: `runs/p4-sequence-edit-delete-20261008-online` (label `seq_edit_delete`, run_id `p4-sequence-edit-delete-20261008`)

## Refused (`zero_shared_prefix`)

the arms share no raw input case: the first case (index 0) already diverges (raw_sha256_differs, left raw 0e82fe6fcf188adfd352dce52b6a0c53cca9418b2d05c1d5ee4c7cba781425d3, right raw d99079771646e93f615fe282946be2a95dd8d971082e070aa2612170aa311361), so there is no per-case comparable window

## Comparison window

the leading receipt cases whose raw_sha256 is identical in both arms, compared in receipt order; the searches diverge by construction, so this prefix is the only per-case comparable window

| quantity | left | right | shared |
|---|---|---|---|
| receipt cases | 8 | 8 | 0 |
| declared tests | 8 | 8 | - |
| declared statuses | {"complete": 8} | {"complete": 8} | - |
| covered by the window | False | False | - |
| window case cap | 200000 | 200000 | reached=False |

First divergence: case 0 (raw_sha256_differs), left raw `0e82fe6fcf188adfd352dce52b6a0c53cca9418b2d05c1d5ee4c7cba781425d3`, right raw `d99079771646e93f615fe282946be2a95dd8d971082e070aa2612170aa311361`.

Raw-records cross-check (online_raw_records_hex): 0/0 agreed.

## Declared budgets

| quantity | left | right | equal |
|---|---|---|---|
| max_tests | 8 | 8 | True |
| duration_seconds | 25.0 | 25.0 | True |
| feedback_interval | 16 | 16 | True |
| search_seed | 20261008 | 20261008 | True |
| global_mutation_seed | 20261008 | 20261008 | True |
| declared_tests (realized case count) | 8 | 8 | True |

same declared budget: True; same declared case count: True

## Per-family equivalence

| family | verdict | driver | equal | unequal | miss L | miss R | miss both | reason |
|---|---|---|---|---|---|---|---|---|
| status | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| effective_genome | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| path | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| direction | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| applied_sources | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| checker_violations | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| coverage | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |
| local_ticks | unknown | - | 0 | 0 | 0 | 0 | 0 | the comparison window is empty, so no case of this family could be compared |

The counts above sum the family's in-scope *verdict-role* fields; context-role fields are listed per field below and never define a family verdict.

## Per-field detail

| field | role | in scope | verdict | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|---|---|
| status.status | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| effective_genome.effective_genome_sha256 | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| effective_genome.genome_sha256 | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| path.path_id | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| path.applied_path | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| direction.direction | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| applied_sources.applied_sources | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| applied_sources.applied_source_ids | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| applied_sources.source_id | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| checker_violations.violations | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| checker_violations.rejection | context | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| checker_violations.error | context | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| coverage.coverage_hex | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| local_ticks.local_ticks | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |
| local_ticks.total_local_ticks | verdict | False | unknown | 0 | 0 | 0 | 0 | 0 | [] |

## Output equivalence claimed = False

output equivalence is claimed only when the shared raw-input window covers both arms completely, both arms have the same receipt case count, the window was not truncated by the case cap, and every in-scope declared field is equal in every window case; a `compared` evidence status never implies it

| condition | satisfied | detail |
|---|---|---|
| window_computable | True | shared raw-input prefix of 0 case(s) |
| same_receipt_case_count | True | left 8, right 8 |
| window_covers_left_arm | False | window 0 of left 8 |
| window_covers_right_arm | False | window 0 of right 8 |
| window_not_truncated | True | the cap was not reached |
| every_inscope_field_equivalent | False | 0 in-scope verdict field(s); 0 unequal, 8 family/families unknown |
| every_family_equivalent | False | not_equivalent [], unknown ['applied_sources', 'checker_violations', 'coverage', 'direction', 'effective_genome', 'local_ticks', 'path', 'status'] |

Why output equivalence is not claimed:

- window_covers_left_arm: window 0 of left 8
- window_covers_right_arm: window 0 of right 8
- every_inscope_field_equivalent: 0 in-scope verdict field(s); 0 unequal, 8 family/families unknown
- every_family_equivalent: not_equivalent [], unknown ['applied_sources', 'checker_violations', 'coverage', 'direction', 'effective_genome', 'local_ticks', 'path', 'status']

Declared fields that carry no information in this window (reported, never counted as equal): `applied_sources.applied_source_ids`, `applied_sources.applied_sources`, `applied_sources.source_id`, `checker_violations.error`, `checker_violations.rejection`, `checker_violations.violations`, `coverage.coverage_hex`, `direction.direction`, `effective_genome.effective_genome_sha256`, `effective_genome.genome_sha256`, `local_ticks.local_ticks`, `local_ticks.total_local_ticks`, `path.applied_path`, `path.path_id`, `status.status`

## What an `equivalent` verdict does NOT claim

- an `equivalent` verdict covers only the declared per-case receipt projection inside the shared raw-input window; it says nothing about search quality (target hits, coverage novelty, chain yield, certificates) or about the trace containers, which are never opened
- `output_equivalence.claimed = true` requires the window to cover both arms completely, both arms to have the same receipt case count, no window truncation and every in-scope declared field to be equal; it is never implied by `evidence_status = compared`
- a `not_equivalent` verdict names the exact field(s) and case indexes; a field recorded only by one arm's bookkeeping path (for example the duplicated `applied_source_ids` alias) can produce a real `not_equivalent` verdict without a DUT behaviour difference, so the driving field must be read with the per-field table
- `unknown` is the absence of evidence: a declared field that is null or absent in the window - on one arm or on both - is never counted as equal
- the window is a prefix in receipt order, not a set intersection: cases that match later but not in prefix order stay outside the window
- the window proves *byte-level* raw-input identity, not source or plan identity: the same raw bytes can be produced by a different applied source (the path-switch pair is the concrete case - identical `raw_sha256` and `online_raw_records_hex` at case 0, different `online_source`, `operator_id`, path and direction), which is why the per-field comparison and `outside_declared_projection` must be read together with the window length
- the declared projection fixes the claim, not the record: receipt fields outside it (timing maps, `run_id`/`slot`/`buffer_id` bookkeeping, `semantic_sha256`, interaction deltas) are reported separately under `outside_declared_projection` and a differing `other` field there is a warning that the projection hides part of the case record
- the comparison reads saved artifacts only; no RTL, Verilator, cargo or fuzz client is started and no trace container is opened

## Receipt fields outside the declared projection

`timing` and `run_bookkeeping` differences are expected between two arms; a differing `other` field (for example `semantic_sha256`, `target_id`, interaction deltas) means the declared projection hides part of the case record and must be read before trusting an `equivalent` verdict

Difference classes: other=0, run_bookkeeping=0, timing=0; tracked 0 of at most 64 field(s), truncated=False.

No field outside the declared projection differs inside the window.

Read scope: `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (left); `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (right). No trace container was opened.

