# Arm equivalence (arm_equivalence.v1)

- left arm: `runs/current-dataflow-p5-paired-20261007-online` (label `paired_continuous`, run_id `current-dataflow-p5-paired-20261007`)
- right arm: `runs/current-dataflow-p5-paired-20261007-cold-start` (label `paired_cold_start`, run_id `current-dataflow-p5-paired-20261007-cold-start`)

## Compared

The arms share a decodable identity and a non-empty shared raw-input window.

## Comparison window

the leading receipt cases whose raw_sha256 is identical in both arms, compared in receipt order; the searches diverge by construction, so this prefix is the only per-case comparable window

| quantity | left | right | shared |
|---|---|---|---|
| receipt cases | 24 | 24 | 24 |
| declared tests | 24 | 24 | - |
| declared statuses | {"complete": 24} | {"complete": 24} | - |
| covered by the window | True | True | - |
| window case cap | 200000 | 200000 | reached=False |

Raw-records cross-check (online_raw_records_hex): 24/24 agreed.

## Declared budgets

| quantity | left | right | equal |
|---|---|---|---|
| max_tests | 24 | 24 | True |
| duration_seconds | 30.0 | 30.0 | True |
| feedback_interval | 16 | 16 | True |
| search_seed | 20261007 | 20261007 | True |
| global_mutation_seed | 20261007 | 20261007 | True |
| declared_tests (realized case count) | 24 | 24 | True |

same declared budget: True; same declared case count: True

## Per-family equivalence

| family | verdict | driver | equal | unequal | miss L | miss R | miss both | reason |
|---|---|---|---|---|---|---|---|---|
| status | equivalent | status | 24 | 0 | 0 | 0 | 0 | status: status is identical in all 24 window cases |
| effective_genome | equivalent | effective_genome_sha256 | 48 | 0 | 0 | 0 | 0 | effective_genome_sha256: effective_genome_sha256 is identical in all 24 window cases |
| path | equivalent | path_id | 48 | 0 | 0 | 0 | 0 | path_id: path_id is identical in all 24 window cases |
| direction | equivalent | direction | 24 | 0 | 0 | 0 | 0 | direction: direction is identical in all 24 window cases |
| applied_sources | not_equivalent | applied_source_ids | 63 | 9 | 0 | 0 | 0 | applied_source_ids: applied_source_ids differs in 9 of 24 window cases |
| checker_violations | equivalent | violations | 24 | 0 | 0 | 0 | 0 | violations: violations is identical in all 24 window cases |
| coverage | not_equivalent | coverage_hex | 2 | 22 | 0 | 0 | 0 | coverage_hex: coverage_hex differs in 22 of 24 window cases |
| local_ticks | not_equivalent | local_ticks | 18 | 30 | 0 | 0 | 0 | local_ticks: local_ticks differs in 15 of 24 window cases |

The counts above sum the family's in-scope *verdict-role* fields; context-role fields are listed per field below and never define a family verdict.

## Per-field detail

| field | role | in scope | verdict | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|---|---|
| status.status | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| effective_genome.effective_genome_sha256 | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| effective_genome.genome_sha256 | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| path.path_id | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| path.applied_path | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| direction.direction | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| applied_sources.applied_sources | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| applied_sources.applied_source_ids | verdict | True | not_equivalent | 15 | 9 | 0 | 0 | 0 | [1, 3, 6, 10, 14, 15, 17, 18, 2… |
| applied_sources.source_id | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| checker_violations.violations | verdict | True | equivalent | 24 | 0 | 0 | 0 | 0 | [] |
| checker_violations.rejection | context | False | not_applicable | 0 | 0 | 0 | 0 | 24 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| checker_violations.error | context | False | not_applicable | 0 | 0 | 0 | 0 | 24 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| coverage.coverage_hex | verdict | True | not_equivalent | 2 | 22 | 0 | 0 | 0 | [1, 2, 3, 4, 5, 6, 7, 8, 9, 10,… |
| local_ticks.local_ticks | verdict | True | not_equivalent | 9 | 15 | 0 | 0 | 0 | [1, 2, 3, 6, 8, 9, 10, 12, 13, … |
| local_ticks.total_local_ticks | verdict | True | not_equivalent | 9 | 15 | 0 | 0 | 0 | [1, 2, 3, 6, 8, 9, 10, 12, 13, … |

## Output equivalence claimed = False

output equivalence is claimed only when the shared raw-input window covers both arms completely, both arms have the same receipt case count, the window was not truncated by the case cap, and every in-scope declared field is equal in every window case; a `compared` evidence status never implies it

| condition | satisfied | detail |
|---|---|---|
| window_computable | True | shared raw-input prefix of 24 case(s) |
| same_receipt_case_count | True | left 24, right 24 |
| window_covers_left_arm | True | window 24 of left 24 |
| window_covers_right_arm | True | window 24 of right 24 |
| window_not_truncated | True | the cap was not reached |
| every_inscope_field_equivalent | False | 13 in-scope verdict field(s); 4 unequal, 0 family/families unknown |
| every_family_equivalent | False | not_equivalent ['applied_sources', 'coverage', 'local_ticks'], unknown [] |

Why output equivalence is not claimed:

- every_inscope_field_equivalent: 13 in-scope verdict field(s); 4 unequal, 0 family/families unknown
- every_family_equivalent: not_equivalent ['applied_sources', 'coverage', 'local_ticks'], unknown []
- applied_sources.applied_source_ids (verdict) differs in 9 window case(s): [1, 3, 6, 10, 14, 15, 17, 18, 22]
- coverage.coverage_hex (verdict) differs in 22 window case(s): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
- local_ticks.local_ticks (verdict) differs in 15 window case(s): [1, 2, 3, 6, 8, 9, 10, 12, 13, 15, 16, 17, 20, 21, 22]
- local_ticks.total_local_ticks (verdict) differs in 15 window case(s): [1, 2, 3, 6, 8, 9, 10, 12, 13, 15, 16, 17, 20, 21, 22]

Declared fields that carry no information in this window (reported, never counted as equal): `checker_violations.error`, `checker_violations.rejection`

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

Difference classes: other=5, run_bookkeeping=3, timing=3; tracked 27 of at most 64 field(s), truncated=False.

| field | class | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|
| interaction_deferred | other | 23 | 0 | 1 | 0 | 0 | [15] |
| interaction_feature_deltas | other | 23 | 1 | 0 | 0 | 0 | [15] |
| interaction_new_features | other | 23 | 1 | 0 | 0 | 0 | [15] |
| interaction_source_gains | other | 23 | 1 | 0 | 0 | 0 | [15] |
| semantic_sha256 | other | 1 | 23 | 0 | 0 | 0 | [1, 2, 3, 4, 5, 6, 7, 8, 9, 10,… |
| buffer_id | run_bookkeeping | 1 | 23 | 0 | 0 | 0 | [1, 2, 3, 4, 5, 6, 7, 8, 9, 10,… |
| run_id | run_bookkeeping | 0 | 24 | 0 | 0 | 0 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| slot | run_bookkeeping | 2 | 22 | 0 | 0 | 0 | [2, 3, 4, 5, 6, 7, 8, 9, 10, 11… |
| online_phase_timing_seconds | timing | 0 | 24 | 0 | 0 | 0 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| online_runner_timing_seconds | timing | 0 | 24 | 0 | 0 | 0 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| online_submit_timing_seconds | timing | 0 | 24 | 0 | 0 | 0 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |

Read scope: `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (left); `receipts.jsonl`, `report.json`, `online_run_identity.json` (right). No trace container was opened.

