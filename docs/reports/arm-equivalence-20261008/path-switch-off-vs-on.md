# Arm equivalence (arm_equivalence.v1)

- left arm: `runs/current-dataflow-p4-path-switch-off-20261007-online` (label `path_switch_off`, run_id `current-dataflow-p4-path-switch-off-20261007`)
- right arm: `runs/current-dataflow-p4-path-switch-on-20261007-online` (label `path_switch_on`, run_id `current-dataflow-p4-path-switch-on-20261007`)

## Compared

The arms share a decodable identity and a non-empty shared raw-input window.

## Comparison window

the leading receipt cases whose raw_sha256 is identical in both arms, compared in receipt order; the searches diverge by construction, so this prefix is the only per-case comparable window

| quantity | left | right | shared |
|---|---|---|---|
| receipt cases | 96 | 96 | 1 |
| declared tests | 96 | 96 | - |
| declared statuses | {"complete": 94, "input_invalid": 2} | {"complete": 91, "input_invalid": 5} | - |
| covered by the window | False | False | - |
| window case cap | 200000 | 200000 | reached=False |

First divergence: case 1 (raw_sha256_differs), left raw `819b265ed890cbfc934efd3eb9b1d56bfd62e89981421a068a63c52806ae5cce`, right raw `3343cb2bebd72e5c1d75fb8a2ccc8c3da8dbe429cae44d705459d4eaeef383da`.

Raw-records cross-check (online_raw_records_hex): 1/1 agreed.

## Declared budgets

| quantity | left | right | equal |
|---|---|---|---|
| max_tests | 96 | 96 | True |
| duration_seconds | 150.0 | 150.0 | True |
| feedback_interval | 16 | 16 | True |
| search_seed | 20261007 | 20261007 | True |
| global_mutation_seed | 20261007 | 20261007 | True |
| declared_tests (realized case count) | 96 | 96 | True |

same declared budget: True; same declared case count: True

## Per-family equivalence

| family | verdict | driver | equal | unequal | miss L | miss R | miss both | reason |
|---|---|---|---|---|---|---|---|---|
| status | equivalent | status | 1 | 0 | 0 | 0 | 0 | status: status is identical in all 1 window cases |
| effective_genome | not_equivalent | effective_genome_sha256 | 0 | 2 | 0 | 0 | 0 | effective_genome_sha256: effective_genome_sha256 differs in 1 of 1 window cases |
| path | not_equivalent | path_id | 0 | 2 | 0 | 0 | 0 | path_id: path_id differs in 1 of 1 window cases |
| direction | not_equivalent | direction | 0 | 1 | 0 | 0 | 0 | direction: direction differs in 1 of 1 window cases |
| applied_sources | not_equivalent | applied_sources | 0 | 3 | 0 | 0 | 0 | applied_sources: applied_sources differs in 1 of 1 window cases |
| checker_violations | equivalent | violations | 1 | 0 | 0 | 0 | 0 | violations: violations is identical in all 1 window cases |
| coverage | equivalent | coverage_hex | 1 | 0 | 0 | 0 | 0 | coverage_hex: coverage_hex is identical in all 1 window cases |
| local_ticks | equivalent | local_ticks | 2 | 0 | 0 | 0 | 0 | local_ticks: local_ticks is identical in all 1 window cases |

The counts above sum the family's in-scope *verdict-role* fields; context-role fields are listed per field below and never define a family verdict.

## Per-field detail

| field | role | in scope | verdict | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|---|---|
| status.status | verdict | True | equivalent | 1 | 0 | 0 | 0 | 0 | [] |
| effective_genome.effective_genome_sha256 | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| effective_genome.genome_sha256 | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| path.path_id | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| path.applied_path | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| direction.direction | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| applied_sources.applied_sources | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| applied_sources.applied_source_ids | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| applied_sources.source_id | verdict | True | not_equivalent | 0 | 1 | 0 | 0 | 0 | [0] |
| checker_violations.violations | verdict | True | equivalent | 1 | 0 | 0 | 0 | 0 | [] |
| checker_violations.rejection | context | False | not_applicable | 0 | 0 | 0 | 0 | 1 | [0] |
| checker_violations.error | context | False | not_applicable | 0 | 0 | 0 | 0 | 1 | [0] |
| coverage.coverage_hex | verdict | True | equivalent | 1 | 0 | 0 | 0 | 0 | [] |
| local_ticks.local_ticks | verdict | True | equivalent | 1 | 0 | 0 | 0 | 0 | [] |
| local_ticks.total_local_ticks | verdict | True | equivalent | 1 | 0 | 0 | 0 | 0 | [] |

## Output equivalence claimed = False

output equivalence is claimed only when the shared raw-input window covers both arms completely, both arms have the same receipt case count, the window was not truncated by the case cap, and every in-scope declared field is equal in every window case; a `compared` evidence status never implies it

| condition | satisfied | detail |
|---|---|---|
| window_computable | True | shared raw-input prefix of 1 case(s) |
| same_receipt_case_count | True | left 96, right 96 |
| window_covers_left_arm | False | window 1 of left 96 |
| window_covers_right_arm | False | window 1 of right 96 |
| window_not_truncated | True | the cap was not reached |
| every_inscope_field_equivalent | False | 13 in-scope verdict field(s); 8 unequal, 0 family/families unknown |
| every_family_equivalent | False | not_equivalent ['applied_sources', 'direction', 'effective_genome', 'path'], unknown [] |

Why output equivalence is not claimed:

- window_covers_left_arm: window 1 of left 96
- window_covers_right_arm: window 1 of right 96
- every_inscope_field_equivalent: 13 in-scope verdict field(s); 8 unequal, 0 family/families unknown
- every_family_equivalent: not_equivalent ['applied_sources', 'direction', 'effective_genome', 'path'], unknown []
- effective_genome.effective_genome_sha256 (verdict) differs in 1 window case(s): [0]
- effective_genome.genome_sha256 (verdict) differs in 1 window case(s): [0]
- path.path_id (verdict) differs in 1 window case(s): [0]
- path.applied_path (verdict) differs in 1 window case(s): [0]
- direction.direction (verdict) differs in 1 window case(s): [0]
- applied_sources.applied_sources (verdict) differs in 1 window case(s): [0]
- applied_sources.applied_source_ids (verdict) differs in 1 window case(s): [0]
- applied_sources.source_id (verdict) differs in 1 window case(s): [0]

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

Difference classes: other=7, run_bookkeeping=2, timing=3; tracked 36 of at most 64 field(s), truncated=False.

| field | class | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|
| flow_id | other | 0 | 1 | 0 | 0 | 0 | [0] |
| online_source | other | 0 | 1 | 0 | 0 | 0 | [0] |
| operator_id | other | 0 | 1 | 0 | 0 | 0 | [0] |
| semantic_sha256 | other | 0 | 1 | 0 | 0 | 0 | [0] |
| source_action | other | 0 | 1 | 0 | 0 | 0 | [0] |
| source_selection_reason | other | 0 | 1 | 0 | 0 | 0 | [0] |
| target_id | other | 0 | 1 | 0 | 0 | 0 | [0] |
| candidate_id | run_bookkeeping | 0 | 1 | 0 | 0 | 0 | [0] |
| run_id | run_bookkeeping | 0 | 1 | 0 | 0 | 0 | [0] |
| online_phase_timing_seconds | timing | 0 | 1 | 0 | 0 | 0 | [0] |
| online_runner_timing_seconds | timing | 0 | 1 | 0 | 0 | 0 | [0] |
| online_submit_timing_seconds | timing | 0 | 1 | 0 | 0 | 0 | [0] |

Read scope: `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (left); `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (right). No trace container was opened.

