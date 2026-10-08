# Arm equivalence (arm_equivalence.v1)

- left arm: `runs/current-dataflow-p4-initial-ram-off-20261007-online` (label `initial_ram_off`, run_id `current-dataflow-p4-initial-ram-off-20261007`)
- right arm: `runs/current-dataflow-p4-initial-ram-on-20261007-online` (label `initial_ram_on`, run_id `current-dataflow-p4-initial-ram-on-20261007`)

## Compared

The arms share a decodable identity and a non-empty shared raw-input window.

## Comparison window

the leading receipt cases whose raw_sha256 is identical in both arms, compared in receipt order; the searches diverge by construction, so this prefix is the only per-case comparable window

| quantity | left | right | shared |
|---|---|---|---|
| receipt cases | 96 | 96 | 96 |
| declared tests | 96 | 96 | - |
| declared statuses | {"complete": 94, "input_invalid": 2} | {"complete": 94, "input_invalid": 2} | - |
| covered by the window | True | True | - |
| window case cap | 200000 | 200000 | reached=False |

Raw-records cross-check (online_raw_records_hex): 96/96 agreed.

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
| status | equivalent | status | 96 | 0 | 0 | 0 | 0 | status: status is identical in all 96 window cases |
| effective_genome | unknown | effective_genome_sha256 | 188 | 0 | 0 | 0 | 4 | effective_genome_sha256: effective_genome_sha256 is missing (null or absent) in 2 of 96 window cases (left-only 0, right-only 0, both 2) |
| path | unknown | path_id | 188 | 0 | 0 | 0 | 4 | path_id: path_id is missing (null or absent) in 2 of 96 window cases (left-only 0, right-only 0, both 2) |
| direction | equivalent | direction | 96 | 0 | 0 | 0 | 0 | direction: direction is identical in all 96 window cases |
| applied_sources | equivalent | applied_sources | 288 | 0 | 0 | 0 | 0 | applied_sources: applied_sources is identical in all 96 window cases |
| checker_violations | equivalent | violations | 96 | 0 | 0 | 0 | 0 | violations: violations is identical in all 96 window cases |
| coverage | equivalent | coverage_hex | 96 | 0 | 0 | 0 | 0 | coverage_hex: coverage_hex is identical in all 96 window cases |
| local_ticks | unknown | local_ticks | 190 | 0 | 0 | 0 | 2 | local_ticks: local_ticks is missing (null or absent) in 2 of 96 window cases (left-only 0, right-only 0, both 2) |

The counts above sum the family's in-scope *verdict-role* fields; context-role fields are listed per field below and never define a family verdict.

## Per-field detail

| field | role | in scope | verdict | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|---|---|
| status.status | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| effective_genome.effective_genome_sha256 | verdict | True | unknown | 94 | 0 | 0 | 0 | 2 | [15, 30] |
| effective_genome.genome_sha256 | verdict | True | unknown | 94 | 0 | 0 | 0 | 2 | [15, 30] |
| path.path_id | verdict | True | unknown | 94 | 0 | 0 | 0 | 2 | [15, 30] |
| path.applied_path | verdict | True | unknown | 94 | 0 | 0 | 0 | 2 | [15, 30] |
| direction.direction | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| applied_sources.applied_sources | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| applied_sources.applied_source_ids | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| applied_sources.source_id | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| checker_violations.violations | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| checker_violations.rejection | context | False | not_applicable | 0 | 0 | 0 | 0 | 96 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| checker_violations.error | context | True | unknown | 2 | 0 | 0 | 0 | 94 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| coverage.coverage_hex | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |
| local_ticks.local_ticks | verdict | True | unknown | 94 | 0 | 0 | 0 | 2 | [15, 30] |
| local_ticks.total_local_ticks | verdict | True | equivalent | 96 | 0 | 0 | 0 | 0 | [] |

## Output equivalence claimed = False

output equivalence is claimed only when the shared raw-input window covers both arms completely, both arms have the same receipt case count, the window was not truncated by the case cap, and every in-scope declared field is equal in every window case; a `compared` evidence status never implies it

| condition | satisfied | detail |
|---|---|---|
| window_computable | True | shared raw-input prefix of 96 case(s) |
| same_receipt_case_count | True | left 96, right 96 |
| window_covers_left_arm | True | window 96 of left 96 |
| window_covers_right_arm | True | window 96 of right 96 |
| window_not_truncated | True | the cap was not reached |
| every_inscope_field_equivalent | False | 13 in-scope verdict field(s); 0 unequal, 3 family/families unknown |
| every_family_equivalent | False | not_equivalent [], unknown ['effective_genome', 'local_ticks', 'path'] |

Why output equivalence is not claimed:

- every_inscope_field_equivalent: 13 in-scope verdict field(s); 0 unequal, 3 family/families unknown
- every_family_equivalent: not_equivalent [], unknown ['effective_genome', 'local_ticks', 'path']

Declared fields that carry no information in this window (reported, never counted as equal): `checker_violations.rejection`

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

Difference classes: other=0, run_bookkeeping=1, timing=3; tracked 36 of at most 64 field(s), truncated=False.

| field | class | equal | unequal | miss L | miss R | miss both | case indexes |
|---|---|---|---|---|---|---|---|
| run_id | run_bookkeeping | 0 | 96 | 0 | 0 | 0 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| online_phase_timing_seconds | timing | 0 | 96 | 0 | 0 | 0 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| online_runner_timing_seconds | timing | 0 | 94 | 0 | 0 | 2 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |
| online_submit_timing_seconds | timing | 0 | 94 | 0 | 0 | 2 | [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, … |

Read scope: `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (left); `receipts.jsonl`, `report.json`, `online_run_identity.json`, `decoder_manifest.json` (right). No trace container was opened.

