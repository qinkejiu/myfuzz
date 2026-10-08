# P5 单臂指标汇总（`p5_arm_metrics.v1`）

一个固定预算对照所需的全部声明量集中在本文件：每臂的 一次性编译/初始化、每例 admission、真实 RTL 事务、Router/Scheduler、增量反馈、日志/证据、p50/p95 时延、有效例/s、完整真实链/s、覆盖增量/s 与无效/超时比例。
每个数字都标注了它来自哪个 artifact key；输入缺失时为 `null` 并给出原因，绝不用 0 代替。

Checklist metric groups: `one_time_compile_init`, `per_case_admission`, `real_rtl_transactions`, `router_scheduler`, `incremental_feedback`, `log_evidence`, `latency_percentiles`, `effective_cases_per_second`, `certified_chains_per_second`, `coverage_novelty`, `invalid_or_timeout_ratio`, `status_counts`

## 1. 总览

| 臂 | arm_kind | 有效例/s | 完整链 | 完整链/s | 覆盖增量 位/s | 覆盖增量 边/s | 无效/超时 | 逐例 p50 (s) | 逐例 p95 (s) | 终结 total_before_report (s) | trace 字节 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| chain-acceptance-31s | scenario_online_cases | 0.767422 | 8 | 0.255807 | 0.127904 | 0.287783 | 0 | 1.29653 | 1.72226 | 11.5503 | 163190709 |
| chain-600s | scenario_online_cases | 0.612963 | 27 | 0.0449728 | 0.00666264 | 0.0149909 | 0 | 1.6483 | 2.37667 | 67.7868 | 172324767 |
| paired-31s | scenario_online_cases | 0.779642 | 8 | 0.259881 | 0.12994 | 0.292366 | 0 | 1.27179 | 1.67116 | 11.2796 | 163567647 |
| paired-frozen-a | scenario_online_cases | 0.708553 | 7 | 0.215647 | 0.123227 | 0.27726 | 0.0416667 | 1.42173 | 1.77383 | 11.2131 | 157053470 |
| format2-jsonl | scenario_online_cases | 0.621291 | 13 | 0.10769 | 0.0331355 | 0.0745549 | 0.025974 | 1.62889 | 2.09408 | 24.6109 | 493194248 |
| format2-zlib | scenario_online_cases | 0.655778 | 14 | 0.116214 | 0.033204 | 0.0747089 | 0.0246914 | 1.53075 | 2.01874 | 13.4693 | 36903052 |
| p4-cpu-side-foreign | not_a_scenario_online_session | null | null | null | null | null | null | null | null | null | null |

## 2. 每臂全部声明量

### 臂 `chain-acceptance-31s`

- `run_dir`: `runs/current-dataflow-p5-chain-acceptance-20261007-online`
- `run_id`: `current-dataflow-p5-chain-acceptance-20261007`
- `arm_kind`: `scenario_online_cases` (来源 `report.json:execution_mode`)
- `analysis_performed`: true

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0 |
| `one_time_compile_init` | `finalization_timing_seconds` | {"identity_write": 0.2375842189999844, "plan_write": 0.002080399999982774, "session_finish": 6.244267451999974, "total_before_report": 11.550270812000008, "trace_write": 5.005776271999991} | report.json:finalization_timing_seconds |  |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | 11.5503 | report.json:finalization_timing_seconds.total_before_report |  |
| `one_time_compile_init` | `effective_search_seconds` | 31.2735 | report.json:effective_search_seconds |  |
| `one_time_compile_init` | `elapsed_seconds` | 32.4408 | report.json:elapsed_seconds |  |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | 1.16729 | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) |  |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | cold_start.json is absent, so the cold-start baseline case count is unknown |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | cold_start.json:init_seconds_total is absent |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | either cold_start.json init_seconds or report.json:elapsed_seconds is unavailable, so the initialization share of elapsed is undefined |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json carries no finite positive wall_clock_seconds, so the initialization share of the cold group's wall clock is undefined |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0 |
| `per_case_admission` | `receipt_rows` | 24 | receipts.jsonl (decoded rows) |  |
| `per_case_admission` | `reported_tests` | 24 | report.json:tests |  |
| `per_case_admission` | `admissions_total` | 39 | online_plan.json:source_admissions.admissions |  |
| `per_case_admission` | `fuzz_source_admissions` | 24 | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `admissions_by_role` | {"fixed_support": 15, "fuzz_source": 24} | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `candidate_dispositions` | {"admitted": 24} | receipts.jsonl:candidate_disposition |  |
| `per_case_admission` | `candidate_disposition_reasons` | {"rtl_case_committed": 24} | receipts.jsonl:candidate_disposition_reason |  |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | 24 | receipts.jsonl:online_submit_timing_seconds |  |
| `per_case_admission` | `local_command_count_total` | 2324 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p50` | 97 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p95` | 98 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | 0.0497311 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | 0.0551383 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `host_remainder_seconds_p50` | 1.1839 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `host_remainder_seconds_p95` | 1.54238 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `cases_with_local_ticks` | 24 | receipts.jsonl:local_ticks |  |
| `per_case_admission` | `local_ticks_by_component_sum` | {"cpu": 768.0, "gpio_a": 808.0, "gpio_b": 808.0} | receipts.jsonl:local_ticks.<component> (sum) |  |
| `per_case_admission` | `total_local_ticks_sum` | 2384 | receipts.jsonl:total_local_ticks (sum) |  |
| `per_case_admission` | `cases_with_total_local_ticks` | 24 | receipts.jsonl:total_local_ticks |  |
| `per_case_admission` | `coverage_records` | 24 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `raw_record_count` | 24 | receipts.jsonl:online_raw_records_hex |  |
| `per_case_admission` | `cases_with_violations` | 0 | receipts.jsonl:violations |  |
| `real_rtl_transactions` | `cases_with_runner_timing` | 24 | receipts.jsonl:online_runner_timing_seconds |  |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | 24 | receipts.jsonl:candidate_disposition_reason |  |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | 24 | receipts.jsonl:total_local_ticks |  |
| `real_rtl_transactions` | `record_semantics` | "mutation_decisions_not_dut_cycles" | report.json:record_semantics |  |
| `real_rtl_transactions` | `total_local_ticks_semantics` | "sum_of_independent_local_ticks_cost_only" | report.json:total_local_ticks_semantics |  |
| `real_rtl_transactions` | `clock_model` | "independent_local_ticks_and_causal_order" | report.json:clock_model |  |
| `router_scheduler` | `online_runner_timing_seconds` | {"observed_output_route": {"count": 24, "p50": 0.0017591970003536517, "p95": 0.03827533314969713, "sum_seconds": 0.13025286800061053}, "router_drain": {"count": 24, "p50": 0.0014638085000058254, "p95": 0.0034885372500014, "sum_seconds": 0.0342011240000204}, "router_enqueue": {"count": 24, "p50": 1.73199999977669e-05, "p95": 3.333725000373988e-05, "sum_seconds": 0.0003729120000173225}, "router_transact": {"count": 24, "p50": 0.0, "p95": 0.0, "sum_seconds": 0.0}, "runner_step": {"count": 24, "p50": 1.0223153959998967, "p95": 1.381613443949884, "sum_seconds": 25.036164701000303}, "scheduler_batch": {"count": 24, "p50": 1.022501638000037, "p95": 1.3818034570999245, "sum_seconds": 25.040468572000094}} | receipts.jsonl:online_runner_timing_seconds |  |
| `router_scheduler` | `cases_with_router_transact` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact |  |
| `router_scheduler` | `router_transact_seconds_sum` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) |  |
| `router_scheduler` | `cases_with_scheduler_batch` | 24 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch |  |
| `router_scheduler` | `scheduler_batch_seconds_sum` | 25.0405 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) |  |
| `router_scheduler` | `cases_with_observed_output_route` | 24 | receipts.jsonl:online_runner_timing_seconds.observed_output_route |  |
| `router_scheduler` | `observed_output_route_seconds_sum` | 0.130253 | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) |  |
| `router_scheduler` | `nested_phase_semantics` | "online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time" | report.json (declared nested timing contract) |  |
| `incremental_feedback` | `completed_feedback_exchanges` | 2 | report.json:completed_feedback_exchanges |  |
| `incremental_feedback` | `mutation_hint_updates` | 3 | report.json:mutation_hint_updates |  |
| `incremental_feedback` | `mutation_hint_schema` | "scenario_mutation_hint.v1" | report.json:mutation_hint_schema |  |
| `incremental_feedback` | `cases_with_interaction_new_features` | 1 | receipts.jsonl:interaction_new_features |  |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | 1 | receipts.jsonl:interaction_feature_deltas |  |
| `incremental_feedback` | `cases_with_interaction_source_gains` | 1 | receipts.jsonl:interaction_source_gains |  |
| `incremental_feedback` | `cases_deferred` | 23 | receipts.jsonl:interaction_deferred |  |
| `incremental_feedback` | `source_action_gate_enforce` | null | report.json:source_action_gate.enforce | report.json:source_action_gate is absent |
| `incremental_feedback` | `source_action_gate_action_count` | null | report.json:source_action_gate.action_ids | report.json:source_action_gate.action_ids is absent |
| `incremental_feedback` | `path_switch` | null | report.json:path_switch | report.json:path_switch is absent |
| `incremental_feedback` | `closed_loop_energy_enabled` | null | report.json:closed_loop_energy.enabled | report.json:closed_loop_energy is absent |
| `incremental_feedback` | `closed_loop_energy_counts` | null | report.json:closed_loop_energy.counts | report.json:closed_loop_energy.counts is absent |
| `log_evidence` | `trace_format` | "json.v1" | online_final_trace.meta.json:schema_version / online_final_trace.json |  |
| `log_evidence` | `trace_meta_schema_version` | null | online_final_trace.meta.json:schema_version | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_events_file` | "online_final_trace.json" | online_final_trace.meta.json:events_file |  |
| `log_evidence` | `trace_bytes` | 163190709 | trace container file (bytes) |  |
| `log_evidence` | `trace_meta_container_split` | false | online_final_trace.meta.json + online_events.jsonl / online_events.zlib |  |
| `log_evidence` | `trace_events_ingested` | 31795 | trace container file (events decoded) |  |
| `log_evidence` | `trace_declared_event_count` | null | online_final_trace.meta.json:event_count | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_event_count_match` | null | online_final_trace.meta.json:event_count vs decoded events | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_semantic_sha256_verified` | true | online_final_trace.meta.json:semantic_sha256 vs recomputed digest |  |
| `log_evidence` | `trace_meta_bytes` | null | online_final_trace.meta.json (bytes) | online_final_trace.meta.json is absent |
| `log_evidence` | `receipts_bytes` | 63721 | receipts.jsonl (bytes) |  |
| `log_evidence` | `client_log_bytes` | 748 | client.log (bytes) |  |
| `log_evidence` | `session_manifest_bytes` | 2402112 | online_session_manifest.json (bytes) |  |
| `log_evidence` | `evidence_footprint_bytes` | 165832324 | run directory artifacts (bytes, sum) |  |
| `latency_percentiles` | `online_phase_timing_seconds` | {"checker": {"count": 24, "p50": 1.8730000164168814e-06, "p95": 3.0665999929624378e-06}, "feedback_credit": {"count": 24, "p50": 0.0008537934999992558, "p95": 0.0011216287499891564}, "interaction_ingest": {"count": 24, "p50": 0.014802535000015382, "p95": 0.07816369600000143}, "receipt_build": {"count": 24, "p50": 1.734399999975267e-05, "p95": 2.1041499992691114e-05}, "rtl_submit": {"count": 24, "p50": 1.2342730215000017, "p95": 1.5956302178500095}, "selection_decode": {"count": 24, "p50": 9.859950000645767e-05, "p95": 0.0001275398000089467}, "total": {"count": 24, "p50": 1.2965321960000011, "p95": 1.7222636415500077}, "trace_digest": {"count": 24, "p50": 0.04756563249999601, "p95": 0.053959545350004134}} | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `per_case_total_seconds` | {"count": 24, "p50": 1.2965321960000011, "p95": 1.7222636415500077} | receipts.jsonl:online_phase_timing_seconds.total |  |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | 24 | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `invalid_timing_values` | 0 | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds |  |
| `effective_cases_per_second` | `effective_cases_per_second` | 0.767422 | receipts.jsonl:status / report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `complete_status_count` | 24 | receipts.jsonl:status |  |
| `effective_cases_per_second` | `denominator_seconds` | 31.2735 | report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | 0.767422 | receipts.jsonl (rows) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains` | 8 | trace events (runtime_chain_certificate.v1 certificates) |  |
| `certified_chains_per_second` | `certified_chains_per_second` | 0.255807 | trace events (certificates) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains_by_direction` | {"CPU_TO_IP_TO_CPU": 3, "IP_TO_CPU_TO_IP": 5} | trace events (certificates:direction) |  |
| `certified_chains_per_second` | `certified_chains_same_case` | 7 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `certified_chains_cross_case` | 1 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `incomplete_certificates` | 16 | trace events (incomplete certificates) |  |
| `certified_chains_per_second` | `first_missing_hop_histogram` | {"instruction_fetch": 6, "pin8_injection": 10} | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `unresolvable_missing_hops` | 0 | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `certified_admissions` | 8 | trace events (certificates:source_admission_id) |  |
| `certified_chains_per_second` | `chain_completion_by_admission` | {"accounted_admissions": 24, "admissions_by_role": {"fixed_support": 15, "fuzz_source": 24}, "admissions_total": 39, "admissions_total_source": "online_plan.json:source_admissions.admissions", "certificates_without_admission_id": 0, "certified_admissions": 8, "certified_fuzz_source_ratio": 0.3333333333333333, "certified_ratio": 0.20512820512820512, "certified_ratio_denominator": "admissions_total", "certified_ratio_reason": null, "fuzz_source_admissions": 24, "incomplete_admissions": 16, "unaccounted_fuzz_source_admissions": 0} | online_plan.json:source_admissions.admissions joined to certificates |  |
| `certified_chains_per_second` | `chain_producer_available` | true | chain_certificates.ChainCertificates |  |
| `certified_chains_per_second` | `semantics` | "unique certificate_id values the injected producer certified for this artifact; when incomplete certificates dominate, the value states artifact capability rather than DUT chain occurrence" | trace events (declared certificate contract) |  |
| `coverage_novelty` | `first_seen_target_bits` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `first_seen_target_slots` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `new_target_bits_per_second` | 0.127904 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `new_target_slots_per_second` | 0.127904 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `unique_witnessed_edges` | 9 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `edge_candidate_observations` | 1940 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `new_witnessed_edges_per_second` | 0.287783 | trace events:provenance.edge_candidates / report.json:effective_search_seconds |  |
| `coverage_novelty` | `method` | "acceptance_metrics.analyze_run -> local_target_novelty.new_target_bits_per_second and witnessed_edge_novelty.new_edges_per_second; paired_efficiency.compare_runs copies exactly these two fields into groups.<label>.coverage_novelty / groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical to that module's per-group rates" | p5_arm_metrics.v1 (declared reuse) |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | 24 | receipts.jsonl (decoded rows) |  |
| `invalid_or_timeout_ratio` | `complete_count` | 24 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `timeout_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `finding_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | [] | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `definition` | "a case is invalid or timed out when its receipt status is in the reported invalid/timeout sets; findings and complete cases are excluded" | acceptance_metrics.invalid_or_timeout_detail.definition |  |
| `status_counts` | `status_counts` | {"complete": 24} | receipts.jsonl:status |  |
| `status_counts` | `status_counts_total` | 24 | receipts.jsonl (decoded rows) |  |
| `status_counts` | `reported_statuses` | {"complete": 24} | report.json:statuses |  |
| `status_counts` | `reports_agree` | true | report.json:statuses vs receipts.jsonl:status |  |

### 臂 `chain-600s`

- `run_dir`: `runs/current-dataflow-p5-chain-600s-20261007-online`
- `run_id`: `current-dataflow-p5-chain-600s-20261007`
- `arm_kind`: `scenario_online_cases` (来源 `report.json:execution_mode`)
- `analysis_performed`: true

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0 |
| `one_time_compile_init` | `finalization_timing_seconds` | {"identity_write": 0.3004992789992684, "plan_write": 0.003330243999698723, "session_finish": 19.334471130000566, "total_before_report": 67.78683452000041, "trace_write": 48.051289633000124} | report.json:finalization_timing_seconds |  |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | 67.7868 | report.json:finalization_timing_seconds.total_before_report |  |
| `one_time_compile_init` | `effective_search_seconds` | 600.363 | report.json:effective_search_seconds |  |
| `one_time_compile_init` | `elapsed_seconds` | 601.544 | report.json:elapsed_seconds |  |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | 1.181 | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) |  |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | cold_start.json is absent, so the cold-start baseline case count is unknown |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | cold_start.json:init_seconds_total is absent |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | either cold_start.json init_seconds or report.json:elapsed_seconds is unavailable, so the initialization share of elapsed is undefined |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json carries no finite positive wall_clock_seconds, so the initialization share of the cold group's wall clock is undefined |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0 |
| `per_case_admission` | `receipt_rows` | 368 | receipts.jsonl (decoded rows) |  |
| `per_case_admission` | `reported_tests` | 368 | report.json:tests |  |
| `per_case_admission` | `admissions_total` | 559 | online_plan.json:source_admissions.admissions |  |
| `per_case_admission` | `fuzz_source_admissions` | 368 | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `admissions_by_role` | {"fixed_support": 191, "fuzz_source": 368} | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `candidate_dispositions` | {"admitted": 368} | receipts.jsonl:candidate_disposition |  |
| `per_case_admission` | `candidate_disposition_reasons` | {"rtl_case_committed": 368} | receipts.jsonl:candidate_disposition_reason |  |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | 368 | receipts.jsonl:online_submit_timing_seconds |  |
| `per_case_admission` | `local_command_count_total` | 35607 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p50` | 97 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p95` | 98 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | 0.0523707 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | 0.057297 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `host_remainder_seconds_p50` | 1.50954 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `host_remainder_seconds_p95` | 2.22962 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `cases_with_local_ticks` | 368 | receipts.jsonl:local_ticks |  |
| `per_case_admission` | `local_ticks_by_component_sum` | {"cpu": 11776.0, "gpio_a": 12348.0, "gpio_b": 12320.0} | receipts.jsonl:local_ticks.<component> (sum) |  |
| `per_case_admission` | `total_local_ticks_sum` | 36444 | receipts.jsonl:total_local_ticks (sum) |  |
| `per_case_admission` | `cases_with_total_local_ticks` | 368 | receipts.jsonl:total_local_ticks |  |
| `per_case_admission` | `coverage_records` | 368 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `raw_record_count` | 368 | receipts.jsonl:online_raw_records_hex |  |
| `per_case_admission` | `cases_with_violations` | 0 | receipts.jsonl:violations |  |
| `real_rtl_transactions` | `cases_with_runner_timing` | 368 | receipts.jsonl:online_runner_timing_seconds |  |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | 368 | receipts.jsonl:candidate_disposition_reason |  |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | 368 | receipts.jsonl:total_local_ticks |  |
| `real_rtl_transactions` | `record_semantics` | "mutation_decisions_not_dut_cycles" | report.json:record_semantics |  |
| `real_rtl_transactions` | `total_local_ticks_semantics` | "sum_of_independent_local_ticks_cost_only" | report.json:total_local_ticks_semantics |  |
| `real_rtl_transactions` | `clock_model` | "independent_local_ticks_and_causal_order" | report.json:clock_model |  |
| `router_scheduler` | `online_runner_timing_seconds` | {"observed_output_route": {"count": 368, "p50": 0.0018796789981934126, "p95": 0.002237717099069414, "sum_seconds": 1.263490157041815}, "router_drain": {"count": 368, "p50": 0.0011758955001823779, "p95": 0.003492408800184421, "sum_seconds": 0.44227178199253103}, "router_enqueue": {"count": 368, "p50": 1.7342500086670043e-05, "p95": 4.072175042892923e-05, "sum_seconds": 0.0057956819982791785}, "router_transact": {"count": 368, "p50": 0.0, "p95": 0.0, "sum_seconds": 0.0}, "runner_step": {"count": 368, "p50": 1.1270980435037927, "p95": 2.0464853362487703, "sum_seconds": 447.8241906101084}, "scheduler_batch": {"count": 368, "p50": 1.127332741999453, "p95": 2.0467155602003, "sum_seconds": 447.90465164102534}} | receipts.jsonl:online_runner_timing_seconds |  |
| `router_scheduler` | `cases_with_router_transact` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact |  |
| `router_scheduler` | `router_transact_seconds_sum` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) |  |
| `router_scheduler` | `cases_with_scheduler_batch` | 368 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch |  |
| `router_scheduler` | `scheduler_batch_seconds_sum` | 447.905 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) |  |
| `router_scheduler` | `cases_with_observed_output_route` | 368 | receipts.jsonl:online_runner_timing_seconds.observed_output_route |  |
| `router_scheduler` | `observed_output_route_seconds_sum` | 1.26349 | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) |  |
| `router_scheduler` | `nested_phase_semantics` | "online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time" | report.json (declared nested timing contract) |  |
| `incremental_feedback` | `completed_feedback_exchanges` | 31 | report.json:completed_feedback_exchanges |  |
| `incremental_feedback` | `mutation_hint_updates` | 32 | report.json:mutation_hint_updates |  |
| `incremental_feedback` | `mutation_hint_schema` | "scenario_mutation_hint.v1" | report.json:mutation_hint_schema |  |
| `incremental_feedback` | `cases_with_interaction_new_features` | 1 | receipts.jsonl:interaction_new_features |  |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | 23 | receipts.jsonl:interaction_feature_deltas |  |
| `incremental_feedback` | `cases_with_interaction_source_gains` | 1 | receipts.jsonl:interaction_source_gains |  |
| `incremental_feedback` | `cases_deferred` | 345 | receipts.jsonl:interaction_deferred |  |
| `incremental_feedback` | `source_action_gate_enforce` | null | report.json:source_action_gate.enforce | report.json:source_action_gate is absent |
| `incremental_feedback` | `source_action_gate_action_count` | null | report.json:source_action_gate.action_ids | report.json:source_action_gate.action_ids is absent |
| `incremental_feedback` | `path_switch` | null | report.json:path_switch | report.json:path_switch is absent |
| `incremental_feedback` | `closed_loop_energy_enabled` | null | report.json:closed_loop_energy.enabled | report.json:closed_loop_energy is absent |
| `incremental_feedback` | `closed_loop_energy_counts` | null | report.json:closed_loop_energy.counts | report.json:closed_loop_energy.counts is absent |
| `log_evidence` | `trace_format` | "zlib_chunks.v1" | online_final_trace.meta.json:schema_version / online_final_trace.json |  |
| `log_evidence` | `trace_meta_schema_version` | "online_trace_zlib_chunks.v1" | online_final_trace.meta.json:schema_version |  |
| `log_evidence` | `trace_events_file` | "online_events.zlib" | online_final_trace.meta.json:events_file |  |
| `log_evidence` | `trace_bytes` | 172324767 | trace container file (bytes) |  |
| `log_evidence` | `trace_meta_container_split` | true | online_final_trace.meta.json + online_events.jsonl / online_events.zlib |  |
| `log_evidence` | `trace_events_ingested` | 570196 | trace container file (events decoded) |  |
| `log_evidence` | `trace_declared_event_count` | 570196 | online_final_trace.meta.json:event_count |  |
| `log_evidence` | `trace_event_count_match` | true | online_final_trace.meta.json:event_count vs decoded events |  |
| `log_evidence` | `trace_semantic_sha256_verified` | true | online_final_trace.meta.json:semantic_sha256 vs recomputed digest |  |
| `log_evidence` | `trace_meta_bytes` | 436 | online_final_trace.meta.json (bytes) |  |
| `log_evidence` | `receipts_bytes` | 975420 | receipts.jsonl (bytes) |  |
| `log_evidence` | `client_log_bytes` | 3651 | client.log (bytes) |  |
| `log_evidence` | `session_manifest_bytes` | 2402237 | online_session_manifest.json (bytes) |  |
| `log_evidence` | `evidence_footprint_bytes` | 176609081 | run directory artifacts (bytes, sum) |  |
| `latency_percentiles` | `online_phase_timing_seconds` | {"checker": {"count": 368, "p50": 2.204999873356428e-06, "p95": 2.9478500437107868e-06}, "feedback_credit": {"count": 368, "p50": 0.0012192384992886218, "p95": 0.008300694699937595}, "interaction_ingest": {"count": 368, "p50": 0.019711551000000327, "p95": 0.11481537929971637}, "receipt_build": {"count": 368, "p50": 1.8019499748334056e-05, "p95": 2.2032999549992382e-05}, "rtl_submit": {"count": 368, "p50": 1.5610182810000879, "p95": 2.2839247884997347}, "selection_decode": {"count": 368, "p50": 0.00010656050017132657, "p95": 0.00012797594972653316}, "total": {"count": 368, "p50": 1.6483040389998678, "p95": 2.37667041749919}, "trace_digest": {"count": 368, "p50": 0.05275617000006605, "p95": 0.06051322659973266}} | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `per_case_total_seconds` | {"count": 368, "p50": 1.6483040389998678, "p95": 2.37667041749919} | receipts.jsonl:online_phase_timing_seconds.total |  |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | 368 | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `invalid_timing_values` | 0 | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds |  |
| `effective_cases_per_second` | `effective_cases_per_second` | 0.612963 | receipts.jsonl:status / report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `complete_status_count` | 368 | receipts.jsonl:status |  |
| `effective_cases_per_second` | `denominator_seconds` | 600.363 | report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | 0.612963 | receipts.jsonl (rows) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains` | 27 | trace events (runtime_chain_certificate.v1 certificates) |  |
| `certified_chains_per_second` | `certified_chains_per_second` | 0.0449728 | trace events (certificates) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains_by_direction` | {"CPU_TO_IP_TO_CPU": 20, "IP_TO_CPU_TO_IP": 7} | trace events (certificates:direction) |  |
| `certified_chains_per_second` | `certified_chains_same_case` | 21 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `certified_chains_cross_case` | 6 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `incomplete_certificates` | 341 | trace events (incomplete certificates) |  |
| `certified_chains_per_second` | `first_missing_hop_histogram` | {"instruction_fetch": 137, "pin8_injection": 184, "retired_target_delivery": 20} | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `unresolvable_missing_hops` | 0 | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `certified_admissions` | 27 | trace events (certificates:source_admission_id) |  |
| `certified_chains_per_second` | `chain_completion_by_admission` | {"accounted_admissions": 368, "admissions_by_role": {"fixed_support": 191, "fuzz_source": 368}, "admissions_total": 559, "admissions_total_source": "online_plan.json:source_admissions.admissions", "certificates_without_admission_id": 0, "certified_admissions": 27, "certified_fuzz_source_ratio": 0.07336956521739131, "certified_ratio": 0.04830053667262969, "certified_ratio_denominator": "admissions_total", "certified_ratio_reason": null, "fuzz_source_admissions": 368, "incomplete_admissions": 341, "unaccounted_fuzz_source_admissions": 0} | online_plan.json:source_admissions.admissions joined to certificates |  |
| `certified_chains_per_second` | `chain_producer_available` | true | chain_certificates.ChainCertificates |  |
| `certified_chains_per_second` | `semantics` | "unique certificate_id values the injected producer certified for this artifact; when incomplete certificates dominate, the value states artifact capability rather than DUT chain occurrence" | trace events (declared certificate contract) |  |
| `coverage_novelty` | `first_seen_target_bits` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `first_seen_target_slots` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `new_target_bits_per_second` | 0.00666264 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `new_target_slots_per_second` | 0.00666264 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `unique_witnessed_edges` | 9 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `edge_candidate_observations` | 26990 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `new_witnessed_edges_per_second` | 0.0149909 | trace events:provenance.edge_candidates / report.json:effective_search_seconds |  |
| `coverage_novelty` | `method` | "acceptance_metrics.analyze_run -> local_target_novelty.new_target_bits_per_second and witnessed_edge_novelty.new_edges_per_second; paired_efficiency.compare_runs copies exactly these two fields into groups.<label>.coverage_novelty / groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical to that module's per-group rates" | p5_arm_metrics.v1 (declared reuse) |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | 368 | receipts.jsonl (decoded rows) |  |
| `invalid_or_timeout_ratio` | `complete_count` | 368 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `timeout_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `finding_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | [] | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `definition` | "a case is invalid or timed out when its receipt status is in the reported invalid/timeout sets; findings and complete cases are excluded" | acceptance_metrics.invalid_or_timeout_detail.definition |  |
| `status_counts` | `status_counts` | {"complete": 368} | receipts.jsonl:status |  |
| `status_counts` | `status_counts_total` | 368 | receipts.jsonl (decoded rows) |  |
| `status_counts` | `reported_statuses` | {"complete": 368} | report.json:statuses |  |
| `status_counts` | `reports_agree` | true | report.json:statuses vs receipts.jsonl:status |  |

### 臂 `paired-31s`

- `run_dir`: `runs/current-dataflow-p5-paired-20261007-online`
- `run_id`: `current-dataflow-p5-paired-20261007`
- `arm_kind`: `scenario_online_cases` (来源 `report.json:execution_mode`)
- `analysis_performed`: true

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0 |
| `one_time_compile_init` | `finalization_timing_seconds` | {"identity_write": 0.24603204600043682, "plan_write": 0.0016510390005350928, "session_finish": 5.953963650000333, "total_before_report": 11.279588528999739, "trace_write": 5.015455765000297} | report.json:finalization_timing_seconds |  |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | 11.2796 | report.json:finalization_timing_seconds.total_before_report |  |
| `one_time_compile_init` | `effective_search_seconds` | 30.7834 | report.json:effective_search_seconds |  |
| `one_time_compile_init` | `elapsed_seconds` | 31.9053 | report.json:elapsed_seconds |  |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | 1.12196 | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) |  |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | cold_start.json is absent, so the cold-start baseline case count is unknown |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | cold_start.json:init_seconds_total is absent |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | either cold_start.json init_seconds or report.json:elapsed_seconds is unavailable, so the initialization share of elapsed is undefined |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json carries no finite positive wall_clock_seconds, so the initialization share of the cold group's wall clock is undefined |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0 |
| `per_case_admission` | `receipt_rows` | 24 | receipts.jsonl (decoded rows) |  |
| `per_case_admission` | `reported_tests` | 24 | report.json:tests |  |
| `per_case_admission` | `admissions_total` | 39 | online_plan.json:source_admissions.admissions |  |
| `per_case_admission` | `fuzz_source_admissions` | 24 | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `admissions_by_role` | {"fixed_support": 15, "fuzz_source": 24} | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `candidate_dispositions` | {"admitted": 24} | receipts.jsonl:candidate_disposition |  |
| `per_case_admission` | `candidate_disposition_reasons` | {"rtl_case_committed": 24} | receipts.jsonl:candidate_disposition_reason |  |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | 24 | receipts.jsonl:online_submit_timing_seconds |  |
| `per_case_admission` | `local_command_count_total` | 2324 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p50` | 97 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p95` | 98 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | 0.0493926 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | 0.0518143 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `host_remainder_seconds_p50` | 1.14147 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `host_remainder_seconds_p95` | 1.54406 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `cases_with_local_ticks` | 24 | receipts.jsonl:local_ticks |  |
| `per_case_admission` | `local_ticks_by_component_sum` | {"cpu": 768.0, "gpio_a": 808.0, "gpio_b": 808.0} | receipts.jsonl:local_ticks.<component> (sum) |  |
| `per_case_admission` | `total_local_ticks_sum` | 2384 | receipts.jsonl:total_local_ticks (sum) |  |
| `per_case_admission` | `cases_with_total_local_ticks` | 24 | receipts.jsonl:total_local_ticks |  |
| `per_case_admission` | `coverage_records` | 24 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `raw_record_count` | 24 | receipts.jsonl:online_raw_records_hex |  |
| `per_case_admission` | `cases_with_violations` | 0 | receipts.jsonl:violations |  |
| `real_rtl_transactions` | `cases_with_runner_timing` | 24 | receipts.jsonl:online_runner_timing_seconds |  |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | 24 | receipts.jsonl:candidate_disposition_reason |  |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | 24 | receipts.jsonl:total_local_ticks |  |
| `real_rtl_transactions` | `record_semantics` | "mutation_decisions_not_dut_cycles" | report.json:record_semantics |  |
| `real_rtl_transactions` | `total_local_ticks_semantics` | "sum_of_independent_local_ticks_cost_only" | report.json:total_local_ticks_semantics |  |
| `real_rtl_transactions` | `clock_model` | "independent_local_ticks_and_causal_order" | report.json:clock_model |  |
| `router_scheduler` | `online_runner_timing_seconds` | {"observed_output_route": {"count": 24, "p50": 0.0017192909963341663, "p95": 0.03736210700453739, "sum_seconds": 0.1295537279875134}, "router_drain": {"count": 24, "p50": 0.0012267079996490793, "p95": 0.0030413244994178966, "sum_seconds": 0.029812087998834613}, "router_enqueue": {"count": 24, "p50": 1.7498000033810968e-05, "p95": 3.364494991728861e-05, "sum_seconds": 0.00036070699752599467}, "router_transact": {"count": 24, "p50": 0.0, "p95": 0.0, "sum_seconds": 0.0}, "runner_step": {"count": 24, "p50": 1.0019587134970607, "p95": 1.3223248583497935, "sum_seconds": 24.637382574014737}, "scheduler_batch": {"count": 24, "p50": 1.0021554569993896, "p95": 1.3225083823536352, "sum_seconds": 24.641897906008126}} | receipts.jsonl:online_runner_timing_seconds |  |
| `router_scheduler` | `cases_with_router_transact` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact |  |
| `router_scheduler` | `router_transact_seconds_sum` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) |  |
| `router_scheduler` | `cases_with_scheduler_batch` | 24 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch |  |
| `router_scheduler` | `scheduler_batch_seconds_sum` | 24.6419 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) |  |
| `router_scheduler` | `cases_with_observed_output_route` | 24 | receipts.jsonl:online_runner_timing_seconds.observed_output_route |  |
| `router_scheduler` | `observed_output_route_seconds_sum` | 0.129554 | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) |  |
| `router_scheduler` | `nested_phase_semantics` | "online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time" | report.json (declared nested timing contract) |  |
| `incremental_feedback` | `completed_feedback_exchanges` | 2 | report.json:completed_feedback_exchanges |  |
| `incremental_feedback` | `mutation_hint_updates` | 3 | report.json:mutation_hint_updates |  |
| `incremental_feedback` | `mutation_hint_schema` | "scenario_mutation_hint.v1" | report.json:mutation_hint_schema |  |
| `incremental_feedback` | `cases_with_interaction_new_features` | 1 | receipts.jsonl:interaction_new_features |  |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | 1 | receipts.jsonl:interaction_feature_deltas |  |
| `incremental_feedback` | `cases_with_interaction_source_gains` | 1 | receipts.jsonl:interaction_source_gains |  |
| `incremental_feedback` | `cases_deferred` | 23 | receipts.jsonl:interaction_deferred |  |
| `incremental_feedback` | `source_action_gate_enforce` | null | report.json:source_action_gate.enforce | report.json:source_action_gate is absent |
| `incremental_feedback` | `source_action_gate_action_count` | null | report.json:source_action_gate.action_ids | report.json:source_action_gate.action_ids is absent |
| `incremental_feedback` | `path_switch` | null | report.json:path_switch | report.json:path_switch is absent |
| `incremental_feedback` | `closed_loop_energy_enabled` | null | report.json:closed_loop_energy.enabled | report.json:closed_loop_energy is absent |
| `incremental_feedback` | `closed_loop_energy_counts` | null | report.json:closed_loop_energy.counts | report.json:closed_loop_energy.counts is absent |
| `log_evidence` | `trace_format` | "json.v1" | online_final_trace.meta.json:schema_version / online_final_trace.json |  |
| `log_evidence` | `trace_meta_schema_version` | null | online_final_trace.meta.json:schema_version | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_events_file` | "online_final_trace.json" | online_final_trace.meta.json:events_file |  |
| `log_evidence` | `trace_bytes` | 163567647 | trace container file (bytes) |  |
| `log_evidence` | `trace_meta_container_split` | false | online_final_trace.meta.json + online_events.jsonl / online_events.zlib |  |
| `log_evidence` | `trace_events_ingested` | 31795 | trace container file (events decoded) |  |
| `log_evidence` | `trace_declared_event_count` | null | online_final_trace.meta.json:event_count | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_event_count_match` | null | online_final_trace.meta.json:event_count vs decoded events | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_semantic_sha256_verified` | true | online_final_trace.meta.json:semantic_sha256 vs recomputed digest |  |
| `log_evidence` | `trace_meta_bytes` | null | online_final_trace.meta.json (bytes) | online_final_trace.meta.json is absent |
| `log_evidence` | `receipts_bytes` | 63943 | receipts.jsonl (bytes) |  |
| `log_evidence` | `client_log_bytes` | 738 | client.log (bytes) |  |
| `log_evidence` | `session_manifest_bytes` | 2402237 | online_session_manifest.json (bytes) |  |
| `log_evidence` | `evidence_footprint_bytes` | 166209352 | run directory artifacts (bytes, sum) |  |
| `latency_percentiles` | `online_phase_timing_seconds` | {"checker": {"count": 24, "p50": 1.9629997041192837e-06, "p95": 2.823250088113127e-06}, "feedback_credit": {"count": 24, "p50": 0.0008121615005620697, "p95": 0.0011261987501256954}, "interaction_ingest": {"count": 24, "p50": 0.015276239499598887, "p95": 0.07561118140069993}, "receipt_build": {"count": 24, "p50": 1.7316999674221734e-05, "p95": 2.253405045848922e-05}, "rtl_submit": {"count": 24, "p50": 1.1922244200000023, "p95": 1.59446386504992}, "selection_decode": {"count": 24, "p50": 0.00010053050027636345, "p95": 0.00014234470049814262}, "total": {"count": 24, "p50": 1.2717864745000043, "p95": 1.6711592015501993}, "trace_digest": {"count": 24, "p50": 0.047388904000399634, "p95": 0.052663703100279236}} | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `per_case_total_seconds` | {"count": 24, "p50": 1.2717864745000043, "p95": 1.6711592015501993} | receipts.jsonl:online_phase_timing_seconds.total |  |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | 24 | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `invalid_timing_values` | 0 | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds |  |
| `effective_cases_per_second` | `effective_cases_per_second` | 0.779642 | receipts.jsonl:status / report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `complete_status_count` | 24 | receipts.jsonl:status |  |
| `effective_cases_per_second` | `denominator_seconds` | 30.7834 | report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | 0.779642 | receipts.jsonl (rows) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains` | 8 | trace events (runtime_chain_certificate.v1 certificates) |  |
| `certified_chains_per_second` | `certified_chains_per_second` | 0.259881 | trace events (certificates) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains_by_direction` | {"CPU_TO_IP_TO_CPU": 3, "IP_TO_CPU_TO_IP": 5} | trace events (certificates:direction) |  |
| `certified_chains_per_second` | `certified_chains_same_case` | 7 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `certified_chains_cross_case` | 1 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `incomplete_certificates` | 16 | trace events (incomplete certificates) |  |
| `certified_chains_per_second` | `first_missing_hop_histogram` | {"instruction_fetch": 6, "pin8_injection": 10} | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `unresolvable_missing_hops` | 0 | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `certified_admissions` | 8 | trace events (certificates:source_admission_id) |  |
| `certified_chains_per_second` | `chain_completion_by_admission` | {"accounted_admissions": 24, "admissions_by_role": {"fixed_support": 15, "fuzz_source": 24}, "admissions_total": 39, "admissions_total_source": "online_plan.json:source_admissions.admissions", "certificates_without_admission_id": 0, "certified_admissions": 8, "certified_fuzz_source_ratio": 0.3333333333333333, "certified_ratio": 0.20512820512820512, "certified_ratio_denominator": "admissions_total", "certified_ratio_reason": null, "fuzz_source_admissions": 24, "incomplete_admissions": 16, "unaccounted_fuzz_source_admissions": 0} | online_plan.json:source_admissions.admissions joined to certificates |  |
| `certified_chains_per_second` | `chain_producer_available` | true | chain_certificates.ChainCertificates |  |
| `certified_chains_per_second` | `semantics` | "unique certificate_id values the injected producer certified for this artifact; when incomplete certificates dominate, the value states artifact capability rather than DUT chain occurrence" | trace events (declared certificate contract) |  |
| `coverage_novelty` | `first_seen_target_bits` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `first_seen_target_slots` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `new_target_bits_per_second` | 0.12994 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `new_target_slots_per_second` | 0.12994 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `unique_witnessed_edges` | 9 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `edge_candidate_observations` | 1940 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `new_witnessed_edges_per_second` | 0.292366 | trace events:provenance.edge_candidates / report.json:effective_search_seconds |  |
| `coverage_novelty` | `method` | "acceptance_metrics.analyze_run -> local_target_novelty.new_target_bits_per_second and witnessed_edge_novelty.new_edges_per_second; paired_efficiency.compare_runs copies exactly these two fields into groups.<label>.coverage_novelty / groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical to that module's per-group rates" | p5_arm_metrics.v1 (declared reuse) |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | 24 | receipts.jsonl (decoded rows) |  |
| `invalid_or_timeout_ratio` | `complete_count` | 24 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `timeout_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `finding_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | [] | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `definition` | "a case is invalid or timed out when its receipt status is in the reported invalid/timeout sets; findings and complete cases are excluded" | acceptance_metrics.invalid_or_timeout_detail.definition |  |
| `status_counts` | `status_counts` | {"complete": 24} | receipts.jsonl:status |  |
| `status_counts` | `status_counts_total` | 24 | receipts.jsonl (decoded rows) |  |
| `status_counts` | `reported_statuses` | {"complete": 24} | report.json:statuses |  |
| `status_counts` | `reports_agree` | true | report.json:statuses vs receipts.jsonl:status |  |

### 臂 `paired-frozen-a`

- `run_dir`: `runs/p5-paired-frozen-20261008-a-online`
- `run_id`: `p5-paired-frozen-20261008-a`
- `arm_kind`: `scenario_online_cases` (来源 `report.json:execution_mode`)
- `analysis_performed`: true

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0 |
| `one_time_compile_init` | `finalization_timing_seconds` | {"identity_write": 0.213554854002723, "plan_write": 0.0025631839962443337, "session_finish": 5.818922692000342, "total_before_report": 11.213116128004913, "trace_write": 5.116094719996909} | report.json:finalization_timing_seconds |  |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | 11.2131 | report.json:finalization_timing_seconds.total_before_report |  |
| `one_time_compile_init` | `effective_search_seconds` | 32.4605 | report.json:effective_search_seconds |  |
| `one_time_compile_init` | `elapsed_seconds` | 33.7305 | report.json:elapsed_seconds |  |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | 1.27005 | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) |  |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | cold_start.json is absent, so the cold-start baseline case count is unknown |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | cold_start.json:init_seconds_total is absent |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | either cold_start.json init_seconds or report.json:elapsed_seconds is unavailable, so the initialization share of elapsed is undefined |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json carries no finite positive wall_clock_seconds, so the initialization share of the cold group's wall clock is undefined |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0 |
| `per_case_admission` | `receipt_rows` | 24 | receipts.jsonl (decoded rows) |  |
| `per_case_admission` | `reported_tests` | 24 | report.json:tests |  |
| `per_case_admission` | `admissions_total` | 39 | online_plan.json:source_admissions.admissions |  |
| `per_case_admission` | `fuzz_source_admissions` | 23 | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `admissions_by_role` | {"fixed_support": 16, "fuzz_source": 23} | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `candidate_dispositions` | {"admitted": 23, "rejected": 1} | receipts.jsonl:candidate_disposition |  |
| `per_case_admission` | `candidate_disposition_reasons` | {"rtl_case_committed": 23, "source_action_not_constructible": 1} | receipts.jsonl:candidate_disposition_reason |  |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | 23 | receipts.jsonl:online_submit_timing_seconds |  |
| `per_case_admission` | `local_command_count_total` | 2226 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p50` | 97 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p95` | 98 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | 0.0567244 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | 0.0628539 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `host_remainder_seconds_p50` | 1.31096 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `host_remainder_seconds_p95` | 1.59173 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `cases_with_local_ticks` | 23 | receipts.jsonl:local_ticks |  |
| `per_case_admission` | `local_ticks_by_component_sum` | {"cpu": 736.0, "gpio_a": 768.0, "gpio_b": 776.0} | receipts.jsonl:local_ticks.<component> (sum) |  |
| `per_case_admission` | `total_local_ticks_sum` | 2280 | receipts.jsonl:total_local_ticks (sum) |  |
| `per_case_admission` | `cases_with_total_local_ticks` | 24 | receipts.jsonl:total_local_ticks |  |
| `per_case_admission` | `coverage_records` | 24 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `raw_record_count` | 24 | receipts.jsonl:online_raw_records_hex |  |
| `per_case_admission` | `cases_with_violations` | 0 | receipts.jsonl:violations |  |
| `real_rtl_transactions` | `cases_with_runner_timing` | 23 | receipts.jsonl:online_runner_timing_seconds |  |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | 23 | receipts.jsonl:candidate_disposition_reason |  |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | 24 | receipts.jsonl:total_local_ticks |  |
| `real_rtl_transactions` | `record_semantics` | "mutation_decisions_not_dut_cycles" | report.json:record_semantics |  |
| `real_rtl_transactions` | `total_local_ticks_semantics` | "sum_of_independent_local_ticks_cost_only" | report.json:total_local_ticks_semantics |  |
| `real_rtl_transactions` | `clock_model` | "independent_local_ticks_and_causal_order" | report.json:clock_model |  |
| `router_scheduler` | `online_runner_timing_seconds` | {"observed_output_route": {"count": 23, "p50": 0.0019517730252118781, "p95": 0.002241092333133565, "sum_seconds": 0.04565298578381771}, "router_drain": {"count": 23, "p50": 0.0014440059967455454, "p95": 0.003418474795034854, "sum_seconds": 0.029067207011394203}, "router_enqueue": {"count": 23, "p50": 1.882999640656635e-05, "p95": 4.8303794756066054e-05, "sum_seconds": 0.000422778983192984}, "router_transact": {"count": 23, "p50": 0.0, "p95": 0.0, "sum_seconds": 0.0}, "runner_step": {"count": 23, "p50": 1.0906504099839367, "p95": 1.3403780544969777, "sum_seconds": 24.938006637006765}, "scheduler_batch": {"count": 23, "p50": 1.0908700559739373, "p95": 1.3406903316143144, "sum_seconds": 24.943979959061835}} | receipts.jsonl:online_runner_timing_seconds |  |
| `router_scheduler` | `cases_with_router_transact` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact |  |
| `router_scheduler` | `router_transact_seconds_sum` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) |  |
| `router_scheduler` | `cases_with_scheduler_batch` | 23 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch |  |
| `router_scheduler` | `scheduler_batch_seconds_sum` | 24.944 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) |  |
| `router_scheduler` | `cases_with_observed_output_route` | 23 | receipts.jsonl:online_runner_timing_seconds.observed_output_route |  |
| `router_scheduler` | `observed_output_route_seconds_sum` | 0.045653 | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) |  |
| `router_scheduler` | `nested_phase_semantics` | "online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time" | report.json (declared nested timing contract) |  |
| `incremental_feedback` | `completed_feedback_exchanges` | 2 | report.json:completed_feedback_exchanges |  |
| `incremental_feedback` | `mutation_hint_updates` | 3 | report.json:mutation_hint_updates |  |
| `incremental_feedback` | `mutation_hint_schema` | "scenario_mutation_hint.v1" | report.json:mutation_hint_schema |  |
| `incremental_feedback` | `cases_with_interaction_new_features` | 0 | receipts.jsonl:interaction_new_features |  |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | 0 | receipts.jsonl:interaction_feature_deltas |  |
| `incremental_feedback` | `cases_with_interaction_source_gains` | 0 | receipts.jsonl:interaction_source_gains |  |
| `incremental_feedback` | `cases_deferred` | 23 | receipts.jsonl:interaction_deferred |  |
| `incremental_feedback` | `source_action_gate_enforce` | true | report.json:source_action_gate.enforce |  |
| `incremental_feedback` | `source_action_gate_action_count` | 23 | report.json:source_action_gate.action_ids |  |
| `incremental_feedback` | `path_switch` | {"attempts": 0, "changed": 0, "enabled": false, "granted": 0, "operator_ids": {}, "refusals": {}, "rejection_codes": {}, "schema_version": "online_path_switch_state.v1", "source": "default", "status": "disabled"} | report.json:path_switch |  |
| `incremental_feedback` | `closed_loop_energy_enabled` | false | report.json:closed_loop_energy.enabled |  |
| `incremental_feedback` | `closed_loop_energy_counts` | {"certificate_count": 0, "closed_loop_count": 0, "partial_propagation_count": 0, "stage_reached_count": 0} | report.json:closed_loop_energy.counts |  |
| `log_evidence` | `trace_format` | "json.v1" | online_final_trace.meta.json:schema_version / online_final_trace.json |  |
| `log_evidence` | `trace_meta_schema_version` | null | online_final_trace.meta.json:schema_version | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_events_file` | "online_final_trace.json" | online_final_trace.meta.json:events_file |  |
| `log_evidence` | `trace_bytes` | 157053470 | trace container file (bytes) |  |
| `log_evidence` | `trace_meta_container_split` | false | online_final_trace.meta.json + online_events.jsonl / online_events.zlib |  |
| `log_evidence` | `trace_events_ingested` | 30657 | trace container file (events decoded) |  |
| `log_evidence` | `trace_declared_event_count` | null | online_final_trace.meta.json:event_count | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_event_count_match` | null | online_final_trace.meta.json:event_count vs decoded events | no streamable trace artifact is present in this run directory |
| `log_evidence` | `trace_semantic_sha256_verified` | true | online_final_trace.meta.json:semantic_sha256 vs recomputed digest |  |
| `log_evidence` | `trace_meta_bytes` | null | online_final_trace.meta.json (bytes) | online_final_trace.meta.json is absent |
| `log_evidence` | `receipts_bytes` | 99374 | receipts.jsonl (bytes) |  |
| `log_evidence` | `client_log_bytes` | 730 | client.log (bytes) |  |
| `log_evidence` | `session_manifest_bytes` | 2406053 | online_session_manifest.json (bytes) |  |
| `log_evidence` | `evidence_footprint_bytes` | 159751779 | run directory artifacts (bytes, sum) |  |
| `latency_percentiles` | `online_phase_timing_seconds` | {"checker": {"count": 24, "p50": 2.298500476172194e-06, "p95": 4.002351852250286e-06}, "feedback_credit": {"count": 24, "p50": 0.000982399498752784, "p95": 0.0013852286014298444}, "interaction_ingest": {"count": 24, "p50": 0.015975999500369653, "p95": 0.0819402036475367}, "receipt_build": {"count": 24, "p50": 2.4573004338890314e-05, "p95": 3.123384558421094e-05}, "rtl_submit": {"count": 24, "p50": 1.347087942998769, "p95": 1.6421706616521987}, "selection_decode": {"count": 24, "p50": 0.00021024050147389062, "p95": 0.00034591230360092595}, "total": {"count": 24, "p50": 1.4217341525036318, "p95": 1.7738346081507188}, "trace_digest": {"count": 24, "p50": 0.049657098497846164, "p95": 0.05733930095120741}} | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `per_case_total_seconds` | {"count": 24, "p50": 1.4217341525036318, "p95": 1.7738346081507188} | receipts.jsonl:online_phase_timing_seconds.total |  |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | 24 | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `invalid_timing_values` | 0 | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds |  |
| `effective_cases_per_second` | `effective_cases_per_second` | 0.708553 | receipts.jsonl:status / report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `complete_status_count` | 23 | receipts.jsonl:status |  |
| `effective_cases_per_second` | `denominator_seconds` | 32.4605 | report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | 0.73936 | receipts.jsonl (rows) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains` | 7 | trace events (runtime_chain_certificate.v1 certificates) |  |
| `certified_chains_per_second` | `certified_chains_per_second` | 0.215647 | trace events (certificates) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains_by_direction` | {"CPU_TO_IP_TO_CPU": 2, "IP_TO_CPU_TO_IP": 5} | trace events (certificates:direction) |  |
| `certified_chains_per_second` | `certified_chains_same_case` | 7 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `certified_chains_cross_case` | 0 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `incomplete_certificates` | 16 | trace events (incomplete certificates) |  |
| `certified_chains_per_second` | `first_missing_hop_histogram` | {"instruction_fetch": 4, "mmio_write_acceptance": 1, "pin8_injection": 11} | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `unresolvable_missing_hops` | 0 | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `certified_admissions` | 7 | trace events (certificates:source_admission_id) |  |
| `certified_chains_per_second` | `chain_completion_by_admission` | {"accounted_admissions": 23, "admissions_by_role": {"fixed_support": 16, "fuzz_source": 23}, "admissions_total": 39, "admissions_total_source": "online_plan.json:source_admissions.admissions", "certificates_without_admission_id": 0, "certified_admissions": 7, "certified_fuzz_source_ratio": 0.30434782608695654, "certified_ratio": 0.1794871794871795, "certified_ratio_denominator": "admissions_total", "certified_ratio_reason": null, "fuzz_source_admissions": 23, "incomplete_admissions": 16, "unaccounted_fuzz_source_admissions": 0} | online_plan.json:source_admissions.admissions joined to certificates |  |
| `certified_chains_per_second` | `chain_producer_available` | true | chain_certificates.ChainCertificates |  |
| `certified_chains_per_second` | `semantics` | "unique certificate_id values the injected producer certified for this artifact; when incomplete certificates dominate, the value states artifact capability rather than DUT chain occurrence" | trace events (declared certificate contract) |  |
| `coverage_novelty` | `first_seen_target_bits` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `first_seen_target_slots` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `new_target_bits_per_second` | 0.123227 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `new_target_slots_per_second` | 0.123227 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `unique_witnessed_edges` | 9 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `edge_candidate_observations` | 1852 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `new_witnessed_edges_per_second` | 0.27726 | trace events:provenance.edge_candidates / report.json:effective_search_seconds |  |
| `coverage_novelty` | `method` | "acceptance_metrics.analyze_run -> local_target_novelty.new_target_bits_per_second and witnessed_edge_novelty.new_edges_per_second; paired_efficiency.compare_runs copies exactly these two fields into groups.<label>.coverage_novelty / groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical to that module's per-group rates" | p5_arm_metrics.v1 (declared reuse) |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | 0.0416667 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | 24 | receipts.jsonl (decoded rows) |  |
| `invalid_or_timeout_ratio` | `complete_count` | 23 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_count` | 1 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `timeout_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `finding_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | [] | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `definition` | "a case is invalid or timed out when its receipt status is in the reported invalid/timeout sets; findings and complete cases are excluded" | acceptance_metrics.invalid_or_timeout_detail.definition |  |
| `status_counts` | `status_counts` | {"complete": 23, "input_invalid": 1} | receipts.jsonl:status |  |
| `status_counts` | `status_counts_total` | 24 | receipts.jsonl (decoded rows) |  |
| `status_counts` | `reported_statuses` | {"complete": 23, "input_invalid": 1} | report.json:statuses |  |
| `status_counts` | `reports_agree` | true | report.json:statuses vs receipts.jsonl:status |  |

### 臂 `format2-jsonl`

- `run_dir`: `runs/p5-format2-jsonl-20261007-online`
- `run_id`: `p5-format2-jsonl-20261007`
- `arm_kind`: `scenario_online_cases` (来源 `report.json:execution_mode`)
- `analysis_performed`: true

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0 |
| `one_time_compile_init` | `finalization_timing_seconds` | {"identity_write": 0.37398606300121173, "plan_write": 0.0022957270048209466, "session_finish": 3.392919719000929, "total_before_report": 24.6109325360012, "trace_write": 20.74458272299671} | report.json:finalization_timing_seconds |  |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | 24.6109 | report.json:finalization_timing_seconds.total_before_report |  |
| `one_time_compile_init` | `effective_search_seconds` | 120.716 | report.json:effective_search_seconds |  |
| `one_time_compile_init` | `elapsed_seconds` | 122.012 | report.json:elapsed_seconds |  |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | 1.2959 | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) |  |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | cold_start.json is absent, so the cold-start baseline case count is unknown |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | cold_start.json:init_seconds_total is absent |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | either cold_start.json init_seconds or report.json:elapsed_seconds is unavailable, so the initialization share of elapsed is undefined |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json carries no finite positive wall_clock_seconds, so the initialization share of the cold group's wall clock is undefined |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0 |
| `per_case_admission` | `receipt_rows` | 77 | receipts.jsonl (decoded rows) |  |
| `per_case_admission` | `reported_tests` | 77 | report.json:tests |  |
| `per_case_admission` | `admissions_total` | 117 | online_plan.json:source_admissions.admissions |  |
| `per_case_admission` | `fuzz_source_admissions` | 75 | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `admissions_by_role` | {"fixed_support": 42, "fuzz_source": 75} | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `candidate_dispositions` | {"admitted": 75, "rejected": 2} | receipts.jsonl:candidate_disposition |  |
| `per_case_admission` | `candidate_disposition_reasons` | {"rtl_case_committed": 75, "source_action_not_constructible": 2} | receipts.jsonl:candidate_disposition_reason |  |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | 75 | receipts.jsonl:online_submit_timing_seconds |  |
| `per_case_admission` | `local_command_count_total` | 7251 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p50` | 96 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p95` | 98 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | 0.0566316 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | 0.0611234 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `host_remainder_seconds_p50` | 1.49504 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `host_remainder_seconds_p95` | 1.95464 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `cases_with_local_ticks` | 75 | receipts.jsonl:local_ticks |  |
| `per_case_admission` | `local_ticks_by_component_sum` | {"cpu": 2400.0, "gpio_a": 2500.0, "gpio_b": 2504.0} | receipts.jsonl:local_ticks.<component> (sum) |  |
| `per_case_admission` | `total_local_ticks_sum` | 7404 | receipts.jsonl:total_local_ticks (sum) |  |
| `per_case_admission` | `cases_with_total_local_ticks` | 77 | receipts.jsonl:total_local_ticks |  |
| `per_case_admission` | `coverage_records` | 77 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `raw_record_count` | 77 | receipts.jsonl:online_raw_records_hex |  |
| `per_case_admission` | `cases_with_violations` | 0 | receipts.jsonl:violations |  |
| `real_rtl_transactions` | `cases_with_runner_timing` | 75 | receipts.jsonl:online_runner_timing_seconds |  |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | 75 | receipts.jsonl:candidate_disposition_reason |  |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | 77 | receipts.jsonl:total_local_ticks |  |
| `real_rtl_transactions` | `record_semantics` | "mutation_decisions_not_dut_cycles" | report.json:record_semantics |  |
| `real_rtl_transactions` | `total_local_ticks_semantics` | "sum_of_independent_local_ticks_cost_only" | report.json:total_local_ticks_semantics |  |
| `real_rtl_transactions` | `clock_model` | "independent_local_ticks_and_causal_order" | report.json:clock_model |  |
| `router_scheduler` | `online_runner_timing_seconds` | {"observed_output_route": {"count": 75, "p50": 0.002056207988061942, "p95": 0.0023608294090081473, "sum_seconds": 0.2443317685101647}, "router_drain": {"count": 75, "p50": 0.0, "p95": 0.0040352523072215265, "sum_seconds": 0.09649911599990446}, "router_enqueue": {"count": 75, "p50": 0.0, "p95": 4.344309563748538e-05, "sum_seconds": 0.0012152330164099112}, "router_transact": {"count": 75, "p50": 0.0, "p95": 0.0, "sum_seconds": 0.0}, "runner_step": {"count": 75, "p50": 1.2662560540265986, "p95": 1.4939102138938325, "sum_seconds": 92.44320326521847}, "scheduler_batch": {"count": 75, "p50": 1.266608224970696, "p95": 1.4941951238964974, "sum_seconds": 92.46567832570145}} | receipts.jsonl:online_runner_timing_seconds |  |
| `router_scheduler` | `cases_with_router_transact` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact |  |
| `router_scheduler` | `router_transact_seconds_sum` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) |  |
| `router_scheduler` | `cases_with_scheduler_batch` | 75 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch |  |
| `router_scheduler` | `scheduler_batch_seconds_sum` | 92.4657 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) |  |
| `router_scheduler` | `cases_with_observed_output_route` | 75 | receipts.jsonl:online_runner_timing_seconds.observed_output_route |  |
| `router_scheduler` | `observed_output_route_seconds_sum` | 0.244332 | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) |  |
| `router_scheduler` | `nested_phase_semantics` | "online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time" | report.json (declared nested timing contract) |  |
| `incremental_feedback` | `completed_feedback_exchanges` | 2 | report.json:completed_feedback_exchanges |  |
| `incremental_feedback` | `mutation_hint_updates` | 3 | report.json:mutation_hint_updates |  |
| `incremental_feedback` | `mutation_hint_schema` | "scenario_mutation_hint.v1" | report.json:mutation_hint_schema |  |
| `incremental_feedback` | `cases_with_interaction_new_features` | 1 | receipts.jsonl:interaction_new_features |  |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | 3 | receipts.jsonl:interaction_feature_deltas |  |
| `incremental_feedback` | `cases_with_interaction_source_gains` | 1 | receipts.jsonl:interaction_source_gains |  |
| `incremental_feedback` | `cases_deferred` | 72 | receipts.jsonl:interaction_deferred |  |
| `incremental_feedback` | `source_action_gate_enforce` | true | report.json:source_action_gate.enforce |  |
| `incremental_feedback` | `source_action_gate_action_count` | 75 | report.json:source_action_gate.action_ids |  |
| `incremental_feedback` | `path_switch` | {"attempts": 0, "changed": 0, "enabled": false, "granted": 0, "operator_ids": {}, "refusals": {}, "rejection_codes": {}, "schema_version": "online_path_switch_state.v1", "source": "default", "status": "disabled"} | report.json:path_switch |  |
| `incremental_feedback` | `closed_loop_energy_enabled` | false | report.json:closed_loop_energy.enabled |  |
| `incremental_feedback` | `closed_loop_energy_counts` | {"certificate_count": 0, "closed_loop_count": 0, "partial_propagation_count": 0, "stage_reached_count": 0} | report.json:closed_loop_energy.counts |  |
| `log_evidence` | `trace_format` | "jsonl.v1" | online_final_trace.meta.json:schema_version / online_final_trace.json |  |
| `log_evidence` | `trace_meta_schema_version` | "online_trace_jsonl.v1" | online_final_trace.meta.json:schema_version |  |
| `log_evidence` | `trace_events_file` | "online_events.jsonl" | online_final_trace.meta.json:events_file |  |
| `log_evidence` | `trace_bytes` | 493194248 | trace container file (bytes) |  |
| `log_evidence` | `trace_meta_container_split` | true | online_final_trace.meta.json + online_events.jsonl / online_events.zlib |  |
| `log_evidence` | `trace_events_ingested` | 108113 | trace container file (events decoded) |  |
| `log_evidence` | `trace_declared_event_count` | 108113 | online_final_trace.meta.json:event_count |  |
| `log_evidence` | `trace_event_count_match` | true | online_final_trace.meta.json:event_count vs decoded events |  |
| `log_evidence` | `trace_semantic_sha256_verified` | true | online_final_trace.meta.json:semantic_sha256 vs recomputed digest |  |
| `log_evidence` | `trace_meta_bytes` | 428 | online_final_trace.meta.json (bytes) |  |
| `log_evidence` | `receipts_bytes` | 327735 | receipts.jsonl (bytes) |  |
| `log_evidence` | `client_log_bytes` | 728 | client.log (bytes) |  |
| `log_evidence` | `session_manifest_bytes` | 2405220 | online_session_manifest.json (bytes) |  |
| `log_evidence` | `evidence_footprint_bytes` | 496263865 | run directory artifacts (bytes, sum) |  |
| `latency_percentiles` | `online_phase_timing_seconds` | {"checker": {"count": 77, "p50": 2.5529952836222947e-06, "p95": 3.7234000046737493e-06}, "feedback_credit": {"count": 77, "p50": 0.0011819119972642511, "p95": 0.001835594599833712}, "interaction_ingest": {"count": 77, "p50": 0.018258040996443015, "p95": 0.0903424351970898}, "receipt_build": {"count": 77, "p50": 2.1045998437330127e-05, "p95": 2.5873804406728596e-05}, "rtl_submit": {"count": 77, "p50": 1.5384768380026799, "p95": 1.9999725086003308}, "selection_decode": {"count": 77, "p50": 0.00020917999790981412, "p95": 0.00034148180129704996}, "total": {"count": 77, "p50": 1.628892282002198, "p95": 2.094082938598876}, "trace_digest": {"count": 77, "p50": 0.051883096995879896, "p95": 0.059990694401494696}} | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `per_case_total_seconds` | {"count": 77, "p50": 1.628892282002198, "p95": 2.094082938598876} | receipts.jsonl:online_phase_timing_seconds.total |  |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | 77 | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `invalid_timing_values` | 0 | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds |  |
| `effective_cases_per_second` | `effective_cases_per_second` | 0.621291 | receipts.jsonl:status / report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `complete_status_count` | 75 | receipts.jsonl:status |  |
| `effective_cases_per_second` | `denominator_seconds` | 120.716 | report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | 0.637859 | receipts.jsonl (rows) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains` | 13 | trace events (runtime_chain_certificate.v1 certificates) |  |
| `certified_chains_per_second` | `certified_chains_per_second` | 0.10769 | trace events (certificates) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains_by_direction` | {"CPU_TO_IP_TO_CPU": 7, "IP_TO_CPU_TO_IP": 6} | trace events (certificates:direction) |  |
| `certified_chains_per_second` | `certified_chains_same_case` | 12 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `certified_chains_cross_case` | 1 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `incomplete_certificates` | 62 | trace events (incomplete certificates) |  |
| `certified_chains_per_second` | `first_missing_hop_histogram` | {"instruction_fetch": 22, "mmio_write_acceptance": 4, "pin8_injection": 36} | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `unresolvable_missing_hops` | 0 | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `certified_admissions` | 13 | trace events (certificates:source_admission_id) |  |
| `certified_chains_per_second` | `chain_completion_by_admission` | {"accounted_admissions": 75, "admissions_by_role": {"fixed_support": 42, "fuzz_source": 75}, "admissions_total": 117, "admissions_total_source": "online_plan.json:source_admissions.admissions", "certificates_without_admission_id": 0, "certified_admissions": 13, "certified_fuzz_source_ratio": 0.17333333333333334, "certified_ratio": 0.1111111111111111, "certified_ratio_denominator": "admissions_total", "certified_ratio_reason": null, "fuzz_source_admissions": 75, "incomplete_admissions": 62, "unaccounted_fuzz_source_admissions": 0} | online_plan.json:source_admissions.admissions joined to certificates |  |
| `certified_chains_per_second` | `chain_producer_available` | true | chain_certificates.ChainCertificates |  |
| `certified_chains_per_second` | `semantics` | "unique certificate_id values the injected producer certified for this artifact; when incomplete certificates dominate, the value states artifact capability rather than DUT chain occurrence" | trace events (declared certificate contract) |  |
| `coverage_novelty` | `first_seen_target_bits` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `first_seen_target_slots` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `new_target_bits_per_second` | 0.0331355 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `new_target_slots_per_second` | 0.0331355 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `unique_witnessed_edges` | 9 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `edge_candidate_observations` | 5564 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `new_witnessed_edges_per_second` | 0.0745549 | trace events:provenance.edge_candidates / report.json:effective_search_seconds |  |
| `coverage_novelty` | `method` | "acceptance_metrics.analyze_run -> local_target_novelty.new_target_bits_per_second and witnessed_edge_novelty.new_edges_per_second; paired_efficiency.compare_runs copies exactly these two fields into groups.<label>.coverage_novelty / groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical to that module's per-group rates" | p5_arm_metrics.v1 (declared reuse) |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | 0.025974 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | 77 | receipts.jsonl (decoded rows) |  |
| `invalid_or_timeout_ratio` | `complete_count` | 75 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_count` | 2 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `timeout_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `finding_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | [] | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `definition` | "a case is invalid or timed out when its receipt status is in the reported invalid/timeout sets; findings and complete cases are excluded" | acceptance_metrics.invalid_or_timeout_detail.definition |  |
| `status_counts` | `status_counts` | {"complete": 75, "input_invalid": 2} | receipts.jsonl:status |  |
| `status_counts` | `status_counts_total` | 77 | receipts.jsonl (decoded rows) |  |
| `status_counts` | `reported_statuses` | {"complete": 75, "input_invalid": 2} | report.json:statuses |  |
| `status_counts` | `reports_agree` | true | report.json:statuses vs receipts.jsonl:status |  |

### 臂 `format2-zlib`

- `run_dir`: `runs/p5-format2-zlib-20261007-online`
- `run_id`: `p5-format2-zlib-20261007`
- `arm_kind`: `scenario_online_cases` (来源 `report.json:execution_mode`)
- `analysis_performed`: true

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0 |
| `one_time_compile_init` | `finalization_timing_seconds` | {"identity_write": 0.16611999599990668, "plan_write": 0.00202593399444595, "session_finish": 4.065045139002905, "total_before_report": 13.469330645006266, "trace_write": 9.14617208299751} | report.json:finalization_timing_seconds |  |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | 13.4693 | report.json:finalization_timing_seconds.total_before_report |  |
| `one_time_compile_init` | `effective_search_seconds` | 120.468 | report.json:effective_search_seconds |  |
| `one_time_compile_init` | `elapsed_seconds` | 121.645 | report.json:elapsed_seconds |  |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | 1.1775 | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) |  |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | cold_start.json is absent, so the cold-start baseline case count is unknown |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | cold_start.json:init_seconds_total is absent |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | cold_start.json is absent from this arm, so the per-case cold-start initialization cost was not measured here; a continuous online session has no per-case cold start |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | either cold_start.json init_seconds or report.json:elapsed_seconds is unavailable, so the initialization share of elapsed is undefined |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json carries no finite positive wall_clock_seconds, so the initialization share of the cold group's wall clock is undefined |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0 |
| `per_case_admission` | `receipt_rows` | 81 | receipts.jsonl (decoded rows) |  |
| `per_case_admission` | `reported_tests` | 81 | report.json:tests |  |
| `per_case_admission` | `admissions_total` | 123 | online_plan.json:source_admissions.admissions |  |
| `per_case_admission` | `fuzz_source_admissions` | 79 | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `admissions_by_role` | {"fixed_support": 44, "fuzz_source": 79} | online_plan.json:source_admissions.admissions[].role |  |
| `per_case_admission` | `candidate_dispositions` | {"admitted": 79, "rejected": 2} | receipts.jsonl:candidate_disposition |  |
| `per_case_admission` | `candidate_disposition_reasons` | {"rtl_case_committed": 79, "source_action_not_constructible": 2} | receipts.jsonl:candidate_disposition_reason |  |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | 79 | receipts.jsonl:online_submit_timing_seconds |  |
| `per_case_admission` | `local_command_count_total` | 7637 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p50` | 96 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_count_p95` | 98 | receipts.jsonl:online_submit_timing_seconds.local_command_count |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | 0.0548176 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | 0.0579608 | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip |  |
| `per_case_admission` | `host_remainder_seconds_p50` | 1.40258 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `host_remainder_seconds_p95` | 1.89882 | receipts.jsonl:online_submit_timing_seconds.host_remainder |  |
| `per_case_admission` | `cases_with_local_ticks` | 79 | receipts.jsonl:local_ticks |  |
| `per_case_admission` | `local_ticks_by_component_sum` | {"cpu": 2528.0, "gpio_a": 2632.0, "gpio_b": 2636.0} | receipts.jsonl:local_ticks.<component> (sum) |  |
| `per_case_admission` | `total_local_ticks_sum` | 7796 | receipts.jsonl:total_local_ticks (sum) |  |
| `per_case_admission` | `cases_with_total_local_ticks` | 81 | receipts.jsonl:total_local_ticks |  |
| `per_case_admission` | `coverage_records` | 81 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `per_case_admission` | `raw_record_count` | 81 | receipts.jsonl:online_raw_records_hex |  |
| `per_case_admission` | `cases_with_violations` | 0 | receipts.jsonl:violations |  |
| `real_rtl_transactions` | `cases_with_runner_timing` | 79 | receipts.jsonl:online_runner_timing_seconds |  |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | 79 | receipts.jsonl:candidate_disposition_reason |  |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | 81 | receipts.jsonl:total_local_ticks |  |
| `real_rtl_transactions` | `record_semantics` | "mutation_decisions_not_dut_cycles" | report.json:record_semantics |  |
| `real_rtl_transactions` | `total_local_ticks_semantics` | "sum_of_independent_local_ticks_cost_only" | report.json:total_local_ticks_semantics |  |
| `real_rtl_transactions` | `clock_model` | "independent_local_ticks_and_causal_order" | report.json:clock_model |  |
| `router_scheduler` | `online_runner_timing_seconds` | {"observed_output_route": {"count": 79, "p50": 0.0019063600557274185, "p95": 0.0021687714943254832, "sum_seconds": 0.2352356965202489}, "router_drain": {"count": 79, "p50": 0.0, "p95": 0.00352522239627433, "sum_seconds": 0.08819250098167686}, "router_enqueue": {"count": 79, "p50": 0.0, "p95": 4.956450138706714e-05, "sum_seconds": 0.0012197140022180974}, "router_transact": {"count": 79, "p50": 0.0, "p95": 0.0, "sum_seconds": 0.0}, "runner_step": {"count": 79, "p50": 1.1940011809347197, "p95": 1.4062819615042828, "sum_seconds": 91.32827863222337}, "scheduler_batch": {"count": 79, "p50": 1.1942440110069583, "p95": 1.4065394465964345, "sum_seconds": 91.34780205505376}} | receipts.jsonl:online_runner_timing_seconds |  |
| `router_scheduler` | `cases_with_router_transact` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact |  |
| `router_scheduler` | `router_transact_seconds_sum` | 0 | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) |  |
| `router_scheduler` | `cases_with_scheduler_batch` | 79 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch |  |
| `router_scheduler` | `scheduler_batch_seconds_sum` | 91.3478 | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) |  |
| `router_scheduler` | `cases_with_observed_output_route` | 79 | receipts.jsonl:online_runner_timing_seconds.observed_output_route |  |
| `router_scheduler` | `observed_output_route_seconds_sum` | 0.235236 | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) |  |
| `router_scheduler` | `nested_phase_semantics` | "online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time" | report.json (declared nested timing contract) |  |
| `incremental_feedback` | `completed_feedback_exchanges` | 2 | report.json:completed_feedback_exchanges |  |
| `incremental_feedback` | `mutation_hint_updates` | 3 | report.json:mutation_hint_updates |  |
| `incremental_feedback` | `mutation_hint_schema` | "scenario_mutation_hint.v1" | report.json:mutation_hint_schema |  |
| `incremental_feedback` | `cases_with_interaction_new_features` | 1 | receipts.jsonl:interaction_new_features |  |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | 4 | receipts.jsonl:interaction_feature_deltas |  |
| `incremental_feedback` | `cases_with_interaction_source_gains` | 1 | receipts.jsonl:interaction_source_gains |  |
| `incremental_feedback` | `cases_deferred` | 75 | receipts.jsonl:interaction_deferred |  |
| `incremental_feedback` | `source_action_gate_enforce` | true | report.json:source_action_gate.enforce |  |
| `incremental_feedback` | `source_action_gate_action_count` | 79 | report.json:source_action_gate.action_ids |  |
| `incremental_feedback` | `path_switch` | {"attempts": 0, "changed": 0, "enabled": false, "granted": 0, "operator_ids": {}, "refusals": {}, "rejection_codes": {}, "schema_version": "online_path_switch_state.v1", "source": "default", "status": "disabled"} | report.json:path_switch |  |
| `incremental_feedback` | `closed_loop_energy_enabled` | false | report.json:closed_loop_energy.enabled |  |
| `incremental_feedback` | `closed_loop_energy_counts` | {"certificate_count": 0, "closed_loop_count": 0, "partial_propagation_count": 0, "stage_reached_count": 0} | report.json:closed_loop_energy.counts |  |
| `log_evidence` | `trace_format` | "zlib_chunks.v1" | online_final_trace.meta.json:schema_version / online_final_trace.json |  |
| `log_evidence` | `trace_meta_schema_version` | "online_trace_zlib_chunks.v1" | online_final_trace.meta.json:schema_version |  |
| `log_evidence` | `trace_events_file` | "online_events.zlib" | online_final_trace.meta.json:events_file |  |
| `log_evidence` | `trace_bytes` | 36903052 | trace container file (bytes) |  |
| `log_evidence` | `trace_meta_container_split` | true | online_final_trace.meta.json + online_events.jsonl / online_events.zlib |  |
| `log_evidence` | `trace_events_ingested` | 114309 | trace container file (events decoded) |  |
| `log_evidence` | `trace_declared_event_count` | 114309 | online_final_trace.meta.json:event_count |  |
| `log_evidence` | `trace_event_count_match` | true | online_final_trace.meta.json:event_count vs decoded events |  |
| `log_evidence` | `trace_semantic_sha256_verified` | true | online_final_trace.meta.json:semantic_sha256 vs recomputed digest |  |
| `log_evidence` | `trace_meta_bytes` | 433 | online_final_trace.meta.json (bytes) |  |
| `log_evidence` | `receipts_bytes` | 345893 | receipts.jsonl (bytes) |  |
| `log_evidence` | `client_log_bytes` | 727 | client.log (bytes) |  |
| `log_evidence` | `session_manifest_bytes` | 2405220 | online_session_manifest.json (bytes) |  |
| `log_evidence` | `evidence_footprint_bytes` | 40001802 | run directory artifacts (bytes, sum) |  |
| `latency_percentiles` | `online_phase_timing_seconds` | {"checker": {"count": 81, "p50": 2.410000888630748e-06, "p95": 3.0989976949058473e-06}, "feedback_credit": {"count": 81, "p50": 0.00108700599957956, "p95": 0.0017211970043717884}, "interaction_ingest": {"count": 81, "p50": 0.017961628996999934, "p95": 0.08380137100175489}, "receipt_build": {"count": 81, "p50": 2.1141997422091663e-05, "p95": 2.5344997993670404e-05}, "rtl_submit": {"count": 81, "p50": 1.449252096004784, "p95": 1.9438498320014332}, "selection_decode": {"count": 81, "p50": 0.00021039899729657918, "p95": 0.00034485999640310183}, "total": {"count": 81, "p50": 1.530746092001209, "p95": 2.018738275997748}, "trace_digest": {"count": 81, "p50": 0.05126987899711821, "p95": 0.0575433880003402}} | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `per_case_total_seconds` | {"count": 81, "p50": 1.530746092001209, "p95": 2.018738275997748} | receipts.jsonl:online_phase_timing_seconds.total |  |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | 81 | receipts.jsonl:online_phase_timing_seconds |  |
| `latency_percentiles` | `invalid_timing_values` | 0 | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds |  |
| `effective_cases_per_second` | `effective_cases_per_second` | 0.655778 | receipts.jsonl:status / report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `complete_status_count` | 79 | receipts.jsonl:status |  |
| `effective_cases_per_second` | `denominator_seconds` | 120.468 | report.json:effective_search_seconds |  |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | 0.67238 | receipts.jsonl (rows) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains` | 14 | trace events (runtime_chain_certificate.v1 certificates) |  |
| `certified_chains_per_second` | `certified_chains_per_second` | 0.116214 | trace events (certificates) / report.json:effective_search_seconds |  |
| `certified_chains_per_second` | `certified_chains_by_direction` | {"CPU_TO_IP_TO_CPU": 8, "IP_TO_CPU_TO_IP": 6} | trace events (certificates:direction) |  |
| `certified_chains_per_second` | `certified_chains_same_case` | 13 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `certified_chains_cross_case` | 1 | trace events (certificates:source/endpoint_case_index) |  |
| `certified_chains_per_second` | `incomplete_certificates` | 65 | trace events (incomplete certificates) |  |
| `certified_chains_per_second` | `first_missing_hop_histogram` | {"instruction_fetch": 23, "mmio_write_acceptance": 4, "pin8_injection": 38} | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `unresolvable_missing_hops` | 0 | trace events (incomplete certificates:missing_hops[0]) |  |
| `certified_chains_per_second` | `certified_admissions` | 14 | trace events (certificates:source_admission_id) |  |
| `certified_chains_per_second` | `chain_completion_by_admission` | {"accounted_admissions": 79, "admissions_by_role": {"fixed_support": 44, "fuzz_source": 79}, "admissions_total": 123, "admissions_total_source": "online_plan.json:source_admissions.admissions", "certificates_without_admission_id": 0, "certified_admissions": 14, "certified_fuzz_source_ratio": 0.17721518987341772, "certified_ratio": 0.11382113821138211, "certified_ratio_denominator": "admissions_total", "certified_ratio_reason": null, "fuzz_source_admissions": 79, "incomplete_admissions": 65, "unaccounted_fuzz_source_admissions": 0} | online_plan.json:source_admissions.admissions joined to certificates |  |
| `certified_chains_per_second` | `chain_producer_available` | true | chain_certificates.ChainCertificates |  |
| `certified_chains_per_second` | `semantics` | "unique certificate_id values the injected producer certified for this artifact; when incomplete certificates dominate, the value states artifact capability rather than DUT chain occurrence" | trace events (declared certificate contract) |  |
| `coverage_novelty` | `first_seen_target_bits` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `first_seen_target_slots` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `coverage_width_bytes` | 4 | receipts.jsonl:coverage_hex |  |
| `coverage_novelty` | `new_target_bits_per_second` | 0.033204 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `new_target_slots_per_second` | 0.033204 | receipts.jsonl:coverage_hex / report.json:effective_search_seconds |  |
| `coverage_novelty` | `unique_witnessed_edges` | 9 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `edge_candidate_observations` | 5846 | trace events:provenance.edge_candidates |  |
| `coverage_novelty` | `new_witnessed_edges_per_second` | 0.0747089 | trace events:provenance.edge_candidates / report.json:effective_search_seconds |  |
| `coverage_novelty` | `method` | "acceptance_metrics.analyze_run -> local_target_novelty.new_target_bits_per_second and witnessed_edge_novelty.new_edges_per_second; paired_efficiency.compare_runs copies exactly these two fields into groups.<label>.coverage_novelty / groups.<label>.witnessed_edge_novelty, so the rates here are bit-identical to that module's per-group rates" | p5_arm_metrics.v1 (declared reuse) |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | 0.0246914 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | 81 | receipts.jsonl (decoded rows) |  |
| `invalid_or_timeout_ratio` | `complete_count` | 79 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `invalid_count` | 2 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `timeout_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `finding_count` | 0 | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | [] | receipts.jsonl:status |  |
| `invalid_or_timeout_ratio` | `definition` | "a case is invalid or timed out when its receipt status is in the reported invalid/timeout sets; findings and complete cases are excluded" | acceptance_metrics.invalid_or_timeout_detail.definition |  |
| `status_counts` | `status_counts` | {"complete": 79, "input_invalid": 2} | receipts.jsonl:status |  |
| `status_counts` | `status_counts_total` | 81 | receipts.jsonl (decoded rows) |  |
| `status_counts` | `reported_statuses` | {"complete": 79, "input_invalid": 2} | report.json:statuses |  |
| `status_counts` | `reports_agree` | true | report.json:statuses vs receipts.jsonl:status |  |

### 臂 `p4-cpu-side-foreign`

- `run_dir`: `runs/p4-cpu-side-first-seen-20261008-online`
- `run_id`: `None`
- `arm_kind`: `not_a_scenario_online_session` (来源 `report.json:schema_version`)
- `arm_kind_reason`: report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null
- `analysis_performed`: false

| checklist 组 | 指标 | 值 | 来源 artifact key | null 原因 |
|---|---|---|---|---|
| `one_time_compile_init` | `compilation_seconds` | null | report.json (no RTL compile/elaboration timing key exists in the scenario online run report) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `finalization_timing_seconds` | null | report.json:finalization_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `finalization_total_before_report_seconds` | null | report.json:finalization_timing_seconds.total_before_report | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `effective_search_seconds` | null | report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `elapsed_seconds` | null | report.json:elapsed_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `elapsed_minus_effective_search_seconds` | null | report.json:elapsed_seconds - report.json:effective_search_seconds (derived) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_baseline_case_count` | null | cold_start.json:case_count | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_init_seconds_p50` | null | cold_start.json:cases[].init_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_init_seconds_p95` | null | cold_start.json:cases[].init_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_init_seconds_total` | null | cold_start.json:cases[].init_seconds (sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_document_init_seconds_total` | null | cold_start.json:init_seconds_total | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_cases_with_init_seconds` | null | cold_start.json:cases[].init_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_share_of_elapsed` | null | cold_start.json:cases[].init_seconds / report.json:elapsed_seconds (derived) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `cold_start_share_of_wall_clock_seconds` | null | cold_start.json:cases[].init_seconds / report.json:wall_clock_seconds (derived) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `one_time_compile_init` | `per_case_initialization_seconds` | null | cold_start.json:cases[].init_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `receipt_rows` | null | receipts.jsonl (decoded rows) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `reported_tests` | null | report.json:tests | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `admissions_total` | null | online_plan.json:source_admissions.admissions | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `fuzz_source_admissions` | null | online_plan.json:source_admissions.admissions[].role | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `admissions_by_role` | null | online_plan.json:source_admissions.admissions[].role | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `candidate_dispositions` | null | receipts.jsonl:candidate_disposition | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `candidate_disposition_reasons` | null | receipts.jsonl:candidate_disposition_reason | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `cases_with_online_submit_timing_seconds` | null | receipts.jsonl:online_submit_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `local_command_count_total` | null | receipts.jsonl:online_submit_timing_seconds.local_command_count | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `local_command_count_p50` | null | receipts.jsonl:online_submit_timing_seconds.local_command_count | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `local_command_count_p95` | null | receipts.jsonl:online_submit_timing_seconds.local_command_count | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `local_command_roundtrip_seconds_p50` | null | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `local_command_roundtrip_seconds_p95` | null | receipts.jsonl:online_submit_timing_seconds.local_command_roundtrip | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `host_remainder_seconds_p50` | null | receipts.jsonl:online_submit_timing_seconds.host_remainder | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `host_remainder_seconds_p95` | null | receipts.jsonl:online_submit_timing_seconds.host_remainder | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `cases_with_local_ticks` | null | receipts.jsonl:local_ticks | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `local_ticks_by_component_sum` | null | receipts.jsonl:local_ticks.<component> (sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `total_local_ticks_sum` | null | receipts.jsonl:total_local_ticks (sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `cases_with_total_local_ticks` | null | receipts.jsonl:total_local_ticks | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `coverage_records` | null | receipts.jsonl:coverage_hex | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `coverage_width_bytes` | null | receipts.jsonl:coverage_hex | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `raw_record_count` | null | receipts.jsonl:online_raw_records_hex | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `per_case_admission` | `cases_with_violations` | null | receipts.jsonl:violations | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `real_rtl_transactions` | `cases_with_runner_timing` | null | receipts.jsonl:online_runner_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `real_rtl_transactions` | `cases_with_rtl_case_committed` | null | receipts.jsonl:candidate_disposition_reason | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `real_rtl_transactions` | `cases_with_total_local_ticks` | null | receipts.jsonl:total_local_ticks | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `real_rtl_transactions` | `record_semantics` | null | report.json:record_semantics | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `real_rtl_transactions` | `total_local_ticks_semantics` | null | report.json:total_local_ticks_semantics | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `real_rtl_transactions` | `clock_model` | null | report.json:clock_model | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `online_runner_timing_seconds` | null | receipts.jsonl:online_runner_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `cases_with_router_transact` | null | receipts.jsonl:online_runner_timing_seconds.router_transact | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `router_transact_seconds_sum` | null | receipts.jsonl:online_runner_timing_seconds.router_transact (sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `cases_with_scheduler_batch` | null | receipts.jsonl:online_runner_timing_seconds.scheduler_batch | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `scheduler_batch_seconds_sum` | null | receipts.jsonl:online_runner_timing_seconds.scheduler_batch (sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `cases_with_observed_output_route` | null | receipts.jsonl:online_runner_timing_seconds.observed_output_route | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `observed_output_route_seconds_sum` | null | receipts.jsonl:online_runner_timing_seconds.observed_output_route (sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `router_scheduler` | `nested_phase_semantics` | null | report.json (declared nested timing contract) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `completed_feedback_exchanges` | null | report.json:completed_feedback_exchanges | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `mutation_hint_updates` | null | report.json:mutation_hint_updates | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `mutation_hint_schema` | null | report.json:mutation_hint_schema | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `cases_with_interaction_new_features` | null | receipts.jsonl:interaction_new_features | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `cases_with_interaction_feature_deltas` | null | receipts.jsonl:interaction_feature_deltas | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `cases_with_interaction_source_gains` | null | receipts.jsonl:interaction_source_gains | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `cases_deferred` | null | receipts.jsonl:interaction_deferred | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `source_action_gate_enforce` | null | report.json:source_action_gate.enforce | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `source_action_gate_action_count` | null | report.json:source_action_gate.action_ids | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `path_switch` | null | report.json:path_switch | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `closed_loop_energy_enabled` | null | report.json:closed_loop_energy.enabled | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `incremental_feedback` | `closed_loop_energy_counts` | null | report.json:closed_loop_energy.counts | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_format` | null | online_final_trace.meta.json:schema_version / online_final_trace.json | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_meta_schema_version` | null | online_final_trace.meta.json:schema_version | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_events_file` | null | online_final_trace.meta.json:events_file | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_bytes` | null | trace container file (bytes) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_meta_container_split` | null | online_final_trace.meta.json + online_events.jsonl / online_events.zlib | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_events_ingested` | null | trace container file (events decoded) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_declared_event_count` | null | online_final_trace.meta.json:event_count | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_event_count_match` | null | online_final_trace.meta.json:event_count vs decoded events | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_semantic_sha256_verified` | null | online_final_trace.meta.json:semantic_sha256 vs recomputed digest | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `trace_meta_bytes` | null | online_final_trace.meta.json (bytes) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `receipts_bytes` | null | receipts.jsonl (bytes) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `client_log_bytes` | null | client.log (bytes) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `session_manifest_bytes` | null | online_session_manifest.json (bytes) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `log_evidence` | `evidence_footprint_bytes` | null | run directory artifacts (bytes, sum) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `latency_percentiles` | `online_phase_timing_seconds` | null | receipts.jsonl:online_phase_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `latency_percentiles` | `per_case_total_seconds` | null | receipts.jsonl:online_phase_timing_seconds.total | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `latency_percentiles` | `cases_with_online_phase_timing_seconds` | null | receipts.jsonl:online_phase_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `latency_percentiles` | `invalid_timing_values` | null | receipts.jsonl:online_phase_timing_seconds / online_runner_timing_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `effective_cases_per_second` | `effective_cases_per_second` | null | receipts.jsonl:status / report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `effective_cases_per_second` | `complete_status_count` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `effective_cases_per_second` | `denominator_seconds` | null | report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `effective_cases_per_second` | `all_receipt_cases_per_second` | null | receipts.jsonl (rows) / report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `certified_chains` | null | trace events (runtime_chain_certificate.v1 certificates) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `certified_chains_per_second` | null | trace events (certificates) / report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `certified_chains_by_direction` | null | trace events (certificates:direction) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `certified_chains_same_case` | null | trace events (certificates:source/endpoint_case_index) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `certified_chains_cross_case` | null | trace events (certificates:source/endpoint_case_index) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `incomplete_certificates` | null | trace events (incomplete certificates) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `first_missing_hop_histogram` | null | trace events (incomplete certificates:missing_hops[0]) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `unresolvable_missing_hops` | null | trace events (incomplete certificates:missing_hops[0]) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `certified_admissions` | null | trace events (certificates:source_admission_id) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `chain_completion_by_admission` | null | online_plan.json:source_admissions.admissions joined to certificates | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `chain_producer_available` | null | chain_certificates.ChainCertificates | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `certified_chains_per_second` | `semantics` | null | trace events (declared certificate contract) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `first_seen_target_bits` | null | receipts.jsonl:coverage_hex | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `first_seen_target_slots` | null | receipts.jsonl:coverage_hex | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `coverage_width_bytes` | null | receipts.jsonl:coverage_hex | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `new_target_bits_per_second` | null | receipts.jsonl:coverage_hex / report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `new_target_slots_per_second` | null | receipts.jsonl:coverage_hex / report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `unique_witnessed_edges` | null | trace events:provenance.edge_candidates | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `edge_candidate_observations` | null | trace events:provenance.edge_candidates | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `new_witnessed_edges_per_second` | null | trace events:provenance.edge_candidates / report.json:effective_search_seconds | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `coverage_novelty` | `method` | null | p5_arm_metrics.v1 (declared reuse) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_ratio` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `invalid_or_timeout_denominator` | null | receipts.jsonl (decoded rows) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `complete_count` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `invalid_count` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `timeout_count` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `finding_count` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `unclassified_statuses` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `invalid_or_timeout_ratio` | `definition` | null | acceptance_metrics.invalid_or_timeout_detail.definition | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `status_counts` | `status_counts` | null | receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `status_counts` | `status_counts_total` | null | receipts.jsonl (decoded rows) | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `status_counts` | `reported_statuses` | null | report.json:statuses | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |
| `status_counts` | `reports_agree` | null | report.json:statuses vs receipts.jsonl:status | report.json declares schema_version 'soc_result.v1' and the directory carries no receipts.jsonl and no online trace container, so this is not a scenario online dataflow session and every metric is null |

## 3. 边界

- read-only aggregation of saved run directories; no RTL, Verilator, cargo or fuzz process is started and no artifact is written back into a run
- receipts.jsonl is streamed twice (once by acceptance_metrics.analyze_run, once by the admission scan here) and the trace container is streamed once by analyze_run; nothing is materialized and memory stays bounded by the event batch and the timing-sample cap
- no artifact in the run directory records RTL compile/elaboration seconds; report.json carries only finalization_timing_seconds (one-time, after the search) and the RTL build is prebuilt outside the online session, so this stays null rather than 0
- the continuous session charges no initialization to any single case: its one-time build/init is outside every per-case total and is not recorded per case, so this quantity stays null rather than 0
- online_runner_timing_seconds phases are nested per case (scheduler_batch contains runner_step, which contains the router phases); the sums in this group must not be added together and are not pure RTL time
- report.json:record_semantics declares the receipts as mutation decisions rather than DUT cycles, and report.json:total_local_ticks_semantics declares the local ticks as cost-only; neither is a DUT cycle count
- certified chain counts are the certificates the frozen producer emitted for the artifact; they state artifact capability and do not independently re-derive hop evidence from raw events
- the invalid/timeout ratio is null whenever a receipt status falls outside the shipped invalid/timeout sets; the exact status counts are still reported, and the ratio is never widened to make a status fit
- cold_start.json is written by scripts/bench_ibex_pulp_cold_start.py for the per-case cold-start group; a continuous online session has no such document and its per-case initialization stays null

