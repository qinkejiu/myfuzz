# Scripts

Scripts for the current independent-harness workflow live here and under
`src/myfuzz/scripts/`.

```text
generate_local_harness.py             create a generated local harness from a registered profile
record_scenario.py                    record a continuous multi-component testcase
replay_scenario.py                    replay saved evidence using a scenario factory
run_scenario_campaign.py              run a configured scenario mutation campaign
query_capabilities.py                 list documented runtime evidence and limits without starting RTL
run_ibex_pulp_online.py                 run/replay one persistent Ibex + dual PULP GPIO RFuzz pilot
bench_ibex_pulp_cold_start.py         one fresh runtime per saved input: startup-cost baseline JSON
run_first_step_cold_start_run.py      one fresh session per frozen continuous case, aggregated into a pairable cold run directory
bench_first_step_paired.py            pair a continuous run directory with a per-case cold-start one (paired_efficiency_report.v1)
run_first_step_acceptance.py          analyze (or run + analyze) one saved online session: certified chain/s, coverage novelty, per-case p50/p95
check_doc_links.py                    verify relative Markdown links and anchors without touching the files
source_branch_instrumenter.py         optional source-level RTL coverage inserter
instrument_ibex.sh / instrument_cva6.sh optional CPU-only source-instrumentation helpers
generate_soc.py / run_soc_campaigns.py separate historical full-SoC composition path
runs/                                 dated campaign and comparison launchers
```

The independent-harness design is documented in [`docs/CURRENT_DESIGN.md`](../docs/CURRENT_DESIGN.md).
The current code boundary and staged implementation work are in
[`docs/CODE_ORGANIZATION.md`](../docs/CODE_ORGANIZATION.md) and the
[`current implementation plan`](../docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md).
The local harness generator and scenario runner use registered component facts,
protocol adapters and explicit dependency bindings.

`generate_soc.py` belongs to a separate historical tool path. It implements the generation phase of
`docs/superpowers/plans/2026-09-20-soc-composition-assurance-plan.md`: it binds
source-pinned component profiles to elaborated RTL facts, builds the port
disposition ledger and the validated plan, renders the SoC top and independently
audits the generated structure. See `examples/soc_generation/README.md`; this
path is not the active independent-harness architecture.

The three unreferenced prototype generators formerly under `scripts/codegen/`
and two unrelated Codex workspace-management scripts were moved outside the
repository. Their recoverable copies and SHA-256 values are listed in the
external `excluded-files-manifest.json` created for the 2026-10-06 cleanup.

The full pipeline runner is `src/myfuzz/scripts/run_design_flow.py`.
