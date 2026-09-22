# Scripts

Standalone project scripts live here.

```text
source_branch_instrumenter.py         source-level Verilog/SystemVerilog inserter
instrument_ibex.sh                    direct Ibex insertion helper
instrument_cva6.sh                    direct CVA6 insertion helper
generate_soc.py                       automatic SoC composition from user RTL/profiles
compare_soc_campaigns.py              strict direct/constraint/repair campaign comparison
runs/                                 reproducible Ibex/CVA6 experiment launchers
codegen/                              harness generation helpers, when present in the local tree
```

`generate_soc.py` implements the generation phase of
`docs/superpowers/plans/2026-09-20-soc-composition-assurance-plan.md`: it binds
source-pinned component profiles to elaborated RTL facts, builds the port
disposition ledger and the validated plan, renders the SoC top and independently
audits the generated structure. See `examples/soc_generation/README.md`.

The full pipeline runner is `src/myfuzz/scripts/run_design_flow.py`.
