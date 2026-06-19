# Scripts

Standalone project scripts live here.

```text
source_branch_instrumenter.py         source-level Verilog/SystemVerilog inserter
instrument_ibex.sh                    direct Ibex insertion helper
instrument_cva6.sh                    direct CVA6 insertion helper
runs/                                 reproducible Ibex/CVA6 experiment launchers
codegen/                              harness generation helpers, when present in the local tree
```

The full pipeline runner is `src/myfuzz/scripts/run_design_flow.py`.
