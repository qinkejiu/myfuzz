# Task 6 Fix 3 Report

Base: `edfb773ea6ee6735ba9d560bb692c6272b364c11`

## Fixed review findings

1. Canonical full-byte-enable constraints now identify a concrete raw ABI destination. `project_sample` overrides that destination with the full-byte mask, and the dependency-aware SystemVerilog binds the same canonical signal to the corresponding DUT port. Unconnected canonical signals are rejected by plan validation.
2. AXI4 continues to force single-beat length, ID, and last values. It now also forces `awburst`/`arburst` to INCR and derives `awsize`/`arsize` from a declared `data_width_log2_bytes` capability. Non-power-of-two byte data widths are rejected.
3. Constant projection actions are fail-closed when any second action targets the same destination; catalog validation applies the same rule to declared fields.
4. Capability parsing converts all invalid enum/container forms into `ProtocolDefinitionError`. `x-` extensions require a non-empty suffix and bounded scalar names/strings (256 characters maximum), while duplicate-key and declaration checks remain enabled.

## API compatibility

`CanonicalByteEnable` retains its original four positional fields and adds an optional trailing `destination_id`. A constraint without a concrete destination is rejected when a projection plan is built, rather than being silently emitted as an unconnected signal.

## Regression and verification

- Confirmed new regressions were red before implementation, including disconnected canonical byte-enable propagation, constant overwrite composition, raw AXI burst values, invalid enum containers, overlong extensions, and empty `x-` names.
- `PYTHONPATH=src python3 -m unittest discover -s tests/protocols -t . -v`: 53 passed.
- `PYTHONPATH=src python3 -m unittest discover -s tests/harness -t . -v`: 66 passed.
- Directed RTL checks: 6 passed with Verilator 5.051 and Icarus Verilog 14.0.
- `PYTHONPATH=src python3 -m compileall -q src/myfuzz/harness src/myfuzz/protocols`: passed.
- `git diff --check`: passed.

## Scope protection

Only Task6 protocol/harness/model/catalog/plugin/test files plus this report are staged. Existing Task5 changes, `.superpowers/sdd/task-2-report.md`, and `third_party/` remain untouched and unstaged.
